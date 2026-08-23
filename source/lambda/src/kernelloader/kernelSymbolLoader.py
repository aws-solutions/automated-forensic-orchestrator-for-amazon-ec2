#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import json
import os
import time
import uuid

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response, ssm_output_log_group
from ..common.log import get_logger
from ..common.redact import redact
from ..common.vpc_lookup import forensic_subnet_id
from ..common.managed_nodes import describe_node

# initialise loggers
logger = get_logger(__name__)

instance_id = ""

# Distributions this Lambda can build a symbol table for, mapped to the
# environment variable holding the SSM document that does it.
#
# The mapping has to be explicit because two different conventions meet here and
# they only agreed by coincidence. The CDK names each document's environment
# variable after its *filename*
# (forensic-ssm-document-builder-stack.ts: name.replace(HYPHEN, '_').toUpperCase()),
# while this handler used to build the name from the *distribution* string:
# os.environ[distribution + "_VOLATILITY_SYMBOL"].
#
# That worked for RHEL8 and AL2023 only because someone happened to name those
# files to match. It could never work for Amazon Linux 2, whose document is
# amazon-linux-2-volatility-profile.json and therefore
# AMAZON_LINUX_2_VOLATILITY_PROFILE - a name "AL2" cannot produce. RHEL7 and
# RHEL9 were advertised for years with no document and no variable at all, so
# they passed validation and then raised KeyError after a builder instance had
# already been launched.
#
# One table, one place to get wrong, and test/distribution-support.test.ts
# asserts every entry resolves to a document that exists and that declares every
# parameter this handler sends. Adding an operating system is a row plus a
# document, not a naming convention to rediscover.
SYMBOL_DOCUMENT_ENV_VARS = {
    "RHEL8": "RHEL8_VOLATILITY_SYMBOL",
    "AL2023": "AL2023_VOLATILITY_SYMBOL",
    "AL2": "AMAZON_LINUX_2_VOLATILITY_PROFILE",
}

SUPPORTED_DISTRIBUTIONS = tuple(SYMBOL_DOCUMENT_ENV_VARS)

# instance_status_ok only proves the EC2 status checks passed; the SSM agent
# registers with Systems Manager afterwards, so reading
# describe_instance_information once straight after that waiter routinely misses
# a builder that is perfectly healthy.
SSM_REGISTRATION_POLL_SECONDS = 15
SSM_REGISTRATION_ATTEMPTS = 20

# botocore's instance_status_ok waiter defaults to 15 seconds x 40 attempts, so
# on its own it can burn 585 seconds of a 900 second Lambda. Followed by a fixed
# SSM registration poll of 20 x 15 seconds that is another 285, for 870 seconds
# of sleeping inside a 900 second budget: the handler used to hit the Lambda
# timeout instead of raising a diagnostic, and because the state machine's "Stop
# instance" state sits downstream of this one it was never reached and the
# t3.large leaked. Both waits are now bounded by the clock.
EC2_WAITER_DELAY_SECONDS = 15

# Left for terminate_instances and for the state machine to receive the error.
CLEANUP_RESERVE_SECONDS = 60

# The EC2 status check is allowed at most this share of the remaining budget so
# that a slow booting instance cannot starve the SSM registration poll.
EC2_WAITER_BUDGET_SHARE = 0.6


# Used when the context cannot report a clock, so that the waits keep the
# behaviour they had before this budget was introduced rather than collapsing to
# a single attempt.
NO_CLOCK_BUDGET_SECONDS = (
    SSM_REGISTRATION_ATTEMPTS * SSM_REGISTRATION_POLL_SECONDS
)


def remaining_budget_seconds(context, reserve=CLEANUP_RESERVE_SECONDS):
    """Seconds of Lambda budget left, less a reserve for cleanup."""
    try:
        remaining_ms = int(context.get_remaining_time_in_millis())
    except Exception:
        return NO_CLOCK_BUDGET_SECONDS
    return max(0, int(remaining_ms / 1000) - reserve)


def terminate_builder_instance(ec2_client, instance_id):
    """Terminate the builder, never masking the error that caused this."""
    if not instance_id:
        return
    try:
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        logger.info(f"terminated kernel symbol builder instance {instance_id}")
    except Exception as termination_error:
        logger.error(
            "could not terminate kernel symbol builder instance "
            f"{instance_id}: {termination_error}"
        )


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
    """
    output_body = {}
    logger.info("event %s", redact(event))
    region = os.environ["AWS_REGION"]

    region = os.environ["AWS_REGION"]
    aws_account_id = context.invoked_function_arn.split(":")[4]

    try:
        s3bucket_name = os.environ["S3_BUCKET_NAME"]
        s3bucket_key_arn = os.environ["S3_BUCKET_KEY_ARN"]
        s3_role_arn = os.environ["S3_COPY_ROLE"]
        ssm_client_current_account = create_aws_client("ssm")
        ec2_client = create_aws_client("ec2")

        vpc_id = os.environ["VPC_ID"]
        ami_id = event["amiId"]

        distribution = event["distribution"]
        supported_dis = list(SUPPORTED_DISTRIBUTIONS)
        if distribution not in supported_dis:
            raise ValueError(
                "Invalid distribution value, supports"
                + ",".join(supported_dis)
            )

        # Only Red Hat needs subscription-manager credentials to reach the
        # debuginfo repositories. Amazon Linux 2023 serves kernel-debuginfo
        # from the amazonlinux-debuginfo repo, so no credentials are required
        # and the symbol document does not declare those parameters.
        requires_subscription = distribution.startswith("RHEL")
        username = event.get("username")
        password = event.get("password")
        if requires_subscription and not (username and password):
            raise ValueError(
                f"distribution {distribution} requires username and password"
                " for the Red Hat subscription manager"
            )

        # Resolved before anything is launched. This handler never terminates
        # the instance it starts, so a KeyError here after run_instances leaves
        # a builder running for as long as the account owner takes to notice.
        document_env_var = SYMBOL_DOCUMENT_ENV_VARS[distribution]
        try:
            document_name = os.environ[document_env_var]
        except KeyError:
            # The distribution is in the table but the CDK did not wire the
            # document. Say which variable is missing rather than surfacing a
            # bare KeyError on a name the reader cannot place.
            raise ValueError(
                f"{distribution} is supported but {document_env_var} is not set"
                " - the SSM document for it was not deployed"
            )

        instance_profile_arn = os.environ["FORENSIC_INSTANCE_PROFILE"]
        # forensic_subnet_id raises SubnetNotFound naming the VPC and the tag rather
        # than IndexError on an empty list. An empty list is the normal case when the
        # solution is pointed at an existing VPC: those subnets were not created by
        # this app and so carry no aws-cdk:subnet-name tag.
        subnet_id = forensic_subnet_id(ec2_client, vpc_id)
        # spin up instance to get correct symbol file
        ec2_response = ec2_client.run_instances(
            ImageId=ami_id,
            MaxCount=1,
            MinCount=1,
            SubnetId=subnet_id,
            InstanceType="t3.large",
            Placement={"Tenancy": "default"},
            Monitoring={"Enabled": False},
            DisableApiTermination=False,
            InstanceInitiatedShutdownBehavior="stop",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "forensic-kernel-loader-instance",
                        },
                        {"Key": "InstanceType", "Value": "FORENSIC"},
                    ],
                },
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "forensic-set-up",
                        },
                        {"Key": "InstanceType", "Value": "FORENSIC"},
                    ],
                },
            ],
            EbsOptimized=True,
            IamInstanceProfile={"Arn": instance_profile_arn},
        )

        logger.info(ec2_response)
        instance_id = ec2_response["Instances"][0]["InstanceId"]

        logger.info(instance_id)

        # Everything from here on can fail with a running builder, so any
        # failure terminates it before the error propagates. The success path
        # deliberately leaves it running: the state machine hands the instance
        # id to its own "Stop instance" state once the build finishes.
        try:
            return start_symbol_build(
                context=context,
                ec2_client=ec2_client,
                ssm_client_current_account=ssm_client_current_account,
                instance_id=instance_id,
                document_name=document_name,
                region=region,
                aws_account_id=aws_account_id,
                s3bucket_name=s3bucket_name,
                s3bucket_key_arn=s3bucket_key_arn,
                s3_role_arn=s3_role_arn,
                requires_subscription=requires_subscription,
                username=username,
                password=password,
                output_body=output_body,
            )
        except Exception:
            terminate_builder_instance(ec2_client, instance_id)
            raise

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        raise e


def start_symbol_build(
    context,
    ec2_client,
    ssm_client_current_account,
    instance_id,
    document_name,
    region,
    aws_account_id,
    s3bucket_name,
    s3bucket_key_arn,
    s3_role_arn,
    requires_subscription,
    username,
    password,
    output_body,
):
    """Wait for the builder to become usable and start the symbol build."""
    is_ssm_installed = False

    waiter = ec2_client.get_waiter("instance_status_ok")
    ec2_budget = int(
        remaining_budget_seconds(context) * EC2_WAITER_BUDGET_SHARE
    )
    waiter.wait(
        InstanceIds=[instance_id],
        WaiterConfig={
            "Delay": EC2_WAITER_DELAY_SECONDS,
            "MaxAttempts": max(1, ec2_budget // EC2_WAITER_DELAY_SECONDS),
        },
    )

    if wait_for_ssm_registration(
        ssm_client_current_account, instance_id, context
    ):
        is_ssm_installed = True
        output_body["SSM_STATUS"] = "SUCCEEDED"

    logger.info("output %s", redact(output_body))

    if not is_ssm_installed:
        raise RuntimeError("SSM Not installed")

    sts = create_aws_client("sts")

    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3LeastPrivilege",
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": [f"arn:aws:s3:::{s3bucket_name}/*"],
            },
            {
                "Sid": "GenerateKMSDataKey",
                "Effect": "Allow",
                "Action": ["kms:GenerateDataKey*", "kms:Decrypt"],
                "Resource": [s3bucket_key_arn],
            },
        ],
    }
    logger.info(
        {
            "message": "Assuming s3 Copy Role with session policy",
            "SessionPolicy": session_policy,
        }
    )

    tokens = sts.assume_role(
        RoleArn=s3_role_arn,
        RoleSessionName="{}-s3copy".format(str(uuid.uuid4())),
        DurationSeconds=3600,
        Policy=json.dumps(session_policy),
    )["Credentials"]

    params = {
        "AccessKeyId": [tokens["AccessKeyId"]],
        "SecretAccessKey": [tokens["SecretAccessKey"]],
        "SessionToken": [tokens["SessionToken"]],
        "Region": [region],
        "s3bucket": [s3bucket_name],
        "ExecutionTimeout": ["3600"],
    }
    if requires_subscription:
        #  TODO move to config and scret mgr
        params["SubscriptionManagerUsername"] = [username]
        params["SubscriptionManagerPassword"] = [password]
    response = ssm_client_current_account.send_command(
        InstanceIds=[instance_id],
        DocumentName=f"arn:aws:ssm:{region}:{aws_account_id}:document/{document_name}",
        Comment="Forensic Tools upload for " + instance_id,
        Parameters=params,
        CloudWatchOutputConfig={
            "CloudWatchLogGroupName": ssm_output_log_group("forensictools"),
            "CloudWatchOutputEnabled": True,
        },
    )
    logger.info("output %s", redact(output_body))

    ssm_command_id = response["Command"]["CommandId"]
    output_body["CommandId"] = ssm_command_id
    output_body["InstanceId"] = instance_id

    return create_response(200, output_body)


def wait_for_ssm_registration(ssm_client, instance_id, context=None):
    """Poll until the SSM agent on the builder reports PingStatus Online.

    Returns the managed node entry, or None if it never came Online.

    Bounded by whatever Lambda budget is left as well as by
    SSM_REGISTRATION_ATTEMPTS, so that this poll cannot be the thing that walks
    the handler into its timeout - which would skip the terminate in the caller
    and leak the builder.
    """
    attempts = SSM_REGISTRATION_ATTEMPTS
    if context is not None:
        affordable = (
            remaining_budget_seconds(context) // SSM_REGISTRATION_POLL_SECONDS
        )
        attempts = max(1, min(attempts, affordable))

    for attempt in range(attempts):
        builder_info = describe_builder_instance(ssm_client, instance_id)
        if builder_info and builder_info.get("PingStatus") == "Online":
            return builder_info
        if attempt + 1 < attempts:
            time.sleep(SSM_REGISTRATION_POLL_SECONDS)
    return None


def describe_builder_instance(ssm_client, instance_id):
    """Look the builder up in Systems Manager by instance id.

    Delegates to common.managed_nodes.describe_node, which filters by instance id
    and paginates. Four handlers had their own copy of this and two others did
    not, which is how the unfiltered form survived in the disk investigation and
    the instance status check.
    """
    return describe_node(ssm_client, instance_id)
