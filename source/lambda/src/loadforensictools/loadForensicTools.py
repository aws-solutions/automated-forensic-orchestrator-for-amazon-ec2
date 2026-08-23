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

import boto3
from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import WaiterError

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response, ssm_output_log_group
from ..common.log import get_logger
from ..common.redact import redact
from ..common.vpc_lookup import forensic_subnet_id
from ..common.managed_nodes import describe_node
from ..customaction.createCustomAction import send_status_to_cfn

# initialise loggers
logger = get_logger(__name__)

# S3 prefixes the two builder SSM documents upload into. The memory
# acquisition and analysis documents read these objects back months after the
# deployment, so an unusable object here silently degrades a real
# investigation rather than failing at deployment time.
#
# volatility3/symbols/ is deliberately NOT in this list even though the builder
# seeds one object into it. That prefix is owned by the kernel symbol state
# machine, which appends one symbol table per kernel release for the life of the
# deployment (forensic-solution-builder-stack.ts sets VOLATILITY2_PROFILES_PREFIX
# to it). Verifying it here made the custom resource fail on any zero byte object
# under it from any past on-demand build - and, because BuildVersion sends this
# resource an Update on every version bump, that turned one historical failed
# symbol build into UPDATE_FAILED on the next upgrade while delete-markering an
# object in the evidence bucket on the way. The symbol table that matters for an
# investigation is the per kernel release one built on demand, not the seed.
TOOL_ARTIFACT_PREFIXES = (
    "tools/LiME/",
    "tools/volatility3/",
)

# botocore's command_executed waiter defaults to 20 attempts every 5 seconds
# and therefore gives up after 100 seconds. Building LiME and running
# dwarf2json over a kernel debuginfo image takes far longer than that, so the
# default waiter always expired and the build outcome was never observed.
SSM_WAITER_DELAY_SECONDS = 15

# Held back from the Lambda budget so that the builder instance can always be
# terminated, the artifacts verified and CloudFormation signalled.
CLEANUP_RESERVE_SECONDS = 120

# GetCommandInvocation statuses the CommandExecuted waiter retries on. Seeing
# one of these when the waiter gives up means the build was still running when
# the Lambda budget ran out, which is not evidence that the build was bad.
COMMAND_IN_FLIGHT_STATUSES = ("Pending", "InProgress", "Delayed")

# instance_status_ok only proves the EC2 status checks passed; the SSM agent
# registers with Systems Manager afterwards, so a single read straight after
# that waiter routinely misses a builder that is perfectly healthy. Capped well
# below the Lambda budget so that a builder which never registers still leaves
# time to terminate it and signal CloudFormation.
SSM_REGISTRATION_POLL_SECONDS = 15
SSM_REGISTRATION_MAX_SECONDS = 300

# The EC2 status check is allowed at most this share of the remaining budget, so
# that it cannot starve the SSM registration poll or the cleanup reserve.
# botocore's own default for instance_status_ok is 15s x 40 = 600s.
EC2_WAITER_DELAY_SECONDS = 15
EC2_WAITER_BUDGET_SHARE = 0.5

# Tag carrying this invocation's RunInstances idempotency token, so that a
# builder whose launch response never came back can still be found and
# terminated. ec2:Terminate* is already scoped to InstanceType=FORENSIC, which
# every builder also carries.
BUILDER_INVOCATION_TAG_KEY = "ForensicToolsBuilderInvocation"

# An instance in any of these states is still billing and still has to go.
# "terminated" and "shutting-down" are deliberately absent.
BUILDER_LIVE_STATES = ("pending", "running", "stopping", "stopped")

# The builder documents to run, keyed by the platform SSM reports for the
# builder AMI. PlatformName alone cannot tell the two Amazon Linux releases
# apart - the agent reports "Amazon Linux" for both - so the key carries the
# version as well.
#
# Amazon Linux 2 cannot build a Volatility 3 symbol table at all any more: its
# system Python is 3.7 while volatility3 requires >= 3.8, and kernel-debuginfo
# is no longer published for current AL2 kernels now that AL2 has reached end
# of life. Its pair is kept so that an existing deployment still gets its LiME
# module and source zips, but Amazon Linux 2023 is the supported builder.
BUILDER_DOCUMENTS = {
    ("amazon linux", "2"): (
        ("AMAZON_LINUX_2_LIME_VOLATILITY_LOADER", "forensictools"),
        ("AMAZON_LINUX_2_VOLATILITY_PROFILE", "forensicprofilelaoder"),
    ),
    ("amazon linux", "2023"): (
        ("AL2023_LIME_VOLATILITY_LOADER", "forensictools"),
        # The same document kernelSymbolLoader runs for on demand symbol
        # builds, so there is one validated AL2023 symbol build rather than
        # two that can drift apart.
        ("AL2023_VOLATILITY_SYMBOL", "forensicprofilelaoder"),
    ),
}

# Resolves to the newest Amazon Linux 2023 x86_64 AMI in any region, and is
# quoted in the failure message so that fixing an unsupported builder AMI is a
# single cdk.json edit.
AL2023_AMI_PARAMETER = (
    "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
)


class ToolBuildIncomplete(Exception):
    """The builder was still working when the Lambda ran out of budget.

    Distinct from a build failure: nothing is known to be wrong, we simply
    stopped watching. 900 seconds is the Lambda maximum, so this cannot be
    fixed by raising the timeout.
    """


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """Lambda function handler backing the forensic tools custom resource.

    Nothing may escape this function. CloudFormation has no other way of
    learning the outcome, so an invocation that ends without a response leaves
    the stack in CREATE_IN_PROGRESS until the one hour custom resource timeout
    expires. Every exit path therefore funnels through exactly one
    signal_cloudformation call, and that helper cannot raise either.
    """
    logger.info("event %s", redact(event))
    physical_resource_id = resolve_physical_resource_id(event)

    try:
        status, response_data, output_body, reason = load_forensic_tools(
            event, context
        )
    except Exception as error:
        # Everything the loader needs to even start lives in here: the four
        # environment variables, and create_aws_client - whose
        # AWSCachedClient.__init__ makes a live sts:GetCallerIdentity call from
        # a private subnet before it hands back a client. A KeyError on a
        # missing variable or a connectivity failure building a client used to
        # escape the handler with no CloudFormation response at all.
        logger.error(
            {
                "isError": True,
                "type": error.__class__.__name__,
                "message": str(error),
            }
        )
        status = "FAILED"
        response_data = {}
        reason = (
            "forensic tools loader failed before the builder could be "
            f"started: {error.__class__.__name__}: {error}"
        )
        output_body = build_error_output(reason)

    signal_cloudformation(
        event, context, status, response_data, physical_resource_id, reason
    )
    return create_response(200 if status == "SUCCESS" else 500, output_body)


def resolve_physical_resource_id(event) -> str:
    """Physical resource id, resolved without being able to raise.

    send_status_to_cfn needs one before anything else can be reported, so this
    cannot be the thing that stops CloudFormation being signalled.
    """
    try:
        properties = event.get("ResourceProperties") or {}
        # str() because Id is whatever CloudFormation was given. A list or a
        # number made this concatenation raise TypeError, and because it runs
        # before the first try block that meant the handler exited with zero
        # signals sent - the one outcome the restructure exists to prevent.
        return "CustomAction" + str(properties.get("Id", "ERROR"))
    except Exception:
        return "CustomActionERROR"


def signal_cloudformation(
    event, context, status, response_data, physical_resource_id, reason
):
    """Send the one CloudFormation response this invocation is allowed to send.

    send_status_to_cfn already retries a failed presigned PUT and logs rather
    than propagating, but it is guarded again here because a second signal is
    not an option: whatever it still manages to raise can only be logged.
    """
    try:
        send_status_to_cfn(
            event,
            context,
            status,
            response_data,
            physical_resource_id,
            logger,
            reason=reason,
        )
    except Exception as error:
        logger.error(
            {
                "isError": True,
                "message": "could not signal CloudFormation; the stack will "
                "wait for the custom resource timeout",
                "type": error.__class__.__name__,
                "error": str(error),
            }
        )


def build_error_output(reason: str) -> dict:
    return {
        "errorName": "Error: Creating or loading tools",
        "errorDescription": reason,
        "errorPhase": "Forensic Tools",
        "errorComponentId": "loadForensicTools",
        "errorComponentType": "Lambda",
        "eventData": reason.replace('"', "-"),
    }


def load_forensic_tools(event, context):
    """Build the forensic tools and decide what to report.

    Returns (status, response_data, output_body, reason) rather than signalling
    CloudFormation itself, so that the handler above owns the single signal.
    """
    logger.debug(json.dumps(event.get("ResourceProperties") or {}))

    output_body: dict = {}
    response_data: dict = {}

    if event["RequestType"] not in ("Create", "Update"):
        return "SUCCESS", response_data, output_body, None

    partition, aws_account_id = parse_function_arn(context)
    config = {
        "region": os.environ["AWS_REGION"],
        "partition": partition,
        "aws_account_id": aws_account_id,
        "s3bucket_name": os.environ["S3_BUCKET_NAME"],
        "s3bucket_key_arn": os.environ["S3_BUCKET_KEY_ARN"],
        "s3_role_arn": os.environ["S3_COPY_ROLE"],
    }

    ec2_client = create_aws_client("ec2")
    ssm_client = create_aws_client("ssm")

    client_token = builder_client_token(event)

    instance_id = None
    build_error = None
    build_incomplete = None
    # Pre-initialised so that it can never be an unbound local, however the
    # finally block below turns out.
    termination_error = None
    try:
        instance_id = launch_builder_instance(ec2_client, client_token)
        build_forensic_tools(
            context,
            ec2_client,
            ssm_client,
            instance_id,
            config,
            output_body,
        )
    except ToolBuildIncomplete as error:
        build_incomplete = error
        logger.warning(
            {
                "message": "forensic tools build was still running when the "
                "Lambda budget ran out",
                "detail": str(error),
            }
        )
    except Exception as error:
        build_error = error
        logger.error(
            {
                "isError": True,
                "type": error.__class__.__name__,
                "message": str(error),
            }
        )
    finally:
        # The builder cannot upload anything more once it is gone, so this has
        # to run before the artifacts are inspected below.
        # terminate_builder_instances swallows every exception, which is what
        # keeps this finally block from replacing build_error with a cleanup
        # error and losing the build failure entirely.
        termination_error = terminate_builder_instances(
            ec2_client, instance_id, client_token
        )

    artifact_problems: list = []
    artifact_warnings: list = []
    verification_error = None
    try:
        artifact_problems, artifact_warnings = verify_tool_artifacts(config)
    # Bare Exception, matching terminate_builder_instances. A non-boto error
    # here used to escape load_forensic_tools entirely, so the handler's
    # generic except discarded the build failure and every artifact problem and
    # reported "failed before the builder could be started" instead.
    except Exception as error:
        verification_error = error
        logger.error(
            {
                "isError": True,
                "message": "forensic tool artifacts could not be verified",
                "type": error.__class__.__name__,
                "error": str(error),
            }
        )

    if build_incomplete:
        # 900 seconds is the Lambda ceiling, so this is not a tunable. The
        # builder is terminated immediately below, which means whatever it had
        # already uploaded is exactly what the artifact check inspects: the
        # bucket state is the ground truth here, not the waiter.
        response_data["ToolBuildIncomplete"] = str(build_incomplete)
        output_body["toolBuildIncomplete"] = str(build_incomplete)

    if artifact_warnings:
        # An absent artifact is not a poisoned one. Both consumers already
        # fall back - the investigation document clones volatility3 and the
        # acquisition document rebuilds LiME on the target - and the symbol
        # table that actually matters is the per kernel release one the
        # profile state machine builds on demand, not the builder's own. So
        # a cache that was never warmed is reported, not rolled back.
        logger.warning(
            {
                "message": "forensic tools were not pre-seeded into the "
                "evidence bucket",
                "warnings": artifact_warnings,
            }
        )
        response_data["ToolArtifactWarnings"] = "; ".join(artifact_warnings)
        output_body["toolArtifactWarnings"] = artifact_warnings

    if termination_error:
        # A leaked builder instance costs money and widens the blast radius,
        # but it does not make the pre-seeded artifacts unusable, so it is
        # reported loudly instead of rolling the whole stack back.
        response_data["BuilderInstanceTerminationError"] = str(
            termination_error
        )
        output_body["builderInstanceTerminationError"] = str(termination_error)

    failures = []
    # Anything that changed the evidence bucket comes first. send_status_to_cfn
    # truncates the reason to 255 characters, and the record that an object was
    # removed from - or knowingly left broken in - the evidence bucket is the
    # one fact that has to survive that truncation; a build stack trace is
    # recoverable from the log stream the reason already points at.
    failures.extend(artifact_problems)
    if build_error:
        failures.append(
            "forensic tools build failed with "
            f"{build_error.__class__.__name__}: {build_error}"
        )
    if verification_error:
        failures.append(
            "forensic tool artifacts could not be verified: "
            f"{verification_error}"
        )

    if failures:
        reason = "; ".join(failures)
        output_body.update(build_error_output(reason))
        logger.error(
            {
                "isError": True,
                "message": "forensic tools loader reporting FAILED to "
                "CloudFormation",
                "reason": reason,
            }
        )
        return "FAILED", response_data, output_body, reason

    # A SUCCESS that carries warnings still has to say so. CloudFormation shows
    # the reason on the stack event; with reason=None the operator sees only
    # "See details in CloudWatch Log Stream", so a fresh deployment whose build
    # ran out of budget - or which pre-seeded nothing at all - reached
    # CREATE_COMPLETE with no visible indication that the tool cache is empty.
    advisories = []
    if response_data.get("ToolBuildIncomplete"):
        advisories.append(str(response_data["ToolBuildIncomplete"]))
    if response_data.get("ToolArtifactWarnings"):
        advisories.append(str(response_data["ToolArtifactWarnings"]))
    if advisories:
        # CloudFormation truncates Reason at 255 characters.
        return (
            "SUCCESS",
            response_data,
            output_body,
            "; ".join(advisories)[:255],
        )

    return "SUCCESS", response_data, output_body, None


def parse_function_arn(context):
    """Partition and account id, both taken from this function's own ARN.

    The partition cannot be hardcoded to "aws": in aws-cn and aws-us-gov the
    session policies below would then name resources in a partition that does
    not exist, granting nothing, so every S3 call would be denied and the
    resource would fail on every deployment. Nothing sets AWS_PARTITION on this
    function's environment, and the invoked function ARN is already parsed here
    for the account id, so it is the reliable source for both.
    """
    arn_parts = context.invoked_function_arn.split(":")
    return arn_parts[1], arn_parts[4]


def builder_client_token(event) -> str:
    """Deterministic RunInstances idempotency token for this request.

    CloudFormation invokes custom resource Lambdas asynchronously and the
    Lambda service retries an asynchronous invocation that errors or times out.
    Each retry is a separate invocation, so botocore's own auto generated token
    - which it does reuse across the retries inside one call - does not stop a
    retry from launching a second builder and orphaning the first. The
    CloudFormation RequestId is stable across those retries, so keying the token
    off it makes the retry return the instance the first invocation launched.

    RunInstances allows at most 64 ASCII characters and a RequestId is a 36
    character UUID, so the prefix that makes the token recognisable in
    CloudTrail still fits.
    """
    return "forensic-tools-" + event["RequestId"]


def launch_builder_instance(ec2_client, client_token: str) -> str:
    """Launch the throw away instance the forensic tools are built on."""
    vpc_id = os.environ["VPC_ID"]
    ami_id = os.environ["AMI_ID"]
    instance_profile_arn = os.environ["FORENSIC_INSTANCE_PROFILE"]

    # forensic_subnet_id raises SubnetNotFound naming the VPC and the tag rather
    # than IndexError on an empty list. An empty list is the normal case when the
    # solution is pointed at an existing VPC: those subnets were not created by
    # this app and so carry no aws-cdk:subnet-name tag.
    subnet_id = forensic_subnet_id(ec2_client, vpc_id)
    ec2_response = ec2_client.run_instances(
        ImageId=ami_id,
        MaxCount=1,
        MinCount=1,
        SubnetId=subnet_id,
        ClientToken=client_token,
        # Matches kernelSymbolLoader, which runs the same dwarf2json over
        # kernel debuginfo workload. t3.small gives this 2 GiB and a 20%
        # CPU credit baseline, which is why the build never finished inside
        # the waiter; the Lambda ceiling of 900 seconds cannot be raised, so
        # the only lever left is making the build faster.
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
                        "Value": "forensic-test-instance",
                    },
                    {"Key": "InstanceType", "Value": "FORENSIC"},
                    # Load bearing, not bookkeeping: this is the only way to
                    # find a builder whose launch response never came back.
                    {
                        "Key": BUILDER_INVOCATION_TAG_KEY,
                        "Value": client_token,
                    },
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
    return instance_id


def terminate_builder_instances(ec2_client, instance_id, client_token):
    """Terminate this invocation's builders, returning the error not raising it.

    Called from a finally block on both the success and the failure path, so it
    must never raise. An exception escaping a finally block replaces the
    original build error with itself, which is why every handler here is
    "except Exception" rather than "except (BotoCoreError, ClientError)": a
    TypeError, an AttributeError or a MemoryError from the cleanup would
    otherwise discard the build failure and, before the handler was restructured,
    leave CloudFormation unsignalled as well.

    The known instance id is not enough on its own. If RunInstances launched
    the instance and the response was then lost, this invocation has no id for
    an instance that is running and billing, so the invocation tag is swept as
    well.
    """
    instance_ids = set()
    if instance_id:
        instance_ids.add(instance_id)

    error = None
    try:
        instance_ids.update(find_builder_instances(ec2_client, client_token))
    except Exception as sweep_error:
        error = sweep_error
        logger.error(
            {
                "isError": True,
                "message": "could not sweep for orphaned forensic tools "
                "builder instances",
                "clientToken": client_token,
                "type": sweep_error.__class__.__name__,
                "error": str(sweep_error),
            }
        )

    if not instance_ids:
        return error

    try:
        logger.info(
            {
                "message": "terminating forensic tools builder instances",
                "instanceIds": sorted(instance_ids),
            }
        )
        ec2_client.terminate_instances(InstanceIds=sorted(instance_ids))
    except Exception as terminate_error:
        logger.error(
            {
                "isError": True,
                "message": "failed to terminate forensic tools builder "
                "instances",
                "instanceIds": sorted(instance_ids),
                "type": terminate_error.__class__.__name__,
                "error": str(terminate_error),
            }
        )
        return terminate_error
    return error


def find_builder_instances(ec2_client, client_token: str) -> set:
    """Ids of instances this invocation launched that are still alive."""
    found = set()
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[
            {
                "Name": f"tag:{BUILDER_INVOCATION_TAG_KEY}",
                "Values": [client_token],
            },
            {
                "Name": "instance-state-name",
                "Values": list(BUILDER_LIVE_STATES),
            },
        ]
    ):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                found.add(instance["InstanceId"])
    return found


def build_forensic_tools(
    context, ec2_client, ssm_client, instance_id, config, output_body
):
    """Run both builder SSM documents on the instance and wait for them."""
    waiter = ec2_client.get_waiter("instance_status_ok")
    # Bounded by the clock. botocore's default is 15s x 40 = 600s, two thirds of
    # the Lambda budget, and unlike the SSM poll below this waiter never
    # consulted remaining_budget_seconds - so CLEANUP_RESERVE_SECONDS was only
    # honoured by accident, and a slow booting builder could walk the invocation
    # into its timeout with no signal sent at all.
    status_budget = int(
        remaining_budget_seconds(context) * EC2_WAITER_BUDGET_SHARE
    )
    waiter.wait(
        InstanceIds=[instance_id],
        WaiterConfig={
            "Delay": EC2_WAITER_DELAY_SECONDS,
            "MaxAttempts": max(1, status_budget // EC2_WAITER_DELAY_SECONDS),
        },
    )

    builder_info = wait_for_ssm_registration(
        ssm_client, context, instance_id, output_body
    )
    logger.info("output %s", redact(output_body))

    # The same call that proves the agent is up also reports what the builder
    # is running, so no extra API call or AMI convention is needed to pick the
    # documents that can actually build on it.
    documents = select_builder_documents(builder_info)
    # Resolved before the first command is sent, so that a document which was
    # never deployed fails the same way whether it is the first or the second in
    # the pair, instead of half building and then raising KeyError.
    document_names = [
        (os.environ[env_var], log_group) for env_var, log_group in documents
    ]

    params = build_document_parameters(config)

    for document_name, log_group in document_names:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="arn:{}:ssm:{}:{}:document/{}".format(
                config["partition"],
                config["region"],
                config["aws_account_id"],
                document_name,
            ),
            Comment="Forensic Tools upload for " + instance_id,
            Parameters=params,
            CloudWatchOutputConfig={
                "CloudWatchLogGroupName": ssm_output_log_group(log_group),
                "CloudWatchOutputEnabled": True,
            },
        )
        wait_for_command(
            ssm_client, context, response["Command"]["CommandId"], instance_id
        )


def wait_for_ssm_registration(ssm_client, context, instance_id, output_body):
    """Poll until the SSM agent on the builder reports PingStatus Online.

    instance_status_ok only proves the EC2 status checks passed; the agent
    registers with Systems Manager afterwards, so reading
    describe_instance_information once straight after that waiter routinely
    misses a healthy builder and used to roll the whole stack back with
    "SSM Not installed". Bounded by the same Lambda budget the command waiter
    uses so that the cleanup reserve is still honoured.
    """
    budget_seconds = min(
        SSM_REGISTRATION_MAX_SECONDS, remaining_budget_seconds(context)
    )
    attempts = max(1, budget_seconds // SSM_REGISTRATION_POLL_SECONDS)

    builder_info = None
    for attempt in range(attempts):
        builder_info = describe_builder_instance(ssm_client, instance_id)
        if builder_info and builder_info.get("PingStatus") == "Online":
            output_body["SSM_STATUS"] = "SUCCEEDED"
            return builder_info
        if attempt + 1 < attempts:
            time.sleep(SSM_REGISTRATION_POLL_SECONDS)

    raise RuntimeError(
        "SSM Not installed: the agent on forensic tools builder {} did not "
        "report PingStatus Online within {} seconds, last seen {}".format(
            instance_id,
            budget_seconds,
            (builder_info or {}).get("PingStatus", "not registered at all"),
        )
    )


def describe_builder_instance(ssm_client, instance_id):
    """Look the builder up in Systems Manager by instance id.

    Delegates to common.managed_nodes.describe_node, which filters by instance id
    and paginates. Four handlers had their own copy of this and two others did
    not, which is how the unfiltered form survived in the disk investigation and
    the instance status check.
    """
    return describe_node(ssm_client, instance_id)


def remaining_budget_seconds(context) -> int:
    """Seconds left in this invocation once the cleanup reserve is held back."""
    return max(
        0,
        int(context.get_remaining_time_in_millis() / 1000)
        - CLEANUP_RESERVE_SECONDS,
    )


def select_builder_documents(builder_info: dict) -> tuple:
    """Pick the builder documents for the platform the builder reports.

    Raises RuntimeError for anything but Amazon Linux 2 or 2023. Falling back
    to the Amazon Linux 2 pair is what made the original defect silent: on
    Amazon Linux 2023 those commands run, exit 0 and upload nothing, so the
    deployment reached CREATE_COMPLETE with an empty tool cache.
    """
    platform_name = builder_info.get("PlatformName") or ""
    platform_version = builder_info.get("PlatformVersion") or ""
    # Amazon Linux 2 reports "2" and Amazon Linux 2023 reports "2023", both
    # taken from VERSION_ID in /etc/os-release. Keeping only the major
    # component means a point release would still be recognised instead of
    # rolling the stack back.
    documents = BUILDER_DOCUMENTS.get(
        (
            platform_name.strip().lower(),
            platform_version.strip().split(".")[0],
        )
    )
    if documents is None:
        raise RuntimeError(
            "forensic tools builder AMI {} reports platform '{} {}', which "
            "has no forensic tool builder documents. Only Amazon Linux 2 and "
            "Amazon Linux 2023 are supported. Point the toolsAMI entry for "
            "this region in cdk.json at an Amazon Linux 2023 AMI, for example "
            "the current value of the public SSM parameter {}.".format(
                os.environ.get("AMI_ID", "unknown"),
                platform_name or "unknown",
                platform_version or "unknown",
                AL2023_AMI_PARAMETER,
            )
        )

    logger.info(
        {
            "message": "selected forensic tool builder documents",
            "platformName": platform_name,
            "platformVersion": platform_version,
            "documents": [
                os.environ.get(env_var, "unset:" + env_var)
                for env_var, _ in documents
            ],
        }
    )
    return documents


def build_document_parameters(config) -> dict:
    """Assume the copy role and build the SSM document parameters.

    These credentials are handed to the builder instance as plain SSM document
    parameters, so the session policy stays write only.
    """
    tokens = assume_s3_copy_role(
        config["s3_role_arn"],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3LeastPrivilege",
                    "Effect": "Allow",
                    "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                    "Resource": [
                        "arn:{}:s3:::{}/*".format(
                            config["partition"], config["s3bucket_name"]
                        )
                    ],
                },
                {
                    "Sid": "GenerateKMSDataKey",
                    "Effect": "Allow",
                    "Action": ["kms:GenerateDataKey*", "kms:Decrypt"],
                    "Resource": [config["s3bucket_key_arn"]],
                },
            ],
        },
    )

    return {
        "AccessKeyId": [tokens["AccessKeyId"]],
        "SecretAccessKey": [tokens["SecretAccessKey"]],
        "SessionToken": [tokens["SessionToken"]],
        "Region": [config["region"]],
        "s3bucket": [config["s3bucket_name"]],
        "ExecutionTimeout": ["3600"],
    }


def assume_s3_copy_role(s3_role_arn: str, session_policy: dict) -> dict:
    sts = create_aws_client("sts")
    logger.info(
        {
            "message": "Assuming s3 Copy Role with session policy",
            "SessionPolicy": session_policy,
        }
    )
    return sts.assume_role(
        RoleArn=s3_role_arn,
        RoleSessionName="{}-s3copy".format(str(uuid.uuid4())),
        DurationSeconds=3600,
        Policy=json.dumps(session_policy),
    )["Credentials"]


def wait_for_command(ssm_client, context, command_id, instance_id):
    """Wait for an SSM command and raise unless it reached Success.

    Raises ToolBuildIncomplete if the command was still running when the
    budget ran out, and RuntimeError if it reached a terminal non-Success
    status. Only the second is evidence that the build itself was bad.

    The budget comes from the Lambda's own remaining time rather than from the
    botocore default, which expires after 100 seconds and so never observed
    the outcome of a build that takes minutes.
    """
    budget_seconds = max(
        SSM_WAITER_DELAY_SECONDS, remaining_budget_seconds(context)
    )
    waiter = ssm_client.get_waiter("command_executed")
    try:
        waiter.wait(
            CommandId=command_id,
            InstanceId=instance_id,
            WaiterConfig={
                "Delay": SSM_WAITER_DELAY_SECONDS,
                "MaxAttempts": budget_seconds // SSM_WAITER_DELAY_SECONDS,
            },
        )
    except WaiterError as error:
        # botocore records the last GetCommandInvocation response on the
        # error, and the waiter's retry acceptors are exactly the in flight
        # statuses, so Status separates "we stopped watching" from "the
        # command failed" structurally rather than by parsing the message. It
        # is at most one Delay stale, which cannot change the verdict: a build
        # that failed inside that window either uploaded a poisoned artifact,
        # which verify_tool_artifacts still fails on, or uploaded nothing,
        # which is a warning either way. An absent Status means the
        # invocation never resolved, which is a real failure.
        status = (error.last_response or {}).get("Status", "Unknown")
        message = (
            "SSM command {} on {} did not reach Success, last status {}: {}"
        ).format(command_id, instance_id, status, error)
        if status in COMMAND_IN_FLIGHT_STATUSES:
            raise ToolBuildIncomplete(message) from error
        raise RuntimeError(message) from error


def verify_tool_artifacts(config):
    """Report unusable objects under the tool prefixes.

    Returns (problems, warnings). A problem is an artifact that would poison an
    investigation; a warning is only an artifact that is absent.

    A failed dwarf2json run still leaves a zero byte symbol file behind, the
    document uploads it and then exits 0, so an artifact that merely exists is
    not evidence of a usable build.
    """
    s3bucket_name = config["s3bucket_name"]
    s3_client = create_artifact_s3_client(config)

    problems = []
    warnings = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for prefix in TOOL_ARTIFACT_PREFIXES:
        usable = 0
        for page in paginator.paginate(Bucket=s3bucket_name, Prefix=prefix):
            for item in page.get("Contents", []):
                key = item["Key"]
                # A console created folder marker is a zero byte object that
                # no document ever reads, so it is not a build problem.
                if key.endswith("/"):
                    continue
                if item["Size"] > 0:
                    usable += 1
                    continue
                try:
                    problems.append(
                        handle_unusable_artifact(s3_client, s3bucket_name, key)
                    )
                # Bare Exception for the same reason: this must never unwind,
                # whatever the cause.
                except Exception as error:
                    # One key that cannot be inspected or removed must not
                    # unwind this function: that would discard the problems
                    # already found and skip every remaining prefix, turning a
                    # partial failure into silence about everything after it.
                    logger.error(
                        {
                            "isError": True,
                            "message": "could not handle unusable forensic "
                            "tool artifact",
                            "bucket": s3bucket_name,
                            "key": key,
                            "type": error.__class__.__name__,
                            "error": str(error),
                        }
                    )
                    problems.append(
                        "unusable zero byte artifact "
                        f"s3://{s3bucket_name}/{key} could not be handled: "
                        f"{error}"
                    )
        if usable == 0:
            warnings.append(
                f"no artifact pre-seeded under s3://{s3bucket_name}/{prefix}"
            )
    return problems, warnings


def handle_unusable_artifact(s3_client, s3bucket_name, key) -> str:
    """Deal with a zero byte artifact and return the problem to report.

    A DELETE without a VersionId is not the harmless, audit preserving operation
    it looks like. On a versioned bucket it inserts a delete marker that becomes
    the current version, and a plain GetObject then returns 404 for that key no
    matter how many good versions sit underneath it - which is exactly how
    lime-memory-load-investigation.json reads the table, with a plain
    "aws s3 cp" and no version id. volatility3/symbols/ is cumulative, one
    object per kernel release written by the on demand profile state machine, so
    delete markering a key whose previous version is a valid symbol table
    destroys a working investigation path.

    So the delete marker only goes in when no usable version of the key exists.
    Otherwise the key is left alone and the zero byte current version is
    reported instead; either way the artifact still fails the resource, which is
    the property that makes the zero byte check worth having.
    """
    usable_version_id = find_usable_object_version(
        s3_client, s3bucket_name, key
    )
    if usable_version_id:
        logger.error(
            {
                "isError": True,
                "message": "zero byte forensic tool artifact is the current "
                "version of a key that still has a usable earlier version, so "
                "the key is left alone rather than delete markered",
                "bucket": s3bucket_name,
                "key": key,
                "usableVersionId": usable_version_id,
            }
        )
        return (
            f"unusable zero byte artifact s3://{s3bucket_name}/{key} is the "
            f"current version and was kept, because version "
            f"{usable_version_id} of that key is still usable"
        )

    logger.error(
        {
            "isError": True,
            "message": "removing unusable zero byte forensic tool artifact",
            "bucket": s3bucket_name,
            "key": key,
        }
    )
    s3_client.delete_object(Bucket=s3bucket_name, Key=key)
    return f"removed unusable zero byte artifact s3://{s3bucket_name}/{key}"


def find_usable_object_version(s3_client, s3bucket_name, key):
    """VersionId of a non empty version of this exact key, if there is one.

    Prefix is the closest ListObjectVersions has to an exact key match, so keys
    that merely start with this one are filtered out. On an unversioned bucket
    the only version returned is the current zero byte object, which correctly
    yields None and lets the delete go ahead.
    """
    paginator = s3_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=s3bucket_name, Prefix=key):
        for version in page.get("Versions", []):
            if version.get("Key") != key:
                continue
            if version.get("Size", 0) > 0:
                return version.get("VersionId")
    return None


def create_artifact_s3_client(config):
    """S3 client for artifact verification.

    The Lambda execution role has no S3 access of its own, so the copy role is
    assumed a second time. This session policy is separate from the write only
    one handed to the builder instance so that the instance never receives
    delete permissions on the evidence bucket.
    """
    s3bucket_name = config["s3bucket_name"]
    partition = config["partition"]
    tokens = assume_s3_copy_role(
        config["s3_role_arn"],
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ListToolArtifacts",
                    "Effect": "Allow",
                    # ListBucketVersions is what makes it possible to tell a
                    # zero byte object that is hiding a good earlier version
                    # from one that is all there is.
                    "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
                    "Resource": [f"arn:{partition}:s3:::{s3bucket_name}"],
                },
                {
                    "Sid": "RemoveUnusableToolArtifacts",
                    "Effect": "Allow",
                    "Action": ["s3:DeleteObject"],
                    "Resource": [
                        f"arn:{partition}:s3:::{s3bucket_name}/{prefix}*"
                        for prefix in TOOL_ARTIFACT_PREFIXES
                    ],
                },
            ],
        },
    )
    return boto3.client(
        "s3",
        region_name=config["region"],
        aws_access_key_id=tokens["AccessKeyId"],
        aws_secret_access_key=tokens["SecretAccessKey"],
        aws_session_token=tokens["SessionToken"],
    )
