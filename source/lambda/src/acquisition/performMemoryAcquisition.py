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
import uuid

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import (
    clean_date_format,
    create_response,
    ssm_output_log_group,
)
from ..common.exception import MemoryAcquisitionError
from ..common.log import get_logger
from ..common.redact import redact
from ..common.managed_nodes import online_node_ids
from ..common.platform_dispatch import platform_of, resolve_document
from ..common.node_processing import (
    normalize_instance_ids,
    normalize_instance_info,
)
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)

instance_id = ""


# DescribeInstanceInformation returns 10 managed nodes per page by default and
# 50 at most, and the InstanceIds filter itself accepts at most 50 values.
SSM_DESCRIBE_MAX_FILTER_VALUES = 50


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """
    Lambda function handler for performing memory Forensics - Memory acquisition
    """
    # implementation Payload
    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    output_body["forensicType"] = ForensicCategory.MEMORY.value
    forensic_id = input_body["forensicId"]
    app_account_region = input_body.get("instanceRegion")

    region = os.environ["AWS_REGION"]
    s3bucket_name = os.environ["S3_BUCKET_NAME"]
    s3bucket_key_arn = os.environ["S3_BUCKET_KEY_ARN"]
    s3_role_arn = os.environ["S3_COPY_ROLE"]
    # is_ssm_installed = False
    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=(
            True
            if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
            else False
        ),
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )

    try:
        forensic_record = fds.update_forensic_record_phase_status(
            id=forensic_id,
            memory=(
                ForensicsProcessingPhase.ACQUISITION,
                "Beginning memory acquisition",
            ),
        )
        ssm_client_current_account = create_aws_client("ssm")

        app_account_id = input_body.get("instanceAccount")
        current_account = context.invoked_function_arn.split(":")[4]

        app_account_role = os.environ["APP_ACCOUNT_ROLE"]
        ssm_client = create_aws_client(
            "ssm",
            current_account=current_account,
            target_account=app_account_id,
            target_region=app_account_region,
            app_account_role=app_account_role,
        )

        # Normalize instance IDs to always work with a list
        if "clusterInfo" in input_body:
            instance_ids = normalize_instance_ids(
                input_body.get("clusterInfo").get("affectedNode")
            )
        else:
            instance_ids = normalize_instance_ids(forensic_record.resourceId)

        if not instance_ids:
            raise MemoryAcquisitionError("No valid instance IDs provided")

        # Read for the parameter guards below, which compare the *resolved*
        # document against these two. There is deliberately no pre-loop default
        # any more: a default is what let the previous instance's document be
        # reused for the next one.
        linux_memory_acquisition_document_name = os.environ[
            "LINUX_LIME_MEMORY_ACQUISITION"
        ]
        windows_memory_acquisition_document_name = os.environ[
            "WINDOWS_LIME_MEMORY_ACQUISITION"
        ]

        logger.info("Lambda running")

        output_body["forensicId"] = forensic_id
        output_body["ForensicInstanceIds"] = instance_ids
        output_body["InstanceResults"] = {}

        # platform_name = input_body.get("instanceInfo").get("PlatformName")
        # platform_detail = input_body.get("instanceInfo").get("PlatformDetails")

        # platform_version = input_body.get("instanceInfo").get(
        #     "PlatformVersion"
        # )

        # Normalize instance info to always work with a dictionary
        instances_info = normalize_instance_info(
            input_body.get("instanceInfo")
        )

        logger.info(
            f"Instance Info for all the affected instance is {instances_info}"
        )

        ssm_enabled_instances = {}
        for instance_id in sorted(online_node_ids(ssm_client, instance_ids)):
            ssm_enabled_instances[instance_id] = True
            output_body["InstanceResults"][instance_id] = {
                "SSM_STATUS": "SUCCEEDED"
            }

        # if platform_detail == "Windows":
        #     memory_acquisition_document_name = (
        #         windows_memory_acquisition_document_name
        #     )
        # elif platform_name == "Red Hat Enterprise Linux":
        #     if 10 > float(platform_version) > 9:
        #         rhel_version = "9"
        #     if 9 > float(platform_version) > 8:
        #         rhel_version = "8"
        #     if 8 > float(platform_version) > 7:
        #         rhel_version = "7"
        #     memory_acquisition_document_name = os.environ[
        #         "RHEL" + rhel_version + "_LIME_MEMORY_ACQUISITION"
        #     ]

        for instance_id in instance_ids:
            try:
                if not ssm_enabled_instances.get(instance_id):
                    output_body["InstanceResults"][instance_id] = {
                        "SSM_STATUS": "FAILED",
                        "error": "SSM not installed",
                    }
                    logger.warning(
                        f"SSM not installed on instance {instance_id}"
                    )
                    continue
                # Resolved per instance from that instance's own platform.
                #
                # Two defects lived here. The document was chosen once before
                # the loop and only ever reassigned, so in a finding naming both
                # a Windows and a Linux instance the Windows document leaked onto
                # every Linux instance after it - winpmem sent to a host with no
                # winpmem, which loses that instance's memory. And the Red Hat
                # major version came from three ranges open at the lower bound,
                # so RHEL 8.0 matched none of them and inherited the previous
                # instance's version. Both now live in one place, shared with
                # completion, memory analysis and disk investigation.
                platform = platform_of(
                    input_body.get("instanceInfo"), instance_id
                )
                memory_acquisition_document_name = resolve_document(
                    platform, "MEMORY_ACQUISITION"
                )
                logger.info(
                    f"Invoking ssm document {memory_acquisition_document_name} for instance {instance_id}"
                )
                ssm_client_current_account.modify_document_permission(
                    Name=memory_acquisition_document_name,
                    PermissionType="Share",
                    AccountIdsToAdd=[app_account_id],
                )
                # for item in response["InstanceInformationList"]:
                #     if item["InstanceId"] == instance_id:
                #         is_ssm_installed = True
                #         output_body["SSM_STATUS"] = "SUCCEEDED"

                # if is_ssm_installed:
                sts = create_aws_client("sts")

                s3_prefix = "memory/{0}/{1}".format(instance_id, forensic_id)

                session_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "S3LeastPrivilege",
                            "Effect": "Allow",
                            "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                            "Resource": [
                                f"arn:aws:s3:::{s3bucket_name}/{s3_prefix}/*"
                            ],
                        },
                        {
                            # These credentials are handed to the instance under
                            # investigation, which is by definition attacker
                            # controlled. s3:Get* on the whole bucket let it read
                            # every other case's evidence.
                            #
                            # Two prefixes, and only two: tools/ holds the
                            # pre-built LiME modules the document downloads, and
                            # the case's own prefix is head-object'ed at the end
                            # to confirm the capture actually landed and is not
                            # zero bytes. Scoping this to tools/ alone made that
                            # check fail with HeadObject 403 and the acquisition
                            # abort after a successful capture.
                            #
                            # The last element used to be two ARNs with the comma
                            # missing between them, so Python concatenated them
                            # into the single nonsense resource
                            # "arn:aws:s3:::<bucket>/arn:aws:s3:::<bucket>".
                            # ruff flags it as ISC004.
                            "Sid": "S3LeastGetPrivilege",
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                            "Resource": [
                                f"arn:aws:s3:::{s3bucket_name}/tools/*",
                                f"arn:aws:s3:::{s3bucket_name}/{s3_prefix}/*",
                            ],
                        },
                        {
                            "Sid": "S3LeastListPrivilege",
                            "Effect": "Allow",
                            "Action": [
                                "s3:ListBucket",
                                "s3:GetBucketLocation",
                            ],
                            "Resource": [f"arn:aws:s3:::{s3bucket_name}"],
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
                    "s3ArtifactLocation": [
                        "s3://{0}/memory/{1}/{2}".format(
                            s3bucket_name, instance_id, forensic_id
                        )
                    ],
                }
                # The Linux and RHEL documents download a LiME module pre-built
                # for the target's kernel release from
                # s3://<bucket>/tools/LiME/lime-<release>.ko. Without this
                # parameter s3bucket keeps its placeholder default, the download
                # is attempted against a bucket literally named "S3 bucket
                # Location" and always fails, so every acquisition falls through
                # to compiling LiME on the instance under investigation - which
                # aborts outright whenever kernel-devel for the running kernel is
                # not in the enabled repositories.
                #
                # windows-lime-memory-acquisition.json does not declare s3bucket
                # and SSM rejects any parameter a document does not declare, so
                # this is keyed on the document actually selected above.
                if (
                    memory_acquisition_document_name
                    != windows_memory_acquisition_document_name
                ):
                    params["s3bucket"] = [s3bucket_name]
                    # ExecutionTimeout is declared by these documents and drives
                    # the step's timeoutSeconds, but was never sent, so every
                    # acquisition ran with the document default of 1800s no
                    # matter what ssmExecutionTimeout was set to. The capture is
                    # streamed through a single-threaded gzip, so a large target
                    # needs this raised.
                    params["ExecutionTimeout"] = [
                        os.environ.get("SSM_EXECUTION_TIMEOUT", "1800")
                    ]

                # Only the generic Linux document implements the two tool
                # fallback, so only it declares this parameter. RHEL acquires
                # with AVML already and Windows with winpmem, and SSM rejects
                # the whole send_command with InvalidParameters when a parameter
                # is not declared - so sending this to either of them would stop
                # the acquisition rather than configure it.
                if (
                    memory_acquisition_document_name
                    == linux_memory_acquisition_document_name
                ):
                    params["memoryAcquisitionTools"] = [
                        os.environ.get(
                            "MEMORY_ACQUISITION_TOOLS", "lime,avml"
                        )
                    ]

                logger.info(
                    "Performing memory acquisition for "
                    f"{platform.get('PlatformName')} instance {instance_id} "
                    f"with {memory_acquisition_document_name}"
                )
                response = ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=f"arn:aws:ssm:{region}:{current_account}:document/{memory_acquisition_document_name}",
                    Comment="Memory Acquisition for " + instance_id,
                    Parameters=params,
                    CloudWatchOutputConfig={
                        "CloudWatchLogGroupName": ssm_output_log_group(
                            forensic_id
                        ),
                        "CloudWatchOutputEnabled": True,
                    },
                )

                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name="Acquiring instance memory",
                    description=f"Acquiring memory of instance id: {instance_id}",
                    phase=ForensicsProcessingPhase.ACQUISITION,
                    component_id="performMemoryAcquisition",
                    component_type="Lambda",
                    event_data=clean_date_format(response),
                )

                cmd_id = response["Command"]["CommandId"]

                # output_body["MemoryAcquisition"] = {}
                # output_body["MemoryAcquisition"]["CommandId"] = cmd_id
                # output_body["MemoryAcquisition"]["CommandIdArtifactMap"] = {
                #     cmd_id: {
                #         "Prefix": s3_prefix,
                #         "SSMDocumentName": memory_acquisition_document_name,
                #     }
                # }
                if (
                    "MemoryAcquisition"
                    not in output_body["InstanceResults"][instance_id]
                ):
                    output_body["InstanceResults"][instance_id][
                        "MemoryAcquisition"
                    ] = {}
                output_body["InstanceResults"][instance_id][
                    "MemoryAcquisition"
                ] = {
                    "CommandId": cmd_id,
                    "CommandIdArtifactMap": {
                        cmd_id: {
                            "Prefix": s3_prefix,
                            "SSMDocumentName": memory_acquisition_document_name,
                        }
                    },
                }
            except Exception as e:
                logger.error(
                    f"Error processing instance {instance_id}: {str(e)}"
                )
                output_body["InstanceResults"][instance_id] = {
                    "SSM_STATUS": "FAILED",
                    "error": str(e),
                }
        logger.info("output %s", redact(output_body))
        return create_response(200, output_body)
    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        exception_message = str(e)
        forensic_type = output_body["forensicType"]

        output_body["errorName"] = "Error: Creating memory dump"
        output_body["errorDescription"] = (
            f"Error while performing Forensic {forensic_type} acquisition"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "performMemoryAcquisition"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise MemoryAcquisitionError(output_body)
