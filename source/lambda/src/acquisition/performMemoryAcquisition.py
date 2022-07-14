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
from ..common.common import clean_date_format, create_response
from ..common.log import get_logger
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)

instance_id = ""


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
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
    is_ssm_installed = False
    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=True
        if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
        else False,
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

        instance_id = forensic_record.resourceId

        memory_acquisition_document_name = os.environ[
            "LINUX_LIME_MEMORY_ACQUISITION"
        ]
        windows_memory_acquisition_document_name = os.environ[
            "WINDOWS_LIME_MEMORY_ACQUISITION"
        ]
        ssm_execution_timeout = os.environ["SSM_EXECUTION_TIMEOUT"]

        logger.info("Lambda running")
        platform_details = input_body.get("instanceInfo").get(
            "PlatformDetails"
        )

        if platform_details == "Windows":
            memory_acquisition_document_name = (
                windows_memory_acquisition_document_name
            )

        ssm_client_current_account.modify_document_permission(
            Name=memory_acquisition_document_name,
            PermissionType="Share",
            AccountIdsToAdd=[app_account_id],
        )

        response = ssm_client.describe_instance_information()

        for item in response["InstanceInformationList"]:
            if item["InstanceId"] == instance_id:
                is_ssm_installed = True
                output_body["SSM_STATUS"] = "SUCCEEDED"

        output_body["forensicId"] = forensic_id
        output_body["ForensicInstanceId"] = instance_id

        logger.info(output_body)

        if is_ssm_installed:
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
                        "Sid": "S3LeastGetPrivilege",
                        "Effect": "Allow",
                        "Action": ["s3:Get*"],
                        "Resource": [
                            f"arn:aws:s3:::{s3bucket_name}/*",
                            f"arn:aws:s3:::{s3bucket_name}/"
                            f"arn:aws:s3:::{s3bucket_name}",
                        ],
                    },
                    {
                        "Sid": "S3LeastListPrivilege",
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
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
                "s3bucket": [s3bucket_name],
                "AccessKeyId": [tokens["AccessKeyId"]],
                "SecretAccessKey": [tokens["SecretAccessKey"]],
                "SessionToken": [tokens["SessionToken"]],
                "Region": [region],
                "ExecutionTimeout": [ssm_execution_timeout],
                "s3ArtifactLocation": [
                    "s3://{0}/memory/{1}/{2}".format(
                        s3bucket_name, instance_id, forensic_id
                    )
                ],
            }
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName=f"arn:aws:ssm:{region}:{current_account}:document/{memory_acquisition_document_name}",
                Comment="Memory Acquisition for " + instance_id,
                Parameters=params,
                CloudWatchOutputConfig={
                    "CloudWatchLogGroupName": forensic_id,
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

            output_body["MemoryAcquisition"] = {}
            output_body["MemoryAcquisition"]["CommandId"] = cmd_id
            output_body["MemoryAcquisition"]["CommandIdArtifactMap"] = {
                cmd_id: {
                    "Prefix": s3_prefix,
                    "SSMDocumentName": memory_acquisition_document_name,
                }
            }

            logger.info(output_body)
            return create_response(200, output_body)
        else:
            raise RuntimeError("SSM Not installed")

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
        output_body[
            "errorDescription"
        ] = f"Error while performing Forensic {forensic_type} acquisition"
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "performMemoryAcquisition"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise RuntimeError(output_body)
