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
from ..common.common import create_response
from ..common.log import get_logger
from ..customaction.createCustomAction import send_status_to_cfn

# initialise loggers
logger = get_logger(__name__)

instance_id = ""


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
    """
    # implementation Payload
    output_body = {}
    logger.info(event)
    properties = event["ResourceProperties"]
    logger.debug(json.dumps(properties))
    region = os.environ["AWS_REGION"]

    response_data = {}
    physical_resource_id = ""
    # boto3.client("securityhub")
    physical_resource_id = "CustomAction" + properties.get("Id", "ERROR")

    region = os.environ["AWS_REGION"]
    aws_account_id = context.invoked_function_arn.split(":")[4]

    if event["RequestType"] == "Create" or event["RequestType"] == "Update":
        try:

            s3bucket_name = os.environ["S3_BUCKET_NAME"]
            s3bucket_key_arn = os.environ["S3_BUCKET_KEY_ARN"]
            s3_role_arn = os.environ["S3_COPY_ROLE"]
            ssm_client_current_account = create_aws_client("ssm")
            ec2_client = create_aws_client("ec2")

            is_ssm_installed = False
            vpc_id = os.environ["VPC_ID"]
            ami_id = os.environ["AMI_ID"]
            instance_profile_arn = os.environ["FORENSIC_INSTANCE_PROFILE"]
            ec2_response = ec2_client.describe_subnets(
                Filters=[
                    {
                        "Name": "tag:aws-cdk:subnet-name",
                        "Values": [
                            "service",
                        ],
                    },
                    {"Name": "vpc-id", "Values": [vpc_id]},
                ],
                DryRun=False,
            )

            subnet_id = ec2_response["Subnets"][0]["SubnetId"]
            # ---
            ec2_response = ec2_client.run_instances(
                ImageId=ami_id,
                MaxCount=1,
                MinCount=1,
                SubnetId=subnet_id,
                InstanceType="t3.small",
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

            waiter = ec2_client.get_waiter("instance_status_ok")
            waiter.wait(InstanceIds=[instance_id])

            response = (
                ssm_client_current_account.describe_instance_information()
            )

            for item in response["InstanceInformationList"]:
                if item["InstanceId"] == instance_id:
                    is_ssm_installed = True
                    output_body["SSM_STATUS"] = "SUCCEEDED"

            logger.info(output_body)

            if is_ssm_installed:
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
                document_name = os.environ[
                    "AMAZON_LINUX_2_LIME_VOLATILITY_LOADER"
                ]
                response = ssm_client_current_account.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=f"arn:aws:ssm:{region}:{aws_account_id}:document/{document_name}",
                    Comment="Forensic Tools upload for " + instance_id,
                    Parameters=params,
                    CloudWatchOutputConfig={
                        "CloudWatchLogGroupName": "forensictools",
                        "CloudWatchOutputEnabled": True,
                    },
                )
                logger.info(output_body)

                ssm_waiter = ssm_client_current_account.get_waiter(
                    "command_executed"
                )
                ssm_command_id = response["Command"]["CommandId"]
                ssm_waiter.wait(
                    CommandId=ssm_command_id, InstanceId=instance_id
                )

                document_name = os.environ["AMAZON_LINUX_2_VOLATILITY_PROFILE"]
                response = ssm_client_current_account.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=f"arn:aws:ssm:{region}:{aws_account_id}:document/{document_name}",
                    Comment="Forensic Tools upload for " + instance_id,
                    Parameters=params,
                    CloudWatchOutputConfig={
                        "CloudWatchLogGroupName": "forensicprofilelaoder",
                        "CloudWatchOutputEnabled": True,
                    },
                )
                ssm_command_id = response["Command"]["CommandId"]
                ssm_waiter.wait(
                    CommandId=ssm_command_id, InstanceId=instance_id
                )
                send_status_to_cfn(
                    event,
                    context,
                    "SUCCESS",
                    response_data,
                    physical_resource_id,
                    logger,
                )
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
            forensic_type = "Tools Loader"

            output_body["errorName"] = "Error: Creating or loading tools"
            output_body[
                "errorDescription"
            ] = f"Error while performing Forensic {forensic_type} Tools loaded"
            output_body["errorPhase"] = "Forensic Tools"
            output_body["errorComponentId"] = "loadForensicTools"
            output_body["errorComponentType"] = "Lambda"
            output_body["eventData"] = exception_message.replace('"', "-")

            send_status_to_cfn(
                event,
                context,
                "SUCCESS",
                response_data,
                physical_resource_id,
                logger,
            )
    else:
        send_status_to_cfn(
            event,
            context,
            "SUCCESS",
            response_data,
            physical_resource_id,
            logger,
        )
