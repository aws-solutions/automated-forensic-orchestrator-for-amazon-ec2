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

import logging
import os
import secrets
import string

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.log import get_logger
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


def id_generator(size=1000, chars=string.ascii_uppercase + string.digits):
    logger.info("rdmNumber generator")
    logger.info(secrets.randbelow(size))
    rdm_number = f"{secrets.randbelow(size)}"
    logger.info(rdm_number)
    return rdm_number


@xray_recorder.capture("Create Forensic Instance")
def handler(event, _):
    logger.info("Got event{}".format(event))

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
    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    forensic_type = input_body["forensicType"]
    # implementation
    try:

        region = os.environ["AWS_REGION"]
        ssm_client = AWSCachedClient(region).get_connection("ssm")
        ssm_response = ssm_client.get_parameter(
            Name=os.environ["FORENSIC_AMI_NAME"], WithDecryption=True
        )
        ubuntu_ami_id = ssm_response["Parameter"]["Value"]
        logging.info(ubuntu_ami_id)

        instance_profile_arn = os.environ["FORENSIC_INSTANCE_PROFILE"]
        user_data = """#!/bin/bash
            mkdir /data
            mkfs -F -t ext4 /dev/xvdf
            mount /dev/xvdf /data"""

        ec2_client = AWSCachedClient(region).get_connection("ec2")

        # hard coding to first available VPC.
        # Fall back would be creating a new security group at run time.

        vpc_id = os.environ["VPC_ID"]
        forensic_id = input_body["forensicId"]

        if forensic_type == ForensicCategory.DISK.value:
            fds.update_forensic_record_phase_status(
                id=forensic_id,
                disk=(
                    ForensicsProcessingPhase.INVESTIGATION,
                    f"Performing {forensic_type} investigation",
                ),
            )
        elif forensic_type == ForensicCategory.MEMORY.value:
            fds.update_forensic_record_phase_status(
                id=forensic_id,
                memory=(
                    ForensicsProcessingPhase.INVESTIGATION,
                    f"Performing {forensic_type} investigation",
                ),
            )

        security_groups = ec2_client.create_security_group(
            Description="Forensics Security Group for Case: " + forensic_id,
            GroupName="ForensicsSG_" + forensic_id + "_" + id_generator(),
            VpcId=vpc_id,
            DryRun=False,
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [
                        {"Key": "InstanceType", "Value": "FORENSIC"},
                    ],
                },
            ],
        )
        logging.info(security_groups)

        # create Dynamic Security Groups rather than static.

        security_group = security_groups["GroupId"]
        output_body["SecurityGroup"] = security_group

        logging.info(security_group)

        disk_size = int(os.environ["DISK_SIZE"])

        # need to add non-Default Security Group , VPC_ID, Subnet_ID

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

        logging.info(ec2_response)

        subnet_id = ec2_response["Subnets"][0]["SubnetId"]

        logging.info(subnet_id)

        # ---
        ec2_response = ec2_client.run_instances(
            ImageId=ubuntu_ami_id,
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[security_group],
            SubnetId=subnet_id,
            InstanceType="m4.2xlarge",
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
                            "Value": "{0}_{1}_Ubuntu".format(
                                forensic_type, forensic_id
                            ),
                        },
                        {"Key": "CaseID", "Value": forensic_id},
                        {"Key": "InstanceType", "Value": "FORENSIC"},
                    ],
                },
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "Name", "Value": forensic_id + "_UbuntuVlm"},
                        {"Key": "forensicId", "Value": forensic_id},
                        {"Key": "InstanceType", "Value": "FORENSIC"},
                    ],
                },
            ],
            EbsOptimized=True,
            IamInstanceProfile={"Arn": instance_profile_arn},
            UserData=user_data,
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeSize": disk_size,
                        "DeleteOnTermination": True,
                        "VolumeType": "gp2",
                    },
                },
                {
                    "DeviceName": "/dev/sdf",
                    "Ebs": {
                        "VolumeSize": disk_size,
                        "DeleteOnTermination": True,
                        "VolumeType": "gp2",
                    },
                },
            ],
        )
        instances = ec2_response["Instances"]
        output_body["ForensicInvestigationInstanceId"] = instances[0][
            "InstanceId"
        ]

        fds.add_forensic_timeline_event(
            id=forensic_id,
            name="Creating Forensic Instance",
            description="Creating a Forensic Instance to perform investigation",
            phase=ForensicsProcessingPhase.INVESTIGATION,
            component_id="createForensicInstance",
            component_type="Lambda",
            event_data=clean_date_format(instances[0]),
        )

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

        output_body["errorName"] = "Error: Creating Forensic Instance"
        output_body[
            "errorDescription"
        ] = f"Error while creating a {forensic_type} forensic investigation instance"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "createForensicInstance"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise RuntimeError(output_body)
