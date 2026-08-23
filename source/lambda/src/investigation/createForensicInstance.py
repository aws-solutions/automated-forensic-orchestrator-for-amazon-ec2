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

from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError

from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..common.redact import redact
from ..common.vpc_lookup import forensic_subnet_id
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


def id_generator(size=1000):
    logger.info("rdmNumber generator")
    logger.info(secrets.randbelow(size))
    rdm_number = f"{secrets.randbelow(size)}"
    logger.info(rdm_number)
    return rdm_number


# Candidate instance types for the analysis host, tried in order.
#
# The subnet - and therefore the Availability Zone - is fixed, so a single
# hardcoded type means one AZ's capacity for one type with no fallback. That
# failed a real disk investigation twice with InsufficientInstanceCapacity, once
# on the previous generation m4.2xlarge and once on m6i.2xlarge, in both cases
# after the snapshots had already been taken. Every default below is 8 vCPU and
# 32 GiB, so they are interchangeable for this workload.
DEFAULT_ANALYSIS_INSTANCE_TYPES = (
    "m6i.2xlarge",
    "m6a.2xlarge",
    "m5.2xlarge",
    "m5a.2xlarge",
)

# RunInstances errors that mean "this type, here, right now" rather than
# "this request is wrong". Only these are worth trying another type for.
CAPACITY_ERROR_CODES = (
    "InsufficientInstanceCapacity",
    "InsufficientHostCapacity",
    "Unsupported",
    "UnsupportedOperation",
    "InstanceLimitExceeded",
)


def analysis_instance_types() -> list:
    """Instance types to try, from configuration or the defaults."""
    configured = os.environ.get("FORENSIC_INSTANCE_TYPE", "").strip()
    if not configured:
        return list(DEFAULT_ANALYSIS_INSTANCE_TYPES)
    # A comma separated list lets an operator express their own preference
    # order; a single value still works and is then the only type tried.
    candidates = [
        part.strip() for part in configured.split(",") if part.strip()
    ]
    # A value of only separators would otherwise leave nothing to launch, and
    # an analysis host is not optional.
    return candidates or list(DEFAULT_ANALYSIS_INSTANCE_TYPES)


def run_analysis_instance(ec2_client, instance_types: list, **kwargs):
    """RunInstances, falling back through instance_types on capacity errors.

    The evidence has already been captured by the time this runs, so giving up
    because one instance type is momentarily unavailable in one Availability
    Zone loses the investigation for a reason that has nothing to do with the
    case.
    """
    last_error = None
    for instance_type in instance_types:
        try:
            return ec2_client.run_instances(
                InstanceType=instance_type, **kwargs
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in CAPACITY_ERROR_CODES:
                raise
            logger.warning(
                f"{instance_type} unavailable for the forensic analysis "
                f"instance ({code}); trying the next candidate"
            )
            last_error = error
    if last_error is None:
        # Only reachable if instance_types is empty, which
        # analysis_instance_types prevents. Raising something derived from
        # BaseException keeps this honest rather than `raise None`.
        raise InvestigationError(
            {
                "eventData": (
                    "no analysis instance types to try - check "
                    "FORENSIC_INSTANCE_TYPE"
                )
            }
        )
    raise last_error


@xray_recorder.capture("Create Forensic Instance")
def handler(event, _):
    logger.info("Got event %s", redact(event))

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
        # The evidence volume is requested as /dev/sdf, but the name the guest
        # sees depends on the hypervisor: Xen instance types rename it to
        # /dev/xvdf, Nitro types enumerate it as an NVMe device such as
        # /dev/nvme1n1. Hardcoding /dev/xvdf tied the analysis host to previous
        # generation types. Discover it instead, and fail loudly - the
        # investigation documents check that /data is not RAM backed, but they
        # cannot tell the difference between "mounted" and "mkfs silently did
        # nothing", and a plaso storage file on the root volume is a much
        # smaller disk than the operator asked for.
        user_data = """#!/bin/bash
set -x
mkdir -p /data
data_device=
for candidate in /dev/xvdf /dev/sdf ; do
    if [ -b "$candidate" ]; then data_device=$candidate; break; fi
done
if [ -z "$data_device" ]; then
    root_source=$(findmnt -n -o SOURCE /)
    root_parent=$(lsblk -no PKNAME "$root_source" 2>/dev/null | head -1)
    if [ -n "$root_parent" ]; then
        root_disk="/dev/$root_parent"
    else
        root_disk=$(printf '%s' "$root_source" | sed -E 's/p?[0-9]+$//')
    fi
    data_device=$(lsblk -dpno NAME,TYPE | awk '$2 == "disk" {print $1}' | grep -v -x "$root_disk" | head -1)
fi
if [ -z "$data_device" ]; then
    echo "FORENSIC_INSTANCE_SETUP_FAILED: no evidence volume found" >&2
    exit 1
fi
mkfs -F -t ext4 "$data_device" || exit 1
mount "$data_device" /data || exit 1
echo "mounted $data_device at /data"
"""

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

        # forensic_subnet_id raises SubnetNotFound naming the VPC and the tag rather
        # than IndexError on an empty list. An empty list is the normal case when the
        # solution is pointed at an existing VPC: those subnets were not created by
        # this app and so carry no aws-cdk:subnet-name tag.
        subnet_id = forensic_subnet_id(ec2_client, vpc_id)

        logging.info(subnet_id)

        # ---
        ec2_response = run_analysis_instance(
            ec2_client=ec2_client,
            instance_types=analysis_instance_types(),
            ImageId=ubuntu_ami_id,
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[security_group],
            SubnetId=subnet_id,
            Placement={"Tenancy": "default"},
            Monitoring={"Enabled": False},
            DisableApiTermination=False,
            InstanceInitiatedShutdownBehavior="stop",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {
                            # Not "_Ubuntu": the analysis host has been Amazon
                            # Linux 2023 since 2.0.0, so that suffix labelled
                            # every instance in the console with the wrong
                            # operating system - and this tag is how an examiner
                            # identifies the host holding a case's evidence.
                            "Key": "Name",
                            "Value": "{0}_{1}_analysis".format(
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
                        {"Key": "Name", "Value": forensic_id + "_analysisVlm"},
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
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "VolumeSize": disk_size,
                        "DeleteOnTermination": True,
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
        output_body["errorDescription"] = (
            f"Error while creating a {forensic_type} forensic investigation instance"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "createForensicInstance"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
