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

import os

from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.exception import ForensicLambdaExecutionException
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Isolate Instance")
def handler(event, context):
    logger.info("Got event{}".format(event))
    input_body = event["Payload"]["body"]

    app_account_region = input_body.get("instanceRegion")
    instance_id = input_body.get("instanceInfo").get("InstanceId")
    recorded_sgs = input_body.get("instanceInfo").get("SecurityGroups")
    recorded_enis = input_body.get("instanceInfo").get("NetworkInterfaces")
    sg_for_eni = [
        {
            "SecurityGroup": [sg.get("GroupId") for sg in item.get("Groups")],
            "ENI_ID": item.get("NetworkInterfaceId"),
        }
        for item in recorded_enis
    ]
    original_sg_ids = [item.get("GroupId") for item in recorded_sgs]
    # implementation

    app_account_id = input_body.get("instanceAccount")
    current_account = context.invoked_function_arn.split(":")[4]

    app_account_role = os.environ["APP_ACCOUNT_ROLE"]

    ec2_client = create_aws_client(
        "ec2",
        current_account=current_account,
        target_account=app_account_id,
        target_region=app_account_region,
        app_account_role=app_account_role,
    )

    ddb_client = create_aws_client("dynamodb")

    instance_vpc = input_body.get("instanceInfo").get("VpcId")

    output = input_body.copy()
    fds = ForensicDataService(
        ddb_client=ddb_client,
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=True
        if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
        else False,
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )
    forensic_id = input_body.get("forensicId")
    forensic_record = fds.get_forensic_record(
        record_id=forensic_id, metadata_only=True
    )

    try:
        (
            isolation_sg,
            isolation_sg_no_rule,
        ) = get_required_isolation_security_groups(ec2_client, instance_vpc)

        logger.info(
            f"isolating instance {instance_id}, step1 coverting all traffic to untracked"
        )
        for eni in sg_for_eni:
            eni_id = eni.get("ENI_ID")
            ec2_client.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[isolation_sg]
            )
            ec2_client.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[isolation_sg_no_rule]
            )

    except ForensicLambdaExecutionException as e:
        logger.error("isolation failed")
        logger.error(e)
        # best effort to revert back to original sgs
        try:
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id, Groups=original_sg_ids
            )
        except ForensicLambdaExecutionException:
            logger.error("isolation reverting failed, abort")
        # revert to original sg groups
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }

        fds.add_forensic_timeline_event(
            id=forensic_id,
            name="Instance isolated",
            description=f"Instance isolated for {instance_id}",
            phase=ForensicsProcessingPhase.ISOLATION,
            component_id="isolateEc2",
            component_type="Lambda",
            event_data=exception_obj,
        )

        fds.update_forensic_record_phase_status(
            id=forensic_record.id,
            disk=(
                ForensicsProcessingPhase.FAILED,
                f"Error whileisolate instance {instance_id}",
            ),
        )
        raise e

    return create_response(200, output)


def get_required_isolation_security_groups(ec2_client, instance_vpc):
    sg_name_untrack_covertion = f"Forensic-isolation-convertion-{instance_vpc}"
    sg_name_no_rule = f"Forensic-isolation-no-rule-{instance_vpc}"

    check_sg_response = get_existing_security_group(
        ec2_client, [sg_name_untrack_covertion, sg_name_no_rule]
    )

    existing_sg_for_vpc = check_sg_response.get("SecurityGroups")
    logger.info(f"got existing sg {existing_sg_for_vpc}")
    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"existing sg names {existing_sg_names_for_vpc}")

    # Group 1 to conver all traffic to untrack
    if sg_name_untrack_covertion not in existing_sg_names_for_vpc:
        logger.info(f"create security group , {sg_name_untrack_covertion}")
        resonse = ec2_client.create_security_group(
            Description="Forensic isolation security group untrack coverting",
            GroupName=sg_name_untrack_covertion,
            VpcId=instance_vpc,
        )
        isolation_sg = resonse.get("GroupId")
        logger.info(f"created , {sg_name_untrack_covertion}")
        ec2_client.authorize_security_group_ingress(
            GroupId=isolation_sg,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
    else:
        logger.info(
            f"found existing security group {sg_name_untrack_covertion} for vpc {instance_vpc}"
        )
        isolation_sg = next(
            sg.get("GroupId")
            for sg in check_sg_response.get("SecurityGroups")
            if sg.get("GroupName") == sg_name_untrack_covertion
        )

    logger.info("check for no rule sg")

    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"creating no rule group {sg_name_no_rule}")
    # Group 2 to isolate instance
    if sg_name_no_rule not in existing_sg_names_for_vpc:
        resonse = ec2_client.create_security_group(
            Description="Forensic isolation security group no rule",
            GroupName=sg_name_no_rule,
            VpcId=instance_vpc,
        )
        isolation_sg_no_rule = resonse.get("GroupId")
        ec2_client.revoke_security_group_egress(
            GroupId=isolation_sg_no_rule,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        )
    else:
        logger.info(
            f"found existing security group {sg_name_no_rule} for vpc {instance_vpc}"
        )
        isolation_sg_no_rule = next(
            sg.get("GroupId")
            for sg in check_sg_response.get("SecurityGroups")
            if sg.get("GroupName") == sg_name_no_rule
        )

    return isolation_sg, isolation_sg_no_rule


def get_existing_security_group(ec2_client, groups_name: list):
    try:
        check_sg_response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": groups_name},
            ]
        )
    except ClientError as e:
        # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
        # InvalidGroup.NotFound
        code = e.response["Error"]["Code"]
        if e.response["Error"]["Code"] == "InvalidGroup.NotFound":
            logger.error(f"both groups not exist, {code}")
            check_sg_response = {"SecurityGroups": []}
        else:
            raise e
    return check_sg_response
