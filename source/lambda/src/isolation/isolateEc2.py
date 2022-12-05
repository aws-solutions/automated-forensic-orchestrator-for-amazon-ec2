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

import datetime
import json
import os

from arnparse import arnparse
from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.exception import (
    ForensicLambdaExecutionException,
    MemoryAcquisitionError,
)
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Isolate Instance")
def handler(event, context):
    logger.info("Got event{}".format(event))
    input_body = {}
    error_handling_flow = False
    if event.get("Error") == MemoryAcquisitionError.__name__:
        cause = json.loads(event["Cause"])
        error_message = cause["errorMessage"]
        input_body = json.loads(error_message)
        error_handling_flow = True
    else:
        input_body = event["Payload"]["body"]
    output = input_body.copy()
    logger.info(f"inputboy {input_body}")
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
    forensic_isolation_instance_profile_name = os.environ[
        "FORENSIC_ISOLATION_INSTANCE_PROFILE_NAME"
    ]

    ec2_client = create_aws_client(
        "ec2",
        current_account=current_account,
        target_account=app_account_id,
        target_region=app_account_region,
        app_account_role=app_account_role,
    )

    iam_client = create_aws_client(
        "iam",
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

    if (
        forensic_record.memoryAnalysisStatus
        == ForensicsProcessingPhase.ISOLATION_FAILED
    ):
        logger.warning(
            f"Previous isolation fail for forensic record {forensic_id}, proceed to error handling"
        )
        raise ForensicLambdaExecutionException("Previous isolation failed")

    enable_evidence_protection(instance_id, ec2_client)

    enable_evidence_protection_ebs(
        instance_id,
        forensic_record.resourceInfo["BlockDeviceMappings"],
        ec2_client,
    )

    try:
        (
            isolation_sg,
            isolation_sg_no_rule,
        ) = get_required_isolation_security_groups(ec2_client, instance_vpc)

        logger.info(
            f"isolating instance {instance_id}, step1 converting all traffic to untracked"
        )
        for eni in sg_for_eni:
            eni_id = eni.get("ENI_ID")
            ec2_client.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[isolation_sg]
            )
            ec2_client.modify_network_interface_attribute(
                NetworkInterfaceId=eni_id, Groups=[isolation_sg_no_rule]
            )

        detach_eip_from_instance(instance_id, ec2_client)

        invalid_existing_credential_sessions(iam_client, forensic_record)

        update_profile_for_instance(
            instance_id,
            app_account_id,
            forensic_isolation_instance_profile_name,
            ec2_client,
            current_account,
        )

        fds.add_forensic_timeline_event(
            id=forensic_id,
            name="Instance isolated",
            description=f"Instance isolated for {instance_id}",
            phase=ForensicsProcessingPhase.ISOLATION,
            component_id="isolateEc2",
            component_type="Lambda",
            event_data=None,
        )

    except Exception as e:
        logger.error(f"isolation failed, {e}")
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
            name="Instance isolation failed",
            description=f"Instance isolated for {instance_id} failed",
            phase=ForensicsProcessingPhase.ISOLATION_FAILED,
            component_id="isolateEc2",
            component_type="Lambda",
            event_data=exception_obj,
        )

        logger.info(
            f"Update forensic record isolation status for {forensic_record.id}"
        )
        fds.update_forensic_record_phase_status(
            id=forensic_record.id,
            memory=(
                ForensicsProcessingPhase.ISOLATION_FAILED,
                f"Error while isolating instance {instance_id}",
            ),
        )
        raise e
    if error_handling_flow:
        raise ForensicLambdaExecutionException(error_message)
    return create_response(200, output)


def invalid_existing_credential_sessions(iam_client, forensic_record):
    instance_profile = forensic_record.resourceInfo["IamInstanceProfile"]
    if not instance_profile:
        return
    instance_profile_arn = forensic_record.resourceInfo["IamInstanceProfile"][
        "Arn"
    ]
    parsed_arn = arnparse(instance_profile_arn)
    profile_name = parsed_arn.resource
    iam_profile_rsp = iam_client.get_instance_profile(
        InstanceProfileName=profile_name
    )

    profile_info = iam_profile_rsp.get("InstanceProfile")
    logger.info(f"Process profile: {profile_info}")
    all_role_names = [item.get("RoleName") for item in profile_info["Roles"]]
    logger.info(f"Revoke sts sessions for roles: {all_role_names}")
    current_time = datetime.datetime.now()
    for name in all_role_names:
        logger.info(
            f"Revoke access for sessions associated with role : {name}"
        )
        iam_client.put_role_policy(
            RoleName=name,
            PolicyName="AWSRevokeOlderSTSSessions",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],"Condition":{"DateLessThan":{"aws:TokenIssueTime":"'
            + current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            + '"}}}]}',
        )


def detach_eip_from_instance(instance_id: str, ec2_client) -> None:
    """
    Detach any EIP associations from the target instance
    """
    logger.info(f"detach eip from instance {instance_id}")
    response = ec2_client.describe_addresses(
        Filters=[
            {
                "Name": "instance-id",
                "Values": [
                    instance_id,
                ],
            },
        ]
    )

    association_ids = [
        item.get("AssociationId") for item in response.get("Addresses")
    ]
    logger.info(f"detach eip association {association_ids}")
    for association_id in association_ids:
        ec2_client.disassociate_address(
            AssociationId=association_id,
        )


def get_required_isolation_security_groups(ec2_client, instance_vpc):
    sg_name_untrack_conversion = (
        f"Forensic-isolation-convertion-{instance_vpc}"
    )
    sg_name_no_rule = f"Forensic-isolation-no-rule-{instance_vpc}"

    check_sg_response = get_existing_security_group(
        ec2_client, [sg_name_untrack_conversion, sg_name_no_rule]
    )

    existing_sg_for_vpc = check_sg_response.get("SecurityGroups")
    logger.info(f"got existing sg {existing_sg_for_vpc}")
    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"existing sg names {existing_sg_names_for_vpc}")

    # Group 1 to conver all traffic to untrack
    if sg_name_untrack_conversion not in existing_sg_names_for_vpc:
        logger.info(f"create security group , {sg_name_untrack_conversion}")
        response = ec2_client.create_security_group(
            Description="Forensic isolation security group untrack converting",
            GroupName=sg_name_untrack_conversion,
            VpcId=instance_vpc,
        )
        isolation_sg = response.get("GroupId")
        logger.info(f"created , {sg_name_untrack_conversion}")
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
            f"found existing security group {sg_name_untrack_conversion} for vpc {instance_vpc}"
        )
        isolation_sg = next(
            sg.get("GroupId")
            for sg in check_sg_response.get("SecurityGroups")
            if sg.get("GroupName") == sg_name_untrack_conversion
        )

    logger.info("check for no rule sg")

    existing_sg_names_for_vpc = [
        sg.get("GroupName") for sg in existing_sg_for_vpc
    ]
    logger.info(f"creating no rule group {sg_name_no_rule}")
    # Group 2 to isolate instance
    if sg_name_no_rule not in existing_sg_names_for_vpc:
        response = ec2_client.create_security_group(
            Description="Forensic isolation security group no rule",
            GroupName=sg_name_no_rule,
            VpcId=instance_vpc,
        )
        isolation_sg_no_rule = response.get("GroupId")
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


def enable_evidence_protection(instance_id: str, ec2_client):
    """
    perform evidence protection operation for the instance to be isolated
    """
    try:
        logger.info(f"Enable termination protection for {instance_id}")
        update_termination_protection_rsp = (
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id, DisableApiTermination={"Value": True}
            )
        )
        logger.info(
            f"Enable termination protection response {update_termination_protection_rsp}"
        )

        update_shutdown_behavior_rsp = ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceInitiatedShutdownBehavior={"Value": "stop"},
        )
        logger.info(
            f"Set shutdown behavior response {update_shutdown_behavior_rsp}"
        )
    except ClientError as e:
        logger.error(
            "instance protection operation failed, proceed to isolate"
        )
        logger.error(e)


def enable_evidence_protection_ebs(
    instance_id: str, block_mapping: list, ec2_client
):
    """
    Update mounted EBS termination behaviour
    """
    device_to_be_updated = [
        {
            "DeviceName": item["DeviceName"],
            "Ebs": {"DeleteOnTermination": False},
        }
        for idx, item in enumerate(block_mapping)
        if "Ebs" in item
    ]
    try:
        logger.info(
            f"Update Delete on termination to false for {instance_id} with request {device_to_be_updated}"
        )
        update_ebs_volume_response = ec2_client.modify_instance_attribute(
            InstanceId=instance_id, BlockDeviceMappings=device_to_be_updated
        )
        logger.info(
            f"Update Delete on termination to false {update_ebs_volume_response}"
        )

    except ClientError as e:
        logger.error(
            "Update Delete on termination to false, proceed to isolate"
        )
        logger.error(e)


def update_profile_for_instance(
    instance_id: str,
    app_account: str,
    forensic_isolation_instance_profile: str,
    ec2_client,
    current_account: str,
):
    """
    Attach isolation profile to isolated instance
    """
    target_profile_name = forensic_isolation_instance_profile
    if app_account == current_account:
        target_profile_name = os.environ[
            "SOLUTION_ACCOUNT_ISOLATION_INSTANCE_PROFILE_NAME"
        ]

    try:
        profile_arn = f"arn arn:aws:iam::{app_account}:instance-profile/{target_profile_name}"
        logger.info(
            f"Update instance profile for {instance_id} with role {profile_arn}"
        )
        iam_instance_profile_associations = (
            ec2_client.describe_iam_instance_profile_associations(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]
            )["IamInstanceProfileAssociations"]
        )

        if len(iam_instance_profile_associations) > 0:
            # can only max 1
            association_id = iam_instance_profile_associations[0][
                "AssociationId"
            ]
            logger.info(
                f"Update instance profile association {iam_instance_profile_associations} for {instance_id} with role {profile_arn}"
            )
            logger.info(
                f"Test arn {profile_arn} name {target_profile_name} association id  {association_id}"
            )

            ec2_client.replace_iam_instance_profile_association(
                IamInstanceProfile={"Name": target_profile_name},
                AssociationId=association_id,
            )
        else:
            # no profile associated, this should not happen
            # in case it does, we will provide best effort to protect the instance by associate a new profile
            logger.warning(
                f"Existing profile not found for {instance_id} , associating isolating instance profile"
            )
            ec2_client.associate_iam_instance_profile(
                IamInstanceProfile={"Name": target_profile_name},
                InstanceId=instance_id,
            )

    except Exception as e:
        logger.error(
            "Update instance profile fail, non critical failure proceed"
        )
        logger.error(e)
