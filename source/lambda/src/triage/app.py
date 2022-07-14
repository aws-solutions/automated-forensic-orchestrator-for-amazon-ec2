#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os

from arnparse import arnparse
from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.log import get_logger
from ..data.datatypes import Finding, ForensicsProcessingPhase, ResourceType
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Forensic Triaging")
def lambda_handler(event, context):
    """
    Get instance info for given triggered event from event bridge
    """

    app_account_role = os.environ["APP_ACCOUNT_ROLE"]

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

    forensic_record, instance_id, instance_account, instance_region = (
        None,
        None,
        None,
        None,
    )

    try:
        # Expecting a Security Hub custom action event
        action_name = get_action_name(event)

        is_triggered_by_fo_security_hub_custom_action(action_name)

        isolation_needed = is_isolation_action(action_name)

        # Is an EC2 Instance resource in scope for the finding?
        is_single_ec2_instance_in_scope(event)

        related_findings = get_related_findings(event)
        logger.info(related_findings)
        instance_id, instance_account, instance_region = get_instance_details(
            event
        )

        forensic_record = fds.create_forensic_record(
            resource_type=ResourceType.INSTANCE,
            resource_id=instance_id,
            aws_account_id=instance_account,
            aws_region=instance_region,
            associated_findings=[
                Finding(
                    finding["finding_id"],
                    finding["product"],
                    finding["region"],
                )
                for finding in related_findings
            ],
        )

        logger.info("Retrieve instance info")

        current_account = context.invoked_function_arn.split(":")[4]

        ec2_client = create_aws_client(
            "ec2",
            current_account=current_account,
            target_account=instance_account,
            target_region=instance_region,
            app_account_role=app_account_role,
        )

        instance_info = clean_date_format(
            retrieve_instance_info(logger, ec2_client, instance_id)
        )

        logger.info("Retrieved instance info {0}".format(instance_info))

        fds.add_forensic_timeline_event(
            id=forensic_record.id,
            name="Get Instance Info",
            description="Retrieved instance info",
            phase=ForensicsProcessingPhase.TRIAGE,
            component_id="triage",
            component_type="Lambda",
            event_data=instance_info,
        )

        fds.update_forensic_record_resource_info(
            id=forensic_record.id, resource_info=instance_info
        )

        fds.update_forensic_record_phase_status(
            id=forensic_record.id,
            triage=(ForensicsProcessingPhase.SUCCESS, "Completed triage"),
        )

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }

        logger.error(exception_obj)

        if not forensic_record:
            forensic_record = fds.create_failed_forensic_record(
                event_data=exception_obj
            )
        else:
            fds.add_forensic_timeline_event(
                id=forensic_record.id,
                name="Error: Triaging Instance",
                description="Error while processing Forensic Orchestrator trigger event",
                phase=ForensicsProcessingPhase.TRIAGE,
                component_id="triage",
                component_type="Lambda",
                event_data=exception_obj,
            )

        raise e

    return create_response(
        200,
        {
            "instanceInfo": instance_info,
            "forensicId": forensic_record.id,
            "instanceAccount": instance_account,
            "instanceRegion": instance_region,
            "isAcquisitionRequired": is_triage_required(instance_info),
            "isIsolationNeeded": isolation_needed,
        },
    )


def get_action_name(event):
    action = event["resources"][0]
    action_array = action.split("/")
    action_name = action_array[len(action_array) - 1]
    return action_name


def is_isolation_action(action_name) -> bool:
    return action_name == "ForensicIsolateAct"


def is_triggered_by_fo_security_hub_custom_action(action_name):

    if action_name not in [
        "TriageAction",
        "TriageIsolationAction",
        "ForensicTriageAction",
        "ForensicIsolateAct",
    ]:
        logger.warning(f"Invalid event name: {action_name}")
        raise ValueError(f"Invalid event name: {action_name}")


def is_single_ec2_instance_in_scope(event):
    findings = event["detail"]["findings"]
    instances = []

    for finding in findings:
        instances.extend(
            [
                resource
                for resource in finding["Resources"]
                if resource.get("Type") == "AwsEc2Instance"
            ]
        )

    if not instances:
        raise ValueError(f"Invalid trigger event: {event}")

    if len(instances) > 1:
        raise ValueError(f"More than one instance in-scope for event: {event}")

    return instances


def get_instance_details(event):
    resource_arn = event["detail"]["findings"][0]["Resources"][0]["Id"]
    logger.info(resource_arn)

    parsed_arn = arnparse(resource_arn)
    ec2_instance_id = parsed_arn.resource
    ec2_instance_account = parsed_arn.account_id
    ec2_instance_region = parsed_arn.region

    if not ec2_instance_id:
        raise ValueError(
            "The EC2 Instance ID is missing in trigger event: {0}".format(
                event
            )
        )

    return ec2_instance_id, ec2_instance_account, ec2_instance_region


def get_related_findings(event):
    findings = event["detail"]["findings"]
    related_findings = []

    for finding in findings:
        related_findings.append(
            {
                "finding_id": (
                    finding.get("Id")
                    if finding.get("ProductName") == "Security Hub"
                    else finding.get("GeneratorId")
                ),
                "product": finding.get("ProductName"),
                "region": finding.get("Region"),
                "account": finding.get("AwsAccountId"),
            }
        )

    return related_findings


def is_triage_required(instance_info) -> bool:
    try:
        explicit_triage_set = any(
            element.get("Key") == "IsTriageRequired"
            and element.get("Value") == "True"
            for element in instance_info["Tags"]
        )
        no_triage_tag_present = all(
            element.get("Key") != "IsTriageRequired"
            for element in instance_info["Tags"]
        )
        return explicit_triage_set or no_triage_tag_present
    except Exception as e:
        logger.error(f"No tags found in the instance {e}")
        return True


def retrieve_instance_info(logger, ec2_client, instance_id: str):
    logger.info("retrieve_instance_info")
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    logger.info("retrieve_instance_info2")

    logger.info("ec2 instance raw response %s", response)
    if not response["Reservations"][0]["Instances"]:
        logger.error(
            f"Error while retrieving instance info for: {instance_id}"
        )
        raise ValueError("No associated instance info available: ")

    return response["Reservations"][0]["Instances"][0]
