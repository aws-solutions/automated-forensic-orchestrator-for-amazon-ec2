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

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger
from ..common.redact import redact
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Forensic Send Notification")
def handler(event, _):
    """
    Lambda function handler for Send notification
    """
    logger.info("Got event %s", redact(event))
    logger.info("Sending error notification for forensic process")

    cause = json.loads(event.get("Cause"))
    logger.info(f"Got cause {cause}")
    error_message = json.loads(cause["errorMessage"])

    logger.info(f"Got errorMessage {error_message}")

    input_body = error_message

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

    sns_client = create_aws_client("sns")

    notification_arn = os.environ["NOTIFICATION_TOPIC_ARN"]

    forensic_id = input_body.get("forensicId")

    forensic_record = fds.get_forensic_record(
        record_id=forensic_id, metadata_only=True
    )
    ec2_instance_id = forensic_record.resourceId
    ec2_instance_account = forensic_record.awsAccountId

    error_name = input_body.get("errorName")
    error_description = input_body.get("errorDescription")
    error_phase = input_body.get("errorPhase")
    error_component_id = input_body.get("errorComponentId")
    error_component_type = input_body.get("errorComponentType")
    error_event_data = input_body.get("eventData")

    fds.add_forensic_timeline_event(
        id=forensic_id,
        name=error_name,
        description=error_description,
        phase=ForensicsProcessingPhase[error_phase],
        component_id=error_component_id,
        component_type=error_component_type,
        event_data=error_event_data,
    )
    phase_status = (
        ForensicsProcessingPhase.FAILED,
        error_description,
    )
    forensic_type = input_body.get("forensicType")

    if forensic_type == ForensicCategory.DISK.value:
        fds.update_forensic_record_phase_status(
            id=forensic_id,
            disk=phase_status,
        )
    else:
        fds.update_forensic_record_phase_status(
            id=forensic_id,
            memory=phase_status,
        )

    message = f"Forensic record {forensic_id} aborted due to {error_description}. Target EC2 instance {ec2_instance_id} in account {ec2_instance_account}."
    subject_suffix = "failed"

    # The analysis instance is deliberately left running when an investigation
    # fails: the capture has already been downloaded and decompressed under
    # /data and any partial output is still there, so terminating it would
    # destroy the only surface on which the failure can be diagnosed. Reading
    # that capture is how the "no kernel banner" acquisition failure was
    # identified at all.
    #
    # Nothing said so, though. terminateForensicInstance sits only on the
    # success path, so the instance simply stayed up with no mention in the
    # notification, no entry in the record, and no owner - and these are
    # 8 vCPU / 32 GiB instances. Say that it is retained, why, and that closing
    # the case means terminating it.
    investigation_instance_id = input_body.get(
        "ForensicInvestigationInstanceId"
    )
    if investigation_instance_id:
        retention_note = (
            f" Forensic analysis instance {investigation_instance_id} has been "
            "left running on purpose so the evidence under /data can be "
            "examined; connect with Session Manager. It is not terminated "
            "automatically - terminate it when the case is closed."
        )
        message += retention_note

        fds.add_forensic_timeline_event(
            id=forensic_id,
            name="Retaining analysis instance",
            description=(
                f"Analysis instance {investigation_instance_id} retained for "
                "diagnosis after a failed investigation. Terminate it when the "
                "case is closed."
            ),
            phase=ForensicsProcessingPhase.FAILED,
            component_id="sendErrorNotification",
            component_type="Lambda",
            event_data={
                "ForensicInvestigationInstanceId": investigation_instance_id,
                "retainedForDiagnosis": True,
            },
        )

    sns_client.publish(
        TopicArn=notification_arn,
        Message=message,
        Subject=f"Forensic {forensic_id} {subject_suffix}",
    )

    return create_response(
        200,
        {"message": "Successfully sent notification"},
    )
