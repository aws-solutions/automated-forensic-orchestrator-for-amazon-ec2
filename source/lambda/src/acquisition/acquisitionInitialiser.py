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

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger
from ..data.datatypes import ForensicCategory, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)
logger.info("testing log")


@xray_recorder.capture("acquisition_initializer")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Acquisition setup
    """
    logger.info("Lambda running")
    input_body = event["input"]["Payload"]["body"]
    forensic_id = input_body["forensicId"]
    execution_id = event["sfn"]["Id"]
    output = input_body.copy()
    output["forensicType"] = ForensicCategory.DISK.value
    output["IsolationRequired"] = False

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

    fds.add_forensic_timeline_event(
        id=forensic_id,
        name="Disk acquisition",
        description="Disk acquisition state machine initiated",
        phase=ForensicsProcessingPhase.ACQUISITION,
        component_id="acquisitionInitialiser",
        component_type="Lambda",
        event_data={"sfnExecutionId": execution_id},
    )

    fds.update_forensic_record_phase_status(
        id=forensic_id,
        disk=(
            ForensicsProcessingPhase.ACQUISITION,
            "Beginning disk acquisition",
        ),
    )

    logger.error("Error logging")
    logger.info("Lambda running")

    return create_response(200, output)
