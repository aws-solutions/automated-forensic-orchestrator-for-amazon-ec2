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

from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.common import clean_date_format, create_response
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


# function to check instance SSM status
@xray_recorder.capture("Check Instance Status")
def handler(event, _):
    logger.info("Got event{}".format(event))
    region = os.environ["AWS_REGION"]
    ssmclient = AWSCachedClient(region).get_connection("ssm")

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
    forensic_id = input_body["forensicId"]
    output_body = input_body.copy()

    forensic_type = input_body["forensicType"]
    try:
        forensic_investigation_instance_id = input_body[
            "ForensicInvestigationInstanceId"
        ]

        logger.info(
            "Got ForensicInvestigationInstanceId {}".format(
                forensic_investigation_instance_id
            )
        )

        ssm_response = ssmclient.describe_instance_information()

        output_body["forensicInvestigationInstance"] = {}

        contains_forensic_id = any(
            element.get("InstanceId") == forensic_investigation_instance_id
            for element in ssm_response["InstanceInformationList"]
        )

        if contains_forensic_id:
            output_body["forensicInvestigationInstance"][
                "SSM_Status"
            ] = "SUCCEEDED"

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Forensic Instance Associated",
                description=f"Forensic Instance associated: {forensic_investigation_instance_id}",
                phase=ForensicsProcessingPhase.INVESTIGATION,
                component_id="checkInstanceStatus",
                component_type="Lambda",
                event_data=clean_date_format(ssm_response),
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

        output_body["errorName"] = "Error: Checking Forensic Instance Status"
        output_body[
            "errorDescription"
        ] = f"Error while performing forensic analysis for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "checkInstanceStatus"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
