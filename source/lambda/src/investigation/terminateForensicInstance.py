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
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Terminate Forensic Instance")
def handler(event, _):
    logger.info("Got event{}".format(event))
    table_name = os.environ["INSTANCE_TABLE_NAME"]

    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=table_name,
        auto_notify_subscribers=True
        if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
        else False,
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )
    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]
    forensic_type = input_body["forensicType"]
    output_body = input_body.copy()
    # implementation
    try:

        forensic_investigation_instance_id = input_body.get(
            "ForensicInvestigationInstanceId"
        )
        region = os.environ["AWS_REGION"]

        ec2_client = AWSCachedClient(region).get_connection("ec2")

        ec2response = ec2_client.terminate_instances(
            InstanceIds=[
                forensic_investigation_instance_id,
            ]
        )

        fds.add_forensic_timeline_event(
            id=forensic_id,
            name="Terminating Forensic Instance",
            description="Terminating Forensic Instance post investigation",
            phase=ForensicsProcessingPhase.INVESTIGATION,
            component_id="terminateForensicInstance",
            component_type="Lambda",
            event_data=clean_date_format(ec2response),
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

        output_body["errorName"] = "Error: Terminating Forensic Instance"
        output_body[
            "errorDescription"
        ] = f"Error while terminating a {forensic_type} forensic investigation instance"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "terminateForensicInstance"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise RuntimeError(output_body)
