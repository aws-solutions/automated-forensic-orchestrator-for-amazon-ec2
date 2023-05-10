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

from ..common.awsapi_cached_client import AWSCachedClient
from ..common.common import create_response
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Terminate Builder Instance")
def handler(event, _):
    logger.info("Got event{}".format(event))

    input_body = event["Payload"]["body"]
    instance_id = input_body["InstanceId"]

    output_body = input_body.copy()
    # implementation
    try:

        region = os.environ["AWS_REGION"]

        ec2_client = AWSCachedClient(region).get_connection("ec2")

        ec2_client.terminate_instances(
            InstanceIds=[
                instance_id,
            ]
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

        output_body["errorName"] = "Error: Terminating Builder Instance"
        output_body[
            "errorDescription"
        ] = f"Error while terminating builder instance {instance_id} instance"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "terminateBuilderInstance"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
