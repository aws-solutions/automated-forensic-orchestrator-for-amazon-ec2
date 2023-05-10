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

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Perform Memory Acquisition")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
    """

    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    logger.info(event)
    instance_id = input_body["InstanceId"]
    output_body["isInstanceProfileBuildingComplete"] = False
    try:
        ssm_client_current_account = create_aws_client("ssm")

        ssm_waiter = ssm_client_current_account.get_waiter("command_executed")

        ssm_command_id = input_body["CommandId"]
        ssm_waiter.wait(
            CommandId=ssm_command_id,
            InstanceId=instance_id,
            WaiterConfig={"Delay": 60, "MaxAttempts": 3},
        )
        output_body["isInstanceProfileBuildingComplete"] = True
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

        exception_message = str(e)
        return create_response(200, output_body)
