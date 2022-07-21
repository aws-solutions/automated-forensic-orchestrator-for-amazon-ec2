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

from ..common.awsapi_cached_client import create_aws_client
from ..common.log import get_logger

logger = get_logger(__name__)


def lambda_handler(event, context):
    """
    response to image builder trigger event
    """
    logger.info("triggering new pipeline")
    # const { RequestType, ResourceProperties } = event;

    logger.info(event)
    logger.info(context)
    request_type = event.get("RequestType")
    if request_type not in ["Create", "Update"]:
        return create_cfn_response(event, "SUCCESS", "skipped")
    pipeline_arn = event.get("ResourceProperties")["PIIPELINE_ARN"]
    imgbuilder_client = create_aws_client("imagebuilder")
    try:
        imgbuilder_client.start_image_pipeline_execution(
            imagePipelineArn=pipeline_arn
        )
    except Exception as e:
        logger.error(e)
        return create_cfn_response(
            event, "FAILED", "failed to trigger pipeline"
        )

    return create_cfn_response(event, "SUCCESS", "triggered pipeline")


def create_cfn_response(event, status: str, reason: str) -> dict:
    return {
        "RequestId": event.get("RequestId"),
        "LogicalResourceId": event.get("LogicalResourceId"),
        "PhysicalResourceId": "img-builder-trigger-cr",
        "StackId": event.get("StackId"),
        "Status": status,
        "Reason": reason,
    }
