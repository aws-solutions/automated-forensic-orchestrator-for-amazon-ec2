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

import json
import os

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger

logger = get_logger(__name__)


def lambda_handler(event, context):
    """
    response to image builder completion event
    """
    logger.info("image builder completed")
    logger.info(event)
    logger.info(context)
    logger.info(event.get("Records")[0].get("Sns").get("Message"))

    message_body = event.get("Records")[0].get("Sns").get("Message")
    json_body = json.loads(message_body)
    logger.info(json_body["outputResources"]["amis"][0]["image"])
    ami = json_body["outputResources"]["amis"][0]["image"]
    logger.info(f"ami {ami}")
    ssm_key = os.environ["IMAGE_SSM_NAME"]
    logger.info(f"updating ssm {ssm_key}")
    ssm_client = create_aws_client("ssm")
    try:
        result = ssm_client.put_parameter(
            Name=ssm_key,
            Value=ami,
            Type="String",
            DataType="text",
            Tier="Advanced",
            Overwrite=True,
        )
        logger.info(result)
    except Exception as e:
        logger.error(e)

    return create_response(200, {})
