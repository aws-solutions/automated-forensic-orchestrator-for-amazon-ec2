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

import boto3
import requests
from aws_xray_sdk.core import xray_recorder
from botocore.exceptions import ClientError

from ..common.awsapi_cached_client import AWSCachedClient
from ..common.common import create_response
from ..common.log import get_logger

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("send_status_to_cfn")
def send_status_to_cfn(
    event,
    context,
    response_status,
    response_data,
    physical_resource_id,
    logger,
    reason=None,
):

    response_url = event["ResponseURL"]
    logger.info("CFN response URL: " + response_url)

    response_body = {}
    response_body["Status"] = response_status
    response_body["PhysicalResourceId"] = (
        physical_resource_id or context.log_stream_name
    )

    msg = f"See details in CloudWatch Log Stream:  {context.log_stream_name}"

    logger.debug("PhysicalResourceId: " + physical_resource_id)
    if not reason:
        response_body["Reason"] = msg
    else:
        response_body["Reason"] = str(reason)[0:255] + "... " + msg

    response_body["StackId"] = event["StackId"]
    response_body["RequestId"] = event["RequestId"]
    response_body["LogicalResourceId"] = event["LogicalResourceId"]

    if response_data and isinstance(response_data, dict):
        response_body["Data"] = response_data

    logger.debug("<<<<<<< Response body >>>>>>>>>>")
    logger.debug(response_body)
    json_response_body = json.dumps(response_body)

    headers = {
        "content-type": "",
        "content-length": str(len(json_response_body)),
    }

    try:
        if response_url == "https://pre-signed-S3-url-for-response":
            logger.info(
                "CloudFormation returned status code: THIS IS A TEST OUTSIDE OF CLOUDFORMATION"
            )
        else:
            response = requests.put(
                response_url, data=json_response_body, headers=headers
            )
            logger.info(response)
            if "reason" in response:
                logger.info(f"CloudFormation returned status code: {response}")

    except Exception as e:
        logger.error("send(..) failed executing requests.put(..): " + str(e))
        raise
    return create_response(200, "send Status successful")


@xray_recorder.capture("Create SecurityHub Action")
def lambda_handler(event, context):

    boto3_session = boto3.session.Session()
    region = boto3_session.region_name

    response_data = {}
    physical_resource_id = ""

    try:
        logger.info(event)
        properties = event["ResourceProperties"]
        logger.debug(json.dumps(properties))
        region = os.environ["AWS_REGION"]
        partition = os.getenv(
            "AWS_PARTITION", default="aws"
        )  # Set by deployment template
        client = AWSCachedClient(region).get_connection("securityhub")
        # boto3.client("securityhub")
        physical_resource_id = "CustomAction" + properties.get("Id", "ERROR")

        logger.info(physical_resource_id)

        if event["RequestType"] in ["Create", "Update"]:
            try:
                logger.info(
                    event["RequestType"].upper() + ": " + physical_resource_id
                )
                response = client.create_action_target(
                    Name=properties["Name"],
                    Description=properties["Description"],
                    Id=properties["Id"],
                )
                logger.info(response)
                response_data["Arn"] = response["ActionTargetArn"]
            except ClientError as error:
                handle_client_error_creation(error)
            except Exception as e:
                logger.error(e)
                raise
        elif event["RequestType"] == "Delete":
            try:
                logger.info("DELETE: " + physical_resource_id)
                account_id = context.invoked_function_arn.split(":")[4]
                client.delete_action_target(
                    ActionTargetArn=f"arn:{partition}:securityhub:{region}:{account_id}:action/custom/{properties['Id']}"
                )
            except ClientError as error:
                handle_client_error_deletion(error)
            except Exception as e:
                logger.error(e)
                raise
        else:
            err_msg = "Invalid RequestType: " + event["RequestType"]
            logger.error(err_msg)
            send_status_to_cfn(
                event,
                context,
                "FAILED",
                response_data,
                physical_resource_id,
                logger,
                reason=err_msg,
            )

        send_status_to_cfn(
            event,
            context,
            "SUCCESS",
            response_data,
            physical_resource_id,
            logger,
        )
        return create_response(200, "send Status successful")

    except Exception as err:
        logger.error("An exception occurred: ")
        err_msg = err.__class__.__name__ + ": " + str(err)
        logger.error(err_msg)
        send_status_to_cfn(
            event,
            context,
            "FAILED",
            response_data,
            physical_resource_id,
            logger,
            reason=err_msg,
        )
        return create_response(500, "send Status Error")


def handle_client_error_deletion(error: ClientError):
    if error.response["Error"]["Code"] == "ResourceNotFoundException":
        logger.info("ResourceNotFoundException - nothing to delete.")
    elif error.response["Error"]["Code"] == "InvalidAccessException":
        logger.info(
            "InvalidAccessException - not subscribed to Security Hub (nothing to delete)."
        )
    else:
        logger.error(error)
        raise error


def handle_client_error_creation(error: ClientError):
    if error.response["Error"]["Code"] == "ResourceConflictException":
        logger.info("ResourceConflictException: already exists. Continuing")
    elif error.response["Error"]["Code"] == "InvalidAccessException":
        logger.info(
            "InvalidAccessException - Account is not subscribed to AWS Security Hub."
        )
        raise error
    else:
        logger.error(error)
        raise error
