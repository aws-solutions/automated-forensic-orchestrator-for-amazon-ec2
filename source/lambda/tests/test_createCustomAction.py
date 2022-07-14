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

"""
Unit Test: createCustomAction.py
"""

import os
import pytest

import boto3
from unittest import mock
from unittest.mock import MagicMock, Mock, patch
from botocore.stub import Stubber, ANY
from ..src.common.awsapi_cached_client import AWSCachedClient
from ..src.customaction.createCustomAction import (
    send_status_to_cfn as function_send_status_test,
)

from ..src.customaction.createCustomAction import (
    lambda_handler as function_lambda_handler_test,
)
from ..src.common.log import get_logger


# initialise loggers
logger = get_logger(__name__)

event = {
    "RequestType": "Create",
    "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
    "ResponseURL": "https://cloudformation-custom-resource-response-apsoutheast2.s3-ap-southeast-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aap-southeast-2%3A123456789012%3Astack/ForensicSolutionStack",
    "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicSolutionStack/8dfc7990-5942-11ec-93ec-0613a5a5f95a",
    "RequestId": "6715ccf3-ce9a-4eff-b32d-586c71ca8fda",
    "LogicalResourceId": "securityHubCustomActionCustomAction6FF54E59",
    "ResourceType": "Custom::ActionTarget",
    "ResourceProperties": {
        "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
        "Description": "Trigger Forensic Triage Action",
        "Id": "ForensicTriageAction",
        "Name": "Forensic Triage ",
    },
}


def mock_connection(ec_response):
    mockClient = Mock(boto3)
    mockClient.client = MagicMock()
    return mockClient


def mocked_requests_put(*args, **kwargs):
    return {"reason": ""}


@mock.patch("requests.put", side_effect=mocked_requests_put)
def test_trigger_send_custom_action__event(self):

    context = MagicMock()
    context.log_stream_name = "customaction"
    ret = function_send_status_test(
        event,
        context,
        "SUCCESS",
        "Data",
        "123456",
        logger,
        reason="err_msg",
    )
    assert ret.get("statusCode") == 200


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("securityhub"))
    mockClient.get_caller_identity = MagicMock()
    mockClient._get_local_account_id = lambda: {}
    mockClient.create_action_target = {"ActionTargetArn": "ActionTargetArn"}
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "LIME_MEMORY_LOAD_INVESTIGATION": "documentName",
        "AWS_ACCESS_KEY_ID": "foo",
        "AWS_SECRET_ACCESS_KEY": "bar",
    },
)
@mock.patch("requests.put", side_effect=mocked_requests_put)
def test_trigger_event(self):

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection({})),
    ) as mockConnection:
        context = MagicMock()
        context.log_stream_name = "customaction"
        ret = function_lambda_handler_test(event, context)
        assert ret.get("statusCode") == 500
