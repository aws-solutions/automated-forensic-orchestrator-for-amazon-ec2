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

from multiprocessing import get_logger
import os
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3


from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.imagebuilder.app import (
    lambda_handler as function_under_test,
)

start_image_pipeline_execution_fn = MagicMock()


def mock_connection():
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = MagicMock()

    mockClient.start_image_pipeline_execution = (
        start_image_pipeline_execution_fn
    )

    return mockClient


event = {
    "RequestType": "Create",
    "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicImageBuilderStack-AWSImageBuilderEventssan-r6hszCfWvYHK",
    "ResponseURL": "https://cloudformation-custom-resource-response-apsoutheast2.s3-ap-southeast-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aap-southeast-2%3A123456789012%3Astack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886%7CAWSImageBuilderEventssansift4B95B161%7C934366cb-35f1-4c14-82db-5e16309dc413?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20220302T071211Z&X-Amz-SignedHeaders=host&X-Amz-Expires=7200&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20220302%2Fap-southeast-2%2Fs3%2Faws4_request&X-Amz-Signature=a1c4ba1c0b6d943b1c39b4b6b852240c2a65d17f5f5eab0b77d98db5cd0df281",
    "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886",
    "RequestId": "934366cb-35f1-4c14-82db-5e16309dc413",
    "LogicalResourceId": "AWSImageBuilderEventssansift4B95B161",
    "ResourceType": "AWS::CloudFormation::CustomResource",
    "ResourceProperties": {
        "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicImageBuilderStack-AWSImageBuilderEventssan-r6hszCfWvYHK",
        "PIIPELINE_ARN": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image-pipeline/imagebuilderpipelinesansift",
    },
}


def test_trigger_event():

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        ret = function_under_test(event, {})
        assert ret == {
            "RequestId": "934366cb-35f1-4c14-82db-5e16309dc413",
            "LogicalResourceId": "AWSImageBuilderEventssansift4B95B161",
            "PhysicalResourceId": "img-builder-trigger-cr",
            "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886",
            "Status": "SUCCESS",
            "Reason": "skipped",
        }


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def test_trigger_event():

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        ret = function_under_test(event, {})
        assert ret == {
            "RequestId": "934366cb-35f1-4c14-82db-5e16309dc413",
            "LogicalResourceId": "AWSImageBuilderEventssansift4B95B161",
            "PhysicalResourceId": "img-builder-trigger-cr",
            "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886",
            "Status": "SUCCESS",
            "Reason": "triggered pipeline",
        }


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def test_trigger_event_skipped():

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        delete_event = event.copy()
        delete_event["RequestType"] = "DELETE"
        ret = function_under_test(delete_event, {})
        assert ret == {
            "RequestId": "934366cb-35f1-4c14-82db-5e16309dc413",
            "LogicalResourceId": "AWSImageBuilderEventssansift4B95B161",
            "PhysicalResourceId": "img-builder-trigger-cr",
            "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886",
            "Status": "SUCCESS",
            "Reason": "skipped",
        }


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def test_trigger_event_failed():
    start_image_pipeline_execution_fn.side_effect = Exception("AWS ERROR!")

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        ret = function_under_test(event, {})
        assert ret == {
            "RequestId": "934366cb-35f1-4c14-82db-5e16309dc413",
            "LogicalResourceId": "AWSImageBuilderEventssansift4B95B161",
            "PhysicalResourceId": "img-builder-trigger-cr",
            "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicImageBuilderStack/3c8406a0-99f7-11ec-9efc-06731106c886",
            "Status": "FAILED",
            "Reason": "failed to trigger pipeline",
        }
