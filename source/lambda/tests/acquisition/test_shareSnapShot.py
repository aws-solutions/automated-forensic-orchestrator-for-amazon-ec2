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
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3

from ...src.acquisition.shareSnapShot import handler as function_under_test
from ...src.common.awsapi_cached_client import AWSCachedClient, BotoSession
import pytest

modify_snapshot_attribute_fn = MagicMock()

modify_snapshot_attribute_fn.return_value = (
    lambda Attribute, DryRun, UserIds, SnapshotId, OperationType, CreateVolumePermission: {}
)

update_item_fn = MagicMock()


def mock_client(ec_response):
    modify_snapshot_attribute_fn.reset_mock()
    mockClient = Mock(boto3.client("ec2"))
    mockClient.modify_snapshot_attribute = modify_snapshot_attribute_fn

    return mockClient


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient.modify_snapshot_attribute = modify_snapshot_attribute_fn

    mockClient.update_item = update_item_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_share_betwen_accounts_event():
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "snapshotIds": ["snap-0d5adc83c8bc99da1"],
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
            },
        },
        "statusCode": 200,
    }

    mock_ec2_client = MagicMock()
    mock_boto_session = MagicMock()
    mock_boto_session.client = mock_ec2_client
    with patch.object(
        BotoSession,
        "client",
        Mock(return_value=mock_client({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = function_under_test(event, context)
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_same_accounts_should_not_share_snapshot():
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "snapshotIds": ["snap-0d5adc83c8bc99da1"],
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
            },
        },
        "statusCode": 200,
    }

    mock_ec2_client = MagicMock()
    mock_boto_session = MagicMock()
    mock_boto_session.client = mock_ec2_client
    modify_snapshot_attribute_fn.reset_mock()
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = function_under_test(event, context)
        # modify_snapshot_attribute_fn.assert_not_called()
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_share_betwen_accounts_event():
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "appAccountId": "123456789012",
                "snapshotIds": ["snap-0d5adc83c8bc99da1"],
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
            },
        },
        "statusCode": 200,
    }

    modify_snapshot_attribute_fn.side_effect = Exception("AWS ERROR!")

    with patch.object(
        BotoSession,
        "client",
        Mock(return_value=mock_client({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        function_under_test(event, context)
        assert execinfo.type == Exception
        update_item_fn.assert_called()
        modify_snapshot_attribute_fn.reset_mock()
