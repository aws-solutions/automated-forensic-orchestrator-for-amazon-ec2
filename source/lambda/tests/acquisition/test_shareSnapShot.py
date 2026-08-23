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
import pytest

from ...src.acquisition.shareSnapShot import handler as function_under_test
from ...src.common.awsapi_cached_client import AWSCachedClient, BotoSession

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
@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
@patch.object(AWSCachedClient, "_get_local_account_id", Mock(return_value={}))
def test_same_account_disk_flow_returns_success():
    """Named "share between accounts", but instanceAccount here equals the account
    in invoked_function_arn, so this is the same-account path.

    _get_local_account_id is patched, as in every other suite that constructs an
    AWSCachedClient, because it calls sts:GetCallerIdentity. Without the patch
    this test made a real call to STS: it passed on a developer machine by
    silently using that developer's credentials, and failed in CI where there are
    none. The environment decorator is here for the same reason the neighbouring
    tests have one - without it the test read whatever region the shell happened
    to export."""
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
                "instanceRegion": "ap-southeast-2",
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
        modify_snapshot_attribute_fn.assert_not_called()
        assert ret.get("statusCode") == 200
        # Nothing is shared, but sharing is nonetheless complete: the snapshot
        # is already in the forensic account because it is the application
        # account. isSnapshotShared is a phase marker downstream -
        # checkCopySnapShotStatus only writes isSnapShotCopyComplete on the
        # sharing-complete branch, and the "Is Copy SnapShot Complete" choice
        # reads exactly that path. Leaving this False made every single-account
        # disk acquisition fail with States.Runtime "invalid path" after the
        # snapshot had been taken and copied. Asserting only statusCode 200,
        # as this test used to, passed throughout.
        assert ret["body"]["isSnapshotShared"] is True


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_a_sharing_failure_propagates():
    """This used to share its name with the test above, so only this one ran."""
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "appAccountId": "123456789012",
                "snapshotIds": ["snap-0d5adc83c8bc99da1"],
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "instanceRegion": "ap-southeast-2",
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


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_a_snapshot_is_shared_when_the_accounts_differ():
    """The primary production path: the application account is not the forensic
    account, so the snapshot has to be shared with it before it can be copied.

    This branch had no coverage, because the test that was meant to exercise it
    shared a function name with the one below and was therefore never defined.
    """
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "210987654321",
                "instanceRegion": "ap-southeast-2",
                "snapshotIds": ["snap-0d5adc83c8bc99da1"],
                "snapshotArtifactMap": {
                    "snap-0d5adc83c8bc99da1": "artifact-1"
                },
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
            },
        },
        "statusCode": 200,
    }

    modify_snapshot_attribute_fn.reset_mock(side_effect=True)
    modify_snapshot_attribute_fn.return_value = {}

    # Two seams: BotoSession.client is the assumed-role EC2 client the sharing
    # branch builds, AWSCachedClient.get_connection is what the forensic data
    # service uses for DynamoDB.
    with patch.object(
        BotoSession, "client", Mock(return_value=mock_client({}))
    ), patch.object(
        AWSCachedClient, "get_connection", Mock(return_value=MagicMock())
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = function_under_test(event, context)

    assert ret.get("statusCode") == 200
    assert ret["body"]["isSnapshotShared"] is True
    assert ret["body"]["appAccount"] == "210987654321"
    assert ret["body"]["snapshotIdsShared"] == ["snap-0d5adc83c8bc99da1"]
    # The snapshot really was shared, with the application account.
    modify_snapshot_attribute_fn.assert_called()
    shared_with = modify_snapshot_attribute_fn.call_args.kwargs
    assert "210987654321" in str(shared_with)


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_every_node_of_an_eks_cluster_is_shared():
    """EKS findings carry several nodes, each with its own snapshots.

    This branch is separate code from the single-instance one and had no
    coverage: a node whose snapshots were never shared cannot be copied into the
    forensic account, so its evidence is simply absent from the case.
    """
    node_a = "i-0aaaaaaaaaaaaaaaa"
    node_b = "i-0bbbbbbbbbbbbbbbb"
    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "instanceAccount": "210987654321",
                "instanceRegion": "ap-southeast-2",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "clusterInfo": {"affectedNode": [node_a, node_b]},
                node_a: {
                    "snapshotIds": ["snap-0aaa"],
                    "snapshotArtifactMap": {"snap-0aaa": "artifact-a"},
                },
                node_b: {
                    "snapshotIds": ["snap-0bbb", "snap-0ccc"],
                    "snapshotArtifactMap": {
                        "snap-0bbb": "artifact-b",
                        "snap-0ccc": "artifact-c",
                    },
                },
            },
        },
        "statusCode": 200,
    }

    modify_snapshot_attribute_fn.reset_mock(side_effect=True)
    modify_snapshot_attribute_fn.return_value = {}

    with patch.object(
        BotoSession, "client", Mock(return_value=mock_client({}))
    ), patch.object(
        AWSCachedClient, "get_connection", Mock(return_value=MagicMock())
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = function_under_test(event, context)

    assert ret.get("statusCode") == 200
    # Every node is marked shared, and every one of its snapshots was shared.
    for node in (node_a, node_b):
        assert ret["body"][node]["isSnapshotShared"] is True
    shared = {
        call.kwargs.get("SnapshotId")
        for call in modify_snapshot_attribute_fn.call_args_list
    }
    assert shared == {"snap-0aaa", "snap-0bbb", "snap-0ccc"}, (
        f"only {shared} were shared; a node's snapshots that are never shared "
        "cannot be copied into the forensic account"
    )
