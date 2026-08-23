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

"""Lifecycle of the Security Hub custom action resource.

This custom resource creates the "Forensic Triage" action an analyst clicks in
the Security Hub console. Its Create, Delete and error branches all end in a
CloudFormation signal, and a branch that signals twice - or not at all - either
races or hangs the stack for an hour.

The tolerated ClientErrors matter as much as the happy paths: a stack that is
redeployed over an existing action, or torn down after the action is already
gone, must not fail.
"""

import os
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from ...src.customaction import createCustomAction

ENVIRONMENT = {"AWS_REGION": "ap-southeast-2"}

ACTION_ARN = (
    "arn:aws:securityhub:ap-southeast-2:123456789012:action/custom/"
    "ForensicTriageAction"
)


def build_event(request_type):
    return {
        "RequestType": request_type,
        "ResourceProperties": {
            "Id": "ForensicTriageAction",
            "Name": "Forensic Triage",
            "Description": "Trigger Forensic Triage Action",
        },
        "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/s/1",
        "RequestId": "req-1",
        "LogicalResourceId": "logical",
        "ResponseURL": "https://example.invalid/presigned",
    }


def build_context():
    context = MagicMock()
    context.invoked_function_arn = (
        "arn:aws:lambda:ap-southeast-2:123456789012:function:Fo-createAction"
    )
    return context


def client_error(code, operation):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


def run(event, security_hub):
    """Invoke the handler, returning the statuses signalled to CloudFormation."""
    send_status = MagicMock()
    cached = MagicMock()
    cached.get_connection.return_value = security_hub
    with patch.object(
        createCustomAction, "send_status_to_cfn", send_status
    ), patch.object(
        createCustomAction, "AWSCachedClient", MagicMock(return_value=cached)
    ):
        createCustomAction.lambda_handler(event, build_context())
    return [
        call.args[2] if len(call.args) > 2 else call.kwargs.get("status")
        for call in send_status.call_args_list
    ], send_status


@mock.patch.dict(os.environ, ENVIRONMENT)
@pytest.mark.parametrize("request_type", ["Create", "Update"])
def test_create_and_update_register_the_action_and_signal_success(
    request_type,
):
    security_hub = MagicMock()
    security_hub.create_action_target.return_value = {
        "ActionTargetArn": ACTION_ARN
    }

    statuses, send_status = run(build_event(request_type), security_hub)

    security_hub.create_action_target.assert_called_once()
    assert security_hub.create_action_target.call_args.kwargs["Id"] == (
        "ForensicTriageAction"
    )
    assert statuses == ["SUCCESS"]
    # The action ARN is what the EventBridge rule pattern is built from.
    assert send_status.call_args.args[3]["Arn"] == ACTION_ARN


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_an_action_that_already_exists_is_not_a_deployment_failure():
    """Redeploying over an existing action must succeed.

    Security Hub returns ResourceConflictException, which is tolerated because
    the desired state already holds.
    """
    security_hub = MagicMock()
    security_hub.create_action_target.side_effect = client_error(
        "ResourceConflictException", "CreateActionTarget"
    )

    statuses, _ = run(build_event("Create"), security_hub)

    assert statuses == ["SUCCESS"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_an_account_not_subscribed_to_security_hub_fails_the_resource():
    """InvalidAccessException is deliberately NOT tolerated on create: the
    solution cannot work without Security Hub, and silently succeeding would
    leave an operator with no custom action and no error."""
    security_hub = MagicMock()
    security_hub.create_action_target.side_effect = client_error(
        "InvalidAccessException", "CreateActionTarget"
    )

    statuses, _ = run(build_event("Create"), security_hub)

    assert statuses == ["FAILED"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_delete_removes_the_action_and_signals_success():
    security_hub = MagicMock()

    statuses, _ = run(build_event("Delete"), security_hub)

    security_hub.delete_action_target.assert_called_once_with(
        ActionTargetArn=ACTION_ARN
    )
    assert statuses == ["SUCCESS"]


@mock.patch.dict(os.environ, ENVIRONMENT)
@pytest.mark.parametrize(
    "code", ["ResourceNotFoundException", "InvalidAccessException"]
)
def test_deleting_an_action_that_is_already_gone_still_succeeds(code):
    """A stack teardown must not be blocked by an action someone removed by
    hand, or by an account that has since unsubscribed from Security Hub."""
    security_hub = MagicMock()
    security_hub.delete_action_target.side_effect = client_error(
        code, "DeleteActionTarget"
    )

    statuses, _ = run(build_event("Delete"), security_hub)

    assert statuses == ["SUCCESS"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_an_unexpected_client_error_on_delete_fails_the_resource():
    security_hub = MagicMock()
    security_hub.delete_action_target.side_effect = client_error(
        "AccessDeniedException", "DeleteActionTarget"
    )

    statuses, _ = run(build_event("Delete"), security_hub)

    assert statuses == ["FAILED"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_every_request_type_signals_exactly_once():
    """The invariant behind all of the above: one invocation, one response.

    CloudFormation acts on the first response it receives, so two responses make
    the outcome a race and none hangs the stack until the one hour custom
    resource timeout expires.
    """
    for request_type in ("Create", "Update", "Delete", "Frobnicate"):
        security_hub = MagicMock()
        security_hub.create_action_target.return_value = {
            "ActionTargetArn": ACTION_ARN
        }
        statuses, _ = run(build_event(request_type), security_hub)
        assert len(statuses) == 1, (
            f"{request_type} sent {statuses} - a custom resource may signal "
            "exactly once"
        )
