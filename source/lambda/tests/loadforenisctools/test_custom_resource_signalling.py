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

"""CloudFormation signalling invariants for the custom resource Lambdas.

A custom resource that ends without a response leaves the stack in
CREATE_IN_PROGRESS until the one hour timeout expires, and one that sends two
responses leaves which of them wins to a race. Neither shows up in a happy path
test, so each invariant is asserted directly here.
"""

import os
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from ...src.customaction import createCustomAction
from ...src.loadforensictools import loadForensicTools


def statuses_sent(send_status):
    """The Status of every CloudFormation response the handler attempted."""
    return [
        call.args[2] if len(call.args) > 2 else call.kwargs.get("status")
        for call in send_status.call_args_list
    ]


# ---------------------------------------------------------------- B-2 / no-signal


@pytest.mark.parametrize(
    "resource_id",
    [
        ["a", "list"],
        {"a": "dict"},
        1234,
        None,
    ],
)
def test_the_physical_resource_id_can_never_raise(resource_id):
    """This runs before the first try block, so if it raises the handler exits
    with zero signals sent - the one outcome the restructure exists to prevent.

    A list made "CustomAction" + Id raise TypeError.
    """
    event = {"ResourceProperties": {"Id": resource_id}}

    resolved = loadForensicTools.resolve_physical_resource_id(event)

    assert isinstance(resolved, str)
    assert resolved.startswith("CustomAction")


def test_the_physical_resource_id_survives_a_hostile_event():
    """Nothing about the event shape may make this raise."""
    for event in (
        {},
        {"ResourceProperties": None},
        {"ResourceProperties": {}},
    ):
        assert loadForensicTools.resolve_physical_resource_id(
            event
        ).startswith("CustomAction")


# ------------------------------------------------------------------ B-1 / double


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "SECURITY_HUB_ACCOUNT": "123456789012",
    },
)
def test_an_invalid_request_type_signals_exactly_once():
    """FAILED used to be followed by SUCCESS on the same invocation.

    A failing PUT re-raising out of send_status_to_cfn was the only thing that
    ever prevented the fall-through; once delivery was retried and its failure
    swallowed, SUCCESS was always attempted afterwards.
    """
    event = {
        "RequestType": "Frobnicate",
        "ResourceProperties": {
            "Id": "ForensicTriageAction",
            "Name": "Forensic Triage",
            "Description": "d",
        },
        "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/s/1",
        "RequestId": "req-1",
        "LogicalResourceId": "logical",
        "ResponseURL": "https://example.invalid/presigned",
    }
    context = MagicMock()
    context.invoked_function_arn = (
        "arn:aws:lambda:ap-southeast-2:123456789012:function:Fo-createAction"
    )

    send_status = MagicMock()
    with patch.object(
        createCustomAction, "send_status_to_cfn", send_status
    ), patch.object(createCustomAction, "AWSCachedClient", MagicMock()):
        createCustomAction.lambda_handler(event, context)

    sent = statuses_sent(send_status)
    assert sent == ["FAILED"], f"expected exactly one FAILED, got {sent}"


# --------------------------------------------------------------- A-4 / budgeting


def test_the_ec2_status_waiter_is_bounded_by_the_remaining_budget():
    """botocore's default for instance_status_ok is 15s x 40 = 600s, two thirds
    of the Lambda budget, and this waiter never consulted the clock - so the
    cleanup reserve was honoured only by accident."""
    context = MagicMock()
    context.get_remaining_time_in_millis = MagicMock(return_value=900000)

    budget = loadForensicTools.remaining_budget_seconds(context)
    assert budget == 900 - loadForensicTools.CLEANUP_RESERVE_SECONDS

    share = int(budget * loadForensicTools.EC2_WAITER_BUDGET_SHARE)
    attempts = max(1, share // loadForensicTools.EC2_WAITER_DELAY_SECONDS)
    ec2_worst_case = attempts * loadForensicTools.EC2_WAITER_DELAY_SECONDS

    # The status waiter alone must leave room for the registration poll and the
    # cleanup reserve inside the 900s Lambda maximum.
    assert (
        ec2_worst_case
        + loadForensicTools.SSM_REGISTRATION_MAX_SECONDS
        + loadForensicTools.CLEANUP_RESERVE_SECONDS
        <= 900
    ), "the fixed waits still exceed the Lambda budget"

    # And it must collapse, not expand, when little budget is left.
    starved = MagicMock()
    starved.get_remaining_time_in_millis = MagicMock(return_value=130000)
    starved_budget = loadForensicTools.remaining_budget_seconds(starved)
    assert starved_budget < budget
    assert (
        max(
            1,
            int(starved_budget * loadForensicTools.EC2_WAITER_BUDGET_SHARE)
            // loadForensicTools.EC2_WAITER_DELAY_SECONDS,
        )
        < attempts
    )
