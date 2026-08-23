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

"""Telling someone the analysis instance is still running.

`terminateForensicInstance` sits only on the investigation state machine's
success path; every task's `addCatch` routes to `sendErrorNotification` and then
to a Fail state, which never touches the instance. That is the behaviour we want
- the capture is already downloaded and decompressed under /data on that host,
so terminating it on failure would destroy the only place the failure can be
diagnosed. Reading a retained host is how the 97.7%-NUL LiME capture was
identified.

What was missing was any acknowledgement of it. Two m6i.2xlarge instances sat
running after two failed investigations with nothing in the notification, nothing
in the forensic record and no owner. These tests pin the acknowledgement, not the
retention.
"""

import json
import os
from unittest import mock
from unittest.mock import MagicMock, patch

from ...src.notification import sendErrorNotification

FORENSIC_ID = "17a681b8-6afd-48a7-8c0b-7533d71911d7"
ANALYSIS_INSTANCE = "i-01f8e595949ee68b4"
TARGET_INSTANCE = "i-08a12637d4be98794"

ENVIRONMENT = {
    "AWS_REGION": "us-east-1",
    "INSTANCE_TABLE_NAME": "table",
    "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:forensic",
}


def build_event(include_analysis_instance: bool):
    body = {
        "forensicId": FORENSIC_ID,
        "errorName": "Error: Check Forensic Investigation Status",
        "errorDescription": (
            "Error while performing forensic analysis for forensic id: "
            f"{FORENSIC_ID}"
        ),
        "errorPhase": "INVESTIGATION",
        "errorComponentId": "checkForensicInvestigationStatus",
        "errorComponentType": "Lambda",
        "forensicType": "MEMORY",
    }
    if include_analysis_instance:
        body["ForensicInvestigationInstanceId"] = ANALYSIS_INSTANCE

    return {"Cause": json.dumps({"errorMessage": json.dumps(body)})}


def run_handler(event):
    """Returns (published message, timeline event calls)."""
    sns_client = MagicMock()
    forensic_record = MagicMock()
    forensic_record.resourceId = TARGET_INSTANCE
    forensic_record.awsAccountId = "123456789012"

    data_service = MagicMock()
    data_service.get_forensic_record.return_value = forensic_record

    with patch.object(
        sendErrorNotification, "create_aws_client", lambda *a, **k: sns_client
    ), patch.object(
        sendErrorNotification,
        "ForensicDataService",
        MagicMock(return_value=data_service),
    ):
        sendErrorNotification.handler(event, MagicMock())

    assert (
        sns_client.publish.call_args is not None
    ), "no notification was published, so this test would assert nothing"
    return (
        sns_client.publish.call_args.kwargs["Message"],
        data_service.add_forensic_timeline_event.call_args_list,
    )


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_notification_names_the_retained_instance():
    message, _ = run_handler(build_event(include_analysis_instance=True))

    assert ANALYSIS_INSTANCE in message, (
        "the failure notification does not mention the analysis instance, so "
        "nobody knows an 8 vCPU instance is still running"
    )


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_notification_says_retention_is_deliberate_and_needs_action():
    message, _ = run_handler(build_event(include_analysis_instance=True))

    lowered = message.lower()
    # Deliberate, so it is not read as a leak...
    assert "on purpose" in lowered or "deliberate" in lowered
    # ...and someone has to act, so it is not read as self-cleaning.
    assert "terminate" in lowered
    # And where the evidence is, which is the reason for keeping it.
    assert "/data" in message


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_forensic_record_carries_the_retention():
    """SNS is fire and forget; the record is what an analyst returns to."""
    _, timeline_calls = run_handler(
        build_event(include_analysis_instance=True)
    )

    retention_events = [
        call
        for call in timeline_calls
        if "retain" in str(call.kwargs.get("name", "")).lower()
    ]
    assert (
        retention_events
    ), "nothing in the forensic record says the instance was retained"

    event_data = retention_events[0].kwargs.get("event_data") or {}
    assert (
        event_data.get("ForensicInvestigationInstanceId") == ANALYSIS_INSTANCE
    )
    assert event_data.get("retainedForDiagnosis") is True


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_a_failure_before_the_instance_exists_says_nothing_about_retention():
    """Most failures happen before an analysis instance is created.

    Acquisition and triage failures route through the same notification, and
    claiming an instance was retained when none exists would send an operator
    looking for something that is not there.
    """
    message, timeline_calls = run_handler(
        build_event(include_analysis_instance=False)
    )

    assert "left running" not in message.lower()
    assert "terminate" not in message.lower()
    assert not [
        call
        for call in timeline_calls
        if "retain" in str(call.kwargs.get("name", "")).lower()
    ]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_original_failure_is_still_the_subject_of_the_message():
    """The retention note is an addition, not a replacement."""
    message, _ = run_handler(build_event(include_analysis_instance=True))

    assert FORENSIC_ID in message
    assert TARGET_INSTANCE in message
    assert "aborted" in message


def test_terminate_is_not_wired_into_the_investigation_failure_path():
    """Guards the behaviour these tests assume, in the state machine itself.

    If a future change adds terminateForensicInstance to the failure chain, the
    retained-host notification becomes a lie and the diagnostic surface is gone.
    """
    from pathlib import Path

    definition = (
        Path(__file__).resolve().parents[3]
        / "lib"
        / "forensic-orchestrator"
        / "investigation"
        / "investigation-step-functions.ts"
    ).read_text()

    # The failure chain is built once and reused by every addCatch.
    assert "investigationFailedChain" in definition
    chain_start = definition.index("const investigationFailedChain")
    chain_end = definition.index(";", chain_start)
    chain = definition[chain_start:chain_end]

    assert "terminateForensicInstance" not in chain, (
        "terminateForensicInstance has been added to the investigation failure "
        "chain, which destroys the evidence on the analysis host that the "
        "failure has to be diagnosed from"
    )
