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

"""Credentials must not reach CloudWatch Logs.

Two real leaks motivated this, both found by a security review rather than by
anything in the build:

* ``runForensicsCommand`` logged the ``params`` dict it sends to Systems Manager,
  containing the ``AccessKeyId``, ``SecretAccessKey`` and ``SessionToken`` it had
  just obtained from ``AssumeRole``.
* ``kernelSymbolLoader`` logged its raw event, which for a Red Hat target carries
  the customer's Red Hat subscription ``username`` and ``password`` - not a
  short-lived AWS credential but a long-lived one belonging to someone else.

The last test is the one that matters over time: it walks the handlers and fails
if any of them logs a raw payload again.
"""

import re
from pathlib import Path

import pytest

from ...src.common.redact import (
    REDACTED,
    redact,
    sensitive_key_names,
    trace,
)

SRC = Path(__file__).resolve().parents[2] / "src"


class TestRedact:
    def test_masks_the_sts_triple(self):
        params = {
            "AccessKeyId": ["AKIAIOSFODNN7EXAMPLE"],
            "SecretAccessKey": ["wJalrXUtnFEMI/K7MDENG"],
            "SessionToken": ["FwoGZXIvYXdzEM3"],
            "Region": ["us-east-1"],
            "s3Location": ["s3://bucket/key"],
        }
        out = redact(params)
        assert out["AccessKeyId"] == REDACTED
        assert out["SecretAccessKey"] == REDACTED
        assert out["SessionToken"] == REDACTED
        # Everything else survives, or the log line stops being useful.
        assert out["Region"] == ["us-east-1"]
        assert out["s3Location"] == ["s3://bucket/key"]

    def test_masks_the_red_hat_subscription_pair(self):
        event = {
            "amiId": "ami-0123",
            "distribution": "RHEL8",
            "username": "customer@example.com",
            "password": "hunter2",
        }
        out = redact(event)
        assert out["username"] == REDACTED
        assert out["password"] == REDACTED
        assert out["distribution"] == "RHEL8"

    def test_masks_the_ssm_parameter_spellings_too(self):
        # The symbol builder sends these as SSM document parameters, so the same
        # secret appears under a second set of names.
        out = redact(
            {
                "SubscriptionManagerUsername": ["u"],
                "SubscriptionManagerPassword": ["p"],
            }
        )
        assert out["SubscriptionManagerUsername"] == REDACTED
        assert out["SubscriptionManagerPassword"] == REDACTED

    def test_reaches_credentials_nested_in_the_state_machine_payload(self):
        # Where they actually live: several levels down under Payload.body.
        event = {
            "Payload": {
                "body": {
                    "forensicId": "abc",
                    "InstanceResults": {
                        "i-0abc": {"MemoryAcquisition": {"SessionToken": "t"}}
                    },
                }
            }
        }
        out = redact(event)
        token = out["Payload"]["body"]["InstanceResults"]["i-0abc"][
            "MemoryAcquisition"
        ]["SessionToken"]
        assert token == REDACTED
        assert out["Payload"]["body"]["forensicId"] == "abc"

    def test_matches_regardless_of_case_or_separator(self):
        out = redact({"secret_access_key": "x", "Session-Token": "y"})
        assert out["secret_access_key"] == REDACTED
        assert out["Session-Token"] == REDACTED

    def test_does_not_mutate_the_input(self):
        # The handler logs the payload and then sends it onward. A redactor that
        # emptied it in place would be worse than the leak it fixes.
        params = {"SecretAccessKey": ["real"], "Region": ["us-east-1"]}
        redact(params)
        assert params["SecretAccessKey"] == ["real"]

    def test_survives_a_self_referential_payload(self):
        payload = {"forensicId": "abc"}
        payload["self"] = payload
        redact(payload)  # bounded depth: must return rather than recurse forever

    def test_passes_through_scalars_and_none(self):
        assert redact("plain") == "plain"
        assert redact(None) is None
        assert redact(7) == 7

    def test_lists_are_walked(self):
        out = redact([{"password": "p"}, {"forensicId": "abc"}])
        assert out[0]["password"] == REDACTED
        assert out[1]["forensicId"] == "abc"

    def test_the_key_list_covers_what_this_solution_actually_passes(self):
        names = set(sensitive_key_names())
        for required in (
            "accesskeyid",
            "secretaccesskey",
            "sessiontoken",
            "password",
            "username",
        ):
            assert required in names


class TestTrace:
    def test_selects_only_the_named_fields(self):
        body = {
            "forensicId": "abc",
            "forensicType": "MEMORY",
            "SecretAccessKey": "should never appear",
        }
        assert trace(body, "forensicId", "forensicType") == {
            "forensicId": "abc",
            "forensicType": "MEMORY",
        }

    def test_omits_absent_fields_rather_than_reporting_them_as_None(self):
        assert trace({"forensicId": "abc"}, "forensicId", "missing") == {
            "forensicId": "abc"
        }

    def test_a_non_dict_payload_yields_nothing(self):
        assert trace("not a dict", "forensicId") == {}


class TestNoHandlerLogsARawPayload:
    """The check that keeps this fixed.

    Each pattern below is a real line that was in the code and is exactly how the
    two credential leaks reached CloudWatch.
    """

    FORBIDDEN = [
        (r"logger\.info\(event\)", "logger.info(event)"),
        (r"logger\.info\(params\)", "logger.info(params)"),
        (r"logger\.info\(output_body\)", "logger.info(output_body)"),
        (r"logger\.info\(input_body\)", "logger.info(input_body)"),
        (
            r'logger\.info\(\s*f?"[^"]*\{event\}',
            "an f-string interpolating the whole event",
        ),
        (
            r'logger\.info\(\s*"Got event\{\}"\.format\(event\)',
            'logger.info("Got event{}".format(event))',
        ),
        (
            r'logger\.info\(\s*f?"[^"]*\{input_body\}',
            "an f-string interpolating the whole input body",
        ),
    ]

    @pytest.mark.parametrize("handler", sorted(SRC.rglob("*.py")), ids=str)
    def test_no_raw_payload_logging(self, handler):
        if handler.name == "redact.py":
            return  # this module documents the patterns it exists to prevent
        code = "\n".join(
            line
            for line in handler.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        for pattern, description in self.FORBIDDEN:
            assert not re.search(pattern, code), (
                f"{handler.relative_to(SRC)} logs a raw payload via "
                f"{description}. Wrap it in redact() or select fields with "
                "trace() - this is how the STS triple and the Red Hat "
                "subscription password reached CloudWatch Logs."
            )
