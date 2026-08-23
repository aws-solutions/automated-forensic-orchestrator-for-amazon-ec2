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

"""Instance type selection for the forensic analysis host.

The analysis instance is launched into a fixed subnet, so it competes for one
Availability Zone's capacity for whatever type is asked for. A single hardcoded
type therefore loses the investigation whenever that type is momentarily
unavailable - and by then the snapshots have already been taken, so the evidence
exists and the case is lost for an unrelated reason. This happened twice against
a live account, on m4.2xlarge and then on m6i.2xlarge.
"""

import os
from unittest import mock
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from ...src.investigation.createForensicInstance import (
    CAPACITY_ERROR_CODES,
    DEFAULT_ANALYSIS_INSTANCE_TYPES,
    analysis_instance_types,
    run_analysis_instance,
)


def capacity_error(code="InsufficientInstanceCapacity"):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": f"We currently do not have sufficient capacity ({code})",
            }
        },
        "RunInstances",
    )


class TestAnalysisInstanceTypes:
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_the_defaults_are_used_when_nothing_is_configured(self):
        assert analysis_instance_types() == list(
            DEFAULT_ANALYSIS_INSTANCE_TYPES
        )

    @mock.patch.dict(os.environ, {"FORENSIC_INSTANCE_TYPE": "   "})
    def test_a_blank_configuration_falls_back_to_the_defaults(self):
        assert analysis_instance_types() == list(
            DEFAULT_ANALYSIS_INSTANCE_TYPES
        )

    @mock.patch.dict(os.environ, {"FORENSIC_INSTANCE_TYPE": "m5.4xlarge"})
    def test_a_single_configured_type_is_honoured_exactly(self):
        # An operator who pins one type gets one type: no silent substitution.
        assert analysis_instance_types() == ["m5.4xlarge"]

    @mock.patch.dict(
        os.environ,
        {"FORENSIC_INSTANCE_TYPE": "m6i.2xlarge, m5.2xlarge ,r6i.2xlarge"},
    )
    def test_a_list_preserves_the_operators_preference_order(self):
        assert analysis_instance_types() == [
            "m6i.2xlarge",
            "m5.2xlarge",
            "r6i.2xlarge",
        ]

    def test_every_default_is_eight_vcpu_and_thirty_two_gib(self):
        # The fallbacks have to be interchangeable for this workload: the
        # analysis host decompresses a multi-GB capture and runs plaso.
        for instance_type in DEFAULT_ANALYSIS_INSTANCE_TYPES:
            assert instance_type.endswith(".2xlarge"), (
                f"{instance_type} is not a 2xlarge, so it is not a like for "
                "like substitute for the others"
            )


class TestRunAnalysisInstance:
    def test_the_first_available_type_is_used(self):
        ec2 = MagicMock()
        ec2.run_instances.return_value = {"Instances": [{"InstanceId": "i-1"}]}

        result = run_analysis_instance(
            ec2, ["m6i.2xlarge", "m5.2xlarge"], ImageId="ami-1"
        )

        assert result["Instances"][0]["InstanceId"] == "i-1"
        ec2.run_instances.assert_called_once()
        assert (
            ec2.run_instances.call_args.kwargs["InstanceType"] == "m6i.2xlarge"
        )

    def test_a_capacity_error_moves_to_the_next_type(self):
        """The exact failure seen live, twice."""
        ec2 = MagicMock()
        ec2.run_instances.side_effect = [
            capacity_error(),
            {"Instances": [{"InstanceId": "i-2"}]},
        ]

        result = run_analysis_instance(
            ec2, ["m6i.2xlarge", "m5.2xlarge"], ImageId="ami-1"
        )

        assert result["Instances"][0]["InstanceId"] == "i-2"
        tried = [
            call.kwargs["InstanceType"]
            for call in ec2.run_instances.call_args_list
        ]
        assert tried == ["m6i.2xlarge", "m5.2xlarge"]

    @pytest.mark.parametrize("code", CAPACITY_ERROR_CODES)
    def test_every_tolerated_code_triggers_a_fallback(self, code):
        ec2 = MagicMock()
        ec2.run_instances.side_effect = [
            capacity_error(code),
            {"Instances": [{"InstanceId": "i-3"}]},
        ]

        result = run_analysis_instance(ec2, ["a.2xlarge", "b.2xlarge"])

        assert result["Instances"][0]["InstanceId"] == "i-3"

    def test_a_malformed_request_fails_immediately(self):
        """Only capacity errors are worth retrying. An invalid AMI or a missing
        permission is wrong for every instance type, and walking the whole list
        would just delay a failure the operator needs to see."""
        ec2 = MagicMock()
        ec2.run_instances.side_effect = ClientError(
            {"Error": {"Code": "InvalidAMIID.NotFound", "Message": "no ami"}},
            "RunInstances",
        )

        with pytest.raises(ClientError) as raised:
            run_analysis_instance(ec2, ["a.2xlarge", "b.2xlarge"])

        assert (
            raised.value.response["Error"]["Code"] == "InvalidAMIID.NotFound"
        )
        ec2.run_instances.assert_called_once()

    def test_exhausting_every_type_raises_the_last_capacity_error(self):
        """With no capacity anywhere the caller still gets a diagnosable error,
        not None."""
        ec2 = MagicMock()
        ec2.run_instances.side_effect = capacity_error()

        with pytest.raises(ClientError) as raised:
            run_analysis_instance(ec2, ["a.2xlarge", "b.2xlarge", "c.2xlarge"])

        assert (
            raised.value.response["Error"]["Code"]
            == "InsufficientInstanceCapacity"
        )
        assert ec2.run_instances.call_count == 3
