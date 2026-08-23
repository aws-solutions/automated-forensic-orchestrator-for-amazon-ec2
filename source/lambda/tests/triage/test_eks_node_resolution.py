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

"""Resolving the EC2 node behind an EKS GuardDuty finding.

A GuardDuty EKS finding names the cluster, not the instance. For a finding
attributed to a node, triage derives the node's private IP from the Kubernetes
username and looks the instance up by that IP. Two things there are easy to get
wrong and neither shows up in a happy-path assertion on statusCode:

*   ``list(instance_id)`` instead of ``[instance_id]``. InstanceId is a string,
    so ``list()`` returns its characters - 19 of them - which then became the
    forensic record's resource_id and, downstream, ForensicInstanceIds. Every
    acquisition would iterate the characters and try to image instances called
    "i", "-" and "0". The EKS Node path could not have worked.
*   the private IP derivation itself, which is string surgery on a Kubernetes
    username of the form ``system:node:ip-10-1-3-45.ec2.internal``.
"""

import pytest

from ...src.common.node_processing import normalize_instance_ids


def derive_node_ip(username):
    """The derivation triage performs, kept identical to app.py."""
    return username.split(":")[-1].split(".")[0].replace("-", ".").strip("ip.")


class TestNodeIpDerivation:
    @pytest.mark.parametrize(
        "username,expected",
        [
            ("system:node:ip-10-1-3-45.ec2.internal", "10.1.3.45"),
            ("system:node:ip-10-0-0-1.ec2.internal", "10.0.0.1"),
            ("system:node:ip-172-31-255-254.ec2.internal", "172.31.255.254"),
            # us-east-1 uses .ec2.internal, other regions use
            # .<region>.compute.internal; only the first label matters.
            (
                "system:node:ip-10-1-3-45.us-west-2.compute.internal",
                "10.1.3.45",
            ),
        ],
    )
    def test_the_private_ip_is_recovered_from_the_kubernetes_username(
        self, username, expected
    ):
        assert derive_node_ip(username) == expected

    def test_the_derived_value_is_a_usable_describe_instances_filter(self):
        # It is passed straight into a private-ip-address filter, so it has to
        # be four dotted decimal octets and nothing else.
        ip = derive_node_ip("system:node:ip-10-1-3-45.ec2.internal")
        octets = ip.split(".")
        assert len(octets) == 4
        assert all(o.isdigit() and 0 <= int(o) <= 255 for o in octets)


class TestAffectedNodeList:
    """The shape handed to create_forensic_record as resource_id."""

    INSTANCE_ID = "i-0f295a8ed1cf3e4cb"

    def describe_instances_response(self):
        return {
            "Reservations": [{"Instances": [{"InstanceId": self.INSTANCE_ID}]}]
        }

    def test_the_node_list_holds_the_instance_id_not_its_characters(self):
        response = self.describe_instances_response()

        # The corrected expression.
        affected_node_list = [
            response["Reservations"][0]["Instances"][0]["InstanceId"]
        ]

        assert affected_node_list == [self.INSTANCE_ID]
        assert len(affected_node_list) == 1

    def test_the_original_expression_is_demonstrably_wrong(self):
        """Guards the fix by showing what it replaced.

        If someone reintroduces list(), this documents exactly what breaks.
        """
        response = self.describe_instances_response()

        broken = list(
            response["Reservations"][0]["Instances"][0]["InstanceId"]
        )

        assert broken != [self.INSTANCE_ID]
        assert len(broken) == len(self.INSTANCE_ID)
        assert broken[0] == "i" and broken[1] == "-"

    def test_the_node_list_survives_normalisation_used_downstream(self):
        """performMemoryAcquisition funnels this through normalize_instance_ids,
        which passes a list straight through - so a character list would reach
        send_command as 19 separate instance ids."""
        good = [self.INSTANCE_ID]
        assert normalize_instance_ids(good) == [self.INSTANCE_ID]

        broken = list(self.INSTANCE_ID)
        assert len(normalize_instance_ids(broken)) == len(self.INSTANCE_ID)


def test_triage_does_not_apply_list_to_an_instance_id():
    """Guards app.py itself, not just the expression above.

    Driving the real EKS Node branch needs a live cluster, so this asserts on the
    source: the broken form must not come back. The distinction matters because
    both forms are valid Python and produce a list, so nothing else fails.
    """
    import re
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2] / "src" / "triage" / "app.py"
    ).read_text()

    # list(...) wrapped directly around a subscript ending in ["InstanceId"]
    broken = re.compile(
        r"list\(\s*[^)]*\[\s*[\"']InstanceId[\"']\s*\]\s*\)", re.S
    )
    offenders = broken.findall(source)
    assert not offenders, (
        "triage/app.py applies list() to an InstanceId string, which yields its "
        f"characters rather than the id: {offenders}"
    )

    # and the corrected form is present, so this test cannot pass vacuously by
    # the branch having been deleted
    assert '"InstanceId"' in source
    assert "affected_node_list = [" in source
