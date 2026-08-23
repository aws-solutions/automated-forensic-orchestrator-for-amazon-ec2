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

"""Instance id and instance info normalisation.

Every acquisition and investigation Lambda funnels its input through these two
functions, so a shape they mishandle silently loses an instance from a finding
rather than failing. Both accept several shapes because triage produces one
shape for a single EC2 instance and another for the nodes of an EKS cluster.
"""

from ...src.common.node_processing import (
    normalize_instance_ids,
    normalize_instance_info,
)

INSTANCE_A = "i-0aaaaaaaaaaaaaaaa"
INSTANCE_B = "i-0bbbbbbbbbbbbbbbb"


class TestNormalizeInstanceIds:
    def test_a_single_id_becomes_a_one_item_list(self):
        assert normalize_instance_ids(INSTANCE_A) == [INSTANCE_A]

    def test_a_list_is_returned_as_is(self):
        assert normalize_instance_ids([INSTANCE_A, INSTANCE_B]) == [
            INSTANCE_A,
            INSTANCE_B,
        ]

    def test_falsy_input_is_an_empty_list_not_a_crash(self):
        # A finding with no resolvable instance must not make the caller iterate
        # over None.
        for empty in (None, "", [], {}):
            assert normalize_instance_ids(empty) == []

    def test_an_unexpected_type_is_coerced_rather_than_dropped(self):
        # Losing an instance silently is worse than carrying an odd looking id
        # that the next API call will reject visibly.
        assert normalize_instance_ids(1234) == ["1234"]

    # Note: the module's own except branch is unreachable. It logs with an
    # f-string that interpolates the same value whose str() just failed, so the
    # handler raises again. Not tested and not "fixed": instance ids reach these
    # functions from DynamoDB and from JSON events, both of which can only
    # produce strings and lists.


class TestNormalizeInstanceInfo:
    def test_a_single_instance_dictionary_is_keyed_by_its_id(self):
        info = {"InstanceId": INSTANCE_A, "PlatformName": "Amazon Linux"}

        assert normalize_instance_info(info) == {INSTANCE_A: info}

    def test_a_list_of_dictionaries_is_keyed_by_id(self):
        a = {"InstanceId": INSTANCE_A, "PlatformName": "Amazon Linux"}
        b = {"InstanceId": INSTANCE_B, "PlatformDetails": "Windows"}

        assert normalize_instance_info([a, b]) == {
            INSTANCE_A: a,
            INSTANCE_B: b,
        }

    def test_a_mapping_already_keyed_by_instance_id_is_preserved(self):
        # performMemoryAcquisition looks up instances_info.get(instance_id), so a
        # mapping that came back keyed already must survive unchanged.
        keyed = {
            INSTANCE_A: {"PlatformName": "Amazon Linux"},
            INSTANCE_B: {"PlatformName": "Ubuntu"},
        }

        normalized = normalize_instance_info(keyed)

        assert set(normalized) == {INSTANCE_A, INSTANCE_B}
        assert normalized[INSTANCE_A]["PlatformName"] == "Amazon Linux"

    def test_falsy_input_is_an_empty_mapping(self):
        for empty in (None, {}, []):
            assert normalize_instance_info(empty) == {}

    def test_the_platform_lookup_the_acquisition_lambda_relies_on(self):
        """performMemoryAcquisition selects its SSM document from
        PlatformName/PlatformDetails read out of this mapping. If the shape is
        lost the lookup returns {} and every instance is treated as generic
        Linux - which is how a Windows instance would be sent the LiME document.
        """
        windows = {
            "InstanceId": INSTANCE_B,
            "PlatformName": "Windows",
            "PlatformDetails": "Windows",
        }

        normalized = normalize_instance_info([windows])

        assert normalized[INSTANCE_B]["PlatformDetails"] == "Windows"
