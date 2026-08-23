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

"""Two lookups that were each written from scratch in several handlers.

**Managed node registration.** ``DescribeInstanceInformation`` returns 10 nodes
by default and 50 at most, and it paginates. Asking it unfiltered and reading one
response therefore answers "is this instance registered with Systems Manager?"
with *no* in any account holding more managed nodes than one page - about a
freshly launched instance that is perfectly healthy. Four handlers were fixed to
filter and paginate; two were not, and one of those returns HTTP 200 having sent
no commands at all when it gets the wrong answer.

**The forensic subnet.** Three handlers find the subnet to launch into by
filtering on the ``aws-cdk:subnet-name`` tag and then indexing ``[0]``. When the
solution creates its own VPC that tag is always present. When it is pointed at an
existing VPC - a documented deployment mode, ``isExistingVPC`` with
``Vpc.fromLookup`` - the customer's subnets carry no such tag, the filter matches
nothing, and all three raise ``IndexError: list index out of range``.

Both are one lookup expressed once here, and the handlers are asserted not to
re-implement either.
"""

import re
from pathlib import Path

import pytest
from unittest.mock import MagicMock

from ...src.common.managed_nodes import (
    ONLINE,
    NodeLookupError,
    online_node_ids,
)
from ...src.common.vpc_lookup import SubnetNotFound, forensic_subnet_id

SRC = Path(__file__).resolve().parents[2] / "src"


def node(instance_id, ping=ONLINE):
    return {"InstanceId": instance_id, "PingStatus": ping}


def ssm_client(pages, expect_filter=True):
    """An SSM client whose paginator yields `pages` of InstanceInformationList."""
    client = MagicMock()
    seen = {}

    def get_paginator(operation_name):
        assert operation_name == "describe_instance_information"
        paginator = MagicMock()

        def paginate(**kwargs):
            seen.update(kwargs)
            return [{"InstanceInformationList": page} for page in pages]

        paginator.paginate.side_effect = paginate
        return paginator

    client.get_paginator = get_paginator
    client._seen = seen
    return client


class TestManagedNodeLookup:
    def test_finds_a_node_on_a_later_page(self):
        """The defect: only the first page was ever read."""
        wanted = "i-0deadbeefdeadbeef"
        pages = [[node(f"i-{n:016x}") for n in range(50)], [node(wanted)]]
        assert online_node_ids(ssm_client(pages), [wanted]) == {wanted}

    def test_filters_by_instance_id(self):
        """Unfiltered, the answer depends on how many nodes the account has."""
        wanted = "i-0aaaaaaaaaaaaaaaa"
        client = ssm_client([[node(wanted)]])
        online_node_ids(client, [wanted])
        assert "Filters" in client._seen, (
            "the lookup must filter by InstanceIds; an unfiltered call returns "
            "whichever 10 nodes the account happens to list first"
        )
        assert client._seen["Filters"] == [
            {"Key": "InstanceIds", "Values": [wanted]}
        ]

    def test_an_offline_node_is_not_online(self):
        offline = "i-0bbbbbbbbbbbbbbbb"
        assert (
            online_node_ids(
                ssm_client([[node(offline, ping="ConnectionLost")]]), [offline]
            )
            == set()
        )

    def test_an_absent_node_is_not_online(self):
        assert online_node_ids(ssm_client([[]]), ["i-0cccccccccccccccc"]) == set()

    def test_an_empty_page_carrying_a_token_is_still_paginated(self):
        # A permitted response: an empty page followed by a page with results.
        wanted = "i-0dddddddddddddddd"
        assert online_node_ids(ssm_client([[], [node(wanted)]]), [wanted]) == {
            wanted
        }

    def test_batches_within_the_filter_value_limit(self):
        """A Values list is capped, so a big finding must be asked in batches."""
        ids = [f"i-{n:016x}" for n in range(120)]
        client = MagicMock()
        asked = []

        def get_paginator(operation_name):
            paginator = MagicMock()

            def paginate(**kwargs):
                values = kwargs["Filters"][0]["Values"]
                asked.append(len(values))
                return [
                    {"InstanceInformationList": [node(i) for i in values]}
                ]

            paginator.paginate.side_effect = paginate
            return paginator

        client.get_paginator = get_paginator
        assert online_node_ids(client, ids) == set(ids)
        assert asked, "no request was made"
        assert max(asked) <= 50, (
            f"asked for {max(asked)} instance ids in one filter; the documented "
            "maximum for this filter is 50"
        )

    def test_no_instance_ids_asks_nothing(self):
        client = MagicMock()
        client.get_paginator = MagicMock(
            side_effect=AssertionError("must not call SSM for an empty list")
        )
        assert online_node_ids(client, []) == set()

    def test_a_client_failure_is_not_reported_as_not_registered(self):
        """Silently returning "not online" for an API error is how a healthy
        instance gets reported as having no SSM agent."""
        client = MagicMock()

        def get_paginator(operation_name):
            paginator = MagicMock()
            paginator.paginate.side_effect = RuntimeError("throttled")
            return paginator

        client.get_paginator = get_paginator
        with pytest.raises(NodeLookupError):
            online_node_ids(client, ["i-0eeeeeeeeeeeeeeee"])


class TestNoHandlerAsksSsmDirectly:
    HANDLERS = [
        "investigation/checkInstanceStatus.py",
        "investigation/runForensicsCommand.py",
        "investigation/runMemoryAnalysis.py",
        "acquisition/performMemoryAcquisition.py",
        "kernelloader/kernelSymbolLoader.py",
        "loadforensictools/loadForensicTools.py",
        "triage/app.py",
    ]

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_uses_the_shared_lookup(self, handler):
        code = executable_lines(SRC / handler)
        # The API being *called*, not merely named: several of these files
        # explain in a docstring why the unfiltered form was wrong, and that
        # explanation is the reason the fix has stuck where it has.
        called = re.search(
            r"(get_paginator\(\s*[\"']describe_instance_information"
            r"|\.describe_instance_information\s*\()",
            code,
        )
        assert not called, (
            f"{handler} calls DescribeInstanceInformation itself. Four handlers "
            "were fixed to filter and paginate and two were not, which is what "
            "having seven copies of this lookup produced."
        )


class TestForensicSubnetLookup:
    def ec2(self, subnets):
        client = MagicMock()
        client.describe_subnets = MagicMock(
            return_value={"Subnets": subnets}
        )
        return client

    def test_returns_the_subnet_id(self):
        client = self.ec2([{"SubnetId": "subnet-0abc"}])
        assert forensic_subnet_id(client, "vpc-0123", "service") == "subnet-0abc"

    def test_filters_on_the_tag_and_the_vpc(self):
        client = self.ec2([{"SubnetId": "subnet-0abc"}])
        forensic_subnet_id(client, "vpc-0123", "service")
        filters = client.describe_subnets.call_args.kwargs["Filters"]
        assert {"Name": "vpc-id", "Values": ["vpc-0123"]} in filters
        assert any(
            f["Name"] == "tag:aws-cdk:subnet-name" and f["Values"] == ["service"]
            for f in filters
        )

    def test_no_matching_subnet_says_so_instead_of_IndexError(self):
        # The defect: `["Subnets"][0]` on an empty list. In the existing-VPC
        # deployment mode the customer's subnets carry no aws-cdk:subnet-name
        # tag, so this is the normal case there, and every affected workflow
        # failed with "list index out of range".
        client = self.ec2([])
        with pytest.raises(SubnetNotFound) as caught:
            forensic_subnet_id(client, "vpc-0123", "service")
        message = str(caught.value)
        assert "vpc-0123" in message
        assert "service" in message
        assert "aws-cdk:subnet-name" in message

    def test_is_deterministic_when_several_subnets_match(self):
        # One subnet per availability zone matches. Picking whichever the API
        # happened to list first made the launch AZ vary between runs, which
        # matters because a snapshot restore has to be in the volume's AZ.
        client = self.ec2(
            [
                {"SubnetId": "subnet-0ccc", "AvailabilityZone": "us-east-1c"},
                {"SubnetId": "subnet-0aaa", "AvailabilityZone": "us-east-1a"},
            ]
        )
        first = forensic_subnet_id(client, "vpc-0123", "service")
        client2 = self.ec2(
            [
                {"SubnetId": "subnet-0aaa", "AvailabilityZone": "us-east-1a"},
                {"SubnetId": "subnet-0ccc", "AvailabilityZone": "us-east-1c"},
            ]
        )
        assert first == forensic_subnet_id(client2, "vpc-0123", "service")


class TestNoHandlerResolvesSubnetsItself:
    HANDLERS = [
        "investigation/createForensicInstance.py",
        "loadforensictools/loadForensicTools.py",
        "kernelloader/kernelSymbolLoader.py",
    ]

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_uses_the_shared_lookup(self, handler):
        code = executable_lines(SRC / handler)
        assert not re.search(r'\["Subnets"\]\[0\]', code), (
            f"{handler} still indexes Subnets[0]; an empty list is the normal "
            "case when the solution is pointed at an existing VPC"
        )
        assert "forensic_subnet_id" in code


def executable_lines(path: Path) -> str:
    """Source with comment-only lines removed.

    The handlers quote the old expressions in comments to explain why they were
    replaced, and that explanation is worth keeping.
    """
    return "\n".join(
        line
        for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )
