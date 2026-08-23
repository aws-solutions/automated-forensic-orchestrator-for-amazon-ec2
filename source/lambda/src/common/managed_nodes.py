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

"""Is this instance registered with Systems Manager and reachable?

Seven places asked that question and each answered it from scratch.
``DescribeInstanceInformation`` returns **10** managed nodes by default, **50** at
most, and it paginates - so asking it unfiltered and reading a single response
answers "no" in any account holding more managed nodes than one page, about an
instance that is perfectly healthy.

Four of those seven were fixed to filter and paginate. Two were not:

* ``checkInstanceStatus`` reported a ready analysis instance as not associated
  with Systems Manager, so the investigation waited on an instance that was
  already waiting for it.
* ``runForensicsCommand`` concluded no SSM agent was present, sent **no disk
  investigation commands at all**, and returned HTTP 200 - so the investigation
  reported success having produced nothing, on a different host, possibly after
  the evidence was gone.

Fixing them one file at a time is how the fifth, sixth and seventh copies came to
disagree. ``tests/common/test_managed_node_and_subnet_lookup.py`` asserts no
handler calls the API directly any more.
"""

from typing import Any, Dict, Iterable, List, Optional, Set

from .log import get_logger

logger = get_logger(__name__)

ONLINE = "Online"

# The InstanceIds filter accepts at most this many values per request, so a
# finding naming more instances than this is asked for in batches. Reading only
# the first batch would reintroduce the very bug this module exists to remove.
MAX_FILTER_VALUES = 50


class NodeLookupError(Exception):
    """Systems Manager could not be asked whether these nodes are registered.

    Raised rather than returning "not registered", because the two are not the
    same thing and treating them as one is how a throttled API call became "this
    instance has no SSM agent" - and, downstream, an investigation that ran no
    commands and reported success.
    """


def _batches(items: List[str], size: int) -> Iterable[List[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def online_node_ids(ssm_client, instance_ids: Iterable[str]) -> Set[str]:
    """Which of ``instance_ids`` are registered with SSM and report Online.

    Filtered by instance id, paginated, and batched to the filter's value limit.
    PingStatus is checked because a registered node that is offline - including a
    terminated one, which lingers in the inventory - cannot run a command either.
    """
    wanted = [i for i in instance_ids or [] if i]
    if not wanted:
        return set()

    online: Set[str] = set()
    for batch in _batches(wanted, MAX_FILTER_VALUES):
        try:
            paginator = ssm_client.get_paginator(
                "describe_instance_information"
            )
            for page in paginator.paginate(
                Filters=[{"Key": "InstanceIds", "Values": batch}]
            ):
                for item in page.get("InstanceInformationList", []):
                    if (
                        item.get("InstanceId") in set(batch)
                        and item.get("PingStatus") == ONLINE
                    ):
                        online.add(item["InstanceId"])
        except Exception as lookup_error:
            raise NodeLookupError(
                "could not determine Systems Manager registration for "
                f"{', '.join(batch)}: {lookup_error}"
            )

    missing = set(wanted) - online
    if missing:
        logger.info(
            "not registered with Systems Manager or not Online: %s",
            ", ".join(sorted(missing)),
        )
    return online


def is_node_online(ssm_client, instance_id: str) -> bool:
    """Whether one instance is registered with SSM and reports Online."""
    return instance_id in online_node_ids(ssm_client, [instance_id])


def describe_node(ssm_client, instance_id: str) -> Optional[Dict[str, Any]]:
    """The Systems Manager inventory record for one instance, or None.

    Filtered and paginated for the same reasons as :func:`online_node_ids`, and
    used where the *contents* of the record are wanted rather than liveness -
    triage reads PlatformType, PlatformName and PlatformVersion from it, and
    those decide which document every later phase runs.
    """
    if not instance_id:
        return None
    try:
        paginator = ssm_client.get_paginator("describe_instance_information")
        for page in paginator.paginate(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ):
            for item in page.get("InstanceInformationList", []):
                if item.get("InstanceId") == instance_id:
                    return item
    except Exception as lookup_error:
        raise NodeLookupError(
            "could not read the Systems Manager record for "
            f"{instance_id}: {lookup_error}"
        )
    return None
