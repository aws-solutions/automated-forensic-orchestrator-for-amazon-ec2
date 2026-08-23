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

"""Reading a forensic record spans more than one DynamoDB page.

A Query returns at most 1 MB of items and sets LastEvaluatedKey. That limit is
reachable here for a specific reason: several timeline events store an entire AWS
API response as their event data, tens of kilobytes each.

What made the truncation a hard failure rather than a lost tail is the sort order.
All of a record's items share one PK and come back sorted by SK, and the sort keys
are ``ARTIFACT#``, ``EVENT#`` and ``RECORD#``. ``RECORD#`` sorts last, so the
metadata item - the one the reader looks for to decide the record exists - is the
*first* thing to fall off the page. A case with a rich timeline therefore raised
``DoesNotExistException`` ("does not exist or has been deleted") about a live
forensic record, which is the worst possible thing to tell an investigator.
"""

from unittest.mock import MagicMock

import pytest

from ...src.data.base import ForensicDynamoDBService


def item(sk, **attrs):
    packed = {"PK": {"S": "RECORD#abc"}, "SK": {"S": sk}}
    packed.update({k: {"S": v} for k, v in attrs.items()})
    return packed


class PagedClient:
    """A DynamoDB client that only ever returns one page at a time."""

    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def query(self, **kwargs):
        self.requests.append(kwargs)
        index = 0
        if "ExclusiveStartKey" in kwargs:
            index = kwargs["ExclusiveStartKey"]["page"]
        page = self.pages[index]
        response = {"Items": page}
        if index + 1 < len(self.pages):
            response["LastEvaluatedKey"] = {"page": index + 1}
        return response


def service(client):
    # The real constructor, so the deserialiser is the one production uses.
    return ForensicDynamoDBService(ddb_client=client, ddb_table_name="table")


def test_items_from_every_page_are_returned():
    # SK ascending, as DynamoDB returns them: artifacts, then events, then the
    # RECORD# metadata item last.
    pages = [
        [item("ARTIFACT#1"), item("ARTIFACT#2")],
        [item("EVENT#1"), item("EVENT#2")],
        [item("RECORD#abc#METADATA", forensicId="abc")],
    ]
    client = PagedClient(pages)

    result = service(client)._query("RECORD#", "abc")

    assert len(result) == 5, (
        "only the first page was read; a record's artifacts, timeline and "
        "metadata do not fit in one 1 MB page"
    )
    assert len(client.requests) == 3
    # Every request after the first has to carry the continuation token.
    assert "ExclusiveStartKey" not in client.requests[0]
    assert client.requests[1]["ExclusiveStartKey"] == {"page": 1}


def test_a_live_record_is_not_reported_as_deleted():
    """The failure this fixes, stated as its symptom."""
    pages = [
        [item(f"EVENT#{n}") for n in range(40)],
        [item("RECORD#abc#METADATA", forensicId="abc")],
    ]
    # No exception: the metadata item is on page two, and it is found.
    result = service(PagedClient(pages))._query("RECORD#", "abc")
    assert any(i["SK"].startswith("RECORD#") for i in result)


def test_a_genuinely_absent_record_still_raises():
    """The check must still work - this is not a licence to accept anything."""
    from ...src.data.base import DoesNotExistException

    pages = [[item("EVENT#1")], [item("EVENT#2")]]
    with pytest.raises(DoesNotExistException):
        service(PagedClient(pages))._query("RECORD#", "abc")


def test_the_key_condition_is_unchanged_across_pages():
    pages = [[item("EVENT#1")], [item("RECORD#abc#METADATA")]]
    client = PagedClient(pages)
    service(client)._query("RECORD#", "abc")
    for request in client.requests:
        assert request["KeyConditionExpression"] == "PK = :PK"
        assert request["ExpressionAttributeValues"] == {
            ":PK": {"S": "RECORD#abc"}
        }
        assert request["TableName"] == "table"
