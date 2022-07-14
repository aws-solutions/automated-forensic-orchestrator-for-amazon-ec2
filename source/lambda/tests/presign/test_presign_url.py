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

import os
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3
import pytest

from ...src.common.awsapi_cached_client import AWSCachedClient

# from ..src.triage  import handler as function_under_test
# from ..src.triage.app import lambda_handler as function_under_test
from ...src.presign import app


@pytest.fixture()
def event():
    return {
        "arguments": {
            "input": {
                "id": "673852cb-9f85-4d49-b923-4f08baa6d9a7",
                "artifactId": "4b9e0af0-e3d1-463b-9b97-9a0476aaf12b",
            }
        },
        "identity": None,
        "source": None,
        "request": {
            "headers": {
                "x-forwarded-for": "1.2.3.4, 5.6.7.8",
                "accept-encoding": "gzip, deflate, br",
                "cloudfront-viewer-country": "NL",
                "cloudfront-is-tablet-viewer": "false",
                "referer": "https://eu-west-1.console.aws.amazon.com/appsync/home?region=eu-west-1",
                "via": "2.0 9fce949f3749407c8e6a75087e168b47.cloudfront.net (CloudFront)",
                "cloudfront-forwarded-proto": "https",
                "origin": "https://eu-west-1.console.aws.amazon.com",
                "x-api-key": "da1-c33ullkbkze3jg5hf5ddgcs4fq",
                "content-type": "application/json",
                "x-amzn-trace-id": "Root=1-606eb2f2-1babc433453a332c43fb4494",
                "x-amz-cf-id": "SJw16ZOPuMZMINx5Xcxa9pB84oMPSGCzNOfrbJLvd80sPa0waCXzYQ==",
                "content-length": "114",
                "x-amz-user-agent": "AWS-Console-AppSync/",
                "x-forwarded-proto": "https",
                "host": "ldcvmkdnd5az3lm3gnf5ixvcyy.appsync-api.eu-west-1.amazonaws.com",
                "accept-language": "en-US,en;q=0.5",
                "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0",
                "cloudfront-is-desktop-viewer": "true",
                "cloudfront-is-mobile-viewer": "false",
                "accept": "*/*",
                "x-forwarded-port": "443",
                "cloudfront-is-smarttv-viewer": "false",
            }
        },
        "prev": None,
        "info": {
            "parentTypeName": "Query",
            "selectionSetList": ["url", "id", "artifactId"],
            "selectionSetGraphQL": "{\n  url\n  id\n  artifactId\n}",
            "fieldName": "getArtifactDownloadUrl",
            "variables": {},
        },
        "stash": {},
    }


get_item = MagicMock()
get_item.return_value = {
    "Item": {
        "componentType": {"S": "Lambda"},
        "artifactSHA256": {
            "S": "OGU2NDc0MThlOTAxNTMxYTBmMDVkYzNmNzVhOTlhOTAyMjQ1NzM5NzgxYzViOGU5OTM1YzQwYWRiZjBkZDA3OSAgbGludXhfbWVtY2FwdHVyZS5saW1lCg=="
        },
        "artifactSize": {"N": "1043958848"},
        "creationTime": {"S": "2022-02-21T08:20:48.322863+00:00"},
        "status": {"S": "SUCCESS"},
        "lastUpdatedTime": {"S": "2022-02-21T08:20:48.322863+00:00"},
        "artifactLocation": {
            "S": "memory/i-0d02bff5f6d29258d/673852cb-9f85-4d49-b923-4f08baa6d9a7/linux_memcapture.lime"
        },
        "ssmDocumentName": {
            "S": "ForensicSolutionStack-ForensicSSMDBuilderStackSSMDocumentlinuxlimememoryacquisitionAF2BE0B7-0trqhNLt4XuA"
        },
        "ssmCommandId": {"S": "7a91b1da-10de-4bf6-8971-5581452dfb0b"},
        "category": {"S": "MEMORY"},
        "SK": {"S": "ARTIFACT#4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
        "componentId": {"S": "checkMemoryAcquisition"},
        "PK": {"S": "RECORD#673852cb-9f85-4d49-b923-4f08baa6d9a7"},
        "id": {"S": "4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
        "forensicId": {"S": "673852cb-9f85-4d49-b923-4f08baa6d9a7"},
        "type": {"S": "MEMORYDUMP"},
    }
}


generate_presigned_url = MagicMock()
generate_presigned_url.return_value = "https://artifactbucket/memory/i-0d02bff5f6d29258d/673852cb-9f85-4d49-b923-4f08baa6d9a7/linux_memcapture.lime"


def mock_connection():
    mockClient = Mock(boto3.client("dynamodb"))
    mockClient.get_caller_identity = MagicMock()
    mockClient._get_local_account_id = lambda: {}
    mockClient.get_item = get_item
    mockClient.generate_presigned_url = generate_presigned_url
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "AWS_ACCESS_KEY_ID": "foo",
        "AWS_SECRET_ACCESS_KEY": "bar",
        "INSTANCE_TABLE_NAME": "table",
        "ARTIFACT_BUCKET_NAME": "artifactbucket",
    },
)
def test_generate_presigned_url_for_valid_artifact(event):
    with patch.object(
        app, "create_aws_client", Mock(return_value=mock_connection())
    ):
        # context = MagicMock()
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = app.handler(event, {})
        assert (
            ret.get("url")
            == "https://artifactbucket/memory/i-0d02bff5f6d29258d/673852cb-9f85-4d49-b923-4f08baa6d9a7/linux_memcapture.lime"
        )

        # assert get_item.call_count(1)
        get_item.assert_called_once_with(
            TableName="table",
            Key={
                "PK": {"S": f"RECORD#673852cb-9f85-4d49-b923-4f08baa6d9a7"},
                "SK": {"S": f"ARTIFACT#4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
            },
        )


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "AWS_ACCESS_KEY_ID": "foo",
        "AWS_SECRET_ACCESS_KEY": "bar",
        "INSTANCE_TABLE_NAME": "table",
        "ARTIFACT_BUCKET_NAME": "artifactbucket",
    },
)
def test_generate_presigned_url_for_invalid_artifact(event):
    get_item.reset_mock()
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection()),
    ):
        get_item.return_value = {
            "Item": {
                "componentType": {"S": "Lambda"},
                "artifactSHA256": {
                    "S": "OGU2NDc0MThlOTAxNTMxYTBmMDVkYzNmNzVhOTlhOTAyMjQ1NzM5NzgxYzViOGU5OTM1YzQwYWRiZjBkZDA3OSAgbGludXhfbWVtY2FwdHVyZS5saW1lCg=="
                },
                "artifactSize": {"N": "1043958848"},
                "creationTime": {"S": "2022-02-21T08:20:48.322863+00:00"},
                "status": {"S": "SUCCESS"},
                "lastUpdatedTime": {"S": "2022-02-21T08:20:48.322863+00:00"},
                "ssmDocumentName": {
                    "S": "ForensicSolutionStack-ForensicSSMDBuilderStackSSMDocumentlinuxlimememoryacquisitionAF2BE0B7-0trqhNLt4XuA"
                },
                "ssmCommandId": {"S": "7a91b1da-10de-4bf6-8971-5581452dfb0b"},
                "category": {"S": "MEMORY"},
                "SK": {"S": "ARTIFACT#4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
                "componentId": {"S": "checkMemoryAcquisition"},
                "PK": {"S": "RECORD#673852cb-9f85-4d49-b923-4f08baa6d9a7"},
                "id": {"S": "4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
                "forensicId": {"S": "673852cb-9f85-4d49-b923-4f08baa6d9a7"},
                "type": {"S": "MEMORYDUMP"},
            }
        }

        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        with pytest.raises(app.ArtifactNotFoundError) as excinfo:
            app.handler(event, {})

        assert excinfo.type == app.ArtifactNotFoundError

        # assert get_item.call_count(1)
        get_item.assert_called_once_with(
            TableName="table",
            Key={
                "PK": {"S": f"RECORD#673852cb-9f85-4d49-b923-4f08baa6d9a7"},
                "SK": {"S": f"ARTIFACT#4b9e0af0-e3d1-463b-9b97-9a0476aaf12b"},
            },
        )
