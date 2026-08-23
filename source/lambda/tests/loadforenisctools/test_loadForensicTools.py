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
import time
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3
import pytest
from botocore import exceptions as boto_exceptions
from botocore.exceptions import ClientError, WaiterError

from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.customaction import createCustomAction
from ...src.loadforensictools import loadForensicTools

event = {}
tokens = {}
ssmResponse = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing load forensic tools Flow Started ")
    global event
    event = {
        "RequestType": "Create",
        "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
        "ResponseURL": "https://cloudformation-custom-resource-response-apsoutheast2.s3-ap-southeast-2.amazonaws.com/arn%3Aaws%3Acloudformation%3Aap-southeast-2%3A123456789012%3Astack/ForensicSolutionStack",
        "StackId": "arn:aws:cloudformation:ap-southeast-2:123456789012:stack/ForensicSolutionStack/8dfc7990-5942-11ec-93ec-0613a5a5f95a",
        "RequestId": "6715ccf3-ce9a-4eff-b32d-586c71ca8fda",
        "LogicalResourceId": "securityHubCustomActionCustomAction6FF54E59",
        "ResourceType": "Custom::ActionTarget",
        "ResourceProperties": {
            "ServiceToken": "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-securityHubCustomActioninsta-QM3kDlrE4Nzf",
            "Description": "Trigger Forensic Triage Action",
            "Id": "ForensicTriageAction",
            "Name": "Forensic Triage ",
        },
    }
    global tokens
    tokens = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEM3//////////SAMPLE",
            "Expiration": "datetime.datetime(2021, 11, 26, 4, 34, 20, tzinfo=tzlocal())",
        }
    }
    global ssmResponse
    # DescribeInstanceInformation returns at most one entry per instance id, so
    # the unrelated Ubuntu node carries its own: it is here to prove the builder
    # is picked out of a crowd, not to be mistaken for the builder.
    ssmResponse = {
        "InstanceInformationList": [
            {
                "InstanceId": "i-0aaaaaaaaaaaaaaaa",
                "PingStatus": "Online",
                "LastPingDateTime": "Fri, 26 Nov 2021 20:33:48 GMT",
                "AgentVersion": "3.0.1124.0",
                "IsLatestVersion": False,
                "PlatformType": "Linux",
                "PlatformName": "Ubuntu",
                "PlatformVersion": "20.04",
                "ResourceType": "EC2Instance",
                "IPAddress": "10.1.3.102",
                "ComputerName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
            },
            {
                "InstanceId": "i-0bf2bf6b175654c6e",
                "PingStatus": "Online",
                "LastPingDateTime": "Fri, 26 Nov 2021 20:33:48 GMT",
                "AgentVersion": "3.0.1124.0",
                "IsLatestVersion": False,
                "PlatformType": "Linux",
                "PlatformName": "Amazon Linux",
                "PlatformVersion": "2",
                "ResourceType": "EC2Instance",
                "IPAddress": "10.1.3.238",
                "ComputerName": "ip-10-1-3-238.ap-southeast-2.compute.internal",
            },
        ],
        "ResponseMetadata": {
            "RequestId": "527f7371-131a-4069-bda1-a4e1d5efaa82",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "server": "Server",
                "date": "Fri, 26 Nov 2021 20:33:48 GMT",
                "content-type": "application/x-amz-json-1.1",
                "content-length": "705",
                "connection": "keep-alive",
                "x-amzn-requestid": "527f7371-131a-4069-bda1-a4e1d5efaa82",
            },
            "RetryAttempts": 0,
        },
    }

    # yield
    # print ('Testing Memory Acquisition Flow Completed')
    def teardown():
        print("Testing Forensic Tools Flow Completed")

    request.addfinalizer(teardown)


assume_role_fn = MagicMock(return_value={})
describe_instance_information_fn = MagicMock()
describe_instances_fn = MagicMock()
send_command_fn = MagicMock()
modify_document_permission_fn = MagicMock()
describe_subnets_fn = MagicMock()
run_instances_fn = MagicMock()
terminate_instances_fn = MagicMock()
instance_waiter_fn = MagicMock()
command_waiter_fn = MagicMock()
s3_client_fn = MagicMock()
boto3_module_fn = MagicMock()

BUILDER_INSTANCE_ID = "i-0bf2bf6b175654c6e"
SSM_COMMAND_ID = "73f4f7bb-53a7-4397-8085-c5b6baa8a126"
# The symbol table the builder seeds. volatility3/symbols/ is owned by the
# kernel symbol state machine, which appends to it for the life of the
# deployment, so the loader deliberately does not verify that prefix.
SEEDED_SYMBOL_KEY = (
    "volatility3/symbols/Linux-4.14.336-257.566.amzn2.x86_64.json"
)
# A builder-owned artifact, used by the tests below as the thing that gets
# poisoned. Both consumers read it back with a plain "aws s3 cp".
POISONED_PREFIX = "tools/volatility3/"
POISONABLE_KEY = "tools/volatility3/volatility3.zip"
LIME_KEY = "tools/LiME/LiME.zip"
CLIENT_TOKEN = "forensic-tools-6715ccf3-ce9a-4eff-b32d-586c71ca8fda"

# What the evidence bucket looks like after a build that actually worked.
USABLE_TOOL_ARTIFACTS = {
    "tools/LiME/": [
        {"Key": LIME_KEY, "Size": 204800},
        {
            "Key": "tools/LiME/lime-4.14.336-257.566.amzn2.x86_64.ko",
            "Size": 71680,
        },
    ],
    "tools/volatility3/": [
        {"Key": "tools/volatility3/volatility3.zip", "Size": 1048576},
    ],
    "volatility3/symbols/": [{"Key": SEEDED_SYMBOL_KEY, "Size": 33554432}],
}


def get_waiter_fn(waiter_name):
    if waiter_name == "command_executed":
        return command_waiter_fn
    return instance_waiter_fn


def get_paginator_fn(operation_name):
    """Paginator seam for the two paginated EC2/SSM calls the loader makes."""
    paginator = MagicMock()
    if operation_name == "describe_instance_information":
        paginator.paginate.side_effect = lambda **kwargs: [
            describe_instance_information_fn(**kwargs)
        ]
    elif operation_name == "describe_instances":
        paginator.paginate.side_effect = lambda **kwargs: [
            describe_instances_fn(**kwargs)
        ]
    else:
        raise AssertionError("unexpected paginator " + operation_name)
    return paginator


def setup_positive_mocks():

    describe_instance_information_fn.reset_mock(side_effect=True)
    describe_instance_information_fn.return_value = ssmResponse
    describe_instances_fn.reset_mock(side_effect=True)
    describe_instances_fn.return_value = {"Reservations": []}
    describe_subnets_fn.return_value = {
        "Subnets": [{"SubnetId": "sub-1234567890"}]
    }
    run_instances_fn.reset_mock(side_effect=True)
    run_instances_fn.return_value = {
        "Instances": [{"InstanceId": BUILDER_INSTANCE_ID}]
    }
    terminate_instances_fn.reset_mock(side_effect=True)
    instance_waiter_fn.reset_mock(side_effect=True)
    command_waiter_fn.reset_mock(side_effect=True)
    send_command_fn.reset_mock()
    send_command_fn.return_value = {"Command": {"CommandId": SSM_COMMAND_ID}}
    setup_artifact_listing(USABLE_TOOL_ARTIFACTS)


def setup_artifact_listing(objects_by_prefix, versions_by_key=None):
    """Fake the paginated S3 calls the artifact check runs.

    versions_by_key is what ListObjectVersions reports for a given key, which is
    how a zero byte current version sitting on top of a usable earlier version
    is expressed.
    """
    versions = versions_by_key or {}

    def list_objects_v2(Bucket, Prefix):
        return [{"Contents": objects_by_prefix.get(Prefix, [])}]

    def list_object_versions(Bucket, Prefix):
        return [{"Versions": versions.get(Prefix, [])}]

    def get_paginator(operation_name):
        paginator = MagicMock()
        if operation_name == "list_objects_v2":
            paginator.paginate.side_effect = list_objects_v2
        elif operation_name == "list_object_versions":
            paginator.paginate.side_effect = list_object_versions
        else:
            raise AssertionError("unexpected S3 paginator " + operation_name)
        return paginator

    s3_client_fn.reset_mock(return_value=True, side_effect=True)
    s3_client_fn.get_paginator.side_effect = get_paginator
    boto3_module_fn.client.return_value = s3_client_fn


def build_context(partition="aws"):
    context = MagicMock()
    context.invoked_function_arn = (
        f"arn:{partition}:lambda:ap-southeast-2:123456789012:function:"
        "ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
    )
    context.get_remaining_time_in_millis.return_value = 900000
    return context


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.put_item = MagicMock()
    mockClient.assume_role = assume_role_fn
    mockClient.describe_instance_information = describe_instance_information_fn
    mockClient.send_command = send_command_fn
    mockClient.modify_document_permission = modify_document_permission_fn
    mockClient.run_instances = run_instances_fn
    mockClient.describe_subnets = describe_subnets_fn
    mockClient.terminate_instances = terminate_instances_fn
    mockClient.get_waiter = get_waiter_fn
    mockClient.get_paginator = get_paginator_fn
    return mockClient


def mock_connection_sts():
    mockClient = Mock(boto3.client("sts"))
    mockClient.assume_role = tokens
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
        "WINDOWS_LIME_MEMORY_ACQUISITION": "documentName",
        "LINUX_LIME_MEMORY_ACQUISITION": "documentName",
        "AMAZON_LINUX_2_VOLATILITY_PROFILE": "documentName",
        "AMAZON_LINUX_2_LIME_VOLATILITY_LOADER": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
        "AMI_ID": "ami-1234567890",
        "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
    },
)
def test_happy_path_flow_trigger_event():
    assume_role_fn.return_value = tokens

    describe_instance_information_fn.return_value = ssmResponse
    setup_positive_mocks()
    send_command_fn.return_value = {
        "Command": {
            "CommandId": "73f4f7bb-53a7-4397-8085-c5b6baa8a126",
            "DocumentName": "lime-memory-acquisition",
            "DocumentVersion": "$DEFAULT",
            "Comment": "Memory Acquisition for i-0bf2bf6b175654c6e",
            "ExpiresAfter": "datetime.datetime(2021, 11, 27, 0, 13, 10, 794000, tzinfo=tzlocal())",
            "Parameters": {
                "AccessKeyId": ["AKIAIOSFODNN7EXAMPLE"],
                "Region": ["ap-southeast-2"],
                "SecretAccessKey": [
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                ],
                "SessionToken": ["FwoGZXIvYXdzEM3//////////SAMPLE"],
                "s3bucket": ["forensicsolutionstack-forensicbucket"],
                "s3commands": [
                    "aws s3 cp . s3://forensicsolutionstack-forensicbucket/memory/i-0bf2bf6b175654c6e/c5eddc90-9f06-4517-a684-a68f3744f97e --recursive"
                ],
                "ExecutionTimeout": ["1800"],
            },
            "InstanceIds": ["i-0bf2bf6b175654c6e"],
            "Targets": [],
            "RequestedDateTime": "datetime.datetime(2021, 11, 26, 23, 12, 10, 794000, tzinfo=tzlocal())",
            "Status": "Pending",
            "StatusDetails": "Pending",
            "OutputS3Region": "ap-southeast-2",
            "OutputS3BucketName": "",
            "OutputS3KeyPrefix": "",
            "MaxConcurrency": "50",
            "MaxErrors": "0",
            "TargetCount": 1,
            "CompletedCount": 0,
            "ErrorCount": 0,
            "DeliveryTimedOutCount": 0,
            "ServiceRole": "",
            "NotificationConfig": {
                "NotificationArn": "",
                "NotificationEvents": [],
                "NotificationType": "",
            },
            "CloudWatchOutputConfig": {
                "CloudWatchLogGroupName": "",
                "CloudWatchOutputEnabled": False,
            },
            "TimeoutSeconds": 3600,
        },
        "ResponseMetadata": {
            "RequestId": "9d1696b6-80d6-4df8-aad5-a2367caf4689",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "server": "Server",
                "date": "Fri, 26 Nov 2021 23:12:10 GMT",
                "content-type": "application/x-amz-json-1.1",
                "content-length": "1599",
                "connection": "keep-alive",
                "x-amzn-requestid": "9d1696b6-80d6-4df8-aad5-a2367caf4689",
            },
            "RetryAttempts": 0,
        },
    }

    with patch.object(
        loadForensicTools,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), patch.object(loadForensicTools, "boto3", boto3_module_fn, create=True):
        ret = loadForensicTools.handler(event, build_context())
        assert ret.get("statusCode") == 200


TOOLS_ENVIRONMENT = {
    "AWS_REGION": "ap-southeast-2",
    "S3_BUCKET_NAME": "BUCKET_FORENSICS",
    "S3_COPY_ROLE": "arn:s3copRole",
    "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
    "AMAZON_LINUX_2_VOLATILITY_PROFILE": "documentName",
    "AMAZON_LINUX_2_LIME_VOLATILITY_LOADER": "documentName",
    "SSM_EXECUTION_TIMEOUT": "1800",
    "VPC_ID": "vpc-1234567890",
    "AMI_ID": "ami-1234567890",
    "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
}

# The exact failure observed in a live deployment: the command_executed waiter
# ran out of attempts while the LiME/dwarf2json build was still running. The
# last GetCommandInvocation response is what botocore attaches, and its Status
# is still an in flight one, so nothing is known to have gone wrong.
WAITER_BUDGET_EXHAUSTED = WaiterError(
    name="CommandExecuted",
    reason="Max attempts exceeded",
    last_response={"Status": "InProgress"},
)

# The command itself reached a terminal failure status. This is direct
# evidence the build was bad.
WAITER_COMMAND_FAILED = WaiterError(
    name="CommandExecuted",
    reason=(
        "Waiter encountered a terminal failure state: For expression "
        '"Status" we matched expected path: "Failed"'
    ),
    last_response={"Status": "Failed", "StatusDetails": "Failed"},
)

# InvocationDoesNotExist is a retry acceptor, so a command that never reaches
# the instance exhausts the attempts with an error response carrying no Status.
WAITER_INVOCATION_MISSING = WaiterError(
    name="CommandExecuted",
    reason="Max attempts exceeded",
    last_response={"Error": {"Code": "InvocationDoesNotExist"}},
)


def run_handler(cfn_status_fn, context=None, create_aws_client=None):
    # create=True keeps the boto3 seam patchable against a build of this
    # module that has no S3 verification yet, so the regression tests below
    # fail on their assertion rather than on a missing patch target.
    #
    # sleep is stubbed because the SSM registration poll is deliberately spaced
    # out in seconds; no test needs to spend that.
    if create_aws_client is None:
        create_aws_client = Mock(return_value=mock_connection({}))
    with patch.object(
        loadForensicTools, "create_aws_client", create_aws_client
    ), patch.object(
        loadForensicTools, "boto3", boto3_module_fn, create=True
    ), patch.object(
        loadForensicTools, "send_status_to_cfn", cfn_status_fn
    ), patch.object(
        time, "sleep", MagicMock()
    ):
        return loadForensicTools.handler(event, context or build_context())


def cfn_status_of(cfn_status_fn):
    return cfn_status_fn.call_args.args[2]


def cfn_reason_of(cfn_status_fn):
    return cfn_status_fn.call_args.kwargs.get("reason", "")


def cfn_data_of(cfn_status_fn):
    return cfn_status_fn.call_args.args[3]


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_terminal_command_failure_reports_failed_to_cloudformation():
    """A build that failed used to be reported to CloudFormation as SUCCESS
    from the except block, so the stack reached CREATE_COMPLETE with no
    forensic tools in the evidence bucket."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_COMMAND_FAILED
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    assert SSM_COMMAND_ID in reason
    assert BUILDER_INSTANCE_ID in reason
    assert "last status Failed" in reason


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_budget_exhaustion_warns_but_does_not_fail_the_resource():
    """Running out of Lambda budget is not evidence the build was bad, and
    900s is the Lambda ceiling so it cannot be tuned away. The builder is
    terminated straight afterwards, so the bucket - checked separately - is
    the ground truth, not the waiter."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_BUDGET_EXHAUSTED
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    incomplete = cfn_data_of(cfn_status_fn)["ToolBuildIncomplete"]
    assert SSM_COMMAND_ID in incomplete
    assert "last status InProgress" in incomplete
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    # The builder still has to go, budget or no budget.
    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_budget_exhaustion_still_fails_when_it_poisoned_an_artifact():
    """The safety property that makes warning on budget exhaustion sound: the
    one outcome that must never pass silently is caught by the artifact check,
    not by the waiter."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_BUDGET_EXHAUSTED
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(poisoned)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_called_once_with(
        Bucket="BUCKET_FORENSICS", Key=POISONABLE_KEY
    )
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert POISONABLE_KEY in cfn_reason_of(cfn_status_fn)


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_unresolvable_command_invocation_is_treated_as_a_failure():
    """No Status at all means the invocation never resolved on the instance,
    which is a real failure rather than a build we merely stopped watching."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_INVOCATION_MISSING
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert "last status Unknown" in cfn_reason_of(cfn_status_fn)


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_builder_is_sized_like_the_sibling_symbol_builder():
    """kernelSymbolLoader runs the same dwarf2json over kernel debuginfo work
    on t3.large. t3.small gave this 2 GiB and a 20% CPU credit baseline, which
    is why the build never finished; with the Lambda ceiling fixed at 900s the
    only remaining lever is build speed."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    run_instances_fn.reset_mock()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    assert run_instances_fn.call_args.kwargs["InstanceType"] == "t3.large"


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_zero_byte_symbol_artifact_is_removed_and_fails_the_resource():
    """dwarf2json redirects into the symbol file before it fails, and the
    document exits 0, so the SSM command succeeds while the evidence bucket
    receives an empty symbol table. Presence is not proof of a usable build."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(poisoned)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_called_once_with(
        Bucket="BUCKET_FORENSICS", Key=POISONABLE_KEY
    )
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert POISONABLE_KEY in cfn_reason_of(cfn_status_fn)


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_absent_artifact_warns_but_does_not_fail_the_resource():
    """An absent artifact is not a poisoned one. Both consumers fall back on
    their own, and the symbol table that matters is the per kernel release one
    built on demand, so a cache that was never warmed must not turn an upgrade
    into UPDATE_FAILED - which would hit every existing deployment, since this
    build has been failing since 2022."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    setup_artifact_listing({})
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_not_called()
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    warnings = cfn_data_of(cfn_status_fn)["ToolArtifactWarnings"]
    assert "tools/LiME/" in warnings
    assert "tools/volatility3/" in warnings
    # volatility3/symbols/ is not warned about because it is not verified: the
    # kernel symbol state machine owns that prefix. See TOOL_ARTIFACT_PREFIXES.
    assert "volatility3/symbols/" not in warnings


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_stale_zero_byte_symbol_table_does_not_fail_the_resource():
    """volatility3/symbols/ accumulates one symbol table per kernel release for
    the life of the deployment, written by the kernel symbol state machine and
    not by this builder. Verifying it here meant one historical failed on-demand
    symbol build turned the next version bump - which BuildVersion now delivers
    as an Update - into UPDATE_FAILED, delete-markering an object in the evidence
    bucket on the way."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    listing = dict(USABLE_TOOL_ARTIFACTS)
    listing["volatility3/symbols/"] = [
        {"Key": SEEDED_SYMBOL_KEY, "Size": 33554432},
        {"Key": "volatility3/symbols/Linux-6.1.0-stale.json", "Size": 0},
    ]
    setup_artifact_listing(listing)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    # and nothing in the evidence bucket was touched
    s3_client_fn.delete_object.assert_not_called()


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_zero_byte_artifact_fails_even_when_its_prefix_is_otherwise_empty():
    """The two outcomes have to stay separable: the same empty prefix that is
    only a warning on its own must still fail once it holds a poisoned
    object."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    setup_artifact_listing(
        {POISONED_PREFIX: [{"Key": POISONABLE_KEY, "Size": 0}]}
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_called_once_with(
        Bucket="BUCKET_FORENSICS", Key=POISONABLE_KEY
    )
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    # The zero byte object is the failure; the empty prefixes stay warnings.
    reason = cfn_reason_of(cfn_status_fn)
    assert "removed unusable zero byte artifact" in reason
    assert "no artifact pre-seeded" not in reason
    assert "tools/LiME/" in cfn_data_of(cfn_status_fn)["ToolArtifactWarnings"]


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_builder_instance_is_terminated_on_the_success_path():
    """The builder used to be left running after every deployment."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_builder_instance_is_terminated_when_the_build_fails():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_COMMAND_FAILED
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_builder_instance_is_terminated_when_ssm_never_registers():
    """The instance id only exists after run_instances, and the SSM check
    raises straight afterwards, so the cleanup has to survive an exception
    thrown part way through."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    describe_instance_information_fn.return_value = {
        "InstanceInformationList": []
    }
    cfn_status_fn = MagicMock()

    try:
        ret = run_handler(cfn_status_fn)
    finally:
        describe_instance_information_fn.return_value = ssmResponse

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert "SSM Not installed" in cfn_reason_of(cfn_status_fn)


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_termination_failure_does_not_mask_the_build_error():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_COMMAND_FAILED
    terminate_instances_fn.side_effect = ClientError(
        {
            "Error": {
                "Code": "UnauthorizedOperation",
                "Message": "not authorized to perform TerminateInstances",
            }
        },
        "TerminateInstances",
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    reason = cfn_reason_of(cfn_status_fn)
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert "last status Failed" in reason
    assert "UnauthorizedOperation" not in reason
    assert "UnauthorizedOperation" in (
        cfn_data_of(cfn_status_fn)["BuilderInstanceTerminationError"]
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_builder_never_receives_delete_permission_on_the_bucket():
    """The SSM document parameters are plain text in the command history, so
    the credentials handed to the builder must stay write only. The artifact
    clean up assumes the copy role a second time for its own session policy."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    assume_role_fn.reset_mock()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    policies = [
        call.kwargs["Policy"] for call in assume_role_fn.call_args_list
    ]
    assert len(policies) == 2
    assert "s3:DeleteObject" not in policies[0]
    assert "s3:DeleteObject" in policies[1]
    assert "s3:PutObject" not in policies[1]
    sent_params = send_command_fn.call_args.kwargs["Parameters"]
    assert sent_params["s3bucket"] == ["BUCKET_FORENSICS"]


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_command_waiter_budget_comes_from_the_lambda_timeout():
    """The botocore default gives up after 100 seconds, long before a LiME or
    dwarf2json build finishes."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    waiter_config = command_waiter_fn.wait.call_args.kwargs["WaiterConfig"]
    delay = waiter_config["Delay"]
    assert delay * waiter_config["MaxAttempts"] > 100
    assert delay * waiter_config["MaxAttempts"] <= 900 - 120


# Every builder document name is distinct so that a selection test cannot pass
# by accident: TOOLS_ENVIRONMENT gives both Amazon Linux 2 documents the same
# value.
BUILDER_DOCUMENT_ENVIRONMENT = {
    **TOOLS_ENVIRONMENT,
    "AMAZON_LINUX_2_LIME_VOLATILITY_LOADER": "al2LimeVolatilityLoader",
    "AMAZON_LINUX_2_VOLATILITY_PROFILE": "al2VolatilityProfile",
    "AL2023_LIME_VOLATILITY_LOADER": "al2023LimeVolatilityLoader",
    "AL2023_VOLATILITY_SYMBOL": "al2023VolatilitySymbol",
}


def builder_instance_information(platform_name, platform_version):
    """One describe_instance_information entry for the builder instance.

    Shaped like the live response, which carries exactly one entry per
    instance id, unlike the legacy ssmResponse fixture above.
    """
    return {
        "InstanceInformationList": [
            {
                "InstanceId": BUILDER_INSTANCE_ID,
                "PingStatus": "Online",
                "AgentVersion": "3.3.1611.0",
                "PlatformType": "Linux",
                "PlatformName": platform_name,
                "PlatformVersion": platform_version,
                "ResourceType": "EC2Instance",
            }
        ]
    }


def run_handler_on_platform(cfn_status_fn, platform_name, platform_version):
    describe_instance_information_fn.return_value = (
        builder_instance_information(platform_name, platform_version)
    )
    try:
        return run_handler(cfn_status_fn)
    finally:
        describe_instance_information_fn.return_value = ssmResponse


def documents_sent():
    return [
        call.kwargs["DocumentName"].split("/")[-1]
        for call in send_command_fn.call_args_list
    ]


@mock.patch.dict(os.environ, BUILDER_DOCUMENT_ENVIRONMENT)
def test_amazon_linux_2023_builder_selects_the_al2023_documents():
    """Document selection was hardcoded to the Amazon Linux 2 pair, so an
    AL2023 builder ran AL2 commands: no volatility3 (AL2's Python 3.7 is below
    the 3.8 minimum) and no kernel-debuginfo (unpublished since AL2 went end of
    life on 2026-06-30), leaving the evidence bucket unseeded."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler_on_platform(cfn_status_fn, "Amazon Linux", "2023")

    # The symbol step reuses the document kernelSymbolLoader already runs, so
    # there is one validated AL2023 symbol build rather than two.
    assert documents_sent() == [
        "al2023LimeVolatilityLoader",
        "al2023VolatilitySymbol",
    ]
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, BUILDER_DOCUMENT_ENVIRONMENT)
def test_amazon_linux_2023_point_release_still_selects_the_al2023_documents():
    """The agent derives PlatformVersion from VERSION_ID, which is a bare
    "2023" on every AL2023 release seen so far. Matching on the major version
    keeps a point release from being read as an unsupported platform and
    rolling the stack back."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler_on_platform(
        cfn_status_fn, "Amazon Linux", "2023.12.20260817"
    )

    assert documents_sent() == [
        "al2023LimeVolatilityLoader",
        "al2023VolatilitySymbol",
    ]
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, BUILDER_DOCUMENT_ENVIRONMENT)
def test_amazon_linux_2_builder_selects_the_amazon_linux_2_documents():
    """PlatformName is "Amazon Linux" on both AL2 and AL2023, so the version
    is what separates them. An existing AL2 toolsAMI must keep getting the AL2
    documents rather than AL2023 dnf commands it cannot run."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler_on_platform(cfn_status_fn, "Amazon Linux", "2")

    assert documents_sent() == [
        "al2LimeVolatilityLoader",
        "al2VolatilityProfile",
    ]
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, BUILDER_DOCUMENT_ENVIRONMENT)
def test_unsupported_builder_platform_fails_with_an_actionable_reason():
    """Falling back to the Amazon Linux 2 documents on an unrecognised builder
    is what made the original bug silent: the commands ran, exited 0 and
    uploaded nothing. Naming the AMI and the parameter to resolve makes the
    fix a one line cdk.json change."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler_on_platform(cfn_status_fn, "Ubuntu", "20.04")

    assert documents_sent() == []
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    assert "Ubuntu" in reason
    assert "20.04" in reason
    assert "ami-1234567890" in reason
    assert "al2023-ami-kernel-default-x86_64" in reason
    # An unusable builder still has to be cleaned up.
    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_unused_platform_documents_are_not_required_in_the_environment():
    """AMAZON_LINUX_2_* and AL2023_* are populated from the same SSM document
    directory, but an AL2 builder must not start reading the AL2023 variables:
    a KeyError there would fail every existing deployment."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    ret = run_handler_on_platform(cfn_status_fn, "Amazon Linux", "2")

    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200


# ---------------------------------------------------------------------------
# C1 - every exit path signals CloudFormation, exactly once
#
# An invocation that ends without a response leaves the stack in
# CREATE_IN_PROGRESS for the full one hour custom resource timeout, so "no
# signal" is a worse outcome than "wrong signal". Nothing may escape the
# handler, and nothing may signal twice either.
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_missing_environment_variable_still_signals_cloudformation():
    """The environment reads used to sit outside every try block, so a
    misconfigured function raised KeyError straight out of the handler and
    CloudFormation heard nothing at all."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    # patch.dict restores the whole environment on the way out.
    os.environ.pop("S3_BUCKET_NAME")
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert "S3_BUCKET_NAME" in cfn_reason_of(cfn_status_fn)
    # Nothing was launched, so nothing needs terminating either.
    run_instances_fn.assert_not_called()


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_client_that_cannot_be_built_still_signals_cloudformation():
    """create_aws_client is not a cheap constructor: AWSCachedClient.__init__
    makes a live sts:GetCallerIdentity call, and this function runs in a private
    subnet. A NAT blip, a throttle or a missing STS endpoint used to escape the
    handler with no CloudFormation response."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()
    unreachable_sts = Mock(
        side_effect=boto_exceptions.EndpointConnectionError(
            endpoint_url="https://sts.ap-southeast-2.amazonaws.com"
        )
    )

    ret = run_handler(cfn_status_fn, create_aws_client=unreachable_sts)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert "EndpointConnectionError" in cfn_reason_of(cfn_status_fn)


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_malformed_event_still_signals_cloudformation():
    """RequestType is read before anything else, and a physical resource id has
    to be resolvable even when ResourceProperties is not there, otherwise the
    reporting path is itself the thing that fails."""
    global event
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()
    event = {
        "ResponseURL": event["ResponseURL"],
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
    }

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    assert cfn_status_fn.call_args.args[4] == "CustomActionERROR"


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
@pytest.mark.parametrize(
    "waiter_error",
    [
        WAITER_COMMAND_FAILED,
        WAITER_BUDGET_EXHAUSTED,
        WAITER_INVOCATION_MISSING,
    ],
)
def test_cloudformation_is_signalled_exactly_once_on_every_outcome(
    waiter_error,
):
    """One resource, one response. Two responses is as much of a defect as
    none: the second is rejected by the presigned URL and the record of what
    happened is whichever one arrived first."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = waiter_error
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(poisoned)
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_cloudformation_is_signalled_exactly_once_on_the_success_path():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_delete_request_signals_cloudformation_exactly_once():
    global event
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    event["RequestType"] = "Delete"
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    run_instances_fn.assert_not_called()


# ---------------------------------------------------------------------------
# C2 - a cleanup failure must not swallow the build failure
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_non_boto_termination_error_does_not_mask_the_build_error():
    """The termination helper only caught BotoCoreError and ClientError, so a
    TypeError, AttributeError or MemoryError escaped the finally block,
    replaced the build error with itself and - before the handler was
    restructured - left CloudFormation unsignalled."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_COMMAND_FAILED
    terminate_instances_fn.side_effect = TypeError(
        "InstanceIds: expected list, got Mock"
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    # The build failure is what CloudFormation is told about ...
    assert "last status Failed" in reason
    assert "expected list" not in reason
    # ... and the cleanup problem is still reported, just not in its place.
    assert "expected list" in (
        cfn_data_of(cfn_status_fn)["BuilderInstanceTerminationError"]
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_non_boto_termination_error_does_not_hide_a_successful_build():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    terminate_instances_fn.side_effect = AttributeError("no such attribute")
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    assert "no such attribute" in (
        cfn_data_of(cfn_status_fn)["BuilderInstanceTerminationError"]
    )


# ---------------------------------------------------------------------------
# C3 - the SSM registration check has to be exact, and has to wait
# ---------------------------------------------------------------------------


def crowd_of_managed_nodes(size):
    """Other Systems Manager managed nodes in the same account."""
    return [
        {
            "InstanceId": f"i-0c{index:015x}",
            "PingStatus": "Online",
            "PlatformType": "Linux",
            "PlatformName": "Amazon Linux",
            "PlatformVersion": "2",
            "ResourceType": "EC2Instance",
        }
        for index in range(size)
    ]


def setup_paged_managed_nodes(builder_entries, crowd_size=50):
    """Honour the DescribeInstanceInformation contract in the fixture.

    MaxResults defaults to 10 items and is capped at 50, so an unfiltered read
    returns one page of whatever the account happens to have; only a filtered
    read is guaranteed to contain a specific instance. builder_entries is
    consumed one entry per call so that a builder which is not registered yet on
    the first read can come Online on a later one.
    """
    crowd = crowd_of_managed_nodes(crowd_size)
    pending = list(builder_entries)

    def describe(**kwargs):
        wanted = [
            value
            for spec in kwargs.get("Filters") or []
            if spec["Key"] == "InstanceIds"
            for value in spec["Values"]
        ]
        builder = pending.pop(0) if len(pending) > 1 else pending[0]
        available = crowd + ([builder] if builder else [])
        if not wanted:
            return {"InstanceInformationList": crowd}
        return {
            "InstanceInformationList": [
                item for item in available if item["InstanceId"] in wanted
            ]
        }

    describe_instance_information_fn.reset_mock(
        return_value=True, side_effect=True
    )
    describe_instance_information_fn.side_effect = describe


def online_builder(platform_version="2"):
    return {
        "InstanceId": BUILDER_INSTANCE_ID,
        "PingStatus": "Online",
        "PlatformType": "Linux",
        "PlatformName": "Amazon Linux",
        "PlatformVersion": platform_version,
        "ResourceType": "EC2Instance",
    }


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_builder_is_looked_up_by_instance_id():
    """Filters=[{Key: InstanceIds}] is what makes the answer exact; without it
    the response is a page of whatever else the account manages."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    assert describe_instance_information_fn.call_args.kwargs["Filters"] == [
        {"Key": "InstanceIds", "Values": [BUILDER_INSTANCE_ID]}
    ]


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_builder_is_found_in_an_account_with_a_page_full_of_nodes():
    """MaxResults defaults to 10 and caps at 50, so an unfiltered read simply
    does not contain the builder in any account of a realistic size: the loader
    reported "SSM Not installed" and rolled the whole stack back while the
    builder was perfectly healthy."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    setup_paged_managed_nodes([online_builder()], crowd_size=50)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    assert documents_sent() == ["documentName", "documentName"]


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_ssm_agent_is_given_time_to_register():
    """instance_status_ok only proves the EC2 status checks passed; the agent
    registers afterwards. Reading once meant a builder that was 15 seconds
    behind failed the deployment."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    setup_paged_managed_nodes([None, None, online_builder()], crowd_size=3)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert describe_instance_information_fn.call_count >= 3
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_registered_but_offline_agent_is_not_treated_as_ready():
    """A node whose agent has stopped answering is listed with PingStatus
    ConnectionLost. Sending it a command would just time out."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    offline = dict(online_builder(), PingStatus="ConnectionLost")
    setup_paged_managed_nodes([offline], crowd_size=1)
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    assert "SSM Not installed" in reason
    assert "ConnectionLost" in reason
    send_command_fn.assert_not_called()


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_registration_poll_stays_inside_the_cleanup_reserve():
    """The poll must not eat the budget the terminate and the CloudFormation
    signal need."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    setup_paged_managed_nodes([None], crowd_size=1)
    cfn_status_fn = MagicMock()
    context = build_context()
    context.get_remaining_time_in_millis.return_value = 150000

    run_handler(cfn_status_fn, context=context)

    # 150s of budget minus the 120s reserve leaves 30s, which is two polls.
    assert describe_instance_information_fn.call_count == 2
    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )
    assert cfn_status_fn.call_count == 1


# ---------------------------------------------------------------------------
# C4 - a versionless delete can destroy a working investigation path
# ---------------------------------------------------------------------------

# A valid symbol table under the same key, from an earlier build.
USABLE_SYMBOL_VERSION = {
    "Key": POISONABLE_KEY,
    "VersionId": "Xy9SBWnKQ.rGKr6wKPZbYZ1kQ7Ss4Bhq",
    "Size": 33554432,
    "IsLatest": False,
}
POISONED_SYMBOL_VERSION = {
    "Key": POISONABLE_KEY,
    "VersionId": "3sL7WdV1sPbGnPxYh_lNKm2yqHRc8kZP",
    "Size": 0,
    "IsLatest": True,
}


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_zero_byte_artifact_is_kept_when_an_earlier_version_is_usable():
    """A DELETE without a VersionId inserts a delete marker that becomes the
    current version, so a plain GetObject returns 404 for the key regardless of
    the versions underneath it - and lime-memory-load-investigation.json fetches
    the symbol table with a plain "aws s3 cp". volatility3/symbols/ is
    cumulative, one object per kernel release, so delete markering a key whose
    previous version is a valid 33 MB table destroys a working investigation
    path. The problem is reported; the key is left reachable."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(
        poisoned,
        versions_by_key={
            POISONABLE_KEY: [POISONED_SYMBOL_VERSION, USABLE_SYMBOL_VERSION]
        },
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_not_called()
    # A poisoned artifact still fails the resource, delete or no delete.
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    assert POISONABLE_KEY in reason
    assert USABLE_SYMBOL_VERSION["VersionId"] in reason


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_zero_byte_artifact_is_removed_when_no_version_is_usable():
    """With nothing usable to protect, the delete marker is what stops the
    investigation documents reading an empty table."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(
        poisoned, versions_by_key={POISONABLE_KEY: [POISONED_SYMBOL_VERSION]}
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_called_once_with(
        Bucket="BUCKET_FORENSICS", Key=POISONABLE_KEY
    )
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_usable_version_of_a_different_key_does_not_protect_this_one():
    """Prefix is the closest ListObjectVersions has to an exact key match, so a
    longer key that merely starts with this one must not be mistaken for an
    earlier version of it."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(
        poisoned,
        versions_by_key={
            POISONABLE_KEY: [
                POISONED_SYMBOL_VERSION,
                dict(USABLE_SYMBOL_VERSION, Key=POISONABLE_KEY + ".backup"),
            ]
        },
    )
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    s3_client_fn.delete_object.assert_called_once_with(
        Bucket="BUCKET_FORENSICS", Key=POISONABLE_KEY
    )


# ---------------------------------------------------------------------------
# W2 - one key that cannot be handled must not discard the other findings
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_delete_failure_does_not_discard_the_other_artifact_problems():
    """A ClientError from delete_object used to unwind the whole verification,
    throwing away the problems already found and skipping every prefix after
    it: a partial failure became silence about everything else."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned["tools/LiME/"] = [{"Key": LIME_KEY, "Size": 0}]
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(poisoned)
    s3_client_fn.delete_object.side_effect = lambda Bucket, Key: (
        _raise_access_denied() if Key == LIME_KEY else None
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500
    reason = cfn_reason_of(cfn_status_fn)
    # tools/LiME/ is inspected first, and used to be the last thing reported.
    assert LIME_KEY in reason
    assert POISONABLE_KEY in reason


def _raise_access_denied():
    raise ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "DeleteObject",
    )


# ---------------------------------------------------------------------------
# W3 - a builder must never be launched without a way to find it again
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_builder_launch_is_keyed_to_this_cloudformation_request():
    """CloudFormation invokes custom resource Lambdas asynchronously and the
    Lambda service retries an asynchronous invocation that errors or times out.
    Each retry is a separate invocation with its own botocore generated token,
    so without a token of our own a retry launches a second builder and orphans
    the first. RequestId is stable across those retries."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    launch = run_instances_fn.call_args.kwargs
    assert launch["ClientToken"] == CLIENT_TOKEN
    instance_tags = [
        spec["Tags"]
        for spec in launch["TagSpecifications"]
        if spec["ResourceType"] == "instance"
    ][0]
    assert {
        "Key": "ForensicToolsBuilderInvocation",
        "Value": CLIENT_TOKEN,
    } in instance_tags


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_builder_orphaned_by_a_lost_launch_response_is_swept_by_tag():
    """If RunInstances launched the instance and the response never came back,
    this invocation has no instance id for something that is running and
    billing. The invocation tag is the only way to find it."""
    orphan_id = "i-0dddddddddddddddd"
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    run_instances_fn.side_effect = ClientError(
        {
            "Error": {
                "Code": "RequestLimitExceeded",
                "Message": "Request limit exceeded.",
            }
        },
        "RunInstances",
    )
    describe_instances_fn.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": orphan_id}]}]
    }
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    assert describe_instances_fn.call_args.kwargs["Filters"] == [
        {
            "Name": "tag:ForensicToolsBuilderInvocation",
            "Values": [CLIENT_TOKEN],
        },
        {
            "Name": "instance-state-name",
            "Values": ["pending", "running", "stopping", "stopped"],
        },
    ]
    terminate_instances_fn.assert_called_once_with(InstanceIds=[orphan_id])
    assert cfn_status_fn.call_count == 1
    assert cfn_status_of(cfn_status_fn) == "FAILED"
    assert ret.get("statusCode") == 500


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_second_builder_from_the_same_invocation_is_also_terminated():
    """Belt and braces for the case where the sweep finds something the
    launch response did not mention."""
    extra_id = "i-0eeeeeeeeeeeeeeee"
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    describe_instances_fn.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {"InstanceId": BUILDER_INSTANCE_ID},
                    {"InstanceId": extra_id},
                ]
            }
        ]
    }
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=sorted([BUILDER_INSTANCE_ID, extra_id])
    )


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_failed_sweep_does_not_stop_the_known_builder_being_terminated():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    describe_instances_fn.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
        "DescribeInstances",
    )
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn)

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )
    assert cfn_status_of(cfn_status_fn) == "SUCCESS"
    assert ret.get("statusCode") == 200
    assert "UnauthorizedOperation" in (
        cfn_data_of(cfn_status_fn)["BuilderInstanceTerminationError"]
    )


# ---------------------------------------------------------------------------
# W4 - the signalling helper itself must not be able to leave CFN waiting
# ---------------------------------------------------------------------------


def cfn_event_for_signalling():
    return {
        "ResponseURL": "https://cloudformation-custom-resource-response.example/x",
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
    }


def test_a_failing_presigned_put_is_retried_and_never_propagates():
    """send_status_to_cfn re-raised on a failed PUT, and it is called from
    places that cannot handle that: propagating only swapped a slow failure for
    an unsignalled one, because there is no second response to send."""
    put_fn = MagicMock(side_effect=OSError("Connection reset by peer"))

    with patch.object(
        createCustomAction.requests, "put", put_fn
    ), patch.object(time, "sleep", MagicMock()):
        ret = createCustomAction.send_status_to_cfn(
            cfn_event_for_signalling(),
            build_context(),
            "FAILED",
            {},
            "CustomActionForensicLoaderAction",
            createCustomAction.logger,
            reason="something went wrong",
        )

    assert put_fn.call_count == createCustomAction.CFN_RESPONSE_ATTEMPTS
    assert ret.get("statusCode") == 500


def test_a_delivered_presigned_put_is_attempted_exactly_once():
    """The presigned URL is consumed by the first successful PUT, so a
    delivered response must not be retried."""
    put_fn = MagicMock(return_value=MagicMock(status_code=200))

    with patch.object(
        createCustomAction.requests, "put", put_fn
    ), patch.object(time, "sleep", MagicMock()):
        ret = createCustomAction.send_status_to_cfn(
            cfn_event_for_signalling(),
            build_context(),
            "SUCCESS",
            {},
            "CustomActionForensicLoaderAction",
            createCustomAction.logger,
        )

    assert put_fn.call_count == 1
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_a_signalling_helper_that_still_raises_is_not_signalled_twice():
    """The outermost guard has to tolerate the signalling helper raising, and
    tolerating it means logging - not trying again with a second response."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    cfn_status_fn = MagicMock(side_effect=RuntimeError("requests exploded"))

    ret = run_handler(cfn_status_fn)

    assert cfn_status_fn.call_count == 1
    assert ret.get("statusCode") == 200


# ---------------------------------------------------------------------------
# W1 - the evidence bucket mutation has to survive the 255 character truncation
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_the_evidence_bucket_mutation_survives_the_reason_truncation():
    """send_status_to_cfn truncates the reason to 255 characters. A terminal
    build failure plus one poisoned artifact measures well past that, and the
    fact that gets dropped used to be the record that an object was removed from
    the evidence bucket."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    command_waiter_fn.wait.side_effect = WAITER_COMMAND_FAILED
    poisoned = dict(USABLE_TOOL_ARTIFACTS)
    poisoned[POISONED_PREFIX] = [{"Key": POISONABLE_KEY, "Size": 0}]
    setup_artifact_listing(poisoned)
    cfn_status_fn = MagicMock()

    run_handler(cfn_status_fn)

    reason = cfn_reason_of(cfn_status_fn)
    assert len(reason) > 255
    assert POISONABLE_KEY in reason[0:255]
    assert "removed unusable zero byte artifact" in reason[0:255]


# ---------------------------------------------------------------------------
# W7 - the partition cannot be hardcoded to "aws"
# ---------------------------------------------------------------------------


@mock.patch.dict(os.environ, TOOLS_ENVIRONMENT)
def test_every_arn_is_built_from_the_partition_this_function_runs_in():
    """In aws-cn and aws-us-gov an arn:aws: resource does not exist, so the
    narrowed session policies granted nothing and the resource failed on every
    single deployment."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    assume_role_fn.reset_mock()
    cfn_status_fn = MagicMock()

    ret = run_handler(cfn_status_fn, context=build_context("aws-cn"))

    assert ret.get("statusCode") == 200
    document_arn = send_command_fn.call_args.kwargs["DocumentName"]
    assert document_arn.startswith("arn:aws-cn:ssm:ap-southeast-2:")
    policies = [
        call.kwargs["Policy"] for call in assume_role_fn.call_args_list
    ]
    assert len(policies) == 2
    for policy in policies:
        assert "arn:aws-cn:s3:::BUCKET_FORENSICS" in policy
        assert "arn:aws:s3:::" not in policy
