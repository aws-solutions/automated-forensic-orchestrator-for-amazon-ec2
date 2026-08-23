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

from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.kernelloader import kernelSymbolLoader

event = {}
tokens = {}
ssmResponse = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing load forensic tools Flow Started ")
    global event
    event = {
        "amiId": "ami-123",
        "distribution": "RHEL8",
        "username": "username",
        "password": "password",
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
send_command_fn = MagicMock()
modify_document_permission_fn = MagicMock()
describe_subnets_fn = MagicMock()
run_instances_fn = MagicMock()


BUILDER_INSTANCE_ID = "i-0bf2bf6b175654c6e"


def setup_positive_mocks():

    describe_instance_information_fn.reset_mock(side_effect=True)
    describe_instance_information_fn.return_value = ssmResponse
    describe_subnets_fn.return_value = {
        "Subnets": [{"SubnetId": "sub-1234567890"}]
    }
    run_instances_fn.reset_mock(side_effect=True)
    run_instances_fn.return_value = {
        "Instances": [{"InstanceId": BUILDER_INSTANCE_ID}]
    }


def get_paginator_fn(operation_name):
    """Paginator seam for the one paginated SSM call this handler makes."""
    if operation_name != "describe_instance_information":
        raise AssertionError("unexpected paginator " + operation_name)
    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **kwargs: [
        describe_instance_information_fn(**kwargs)
    ]
    return paginator


terminate_instances_fn = MagicMock()


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
    mockClient.get_paginator = get_paginator_fn
    mockClient.terminate_instances = terminate_instances_fn
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
        "RHEL8_VOLATILITY_SYMBOL": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
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
        kernelSymbolLoader,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = kernelSymbolLoader.handler(event, context)
        assert ret.get("statusCode") == 200


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
        "RHEL8_VOLATILITY_SYMBOL": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
        "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
    },
)
def test_unsupported_distribution_error():
    assume_role_fn.return_value = tokens

    describe_instance_information_fn.return_value = ssmResponse
    setup_positive_mocks()

    with patch.object(
        kernelSymbolLoader,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = kernelSymbolLoader.handler(
            {"amiId": "ami-123", "distribution": "unsupported"}, context
        )
        assert execinfo.type == ValueError


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
        "AL2023_VOLATILITY_SYMBOL": "al2023DocumentName",
        "RHEL8_VOLATILITY_SYMBOL": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
        "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
    },
)
def test_al2023_symbol_build_needs_no_subscription_credentials():
    """AL2023 gets debuginfo from amazonlinux-debuginfo, so the symbol
    document declares no subscription-manager parameters. Sending them
    anyway would make SSM reject the command as InvalidParameters."""
    assume_role_fn.return_value = tokens
    describe_instance_information_fn.return_value = ssmResponse
    setup_positive_mocks()
    send_command_fn.reset_mock()
    send_command_fn.return_value = {
        "Command": {"CommandId": "73f4f7bb-53a7-4397-8085-c5b6baa8a126"}
    }

    with patch.object(
        kernelSymbolLoader,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = kernelSymbolLoader.handler(
            {"amiId": "ami-123", "distribution": "AL2023"}, context
        )

    assert ret.get("statusCode") == 200
    sent_params = send_command_fn.call_args.kwargs["Parameters"]
    assert "SubscriptionManagerUsername" not in sent_params
    assert "SubscriptionManagerPassword" not in sent_params
    assert sent_params["s3bucket"] == ["BUCKET_FORENSICS"]
    assert (
        "al2023DocumentName"
        in send_command_fn.call_args.kwargs["DocumentName"]
    )


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
        "RHEL8_VOLATILITY_SYMBOL": "documentName",
        "SSM_EXECUTION_TIMEOUT": "1800",
        "VPC_ID": "vpc-1234567890",
        "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
    },
)
def test_rhel_symbol_build_without_credentials_is_rejected():
    """RHEL still needs subscription-manager credentials; omitting them used
    to raise KeyError deep in the handler after an instance was launched."""
    assume_role_fn.return_value = tokens
    describe_instance_information_fn.return_value = ssmResponse
    setup_positive_mocks()

    with patch.object(
        kernelSymbolLoader,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(ValueError) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        kernelSymbolLoader.handler(
            {"amiId": "ami-123", "distribution": "RHEL8"}, context
        )

    assert "subscription manager" in str(execinfo.value)


SYMBOL_ENVIRONMENT = {
    "AWS_REGION": "ap-southeast-2",
    "S3_BUCKET_NAME": "BUCKET_FORENSICS",
    "S3_COPY_ROLE": "arn:s3copRole",
    "S3_BUCKET_KEY_ARN": "arn:aws:kms:ap-southeast-2:123456789012:key/78dd4742-e6b8-4e1c-acc5-5ad35042a86b",
    "RHEL8_VOLATILITY_SYMBOL": "rhel8DocumentName",
    "AL2023_VOLATILITY_SYMBOL": "al2023DocumentName",
    "SSM_EXECUTION_TIMEOUT": "1800",
    "VPC_ID": "vpc-1234567890",
    "FORENSIC_INSTANCE_PROFILE": "arn:instance:profile",
}


def build_context(remaining_millis=900000):
    context = MagicMock()
    context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
    # A bare MagicMock answers get_remaining_time_in_millis with a MagicMock
    # whose __int__ is 1, i.e. a Lambda with one millisecond left, which now
    # legitimately collapses both waits to a single attempt. Model the real
    # 900 second budget PythonLambdaConstruct configures.
    context.get_remaining_time_in_millis = MagicMock(
        return_value=remaining_millis
    )
    return context


def run_handler(handler_event):
    with patch.object(
        kernelSymbolLoader,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), patch.object(time, "sleep", MagicMock()):
        return kernelSymbolLoader.handler(handler_event, build_context())


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
@pytest.mark.parametrize("distribution", ["RHEL7", "RHEL9"])
def test_a_distribution_without_a_symbol_document_is_not_offered(distribution):
    """RHEL7 and RHEL9 were advertised as supported, but only
    RHEL8-volatility-symbol.json and AL2023-volatility-symbol.json exist, so
    <DISTRIBUTION>_VOLATILITY_SYMBOL was never set for them. That raised
    KeyError - after an instance had been launched, which this handler never
    terminates."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()

    with pytest.raises(ValueError) as execinfo:
        run_handler(
            {
                "amiId": "ami-123",
                "distribution": distribution,
                "username": "u",
                "password": "p",
            }
        )

    assert "Invalid distribution value" in str(execinfo.value)
    run_instances_fn.assert_not_called()


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_a_missing_symbol_document_is_detected_before_anything_is_launched():
    """The document name used to be resolved after run_instances, so an
    incompletely deployed stack leaked a t3.large that nothing terminates.

    It now raises ValueError rather than a bare KeyError: the distribution is
    supported, the deployment is incomplete, and those are different problems.
    The message has to name the variable, because "KeyError:
    'AL2023_VOLATILITY_SYMBOL'" tells an operator nothing about which document
    failed to deploy.
    """
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    # patch.dict restores the whole environment on the way out.
    os.environ.pop("AL2023_VOLATILITY_SYMBOL")

    with pytest.raises(ValueError) as execinfo:
        run_handler({"amiId": "ami-123", "distribution": "AL2023"})

    message = str(execinfo.value)
    assert "AL2023_VOLATILITY_SYMBOL" in message
    assert "AL2023" in message
    assert "not deployed" in message
    run_instances_fn.assert_not_called()


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_the_builder_is_looked_up_by_instance_id():
    """An unfiltered describe_instance_information returns 10 managed nodes by
    default and 50 at most, so in any account of a realistic size the builder is
    absent from the response and this handler raised "SSM Not installed" while
    the builder was healthy."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()

    ret = run_handler({"amiId": "ami-123", "distribution": "AL2023"})

    assert ret.get("statusCode") == 200
    assert describe_instance_information_fn.call_args.kwargs["Filters"] == [
        {"Key": "InstanceIds", "Values": [BUILDER_INSTANCE_ID]}
    ]


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_the_builder_is_found_in_an_account_with_a_page_full_of_nodes():
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    crowd = [
        {
            "InstanceId": f"i-0c{index:015x}",
            "PingStatus": "Online",
            "PlatformName": "Amazon Linux",
            "PlatformVersion": "2",
        }
        for index in range(50)
    ]
    builder = {
        "InstanceId": BUILDER_INSTANCE_ID,
        "PingStatus": "Online",
        "PlatformName": "Amazon Linux",
        "PlatformVersion": "2023",
    }

    def describe(**kwargs):
        wanted = [
            value
            for spec in kwargs.get("Filters") or []
            if spec["Key"] == "InstanceIds"
            for value in spec["Values"]
        ]
        if not wanted:
            return {"InstanceInformationList": crowd}
        return {
            "InstanceInformationList": [
                item
                for item in crowd + [builder]
                if item["InstanceId"] in wanted
            ]
        }

    describe_instance_information_fn.reset_mock(
        return_value=True, side_effect=True
    )
    describe_instance_information_fn.side_effect = describe

    ret = run_handler({"amiId": "ami-123", "distribution": "AL2023"})

    assert ret.get("statusCode") == 200
    assert ret.get("body").get("InstanceId") == BUILDER_INSTANCE_ID


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_the_ssm_agent_is_given_time_to_register():
    """instance_status_ok only proves the EC2 status checks passed; the agent
    registers afterwards, so reading once failed a healthy builder."""
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    responses = [
        {"InstanceInformationList": []},
        {"InstanceInformationList": []},
        {
            "InstanceInformationList": [
                {
                    "InstanceId": BUILDER_INSTANCE_ID,
                    "PingStatus": "Online",
                    "PlatformName": "Amazon Linux",
                    "PlatformVersion": "2023",
                }
            ]
        },
    ]
    describe_instance_information_fn.reset_mock(
        return_value=True, side_effect=True
    )
    describe_instance_information_fn.side_effect = responses

    ret = run_handler({"amiId": "ami-123", "distribution": "AL2023"})

    assert describe_instance_information_fn.call_count == 3
    assert ret.get("statusCode") == 200


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_a_failure_after_launch_terminates_the_builder_instance():
    """Every post-launch failure has to terminate the t3.large.

    The state machine's "Stop instance" state is downstream of this handler, so
    it is unreachable when the handler raises - the instance simply kept running.
    botocore's instance_status_ok waiter alone can burn 585s of the 900s Lambda
    and the fixed SSM registration poll another 285s, so the handler used to hit
    its timeout rather than raising anything at all.
    """
    assume_role_fn.return_value = tokens
    setup_positive_mocks()
    terminate_instances_fn.reset_mock()

    client = mock_connection({})
    client.get_waiter.return_value.wait.side_effect = RuntimeError(
        "instance never passed its status checks"
    )

    with patch.object(
        kernelSymbolLoader, "create_aws_client", Mock(return_value=client)
    ), patch.object(time, "sleep", MagicMock()):
        with pytest.raises(RuntimeError):
            kernelSymbolLoader.handler(
                {"amiId": "ami-123", "distribution": "AL2023"}, build_context()
            )

    terminate_instances_fn.assert_called_once_with(
        InstanceIds=[BUILDER_INSTANCE_ID]
    )


@mock.patch.dict(os.environ, SYMBOL_ENVIRONMENT)
def test_both_waits_are_bounded_by_the_remaining_lambda_budget():
    """870s of fixed waits inside a 900s timeout is not survivable.

    With little budget left the waits must collapse rather than run to their
    static attempt counts, so that the terminate above is still reached.
    """
    starved = kernelSymbolLoader.remaining_budget_seconds(
        build_context(remaining_millis=90000)
    )
    roomy = kernelSymbolLoader.remaining_budget_seconds(
        build_context(remaining_millis=900000)
    )

    assert starved < roomy
    # the cleanup reserve is genuinely withheld
    assert starved == 90 - kernelSymbolLoader.CLEANUP_RESERVE_SECONDS
    ec2_worst_case = (
        int(roomy * kernelSymbolLoader.EC2_WAITER_BUDGET_SHARE)
        // kernelSymbolLoader.EC2_WAITER_DELAY_SECONDS
    ) * kernelSymbolLoader.EC2_WAITER_DELAY_SECONDS
    ssm_worst_case = (
        kernelSymbolLoader.SSM_REGISTRATION_ATTEMPTS
        * kernelSymbolLoader.SSM_REGISTRATION_POLL_SECONDS
    )
    assert ec2_worst_case + ssm_worst_case < 900
