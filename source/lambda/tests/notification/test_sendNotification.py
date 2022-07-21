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

from ...src.common.awsapi_cached_client import create_aws_client

# from ..src.triage  import handler as function_under_test
# from ..src.triage.app import lambda_handler as function_under_test
from ...src.notification import sendNotification as app


def disk_event():
    return {
        "Payload": {
            "body": {
                "forensicId": "1234567890",
                "forensicType": "DISK",
            }
        },
        "statusCode": 200,
    }


def memory_event():
    return {
        "Payload": {
            "body": {
                "forensicId": "1234567890",
                "forensicType": "MEMORY",
            }
        },
        "statusCode": 200,
    }


def forensic_record():
    return {
        "resourceId": {"S": "i-01abc123def"},
        "resourceInfo": {
            "M": {
                "BlockDeviceMappings": {
                    "L": [
                        {
                            "M": {
                                "DeviceName": {"S": "/dev/xvda"},
                                "Ebs": {
                                    "M": {
                                        "Status": {"S": "attached"},
                                        "VolumeId": {
                                            "S": "vol-0fa9fbf1a0323a04f"
                                        },
                                        "AttachTime": {
                                            "S": "2021-11-18T04:58:54+00:00"
                                        },
                                        "DeleteOnTermination": {"BOOL": True},
                                    }
                                },
                            }
                        }
                    ]
                },
                "IamInstanceProfile": {
                    "M": {
                        "Arn": {
                            "S": "arn:aws:iam::123456789012:instance-profile/SSMDefaultRole"
                        },
                        "Id": {"S": "AIPAYFFB3ORIFIFKOTFH4"},
                    }
                },
                "SubnetId": {"S": "subnet-0be828943dae437d0"},
                "EbsOptimized": {"BOOL": False},
                "Placement": {
                    "M": {
                        "GroupName": {"S": ""},
                        "Tenancy": {"S": "default"},
                        "AvailabilityZone": {"S": "ap-southeast-2b"},
                    }
                },
                "EnclaveOptions": {"M": {"Enabled": {"BOOL": False}}},
                "NetworkInterfaces": {
                    "L": [
                        {
                            "M": {
                                "Status": {"S": "in-use"},
                                "Description": {
                                    "S": "Primary network interface"
                                },
                                "PrivateDnsName": {
                                    "S": "ip-10-0-4-29.ap-southeast-2.compute.internal"
                                },
                                "PrivateIpAddress": {"S": "10.0.4.29"},
                                "PrivateIpAddresses": {
                                    "L": [
                                        {
                                            "M": {
                                                "Primary": {"BOOL": True},
                                                "PrivateDnsName": {
                                                    "S": "ip-10-0-4-29.ap-southeast-2.compute.internal"
                                                },
                                                "PrivateIpAddress": {
                                                    "S": "10.0.4.29"
                                                },
                                            }
                                        }
                                    ]
                                },
                                "Attachment": {
                                    "M": {
                                        "Status": {"S": "attached"},
                                        "NetworkCardIndex": {"N": "0"},
                                        "AttachmentId": {
                                            "S": "eni-attach-0908c8c7a432be0b7"
                                        },
                                        "DeviceIndex": {"N": "0"},
                                        "AttachTime": {
                                            "S": "2021-11-18T04:58:52+00:00"
                                        },
                                        "DeleteOnTermination": {"BOOL": True},
                                    }
                                },
                                "Ipv6Addresses": {"L": []},
                                "SubnetId": {"S": "subnet-0be828943dae437d0"},
                                "MacAddress": {"S": "02:4b:07:fd:ec:e4"},
                                "NetworkInterfaceId": {
                                    "S": "eni-06c16aff96eb76787"
                                },
                                "SourceDestCheck": {"BOOL": True},
                                "InterfaceType": {"S": "interface"},
                                "OwnerId": {"S": "123456789012"},
                                "VpcId": {"S": "vpc-0c315768612ee4eb1"},
                                "Groups": {
                                    "L": [
                                        {
                                            "M": {
                                                "GroupName": {
                                                    "S": "launch-wizard-2"
                                                },
                                                "GroupId": {
                                                    "S": "sg-0921dc1131442951f"
                                                },
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                },
                "ImageId": {"S": "ami-043e0add5c8665836"},
                "InstanceType": {"S": "t2.micro"},
                "Monitoring": {"M": {"State": {"S": "disabled"}}},
                "Tags": {
                    "L": [
                        {
                            "M": {
                                "Value": {"S": "DEV"},
                                "Key": {"S": "Patch Group"},
                            }
                        }
                    ]
                },
                "ProductCodes": {"L": []},
                "HibernationOptions": {"M": {"Configured": {"BOOL": False}}},
                "LaunchTime": {"S": "2021-11-18T04:58:52+00:00"},
                "Architecture": {"S": "x86_64"},
                "MetadataOptions": {
                    "M": {
                        "HttpPutResponseHopLimit": {"N": "1"},
                        "HttpProtocolIpv6": {"S": "disabled"},
                        "HttpTokens": {"S": "optional"},
                        "HttpEndpoint": {"S": "enabled"},
                        "State": {"S": "applied"},
                    }
                },
                "Hypervisor": {"S": "xen"},
                "InstanceId": {"S": "i-0e7c6b5d34c76650a"},
                "VirtualizationType": {"S": "hvm"},
                "CpuOptions": {
                    "M": {
                        "ThreadsPerCore": {"N": "1"},
                        "CoreCount": {"N": "1"},
                    }
                },
                "UsageOperationUpdateTime": {"S": "2021-11-18T04:58:52+00:00"},
                "PublicDnsName": {"S": ""},
                "KeyName": {"S": "personal_isengard_key"},
                "RootDeviceType": {"S": "ebs"},
                "SourceDestCheck": {"BOOL": True},
                "AmiLaunchIndex": {"N": "0"},
                "VpcId": {"S": "vpc-0c315768612ee4eb1"},
                "State": {
                    "M": {"Code": {"N": "16"}, "Name": {"S": "running"}}
                },
                "StateTransitionReason": {"S": ""},
                "ClientToken": {"S": ""},
                "UsageOperation": {"S": "RunInstances"},
                "CapacityReservationSpecification": {
                    "M": {"CapacityReservationPreference": {"S": "open"}}
                },
            }
        },
        "creationTime": {"S": "2022-02-18T01:24:44.104700+00:00"},
        "awsAccountId": {"S": "123456789012"},
        "diskAnalysisStatus": {"S": "SUCCESS"},
        "associatedFindings": {
            "L": [
                {
                    "M": {
                        "region": {"S": "ap-southeast-2"},
                        "service": {"S": "securityhub"},
                        "id": {
                            "S": "arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.8/finding/482e8524-4f22-4a27-9dba-b8a582f24529"
                        },
                    }
                }
            ]
        },
        "lastUpdatedTime": {"S": "2022-02-18T01:24:51.518344+00:00"},
        "GSI1SK": {
            "S": "#REGION#ap-southeast-2#ResourceType.INSTANCE#i-01abc123def"
        },
        "awsRegion": {"S": "ap-southeast-2"},
        "memoryAnalysisStatus": {"S": "SUCCESS"},
        "triageStatus": {"S": "SUCCESS"},
        "GSI1PK": {"S": "123456789012"},
        "resourceType": {"S": "INSTANCE"},
        "diskAnalysisStatusDescription": {"S": "Beginning disk acquisition"},
        "SK": {"S": "RECORD#fbd6b0d3-a203-401c-86cd-1f679109ac7a#METADATA"},
        "triageStatusDescription": {"S": "Completed triage"},
        "PK": {"S": "RECORD#fbd6b0d3-a203-401c-86cd-1f679109ac7a"},
        "id": {"S": "fbd6b0d3-a203-401c-86cd-1f679109ac7a"},
        "memoryAnalysisStatusDescription": {
            "S": "Beginning memory acquisition"
        },
        "sourceAccountSnapshots": {
            "L": [
                {
                    "M": {
                        "volumeId": {"S": "vol-0d7a6f5a15ef95ea9"},
                        "snapshotId": {"S": "snap-018eebb9524445e0b"},
                        "awsAccountId": {"S": "123456789012"},
                        "region": {"S": "ap-southeast-2"},
                        "volumeSize": {"N": "8"},
                    }
                }
            ]
        },
    }


def get_item_event():
    return {"Item": forensic_record()}


publish_fn = MagicMock()
get_item_fn = MagicMock(return_value=get_item_event())


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.get_item = get_item_fn
    mockClient.publish = publish_fn
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:100000:test-topic",
        "FORENSIC_BUCKET": "forensicbucket",
    },
)
def test_send_notification_for_successful_forensic_disk():
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):

        # context = MagicMock()
        # context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = app.handler(disk_event(), {})
        assert ret.get("statusCode") == 200
        # assert publish_fn.call_count(1)
        # assert publish_fn.call_count(1)
        publish_fn.assert_called_once_with(
            TopicArn="arn:aws:sns:ap-southeast-2:100000:test-topic",
            Message="Disk analysis for forensic record 1234567890 finished successfully. \n EC2 instance i-01abc123def in account 123456789012 has been isolated and analyzed. \n Forensic details are stored in s3 bucket:  forensicbucket. \n For more details on timeline kindly look into Dynamodb table : table",
            Subject="Forensic 1234567890 succeeded",
        )
        publish_fn.reset_mock()


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:100000:test-topic",
        "FORENSIC_BUCKET": "forensicbucket",
    },
)
def test_send_notification_for_successful_forensic_memory():
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        # context = MagicMock()
        # context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = app.handler(memory_event(), {})
        assert ret.get("statusCode") == 200
        # assert publish_fn.call_count(1)
        # assert publish_fn.call_count(1)
        publish_fn.assert_called_once_with(
            TopicArn="arn:aws:sns:ap-southeast-2:100000:test-topic",
            Message="Memory analysis for forensic record 1234567890 finished successfully. \n EC2 instance i-01abc123def in account 123456789012 has been isolated and analyzed. \n Forensic details are stored in s3 bucket :  forensicbucket. \n For more details on timeline kindly look into Dynamodb table : table",
            Subject="Forensic 1234567890 succeeded",
        )
        publish_fn.reset_mock()


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:100000:test-topic",
        "FORENSIC_BUCKET": "forensicbucket",
    },
)
def test_send_notification_for_failed_forensic_disk():
    publish_fn.reset_mock()
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        failed_disk_state = get_item_event()
        failed_disk_state["Item"]["diskAnalysisStatus"] = {"S": "FAILED"}
        failed_disk_state["Item"]["diskAnalysisStatusDescription"] = {
            "S": "A reason"
        }

        get_item_fn.return_value = failed_disk_state

        ret = app.handler(disk_event(), {})
        assert ret.get("statusCode") == 200
        publish_fn.assert_called_once_with(
            TopicArn="arn:aws:sns:ap-southeast-2:100000:test-topic",
            Message="Forensic record 1234567890 aborted due to A reason. \n Target EC2 instance i-01abc123def in account 123456789012.",
            Subject="Forensic 1234567890 failed",
        )


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:100000:test-topic",
        "FORENSIC_BUCKET": "forensicbucket",
    },
)
def test_send_notification_for_failed_forensic_memory():
    publish_fn.reset_mock()
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        failed_memory_state = get_item_event()
        failed_memory_state["Item"]["memoryAnalysisStatus"] = {"S": "FAILED"}
        failed_memory_state["Item"]["memoryAnalysisStatusDescription"] = {
            "S": "A reason"
        }

        get_item_fn.return_value = failed_memory_state

        ret = app.handler(memory_event(), {})
        assert ret.get("statusCode") == 200
        publish_fn.assert_called_once_with(
            TopicArn="arn:aws:sns:ap-southeast-2:100000:test-topic",
            Message="Forensic record 1234567890 aborted due to A reason. \n Target EC2 instance i-01abc123def in account 123456789012",
            Subject="Forensic 1234567890 failed",
        )
