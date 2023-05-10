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
from ...src.investigation.runForensicsCommand import (
    handler as function_under_test,
)

event = {}
tokens = {}
ssmResponse = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing Run Forensic Command for Disk investigation Started ")
    global event
    event = {
        "ExecutedVersion": "$LATEST",
        "Payload": {
            "body": {
                "ForensicInstanceId": "i-0bf2bf6b175654c6e123",
                "ForensicInvestigationInstanceId": "i-0b3daeccbc7e52246",
                "MemoryForensics": {
                    "CommandId": "26608e13-4c7a-4353-ad97-67e2e6cc66e4"
                },
                "forensicType": "MEMORY",
                "SSM_STATUS": "SUCCEEDED",
                "forensicId": "b6167d32-c3e6-4efc-b2ea-bc0f61b2f682",
                "isMemoryAcquisitionComplete": "TRUE",
                "instanceId": "i-d",
                "forensicAttachedVolumeInfo": [
                    {
                        "attachedDevice": "xdf/vol",
                        "attachedVolumeId": "vol-12345",
                        "instanceVolumeMountingPoint": "/data/01",
                    }
                ],
                "VolumeArtifactMap": {
                    "vol-12345": "391b775f-21f5-41ad-af70-62e77c518eaa"
                },
                "instanceInfo": {
                    "PlatformDetails": "Windows",
                },
            }
        },
        "StatusCode": 200,
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
    ssmResponse = {
        "InstanceInformationList": [
            {
                "InstanceId": "i-0b3daeccbc7e52246",
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
                "InstanceId": "i-0bf2bf6b175654c6e123",
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
    }

    def teardown():
        print("Testing Run Forensic Command for Disk investigation Completed")

    request.addfinalizer(teardown)


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
        "diskAnalysisStatus": {"S": "ACQUISITION"},
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
        "memoryAnalysisStatus": {"S": "ACQUISITION"},
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


describe_instance_information_fn = MagicMock()
send_command_fn = MagicMock()
get_item_fn = MagicMock()
assume_role_fn = MagicMock()
update_item_fn = MagicMock()
get_item_fn = MagicMock(return_value=get_item_event())


def setup_postive_mocks():
    describe_instance_information_fn.return_value = ssmResponse

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


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = MagicMock()
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: response
    mockClient.put_item = MagicMock()
    mockClient.get_item = get_item_fn
    mockClient.assume_role = assume_role_fn
    mockClient.describe_instance_information = describe_instance_information_fn
    mockClient.send_command = send_command_fn
    mockClient.update_item = update_item_fn
    mockClient.get_item = get_item_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "LINUX_DISK_INVESTIGATION": "documentName",
        "WINDOWS_DISK_INVESTIGATION": "win_doc",
    },
)
def test_trigger_event():
    assume_role_fn.return_value = tokens
    setup_postive_mocks()
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection({})),
    ):
        ret = function_under_test(event, "")
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "BUCKET_FORENSICS",
        "S3_COPY_ROLE": "arn:s3copRole",
        "LINUX_DISK_INVESTIGATION": "documentName",
        "WINDOWS_DISK_INVESTIGATION": "win_doc",
    },
)
def test_error_flowtrigger_event():
    describe_instance_information_fn.return_value = {}
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        ret = function_under_test(event, "")
        assert execinfo.type == Exception
        update_item_fn.assert_called()
