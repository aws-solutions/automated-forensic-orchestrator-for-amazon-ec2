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

from ...src.common.exception import ForensicLambdaExecutionException

from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.acquisition import checkMemoryAcquisition

event = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing Check Memory Acquisition Flow Started ")
    global event
    event = {
        "Payload": {
            "body": {
                "forensicType": "MEMORY",
                "ForensicInstanceId": "i-04a5fde997d49e225",
                "MemoryAcquisition": {
                    "CommandId": "c2ddbb3d-5d18-45d4-807e-07e936b6f0ec",
                    "CommandIdArtifactMap": {
                        "c2ddbb3d-5d18-45d4-807e-07e936b6f0ec": {
                            "Prefix": "memory/i-0d02bff5f6d29258d/fbd6b0d3-a203-401c-86cd-1f679109ac7a",
                            "SSMDocumentName": "ForensicSolutionStack-ForensicSSMDBuilderStackSSMDocumentlinuxlimememoryacquisitionAF2BE0B7-0trqhNLt4XuA",
                        }
                    },
                },
                "instanceInfo": {
                    "PlatformDetails": "Linux/UNIX",
                },
                "SSM_STATUS": "SUCCEEDED",
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
            }
        },
        "statusCode": 200,
    }
    # yield
    # print ('Testing Check Memory Acquisition Flow Completed')
    def teardown():
        print("Testing Check Memory Acquisition Flow Completed")

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


def get_update_record_event():
    return {"Attributes": forensic_record()}


def get_item_event():
    return {"Item": forensic_record()}


def list_objects_event():
    return {
        "Contents": [
            {
                "Key": "memory/i-0d02bff5f6d29258d/459f3a69-0912-4f25-acf3-2c9f9066ec35/linux_memcapture.lime",
                "LastModified": "2022-02-16T04:36:03+00:00",
                "ETag": '"b58fc8f79fc1ef79628cd678762e59fa-125"',
                "Size": 1043958848,
                "StorageClass": "STANDARD",
            },
            {
                "Key": "memory/i-0d02bff5f6d29258d/459f3a69-0912-4f25-acf3-2c9f9066ec35/linux_memcapture_sha256.txt",
                "LastModified": "2022-02-16T04:36:03+00:00",
                "ETag": '"6830124924c63c8b92db6caa4c9a5ee4"',
                "Size": 88,
                "StorageClass": "STANDARD",
            },
            {
                "Key": "memory/i-0d02bff5f6d29258d/459f3a69-0912-4f25-acf3-2c9f9066ec35/memory-sha-hash.txt",
                "LastModified": "2022-02-16T04:36:03+00:00",
                "ETag": '"00ec3430413f82e67be0456fafc47c9d"',
                "Size": 88,
                "StorageClass": "STANDARD",
            },
        ]
    }


get_command_invocation_fn = MagicMock()
update_item_fn = MagicMock(return_value=get_update_record_event())
get_item_fn = MagicMock(return_value=get_item_event())
put_item_fn = MagicMock(return_value={})
list_objects_fn = MagicMock(return_value=list_objects_event())
transact_write_item_fn = MagicMock(return_value={})
update_item_fn = MagicMock(return_value=get_update_record_event())
modify_document_permission_fn = MagicMock()


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.get_command_invocation = get_command_invocation_fn
    mockClient.update_item = update_item_fn
    mockClient.get_item = get_item_fn
    mockClient.put_item = put_item_fn
    mockClient.list_objects_v2 = list_objects_fn
    mockClient.transact_write_items = transact_write_item_fn
    mockClient.update_item = update_item_fn
    mockClient.modify_document_permission = modify_document_permission_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "testbucket",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "WINDOWS_LIME_MEMORY_ACQUISITION": "documentName",
        "LINUX_LIME_MEMORY_ACQUISITION": "documentName",
    },
)
def test_trigger_event():
    get_command_invocation_fn.return_value = {"StatusDetails": "Success"}
    with patch.object(
        checkMemoryAcquisition,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = checkMemoryAcquisition.handler(event, context)
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "testbucket",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "WINDOWS_LIME_MEMORY_ACQUISITION": "documentName",
        "LINUX_LIME_MEMORY_ACQUISITION": "documentName",
    },
)
def test_no_uploaded_memory_capture_artifacts():
    get_command_invocation_fn.return_value = {"StatusDetails": "Success"}
    put_item_fn.return_value = {}
    with patch.object(
        checkMemoryAcquisition,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"

        ret = checkMemoryAcquisition.handler(event, context)
        assert execinfo.type == ForensicLambdaExecutionException


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "S3_BUCKET_NAME": "testbucket",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
        "WINDOWS_LIME_MEMORY_ACQUISITION": "documentName",
        "LINUX_LIME_MEMORY_ACQUISITION": "documentName",
    },
)
def test_record_failure_when_exception():
    get_command_invocation_fn.side_effect = Exception("AWS ERROR!")
    with patch.object(
        checkMemoryAcquisition,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"

        ret = checkMemoryAcquisition.handler(event, context)
        assert execinfo.type == Exception
        update_item_fn.assert_called()
        get_command_invocation_fn.reset_mock()
