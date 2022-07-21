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
from ...src.acquisition.acquisitionInitialiser import (
    handler as function_under_test,
)

event = {}


@pytest.fixture(scope="function", autouse=True)
def setupevent(request):

    print("Testing Check Store-update Forensics Info Started  ")
    global event
    event = {
        "input": {
            "ExecutedVersion": "$LATEST",
            "Payload": {
                "body": {
                    "forensicId": "2b57d956-648d-4188-9df9-92abbd62d9d4",
                    "instanceAccount": "123456789012",
                    "instanceRegion": "ap-southeast-2",
                    "instanceInfo": {
                        "AmiLaunchIndex": 0,
                        "Architecture": "x86_64",
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xvda",
                                "Ebs": {
                                    "AttachTime": "2021-12-10T04:45:43+00:00",
                                    "DeleteOnTermination": True,
                                    "Status": "attached",
                                    "VolumeId": "vol-0b596582eb832fd28",
                                },
                            }
                        ],
                        "CapacityReservationSpecification": {
                            "CapacityReservationPreference": "open"
                        },
                        "ClientToken": "",
                        "CpuOptions": {"CoreCount": 1, "ThreadsPerCore": 2},
                        "EbsOptimized": True,
                        "EnaSupport": True,
                        "EnclaveOptions": {"Enabled": False},
                        "HibernationOptions": {"Configured": False},
                        "Hypervisor": "xen",
                        "IamInstanceProfile": {
                            "Arn": "arn:aws:iam::123456789012:instance-profile/SSM-Test-Instnace",
                            "Id": "AIPATSJUVGIT77T3MJTS2",
                        },
                        "ImageId": "ami-0bd2230cfb28832f7",
                        "InstanceId": "i-0e161b8fc12055378",
                        "InstanceType": "t3.medium",
                        "KeyName": "deena-101",
                        "LaunchTime": "2021-12-10T04:45:42+00:00",
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpProtocolIpv6": "disabled",
                            "HttpPutResponseHopLimit": 1,
                            "HttpTokens": "optional",
                            "State": "applied",
                        },
                        "Monitoring": {"State": "disabled"},
                        "NetworkInterfaces": [
                            {
                                "Attachment": {
                                    "AttachTime": "2021-12-10T04:45:42+00:00",
                                    "AttachmentId": "eni-attach-0cefe4446e3a45bca",
                                    "DeleteOnTermination": True,
                                    "DeviceIndex": 0,
                                    "NetworkCardIndex": 0,
                                    "Status": "attached",
                                },
                                "Description": "Primary network interface",
                                "Groups": [
                                    {
                                        "GroupId": "sg-0b40f73cba796211b",
                                        "GroupName": "launch-wizard-2",
                                    }
                                ],
                                "InterfaceType": "interface",
                                "Ipv6Addresses": [],
                                "MacAddress": "06:94:27:42:03:f6",
                                "NetworkInterfaceId": "eni-0bd0ae23816da19c4",
                                "OwnerId": "123456789012",
                                "PrivateDnsName": "ip-10-1-3-235.ap-southeast-2.compute.internal",
                                "PrivateIpAddress": "10.1.3.235",
                                "PrivateIpAddresses": [
                                    {
                                        "Primary": True,
                                        "PrivateDnsName": "ip-10-1-3-235.ap-southeast-2.compute.internal",
                                        "PrivateIpAddress": "10.1.3.235",
                                    }
                                ],
                                "SourceDestCheck": True,
                                "Status": "in-use",
                                "SubnetId": "subnet-032da126cc939a487",
                                "VpcId": "vpc-0ad72fa4db17073fe",
                            }
                        ],
                        "Placement": {
                            "AvailabilityZone": "ap-southeast-2b",
                            "GroupName": "",
                            "Tenancy": "default",
                        },
                        "PlatformDetails": "Linux/UNIX",
                        "PrivateDnsName": "ip-10-1-3-235.ap-southeast-2.compute.internal",
                        "PrivateDnsNameOptions": {
                            "EnableResourceNameDnsAAAARecord": False,
                            "EnableResourceNameDnsARecord": False,
                            "HostnameType": "ip-name",
                        },
                        "PrivateIpAddress": "10.1.3.235",
                        "ProductCodes": [],
                        "PublicDnsName": "",
                        "RootDeviceName": "/dev/xvda",
                        "RootDeviceType": "ebs",
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-0b40f73cba796211b",
                                "GroupName": "launch-wizard-2",
                            }
                        ],
                        "SourceDestCheck": True,
                        "State": {"Code": 16, "Name": "running"},
                        "StateTransitionReason": "",
                        "SubnetId": "subnet-032da126cc939a487",
                        "Tags": [{"Key": "Name", "Value": "Test-SSM05"}],
                        "UsageOperation": "RunInstances",
                        "UsageOperationUpdateTime": "2021-12-10T04:45:42+00:00",
                        "VirtualizationType": "hvm",
                        "VpcId": "vpc-0ad72fa4db17073fe",
                    },
                    "isAcquisitionRequired": True,
                },
                "statusCode": 200,
            },
            "StatusCode": 200,
        },
        "sfn": {
            "Id": "arn:aws:states:ap-southeast-2:123456789012:execution:Disk-Forensics-Acquisition-Function:98040929-e765-4b87-b679-3f66586b17de"
        },
    }

    # yield
    # print ('Testing Check Store-update Forensics Info Completed')
    def teardown():
        print("Testing Check Store-update Forensics Info Completed")

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
                            "S": "arn:aws:iam::123456789012:instance-profile/SSMDefaultRoleForPVREReporting"
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


get_item_fn = MagicMock(return_value=get_item_event())
update_item_fn = MagicMock(return_value=get_update_record_event())
put_item_fn = MagicMock(return_value={})


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("dynamodb"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.update_item = update_item_fn
    mockClient.get_item = get_item_fn
    mockClient.put_item = put_item_fn
    return mockClient


@mock.patch.dict(
    os.environ,
    {"AWS_REGION": "ap-southeast-2", "INSTANCE_TABLE_NAME": "table"},
)
def test_trigger_event():
    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection({})),
    ):
        ret = function_under_test(event, "")
        assert ret.get("statusCode") == 200
