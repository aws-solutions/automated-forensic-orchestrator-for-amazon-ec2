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

from ...src.common.awsapi_cached_client import AWSCachedClient, BotoSession
from ...src.acquisition import performInstanceSnapshot


@pytest.fixture()
def eb_event():
    return {"forensicId": "123", "forensicType": "DISK"}


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


create_snapshots_fn = MagicMock()
get_item_fn = MagicMock(return_value=get_item_event())
describe_snapshot_fn = MagicMock()
put_item_fn = MagicMock(return_value={})
update_item_fn = MagicMock(return_value=get_update_record_event())
assume_role_fn = MagicMock(return_value={})
transact_write_item_fn = MagicMock(return_value={})


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.put_item = MagicMock()
    mockClient.get_item = get_item_fn
    mockClient.create_snapshots = create_snapshots_fn
    mockClient.update_item = update_item_fn
    mockClient.transact_write_items = transact_write_item_fn
    mockClient.assume_role = assume_role_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_trigger_event():

    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "IsolationRequired": False,
                "forensicId": "bd934f76-d6eb-4bb0-a0c7-53592ee18de3",
                "instanceAccount": "100000000000000",
                "instanceInfo": {
                    "AmiLaunchIndex": 0,
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2021-11-23T18:41:34+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-0f6d9d7309f46daaa",
                            },
                        }
                    ],
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "ClientToken": "",
                    "CpuOptions": {"CoreCount": 1, "ThreadsPerCore": 1},
                    "EbsOptimized": False,
                    "EnaSupport": True,
                    "EnclaveOptions": {"Enabled": False},
                    "HibernationOptions": {"Configured": False},
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/SSM-Test-Instnace",
                        "Id": "AIPATSJUVGIT77T3MJTS2",
                    },
                    "ImageId": "ami-0bf8b986de7e3c7ce",
                    "InstanceId": "i-04a5fde997d49e225",
                    "InstanceType": "t2.micro",
                    "KeyName": "deena-101",
                    "LaunchTime": "2021-11-23T18:41:33+00:00",
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
                                "AttachTime": "2021-11-23T18:41:33+00:00",
                                "AttachmentId": "eni-attach-0d4efbdffe93168c6",
                                "DeleteOnTermination": True,
                                "DeviceIndex": 0,
                                "NetworkCardIndex": 0,
                                "Status": "attached",
                            },
                            "Description": "Primary network interface",
                            "Groups": [
                                {
                                    "GroupId": "sg-0e9e80e72106216a4",
                                    "GroupName": "launch-wizard-4",
                                }
                            ],
                            "InterfaceType": "interface",
                            "Ipv6Addresses": [],
                            "MacAddress": "06:92:7d:6b:63:b0",
                            "NetworkInterfaceId": "eni-0e45a70096705b5d2",
                            "OwnerId": "123456789012",
                            "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                            "PrivateIpAddress": "10.1.3.102",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": True,
                                    "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                                    "PrivateIpAddress": "10.1.3.102",
                                }
                            ],
                            "SourceDestCheck": True,
                            "Status": "in-use",
                            "SubnetId": "subnet-038606b401271d4fb",
                            "VpcId": "vpc-08936c7ad3a7ae4d7",
                        }
                    ],
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-2b",
                        "GroupName": "",
                        "Tenancy": "default",
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                    "PrivateIpAddress": "10.1.3.102",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0e9e80e72106216a4",
                            "GroupName": "launch-wizard-4",
                        }
                    ],
                    "SourceDestCheck": True,
                    "State": {"Code": 16, "Name": "running"},
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-038606b401271d4fb",
                    "Tags": [{"Key": "Name", "Value": "SSM-San-sift"}],
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2021-11-23T18:41:33+00:00",
                    "VirtualizationType": "hvm",
                    "VpcId": "vpc-08936c7ad3a7ae4d7",
                },
                "isAcquisitionRequired": True,
            },
            "statusCode": 200,
        }
    }
    create_snapshots_fn.return_value = {"Snapshots": [{"VolumeId": 123}]}
    with patch.object(
        performInstanceSnapshot,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = performInstanceSnapshot.handler(event, context)
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_failure_on_snapshot():

    event = {
        "Payload": {
            "body": {
                "forensicType": "DISK",
                "IsolationRequired": False,
                "forensicId": "bd934f76-d6eb-4bb0-a0c7-53592ee18de3",
                "instanceAccount": "100000000000000",
                "instanceInfo": {
                    "AmiLaunchIndex": 0,
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2021-11-23T18:41:34+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-0f6d9d7309f46daaa",
                            },
                        }
                    ],
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "ClientToken": "",
                    "CpuOptions": {"CoreCount": 1, "ThreadsPerCore": 1},
                    "EbsOptimized": False,
                    "EnaSupport": True,
                    "EnclaveOptions": {"Enabled": False},
                    "HibernationOptions": {"Configured": False},
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::123456789012:instance-profile/SSM-Test-Instnace",
                        "Id": "AIPATSJUVGIT77T3MJTS2",
                    },
                    "ImageId": "ami-0bf8b986de7e3c7ce",
                    "InstanceId": "i-04a5fde997d49e225",
                    "InstanceType": "t2.micro",
                    "KeyName": "deena-101",
                    "LaunchTime": "2021-11-23T18:41:33+00:00",
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
                                "AttachTime": "2021-11-23T18:41:33+00:00",
                                "AttachmentId": "eni-attach-0d4efbdffe93168c6",
                                "DeleteOnTermination": True,
                                "DeviceIndex": 0,
                                "NetworkCardIndex": 0,
                                "Status": "attached",
                            },
                            "Description": "Primary network interface",
                            "Groups": [
                                {
                                    "GroupId": "sg-0e9e80e72106216a4",
                                    "GroupName": "launch-wizard-4",
                                }
                            ],
                            "InterfaceType": "interface",
                            "Ipv6Addresses": [],
                            "MacAddress": "06:92:7d:6b:63:b0",
                            "NetworkInterfaceId": "eni-0e45a70096705b5d2",
                            "OwnerId": "123456789012",
                            "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                            "PrivateIpAddress": "10.1.3.102",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": True,
                                    "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                                    "PrivateIpAddress": "10.1.3.102",
                                }
                            ],
                            "SourceDestCheck": True,
                            "Status": "in-use",
                            "SubnetId": "subnet-038606b401271d4fb",
                            "VpcId": "vpc-08936c7ad3a7ae4d7",
                        }
                    ],
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-2b",
                        "GroupName": "",
                        "Tenancy": "default",
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "PrivateDnsName": "ip-10-1-3-102.ap-southeast-2.compute.internal",
                    "PrivateIpAddress": "10.1.3.102",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0e9e80e72106216a4",
                            "GroupName": "launch-wizard-4",
                        }
                    ],
                    "SourceDestCheck": True,
                    "State": {"Code": 16, "Name": "running"},
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-038606b401271d4fb",
                    "Tags": [{"Key": "Name", "Value": "SSM-San-sift"}],
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2021-11-23T18:41:33+00:00",
                    "VirtualizationType": "hvm",
                    "VpcId": "vpc-08936c7ad3a7ae4d7",
                },
                "isAcquisitionRequired": True,
            },
            "statusCode": 200,
        }
    }
    create_snapshots_fn.return_value = {"Snapshots": [{"VolumeId": 123}]}
    with patch.object(
        performInstanceSnapshot,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        create_snapshots_fn.side_effect = Exception("Underlying service error")
        performInstanceSnapshot.handler(event, context)
        assert execinfo.type == Exception

        create_snapshots_fn.reset_mock()
