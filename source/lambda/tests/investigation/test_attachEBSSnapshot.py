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
from ...src.investigation import attachEBSSnapShot


@pytest.fixture(scope="function", autouse=True)
@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "VOLUME_ENCRYPTION_KEY_ID": "key_1",
        "VOLUME_MOUNT_CMD_ID": "DOC_1",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def setupevent(request):

    print("Testing Attach Snapshot Started ")

    print(os.environ["AWS_CODEGURU_PROFILER_GROUP_NAME"])
    # yield
    # print ('Testing Check Forensic Investigation SSM Command Status Checker Completed')
    def teardown():
        print("Testing Attach Snapshot Completed")

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
                },
                {
                    "M": {
                        "volumeId": {"S": "vol-0d7a6f5a15ef95ea9"},
                        "snapshotId": {"S": "snap-04eb0248c744509d2"},
                        "awsAccountId": {"S": "123456789012"},
                        "region": {"S": "ap-southeast-2"},
                        "volumeSize": {"N": "8"},
                    }
                },
                {
                    "M": {
                        "volumeId": {"S": "vol-0d7a6f5a15ef95ea9"},
                        "snapshotId": {"S": "snap-05fa59e7472871819"},
                        "awsAccountId": {"S": "123456789012"},
                        "region": {"S": "ap-southeast-2"},
                        "volumeSize": {"N": "8"},
                    }
                },
            ]
        },
    }


def get_update_record_event():
    return {"Attributes": forensic_record()}


def get_item_event():
    return {"Item": forensic_record()}


def describe_instances():
    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "AmiLaunchIndex": 0,
                        "Architecture": "x86_64",
                        "BlockDeviceMappings": [
                            {
                                "DeviceName": "/dev/xvda",
                                "Ebs": {
                                    "AttachTime": "2022-01-08T09:06:50+00:00",
                                    "DeleteOnTermination": True,
                                    "Status": "attached",
                                    "VolumeId": "vol-092ba93c64d99541a",
                                },
                            },
                            {
                                "DeviceName": "/dev/sdb",
                                "Ebs": {
                                    "AttachTime": "2022-01-08T09:06:50+00:00",
                                    "DeleteOnTermination": True,
                                    "Status": "attached",
                                    "VolumeId": "vol-0d6c6db7810ec93d3",
                                },
                            },
                            {
                                "DeviceName": "/dev/sdc",
                                "Ebs": {
                                    "AttachTime": "2022-01-08T09:06:50+00:00",
                                    "DeleteOnTermination": True,
                                    "Status": "attached",
                                    "VolumeId": "vol-07e7d0f2549e69870",
                                },
                            },
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
                        "ImageId": "ami-0bd2230cfb28832f7",
                        "InstanceId": "i-0c9ef942fb2d9e4da",
                        "InstanceType": "t2.small",
                        "KeyName": "deena-101",
                        "LaunchTime": "2022-01-08T09:06:49+00:00",
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
                                    "AttachTime": "2022-01-08T09:06:49+00:00",
                                    "AttachmentId": "eni-attach-0842732d286e0e49f",
                                    "DeleteOnTermination": True,
                                    "DeviceIndex": 0,
                                    "NetworkCardIndex": 0,
                                    "Status": "attached",
                                },
                                "Description": "Primary network interface",
                                "Groups": [
                                    {
                                        "GroupId": "sg-0a9da96bff492ec1d",
                                        "GroupName": "launch-wizard-2",
                                    }
                                ],
                                "InterfaceType": "interface",
                                "Ipv6Addresses": [],
                                "MacAddress": "02:54:7d:7b:b6:ec",
                                "NetworkInterfaceId": "eni-07df643683c680152",
                                "OwnerId": "123456789012",
                                "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                                "PrivateIpAddress": "10.1.2.251",
                                "PrivateIpAddresses": [
                                    {
                                        "Primary": True,
                                        "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                                        "PrivateIpAddress": "10.1.2.251",
                                    }
                                ],
                                "SourceDestCheck": True,
                                "Status": "in-use",
                                "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                                "VpcId": "vpc-0f7cf4b8c7437854e",
                            }
                        ],
                        "Placement": {
                            "AvailabilityZone": "ap-southeast-2a",
                            "GroupName": "",
                            "Tenancy": "default",
                        },
                        "PlatformDetails": "Linux/UNIX",
                        "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                        "PrivateDnsNameOptions": {
                            "EnableResourceNameDnsAAAARecord": False,
                            "EnableResourceNameDnsARecord": True,
                            "HostnameType": "ip-name",
                        },
                        "PrivateIpAddress": "10.1.2.251",
                        "ProductCodes": [],
                        "PublicDnsName": "",
                        "RootDeviceName": "/dev/xvda",
                        "RootDeviceType": "ebs",
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-0a9da96bff492ec1d",
                                "GroupName": "launch-wizard-2",
                            }
                        ],
                        "SourceDestCheck": True,
                        "State": {"Code": 16, "Name": "running"},
                        "StateTransitionReason": "",
                        "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                        "Tags": [
                            {"Key": "Name", "Value": "SSM-Test-Instance"}
                        ],
                        "UsageOperation": "RunInstances",
                        "UsageOperationUpdateTime": "2022-01-08T09:06:49+00:00",
                        "VirtualizationType": "hvm",
                        "VpcId": "vpc-0f7cf4b8c7437854e",
                    }
                ]
            }
        ]
    }


get_item_fn = MagicMock(return_value=get_item_event())
update_item_fn = MagicMock()
create_volume_fn = MagicMock()
send_command_fn = MagicMock()
create_volume_fn.return_value = {"VolumeId": "v1"}
describe_instances_fn = MagicMock(return_value=describe_instances())
transact_write_item_fn = MagicMock(return_value={})
put_item_fn = MagicMock(return_value={})


def mock_connection(response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = MagicMock()
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = describe_instances_fn
    mockClient.update_item = update_item_fn
    mockClient.get_item = get_item_fn
    mockClient.get_waiter = MagicMock()
    mockClient.create_volume = create_volume_fn
    mockClient.send_command = send_command_fn
    mockClient.transact_write_items = transact_write_item_fn
    mockClient.put_item = MagicMock()
    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "VOLUME_ENCRYPTION_KEY_ID": "key_1",
        "VOLUME_MOUNT_CMD_ID": "DOC_1",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def test_trigger_event():
    event = {
        "ExecutedVersion": "$LATEST",
        "Payload": {
            "body": {
                "ForensicInvestigationInstanceId": "i-0d2a08080cb03bb93",
                "IsolationRequired": False,
                "SecurityGroup": "sg-080766f662ffdf836",
                "forensicId": "c8b6344c-5c14-4b49-a5d7-38dfb1de5a04",
                "forensicInvestigationInstance": {"SSM_Status": "SUCCEEDED"},
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceInfo": {
                    "AmiLaunchIndex": 0,
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-092ba93c64d99541a",
                            },
                        },
                        {
                            "DeviceName": "/dev/sdb",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-0d6c6db7810ec93d3",
                            },
                        },
                        {
                            "DeviceName": "/dev/sdc",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-07e7d0f2549e69870",
                            },
                        },
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
                    "ImageId": "ami-0bd2230cfb28832f7",
                    "InstanceId": "i-0c9ef942fb2d9e4da",
                    "InstanceType": "t2.small",
                    "KeyName": "deena-101",
                    "LaunchTime": "2022-01-08T09:06:49+00:00",
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
                                "AttachTime": "2022-01-08T09:06:49+00:00",
                                "AttachmentId": "eni-attach-0842732d286e0e49f",
                                "DeleteOnTermination": True,
                                "DeviceIndex": 0,
                                "NetworkCardIndex": 0,
                                "Status": "attached",
                            },
                            "Description": "Primary network interface",
                            "Groups": [
                                {
                                    "GroupId": "sg-0a9da96bff492ec1d",
                                    "GroupName": "launch-wizard-2",
                                }
                            ],
                            "InterfaceType": "interface",
                            "Ipv6Addresses": [],
                            "MacAddress": "02:54:7d:7b:b6:ec",
                            "NetworkInterfaceId": "eni-07df643683c680152",
                            "OwnerId": "123456789012",
                            "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                            "PrivateIpAddress": "10.1.2.251",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": True,
                                    "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                                    "PrivateIpAddress": "10.1.2.251",
                                }
                            ],
                            "SourceDestCheck": True,
                            "Status": "in-use",
                            "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                            "VpcId": "vpc-0f7cf4b8c7437854e",
                        }
                    ],
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-2a",
                        "GroupName": "",
                        "Tenancy": "default",
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                    "PrivateDnsNameOptions": {
                        "EnableResourceNameDnsAAAARecord": False,
                        "EnableResourceNameDnsARecord": True,
                        "HostnameType": "ip-name",
                    },
                    "PrivateIpAddress": "10.1.2.251",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "RootDeviceName": "/dev/xvda",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0a9da96bff492ec1d",
                            "GroupName": "launch-wizard-2",
                        }
                    ],
                    "SourceDestCheck": True,
                    "State": {"Code": 16, "Name": "running"},
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                    "Tags": [{"Key": "Name", "Value": "SSM-Test-Instance"}],
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2022-01-08T09:06:49+00:00",
                    "VirtualizationType": "hvm",
                    "VpcId": "vpc-0f7cf4b8c7437854e",
                },
                "isAcquisitionRequired": True,
                "isSnapShotComplete": True,
                "snapshotArtifactMap": {
                    "snap-018eebb9524445e0b": "a0b18a74-c2f1-4309-b17d-c8253b01ab29",
                    "snap-04eb0248c744509d2": "b0b18a74-c2f1-4309-b17d-c8253b01ab29",
                    "snap-05fa59e7472871819": "c0b18a74-c2f1-4309-b17d-c8253b01ab29",
                },
                "snapshotIds": [
                    "snap-018eebb9524445e0b",
                    "snap-04eb0248c744509d2",
                    "snap-05fa59e7472871819",
                ],
                "snapshotIdsShared": [
                    "snap-018eebb9524445e0b",
                    "snap-04eb0248c744509d2",
                    "snap-05fa59e7472871819",
                ],
            },
            "statusCode": 200,
        },
        "SdkHttpMetadata": {
            "AllHttpHeaders": {
                "X-Amz-Executed-Version": ["$LATEST"],
                "x-amzn-Remapped-Content-Length": ["0"],
                "Connection": ["keep-alive"],
                "x-amzn-RequestId": ["b0fdab15-e55c-462d-8460-cec2ffb7d028"],
                "Content-Length": ["3733"],
                "Date": ["Tue, 11 Jan 2022 05:38:18 GMT"],
                "X-Amzn-Trace-Id": [
                    "root=1-61dd174b-4c88672a14daa79e99dbd0f8;parent=30c8f9bee390ee20;sampled=1"
                ],
                "Content-Type": ["application/json"],
            },
            "HttpHeaders": {
                "Connection": "keep-alive",
                "Content-Length": "3733",
                "Content-Type": "application/json",
                "Date": "Tue, 11 Jan 2022 05:38:18 GMT",
                "X-Amz-Executed-Version": "$LATEST",
                "x-amzn-Remapped-Content-Length": "0",
                "x-amzn-RequestId": "b0fdab15-e55c-462d-8460-cec2ffb7d028",
                "X-Amzn-Trace-Id": "root=1-61dd174b-4c88672a14daa79e99dbd0f8;parent=30c8f9bee390ee20;sampled=1",
            },
            "HttpStatusCode": 200,
        },
        "SdkResponseMetadata": {
            "RequestId": "b0fdab15-e55c-462d-8460-cec2ffb7d028"
        },
        "StatusCode": 200,
    }
    with patch.object(
        attachEBSSnapShot,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = attachEBSSnapShot.handler(event, context)
        print(ret)
        first_attached_volume_info = ret.get("body").get(
            "forensicAttachedVolumeInfo"
        )[0]

        assert ret.get("statusCode") == 200
        assert len(ret.get("body").get("forensicAttachedVolumeInfo")) == 3
        assert (
            ret.get("body").get("forensicId")
            == "c8b6344c-5c14-4b49-a5d7-38dfb1de5a04"
        )
        assert first_attached_volume_info.get("attachedVolumeId") == "v1"
        assert first_attached_volume_info.get("attachedDevice") == "/dev/sdg"
        assert (
            first_attached_volume_info.get("instanceVolumeMountingPoint")
            == "/data/dev/xvdg1"
        )


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "VOLUME_ENCRYPTION_KEY_ID": "key_1",
        "VOLUME_MOUNT_CMD_ID": "DOC_1",
        "AWS_CODEGURU_PROFILER_GROUP_NAME": "Code-Profiler",
    },
)
def test_trigger_encounter_error_when_update_volume():
    event = {
        "ExecutedVersion": "$LATEST",
        "Payload": {
            "body": {
                "ForensicInvestigationInstanceId": "i-0d2a08080cb03bb93",
                "IsolationRequired": False,
                "SecurityGroup": "sg-080766f662ffdf836",
                "forensicId": "c8b6344c-5c14-4b49-a5d7-38dfb1de5a04",
                "forensicInvestigationInstance": {"SSM_Status": "SUCCEEDED"},
                "forensicType": "DISK",
                "instanceAccount": "123456789012",
                "instanceInfo": {
                    "AmiLaunchIndex": 0,
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-092ba93c64d99541a",
                            },
                        },
                        {
                            "DeviceName": "/dev/sdb",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-0d6c6db7810ec93d3",
                            },
                        },
                        {
                            "DeviceName": "/dev/sdc",
                            "Ebs": {
                                "AttachTime": "2022-01-08T09:06:50+00:00",
                                "DeleteOnTermination": True,
                                "Status": "attached",
                                "VolumeId": "vol-07e7d0f2549e69870",
                            },
                        },
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
                    "ImageId": "ami-0bd2230cfb28832f7",
                    "InstanceId": "i-0c9ef942fb2d9e4da",
                    "InstanceType": "t2.small",
                    "KeyName": "deena-101",
                    "LaunchTime": "2022-01-08T09:06:49+00:00",
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
                                "AttachTime": "2022-01-08T09:06:49+00:00",
                                "AttachmentId": "eni-attach-0842732d286e0e49f",
                                "DeleteOnTermination": True,
                                "DeviceIndex": 0,
                                "NetworkCardIndex": 0,
                                "Status": "attached",
                            },
                            "Description": "Primary network interface",
                            "Groups": [
                                {
                                    "GroupId": "sg-0a9da96bff492ec1d",
                                    "GroupName": "launch-wizard-2",
                                }
                            ],
                            "InterfaceType": "interface",
                            "Ipv6Addresses": [],
                            "MacAddress": "02:54:7d:7b:b6:ec",
                            "NetworkInterfaceId": "eni-07df643683c680152",
                            "OwnerId": "123456789012",
                            "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                            "PrivateIpAddress": "10.1.2.251",
                            "PrivateIpAddresses": [
                                {
                                    "Primary": True,
                                    "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                                    "PrivateIpAddress": "10.1.2.251",
                                }
                            ],
                            "SourceDestCheck": True,
                            "Status": "in-use",
                            "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                            "VpcId": "vpc-0f7cf4b8c7437854e",
                        }
                    ],
                    "Placement": {
                        "AvailabilityZone": "ap-southeast-2a",
                        "GroupName": "",
                        "Tenancy": "default",
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "PrivateDnsName": "ip-10-1-2-251.ap-southeast-2.compute.internal",
                    "PrivateDnsNameOptions": {
                        "EnableResourceNameDnsAAAARecord": False,
                        "EnableResourceNameDnsARecord": True,
                        "HostnameType": "ip-name",
                    },
                    "PrivateIpAddress": "10.1.2.251",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "RootDeviceName": "/dev/xvda",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0a9da96bff492ec1d",
                            "GroupName": "launch-wizard-2",
                        }
                    ],
                    "SourceDestCheck": True,
                    "State": {"Code": 16, "Name": "running"},
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0b3ab4f31cb0d6ff5",
                    "Tags": [{"Key": "Name", "Value": "SSM-Test-Instance"}],
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2022-01-08T09:06:49+00:00",
                    "VirtualizationType": "hvm",
                    "VpcId": "vpc-0f7cf4b8c7437854e",
                },
                "isAcquisitionRequired": True,
                "isSnapShotComplete": True,
                "snapshotArtifactMap": {
                    "snap-057aaf029fede01e2": "a0b18a74-c2f1-4309-b17d-c8253b01ab29",
                    "snap-04eb0248c744509d2": "b0b18a74-c2f1-4309-b17d-c8253b01ab29",
                    "snap-05fa59e7472871819": "c0b18a74-c2f1-4309-b17d-c8253b01ab29",
                },
                "snapshotIds": [
                    "snap-057aaf029fede01e2",
                    "snap-04eb0248c744509d2",
                    "snap-05fa59e7472871819",
                ],
                "snapshotIdsShared": [
                    "snap-057aaf029fede01e2",
                    "snap-04eb0248c744509d2",
                    "snap-05fa59e7472871819",
                ],
            },
            "statusCode": 200,
        },
        "SdkHttpMetadata": {
            "AllHttpHeaders": {
                "X-Amz-Executed-Version": ["$LATEST"],
                "x-amzn-Remapped-Content-Length": ["0"],
                "Connection": ["keep-alive"],
                "x-amzn-RequestId": ["b0fdab15-e55c-462d-8460-cec2ffb7d028"],
                "Content-Length": ["3733"],
                "Date": ["Tue, 11 Jan 2022 05:38:18 GMT"],
                "X-Amzn-Trace-Id": [
                    "root=1-61dd174b-4c88672a14daa79e99dbd0f8;parent=30c8f9bee390ee20;sampled=1"
                ],
                "Content-Type": ["application/json"],
            },
            "HttpHeaders": {
                "Connection": "keep-alive",
                "Content-Length": "3733",
                "Content-Type": "application/json",
                "Date": "Tue, 11 Jan 2022 05:38:18 GMT",
                "X-Amz-Executed-Version": "$LATEST",
                "x-amzn-Remapped-Content-Length": "0",
                "x-amzn-RequestId": "b0fdab15-e55c-462d-8460-cec2ffb7d028",
                "X-Amzn-Trace-Id": "root=1-61dd174b-4c88672a14daa79e99dbd0f8;parent=30c8f9bee390ee20;sampled=1",
            },
            "HttpStatusCode": 200,
        },
        "SdkResponseMetadata": {
            "RequestId": "b0fdab15-e55c-462d-8460-cec2ffb7d028"
        },
        "StatusCode": 200,
    }
    create_volume_fn.side_effect = Exception("Underlying service error")
    with patch.object(
        attachEBSSnapShot,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = attachEBSSnapShot.handler(event, "")
        assert execinfo.type == Exception
        update_item_fn.assert_called()
        create_volume_fn.reset_mock()
