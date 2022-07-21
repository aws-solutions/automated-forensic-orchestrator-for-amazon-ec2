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
from ...src.isolation import isolateEc2

modify_snapshot_attribute_fn = MagicMock()

modify_snapshot_attribute_fn.return_value = (
    lambda Attribute, DryRun, UserIds, SnapshotId, OperationType, CreateVolumePermission: {}
)

modify_network_interface_attribute_fn = MagicMock()

describe_security_groups_fn = MagicMock()


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


def get_update_record_event():
    return {"Attributes": forensic_record()}


create_security_group_fn = MagicMock()


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("sts"))
    mockClient.assume_role = MagicMock(return_value={})
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.put_item = MagicMock()
    mockClient.get_item = MagicMock(return_value=get_item_event())
    mockClient.update_item = MagicMock(return_value=get_update_record_event())
    mockClient.modify_snapshot_attribute = modify_snapshot_attribute_fn
    mockClient.revoke_security_group_egress = describe_security_groups_fn
    mockClient.describe_security_groups = describe_security_groups_fn
    mockClient.authorize_security_group_ingress = MagicMock()
    mockClient.modify_network_interface_attribute = (
        modify_network_interface_attribute_fn
    )

    mockClient.create_security_group = create_security_group_fn
    return mockClient


event = {
    "Payload": {
        "body": {
            "ForensicInstanceId": "i-0edaf8fbe9d9fe5db",
            "MemoryAcquisition": {
                "CommandId": "f39ff7b5-7cb2-4c4f-8864-2534f5785fa3",
                "CommandIdArtifactMap": {
                    "f39ff7b5-7cb2-4c4f-8864-2534f5785fa3": {
                        "Prefix": "memory/i-0edaf8fbe9d9fe5db/34d1bbcc-f1cd-4a7b-96f7-55a5dc632fd7",
                        "SSMDocumentName": "ForensicSolutionStack-ForensicSSMDBuilderStackSSMDocumentlinuxlimememoryacquisitionAF2BE0B7-rDFxf6FA5xK2",
                    }
                },
                "CommandInputArtifactId": "4d520810-918d-4401-80c6-1a26d8538e8a",
            },
            "SSM_STATUS": "SUCCEEDED",
            "forensicId": "34d1bbcc-f1cd-4a7b-96f7-55a5dc632fd7",
            "forensicType": "MEMORY",
            "instanceAccount": "123456789012",
            "instanceInfo": {
                "AmiLaunchIndex": 0,
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2021-07-22T02:19:43+00:00",
                            "DeleteOnTermination": True,
                            "Status": "attached",
                            "VolumeId": "vol-046787e846d70d266",
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
                    "Arn": "arn:aws:iam::123456789012:instance-profile/SSMDefaultRoleForPVREReporting",
                    "Id": "AIPAV6EF4S4HNBKH6RCBU",
                },
                "ImageId": "ami-0c9fe0dec6325a30c",
                "InstanceId": "i-0edaf8fbe9d9fe5db",
                "InstanceType": "t2.micro",
                "KeyName": "yang-test-pair-secondary-account-ec2",
                "LaunchTime": "2021-07-22T02:19:42+00:00",
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
                        "Association": {
                            "IpOwnerId": "amazon",
                            "PublicDnsName": "ec2-3-25-101-236.ap-southeast-2.compute.amazonaws.com",
                            "PublicIp": "3.25.101.236",
                        },
                        "Attachment": {
                            "AttachTime": "2021-07-22T02:19:42+00:00",
                            "AttachmentId": "eni-attach-01d8a69308fda7ad5",
                            "DeleteOnTermination": True,
                            "DeviceIndex": 0,
                            "NetworkCardIndex": 0,
                            "Status": "attached",
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupId": "sg-0d9db26a2073634f3",
                                "GroupName": "SSMVPCEndpoints",
                            },
                            {
                                "GroupId": "sg-0b0ffe55ff4cfd71d",
                                "GroupName": "launch-wizard-2",
                            },
                        ],
                        "InterfaceType": "interface",
                        "Ipv6Addresses": [],
                        "MacAddress": "06:22:e1:34:fe:74",
                        "NetworkInterfaceId": "eni-01ae5d0170ba7d60d",
                        "OwnerId": "123456789012",
                        "PrivateDnsName": "ip-172-31-42-48.ap-southeast-2.compute.internal",
                        "PrivateIpAddress": "172.31.42.48",
                        "PrivateIpAddresses": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-3-25-101-236.ap-southeast-2.compute.amazonaws.com",
                                    "PublicIp": "3.25.101.236",
                                },
                                "Primary": True,
                                "PrivateDnsName": "ip-172-31-42-48.ap-southeast-2.compute.internal",
                                "PrivateIpAddress": "172.31.42.48",
                            }
                        ],
                        "SourceDestCheck": True,
                        "Status": "in-use",
                        "SubnetId": "subnet-10f83158",
                        "VpcId": "vpc-d556a2b3",
                    }
                ],
                "Placement": {
                    "AvailabilityZone": "ap-southeast-2a",
                    "GroupName": "",
                    "Tenancy": "default",
                },
                "PlatformDetails": "Linux/UNIX",
                "PrivateDnsName": "ip-172-31-42-48.ap-southeast-2.compute.internal",
                "PrivateDnsNameOptions": {},
                "PrivateIpAddress": "172.31.42.48",
                "ProductCodes": [],
                "PublicDnsName": "ec2-3-25-101-236.ap-southeast-2.compute.amazonaws.com",
                "PublicIpAddress": "3.25.101.236",
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0d9db26a2073634f3",
                        "GroupName": "SSMVPCEndpoints",
                    },
                    {
                        "GroupId": "sg-0b0ffe55ff4cfd71d",
                        "GroupName": "launch-wizard-2",
                    },
                ],
                "SourceDestCheck": True,
                "State": {"Code": 16, "Name": "running"},
                "StateTransitionReason": "",
                "SubnetId": "subnet-10f83158",
                "Tags": [
                    {"Key": "Name", "Value": "FF_TEST_TARGET_DONOTDELETE"},
                    {"Key": "FF_TEST", "Value": "1"},
                ],
                "UsageOperation": "RunInstances",
                "UsageOperationUpdateTime": "2021-07-22T02:19:42+00:00",
                "VirtualizationType": "hvm",
                "VpcId": "vpc-d556a2b3",
            },
            "instanceRegion": "ap-southeast-2",
            "isAcquisitionRequired": True,
            "isIsolationNeeded": True,
            "isMemoryAcquisitionComplete": "TRUE",
        },
        "statusCode": 200,
    },
    "SdkResponseMetadata": {
        "RequestId": "cb758ea0-06ba-4cfd-93b0-01edc4f98191"
    },
    "StatusCode": 200,
}

event_multiple_eni = {
    "ExecutedVersion": "$LATEST",
    "Payload": {
        "body": {
            "ForensicInstanceId": "i-056eed1d049318beb",
            "forensicId": "8b242e75-b64a-42f3-9ac4-1b322cd3f974",
            "instanceAccount": "123456789012",
            "instanceInfo": {
                "AmiLaunchIndex": 0,
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {
                            "AttachTime": "2022-03-01T03:16:11+00:00",
                            "DeleteOnTermination": True,
                            "Status": "attached",
                            "VolumeId": "vol-060758da1b3875f5f",
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
                    "Arn": "arn:aws:iam::123456789012:instance-profile/SSMDefaultRoleForPVREReporting",
                    "Id": "AIPAV6EF4S4HNBKH6RCBU",
                },
                "ImageId": "ami-0b7dcd6e6fd797935",
                "InstanceId": "i-056eed1d049318beb",
                "InstanceType": "t2.micro",
                "KeyName": "yang-test-pair-secondary-account-ec2",
                "LaunchTime": "2022-03-01T03:16:10+00:00",
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
                            "AttachTime": "2022-03-07T04:51:34+00:00",
                            "AttachmentId": "eni-attach-0f56311ec8a14cc6c",
                            "DeleteOnTermination": False,
                            "DeviceIndex": 1,
                            "NetworkCardIndex": 0,
                            "Status": "attached",
                        },
                        "Description": "test ec12",
                        "Groups": [
                            {
                                "GroupId": "sg-02926e018422717c1",
                                "GroupName": "launch-wizard-3",
                            },
                            {
                                "GroupId": "sg-0dd1c5e192fe84008",
                                "GroupName": "default",
                            },
                        ],
                        "InterfaceType": "interface",
                        "Ipv6Addresses": [],
                        "MacAddress": "06:32:88:c4:96:d4",
                        "NetworkInterfaceId": "eni-02ee98da535b1debc",
                        "OwnerId": "123456789012",
                        "PrivateDnsName": "ip-10-0-0-94.ap-southeast-2.compute.internal",
                        "PrivateIpAddress": "10.0.0.94",
                        "PrivateIpAddresses": [
                            {
                                "Primary": True,
                                "PrivateDnsName": "ip-10-0-0-94.ap-southeast-2.compute.internal",
                                "PrivateIpAddress": "10.0.0.94",
                            }
                        ],
                        "SourceDestCheck": True,
                        "Status": "in-use",
                        "SubnetId": "subnet-09ec1f4a0336f6431",
                        "VpcId": "vpc-0d2c9296c3b26e396",
                    },
                    {
                        "Attachment": {
                            "AttachTime": "2022-03-01T03:16:10+00:00",
                            "AttachmentId": "eni-attach-033c43b5874b8945a",
                            "DeleteOnTermination": True,
                            "DeviceIndex": 0,
                            "NetworkCardIndex": 0,
                            "Status": "attached",
                        },
                        "Description": "Primary network interface",
                        "Groups": [
                            {
                                "GroupId": "sg-02926e018422717c1",
                                "GroupName": "launch-wizard-3",
                            }
                        ],
                        "InterfaceType": "interface",
                        "Ipv6Addresses": [],
                        "MacAddress": "06:ec:07:49:0d:64",
                        "NetworkInterfaceId": "eni-0260c6db84154be75",
                        "OwnerId": "123456789012",
                        "PrivateDnsName": "ip-10-0-0-102.ap-southeast-2.compute.internal",
                        "PrivateIpAddress": "10.0.0.102",
                        "PrivateIpAddresses": [
                            {
                                "Primary": True,
                                "PrivateDnsName": "ip-10-0-0-102.ap-southeast-2.compute.internal",
                                "PrivateIpAddress": "10.0.0.102",
                            }
                        ],
                        "SourceDestCheck": True,
                        "Status": "in-use",
                        "SubnetId": "subnet-09ec1f4a0336f6431",
                        "VpcId": "vpc-0d2c9296c3b26e396",
                    },
                ],
                "Placement": {
                    "AvailabilityZone": "ap-southeast-2a",
                    "GroupName": "",
                    "Tenancy": "default",
                },
                "PlatformDetails": "Linux/UNIX",
                "PrivateDnsName": "ip-10-0-0-102.ap-southeast-2.compute.internal",
                "PrivateDnsNameOptions": {
                    "EnableResourceNameDnsAAAARecord": False,
                    "EnableResourceNameDnsARecord": True,
                    "HostnameType": "ip-name",
                },
                "PrivateIpAddress": "10.0.0.102",
                "ProductCodes": [],
                "PublicDnsName": "",
                "RootDeviceName": "/dev/sda1",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupId": "sg-02926e018422717c1",
                        "GroupName": "launch-wizard-3",
                    }
                ],
                "SourceDestCheck": True,
                "State": {"Code": 16, "Name": "running"},
                "StateTransitionReason": "",
                "SubnetId": "subnet-09ec1f4a0336f6431",
                "Tags": [{"Key": "Name", "Value": "ForensicTestInstance"}],
                "UsageOperation": "RunInstances",
                "UsageOperationUpdateTime": "2022-03-01T03:16:10+00:00",
                "VirtualizationType": "hvm",
                "VpcId": "vpc-0d2c9296c3b26e396",
            },
            "instanceRegion": "ap-southeast-2",
            "isAcquisitionRequired": True,
            "isIsolationNeeded": True,
        },
        "statusCode": 200,
    },
    "SdkHttpMetadata": {
        "AllHttpHeaders": {
            "X-Amz-Executed-Version": ["$LATEST"],
            "x-amzn-Remapped-Content-Length": ["0"],
            "Connection": ["keep-alive"],
            "x-amzn-RequestId": ["5ec95386-874b-4d11-9d4b-62989a3e917a"],
            "Content-Length": ["4003"],
            "Date": ["Mon, 07 Mar 2022 04:55:07 GMT"],
            "X-Amzn-Trace-Id": [
                "root=1-62259024-cba163a0894da987b99de7fa;parent=248b429d6f029774;sampled=1"
            ],
            "Content-Type": ["application/json"],
        },
        "HttpHeaders": {
            "Connection": "keep-alive",
            "Content-Length": "4003",
            "Content-Type": "application/json",
            "Date": "Mon, 07 Mar 2022 04:55:07 GMT",
            "X-Amz-Executed-Version": "$LATEST",
            "x-amzn-Remapped-Content-Length": "0",
            "x-amzn-RequestId": "5ec95386-874b-4d11-9d4b-62989a3e917a",
            "X-Amzn-Trace-Id": "root=1-62259024-cba163a0894da987b99de7fa;parent=248b429d6f029774;sampled=1",
        },
        "HttpStatusCode": 200,
    },
    "SdkResponseMetadata": {
        "RequestId": "5ec95386-874b-4d11-9d4b-62989a3e917a"
    },
    "StatusCode": 200,
}


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_add_isolation_sg_for_first_time():

    modify_snapshot_attribute_fn.reset_mock()
    with patch.object(
        isolateEc2,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = isolateEc2.handler(event, context)
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_add_isolation_sg_when_sg_for_vpc_exists():

    modify_snapshot_attribute_fn.reset_mock()
    # all security group created
    describe_security_groups_fn.return_value = {
        "SecurityGroups": [
            {
                "Description": "Forensic isolation security group no rule",
                "GroupName": "Forensic-isolation-no-rule-vpc-d556a2b3",
                "IpPermissions": [],
                "OwnerId": "123456789012",
                "GroupId": "sg-11111",
            },
            {
                "Description": "Forensic isolation security group no rule",
                "GroupName": "Forensic-isolation-convertion-vpc-d556a2b3",
                "IpPermissions": [],
                "OwnerId": "123456789012",
                "GroupId": "sg-22222",
            },
        ]
    }
    modify_snapshot_attribute_fn.side_effect = Exception("AWS ERROR!")

    with patch.object(
        isolateEc2,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = isolateEc2.handler(event, context)
        # modify_snapshot_attribute_fn.assert_not_called()
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_add_isolation_sg_for_all_eni():

    create_security_group_fn.side_effect = [
        {"GroupId": "sg-coverting"},
        {"GroupId": "sg-no-rule"},
    ]

    with patch.object(
        isolateEc2,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        ret = isolateEc2.handler(event_multiple_eni, context)
        eni_a = "eni-0260c6db84154be75"
        modify_network_interface_attribute_fn.assert_called_with(
            NetworkInterfaceId=eni_a, Groups=["sg-no-rule"]
        )
        assert ret.get("statusCode") == 200


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_isolation_failed():
    modify_snapshot_attribute_fn.reset_mock()
    # all security group created
    describe_security_groups_fn.side_effect = Exception("AWS error")

    # modify_snapshot_attribute_fn.side_effect = Exception("AWS ERROR!")

    with patch.object(
        isolateEc2,
        "create_aws_client",
        Mock(return_value=mock_connection({})),
    ), pytest.raises(Exception) as execinfo:

        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        isolateEc2.handler(event, context)
        assert execinfo.type == Exception
        # modify_snapshot_attribute_fn.assert_not_called()
