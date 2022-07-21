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

from ..src.common.awsapi_cached_client import (
    AWSCachedClient,
    BotoSession,
    create_aws_client,
)

# from ..src.triage  import handler as function_under_test
# from ..src.triage.app import lambda_handler as function_under_test
from ..src.triage import app


@pytest.fixture()
def eb_event():
    return {
        "version": "0",
        "id": "65931ccc-2c13-2661-a0ee-7d41466879a0",
        "detail-type": "Security Hub Findings - Custom Action",
        "source": "aws.securityhub",
        "account": "123456789012",
        "time": "2021-11-29T05:45:13Z",
        "region": "ap-southeast-2",
        "resources": [
            "arn:aws:securityhub:ap-southeast-2:123456789012:action/custom/ForensicTriageAction"
        ],
        "detail": {
            "actionName": "Forensic Triage ",
            "actionDescription": "Trigger Forensic Triage Action",
            "findings": [
                {
                    "ProductArn": "arn:aws:securityhub:ap-southeast-2::product/aws/securityhub",
                    "Types": [
                        "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
                    ],
                    "Description": "This control checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The control passes if HttpTokens is set to required for IMDSv2. The control fails if HttpTokens is set to optional.",
                    "Compliance": {"Status": "FAILED"},
                    "ProductName": "Security Hub",
                    "FirstObservedAt": "2021-11-29T05:35:37.063Z",
                    "CreatedAt": "2021-11-29T05:35:37.063Z",
                    "LastObservedAt": "2021-11-29T05:35:42.710Z",
                    "CompanyName": "AWS",
                    "FindingProviderFields": {
                        "Types": [
                            "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
                        ],
                        "Severity": {
                            "Normalized": 70,
                            "Label": "HIGH",
                            "Product": 70,
                            "Original": "HIGH",
                        },
                    },
                    "ProductFields": {
                        "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                        "StandardsSubscriptionArn": "arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0",
                        "ControlId": "EC2.8",
                        "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/EC2.8/remediation",
                        "RelatedAWSResources:0/name": "securityhub-ec2-imdsv2-check-2e9b12a3",
                        "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                        "StandardsControlArn": "arn:aws:securityhub:ap-southeast-2:123456789012:control/aws-foundational-security-best-practices/v/1.0.0/EC2.8",
                        "aws/securityhub/ProductName": "Security Hub",
                        "aws/securityhub/CompanyName": "AWS",
                        "Resources:0/Id": "arn:aws:ec2:ap-southeast-2:123456789012:instance/i-0bf2bf6b175654c6e",
                        "aws/securityhub/FindingId": "arn:aws:securityhub:ap-southeast-2::product/aws/securityhub/arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.8/finding/482e8524-4f22-4a27-9dba-b8a582f24529",
                    },
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For directions on how to fix this issue, consult the AWS Security Hub Foundational Security Best Practices documentation.",
                            "Url": "https://docs.aws.amazon.com/console/securityhub/EC2.8/remediation",
                        }
                    },
                    "SchemaVersion": "2018-10-08",
                    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.8",
                    "RecordState": "ACTIVE",
                    "Title": "EC2.8 EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
                    "Workflow": {"Status": "NEW"},
                    "Severity": {
                        "Normalized": 70,
                        "Label": "HIGH",
                        "Product": 70,
                        "Original": "HIGH",
                    },
                    "UpdatedAt": "2021-11-29T05:35:37.063Z",
                    "WorkflowState": "NEW",
                    "AwsAccountId": "123456789012",
                    "Region": "ap-southeast-2",
                    "Id": "arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.8/finding/482e8524-4f22-4a27-9dba-b8a582f24529",
                    "Resources": [
                        {
                            "Partition": "aws",
                            "Type": "AwsEc2Instance",
                            "Details": {
                                "AwsEc2Instance": {
                                    "KeyName": "deena-101",
                                    "VpcId": "vpc-08936c7ad3a7ae4d7",
                                    "NetworkInterfaces": [
                                        {
                                            "NetworkInterfaceId": "eni-0c6458cc791f3a399"
                                        }
                                    ],
                                    "ImageId": "ami-0c9f90931dd48d1f2",
                                    "SubnetId": "subnet-038606b401271d4fb",
                                    "LaunchedAt": "2021-11-24T02:10:50.000Z",
                                    "IamInstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/SSM-Test-Instnace",
                                }
                            },
                            "Region": "ap-southeast-2",
                            "Id": "arn:aws:ec2:ap-southeast-2:123456789012:instance/i-0bf2bf6b175654c6e",
                        }
                    ],
                }
            ],
        },
    }


def eb_invalid_event():
    return {
        "version": "0",
        "id": "65931ccc-2c13-2661-a0ee-7d41466879a0",
        "detail-type": "Security Hub Findings - Custom Action",
        "source": "aws.securityhub",
        "account": "123456789012",
        "time": "2021-11-29T05:45:13Z",
        "region": "ap-southeast-2",
        "resources": [
            "arn:aws:securityhub:ap-southeast-2:123456789012:action/custom/ForensicNotTriageAction"
        ],
        "detail": {
            "actionName": "Forensic Triage ",
            "actionDescription": "Trigger Forensic Triage Action",
            "findings": [
                {
                    "ProductArn": "arn:aws:securityhub:ap-southeast-2::product/aws/securityhub",
                    "Types": [
                        "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
                    ],
                    "Description": "This control checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The control passes if HttpTokens is set to required for IMDSv2. The control fails if HttpTokens is set to optional.",
                    "Compliance": {"Status": "FAILED"},
                    "ProductName": "Security Hub",
                    "FirstObservedAt": "2021-11-29T05:35:37.063Z",
                    "CreatedAt": "2021-11-29T05:35:37.063Z",
                    "LastObservedAt": "2021-11-29T05:35:42.710Z",
                    "CompanyName": "AWS",
                    "FindingProviderFields": {
                        "Types": [
                            "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
                        ],
                        "Severity": {
                            "Normalized": 70,
                            "Label": "HIGH",
                            "Product": 70,
                            "Original": "HIGH",
                        },
                    },
                    "ProductFields": {
                        "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                        "StandardsSubscriptionArn": "arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0",
                        "ControlId": "EC2.8",
                        "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/EC2.8/remediation",
                        "RelatedAWSResources:0/name": "securityhub-ec2-imdsv2-check-2e9b12a3",
                        "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                        "StandardsControlArn": "arn:aws:securityhub:ap-southeast-2:123456789012:control/aws-foundational-security-best-practices/v/1.0.0/EC2.8",
                        "aws/securityhub/ProductName": "Security Hub",
                        "aws/securityhub/CompanyName": "AWS",
                        "Resources:0/Id": "arn:aws:ec2:ap-southeast-2:123456789012:instance/i-0bf2bf6b175654c6e",
                        "aws/securityhub/FindingId": "arn:aws:securityhub:ap-southeast-2::product/aws/securityhub/arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.8/finding/482e8524-4f22-4a27-9dba-b8a582f24529",
                    },
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For directions on how to fix this issue, consult the AWS Security Hub Foundational Security Best Practices documentation.",
                            "Url": "https://docs.aws.amazon.com/console/securityhub/EC2.8/remediation",
                        }
                    },
                    "SchemaVersion": "2018-10-08",
                    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.8",
                    "RecordState": "ACTIVE",
                    "Title": "EC2.8 EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
                    "Workflow": {"Status": "NEW"},
                    "Severity": {
                        "Normalized": 70,
                        "Label": "HIGH",
                        "Product": 70,
                        "Original": "HIGH",
                    },
                    "UpdatedAt": "2021-11-29T05:35:37.063Z",
                    "WorkflowState": "NEW",
                    "AwsAccountId": "123456789012",
                    "Region": "ap-southeast-2",
                    "Id": "arn:aws:securityhub:ap-southeast-2:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.8/finding/482e8524-4f22-4a27-9dba-b8a582f24529",
                    "Resources": [
                        {
                            "Partition": "aws",
                            "Type": "AwsEc2Instance",
                            "Details": {
                                "AwsEc2Instance": {
                                    "KeyName": "deena-101",
                                    "VpcId": "vpc-08936c7ad3a7ae4d7",
                                    "NetworkInterfaces": [
                                        {
                                            "NetworkInterfaceId": "eni-0c6458cc791f3a399"
                                        }
                                    ],
                                    "ImageId": "ami-0c9f90931dd48d1f2",
                                    "SubnetId": "subnet-038606b401271d4fb",
                                    "LaunchedAt": "2021-11-24T02:10:50.000Z",
                                    "IamInstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/SSM-Test-Instnace",
                                }
                            },
                            "Region": "ap-southeast-2",
                            "Id": "arn:aws:ec2:ap-southeast-2:123456789012:instance/i-0bf2bf6b175654c6e",
                        }
                    ],
                }
            ],
        },
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


put_item_fn = MagicMock(return_value={})
transact_write_item_fn = MagicMock(return_value={})
get_item_fn = MagicMock(return_value=get_item_event())
update_item_fn = MagicMock(return_value=get_update_record_event())


def mock_connection(describe_instance_fn):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    # mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.describe_instances = describe_instance_fn
    # describe_instance_fn.return_value = ec_response
    mockClient.put_item = put_item_fn
    mockClient.get_item = get_item_fn
    mockClient.update_item = update_item_fn
    mockClient.transact_write_items = transact_write_item_fn

    return mockClient


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_invalid_trigger_event():
    invalid_event = eb_invalid_event()
    context = MagicMock()
    context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
    with patch.object(
        app,
        "create_aws_client",
        Mock(
            return_value=mock_connection(
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "Tags": [
                                        {
                                            "Key": "random_key",
                                            "Value": "random_value",
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            )
        ),
    ), pytest.raises(Exception) as execinfo:
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        app.lambda_handler(invalid_event, context)
    assert execinfo.type == ValueError
    transact_write_item_fn.assert_called()


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_error_retriving_instance_info(eb_event):
    context = MagicMock()
    context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
    describe_instance_fn = MagicMock()
    describe_instance_fn.side_effect = Exception("AWS ERROR!")
    with patch.object(
        app,
        "create_aws_client",
        Mock(return_value=mock_connection(describe_instance_fn)),
    ), pytest.raises(Exception) as execinfo:
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        app.lambda_handler(eb_event, context)
    assert execinfo.type == Exception
    describe_instance_fn.reset_mock()
    put_item_fn.assert_called()


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_acquisition_tagged_not_required(eb_event):
    with patch.object(
        app,
        "create_aws_client",
        Mock(
            return_value=mock_connection(
                lambda InstanceIds: {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "Tags": [
                                        {
                                            "Key": "random_key",
                                            "Value": "random_value",
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            )
        ),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = app.lambda_handler(eb_event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isAcquisitionRequired") == True


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_acquisition_tagged_not_required_with_specific_false(eb_event):
    with patch.object(
        app,
        "create_aws_client",
        Mock(
            return_value=mock_connection(
                lambda InstanceIds: {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "Tags": [
                                        {
                                            "Key": "IsTriageRequired",
                                            "Value": "False",
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            )
        ),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        assert os.environ["AWS_REGION"] == "ap-southeast-2"
        ret = app.lambda_handler(eb_event, context)
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isAcquisitionRequired") == False


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    },
)
def test_triage_required(eb_event):
    # given
    with patch.object(
        app,
        "create_aws_client",
        Mock(
            return_value=mock_connection(
                lambda InstanceIds: {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "Tags": [
                                        {
                                            "Key": "IsTriageRequired",
                                            "Value": "True",
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            )
        ),
    ):
        context = MagicMock()
        context.invoked_function_arn = "arn:aws:lambda:ap-southeast-2:123456789012:function:ForensicSolutionStack-forensicsDiskAcquisitionshar-wXRzDyfmUixV"
        # when
        ret = app.lambda_handler(eb_event, context)
        # then
        assert ret.get("statusCode") == 200
        assert ret.get("body").get("isAcquisitionRequired") == True
