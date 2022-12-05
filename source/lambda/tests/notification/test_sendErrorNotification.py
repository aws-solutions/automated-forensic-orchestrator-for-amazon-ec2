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

from ...src.notification import sendErrorNotification as app


def disk_event():
    return {
        "Error": "RuntimeError",
        "Cause": '{"errorMessage":"{\\"IsolationRequired\\": false, \\"forensicId\\": \\"6d7adfdc-09e1-46a2-a652-5ee4ca0bf752\\", \\"forensicType\\": \\"DISK\\", \\"instanceAccount\\": \\"123456789012\\", \\"instanceInfo\\": {\\"AmiLaunchIndex\\": 0, \\"Architecture\\": \\"x86_64\\", \\"BlockDeviceMappings\\": [{\\"DeviceName\\": \\"/dev/xvda\\", \\"Ebs\\": {\\"AttachTime\\": \\"2022-10-10T22:21:06+00:00\\", \\"DeleteOnTermination\\": true, \\"Status\\": \\"attached\\", \\"VolumeId\\": \\"vol-08b8d15458da173d2\\"}}], \\"CapacityReservationSpecification\\": {\\"CapacityReservationPreference\\": \\"open\\"}, \\"ClientToken\\": \\"\\", \\"CpuOptions\\": {\\"CoreCount\\": 1, \\"ThreadsPerCore\\": 2}, \\"EbsOptimized\\": true, \\"EnaSupport\\": true, \\"EnclaveOptions\\": {\\"Enabled\\": false}, \\"HibernationOptions\\": {\\"Configured\\": false}, \\"Hypervisor\\": \\"xen\\", \\"IamInstanceProfile\\": {\\"Arn\\": \\"arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup\\", \\"Id\\": \\"AIPASJROTNDTDUFEOXLUS\\"}, \\"ImageId\\": \\"ami-067e6178c7a211324\\", \\"InstanceId\\": \\"i-0945b8635eb44bdf8\\", \\"InstanceType\\": \\"t3.micro\\", \\"KeyName\\": \\"forensic-instance-key\\", \\"LaunchTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"MetadataOptions\\": {\\"HttpEndpoint\\": \\"enabled\\", \\"HttpProtocolIpv6\\": \\"disabled\\", \\"HttpPutResponseHopLimit\\": 1, \\"HttpTokens\\": \\"optional\\", \\"State\\": \\"applied\\"}, \\"Monitoring\\": {\\"State\\": \\"disabled\\"}, \\"NetworkInterfaces\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"3.26.130.132\\"}, \\"Attachment\\": {\\"AttachTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"AttachmentId\\": \\"eni-attach-0e6694a437de6e807\\", \\"DeleteOnTermination\\": true, \\"DeviceIndex\\": 0, \\"NetworkCardIndex\\": 0, \\"Status\\": \\"attached\\"}, \\"Description\\": \\"\\", \\"Groups\\": [{\\"GroupId\\": \\"sg-033ff377307390ea1\\", \\"GroupName\\": \\"default\\"}], \\"InterfaceType\\": \\"interface\\", \\"Ipv6Addresses\\": [], \\"MacAddress\\": \\"0a:e5:d2:cf:d6:74\\", \\"NetworkInterfaceId\\": \\"eni-032aa23bfdd68efd3\\", \\"OwnerId\\": \\"123456789012\\", \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.19.207\\", \\"PrivateIpAddresses\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"3.26.130.132\\"}, \\"Primary\\": true, \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.19.207\\"}], \\"SourceDestCheck\\": true, \\"Status\\": \\"in-use\\", \\"SubnetId\\": \\"subnet-08c39066d2b0c58fa\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}], \\"Placement\\": {\\"AvailabilityZone\\": \\"ap-southeast-2c\\", \\"GroupName\\": \\"\\", \\"Tenancy\\": \\"default\\"}, \\"PlatformDetails\\": \\"Linux/UNIX\\", \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateDnsNameOptions\\": {\\"EnableResourceNameDnsAAAARecord\\": false, \\"EnableResourceNameDnsARecord\\": true, \\"HostnameType\\": \\"ip-name\\"}, \\"PrivateIpAddress\\": \\"172.31.19.207\\", \\"ProductCodes\\": [], \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIpAddress\\": \\"3.26.130.132\\", \\"RootDeviceName\\": \\"/dev/xvda\\", \\"RootDeviceType\\": \\"ebs\\", \\"SecurityGroups\\": [{\\"GroupId\\": \\"sg-033ff377307390ea1\\", \\"GroupName\\": \\"default\\"}], \\"SourceDestCheck\\": true, \\"State\\": {\\"Code\\": 16, \\"Name\\": \\"running\\"}, \\"StateTransitionReason\\": \\"\\", \\"SubnetId\\": \\"subnet-08c39066d2b0c58fa\\", \\"Tags\\": [{\\"Key\\": \\"Name\\", \\"Value\\": \\"forensic-test-016\\"}], \\"UsageOperation\\": \\"RunInstances\\", \\"UsageOperationUpdateTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"VirtualizationType\\": \\"hvm\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}, \\"instanceRegion\\": \\"ap-southeast-2\\", \\"isAcquisitionRequired\\": true, \\"isIsolationNeeded\\": true, \\"instanceId\\": \\"i-0945b8635eb44bdf8\\", \\"errorName\\": \\"Error: creating snapshot for forensic id6d7adfdc-09e1-46a2-a652-5ee4ca0bf752\\", \\"errorDescription\\": \\"Error while creating snapshot DISK acquisition - Instance Snapshot\\", \\"errorPhase\\": \\"ACQUISITION\\", \\"errorComponentId\\": \\"performInstanceSnapshot\\", \\"errorComponentType\\": \\"Lambda\\", \\"eventData\\": \\"An error occurred (InvalidParameterValue) when calling the CreateSnapshots operation: There are no attached EBS-backed volumes on the instance id (i-0945b8635eb44bdf8).\\"}","errorType":"RuntimeError","requestId":"3471dac7-dc10-4241-abc6-64a5a1dc5cc6","stackTrace":["  File \\"/opt/python/wrapt/wrappers.py\\", line 578, in __call__\\n    return self._self_wrapper(self.__wrapped__, self._self_instance,\\n","  File \\"/opt/python/aws_xray_sdk/core/models/subsegment.py\\", line 54, in __call__\\n    return self.recorder.record_subsegment(\\n","  File \\"/opt/python/aws_xray_sdk/core/recorder.py\\", line 424, in record_subsegment\\n    return_value = wrapped(*args, **kwargs)\\n","  File \\"/var/task/src/acquisition/performInstanceSnapshot.py\\", line 147, in handler\\n    raise RuntimeError(json.dumps(output_body))\\n"]}',
    }


def memory_event():
    return {
        "Error": "RuntimeError",
        "Cause": '{"errorMessage":"{\\"IsolationRequired\\": false, \\"forensicId\\": \\"6d7adfdc-09e1-46a2-a652-5ee4ca0bf752\\", \\"forensicType\\": \\"DISK\\", \\"instanceAccount\\": \\"123456789012\\", \\"instanceInfo\\": {\\"AmiLaunchIndex\\": 0, \\"Architecture\\": \\"x86_64\\", \\"BlockDeviceMappings\\": [{\\"DeviceName\\": \\"/dev/xvda\\", \\"Ebs\\": {\\"AttachTime\\": \\"2022-10-10T22:21:06+00:00\\", \\"DeleteOnTermination\\": true, \\"Status\\": \\"attached\\", \\"VolumeId\\": \\"vol-08b8d15458da173d2\\"}}], \\"CapacityReservationSpecification\\": {\\"CapacityReservationPreference\\": \\"open\\"}, \\"ClientToken\\": \\"\\", \\"CpuOptions\\": {\\"CoreCount\\": 1, \\"ThreadsPerCore\\": 2}, \\"EbsOptimized\\": true, \\"EnaSupport\\": true, \\"EnclaveOptions\\": {\\"Enabled\\": false}, \\"HibernationOptions\\": {\\"Configured\\": false}, \\"Hypervisor\\": \\"xen\\", \\"IamInstanceProfile\\": {\\"Arn\\": \\"arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup\\", \\"Id\\": \\"AIPASJROTNDTDUFEOXLUS\\"}, \\"ImageId\\": \\"ami-067e6178c7a211324\\", \\"InstanceId\\": \\"i-0945b8635eb44bdf8\\", \\"InstanceType\\": \\"t3.micro\\", \\"KeyName\\": \\"forensic-instance-key\\", \\"LaunchTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"MetadataOptions\\": {\\"HttpEndpoint\\": \\"enabled\\", \\"HttpProtocolIpv6\\": \\"disabled\\", \\"HttpPutResponseHopLimit\\": 1, \\"HttpTokens\\": \\"optional\\", \\"State\\": \\"applied\\"}, \\"Monitoring\\": {\\"State\\": \\"disabled\\"}, \\"NetworkInterfaces\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"3.26.130.132\\"}, \\"Attachment\\": {\\"AttachTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"AttachmentId\\": \\"eni-attach-0e6694a437de6e807\\", \\"DeleteOnTermination\\": true, \\"DeviceIndex\\": 0, \\"NetworkCardIndex\\": 0, \\"Status\\": \\"attached\\"}, \\"Description\\": \\"\\", \\"Groups\\": [{\\"GroupId\\": \\"sg-033ff377307390ea1\\", \\"GroupName\\": \\"default\\"}], \\"InterfaceType\\": \\"interface\\", \\"Ipv6Addresses\\": [], \\"MacAddress\\": \\"0a:e5:d2:cf:d6:74\\", \\"NetworkInterfaceId\\": \\"eni-032aa23bfdd68efd3\\", \\"OwnerId\\": \\"123456789012\\", \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.19.207\\", \\"PrivateIpAddresses\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"3.26.130.132\\"}, \\"Primary\\": true, \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.19.207\\"}], \\"SourceDestCheck\\": true, \\"Status\\": \\"in-use\\", \\"SubnetId\\": \\"subnet-08c39066d2b0c58fa\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}], \\"Placement\\": {\\"AvailabilityZone\\": \\"ap-southeast-2c\\", \\"GroupName\\": \\"\\", \\"Tenancy\\": \\"default\\"}, \\"PlatformDetails\\": \\"Linux/UNIX\\", \\"PrivateDnsName\\": \\"ip-172-31-19-207.ap-southeast-2.compute.internal\\", \\"PrivateDnsNameOptions\\": {\\"EnableResourceNameDnsAAAARecord\\": false, \\"EnableResourceNameDnsARecord\\": true, \\"HostnameType\\": \\"ip-name\\"}, \\"PrivateIpAddress\\": \\"172.31.19.207\\", \\"ProductCodes\\": [], \\"PublicDnsName\\": \\"ec2-3-26-130-132.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIpAddress\\": \\"3.26.130.132\\", \\"RootDeviceName\\": \\"/dev/xvda\\", \\"RootDeviceType\\": \\"ebs\\", \\"SecurityGroups\\": [{\\"GroupId\\": \\"sg-033ff377307390ea1\\", \\"GroupName\\": \\"default\\"}], \\"SourceDestCheck\\": true, \\"State\\": {\\"Code\\": 16, \\"Name\\": \\"running\\"}, \\"StateTransitionReason\\": \\"\\", \\"SubnetId\\": \\"subnet-08c39066d2b0c58fa\\", \\"Tags\\": [{\\"Key\\": \\"Name\\", \\"Value\\": \\"forensic-test-016\\"}], \\"UsageOperation\\": \\"RunInstances\\", \\"UsageOperationUpdateTime\\": \\"2022-10-10T22:21:05+00:00\\", \\"VirtualizationType\\": \\"hvm\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}, \\"instanceRegion\\": \\"ap-southeast-2\\", \\"isAcquisitionRequired\\": true, \\"isIsolationNeeded\\": true, \\"instanceId\\": \\"i-0945b8635eb44bdf8\\", \\"errorName\\": \\"Error: creating snapshot for forensic id6d7adfdc-09e1-46a2-a652-5ee4ca0bf752\\", \\"errorDescription\\": \\"Error while creating snapshot DISK acquisition - Instance Snapshot\\", \\"errorPhase\\": \\"ACQUISITION\\", \\"errorComponentId\\": \\"performInstanceSnapshot\\", \\"errorComponentType\\": \\"Lambda\\", \\"eventData\\": \\"An error occurred (InvalidParameterValue) when calling the CreateSnapshots operation: There are no attached EBS-backed volumes on the instance id (i-0945b8635eb44bdf8).\\"}","errorType":"RuntimeError","requestId":"3471dac7-dc10-4241-abc6-64a5a1dc5cc6","stackTrace":["  File \\"/opt/python/wrapt/wrappers.py\\", line 578, in __call__\\n    return self._self_wrapper(self.__wrapped__, self._self_instance,\\n","  File \\"/opt/python/aws_xray_sdk/core/models/subsegment.py\\", line 54, in __call__\\n    return self.recorder.record_subsegment(\\n","  File \\"/opt/python/aws_xray_sdk/core/recorder.py\\", line 424, in record_subsegment\\n    return_value = wrapped(*args, **kwargs)\\n","  File \\"/var/task/src/acquisition/performInstanceSnapshot.py\\", line 147, in handler\\n    raise RuntimeError(json.dumps(output_body))\\n"]}',
    }


def mem_acquisition_error():
    return {
        "Error": "MemoryAcquisitionError",
        "Cause": '{"errorMessage":"{\\"forensicId\\": \\"82b5c8be-54dd-4037-9aef-3aad6e08f87a\\", \\"instanceAccount\\": \\"123456789012\\", \\"instanceInfo\\": {\\"AmiLaunchIndex\\": 0, \\"Architecture\\": \\"x86_64\\", \\"BlockDeviceMappings\\": [{\\"DeviceName\\": \\"/dev/xvda\\", \\"Ebs\\": {\\"AttachTime\\": \\"2022-10-10T06:32:27+00:00\\", \\"DeleteOnTermination\\": true, \\"Status\\": \\"attached\\", \\"VolumeId\\": \\"vol-0c002bb3f4b926750\\"}}], \\"CapacityReservationSpecification\\": {\\"CapacityReservationPreference\\": \\"open\\"}, \\"ClientToken\\": \\"\\", \\"CpuOptions\\": {\\"CoreCount\\": 1, \\"ThreadsPerCore\\": 1}, \\"EbsOptimized\\": false, \\"EnaSupport\\": true, \\"EnclaveOptions\\": {\\"Enabled\\": false}, \\"HibernationOptions\\": {\\"Configured\\": false}, \\"Hypervisor\\": \\"xen\\", \\"IamInstanceProfile\\": {\\"Arn\\": \\"arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup\\", \\"Id\\": \\"AIPASJROTNDTDUFEOXLUS\\"}, \\"ImageId\\": \\"ami-067e6178c7a211324\\", \\"InstanceId\\": \\"i-0bf15db2a59e0caf9\\", \\"InstanceType\\": \\"t2.micro\\", \\"KeyName\\": \\"forensic-instance-key\\", \\"LaunchTime\\": \\"2022-10-10T06:32:26+00:00\\", \\"MetadataOptions\\": {\\"HttpEndpoint\\": \\"enabled\\", \\"HttpProtocolIpv6\\": \\"disabled\\", \\"HttpPutResponseHopLimit\\": 1, \\"HttpTokens\\": \\"optional\\", \\"State\\": \\"applied\\"}, \\"Monitoring\\": {\\"State\\": \\"disabled\\"}, \\"NetworkInterfaces\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-13-239-120-35.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"13.239.120.35\\"}, \\"Attachment\\": {\\"AttachTime\\": \\"2022-10-10T06:32:26+00:00\\", \\"AttachmentId\\": \\"eni-attach-0f6a92d7dd280ec22\\", \\"DeleteOnTermination\\": true, \\"DeviceIndex\\": 0, \\"NetworkCardIndex\\": 0, \\"Status\\": \\"attached\\"}, \\"Description\\": \\"\\", \\"Groups\\": [{\\"GroupId\\": \\"sg-03edb2cd48fdf5f52\\", \\"GroupName\\": \\"launch-wizard-3\\"}], \\"InterfaceType\\": \\"interface\\", \\"Ipv6Addresses\\": [], \\"MacAddress\\": \\"06:d1:4c:ee:00:e8\\", \\"NetworkInterfaceId\\": \\"eni-09f9ceeb8e1a00d74\\", \\"OwnerId\\": \\"123456789012\\", \\"PrivateDnsName\\": \\"ip-172-31-47-97.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.47.97\\", \\"PrivateIpAddresses\\": [{\\"Association\\": {\\"IpOwnerId\\": \\"amazon\\", \\"PublicDnsName\\": \\"ec2-13-239-120-35.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIp\\": \\"13.239.120.35\\"}, \\"Primary\\": true, \\"PrivateDnsName\\": \\"ip-172-31-47-97.ap-southeast-2.compute.internal\\", \\"PrivateIpAddress\\": \\"172.31.47.97\\"}], \\"SourceDestCheck\\": true, \\"Status\\": \\"in-use\\", \\"SubnetId\\": \\"subnet-06504490a004d965a\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}], \\"Placement\\": {\\"AvailabilityZone\\": \\"ap-southeast-2b\\", \\"GroupName\\": \\"\\", \\"Tenancy\\": \\"default\\"}, \\"PlatformDetails\\": \\"Linux/UNIX\\", \\"PrivateDnsName\\": \\"ip-172-31-47-97.ap-southeast-2.compute.internal\\", \\"PrivateDnsNameOptions\\": {\\"EnableResourceNameDnsAAAARecord\\": false, \\"EnableResourceNameDnsARecord\\": true, \\"HostnameType\\": \\"ip-name\\"}, \\"PrivateIpAddress\\": \\"172.31.47.97\\", \\"ProductCodes\\": [], \\"PublicDnsName\\": \\"ec2-13-239-120-35.ap-southeast-2.compute.amazonaws.com\\", \\"PublicIpAddress\\": \\"13.239.120.35\\", \\"RootDeviceName\\": \\"/dev/xvda\\", \\"RootDeviceType\\": \\"ebs\\", \\"SecurityGroups\\": [{\\"GroupId\\": \\"sg-03edb2cd48fdf5f52\\", \\"GroupName\\": \\"launch-wizard-3\\"}], \\"SourceDestCheck\\": true, \\"State\\": {\\"Code\\": 16, \\"Name\\": \\"running\\"}, \\"StateTransitionReason\\": \\"\\", \\"SubnetId\\": \\"subnet-06504490a004d965a\\", \\"Tags\\": [{\\"Key\\": \\"Name\\", \\"Value\\": \\"forensic-test-015\\"}], \\"UsageOperation\\": \\"RunInstances\\", \\"UsageOperationUpdateTime\\": \\"2022-10-10T06:32:26+00:00\\", \\"VirtualizationType\\": \\"hvm\\", \\"VpcId\\": \\"vpc-01e9be2545db498e6\\"}, \\"instanceRegion\\": \\"ap-southeast-2\\", \\"isAcquisitionRequired\\": true, \\"isIsolationNeeded\\": true, \\"forensicType\\": \\"MEMORY\\", \\"SSM_STATUS\\": \\"SUCCEEDED\\", \\"ForensicInstanceId\\": \\"i-0bf15db2a59e0caf9\\", \\"errorName\\": \\"Error: Creating memory dump\\", \\"errorDescription\\": \\"Error while performing Forensic MEMORY acquisition\\", \\"errorPhase\\": \\"ACQUISITION\\", \\"errorComponentId\\": \\"performMemoryAcquisition\\", \\"errorComponentType\\": \\"Lambda\\", \\"eventData\\": \\"SSM Not installed\\"}","errorType":"MemoryAcquisitionError","requestId":"539c3ebf-19c2-4537-be16-f0e633bb67b5","stackTrace":["  File \\"/opt/python/wrapt/wrappers.py\\", line 578, in __call__\\n    return self._self_wrapper(self.__wrapped__, self._self_instance,\\n","  File \\"/opt/python/aws_xray_sdk/core/models/subsegment.py\\", line 54, in __call__\\n    return self.recorder.record_subsegment(\\n","  File \\"/opt/python/aws_xray_sdk/core/recorder.py\\", line 424, in record_subsegment\\n    return_value = wrapped(*args, **kwargs)\\n","  File \\"/var/task/src/acquisition/performMemoryAcquisition.py\\", line 250, in handler\\n    raise MemoryAcquisitionError(json.dumps(output_body))\\n"]}',
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


def get_update_record_event():
    return {"Attributes": forensic_record()}


publish_fn = MagicMock()
get_item_fn = MagicMock(return_value=get_item_event())


def mock_connection(ec_response):
    mockClient = Mock(boto3.client("ec2"))
    mockClient.get_caller_identity = lambda: {}
    mockClient._get_local_account_id = lambda: {}
    mockClient.describe_instances = lambda InstanceIds: ec_response
    mockClient.put_item = MagicMock(return_value={})
    mockClient.get_item = MagicMock(return_value=get_item_event())
    mockClient.update_item = MagicMock(return_value=get_update_record_event())
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


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "INSTANCE_TABLE_NAME": "table",
        "NOTIFICATION_TOPIC_ARN": "arn:aws:sns:ap-southeast-2:100000:test-topic",
        "FORENSIC_BUCKET": "forensicbucket",
    },
)
def test_send_notification_for_failed_forensic_mem_acquisition():
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

        ret = app.handler(mem_acquisition_error(), {})
        assert ret.get("statusCode") == 200
