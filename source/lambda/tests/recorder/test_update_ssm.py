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

from multiprocessing import get_logger
import os
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import boto3


from ...src.common.awsapi_cached_client import AWSCachedClient
from ...src.recorder.app import (
    lambda_handler as function_under_test,
)

put_parameter_fn = MagicMock()


def mock_connection():
    mockClient = Mock(boto3.client("ssm"))
    mockClient.get_caller_identity = MagicMock()

    mockClient.put_parameter = put_parameter_fn

    return mockClient


event = {
    "Records": [
        {
            "EventSource": "aws:sns",
            "EventVersion": "1.0",
            "EventSubscriptionArn": "arn:aws:sns:ap-southeast-2:123456789012:ForensicImageBuilderStack-AWSImageBuilderEventssansiftForensicImgBuilderNotificationTopic2986332F-1JQIWK9OO8AKF:2c6d5205-4b1a-43b2-a05f-9b472305a615",
            "Sns": {
                "Type": "Notification",
                "MessageId": "d20f3241-8071-5003-a5e2-68d8a2d35d66",
                "TopicArn": "arn:aws:sns:ap-southeast-2:123456789012:ForensicImageBuilderStack-AWSImageBuilderEventssansiftForensicImgBuilderNotificationTopic2986332F-1JQIWK9OO8AKF",
                "Subject": "None",
                "Message": '{\n  "versionlessArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image/sansift-image01",\n  "semver": 1237940039285380277046607873,\n  "arn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image/sansift-image01/1.0.2/1",\n  "name": "sansift-image01",\n  "version": "1.0.2",\n  "type": "AMI",\n  "buildVersion": 1,\n  "state": {\n    "status": "AVAILABLE"\n  },\n  "platform": "Linux",\n  "imageRecipe": {\n    "arn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image-recipe/sansift-image01/1.0.2",\n    "name": "sansift-image01",\n    "version": "1.0.2",\n    "components": [\n      {\n        "componentArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:component/san-sift/1.0.2/1"\n      }\n    ],\n    "platform": "Linux",\n    "parentImage": "ami-0b7dcd6e6fd797935",\n    "blockDeviceMappings": [],\n    "dateCreated": "Mar 2, 2022 7:09:50 AM",\n    "tags": {\n      "internalId": "514c3987-3ab1-4a7a-8a1c-14f2655b9c14",\n      "resourceArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image-recipe/sansift-image01/1.0.2"\n    },\n    "accountId": "123456789012"\n  },\n  "sourcePipelineArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image-pipeline/imagebuilderpipelinesansift",\n  "infrastructureConfiguration": {\n    "arn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:infrastructure-configuration/infraconfiguration",\n    "name": "infraConfiguration",\n    "instanceTypes": [\n      "t3.large",\n      "t3.xlarge"\n    ],\n    "instanceProfileName": "ImageBuilderInstanceProfile-ap-southeast-2",\n    "securityGroupIds": [\n      "sg-0526fc5559beecb6d"\n    ],\n    "subnetId": "subnet-0d9c2c843d4f08593",\n    "tags": {\n      "internalId": "aa2b73b0-93a8-4078-b2ad-31704bd48ac7",\n      "resourceArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:infrastructure-configuration/infraconfiguration"\n    },\n    "logging": {\n      "s3Logs": {}\n    },\n    "terminateInstanceOnFailure": true,\n    "snsTopicArn": "arn:aws:sns:ap-southeast-2:123456789012:ForensicImageBuilderStack-AWSImageBuilderEventssansiftForensicImgBuilderNotificationTopic2986332F-1JQIWK9OO8AKF",\n    "dateCreated": "Mar 2, 2022 7:12:14 AM",\n    "accountId": "123456789012"\n  },\n  "imageTestsConfigurationDocument": {\n    "imageTestsEnabled": true,\n    "timeoutMinutes": 720\n  },\n  "dateCreated": "Mar 2, 2022 7:19:19 AM",\n  "outputResources": {\n    "amis": [\n      {\n        "region": "ap-southeast-2",\n        "image": "ami-066e5a16212730635",\n        "name": "sansift-image01 2022-03-02T07-19-55.104Z",\n        "accountId": "123456789012"\n      }\n    ]\n  },\n  "buildExecutionId": "63e913e5-1969-4e92-9a4f-fb05bea0916a",\n  "testExecutionId": "65cffbdb-949b-4f73-a369-e98e8e5677e2",\n  "accountId": "123456789012",\n  "osVersion": "Ubuntu 20",\n  "enhancedImageMetadataEnabled": true,\n  "buildType": "USER_INITIATED",\n  "tags": {\n    "internalId": "e35a5667-0601-4bf5-87e1-22a6fafb83da",\n    "resourceArn": "arn:aws:imagebuilder:ap-southeast-2:123456789012:image/sansift-image01/1.0.2/1"\n  }\n}',
                "Timestamp": "2022-03-02T07:44:34.700Z",
                "SignatureVersion": "1",
                "Signature": "aYRXEo8dQhQr53nzTa3bpuf9H3uw8XfZgLyUkJ/f4jiTssnD3Wl34jBnC8w9l3bsPYtKiy/PgPsVRAtPUplKpxPcAilxkPBzJL0yzj4yf3vXZPWeqGjMvFgClmLE8kjx5VHhx0Nb9as5Ze6y1qSKm1KX4WZUFsQjUh3pBkfIZ58XWXDkxRE64Mf8gOu6k8PzqwKM9jgHYRFC2IKkKHStldo4tnLmyyWokvRotFUqqr9Z+lzxEuD73p4mJ+RJjHao9Pn3FPpUiLpSbxKFYApr/TZWAoeZoFMilpXE7sfLvhX/4mTUD1hc7jA2Nr7pjMfYxkeqfuKEWrGCEXlId7/rzw==",
                "SigningCertUrl": "https://sns.ap-southeast-2.amazonaws.com/SimpleNotificationService-7ff5318490ec183fbaddaa2a969abfda.pem",
                "UnsubscribeUrl": "https://sns.ap-southeast-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:ap-southeast-2:123456789012:ForensicImageBuilderStack-AWSImageBuilderEventssansiftForensicImgBuilderNotificationTopic2986332F-1JQIWK9OO8AKF:2c6d5205-4b1a-43b2-a05f-9b472305a615",
                "MessageAttributes": {},
            },
        }
    ]
}


@mock.patch.dict(
    os.environ,
    {
        "AWS_REGION": "ap-southeast-2",
        "IMAGE_SSM_NAME": "sansift",
    },
)
def test_trigger_event():

    with patch.object(
        AWSCachedClient,
        "get_connection",
        Mock(return_value=mock_connection()),
    ):
        ret = function_under_test(event, {})
        assert ret.get("statusCode") == 200
        put_parameter_fn.assert_called_once_with(
            Name="sansift",
            Value="ami-066e5a16212730635",
            Type="String",
            DataType="text",
            Tier="Advanced",
            Overwrite=True,
        )
