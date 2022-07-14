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
from unittest import TestCase

import boto3
import pytest
import requests

"""
Make sure env variable AWS_STACK_NAME exists with the name of the stack we are going to test.
"""


@pytest.mark.skip(reason="No infra to run this test yet")
class TestApiGateway(TestCase):
    api_endpoint: str

    @classmethod
    def get_stack_name(cls) -> str:
        stack_name = os.environ.get("AWS_STACK_NAME")
        if not stack_name:
            raise Exception(
                "Cannot find env var AWS_STACK_NAME. \n"
                "Please setup this environment variable with the stack name where we are running integration tests."
            )

        return stack_name

    def setUp(self) -> None:
        """
        Based on the provided env variable AWS_STACK_NAME,
        here we use cloudformation API to find out what the HelloWorldApi URL is
        """
        stack_name = TestApiGateway.get_stack_name()

        client = boto3.client("cloudformation")

        try:
            response = client.describe_stacks(StackName=stack_name)
        except Exception as e:
            raise Exception(
                f"Cannot find stack {stack_name}. \n"
                f'Please make sure stack with the name "{stack_name}" exists.'
            ) from e

        stacks = response["Stacks"]

        stack_outputs = stacks[0]["Outputs"]
        api_outputs = [
            output
            for output in stack_outputs
            if output["OutputKey"] == "HelloWorldApi"
        ]
        self.assertTrue(
            api_outputs,
            f"Cannot find output HelloWorldApi in stack {stack_name}",
        )

        self.api_endpoint = api_outputs[0]["OutputValue"]

    def test_api_gateway(self):
        """
        Call the API Gateway endpoint and check the response
        """
        response = requests.get(self.api_endpoint)
        self.assertDictEqual(response.json(), {"message": "hello world"})
