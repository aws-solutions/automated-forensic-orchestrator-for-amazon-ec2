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

# *******************************************************************
# Required Modules:
# *******************************************************************
from logging import getLogger

import boto3
from aws_xray_sdk.core import patch_all, xray_recorder
from botocore.config import Config

logger = getLogger(__name__)


def create_aws_client(
    client_name: str,
    current_account=None,
    target_account=None,
    target_region=None,
    app_account_role=None,
    custom_boto_config=None,
):
    if target_account == current_account and not app_account_role:
        logger.info(
            f"client is in same account as solution account {target_account} use default client"
        )
        region = target_region if target_region else os.environ["AWS_REGION"]
        return AWSCachedClient(region, custom_boto_config).get_connection(
            client_name
        )
    else:
        logger.info(
            f"creating client {client_name} for target account {target_account} create assume role session"
        )
        ec2_assumerole_session = BotoSession(
            account=target_account,
            role=app_account_role,
            target_region=target_region,
        )
        return ec2_assumerole_session.client(client_name)


patch_all()
xray_recorder.configure(context_missing="LOG_ERROR")


@xray_recorder.capture("AWS Cached Client")
class AWSCachedClient:
    """
    Maintains a hash of AWS API Client connections by region and service
    """

    account = ""
    region = ""
    client: dict = {}
    solution_id = ""
    solution_version = "V1.0.0"

    def __init__(self, region, custom_boto_config=None):
        """
        Create a Boto3 Client object. Region is used for operations such
        as retrieving account number, and as the default for get_connection.
        """
        self.solution_id = os.getenv("SOLUTION_ID", "SO0191")
        self.solution_version = os.getenv("SOLUTION_VERSION", "V1.0.0")
        self.region = region
        self.boto_config = (
            custom_boto_config
            if custom_boto_config
            else Config(
                user_agent_extra=f"AwsSolution/{self.solution_id}/{self.solution_version}",
                retries={"max_attempts": 10, "mode": "standard"},
            )
        )
        self.account = self._get_local_account_id()

    def get_connection(self, service, region=None):
        """Connect to AWS api"""
        if not region:
            region = self.region

        if service not in self.client:
            self.client[service] = {}

        if region not in self.client[service]:
            self.client[service][region] = boto3.client(
                service,
                region_name=region,
                config=self.boto_config,
                endpoint_url="https://"
                + service
                + "."
                + region
                + ".amazonaws.com",
            )

        return self.client[service][region]

    def _get_local_account_id(self):
        """
        get local account info
        """
        aws_account_id = (
            self.get_connection("sts", self.region)
            .get_caller_identity()
            .get("Account")
        )
        return aws_account_id


class MissingAssumedRole(Exception):
    pass


class BotoSession:
    client_props: dict = {}
    resource_props: dict = {}
    STS = None
    partition = None
    session = None
    target = None
    role = None
    target_region = None

    def create_session(self):
        self.STS = None
        # Local or remote? Who am I?
        self.STS = boto3.client(
            "sts",
            config=self.boto_config,
            endpoint_url="https://sts."
            + self.target_region
            + ".amazonaws.com",
        )
        if not self.target:
            self.target = self.STS.get_caller_identity()["Account"]
        remote_account = self.STS.assume_role(
            RoleArn="arn:"
            + self.partition
            + ":iam::"
            + self.target
            + ":role/"
            + self.role,
            RoleSessionName="sechub_admin",
        )
        self.session = boto3.session.Session(
            aws_access_key_id=remote_account["Credentials"]["AccessKeyId"],
            aws_secret_access_key=remote_account["Credentials"][
                "SecretAccessKey"
            ],
            aws_session_token=remote_account["Credentials"]["SessionToken"],
        )

        boto3.setup_default_session()

    def __init__(
        self, account=None, role=None, partition=None, target_region=None
    ):
        """
        Create a session
        account: None or the target account
        """
        # Default partition to 'aws'
        if not partition:
            partition = "aws"
        self.target = account
        if not role:
            raise MissingAssumedRole
        else:
            self.role = role
        self.session = None
        self.target_region = target_region
        self.partition = os.getenv("AWS_PARTITION", partition)
        self.solution_id = os.getenv("SOLUTION_ID", "SO0191")
        self.solution_version = os.getenv("SOLUTION_VERSION", "V1.0.0")
        self.boto_config = Config(
            user_agent_extra=f"AwsSolution/{self.solution_id}/{self.solution_version}",
            retries={"max_attempts": 10, "mode": "standard"},
        )

    def client(self, name, **kwargs):
        if self.session is None:
            self.create_session()
        self.client_props[name] = self.session.client(
            name, config=self.boto_config, **kwargs
        )
        return self.client_props[name]

    def resource(self, name, **kwargs):

        self.resource_props[name] = self.session.resource(
            name, config=self.boto_config, **kwargs
        )
        return self.resource_props[name]
