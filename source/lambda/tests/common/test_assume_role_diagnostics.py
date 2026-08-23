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

"""What an operator is told when the application account role is missing.

Every Lambda reaches the instance under investigation by assuming
``ForensicEc2AllowAccessRole-<region>`` in the account that owns it, and that
happens on the first API call of an incident. Observed live on a single-account
deployment whose prerequisite stack had been removed: triage died with

    An error occurred (AccessDenied) when calling the AssumeRole operation:
    User: arn:...:assumed-role/triage-us-east-1-Role/Fo-triage is not authorized
    to perform: sts:AssumeRole on resource: arn:aws:iam::123456789012:role/
    ForensicEc2AllowAccessRole-us-east-1

which names both roles and says nothing about why the role is absent or what to
do, and in the same-account case reads as "cannot assume a role in the account I
am already in". There is a same-account shortcut in ``create_aws_client``, but it
is gated on ``app_account_role`` being falsy and the CDK always sets
``APP_ACCOUNT_ROLE``, so it never fires - which is exactly the thing an operator
needs told.
"""

import pytest
from botocore.exceptions import ClientError

from ...src.common import awsapi_cached_client
from ...src.common.awsapi_cached_client import create_aws_client
from ...src.common.exception import ForensicLambdaExecutionException

FORENSIC_ACCOUNT = "123456789012"
APP_ACCOUNT = "506545071323"
ROLE = "ForensicEc2AllowAccessRole-us-east-1"


def access_denied():
    return ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": (
                    "User: arn:aws:sts::123456789012:assumed-role/"
                    "triage-us-east-1-Role/Fo-triage is not authorized to "
                    "perform: sts:AssumeRole on resource: "
                    f"arn:aws:iam::123456789012:role/{ROLE}"
                ),
            }
        },
        "AssumeRole",
    )


@pytest.fixture
def assume_role_denied(monkeypatch):
    """Make the lazily created assume-role session fail as it does live."""

    class DeniedSession:
        def __init__(self, *args, **kwargs):
            pass

        def client(self, *args, **kwargs):
            raise access_denied()

    monkeypatch.setattr(awsapi_cached_client, "BotoSession", DeniedSession)


class TestTheMessageNamesTheRemedy:
    def test_it_raises_a_forensic_exception_not_a_raw_client_error(
        self, assume_role_denied
    ):
        with pytest.raises(ForensicLambdaExecutionException):
            create_aws_client(
                "ec2",
                current_account=FORENSIC_ACCOUNT,
                target_account=APP_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

    def test_it_names_the_role_the_account_and_the_template(
        self, assume_role_denied
    ):
        with pytest.raises(ForensicLambdaExecutionException) as execinfo:
            create_aws_client(
                "ec2",
                current_account=FORENSIC_ACCOUNT,
                target_account=APP_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

        message = str(execinfo.value)
        assert ROLE in message
        assert APP_ACCOUNT in message
        assert "cross-account-role.yml" in message
        assert "solutionInstalledAccount" in message
        assert "solutionAccountRegion" in message
        # The underlying error is preserved, not swallowed.
        assert "sts:AssumeRole" in message

    def test_the_same_account_case_explains_why_a_role_is_needed_at_all(
        self, assume_role_denied
    ):
        """The confusing case, and the one that has to be spelled out."""
        with pytest.raises(ForensicLambdaExecutionException) as execinfo:
            create_aws_client(
                "ec2",
                current_account=FORENSIC_ACCOUNT,
                target_account=FORENSIC_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

        message = str(execinfo.value)
        assert "same" in message.lower()
        assert "APP_ACCOUNT_ROLE" in message

    def test_the_cross_account_case_does_not_claim_the_accounts_are_the_same(
        self, assume_role_denied
    ):
        with pytest.raises(ForensicLambdaExecutionException) as execinfo:
            create_aws_client(
                "ec2",
                current_account=FORENSIC_ACCOUNT,
                target_account=APP_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

        assert "APP_ACCOUNT_ROLE" not in str(execinfo.value)

    def test_account_ids_compare_as_strings_not_by_type(
        self, assume_role_denied
    ):
        """Account ids arrive as both str and int depending on the caller.

        The prerequisite template declares solutionInstalledAccount as a Number,
        and event payloads carry it as a string, so a plain == would report a
        single-account deployment as cross-account and print the wrong remedy.
        """
        with pytest.raises(ForensicLambdaExecutionException) as execinfo:
            create_aws_client(
                "ec2",
                current_account=int(FORENSIC_ACCOUNT),
                target_account=FORENSIC_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

        assert "APP_ACCOUNT_ROLE" in str(execinfo.value)


class TestOtherFailuresAreNotReinterpreted:
    def test_a_non_access_denied_client_error_propagates_unchanged(
        self, monkeypatch
    ):
        """Only AccessDenied means "the role is not there".

        Throttling or an expired token must not be reported as a missing
        prerequisite stack, or the operator goes and redeploys the wrong thing.
        """

        class ThrottledSession:
            def __init__(self, *args, **kwargs):
                pass

            def client(self, *args, **kwargs):
                raise ClientError(
                    {"Error": {"Code": "Throttling", "Message": "slow down"}},
                    "AssumeRole",
                )

        monkeypatch.setattr(
            awsapi_cached_client, "BotoSession", ThrottledSession
        )

        with pytest.raises(ClientError) as execinfo:
            create_aws_client(
                "ec2",
                current_account=FORENSIC_ACCOUNT,
                target_account=APP_ACCOUNT,
                target_region="us-east-1",
                app_account_role=ROLE,
            )

        assert execinfo.value.response["Error"]["Code"] == "Throttling"
