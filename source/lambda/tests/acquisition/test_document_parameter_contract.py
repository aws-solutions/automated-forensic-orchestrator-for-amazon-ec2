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

"""The parameter contract between the acquisition Lambda and its SSM documents.

Two failure modes motivate this file, and neither is visible to any other test
because both sides are individually well formed:

* A document declares a parameter the Lambda never sends. The parameter silently
  keeps its declared default, which for these documents is descriptive filler
  such as ``S3 bucket Location``, so the shell renders a nonsense value instead
  of failing. This is how the LiME pre-built module download came to be attempted
  against a bucket literally named "S3 bucket Location" on every acquisition.
* The Lambda sends a parameter a document does not declare. SSM rejects the whole
  ``send_command`` with ``InvalidParameters``, so the acquisition never starts.

Both directions are asserted against the real document JSON.
"""

import json
import os
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from ...src.acquisition import performMemoryAcquisition

SSM_DOCUMENT_DIR = Path(__file__).resolve().parents[3] / "ssm-documents"

INSTANCE_ID = "i-0bf2bf6b175654c6e"

# Each case: the document the handler must select, and the instanceInfo that
# should make it select it. The env vars below map these stems to the selection
# logic, so the captured DocumentName identifies the file to check against.
PLATFORM_CASES = [
    (
        "linux_lime-memory-acquisition",
        {
            "InstanceId": INSTANCE_ID,
            "PlatformName": "Amazon Linux",
            "PlatformType": "Linux",
            "PlatformVersion": "2023",
        },
    ),
    (
        "RHEL8-lime-memory-acquisition",
        {
            "InstanceId": INSTANCE_ID,
            "PlatformName": "Red Hat Enterprise Linux",
            "PlatformType": "Linux",
            "PlatformVersion": "8.5",
        },
    ),
    (
        "windows-lime-memory-acquisition",
        {
            "InstanceId": INSTANCE_ID,
            "PlatformName": "Windows",
            "PlatformType": "Windows",
            "PlatformDetails": "Windows",
            "PlatformVersion": "2019",
        },
    ),
]

ENVIRONMENT = {
    "AWS_REGION": "ap-southeast-2",
    "INSTANCE_TABLE_NAME": "table",
    "S3_BUCKET_NAME": "BUCKET_FORENSICS",
    "S3_COPY_ROLE": "arn:aws:iam::123456789012:role/s3CopyRole",
    "S3_BUCKET_KEY_ARN": (
        "arn:aws:kms:ap-southeast-2:123456789012:key/"
        "78dd4742-e6b8-4e1c-acc5-5ad35042a86b"
    ),
    "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    "SSM_EXECUTION_TIMEOUT": "1800",
    # Deliberately the file stems, so the captured DocumentName is the filename.
    "LINUX_LIME_MEMORY_ACQUISITION": "linux_lime-memory-acquisition",
    "RHEL8_LIME_MEMORY_ACQUISITION": "RHEL8-lime-memory-acquisition",
    "WINDOWS_LIME_MEMORY_ACQUISITION": "windows-lime-memory-acquisition",
}


def declared_parameters(document_stem):
    document = json.loads(
        (SSM_DOCUMENT_DIR / f"{document_stem}.json").read_text()
    )
    return document.get("parameters", {})


def send_command_for(instance_info):
    """Run the handler for one platform and return the send_command kwargs."""
    send_command = MagicMock(
        return_value={"Command": {"CommandId": "73f4f7bb-53a7"}}
    )

    client = MagicMock()
    client.send_command = send_command
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "FwoGZXIvYXdzEM3EXAMPLE",
        }
    }
    registered = {
        "InstanceInformationList": [
            {"InstanceId": INSTANCE_ID, "PingStatus": "Online"}
        ]
    }
    client.describe_instance_information.return_value = registered

    # The handler pages and chunks DescribeInstanceInformation.
    def get_paginator(operation_name):
        assert operation_name == "describe_instance_information"
        paginator = MagicMock()
        paginator.paginate.side_effect = lambda **kwargs: [registered]
        return paginator

    client.get_paginator = get_paginator

    forensic_record = MagicMock()
    forensic_record.resourceId = INSTANCE_ID

    data_service = MagicMock()
    data_service.update_forensic_record_phase_status.return_value = (
        forensic_record
    )

    event = {
        "Payload": {
            "body": {
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isAcquisitionRequired": True,
                "instanceAccount": "123456789012",
                "instanceInfo": instance_info,
            },
            "statusCode": 200,
        }
    }

    context = MagicMock()
    context.invoked_function_arn = (
        "arn:aws:lambda:ap-southeast-2:123456789012:function:Fo-perform"
    )

    with patch.object(
        performMemoryAcquisition, "create_aws_client", lambda *a, **k: client
    ), patch.object(
        performMemoryAcquisition,
        "ForensicDataService",
        MagicMock(return_value=data_service),
    ):
        performMemoryAcquisition.handler(event, context)

    assert send_command.call_args is not None, (
        "the handler never called send_command, so this test would assert "
        "nothing about the parameter contract"
    )
    return send_command.call_args.kwargs


@pytest.mark.parametrize("expected_stem,instance_info", PLATFORM_CASES)
@mock.patch.dict(os.environ, ENVIRONMENT)
def test_sent_parameters_are_declared_by_the_selected_document(
    expected_stem, instance_info
):
    kwargs = send_command_for(instance_info)

    # send_command is given a full document ARN, not a bare name.
    selected = kwargs["DocumentName"].rsplit("/", 1)[-1]
    assert (
        selected == expected_stem
    ), f"expected the handler to select {expected_stem}, got {selected}"

    declared = set(declared_parameters(expected_stem))
    sent = set(kwargs["Parameters"])

    undeclared = sent - declared
    assert not undeclared, (
        f"{expected_stem} does not declare {sorted(undeclared)}; SSM rejects "
        "send_command with InvalidParameters when a parameter is not declared"
    )


@pytest.mark.parametrize("expected_stem,instance_info", PLATFORM_CASES)
@mock.patch.dict(os.environ, ENVIRONMENT)
def test_parameters_without_a_usable_default_are_sent(
    expected_stem, instance_info
):
    """A declared default that is descriptive filler is not a usable default.

    These documents use their defaults as documentation ("S3 bucket Location",
    "session Token"), so a parameter left unsent renders that text into the
    shell rather than failing. Any parameter whose default is not a real value
    has to be supplied by the Lambda.
    """
    sent = set(send_command_for(instance_info)["Parameters"])

    filler = {
        name
        for name, spec in declared_parameters(expected_stem).items()
        # Placeholder defaults are prose: they contain a space. Real defaults in
        # these documents are values like "1800", "" or "volatility3/symbols".
        if " " in str(spec.get("default", ""))
    }

    missing = filler - sent
    assert not missing, (
        f"{expected_stem} declares {sorted(missing)} with a placeholder "
        "default and the Lambda does not send them, so the document will run "
        "with that placeholder text substituted in"
    )
