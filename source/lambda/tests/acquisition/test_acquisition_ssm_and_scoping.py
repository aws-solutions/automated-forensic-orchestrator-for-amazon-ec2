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

"""Managed node discovery and credential scope for memory acquisition.

Both behaviours here are invisible to a happy-path test: discovery only breaks
once a finding names more instances than one DescribeInstanceInformation page
holds, and the credential scope only matters to an attacker who already controls
the instance under investigation.
"""

import json
import os
from unittest import mock
from unittest.mock import MagicMock, patch

from ...src.acquisition import performMemoryAcquisition

BUCKET = "BUCKET_FORENSICS"

ENVIRONMENT = {
    "AWS_REGION": "ap-southeast-2",
    "INSTANCE_TABLE_NAME": "table",
    "S3_BUCKET_NAME": BUCKET,
    "S3_COPY_ROLE": "arn:aws:iam::123456789012:role/s3CopyRole",
    "S3_BUCKET_KEY_ARN": (
        "arn:aws:kms:ap-southeast-2:123456789012:key/"
        "78dd4742-e6b8-4e1c-acc5-5ad35042a86b"
    ),
    "APP_ACCOUNT_ROLE": "ForensicEc2AllowAccessRole",
    "SSM_EXECUTION_TIMEOUT": "1800",
    "LINUX_LIME_MEMORY_ACQUISITION": "linuxDoc",
    "RHEL8_LIME_MEMORY_ACQUISITION": "rhel8Doc",
    "WINDOWS_LIME_MEMORY_ACQUISITION": "windowsDoc",
}


def node(instance_id, ping="Online", **platform):
    return {
        "InstanceId": instance_id,
        "PingStatus": ping,
        "PlatformName": "Amazon Linux",
        "PlatformType": "Linux",
        "PlatformVersion": "2023",
        **platform,
    }


def windows_node(instance_id):
    return node(
        instance_id,
        PlatformName="Microsoft Windows Server",
        PlatformType="Windows",
        PlatformDetails="Windows",
        PlatformVersion="2019",
    )


def rhel_node(instance_id, version):
    return node(
        instance_id,
        PlatformName="Red Hat Enterprise Linux",
        PlatformDetails="Red Hat Enterprise Linux",
        PlatformVersion=version,
    )


def run_handler(instance_ids, pages, info=None):
    """Drive the handler over instance_ids, with DescribeInstanceInformation
    answering `pages` (a list of InstanceInformationList payloads).

    `info` overrides the instanceInfo payload, which is what the handler reads
    the platform from - separate from `pages`, which is Systems Manager's view.

    Returns (response, send_command mock, assume_role mock).
    """
    send_command = MagicMock(
        return_value={"Command": {"CommandId": "73f4f7bb-53a7"}}
    )
    assume_role = MagicMock(
        return_value={
            "Credentials": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                "SessionToken": "FwoGZXIvYXdzEM3EXAMPLE",
            }
        }
    )

    client = MagicMock()
    client.send_command = send_command
    client.assume_role = assume_role

    def get_paginator(operation_name):
        assert operation_name == "describe_instance_information"
        paginator = MagicMock()
        paginator.paginate.side_effect = lambda **kwargs: [
            {"InstanceInformationList": page} for page in pages
        ]
        return paginator

    client.get_paginator = get_paginator

    record = MagicMock()
    record.resourceId = instance_ids

    service = MagicMock()
    service.update_forensic_record_phase_status.return_value = record

    event = {
        "Payload": {
            "body": {
                "forensicId": "1c5b3574-8e67-4fc8-a34e-fe480534ccc1",
                "isAcquisitionRequired": True,
                "instanceAccount": "123456789012",
                "instanceInfo": (
                    info
                    if info is not None
                    else [node(i) for i in instance_ids]
                ),
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
        MagicMock(return_value=service),
    ):
        response = performMemoryAcquisition.handler(event, context)

    return response, send_command, assume_role


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_instances_beyond_the_first_page_are_still_acquired():
    """DescribeInstanceInformation returns at most 50 nodes per page.

    Reading a single response marked every instance past the first page
    "SSM not installed" and skipped its acquisition, so a finding naming more
    instances than one page holds silently lost evidence for the remainder.
    """
    ids = [f"i-{n:017x}" for n in range(1, 61)]
    pages = [[node(i) for i in ids[:50]], [node(i) for i in ids[50:]]]

    response, send_command, _ = run_handler(ids, pages)

    acquired = {
        call.kwargs["InstanceIds"][0] for call in send_command.call_args_list
    }
    assert acquired == set(ids), (
        f"{len(set(ids) - acquired)} instances were never sent an acquisition "
        "command"
    )
    results = response["body"]["InstanceResults"]
    assert all(
        results[i]["SSM_STATUS"] == "SUCCEEDED" for i in ids
    ), "an instance on a later page was reported as SSM not installed"


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_an_offline_managed_node_is_not_treated_as_ssm_enabled():
    """A registered but offline node - including a terminated one - is still
    returned by DescribeInstanceInformation and cannot run an acquisition."""
    online, offline = "i-0aaaaaaaaaaaaaaaa", "i-0bbbbbbbbbbbbbbbb"

    response, send_command, _ = run_handler(
        [online, offline],
        [[node(online), node(offline, ping="ConnectionLost")]],
    )

    targeted = {
        call.kwargs["InstanceIds"][0] for call in send_command.call_args_list
    }
    assert targeted == {online}
    results = response["body"]["InstanceResults"]
    assert results[offline]["SSM_STATUS"] == "FAILED"
    assert results[online]["SSM_STATUS"] == "SUCCEEDED"


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_session_policy_scopes_reads_to_the_tool_prefix():
    """The credentials go to the instance under investigation.

    s3:Get* on the whole bucket let an attacker-controlled host read every other
    case's evidence, and the resource list carried a malformed ARN produced by a
    missing comma between two f-strings (ruff ISC004). The documents only ever
    read the staged LiME modules under tools/.
    """
    instance_id = "i-0aaaaaaaaaaaaaaaa"

    _, _, assume_role = run_handler([instance_id], [[node(instance_id)]])

    policy = json.loads(assume_role.call_args.kwargs["Policy"])
    resources = [
        resource
        for statement in policy["Statement"]
        for resource in statement["Resource"]
    ]

    # No ARN may contain a second embedded ARN.
    for resource in resources:
        assert resource.count("arn:aws:s3:::") <= 1, (
            f"malformed resource {resource!r} - two ARNs were concatenated "
            "instead of being separate list entries"
        )

    # Object reads only: the ListBucket statement legitimately names the bucket
    # and carries s3:GetBucketLocation.
    reads = [
        statement
        for statement in policy["Statement"]
        if any(
            action in ("s3:GetObject", "s3:GetObjectVersion", "s3:Get*")
            for action in statement["Action"]
        )
    ]
    assert reads, "the acquisition still needs to read the staged LiME module"

    # Exactly two prefixes are legitimate: tools/, holding the pre-built LiME
    # modules, and this case's own prefix, which the document head-objects at the
    # end to prove the capture landed and is not zero bytes. Anything wider lets
    # an attacker-controlled host read other cases' evidence.
    case_prefix = f"arn:aws:s3:::{BUCKET}/memory/{instance_id}/"
    for statement in reads:
        assert "s3:Get*" not in statement["Action"]
        for resource in statement["Resource"]:
            allowed = resource == f"arn:aws:s3:::{BUCKET}/tools/*" or (
                resource.startswith(case_prefix) and resource.endswith("/*")
            )
            assert allowed, (
                f"read access is granted on {resource!r}, which is broader "
                "than the tools prefix and this case's own prefix"
            )
        # Never the whole bucket.
        assert f"arn:aws:s3:::{BUCKET}/*" not in statement["Resource"]

    # And the case prefix really is present, or the document's own head-object
    # check fails with 403 after a successful capture.
    read_resources = [r for s in reads for r in s["Resource"]]
    assert any(
        r.startswith(case_prefix) for r in read_resources
    ), "the acquisition cannot verify its own upload without reading it back"

    writes = [
        statement
        for statement in policy["Statement"]
        if "s3:PutObject" in statement["Action"]
    ]
    assert writes, "the acquisition must be able to upload its capture"
    for statement in writes:
        for resource in statement["Resource"]:
            assert resource.startswith(f"arn:aws:s3:::{BUCKET}/memory/")


def sent_for(instance_id, send_command):
    """The send_command call that targeted instance_id."""
    for call in send_command.call_args_list:
        if call.kwargs["InstanceIds"] == [instance_id]:
            return call.kwargs
    raise AssertionError(f"{instance_id} was never sent an acquisition command")


@mock.patch.dict(
    os.environ, {**ENVIRONMENT, "MEMORY_ACQUISITION_TOOLS": "avml,lime"}
)
def test_the_linux_document_is_told_which_tools_to_try():
    """The generic Linux document tries LiME then AVML, in the order given.

    Configurable because the right order is a site decision: AVML first avoids
    loading a kernel module on a production host, LiME first keeps the mechanism
    that has always been used. The value has to reach the document for either
    choice to mean anything.
    """
    instance_id = "i-0aaaaaaaaaaaaaaaa"

    _, send_command, _ = run_handler([instance_id], [[node(instance_id)]])

    sent = sent_for(instance_id, send_command)
    assert sent["DocumentName"].endswith("/linuxDoc")
    assert sent["Parameters"]["memoryAcquisitionTools"] == ["avml,lime"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_tool_list_defaults_when_the_stack_did_not_set_it():
    """An older deployment has no MEMORY_ACQUISITION_TOOLS on the function."""
    instance_id = "i-0aaaaaaaaaaaaaaaa"

    _, send_command, _ = run_handler([instance_id], [[node(instance_id)]])

    sent = sent_for(instance_id, send_command)
    assert sent["Parameters"]["memoryAcquisitionTools"] == ["lime,avml"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_tool_list_is_not_sent_to_documents_that_do_not_declare_it():
    """SSM rejects the whole send_command with InvalidParameters when a
    parameter is not declared.

    So sending memoryAcquisitionTools to the Windows or RHEL documents would not
    misconfigure their acquisition - it would stop it from starting at all, and
    the only signal would be an SSM error on a machine already under
    investigation. Only the generic Linux document implements the fallback and
    only it declares the parameter.
    """
    windows, rhel = "i-0aaaaaaaaaaaaaaaa", "i-0bbbbbbbbbbbbbbbb"
    ids = [windows, rhel]

    _, send_command, _ = run_handler(
        ids,
        [[node(i) for i in ids]],
        info=[windows_node(windows), rhel_node(rhel, "8.10")],
    )

    assert sent_for(windows, send_command)["DocumentName"].endswith(
        "/windowsDoc"
    )
    assert sent_for(rhel, send_command)["DocumentName"].endswith("/rhel8Doc")
    for instance_id in ids:
        assert (
            "memoryAcquisitionTools"
            not in sent_for(instance_id, send_command)["Parameters"]
        )


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_the_windows_document_does_not_leak_onto_a_later_linux_instance():
    """The document was chosen once before the loop and only ever reassigned.

    A finding naming both a Windows and a Linux instance therefore sent winpmem
    to the Linux host - which has no winpmem - so that instance's memory was
    never captured, and because the command itself was accepted the failure
    surfaced as an SSM command failure rather than as an unsupported platform.
    Order matters to this test: the Windows instance has to come first.
    """
    windows, linux = "i-0aaaaaaaaaaaaaaaa", "i-0bbbbbbbbbbbbbbbb"
    ids = [windows, linux]

    _, send_command, _ = run_handler(
        ids,
        [[node(i) for i in ids]],
        info=[windows_node(windows), node(linux)],
    )

    assert sent_for(windows, send_command)["DocumentName"].endswith(
        "/windowsDoc"
    )
    linux_sent = sent_for(linux, send_command)
    assert linux_sent["DocumentName"].endswith("/linuxDoc")
    # and it is configured, which the Windows document would have refused
    assert linux_sent["Parameters"]["memoryAcquisitionTools"] == ["lime,avml"]


@mock.patch.dict(os.environ, ENVIRONMENT)
def test_a_dot_zero_red_hat_release_still_resolves_to_its_own_document():
    """The version ranges were open at the lower bound.

    `9 > float("8.0") > 8` is false, and so were the other two, so RHEL 8.0
    matched no branch and rhel_version kept whatever the previous instance in
    the loop had set - here RHEL 9, whose document is not deployed. On the first
    instance of a finding it was unbound instead.
    """
    nine, eight = "i-0aaaaaaaaaaaaaaaa", "i-0bbbbbbbbbbbbbbbb"
    ids = [nine, eight]

    response, send_command, _ = run_handler(
        ids,
        [[node(i) for i in ids]],
        info=[rhel_node(nine, "9.4"), rhel_node(eight, "8.0")],
    )

    assert sent_for(eight, send_command)["DocumentName"].endswith("/rhel8Doc")
    # RHEL 9 has no acquisition document, so it fails - but it fails saying so,
    # and it does not take the RHEL 8 instance down with it.
    results = response["body"]["InstanceResults"]
    assert results[eight]["SSM_STATUS"] == "SUCCEEDED"
    failure = str(results[nine])
    assert "not supported" in failure
    # The release, and the variable whose absence is the reason. A bare
    # KeyError('RHEL9_LIME_MEMORY_ACQUISITION') named the second but not the
    # first, and UnboundLocalError named neither.
    assert "9.4" in failure
    assert "RHEL9_LIME_MEMORY_ACQUISITION" in failure
    assert nine in failure
