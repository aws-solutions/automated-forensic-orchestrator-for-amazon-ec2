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

"""One resolver for "which SSM document does this instance need".

Four handlers used to answer that question independently - acquisition,
acquisition completion, memory analysis and disk investigation - and each copy
carried its own version of the same three mistakes:

  * Red Hat's major version came from three strict inequalities open at the lower
    bound, so `9 > float("8.0") > 8` was false and RHEL 8.0 matched no branch,
    leaving the version variable unbound or holding the previous instance's value.
  * the document's environment variable name was built by concatenating that
    version, so a release with no deployed document raised a bare KeyError on a
    name the reader cannot place.
  * the platform was looked up in a list by instance id with no handling for
    "not found", so the variable silently kept the previous instance's platform.

Fixing them one file at a time is how the third and fourth copies survived. This
suite pins the shared resolver's behaviour, and every handler is asserted to use
it rather than re-deriving any of it.
"""

import os
import re
from pathlib import Path

import pytest

from ...src.common.platform_dispatch import (
    DOCUMENT_ENV_VARS,
    PlatformNotSupported,
    platform_of,
    resolve_document,
)

SRC = Path(__file__).resolve().parents[2] / "src"

WINDOWS = {
    "InstanceId": "i-0win",
    "PlatformDetails": "Windows",
    "PlatformType": "Windows",
    "PlatformName": "Microsoft Windows Server 2019 Datacenter",
    "PlatformVersion": "10.0.17763",
}
AL2023 = {
    "InstanceId": "i-0al2023",
    "PlatformDetails": "Linux/UNIX",
    "PlatformType": "Linux",
    "PlatformName": "Amazon Linux",
    "PlatformVersion": "2023",
}
RHEL810 = {
    "InstanceId": "i-0rhel810",
    "PlatformDetails": "Red Hat Enterprise Linux",
    "PlatformType": "Linux",
    "PlatformName": "Red Hat Enterprise Linux",
    "PlatformVersion": "8.10",
}
RHEL80 = {**RHEL810, "InstanceId": "i-0rhel80", "PlatformVersion": "8.0"}
RHEL94 = {**RHEL810, "InstanceId": "i-0rhel94", "PlatformVersion": "9.4"}

# The values above are what AWS actually returns, measured on live instances in
# us-east-1: EC2 DescribeInstances PlatformDetails is "Windows",
# "Red Hat Enterprise Linux" or "Linux/UNIX", and SSM
# DescribeInstanceInformation PlatformName is "Microsoft Windows Server 2019
# Datacenter", "Red Hat Enterprise Linux" or "Amazon Linux".

ENVIRONMENT = {
    "LINUX_LIME_MEMORY_ACQUISITION": "linuxAcq",
    "WINDOWS_LIME_MEMORY_ACQUISITION": "windowsAcq",
    "RHEL8_LIME_MEMORY_ACQUISITION": "rhel8Acq",
    "LIME_MEMORY_LOAD_INVESTIGATION": "linuxLoad",
    "WINDOWS_LIME_MEMORY_LOAD_INVESTIGATION": "windowsLoad",
    "RHEL8_LIME_MEMORY_LOAD_INVESTIGATION": "rhel8Load",
    "LINUX_DISK_INVESTIGATION": "linuxDisk",
    "WINDOWS_DISK_INVESTIGATION": "windowsDisk",
}


class TestRedHatVersion:
    """The open-range bug, in the release where it bites."""

    @pytest.mark.parametrize(
        "version,expected",
        [
            ("8.10", "8"),
            ("8.0", "8"),  # matched no branch before
            ("8", "8"),  # matched no branch before
            ("9.4", "9"),
            ("9.0", "9"),  # matched no branch before
            ("7.9", "7"),
        ],
    )
    def test_major_version(self, version, expected):
        node = {**RHEL810, "PlatformVersion": version}
        with mock_env():
            if expected == "8":
                assert resolve_document(node, "MEMORY_ACQUISITION").endswith(
                    "rhel8Acq"
                ) or resolve_document(node, "MEMORY_ACQUISITION") == "rhel8Acq"
            else:
                # 7 and 9 have no deployed document; the point here is that the
                # major version was computed at all rather than left unbound.
                with pytest.raises(PlatformNotSupported) as caught:
                    resolve_document(node, "MEMORY_ACQUISITION")
                assert f"RHEL{expected}" in str(caught.value)

    def test_a_dot_zero_release_is_not_silently_the_previous_instance(self):
        """The bug this replaces: rhel_version kept the last value it held.

        Resolving 9.4 first and then 8.0 is the order that exposed it - 9.4 set
        the variable, 8.0 matched no branch, and 8.0 was then resolved as 9.
        """
        with mock_env():
            with pytest.raises(PlatformNotSupported):
                resolve_document(RHEL94, "MEMORY_ACQUISITION")
            assert resolve_document(RHEL80, "MEMORY_ACQUISITION") == "rhel8Acq"

    def test_an_unparseable_version_says_so(self):
        node = {**RHEL810, "PlatformVersion": "not-a-version"}
        with mock_env():
            with pytest.raises(PlatformNotSupported) as caught:
                resolve_document(node, "MEMORY_ACQUISITION")
            assert "not-a-version" in str(caught.value)


class TestUnsupportedReleasesAreNamed:
    def test_rhel9_names_the_release_and_the_missing_variable(self):
        with mock_env():
            with pytest.raises(PlatformNotSupported) as caught:
                resolve_document(RHEL94, "MEMORY_ACQUISITION")
            message = str(caught.value)
            # A bare KeyError on RHEL9_LIME_MEMORY_ACQUISITION is what this
            # replaces: it named a variable, not a problem.
            assert "9.4" in message
            assert "RHEL9" in message
            assert "not deployed" in message or "no document" in message


class TestEveryPlatformResolves:
    @pytest.mark.parametrize(
        "node,kind,expected",
        [
            (WINDOWS, "MEMORY_ACQUISITION", "windowsAcq"),
            (AL2023, "MEMORY_ACQUISITION", "linuxAcq"),
            (RHEL810, "MEMORY_ACQUISITION", "rhel8Acq"),
            (WINDOWS, "MEMORY_LOAD_INVESTIGATION", "windowsLoad"),
            (AL2023, "MEMORY_LOAD_INVESTIGATION", "linuxLoad"),
            (RHEL810, "MEMORY_LOAD_INVESTIGATION", "rhel8Load"),
            (WINDOWS, "DISK_INVESTIGATION", "windowsDisk"),
            (AL2023, "DISK_INVESTIGATION", "linuxDisk"),
        ],
    )
    def test_resolves(self, node, kind, expected):
        with mock_env():
            assert resolve_document(node, kind) == expected

    def test_declares_the_kinds_the_handlers_ask_for(self):
        assert set(DOCUMENT_ENV_VARS) >= {
            "MEMORY_ACQUISITION",
            "MEMORY_LOAD_INVESTIGATION",
            "DISK_INVESTIGATION",
        }


class TestPlatformOf:
    """The list lookup that used to fall through to the previous instance."""

    def test_finds_the_named_instance_in_a_list(self):
        got = platform_of([WINDOWS, AL2023], "i-0al2023")
        assert got["PlatformName"] == "Amazon Linux"

    def test_accepts_the_single_instance_dict_form(self):
        assert platform_of(AL2023, "i-0al2023")["PlatformName"] == "Amazon Linux"

    def test_a_missing_instance_raises_instead_of_returning_the_previous_one(self):
        # The defect: `for x in list: if match: platform = ...` with no else left
        # `platform` holding the previous iteration's value, so a node absent from
        # instanceInfo was analysed as whichever node came before it.
        with pytest.raises(PlatformNotSupported) as caught:
            platform_of([WINDOWS], "i-0notthere")
        assert "i-0notthere" in str(caught.value)

    def test_a_dict_for_a_different_instance_is_not_silently_accepted(self):
        with pytest.raises(PlatformNotSupported):
            platform_of(AL2023, "i-0somethingelse")


class TestNoHandlerReimplementsTheDispatch:
    """The reason there were four copies: nothing stopped a fifth."""

    HANDLERS = [
        "acquisition/performMemoryAcquisition.py",
        "acquisition/checkMemoryAcquisition.py",
        "investigation/runMemoryAnalysis.py",
        "investigation/runForensicsCommand.py",
    ]

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_no_open_range_version_tests(self, handler):
        code = executable_lines(SRC / handler)
        assert not re.search(r"\d+\s*>\s*float\(\s*platform_version", code), (
            f"{handler} still derives the Red Hat major version itself; the open "
            "ranges are the bug that made RHEL 8.0 unresolvable"
        )

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_no_env_var_built_by_concatenation(self, handler):
        code = executable_lines(SRC / handler)
        assert not re.search(r'"RHEL"\s*\+', code), (
            f"{handler} still builds a document environment variable by "
            "concatenating a version"
        )

    @pytest.mark.parametrize("handler", HANDLERS)
    def test_uses_the_shared_resolver(self, handler):
        code = executable_lines(SRC / handler)
        assert "resolve_document" in code or "platform_of" in code, (
            f"{handler} does not use the shared resolver"
        )


class TestUnshareMatchesShare:
    """Whatever acquisition shared must be what completion unshares."""

    def test_completion_resolves_the_document_rather_than_guessing(self):
        code = executable_lines(SRC / "acquisition/checkMemoryAcquisition.py")
        # It used to branch on `platform_details == "Windows"` only, with no Red
        # Hat case at all: acquisition shared the RHEL8 document with the
        # application account and completion removed the *Linux* document, so the
        # RHEL8 document stayed shared with that account for good.
        assert "resolve_document" in code
        assert not re.search(r'platform_details\s*==\s*"Windows"', code), (
            "completion still decides which document to unshare from a single "
            "Windows comparison"
        )

    def test_completion_does_not_take_the_first_node_for_a_whole_cluster(self):
        code = executable_lines(SRC / "acquisition/checkMemoryAcquisition.py")
        # instanceInfo[0] made a mixed-platform EKS cluster unshare one document
        # and leave the other shared.
        assert not re.search(r'instanceInfo"\)\[0\]', code)


def executable_lines(path: Path) -> str:
    """Source with comment-only lines removed.

    Several of these files quote the old expression in a comment to explain why
    it was replaced, and that explanation is worth keeping.
    """
    return "\n".join(
        line
        for line in path.read_text().splitlines()
        if not line.lstrip().startswith("#")
    )


def mock_env():
    from unittest import mock as _mock

    return _mock.patch.dict(os.environ, ENVIRONMENT, clear=False)
