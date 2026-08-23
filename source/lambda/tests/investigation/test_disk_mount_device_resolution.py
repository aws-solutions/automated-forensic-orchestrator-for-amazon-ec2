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

"""Mounting the acquired evidence volume on the analysis host.

This is the step every disk investigation passes through, and it was failing
for two independent reasons that no existing test could see, because both sides
are individually well formed and the mount used to be unchecked.

*   ``attachEBSSnapShot`` asked EC2 to attach at ``/dev/sdg`` and then told the
    SSM document to mount ``/dev/xvdg1``. EC2 only honours the requested name on
    the Xen instance families. Every instance type this solution now uses for
    analysis is Nitro, where the kernel names EBS volumes ``/dev/nvmeXnY`` and
    udev links the requested ``/dev/sdg`` to it but never creates ``/dev/xvdg``.
    So the mount named a device that could not exist. Verified on a live
    m6i.2xlarge: with volumes attached at ``/dev/sdf`` and ``/dev/sdg``,
    ``/dev/sdf1`` resolved to ``/dev/nvme1n1p1`` while every ``/dev/xvd*`` form
    was absent.

*   The mount named no filesystem type. Amazon Linux 2023 ships no ``ntfs-3g``
    in any of its repositories, and while its kernel does carry the in-tree
    ``ntfs3`` driver, blkid reports the type as ``ntfs`` whereas the kernel
    registers ``ntfs3`` - so a bare mount of a Windows evidence volume fails
    with ``unknown filesystem type 'ntfs'``. Separately, an XFS evidence volume
    cloned from an instance built on the same AMI as the analysis host carries
    the same filesystem UUID as the host's own root, and XFS refuses to mount a
    duplicate UUID. Both were reproduced live before being fixed.

The device-name assertions below are on the Lambda; the mount assertions are on
the document text, because driving the document itself needs a live instance
with a real evidence volume attached.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from ...src.investigation import attachEBSSnapShot

SSM_DOCUMENT_DIR = Path(__file__).resolve().parents[3] / "ssm-documents"
PREPARE_DOCUMENT = SSM_DOCUMENT_DIR / "linux-disk-investigation-prepare.json"

FORENSIC_ID = "1c5b3574-8e67-4fc8-a34e-fe480534ccc1"
FORENSIC_INSTANCE_ID = "i-0d15e4496cee04a79"
VOLUME_ID = "vol-0c71f9a100a8a4a93"


def prepare_document():
    return json.loads(PREPARE_DOCUMENT.read_text())


def prepare_script():
    document = prepare_document()
    return "\n".join(
        line
        for step in document["mainSteps"]
        for line in step["inputs"].get("runCommand", [])
    )


def mount_command_parameters():
    """Run attach_volume and return the parameters it sends to the document."""
    ssmclient = MagicMock()
    ec2_client = MagicMock()

    attachEBSSnapShot.attach_volume(
        ec2_client=ec2_client,
        ssmclient=ssmclient,
        fds=MagicMock(),
        ssm_mount_volume_command_id="prepare-document",
        forensic_id=FORENSIC_ID,
        forensic_instance_id=FORENSIC_INSTANCE_ID,
        volume_ids=[VOLUME_ID],
        volume_artifact_map={VOLUME_ID: "artifact-id"},
    )

    assert ssmclient.send_command.call_args is not None, (
        "attach_volume never sent the mount command, so this test would "
        "assert nothing"
    )
    return ssmclient.send_command.call_args.kwargs["Parameters"]


class TestDeviceNameSentToTheDocument:
    def test_the_device_name_is_not_a_xen_only_xvd_name(self):
        """The regression that broke every disk investigation on Nitro."""
        parameters = mount_command_parameters()
        device = parameters["volumeDeviceName"][0]

        assert not device.startswith("/dev/xvd"), (
            f"the mount targets {device}, which EC2 only ever creates on the "
            "Xen instance families; the analysis instance types are all Nitro, "
            "where this device does not exist and the mount fails"
        )

    def test_the_device_name_matches_the_name_the_volume_was_attached_at(self):
        parameters = mount_command_parameters()
        device = parameters["volumeDeviceName"][0]

        # attach_volume asks EC2 for /dev/sdg (chr(103) == 'g' for the first
        # volume), and udev provides that name on Nitro as a symlink to the
        # NVMe device. The partition suffix is what gets mounted.
        assert device == "/dev/sdg1", device

    def test_the_volume_id_is_sent_so_the_device_can_be_resolved(self):
        """The volume id is the only identifier stable across Xen and Nitro."""
        parameters = mount_command_parameters()

        assert "volumeId" in parameters, (
            "without the volume id the document cannot resolve the real device "
            "when the requested name is absent"
        )
        assert parameters["volumeId"] == [VOLUME_ID]

    def test_the_mount_point_is_not_the_working_area(self):
        """The evidence volume is mounted read-only.

        The investigation documents write their plaso storage file and csv under
        /data/forensic-analysis, so the evidence mount has to be somewhere else
        or a read-only mount would break the analysis that reads it.
        """
        parameters = mount_command_parameters()
        target = parameters["targetFolder"][0]

        assert target.startswith("/data/")
        assert not target.startswith("/data/forensic-analysis")


class TestParameterContract:
    """Both directions, as for the acquisition documents.

    A parameter the Lambda sends but the document does not declare makes SSM
    reject the whole send_command with InvalidParameters.
    """

    def test_every_sent_parameter_is_declared_by_the_document(self):
        sent = set(mount_command_parameters())
        declared = set(prepare_document().get("parameters", {}))

        undeclared = sent - declared
        assert not undeclared, (
            f"linux-disk-investigation-prepare does not declare "
            f"{sorted(undeclared)}; SSM rejects send_command with "
            "InvalidParameters when a parameter is not declared"
        )

    def test_the_document_declares_no_placeholder_it_is_not_sent(self):
        """A prose default is not a usable default."""
        sent = set(mount_command_parameters())
        declared = prepare_document().get("parameters", {})

        # The credential parameters are declared but unused by this document's
        # script, so exclude anything the script never references.
        script = prepare_script()
        filler = {
            name
            for name, spec in declared.items()
            if " " in str(spec.get("default", ""))
            and "{{ " + name + " }}" not in script
            and "{{" + name + "}}" in script
        }

        missing = filler - sent
        assert not missing, (
            f"the document substitutes {sorted(missing)} into the shell but "
            "the Lambda never sends them, so the placeholder text is used"
        )


class TestFilesystemAwareMount:
    """Assertions on the document, which cannot be driven without a live host."""

    def test_the_mount_is_no_longer_filesystem_agnostic(self):
        script = prepare_script()

        assert "blkid" in script, (
            "the script does not detect the evidence filesystem, so it cannot "
            "mount NTFS or work around a duplicate XFS UUID"
        )

    def test_ntfs_loads_the_kernel_driver_and_names_the_type(self):
        script = prepare_script()

        assert "modprobe ntfs3" in script, (
            "Amazon Linux 2023 does not load ntfs3 by default and ships no "
            "ntfs-3g, so the driver has to be loaded explicitly"
        )
        assert "mount -t ntfs3" in script, (
            "blkid reports 'ntfs' while the kernel registers 'ntfs3', so the "
            "type has to be named or the mount fails with 'unknown filesystem "
            "type'"
        )

    def test_xfs_skips_the_duplicate_uuid_check(self):
        script = prepare_script()

        assert "nouuid" in script, (
            "an evidence volume cloned from an instance built on the same AMI "
            "as the analysis host has the same XFS UUID as the host root, and "
            "XFS refuses to mount a duplicate"
        )

    @pytest.mark.parametrize("fs_type", ["ntfs", "xfs"])
    def test_each_handled_filesystem_has_its_own_branch(self, fs_type):
        script = prepare_script()

        assert f"{fs_type}" in script

    def test_evidence_is_mounted_read_only(self):
        script = prepare_script()

        # Every mount in the script carries ro. Anything else writes to
        # evidence.
        mounts = [
            line.strip()
            for line in script.splitlines()
            if line.strip().startswith("mount ")
            or line.strip().startswith("mount -")
        ]
        assert mounts, "no mount command found in the document"
        for mount in mounts:
            assert (
                "-o ro" in mount or "ro," in mount
            ), f"this mount is writable, so it can alter evidence: {mount}"

    def test_the_device_is_resolved_rather_than_assumed(self):
        script = prepare_script()

        assert "lsblk" in script, (
            "the script does not enumerate block devices, so it cannot recover "
            "when the requested device name is absent"
        )
        # The NVMe serial is the volume id with its dashes removed.
        assert "tr -d '-'" in script

    def test_a_missing_device_fails_loudly(self):
        """The mount used to be unchecked, so a failure reported Success and
        plaso then produced a header-only timeline that passed its size check.
        """
        script = prepare_script()

        assert "DISK_PREPARE_FAILED" in script
        assert "no block device for volume" in script
