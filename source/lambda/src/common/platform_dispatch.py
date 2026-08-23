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

"""Which SSM document does this instance need?

Four handlers answered that question independently - acquisition, acquisition
completion, memory analysis and disk investigation - and each copy carried its
own version of the same three mistakes:

  * **Red Hat's major version** came from three strict inequalities open at the
    lower bound (``9 > float(platform_version) > 8``), so a ``.0`` release
    matched no branch at all. The version variable was then either unbound, or -
    worse, in a loop over several instances - still holding the *previous*
    instance's value, which resolved to another release's document.
  * **the environment variable name** was built by concatenating that version,
    so a release with no deployed document raised a bare ``KeyError`` naming a
    variable rather than a problem, after work had already been started.
  * **the platform lookup** searched a list for an instance id and assigned
    inside the loop with no handling for "not found", so an instance absent from
    ``instanceInfo`` was processed as whichever instance came before it.

Fixing those one file at a time is precisely how the third and fourth copies
survived. Everything here is derived once, and
``tests/common/test_platform_dispatch.py`` asserts no handler re-derives any of
it.

The field values are what AWS actually returns, measured on live instances:
EC2 ``DescribeInstances`` reports ``PlatformDetails`` as ``Windows``,
``Red Hat Enterprise Linux`` or ``Linux/UNIX``; SSM
``DescribeInstanceInformation`` reports ``PlatformName`` as
``Microsoft Windows Server 2019 Datacenter``, ``Red Hat Enterprise Linux`` or
``Amazon Linux``. Both are present because triage starts from the EC2 record and
augments it with the SSM fields.
"""

import os
from typing import Any, Dict, List, Mapping, Optional, Union

from .log import get_logger

logger = get_logger(__name__)


class PlatformNotSupported(Exception):
    """The instance's platform has no document deployed for this workflow.

    Raised in place of ``KeyError``, ``UnboundLocalError`` and
    ``ValueError: could not convert string to float``, all of which this module
    replaced, and all of which named an implementation detail rather than the
    instance and the reason.
    """


# Workflow -> the suffix of the environment variable holding each document.
#
# The CDK derives every variable from the document's *filename*
# (forensic-ssm-document-builder-stack.ts: name.replace(HYPHEN, '_').toUpperCase()),
# which is why these are spelled out rather than generated: the Linux memory
# load document is lime-memory-load-investigation.json and therefore
# LIME_MEMORY_LOAD_INVESTIGATION with no LINUX_ prefix, while the Linux
# acquisition document is linux_lime-memory-acquisition.json and therefore
# LINUX_LIME_MEMORY_ACQUISITION with one. No rule connects the two.
DOCUMENT_ENV_VARS: Dict[str, Dict[str, str]] = {
    "MEMORY_ACQUISITION": {
        "windows": "WINDOWS_LIME_MEMORY_ACQUISITION",
        "linux": "LINUX_LIME_MEMORY_ACQUISITION",
        "rhel": "RHEL{major}_LIME_MEMORY_ACQUISITION",
    },
    "MEMORY_LOAD_INVESTIGATION": {
        "windows": "WINDOWS_LIME_MEMORY_LOAD_INVESTIGATION",
        "linux": "LIME_MEMORY_LOAD_INVESTIGATION",
        "rhel": "RHEL{major}_LIME_MEMORY_LOAD_INVESTIGATION",
    },
    "DISK_INVESTIGATION": {
        "windows": "WINDOWS_DISK_INVESTIGATION",
        "linux": "LINUX_DISK_INVESTIGATION",
        # Red Hat disk investigation uses the generic Linux document: disk
        # acquisition is snapshot based and the investigation reads a mounted
        # filesystem, so nothing about it is release specific.
        "rhel": "LINUX_DISK_INVESTIGATION",
    },
}

WINDOWS_PLATFORM_DETAIL = "Windows"
RHEL_PLATFORM_NAME = "Red Hat Enterprise Linux"


def platform_of(
    instance_info: Union[Dict[str, Any], List[Dict[str, Any]]],
    instance_id: str,
) -> Dict[str, Any]:
    """The platform record for ``instance_id``.

    ``instanceInfo`` is a single dict for an EC2 finding and a list of nodes for
    an EKS one, so both shapes are accepted. A missing instance raises rather
    than returning the wrong instance's record: the loops this replaces assigned
    inside the loop body and, on no match, silently left the previous node's
    platform in place.
    """
    if isinstance(instance_info, dict):
        # A single-instance payload. Confirm it is the instance being asked
        # about; the callers that passed a dict never checked.
        found_id = instance_info.get("InstanceId")
        if found_id and instance_id and found_id != instance_id:
            raise PlatformNotSupported(
                f"instanceInfo describes {found_id}, not {instance_id} - "
                "refusing to use another instance's platform for this one"
            )
        return instance_info

    for node in instance_info or []:
        if node.get("InstanceId") == instance_id:
            return node

    known = ", ".join(
        str(node.get("InstanceId")) for node in (instance_info or [])
    )
    raise PlatformNotSupported(
        f"{instance_id} is not described in instanceInfo (which describes "
        f"{known or 'nothing'}) - refusing to use another instance's platform "
        "for this one"
    )


def rhel_major_version(platform_version: Any) -> str:
    """Red Hat's major version, for any release string AWS reports.

    ``int(float(...))`` rather than three ranges. The ranges were open at the
    lower bound, so ``9 > float("8.0") > 8`` was false and RHEL 8.0 - a real
    release - matched none of them.
    """
    try:
        return str(int(float(platform_version)))
    except (TypeError, ValueError):
        raise PlatformNotSupported(
            f"cannot read a Red Hat major version from PlatformVersion "
            f"{platform_version!r}"
        )


def resolve_document(
    platform: Dict[str, Any],
    workflow: str,
    environ: Optional[Dict[str, str]] = None,
) -> str:
    """The document name for this platform and workflow.

    ``workflow`` is a key of :data:`DOCUMENT_ENV_VARS`. Raises
    :class:`PlatformNotSupported` naming the instance, the release and the
    variable when no document is deployed - which is what a RHEL 7 or RHEL 9
    target hits, having previously raised ``KeyError('RHEL9_...')`` after the
    workflow had already launched an instance nobody terminates.
    """
    # os.environ is a Mapping, not a dict, so bind it to a local of the widest
    # type rather than reassigning the parameter.
    variables_source: Mapping[str, str] = (
        os.environ if environ is None else environ
    )
    try:
        variables = DOCUMENT_ENV_VARS[workflow]
    except KeyError:
        raise PlatformNotSupported(f"unknown workflow {workflow!r}")

    platform_detail = platform.get("PlatformDetails")
    platform_name = platform.get("PlatformName")
    instance_id = platform.get("InstanceId", "the instance")
    described = platform_name or platform_detail or "an unknown platform"

    if platform_detail == WINDOWS_PLATFORM_DETAIL:
        env_var = variables["windows"]
    elif platform_name == RHEL_PLATFORM_NAME:
        major = rhel_major_version(platform.get("PlatformVersion"))
        env_var = variables["rhel"].format(major=major)
        described = f"Red Hat Enterprise Linux {platform.get('PlatformVersion')}"
    else:
        env_var = variables["linux"]

    document_name = variables_source.get(env_var)
    if not document_name:
        raise PlatformNotSupported(
            f"{described} on {instance_id} is not supported for "
            f"{workflow.lower().replace('_', ' ')} - {env_var} is not set, so "
            "no document is deployed for it"
        )
    logger.info(
        "resolved %s for %s to %s (%s)",
        workflow,
        instance_id,
        document_name,
        env_var,
    )
    return document_name


def is_windows(platform: Dict[str, Any]) -> bool:
    """Whether this instance is Windows, by the one field that says so."""
    return platform.get("PlatformDetails") == WINDOWS_PLATFORM_DETAIL
