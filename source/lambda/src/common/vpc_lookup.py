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

"""Which subnet does a forensic instance launch into?

Three handlers - the analysis instance, the symbol builder and the deploy-time
tools loader - each found it by filtering on the ``aws-cdk:subnet-name`` tag and
then indexing ``["Subnets"][0]``.

That tag exists because this solution's own VPC is built by the CDK with a subnet
group named ``service``. It does **not** exist when the solution is pointed at an
existing VPC, which is a documented deployment mode: ``isExistingVPC`` with
``vpcID`` resolves the VPC through ``Vpc.fromLookup``, and the customer's subnets
were not created by this app. The filter then matches nothing, ``Subnets`` is
empty, and all three handlers raised ``IndexError: list index out of range`` -
which names neither the tag, nor the VPC, nor the deployment mode that caused it.

The choice is also made deterministic here. One subnet per availability zone
matches the filter, and taking whichever the API listed first let the launch AZ
vary between runs of the same workflow.
"""

from typing import Any, Dict, List

from .log import get_logger

logger = get_logger(__name__)

SUBNET_NAME_TAG = "tag:aws-cdk:subnet-name"
DEFAULT_SUBNET_GROUP = "service"


class SubnetNotFound(Exception):
    """No subnet in this VPC carries the subnet-group tag being looked for."""


def forensic_subnet_id(
    ec2_client,
    vpc_id: str,
    subnet_group: str = DEFAULT_SUBNET_GROUP,
) -> str:
    """The id of the subnet tagged ``subnet_group`` in ``vpc_id``.

    Raises :class:`SubnetNotFound` naming the VPC, the tag and the value when
    nothing matches, rather than raising ``IndexError`` from an empty list.
    """
    response = ec2_client.describe_subnets(
        Filters=[
            {"Name": SUBNET_NAME_TAG, "Values": [subnet_group]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ],
        DryRun=False,
    )
    subnets: List[Dict[str, Any]] = response.get("Subnets") or []
    if not subnets:
        raise SubnetNotFound(
            f"no subnet in {vpc_id} is tagged aws-cdk:subnet-name="
            f"{subnet_group}, so there is nowhere to launch a forensic "
            "instance. When this solution creates its own VPC that tag is "
            "applied automatically; when it is pointed at an existing VPC with "
            "isExistingVPC, tag the subnet you want forensic instances to use "
            f"with aws-cdk:subnet-name={subnet_group}"
        )

    # Deterministic: one subnet per availability zone matches, and the API does
    # not promise an order.
    chosen = sorted(
        subnets, key=lambda s: (s.get("AvailabilityZone") or "", s["SubnetId"])
    )[0]
    if len(subnets) > 1:
        logger.info(
            "%d subnets are tagged %s in %s; using %s in %s",
            len(subnets),
            subnet_group,
            vpc_id,
            chosen["SubnetId"],
            chosen.get("AvailabilityZone", "an unreported AZ"),
        )
    return chosen["SubnetId"]
