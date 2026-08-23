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

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.exception import DiskAcquisitionError
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Share Snap Shot")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Share Snapshot
    """

    app_account_role = os.environ["APP_ACCOUNT_ROLE"]
    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    forensic_type = input_body["forensicType"]
    app_account_id = input_body.get("instanceAccount")
    app_account_region = input_body.get("instanceRegion")

    forensic_id = input_body.get("forensicId")
    current_account = context.invoked_function_arn.split(":")[4]

    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=(
            True
            if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
            else False
        ),
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )

    try:
        if app_account_id != current_account:
            ec2_client = create_aws_client(
                "ec2",
                current_account=current_account,
                target_account=app_account_id,
                target_region=app_account_region,
                app_account_role=app_account_role,
            )
            if "clusterInfo" in input_body:
                for instance_id in input_body.get("clusterInfo").get(
                    "affectedNode"
                ):
                    if (
                        isinstance(input_body[instance_id], dict)
                        and "snapshotIds" in input_body[instance_id]
                    ):
                        instance_data = input_body[instance_id]
                        snapshot_ids = instance_data.get("snapshotIds")
                        snapshot_artifact_map = instance_data.get(
                            "snapshotArtifactMap"
                        )
                        input_body[instance_id][
                            "snapshotIdsShared"
                        ] = snapshot_ids
                        input_body[instance_id][
                            "snapshotArtifactMap"
                        ] = snapshot_artifact_map
                        for snapshot_id in snapshot_ids:
                            response = _share_snapshot(
                                ec2_client=ec2_client,
                                target_account_id=app_account_id,
                                snapshot_id=snapshot_id,
                                solution_account=current_account,
                            )

                            logger.info(response)

                            fds.update_forensic_artifact(
                                id=forensic_id,
                                artifact_id=snapshot_artifact_map[snapshot_id],
                                phase=ForensicsProcessingPhase.ACQUISITION,
                                component_id="shareSnapShot",
                                component_type="Lambda",
                            )

                            fds.add_forensic_timeline_event(
                                id=forensic_id,
                                name="Sharing snapshot",
                                description="Sharing snapshot to Forensic Account",
                                phase=ForensicsProcessingPhase.ACQUISITION,
                                component_id="shareSnapShot",
                                component_type="Lambda",
                                event_data={
                                    "forensicId": forensic_id,
                                    "snapshotId": snapshot_id,
                                    "sourceAccount": app_account_id,
                                    "solutionAccount": current_account,
                                },
                            )
                    output_body[instance_id]["isSnapshotShared"] = True
            else:

                snapshot_ids = input_body.get("snapshotIds")
                snapshot_artifact_map = input_body.get("snapshotArtifactMap")
                output_body["snapshotIdsShared"] = snapshot_ids
                output_body["snapshotArtifactMap"] = snapshot_artifact_map
                for snapshot_id in snapshot_ids:
                    response = _share_snapshot(
                        ec2_client=ec2_client,
                        target_account_id=app_account_id,
                        snapshot_id=snapshot_id,
                        solution_account=current_account,
                    )

                    logger.info(response)

                    fds.add_forensic_timeline_event(
                        id=forensic_id,
                        name="Sharing snapshot",
                        description="Sharing snapshot to Forensic Account",
                        phase=ForensicsProcessingPhase.ACQUISITION,
                        component_id="shareSnapShot",
                        component_type="Lambda",
                        event_data={
                            "forensicId": forensic_id,
                            "snapshotId": snapshot_id,
                            "sourceAccount": app_account_id,
                            "solutionAccount": current_account,
                        },
                    )

            output_body["appAccount"] = app_account_id
            output_body["isSnapshotShared"] = True
        else:
            # Same-account deployment: the snapshot is already visible to the
            # forensic account because it *is* the application account, so there
            # is nothing to share and no ModifySnapshotAttribute to make.
            #
            # The flag still has to be set. Downstream it is a phase marker, not
            # a record of an API call: performCopySnapshot and
            # checkCopySnapShotStatus both branch on it to decide whether they
            # are working in the application account or the forensic one, and
            # the "Is Copy SnapShot Complete" choice reads
            # $.Payload.body.isSnapShotCopyComplete, which the checker only
            # writes on the sharing-complete branch. Leaving it False made every
            # single-account disk acquisition fail at that choice with
            # States.Runtime "invalid path", after the snapshot had already been
            # taken and copied.
            output_body["appAccount"] = app_account_id
            output_body["isSnapshotShared"] = True
            if "clusterInfo" in input_body:
                for instance_id in input_body.get("clusterInfo").get(
                    "affectedNode"
                ):
                    if isinstance(output_body.get(instance_id), dict):
                        output_body[instance_id]["isSnapshotShared"] = True

    except Exception as e:
        logger.error(e)

        logger.error(
            f"Error while sharing snapshot for forensic id :{forensic_id}"
        )
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body["errorName"] = (
            f"Error: sharing snapshot for forensic id:{forensic_id} of type {forensic_type}"
        )
        output_body["errorDescription"] = (
            f"Error while sharing snapshot for forensic id:{forensic_id}t"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "shareSnapShot"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise DiskAcquisitionError(output_body)

    return create_response(
        200,
        output_body,
    )


def _share_snapshot(
    ec2_client, target_account_id, snapshot_id, solution_account
):

    return ec2_client.modify_snapshot_attribute(
        Attribute="createVolumePermission",
        CreateVolumePermission={
            "Add": [
                {"UserId": solution_account},
            ]
        },
        OperationType="add",
        SnapshotId=snapshot_id,
        UserIds=[target_account_id],
        DryRun=False,
    )
