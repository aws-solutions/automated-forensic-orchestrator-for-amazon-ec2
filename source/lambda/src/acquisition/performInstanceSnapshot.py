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
from ..data.datatypes import (
    ArtifactCategory,
    ArtifactStatus,
    ArtifactType,
    ForensicsProcessingPhase,
    Snapshot,
)
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Perform Instance SnapShot")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
    """
    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=os.environ["INSTANCE_TABLE_NAME"],
        auto_notify_subscribers=True
        if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
        else False,
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )

    current_account = context.invoked_function_arn.split(":")[4]
    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]

    output_body = input_body.copy()
    forensic_type = input_body["forensicType"]

    app_account_id = input_body.get("instanceAccount")
    app_account_region = input_body.get("instanceRegion")

    app_account_role = os.environ["APP_ACCOUNT_ROLE"]
    logger.info(f"current_account {current_account}")
    logger.info(f"app_account_id {app_account_id}")

    ec2_client = create_aws_client(
        "ec2",
        current_account=current_account,
        target_account=app_account_id,
        target_region=app_account_region,
        app_account_role=app_account_role,
    )

    try:
        forensic_record = fds.get_forensic_record(
            record_id=forensic_id, metadata_only=True
        )

        instance_id = forensic_record.resourceId
        output_body["instanceId"] = instance_id
        logger.info("Taking snapshot for EBS volumes {0}".format(instance_id))

        snapshot_details = ec2_client.create_snapshots(
            Description=f"Isolated Instance - Forensic ID: {forensic_id}",
            InstanceSpecification={
                "InstanceId": instance_id,
                "ExcludeBootVolume": False,
            },
        )

        snapshot_ids = []
        snapshot_artifact_map = {}

        for snapshot in snapshot_details.get("Snapshots"):
            artifact_id = fds.create_forensic_artifact(
                id=forensic_id,
                phase=ForensicsProcessingPhase.ACQUISITION,
                category=ArtifactCategory.DISK,
                type=ArtifactType.EC2SNAPSHOT,
                status=ArtifactStatus.CREATING,
                component_id="performInstanceSnapshot",
                component_type="Lambda",
                source_account_snapshot=Snapshot(
                    snapshot.get("SnapshotId"),
                    snapshot.get("VolumeId"),
                    snapshot.get("VolumeSize"),
                    app_account_id,
                    app_account_region,
                ),
            )
            snapshot_ids.append(snapshot.get("SnapshotId"))

            snapshot_artifact_map[snapshot.get("SnapshotId")] = artifact_id

        output_body["isSnapShotComplete"] = False
        output_body["snapshotIds"] = snapshot_ids
        output_body["snapshotArtifactMap"] = snapshot_artifact_map
        output_body["isSnapshotShared"] = False

    except Exception as e:
        logger.error(e)
        logger.error(
            f"Error while creating snapshot for forensic id :{forensic_id}"
        )
        forensic_id = input_body.get("forensicId")
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body[
            "errorName"
        ] = f"Error: creating snapshot for forensic id{forensic_id}"
        output_body[
            "errorDescription"
        ] = f"Error while creating snapshot {forensic_type} acquisition - Instance Snapshot"
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "performInstanceSnapshot"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise DiskAcquisitionError(output_body)

    return create_response(200, output_body)
