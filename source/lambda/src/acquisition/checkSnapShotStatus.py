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
from ..data.datatypes import ArtifactStatus, ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Check Snapshot Status")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot Completion status
    """
    current_account = context.invoked_function_arn.split(":")[4]
    input_body = event["Payload"]["body"]
    output_body = input_body.copy()
    forensic_type = input_body["forensicType"]

    app_account_id = input_body.get("instanceAccount")
    app_account_region = input_body.get("instanceRegion")
    app_account_role = os.environ["APP_ACCOUNT_ROLE"]

    forensic_id = input_body.get("forensicId")

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

    ec2_client = create_aws_client(
        "ec2",
        current_account=current_account,
        target_account=app_account_id,
        target_region=app_account_region,
        app_account_role=app_account_role,
    )

    try:
        snapshot_ids = input_body.get("snapshotIds")
        snapshot_artifact_map = input_body.get("snapshotArtifactMap")

        snapshots = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)

        snapshots_complete = all_snapshots_completed(snapshots)
        output_body["isSnapShotComplete"] = snapshots_complete
        output_body["snapshotIds"] = snapshot_ids
        output_body["snapshotArtifactMap"] = snapshot_artifact_map

        for snapshot in snapshots.get("Snapshots"):
            if snapshot.get("State") == "completed":
                fds.update_forensic_artifact(
                    id=forensic_id,
                    artifact_id=snapshot_artifact_map[
                        snapshot.get("SnapshotId")
                    ],
                    status=ArtifactStatus.SUCCESS,
                    phase=ForensicsProcessingPhase.ACQUISITION,
                    component_id="checkSnapShotStatus",
                    component_type="Lambda",
                )

        return create_response(200, output_body)

    except Exception as e:
        logger.error(e)
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
        ] = f"Error: checking snapshot status for forensic id{forensic_id}"
        output_body[
            "errorDescription"
        ] = f"Error while checking snapshot status {forensic_type} acquisition - Instance Snapshot"
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "checkSnapShotStatus"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise DiskAcquisitionError(output_body)


def all_snapshots_completed(snapshots) -> bool:
    return all(
        element.get("State") == "completed"
        for element in snapshots["Snapshots"]
    )
