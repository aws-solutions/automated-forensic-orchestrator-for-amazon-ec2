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
import re
import time

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import create_aws_client
from ..common.common import create_response
from ..common.log import get_logger
from ..data.datatypes import (
    ArtifactCategory,
    ArtifactStatus,
    ArtifactType,
    ForensicsProcessingPhase,
    Volume,
)
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Attach EBS Snapshot")
def handler(event, context):
    logger.info(f"process event {event}")
    current_account = context.invoked_function_arn.split(":")[4]
    ec2_client = create_aws_client("ec2")
    ssmclient = create_aws_client("ssm")

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

    region = os.environ["AWS_REGION"]
    volume_encryption_key_id = os.environ["VOLUME_ENCRYPTION_KEY_ID"]
    ssm_mount_volume_command_id = os.environ["VOLUME_MOUNT_CMD_ID"]

    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]

    forensic_type = input_body["forensicType"]
    forensic_instance_id = input_body["ForensicInvestigationInstanceId"]

    output_body = input_body.copy()

    """
    Lambda function handler for Attaching EBS SnapShot
    """
    try:
        forensic_record = fds.get_forensic_record(
            record_id=forensic_id, metadata_only=True
        )

        logger.info(forensic_record)

        snapshot_ids = input_body["snapshotIds"]

        response = ec2_client.describe_instances(
            InstanceIds=[forensic_instance_id]
        )

        logger.info(response)

        logger.info(response["Reservations"][0]["Instances"][0])

        availability_zone = response["Reservations"][0]["Instances"][0][
            "Placement"
        ]["AvailabilityZone"]

        logger.info(f"creating volume for snapshots {snapshot_ids}")

        volume_ids = []
        volume_artifact_map = {}

        for snapshot_id in snapshot_ids:
            volume = _create_volume(
                ec2_client,
                snapshot_id,
                availability_zone,
                volume_encryption_key_id,
            )
            artifact_id = fds.create_forensic_artifact(
                id=forensic_id,
                phase=ForensicsProcessingPhase.ACQUISITION,
                category=ArtifactCategory.DISK,
                type=ArtifactType.EC2VOLUME,
                status=ArtifactStatus.CREATING,
                component_id="attachEBSSnapShot",
                component_type="Lambda",
                forensic_account_volume=Volume(
                    volume.get("VolumeId"),
                    volume.get("Size"),
                    current_account,
                    region,
                ),
                input_artifact_category=ArtifactCategory.DISK,
                input_artifact_type=ArtifactType.EC2SNAPSHOT,
                input_artifact_id=snapshot_id,
            )
            volume_ids.append(volume.get("VolumeId"))
            volume_artifact_map[volume.get("VolumeId")] = artifact_id

        output_body["VolumeArtifactMap"] = volume_artifact_map

        # TODO: can be extract as another function, just beware of function number
        logger.info(f"wait until volume is ready {volume_ids}")
        ec2_client.get_waiter("volume_available").wait(VolumeIds=volume_ids)

        for artifact_id in volume_artifact_map.values():
            fds.update_forensic_artifact(
                id=forensic_id,
                artifact_id=artifact_id,
                status=ArtifactStatus.SUCCESS,
                phase=ForensicsProcessingPhase.ACQUISITION,
                component_id="attachEBSSnapShot",
                component_type="Lambda",
            )

        # Initial performance might be slow https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-initialize.html
        forensic_attached_volume_info = [
            {
                "attachedVolumeId": vId,
                "attachedDevice": "/dev/sd" + chr(idx + 103),
            }
            for idx, vId in enumerate(volume_ids)
        ]
        for info in forensic_attached_volume_info:
            ec2_client.attach_volume(
                InstanceId=forensic_instance_id,
                DryRun=False,
                VolumeId=info.get("attachedVolumeId"),
                # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
                Device=info.get("attachedDevice"),
            )
            attached_volume_id = info.get("attachedVolumeId")
            attached_device = info.get("attachedDevice")

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Attaching volume",
                description="Attaching volume for investigation",
                phase=ForensicsProcessingPhase.INVESTIGATION,
                component_id="attachEBSSnapShot",
                component_type="Lambda",
                event_data={
                    "attachedVolumeId": attached_volume_id,
                    "attachedDevice": attached_device,
                },
            )

            volume_suffix = re.search(
                "/dev/(.+)", attached_device, re.IGNORECASE
            ).group(1)[-1]
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
            instance_attached_device = "/dev/xvd" + volume_suffix + "1"
            mounting_point = "/data" + instance_attached_device
            logger.info(
                f"waiting for volume {attached_volume_id} to become availabile"
            )
            ec2_client.get_waiter("volume_in_use").wait(
                VolumeIds=[attached_volume_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 5},
            )
            # TODO: waiter is not reliable
            time.sleep(3)
            ssmclient.send_command(
                InstanceIds=[forensic_instance_id],
                DocumentName=ssm_mount_volume_command_id,
                Comment="Mount volume",
                Parameters={
                    "targetFolder": [mounting_point],
                    "volumeDeviceName": [instance_attached_device],
                },
            )
            info["instanceVolumeMountingPoint"] = mounting_point

            fds.add_forensic_timeline_event(
                id=forensic_id,
                name="Mounting volume",
                description=f"Mounting volume: {attached_volume_id} on Forensic Instance: {forensic_instance_id}",
                phase=ForensicsProcessingPhase.INVESTIGATION,
                component_id="attachEBSSnapShot",
                component_type="Lambda",
                event_data={
                    "targetFolder": [mounting_point],
                    "volumeDeviceName": [instance_attached_device],
                },
            )

        logger.info(
            f"Update forensic info for {forensic_attached_volume_info}"
        )

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body["errorName"] = "Error: performing attach EBS Snapshot"
        output_body[
            "errorDescription"
        ] = f"Error while attaching snapshot to instance {forensic_instance_id} for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "attachEBSSnapShot"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise RuntimeError(output_body)

    output_body["forensicAttachedVolumeInfo"] = forensic_attached_volume_info
    return create_response(200, output_body)


def _create_volume(
    ec2_client, snapshot_id, availability_zone, volume_encryption_key_id
) -> str:
    response = ec2_client.create_volume(
        Encrypted=True,
        KmsKeyId=volume_encryption_key_id,
        AvailabilityZone=availability_zone,
        SnapshotId=snapshot_id,
    )
    return response
