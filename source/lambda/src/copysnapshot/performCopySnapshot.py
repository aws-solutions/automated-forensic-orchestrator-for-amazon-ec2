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
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Perform Instance Copy SnapShot")
def handler(event, context):
    """
    Lambda function handler for performing Disk Forensics - Perform Copy Snapshot
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

    forensic_key_id = os.environ.get("FORENSIC_EBS_KEY_ID")
    app_forensic_key_alias = os.environ.get("APP_FORENSIC_EBS_KEY_ALIAS")
    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]

    output_body = input_body.copy()
    forensic_type = input_body["forensicType"]

    app_account_id = input_body.get("instanceAccount")
    app_account_region = input_body.get("instanceRegion")
    app_account_role = os.environ["APP_ACCOUNT_ROLE"]

    is_snapshot_sharing_complete = input_body["isSnapshotShared"]

    snapshot_ids = input_body.get("snapshotIds")
    logger.info(f"current_account {current_account}")
    logger.info(f"app_account_id {app_account_id}")

    description = f"Copy Snapshot - Forensic ID {forensic_id}"

    if is_snapshot_sharing_complete:
        ec2_client = create_aws_client(
            "ec2",
        )
    else:
        ec2_client = create_aws_client(
            "ec2",
            current_account=current_account,
            target_account=app_account_id,
            target_region=app_account_region,
            app_account_role=app_account_role,
        )
        forensic_key_id = "alias/" + app_forensic_key_alias
        description = f"Copy Snapshot to be shared - Forensic ID {forensic_id}"

    try:
        forensic_record = fds.get_forensic_record(
            record_id=forensic_id, metadata_only=True
        )

        instance_id = forensic_record.resourceId
        output_body["instanceId"] = instance_id
        logger.info(
            "Taking Copy snapshot for EBS volumes {0}".format(instance_id)
        )

        copy_snapshot_ids = []
        for snapshot in snapshot_ids:
            snapshot_details = ec2_client.copy_snapshot(
                Description=description,
                Encrypted=True,
                KmsKeyId=forensic_key_id,
                SourceRegion=app_account_region,
                SourceSnapshotId=snapshot,
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [{"Key": "ForensicID", "Value": forensic_id}],
                    }
                ],
            )
            copy_snapshot_ids.append(snapshot_details.get("SnapshotId"))

        if is_snapshot_sharing_complete:
            output_body["app_snapshotIds"] = output_body["snapshotIds"]
            output_body["forensicCopysnapshotIds"] = copy_snapshot_ids
            output_body["isAppCopySnapShotComplete"] = False
            output_body["snapshotIds"] = copy_snapshot_ids
        else:
            output_body["isCopySnapShotComplete"] = False
            output_body["sourceSnapshotIds"] = snapshot_ids
            output_body["copySnapshotIds"] = copy_snapshot_ids
            output_body["snapshotIds"] = copy_snapshot_ids

        return create_response(200, output_body)

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
        ] = f"Error: creating snapshot copy for forensic id{forensic_id}"
        output_body[
            "errorDescription"
        ] = f"Error while creating snapshot {forensic_type} acquisition - Instance Copy Snapshot"
        output_body["errorPhase"] = ForensicsProcessingPhase.ACQUISITION.name
        output_body["errorComponentId"] = "performInstanceCopySnapshot"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
