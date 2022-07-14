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
from ..common.log import get_logger
from ..data.datatypes import ForensicCategory
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Forensic Send Notification")
def handler(event, _):
    """
    Lambda function handler for Send notification
    """
    logger.info("Sending notification for forensic process")
    ddb_table_name = os.environ["INSTANCE_TABLE_NAME"]
    fds = ForensicDataService(
        ddb_client=create_aws_client("dynamodb"),
        ddb_table_name=ddb_table_name,
        auto_notify_subscribers=True
        if os.environ.get("APPSYNC_API_SUBSCRIPTION_NOTIFICATIONS")
        else False,
        appsync_api_endpoint_url=os.environ.get(
            "APPSYNC_API_ENDPOINT", "API_NOT_ENABLED"
        ),
    )

    sns_client = create_aws_client("sns")

    notification_arn = os.environ["NOTIFICATION_TOPIC_ARN"]
    s3_bucket_name = os.environ["FORENSIC_BUCKET"]
    input_body = event["Payload"]["body"]
    forensic_id = input_body.get("forensicId")
    forensic_type = input_body.get("forensicType")

    forensic_record = fds.get_forensic_record(
        record_id=forensic_id, metadata_only=True
    )

    disk_analysis_status = forensic_record.diskAnalysisStatus
    memory_analysis_status = forensic_record.memoryAnalysisStatus
    ec2_instance_id = forensic_record.resourceId
    ec2_instance_account = forensic_record.awsAccountId
    message = ""
    subject_suffix = ""

    logger.info(
        f"resultStatus (DISK: {disk_analysis_status}) (MEMORY: {memory_analysis_status}) for forensic record {forensic_id}"
    )

    if forensic_type == ForensicCategory.DISK.value:
        if disk_analysis_status.value == "SUCCESS":
            message = f"Disk analysis for forensic record {forensic_id} finished successfully. \n EC2 instance {ec2_instance_id} in account {ec2_instance_account} has been isolated and analyzed. \n Forensic details are stored in s3 bucket:  {s3_bucket_name}. \n For more details on timeline kindly look into Dynamodb table : {ddb_table_name}"
            subject_suffix = "succeeded"
        elif disk_analysis_status.value == "FAILED":
            reason = forensic_record.diskAnalysisStatusDescription
            message = f"Forensic record {forensic_id} aborted due to {reason}. \n Target EC2 instance {ec2_instance_id} in account {ec2_instance_account}."
            subject_suffix = "failed"

    elif forensic_type == ForensicCategory.MEMORY.value:
        if memory_analysis_status.value == "SUCCESS":
            message = f"Memory analysis for forensic record {forensic_id} finished successfully. \n EC2 instance {ec2_instance_id} in account {ec2_instance_account} has been isolated and analyzed. \n Forensic details are stored in s3 bucket :  {s3_bucket_name}. \n For more details on timeline kindly look into Dynamodb table : {ddb_table_name}"
            subject_suffix = "succeeded"
        elif memory_analysis_status.value == "FAILED":
            reason = forensic_record.memoryAnalysisStatusDescription
            message = f"Forensic record {forensic_id} aborted due to {reason}. \n Target EC2 instance {ec2_instance_id} in account {ec2_instance_account}"
            subject_suffix = "failed"

    if message:
        sns_client.publish(
            TopicArn=notification_arn,
            Message=message,
            Subject=f"Forensic {forensic_id} {subject_suffix}",
        )

        return create_response(
            200,
            {"message": "Successfully sent notification"},
        )
    else:
        return create_response(
            200,
            {"message": "No success or failure status found"},
        )
