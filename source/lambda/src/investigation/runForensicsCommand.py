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
import uuid

from aws_xray_sdk.core import xray_recorder

from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.platform_dispatch import (
    is_windows,
    platform_of,
    resolve_document,
)
from ..common.common import (
    clean_date_format,
    create_response,
    ssm_output_log_group,
)
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..common.redact import redact
from ..common.managed_nodes import is_node_online
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


instance_id = ""


@xray_recorder.capture("Run Disk Forensics")
def handler(event, _):
    """
    Lambda function handler for performing Disk Forensics - Perform Snapshot
    """
    region = os.environ["AWS_REGION"]
    s3_bucket_name = os.environ["S3_BUCKET_NAME"]
    # The document is resolved from the instance's platform below, not defaulted
    # to Linux here. A default meant a Windows target whose platform lookup went
    # wrong ran the Linux disk investigation instead of failing.
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

    # implementation Payload
    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]
    s3_role_arn = os.environ["S3_COPY_ROLE"]
    forensic_type = input_body["forensicType"]
    output_body = input_body.copy()
    # platform_details = input_body.get("instanceInfo").get("PlatformDetails")
    # parser_id = "linux"
    # if platform_details == "Windows":
    #     parser_id = "winevt,winevtx,winprefetch"
    #     disk_investigation_document_name = os.environ[
    #         "WINDOWS_DISK_INVESTIGATION"
    #     ]
    try:
        if "clusterInfo" in input_body:
            instance_id = input_body["instanceId"][0]
        else:
            instance_id = input_body.get("instanceId")
        # platform_of raises when the instance is absent from instanceInfo. The
        # cluster branch used to assign platform_details inside its loop with no
        # else, so a node that was not described there left the name unbound and
        # the comparison below raised UnboundLocalError - after the investigation
        # instance had already been launched.
        platform = platform_of(input_body["instanceInfo"], instance_id)
        parser_id = "linux"
        if is_windows(platform):
            parser_id = "winevt,winevtx,winprefetch"
        disk_investigation_document_name = resolve_document(
            platform, "DISK_INVESTIGATION"
        )
        volume_list = input_body["forensicAttachedVolumeInfo"]
        volume_artifact_map = input_body["VolumeArtifactMap"]

        forensic_investigation_instance_id = input_body.get(
            "ForensicInvestigationInstanceId"
        )
        ssm_client = AWSCachedClient(region).get_connection("ssm")

        # Filtered and paginated via the shared lookup, and PingStatus is
        # checked. This used to call DescribeInstanceInformation unfiltered and
        # read one response - 10 nodes by default, 50 at most - so in any account
        # with more managed nodes than one page is_ssm_installed stayed False,
        # **no disk investigation command was sent at all**, and the handler
        # still returned 200: the investigation reported success having produced
        # nothing.
        is_ssm_installed = is_node_online(
            ssm_client, forensic_investigation_instance_id
        )
        logger.info(
            f"{forensic_investigation_instance_id} online: {is_ssm_installed}"
        )

        if not is_ssm_installed:
            # This used to fall past the `if` below and return 200 with no
            # ssmCommandList, so a disk investigation that sent no commands at
            # all reported success - and the missing evidence surfaced later, on
            # another host, possibly after the target was gone.
            raise InvestigationError(
                f"the forensic investigation instance "
                f"{forensic_investigation_instance_id} is not registered with "
                "Systems Manager or is not Online, so no disk investigation "
                "command can be sent to it"
            )

        ssm_cmd_list = []
        ssm_cmd_artifact_map = {}

        if is_ssm_installed:
            sts = AWSCachedClient(region).get_connection("sts")

            tokens = sts.assume_role(
                RoleArn=s3_role_arn,
                RoleSessionName="{}-s3read-copy".format(str(uuid.uuid4())),
            )["Credentials"]
            volume_number = 0
            for volume_details in volume_list:
                volume_number = volume_number + 1
                attached_volume_id = volume_details["attachedVolumeId"]
                instance_volume_mounting_point = volume_details[
                    "instanceVolumeMountingPoint"
                ]

                params = {
                    "AccessKeyId": [tokens["AccessKeyId"]],
                    "SecretAccessKey": [tokens["SecretAccessKey"]],
                    "SessionToken": [tokens["SessionToken"]],
                    "Region": [region],
                    "forensicID": [forensic_id],
                    "attachedVolumeId": [attached_volume_id],
                    "attachedVolumeMountInfo": [
                        instance_volume_mounting_point
                    ],
                    "s3Location": [
                        "s3://{0}/disk-analysis/{1}/{2}/{3}".format(
                            s3_bucket_name,
                            instance_id,
                            forensic_id,
                            attached_volume_id,
                        )
                    ],
                    "ParserID": [parser_id],
                    "TargetVolume": [f"{volume_number}"],
                }
                logger.info("ssm parameters %s", redact(params))
                response = ssm_client.send_command(
                    InstanceIds=[forensic_investigation_instance_id],
                    DocumentName=disk_investigation_document_name,
                    Comment="Disk Analysis for " + instance_id,
                    Parameters=params,
                    CloudWatchOutputConfig={
                        "CloudWatchLogGroupName": ssm_output_log_group(
                            forensic_id
                        ),
                        "CloudWatchOutputEnabled": True,
                    },
                )

                fds.add_forensic_timeline_event(
                    id=forensic_id,
                    name="Disk Investigation",
                    description="Running disk investigation commands",
                    phase=ForensicsProcessingPhase.INVESTIGATION,
                    component_id="runForensicsCommand",
                    component_type="Lambda",
                    event_data=clean_date_format(response),
                )

                cmd_id = response["Command"]["CommandId"]

                ssm_cmd_artifact_map[cmd_id] = {
                    "Prefix": "disk-analysis/{0}/{1}/{2}".format(
                        instance_id,
                        forensic_id,
                        attached_volume_id,
                    ),
                    "SSMDocumentName": disk_investigation_document_name,
                    "CommandInputArtifactId": volume_artifact_map[
                        attached_volume_id
                    ],
                }

                ssm_cmd_list.append(cmd_id)

            output_body["ssmCommandList"] = ssm_cmd_list
            output_body["CommandIdArtifactMap"] = ssm_cmd_artifact_map

            logger.info("output %s", redact(output_body))
        return create_response(200, output_body)

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body["errorName"] = (
            "Error: Forensic Investigation Run Forensic Commands"
        )
        output_body["errorDescription"] = (
            f"Error while performing forensic analysis for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "runForensicsCommand"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
