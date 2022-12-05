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

from ..common.aws_utils import resolve_artifact_metadata
from ..common.awsapi_cached_client import AWSCachedClient, create_aws_client
from ..common.common import create_response
from ..common.exception import (
    ForensicLambdaExecutionException,
    InvestigationError,
)
from ..common.log import get_logger
from ..data.datatypes import (
    ArtifactCategory,
    ArtifactStatus,
    ArtifactType,
    ForensicCategory,
    ForensicsProcessingPhase,
)
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)


@xray_recorder.capture("Check Forensic Investigation Status")
def handler(event, _):
    logger.info("Got event{}".format(event))

    region = os.environ["AWS_REGION"]
    ssmclient = AWSCachedClient(region).get_connection("ssm")
    s3_bucket_name = os.environ["S3_BUCKET_NAME"]
    s3_client = create_aws_client("s3")

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

    input_body = event["Payload"]["body"]
    forensic_id = input_body["forensicId"]

    forensic_type = input_body["forensicType"]
    try:
        # code starts here.
        output_body = input_body.copy()
        logger.info(
            "Got ForensicInstanceId {}".format(
                input_body["ForensicInvestigationInstanceId"]
            )
        )
        if ForensicCategory.MEMORY.value in input_body["forensicType"]:
            memory_investigation(
                ssmclient,
                s3_bucket_name,
                s3_client,
                fds,
                input_body,
                forensic_id,
                output_body,
            )
        else:
            disk_investigation(
                ssmclient,
                s3_bucket_name,
                s3_client,
                fds,
                input_body,
                forensic_id,
                output_body,
            )

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

        output_body["errorName"] = "Error: Check Forensic Investigation Status"
        output_body[
            "errorDescription"
        ] = f"Error while performing forensic analysis for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "checkForensicInvestigationStatus"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)


def disk_investigation(
    ssmclient,
    s3_bucket_name,
    s3_client,
    fds,
    input_body,
    forensic_id,
    output_body,
):
    command_list = input_body["ssmCommandList"]
    command_id_artifact_map = input_body["CommandIdArtifactMap"]

    logger.info(command_list)
    succeeded = []

    for command_id in command_list:
        ssm_response = ssmclient.get_command_invocation(
            CommandId=command_id,
            InstanceId=input_body["ForensicInvestigationInstanceId"],
        )
        logger.info(ssm_response)
        if ssm_response.get("StatusDetails", None) in [
            "Pending",
            "Delayed",
            "InProgress",
        ]:
            output_body["forensicAnalysisComplete"] = "FALSE"
            break
        elif ssm_response.get("StatusDetails", None) == "Success":
            handle_successful_execution(
                s3_bucket_name,
                s3_client,
                fds,
                forensic_id,
                output_body,
                command_id_artifact_map,
                succeeded,
                command_id,
            )

        elif ssm_response.get("StatusDetails", None) not in ["Success"]:
            logger.error(ssm_response)
            raise ForensicLambdaExecutionException(
                "Job execution failed. {}".format(
                    ssm_response.get("StatusDetails", None)
                )
            )

    logger.info(command_list)
    logger.info(succeeded)
    if len(succeeded) == len(command_list):
        fds.update_forensic_record_phase_status(
            id=forensic_id,
            disk=(
                ForensicsProcessingPhase.SUCCESS,
                "Completed forensic disk analysis",
            ),
        )


def handle_successful_execution(
    s3_bucket_name,
    s3_client,
    fds,
    forensic_id,
    output_body,
    command_id_artifact_map,
    succeeded,
    command_id,
):
    succeeded.append(command_id)

    output_body["forensicAnalysisComplete"] = "SUCCESS"

    artifact_location_prefix = command_id_artifact_map[command_id]["Prefix"]
    ssm_document_name = command_id_artifact_map[command_id]["SSMDocumentName"]
    input_artifact_id = command_id_artifact_map[command_id][
        "CommandInputArtifactId"
    ]

    artifact_metadata = resolve_artifact_metadata(
        s3_client, s3_bucket_name, artifact_location_prefix
    )

    for artifact in artifact_metadata:
        fds.create_forensic_artifact(
            id=forensic_id,
            phase=ForensicsProcessingPhase.INVESTIGATION,
            category=ArtifactCategory.DISK,
            type=ArtifactType.DISKANALYSIS,
            status=ArtifactStatus.SUCCESS,
            component_id="checkForensicInvestigationStatus",
            component_type="Lambda",
            ssm_document_name=ssm_document_name,
            ssm_command_id=command_id,
            input_artifact_category=ArtifactCategory.DISK,
            input_artifact_type=ArtifactType.EC2VOLUME,
            input_artifact_id=input_artifact_id,
            artifact_location=artifact.get("artifact_location"),
            artifact_size=artifact.get("artifact_size"),
            artifact_SHA256=artifact.get("sha256"),
        )


def memory_investigation(
    ssmclient,
    s3_bucket_name,
    s3_client,
    fds,
    input_body,
    forensic_id,
    output_body,
):
    command_id = input_body["MemoryInvestigation"]["CommandId"]
    command_id_artifact_map = input_body["MemoryInvestigation"][
        "CommandIdArtifactMap"
    ]
    prefix = command_id_artifact_map[command_id]["Prefix"]
    ssm_document_name = command_id_artifact_map[command_id]["SSMDocumentName"]
    input_artifact_id = command_id_artifact_map[command_id][
        "CommandInputArtifactId"
    ]

    ssm_response = ssmclient.get_command_invocation(
        CommandId=command_id,
        InstanceId=input_body["ForensicInvestigationInstanceId"],
    )
    logger.info(input_body)
    if ssm_response.get("StatusDetails", None) in [
        "Pending",
        "Delayed",
        "InProgress",
    ]:
        output_body["forensicAnalysisComplete"] = "FALSE"
    elif ssm_response.get("StatusDetails", None) == "Success":
        output_body["forensicAnalysisComplete"] = "SUCCESS"

        artifact_metadata = resolve_artifact_metadata(
            s3_client, s3_bucket_name, prefix
        )

        for artifact in artifact_metadata:
            fds.create_forensic_artifact(
                id=forensic_id,
                phase=ForensicsProcessingPhase.INVESTIGATION,
                category=ArtifactCategory.MEMORY,
                type=ArtifactType.MEMORYANALYSIS,
                status=ArtifactStatus.SUCCESS,
                component_id="checkForensicInvestigationStatus",
                component_type="Lambda",
                ssm_document_name=ssm_document_name,
                ssm_command_id=command_id,
                input_artifact_category=ArtifactCategory.MEMORY,
                input_artifact_type=ArtifactType.MEMORYDUMP,
                input_artifact_id=input_artifact_id,
                artifact_location=artifact.get("artifact_location"),
                artifact_size=artifact.get("artifact_size"),
                artifact_SHA256=artifact.get("sha256"),
            )

        fds.update_forensic_record_phase_status(
            id=forensic_id,
            memory=(
                ForensicsProcessingPhase.SUCCESS,
                "Completed forensic Memory analysis",
            ),
        )

    elif ssm_response.get("StatusDetails", None) not in ["Success"]:
        raise ForensicLambdaExecutionException(
            "Job execution failed. {}".format(
                ssm_response.get("StatusDetails", None)
            )
        )
