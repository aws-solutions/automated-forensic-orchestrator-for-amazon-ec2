###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################
import os

from aws_xray_sdk.core import xray_recorder
from botocore.config import Config
from botocore.exceptions import ClientError

from ..common.awsapi_cached_client import create_aws_client
from ..common.log import get_logger
from ..data.service import ForensicDataService

logger = get_logger(__name__)


@xray_recorder.capture("Generate Presigned URL")
def handler(event, context):
    """
    Lambda function handler for generating a presigned URL
    """
    artifact_bucket_name = os.environ["ARTIFACT_BUCKET_NAME"]

    s3_client = create_aws_client(
        "s3", custom_boto_config=Config(signature_version="s3v4")
    )

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

    forensic_id = event["arguments"]["input"]["id"]
    artifact_id = event["arguments"]["input"]["artifactId"]

    ##############
    # Retreive Artifact record from Dynamo
    ##############
    try:
        logger.info(
            "Retrieving Artifact: {0} for Forensic Record: {1}".format(
                artifact_id, forensic_id
            )
        )

        artifact_record = fds.get_forensic_artifact(forensic_id, artifact_id)

        if not artifact_record.artifactLocation:
            raise ArtifactNotFoundError(
                "Forensic Artifact does not have a corresponding file in S3"
            )

        artifact_location = artifact_record.artifactLocation

    except ArtifactNotFoundError:
        raise
    except (ValueError, ClientError):
        raise ArtifactNotFoundError("Unable to retrieve Artifact record")

    ##############
    # Generate a presigned URL for an Artifact
    ##############
    try:
        logger.info(f"Generating Presigned URL - {event}")

        response = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": artifact_bucket_name, "Key": artifact_location},
            ExpiresIn=3600,
        )
        if not response:
            raise ValueError

    except Exception as e:
        logger.error(e)
        logger.error(
            "Error while generating a presigned URL for Artifact: {0} and Forensic Record {1}".format(
                artifact_id, forensic_id
            )
        )
        raise PresignedUrlGenerationError(
            "Error generating a presigned URL for requested Artifact"
        )

    return {"id": forensic_id, "artifactId": artifact_id, "url": response}


class ArtifactNotFoundError(Exception):
    pass


class PresignedUrlGenerationError(Exception):
    pass
