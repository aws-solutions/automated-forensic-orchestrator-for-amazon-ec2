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
from ..common.platform_dispatch import platform_of, resolve_document
from ..common.managed_nodes import is_node_online
from ..common.common import (
    clean_date_format,
    create_response,
    ssm_output_log_group,
)
from ..common.exception import InvestigationError
from ..common.log import get_logger
from ..common.redact import redact
from ..data.datatypes import ForensicsProcessingPhase
from ..data.service import ForensicDataService

# initialise loggers
logger = get_logger(__name__)

instance_id = ""

# s3ProfileDownloadURI
# OSProfile

region = os.environ["AWS_REGION"]
s3_bucket_name = os.environ["S3_BUCKET_NAME"]
# The Windows document name is no longer read here. It was resolved at import
# time, so an unset variable failed the whole module rather than the one
# investigation that needed it, and the name it held was misleading: it is the
# memory *load investigation* document, not an acquisition document.
# platform_dispatch.resolve_document reads it when a Windows target needs it.


@xray_recorder.capture("Run Memory Forensics")
def handler(event, _):
    """
    Lambda function handler for performing Memory Forensic Analysis
    """
    input_body = event["Payload"]["body"]

    if "clusterInfo" in input_body:
        for each_instance_id in input_body["ForensicInstanceIds"]:
            # platform_of raises when a node is absent from instanceInfo. The
            # loop this replaces assigned inside its inner loop and had no else,
            # so an absent node was investigated with the *previous* node's
            # platform - and therefore possibly another distribution's document
            # and symbol table - or raised UnboundLocalError on the first node.
            platform = platform_of(input_body["instanceInfo"], each_instance_id)
            output_body = perform_memory_investigation(
                each_instance_id,
                platform,
                event,
            )
        return create_response(200, output_body)
    else:
        instance_id = input_body["ForensicInstanceIds"][0]
        platform = platform_of(input_body.get("instanceInfo"), instance_id)
        output_body = perform_memory_investigation(
            instance_id,
            platform,
            event,
        )
        return create_response(200, output_body)


def perform_memory_investigation(instance_id, platform, event):
    # One resolver, shared with acquisition, completion and disk investigation.
    # This function used to derive the Red Hat major version from three ranges
    # open at the lower bound - so RHEL 8.0 matched none of them and
    # rhel_version was unbound - and then build the environment variable name by
    # concatenating it, which raised a bare KeyError for any release with no
    # deployed document. See common/platform_dispatch.py.
    memory_load_document_name = resolve_document(
        platform, "MEMORY_LOAD_INVESTIGATION"
    )
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
    logger.info("The input body is %s", redact(input_body))
    input_artifact_id = input_body["InstanceResults"][instance_id][
        "MemoryAcquisition"
    ]["CommandInputArtifactId"]
    forensic_type = input_body["forensicType"]
    output_body = input_body.copy()

    try:

        forensic_investigation_instance_id = input_body[
            "ForensicInvestigationInstanceId"
        ]
        ssm_client = create_aws_client("ssm")

        # Filtered and paginated. An unfiltered DescribeInstanceInformation
        # returns 10 managed nodes by default and 50 at most, so in any account
        # with more managed nodes than one page the freshly launched analysis
        # instance was simply absent from the response: is_ssm_installed stayed
        # False, no analysis command was ever sent, and the investigation
        # reported success having produced nothing. PingStatus is checked because
        # a registered node that is offline cannot run the analysis either.
        is_ssm_installed = is_node_online(
            ssm_client, forensic_investigation_instance_id
        )
        if not is_ssm_installed:
            # The only return used to sit inside `if is_ssm_installed:` with no
            # else, so an unreachable analysis host fell out of the function and
            # it returned None - a null Payload for the state machine, which
            # fails the next state on a missing field rather than saying the
            # analysis host could not be reached.
            raise InvestigationError(
                f"the forensic investigation instance "
                f"{forensic_investigation_instance_id} is not registered with "
                "Systems Manager or is not Online, so no memory analysis "
                "command can be sent to it"
            )

        output_body["forensicId"] = forensic_id
        output_body["ForensicInstanceId"] = instance_id
        output_body["forensicInvestigationInstanceId"] = (
            forensic_investigation_instance_id
        )

        ssm_cmd_artifact_map = {}

        if is_ssm_installed:
            sts = AWSCachedClient(region).get_connection("sts")

            tokens = sts.assume_role(
                RoleArn=s3_role_arn,
                RoleSessionName="{}-s3read-copy".format(str(uuid.uuid4())),
            )["Credentials"]

            params = {
                "AccessKeyId": [tokens["AccessKeyId"]],
                "SecretAccessKey": [tokens["SecretAccessKey"]],
                "SessionToken": [tokens["SessionToken"]],
                "Region": [region],
                "s3DownloadCommands": [
                    "aws s3 cp s3://{0}/memory/{1}/{2} . --recursive".format(
                        s3_bucket_name, instance_id, forensic_id
                    )
                ],
                "s3Bucket": [s3_bucket_name],
                "s3MemoryCaptureKey": [
                    "memory/{0}/{1}".format(instance_id, forensic_id)
                ],
                "s3ProfileBucket": [os.environ["VOLATILITY2_PROFILES_BUCKET"]],
                "s3ProfileLocation": [
                    os.environ["VOLATILITY2_PROFILES_PREFIX"]
                ],
                "forensicID": [forensic_id],
                "s3Location": [
                    "s3://{0}/memory-analysis/{1}/{2}".format(
                        s3_bucket_name, instance_id, forensic_id
                    )
                ],
            }
            response = ssm_client.send_command(
                InstanceIds=[forensic_investigation_instance_id],
                DocumentName=memory_load_document_name,
                Comment="Memory Analysis for " + instance_id,
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
                name="Memory Investigation",
                description="Running memory investigation commands",
                phase=ForensicsProcessingPhase.INVESTIGATION,
                component_id="runForensicsCommand",
                component_type="Lambda",
                event_data=clean_date_format(response),
            )

            cmd_id = response["Command"]["CommandId"]

            ssm_cmd_artifact_map[cmd_id] = {
                "Prefix": "memory-analysis/{0}/{1}".format(
                    instance_id, forensic_id
                ),
                "SSMDocumentName": memory_load_document_name,
                "CommandInputArtifactId": input_artifact_id,
            }

            output_body["InstanceResults"][instance_id][
                "MemoryInvestigation"
            ] = {}
            output_body["InstanceResults"][instance_id]["MemoryInvestigation"][
                "CommandId"
            ] = cmd_id
            output_body["InstanceResults"][instance_id]["MemoryInvestigation"][
                "CommandIdArtifactMap"
            ] = ssm_cmd_artifact_map

            logger.info("output %s", redact(output_body))
            return output_body

    except Exception as e:
        exception_type = e.__class__.__name__
        exception_message = str(e)
        exception_obj = {
            "isError": True,
            "type": exception_type,
            "message": exception_message,
        }
        logger.error(exception_obj)

        output_body["errorName"] = "Error: Memory Analysis"
        output_body["errorDescription"] = (
            f"Error while performing memory analysis for forensic id:  {forensic_id} forensic investigation instance on forensic Type : {forensic_type}"
        )
        output_body["errorPhase"] = ForensicsProcessingPhase.INVESTIGATION.name
        output_body["errorComponentId"] = "runMemoryAnalysis"
        output_body["errorComponentType"] = "Lambda"
        output_body["eventData"] = exception_message.replace('"', "-")

        raise InvestigationError(output_body)
