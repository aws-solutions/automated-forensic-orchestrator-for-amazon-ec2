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

import datetime
import json
from typing import Union

from aws_xray_sdk.core import patch_all, xray_recorder
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

patch_all()
xray_recorder.configure(context_missing="LOG_ERROR")


# Every SSM command this solution sends asks the agent to archive its output to
# CloudWatch Logs, because SSM itself only keeps the first 24 KB of stdout and
# stderr and volatility3's progress output alone exceeds that - so when a memory
# investigation fails, the part that says why is usually the part that was
# truncated away.
#
# The log group used to be named after the forensic id alone, which produced
# bare-UUID log groups that are unfindable in the console and impossible to
# scope an IAM policy to. Prefixing them means the instance roles can be granted
# logs:CreateLogGroup/CreateLogStream/PutLogEvents on this prefix and nothing
# else. Without that grant no log group is ever created and the archiving is
# silently a no-op, which is how it behaved until now.
SSM_OUTPUT_LOG_GROUP_PREFIX = "/aws/ssm/forensic-orchestrator"


def ssm_output_log_group(name: str) -> str:
    """CloudWatch log group for an SSM command's archived output.

    ``name`` is normally the forensic id, so one investigation's commands are
    grouped together.
    """
    return f"{SSM_OUTPUT_LOG_GROUP_PREFIX}/{name}"


def to_ddb_dict(pkg):
    t = TypeSerializer()
    return t.serialize(pkg)


def dict_to_object(ddb_dict):
    if ddb_dict:
        d = TypeDeserializer()
        return {k: d.deserialize(value=v) for k, v in ddb_dict.items()}
    else:
        return ddb_dict


def date_time_formater(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()


def create_response(code: int, body: Union[dict, str]):
    json_content = {
        "body": clean_date_format(body),
        "statusCode": code,
    }
    return json_content


def clean_date_format(obj):
    return json.loads(
        json.dumps(obj, sort_keys=True, indent=2, default=date_time_formater)
    )
