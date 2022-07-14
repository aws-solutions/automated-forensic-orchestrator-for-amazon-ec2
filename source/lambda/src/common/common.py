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
