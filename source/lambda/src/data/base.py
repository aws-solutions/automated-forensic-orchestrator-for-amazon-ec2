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

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from .exceptions import AlreadyExistsException, DoesNotExistException


class ForensicDynamoDBService:
    def __init__(self, ddb_client, ddb_table_name):
        self.client = ddb_client
        self.table = ddb_table_name
        self._deserialiser = TypeDeserializer()
        self._serialiser = TypeSerializer()

    def deserialize(self, service_object):
        return {
            k: self._deserialiser.deserialize(v)
            for k, v in service_object.items()
        }

    def serialize(self, python_object):
        return {
            k: self._serialiser.serialize(v) for k, v in python_object.items()
        }

    def filter_attributes(self, item, attributes_to_remove):
        return {k: v for k, v in item.items() if k not in attributes_to_remove}

    def _get_metadata_query_item(self, type_prefix, items):
        for item in items:
            if item["SK"].startswith(type_prefix):
                return item
        return None

    def _get_item(
        self, type_prefix, id, subtype_prefix, subtype_id, subtype_suffix=""
    ):
        response = self.client.get_item(
            TableName=self.table,
            Key={
                "PK": {"S": f"{type_prefix}{id}"},
                "SK": {"S": f"{subtype_prefix}{subtype_id}{subtype_suffix}"},
            },
        )

        result = self.deserialize(response.get("Item", {}))

        # Check for empty or expired / deleted item
        if not result:
            raise DoesNotExistException(
                f"Resource with id {id} does not exist or has been deleted."
            )

        return result

    def _query(self, type_prefix, id, check_metadata_item=True):
        response = self.client.query(
            TableName=self.table,
            KeyConditionExpression="PK = :PK",
            ExpressionAttributeValues={
                ":PK": {"S": f"{type_prefix}{id}"},
            },
        )

        result = [self.deserialize(item) for item in response.get("Items", [])]

        # Make sure that top-level item exists
        if (
            check_metadata_item
            and self._get_metadata_query_item(type_prefix, result) is None
        ):
            raise DoesNotExistException(
                f"Resource with id {id} does not exist or has been deleted."
            )

        return result

    def _create(self, item):
        try:
            response = self.client.put_item(
                TableName=self.table,
                Item=self.serialize(item),
                ConditionExpression="attribute_not_exists(PK)",
            )
        except self.client.exceptions.ConditionalCheckFailedException as e:
            # Resource already exists
            raise AlreadyExistsException from e

        return self.deserialize(response.get("Attributes", {}))

    def _get_update_expression(
        self,
        type_prefix,
        id,
        subtype_prefix,
        subtype_id,
        new_attributes,
        subtype_suffix="",
        is_transaction=False,
    ):
        attribute_names = {}
        attribute_values = {}
        update_expressions = []

        # Generate placeholder values and update expressions based on input attributes
        for i, (k, v) in enumerate(self.serialize(new_attributes).items()):
            attr_name = f"#N{i}"
            attr_val = f":v{i}"
            attribute_names[attr_name] = k
            attribute_values[attr_val] = v
            update_expressions.append(f"{attr_name} = {attr_val}")

        exp = {
            "TableName": self.table,
            "Key": {
                "PK": {"S": f"{type_prefix}{id}"},
                "SK": {"S": f"{subtype_prefix}{subtype_id}{subtype_suffix}"},
            },
            "ConditionExpression": "attribute_exists(PK)",
            "ExpressionAttributeNames": attribute_names,
            "ExpressionAttributeValues": attribute_values,
            "UpdateExpression": f"SET {', '.join(update_expressions)}",
        }

        if not is_transaction:
            exp["ReturnValues"] = "ALL_NEW"

        return exp

    def _get_list_append_expression(
        self,
        type_prefix,
        id,
        subtype_prefix,
        subtype_id,
        new_attributes,
        subtype_suffix="",
        is_transaction=False,
    ):
        attribute_names = {}
        attribute_values = {}
        update_expressions = []
        condition_expressions = []
        condition_expressions.append("(attribute_exists(PK))")

        empty_list = {}

        # Generate placeholder values and update expressions based on input attributes
        for i, (k, v) in enumerate(self.serialize(new_attributes).items()):
            attr_name = f"#N{i}"
            attr_val = f":v{i}"
            attribute_names[attr_name] = k
            attribute_values[attr_val] = v
            if isinstance(attr_val, list):
                update_expressions.append(
                    f"{attr_name} = list_append(if_not_exists({attr_name}, :empty_list),:{attr_val})"
                )
                condition_expressions.append(
                    f"(NOT contains({attr_name}, {attr_val}))"
                )
                empty_list = {
                    ":empty_list": {"L": []},
                }
            else:
                update_expressions.append(f"{attr_name} = {attr_val}")

        exp = {
            "TableName": self.table,
            "Key": {
                "PK": {"S": f"{type_prefix}{id}"},
                "SK": {"S": f"{subtype_prefix}{subtype_id}{subtype_suffix}"},
            },
            "ConditionExpression": f"{' and '.join(condition_expressions)}",
            "ExpressionAttributeNames": attribute_names,
            "ExpressionAttributeValues": {
                **attribute_values,
                **empty_list,
            },
            "UpdateExpression": f"SET {', '.join(update_expressions)}",
        }

        if not is_transaction:
            exp["ReturnValues"] = "ALL_NEW"

        return exp

    def _update(
        self,
        type_prefix,
        id,
        subtype_prefix,
        subtype_id,
        new_attributes,
        subtype_suffix="",
    ):
        try:
            response = self.client.update_item(
                **self._get_update_expression(
                    type_prefix=type_prefix,
                    id=id,
                    subtype_prefix=subtype_prefix,
                    subtype_id=subtype_id,
                    new_attributes=new_attributes,
                    subtype_suffix=subtype_suffix,
                )
            )
        except self.client.exceptions.ConditionalCheckFailedException as e:
            raise DoesNotExistException(
                f"Resource with ID {id} does not exist."
            ) from e

        return self.deserialize(response.get("Attributes", {}))
