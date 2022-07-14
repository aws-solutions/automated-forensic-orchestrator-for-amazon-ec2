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

import inspect
import json
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests
from aws_xray_sdk.core import xray_recorder
from boto3 import Session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from ..common.common import date_time_formater
from ..common.log import get_logger
from .base import ForensicDynamoDBService
from .datatypes import (
    ArtifactCategory,
    ArtifactStatus,
    ArtifactType,
    Finding,
    ForensicArtifact,
    ForensicRecord,
    ForensicsProcessingPhase,
    ForensicTimelineEvent,
    ResourceType,
    Snapshot,
    Volume,
)


class ForensicDataService(ForensicDynamoDBService):
    """Class for Forensic Orchestrator data operations ."""

    _record_prefix = "RECORD#"
    _artifact_type_prefix = "ARTIFACT#"
    _event_type_prefix = "EVENT#"
    _metadata_prefix = "#METADATA"

    _attribute_filter = ["PK", "SK", "GSI1PK", "GSI1SK"]

    def __init__(
        self,
        ddb_client,
        ddb_table_name,
        auto_notify_subscribers,
        appsync_api_endpoint_url,
    ):
        super().__init__(ddb_client, ddb_table_name)

        self._auto_notify_subscribers = auto_notify_subscribers
        self._appsync_api_endpoint_url = appsync_api_endpoint_url
        self._logger = get_logger(__name__)

    @xray_recorder.capture("get_forensic_record")
    def get_forensic_record(
        self, record_id: str, metadata_only: bool = False
    ) -> ForensicRecord:
        try:
            response = (
                self._get_item(
                    self._record_prefix,
                    record_id,
                    self._record_prefix,
                    record_id,
                    self._metadata_prefix,
                )
                if metadata_only
                else self._query(self._record_prefix, record_id, metadata_only)
            )
        except Exception:
            raise

        if metadata_only:
            return self._unpack_dict_to_dataclass(
                ForensicRecord,
                self.filter_attributes(response, self._attribute_filter),
            )

        record = {}
        artifacts = []
        timeline = []
        for item in response:
            if item["SK"].startswith(self._record_prefix):
                record = self.filter_attributes(item, self._attribute_filter)
            elif item["SK"].startswith(self._artifact_type_prefix):
                artifacts.append(
                    self.filter_attributes(item, self._attribute_filter)
                )
            elif item["SK"].startswith(self._event_type_prefix):
                timeline.append(
                    self.filter_attributes(item, self._attribute_filter)
                )

        record["artifacts"] = artifacts
        record["timeline"] = timeline

        return self._unpack_dict_to_dataclass(ForensicRecord, record)

    @xray_recorder.capture("get_forensic_artifact")
    def get_forensic_artifact(
        self, record_id: str, artifact_id: str
    ) -> ForensicArtifact:
        try:
            response = self._get_item(
                self._record_prefix,
                record_id,
                self._artifact_type_prefix,
                artifact_id,
            )
        except Exception:
            raise

        return self._unpack_dict_to_dataclass(
            ForensicArtifact,
            self.filter_attributes(response, self._attribute_filter),
        )

    @xray_recorder.capture("create_forensic_record")
    def create_forensic_record(
        self,
        resource_type: ResourceType,
        resource_id: str,
        aws_account_id: str,
        aws_region: str,
        resource_info: dict = None,
        associated_findings: List[Finding] = None,
    ) -> ForensicRecord:
        record_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        item: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{record_id}",
            "SK": f"{self._record_prefix}{record_id}{self._metadata_prefix}",
            "GSI1PK": aws_account_id,
            "GSI1SK": f"#REGION#{aws_region}#{resource_type.value}#{resource_id}",
            "id": record_id,
            "resourceType": resource_type.value,
            "resourceId": resource_id,
            "awsAccountId": aws_account_id,
            "awsRegion": aws_region,
            "creationTime": now,
            "lastUpdatedTime": now,
            "triageStatus": ForensicsProcessingPhase.TRIAGE.value,
            "triageStatusDescription": "Triage initiated",
            "memoryAnalysisStatus": ForensicsProcessingPhase.TRIAGE.value,
            "memoryAnalysisStatusDescription": "Waiting for Triage completion",
            "diskAnalysisStatus": ForensicsProcessingPhase.TRIAGE.value,
            "diskAnalysisStatusDescription": "Waiting for Triage completion",
        }
        if associated_findings:
            item["associatedFindings"] = [
                asdict(finding) for finding in associated_findings
            ]
        if resource_info:
            item["resourceInfo"] = resource_info

        try:
            self._create(item)
        except Exception:
            raise

        return self._unpack_dict_to_dataclass(
            ForensicRecord,
            self.filter_attributes(item, self._attribute_filter),
        )

    @xray_recorder.capture("create_failed_forensic_record")
    def create_failed_forensic_record(self, event_data) -> ForensicRecord:
        record_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{record_id}",
            "SK": f"{self._record_prefix}{record_id}{self._metadata_prefix}",
            "id": record_id,
            "resourceType": ResourceType.INSTANCE.value,
            "resourceId": "Unknown",
            "awsAccountId": "Unknown",
            "awsRegion": "Unknown",
            "creationTime": now,
            "lastUpdatedTime": now,
            "triageStatus": ForensicsProcessingPhase.FAILED.value,
            "triageStatusDescription": "Failed to process Forensic Orchestrator trigger event - Triage",
            "memoryAnalysisStatus": ForensicsProcessingPhase.FAILED.value,
            "memoryAnalysisStatusDescription": "Failed to process Forensic Orchestrator trigger event - Memory Analysis",
            "diskAnalysisStatus": ForensicsProcessingPhase.FAILED.value,
            "diskAnalysisStatusDescription": "Failed to process Forensic Orchestrator trigger event - Disk Analysis",
        }

        event: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{record_id}",
            "SK": f"{self._event_type_prefix}{now}#{event_id}",
            "id": event_id,
            "forensicId": record_id,
            "name": "Error: Triaging Instance",
            "description": "Error while processing Forensic Orchestrator trigger event",
            "phase": ForensicsProcessingPhase.FAILED.value,
            "componentId": "triage",
            "componentType": "Lambda",
            "creationTime": now,
            "eventData": event_data,
        }

        commands = []

        commands.append(
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self.serialize(record),
                }
            }
        )

        commands.append(
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self.serialize(event),
                }
            }
        )

        self.client.transact_write_items(TransactItems=commands)

        return self._unpack_dict_to_dataclass(
            ForensicRecord,
            self.filter_attributes(record, self._attribute_filter),
        )

    @xray_recorder.capture("update_forensic_record_phase")
    def update_forensic_record_phase_status(
        self,
        id: str,
        triage: Tuple[ForensicsProcessingPhase, str] = None,
        memory: Tuple[ForensicsProcessingPhase, str] = None,
        disk: Tuple[ForensicsProcessingPhase, str] = None,
    ) -> ForensicRecord:
        now = datetime.now(timezone.utc).isoformat()

        update_item: Dict[str, Any] = {
            "lastUpdatedTime": now,
        }

        if triage:
            update_item["triageStatus"] = triage[0].value
            update_item["triageStatusDescription"] = triage[1]
        if memory:
            update_item["memoryAnalysisStatus"] = memory[0].value
            update_item["memoryAnalysisStatusDescription"] = memory[1]
        if disk:
            update_item["diskAnalysisStatus"] = disk[0].value
            update_item["diskAnalysisStatusDescription"] = disk[1]

        try:
            result = self._update(
                type_prefix=self._record_prefix,
                id=id,
                subtype_prefix=self._record_prefix,
                subtype_id=id,
                new_attributes=update_item,
                subtype_suffix=self._metadata_prefix,
            )
        except Exception:
            raise

        if self._auto_notify_subscribers:
            self._notify_subscribers_forensic_record(
                forensic_record=self.filter_attributes(
                    result, self._attribute_filter
                )
            )

        return self._unpack_dict_to_dataclass(
            ForensicRecord,
            self.filter_attributes(result, self._attribute_filter),
        )

    @xray_recorder.capture("update_forensic_record_resource_info")
    def update_forensic_record_resource_info(
        self,
        id: str,
        resource_info: dict,
    ) -> ForensicRecord:
        now = datetime.now(timezone.utc).isoformat()

        update_item: Dict[str, Any] = {
            "lastUpdatedTime": now,
            "resourceInfo": resource_info,
        }

        try:
            result = self._update(
                type_prefix=self._record_prefix,
                id=id,
                subtype_prefix=self._record_prefix,
                subtype_id=id,
                new_attributes=update_item,
                subtype_suffix=self._metadata_prefix,
            )
        except Exception:
            raise

        if self._auto_notify_subscribers:
            self._notify_subscribers_forensic_record(
                forensic_record=self.filter_attributes(
                    result, self._attribute_filter
                )
            )

        return self._unpack_dict_to_dataclass(
            ForensicRecord,
            self.filter_attributes(result, self._attribute_filter),
        )

    @xray_recorder.capture("add_forensic_timeline_event")
    def add_forensic_timeline_event(
        self,
        id: str,
        name: str,
        description: str,
        phase: ForensicsProcessingPhase,
        component_id: str,
        component_type: str,
        artifact: ForensicArtifact = None,
        event_data: dict = None,
    ) -> ForensicTimelineEvent:

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        forensic_event: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{id}",
            "SK": f"{self._event_type_prefix}{now}#{event_id}",
            "id": event_id,
            "forensicId": id,
            "name": name,
            "description": description,
            "phase": phase.value,
            "componentId": component_id,
            "componentType": component_type,
            "creationTime": now,
        }
        if artifact:
            forensic_event["artifact"] = asdict(artifact)
        if event_data:
            forensic_event["eventData"] = event_data

        try:
            self._create(forensic_event)
        except Exception:
            raise

        if self._auto_notify_subscribers:
            self._notify_subscribers_timeline_event(
                forensic_event=self.filter_attributes(
                    forensic_event, self._attribute_filter
                )
            )

        return self._unpack_dict_to_dataclass(
            ForensicTimelineEvent,
            self.filter_attributes(forensic_event, self._attribute_filter),
        )

    @xray_recorder.capture("create_forensic_artifact")
    def create_forensic_artifact(
        self,
        id: str,
        phase: ForensicsProcessingPhase,
        category: ArtifactCategory,
        type: ArtifactType,
        status: ArtifactStatus,
        component_id: str,
        component_type: str,
        source_account_snapshot: Snapshot = None,
        forensic_account_snapshot: Snapshot = None,
        forensic_account_volume: Volume = None,
        input_artifact_category: ArtifactCategory = None,
        input_artifact_type: ArtifactType = None,
        input_artifact_id: str = None,
        ssm_document_name: str = None,
        ssm_command_id: str = None,
        artifact_location: str = None,
        artifact_size: int = None,
        artifact_SHA256: str = None,
    ) -> str:

        artifact_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())

        now = datetime.now(timezone.utc).isoformat()

        commands = []

        forensic_record_update: Dict[str, Any] = {
            "lastUpdatedTime": now,
        }

        if source_account_snapshot:
            forensic_record_update["sourceAccountSnapshots"] = [
                asdict(source_account_snapshot)
            ]
            commands.append(
                {
                    "Update": self._get_list_append_expression(
                        type_prefix=self._record_prefix,
                        id=id,
                        subtype_prefix=self._record_prefix,
                        subtype_id=id,
                        new_attributes=forensic_record_update,
                        subtype_suffix=self._metadata_prefix,
                        is_transaction=True,
                    )
                }
            )
        elif forensic_account_snapshot:
            forensic_record_update["forensicAccountSnapshots"] = [
                asdict(forensic_account_snapshot)
            ]
            commands.append(
                {
                    "Update": self._get_list_append_expression(
                        type_prefix=self._record_prefix,
                        id=id,
                        subtype_prefix=self._record_prefix,
                        subtype_id=id,
                        new_attributes=forensic_record_update,
                        subtype_suffix=self._metadata_prefix,
                        is_transaction=True,
                    )
                }
            )

        elif forensic_account_volume:
            forensic_record_update["forensicAccountVolumes"] = [
                asdict(forensic_account_volume)
            ]
            commands.append(
                {
                    "Update": self._get_list_append_expression(
                        type_prefix=self._record_prefix,
                        id=id,
                        subtype_prefix=self._record_prefix,
                        subtype_id=id,
                        new_attributes=forensic_record_update,
                        subtype_suffix=self._metadata_prefix,
                        is_transaction=True,
                    )
                }
            )

        artifact: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{id}",
            "SK": f"{self._artifact_type_prefix}{artifact_id}",
            "id": artifact_id,
            "forensicId": id,
            "category": category.value,
            "type": type.value,
            "componentId": component_id,
            "componentType": component_type,
            "status": status.value,
            "creationTime": now,
            "lastUpdatedTime": now,
        }

        if source_account_snapshot:
            artifact["snapshot"] = asdict(source_account_snapshot)
        elif forensic_account_snapshot:
            artifact["snapshot"] = asdict(forensic_account_snapshot)
        if forensic_account_volume:
            artifact["volume"] = asdict(forensic_account_volume)
        if input_artifact_category:
            artifact["inputArtifactCategory"] = input_artifact_category.value
        if input_artifact_type:
            artifact["inputArtifactType"] = input_artifact_type.value
        if input_artifact_id:
            artifact["inputArtifactId"] = input_artifact_id
        if ssm_document_name:
            artifact["ssmDocumentName"] = ssm_document_name
        if ssm_command_id:
            artifact["ssmCommandId"] = ssm_command_id
        if artifact_location:
            artifact["artifactLocation"] = artifact_location
        if artifact_size:
            artifact["artifactSize"] = artifact_size
        if artifact_SHA256:
            artifact["artifactSHA256"] = artifact_SHA256

        commands.append(
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self.serialize(artifact),
                }
            }
        )

        forensic_event: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{id}",
            "SK": f"{self._event_type_prefix}{now}#{event_id}",
            "id": event_id,
            "forensicId": id,
            "name": "Artifact creation started",
            "description": "Creation of a forensics artifact has been initiated by Forensics Orchestrator",
            "phase": phase.value,
            "componentId": component_id,
            "componentType": component_type,
            "creationTime": now,
            "artifact": self.filter_attributes(
                artifact, self._attribute_filter
            ),
        }

        commands.append(
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self.serialize(forensic_event),
                }
            }
        )

        self.client.transact_write_items(TransactItems=commands)

        if self._auto_notify_subscribers:
            self._notify_subscribers_artifact(
                artifact=self.filter_attributes(
                    artifact, self._attribute_filter
                )
            )
            self._notify_subscribers_timeline_event(
                forensic_event=self.filter_attributes(
                    forensic_event, self._attribute_filter
                )
            )

        return artifact_id

    @xray_recorder.capture("update_forensic_artifact")
    def update_forensic_artifact(
        self,
        id: str,
        artifact_id: str,
        phase: ForensicsProcessingPhase,
        component_id: str,
        component_type: str,
        status: ArtifactStatus = None,
        artifact_location: str = None,
        artifact_size: int = None,
        artifact_SHA256: str = None,
    ) -> bool:

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        commands = []

        forensic_artifact_update: Dict[str, Any] = {
            "lastUpdatedTime": now,
        }

        if status:
            forensic_artifact_update["status"] = status.value
        if artifact_location:
            forensic_artifact_update["artifactLocation"] = artifact_location
        if artifact_size:
            forensic_artifact_update["artifactSize"] = artifact_size
        if artifact_SHA256:
            forensic_artifact_update["artifactSHA256"] = artifact_SHA256

        commands.append(
            {
                "Update": self._get_update_expression(
                    type_prefix=self._record_prefix,
                    id=id,
                    subtype_prefix=self._artifact_type_prefix,
                    subtype_id=artifact_id,
                    new_attributes=forensic_artifact_update,
                    is_transaction=True,
                )
            }
        )

        forensic_event: Dict[str, Any] = {
            "PK": f"{self._record_prefix}{id}",
            "SK": f"{self._event_type_prefix}{now}#{event_id}",
            "id": event_id,
            "forensicId": id,
            "name": "Artifact updated",
            "description": "Creation of a forensics artifact has been initiated by Forensics Orchestrator",
            "phase": phase.value,
            "componentId": component_id,
            "componentType": component_type,
            "creationTime": now,
            "artifact": self.filter_attributes(
                forensic_artifact_update, self._attribute_filter
            ),
        }

        commands.append(
            {
                "Put": {
                    "TableName": self.table,
                    "Item": self.serialize(forensic_event),
                }
            }
        )

        self.client.transact_write_items(TransactItems=commands)

        if self._auto_notify_subscribers:
            self._notify_subscribers_artifact(
                artifact=self.filter_attributes(
                    forensic_artifact_update, self._attribute_filter
                )
            )
            self._notify_subscribers_timeline_event(
                forensic_event=self.filter_attributes(
                    forensic_event, self._attribute_filter
                )
            )

        return True

    def _unpack_dict_to_dataclass(self, cls, data):
        return cls(
            **{
                key: (
                    data[key]
                    if val.default == val.empty
                    else data.get(key, val.default)
                )
                for key, val in inspect.signature(cls).parameters.items()
            }
        )

    def _apig_sigv4_request(
        self,
        method,
        service_name,
        url,
        data=None,
        params=None,
        headers=None,
        session=None,
    ):
        if not session:
            session = Session()

        creds = session.get_credentials().get_frozen_credentials()
        request = AWSRequest(
            method=method, url=url, data=data, params=params, headers=headers
        )
        SigV4Auth(creds, service_name, session.region_name).add_auth(request)
        return requests.request(
            method=method, url=url, headers=dict(request.headers), data=data
        )

    @xray_recorder.capture("_notify_subscribers")
    def _notify_subscribers_forensic_record(self, forensic_record: dict):

        if forensic_record.get("resourceInfo"):
            forensic_record["resourceInfo"] = json.dumps(
                forensic_record["resourceInfo"],
                sort_keys=True,
                indent=2,
                default=date_time_formater,
            )

        payload = {
            "operationName": "notifyForensicsRecordChange",
            "variables": {"input": forensic_record},
            "query": """
                mutation notifyForensicsRecordChange($input: NotifyForensicsProcessingStateChangeInput!) {
                    notifyForensicsRecordChange(input: $input) {
                        id
                        resourceType
                        resourceId
                        awsAccountId
                        awsRegion
                        creationTime
                        lastUpdatedTime
                        triageStatus
                        triageStatusDescription
                        memoryAnalysisStatus
                        memoryAnalysisStatusDescription
                        diskAnalysisStatus
                        diskAnalysisStatusDescription
                        completionTime
                        resourceInfo
                        sourceAccountSnapshots {
                            awsAccountId
                            region
                            snapshotId
                            volumeId
                            volumeSize
                        }
                        forensicAccountSnapshots {
                            awsAccountId
                            region
                            snapshotId
                            volumeId
                            volumeSize
                        }
                        forensicAccountVolumes {
                            awsAccountId
                            region
                            volumeId
                            volumeSize
                        }
                        associatedFindings {
                            id
                            service
                            region
                        }
                    }
                }
            """,
        }

        resp = self._apig_sigv4_request(
            "POST",
            "appsync",
            self._appsync_api_endpoint_url,
            data=json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                default=date_time_formater,
            ),
        )

        try:
            resp.raise_for_status()
            self._logger.info(
                {
                    "appSyncOperation": "notifyForensicsRecordChange",
                    "responseCode": resp.status_code,
                }
            )
        except requests.exceptions.HTTPError as e:
            self._logger.error(
                {
                    "appSyncOperation": "notifyForensicsRecordChange",
                    "responseCode": resp.status_code,
                    "error": e,
                }
            )

    @xray_recorder.capture("_notify_subscribers_artifact")
    def _notify_subscribers_artifact(self, artifact: dict):

        payload = {
            "operationName": "notifyNewOrUpdatedForensicArtifact",
            "variables": {"input": artifact},
            "query": """
                mutation notifyNewOrUpdatedForensicArtifact($input: NotifyForensicArtifactInput!) {
                    notifyNewOrUpdatedForensicArtifact(input: $input) {
                        artifactLocation
                        artifactSHA256
                        artifactSize
                        category
                        componentId
                        componentType
                        creationTime
                        id
                        forensicId
                        inputArtifactCategory
                        inputArtifactId
                        inputArtifactType
                        lastUpdatedTime
                        snapshot {
                            awsAccountId
                            region
                            snapshotId
                            volumeId
                            volumeSize
                        }
                        ssmCommandId
                        ssmDocumentName
                        status
                        type
                        volume {
                            awsAccountId
                            region
                            volumeId
                            volumeSize
                        }
                    }
                }
            """,
        }

        resp = self._apig_sigv4_request(
            "POST",
            "appsync",
            self._appsync_api_endpoint_url,
            data=json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                default=date_time_formater,
            ),
        )
        try:
            resp.raise_for_status()
            self._logger.info(
                {
                    "appSyncOperation": "notifyNewOrUpdatedForensicArtifact",
                    "responseCode": resp.status_code,
                }
            )
        except requests.exceptions.HTTPError as e:
            self._logger.error(
                {
                    "appSyncOperation": "notifyNewOrUpdatedForensicArtifact",
                    "responseCode": resp.status_code,
                    "error": e,
                }
            )

    @xray_recorder.capture("_notify_subscribers_timeline_event")
    def _notify_subscribers_timeline_event(self, forensic_event: dict):

        if forensic_event.get("eventData"):
            forensic_event["eventData"] = json.dumps(
                forensic_event["eventData"],
                sort_keys=True,
                indent=2,
                default=date_time_formater,
            )

        payload = {
            "operationName": "notifyNewForensicTimelineEvent",
            "variables": {"input": forensic_event},
            "query": """
                mutation notifyNewForensicTimelineEvent($input: NotifyForensicTimelineEventInput!) {
                    notifyNewForensicTimelineEvent(input: $input) {
                        componentId
                        componentType
                        creationTime
                        description
                        eventData
                        forensicId
                        id
                        name
                        phase
                        artifact {
                            artifactLocation
                            artifactSHA256
                            artifactSize
                            category
                            componentId
                            componentType
                            creationTime
                            forensicId
                            id
                            inputArtifactCategory
                            inputArtifactId
                            inputArtifactType
                            lastUpdatedTime
                            snapshot {
                                awsAccountId
                                region
                                snapshotId
                                volumeId
                                volumeSize
                            }
                            ssmCommandId
                            ssmDocumentName
                            status
                            type
                            volume {
                                awsAccountId
                                region
                                volumeId
                                volumeSize
                            }
                        }
                    }
                }
            """,
        }

        resp = self._apig_sigv4_request(
            "POST",
            "appsync",
            self._appsync_api_endpoint_url,
            data=json.dumps(
                payload,
                sort_keys=True,
                indent=2,
                default=date_time_formater,
            ),
        )
        try:
            resp.raise_for_status()
            self._logger.info(
                {
                    "appSyncOperation": "notifyNewForensicTimelineEvent",
                    "responseCode": resp.status_code,
                }
            )
        except requests.exceptions.HTTPError as e:
            self._logger.error(
                {
                    "appSyncOperation": "notifyNewForensicTimelineEvent",
                    "responseCode": resp.status_code,
                    "error": e,
                }
            )
