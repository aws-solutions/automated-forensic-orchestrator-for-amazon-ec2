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

from dataclasses import dataclass, field
from enum import Enum
from typing import List


def _none():
    return None


class ForensicCategory(Enum):
    DISK = "DISK"
    MEMORY = "MEMORY"


class ArtifactCategory(Enum):
    DISK = "DISK"
    MEMORY = "MEMORY"


class ArtifactType(Enum):
    EC2SNAPSHOT = "EC2SNAPSHOT"
    EC2VOLUME = "EC2VOLUME"
    DISKDUMP = "DISKDUMP"
    MEMORYDUMP = "MEMORYDUMP"
    DISKANALYSIS = "DISKANALYSIS"
    MEMORYANALYSIS = "MEMORYANALYSIS"


class ArtifactStatus(Enum):
    CREATING = "CREATING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ResourceType(Enum):
    INSTANCE = "INSTANCE"


class ForensicsProcessingPhase(Enum):
    TRIAGE = "TRIAGE"
    ACQUISITION = "ACQUISITION"
    INVESTIGATION = "INVESTIGATION"
    ISOLATION = "ISOLATION"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


@dataclass
class Snapshot:
    snapshotId: str
    volumeId: str
    volumeSize: int
    awsAccountId: str
    region: str


@dataclass
class Volume:
    volumeId: str
    volumeSize: int
    awsAccountId: str
    region: str


@dataclass
class Finding:
    id: str
    service: str
    region: str


@dataclass
class ForensicArtifact:
    """Class for tracking forensic artifacts produced by Forensic Orchestrator."""

    id: str
    forensicId: str
    category: ArtifactCategory
    type: ArtifactType
    status: ArtifactStatus
    componentId: str
    componentType: str
    creationTime: str
    lastUpdatedTime: str
    snapshot: Snapshot = field(default_factory=_none)
    volume: Volume = field(default_factory=_none)
    inputArtifactCategory: ArtifactCategory = field(default_factory=_none)
    inputArtifactType: ArtifactType = field(default_factory=_none)
    inputArtifactId: str = field(default_factory=_none)
    ssmDocumentName: str = field(default_factory=_none)
    ssmCommandId: str = field(default_factory=_none)
    artifactLocation: str = field(default_factory=_none)
    artifactSize: int = field(default_factory=_none)
    artifactSHA256: str = field(default_factory=_none)

    def __post_init__(self):
        if self.snapshot and isinstance(self.snapshot, dict):
            self.snapshot = Snapshot(**self.snapshot)
        if self.volume and isinstance(self.volume, dict):
            self.volume = Volume(**self.volume)
        if self.category:
            self.category = ArtifactCategory[self.category]
        if self.type:
            self.type = ArtifactType[self.type]
        if self.status:
            self.status = ArtifactStatus[self.status]
        if self.inputArtifactCategory:
            self.inputArtifactCategory = ArtifactCategory[
                self.inputArtifactCategory
            ]
        if self.inputArtifactType:
            self.inputArtifactType = ArtifactType[self.inputArtifactType]


@dataclass
class ForensicTimelineEvent:
    """Class for tracking forensic events emitted by Forensic Orchestrator."""

    id: str
    forensicId: str
    phase: ForensicsProcessingPhase
    name: str
    description: str
    componentId: str
    componentType: str
    creationTime: str
    artifact: ForensicArtifact = field(default_factory=_none)
    eventData: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.artifact and isinstance(self.artifact, dict):
            self.artifact = ForensicArtifact(**self.artifact)
        if self.phase:
            self.phase = ForensicsProcessingPhase[self.phase]


@dataclass
class ForensicRecord:
    """Class for tracking forensic processing tasks."""

    id: str
    resourceType: ResourceType
    resourceId: str
    awsAccountId: str
    awsRegion: str
    creationTime: str
    lastUpdatedTime: str
    triageStatus: ForensicsProcessingPhase
    triageStatusDescription: str
    memoryAnalysisStatus: ForensicsProcessingPhase
    memoryAnalysisStatusDescription: str
    diskAnalysisStatus: ForensicsProcessingPhase
    diskAnalysisStatusDescription: str
    completionTime: str = field(default_factory=_none)
    resourceInfo: dict = field(default_factory=dict)
    sourceAccountSnapshots: List[Snapshot] = field(default_factory=list)
    forensicAccountSnapshots: List[Snapshot] = field(default_factory=list)
    forensicAccountVolumes: List[Volume] = field(default_factory=list)
    associatedFindings: List[Finding] = field(default_factory=list)
    artifacts: List[ForensicArtifact] = field(default_factory=list)
    timeline: List[ForensicTimelineEvent] = field(default_factory=list)

    def __post_init__(self):
        if self.resourceType:
            self.resourceType = ResourceType[self.resourceType]
        if self.triageStatus:
            self.triageStatus = ForensicsProcessingPhase[self.triageStatus]
        if self.memoryAnalysisStatus:
            self.memoryAnalysisStatus = ForensicsProcessingPhase[
                self.memoryAnalysisStatus
            ]
        if self.diskAnalysisStatus:
            self.diskAnalysisStatus = ForensicsProcessingPhase[
                self.diskAnalysisStatus
            ]
        if self.sourceAccountSnapshots:
            self.sourceAccountSnapshots = [
                Snapshot(**s)
                for s in self.sourceAccountSnapshots
                if isinstance(s, dict)
            ]
        if self.forensicAccountSnapshots:
            self.forensicAccountSnapshots = [
                Snapshot(**s)
                for s in self.forensicAccountSnapshots
                if isinstance(s, dict)
            ]
        if self.forensicAccountVolumes:
            self.forensicAccountVolumes = [
                Volume(**v)
                for v in self.forensicAccountVolumes
                if isinstance(v, dict)
            ]
        if self.associatedFindings:
            self.associatedFindings = [
                Finding(**f)
                for f in self.associatedFindings
                if isinstance(f, dict)
            ]
        if self.artifacts:
            self.artifacts = [
                ForensicArtifact(**a)
                for a in self.associatedFindings
                if isinstance(a, dict)
            ]
        if self.timeline:
            self.timeline = [
                ForensicTimelineEvent(**e)
                for e in self.timeline
                if isinstance(e, dict)
            ]
