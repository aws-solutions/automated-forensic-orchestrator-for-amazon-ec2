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
import json


class ForensicLambdaExecutionException(Exception):
    """Forensic Lambda Execution Exception"""

    pass


class ForensicExecutionException(Exception):
    def __init__(self, error_content: dict) -> None:
        error_content_str = json.dumps(error_content)
        super().__init__(error_content_str)


class MemoryAcquisitionError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Memory Acquisition failed"""

    pass


class DiskAcquisitionError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Disk Acquisition failed"""

    pass


class InvestigationError(ForensicExecutionException):
    """Forensic Lambda Execution Exception Disk Acquisition failed"""

    pass
