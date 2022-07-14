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


import logging

from aws_xray_sdk.core import patch_all, xray_recorder

patch_all()
xray_recorder.configure(context_missing="LOG_ERROR")


@xray_recorder.capture("Forensic Logger")
def get_logger(name=__name__):
    """
    this is the warper to return a logger with the solution wide configration
    """
    if len(logging.getLogger().handlers) > 0:
        # for deployed env
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.basicConfig(
            format="%(asctime)s %(message)s",
            datefmt="%m/%d/%Y %I:%M:%S %p",
            level=logging.INFO,
        )
    logger = logging.getLogger(name)
    return logger
