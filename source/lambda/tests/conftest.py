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

"""Make the Python suite hermetic.

Until this file existed the suite passed on a developer machine and failed in CI
with 120 errors of ``botocore.exceptions.NoRegionError: You must specify a
region``. Two things were going on, and both are worth naming because either
alone would have been enough:

1. **It depended on the developer's shell.** Anyone with ``AWS_REGION`` or
   ``AWS_PROFILE`` exported - which is everyone who has used the AWS CLI in that
   terminal - got a region for free. CI has no AWS environment at all, so every
   test that constructs a boto3 client without an explicit region failed there
   and only there.
2. **It depended on test ordering.** Several test modules set
   ``os.environ["AWS_REGION"]`` at import time. pytest imports every module into
   one process, so that assignment leaked into every test that happened to run
   afterwards. 351 tests passed for that reason rather than on their own merit.

Setting the region here fixes both: the value is present before any test module
is imported, and it no longer matters which module ran first or what the
developer's shell contains.

The placeholder credentials are not incidental. Without them, a test that builds
a client and reaches the network on a machine holding live credentials would use
them - in a repository whose whole subject is other people's evidence. Explicitly
invalid values make that impossible, and they make an accidental real call fail
loudly instead of quietly succeeding.
"""

import os

import pytest

# Chosen to be recognisable in a stack trace as "this came from the test
# harness", not from anything a developer or CI configured.
TEST_REGION = "us-east-1"
TEST_CREDENTIALS = {
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AWS_SESSION_TOKEN": "TESTSESSIONTOKENnotarealtokenTESTSESSIONTOKEN",
}


def pytest_configure(config):
    """Fix the AWS environment before any test module is imported.

    pytest_configure runs during startup, ahead of collection, which is what
    makes this reliable: a fixture would run too late for modules that read
    os.environ at import time, and those are exactly the modules that were
    leaking a region to everything else.
    """
    os.environ["AWS_DEFAULT_REGION"] = TEST_REGION
    os.environ["AWS_REGION"] = TEST_REGION
    for name, value in TEST_CREDENTIALS.items():
        os.environ[name] = value
    # A developer profile must not be consulted: it can carry a different region,
    # SSO state, or real credentials, any of which reintroduces the difference
    # between "passes here" and "passes in CI".
    os.environ.pop("AWS_PROFILE", None)
    # Never read ~/.aws during a unit test run.
    os.environ["AWS_CONFIG_FILE"] = os.devnull
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    # Fail fast rather than retrying against an endpoint that is not there.
    os.environ.setdefault("AWS_MAX_ATTEMPTS", "1")
    os.environ.setdefault("AWS_RETRY_MODE", "standard")
    os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture(autouse=True)
def aws_environment_is_hermetic():
    """Restore the harness environment around every test.

    Individual tests use ``mock.patch.dict(os.environ, ...)`` freely, and a test
    that mutates os.environ without restoring it would otherwise change the
    meaning of everything after it - the ordering dependency this file exists to
    remove.
    """
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)
