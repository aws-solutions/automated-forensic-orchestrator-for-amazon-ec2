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

"""Keep credentials out of CloudWatch Logs.

Every handler in this solution logged its whole input at entry, and the payload
travelling through the state machine is not innocent:

* ``runForensicsCommand`` logged the ``params`` dict it sends to Systems Manager,
  which holds ``AccessKeyId``, ``SecretAccessKey`` and ``SessionToken`` from
  ``AssumeRole`` - temporary, but written verbatim into CloudWatch and retained
  for the log group's lifetime.
* ``kernelSymbolLoader`` logged its raw event, and for Red Hat targets that event
  carries ``username`` and ``password`` for the customer's Red Hat subscription -
  a long-lived credential belonging to someone else.

Both were found by a security review rather than by anything in the build, which
is why redaction lives in one place with a test that enumerates the key names.
Adding a handler that logs a payload is fine; adding one that logs a secret now
requires deliberately bypassing this.

:func:`redact` keeps the shape of a payload - which is what makes these logs
worth having - and replaces only the values whose key names denote a secret.
:func:`trace` is for the handler-entry case where a couple of identifiers are all
anyone actually needs.
"""

import copy
from typing import Any, Dict, Iterable

REDACTED = "***REDACTED***"

# Compared case-insensitively against each key. Chosen from what actually travels
# through this solution's payloads rather than from a generic word list:
#   - the STS triple, passed to every SSM document that writes to the evidence
#     bucket because the instance under investigation has no instance profile
#   - the Red Hat subscription pair, in both the event and the SSM parameter
#     spellings the symbol builder uses
SENSITIVE_KEYS = frozenset(
    {
        "accesskeyid",
        "secretaccesskey",
        "sessiontoken",
        "secretkey",
        "password",
        "passwd",
        "username",
        "subscriptionmanagerusername",
        "subscriptionmanagerpassword",
        "credentials",
        "secret",
        "privatekey",
        "authorization",
    }
)


def _is_sensitive(key: Any) -> bool:
    return isinstance(key, str) and key.replace("_", "").replace(
        "-", ""
    ).lower() in SENSITIVE_KEYS


def redact(payload: Any, _depth: int = 0) -> Any:
    """A copy of ``payload`` with secret-valued keys masked.

    Recurses through dicts and lists so a credential nested inside the state
    machine's accumulated context is masked too - which is where these actually
    live, several levels down under ``Payload.body``.

    Depth is bounded so a self-referential structure cannot spin, and the input is
    never mutated: a redacting logger that quietly emptied the payload the handler
    then sends to Systems Manager would be worse than the leak.
    """
    if _depth > 12:
        return payload
    if isinstance(payload, dict):
        return {
            key: (
                REDACTED
                if _is_sensitive(key)
                else redact(value, _depth + 1)
            )
            for key, value in payload.items()
        }
    if isinstance(payload, (list, tuple)):
        redacted = [redact(item, _depth + 1) for item in payload]
        return type(payload)(redacted) if isinstance(payload, tuple) else redacted
    return payload


def trace(payload: Any, *keys: str) -> Dict[str, Any]:
    """Just the named keys, for logging at handler entry.

    Field selection rather than redaction, for the common case where a forensic
    id and an instance id are the whole reason the log line exists.
    """
    if not isinstance(payload, dict):
        return {}
    return {key: payload.get(key) for key in keys if key in payload}


def redacted_copy(payload: Any) -> Any:
    """:func:`redact` over a deep copy, when the caller wants to be certain.

    :func:`redact` already builds new containers, so this differs only for
    objects it passes through by reference. Used where a payload is logged and
    then handed onward in the same breath.
    """
    return redact(copy.deepcopy(payload))


def sensitive_key_names() -> Iterable[str]:
    """The key names treated as secret, for tests and for documentation."""
    return sorted(SENSITIVE_KEYS)
