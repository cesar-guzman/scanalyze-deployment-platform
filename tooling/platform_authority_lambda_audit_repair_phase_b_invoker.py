"""Exact synchronous invoker for the GUG-221 Phase B broker.

The signed provider topology receipt is deliberately carried in the one-shot
request, not in Lambda configuration.  The invoker performs only local shape,
freshness and static-binding checks.  The broker remains the authority boundary
and independently verifies the KMS signature before creating effect clients.
"""

from __future__ import annotations

import base64
from datetime import datetime
import json
import re
from typing import Any, Mapping, Protocol

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    FUNCTION_ALIAS,
    FUNCTION_NAME,
    REQUEST_KEYS,
    PhaseBPepError,
    validate_broker_topology_evidence,
)


MAX_INVOCATION_PAYLOAD_BYTES = 16 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(r"^gug221-phase-b-[0-9a-f]{64}$")


class PhaseBInvokerError(RuntimeError):
    """Sanitized local or ambiguous invocation failure."""


class LambdaInvokeClient(Protocol):
    def invoke(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _client_context(
    *,
    execution_id: str,
    broker_topology_sha256: str,
) -> str:
    value = {
        "custom": {
            "transport": "REQUEST_RESPONSE",
            "execution_id": execution_id,
            "broker_topology_sha256": broker_topology_sha256,
        }
    }
    return base64.b64encode(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).decode("ascii")


def invoke_phase_b_broker(
    *,
    client: LambdaInvokeClient,
    authorization_code: str,
    code_verifier: str,
    oauth_state: str,
    broker_topology_evidence: Mapping[str, Any],
    execution_id: str,
    broker_topology_sha256: str,
    now: datetime,
) -> Mapping[str, Any]:
    """Invoke one exact qualified alias once with signed topology evidence."""

    if (
        _EXECUTION_ID.fullmatch(execution_id) is None
        or _DIGEST.fullmatch(broker_topology_sha256) is None
    ):
        raise PhaseBInvokerError("PHASE_B_INVOKE_BINDING_INVALID")
    try:
        validate_broker_topology_evidence(
            broker_topology_evidence,
            now=now,
        )
    except PhaseBPepError as exc:
        raise PhaseBInvokerError(exc.code) from None
    if (
        broker_topology_evidence.get("broker_topology_sha256")
        != broker_topology_sha256
    ):
        raise PhaseBInvokerError("BROKER_TOPOLOGY_EVIDENCE_BINDING_MISMATCH")

    evidence = dict(broker_topology_evidence)
    event: dict[str, Any] = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_proof_request"
        ),
        "authorization_code": authorization_code,
        "code_verifier": code_verifier,
        "oauth_state": oauth_state,
        "broker_topology_evidence": evidence,
    }
    if set(event) != REQUEST_KEYS:
        raise PhaseBInvokerError("PHASE_B_INVOKE_REQUEST_INVALID")
    try:
        payload = bytearray(
            json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        )
    except (TypeError, ValueError, UnicodeError):
        raise PhaseBInvokerError("PHASE_B_INVOKE_REQUEST_INVALID") from None
    if not 1 <= len(payload) <= MAX_INVOCATION_PAYLOAD_BYTES:
        for index in range(len(payload)):
            payload[index] = 0
        raise PhaseBInvokerError("PHASE_B_INVOKE_REQUEST_INVALID")

    try:
        response = client.invoke(
            FunctionName=FUNCTION_NAME,
            Qualifier=FUNCTION_ALIAS,
            InvocationType="RequestResponse",
            ClientContext=_client_context(
                execution_id=execution_id,
                broker_topology_sha256=broker_topology_sha256,
            ),
            Payload=bytes(payload),
        )
    except Exception:
        raise PhaseBInvokerError("PHASE_B_INVOKE_UNCERTAIN") from None
    finally:
        for index in range(len(payload)):
            payload[index] = 0
        evidence.clear()
        event.clear()
        authorization_code = ""
        code_verifier = ""
        oauth_state = ""

    if (
        not isinstance(response, Mapping)
        or response.get("StatusCode") != 200
        or response.get("FunctionError") is not None
    ):
        raise PhaseBInvokerError("PHASE_B_INVOKE_UNCERTAIN")
    return response
