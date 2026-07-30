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
from typing import Any, Mapping, NoReturn, Protocol, Sequence

from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    AUTHORITY_ACCOUNT_ID,
    AWS_IDENTITY_CONTEXT_POLICY_ARN,
    BROKER_ROLE_NAME,
    DIRECT_EFFECT_ACTION,
    DIRECT_EFFECT_BLOCKED,
    FUNCTION_ALIAS,
    FUNCTION_NAME,
    IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
    POLICY_SNAPSHOT_DIGEST,
    POLICY_SNAPSHOT_VERSION,
    PROOF_REQUIRED_ACTION,
    REGION,
    REQUEST_KEYS,
    PhaseBPepError,
    canonical_digest,
    parse_timestamp,
    validate_broker_topology_evidence,
)


MAX_INVOCATION_PAYLOAD_BYTES = 16 * 1024
MAX_RESPONSE_PAYLOAD_BYTES = 64 * 1024
MAX_RESPONSE_BODY_BYTES = 48 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONZERO_DIGEST = re.compile(r"^sha256:(?!0{64})[0-9a-f]{64}$")
_RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(r"^gug221-phase-b-[0-9a-f]{64}$")
_DENIAL_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_STACK_ARN = re.compile(
    rf"^arn:aws:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:stack/"
    r"scanalyze-platform-authority-lambda-audit-repair-pep/"
    r"[0-9a-fA-F-]{36}$"
)
_CHANGE_SET_ARN = re.compile(
    rf"^arn:aws:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:changeSet/"
    r"gug221-lambda-audit-repair-pep-create/[0-9a-fA-F-]{36}$"
)
_CLIENT_REQUEST_TOKEN = re.compile(r"^gug221-b-[0-9a-f]{48}$")

APPLICATION_RESPONSE_KEYS = frozenset(
    {"statusCode", "headers", "isBase64Encoded", "body"}
)
APPLICATION_RESPONSE_HEADERS = {
    "cache-control": "no-store",
    "content-type": "application/json",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff",
}
SUCCESS_BODY_KEYS = frozenset(
    {"identity_proof", "broker_effect", "closure_pending"}
)
POLICY_DIGEST_FIELDS = (
    "invoker_policy_sha256",
    "broker_policy_sha256",
    "proof_policy_sha256",
    "application_actor_policy_sha256",
)
PROOF_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "binding_digest",
        "managed_policy_arn",
        "managed_policy_version",
        "managed_policy_digest",
        "proof_required_action",
        "direct_effect_action",
        "direct_effect_status",
        "expected_user_id_digest",
        "proof_role_arn_digest",
        "proof_session_arn_digest",
        "token_pair_digest",
        "phase_b_intent_digest",
        "change_set_receipt_digest",
        "execution_request_digest",
        "template_digest",
        "parameters_digest",
        "resource_inventory_digest",
        "ledger_controls_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "proof_expires_at",
        "provided_context_count",
        "provided_context_provider_arn",
        "identity_context_user_binding",
        "id_token_serialized",
        "identity_context_serialized",
        "credentials_exposed",
        "credentials_consumed_for_effect",
        "live_effect_authorized",
        "native_on_behalf_of",
        "receipt_digest",
    }
)
EFFECT_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "execution_id",
        "binding_digest",
        "proof_receipt_digest",
        "ledger_digest",
        "closure_pending_receipt_digest",
        "execution_request_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "stack_arn",
        "change_set_arn",
        "client_request_token",
        "effect_principal_type",
        "effect_principal_arn",
        "proof_credentials_used_for_effect",
        "attempts",
        "execution_ambiguous",
        "retry_permitted",
        "one_shot_execution_gate_consumed",
        "native_on_behalf_of",
        "provider_revocation_pending",
        "authority_revoked",
        "production_status",
        "receipt_digest",
    }
)
CLOSURE_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "execution_id",
        "binding_digest",
        "ledger_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "execution_status",
        "issued_at",
        "revocation_scope",
        "execution_binding_consumed",
        "authority_revoked",
        "provider_revocation_verified",
        "identity_center_assignment_removed",
        "invoke_permission_removed",
        "pending_operations_absent",
        "extant_sessions_invalidated",
        "wall_clock_window_expired",
        "live_closure_status",
        "attempts",
        "retry_permitted",
        "native_on_behalf_of",
        "receipt_digest",
    }
)


class PhaseBInvokerError(RuntimeError):
    """Sanitized local or ambiguous invocation failure."""


class LambdaInvokeClient(Protocol):
    def invoke(self, **kwargs: Any) -> Mapping[str, Any]: ...


class _ApplicationResponseInvalid(ValueError):
    """Internal sentinel; never expose provider payload details."""


def _invalid_response() -> NoReturn:
    raise _ApplicationResponseInvalid


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _reject_duplicate_pairs(
    pairs: Sequence[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid_response()
        result[key] = value
    return result


def _reject_non_finite(_: str) -> NoReturn:
    _invalid_response()


def _strict_json_object(
    value: str | bytes | bytearray,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        encoded_size = (
            len(value.encode("utf-8"))
            if isinstance(value, str)
            else len(value)
        )
    except (UnicodeError, ValueError):
        _invalid_response()
    if not 1 <= encoded_size <= max_bytes:
        _invalid_response()
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except _ApplicationResponseInvalid:
        raise
    except (json.JSONDecodeError, TypeError, UnicodeError, ValueError):
        _invalid_response()
    if type(parsed) is not dict:
        _invalid_response()
    return parsed


def _declared_stream_length(value: object) -> int | None:
    observed: list[int] = []
    for name in ("content_length", "_content_length"):
        candidate = getattr(value, name, None)
        if candidate is None:
            continue
        if type(candidate) is not int or candidate < 0:
            _invalid_response()
        observed.append(candidate)
    if len(set(observed)) > 1:
        _invalid_response()
    return observed[0] if observed else None


def _read_response_payload(value: object) -> bytearray:
    """Read one response once, prove EOF, and retain only a mutable buffer."""

    if type(value) in {bytes, bytearray}:
        if not 1 <= len(value) <= MAX_RESPONSE_PAYLOAD_BYTES:
            if type(value) is bytearray:
                _wipe(value)
            _invalid_response()
        result = bytearray(value)
        if type(value) is bytearray:
            _wipe(value)
        return result

    result = bytearray()
    first = bytearray()
    tail = bytearray()
    try:
        read = getattr(value, "read", None)
        if not callable(read):
            _invalid_response()
        tell = getattr(value, "tell", None)
        if callable(tell):
            position = tell()
            if type(position) is not int or position != 0:
                _invalid_response()
        declared_length = _declared_stream_length(value)
        if (
            declared_length is not None
            and declared_length > MAX_RESPONSE_PAYLOAD_BYTES
        ):
            _invalid_response()

        raw_first = read(MAX_RESPONSE_PAYLOAD_BYTES + 1)
        if type(raw_first) not in {bytes, bytearray}:
            _invalid_response()
        first.extend(raw_first)
        if type(raw_first) is bytearray:
            _wipe(raw_first)
        if not 1 <= len(first) <= MAX_RESPONSE_PAYLOAD_BYTES:
            _invalid_response()

        raw_tail = read(1)
        if type(raw_tail) not in {bytes, bytearray}:
            _invalid_response()
        tail.extend(raw_tail)
        if type(raw_tail) is bytearray:
            _wipe(raw_tail)
        if tail:
            # A bounded read that returns short and then produces more bytes is
            # ambiguous; do not silently join or reinterpret partial chunks.
            _invalid_response()
        if declared_length is not None and declared_length != len(first):
            _invalid_response()
        if callable(tell):
            position = tell()
            if type(position) is not int or position != len(first):
                _invalid_response()
        result.extend(first)
        return result
    except _ApplicationResponseInvalid:
        raise
    except Exception:
        _invalid_response()
    finally:
        _wipe(first)
        _wipe(tail)
        close = getattr(value, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _require_exact(
    value: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> None:
    for key, expected_value in expected.items():
        actual = value.get(key)
        if type(actual) is not type(expected_value) or actual != expected_value:
            _invalid_response()


def _require_digest_fields(
    value: Mapping[str, Any],
    fields: Sequence[str],
    *,
    nonzero_fields: Sequence[str] = (),
) -> None:
    nonzero = frozenset(nonzero_fields)
    for field_name in fields:
        pattern = _NONZERO_DIGEST if field_name in nonzero else _DIGEST
        candidate = value.get(field_name)
        if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
            _invalid_response()


def _require_raw_digest_fields(
    value: Mapping[str, Any],
    fields: Sequence[str],
) -> None:
    for field_name in fields:
        candidate = value.get(field_name)
        if (
            not isinstance(candidate, str)
            or _RAW_DIGEST.fullmatch(candidate) is None
        ):
            _invalid_response()


def _require_canonical_receipt(
    value: object,
    *,
    keys: frozenset[str],
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        _invalid_response()
    receipt = dict(value)
    claimed = receipt.pop("receipt_digest", None)
    if (
        not isinstance(claimed, str)
        or _DIGEST.fullmatch(claimed) is None
    ):
        _invalid_response()
    try:
        expected = canonical_digest(receipt)
    except (TypeError, UnicodeError, ValueError):
        _invalid_response()
    if claimed != expected:
        _invalid_response()
    return dict(value)


def _validate_proof_receipt(value: object) -> dict[str, Any]:
    receipt = _require_canonical_receipt(value, keys=PROOF_RECEIPT_KEYS)
    _require_exact(
        receipt,
        {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": "IDENTITY_CONTEXT_PROOF_VERIFIED",
            "managed_policy_arn": AWS_IDENTITY_CONTEXT_POLICY_ARN,
            "managed_policy_version": POLICY_SNAPSHOT_VERSION,
            "managed_policy_digest": POLICY_SNAPSHOT_DIGEST,
            "proof_required_action": PROOF_REQUIRED_ACTION,
            "direct_effect_action": DIRECT_EFFECT_ACTION,
            "direct_effect_status": DIRECT_EFFECT_BLOCKED,
            "provided_context_count": 1,
            "provided_context_provider_arn": (
                IDENTITY_CENTER_CONTEXT_PROVIDER_ARN
            ),
            "identity_context_user_binding": (
                "VERIFIED_BY_EXACT_STS_SET_CONTEXT_TRUST"
            ),
            "id_token_serialized": False,
            "identity_context_serialized": False,
            "credentials_exposed": False,
            "credentials_consumed_for_effect": False,
            "live_effect_authorized": False,
            "native_on_behalf_of": False,
        },
    )
    _require_digest_fields(
        receipt,
        (
            "binding_digest",
            "managed_policy_digest",
            "expected_user_id_digest",
            "proof_role_arn_digest",
            "proof_session_arn_digest",
            "token_pair_digest",
            "phase_b_intent_digest",
            "change_set_receipt_digest",
            "execution_request_digest",
            "template_digest",
            "parameters_digest",
            "resource_inventory_digest",
            "ledger_controls_digest",
            "broker_topology_sha256",
            "broker_topology_provider_evidence_digest",
            "receipt_digest",
        ),
        nonzero_fields=("broker_topology_provider_evidence_digest",),
    )
    _require_raw_digest_fields(receipt, POLICY_DIGEST_FIELDS)
    try:
        parse_timestamp(
            receipt.get("proof_expires_at"),
            code="PROOF_EXPIRATION_INVALID",
        )
    except (PhaseBPepError, TypeError, ValueError):
        _invalid_response()
    return receipt


def _validate_effect_receipt(value: object) -> dict[str, Any]:
    receipt = _require_canonical_receipt(value, keys=EFFECT_RECEIPT_KEYS)
    _require_exact(
        receipt,
        {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_"
                "broker_effect_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": "DISPATCH_ACCEPTED",
            "effect_principal_type": "AWS_SERVICE_ROLE",
            "effect_principal_arn": (
                f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{BROKER_ROLE_NAME}"
            ),
            "proof_credentials_used_for_effect": False,
            "attempts": 1,
            "execution_ambiguous": False,
            "retry_permitted": False,
            "one_shot_execution_gate_consumed": True,
            "native_on_behalf_of": False,
            "provider_revocation_pending": True,
            "authority_revoked": False,
            "production_status": "NO-GO",
        },
    )
    execution_id = receipt.get("execution_id")
    if (
        not isinstance(execution_id, str)
        or _EXECUTION_ID.fullmatch(execution_id) is None
    ):
        _invalid_response()
    _require_digest_fields(
        receipt,
        (
            "binding_digest",
            "proof_receipt_digest",
            "ledger_digest",
            "closure_pending_receipt_digest",
            "execution_request_digest",
            "broker_topology_sha256",
            "broker_topology_provider_evidence_digest",
            "receipt_digest",
        ),
        nonzero_fields=("broker_topology_provider_evidence_digest",),
    )
    _require_raw_digest_fields(receipt, POLICY_DIGEST_FIELDS)
    for field_name, pattern in (
        ("stack_arn", _STACK_ARN),
        ("change_set_arn", _CHANGE_SET_ARN),
        ("client_request_token", _CLIENT_REQUEST_TOKEN),
    ):
        candidate = receipt.get(field_name)
        if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
            _invalid_response()
    return receipt


def _validate_closure_receipt(value: object) -> dict[str, Any]:
    receipt = _require_canonical_receipt(value, keys=CLOSURE_RECEIPT_KEYS)
    _require_exact(
        receipt,
        {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_"
                "closure_pending_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": "PROVIDER_REVOCATION_PENDING",
            "execution_status": "DISPATCH_ACCEPTED",
            "revocation_scope": "PROVIDER_IDENTITY_AND_INVOKE_AUTHORITY",
            "execution_binding_consumed": True,
            "authority_revoked": False,
            "provider_revocation_verified": False,
            "identity_center_assignment_removed": False,
            "invoke_permission_removed": False,
            "pending_operations_absent": False,
            "extant_sessions_invalidated": False,
            "wall_clock_window_expired": False,
            "live_closure_status": (
                "PENDING_PROVIDER_READBACK_AND_SESSION_EXPIRY"
            ),
            "attempts": 1,
            "retry_permitted": False,
            "native_on_behalf_of": False,
        },
    )
    execution_id = receipt.get("execution_id")
    if (
        not isinstance(execution_id, str)
        or _EXECUTION_ID.fullmatch(execution_id) is None
    ):
        _invalid_response()
    _require_digest_fields(
        receipt,
        (
            "binding_digest",
            "ledger_digest",
            "broker_topology_sha256",
            "broker_topology_provider_evidence_digest",
            "receipt_digest",
        ),
        nonzero_fields=("broker_topology_provider_evidence_digest",),
    )
    try:
        parse_timestamp(
            receipt.get("issued_at"),
            code="CLOSURE_PENDING_TIME_INVALID",
        )
    except (PhaseBPepError, TypeError, ValueError):
        _invalid_response()
    return receipt


def _validate_success_body(
    body: dict[str, Any],
    *,
    broker_topology_evidence: Mapping[str, Any],
    execution_id: str,
    broker_topology_sha256: str,
) -> dict[str, Any]:
    if set(body) != SUCCESS_BODY_KEYS:
        _invalid_response()
    proof = _validate_proof_receipt(body.get("identity_proof"))
    effect = _validate_effect_receipt(body.get("broker_effect"))
    closure = _validate_closure_receipt(body.get("closure_pending"))

    if (
        effect["execution_id"] != execution_id
        or closure["execution_id"] != execution_id
        or any(
            receipt["broker_topology_sha256"] != broker_topology_sha256
            for receipt in (proof, effect, closure)
        )
        or any(
            receipt["broker_topology_provider_evidence_digest"]
            != broker_topology_evidence.get("receipt_digest")
            for receipt in (proof, effect, closure)
        )
        or proof["binding_digest"] != effect["binding_digest"]
        or proof["binding_digest"] != closure["binding_digest"]
        or proof["execution_request_digest"]
        != effect["execution_request_digest"]
        or effect["proof_receipt_digest"] != proof["receipt_digest"]
        or effect["ledger_digest"] != closure["ledger_digest"]
        or effect["closure_pending_receipt_digest"]
        != closure["receipt_digest"]
        or closure["execution_status"] != effect["status"]
    ):
        _invalid_response()
    for field_name in POLICY_DIGEST_FIELDS:
        expected = broker_topology_evidence.get(field_name)
        if (
            proof[field_name] != expected
            or effect[field_name] != expected
        ):
            _invalid_response()
    return {
        "identity_proof": proof,
        "broker_effect": effect,
        "closure_pending": closure,
    }


def _validated_application_response(
    payload_source: object,
    *,
    broker_topology_evidence: Mapping[str, Any],
    execution_id: str,
    broker_topology_sha256: str,
) -> dict[str, Any]:
    payload = _read_response_payload(payload_source)
    try:
        envelope = _strict_json_object(
            payload,
            max_bytes=MAX_RESPONSE_PAYLOAD_BYTES,
        )
    finally:
        _wipe(payload)
    if set(envelope) != APPLICATION_RESPONSE_KEYS:
        _invalid_response()
    _require_exact(
        envelope,
        {
            "headers": APPLICATION_RESPONSE_HEADERS,
            "isBase64Encoded": False,
        },
    )
    status_code = envelope.get("statusCode")
    if type(status_code) is not int:
        _invalid_response()
    body_value = envelope.get("body")
    if not isinstance(body_value, str):
        _invalid_response()
    if status_code == 403:
        denial = _strict_json_object(
            body_value,
            max_bytes=MAX_RESPONSE_BODY_BYTES,
        )
        if (
            set(denial) != {"status", "reason_code"}
            or denial.get("status") != "DENY"
            or not isinstance(denial.get("reason_code"), str)
            or _DENIAL_REASON.fullmatch(denial["reason_code"]) is None
        ):
            _invalid_response()
        raise PhaseBInvokerError("PHASE_B_BROKER_DENIED")
    if status_code != 200:
        # 202 and every 5xx/unknown application status are reconcile-only.
        _invalid_response()
    body = _strict_json_object(
        body_value,
        max_bytes=MAX_RESPONSE_BODY_BYTES,
    )
    return _validate_success_body(
        body,
        broker_topology_evidence=broker_topology_evidence,
        execution_id=execution_id,
        broker_topology_sha256=broker_topology_sha256,
    )


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

    if not isinstance(response, Mapping):
        raise PhaseBInvokerError("PHASE_B_INVOKE_UNCERTAIN")
    transport_status = response.get("StatusCode")
    if (
        type(transport_status) is not int
        or transport_status != 200
        or response.get("FunctionError") is not None
    ):
        raise PhaseBInvokerError("PHASE_B_INVOKE_UNCERTAIN")
    try:
        return _validated_application_response(
            response.get("Payload"),
            broker_topology_evidence=broker_topology_evidence,
            execution_id=execution_id,
            broker_topology_sha256=broker_topology_sha256,
        )
    except PhaseBInvokerError:
        raise
    except Exception:
        # Once RequestResponse was dispatched, any payload/read/contract
        # ambiguity is terminal and reconcile-only. Never expose raw errors.
        raise PhaseBInvokerError("PHASE_B_INVOKE_UNCERTAIN") from None
