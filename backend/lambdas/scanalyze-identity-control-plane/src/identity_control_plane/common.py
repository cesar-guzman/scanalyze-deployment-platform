from __future__ import annotations

import hashlib
import hmac
import logging
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol


CUSTOMER_ID_PATTERN = re.compile(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
DEPLOYMENT_ID_PATTERN = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
SUBJECT_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
POLICY_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuditSink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...


def is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def constant_time_equal(actual: object, expected: object) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, str):
        return False
    return hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))


def parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            result = datetime.fromisoformat(normalized)
        except ValueError:
            return None
    else:
        return None
    if result.tzinfo is None:
        return None
    return result.astimezone(timezone.utc)


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def opaque_reference(*parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def sanitized_audit_event(
    *,
    now: datetime,
    decision: str,
    reason_code: str,
    action: str,
    policy_version: str,
    policy_digest: str,
    correlation_parts: tuple[object, ...] = (),
) -> dict[str, Any]:
    return {
        "event_schema_version": "identity-audit.v1",
        "timestamp": utc_timestamp(now),
        "decision_id": opaque_reference(
            action,
            reason_code,
            utc_timestamp(now),
            *correlation_parts,
        ),
        "principal_type": "user" if action != "m2m.provision" else "m2m",
        "principal_reference": "redacted",
        "customer_reference": "redacted",
        "deployment_reference": "redacted",
        "action": action,
        "resource_type": "identity_control_plane",
        "decision": decision,
        "reason_code": reason_code,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
        "assurance": "validated_control_plane",
        "correlation_reference": opaque_reference(*correlation_parts)
        if correlation_parts
        else "unavailable",
    }


def emit_sanitized(
    *,
    audit_sink: AuditSink,
    logger: logging.Logger,
    event: Mapping[str, Any],
    required: bool,
) -> bool:
    try:
        audit_sink.emit(dict(event))
        return True
    except Exception:
        logger.error("identity_audit_emit_failed")
        if required:
            return False
        return False
