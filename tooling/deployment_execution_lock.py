"""Pure fail-closed model for conditional deployment execution locking."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest


DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
DEPLOYMENT_ID = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
EXECUTION_ID = re.compile(r"^exec_[0-9A-HJKMNP-TV-Z]{26}$")
OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{7,255}$")
REQUEST_FIELDS = frozenset(
    {
        "deployment_id",
        "account_id",
        "region",
        "execution_id",
        "owner",
        "registry_record_digest",
        "expected_lock_version",
        "ttl_seconds",
    }
)
LOCK_FIELDS = frozenset(
    {
        "schema_version",
        "deployment_id",
        "account_id",
        "region",
        "execution_id",
        "owner",
        "status",
        "acquired_at",
        "expires_at",
        "registry_record_digest",
        "lock_version",
        "lock_digest",
    }
)


def _parse(value: str) -> datetime:
    if not isinstance(value, str):
        raise AuthorizationError("execution lock timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("execution lock timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationError("execution lock timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _now_utc(now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise AuthorizationError("execution lock current time must be timezone-aware")
    return now.astimezone(UTC)


def _verify_digest(lock: dict[str, Any]) -> None:
    claimed = lock.get("lock_digest")
    body = {key: value for key, value in lock.items() if key != "lock_digest"}
    if not isinstance(claimed, str) or not DIGEST.fullmatch(claimed):
        raise AuthorizationError("execution lock digest is malformed")
    if claimed != canonical_digest(body):
        raise AuthorizationError("execution lock digest mismatch")


def _validate_request(request: dict[str, Any]) -> None:
    if set(request) != REQUEST_FIELDS:
        raise AuthorizationError("execution lock request fields are malformed")
    patterns = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": EXECUTION_ID,
        "owner": OWNER,
        "registry_record_digest": DIGEST,
    }
    for field, pattern in patterns.items():
        value = request.get(field)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise AuthorizationError(f"execution lock request {field} is malformed")
    expected_version = request.get("expected_lock_version")
    if (
        isinstance(expected_version, bool)
        or not isinstance(expected_version, int)
        or expected_version < 0
    ):
        raise AuthorizationError("execution lock expected version is malformed")
    ttl_seconds = request.get("ttl_seconds")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 300 <= ttl_seconds <= 3600
    ):
        raise AuthorizationError("execution lock TTL must be between 300 and 3600 seconds")


def _validate_existing(lock: dict[str, Any], now: datetime) -> tuple[datetime, datetime]:
    if set(lock) != LOCK_FIELDS or lock.get("schema_version") != "1":
        raise AuthorizationError("execution lock record is malformed")
    _verify_digest(lock)
    lock_version = lock.get("lock_version")
    if (
        isinstance(lock_version, bool)
        or not isinstance(lock_version, int)
        or lock_version < 1
    ):
        raise AuthorizationError("execution lock version is malformed")
    acquired_at = _parse(lock.get("acquired_at"))
    expires_at = _parse(lock.get("expires_at"))
    if acquired_at >= expires_at:
        raise AuthorizationError("execution lock interval is invalid")
    if not 300 <= (expires_at - acquired_at).total_seconds() <= 3600:
        raise AuthorizationError("execution lock duration is outside the approved range")
    if acquired_at > now:
        raise AuthorizationError("execution lock was acquired in the future")
    return acquired_at, expires_at


def acquire_lock(
    *,
    existing: dict[str, Any] | None,
    request: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Model a conditional lock acquisition without automatic stale recovery.

    A real registry adapter must use the returned expected version/digest in one
    conditional write. This function never performs cloud or storage writes.
    """
    current_time = _now_utc(now)
    _validate_request(request)
    ttl_seconds = request["ttl_seconds"]

    if existing is None:
        if request.get("expected_lock_version") != 0:
            raise AuthorizationError("initial lock acquisition requires version zero")
        next_version = 1
    else:
        _, existing_expires_at = _validate_existing(existing, current_time)
        expected_version = request.get("expected_lock_version")
        if expected_version != existing.get("lock_version"):
            raise AuthorizationError("execution lock version conflict")
        for field in ("deployment_id", "account_id", "region"):
            if request.get(field) != existing.get(field):
                raise AuthorizationError(f"execution lock {field} cannot be reassigned")
        if existing.get("status") == "HELD":
            if request["registry_record_digest"] != existing.get("registry_record_digest"):
                raise AuthorizationError(
                    "execution lock registry_record_digest cannot be reassigned while held"
                )
            if existing_expires_at > current_time:
                raise AuthorizationError("deployment execution lock is already held")
            raise AuthorizationError(
                "reviewed stale-lock recovery is required; automatic takeover is forbidden"
            )
        if existing.get("status") != "RELEASED":
            raise AuthorizationError("execution lock has an unknown state")
        next_version = existing["lock_version"] + 1

    acquired_at = current_time.replace(microsecond=0)
    expires_at = acquired_at + timedelta(seconds=ttl_seconds)
    lock: dict[str, Any] = {
        "schema_version": "1",
        "deployment_id": request["deployment_id"],
        "account_id": request["account_id"],
        "region": request["region"],
        "execution_id": request["execution_id"],
        "owner": request["owner"],
        "status": "HELD",
        "acquired_at": acquired_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "registry_record_digest": request["registry_record_digest"],
        "lock_version": next_version,
    }
    lock["lock_digest"] = canonical_digest(lock)
    return lock
