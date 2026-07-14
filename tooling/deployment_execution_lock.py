"""Pure fail-closed model for conditional deployment execution locking."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError("execution lock timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError("execution lock timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _verify_digest(lock: dict[str, Any]) -> None:
    claimed = lock.get("lock_digest")
    body = {key: value for key, value in lock.items() if key != "lock_digest"}
    if claimed != canonical_digest(body):
        raise AuthorizationError("execution lock digest mismatch")


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
    ttl_seconds = request.get("ttl_seconds")
    if not isinstance(ttl_seconds, int) or not 300 <= ttl_seconds <= 3600:
        raise AuthorizationError("execution lock TTL must be between 300 and 3600 seconds")

    if existing is None:
        if request.get("expected_lock_version") != 0:
            raise AuthorizationError("initial lock acquisition requires version zero")
        next_version = 1
    else:
        _verify_digest(existing)
        expected_version = request.get("expected_lock_version")
        if expected_version != existing.get("lock_version"):
            raise AuthorizationError("execution lock version conflict")
        for field in ("deployment_id", "account_id", "region", "registry_record_digest"):
            if request.get(field) != existing.get(field):
                raise AuthorizationError(f"execution lock {field} cannot be reassigned")
        if existing.get("status") == "HELD":
            if _parse(existing["expires_at"]) > now.astimezone(UTC):
                raise AuthorizationError("deployment execution lock is already held")
            raise AuthorizationError(
                "reviewed stale-lock recovery is required; automatic takeover is forbidden"
            )
        if existing.get("status") != "RELEASED":
            raise AuthorizationError("execution lock has an unknown state")
        next_version = existing["lock_version"] + 1

    acquired_at = now.astimezone(UTC).replace(microsecond=0)
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
