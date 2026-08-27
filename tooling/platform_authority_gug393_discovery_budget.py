"""Deterministic, provider-independent discovery budget for GUG-393.

This module owns no AWS client and performs no network activity.  It validates
an explicit owner-supplied envelope, converts every USD value to integer
nano-USD, and provides one shared fail-before-increment ledger for the later
GUG-392 provider integration.  The cost model is an authorization input, not a
claim about AWS pricing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
import threading
from typing import Any, Mapping


RECORD_TYPE = "scanalyze.platform_authority.gug393_discovery_budget.v1"
SUMMARY_RECORD_TYPE = (
    "scanalyze.platform_authority.gug393_discovery_budget_summary.v1"
)
SCHEMA_VERSION = 1

HARD_MAX_NETWORK_CALLS = 5_006
HARD_MAX_PROVIDER_CALLS = 5_000
HARD_MAX_CREDENTIAL_VENDING_CALLS = 6
HARD_MAX_PAGE_CALLS = 4_300
HARD_MAX_RESPONSE_BYTES = 256 * 1024
HARD_MAX_TOTAL_RESPONSE_BYTES = 32 * 1024 * 1024
NANO_USD_PER_USD = 1_000_000_000

_TOP_LEVEL_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "max_network_calls",
        "max_provider_calls",
        "max_credential_vending_calls",
        "max_page_calls",
        "max_response_bytes",
        "max_total_response_bytes",
        "maximum_cost_usd",
        "cost_model",
    }
)
_COST_MODEL_FIELDS = frozenset(
    {
        "fixed_run_cost_usd_upper",
        "per_network_attempt_cost_usd_upper",
        "per_projected_response_byte_cost_usd_upper",
        "pricing_reference_digest",
        "valid_from",
        "valid_until",
    }
)
_LIMITS = {
    "max_network_calls": HARD_MAX_NETWORK_CALLS,
    "max_provider_calls": HARD_MAX_PROVIDER_CALLS,
    "max_credential_vending_calls": HARD_MAX_CREDENTIAL_VENDING_CALLS,
    "max_page_calls": HARD_MAX_PAGE_CALLS,
    "max_response_bytes": HARD_MAX_RESPONSE_BYTES,
    "max_total_response_bytes": HARD_MAX_TOTAL_RESPONSE_BYTES,
}
_USD = re.compile(r"^(0|[1-9][0-9]*)\.([0-9]{9})$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_OPERATION = re.compile(r"^[a-z0-9][a-z0-9-]*:[A-Z][A-Za-z0-9]*$")
_CREDENTIAL_VEND_OPERATION = "sso:GetRoleCredentials"


class DiscoveryBudgetError(ValueError):
    """Stable, public-safe budget failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code if _TOKEN.fullmatch(code) else "DISCOVERY_BUDGET_BLOCKED"
        )
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise DiscoveryBudgetError(code)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise DiscoveryBudgetError("DISCOVERY_BUDGET_INVALID") from exc


def _canonical_copy(value: Any) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - encoder is closed
        raise DiscoveryBudgetError("DISCOVERY_BUDGET_INVALID") from exc


def _digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _nano_usd(value: Any) -> int:
    if not isinstance(value, str):
        _fail("DISCOVERY_BUDGET_COST_INVALID")
    match = _USD.fullmatch(value)
    if match is None:
        _fail("DISCOVERY_BUDGET_COST_INVALID")
    try:
        return int(match.group(1)) * NANO_USD_PER_USD + int(match.group(2))
    except ValueError as exc:
        raise DiscoveryBudgetError("DISCOVERY_BUDGET_COST_INVALID") from exc


def _stamp(value: Any) -> datetime:
    if not isinstance(value, str) or _STAMP.fullmatch(value) is None:
        _fail("DISCOVERY_BUDGET_WINDOW_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DiscoveryBudgetError("DISCOVERY_BUDGET_WINDOW_INVALID") from exc
    canonical = (
        parsed.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if parsed.tzinfo is None or canonical != value:
        _fail("DISCOVERY_BUDGET_WINDOW_INVALID")
    return parsed.astimezone(UTC).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class ValidatedDiscoveryBudget:
    """Canonical owner document plus its recomputable cost and digest."""

    document: dict[str, Any]
    digest: str
    worst_case_cost_nano_usd: int


def validate_discovery_budget(
    value: Mapping[str, Any],
    now: datetime | None = None,
    require_active: bool = False,
) -> ValidatedDiscoveryBudget:
    """Validate and detach one explicit owner-supplied discovery budget.

    Historical validation is clock-free.  Action-time validation must set
    ``require_active=True`` and supply an aware ``now``; this module never
    silently consults a live clock.
    """

    if type(require_active) is not bool:
        _fail("DISCOVERY_BUDGET_INVALID")
    if not isinstance(value, Mapping) or set(value) != _TOP_LEVEL_FIELDS:
        _fail("DISCOVERY_BUDGET_INVALID")
    document = _canonical_copy(value)
    if (
        not isinstance(document, dict)
        or document.get("record_type") != RECORD_TYPE
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != SCHEMA_VERSION
    ):
        _fail("DISCOVERY_BUDGET_INVALID")

    for field, hard_limit in _LIMITS.items():
        supplied = document.get(field)
        if type(supplied) is not int or not 0 <= supplied <= hard_limit:
            _fail("DISCOVERY_BUDGET_HARD_CEILING_EXCEEDED")

    if (
        document["max_provider_calls"] > document["max_network_calls"]
        or document["max_credential_vending_calls"]
        > document["max_network_calls"]
        or document["max_network_calls"]
        > document["max_provider_calls"]
        + document["max_credential_vending_calls"]
        or document["max_page_calls"] > document["max_provider_calls"]
        or document["max_response_bytes"]
        > document["max_total_response_bytes"]
    ):
        _fail("DISCOVERY_BUDGET_INVALID")

    maximum_cost = _nano_usd(document.get("maximum_cost_usd"))
    cost_model = document.get("cost_model")
    if not isinstance(cost_model, Mapping) or set(cost_model) != _COST_MODEL_FIELDS:
        _fail("DISCOVERY_COST_MODEL_INVALID")
    pricing_reference = cost_model.get("pricing_reference_digest")
    if not isinstance(pricing_reference, str) or _DIGEST.fullmatch(
        pricing_reference
    ) is None or pricing_reference == "sha256:" + "0" * 64:
        _fail("DISCOVERY_COST_MODEL_INVALID")

    fixed_cost = _nano_usd(cost_model.get("fixed_run_cost_usd_upper"))
    per_network = _nano_usd(
        cost_model.get("per_network_attempt_cost_usd_upper")
    )
    per_byte = _nano_usd(
        cost_model.get("per_projected_response_byte_cost_usd_upper")
    )
    valid_from = _stamp(cost_model.get("valid_from"))
    valid_until = _stamp(cost_model.get("valid_until"))
    if valid_from >= valid_until:
        _fail("DISCOVERY_BUDGET_WINDOW_INVALID")

    if now is not None:
        if not isinstance(now, datetime) or now.tzinfo is None:
            _fail("DISCOVERY_BUDGET_CLOCK_INVALID")
        evaluated_at = now.astimezone(UTC)
    else:
        evaluated_at = None
    if require_active:
        if evaluated_at is None:
            _fail("DISCOVERY_BUDGET_CLOCK_REQUIRED")
        if not valid_from <= evaluated_at < valid_until:
            _fail("DISCOVERY_COST_MODEL_INACTIVE")

    worst_case_cost = (
        fixed_cost
        + document["max_network_calls"] * per_network
        + document["max_total_response_bytes"] * per_byte
    )
    if worst_case_cost > maximum_cost:
        _fail("DISCOVERY_COST_BUDGET_INSUFFICIENT")

    return ValidatedDiscoveryBudget(
        document=document,
        digest=_digest(document),
        worst_case_cost_nano_usd=worst_case_cost,
    )


class GlobalDiscoveryBudget:
    """Atomic all-domain call, page, response-byte, and modeled-cost ledger."""

    def __init__(self, validated: ValidatedDiscoveryBudget) -> None:
        if type(validated) is not ValidatedDiscoveryBudget:
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")
        try:
            checked = validate_discovery_budget(validated.document)
        except DiscoveryBudgetError as exc:
            raise DiscoveryBudgetError("DISCOVERY_BUDGET_BINDING_INVALID") from exc
        if (
            checked.digest != validated.digest
            or checked.worst_case_cost_nano_usd
            != validated.worst_case_cost_nano_usd
        ):
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")

        self._document = checked.document
        self._budget_digest = checked.digest
        self._cost_model_digest = _digest(self._document["cost_model"])
        model = self._document["cost_model"]
        self._maximum_cost = _nano_usd(self._document["maximum_cost_usd"])
        self._per_network_cost = _nano_usd(
            model["per_network_attempt_cost_usd_upper"]
        )
        self._per_byte_cost = _nano_usd(
            model["per_projected_response_byte_cost_usd_upper"]
        )
        self._modeled_cost = _nano_usd(model["fixed_run_cost_usd_upper"])
        self._provider_calls = 0
        self._credential_vending_calls = 0
        self._network_calls = 0
        self._page_calls = 0
        self._response_bytes = 0
        self._lock = threading.Lock()

    def _require_cost(self, value: int) -> None:
        if value > self._maximum_cost:
            _fail("DISCOVERY_COST_BUDGET_EXCEEDED")

    def reserve_provider_call(self, operation: str, is_page: bool) -> None:
        """Reserve one provider operation before any SDK invocation."""

        if (
            not isinstance(operation, str)
            or _OPERATION.fullmatch(operation) is None
            or operation == _CREDENTIAL_VEND_OPERATION
            or type(is_page) is not bool
        ):
            _fail("DISCOVERY_PROVIDER_OPERATION_INVALID")
        page_call = is_page or operation.split(":", 1)[1].startswith("List")
        with self._lock:
            next_provider = self._provider_calls + 1
            next_network = self._network_calls + 1
            next_pages = self._page_calls + int(page_call)
            next_cost = self._modeled_cost + self._per_network_cost
            if next_provider > self._document["max_provider_calls"]:
                _fail("DISCOVERY_PROVIDER_CALL_BUDGET_EXCEEDED")
            if next_network > self._document["max_network_calls"]:
                _fail("DISCOVERY_NETWORK_CALL_BUDGET_EXCEEDED")
            if next_pages > self._document["max_page_calls"]:
                _fail("DISCOVERY_PAGE_CALL_BUDGET_EXCEEDED")
            self._require_cost(next_cost)
            self._provider_calls = next_provider
            self._network_calls = next_network
            self._page_calls = next_pages
            self._modeled_cost = next_cost

    def record_credential_vend(self, operation: str) -> None:
        """Count the sole permitted direct-SSO credential network operation."""

        if operation != _CREDENTIAL_VEND_OPERATION:
            _fail("DISCOVERY_CREDENTIAL_VENDING_OPERATION_NOT_ALLOWED")
        with self._lock:
            next_vending = self._credential_vending_calls + 1
            next_network = self._network_calls + 1
            next_cost = self._modeled_cost + self._per_network_cost
            if next_vending > self._document["max_credential_vending_calls"]:
                _fail("DISCOVERY_CREDENTIAL_VENDING_BUDGET_EXCEEDED")
            if next_network > self._document["max_network_calls"]:
                _fail("DISCOVERY_NETWORK_CALL_BUDGET_EXCEEDED")
            self._require_cost(next_cost)
            self._credential_vending_calls = next_vending
            self._network_calls = next_network
            self._modeled_cost = next_cost

    def record_response(self, byte_count: int) -> None:
        """Commit one sanitized/projected provider response byte count."""

        if type(byte_count) is not int or byte_count < 0:
            _fail("DISCOVERY_RESPONSE_BYTE_COUNT_INVALID")
        with self._lock:
            if byte_count > self._document["max_response_bytes"]:
                _fail("DISCOVERY_RESPONSE_BYTE_BUDGET_EXCEEDED")
            next_bytes = self._response_bytes + byte_count
            next_cost = self._modeled_cost + byte_count * self._per_byte_cost
            if next_bytes > self._document["max_total_response_bytes"]:
                _fail("DISCOVERY_TOTAL_RESPONSE_BYTE_BUDGET_EXCEEDED")
            self._require_cost(next_cost)
            self._response_bytes = next_bytes
            self._modeled_cost = next_cost

    def summary(self) -> dict[str, Any]:
        """Return digest-only bindings and scalar counters, never raw inputs."""

        with self._lock:
            body = {
                "record_type": SUMMARY_RECORD_TYPE,
                "budget_digest": self._budget_digest,
                "cost_model_digest": self._cost_model_digest,
                "provider_calls": self._provider_calls,
                "credential_vending_calls": self._credential_vending_calls,
                "network_calls": self._network_calls,
                "page_calls": self._page_calls,
                "projected_response_bytes": self._response_bytes,
                "modeled_cost_nano_usd": self._modeled_cost,
            }
            return {**body, "summary_digest": _digest(body)}


__all__ = [
    "DiscoveryBudgetError",
    "GlobalDiscoveryBudget",
    "HARD_MAX_CREDENTIAL_VENDING_CALLS",
    "HARD_MAX_NETWORK_CALLS",
    "HARD_MAX_PAGE_CALLS",
    "HARD_MAX_PROVIDER_CALLS",
    "HARD_MAX_RESPONSE_BYTES",
    "HARD_MAX_TOTAL_RESPONSE_BYTES",
    "NANO_USD_PER_USD",
    "RECORD_TYPE",
    "SCHEMA_VERSION",
    "SUMMARY_RECORD_TYPE",
    "ValidatedDiscoveryBudget",
    "validate_discovery_budget",
]
