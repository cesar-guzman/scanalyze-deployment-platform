"""Sealed aggregate budget for one atomic GUG-376 collision admission.

One opaque instance is shared by the inventory and candidate-policy readers.
The budget reserves every SDK call before the boundary, accounts its projected
response afterwards, and binds it to the exact combined transcript.  It has no
AWS imports, performs no live work, and retains no response values.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
import threading
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_collision_catalog import TARGET_COUNT
from tooling import (
    platform_authority_gug376_collision_transcript_contract as transcript,
)


BUDGET_RECORD_TYPE = "scanalyze.platform_authority.gug376_collision_budget.v1"
SUMMARY_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_collision_budget_summary.v1"
)
WORST_CASE_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_collision_budget_worst_case.v1"
)

LOCAL_DIRECT_SSO = "LOCAL_DIRECT_SSO"
POST_READER_RUNTIME = "POST_READER_RUNTIME"
SESSION_MODES = frozenset({LOCAL_DIRECT_SSO, POST_READER_RUNTIME})
DIRECT_SSO = "DIRECT_SSO"
ASSUME_ROLE = "ASSUME_ROLE"
ASSUME_ROLE_DURATION_SECONDS = 900

INVENTORY_CAPTURE_COUNT = 2
CANDIDATE_CAPTURE_COUNT = 3
MAX_SESSION_OPENS = 10
# Compatibility name: only POST_READER_RUNTIME turns all ten session opens
# into AssumeRole calls.  LOCAL_DIRECT_SSO has zero AssumeRole calls.
MAX_ROLE_OPENS = MAX_SESSION_OPENS
MAX_SOURCE_CREDENTIAL_BINDINGS = 2
MAX_SOURCE_CREDENTIAL_VENDS = 2
MAX_RESPONSE_BYTES = 256 * 1024
MAX_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_MODELED_COST_MICRO_USD = 50_000
MODELED_COST_MICRO_USD_PER_ROLE_OPEN = 2
MODELED_COST_MICRO_USD_PER_SOURCE_VEND = 2
MODELED_COST_MICRO_USD_PER_CALL = 2
MODELED_RESPONSE_QUANTUM_BYTES = 1024
MODELED_COST_MICRO_USD_PER_RESPONSE_QUANTUM = 1

# Exact current provider topology used for the upper-bound derivation.  The
# inventory reader has seven paginator streams per capture: artifact buckets,
# authority CFN/KMS, and management CFN/SSO instance/application/permission
# sets.  The closed item cap can additionally drive one detail call per listed
# permission set.  Candidate captures conservatively treat every retained
# target as both a MAX_PAGES inventory stream and a one-call ownership stream.
INVENTORY_PAGINATED_STREAMS_PER_CAPTURE = 7
INVENTORY_DIRECT_SELECTOR_CALLS_PER_CAPTURE = TARGET_COUNT
# The paginator can return up to the provider's closed 2,048-item cap across
# its pages, after which the provider performs one DescribePermissionSet call
# per returned ARN.  The call budget must cover those attempts even if a later
# transcript invariant rejects an overlong detail stream.
MAX_PERMISSION_SET_DETAIL_CALLS_PER_CAPTURE = 2_048
IDENTITY_CALLS_PER_CAPTURE = 2
HEADROOM_PERCENT = 10


def _ceil_percent(value: int, percent: int) -> int:
    return (value * percent + 99) // 100


_INVENTORY_PROVIDER_BASE = INVENTORY_CAPTURE_COUNT * (
    IDENTITY_CALLS_PER_CAPTURE
    + INVENTORY_PAGINATED_STREAMS_PER_CAPTURE * transcript.MAX_PAGES
    + INVENTORY_DIRECT_SELECTOR_CALLS_PER_CAPTURE
    + MAX_PERMISSION_SET_DETAIL_CALLS_PER_CAPTURE
)
_CANDIDATE_PROVIDER_BASE = CANDIDATE_CAPTURE_COUNT * (
    IDENTITY_CALLS_PER_CAPTURE
    + TARGET_COUNT * transcript.MAX_PAGES
    + TARGET_COUNT
)
_PROVIDER_BASE = _INVENTORY_PROVIDER_BASE + _CANDIDATE_PROVIDER_BASE
_PROVIDER_HEADROOM = _ceil_percent(_PROVIDER_BASE, HEADROOM_PERCENT)
MAX_PROVIDER_CALLS = _PROVIDER_BASE + _PROVIDER_HEADROOM

_PAGE_BASE = (
    INVENTORY_CAPTURE_COUNT
    * INVENTORY_PAGINATED_STREAMS_PER_CAPTURE
    * transcript.MAX_PAGES
    + CANDIDATE_CAPTURE_COUNT * TARGET_COUNT * transcript.MAX_PAGES
)
_PAGE_HEADROOM = _ceil_percent(_PAGE_BASE, HEADROOM_PERCENT)
MAX_PAGE_CALLS = _PAGE_BASE + _PAGE_HEADROOM
MAX_NETWORK_CALLS = MAX_PROVIDER_CALLS + MAX_SESSION_OPENS

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,191}$")
_BUDGET_TOKEN = object()
_RESERVATION_TOKEN = object()
_MISSING = object()
_STAGES = frozenset({"inventory", "candidate"})
_DOMAINS = frozenset({"authority", "management"})
_PURPOSES_BY_STAGE = {
    "inventory": (
        "policy-discovery-independent-scan-1",
        "policy-discovery-independent-scan-2",
    ),
    "candidate": (
        "independent-snapshot-1",
        "independent-snapshot-2",
        "pre-effect-snapshot",
    ),
}
_CAPTURE_INDEXES_BY_STAGE = {
    "inventory": frozenset({1, 2}),
    "candidate": frozenset({1, 2, 3}),
}
_EXPECTED_SESSION_KEYS = frozenset(
    (stage, domain, purpose)
    for stage, purposes in _PURPOSES_BY_STAGE.items()
    for purpose in purposes
    for domain in _DOMAINS
)


class CollisionBudgetError(RuntimeError):
    """Stable, value-free failure from the budget boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CollisionBudgetError(code)


def _copy(value: object, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception:
        raise CollisionBudgetError(code) from None


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _sealed_event(body: Mapping[str, Any]) -> dict[str, Any]:
    copied = _copy(body, "COLLISION_BUDGET_EVENT_INVALID")
    return {**copied, "event_digest": canonical_digest(copied)}


def _event_digest_valid(event: Mapping[str, Any]) -> bool:
    body = {key: value for key, value in event.items() if key != "event_digest"}
    return event.get("event_digest") == canonical_digest(body)


def _modeled_response_cost(byte_count: int) -> int:
    if byte_count == 0:
        return 0
    quanta = (
        byte_count + MODELED_RESPONSE_QUANTUM_BYTES - 1
    ) // MODELED_RESPONSE_QUANTUM_BYTES
    return quanta * MODELED_COST_MICRO_USD_PER_RESPONSE_QUANTUM


def collision_budget_worst_case() -> dict[str, Any]:
    """Return the fixed, replayable derivation of provider/page caps."""

    body = {
        "record_type": WORST_CASE_RECORD_TYPE,
        "target_count": TARGET_COUNT,
        "inventory_capture_count": INVENTORY_CAPTURE_COUNT,
        "candidate_capture_count": CANDIDATE_CAPTURE_COUNT,
        "max_pages_per_stream": transcript.MAX_PAGES,
        "inventory_paginated_streams_per_capture": (
            INVENTORY_PAGINATED_STREAMS_PER_CAPTURE
        ),
        "inventory_direct_selector_calls_per_capture": (
            INVENTORY_DIRECT_SELECTOR_CALLS_PER_CAPTURE
        ),
        "max_permission_set_detail_calls_per_capture": (
            MAX_PERMISSION_SET_DETAIL_CALLS_PER_CAPTURE
        ),
        "identity_calls_per_capture": IDENTITY_CALLS_PER_CAPTURE,
        "inventory_provider_calls_base": _INVENTORY_PROVIDER_BASE,
        "candidate_provider_calls_base": _CANDIDATE_PROVIDER_BASE,
        "provider_calls_base": _PROVIDER_BASE,
        "provider_calls_headroom": _PROVIDER_HEADROOM,
        "max_provider_calls": MAX_PROVIDER_CALLS,
        "page_calls_base": _PAGE_BASE,
        "page_calls_headroom": _PAGE_HEADROOM,
        "max_page_calls": MAX_PAGE_CALLS,
        "headroom_percent": HEADROOM_PERCENT,
        "max_network_calls": MAX_NETWORK_CALLS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "max_modeled_cost_micro_usd": MAX_MODELED_COST_MICRO_USD,
        "modeled_max_cost_micro_usd": (
            MAX_PROVIDER_CALLS * MODELED_COST_MICRO_USD_PER_CALL
            + MAX_SESSION_OPENS * MODELED_COST_MICRO_USD_PER_ROLE_OPEN
            + _modeled_response_cost(MAX_TOTAL_RESPONSE_BYTES)
        ),
    }
    return {**body, "derivation_digest": canonical_digest(body)}


def _budget_body(session_mode: str, operation: str) -> dict[str, Any]:
    derivation = collision_budget_worst_case()
    return {
        "record_type": BUDGET_RECORD_TYPE,
        "session_mode": session_mode,
        "operation": operation,
        "operation_digest": canonical_digest(operation),
        "max_session_opens": MAX_SESSION_OPENS,
        "max_source_credential_bindings": MAX_SOURCE_CREDENTIAL_BINDINGS,
        "max_source_credential_vends": MAX_SOURCE_CREDENTIAL_VENDS,
        "max_provider_calls": MAX_PROVIDER_CALLS,
        "max_network_calls": MAX_NETWORK_CALLS,
        "max_page_calls": MAX_PAGE_CALLS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "max_modeled_cost_micro_usd": MAX_MODELED_COST_MICRO_USD,
        "expected_session_keys_digest": canonical_digest(
            [list(key) for key in sorted(_EXPECTED_SESSION_KEYS)]
        ),
        "worst_case_derivation_digest": derivation["derivation_digest"],
    }


def collision_budget_digest(*, session_mode: str, operation: str) -> str:
    """Compute the fixed budget digest for an already validated mode/op pair."""

    if session_mode not in SESSION_MODES or _OPERATION.fullmatch(operation) is None:
        _fail("COLLISION_BUDGET_CONFIG_INVALID")
    return canonical_digest(_budget_body(session_mode, operation))


def _operation_phase(operation: str) -> str:
    try:
        from tooling.platform_authority_gug376_collision_admission import (
            route_collision_operation_phase,
        )

        return route_collision_operation_phase(operation)
    except Exception:
        raise CollisionBudgetError(
            "COLLISION_BUDGET_OPERATION_INVALID"
        ) from None


class _ProviderCallReservation:
    __slots__ = (
        "_token", "_budget", "_ordinal", "_stage", "_domain",
        "_operation", "_page_call", "_projected_response_bytes",
        "_modeled_cost_micro_usd", "_state", "_response_bytes",
        "_response_digest", "_transcript_event", "_transcript_event_digest",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        _fail("COLLISION_BUDGET_RESERVATION_SUBCLASS_FORBIDDEN")

    def __init__(
        self,
        token: object,
        *,
        budget: "_CollisionBudget",
        ordinal: int,
        stage: str,
        domain: str,
        operation: str,
        page_call: bool,
        projected_response_bytes: int,
        modeled_cost_micro_usd: int,
    ) -> None:
        if token is not _RESERVATION_TOKEN:
            _fail("COLLISION_BUDGET_RESERVATION_BUILDER_REQUIRED")
        values = {
            "_token": token,
            "_budget": budget,
            "_ordinal": ordinal,
            "_stage": stage,
            "_domain": domain,
            "_operation": operation,
            "_page_call": page_call,
            "_projected_response_bytes": projected_response_bytes,
            "_modeled_cost_micro_usd": modeled_cost_micro_usd,
            "_state": "RESERVED",
            "_response_bytes": None,
            "_response_digest": None,
            "_transcript_event": None,
            "_transcript_event_digest": None,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        _fail("COLLISION_BUDGET_RESERVATION_IMMUTABLE")


class _CollisionBudget:
    __slots__ = (
        "_token", "_session_mode", "_operation", "_operation_phase",
        "_budget_digest", "_state", "_failure_code", "_session_keys",
        "_source_bindings", "_journal", "_reservations",
        "_session_open_count", "_direct_sso_session_opens",
        "_assume_role_opens", "_source_credential_vends",
        "_provider_calls", "_network_calls", "_page_calls",
        "_pending_projected_response_bytes", "_response_bytes",
        "_non_response_cost_micro_usd", "_modeled_cost_micro_usd",
        "_summary", "_integrity_digest", "_lock",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        _fail("COLLISION_BUDGET_SUBCLASS_FORBIDDEN")

    def __init__(
        self,
        token: object,
        *,
        session_mode: str,
        operation: str,
        operation_phase: str,
    ) -> None:
        if token is not _BUDGET_TOKEN:
            _fail("COLLISION_BUDGET_BUILDER_REQUIRED")
        values: dict[str, Any] = {
            "_token": token,
            "_session_mode": session_mode,
            "_operation": operation,
            "_operation_phase": operation_phase,
            "_budget_digest": collision_budget_digest(
                session_mode=session_mode, operation=operation
            ),
            "_state": "ACTIVE",
            "_failure_code": None,
            "_session_keys": set(),
            "_source_bindings": {},
            "_journal": [],
            "_reservations": [],
            "_session_open_count": 0,
            "_direct_sso_session_opens": 0,
            "_assume_role_opens": 0,
            "_source_credential_vends": 0,
            "_provider_calls": 0,
            "_network_calls": 0,
            "_page_calls": 0,
            "_pending_projected_response_bytes": 0,
            "_response_bytes": 0,
            "_non_response_cost_micro_usd": 0,
            "_modeled_cost_micro_usd": 0,
            "_summary": None,
            "_integrity_digest": "",
            "_lock": threading.Lock(),
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_integrity_digest", _integrity_digest(self))

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        _fail("COLLISION_BUDGET_IMMUTABLE")

    @property
    def session_mode(self) -> str:
        """Expose only the sealed mode required by typed reader adapters."""

        return self._session_mode

    @property
    def operation(self) -> str:
        """Expose only the sealed operation required by typed loaders."""

        return self._operation

    def reserve_direct_sso_session_open(
        self,
        *,
        domain: str,
        policy_stage: str,
        capture_index: int,
        purpose: str,
    ) -> None:
        """Typed facade used by the local direct-SSO reader factory."""

        stage = {
            "inventory": "inventory",
            "candidate-detail": "candidate",
        }.get(policy_stage)
        purposes = _PURPOSES_BY_STAGE.get(str(stage))
        if (
            stage is None
            or type(capture_index) is not int
            or purposes is None
            or not 1 <= capture_index <= len(purposes)
            or purpose != purposes[capture_index - 1]
        ):
            _fail("COLLISION_BUDGET_SESSION_OPEN_INVALID")
        reserve_direct_sso_session_open(
            self,
            stage=stage,
            domain=domain,
            purpose=purpose,
        )

    def record_source_credential_binding(
        self,
        *,
        domain: str,
        binding_digest: str,
        credential_vended: bool,
    ) -> None:
        """Typed facade for one underlying source binding per domain."""

        record_source_credential_binding(
            self,
            domain=domain,
            binding_digest=binding_digest,
            credential_vended=credential_vended,
        )

    def complete(
        self, *, transcript_events: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """Typed facade for the atomic loader's terminal seal."""

        return complete_collision_budget(
            self,
            transcript_events=transcript_events,
        )

    def evidence_events(self) -> list[dict[str, Any]]:
        """Typed facade for detached terminal budget evidence."""

        return collision_budget_events(self)


def _integrity_digest(value: _CollisionBudget) -> str:
    """O(1) scalar seal; full journal seals are replayed at completion."""

    return canonical_digest(
        {
            "budget_digest": value._budget_digest,
            "operation_phase": value._operation_phase,
            "state": value._state,
            "failure_code": value._failure_code,
            "session_key_count": len(value._session_keys),
            "source_binding_count": len(value._source_bindings),
            "journal_count": len(value._journal),
            "reservation_count": len(value._reservations),
            "session_open_count": value._session_open_count,
            "direct_sso_session_opens": value._direct_sso_session_opens,
            "assume_role_opens": value._assume_role_opens,
            "source_credential_vends": value._source_credential_vends,
            "provider_calls": value._provider_calls,
            "network_calls": value._network_calls,
            "page_calls": value._page_calls,
            "pending_projected_response_bytes": (
                value._pending_projected_response_bytes
            ),
            "response_bytes": value._response_bytes,
            "non_response_cost_micro_usd": value._non_response_cost_micro_usd,
            "modeled_cost_micro_usd": value._modeled_cost_micro_usd,
            "summary_digest": (
                value._summary.get("summary_digest")
                if isinstance(value._summary, Mapping)
                else None
            ),
        }
    )


def _checked_budget(value: object) -> _CollisionBudget:
    if type(value) is not _CollisionBudget or value._token is not _BUDGET_TOKEN:
        _fail("COLLISION_BUDGET_INVALID")
    return value


def _verify_locked(value: _CollisionBudget) -> None:
    if value._integrity_digest != _integrity_digest(value):
        _fail("COLLISION_BUDGET_INTEGRITY_INVALID")


def _refresh_locked(value: _CollisionBudget) -> None:
    object.__setattr__(value, "_integrity_digest", _integrity_digest(value))


def _require_active_locked(value: _CollisionBudget) -> None:
    _verify_locked(value)
    if value._state != "ACTIVE":
        _fail("COLLISION_BUDGET_NOT_ACTIVE")


def _poison_locked(value: _CollisionBudget, code: str) -> None:
    object.__setattr__(value, "_state", "FAILED")
    object.__setattr__(value, "_failure_code", code)
    _refresh_locked(value)
    _fail(code)


def _recompute_modeled_cost_locked(value: _CollisionBudget) -> int:
    return value._non_response_cost_micro_usd + _modeled_response_cost(
        value._response_bytes + value._pending_projected_response_bytes
    )


def _checked_reservation(
    value: object,
) -> tuple[_ProviderCallReservation, _CollisionBudget]:
    if (
        type(value) is not _ProviderCallReservation
        or value._token is not _RESERVATION_TOKEN
    ):
        _fail("COLLISION_BUDGET_RESERVATION_INVALID")
    budget = _checked_budget(value._budget)
    journal_index = value._ordinal - 1
    if (
        journal_index < 0
        or journal_index >= len(budget._journal)
        or budget._journal[journal_index] is not value
    ):
        _fail("COLLISION_BUDGET_RESERVATION_INVALID")
    return value, budget


def build_collision_budget(*, session_mode: str, operation: str) -> object:
    """Build the only accepted budget, sealed to session mode and operation."""

    if session_mode not in SESSION_MODES or not isinstance(operation, str):
        _fail("COLLISION_BUDGET_CONFIG_INVALID")
    if _OPERATION.fullmatch(operation) is None:
        _fail("COLLISION_BUDGET_CONFIG_INVALID")
    phase = _operation_phase(operation)
    return _CollisionBudget(
        _BUDGET_TOKEN,
        session_mode=session_mode,
        operation=operation,
        operation_phase=phase,
    )


def reserve_session_open(
    budget: object,
    *,
    stage: str,
    domain: str,
    purpose: str,
    session_kind: str,
    duration_seconds: int | None = None,
) -> None:
    """Reserve one exact SDK session open before invoking its adapter."""

    checked = _checked_budget(budget)
    key = (stage, domain, purpose)
    expected_kind = (
        DIRECT_SSO
        if checked._session_mode == LOCAL_DIRECT_SSO
        else ASSUME_ROLE
    )
    expected_duration = (
        None
        if checked._session_mode == LOCAL_DIRECT_SSO
        else ASSUME_ROLE_DURATION_SECONDS
    )
    if (
        key not in _EXPECTED_SESSION_KEYS
        or session_kind != expected_kind
        or duration_seconds != expected_duration
    ):
        _fail("COLLISION_BUDGET_SESSION_OPEN_INVALID")
    with checked._lock:
        _require_active_locked(checked)
        if checked._session_open_count >= MAX_SESSION_OPENS:
            _fail("COLLISION_BUDGET_SESSION_OPEN_LIMIT_EXCEEDED")
        if key in checked._session_keys:
            _fail("COLLISION_BUDGET_SESSION_OPEN_DUPLICATE")
        network_call = session_kind == ASSUME_ROLE
        cost = MODELED_COST_MICRO_USD_PER_ROLE_OPEN if network_call else 0
        modeled = (
            checked._modeled_cost_micro_usd + cost
        )
        if modeled > MAX_MODELED_COST_MICRO_USD:
            _fail("COLLISION_BUDGET_COST_LIMIT_EXCEEDED")
        event = _sealed_event(
            {
                "ordinal": len(checked._journal) + 1,
                "kind": "SESSION_OPEN",
                "session_mode": checked._session_mode,
                "session_kind": session_kind,
                "stage": stage,
                "domain": domain,
                "purpose": purpose,
                "duration_seconds": duration_seconds,
                "network_call": network_call,
                "modeled_cost_micro_usd": cost,
            }
        )
        checked._session_keys.add(key)
        checked._journal.append(event)
        object.__setattr__(
            checked, "_session_open_count", checked._session_open_count + 1
        )
        if session_kind == DIRECT_SSO:
            object.__setattr__(
                checked,
                "_direct_sso_session_opens",
                checked._direct_sso_session_opens + 1,
            )
        else:
            object.__setattr__(
                checked, "_assume_role_opens", checked._assume_role_opens + 1
            )
            object.__setattr__(
                checked, "_network_calls", checked._network_calls + 1
            )
        object.__setattr__(
            checked,
            "_non_response_cost_micro_usd",
            checked._non_response_cost_micro_usd + cost,
        )
        object.__setattr__(checked, "_modeled_cost_micro_usd", modeled)
        _refresh_locked(checked)


def reserve_direct_sso_session_open(
    budget: object, *, stage: str, domain: str, purpose: str
) -> None:
    reserve_session_open(
        budget,
        stage=stage,
        domain=domain,
        purpose=purpose,
        session_kind=DIRECT_SSO,
    )


def reserve_assume_role_open(
    budget: object,
    *,
    stage: str,
    domain: str,
    purpose: str,
    duration_seconds: int = ASSUME_ROLE_DURATION_SECONDS,
) -> None:
    reserve_session_open(
        budget,
        stage=stage,
        domain=domain,
        purpose=purpose,
        session_kind=ASSUME_ROLE,
        duration_seconds=duration_seconds,
    )


def record_source_credential_binding(
    budget: object,
    *,
    domain: str,
    binding_digest: str,
    credential_vended: bool,
) -> None:
    """Bind one PRE direct-SSO source; cached credentials set vend false."""

    checked = _checked_budget(budget)
    if (
        checked._session_mode != LOCAL_DIRECT_SSO
        or domain not in _DOMAINS
        or not _is_digest(binding_digest)
        or type(credential_vended) is not bool
    ):
        _fail("COLLISION_BUDGET_SOURCE_BINDING_INVALID")
    with checked._lock:
        _require_active_locked(checked)
        if len(checked._source_bindings) >= MAX_SOURCE_CREDENTIAL_BINDINGS:
            _fail("COLLISION_BUDGET_SOURCE_BINDING_LIMIT_EXCEEDED")
        if domain in checked._source_bindings:
            _fail("COLLISION_BUDGET_SOURCE_BINDING_DUPLICATE")
        vend_count = checked._source_credential_vends + int(credential_vended)
        if vend_count > MAX_SOURCE_CREDENTIAL_VENDS:
            _fail("COLLISION_BUDGET_SOURCE_VEND_LIMIT_EXCEEDED")
        cost = MODELED_COST_MICRO_USD_PER_SOURCE_VEND if credential_vended else 0
        if checked._modeled_cost_micro_usd + cost > MAX_MODELED_COST_MICRO_USD:
            _fail("COLLISION_BUDGET_COST_LIMIT_EXCEEDED")
        event = _sealed_event(
            {
                "ordinal": len(checked._journal) + 1,
                "kind": "SOURCE_CREDENTIAL_BINDING",
                "session_mode": checked._session_mode,
                "domain": domain,
                "binding_digest": binding_digest,
                "credential_vended": credential_vended,
                "network_call": credential_vended,
                "modeled_cost_micro_usd": cost,
            }
        )
        checked._source_bindings[domain] = (
            binding_digest,
            credential_vended,
        )
        checked._journal.append(event)
        object.__setattr__(checked, "_source_credential_vends", vend_count)
        if credential_vended:
            object.__setattr__(
                checked, "_network_calls", checked._network_calls + 1
            )
        object.__setattr__(
            checked,
            "_non_response_cost_micro_usd",
            checked._non_response_cost_micro_usd + cost,
        )
        object.__setattr__(
            checked,
            "_modeled_cost_micro_usd",
            checked._modeled_cost_micro_usd + cost,
        )
        _refresh_locked(checked)


def reserve_provider_call(
    budget: object,
    *,
    stage: str,
    domain: str,
    operation: str,
    page_call: bool | None = None,
    projected_response_bytes: int = MAX_RESPONSE_BYTES,
    modeled_cost_micro_usd: int = MODELED_COST_MICRO_USD_PER_CALL,
) -> object:
    """Reserve one SDK call and its worst-case in-flight response envelope."""

    checked = _checked_budget(budget)
    inferred_page_call = operation in transcript.LIST_DISCOVERY_OPERATIONS
    if page_call is None:
        page_call = inferred_page_call
    if (
        stage not in _STAGES
        or domain not in _DOMAINS
        or operation not in transcript.READ_ONLY_OPERATION_ALLOWLIST
        or type(page_call) is not bool
        or page_call is not inferred_page_call
        or type(projected_response_bytes) is not int
        or not 0 <= projected_response_bytes <= MAX_RESPONSE_BYTES
        or type(modeled_cost_micro_usd) is not int
        or modeled_cost_micro_usd < MODELED_COST_MICRO_USD_PER_CALL
    ):
        _fail("COLLISION_BUDGET_PROVIDER_RESERVATION_INVALID")
    with checked._lock:
        _require_active_locked(checked)
        if checked._provider_calls >= MAX_PROVIDER_CALLS:
            _fail("COLLISION_BUDGET_PROVIDER_CALL_LIMIT_EXCEEDED")
        if page_call and checked._page_calls >= MAX_PAGE_CALLS:
            _fail("COLLISION_BUDGET_PAGE_CALL_LIMIT_EXCEEDED")
        if checked._network_calls >= MAX_NETWORK_CALLS:
            _fail("COLLISION_BUDGET_NETWORK_CALL_LIMIT_EXCEEDED")
        projected_total = (
            checked._response_bytes
            + checked._pending_projected_response_bytes
            + projected_response_bytes
        )
        if projected_total > MAX_TOTAL_RESPONSE_BYTES:
            _fail("COLLISION_BUDGET_TOTAL_RESPONSE_LIMIT_EXCEEDED")
        non_response_cost = (
            checked._non_response_cost_micro_usd + modeled_cost_micro_usd
        )
        modeled_total = non_response_cost + _modeled_response_cost(
            projected_total
        )
        if modeled_total > MAX_MODELED_COST_MICRO_USD:
            _fail("COLLISION_BUDGET_COST_LIMIT_EXCEEDED")
        reservation = _ProviderCallReservation(
            _RESERVATION_TOKEN,
            budget=checked,
            ordinal=len(checked._journal) + 1,
            stage=stage,
            domain=domain,
            operation=operation,
            page_call=page_call,
            projected_response_bytes=projected_response_bytes,
            modeled_cost_micro_usd=modeled_cost_micro_usd,
        )
        checked._reservations.append(reservation)
        checked._journal.append(reservation)
        object.__setattr__(
            checked, "_provider_calls", checked._provider_calls + 1
        )
        object.__setattr__(
            checked, "_network_calls", checked._network_calls + 1
        )
        if page_call:
            object.__setattr__(
                checked, "_page_calls", checked._page_calls + 1
            )
        object.__setattr__(
            checked,
            "_pending_projected_response_bytes",
            checked._pending_projected_response_bytes
            + projected_response_bytes,
        )
        object.__setattr__(
            checked, "_non_response_cost_micro_usd", non_response_cost
        )
        object.__setattr__(
            checked, "_modeled_cost_micro_usd", modeled_total
        )
        _refresh_locked(checked)
        return reservation


def account_provider_response(
    reservation: object,
    *,
    response: object = _MISSING,
    response_bytes: int | None = None,
    response_digest: str | None = None,
) -> None:
    """Account one normalized SDK response after its reserved call returns."""

    checked_reservation, budget = _checked_reservation(reservation)
    if response is not _MISSING:
        if response_bytes is not None or response_digest is not None:
            _fail("COLLISION_BUDGET_RESPONSE_INVALID")
        try:
            serialized = canonical_json(response).encode("utf-8")
        except Exception:
            raise CollisionBudgetError("COLLISION_BUDGET_RESPONSE_INVALID") from None
        checked_bytes = len(serialized)
        checked_digest = canonical_digest(response)
    elif (
        type(response_bytes) is int
        and response_bytes >= 0
        and _is_digest(response_digest)
    ):
        checked_bytes = response_bytes
        checked_digest = response_digest
    else:
        _fail("COLLISION_BUDGET_RESPONSE_INVALID")
    with budget._lock:
        _require_active_locked(budget)
        if checked_reservation._state != "RESERVED":
            _fail("COLLISION_BUDGET_RESPONSE_ALREADY_ACCOUNTED")
        if (
            checked_bytes > MAX_RESPONSE_BYTES
            or checked_bytes > checked_reservation._projected_response_bytes
        ):
            _poison_locked(budget, "COLLISION_BUDGET_RESPONSE_LIMIT_EXCEEDED")
        total = budget._response_bytes + checked_bytes
        if total > MAX_TOTAL_RESPONSE_BYTES:
            _poison_locked(
                budget, "COLLISION_BUDGET_TOTAL_RESPONSE_LIMIT_EXCEEDED"
            )
        object.__setattr__(checked_reservation, "_state", "ACCOUNTED")
        object.__setattr__(checked_reservation, "_response_bytes", checked_bytes)
        object.__setattr__(checked_reservation, "_response_digest", checked_digest)
        object.__setattr__(budget, "_response_bytes", total)
        object.__setattr__(
            budget,
            "_pending_projected_response_bytes",
            budget._pending_projected_response_bytes
            - checked_reservation._projected_response_bytes,
        )
        modeled = _recompute_modeled_cost_locked(budget)
        if modeled > MAX_MODELED_COST_MICRO_USD:
            _poison_locked(budget, "COLLISION_BUDGET_COST_LIMIT_EXCEEDED")
        object.__setattr__(budget, "_modeled_cost_micro_usd", modeled)
        _refresh_locked(budget)


def _checked_transcript_event(
    value: object,
    *,
    stage: str,
    domain: str,
    operation: str,
    page_call: bool,
) -> dict[str, Any]:
    copied = _copy(value, "COLLISION_BUDGET_TRANSCRIPT_EVENT_INVALID")
    projection = copied.get("response_projection") if isinstance(copied, dict) else None
    capture_index = copied.get("capture_index") if isinstance(copied, dict) else None
    if (
        not isinstance(copied, dict)
        or set(copied) != set(transcript.EVENT_FIELDS)
        or copied.get("domain") != domain
        or copied.get("operation") != operation
        or page_call is not (operation in transcript.LIST_DISCOVERY_OPERATIONS)
        or type(capture_index) is not int
        or capture_index not in _CAPTURE_INDEXES_BY_STAGE[stage]
        or type(copied.get("ordinal")) is not int
        or copied["ordinal"] < 1
        or copied.get("region") != transcript.REGION
        or copied.get("outcome") not in transcript.READ_ONLY_OUTCOMES
        or copied.get("read_only") is not True
        or copied.get("aws_mutations") != 0
        or type(copied.get("page_index")) is not int
        or not 1 <= copied["page_index"] <= transcript.MAX_PAGES
        or not isinstance(projection, dict)
        or not _is_digest(copied.get("request_digest"))
        or not _is_digest(copied.get("operation_request_digest"))
        or copied.get("response_digest") != canonical_digest(projection)
        or not _is_digest(copied.get("session_digest"))
        or copied.get("provider_implementation_digest")
        != transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        or not isinstance(copied.get("target_ids"), list)
    ):
        _fail("COLLISION_BUDGET_TRANSCRIPT_EVENT_INVALID")
    return copied


def bind_provider_transcript_event(
    reservation: object, *, transcript_event: Mapping[str, Any]
) -> None:
    """Bind an accounted call to its final digest-only transcript event."""

    checked_reservation, budget = _checked_reservation(reservation)
    event = _checked_transcript_event(
        transcript_event,
        stage=checked_reservation._stage,
        domain=checked_reservation._domain,
        operation=checked_reservation._operation,
        page_call=checked_reservation._page_call,
    )
    with budget._lock:
        _require_active_locked(budget)
        if checked_reservation._state != "ACCOUNTED":
            _fail("COLLISION_BUDGET_TRANSCRIPT_BINDING_ORDER_INVALID")
        object.__setattr__(checked_reservation, "_state", "BOUND")
        object.__setattr__(checked_reservation, "_transcript_event", event)
        object.__setattr__(
            checked_reservation,
            "_transcript_event_digest",
            canonical_digest(event),
        )
        _refresh_locked(budget)


def _provider_event(value: _ProviderCallReservation) -> dict[str, Any]:
    if (
        value._state != "BOUND"
        or type(value._response_bytes) is not int
        or not _is_digest(value._response_digest)
        or not _is_digest(value._transcript_event_digest)
    ):
        _fail("COLLISION_BUDGET_EVIDENCE_INCOMPLETE")
    return _sealed_event(
        {
            "ordinal": value._ordinal,
            "kind": "PROVIDER_CALL",
            "stage": value._stage,
            "domain": value._domain,
            "operation": value._operation,
            "page_call": value._page_call,
            "projected_response_bytes": value._projected_response_bytes,
            "response_bytes": value._response_bytes,
            "response_digest": value._response_digest,
            "modeled_cost_micro_usd": value._modeled_cost_micro_usd,
            "transcript_event_digest": value._transcript_event_digest,
        }
    )


def _events_locked(value: _CollisionBudget) -> list[dict[str, Any]]:
    events = [
        _provider_event(item)
        if type(item) is _ProviderCallReservation
        else _copy(item, "COLLISION_BUDGET_EVENT_INVALID")
        for item in value._journal
    ]
    if [event.get("ordinal") for event in events] != list(
        range(1, len(events) + 1)
    ):
        _fail("COLLISION_BUDGET_INTEGRITY_INVALID")
    return events


def _mode_completion_valid(value: _CollisionBudget) -> bool:
    if value._session_mode == LOCAL_DIRECT_SSO:
        return (
            value._direct_sso_session_opens == MAX_SESSION_OPENS
            and value._assume_role_opens == 0
            and set(value._source_bindings) == set(_DOMAINS)
            and 0 <= value._source_credential_vends <= 2
        )
    return (
        value._direct_sso_session_opens == 0
        and value._assume_role_opens == MAX_SESSION_OPENS
        and not value._source_bindings
        and value._source_credential_vends == 0
    )


def complete_collision_budget(
    budget: object, *, transcript_events: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Seal a run only after exact sessions, responses, and transcripts."""

    checked = _checked_budget(budget)
    supplied = _copy(transcript_events, "COLLISION_BUDGET_TRANSCRIPT_INVALID")
    if not isinstance(supplied, list):
        _fail("COLLISION_BUDGET_TRANSCRIPT_INVALID")
    with checked._lock:
        _require_active_locked(checked)
        if (
            checked._session_open_count != MAX_SESSION_OPENS
            or checked._session_keys != set(_EXPECTED_SESSION_KEYS)
            or not _mode_completion_valid(checked)
        ):
            _fail("COLLISION_BUDGET_SESSION_MATRIX_INCOMPLETE")
        if checked._pending_projected_response_bytes != 0 or any(
            reservation._state != "BOUND"
            for reservation in checked._reservations
        ):
            _fail("COLLISION_BUDGET_EVIDENCE_INCOMPLETE")
        bound = [reservation._transcript_event for reservation in checked._reservations]
        if canonical_json(supplied) != canonical_json(bound):
            _fail("COLLISION_BUDGET_TRANSCRIPT_MISMATCH")
        events = _events_locked(checked)
        body = {
            "record_type": SUMMARY_RECORD_TYPE,
            "status": "COMPLETED",
            "session_mode": checked._session_mode,
            "operation": checked._operation,
            "operation_phase": checked._operation_phase,
            "budget_digest": checked._budget_digest,
            "session_open_count": checked._session_open_count,
            "direct_sso_session_opens": checked._direct_sso_session_opens,
            "assume_role_opens": checked._assume_role_opens,
            "assume_role_duration_seconds": (
                ASSUME_ROLE_DURATION_SECONDS
                if checked._assume_role_opens
                else None
            ),
            "source_credential_bindings": len(checked._source_bindings),
            "source_credential_vends": checked._source_credential_vends,
            "provider_calls": checked._provider_calls,
            "network_calls": checked._network_calls,
            "page_calls": checked._page_calls,
            "response_bytes": checked._response_bytes,
            "modeled_cost_micro_usd": checked._modeled_cost_micro_usd,
            "events_digest": canonical_digest(events),
            "transcript_events_digest": canonical_digest(supplied),
        }
        summary = {**body, "summary_digest": canonical_digest(body)}
        object.__setattr__(checked, "_state", "COMPLETED")
        object.__setattr__(checked, "_summary", summary)
        _refresh_locked(checked)
        return _copy(summary, "COLLISION_BUDGET_SUMMARY_INVALID")


def collision_budget_events(budget: object) -> list[dict[str, Any]]:
    """Return detached digest-only events after successful completion."""

    checked = _checked_budget(budget)
    with checked._lock:
        _verify_locked(checked)
        if checked._state != "COMPLETED" or checked._summary is None:
            _fail("COLLISION_BUDGET_NOT_COMPLETED")
        events = _events_locked(checked)
        if checked._summary.get("events_digest") != canonical_digest(events):
            _fail("COLLISION_BUDGET_INTEGRITY_INVALID")
        return _copy(events, "COLLISION_BUDGET_EVENT_INVALID")


def _validate_session_event(
    value: Mapping[str, Any], mode: str
) -> tuple[str, str, str]:
    fields = {
        "ordinal", "kind", "session_mode", "session_kind", "stage",
        "domain", "purpose", "duration_seconds", "network_call",
        "modeled_cost_micro_usd", "event_digest",
    }
    key = (value.get("stage"), value.get("domain"), value.get("purpose"))
    expected_kind = DIRECT_SSO if mode == LOCAL_DIRECT_SSO else ASSUME_ROLE
    expected_duration = None if mode == LOCAL_DIRECT_SSO else 900
    expected_network = mode == POST_READER_RUNTIME
    expected_cost = MODELED_COST_MICRO_USD_PER_ROLE_OPEN if expected_network else 0
    if (
        set(value) != fields
        or value.get("kind") != "SESSION_OPEN"
        or value.get("session_mode") != mode
        or value.get("session_kind") != expected_kind
        or value.get("duration_seconds") != expected_duration
        or value.get("network_call") is not expected_network
        or value.get("modeled_cost_micro_usd") != expected_cost
        or key not in _EXPECTED_SESSION_KEYS
        or not _event_digest_valid(value)
    ):
        _fail("COLLISION_BUDGET_EVENT_INVALID")
    return key  # type: ignore[return-value]


def _validate_source_event(
    value: Mapping[str, Any], mode: str
) -> tuple[str, bool, int]:
    fields = {
        "ordinal", "kind", "session_mode", "domain", "binding_digest",
        "credential_vended", "network_call", "modeled_cost_micro_usd",
        "event_digest",
    }
    vended = value.get("credential_vended")
    cost = MODELED_COST_MICRO_USD_PER_SOURCE_VEND if vended is True else 0
    if (
        set(value) != fields
        or mode != LOCAL_DIRECT_SSO
        or value.get("kind") != "SOURCE_CREDENTIAL_BINDING"
        or value.get("session_mode") != mode
        or value.get("domain") not in _DOMAINS
        or not _is_digest(value.get("binding_digest"))
        or type(vended) is not bool
        or value.get("network_call") is not vended
        or value.get("modeled_cost_micro_usd") != cost
        or not _event_digest_valid(value)
    ):
        _fail("COLLISION_BUDGET_EVENT_INVALID")
    return str(value["domain"]), vended, cost


def _validate_provider_event(
    value: Mapping[str, Any], transcript_event: Mapping[str, Any]
) -> tuple[int, int, int]:
    fields = {
        "ordinal", "kind", "stage", "domain", "operation", "page_call",
        "projected_response_bytes", "response_bytes", "response_digest",
        "modeled_cost_micro_usd", "transcript_event_digest", "event_digest",
    }
    stage = value.get("stage")
    operation = value.get("operation")
    projected = value.get("projected_response_bytes")
    response_bytes = value.get("response_bytes")
    cost = value.get("modeled_cost_micro_usd")
    page_call = value.get("page_call")
    if (
        set(value) != fields
        or value.get("kind") != "PROVIDER_CALL"
        or stage not in _STAGES
        or value.get("domain") not in _DOMAINS
        or operation not in transcript.READ_ONLY_OPERATION_ALLOWLIST
        or type(page_call) is not bool
        or page_call is not (operation in transcript.LIST_DISCOVERY_OPERATIONS)
        or type(projected) is not int
        or not 0 <= projected <= MAX_RESPONSE_BYTES
        or type(response_bytes) is not int
        or not 0 <= response_bytes <= projected
        or not _is_digest(value.get("response_digest"))
        or type(cost) is not int
        or cost < MODELED_COST_MICRO_USD_PER_CALL
        or value.get("transcript_event_digest") != canonical_digest(transcript_event)
        or not _event_digest_valid(value)
    ):
        _fail("COLLISION_BUDGET_EVENT_INVALID")
    _checked_transcript_event(
        transcript_event,
        stage=str(stage),
        domain=str(value["domain"]),
        operation=str(operation),
        page_call=page_call,
    )
    return int(page_call), response_bytes, cost


def validate_collision_budget_evidence(
    *,
    summary: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    transcript_events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Replay a completed summary, journal, and combined transcript."""

    checked_summary = _copy(summary, "COLLISION_BUDGET_SUMMARY_INVALID")
    checked_events = _copy(events, "COLLISION_BUDGET_EVENT_INVALID")
    checked_transcript = _copy(transcript_events, "COLLISION_BUDGET_TRANSCRIPT_INVALID")
    fields = {
        "record_type", "status", "session_mode", "operation",
        "operation_phase", "budget_digest", "session_open_count",
        "direct_sso_session_opens", "assume_role_opens",
        "assume_role_duration_seconds", "source_credential_bindings",
        "source_credential_vends", "provider_calls", "network_calls",
        "page_calls", "response_bytes", "modeled_cost_micro_usd",
        "events_digest", "transcript_events_digest", "summary_digest",
    }
    if not isinstance(checked_summary, dict):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    mode = checked_summary.get("session_mode")
    operation = checked_summary.get("operation")
    if (
        not isinstance(checked_events, list)
        or not isinstance(checked_transcript, list)
        or set(checked_summary) != fields
        or checked_summary.get("record_type") != SUMMARY_RECORD_TYPE
        or checked_summary.get("status") != "COMPLETED"
        or mode not in SESSION_MODES
        or not isinstance(operation, str)
        or checked_summary.get("budget_digest")
        != collision_budget_digest(session_mode=mode, operation=operation)
        or checked_summary.get("operation_phase")
        != _operation_phase(operation)
        or checked_summary.get("summary_digest")
        != canonical_digest(
            {
                key: value
                for key, value in checked_summary.items()
                if key != "summary_digest"
            }
        )
        or checked_summary.get("events_digest") != canonical_digest(checked_events)
        or checked_summary.get("transcript_events_digest")
        != canonical_digest(checked_transcript)
    ):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")

    session_keys: set[tuple[str, str, str]] = set()
    source_domains: set[str] = set()
    direct = assumes = source_vends = provider_index = page_count = 0
    response_total = non_response_cost = network_count = 0
    for ordinal, event in enumerate(checked_events, 1):
        if not isinstance(event, dict) or event.get("ordinal") != ordinal:
            _fail("COLLISION_BUDGET_EVENT_INVALID")
        kind = event.get("kind")
        if kind == "SESSION_OPEN":
            key = _validate_session_event(event, str(mode))
            if key in session_keys:
                _fail("COLLISION_BUDGET_EVENT_INVALID")
            session_keys.add(key)
            if event["session_kind"] == DIRECT_SSO:
                direct += 1
            else:
                assumes += 1
            network_count += int(event["network_call"])
            non_response_cost += int(event["modeled_cost_micro_usd"])
        elif kind == "SOURCE_CREDENTIAL_BINDING":
            domain, vended, cost = _validate_source_event(event, str(mode))
            if domain in source_domains:
                _fail("COLLISION_BUDGET_EVENT_INVALID")
            source_domains.add(domain)
            source_vends += int(vended)
            network_count += int(vended)
            non_response_cost += cost
        elif kind == "PROVIDER_CALL":
            if provider_index >= len(checked_transcript):
                _fail("COLLISION_BUDGET_TRANSCRIPT_MISMATCH")
            page, byte_count, cost = _validate_provider_event(
                event, checked_transcript[provider_index]
            )
            provider_index += 1
            page_count += page
            response_total += byte_count
            non_response_cost += cost
            network_count += 1
        else:
            _fail("COLLISION_BUDGET_EVENT_INVALID")

    modeled_cost = non_response_cost + _modeled_response_cost(response_total)
    pre_valid = (
        mode == LOCAL_DIRECT_SSO
        and direct == MAX_SESSION_OPENS
        and assumes == 0
        and source_domains == set(_DOMAINS)
        and 0 <= source_vends <= 2
        and checked_summary.get("assume_role_duration_seconds") is None
    )
    post_valid = (
        mode == POST_READER_RUNTIME
        and direct == 0
        and assumes == MAX_SESSION_OPENS
        and not source_domains
        and source_vends == 0
        and checked_summary.get("assume_role_duration_seconds") == 900
    )
    if (
        not (pre_valid or post_valid)
        or session_keys != set(_EXPECTED_SESSION_KEYS)
        or provider_index != len(checked_transcript)
        or provider_index > MAX_PROVIDER_CALLS
        or page_count > MAX_PAGE_CALLS
        or network_count > MAX_NETWORK_CALLS
        or response_total > MAX_TOTAL_RESPONSE_BYTES
        or modeled_cost > MAX_MODELED_COST_MICRO_USD
        or checked_summary.get("session_open_count") != len(session_keys)
        or checked_summary.get("direct_sso_session_opens") != direct
        or checked_summary.get("assume_role_opens") != assumes
        or checked_summary.get("source_credential_bindings") != len(source_domains)
        or checked_summary.get("source_credential_vends") != source_vends
        or checked_summary.get("provider_calls") != provider_index
        or checked_summary.get("network_calls") != network_count
        or checked_summary.get("page_calls") != page_count
        or checked_summary.get("response_bytes") != response_total
        or checked_summary.get("modeled_cost_micro_usd") != modeled_cost
    ):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    return checked_summary


def validate_collision_budget_summary(
    summary: Mapping[str, Any],
    *,
    events: Sequence[Mapping[str, Any]],
    transcript_events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return validate_collision_budget_evidence(
        summary=summary,
        events=events,
        transcript_events=transcript_events,
    )


__all__ = [
    "ASSUME_ROLE", "ASSUME_ROLE_DURATION_SECONDS", "BUDGET_RECORD_TYPE",
    "CANDIDATE_CAPTURE_COUNT", "CollisionBudgetError", "DIRECT_SSO",
    "INVENTORY_CAPTURE_COUNT", "MAX_MODELED_COST_MICRO_USD",
    "MAX_NETWORK_CALLS", "MAX_PAGE_CALLS", "MAX_PROVIDER_CALLS",
    "MAX_RESPONSE_BYTES", "MAX_ROLE_OPENS", "MAX_SESSION_OPENS",
    "MAX_SOURCE_CREDENTIAL_BINDINGS", "MAX_SOURCE_CREDENTIAL_VENDS",
    "MAX_TOTAL_RESPONSE_BYTES", "MODELED_COST_MICRO_USD_PER_CALL",
    "LOCAL_DIRECT_SSO", "POST_READER_RUNTIME", "SESSION_MODES",
    "SUMMARY_RECORD_TYPE", "account_provider_response",
    "bind_provider_transcript_event", "build_collision_budget",
    "collision_budget_digest", "collision_budget_events",
    "collision_budget_worst_case", "complete_collision_budget",
    "record_source_credential_binding", "reserve_assume_role_open",
    "reserve_direct_sso_session_open", "reserve_provider_call",
    "reserve_session_open", "validate_collision_budget_evidence",
    "validate_collision_budget_summary",
]
