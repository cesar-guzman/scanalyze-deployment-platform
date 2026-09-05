"""Connected, read-only executor for GUG-376 collision admission.

The module is inert at import time and deliberately contains no SDK or boto3
construction.  A connected adapter must implement the protocols below.  The
executor claims one private request exactly once, captures two independent
snapshots followed by one immediate pre-effect snapshot, validates a closed
read-only call transcript, and persists the resulting admission create-only.

No mutation is performed here.  The output is only an operation-bound,
short-lived admission consumed by a separate mutating adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Protocol

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    private_target_absent,
    read_private_json,
    write_private_json,
)
from tooling.platform_authority_gug376_collision_admission import (
    DEFAULT_TRANSCRIPT_FILE,
    SNAPSHOT_TYPE,
    TRANSCRIPT_SIDECAR_TYPE,
    RouteCollisionAdmissionError,
    RouteCollisionAdmissionResult,
    approved_route_collision_admission_request,
    build_route_collision_admission_result,
    persist_route_collision_admission_result,
    read_and_claim_route_collision_admission_request,
    validate_route_collision_snapshot,
)
from tooling.platform_authority_gug376_collision_aws_provider import (
    assert_attested_provider_factory,
    session_uniqueness_registry_summary,
)
from tooling import platform_authority_gug376_collision_budget as collision_budget
from tooling.platform_authority_gug376_collision_transcript_contract import (
    CollisionTranscriptContractError,
    READ_ONLY_OPERATION_ALLOWLIST,
    TRANSCRIPT_SUMMARY_TYPE,
    validate_route_collision_transcript_bundle as _validate_transcript_contract,
)


INDEPENDENT_CAPTURE_PURPOSES = (
    "independent-snapshot-1",
    "independent-snapshot-2",
    "pre-effect-snapshot",
)

_SIDECAR_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "request_digest",
        "claim_digest",
        "admission_digest",
        "private_evidence_digest",
        "snapshot_transcript_digests",
        "events",
        "events_digest",
        "summary",
        "recorded_at",
        "read_only",
        "aws_mutations",
        "sidecar_digest",
    }
)

_EXECUTOR_PUBLIC_CODES = frozenset(
    {
        "ROUTE_COLLISION_CALL_SUMMARY_INVALID",
        "ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID",
        "ROUTE_COLLISION_CATALOG_INVALID",
        "ROUTE_COLLISION_CLOCK_INVALID",
        "ROUTE_COLLISION_CLOCK_REGRESSED",
        "ROUTE_COLLISION_DISPOSITIONS_INVALID",
        "ROUTE_COLLISION_IDENTITY_CALL_ORDER_INVALID",
        "ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID",
        "ROUTE_COLLISION_PROVIDER_EVIDENCE_INVALID",
        "ROUTE_COLLISION_PROVIDER_FAILED",
        "ROUTE_COLLISION_PROVIDER_ATTESTATION_INVALID",
        "ROUTE_COLLISION_PROVIDER_NOT_ATTESTED",
        "ROUTE_COLLISION_POLICY_BINDING_INVALID",
        "ROUTE_COLLISION_OPERATION_REQUEST_BINDING_INVALID",
        "ROUTE_COLLISION_PAGINATION_INCOMPLETE",
        "ROUTE_COLLISION_PAGINATION_INVALID",
        "ROUTE_COLLISION_REQUEST_NOT_ACTIVE",
        "ROUTE_COLLISION_RESPONSE_BINDING_INVALID",
        "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
        "ROUTE_COLLISION_SNAPSHOT_SESSION_NOT_INDEPENDENT",
        "ROUTE_COLLISION_SESSION_REGISTRY_INVALID",
        "ROUTE_COLLISION_TARGET_EVIDENCE_INVALID",
        "ROUTE_COLLISION_TRANSCRIPT_AGGREGATE_MISMATCH",
        "ROUTE_COLLISION_TRANSCRIPT_FIELDS_INVALID",
        "ROUTE_COLLISION_TRANSCRIPT_INVALID",
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_READBACK_MISMATCH",
    }
)


class RouteCollisionSnapshotProvider(Protocol):
    """One isolated dual-domain read-only capture."""

    def read_identity(self, *, domain: str) -> Mapping[str, Any]: ...

    def read_target_observations(
        self,
        *,
        domain: str,
        targets: Sequence[Mapping[str, Any]],
        expected_dispositions: Mapping[str, str],
    ) -> Mapping[str, Mapping[str, Any]]: ...

    def transcript_events(self) -> Sequence[Mapping[str, Any]]: ...


class RouteCollisionAdmissionProviderFactory(Protocol):
    """Injected factory; a concrete implementation may own SDK sessions."""

    def open_snapshot(
        self,
        *,
        request: Mapping[str, Any],
        capture_index: int,
        purpose: str,
    ) -> RouteCollisionSnapshotProvider: ...

    def transcript_events(self) -> Sequence[Mapping[str, Any]]: ...

    def transcript_summary(self) -> Mapping[str, Any]: ...

    def provider_attestation(self) -> Mapping[str, Any]: ...


Clock = Callable[[], datetime]


def _fail(code: str) -> None:
    raise RouteCollisionAdmissionError(code)


def _sanitized_error(exc: Exception) -> RouteCollisionAdmissionError:
    if (
        isinstance(exc, RouteCollisionAdmissionError)
        and exc.code in _EXECUTOR_PUBLIC_CODES
    ):
        return RouteCollisionAdmissionError(exc.code)
    return RouteCollisionAdmissionError("ROUTE_COLLISION_EXECUTION_FAILED")


def _provider_call(call: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
    """Invoke an injected provider without allowing its error codes through."""

    try:
        return call(*args, **kwargs)
    except Exception:
        raise RouteCollisionAdmissionError(
            "ROUTE_COLLISION_PROVIDER_FAILED"
        ) from None


def _attested_factory(value: object) -> RouteCollisionAdmissionProviderFactory:
    try:
        checked = assert_attested_provider_factory(value)
    except Exception:
        _fail("ROUTE_COLLISION_PROVIDER_NOT_ATTESTED")
    return checked  # type: ignore[return-value]


def _validate_provider_attestation(
    value: object,
    *,
    request: Mapping[str, Any],
) -> None:
    checked = _json_ready(
        value,
        "ROUTE_COLLISION_PROVIDER_ATTESTATION_INVALID",
    )
    required = {
        "record_type",
        "schema_version",
        "provider_implementation_digest",
        "factory_attestation_digest",
        "policy_set_digest",
        "policy_digests",
        "policy_stage",
        "discovery_provenance_digest",
        "target_count",
        "region",
        "before_call_enforced",
        "read_only",
        "aws_mutations",
    }
    catalog = request.get("catalog")
    identities = request.get("expected_identities")
    identity_sources = {
        value.get("source")
        for value in identities.values()
        if isinstance(value, Mapping)
    } if isinstance(identities, Mapping) else set()
    if (
        not isinstance(checked, dict)
        or set(checked) != required
        or not isinstance(catalog, Mapping)
        or checked.get("record_type")
        != (
            "scanalyze.platform_authority."
            "gug376_collision_aws_provider_attestation.v1"
        )
        or checked.get("schema_version") != 1
        or checked.get("provider_implementation_digest")
        != request.get("collision_provider_implementation_digest")
        or checked.get("policy_set_digest")
        != request.get("collision_policy_set_digest")
        or checked.get("policy_digests")
        != request.get("collision_policy_digests")
        or checked.get("policy_stage")
        != request.get("collision_policy_stage")
        or checked.get("discovery_provenance_digest")
        != request.get("collision_discovery_provenance_digest")
        or checked.get("target_count") != catalog.get("target_count")
        or checked.get("region") != catalog.get("region")
        or type(checked.get("before_call_enforced")) is not bool
        or (
            "BROKER_SERVICE_ROLE" in identity_sources
            and checked.get("before_call_enforced") is not True
        )
        or checked.get("read_only") is not True
        or checked.get("aws_mutations") != 0
    ):
        _fail("ROUTE_COLLISION_PROVIDER_ATTESTATION_INVALID")
    factory_digest = checked.get("factory_attestation_digest")
    if (
        not isinstance(factory_digest, str)
        or not factory_digest.startswith("sha256:")
        or len(factory_digest) != 71
    ):
        _fail("ROUTE_COLLISION_PROVIDER_ATTESTATION_INVALID")


def _json_ready(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception:
        raise RouteCollisionAdmissionError(code) from None


def _checked_time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("ROUTE_COLLISION_CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("ROUTE_COLLISION_WINDOW_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RouteCollisionAdmissionError(
            "ROUTE_COLLISION_WINDOW_INVALID"
        ) from exc
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if normalized.isoformat().replace("+00:00", "Z") != value:
        _fail("ROUTE_COLLISION_WINDOW_INVALID")
    return normalized


def _stamp(value: datetime) -> str:
    return _checked_time(value).isoformat().replace("+00:00", "Z")


class _ActiveClock:
    """Monotonic action-time checks against the exact request window."""

    def __init__(self, clock: Clock) -> None:
        if not callable(clock):
            _fail("ROUTE_COLLISION_CLOCK_INVALID")
        self._clock = clock
        self._last: datetime | None = None

    def tick(self, request: Mapping[str, Any] | None = None) -> datetime:
        try:
            value = _checked_time(self._clock())
        except Exception:
            raise RouteCollisionAdmissionError(
                "ROUTE_COLLISION_CLOCK_INVALID"
            ) from None
        if self._last is not None and value < self._last:
            _fail("ROUTE_COLLISION_CLOCK_REGRESSED")
        self._last = value
        if request is not None:
            start = _parse_time(request.get("not_before"))
            end = _parse_time(request.get("expires_at"))
            if not start <= value < end:
                _fail("ROUTE_COLLISION_REQUEST_NOT_ACTIVE")
        return value


def _targets_by_domain(
    request: Mapping[str, Any], domain: str
) -> list[Mapping[str, Any]]:
    catalog = request.get("catalog")
    targets = catalog.get("targets") if isinstance(catalog, Mapping) else None
    if not isinstance(targets, list):
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    selected = [
        target
        for target in targets
        if isinstance(target, Mapping) and target.get("domain") == domain
    ]
    if not selected or any(
        not isinstance(target.get("target_id"), str) for target in selected
    ):
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    return selected


def _persist_transcript_sidecar(
    *,
    private_root: Path,
    result: RouteCollisionAdmissionResult,
    events: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
    recorded_at: datetime,
) -> dict[str, Any]:
    checked_events = _json_ready(
        events, "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID"
    )
    checked_summary = _json_ready(
        summary, "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID"
    )
    if not isinstance(checked_events, list) or not isinstance(
        checked_summary, dict
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    evidence = result.private_evidence
    receipt = result.public_receipt
    sidecar: dict[str, Any] = {
        "record_type": TRANSCRIPT_SIDECAR_TYPE,
        "schema_version": 1,
        "request_digest": evidence["request_digest"],
        "claim_digest": evidence["claim_digest"],
        "admission_digest": receipt["admission_digest"],
        "private_evidence_digest": evidence["private_evidence_digest"],
        "snapshot_transcript_digests": [
            snapshot["transcript_digest"] for snapshot in evidence["snapshots"]
        ],
        "events": checked_events,
        "events_digest": canonical_digest(checked_events),
        "summary": checked_summary,
        "recorded_at": _stamp(recorded_at),
        "read_only": True,
        "aws_mutations": 0,
    }
    sidecar["sidecar_digest"] = canonical_digest(sidecar)
    if set(sidecar) != _SIDECAR_FIELDS:
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    try:
        private_target_absent(private_root, DEFAULT_TRANSCRIPT_FILE)
        write_private_json(private_root, DEFAULT_TRANSCRIPT_FILE, sidecar)
        if read_private_json(private_root, DEFAULT_TRANSCRIPT_FILE) != sidecar:
            _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_READBACK_MISMATCH")
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(
            "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID"
        ) from exc
    return sidecar


def validate_route_collision_transcript_bundle(
    *,
    events: object,
    summary: object,
    request: Mapping[str, Any],
    snapshots: Sequence[Mapping[str, Any]],
) -> None:
    """Revalidate the persisted transcript through the pure shared contract."""

    try:
        _validate_transcript_contract(
            events=events,
            summary=summary,
            request=request,
            snapshots=snapshots,
        )
    except CollisionTranscriptContractError as exc:
        _fail(exc.code)


def _capture_snapshot(
    *,
    provider: RouteCollisionSnapshotProvider,
    request: Mapping[str, Any],
    capture_index: int,
    active_clock: _ActiveClock,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    identities: dict[str, Mapping[str, Any]] = {}
    observations: dict[str, Mapping[str, Any]] = {}
    expected_all = request.get("expected_dispositions")
    if not isinstance(expected_all, Mapping):
        _fail("ROUTE_COLLISION_DISPOSITIONS_INVALID")

    for domain in ("authority", "management"):
        targets = _targets_by_domain(request, domain)
        target_ids = {str(target["target_id"]) for target in targets}
        expected = {
            target_id: str(expected_all[target_id])
            for target_id in target_ids
            if target_id in expected_all
        }
        if set(expected) != target_ids:
            _fail("ROUTE_COLLISION_DISPOSITIONS_INVALID")
        # DIRECT_SSO providers predate the injected provider hook.  Preserve
        # that local mode only by applying this executor-owned action-time gate
        # immediately before every provider call; BROKER_SERVICE_ROLE also has
        # its provider-internal hook as attested above.
        active_clock.tick(request)
        identity = _json_ready(
            _provider_call(provider.read_identity, domain=domain),
            "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
        )
        active_clock.tick(request)
        domain_observations = _json_ready(
            _provider_call(
                provider.read_target_observations,
                domain=domain,
                targets=targets,
                expected_dispositions=expected,
            ),
            "ROUTE_COLLISION_TARGET_EVIDENCE_INVALID",
        )
        if not isinstance(identity, dict) or not isinstance(
            domain_observations, dict
        ):
            _fail("ROUTE_COLLISION_PROVIDER_EVIDENCE_INVALID")
        if set(domain_observations) != target_ids:
            _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
        identities[domain] = identity
        observations.update(domain_observations)

    if set(observations) != set(expected_all):
        _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
    active_clock.tick(request)
    events = _json_ready(
        _provider_call(provider.transcript_events),
        "ROUTE_COLLISION_TRANSCRIPT_INVALID",
    )
    if not isinstance(events, list) or not events:
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    # Timestamp the snapshot only after both domains and the complete segment
    # have been captured.  This is the action-time recheck for capture 3.
    observed_at = active_clock.tick(request)
    semantic = {
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "target_observations": observations,
    }
    snapshot: dict[str, Any] = {
        "record_type": SNAPSHOT_TYPE,
        "schema_version": 1,
        "capture_index": capture_index,
        "request_digest": request["request_digest"],
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "identities": identities,
        "target_observations": observations,
        "semantic_facts_digest": canonical_digest(semantic),
        "transcript_digest": canonical_digest(events),
        "complete": True,
        "observed_at": _stamp(observed_at),
    }
    snapshot["snapshot_digest"] = canonical_digest(snapshot)
    validate_route_collision_snapshot(
        snapshot,
        request=request,
        capture_index=capture_index,
    )
    return snapshot, events


def execute_route_collision_admission(
    *,
    provider_factory: RouteCollisionAdmissionProviderFactory,
    private_root: Path,
    expected_request_digest: str,
    clock: Clock,
    collision_budget_capability: object | None = None,
    prior_transcript_events: Sequence[Mapping[str, Any]] = (),
    session_registry: object | None = None,
) -> RouteCollisionAdmissionResult:
    """Claim, capture, validate, and create one private admission result."""

    active_clock = _ActiveClock(clock)
    try:
        provider_factory = _attested_factory(provider_factory)
        claim_time = active_clock.tick()
        capability = read_and_claim_route_collision_admission_request(
            private_root=private_root,
            expected_request_digest=expected_request_digest,
            now=claim_time,
        )
        request = approved_route_collision_admission_request(capability)
        _validate_provider_attestation(
            _provider_call(provider_factory.provider_attestation),
            request=request,
        )
        # Recheck immediately after the create-only claim and before opening
        # any connected provider session.
        active_clock.tick(request)

        snapshots: list[dict[str, Any]] = []
        all_events: list[dict[str, Any]] = []
        opened: list[RouteCollisionSnapshotProvider] = []
        for capture_index, purpose in enumerate(
            INDEPENDENT_CAPTURE_PURPOSES, 1
        ):
            active_clock.tick(request)
            provider = _provider_call(
                provider_factory.open_snapshot,
                request=request,
                capture_index=capture_index,
                purpose=purpose,
            )
            if provider is None or any(provider is prior for prior in opened):
                _fail("ROUTE_COLLISION_SNAPSHOT_SESSION_NOT_INDEPENDENT")
            opened.append(provider)
            snapshot, events = _capture_snapshot(
                provider=provider,
                request=request,
                capture_index=capture_index,
                active_clock=active_clock,
            )
            snapshots.append(snapshot)
            all_events.extend(events)

        aggregate_events = _json_ready(
            _provider_call(provider_factory.transcript_events),
            "ROUTE_COLLISION_TRANSCRIPT_INVALID",
        )
        if aggregate_events != all_events:
            _fail("ROUTE_COLLISION_TRANSCRIPT_AGGREGATE_MISMATCH")
        summary = _json_ready(
            _provider_call(provider_factory.transcript_summary),
            "ROUTE_COLLISION_CALL_SUMMARY_INVALID",
        )
        validate_route_collision_transcript_bundle(
            events=all_events,
            summary=summary,
            request=request,
            snapshots=snapshots,
        )

        budget_summary = None
        budget_events = None
        budget_transcript_events = None
        registry_summary = None
        if collision_budget_capability is None:
            if prior_transcript_events or session_registry is not None:
                _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
        else:
            if session_registry is None:
                _fail("ROUTE_COLLISION_SESSION_REGISTRY_INVALID")
            checked_prior = _json_ready(
                prior_transcript_events,
                "ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID",
            )
            if not isinstance(checked_prior, list) or not checked_prior:
                _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
            budget_transcript_events = checked_prior + all_events
            try:
                budget_summary = collision_budget.complete_collision_budget(
                    collision_budget_capability,
                    transcript_events=budget_transcript_events,
                )
                budget_events = collision_budget.collision_budget_events(
                    collision_budget_capability
                )
                collision_budget.validate_collision_budget_evidence(
                    summary=budget_summary,
                    events=budget_events,
                    transcript_events=budget_transcript_events,
                )
            except collision_budget.CollisionBudgetError:
                _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
            registry_summary = _json_ready(
                session_uniqueness_registry_summary(session_registry),
                "ROUTE_COLLISION_SESSION_REGISTRY_INVALID",
            )
            if (
                not isinstance(registry_summary, dict)
                or registry_summary.get("session_count") != 10
                or registry_summary.get("session_nonce_count") != 10
                or registry_summary.get("sdk_session_count") != 10
            ):
                _fail("ROUTE_COLLISION_SESSION_REGISTRY_INVALID")

        sealed_at = active_clock.tick(request)
        result = build_route_collision_admission_result(
            capability=capability,
            snapshots=snapshots,
            sealed_at=sealed_at,
            collision_budget_summary=budget_summary,
            collision_budget_events=budget_events,
            collision_budget_transcript_events=budget_transcript_events,
            session_registry_summary=registry_summary,
        )
        _persist_transcript_sidecar(
            private_root=private_root,
            result=result,
            events=all_events,
            summary=summary,
            recorded_at=sealed_at,
        )
        persist_route_collision_admission_result(
            private_root=private_root,
            result=result,
        )
        return result
    except Exception as exc:
        # Suppress the original exception context: SDK messages may contain
        # request identifiers, endpoints, or principal details.  Only the
        # stable boundary code is allowed to cross this layer.
        raise _sanitized_error(exc) from None


__all__ = [
    "INDEPENDENT_CAPTURE_PURPOSES",
    "READ_ONLY_OPERATION_ALLOWLIST",
    "TRANSCRIPT_SUMMARY_TYPE",
    "RouteCollisionAdmissionProviderFactory",
    "RouteCollisionSnapshotProvider",
    "execute_route_collision_admission",
    "validate_route_collision_transcript_bundle",
]
