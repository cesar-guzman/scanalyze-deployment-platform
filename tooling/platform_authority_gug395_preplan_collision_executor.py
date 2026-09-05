"""Attested executor for the GUG-395 pre-plan collision probe.

The executor performs no work at import time.  Its connected path accepts one
claimed private capability, opens four independent direct-SSO sessions, makes
``sts:GetCallerIdentity`` the first signed call in every session, captures two
bounded snapshots per domain, and persists only create-only evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_live_provider import (
    LiveProviderError,
    LiveProviderFactory,
    is_attested_collision_probe_provider,
)
from tooling.platform_authority_gug395_preplan_collision_probe import (
    CollisionCallLedger,
    CollisionProbeBudget,
    CollisionProbeError,
    CollisionProbeExecutionCapability,
    CollisionProbeResult,
    MAX_APPLICATIONS,
    MAX_CODE_SIGNING_CONFIGS,
    MAX_KMS_KEYS,
    MAX_OWNED_BUCKETS,
    MAX_PERMISSION_SETS,
    MAX_SIGNING_PROFILES,
    REGION,
    approved_collision_probe_claim_digest,
    approved_collision_probe_request,
    assert_collision_probe_execution_active,
    assert_collision_probe_private_root_binding,
    build_collision_probe_failure_result,
    build_collision_probe_result,
    claim_collision_probe_execution,
    complete_collision_probe_execution,
    persist_collision_probe_result,
)


def _fail(code: str) -> None:
    raise CollisionProbeError(code)


def _checked_now(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("COLLISION_CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0)


def _sanitized_probe_error(exc: Exception) -> CollisionProbeError:
    if isinstance(exc, CollisionProbeError):
        return CollisionProbeError(exc.code)
    if isinstance(exc, LiveProviderError):
        return CollisionProbeError(exc.code)
    return CollisionProbeError("COLLISION_UNCERTAIN_RECONCILE_ONLY")


def _stamp(value: datetime) -> str:
    return (
        _checked_now(value)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _json_ready(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, datetime):
        return _stamp(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    _fail("COLLISION_PROVIDER_FACTS_INVALID")


def _snapshot(
    *,
    domain: str,
    capture_index: int,
    identity: Mapping[str, Any],
    facts: Mapping[str, Any],
    transcript_segment_digest: str,
) -> dict[str, Any]:
    checked_identity = _json_ready(identity)
    checked_facts = _json_ready(facts)
    if not isinstance(checked_identity, dict) or not isinstance(checked_facts, dict):
        _fail("COLLISION_PROVIDER_FACTS_INVALID")
    required = {
        "complete",
        "prerequisites_ready",
        "collisions",
        "collision_count",
        "resource_counts",
        "facts",
    }
    if (
        set(checked_facts) != required
        or type(checked_facts.get("complete")) is not bool
        or type(checked_facts.get("prerequisites_ready")) is not bool
        or not isinstance(checked_facts.get("collisions"), list)
        or checked_facts.get("collision_count")
        != len(checked_facts["collisions"])
        or not isinstance(checked_facts.get("resource_counts"), dict)
        or not isinstance(checked_facts.get("facts"), dict)
    ):
        _fail("COLLISION_PROVIDER_FACTS_INVALID")
    semantic_facts = {
        "complete": checked_facts["complete"],
        "prerequisites_ready": checked_facts["prerequisites_ready"],
        "collisions": checked_facts["collisions"],
        "collision_count": checked_facts["collision_count"],
        "resource_counts": checked_facts["resource_counts"],
        "facts": checked_facts["facts"],
    }
    snapshot = {
        "domain": domain,
        "capture_index": capture_index,
        "identity": checked_identity,
        "complete": semantic_facts["complete"],
        "prerequisites_ready": semantic_facts["prerequisites_ready"],
        "collisions": semantic_facts["collisions"],
        "collision_count": semantic_facts["collision_count"],
        "resource_counts": semantic_facts["resource_counts"],
        "facts": semantic_facts["facts"],
        "facts_digest": canonical_digest(semantic_facts),
        "transcript_segment_digest": transcript_segment_digest,
    }
    snapshot["snapshot_digest"] = canonical_digest(snapshot)
    return snapshot


def _session_transcript_segment_digest(
    ledger: CollisionCallLedger, identity: Mapping[str, Any]
) -> str:
    session_digest = identity.get("session_id_digest")
    events = [
        event
        for event in ledger.partial_evidence_events()
        if event.get("session_digest") == session_digest
    ]
    if not events or any(event.get("outcome") != "SUCCESS" for event in events):
        _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
    return canonical_digest(events)


def _authority_snapshot(
    *,
    provider_factory: LiveProviderFactory,
    request: Mapping[str, Any],
    ledger: CollisionCallLedger,
    capture_index: int,
) -> dict[str, Any]:
    factory = provider_factory.build_authority(
        profile=request["profiles"]["authority"]["name"],
        ledger=ledger,
        capture_index=capture_index,
        retries=0,
    )
    session = factory.open_sts(
        policy=request["policies"]["authority"],
        policy_digest=request["policy_digests"]["authority"],
        region=REGION,
        stage="collision_probe",
    )
    identity = session.get_caller_identity()
    reader = session.open_collision_reader()
    facts = reader.read_collision_facts(
        request["targets"],
        max_owned_buckets=MAX_OWNED_BUCKETS,
        max_kms_keys=MAX_KMS_KEYS,
        max_signing_profiles=MAX_SIGNING_PROFILES,
        max_code_signing_configs=MAX_CODE_SIGNING_CONFIGS,
    )
    return _snapshot(
        domain="authority",
        capture_index=capture_index,
        identity=identity,
        facts=facts,
        transcript_segment_digest=_session_transcript_segment_digest(
            ledger, identity
        ),
    )


def _identity_snapshot(
    *,
    provider_factory: LiveProviderFactory,
    request: Mapping[str, Any],
    ledger: CollisionCallLedger,
    capture_index: int,
) -> dict[str, Any]:
    identity_profile = request["profiles"]["identity_center"]
    factory = provider_factory.build_identity(
        profile=identity_profile["name"],
        ledger=ledger,
        capture_index=capture_index,
        retries=0,
    )
    session = factory.open_sts(
        policy=request["policies"]["identity_center"],
        policy_digest=request["policy_digests"]["identity_center"],
        region=REGION,
        stage="collision_probe",
    )
    identity = session.get_caller_identity()
    reader = session.open_collision_reader()
    facts = reader.read_collision_facts(
        request["targets"],
        max_applications=MAX_APPLICATIONS,
        max_permission_sets=MAX_PERMISSION_SETS,
        expected_identity_center_kms_mode=identity_profile[
            "identity_center_kms_mode"
        ],
        expected_identity_center_kms_key_arn=identity_profile[
            "identity_center_kms_key_arn"
        ],
    )
    return _snapshot(
        domain="identity_center",
        capture_index=capture_index,
        identity=identity,
        facts=facts,
        transcript_segment_digest=_session_transcript_segment_digest(
            ledger, identity
        ),
    )


def _persist_zero_call_failure(
    *,
    execution_capability: CollisionProbeExecutionCapability,
    private_root: Path,
    request: Mapping[str, Any],
    budget_summary: Mapping[str, Any],
    budget_events: list[Mapping[str, Any]],
    blocker: CollisionProbeError,
    sealed_at: datetime,
) -> CollisionProbeResult:
    if (
        budget_summary.get("provider_calls") != 0
        or budget_summary.get("session_bootstrap_attempts") != 0
        or budget_summary.get("credential_vending_calls") != 0
        or budget_summary.get("network_calls") != 0
        or budget_events
    ):
        _fail("COLLISION_PRE_EXECUTION_EVIDENCE_INVALID")
    assert_collision_probe_execution_active(execution_capability)
    result = build_collision_probe_failure_result(
        request=request,
        authority_snapshots=[],
        identity_center_snapshots=[],
        provider_summary={
            "provider_calls": 0,
            "aws_calls": None,
            "aws_mutations": 0,
            "live_provider_evidence": False,
            "transcript_digest": canonical_digest([]),
        },
        transcript_events=[],
        budget_summary=budget_summary,
        budget_events=budget_events,
        blocker_code=blocker.code,
        sealed_at=_stamp(sealed_at),
    )
    try:
        persist_collision_probe_result(
            private_root=private_root,
            result=result,
            expected_claim_digest=approved_collision_probe_claim_digest(
                execution_capability
            ),
        )
    except Exception as exc:
        raise blocker from exc
    complete_collision_probe_execution(execution_capability)
    return result


def execute_preplan_collision_probe(
    *,
    provider_factory: LiveProviderFactory,
    execution_capability: CollisionProbeExecutionCapability,
    private_root: Path,
    now: datetime,
) -> CollisionProbeResult:
    """Run the complete four-session probe and seal one digest-only receipt."""

    checked_now = _checked_now(now)
    request = approved_collision_probe_request(execution_capability)
    # A root mismatch is custody corruption.  Never transition or write a
    # result into a root other than the exact request-bound directory.
    assert_collision_probe_private_root_binding(
        execution_capability, private_root
    )
    preflight_budget = CollisionProbeBudget(request)
    try:
        claim_collision_probe_execution(execution_capability)
    except Exception as exc:
        blocked_error = _sanitized_probe_error(exc)
        try:
            return _persist_zero_call_failure(
                execution_capability=execution_capability,
                private_root=private_root,
                request=request,
                budget_summary=preflight_budget.summary(),
                budget_events=preflight_budget.partial_evidence_events(),
                blocker=blocked_error,
                sealed_at=checked_now,
            )
        except Exception as failure_exc:
            raise blocked_error from failure_exc
    try:
        attested = is_attested_collision_probe_provider(
            provider_factory, execution_capability
        )
    except Exception as exc:
        blocked_error = _sanitized_probe_error(exc)
        return _persist_zero_call_failure(
            execution_capability=execution_capability,
            private_root=private_root,
            request=request,
            budget_summary=preflight_budget.summary(),
            budget_events=preflight_budget.partial_evidence_events(),
            blocker=blocked_error,
            sealed_at=checked_now,
        )
    if not attested:
        return _persist_zero_call_failure(
            execution_capability=execution_capability,
            private_root=private_root,
            request=request,
            budget_summary=preflight_budget.summary(),
            budget_events=preflight_budget.partial_evidence_events(),
            blocker=CollisionProbeError("ATTESTED_COLLISION_PROVIDER_REQUIRED"),
            sealed_at=checked_now,
        )
    ledger = CollisionCallLedger()
    authority: list[dict[str, Any]] = []
    identity: list[dict[str, Any]] = []
    blocked_error: CollisionProbeError | None = None
    try:
        for index in (1, 2):
            authority.append(
                _authority_snapshot(
                    provider_factory=provider_factory,
                    request=request,
                    ledger=ledger,
                    capture_index=index,
                )
            )
        for index in (1, 2):
            identity.append(
                _identity_snapshot(
                    provider_factory=provider_factory,
                    request=request,
                    ledger=ledger,
                    capture_index=index,
                )
            )
        ledger.raise_if_failed()
        provider_summary = provider_factory.transcript_summary()
        transcript_events = provider_factory.transcript_events()
        budget_summary = provider_factory.collision_budget_summary()
        budget_events = provider_factory.collision_budget_evidence_events()
        result = build_collision_probe_result(
            request=request,
            authority_snapshots=authority,
            identity_center_snapshots=identity,
            provider_summary=provider_summary,
            transcript_events=transcript_events,
            budget_summary=budget_summary,
            budget_events=budget_events,
            sealed_at=_stamp(provider_factory.evaluation_time()),
        )
    except Exception as exc:
        blocked_error = _sanitized_probe_error(exc)
        try:
            result = build_collision_probe_failure_result(
                request=request,
                authority_snapshots=authority,
                identity_center_snapshots=identity,
                provider_summary=(
                    provider_factory.collision_partial_transcript_summary()
                ),
                transcript_events=(
                    provider_factory.collision_partial_transcript_events()
                ),
                budget_summary=provider_factory.collision_budget_summary(),
                budget_events=(
                    provider_factory.collision_budget_partial_evidence_events()
                ),
                blocker_code=blocked_error.code,
                sealed_at=_stamp(provider_factory.failure_evaluation_time()),
            )
        except Exception:
            raise blocked_error from exc
    try:
        persist_collision_probe_result(
            private_root=private_root,
            result=result,
            expected_claim_digest=approved_collision_probe_claim_digest(
                execution_capability
            ),
        )
    except Exception as exc:
        if blocked_error is not None:
            raise blocked_error from exc
        raise _sanitized_probe_error(exc) from exc
    complete_collision_probe_execution(execution_capability)
    return result


def persist_pre_execution_collision_probe_failure(
    *,
    execution_capability: CollisionProbeExecutionCapability,
    private_root: Path,
    budget: CollisionProbeBudget,
    blocker: Exception,
    sealed_at: datetime,
) -> CollisionProbeResult:
    """Seal a no-call blocked result when provider construction cannot start.

    The CLI invokes this only after the private request has been claimed and
    before a provider factory or SDK session exists.  Consequently the empty
    transcript is exact and the budget must still be at its zero-call state.
    """

    checked_time = _checked_now(sealed_at)
    if type(budget) is not CollisionProbeBudget:
        _fail("COLLISION_BUDGET_BINDING_INVALID")
    assert_collision_probe_private_root_binding(
        execution_capability, private_root
    )
    request = approved_collision_probe_request(execution_capability)
    budget_summary = budget.summary()
    budget_events = budget.partial_evidence_events()
    if (
        budget_summary.get("provider_calls") != 0
        or budget_summary.get("session_bootstrap_attempts") != 0
        or budget_summary.get("credential_vending_calls") != 0
        or budget_summary.get("network_calls") != 0
        or budget_events
    ):
        _fail("COLLISION_PRE_EXECUTION_EVIDENCE_INVALID")
    blocked_error = _sanitized_probe_error(blocker)
    try:
        claim_collision_probe_execution(execution_capability)
    except Exception as exc:
        blocked_error = _sanitized_probe_error(exc)
    return _persist_zero_call_failure(
        execution_capability=execution_capability,
        private_root=private_root,
        request=request,
        budget_summary=budget_summary,
        budget_events=budget_events,
        blocker=blocked_error,
        sealed_at=checked_time,
    )


__all__ = [
    "execute_preplan_collision_probe",
    "persist_pre_execution_collision_probe_failure",
]
