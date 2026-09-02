from __future__ import annotations

from copy import deepcopy

import pytest

from tooling import platform_authority_gug376_collision_budget as subject
from tooling import (
    platform_authority_gug376_collision_transcript_contract as transcript,
)
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest


OPERATION = "route:create-change-set"
PURPOSES = {
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


def _budget(mode: str = subject.LOCAL_DIRECT_SSO) -> object:
    return subject.build_collision_budget(
        session_mode=mode,
        operation=OPERATION,
    )


def _open_all_sessions(budget: object, *, mode: str) -> None:
    for stage, purposes in PURPOSES.items():
        for purpose in purposes:
            for domain in ("authority", "management"):
                if mode == subject.LOCAL_DIRECT_SSO:
                    subject.reserve_direct_sso_session_open(
                        budget,
                        stage=stage,
                        domain=domain,
                        purpose=purpose,
                    )
                else:
                    subject.reserve_assume_role_open(
                        budget,
                        stage=stage,
                        domain=domain,
                        purpose=purpose,
                        duration_seconds=900,
                    )


def _open_all_sessions_through_local_facade(budget: object) -> None:
    for stage, purposes in PURPOSES.items():
        policy_stage = (
            "inventory" if stage == "inventory" else "candidate-detail"
        )
        for capture_index, purpose in enumerate(purposes, 1):
            for domain in ("authority", "management"):
                budget.reserve_direct_sso_session_open(  # type: ignore[attr-defined]
                    domain=domain,
                    policy_stage=policy_stage,
                    capture_index=capture_index,
                    purpose=purpose,
                )


def _bind_pre_sources(budget: object) -> None:
    subject.record_source_credential_binding(
        budget,
        domain="authority",
        binding_digest=canonical_digest({"source": "authority"}),
        credential_vended=True,
    )
    subject.record_source_credential_binding(
        budget,
        domain="management",
        binding_digest=canonical_digest({"source": "management"}),
        credential_vended=False,
    )


def _transcript_event(
    *,
    ordinal: int,
    capture_index: int,
    domain: str,
    operation: str,
) -> dict[str, object]:
    projection = {
        "page_item_digests": [],
        "output_cursor_digest": None,
        "page_complete": True,
        "target_evidence_digests": {},
    }
    return {
        "ordinal": ordinal,
        "capture_index": capture_index,
        "domain": domain,
        "account_id": "042360977644",
        "region": transcript.REGION,
        "session_digest": canonical_digest(
            {"ordinal": ordinal, "domain": domain}
        ),
        "provider_implementation_digest": (
            transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        ),
        "operation": operation,
        "outcome": "SUCCESS",
        "request_digest": canonical_digest({"request": OPERATION}),
        "operation_request_digest": canonical_digest(
            {"operation": operation, "ordinal": ordinal}
        ),
        "page_index": 1,
        "input_cursor_digest": None,
        "response_projection": projection,
        "response_digest": canonical_digest(projection),
        "target_ids": [],
        "read_only": True,
        "aws_mutations": 0,
    }


def _completed_call(
    budget: object,
    *,
    stage: str,
    capture_index: int,
    ordinal: int,
    operation: str = "sts:GetCallerIdentity",
    domain: str = "authority",
) -> dict[str, object]:
    reservation = subject.reserve_provider_call(
        budget,
        stage=stage,
        domain=domain,
        operation=operation,
        projected_response_bytes=1024,
    )
    subject.account_provider_response(
        reservation,
        response={"account": "digest-only-test"},
    )
    event = _transcript_event(
        ordinal=ordinal,
        capture_index=capture_index,
        domain=domain,
        operation=operation,
    )
    subject.bind_provider_transcript_event(
        reservation,
        transcript_event=event,
    )
    return event


def _complete_pre_with_two_calls() -> tuple[dict, list[dict], list[dict]]:
    budget = _budget()
    _bind_pre_sources(budget)
    _open_all_sessions(budget, mode=subject.LOCAL_DIRECT_SSO)
    events = [
        _completed_call(
            budget,
            stage="inventory",
            capture_index=1,
            ordinal=1,
        ),
        _completed_call(
            budget,
            stage="candidate",
            capture_index=1,
            ordinal=1,
            domain="management",
        ),
    ]
    summary = subject.complete_collision_budget(
        budget,
        transcript_events=events,
    )
    evidence = subject.collision_budget_events(budget)
    return summary, evidence, events


def test_worst_case_caps_are_derived_with_headroom_and_cost_coherence() -> None:
    value = subject.collision_budget_worst_case()

    inventory = 2 * (2 + 7 * transcript.MAX_PAGES + 73 + 2_048)
    candidate = 3 * (2 + 73 * transcript.MAX_PAGES + 73)
    provider_base = inventory + candidate
    page_base = 2 * 7 * transcript.MAX_PAGES + 3 * 73 * transcript.MAX_PAGES

    assert value["inventory_provider_calls_base"] == inventory == 4_694
    assert value["candidate_provider_calls_base"] == candidate == 7_233
    assert value["provider_calls_base"] == provider_base == 11_927
    assert value["provider_calls_headroom"] == 1_193
    assert subject.MAX_PROVIDER_CALLS == 13_120
    assert value["page_calls_base"] == page_base == 7_456
    assert value["page_calls_headroom"] == 746
    assert subject.MAX_PAGE_CALLS == 8_202
    assert value["modeled_max_cost_micro_usd"] < 50_000
    assert (
        subject.MAX_PROVIDER_CALLS * subject.MAX_RESPONSE_BYTES
        > subject.MAX_TOTAL_RESPONSE_BYTES
    )
    assert value["derivation_digest"] == canonical_digest(
        {key: item for key, item in value.items() if key != "derivation_digest"}
    )


def test_pre_budget_is_shared_sealed_and_replayable() -> None:
    summary, evidence, transcript_events = _complete_pre_with_two_calls()

    assert summary["session_mode"] == subject.LOCAL_DIRECT_SSO
    assert summary["operation"] == OPERATION
    assert summary["session_open_count"] == 10
    assert summary["direct_sso_session_opens"] == 10
    assert summary["assume_role_opens"] == 0
    assert summary["assume_role_duration_seconds"] is None
    assert summary["source_credential_bindings"] == 2
    assert summary["source_credential_vends"] == 1
    assert summary["provider_calls"] == 2
    assert summary["network_calls"] == 3
    assert summary["events_digest"] == canonical_digest(evidence)
    assert subject.validate_collision_budget_evidence(
        summary=summary,
        events=evidence,
        transcript_events=transcript_events,
    ) == summary


def test_local_reader_facade_maps_candidate_detail_and_validates_capture() -> None:
    budget = _budget()
    budget.record_source_credential_binding(  # type: ignore[attr-defined]
        domain="authority",
        binding_digest=canonical_digest("authority"),
        credential_vended=False,
    )
    budget.record_source_credential_binding(  # type: ignore[attr-defined]
        domain="management",
        binding_digest=canonical_digest("management"),
        credential_vended=False,
    )
    _open_all_sessions_through_local_facade(budget)

    summary = budget.complete(transcript_events=[])  # type: ignore[attr-defined]
    assert summary["session_mode"] == subject.LOCAL_DIRECT_SSO
    assert summary["direct_sso_session_opens"] == 10
    assert budget.operation == OPERATION  # type: ignore[attr-defined]

    invalid = _budget()
    with pytest.raises(subject.CollisionBudgetError):
        invalid.reserve_direct_sso_session_open(  # type: ignore[attr-defined]
            domain="authority",
            policy_stage="candidate-detail",
            capture_index=4,
            purpose=PURPOSES["candidate"][-1],
        )


def test_post_budget_claims_exact_ten_assume_role_900_second_opens() -> None:
    budget = _budget(subject.POST_READER_RUNTIME)
    _open_all_sessions(budget, mode=subject.POST_READER_RUNTIME)

    summary = subject.complete_collision_budget(budget, transcript_events=[])
    evidence = subject.collision_budget_events(budget)

    assert summary["direct_sso_session_opens"] == 0
    assert summary["assume_role_opens"] == 10
    assert summary["assume_role_duration_seconds"] == 900
    assert summary["source_credential_bindings"] == 0
    assert summary["source_credential_vends"] == 0
    assert summary["network_calls"] == 10
    assert subject.validate_collision_budget_summary(
        summary,
        events=evidence,
        transcript_events=[],
    ) == summary


def test_session_mode_and_operation_are_mandatory_and_sealed() -> None:
    with pytest.raises(subject.CollisionBudgetError) as invalid_mode:
        subject.build_collision_budget(
            session_mode="UNSEALED",
            operation=OPERATION,
        )
    assert invalid_mode.value.code == "COLLISION_BUDGET_CONFIG_INVALID"

    with pytest.raises(subject.CollisionBudgetError) as invalid_operation:
        subject.build_collision_budget(
            session_mode=subject.LOCAL_DIRECT_SSO,
            operation="invented-operation",
        )
    assert invalid_operation.value.code == "COLLISION_BUDGET_OPERATION_INVALID"

    pre = _budget()
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_assume_role_open(
            pre,
            stage="inventory",
            domain="authority",
            purpose=PURPOSES["inventory"][0],
        )

    post = _budget(subject.POST_READER_RUNTIME)
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_direct_sso_session_open(
            post,
            stage="inventory",
            domain="authority",
            purpose=PURPOSES["inventory"][0],
        )
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_assume_role_open(
            post,
            stage="inventory",
            domain="authority",
            purpose=PURPOSES["inventory"][0],
            duration_seconds=901,
        )


def test_pre_requires_two_source_bindings_but_allows_cached_vends() -> None:
    budget = _budget()
    _open_all_sessions(budget, mode=subject.LOCAL_DIRECT_SSO)
    subject.record_source_credential_binding(
        budget,
        domain="authority",
        binding_digest=canonical_digest("authority"),
        credential_vended=False,
    )

    with pytest.raises(subject.CollisionBudgetError) as incomplete:
        subject.complete_collision_budget(budget, transcript_events=[])
    assert incomplete.value.code == "COLLISION_BUDGET_SESSION_MATRIX_INCOMPLETE"

    subject.record_source_credential_binding(
        budget,
        domain="management",
        binding_digest=canonical_digest("management"),
        credential_vended=False,
    )
    summary = subject.complete_collision_budget(budget, transcript_events=[])
    assert summary["source_credential_bindings"] == 2
    assert summary["source_credential_vends"] == 0


def test_eleventh_session_open_and_duplicate_source_binding_block() -> None:
    budget = _budget()
    _bind_pre_sources(budget)
    _open_all_sessions(budget, mode=subject.LOCAL_DIRECT_SSO)

    with pytest.raises(subject.CollisionBudgetError) as over:
        subject.reserve_direct_sso_session_open(
            budget,
            stage="inventory",
            domain="authority",
            purpose=PURPOSES["inventory"][0],
        )
    assert over.value.code == "COLLISION_BUDGET_SESSION_OPEN_LIMIT_EXCEEDED"

    duplicate_budget = _budget()
    subject.record_source_credential_binding(
        duplicate_budget,
        domain="authority",
        binding_digest=canonical_digest("one"),
        credential_vended=True,
    )
    with pytest.raises(subject.CollisionBudgetError) as duplicate:
        subject.record_source_credential_binding(
            duplicate_budget,
            domain="authority",
            binding_digest=canonical_digest("two"),
            credential_vended=True,
        )
    assert duplicate.value.code == "COLLISION_BUDGET_SOURCE_BINDING_DUPLICATE"


def test_first_call_beyond_derived_provider_cap_blocks() -> None:
    budget = _budget()
    for _ in range(subject.MAX_PROVIDER_CALLS):
        subject.reserve_provider_call(
            budget,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
            projected_response_bytes=0,
        )

    with pytest.raises(subject.CollisionBudgetError) as over:
        subject.reserve_provider_call(
            budget,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
            projected_response_bytes=0,
        )
    assert over.value.code == "COLLISION_BUDGET_PROVIDER_CALL_LIMIT_EXCEEDED"


def test_first_page_beyond_derived_page_cap_blocks() -> None:
    budget = _budget()
    for _ in range(subject.MAX_PAGE_CALLS):
        subject.reserve_provider_call(
            budget,
            stage="inventory",
            domain="authority",
            operation="s3:ListAllMyBuckets",
            projected_response_bytes=0,
        )

    with pytest.raises(subject.CollisionBudgetError) as over:
        subject.reserve_provider_call(
            budget,
            stage="inventory",
            domain="authority",
            operation="s3:ListAllMyBuckets",
            projected_response_bytes=0,
        )
    assert over.value.code == "COLLISION_BUDGET_PAGE_CALL_LIMIT_EXCEEDED"


def test_individual_and_aggregate_response_limits_fail_closed() -> None:
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_provider_call(
            _budget(),
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
            projected_response_bytes=subject.MAX_RESPONSE_BYTES + 1,
        )

    poisoned = _budget()
    reservation = subject.reserve_provider_call(
        poisoned,
        stage="inventory",
        domain="authority",
        operation="sts:GetCallerIdentity",
        projected_response_bytes=10,
    )
    with pytest.raises(subject.CollisionBudgetError) as oversized:
        subject.account_provider_response(
            reservation,
            response_bytes=11,
            response_digest=canonical_digest("oversized"),
        )
    assert oversized.value.code == "COLLISION_BUDGET_RESPONSE_LIMIT_EXCEEDED"
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_provider_call(
            poisoned,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
        )

    aggregate = _budget()
    for index in range(
        subject.MAX_TOTAL_RESPONSE_BYTES // subject.MAX_RESPONSE_BYTES
    ):
        call = subject.reserve_provider_call(
            aggregate,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
        )
        subject.account_provider_response(
            call,
            response_bytes=subject.MAX_RESPONSE_BYTES,
            response_digest=canonical_digest({"page": index}),
        )
    with pytest.raises(subject.CollisionBudgetError) as total:
        subject.reserve_provider_call(
            aggregate,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
            projected_response_bytes=1,
        )
    assert total.value.code == "COLLISION_BUDGET_TOTAL_RESPONSE_LIMIT_EXCEEDED"


def test_modeled_cost_above_five_cents_blocks_before_call() -> None:
    budget = _budget()
    with pytest.raises(subject.CollisionBudgetError) as over:
        subject.reserve_provider_call(
            budget,
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
            projected_response_bytes=0,
            modeled_cost_micro_usd=subject.MAX_MODELED_COST_MICRO_USD + 1,
        )
    assert over.value.code == "COLLISION_BUDGET_COST_LIMIT_EXCEEDED"


def test_completion_requires_account_bind_and_exact_transcript_order() -> None:
    budget = _budget()
    _bind_pre_sources(budget)
    _open_all_sessions(budget, mode=subject.LOCAL_DIRECT_SSO)
    first = _completed_call(
        budget,
        stage="inventory",
        capture_index=1,
        ordinal=1,
    )
    second = _completed_call(
        budget,
        stage="candidate",
        capture_index=1,
        ordinal=1,
        domain="management",
    )

    with pytest.raises(subject.CollisionBudgetError) as reordered:
        subject.complete_collision_budget(
            budget,
            transcript_events=[second, first],
        )
    assert reordered.value.code == "COLLISION_BUDGET_TRANSCRIPT_MISMATCH"

    summary = subject.complete_collision_budget(
        budget,
        transcript_events=[first, second],
    )
    assert summary["provider_calls"] == 2

    pending = _budget()
    _bind_pre_sources(pending)
    _open_all_sessions(pending, mode=subject.LOCAL_DIRECT_SSO)
    subject.reserve_provider_call(
        pending,
        stage="inventory",
        domain="authority",
        operation="sts:GetCallerIdentity",
    )
    with pytest.raises(subject.CollisionBudgetError) as incomplete:
        subject.complete_collision_budget(pending, transcript_events=[])
    assert incomplete.value.code == "COLLISION_BUDGET_EVIDENCE_INCOMPLETE"


def test_replay_rejects_event_summary_and_transcript_tampering() -> None:
    summary, events, transcript_events = _complete_pre_with_two_calls()

    changed_event = deepcopy(events)
    changed_event[-1]["response_bytes"] += 1
    with pytest.raises(subject.CollisionBudgetError):
        subject.validate_collision_budget_evidence(
            summary=summary,
            events=changed_event,
            transcript_events=transcript_events,
        )

    changed_summary = deepcopy(summary)
    changed_summary["assume_role_opens"] = 10
    with pytest.raises(subject.CollisionBudgetError):
        subject.validate_collision_budget_evidence(
            summary=changed_summary,
            events=events,
            transcript_events=transcript_events,
        )

    changed_transcript = deepcopy(transcript_events)
    changed_transcript[0]["domain"] = "management"
    with pytest.raises(subject.CollisionBudgetError):
        subject.validate_collision_budget_evidence(
            summary=summary,
            events=events,
            transcript_events=changed_transcript,
        )


def test_budget_and_reservation_reject_duck_types_and_reuse() -> None:
    with pytest.raises(subject.CollisionBudgetError):
        subject.reserve_provider_call(
            object(),
            stage="inventory",
            domain="authority",
            operation="sts:GetCallerIdentity",
        )

    budget = _budget()
    reservation = subject.reserve_provider_call(
        budget,
        stage="inventory",
        domain="authority",
        operation="sts:GetCallerIdentity",
        projected_response_bytes=128,
    )
    subject.account_provider_response(reservation, response={})
    with pytest.raises(subject.CollisionBudgetError) as reused:
        subject.account_provider_response(reservation, response={})
    assert reused.value.code == "COLLISION_BUDGET_RESPONSE_ALREADY_ACCOUNTED"

    with pytest.raises(subject.CollisionBudgetError):
        subject.bind_provider_transcript_event(
            object(),
            transcript_event={},
        )
