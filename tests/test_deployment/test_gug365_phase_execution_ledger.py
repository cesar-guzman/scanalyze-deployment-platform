"""Offline tests for the durable GUG-365 phase execution ledger."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import fcntl
import io
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence

import pytest
from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import platform_authority_gug365_phase_execution_ledger as ledger  # noqa: E402


NOW = datetime(2035, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
DIGESTS = ["sha256:" + str(index) * 64 for index in range(1, 9)]
INITIAL_ABSENCE_DIGEST = ledger.canonical_digest(
    {"classification": "ALL_TARGETS_ABSENT", "observed_at": "AUTHORIZED"}
)


def _operation(sequence: int) -> dict[str, Any]:
    request = {"Synthetic": sequence}
    return {
        "sequence": sequence,
        "service": "iam",
        "api_action": "GetRole" if sequence == 1 else "CreateRole",
        "request": request,
        "request_digest": ledger.canonical_digest(request),
        "attempt_limit": 1,
        "retry_permitted": False,
    }


def _authority_requirement(phase: str) -> dict[str, Any]:
    return {
        "phase": phase,
        "required_policy_document_digest": DIGESTS[6],
        "accepted_cap_sources": ["DEDICATED_ROLE_PERMISSIONS_BOUNDARY"],
        "maximum_session_lifetime_seconds": 900,
    }


def _evidence(
    plan: Mapping[str, Any],
    phase: str,
    *,
    evaluation_at: datetime = NOW,
    caller_digest: str = DIGESTS[0],
    session_identifier_digest: str = DIGESTS[7],
) -> dict[str, Any]:
    selected = next(
        item for item in plan["authorization_phases"] if item["phase"] == phase
    )
    policy_digest = selected["executor_effective_authority_requirement"][
        "required_policy_document_digest"
    ]
    issued = evaluation_at - timedelta(seconds=60)
    collected = evaluation_at - timedelta(seconds=30)
    expires = evaluation_at + timedelta(seconds=840)
    result: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug365_executor_authority_evidence.v1"
        ),
        "phase": phase,
        "caller_account_id": plan["target"]["authority_account_id"],
        "region": plan["target"]["region"],
        "caller_arn_digest": caller_digest,
        "session_identifier_digest": session_identifier_digest,
        "session_issued_at": issued.isoformat().replace("+00:00", "Z"),
        "session_expires_at": expires.isoformat().replace("+00:00", "Z"),
        "evidence_collected_at": collected.isoformat().replace("+00:00", "Z"),
        "session_lifetime_seconds": 900,
        "session_remaining_seconds": 840,
        "session_chain_depth": 0,
        "evidence_collected_after_sts": True,
        "effective_policy_inventory_complete": True,
        "sole_identity_policy_document_digest": policy_digest,
        "additional_inline_policy_count": 0,
        "additional_attached_policy_count": 0,
        "group_policy_count": 0,
        "maximum_authority_source": "DEDICATED_ROLE_PERMISSIONS_BOUNDARY",
        "maximum_authority_document_digest": policy_digest,
        "raw_caller_arn_persisted": False,
        "evidence_digest": "",
    }
    result["evidence_digest"] = ledger.canonical_digest(
        {key: value for key, value in result.items() if key != "evidence_digest"}
    )
    return result


def _plan() -> dict[str, Any]:
    operations = [_operation(1), _operation(2)]
    phases = ledger.FORWARD_PHASES
    plan: dict[str, Any] = {
        "target": {
            "authority_account_id": "123456789012",
            "region": "us-east-1",
        },
        "boundary_set_digest": DIGESTS[0],
        "child_role_set_digest": DIGESTS[1],
        "service_role_digest": DIGESTS[2],
        "ledger_table_digest": DIGESTS[3],
        "broker_function_digest": DIGESTS[4],
        "ledger_factory_function_digest": DIGESTS[5],
        "ledger_factory_log_group_digest": DIGESTS[6],
        "planned_iam_write_digest": DIGESTS[7],
        "planned_readback_digest": ledger.canonical_digest([]),
        "authorization_phases": [
            {
                "phase": phase,
                "operations": copy.deepcopy(operations),
                "executor_effective_authority_requirement": (
                    _authority_requirement(phase)
                ),
                "checkpoint_digest": ledger.canonical_digest(
                    {"phase": phase, "checkpoint": "EXACT"}
                ),
            }
            for phase in phases
        ],
        "revocation": {
            "phase": "REVOCATOR",
            "operations": operations,
            "executor_effective_authority_requirement": (
                _authority_requirement("REVOCATOR")
            ),
        },
        "plan_digest": "",
    }
    plan["plan_digest"] = ledger.canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )
    return plan


def _full_plan() -> dict[str, Any]:
    return _plan()


def _consumed_bundle(
    plan: Mapping[str, Any],
    *,
    evaluation_lead_seconds: int = 0,
    phase_spacing_seconds: int = 1_200,
    reuse_session_identifier: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    records: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    expected_bundle_digest = ""
    previous: dict[str, Any] | None = None
    previous_phase_item: Mapping[str, Any] | None = None
    for phase_index, phase_item in enumerate(plan["authorization_phases"]):
        phase = phase_item["phase"]
        phase_start = NOW + timedelta(seconds=phase_index * phase_spacing_seconds)
        evaluation_at = phase_start - timedelta(seconds=evaluation_lead_seconds)
        required_checkpoint = (
            INITIAL_ABSENCE_DIGEST
            if previous_phase_item is None
            else previous_phase_item["checkpoint_digest"]
        )
        caller_digest = ledger.canonical_digest(
            {"phase": phase, "caller_session": phase_index}
        )
        session_identifier_digest = ledger.canonical_digest(
            {
                "phase": "REUSED" if reuse_session_identifier else phase,
                "session": 0 if reuse_session_identifier else phase_index,
            }
        )
        evidence = _evidence(
            plan,
            phase,
            evaluation_at=evaluation_at,
            caller_digest=caller_digest,
            session_identifier_digest=session_identifier_digest,
        )
        predecessor_security = _predecessor_security(
            previous, previous_phase_item
        )
        prepared = ledger.build_prepared_ledger(
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            phase=phase,
            profile_class="GUG365" + phase.replace("_", ""),
            caller_arn_digest=caller_digest,
            executor_authority_evidence_digest=evidence["evidence_digest"],
            executor_authority_evidence=evidence,
            authority_evaluation_at=evaluation_at,
            authority_session_identifier_digest=session_identifier_digest,
            authority_session_issued_at=evaluation_at - timedelta(seconds=60),
            authority_session_expires_at=evaluation_at + timedelta(seconds=840),
            authority_evidence_collected_at=evaluation_at - timedelta(seconds=30),
            host_digest=DIGESTS[2],
            predecessor_phase=(
                None if previous_phase_item is None else previous_phase_item["phase"]
            ),
            predecessor_terminal_receipt_digest=(
                None
                if previous is None
                else previous["receipt_chain"][-1]["receipt_digest"]
            ),
            predecessor_ledger_digest=(
                None if previous is None else previous["ledger_digest"]
            ),
            before_state_digest=required_checkpoint,
            required_predecessor_checkpoint_digest=required_checkpoint,
            **predecessor_security,
            not_before=phase_start,
            expires_at=phase_start + timedelta(minutes=10),
        )
        authorization = _authorization(prepared)
        claimed = ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=phase_start + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class=prepared["profile_class"],
            caller_arn_digest=caller_digest,
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=DIGESTS[2],
            execution_authorization=authorization,
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            executor_authority_evidence=evidence,
            authority_evaluation_at=evaluation_at,
            **predecessor_security,
        ).proposed_record
        current = claimed
        for sequence in (1, 2):
            in_flight = ledger.prepare_operation_in_flight(
                current,
                expected_version=current["ledger_version"],
                expected_digest=current["ledger_digest"],
                at=phase_start + timedelta(seconds=sequence + 1),
                operation_sequence=sequence,
            ).proposed_record
            current = ledger.prepare_operation_record(
                in_flight,
                expected_version=in_flight["ledger_version"],
                expected_digest=in_flight["ledger_digest"],
                at=phase_start + timedelta(seconds=sequence + 2),
                operation_sequence=sequence,
                outcome="SUCCEEDED",
                provider_result_digest=DIGESTS[4],
            ).proposed_record
        derived = ledger.phase_binding_from_plan(
            plan,
            phase=phase,
            expected_plan_digest=plan["plan_digest"],
        )
        expected_bundle_digest = derived["bundle_digest"]
        records.append(current)
        bindings.append(
            {
                "phase": phase,
                "ledger_id": prepared["ledger_id"],
                "initial_ledger_digest": prepared["initial_ledger_digest"],
                "claim_nonce_digest": DIGESTS[3],
                "terminal_receipt_digest": current["receipt_chain"][-1][
                    "receipt_digest"
                ],
                "caller_arn_digest": current["caller_arn_digest"],
                "executor_authority_evidence_digest": current[
                    "executor_authority_evidence_digest"
                ],
                "authority_session_identifier_digest": current[
                    "authority_session_identifier_digest"
                ],
                "authority_session_issued_at": current[
                    "authority_session_issued_at"
                ],
                "authority_session_expires_at": current[
                    "authority_session_expires_at"
                ],
                "authority_evidence_collected_at": current[
                    "authority_evidence_collected_at"
                ],
                "authority_evaluation_at": current["authority_evaluation_at"],
                "predecessor_phase": current["predecessor_phase"],
                "predecessor_terminal_receipt_digest": current[
                    "predecessor_terminal_receipt_digest"
                ],
                "predecessor_ledger_digest": current[
                    "predecessor_ledger_digest"
                ],
                "before_state_digest": current["before_state_digest"],
                "required_predecessor_checkpoint_digest": current[
                    "required_predecessor_checkpoint_digest"
                ],
            }
        )
        previous = current
        previous_phase_item = phase_item
    return records, bindings, expected_bundle_digest


def _prepared_later_phase(
    plan: Mapping[str, Any],
    previous: Mapping[str, Any],
    previous_phase_item: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    phase_item = plan["authorization_phases"][1]
    phase_start = NOW + timedelta(minutes=20)
    phase = phase_item["phase"]
    evidence = _evidence(
        plan,
        phase,
        evaluation_at=phase_start,
        caller_digest=ledger.canonical_digest({"phase": phase, "caller": 1}),
        session_identifier_digest=ledger.canonical_digest(
            {"phase": phase, "session": 1}
        ),
    )
    security = _predecessor_security(previous, previous_phase_item)
    prepared = ledger.build_prepared_ledger(
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        phase=phase,
        profile_class="GUG365FoundationFactory",
        caller_arn_digest=evidence["caller_arn_digest"],
        executor_authority_evidence_digest=evidence["evidence_digest"],
        executor_authority_evidence=evidence,
        authority_evaluation_at=phase_start,
        authority_session_identifier_digest=evidence["session_identifier_digest"],
        authority_session_issued_at=phase_start - timedelta(seconds=60),
        authority_session_expires_at=phase_start + timedelta(seconds=840),
        authority_evidence_collected_at=phase_start - timedelta(seconds=30),
        host_digest=DIGESTS[2],
        predecessor_phase=previous["phase"],
        predecessor_terminal_receipt_digest=previous["receipt_chain"][-1][
            "receipt_digest"
        ],
        predecessor_ledger_digest=previous["ledger_digest"],
        before_state_digest=previous_phase_item["checkpoint_digest"],
        required_predecessor_checkpoint_digest=previous_phase_item[
            "checkpoint_digest"
        ],
        **security,
        not_before=phase_start,
        expires_at=phase_start + timedelta(minutes=10),
    )
    return prepared, evidence, security


def _prepared(plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    selected_plan = _plan() if plan is None else plan
    evidence = _evidence(selected_plan, "POLICY_FACTORY")
    return ledger.build_prepared_ledger(
        plan=selected_plan,
        expected_plan_digest=selected_plan["plan_digest"],
        phase="POLICY_FACTORY",
        profile_class="GUG365PolicyFactory",
        caller_arn_digest=DIGESTS[0],
        executor_authority_evidence_digest=evidence["evidence_digest"],
        executor_authority_evidence=evidence,
        authority_evaluation_at=NOW,
        authority_session_identifier_digest=DIGESTS[7],
        authority_session_issued_at=NOW - timedelta(seconds=60),
        authority_session_expires_at=NOW + timedelta(seconds=840),
        authority_evidence_collected_at=NOW - timedelta(seconds=30),
        host_digest=DIGESTS[2],
        predecessor_phase=None,
        predecessor_terminal_receipt_digest=None,
        predecessor_ledger_digest=None,
        before_state_digest=INITIAL_ABSENCE_DIGEST,
        required_predecessor_checkpoint_digest=INITIAL_ABSENCE_DIGEST,
        expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
        predecessor_record=None,
        expected_predecessor_binding=None,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def _authorization(
    prepared: Mapping[str, Any], claim_nonce_digest: str = DIGESTS[3]
) -> dict[str, Any]:
    return {
        field: (
            claim_nonce_digest
            if field == "claim_nonce_digest"
            else copy.deepcopy(prepared[field])
        )
        for field in ledger._EXECUTION_AUTHORIZATION_FIELDS  # noqa: SLF001
    }


def _predecessor_security(
    previous: Mapping[str, Any] | None,
    previous_phase_item: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if previous is None:
        return {
            "expected_initial_bundle_absence_digest": INITIAL_ABSENCE_DIGEST,
            "predecessor_record": None,
            "expected_predecessor_binding": None,
        }
    assert previous_phase_item is not None
    return {
        "expected_initial_bundle_absence_digest": None,
        "predecessor_record": copy.deepcopy(previous),
        "expected_predecessor_binding": {
            "phase": previous["phase"],
            "ledger_id": previous["ledger_id"],
            "initial_ledger_digest": previous["initial_ledger_digest"],
            "claim_nonce_digest": previous["claim"]["claim_nonce_digest"],
            "terminal_receipt_digest": previous["receipt_chain"][-1][
                "receipt_digest"
            ],
            "ledger_digest": previous["ledger_digest"],
            "checkpoint_digest": previous_phase_item["checkpoint_digest"],
        },
    }


def _claim_security(
    prepared: Mapping[str, Any], plan: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    selected_plan = _plan() if plan is None else plan
    return {
        "execution_authorization": _authorization(prepared),
        "plan": selected_plan,
        "expected_plan_digest": selected_plan["plan_digest"],
        "executor_authority_evidence": _evidence(
            selected_plan, str(prepared["phase"])
        ),
        "authority_evaluation_at": NOW,
        "expected_initial_bundle_absence_digest": INITIAL_ABSENCE_DIGEST,
        "predecessor_record": None,
        "expected_predecessor_binding": None,
    }


def _claimed(
    prepared: Mapping[str, Any], plan: Mapping[str, Any] | None = None
) -> ledger.CasTransition:
    selected_plan = _plan() if plan is None else plan
    return ledger.prepare_claim(
        prepared,
        expected_version=prepared["ledger_version"],
        expected_digest=prepared["ledger_digest"],
        at=NOW + timedelta(seconds=1),
        claim_nonce_digest=DIGESTS[3],
        profile_class="GUG365PolicyFactory",
        caller_arn_digest=DIGESTS[0],
        executor_authority_evidence_digest=prepared[
            "executor_authority_evidence_digest"
        ],
        host_digest=DIGESTS[2],
        **_claim_security(prepared, selected_plan),
    )


def _in_flight(
    claimed: Mapping[str, Any], sequence: int = 1
) -> dict[str, Any]:
    return ledger.prepare_operation_in_flight(
        claimed,
        expected_version=claimed["ledger_version"],
        expected_digest=claimed["ledger_digest"],
        at=NOW + timedelta(seconds=sequence),
        operation_sequence=sequence,
    ).proposed_record


def _ambiguous_first_operation() -> dict[str, Any]:
    claimed = _claimed(_prepared()).proposed_record
    in_flight = _in_flight(claimed)
    return ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record


def _bound_reconciliation_binding(
    ambiguous: Mapping[str, Any],
    *,
    expected_effect_state_digest: str,
    expected_no_effect_state_digest: str,
) -> dict[str, Any]:
    outcome = ambiguous["operation_outcomes"][-1]
    binding: dict[str, Any] = {
        "ambiguous_ledger_digest": ambiguous["ledger_digest"],
        "ambiguous_operation_sequence": outcome["operation_sequence"],
        "ambiguous_request_digest": outcome["request_digest"],
        "ambiguous_operation_digest": ledger.canonical_digest(
            {"phase": ambiguous["phase"], "operation_sequence": 1}
        ),
        "readback_contract_digest": ledger.canonical_digest(
            {"contract": "exact-read-only", "operation_sequence": 1}
        ),
        "caller_arn_digest": ambiguous["caller_arn_digest"],
        "session_identifier_digest": ambiguous[
            "authority_session_identifier_digest"
        ],
        "identity_receipt_digest": ledger.canonical_digest(
            {"identity": "current-sts-session"}
        ),
        "provider_transcript_digest": ledger.canonical_digest(
            {"provider_writes": 0, "readback_contract": "exact-read-only"}
        ),
        "expectation_binding_digest": "",
    }
    expectation = {
        "ledger_id": ambiguous["ledger_id"],
        "ambiguous_ledger_digest": ambiguous["ledger_digest"],
        "plan_digest": ambiguous["plan_digest"],
        "phase": ambiguous["phase"],
        "ordered_operations_digest": ambiguous["ordered_operations_digest"],
        "ambiguous_operation_sequence": binding[
            "ambiguous_operation_sequence"
        ],
        "ambiguous_request_digest": binding["ambiguous_request_digest"],
        "ambiguous_operation_digest": binding["ambiguous_operation_digest"],
        "readback_contract_digest": binding["readback_contract_digest"],
        "caller_arn_digest": binding["caller_arn_digest"],
        "session_identifier_digest": binding["session_identifier_digest"],
        "identity_receipt_digest": binding["identity_receipt_digest"],
        "expected_effect_state_digest": expected_effect_state_digest,
        "expected_no_effect_state_digest": expected_no_effect_state_digest,
    }
    binding["expectation_binding_digest"] = ledger.canonical_digest(expectation)
    return binding


def test_prepare_binds_plan_bundle_target_authority_window_host_and_order() -> None:
    plan = _plan()
    prepared = _prepared(plan)
    binding = ledger.phase_binding_from_plan(
        plan,
        phase="POLICY_FACTORY",
        expected_plan_digest=plan["plan_digest"],
    )
    assert prepared["plan_digest"] == plan["plan_digest"]
    assert prepared["bundle_digest"] == binding["bundle_digest"]
    assert prepared["account_id"] == "123456789012"
    assert prepared["region"] == "us-east-1"
    assert prepared["profile_class"] == "GUG365PolicyFactory"
    assert prepared["phase"] == "POLICY_FACTORY"
    assert prepared["ordered_operations_digest"] == binding[
        "ordered_operations_digest"
    ]
    assert prepared["ordered_request_digests"] == binding[
        "ordered_request_digests"
    ]
    assert prepared["attempt_count"] == 0
    assert prepared["status"] == "PREPARED"
    ledger.validate_ledger(prepared)


def test_claim_is_one_attempt_cas_and_replay_is_blocked() -> None:
    prepared = _prepared()
    claimed = _claimed(prepared)
    assert claimed.attempt_limit == 1
    assert claimed.retry_permitted is False
    assert claimed.expected_version == 1
    assert claimed.expected_digest == prepared["ledger_digest"]
    assert claimed.proposed_record["status"] == "CLAIMED"
    assert claimed.proposed_record["attempt_count"] == 1
    assert claimed.proposed_record["previous_ledger_digest"] == prepared[
        "ledger_digest"
    ]
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_REPLAY_BLOCKED"):
        _claimed(claimed.proposed_record)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_CAS_CONFLICT"):
        ledger.prepare_claim(
            prepared,
            expected_version=99,
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class="GUG365PolicyFactory",
            caller_arn_digest=DIGESTS[0],
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=DIGESTS[2],
            **_claim_security(prepared),
        )


def test_claim_rejects_expiry_and_every_executor_binding_mismatch() -> None:
    prepared = _prepared()
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_EXPIRED_OR_NOT_YET_VALID"
    ):
        ledger.prepare_claim(
            prepared,
            expected_version=1,
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(minutes=10),
            claim_nonce_digest=DIGESTS[3],
            profile_class="GUG365PolicyFactory",
            caller_arn_digest=DIGESTS[0],
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=DIGESTS[2],
            **_claim_security(prepared),
        )
    for field, value in (
        ("profile_class", "WrongProfile"),
        ("caller_arn_digest", DIGESTS[4]),
        ("executor_authority_evidence_digest", DIGESTS[5]),
        ("host_digest", DIGESTS[6]),
    ):
        arguments = {
            "profile_class": "GUG365PolicyFactory",
            "caller_arn_digest": DIGESTS[0],
            "executor_authority_evidence_digest": prepared[
                "executor_authority_evidence_digest"
            ],
            "host_digest": DIGESTS[2],
            **_claim_security(prepared),
        }
        arguments[field] = value
        with pytest.raises(
            ledger.PhaseLedgerError, match="CLAIM_BINDING_MISMATCH"
        ):
            ledger.prepare_claim(
                prepared,
                expected_version=1,
                expected_digest=prepared["ledger_digest"],
                at=NOW + timedelta(seconds=1),
                claim_nonce_digest=DIGESTS[3],
                **arguments,
            )


def test_pre_effect_authorization_rejects_alternate_root_nonce_or_stale_evidence(
    tmp_path: Path,
) -> None:
    plan = _plan()
    prepared = _prepared(plan)
    alternate = _prepared(plan)
    alternate["host_digest"] = DIGESTS[6]
    alternate["ledger_id"] = ledger.canonical_digest(
        ledger._immutable_projection(alternate)  # noqa: SLF001
    )
    alternate["initial_ledger_digest"] = ledger.canonical_digest(
        ledger._prepared_baseline(alternate)  # noqa: SLF001
    )
    alternate["ledger_digest"] = ledger.canonical_digest(
        {key: value for key, value in alternate.items() if key != "ledger_digest"}
    )
    with pytest.raises(
        ledger.PhaseLedgerError,
        match="PHASE_EXECUTION_AUTHORIZATION_BINDING_MISMATCH",
    ):
        ledger.prepare_claim(
            alternate,
            expected_version=alternate["ledger_version"],
            expected_digest=alternate["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class=alternate["profile_class"],
            caller_arn_digest=alternate["caller_arn_digest"],
            executor_authority_evidence_digest=alternate[
                "executor_authority_evidence_digest"
            ],
            host_digest=alternate["host_digest"],
            execution_authorization=_authorization(prepared),
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
        )
    with pytest.raises(ledger.PhaseLedgerError, match="CLAIM_NONCE_NOT_AUTHORIZED"):
        ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[4],
            profile_class=prepared["profile_class"],
            caller_arn_digest=prepared["caller_arn_digest"],
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=prepared["host_digest"],
            **_claim_security(prepared, plan),
        )
    stale = _evidence(plan, "POLICY_FACTORY")
    with pytest.raises(ledger.PhaseLedgerError, match="EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED"):
        ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class=prepared["profile_class"],
            caller_arn_digest=prepared["caller_arn_digest"],
            executor_authority_evidence_digest=prepared[
                "executor_authority_evidence_digest"
            ],
            host_digest=prepared["host_digest"],
            execution_authorization=_authorization(prepared),
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            executor_authority_evidence=stale,
            authority_evaluation_at=NOW + timedelta(minutes=20),
            **_predecessor_security(None, None),
        )


def test_later_phase_requires_exact_consumed_predecessor_before_claim_or_callback(
    tmp_path: Path,
) -> None:
    plan = _full_plan()
    records, _bindings, _bundle = _consumed_bundle(plan)
    previous = records[0]
    previous_phase_item = plan["authorization_phases"][0]
    prepared, evidence, security = _prepared_later_phase(
        plan, previous, previous_phase_item
    )
    phase_start = NOW + timedelta(minutes=20)
    common = {
        "expected_version": prepared["ledger_version"],
        "expected_digest": prepared["ledger_digest"],
        "at": phase_start + timedelta(seconds=1),
        "claim_nonce_digest": DIGESTS[3],
        "profile_class": prepared["profile_class"],
        "caller_arn_digest": prepared["caller_arn_digest"],
        "executor_authority_evidence_digest": prepared[
            "executor_authority_evidence_digest"
        ],
        "host_digest": prepared["host_digest"],
        "execution_authorization": _authorization(prepared),
        "plan": plan,
        "expected_plan_digest": plan["plan_digest"],
        "executor_authority_evidence": evidence,
        "authority_evaluation_at": phase_start,
    }
    for bad_security in (
        {
            "expected_initial_bundle_absence_digest": None,
            "predecessor_record": None,
            "expected_predecessor_binding": None,
        },
        {
            **security,
            "predecessor_record": copy.deepcopy(previous) | {"status": "CLAIMED"},
        },
        {
            **security,
            "expected_predecessor_binding": {
                **security["expected_predecessor_binding"],
                "terminal_receipt_digest": DIGESTS[7],
            },
        },
    ):
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.prepare_claim(prepared, **common, **bad_security)

    claim = ledger.prepare_claim(prepared, **common, **security)
    root = tmp_path / "private-later-phase"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(prepared)
    store.compare_and_swap(claim)
    callbacks = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal callbacks
        callbacks += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError, match="PREDECESSOR_RECORD_AND_BINDING_REQUIRED"
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=evidence,
            authority_evaluation_at=phase_start,
            expected_initial_bundle_absence_digest=None,
            predecessor_record=None,
            expected_predecessor_binding=None,
            clock=lambda: phase_start + timedelta(seconds=2),
            invoke_once=invoke,
        )
    assert callbacks == 0
    assert store.read(prepared["ledger_id"])["status"] == "CLAIMED"


def test_runner_rejects_wrong_independent_authorization_before_callback(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError, match="INITIAL_PHASE_PRECONDITION_MISMATCH"
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            expected_initial_bundle_absence_digest=DIGESTS[7],
            predecessor_record=None,
            expected_predecessor_binding=None,
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    wrong = _authorization(prepared, claim_nonce_digest=DIGESTS[5])
    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_CLAIM_NONCE_NOT_AUTHORIZED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=wrong,
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    assert calls == 0
    assert store.read(prepared["ledger_id"])["status"] == "CLAIMED"


def test_future_authority_evaluation_cannot_authorize_earlier_claim_or_callback(
    tmp_path: Path,
) -> None:
    plan = _plan()
    future_evaluation = NOW + timedelta(seconds=20)
    future_evidence = _evidence(
        plan, "POLICY_FACTORY", evaluation_at=future_evaluation
    )
    forged = _prepared(plan)
    forged.update(
        {
            "executor_authority_evidence_digest": future_evidence[
                "evidence_digest"
            ],
            "authority_session_identifier_digest": future_evidence[
                "session_identifier_digest"
            ],
            "authority_session_issued_at": future_evidence["session_issued_at"],
            "authority_session_expires_at": future_evidence[
                "session_expires_at"
            ],
            "authority_evidence_collected_at": future_evidence[
                "evidence_collected_at"
            ],
            "authority_evaluation_at": future_evaluation.isoformat().replace(
                "+00:00", "Z"
            ),
        }
    )
    forged["ledger_id"] = ledger.canonical_digest(
        ledger._immutable_projection(forged)  # noqa: SLF001
    )
    forged["initial_ledger_digest"] = ledger.canonical_digest(
        ledger._prepared_baseline(forged)  # noqa: SLF001
    )
    forged["ledger_digest"] = ledger.canonical_digest(
        {key: value for key, value in forged.items() if key != "ledger_digest"}
    )
    with pytest.raises(
        ledger.PhaseLedgerError,
        match="PHASE_EXECUTION_AUTHORIZATION_SESSION_INVALID",
    ):
        ledger.prepare_claim(
            forged,
            expected_version=forged["ledger_version"],
            expected_digest=forged["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class=forged["profile_class"],
            caller_arn_digest=forged["caller_arn_digest"],
            executor_authority_evidence_digest=forged[
                "executor_authority_evidence_digest"
            ],
            host_digest=forged["host_digest"],
            execution_authorization=_authorization(forged),
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            executor_authority_evidence=future_evidence,
            authority_evaluation_at=future_evaluation,
            **_predecessor_security(None, None),
        )

    future_prepared = ledger.build_prepared_ledger(
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        phase="POLICY_FACTORY",
        profile_class="GUG365PolicyFactoryFuture",
        caller_arn_digest=DIGESTS[0],
        executor_authority_evidence_digest=future_evidence["evidence_digest"],
        executor_authority_evidence=future_evidence,
        authority_evaluation_at=future_evaluation,
        authority_session_identifier_digest=future_evidence[
            "session_identifier_digest"
        ],
        authority_session_issued_at=datetime.fromisoformat(
            future_evidence["session_issued_at"].replace("Z", "+00:00")
        ),
        authority_session_expires_at=datetime.fromisoformat(
            future_evidence["session_expires_at"].replace("Z", "+00:00")
        ),
        authority_evidence_collected_at=datetime.fromisoformat(
            future_evidence["evidence_collected_at"].replace("Z", "+00:00")
        ),
        host_digest=DIGESTS[2],
        predecessor_phase=None,
        predecessor_terminal_receipt_digest=None,
        predecessor_ledger_digest=None,
        before_state_digest=INITIAL_ABSENCE_DIGEST,
        required_predecessor_checkpoint_digest=INITIAL_ABSENCE_DIGEST,
        **_predecessor_security(None, None),
        not_before=future_evaluation,
        expires_at=future_evaluation + timedelta(minutes=10),
    )
    root = tmp_path / "private-future-evaluation"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(future_prepared)
    claimed = ledger.prepare_claim(
        future_prepared,
        expected_version=future_prepared["ledger_version"],
        expected_digest=future_prepared["ledger_digest"],
        at=future_evaluation + timedelta(seconds=1),
        claim_nonce_digest=DIGESTS[3],
        profile_class=future_prepared["profile_class"],
        caller_arn_digest=future_prepared["caller_arn_digest"],
        executor_authority_evidence_digest=future_prepared[
            "executor_authority_evidence_digest"
        ],
        host_digest=future_prepared["host_digest"],
        execution_authorization=_authorization(future_prepared),
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        executor_authority_evidence=future_evidence,
        authority_evaluation_at=future_evaluation,
        **_predecessor_security(None, None),
    )
    store.compare_and_swap(claimed)
    callbacks = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal callbacks
        callbacks += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError,
        match="RUNNER_AUTHORITY_EVALUATION_NOT_YET_VALID",
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=future_prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(future_prepared),
            executor_authority_evidence=future_evidence,
            authority_evaluation_at=future_evaluation,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=1),
            invoke_once=invoke,
        )
    assert callbacks == 0
    assert store.read(future_prepared["ledger_id"])["status"] == "CLAIMED"


def test_runner_snapshots_mutable_authorization_and_evidence_before_effect(
    tmp_path: Path,
) -> None:
    class MutatingMapping(dict[str, Any]):
        def __init__(self, value: Mapping[str, Any], mutation: Any) -> None:
            super().__init__(copy.deepcopy(value))
            self._mutation = mutation

        def items(self) -> Any:
            snapshot = copy.deepcopy(list(super().items()))
            self._mutation(self)
            return iter(snapshot)

    store, plan, prepared = _claimed_store(tmp_path)
    bad_authorization = _authorization(prepared)
    bad_authorization["claim_nonce_digest"] = DIGESTS[5]
    moving_authorization = MutatingMapping(
        bad_authorization,
        lambda value: value.update(_authorization(prepared)),
    )
    good_evidence = _evidence(plan, "POLICY_FACTORY")
    bad_evidence = copy.deepcopy(good_evidence)
    bad_evidence["additional_attached_policy_count"] = 1
    bad_evidence["evidence_digest"] = ledger.canonical_digest(
        {
            key: value
            for key, value in bad_evidence.items()
            if key != "evidence_digest"
        }
    )
    moving_evidence = MutatingMapping(
        bad_evidence,
        lambda value: value.update(copy.deepcopy(good_evidence)),
    )
    callbacks = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal callbacks
        callbacks += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError, match="RUNNER_CLAIM_NONCE_NOT_AUTHORIZED"
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=moving_authorization,
            executor_authority_evidence=moving_evidence,
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    assert callbacks == 0
    assert moving_authorization["claim_nonce_digest"] == DIGESTS[3]
    assert moving_evidence["additional_attached_policy_count"] == 0
    assert store.read(prepared["ledger_id"])["status"] == "CLAIMED"


def test_canonical_plan_snapshot_prevents_mutation_toctou(
    tmp_path: Path,
) -> None:
    class MutatingPlan(dict[str, Any]):
        def items(self) -> Any:
            snapshot = copy.deepcopy(list(super().items()))
            self["authorization_phases"][0]["operations"][0]["request"][
                "Synthetic"
            ] = 999
            return iter(snapshot)

    store, plan, prepared = _claimed_store(tmp_path)
    moving = MutatingPlan(copy.deepcopy(plan))
    seen: list[int] = []

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        seen.append(operation["request"]["Synthetic"])
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    result = ledger.execute_claimed_phase(
        store=store,
        plan=moving,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: NOW + timedelta(seconds=2),
        invoke_once=invoke,
    )
    assert result["status"] == "CONSUMED"
    assert seen == [1, 2]
    assert moving["authorization_phases"][0]["operations"][0]["request"][
        "Synthetic"
    ] == 999


def test_operation_sequence_consumes_only_after_final_one_attempt() -> None:
    claimed = _claimed(_prepared()).proposed_record
    in_flight = _in_flight(claimed)
    first = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[4],
    )
    assert first.proposed_record["status"] == "CLAIMED"
    assert first.proposed_record["claim"]["next_operation_sequence"] == 2
    second_in_flight = _in_flight(first.proposed_record, 2)
    consumed = ledger.prepare_operation_record(
        second_in_flight,
        expected_version=second_in_flight["ledger_version"],
        expected_digest=second_in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        operation_sequence=2,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[5],
    )
    record = consumed.proposed_record
    assert record["status"] == "CONSUMED"
    assert all(item["write_attempt_count"] == 1 for item in record["operation_outcomes"])
    assert all(item["blind_retry_permitted"] is False for item in record["operation_outcomes"])
    assert record["operation_outcomes"][0]["request_digest"] == record[
        "ordered_request_digests"
    ][0]
    assert record["receipt_chain"][1]["previous_receipt_digest"] == record[
        "receipt_chain"
    ][0]["receipt_digest"]
    assert "arn" not in ledger.canonical_json(record["receipt_chain"]).casefold()
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_OPERATION_NOT_IN_FLIGHT"
    ):
        ledger.prepare_operation_record(
            record,
            expected_version=record["ledger_version"],
            expected_digest=record["ledger_digest"],
            at=NOW + timedelta(seconds=4),
            operation_sequence=1,
            outcome="SUCCEEDED",
            provider_result_digest=DIGESTS[4],
        )


def test_ambiguous_result_allows_read_only_reconcile_and_never_blind_retry() -> None:
    claimed = _claimed(_prepared()).proposed_record
    in_flight = _in_flight(claimed)
    ambiguous = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record
    assert ambiguous["status"] == "AMBIGUOUS"
    assert ambiguous["operation_outcomes"][-1]["next_required_action"] == "RECONCILE_READ_ONLY"
    reconciled = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        observed_state_digest=DIGESTS[5],
        classification="EFFECT_PROVEN",
    )
    assert reconciled.attempt_limit == 1
    assert reconciled.retry_permitted is False
    record = reconciled.proposed_record
    assert record["reconciliation"]["read_only"] is True
    assert record["reconciliation"]["provider_writes_performed"] == 0
    assert record["reconciliation"]["retry_of_ambiguous_write_permitted"] is False
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_NOT_PERMITTED"
    ):
        ledger.prepare_read_only_reconciliation(
            claimed,
            expected_version=claimed["ledger_version"],
            expected_digest=claimed["ledger_digest"],
            at=NOW + timedelta(seconds=2),
            observed_state_digest=DIGESTS[5],
            classification="EFFECT_PROVEN",
        )


@pytest.mark.parametrize(
    ("observed_kind", "expected_classification"),
    [
        ("effect", "EFFECT_PROVEN"),
        ("no_effect", "NO_EFFECT_PROVEN"),
        ("other", "INCONCLUSIVE"),
    ],
)
def test_bound_reconciliation_derives_classification_and_persists_causal_evidence(
    observed_kind: str,
    expected_classification: str,
) -> None:
    ambiguous = _ambiguous_first_operation()
    effect = ledger.canonical_digest({"state": "effect"})
    no_effect = ledger.canonical_digest({"state": "no-effect"})
    observed = {
        "effect": effect,
        "no_effect": no_effect,
        "other": ledger.canonical_digest({"state": "inconclusive"}),
    }[observed_kind]
    binding = _bound_reconciliation_binding(
        ambiguous,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
    )

    transition = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        observed_state_digest=observed,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        reconciliation_binding=binding,
    )

    record = transition.proposed_record
    reconciliation = record["reconciliation"]
    assert reconciliation["classification"] == expected_classification
    assert reconciliation["binding_mode"] == "CAUSAL_EXPECTATIONS_BOUND"
    assert reconciliation["ambiguous_ledger_digest"] == ambiguous["ledger_digest"]
    assert reconciliation["ambiguous_operation_sequence"] == 1
    assert reconciliation["ambiguous_request_digest"] == ambiguous[
        "operation_outcomes"
    ][-1]["request_digest"]
    assert reconciliation["expected_effect_state_digest"] == effect
    assert reconciliation["expected_no_effect_state_digest"] == no_effect
    assert reconciliation["caller_arn_digest"] == ambiguous["caller_arn_digest"]
    assert reconciliation["session_identifier_digest"] == ambiguous[
        "authority_session_identifier_digest"
    ]
    receipt_facts = record["receipt_chain"][-1]["facts"]
    assert receipt_facts["expectation_binding_digest"] == binding[
        "expectation_binding_digest"
    ]
    assert receipt_facts["provider_transcript_digest"] == binding[
        "provider_transcript_digest"
    ]
    assert receipt_facts["provider_writes_performed"] == 0
    ledger.validate_ledger(record)


def test_bound_reconciliation_matches_the_draft_2020_ledger_schema() -> None:
    ambiguous = _ambiguous_first_operation()
    effect = ledger.canonical_digest({"state": "effect"})
    no_effect = ledger.canonical_digest({"state": "no-effect"})
    binding = _bound_reconciliation_binding(
        ambiguous,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
    )
    record = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        observed_state_digest=effect,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        reconciliation_binding=binding,
    ).proposed_record
    schema = json.loads(
        (
            REPO_ROOT
            / "schemas/platform-authority-gug365-phase-execution-ledger.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)


def test_bound_reconciliation_rejects_partial_substituted_or_caller_classified_evidence() -> None:
    ambiguous = _ambiguous_first_operation()
    effect = ledger.canonical_digest({"state": "effect"})
    no_effect = ledger.canonical_digest({"state": "no-effect"})
    binding = _bound_reconciliation_binding(
        ambiguous,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
    )
    common = {
        "expected_version": ambiguous["ledger_version"],
        "expected_digest": ambiguous["ledger_digest"],
        "at": NOW + timedelta(seconds=3),
        "observed_state_digest": effect,
    }

    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_BINDING_INCOMPLETE"
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            **common,
            expected_effect_state_digest=effect,
        )
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_EXPECTATIONS_INVALID"
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            **common,
            expected_effect_state_digest=effect,
            expected_no_effect_state_digest=effect,
            reconciliation_binding=binding,
        )
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_CLASSIFICATION_MISMATCH"
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            **common,
            classification="NO_EFFECT_PROVEN",
            expected_effect_state_digest=effect,
            expected_no_effect_state_digest=no_effect,
            reconciliation_binding=binding,
        )
    substituted = copy.deepcopy(binding)
    substituted["session_identifier_digest"] = DIGESTS[6]
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_BINDING_MISMATCH"
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            **common,
            expected_effect_state_digest=effect,
            expected_no_effect_state_digest=no_effect,
            reconciliation_binding=substituted,
        )
    with pytest.raises(
        ledger.PhaseLedgerError,
        match="RECONCILIATION_EXPECTATION_BINDING_MISMATCH",
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            **common,
            expected_effect_state_digest=no_effect,
            expected_no_effect_state_digest=ledger.canonical_digest(
                {"state": "different-no-effect"}
            ),
            reconciliation_binding=binding,
        )


def test_bound_reconciliation_resealed_causal_substitution_fails_validation() -> None:
    ambiguous = _ambiguous_first_operation()
    effect = ledger.canonical_digest({"state": "effect"})
    no_effect = ledger.canonical_digest({"state": "no-effect"})
    binding = _bound_reconciliation_binding(
        ambiguous,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
    )
    record = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        observed_state_digest=effect,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        reconciliation_binding=binding,
    ).proposed_record

    cases: list[dict[str, Any]] = []
    wrong_expectation = copy.deepcopy(record)
    wrong_expectation["reconciliation"]["expected_effect_state_digest"] = DIGESTS[5]
    cases.append(wrong_expectation)
    wrong_operation = copy.deepcopy(record)
    wrong_operation["reconciliation"]["ambiguous_operation_digest"] = DIGESTS[5]
    wrong_operation["receipt_chain"][-1]["facts"][
        "ambiguous_operation_digest"
    ] = DIGESTS[5]
    cases.append(wrong_operation)
    wrong_classification = copy.deepcopy(record)
    wrong_classification["reconciliation"]["classification"] = "NO_EFFECT_PROVEN"
    wrong_classification["receipt_chain"][-1]["facts"][
        "classification"
    ] = "NO_EFFECT_PROVEN"
    cases.append(wrong_classification)
    missing_receipt_evidence = copy.deepcopy(record)
    del missing_receipt_evidence["receipt_chain"][-1]["facts"][
        "provider_transcript_digest"
    ]
    cases.append(missing_receipt_evidence)

    for case in cases:
        _reseal_receipts_and_ledger(case)
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_ledger(case)


def test_classifier_accepts_consumed_record_not_naked_equal_digests() -> None:
    plan = _plan()
    prepared = _prepared(plan)
    binding = ledger.phase_binding_from_plan(
        plan,
        phase="POLICY_FACTORY",
        expected_plan_digest=plan["plan_digest"],
    )
    claimed = _claimed(prepared).proposed_record
    in_flight = _in_flight(claimed)
    first = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[4],
    ).proposed_record
    second_in_flight = _in_flight(first, 2)
    consumed = ledger.prepare_operation_record(
        second_in_flight,
        expected_version=second_in_flight["ledger_version"],
        expected_digest=second_in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        operation_sequence=2,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[5],
    ).proposed_record
    assert ledger.validate_consumed_causal_record(
        consumed,
        expected_plan_digest=plan["plan_digest"],
        expected_bundle_digest=binding["bundle_digest"],
        expected_phase="POLICY_FACTORY",
        expected_ledger_id=prepared["ledger_id"],
        expected_initial_ledger_digest=prepared["initial_ledger_digest"],
        expected_claim_nonce_digest=DIGESTS[3],
        expected_terminal_receipt_digest=consumed["receipt_chain"][-1][
            "receipt_digest"
        ],
    ) == consumed["ledger_digest"]
    tampered = copy.deepcopy(consumed)
    tampered["host_digest"] = DIGESTS[7]
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_DIGEST_MISMATCH"):
        ledger.validate_consumed_causal_record(
            tampered,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=binding["bundle_digest"],
            expected_phase="POLICY_FACTORY",
            expected_ledger_id=prepared["ledger_id"],
            expected_initial_ledger_digest=prepared["initial_ledger_digest"],
            expected_claim_nonce_digest=DIGESTS[3],
            expected_terminal_receipt_digest=consumed["receipt_chain"][-1][
                "receipt_digest"
            ],
        )
    with pytest.raises(
        ledger.PhaseLedgerError, match="CAUSAL_LEDGER_CLAIM_BINDING_MISMATCH"
    ):
        ledger.validate_consumed_causal_record(
            prepared,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=binding["bundle_digest"],
            expected_phase="POLICY_FACTORY",
            expected_ledger_id=prepared["ledger_id"],
            expected_initial_ledger_digest=prepared["initial_ledger_digest"],
            expected_claim_nonce_digest=DIGESTS[3],
            expected_terminal_receipt_digest=DIGESTS[4],
        )

    forged = copy.deepcopy(consumed)
    forged["initial_ledger_digest"] = DIGESTS[7]
    forged["ledger_digest"] = ledger.canonical_digest(
        {key: value for key, value in forged.items() if key != "ledger_digest"}
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="INITIAL_LEDGER_DIGEST_MISMATCH"
    ):
        ledger.validate_consumed_causal_record(
            forged,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=binding["bundle_digest"],
            expected_phase="POLICY_FACTORY",
            expected_ledger_id=prepared["ledger_id"],
            expected_initial_ledger_digest=prepared["initial_ledger_digest"],
            expected_claim_nonce_digest=DIGESTS[3],
            expected_terminal_receipt_digest=consumed["receipt_chain"][-1][
                "receipt_digest"
            ],
        )


def test_plan_operation_request_digest_retry_or_order_drift_blocks_prepare() -> None:
    for mutation in ("request", "retry", "order"):
        plan = _plan()
        operations = plan["authorization_phases"][0]["operations"]
        if mutation == "request":
            operations[0]["request"]["Synthetic"] = 999
        elif mutation == "retry":
            operations[0]["retry_permitted"] = True
        else:
            operations.reverse()
        plan["plan_digest"] = ledger.canonical_digest(
            {key: value for key, value in plan.items() if key != "plan_digest"}
        )
        with pytest.raises(ledger.PhaseLedgerError):
            _prepared(plan)


def _cas_worker(
    root: str, transition: ledger.CasTransition, queue: multiprocessing.Queue[str]
) -> None:
    try:
        ledger.DurablePhaseLedgerStore(Path(root)).compare_and_swap(transition)
    except ledger.PhaseLedgerError as exc:
        queue.put(exc.code)
    else:
        queue.put("OK")


def _blocking_runner_worker(
    root: str,
    plan: Mapping[str, Any],
    ledger_id: str,
    execution_authorization: Mapping[str, Any],
    entered: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
    queue: multiprocessing.Queue[str],
) -> None:
    store = ledger.DurablePhaseLedgerStore(Path(root))

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        entered.set()
        release.wait(30)
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    try:
        result = ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=ledger_id,
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=execution_authorization,
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    except BaseException as exc:  # pragma: no cover - diagnostic child path
        queue.put(type(exc).__name__)
    else:
        queue.put(str(result["status"]))


def test_owner_only_store_create_and_atomic_cas_reject_stale_writer(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    store.create(prepared)
    name = next(root.iterdir())
    metadata = name.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    transition = _claimed(prepared)
    stored = store.compare_and_swap(transition)
    assert stored == transition.proposed_record
    assert store.read(prepared["ledger_id"]) == stored
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_CAS_CONFLICT"):
        store.compare_and_swap(transition)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_ALREADY_EXISTS"):
        store.create(prepared)


def test_concurrent_same_cas_has_exactly_one_winner(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    store.create(prepared)
    transition = _claimed(prepared)
    queue: multiprocessing.Queue[str] = multiprocessing.Queue()
    workers = [
        multiprocessing.Process(
            target=_cas_worker, args=(str(root), transition, queue)
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    results = sorted(queue.get(timeout=2) for _ in workers)
    assert results.count("OK") == 1
    assert len([item for item in results if item != "OK"]) == 1
    assert store.read(prepared["ledger_id"])["ledger_version"] == 2


def test_store_rejects_unsafe_root_symlink_hardlink_and_mode(tmp_path: Path) -> None:
    prepared = _prepared()
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    real.chmod(0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_ROOT_SYMLINK_FORBIDDEN"
    ):
        ledger.DurablePhaseLedgerStore(alias).create(prepared)
    real.chmod(0o755)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_ROOT_MODE_INVALID"):
        ledger.DurablePhaseLedgerStore(real).create(prepared)
    real.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(real)
    store.create(prepared)
    path = real / store._name(prepared["ledger_id"])  # noqa: SLF001
    hardlink = tmp_path / "hardlink"
    os.link(path, hardlink)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_FILE_INVALID"):
        store.read(prepared["ledger_id"])


def test_store_fails_closed_without_nofollow_for_create_read_and_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    populated_root = tmp_path / "private-populated"
    populated_root.mkdir(mode=0o700)
    populated_root.chmod(0o700)
    populated = ledger.DurablePhaseLedgerStore(populated_root)
    prepared = _prepared()
    populated.create(prepared)

    empty_root = tmp_path / "private-empty"
    empty_root.mkdir(mode=0o700)
    empty_root.chmod(0o700)
    empty = ledger.DurablePhaseLedgerStore(empty_root)
    monkeypatch.delattr(ledger.os, "O_NOFOLLOW")

    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_NOFOLLOW_UNAVAILABLE"):
        empty.create(_prepared())
    assert list(empty_root.iterdir()) == []
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_NOFOLLOW_UNAVAILABLE"):
        populated.read(prepared["ledger_id"])
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_NOFOLLOW_UNAVAILABLE"):
        populated.compare_and_swap(_claimed(prepared))
    assert populated_root.joinpath(populated._name(prepared["ledger_id"])).exists()  # noqa: SLF001


def test_store_rejects_root_swap_between_path_check_and_component_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-root-swap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    replacement = tmp_path / "replacement-root"
    replacement.mkdir(mode=0o700)
    replacement.chmod(0o700)
    displaced = tmp_path / "displaced-root"

    def swap_after_checks(_path: Path) -> None:
        root.rename(displaced)
        replacement.rename(root)

    monkeypatch.setattr(ledger, "_require_local_filesystem", swap_after_checks)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_ROOT_MODE_INVALID"):
        ledger.DurablePhaseLedgerStore(root).create(_prepared())
    assert not list(root.glob("gug365-phase-ledger-*.json"))


def test_store_requires_local_filesystem_from_bound_root_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-local-fs-recheck"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    probed_fds: list[int] = []

    def bound_network(descriptor: int) -> None:
        probed_fds.append(descriptor)
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        raise ledger.PhaseLedgerError("LEDGER_FILESYSTEM_NOT_LOCAL")

    monkeypatch.setattr(
        ledger, "_require_local_filesystem_fd", bound_network
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_FILESYSTEM_NOT_LOCAL"
    ):
        ledger.DurablePhaseLedgerStore(root).create(_prepared())
    assert len(probed_fds) == 1
    assert not list(root.glob("gug365-phase-ledger-*.json"))


def test_fd_native_filesystem_and_cloud_checks_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-fd-native"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
        monkeypatch.setattr(ledger.sys, "platform", "linux")
        monkeypatch.setattr(
            "builtins.open",
            lambda *_args, **_kwargs: io.StringIO(
                f"36 25 {device} / / rw - ext4 /dev/sda rw\n"
            ),
        )
        ledger._require_local_filesystem_fd(descriptor)  # noqa: SLF001

        monkeypatch.setattr(
            "builtins.open",
            lambda *_args, **_kwargs: io.StringIO(
                f"36 25 {device} / / rw - nfs server:/share rw\n"
            ),
        )
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILESYSTEM_NOT_LOCAL"
        ):
            ledger._require_local_filesystem_fd(descriptor)  # noqa: SLF001

        monkeypatch.setattr(
            "builtins.open", lambda *_args, **_kwargs: io.StringIO("malformed\n")
        )
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILESYSTEM_STATUS_UNVERIFIED"
        ):
            ledger._require_local_filesystem_fd(descriptor)  # noqa: SLF001
    finally:
        os.close(descriptor)

    monkeypatch.undo()
    inspected: list[int] = []

    def cloud_marker(fd: int) -> list[str]:
        inspected.append(fd)
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
        return ["com.apple.fileprovider.root"]

    monkeypatch.setattr(ledger, "_fd_xattrs", cloud_marker)
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_ROOT_CLOUD_MANAGED_FORBIDDEN"
    ):
        ledger.DurablePhaseLedgerStore(root).create(_prepared())
    assert inspected


def test_store_rejection_paths_do_not_leak_root_data_or_lease_fds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fd_directory = Path("/dev/fd" if sys.platform == "darwin" else "/proc/self/fd")

    def count_fds() -> int:
        return len(list(fd_directory.iterdir()))

    root = tmp_path / "private-fd-balance"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    baseline = count_fds()

    def reject_filesystem(_descriptor: int) -> None:
        raise ledger.PhaseLedgerError("LEDGER_FILESYSTEM_NOT_LOCAL")

    monkeypatch.setattr(ledger, "_require_local_filesystem_fd", reject_filesystem)
    for _ in range(50):
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILESYSTEM_NOT_LOCAL"
        ):
            store.create(prepared)
    assert count_fds() == baseline

    monkeypatch.undo()
    store.create(prepared)
    baseline = count_fds()
    original_acl = ledger._reject_fd_acl  # noqa: SLF001

    def reject_regular(descriptor: int, code: str) -> None:
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ledger.PhaseLedgerError(code)
        original_acl(descriptor, code)

    monkeypatch.setattr(ledger, "_reject_fd_acl", reject_regular)
    for operation in (
        lambda: store.read(prepared["ledger_id"]),
        lambda: store.execution_lease(prepared["ledger_id"]).__enter__(),
    ):
        for _ in range(50):
            with pytest.raises(
                ledger.PhaseLedgerError, match="LEDGER_FILE_ACL_FORBIDDEN"
            ):
                operation()
        assert count_fds() == baseline


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin ACL regression")
def test_store_rejects_nontrivial_and_inherited_darwin_acls(
    tmp_path: Path,
) -> None:
    prepared = _prepared()
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(root)],
        check=True,
        timeout=5,
    )
    try:
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_ROOT_ACL_FORBIDDEN"
        ):
            ledger.DurablePhaseLedgerStore(root).create(prepared)
    finally:
        subprocess.run(["/bin/chmod", "-N", str(root)], check=True, timeout=5)

    inherited_root = tmp_path / "inherited-private"
    inherited_root.mkdir(mode=0o700)
    inherited_root.chmod(0o700)
    inherited_store = ledger.DurablePhaseLedgerStore(inherited_root)
    inherited_data = inherited_root / inherited_store._name(  # noqa: SLF001
        prepared["ledger_id"]
    )
    subprocess.run(
        [
            "/bin/chmod",
            "+a",
            "everyone allow read,file_inherit",
            str(inherited_root),
        ],
        check=True,
        timeout=5,
    )
    inherited_data.write_bytes(ledger._record_bytes(prepared))  # noqa: SLF001
    inherited_data.chmod(0o600)
    subprocess.run(
        ["/bin/chmod", "-N", str(inherited_root)], check=True, timeout=5
    )
    try:
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILE_ACL_FORBIDDEN"
        ):
            inherited_store.read(prepared["ledger_id"])
    finally:
        subprocess.run(
            ["/bin/chmod", "-N", str(inherited_data)], check=True, timeout=5
        )

    store = ledger.DurablePhaseLedgerStore(root)
    store.create(prepared)
    data = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(data)],
        check=True,
        timeout=5,
    )
    try:
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILE_ACL_FORBIDDEN"
        ):
            store.read(prepared["ledger_id"])
    finally:
        subprocess.run(["/bin/chmod", "-N", str(data)], check=True, timeout=5)

    lease = root / store._lock_name(prepared["ledger_id"])  # noqa: SLF001
    subprocess.run(
        ["/bin/chmod", "+a", "everyone allow read", str(lease)],
        check=True,
        timeout=5,
    )
    try:
        with pytest.raises(
            ledger.PhaseLedgerError, match="LEDGER_FILE_ACL_FORBIDDEN"
        ):
            store.compare_and_swap(_claimed(prepared))
    finally:
        subprocess.run(["/bin/chmod", "-N", str(lease)], check=True, timeout=5)


def test_store_rejects_network_or_non_durable_filesystem_and_cloud_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)

    def network_mount(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["/sbin/mount"],
            0,
            stdout=f"server:/share on {tmp_path} (nfs, local)\n",
            stderr="",
        )

    monkeypatch.setattr(ledger.sys, "platform", "darwin")
    monkeypatch.setattr(ledger.subprocess, "run", network_mount)
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_FILESYSTEM_NOT_LOCAL"
    ):
        ledger._require_local_filesystem(root)  # noqa: SLF001

    monkeypatch.setattr(ledger.os, "listxattr", None, raising=False)

    def marked_ancestor(
        command: Sequence[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        candidate = Path(command[-1])
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=(
                "com.apple.fileprovider.root\n"
                if candidate == tmp_path
                else ""
            ),
            stderr="",
        )

    monkeypatch.setattr(ledger.subprocess, "run", marked_ancestor)
    with pytest.raises(
        ledger.PhaseLedgerError, match="LEDGER_ROOT_CLOUD_MANAGED_FORBIDDEN"
    ):
        ledger._reject_cloud_xattrs(root)  # noqa: SLF001


def test_stable_lease_serializes_cas_across_data_inode_replacements(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    store.create(prepared)
    data = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    first_inode = data.stat().st_ino
    with store.execution_lease(prepared["ledger_id"]) as lease_descriptor:
        claimed = store._compare_and_swap_under_lease(  # noqa: SLF001
            _claimed(prepared), lease_descriptor
        )
        second_inode = data.stat().st_ino
        assert second_inode != first_inode
        in_flight = store._compare_and_swap_under_lease(  # noqa: SLF001
            ledger.prepare_operation_in_flight(
                claimed,
                expected_version=claimed["ledger_version"],
                expected_digest=claimed["ledger_digest"],
                at=NOW + timedelta(seconds=2),
                operation_sequence=1,
            ),
            lease_descriptor,
        )
        assert data.stat().st_ino != second_inode
        assert in_flight["status"] == "IN_FLIGHT"


def test_recovery_cannot_overtake_live_callback_then_recovers_after_crash(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    entered = multiprocessing.Event()
    release = multiprocessing.Event()
    queue: multiprocessing.Queue[str] = multiprocessing.Queue()
    worker = multiprocessing.Process(
        target=_blocking_runner_worker,
        args=(
            str(store.root),
            plan,
            prepared["ledger_id"],
            _authorization(prepared),
            entered,
            release,
            queue,
        ),
    )
    worker.start()
    assert entered.wait(10)
    assert store.read(prepared["ledger_id"])["status"] == "IN_FLIGHT"
    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_ACTIVE"):
        ledger.recover_persisted_in_flight(
            store=store,
            ledger_id=prepared["ledger_id"],
            at=NOW + timedelta(seconds=3),
        )
    worker.terminate()
    worker.join(10)
    assert not worker.is_alive()
    recovered = ledger.recover_persisted_in_flight(
        store=store,
        ledger_id=prepared["ledger_id"],
        at=NOW + timedelta(seconds=3),
    )
    assert recovered["status"] == "AMBIGUOUS"


@pytest.mark.parametrize("target", ["data", "lease"])
@pytest.mark.parametrize("violation", ["hardlink", "symlink", "mode"])
def test_store_rejects_data_and_lease_link_or_mode_tampering(
    tmp_path: Path, target: str, violation: str
) -> None:
    root = tmp_path / f"private-{target}-{violation}"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    store.create(prepared)
    path = root / (
        store._name(prepared["ledger_id"])  # noqa: SLF001
        if target == "data"
        else store._lock_name(prepared["ledger_id"])  # noqa: SLF001
    )
    if violation == "hardlink":
        os.link(path, tmp_path / f"alias-{target}")
    elif violation == "symlink":
        replacement = tmp_path / f"replacement-{target}"
        replacement.write_text("synthetic", encoding="utf-8")
        replacement.chmod(0o600)
        path.unlink()
        path.symlink_to(replacement)
    else:
        path.chmod(0o640)
    with pytest.raises(ledger.PhaseLedgerError):
        if target == "data":
            store.read(prepared["ledger_id"])
        else:
            store.compare_and_swap(_claimed(prepared))


def test_store_snapshots_mutable_create_and_cas_inputs(tmp_path: Path) -> None:
    class MutatingRecord(dict[str, Any]):
        def items(self) -> Any:
            snapshot = copy.deepcopy(list(super().items()))
            self["ordered_request_digests"][0] = DIGESTS[7]
            return iter(snapshot)

    root = tmp_path / "private-snapshot"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    expected_prepared = copy.deepcopy(prepared)
    moving_prepared = MutatingRecord(copy.deepcopy(prepared))
    store.create(moving_prepared)
    assert moving_prepared["ordered_request_digests"][0] == DIGESTS[7]
    assert store.read(prepared["ledger_id"]) == expected_prepared

    claimed = _claimed(prepared).proposed_record
    expected_claimed = copy.deepcopy(claimed)
    moving_claimed = MutatingRecord(copy.deepcopy(claimed))
    result = store.compare_and_swap(
        ledger.CasTransition(
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            proposed_record=moving_claimed,
        )
    )
    assert moving_claimed["ordered_request_digests"][0] == DIGESTS[7]
    assert result == expected_claimed
    result["claim"]["next_operation_sequence"] = 99
    assert store.read(prepared["ledger_id"])["claim"][
        "next_operation_sequence"
    ] == 1


def test_store_interrupted_initial_write_and_orphan_lease_are_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-interrupted-create"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    original_write = ledger._write_all  # noqa: SLF001

    def interrupted(descriptor: int, payload: bytes) -> None:
        os.write(descriptor, payload[:31])
        raise RuntimeError("synthetic interrupted staged write")

    monkeypatch.setattr(ledger, "_write_all", interrupted)
    with pytest.raises(RuntimeError, match="synthetic interrupted"):
        store.create(prepared)
    final_path = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    lease_path = root / store._lock_name(prepared["ledger_id"])  # noqa: SLF001
    assert final_path.exists() is False
    assert lease_path.exists() is True
    assert not list(root.glob(".gug365-ledger-*.tmp"))

    monkeypatch.setattr(ledger, "_write_all", original_write)
    store.create(prepared)
    assert store.read(prepared["ledger_id"]) == prepared

    orphan_root = tmp_path / "private-orphan-lease"
    orphan_root.mkdir(mode=0o700)
    orphan_root.chmod(0o700)
    orphan_store = ledger.DurablePhaseLedgerStore(orphan_root)
    orphan_prepared = _prepared()
    orphan_lease = orphan_root / orphan_store._lock_name(  # noqa: SLF001
        orphan_prepared["ledger_id"]
    )
    orphan_lease.touch(mode=0o600)
    orphan_lease.chmod(0o600)
    orphan_store.create(orphan_prepared)
    assert orphan_store.read(orphan_prepared["ledger_id"]) == orphan_prepared


def test_store_recovers_publish_before_pending_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-publish-recovery"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    pending_name = store._pending_name(prepared["ledger_id"])  # noqa: SLF001
    original_unlink = ledger.os.unlink
    pending_unlinks = 0

    def interrupted_unlink(path: str, *args: Any, **kwargs: Any) -> None:
        nonlocal pending_unlinks
        if path == pending_name:
            pending_unlinks += 1
            if pending_unlinks >= 2:
                raise RuntimeError("synthetic crash after publish")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(ledger.os, "unlink", interrupted_unlink)
    with pytest.raises(RuntimeError, match="synthetic crash after publish"):
        store.create(prepared)
    final_path = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    pending_path = root / pending_name
    assert final_path.exists() and pending_path.exists()
    final_stat = final_path.stat()
    pending_stat = pending_path.stat()
    assert (final_stat.st_dev, final_stat.st_ino) == (
        pending_stat.st_dev,
        pending_stat.st_ino,
    )

    monkeypatch.setattr(ledger.os, "unlink", original_unlink)
    store.create(prepared)
    assert final_path.exists() and not pending_path.exists()
    assert store.read(prepared["ledger_id"]) == prepared


def test_store_preserves_pending_marker_after_post_link_sync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-post-link-failure"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    original_sync = ledger._durable_sync  # noqa: SLF001
    original_link = ledger.os.link
    linked = False

    def traced_link(*args: Any, **kwargs: Any) -> None:
        nonlocal linked
        original_link(*args, **kwargs)
        linked = True

    def fail_first_post_link_sync(descriptor: int) -> None:
        if linked and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ledger.PhaseLedgerError("DURABLE_SYNC_FAILED")
        original_sync(descriptor)

    monkeypatch.setattr(ledger.os, "link", traced_link)
    monkeypatch.setattr(ledger, "_durable_sync", fail_first_post_link_sync)
    with pytest.raises(ledger.PhaseLedgerError, match="DURABLE_SYNC_FAILED"):
        store.create(prepared)
    final_path = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    pending_path = root / store._pending_name(prepared["ledger_id"])  # noqa: SLF001
    assert final_path.exists() and pending_path.exists()
    assert (final_path.stat().st_dev, final_path.stat().st_ino) == (
        pending_path.stat().st_dev,
        pending_path.stat().st_ino,
    )

    monkeypatch.setattr(ledger, "_durable_sync", original_sync)
    store.create(prepared)
    assert final_path.exists() and not pending_path.exists()
    assert store.read(prepared["ledger_id"]) == prepared


def test_failed_recovery_never_deletes_preexisting_pending_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-recovery-marker-custody"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    original_sync = ledger._durable_sync  # noqa: SLF001
    original_link = ledger.os.link
    linked = False

    def traced_link(*args: Any, **kwargs: Any) -> None:
        nonlocal linked
        original_link(*args, **kwargs)
        linked = True

    def fail_post_link(descriptor: int) -> None:
        if linked and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ledger.PhaseLedgerError("DURABLE_SYNC_FAILED")
        original_sync(descriptor)

    monkeypatch.setattr(ledger.os, "link", traced_link)
    monkeypatch.setattr(ledger, "_durable_sync", fail_post_link)
    with pytest.raises(ledger.PhaseLedgerError, match="DURABLE_SYNC_FAILED"):
        store.create(prepared)
    final_path = root / store._name(prepared["ledger_id"])  # noqa: SLF001
    pending_path = root / store._pending_name(prepared["ledger_id"])  # noqa: SLF001
    assert final_path.exists() and pending_path.exists()

    monkeypatch.setattr(ledger.os, "link", original_link)
    monkeypatch.setattr(ledger, "_durable_sync", original_sync)
    original_read = ledger._read_record  # noqa: SLF001

    def fail_recovery_read(_descriptor: int) -> dict[str, Any]:
        raise ledger.PhaseLedgerError("SYNTHETIC_RECOVERY_READ_FAILURE")

    monkeypatch.setattr(ledger, "_read_record", fail_recovery_read)
    with pytest.raises(
        ledger.PhaseLedgerError, match="SYNTHETIC_RECOVERY_READ_FAILURE"
    ):
        store.create(prepared)
    assert final_path.exists() and pending_path.exists()
    assert (final_path.stat().st_dev, final_path.stat().st_ino) == (
        pending_path.stat().st_dev,
        pending_path.stat().st_ino,
    )

    monkeypatch.setattr(ledger, "_read_record", original_read)
    store.create(prepared)
    assert final_path.exists() and not pending_path.exists()
    assert store.read(prepared["ledger_id"]) == prepared


@pytest.mark.parametrize("transition_kind", ["create", "cas"])
def test_store_rebinds_staged_fd_to_path_before_publish_or_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, transition_kind: str
) -> None:
    root = tmp_path / f"private-stage-swap-{transition_kind}"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    if transition_kind == "cas":
        store.create(prepared)
    original_verify = ledger._verify_open_file_binding  # noqa: SLF001
    swapped = False

    def swap_then_verify(
        root_fd: int,
        name: str,
        descriptor: int,
        *,
        expected_link_count: int,
    ) -> None:
        nonlocal swapped
        is_target = (
            transition_kind == "create"
            and name.endswith(".pending")
            or transition_kind == "cas"
            and name.endswith(".tmp")
        )
        if is_target and not swapped:
            swapped = True
            displaced = f"{name}.displaced"
            os.rename(name, displaced, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            replacement = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | ledger._required_nofollow(),  # noqa: SLF001
                0o600,
                dir_fd=root_fd,
            )
            os.close(replacement)
        original_verify(
            root_fd,
            name,
            descriptor,
            expected_link_count=expected_link_count,
        )

    monkeypatch.setattr(ledger, "_verify_open_file_binding", swap_then_verify)
    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_FILE_CHANGED"):
        if transition_kind == "create":
            store.create(prepared)
        else:
            store.compare_and_swap(_claimed(prepared))
    assert swapped is True
    if transition_kind == "create":
        assert not (root / store._name(prepared["ledger_id"])).exists()  # noqa: SLF001
    else:
        assert store.read(prepared["ledger_id"]) == prepared


def test_darwin_fullfsync_is_required_and_failure_blocks_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-fullfsync"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    calls: list[tuple[int, int]] = []

    def traced_fcntl(descriptor: int, operation: int, *args: Any) -> int:
        if operation == ledger._DARWIN_F_FULLFSYNC:  # noqa: SLF001
            calls.append((descriptor, operation))
            return 0
        return fcntl.fcntl(descriptor, operation, *args)

    monkeypatch.setattr(ledger.sys, "platform", "darwin")
    monkeypatch.setattr(ledger.fcntl, "fcntl", traced_fcntl)
    monkeypatch.setattr(ledger, "_reject_cloud_xattrs", lambda _path: None)
    monkeypatch.setattr(ledger, "_reject_extended_acl", lambda _path, _code: None)
    monkeypatch.setattr(ledger, "_reject_fd_cloud_xattrs", lambda _fd: None)
    monkeypatch.setattr(ledger, "_reject_fd_acl", lambda _fd, _code: None)
    monkeypatch.setattr(ledger, "_require_local_filesystem", lambda _path: None)
    monkeypatch.setattr(ledger, "_require_local_filesystem_fd", lambda _fd: None)
    store.create(prepared)
    assert len(calls) >= 4

    failing_root = tmp_path / "private-fullfsync-failure"
    failing_root.mkdir(mode=0o700)
    failing_root.chmod(0o700)
    failing_store = ledger.DurablePhaseLedgerStore(failing_root)
    failing_prepared = _prepared()

    def failed_fullsync(
        descriptor: int, operation: int, *args: Any
    ) -> int:
        if operation == ledger._DARWIN_F_FULLFSYNC:  # noqa: SLF001
            raise OSError("synthetic media barrier failure")
        return fcntl.fcntl(descriptor, operation, *args)

    monkeypatch.setattr(ledger.fcntl, "fcntl", failed_fullsync)
    with pytest.raises(ledger.PhaseLedgerError, match="DURABLE_SYNC_FAILED"):
        failing_store.create(failing_prepared)
    assert not (
        failing_root / failing_store._name(failing_prepared["ledger_id"])  # noqa: SLF001
    ).exists()


def test_create_durably_orders_lease_and_pending_before_final_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-create-ordering"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    events: list[str] = []
    original_sync = ledger._durable_sync  # noqa: SLF001
    original_link = ledger.os.link

    def traced_sync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        events.append("DIR_SYNC" if stat.S_ISDIR(metadata.st_mode) else "FILE_SYNC")
        original_sync(descriptor)

    def traced_link(*args: Any, **kwargs: Any) -> None:
        events.append("FINAL_LINK")
        original_link(*args, **kwargs)

    monkeypatch.setattr(ledger, "_durable_sync", traced_sync)
    monkeypatch.setattr(ledger.os, "link", traced_link)
    store.create(prepared)
    link_index = events.index("FINAL_LINK")
    before_link = events[:link_index]
    assert before_link.count("FILE_SYNC") >= 2
    assert before_link.count("DIR_SYNC") >= 2
    assert before_link.index("DIR_SYNC") > before_link.index("FILE_SYNC")
    second_file = [index for index, event in enumerate(before_link) if event == "FILE_SYNC"][1]
    assert any(event == "DIR_SYNC" for event in before_link[second_file + 1 :])
    assert "DIR_SYNC" in events[link_index + 1 :]


def test_cas_durably_orders_staged_entry_before_atomic_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-cas-ordering"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    prepared = _prepared()
    store.create(prepared)
    events: list[str] = []
    original_sync = ledger._durable_sync  # noqa: SLF001
    original_replace = ledger.os.replace

    def traced_sync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        events.append("DIR_SYNC" if stat.S_ISDIR(metadata.st_mode) else "FILE_SYNC")
        original_sync(descriptor)

    def traced_replace(*args: Any, **kwargs: Any) -> None:
        events.append("REPLACE")
        original_replace(*args, **kwargs)

    monkeypatch.setattr(ledger, "_durable_sync", traced_sync)
    monkeypatch.setattr(ledger.os, "replace", traced_replace)
    store.compare_and_swap(_claimed(prepared))

    replace_index = events.index("REPLACE")
    assert events[replace_index - 2 : replace_index] == ["FILE_SYNC", "DIR_SYNC"]
    assert events[replace_index + 1] == "DIR_SYNC"


def _claimed_store(tmp_path: Path) -> tuple[
    ledger.DurablePhaseLedgerStore, dict[str, Any], dict[str, Any]
]:
    plan = _plan()
    prepared = _prepared(plan)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(prepared)
    store.compare_and_swap(_claimed(prepared))
    return store, plan, prepared


def test_runner_executes_exact_order_once_and_persists_each_result(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls: list[int] = []

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        calls.append(operation["sequence"])
        assert operation["attempt_limit"] == 1
        assert operation["retry_permitted"] is False
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: NOW + timedelta(seconds=2),
        invoke_once=invoke,
    )
    assert calls == [1, 2]
    assert result["status"] == "CONSUMED"
    assert result["ledger_version"] == 6
    assert result["ledger_version"] == 1 + len(result["receipt_chain"])


def test_runner_clock_rollback_before_claim_or_previous_outcome_never_invokes(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls: list[int] = []

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        calls.append(operation["sequence"])
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError, match="OPERATION_IN_FLIGHT_TIME_NOT_MONOTONIC"
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
                executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
                authority_evaluation_at=NOW,
                **_predecessor_security(None, None),
                clock=lambda: NOW,
            invoke_once=invoke,
        )
    assert calls == []
    assert store.read(prepared["ledger_id"])["status"] == "CLAIMED"

    rollback_root = tmp_path / "private-rollback-second"
    rollback_root.mkdir(mode=0o700)
    rollback_root.chmod(0o700)
    rollback_store = ledger.DurablePhaseLedgerStore(rollback_root)
    rollback_prepared = _prepared(plan)
    rollback_store.create(rollback_prepared)
    rollback_store.compare_and_swap(_claimed(rollback_prepared, plan))
    times = iter(
        [
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=2),
        ]
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="OPERATION_IN_FLIGHT_TIME_NOT_MONOTONIC"
    ):
        ledger.execute_claimed_phase(
            store=rollback_store,
            plan=plan,
            ledger_id=rollback_prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(rollback_prepared),
                executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
                authority_evaluation_at=NOW,
                **_predecessor_security(None, None),
                clock=lambda: next(times),
            invoke_once=invoke,
        )
    assert calls == [1]
    stored = rollback_store.read(rollback_prepared["ledger_id"])
    assert stored["status"] == "CLAIMED"
    assert len(stored["operation_outcomes"]) == 1


def test_runner_expiry_between_operations_invokes_no_next_callback(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls: list[int] = []
    times = iter(
        [
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(minutes=10),
        ]
    )

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        calls.append(operation["sequence"])
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_LEDGER_EXPIRED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: next(times),
            invoke_once=invoke,
        )
    assert calls == [1]
    stored = store.read(prepared["ledger_id"])
    assert stored["status"] == "CLAIMED"
    assert stored["claim"]["next_operation_sequence"] == 2


def test_runner_crossing_expiry_persists_ambiguous_and_stops(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls: list[int] = []
    times = iter(
        [
            NOW + timedelta(minutes=9, seconds=58),
            NOW + timedelta(minutes=9, seconds=59),
            NOW + timedelta(minutes=10),
        ]
    )

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        calls.append(operation["sequence"])
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: next(times),
        invoke_once=invoke,
    )
    assert calls == [1]
    assert result["status"] == "AMBIGUOUS"
    assert result["operation_outcomes"] == [
        {
            "operation_sequence": 1,
            "request_digest": result["ordered_request_digests"][0],
            "result": "AMBIGUOUS",
            "provider_result_digest": None,
            "recorded_at": "2035-01-02T03:14:05Z",
            "write_attempt_count": 1,
            "blind_retry_permitted": False,
            "next_required_action": "RECONCILE_READ_ONLY",
        }
    ]
    assert store.read(prepared["ledger_id"])["status"] == "AMBIGUOUS"


def test_runner_crossing_expiry_during_in_flight_cas_invokes_zero_callbacks(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    callbacks = 0
    times = iter(
        [
            NOW + timedelta(minutes=9, seconds=59),
            NOW + timedelta(minutes=10),
        ]
    )

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal callbacks
        callbacks += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: next(times),
        invoke_once=invoke,
    )
    assert callbacks == 0
    assert result["status"] == "AMBIGUOUS"
    assert result["operation_outcomes"][-1]["result"] == "AMBIGUOUS"
    assert store.read(prepared["ledger_id"])["status"] == "AMBIGUOUS"


def test_runner_crossing_authority_session_expiry_persists_ambiguous(
    tmp_path: Path,
) -> None:
    plan = _plan()
    evidence = _evidence(plan, "POLICY_FACTORY")
    evidence["session_expires_at"] = (NOW + timedelta(seconds=600)).isoformat().replace(
        "+00:00", "Z"
    )
    evidence["session_lifetime_seconds"] = 660
    evidence["session_remaining_seconds"] = 600
    evidence["evidence_digest"] = ledger.canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    prepared = ledger.build_prepared_ledger(
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        phase="POLICY_FACTORY",
        profile_class="GUG365PolicyFactory",
        caller_arn_digest=DIGESTS[0],
        executor_authority_evidence_digest=evidence["evidence_digest"],
        executor_authority_evidence=evidence,
        authority_evaluation_at=NOW,
        authority_session_identifier_digest=DIGESTS[7],
        authority_session_issued_at=NOW - timedelta(seconds=60),
        authority_session_expires_at=NOW + timedelta(seconds=600),
        authority_evidence_collected_at=NOW - timedelta(seconds=30),
        host_digest=DIGESTS[2],
        predecessor_phase=None,
        predecessor_terminal_receipt_digest=None,
        predecessor_ledger_digest=None,
        before_state_digest=INITIAL_ABSENCE_DIGEST,
        required_predecessor_checkpoint_digest=INITIAL_ABSENCE_DIGEST,
        **_predecessor_security(None, None),
        not_before=NOW,
        expires_at=NOW + timedelta(seconds=600),
    )
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(prepared)
    claimed = ledger.prepare_claim(
        prepared,
        expected_version=prepared["ledger_version"],
        expected_digest=prepared["ledger_digest"],
        at=NOW + timedelta(seconds=1),
        claim_nonce_digest=DIGESTS[3],
        profile_class=prepared["profile_class"],
        caller_arn_digest=prepared["caller_arn_digest"],
        executor_authority_evidence_digest=prepared[
            "executor_authority_evidence_digest"
        ],
        host_digest=prepared["host_digest"],
        execution_authorization=_authorization(prepared),
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        executor_authority_evidence=evidence,
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
    )
    store.compare_and_swap(claimed)
    times = iter(
        [
            NOW + timedelta(seconds=598),
            NOW + timedelta(seconds=599),
            NOW + timedelta(seconds=600),
        ]
    )
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=evidence,
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: next(times),
        invoke_once=invoke,
    )
    assert calls == 1
    assert result["status"] == "AMBIGUOUS"
    assert result["operation_outcomes"][-1]["result"] == "AMBIGUOUS"


def test_runner_ambiguous_stops_all_future_callbacks(tmp_path: Path) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls: list[int] = []

    def invoke(operation: Mapping[str, Any]) -> ledger.OperationResult:
        calls.append(operation["sequence"])
        return ledger.OperationResult("AMBIGUOUS", None)

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: NOW + timedelta(seconds=2),
        invoke_once=invoke,
    )
    assert calls == [1]
    assert result["status"] == "AMBIGUOUS"
    assert result["operation_outcomes"][-1]["next_required_action"] == (
        "RECONCILE_READ_ONLY"
    )


def test_mid_phase_ambiguous_reconcile_never_certifies_complete() -> None:
    plan = _plan()
    prepared = _prepared(plan)
    claimed = _claimed(prepared).proposed_record
    in_flight = _in_flight(claimed)
    ambiguous = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record
    reconciled = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        observed_state_digest=DIGESTS[5],
        classification="EFFECT_PROVEN",
    ).proposed_record
    binding = ledger.phase_binding_from_plan(
        plan,
        phase="POLICY_FACTORY",
        expected_plan_digest=plan["plan_digest"],
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="CAUSAL_LEDGER_RECORD_NOT_ACCEPTED"
    ):
        ledger.validate_consumed_causal_record(
            reconciled,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=binding["bundle_digest"],
            expected_phase="POLICY_FACTORY",
            expected_ledger_id=prepared["ledger_id"],
            expected_initial_ledger_digest=prepared["initial_ledger_digest"],
            expected_claim_nonce_digest=DIGESTS[3],
            expected_terminal_receipt_digest=reconciled["receipt_chain"][-1][
                "receipt_digest"
            ],
        )


def test_final_ambiguous_reconcile_without_independent_evidence_never_certifies() -> None:
    plan = _plan()
    prepared = _prepared(plan)
    claimed = _claimed(prepared, plan).proposed_record
    first_in_flight = _in_flight(claimed)
    first = ledger.prepare_operation_record(
        first_in_flight,
        expected_version=first_in_flight["ledger_version"],
        expected_digest=first_in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        operation_sequence=1,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[4],
    ).proposed_record
    final_in_flight = ledger.prepare_operation_in_flight(
        first,
        expected_version=first["ledger_version"],
        expected_digest=first["ledger_digest"],
        at=NOW + timedelta(seconds=4),
        operation_sequence=2,
    ).proposed_record
    ambiguous = ledger.prepare_operation_record(
        final_in_flight,
        expected_version=final_in_flight["ledger_version"],
        expected_digest=final_in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=5),
        operation_sequence=2,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record
    reconciled = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=6),
        observed_state_digest=DIGESTS[5],
        classification="EFFECT_PROVEN",
    ).proposed_record
    binding = ledger.phase_binding_from_plan(
        plan,
        phase="POLICY_FACTORY",
        expected_plan_digest=plan["plan_digest"],
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="CAUSAL_LEDGER_RECORD_NOT_ACCEPTED"
    ):
        ledger.validate_consumed_causal_record(
            reconciled,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=binding["bundle_digest"],
            expected_phase="POLICY_FACTORY",
            expected_ledger_id=prepared["ledger_id"],
            expected_initial_ledger_digest=prepared["initial_ledger_digest"],
            expected_claim_nonce_digest=DIGESTS[3],
            expected_terminal_receipt_digest=reconciled["receipt_chain"][-1][
                "receipt_digest"
            ],
        )


def test_receipt_event_source_version_or_facts_tampering_is_rejected() -> None:
    claimed = _claimed(_prepared()).proposed_record
    for field, value in (
        ("event", "CONSUMED"),
        ("source_ledger_version", 99),
        ("facts", {"attempt": 1}),
    ):
        tampered = copy.deepcopy(claimed)
        tampered["receipt_chain"][0][field] = value
        tampered["receipt_chain"][0]["receipt_digest"] = ledger.canonical_digest(
            {
                key: item
                for key, item in tampered["receipt_chain"][0].items()
                if key != "receipt_digest"
            }
        )
        tampered["ledger_digest"] = ledger.canonical_digest(
            {key: item for key, item in tampered.items() if key != "ledger_digest"}
        )
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_ledger(tampered)


def test_receipt_replay_rejects_swapped_interleaving_or_forged_source_digest() -> None:
    claimed = _claimed(_prepared()).proposed_record
    in_flight = _in_flight(claimed)
    successful = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[4],
    ).proposed_record
    forged_source = copy.deepcopy(successful)
    forged_source["receipt_chain"][1]["source_ledger_digest"] = DIGESTS[7]
    _reseal_receipts_and_ledger(forged_source)
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECEIPT_CAUSAL_SOURCE_MISMATCH"
    ):
        ledger.validate_ledger(forged_source)

    swapped = copy.deepcopy(successful)
    swapped["receipt_chain"][1], swapped["receipt_chain"][2] = (
        swapped["receipt_chain"][2],
        swapped["receipt_chain"][1],
    )
    for sequence, receipt in enumerate(swapped["receipt_chain"], 1):
        receipt["sequence"] = sequence
        receipt["source_ledger_version"] = sequence
    _reseal_receipts_and_ledger(swapped)
    with pytest.raises(ledger.PhaseLedgerError):
        ledger.validate_ledger(swapped)


def test_transition_times_are_monotonic_and_window_bound() -> None:
    prepared = _prepared()
    claimed = _claimed(prepared).proposed_record
    with pytest.raises(
        ledger.PhaseLedgerError, match="OPERATION_IN_FLIGHT_TIME_NOT_MONOTONIC"
    ):
        ledger.prepare_operation_in_flight(
            claimed,
            expected_version=claimed["ledger_version"],
            expected_digest=claimed["ledger_digest"],
            at=NOW,
            operation_sequence=1,
        )
    in_flight = _in_flight(claimed)
    with pytest.raises(
        ledger.PhaseLedgerError, match="OPERATION_OUTCOME_TIME_NOT_MONOTONIC"
    ):
        ledger.prepare_operation_record(
            in_flight,
            expected_version=in_flight["ledger_version"],
            expected_digest=in_flight["ledger_digest"],
            at=NOW,
            operation_sequence=1,
            outcome="SUCCEEDED",
            provider_result_digest=DIGESTS[4],
        )
    ambiguous = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record
    with pytest.raises(
        ledger.PhaseLedgerError, match="RECONCILIATION_TIME_NOT_MONOTONIC"
    ):
        ledger.prepare_read_only_reconciliation(
            ambiguous,
            expected_version=ambiguous["ledger_version"],
            expected_digest=ambiguous["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            observed_state_digest=DIGESTS[5],
            classification="EFFECT_PROVEN",
        )


def test_callback_exception_persists_ambiguous_and_never_reinvokes(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        raise TimeoutError

    result = ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=prepared["ledger_id"],
        expected_plan_digest=plan["plan_digest"],
        execution_authorization=_authorization(prepared),
        executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
        authority_evaluation_at=NOW,
        **_predecessor_security(None, None),
        clock=lambda: NOW + timedelta(seconds=2),
        invoke_once=invoke,
    )
    assert calls == 1
    assert result["status"] == "AMBIGUOUS"
    assert store.read(prepared["ledger_id"])["status"] == "AMBIGUOUS"
    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_LEDGER_NOT_CLAIMED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=3),
            invoke_once=invoke,
        )
    assert calls == 1


def test_callback_clock_rollback_leaves_in_flight_until_explicit_recovery(
    tmp_path: Path,
) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    calls = 0
    times = iter(
        [
            NOW + timedelta(seconds=2),
            NOW + timedelta(seconds=3),
            NOW + timedelta(seconds=2, milliseconds=500),
        ]
    )

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_TIME_ROLLBACK"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: next(times),
            invoke_once=invoke,
        )
    assert calls == 1
    assert store.read(prepared["ledger_id"])["status"] == "IN_FLIGHT"

    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_LEDGER_NOT_CLAIMED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=4),
            invoke_once=invoke,
        )
    assert calls == 1
    recovered = ledger.recover_persisted_in_flight(
        store=store,
        ledger_id=prepared["ledger_id"],
        at=NOW + timedelta(seconds=4),
    )
    assert recovered["status"] == "AMBIGUOUS"


def test_preexisting_in_flight_recovery_invokes_zero_callbacks(tmp_path: Path) -> None:
    store, plan, prepared = _claimed_store(tmp_path)
    claimed = store.read(prepared["ledger_id"])
    store.compare_and_swap(
        ledger.prepare_operation_in_flight(
            claimed,
            expected_version=claimed["ledger_version"],
            expected_digest=claimed["ledger_digest"],
            at=NOW + timedelta(seconds=2),
            operation_sequence=1,
        )
    )
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_LEDGER_NOT_CLAIMED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=plan,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=plan["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(plan, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=3),
            invoke_once=invoke,
        )
    assert calls == 0
    recovered = ledger.recover_persisted_in_flight(
        store=store,
        ledger_id=prepared["ledger_id"],
        at=NOW + timedelta(seconds=3),
    )
    assert recovered["status"] == "AMBIGUOUS"


def test_two_runners_only_cas_winner_may_invoke(tmp_path: Path) -> None:
    store, _plan_value, prepared = _claimed_store(tmp_path)
    claimed = store.read(prepared["ledger_id"])
    transition = ledger.prepare_operation_in_flight(
        claimed,
        expected_version=claimed["ledger_version"],
        expected_digest=claimed["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
    )
    queue: multiprocessing.Queue[str] = multiprocessing.Queue()
    workers = [
        multiprocessing.Process(
            target=_cas_worker, args=(str(store.root), transition, queue)
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    results = [queue.get(timeout=2) for _ in workers]
    assert results.count("OK") == 1
    assert store.read(prepared["ledger_id"])["status"] == "IN_FLIGHT"


def _reseal_receipts_and_ledger(record: dict[str, Any]) -> None:
    previous: str | None = None
    for receipt in record["receipt_chain"]:
        receipt["previous_receipt_digest"] = previous
        receipt["receipt_digest"] = ledger.canonical_digest(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_digest"
            }
        )
        previous = receipt["receipt_digest"]
    record["ledger_digest"] = ledger.canonical_digest(
        {key: value for key, value in record.items() if key != "ledger_digest"}
    )


def _reseal_identity_receipts_and_ledger(record: dict[str, Any]) -> None:
    record["ledger_id"] = ledger.canonical_digest(
        ledger._immutable_projection(record)  # noqa: SLF001
    )
    record["initial_ledger_digest"] = ledger.canonical_digest(
        ledger._prepared_baseline(record)  # noqa: SLF001
    )
    _reseal_receipts_and_ledger(record)


def test_every_immutable_projection_field_reseal_fails_validation_and_cas(
    tmp_path: Path,
) -> None:
    prepared = _prepared()
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(prepared)
    original = _claimed(prepared)
    mutations: dict[str, Any] = {
        "plan_digest": DIGESTS[7],
        "bundle_digest": DIGESTS[6],
        "account_id": "999999999999",
        "region": "us-west-2",
        "phase": "FOUNDATION_FACTORY",
        "ordered_operations_digest": DIGESTS[5],
        "operation_count": 3,
        "ordered_request_digests": [*prepared["ordered_request_digests"], DIGESTS[4]],
        "profile_class": "DifferentProfileClass",
        "caller_arn_digest": DIGESTS[4],
        "executor_authority_evidence_digest": DIGESTS[5],
        "not_before": "2035-01-02T03:04:04Z",
        "expires_at": "2035-01-02T03:14:04Z",
        "host_digest": DIGESTS[6],
    }
    for field, value in mutations.items():
        proposed = copy.deepcopy(original.proposed_record)
        proposed[field] = value
        proposed["ledger_digest"] = ledger.canonical_digest(
            {key: item for key, item in proposed.items() if key != "ledger_digest"}
        )
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_ledger(proposed)
        transition = ledger.CasTransition(
            expected_version=original.expected_version,
            expected_digest=original.expected_digest,
            proposed_record=proposed,
        )
        with pytest.raises(ledger.PhaseLedgerError):
            store.compare_and_swap(transition)
        assert store.read(prepared["ledger_id"]) == prepared


def test_nested_claim_inflight_outcome_and_reconciliation_reseal_fail() -> None:
    prepared = _prepared()
    claimed = _claimed(prepared).proposed_record
    in_flight = _in_flight(claimed)
    successful = ledger.prepare_operation_record(
        in_flight,
        expected_version=in_flight["ledger_version"],
        expected_digest=in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=2),
        operation_sequence=1,
        outcome="SUCCEEDED",
        provider_result_digest=DIGESTS[4],
    ).proposed_record
    second_in_flight = _in_flight(successful, 2)
    ambiguous = ledger.prepare_operation_record(
        second_in_flight,
        expected_version=second_in_flight["ledger_version"],
        expected_digest=second_in_flight["ledger_digest"],
        at=NOW + timedelta(seconds=3),
        operation_sequence=2,
        outcome="AMBIGUOUS",
        provider_result_digest=None,
    ).proposed_record
    reconciled = ledger.prepare_read_only_reconciliation(
        ambiguous,
        expected_version=ambiguous["ledger_version"],
        expected_digest=ambiguous["ledger_digest"],
        at=NOW + timedelta(seconds=4),
        observed_state_digest=DIGESTS[5],
        classification="EFFECT_PROVEN",
    ).proposed_record

    cases: list[dict[str, Any]] = []
    claim_extra = copy.deepcopy(claimed)
    claim_extra["claim"]["extra"] = True
    cases.append(claim_extra)
    bad_nonce = copy.deepcopy(claimed)
    bad_nonce["claim"]["claim_nonce_digest"] = "x"
    bad_nonce["receipt_chain"][0]["facts"]["claim_nonce_digest"] = "x"
    cases.append(bad_nonce)
    bad_claim_time = copy.deepcopy(claimed)
    bad_claim_time["claim"]["claimed_at"] = "tomorrow"
    bad_claim_time["receipt_chain"][0]["at"] = "tomorrow"
    cases.append(bad_claim_time)
    in_flight_extra = copy.deepcopy(in_flight)
    in_flight_extra["in_flight_operation"]["extra"] = True
    cases.append(in_flight_extra)
    bad_started_at = copy.deepcopy(in_flight)
    bad_started_at["in_flight_operation"]["started_at"] = "tomorrow"
    cases.append(bad_started_at)
    outcome_extra = copy.deepcopy(successful)
    outcome_extra["operation_outcomes"][0]["extra"] = True
    cases.append(outcome_extra)
    bad_provider = copy.deepcopy(successful)
    bad_provider["operation_outcomes"][0]["provider_result_digest"] = "x"
    bad_provider["receipt_chain"][2]["facts"]["provider_result_digest"] = "x"
    cases.append(bad_provider)
    bad_reconciliation = copy.deepcopy(reconciled)
    bad_reconciliation["reconciliation"]["observed_state_digest"] = "x"
    bad_reconciliation["receipt_chain"][-1]["facts"][
        "observed_state_digest"
    ] = "x"
    cases.append(bad_reconciliation)
    reconciliation_extra = copy.deepcopy(reconciled)
    reconciliation_extra["reconciliation"]["extra"] = True
    cases.append(reconciliation_extra)

    for case in cases:
        _reseal_receipts_and_ledger(case)
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_ledger(case)


def test_resealed_plan_not_independently_authorized_never_reaches_callback(
    tmp_path: Path,
) -> None:
    original = _plan()
    malicious = copy.deepcopy(original)
    malicious["authorization_phases"][0]["operations"][1]["request"] = {
        "Synthetic": 999
    }
    malicious["authorization_phases"][0]["operations"][1][
        "request_digest"
    ] = ledger.canonical_digest({"Synthetic": 999})
    malicious["plan_digest"] = ledger.canonical_digest(
        {key: value for key, value in malicious.items() if key != "plan_digest"}
    )
    malicious_evidence = _evidence(malicious, "POLICY_FACTORY")
    with pytest.raises(ledger.PhaseLedgerError, match="PLAN_DIGEST_NOT_AUTHORIZED"):
        ledger.build_prepared_ledger(
            plan=malicious,
            expected_plan_digest=original["plan_digest"],
            phase="POLICY_FACTORY",
            profile_class="GUG365PolicyFactory",
            caller_arn_digest=DIGESTS[0],
            executor_authority_evidence_digest=malicious_evidence[
                "evidence_digest"
            ],
            executor_authority_evidence=malicious_evidence,
            authority_evaluation_at=NOW,
            authority_session_identifier_digest=DIGESTS[7],
            authority_session_issued_at=NOW - timedelta(seconds=60),
            authority_session_expires_at=NOW + timedelta(seconds=840),
            authority_evidence_collected_at=NOW - timedelta(seconds=30),
            host_digest=DIGESTS[2],
            predecessor_phase=None,
            predecessor_terminal_receipt_digest=None,
            predecessor_ledger_digest=None,
            before_state_digest=INITIAL_ABSENCE_DIGEST,
            required_predecessor_checkpoint_digest=INITIAL_ABSENCE_DIGEST,
            **_predecessor_security(None, None),
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )

    store, _plan_value, prepared = _claimed_store(tmp_path)
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(ledger.PhaseLedgerError, match="PLAN_DIGEST_NOT_AUTHORIZED"):
        ledger.execute_claimed_phase(
            store=store,
            plan=malicious,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=original["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(original, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    assert calls == 0


def test_complete_ordered_eight_phase_causal_bundle_and_negative_bindings() -> None:
    plan = _full_plan()
    records, bindings, bundle_digest = _consumed_bundle(plan)
    result = ledger.validate_consumed_causal_bundle(
        plan,
        expected_plan_digest=plan["plan_digest"],
        expected_bundle_digest=bundle_digest,
        phase_records=records,
        expected_phase_bindings=bindings,
        expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
    )
    assert result.startswith("sha256:")

    invalid_cases: list[tuple[list[dict[str, Any]], list[dict[str, Any]]]] = []
    invalid_cases.append((records[:-1], bindings[:-1]))
    invalid_cases.append(([records[1], records[0], *records[2:]], bindings))
    invalid_cases.append(([records[0], records[0], *records[2:]], bindings))
    invalid_cases.append(
        ([*records, copy.deepcopy(records[-1])], [*bindings, copy.deepcopy(bindings[-1])])
    )
    for field, value in (
        ("ledger_id", DIGESTS[7]),
        ("initial_ledger_digest", DIGESTS[7]),
        ("claim_nonce_digest", DIGESTS[7]),
        ("terminal_receipt_digest", DIGESTS[7]),
    ):
        bad_bindings = copy.deepcopy(bindings)
        bad_bindings[3][field] = value
        invalid_cases.append((records, bad_bindings))
    extra_key = copy.deepcopy(bindings)
    extra_key[0]["extra"] = True
    invalid_cases.append((records, extra_key))

    for candidate_records, candidate_bindings in invalid_cases:
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_consumed_causal_bundle(
                plan,
                expected_plan_digest=plan["plan_digest"],
                expected_bundle_digest=bundle_digest,
                phase_records=candidate_records,
                expected_phase_bindings=candidate_bindings,
                expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
            )


def test_causal_bundle_accepts_evaluation_before_not_before_and_rejects_tamper() -> None:
    plan = _full_plan()
    records, bindings, bundle_digest = _consumed_bundle(
        plan, evaluation_lead_seconds=5
    )
    assert ledger.validate_consumed_causal_bundle(
        plan,
        expected_plan_digest=plan["plan_digest"],
        expected_bundle_digest=bundle_digest,
        phase_records=records,
        expected_phase_bindings=bindings,
        expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
    ).startswith("sha256:")
    tampered_bindings = copy.deepcopy(bindings)
    tampered_bindings[0]["authority_evaluation_at"] = records[0]["not_before"]
    with pytest.raises(
        ledger.PhaseLedgerError,
        match="CAUSAL_BUNDLE_INDEPENDENT_BINDING_MISMATCH",
    ):
        ledger.validate_consumed_causal_bundle(
            plan,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=bundle_digest,
            phase_records=records,
            expected_phase_bindings=tampered_bindings,
            expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
        )


def test_causal_bundle_rejects_reused_or_overlapping_authority_session() -> None:
    plan = _full_plan()
    reused_records, reused_bindings, bundle_digest = _consumed_bundle(
        plan, reuse_session_identifier=True
    )
    with pytest.raises(
        ledger.PhaseLedgerError, match="CAUSAL_BUNDLE_AUTHORITY_SESSION_REUSE"
    ):
        ledger.validate_consumed_causal_bundle(
            plan,
            expected_plan_digest=plan["plan_digest"],
            expected_bundle_digest=bundle_digest,
            phase_records=reused_records,
            expected_phase_bindings=reused_bindings,
            expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
        )

    # At 890-second spacing, phase 2 was issued ten seconds before phase 1's
    # session expired even though its evidence was collected twenty seconds
    # after that expiry.  Collection chronology cannot conceal session overlap.
    with pytest.raises(
        ledger.PhaseLedgerError, match="PREDECESSOR_PHASE_PRECONDITION_MISMATCH"
    ):
        _consumed_bundle(plan, phase_spacing_seconds=890)


def test_canonical_eight_phase_set_is_required_before_any_effect(tmp_path: Path) -> None:
    canonical = _full_plan()
    reduced = copy.deepcopy(canonical)
    reduced["authorization_phases"] = reduced["authorization_phases"][:-1]
    reduced["plan_digest"] = ledger.canonical_digest(
        {key: value for key, value in reduced.items() if key != "plan_digest"}
    )
    evidence = _evidence(reduced, "POLICY_FACTORY")
    with pytest.raises(
        ledger.PhaseLedgerError, match="CANONICAL_AUTHORIZATION_PHASE_SET_INVALID"
    ):
        ledger.build_prepared_ledger(
            plan=reduced,
            expected_plan_digest=reduced["plan_digest"],
            phase="POLICY_FACTORY",
            profile_class="GUG365PolicyFactory",
            caller_arn_digest=DIGESTS[0],
            executor_authority_evidence_digest=evidence["evidence_digest"],
            executor_authority_evidence=evidence,
            authority_evaluation_at=NOW,
            authority_session_identifier_digest=DIGESTS[7],
            authority_session_issued_at=NOW - timedelta(seconds=60),
            authority_session_expires_at=NOW + timedelta(seconds=840),
            authority_evidence_collected_at=NOW - timedelta(seconds=30),
            host_digest=DIGESTS[2],
            predecessor_phase=None,
            predecessor_terminal_receipt_digest=None,
            predecessor_ledger_digest=None,
            before_state_digest=INITIAL_ABSENCE_DIGEST,
            required_predecessor_checkpoint_digest=INITIAL_ABSENCE_DIGEST,
            **_predecessor_security(None, None),
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )

    store, _plan_value, prepared = _claimed_store(tmp_path)
    callbacks = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal callbacks
        callbacks += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(
        ledger.PhaseLedgerError, match="CANONICAL_AUTHORIZATION_PHASE_SET_INVALID"
    ):
        ledger.execute_claimed_phase(
            store=store,
            plan=reduced,
            ledger_id=prepared["ledger_id"],
            expected_plan_digest=reduced["plan_digest"],
            execution_authorization=_authorization(prepared),
            executor_authority_evidence=_evidence(canonical, "POLICY_FACTORY"),
            authority_evaluation_at=NOW,
            **_predecessor_security(None, None),
            clock=lambda: NOW + timedelta(seconds=2),
            invoke_once=invoke,
        )
    assert callbacks == 0


def test_causal_bundle_rejects_fully_resealed_plan_binding_substitutions() -> None:
    plan = _full_plan()
    records, bindings, bundle_digest = _consumed_bundle(plan)

    forged_records: list[dict[str, Any]] = []

    request_forge = copy.deepcopy(records[0])
    forged_request_digest = "sha256:" + "9" * 64
    request_forge["ordered_request_digests"][0] = forged_request_digest
    request_forge["operation_outcomes"][0]["request_digest"] = (
        forged_request_digest
    )
    request_forge["receipt_chain"][1]["facts"]["request_digest"] = (
        forged_request_digest
    )
    request_forge["receipt_chain"][2]["facts"]["request_digest"] = (
        forged_request_digest
    )
    forged_records.append(request_forge)

    count_forge = copy.deepcopy(records[0])
    count_forge["operation_count"] = 1
    count_forge["ordered_request_digests"] = count_forge[
        "ordered_request_digests"
    ][:1]
    count_forge["operation_outcomes"] = count_forge["operation_outcomes"][:1]
    count_forge["receipt_chain"] = count_forge["receipt_chain"][:3]
    count_forge["ledger_version"] = 4
    count_forge["claim"]["next_operation_sequence"] = 1
    count_forge["operation_outcomes"][0]["next_required_action"] = "NO_RETRY"
    count_forge["receipt_chain"][2]["facts"]["next_required_action"] = (
        "NO_RETRY"
    )
    forged_records.append(count_forge)

    operations_forge = copy.deepcopy(records[0])
    operations_forge["ordered_operations_digest"] = "sha256:" + "8" * 64
    forged_records.append(operations_forge)

    account_forge = copy.deepcopy(records[0])
    account_forge["account_id"] = "999999999999"
    forged_records.append(account_forge)

    region_forge = copy.deepcopy(records[0])
    region_forge["region"] = "us-west-2"
    forged_records.append(region_forge)

    for forged in forged_records:
        _reseal_identity_receipts_and_ledger(forged)
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_ledger(forged)
        candidate_records = [forged, *records[1:]]
        candidate_bindings = copy.deepcopy(bindings)
        candidate_bindings[0].update(
            {
                "ledger_id": forged["ledger_id"],
                "initial_ledger_digest": forged["initial_ledger_digest"],
                "claim_nonce_digest": forged["claim"]["claim_nonce_digest"],
                "terminal_receipt_digest": forged["receipt_chain"][-1][
                    "receipt_digest"
                ],
            }
        )
        with pytest.raises(ledger.PhaseLedgerError):
            ledger.validate_consumed_causal_bundle(
                plan,
                expected_plan_digest=plan["plan_digest"],
                expected_bundle_digest=bundle_digest,
                phase_records=candidate_records,
                expected_phase_bindings=candidate_bindings,
                expected_initial_bundle_absence_digest=INITIAL_ABSENCE_DIGEST,
            )


def test_runner_rejects_resealed_reduced_operation_set_before_callback(
    tmp_path: Path,
) -> None:
    plan = _plan()
    forged = _prepared(plan)
    forged["operation_count"] = 1
    forged["ordered_request_digests"] = forged["ordered_request_digests"][:1]
    forged["ordered_operations_digest"] = ledger.canonical_digest(
        plan["authorization_phases"][0]["operations"][:1]
    )
    _reseal_identity_receipts_and_ledger(forged)
    ledger.validate_ledger(forged)
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(root)
    store.create(forged)
    calls = 0

    def invoke(_operation: Mapping[str, Any]) -> ledger.OperationResult:
        nonlocal calls
        calls += 1
        return ledger.OperationResult("SUCCEEDED", DIGESTS[4])

    with pytest.raises(ledger.PhaseLedgerError, match="LEDGER_AUTHORIZED_PHASE_BINDING_MISMATCH"):
        ledger.prepare_claim(
            forged,
            expected_version=forged["ledger_version"],
            expected_digest=forged["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=DIGESTS[3],
            profile_class=forged["profile_class"],
            caller_arn_digest=forged["caller_arn_digest"],
            executor_authority_evidence_digest=forged[
                "executor_authority_evidence_digest"
            ],
            host_digest=forged["host_digest"],
            **_claim_security(forged, plan),
        )
    assert calls == 0
    assert store.read(forged["ledger_id"])["status"] == "PREPARED"
