from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling import platform_authority_gug376_live_executor as live
from tooling.platform_authority_gug376_authority_inventory_collector import (
    read_private_json,
    write_private_json,
)
from tooling import platform_authority_gug376_live_request_materializer as materializer
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    ALLOWED_OPERATIONS,
    live_closed_policy,
)


def _digest(label: str) -> str:
    return canonical_digest(label)


def _run() -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug376_live_readonly_run.v2",
        "status": "LIVE_READ_ONLY_CAPTURED",
        "classification": "LIVE_DUAL_DOMAIN_CAPTURED",
        "source_commit_sha": "1" * 40,
        "source_tree_sha": "2" * 40,
        "window_digest": _digest("window"),
        "policy_digest": live.LIVE_POLICY_DIGEST,
        "authorization_digest": _digest("authorization"),
        "attestation_digest": _digest("attestation"),
        "trust_anchor_digest": _digest("trust"),
        "run_id_digest": _digest("run-id"),
        "profile_binding_digest": _digest("profiles"),
        "request_digest": _digest("request"),
        "checkpoint_digest": _digest("checkpoint"),
        "approval_reference_digest": _digest("approval"),
        "authority_receipt_digest": _digest("authority-receipt"),
        "identity_center_receipt_digest": _digest("identity-receipt"),
        "authority_snapshot_digests": [_digest("a-snapshot-1"), _digest("a-snapshot-2")],
        "identity_center_snapshot_digests": [_digest("i-snapshot-1"), _digest("i-snapshot-2")],
        "authority_session_digests": [_digest("a-session-1"), _digest("a-session-2")],
        "identity_center_session_digests": [_digest("i-session-1"), _digest("i-session-2")],
        "transcript_digest": _digest("transcript"),
        "provider_calls": 11,
        "aws_calls": 11,
        "authority_classification": "ABSENT_READY",
        "identity_center_classification": "ABSENT_READY",
        "evidence_manifest_digest": _digest("evidence-manifest"),
        "sealed_at": "2026-08-27T00:10:00Z",
        "evidence_complete": True,
        "evidence_stable": True,
        "live_provider_evidence": True,
        "read_only": True,
        "aws_mutations": 0,
        "reconciliation_only": False,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    value["run_digest"] = canonical_digest(value)
    return value


def _handoff(run: dict[str, Any]) -> dict[str, Any]:
    value = {
        key: item
        for key, item in run.items()
        if key
        not in {
            "record_type",
            "handoff_digest",
            "authority_snapshot_digests",
            "identity_center_snapshot_digests",
            "authority_session_digests",
            "identity_center_session_digests",
            "run_id_digest",
            "profile_binding_digest",
        }
    }
    value["record_type"] = "scanalyze.platform_authority.gug376_live_readonly_handoff.v2"
    value["handoff_digest"] = canonical_digest(value)
    return value


def _reseal(value: dict[str, Any], key: str) -> dict[str, Any]:
    value[key] = canonical_digest({name: item for name, item in value.items() if name != key})
    return value


def test_live_closed_policy_keeps_kms_dependency_non_dispatchable() -> None:
    policy = live_closed_policy()

    assert policy["dependencies"] == {"identity_center": ["kms:Decrypt"]}
    operations = policy["operations"]["identity_center"]
    assert "sso:DescribePermissionSet" in operations
    assert "kms:Decrypt" not in operations
    assert all("kms:Decrypt" not in actions for actions in ALLOWED_OPERATIONS.values())


def test_v2_run_and_handoff_are_schema_closed_digest_only_no_go() -> None:
    run = _run()
    handoff = _handoff(run)
    assert live.validate_live_run_record(run) == run
    assert live.validate_live_public_handoff(handoff) == handoff
    assert live.validate_live_bundle(run, handoff) == (run, handoff)
    public = str(handoff)
    for sensitive in ("arn:aws:", "profile_name", "UserId", "account_id", "private_root"):
        assert sensitive not in public
    assert handoff["deployment_authorized"] is False
    assert handoff["production_status"] == "NO-GO"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "LIVE_INVENTORY_NOT_PROVEN"),
        ("classification", "SYNTHETIC_VALIDATED"),
        ("provider_calls", 10),
        ("aws_calls", 0),
        ("aws_mutations", 1),
        ("live_provider_evidence", False),
        ("deployment_authorized", True),
        ("independent_approval_present", True),
        ("production_status", "GO"),
        ("authority_classification", "EXACT_PRESENT_NO_TOUCH"),
        ("authority_classification", "DRIFT_BLOCKED_NO_REPAIR"),
    ],
)
def test_v2_validator_rejects_overclaims_and_inconsistent_counts(field: str, value: Any) -> None:
    run = _run()
    run[field] = value
    _reseal(run, "run_digest")
    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)


def test_v2_validator_rejects_cross_domain_reuse_and_extra_fields() -> None:
    run = _run()
    run["identity_center_session_digests"][0] = run["authority_session_digests"][0]
    _reseal(run, "run_digest")
    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)
    handoff = _handoff(_run())
    handoff["profile"] = "must-never-be-public"
    _reseal(handoff, "handoff_digest")
    with pytest.raises(live.LiveExecutorError, match="PUBLIC_HANDOFF_V2_INVALID"):
        live.validate_live_public_handoff(handoff)


def test_v2_validator_rejects_three_identity_sessions_and_handoff_overclaim() -> None:
    run = _run()
    run["identity_center_session_digests"].append(_digest("i-session-3"))
    _reseal(run, "run_digest")
    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)

    handoff = _handoff(_run())
    handoff["authority_classification"] = "EXACT_PRESENT_NO_TOUCH"
    _reseal(handoff, "handoff_digest")
    with pytest.raises(live.LiveExecutorError, match="PUBLIC_HANDOFF_V2_INVALID"):
        live.validate_live_public_handoff(handoff)


def test_v2_validator_rejects_causally_impossible_provider_call_count() -> None:
    run = _run()
    run["provider_calls"] = run["aws_calls"] = 1
    _reseal(run, "run_digest")

    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)


def test_v2_validators_reject_self_sealed_impossible_timestamp() -> None:
    run = _run()
    run["sealed_at"] = "2026-02-31T25:61:61Z"
    _reseal(run, "run_digest")
    handoff = _handoff(run)

    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)
    with pytest.raises(live.LiveExecutorError, match="PUBLIC_HANDOFF_V2_INVALID"):
        live.validate_live_public_handoff(handoff)
    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_bundle(run, handoff)


@pytest.mark.parametrize(
    ("classification", "session_count"),
    [
        ("ABSENT_READY", 4),
        ("EXACT_PRESENT_NO_TOUCH", 2),
    ],
)
def test_v2_validator_rejects_impossible_identity_classification_session_pairs(
    classification: str, session_count: int
) -> None:
    run = _run()
    run["identity_center_classification"] = classification
    run["identity_center_session_digests"] = [
        _digest(f"i-session-{index}") for index in range(1, session_count + 1)
    ]
    _reseal(run, "run_digest")

    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)


def test_v2_validator_requires_generated_role_authority_state_for_identity_exact() -> None:
    run = _run()
    run["identity_center_classification"] = "EXACT_PRESENT_NO_TOUCH"
    run["identity_center_session_digests"] = [
        _digest(f"i-session-{index}") for index in range(1, 5)
    ]
    _reseal(run, "run_digest")
    with pytest.raises(live.LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        live.validate_live_run_record(run)

    run["authority_classification"] = "PREEXISTING_NO_TOUCH"
    _reseal(run, "run_digest")
    assert live.validate_live_run_record(run) == run


def test_v2_bundle_rejects_self_sealed_handoff_from_another_run() -> None:
    run = _run()
    handoff = _handoff(run)
    handoff["run_digest"] = _digest("nonexistent-run")
    _reseal(handoff, "handoff_digest")

    assert live.validate_live_public_handoff(handoff) == handoff
    with pytest.raises(live.LiveExecutorError, match="LIVE_BUNDLE_V2_INVALID"):
        live.validate_live_bundle(run, handoff)


class _InjectedFactory:
    mode = "INJECTED_NON_LIVE"
    concrete_provider = False

    def __init__(self) -> None:
        self.builds = 0

    def build_authority(self, **_kwargs: Any) -> None:
        self.builds += 1

    def build_identity(self, **_kwargs: Any) -> None:
        self.builds += 1

    def transcript_summary(self) -> dict[str, Any]:
        raise AssertionError("transcript must not be requested")


def test_injected_factory_cannot_enter_attested_live_path(tmp_path: Path) -> None:
    factory = _InjectedFactory()
    with pytest.raises(live.LiveExecutorError, match="ATTESTED_LIVE_PROVIDER_REQUIRED"):
        live.execute_live(
            {},
            factory,
            private_root=tmp_path,
            now=datetime.now(UTC),
            actual_source_commit_sha="1" * 40,
            actual_source_tree_sha="2" * 40,
            request_digest=_digest("request"),
            checkpoint_digest=_digest("checkpoint"),
            approval_reference_digest=_digest("approval"),
            execution_capability=object(),
        )
    assert factory.builds == 0


def test_spoofed_public_live_flags_cannot_promote_an_injected_factory(
    tmp_path: Path,
) -> None:
    factory = _InjectedFactory()
    factory.mode = "ATTESTED_LIVE"
    factory.concrete_provider = True
    with pytest.raises(live.LiveExecutorError, match="ATTESTED_LIVE_PROVIDER_REQUIRED"):
        live.execute_live(
            {},
            factory,
            private_root=tmp_path,
            now=datetime.now(UTC),
            actual_source_commit_sha="1" * 40,
            actual_source_tree_sha="2" * 40,
            request_digest=_digest("request"),
            checkpoint_digest=_digest("checkpoint"),
            approval_reference_digest=_digest("approval"),
            execution_capability=object(),
        )
    assert factory.builds == 0


def test_legacy_live_spelling_remains_rejected() -> None:
    with pytest.raises(live.OrchestratorError, match="LIVE_PROVIDER_NOT_IMPLEMENTED"):
        live.CallLedger("LIVE")
    ledger = live.CallLedger("ATTESTED_LIVE")
    session = _digest("session")
    ticket = ledger.authorize(
        domain="authority",
        session_digest=session,
        operation="sts:GetCallerIdentity",
        retries=0,
        started_at="2026-08-27T00:00:00Z",
    )
    ledger.complete(
        ticket,
        _digest("identity"),
        completed_at="2026-08-27T00:00:01Z",
    )
    assert ledger.finalize()[0] == 1


def _private_root(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _durable_request_artifacts(
    root: Path, *, label: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_sha = ("1" if label == "approved" else "3") * 40
    tree_sha = ("2" if label == "approved" else "4") * 40
    request_digest = _digest(f"{label}-request")
    checkpoint_digest = _digest(f"{label}-checkpoint")
    approval_digest = _digest(f"{label}-approval")
    policy_digest = _digest(f"{label}-authority-policy")
    authority_plan = {
        "targets": {
            "runtime_source_function_version_arn": (
                "arn:aws:lambda:us-east-1:111122223333:"
                "function:approved-source:7"
            )
        },
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:30:00Z",
        "expected_account_id": "111122223333",
        "expected_principal_arn": (
            "arn:aws:sts::111122223333:"
            "assumed-role/ApprovedReadOnly/operator"
        ),
        "authority_verification_digest": _digest(
            f"{label}-authority-verification"
        ),
        "expected_policy_digest": policy_digest,
    }
    identity_plan = {
        "private_targets": {
            "identity_store_id": "d-1234567890",
            "application_name": "ApprovedApplication",
        },
        "not_before": "2025-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:30:00Z",
        "expected_account_id": "444455556666",
        "expected_principal_arn": (
            "arn:aws:sts::444455556666:"
            "assumed-role/ApprovedReadOnly/operator"
        ),
        "authority_verification_digest": _digest(
            f"{label}-identity-verification"
        ),
        "expected_discovery_policy_digest": _digest(
            f"{label}-discovery-policy"
        ),
        "expected_exact_policy_digest": _digest(f"{label}-exact-policy"),
        "expected_target_digest": _digest(f"{label}-target"),
        "expected_facts_digest": _digest(f"{label}-facts"),
    }
    _, authority_plan_digest = live._authority_plan_binding(
        authority_plan, code="TEST_INVALID"
    )
    _, identity_plan_digest = live._identity_plan_binding(
        identity_plan, code="TEST_INVALID"
    )
    root_digest = materializer.private_root_binding_digest(root)
    request_file = f"{label}-request.json"
    checkpoint_file = f"{label}-checkpoint.json"
    request = {
        "record_type": materializer.REQUEST_RECORD_TYPE,
        "request_file": request_file,
        "owner_checkpoint_file": checkpoint_file,
        "request_digest": request_digest,
        "owner_checkpoint_digest": checkpoint_digest,
        "source_commit_sha": source_sha,
        "source_tree_sha": tree_sha,
        "host_digest": _digest(f"{label}-host"),
        "private_root_digest": root_digest,
        "approval_reference_digest": approval_digest,
        "not_before": "2025-01-01T00:01:00Z",
        "expires_at": "2025-01-01T00:10:00Z",
        "authority_plan": authority_plan,
        "identity_center_plan": identity_plan,
        "authorization": {
            "authority_plan_digest": authority_plan_digest,
            "identity_center_plan_digest": identity_plan_digest,
        },
    }
    checkpoint = {
        "record_type": materializer.CHECKPOINT_RECORD_TYPE,
        "request_file": request_file,
        "owner_checkpoint_file": checkpoint_file,
        "checkpoint_digest": checkpoint_digest,
        "plan_window_digest": canonical_digest(
            {
                "not_before": authority_plan["not_before"],
                "not_after": authority_plan["not_after"],
                "region": "us-east-1",
            }
        ),
        "authority_plan_digest": authority_plan_digest,
        "identity_center_plan_digest": identity_plan_digest,
    }
    claim_body = {
        "record_type": (
            "scanalyze.platform_authority.gug376_live_consumption_claim.v1"
        ),
        "implementation_issue": "GUG-392",
        "parent_issue": "GUG-376",
        "source_commit_sha": source_sha,
        "source_tree_sha": tree_sha,
        "request_digest": request_digest,
        "checkpoint_digest": checkpoint_digest,
        "approval_reference_digest": approval_digest,
        "host_digest": request["host_digest"],
        "private_root_digest": root_digest,
        "claimed_at": "2025-01-01T00:02:00Z",
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    claim = {**claim_body, "claim_digest": canonical_digest(claim_body)}
    write_private_json(root, request_file, request)
    write_private_json(root, checkpoint_file, checkpoint)
    write_private_json(root, materializer.CONSUMPTION_CLAIM, claim)
    evidence = {
        "source_commit_sha": source_sha,
        "source_tree_sha": tree_sha,
        "not_before": authority_plan["not_before"],
        "not_after": authority_plan["not_after"],
        "window_digest": checkpoint["plan_window_digest"],
        "request_file": request_file,
        "request_digest": request_digest,
        "owner_checkpoint_file": checkpoint_file,
        "checkpoint_digest": checkpoint_digest,
        "consumption_claim_file": materializer.CONSUMPTION_CLAIM,
        "consumption_claim_digest": claim["claim_digest"],
        "approval_reference_digest": approval_digest,
    }
    return request, checkpoint, claim, evidence


def _accept_materialized_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def validate(
        request: dict[str, Any],
        checkpoint: dict[str, Any],
        **kwargs: Any,
    ) -> SimpleNamespace:
        assert kwargs["now"] == datetime(2025, 1, 1, 0, 1, tzinfo=UTC)
        return SimpleNamespace(
            request=copy.deepcopy(request),
            owner_checkpoint=copy.deepcopy(checkpoint),
        )

    monkeypatch.setattr(live, "validate_materialized_live_request", validate)


def test_durable_request_recertification_does_not_require_an_active_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_root(tmp_path, "approved")
    expected = _durable_request_artifacts(root, label="approved")
    _accept_materialized_pair(monkeypatch)

    actual = live._validate_physical_request_artifacts(
        root, evidence=expected[3]
    )

    assert actual == expected[:3]


@pytest.mark.parametrize(
    ("artifact", "action"),
    [
        *((artifact, "missing") for artifact in ("request", "checkpoint", "claim")),
        *((artifact, "tamper") for artifact in ("request", "checkpoint", "claim")),
        *((artifact, "substitute") for artifact in ("request", "checkpoint", "claim")),
        *((artifact, "custody") for artifact in ("request", "checkpoint", "claim")),
    ],
)
def test_durable_recertification_rejects_invalid_physical_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    action: str,
) -> None:
    root = _private_root(tmp_path, "approved")
    request, checkpoint, claim, evidence = _durable_request_artifacts(
        root, label="approved"
    )
    _accept_materialized_pair(monkeypatch)
    filenames = {
        "request": request["request_file"],
        "checkpoint": checkpoint["owner_checkpoint_file"],
        "claim": materializer.CONSUMPTION_CLAIM,
    }
    target = root / filenames[artifact]
    if action == "missing":
        target.unlink()
    elif action == "tamper":
        value = read_private_json(root, filenames[artifact])
        if artifact == "request":
            value["request_digest"] = _digest("tampered-request")
        elif artifact == "checkpoint":
            value["checkpoint_digest"] = _digest("tampered-checkpoint")
        else:
            value["read_only"] = False
        target.write_text(canonical_json(value) + "\n", encoding="utf-8")
    elif action == "substitute":
        foreign_root = _private_root(tmp_path, "foreign")
        foreign = _durable_request_artifacts(foreign_root, label="foreign")
        foreign_names = {
            "request": foreign[0]["request_file"],
            "checkpoint": foreign[1]["owner_checkpoint_file"],
            "claim": materializer.CONSUMPTION_CLAIM,
        }
        target.write_bytes((foreign_root / foreign_names[artifact]).read_bytes())
    else:
        target.chmod(0o640)

    with pytest.raises(
        live.LiveExecutorError, match="PRIVATE_EVIDENCE_REQUEST_INVALID"
    ):
        live._validate_physical_request_artifacts(root, evidence=evidence)


def _snapshot_artifacts(
    root: Path,
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    authority_binding, _ = live._authority_plan_binding(
        request["authority_plan"], code="TEST_INVALID"
    )
    identity_binding, identity_plan_digest = live._identity_plan_binding(
        request["identity_center_plan"], code="TEST_INVALID"
    )
    snapshots: list[dict[str, Any]] = []
    for index in range(2):
        snapshot = {
            "policy_digest": authority_binding["policy_digest"],
            "runtime_target_digest": authority_binding[
                "runtime_target_digest"
            ],
            "identity": {
                "account_id": authority_binding["account_id"],
                "principal_arn": authority_binding["principal_arn"],
                "policy_digest": authority_binding["policy_digest"],
                "authority_verification_digest": authority_binding[
                    "authority_verification_digest"
                ],
                "region": authority_binding["region"],
                "observed_at": f"2025-01-01T00:0{index + 2}:00Z",
                "expires_at": "2025-01-01T00:45:00Z",
                "session_id_digest": _digest(f"authority-session-{index}"),
            },
        }
        snapshot["snapshot_digest"] = canonical_digest(snapshot)
        snapshots.append(snapshot)
    for index in range(2):
        snapshot = {
            "plan_binding": identity_binding,
            "plan_binding_digest": identity_plan_digest,
            "session_digests": [_digest(f"identity-session-{index}")],
        }
        snapshot["snapshot_digest"] = canonical_digest(snapshot)
        snapshots.append(snapshot)
    for name, snapshot in zip(live.ARTIFACT_NAMES, snapshots):
        write_private_json(root, name, snapshot)
    authority_collector = {
        "classification": "ABSENT_READY",
        "runtime_target_digest": authority_binding["runtime_target_digest"],
        "snapshot_digests": [item["snapshot_digest"] for item in snapshots[:2]],
    }
    identity_collector = {
        "classification": "ABSENT_READY",
        "snapshot_digests": [item["snapshot_digest"] for item in snapshots[2:]],
    }
    return authority_collector, identity_collector


def test_snapshot_recertification_uses_approved_plan_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_root(tmp_path, "approved")
    request, checkpoint, _, _ = _durable_request_artifacts(
        root, label="approved"
    )
    authority_collector, identity_collector = _snapshot_artifacts(root, request)
    monkeypatch.setattr(
        live, "certify_authority", lambda *_args, **_kwargs: authority_collector
    )
    monkeypatch.setattr(
        live,
        "certify_identity_center",
        lambda *_args, **_kwargs: identity_collector,
    )
    monkeypatch.setattr(live, "validate_authority_receipt", lambda value: value)
    monkeypatch.setattr(live, "validate_identity_center_receipt", lambda value: value)
    monkeypatch.setattr(
        live, "_validate_cross_domain_identity_role_state", lambda **_: None
    )

    authority_sessions, identity_sessions = live._validate_physical_live_snapshots(
        root,
        authority_collector=authority_collector,
        identity_collector=identity_collector,
        approved_request=request,
        owner_checkpoint=checkpoint,
    )

    assert len(authority_sessions) == len(identity_sessions) == 2


@pytest.mark.parametrize("domain", ("authority", "identity_center"))
def test_snapshot_recertification_rejects_substituted_plan_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    domain: str,
) -> None:
    root = _private_root(tmp_path, "approved")
    request, checkpoint, _, _ = _durable_request_artifacts(
        root, label="approved"
    )
    authority_collector, identity_collector = _snapshot_artifacts(root, request)
    index = 0 if domain == "authority" else 2
    name = live.ARTIFACT_NAMES[index]
    snapshot = read_private_json(root, name)
    if domain == "authority":
        snapshot["policy_digest"] = _digest("substituted-authority-policy")
    else:
        snapshot["plan_binding_digest"] = _digest("substituted-identity-plan")
    snapshot["snapshot_digest"] = canonical_digest(
        {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    )
    (root / name).write_text(canonical_json(snapshot) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        live, "certify_authority", lambda *_args, **_kwargs: authority_collector
    )
    monkeypatch.setattr(
        live,
        "certify_identity_center",
        lambda *_args, **_kwargs: identity_collector,
    )
    monkeypatch.setattr(
        live, "_validate_cross_domain_identity_role_state", lambda **_: None
    )
    monkeypatch.setattr(live, "validate_authority_receipt", lambda value: value)
    monkeypatch.setattr(live, "validate_identity_center_receipt", lambda value: value)

    with pytest.raises(
        live.LiveExecutorError, match="PRIVATE_EVIDENCE_SNAPSHOT_INVALID"
    ):
        live._validate_physical_live_snapshots(
            root,
            authority_collector=authority_collector,
            identity_collector=identity_collector,
            approved_request=request,
            owner_checkpoint=checkpoint,
        )
