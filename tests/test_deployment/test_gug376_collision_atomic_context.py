"""Custody and CLI tests for the private atomic collision context."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.test_deployment import (
    test_gug392_live_request_materializer as gug392_data,
)
from tests.test_deployment import (
    test_gug395_preplan_collision_probe as gug395_data,
)
from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_authority_inventory_collector import (
    read_private_json,
    write_private_json,
)
from tooling import platform_authority_gug376_collision_atomic_context as subject
from tooling import (
    platform_authority_gug376_collision_atomic_admission as atomic_admission,
)
from tooling import platform_authority_gug376_collision_direct_sso as direct_sso
from tooling import platform_authority_gug376_collision_policy as collision_policy
from tooling import platform_authority_gug376_live_request_materializer as gug392
from tooling import platform_authority_gug393_private_input_discovery as gug393
from tooling import platform_authority_gug395_preplan_collision_probe as gug395


SCRIPT = (
    Path(__file__).parents[2]
    / "scripts/deployment/platform-authority-gug376-collision-admission.py"
)
NOW = datetime(2026, 8, 28, 1, 11, tzinfo=UTC)
NOT_BEFORE = "2026-08-28T01:10:00Z"
EXPIRES_AT = "2026-08-28T01:15:00Z"
BOOTSTRAP_INTENT_DIGEST = canonical_digest({"intent": "gug376"})
APPROVAL_REFERENCE_DIGEST = canonical_digest({"approval": "effect-1"})
APPROVED_OPERATION = "foundation-create:dispatch"


def _root(tmp_path: Path, name: str) -> Path:
    value = tmp_path / name
    value.mkdir(mode=0o700)
    value.chmod(0o700)
    return value.resolve(strict=True)


def _replace(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        for old, new in replacements.items():
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_replace(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _replace(item, replacements) for key, item in value.items()}
    return value


def _persist_gug395(root: Path) -> dict[str, Any]:
    request, claim = gug395_data._write_result_custody(root)  # noqa: SLF001
    result = gug395_data._build_success_result(request=request)  # noqa: SLF001
    gug395.persist_collision_probe_result(
        private_root=root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )
    return request


def _replace_gug395_with_valid_absent_result(root: Path) -> None:
    request = read_private_json(root, gug395.DEFAULT_REQUEST_FILE)
    claim = read_private_json(root, gug395.DEFAULT_CLAIM_FILE)
    (root / gug395.DEFAULT_RESULT_FILE).unlink()
    replacement = gug395_data._build_success_result(  # noqa: SLF001
        request=request,
        credential_vends=1,
    )
    assert replacement.public_receipt["classification"] == gug395.ABSENT_READY
    gug395.persist_collision_probe_result(
        private_root=root,
        result=replacement,
        expected_claim_digest=claim["claim_digest"],
    )


def _persist_gug393(root: Path, request395: dict[str, Any]) -> dict[str, Any]:
    authority_input, identity_input = gug392_data._plan_inputs()  # noqa: SLF001
    replacements = {
        gug392_data.AUTHORITY_ACCOUNT: gug395_data.AUTHORITY_ACCOUNT,
        gug392_data.IDENTITY_ACCOUNT: gug395_data.IDENTITY_ACCOUNT,
        "synthetic-private-artifacts": gug395_data.ARTIFACT_BUCKET,
    }
    authority_input = _replace(authority_input, replacements)
    identity_input = _replace(identity_input, replacements)
    authority_profile = request395["profiles"]["authority"]
    identity_profile = request395["profiles"]["identity_center"]
    authority_input.update(
        {
            "not_before": request395["not_before"],
            "not_after": request395["expires_at"],
            "expected_account_id": authority_profile["expected_account_id"],
            "expected_principal_arn": gug395_data.AUTHORITY_PRINCIPAL,
            "authority_verification_digest": authority_profile[
                "authority_verification_digest"
            ],
        }
    )
    identity_input.update(
        {
            "not_before": request395["not_before"],
            "not_after": request395["expires_at"],
            "expected_account_id": identity_profile["expected_account_id"],
            "expected_principal_arn": gug395_data.IDENTITY_PRINCIPAL,
            "authority_verification_digest": identity_profile[
                "authority_verification_digest"
            ],
        }
    )
    instance_arn = request395["targets"]["identity_center_application"][
        "instance_arn"
    ]
    identity_input["expected_state"]["instance"]["instance_arn"] = instance_arn
    identity_input["expected_state"]["instance"]["owner_account_id"] = (
        gug395_data.IDENTITY_ACCOUNT
    )
    _actor_policy, actor_digest = gug392.render_application_actor_policy(
        authority_input["targets"],
        authority_account_id=gug395_data.AUTHORITY_ACCOUNT,
    )
    identity_input["private_targets"][
        "application_actor_policy_digest"
    ] = actor_digest
    plans = gug393.materialize_live_plans(
        authority_input=authority_input,
        identity_center_input=identity_input,
    )
    decision_body = {
        "approval": "synthetic-gug393-owner-decision",
        "source_commit_sha": request395["source_commit_sha"],
        "source_tree_sha": request395["source_tree_sha"],
    }
    decision = {**decision_body, "decision_digest": canonical_digest(decision_body)}
    artifacts = {
        gug393.DEFAULT_AUTHORITY_INPUT_FILE: authority_input,
        gug393.DEFAULT_IDENTITY_INPUT_FILE: identity_input,
        gug393.DEFAULT_AUTHORITY_PLAN_FILE: plans.authority_plan,
        gug393.DEFAULT_IDENTITY_PLAN_FILE: plans.identity_center_plan,
        gug393.DEFAULT_DECISION_FILE: decision,
    }
    manifest_body = {
        "record_type": gug393.MANIFEST_TYPE,
        "schema_version": 1,
        "implementation_issue": gug393.IMPLEMENTATION_ISSUE,
        "parent_issue": gug393.PARENT_ISSUE,
        "live_issue": gug393.LIVE_ISSUE,
        "proposal_digest": canonical_digest({"proposal": "synthetic"}),
        "decision_digest": decision["decision_digest"],
        "source_commit_sha": request395["source_commit_sha"],
        "source_tree_sha": request395["source_tree_sha"],
        "source_contract_digest": canonical_digest({"source": "synthetic"}),
        "request_digest": canonical_digest({"request": "synthetic"}),
        "budget_digest": canonical_digest({"budget": "synthetic"}),
        "private_root_digest": gug393.private_root_binding_digest(root),
        "host_digest": gug393.operational_host_digest(),
        "artifact_digests": {
            name: canonical_digest(value) for name, value in artifacts.items()
        },
        "authority_input_file": gug393.DEFAULT_AUTHORITY_INPUT_FILE,
        "identity_center_input_file": gug393.DEFAULT_IDENTITY_INPUT_FILE,
        "authority_plan_file": gug393.DEFAULT_AUTHORITY_PLAN_FILE,
        "identity_center_plan_file": gug393.DEFAULT_IDENTITY_PLAN_FILE,
        "decision_file": gug393.DEFAULT_DECISION_FILE,
        "manifest_file": gug393.DEFAULT_MANIFEST_FILE,
        "materialized_at": request395["not_before"],
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    manifest = {
        **manifest_body,
        "manifest_digest": canonical_digest(manifest_body),
    }
    for name, value in artifacts.items():
        write_private_json(root, name, value)
    write_private_json(root, gug393.DEFAULT_MANIFEST_FILE, manifest)
    assert gug393.validate_input_materialization_manifest(root, manifest) == manifest
    return manifest


def _materialized_roots(
    tmp_path: Path,
    *,
    suffix: str = "",
    gug393_root: Path | None = None,
    gug395_root: Path | None = None,
    approval_reference_digest: str = APPROVAL_REFERENCE_DIGEST,
    approved_operation: str = APPROVED_OPERATION,
    authorized_at: str = NOT_BEFORE,
    expires_at: str = EXPIRES_AT,
    now: datetime = NOW,
) -> tuple[Path, Path, Path, Path, dict[str, Any]]:
    admission_root = _root(tmp_path, f"admission{suffix}")
    effect_root = _root(tmp_path, f"effect{suffix}")
    if (gug393_root is None) != (gug395_root is None):
        raise ValueError("shared lineage roots must be supplied together")
    if gug393_root is None and gug395_root is None:
        gug393_root = _root(tmp_path, "gug393")
        gug395_root = _root(tmp_path, "gug395")
        request395 = _persist_gug395(gug395_root)
        _persist_gug393(gug393_root, request395)
    assert gug393_root is not None and gug395_root is not None
    context = subject.materialize_atomic_collision_context(
        admission_private_root=admission_root,
        effect_private_root=effect_root,
        gug393_private_root=gug393_root,
        gug395_private_root=gug395_root,
        bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
        approval_reference_digest=approval_reference_digest,
        approved_operation=approved_operation,
        authorized_at=authorized_at,
        expires_at=expires_at,
        clock=lambda: now,
    )
    return admission_root, effect_root, gug393_root, gug395_root, context


def test_context_reuses_one_absent_lineage_across_two_fresh_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _materialized_roots(tmp_path, suffix="-one")
    second_approval = canonical_digest({"approval": "effect-2"})
    second = _materialized_roots(
        tmp_path,
        suffix="-two",
        gug393_root=first[2],
        gug395_root=first[3],
        approval_reference_digest=second_approval,
        authorized_at="2026-08-28T02:00:00Z",
        expires_at="2026-08-28T02:10:00Z",
        now=datetime(2026, 8, 28, 2, 1, tzinfo=UTC),
    )

    first_context = first[4]
    second_context = second[4]
    assert first[2:4] == second[2:4]
    assert first_context["gug395_private_root_digest"] == second_context[
        "gug395_private_root_digest"
    ]
    assert first_context["gug395_request_digest"] == second_context[
        "gug395_request_digest"
    ]
    assert first_context["admission_private_root_digest"] != second_context[
        "admission_private_root_digest"
    ]
    assert first_context["effect_private_root_digest"] != second_context[
        "effect_private_root_digest"
    ]
    assert first_context["context_digest"] != second_context["context_digest"]
    assert second_context["approval_reference_digest"] == second_approval
    assert second_context["catalog"]["not_before"] == "2026-08-28T02:00:00Z"
    assert second_context["catalog"]["expires_at"] == "2026-08-28T02:10:00Z"
    monkeypatch.setattr(
        subject,
        "build_direct_sso_policy_session_opener_factory",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        subject,
        "build_atomic_route_collision_admission_loader",
        lambda *, config: config,
    )
    first_config = subject.build_atomic_loader_from_private_context(
        admission_private_root=first[0],
        effect_private_root=first[1],
        gug393_private_root=first[2],
        gug395_private_root=first[3],
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_authorized_at=NOT_BEFORE,
        expected_expires_at=EXPIRES_AT,
        expected_operation=APPROVED_OPERATION,
        expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
        environment={},
        clock=lambda: NOW,
    )
    second_config = subject.build_atomic_loader_from_private_context(
        admission_private_root=second[0],
        effect_private_root=second[1],
        gug393_private_root=second[2],
        gug395_private_root=second[3],
        expected_approval_reference_digest=second_approval,
        expected_authorized_at="2026-08-28T02:00:00Z",
        expected_expires_at="2026-08-28T02:10:00Z",
        expected_operation=APPROVED_OPERATION,
        expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
        environment={},
        clock=lambda: datetime(2026, 8, 28, 2, 1, tzinfo=UTC),
    )
    assert first_config.gug395_private_root == second_config.gug395_private_root
    assert first_config.admission_private_root != second_config.admission_private_root
    assert first_config.atomic_context_digest != second_config.atomic_context_digest


def test_context_rejects_collision_blocked_lineage(tmp_path: Path) -> None:
    admission_root = _root(tmp_path, "admission")
    effect_root = _root(tmp_path, "effect")
    gug393_root = _root(tmp_path, "gug393")
    gug395_root = _root(tmp_path, "gug395")
    request, claim = gug395_data._write_result_custody(  # noqa: SLF001
        gug395_root
    )
    result = gug395_data._build_success_result(  # noqa: SLF001
        request=request,
        authority_collisions=["artifact_bucket"],
    )
    assert result.public_receipt["classification"] == gug395.COLLISION_BLOCKED
    gug395.persist_collision_probe_result(
        private_root=gug395_root,
        result=result,
        expected_claim_digest=claim["claim_digest"],
    )
    _persist_gug393(gug393_root, request)

    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_GUG395_RESULT_INVALID",
    ):
        subject.materialize_atomic_collision_context(
            admission_private_root=admission_root,
            effect_private_root=effect_root,
            gug393_private_root=gug393_root,
            gug395_private_root=gug395_root,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            approved_operation=APPROVED_OPERATION,
            authorized_at=NOT_BEFORE,
            expires_at=EXPIRES_AT,
            clock=lambda: NOW,
        )


@pytest.mark.parametrize(
    ("authorized_at", "expires_at", "now"),
    [
        (
            "2026-08-28T01:00:00Z",
            "2026-08-28T01:16:00Z",
            datetime(2026, 8, 28, 1, 5, tzinfo=UTC),
        ),
        (
            "2026-08-28T01:00:00Z",
            "2026-08-28T01:15:00Z",
            datetime(2026, 8, 28, 1, 15, tzinfo=UTC),
        ),
    ],
)
def test_context_rejects_overlong_or_stale_effect_window(
    tmp_path: Path,
    authorized_at: str,
    expires_at: str,
    now: datetime,
) -> None:
    admission_root = _root(tmp_path, "admission")
    effect_root = _root(tmp_path, "effect")
    gug393_root = _root(tmp_path, "gug393")
    gug395_root = _root(tmp_path, "gug395")

    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_WINDOW_INVALID",
    ):
        subject.materialize_atomic_collision_context(
            admission_private_root=admission_root,
            effect_private_root=effect_root,
            gug393_private_root=gug393_root,
            gug395_private_root=gug395_root,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            approved_operation=APPROVED_OPERATION,
            authorized_at=authorized_at,
            expires_at=expires_at,
            clock=lambda: now,
        )


def test_context_rejects_inline_broker_only_operation_for_local_cli(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_APPROVED_OPERATION_INVALID",
    ):
        subject.materialize_atomic_collision_context(
            admission_private_root=_root(tmp_path, "admission"),
            effect_private_root=_root(tmp_path, "effect"),
            gug393_private_root=_root(tmp_path, "gug393"),
            gug395_private_root=_root(tmp_path, "gug395"),
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            approved_operation="seed-revoke-create-v1",
            authorized_at=NOT_BEFORE,
            expires_at=EXPIRES_AT,
            clock=lambda: NOW,
        )


def test_context_reopens_both_custodies_and_derives_canonical_kms_binding(
    tmp_path: Path,
) -> None:
    (
        admission_root,
        effect_root,
        gug393_root,
        gug395_root,
        context,
    ) = _materialized_roots(tmp_path)
    checked = subject.read_atomic_collision_context(
        admission_private_root=admission_root,
        effect_private_root=effect_root,
        gug393_private_root=gug393_root,
        gug395_private_root=gug395_root,
        clock=lambda: NOW,
    )
    bindings = checked["private_bindings"]
    assert checked == context
    assert bindings["source"] == "GUG393_PERSISTED_MATERIALIZATION"
    assert bindings["identity_center_instance_arn"] == (
        "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    )
    assert bindings["identity_center_kms_binding_digest"] == canonical_digest(
        {
            "binding_name": "identity_center_kms_key_arn",
            "identity_center_instance_arn": bindings[
                "identity_center_instance_arn"
            ],
            "mode": "CUSTOMER_MANAGED_KEY",
            "key_arn": bindings["identity_center_kms_key_arn"],
        }
    )
    assert context["effect_private_root_digest"] != context[
        "admission_private_root_digest"
    ]
    assert context["gug395_private_root_digest"] not in {
        context["effect_private_root_digest"],
        context["admission_private_root_digest"],
        context["gug393_private_root_digest"],
    }
    assert context["approval_reference_digest"] == APPROVAL_REFERENCE_DIGEST


def test_context_readback_rejects_resealed_gug393_artifact(
    tmp_path: Path,
) -> None:
    (
        admission_root,
        effect_root,
        gug393_root,
        gug395_root,
        _context,
    ) = _materialized_roots(tmp_path)
    plan_path = gug393_root / gug393.DEFAULT_AUTHORITY_PLAN_FILE
    changed = read_private_json(gug393_root, gug393.DEFAULT_AUTHORITY_PLAN_FILE)
    changed["tampered"] = True
    plan_path.unlink()
    write_private_json(gug393_root, gug393.DEFAULT_AUTHORITY_PLAN_FILE, changed)

    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID",
    ):
        subject.read_atomic_collision_context(
            admission_private_root=admission_root,
            effect_private_root=effect_root,
            gug393_private_root=gug393_root,
            gug395_private_root=gug395_root,
            clock=lambda: NOW,
        )


def test_context_rejects_gug393_artifact_swap_after_manifest_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission_root = _root(tmp_path, "admission")
    effect_root = _root(tmp_path, "effect")
    gug393_root = _root(tmp_path, "gug393")
    gug395_root = _root(tmp_path, "gug395")
    request395 = _persist_gug395(gug395_root)
    _persist_gug393(gug393_root, request395)
    original_validate = gug393.validate_input_materialization_manifest
    swapped = False

    def validate_then_swap(
        private_root: Path,
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        nonlocal swapped
        checked = original_validate(private_root, manifest)
        authority_input = read_private_json(
            private_root,
            checked["authority_input_file"],
        )
        identity_input = read_private_json(
            private_root,
            checked["identity_center_input_file"],
        )
        identity_input["private_targets"][
            "identity_center_kms_key_arn"
        ] = (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        )
        replacement = gug393.materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )
        artifacts = {
            checked["authority_input_file"]: authority_input,
            checked["identity_center_input_file"]: identity_input,
            checked["authority_plan_file"]: replacement.authority_plan,
            checked["identity_center_plan_file"]: (
                replacement.identity_center_plan
            ),
        }
        for name, artifact in artifacts.items():
            (private_root / name).unlink()
            write_private_json(private_root, name, artifact)
        swapped = True
        return checked

    monkeypatch.setattr(
        subject.gug393,
        "validate_input_materialization_manifest",
        validate_then_swap,
    )
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_GUG393_MATERIALIZATION_INVALID",
    ):
        subject.materialize_atomic_collision_context(
            admission_private_root=admission_root,
            effect_private_root=effect_root,
            gug393_private_root=gug393_root,
            gug395_private_root=gug395_root,
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            approved_operation=APPROVED_OPERATION,
            authorized_at=NOT_BEFORE,
            expires_at=EXPIRES_AT,
            clock=lambda: NOW,
        )
    assert swapped is True


def test_context_readback_rejects_context_tamper(tmp_path: Path) -> None:
    (
        admission_root,
        effect_root,
        gug393_root,
        gug395_root,
        _context,
    ) = _materialized_roots(tmp_path)
    path = admission_root / subject.CONTEXT_FILE
    changed = read_private_json(admission_root, subject.CONTEXT_FILE)
    changed["approval_reference_digest"] = canonical_digest(
        {"approval": "forged"}
    )
    path.unlink()
    write_private_json(admission_root, subject.CONTEXT_FILE, changed)

    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_CONTEXT_INVALID",
    ):
        subject.read_atomic_collision_context(
            admission_private_root=admission_root,
            effect_private_root=effect_root,
            gug393_private_root=gug393_root,
            gug395_private_root=gug395_root,
            clock=lambda: NOW,
        )


def test_context_readback_rejects_expired_authorization_window(
    tmp_path: Path,
) -> None:
    roots = _materialized_roots(tmp_path)
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_WINDOW_INVALID",
    ):
        subject.read_atomic_collision_context(
            admission_private_root=roots[0],
            effect_private_root=roots[1],
            gug393_private_root=roots[2],
            gug395_private_root=roots[3],
            clock=lambda: datetime(2026, 8, 28, 1, 15, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("admission", "effect"),
        ("admission", "gug393"),
        ("admission", "gug395"),
        ("effect", "gug393"),
        ("effect", "gug395"),
        ("gug393", "gug395"),
    ],
)
def test_context_forbids_any_private_root_reuse(
    tmp_path: Path,
    left: str,
    right: str,
) -> None:
    admission_root = _root(tmp_path, "admission")
    effect_root = _root(tmp_path, "effect")
    gug393_root = _root(tmp_path, "gug393")
    gug395_root = _root(tmp_path, "gug395")
    request395 = _persist_gug395(gug395_root)
    _persist_gug393(gug393_root, request395)
    roots = {
        "admission": admission_root,
        "effect": effect_root,
        "gug393": gug393_root,
        "gug395": gug395_root,
    }
    roots[right] = roots[left]

    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_ROOT_REUSE_FORBIDDEN",
    ):
        subject.materialize_atomic_collision_context(
            admission_private_root=roots["admission"],
            effect_private_root=roots["effect"],
            gug393_private_root=roots["gug393"],
            gug395_private_root=roots["gug395"],
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            approved_operation=APPROVED_OPERATION,
            authorized_at=NOT_BEFORE,
            expires_at=EXPIRES_AT,
            clock=lambda: NOW,
        )


def test_context_builds_only_the_local_direct_sso_execution_locus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        admission_root,
        effect_root,
        gug393_root,
        gug395_root,
        _context,
    ) = _materialized_roots(tmp_path)
    opener_factory = object()
    monkeypatch.setattr(
        subject,
        "build_direct_sso_policy_session_opener_factory",
        lambda **_kwargs: opener_factory,
    )
    monkeypatch.setattr(
        subject,
        "build_atomic_route_collision_admission_loader",
        lambda *, config: config,
    )

    config = subject.build_atomic_loader_from_private_context(
        admission_private_root=admission_root,
        effect_private_root=effect_root,
        gug393_private_root=gug393_root,
        gug395_private_root=gug395_root,
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_authorized_at=NOT_BEFORE,
        expected_expires_at=EXPIRES_AT,
        expected_operation=APPROVED_OPERATION,
        expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
        environment={},
        clock=lambda: NOW,
    )

    assert config.execution_locus == subject.admission.LOCAL_ATOMIC_CLI
    assert config.session_opener_factory is opener_factory
    assert config.approval_reference_digest == APPROVAL_REFERENCE_DIGEST
    assert config.approved_operation == APPROVED_OPERATION
    _replace_gug395_with_valid_absent_result(gug395_root)
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_GUG395_LINEAGE_CHANGED",
    ):
        config.identity_bindings_factory(
            private_root=gug395_root,
            collision_policy_set=(
                collision_policy.materialize_route_collision_policy_set(
                    config.catalog
                )
            ),
            session_mode=subject.LOCAL_DIRECT_SSO,
        )


def test_context_builder_rejects_authorization_mismatch_before_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = _materialized_roots(tmp_path)
    adapter_called = False

    def _adapter(**_kwargs: Any) -> object:
        nonlocal adapter_called
        adapter_called = True
        return object()

    monkeypatch.setattr(
        subject,
        "build_direct_sso_policy_session_opener_factory",
        _adapter,
    )
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_AUTHORIZATION_BINDING_INVALID",
    ):
        subject.build_atomic_loader_from_private_context(
            admission_private_root=roots[0],
            effect_private_root=roots[1],
            gug393_private_root=roots[2],
            gug395_private_root=roots[3],
            expected_approval_reference_digest=canonical_digest(
                {"approval": "wrong"}
            ),
            expected_authorized_at=NOT_BEFORE,
            expected_expires_at=EXPIRES_AT,
            expected_operation=APPROVED_OPERATION,
            expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
            environment={},
            clock=lambda: NOW,
        )
    assert adapter_called is False


def test_context_builder_rejects_source_mismatch_before_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = _materialized_roots(tmp_path)
    adapter_called = False

    def _adapter(**_kwargs: Any) -> object:
        nonlocal adapter_called
        adapter_called = True
        return object()

    monkeypatch.setattr(
        subject,
        "build_direct_sso_policy_session_opener_factory",
        _adapter,
    )
    with pytest.raises(
        subject.AtomicCollisionContextError,
        match="ATOMIC_COLLISION_SOURCE_BINDING_INVALID",
    ):
        subject.build_atomic_loader_from_private_context(
            admission_private_root=roots[0],
            effect_private_root=roots[1],
            gug393_private_root=roots[2],
            gug395_private_root=roots[3],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            expected_authorized_at=NOT_BEFORE,
            expected_expires_at=EXPIRES_AT,
            expected_operation=APPROVED_OPERATION,
            expected_source_commit_sha="f" * 40,
            environment={},
            clock=lambda: NOW,
        )
    assert adapter_called is False


def test_atomic_loader_rejects_valid_lineage_swap_before_session_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = _materialized_roots(tmp_path)
    session_open_started = False

    def _session_opener_factory(*_args: Any) -> object:
        nonlocal session_open_started
        session_open_started = True
        raise AssertionError("session opener must remain unreachable")

    monkeypatch.setattr(
        subject,
        "build_direct_sso_policy_session_opener_factory",
        lambda **_kwargs: _session_opener_factory,
    )
    loader = subject.build_atomic_loader_from_private_context(
        admission_private_root=roots[0],
        effect_private_root=roots[1],
        gug393_private_root=roots[2],
        gug395_private_root=roots[3],
        expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
        expected_authorized_at=NOT_BEFORE,
        expected_expires_at=EXPIRES_AT,
        expected_operation=APPROVED_OPERATION,
        expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
        environment={},
        clock=lambda: NOW,
    )
    _replace_gug395_with_valid_absent_result(roots[3])
    effect_request = {"effect": "synthetic-foundation-dispatch"}

    with pytest.raises(
        atomic_admission.AtomicCollisionAdmissionError,
        match="ATOMIC_COLLISION_GUG395_LINEAGE_CHANGED",
    ):
        atomic_admission.invoke_route_collision_admission_loader(
            loader,
            operation=APPROVED_OPERATION,
            effect_request=effect_request,
            effect_request_digest=canonical_digest(effect_request),
            bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
            now=NOW,
        )
    assert session_open_started is False


def test_context_builder_rejects_lineage_swap_before_sdk_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = _materialized_roots(tmp_path)
    original_read = subject.read_atomic_collision_context
    sdk_load_started = False

    def read_then_swap(**kwargs: Any) -> dict[str, Any]:
        context = original_read(**kwargs)
        _replace_gug395_with_valid_absent_result(roots[3])
        return context

    def sdk_must_not_load(_root: Path) -> object:
        nonlocal sdk_load_started
        sdk_load_started = True
        raise AssertionError("SDK cache must remain unreachable")

    monkeypatch.setattr(subject, "read_atomic_collision_context", read_then_swap)
    monkeypatch.setattr(direct_sso.live, "_load_sdk", sdk_must_not_load)

    with pytest.raises(
        direct_sso.DirectSsoCollisionAdapterError,
        match="COLLISION_DIRECT_SSO_GUG395_LINEAGE_CHANGED",
    ):
        subject.build_atomic_loader_from_private_context(
            admission_private_root=roots[0],
            effect_private_root=roots[1],
            gug393_private_root=roots[2],
            gug395_private_root=roots[3],
            expected_approval_reference_digest=APPROVAL_REFERENCE_DIGEST,
            expected_authorized_at=NOT_BEFORE,
            expected_expires_at=EXPIRES_AT,
            expected_operation=APPROVED_OPERATION,
            expected_source_commit_sha=gug395_data.SOURCE_COMMIT,
            environment={},
            clock=lambda: NOW,
        )
    assert sdk_load_started is False


def _load_cli() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gug376_collision_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_context_cli_requires_persisted_gug393_custody_and_has_no_manual_file(
) -> None:
    parser = _load_cli()._parser()  # noqa: SLF001
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "materialize-context",
                "--admission-private-root",
                "/tmp/admission",
                "--effect-private-root",
                "/tmp/effect",
                "--gug393-private-root",
                "/tmp/gug393",
                "--bootstrap-intent-digest",
                "sha256:" + "1" * 64,
            ]
        )
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "materialize-context",
                "--admission-private-root",
                "/tmp/admission",
                "--effect-private-root",
                "/tmp/effect",
                "--gug393-private-root",
                "/tmp/gug393",
                "--gug395-private-root",
                "/tmp/gug395",
                "--approval-reference-digest",
                "sha256:" + "2" * 64,
                "--approved-operation",
                APPROVED_OPERATION,
                "--authorized-at",
                NOT_BEFORE,
                "--expires-at",
                EXPIRES_AT,
                "--private-bindings-file",
                "/tmp/forged.json",
                "--bootstrap-intent-digest",
                "sha256:" + "1" * 64,
            ]
        )
