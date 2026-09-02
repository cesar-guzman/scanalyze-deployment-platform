from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from tooling import platform_authority_change_set_retirement_package as broker_package
from tooling import (
    platform_authority_gug365_upstream_prerequisites as gug365_upstream,
)
from tooling import platform_authority_gug395_preplan_seed as subject
from tooling import platform_authority_retirement_ledger_factory_package as factory_package
from tooling import (
    platform_authority_retirement_entrypoint_service_role_materializer as gug365_service,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "1" * 40
SOURCE_TREE = "2" * 40
CREATED_AT = "2026-08-27T23:50:00Z"


@pytest.fixture(autouse=True)
def _synthetic_clean_source_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    def verify(**kwargs: object) -> object:
        required = kwargs["required_source_digests"]
        sources = [
            {"repository_path": path, "content_digest": digest}
            for path, digest in sorted(required.items())
        ]
        record: dict[str, object] = {
            "record_type": subject.source_verifier.RECORD_TYPE,
            "schema_version": 1,
            "verifier_id": subject.source_verifier.VERIFIER_ID,
            "expected_remote_ref": subject.EXPECTED_REMOTE_REF,
            "source_commit_sha": kwargs["expected_commit_sha"],
            "source_tree_sha": kwargs["expected_tree_sha"],
            "remote_ref_commit_sha": kwargs["expected_commit_sha"],
            "checkout_clean": True,
            "required_source_count": len(sources),
            "required_source_set_digest": subject.canonical_digest(sources),
            "repository_tree_entries_digest": subject.canonical_digest(
                {"tree": kwargs["expected_tree_sha"]}
            ),
            "aws_calls": 0,
            "aws_mutations": 0,
        }
        record["verification_digest"] = subject.canonical_digest(record)
        return subject.source_verifier.RepositorySourceVerification(
            document=record
        )

    monkeypatch.setattr(
        subject.source_verifier, "verify_clean_repository_source", verify
    )


def _package_manifests() -> tuple[dict[str, object], dict[str, object]]:
    broker_sources = {
        path: (REPO_ROOT / path).read_bytes() for path in broker_package.SOURCE_PATHS
    }
    factory_sources = {
        path: (REPO_ROOT / path).read_bytes() for path in factory_package.SOURCE_PATHS
    }
    broker = broker_package.build_retirement_package(
        source_root=REPO_ROOT,
        source_commit=SOURCE_COMMIT,
        broker_runtime_version_arn=(
            "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
        ),
        broker_version_binding_sha256=subject.canonical_digest(
            {"binding": "gug395-test"}
        ),
        committed_sources=broker_sources,
    )
    factory = factory_package.build_ledger_factory_package(
        source_root=REPO_ROOT,
        source_commit=SOURCE_COMMIT,
        runtime_version_arn=(
            "arn:aws:lambda:us-east-1::runtime:" + "b" * 64
        ),
        committed_sources=factory_sources,
    )
    return copy.deepcopy(broker.manifest), copy.deepcopy(factory.manifest)


def _owner_values() -> dict[str, str]:
    return {
        "artifact_bucket_name": (
            "scanalyze-g376-art-111111111111-"
            "042360977644-us-east-1-an"
        ),
        "authority_account_id": "042360977644",
        "kms_alias_name": "alias/scanalyze-gug395",
        "kms_admin_principal_arn": "arn:aws:iam::042360977644:root",
        "artifact_bucket_policy_principal_arn": (
            "arn:aws:iam::042360977644:root"
        ),
        "identity_center_application_name": "ScanalyzeAuthorityRetirement",
        "identity_center_redirect_uri": "http://127.0.0.1:18443/callback",
        "identity_center_application_provider_arn": (
            "arn:aws:sso::aws:applicationProvider/custom"
        ),
        "identity_center_instance_arn": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "identity_store_user_id": (
            "0123456789-12345678-1234-1234-1234-1234567890ab"
        ),
        "authority_target_id": "042360977644",
        "classifier_permission_set_name": "ScanalyzeAuthorityRetireClass",
        "approver_permission_set_name": "ScanalyzeAuthorityRetireApprove",
        "signing_profile_name": "scanalyze_gug395",
        **subject._expected_unsigned_object_keys(SOURCE_COMMIT),
    }


def _owner_input() -> dict[str, object]:
    values = _owner_values()
    decisions: list[dict[str, object]] = []
    derived = set(subject._expected_unsigned_object_keys(SOURCE_COMMIT))
    for key in subject.REQUIRED_DECISION_KEYS:
        decisions.append(
            {
                "key": key,
                "value": values[key],
                "provenance": {
                    "kind": (
                        "REPOSITORY_SOURCE" if key in derived else "OWNER_DECISION"
                    ),
                    "source_digest": subject.canonical_digest({"key": key}),
                    "source_pointer": f"/decisions/{key}",
                },
                "impact": "Binds one exact private input.",
                "rollback_boundary": "A change requires a new seed.",
            }
        )
    broker_manifest, factory_manifest = _package_manifests()
    record: dict[str, object] = {
        "record_type": subject.OWNER_INPUT_TYPE,
        "schema_version": 1,
        "source_commit_sha": SOURCE_COMMIT,
        "source_tree_sha": SOURCE_TREE,
        "decisions": decisions,
        "artifact_inputs": [
            {"package": "broker", "package_manifest": broker_manifest},
            {
                "package": "ledger_factory",
                "package_manifest": factory_manifest,
            },
        ],
    }
    record["owner_input_digest"] = subject.canonical_digest(record)
    return record


def _seed_with_source() -> tuple[
    dict[str, object], subject.VerifiedRepositorySource
]:
    owner = _owner_input()
    verified_source = subject.verify_repository_source_binding(
        owner_input=owner, repo_root=REPO_ROOT
    )
    seed = subject.build_preplan_seed(
        owner_input=owner,
        private_custody_digest=subject.canonical_digest("/private/gug395"),
        verified_source=verified_source,
    )
    return seed, verified_source


def _seed() -> dict[str, object]:
    return _seed_with_source()[0]


def _build_seed(
    owner: dict[str, object], *, custody_digest: str | None = None
) -> dict[str, object]:
    return subject.build_preplan_seed(
        owner_input=owner,
        private_custody_digest=(
            custody_digest or subject.canonical_digest("/private/gug395")
        ),
        verified_source=subject.verify_repository_source_binding(
            owner_input=owner, repo_root=REPO_ROOT
        ),
    )


def _reseal(record: dict[str, object], field: str) -> None:
    record.pop(field, None)
    record[field] = subject.canonical_digest(record)


def test_catalog_exposes_exact_closed_counts_and_real_gaps() -> None:
    summary = subject.public_catalog_summary()
    assert summary["phase_count"] == 9
    assert summary["operation_count"] == 30
    assert summary["provider_slot_count"] == 22
    assert summary["routed_provider_slot_count"] == 8
    assert summary["missing_provider_route_count"] == 14
    assert summary["source_contract_gap_count"] == 6
    assert summary["live_execution_ready"] is False
    assert summary["aws_calls"] == summary["aws_mutations"] == 0


def test_seed_is_deterministic_under_mapping_reordering() -> None:
    first = _owner_input()
    second = {
        key: copy.deepcopy(value) for key, value in reversed(list(first.items()))
    }
    second["decisions"] = [
        {key: value for key, value in reversed(list(item.items()))}
        for item in first["decisions"]
    ]
    _reseal(second, "owner_input_digest")
    custody = subject.canonical_digest("/private/gug395")
    assert _build_seed(first, custody_digest=custody) == _build_seed(
        second, custody_digest=custody
    )


def test_seed_requires_the_opaque_clean_source_capability() -> None:
    with pytest.raises(
        subject.PreplanSeedError, match="SOURCE_VERIFICATION_REQUIRED"
    ):
        subject.build_preplan_seed(
            owner_input=_owner_input(),
            private_custody_digest=subject.canonical_digest(
                "/private/gug395"
            ),
            verified_source=None,  # type: ignore[arg-type]
        )


def test_seed_fails_if_source_reverification_becomes_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _owner_input()
    capability = subject.verify_repository_source_binding(
        owner_input=owner, repo_root=REPO_ROOT
    )

    def unavailable(**_: object) -> object:
        raise subject.source_verifier.RepositorySourceVerificationError(
            "SOURCE_CHECKOUT_CHANGED"
        )

    monkeypatch.setattr(
        subject.source_verifier,
        "verify_clean_repository_source",
        unavailable,
    )
    with pytest.raises(subject.PreplanSeedError, match="SOURCE_CHECKOUT_CHANGED"):
        subject.build_preplan_seed(
            owner_input=owner,
            private_custody_digest=subject.canonical_digest(
                "/private/gug395"
            ),
            verified_source=capability,
        )


def test_seed_requires_exact_sixteen_ordered_input_values() -> None:
    owner = _owner_input()
    owner["decisions"] = owner["decisions"][:-1]
    _reseal(owner, "owner_input_digest")
    with pytest.raises(subject.PreplanSeedError, match="DECISIONS_INVALID"):
        _build_seed(owner)


def test_seed_reports_fourteen_owner_two_derived_and_sixteen_bound_values() -> None:
    seed = _seed()
    assert seed["owner_decision_count"] == 14
    assert seed["derived_binding_count"] == 2
    assert seed["bound_value_count"] == 16


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("identity_center_application_name", "A" * 101),
        ("signing_profile_name", "profile-with-dash"),
        ("signing_profile_name", "A" * 65),
    ),
)
def test_seed_rejects_names_outside_downstream_domains(
    key: str, value: str
) -> None:
    owner = _owner_input()
    decision = next(item for item in owner["decisions"] if item["key"] == key)
    decision["value"] = value
    _reseal(owner, "owner_input_digest")
    with pytest.raises(subject.PreplanSeedError, match="DECISION_NAME_INVALID"):
        _build_seed(owner)


@pytest.mark.parametrize(
    "bucket_name",
    [
        "scanalyze-g376-art-111111111111-042360977644-us-east-1",
        "scanalyze-g376-art-11111111111g-042360977644-us-east-1-an",
        "scanalyze-g376-art-111111111111-123456789012-us-east-1-an",
        "scanalyze-g376-art-111111111111-042360977644-us-west-2-an",
        "scanalyze-gug395-example",
    ],
)
def test_seed_requires_the_exact_account_regional_bucket_name_pattern(
    bucket_name: str,
) -> None:
    owner = _owner_input()
    decision = next(
        item
        for item in owner["decisions"]
        if item["key"] == "artifact_bucket_name"
    )
    decision["value"] = bucket_name
    _reseal(owner, "owner_input_digest")

    with pytest.raises(subject.PreplanSeedError, match="DECISION_BUCKET_INVALID"):
        _build_seed(owner)


def test_owner_identity_domains_match_the_gug365_consumer() -> None:
    owner = _owner_input()
    application = next(
        item
        for item in owner["decisions"]
        if item["key"] == "identity_center_application_name"
    )
    application["value"] = "A"
    _reseal(owner, "owner_input_digest")

    seed = _build_seed(owner)
    owner_values = {
        str(item["key"]): str(item["value"]) for item in seed["decisions"]
    }
    gug365_upstream._validate_identity_owner_values(owner_values)
    gug365_upstream._validate_request_payload(
        "KMS_FOUNDATION",
        "kms:CreateAlias",
        {
            "AliasName": owner_values["kms_alias_name"],
            "TargetKeyId": "synthetic-target-key-id",
        },
    )
    assert owner_values["identity_center_application_name"] == "A"


def test_seed_and_gug365_both_reject_provider_arn_with_underscore() -> None:
    owner = _owner_input()
    provider = next(
        item
        for item in owner["decisions"]
        if item["key"] == "identity_center_application_provider_arn"
    )
    provider["value"] = "arn:aws:sso::aws:applicationProvider/custom_provider"
    _reseal(owner, "owner_input_digest")
    with pytest.raises(subject.PreplanSeedError, match="DECISION_PROVIDER_INVALID"):
        _build_seed(owner)

    owner_values = _owner_values()
    owner_values["identity_center_application_provider_arn"] = str(
        provider["value"]
    )
    with pytest.raises(
        gug365_upstream.UpstreamPrerequisiteError,
        match="IDENTITY_OWNER_DECISION_VALUES_INVALID",
    ):
        gug365_upstream._validate_identity_owner_values(owner_values)


def test_seed_and_gug365_both_reject_non_scanalyze_kms_alias() -> None:
    owner = _owner_input()
    alias = next(
        item for item in owner["decisions"] if item["key"] == "kms_alias_name"
    )
    alias["value"] = "alias/custom-gug395"
    _reseal(owner, "owner_input_digest")
    with pytest.raises(subject.PreplanSeedError, match="DECISION_ALIAS_INVALID"):
        _build_seed(owner)

    with pytest.raises(
        gug365_upstream.UpstreamPrerequisiteError,
        match="KMS_ALIAS_REQUEST_INVALID",
    ):
        gug365_upstream._validate_request_payload(
            "KMS_FOUNDATION",
            "kms:CreateAlias",
            {
                "AliasName": alias["value"],
                "TargetKeyId": "synthetic-target-key-id",
            },
        )


def test_derived_object_keys_are_source_owned_not_caller_mutable() -> None:
    owner = _owner_input()
    decision = owner["decisions"][-1]
    decision["value"] = f"arbitrary/{SOURCE_COMMIT}/factory.zip"
    _reseal(owner, "owner_input_digest")
    with pytest.raises(
        subject.PreplanSeedError, match="OWNER_VALUE_CROSS_BINDING_INVALID"
    ):
        _build_seed(owner)


def test_seed_requires_real_package_manifests_not_digest_summaries() -> None:
    owner = _owner_input()
    owner["artifact_inputs"][0] = {
        "package": "broker",
        "archive_sha256": "a" * 64,
        "lambda_code_sha256": "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=",
        "manifest_digest": subject.canonical_digest("fabricated"),
        "archive_size_bytes": 1,
    }
    _reseal(owner, "owner_input_digest")
    with pytest.raises(
        subject.PreplanSeedError, match="ARTIFACT_PACKAGE_MANIFEST_INVALID"
    ):
        _build_seed(owner)


def test_seed_rejects_package_digest_alias_even_when_manifest_is_resealed() -> None:
    owner = _owner_input()
    manifest = owner["artifact_inputs"][1]["package_manifest"]
    manifest["lambda_code_sha256"] = "A" * 43 + "="
    _reseal(manifest, "manifest_digest")
    _reseal(owner, "owner_input_digest")
    with pytest.raises(subject.PreplanSeedError):
        _build_seed(owner)


def test_seed_validator_rejects_resealed_source_manifest_substitution() -> None:
    seed = _seed()
    seed["source_manifest_digest"] = "sha256:" + "f" * 64
    _reseal(seed, "seed_digest")
    with pytest.raises(subject.PreplanSeedError, match="SEED_CATALOG_DRIFT"):
        subject.validate_preplan_seed(seed)


def test_seed_validator_rechecks_nested_provenance_after_reseal() -> None:
    seed = _seed()
    decision = seed["decisions"][0]
    decision["provenance"]["kind"] = "REPOSITORY_SOURCE"
    _reseal(decision, "decision_digest")
    seed["bound_values_digest"] = subject.canonical_digest(seed["decisions"])
    _reseal(seed, "seed_digest")
    with pytest.raises(subject.PreplanSeedError, match="DECISION_INVALID"):
        subject.validate_preplan_seed(seed)


def test_seed_can_be_bound_to_the_current_private_root_digest() -> None:
    seed = _seed()
    subject.validate_preplan_seed(
        seed, expected_private_custody_digest=seed["private_custody_digest"]
    )
    with pytest.raises(
        subject.PreplanSeedError, match="PRIVATE_CUSTODY_DIGEST_MISMATCH"
    ):
        subject.validate_preplan_seed(
            seed,
            expected_private_custody_digest=subject.canonical_digest("/other"),
        )


def test_pending_plan_is_exact_and_cannot_claim_live_execution() -> None:
    seed = _seed()
    plan = subject.build_mutation_plan(seed=seed)
    assert plan["phase_count"] == 9
    assert plan["operation_count"] == 30
    assert plan["provider_slot_count"] == 22
    assert plan["routed_provider_slot_count"] == 8
    assert plan["missing_provider_route_count"] == 14
    assert plan["source_contract_gap_count"] == 6
    assert plan["request_materialization_status"] == "BLOCKED_SOURCE_CONTRACT_GAPS"
    assert plan["exact_live_plan_materialized"] is False
    assert plan["live_execution_ready"] is False
    auth_method = next(
        item
        for item in plan["operations"]
        if item["operation_kind"] == "PUT_APPLICATION_AUTH_METHOD"
    )
    assert auth_method["source_contract_status"] == "BLOCKED_AUTH_METHOD_SOURCE_GAP"


def test_resealed_plan_splice_fails_exact_recompilation() -> None:
    seed = _seed()
    plan = subject.build_mutation_plan(seed=seed)
    plan["operations"][0]["owner_decision_digests"].reverse()
    _reseal(plan["operations"][0], "request_template_binding_digest")
    _reseal(plan, "plan_digest")
    with pytest.raises(subject.PreplanSeedError, match="PLAN_RECOMPILATION_MISMATCH"):
        subject.validate_mutation_plan(plan, seed=seed)


def test_terminal_handoff_stays_fail_closed_until_provider_gaps_close() -> None:
    seed = _seed()
    plan = subject.build_mutation_plan(seed=seed)
    with pytest.raises(
        subject.PreplanSeedError,
        match="STOP_LIVE_EXECUTION_PLAN_NOT_IMPLEMENTED",
    ):
        subject.validate_terminal_handoff({}, seed=seed, plan=plan)


def test_no_terminal_capability_minter_or_ready_builder_path_exists() -> None:
    assert not hasattr(subject, "verify_terminal_handoff")
    seed = _seed()
    plan = subject.build_mutation_plan(seed=seed)
    verification_digest = subject.canonical_digest(
        "synthetic-terminal-verification"
    )
    capability = subject.VerifiedTerminalHandoff(
        subject._VERIFIED_HANDOFF_SENTINEL,
        {"external_verification_digest": verification_digest},
        verification_digest,
    )
    with pytest.raises(
        subject.PreplanSeedError,
        match="STOP_LIVE_EXECUTION_PLAN_NOT_IMPLEMENTED",
    ):
        subject.build_downstream_checkpoint_receipt(
            seed=seed,
            plan=plan,
            verified_handoff=capability,
            gug363_intent={},
            gug363_plan={},
            broker_package_manifest={},
            broker_package_archive=b"",
            ledger_factory_signing_contract={},
            ledger_factory_package_archive=b"",
            created_at=CREATED_AT,
            repo_root=REPO_ROOT,
        )


def test_terminal_capability_rejects_external_verification_splice() -> None:
    with pytest.raises(
        subject.PreplanSeedError,
        match="TERMINAL_HANDOFF_VERIFICATION_MISMATCH",
    ):
        subject.VerifiedTerminalHandoff(
            subject._VERIFIED_HANDOFF_SENTINEL,
            {
                "external_verification_digest": subject.canonical_digest(
                    "terminal-verifier-a"
                )
            },
            subject.canonical_digest("terminal-verifier-b"),
        )


def test_terminal_capability_snapshots_record_without_caller_alias() -> None:
    verification_digest = subject.canonical_digest("terminal-verifier")
    original = {
        "external_verification_digest": verification_digest,
        "nested": {"run": "a"},
    }
    capability = subject.VerifiedTerminalHandoff(
        subject._VERIFIED_HANDOFF_SENTINEL,
        original,
        verification_digest,
    )

    original["external_verification_digest"] = subject.canonical_digest(
        "replacement-verifier"
    )
    original["nested"]["run"] = "b"
    first_read = capability.record
    first_read["nested"]["run"] = "c"

    assert capability.record == {
        "external_verification_digest": verification_digest,
        "nested": {"run": "a"},
    }


def test_public_ledger_factory_validator_snapshots_each_input_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = {"nested": {"value": "contract"}}
    gug363_plan = {"nested": {"value": "plan"}}
    snapshot_codes: list[str] = []
    original_snapshot = gug365_service._canonical_snapshot

    def record_snapshot(value: object, code: str) -> object:
        snapshot_codes.append(code)
        return original_snapshot(value, code)

    def validate_snapshot(**kwargs: object) -> None:
        contract_snapshot = kwargs["contract"]
        plan_snapshot = kwargs["gug363_plan"]
        assert isinstance(contract_snapshot, dict)
        assert isinstance(plan_snapshot, dict)
        assert contract_snapshot is not contract
        assert plan_snapshot is not gug363_plan
        assert kwargs["repo_root"] == REPO_ROOT
        contract_snapshot["nested"]["value"] = "validated-contract"
        plan_snapshot["nested"]["value"] = "validated-plan"

    monkeypatch.setattr(
        gug365_service, "_canonical_snapshot", record_snapshot
    )
    monkeypatch.setattr(
        gug365_service,
        "_validate_ledger_factory_artifact_signing_contract",
        validate_snapshot,
    )
    gug365_service.validate_ledger_factory_artifact_signing_contract(
        contract=contract,
        expected_contract_digest="sha256:" + "0" * 64,
        gug363_plan=gug363_plan,
        repo_root=REPO_ROOT,
    )
    assert contract == {"nested": {"value": "contract"}}
    assert gug363_plan == {"nested": {"value": "plan"}}
    assert snapshot_codes == [
        "LEDGER_FACTORY_SIGNING_CONTRACT_SNAPSHOT_INVALID",
        "LEDGER_FACTORY_GUG363_PLAN_SNAPSHOT_INVALID",
    ]


def test_public_ledger_factory_validator_has_only_stable_boundary_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        gug365_service.ServiceRoleMaterializationError,
        match="LEDGER_FACTORY_SIGNING_CONTRACT_SNAPSHOT_INVALID",
    ):
        gug365_service.validate_ledger_factory_artifact_signing_contract(
            contract={"non_json": object()},
            expected_contract_digest="sha256:" + "0" * 64,
            gug363_plan={},
            repo_root=REPO_ROOT,
        )

    with pytest.raises(
        gug365_service.ServiceRoleMaterializationError,
        match="LEDGER_FACTORY_REPOSITORY_ROOT_INVALID",
    ):
        gug365_service.validate_ledger_factory_artifact_signing_contract(
            contract={},
            expected_contract_digest="sha256:" + "0" * 64,
            gug363_plan={},
            repo_root=Path("relative-repository"),
        )

    def unexpected_failure(**_: object) -> None:
        raise TypeError("must not escape the public validator")

    monkeypatch.setattr(
        gug365_service,
        "_validate_ledger_factory_artifact_signing_contract",
        unexpected_failure,
    )
    with pytest.raises(
        gug365_service.ServiceRoleMaterializationError,
        match="LEDGER_FACTORY_SIGNING_CONTRACT_VALIDATION_FAILED",
    ):
        gug365_service.validate_ledger_factory_artifact_signing_contract(
            contract={},
            expected_contract_digest="sha256:" + "0" * 64,
            gug363_plan={},
            repo_root=REPO_ROOT,
        )


def test_fresh_gug365_capability_rejects_public_construction() -> None:
    with pytest.raises(
        subject.PreplanSeedError, match="GUG365_FRESH_CHECKPOINT_REQUIRED"
    ):
        subject.VerifiedFreshGug365Checkpoint(
            object(),
            subject.canonical_digest("checkpoint"),
            subject.canonical_digest("handoff"),
            subject.canonical_digest("plan"),
            subject.canonical_digest("downstream-receipt"),
            subject.canonical_digest("downstream-private-manifest"),
            SOURCE_COMMIT,
            SOURCE_TREE,
            subject.canonical_digest("account"),
            subject.canonical_digest("caller"),
            subject.canonical_digest("provider"),
            subject.canonical_digest("inventory"),
            "2026-08-28T00:00:00Z",
            "2026-08-28T00:10:00Z",
        )


def test_post_checkpoint_materializer_rejects_cross_run_plan_splice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = _seed()
    plan = subject.build_mutation_plan(seed=seed)
    decisions = {
        str(item["key"]): str(item["value"])
        for item in seed["decisions"]
    }
    kms_arn = (
        "arn:aws:kms:us-east-1:042360977644:key/"
        "12345678-1234-1234-1234-1234567890ab"
    )
    verification_digest = subject.canonical_digest("terminal-verifier-a")
    phase_certifications = [
        {
            "phase_certification_digest": subject.canonical_digest(
                {"run": "a", "phase": sequence}
            )
        }
        for sequence in range(1, 10)
    ]
    operation_receipts = [
        {
            "operation_receipt_digest": subject.canonical_digest(
                {"run": "a", "operation": sequence}
            )
        }
        for sequence in range(1, 31)
    ]
    terminal_bindings = {
        "broker_package_manifest_digest": subject.canonical_digest(
            "run-a-broker-package"
        ),
        "broker_signing_contract_digest": subject.canonical_digest(
            "run-a-broker-signing"
        ),
        "ledger_factory_package_manifest_digest": subject.canonical_digest(
            "run-a-factory-package"
        ),
        "ledger_factory_signing_contract_digest": subject.canonical_digest(
            "run-a-factory-signing"
        ),
        "gug363_intent_digest": subject.canonical_digest("run-a-intent"),
        "gug363_plan_digest": subject.canonical_digest("run-a-plan"),
    }
    handoff = {
        "external_verification_digest": verification_digest,
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "seed_digest": seed["seed_digest"],
        "plan_digest": plan["plan_digest"],
        "handoff_digest": subject.canonical_digest("run-a-handoff"),
        "execution_ledger_digest": subject.canonical_digest("run-a-ledger"),
        "phase_certifications": phase_certifications,
        "operation_receipts": operation_receipts,
        "provider_slot_binding_set_digest": subject.canonical_digest(
            "run-a-provider-slots"
        ),
        "identity_center_application_name_digest": subject.canonical_digest(
            decisions["identity_center_application_name"]
        ),
        "identity_center_application_provider_arn_digest": (
            subject.canonical_digest(
                decisions["identity_center_application_provider_arn"]
            )
        ),
        "identity_center_kms_key_arn_digest": subject.canonical_digest(kms_arn),
        **terminal_bindings,
    }
    verified_handoff = subject.VerifiedTerminalHandoff(
        subject._VERIFIED_HANDOFF_SENTINEL,
        handoff,
        verification_digest,
    )
    receipt = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/"
            "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    receipt.update(
        status="READY_FOR_GUG365_FRESH_CHECKPOINT",
        evidence_scope="CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
        checkpoint_builder_status="MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF",
        certified_terminal_capability_present=True,
        source_commit_sha=seed["source_commit_sha"],
        source_tree_sha=seed["source_tree_sha"],
        preplan_seed_digest=seed["seed_digest"],
        terminal_verification_digest=verification_digest,
        mutation_plan_digest=plan["plan_digest"],
        terminal_handoff_digest=handoff["handoff_digest"],
        execution_ledger_digest=handoff["execution_ledger_digest"],
        phase_certification_digests=[
            item["phase_certification_digest"]
            for item in phase_certifications
        ],
        operation_receipt_digests=[
            item["operation_receipt_digest"] for item in operation_receipts
        ],
        provider_slot_binding_set_digest=handoff[
            "provider_slot_binding_set_digest"
        ],
        **terminal_bindings,
    )
    receipt["private_manifest_digest"] = subject.canonical_digest(
        subject._downstream_receipt_private_projection(receipt)
    )
    _reseal(receipt, "receipt_digest")
    subject.validate_downstream_materialization_receipt(
        receipt,
        verified_handoff=verified_handoff,
    )

    plan363 = {
        "source": {
            "commit": seed["source_commit_sha"],
            "tree": seed["source_tree_sha"],
        },
        "intent_digest": subject.canonical_digest("run-b-intent"),
        "plan_digest": subject.canonical_digest("run-b-plan"),
        "artifact_signing_contract_digest": subject.canonical_digest(
            "run-b-broker-signing"
        ),
        "artifact_signing_contract": {
            "unsigned_source": {
                "manifest_digest": subject.canonical_digest(
                    "run-b-broker-package"
                )
            }
        },
    }
    plan365 = {
        "plan_digest": subject.canonical_digest("run-b-gug365-plan"),
        "ledger_factory_artifact_signing_contract_digest": (
            subject.canonical_digest("run-b-factory-signing")
        ),
        "ledger_factory_artifact_signing_contract": {
            "package_manifest": {
                "manifest_digest": subject.canonical_digest(
                    "run-b-factory-package"
                )
            }
        },
    }
    checkpoint = subject.VerifiedFreshGug365Checkpoint(
        subject._FRESH_CHECKPOINT_SENTINEL,
        subject.canonical_digest("fresh-gug365-checkpoint"),
        handoff["handoff_digest"],
        plan365["plan_digest"],
        receipt["receipt_digest"],
        receipt["private_manifest_digest"],
        seed["source_commit_sha"],
        seed["source_tree_sha"],
        subject.canonical_digest(decisions["authority_account_id"]),
        subject.canonical_digest("fresh-caller"),
        subject.canonical_digest("fresh-provider"),
        subject.canonical_digest("fresh-inventory"),
        "2026-08-28T00:00:00Z",
        "2026-08-28T00:10:00Z",
    )
    monkeypatch.setattr(subject, "validate_terminal_handoff", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        subject.gug363,
        "validate_materialization_plan",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        subject.gug365,
        "validate_service_role_materialization_plan",
        lambda *args, **kwargs: None,
    )
    with pytest.raises(
        subject.PreplanSeedError,
        match="DOWNSTREAM_PLAN_TERMINAL_BINDING_MISMATCH",
    ):
        subject.materialize_post_checkpoint_source_bundle(
            seed=seed,
            plan=plan,
            verified_handoff=verified_handoff,
            downstream_checkpoint_receipt=receipt,
            fresh_gug365_checkpoint=checkpoint,
            gug363_plan=plan363,
            gug365_plan=plan365,
            identity_center_application_name=decisions[
                "identity_center_application_name"
            ],
            identity_center_application_provider_arn=decisions[
                "identity_center_application_provider_arn"
            ],
            identity_center_kms_key_arn=kms_arn,
            materialized_at="2026-08-28T00:05:00Z",
            repo_root=REPO_ROOT,
        )


def test_public_seed_receipt_is_digest_only_and_self_sealed() -> None:
    seed, verified_source = _seed_with_source()
    receipt = subject.build_preplan_seed_receipt(
        seed=seed,
        verified_source=verified_source,
        created_at=CREATED_AT,
    )
    subject.validate_preplan_seed_receipt(
        receipt, seed=seed, verified_source=verified_source
    )
    rendered = subject.canonical_json(receipt)
    assert "arn:aws:" not in rendered
    assert "042360977644" not in rendered
    assert "/Users/" not in rendered
    assert receipt["verified_source_capability_present"] is True
    assert receipt["live_execution_ready"] is False
    assert receipt["production_status"] == "NO-GO"


def test_materialized_seed_receipt_requires_exact_seed_and_source_capability() -> None:
    seed, verified_source = _seed_with_source()
    receipt = subject.build_preplan_seed_receipt(
        seed=seed,
        verified_source=verified_source,
        created_at=CREATED_AT,
    )
    with pytest.raises(
        subject.PreplanSeedError, match="SOURCE_VERIFICATION_REQUIRED"
    ):
        subject.validate_preplan_seed_receipt(receipt, seed=seed)

    other_seed = _build_seed(
        _owner_input(),
        custody_digest=subject.canonical_digest("/private/other-gug395"),
    )
    with pytest.raises(
        subject.PreplanSeedError, match="SEED_RECEIPT_CAPABILITY_MISMATCH"
    ):
        subject.validate_preplan_seed_receipt(
            receipt,
            seed=other_seed,
            verified_source=verified_source,
        )


def test_private_json_custody_is_create_only_owner_only_and_no_follow(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    value = {"record_type": "synthetic", "digest": subject.canonical_digest("x")}
    subject.write_private_json_create_only(
        private_root=root, filename="record.json", value=value
    )
    target = root / "record.json"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert subject.read_private_json(
        private_root=root, filename="record.json"
    ) == value
    with pytest.raises(subject.PreplanSeedError, match="PRIVATE_ARTIFACT_EXISTS"):
        subject.write_private_json_create_only(
            private_root=root, filename="record.json", value=value
        )

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    os.chmod(outside, 0o600)
    (root / "link.json").symlink_to(outside)
    with pytest.raises(subject.PreplanSeedError):
        subject.read_private_json(private_root=root, filename="link.json")


def test_cli_invalid_created_at_does_not_publish_create_only_seed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    subject.write_private_json_create_only(
        private_root=root,
        filename="owner-input.json",
        value=_owner_input(),
    )
    result = subject.main(
        [
            "seed",
            "--repo-root",
            str(REPO_ROOT),
            "--private-root",
            str(root),
            "--owner-input",
            "owner-input.json",
            "--output",
            "preplan-seed.json",
            "--created-at",
            "not-a-timestamp",
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert "SEED_RECEIPT_TIME_INVALID" in captured.err
    assert not (root / "preplan-seed.json").exists()


def test_cli_catalog_runs_in_isolated_standard_library_mode() -> None:
    script = (
        REPO_ROOT
        / "scripts/deployment/platform-authority-gug395-preplan-seed.py"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", str(script), "catalog"],
        cwd=REPO_ROOT,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    record = json.loads(completed.stdout)
    assert record["aws_calls"] == record["aws_mutations"] == 0
    assert record["live_execution_ready"] is False


def test_module_has_no_live_sdk_network_or_process_imports() -> None:
    source_path = REPO_ROOT / "tooling/platform_authority_gug395_preplan_seed.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
    assert imported.isdisjoint(
        {"boto3", "botocore", "requests", "socket", "subprocess"}
    )
