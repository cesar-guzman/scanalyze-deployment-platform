from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from tooling import platform_authority_plan_permission_repair as repair
from tooling import platform_authority_plan_permission_repair_broker_config as subject
from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import platform_authority_plan_permission_repair_route_broker as broker

from tests.test_deployment.gug376_foundation_fixtures import (
    build_foundation_contract,
    build_pep_signed_receipt,
    build_template_readback,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "a" * 40
NOW = datetime(2026, 8, 30, 20, 0, tzinfo=timezone.utc)
CHANGE_SET_NAME = "scanalyze-platform-authority-bootstrap-20260830200000"


class FakeGit:
    def read_at(self, commit: str, path: str) -> bytes:
        assert commit == SOURCE_COMMIT
        return (REPO_ROOT / path).read_bytes()

    def tree_at(self, commit: str) -> str:
        assert commit == SOURCE_COMMIT
        return "b" * 40


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result[field] = subject.route.digest_value(result)
    return result


def _snapshot() -> dict[str, Any]:
    policy_template = json.loads(
        (REPO_ROOT / subject._POLICY_TEMPLATE_PATH).read_text(encoding="utf-8")
    )
    target = repair.render_bootstrap_iam_policy(
        policy_template=policy_template,
        binding=repair._bootstrap_binding(),  # noqa: SLF001
        change_set_name=CHANGE_SET_NAME,
    )
    predecessor = repair.render_predecessor_policy(target)
    return _seal(
        {
            "schema_version": 1,
            "record_type": subject.PLAN_SNAPSHOT_RECORD_TYPE,
            "source_commit": SOURCE_COMMIT,
            "bootstrap_change_set_name": CHANGE_SET_NAME,
            "management_account_id": subject.route.MANAGEMENT_ACCOUNT_ID,
            "authority_account_id": subject.route.AUTHORITY_ACCOUNT_ID,
            "region": subject.route.REGION,
            "identity_center_instance_arn": (
                "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
            ),
            "identity_store_id": "d-1234567890",
            "identity_store_arn": (
                "arn:aws:identitystore::839393571433:identitystore/d-1234567890"
            ),
            "principal_id": "12345678-1234-4123-8123-123456789012",
            "principal_user_arn": (
                "arn:aws:identitystore:::user/"
                "12345678-1234-4123-8123-123456789012"
            ),
            "permission_set_arn": (
                "arn:aws:sso:::permissionSet/ssoins-ABCDEFGHIJKLMNOP/"
                "ps-ABCDEFGHIJKLMNOP"
            ),
            "permission_set_description": "Exact reviewed Plan permission set",
            "permission_set_tags": {
                "managed_by": "terraform",
                "service": "scanalyze-platform-authority",
            },
            "current_policy_digest": repair.canonical_digest(predecessor),
            "desired_policy_digest": repair.canonical_digest(target),
            "generated_role_arn": (
                "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789ABCDEF"
            ),
            "generated_role_name": (
                "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_0123456789ABCDEF"
            ),
            "saml_provider_arn": (
                "arn:aws:iam::042360977644:saml-provider/"
                "AWSSSO_scanalyze_DO_NOT_DELETE"
            ),
            "identity_center_kms_mode": "AWS_OWNED_KMS_KEY",
            "identity_center_kms_key_arn": None,
            "authority_verifier": {
                "profile": "042360977644_AWSReadOnlyAccess",
                "account_id": "042360977644",
                "caller_arn": (
                    "arn:aws:sts::042360977644:assumed-role/"
                    "AWSReservedSSO_AWSReadOnlyAccess_0123456789ABCDEF/cesar"
                ),
                "region": "us-east-1",
            },
            "identity_center_verifier": {
                "profile": "839393571433_ReadOnlyAccess",
                "account_id": "839393571433",
                "caller_arn": (
                    "arn:aws:sts::839393571433:assumed-role/"
                    "AWSReservedSSO_AWSReadOnlyAccess_"
                    "0123456789FEDCBA/cesar"
                ),
                "region": "us-east-1",
            },
            "observed_at": subject._stamp(NOW),  # noqa: SLF001
            "aws_calls": 24,
            "aws_mutations": 0,
            "production_status": "NO-GO",
        },
        "snapshot_digest",
    )


def _input() -> dict[str, Any]:
    foundation = build_foundation_contract(
        source_commit=SOURCE_COMMIT,
        observed_at=NOW,
    )
    pep_receipt = build_pep_signed_receipt(
        source_commit=SOURCE_COMMIT,
        observed_at=NOW,
        bootstrap_intent=foundation["bootstrap_intent"],
        foundation_publish_binding=deepcopy(
            foundation["foundation_publish_binding"]
        ),
    )
    return _seal(
        {
            "schema_version": 1,
            "record_type": subject.RECORD_TYPE,
            "source_commit": SOURCE_COMMIT,
            "route_not_before": "2026-08-30T19:45:00Z",
            "route_not_after": "2026-08-30T21:00:00Z",
            "repair_not_before": "2026-08-30T20:00:00Z",
            "repair_not_after": "2026-08-30T20:15:00Z",
            "bootstrap_change_set_name": CHANGE_SET_NAME,
            "artifact_bootstrap_intent": foundation["bootstrap_intent"],
            "foundation_publish_binding": foundation[
                "foundation_publish_binding"
            ],
            "plan_snapshot": _snapshot(),
            "template_readbacks": {
                "route_template": {},
                "delegation_template": {},
                "pep_template": {},
                "pep_protection_template": {},
            },
            "broker_artifact_handoff": {},
            "pep_signed_artifact_receipt": pep_receipt,
            "production_authorized": False,
        },
        "input_digest",
    )


def _unbound_input() -> dict[str, Any]:
    value = _input()
    value.pop("plan_snapshot")
    value.pop("input_digest")
    return _seal(value, "input_digest")


def test_binds_independent_snapshot_to_sealed_private_draft() -> None:
    snapshot = _snapshot()
    result = subject.bind_plan_snapshot(
        _unbound_input(), plan_snapshot=snapshot, now=NOW
    )

    assert result["plan_snapshot"] == snapshot
    assert result["bootstrap_change_set_name"] == CHANGE_SET_NAME
    assert result["input_digest"] == subject.route.digest_value(
        {key: item for key, item in result.items() if key != "input_digest"}
    )


def test_reader_role_source_contract_digests_match_committed_templates() -> None:
    management = subject._reader_role_source_digests(  # noqa: SLF001
        (REPO_ROOT / subject.route.ROUTE_TEMPLATE_PATH).read_bytes(),
        logical_id="ManagementCollisionReaderRole",
    )
    authority = subject._reader_role_source_digests(  # noqa: SLF001
        (REPO_ROOT / subject.seed.SOURCE_TEMPLATE_PATH).read_bytes(),
        logical_id="AuthorityCollisionReaderRole",
    )

    assert management == (
        broker.MANAGEMENT_COLLISION_READER_POLICY_SOURCE_CONTRACT_DIGEST,
        broker.MANAGEMENT_COLLISION_READER_TRUST_SOURCE_CONTRACT_DIGEST,
    )
    assert authority == (
        broker.AUTHORITY_COLLISION_READER_POLICY_SOURCE_CONTRACT_DIGEST,
        broker.AUTHORITY_COLLISION_READER_TRUST_SOURCE_CONTRACT_DIGEST,
    )


@pytest.mark.parametrize("variant", ["embedded", "missing", "change-set"])
def test_snapshot_binding_rejects_duplicate_missing_or_mismatched_authority(
    variant: str,
) -> None:
    draft = _unbound_input()
    snapshot: Mapping[str, Any] = _snapshot()
    if variant == "embedded":
        draft = _input()
    elif variant == "missing":
        snapshot = {}
    else:
        candidate = deepcopy(dict(snapshot))
        candidate["bootstrap_change_set_name"] = (
            "scanalyze-platform-authority-bootstrap-plan-other"
        )
        candidate["snapshot_digest"] = subject.route.digest_value(
            {
                key: item
                for key, item in candidate.items()
                if key != "snapshot_digest"
            }
        )
        snapshot = candidate

    with pytest.raises(subject.BrokerConfigMaterializationError):
        subject.bind_plan_snapshot(
            draft, plan_snapshot=snapshot, now=NOW
        )


def _materialize(monkeypatch: pytest.MonkeyPatch, value: Mapping[str, Any]) -> dict[str, Any]:
    storage = value["foundation_publish_binding"]
    paths = {
        "route_template": subject.route.ROUTE_TEMPLATE_PATH,
        "delegation_template": subject.route.DELEGATION_TEMPLATE_PATH,
        "pep_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "pep_protection_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
    }
    receipts = {
        kind: build_template_readback(
            artifact_kind=kind,
            source_commit=SOURCE_COMMIT,
            observed_at=NOW,
            artifact_payload=(REPO_ROOT / paths[kind]).read_bytes(),
            foundation_publish_binding=storage,
        )
        for kind in value["template_readbacks"]
    }
    pep_digest = value["pep_signed_artifact_receipt"]["receipt_digest"]
    monkeypatch.setattr(
        subject.template_readback,
        "validate_template_readback_receipt",
        lambda _value, *, artifact_kind, **_kwargs: receipts[artifact_kind],
    )
    monkeypatch.setattr(
        subject,
        "_validate_handoff",
        lambda *_args, **_kwargs: {
            "handoff_digest": "sha256:" + "c" * 64,
            "broker_code": {"upstream_storage_binding": storage},
            "pep_runtime_binding": {
                "pep_signed_artifact_receipt_digest": pep_digest,
                "upstream_storage_binding_digest": storage[
                    "binding_digest"
                ],
            },
        },
    )
    monkeypatch.setattr(
        subject.pep_artifact,
        "validate_signed_artifact_receipt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(subject.seed, "validate_input", lambda item: dict(item))
    return subject.materialize_broker_seed_input(
        value,
        git=FakeGit(),
        expected_storage_binding=storage,
        now=NOW,
    )


def test_materializes_exact_runtime_config_with_update_previous_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _materialize(monkeypatch, _input())
    config = result["broker_config"]
    validated = broker.BrokerConfig.from_mapping(config)
    envelope = broker.encode_runtime_config(config)
    # Keep explicit headroom inside the Lambda 4,096-byte aggregate
    # environment quota; the seed parser's 3,800-byte hard ceiling is only a
    # final fail-closed bound.
    assert len(broker.canonical_json(envelope).encode("utf-8")) <= 3_500
    assert validated.source_commit == SOURCE_COMMIT
    assert config["recovery_not_after"] == "2026-08-31T21:00:00Z"
    assert validated.recovery_not_after == datetime(
        2026, 8, 31, 21, 0, tzinfo=timezone.utc
    )
    assert config["normal_plan_generated_role_name"] == (
        _snapshot()["generated_role_name"]
    )
    assert config["normal_plan_generated_role_arn"] == (
        _snapshot()["generated_role_arn"]
    )
    assert validated.normal_plan_generated_role_name == (
        _snapshot()["generated_role_name"]
    )
    assert validated.normal_plan_generated_role_arn == (
        _snapshot()["generated_role_arn"]
    )
    route_update = config["requests"]["seed-revoke-create-v1"]["Parameters"]
    explicit = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in route_update
        if "ParameterValue" in item
    }
    assert explicit == {
        "SeedAssignmentsEnabled": "false",
        "BrokerInvokerAssignmentEnabled": "true",
    }
    assert all(
        item == {"ParameterKey": item["ParameterKey"], "UsePreviousValue": True}
        for item in route_update
        if item["ParameterKey"] not in explicit
    )
    pep_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in config["requests"]["pep-create-v1"]["Parameters"]
    }
    assert pep_parameters["RepairInvokerPermissionSetArn"] == (
        broker.REPAIR_INVOKER_PERMISSION_SET_SENTINEL
    )
    assert pep_parameters["ImmutableConfigurationDigest"] == (
        subject.DYNAMIC_IMMUTABLE_DIGEST_SENTINEL
    )
    assert "LedgerDeletionProtectionEnabled" not in pep_parameters
    protection_request = config["requests"]["pep-protection-create-v1"]
    assert protection_request["TemplateURL"] != config["requests"][
        "pep-create-v1"
    ]["TemplateURL"]
    assert protection_request["TemplateURL"].endswith(
        "cfn-platform-authority-bootstrap-plan-repair-pep-protection.yaml"
        "?versionId=pep-protection-template-version-1"
    )
    assert protection_request["Parameters"] == [
        {"ParameterKey": key, "UsePreviousValue": True}
        for key in pep_parameters
    ]
    protection_changes = config["creator_contracts"][
        "pep-protection-create-v1"
    ]["expected_changes"]
    assert [item["logical_resource_id"] for item in protection_changes] == list(
        seed.PEP_LIFECYCLE_RESOURCE_IDS
    )
    repair_ledger = next(
        item
        for item in protection_changes
        if item["logical_resource_id"] == "RepairLedger"
    )
    assert repair_ledger["scope"] == [
        "DeletionPolicy",
        "Properties",
        "UpdateReplacePolicy",
    ]
    assert repair_ledger["details"] == [
        {
            "target_attribute": "DeletionPolicy",
            "target_name": None,
            "requires_recreation": None,
            "evaluation": "Static",
            "change_source": "DirectModification",
            "causing_entity": None,
        },
        {
            "target_attribute": "Properties",
            "target_name": "DeletionProtectionEnabled",
            "requires_recreation": "Never",
            "evaluation": "Static",
            "change_source": "DirectModification",
            "causing_entity": None,
        },
        {
            "target_attribute": "UpdateReplacePolicy",
            "target_name": None,
            "requires_recreation": None,
            "evaluation": "Static",
            "change_source": "DirectModification",
            "causing_entity": None,
        },
    ]
    assert config["terminal_expectations"]["seed-revoke-execute-v1"][
        "expected_static_outputs"
    ]["SeedAssignmentMode"] == "false"
    assert config["permission_set_output_contracts"]["route"][
        "required_mode_outputs"
    ]["SeedAssignmentMode"] == "true"


def test_rejects_resealed_policy_source_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _input()
    snapshot = deepcopy(value["plan_snapshot"])
    snapshot["desired_policy_digest"] = "sha256:" + "f" * 64
    snapshot.pop("snapshot_digest")
    snapshot = _seal(snapshot, "snapshot_digest")
    value["plan_snapshot"] = snapshot
    value.pop("input_digest")
    value = _seal(value, "input_digest")
    with pytest.raises(subject.BrokerConfigMaterializationError, match="POLICY_SOURCE_BINDING_INVALID"):
        _materialize(monkeypatch, value)


def test_rejects_pep_storage_binding_drift_from_template_and_broker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = _input()
    storage = value["pep_signed_artifact_receipt"][
        "upstream_storage_binding"
    ]
    storage["bucket"] = "foreign-artifacts"
    storage["binding_digest"] = seed.digest_value(
        {
            key: item
            for key, item in storage.items()
            if key != "binding_digest"
        }
    )
    value.pop("input_digest")
    value = _seal(value, "input_digest")
    with pytest.raises(
        subject.BrokerConfigMaterializationError,
        match="PEP_ARTIFACT_BINDING_INVALID",
    ):
        _materialize(monkeypatch, value)


def test_rejects_stale_snapshot_and_unapproved_verifier_profile() -> None:
    value = _snapshot()
    value["observed_at"] = subject._stamp(NOW - timedelta(minutes=16))  # noqa: SLF001
    value.pop("snapshot_digest")
    value = _seal(value, "snapshot_digest")
    with pytest.raises(subject.BrokerConfigMaterializationError, match="PLAN_SNAPSHOT_STALE"):
        subject.validate_plan_snapshot(value, source_commit=SOURCE_COMMIT, now=NOW)

    value = _snapshot()
    value["authority_verifier"]["profile"] = "default"
    value.pop("snapshot_digest")
    value = _seal(value, "snapshot_digest")
    with pytest.raises(subject.BrokerConfigMaterializationError, match="PLAN_SNAPSHOT_INVALID"):
        subject.validate_plan_snapshot(value, source_commit=SOURCE_COMMIT, now=NOW)
