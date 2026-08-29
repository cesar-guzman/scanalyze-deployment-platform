"""Fail-closed tests for repository-attested protected live inputs."""
from __future__ import annotations

import base64
import copy
import json
import os
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from tooling.authorize_deployment_backend import canonical_digest
from tooling.nonprod_live_input_materializer import (
    LiveInputMaterializationError,
    MAX_ENCODED_REQUEST_BYTES,
    load_repository_claim,
    load_repository_deployment_request,
    materialize_live_inputs,
    persist_materialized_live_inputs,
    stable_sealed_request_digest,
    stage_sealed_request_from_environment,
    validate_repository_deployment_request_binding,
    validate_materialized_live_inputs,
)
from tooling.validate_github_deployment_identity import (
    derive_oidc_subject,
    environment_configuration_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 20, 5, tzinfo=UTC)
CUSTOMER_ID = "cust_" + ("A" * 26)
DEPLOYMENT_ID = "dep_" + ("A" * 26)
EXECUTION_ID = "exec_" + ("A" * 26)
CHANGE_ID = "chg_" + ("A" * 26)
DESTINATION_ACCOUNT_ID = "111222333444"
AUTHORITY_ACCOUNT_ID = "555666777888"
REGION = "us-east-1"
REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
WORKFLOW_SHA = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=REPO_ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()


def _sha(character: str) -> str:
    return "sha256:" + (character * 64)


def _roles() -> dict:
    names = {
        "plan": "ScanalyzeCustomer-Plan",
        "apply": "ScanalyzeCustomer-Apply",
        "identity_plan": "ScanalyzeCustomer-Identity-Plan",
        "identity_apply": "ScanalyzeCustomer-Identity-Apply",
        "promotion": "ScanalyzeCustomer-Promotion",
        "validation": "ScanalyzeCustomer-Validation",
        "diagnostic": "ScanalyzeCustomer-Diagnostic",
        "state_recovery": "ScanalyzeCustomer-StateRecovery",
    }
    return {
        key: {
            "arn": f"arn:aws:iam::{DESTINATION_ACCOUNT_ID}:role/{name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
            "account_id_tag": DESTINATION_ACCOUNT_ID,
            "region_tag": REGION,
            "environment_tag": "dev",
        }
        for key, name in names.items()
    }


def _account_ready() -> dict:
    document = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT_ID,
        "region": REGION,
        "environment": "dev",
        "baseline_version": "v2.1.0",
        "provisioned_at": "2026-08-28T19:30:00Z",
        "roles": _roles(),
        "state_infrastructure": {
            "state_bucket": (
                f"arn:aws:s3:::scanalyze-{DESTINATION_ACCOUNT_ID}-tf-state"
            ),
            "plan_bucket": (
                f"arn:aws:s3:::scanalyze-{DESTINATION_ACCOUNT_ID}-tf-plan"
            ),
            "evidence_bucket": (
                f"arn:aws:s3:::scanalyze-{DESTINATION_ACCOUNT_ID}-tf-evidence"
            ),
            "contracts_bucket": (
                f"arn:aws:s3:::scanalyze-{DESTINATION_ACCOUNT_ID}-contracts"
            ),
            "state_kms_key": (
                f"arn:aws:kms:{REGION}:{DESTINATION_ACCOUNT_ID}:key/"
                "11111111-1111-4111-8111-111111111111"
            ),
            "evidence_kms_key": (
                f"arn:aws:kms:{REGION}:{DESTINATION_ACCOUNT_ID}:key/"
                "22222222-2222-4222-8222-222222222222"
            ),
            "contracts_kms_key": (
                f"arn:aws:kms:{REGION}:{DESTINATION_ACCOUNT_ID}:key/"
                "33333333-3333-4333-8333-333333333333"
            ),
        },
        "controls": {
            "state_versioning_enabled": True,
            "state_default_encryption": "aws:kms",
            "state_bucket_key_enabled": True,
            "state_public_access_blocked": True,
            "state_object_lock_enabled": False,
            "native_lockfile_enabled": True,
            "plan_versioning_enabled": True,
            "plan_default_encryption": "aws:kms",
            "plan_kms_key": (
                f"arn:aws:kms:{REGION}:{DESTINATION_ACCOUNT_ID}:key/"
                "22222222-2222-4222-8222-222222222222"
            ),
            "plan_bucket_key_enabled": True,
            "plan_public_access_blocked": True,
            "plan_lifecycle_days": 1,
        },
    }
    document["contract_digest"] = canonical_digest(document)
    return document


def _sources() -> dict:
    account_ready = _account_ready()
    target = {
        "schema_version": "2",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT_ID,
        "region": REGION,
        "environment": "dev",
        "runtime_origin": {
            "schema_version": "1",
            "domain_name": "app.synthetic.invalid",
        },
        "status": "READY",
        "registry_version": 3,
        "account_ready": {
            "schema_version": "2",
            "baseline_version": account_ready["baseline_version"],
            "contract_digest": account_ready["contract_digest"],
        },
        "state_binding": {
            "state_bucket": account_ready["state_infrastructure"]["state_bucket"],
            "state_kms_key": account_ready["state_infrastructure"]["state_kms_key"],
        },
    }
    target["record_digest"] = canonical_digest(target)
    manifest = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "environment": "dev",
        "aws_account_id": DESTINATION_ACCOUNT_ID,
        "aws_region": REGION,
        "github": {
            "environment": f"scanalyze-{DEPLOYMENT_ID}-dev",
            "oidc_role_arn": (
                f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
                f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
            ),
        },
        "ecr": {"prefix": "synthetic/scanalyze"},
        "base_image_uri": (
            f"{DESTINATION_ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/"
            f"synthetic/base@{_sha('a')}"
        ),
        "enabled_domains": ["bank", "personal", "gov"],
        "domain": "app.synthetic.invalid",
    }
    execution_lock = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT_ID,
        "region": REGION,
        "execution_id": EXECUTION_ID,
        "owner": "github:synthetic-workflow",
        "status": "HELD",
        "acquired_at": "2026-08-28T20:00:00Z",
        "expires_at": "2026-08-28T20:30:00Z",
        "registry_record_digest": target["record_digest"],
        "lock_version": 1,
    }
    execution_lock["lock_digest"] = canonical_digest(execution_lock)
    resolution = {
        "schema_version": "3",
        "consumer_layer": "global",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": DESTINATION_ACCOUNT_ID,
        "region": REGION,
        "release_version": "2026.08.28",
        "release_digest": _sha("b"),
        "resolved_at": "2026-08-28T20:04:00Z",
        "max_contract_age_seconds": 300,
        "required_contracts": [
            {"contract_id": "account-ready/v2", "contract": account_ready}
        ],
    }
    resolution["resolution_digest"] = canonical_digest(resolution)
    return {
        "manifest": manifest,
        "target_record": target,
        "target_anchor": {
            "schema_version": "1",
            "deployment_id": DEPLOYMENT_ID,
            "registry_version": target["registry_version"],
            "record_digest": target["record_digest"],
        },
        "account_ready": account_ready,
        "execution_lock": execution_lock,
        "contract_resolution": resolution,
    }


def _github_identity(sources: dict) -> dict:
    identity = json.loads(
        (REPO_ROOT / "fixtures/valid/github-deployment-identity-v1-synthetic.json")
        .read_text(encoding="utf-8")
    )
    identity.update(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        account_id=DESTINATION_ACCOUNT_ID,
        region=REGION,
        environment="dev",
    )
    identity["repository"] = {
        "owner": "cesar-guzman",
        "name": "scanalyze-deployment-platform",
        "owner_id": "11",
        "repository_id": "22",
        "visibility": "private",
    }
    collector = identity["collector_authority"]
    collector.update(
        installation_account_id="11",
        installation_account_login="cesar-guzman",
        installation_target_type="Organization",
        repository_ids=["22"],
    )
    github_environment = f"scanalyze-{DEPLOYMENT_ID}-dev"
    identity["workflow"] = {
        "path": ".github/workflows/nonprod-release.yml",
        "ref": "refs/heads/main",
        "workflow_ref": (
            f"{REPOSITORY}/.github/workflows/"
            "nonprod-release.yml@refs/heads/main"
        ),
        "event_name": "workflow_dispatch",
        "execution_mode": "live",
        "github_environment": github_environment,
    }
    orchestrator = (
        f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
        f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
    )
    identity["oidc"].update(
        orchestrator_role_arn=orchestrator,
        required_role_tags={
            "service": "scanalyze-orchestrator",
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "account_id": DESTINATION_ACCOUNT_ID,
            "region": REGION,
            "environment": "dev",
        },
    )
    protection = identity["environment_protection"]
    protection.update(
        name=github_environment,
        required_reviewers=[
            {"type": "User", "id": "55", "login": "independent-reviewer"}
        ],
        initiator_login="release-initiator",
        variables={
            "CUSTOMER_ID": CUSTOMER_ID,
            "DEPLOYMENT_ID": DEPLOYMENT_ID,
            "AWS_ACCOUNT_ID": DESTINATION_ACCOUNT_ID,
            "AWS_REGION": REGION,
            "LOGICAL_ENVIRONMENT": "dev",
            "OIDC_ORCHESTRATOR_ROLE_ARN": orchestrator,
            "ORCHESTRATOR_ROLE_ARN": orchestrator,
            "GENERIC_PLAN_ROLE_ARN": _roles()["plan"]["arn"],
            "GENERIC_APPLY_ROLE_ARN": _roles()["apply"]["arn"],
            "IDENTITY_PLAN_ROLE_ARN": _roles()["identity_plan"]["arn"],
            "IDENTITY_APPLY_ROLE_ARN": _roles()["identity_apply"]["arn"],
            "PLATFORM_AUTHORITY_ACCOUNT_ID": AUTHORITY_ACCOUNT_ID,
            "REPOSITORY_ID": "22",
            "REPOSITORY_OWNER_ID": "11",
            "SECOND_P0_REVIEWER_ID": "55",
            "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID": collector["app_id"],
        },
        secret_names=[
            "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY",
            "SCANALYZE_LIVE_INPUT_BUNDLE_B64",
        ],
    )
    resource_tags = {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT_ID,
        "region": REGION,
        "environment": "dev",
    }
    for name, role in identity["terminal_roles"].items():
        role["role_arn"] = _roles()[name]["arn"]
        role["required_resource_tags"] = resource_tags
    for key in ("diagnostic_access", "state_recovery_access"):
        identity[key]["role_arn"] = _roles()[
            "diagnostic" if key == "diagnostic_access" else "state_recovery"
        ]["arn"]
        identity[key]["principal"] = (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/ScanalyzeBreakGlass"
        )
    identity["oidc"]["subject"] = derive_oidc_subject(identity)
    identity["contract_digest"] = canonical_digest(
        {key: value for key, value in identity.items() if key != "contract_digest"}
    )
    return identity


def _github_environment_anchor(identity: dict) -> dict:
    anchor = {
        "schema_version": "1",
        "record_type": "github_environment_anchor",
        "source": "github-api",
        "repository_owner_id": "11",
        "repository_id": "22",
        "environment_name": f"scanalyze-{DEPLOYMENT_ID}-dev",
        "configuration_digest": environment_configuration_digest(identity),
        "captured_at": "2026-08-28T20:00:00Z",
        "expires_at": "2026-08-28T20:10:00Z",
    }
    anchor["evidence_digest"] = canonical_digest(anchor)
    return anchor


def _sealed_request() -> dict:
    cost_model = {
        "currency": "USD",
        "modeled_cost_upper_bound_usd_micros": 5_000_000,
        "modeled_at": "2026-08-28T20:00:00Z",
        "expires_at": "2026-08-28T21:00:00Z",
    }
    cost_model["cost_model_digest"] = canonical_digest(cost_model)
    sources = _sources()
    identity = _github_identity(sources)
    sources["github_deployment_identity"] = identity
    sources["github_environment_anchor"] = _github_environment_anchor(identity)
    document = {
        "schema_version": "1",
        "record_type": "nonprod_live_input_sealed_request",
        "authority_bindings": {
            "platform_authority_account_id": AUTHORITY_ACCOUNT_ID,
            "orchestrator_role_arn": (
                f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
                f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
            ),
            "expected_approver_user_id": 55,
        },
        "cost_model": cost_model,
        "release_bindings": {
            "release_version": "2026.08.28",
            "release_policy_digest": _sha("c"),
            "release_projection_digest": _sha("d"),
            "plan_policy_digest": _sha("e"),
            "github_deployment_identity_digest": identity["contract_digest"],
            "environment_configuration_digest": environment_configuration_digest(
                identity
            ),
            "platform_authority_digest": _sha("2"),
            "toolchain_digest": _sha("3"),
            "root_module_digest": _sha("4"),
        },
        "sources": sources,
    }
    document["sealed_request_digest"] = stable_sealed_request_digest(document)
    return document


def _refresh_github_authority_evidence(sealed: dict) -> None:
    identity = sealed["sources"]["github_deployment_identity"]
    identity["oidc"]["subject"] = derive_oidc_subject(identity)
    identity["contract_digest"] = canonical_digest(
        {key: value for key, value in identity.items() if key != "contract_digest"}
    )
    configuration_digest = environment_configuration_digest(identity)
    sealed["release_bindings"]["github_deployment_identity_digest"] = identity[
        "contract_digest"
    ]
    sealed["release_bindings"][
        "environment_configuration_digest"
    ] = configuration_digest
    anchor = sealed["sources"]["github_environment_anchor"]
    anchor["configuration_digest"] = configuration_digest
    anchor["evidence_digest"] = canonical_digest(
        {key: value for key, value in anchor.items() if key != "evidence_digest"}
    )
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)


def _deployment_request() -> dict:
    return {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "environment": "dev",
        "release_digest": _sha("b"),
        "requested_by": "github:synthetic-author",
        "requested_at": "2026-08-28T19:00:00Z",
        "change_ticket": "GUG-125",
        "target_layer": "global",
        "approval": {
            "status": "approved",
            "requested_reviewers": ["github:synthetic-reviewer"],
            "decided_by": "github:synthetic-reviewer",
            "decided_at": "2026-08-28T19:30:00Z",
        },
        "non_sensitive_selectors": {"region": REGION},
    }


def _claim(operation: str = "plan", sealed_request: dict | None = None) -> dict:
    request = _deployment_request()
    sealed = sealed_request or _sealed_request()
    document = {
        "schema_version": "1",
        "record_type": "nonprod_live_input_claim",
        "repository": REPOSITORY,
        "deployment_id": DEPLOYMENT_ID,
        "environment": "dev",
        "region": REGION,
        "layer": "global",
        "operation": operation,
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
        "release_digest": _sha("b"),
        "maximum_cost_usd_micros": 10_000_000,
        "deployment_request": request,
        "deployment_request_digest": canonical_digest(request),
        "sealed_request_digest": sealed["sealed_request_digest"],
        "valid_from": "2026-08-28T20:00:00Z",
        "expires_at": "2026-08-28T21:00:00Z",
    }
    document["claim_digest"] = canonical_digest(document)
    return document


def _runtime() -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": (
            f"{REPOSITORY}/.github/workflows/"
            "nonprod-release.yml@refs/heads/main"
        ),
        "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA,
        "GITHUB_SHA": WORKFLOW_SHA,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_OWNER_ID": "11",
        "GITHUB_REPOSITORY_ID": "22",
        "GITHUB_RUN_ID": "33",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_ACTOR_ID": "44",
    }


def _materialize(
    private_root: Path,
    *,
    claim: dict | None = None,
    sealed_request: dict | None = None,
    operation: str = "plan",
):
    sealed = sealed_request or _sealed_request()
    selected_claim = claim or _claim(operation, sealed)
    return materialize_live_inputs(
        claim=selected_claim,
        sealed_request=sealed,
        deployment_id=DEPLOYMENT_ID,
        layer="global",
        operation=operation,
        claim_digest=selected_claim["claim_digest"],
        private_root=private_root,
        runtime_environment=_runtime(),
        now=NOW,
        repo_root=REPO_ROOT,
    )


def test_plan_materialization_is_deterministic_across_private_roots(
    tmp_path: Path,
) -> None:
    first = _materialize(tmp_path / "first")
    second = _materialize(tmp_path / "second")

    assert first.receipt == second.receipt
    assert first.receipt["code"] == "LIVE_INPUTS_MATERIALIZED"
    assert first.receipt["materialization_valid"] is True
    assert first.receipt["controller_input_ready"] is True
    assert first.receipt["oidc_authorized"] is True
    assert first.receipt["terminal_operation_authorized"] is False
    assert first.receipt["aws_calls"] == 0
    assert first.receipt["aws_mutations"] == 0
    context = first.documents["context.json"]
    bindings = first.documents["bindings.json"]
    manifest = first.documents["manifest.json"]
    assert context["workflow_run_attempt"] == 1
    assert first.receipt["expected_approver_user_id"] == 55
    assert context["expected_approver_user_id"] == 55
    assert bindings["expected_approver_user_id"] == 55
    assert manifest["expected_approver_user_id"] == 55
    assert (
        first.receipt["github_environment_anchor_digest"]
        == context["github_environment_anchor_digest"]
        == manifest["github_environment_anchor_digest"]
    )
    assert "github_environment_anchor_digest" not in bindings
    assert (
        first.receipt["approval_authority_digest"]
        == context["approval_authority_digest"]
        == bindings["approval_authority_digest"]
        == manifest["approval_authority_digest"]
    )
    assert str(tmp_path) not in json.dumps(first.receipt)
    assert DESTINATION_ACCOUNT_ID not in json.dumps(first.receipt)
    assert "arn:aws" not in json.dumps(first.receipt)


def test_runtime_sha_is_bound_after_the_sealed_claim_without_self_reference(
    tmp_path: Path,
) -> None:
    sealed = _sealed_request()
    identity = sealed["sources"]["github_deployment_identity"]
    assert "source_sha" not in identity["workflow"]
    assert "MAIN_SHA" not in identity["environment_protection"]["variables"]

    materialized = _materialize(
        tmp_path,
        claim=_claim(sealed_request=sealed),
        sealed_request=sealed,
    )

    context = materialized.documents["context.json"]
    assert context["workflow_sha"] == WORKFLOW_SHA
    assert context["main_sha"] == WORKFLOW_SHA
    assert context["source_revision_digest"].startswith("sha256:")


@pytest.mark.parametrize("legacy_binding", ["source_sha", "MAIN_SHA"])
def test_sealed_identity_rejects_legacy_runtime_sha_bindings(
    tmp_path: Path,
    legacy_binding: str,
) -> None:
    sealed = _sealed_request()
    identity = sealed["sources"]["github_deployment_identity"]
    if legacy_binding == "source_sha":
        identity["workflow"][legacy_binding] = WORKFLOW_SHA
    else:
        identity["environment_protection"]["variables"][legacy_binding] = (
            WORKFLOW_SHA
        )
    _refresh_github_authority_evidence(sealed)

    with pytest.raises(
        LiveInputMaterializationError,
        match="GITHUB_DEPLOYMENT_IDENTITY_INVALID",
    ):
        _materialize(
            tmp_path,
            claim=_claim(sealed_request=sealed),
            sealed_request=sealed,
        )


def test_github_environment_anchor_must_be_current(tmp_path: Path) -> None:
    sealed = _sealed_request()
    anchor = sealed["sources"]["github_environment_anchor"]
    anchor["captured_at"] = "2026-08-28T19:40:00Z"
    anchor["expires_at"] = "2026-08-28T19:50:00Z"
    _refresh_github_authority_evidence(sealed)
    claim = _claim(sealed_request=sealed)

    with pytest.raises(
        LiveInputMaterializationError, match="GITHUB_ENVIRONMENT_ANCHOR_NOT_CURRENT"
    ):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_github_environment_anchor_requires_exactly_one_user_reviewer(
    tmp_path: Path,
) -> None:
    sealed = _sealed_request()
    reviewers = sealed["sources"]["github_deployment_identity"][
        "environment_protection"
    ]["required_reviewers"]
    reviewers.append({"type": "User", "id": "56", "login": "other-reviewer"})
    _refresh_github_authority_evidence(sealed)
    claim = _claim(sealed_request=sealed)

    with pytest.raises(
        LiveInputMaterializationError, match="GITHUB_ENVIRONMENT_REVIEWER_NOT_EXACT"
    ):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_sealed_reviewer_must_match_the_anchored_reviewer(tmp_path: Path) -> None:
    sealed = _sealed_request()
    sealed["authority_bindings"]["expected_approver_user_id"] = 56
    _refresh_github_authority_evidence(sealed)
    claim = _claim(sealed_request=sealed)

    with pytest.raises(
        LiveInputMaterializationError,
        match="GITHUB_ENVIRONMENT_REVIEWER_BINDING_MISMATCH",
    ):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_rerun_failed_jobs_attempt_is_denied_before_oidc(tmp_path: Path) -> None:
    runtime = _runtime()
    runtime["GITHUB_RUN_ATTEMPT"] = "2"
    sealed = _sealed_request()
    claim = _claim(sealed_request=sealed)

    with pytest.raises(
        LiveInputMaterializationError, match="GITHUB_RUNTIME_BINDING_MISMATCH"
    ):
        materialize_live_inputs(
            claim=claim,
            sealed_request=sealed,
            deployment_id=DEPLOYMENT_ID,
            layer="global",
            operation="plan",
            claim_digest=claim["claim_digest"],
            private_root=tmp_path,
            runtime_environment=runtime,
            now=NOW,
            repo_root=REPO_ROOT,
        )
def test_apply_materialization_requires_controller_readback_but_allows_oidc(
    tmp_path: Path,
) -> None:
    result = _materialize(tmp_path / "apply", operation="apply")

    assert result.receipt["durable_readback_required"] is True
    assert result.receipt["oidc_authorized"] is True
    assert result.receipt["terminal_operation_authorized"] is False
    manifest = result.documents["manifest.json"]
    assert manifest["apply_inputs_ready"] is False
    assert manifest["plan_inputs_ready"] is False
    assert result.documents["apply-inputs.json"]["plan_record"].endswith(
        "/materialized/controller/plan-record.json"
    )


def test_bundle_substitution_and_claim_tampering_fail_closed(tmp_path: Path) -> None:
    sealed = _sealed_request()
    claim = _claim(sealed_request=sealed)
    sealed["sources"]["manifest"]["region"] = "us-west-2"
    with pytest.raises(
        LiveInputMaterializationError, match="SEALED_REQUEST_DIGEST_MISMATCH"
    ):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)

    sealed = _sealed_request()
    claim = _claim(sealed_request=sealed)
    claim["layer"] = "network"
    with pytest.raises(LiveInputMaterializationError, match="CLAIM_DIGEST_MISMATCH"):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_repository_claim_must_equal_exact_tracked_head_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    claim_path = (
        repository
        / "deployment/live-input-claims"
        / DEPLOYMENT_ID
        / "global/plan.json"
    )
    claim_path.parent.mkdir(parents=True)
    claim = _claim()
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test claim",
        ],
        check=True,
    )

    assert load_repository_claim(
        repo_root=repository,
        deployment_id=DEPLOYMENT_ID,
        layer="global",
        operation="plan",
    ) == claim

    claim_path.write_text(
        json.dumps({**claim, "region": "us-west-2"}), encoding="utf-8"
    )
    with pytest.raises(
        LiveInputMaterializationError, match="REPOSITORY_CLAIM_NOT_PROVEN"
    ):
        load_repository_claim(
            repo_root=repository,
            deployment_id=DEPLOYMENT_ID,
            layer="global",
            operation="plan",
        )


def test_repository_claim_parses_only_the_bytes_compared_with_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    claim_path = (
        repository
        / "deployment/live-input-claims"
        / DEPLOYMENT_ID
        / "global/plan.json"
    )
    claim_path.parent.mkdir(parents=True)
    claim = _claim()
    claim_path.write_text(json.dumps(claim), encoding="utf-8")
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test claim",
        ],
        check=True,
    )

    original_read_text = Path.read_text
    substituted = {**claim, "region": "us-west-2"}

    def race_path_reread(path: Path, *args: object, **kwargs: object) -> str:
        if path == claim_path:
            return json.dumps(substituted)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", race_path_reread)

    assert load_repository_claim(
        repo_root=repository,
        deployment_id=DEPLOYMENT_ID,
        layer="global",
        operation="plan",
    ) == claim


def test_repository_claim_rejects_symlinked_parent_after_review(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    deployment_root = (
        repository / "deployment/live-input-claims" / DEPLOYMENT_ID
    )
    claim_path = deployment_root / "global/plan.json"
    claim_path.parent.mkdir(parents=True)
    claim_path.write_text(json.dumps(_claim()), encoding="utf-8")
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test claim",
        ],
        check=True,
    )
    backing_root = deployment_root.with_name("backing")
    deployment_root.rename(backing_root)
    deployment_root.symlink_to(backing_root.name, target_is_directory=True)

    with pytest.raises(
        LiveInputMaterializationError, match="REPOSITORY_CLAIM_NOT_PROVEN"
    ):
        load_repository_claim(
            repo_root=repository,
            deployment_id=DEPLOYMENT_ID,
            layer="global",
            operation="plan",
        )


def test_tracked_request_must_equal_exact_head_and_claim_binding(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    request_path = Path("deployment/requests/synthetic.json")
    destination = repository / request_path
    destination.parent.mkdir(parents=True)
    request = _deployment_request()
    destination.write_text(json.dumps(request), encoding="utf-8")
    schema_destination = repository / "schemas/deployment-request.schema.json"
    schema_destination.parent.mkdir(parents=True)
    schema_destination.write_text(
        (REPO_ROOT / "schemas/deployment-request.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test request",
        ],
        check=True,
    )

    assert load_repository_deployment_request(
        repo_root=repository,
        request_path=request_path,
    ) == request
    validate_repository_deployment_request_binding(
        claim=_claim(),
        repo_root=repository,
        request_path=request_path,
    )

    substituted_claim = _claim()
    substituted_claim["deployment_request"]["change_ticket"] = "GUG-999"
    substituted_claim["deployment_request_digest"] = canonical_digest(
        substituted_claim["deployment_request"]
    )
    with pytest.raises(
        LiveInputMaterializationError,
        match="DEPLOYMENT_REQUEST_BINDING_MISMATCH",
    ):
        validate_repository_deployment_request_binding(
            claim=substituted_claim,
            repo_root=repository,
            request_path=request_path,
        )

    destination.write_text(
        json.dumps({**request, "release_digest": _sha("f")}),
        encoding="utf-8",
    )
    with pytest.raises(
        LiveInputMaterializationError,
        match="DEPLOYMENT_REQUEST_NOT_PROVEN",
    ):
        load_repository_deployment_request(
            repo_root=repository,
            request_path=request_path,
        )

    with pytest.raises(
        LiveInputMaterializationError,
        match="DEPLOYMENT_REQUEST_NOT_PROVEN",
    ):
        load_repository_deployment_request(
            repo_root=repository,
            request_path=Path("../outside.json"),
        )


def test_repository_request_parses_only_the_bytes_compared_with_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    request_path = Path("deployment/requests/synthetic.json")
    destination = repository / request_path
    destination.parent.mkdir(parents=True)
    request = _deployment_request()
    destination.write_text(json.dumps(request), encoding="utf-8")
    schema_destination = repository / "schemas/deployment-request.schema.json"
    schema_destination.parent.mkdir(parents=True)
    schema_destination.write_text(
        (REPO_ROOT / "schemas/deployment-request.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test request",
        ],
        check=True,
    )

    original_read_text = Path.read_text
    substituted = {**request, "change_ticket": "GUG-999"}

    def race_path_reread(path: Path, *args: object, **kwargs: object) -> str:
        if path == destination:
            return json.dumps(substituted)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", race_path_reread)

    assert load_repository_deployment_request(
        repo_root=repository,
        request_path=request_path,
    ) == request


def test_repository_request_rejects_symlinked_parent_after_review(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    request_root = repository / "deployment/requests"
    request_path = Path("deployment/requests/approved/synthetic.json")
    destination = repository / request_path
    backing = request_root / "backing/synthetic.json"
    destination.parent.mkdir(parents=True)
    backing.parent.mkdir(parents=True)
    request = _deployment_request()
    destination.write_text(json.dumps(request), encoding="utf-8")
    backing.write_text(json.dumps(request), encoding="utf-8")
    schema_destination = repository / "schemas/deployment-request.schema.json"
    schema_destination.parent.mkdir(parents=True)
    schema_destination.write_text(
        (REPO_ROOT / "schemas/deployment-request.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", repository], check=True)
    subprocess.run(["git", "-C", repository, "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            repository,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "test request",
        ],
        check=True,
    )
    destination.unlink()
    destination.parent.rmdir()
    destination.parent.symlink_to("backing", target_is_directory=True)

    with pytest.raises(
        LiveInputMaterializationError,
        match="DEPLOYMENT_REQUEST_NOT_PROVEN",
    ):
        load_repository_deployment_request(
            repo_root=repository,
            request_path=request_path,
        )


def test_cross_account_source_is_denied_even_when_bundle_and_claim_are_resealed(
    tmp_path: Path,
) -> None:
    sealed = _sealed_request()
    sealed["sources"]["manifest"]["aws_account_id"] = "999888777666"
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)
    claim = _claim(sealed_request=sealed)
    with pytest.raises(
        LiveInputMaterializationError, match="BACKEND_AUTHORIZATION_DENIED"
    ):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_state_is_not_accepted_from_the_pre_oidc_transport(tmp_path: Path) -> None:
    sealed = _sealed_request()
    sealed["sources"]["state_readback"] = {
        "status": "PRESENT",
        "lineage": "caller-controlled-state",
        "serial": 7,
    }
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)
    claim = _claim(sealed_request=sealed)

    with pytest.raises(LiveInputMaterializationError, match="SEALED_REQUEST_INVALID"):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_cost_guard_denies_over_budget_and_stale_models(tmp_path: Path) -> None:
    sealed = _sealed_request()
    sealed["cost_model"]["modeled_cost_upper_bound_usd_micros"] = 10_000_001
    sealed["cost_model"]["cost_model_digest"] = canonical_digest(
        {
            key: value
            for key, value in sealed["cost_model"].items()
            if key != "cost_model_digest"
        }
    )
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)
    claim = _claim(sealed_request=sealed)
    with pytest.raises(LiveInputMaterializationError, match="COST_BOUND_EXCEEDED"):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)

    sealed = _sealed_request()
    sealed["cost_model"]["expires_at"] = "2026-08-28T20:05:00Z"
    sealed["cost_model"]["cost_model_digest"] = canonical_digest(
        {
            key: value
            for key, value in sealed["cost_model"].items()
            if key != "cost_model_digest"
        }
    )
    sealed["sealed_request_digest"] = stable_sealed_request_digest(sealed)
    claim = _claim(sealed_request=sealed)
    with pytest.raises(LiveInputMaterializationError, match="COST_MODEL_NOT_CURRENT"):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)

    sealed = _sealed_request()
    claim = _claim(sealed_request=sealed)
    claim["expires_at"] = "2026-08-28T20:05:00Z"
    claim["claim_digest"] = canonical_digest(
        {key: value for key, value in claim.items() if key != "claim_digest"}
    )
    with pytest.raises(LiveInputMaterializationError, match="CLAIM_NOT_CURRENT"):
        _materialize(tmp_path, claim=claim, sealed_request=sealed)


def test_strict_base64_transport_is_exclusive_and_private(tmp_path: Path) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    payload = json.dumps(_sealed_request(), sort_keys=True).encode()
    environment = {
        "SCANALYZE_LIVE_INPUT_BUNDLE_B64": base64.b64encode(payload).decode()
    }

    path = stage_sealed_request_from_environment(
        private_root=root, environment=environment
    )
    assert path.read_bytes() == payload
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not (root / ".sealed-request.json.stage").exists()
    with pytest.raises(
        LiveInputMaterializationError, match="SEALED_REQUEST_ALREADY_EXISTS"
    ):
        stage_sealed_request_from_environment(
            private_root=root, environment=environment
        )

    invalid_root = tmp_path / "invalid"
    invalid_root.mkdir(mode=0o700)
    with pytest.raises(
        LiveInputMaterializationError, match="SEALED_REQUEST_TRANSPORT_INVALID"
    ):
        stage_sealed_request_from_environment(
            private_root=invalid_root,
            environment={"SCANALYZE_LIVE_INPUT_BUNDLE_B64": "not base64!"},
        )
    assert not (invalid_root / "sealed-request.json").exists()

    oversized_root = tmp_path / "oversized"
    oversized_root.mkdir(mode=0o700)
    with pytest.raises(
        LiveInputMaterializationError, match="SEALED_REQUEST_TRANSPORT_INVALID"
    ):
        stage_sealed_request_from_environment(
            private_root=oversized_root,
            environment={
                "SCANALYZE_LIVE_INPUT_BUNDLE_B64": "A"
                * (MAX_ENCODED_REQUEST_BYTES + 1)
            },
        )
    assert not (oversized_root / "sealed-request.json").exists()


def test_fixed_layout_is_create_only_owner_only_and_rebuild_validated(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    result = _materialize(root)

    persist_materialized_live_inputs(private_root=root, materialization=result)
    validate_materialized_live_inputs(private_root=root, expected=result)
    materialized = root / "materialized"
    assert stat.S_IMODE(materialized.stat().st_mode) == 0o700
    assert stat.S_IMODE((materialized / "receipt.json").stat().st_mode) == 0o600
    assert set(path.name for path in materialized.iterdir()) == {
        "sources",
        "controller",
        "plan",
        "context.json",
        "bindings.json",
        "backend-binding.json",
        "plan-inputs.json",
        "apply-inputs.json",
        "manifest.json",
        "receipt.json",
    }
    with pytest.raises(LiveInputMaterializationError, match="OUTPUT_ALREADY_EXISTS"):
        persist_materialized_live_inputs(private_root=root, materialization=result)

    controller_file = materialized / "controller" / "plan-record.json"
    controller_file.write_text("{}", encoding="utf-8")
    controller_file.chmod(0o600)
    with pytest.raises(
        LiveInputMaterializationError, match="CONTROLLER_INPUT_PREPOPULATED"
    ):
        validate_materialized_live_inputs(private_root=root, expected=result)

    controller_file.unlink()
    extra = materialized / "caller-selected.json"
    extra.write_text("{}", encoding="utf-8")
    extra.chmod(0o600)
    with pytest.raises(
        LiveInputMaterializationError, match="MATERIALIZED_OUTPUT_INVALID"
    ):
        validate_materialized_live_inputs(private_root=root, expected=result)


def test_claim_and_sealed_request_schemas_are_closed() -> None:
    claim_schema = json.loads(
        (REPO_ROOT / "schemas/nonprod-live-input-claim.v1.schema.json").read_text()
    )
    sealed_schema = json.loads(
        (
            REPO_ROOT
            / "schemas/nonprod-live-input-sealed-request.v1.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator.check_schema(claim_schema)
    jsonschema.Draft202012Validator.check_schema(sealed_schema)
    jsonschema.Draft202012Validator(claim_schema).validate(_claim())
    jsonschema.Draft202012Validator(sealed_schema).validate(_sealed_request())

    claim = _claim()
    claim["caller_path"] = "/tmp/substitute.json"
    assert list(jsonschema.Draft202012Validator(claim_schema).iter_errors(claim))


def test_public_synthetic_pair_has_complete_integrity_binding() -> None:
    claim = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/nonprod-live-input-claim-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    sealed = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/nonprod-live-input-sealed-request-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    cost_model = sealed["cost_model"]
    assert claim["deployment_request_digest"] == canonical_digest(
        claim["deployment_request"]
    )
    assert cost_model["cost_model_digest"] == canonical_digest(
        {
            key: value
            for key, value in cost_model.items()
            if key != "cost_model_digest"
        }
    )
    assert sealed["sealed_request_digest"] == stable_sealed_request_digest(sealed)
    assert claim["sealed_request_digest"] == sealed["sealed_request_digest"]
    assert claim["claim_digest"] == canonical_digest(
        {key: value for key, value in claim.items() if key != "claim_digest"}
    )


def test_cli_failure_is_sanitized_and_does_not_echo_secret(tmp_path: Path) -> None:
    secret = "private-sensitive-bundle-value"
    result = subprocess.run(
        [
            sys.executable,
            str(
                REPO_ROOT
                / "scripts/deployment/nonprod-live-input-materializer.py"
            ),
            "materialize",
            "--private-root",
            str(tmp_path / "missing"),
            "--deployment-id",
            DEPLOYMENT_ID,
            "--layer",
            "global",
            "--operation",
            "plan",
            "--claim-digest",
            _sha("a"),
            "--request-path",
            "deployment/requests/synthetic.json",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "SCANALYZE_LIVE_INPUT_BUNDLE_B64": secret},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == "FAIL: PRIVATE_ROOT_INVALID\n"
    assert secret not in result.stdout + result.stderr
