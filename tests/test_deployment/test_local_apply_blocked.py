"""Local execution must remain fail-closed and contract-bound."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from tooling.validate_digest import canonicalize, compute_digest


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_ID = "111222333444"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
RELEASE_VERSION = "2026.07.14"
EXECUTION_ID = "exec_01J5A1B2C3D4E5F6G7H8J9K0M1"


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = f"{Path(sys.executable).parent}:{env['PATH']}"
    return subprocess.run(
        ["bash", str(script), *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def _resolution(layer: str, *, tamper: bool = False) -> dict:
    document = {
        "schema_version": "1",
        "consumer_layer": layer,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "release_digest": RELEASE_DIGEST,
        "release_version": RELEASE_VERSION,
        "resolved_at": "2026-07-14T00:05:00Z",
        "required_contracts": [
            {
                "contract_id": "global/v1",
                "contract_digest": "sha256:" + ("c" * 64),
                "module_source_digest": "sha256:" + ("d" * 64),
                "producer": "roots/global",
                "release_version": RELEASE_VERSION,
                "produced_at": "2026-07-14T00:00:00Z",
            }
        ],
        "variables": {
            "upstream_contract_digest": "sha256:" + ("c" * 64),
            "expected_upstream_digest": "sha256:" + ("c" * 64),
            "upstream_schema_version": "1",
        },
    }
    document["resolution_digest"] = compute_digest(canonicalize(document))
    if tamper:
        document["variables"]["upstream_schema_version"] = "9"
    return document


def _content_digest(document: dict, field: str) -> str:
    return compute_digest(canonicalize({key: value for key, value in document.items() if key != field}))


def _backend_evidence(tmp_path: Path) -> dict[str, Path]:
    acquired_at = datetime.now(UTC).replace(microsecond=0)
    expires_at = acquired_at + timedelta(minutes=30)
    manifest = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "environment": "sandbox",
        "aws_account_id": ACCOUNT_ID,
        "aws_region": "us-east-1",
        "github": {
            "environment": "synthetic-sandbox",
            "oidc_role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/github-oidc-scanalyze-deploy",
        },
        "ecr": {"prefix": "dep-01j5a1b2c3d4e5f6g7h8j9k0m1/scanalyze"},
        "base_image_uri": "synthetic.invalid/base@sha256:" + ("b" * 64),
        "enabled_domains": ["bank"],
    }
    roles = {
        name: {
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
        }
        for name in (
            "plan",
            "apply",
            "promotion",
            "validation",
            "diagnostic",
            "state_recovery",
        )
    }
    account_ready = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "environment": "sandbox",
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-07-14T00:00:00Z",
        "roles": roles,
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
            "state_kms_key": f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000001",
            "evidence_kms_key": f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000002",
            "contracts_kms_key": f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000003",
        },
        "controls": {
            "state_versioning_enabled": True,
            "state_default_encryption": "aws:kms",
            "state_bucket_key_enabled": True,
            "state_public_access_blocked": True,
            "state_object_lock_enabled": False,
            "native_lockfile_enabled": True,
        },
    }
    account_ready["contract_digest"] = _content_digest(account_ready, "contract_digest")
    target = {
        "schema_version": "1",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "environment": "sandbox",
        "status": "READY",
        "registry_version": 1,
        "account_ready": {
            "schema_version": "2",
            "baseline_version": "v2.0.0",
            "contract_digest": account_ready["contract_digest"],
        },
        "state_binding": {
            "state_bucket": account_ready["state_infrastructure"]["state_bucket"],
            "state_kms_key": account_ready["state_infrastructure"]["state_kms_key"],
        },
    }
    target["record_digest"] = _content_digest(target, "record_digest")
    anchor = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "registry_version": 1,
        "record_digest": target["record_digest"],
    }
    lock = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "execution_id": EXECUTION_ID,
        "owner": "github:synthetic/repository:run:123",
        "status": "HELD",
        "acquired_at": acquired_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "registry_record_digest": target["record_digest"],
        "lock_version": 1,
    }
    lock["lock_digest"] = _content_digest(lock, "lock_digest")

    paths = {
        "manifest": tmp_path / "manifest.yaml",
        "target": tmp_path / "target.json",
        "anchor": tmp_path / "anchor.json",
        "account_ready": tmp_path / "account-ready.json",
        "lock": tmp_path / "lock.json",
    }
    paths["manifest"].write_text(yaml.safe_dump(manifest), encoding="utf-8")
    for name, document in (
        ("target", target),
        ("anchor", anchor),
        ("account_ready", account_ready),
        ("lock", lock),
    ):
        paths[name].write_text(json.dumps(document), encoding="utf-8")
        paths[name].chmod(0o600)
    return paths


def _run_layer_plan(
    tmp_path: Path,
    *,
    include_resolution: bool = True,
    tamper_resolution: bool = False,
) -> tuple[subprocess.CompletedProcess[str], dict, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    plan_dir = tmp_path / "plans"
    plan_dir.mkdir()
    capture_path = tmp_path / "terraform-variables.json"
    backend_capture_path = tmp_path / "terraform-backend.hcl"
    resolution_path = tmp_path / "resolution.json"
    resolution_path.write_text(
        json.dumps(_resolution("network", tamper=tamper_resolution)),
        encoding="utf-8",
    )
    resolution_path.chmod(0o600)
    backend = _backend_evidence(tmp_path)

    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf '%s\n' '{ACCOUNT_ID}'
        """,
    )
    _write_executable(
        fake_bin / "terraform",
        """
        #!/usr/bin/env bash
        set -euo pipefail
        is_init=false
        for argument in "$@"; do
          case "$argument" in
            init) is_init=true ;;
            -backend-config=*) cp "${argument#-backend-config=}" "$BACKEND_CAPTURE_PATH" ;;
            -var-file=*) cp "${argument#-var-file=}" "$CAPTURE_PATH" ;;
          esac
        done
        [[ "$is_init" == true ]] && exit 0
        for argument in "$@"; do
          [[ "$argument" == "plan" ]] && exit 0
        done
        exit 64
        """,
    )

    command = [
        "bash",
        str(REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh"),
        "plan",
        "--layer",
        "network",
        "--plan-dir",
        str(plan_dir),
        "--customer-id",
        CUSTOMER_ID,
        "--deployment-id",
        DEPLOYMENT_ID,
        "--account-id",
        ACCOUNT_ID,
        "--region",
        "us-east-1",
        "--release-version",
        RELEASE_VERSION,
        "--release-digest",
        RELEASE_DIGEST,
        "--manifest",
        str(backend["manifest"]),
        "--target-record",
        str(backend["target"]),
        "--target-anchor",
        str(backend["anchor"]),
        "--account-ready",
        str(backend["account_ready"]),
        "--execution-lock",
        str(backend["lock"]),
        "--execution-id",
        EXECUTION_ID,
    ]
    if include_resolution:
        command.extend(["--resolved-input", str(resolution_path)])

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{Path(sys.executable).parent}:{env['PATH']}"
    env["CAPTURE_PATH"] = str(capture_path)
    env["BACKEND_CAPTURE_PATH"] = str(backend_capture_path)
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    captured = (
        json.loads(capture_path.read_text(encoding="utf-8"))
        if capture_path.is_file()
        else {}
    )
    backend_capture = (
        backend_capture_path.read_text(encoding="utf-8")
        if backend_capture_path.is_file()
        else ""
    )
    return result, captured, backend_capture


def test_apply_all_is_blocked_before_any_live_precondition() -> None:
    result = _run(REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh", "apply-all")
    assert result.returncode == 2
    assert "Mock-backed plans are never authorized for apply" in result.stderr


def test_direct_layer_apply_is_blocked_before_aws_access() -> None:
    result = _run(REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh", "apply")
    assert result.returncode == 2
    assert "Local Terraform apply is disabled" in result.stderr


def test_plan_all_reads_canonical_dag_order(tmp_path: Path) -> None:
    result = _run(
        REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh",
        "plan-all",
        "--manifest",
        str(REPO_ROOT / "examples" / "deployments" / "synthetic-nonprod.yaml"),
        "--plan-dir",
        str(tmp_path),
        "--dry-run",
    )
    assert result.returncode == 0, result.stderr
    expected = [
        "account-ready-gate",
        "global",
        "network",
        "platform",
        "data-foundation",
        "cicd",
        "identity-control-plane",
        "services",
        "edge-identity",
        "edge",
        "addons",
    ]
    positions = [result.stdout.index(f"Planning layer: {layer}") for layer in expected]
    assert positions == sorted(positions)


def test_manifest_path_is_data_and_cli_cannot_override_authority(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest-'$(touch should-not-exist)'.yaml"
    manifest.write_text(
        (REPO_ROOT / "examples" / "deployments" / "synthetic-nonprod.yaml").read_text(),
        encoding="utf-8",
    )
    plan_dir = tmp_path / "plans"
    plan_dir.mkdir()

    accepted = _run(
        REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh",
        "plan-all",
        "--manifest",
        str(manifest),
        "--plan-dir",
        str(plan_dir),
        "--dry-run",
    )
    rejected = _run(
        REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh",
        "plan-all",
        "--manifest",
        str(manifest),
        "--account-id",
        "555666777888",
        "--plan-dir",
        str(plan_dir),
        "--dry-run",
    )

    assert accepted.returncode == 0, accepted.stderr
    assert rejected.returncode == 2
    assert "conflicts with the validated manifest" in rejected.stderr
    assert not (tmp_path / "should-not-exist").exists()


def test_plan_requires_verified_resolution_before_terraform(tmp_path: Path) -> None:
    result, captured, backend = _run_layer_plan(tmp_path, include_resolution=False)
    assert result.returncode == 2
    assert "--resolved-input is required" in result.stderr
    assert captured == {}
    assert backend == ""


def test_plan_rejects_tampered_resolution_before_terraform(tmp_path: Path) -> None:
    result, captured, backend = _run_layer_plan(tmp_path, tamper_resolution=True)
    assert result.returncode == 2
    assert "Verified contract resolution is required" in result.stderr
    assert captured == {}
    assert backend == ""


def test_plan_uses_only_verified_materialized_variables(tmp_path: Path) -> None:
    result, captured, backend = _run_layer_plan(tmp_path)
    assert result.returncode == 0, result.stderr
    assert captured == {
        "upstream_contract_digest": "sha256:" + ("c" * 64),
        "expected_upstream_digest": "sha256:" + ("c" * 64),
        "upstream_schema_version": "1",
    }
    assert not list((tmp_path / "plans").glob(".*.auto.tfvars.json"))
    assert "use_lockfile = true" in backend
    assert "dynamodb_table" not in backend
    assert f'allowed_account_ids = ["{ACCOUNT_ID}"]' in backend
    assert not list((tmp_path / "plans").glob(".*.backend.hcl"))
    assert not list((tmp_path / "plans").glob(".*.backend-binding.json"))


def test_resolution_validator_rejects_self_consistent_noncanonical_evidence(
    tmp_path: Path,
) -> None:
    resolution = _resolution("network")
    resolution["required_contracts"][0]["contract_id"] = "network/v2"
    resolution["required_contracts"][0]["producer"] = "roots/network"
    digest_input = {
        key: value for key, value in resolution.items() if key != "resolution_digest"
    }
    resolution["resolution_digest"] = compute_digest(canonicalize(digest_input))
    resolution_path = tmp_path / "resolution.json"
    resolution_path.write_text(json.dumps(resolution), encoding="utf-8")
    resolution_path.chmod(0o600)
    materialized = tmp_path / "materialized.json"

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment/validate-contract-resolution.py"),
            "--resolution",
            str(resolution_path),
            "--layer",
            "network",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "us-east-1",
            "--release-version",
            RELEASE_VERSION,
            "--release-digest",
            RELEASE_DIGEST,
            "--materialize-out",
            str(materialized),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "canonical DAG target" in result.stderr
    assert not materialized.exists()


def test_resolution_validator_rejects_self_consistent_undeclared_variable(
    tmp_path: Path,
) -> None:
    resolution = _resolution("network")
    resolution["variables"]["vpc_id"] = "vpc-not-authorized-for-this-consumer"
    digest_input = {
        key: value for key, value in resolution.items() if key != "resolution_digest"
    }
    resolution["resolution_digest"] = compute_digest(canonicalize(digest_input))
    resolution_path = tmp_path / "resolution.json"
    resolution_path.write_text(json.dumps(resolution), encoding="utf-8")
    resolution_path.chmod(0o600)
    materialized = tmp_path / "materialized.json"

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment/validate-contract-resolution.py"),
            "--resolution",
            str(resolution_path),
            "--layer",
            "network",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "us-east-1",
            "--release-version",
            RELEASE_VERSION,
            "--release-digest",
            RELEASE_DIGEST,
            "--materialize-out",
            str(materialized),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "canonical consumer bindings" in result.stderr
    assert not materialized.exists()
