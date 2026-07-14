"""Local execution must remain fail-closed and contract-bound."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from tooling.validate_digest import canonicalize, compute_digest


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_ID = "111222333444"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
RELEASE_VERSION = "2026.07.14"


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


def _run_layer_plan(
    tmp_path: Path,
    *,
    include_resolution: bool = True,
    tamper_resolution: bool = False,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    plan_dir = tmp_path / "plans"
    plan_dir.mkdir()
    capture_path = tmp_path / "terraform-variables.json"
    resolution_path = tmp_path / "resolution.json"
    resolution_path.write_text(
        json.dumps(_resolution("network", tamper=tamper_resolution)),
        encoding="utf-8",
    )
    resolution_path.chmod(0o600)

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
        for argument in "$@"; do
          case "$argument" in
            init) exit 0 ;;
            -var-file=*) cp "${argument#-var-file=}" "$CAPTURE_PATH" ;;
          esac
        done
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
    ]
    if include_resolution:
        command.extend(["--resolved-input", str(resolution_path)])

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{Path(sys.executable).parent}:{env['PATH']}"
    env["CAPTURE_PATH"] = str(capture_path)
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
    return result, captured


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


def test_plan_requires_verified_resolution_before_terraform(tmp_path: Path) -> None:
    result, captured = _run_layer_plan(tmp_path, include_resolution=False)
    assert result.returncode == 2
    assert "--resolved-input is required" in result.stderr
    assert captured == {}


def test_plan_rejects_tampered_resolution_before_terraform(tmp_path: Path) -> None:
    result, captured = _run_layer_plan(tmp_path, tamper_resolution=True)
    assert result.returncode == 2
    assert "Verified contract resolution is required" in result.stderr
    assert captured == {}


def test_plan_uses_only_verified_materialized_variables(tmp_path: Path) -> None:
    result, captured = _run_layer_plan(tmp_path)
    assert result.returncode == 0, result.stderr
    assert captured == {
        "upstream_contract_digest": "sha256:" + ("c" * 64),
        "expected_upstream_digest": "sha256:" + ("c" * 64),
        "upstream_schema_version": "1",
    }
    assert not list((tmp_path / "plans").glob(".*.auto.tfvars.json"))


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
