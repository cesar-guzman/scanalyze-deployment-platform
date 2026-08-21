"""Local execution must remain fail-closed and contract-bound."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
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
    outputs = {
        "ecs_execution_role_arn": (
            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeEcsExecution"
        ),
        "ecs_task_role_arns": {
            "scanalyze-ingest-api": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngestTask"
            )
        },
    }
    contract = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "global",
        "scope": "global",
        "layer": "global",
        "producer": "roots/global",
        "release_version": RELEASE_VERSION,
        "release_digest": RELEASE_DIGEST,
        "output_schema_version": "global/v1",
        "outputs": outputs,
        "contract_digest": compute_digest(canonicalize(outputs)),
        "produced_at": "2026-07-14T00:00:00Z",
        "terraform_workspace": "default",
        "state_key": f"{DEPLOYMENT_ID}/global/terraform.tfstate",
        "module_source_digest": "sha256:" + ("d" * 64),
    }
    document = {
        "schema_version": "3",
        "consumer_layer": layer,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "release_digest": RELEASE_DIGEST,
        "release_version": RELEASE_VERSION,
        "resolved_at": "2026-07-14T00:05:00Z",
        "max_contract_age_seconds": 3600,
        "required_contracts": [contract],
    }
    document["resolution_digest"] = compute_digest(canonicalize(document))
    if tamper:
        document["required_contracts"][0]["outputs"][
            "ecs_execution_role_arn"
        ] = f"arn:aws:iam::{ACCOUNT_ID}:role/Unreviewed"
    return document


def _account_ready_resolution(account_ready: dict, *, tamper: bool = False) -> dict:
    document = {
        "schema_version": "3",
        "consumer_layer": "global",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "release_digest": RELEASE_DIGEST,
        "release_version": RELEASE_VERSION,
        "resolved_at": "2026-07-14T00:05:00Z",
        "max_contract_age_seconds": 3600,
        "required_contracts": [
            {"contract_id": "account-ready/v2", "contract": account_ready}
        ],
    }
    document["resolution_digest"] = compute_digest(canonicalize(document))
    if tamper:
        document["required_contracts"][0]["contract"]["environment"] = "unreviewed"
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
        "domain": "app.synthetic.example",
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
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{role_name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
            "account_id_tag": ACCOUNT_ID,
            "region_tag": "us-east-1",
            "environment_tag": "sandbox",
        }
        for name, role_name in (
            ("plan", "Plan"),
            ("apply", "Apply"),
            ("identity_plan", "Identity-Plan"),
            ("identity_apply", "Identity-Apply"),
            ("promotion", "Promotion"),
            ("validation", "Validation"),
            ("diagnostic", "Diagnostic"),
            ("state_recovery", "StateRecovery"),
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
    layer: str = "network",
    include_resolution: bool = True,
    tamper_resolution: bool = False,
    tamper_backend_binding: str | None = None,
    plan_parent_mode: int | None = None,
    plan_dir_mode: int | None = None,
    ambient_environment: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict, str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    plan_parent = tmp_path
    if plan_parent_mode is not None:
        plan_parent = tmp_path / "plan-parent"
        plan_parent.mkdir()
        plan_parent.chmod(plan_parent_mode)
    plan_dir = plan_parent / "plans"
    plan_dir.mkdir()
    if plan_dir_mode is not None:
        plan_dir.chmod(plan_dir_mode)
    capture_path = tmp_path / "terraform-variables.json"
    backend_capture_path = tmp_path / "terraform-backend.hcl"
    terraform_environment_path = tmp_path / "terraform-environment.txt"
    aws_marker_path = tmp_path / "aws-called"
    terraform_marker_path = tmp_path / "terraform-called"
    backend = _backend_evidence(tmp_path)
    account_ready = json.loads(backend["account_ready"].read_text(encoding="utf-8"))
    resolution = (
        _account_ready_resolution(account_ready, tamper=tamper_resolution)
        if layer == "global"
        else _resolution(layer, tamper=tamper_resolution)
    )
    resolution_path = tmp_path / "resolution.json"
    resolution_path.write_text(
        json.dumps(resolution),
        encoding="utf-8",
    )
    resolution_path.chmod(0o600)

    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(aws_marker_path))}
        printf '%s\n' '{ACCOUNT_ID}'
        """,
    )
    _write_executable(
        fake_bin / "terraform",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(terraform_marker_path))}
        compgen -e | sort > {shlex.quote(str(terraform_environment_path))}
        is_init=false
        for argument in "$@"; do
          case "$argument" in
            init) is_init=true ;;
            -backend-config=*) cp "${{argument#-backend-config=}}" {shlex.quote(str(backend_capture_path))} ;;
            -var-file=*) cp "${{argument#-var-file=}}" {shlex.quote(str(capture_path))} ;;
          esac
        done
        [[ "$is_init" == true ]] && exit 0
        for argument in "$@"; do
          [[ "$argument" == "plan" ]] && exit 0
        done
        exit 64
        """,
    )
    if tamper_backend_binding is not None:
        tamper_script = fake_bin / "tamper-backend-binding.py"
        tamper_script.write_text(
            textwrap.dedent(
                """
                import hashlib
                import json
                import os
                import sys
                from pathlib import Path

                binding_path = Path(sys.argv[1])
                backend_path = Path(sys.argv[2])
                mode = sys.argv[3]
                plan_dir = Path(sys.argv[4])
                if mode == "replace-plan-dir":
                    displaced = plan_dir.with_name("displaced-plan-directory")
                    os.replace(plan_dir, displaced)
                    plan_dir.mkdir(mode=0o700)
                elif mode == "symlink":
                    binding_path.unlink()
                    binding_path.symlink_to(backend_path)
                else:
                    document = json.loads(binding_path.read_text(encoding="utf-8"))
                    if mode == "stale-digest":
                        document["account_ready_digest"] = "sha256:" + ("0" * 64)
                    elif mode == "foreign-tuple":
                        document["account_id"] = "999888777666"
                        unsigned = {
                            key: value
                            for key, value in document.items()
                            if key != "binding_digest"
                        }
                        canonical = json.dumps(
                            unsigned,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                        ).encode("ascii")
                        document["binding_digest"] = (
                            "sha256:" + hashlib.sha256(canonical).hexdigest()
                        )
                    else:
                        raise SystemExit("unsupported test tamper mode")
                    replacement = binding_path.with_name("replacement-binding.json")
                    replacement.write_text(
                        json.dumps(document, sort_keys=True, indent=2) + "\\n",
                        encoding="utf-8",
                    )
                    replacement.chmod(0o600)
                    os.replace(replacement, binding_path)
                """
            ).lstrip(),
            encoding="utf-8",
        )
        _write_executable(
            fake_bin / "python3",
            f"""
            #!/usr/bin/env bash
            set -u
            real_python={shlex.quote(sys.executable)}
            "$real_python" "$@"
            status=$?
            if [[ "$status" -eq 0 && "${{1:-}}" == {shlex.quote(str(REPO_ROOT / "tooling" / "authorize_deployment_backend.py"))} ]]; then
              binding_out=""
              backend_out=""
              while [[ "$#" -gt 0 ]]; do
                case "$1" in
                  --binding-out) binding_out="$2"; shift 2 ;;
                  --backend-out) backend_out="$2"; shift 2 ;;
                  *) shift ;;
                esac
              done
              "$real_python" {shlex.quote(str(tamper_script))} \
                "$binding_out" "$backend_out" {shlex.quote(tamper_backend_binding)} \
                {shlex.quote(str(plan_dir))}
            fi
            exit "$status"
            """,
        )

    command = [
        "bash",
        str(REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh"),
        "plan",
        "--layer",
        layer,
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
    if ambient_environment:
        env.update(ambient_environment)
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
    result, captured, backend = _run_layer_plan(
        tmp_path,
        ambient_environment={"UNREVIEWED_AMBIENT": "must-not-reach-terraform"},
    )
    assert result.returncode == 0, result.stderr
    assert captured == {
        "upstream_contract_digest": _resolution("network")[
            "required_contracts"
        ][0]["contract_digest"],
        "expected_upstream_digest": _resolution("network")[
            "required_contracts"
        ][0]["contract_digest"],
        "upstream_schema_version": "1",
    }
    assert not list((tmp_path / "plans").glob(".*.auto.tfvars.json"))
    assert "use_lockfile = true" in backend
    assert "dynamodb_table" not in backend
    assert f'allowed_account_ids = ["{ACCOUNT_ID}"]' in backend
    assert not list((tmp_path / "plans").glob(".*.backend.hcl"))
    assert not list((tmp_path / "plans").glob(".*.backend-binding.json"))
    environment_names = set(
        (tmp_path / "terraform-environment.txt").read_text().splitlines()
    )
    assert {
        name for name in environment_names if name.startswith("TF_")
    } == {
        "TF_CLI_CONFIG_FILE",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
    }
    assert "UNREVIEWED_AMBIENT" not in environment_names


def test_global_plan_uses_backend_anchored_account_ready_v3(tmp_path: Path) -> None:
    result, captured, backend = _run_layer_plan(tmp_path, layer="global")

    account_ready = json.loads(
        (tmp_path / "account-ready.json").read_text(encoding="utf-8")
    )
    assert result.returncode == 0, result.stderr
    assert captured == {
        "expected_upstream_digest": account_ready["contract_digest"],
        "upstream_contract_digest": account_ready["contract_digest"],
        "upstream_schema_version": "2",
    }
    assert "use_lockfile = true" in backend
    assert (tmp_path / "aws-called").is_file()
    assert (tmp_path / "terraform-called").is_file()


@pytest.mark.parametrize(
    "tamper_mode",
    ["symlink", "stale-digest", "foreign-tuple"],
)
def test_plan_rejects_replaced_backend_binding_before_aws_or_terraform(
    tmp_path: Path,
    tamper_mode: str,
) -> None:
    result, captured, backend = _run_layer_plan(
        tmp_path,
        layer="global",
        tamper_backend_binding=tamper_mode,
    )

    assert result.returncode == 2
    assert "Unable to revalidate authorized backend binding" in result.stderr
    assert "Traceback" not in result.stderr
    assert CUSTOMER_ID not in result.stderr
    assert DEPLOYMENT_ID not in result.stderr
    assert ACCOUNT_ID not in result.stderr
    assert not (tmp_path / "aws-called").exists()
    assert not (tmp_path / "terraform-called").exists()
    assert captured == {}
    assert backend == ""


def test_plan_rejects_plan_directory_replacement_before_aws_or_terraform(
    tmp_path: Path,
) -> None:
    result, captured, backend = _run_layer_plan(
        tmp_path,
        layer="global",
        tamper_backend_binding="replace-plan-dir",
    )

    assert result.returncode == 2
    assert "Plan directory identity changed after backend authorization" in result.stderr
    assert not (tmp_path / "aws-called").exists()
    assert not (tmp_path / "terraform-called").exists()
    assert captured == {}
    assert backend == ""


def test_plan_rejects_non_owner_controlled_plan_directory_before_subprocesses(
    tmp_path: Path,
) -> None:
    result, captured, backend = _run_layer_plan(tmp_path, plan_dir_mode=0o770)

    assert result.returncode == 2
    assert "owner-controlled" in result.stderr
    assert not (tmp_path / "aws-called").exists()
    assert not (tmp_path / "terraform-called").exists()
    assert captured == {}
    assert backend == ""


def test_plan_rejects_writable_plan_directory_ancestor_before_subprocesses(
    tmp_path: Path,
) -> None:
    result, captured, backend = _run_layer_plan(
        tmp_path,
        plan_parent_mode=0o777,
        plan_dir_mode=0o700,
    )

    assert result.returncode == 2
    assert "owner-controlled ancestry" in result.stderr
    assert not (tmp_path / "aws-called").exists()
    assert not (tmp_path / "terraform-called").exists()
    assert captured == {}
    assert backend == ""


def test_resolution_validator_rejects_self_consistent_noncanonical_evidence(
    tmp_path: Path,
) -> None:
    resolution = _resolution("network")
    resolution["required_contracts"][0]["output_schema_version"] = "network/v2"
    resolution["required_contracts"][0]["layer"] = "network"
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


def test_resolution_validator_rejects_legacy_variables_authority(
    tmp_path: Path,
) -> None:
    resolution = _resolution("network")
    resolution["variables"] = {
        "vpc_id": "vpc-not-authorized-for-this-consumer"
    }
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
    assert "resolution schema validation failed" in result.stderr
    assert not materialized.exists()


@pytest.mark.parametrize(
    ("evidence_path", "rejected_value"),
    [
        (("contract_digest",), "sha256:" + ("9" * 64)),
        (("output_schema_version",), "global/v9"),
        (
            ("outputs", "ecs_execution_role_arn"),
            f"arn:aws:iam::{ACCOUNT_ID}:role/Unreviewed",
        ),
    ],
)
def test_active_validator_rejects_self_consistent_contract_evidence_tampering(
    tmp_path: Path,
    evidence_path: tuple[str, ...],
    rejected_value: str,
) -> None:
    resolution = _resolution("network")
    target = resolution["required_contracts"][0]
    for key in evidence_path[:-1]:
        target = target[key]
    target[evidence_path[-1]] = rejected_value
    resolution["resolution_digest"] = compute_digest(
        canonicalize(
            {
                key: value
                for key, value in resolution.items()
                if key != "resolution_digest"
            }
        )
    )
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
    assert rejected_value not in result.stdout + result.stderr
    assert not materialized.exists()


def test_active_validator_rejects_resolution_v1_downgrade(
    tmp_path: Path,
) -> None:
    resolution = {
        "schema_version": "1",
        "consumer_layer": "network",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "release_version": RELEASE_VERSION,
        "release_digest": RELEASE_DIGEST,
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
    resolution["resolution_digest"] = compute_digest(canonicalize(resolution))
    resolution_path = tmp_path / "resolution-v1.json"
    resolution_path.write_text(json.dumps(resolution), encoding="utf-8")
    resolution_path.chmod(0o600)
    materialized = tmp_path / "materialized.json"

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts/deployment/validate-contract-resolution.py"),
            "--resolution",
            str(resolution_path),
            "--schema",
            str(REPO_ROOT / "schemas/contract-resolution.v1.schema.json"),
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
    assert "schema downgrade is forbidden" in result.stderr
    assert not materialized.exists()


def test_active_validator_rejects_duplicate_json_keys(
    tmp_path: Path,
) -> None:
    resolution = _resolution("network")
    encoded = json.dumps(resolution)
    encoded = encoded.replace(
        '"consumer_layer": "network"',
        '"consumer_layer": "edge", "consumer_layer": "network"',
        1,
    )
    resolution_path = tmp_path / "resolution-duplicate-key.json"
    resolution_path.write_text(encoded, encoding="utf-8")
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
    assert "duplicate object key" in result.stderr
    assert not materialized.exists()


@pytest.mark.parametrize("nonfinite_constant", ["NaN", "Infinity", "-Infinity"])
def test_active_validator_rejects_nonfinite_json_numbers(
    tmp_path: Path,
    nonfinite_constant: str,
) -> None:
    resolution = _resolution("network")
    encoded = json.dumps(resolution).replace(
        '"max_contract_age_seconds": 3600',
        f'"max_contract_age_seconds": {nonfinite_constant}',
        1,
    )
    resolution_path = tmp_path / "resolution-nonfinite.json"
    resolution_path.write_text(encoded, encoding="utf-8")
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
    assert "non-finite numeric constant" in result.stderr
    assert nonfinite_constant not in result.stdout + result.stderr
    assert not materialized.exists()


def test_active_validator_rejects_resolution_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "resolution-target.json"
    target.write_text(json.dumps(_resolution("network")), encoding="utf-8")
    target.chmod(0o600)
    resolution_path = tmp_path / "resolution-link.json"
    resolution_path.symlink_to(target)
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
    assert "symlink" in result.stderr
    assert not materialized.exists()


@pytest.mark.parametrize(
    ("variable_name", "rejected_value"),
    [
        ("TF_VAR_service_definitions", '{"unsafe":true}'),
        ("TF_VAR_domain_name", "unreviewed.invalid"),
        ("TF_VAR_unreviewed_input", "future-input"),
        ("TF_CLI_ARGS", "-var=domain_name=unreviewed.invalid"),
        ("TF_CLI_ARGS", "-var-file=unreviewed.tfvars"),
        ("TF_CLI_ARGS_plan", "-target=module.unreviewed"),
        ("TF_CLI_ARGS_plan", "-replace=module.unreviewed"),
        ("TF_CLI_ARGS_plan", "-destroy"),
        ("TF_WORKSPACE", "unreviewed"),
        ("TF_REATTACH_PROVIDERS", '{"unsafe":"provider"}'),
        ("TF_CLI_CONFIG_FILE", "unreviewed.tfrc"),
        ("TF_DATA_DIR", "unreviewed-data"),
        ("TF_PLUGIN_CACHE_DIR", "unreviewed-cache"),
        ("TF_LOG", "TRACE"),
        ("TF_LOG_PATH", "unreviewed.log"),
    ],
)
def test_plan_rejects_ambient_terraform_environment_before_any_subprocess(
    tmp_path: Path,
    variable_name: str,
    rejected_value: str,
) -> None:
    result, captured, backend = _run_layer_plan(
        tmp_path,
        ambient_environment={variable_name: rejected_value},
    )

    assert result.returncode != 0
    assert variable_name in result.stderr
    assert rejected_value not in result.stdout + result.stderr
    assert not (tmp_path / "aws-called").exists()
    assert not (tmp_path / "terraform-called").exists()
    assert captured == {}
    assert backend == ""
    assert not list((tmp_path / "plans").iterdir())
