"""GUG-122 deployment target, backend, and locking security contracts."""
from __future__ import annotations

import copy
import json
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    authorize_backend,
    authorize_backendless_gate,
    canonical_digest,
    load_json_strict,
    render_backend_hcl,
    write_private_file,
)
from tooling.deployment_execution_lock import acquire_lock
from tooling.deployment_registry import (
    prepare_registry_create,
    prepare_registry_update,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
OTHER_DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M2"
ACCOUNT_ID = "111222333444"
OTHER_ACCOUNT_ID = "555666777888"
REGION = "us-east-1"
ENVIRONMENT = "sandbox"
NOW = datetime(2026, 7, 14, 18, 0, tzinfo=UTC)


def _digest(document: dict, field: str) -> str:
    return canonical_digest({k: v for k, v in document.items() if k != field})


def _manifest() -> dict:
    return {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "environment": ENVIRONMENT,
        "aws_account_id": ACCOUNT_ID,
        "aws_region": REGION,
        "domain": "app.synthetic.example",
        "github": {
            "environment": "synthetic-sandbox",
            "oidc_role_arn": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/github-oidc-scanalyze-deploy"
            ),
        },
        "ecr": {"prefix": "dep-01j5a1b2c3d4e5f6g7h8j9k0m1/scanalyze"},
        "base_image_uri": (
            f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/base:3.11"
            "@sha256:" + ("a" * 64)
        ),
        "enabled_domains": ["bank", "personal", "gov"],
    }


def _account_ready() -> dict:
    roles = {}
    for role, role_name in (
        ("plan", "Plan"),
        ("apply", "Apply"),
        ("identity_plan", "Identity-Plan"),
        ("identity_apply", "Identity-Apply"),
        ("promotion", "Promotion"),
        ("validation", "Validation"),
        ("diagnostic", "Diagnostic"),
        ("state_recovery", "StateRecovery"),
    ):
        roles[role] = {
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{role_name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
            "account_id_tag": ACCOUNT_ID,
            "region_tag": REGION,
            "environment_tag": ENVIRONMENT,
        }
    document = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-07-14T17:00:00Z",
        "roles": roles,
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
            "state_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000001"
            ),
            "evidence_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000002"
            ),
            "contracts_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "00000000-0000-0000-0000-000000000003"
            ),
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
    document["contract_digest"] = _digest(document, "contract_digest")
    return document


def _target(account_ready: dict) -> dict:
    document = {
        "schema_version": "1",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": "sandbox",
        "status": "READY",
        "registry_version": 7,
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
    document["record_digest"] = _digest(document, "record_digest")
    return document


def _target_v2(account_ready: dict) -> dict:
    document = _target(account_ready)
    document["schema_version"] = "2"
    document["runtime_origin"] = {
        "schema_version": "1",
        "domain_name": "app.synthetic.example",
    }
    document["record_digest"] = _digest(document, "record_digest")
    return document


def _anchor(target: dict) -> dict:
    return {
        "schema_version": "1",
        "deployment_id": target["deployment_id"],
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }


def _lock(target: dict) -> dict:
    document = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M1",
        "owner": "github:synthetic/repository:run:123",
        "status": "HELD",
        "acquired_at": "2026-07-14T17:55:00Z",
        "expires_at": "2026-07-14T18:30:00Z",
        "registry_record_digest": target["record_digest"],
        "lock_version": 3,
    }
    document["lock_digest"] = _digest(document, "lock_digest")
    return document


def _catalog() -> dict:
    import yaml

    return yaml.safe_load((REPO_ROOT / "deployment/layers.yaml").read_text())


def _authorized(layer: str = "network") -> tuple[dict, dict, dict, dict, dict]:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    binding = authorize_backend(
        manifest=_manifest(),
        target=target,
        anchor=anchor,
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer=layer,
        now=NOW,
        schema_dir=SCHEMAS,
    )
    return binding, target, anchor, account_ready, lock


def _write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def _write_top_level_evidence(
    tmp_path: Path,
    mutation: str,
    *,
    command_name: str = "plan-layer",
) -> tuple[dict[str, Path], list[str]]:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)

    if mutation == "tampered-target-digest":
        target["record_digest"] = "sha256:" + ("f" * 64)
    elif mutation == "tampered-account-ready":
        account_ready["controls"]["state_versioning_enabled"] = False
        account_ready["contract_digest"] = _digest(
            account_ready,
            "contract_digest",
        )
    elif mutation == "wrong-anchor":
        anchor["record_digest"] = "sha256:" + ("e" * 64)
    elif mutation == "released-lock":
        lock["status"] = "RELEASED"
        lock["lock_digest"] = _digest(lock, "lock_digest")
    elif mutation == "foreign-lock":
        lock["deployment_id"] = OTHER_DEPLOYMENT_ID
        lock["lock_digest"] = _digest(lock, "lock_digest")
    elif mutation != "missing-target":
        raise AssertionError(f"unsupported mutation: {mutation}")

    paths = {
        "manifest": tmp_path / "manifest.yaml",
        "target": tmp_path / "target.json",
        "anchor": tmp_path / "anchor.json",
        "account_ready": tmp_path / "account-ready.json",
        "lock": tmp_path / "lock.json",
        "resolution": tmp_path / "resolution.json",
    }
    paths["manifest"].write_text(json.dumps(_manifest()), encoding="utf-8")
    for name, document in (
        ("target", target),
        ("anchor", anchor),
        ("account_ready", account_ready),
        ("lock", lock),
    ):
        if mutation == "missing-target" and name == "target":
            continue
        paths[name].write_text(json.dumps(document), encoding="utf-8")
        paths[name].chmod(0o600)
    paths["resolution"].write_text("{}", encoding="utf-8")
    paths["resolution"].chmod(0o600)

    command = [
        "bash",
        str(REPO_ROOT / "scripts/deployment/scanalyze-deploy.sh"),
        command_name,
        "--manifest",
        str(paths["manifest"]),
        "--customer-id",
        CUSTOMER_ID,
        "--deployment-id",
        DEPLOYMENT_ID,
        "--account-id",
        ACCOUNT_ID,
        "--region",
        REGION,
        "--environment",
        ENVIRONMENT,
        "--layer",
        "network",
        "--release-version",
        "2026.07.27",
        "--release-digest",
        "sha256:" + ("a" * 64),
        "--resolved-input",
        str(paths["resolution"]),
        "--target-record",
        str(paths["target"]),
        "--target-anchor",
        str(paths["anchor"]),
        "--account-ready",
        str(paths["account_ready"]),
        "--execution-lock",
        str(paths["lock"]),
        "--execution-id",
        lock["execution_id"],
        "--plan-dir",
        str(tmp_path / "plans"),
        "--no-dry-run",
    ]
    return paths, command


def _run_top_level_invalid_plan(
    tmp_path: Path,
    mutation: str,
    *,
    assertion_override: tuple[str, str] | None = None,
    command_name: str = "plan-layer",
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (tmp_path / "plans").mkdir()
    aws_marker = tmp_path / "aws-called"
    terraform_marker = tmp_path / "terraform-called"
    _, command = _write_top_level_evidence(
        tmp_path,
        mutation,
        command_name=command_name,
    )
    if assertion_override is not None:
        option, value = assertion_override
        command[command.index(option) + 1] = value

    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(aws_marker))}
        printf '%s\n' {shlex.quote(ACCOUNT_ID)}
        """,
    )
    _write_executable(
        fake_bin / "terraform",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(terraform_marker))}
        exit 64
        """,
    )
    env = os.environ.copy()
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    ):
        env.pop(name, None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    env["SCANALYZE_ALLOW_LIVE"] = "1"
    env["PATH"] = f"{fake_bin}:{Path(sys.executable).parent}:{env['PATH']}"
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, aws_marker, terraform_marker


def _run_backendless_gate(
    tmp_path: Path,
    mutation: str = "valid",
    *,
    plan_dir_target: Path | None = None,
    direct_wrapper: bool = False,
    top_level_dry_run: bool = False,
    artifact_symlink: str | None = None,
    artifact_race: str | None = None,
    wrapper_repo_root: Path = REPO_ROOT,
    real_terraform: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    account_ready = _account_ready()
    if mutation == "swapped-roles":
        plan_arn = account_ready["roles"]["plan"]["arn"]
        account_ready["roles"]["plan"]["arn"] = account_ready["roles"]["apply"]["arn"]
        account_ready["roles"]["apply"]["arn"] = plan_arn
    elif mutation == "arbitrary-bucket":
        account_ready["state_infrastructure"]["evidence_bucket"] = (
            f"arn:aws:s3:::arbitrary-evidence-{ACCOUNT_ID}"
        )
    elif mutation not in {"valid", "wrong-anchor"}:
        raise AssertionError(f"unsupported backendless gate mutation: {mutation}")
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)
    anchor = _anchor(target)
    if mutation == "wrong-anchor":
        anchor["record_digest"] = "sha256:" + ("f" * 64)

    evidence = {
        "manifest": tmp_path / "manifest.yaml",
        "target": tmp_path / "target.json",
        "anchor": tmp_path / "anchor.json",
        "account_ready": tmp_path / "account-ready.json",
    }
    evidence["manifest"].write_text(json.dumps(_manifest()), encoding="utf-8")
    for name, document in (
        ("target", target),
        ("anchor", anchor),
        ("account_ready", account_ready),
    ):
        evidence[name].write_text(json.dumps(document), encoding="utf-8")
        evidence[name].chmod(0o600)

    plan_dir = tmp_path / "plans"
    if plan_dir_target is None:
        plan_dir.mkdir()
    else:
        plan_dir.symlink_to(plan_dir_target, target_is_directory=True)
    if artifact_symlink is not None:
        if plan_dir_target is not None:
            raise AssertionError("artifact symlink requires a real plan directory")
        artifact_names = {
            "plan": "account-ready-gate.tfplan",
            "summary": "account-ready-gate-plan-summary.txt",
        }
        artifact_name = artifact_names[artifact_symlink]
        sentinel = tmp_path / f"{artifact_symlink}-sentinel"
        sentinel.write_text("DO_NOT_CLOBBER\n", encoding="utf-8")
        (plan_dir / artifact_name).symlink_to(sentinel)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    aws_marker = tmp_path / "aws-called"
    terraform_marker = tmp_path / "terraform-calls"
    projection_marker = tmp_path / "gate-projection.json"
    tf_data_marker = tmp_path / "tf-data-dir"
    cli_config_marker = tmp_path / "terraform-cli-config"
    race_command = ":"
    if artifact_race == "plan":
        race_sentinel = tmp_path / "plan-race-sentinel"
        race_sentinel.write_text("DO_NOT_CLOBBER\n", encoding="utf-8")
        final_plan = plan_dir / "account-ready-gate.tfplan"
        race_command = (
            f"ln -s {shlex.quote(str(race_sentinel))} "
            f"{shlex.quote(str(final_plan))}"
        )
    elif artifact_race is not None:
        raise AssertionError(f"unsupported artifact race: {artifact_race}")
    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(aws_marker))}
        exit 97
        """,
    )
    if real_terraform is None:
        _write_executable(
            fake_bin / "terraform",
            f"""
            #!/usr/bin/env bash
            set -euo pipefail
            [[ "${{TF_DATA_DIR:-}}" == "${{HOME}}/data" ]]
            [[ -d "$TF_DATA_DIR" ]]
            [[ "${{CHECKPOINT_DISABLE:-}}" == "1" ]]
            cp -- "$TF_CLI_CONFIG_FILE" {shlex.quote(str(cli_config_marker))}
            printf '%s\n' "$TF_DATA_DIR" > {shlex.quote(str(tf_data_marker))}
            printf '%s\n' "$*" >> {shlex.quote(str(terraform_marker))}
            saw_plan=false
            saw_state=false
            for argument in "$@"; do
              case "$argument" in
                -chdir=*)
                  [[ "${{argument#-chdir=}}" == "${{HOME}}/root" ]]
                  ;;
                plan)
                  saw_plan=true
                  ;;
                -state=*)
                  [[ "${{argument#-state=}}" == "${{HOME}}/gate-empty.tfstate" ]]
                  saw_state=true
                  ;;
                -var-file=*)
                  cp -- "${{argument#-var-file=}}" {shlex.quote(str(projection_marker))}
                  ;;
                -out=*)
                  : > "${{argument#-out=}}"
                  {race_command}
                  ;;
              esac
            done
            if [[ "$saw_plan" == true ]]; then
              [[ "$saw_state" == true ]]
            fi
            """,
        )
    else:
        (fake_bin / "terraform").symlink_to(real_terraform)

    common_arguments = [
        "--manifest",
        str(evidence["manifest"]),
        "--customer-id",
        CUSTOMER_ID,
        "--deployment-id",
        DEPLOYMENT_ID,
        "--account-id",
        ACCOUNT_ID,
        "--region",
        REGION,
        "--environment",
        ENVIRONMENT,
        "--layer",
        "account-ready-gate",
        "--target-record",
        str(evidence["target"]),
        "--target-anchor",
        str(evidence["anchor"]),
        "--account-ready",
        str(evidence["account_ready"]),
        "--plan-dir",
        str(plan_dir),
    ]
    if direct_wrapper:
        command = [
            "bash",
            str(wrapper_repo_root / "scripts/deployment/terraform-layer.sh"),
            "plan",
            *common_arguments,
        ]
    else:
        command = [
            "bash",
            str(wrapper_repo_root / "scripts/deployment/scanalyze-deploy.sh"),
            "plan-layer",
            *common_arguments,
        ]
        if not top_level_dry_run:
            command.append("--no-dry-run")
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("AWS_") or name.startswith("TF_"):
            env.pop(name, None)
    env.pop("SCANALYZE_ALLOW_LIVE", None)
    env["PATH"] = f"{fake_bin}:{Path(sys.executable).parent}:{env['PATH']}"
    result = subprocess.run(
        command,
        cwd=wrapper_repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, aws_marker, terraform_marker, projection_marker


def test_authorization_derives_backend_only_from_trusted_bindings() -> None:
    binding, target, _, account_ready, _ = _authorized()

    assert binding["customer_id"] == CUSTOMER_ID
    assert binding["deployment_id"] == DEPLOYMENT_ID
    assert binding["account_id"] == ACCOUNT_ID
    assert binding["region"] == REGION
    assert binding["layer"] == "network"
    assert binding["backend"] == {
        "bucket": f"scanalyze-{ACCOUNT_ID}-tf-state",
        "key": f"{DEPLOYMENT_ID}/{REGION}/network/terraform.tfstate",
        "region": REGION,
        "encrypt": True,
        "kms_key_id": account_ready["state_infrastructure"]["state_kms_key"],
        "use_lockfile": True,
        "allowed_account_ids": [ACCOUNT_ID],
    }
    assert binding["registry_record_digest"] == target["record_digest"]
    assert binding["binding_digest"] == _digest(binding, "binding_digest")


@pytest.mark.parametrize(
    "mutation",
    ["swapped-roles", "state-bucket", "evidence-bucket", "contracts-bucket"],
)
def test_backend_authorization_reuses_strict_account_ready_v2_verifier(
    mutation: str,
) -> None:
    account_ready = _account_ready()
    if mutation == "swapped-roles":
        plan_arn = account_ready["roles"]["plan"]["arn"]
        account_ready["roles"]["plan"]["arn"] = account_ready["roles"]["apply"]["arn"]
        account_ready["roles"]["apply"]["arn"] = plan_arn
    else:
        field = mutation.replace("-", "_")
        account_ready["state_infrastructure"][field] = (
            f"arn:aws:s3:::arbitrary-{mutation}-{ACCOUNT_ID}"
        )
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(
        AuthorizationError,
        match="ACCOUNT_READY v2 strict verification failed",
    ):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_backendless_gate_projection_and_preconditions_are_offline(
    tmp_path: Path,
) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    projection = authorize_backendless_gate(
        manifest=_manifest(),
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        schema_dir=SCHEMAS,
    )

    assert projection == {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "expected_baseline_version": "v2.0.0",
        "expected_contract_digest": account_ready["contract_digest"],
        "account_ready_binding": {
            "schema_version": "2",
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "account_id": ACCOUNT_ID,
            "region": REGION,
            "environment": ENVIRONMENT,
            "baseline_version": "v2.0.0",
            "contract_digest": account_ready["contract_digest"],
        },
    }

    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")

    harness = tmp_path / "gate-harness"
    harness.mkdir()
    gate_root = REPO_ROOT / "roots/account-ready-gate"
    for filename in ("variables.tf", "contract_validation.tf"):
        (harness / filename).write_text(
            (gate_root / filename).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    (harness / "versions.tf").write_text(
        'terraform { required_version = ">= 1.14.6, < 1.15.0" }\n',
        encoding="utf-8",
    )
    terraform_home = tmp_path / "terraform-home"
    terraform_home.mkdir()
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("AWS_") or name.startswith("TF_"):
            env.pop(name, None)
    env.update(
        {
            "CHECKPOINT_DISABLE": "1",
            "HOME": str(terraform_home),
            "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0",
        }
    )
    initialized = subprocess.run(
        [
            terraform_binary,
            f"-chdir={harness}",
            "init",
            "-backend=false",
            "-input=false",
            "-no-color",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert initialized.returncode == 0, initialized.stderr

    variables_path = tmp_path / "gate.auto.tfvars.json"

    def plan(candidate: dict) -> subprocess.CompletedProcess[str]:
        variables_path.write_text(json.dumps(candidate), encoding="utf-8")
        return subprocess.run(
            [
                terraform_binary,
                f"-chdir={harness}",
                "plan",
                "-input=false",
                "-no-color",
                "-refresh=false",
                "-lock=false",
                f"-var-file={variables_path}",
            ],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    valid = plan(projection)
    assert valid.returncode == 0, valid.stderr

    mismatches = (
        ("customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2", "customer binding"),
        ("deployment_id", OTHER_DEPLOYMENT_ID, "deployment binding"),
        ("account_id", OTHER_ACCOUNT_ID, "account binding"),
        ("region", "us-west-2", "region binding"),
        ("environment", "staging", "environment binding"),
        ("baseline_version", "v2.0.1", "baseline version"),
        ("contract_digest", "sha256:" + ("b" * 64), "digest"),
    )
    for field, value, expected in mismatches:
        candidate = copy.deepcopy(projection)
        candidate["account_ready_binding"][field] = value
        denied = plan(candidate)
        assert denied.returncode != 0
        assert expected in denied.stderr


def test_backendless_gate_runtime_calls_no_aws_and_uses_no_backend(
    tmp_path: Path,
) -> None:
    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(tmp_path)
    )

    assert result.returncode == 0, result.stderr
    assert not aws_marker.exists()
    calls = terraform_marker.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 2
    assert " init -backend=false -input=false -no-color" in calls[0]
    assert "-backend-config" not in "\n".join(calls)
    assert " plan -input=false -no-color -refresh=false -lock=false " in calls[1]
    assert " -state=" in calls[1]
    assert "/gate-empty.tfstate" in calls[1]
    assert "-var-file=" in calls[1]
    projection = json.loads(projection_marker.read_text(encoding="utf-8"))
    assert projection["account_ready_binding"]["contract_digest"].startswith(
        "sha256:"
    )
    assert projection["expected_contract_digest"] == (
        projection["account_ready_binding"]["contract_digest"]
    )
    plan_dir = tmp_path / "plans"
    for artifact in (
        plan_dir / "account-ready-gate.tfplan",
        plan_dir / "account-ready-gate-plan-summary.txt",
    ):
        assert artifact.is_file()
        assert not artifact.is_symlink()
        assert artifact.stat().st_mode & 0o777 == 0o600
    tf_data_dir = Path((tmp_path / "tf-data-dir").read_text(encoding="utf-8").strip())
    assert tf_data_dir.name == "data"
    assert tf_data_dir.parent.name.startswith(".account-ready-gate.terraform-home.")
    assert not tf_data_dir.exists()
    cli_config = (tmp_path / "terraform-cli-config").read_text(encoding="utf-8")
    assert "provider_installation" in cli_config
    assert "filesystem_mirror" in cli_config
    assert "provider-mirror" in cli_config
    assert "direct {" not in cli_config
    assert not list(plan_dir.glob(".account-ready-gate.terraform-home.*"))


@pytest.mark.parametrize(
    ("direct_wrapper", "top_level_dry_run"),
    [(False, True), (True, False)],
)
def test_physical_plan_dir_resolution_rejects_symlink_into_repository(
    tmp_path: Path,
    direct_wrapper: bool,
    top_level_dry_run: bool,
) -> None:
    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(
            tmp_path,
            plan_dir_target=REPO_ROOT,
            direct_wrapper=direct_wrapper,
            top_level_dry_run=top_level_dry_run,
        )
    )

    assert result.returncode != 0
    assert "--plan-dir must be outside the repository" in result.stderr
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()


@pytest.mark.parametrize("artifact_symlink", ["plan", "summary"])
def test_preexisting_artifact_symlink_is_denied_without_clobber(
    tmp_path: Path,
    artifact_symlink: str,
) -> None:
    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(
            tmp_path,
            artifact_symlink=artifact_symlink,
        )
    )

    sentinel = tmp_path / f"{artifact_symlink}-sentinel"
    artifact_names = {
        "plan": "account-ready-gate.tfplan",
        "summary": "account-ready-gate-plan-summary.txt",
    }
    destination = tmp_path / "plans" / artifact_names[artifact_symlink]
    assert result.returncode != 0
    assert "destination already exists" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "DO_NOT_CLOBBER\n"
    assert destination.is_symlink()
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()


def test_artifact_publication_rolls_back_summary_when_plan_destination_races(
    tmp_path: Path,
) -> None:
    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(tmp_path, artifact_race="plan")
    )

    plan_dir = tmp_path / "plans"
    plan = plan_dir / "account-ready-gate.tfplan"
    summary = plan_dir / "account-ready-gate-plan-summary.txt"
    sentinel = tmp_path / "plan-race-sentinel"
    assert result.returncode != 0
    assert "private plan artifact publication failed" in result.stderr
    assert plan.is_symlink()
    assert plan.resolve() == sentinel
    assert sentinel.read_text(encoding="utf-8") == "DO_NOT_CLOBBER\n"
    assert not summary.exists()
    assert not aws_marker.exists()
    assert len(terraform_marker.read_text(encoding="utf-8").splitlines()) == 2
    assert projection_marker.exists()
    assert not list(plan_dir.glob(".account-ready-gate.terraform-home.*"))


def _isolated_gate_wrapper_repo(
    tmp_path: Path,
    terraform_configuration: str,
) -> tuple[Path, Path]:
    wrapper_repo = tmp_path / "runtime-repo"
    deployment_scripts = wrapper_repo / "scripts/deployment"
    tooling_dir = wrapper_repo / "tooling"
    gate_root = wrapper_repo / "roots/account-ready-gate"
    deployment_scripts.mkdir(parents=True)
    tooling_dir.mkdir()
    gate_root.mkdir(parents=True)
    (deployment_scripts / "terraform-layer.sh").symlink_to(
        REPO_ROOT / "scripts/deployment/terraform-layer.sh"
    )
    for filename in ("authorize_deployment_backend.py", "verify_account_ready.py"):
        (tooling_dir / filename).symlink_to(REPO_ROOT / "tooling" / filename)
    (gate_root / "main.tf").write_text(terraform_configuration, encoding="utf-8")
    return wrapper_repo, gate_root


def test_backendless_gate_ignores_root_state_and_dot_terraform(
    tmp_path: Path,
) -> None:
    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")

    wrapper_repo, gate_root = _isolated_gate_wrapper_repo(
        tmp_path,
        'terraform { required_version = ">= 1.14.6, < 1.15.0" }\n',
    )
    state_sentinel = gate_root / "terraform.tfstate"
    state_sentinel.write_text("DO_NOT_READ_OR_TOUCH\n", encoding="utf-8")
    dot_terraform_sentinel = gate_root / ".terraform"
    dot_terraform_sentinel.write_text("DO_NOT_READ_OR_TOUCH\n", encoding="utf-8")

    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(
            tmp_path,
            direct_wrapper=True,
            wrapper_repo_root=wrapper_repo,
            real_terraform=Path(terraform_binary),
        )
    )

    assert result.returncode == 0, result.stderr
    assert state_sentinel.read_text(encoding="utf-8") == "DO_NOT_READ_OR_TOUCH\n"
    assert dot_terraform_sentinel.read_text(encoding="utf-8") == (
        "DO_NOT_READ_OR_TOUCH\n"
    )
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()
    plan_dir = tmp_path / "plans"
    for artifact in (
        plan_dir / "account-ready-gate.tfplan",
        plan_dir / "account-ready-gate-plan-summary.txt",
    ):
        assert artifact.is_file()
        assert not artifact.is_symlink()
        assert artifact.stat().st_mode & 0o777 == 0o600
    assert not list(plan_dir.glob(".account-ready-gate.terraform-home.*"))


def test_backendless_gate_real_root_uses_only_builtin_provider(tmp_path: Path) -> None:
    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")

    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(
            tmp_path,
            direct_wrapper=True,
            real_terraform=Path(terraform_binary),
        )
    )

    assert result.returncode == 0, result.stderr
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()
    plan_dir = tmp_path / "plans"
    summary = plan_dir / "account-ready-gate-plan-summary.txt"
    output = result.stdout + result.stderr + summary.read_text(encoding="utf-8")
    for sensitive in (
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        ACCOUNT_ID,
        _account_ready()["contract_digest"],
    ):
        assert sensitive not in output
    for artifact in (plan_dir / "account-ready-gate.tfplan", summary):
        assert artifact.is_file()
        assert not artifact.is_symlink()
        assert artifact.stat().st_mode & 0o777 == 0o600
    assert not list(plan_dir.glob(".account-ready-gate.terraform-home.*"))


def test_backendless_gate_cannot_download_external_providers(tmp_path: Path) -> None:
    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")

    wrapper_repo, _ = _isolated_gate_wrapper_repo(
        tmp_path,
        """
        terraform {
          required_version = ">= 1.14.6, < 1.15.0"
          required_providers {
            aws = {
              source  = "hashicorp/aws"
              version = "= 6.0.0"
            }
          }
        }
        """,
    )

    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(
            tmp_path,
            direct_wrapper=True,
            wrapper_repo_root=wrapper_repo,
            real_terraform=Path(terraform_binary),
        )
    )

    output = result.stdout + result.stderr
    normalized_output = " ".join(output.split())
    assert result.returncode != 0
    assert "was not found in any of the search locations" in normalized_output
    assert "provider-mirror" in output
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()
    plan_dir = tmp_path / "plans"
    assert not (plan_dir / "account-ready-gate.tfplan").exists()
    assert not (plan_dir / "account-ready-gate-plan-summary.txt").exists()
    assert not list(plan_dir.glob(".account-ready-gate.terraform-home.*"))


@pytest.mark.parametrize(
    "mutation",
    ["swapped-roles", "arbitrary-bucket", "wrong-anchor"],
)
def test_backendless_gate_invalid_evidence_calls_no_aws_or_terraform(
    tmp_path: Path,
    mutation: str,
) -> None:
    result, aws_marker, terraform_marker, projection_marker = (
        _run_backendless_gate(tmp_path, mutation)
    )

    assert result.returncode != 0
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert not projection_marker.exists()
    output = result.stdout + result.stderr
    for sensitive in (ACCOUNT_ID, DEPLOYMENT_ID, "arn:aws:", "sha256:"):
        assert sensitive not in output


def test_domain_owning_layer_uses_digest_bound_target_v2_origin() -> None:
    account_ready = _account_ready()
    target = _target_v2(account_ready)
    binding = authorize_backend(
        manifest=_manifest(),
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        execution_lock=_lock(target),
        layer_catalog=_catalog(),
        layer="edge",
        now=NOW,
        schema_dir=SCHEMAS,
    )

    assert binding["schema_version"] == "2"
    assert binding["runtime_origin"] == target["runtime_origin"]
    assert binding["registry_record_digest"] == target["record_digest"]
    assert binding["binding_digest"] == _digest(binding, "binding_digest")


def test_domain_owning_layer_rejects_manifest_origin_substitution() -> None:
    account_ready = _account_ready()
    target = _target_v2(account_ready)
    manifest = _manifest()
    manifest["domain"] = "substituted.synthetic.example"

    with pytest.raises(AuthorizationError, match="conflicting domain_name binding"):
        authorize_backend(
            manifest=manifest,
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="identity-control-plane",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_domain_owning_layer_rejects_unbound_target_v1() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)

    with pytest.raises(
        AuthorizationError,
        match="domain-owning layers require deployment target v2",
    ):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="edge",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_registry_v2_makes_runtime_origin_immutable() -> None:
    account_ready = _account_ready()
    current = _target_v2(account_ready)
    current["registry_version"] = 1
    current["status"] = "REQUESTED"
    current["record_digest"] = _digest(current, "record_digest")
    assert prepare_registry_create(current)["condition_expression"] == (
        "attribute_not_exists(deployment_id)"
    )

    proposed = copy.deepcopy(current)
    proposed["registry_version"] = 2
    proposed["status"] = "BASELINING"
    proposed["runtime_origin"]["domain_name"] = "substituted.synthetic.example"
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="runtime_origin"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )


def test_registry_cas_migrates_v1_to_v2_without_other_state_change() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["schema_version"] = "2"
    proposed["registry_version"] += 1
    proposed["runtime_origin"] = {
        "schema_version": "1",
        "domain_name": "app.synthetic.example",
    }
    proposed["record_digest"] = _digest(proposed, "record_digest")

    write = prepare_registry_update(
        current=current,
        proposed=proposed,
        expected_version=current["registry_version"],
        expected_digest=current["record_digest"],
    )

    assert "schema_version = :expected_schema_version" in write[
        "condition_expression"
    ]
    assert write["expression_attribute_values"][":expected_schema_version"] == "1"
    assert proposed["record_digest"] != current["record_digest"]


def test_registry_v1_to_v2_migration_cannot_change_status() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["schema_version"] = "2"
    proposed["registry_version"] += 1
    proposed["status"] = "ACTIVE"
    proposed["runtime_origin"] = {
        "schema_version": "1",
        "domain_name": "app.synthetic.example",
    }
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="cannot change status"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )


def test_manifest_v2_rejects_request_supplied_backend_coordinates() -> None:
    manifest = _manifest()
    manifest["terraform_backend"] = {
        "bucket": "attacker-controlled",
        "key": "foreign/terraform.tfstate",
    }
    schema = json.loads(
        (SCHEMAS / "deployment-manifest.v2.schema.json").read_text()
    )

    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(manifest))

    assert errors
    assert any("terraform_backend" in error.message for error in errors)


def test_legacy_manifest_is_not_accepted_by_operational_authorizer() -> None:
    manifest = _manifest()
    manifest["schema_version"] = "1"
    manifest["terraform_backend"] = {
        "bucket": "legacy",
        "lock_table": "legacy",
        "key_prefix": "legacy",
    }
    account_ready = _account_ready()
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="manifest v2"):
        authorize_backend(
            manifest=manifest,
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_legacy_account_ready_is_not_accepted_by_operational_authorizer() -> None:
    account_ready = _account_ready()
    account_ready["schema_version"] = "1"
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="ACCOUNT_READY v2"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("document_name", "field", "value"),
    [
        ("manifest", "customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("manifest", "deployment_id", OTHER_DEPLOYMENT_ID),
        ("manifest", "aws_account_id", "555666777888"),
        ("manifest", "aws_region", "us-west-2"),
        ("manifest", "environment", "staging"),
        ("account_ready", "customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("account_ready", "deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_ready", "account_id", "555666777888"),
        ("account_ready", "region", "us-west-2"),
    ],
)
def test_cross_boundary_or_conflicting_target_fails_closed(
    document_name: str,
    field: str,
    value: str,
) -> None:
    manifest = _manifest()
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    document = manifest if document_name == "manifest" else account_ready
    document[field] = value
    if document_name == "account_ready":
        document["contract_digest"] = _digest(document, "contract_digest")

    with pytest.raises(AuthorizationError):
        authorize_backend(
            manifest=manifest,
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_tampered_or_unanchored_registry_record_fails_closed() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    lock = _lock(target)
    target["region"] = "us-west-2"

    with pytest.raises(AuthorizationError, match="record digest"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_registry_anchor_version_and_digest_are_exact() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    anchor["registry_version"] += 1

    with pytest.raises(AuthorizationError, match="anchor"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=anchor,
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("control", "value"),
    [
        ("state_versioning_enabled", False),
        ("state_default_encryption", "AES256"),
        ("state_bucket_key_enabled", False),
        ("state_public_access_blocked", False),
        ("state_object_lock_enabled", True),
        ("native_lockfile_enabled", False),
    ],
)
def test_account_baseline_security_mismatch_fails_closed(
    control: str,
    value: object,
) -> None:
    account_ready = _account_ready()
    account_ready["controls"][control] = value
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id_tag", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("deployment_id_tag", OTHER_DEPLOYMENT_ID),
        ("account_id_tag", "555666777888"),
        ("region_tag", "us-west-2"),
        ("environment_tag", "staging"),
    ],
)
def test_account_ready_role_resource_tags_are_authoritative(
    field: str, value: str
) -> None:
    account_ready = _account_ready()
    account_ready["roles"]["plan"][field] = value
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="role .*binding|role .*tag"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_foreign_bucket_or_kms_binding_fails_closed() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    target["state_binding"]["state_bucket"] = (
        "arn:aws:s3:::scanalyze-555666777888-tf-state"
    )
    target["record_digest"] = _digest(target, "record_digest")

    with pytest.raises(AuthorizationError, match="state binding"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    "kms_key",
    [
        "arn:aws:kms:us-east-1:555666777888:key/00000000-0000-0000-0000-000000000001",
        f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:key/00000000-0000-0000-0000-000000000001",
    ],
)
def test_state_kms_key_must_match_exact_account_and_region(kms_key: str) -> None:
    account_ready = _account_ready()
    account_ready["state_infrastructure"]["state_kms_key"] = kms_key
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="state KMS key"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize("status", ["SUSPENDED", "OFFBOARDING", "ARCHIVED"])
def test_non_executable_registry_status_is_denied(status: str) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    target["status"] = status
    target["record_digest"] = _digest(target, "record_digest")

    with pytest.raises(AuthorizationError, match="status"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"status": "RELEASED"},
        {"deployment_id": OTHER_DEPLOYMENT_ID},
        {"account_id": "555666777888"},
        {"region": "us-west-2"},
        {"expires_at": "2026-07-14T17:59:59Z"},
        {"registry_record_digest": "sha256:" + ("f" * 64)},
    ],
)
def test_missing_foreign_released_or_expired_lock_is_denied(
    mutation: dict[str, object],
) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    lock = _lock(target)
    lock.update(mutation)
    lock["lock_digest"] = _digest(lock, "lock_digest")

    with pytest.raises(AuthorizationError, match="lock"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


@pytest.mark.parametrize(
    ("acquired_at", "expires_at", "message"),
    [
        ("2026-07-14T18:01:00Z", "2026-07-14T18:31:00Z", "future"),
        ("2026-07-14T17:59:00Z", "2026-07-14T18:03:00Z", "duration"),
        ("2026-07-14T16:59:00Z", "2026-07-14T18:00:01Z", "duration"),
    ],
)
def test_future_or_out_of_range_lock_interval_is_denied(
    acquired_at: str,
    expires_at: str,
    message: str,
) -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    lock = _lock(target)
    lock["acquired_at"] = acquired_at
    lock["expires_at"] = expires_at
    lock["lock_digest"] = _digest(lock, "lock_digest")

    with pytest.raises(AuthorizationError, match=message):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=lock,
            layer_catalog=_catalog(),
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_new_contracts_accept_multi_segment_aws_partitions() -> None:
    _, target, _, account_ready, lock = _authorized()
    partition = "aws-us-gov"
    for role in account_ready["roles"].values():
        role["arn"] = role["arn"].replace("arn:aws:", f"arn:{partition}:")
    for field in ("state_bucket", "evidence_bucket", "contracts_bucket"):
        account_ready["state_infrastructure"][field] = account_ready[
            "state_infrastructure"
        ][field].replace("arn:aws:", f"arn:{partition}:")
    for field in ("state_kms_key", "evidence_kms_key", "contracts_kms_key"):
        account_ready["state_infrastructure"][field] = account_ready[
            "state_infrastructure"
        ][field].replace("arn:aws:", f"arn:{partition}:")
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target["account_ready"]["contract_digest"] = account_ready["contract_digest"]
    target["state_binding"] = {
        "state_bucket": account_ready["state_infrastructure"]["state_bucket"],
        "state_kms_key": account_ready["state_infrastructure"]["state_kms_key"],
    }
    target["record_digest"] = _digest(target, "record_digest")
    lock["registry_record_digest"] = target["record_digest"]
    lock["lock_digest"] = _digest(lock, "lock_digest")

    result = authorize_backend(
        manifest=_manifest(),
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer="network",
        now=NOW,
        schema_dir=SCHEMAS,
    )

    assert result["backend"]["kms_key_id"].startswith(f"arn:{partition}:kms:")


def test_same_deployment_cannot_acquire_concurrent_or_stale_lock() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    existing = _lock(target)
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": 3,
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match="already held"):
        acquire_lock(existing=existing, request=request, now=NOW)

    stale = copy.deepcopy(existing)
    stale["expires_at"] = "2026-07-14T18:00:00Z"
    stale["lock_digest"] = _digest(stale, "lock_digest")
    with pytest.raises(AuthorizationError, match="reviewed stale-lock recovery"):
        acquire_lock(existing=stale, request=request, now=NOW)


def test_released_lock_can_be_reacquired_with_exact_version() -> None:
    account_ready = _account_ready()
    target = _target(account_ready)
    existing = _lock(target)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": 3,
        "ttl_seconds": 1800,
    }

    acquired = acquire_lock(existing=existing, request=request, now=NOW)

    assert acquired["status"] == "HELD"
    assert acquired["lock_version"] == 4
    assert acquired["lock_digest"] == _digest(acquired, "lock_digest")


@pytest.mark.parametrize("current_status", ["READY", "SUSPENDED"])
def test_released_lock_follows_authorized_registry_digest_transition(
    current_status: str,
) -> None:
    current = _target(_account_ready())
    current["status"] = current_status
    current["record_digest"] = _digest(current, "record_digest")
    proposed = copy.deepcopy(current)
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")
    prepare_registry_update(
        current=current,
        proposed=proposed,
        expected_version=current["registry_version"],
        expected_digest=current["record_digest"],
    )
    existing = _lock(current)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": proposed["record_digest"],
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }

    acquired = acquire_lock(existing=existing, request=request, now=NOW)

    assert acquired["status"] == "HELD"
    assert acquired["lock_version"] == existing["lock_version"] + 1
    assert acquired["registry_record_digest"] == proposed["record_digest"]
    assert acquired["execution_id"] == request["execution_id"]
    assert acquired["owner"] == request["owner"]
    assert acquired["deployment_id"] == existing["deployment_id"]
    assert acquired["account_id"] == existing["account_id"]
    assert acquired["region"] == existing["region"]
    assert acquired["lock_digest"] == _digest(acquired, "lock_digest")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_id", OTHER_ACCOUNT_ID),
        ("region", "us-west-2"),
    ],
)
def test_released_lock_transition_cannot_reassign_identity(
    field: str,
    value: str,
) -> None:
    current = _target(_account_ready())
    existing = _lock(current)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": "sha256:" + ("f" * 64),
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }
    request[field] = value

    with pytest.raises(AuthorizationError, match="cannot be reassigned"):
        acquire_lock(existing=existing, request=request, now=NOW)


def test_held_lock_cannot_substitute_registry_digest() -> None:
    target = _target(_account_ready())
    existing = _lock(target)
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": "sha256:" + ("f" * 64),
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match="registry_record_digest"):
        acquire_lock(existing=existing, request=request, now=NOW)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"expected_lock_version": 2}, "version conflict"),
        ({"registry_record_digest": "not-a-digest"}, "digest"),
    ],
)
def test_released_lock_transition_rejects_stale_or_malformed_request(
    mutation: dict[str, object],
    message: str,
) -> None:
    target = _target(_account_ready())
    existing = _lock(target)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": "sha256:" + ("f" * 64),
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }
    request.update(mutation)

    with pytest.raises(AuthorizationError, match=message):
        acquire_lock(existing=existing, request=request, now=NOW)


@pytest.mark.parametrize(
    ("acquired_at", "expires_at", "message"),
    [
        ("2026-07-14T18:01:00Z", "2026-07-14T18:31:00Z", "future"),
        ("2026-07-14T17:00:00", "2026-07-14T17:30:00Z", "timezone-aware"),
    ],
)
def test_released_lock_rejects_ambiguous_existing_timestamps(
    acquired_at: str,
    expires_at: str,
    message: str,
) -> None:
    target = _target(_account_ready())
    existing = _lock(target)
    existing.update(
        status="RELEASED",
        acquired_at=acquired_at,
        expires_at=expires_at,
    )
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match=message):
        acquire_lock(existing=existing, request=request, now=NOW)


def test_released_lock_replay_with_stale_version_is_denied() -> None:
    target = _target(_account_ready())
    existing = _lock(target)
    existing["status"] = "RELEASED"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }
    acquired = acquire_lock(existing=existing, request=request, now=NOW)

    with pytest.raises(AuthorizationError, match="version conflict"):
        acquire_lock(existing=acquired, request=request, now=NOW)


def test_lock_acquisition_rejects_unknown_state_and_ambiguous_input() -> None:
    target = _target(_account_ready())
    existing = _lock(target)
    existing["status"] = "UNKNOWN"
    existing["lock_digest"] = _digest(existing, "lock_digest")
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": existing["lock_version"],
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match="unknown state"):
        acquire_lock(existing=existing, request=request, now=NOW)

    request["unexpected"] = "ambiguous"
    with pytest.raises(AuthorizationError, match="fields are malformed"):
        acquire_lock(existing=None, request=request, now=NOW)


def test_lock_acquisition_requires_timezone_aware_current_time() -> None:
    target = _target(_account_ready())
    request = {
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "execution_id": "exec_01J5A1B2C3D4E5F6G7H8J9K0M2",
        "owner": "github:synthetic/repository:run:124",
        "registry_record_digest": target["record_digest"],
        "expected_lock_version": 0,
        "ttl_seconds": 1800,
    }

    with pytest.raises(AuthorizationError, match="current time must be timezone-aware"):
        acquire_lock(existing=None, request=request, now=datetime(2026, 7, 14, 18, 0))


def test_state_key_is_collision_free_across_deployments() -> None:
    first, target, _, account_ready, lock = _authorized()
    manifest = _manifest()
    manifest["deployment_id"] = OTHER_DEPLOYMENT_ID
    account_ready["deployment_id"] = OTHER_DEPLOYMENT_ID
    for role in account_ready["roles"].values():
        role["deployment_id_tag"] = OTHER_DEPLOYMENT_ID
    account_ready["contract_digest"] = _digest(account_ready, "contract_digest")
    target["deployment_id"] = OTHER_DEPLOYMENT_ID
    target["account_ready"]["contract_digest"] = account_ready["contract_digest"]
    target["record_digest"] = _digest(target, "record_digest")
    lock["deployment_id"] = OTHER_DEPLOYMENT_ID
    lock["registry_record_digest"] = target["record_digest"]
    lock["lock_digest"] = _digest(lock, "lock_digest")

    second = authorize_backend(
        manifest=manifest,
        target=target,
        anchor=_anchor(target),
        account_ready=account_ready,
        execution_lock=lock,
        layer_catalog=_catalog(),
        layer="network",
        now=NOW,
        schema_dir=SCHEMAS,
    )

    assert first["backend"]["key"] != second["backend"]["key"]


def test_path_traversal_or_nonterraform_layer_is_rejected() -> None:
    catalog = _catalog()
    catalog["layers"][2]["state_key"] = "{deployment_id}/../foreign.tfstate"
    account_ready = _account_ready()
    target = _target(account_ready)

    with pytest.raises(AuthorizationError, match="state key"):
        authorize_backend(
            manifest=_manifest(),
            target=target,
            anchor=_anchor(target),
            account_ready=account_ready,
            execution_lock=_lock(target),
            layer_catalog=catalog,
            layer="network",
            now=NOW,
            schema_dir=SCHEMAS,
        )


def test_backend_hcl_uses_native_lockfile_and_no_legacy_table() -> None:
    binding, *_ = _authorized()

    rendered = render_backend_hcl(binding)

    assert "use_lockfile = true" in rendered
    assert "encrypt = true" in rendered
    assert f'key = "{DEPLOYMENT_ID}/{REGION}/network/terraform.tfstate"' in rendered
    assert "dynamodb_table" not in rendered
    assert "lock_table" not in rendered


def test_strict_json_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    document = tmp_path / "duplicate.json"
    document.write_text('{"deployment_id":"one","deployment_id":"two"}')

    with pytest.raises(AuthorizationError, match="duplicate"):
        load_json_strict(document)


def test_backend_artifacts_are_private_and_symlinks_are_denied(tmp_path: Path) -> None:
    destination = tmp_path / "backend.hcl"
    write_private_file(destination, "encrypt = true\n")
    assert destination.stat().st_mode & 0o777 == 0o600

    symlink = tmp_path / "backend-link.hcl"
    symlink.symlink_to(destination)
    with pytest.raises(AuthorizationError, match="symlink"):
        write_private_file(symlink, "replacement\n")


def test_all_operational_backend_templates_use_native_lockfile() -> None:
    templates = sorted((REPO_ROOT / "roots").glob("*/backend.example.hcl"))
    operational = [path for path in templates if "account-ready-gate" not in str(path)]
    assert operational
    for path in operational:
        text = path.read_text()
        assert "use_lockfile" in text, path
        assert "dynamodb_table" not in text, path


def test_each_terraform_layer_declares_s3_backend() -> None:
    catalog = _catalog()
    for stage in catalog["layers"]:
        if stage["kind"] != "terraform":
            continue
        root = REPO_ROOT / stage["root"]
        terraform_source = "\n".join(
            path.read_text() for path in sorted(root.glob("*.tf"))
        )
        assert 'backend "s3" {}' in terraform_source, stage["layer"]


def test_registry_policy_cannot_scan_or_unconditionally_delete() -> None:
    policy = json.loads((REPO_ROOT / "policies/iam/orchestrator-role.json").read_text())
    allowed_actions = {
        action
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }
    assert "dynamodb:Scan" not in allowed_actions
    assert "dynamodb:DeleteItem" not in allowed_actions
    registry_writes = [
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "WriteDeploymentRegistry"
    ]
    assert len(registry_writes) == 1
    assert "dynamodb:LeadingKeys" in json.dumps(registry_writes[0]["Condition"])


def test_state_recovery_cannot_delete_state_or_arbitrary_prefixes() -> None:
    policy = json.loads((REPO_ROOT / "policies/iam/state-recovery-role.json").read_text())
    delete_statements = []
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = statement["Action"]
        actions = actions if isinstance(actions, list) else [actions]
        resources = statement["Resource"]
        resources = resources if isinstance(resources, list) else [resources]
        if "s3:DeleteObject" in actions:
            delete_statements.append(statement)
            assert all(resource.endswith("terraform.tfstate.tflock") for resource in resources)
    assert len(delete_statements) == 1
    assert delete_statements[0]["Condition"]["StringEquals"][
        "aws:PrincipalTag/recovery_approved"
    ] == "true"


def test_state_recovery_version_inventory_is_exactly_bound() -> None:
    policy = json.loads((REPO_ROOT / "policies/iam/state-recovery-role.json").read_text())
    statements = policy["Statement"]
    listings = [
        statement
        for statement in statements
        if statement.get("Sid") == "ListBoundStateVersions"
    ]

    assert len(listings) == 1
    listing = listings[0]
    actions = listing["Action"]
    assert set(actions if isinstance(actions, list) else [actions]) == {
        "s3:ListBucket",
        "s3:ListBucketVersions",
    }
    assert listing["Resource"] == (
        "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-state"
    )
    assert listing["Condition"] == {
        "StringLike": {
            "s3:prefix": "${deployment_id}/*/terraform.tfstate",
        },
        "StringEquals": {
            "aws:PrincipalTag/deployment_id": "${deployment_id}",
            "aws:PrincipalTag/operation": "state-recovery",
        },
    }
    allowed_actions = {
        action
        for statement in statements
        if statement["Effect"] == "Allow"
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }
    assert "s3:ListAllMyBuckets" not in allowed_actions
    assert "s3:DeleteObjectVersion" not in allowed_actions
    assert all("*" not in resource for resource in [listing["Resource"]])


def test_state_recovery_trust_requires_independent_review_and_exact_tags() -> None:
    trust = json.loads((REPO_ROOT / "policies/trust/state-recovery-trust.json").read_text())
    by_action = {statement["Action"]: statement for statement in trust["Statement"]}
    assert set(by_action) == {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }
    assume = by_action["sts:AssumeRole"]["Condition"]
    assert assume["StringEquals"]["aws:PrincipalTag/mfa_authenticated"] == "true"
    assert assume["StringEquals"]["aws:PrincipalTag/break_glass_approved"] == "true"
    assert assume["StringEquals"]["aws:RequestTag/recovery_approved"] == "true"
    assert assume["StringLike"]["aws:RequestTag/incident_id"] == "inc_*"
    tags = by_action["sts:TagSession"]["Condition"]
    assert set(tags["ForAllValues:StringEquals"]["aws:TagKeys"]) == {
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "operation",
        "incident_id",
        "operator_id",
        "recovery_approved",
    }
    assert all(value == "false" for value in tags["Null"].values())


def test_backend_authorization_precedes_aws_identity_lookup() -> None:
    wrapper = (REPO_ROOT / "scripts/deployment/terraform-layer.sh").read_text()

    assert wrapper.index("tooling/authorize_deployment_backend.py") < wrapper.index(
        "aws sts get-caller-identity"
    )


def test_top_level_plan_delegates_account_verification_to_authorized_child() -> None:
    wrapper = (REPO_ROOT / "scripts/deployment/scanalyze-deploy.sh").read_text()
    plan_layer = wrapper[
        wrapper.index("cmd_plan_layer() {") : wrapper.index("cmd_apply_layer() {")
    ]
    deploy_services = wrapper[
        wrapper.index("cmd_deploy_services() {") : wrapper.index("cmd_validate_live() {")
    ]

    assert "guard_account_binding" not in plan_layer
    assert "guard_account_binding" not in deploy_services
    assert 'bash "$SCRIPT_DIR/terraform-layer.sh" plan' in plan_layer
    assert 'LAYER="services" cmd_plan_layer' in deploy_services


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-target",
        "tampered-target-digest",
        "tampered-account-ready",
        "wrong-anchor",
        "released-lock",
        "foreign-lock",
    ],
)
def test_top_level_invalid_backend_evidence_calls_no_aws_or_terraform(
    tmp_path: Path,
    mutation: str,
) -> None:
    result, aws_marker, terraform_marker = _run_top_level_invalid_plan(
        tmp_path,
        mutation,
    )

    assert result.returncode != 0
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    output = result.stdout + result.stderr
    for sensitive in (
        ACCOUNT_ID,
        DEPLOYMENT_ID,
        f"scanalyze-{ACCOUNT_ID}-tf-state",
        "arn:aws:kms:",
        "sha256:",
        "exec_",
    ):
        assert sensitive not in output


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--deployment-id", OTHER_DEPLOYMENT_ID),
        ("--account-id", OTHER_ACCOUNT_ID),
        ("--region", "us-west-2"),
    ],
)
def test_top_level_wrong_request_assertion_calls_no_aws_or_terraform(
    tmp_path: Path,
    option: str,
    value: str,
) -> None:
    result, aws_marker, terraform_marker = _run_top_level_invalid_plan(
        tmp_path,
        "tampered-target-digest",
        assertion_override=(option, value),
    )

    assert result.returncode != 0
    assert "conflicts with the validated manifest" in result.stderr
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    assert value not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-target",
        "tampered-target-digest",
        "tampered-account-ready",
        "wrong-anchor",
        "released-lock",
        "foreign-lock",
    ],
)
def test_deploy_services_invalid_backend_evidence_calls_no_aws_or_terraform(
    tmp_path: Path,
    mutation: str,
) -> None:
    result, aws_marker, terraform_marker = _run_top_level_invalid_plan(
        tmp_path,
        mutation,
        command_name="deploy-services",
    )

    assert result.returncode != 0
    assert not aws_marker.exists()
    assert not terraform_marker.exists()
    output = result.stdout + result.stderr
    for sensitive in (
        ACCOUNT_ID,
        DEPLOYMENT_ID,
        f"scanalyze-{ACCOUNT_ID}-tf-state",
        "arn:aws:kms:",
        "sha256:",
        "exec_",
    ):
        assert sensitive not in output


def test_registry_create_is_create_only() -> None:
    target = _target(_account_ready())
    target["registry_version"] = 1
    target["record_digest"] = _digest(target, "record_digest")

    write = prepare_registry_create(target)

    assert write["condition_expression"] == "attribute_not_exists(deployment_id)"


def test_registry_update_requires_exact_version_digest_and_binding() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    write = prepare_registry_update(
        current=current,
        proposed=proposed,
        expected_version=current["registry_version"],
        expected_digest=current["record_digest"],
    )

    assert "registry_version = :expected_version" in write["condition_expression"]
    assert "record_digest = :expected_digest" in write["condition_expression"]
    assert "customer_id = :customer_id" in write["condition_expression"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"),
        ("deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_id", "555666777888"),
        ("region", "us-west-2"),
    ],
)
def test_registry_update_cannot_reassign_ownership(
    field: str,
    value: str,
) -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed[field] = value
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="immutable"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )


def test_registry_update_rejects_stale_compare_and_swap() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ACTIVE"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="version conflict"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"] - 1,
            expected_digest=current["record_digest"],
        )


def test_registry_update_rejects_unsafe_lifecycle_jump() -> None:
    current = _target(_account_ready())
    proposed = copy.deepcopy(current)
    proposed["status"] = "ARCHIVED"
    proposed["registry_version"] += 1
    proposed["record_digest"] = _digest(proposed, "record_digest")

    with pytest.raises(AuthorizationError, match="transition is forbidden"):
        prepare_registry_update(
            current=current,
            proposed=proposed,
            expected_version=current["registry_version"],
            expected_digest=current["record_digest"],
        )
