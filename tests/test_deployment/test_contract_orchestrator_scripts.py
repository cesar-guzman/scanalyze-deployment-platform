"""Safety and integrity tests for local contract resolution/publication."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tooling.validate_digest import canonicalize, compute_digest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PUBLISH_SCRIPT = REPO_ROOT / "scripts" / "deployment" / "publish-contract.py"
RESOLVE_SCRIPT = REPO_ROOT / "scripts" / "deployment" / "resolve-contracts.py"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
ACCOUNT_ID = "111222333444"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
RELEASE_VERSION = "2026.07.14"
MODULE_SOURCE_DIGEST = "sha256:" + ("b" * 64)
STATE_KEY = f"{DEPLOYMENT_ID}/global/terraform.tfstate"
PRODUCED_AT = "2026-07-10T18:30:00Z"
RESOLVED_AT = "2026-07-10T18:35:00Z"


@pytest.fixture
def global_outputs() -> dict:
    return {
        "ecs_execution_role_arn": (
            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeEcsExecution"
        ),
        "ecs_task_role_arns": {
            "scanalyze-ingest-api": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngestTask"
            )
        },
    }


def _terraform_output(outputs: dict) -> dict:
    document = {
        "contract_payload": {
            "sensitive": False,
            "value": {"layer": "global", "schema_version": "1", "state_scope": "global"},
        }
    }
    document.update(
        {
            name: {"sensitive": False, "value": value}
            for name, value in outputs.items()
        }
    )
    return document


def _publish_args(source: Path, output: Path) -> list[str]:
    return [
        sys.executable,
        str(PUBLISH_SCRIPT),
        "--from-terraform-output-json",
        str(source),
        "--layer",
        "global",
        "--customer-id",
        CUSTOMER_ID,
        "--deployment-id",
        DEPLOYMENT_ID,
        "--account-id",
        ACCOUNT_ID,
        "--region",
        "global",
        "--release-digest",
        RELEASE_DIGEST,
        "--release-version",
        RELEASE_VERSION,
        "--module-source-digest",
        MODULE_SOURCE_DIGEST,
        "--produced-at",
        PRODUCED_AT,
        "--state-key",
        STATE_KEY,
        "--out",
        str(output),
    ]


def _resolve_args(contract: Path, output: Path) -> list[str]:
    return [
        sys.executable,
        str(RESOLVE_SCRIPT),
        "--contract",
        str(contract),
        "--allow-fixtures",
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
        "--release-digest",
        RELEASE_DIGEST,
        "--release-version",
        RELEASE_VERSION,
        "--resolved-at",
        RESOLVED_AT,
        "--required-contract",
        "global/v1",
        "--out",
        str(output),
    ]


def _run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _write_json(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def test_publish_is_dry_run_and_writes_valid_mode_0600_envelope(
    tmp_path, global_outputs
):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))

    result = _run(_publish_args(source, output))

    assert result.returncode == 0, result.stderr
    assert "DRY_RUN" in result.stdout
    assert "AWS_WRITE=disabled" in result.stdout
    assert ACCOUNT_ID not in result.stdout
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    envelope = json.loads(output.read_text(encoding="utf-8"))
    assert envelope["outputs"] == global_outputs
    assert envelope["contract_digest"] == compute_digest(canonicalize(global_outputs))
    assert envelope["producer"] == "roots/global"
    assert envelope["output_schema_version"] == "global/v1"
    assert envelope["produced_at"] == PRODUCED_AT
    assert envelope["release_version"] == RELEASE_VERSION


def test_publish_rejects_non_default_workspace(tmp_path, global_outputs):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    args = _publish_args(source, output) + ["--terraform-workspace", "custom"]

    result = _run(args)

    assert result.returncode == 2
    assert not output.exists()


def test_publish_rejects_invalid_explicit_produced_at(tmp_path, global_outputs):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    args = _publish_args(source, output)
    args[args.index(PRODUCED_AT)] = "not-a-timestamp"

    result = _run(args)

    assert result.returncode == 1
    assert "produced_at" in result.stderr
    assert "not-a-timestamp" not in result.stderr
    assert not output.exists()


def test_publish_never_overwrites_or_deletes_existing_output(tmp_path, global_outputs):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    output.write_text("preserve-me", encoding="utf-8")

    result = _run(_publish_args(source, output))

    assert result.returncode == 1
    assert output.read_text(encoding="utf-8") == "preserve-me"


def test_publish_rejects_state_key_owned_by_another_layer(tmp_path, global_outputs):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    args = _publish_args(source, output)
    args[args.index(STATE_KEY)] = f"{DEPLOYMENT_ID}/edge/terraform.tfstate"

    result = _run(args)

    assert result.returncode == 1
    assert "not owned by the declared producer layer" in result.stderr
    assert not output.exists()


def test_resolve_requires_explicit_allow_fixtures(tmp_path, global_outputs):
    contract = tmp_path / "contract.json"
    output = tmp_path / "vars.json"
    envelope = {
        "outputs": global_outputs,
    }
    _write_json(contract, envelope)
    args = _resolve_args(contract, output)
    args.remove("--allow-fixtures")

    result = _run(args)

    assert result.returncode == 2
    assert "BLOCKED_FIXTURES" in result.stderr
    assert not output.exists()


def test_publish_then_resolve_writes_content_bound_resolution_to_mode_0600(
    tmp_path, global_outputs
):
    terraform_output = tmp_path / "terraform-output.json"
    envelope = tmp_path / "global-envelope.json"
    var_file = tmp_path / "network.auto.tfvars.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    publish_result = _run(_publish_args(terraform_output, envelope))
    assert publish_result.returncode == 0, publish_result.stderr

    result = _run(_resolve_args(envelope, var_file))

    assert result.returncode == 0, result.stderr
    assert "resolved 1 contract(s)" in result.stdout
    assert ACCOUNT_ID not in result.stdout
    resolution = json.loads(var_file.read_text(encoding="utf-8"))
    assert resolution["consumer_layer"] == "network"
    assert resolution["customer_id"] == CUSTOMER_ID
    assert resolution["release_version"] == RELEASE_VERSION
    assert resolution["required_contracts"][0]["contract_id"] == "global/v1"
    assert resolution["variables"]["upstream_contract_digest"] == (
        resolution["variables"]["expected_upstream_digest"]
    )
    assert stat.S_IMODE(var_file.stat().st_mode) == 0o600


def test_resolve_rejects_tampered_digest_without_echoing_values(tmp_path, global_outputs):
    terraform_output = tmp_path / "terraform-output.json"
    envelope_path = tmp_path / "global-envelope.json"
    var_file = tmp_path / "network.auto.tfvars.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    assert _run(_publish_args(terraform_output, envelope_path)).returncode == 0
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["contract_digest"] = "sha256:" + ("0" * 64)
    envelope_path.unlink()
    _write_json(envelope_path, envelope)

    result = _run(_resolve_args(envelope_path, var_file))

    assert result.returncode == 1
    assert "digest verification failed" in result.stderr
    assert ACCOUNT_ID not in result.stderr
    assert not var_file.exists()


def test_resolve_rejects_binding_mismatch_without_echoing_identifiers(
    tmp_path, global_outputs
):
    terraform_output = tmp_path / "terraform-output.json"
    envelope_path = tmp_path / "global-envelope.json"
    var_file = tmp_path / "network.auto.tfvars.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    assert _run(_publish_args(terraform_output, envelope_path)).returncode == 0
    args = _resolve_args(envelope_path, var_file)
    expected_index = args.index(ACCOUNT_ID)
    args[expected_index] = "999888777666"

    result = _run(args)

    assert result.returncode == 1
    assert "account binding mismatch" in result.stderr
    assert ACCOUNT_ID not in result.stderr
    assert "999888777666" not in result.stderr
    assert not var_file.exists()


def test_resolve_rejects_state_ownership_mismatch(tmp_path, global_outputs):
    terraform_output = tmp_path / "terraform-output.json"
    envelope_path = tmp_path / "global-envelope.json"
    var_file = tmp_path / "network.auto.tfvars.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    assert _run(_publish_args(terraform_output, envelope_path)).returncode == 0
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    envelope["state_key"] = f"{DEPLOYMENT_ID}/edge/terraform.tfstate"
    envelope_path.unlink()
    _write_json(envelope_path, envelope)

    result = _run(_resolve_args(envelope_path, var_file))

    assert result.returncode == 1
    assert "state ownership binding mismatch" in result.stderr
    assert not var_file.exists()


def test_publish_rejects_sensitive_output_without_echoing_secret(tmp_path, global_outputs):
    secret = "do-not-print-this-secret"
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    document = _terraform_output(global_outputs)
    document["unsafe"] = {"sensitive": True, "value": secret}
    _write_json(source, document)

    result = _run(_publish_args(source, output))

    assert result.returncode == 1
    assert "sensitive value" in result.stderr
    assert secret not in result.stdout + result.stderr
    assert not output.exists()


@pytest.mark.parametrize("acknowledged", [False, True])
def test_publish_live_mode_is_always_blocked_before_writing(
    tmp_path, global_outputs, acknowledged
):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    args = _publish_args(source, output) + ["--live"]
    env = os.environ.copy()
    if acknowledged:
        env["SCANALYZE_ALLOW_LIVE"] = "1"
    else:
        env.pop("SCANALYZE_ALLOW_LIVE", None)

    result = _run(args, env=env)

    assert result.returncode == 2
    assert "BLOCKED_LIVE" in result.stderr
    if acknowledged:
        assert "not implemented" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("acknowledged", [False, True])
def test_resolve_live_mode_is_always_blocked_before_writing(tmp_path, acknowledged):
    output = tmp_path / "network.auto.tfvars.json"
    args = [
        sys.executable,
        str(RESOLVE_SCRIPT),
        "--live",
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
            "--release-digest",
            RELEASE_DIGEST,
            "--release-version",
            RELEASE_VERSION,
            "--resolved-at",
            RESOLVED_AT,
        "--required-contract",
        "global/v1",
        "--out",
        str(output),
    ]
    env = os.environ.copy()
    if acknowledged:
        env["SCANALYZE_ALLOW_LIVE"] = "1"
    else:
        env.pop("SCANALYZE_ALLOW_LIVE", None)

    result = _run(args, env=env)

    assert result.returncode == 2
    assert "BLOCKED_LIVE" in result.stderr
    if acknowledged:
        assert "not implemented" in result.stderr
    assert not output.exists()
