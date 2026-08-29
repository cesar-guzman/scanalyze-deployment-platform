"""Safety and integrity tests for local contract resolution/publication."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
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


def _write_stateful_fake_aws(
    executable: Path,
    *,
    state_path: Path,
    calls_path: Path,
) -> None:
    """Create a hermetic AWS CLI fake for the live contract lifecycle."""
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        f"state_path = Path({str(state_path)!r})\n"
        f"calls_path = Path({str(calls_path)!r})\n"
        "args = sys.argv[1:]\n"
        "service, operation = args[0], args[1]\n"
        "def value(option):\n"
        "    return args[args.index(option) + 1]\n"
        "region = value('--region')\n"
        "account = os.environ['FAKE_AWS_ACCOUNT_ID']\n"
        "calls = json.loads(calls_path.read_text()) if calls_path.exists() else []\n"
        "entry = {'service': service, 'operation': operation, 'region': region}\n"
        "if operation == 'put-parameter':\n"
        "    entry['no_overwrite'] = '--no-overwrite' in args\n"
        "    entry['tag_count'] = len(json.loads(value('--tags')))\n"
        "calls.append(entry)\n"
        "calls_path.write_text(json.dumps(calls))\n"
        "state = json.loads(state_path.read_text()) if state_path.exists() else {}\n"
        "if (service, operation) == ('sts', 'get-caller-identity'):\n"
        "    result = {'Account': account, 'Arn': f'arn:aws:sts::{account}:assumed-role/ScanalyzePlan/fake', 'UserId': 'AROATEST:fake'}\n"
        "elif (service, operation) == ('ssm', 'put-parameter'):\n"
        "    name = value('--name')\n"
        "    if name in state or '--no-overwrite' not in args:\n"
        "        sys.exit(254)\n"
        "    state[name] = {'parameter': {'Name': name, 'Type': 'String', 'Value': value('--value'), 'Version': 1, 'ARN': f'arn:aws:ssm:{region}:{account}:parameter{name}', 'DataType': 'text'}, 'tags': json.loads(value('--tags'))}\n"
        "    state_path.write_text(json.dumps(state))\n"
        "    result = {'Version': 1, 'Tier': 'Standard'}\n"
        "elif (service, operation) == ('ssm', 'get-parameter'):\n"
        "    result = {'Parameter': state[value('--name')]['parameter']}\n"
        "elif (service, operation) == ('ssm', 'list-tags-for-resource'):\n"
        "    result = {'TagList': state[value('--resource-id')]['tags']}\n"
        "elif (service, operation) == ('ssm', 'get-parameters-by-path'):\n"
        "    prefix = value('--path') + '/'\n"
        "    if '--next-token' not in args:\n"
        "        result = {'Parameters': [], 'NextToken': 'page-2'}\n"
        "    else:\n"
        "        result = {'Parameters': [item['parameter'] for name, item in sorted(state.items()) if name.startswith(prefix)]}\n"
        "else:\n"
        "    sys.exit(253)\n"
        "print(json.dumps(result))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)


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
    assert resolution["schema_version"] == "3"
    assert resolution["consumer_layer"] == "network"
    assert resolution["customer_id"] == CUSTOMER_ID
    assert resolution["release_version"] == RELEASE_VERSION
    assert resolution["required_contracts"][0]["output_schema_version"] == "global/v1"
    assert resolution["required_contracts"][0]["outputs"] == global_outputs
    assert "variables" not in resolution
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


def test_publish_live_mode_requires_acknowledgement_before_aws(
    tmp_path, global_outputs
):
    source = tmp_path / "terraform-output.json"
    output = tmp_path / "global-envelope.json"
    _write_json(source, _terraform_output(global_outputs))
    args = _publish_args(source, output) + ["--live"]
    env = os.environ.copy()
    env.pop("SCANALYZE_ALLOW_LIVE", None)

    result = _run(args, env=env)

    assert result.returncode == 2
    assert "BLOCKED_LIVE" in result.stderr
    assert not output.exists()


def test_resolve_live_mode_requires_acknowledgement_before_aws(tmp_path):
    output = tmp_path / "network.auto.tfvars.json"
    aws_marker = tmp_path / "aws-called"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_aws = fake_bin / "aws"
    fake_aws.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"Path({str(aws_marker)!r}).write_text('called\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    fake_aws.chmod(0o755)
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
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env.pop("SCANALYZE_ALLOW_LIVE", None)

    result = _run(args, env=env)

    assert result.returncode == 2
    assert "BLOCKED_LIVE" in result.stderr
    assert not output.exists()
    assert not aws_marker.exists()


def test_live_publish_then_resolve_uses_create_only_ssm_and_exact_readback(
    tmp_path, global_outputs
):
    action_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    terraform_output = tmp_path / "terraform-output.json"
    envelope_path = tmp_path / "global-envelope.json"
    resolution_path = tmp_path / "network.resolution.json"
    replay_path = tmp_path / "replay-envelope.json"
    fake_aws = tmp_path / "aws"
    state_path = tmp_path / "ssm-state.json"
    calls_path = tmp_path / "aws-calls.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    _write_stateful_fake_aws(
        fake_aws,
        state_path=state_path,
        calls_path=calls_path,
    )
    env = os.environ.copy()
    env["SCANALYZE_ALLOW_LIVE"] = "1"
    env["FAKE_AWS_ACCOUNT_ID"] = ACCOUNT_ID

    publish_args = _publish_args(terraform_output, envelope_path) + [
        "--live",
        "--aws-region",
        "us-east-1",
        "--use-runtime-credentials",
        "--aws-cli",
        str(fake_aws),
    ]
    publish_args[publish_args.index(PRODUCED_AT)] = action_time
    published = _run(publish_args, env=env)
    assert published.returncode == 0, published.stderr
    assert "published immutable contract" in published.stdout
    assert ACCOUNT_ID not in published.stdout + published.stderr
    assert stat.S_IMODE(envelope_path.stat().st_mode) == 0o600

    resolved = _run(
        [
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
            "--aws-region",
            "us-east-1",
            "--use-runtime-credentials",
            "--aws-cli",
            str(fake_aws),
            "--release-digest",
            RELEASE_DIGEST,
            "--release-version",
            RELEASE_VERSION,
            "--resolved-at",
            action_time,
            "--required-contract",
            "global/v1",
            "--out",
            str(resolution_path),
        ],
        env=env,
    )
    assert resolved.returncode == 0, resolved.stderr
    assert ACCOUNT_ID not in resolved.stdout + resolved.stderr
    resolution = json.loads(resolution_path.read_text(encoding="utf-8"))
    assert resolution["required_contracts"] == [
        json.loads(envelope_path.read_text(encoding="utf-8"))
    ]
    assert stat.S_IMODE(resolution_path.stat().st_mode) == 0o600

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(state) == 1
    parameter_name = next(iter(state))
    assert ":" not in parameter_name
    assert "/releases/sha256-" in parameter_name
    calls = json.loads(calls_path.read_text(encoding="utf-8"))
    assert calls[0]["operation"] == "get-caller-identity"
    assert [call["operation"] for call in calls].count("put-parameter") == 1
    put = next(call for call in calls if call["operation"] == "put-parameter")
    assert put == {
        "service": "ssm",
        "operation": "put-parameter",
        "region": "us-east-1",
        "no_overwrite": True,
        "tag_count": 7,
    }
    assert all(call["region"] == "us-east-1" for call in calls)

    replay_args = [
        replay_path.as_posix() if value == envelope_path.as_posix() else value
        for value in publish_args
    ]
    replayed = _run(replay_args, env=env)
    assert replayed.returncode == 0, replayed.stderr
    assert "published immutable contract" in replayed.stdout
    assert json.loads(replay_path.read_text(encoding="utf-8")) == json.loads(
        envelope_path.read_text(encoding="utf-8")
    )
    assert stat.S_IMODE(replay_path.stat().st_mode) == 0o600
    replay_calls = json.loads(calls_path.read_text(encoding="utf-8"))
    assert [call["operation"] for call in replay_calls].count("put-parameter") == 2
    assert [call["operation"] for call in replay_calls].count("get-parameter") >= 6
    assert [call["operation"] for call in replay_calls].count(
        "list-tags-for-resource"
    ) == 4


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("schema", "schema validation failed"),
        ("digest", "digest verification failed"),
        ("stale", "contract is stale"),
    ],
)
def test_live_resolution_rejects_invalid_or_stale_ssm_envelope(
    tmp_path, global_outputs, case, expected
):
    action_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    terraform_output = tmp_path / "terraform-output.json"
    envelope_path = tmp_path / "global-envelope.json"
    resolution_path = tmp_path / "network.resolution.json"
    fake_aws = tmp_path / "aws"
    state_path = tmp_path / "ssm-state.json"
    calls_path = tmp_path / "aws-calls.json"
    _write_json(terraform_output, _terraform_output(global_outputs))
    _write_stateful_fake_aws(
        fake_aws,
        state_path=state_path,
        calls_path=calls_path,
    )
    env = os.environ.copy()
    env["SCANALYZE_ALLOW_LIVE"] = "1"
    env["FAKE_AWS_ACCOUNT_ID"] = ACCOUNT_ID
    publish_args = _publish_args(terraform_output, envelope_path) + [
        "--live",
        "--aws-region",
        "us-east-1",
        "--use-runtime-credentials",
        "--aws-cli",
        str(fake_aws),
    ]
    publish_args[publish_args.index(PRODUCED_AT)] = action_time
    published = _run(publish_args, env=env)
    assert published.returncode == 0, published.stderr

    state = json.loads(state_path.read_text(encoding="utf-8"))
    stored = next(iter(state.values()))["parameter"]
    envelope = json.loads(stored["Value"])
    if case == "schema":
        envelope.pop("module_source_digest")
    elif case == "digest":
        envelope["outputs"]["ecs_execution_role_arn"] = (
            f"arn:aws:iam::{ACCOUNT_ID}:role/Altered"
        )
    else:
        envelope["produced_at"] = "2026-07-01T00:00:00Z"
    stored["Value"] = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    state_path.write_text(json.dumps(state), encoding="utf-8")

    result = _run(
        [
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
            "--aws-region",
            "us-east-1",
            "--use-runtime-credentials",
            "--aws-cli",
            str(fake_aws),
            "--release-digest",
            RELEASE_DIGEST,
            "--release-version",
            RELEASE_VERSION,
            "--resolved-at",
            action_time,
            "--max-contract-age-seconds",
            "3600",
            "--required-contract",
            "global/v1",
            "--out",
            str(resolution_path),
        ],
        env=env,
    )

    assert result.returncode == 1
    assert expected in result.stderr
    assert ACCOUNT_ID not in result.stdout + result.stderr
    assert not resolution_path.exists()
