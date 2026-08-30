"""Hermetic contracts for the read-only Terraform observation action."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_deployment.test_gug122_backend_authorization import (
    ACCOUNT_ID,
    CUSTOMER_ID,
    DEPLOYMENT_ID,
    ENVIRONMENT,
    REGION,
    _account_ready,
    _anchor,
    _manifest,
    _target,
    _write_executable,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER = REPO_ROOT / "scripts/deployment/terraform-layer.sh"


def _run_wrapper(
    tmp_path: Path,
    *,
    action: str,
    terraform_plan_rc: int,
) -> tuple[subprocess.CompletedProcess[str], Path, Path, Path]:
    account_ready = _account_ready()
    target = _target(account_ready)
    anchor = _anchor(target)
    evidence = {
        "manifest": tmp_path / "manifest.json",
        "target": tmp_path / "target.json",
        "anchor": tmp_path / "anchor.json",
        "account_ready": tmp_path / "account-ready.json",
    }
    for name, document in (
        ("manifest", _manifest()),
        ("target", target),
        ("anchor", anchor),
        ("account_ready", account_ready),
    ):
        evidence[name].write_text(json.dumps(document), encoding="utf-8")
        evidence[name].chmod(0o600)

    plan_dir = tmp_path / "plans"
    plan_dir.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    aws_marker = tmp_path / "aws-called"
    terraform_marker = tmp_path / "terraform-calls"
    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf 'called\n' > {shlex.quote(str(aws_marker))}
        exit 97
        """,
    )
    _write_executable(
        fake_bin / "terraform",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf '%s\n' "$*" >> {shlex.quote(str(terraform_marker))}
        phase=""
        plan_file=""
        for argument in "$@"; do
          case "$argument" in
            init|plan|apply) phase="$argument" ;;
            -out=*) plan_file="${{argument#-out=}}" ;;
          esac
        done
        if [[ "$phase" == "apply" ]]; then
          exit 98
        fi
        if [[ "$phase" == "plan" ]]; then
          [[ -n "$plan_file" ]]
          : > "$plan_file"
          exit {terraform_plan_rc}
        fi
        [[ "$phase" == "init" ]]
        """,
    )
    command = [
        "bash",
        str(WRAPPER),
        action,
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
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("AWS_") or name.startswith("TF_"):
            env.pop(name, None)
    env["PATH"] = f"{fake_bin}:{Path(sys.executable).parent}:{env['PATH']}"
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return result, aws_marker, terraform_marker, plan_dir


@pytest.mark.parametrize("terraform_plan_rc", [0, 2])
def test_observe_accepts_no_change_and_change_without_locking(
    tmp_path: Path,
    terraform_plan_rc: int,
) -> None:
    result, aws_marker, terraform_marker, plan_dir = _run_wrapper(
        tmp_path,
        action="observe",
        terraform_plan_rc=terraform_plan_rc,
    )

    assert result.returncode == 0, result.stderr
    assert not aws_marker.exists()
    calls = terraform_marker.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 2
    assert " init -backend=false -input=false -no-color" in calls[0]
    assert " plan -input=false -no-color -refresh=false -lock=false " in calls[1]
    assert " -detailed-exitcode " in calls[1]
    assert " apply" not in "\n".join(calls)
    for artifact in (
        plan_dir / "account-ready-gate.tfplan",
        plan_dir / "account-ready-gate-plan-summary.txt",
    ):
        assert artifact.is_file()
        assert artifact.stat().st_mode & 0o777 == 0o600


def test_observe_rejects_other_terraform_status_before_publication(
    tmp_path: Path,
) -> None:
    result, aws_marker, terraform_marker, plan_dir = _run_wrapper(
        tmp_path,
        action="observe",
        terraform_plan_rc=1,
    )

    assert result.returncode != 0
    assert "Terraform observation failed" in result.stderr
    assert not aws_marker.exists()
    assert " apply" not in terraform_marker.read_text(encoding="utf-8")
    assert not (plan_dir / "account-ready-gate.tfplan").exists()
    assert not (plan_dir / "account-ready-gate-plan-summary.txt").exists()


def test_plan_keeps_legacy_exit_and_flag_contract(tmp_path: Path) -> None:
    changed, aws_marker, terraform_marker, plan_dir = _run_wrapper(
        tmp_path,
        action="plan",
        terraform_plan_rc=2,
    )

    assert changed.returncode == 2
    assert not aws_marker.exists()
    calls = terraform_marker.read_text(encoding="utf-8").splitlines()
    assert " -detailed-exitcode" not in calls[-1]
    assert " plan -input=false -no-color -refresh=false -lock=false " in calls[-1]
    assert not (plan_dir / "account-ready-gate.tfplan").exists()
    assert not (plan_dir / "account-ready-gate-plan-summary.txt").exists()


def test_apply_remains_denied_before_argument_or_tool_processing() -> None:
    result = subprocess.run(
        ["bash", str(WRAPPER), "apply"],
        cwd=REPO_ROOT,
        env={"PATH": os.environ["PATH"]},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Local Terraform apply is disabled" in result.stderr


def test_observe_flags_cover_backendless_and_registry_backends() -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    observe = source[source.index('if [[ "$ACTION" == "observe" ]]') :]
    observe = observe[: observe.index('elif [[ "$BACKENDLESS_GATE" == true ]]')]

    assert observe.count("-detailed-exitcode") == 2
    assert observe.count("-lock=false") == 2
    assert " apply " not in observe
