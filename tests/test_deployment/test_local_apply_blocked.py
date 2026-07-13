"""Local mock-backed apply paths must remain fail-closed."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_ID = "111222333444"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    venv_bin = REPO_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}:{env['PATH']}"
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


def _run_layer_plan(
    tmp_path: Path,
    layer: str,
    *,
    overrides: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    plan_dir = tmp_path / "plans"
    plan_dir.mkdir()
    capture_path = tmp_path / "terraform-contract-environment.txt"

    _write_executable(
        fake_bin / "aws",
        f"""
        #!/usr/bin/env bash
        set -euo pipefail
        printf '%s\\n' '{ACCOUNT_ID}'
        """,
    )
    _write_executable(
        fake_bin / "terraform",
        """
        #!/usr/bin/env bash
        set -euo pipefail

        for argument in "$@"; do
          case "$argument" in
            init)
              exit 0
              ;;
            plan)
              {
                printf 'contract_id=%s\\n' "${TF_VAR_upstream_contract_id-<unset>}"
                printf 'schema_version=%s\\n' "${TF_VAR_upstream_schema_version-<unset>}"
              } > "$CAPTURE_PATH"
              exit 0
              ;;
          esac
        done

        exit 64
        """,
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["CAPTURE_PATH"] = str(capture_path)
    env.pop("TF_VAR_upstream_contract_id", None)
    env.pop("TF_VAR_upstream_schema_version", None)
    if overrides:
        env.update(overrides)

    result = subprocess.run(
        [
            "bash",
            str(REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh"),
            "plan",
            "--layer",
            layer,
            "--plan-dir",
            str(plan_dir),
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "us-east-1",
            "--deployment-id",
            DEPLOYMENT_ID,
        ],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    captured = {}
    if capture_path.is_file():
        captured = dict(
            line.split("=", maxsplit=1)
            for line in capture_path.read_text(encoding="utf-8").splitlines()
        )
    return result, captured


def test_apply_all_is_blocked_before_any_live_precondition() -> None:
    result = _run(
        REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh",
        "apply-all",
    )

    assert result.returncode == 2
    assert "Mock-backed plans are never authorized for apply" in result.stderr


def test_direct_layer_apply_is_blocked_before_aws_access() -> None:
    result = _run(
        REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh",
        "apply",
    )

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
        "services",
        "edge-identity",
        "edge",
        "addons",
    ]
    positions = [result.stdout.index(f"Planning layer: {layer}") for layer in expected]
    assert positions == sorted(positions)


@pytest.mark.parametrize("layer", ["cicd", "services"])
def test_local_plan_uses_v2_metadata_for_data_foundation_consumers(
    tmp_path: Path,
    layer: str,
) -> None:
    result, captured = _run_layer_plan(tmp_path, layer)

    assert result.returncode == 0, result.stderr
    assert captured == {
        "contract_id": "data-foundation/v2",
        "schema_version": "2",
    }


@pytest.mark.parametrize(
    "layer",
    [
        "account-ready-gate",
        "global",
        "network",
        "platform",
        "data-foundation",
        "edge-identity",
        "edge",
        "addons",
    ],
)
def test_local_plan_preserves_v1_metadata_for_legacy_layers(
    tmp_path: Path,
    layer: str,
) -> None:
    result, captured = _run_layer_plan(tmp_path, layer)

    assert result.returncode == 0, result.stderr
    assert captured == {
        "contract_id": "<unset>",
        "schema_version": "1",
    }


def test_local_plan_preserves_explicit_contract_metadata_overrides(
    tmp_path: Path,
) -> None:
    result, captured = _run_layer_plan(
        tmp_path,
        "services",
        overrides={
            "TF_VAR_upstream_contract_id": "caller-supplied/v9",
            "TF_VAR_upstream_schema_version": "9",
        },
    )

    assert result.returncode == 0, result.stderr
    assert captured == {
        "contract_id": "caller-supplied/v9",
        "schema_version": "9",
    }
