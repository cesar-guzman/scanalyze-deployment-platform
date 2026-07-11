"""Local mock-backed apply paths must remain fail-closed."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


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
