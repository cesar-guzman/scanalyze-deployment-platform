"""Safety tests for the local real-manifest generator."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "deployment" / "generate-dev-manifest.sh"


def _fake_aws(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text("#!/usr/bin/env bash\nprintf '%s\\n' '123456789012'\n")
    aws.chmod(0o700)
    return bin_dir


def _safe_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "AWS_PROFILE": "approved-nonprod",
            "AWS_REGION": "us-east-1",
            "PATH": f"{_fake_aws(tmp_path)}:{env['PATH']}",
        }
    )
    return env


def test_generator_requires_explicit_output() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "synthetic-dev"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--output is required" in result.stderr


def test_generator_rejects_output_inside_repository(tmp_path: Path) -> None:
    forbidden = REPO_ROOT / "examples" / "deployments" / "blocked.generated.yaml"
    result = subprocess.run(
        ["bash", str(SCRIPT), "synthetic-dev", "--output", str(forbidden)],
        cwd=REPO_ROOT,
        env=_safe_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "outside the repository" in result.stderr
    assert not forbidden.exists()


def test_generator_writes_private_file_outside_repository(tmp_path: Path) -> None:
    output = tmp_path / "manifest.yaml"
    result = subprocess.run(
        ["bash", str(SCRIPT), "synthetic-dev", "--output", str(output)],
        cwd=REPO_ROOT,
        env=_safe_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert output.exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "123456789012" not in result.stdout

    content = output.read_text()
    assert 'customer_id: "synthetic-dev"' in content
    assert 'aws_account_id: "123456789012"' in content
