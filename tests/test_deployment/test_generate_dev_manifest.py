"""Safety tests for the local real-manifest generator."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "deployment" / "generate-dev-manifest.sh"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
GITHUB_ENVIRONMENT = f"scanalyze-{DEPLOYMENT_ID}-dev"


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


def _generator_args(output: Path) -> list[str]:
    return [
        "bash",
        str(SCRIPT),
        "synthetic-dev",
        "--deployment-id",
        DEPLOYMENT_ID,
        "--github-environment",
        GITHUB_ENVIRONMENT,
        "--output",
        str(output),
    ]


def test_generator_requires_explicit_output() -> None:
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "synthetic-dev",
            "--deployment-id",
            DEPLOYMENT_ID,
            "--github-environment",
            GITHUB_ENVIRONMENT,
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--output is required" in result.stderr


def test_generator_rejects_output_inside_repository(tmp_path: Path) -> None:
    forbidden = REPO_ROOT / "examples" / "deployments" / "blocked.generated.yaml"
    args = _generator_args(forbidden)
    result = subprocess.run(
        args,
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
        _generator_args(output),
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
    manifest = yaml.safe_load(content)
    assert manifest["deployment_id"] == DEPLOYMENT_ID
    assert manifest["github"]["environment"] == GITHUB_ENVIRONMENT
    assert "github_environment" not in manifest


def test_generator_requires_registry_assigned_deployment_id(tmp_path: Path) -> None:
    output = tmp_path / "manifest.yaml"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "synthetic-dev",
            "--github-environment",
            GITHUB_ENVIRONMENT,
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        env=_safe_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--deployment-id is required" in result.stderr
    assert not output.exists()


def test_generator_requires_separate_github_environment_binding(
    tmp_path: Path,
) -> None:
    output = tmp_path / "manifest.yaml"
    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "synthetic-dev",
            "--deployment-id",
            DEPLOYMENT_ID,
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        env=_safe_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--github-environment is required" in result.stderr
    assert not output.exists()


def test_generator_rejects_invalid_registry_deployment_id(tmp_path: Path) -> None:
    output = tmp_path / "manifest.yaml"
    args = _generator_args(output)
    args[args.index(DEPLOYMENT_ID)] = "dep_random-local-id"

    result = subprocess.run(
        args,
        cwd=REPO_ROOT,
        env=_safe_env(tmp_path),
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "approved registry" in result.stderr
    assert not output.exists()


def test_generator_is_deterministic_for_registry_identity(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    env = _safe_env(tmp_path)

    first_result = subprocess.run(
        _generator_args(first),
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    second_result = subprocess.run(
        _generator_args(second),
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert first_result.returncode == 0, first_result.stderr
    assert second_result.returncode == 0, second_result.stderr
    assert first.read_bytes() == second.read_bytes()
