"""Regression tests for the local reproducibility contracts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLEAN_CLONE_SCRIPT = REPO_ROOT / "scripts" / "repro" / "verify-clean-clone.sh"
RELEASE_DRY_RUN_SCRIPT = (
    REPO_ROOT / "scripts" / "repro" / "run-release-dry-run.sh"
)


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _minimal_repro_remote(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Repro Test")
    _git(source, "config", "user.email", "repro@example.invalid")

    services = (
        "ingest-api",
        "ocr-worker",
        "postprocess-worker",
        "classifier-worker",
        "bank-worker",
        "personal-worker",
        "gov-worker",
    )
    for service in services:
        service_dir = source / "backend" / "workers" / f"scanalyze-{service}"
        service_dir.mkdir(parents=True)
        (service_dir / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    required_files = (
        "README.md",
        "REPRODUCIBILITY.md",
        ".gitignore",
        "pyproject.toml",
        "schemas/deployment-manifest.schema.json",
        "examples/deployments/synthetic-nonprod.yaml",
        "scripts/deployment/scanalyze-deploy.sh",
        "scripts/deployment/validate-manifest.py",
        "scripts/repro/verify-clean-clone.sh",
        "playbooks/enterprise-client-deployment.md",
    )
    for relative in required_files:
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("test fixture\n", encoding="utf-8")

    (source / "Makefile").write_text(
        "bootstrap-local:\n\t@true\n\nrepro-check:\n\t@true\n",
        encoding="utf-8",
    )
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "test fixture")
    commit = _git(source, "rev-parse", "HEAD")

    remote = tmp_path / "remote.git"
    _git(tmp_path, "clone", "--quiet", "--bare", str(source), str(remote))
    return remote, commit


def test_clean_clone_fails_when_local_head_is_absent_from_remote(
    tmp_path: Path,
) -> None:
    remote, _ = _minimal_repro_remote(tmp_path)

    result = _run(
        "bash",
        str(CLEAN_CLONE_SCRIPT),
        "--remote",
        str(remote),
        "--ref",
        "HEAD",
    )

    assert result.returncode == 1
    assert "requested commit is not available from the cloned remote" in result.stderr
    assert "PASSED: Clean clone verification complete" not in result.stdout


def test_clean_clone_checks_out_and_reports_the_exact_requested_sha(
    tmp_path: Path,
) -> None:
    remote, commit = _minimal_repro_remote(tmp_path)

    result = _run(
        "bash",
        str(CLEAN_CLONE_SCRIPT),
        "--remote",
        str(remote),
        "--ref",
        commit,
    )

    assert result.returncode == 0, result.stderr
    assert f"Commit:  {commit}" in result.stdout


def _fake_python(tmp_path: Path, version: str) -> Path:
    executable = tmp_path / f"python-{version}"
    executable.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' '{version}'\n")
    executable.chmod(0o700)
    return executable


def test_toolchain_check_fails_closed_on_python_version_mismatch(
    tmp_path: Path,
) -> None:
    fake_python = _fake_python(tmp_path, "0.0.0")

    result = _run(
        "make",
        "--no-print-directory",
        "toolchain-check",
        f"PYTHON={fake_python}",
    )

    assert result.returncode != 0
    assert "BLOCKED_TOOLING" in result.stdout


def test_bootstrap_fails_closed_when_dependency_installation_fails(
    tmp_path: Path,
) -> None:
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text(
        """#!/usr/bin/env bash
if [[ "$*" == *"-m pip install"* ]]; then
  exit 42
fi
printf '%s\\n' '3.11.14'
""",
        encoding="utf-8",
    )
    venv_python.chmod(0o700)

    fake_terraform = tmp_path / "terraform"
    fake_terraform.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' '{\"terraform_version\":\"1.14.6\"}'\n",
        encoding="utf-8",
    )
    fake_terraform.chmod(0o700)

    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-f",
            str(REPO_ROOT / "Makefile"),
            "bootstrap-local",
            f"TERRAFORM={fake_terraform}",
            "PINNED_PYTHON_VERSION=3.11.14",
            "PINNED_TF_VERSION=1.14.6",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "BLOCKED_TOOLING: dependency installation failed" in result.stdout


def test_release_dry_run_covers_all_layers_and_cleans_temp_dir(
    tmp_path: Path,
) -> None:
    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_path)

    result = _run("bash", str(RELEASE_DRY_RUN_SCRIPT), env=env)

    assert result.returncode == 0, result.stderr
    expected_layers = (
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
    )
    positions = [
        result.stdout.index(f"Planning layer: {layer}") for layer in expected_layers
    ]
    assert positions == sorted(positions)
    assert not list(tmp_path.glob("scanalyze-release-dry-run.*"))


def test_release_dry_run_accepts_setup_python_without_repository_venv(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "setup-python-bin"
    fake_bin.mkdir()
    setup_python = fake_bin / "python3"
    setup_python.write_text(
        f'#!/usr/bin/env bash\nexec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    setup_python.chmod(0o700)

    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_path)
    env["SCANALYZE_VENV_BIN"] = str(tmp_path / "missing-venv" / "bin")
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = _run("bash", str(RELEASE_DRY_RUN_SCRIPT), env=env)

    assert result.returncode == 0, result.stderr
    assert "All layers planned" in result.stdout
    assert not list(tmp_path.glob("scanalyze-release-dry-run.*"))


def test_make_release_dry_run_uses_the_tested_orchestrator_wrapper() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "bash scripts/repro/run-release-dry-run.sh" in makefile


def test_reproducibility_docs_do_not_overclaim_offline_provider_checks() -> None:
    guide = (REPO_ROOT / "REPRODUCIBILITY.md").read_text(encoding="utf-8")
    normalized = " ".join(guide.split())

    assert "runs entirely offline" not in guide
    assert "may require network access" in guide
    assert "`provider-check` is separate" in normalized


def test_rollback_runbook_is_explicitly_no_go_without_an_unproven_rto() -> None:
    runbook = (REPO_ROOT / "docs" / "operations" / "rollback.md").read_text(
        encoding="utf-8"
    )

    assert "no-go" in runbook.lower()
    assert "target-state" in runbook.lower()
    assert "The live rollback entrypoint is" not in runbook
    assert "< 15 minutes" not in runbook
