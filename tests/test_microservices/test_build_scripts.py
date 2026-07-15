from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "microservices" / "build-push.sh"
CHANGED_SCRIPT = REPO_ROOT / "scripts" / "microservices" / "changed-services.sh"
MAKEFILE = REPO_ROOT / "Makefile"


def run_script(script: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    command_env = os.environ.copy()
    if env:
        command_env.update(env)
    return subprocess.run(
        [str(script), *args],
        cwd=REPO_ROOT,
        env=command_env,
        text=True,
        capture_output=True,
        check=False,
    )


def make_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run_git_safety(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "--no-print-directory", "-f", str(MAKEFILE), "git-safety"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )


def init_safety_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "app.py"
    source.write_text("print('safe baseline')\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "ci@example.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "CI Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=repo, check=True)
    return repo, source


def synthetic_secret_marker() -> str:
    return "AWS_" + "ACCESS_KEY_ID=" + ("X" * 16)


def fake_tool_env(tmp_path: Path, aws_account: str | None = None) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker_log = tmp_path / "docker.log"
    make_executable(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n",
    )
    if aws_account is not None:
        make_executable(
            bin_dir / "aws",
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"${1:-}\" == \"sts\" ]]; then\n"
            f"  printf '%s\\n' '{aws_account}'\n"
            "  exit 0\n"
            "fi\n"
            "exit 99\n",
        )
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_LOG": str(docker_log),
    }
    return env, docker_log


def reconcile_tool_env(
    tmp_path: Path,
    digest: str,
    mutability: str = "IMMUTABLE",
    git_status: str = "",
) -> tuple[dict[str, str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws_log = tmp_path / "aws.log"
    real_git = shutil.which("git")
    assert real_git is not None

    make_executable(
        bin_dir / "git",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "for arg in \"$@\"; do\n"
        "  if [[ \"$arg\" == \"status\" ]]; then printf '%s' \"$GIT_STATUS\"; exit 0; fi\n"
        "done\n"
        "exec \"$REAL_GIT\" \"$@\"\n",
    )
    make_executable(
        bin_dir / "aws",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$*\" >> \"$AWS_LOG\"\n"
        "case \"${1:-}:${2:-}\" in\n"
        "  sts:get-caller-identity) printf '%s\\n' '123456789012' ;;\n"
        f"  ecr:describe-repositories) printf '%s\\n' '{mutability}' ;;\n"
        "  ecr:batch-get-image) printf '%s\\n' '1' ;;\n"
        f"  ecr:describe-images) printf '%s\\n' '{digest}' ;;\n"
        "  ssm:put-parameter) : ;;\n"
        "  *) exit 99 ;;\n"
        "esac\n",
    )
    return {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "AWS_LOG": str(aws_log),
        "GIT_STATUS": git_status,
        "REAL_GIT": real_git,
    }, aws_log


def publish_tool_env(tmp_path: Path, digest: str) -> tuple[dict[str, str], Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws_log = tmp_path / "aws.log"
    docker_log = tmp_path / "docker.log"
    real_git = shutil.which("git")
    assert real_git is not None

    make_executable(
        bin_dir / "git",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "for arg in \"$@\"; do\n"
        "  if [[ \"$arg\" == \"status\" ]]; then exit 0; fi\n"
        "done\n"
        "exec \"$REAL_GIT\" \"$@\"\n",
    )
    make_executable(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n",
    )
    make_executable(
        bin_dir / "aws",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' \"$*\" >> \"$AWS_LOG\"\n"
        "case \"${1:-}:${2:-}\" in\n"
        "  sts:get-caller-identity) printf '%s\\n' '123456789012' ;;\n"
        "  ecr:describe-repositories) printf '%s\\n' 'IMMUTABLE' ;;\n"
        "  ecr:batch-get-image) printf '%s\\n' '0' ;;\n"
        "  ecr:get-login-password) printf '%s\\n' 'token' ;;\n"
        f"  ecr:describe-images) printf '%s\\n' '{digest}' ;;\n"
        "  *) exit 99 ;;\n"
        "esac\n",
    )
    return {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "AWS_LOG": str(aws_log),
        "DOCKER_LOG": str(docker_log),
        "REAL_GIT": real_git,
    }, aws_log, docker_log


def test_no_push_builds_one_service_without_aws(tmp_path: Path) -> None:
    env, docker_log = fake_tool_env(tmp_path)
    base_image = f"python@sha256:{'a' * 64}"
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ingest-api",
        "--tag",
        "sha-test123",
        "--base-image",
        base_image,
        "--no-push",
        "--no-write-ssm",
        env=env,
    )

    assert result.returncode == 0, result.stderr
    invocation = docker_log.read_text(encoding="utf-8")
    assert "build --platform linux/amd64" in invocation
    assert f"BASE_IMAGE={base_image}" in invocation
    assert "scanalyze-ci/ingest-api:sha-test123" in invocation


def test_all_mode_builds_exact_service_allowlist(tmp_path: Path) -> None:
    env, docker_log = fake_tool_env(tmp_path)
    result = run_script(
        BUILD_SCRIPT,
        "--all",
        "--tag",
        "validation",
        "--base-image",
        f"python@sha256:{'a' * 64}",
        "--no-push",
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert len(docker_log.read_text(encoding="utf-8").splitlines()) == 7


def test_no_push_rejects_mutable_base_image() -> None:
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ingest-api",
        "--tag",
        "sha-test123",
        "--base-image",
        "python:3.11-slim",
        "--no-push",
    )

    assert result.returncode == 2
    assert "immutable @sha256" in result.stderr


def test_rejects_invalid_or_unsafe_argument_combinations() -> None:
    cases = [
        ("--service", "unknown", "--tag", "safe", "--base-image", "python:3.11-slim"),
        ("--all", "--tag", "latest", "--base-image", "python:3.11-slim"),
        (
            "--all",
            "--tag",
            "safe",
            "--base-image",
            "python:3.11-slim",
            "--write-ssm",
            "--no-push",
        ),
        (
            "--service",
            "ingest-api",
            "--all",
            "--tag",
            "safe",
            "--base-image",
            "python:3.11-slim",
        ),
        (
            "--service",
            "ingest-api",
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
            "--deployment-id",
            "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "--ecr-prefix",
            "dep-01bbbbbbbbbbbbbbbbbbbbbbbbbb/scanalyze",
            "--tag",
            "safe",
            "--base-image",
            f"123456789012.dkr.ecr.us-east-1.amazonaws.com/base-images/python@sha256:{'a' * 64}",
            "--push",
            "--no-write-ssm",
        ),
    ]

    for args in cases:
        result = run_script(BUILD_SCRIPT, *args)
        assert result.returncode == 2
        assert "ERROR:" in result.stderr


def test_push_fails_before_docker_when_caller_account_differs(tmp_path: Path) -> None:
    env, docker_log = fake_tool_env(tmp_path, aws_account="999999999999")
    digest = "a" * 64
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ocr-worker",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--base-image",
        f"123456789012.dkr.ecr.us-east-1.amazonaws.com/base-images/python@sha256:{digest}",
        "--push",
        "--no-write-ssm",
        env=env,
    )

    assert result.returncode == 2
    assert "caller account" in result.stderr
    assert not docker_log.exists()


def test_changed_service_selector_outputs_canonical_json() -> None:
    all_result = run_script(CHANGED_SCRIPT, "--all")
    one_result = run_script(CHANGED_SCRIPT, "--service", "scanalyze-gov-worker")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    no_change_result = run_script(CHANGED_SCRIPT, "--service-diff", head, head)

    assert all_result.returncode == 0
    assert len(json.loads(all_result.stdout)) == 7
    assert one_result.returncode == 0
    assert json.loads(one_result.stdout) == ["gov-worker"]
    assert no_change_result.returncode == 0
    assert json.loads(no_change_result.stdout) == []


def test_service_diff_separates_publish_matrix_from_global_validation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    script = repo / "scripts" / "microservices" / "changed-services.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(CHANGED_SCRIPT, script)
    (repo / "backend" / "workers" / "scanalyze-ingest-api").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    service_file = repo / "backend" / "workers" / "scanalyze-ingest-api" / "app.py"
    workflow_file = repo / ".github" / "workflows" / "microservices-build.yml"
    service_file.write_text("baseline\n", encoding="utf-8")
    workflow_file.write_text("name: baseline\n", encoding="utf-8")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "ci@example.invalid")
    git("config", "user.name", "CI Test")
    git("add", ".")
    git("commit", "-qm", "baseline")
    base = git("rev-parse", "HEAD")
    service_file.write_text("changed\n", encoding="utf-8")
    workflow_file.write_text("name: changed\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "mixed change")
    head = git("rev-parse", "HEAD")

    validate = subprocess.run(
        [str(script), "--diff", base, head],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    publish = subprocess.run(
        [str(script), "--service-diff", base, head],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )

    assert len(json.loads(validate.stdout)) == 7
    assert json.loads(publish.stdout) == ["ingest-api"]


def test_service_diff_selects_both_sides_of_cross_service_rename(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    script = repo / "scripts" / "microservices" / "changed-services.sh"
    script.parent.mkdir(parents=True)
    shutil.copy2(CHANGED_SCRIPT, script)
    ingest_dir = repo / "backend" / "workers" / "scanalyze-ingest-api"
    ocr_dir = repo / "backend" / "workers" / "scanalyze-ocr-worker"
    ingest_dir.mkdir(parents=True)
    ocr_dir.mkdir(parents=True)
    source_file = ingest_dir / "shared.py"
    source_file.write_text("baseline\n", encoding="utf-8")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "ci@example.invalid")
    git("config", "user.name", "CI Test")
    git("add", ".")
    git("commit", "-qm", "baseline")
    base = git("rev-parse", "HEAD")
    git("mv", str(source_file.relative_to(repo)), str((ocr_dir / "shared.py").relative_to(repo)))
    git("commit", "-qm", "move between services")
    head = git("rev-parse", "HEAD")

    result = subprocess.run(
        [str(script), "--service-diff", base, head],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )

    assert json.loads(result.stdout) == ["ingest-api", "ocr-worker"]


def test_reconcile_existing_verifies_digest_and_writes_only_metadata(tmp_path: Path) -> None:
    digest = f"sha256:{'b' * 64}"
    env, aws_log = reconcile_tool_env(tmp_path, digest)
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ocr-worker",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--push",
        "--write-ssm",
        "--reconcile-existing",
        digest,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    calls = aws_log.read_text(encoding="utf-8")
    assert calls.count("ssm put-parameter") == 2
    assert "ecr get-login-password" not in calls
    assert "no image was built or pushed" in result.stdout


def test_reconcile_existing_rejects_mutable_repository(tmp_path: Path) -> None:
    digest = f"sha256:{'c' * 64}"
    env, aws_log = reconcile_tool_env(tmp_path, digest, mutability="MUTABLE")
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ocr-worker",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--push",
        "--write-ssm",
        "--reconcile-existing",
        digest,
        env=env,
    )

    assert result.returncode == 2
    assert "immutable tags" in result.stderr
    assert "ssm put-parameter" not in aws_log.read_text(encoding="utf-8")


def test_reconcile_existing_rejects_digest_mismatch_without_writes(tmp_path: Path) -> None:
    existing_digest = f"sha256:{'c' * 64}"
    requested_digest = f"sha256:{'d' * 64}"
    env, aws_log = reconcile_tool_env(tmp_path, existing_digest)
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ocr-worker",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--push",
        "--write-ssm",
        "--reconcile-existing",
        requested_digest,
        env=env,
    )

    assert result.returncode == 2
    assert "does not match" in result.stderr
    assert "ssm put-parameter" not in aws_log.read_text(encoding="utf-8")


def test_reconcile_existing_rejects_dirty_worktree_without_writes(tmp_path: Path) -> None:
    digest = f"sha256:{'f' * 64}"
    env, aws_log = reconcile_tool_env(tmp_path, digest, git_status=" M unsafe.py\n")
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ocr-worker",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--push",
        "--write-ssm",
        "--reconcile-existing",
        digest,
        env=env,
    )

    assert result.returncode == 2
    assert "clean Git worktree" in result.stderr
    assert "ssm put-parameter" not in aws_log.read_text(encoding="utf-8")


def test_push_happy_path_builds_and_verifies_digest_without_ssm(tmp_path: Path) -> None:
    digest = f"sha256:{'d' * 64}"
    env, aws_log, docker_log = publish_tool_env(tmp_path, digest)
    base_digest = "e" * 64
    result = run_script(
        BUILD_SCRIPT,
        "--service",
        "ingest-api",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--ecr-prefix",
        "dep-01arz3ndektsv4rrffq69g5fav/scanalyze",
        "--tag",
        "sha-test",
        "--base-image",
        f"123456789012.dkr.ecr.us-east-1.amazonaws.com/base-images/python@sha256:{base_digest}",
        "--push",
        "--no-write-ssm",
        env=env,
    )

    assert result.returncode == 0, result.stderr
    docker_calls = docker_log.read_text(encoding="utf-8")
    assert "login --username AWS --password-stdin" in docker_calls
    assert "build --platform linux/amd64" in docker_calls
    assert "push 123456789012.dkr.ecr.us-east-1.amazonaws.com/" in docker_calls
    assert "ssm put-parameter" not in aws_log.read_text(encoding="utf-8")
    assert digest in result.stdout


def test_git_safety_reads_staged_bytes_from_index(tmp_path: Path) -> None:
    repo, source = init_safety_repo(tmp_path)
    source.write_text(synthetic_secret_marker() + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
    source.write_text("print('safe worktree')\n", encoding="utf-8")

    result = run_git_safety(repo)

    assert result.returncode != 0
    assert "tracked index content" in result.stdout


def test_git_safety_scans_tracked_and_untracked_code_nul_safely(tmp_path: Path) -> None:
    repo, source = init_safety_repo(tmp_path)
    source.write_text(synthetic_secret_marker() + "\n", encoding="utf-8")

    tracked_result = run_git_safety(repo)

    assert tracked_result.returncode != 0
    assert "tracked or untracked worktree content" in tracked_result.stdout

    source.write_text("print('safe worktree')\n", encoding="utf-8")
    unusual_path = repo / "untracked module\nname.py"
    unusual_path.write_text(synthetic_secret_marker() + "\n", encoding="utf-8")

    untracked_result = run_git_safety(repo)

    assert untracked_result.returncode != 0
    assert "tracked or untracked worktree content" in untracked_result.stdout


def test_git_safety_accepts_clean_code_with_unusual_filename(tmp_path: Path) -> None:
    repo, _ = init_safety_repo(tmp_path)
    unusual_path = repo / "untracked module\nname.py"
    unusual_path.write_text("print('safe untracked code')\n", encoding="utf-8")

    result = run_git_safety(repo)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Git safety OK." in result.stdout


def test_git_safety_fails_closed_when_git_inventory_is_unavailable(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    result = run_git_safety(not_a_repo)

    assert result.returncode != 0
    assert "unable to enumerate tracked index files" in result.stdout


def test_git_safety_rejects_prohibited_file_present_only_in_index(tmp_path: Path) -> None:
    repo, _ = init_safety_repo(tmp_path)
    prohibited = repo / ".env.audit"
    prohibited.write_text("SAFE_TEST_VALUE=1\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", ".env.audit"], cwd=repo, check=True)
    prohibited.unlink()

    result = run_git_safety(repo)

    assert result.returncode != 0
    assert "Prohibited file type detected in tracked index" in result.stdout


def test_git_safety_rejects_forced_artifact_in_ignored_directory(tmp_path: Path) -> None:
    repo, _ = init_safety_repo(tmp_path)
    artifact = repo / ".work" / "review.txt"
    artifact.parent.mkdir()
    artifact.write_text("safe test content\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "-f", ".work/review.txt"],
        cwd=repo,
        check=True,
    )

    result = run_git_safety(repo)

    assert result.returncode != 0
    assert "Prohibited file type detected in tracked index" in result.stdout
