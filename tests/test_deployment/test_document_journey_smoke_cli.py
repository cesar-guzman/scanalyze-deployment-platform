"""Private CLI/source/journal tests; all coordinates and tokens are synthetic."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/validation/document-journey-smoke.py"
FAKE_TOKEN = "synthetic-test-only-not-a-credential"
STUB = '''
class SmokeError(ValueError):
    def __init__(self, code): self.code = code
class SmokeConfig:
    @classmethod
    def from_dict(cls, value): return value
class HttpsTransport:
    pass
def run_smoke(config, access_token, transport, *, on_progress, on_recovery):
    assert access_token == "synthetic-test-only-not-a-credential"
    steps = ["CREATE", "UPLOAD", "SUBMIT", "STATUS", "RESULT", "REPLAY"]
    on_recovery({"event": "CREATE_PREPARED", "idempotency_key": "12345678-1234-4123-8123-123456789012", "request_sha256": "sha256:" + "a" * 64})
    on_recovery({"event": "DOCUMENT_CREATED", "document_id": "a" * 32})
    for number, stage in enumerate(steps, 1):
        on_progress({"stage": stage, "requests": number, "status": "BEFORE_REQUEST"})
        on_progress({"stage": stage, "requests": number, "status": "STEP_PASSED"})
    return {"schema_version": 1, "status": "APPLICATION_SMOKE_PASSED",
            "scope": "single_synthetic_bank_document", "production_authorized": False,
            "requests": 6, "completed_steps": steps, "document_id_sha256": "sha256:" + "a" * 64,
            "pdf_sha256": "sha256:" + "b" * 64, "elapsed_milliseconds": 1}
'''


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("CLI tests must never use a real network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def cli_module():
    spec = importlib.util.spec_from_file_location("document_smoke_cli_tests", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _environment(with_token=True):
    result = {"PATH": os.defpath, "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
              "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    if with_token:
        result["SCANALYZE_SMOKE_ACCESS_TOKEN"] = FAKE_TOKEN
    return result


def _git(repo, *arguments):
    return subprocess.run(
        ["git", "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid",
         "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={os.devnull}",
         "-C", str(repo), *arguments],
        capture_output=True, text=True, env=_environment(False), check=True,
    ).stdout.strip()


@pytest.fixture
def source(tmp_path):
    # A disposable synthetic Git repository, never the user's repository/history.
    repo = (tmp_path / "source").resolve()
    repo.mkdir(mode=0o700)
    script = repo / "scripts/validation/document-journey-smoke.py"
    script.parent.mkdir(parents=True)
    script.write_bytes(CLI.read_bytes())
    tooling = repo / "tooling"
    tooling.mkdir()
    (tooling / "__init__.py").write_text("")
    (tooling / "document_journey_smoke.py").write_text(STUB)
    _git(repo, "init", "-b", "main")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "test: synthetic smoke source")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo, script


@pytest.fixture
def private_paths(tmp_path):
    directory = (tmp_path / "private").resolve()
    directory.mkdir(mode=0o700)
    config = directory / "config.json"
    config.write_text(json.dumps({
        "schema_version": 1, "environment": "dev", "processing_domain": "bank",
        "api_origin": "https://synthetic.example.invalid",
        "upload_host": "synthetic-test.s3.us-east-1.amazonaws.com",
        "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", "region": "us-east-1",
        "authorization_reference": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "timeout_seconds": 60, "poll_interval_seconds": 1, "max_requests": 16,
    }))
    config.chmod(0o600)
    return config, directory / "receipt.jsonl"


def _run(script, config, receipt, *, authorize=True, with_token=True):
    arguments = [sys.executable, "-B", "-I", str(script), "run", "--config", str(config),
                 "--receipt", str(receipt)]
    if authorize:
        arguments.append("--authorize-application-writes")
    return subprocess.run(arguments, capture_output=True, text=True, check=False,
                          env=_environment(with_token), timeout=20)


def _assert_failure(result, code):
    assert result.returncode == 2
    assert result.stderr.strip() == code
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert FAKE_TOKEN not in result.stdout + result.stderr


def test_real_help_needs_no_parent_module_or_token():
    result = subprocess.run([sys.executable, "-B", "-I", str(CLI), "--help"],
                            capture_output=True, text=True, env=_environment(False), check=False)
    assert result.returncode == 0
    assert "run" in result.stdout
    assert result.stderr == ""


def test_authorization_required_before_source_or_private_input(private_paths):
    config, receipt = private_paths
    result = _run(CLI, config, receipt, authorize=False)
    _assert_failure(result, "APPLICATION_WRITE_AUTHORIZATION_REQUIRED")
    assert not receipt.exists()


def test_argument_error_does_not_echo_secret_or_path():
    result = subprocess.run([sys.executable, "-B", "-I", str(CLI), "run", "--token", FAKE_TOKEN],
                            capture_output=True, text=True, env=_environment(False), check=False)
    _assert_failure(result, "CLI_ARGUMENTS_INVALID")


@pytest.mark.parametrize("state,code", [
    ("branch", "SOURCE_NOT_MAIN"), ("dirty", "SOURCE_NOT_CLEAN"),
    ("untracked", "SOURCE_NOT_CLEAN"), ("upstream", "SOURCE_HEAD_MISMATCH"),
    ("missing_upstream", "SOURCE_VERIFICATION_FAILED"),
])
def test_real_source_gate(source, private_paths, state, code):
    repo, script = source
    config, receipt = private_paths
    if state == "branch":
        _git(repo, "switch", "-c", "codex/synthetic")
    elif state == "dirty":
        script.write_text(script.read_text() + "\n# Synthetic change\n")
    elif state == "untracked":
        (repo / "untracked.txt").write_text("synthetic")
    elif state == "missing_upstream":
        _git(repo, "update-ref", "-d", "refs/remotes/origin/main")
    else:
        _git(repo, "commit", "--allow-empty", "-m", "test: ahead of pinned baseline")
    _assert_failure(_run(script, config, receipt), code)
    assert not receipt.exists()


def test_success_journals_start_progress_and_summary_without_coordinates(source, private_paths):
    repo, script = source
    config, receipt = private_paths
    result = _run(script, config, receipt)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "APPLICATION_SMOKE_PASSED"
    assert summary["production_authorized"] is False
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    events = [json.loads(line) for line in receipt.read_text().splitlines()]
    assert events[0]["event"] == "STARTED"
    assert events[1]["event"] == "CREATE_PREPARED"
    assert events[2]["event"] == "DOCUMENT_CREATED"
    assert events[0]["source_commit"] == _git(repo, "rev-parse", "HEAD")
    assert set(events[0]) == {"event", "source_commit", "config_sha256"}
    assert len(events) == 16
    assert events[-1] == {"event": "SUMMARY", **summary}
    public = receipt.read_text() + result.stdout + result.stderr
    for excluded in (FAKE_TOKEN, "synthetic.example.invalid", "s3.us-east-1.amazonaws.com",
                     "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", str(config), "aaaaaaaa-aaaa-"):
        assert excluded not in public


def test_existing_receipt_is_never_overwritten_or_rerun(source, private_paths):
    _, script = source
    config, receipt = private_paths
    receipt.write_text("prior evidence\n")
    receipt.chmod(0o600)
    _assert_failure(_run(script, config, receipt), "RECEIPT_ALREADY_EXISTS")
    assert receipt.read_text() == "prior evidence\n"


def test_missing_token_leaves_durable_failure_not_success(source, private_paths):
    _, script = source
    config, receipt = private_paths
    _assert_failure(_run(script, config, receipt, with_token=False), "ACCESS_TOKEN_REQUIRED")
    events = [json.loads(line) for line in receipt.read_text().splitlines()]
    assert [event["event"] for event in events] == ["STARTED", "FAILED"]
    assert events[-1]["code"] == "ACCESS_TOKEN_REQUIRED"


def test_core_rejects_missing_recovery_callback(private_paths):
    from tooling import document_journey_smoke as real_core
    config_path, _ = private_paths
    config_data = {
        "schema_version": 1, "environment": "dev", "processing_domain": "bank",
        "api_origin": "https://synthetic.example.invalid",
        "upload_host": "synthetic-test.s3.us-east-1.amazonaws.com",
        "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", "region": "us-east-1",
        "authorization_reference": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "timeout_seconds": 60, "poll_interval_seconds": 1, "max_requests": 16,
    }
    config = real_core.SmokeConfig.from_dict(config_data)
    with pytest.raises(real_core.SmokeError) as exc:
        real_core.run_smoke(config, FAKE_TOKEN, real_core.HttpsTransport())
    assert exc.value.code == "RECOVERY_JOURNAL_REQUIRED"

def test_cli_integrates_real_core_recovery(
    cli_module, private_paths, monkeypatch, capsys,
):
    from tooling import document_journey_smoke as real_core

    config, receipt = private_paths
    monkeypatch.setattr(cli_module, "_verify_source", lambda: "c" * 40)
    monkeypatch.setenv("SCANALYZE_SMOKE_ACCESS_TOKEN", FAKE_TOKEN)

    def trigger_transport_failure(*_args, **_kwargs):
        raise real_core.SmokeError("SYNTHETIC_TRANSPORT_FAILURE")

    monkeypatch.setattr(real_core.HttpsTransport, "request", trigger_transport_failure)
    
    result = cli_module.main([
        "run", "--config", str(config), "--receipt", str(receipt),
        "--authorize-application-writes",
    ])
    
    assert result == 2
    events = [json.loads(line) for line in receipt.read_text().splitlines()]
    event_names = [event.get("event", event.get("stage", "UNKNOWN")) for event in events]
    assert "CREATE_PREPARED" in event_names
    assert events[-1]["code"] == "SYNTHETIC_TRANSPORT_FAILURE"
    
def test_recovery_invalid_event_aborts(cli_module, private_paths):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_EVENT_INVALID"):
            journal.recovery({"event": "CREATE_PREPARED", "idempotency_key": "invalid", "request_sha256": "sha256:" + "a" * 64})
    finally:
        journal.close()

def test_recovery_fsync_failure_aborts(cli_module, private_paths, monkeypatch):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    
    def failed(_descriptor):
        raise OSError("synthetic failure with private data")
    monkeypatch.setattr(cli_module.os, "fsync", failed)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_WRITE_FAILED"):
            journal.recovery({"event": "CREATE_PREPARED", "idempotency_key": "12345678-1234-4123-8123-123456789012", "request_sha256": "sha256:" + "a" * 64})
    finally:
        journal.close()


@pytest.mark.parametrize("text,code", [
    ('{"schema_version":1,"schema_version":1}', "CONFIG_DUPLICATE_KEY"),
    ('{"nested":{"x":1,"x":2}}', "CONFIG_DUPLICATE_KEY"),
    ('{"value":NaN}', "CONFIG_NONFINITE_NUMBER"),
    ('{"value":Infinity}', "CONFIG_NONFINITE_NUMBER"),
    ("[]", "CONFIG_OBJECT_REQUIRED"), ("{", "CONFIG_JSON_INVALID"),
    ("x" * 16_385, "CONFIG_SIZE_INVALID"),
])
def test_strict_private_json(source, private_paths, text, code):
    _, script = source
    config, receipt = private_paths
    config.write_text(text)
    _assert_failure(_run(script, config, receipt), code)
    assert not receipt.exists()


@pytest.mark.parametrize("mode,target,code", [
    (0o644, "config", "CONFIG_FILE_PERMISSIONS_INVALID"),
    (0o750, "directory", "PRIVATE_DIRECTORY_PERMISSIONS_INVALID"),
])
def test_private_permissions(source, private_paths, mode, target, code):
    _, script = source
    config, receipt = private_paths
    (config if target == "config" else config.parent).chmod(mode)
    _assert_failure(_run(script, config, receipt), code)
    assert not receipt.exists()


def test_hardlinked_config_rejected(source, private_paths):
    _, script = source
    config, receipt = private_paths
    os.link(config, config.parent / "copy.json")
    _assert_failure(_run(script, config, receipt), "CONFIG_FILE_PERMISSIONS_INVALID")


def test_config_symlink_rejected(source, private_paths):
    _, script = source
    config, receipt = private_paths
    link = config.parent / "link.json"
    link.symlink_to(config)
    _assert_failure(_run(script, link, receipt), "PRIVATE_IO_FAILED")


def test_fifo_config_is_rejected_without_blocking(source, private_paths):
    _, script = source
    config, receipt = private_paths
    fifo = config.parent / "fifo.json"
    os.mkfifo(fifo, 0o600)
    _assert_failure(_run(script, fifo, receipt), "CONFIG_FILE_PERMISSIONS_INVALID")


def test_parent_symlink_rejected(source, private_paths):
    _, script = source
    config, receipt = private_paths
    link = config.parent.parent / "private-link"
    link.symlink_to(config.parent, target_is_directory=True)
    _assert_failure(_run(script, link / config.name, receipt), "PRIVATE_IO_FAILED")


def test_receipt_symlink_cannot_replace_target(source, private_paths):
    _, script = source
    config, receipt = private_paths
    receipt.symlink_to(config)
    before = config.read_bytes()
    _assert_failure(_run(script, config, receipt), "RECEIPT_ALREADY_EXISTS")
    assert config.read_bytes() == before


@pytest.mark.parametrize("name", ["CloudStorage", "OneDrive-Test", "FileProvider", "Mobile Documents"])
def test_synced_custody_rejected_before_creation(source, private_paths, name):
    _, script = source
    config, receipt = private_paths
    target = config.parent / name
    target.mkdir(mode=0o700)
    _assert_failure(_run(script, config, target / receipt.name), "SYNCED_STORAGE_FORBIDDEN")
    assert not (target / receipt.name).exists()


def test_git_custody_rejected(cli_module, source):
    repo, _ = source
    with pytest.raises(cli_module.CliError, match="PRIVATE_PATH_INSIDE_GIT"):
        cli_module._private_parent(repo / "receipt.jsonl")


def test_git_subprocess_never_inherits_token(cli_module, monkeypatch):
    monkeypatch.setenv(cli_module.TOKEN_ENV, FAKE_TOKEN)
    seen = {}
    def fake_run(arguments, **kwargs):
        seen.update(kwargs["env"])
        return subprocess.CompletedProcess(arguments, 0, "synthetic", "")
    monkeypatch.setattr(cli_module.subprocess, "run", fake_run)
    assert cli_module._git(ROOT, "rev-parse", "HEAD") == "synthetic"
    assert cli_module.TOKEN_ENV not in seen
    assert FAKE_TOKEN not in seen.values()


def test_progress_is_fsynced_and_failure_interrupts_callback(cli_module, private_paths, monkeypatch):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    original = cli_module.os.fsync
    calls = []
    def tracked(descriptor):
        calls.append(descriptor)
        return original(descriptor)
    monkeypatch.setattr(cli_module.os, "fsync", tracked)
    event = {"stage": "CREATE", "requests": 1, "status": "BEFORE_REQUEST"}
    journal.progress(event)
    assert calls == [journal.descriptor]
    def failed(_descriptor):
        raise OSError("synthetic failure with private data")
    monkeypatch.setattr(cli_module.os, "fsync", failed)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_WRITE_FAILED"):
            journal.progress(event)
    finally:
        journal.close()


def test_callback_rejects_unsanitized_extra_fields(cli_module, private_paths):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_EVENT_INVALID"):
            journal.progress({"stage": "CREATE", "requests": 1, "status": "BEFORE_REQUEST",
                              "url": "https://synthetic.example.invalid"})
        assert receipt.read_bytes() == b""
    finally:
        journal.close()


def test_journal_custody_change_aborts(cli_module, private_paths):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    receipt.chmod(0o644)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_CUSTODY_CHANGED"):
            journal.append({"event": "FAILED", "code": "SYNTHETIC_FAILURE"})
    finally:
        journal.close()


def test_partial_write_failure_cannot_append_a_misleading_final_record(
    cli_module, private_paths, monkeypatch,
):
    _, receipt = private_paths
    journal = cli_module.Journal(receipt)
    original = cli_module.os.write
    calls = []
    def partial_then_failed(descriptor, data):
        calls.append(descriptor)
        if len(calls) == 1:
            return original(descriptor, data[:5])
        raise OSError("synthetic disk failure")
    monkeypatch.setattr(cli_module.os, "write", partial_then_failed)
    try:
        with pytest.raises(cli_module.CliError, match="JOURNAL_WRITE_FAILED"):
            journal.progress({"stage": "CREATE", "requests": 1, "status": "BEFORE_REQUEST"})
        assert journal.broken is True
        with pytest.raises(cli_module.CliError, match="JOURNAL_WRITE_FAILED"):
            journal.append({"event": "FAILED", "code": "SYNTHETIC_FAILURE"})
        assert len(calls) == 2
        assert receipt.stat().st_size == 5
    finally:
        journal.close()


@pytest.mark.parametrize("exception,code", [
    ('SmokeError("SYNTHETIC_RUN_FAILED")', "SYNTHETIC_RUN_FAILED"),
    ('RuntimeError("synthetic-test-only-not-a-credential")', "SMOKE_FAILED"),
    ('SmokeError("https://synthetic.example.invalid/private")', "SMOKE_FAILED"),
])
def test_run_failure_records_only_safe_code(source, private_paths, exception, code):
    repo, script = source
    config, receipt = private_paths
    module = repo / "tooling/document_journey_smoke.py"
    module.write_text(STUB + f"\ndef run_smoke(*args, **kwargs):\n    raise {exception}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "test: synthetic failure outcome")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _assert_failure(_run(script, config, receipt), code)
    events = [json.loads(line) for line in receipt.read_text().splitlines()]
    assert [event["event"] for event in events] == ["STARTED", "FAILED"]
    assert events[-1] == {"event": "FAILED", "code": code}
    assert FAKE_TOKEN not in receipt.read_text()
    assert "https://" not in receipt.read_text()
