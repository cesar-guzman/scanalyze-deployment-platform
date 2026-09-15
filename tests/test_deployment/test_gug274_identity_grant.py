"""Offline PKCE regressions with real sockets/pipes and the existing CLI reader."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from tooling import platform_authority_bootstrap_identity_grant as grant


ROOT = Path(__file__).resolve().parents[2]
APP = "arn:aws:sso::042360977644:application/ssoins-1111111111111111/apl-2222222222222222"
INSTANCE = "arn:aws:sso:::instance/ssoins-1111111111111111"
CODE = "synthetic-one-use-code"


def binding_bytes(**changes: str) -> bytes:
    value = {"schema_version": "1", "record_type": "platform_authority_bootstrap_pkce_binding",
             "authority_account_id": "042360977644", "region": "us-east-1",
             "application_arn": APP, "instance_arn": INSTANCE, "redirect_uri": grant.REDIRECT_URI}
    value.update(changes)
    return json.dumps(value, sort_keys=True).encode()


def binding() -> grant.ApplicationBinding:
    raw = binding_bytes()
    return grant.ApplicationBinding.from_bytes(raw, hashlib.sha256(raw).hexdigest())


def request(state: str, **changes: str) -> bytes:
    values = {"code": CODE, "state": state}
    values.update(changes)
    return ("GET /callback?" + urlencode(values) + " HTTP/1.1\r\nHost: 127.0.0.1:38271\r\n\r\n").encode()


@pytest.fixture
def cli():
    spec = importlib.util.spec_from_file_location("gug274_cli_pkce_test", ROOT / "scripts/deployment/platform-authority-bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_binding_pin_is_independent_and_metadata_is_closed():
    raw = binding_bytes()
    pin = hashlib.sha256(raw).hexdigest()
    value = grant.ApplicationBinding.from_bytes(raw, pin)
    assert value.application_arn == APP and value.instance_arn == INSTANCE
    assert APP not in repr(value)
    with pytest.raises(grant.IdentityGrantError, match="PIN_MISMATCH"):
        grant.ApplicationBinding.from_bytes(binding_bytes(redirect_uri="http://127.0.0.1:49152/callback"), pin)


@pytest.mark.parametrize("changes", [
    {"authority_account_id": "111122223333"}, {"region": "eu-west-1"},
    {"redirect_uri": "http://localhost:38271/callback"},
    {"redirect_uri": "http://127.0.0.1:49152/callback"},
    {"redirect_uri": grant.REDIRECT_URI + "?code=fake"},
    {"application_arn": APP.replace("042360977644", "111122223333")},
    {"instance_arn": INSTANCE.replace("1111111111111111", "2222222222222222")},
    {"extra": "field"}, {"schema_version": "2"},
])
def test_repinning_invalid_topology_does_not_admit_it(changes):
    raw = binding_bytes(**changes)
    with pytest.raises(grant.IdentityGrantError):
        grant.ApplicationBinding.from_bytes(raw, hashlib.sha256(raw).hexdigest())


def test_binding_file_requires_private_regular_no_symlink(tmp_path):
    tmp_path = tmp_path.resolve()
    tmp_path.chmod(0o700)
    path = tmp_path / "binding.json"
    raw = binding_bytes()
    path.write_bytes(raw)
    path.chmod(0o600)
    pin = hashlib.sha256(raw).hexdigest()
    assert grant.read_binding(path, pin) == binding()
    path.chmod(0o644)
    with pytest.raises(grant.IdentityGrantError, match="PATH_INVALID"):
        grant.read_binding(path, pin)
    path.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(grant.IdentityGrantError, match="PATH_INVALID"):
        grant.read_binding(link, pin)


def test_pkce_exact_endpoint_and_canonical_s256_without_other_scopes():
    pending = grant.PendingGrant()
    assert len(pending.state) == 43 and len(pending.verifier) == 64
    url = urlsplit(pending.authorization_url(binding()))
    assert url.scheme == "https" and url.netloc == "oidc.us-east-1.amazonaws.com" and url.path == "/authorize"
    query = parse_qs(url.query)
    assert query == {
        "response_type": ["code"], "client_id": [APP], "redirect_uri": [grant.REDIRECT_URI],
        "state": [pending.state], "code_challenge_method": ["S256"], "scopes": ["sts:identity_context"],
        "code_challenge": [base64.urlsafe_b64encode(hashlib.sha256(pending.verifier.encode()).digest()).rstrip(b"=").decode()],
    }
    assert pending.verifier not in repr(pending) and "=" not in query["code_challenge"][0]


def test_request_is_one_shot_and_clears_memory_fields():
    pending = grant.PendingGrant()
    verifier = pending.verifier
    incoming = request(pending.state)
    output = json.loads(pending.consume_request(incoming))
    assert output == {"schema_version": "1", "record_type": "platform_authority_bootstrap_identity_grant",
                      "authorization_code": CODE, "code_verifier": verifier}
    assert pending.state == pending.verifier == ""
    with pytest.raises(grant.IdentityGrantError, match="ALREADY_CONSUMED"):
        pending.consume_request(incoming)
    with pytest.raises(grant.IdentityGrantError, match="ALREADY_CONSUMED"):
        pending.authorization_url(binding())


@pytest.mark.parametrize("mutate", [
    lambda raw: raw.replace(b"GET ", b"POST "),
    lambda raw: raw.replace(b"HTTP/1.1", b"HTTP/1.0"),
    lambda raw: raw.replace(b"Host: 127.0.0.1:38271", b"Host: evil.example"),
    lambda raw: raw.replace(b"Host: 127.0.0.1:38271", b"Host: localhost:38271"),
    lambda raw: raw.replace(b"/callback?", b"/callback/other?"),
    lambda raw: raw.replace(b"/callback?", b"http://127.0.0.1:38271/callback?"),
    lambda raw: raw.replace(b" HTTP", b"&extra=1 HTTP"),
    lambda raw: raw.replace(b" HTTP", b"&code=second-code HTTP"),
    lambda raw: raw.replace(b" HTTP", b"#fragment HTTP"),
    lambda raw: raw.replace(CODE.encode(), b"%zzbad-code"),
    lambda raw: raw.replace(CODE.encode(), b"%0abad-code"),
    lambda raw: raw.replace(CODE.encode(), b"short"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nHost: evil.example\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nContent-Length: 1\r\n\r\n"),
    lambda raw: raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
])
def test_bad_callbacks_fail_without_echo_and_burn_pending_grant(mutate):
    pending = grant.PendingGrant()
    with pytest.raises(grant.IdentityGrantError) as raised:
        pending.consume_request(mutate(request(pending.state)))
    assert CODE not in str(raised.value)
    assert pending.state == pending.verifier == ""


def test_wrong_state_is_rejected():
    pending = grant.PendingGrant()
    with pytest.raises(grant.IdentityGrantError, match="STATE_MISMATCH"):
        pending.consume_request(request("a" * 43))
    assert pending.verifier == ""


def test_fixed_port_collision_has_no_fallback():
    listener = grant.open_listener()
    try:
        with pytest.raises(grant.IdentityGrantError, match="PORT_UNAVAILABLE"):
            grant.open_listener()
    finally:
        listener.close()


def send_callback(raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", grant.CALLBACK_PORT), timeout=3) as client:
        client.sendall(raw)
        chunks = []
        while chunk := client.recv(4096):
            chunks.append(chunk)
        return b"".join(chunks)


def test_real_socket_callback_response_has_no_grant_and_listener_closes(capsys):
    listener = grant.open_listener()
    pending = grant.PendingGrant()
    raw = request(pending.state)
    responses = []
    thread = threading.Thread(target=lambda: responses.append(send_callback(raw)))
    thread.start()
    payload = grant.receive_callback(listener, pending, child_alive=lambda: True, timeout=2)
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert json.loads(payload)["authorization_code"] == CODE
    assert b"200 OK" in responses[0] and b"Cache-Control: no-store" in responses[0]
    assert CODE.encode() not in responses[0] and listener.fileno() == -1
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("alive,timeout,reason", [(True, 0.02, "CALLBACK_TIMEOUT"), (False, 1, "CHILD_EXITED")])
def test_callback_timeout_and_child_exit_close_listener(alive, timeout, reason):
    listener = grant.open_listener()
    pending = grant.PendingGrant()
    with pytest.raises(grant.IdentityGrantError, match=reason):
        grant.receive_callback(listener, pending, child_alive=lambda: alive, timeout=timeout)
    assert pending.verifier == "" and listener.fileno() == -1


def plan_arguments():
    return ["--destination-account-id", "905418363887", "--initiator-id", "synthetic-operator",
            "--change-set-name", "scanalyze-platform-authority-bootstrap-20300101000000",
            "--plan-out", "/private/tmp/plan.synthetic.json", "--allow-change-set-write"]


@pytest.mark.parametrize("suffix", [
    ["--identity-grant-fd", "3"], ["--identity-grant-ready-fd", "4"],
    ["--authority-account-id", "111122223333"], ["--region", "eu-west-1"],
    ["--profile", "administrator"], ["--help"], ["--plan-out", "duplicate"],
])
def test_command_forwarding_has_no_argv_override(suffix):
    with pytest.raises(grant.IdentityGrantError, match="ARGUMENTS_INVALID"):
        grant.child_arguments("plan", plan_arguments() + suffix)


def test_real_ready_and_grant_descriptors_preserve_cli_consumer(cli):
    read_fd, write_fd = os.pipe()
    ready_read, ready_write = os.pipe()
    args = argparse.Namespace(identity_grant_fd=read_fd, identity_grant_ready_fd=ready_write)
    try:
        cli._validate_identity_grant_ready_descriptor(args)
        cli._signal_identity_grant_ready(args, "plan")
        ready_write = -1
        value = json.loads(os.read(ready_read, 512))
        assert value == {"schema_version": "1", "record_type": "platform_authority_bootstrap_grant_ready",
                         "operation": "plan", "pid": os.getpid()}
        assert os.read(ready_read, 1) == b""
        pending = grant.PendingGrant()
        payload = pending.consume_request(request(pending.state))
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        assert json.loads(cli._read_identity_grant_json(read_fd)) == json.loads(payload)
    finally:
        for fd in (read_fd, write_fd, ready_read, ready_write):
            if fd >= 0:
                os.close(fd)


def test_no_opt_in_preserves_legacy(cli):
    cli._validate_identity_grant_ready_descriptor(argparse.Namespace())
    cli._signal_identity_grant_ready(argparse.Namespace(), "plan")


def test_invalid_ready_descriptor_stops_main_before_handler(cli, monkeypatch, tmp_path):
    path = tmp_path / "not-a-pipe"
    with path.open("wb") as stream:
        called = []
        args = argparse.Namespace(identity_grant_fd=stream.fileno(), identity_grant_ready_fd=stream.fileno(),
                                  handler=lambda _: called.append(True))
        parser = argparse.Namespace(parse_args=lambda: args)
        monkeypatch.setattr(cli, "_parser", lambda: parser)
        assert cli.main() == 1
        assert called == [] and path.read_bytes() == b""


def test_ready_rejects_wrong_pipe_direction(cli):
    grant_read, grant_write = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        with pytest.raises(cli.BootstrapAuthorizationError):
            cli._validate_identity_grant_ready_descriptor(argparse.Namespace(
                identity_grant_fd=grant_read, identity_grant_ready_fd=ready_read))
    finally:
        for fd in (grant_read, grant_write, ready_read, ready_write):
            os.close(fd)


def test_launcher_requires_isolation_before_source_or_browser():
    result = subprocess.run([sys.executable, str(ROOT / "scripts/deployment/platform-authority-bootstrap-identity-grant.py")],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and result.stdout == ""
    assert result.stderr == "GUG274_PKCE_BLOCKED:ISOLATED_PYTHON_REQUIRED\n"


def test_launcher_arg_errors_do_not_echo_input():
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    result = subprocess.run([sys.executable, "-I", "-S", str(ROOT / "scripts/deployment/platform-authority-bootstrap-identity-grant.py"),
                             "--unknown", CODE], env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 2 and result.stdout == "" and CODE not in result.stderr
    assert result.stderr == "GUG274_PKCE_BLOCKED:ARGUMENTS_INVALID\n"


@pytest.mark.parametrize("changes", [{"pid": 987}, {"operation": "apply"}, {"extra": "not-allowed"}])
def test_ready_message_is_exact_to_child_process_and_operation(changes):
    read_fd, write_fd = os.pipe()
    value = {"schema_version": "1", "record_type": "platform_authority_bootstrap_grant_ready",
             "operation": "plan", "pid": 123}
    value.update(changes)
    os.write(write_fd, json.dumps(value).encode())
    os.close(write_fd)
    try:
        with pytest.raises(grant.IdentityGrantError, match="READINESS_INVALID"):
            grant.wait_ready(read_fd, operation="plan", child=SimpleNamespace(pid=123, poll=lambda: None))
    finally:
        os.close(read_fd)


def test_wait_ready_times_out_and_detects_child_exit():
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(grant.IdentityGrantError, match="READINESS_TIMEOUT"):
            grant.wait_ready(read_fd, operation="plan", child=SimpleNamespace(pid=123, poll=lambda: None), timeout=0.01)
        with pytest.raises(grant.IdentityGrantError, match="CHILD_EXITED"):
            grant.wait_ready(read_fd, operation="plan", child=SimpleNamespace(pid=123, poll=lambda: 1), timeout=1)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_pipe_transport_cannot_wait_forever_for_stalled_or_dead_child():
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(grant.IdentityGrantError, match="PIPE_WRITE_TIMEOUT"):
            grant.write_pipe(write_fd, b"x" * (4 * 1024 * 1024), child_alive=lambda: True, timeout=0.01)
        with pytest.raises(grant.IdentityGrantError, match="CHILD_EXITED_DURING_TRANSPORT"):
            grant.write_pipe(write_fd, b"synthetic", child_alive=lambda: False)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def offline_source_snapshot():
    from tooling.platform_authority_bootstrap_artifact_package import SOURCE_PATHS, PROVENANCE_PATHS
    snapshot = {str(path): (ROOT / path).read_bytes() for path in (*SOURCE_PATHS, *PROVENANCE_PATHS) if path.suffix == ".py"}
    entry = "scripts/deployment/platform-authority-bootstrap.py"
    # Only replace dispatch of the external operation. The real parser,
    # readiness, reader, source importer and all transitive imports remain.
    offline = "\n".join([
        "if __name__ == '__main__':",
        "    args = _parser().parse_args()",
        "    _validate_identity_grant_ready_descriptor(args)",
        "    _signal_identity_grant_ready(args, 'plan')",
        "    value = json.loads(_read_identity_grant_json(args.identity_grant_fd))",
        f"    assert value['authorization_code'] == {CODE!r}",
        "    assert len(value['code_verifier']) == 64",
        "    value.clear()",
    ]) + "\n"
    original = snapshot[entry]
    suffix = b'if __name__ == "__main__":\n    raise SystemExit(main())\n'
    assert original.endswith(suffix)
    snapshot[entry] = original[:-len(suffix)] + offline.encode()
    return snapshot


def test_launcher_transports_to_real_cli_reader_after_real_ready_signal(tmp_path, monkeypatch, capsys):
    real_popen = subprocess.Popen
    observed = []
    callback_threads = []
    responses = []
    steps = []
    def consumer_only(command, **kwargs):
        observed.append((command, kwargs))
        return real_popen(command, **kwargs)
    monkeypatch.setattr(grant.subprocess, "Popen", consumer_only)
    def browser(url):
        steps.append("browser")
        assert steps == ["source", "source", "browser"]
        state = parse_qs(urlsplit(url).query)["state"][0]
        thread = threading.Thread(target=lambda: responses.append(send_callback(request(state))))
        callback_threads.append(thread)
        thread.start()
    assert grant.launch(source_root=ROOT, source_snapshot=offline_source_snapshot(), binding=binding(), operation="plan", arguments=plan_arguments(),
                        revalidate_source=lambda: steps.append("source"), browser=browser) == 0
    for thread in callback_threads:
        thread.join(timeout=3)
        assert not thread.is_alive()
    command, kwargs = observed[0]
    assert command[:5] == [sys.executable, "-I", "-S", "-c", grant.CHILD_BOOTSTRAP]
    assert kwargs["close_fds"] is True and len(kwargs["pass_fds"]) == 3
    assert CODE not in repr(command) and "env" not in kwargs
    assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
    assert b"200 OK" in responses[0]
    assert capsys.readouterr() == ("", "")


def source_checkout(tmp_path):
    from tooling.platform_authority_bootstrap_artifact_package import (
        PROVENANCE_PATHS, SOURCE_PATHS, resolve_trusted_executable,
        verify_clean_source_commit,
    )
    root = (tmp_path / "source").resolve()
    for relative in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    git = str(resolve_trusted_executable(name="git", source_root=root))
    def run(*args):
        return subprocess.run([git, *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    run("init", "-q")
    run("add", ".")
    run("-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", "commit", "-qm", "synthetic reviewed source")
    commit = run("rev-parse", "HEAD")
    verify_clean_source_commit(source_root=root, source_commit=commit)
    return root, commit, run


def test_actual_launcher_rejects_hidden_helper_drift_before_import(tmp_path):
    root, commit, git = source_checkout(tmp_path)
    helper = Path("tooling/platform_authority_bootstrap_identity_grant.py")
    marker = tmp_path / "unverified-helper-executed"
    git("update-index", "--assume-unchanged", str(helper))
    with (root / helper).open("a") as stream:
        stream.write(f"\nPath({str(marker)!r}).write_text('unverified')\n")
    assert git("status", "--porcelain", "--untracked-files=all") == ""
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    result = subprocess.run([sys.executable, "-I", "-S", str(root / "scripts/deployment/platform-authority-bootstrap-identity-grant.py"),
                             "--source-commit", commit, "--binding", str(tmp_path / "unread.json"),
                             "--expected-binding-sha256", "a" * 64, "plan", *plan_arguments()],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and result.stdout == ""
    assert result.stderr == "GUG274_PKCE_BLOCKED:OPERATION_REJECTED_OR_UNCERTAIN\n"
    assert not marker.exists()


@pytest.mark.parametrize("relative", [
    "scripts/deployment/platform-authority-bootstrap.py",
    "tooling/platform_authority_bootstrap.py",
])
def test_verified_child_snapshot_never_executes_post_check_disk_mutation(tmp_path, monkeypatch, relative):
    from tooling.platform_authority_bootstrap_artifact_package import (
        SOURCE_PATHS, PROVENANCE_PATHS, verify_clean_source_commit,
    )
    root, commit, _ = source_checkout(tmp_path)
    snapshot = {str(path): (root / path).read_bytes() for path in (*SOURCE_PATHS, *PROVENANCE_PATHS) if path.suffix == ".py"}
    marker = tmp_path / "post-check-source-executed"
    verified = []
    def verify_then_concurrent_edit():
        verify_clean_source_commit(source_root=root, source_commit=commit)
        verified.append(True)
        (root / relative).write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    def forbidden_browser(url):
        raise AssertionError("No browser for a rejected normal CLI profile")
    with pytest.raises(grant.IdentityGrantError, match="CHILD_(EXITED|CLOSED)_BEFORE_READY"):
        grant.launch(source_root=root, source_snapshot=snapshot, binding=binding(),
                     operation="plan", arguments=plan_arguments(),
                     revalidate_source=verify_then_concurrent_edit, browser=forbidden_browser)
    assert verified == [True]
    assert not marker.exists()
