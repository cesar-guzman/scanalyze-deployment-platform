"""Offline JWT operator transport: real CLI, anonymous pipes and loopback sockets.

Only OidcPublicClient.exchange_code is replaced at the provider I/O boundary.
Synthetic JWT signatures are never claimed as authentication or AWS evidence.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
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
from tooling.platform_authority_bootstrap_jwt_grant import operation_binding_digest
from tests.test_deployment.test_gug274_jwt_grant import token as synthetic_jwt


ROOT = Path(__file__).resolve().parents[2]
APP = "arn:aws:sso::042360977644:application/ssoins-1111111111111111/apl-2222222222222222"
INSTANCE = "arn:aws:sso:::instance/ssoins-1111111111111111"
TTI = "arn:aws:sso::042360977644:trustedTokenIssuer/ssoins-1111111111111111/tti-11111111-2222-3333-4444-555555555555"
PLAN = "sha256:" + "a" * 64
APPROVAL = "sha256:" + "b" * 64
CODE = "synthetic-pkce-authorization-code"


@pytest.fixture
def cli():
    spec = importlib.util.spec_from_file_location("gug274_cli_jwt_transport_test", ROOT / "scripts/deployment/platform-authority-bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def binding_bytes(**changes):
    value = {
        "schema_version": "2", "record_type": "platform_authority_bootstrap_jwt_binding",
        "authority_account_id": grant.AUTHORITY_ACCOUNT, "region": grant.REGION,
        "application_arn": APP, "instance_arn": INSTANCE, "redirect_uri": grant.REDIRECT_URI,
        "trusted_token_issuer_arn": TTI, "issuer_url": "https://issuer.example.test",
        "audience": "synthetic-public-client", "authorization_endpoint": "https://issuer.example.test/authorize",
        "token_endpoint": "https://issuer.example.test/token",
    }
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def binding():
    raw = binding_bytes()
    return grant.ApplicationBinding.from_bytes(raw, hashlib.sha256(raw).hexdigest())


def legacy_binding():
    return grant.ApplicationBinding(APP, INSTANCE)


def nonce_for(operation):
    return operation_binding_digest("approval" if operation == "approve" else operation,
                                    PLAN, None if operation == "plan" else APPROVAL)


def assertion_for(nonce, **changes):
    epoch = int(datetime.now(UTC).timestamp())
    payload = {
        "iss": "https://issuer.example.test", "aud": "synthetic-public-client",
        "sub": "synthetic-human", "jti": "synthetic-one-operation",
        "nonce": nonce, "iat": epoch, "auth_time": epoch, "exp": epoch + 300,
    }
    payload.update(changes)
    return synthetic_jwt(payload)


def envelope(assertion):
    return {"schema_version": "2", "record_type": "platform_authority_bootstrap_identity_grant",
            "grant_type": grant.JWT_BEARER_GRANT, "assertion": assertion}


def callback(state):
    return ("GET /callback?" + urlencode({"code": CODE, "state": state})
            + " HTTP/1.1\r\nHost: 127.0.0.1:38271\r\n\r\n").encode()


def send_callback(raw):
    with socket.create_connection(("127.0.0.1", grant.CALLBACK_PORT), timeout=3) as connection:
        connection.sendall(raw)
        received = bytearray()
        while chunk := connection.recv(4096):
            received.extend(chunk)
        return bytes(received)


def close_descriptors(*descriptors):
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass  # The real signaling/transport API owns some descriptor closes.


def test_v2_binding_pin_is_independent_and_captures_exact_issuer_tti_and_endpoints():
    raw = binding_bytes()
    expected = hashlib.sha256(raw).hexdigest()
    value = grant.ApplicationBinding.from_bytes(raw, expected)
    assert value.grant_version == "2"
    assert value.jwt_bearer.trusted_token_issuer_arn == TTI
    assert value.oidc_client.authorization_endpoint == "https://issuer.example.test/authorize"
    assert value.oidc_client.token_endpoint == "https://issuer.example.test/token"
    for field, replacement in {
        "trusted_token_issuer_arn": TTI[:-1] + "6", "issuer_url": "https://other.example.test",
        "authorization_endpoint": "https://other.example.test/authorize",
        "token_endpoint": "https://other.example.test/token", "audience": "other-client",
    }.items():
        with pytest.raises(grant.IdentityGrantError, match="BINDING_PIN_MISMATCH"):
            grant.ApplicationBinding.from_bytes(binding_bytes(**{field: replacement}), expected)


@pytest.mark.parametrize("changes", [
    {"schema_version": "1"}, {"record_type": "platform_authority_bootstrap_pkce_binding"},
    {"extra": "field"}, {"authority_account_id": "111122223333"},
    {"trusted_token_issuer_arn": TTI.replace("042360977644", "111122223333")},
    {"trusted_token_issuer_arn": TTI.replace("ssoins-1111111111111111", "ssoins-2222222222222222")},
    {"trusted_token_issuer_arn": TTI.replace("/tti-", "/")},
    {"issuer_url": "http://issuer.example.test"}, {"issuer_url": "https://localhost"},
    {"issuer_url": "https://issuer.example.test?different=true"},
    {"authorization_endpoint": "http://issuer.example.test/authorize"},
    {"token_endpoint": "https://127.0.0.1/token"},
    {"redirect_uri": "http://127.0.0.1:49152/callback"},
])
def test_repinning_does_not_admit_invalid_v2_binding_or_downgrade(changes):
    raw = binding_bytes(**changes)
    with pytest.raises(grant.IdentityGrantError):
        grant.ApplicationBinding.from_bytes(raw, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("operation", ["plan", "approve", "apply"])
def test_real_cli_ready_pipe_computes_nonce_from_operation_records_not_caller_field(cli, operation):
    grant_read, grant_write = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        args = argparse.Namespace(identity_grant_fd=grant_read, identity_grant_ready_fd=ready_write,
                                  identity_grant_version="2", operation_binding_digest="sha256:" + "c" * 64)
        plan = {"plan_artifact_digest": PLAN}
        approval = None if operation == "plan" else {"approval_artifact_digest": APPROVAL}
        cli._signal_identity_grant_ready(args, operation, plan, approval)
        ready_write = -1
        observed = grant.wait_ready(ready_read, operation=operation, version="2",
                                   child=SimpleNamespace(pid=os.getpid(), poll=lambda: None), timeout=1)
        assert observed == nonce_for(operation)
        assert observed != args.operation_binding_digest
        assert os.read(ready_read, 1) == b""
    finally:
        close_descriptors(grant_read, grant_write, ready_read, ready_write)


@pytest.mark.parametrize("operation,plan,approval", [
    ("plan", None, None), ("approve", {"plan_artifact_digest": PLAN}, None),
    ("apply", {"plan_artifact_digest": PLAN}, None),
    ("plan", {"plan_artifact_digest": PLAN}, {"approval_artifact_digest": APPROVAL}),
])
def test_ready_v2_refuses_missing_or_wrong_operation_artifacts_before_writing(cli, operation, plan, approval):
    grant_read, grant_write = os.pipe()
    ready_read, ready_write = os.pipe()
    try:
        args = argparse.Namespace(identity_grant_fd=grant_read, identity_grant_ready_fd=ready_write, identity_grant_version="2")
        with pytest.raises(cli.BootstrapAuthorizationError):
            cli._signal_identity_grant_ready(args, operation, plan, approval)
        os.set_blocking(ready_read, False)
        with pytest.raises(BlockingIOError):
            os.read(ready_read, 1)
    finally:
        close_descriptors(grant_read, grant_write, ready_read, ready_write)


@pytest.mark.parametrize("version,changes", [
    ("2", {"schema_version": "1"}), ("1", {}),
    ("2", {"operation": "apply"}), ("2", {"pid": 456}),
    ("2", {"extra": "field"}), ("2", {"operation_binding_digest": None}),
    ("2", {"operation_binding_digest": "a" * 64}), ("2", {"operation_binding_digest": "sha256:" + "A" * 64}),
])
def test_ready_receiver_rejects_downgrade_wrong_child_operation_or_nonce(version, changes):
    read_fd, write_fd = os.pipe()
    value = {"schema_version": "2", "record_type": "platform_authority_bootstrap_grant_ready",
             "operation": "plan", "pid": 123, "operation_binding_digest": nonce_for("plan")}
    value.update(changes)
    try:
        os.write(write_fd, json.dumps(value).encode())
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(grant.IdentityGrantError, match="READINESS_INVALID"):
            grant.wait_ready(read_fd, operation="plan", child=SimpleNamespace(pid=123, poll=lambda: None), version=version, timeout=1)
    finally:
        close_descriptors(read_fd, write_fd)


def test_authorization_url_uses_pinned_oidc_pkce_and_cli_nonce_without_a_secret():
    pending = grant.PendingGrant()
    nonce = nonce_for("plan")
    parsed = urlsplit(pending.authorization_url(binding(), nonce))
    assert parsed.scheme + "://" + parsed.netloc + parsed.path == "https://issuer.example.test/authorize"
    query = parse_qs(parsed.query)
    assert set(query) == {"response_type", "client_id", "redirect_uri", "state", "code_challenge_method",
                          "scope", "code_challenge", "nonce", "prompt", "max_age"}
    assert query["nonce"] == [nonce] and query["state"] == [pending.state]
    assert query["client_id"] == ["synthetic-public-client"] and query["scope"] == ["openid"]
    assert query["prompt"] == ["login"] and query["max_age"] == ["0"]
    assert query["redirect_uri"] == [grant.REDIRECT_URI] and query["code_challenge_method"] == ["S256"]
    assert pending.verifier not in parsed.query and CODE not in parsed.query
    assert pending.verifier not in repr(pending)
    with pytest.raises(grant.IdentityGrantError, match="OPERATION_BINDING_INVALID"):
        grant.PendingGrant().authorization_url(binding())
    with pytest.raises(grant.IdentityGrantError, match="OPERATION_BINDING_INVALID"):
        grant.PendingGrant().authorization_url(legacy_binding(), nonce)


def test_real_callback_and_anonymous_socket_reach_v2_cli_reader_without_persisting_or_echoing(cli, monkeypatch, tmp_path, capsys):
    nonce = nonce_for("plan")
    assertion = assertion_for(nonce)
    pending = grant.PendingGrant()
    pending.authorization_url(binding(), nonce)
    verifier = pending.verifier
    calls = []

    def exchange(client, **kwargs):
        calls.append((client, kwargs))
        return assertion

    monkeypatch.setattr(grant.OidcPublicClient, "exchange_code", exchange)
    listener = grant.open_listener()
    responses, thread_errors = [], []

    def send():
        try:
            responses.append(send_callback(callback(pending.state)))
        except Exception as exc:
            thread_errors.append(type(exc).__name__)

    thread = threading.Thread(target=send)
    thread.start()
    payload = grant.receive_callback(listener, pending, child_alive=lambda: True, timeout=2)
    thread.join(timeout=3)
    assert not thread.is_alive() and thread_errors == []
    assert listener.fileno() == -1
    assert json.loads(payload) == envelope(assertion)
    assert calls[0][1] == {"code": CODE, "verifier": verifier, "redirect_uri": grant.REDIRECT_URI}
    assert len(calls) == 1
    receiver, writer = socket.socketpair()
    try:
        writer.sendall(payload)
        writer.shutdown(socket.SHUT_WR)
        assert json.loads(cli._read_identity_grant_json(receiver.fileno(), "2")) == envelope(assertion)
    finally:
        receiver.close()
        writer.close()
    assert pending.state == pending.verifier == "" and pending._binding is None and pending._nonce is None
    with pytest.raises(grant.IdentityGrantError, match="ALREADY_CONSUMED"):
        pending.consume_request(callback("x" * 43))
    assert b"200 OK" in responses[0] and b"Cache-Control: no-store" in responses[0]
    for secret in (CODE, verifier, assertion):
        assert secret.encode() not in responses[0]
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("wrong_state,wrong_nonce", [(True, False), (False, True)])
def test_callback_state_or_returned_jwt_nonce_rejection_burns_pending_grant(monkeypatch, wrong_state, wrong_nonce):
    nonce = nonce_for("plan")
    pending = grant.PendingGrant()
    pending.authorization_url(binding(), nonce)
    calls = []
    assertion = assertion_for("sha256:" + "c" * 64 if wrong_nonce else nonce)

    def exchange(_client, **kwargs):
        calls.append(kwargs)
        return assertion

    monkeypatch.setattr(grant.OidcPublicClient, "exchange_code", exchange)
    with pytest.raises(grant.IdentityGrantError) as caught:
        pending.consume_request(callback("x" * 43 if wrong_state else pending.state))
    assert str(caught.value) == ("CALLBACK_STATE_MISMATCH" if wrong_state else "OIDC_GRANT_REJECTED_OR_UNCERTAIN")
    assert assertion not in str(caught.value) and CODE not in str(caught.value)
    assert len(calls) == (0 if wrong_state else 1)
    assert pending.state == pending.verifier == "" and pending._nonce is None
    with pytest.raises(grant.IdentityGrantError, match="ALREADY_CONSUMED"):
        pending.consume_request(callback("x" * 43))


@pytest.mark.parametrize("reader_version,payload_version", [("1", "2"), ("2", "1")])
def test_cli_reader_refuses_grant_version_downgrade_in_a_real_pipe(cli, reader_version, payload_version):
    payload = envelope(assertion_for(nonce_for("plan"))) if payload_version == "2" else {
        "schema_version": "1", "record_type": "platform_authority_bootstrap_identity_grant",
        "authorization_code": CODE, "code_verifier": "v" * 43,
    }
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, json.dumps(payload).encode())
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(cli.BootstrapAuthorizationError):
            cli._read_identity_grant_json(read_fd, reader_version)
    finally:
        close_descriptors(read_fd, write_fd)


def arguments(operation, directory):
    common = ["--destination-account-id", "444455556666"]
    if operation == "plan":
        return common + ["--initiator-id", "synthetic-operator", "--change-set-name",
                         "scanalyze-platform-authority-bootstrap-20300101000000", "--plan-out", str(directory / "plan.json"), "--allow-change-set-write"]
    if operation == "approve":
        return common + ["--plan", str(directory / "plan.json"), "--approver-id", "synthetic-reviewer",
                         "--approval-out", str(directory / "approval.json")]
    return common + ["--plan", str(directory / "plan.json"), "--approval", str(directory / "approval.json"),
                     "--verification-out", str(directory / "verification.json"), "--backend-config-out", str(directory / "backend.hcl"), "--allow-bootstrap-apply"]


def consumer_snapshot():
    from tooling.platform_authority_bootstrap_artifact_package import SOURCE_PATHS, PROVENANCE_PATHS
    snapshot = {str(path): (ROOT / path).read_bytes() for path in (*SOURCE_PATHS, *PROVENANCE_PATHS) if path.suffix == ".py"}
    entry = "scripts/deployment/platform-authority-bootstrap.py"
    suffix = b'if __name__ == "__main__":\n    raise SystemExit(main())\n'
    assert snapshot[entry].endswith(suffix)
    # Replace cloud operation dispatch only. The actual CLI parser, readiness,
    # selected-grant reader and frozen source importer execute in a real child.
    # These fixture digests are not deployment authority or installation proof.
    offline = "\n".join([
        "if __name__ == '__main__':",
        "    args = _parser().parse_args()",
        "    assert args.identity_grant_version == '2'",
        f"    plan = {{'plan_artifact_digest': {PLAN!r}}}",
        f"    approval = None if args.command == 'plan' else {{'approval_artifact_digest': {APPROVAL!r}}}",
        "    _signal_identity_grant_ready(args, args.command, plan, approval)",
        "    value = json.loads(_read_identity_grant_json(args.identity_grant_fd, args.identity_grant_version))",
        "    assert value['schema_version'] == '2' and value['grant_type'] == JWT_BEARER_GRANT",
        "    encoded = value['assertion'].split('.')[1]",
        "    import base64",
        "    claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))",
        "    expected = operation_binding_digest('approval' if args.command == 'approve' else args.command, plan['plan_artifact_digest'], approval['approval_artifact_digest'] if approval else None)",
        "    assert claims['nonce'] == expected",
        "    value.clear(); claims.clear()",
    ]) + "\n"
    snapshot[entry] = snapshot[entry][:-len(suffix)] + offline.encode()
    return snapshot


@pytest.mark.parametrize("operation", ["plan", "approve", "apply"])
def test_v2_launcher_real_child_nonce_callback_and_grant_pipe_have_no_token_argv_files_or_stdout(operation, tmp_path, monkeypatch, capsys):
    real_popen = subprocess.Popen
    observed, exchanges, replies, threads, thread_errors, steps = [], [], [], [], [], []
    assertion = assertion_for(nonce_for(operation))

    def observe_popen(command, **kwargs):
        observed.append((command, kwargs))
        return real_popen(command, **kwargs)

    def exchange(_client, **kwargs):
        exchanges.append(kwargs)
        return assertion

    def browser(url):
        steps.append("browser")
        assert steps == ["source", "source", "browser"]
        query = parse_qs(urlsplit(url).query)
        assert query["nonce"] == [nonce_for(operation)]
        assert assertion not in url and CODE not in url

        def send():
            try:
                replies.append(send_callback(callback(query["state"][0])))
            except Exception as exc:
                thread_errors.append(type(exc).__name__)

        thread = threading.Thread(target=send)
        threads.append(thread)
        thread.start()

    monkeypatch.setattr(grant.subprocess, "Popen", observe_popen)
    monkeypatch.setattr(grant.OidcPublicClient, "exchange_code", exchange)
    try:
        assert grant.launch(source_root=ROOT, source_snapshot=consumer_snapshot(), binding=binding(), operation=operation,
                            arguments=arguments(operation, tmp_path), revalidate_source=lambda: steps.append("source"), browser=browser) == 0
    finally:
        for thread in threads:
            thread.join(timeout=3)
            assert not thread.is_alive()
    assert thread_errors == [] and len(observed) == len(exchanges) == len(replies) == 1
    command, options = observed[0]
    assert command[-2:] == ["--identity-grant-version", "2"]
    assert options["close_fds"] is True and len(options["pass_fds"]) == 3
    assert options["stdout"] == options["stderr"] == subprocess.DEVNULL and "env" not in options
    for secret in (assertion, CODE, exchanges[0]["verifier"]):
        assert secret not in repr(command) and secret.encode() not in replies[0]
    assert b"200 OK" in replies[0]
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("flag", ["--identity-grant-version", "--operation-binding-digest", "--nonce", "--assertion"])
def test_operator_arguments_cannot_override_selected_version_nonce_or_assertion(flag, tmp_path):
    with pytest.raises(grant.IdentityGrantError, match="COMMAND_ARGUMENTS_INVALID") as caught:
        grant.child_arguments("plan", arguments("plan", tmp_path) + [flag, "synthetic-sensitive-input"])
    assert "synthetic-sensitive-input" not in str(caught.value)
