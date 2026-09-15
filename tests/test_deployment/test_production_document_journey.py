"""Production admission with real signatures/protocol and synthetic HTTP ports."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from tooling import production_document_journey as driver
from tooling import document_journey_smoke as smoke
from tooling import release_policy_gate as gate
from tests.test_deployment import test_document_journey_smoke as protocol

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)
SOURCE = "c" * 40
CUSTOMER = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OPERATION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
POLICY_DIGEST = "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def reject(*_args, **_kwargs):
        pytest.fail("Production tests must not contact a real network")
    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(socket, "create_connection", reject)


class Clock:
    def __init__(self):
        self.elapsed = 0.0

    def monotonic(self):
        return self.elapsed

    def utcnow(self):
        return NOW + timedelta(seconds=self.elapsed)

    def sleep(self, seconds):
        self.elapsed += seconds


@pytest.fixture
def bundle(tmp_path, rsa_key):
    directory = (tmp_path / "evidence").resolve()
    directory.mkdir(mode=0o700)
    receipt = directory / (OPERATION + ".jsonl")
    manifest = json.loads((ROOT / "fixtures/valid/release-v2-complete.synthetic.json").read_bytes())
    attestation = json.loads((ROOT / "fixtures/valid/release-attestation-v2-complete.synthetic.json").read_bytes())
    policy = json.loads((ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.json").read_bytes())
    public = rsa_key.public_key().public_numbers()
    jwks = {"keys": [{"kid": "synthetic-rsa-test", "kty": "RSA", "alg": "RS256", "use": "sig",
                      "n": b64(public.n.to_bytes(256, "big")), "e": b64(public.e.to_bytes(3, "big"))}]}
    config = {
        "schema_version": "3", "config_version": manifest["release_version"], "customer_id": CUSTOMER,
        "deployment_id": DEPLOYMENT, "account_id": "905418363887", "region": "us-east-1", "environment": "production",
        "api_endpoint": driver.ORIGIN + "/api", "identity_values_authoritative": False,
        "cognito": {"user_pool_id": "us-east-1_Synthetic", "spa_client_id": "syntheticspaclient",
            "issuer_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic", "region": "us-east-1",
            "hosted_ui_domain": "https://synthetic.auth.us-east-1.amazoncognito.com",
            "redirect_uri": driver.ORIGIN + "/callback", "post_logout_redirect_uri": driver.ORIGIN + "/",
            "allowed_oauth_flows": ["code"], "pkce_required": True, "client_secret_embedded": False},
        "authorization": {"allowed_token_uses": ["access"],
            "action_scopes": {action: f"scanalyze.api.v1/{action}" for action in ("read", "write", "admin")},
            "policy_version": "1.0.0", "policy_digest": POLICY_DIGEST,
            "policy_canonicalization": "rfc8785_json_canonicalization", "customer_claim_name": "custom:customerId",
            "deployment_claim_name": "custom:deployment_id", "id_tokens_accepted": False},
    }
    authority = {
        "schema_version": "production-document-journey-authority.v1", "operation_id": OPERATION,
        "issued_at": int(NOW.timestamp()), "expires_at": int(NOW.timestamp()) + 120,
        "deployment_observed_at": int(NOW.timestamp()), "deployment_readback_digest": "sha256:" + "d" * 64,
        "environment": "production", "api_origin": driver.ORIGIN, "processing_domain": "bank",
        "customer_id": CUSTOMER, "deployment_id": DEPLOYMENT, "account_id": "905418363887", "region": "us-east-1",
        "subject_id": SUBJECT, "issuer_url": config["cognito"]["issuer_url"], "spa_client_id": "syntheticspaclient",
        "upload_host": protocol.UPLOAD_HOST, "release_manifest_digest": manifest["release_manifest_digest"],
        "release_version": manifest["release_version"], "release_sha256": driver._sha(encoded(manifest)),
        "attestation_sha256": driver._sha(encoded(attestation)), "trust_policy_sha256": driver._sha(encoded(policy)),
        "trust_policy_digest": gate.canonical_digest(policy), "jwks_sha256": driver._sha(encoded(jwks)),
        "runtime_config_sha256": driver._sha(encoded(config)), "driver_source_commit": SOURCE,
        "synthetic_pdf_sha256": driver._sha(smoke.synthetic_pdf()), "timeout_seconds": 60,
        "poll_interval_seconds": 1, "max_requests": 40, "evidence_path": str(receipt),
    }
    claims = {"iss": authority["issuer_url"], "client_id": authority["spa_client_id"], "sub": SUBJECT,
        "custom:customerId": CUSTOMER, "custom:deployment_id": DEPLOYMENT, "principal_type": "user",
        "membership_state": "active", "membership_version": "3", "policy_version": "1.0.0",
        "policy_digest": POLICY_DIGEST, "token_use": "access", "iat": int(NOW.timestamp()) - 1,
        "auth_time": int(NOW.timestamp()) - 1, "exp": int(NOW.timestamp()) + 180,
        "scope": "scanalyze.api.v1/read scanalyze.api.v1/write scanalyze.api.v1/admin"}
    return dict(authority=authority, manifest=manifest, attestation=attestation, policy=policy,
                jwks=jwks, config=config, claims=claims, key=rsa_key, receipt=receipt, clock=Clock())


def token(bundle, *, header=None, key=None):
    header = {"alg": "RS256", "kid": "synthetic-rsa-test"} if header is None else header
    message = b64(encoded(header)) + "." + b64(encoded(bundle["claims"]))
    return message + "." + b64((key or bundle["key"]).sign(message.encode(), padding.PKCS1v15(), hashes.SHA256()))


def inputs(bundle):
    raw = encoded(bundle["authority"])
    return dict(authority_bytes=raw, expected_authority_digest=driver._sha(raw),
        release_bytes=encoded(bundle["manifest"]), attestation_bytes=encoded(bundle["attestation"]),
        trust_policy_bytes=encoded(bundle["policy"]), jwks_bytes=encoded(bundle["jwks"]),
        receipt_path=bundle["receipt"], source_commit=SOURCE, access_token=token(bundle),
        utcnow=bundle["clock"].utcnow, clock=bundle["clock"].monotonic, sleep=bundle["clock"].sleep)


def protocol_responses():
    result = protocol.happy_responses()
    # Preserve the real fixtures' JSON schemas and values; shift only their
    # synthetic timestamps into the signed release's verification window.
    replacements = {
        "2026-01-01T00:00:00Z": "2026-07-14T11:59:50Z",
        "2026-01-01T00:00:03Z": "2026-07-14T11:59:53Z",
        "2026-01-01T00:15:00Z": "2026-07-14T12:10:00Z",
    }
    adjusted = []
    for response in result:
        body = response.body
        for old, new in replacements.items():
            body = body.replace(old.encode(), new.encode())
        adjusted.append(smoke.HttpResponse(response.status, response.headers, body))
    return adjusted


class Client:
    def __init__(self, bundle):
        self.bundle = bundle
        self.responses = protocol_responses()
        self.calls = []
        self.config_bytes = encoded(bundle["config"])
        self.on_request = None

    def request(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), body, timeout))
        if self.on_request:
            self.on_request(self, url)
        if url == driver.ORIGIN + "/config.json":
            return smoke.HttpResponse(200, {"Content-Type": "application/json"}, self.config_bytes)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def run(bundle, client=None, **overrides):
    values = inputs(bundle)
    values.update(overrides)
    return driver.run_journey(**values, client=client or Client(bundle))


def rejection(bundle, client=None, *, before_http=False, **overrides):
    client = client or Client(bundle)
    with pytest.raises(driver.JourneyError) as error:
        run(bundle, client, **overrides)
    assert str(error.value) == error.value.code
    assert "synthetic-rsa-test" not in str(error.value)
    if before_http:
        assert client.calls == []
        assert not bundle["receipt"].exists()
    return error.value.code


def test_full_signed_production_admission_runs_original_protocol_and_sanitized_journal(bundle):
    client = Client(bundle)
    summary = run(bundle, client)
    assert summary["status"] == "JOURNEY_CHECKS_PASSED"
    assert summary["production_authorized"] is False
    assert summary["production_readiness"] == "NOT_ESTABLISHED"
    assert summary["completed_steps"] == list(smoke.STEPS)
    assert summary["total_http_requests"] == 14
    calls = [call for call in client.calls if call[1] != driver.ORIGIN + "/config.json"]
    assert [call[0] for call in calls] == ["POST", "PUT", "POST", "GET", "GET", "POST"]
    assert calls[0][2]["Idempotency-Key"] == calls[-1][2]["Idempotency-Key"]
    assert calls[0][3] == calls[-1][3]
    assert calls[1][2] == {"Content-Type": "application/pdf"}
    assert calls[1][3] == smoke.synthetic_pdf()
    assert all("Authorization" not in call[2] for call in client.calls if call[1].endswith("/config.json"))
    raw = bundle["receipt"].read_text()
    for private in (token(bundle), protocol.UPLOAD_URL, SUBJECT, "Scanalyze Synthetic Bank", "100.0"):
        assert private not in raw
    events = [json.loads(line) for line in raw.splitlines()]
    assert events[1]["event"] == "BEFORE_HTTP"
    prepared = next(index for index, event in enumerate(events) if event.get("event") == "CREATE_PREPARED")
    first_api = next(index for index, event in enumerate(events) if event.get("phase") == "API")
    assert prepared < first_api
    assert bundle["receipt"].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("field,value", [
    ("api_origin", "https://other.invalid"), ("api_origin", driver.ORIGIN + "/"),
    ("environment", "staging"), ("processing_domain", "personal"), ("account_id", "123456789012"),
    ("region", "us-west-2"), ("synthetic_pdf_sha256", "sha256:" + "f" * 64),
    ("driver_source_commit", "d" * 40), ("release_manifest_digest", "sha256:" + "e" * 64),
    ("release_version", "7.7.7"), ("expires_at", int(NOW.timestamp())),
    ("deployment_observed_at", int(NOW.timestamp()) - 301), ("issued_at", True),
    ("max_requests", 13), ("timeout_seconds", 241), ("poll_interval_seconds", 0),
    ("evidence_path", "/private/tmp/unapproved-evidence.jsonl"),
])
def test_resealed_authority_mismatch_still_fails_before_http(bundle, field, value):
    bundle["authority"][field] = value
    rejection(bundle, before_http=True)


def test_changed_authority_with_original_external_pin_is_rejected(bundle):
    approved = driver._sha(encoded(bundle["authority"]))
    bundle["authority"]["customer_id"] = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
    assert rejection(bundle, expected_authority_digest=approved, before_http=True) == "AUTHORITY_PIN_MISMATCH"


@pytest.mark.parametrize("field", ["release_sha256", "attestation_sha256", "trust_policy_sha256", "trust_policy_digest", "jwks_sha256"])
def test_every_independent_input_pin_is_required(bundle, field):
    bundle["authority"][field] = "sha256:" + "f" * 64
    rejection(bundle, before_http=True)


def test_invalid_actual_vsa_cannot_be_approved_by_resealing_its_byte_pin(bundle):
    bundle["attestation"]["signature"]["value"] = base64.b64encode(b"not-a-real-signature").decode()
    bundle["authority"]["attestation_sha256"] = driver._sha(encoded(bundle["attestation"]))
    assert rejection(bundle, before_http=True) == "RELEASE_NOT_APPROVED"


@pytest.mark.parametrize("field,value", [
    ("sub", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), ("custom:customerId", "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
    ("custom:deployment_id", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"), ("client_id", "differentclient"),
    ("iss", "https://issuer.invalid"), ("token_use", "id"), ("principal_type", "machine"),
    ("membership_state", "invited"), ("membership_version", "0"),
    ("iat", int(NOW.timestamp()) - 301), ("exp", int(NOW.timestamp())), ("iat", True),
    ("nbf", int(NOW.timestamp()) + 10), ("scope", "scanalyze.api.v1/read"),
])
def test_real_signed_wrong_or_stale_principal_fails_before_http(bundle, field, value):
    bundle["claims"][field] = value
    rejection(bundle, before_http=True)


def test_jwt_signature_is_verified_not_only_decoded(bundle):
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert rejection(bundle, access_token=token(bundle, key=foreign), before_http=True) == "TOKEN_INVALID"


@pytest.mark.parametrize("header", [
    {"alg": "none", "kid": "synthetic-rsa-test"}, {"alg": "HS256", "kid": "synthetic-rsa-test"},
    {"alg": "RS256", "kid": "unknown"}, {"alg": "RS256", "kid": "synthetic-rsa-test", "jku": "https://wrong.invalid"},
])
def test_jwt_header_cannot_select_algorithm_or_key_source(bundle, header):
    rejection(bundle, access_token=token(bundle, header=header), before_http=True)


@pytest.mark.parametrize("field,value", [
    ("customer_id", "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"), ("deployment_id", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
    ("environment", "dev"), ("config_version", "9.9.9"), ("api_endpoint", "https://wrong.invalid/api"),
])
def test_resealed_config_does_not_override_approved_target_or_release(bundle, field, value):
    bundle["config"][field] = value
    bundle["authority"]["runtime_config_sha256"] = driver._sha(encoded(bundle["config"]))
    client = Client(bundle)
    assert rejection(bundle, client) == "RUNTIME_CONFIG_MISMATCH"
    assert [call[0] for call in client.calls] == ["GET"]


def test_config_drift_between_read_and_create_stops_before_first_post(bundle):
    client = Client(bundle)
    def mutate(port, _url):
        if len(port.calls) == 2:
            port.config_bytes += b" "
    client.on_request = mutate
    assert rejection(bundle, client) == "RUNTIME_CONFIG_MISMATCH"
    assert all(call[0] == "GET" for call in client.calls)


def test_wrong_upload_host_never_receives_pdf_or_bearer(bundle):
    client = Client(bundle)
    created = json.loads(client.responses[0].body)
    created["uploadCapability"]["url"] = "https://foreign.s3.us-east-1.amazonaws.com/path?signature=synthetic"
    client.responses[0] = protocol.response(created, 201)
    assert rejection(bundle, client) == "UPLOAD_CAPABILITY_NOT_ALLOWED"
    assert not any(call[0] == "PUT" for call in client.calls)


def test_unknown_create_outcome_records_recovery_and_never_retries(bundle):
    client = Client(bundle)
    client.responses[0] = TimeoutError("synthetic-private-provider-detail")
    assert rejection(bundle, client) == "REQUEST_OUTCOME_UNKNOWN"
    assert sum(call[0] == "POST" for call in client.calls) == 1
    raw = bundle["receipt"].read_text()
    assert "CREATE_PREPARED" in raw and "SUMMARY" not in raw
    assert "synthetic-private-provider-detail" not in raw
    repeat = Client(bundle)
    assert rejection(bundle, repeat) == "RECEIPT_ALREADY_EXISTS"
    assert repeat.calls == []


def test_failed_chunk_result_is_never_a_success_summary(bundle):
    client = Client(bundle)
    status = json.loads(client.responses[3].body)
    status.update(lifecycle="FAILED", stageState="FAILED", failureDisposition="TERMINAL", safeFailureCode="OCR_FAILED")
    client.responses[3] = protocol.response(status)
    assert rejection(bundle, client) == "DOCUMENT_PROCESSING_FAILED"
    assert "SUMMARY" not in bundle["receipt"].read_text()
    assert not any(call[1].endswith("/result") for call in client.calls)


def test_replay_mismatch_is_not_a_success(bundle):
    client = Client(bundle)
    replay = json.loads(client.responses[-1].body)
    replay["durableResponse"]["documentId"] = "b" * 32
    client.responses[-1] = protocol.response(replay, 201)
    assert rejection(bundle, client) == "IDEMPOTENCY_REPLAY_MISMATCH"


def test_authority_expiring_during_preflight_prevents_create(bundle):
    client = Client(bundle)
    client.on_request = lambda *_: setattr(bundle["clock"], "elapsed", 121)
    assert rejection(bundle, client) == "AUTHORITY_EXPIRED"
    assert all(call[0] == "GET" for call in client.calls)


def test_request_budget_counts_config_reads_and_upload(bundle):
    bundle["authority"]["max_requests"] = 14
    client = Client(bundle)
    observed = json.loads(client.responses[3].body)
    observed.update(lifecycle="PROCESSING", currentStage="OCR", stageState="RUNNING", processingCondition="ACTIVE")
    observed.pop("terminalAt")
    client.responses.insert(3, protocol.response(observed))
    assert rejection(bundle, client) == "REQUEST_BUDGET_EXHAUSTED"
    assert len(client.calls) == 14


def test_input_snapshots_survive_caller_mutation(bundle):
    values = inputs(bundle)
    client = Client(bundle)
    client.on_request = lambda *_: bundle["authority"].update(api_origin="https://wrong.invalid")
    assert driver.run_journey(**values, client=client)["status"] == "JOURNEY_CHECKS_PASSED"


@pytest.mark.parametrize("mode", [0o644, 0o666])
def test_private_input_reader_rejects_permissions(bundle, mode):
    source = bundle["receipt"].parent / "authority.json"
    source.write_bytes(encoded(bundle["authority"]))
    source.chmod(mode)
    with pytest.raises(driver.JourneyError, match="INPUT_CUSTODY_INVALID"):
        driver._read_private(source, driver._cli_support())


def test_missing_explicit_write_authorization_stops_before_source_or_secret_access(monkeypatch, capsys):
    monkeypatch.setattr(driver, "_cli_support", lambda: pytest.fail("must not inspect source"))
    arguments = []
    for flag in ("authority", "release", "attestation", "trust-policy", "jwks", "receipt"):
        arguments.extend(["--" + flag, "/private/tmp/nonexistent.json"])
    arguments.extend(["--expected-authority-digest", "sha256:" + "a" * 64])
    assert driver.main(arguments) == 2
    assert capsys.readouterr().out == ""


def test_cli_uses_real_admission_protocol_and_private_io_without_network(bundle, monkeypatch, capsys):
    support = driver._cli_support()
    monkeypatch.setattr(support, "_verify_source", lambda: SOURCE)
    monkeypatch.setattr(driver, "_cli_support", lambda: support)
    client = Client(bundle)
    monkeypatch.setattr(smoke, "HttpsTransport", lambda: client)
    real_run = driver.run_journey
    def controlled_clock(**kwargs):
        return real_run(**kwargs, utcnow=bundle["clock"].utcnow, clock=bundle["clock"].monotonic, sleep=bundle["clock"].sleep)
    monkeypatch.setattr(driver, "run_journey", controlled_clock)
    # Only the clock boundary is changed; both signatures and the complete
    # source-independent admission/protocol/Journal remain real.
    real_now = driver._now
    monkeypatch.setattr(driver, "_now", lambda clock: real_now(bundle["clock"].utcnow))
    monkeypatch.setenv(driver.TOKEN_ENV, token(bundle))
    files = {"authority": bundle["authority"], "release": bundle["manifest"],
             "attestation": bundle["attestation"], "trust-policy": bundle["policy"], "jwks": bundle["jwks"]}
    args = ["--authorize-application-writes", "--receipt", str(bundle["receipt"]),
            "--expected-authority-digest", driver._sha(encoded(bundle["authority"]))]
    for name, value in files.items():
        path = bundle["receipt"].parent / (name + ".json")
        path.write_bytes(encoded(value))
        path.chmod(0o600)
        args.extend(["--" + name, str(path)])
    assert driver.main(args) == 0
    output = capsys.readouterr()
    assert output.err == ""
    summary = json.loads(output.out)
    assert summary["status"] == "JOURNEY_CHECKS_PASSED"
    assert token(bundle) not in output.out and SUBJECT not in output.out


def test_original_development_cli_still_rejects_production_configuration():
    options = protocol.config_dict()
    options["environment"] = "production"
    with pytest.raises(smoke.SmokeError, match="TARGET_NOT_ALLOWED"):
        smoke.SmokeConfig.from_dict(options)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]'])
def test_strict_input_json_rejects_duplicates_nonfinite_and_nonobject(raw):
    with pytest.raises(driver.JourneyError, match="INPUT_JSON_INVALID"):
        driver._json(raw)


@pytest.mark.parametrize("change", ["extra", "missing"])
def test_authority_has_a_closed_required_contract(bundle, change):
    if change == "extra":
        bundle["authority"]["allow_unsigned"] = True
    else:
        del bundle["authority"]["deployment_readback_digest"]
    assert rejection(bundle, before_http=True) == "AUTHORITY_FIELDS_INVALID"


@pytest.mark.parametrize("change", ["duplicate_kid", "weak_key", "remote_key_url"])
def test_resealed_jwks_still_requires_bounded_unique_rsa_signing_keys(bundle, change):
    if change == "duplicate_kid":
        bundle["jwks"]["keys"].append(dict(bundle["jwks"]["keys"][0]))
    elif change == "weak_key":
        numbers = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_numbers()
        bundle["jwks"]["keys"][0]["n"] = b64(numbers.n.to_bytes(128, "big"))
    else:
        bundle["jwks"]["keys"][0]["jku"] = "https://wrong.invalid/keys"
    bundle["authority"]["jwks_sha256"] = driver._sha(encoded(bundle["jwks"]))
    assert rejection(bundle, before_http=True) == "JWKS_INVALID"


def test_final_config_drift_never_writes_success_summary(bundle):
    client = Client(bundle)
    def mutate(port, _url):
        if len(port.calls) == 14:
            port.config_bytes += b" "
    client.on_request = mutate
    assert rejection(bundle, client) == "RUNTIME_CONFIG_MISMATCH"
    assert len(client.calls) == 14
    assert "SUMMARY" not in bundle["receipt"].read_text()


def test_token_expiry_after_create_never_uploads_or_reauthenticates(bundle):
    bundle["claims"]["exp"] = int(NOW.timestamp()) + 2
    client = Client(bundle)
    def expire(port, _url):
        if len(port.calls) == 3:
            bundle["clock"].elapsed = 3
    client.on_request = expire
    assert rejection(bundle, client) == "TOKEN_EXPIRED"
    assert len(client.calls) == 3
    assert not any(call[0] == "PUT" for call in client.calls)
    assert "SUMMARY" not in bundle["receipt"].read_text()


def test_expiry_during_durable_journal_write_prevents_next_effect(bundle, monkeypatch):
    support = driver._cli_support()
    original = support.Journal.append
    def slow_append(self, event):
        original(self, event)
        if event.get("phase") == "API":
            bundle["clock"].elapsed = 121
    monkeypatch.setattr(support.Journal, "append", slow_append)
    monkeypatch.setattr(driver, "_cli_support", lambda: support)
    client = Client(bundle)
    assert rejection(bundle, client) == "AUTHORITY_EXPIRED"
    assert [call[0] for call in client.calls] == ["GET", "GET"]


def test_journal_failure_stops_before_next_request(bundle, monkeypatch):
    support = driver._cli_support()
    original = support.Journal.append
    def lose_custody(self, event):
        if event.get("phase") == "API":
            os.fchmod(self.descriptor, 0o644)
        return original(self, event)
    monkeypatch.setattr(support.Journal, "append", lose_custody)
    monkeypatch.setattr(driver, "_cli_support", lambda: support)
    client = Client(bundle)
    assert rejection(bundle, client) == "JOURNAL_WRITE_FAILED"
    assert [call[0] for call in client.calls] == ["GET", "GET"]
    assert "SUMMARY" not in bundle["receipt"].read_text()


def test_unauthorized_create_is_not_retried_and_body_is_not_recorded(bundle):
    client = Client(bundle)
    client.responses[0] = smoke.HttpResponse(401, {"Content-Type": "application/json"}, b'{"detail":"synthetic-private-error"}')
    assert rejection(bundle, client) == "HTTP_STATUS_UNEXPECTED"
    assert sum(call[0] == "POST" for call in client.calls) == 1
    raw = bundle["receipt"].read_text()
    assert "synthetic-private-error" not in raw and "SUMMARY" not in raw


@pytest.mark.parametrize("change", ["symlink", "hardlink"])
def test_private_input_aliases_are_rejected(bundle, change):
    source = bundle["receipt"].parent / "authority.json"
    source.write_bytes(encoded(bundle["authority"]))
    source.chmod(0o600)
    alias = source.with_name("alias.json")
    if change == "symlink":
        alias.symlink_to(source)
    else:
        os.link(source, alias)
    with pytest.raises((driver.JourneyError, OSError)):
        driver._read_private(alias, driver._cli_support())


def test_input_custody_change_during_read_is_rejected(bundle, monkeypatch):
    source = bundle["receipt"].parent / "authority.json"
    source.write_bytes(encoded(bundle["authority"]))
    source.chmod(0o600)
    original_inode = source.stat().st_ino
    real_read = os.read
    def mutate_mode(descriptor, count):
        raw = real_read(descriptor, count)
        if os.fstat(descriptor).st_ino == original_inode:
            os.fchmod(descriptor, 0o644)
        return raw
    monkeypatch.setattr(os, "read", mutate_mode)
    with pytest.raises(driver.JourneyError, match="INPUT_CHANGED_DURING_READ"):
        driver._read_private(source, driver._cli_support())


def test_real_signed_waiver_expiring_at_action_time_prevents_create(bundle, monkeypatch):
    from tests.test_deployment import test_release_vsa_producer as signing
    from tooling import release_vsa_producer as producer

    signed = signing.bundle.__wrapped__()
    signing.finding_with_waiver(signed, "2026-07-14T12:00:02Z")
    signing.reanchor(signed)
    result = producer.produce_release_vsa(**signed)
    bundle.update(manifest=signed["manifest"], policy=signed["policy"], attestation=json.loads(result.attestation_bytes))
    authority = bundle["authority"]
    authority.update(release_manifest_digest=bundle["manifest"]["release_manifest_digest"],
        release_sha256=driver._sha(encoded(bundle["manifest"])),
        attestation_sha256=driver._sha(encoded(bundle["attestation"])),
        trust_policy_sha256=driver._sha(encoded(bundle["policy"])), trust_policy_digest=gate.canonical_digest(bundle["policy"]))
    support = driver._cli_support()
    original = support.Journal.append
    def slow_append(self, event):
        original(self, event)
        if event.get("phase") == "API":
            bundle["clock"].elapsed = 3
    monkeypatch.setattr(support.Journal, "append", slow_append)
    monkeypatch.setattr(driver, "_cli_support", lambda: support)
    client = Client(bundle)
    assert rejection(bundle, client) == "RELEASE_NOT_APPROVED"
    assert [call[0] for call in client.calls] == ["GET", "GET"]
    assert "SUMMARY" not in bundle["receipt"].read_text()
