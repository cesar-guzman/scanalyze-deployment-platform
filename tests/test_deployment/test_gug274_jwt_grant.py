"""Offline parser tests: synthetic signatures are deliberately NOT identity proof."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json

import pytest

from tooling.platform_authority_bootstrap import BootstrapAuthorizationError
from tooling import platform_authority_bootstrap_jwt_grant as grant


ACCOUNT = "111122223333"
INSTANCE = "arn:aws:sso:::instance/ssoins-1111111111111111"
TTI = f"arn:aws:sso::{ACCOUNT}:trustedTokenIssuer/ssoins-1111111111111111/tti-11111111-2222-3333-4444-555555555555"
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
EPOCH = int(NOW.timestamp())
PLAN = "sha256:" + "a" * 64
APPROVAL = "sha256:" + "b" * 64
NONCE = grant.operation_binding_digest("plan", PLAN)


def binding(**changes):
    values = {
        "authority_account_id": ACCOUNT,
        "identity_center_instance_arn": INSTANCE,
        "trusted_token_issuer_arn": TTI,
        "issuer_url": "https://issuer.example.test/identity",
        "audience": "synthetic:bootstrap-authority",
    }
    values.update(changes)
    return grant.JwtBearerBinding(**values)


def claims(**changes):
    values = {
        "iss": binding().issuer_url, "aud": binding().audience,
        "sub": "synthetic-person", "jti": "synthetic-one-time-assertion",
        "nonce": NONCE, "iat": EPOCH, "exp": EPOCH + 900, "auth_time": EPOCH,
    }
    values.update(changes)
    return values


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def token(payload=None, header=None, signature=bytes(range(256))):
    # These bytes are not an RSA signature. Passing the parser must never imply
    # authentication, signature verification or permission for a live effect.
    return ".".join((
        encoded(json.dumps(header if header is not None else {"alg": "RS256", "kid": "synthetic-key", "typ": "JWT"}, separators=(",", ":")).encode()),
        encoded(json.dumps(payload if payload is not None else claims(), separators=(",", ":")).encode()),
        encoded(signature),
    ))


def envelope(assertion=None, **changes):
    value = {
        "schema_version": "2", "record_type": "platform_authority_bootstrap_identity_grant",
        "grant_type": grant.JWT_BEARER_GRANT, "assertion": token() if assertion is None else assertion,
    }
    value.update(changes)
    return value


def assert_denied(call):
    with pytest.raises(grant.JwtBearerGrantError) as caught:
        call()
    assert isinstance(caught.value, BootstrapAuthorizationError)
    assert caught.value.code == "BOOTSTRAP_IDENTITY_PROOF_DENIED"
    assert str(caught.value) == "BOOTSTRAP_IDENTITY_PROOF_DENIED"
    return caught.value


def test_binding_is_frozen_and_digest_matches_domain_separated_wire_contract():
    value = binding()
    public_fields = {
        "authority_account_id": ACCOUNT, "identity_center_instance_arn": INSTANCE,
        "trusted_token_issuer_arn": TTI, "issuer_url": value.issuer_url, "audience": value.audience,
        "max_assertion_lifetime_seconds": 900, "max_auth_age_seconds": 300,
    }
    expected = "sha256:" + hashlib.sha256(
        b"scanalyze.platform-authority.bootstrap.jwt-bearer-binding.v2\x00"
        + json.dumps(public_fields, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert value.digest == expected
    with pytest.raises(FrozenInstanceError):
        value.audience = "changed"
    for field, change in {
        "audience": "other-audience", "issuer_url": "https://other.example.test",
        "trusted_token_issuer_arn": TTI[:-1] + "6",
        "max_assertion_lifetime_seconds": 899, "max_auth_age_seconds": 299,
    }.items():
        assert replace(value, **{field: change}).digest != expected


@pytest.mark.parametrize("changes", [
    {"authority_account_id": "000000000000"}, {"authority_account_id": True},
    {"authority_account_id": "111122223334"}, {"authority_account_id": ACCOUNT + "\n"},
    {"identity_center_instance_arn": INSTANCE[:-1] + "2"},
    {"identity_center_instance_arn": INSTANCE.replace("ssoins-", "ins-")},
    {"identity_center_instance_arn": INSTANCE.replace("arn:aws:", "arn:aws-cn:")},
    {"trusted_token_issuer_arn": TTI.replace("/tti-", "/")},
    {"trusted_token_issuer_arn": TTI + "\n"},
    {"trusted_token_issuer_arn": TTI.replace(ACCOUNT, "444455556666")},
    {"trusted_token_issuer_arn": TTI.replace("trustedTokenIssuer", "application")},
    {"trusted_token_issuer_arn": None}, {"audience": ""}, {"audience": ["synthetic:bootstrap-authority"]},
    {"audience": "\t"}, {"audience": "a" * 2049}, {"audience": "bad\ud800"},
    {"max_assertion_lifetime_seconds": 901}, {"max_assertion_lifetime_seconds": 0},
    {"max_assertion_lifetime_seconds": True}, {"max_assertion_lifetime_seconds": 900.0},
    {"max_auth_age_seconds": 301}, {"max_auth_age_seconds": -1}, {"max_auth_age_seconds": False},
])
def test_binding_rejects_wrong_topology_or_limits(changes):
    assert_denied(lambda: binding(**changes))


@pytest.mark.parametrize("url", [
    "http://issuer.example.test", "https://localhost", "https://host.localhost",
    "https://127.0.0.1", "https://[::1]", "https://192.168.1.1", "https://127.1",
    "https://2130706433", "https://0x7f000001", "https://issuer.example.test?",
    "https://issuer.example.test?x=1", "https://issuer.example.test#",
    "https://user@issuer.example.test", "https://user:password@issuer.example.test",
    "https://issuer.example.test:99999", "https://issuer.example.test:0",
    "https://issuer.example.test:",
    "https://issuer.example.test\n", " https://issuer.example.test",
    "https://issuer.example.test\\@localhost", "https://%31%32%37.0.0.1",
    "https://issuer.example.test.", "https://bad_host.example.test", "https://-bad.example.test",
    "https://issuer.example.test/\ud800", None,
])
def test_issuer_url_rejects_ambiguous_local_or_non_https_addresses(url):
    assert_denied(lambda: binding(issuer_url=url))


def test_envelope_consumes_once_hides_token_and_releases_mutable_input():
    incoming = envelope()
    expected = incoming["assertion"]
    value = grant.JwtBearerGrant.from_mapping(incoming)
    assert incoming == {}
    incoming["assertion"] = "changed-after-capture"
    assert expected not in repr(value)
    assert value.consume_once() == expected
    assert value.assertion == ""
    assert_denied(value.consume_once)
    for raw in (json.dumps(envelope()), json.dumps(envelope()).encode()):
        assert grant.JwtBearerGrant.from_json(raw).consume_once() == expected


def test_consumption_is_one_shot_across_concurrent_callers():
    value = grant.JwtBearerGrant.from_mapping(envelope())

    def consume(_number):
        try:
            value.consume_once()
            return "consumed"
        except grant.JwtBearerGrantError:
            return "denied"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(consume, range(32)))
    assert results.count("consumed") == 1
    assert results.count("denied") == 31
    assert value.assertion == ""


@pytest.mark.parametrize("changes", [
    {"schema_version": "1"}, {"record_type": "other"}, {"grant_type": "authorization_code"},
    {"assertion": []}, {"assertion": None}, {"assertion": ""}, {"assertion": "not-a-jwt"},
    {"assertion": "a.b.c\n"}, {"assertion": "a.b.c.d"}, {"assertion": "a..c"},
    {"assertion": "a.b.="}, {"assertion": "a.b." + "x" * grant.MAX_GRANT_BYTES},
    {"extra": "not-allowed"}, {"extra": float("nan")},
])
def test_bad_envelopes_are_sanitized_and_input_is_cleared(changes):
    incoming = envelope()
    incoming.update(changes)
    assert_denied(lambda: grant.JwtBearerGrant.from_mapping(incoming))
    assert incoming == {}


@pytest.mark.parametrize("raw", [
    "[]", "null", "{}", "{", '{"schema_version":"2","schema_version":"2"}',
    '{"nested":{"same":1,"same":2}}', '{"n":NaN}', '{"n":Infinity}', '{"n":-Infinity}',
    '{"n":1e9999}', '{"x":' + '[' * 2000 + '0' + ']' * 2000 + '}',
    '{"x":"\ud800"}', b"\xff", "\ud800", b"\0", bytearray(b"{}"), 1,
    " " * grant.MAX_GRANT_BYTES + "{}",
])
def test_json_boundary_rejects_duplicates_nonfinite_depth_encoding_and_size(raw):
    assert_denied(lambda: grant.JwtBearerGrant.from_json(raw))


def test_duplicate_fields_reject_otherwise_valid_envelope_including_escaped_keys():
    raw = json.dumps(envelope())
    for duplicate in ('"schema_version":"2"', '"schema_versi\\u006fn":"2"'):
        assert_denied(lambda: grant.JwtBearerGrant.from_json(raw[:-1] + "," + duplicate + "}"))


def test_prefilter_returns_none_for_synthetic_signature_without_authentication_claim():
    assert grant.validate_claims(token(), binding(), NONCE, NOW) is None
    assert grant.validate_claims(token(signature=b"not-a-real-signature"), binding(), NONCE, NOW) is None
    assert grant.validate_claims(token(header={"alg": "RS256", "kid": "synthetic-key"}), binding(), NONCE, NOW) is None


@pytest.mark.parametrize("header", [
    {}, {"alg": "RS256"}, {"kid": "key"}, {"alg": "none", "kid": "key"},
    {"alg": "HS256", "kid": "key"}, {"alg": "ES256", "kid": "key"},
    {"alg": "RS256", "kid": ""}, {"alg": "RS256", "kid": []},
    {"alg": "RS256", "kid": "key", "typ": "at+jwt"},
    *[{"alg": "RS256", "kid": "key", key: value} for key, value in (
        ("jku", "https://untrusted.example.test"), ("jwk", {}),
        ("x5u", "https://untrusted.example.test"), ("x5c", []),
        ("crit", []), ("b64", False), ("extra", True),
    )],
])
def test_header_algorithm_and_key_source_are_closed(header):
    assert_denied(lambda: grant.validate_claims(token(header=header), binding(), NONCE, NOW))


@pytest.mark.parametrize("field", ["iss", "aud", "sub", "jti", "nonce", "iat", "exp", "auth_time"])
def test_every_required_claim_must_exist(field):
    payload = claims()
    del payload[field]
    assert_denied(lambda: grant.validate_claims(token(payload), binding(), NONCE, NOW))


@pytest.mark.parametrize("changes", [
    {"iss": "https://other.example.test"}, {"aud": "other-audience"},
    {"aud": ["synthetic:bootstrap-authority"]}, {"sub": ""}, {"sub": "\t"}, {"sub": []},
    {"jti": ""}, {"jti": {}}, {"nonce": "sha256:" + "c" * 64},
    {"nonce": "a" * 64}, {"nonce": "sha256:" + "A" * 64},
    {"iat": EPOCH + 1}, {"exp": EPOCH}, {"exp": EPOCH - 1}, {"exp": EPOCH + 901},
    {"auth_time": EPOCH + 1}, {"auth_time": EPOCH - 301},
    {"iat": EPOCH - 1, "auth_time": EPOCH},
    {"nbf": EPOCH + 1}, {"nbf": -1},
    {"sub": "bad\ud800"}, {"jti": "bad\nvalue"},
])
def test_claim_binding_and_time_failures_are_sanitized(changes):
    assert_denied(lambda: grant.validate_claims(token(claims(**changes)), binding(), NONCE, NOW))


@pytest.mark.parametrize("field", ["iat", "exp", "auth_time", "nbf"])
@pytest.mark.parametrize("value", [True, False, float(EPOCH), str(EPOCH), None, -1, 10**100])
def test_time_claims_are_bounded_integers_never_bool_float_or_strings(field, value):
    assert_denied(lambda: grant.validate_claims(token(claims(**{field: value})), binding(), NONCE, NOW))


def test_time_boundaries_and_independently_tightened_binding_limits():
    assert grant.validate_claims(token(claims(auth_time=EPOCH - 300, nbf=EPOCH)), binding(), NONCE, NOW) is None
    assert grant.validate_claims(token(claims(exp=EPOCH + 1)), binding(), NONCE, NOW) is None
    assert_denied(lambda: grant.validate_claims(token(), binding(max_assertion_lifetime_seconds=899), NONCE, NOW))
    assert_denied(lambda: grant.validate_claims(token(claims(auth_time=EPOCH - 300)), binding(max_auth_age_seconds=299), NONCE, NOW))
    assert_denied(lambda: grant.validate_claims(token(), binding(), NONCE, NOW.replace(tzinfo=None)))
    assert_denied(lambda: grant.validate_claims(token(), binding(), NONCE, "2026-09-14"))
    assert_denied(lambda: grant.validate_claims(token(), binding(), "caller-supplied-plain-nonce", NOW))
    assert_denied(lambda: grant.validate_claims(token(), {}, NONCE, NOW))
    # Subsecond time never truncates an expired assertion back into validity.
    assert_denied(lambda: grant.validate_claims(token(claims(exp=EPOCH + 1)), binding(), NONCE, NOW + timedelta(seconds=1, microseconds=1)))


def test_jwt_json_duplicates_deep_extensions_and_noncanonical_encoding_fail():
    original = token().split(".")
    for index, raw in (
        (0, b'{"alg":"RS256","alg":"RS256","kid":"key"}'),
        (1, json.dumps(claims()).encode()[:-1] + b',"aud":"synthetic:bootstrap-authority"}'),
        (1, json.dumps(claims()).encode()[:-1] + b',"extension":{"same":1,"same":1}}'),
        (1, json.dumps(claims()).encode()[:-1] + b',"extra":NaN}'),
        (1, json.dumps(claims()).encode()[:-1] + b',"extra":' + b'[' * 10 + b'0' + b']' * 10 + b'}'),
        (1, json.dumps(claims(extra=[0] * 513)).encode()),
        (1, json.dumps(claims()).encode()[:-1] + b',"extra":' + b'[0,' * 600 + b'0' + b']' * 600 + b'}'),
        (0, b'\xff'), (1, b'[]'),
    ):
        candidate = original.copy()
        candidate[index] = encoded(raw)
        assert_denied(lambda: grant.validate_claims(".".join(candidate), binding(), NONCE, NOW))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for index in range(3):
        candidate = original.copy()
        decoded = base64.urlsafe_b64decode(candidate[index] + "=" * (-len(candidate[index]) % 4))
        if len(decoded) % 3 == 0:
            decoded += b" "  # JSON whitespace; signature bytes remain deliberately synthetic.
        canonical = encoded(decoded)
        changed = canonical[:-1] + alphabet[alphabet.index(canonical[-1]) + 1]
        assert base64.urlsafe_b64decode(changed + "=" * (-len(changed) % 4)) == decoded
        candidate[index] = changed
        assert_denied(lambda: grant.validate_claims(".".join(candidate), binding(), NONCE, NOW))


def test_each_decoded_jwt_segment_has_its_own_size_limit():
    original = token().split(".")
    for index, oversized in (
        (0, b' ' * 1025), (1, b' ' * 8193), (2, bytes(1025)),
    ):
        candidate = original.copy()
        candidate[index] = encoded(oversized)
        assert_denied(lambda: grant.validate_claims(".".join(candidate), binding(), NONCE, NOW))
    # A token can fit its own byte bound while its complete envelope exceeds it.
    incoming = envelope("a.b." + "x" * (grant.MAX_GRANT_BYTES - 4))
    assert len(incoming["assertion"]) == grant.MAX_GRANT_BYTES
    assert_denied(lambda: grant.JwtBearerGrant.from_mapping(incoming))
    assert incoming == {}


@pytest.mark.parametrize("candidate", [
    "a.b.c", "a.b", "a.b.c.d", "a..c", "a.b.", "a.b.c\n", "a.b.c=", "a.b.c+", "a.b.c/",
    "a.b." + "x" * grant.MAX_GRANT_BYTES,
])
def test_jwt_segments_are_exact_and_bounded(candidate):
    assert_denied(lambda: grant.validate_claims(candidate, binding(), NONCE, NOW))


def test_operation_nonce_binds_each_operation_and_both_protected_digests():
    plan = grant.operation_binding_digest("plan", PLAN)
    approval = grant.operation_binding_digest("approval", PLAN, APPROVAL)
    apply = grant.operation_binding_digest("apply", PLAN, APPROVAL)
    assert len({plan, approval, apply}) == 3
    assert grant.operation_binding_digest("apply", APPROVAL, PLAN) != apply
    assert grant.operation_binding_digest("plan", APPROVAL) != plan
    assert grant.operation_binding_digest("apply", PLAN, "sha256:" + "c" * 64) != apply
    assert_denied(lambda: grant.validate_claims(token(), binding(), apply, NOW))
    expected = "sha256:" + hashlib.sha256(
        b"scanalyze.platform-authority.bootstrap.identity-operation.v2\x00"
        + json.dumps({"operation": "plan", "plan_digest": PLAN, "approval_digest": None}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert plan == expected


@pytest.mark.parametrize("operation,plan,approval", [
    ("approve", PLAN, APPROVAL), ("unknown", PLAN, None), (True, PLAN, None),
    ("plan", PLAN, APPROVAL), ("plan", PLAN, ""), ("plan", "a" * 64, None),
    ("plan", "sha256:" + "A" * 64, None), ("plan", PLAN + "\n", None),
    ("approval", PLAN, None), ("apply", PLAN, None), ("approval", PLAN, "b" * 64),
    ("apply", PLAN, True), ("apply", PLAN, APPROVAL + "\n"),
])
def test_operation_nonce_rejects_ambiguous_operations_and_digest_sources(operation, plan, approval):
    assert_denied(lambda: grant.operation_binding_digest(operation, plan, approval))
