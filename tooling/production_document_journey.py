"""Explicit production journey; importing makes no network or input reads.

The existing DEV/STAGING CLI and its configuration admission remain unchanged.
This entrypoint adds production admission around the same document protocol.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jsonschema import Draft202012Validator, FormatChecker

from tooling import document_journey_smoke as smoke
from tooling import release_policy_gate as release_gate

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://prod.scanalyze.cloud"
TOKEN_ENV = "SCANALYZE_PRODUCTION_SMOKE_ACCESS_TOKEN"
MAX_INPUT_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
_AUTHORITY_FIELDS = frozenset({
    "schema_version", "operation_id", "issued_at", "expires_at", "deployment_observed_at",
    "deployment_readback_digest", "environment", "api_origin", "processing_domain",
    "customer_id", "deployment_id", "account_id", "region", "subject_id",
    "issuer_url", "spa_client_id", "upload_host", "release_manifest_digest", "release_version",
    "release_sha256", "attestation_sha256", "trust_policy_sha256", "trust_policy_digest",
    "jwks_sha256", "runtime_config_sha256", "driver_source_commit", "synthetic_pdf_sha256",
    "timeout_seconds", "poll_interval_seconds", "max_requests", "evidence_path",
})


class JourneyError(smoke.SmokeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: Any, code: str) -> None:
    if not condition:
        raise JourneyError(code)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json(raw: bytes, maximum: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= maximum, "INPUT_SIZE_INVALID")
    try:
        return smoke._json(raw)
    except Exception:
        raise JourneyError("INPUT_JSON_INVALID") from None


def _cli_support():
    # Only definitions are loaded. Source verification / private I/O occur when
    # explicitly invoked; the legacy CLI's main is never called.
    spec = importlib.util.spec_from_file_location(
        "production_journey_private_io", ROOT / "scripts/validation/document-journey-smoke.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_private(path: Path, support) -> bytes:
    parent = support._private_parent(path)
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                 "INPUT_CUSTODY_INVALID")
        _require(0 < before.st_size <= MAX_INPUT_BYTES, "INPUT_SIZE_INVALID")
        chunks = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        _require(len(raw) == before.st_size and
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                  before.st_nlink, before.st_uid, before.st_mode)
                 == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                     after.st_nlink, after.st_uid, after.st_mode),
                 "INPUT_CHANGED_DURING_READ")
        _json(raw)
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _now(clock: Callable[[], datetime]) -> float:
    current = clock()
    _require(isinstance(current, datetime) and current.tzinfo is not None
             and current.utcoffset() is not None, "CLOCK_INVALID")
    return current.timestamp()


def _fresh(authority: dict[str, Any], now: float) -> None:
    _require(authority["deployment_observed_at"] <= authority["issued_at"] <= now < authority["expires_at"]
             and 0 <= now - authority["deployment_observed_at"] <= 300, "AUTHORITY_EXPIRED")


def _admit(authority_bytes: bytes, expected_authority_digest: str, release_bytes: bytes,
           attestation_bytes: bytes, trust_policy_bytes: bytes, jwks_bytes: bytes,
           receipt_path: Path, source_commit: str, now: float):
    _require(type(expected_authority_digest) is str and _DIGEST.fullmatch(expected_authority_digest)
             and _sha(authority_bytes) == expected_authority_digest, "AUTHORITY_PIN_MISMATCH")
    authority = _json(authority_bytes, 16_384)
    _require(set(authority) == _AUTHORITY_FIELDS, "AUTHORITY_FIELDS_INVALID")
    _require(authority["schema_version"] == "production-document-journey-authority.v1"
             and authority["environment"] == "production" and authority["api_origin"] == ORIGIN
             and authority["processing_domain"] == "bank" and authority["region"] == "us-east-1"
             and authority["account_id"] == "905418363887", "TARGET_NOT_ALLOWED")
    patterns = {
        "operation_id": r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        "customer_id": r"cust_[0-9A-HJKMNP-TV-Z]{26}", "deployment_id": r"dep_[0-9A-HJKMNP-TV-Z]{26}",
        "subject_id": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "spa_client_id": r"[A-Za-z0-9]{1,128}",
        "issuer_url": r"https://cognito-idp\.us-east-1\.amazonaws\.com/us-east-1_[A-Za-z0-9]+",
        "upload_host": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.us-east-1\.amazonaws\.com",
        "driver_source_commit": r"[0-9a-f]{40}",
    }
    for field, pattern in patterns.items():
        _require(type(authority[field]) is str and re.fullmatch(pattern, authority[field]), "AUTHORITY_VALUE_INVALID")
    for field in _AUTHORITY_FIELDS:
        if field.endswith(("_digest", "_sha256")):
            _require(type(authority[field]) is str and _DIGEST.fullmatch(authority[field]), "AUTHORITY_VALUE_INVALID")
    for field in ("issued_at", "expires_at", "deployment_observed_at"):
        _require(type(authority[field]) is int and authority[field] > 0, "AUTHORITY_VALUE_INVALID")
    _require(0 < authority["expires_at"] - authority["issued_at"] <= 900, "AUTHORITY_VALUE_INVALID")
    for field, lower, upper in (("timeout_seconds", 30, 240), ("poll_interval_seconds", 1, 30), ("max_requests", 14, 256)):
        _require(type(authority[field]) is int and lower <= authority[field] <= upper, "BUDGET_INVALID")
    _require(authority["driver_source_commit"] == source_commit, "SOURCE_COMMIT_MISMATCH")
    _require(type(authority["evidence_path"]) is str and Path(authority["evidence_path"]) == receipt_path
             and receipt_path.name == authority["operation_id"] + ".jsonl", "EVIDENCE_PATH_MISMATCH")
    _require(authority["synthetic_pdf_sha256"] == _sha(smoke.synthetic_pdf()), "SYNTHETIC_DOCUMENT_MISMATCH")
    for field, raw in (("release_sha256", release_bytes), ("attestation_sha256", attestation_bytes),
                       ("trust_policy_sha256", trust_policy_bytes), ("jwks_sha256", jwks_bytes)):
        _require(_sha(raw) == authority[field], "INPUT_PIN_MISMATCH")
    manifest, attestation, policy, jwks = map(_json, (release_bytes, attestation_bytes, trust_policy_bytes, jwks_bytes))
    decision = release_gate.evaluate_release(manifest, attestation, policy,
        expected_policy_digest=authority["trust_policy_digest"], evaluated_at=datetime.fromtimestamp(now, timezone.utc))
    _require(decision.allowed and decision.manifest_digest == authority["release_manifest_digest"]
             and manifest["release_version"] == authority["release_version"], "RELEASE_NOT_APPROVED")
    _require(set(jwks) == {"keys"} and type(jwks["keys"]) is list and 1 <= len(jwks["keys"]) <= 5,
             "JWKS_INVALID")
    keys = {}
    for jwk in jwks["keys"]:
        _require(type(jwk) is dict and set(jwk) == {"kid", "kty", "alg", "use", "n", "e"}
                 and jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["use"] == "sig"
                 and type(jwk["kid"]) is str and 1 <= len(jwk["kid"]) <= 256 and jwk["kid"] not in keys,
                 "JWKS_INVALID")
        modulus, exponent = _base64(jwk["n"], 512), _base64(jwk["e"], 8)
        _require(modulus[0] != 0 and exponent[0] != 0, "JWKS_INVALID")
        public = rsa.RSAPublicNumbers(int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")).public_key()
        _require(2048 <= public.key_size <= 4096, "JWKS_INVALID")
        keys[jwk["kid"]] = public
    _fresh(authority, now)
    return authority, manifest, attestation, policy, keys


def _base64(value: Any, maximum: int = 16_384) -> bytes:
    _require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
             and re.fullmatch(r"[A-Za-z0-9_-]+", value), "TOKEN_INVALID")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    _require(0 < len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == value, "TOKEN_INVALID")
    return raw


def _verify_token(token: str, authority: dict[str, Any], keys: dict[str, Any], now: float) -> dict[str, Any]:
    try:
        _require(type(token) is str and 16 <= len(token) <= 16_384, "TOKEN_INVALID")
        parts = token.split(".")
        _require(len(parts) == 3, "TOKEN_INVALID")
        header, claims = _json(_base64(parts[0])), _json(_base64(parts[1]))
        _require(set(header) <= {"alg", "kid", "typ"} and header.get("alg") == "RS256"
                 and header.get("typ", "JWT") == "JWT" and type(header.get("kid")) is str
                 and header["kid"] in keys, "TOKEN_INVALID")
        keys[header["kid"]].verify(_base64(parts[2], 512), (parts[0] + "." + parts[1]).encode("ascii"),
                                   padding.PKCS1v15(), hashes.SHA256())
        for field in ("exp", "iat", "auth_time"):
            _require(type(claims.get(field)) is int, "TOKEN_INVALID")
        _require(0 <= claims["auth_time"] <= claims["iat"] <= now < claims["exp"]
                 and now - claims["iat"] < 300, "TOKEN_EXPIRED")
        _require("nbf" not in claims or type(claims["nbf"]) is int and claims["nbf"] <= now, "TOKEN_INVALID")
        expected = {"token_use": "access", "iss": authority["issuer_url"], "client_id": authority["spa_client_id"],
                    "sub": authority["subject_id"], "custom:customerId": authority["customer_id"],
                    "custom:deployment_id": authority["deployment_id"], "principal_type": "user", "membership_state": "active"}
        _require(all(claims.get(key) == value for key, value in expected.items()), "TOKEN_BINDING_MISMATCH")
        _require(type(claims.get("membership_version")) is str
                 and re.fullmatch(r"[1-9][0-9]*", claims["membership_version"]), "TOKEN_BINDING_MISMATCH")
        scopes = claims.get("scope")
        _require(type(scopes) is str and len(scopes) <= 4096
                 and {"scanalyze.api.v1/read", "scanalyze.api.v1/write"} <= set(scopes.split()), "TOKEN_SCOPE_MISSING")
        return claims
    except JourneyError:
        raise
    except Exception:
        raise JourneyError("TOKEN_INVALID") from None


class _BoundTransport:
    def __init__(self, client, authority, token, keys, clock, utcnow, journal, release_check):
        self.client, self.authority, self.token, self.keys = client, authority, token, keys
        self.clock, self.utcnow, self.journal = clock, utcnow, journal
        self.release_check = release_check
        self.start = self.previous_monotonic = clock()
        self.previous_utc = _now(utcnow)
        self.requests = 0
        self.schema = _json((ROOT / "schemas/frontend-config.v3.schema.json").read_bytes())

    def check(self):
        now, tick = _now(self.utcnow), self.clock()
        _require(now >= self.previous_utc and tick >= self.previous_monotonic, "CLOCK_REVERSED")
        self.previous_utc, self.previous_monotonic = now, tick
        _fresh(self.authority, now)
        claims = _verify_token(self.token, self.authority, self.keys, now)
        self.release_check(now)
        remaining = self.authority["timeout_seconds"] - (tick - self.start)
        _require(remaining > 0, "TIME_BUDGET_EXHAUSTED")
        return remaining, claims

    def call(self, method, url, headers, body, timeout, phase):
        remaining, _ = self.check()
        _require(self.requests < self.authority["max_requests"], "REQUEST_BUDGET_EXHAUSTED")
        self.requests += 1
        try:
            self.journal.append({"event": "BEFORE_HTTP", "phase": phase, "requests": self.requests})
        except Exception:
            raise JourneyError("JOURNAL_WRITE_FAILED") from None
        # A durable write can block. Admission must still be current when the
        # network effect begins, not only before the journal's fsync.
        remaining, _ = self.check()
        try:
            response = self.client.request(method, url, dict(headers), body, min(timeout, remaining, 30.0))
        except Exception:
            raise JourneyError("REQUEST_OUTCOME_UNKNOWN") from None
        self.check()
        return response

    def probe(self):
        response = self.call("GET", ORIGIN + "/config.json", {"Accept": "application/json"}, None, 30.0, "CONFIG")
        _require(response.status == 200 and type(response.body) is bytes and len(response.body) <= 65_536
                 and _sha(response.body) == self.authority["runtime_config_sha256"], "RUNTIME_CONFIG_MISMATCH")
        media = next((v for k, v in response.headers.items() if k.lower() == "content-type"), "")
        _require(media.split(";", 1)[0].strip().lower() == "application/json", "RUNTIME_CONFIG_MISMATCH")
        config = _json(response.body, 65_536)
        _require(next(Draft202012Validator(self.schema, format_checker=FormatChecker()).iter_errors(config), None) is None,
                 "RUNTIME_CONFIG_MISMATCH")
        for field in ("customer_id", "deployment_id", "account_id", "region", "environment"):
            _require(config[field] == self.authority[field], "RUNTIME_CONFIG_MISMATCH")
        cognito = config["cognito"]
        _require(config["config_version"] == self.authority["release_version"] and config["api_endpoint"] == ORIGIN + "/api"
                 and cognito["issuer_url"] == self.authority["issuer_url"]
                 and cognito["user_pool_id"] == self.authority["issuer_url"].rsplit("/", 1)[1]
                 and cognito["spa_client_id"] == self.authority["spa_client_id"] and cognito["region"] == "us-east-1"
                 and cognito["redirect_uri"] == ORIGIN + "/callback"
                 and cognito["post_logout_redirect_uri"] == ORIGIN + "/", "RUNTIME_CONFIG_MISMATCH")
        _, claims = self.check()
        _require(claims.get("policy_digest") == config["authorization"]["policy_digest"]
                 and claims.get("policy_version") == config["authorization"]["policy_version"], "TOKEN_POLICY_MISMATCH")

    def request(self, method, url, headers, body, timeout):
        parsed = smoke._url(url)
        is_api = url.startswith(ORIGIN + "/api/v2/") and parsed.hostname == "prod.scanalyze.cloud" and not parsed.query
        is_upload = (method == "PUT" and parsed.hostname == self.authority["upload_host"]
                     and bool(parsed.path) and bool(parsed.query) and dict(headers) == {"Content-Type": "application/pdf"}
                     and body == smoke.synthetic_pdf())
        _require(is_api or is_upload, "REQUEST_TARGET_MISMATCH")
        if is_api:
            _require(headers.get("Authorization") == "Bearer " + self.token, "TOKEN_BINDING_MISMATCH")
        self.probe()
        return self.call(method, url, headers, body, timeout, "API" if is_api else "UPLOAD")


def run_journey(*, authority_bytes: bytes, expected_authority_digest: str,
                release_bytes: bytes, attestation_bytes: bytes, trust_policy_bytes: bytes, jwks_bytes: bytes,
                receipt_path: Path, source_commit: str, access_token: str, client,
                utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
    """Run exactly one journaled intent; dependency injection is not live evidence."""
    journal = None
    try:
        authority, manifest, attestation, policy, keys = _admit(
            authority_bytes, expected_authority_digest, release_bytes, attestation_bytes, trust_policy_bytes,
            jwks_bytes, receipt_path, source_commit, _now(utcnow))
        _verify_token(access_token, authority, keys, _now(utcnow))
        support = _cli_support()
        journal = support.Journal(receipt_path)
        journal.append({"event": "PRODUCTION_JOURNEY_STARTED", "authority_sha256": expected_authority_digest,
                        "release_manifest_digest": authority["release_manifest_digest"], "source_commit": source_commit})
        def release_current(now):
            decision = release_gate.evaluate_release(manifest, attestation, policy,
                expected_policy_digest=authority["trust_policy_digest"],
                evaluated_at=datetime.fromtimestamp(now, timezone.utc))
            _require(decision.allowed, "RELEASE_NOT_APPROVED")

        transport = _BoundTransport(client, authority, access_token, keys, clock, utcnow, journal, release_current)
        transport.probe()
        # Construct only after the distinct production admission above. No DEV
        # config is relabeled and the legacy CLI's from_dict gate is untouched.
        config = smoke.SmokeConfig(environment="production", api_origin=ORIGIN,
            upload_host=authority["upload_host"], deployment_id=authority["deployment_id"],
            authorization_reference=authority["operation_id"], timeout_seconds=authority["timeout_seconds"],
            poll_interval_seconds=authority["poll_interval_seconds"], max_requests=authority["max_requests"])
        result = support._summary(smoke.run_smoke(config, access_token, transport,
            on_progress=journal.progress, on_recovery=journal.recovery, clock=clock, sleep=sleep, utcnow=utcnow))
        transport.probe()
        release_current(_now(utcnow))
        summary = {**result, "status": "JOURNEY_CHECKS_PASSED", "schema_version": "production-document-journey-observation.v1",
                   "production_readiness": "NOT_ESTABLISHED", "authority_sha256": expected_authority_digest,
                   "release_manifest_digest": authority["release_manifest_digest"], "total_http_requests": transport.requests,
                   "deployment_readback_digest": authority["deployment_readback_digest"]}
        journal.append({"event": "SUMMARY", **summary})
        journal.close()
        return summary
    except (Exception, KeyboardInterrupt) as error:
        candidate = getattr(error, "code", None)
        code = candidate if type(candidate) is str and _CODE.fullmatch(candidate) else "PRODUCTION_JOURNEY_FAILED"
        if isinstance(error, KeyboardInterrupt):
            code = "JOURNEY_INTERRUPTED"
        if journal is not None and journal.descriptor >= 0 and not journal.broken:
            try:
                journal.append({"event": "FAILED", "code": code})
            except Exception:
                pass
        raise JourneyError(code) from None
    finally:
        if journal is not None:
            try:
                journal.close()
            except OSError:
                pass


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise JourneyError("CLI_ARGUMENTS_INVALID")


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _Parser(description=__doc__)
        for field in ("authority", "release", "attestation", "trust-policy", "jwks", "receipt"):
            parser.add_argument("--" + field, required=True, type=Path)
        parser.add_argument("--expected-authority-digest", required=True)
        parser.add_argument("--authorize-application-writes", action="store_true")
        args = parser.parse_args(argv)
        _require(args.authorize_application_writes, "APPLICATION_WRITE_AUTHORIZATION_REQUIRED")
        support = _cli_support()
        source_commit = support._verify_source()
        inputs = {name + "_bytes": _read_private(getattr(args, name), support)
                  for name in ("authority", "release", "attestation", "trust_policy", "jwks")}
        _admit(**inputs, expected_authority_digest=args.expected_authority_digest,
               receipt_path=args.receipt, source_commit=source_commit, now=_now(lambda: datetime.now(timezone.utc)))
        token = os.environ.get(TOKEN_ENV)
        _require(token is not None, "ACCESS_TOKEN_REQUIRED")
        summary = run_journey(**inputs, expected_authority_digest=args.expected_authority_digest,
            receipt_path=args.receipt, source_commit=source_commit, access_token=token, client=smoke.HttpsTransport())
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        candidate = getattr(error, "code", None)
        code = candidate if type(candidate) is str and _CODE.fullmatch(candidate) else "PRODUCTION_JOURNEY_FAILED"
        print(code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
