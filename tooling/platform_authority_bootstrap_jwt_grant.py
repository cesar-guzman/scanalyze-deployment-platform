"""Bounded, noncryptographic JWT bearer prefilter for GUG-274.

Passing this module proves neither a signature nor a human identity. The broker
must independently bind the issuer configuration and operation nonce, exchange
the assertion with AWS Identity Center, and obtain the operation-specific STS
identity proof. This module performs no network, credential or filesystem I/O.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import hmac
import ipaddress
import json
import math
import re
from threading import Lock
from urllib.parse import urlsplit

from tooling.platform_authority_bootstrap import BootstrapAuthorizationError


JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
MAX_GRANT_BYTES = 12 * 1024
BINDING_DOMAIN = "scanalyze.platform-authority.bootstrap.jwt-bearer-binding.v2"
OPERATION_DOMAIN = "scanalyze.platform-authority.bootstrap.identity-operation.v2"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
GRANT_FIELDS = frozenset({"schema_version", "record_type", "grant_type", "assertion"})
INSTANCE = re.compile(r"arn:(aws|aws-us-gov|aws-cn):sso:::instance/(ssoins-[A-Za-z0-9]{16})")
# API reference: DescribeTrustedTokenIssuer request/response both require tti-.
# https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_DescribeTrustedTokenIssuer.html
TRUSTED_ISSUER = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):sso::([0-9]{12}):trustedTokenIssuer/"
    r"(ssoins-[A-Za-z0-9]{16})/tti-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
)


class JwtBearerGrantError(BootstrapAuthorizationError):
    """Sanitized denial; never includes input, parser or provider messages."""

    code = "BOOTSTRAP_IDENTITY_PROOF_DENIED"

    def __init__(self) -> None:
        super().__init__(self.code)


def _text(value: object, maximum: int) -> bool:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        return False
    try:
        return (
            len(value.encode("utf-8")) <= maximum
            and bool(value.strip())
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        )
    except UnicodeError:
        return False


def _digest(value: object) -> bool:
    return type(value) is str and DIGEST.fullmatch(value) is not None


def _canonical(value: dict) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise JwtBearerGrantError() from None
    if len(raw) > MAX_GRANT_BYTES:
        raise JwtBearerGrantError()
    return raw


def _domain_digest(domain: str, value: dict) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\x00" + _canonical(value)).hexdigest()


def _json_object(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise JwtBearerGrantError()
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise JwtBearerGrantError()

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise JwtBearerGrantError() from None
    if type(value) is not dict:
        raise JwtBearerGrantError()
    # Bound nested extensions too; claim extraction must not hide malformed data.
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 8 or count > 512:
            raise JwtBearerGrantError()
        if type(item) is dict:
            pending.extend((entry, depth + 1) for pair in item.items() for entry in pair)
        elif type(item) is list:
            pending.extend((entry, depth + 1) for entry in item)
        elif type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise JwtBearerGrantError() from None
        elif type(item) is float and not math.isfinite(item):
            raise JwtBearerGrantError()
    return value


def _issuer_url(value: object) -> bool:
    if not _text(value, 2048) or not value.isascii():
        return False
    if any(char in value for char in "?#\\") or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (
            not value.startswith("https://") or parsed.scheme != "https"
            or parsed.username is not None or parsed.password is not None
            or not host or parsed.port == 0 or parsed.netloc.endswith(":")
        ):
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return False
        labels = host.split(".")
        return (
            len(host) <= 253 and len(labels) >= 2
            and host != "localhost" and not host.endswith(".localhost")
            and any(char.isalpha() for char in labels[-1])
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
        )
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class JwtBearerBinding:
    """Runtime-owned, independently verified configuration, never a grant claim."""

    authority_account_id: str
    identity_center_instance_arn: str
    trusted_token_issuer_arn: str
    issuer_url: str
    audience: str
    max_assertion_lifetime_seconds: int = 900
    max_auth_age_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            type(self.authority_account_id) is not str
            or re.fullmatch(r"(?!000000000000)[0-9]{12}", self.authority_account_id) is None
            or type(self.identity_center_instance_arn) is not str
            or type(self.trusted_token_issuer_arn) is not str
        ):
            raise JwtBearerGrantError()
        instance = INSTANCE.fullmatch(self.identity_center_instance_arn)
        issuer = TRUSTED_ISSUER.fullmatch(self.trusted_token_issuer_arn)
        if (
            instance is None or issuer is None
            or instance[1] != issuer[1] or instance[2] != issuer[3]
            or issuer[2] != self.authority_account_id
            or not _issuer_url(self.issuer_url) or not _text(self.audience, 2048)
            or type(self.max_assertion_lifetime_seconds) is not int
            or not 1 <= self.max_assertion_lifetime_seconds <= 900
            or type(self.max_auth_age_seconds) is not int
            or not 1 <= self.max_auth_age_seconds <= 300
        ):
            raise JwtBearerGrantError()

    @property
    def digest(self) -> str:
        return _domain_digest(BINDING_DOMAIN, {
            "authority_account_id": self.authority_account_id,
            "identity_center_instance_arn": self.identity_center_instance_arn,
            "trusted_token_issuer_arn": self.trusted_token_issuer_arn,
            "issuer_url": self.issuer_url,
            "audience": self.audience,
            "max_assertion_lifetime_seconds": self.max_assertion_lifetime_seconds,
            "max_auth_age_seconds": self.max_auth_age_seconds,
        })


def _assertion(value: object) -> None:
    if type(value) is not str or not 5 <= len(value) <= MAX_GRANT_BYTES:
        raise JwtBearerGrantError()
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value) is None:
        raise JwtBearerGrantError()


@dataclass(slots=True)
class JwtBearerGrant:
    """One-shot RAM envelope; clearing references is not guaranteed memory erasure."""

    assertion: str = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: object = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        _assertion(self.assertion)

    @classmethod
    def from_json(cls, raw: object) -> "JwtBearerGrant":
        try:
            if type(raw) is str:
                raw = raw.encode("utf-8")
            if type(raw) is not bytes or not 2 <= len(raw) <= MAX_GRANT_BYTES:
                raise JwtBearerGrantError()
            return cls.from_mapping(_json_object(raw))
        except (UnicodeError, RecursionError):
            raise JwtBearerGrantError() from None

    @classmethod
    def from_mapping(cls, value: object) -> "JwtBearerGrant":
        if type(value) is not dict:
            raise JwtBearerGrantError()
        # Take the snapshot and release the caller's mutable references even on
        # denial; never retain the supplied mapping or trust its later mutation.
        snapshot = value.copy()
        value.clear()
        try:
            if any(type(key) is not str for key in snapshot) or set(snapshot) != GRANT_FIELDS:
                raise JwtBearerGrantError()
            if any(type(item) is not str for item in snapshot.values()):
                raise JwtBearerGrantError()
            if (
                snapshot["schema_version"] != "2"
                or snapshot["record_type"] != "platform_authority_bootstrap_identity_grant"
                or snapshot["grant_type"] != JWT_BEARER_GRANT
            ):
                raise JwtBearerGrantError()
            _canonical(snapshot)
            return cls(snapshot["assertion"])
        finally:
            snapshot.clear()

    def consume_once(self) -> str:
        with self._lock:
            if self._consumed:
                raise JwtBearerGrantError()
            self._consumed = True
            assertion = self.assertion
            self.assertion = ""
        _assertion(assertion)
        return assertion


def _decode_segment(segment: str, maximum: int) -> bytes:
    if not 1 <= len(segment) <= (maximum * 4 + 2) // 3:
        raise JwtBearerGrantError()
    try:
        raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
        if not raw or len(raw) > maximum or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
            raise JwtBearerGrantError()
        return raw
    except (ValueError, UnicodeError):
        raise JwtBearerGrantError() from None


def validate_claims(assertion: str, binding: JwtBearerBinding, expected_nonce: str, now: datetime) -> None:
    """Prefilter only: None is NOT cryptographic validation or authorization.

    The nonce must be recomputed from the broker's protected operation inputs.
    Zero clock skew deliberately rejects future issuance/authentication and an
    assertion at its exact expiration; operators must use synchronized clocks.
    Only successful AWS exchange plus the existing STS proof establishes identity.
    """
    _assertion(assertion)
    if type(binding) is not JwtBearerBinding or not _digest(expected_nonce):
        raise JwtBearerGrantError()
    try:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise JwtBearerGrantError()
        current = now.timestamp()
    except (ValueError, OverflowError, OSError):
        raise JwtBearerGrantError() from None
    header_segment, claims_segment, signature_segment = assertion.split(".")
    header = _json_object(_decode_segment(header_segment, 1024))
    claims = _json_object(_decode_segment(claims_segment, 8192))
    _decode_segment(signature_segment, 1024)  # Syntax/size only, never a signature check.
    if (
        set(header) not in ({"alg", "kid"}, {"alg", "kid", "typ"})
        or header.get("alg") != "RS256"
        or not _text(header.get("kid"), 256)
        or ("typ" in header and header["typ"] != "JWT")
    ):
        raise JwtBearerGrantError()
    if (
        claims.get("iss") != binding.issuer_url
        or type(claims.get("aud")) is not str or claims["aud"] != binding.audience
        or not _text(claims.get("sub"), 1024) or not _text(claims.get("jti"), 256)
        or not _digest(claims.get("nonce"))
        or not hmac.compare_digest(claims["nonce"], expected_nonce)
    ):
        raise JwtBearerGrantError()
    for key in ("iat", "exp", "auth_time") + (("nbf",) if "nbf" in claims else ()):
        if type(claims.get(key)) is not int or not 0 <= claims[key] <= 253402300799:
            raise JwtBearerGrantError()
    issued, expires, authenticated = claims["iat"], claims["exp"], claims["auth_time"]
    if (
        not authenticated <= issued <= current < expires
        or not 0 < expires - issued <= binding.max_assertion_lifetime_seconds
        or not 0 <= current - authenticated <= binding.max_auth_age_seconds
        or ("nbf" in claims and claims["nbf"] > current)
    ):
        raise JwtBearerGrantError()


def operation_binding_digest(operation: str, plan_digest: str, approval_digest: str | None = None) -> str:
    """Domain-separated operation nonce; inputs must come from protected records."""
    if type(operation) is not str or operation not in {"plan", "approval", "apply"} or not _digest(plan_digest):
        raise JwtBearerGrantError()
    if (operation == "plan" and approval_digest is not None) or (
        operation != "plan" and not _digest(approval_digest)
    ):
        raise JwtBearerGrantError()
    return _domain_digest(OPERATION_DOMAIN, {
        "operation": operation, "plan_digest": plan_digest, "approval_digest": approval_digest,
    })
