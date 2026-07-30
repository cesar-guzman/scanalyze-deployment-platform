"""One-shot Identity Center token and STS ProvidedContexts adapter.

The public API is capability-bound: raw tokens, context assertions, and AWS
credentials never appear in its return value. A caller must provide injected
SDK clients and a one-shot in-process consumer. Those injected implementations
are part of the trusted computing base and MUST NOT copy, retain, serialize, or
log secret material. Python cannot make an in-process object non-exportable, so
the adapter performs best-effort zeroization and makes that trust boundary
explicit. The pinned compatibility guard always runs before OAuth or STS and
cannot be supplied by a caller.

This module does not construct live SDK clients or browser authorization. The
current GUG-215 Lambda action is blocked by the STS-managed identity-context
allowlist, so the repository CLI intentionally exposes offline checks only.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse

from tooling.platform_authority_identity_context_compatibility import (
    BROKER_REQUIRED_ACTION,
    COMPATIBLE_REVIEWED_ACTION,
    CompatibilityDecision,
    bundled_compatibility_decision,
    canonical_digest,
)


AUTHORIZATION_CODE_GRANT = "authorization_code"
IDENTITY_CENTER_CONTEXT_PROVIDER_ARN = (
    "arn:aws:iam::aws:contextProvider/IdentityCenter"
)
REQUIRED_SCOPES = ("sts:identity_context",)
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
SESSION_NAME = re.compile(r"^gug216-[a-f0-9]{16}$")


class SessionBoundaryError(RuntimeError):
    """A sanitized fail-closed session boundary result."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code) else "SESSION_DENIED"
        super().__init__(self.code)


class SsoOidcClient(Protocol):
    def create_token_with_iam(self, **kwargs: Any) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]: ...


class SessionConsumer(Protocol):
    """Trusted one-shot capability consumer; retaining credentials is forbidden."""

    def consume(
        self,
        *,
        credentials: dict[str, Any],
        binding: "IdentityEnhancedBinding",
    ) -> None: ...


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise SessionBoundaryError("CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


@dataclass(frozen=True, slots=True)
class IdentityEnhancedBinding:
    authority_account_id: str
    region: str
    identity_center_application_arn: str
    identity_center_instance_arn: str
    identity_store_arn: str
    role_kind: str
    expected_user_id: str = field(repr=False)
    peer_user_id: str = field(repr=False)
    source_role_arn: str
    target_role_arn: str
    broker_alias: str
    required_action: str
    role_duration_seconds: int = 900
    max_token_lifetime_seconds: int = 3600

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise SessionBoundaryError("ACCOUNT_BINDING_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise SessionBoundaryError("REGION_BINDING_INVALID")
        if self.required_action != BROKER_REQUIRED_ACTION:
            raise SessionBoundaryError("CAPABILITY_BINDING_INVALID")
        if self.role_kind not in {"classifier", "approver"}:
            raise SessionBoundaryError("ROLE_KIND_INVALID")
        if (
            USER_ID.fullmatch(self.expected_user_id) is None
            or USER_ID.fullmatch(self.peer_user_id) is None
        ):
            raise SessionBoundaryError("IDENTITY_STORE_USER_INVALID")
        if self.expected_user_id.lower() == self.peer_user_id.lower():
            raise SessionBoundaryError("INDEPENDENT_OPERATOR_REQUIRED")
        partition = _partition(self.region)
        application = re.fullmatch(
            rf"arn:{partition}:sso::([0-9]{{12}}):application/"
            r"(ssoins-[A-Za-z0-9]{16})/(apl-[A-Za-z0-9]{16})",
            self.identity_center_application_arn,
        )
        instance = re.fullmatch(
            rf"arn:{partition}:sso:::instance/(ssoins-[A-Za-z0-9]{{16}})",
            self.identity_center_instance_arn,
        )
        store = re.fullmatch(
            rf"arn:{partition}:identitystore::([0-9]{{12}}):identitystore/"
            r"(d-[a-z0-9]{10,})",
            self.identity_store_arn,
        )
        if application is None or instance is None or store is None:
            raise SessionBoundaryError("IDENTITY_CENTER_TOPOLOGY_INVALID")
        if application.group(1) != store.group(1) or application.group(2) != instance.group(1):
            raise SessionBoundaryError("IDENTITY_CENTER_TOPOLOGY_MISMATCH")
        expected_source_name = (
            "ScanalyzeAuthorityRetireClass"
            if self.role_kind == "classifier"
            else "ScanalyzeAuthorityRetireApprove"
        )
        expected_target_name = (
            "ScanalyzeGug215ClassifierInvoker"
            if self.role_kind == "classifier"
            else "ScanalyzeGug215ApproverInvoker"
        )
        expected_aliases = {"classify"} if self.role_kind == "classifier" else {"retire", "reconcile"}
        source_pattern = re.compile(
            rf"arn:{partition}:iam::{self.authority_account_id}:role/"
            r"aws-reserved/sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
            rf"AWSReservedSSO_{expected_source_name}_[0-9A-Fa-f]{{16}}"
        )
        if source_pattern.fullmatch(self.source_role_arn) is None:
            raise SessionBoundaryError("SOURCE_ROLE_BINDING_INVALID")
        if self.target_role_arn != (
            f"arn:{partition}:iam::{self.authority_account_id}:role/{expected_target_name}"
        ):
            raise SessionBoundaryError("TARGET_ROLE_BINDING_INVALID")
        if self.broker_alias not in expected_aliases:
            raise SessionBoundaryError("BROKER_ALIAS_BINDING_INVALID")
        if self.role_duration_seconds != 900:
            raise SessionBoundaryError("ROLE_DURATION_INVALID")
        if not 60 <= self.max_token_lifetime_seconds <= 3600:
            raise SessionBoundaryError("TOKEN_LIFETIME_BOUND_INVALID")

    @property
    def binding_digest(self) -> str:
        return canonical_digest(
            {
                "authority_account_id": self.authority_account_id,
                "region": self.region,
                "identity_center_application_arn": self.identity_center_application_arn,
                "identity_center_instance_arn": self.identity_center_instance_arn,
                "identity_store_arn": self.identity_store_arn,
                "role_kind": self.role_kind,
                "expected_user_id": self.expected_user_id,
                "peer_user_id": self.peer_user_id,
                "source_role_arn": self.source_role_arn,
                "target_role_arn": self.target_role_arn,
                "broker_alias": self.broker_alias,
                "required_action": self.required_action,
                "role_duration_seconds": self.role_duration_seconds,
                "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            }
        )


@dataclass(slots=True)
class AuthorizationCodeGrant:
    code: str = field(repr=False)
    code_verifier: str = field(repr=False)
    redirect_uri: str
    issued_at: datetime
    expires_at: datetime
    _consumed: bool = field(default=False, init=False, repr=False)

    def _validate(self, *, now: datetime) -> None:
        if now.tzinfo is None or self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise SessionBoundaryError("CLOCK_INVALID")
        now_utc = now.astimezone(UTC)
        issued = self.issued_at.astimezone(UTC)
        expires = self.expires_at.astimezone(UTC)
        if expires <= issued or expires - issued > timedelta(minutes=5):
            raise SessionBoundaryError("AUTHORIZATION_CODE_LIFETIME_INVALID")
        if now_utc < issued - timedelta(seconds=30) or now_utc >= expires:
            raise SessionBoundaryError("AUTHORIZATION_CODE_EXPIRED")
        if not isinstance(self.code, str) or not 8 <= len(self.code) <= 4096 or self.code.isspace():
            raise SessionBoundaryError("AUTHORIZATION_CODE_MALFORMED")
        if PKCE_VERIFIER.fullmatch(self.code_verifier) is None:
            raise SessionBoundaryError("PKCE_VERIFIER_MALFORMED")
        parsed = urlparse(self.redirect_uri)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.path != "/callback"
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
        ):
            raise SessionBoundaryError("REDIRECT_URI_INVALID")

    def consume_once(self, *, now: datetime) -> tuple[str, str, str]:
        if self._consumed:
            raise SessionBoundaryError("AUTHORIZATION_CODE_REPLAY")
        self._validate(now=now)
        code = self.code
        verifier = self.code_verifier
        redirect = self.redirect_uri
        self._consumed = True
        self.code = ""
        self.code_verifier = ""
        return code, verifier, redirect


@dataclass(frozen=True, slots=True)
class IdentityEnhancedSessionReceipt:
    status: str
    binding_digest: str
    policy_version: str
    policy_digest: str
    required_action: str
    role_kind: str
    broker_alias: str
    expected_user_id_digest: str
    source_role_arn_digest: str
    target_role_arn_digest: str
    expires_at: str
    token_issued: bool = True
    sts_session_issued: bool = True
    session_consumed: bool = True
    broker_invocation_performed: bool = False
    live_retirement_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_identity_enhanced_session_receipt",
            "environment": "non-production",
            "production": False,
            "status": self.status,
            "binding_digest": self.binding_digest,
            "managed_policy_version": self.policy_version,
            "managed_policy_digest": self.policy_digest,
            "required_action": self.required_action,
            "role_kind": self.role_kind,
            "broker_alias": self.broker_alias,
            "expected_user_id_digest": self.expected_user_id_digest,
            "source_role_arn_digest": self.source_role_arn_digest,
            "target_role_arn_digest": self.target_role_arn_digest,
            "expires_at": self.expires_at,
            "token_issued": self.token_issued,
            "sts_session_issued": self.sts_session_issued,
            "session_consumed": self.session_consumed,
            "broker_invocation_performed": self.broker_invocation_performed,
            "live_retirement_authorized": self.live_retirement_authorized,
        }
        value["receipt_digest"] = canonical_digest(value)
        return value


class IdentityEnhancedSessionAdapter:
    """Exchange one code and consume one identity-enhanced session in memory."""

    def __init__(self, *, oidc_client: SsoOidcClient, sts_client: StsClient) -> None:
        self._oidc = oidc_client
        self._sts = sts_client

    def establish_for_capability(
        self,
        *,
        binding: IdentityEnhancedBinding,
        grant: AuthorizationCodeGrant,
        consumer: SessionConsumer,
        now: datetime,
    ) -> IdentityEnhancedSessionReceipt:
        compatibility: CompatibilityDecision = bundled_compatibility_decision()
        if compatibility.required_action != binding.required_action:
            raise SessionBoundaryError("COMPATIBILITY_BINDING_MISMATCH")
        if compatibility.status != COMPATIBLE_REVIEWED_ACTION:
            raise SessionBoundaryError(compatibility.status)
        code, verifier, redirect = grant.consume_once(now=now)
        try:
            try:
                token_response = self._oidc.create_token_with_iam(
                    clientId=binding.identity_center_application_arn,
                    grantType=AUTHORIZATION_CODE_GRANT,
                    code=code,
                    codeVerifier=verifier,
                    redirectUri=redirect,
                    scope=list(REQUIRED_SCOPES),
                )
            except Exception:
                raise SessionBoundaryError("OIDC_EXCHANGE_UNCERTAIN") from None
        finally:
            code = ""
            verifier = ""
        try:
            context_assertion = self._validate_token_response(
                token_response,
                max_lifetime=binding.max_token_lifetime_seconds,
            )
        finally:
            if isinstance(token_response, dict):
                details = token_response.get("awsAdditionalDetails")
                if isinstance(details, dict):
                    details.clear()
                token_response.clear()
        session_name = "gug216-" + secrets.token_hex(8)
        if SESSION_NAME.fullmatch(session_name) is None:  # defensive invariant
            raise SessionBoundaryError("SESSION_NAME_INVALID")
        try:
            try:
                sts_response = self._sts.assume_role(
                    RoleArn=binding.target_role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=binding.role_duration_seconds,
                    ProvidedContexts=[
                        {
                            "ProviderArn": IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
                            "ContextAssertion": context_assertion,
                        }
                    ],
                )
            except Exception:
                raise SessionBoundaryError("STS_EXCHANGE_UNCERTAIN") from None
        finally:
            context_assertion = ""
        try:
            credentials, expiration = self._validate_sts_response(
                sts_response,
                binding=binding,
                now=now,
            )
        finally:
            if isinstance(sts_response, dict):
                raw_credentials = sts_response.get("Credentials")
                if isinstance(raw_credentials, dict):
                    raw_credentials.clear()
                sts_response.clear()
        try:
            consumer.consume(credentials=credentials, binding=binding)
        except Exception:
            raise SessionBoundaryError("SESSION_CONSUMER_UNCERTAIN") from None
        finally:
            credentials.clear()
        return IdentityEnhancedSessionReceipt(
            status="IDENTITY_ENHANCED_SESSION_CONSUMED",
            binding_digest=binding.binding_digest,
            policy_version=compatibility.policy_version,
            policy_digest=compatibility.policy_digest,
            required_action=binding.required_action,
            role_kind=binding.role_kind,
            broker_alias=binding.broker_alias,
            expected_user_id_digest=_digest("identity_store_user_id", binding.expected_user_id),
            source_role_arn_digest=_digest("source_role_arn", binding.source_role_arn),
            target_role_arn_digest=_digest("target_role_arn", binding.target_role_arn),
            expires_at=_iso(expiration),
        )

    @staticmethod
    def _validate_token_response(
        response: Mapping[str, Any],
        *,
        max_lifetime: int,
    ) -> str:
        if not isinstance(response, Mapping):
            raise SessionBoundaryError("OIDC_RESPONSE_MALFORMED")
        if response.get("refreshToken"):
            raise SessionBoundaryError("OIDC_REFRESH_TOKEN_FORBIDDEN")
        if response.get("tokenType") != "Bearer":
            raise SessionBoundaryError("OIDC_TOKEN_TYPE_MISMATCH")
        if response.get("scope") != list(REQUIRED_SCOPES):
            raise SessionBoundaryError("OIDC_SCOPE_MISMATCH")
        expires_in = response.get("expiresIn")
        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 60 <= expires_in <= max_lifetime
        ):
            raise SessionBoundaryError("OIDC_TOKEN_LIFETIME_INVALID")
        access_token = response.get("accessToken")
        if not isinstance(access_token, str) or not 4 <= len(access_token) <= 16384:
            raise SessionBoundaryError("OIDC_ACCESS_TOKEN_MALFORMED")
        details = response.get("awsAdditionalDetails")
        if not isinstance(details, Mapping):
            raise SessionBoundaryError("IDENTITY_CONTEXT_MISSING")
        assertion = details.get("identityContext")
        if not isinstance(assertion, str) or not 4 <= len(assertion) <= 4096:
            if assertion is None:
                raise SessionBoundaryError("IDENTITY_CONTEXT_MISSING")
            raise SessionBoundaryError("IDENTITY_CONTEXT_MALFORMED")
        return assertion

    @staticmethod
    def _validate_sts_response(
        response: Mapping[str, Any],
        *,
        binding: IdentityEnhancedBinding,
        now: datetime,
    ) -> tuple[dict[str, Any], datetime]:
        if not isinstance(response, Mapping):
            raise SessionBoundaryError("STS_RESPONSE_MALFORMED")
        assumed = response.get("AssumedRoleUser")
        arn = assumed.get("Arn") if isinstance(assumed, Mapping) else None
        expected_role = binding.target_role_arn.rsplit("/", 1)[-1]
        expected_pattern = re.compile(
            rf"arn:{_partition(binding.region)}:sts::{binding.authority_account_id}:"
            rf"assumed-role/{re.escape(expected_role)}/gug216-[a-f0-9]{{16}}"
        )
        if not isinstance(arn, str) or expected_pattern.fullmatch(arn) is None:
            raise SessionBoundaryError("STS_ASSUMED_ROLE_MISMATCH")
        raw_credentials = response.get("Credentials")
        if not isinstance(raw_credentials, Mapping) or set(raw_credentials) != {
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
        }:
            raise SessionBoundaryError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
            value = raw_credentials.get(key)
            if not isinstance(value, str) or not value:
                raise SessionBoundaryError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        expiration = raw_credentials.get("Expiration")
        if now.tzinfo is None or not isinstance(expiration, datetime) or expiration.tzinfo is None:
            raise SessionBoundaryError("STS_EXPIRATION_INVALID")
        now_utc = now.astimezone(UTC)
        expiration_utc = expiration.astimezone(UTC)
        if not now_utc < expiration_utc <= now_utc + timedelta(
            seconds=binding.role_duration_seconds
        ):
            raise SessionBoundaryError("STS_EXPIRATION_INVALID")
        credentials = dict(raw_credentials)
        if isinstance(raw_credentials, dict):
            raw_credentials.clear()
        if isinstance(response, dict):
            response.clear()
        return credentials, expiration_utc
