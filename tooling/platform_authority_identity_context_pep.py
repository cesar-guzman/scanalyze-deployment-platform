"""Proof-only Identity Center boundary for the GUG-215 retirement PEP.

An ordinary, duty-scoped invoker reaches one synchronous Lambda Function URL.
The request carries only a one-shot OAuth authorization-code grant.  The
version-pinned broker exchanges that code, passes the opaque Identity Center
context assertion to STS, and proves the exact immutable user against a
zero-authority proof role.  Credentials from that role are never used.

This is deliberately a split-phase PEP.  The human identity is verified by
STS before the existing broker persists the proof digest under its CAS ledger;
the broker execution role remains the only principal allowed to mutate the
ledger or retire the exact Change Set.  No token, assertion, credential, user
identifier, request body, or AWS response is logged or returned.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from tooling.platform_authority_identity_context_compatibility import (
    AWS_IDENTITY_CONTEXT_POLICY_ARN,
    COMPATIBLE_REVIEWED_ACTION,
    POLICY_SNAPSHOT_DIGEST,
    POLICY_SNAPSHOT_VERSION,
    canonical_digest,
    evaluate_identity_context_policy,
    load_bundled_policy_snapshot,
)


PROOF_REQUIRED_ACTION = "sts:SetContext"
COMPATIBLE_PROOF_ONLY_TRANSPORT = "COMPATIBLE_PROOF_ONLY_TRANSPORT"
IDENTITY_CENTER_CONTEXT_PROVIDER_ARN = (
    "arn:aws:iam::aws:contextProvider/IdentityCenter"
)
AUTHORIZATION_CODE_GRANT = "authorization_code"
REQUIRED_SCOPES = ("sts:identity_context",)
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
SESSION_NAME = re.compile(r"^gug217-[a-f0-9]{16}$")
REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "authorization_code",
        "code_verifier",
    }
)
ALLOWED_ALIASES = frozenset({"classify", "retire", "reconcile"})
STS_CLOCK_SKEW_SECONDS = 30


class ProofBoundaryError(RuntimeError):
    """A sanitized fail-closed proof-boundary result."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", code)
            else "IDENTITY_PROOF_DENIED"
        )
        super().__init__(self.code)


class SsoOidcClient(Protocol):
    def create_token_with_iam(self, **kwargs: Any) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]: ...


class RetirementBroker(Protocol):
    def preflight(self, *, alias: str) -> None: ...

    def handle(
        self,
        *,
        alias: str,
        event: object,
        identity_proof_sha256: str,
    ) -> dict[str, Any]: ...


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ProofBoundaryError("CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _secret_digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


@dataclass(frozen=True, slots=True)
class ProofCompatibilityDecision:
    status: str
    policy_arn: str
    policy_version: str
    policy_digest: str
    required_action: str
    live_effect_authorized: bool = False

    def __post_init__(self) -> None:
        if self.status != COMPATIBLE_PROOF_ONLY_TRANSPORT:
            raise ProofBoundaryError("PROOF_COMPATIBILITY_STATUS_INVALID")
        if self.policy_arn != AWS_IDENTITY_CONTEXT_POLICY_ARN:
            raise ProofBoundaryError("PROOF_POLICY_ARN_INVALID")
        if self.required_action != PROOF_REQUIRED_ACTION:
            raise ProofBoundaryError("PROOF_ACTION_INVALID")
        if self.live_effect_authorized:
            raise ProofBoundaryError("PROOF_COMPATIBILITY_OVERCLAIM")

    def to_receipt(self, *, observed_at: datetime) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_identity_context_pep_compatibility",
            "environment": "non-production",
            "production": False,
            "managed_policy_arn": self.policy_arn,
            "managed_policy_version": self.policy_version,
            "managed_policy_digest": self.policy_digest,
            "required_action": self.required_action,
            "status": self.status,
            "token_issued": False,
            "sts_session_issued": False,
            "broker_invocation_performed": False,
            "live_effect_authorized": self.live_effect_authorized,
            "observed_at": _timestamp(observed_at),
        }
        value["receipt_digest"] = canonical_digest(value)
        return value


def proof_compatibility_decision() -> ProofCompatibilityDecision:
    """Prove only that v12 permits STS to establish the deny-all proof session."""

    base = evaluate_identity_context_policy(
        load_bundled_policy_snapshot(),
        policy_arn=AWS_IDENTITY_CONTEXT_POLICY_ARN,
        default_version_id=POLICY_SNAPSHOT_VERSION,
        required_action=PROOF_REQUIRED_ACTION,
        reviewed_digest=POLICY_SNAPSHOT_DIGEST,
    )
    if base.status != COMPATIBLE_REVIEWED_ACTION:
        raise ProofBoundaryError("BLOCKED_IDENTITY_CONTEXT_PROOF_UNSUPPORTED")
    return ProofCompatibilityDecision(
        status=COMPATIBLE_PROOF_ONLY_TRANSPORT,
        policy_arn=base.policy_arn,
        policy_version=base.policy_version,
        policy_digest=base.policy_digest,
        required_action=base.required_action,
    )


@dataclass(frozen=True, slots=True)
class IdentityContextPepBinding:
    authority_account_id: str
    region: str
    identity_center_application_arn: str
    identity_center_instance_arn: str
    identity_store_arn: str
    redirect_uri: str
    broker_execution_role_arn: str
    classifier_user_id: str = field(repr=False)
    approver_user_id: str = field(repr=False)
    classifier_proof_role_arn: str
    approver_proof_role_arn: str
    proof_duration_seconds: int = 900
    max_token_lifetime_seconds: int = 900

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise ProofBoundaryError("ACCOUNT_BINDING_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise ProofBoundaryError("REGION_BINDING_INVALID")
        if (
            USER_ID.fullmatch(self.classifier_user_id) is None
            or USER_ID.fullmatch(self.approver_user_id) is None
        ):
            raise ProofBoundaryError("IDENTITY_STORE_USER_INVALID")
        if self.classifier_user_id.lower() == self.approver_user_id.lower():
            raise ProofBoundaryError("INDEPENDENT_OPERATOR_REQUIRED")
        if self.proof_duration_seconds != 900:
            raise ProofBoundaryError("PROOF_DURATION_INVALID")
        if not 60 <= self.max_token_lifetime_seconds <= 900:
            raise ProofBoundaryError("TOKEN_LIFETIME_INVALID")
        parsed = urlparse(self.redirect_uri)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.path != "/callback"
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ProofBoundaryError("REDIRECT_URI_INVALID")
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
            raise ProofBoundaryError("IDENTITY_CENTER_TOPOLOGY_INVALID")
        if application.group(1) != store.group(1) or application.group(2) != instance.group(1):
            raise ProofBoundaryError("IDENTITY_CENTER_TOPOLOGY_MISMATCH")
        expected_broker = (
            f"arn:{partition}:iam::{self.authority_account_id}:"
            "role/ScanalyzeGug215BrokerExecution"
        )
        expected_classifier = (
            f"arn:{partition}:iam::{self.authority_account_id}:"
            "role/ScanalyzeGug217ClassifierProof"
        )
        expected_approver = (
            f"arn:{partition}:iam::{self.authority_account_id}:"
            "role/ScanalyzeGug217ApproverProof"
        )
        if self.broker_execution_role_arn != expected_broker:
            raise ProofBoundaryError("BROKER_ROLE_BINDING_INVALID")
        if (
            self.classifier_proof_role_arn != expected_classifier
            or self.approver_proof_role_arn != expected_approver
        ):
            raise ProofBoundaryError("PROOF_ROLE_BINDING_INVALID")

    @property
    def binding_digest(self) -> str:
        return canonical_digest(
            {
                "authority_account_id": self.authority_account_id,
                "region": self.region,
                "identity_center_application_arn": self.identity_center_application_arn,
                "identity_center_instance_arn": self.identity_center_instance_arn,
                "identity_store_arn": self.identity_store_arn,
                "redirect_uri": self.redirect_uri,
                "broker_execution_role_arn": self.broker_execution_role_arn,
                "classifier_user_id": self.classifier_user_id.lower(),
                "approver_user_id": self.approver_user_id.lower(),
                "classifier_proof_role_arn": self.classifier_proof_role_arn,
                "approver_proof_role_arn": self.approver_proof_role_arn,
                "proof_duration_seconds": self.proof_duration_seconds,
                "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the internal typed binding; callers must not publish it."""

        return {
            "schema_version": "1",
            "record_type": "platform_authority_identity_context_pep_binding",
            "environment": "non-production",
            "production": False,
            "authority_account_id": self.authority_account_id,
            "region": self.region,
            "identity_center_application_arn": self.identity_center_application_arn,
            "identity_center_instance_arn": self.identity_center_instance_arn,
            "identity_store_arn": self.identity_store_arn,
            "redirect_uri": self.redirect_uri,
            "broker_execution_role_arn": self.broker_execution_role_arn,
            "classifier_user_id": self.classifier_user_id,
            "approver_user_id": self.approver_user_id,
            "classifier_proof_role_arn": self.classifier_proof_role_arn,
            "approver_proof_role_arn": self.approver_proof_role_arn,
            "proof_duration_seconds": self.proof_duration_seconds,
            "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            "identity_separation": "VERIFIED_DISTINCT_IDENTITYSTORE_USERS",
            "live_effect_authorized": False,
            "binding_digest": self.binding_digest,
        }

    def proof_target(self, alias: str) -> tuple[str, str, str, str]:
        if alias == "classify":
            return (
                "classifier",
                self.classifier_user_id,
                self.approver_user_id,
                self.classifier_proof_role_arn,
            )
        if alias in {"retire", "reconcile"}:
            return (
                "independent_approver",
                self.approver_user_id,
                self.classifier_user_id,
                self.approver_proof_role_arn,
            )
        raise ProofBoundaryError("ALIAS_NOT_AUTHORIZED")


@dataclass(slots=True)
class AuthorizationCodeEnvelope:
    authorization_code: str = field(repr=False)
    code_verifier: str = field(repr=False)
    redirect_uri: str
    _consumed: bool = field(default=False, init=False, repr=False)

    @classmethod
    def from_function_url_event(
        cls,
        event: object,
        *,
        binding: IdentityContextPepBinding,
        now: datetime,
    ) -> "AuthorizationCodeEnvelope":
        if now.tzinfo is None:
            raise ProofBoundaryError("CLOCK_INVALID")
        if not isinstance(event, dict):
            raise ProofBoundaryError("TRANSPORT_REQUEST_INVALID")
        raw_body = event.get("body")
        event["body"] = ""
        request_context = event.get("requestContext")
        http = request_context.get("http") if isinstance(request_context, Mapping) else None
        headers = event.get("headers")
        content_type = None
        if isinstance(headers, Mapping):
            content_type = next(
                (
                    value
                    for key, value in headers.items()
                    if isinstance(key, str) and key.lower() == "content-type"
                ),
                None,
            )
        if (
            event.get("version") != "2.0"
            or event.get("routeKey") != "$default"
            or event.get("rawPath") != "/"
            or event.get("rawQueryString") not in (None, "")
            or event.get("isBase64Encoded") is not False
            or not isinstance(http, Mapping)
            or http.get("method") != "POST"
            or content_type != "application/json"
            or not isinstance(raw_body, str)
            or not 2 <= len(raw_body) <= 12288
        ):
            raise ProofBoundaryError("TRANSPORT_REQUEST_INVALID")
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            raise ProofBoundaryError("TRANSPORT_BODY_INVALID") from None
        raw_body = ""
        if not isinstance(body, dict) or set(body) != REQUEST_KEYS:
            if isinstance(body, dict):
                body.clear()
            raise ProofBoundaryError("REQUEST_AUTHORITY_FORBIDDEN")
        try:
            if (
                body.get("schema_version") != "1"
                or body.get("record_type")
                != "platform_authority_identity_context_pep_request"
            ):
                raise ProofBoundaryError("REQUEST_BINDING_INVALID")
            code = body.get("authorization_code")
            verifier = body.get("code_verifier")
            if (
                not isinstance(code, str)
                or not 8 <= len(code) <= 4096
                or code.isspace()
                or not isinstance(verifier, str)
                or PKCE_VERIFIER.fullmatch(verifier) is None
            ):
                raise ProofBoundaryError("AUTHORIZATION_CODE_MALFORMED")
            return cls(
                authorization_code=code,
                code_verifier=verifier,
                redirect_uri=binding.redirect_uri,
            )
        finally:
            body.clear()

    def consume_once(self) -> tuple[str, str, str]:
        if self._consumed:
            raise ProofBoundaryError("AUTHORIZATION_CODE_REPLAY")
        self._consumed = True
        code = self.authorization_code
        verifier = self.code_verifier
        redirect = self.redirect_uri
        self.authorization_code = ""
        self.code_verifier = ""
        return code, verifier, redirect


@dataclass(frozen=True, slots=True)
class IdentityContextProofReceipt:
    status: str
    binding_digest: str
    policy_version: str
    policy_digest: str
    required_action: str
    role_kind: str
    broker_alias: str
    expected_user_id_digest: str
    peer_user_id_digest: str
    proof_role_arn_digest: str
    proof_session_arn_digest: str
    proof_expires_at: str
    credentials_consumed: bool = False
    live_retirement_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_identity_context_proof_receipt",
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
            "peer_user_id_digest": self.peer_user_id_digest,
            "proof_role_arn_digest": self.proof_role_arn_digest,
            "proof_session_arn_digest": self.proof_session_arn_digest,
            "proof_expires_at": self.proof_expires_at,
            "credentials_consumed": self.credentials_consumed,
            "live_retirement_authorized": self.live_retirement_authorized,
        }
        value["receipt_digest"] = canonical_digest(value)
        return value

    @property
    def receipt_digest(self) -> str:
        return str(self.to_dict()["receipt_digest"])


class IdentityContextProofVerifier:
    """Exchange one code and validate one deny-all STS proof session."""

    def __init__(
        self,
        *,
        oidc_client: SsoOidcClient,
        sts_client: StsClient,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._oidc = oidc_client
        self._sts = sts_client
        self._clock = clock or (lambda: datetime.now(tz=UTC))

    def verify(
        self,
        *,
        alias: str,
        event: object,
        binding: IdentityContextPepBinding,
        now: datetime,
    ) -> IdentityContextProofReceipt:
        compatibility = proof_compatibility_decision()
        if alias not in ALLOWED_ALIASES:
            raise ProofBoundaryError("ALIAS_NOT_AUTHORIZED")
        role_kind, expected_user, peer_user, proof_role_arn = binding.proof_target(alias)
        envelope = AuthorizationCodeEnvelope.from_function_url_event(
            event,
            binding=binding,
            now=now,
        )
        code, verifier, redirect = envelope.consume_once()
        token_response: Mapping[str, Any] | None = None
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
                raise ProofBoundaryError("OIDC_EXCHANGE_UNCERTAIN") from None
        finally:
            code = ""
            verifier = ""
            redirect = ""
        try:
            assertion = self._validate_token_response(
                token_response,
                max_lifetime=binding.max_token_lifetime_seconds,
            )
        finally:
            if isinstance(token_response, dict):
                details = token_response.get("awsAdditionalDetails")
                if isinstance(details, dict):
                    details.clear()
                token_response.clear()
        session_name = "gug217-" + secrets.token_hex(8)
        if SESSION_NAME.fullmatch(session_name) is None:
            raise ProofBoundaryError("PROOF_SESSION_NAME_INVALID")
        sts_response: Mapping[str, Any] | None = None
        sts_request_started_at = self._clock()
        try:
            try:
                sts_response = self._sts.assume_role(
                    RoleArn=proof_role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=binding.proof_duration_seconds,
                    ProvidedContexts=[
                        {
                            "ProviderArn": IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
                            "ContextAssertion": assertion,
                        }
                    ],
                )
            except Exception:
                raise ProofBoundaryError("STS_PROOF_UNCERTAIN") from None
        finally:
            assertion = ""
        sts_response_received_at = self._clock()
        try:
            expiration, assumed_role_arn = self._validate_sts_response(
                sts_response,
                authority_account_id=binding.authority_account_id,
                region=binding.region,
                proof_role_arn=proof_role_arn,
                duration_seconds=binding.proof_duration_seconds,
                request_started_at=sts_request_started_at,
                response_received_at=sts_response_received_at,
            )
        finally:
            if isinstance(sts_response, dict):
                credentials = sts_response.get("Credentials")
                if isinstance(credentials, dict):
                    credentials.clear()
                sts_response.clear()
        return IdentityContextProofReceipt(
            status="IDENTITY_CONTEXT_PROOF_VERIFIED",
            binding_digest=binding.binding_digest,
            policy_version=compatibility.policy_version,
            policy_digest=compatibility.policy_digest,
            required_action=compatibility.required_action,
            role_kind=role_kind,
            broker_alias=alias,
            expected_user_id_digest=_secret_digest(
                "identity_store_user_id", expected_user.lower()
            ),
            peer_user_id_digest=_secret_digest(
                "identity_store_user_id", peer_user.lower()
            ),
            proof_role_arn_digest=_secret_digest("proof_role_arn", proof_role_arn),
            proof_session_arn_digest=_secret_digest(
                "proof_session_arn", assumed_role_arn
            ),
            proof_expires_at=_timestamp(expiration),
        )

    @staticmethod
    def _validate_token_response(
        response: Mapping[str, Any] | None,
        *,
        max_lifetime: int,
    ) -> str:
        if not isinstance(response, Mapping):
            raise ProofBoundaryError("OIDC_RESPONSE_MALFORMED")
        if response.get("refreshToken"):
            raise ProofBoundaryError("OIDC_REFRESH_TOKEN_FORBIDDEN")
        if response.get("tokenType") != "Bearer":
            raise ProofBoundaryError("OIDC_TOKEN_TYPE_MISMATCH")
        if response.get("scope") != list(REQUIRED_SCOPES):
            raise ProofBoundaryError("OIDC_SCOPE_MISMATCH")
        expires_in = response.get("expiresIn")
        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 60 <= expires_in <= max_lifetime
        ):
            raise ProofBoundaryError("OIDC_TOKEN_LIFETIME_INVALID")
        access_token = response.get("accessToken")
        if not isinstance(access_token, str) or not 4 <= len(access_token) <= 16384:
            raise ProofBoundaryError("OIDC_ACCESS_TOKEN_MALFORMED")
        details = response.get("awsAdditionalDetails")
        assertion = details.get("identityContext") if isinstance(details, Mapping) else None
        if not isinstance(assertion, str) or not 4 <= len(assertion) <= 2048:
            raise ProofBoundaryError("IDENTITY_CONTEXT_MISSING")
        return assertion

    @staticmethod
    def _validate_sts_response(
        response: Mapping[str, Any] | None,
        *,
        authority_account_id: str,
        region: str,
        proof_role_arn: str,
        duration_seconds: int,
        request_started_at: datetime,
        response_received_at: datetime,
    ) -> tuple[datetime, str]:
        if not isinstance(response, Mapping):
            raise ProofBoundaryError("STS_RESPONSE_MALFORMED")
        assumed = response.get("AssumedRoleUser")
        arn = assumed.get("Arn") if isinstance(assumed, Mapping) else None
        role_name = proof_role_arn.rsplit("/", 1)[-1]
        expected_arn = re.compile(
            rf"arn:{_partition(region)}:sts::{authority_account_id}:"
            rf"assumed-role/{re.escape(role_name)}/gug217-[a-f0-9]{{16}}"
        )
        if not isinstance(arn, str) or expected_arn.fullmatch(arn) is None:
            raise ProofBoundaryError("STS_PROOF_ROLE_MISMATCH")
        credentials = response.get("Credentials")
        if not isinstance(credentials, Mapping) or set(credentials) != {
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
        }:
            raise ProofBoundaryError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        if any(
            not isinstance(credentials.get(key), str) or not credentials.get(key)
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
        ):
            raise ProofBoundaryError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        expiration = credentials.get("Expiration")
        if (
            request_started_at.tzinfo is None
            or response_received_at.tzinfo is None
            or not isinstance(expiration, datetime)
            or expiration.tzinfo is None
        ):
            raise ProofBoundaryError("STS_EXPIRATION_INVALID")
        started_utc = request_started_at.astimezone(UTC)
        received_utc = response_received_at.astimezone(UTC)
        expires_utc = expiration.astimezone(UTC)
        skew = timedelta(seconds=STS_CLOCK_SKEW_SECONDS)
        if (
            received_utc < started_utc - skew
            or expires_utc <= received_utc
            or expires_utc > started_utc + timedelta(seconds=duration_seconds) + skew
        ):
            raise ProofBoundaryError("STS_EXPIRATION_INVALID")
        return expires_utc, arn


class IdentityContextPep:
    """Require a durable proof digest before delegating to the GUG-215 broker."""

    def __init__(
        self,
        *,
        verifier: IdentityContextProofVerifier,
        broker: RetirementBroker,
    ) -> None:
        self._verifier = verifier
        self._broker = broker

    def execute(
        self,
        *,
        alias: str,
        event: object,
        binding: IdentityContextPepBinding,
        now: datetime,
    ) -> dict[str, Any]:
        # Read back the complete effective boundary before exchanging the
        # one-shot authorization code. The broker repeats the same checks in
        # ``handle`` so drift between proof and durable CAS also fails closed.
        self._broker.preflight(alias=alias)
        proof = self._verifier.verify(
            alias=alias,
            event=event,
            binding=binding,
            now=now,
        )
        proof_receipt = proof.to_dict()
        result = self._broker.handle(
            alias=alias,
            event={},
            identity_proof_sha256=str(proof_receipt["receipt_digest"]),
        )
        return {**result, "identity_proof": proof_receipt}
