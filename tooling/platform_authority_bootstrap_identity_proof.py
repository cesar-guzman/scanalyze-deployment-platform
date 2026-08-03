"""Identity Center proof boundary for GUG-274 bootstrap artifact authority.

The artifact-authority Lambdas receive a one-shot authorization-code grant,
exchange it for an opaque Identity Center context assertion, and ask STS to
assume an operation-specific deny-all proof role.  The proof-role trust policy,
not a caller-supplied identifier, binds the real Identity Store user.  No token,
assertion, credential, raw user identifier, or provider response is returned or
persisted.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from tooling.platform_authority_bootstrap import BootstrapAuthorizationError
from tooling.platform_authority_identity_context_pep import (
    IDENTITY_CENTER_CONTEXT_PROVIDER_ARN,
    REQUIRED_SCOPES,
    proof_compatibility_decision,
)


PROOF_DOMAIN = "scanalyze.platform-authority.bootstrap.identity-proof.v1"
PROOF_BINDING_DOMAIN = (
    "scanalyze.platform-authority.bootstrap.identity-proof-binding.v1"
)
AUTHORIZATION_CODE_GRANT = "authorization_code"
ALLOWED_OPERATIONS = frozenset({"plan", "approval", "apply"})
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
SESSION_NAME = re.compile(r"^gug274-(?:plan|approval|apply)-[a-f0-9]{12}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CANONICAL_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
GRANT_FIELDS = frozenset(
    {"schema_version", "record_type", "authorization_code", "code_verifier"}
)
PROOF_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "domain_separator",
        "status",
        "identity_binding_digest",
        "operation",
        "role_kind",
        "expected_user_id_digest",
        "peer_user_id_digest",
        "broker_execution_role_arn_digest",
        "proof_role_arn_digest",
        "proof_session_arn_digest",
        "managed_policy_version",
        "managed_policy_digest",
        "required_action",
        "proof_expires_at",
        "credentials_consumed",
        "live_effect_authorized",
        "proof_receipt_digest",
    }
)
MAX_GRANT_BYTES = 12 * 1024
STS_CLOCK_SKEW_SECONDS = 30


class BootstrapIdentityProofError(BootstrapAuthorizationError):
    """A sanitized, fail-closed Identity Center proof result."""

    code = "BOOTSTRAP_IDENTITY_PROOF_DENIED"


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise BootstrapIdentityProofError("identity proof JSON is invalid") from None
    if len(payload) > MAX_GRANT_BYTES:
        raise BootstrapIdentityProofError("identity proof request exceeds size bound")
    return payload


def _domain_digest(domain: str, value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        domain.encode("ascii") + b"\x00" + _canonical_bytes(value)
    ).hexdigest()


def _secret_digest(label: str, value: str) -> str:
    return _domain_digest(
        "scanalyze.platform-authority.bootstrap.identity-secret.v1",
        {"label": label, "value": value},
    )


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise BootstrapIdentityProofError("identity proof clock is invalid")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class BootstrapIdentityProofBinding:
    """Immutable runtime-owned identity topology for all three operations."""

    authority_account_id: str
    region: str
    identity_center_application_arn: str
    identity_center_instance_arn: str
    identity_store_arn: str
    redirect_uri: str
    plan_user_id: str = field(repr=False)
    second_party_user_id: str = field(repr=False)
    plan_execution_role_arn: str
    approval_execution_role_arn: str
    apply_execution_role_arn: str
    plan_proof_role_arn: str
    approval_proof_role_arn: str
    apply_proof_role_arn: str
    proof_duration_seconds: int = 900
    max_token_lifetime_seconds: int = 900

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise BootstrapIdentityProofError("identity authority account is invalid")
        if REGION.fullmatch(self.region) is None:
            raise BootstrapIdentityProofError("identity authority region is invalid")
        if (
            USER_ID.fullmatch(self.plan_user_id) is None
            or USER_ID.fullmatch(self.second_party_user_id) is None
        ):
            raise BootstrapIdentityProofError("Identity Store user binding is invalid")
        if self.plan_user_id.lower() == self.second_party_user_id.lower():
            raise BootstrapIdentityProofError(
                "Plan and Approval require distinct Identity Store users"
            )
        if self.proof_duration_seconds != 900:
            raise BootstrapIdentityProofError("identity proof duration is invalid")
        if not 60 <= self.max_token_lifetime_seconds <= 900:
            raise BootstrapIdentityProofError("identity token lifetime is invalid")
        parsed = urlparse(self.redirect_uri)
        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.path != "/callback"
            or parsed_port is None
            or not 1024 <= parsed_port <= 65535
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise BootstrapIdentityProofError("identity redirect URI is invalid")

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
            raise BootstrapIdentityProofError("Identity Center topology is invalid")
        if (
            application.group(1) != self.authority_account_id
            or store.group(1) != self.authority_account_id
            or application.group(2) != instance.group(1)
        ):
            raise BootstrapIdentityProofError("Identity Center topology is not exact")

        expected_roles = {
            "plan_execution_role_arn": "ScanalyzeGug274BootstrapPlanAuthority",
            "approval_execution_role_arn": "ScanalyzeGug274BootstrapApprovalAuthority",
            "apply_execution_role_arn": "ScanalyzeGug274BootstrapApplyExecutor",
            "plan_proof_role_arn": "ScanalyzeGug274BootstrapPlanIdentityProof",
            "approval_proof_role_arn": "ScanalyzeGug274BootstrapApprovalIdentityProof",
            "apply_proof_role_arn": "ScanalyzeGug274BootstrapApplyIdentityProof",
        }
        for field_name, role_name in expected_roles.items():
            expected = (
                f"arn:{partition}:iam::{self.authority_account_id}:role/{role_name}"
            )
            if getattr(self, field_name) != expected:
                raise BootstrapIdentityProofError("identity proof role binding is invalid")

    @property
    def binding_digest(self) -> str:
        return _domain_digest(
            PROOF_BINDING_DOMAIN,
            {
                "authority_account_id": self.authority_account_id,
                "region": self.region,
                "identity_center_application_arn": self.identity_center_application_arn,
                "identity_center_instance_arn": self.identity_center_instance_arn,
                "identity_store_arn": self.identity_store_arn,
                "redirect_uri": self.redirect_uri,
                "plan_user_id": self.plan_user_id.lower(),
                "second_party_user_id": self.second_party_user_id.lower(),
                "plan_execution_role_arn": self.plan_execution_role_arn,
                "approval_execution_role_arn": self.approval_execution_role_arn,
                "apply_execution_role_arn": self.apply_execution_role_arn,
                "plan_proof_role_arn": self.plan_proof_role_arn,
                "approval_proof_role_arn": self.approval_proof_role_arn,
                "apply_proof_role_arn": self.apply_proof_role_arn,
                "proof_duration_seconds": self.proof_duration_seconds,
                "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            },
        )

    def proof_target(self, operation: str) -> tuple[str, str, str, str, str]:
        if operation == "plan":
            return (
                "plan_author",
                self.plan_user_id,
                self.second_party_user_id,
                self.plan_execution_role_arn,
                self.plan_proof_role_arn,
            )
        if operation == "approval":
            return (
                "independent_approver",
                self.second_party_user_id,
                self.plan_user_id,
                self.approval_execution_role_arn,
                self.approval_proof_role_arn,
            )
        if operation == "apply":
            return (
                "apply_verifier",
                self.second_party_user_id,
                self.plan_user_id,
                self.apply_execution_role_arn,
                self.apply_proof_role_arn,
            )
        raise BootstrapIdentityProofError("identity proof operation is not authorized")


@dataclass(slots=True)
class AuthorizationCodeGrant:
    authorization_code: str = field(repr=False)
    code_verifier: str = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)

    @classmethod
    def from_json(cls, raw: object) -> "AuthorizationCodeGrant":
        if not isinstance(raw, str) or not 2 <= len(raw.encode("utf-8")) <= MAX_GRANT_BYTES:
            raise BootstrapIdentityProofError("identity grant JSON is invalid")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result

        try:
            value = json.loads(raw, object_pairs_hook=reject_duplicates)
        except (json.JSONDecodeError, ValueError):
            raise BootstrapIdentityProofError("identity grant JSON is invalid") from None
        return cls.from_mapping(value)

    @classmethod
    def from_mapping(cls, value: object) -> "AuthorizationCodeGrant":
        if type(value) is not dict:
            raise BootstrapIdentityProofError("identity grant must be a plain object")
        grant = value
        try:
            _canonical_bytes(grant)
            if set(grant) != GRANT_FIELDS:
                raise BootstrapIdentityProofError("identity grant contract is not closed")
            if (
                grant.get("schema_version") != "1"
                or grant.get("record_type")
                != "platform_authority_bootstrap_identity_grant"
            ):
                raise BootstrapIdentityProofError("identity grant metadata is invalid")
            code = grant.get("authorization_code")
            verifier = grant.get("code_verifier")
            if (
                not isinstance(code, str)
                or not 8 <= len(code) <= 4096
                or code.isspace()
                or not isinstance(verifier, str)
                or PKCE_VERIFIER.fullmatch(verifier) is None
            ):
                raise BootstrapIdentityProofError("authorization code grant is invalid")
            return cls(authorization_code=code, code_verifier=verifier)
        finally:
            grant.clear()

    def consume_once(self) -> tuple[str, str]:
        if self._consumed:
            raise BootstrapIdentityProofError("authorization code grant was replayed")
        self._consumed = True
        code = self.authorization_code
        verifier = self.code_verifier
        self.authorization_code = ""
        self.code_verifier = ""
        return code, verifier


class SsoOidcClient(Protocol):
    def create_token_with_iam(self, **kwargs: Any) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class BootstrapIdentityProofReceipt:
    operation: str
    role_kind: str
    identity_binding_digest: str
    expected_user_id_digest: str
    peer_user_id_digest: str
    broker_execution_role_arn_digest: str
    proof_role_arn_digest: str
    proof_session_arn_digest: str
    managed_policy_version: str
    managed_policy_digest: str
    required_action: str
    proof_expires_at: str

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": "platform_authority_bootstrap_identity_proof",
            "domain_separator": PROOF_DOMAIN,
            "status": "IDENTITY_CONTEXT_PROOF_VERIFIED",
            "identity_binding_digest": self.identity_binding_digest,
            "operation": self.operation,
            "role_kind": self.role_kind,
            "expected_user_id_digest": self.expected_user_id_digest,
            "peer_user_id_digest": self.peer_user_id_digest,
            "broker_execution_role_arn_digest": self.broker_execution_role_arn_digest,
            "proof_role_arn_digest": self.proof_role_arn_digest,
            "proof_session_arn_digest": self.proof_session_arn_digest,
            "managed_policy_version": self.managed_policy_version,
            "managed_policy_digest": self.managed_policy_digest,
            "required_action": self.required_action,
            "proof_expires_at": self.proof_expires_at,
            "credentials_consumed": False,
            "live_effect_authorized": False,
        }
        value["proof_receipt_digest"] = _domain_digest(PROOF_DOMAIN, value)
        return value


def validate_identity_proof_receipt(
    receipt: Mapping[str, Any], *, operation: str, now: datetime | None = None
) -> dict[str, Any]:
    if type(receipt) is not dict or set(receipt) != PROOF_RECEIPT_FIELDS:
        raise BootstrapIdentityProofError("identity proof receipt is not closed")
    if (
        operation not in ALLOWED_OPERATIONS
        or receipt.get("schema_version") != "1"
        or receipt.get("record_type")
        != "platform_authority_bootstrap_identity_proof"
        or receipt.get("domain_separator") != PROOF_DOMAIN
        or receipt.get("status") != "IDENTITY_CONTEXT_PROOF_VERIFIED"
        or receipt.get("operation") != operation
        or receipt.get("credentials_consumed") is not False
        or receipt.get("live_effect_authorized") is not False
        or receipt.get("required_action") != "sts:SetContext"
    ):
        raise BootstrapIdentityProofError("identity proof receipt metadata is invalid")
    expected_role_kind = {
        "plan": "plan_author",
        "approval": "independent_approver",
        "apply": "apply_verifier",
    }[operation]
    if receipt.get("role_kind") != expected_role_kind:
        raise BootstrapIdentityProofError("identity proof role kind is invalid")
    for field_name in (
        "identity_binding_digest",
        "expected_user_id_digest",
        "peer_user_id_digest",
        "broker_execution_role_arn_digest",
        "proof_role_arn_digest",
        "proof_session_arn_digest",
        "managed_policy_digest",
    ):
        if DIGEST.fullmatch(str(receipt.get(field_name, ""))) is None:
            raise BootstrapIdentityProofError("identity proof digest is invalid")
    if receipt.get("expected_user_id_digest") == receipt.get("peer_user_id_digest"):
        raise BootstrapIdentityProofError("identity proof users are not distinct")
    expires_at = receipt.get("proof_expires_at")
    if (
        not isinstance(expires_at, str)
        or CANONICAL_TIMESTAMP.fullmatch(expires_at) is None
    ):
        raise BootstrapIdentityProofError("identity proof expiry is invalid")
    try:
        expires = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError:
        raise BootstrapIdentityProofError("identity proof expiry is invalid") from None
    if now is not None:
        if now.tzinfo is None or expires <= now.astimezone(UTC):
            raise BootstrapIdentityProofError("identity proof receipt is expired")
    claimed = receipt.get("proof_receipt_digest")
    unsigned = {
        key: value for key, value in receipt.items() if key != "proof_receipt_digest"
    }
    if claimed != _domain_digest(PROOF_DOMAIN, unsigned):
        raise BootstrapIdentityProofError("identity proof receipt digest mismatch")
    return dict(receipt)


class BootstrapIdentityProofVerifier:
    """Exchange one code and validate one exact deny-all STS proof session."""

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
        operation: str,
        identity_grant: object,
        binding: BootstrapIdentityProofBinding,
        now: datetime,
    ) -> dict[str, Any]:
        if operation not in ALLOWED_OPERATIONS or now.tzinfo is None:
            raise BootstrapIdentityProofError("identity proof operation is invalid")
        compatibility = proof_compatibility_decision()
        (
            role_kind,
            expected_user,
            peer_user,
            execution_role_arn,
            proof_role_arn,
        ) = binding.proof_target(operation)
        envelope = (
            AuthorizationCodeGrant.from_json(identity_grant)
            if isinstance(identity_grant, str)
            else AuthorizationCodeGrant.from_mapping(identity_grant)
        )
        code, verifier = envelope.consume_once()
        token_response: Mapping[str, Any] | None = None
        try:
            try:
                token_response = self._oidc.create_token_with_iam(
                    clientId=binding.identity_center_application_arn,
                    grantType=AUTHORIZATION_CODE_GRANT,
                    code=code,
                    codeVerifier=verifier,
                    redirectUri=binding.redirect_uri,
                    scope=list(REQUIRED_SCOPES),
                )
            except Exception:
                raise BootstrapIdentityProofError(
                    "Identity Center code exchange is uncertain"
                ) from None
        finally:
            code = ""
            verifier = ""
        try:
            assertion = self._validate_token_response(
                token_response, max_lifetime=binding.max_token_lifetime_seconds
            )
        finally:
            if isinstance(token_response, dict):
                details = token_response.get("awsAdditionalDetails")
                if isinstance(details, dict):
                    details.clear()
                token_response.clear()

        session_name = f"gug274-{operation}-{secrets.token_hex(6)}"
        if SESSION_NAME.fullmatch(session_name) is None:
            raise BootstrapIdentityProofError("identity proof session is invalid")
        started_at = self._clock()
        sts_response: Mapping[str, Any] | None = None
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
                raise BootstrapIdentityProofError(
                    "Identity Center STS proof is uncertain"
                ) from None
        finally:
            assertion = ""
        received_at = self._clock()
        try:
            expiration, assumed_role_arn = self._validate_sts_response(
                sts_response,
                authority_account_id=binding.authority_account_id,
                region=binding.region,
                proof_role_arn=proof_role_arn,
                operation=operation,
                duration_seconds=binding.proof_duration_seconds,
                request_started_at=started_at,
                response_received_at=received_at,
            )
        finally:
            if isinstance(sts_response, dict):
                credentials = sts_response.get("Credentials")
                if isinstance(credentials, dict):
                    credentials.clear()
                sts_response.clear()

        receipt = BootstrapIdentityProofReceipt(
            operation=operation,
            role_kind=role_kind,
            identity_binding_digest=binding.binding_digest,
            expected_user_id_digest=_secret_digest(
                "identity_store_user_id", expected_user.lower()
            ),
            peer_user_id_digest=_secret_digest(
                "identity_store_user_id", peer_user.lower()
            ),
            broker_execution_role_arn_digest=_secret_digest(
                "broker_execution_role_arn", execution_role_arn
            ),
            proof_role_arn_digest=_secret_digest("proof_role_arn", proof_role_arn),
            proof_session_arn_digest=_secret_digest(
                "proof_session_arn", assumed_role_arn
            ),
            managed_policy_version=compatibility.policy_version,
            managed_policy_digest=compatibility.policy_digest,
            required_action=compatibility.required_action,
            proof_expires_at=_timestamp(expiration),
        ).to_dict()
        return validate_identity_proof_receipt(
            receipt, operation=operation, now=now
        )

    @staticmethod
    def _validate_token_response(
        response: Mapping[str, Any] | None, *, max_lifetime: int
    ) -> str:
        if not isinstance(response, Mapping):
            raise BootstrapIdentityProofError("Identity Center response is malformed")
        if response.get("refreshToken"):
            raise BootstrapIdentityProofError("Identity Center refresh token is forbidden")
        if response.get("tokenType") != "Bearer":
            raise BootstrapIdentityProofError("Identity Center token type is invalid")
        if response.get("scope") != list(REQUIRED_SCOPES):
            raise BootstrapIdentityProofError("Identity Center token scope is invalid")
        expires_in = response.get("expiresIn")
        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 60 <= expires_in <= max_lifetime
        ):
            raise BootstrapIdentityProofError("Identity Center token lifetime is invalid")
        access_token = response.get("accessToken")
        if not isinstance(access_token, str) or not 4 <= len(access_token) <= 16384:
            raise BootstrapIdentityProofError("Identity Center token is malformed")
        details = response.get("awsAdditionalDetails")
        assertion = details.get("identityContext") if isinstance(details, Mapping) else None
        if not isinstance(assertion, str) or not 4 <= len(assertion) <= 2048:
            raise BootstrapIdentityProofError("Identity Center context is missing")
        return assertion

    @staticmethod
    def _validate_sts_response(
        response: Mapping[str, Any] | None,
        *,
        authority_account_id: str,
        region: str,
        proof_role_arn: str,
        operation: str,
        duration_seconds: int,
        request_started_at: datetime,
        response_received_at: datetime,
    ) -> tuple[datetime, str]:
        if not isinstance(response, Mapping):
            raise BootstrapIdentityProofError("STS proof response is malformed")
        assumed = response.get("AssumedRoleUser")
        arn = assumed.get("Arn") if isinstance(assumed, Mapping) else None
        role_name = proof_role_arn.rsplit("/", 1)[-1]
        expected = re.compile(
            rf"arn:{_partition(region)}:sts::{authority_account_id}:assumed-role/"
            rf"{re.escape(role_name)}/gug274-{operation}-[a-f0-9]{{12}}"
        )
        if not isinstance(arn, str) or expected.fullmatch(arn) is None:
            raise BootstrapIdentityProofError("STS proof role is not exact")
        credentials = response.get("Credentials")
        if not isinstance(credentials, Mapping) or set(credentials) != {
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
        }:
            raise BootstrapIdentityProofError("STS proof credentials are malformed")
        if any(
            not isinstance(credentials.get(field_name), str)
            or not credentials.get(field_name)
            for field_name in ("AccessKeyId", "SecretAccessKey", "SessionToken")
        ):
            raise BootstrapIdentityProofError("STS proof credentials are malformed")
        expiration = credentials.get("Expiration")
        if (
            request_started_at.tzinfo is None
            or response_received_at.tzinfo is None
            or not isinstance(expiration, datetime)
            or expiration.tzinfo is None
        ):
            raise BootstrapIdentityProofError("STS proof expiry is invalid")
        started = request_started_at.astimezone(UTC)
        received = response_received_at.astimezone(UTC)
        expires = expiration.astimezone(UTC)
        skew = timedelta(seconds=STS_CLOCK_SKEW_SECONDS)
        if (
            received < started - skew
            or expires <= received
            or expires > started + timedelta(seconds=duration_seconds) + skew
        ):
            raise BootstrapIdentityProofError("STS proof expiry is invalid")
        return expires, arn
