"""Dedicated proof-only PEP for the GUG-221 Phase B Change Set execution.

The human caller reaches the broker through an ordinary, invoke-only IAM
Identity Center session.  A short-lived Authorization Code + PKCE grant is
exchanged by the broker application actor.  The returned Identity Center
context is used exactly once to establish a deny-all proof role session whose
trust policy binds the immutable Identity Store user.

The proof credentials are destroyed without being exposed to the execution
path.  A separate Lambda service role consumes an exact one-shot CAS ledger
entry and calls CloudFormation once with the immutable stack ARN, Change Set
ARN and ClientRequestToken.  Any ambiguous boundary is reconcile-only and is
never retried.  This is explicit proof attribution, not native on-behalf-of
execution.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from tooling.platform_authority_identity_context_compatibility import (
    AWS_IDENTITY_CONTEXT_POLICY_ARN,
    BLOCKED_ACTION_UNSUPPORTED,
    COMPATIBLE_REVIEWED_ACTION,
    POLICY_SNAPSHOT_DIGEST,
    POLICY_SNAPSHOT_VERSION,
    evaluate_identity_context_policy,
    load_bundled_policy_snapshot,
)


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
STACK_NAME = "scanalyze-platform-authority-lambda-audit-repair-pep"
CHANGE_SET_NAME = "gug221-lambda-audit-repair-pep-create"
BROKER_ROLE_NAME = "ScanalyzeGug221PhaseBBrokerExecution"
INVOKER_ROLE_NAME = "ScanalyzeGug221PhaseBInvoker"
PROOF_ROLE_NAME = "ScanalyzeGug221PhaseBProof"
LEDGER_TABLE_NAME = (
    "scanalyze-platform-authority-gug221-phase-b-execution-ledger"
)
FUNCTION_NAME = "scanalyze-platform-authority-gug221-phase-b-broker"
FUNCTION_ALIAS = "broker-v1"
IDENTITY_CENTER_CONTEXT_PROVIDER_ARN = (
    "arn:aws:iam::aws:contextProvider/IdentityCenter"
)
AUTHORIZATION_CODE_GRANT = "authorization_code"
REQUIRED_SCOPES = ("openid", "sts:identity_context")
PROOF_REQUIRED_ACTION = "sts:SetContext"
DIRECT_EFFECT_ACTION = "cloudformation:ExecuteChangeSet"
MAX_WINDOW_SECONDS = 900
PROOF_DURATION_SECONDS = 900
MAX_TOKEN_LIFETIME_SECONDS = 900
STS_CLOCK_SKEW_SECONDS = 30
BROKER_TOPOLOGY_MAX_AGE_SECONDS = 300
BROKER_TOPOLOGY_SIGNATURE_ALGORITHM = "ECDSA_SHA_256"
REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "authorization_code",
        "code_verifier",
        "oauth_state",
        "broker_topology_evidence",
    }
)
DIRECT_EFFECT_BLOCKED = "BLOCKED_BY_AWS_IDENTITY_CONTEXT_V12"
PROOF_ONLY_SESSION_MODE = "IDENTITY_ENHANCED_PROOF_ONLY"

_ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_PKCE_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_OAUTH_STATE = re.compile(r"^[A-Za-z0-9._~-]{22,256}$")
_CLIENT_REQUEST_TOKEN = re.compile(r"^gug221-b-[0-9a-f]{48}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RAW_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CODE_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_KMS_SIGNING_KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_BASE64_SIGNATURE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_SESSION_NAME = re.compile(r"^gug221-phase-b-[0-9a-f]{16}$")
_EXECUTION_ID = re.compile(r"^gug221-phase-b-[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)


class PhaseBPepError(RuntimeError):
    """Sanitized, fail-closed Phase B boundary error."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code)
            else "PHASE_B_PEP_DENIED"
        )
        super().__init__(self.code)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _secret_digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PhaseBPepError("CLOCK_INVALID")
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: str, *, code: str = "TIMESTAMP_INVALID") -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise PhaseBPepError(code)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise PhaseBPepError(code) from None


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


BROKER_TOPOLOGY_EVIDENCE_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "authority_account_id",
        "management_account_id",
        "region",
        "provider_readback",
        "identity_center_application_verified",
        "single_operator_assignment_verified",
        "broker_alias_verified",
        "broker_role_verified",
        "proof_role_verified",
        "ledger_resource_policy_verified",
        "direct_qualified_invoke_only",
        "function_url_absent",
        "synchronous_client_context_required",
        "asynchronous_effect_blocked",
        "pending_operations_absent",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "broker_topology_sha256",
        "topology_state_digest",
        "collected_at",
        "signing_key_arn",
        "signature_algorithm",
        "signature",
        "receipt_digest",
    }
)


def broker_topology_signature_digest(value: Mapping[str, Any]) -> str:
    """Return the exact digest signed by the external topology collector."""

    if not isinstance(value, Mapping):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    unsigned = dict(value)
    unsigned.pop("receipt_digest", None)
    unsigned.pop("signature", None)
    return canonical_digest(unsigned)


def validate_broker_topology_evidence(
    value: Mapping[str, Any],
    *,
    now: datetime,
) -> str:
    """Validate a provider-derived prerequisite and return its receipt digest.

    The collector is deliberately external to the broker.  This validator
    accepts no offline or synthetic status and recomputes the receipt digest
    over every typed field.
    """

    if not isinstance(value, Mapping) or set(value) != BROKER_TOPOLOGY_EVIDENCE_KEYS:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    expected = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_"
            "broker_topology_evidence"
        ),
        "environment": "non-production",
        "production": False,
        "status": "PROVIDER_TOPOLOGY_READBACK_VERIFIED",
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "region": REGION,
        "provider_readback": True,
        "identity_center_application_verified": True,
        "single_operator_assignment_verified": True,
        "broker_alias_verified": True,
        "broker_role_verified": True,
        "proof_role_verified": True,
        "ledger_resource_policy_verified": True,
        "direct_qualified_invoke_only": True,
        "function_url_absent": True,
        "synchronous_client_context_required": True,
        "asynchronous_effect_blocked": True,
        "pending_operations_absent": True,
    }
    if any(
        value.get(key) != expected_value
        for key, expected_value in expected.items()
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    for field_name in (
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
    ):
        if _RAW_DIGEST.fullmatch(str(value.get(field_name, ""))) is None:
            raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    if any(
        _DIGEST.fullmatch(str(value.get(field_name, ""))) is None
        for field_name in (
            "broker_topology_sha256",
            "topology_state_digest",
        )
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    signing_key_arn = str(value.get("signing_key_arn", ""))
    if _KMS_SIGNING_KEY_ARN.fullmatch(signing_key_arn) is None:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    if (
        value.get("signature_algorithm")
        != BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    signature = value.get("signature")
    if (
        not isinstance(signature, str)
        or not 80 <= len(signature) <= 1024
        or _BASE64_SIGNATURE.fullmatch(signature) is None
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    try:
        decoded_signature = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID") from None
    if not 64 <= len(decoded_signature) <= 512:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    collected_at = parse_timestamp(
        str(value.get("collected_at", "")),
        code="BROKER_TOPOLOGY_EVIDENCE_INVALID",
    )
    if now.tzinfo is None or now.utcoffset() is None:
        raise PhaseBPepError("CLOCK_INVALID")
    observed_at = now.astimezone(UTC)
    age = observed_at - collected_at.astimezone(UTC)
    if age < timedelta(0):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_FROM_FUTURE")
    if age > timedelta(seconds=BROKER_TOPOLOGY_MAX_AGE_SECONDS):
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_STALE")
    receipt_digest = str(value.get("receipt_digest", ""))
    if _DIGEST.fullmatch(receipt_digest) is None:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_INVALID")
    if broker_topology_signature_digest(value) != receipt_digest:
        raise PhaseBPepError("BROKER_TOPOLOGY_EVIDENCE_DIGEST_MISMATCH")
    return receipt_digest


BROKER_TOPOLOGY_INPUT_KEYS = frozenset(
    {
        "authority_account_id",
        "management_account_id",
        "region",
        "identity_center_application_arn",
        "identity_center_instance_arn",
        "identity_store_arn",
        "operator_user_id_digest",
        "invoker_role_arn",
        "broker_execution_role_arn",
        "proof_role_arn",
        "ledger_table_arn",
        "broker_alias_arn",
        "broker_artifact_bucket",
        "broker_artifact_key",
        "broker_artifact_version",
        "broker_artifact_code_sha256",
        "broker_code_signing_config_arn",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "topology_signing_key_arn",
        "topology_signature_algorithm",
    }
)


def calculate_broker_topology_sha256(value: Mapping[str, str]) -> str:
    """Calculate the immutable broker topology digest from exact inputs."""

    if (
        not isinstance(value, Mapping)
        or set(value) != BROKER_TOPOLOGY_INPUT_KEYS
        or any(not isinstance(item, str) or not item for item in value.values())
    ):
        raise PhaseBPepError("BROKER_TOPOLOGY_INPUT_INVALID")
    return canonical_digest(
        {
            "schema_version": "1",
            **dict(value),
            "provider_readback_required": True,
        }
    )


@dataclass(frozen=True, slots=True)
class IdentityContextCompatibility:
    """Pinned v12 decision: proof is supported, direct execution is blocked."""

    managed_policy_arn: str
    managed_policy_version: str
    managed_policy_digest: str
    proof_action: str
    proof_status: str
    direct_effect_action: str
    direct_effect_status: str

    def __post_init__(self) -> None:
        if (
            self.managed_policy_arn != AWS_IDENTITY_CONTEXT_POLICY_ARN
            or self.managed_policy_version != POLICY_SNAPSHOT_VERSION
            or self.managed_policy_digest != POLICY_SNAPSHOT_DIGEST
            or self.proof_action != PROOF_REQUIRED_ACTION
            or self.proof_status != COMPATIBLE_REVIEWED_ACTION
            or self.direct_effect_action != DIRECT_EFFECT_ACTION
            or self.direct_effect_status != BLOCKED_ACTION_UNSUPPORTED
        ):
            raise PhaseBPepError("IDENTITY_CONTEXT_POLICY_UNSUPPORTED")


def identity_context_compatibility() -> IdentityContextCompatibility:
    """Evaluate the reviewed policy twice instead of inferring its semantics."""

    document = load_bundled_policy_snapshot()
    proof = evaluate_identity_context_policy(
        document,
        policy_arn=AWS_IDENTITY_CONTEXT_POLICY_ARN,
        default_version_id=POLICY_SNAPSHOT_VERSION,
        required_action=PROOF_REQUIRED_ACTION,
        reviewed_digest=POLICY_SNAPSHOT_DIGEST,
    )
    direct = evaluate_identity_context_policy(
        document,
        policy_arn=AWS_IDENTITY_CONTEXT_POLICY_ARN,
        default_version_id=POLICY_SNAPSHOT_VERSION,
        required_action=DIRECT_EFFECT_ACTION,
        reviewed_digest=POLICY_SNAPSHOT_DIGEST,
    )
    return IdentityContextCompatibility(
        managed_policy_arn=proof.policy_arn,
        managed_policy_version=proof.policy_version,
        managed_policy_digest=proof.policy_digest,
        proof_action=proof.required_action,
        proof_status=proof.status,
        direct_effect_action=direct.required_action,
        direct_effect_status=direct.status,
    )


@dataclass(frozen=True, slots=True)
class PhaseBIdentityBinding:
    """Immutable, private binding for one exact Phase B execution."""

    authority_account_id: str
    management_account_id: str
    region: str
    identity_center_application_arn: str
    identity_center_instance_arn: str
    identity_store_arn: str
    redirect_uri: str
    operator_user_id: str = field(repr=False)
    invoker_role_arn: str
    broker_execution_role_arn: str
    proof_role_arn: str
    ledger_table_arn: str
    stack_arn: str
    change_set_arn: str
    client_request_token: str
    phase_b_intent_digest: str
    change_set_receipt_digest: str
    template_digest: str
    parameters_digest: str
    resource_inventory_digest: str
    ledger_controls_digest: str
    oauth_state_digest: str
    invoker_policy_sha256: str
    broker_policy_sha256: str
    proof_policy_sha256: str
    application_actor_policy_sha256: str
    broker_artifact_bucket: str
    broker_artifact_key: str
    broker_artifact_version: str
    broker_artifact_code_sha256: str
    broker_code_signing_config_arn: str
    broker_topology_provider_evidence_digest: str | None
    broker_topology_signing_key_arn: str
    broker_topology_signature_algorithm: str
    expected_broker_topology_sha256: str
    configured_execution_id: str
    execution_not_before: datetime
    execution_not_after: datetime
    proof_duration_seconds: int = PROOF_DURATION_SECONDS
    max_token_lifetime_seconds: int = MAX_TOKEN_LIFETIME_SECONDS

    def __post_init__(self) -> None:
        if (
            _ACCOUNT_ID.fullmatch(self.authority_account_id) is None
            or _ACCOUNT_ID.fullmatch(self.management_account_id) is None
            or self.authority_account_id == self.management_account_id
        ):
            raise PhaseBPepError("ACCOUNT_BINDING_INVALID")
        if _REGION.fullmatch(self.region) is None:
            raise PhaseBPepError("REGION_BINDING_INVALID")
        if _USER_ID.fullmatch(self.operator_user_id) is None:
            raise PhaseBPepError("IDENTITY_STORE_USER_INVALID")
        if _CLIENT_REQUEST_TOKEN.fullmatch(self.client_request_token) is None:
            raise PhaseBPepError("CLIENT_REQUEST_TOKEN_INVALID")
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.phase_b_intent_digest,
                self.change_set_receipt_digest,
                self.template_digest,
                self.parameters_digest,
                self.resource_inventory_digest,
                self.ledger_controls_digest,
                self.oauth_state_digest,
                self.expected_broker_topology_sha256,
            )
        ):
            raise PhaseBPepError("EVIDENCE_BINDING_INVALID")
        if (
            self.broker_topology_provider_evidence_digest is not None
            and (
                _DIGEST.fullmatch(
                    self.broker_topology_provider_evidence_digest
                )
                is None
                or self.broker_topology_provider_evidence_digest
                == "sha256:" + ("0" * 64)
            )
        ):
            raise PhaseBPepError("PROVIDER_TOPOLOGY_EVIDENCE_INVALID")
        if any(
            _RAW_DIGEST.fullmatch(value) is None
            for value in (
                self.invoker_policy_sha256,
                self.broker_policy_sha256,
                self.proof_policy_sha256,
                self.application_actor_policy_sha256,
            )
        ):
            raise PhaseBPepError("POLICY_DIGEST_BINDING_INVALID")
        if (
            _KMS_SIGNING_KEY_ARN.fullmatch(
                self.broker_topology_signing_key_arn
            )
            is None
            or self.broker_topology_signature_algorithm
            != BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
        ):
            raise PhaseBPepError("BROKER_TOPOLOGY_SIGNING_BINDING_INVALID")
        if (
            re.fullmatch(
                r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$",
                self.broker_artifact_bucket,
            )
            is None
            or not 1 <= len(self.broker_artifact_key) <= 1024
            or not 1 <= len(self.broker_artifact_version) <= 1024
            or _CODE_SHA256.fullmatch(self.broker_artifact_code_sha256)
            is None
        ):
            raise PhaseBPepError("BROKER_ARTIFACT_BINDING_INVALID")
        if (
            self.proof_duration_seconds != PROOF_DURATION_SECONDS
            or self.max_token_lifetime_seconds != MAX_TOKEN_LIFETIME_SECONDS
        ):
            raise PhaseBPepError("PROOF_LIFETIME_INVALID")
        if (
            self.execution_not_before.tzinfo is None
            or self.execution_not_after.tzinfo is None
            or self.execution_not_before.utcoffset() is None
            or self.execution_not_after.utcoffset() is None
        ):
            raise PhaseBPepError("EXECUTION_WINDOW_INVALID")
        window = (
            self.execution_not_after.astimezone(UTC)
            - self.execution_not_before.astimezone(UTC)
        )
        if not timedelta(seconds=1) <= window <= timedelta(
            seconds=MAX_WINDOW_SECONDS
        ):
            raise PhaseBPepError("EXECUTION_WINDOW_INVALID")
        parsed_redirect = urlparse(self.redirect_uri)
        if (
            parsed_redirect.scheme != "http"
            or parsed_redirect.hostname != "127.0.0.1"
            or parsed_redirect.path != "/callback"
            or parsed_redirect.port is None
            or not 1024 <= parsed_redirect.port <= 65535
            or parsed_redirect.params
            or parsed_redirect.query
            or parsed_redirect.fragment
            or parsed_redirect.username
            or parsed_redirect.password
        ):
            raise PhaseBPepError("REDIRECT_URI_INVALID")

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
        if (
            application is None
            or instance is None
            or store is None
            or application.group(1) != self.management_account_id
            or store.group(1) != self.management_account_id
            or application.group(2) != instance.group(1)
        ):
            raise PhaseBPepError("IDENTITY_CENTER_TOPOLOGY_INVALID")

        role_prefix = f"arn:{partition}:iam::{self.authority_account_id}:role/"
        invoker_role = re.fullmatch(
            rf"arn:{partition}:iam::{re.escape(self.authority_account_id)}:"
            r"role/aws-reserved/sso\.amazonaws\.com(?:/[a-z0-9-]+)?/"
            rf"AWSReservedSSO_{re.escape(INVOKER_ROLE_NAME)}_"
            r"[0-9A-Fa-f]{16}",
            self.invoker_role_arn,
        )
        if invoker_role is None:
            raise PhaseBPepError("INVOKER_ROLE_BINDING_INVALID")
        if self.broker_execution_role_arn != role_prefix + BROKER_ROLE_NAME:
            raise PhaseBPepError("BROKER_ROLE_BINDING_INVALID")
        if self.proof_role_arn != role_prefix + PROOF_ROLE_NAME:
            raise PhaseBPepError("PROOF_ROLE_BINDING_INVALID")
        expected_table = (
            f"arn:{partition}:dynamodb:{self.region}:{self.authority_account_id}:"
            f"table/{LEDGER_TABLE_NAME}"
        )
        if self.ledger_table_arn != expected_table:
            raise PhaseBPepError("LEDGER_BINDING_INVALID")
        stack_match = re.fullmatch(
            rf"arn:{partition}:cloudformation:{re.escape(self.region)}:"
            rf"{re.escape(self.authority_account_id)}:stack/"
            rf"{re.escape(STACK_NAME)}/"
            r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})",
            self.stack_arn,
        )
        change_set_match = re.fullmatch(
            rf"arn:{partition}:cloudformation:{re.escape(self.region)}:"
            rf"{re.escape(self.authority_account_id)}:changeSet/"
            rf"{re.escape(CHANGE_SET_NAME)}/"
            r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})",
            self.change_set_arn,
        )
        if stack_match is None or change_set_match is None:
            raise PhaseBPepError("CLOUDFORMATION_TARGET_INVALID")
        expected_csc = re.fullmatch(
            rf"arn:{partition}:lambda:{re.escape(self.region)}:"
            rf"{re.escape(self.authority_account_id)}:"
            r"code-signing-config:csc-[a-z0-9]{17}",
            self.broker_code_signing_config_arn,
        )
        if expected_csc is None:
            raise PhaseBPepError("BROKER_CODE_SIGNING_BINDING_INVALID")
        if self.configured_execution_id != self.execution_id:
            raise PhaseBPepError("EXECUTION_ID_BINDING_INVALID")
        if self.expected_broker_topology_sha256 != self.broker_topology_sha256:
            raise PhaseBPepError("BROKER_TOPOLOGY_DIGEST_MISMATCH")

    @property
    def execution_request(self) -> dict[str, str]:
        return {
            "ChangeSetName": self.change_set_arn,
            "StackName": self.stack_arn,
            "ClientRequestToken": self.client_request_token,
        }

    @property
    def execution_request_digest(self) -> str:
        return canonical_digest(self.execution_request)

    @property
    def execution_id(self) -> str:
        digest = canonical_digest(
            {
                "phase": "B_PEP_EXECUTION",
                "execution_request_digest": self.execution_request_digest,
                "not_before": _timestamp(self.execution_not_before),
                "not_after": _timestamp(self.execution_not_after),
            }
        ).removeprefix("sha256:")
        value = "gug221-phase-b-" + digest
        if _EXECUTION_ID.fullmatch(value) is None:  # pragma: no cover
            raise PhaseBPepError("EXECUTION_ID_INVALID")
        return value

    @property
    def broker_alias_arn(self) -> str:
        return (
            f"arn:{_partition(self.region)}:lambda:{self.region}:"
            f"{self.authority_account_id}:function:{FUNCTION_NAME}:"
            f"{FUNCTION_ALIAS}"
        )

    @property
    def broker_environment_variables(self) -> Mapping[str, str]:
        """Return the complete reviewed environment of the published broker.

        Fresh provider evidence is intentionally absent.  Every value here is
        known before the immutable version is published and must be read back
        exactly before the provider topology receipt can be signed.
        """

        return {
            "AUTHORITY_ACCOUNT_ID": self.authority_account_id,
            "MANAGEMENT_ACCOUNT_ID": self.management_account_id,
            "AUTHORITY_REGION": self.region,
            "IDENTITY_CENTER_APPLICATION_ARN": (
                self.identity_center_application_arn
            ),
            "IDENTITY_CENTER_INSTANCE_ARN": (
                self.identity_center_instance_arn
            ),
            "IDENTITY_STORE_ARN": self.identity_store_arn,
            "IDENTITY_CENTER_REDIRECT_URI": self.redirect_uri,
            "OPERATOR_IDENTITY_STORE_USER_ID": self.operator_user_id,
            "INVOKER_ROLE_ARN": self.invoker_role_arn,
            "BROKER_EXECUTION_ROLE_ARN": self.broker_execution_role_arn,
            "PROOF_ROLE_ARN": self.proof_role_arn,
            "EXECUTION_LEDGER_TABLE_ARN": self.ledger_table_arn,
            "EXACT_STACK_ARN": self.stack_arn,
            "EXACT_CHANGE_SET_ARN": self.change_set_arn,
            "EXACT_CLIENT_REQUEST_TOKEN": self.client_request_token,
            "EXECUTION_NOT_BEFORE": _timestamp(self.execution_not_before),
            "CONFIGURED_EXECUTION_ID": self.configured_execution_id,
            "EXECUTION_NOT_AFTER": _timestamp(self.execution_not_after),
            "PHASE_B_INTENT_DIGEST": self.phase_b_intent_digest,
            "CHANGE_SET_RECEIPT_DIGEST": self.change_set_receipt_digest,
            "TEMPLATE_DIGEST": self.template_digest,
            "PARAMETERS_DIGEST": self.parameters_digest,
            "RESOURCE_INVENTORY_DIGEST": self.resource_inventory_digest,
            "LEDGER_CONTROLS_DIGEST": self.ledger_controls_digest,
            "OAUTH_STATE_DIGEST": self.oauth_state_digest,
            "INVOKER_POLICY_SHA256": self.invoker_policy_sha256,
            "BROKER_POLICY_SHA256": self.broker_policy_sha256,
            "PROOF_POLICY_SHA256": self.proof_policy_sha256,
            "APPLICATION_ACTOR_POLICY_SHA256": (
                self.application_actor_policy_sha256
            ),
            "BROKER_ARTIFACT_BUCKET": self.broker_artifact_bucket,
            "BROKER_ARTIFACT_KEY": self.broker_artifact_key,
            "BROKER_ARTIFACT_VERSION": self.broker_artifact_version,
            "BROKER_ARTIFACT_CODE_SHA256": (
                self.broker_artifact_code_sha256
            ),
            "BROKER_CODE_SIGNING_CONFIG_ARN": (
                self.broker_code_signing_config_arn
            ),
            "BROKER_TOPOLOGY_SIGNING_KEY_ARN": (
                self.broker_topology_signing_key_arn
            ),
            "BROKER_TOPOLOGY_SIGNATURE_ALGORITHM": (
                self.broker_topology_signature_algorithm
            ),
            "EXPECTED_BROKER_TOPOLOGY_SHA256": (
                self.expected_broker_topology_sha256
            ),
        }

    @property
    def broker_environment_variables_sha256(self) -> str:
        """Digest the exact provider-readback projection without serializing it."""

        return canonical_digest(
            {
                "schema_version": "1",
                "record_type": (
                    "platform_authority_lambda_audit_repair_phase_b_"
                    "broker_environment_projection"
                ),
                "variables": dict(self.broker_environment_variables),
            }
        )

    @property
    def broker_topology_sha256(self) -> str:
        """Bind only immutable configuration known before first deployment.

        Fresh provider readback is deliberately excluded. It is collected only
        after the immutable alias exists, signed separately, and supplied in
        the exact synchronous invocation payload.
        """

        return calculate_broker_topology_sha256(
            {
                "authority_account_id": self.authority_account_id,
                "management_account_id": self.management_account_id,
                "region": self.region,
                "identity_center_application_arn": (
                    self.identity_center_application_arn
                ),
                "identity_center_instance_arn": self.identity_center_instance_arn,
                "identity_store_arn": self.identity_store_arn,
                "operator_user_id_digest": _secret_digest(
                    "identity_store_user_id", self.operator_user_id.lower()
                ),
                "invoker_role_arn": self.invoker_role_arn,
                "broker_execution_role_arn": self.broker_execution_role_arn,
                "proof_role_arn": self.proof_role_arn,
                "ledger_table_arn": self.ledger_table_arn,
                "broker_alias_arn": self.broker_alias_arn,
                "broker_artifact_bucket": self.broker_artifact_bucket,
                "broker_artifact_key": self.broker_artifact_key,
                "broker_artifact_version": self.broker_artifact_version,
                "broker_artifact_code_sha256": (
                    self.broker_artifact_code_sha256
                ),
                "broker_code_signing_config_arn": (
                    self.broker_code_signing_config_arn
                ),
                "invoker_policy_sha256": self.invoker_policy_sha256,
                "broker_policy_sha256": self.broker_policy_sha256,
                "proof_policy_sha256": self.proof_policy_sha256,
                "application_actor_policy_sha256": (
                    self.application_actor_policy_sha256
                ),
                "topology_signing_key_arn": (
                    self.broker_topology_signing_key_arn
                ),
                "topology_signature_algorithm": (
                    self.broker_topology_signature_algorithm
                ),
            }
        )

    @property
    def binding_digest(self) -> str:
        return canonical_digest(
            {
                "authority_account_id": self.authority_account_id,
                "management_account_id": self.management_account_id,
                "region": self.region,
                "identity_center_application_arn": (
                    self.identity_center_application_arn
                ),
                "identity_center_instance_arn": self.identity_center_instance_arn,
                "identity_store_arn": self.identity_store_arn,
                "redirect_uri": self.redirect_uri,
                "operator_user_id": self.operator_user_id.lower(),
                "invoker_role_arn": self.invoker_role_arn,
                "broker_execution_role_arn": self.broker_execution_role_arn,
                "proof_role_arn": self.proof_role_arn,
                "ledger_table_arn": self.ledger_table_arn,
                "stack_arn": self.stack_arn,
                "change_set_arn": self.change_set_arn,
                "client_request_token": self.client_request_token,
                "phase_b_intent_digest": self.phase_b_intent_digest,
                "change_set_receipt_digest": self.change_set_receipt_digest,
                "template_digest": self.template_digest,
                "parameters_digest": self.parameters_digest,
                "resource_inventory_digest": self.resource_inventory_digest,
                "ledger_controls_digest": self.ledger_controls_digest,
                "oauth_state_digest": self.oauth_state_digest,
                "broker_topology_sha256": self.broker_topology_sha256,
                "broker_topology_signing_key_arn": (
                    self.broker_topology_signing_key_arn
                ),
                "broker_topology_signature_algorithm": (
                    self.broker_topology_signature_algorithm
                ),
                "execution_not_before": _timestamp(self.execution_not_before),
                "execution_not_after": _timestamp(self.execution_not_after),
                "proof_duration_seconds": self.proof_duration_seconds,
                "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            }
        )

    def validate_window(self, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise PhaseBPepError("CLOCK_INVALID")
        observed = now.astimezone(UTC)
        if not (
            self.execution_not_before.astimezone(UTC)
            <= observed
            < self.execution_not_after.astimezone(UTC)
        ):
            raise PhaseBPepError("EXECUTION_WINDOW_CLOSED")

    def to_dict(self) -> dict[str, Any]:
        if self.broker_topology_provider_evidence_digest is None:
            raise PhaseBPepError("PROVIDER_TOPOLOGY_EVIDENCE_REQUIRED")
        return {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_identity_binding"
            ),
            "environment": "non-production",
            "production": False,
            "authority_account_id": self.authority_account_id,
            "management_account_id": self.management_account_id,
            "region": self.region,
            "identity_center_application_arn": self.identity_center_application_arn,
            "identity_center_instance_arn": self.identity_center_instance_arn,
            "identity_store_arn": self.identity_store_arn,
            "redirect_uri": self.redirect_uri,
            "operator_user_id": self.operator_user_id,
            "invoker_role_arn": self.invoker_role_arn,
            "broker_execution_role_arn": self.broker_execution_role_arn,
            "proof_role_arn": self.proof_role_arn,
            "ledger_table_arn": self.ledger_table_arn,
            "stack_arn": self.stack_arn,
            "change_set_arn": self.change_set_arn,
            "change_set_name": CHANGE_SET_NAME,
            "client_request_token": self.client_request_token,
            "phase_b_intent_digest": self.phase_b_intent_digest,
            "change_set_receipt_digest": self.change_set_receipt_digest,
            "template_digest": self.template_digest,
            "parameters_digest": self.parameters_digest,
            "resource_inventory_digest": self.resource_inventory_digest,
            "ledger_controls_digest": self.ledger_controls_digest,
            "oauth_state_digest": self.oauth_state_digest,
            "invoker_policy_sha256": self.invoker_policy_sha256,
            "broker_policy_sha256": self.broker_policy_sha256,
            "proof_policy_sha256": self.proof_policy_sha256,
            "application_actor_policy_sha256": (
                self.application_actor_policy_sha256
            ),
            "broker_artifact_code_sha256": self.broker_artifact_code_sha256,
            "broker_code_signing_config_arn": (
                self.broker_code_signing_config_arn
            ),
            "broker_alias_arn": self.broker_alias_arn,
            "broker_topology_provider_evidence_digest": (
                self.broker_topology_provider_evidence_digest
            ),
            "broker_topology_signing_key_arn": (
                self.broker_topology_signing_key_arn
            ),
            "broker_topology_signature_algorithm": (
                self.broker_topology_signature_algorithm
            ),
            "provider_readback_required": True,
            "provider_readback_evidence_bound": True,
            "live_provider_state_verified_by_broker": False,
            "broker_topology_sha256": self.broker_topology_sha256,
            "execution_request_digest": self.execution_request_digest,
            "execution_id": self.execution_id,
            "execution_not_before": _timestamp(self.execution_not_before),
            "execution_not_after": _timestamp(self.execution_not_after),
            "proof_duration_seconds": self.proof_duration_seconds,
            "max_token_lifetime_seconds": self.max_token_lifetime_seconds,
            "identity_session_mode": PROOF_ONLY_SESSION_MODE,
            "direct_identity_session_execute_change_set": False,
            "effect_principal_type": "AWS_SERVICE_ROLE",
            "native_on_behalf_of": False,
            "binding_digest": self.binding_digest,
        }


@dataclass(slots=True)
class AuthorizationCodeEnvelope:
    """Sensitive one-shot request material that is never serialized."""

    authorization_code: str = field(repr=False)
    code_verifier: str = field(repr=False)
    oauth_state: str = field(repr=False)
    redirect_uri: str
    _consumed: bool = field(default=False, init=False, repr=False)

    @classmethod
    def from_direct_invoke_event(
        cls,
        event: object,
        *,
        binding: PhaseBIdentityBinding,
        now: datetime,
    ) -> "AuthorizationCodeEnvelope":
        binding.validate_window(now)
        if binding.broker_topology_provider_evidence_digest is None:
            raise PhaseBPepError("PROVIDER_TOPOLOGY_EVIDENCE_REQUIRED")
        if not isinstance(event, dict):
            raise PhaseBPepError("TRANSPORT_REQUEST_INVALID")
        if set(event) != REQUEST_KEYS:
            raise PhaseBPepError("REQUEST_AUTHORITY_FORBIDDEN")
        body = dict(event)
        # Direct Lambda invocation avoids SigV4 headers in the event.  Clear
        # the only sensitive payload as soon as a private in-memory envelope
        # owns it.
        event.clear()
        topology_evidence: object = body.get("broker_topology_evidence")
        try:
            if (
                body.get("schema_version") != "1"
                or body.get("record_type")
                != (
                    "platform_authority_lambda_audit_repair_phase_b_"
                    "proof_request"
                )
            ):
                raise PhaseBPepError("REQUEST_BINDING_INVALID")
            if (
                type(topology_evidence) is not dict
                or topology_evidence.get("receipt_digest")
                != binding.broker_topology_provider_evidence_digest
                or topology_evidence.get("broker_topology_sha256")
                != binding.broker_topology_sha256
            ):
                raise PhaseBPepError("REQUEST_BINDING_INVALID")
            code = body.get("authorization_code")
            verifier = body.get("code_verifier")
            oauth_state = body.get("oauth_state")
            if (
                not isinstance(code, str)
                or not 8 <= len(code) <= 4096
                or code.isspace()
                or not isinstance(verifier, str)
                or _PKCE_VERIFIER.fullmatch(verifier) is None
                or len(set(verifier)) < 8
                or not isinstance(oauth_state, str)
                or _OAUTH_STATE.fullmatch(oauth_state) is None
                or _secret_digest("oauth_state", oauth_state)
                != binding.oauth_state_digest
            ):
                raise PhaseBPepError("AUTHORIZATION_CODE_MALFORMED")
            return cls(
                authorization_code=code,
                code_verifier=verifier,
                oauth_state=oauth_state,
                redirect_uri=binding.redirect_uri,
            )
        finally:
            if isinstance(topology_evidence, dict):
                topology_evidence.clear()
            body.clear()

    def consume_once(self) -> tuple[str, str, str]:
        if self._consumed:
            raise PhaseBPepError("AUTHORIZATION_CODE_REPLAY")
        self._consumed = True
        code = self.authorization_code
        verifier = self.code_verifier
        redirect_uri = self.redirect_uri
        self.authorization_code = ""
        self.code_verifier = ""
        self.oauth_state = ""
        return code, verifier, redirect_uri


class SsoOidcClient(Protocol):
    def create_token_with_iam(self, **kwargs: Any) -> Mapping[str, Any]: ...


class StsClient(Protocol):
    def assume_role(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PhaseBProofReceipt:
    binding_digest: str
    expected_user_id_digest: str
    proof_role_arn_digest: str
    proof_session_arn_digest: str
    token_pair_digest: str
    proof_expires_at: str
    phase_b_intent_digest: str
    change_set_receipt_digest: str
    execution_request_digest: str
    template_digest: str
    parameters_digest: str
    resource_inventory_digest: str
    ledger_controls_digest: str
    broker_topology_sha256: str
    broker_topology_provider_evidence_digest: str
    invoker_policy_sha256: str
    broker_policy_sha256: str
    proof_policy_sha256: str
    application_actor_policy_sha256: str
    managed_policy_digest: str = POLICY_SNAPSHOT_DIGEST

    def __post_init__(self) -> None:
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.binding_digest,
                self.expected_user_id_digest,
                self.proof_role_arn_digest,
                self.proof_session_arn_digest,
                self.token_pair_digest,
                self.phase_b_intent_digest,
                self.change_set_receipt_digest,
                self.execution_request_digest,
                self.template_digest,
                self.parameters_digest,
                self.resource_inventory_digest,
                self.ledger_controls_digest,
                self.broker_topology_sha256,
                self.broker_topology_provider_evidence_digest,
                self.managed_policy_digest,
            )
        ):
            raise PhaseBPepError("PROOF_RECEIPT_DIGEST_INVALID")
        if any(
            _RAW_DIGEST.fullmatch(value) is None
            for value in (
                self.invoker_policy_sha256,
                self.broker_policy_sha256,
                self.proof_policy_sha256,
                self.application_actor_policy_sha256,
            )
        ):
            raise PhaseBPepError("PROOF_POLICY_DIGEST_INVALID")
        parse_timestamp(self.proof_expires_at, code="PROOF_EXPIRATION_INVALID")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_proof_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": "IDENTITY_CONTEXT_PROOF_VERIFIED",
            "binding_digest": self.binding_digest,
            "managed_policy_arn": AWS_IDENTITY_CONTEXT_POLICY_ARN,
            "managed_policy_version": POLICY_SNAPSHOT_VERSION,
            "managed_policy_digest": self.managed_policy_digest,
            "proof_required_action": PROOF_REQUIRED_ACTION,
            "direct_effect_action": DIRECT_EFFECT_ACTION,
            "direct_effect_status": DIRECT_EFFECT_BLOCKED,
            "expected_user_id_digest": self.expected_user_id_digest,
            "proof_role_arn_digest": self.proof_role_arn_digest,
            "proof_session_arn_digest": self.proof_session_arn_digest,
            "token_pair_digest": self.token_pair_digest,
            "phase_b_intent_digest": self.phase_b_intent_digest,
            "change_set_receipt_digest": self.change_set_receipt_digest,
            "execution_request_digest": self.execution_request_digest,
            "template_digest": self.template_digest,
            "parameters_digest": self.parameters_digest,
            "resource_inventory_digest": self.resource_inventory_digest,
            "ledger_controls_digest": self.ledger_controls_digest,
            "broker_topology_sha256": self.broker_topology_sha256,
            "broker_topology_provider_evidence_digest": (
                self.broker_topology_provider_evidence_digest
            ),
            "invoker_policy_sha256": self.invoker_policy_sha256,
            "broker_policy_sha256": self.broker_policy_sha256,
            "proof_policy_sha256": self.proof_policy_sha256,
            "application_actor_policy_sha256": (
                self.application_actor_policy_sha256
            ),
            "proof_expires_at": self.proof_expires_at,
            "provided_context_count": 1,
            "provided_context_provider_arn": (
                IDENTITY_CENTER_CONTEXT_PROVIDER_ARN
            ),
            "identity_context_user_binding": (
                "VERIFIED_BY_EXACT_STS_SET_CONTEXT_TRUST"
            ),
            "id_token_serialized": False,
            "identity_context_serialized": False,
            "credentials_exposed": False,
            "credentials_consumed_for_effect": False,
            "live_effect_authorized": False,
            "native_on_behalf_of": False,
        }
        value["receipt_digest"] = canonical_digest(value)
        return value

    @property
    def receipt_digest(self) -> str:
        return str(self.to_dict()["receipt_digest"])


class PhaseBIdentityProofVerifier:
    """Exchange one user grant and destroy one deny-all proof session."""

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
        event: object,
        binding: PhaseBIdentityBinding,
        now: datetime,
    ) -> PhaseBProofReceipt:
        compatibility = identity_context_compatibility()
        binding.validate_window(now)
        provider_evidence_digest = (
            binding.broker_topology_provider_evidence_digest
        )
        if provider_evidence_digest is None:
            raise PhaseBPepError("PROVIDER_TOPOLOGY_EVIDENCE_REQUIRED")
        envelope = AuthorizationCodeEnvelope.from_direct_invoke_event(
            event,
            binding=binding,
            now=now,
        )
        code, verifier, redirect_uri = envelope.consume_once()
        token_response: Mapping[str, Any] | None = None
        try:
            try:
                token_response = self._oidc.create_token_with_iam(
                    clientId=binding.identity_center_application_arn,
                    grantType=AUTHORIZATION_CODE_GRANT,
                    code=code,
                    codeVerifier=verifier,
                    redirectUri=redirect_uri,
                    scope=list(REQUIRED_SCOPES),
                )
            except Exception:
                raise PhaseBPepError("OIDC_EXCHANGE_UNCERTAIN") from None
        finally:
            code = ""
            verifier = ""
            redirect_uri = ""

        id_token = ""
        identity_context = ""
        try:
            id_token, identity_context = self._validate_token_response(
                token_response,
                max_lifetime=binding.max_token_lifetime_seconds,
            )
            token_pair_digest = canonical_digest(
                {
                    "id_token_sha256": _secret_digest("id_token", id_token),
                    "identity_context_sha256": _secret_digest(
                        "identity_context", identity_context
                    ),
                }
            )
        finally:
            if isinstance(token_response, dict):
                details = token_response.get("awsAdditionalDetails")
                if isinstance(details, dict):
                    details.clear()
                token_response.clear()
        session_name = "gug221-phase-b-" + secrets.token_hex(8)
        if _SESSION_NAME.fullmatch(session_name) is None:  # pragma: no cover
            raise PhaseBPepError("PROOF_SESSION_NAME_INVALID")

        sts_response: Mapping[str, Any] | None = None
        request_started_at = self._clock()
        try:
            try:
                sts_response = self._sts.assume_role(
                    RoleArn=binding.proof_role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=binding.proof_duration_seconds,
                    ProvidedContexts=[
                        {
                            "ProviderArn": (
                                IDENTITY_CENTER_CONTEXT_PROVIDER_ARN
                            ),
                            "ContextAssertion": identity_context,
                        }
                    ],
                )
            except Exception:
                raise PhaseBPepError("STS_PROOF_UNCERTAIN") from None
        finally:
            id_token = ""
            identity_context = ""
        response_received_at = self._clock()
        try:
            expiration, assumed_role_arn = self._validate_sts_response(
                sts_response,
                binding=binding,
                request_started_at=request_started_at,
                response_received_at=response_received_at,
            )
        finally:
            if isinstance(sts_response, dict):
                credentials = sts_response.get("Credentials")
                if isinstance(credentials, dict):
                    credentials.clear()
                sts_response.clear()
        return PhaseBProofReceipt(
            binding_digest=binding.binding_digest,
            expected_user_id_digest=_secret_digest(
                "identity_store_user_id", binding.operator_user_id.lower()
            ),
            proof_role_arn_digest=_secret_digest(
                "proof_role_arn", binding.proof_role_arn
            ),
            proof_session_arn_digest=_secret_digest(
                "proof_session_arn", assumed_role_arn
            ),
            token_pair_digest=token_pair_digest,
            proof_expires_at=_timestamp(expiration),
            phase_b_intent_digest=binding.phase_b_intent_digest,
            change_set_receipt_digest=binding.change_set_receipt_digest,
            execution_request_digest=binding.execution_request_digest,
            template_digest=binding.template_digest,
            parameters_digest=binding.parameters_digest,
            resource_inventory_digest=binding.resource_inventory_digest,
            ledger_controls_digest=binding.ledger_controls_digest,
            broker_topology_sha256=binding.broker_topology_sha256,
            broker_topology_provider_evidence_digest=(
                provider_evidence_digest
            ),
            invoker_policy_sha256=binding.invoker_policy_sha256,
            broker_policy_sha256=binding.broker_policy_sha256,
            proof_policy_sha256=binding.proof_policy_sha256,
            application_actor_policy_sha256=(
                binding.application_actor_policy_sha256
            ),
            managed_policy_digest=compatibility.managed_policy_digest,
        )

    @staticmethod
    def _validate_token_response(
        response: Mapping[str, Any] | None,
        *,
        max_lifetime: int,
    ) -> tuple[str, str]:
        if not isinstance(response, Mapping):
            raise PhaseBPepError("OIDC_RESPONSE_MALFORMED")
        if response.get("refreshToken"):
            raise PhaseBPepError("OIDC_REFRESH_TOKEN_FORBIDDEN")
        if response.get("tokenType") != "Bearer":
            raise PhaseBPepError("OIDC_TOKEN_TYPE_MISMATCH")
        if response.get("scope") != list(REQUIRED_SCOPES):
            raise PhaseBPepError("OIDC_SCOPE_MISMATCH")
        expires_in = response.get("expiresIn")
        if (
            not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 60 <= expires_in <= max_lifetime
        ):
            raise PhaseBPepError("OIDC_TOKEN_LIFETIME_INVALID")
        access_token = response.get("accessToken")
        id_token = response.get("idToken")
        details = response.get("awsAdditionalDetails")
        identity_context = (
            details.get("identityContext")
            if isinstance(details, Mapping)
            else None
        )
        if (
            not isinstance(access_token, str)
            or not 4 <= len(access_token) <= 16384
            or not isinstance(id_token, str)
            or not 4 <= len(id_token) <= 32768
            or not isinstance(identity_context, str)
            or not 4 <= len(identity_context) <= 4096
        ):
            raise PhaseBPepError("OIDC_USER_CONTEXT_MALFORMED")
        return id_token, identity_context

    @staticmethod
    def _validate_sts_response(
        response: Mapping[str, Any] | None,
        *,
        binding: PhaseBIdentityBinding,
        request_started_at: datetime,
        response_received_at: datetime,
    ) -> tuple[datetime, str]:
        if not isinstance(response, Mapping):
            raise PhaseBPepError("STS_RESPONSE_MALFORMED")
        assumed = response.get("AssumedRoleUser")
        assumed_arn = (
            assumed.get("Arn") if isinstance(assumed, Mapping) else None
        )
        expected = re.compile(
            rf"arn:{_partition(binding.region)}:sts::"
            rf"{re.escape(binding.authority_account_id)}:assumed-role/"
            rf"{re.escape(PROOF_ROLE_NAME)}/gug221-phase-b-[0-9a-f]{{16}}"
        )
        if (
            not isinstance(assumed_arn, str)
            or expected.fullmatch(assumed_arn) is None
        ):
            raise PhaseBPepError("STS_PROOF_ROLE_MISMATCH")
        credentials = response.get("Credentials")
        if not isinstance(credentials, Mapping) or set(credentials) != {
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
        }:
            raise PhaseBPepError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        if any(
            not isinstance(credentials.get(key), str) or not credentials.get(key)
            for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")
        ):
            raise PhaseBPepError("STS_CREDENTIAL_RESPONSE_MALFORMED")
        expiration = credentials.get("Expiration")
        if (
            request_started_at.tzinfo is None
            or response_received_at.tzinfo is None
            or not isinstance(expiration, datetime)
            or expiration.tzinfo is None
        ):
            raise PhaseBPepError("STS_EXPIRATION_INVALID")
        started = request_started_at.astimezone(UTC)
        received = response_received_at.astimezone(UTC)
        expires = expiration.astimezone(UTC)
        skew = timedelta(seconds=STS_CLOCK_SKEW_SECONDS)
        if (
            received < started - skew
            or expires <= received
            or expires
            > started
            + timedelta(seconds=binding.proof_duration_seconds)
            + skew
        ):
            raise PhaseBPepError("STS_EXPIRATION_INVALID")
        return expires, assumed_arn


LEDGER_STATUSES = frozenset(
    {
        "ATTEMPTED",
        "DISPATCH_ACCEPTED",
        "UNCERTAIN_RECONCILE_ONLY",
    }
)


@dataclass(frozen=True, slots=True)
class OneShotExecutionLedger:
    execution_id: str
    binding_digest: str
    proof_receipt_digest: str
    execution_request_digest: str
    broker_topology_sha256: str
    broker_topology_provider_evidence_digest: str
    invoker_policy_sha256: str
    broker_policy_sha256: str
    proof_policy_sha256: str
    application_actor_policy_sha256: str
    stack_arn: str
    change_set_arn: str
    client_request_token: str
    execution_not_before: str
    execution_not_after: str
    claimed_at: str
    status: str = "ATTEMPTED"
    terminal_at: str | None = None
    attempts: int = 1
    execution_gate_consumed: bool = True
    retry_permitted: bool = False
    native_on_behalf_of: bool = False

    def __post_init__(self) -> None:
        if (
            _EXECUTION_ID.fullmatch(self.execution_id) is None
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.binding_digest,
                    self.proof_receipt_digest,
                    self.execution_request_digest,
                    self.broker_topology_sha256,
                    self.broker_topology_provider_evidence_digest,
                )
            )
            or any(
                _RAW_DIGEST.fullmatch(value) is None
                for value in (
                    self.invoker_policy_sha256,
                    self.broker_policy_sha256,
                    self.proof_policy_sha256,
                    self.application_actor_policy_sha256,
                )
            )
            or _CLIENT_REQUEST_TOKEN.fullmatch(self.client_request_token) is None
            or self.status not in LEDGER_STATUSES
            or self.attempts != 1
            or not self.execution_gate_consumed
            or self.retry_permitted
            or self.native_on_behalf_of
        ):
            raise PhaseBPepError("ONE_SHOT_LEDGER_INVALID")
        for value in (
            self.execution_not_before,
            self.execution_not_after,
            self.claimed_at,
        ):
            parse_timestamp(value, code="ONE_SHOT_LEDGER_TIME_INVALID")
        if self.status == "ATTEMPTED":
            if self.terminal_at is not None:
                raise PhaseBPepError("ONE_SHOT_LEDGER_INVALID")
        elif self.terminal_at is None:
            raise PhaseBPepError("ONE_SHOT_LEDGER_INVALID")
        if self.terminal_at is not None:
            parse_timestamp(
                self.terminal_at, code="ONE_SHOT_LEDGER_TIME_INVALID"
            )

    @classmethod
    def claim(
        cls,
        *,
        binding: PhaseBIdentityBinding,
        proof: PhaseBProofReceipt,
        now: datetime,
    ) -> "OneShotExecutionLedger":
        binding.validate_window(now)
        if proof.binding_digest != binding.binding_digest:
            raise PhaseBPepError("PROOF_BINDING_MISMATCH")
        if (
            proof.broker_topology_sha256 != binding.broker_topology_sha256
            or binding.broker_topology_provider_evidence_digest is None
            or proof.broker_topology_provider_evidence_digest
            != binding.broker_topology_provider_evidence_digest
            or proof.invoker_policy_sha256 != binding.invoker_policy_sha256
            or proof.broker_policy_sha256 != binding.broker_policy_sha256
            or proof.proof_policy_sha256 != binding.proof_policy_sha256
            or proof.application_actor_policy_sha256
            != binding.application_actor_policy_sha256
        ):
            raise PhaseBPepError("PROOF_TOPOLOGY_BINDING_MISMATCH")
        return cls(
            execution_id=binding.execution_id,
            binding_digest=binding.binding_digest,
            proof_receipt_digest=proof.receipt_digest,
            execution_request_digest=binding.execution_request_digest,
            broker_topology_sha256=binding.broker_topology_sha256,
            broker_topology_provider_evidence_digest=(
                binding.broker_topology_provider_evidence_digest
            ),
            invoker_policy_sha256=binding.invoker_policy_sha256,
            broker_policy_sha256=binding.broker_policy_sha256,
            proof_policy_sha256=binding.proof_policy_sha256,
            application_actor_policy_sha256=(
                binding.application_actor_policy_sha256
            ),
            stack_arn=binding.stack_arn,
            change_set_arn=binding.change_set_arn,
            client_request_token=binding.client_request_token,
            execution_not_before=_timestamp(binding.execution_not_before),
            execution_not_after=_timestamp(binding.execution_not_after),
            claimed_at=_timestamp(now),
        )

    def terminal(
        self, *, status: str, now: datetime
    ) -> "OneShotExecutionLedger":
        if self.status != "ATTEMPTED" or status == "ATTEMPTED":
            raise PhaseBPepError("ONE_SHOT_LEDGER_TRANSITION_INVALID")
        return replace(self, status=status, terminal_at=_timestamp(now))

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_"
                "one_shot_execution_ledger"
            ),
            "environment": "non-production",
            "production": False,
            "execution_id": self.execution_id,
            "binding_digest": self.binding_digest,
            "proof_receipt_digest": self.proof_receipt_digest,
            "execution_request_digest": self.execution_request_digest,
            "broker_topology_sha256": self.broker_topology_sha256,
            "broker_topology_provider_evidence_digest": (
                self.broker_topology_provider_evidence_digest
            ),
            "invoker_policy_sha256": self.invoker_policy_sha256,
            "broker_policy_sha256": self.broker_policy_sha256,
            "proof_policy_sha256": self.proof_policy_sha256,
            "application_actor_policy_sha256": (
                self.application_actor_policy_sha256
            ),
            "stack_arn": self.stack_arn,
            "change_set_arn": self.change_set_arn,
            "client_request_token": self.client_request_token,
            "execution_not_before": self.execution_not_before,
            "execution_not_after": self.execution_not_after,
            "claimed_at": self.claimed_at,
            "terminal_at": self.terminal_at,
            "status": self.status,
            "attempts": self.attempts,
            "execution_gate_consumed": self.execution_gate_consumed,
            "wall_clock_window_expired": (
                parse_timestamp(
                    self.terminal_at or self.claimed_at,
                    code="ONE_SHOT_LEDGER_TIME_INVALID",
                )
                >= parse_timestamp(
                    self.execution_not_after,
                    code="ONE_SHOT_LEDGER_TIME_INVALID",
                )
            ),
            "execution_ambiguous": (
                self.status == "UNCERTAIN_RECONCILE_ONLY"
            ),
            "retry_permitted": self.retry_permitted,
            "native_on_behalf_of": self.native_on_behalf_of,
        }
        value["ledger_digest"] = canonical_digest(value)
        return value

    @property
    def ledger_digest(self) -> str:
        return str(self.to_dict()["ledger_digest"])


@dataclass(frozen=True, slots=True)
class PhaseBClosurePendingReceipt:
    """Local terminal-state evidence; provider revocation is still unproven."""

    execution_id: str
    binding_digest: str
    ledger_digest: str
    broker_topology_sha256: str
    broker_topology_provider_evidence_digest: str
    execution_status: str
    issued_at: str

    def __post_init__(self) -> None:
        if (
            _EXECUTION_ID.fullmatch(self.execution_id) is None
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.binding_digest,
                    self.ledger_digest,
                    self.broker_topology_sha256,
                    self.broker_topology_provider_evidence_digest,
                )
            )
            or self.execution_status
            not in {"DISPATCH_ACCEPTED", "UNCERTAIN_RECONCILE_ONLY"}
        ):
            raise PhaseBPepError("CLOSURE_PENDING_RECEIPT_INVALID")
        parse_timestamp(self.issued_at, code="CLOSURE_PENDING_TIME_INVALID")

    @classmethod
    def from_terminal_ledger(
        cls,
        ledger: OneShotExecutionLedger,
        *,
        now: datetime,
    ) -> "PhaseBClosurePendingReceipt":
        if ledger.status not in {
            "DISPATCH_ACCEPTED",
            "UNCERTAIN_RECONCILE_ONLY",
        }:
            raise PhaseBPepError("CLOSURE_BEFORE_TERMINAL_STATE")
        return cls(
            execution_id=ledger.execution_id,
            binding_digest=ledger.binding_digest,
            ledger_digest=ledger.ledger_digest,
            broker_topology_sha256=ledger.broker_topology_sha256,
            broker_topology_provider_evidence_digest=(
                ledger.broker_topology_provider_evidence_digest
            ),
            execution_status=ledger.status,
            issued_at=_timestamp(now),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_"
                "closure_pending_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": "PROVIDER_REVOCATION_PENDING",
            "execution_id": self.execution_id,
            "binding_digest": self.binding_digest,
            "ledger_digest": self.ledger_digest,
            "broker_topology_sha256": self.broker_topology_sha256,
            "broker_topology_provider_evidence_digest": (
                self.broker_topology_provider_evidence_digest
            ),
            "execution_status": self.execution_status,
            "issued_at": self.issued_at,
            "revocation_scope": "PROVIDER_IDENTITY_AND_INVOKE_AUTHORITY",
            "execution_binding_consumed": True,
            "authority_revoked": False,
            "provider_revocation_verified": False,
            "identity_center_assignment_removed": False,
            "invoke_permission_removed": False,
            "pending_operations_absent": False,
            "extant_sessions_invalidated": False,
            "wall_clock_window_expired": False,
            "live_closure_status": (
                "PENDING_PROVIDER_READBACK_AND_SESSION_EXPIRY"
            ),
            "attempts": 1,
            "retry_permitted": False,
            "native_on_behalf_of": False,
        }
        value["receipt_digest"] = canonical_digest(value)
        return value

    @property
    def receipt_digest(self) -> str:
        return str(self.to_dict()["receipt_digest"])


@dataclass(frozen=True, slots=True)
class PhaseBBrokerEffectReceipt:
    """Sanitized receipt for one broker dispatch boundary."""

    ledger: OneShotExecutionLedger
    closure_pending: PhaseBClosurePendingReceipt
    broker_execution_role_arn: str

    def __post_init__(self) -> None:
        if (
            self.ledger.status
            not in {"DISPATCH_ACCEPTED", "UNCERTAIN_RECONCILE_ONLY"}
            or self.closure_pending.execution_id != self.ledger.execution_id
            or self.closure_pending.binding_digest != self.ledger.binding_digest
            or self.closure_pending.ledger_digest != self.ledger.ledger_digest
            or self.closure_pending.broker_topology_sha256
            != self.ledger.broker_topology_sha256
        ):
            raise PhaseBPepError("BROKER_EFFECT_RECEIPT_INVALID")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_phase_b_"
                "broker_effect_receipt"
            ),
            "environment": "non-production",
            "production": False,
            "status": self.ledger.status,
            "execution_id": self.ledger.execution_id,
            "binding_digest": self.ledger.binding_digest,
            "proof_receipt_digest": self.ledger.proof_receipt_digest,
            "ledger_digest": self.ledger.ledger_digest,
            "closure_pending_receipt_digest": (
                self.closure_pending.receipt_digest
            ),
            "execution_request_digest": self.ledger.execution_request_digest,
            "broker_topology_sha256": self.ledger.broker_topology_sha256,
            "broker_topology_provider_evidence_digest": (
                self.ledger.broker_topology_provider_evidence_digest
            ),
            "invoker_policy_sha256": self.ledger.invoker_policy_sha256,
            "broker_policy_sha256": self.ledger.broker_policy_sha256,
            "proof_policy_sha256": self.ledger.proof_policy_sha256,
            "application_actor_policy_sha256": (
                self.ledger.application_actor_policy_sha256
            ),
            "stack_arn": self.ledger.stack_arn,
            "change_set_arn": self.ledger.change_set_arn,
            "client_request_token": self.ledger.client_request_token,
            "effect_principal_type": "AWS_SERVICE_ROLE",
            "effect_principal_arn": self.broker_execution_role_arn,
            "proof_credentials_used_for_effect": False,
            "attempts": 1,
            "execution_ambiguous": (
                self.ledger.status == "UNCERTAIN_RECONCILE_ONLY"
            ),
            "retry_permitted": False,
            "one_shot_execution_gate_consumed": True,
            "native_on_behalf_of": False,
            "provider_revocation_pending": True,
            "authority_revoked": False,
            "production_status": "NO-GO",
        }
        value["receipt_digest"] = canonical_digest(value)
        return value

    @property
    def receipt_digest(self) -> str:
        return str(self.to_dict()["receipt_digest"])


class PhaseBLedgerStore(Protocol):
    def assert_open(self, *, binding: PhaseBIdentityBinding) -> None: ...

    def claim_once(self, *, ledger: OneShotExecutionLedger) -> None: ...

    def close_once(
        self,
        *,
        claimed_ledger_digest: str,
        terminal_ledger: OneShotExecutionLedger,
        closure_pending: PhaseBClosurePendingReceipt,
    ) -> None: ...


class PhaseBExecutionClient(Protocol):
    def assert_exact_target(
        self, *, binding: PhaseBIdentityBinding
    ) -> None: ...

    def execute_exact(self, *, binding: PhaseBIdentityBinding) -> None: ...


class PhaseBExecutionBroker:
    """Service-principal execution with a consumed-before-effect CAS."""

    def __init__(
        self,
        *,
        ledger_store: PhaseBLedgerStore,
        execution_client: PhaseBExecutionClient,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._ledger = ledger_store
        self._execution = execution_client
        self._clock = clock or (lambda: datetime.now(tz=UTC))

    def preflight(
        self, *, binding: PhaseBIdentityBinding, now: datetime
    ) -> None:
        binding.validate_window(now)
        self._ledger.assert_open(binding=binding)
        self._execution.assert_exact_target(binding=binding)

    def dispatch(
        self,
        *,
        binding: PhaseBIdentityBinding,
        proof: PhaseBProofReceipt,
        now: datetime,
    ) -> PhaseBBrokerEffectReceipt:
        binding.validate_window(now)
        claimed = OneShotExecutionLedger.claim(
            binding=binding,
            proof=proof,
            now=now,
        )
        try:
            self._ledger.claim_once(ledger=claimed)
        except Exception:
            # A conditional-write timeout can mean the attempt was consumed.
            # Never execute and never repeat the claim.
            terminal = claimed.terminal(
                status="UNCERTAIN_RECONCILE_ONLY",
                now=self._clock(),
            )
            closure_pending = PhaseBClosurePendingReceipt.from_terminal_ledger(
                terminal,
                now=self._clock(),
            )
            return PhaseBBrokerEffectReceipt(
                ledger=terminal,
                closure_pending=closure_pending,
                broker_execution_role_arn=binding.broker_execution_role_arn,
            )

        try:
            # The proof receipt and all proof credentials are structurally
            # absent from this interface.  The SDK client uses the Lambda
            # service role and receives only immutable binding values.
            self._execution.execute_exact(binding=binding)
            status = "DISPATCH_ACCEPTED"
        except Exception:
            status = "UNCERTAIN_RECONCILE_ONLY"
        terminal = claimed.terminal(status=status, now=self._clock())
        closure_pending = PhaseBClosurePendingReceipt.from_terminal_ledger(
            terminal,
            now=self._clock(),
        )
        try:
            self._ledger.close_once(
                claimed_ledger_digest=claimed.ledger_digest,
                terminal_ledger=terminal,
                closure_pending=closure_pending,
            )
        except Exception:
            if terminal.status != "UNCERTAIN_RECONCILE_ONLY":
                terminal = claimed.terminal(
                    status="UNCERTAIN_RECONCILE_ONLY",
                    now=self._clock(),
                )
                closure_pending = (
                    PhaseBClosurePendingReceipt.from_terminal_ledger(
                        terminal,
                        now=self._clock(),
                    )
                )
        return PhaseBBrokerEffectReceipt(
            ledger=terminal,
            closure_pending=closure_pending,
            broker_execution_role_arn=binding.broker_execution_role_arn,
        )


class PhaseBPep:
    """Orchestrate proof, one-shot CAS and service-principal execution."""

    def __init__(
        self,
        *,
        proof_verifier: PhaseBIdentityProofVerifier,
        broker: PhaseBExecutionBroker,
    ) -> None:
        self._proof = proof_verifier
        self._broker = broker

    def execute(
        self,
        *,
        event: object,
        binding: PhaseBIdentityBinding,
        broker_topology_provider_evidence_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        if (
            _DIGEST.fullmatch(broker_topology_provider_evidence_digest) is None
            or broker_topology_provider_evidence_digest
            == "sha256:" + ("0" * 64)
        ):
            raise PhaseBPepError("PROVIDER_TOPOLOGY_EVIDENCE_REQUIRED")
        bound = replace(
            binding,
            broker_topology_provider_evidence_digest=(
                broker_topology_provider_evidence_digest
            ),
        )
        # Avoid consuming the one-shot user grant when the target, ledger or
        # execution window is already closed.
        self._broker.preflight(binding=bound, now=now)
        proof = self._proof.verify(event=event, binding=bound, now=now)
        execution = self._broker.dispatch(
            binding=bound,
            proof=proof,
            now=self._broker._clock(),
        )
        return {
            "identity_proof": proof.to_dict(),
            "broker_effect": execution.to_dict(),
            "closure_pending": execution.closure_pending.to_dict(),
        }
