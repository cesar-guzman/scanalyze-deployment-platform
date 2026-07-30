"""Pure fail-closed contracts for the GUG-221 server-side repair broker.

The public Lambda event is deliberately content-free.  All authority comes from
the published Lambda version, its immutable environment, the bundled collector
policy, live provider metadata, and the durable DynamoDB claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
COLLECTOR_PERMISSION_SET_NAME = "ScanalyzeAuthorityLambdaAudit"
COLLECTOR_PERMISSION_SET_DESCRIPTION = (
    "GUG-219 read-only account-wide Lambda invocation-authority inventory"
)
COLLECTOR_SESSION_DURATION = "PT1H"
REPAIR_INVOKER_PERMISSION_SET_NAME = "ScanalyzeLambdaAuditRepair"
REPAIR_INVOKER_PERMISSION_SET_DESCRIPTION = (
    "GUG-221 invoke-only private repair PEP boundary"
)
REPAIR_INVOKER_SESSION_DURATION = "PT1H"
REPAIR_FUNCTION_NAME = "scanalyze-authority-lambda-audit-repair"
PLAN_FUNCTION_NAME = "scanalyze-authority-lambda-audit-plan"
READ_FUNCTION_NAME = "scanalyze-authority-lambda-audit-reconcile"
REPAIR_SERVICE_ROLE_ARN = (
    "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
    "ScanalyzeLambdaAuditRepairMutationServiceRole"
)
READ_SERVICE_ROLE_ARN = (
    "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
    "ScanalyzeLambdaAuditRepairReadbackServiceRole"
)
REPAIR_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairExecution"
PLAN_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairPlan"
READ_EXECUTION_ROLE_NAME = "ScanalyzeLambdaAuditRepairReconcile"
COLLECTOR_ROLE_PREFIX = "AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_"
REPAIR_INVOKER_ROLE_PREFIX = "AWSReservedSSO_ScanalyzeLambdaAuditRepair_"
COLLECTOR_INLINE_POLICY_NAME = "AwsSSOInlinePolicy"
SAML_AUDIENCE = "https://signin.aws.amazon.com/saml"
PUBLIC_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_broker_receipt.v1"
)
PRIVATE_LEDGER_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_broker_ledger.v1"
)
SCHEMA_VERSION = 1
PRODUCTION_STATUS = "NO-GO"
PROVIDER_DERIVED_FUNCTION_VERSION = "PROVIDER_DERIVED"
MODES = frozenset({"plan", "repair", "reconcile"})
MODE_QUALIFIERS = MappingProxyType(
    {"plan": "plan-v1", "repair": "repair-v1", "reconcile": "reconcile-v1"}
)
PUBLIC_STATUSES = frozenset(
    {
        "PLAN_VERIFIED",
        "REPAIR_VERIFIED",
        "RECONCILE_VERIFIED",
        "BLOCKED",
        "UNCERTAIN_RECONCILE_ONLY",
    }
)
MUTATION_ATTRIBUTIONS = frozenset({"PROVEN_BY_DURABLE_LEDGER", "UNPROVEN"})
REQUIRED_NEXT_ACTIONS = frozenset(
    {
        "NONE",
        "INVOKE_REPAIR_ALIAS",
        "INVOKE_RECONCILE_ALIAS",
        "REVIEW_BLOCKER",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPAIR_ID_RE = re.compile(r"^gug221-[a-f0-9]{64}$")
_IDENTITY_STORE_RE = re.compile(r"^d-[0-9a-f]{10}$")
_INSTANCE_ARN_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_PERMISSION_SET_ARN_RE = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}$"
)
_PRINCIPAL_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_FUNCTION_VERSION_RE = re.compile(r"^[1-9][0-9]*$")
_SDK_VERSION_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
)
_COLLECTOR_ROLE_NAME_RE = re.compile(
    r"^AWSReservedSSO_ScanalyzeAuthorityLambdaAudit_[0-9A-Fa-f]{16}$"
)
_REPAIR_INVOKER_ROLE_NAME_RE = re.compile(
    r"^AWSReservedSSO_ScanalyzeLambdaAuditRepair_[0-9A-Fa-f]{16}$"
)
_SAML_PROVIDER_ARN_RE = re.compile(
    r"^arn:aws:iam::042360977644:saml-provider/AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
)
_KMS_ARN_RE = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/[0-9a-fA-F-]{36}$"
)
_AUTHORITY_KMS_ARN_RE = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CODE_SHA256_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_CODE_SIGNING_CONFIG_ARN_RE = re.compile(
    r"^arn:aws:lambda:us-east-1:042360977644:"
    r"code-signing-config:csc-[a-z0-9]{17}$"
)
_SIGNING_PROFILE_VERSION_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:signer:us-east-1:042360977644:"
    r"/signing-profiles/[A-Za-z0-9_]{2,64}/[A-Za-z0-9]{10}$"
)


class BrokerContractError(ValueError):
    """A deterministic fail-closed contract violation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BrokerContractError("NAIVE_TIME", "timestamps must be timezone-aware")
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def parse_utc_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BrokerContractError("INVALID_TIME", f"{field} must be a UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BrokerContractError("INVALID_TIME", f"{field} is malformed") from exc
    if parsed.microsecond:
        raise BrokerContractError("INVALID_TIME", f"{field} must not contain fractions")
    return parsed


def validate_empty_event(event: Any) -> None:
    if type(event) is not dict or event:
        raise BrokerContractError(
            "NON_EMPTY_EVENT",
            "the authoritative broker event must be exactly an empty JSON object",
        )


def _required(env: Mapping[str, str], key: str) -> str:
    value = env.get(key)
    if not isinstance(value, str) or not value:
        raise BrokerContractError("MISSING_CONFIG", f"missing immutable setting {key}")
    if value != value.strip():
        raise BrokerContractError("MALFORMED_CONFIG", f"{key} contains surrounding whitespace")
    return value


def _parse_tags(raw: str) -> tuple[tuple[str, str], ...]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrokerContractError("MALFORMED_CONFIG", "EXPECTED_PERMISSION_SET_TAGS_JSON is invalid") from exc
    if not isinstance(value, dict) or not value:
        raise BrokerContractError("MALFORMED_CONFIG", "expected tags must be a non-empty object")
    tags: list[tuple[str, str]] = []
    for key, item in value.items():
        if not isinstance(key, str) or not key or not isinstance(item, str) or not item:
            raise BrokerContractError("MALFORMED_CONFIG", "expected tags must be non-empty strings")
        tags.append((key, item))
    return tuple(sorted(tags))


@dataclass(frozen=True)
class BrokerConfig:
    mode: str
    source_commit: str
    repair_id: str
    principal_id: str
    identity_store_id: str
    instance_arn: str
    collector_permission_set_arn: str
    repair_invoker_permission_set_arn: str
    collector_policy_digest: str
    repair_invoker_policy_digest: str
    original_gug220_ledger_digest: str
    expected_permission_set_tags_json: str
    expected_permission_set_tags: tuple[tuple[str, str], ...]
    ledger_table_name: str
    repair_ledger_kms_key_arn: str
    expected_artifact_code_sha256: str
    expected_code_signing_config_arn: str
    expected_signing_profile_version_arn: str
    not_before: datetime
    not_after: datetime
    function_version: str
    repair_function_version: str
    plan_function_version: str
    function_qualifier: str
    expected_boto3_version: str
    expected_botocore_version: str
    collector_saml_provider_arn: str
    identity_center_kms_mode: str
    identity_center_kms_key_arn: str | None
    repair_service_role_arn: str = REPAIR_SERVICE_ROLE_ARN
    read_service_role_arn: str = READ_SERVICE_ROLE_ARN
    authority_account_id: str = AUTHORITY_ACCOUNT_ID
    management_account_id: str = MANAGEMENT_ACCOUNT_ID
    region: str = REGION
    collector_permission_set_name: str = COLLECTOR_PERMISSION_SET_NAME

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str],
        *,
        mode_override: str | None = None,
        qualifier_override: str | None = None,
    ) -> "BrokerConfig":
        mode = mode_override if mode_override is not None else _required(env, "FUNCTION_MODE")
        if mode not in MODES:
            raise BrokerContractError("INVALID_MODE", "FUNCTION_MODE is not recognized")
        source_commit = _required(env, "SOURCE_COMMIT")
        repair_id = _required(env, "REPAIR_ID")
        principal_id = _required(env, "PRINCIPAL_ID")
        identity_store_id = _required(env, "IDENTITY_STORE_ID")
        instance_arn = _required(env, "IDENTITY_CENTER_INSTANCE_ARN")
        permission_set_arn = _required(env, "COLLECTOR_PERMISSION_SET_ARN")
        repair_invoker_permission_set_arn = _required(
            env, "REPAIR_INVOKER_PERMISSION_SET_ARN"
        )
        collector_digest = _required(env, "COLLECTOR_POLICY_DIGEST")
        invoker_digest = _required(env, "REPAIR_INVOKER_POLICY_DIGEST")
        original_digest = _required(env, "ORIGINAL_GUG220_LEDGER_DIGEST")
        expected_tags_json = _required(env, "EXPECTED_PERMISSION_SET_TAGS_JSON")
        table_name = _required(env, "REPAIR_LEDGER_TABLE_NAME")
        repair_ledger_kms_key_arn = _required(env, "REPAIR_LEDGER_KMS_KEY_ARN")
        expected_artifact_code_sha256 = _required(
            env, "EXPECTED_ARTIFACT_CODE_SHA256"
        )
        expected_code_signing_config_arn = _required(
            env, "EXPECTED_CODE_SIGNING_CONFIG_ARN"
        )
        expected_signing_profile_version_arn = _required(
            env, "EXPECTED_SIGNING_PROFILE_VERSION_ARN"
        )
        not_before = parse_utc_timestamp(_required(env, "REPAIR_NOT_BEFORE"), "REPAIR_NOT_BEFORE")
        not_after = parse_utc_timestamp(_required(env, "REPAIR_NOT_AFTER"), "REPAIR_NOT_AFTER")
        function_version = _required(env, "AWS_LAMBDA_FUNCTION_VERSION")
        repair_function_version = (
            function_version
            if mode == "repair"
            else (
                env.get("REPAIR_FUNCTION_VERSION")
                or (
                    PROVIDER_DERIVED_FUNCTION_VERSION
                    if mode == "plan"
                    else _required(env, "REPAIR_FUNCTION_VERSION")
                )
            )
        )
        plan_function_version = (
            function_version
            if mode == "plan"
            else _required(env, "PLAN_FUNCTION_VERSION")
        )
        function_qualifier = (
            qualifier_override
            if qualifier_override is not None
            else _required(env, "FUNCTION_QUALIFIER")
        )
        expected_boto3_version = _required(env, "EXPECTED_BOTO3_VERSION")
        expected_botocore_version = _required(env, "EXPECTED_BOTOCORE_VERSION")
        saml_provider_arn = _required(env, "COLLECTOR_SAML_PROVIDER_ARN")
        kms_mode = _required(env, "IDENTITY_CENTER_KMS_MODE")
        kms_key_arn = env.get("IDENTITY_CENTER_KMS_KEY_ARN") or None

        if not _COMMIT_RE.fullmatch(source_commit):
            raise BrokerContractError("INVALID_SOURCE_COMMIT", "source commit must be lowercase SHA-1")
        if not _REPAIR_ID_RE.fullmatch(repair_id):
            raise BrokerContractError("INVALID_REPAIR_ID", "repair id is malformed")
        if not _PRINCIPAL_RE.fullmatch(principal_id):
            raise BrokerContractError("INVALID_PRINCIPAL", "principal id is malformed")
        if not _IDENTITY_STORE_RE.fullmatch(identity_store_id):
            raise BrokerContractError("INVALID_IDENTITY_STORE", "identity store id is malformed")
        if not _INSTANCE_ARN_RE.fullmatch(instance_arn):
            raise BrokerContractError("INVALID_INSTANCE", "instance ARN is malformed")
        if not _PERMISSION_SET_ARN_RE.fullmatch(permission_set_arn):
            raise BrokerContractError("INVALID_PERMISSION_SET", "permission set ARN is malformed")
        if not _PERMISSION_SET_ARN_RE.fullmatch(repair_invoker_permission_set_arn):
            raise BrokerContractError("INVALID_PERMISSION_SET", "repair invoker permission set ARN is malformed")
        if repair_invoker_permission_set_arn == permission_set_arn:
            raise BrokerContractError("PERMISSION_SET_COLLISION", "collector and repair invoker must differ")
        if repair_invoker_permission_set_arn.split("/", 2)[1] != permission_set_arn.split("/", 2)[1]:
            raise BrokerContractError("INSTANCE_BINDING_MISMATCH", "permission sets must share one instance")
        for field, digest in (
            ("collector policy", collector_digest),
            ("invoker policy", invoker_digest),
        ):
            if not _SHA256_RE.fullmatch(digest):
                raise BrokerContractError("INVALID_DIGEST", f"{field} digest is malformed")
        if not _SHA256_RE.fullmatch(original_digest):
            raise BrokerContractError(
                "INVALID_DIGEST", "original ledger digest is malformed"
            )
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name):
            raise BrokerContractError("INVALID_LEDGER_TABLE", "ledger table name is malformed")
        if not _AUTHORITY_KMS_ARN_RE.fullmatch(repair_ledger_kms_key_arn):
            raise BrokerContractError(
                "INVALID_LEDGER_KMS_KEY",
                "repair ledger KMS key ARN is malformed",
            )
        if not _CODE_SHA256_BASE64_RE.fullmatch(expected_artifact_code_sha256):
            raise BrokerContractError(
                "INVALID_ARTIFACT_CODE_SHA256",
                "reviewed Lambda artifact CodeSha256 is malformed",
            )
        if not _CODE_SIGNING_CONFIG_ARN_RE.fullmatch(
            expected_code_signing_config_arn
        ):
            raise BrokerContractError(
                "INVALID_CODE_SIGNING_CONFIG",
                "reviewed Lambda code-signing config ARN is malformed",
            )
        if not _SIGNING_PROFILE_VERSION_ARN_RE.fullmatch(
            expected_signing_profile_version_arn
        ):
            raise BrokerContractError(
                "INVALID_SIGNING_PROFILE_VERSION",
                "reviewed signing profile version ARN is malformed",
            )
        if not _FUNCTION_VERSION_RE.fullmatch(function_version):
            raise BrokerContractError("UNPUBLISHED_FUNCTION", "Lambda must execute a published numeric version")
        if (
            repair_function_version != PROVIDER_DERIVED_FUNCTION_VERSION
            and not _FUNCTION_VERSION_RE.fullmatch(repair_function_version)
        ):
            raise BrokerContractError("UNPUBLISHED_FUNCTION", "repair Lambda version must be numeric")
        if (
            repair_function_version == PROVIDER_DERIVED_FUNCTION_VERSION
            and mode != "plan"
        ):
            raise BrokerContractError(
                "UNPUBLISHED_FUNCTION", "only Plan may derive the repair Lambda version"
            )
        if not _FUNCTION_VERSION_RE.fullmatch(plan_function_version):
            raise BrokerContractError("UNPUBLISHED_FUNCTION", "plan Lambda version must be numeric")
        if function_qualifier != MODE_QUALIFIERS[mode]:
            raise BrokerContractError("MODE_QUALIFIER_MISMATCH", "function alias does not match mode")
        if not _SDK_VERSION_RE.fullmatch(expected_boto3_version):
            raise BrokerContractError(
                "INVALID_SDK_VERSION", "expected boto3 version is malformed"
            )
        if not _SDK_VERSION_RE.fullmatch(expected_botocore_version):
            raise BrokerContractError(
                "INVALID_SDK_VERSION", "expected botocore version is malformed"
            )
        if not _SAML_PROVIDER_ARN_RE.fullmatch(saml_provider_arn):
            raise BrokerContractError("INVALID_SAML_PROVIDER", "collector SAML provider ARN is malformed")
        if kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}:
            raise BrokerContractError("INVALID_KMS_MODE", "Identity Center KMS mode is unsupported")
        if kms_mode == "AWS_OWNED_KMS_KEY" and kms_key_arn is not None:
            raise BrokerContractError("INVALID_KMS_BINDING", "AWS-owned KMS mode cannot carry a key ARN")
        if kms_mode == "CUSTOMER_MANAGED_KEY" and (
            kms_key_arn is None or not _KMS_ARN_RE.fullmatch(kms_key_arn)
        ):
            raise BrokerContractError("INVALID_KMS_BINDING", "customer-managed KMS mode requires exact key ARN")
        if not_before >= not_after or not_after - not_before > timedelta(minutes=15):
            raise BrokerContractError("INVALID_WINDOW", "repair window must be positive and at most 15 minutes")

        return cls(
            mode=mode,
            source_commit=source_commit,
            repair_id=repair_id,
            principal_id=principal_id,
            identity_store_id=identity_store_id,
            instance_arn=instance_arn,
            collector_permission_set_arn=permission_set_arn,
            repair_invoker_permission_set_arn=repair_invoker_permission_set_arn,
            collector_policy_digest=collector_digest,
            repair_invoker_policy_digest=invoker_digest,
            original_gug220_ledger_digest=original_digest,
            expected_permission_set_tags_json=expected_tags_json,
            expected_permission_set_tags=_parse_tags(expected_tags_json),
            ledger_table_name=table_name,
            repair_ledger_kms_key_arn=repair_ledger_kms_key_arn,
            expected_artifact_code_sha256=expected_artifact_code_sha256,
            expected_code_signing_config_arn=expected_code_signing_config_arn,
            expected_signing_profile_version_arn=(
                expected_signing_profile_version_arn
            ),
            not_before=not_before,
            not_after=not_after,
            function_version=function_version,
            repair_function_version=repair_function_version,
            plan_function_version=plan_function_version,
            function_qualifier=function_qualifier,
            expected_boto3_version=expected_boto3_version,
            expected_botocore_version=expected_botocore_version,
            collector_saml_provider_arn=saml_provider_arn,
            identity_center_kms_mode=kms_mode,
            identity_center_kms_key_arn=kms_key_arn,
        )

    @property
    def service_role_arn(self) -> str:
        return self.repair_service_role_arn if self.mode == "repair" else self.read_service_role_arn

    @property
    def expected_repair_invoker_tags(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(
                {
                    "environment": "non-production",
                    "managed_by": "cloudformation",
                    "production": "false",
                    "service": "scanalyze-platform-authority",
                    "source_commit": self.source_commit,
                    "work_package": "GUG-221",
                }.items()
            )
        )


def validate_invocation(config: BrokerConfig, invoked_function_arn: str, caller_arn: str) -> None:
    function_name = {
        "plan": PLAN_FUNCTION_NAME,
        "repair": REPAIR_FUNCTION_NAME,
        "reconcile": READ_FUNCTION_NAME,
    }[config.mode]
    execution_role_name = {
        "plan": PLAN_EXECUTION_ROLE_NAME,
        "repair": REPAIR_EXECUTION_ROLE_NAME,
        "reconcile": READ_EXECUTION_ROLE_NAME,
    }[config.mode]
    expected = (
        f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{function_name}:{config.function_qualifier}"
    )
    if invoked_function_arn != expected:
        raise BrokerContractError("FUNCTION_BINDING_MISMATCH", "invoked function ARN is not authoritative")
    role_pattern = re.compile(
        rf"^arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        rf"{execution_role_name}/[A-Za-z0-9+=,.@_-]{{2,64}}$"
    )
    if not role_pattern.fullmatch(caller_arn):
        raise BrokerContractError("EXECUTION_ROLE_MISMATCH", "local Lambda execution role is not authoritative")


def validate_time(config: BrokerConfig, now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise BrokerContractError("NAIVE_TIME", "current time must be timezone-aware")
    normalized = now.astimezone(timezone.utc)
    if normalized < config.not_before or normalized > config.not_after:
        raise BrokerContractError("WINDOW_CLOSED", "the immutable execution window is closed")


def build_private_intent(config: BrokerConfig) -> dict[str, Any]:
    intent = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "scanalyze.platform_authority.lambda_audit_repair_broker_intent.v1",
        "mode": "repair",
        "repair_id": config.repair_id,
        "source_commit": config.source_commit,
        "function_version": config.repair_function_version,
        "plan_function_version": config.plan_function_version,
        "plan_function_version": config.plan_function_version,
        "function_qualifier": MODE_QUALIFIERS["repair"],
        "authority_account_id": config.authority_account_id,
        "management_account_id": config.management_account_id,
        "region": config.region,
        "instance_arn": config.instance_arn,
        "identity_store_id": config.identity_store_id,
        "permission_set_arn": config.collector_permission_set_arn,
        "permission_set_name": config.collector_permission_set_name,
        "repair_invoker_permission_set_arn": config.repair_invoker_permission_set_arn,
        "repair_invoker_permission_set_name": REPAIR_INVOKER_PERMISSION_SET_NAME,
        "repair_invoker_permission_set_description": (
            REPAIR_INVOKER_PERMISSION_SET_DESCRIPTION
        ),
        "repair_invoker_session_duration": REPAIR_INVOKER_SESSION_DURATION,
        "repair_invoker_relay_state": None,
        "expected_repair_invoker_tags": dict(config.expected_repair_invoker_tags),
        "principal_type": "USER",
        "principal_id": config.principal_id,
        "target_account_id": config.authority_account_id,
        "collector_policy_digest": config.collector_policy_digest,
        "repair_invoker_policy_digest": config.repair_invoker_policy_digest,
        "expected_boto3_version": config.expected_boto3_version,
        "expected_botocore_version": config.expected_botocore_version,
        "original_gug220_ledger_digest": config.original_gug220_ledger_digest,
        "repair_ledger_kms_key_arn": config.repair_ledger_kms_key_arn,
        "expected_artifact_code_sha256": config.expected_artifact_code_sha256,
        "expected_code_signing_config_arn": (
            config.expected_code_signing_config_arn
        ),
        "expected_signing_profile_version_arn": (
            config.expected_signing_profile_version_arn
        ),
        "expected_permission_set_tags": dict(config.expected_permission_set_tags),
        "repair_service_role_arn": config.repair_service_role_arn,
        "read_service_role_arn": config.read_service_role_arn,
        "collector_saml_provider_arn": config.collector_saml_provider_arn,
        "identity_center_kms_mode": config.identity_center_kms_mode,
        "identity_center_kms_key_arn": config.identity_center_kms_key_arn,
        "not_before": utc_timestamp(config.not_before),
        "not_after": utc_timestamp(config.not_after),
        "authorized_mutations": [
            "sso:PutInlinePolicyToPermissionSet",
            "sso:CreateAccountAssignment",
            "sso:ProvisionPermissionSet",
        ],
    }
    return intent


def build_private_ledger_claim(
    config: BrokerConfig, now: datetime, state_digest: str
) -> dict[str, Any]:
    """Build the create-only durable Plan record consumed by Repair.

    The historical helper name is retained because the Plan record is the
    one-shot claim for ``repair_id``.  Repair must never create this item; it
    can only consume the exact ``PLAN_VERIFIED`` record with a CAS transition.
    """

    if config.mode != "plan":
        raise BrokerContractError(
            "PLAN_MODE_REQUIRED", "only the dedicated Plan function may create the claim"
        )
    if not _SHA256_RE.fullmatch(state_digest):
        raise BrokerContractError(
            "INVALID_DIGEST", "planned provider state digest is malformed"
        )
    intent = build_private_intent(config)
    intent_digest = canonical_digest(intent)
    binding = {
        "schema_version": SCHEMA_VERSION,
        "record_type": PRIVATE_LEDGER_TYPE,
        "repair_id": config.repair_id,
        "intent_digest": intent_digest,
        "source_commit": config.source_commit,
        "original_gug220_ledger_digest": config.original_gug220_ledger_digest,
        "authority_account_id": config.authority_account_id,
        "management_account_id": config.management_account_id,
        "region": config.region,
        "plan_function_version": config.plan_function_version,
        "repair_function_version": config.repair_function_version,
        "repair_not_before": utc_timestamp(config.not_before),
        "repair_not_after": utc_timestamp(config.not_after),
        "status": "PLAN_VERIFIED",
        "stage": "PLAN_STATE_VERIFIED",
        "effects_attempted": 0,
        "effects_completed": 0,
        "planned_state_digest": state_digest,
        "state_digest": state_digest,
        "provider_immutable": True,
        "claim_condition": "attribute_not_exists(repair_id)",
        "mutation_retry_attempted": False,
        "production_authorized": False,
        "planned_at": utc_timestamp(now),
    }
    binding["ledger_digest"] = canonical_digest(binding)
    return binding


@dataclass(frozen=True)
class Assignment:
    principal_type: str
    principal_id: str
    target_account_id: str = AUTHORITY_ACCOUNT_ID


@dataclass(frozen=True)
class RepairInvokerSnapshot:
    permission_set_arn: str
    permission_set_name: str
    permission_set_description: str
    session_duration: str
    relay_state: str | None
    permission_set_tags: tuple[tuple[str, str], ...]
    inline_policy_digest: str | None
    managed_policy_arns: tuple[str, ...]
    customer_managed_policy_references: tuple[str, ...]
    permissions_boundary_present: bool
    assignments: tuple[Assignment, ...]
    provisioned_account_ids: tuple[str, ...]
    invoker_roles: tuple["CollectorRole", ...]

    def digest(self) -> str:
        return canonical_digest(
            {
                "permission_set_arn": self.permission_set_arn,
                "permission_set_name": self.permission_set_name,
                "permission_set_description": self.permission_set_description,
                "session_duration": self.session_duration,
                "relay_state": self.relay_state,
                "permission_set_tags": dict(self.permission_set_tags),
                "inline_policy_digest": self.inline_policy_digest,
                "managed_policy_arns": list(self.managed_policy_arns),
                "customer_managed_policy_references": list(
                    self.customer_managed_policy_references
                ),
                "permissions_boundary_present": self.permissions_boundary_present,
                "assignments": [
                    {
                        "principal_type": item.principal_type,
                        "principal_id": item.principal_id,
                        "target_account_id": item.target_account_id,
                    }
                    for item in self.assignments
                ],
                "provisioned_account_ids": list(self.provisioned_account_ids),
                "invoker_roles": [
                    {
                        "role_name": item.role_name,
                        "saml_provider_arn": item.saml_provider_arn,
                        "saml_audience": item.saml_audience,
                        "inline_policy_name": item.inline_policy_name,
                        "inline_policy_digest": item.inline_policy_digest,
                        "attached_managed_policy_arns": list(
                            item.attached_managed_policy_arns
                        ),
                        "extra_inline_policy_names": list(
                            item.extra_inline_policy_names
                        ),
                        "permissions_boundary_arn": item.permissions_boundary_arn,
                    }
                    for item in self.invoker_roles
                ],
            }
        )


@dataclass(frozen=True)
class CollectorRole:
    role_name: str
    saml_provider_arn: str
    saml_audience: str
    inline_policy_name: str
    inline_policy_digest: str
    attached_managed_policy_arns: tuple[str, ...] = ()
    extra_inline_policy_names: tuple[str, ...] = ()
    permissions_boundary_arn: str | None = None


@dataclass(frozen=True)
class LiveSnapshot:
    instance_arn: str
    identity_store_id: str
    kms_mode: str
    kms_key_arn: str | None
    permission_set_arn: str
    permission_set_name: str
    permission_set_description: str
    session_duration: str
    relay_state: str | None
    permission_set_tags: tuple[tuple[str, str], ...]
    inline_policy_digest: str | None
    managed_policy_arns: tuple[str, ...]
    customer_managed_policy_references: tuple[str, ...]
    permissions_boundary_present: bool
    assignments: tuple[Assignment, ...]
    provisioned_account_ids: tuple[str, ...]
    collector_roles: tuple[CollectorRole, ...]

    def digest(self) -> str:
        return canonical_digest(
            {
                "instance_arn": self.instance_arn,
                "identity_store_id": self.identity_store_id,
                "kms_mode": self.kms_mode,
                "kms_key_arn": self.kms_key_arn,
                "permission_set_arn": self.permission_set_arn,
                "permission_set_name": self.permission_set_name,
                "permission_set_description": self.permission_set_description,
                "session_duration": self.session_duration,
                "relay_state": self.relay_state,
                "permission_set_tags": dict(self.permission_set_tags),
                "inline_policy_digest": self.inline_policy_digest,
                "managed_policy_arns": list(self.managed_policy_arns),
                "customer_managed_policy_references": list(
                    self.customer_managed_policy_references
                ),
                "permissions_boundary_present": self.permissions_boundary_present,
                "assignments": [
                    {
                        "principal_type": item.principal_type,
                        "principal_id": item.principal_id,
                        "target_account_id": item.target_account_id,
                    }
                    for item in self.assignments
                ],
                "provisioned_account_ids": list(self.provisioned_account_ids),
                "collector_roles": [
                    {
                        "role_name": item.role_name,
                        "saml_provider_arn": item.saml_provider_arn,
                        "saml_audience": item.saml_audience,
                        "inline_policy_name": item.inline_policy_name,
                        "inline_policy_digest": item.inline_policy_digest,
                        "attached_managed_policy_arns": list(item.attached_managed_policy_arns),
                        "extra_inline_policy_names": list(item.extra_inline_policy_names),
                        "permissions_boundary_arn": item.permissions_boundary_arn,
                    }
                    for item in self.collector_roles
                ],
            }
        )


@dataclass(frozen=True)
class BrokerLiveSnapshot:
    invoker: RepairInvokerSnapshot
    collector: LiveSnapshot

    def digest(self) -> str:
        return canonical_digest(
            {
                "repair_invoker_state_digest": self.invoker.digest(),
                "collector_state_digest": self.collector.digest(),
            }
        )


def validate_repair_invoker_snapshot(
    config: BrokerConfig, snapshot: RepairInvokerSnapshot
) -> None:
    if snapshot.permission_set_arn != config.repair_invoker_permission_set_arn:
        raise BrokerContractError("INVOKER_PERMISSION_SET_MISMATCH", "repair invoker ARN differs")
    if snapshot.permission_set_name != REPAIR_INVOKER_PERMISSION_SET_NAME:
        raise BrokerContractError("INVOKER_PERMISSION_SET_MISMATCH", "repair invoker name differs")
    if snapshot.permission_set_description != REPAIR_INVOKER_PERMISSION_SET_DESCRIPTION:
        raise BrokerContractError("INVOKER_DESCRIPTION_MISMATCH", "repair invoker description differs")
    if snapshot.session_duration != REPAIR_INVOKER_SESSION_DURATION:
        raise BrokerContractError("INVOKER_SESSION_DURATION_MISMATCH", "repair invoker duration differs")
    if snapshot.relay_state is not None:
        raise BrokerContractError("INVOKER_RELAY_STATE_MISMATCH", "repair invoker relay state differs")
    if tuple(sorted(snapshot.permission_set_tags)) != config.expected_repair_invoker_tags:
        raise BrokerContractError("INVOKER_TAG_MISMATCH", "repair invoker tags differ")
    if snapshot.inline_policy_digest != config.repair_invoker_policy_digest:
        raise BrokerContractError("INVOKER_POLICY_MISMATCH", "repair invoker policy differs")
    if snapshot.managed_policy_arns or snapshot.customer_managed_policy_references:
        raise BrokerContractError("INVOKER_FOREIGN_POLICY", "repair invoker has policy attachments")
    if snapshot.permissions_boundary_present:
        raise BrokerContractError("INVOKER_BOUNDARY_PRESENT", "repair invoker has a boundary")
    if snapshot.assignments != (Assignment("USER", config.principal_id),):
        raise BrokerContractError("INVOKER_ASSIGNMENT_MISMATCH", "repair invoker assignment differs")
    if snapshot.provisioned_account_ids != (config.authority_account_id,):
        raise BrokerContractError("INVOKER_TARGET_MISMATCH", "repair invoker target differs")
    if len(snapshot.invoker_roles) != 1:
        raise BrokerContractError(
            "INVOKER_ROLE_COUNT_MISMATCH", "one exact repair invoker role is required"
        )
    role = snapshot.invoker_roles[0]
    if not _REPAIR_INVOKER_ROLE_NAME_RE.fullmatch(role.role_name):
        raise BrokerContractError("FOREIGN_INVOKER_ROLE", "repair invoker role name is invalid")
    if role.saml_provider_arn != config.collector_saml_provider_arn:
        raise BrokerContractError("INVOKER_SAML_TRUST_MISMATCH", "invoker SAML provider differs")
    if role.saml_audience != SAML_AUDIENCE:
        raise BrokerContractError("INVOKER_SAML_TRUST_MISMATCH", "invoker SAML audience differs")
    if role.inline_policy_name != COLLECTOR_INLINE_POLICY_NAME:
        raise BrokerContractError("INVOKER_ROLE_POLICY_MISMATCH", "invoker inline policy name differs")
    if role.inline_policy_digest != config.repair_invoker_policy_digest:
        raise BrokerContractError("INVOKER_ROLE_POLICY_MISMATCH", "invoker role policy differs")
    if role.attached_managed_policy_arns or role.extra_inline_policy_names:
        raise BrokerContractError("INVOKER_FOREIGN_ROLE_POLICY", "invoker role has extra policies")
    if role.permissions_boundary_arn is not None:
        raise BrokerContractError("INVOKER_ROLE_BOUNDARY_PRESENT", "invoker role has a boundary")


def _validate_common_snapshot(config: BrokerConfig, snapshot: LiveSnapshot) -> None:
    exact_pairs = (
        (snapshot.instance_arn, config.instance_arn, "instance"),
        (snapshot.identity_store_id, config.identity_store_id, "identity store"),
        (snapshot.permission_set_arn, config.collector_permission_set_arn, "permission set"),
        (snapshot.permission_set_name, config.collector_permission_set_name, "permission set name"),
        (
            snapshot.permission_set_description,
            COLLECTOR_PERMISSION_SET_DESCRIPTION,
            "permission set description",
        ),
        (snapshot.session_duration, COLLECTOR_SESSION_DURATION, "session duration"),
        (snapshot.relay_state, None, "relay state"),
        (snapshot.kms_mode, config.identity_center_kms_mode, "KMS mode"),
        (snapshot.kms_key_arn, config.identity_center_kms_key_arn, "KMS key"),
    )
    for observed, expected, label in exact_pairs:
        if observed != expected:
            raise BrokerContractError("LIVE_BINDING_MISMATCH", f"{label} does not match immutable config")
    if tuple(sorted(snapshot.permission_set_tags)) != config.expected_permission_set_tags:
        raise BrokerContractError("TAG_BINDING_MISMATCH", "permission set tags do not match")
    if snapshot.managed_policy_arns or snapshot.customer_managed_policy_references:
        raise BrokerContractError("FOREIGN_POLICY_ATTACHMENT", "collector permission set has attachments")
    if snapshot.permissions_boundary_present:
        raise BrokerContractError("BOUNDARY_PRESENT", "collector permission set has a boundary")
    if any(item.principal_type != "USER" for item in snapshot.assignments):
        raise BrokerContractError("FOREIGN_PRINCIPAL_TYPE", "group assignments are prohibited")
    if any(item.principal_id != config.principal_id for item in snapshot.assignments):
        raise BrokerContractError("FOREIGN_PRINCIPAL", "foreign collector principal is present")
    if any(
        item.target_account_id != config.authority_account_id
        for item in snapshot.assignments
    ):
        raise BrokerContractError("FOREIGN_TARGET", "collector assignment target is foreign")
    if any(account != config.authority_account_id for account in snapshot.provisioned_account_ids):
        raise BrokerContractError("FOREIGN_TARGET", "collector permission set is provisioned elsewhere")


def validate_collector_role(config: BrokerConfig, role: CollectorRole) -> None:
    if not _COLLECTOR_ROLE_NAME_RE.fullmatch(role.role_name):
        raise BrokerContractError("FOREIGN_COLLECTOR_ROLE", "collector role name is invalid")
    if role.saml_provider_arn != config.collector_saml_provider_arn:
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector SAML provider is not exact")
    if role.saml_audience != SAML_AUDIENCE:
        raise BrokerContractError("SAML_TRUST_MISMATCH", "collector SAML audience is not exact")
    if role.inline_policy_name != COLLECTOR_INLINE_POLICY_NAME:
        raise BrokerContractError("INLINE_POLICY_NAME_MISMATCH", "collector inline policy name is not exact")
    if role.inline_policy_digest != config.collector_policy_digest:
        raise BrokerContractError("INLINE_POLICY_MISMATCH", "collector inline policy differs")
    if role.attached_managed_policy_arns or role.extra_inline_policy_names:
        raise BrokerContractError("FOREIGN_ROLE_POLICY", "collector role has extra policies")
    if role.permissions_boundary_arn is not None:
        raise BrokerContractError("ROLE_BOUNDARY_PRESENT", "collector role has a boundary")


def validate_snapshot(config: BrokerConfig, snapshot: LiveSnapshot, stage: str) -> None:
    """Validate the only accepted state for a specific repair stage."""

    _validate_common_snapshot(config, snapshot)
    if len(snapshot.assignments) > 1 or len(snapshot.provisioned_account_ids) > 1:
        raise BrokerContractError("AMBIGUOUS_LIVE_STATE", "collector state is ambiguous")
    if len(snapshot.collector_roles) > 1:
        raise BrokerContractError("AMBIGUOUS_COLLECTOR_ROLE", "multiple collector roles exist")
    for role in snapshot.collector_roles:
        validate_collector_role(config, role)

    exact_assignment = (Assignment("USER", config.principal_id),)
    exact_target = (config.authority_account_id,)
    if stage == "BEFORE_PUT_INLINE_POLICY":
        expected = (None, (), (), ())
    elif stage == "BEFORE_CREATE_ACCOUNT_ASSIGNMENT":
        expected = (config.collector_policy_digest, (), (), ())
    elif stage == "BEFORE_PROVISION_PERMISSION_SET":
        if snapshot.inline_policy_digest != config.collector_policy_digest:
            raise BrokerContractError("POLICY_NOT_APPLIED", "collector inline policy is not exact")
        if snapshot.assignments != exact_assignment:
            raise BrokerContractError("ASSIGNMENT_NOT_APPLIED", "collector assignment is not exact")
        if snapshot.provisioned_account_ids not in ((), exact_target):
            raise BrokerContractError("TARGET_STATE_MISMATCH", "collector target is not exact")
        return
    elif stage == "FINAL":
        expected = (
            config.collector_policy_digest,
            exact_assignment,
            exact_target,
            snapshot.collector_roles,
        )
        if len(snapshot.collector_roles) != 1:
            raise BrokerContractError("COLLECTOR_ROLE_MISSING", "one exact collector role is required")
    else:
        raise BrokerContractError("UNKNOWN_STAGE", "repair stage is not recognized")

    observed = (
        snapshot.inline_policy_digest,
        snapshot.assignments,
        snapshot.provisioned_account_ids,
        snapshot.collector_roles,
    )
    if observed != expected:
        raise BrokerContractError("STAGE_STATE_MISMATCH", "live state does not match the repair stage")


def build_public_receipt(
    *,
    config: BrokerConfig,
    status: str,
    intent_digest: str,
    ledger_digest: str | None,
    state_digest: str,
    effects_attempted: int,
    effects_completed: int,
    mutation_attribution: str,
    required_next_action: str,
    generated_at: datetime,
) -> dict[str, Any]:
    if status not in PUBLIC_STATUSES:
        raise BrokerContractError("INVALID_PUBLIC_STATUS", "public status is unsupported")
    if mutation_attribution not in MUTATION_ATTRIBUTIONS:
        raise BrokerContractError("INVALID_ATTRIBUTION", "mutation attribution is unsupported")
    if required_next_action not in REQUIRED_NEXT_ACTIONS:
        raise BrokerContractError("INVALID_NEXT_ACTION", "required next action is unsupported")
    if not _SHA256_RE.fullmatch(intent_digest) or not _SHA256_RE.fullmatch(state_digest):
        raise BrokerContractError("INVALID_DIGEST", "public digest is malformed")
    if ledger_digest is not None and not _SHA256_RE.fullmatch(ledger_digest):
        raise BrokerContractError("INVALID_DIGEST", "ledger digest is malformed")
    if effects_attempted < effects_completed or effects_attempted not in range(4):
        raise BrokerContractError("INVALID_EFFECT_COUNT", "effect counts are invalid")
    if effects_completed not in range(4):
        raise BrokerContractError("INVALID_EFFECT_COUNT", "effect counts are invalid")
    if mutation_attribution == "PROVEN_BY_DURABLE_LEDGER" and not ledger_digest:
        raise BrokerContractError("UNPROVEN_ATTRIBUTION", "durable attribution requires a ledger digest")

    counts = (effects_attempted, effects_completed)
    if status == "PLAN_VERIFIED":
        exact = (
            config.mode == "plan"
            and ledger_digest is not None
            and counts == (0, 0)
            and mutation_attribution == "PROVEN_BY_DURABLE_LEDGER"
            and required_next_action == "INVOKE_REPAIR_ALIAS"
        )
    elif status == "REPAIR_VERIFIED":
        exact = (
            config.mode == "repair"
            and ledger_digest is not None
            and counts == (3, 3)
            and mutation_attribution == "PROVEN_BY_DURABLE_LEDGER"
            and required_next_action == "NONE"
        )
    elif status == "RECONCILE_VERIFIED":
        exact = (
            config.mode == "reconcile"
            and ledger_digest is not None
            and counts in {(2, 2), (3, 2), (3, 3)}
            and mutation_attribution == "PROVEN_BY_DURABLE_LEDGER"
            and required_next_action == "NONE"
        )
    elif status == "BLOCKED":
        no_ledger = (
            ledger_digest is None
            and counts == (0, 0)
            and mutation_attribution == "UNPROVEN"
        )
        bound_ledger = (
            ledger_digest is not None
            and counts in {(0, 0), (1, 1), (2, 2)}
            and mutation_attribution
            == ("PROVEN_BY_DURABLE_LEDGER" if effects_completed else "UNPROVEN")
        )
        exact = (
            required_next_action == "REVIEW_BLOCKER"
            and (
                (config.mode == "reconcile" and no_ledger)
                or (config.mode == "repair" and bound_ledger)
            )
        )
    else:  # UNCERTAIN_RECONCILE_ONLY
        invisible_claim = (
            ledger_digest is None
            and counts == (0, 0)
            and mutation_attribution == "UNPROVEN"
        )
        persisted_uncertainty = (
            ledger_digest is not None
            and mutation_attribution == "PROVEN_BY_DURABLE_LEDGER"
            and counts in {(1, 0), (1, 1), (2, 1), (2, 2), (3, 2), (3, 3)}
        )
        exact = (
            config.mode in {"repair", "reconcile"}
            and required_next_action == "INVOKE_RECONCILE_ALIAS"
            and (
                (config.mode == "repair" and invisible_claim)
                or persisted_uncertainty
            )
        )
    if not exact:
        raise BrokerContractError(
            "PUBLIC_RECEIPT_OVERCLAIM", "public receipt state is inconsistent"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": PUBLIC_RECEIPT_TYPE,
        "mode": config.mode,
        "status": status,
        "repair_id_digest": sha256(config.repair_id.encode("utf-8")).hexdigest(),
        "source_commit": config.source_commit,
        "function_version": config.function_version,
        "function_qualifier": config.function_qualifier,
        "region": config.region,
        "authority_account_suffix": config.authority_account_id[-4:],
        "management_account_suffix": config.management_account_id[-4:],
        "intent_digest": intent_digest,
        "ledger_digest": ledger_digest,
        "state_digest": state_digest,
        "effects_attempted": effects_attempted,
        "effects_completed": effects_completed,
        "mutation_attribution": mutation_attribution,
        "required_next_action": required_next_action,
        "generated_at": utc_timestamp(generated_at),
        "production_status": PRODUCTION_STATUS,
    }


def sanitized_blocked_state_digest(code: str) -> str:
    """Return a stable public digest without exposing sensitive exception text."""

    return canonical_digest({"classification": code})
