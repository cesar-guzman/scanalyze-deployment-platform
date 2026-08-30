"""Pure contracts for the GUG-376 bootstrap Plan permission repair.

The module deliberately contains no AWS SDK import.  A deployment package may
bind the provider and durable-ledger ports, but the local CLI cannot obtain
either port and therefore cannot mutate IAM Identity Center directly.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, Protocol, Sequence

from tooling.platform_authority_bootstrap import (
    BootstrapAuthorizationError,
    BootstrapBinding,
    canonical_digest,
    render_bootstrap_iam_policy,
    validate_bootstrap_change_set_name,
)


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
PLAN_PERMISSION_SET_NAME = "ScanalyzeAuthorityBootstrapPlan"
PLAN_SESSION_DURATION = "PT1H"
PLAN_ROLE_PREFIX = "AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_"
PLAN_ROLE_INLINE_POLICY_NAME = "AwsSSOInlinePolicy"
REPAIR_LEDGER_TABLE_NAME = (
    "scanalyze-platform-authority-plan-policy-repair-ledger"
)
SAML_AUDIENCE = "https://signin.aws.amazon.com/saml"
FUNCTION_NAMES = {
    "plan": "scanalyze-platform-authority-plan-policy-plan",
    "repair": "scanalyze-platform-authority-plan-policy-repair",
    "reconcile": "scanalyze-platform-authority-plan-policy-reconcile",
}
FUNCTION_QUALIFIERS = {
    "plan": "plan-v1",
    "repair": "repair-v1",
    "reconcile": "reconcile-v1",
}
EXECUTION_ROLE_NAMES = {
    "plan": "ScanalyzeBootstrapPlanRepairPlan",
    "repair": "ScanalyzeBootstrapPlanRepairExecution",
    "reconcile": "ScanalyzeBootstrapPlanRepairReconcile",
}
INTENT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_intent.v1"
)
LEDGER_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_ledger.v1"
)
RECEIPT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_receipt.v1"
)
AUTHORIZED_MUTATIONS = (
    "sso:PutInlinePolicyToPermissionSet",
    "sso:ProvisionPermissionSet",
)
PRODUCTION_STATUS = "NO-GO"
MAX_WINDOW = timedelta(minutes=15)
LAMBDA_ENTRY_MINIMUM_REMAINING_MS = {
    "plan": 60_000,
    "repair": 480_000,
    "reconcile": 60_000,
}
REPAIR_START_MIN_WINDOW_REMAINING_SECONDS = 660
MUTATION_WINDOW_MIN_REMAINING_SECONDS = 75
PRIVATE_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "repair_id",
        "source_commit",
        "source_bundle_digest",
        "authority_account_id",
        "management_account_id",
        "region",
        "instance_arn",
        "identity_store_id",
        "permission_set_arn",
        "permission_set_name",
        "permission_set_description",
        "permission_set_tags",
        "session_duration",
        "relay_state",
        "repair_invoker_permission_set_arn",
        "principal_id",
        "assignment_digest",
        "provisioned_accounts_digest",
        "role_arn",
        "role_name",
        "saml_provider_arn",
        "identity_center_kms_mode",
        "identity_center_kms_key_arn",
        "invocation_authority_graph_digest",
        "change_set_name",
        "change_set_name_digest",
        "policy_template_digest",
        "predecessor_policy_digest",
        "target_policy_digest",
        "policy_delta_digest",
        "ledger_table_name",
        "ledger_kms_key_arn",
        "expected_artifact_code_sha256",
        "expected_code_signing_config_arn",
        "expected_signing_profile_version_arn",
        "function_versions",
        "function_qualifiers",
        "expected_boto3_version",
        "expected_botocore_version",
        "not_before",
        "not_after",
        "authorized_mutations",
        "retry_permitted",
        "direct_human_sso_mutation_authorized",
        "production_authorized",
        "intent_digest",
    }
)
PRIVATE_LEDGER_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "repair_id",
        "intent_digest",
        "source_commit",
        "status",
        "stage",
        "effects_attempted",
        "effects_completed",
        "planned_state_digest",
        "state_digest",
        "planned_at",
        "provider_immutable",
        "claim_condition",
        "mutation_retry_attempted",
        "retry_permitted",
        "production_authorized",
        "ledger_digest",
    }
)
PRIVATE_LEDGER_ACTIVE_FIELDS = PRIVATE_LEDGER_PLAN_FIELDS | {
    "claimed_at",
    "updated_at",
}
PUBLIC_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "mode",
        "status",
        "repair_id_digest",
        "source_commit_digest",
        "source_bundle_digest",
        "function_version",
        "function_qualifier",
        "region",
        "authority_account_suffix",
        "management_account_suffix",
        "intent_digest",
        "ledger_digest",
        "state_digest",
        "predecessor_policy_digest",
        "target_policy_digest",
        "policy_delta_digest",
        "effects_attempted",
        "effects_completed",
        "mutation_attribution",
        "required_next_action",
        "retry_permitted",
        "direct_human_sso_mutations",
        "generated_at",
        "production_status",
        "receipt_digest",
    }
)

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REPAIR_ID = re.compile(r"^gug376-plan-permission-repair-[0-9a-f]{64}$")
_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$"
)
_IDENTITY_STORE_ID = re.compile(r"^d-[0-9a-z]{10,}$")
_PERMISSION_SET_ARN = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/"
    r"ps-[A-Za-z0-9]{16}$"
)
_PRINCIPAL_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_ROLE_ARN = re.compile(
    r"^arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
    r"AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"
)
_ROLE_NAME = re.compile(
    r"^AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"
)
_SAML_PROVIDER_ARN = re.compile(
    r"^arn:aws:iam::042360977644:saml-provider/"
    r"AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
)
_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_IDENTITY_CENTER_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/"
    r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
)
_CODE_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_CODE_SIGNING_CONFIG_ARN = re.compile(
    r"^arn:aws:lambda:us-east-1:042360977644:"
    r"code-signing-config:csc-[a-z0-9]{17}$"
)
_SIGNING_PROFILE_VERSION_ARN = re.compile(
    r"^arn:aws[a-z-]*:signer:us-east-1:042360977644:"
    r"/signing-profiles/[A-Za-z0-9_]{2,64}/[A-Za-z0-9]{10}$"
)
_FUNCTION_VERSION = re.compile(r"^[1-9][0-9]*$")
_SDK_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
                          r"(?:0|[1-9][0-9]*)$")
_LEDGER_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_TAG_KEY = re.compile(r"^[A-Za-z0-9_.:/=+@-]{1,128}$")

LAMBDA_ENVIRONMENT_LIMIT_BYTES = 4096
MAX_PUBLISHED_FUNCTION_VERSION_BYTES = 20
IMMUTABLE_CONFIGURATION_PARAMETER_TO_ENV = (
    ("SourceCommit", "SOURCE_COMMIT"),
    ("SourceBundleDigest", "SOURCE_BUNDLE_DIGEST"),
    ("RepairId", "REPAIR_ID"),
    ("PrincipalId", "PRINCIPAL_ID"),
    ("IdentityStoreId", "IDENTITY_STORE_ID"),
    ("IdentityCenterInstanceArn", "IDENTITY_CENTER_INSTANCE_ARN"),
    ("PlanPermissionSetArn", "PLAN_PERMISSION_SET_ARN"),
    (
        "ExpectedPermissionSetDescription",
        "EXPECTED_PERMISSION_SET_DESCRIPTION",
    ),
    (
        "RepairInvokerPermissionSetArn",
        "REPAIR_INVOKER_PERMISSION_SET_ARN",
    ),
    ("CurrentPolicyDigest", "CURRENT_POLICY_DIGEST"),
    ("DesiredPolicyDigest", "DESIRED_POLICY_DIGEST"),
    (
        "ExpectedPlanPermissionSetTagsJson",
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
    ),
    ("BootstrapChangeSetName", "BOOTSTRAP_CHANGE_SET_NAME"),
    ("RepairNotBefore", "REPAIR_NOT_BEFORE"),
    ("RepairNotAfter", "REPAIR_NOT_AFTER"),
    ("PlanSamlProviderArn", "PLAN_SAML_PROVIDER_ARN"),
    ("IdentityCenterKmsMode", "IDENTITY_CENTER_KMS_MODE"),
    ("IdentityCenterKmsKeyArn", "IDENTITY_CENTER_KMS_KEY_ARN"),
    ("ExpectedBoto3Version", "EXPECTED_BOTO3_VERSION"),
    ("ExpectedBotocoreVersion", "EXPECTED_BOTOCORE_VERSION"),
    ("ArtifactCodeSha256", "EXPECTED_ARTIFACT_CODE_SHA256"),
    (
        "SigningProfileVersionArn",
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
    ),
)
IMMUTABLE_CONFIGURATION_PARAMETER_KEYS = frozenset(
    parameter for parameter, _ in IMMUTABLE_CONFIGURATION_PARAMETER_TO_ENV
)
IMMUTABLE_CONFIGURATION_ENV_KEYS = frozenset(
    environment for _, environment in IMMUTABLE_CONFIGURATION_PARAMETER_TO_ENV
)


class PlanPermissionRepairError(ValueError):
    """Deterministic fail-closed contract violation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ProviderResponseAmbiguous(RuntimeError):
    """The response cannot prove whether the one allowed effect occurred."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def digest_value(value: Any) -> str:
    """Return the repository-standard, prefixed canonical digest."""

    if isinstance(value, Mapping):
        return canonical_digest(dict(value))
    payload = json.loads(canonical_json({"value": value}))
    return canonical_digest(payload)


def _configuration_tags(value: object) -> dict[str, str]:
    if not isinstance(value, str):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "permission-set tags must be canonical JSON",
        )

    def reject_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate configuration tag")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "permission-set tags must be canonical JSON",
        ) from exc
    if type(parsed) is not dict or not parsed or any(
        not isinstance(key, str)
        or _TAG_KEY.fullmatch(key) is None
        or not isinstance(item, str)
        or not 1 <= len(item) <= 256
        for key, item in parsed.items()
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "permission-set tags are outside the closed shape",
        )
    return dict(parsed)


def immutable_configuration_projection_from_environment(
    env: Mapping[str, str],
) -> dict[str, Any]:
    """Project every operator-controlled immutable Lambda binding."""

    if any(
        not isinstance(env.get(key), str)
        for key in IMMUTABLE_CONFIGURATION_ENV_KEYS
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable configuration is incomplete",
        )
    values = {key: str(env[key]) for key in IMMUTABLE_CONFIGURATION_ENV_KEYS}
    tags = _configuration_tags(
        values["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"]
    )
    values["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"] = canonical_json(tags)
    if (
        _COMMIT.fullmatch(values["SOURCE_COMMIT"]) is None
        or _SHA256.fullmatch(values["SOURCE_BUNDLE_DIGEST"]) is None
        or _REPAIR_ID.fullmatch(values["REPAIR_ID"]) is None
        or _PRINCIPAL_ID.fullmatch(values["PRINCIPAL_ID"]) is None
        or _IDENTITY_STORE_ID.fullmatch(values["IDENTITY_STORE_ID"]) is None
        or len(values["IDENTITY_STORE_ID"].encode("utf-8")) > 64
        or _INSTANCE_ARN.fullmatch(
            values["IDENTITY_CENTER_INSTANCE_ARN"]
        )
        is None
        or _PERMISSION_SET_ARN.fullmatch(values["PLAN_PERMISSION_SET_ARN"])
        is None
        or _PERMISSION_SET_ARN.fullmatch(
            values["REPAIR_INVOKER_PERMISSION_SET_ARN"]
        )
        is None
        or values["PLAN_PERMISSION_SET_ARN"]
        == values["REPAIR_INVOKER_PERMISSION_SET_ARN"]
        or _SHA256.fullmatch(values["CURRENT_POLICY_DIGEST"]) is None
        or _SHA256.fullmatch(values["DESIRED_POLICY_DIGEST"]) is None
        or values["CURRENT_POLICY_DIGEST"]
        == values["DESIRED_POLICY_DIGEST"]
        or _SAML_PROVIDER_ARN.fullmatch(values["PLAN_SAML_PROVIDER_ARN"])
        is None
        or len(values["PLAN_SAML_PROVIDER_ARN"].encode("utf-8")) > 168
        or _CODE_SHA256.fullmatch(
            values["EXPECTED_ARTIFACT_CODE_SHA256"]
        )
        is None
        or _SIGNING_PROFILE_VERSION_ARN.fullmatch(
            values["EXPECTED_SIGNING_PROFILE_VERSION_ARN"]
        )
        is None
        or any(
            _SDK_VERSION.fullmatch(values[key]) is None
            or len(values[key].encode("utf-8")) > 32
            for key in (
                "EXPECTED_BOTO3_VERSION",
                "EXPECTED_BOTOCORE_VERSION",
            )
        )
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable configuration contains a malformed binding",
        )
    try:
        validate_bootstrap_change_set_name(
            values["BOOTSTRAP_CHANGE_SET_NAME"]
        )
    except BootstrapAuthorizationError as exc:
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable Change Set binding is malformed",
        ) from exc
    not_before = parse_timestamp(
        values["REPAIR_NOT_BEFORE"], "REPAIR_NOT_BEFORE"
    )
    not_after = parse_timestamp(
        values["REPAIR_NOT_AFTER"], "REPAIR_NOT_AFTER"
    )
    if not_before >= not_after or not_after - not_before > MAX_WINDOW:
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable repair window is invalid",
        )
    description = values["EXPECTED_PERMISSION_SET_DESCRIPTION"]
    tags_json = values["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"]
    if (
        not 1 <= len(description.encode("utf-8")) <= 700
        or any(ord(character) < 32 or ord(character) > 126 for character in description)
        or not 2 <= len(tags_json.encode("utf-8")) <= 1024
        or any(ord(character) < 32 or ord(character) > 126 for character in tags_json)
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable metadata exceeds the ASCII deployment budget",
        )
    kms_mode = values["IDENTITY_CENTER_KMS_MODE"]
    kms_key = values["IDENTITY_CENTER_KMS_KEY_ARN"]
    if (
        kms_mode == "AWS_OWNED_KMS_KEY"
        and kms_key != ""
    ) or (
        kms_mode == "CUSTOMER_MANAGED_KEY"
        and _IDENTITY_CENTER_KMS_ARN.fullmatch(kms_key) is None
    ) or kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}:
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "immutable Identity Center KMS binding is invalid",
        )
    return {
        "schema_version": 1,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "region": REGION,
        "environment": values,
        "fixed_resources": {
            "ledger_table_name": REPAIR_LEDGER_TABLE_NAME,
            "ledger_kms_key_logical_id": "RepairLedgerKey",
            "code_signing_config_logical_id": "RepairCodeSigningConfig",
        },
        "functions": {
            mode: {
                "name": FUNCTION_NAMES[mode],
                "qualifier": FUNCTION_QUALIFIERS[mode],
                "execution_role_name": EXECUTION_ROLE_NAMES[mode],
                "runtime": "python3.12",
                "architecture": "x86_64",
                "memory_size": 1024,
                "timeout": {"plan": 300, "repair": 600, "reconcile": 300}[
                    mode
                ],
            }
            for mode in FUNCTION_NAMES
        },
    }


def immutable_configuration_digest_from_environment(
    env: Mapping[str, str],
) -> str:
    return canonical_digest(
        immutable_configuration_projection_from_environment(env)
    )


def immutable_configuration_digest_from_parameters(
    parameters: Mapping[str, Any],
) -> str:
    if not isinstance(parameters, Mapping) or set(parameters) != set(
        IMMUTABLE_CONFIGURATION_PARAMETER_KEYS
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "CloudFormation configuration parameters are not exact",
        )
    environment = {
        env_key: parameters[parameter_key]
        for parameter_key, env_key in IMMUTABLE_CONFIGURATION_PARAMETER_TO_ENV
    }
    if any(not isinstance(value, str) for value in environment.values()):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_INVALID",
            "CloudFormation configuration parameters must be strings",
        )
    return immutable_configuration_digest_from_environment(environment)


def immutable_configuration_digest_from_intent(
    intent: Mapping[str, Any],
) -> str:
    parameters = {
        "SourceCommit": intent.get("source_commit"),
        "SourceBundleDigest": intent.get("source_bundle_digest"),
        "RepairId": intent.get("repair_id"),
        "PrincipalId": intent.get("principal_id"),
        "IdentityStoreId": intent.get("identity_store_id"),
        "IdentityCenterInstanceArn": intent.get("instance_arn"),
        "PlanPermissionSetArn": intent.get("permission_set_arn"),
        "ExpectedPermissionSetDescription": intent.get(
            "permission_set_description"
        ),
        "RepairInvokerPermissionSetArn": intent.get(
            "repair_invoker_permission_set_arn"
        ),
        "CurrentPolicyDigest": intent.get("predecessor_policy_digest"),
        "DesiredPolicyDigest": intent.get("target_policy_digest"),
        "ExpectedPlanPermissionSetTagsJson": canonical_json(
            intent.get("permission_set_tags")
        ),
        "BootstrapChangeSetName": intent.get("change_set_name"),
        "RepairNotBefore": intent.get("not_before"),
        "RepairNotAfter": intent.get("not_after"),
        "PlanSamlProviderArn": intent.get("saml_provider_arn"),
        "IdentityCenterKmsMode": intent.get("identity_center_kms_mode"),
        "IdentityCenterKmsKeyArn": (
            intent.get("identity_center_kms_key_arn") or ""
        ),
        "ExpectedBoto3Version": intent.get("expected_boto3_version"),
        "ExpectedBotocoreVersion": intent.get("expected_botocore_version"),
        "ArtifactCodeSha256": intent.get("expected_artifact_code_sha256"),
        "SigningProfileVersionArn": intent.get(
            "expected_signing_profile_version_arn"
        ),
    }
    return immutable_configuration_digest_from_parameters(parameters)


def lambda_environment_size_bytes(env: Mapping[str, str]) -> int:
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in env.items()):
        raise PlanPermissionRepairError(
            "LAMBDA_ENVIRONMENT_INVALID",
            "Lambda environment keys and values must be strings",
        )
    return sum(
        len(key.encode("utf-8")) + len(value.encode("utf-8"))
        for key, value in env.items()
    )


def configured_lambda_environment(
    env: Mapping[str, str], *, mode: str
) -> dict[str, str]:
    if mode not in FUNCTION_NAMES:
        raise PlanPermissionRepairError("INVALID_MODE", "mode is unsupported")
    keys = set(immutable_environment_keys()) | {"IMMU_CONFIG_DIGEST"}
    if mode in {"repair", "reconcile"}:
        keys.add("PLAN_FUNCTION_VERSION")
    if mode == "reconcile":
        keys.add("REPAIR_FUNCTION_VERSION")
    if any(not isinstance(env.get(key), str) for key in keys):
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISSING",
            "immutable Lambda environment is incomplete",
        )
    return {key: str(env[key]) for key in keys}


def validate_lambda_environment_budget(
    env: Mapping[str, str], *, mode: str
) -> int:
    size = lambda_environment_size_bytes(
        configured_lambda_environment(env, mode=mode)
    )
    if size > LAMBDA_ENVIRONMENT_LIMIT_BYTES:
        raise PlanPermissionRepairError(
            "LAMBDA_ENVIRONMENT_BUDGET_EXCEEDED",
            "Lambda environment exceeds the 4096-byte provider limit",
        )
    return size


def validate_immutable_configuration_digest(
    env: Mapping[str, str],
) -> str:
    claimed = env.get("IMMU_CONFIG_DIGEST")
    expected = immutable_configuration_digest_from_environment(env)
    if claimed != expected:
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_DIGEST_MISMATCH",
            "immutable configuration digest differs",
        )
    return expected


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PlanPermissionRepairError(
            "NAIVE_TIME", "timestamps must be timezone-aware"
        )
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PlanPermissionRepairError(
            "INVALID_TIME", f"{field} must be a canonical UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PlanPermissionRepairError(
            "INVALID_TIME", f"{field} is malformed"
        ) from exc
    if parsed.microsecond or _timestamp(parsed) != value:
        raise PlanPermissionRepairError(
            "INVALID_TIME", f"{field} must not contain fractions"
        )
    return parsed


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PlanPermissionRepairError(
            "INVALID_DIGEST", f"{field} must be a prefixed SHA-256 digest"
        )
    return value


def _seal(document: Mapping[str, Any], field: str) -> dict[str, Any]:
    sealed = dict(document)
    sealed[field] = canonical_digest(dict(document))
    return sealed


def _validate_seal(document: Mapping[str, Any], field: str) -> str:
    claimed = _require_digest(document.get(field), field)
    payload = {key: value for key, value in document.items() if key != field}
    if canonical_digest(payload) != claimed:
        raise PlanPermissionRepairError(
            "DIGEST_MISMATCH", f"{field} does not seal the canonical record"
        )
    return claimed


def _bootstrap_binding() -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=REGION,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name=(
            "scanalyze-platform-authority-042360977644-us-east-1-state"
        ),
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=(MANAGEMENT_ACCOUNT_ID,),
    )


def render_target_policy(
    change_set_name: str,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Render the only desired Plan policy from reviewed repository source."""

    try:
        canonical_name = validate_bootstrap_change_set_name(change_set_name)
        root = repo_root or Path(__file__).resolve().parents[1]
        template_path = (
            root / "policies/iam/platform-authority-bootstrap-plan-role.json"
        )
        template = json.loads(template_path.read_text(encoding="utf-8"))
        if type(template) is not dict:
            raise ValueError("policy template must be an object")
        return render_bootstrap_iam_policy(
            policy_template=template,
            binding=_bootstrap_binding(),
            change_set_name=canonical_name,
        )
    except (
        BootstrapAuthorizationError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise PlanPermissionRepairError(
            "TARGET_POLICY_UNAVAILABLE",
            "reviewed bootstrap Plan policy cannot be rendered",
        ) from exc


def render_predecessor_policy(target_policy: Mapping[str, Any]) -> dict[str, Any]:
    """Remove exactly the one reviewed ListChangeSets allow statement."""

    predecessor = deepcopy(dict(target_policy))
    statements = predecessor.get("Statement")
    if not isinstance(statements, list):
        raise PlanPermissionRepairError(
            "TARGET_POLICY_INVALID", "target policy statements are malformed"
        )
    removed = [
        statement
        for statement in statements
        if isinstance(statement, Mapping)
        and statement.get("Sid") == "ListOnlyExactBootstrapChangeSets"
    ]
    if len(removed) != 1:
        raise PlanPermissionRepairError(
            "TARGET_POLICY_INVALID",
            "target policy does not contain one exact repair statement",
        )
    predecessor["Statement"] = [
        statement
        for statement in statements
        if not (
            isinstance(statement, Mapping)
            and statement.get("Sid") == "ListOnlyExactBootstrapChangeSets"
        )
    ]
    return predecessor


def policy_delta_digest(
    predecessor: Mapping[str, Any], target: Mapping[str, Any]
) -> str:
    target_statements = target.get("Statement")
    if not isinstance(target_statements, list):
        raise PlanPermissionRepairError(
            "TARGET_POLICY_INVALID", "target policy statements are malformed"
        )
    added = [
        statement
        for statement in target_statements
        if isinstance(statement, Mapping)
        and statement.get("Sid") == "ListOnlyExactBootstrapChangeSets"
    ]
    if len(added) != 1 or render_predecessor_policy(target) != dict(predecessor):
        raise PlanPermissionRepairError(
            "POLICY_DELTA_INVALID", "policy delta contains more than one change"
        )
    return canonical_digest(
        {
            "operation": "ADD_EXACT_STATEMENT",
            "statement": added[0],
        }
    )


@dataclass(frozen=True, slots=True)
class Assignment:
    principal_type: str
    principal_id: str
    target_account_id: str = AUTHORITY_ACCOUNT_ID

    def as_record(self) -> dict[str, str]:
        return {
            "principal_type": self.principal_type,
            "principal_id": self.principal_id,
            "target_account_id": self.target_account_id,
        }


@dataclass(frozen=True, slots=True)
class RoleSnapshot:
    role_arn: str
    role_name: str
    saml_provider_arn: str
    saml_audience: str
    inline_policy_name: str
    inline_policy: Mapping[str, Any]
    attached_managed_policy_arns: tuple[str, ...] = ()
    extra_inline_policy_names: tuple[str, ...] = ()
    permissions_boundary_arn: str | None = None

    def digest(self) -> str:
        return canonical_digest(
            {
                "role_arn": self.role_arn,
                "role_name": self.role_name,
                "saml_provider_arn": self.saml_provider_arn,
                "saml_audience": self.saml_audience,
                "inline_policy_name": self.inline_policy_name,
                "inline_policy_digest": canonical_digest(
                    dict(self.inline_policy)
                ),
                "attached_managed_policy_arns": list(
                    self.attached_managed_policy_arns
                ),
                "extra_inline_policy_names": list(
                    self.extra_inline_policy_names
                ),
                "permissions_boundary_arn": self.permissions_boundary_arn,
            }
        )


@dataclass(frozen=True, slots=True)
class PlanPermissionSnapshot:
    instance_arn: str
    identity_store_id: str
    identity_center_kms_mode: str
    identity_center_kms_key_arn: str | None
    permission_set_arn: str
    permission_set_name: str
    permission_set_description: str
    session_duration: str
    relay_state: str | None
    permission_set_tags: tuple[tuple[str, str], ...]
    inline_policy: Mapping[str, Any]
    managed_policy_arns: tuple[str, ...]
    customer_managed_policy_references: tuple[str, ...]
    permissions_boundary_present: bool
    assignments: tuple[Assignment, ...]
    provisioned_account_ids: tuple[str, ...]
    pending_operation_count: int
    role: RoleSnapshot
    invocation_authority_graph_digest: str

    def digest(self) -> str:
        return canonical_digest(
            {
                "instance_arn": self.instance_arn,
                "identity_store_id": self.identity_store_id,
                "identity_center_kms_mode": self.identity_center_kms_mode,
                "identity_center_kms_key_arn": self.identity_center_kms_key_arn,
                "permission_set_arn": self.permission_set_arn,
                "permission_set_name": self.permission_set_name,
                "permission_set_description": self.permission_set_description,
                "session_duration": self.session_duration,
                "relay_state": self.relay_state,
                "permission_set_tags": dict(self.permission_set_tags),
                "inline_policy_digest": canonical_digest(
                    dict(self.inline_policy)
                ),
                "managed_policy_arns": list(self.managed_policy_arns),
                "customer_managed_policy_references": list(
                    self.customer_managed_policy_references
                ),
                "permissions_boundary_present": (
                    self.permissions_boundary_present
                ),
                "assignments": [item.as_record() for item in self.assignments],
                "provisioned_account_ids": list(
                    self.provisioned_account_ids
                ),
                "pending_operation_count": self.pending_operation_count,
                "role_digest": self.role.digest(),
                "invocation_authority_graph_digest": (
                    self.invocation_authority_graph_digest
                ),
            }
        )


@dataclass(frozen=True, slots=True)
class RepairBinding:
    source_commit: str
    repair_id: str
    source_bundle_digest: str
    instance_arn: str
    identity_store_id: str
    permission_set_arn: str
    repair_invoker_permission_set_arn: str
    permission_set_description: str
    permission_set_tags: tuple[tuple[str, str], ...]
    principal_id: str
    role_arn: str
    role_name: str
    saml_provider_arn: str
    identity_center_kms_mode: str
    identity_center_kms_key_arn: str | None
    invocation_authority_graph_digest: str
    change_set_name: str
    ledger_table_name: str
    ledger_kms_key_arn: str
    expected_artifact_code_sha256: str
    expected_code_signing_config_arn: str
    expected_signing_profile_version_arn: str
    not_before: datetime
    not_after: datetime
    plan_function_version: str
    repair_function_version: str
    reconcile_function_version: str
    expected_boto3_version: str
    expected_botocore_version: str

    def __post_init__(self) -> None:
        if _COMMIT.fullmatch(self.source_commit) is None:
            raise PlanPermissionRepairError(
                "INVALID_SOURCE_COMMIT", "source commit must be lowercase SHA-1"
            )
        if _REPAIR_ID.fullmatch(self.repair_id) is None:
            raise PlanPermissionRepairError(
                "INVALID_REPAIR_ID", "repair ID is malformed"
            )
        for field, value in (
            ("source_bundle_digest", self.source_bundle_digest),
            (
                "invocation_authority_graph_digest",
                self.invocation_authority_graph_digest,
            ),
        ):
            _require_digest(value, field)
        if _INSTANCE_ARN.fullmatch(self.instance_arn) is None:
            raise PlanPermissionRepairError(
                "INVALID_INSTANCE", "Identity Center instance ARN is malformed"
            )
        if _IDENTITY_STORE_ID.fullmatch(self.identity_store_id) is None:
            raise PlanPermissionRepairError(
                "INVALID_IDENTITY_STORE", "identity store ID is malformed"
            )
        for value in (
            self.permission_set_arn,
            self.repair_invoker_permission_set_arn,
        ):
            if _PERMISSION_SET_ARN.fullmatch(value) is None:
                raise PlanPermissionRepairError(
                    "INVALID_PERMISSION_SET", "permission set ARN is malformed"
                )
        if self.permission_set_arn == self.repair_invoker_permission_set_arn:
            raise PlanPermissionRepairError(
                "PERMISSION_SET_COLLISION",
                "Plan and invoker permission sets must differ",
            )
        if _PRINCIPAL_ID.fullmatch(self.principal_id) is None:
            raise PlanPermissionRepairError(
                "INVALID_PRINCIPAL", "principal ID is malformed"
            )
        if _ROLE_ARN.fullmatch(self.role_arn) is None:
            raise PlanPermissionRepairError(
                "INVALID_ROLE", "generated Plan role ARN is malformed"
            )
        if _ROLE_NAME.fullmatch(self.role_name) is None:
            raise PlanPermissionRepairError(
                "INVALID_ROLE", "generated Plan role name is malformed"
            )
        if not self.role_arn.endswith("/" + self.role_name):
            raise PlanPermissionRepairError(
                "ROLE_BINDING_MISMATCH", "role ARN and role name differ"
            )
        if _SAML_PROVIDER_ARN.fullmatch(self.saml_provider_arn) is None:
            raise PlanPermissionRepairError(
                "INVALID_SAML_PROVIDER", "Plan SAML provider ARN is malformed"
            )
        if self.identity_center_kms_mode not in {
            "AWS_OWNED_KMS_KEY",
            "CUSTOMER_MANAGED_KEY",
        }:
            raise PlanPermissionRepairError(
                "INVALID_KMS_MODE", "Identity Center KMS mode is unsupported"
            )
        if self.identity_center_kms_mode == "AWS_OWNED_KMS_KEY":
            if self.identity_center_kms_key_arn is not None:
                raise PlanPermissionRepairError(
                    "INVALID_KMS_BINDING",
                    "AWS-owned KMS mode cannot carry a key ARN",
                )
        elif (
            self.identity_center_kms_key_arn is None
            or _IDENTITY_CENTER_KMS_ARN.fullmatch(
                self.identity_center_kms_key_arn
            )
            is None
        ):
            raise PlanPermissionRepairError(
                "INVALID_KMS_BINDING",
                "customer-managed KMS mode requires the exact management key",
            )
        try:
            validate_bootstrap_change_set_name(self.change_set_name)
        except BootstrapAuthorizationError as exc:
            raise PlanPermissionRepairError(
                "INVALID_CHANGE_SET_NAME", "Change Set name is invalid"
            ) from exc
        if self.ledger_table_name != REPAIR_LEDGER_TABLE_NAME:
            raise PlanPermissionRepairError(
                "INVALID_LEDGER_TABLE", "ledger table name differs"
            )
        if _KMS_ARN.fullmatch(self.ledger_kms_key_arn) is None:
            raise PlanPermissionRepairError(
                "INVALID_LEDGER_KEY", "ledger KMS key ARN is malformed"
            )
        if _CODE_SHA256.fullmatch(self.expected_artifact_code_sha256) is None:
            raise PlanPermissionRepairError(
                "INVALID_ARTIFACT", "Lambda artifact digest is malformed"
            )
        if (
            _CODE_SIGNING_CONFIG_ARN.fullmatch(
                self.expected_code_signing_config_arn
            )
            is None
        ):
            raise PlanPermissionRepairError(
                "INVALID_CODE_SIGNING_CONFIG",
                "code-signing configuration ARN is malformed",
            )
        if (
            _SIGNING_PROFILE_VERSION_ARN.fullmatch(
                self.expected_signing_profile_version_arn
            )
            is None
        ):
            raise PlanPermissionRepairError(
                "INVALID_SIGNING_PROFILE",
                "signing profile version ARN is malformed",
            )
        for value in (
            self.plan_function_version,
            self.repair_function_version,
            self.reconcile_function_version,
        ):
            if _FUNCTION_VERSION.fullmatch(value) is None:
                raise PlanPermissionRepairError(
                    "UNPUBLISHED_FUNCTION",
                    "all Lambda functions must use published numeric versions",
                )
        for value in (
            self.expected_boto3_version,
            self.expected_botocore_version,
        ):
            if _SDK_VERSION.fullmatch(value) is None:
                raise PlanPermissionRepairError(
                    "INVALID_SDK_VERSION", "SDK version is malformed"
                )
        if (
            self.not_before.tzinfo is None
            or self.not_after.tzinfo is None
            or self.not_before >= self.not_after
            or self.not_after - self.not_before > MAX_WINDOW
        ):
            raise PlanPermissionRepairError(
                "INVALID_WINDOW",
                "repair window must be positive and at most fifteen minutes",
            )
        if not self.permission_set_description:
            raise PlanPermissionRepairError(
                "INVALID_METADATA", "permission-set description is required"
            )
        if not self.permission_set_tags:
            raise PlanPermissionRepairError(
                "INVALID_METADATA", "permission-set tags are required"
            )
        normalized_tags = tuple(sorted(self.permission_set_tags))
        if normalized_tags != self.permission_set_tags:
            raise PlanPermissionRepairError(
                "INVALID_METADATA", "permission-set tags must be sorted"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RepairBinding":
        try:
            tags = value["permission_set_tags"]
            if not isinstance(tags, Mapping) or not tags:
                raise TypeError("permission_set_tags")
            return cls(
                source_commit=str(value["source_commit"]),
                repair_id=str(value["repair_id"]),
                source_bundle_digest=str(value["source_bundle_digest"]),
                instance_arn=str(value["instance_arn"]),
                identity_store_id=str(value["identity_store_id"]),
                permission_set_arn=str(value["permission_set_arn"]),
                repair_invoker_permission_set_arn=str(
                    value["repair_invoker_permission_set_arn"]
                ),
                permission_set_description=str(
                    value["permission_set_description"]
                ),
                permission_set_tags=tuple(
                    sorted((str(key), str(item)) for key, item in tags.items())
                ),
                principal_id=str(value["principal_id"]),
                role_arn=str(value["role_arn"]),
                role_name=str(value["role_name"]),
                saml_provider_arn=str(value["saml_provider_arn"]),
                identity_center_kms_mode=str(
                    value["identity_center_kms_mode"]
                ),
                identity_center_kms_key_arn=(
                    str(value["identity_center_kms_key_arn"])
                    if value.get("identity_center_kms_key_arn")
                    else None
                ),
                invocation_authority_graph_digest=str(
                    value["invocation_authority_graph_digest"]
                ),
                change_set_name=str(value["change_set_name"]),
                ledger_table_name=str(value["ledger_table_name"]),
                ledger_kms_key_arn=str(value["ledger_kms_key_arn"]),
                expected_artifact_code_sha256=str(
                    value["expected_artifact_code_sha256"]
                ),
                expected_code_signing_config_arn=str(
                    value["expected_code_signing_config_arn"]
                ),
                expected_signing_profile_version_arn=str(
                    value["expected_signing_profile_version_arn"]
                ),
                not_before=parse_timestamp(value["not_before"], "not_before"),
                not_after=parse_timestamp(value["not_after"], "not_after"),
                plan_function_version=str(value["plan_function_version"]),
                repair_function_version=str(value["repair_function_version"]),
                reconcile_function_version=str(
                    value["reconcile_function_version"]
                ),
                expected_boto3_version=str(value["expected_boto3_version"]),
                expected_botocore_version=str(
                    value["expected_botocore_version"]
                ),
            )
        except (KeyError, TypeError) as exc:
            raise PlanPermissionRepairError(
                "MALFORMED_BINDING", "private repair binding is incomplete"
            ) from exc


def build_private_intent(
    binding: RepairBinding,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    target = render_target_policy(binding.change_set_name, repo_root=repo_root)
    predecessor = render_predecessor_policy(target)
    assignment = Assignment("USER", binding.principal_id)
    intent = {
        "schema_version": 1,
        "record_type": INTENT_RECORD_TYPE,
        "repair_id": binding.repair_id,
        "source_commit": binding.source_commit,
        "source_bundle_digest": binding.source_bundle_digest,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "region": REGION,
        "instance_arn": binding.instance_arn,
        "identity_store_id": binding.identity_store_id,
        "permission_set_arn": binding.permission_set_arn,
        "permission_set_name": PLAN_PERMISSION_SET_NAME,
        "permission_set_description": binding.permission_set_description,
        "permission_set_tags": dict(binding.permission_set_tags),
        "session_duration": PLAN_SESSION_DURATION,
        "relay_state": None,
        "repair_invoker_permission_set_arn": (
            binding.repair_invoker_permission_set_arn
        ),
        "principal_id": binding.principal_id,
        "assignment_digest": canonical_digest(assignment.as_record()),
        "provisioned_accounts_digest": canonical_digest(
            {"account_ids": [AUTHORITY_ACCOUNT_ID]}
        ),
        "role_arn": binding.role_arn,
        "role_name": binding.role_name,
        "saml_provider_arn": binding.saml_provider_arn,
        "identity_center_kms_mode": binding.identity_center_kms_mode,
        "identity_center_kms_key_arn": binding.identity_center_kms_key_arn,
        "invocation_authority_graph_digest": (
            binding.invocation_authority_graph_digest
        ),
        "change_set_name": binding.change_set_name,
        "change_set_name_digest": digest_value(binding.change_set_name),
        "policy_template_digest": canonical_digest(
            json.loads(
                (
                    (repo_root or Path(__file__).resolve().parents[1])
                    / "policies/iam/platform-authority-bootstrap-plan-role.json"
                ).read_text(encoding="utf-8")
            )
        ),
        "predecessor_policy_digest": canonical_digest(predecessor),
        "target_policy_digest": canonical_digest(target),
        "policy_delta_digest": policy_delta_digest(predecessor, target),
        "ledger_table_name": binding.ledger_table_name,
        "ledger_kms_key_arn": binding.ledger_kms_key_arn,
        "expected_artifact_code_sha256": (
            binding.expected_artifact_code_sha256
        ),
        "expected_code_signing_config_arn": (
            binding.expected_code_signing_config_arn
        ),
        "expected_signing_profile_version_arn": (
            binding.expected_signing_profile_version_arn
        ),
        "function_versions": {
            "plan": binding.plan_function_version,
            "repair": binding.repair_function_version,
            "reconcile": binding.reconcile_function_version,
        },
        "function_qualifiers": dict(FUNCTION_QUALIFIERS),
        "expected_boto3_version": binding.expected_boto3_version,
        "expected_botocore_version": binding.expected_botocore_version,
        "not_before": _timestamp(binding.not_before),
        "not_after": _timestamp(binding.not_after),
        "authorized_mutations": list(AUTHORIZED_MUTATIONS),
        "retry_permitted": False,
        "direct_human_sso_mutation_authorized": False,
        "production_authorized": False,
    }
    return _seal(intent, "intent_digest")


def validate_private_intent(
    intent: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
) -> None:
    if not isinstance(intent, Mapping) or set(intent) != PRIVATE_INTENT_FIELDS:
        raise PlanPermissionRepairError(
            "INTENT_FIELDS_INVALID",
            "private intent fields are not the exact closed contract",
        )
    if type(intent.get("schema_version")) is not int or intent.get(
        "schema_version"
    ) != 1 or intent.get("record_type") != (
        INTENT_RECORD_TYPE
    ):
        raise PlanPermissionRepairError(
            "INTENT_TYPE_MISMATCH", "private intent type is unsupported"
        )
    _validate_seal(intent, "intent_digest")
    if _REPAIR_ID.fullmatch(str(intent.get("repair_id", ""))) is None:
        raise PlanPermissionRepairError(
            "INVALID_REPAIR_ID", "private intent repair ID is malformed"
        )
    if _COMMIT.fullmatch(str(intent.get("source_commit", ""))) is None:
        raise PlanPermissionRepairError(
            "INVALID_SOURCE_COMMIT", "private intent source commit is malformed"
        )
    for field in (
        "source_bundle_digest",
        "assignment_digest",
        "provisioned_accounts_digest",
        "invocation_authority_graph_digest",
        "change_set_name_digest",
        "policy_template_digest",
        "predecessor_policy_digest",
        "target_policy_digest",
        "policy_delta_digest",
    ):
        _require_digest(intent.get(field), field)
    if (
        intent.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or intent.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or intent.get("region") != REGION
        or intent.get("permission_set_name") != PLAN_PERMISSION_SET_NAME
        or intent.get("session_duration") != PLAN_SESSION_DURATION
        or intent.get("relay_state") is not None
        or intent.get("ledger_table_name") != REPAIR_LEDGER_TABLE_NAME
    ):
        raise PlanPermissionRepairError(
            "INTENT_BINDING_MISMATCH", "private intent binding differs"
        )
    pattern_fields = (
        ("instance_arn", _INSTANCE_ARN),
        ("identity_store_id", _IDENTITY_STORE_ID),
        ("permission_set_arn", _PERMISSION_SET_ARN),
        ("repair_invoker_permission_set_arn", _PERMISSION_SET_ARN),
        ("principal_id", _PRINCIPAL_ID),
        ("role_arn", _ROLE_ARN),
        ("role_name", _ROLE_NAME),
        ("saml_provider_arn", _SAML_PROVIDER_ARN),
        ("ledger_table_name", _LEDGER_TABLE_NAME),
        ("ledger_kms_key_arn", _KMS_ARN),
        ("expected_artifact_code_sha256", _CODE_SHA256),
        ("expected_code_signing_config_arn", _CODE_SIGNING_CONFIG_ARN),
        (
            "expected_signing_profile_version_arn",
            _SIGNING_PROFILE_VERSION_ARN,
        ),
        ("expected_boto3_version", _SDK_VERSION),
        ("expected_botocore_version", _SDK_VERSION),
    )
    for field, pattern in pattern_fields:
        value = intent.get(field)
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise PlanPermissionRepairError(
                "INTENT_BINDING_MISMATCH",
                f"private intent {field} is malformed",
            )
    if intent["permission_set_arn"] == intent[
        "repair_invoker_permission_set_arn"
    ]:
        raise PlanPermissionRepairError(
            "PERMISSION_SET_COLLISION",
            "Plan and repair-invoker permission sets must differ",
        )
    if not intent["role_arn"].endswith("/" + intent["role_name"]):
        raise PlanPermissionRepairError(
            "ROLE_BINDING_MISMATCH", "role ARN and role name differ"
        )
    description = intent.get("permission_set_description")
    if not isinstance(description, str) or not 1 <= len(description) <= 700:
        raise PlanPermissionRepairError(
            "INVALID_METADATA", "permission-set description is malformed"
        )
    tags = intent.get("permission_set_tags")
    if type(tags) is not dict or not tags or any(
        not isinstance(key, str)
        or _TAG_KEY.fullmatch(key) is None
        or not isinstance(value, str)
        or not 1 <= len(value) <= 256
        for key, value in tags.items()
    ):
        raise PlanPermissionRepairError(
            "INVALID_METADATA", "permission-set tags are malformed"
        )
    kms_mode = intent.get("identity_center_kms_mode")
    kms_key = intent.get("identity_center_kms_key_arn")
    if (
        kms_mode == "AWS_OWNED_KMS_KEY"
        and kms_key is not None
    ) or (
        kms_mode == "CUSTOMER_MANAGED_KEY"
        and (
            not isinstance(kms_key, str)
            or _IDENTITY_CENTER_KMS_ARN.fullmatch(kms_key) is None
        )
    ):
        raise PlanPermissionRepairError(
            "INVALID_KMS_BINDING", "Identity Center KMS binding differs"
        )
    if kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}:
        raise PlanPermissionRepairError(
            "INVALID_KMS_MODE", "Identity Center KMS mode is unsupported"
        )
    if intent.get("authorized_mutations") != list(AUTHORIZED_MUTATIONS):
        raise PlanPermissionRepairError(
            "MUTATION_SET_MISMATCH", "authorized mutations are not exact"
        )
    if any(
        intent.get(field) is not False
        for field in (
            "retry_permitted",
            "direct_human_sso_mutation_authorized",
            "production_authorized",
        )
    ):
        raise PlanPermissionRepairError(
            "AUTHORITY_OVERCLAIM", "intent overclaims repair authority"
        )
    not_before = parse_timestamp(intent.get("not_before"), "not_before")
    not_after = parse_timestamp(intent.get("not_after"), "not_after")
    if not_before >= not_after or not_after - not_before > MAX_WINDOW:
        raise PlanPermissionRepairError(
            "INVALID_WINDOW", "intent window exceeds fifteen minutes"
        )
    versions = intent.get("function_versions")
    if not isinstance(versions, Mapping) or set(versions) != set(FUNCTION_NAMES):
        raise PlanPermissionRepairError(
            "FUNCTION_BINDING_MISMATCH", "function version binding is incomplete"
        )
    if any(
        not isinstance(value, str) or _FUNCTION_VERSION.fullmatch(value) is None
        for value in versions.values()
    ):
        raise PlanPermissionRepairError(
            "UNPUBLISHED_FUNCTION", "function versions must be numeric"
        )
    if intent.get("function_qualifiers") != FUNCTION_QUALIFIERS:
        raise PlanPermissionRepairError(
            "FUNCTION_BINDING_MISMATCH", "function aliases are not exact"
        )
    assignment_digest = canonical_digest(
        Assignment("USER", intent["principal_id"]).as_record()
    )
    provisioned_accounts_digest = canonical_digest(
        {"account_ids": [AUTHORITY_ACCOUNT_ID]}
    )
    if (
        intent.get("assignment_digest") != assignment_digest
        or intent.get("provisioned_accounts_digest")
        != provisioned_accounts_digest
    ):
        raise PlanPermissionRepairError(
            "INTENT_BINDING_MISMATCH",
            "assignment or provisioned-account digest differs",
        )
    target = render_target_policy(str(intent.get("change_set_name", "")), repo_root=repo_root)
    predecessor = render_predecessor_policy(target)
    root = repo_root or Path(__file__).resolve().parents[1]
    try:
        policy_template = json.loads(
            (
                root
                / "policies/iam/platform-authority-bootstrap-plan-role.json"
            ).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanPermissionRepairError(
            "TARGET_POLICY_UNAVAILABLE",
            "reviewed bootstrap Plan policy cannot be read",
        ) from exc
    expected = {
        "change_set_name_digest": digest_value(intent["change_set_name"]),
        "policy_template_digest": canonical_digest(policy_template),
        "predecessor_policy_digest": canonical_digest(predecessor),
        "target_policy_digest": canonical_digest(target),
        "policy_delta_digest": policy_delta_digest(predecessor, target),
    }
    for field, value in expected.items():
        if intent.get(field) != value:
            raise PlanPermissionRepairError(
                "POLICY_BINDING_MISMATCH", f"{field} differs from source"
            )


def validate_snapshot(
    intent: Mapping[str, Any],
    snapshot: PlanPermissionSnapshot,
    stage: str,
) -> None:
    """Validate the sole eligible state at one repair boundary."""

    validate_private_intent(intent)
    exact = (
        (snapshot.instance_arn, intent["instance_arn"]),
        (snapshot.identity_store_id, intent["identity_store_id"]),
        (
            snapshot.identity_center_kms_mode,
            intent["identity_center_kms_mode"],
        ),
        (
            snapshot.identity_center_kms_key_arn,
            intent["identity_center_kms_key_arn"],
        ),
        (snapshot.permission_set_arn, intent["permission_set_arn"]),
        (snapshot.permission_set_name, PLAN_PERMISSION_SET_NAME),
        (
            snapshot.permission_set_description,
            intent["permission_set_description"],
        ),
        (snapshot.session_duration, PLAN_SESSION_DURATION),
        (snapshot.relay_state, None),
        (dict(snapshot.permission_set_tags), intent["permission_set_tags"]),
        (snapshot.role.role_arn, intent["role_arn"]),
        (snapshot.role.role_name, intent["role_name"]),
        (snapshot.role.saml_provider_arn, intent["saml_provider_arn"]),
        (snapshot.role.saml_audience, SAML_AUDIENCE),
        (snapshot.role.inline_policy_name, PLAN_ROLE_INLINE_POLICY_NAME),
        (
            snapshot.invocation_authority_graph_digest,
            intent["invocation_authority_graph_digest"],
        ),
    )
    if any(observed != expected for observed, expected in exact):
        raise PlanPermissionRepairError(
            "LIVE_BINDING_MISMATCH", "live Plan binding differs from intent"
        )
    if (
        snapshot.managed_policy_arns
        or snapshot.customer_managed_policy_references
        or snapshot.permissions_boundary_present
        or snapshot.role.attached_managed_policy_arns
        or snapshot.role.extra_inline_policy_names
        or snapshot.role.permissions_boundary_arn is not None
    ):
        raise PlanPermissionRepairError(
            "FOREIGN_AUTHORITY", "unexpected policy authority is attached"
        )
    expected_assignment = (Assignment("USER", str(intent["principal_id"])),)
    if (
        snapshot.assignments != expected_assignment
        or canonical_digest(snapshot.assignments[0].as_record())
        != intent["assignment_digest"]
    ):
        raise PlanPermissionRepairError(
            "ASSIGNMENT_MISMATCH", "Plan assignment differs from intent"
        )
    if (
        snapshot.provisioned_account_ids != (AUTHORITY_ACCOUNT_ID,)
        or canonical_digest(
            {"account_ids": list(snapshot.provisioned_account_ids)}
        )
        != intent["provisioned_accounts_digest"]
    ):
        raise PlanPermissionRepairError(
            "PROVISIONED_TARGET_MISMATCH",
            "Plan permission set is provisioned to a foreign account",
        )
    if snapshot.pending_operation_count != 0:
        raise PlanPermissionRepairError(
            "PENDING_OPERATION", "pending Identity Center operations exist"
        )
    permission_digest = canonical_digest(dict(snapshot.inline_policy))
    role_digest = canonical_digest(dict(snapshot.role.inline_policy))
    stages = {
        "BEFORE_PUT_INLINE_POLICY": (
            intent["predecessor_policy_digest"],
            intent["predecessor_policy_digest"],
        ),
        "BEFORE_PROVISION_PERMISSION_SET": (
            intent["target_policy_digest"],
            intent["predecessor_policy_digest"],
        ),
        "FINAL": (
            intent["target_policy_digest"],
            intent["target_policy_digest"],
        ),
    }
    expected_policies = stages.get(stage)
    if expected_policies is None:
        raise PlanPermissionRepairError(
            "UNKNOWN_STAGE", "repair snapshot stage is unsupported"
        )
    if (permission_digest, role_digest) != expected_policies:
        raise PlanPermissionRepairError(
            "STAGE_STATE_MISMATCH", "live policies do not match repair stage"
        )


_PROGRESS = {
    "PLAN_VERIFIED": ("PLAN_STATE_VERIFIED", 0, 0),
    "CLAIMED": ("BEFORE_FIRST_EFFECT", 0, 0),
    "ATTEMPTING_1": ("BEFORE_PUT_INLINE_POLICY", 0, 0),
    "COMPLETED_1": ("AFTER_PUT_INLINE_POLICY", 1, 1),
    "ATTEMPTING_2": ("BEFORE_PROVISION_PERMISSION_SET", 1, 1),
    "COMPLETED_2": ("AFTER_PROVISION_PERMISSION_SET", 2, 2),
    "REPAIR_VERIFIED": ("FINAL_READBACK_VERIFIED", 2, 2),
}
_UNCERTAIN_PROGRESS = {
    "UNCERTAIN_PUT_INLINE_POLICY": (1, 0),
    "UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT": (1, 1),
    "UNCERTAIN_PROVISION_PERMISSION_SET": (2, 1),
    "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT": (2, 2),
    "UNCERTAIN_FINAL_READBACK": (2, 2),
}
_ALLOWED_LEDGER_TRANSITIONS = {
    ("PLAN_VERIFIED", "CLAIMED"): frozenset(
        {("BEFORE_FIRST_EFFECT", 0, 0)}
    ),
    ("CLAIMED", "ATTEMPTING_1"): frozenset(
        {("BEFORE_PUT_INLINE_POLICY", 0, 0)}
    ),
    ("ATTEMPTING_1", "COMPLETED_1"): frozenset(
        {("AFTER_PUT_INLINE_POLICY", 1, 1)}
    ),
    ("ATTEMPTING_1", "UNCERTAIN_RECONCILE_ONLY"): frozenset(
        {
            ("UNCERTAIN_PUT_INLINE_POLICY", 1, 0),
            ("UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT", 1, 1),
        }
    ),
    ("COMPLETED_1", "ATTEMPTING_2"): frozenset(
        {("BEFORE_PROVISION_PERMISSION_SET", 1, 1)}
    ),
    ("ATTEMPTING_2", "COMPLETED_2"): frozenset(
        {("AFTER_PROVISION_PERMISSION_SET", 2, 2)}
    ),
    ("ATTEMPTING_2", "UNCERTAIN_RECONCILE_ONLY"): frozenset(
        {
            ("UNCERTAIN_PROVISION_PERMISSION_SET", 2, 1),
            ("UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT", 2, 2),
            ("UNCERTAIN_FINAL_READBACK", 2, 2),
        }
    ),
    ("COMPLETED_2", "REPAIR_VERIFIED"): frozenset(
        {("FINAL_READBACK_VERIFIED", 2, 2)}
    ),
}


def build_plan_ledger(
    intent: Mapping[str, Any],
    *,
    state_digest: str,
    planned_at: datetime,
) -> dict[str, Any]:
    validate_private_intent(intent)
    _require_digest(state_digest, "state_digest")
    ledger = {
        "schema_version": 1,
        "record_type": LEDGER_RECORD_TYPE,
        "repair_id": intent["repair_id"],
        "intent_digest": intent["intent_digest"],
        "source_commit": intent["source_commit"],
        "status": "PLAN_VERIFIED",
        "stage": "PLAN_STATE_VERIFIED",
        "effects_attempted": 0,
        "effects_completed": 0,
        "planned_state_digest": state_digest,
        "state_digest": state_digest,
        "planned_at": _timestamp(planned_at),
        "provider_immutable": True,
        "claim_condition": "attribute_not_exists(repair_id)",
        "mutation_retry_attempted": False,
        "retry_permitted": False,
        "production_authorized": False,
    }
    return _seal(ledger, "ledger_digest")


def transition_ledger(
    ledger: Mapping[str, Any],
    *,
    expected_status: str,
    new_status: str,
    stage: str,
    effects_attempted: int,
    effects_completed: int,
    state_digest: str,
    updated_at: datetime,
    claimed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_private_ledger(ledger)
    if ledger.get("status") != expected_status:
        raise PlanPermissionRepairError(
            "LEDGER_CAS_MISMATCH", "ledger status differs before transition"
        )
    transition = (stage, effects_attempted, effects_completed)
    if transition not in _ALLOWED_LEDGER_TRANSITIONS.get(
        (expected_status, new_status), frozenset()
    ):
        if expected_status in {
            "REPAIR_VERIFIED",
            "UNCERTAIN_RECONCILE_ONLY",
        }:
            raise PlanPermissionRepairError(
                "REPLAY_BLOCKED",
                "terminal ledger state cannot re-enter repair",
            )
        raise PlanPermissionRepairError(
            "INVALID_LEDGER_TRANSITION",
            "ledger transition is not an allowed state-machine edge",
        )
    first_claim = expected_status == "PLAN_VERIFIED" and new_status == "CLAIMED"
    if first_claim != (claimed_at is not None):
        raise PlanPermissionRepairError(
            "INVALID_LEDGER_TRANSITION",
            "claimed_at may only be introduced by the exact claim edge",
        )
    updated_timestamp = _timestamp(updated_at)
    if "updated_at" in ledger and parse_timestamp(
        updated_timestamp, "updated_at"
    ) < parse_timestamp(
        ledger.get("updated_at"), "updated_at"
    ):
        raise PlanPermissionRepairError(
            "INVALID_LEDGER_TRANSITION",
            "ledger updated_at cannot move backwards",
        )
    changed = dict(ledger)
    changed.update(
        {
            "status": new_status,
            "stage": stage,
            "effects_attempted": effects_attempted,
            "effects_completed": effects_completed,
            "state_digest": _require_digest(state_digest, "state_digest"),
            "updated_at": updated_timestamp,
        }
    )
    if claimed_at is not None:
        changed["claimed_at"] = _timestamp(claimed_at)
    changed.pop("ledger_digest", None)
    sealed = _seal(changed, "ledger_digest")
    validate_private_ledger(sealed)
    return sealed


def validate_private_ledger(ledger: Mapping[str, Any]) -> None:
    expected_fields = (
        PRIVATE_LEDGER_PLAN_FIELDS
        if isinstance(ledger, Mapping)
        and ledger.get("status") == "PLAN_VERIFIED"
        else PRIVATE_LEDGER_ACTIVE_FIELDS
    )
    if not isinstance(ledger, Mapping) or set(ledger) != expected_fields:
        raise PlanPermissionRepairError(
            "LEDGER_FIELDS_INVALID",
            "private ledger fields are not the exact closed contract",
        )
    if type(ledger.get("schema_version")) is not int or ledger.get(
        "schema_version"
    ) != 1 or ledger.get("record_type") != (
        LEDGER_RECORD_TYPE
    ):
        raise PlanPermissionRepairError(
            "LEDGER_TYPE_MISMATCH", "private ledger type is unsupported"
        )
    _validate_seal(ledger, "ledger_digest")
    if _REPAIR_ID.fullmatch(str(ledger.get("repair_id", ""))) is None:
        raise PlanPermissionRepairError(
            "INVALID_REPAIR_ID", "ledger repair ID is malformed"
        )
    if _COMMIT.fullmatch(str(ledger.get("source_commit", ""))) is None:
        raise PlanPermissionRepairError(
            "INVALID_SOURCE_COMMIT", "ledger source commit is malformed"
        )
    for field in ("intent_digest", "planned_state_digest", "state_digest"):
        _require_digest(ledger.get(field), field)
    if (
        ledger.get("provider_immutable") is not True
        or ledger.get("claim_condition") != "attribute_not_exists(repair_id)"
        or ledger.get("mutation_retry_attempted") is not False
        or ledger.get("retry_permitted") is not False
        or ledger.get("production_authorized") is not False
    ):
        raise PlanPermissionRepairError(
            "LEDGER_AUTHORITY_OVERCLAIM", "ledger safety flags are not exact"
        )
    status = ledger.get("status")
    stage = ledger.get("stage")
    counters = (
        ledger.get("effects_attempted"),
        ledger.get("effects_completed"),
    )
    if any(type(value) is not int for value in counters):
        raise PlanPermissionRepairError(
            "IMPOSSIBLE_LEDGER_PROGRESS", "ledger counters must be integers"
        )
    if status == "UNCERTAIN_RECONCILE_ONLY":
        expected = _UNCERTAIN_PROGRESS.get(str(stage))
        if expected != counters:
            raise PlanPermissionRepairError(
                "IMPOSSIBLE_LEDGER_PROGRESS", "uncertain progress is impossible"
            )
    else:
        expected_progress = _PROGRESS.get(str(status))
        if expected_progress != (stage, *counters):
            raise PlanPermissionRepairError(
                "IMPOSSIBLE_LEDGER_PROGRESS", "ledger progress is impossible"
            )
    planned_at = parse_timestamp(ledger.get("planned_at"), "planned_at")
    if status == "PLAN_VERIFIED":
        if "claimed_at" in ledger or "updated_at" in ledger:
            raise PlanPermissionRepairError(
                "IMPOSSIBLE_LEDGER_PROGRESS",
                "unclaimed Plan contains repair timestamps",
            )
        return
    claimed_at = parse_timestamp(ledger.get("claimed_at"), "claimed_at")
    updated_at = parse_timestamp(ledger.get("updated_at"), "updated_at")
    if not (planned_at <= claimed_at <= updated_at):
        raise PlanPermissionRepairError(
            "IMPOSSIBLE_LEDGER_PROGRESS", "ledger timestamps are not monotonic"
        )


def _build_receipt(
    *,
    intent: Mapping[str, Any],
    mode: str,
    status: str,
    ledger: Mapping[str, Any] | None,
    state_digest: str,
    generated_at: datetime,
    mutation_attribution: str,
    required_next_action: str,
) -> dict[str, Any]:
    if mode not in FUNCTION_NAMES:
        raise PlanPermissionRepairError("INVALID_MODE", "mode is unsupported")
    if ledger is not None:
        validate_private_ledger(ledger)
    receipt = {
        "schema_version": 1,
        "record_type": RECEIPT_RECORD_TYPE,
        "mode": mode,
        "status": status,
        "repair_id_digest": digest_value(intent["repair_id"]),
        "source_commit_digest": digest_value(intent["source_commit"]),
        "source_bundle_digest": intent["source_bundle_digest"],
        "function_version": intent["function_versions"][mode],
        "function_qualifier": FUNCTION_QUALIFIERS[mode],
        "region": REGION,
        "authority_account_suffix": AUTHORITY_ACCOUNT_ID[-4:],
        "management_account_suffix": MANAGEMENT_ACCOUNT_ID[-4:],
        "intent_digest": intent["intent_digest"],
        "ledger_digest": ledger.get("ledger_digest") if ledger else None,
        "state_digest": _require_digest(state_digest, "state_digest"),
        "predecessor_policy_digest": intent["predecessor_policy_digest"],
        "target_policy_digest": intent["target_policy_digest"],
        "policy_delta_digest": intent["policy_delta_digest"],
        "effects_attempted": (
            int(ledger.get("effects_attempted", 0)) if ledger else 0
        ),
        "effects_completed": (
            int(ledger.get("effects_completed", 0)) if ledger else 0
        ),
        "mutation_attribution": mutation_attribution,
        "required_next_action": required_next_action,
        "retry_permitted": False,
        "direct_human_sso_mutations": 0,
        "generated_at": _timestamp(generated_at),
        "production_status": PRODUCTION_STATUS,
    }
    sealed = _seal(receipt, "receipt_digest")
    validate_public_receipt(sealed)
    return sealed


def validate_public_receipt(receipt: Mapping[str, Any]) -> None:
    if not isinstance(receipt, Mapping) or set(receipt) != (
        PUBLIC_RECEIPT_FIELDS
    ):
        raise PlanPermissionRepairError(
            "RECEIPT_FIELDS_INVALID",
            "public receipt fields are not the exact closed contract",
        )
    if type(receipt.get("schema_version")) is not int or receipt.get(
        "schema_version"
    ) != 1 or receipt.get("record_type") != (
        RECEIPT_RECORD_TYPE
    ):
        raise PlanPermissionRepairError(
            "RECEIPT_TYPE_MISMATCH", "public receipt type is unsupported"
        )
    _validate_seal(receipt, "receipt_digest")
    for field in (
        "repair_id_digest",
        "source_commit_digest",
        "source_bundle_digest",
        "intent_digest",
        "state_digest",
        "predecessor_policy_digest",
        "target_policy_digest",
        "policy_delta_digest",
    ):
        _require_digest(receipt.get(field), field)
    ledger_digest = receipt.get("ledger_digest")
    if ledger_digest is not None:
        _require_digest(ledger_digest, "ledger_digest")
    if (
        receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("retry_permitted") is not False
        or type(receipt.get("direct_human_sso_mutations")) is not int
        or receipt.get("direct_human_sso_mutations") != 0
        or receipt.get("authority_account_suffix") != "7644"
        or receipt.get("management_account_suffix") != "1433"
        or receipt.get("region") != REGION
    ):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "public receipt safety boundary differs"
        )
    mode = receipt.get("mode")
    if mode not in FUNCTION_NAMES or receipt.get("function_qualifier") != (
        FUNCTION_QUALIFIERS[mode]
    ):
        raise PlanPermissionRepairError(
            "FUNCTION_BINDING_MISMATCH", "receipt function binding differs"
        )
    function_version = receipt.get("function_version")
    if not isinstance(function_version, str) or _FUNCTION_VERSION.fullmatch(
        function_version
    ) is None:
        raise PlanPermissionRepairError(
            "UNPUBLISHED_FUNCTION",
            "receipt function version must be published and numeric",
        )
    attempted = receipt.get("effects_attempted")
    completed = receipt.get("effects_completed")
    if (
        type(attempted) is not int
        or type(completed) is not int
        or not 0 <= completed <= attempted <= 2
    ):
        raise PlanPermissionRepairError(
            "IMPOSSIBLE_RECEIPT_PROGRESS", "receipt counters are impossible"
        )
    status = receipt.get("status")
    allowed = {
        "plan": {"PLAN_VERIFIED", "BLOCKED"},
        "repair": {
            "REPAIR_VERIFIED",
            "BLOCKED",
            "UNCERTAIN_RECONCILE_ONLY",
        },
        "reconcile": {
            "RECONCILE_VERIFIED",
            "BLOCKED",
            "UNCERTAIN_RECONCILE_ONLY",
        },
    }[mode]
    if status not in allowed:
        raise PlanPermissionRepairError(
            "INVALID_PUBLIC_STATUS", "receipt status is unsupported"
        )
    if status == "PLAN_VERIFIED" and (
        attempted,
        completed,
        receipt.get("required_next_action"),
    ) != (0, 0, "INVOKE_REPAIR_ALIAS"):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "Plan receipt progress is impossible"
        )
    if status == "REPAIR_VERIFIED" and (
        attempted,
        completed,
        receipt.get("required_next_action"),
    ) != (2, 2, "NONE"):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "repair receipt progress is impossible"
        )
    if status == "RECONCILE_VERIFIED" and not (
        attempted == 2
        and completed in {1, 2}
        and receipt.get("required_next_action") == "NONE"
    ):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "reconcile receipt progress is impossible"
        )
    if status == "UNCERTAIN_RECONCILE_ONLY" and (
        receipt.get("required_next_action") != "INVOKE_RECONCILE_ALIAS"
    ):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "uncertain receipt must require reconcile"
        )
    if status in {
        "PLAN_VERIFIED",
        "REPAIR_VERIFIED",
        "RECONCILE_VERIFIED",
        "UNCERTAIN_RECONCILE_ONLY",
    } and (
        ledger_digest is None
        or receipt.get("mutation_attribution")
        != "PROVEN_BY_DURABLE_LEDGER"
    ):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM",
            "verified or uncertain receipt requires durable attribution",
        )
    if status == "BLOCKED" and receipt.get("required_next_action") != (
        "REVIEW_BLOCKER"
    ):
        raise PlanPermissionRepairError(
            "PUBLIC_OVERCLAIM", "blocked receipt must require review"
        )
    if receipt.get("mutation_attribution") not in {
        "PROVEN_BY_DURABLE_LEDGER",
        "UNPROVEN",
    }:
        raise PlanPermissionRepairError(
            "INVALID_ATTRIBUTION", "mutation attribution is unsupported"
        )
    parse_timestamp(receipt.get("generated_at"), "generated_at")
    forbidden_fragments = (
        "arn:aws",
        AUTHORITY_ACCOUNT_ID,
        MANAGEMENT_ACCOUNT_ID,
        PLAN_PERMISSION_SET_NAME,
        PLAN_ROLE_PREFIX,
        "request_id",
        "change_set_name",
        "principal_id",
        "policy_document",
    )
    serialized = canonical_json(receipt)
    if any(fragment in serialized for fragment in forbidden_fragments):
        raise PlanPermissionRepairError(
            "PUBLIC_PRIVATE_VALUE_LEAK", "receipt exposes private repair data"
        )


@dataclass(frozen=True, slots=True)
class OperationResult:
    request_id: str
    status: str


class IdentityCenterPort(Protocol):
    def snapshot(self, intent: Mapping[str, Any]) -> PlanPermissionSnapshot: ...

    def put_inline_policy(
        self, intent: Mapping[str, Any], policy_json: str
    ) -> None: ...

    def provision_permission_set(
        self, intent: Mapping[str, Any]
    ) -> OperationResult: ...

    def describe_provisioning(
        self, intent: Mapping[str, Any], request_id: str
    ) -> str: ...


class LedgerPort(Protocol):
    def put_if_absent(self, ledger: Mapping[str, Any]) -> None: ...

    def read(self, repair_id: str) -> Mapping[str, Any] | None: ...

    def compare_and_swap(
        self,
        *,
        repair_id: str,
        expected_ledger_digest: str,
        expected_ledger: Mapping[str, Any],
        replacement: Mapping[str, Any],
    ) -> None: ...


class PlanPermissionRepair:
    """Two-effect, at-most-once state machine over injected ports."""

    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        provider: IdentityCenterPort,
        ledger: LedgerPort,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        maximum_poll_attempts: int = 30,
    ) -> None:
        validate_private_intent(intent)
        self._intent = dict(intent)
        self._provider = provider
        self._ledger = ledger
        self._now = now or (lambda: datetime.now(UTC))
        self._sleep = sleep
        self._maximum_poll_attempts = maximum_poll_attempts

    def _window_remaining_seconds(self) -> float:
        now = self._now().astimezone(UTC)
        start = parse_timestamp(self._intent["not_before"], "not_before")
        end = parse_timestamp(self._intent["not_after"], "not_after")
        if not start <= now <= end:
            raise PlanPermissionRepairError(
                "WINDOW_CLOSED", "immutable repair window is closed"
            )
        return (end - now).total_seconds()

    def _validate_time(self) -> None:
        self._window_remaining_seconds()

    def _validate_repair_start_window(self) -> None:
        if self._window_remaining_seconds() < (
            REPAIR_START_MIN_WINDOW_REMAINING_SECONDS
        ):
            raise PlanPermissionRepairError(
                "WINDOW_BUDGET_INSUFFICIENT",
                "repair window lacks the minimum pre-claim reserve",
            )

    def _validate_mutation_window(self) -> None:
        if self._window_remaining_seconds() <= (
            MUTATION_WINDOW_MIN_REMAINING_SECONDS
        ):
            raise PlanPermissionRepairError(
                "WINDOW_BUDGET_INSUFFICIENT",
                "repair window lacks the minimum mutation reserve",
            )

    def _read_ledger(self) -> dict[str, Any]:
        observed = self._ledger.read(str(self._intent["repair_id"]))
        if observed is None:
            raise PlanPermissionRepairError(
                "LEDGER_MISSING", "durable Plan ledger is absent"
            )
        ledger = dict(observed)
        validate_private_ledger(ledger)
        if (
            ledger["repair_id"] != self._intent["repair_id"]
            or ledger["intent_digest"] != self._intent["intent_digest"]
            or ledger["source_commit"] != self._intent["source_commit"]
        ):
            raise PlanPermissionRepairError(
                "LEDGER_BINDING_MISMATCH", "durable ledger differs from intent"
            )
        return ledger

    def _cas(
        self,
        ledger: Mapping[str, Any],
        *,
        expected_status: str,
        new_status: str,
        stage: str,
        attempted: int,
        completed: int,
        state_digest: str,
        claimed_at: datetime | None = None,
    ) -> dict[str, Any]:
        replacement = transition_ledger(
            ledger,
            expected_status=expected_status,
            new_status=new_status,
            stage=stage,
            effects_attempted=attempted,
            effects_completed=completed,
            state_digest=state_digest,
            updated_at=self._now(),
            claimed_at=claimed_at,
        )
        self._ledger.compare_and_swap(
            repair_id=str(self._intent["repair_id"]),
            expected_ledger_digest=str(ledger["ledger_digest"]),
            expected_ledger=ledger,
            replacement=replacement,
        )
        observed = self._read_ledger()
        if observed != replacement:
            raise PlanPermissionRepairError(
                "LEDGER_READBACK_MISMATCH", "ledger transition was not proven"
            )
        return observed

    def _receipt(
        self,
        *,
        mode: str,
        status: str,
        ledger: Mapping[str, Any] | None,
        state_digest: str,
        mutation_attribution: str,
        next_action: str,
    ) -> dict[str, Any]:
        return _build_receipt(
            intent=self._intent,
            mode=mode,
            status=status,
            ledger=ledger,
            state_digest=state_digest,
            generated_at=self._now(),
            mutation_attribution=mutation_attribution,
            required_next_action=next_action,
        )

    def plan(self) -> dict[str, Any]:
        self._validate_time()
        snapshot = self._provider.snapshot(self._intent)
        validate_snapshot(self._intent, snapshot, "BEFORE_PUT_INLINE_POLICY")
        self._validate_time()
        ledger = build_plan_ledger(
            self._intent,
            state_digest=snapshot.digest(),
            planned_at=self._now(),
        )
        try:
            self._ledger.put_if_absent(ledger)
        except Exception:
            observed = self._ledger.read(str(self._intent["repair_id"]))
            if observed != ledger:
                raise PlanPermissionRepairError(
                    "PLAN_LEDGER_UNPROVEN", "durable Plan write was not proven"
                ) from None
        if self._read_ledger() != ledger:
            raise PlanPermissionRepairError(
                "PLAN_LEDGER_UNPROVEN", "durable Plan readback differs"
            )
        return self._receipt(
            mode="plan",
            status="PLAN_VERIFIED",
            ledger=ledger,
            state_digest=snapshot.digest(),
            mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
            next_action="INVOKE_REPAIR_ALIAS",
        )

    def _mark_uncertain(
        self,
        ledger: Mapping[str, Any],
        *,
        expected_status: str,
        stage: str,
        attempted: int,
        completed: int,
        state_digest: str,
    ) -> Mapping[str, Any] | None:
        try:
            return self._cas(
                ledger,
                expected_status=expected_status,
                new_status="UNCERTAIN_RECONCILE_ONLY",
                stage=stage,
                attempted=attempted,
                completed=completed,
                state_digest=state_digest,
            )
        except Exception:
            return None

    def _uncertain_receipt(
        self,
        ledger: Mapping[str, Any] | None,
        state_digest: str,
    ) -> dict[str, Any]:
        if ledger is None:
            raise PlanPermissionRepairError(
                "UNCERTAINTY_LEDGER_UNPROVEN",
                "uncertain mutation outcome was not durably sealed",
            )
        return self._receipt(
            mode="repair",
            status="UNCERTAIN_RECONCILE_ONLY",
            ledger=ledger,
            state_digest=state_digest,
            mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
            next_action="INVOKE_RECONCILE_ALIAS",
        )

    def _wait_for_provision(self, operation: OperationResult) -> None:
        status = operation.status
        for attempt in range(self._maximum_poll_attempts + 1):
            if status == "SUCCEEDED":
                return
            if status == "FAILED":
                raise ProviderResponseAmbiguous(
                    "provisioning failed without a safe retry boundary"
                )
            if status != "IN_PROGRESS" or attempt == self._maximum_poll_attempts:
                raise ProviderResponseAmbiguous(
                    "provisioning did not reach a proven terminal state"
                )
            self._validate_time()
            self._sleep(1.0)
            status = self._provider.describe_provisioning(
                self._intent, operation.request_id
            )

    def repair(self) -> dict[str, Any]:
        self._validate_repair_start_window()
        initial = self._provider.snapshot(self._intent)
        validate_snapshot(self._intent, initial, "BEFORE_PUT_INLINE_POLICY")
        ledger = self._read_ledger()
        if ledger["status"] != "PLAN_VERIFIED":
            raise PlanPermissionRepairError(
                "REPLAY_BLOCKED", "durable Plan is absent or already consumed"
            )
        if ledger["planned_state_digest"] != initial.digest():
            raise PlanPermissionRepairError(
                "PLAN_STATE_CHANGED", "live state changed after Plan"
            )
        claimed_at = self._now()
        ledger = self._cas(
            ledger,
            expected_status="PLAN_VERIFIED",
            new_status="CLAIMED",
            stage="BEFORE_FIRST_EFFECT",
            attempted=0,
            completed=0,
            state_digest=initial.digest(),
            claimed_at=claimed_at,
        )

        before_put = self._provider.snapshot(self._intent)
        validate_snapshot(
            self._intent, before_put, "BEFORE_PUT_INLINE_POLICY"
        )
        self._validate_mutation_window()
        ledger = self._cas(
            ledger,
            expected_status="CLAIMED",
            new_status="ATTEMPTING_1",
            stage="BEFORE_PUT_INLINE_POLICY",
            attempted=0,
            completed=0,
            state_digest=initial.digest(),
        )
        target = render_target_policy(str(self._intent["change_set_name"]))
        try:
            self._provider.put_inline_policy(
                self._intent, canonical_json(target)
            )
            after_put = self._provider.snapshot(self._intent)
            validate_snapshot(
                self._intent, after_put, "BEFORE_PROVISION_PERMISSION_SET"
            )
        except Exception:
            uncertain = self._mark_uncertain(
                ledger,
                expected_status="ATTEMPTING_1",
                stage="UNCERTAIN_PUT_INLINE_POLICY",
                attempted=1,
                completed=0,
                state_digest=before_put.digest(),
            )
            return self._uncertain_receipt(uncertain, before_put.digest())
        try:
            ledger = self._cas(
                ledger,
                expected_status="ATTEMPTING_1",
                new_status="COMPLETED_1",
                stage="AFTER_PUT_INLINE_POLICY",
                attempted=1,
                completed=1,
                state_digest=after_put.digest(),
            )
        except Exception:
            uncertain = self._mark_uncertain(
                ledger,
                expected_status="ATTEMPTING_1",
                stage="UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT",
                attempted=1,
                completed=1,
                state_digest=after_put.digest(),
            )
            return self._uncertain_receipt(uncertain, after_put.digest())

        before_provision = self._provider.snapshot(self._intent)
        validate_snapshot(
            self._intent,
            before_provision,
            "BEFORE_PROVISION_PERMISSION_SET",
        )
        self._validate_mutation_window()
        ledger = self._cas(
            ledger,
            expected_status="COMPLETED_1",
            new_status="ATTEMPTING_2",
            stage="BEFORE_PROVISION_PERMISSION_SET",
            attempted=1,
            completed=1,
            state_digest=after_put.digest(),
        )
        try:
            operation = self._provider.provision_permission_set(self._intent)
            if not isinstance(operation, OperationResult) or not (
                operation.request_id
            ):
                raise ProviderResponseAmbiguous(
                    "provisioning response lacks request identity"
                )
            self._wait_for_provision(operation)
        except Exception:
            uncertain = self._mark_uncertain(
                ledger,
                expected_status="ATTEMPTING_2",
                stage="UNCERTAIN_PROVISION_PERMISSION_SET",
                attempted=2,
                completed=1,
                state_digest=before_provision.digest(),
            )
            return self._uncertain_receipt(
                uncertain, before_provision.digest()
            )
        try:
            final = self._provider.snapshot(self._intent)
            validate_snapshot(self._intent, final, "FINAL")
        except Exception:
            uncertain = self._mark_uncertain(
                ledger,
                expected_status="ATTEMPTING_2",
                stage="UNCERTAIN_FINAL_READBACK",
                attempted=2,
                completed=2,
                state_digest=before_provision.digest(),
            )
            return self._uncertain_receipt(
                uncertain, before_provision.digest()
            )
        try:
            ledger = self._cas(
                ledger,
                expected_status="ATTEMPTING_2",
                new_status="COMPLETED_2",
                stage="AFTER_PROVISION_PERMISSION_SET",
                attempted=2,
                completed=2,
                state_digest=final.digest(),
            )
        except Exception:
            uncertain = self._mark_uncertain(
                ledger,
                expected_status="ATTEMPTING_2",
                stage="UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT",
                attempted=2,
                completed=2,
                state_digest=final.digest(),
            )
            return self._uncertain_receipt(uncertain, final.digest())
        ledger = self._cas(
            ledger,
            expected_status="COMPLETED_2",
            new_status="REPAIR_VERIFIED",
            stage="FINAL_READBACK_VERIFIED",
            attempted=2,
            completed=2,
            state_digest=final.digest(),
        )
        return self._receipt(
            mode="repair",
            status="REPAIR_VERIFIED",
            ledger=ledger,
            state_digest=final.digest(),
            mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
            next_action="NONE",
        )

    def reconcile(self) -> dict[str, Any]:
        ledger = self._read_ledger()
        snapshot = self._provider.snapshot(self._intent)
        final_exact = True
        try:
            validate_snapshot(self._intent, snapshot, "FINAL")
        except PlanPermissionRepairError:
            final_exact = False
        stage = ledger["stage"]
        final_capable = ledger["status"] == "REPAIR_VERIFIED" or (
            ledger["status"] == "UNCERTAIN_RECONCILE_ONLY"
            and stage
            in {
                "UNCERTAIN_PROVISION_PERMISSION_SET",
                "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT",
                "UNCERTAIN_FINAL_READBACK",
            }
        )
        if final_exact and final_capable:
            return self._receipt(
                mode="reconcile",
                status="RECONCILE_VERIFIED",
                ledger=ledger,
                state_digest=snapshot.digest(),
                mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
                next_action="NONE",
            )
        if ledger["status"] == "UNCERTAIN_RECONCILE_ONLY":
            return self._receipt(
                mode="reconcile",
                status="UNCERTAIN_RECONCILE_ONLY",
                ledger=ledger,
                state_digest=snapshot.digest(),
                mutation_attribution="PROVEN_BY_DURABLE_LEDGER",
                next_action="INVOKE_RECONCILE_ALIAS",
            )
        return self._receipt(
            mode="reconcile",
            status="BLOCKED",
            ledger=ledger,
            state_digest=snapshot.digest(),
            mutation_attribution="UNPROVEN",
            next_action="REVIEW_BLOCKER",
        )


def validate_empty_event(event: Any) -> None:
    if type(event) is not dict or event:
        raise PlanPermissionRepairError(
            "NON_EMPTY_EVENT", "authoritative Lambda event must be exactly {}"
        )


def validate_versioned_lambda_contract(
    *,
    mode: str,
    event: Any,
    context: Any,
    env: Mapping[str, str],
) -> None:
    validate_empty_event(event)
    if mode not in FUNCTION_NAMES:
        raise PlanPermissionRepairError("INVALID_MODE", "mode is unsupported")
    version = env.get("AWS_LAMBDA_FUNCTION_VERSION")
    if not isinstance(version, str) or _FUNCTION_VERSION.fullmatch(version) is None:
        raise PlanPermissionRepairError(
            "UNPUBLISHED_FUNCTION", "Lambda version must be published and numeric"
        )
    expected_version_key = {
        "plan": None,
        "repair": "PLAN_FUNCTION_VERSION",
        "reconcile": "REPAIR_FUNCTION_VERSION",
    }[mode]
    if expected_version_key is not None:
        predecessor_version = env.get(expected_version_key)
        if (
            not isinstance(predecessor_version, str)
            or _FUNCTION_VERSION.fullmatch(predecessor_version) is None
        ):
            raise PlanPermissionRepairError(
                "FUNCTION_CHAIN_UNBOUND",
                "prior published function version is not immutable",
            )
    invoked_arn = getattr(context, "invoked_function_arn", None)
    expected_arn = (
        f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{FUNCTION_NAMES[mode]}:{FUNCTION_QUALIFIERS[mode]}"
    )
    if invoked_arn != expected_arn:
        raise PlanPermissionRepairError(
            "FUNCTION_BINDING_MISMATCH", "invoked Lambda alias is not exact"
        )
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    if not callable(remaining):
        raise PlanPermissionRepairError(
            "FUNCTION_CONTEXT_MISSING", "Lambda runtime context is incomplete"
        )
    remaining_ms = remaining()
    if type(remaining_ms) is not int:
        raise PlanPermissionRepairError(
            "FUNCTION_CONTEXT_MISSING", "Lambda runtime context is incomplete"
        )
    if remaining_ms <= LAMBDA_ENTRY_MINIMUM_REMAINING_MS[mode]:
        raise PlanPermissionRepairError(
            "FUNCTION_BUDGET_INSUFFICIENT",
            "Lambda remaining-time budget is below the mode entry reserve",
        )


def validate_runtime_environment(
    intent: Mapping[str, Any],
    *,
    mode: str,
    env: Mapping[str, str],
) -> None:
    """Bind one injected runtime to the immutable IaC environment."""

    validate_private_intent(intent)
    if mode not in FUNCTION_NAMES:
        raise PlanPermissionRepairError("INVALID_MODE", "mode is unsupported")
    validate_lambda_environment_budget(env, mode=mode)
    claimed_configuration_digest = validate_immutable_configuration_digest(
        env
    )
    if claimed_configuration_digest != immutable_configuration_digest_from_intent(
        intent
    ):
        raise PlanPermissionRepairError(
            "IMMUTABLE_CONFIGURATION_DIGEST_MISMATCH",
            "immutable configuration digest differs from intent",
        )
    expected = {
        "SOURCE_COMMIT": intent["source_commit"],
        "SOURCE_BUNDLE_DIGEST": intent["source_bundle_digest"],
        "REPAIR_ID": intent["repair_id"],
        "PRINCIPAL_ID": intent["principal_id"],
        "IDENTITY_STORE_ID": intent["identity_store_id"],
        "IDENTITY_CENTER_INSTANCE_ARN": intent["instance_arn"],
        "PLAN_PERMISSION_SET_ARN": intent["permission_set_arn"],
        "EXPECTED_PERMISSION_SET_DESCRIPTION": (
            intent["permission_set_description"]
        ),
        "REPAIR_INVOKER_PERMISSION_SET_ARN": (
            intent["repair_invoker_permission_set_arn"]
        ),
        "CURRENT_POLICY_DIGEST": intent["predecessor_policy_digest"],
        "DESIRED_POLICY_DIGEST": intent["target_policy_digest"],
        "BOOTSTRAP_CHANGE_SET_NAME": intent["change_set_name"],
        "REPAIR_LEDGER_TABLE_NAME": intent["ledger_table_name"],
        "REPAIR_LEDGER_KMS_KEY_ARN": intent["ledger_kms_key_arn"],
        "EXPECTED_ARTIFACT_CODE_SHA256": (
            intent["expected_artifact_code_sha256"]
        ),
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": (
            intent["expected_code_signing_config_arn"]
        ),
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": (
            intent["expected_signing_profile_version_arn"]
        ),
        "REPAIR_NOT_BEFORE": intent["not_before"],
        "REPAIR_NOT_AFTER": intent["not_after"],
        "PLAN_SAML_PROVIDER_ARN": intent["saml_provider_arn"],
        "IDENTITY_CENTER_KMS_MODE": intent["identity_center_kms_mode"],
        "IDENTITY_CENTER_KMS_KEY_ARN": (
            intent["identity_center_kms_key_arn"] or ""
        ),
        "EXPECTED_BOTO3_VERSION": intent["expected_boto3_version"],
        "EXPECTED_BOTOCORE_VERSION": intent["expected_botocore_version"],
        "AWS_LAMBDA_FUNCTION_VERSION": intent["function_versions"][mode],
    }
    if mode in {"repair", "reconcile"}:
        expected["PLAN_FUNCTION_VERSION"] = intent["function_versions"]["plan"]
    if mode == "reconcile":
        expected["REPAIR_FUNCTION_VERSION"] = intent["function_versions"][
            "repair"
        ]
    for key, value in expected.items():
        if env.get(key) != value:
            raise PlanPermissionRepairError(
                "IMMUTABLE_ENVIRONMENT_MISMATCH",
                f"immutable runtime setting {key} differs from intent",
            )
    try:
        tags = json.loads(
            str(env.get("EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"))
        )
    except json.JSONDecodeError as exc:
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISMATCH",
            "immutable permission-set tags are malformed",
        ) from exc
    if type(tags) is not dict or tags != intent["permission_set_tags"]:
        raise PlanPermissionRepairError(
            "IMMUTABLE_ENVIRONMENT_MISMATCH",
            "immutable permission-set tags differ from intent",
        )


RuntimeFactory = Callable[
    [str, Mapping[str, str], Any],
    PlanPermissionRepair,
]
_runtime_factory: RuntimeFactory | None = None


def install_runtime_factory(factory: RuntimeFactory | None) -> None:
    """Bind deployment adapters explicitly; ``None`` restores fail-closed mode."""

    global _runtime_factory
    _runtime_factory = factory


def _lambda_handler(mode: str, event: Any, context: Any) -> dict[str, Any]:
    validate_lambda_environment_budget(os.environ, mode=mode)
    validate_immutable_configuration_digest(os.environ)
    validate_versioned_lambda_contract(
        mode=mode,
        event=event,
        context=context,
        env=os.environ,
    )
    if _runtime_factory is None:
        raise PlanPermissionRepairError(
            "RUNTIME_PORTS_NOT_BOUND",
            "versioned Lambda package has no reviewed provider/ledger binding",
        )
    runtime = _runtime_factory(mode, os.environ, context)
    if not isinstance(runtime, PlanPermissionRepair):
        raise PlanPermissionRepairError(
            "RUNTIME_PORTS_NOT_BOUND", "runtime factory returned an invalid binding"
        )
    validate_runtime_environment(runtime._intent, mode=mode, env=os.environ)
    return {
        "plan": runtime.plan,
        "repair": runtime.repair,
        "reconcile": runtime.reconcile,
    }[mode]()


def plan_handler(event: Any, context: Any) -> dict[str, Any]:
    return _lambda_handler("plan", event, context)


def repair_handler(event: Any, context: Any) -> dict[str, Any]:
    return _lambda_handler("repair", event, context)


def reconcile_handler(event: Any, context: Any) -> dict[str, Any]:
    return _lambda_handler("reconcile", event, context)


def sanitized_blocked_receipt(code: str) -> dict[str, Any]:
    """Return a stable offline denial without reflecting rejected inputs."""

    return {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_offline_block.v1"
        ),
        "status": "BLOCKED",
        "blocker_code": code,
        "aws_calls": 0,
        "aws_mutations": 0,
        "direct_human_sso_mutation_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }


def immutable_environment_keys() -> tuple[str, ...]:
    """Expose the shared IaC/runtime environment contract for contract tests."""

    return (
        "SOURCE_COMMIT",
        "SOURCE_BUNDLE_DIGEST",
        "REPAIR_ID",
        "PRINCIPAL_ID",
        "IDENTITY_STORE_ID",
        "IDENTITY_CENTER_INSTANCE_ARN",
        "PLAN_PERMISSION_SET_ARN",
        "EXPECTED_PERMISSION_SET_DESCRIPTION",
        "REPAIR_INVOKER_PERMISSION_SET_ARN",
        "CURRENT_POLICY_DIGEST",
        "DESIRED_POLICY_DIGEST",
        "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
        "BOOTSTRAP_CHANGE_SET_NAME",
        "REPAIR_LEDGER_TABLE_NAME",
        "REPAIR_LEDGER_KMS_KEY_ARN",
        "EXPECTED_ARTIFACT_CODE_SHA256",
        "EXPECTED_CODE_SIGNING_CONFIG_ARN",
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
        "REPAIR_NOT_BEFORE",
        "REPAIR_NOT_AFTER",
        "PLAN_SAML_PROVIDER_ARN",
        "IDENTITY_CENTER_KMS_MODE",
        "IDENTITY_CENTER_KMS_KEY_ARN",
        "EXPECTED_BOTO3_VERSION",
        "EXPECTED_BOTOCORE_VERSION",
    )


__all__: Sequence[str] = (
    "Assignment",
    "AUTHORIZED_MUTATIONS",
    "FUNCTION_NAMES",
    "FUNCTION_QUALIFIERS",
    "IdentityCenterPort",
    "IMMUTABLE_CONFIGURATION_PARAMETER_KEYS",
    "IMMUTABLE_CONFIGURATION_PARAMETER_TO_ENV",
    "LAMBDA_ENVIRONMENT_LIMIT_BYTES",
    "LedgerPort",
    "OperationResult",
    "PlanPermissionRepair",
    "PlanPermissionRepairError",
    "PlanPermissionSnapshot",
    "ProviderResponseAmbiguous",
    "RepairBinding",
    "RoleSnapshot",
    "build_plan_ledger",
    "build_private_intent",
    "configured_lambda_environment",
    "immutable_configuration_digest_from_environment",
    "immutable_configuration_digest_from_intent",
    "immutable_configuration_digest_from_parameters",
    "immutable_configuration_projection_from_environment",
    "immutable_environment_keys",
    "install_runtime_factory",
    "lambda_environment_size_bytes",
    "plan_handler",
    "policy_delta_digest",
    "reconcile_handler",
    "render_predecessor_policy",
    "render_target_policy",
    "repair_handler",
    "sanitized_blocked_receipt",
    "transition_ledger",
    "validate_empty_event",
    "validate_immutable_configuration_digest",
    "validate_lambda_environment_budget",
    "validate_private_intent",
    "validate_private_ledger",
    "validate_public_receipt",
    "validate_runtime_environment",
    "validate_snapshot",
    "validate_versioned_lambda_contract",
)
