"""AWS-enforced one-shot PEP for one retained CloudFormation Change Set.

The broker is the only runtime principal allowed to mutate the GUG-215 ledger
or call ``DeleteChangeSet``. Human permission sets can only obtain
ordinary sessions for exact synchronous Function URLs. GUG-217 proves the
human identity inside this version-pinned broker before the proof digest is
persisted. Request payloads never establish target, identity, or action.

The module intentionally emits only sanitized status codes. It does not log
AWS responses, identifiers, Identity Store values, or control-plane payloads.
"""
from __future__ import annotations

import hashlib
import base64
import copy
import json
import os
import re
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from tooling.platform_authority_single_operator_retirement_exception import (
    EXCEPTION_MODE,
    NORMAL_MODE,
    SingleOperatorExceptionError,
    build_single_operator_retirement_exception,
    require_exception_effect_window,
)


CANONICAL_STACK_NAME = "scanalyze-platform-authority-state-backend"
CANONICAL_STATE_KEY = "platform-authority/terraform.tfstate"
RETIREMENT_LEDGER_TABLE = "scanalyze-platform-authority-change-set-retirements"
BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
BROKER_LOG_GROUP_NAME = f"/aws/lambda/{BROKER_FUNCTION_NAME}"
BROKER_POLICY_NAME = "Gug215ExactRetirement"
CLASSIFIER_INVOKER_POLICY_NAME = "Gug215ClassifierInvokeOnly"
APPROVER_INVOKER_POLICY_NAME = "Gug215ApproverInvokeOnly"
PROOF_POLICY_NAME = "Gug217ZeroAuthorityProof"
PERMISSIONS_BOUNDARY_POLICY_PATH = "/scanalyze/platform-authority/"
BROKER_BOUNDARY_POLICY_NAME = (
    "scanalyze-platform-authority-gug365-broker-boundary"
)
CLASSIFIER_INVOKER_BOUNDARY_POLICY_NAME = (
    "scanalyze-platform-authority-gug365-classifier-invoker-boundary"
)
APPROVER_INVOKER_BOUNDARY_POLICY_NAME = (
    "scanalyze-platform-authority-gug365-approver-invoker-boundary"
)
PROOF_BOUNDARY_POLICY_NAME = (
    "scanalyze-platform-authority-gug365-proof-boundary"
)
LEDGER_FACTORY_ROLE_NAME = "ScanalyzeGug365LedgerFactory"
ALIAS_CLASSIFY = "classify"
ALIAS_RETIRE = "retire"
ALIAS_RECONCILE = "reconcile"
ALIAS_SINGLE_CLASSIFY = "single-classify"
ALIAS_SINGLE_RETIRE = "single-retire"
ALIAS_SINGLE_RECONCILE = "single-reconcile"
AUTHORIZATION_MODE_TWO_HUMAN = NORMAL_MODE
AUTHORIZATION_MODE_SINGLE_OPERATOR = EXCEPTION_MODE
NORMAL_ALIASES = frozenset({ALIAS_CLASSIFY, ALIAS_RETIRE, ALIAS_RECONCILE})
SINGLE_OPERATOR_ALIASES = frozenset(
    {ALIAS_SINGLE_CLASSIFY, ALIAS_SINGLE_RETIRE, ALIAS_SINGLE_RECONCILE}
)
ALLOWED_ALIASES = NORMAL_ALIASES | SINGLE_OPERATOR_ALIASES
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
BASE64_SHA256 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
CHANGE_SET_NAME = re.compile(r"^scanalyze-platform-authority-bootstrap-[0-9]{14}$")
IDENTITY_STORE_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EXPECTED_TAGS = {
    "managed_by": "cloudformation",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-206",
}
EXPECTED_LEDGER_TAGS = {
    "managed_by": "reviewed-direct-dynamodb",
    "service": "scanalyze-platform-authority",
    "data_class": "control-metadata",
    "work_package": "GUG-215",
    "environment": "non-production",
    "production": "false",
}
EXPECTED_RESOURCE_CHANGES = (
    ("StateBucket", "AWS::S3::Bucket", "Add", "False"),
    ("StateBucketPolicy", "AWS::S3::BucketPolicy", "Add", "False"),
    ("StateKmsAlias", "AWS::KMS::Alias", "Add", "False"),
    ("StateKmsKey", "AWS::KMS::Key", "Add", "False"),
)
PUBLIC_ACCESS_BLOCK_KEYS = frozenset(
    {
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    }
)
LEDGER_V2_STATES = frozenset(
    {"CLASSIFIED", "APPROVED", "ATTEMPTED", "RETIRED_RECONCILED"}
)
LEDGER_V3_STATES = frozenset(
    {"CLASSIFIED", "EXCEPTION_ACCEPTED", "ATTEMPTED", "RETIRED_RECONCILED"}
)
LEDGER_V2_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "authority_account_id_digest",
        "region",
        "stack_name",
        "retirement_id",
        "stack_id_digest",
        "change_set_id_digest",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "identity_store_arn_digest",
        "identity_center_instance_arn_digest",
        "identity_center_application_arn_digest",
        "classifier_identity_store_user_id_digest",
        "approver_identity_store_user_id_digest",
        "classifier_assignment_sha256",
        "approver_assignment_sha256",
        "classifier_invoker_policy_sha256",
        "approver_invoker_policy_sha256",
        "classifier_proof_policy_sha256",
        "approver_proof_policy_sha256",
        "identity_center_application_actor_policy_sha256",
        "broker_code_sha256",
        "broker_policy_sha256",
        "identity_separation",
        "human_authentication_evidence",
        "aws_effect_principal",
        "native_on_behalf_of",
        "classifier_identity_proof_sha256",
        "approver_identity_proof_sha256",
        "reconciliation_identity_proof_sha256",
        "state",
        "version",
        "attempt_count",
        "approval_digest",
        "attempt_digest",
        "verification_digest",
        "classified_at",
        "approved_at",
        "attempted_at",
        "verified_at",
        "effect_attribution",
        "next_required_control",
        "updated_at",
        "ledger_digest",
    }
)
LEDGER_V3_KEYS = LEDGER_V2_KEYS | frozenset(
    {
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "single_operator_authorization_sha256",
        "broker_runtime_version_arn_digest",
        "broker_version_binding_sha256",
        "owner_authorization_sha256",
        "exception_created_at",
        "exception_not_before",
        "exception_expires_at",
    }
)
WRITE_ACTIONS = frozenset(
    {
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem",
    }
)
# IAM authorizes TransactWriteItems through its underlying item actions.
# Preserve the historical v1 policy/digest; workforce uses valid IAM actions.
WORKFORCE_WRITE_ACTIONS = WRITE_ACTIONS - {"dynamodb:TransactWriteItems"}


class BrokerError(ValueError):
    """A fail-closed broker decision with a non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code):
            code = "BROKER_DENIED"
        self.code = code
        super().__init__(code)


def _canonical_resource_change(
    resource: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    """Normalize one exact GUG-215 CREATE/Add resource change."""

    logical_id = resource.get("LogicalResourceId")
    resource_type = resource.get("ResourceType")
    action = resource.get("Action")
    if (
        not isinstance(logical_id, str)
        or not isinstance(resource_type, str)
        or not isinstance(action, str)
        or action != "Add"
    ):
        raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")

    replacement = resource["Replacement"] if "Replacement" in resource else "False"
    if not isinstance(replacement, str) or replacement != "False":
        raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
    return logical_id, resource_type, action, replacement


def canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def secret_digest(label: str, value: str) -> str:
    return canonical_digest({label: value})


BROKER_VERSION_BINDING_FIELDS = (
    "authority_account_id",
    "region",
    "change_set_name",
    "expected_template_sha256",
    "expected_evidence_sha256",
    "expected_code_sha256",
    "expected_broker_policy_sha256",
    "identity_store_arn",
    "identity_center_instance_arn",
    "identity_center_application_arn",
    "identity_center_redirect_uri",
    "classifier_identity_store_user_id",
    "approver_identity_store_user_id",
    "classifier_assignment_sha256",
    "approver_assignment_sha256",
    "classifier_invoker_policy_sha256",
    "approver_invoker_policy_sha256",
    "classifier_proof_policy_sha256",
    "approver_proof_policy_sha256",
    "identity_center_application_actor_policy_sha256",
    "classifier_invoker_role_name",
    "approver_invoker_role_name",
    "classifier_proof_role_name",
    "approver_proof_role_name",
    "classifier_permission_set_role_arn",
    "approver_permission_set_role_arn",
    "broker_execution_role_name",
    "code_signing_config_arn",
    "broker_runtime_version_arn",
    "retirement_id",
    "authorization_mode",
)


def broker_version_binding_digest(values: Mapping[str, Any]) -> str:
    """Bind every published-version property and environment input."""

    missing = [field for field in BROKER_VERSION_BINDING_FIELDS if field not in values]
    if missing:
        raise BrokerError("BROKER_VERSION_BINDING_INCOMPLETE")
    return canonical_digest(
        {
            "schema_version": "1",
            "record_type": "platform_authority_gug215_broker_version_binding",
            "lambda_version_properties": {
                "architectures": ["x86_64"],
                "dead_letter_config": {},
                "ephemeral_storage": {"Size": 512},
                "file_system_configs": [],
                "handler": (
                    "tooling.platform_authority_identity_context_pep_runtime.handler"
                ),
                "kms_key_arn": None,
                "layers": [],
                "memory_size": 256,
                "package_type": "Zip",
                "reserved_concurrency": 1,
                "runtime": "python3.12",
                "runtime_update_mode": "Manual",
                "snap_start": {
                    "ApplyOn": "None",
                    "OptimizationStatus": "Off",
                },
                "timeout": 60,
                "tracing_config": {"Mode": "PassThrough"},
                "vpc_config": {
                    "SecurityGroupIds": [],
                    "SubnetIds": [],
                    "VpcId": "",
                },
                "logging": {
                    "application_log_level": "ERROR",
                    "log_format": "JSON",
                    "log_group": BROKER_LOG_GROUP_NAME,
                    "retention_days": 365,
                    "system_log_level": "WARN",
                },
            },
            "configuration": {
                field: values[field] for field in BROKER_VERSION_BINDING_FIELDS
            },
        }
    )


def _require_digest(value: str, code: str) -> str:
    if DIGEST.fullmatch(value) is None:
        raise BrokerError(code)
    return value


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _timestamp(now: datetime) -> str:
    if now.tzinfo is None:
        raise BrokerError("CLOCK_INVALID")
    return now.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise BrokerError("LEDGER_MALFORMED")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BrokerError("LEDGER_MALFORMED") from exc
    if parsed.tzinfo is None:
        raise BrokerError("LEDGER_MALFORMED")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class BrokerConfig:
    authority_account_id: str
    region: str
    change_set_name: str
    expected_template_sha256: str
    expected_evidence_sha256: str
    expected_code_sha256: str
    expected_broker_policy_sha256: str
    identity_store_arn: str
    identity_center_instance_arn: str
    identity_center_application_arn: str
    identity_center_redirect_uri: str
    classifier_identity_store_user_id: str
    approver_identity_store_user_id: str
    classifier_assignment_sha256: str
    approver_assignment_sha256: str
    classifier_invoker_policy_sha256: str
    approver_invoker_policy_sha256: str
    classifier_proof_policy_sha256: str
    approver_proof_policy_sha256: str
    identity_center_application_actor_policy_sha256: str
    classifier_invoker_role_name: str
    approver_invoker_role_name: str
    classifier_proof_role_name: str
    approver_proof_role_name: str
    classifier_permission_set_role_arn: str
    approver_permission_set_role_arn: str
    broker_execution_role_name: str
    code_signing_config_arn: str
    broker_runtime_version_arn: str
    broker_version_binding_sha256: str
    retirement_id: str
    authorization_mode: str = AUTHORIZATION_MODE_TWO_HUMAN
    single_operator_expected_authorization_sha256: str = ""
    single_operator_owner_authorization_sha256: str = ""
    single_operator_exception_created_at: str = ""
    single_operator_exception_not_before: str = ""
    single_operator_exception_expires_at: str = ""
    stack_name: str = CANONICAL_STACK_NAME
    ledger_table_name: str = RETIREMENT_LEDGER_TABLE
    function_name: str = BROKER_FUNCTION_NAME

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise BrokerError("ACCOUNT_BINDING_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise BrokerError("REGION_BINDING_INVALID")
        if self.stack_name != CANONICAL_STACK_NAME:
            raise BrokerError("STACK_BINDING_INVALID")
        if self.ledger_table_name != RETIREMENT_LEDGER_TABLE:
            raise BrokerError("LEDGER_BINDING_INVALID")
        if self.function_name != BROKER_FUNCTION_NAME:
            raise BrokerError("FUNCTION_BINDING_INVALID")
        if CHANGE_SET_NAME.fullmatch(self.change_set_name) is None:
            raise BrokerError("CHANGE_SET_BINDING_INVALID")
        if re.fullmatch(r"gug215#sha256:[a-f0-9]{64}", self.retirement_id) is None:
            raise BrokerError("RETIREMENT_ID_INVALID")
        for value, code in (
            (self.expected_template_sha256, "TEMPLATE_DIGEST_INVALID"),
            (self.expected_evidence_sha256, "EVIDENCE_DIGEST_INVALID"),
            (self.expected_broker_policy_sha256, "BROKER_POLICY_DIGEST_INVALID"),
            (self.classifier_assignment_sha256, "CLASSIFIER_ASSIGNMENT_DIGEST_INVALID"),
            (self.approver_assignment_sha256, "APPROVER_ASSIGNMENT_DIGEST_INVALID"),
            (
                self.classifier_invoker_policy_sha256,
                "CLASSIFIER_POLICY_DIGEST_INVALID",
            ),
            (self.approver_invoker_policy_sha256, "APPROVER_POLICY_DIGEST_INVALID"),
            (self.classifier_proof_policy_sha256, "CLASSIFIER_PROOF_POLICY_DIGEST_INVALID"),
            (self.approver_proof_policy_sha256, "APPROVER_PROOF_POLICY_DIGEST_INVALID"),
            (
                self.identity_center_application_actor_policy_sha256,
                "APPLICATION_ACTOR_POLICY_DIGEST_INVALID",
            ),
        ):
            _require_digest(value, code)
        if BASE64_SHA256.fullmatch(self.expected_code_sha256) is None:
            raise BrokerError("CODE_DIGEST_INVALID")
        if (
            IDENTITY_STORE_USER_ID.fullmatch(self.classifier_identity_store_user_id)
            is None
            or IDENTITY_STORE_USER_ID.fullmatch(self.approver_identity_store_user_id)
            is None
        ):
            raise BrokerError("IDENTITY_STORE_USER_INVALID")
        users_equal = (
            self.classifier_identity_store_user_id.lower()
            == self.approver_identity_store_user_id.lower()
        )
        exception_values = (
            self.single_operator_expected_authorization_sha256,
            self.single_operator_owner_authorization_sha256,
            self.single_operator_exception_created_at,
            self.single_operator_exception_not_before,
            self.single_operator_exception_expires_at,
        )
        if self.authorization_mode == AUTHORIZATION_MODE_TWO_HUMAN:
            if users_equal:
                raise BrokerError("INDEPENDENT_OPERATOR_REQUIRED")
            if any(exception_values):
                raise BrokerError("SINGLE_OPERATOR_CONFIGURATION_FORBIDDEN")
        elif self.authorization_mode == AUTHORIZATION_MODE_SINGLE_OPERATOR:
            if not users_equal:
                raise BrokerError("SINGLE_OPERATOR_IDENTITY_REQUIRED")
            if any(not value for value in exception_values):
                raise BrokerError("CONFIGURATION_INCOMPLETE")
            _require_digest(
                self.single_operator_expected_authorization_sha256,
                "REVIEWED_AUTHORIZATION_DIGEST_INVALID",
            )
        else:
            raise BrokerError("AUTHORIZATION_MODE_INVALID")
        partition = _partition(self.region)
        if not re.fullmatch(
            rf"arn:{partition}:identitystore::[0-9]{{12}}:identitystore/d-[a-z0-9]{{10,}}",
            self.identity_store_arn,
        ):
            raise BrokerError("IDENTITY_STORE_BINDING_INVALID")
        if not re.fullmatch(
            rf"arn:{partition}:sso:::instance/ssoins-[A-Za-z0-9]{{16}}",
            self.identity_center_instance_arn,
        ):
            raise BrokerError("IDENTITY_CENTER_INSTANCE_INVALID")
        if not re.fullmatch(
            rf"arn:{partition}:sso::[0-9]{{12}}:application/"
            r"ssoins-[A-Za-z0-9]{16}/apl-[A-Za-z0-9]{16}",
            self.identity_center_application_arn,
        ):
            raise BrokerError("IDENTITY_CENTER_APPLICATION_INVALID")
        if re.fullmatch(
            r"http://127\.0\.0\.1:[0-9]{4,5}/callback",
            self.identity_center_redirect_uri,
        ) is None:
            raise BrokerError("IDENTITY_CENTER_REDIRECT_INVALID")
        for name in (
            self.classifier_invoker_role_name,
            self.approver_invoker_role_name,
            self.classifier_proof_role_name,
            self.approver_proof_role_name,
            self.broker_execution_role_name,
        ):
            if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", name):
                raise BrokerError("ROLE_BINDING_INVALID")
        if (
            self.classifier_invoker_role_name != "ScanalyzeGug215ClassifierInvoker"
            or self.approver_invoker_role_name != "ScanalyzeGug215ApproverInvoker"
            or self.classifier_proof_role_name != "ScanalyzeGug217ClassifierProof"
            or self.approver_proof_role_name != "ScanalyzeGug217ApproverProof"
            or self.broker_execution_role_name != "ScanalyzeGug215BrokerExecution"
        ):
            raise BrokerError("ROLE_BINDING_INVALID")
        permission_set_role_patterns = (
            (
                self.classifier_permission_set_role_arn,
                "ScanalyzeAuthorityRetireClass",
            ),
            (
                self.approver_permission_set_role_arn,
                "ScanalyzeAuthorityRetireApprove",
            ),
        )
        for role_arn, permission_set_name in permission_set_role_patterns:
            if re.fullmatch(
                rf"arn:{partition}:iam::{self.authority_account_id}:role/"
                r"aws-reserved/sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
                rf"AWSReservedSSO_{permission_set_name}_[0-9A-Fa-f]{{16}}",
                role_arn,
            ) is None:
                raise BrokerError("PERMISSION_SET_ROLE_BINDING_INVALID")
        if not self.code_signing_config_arn.startswith(
            f"arn:{partition}:lambda:{self.region}:{self.authority_account_id}:code-signing-config:"
        ):
            raise BrokerError("CODE_SIGNING_BINDING_INVALID")
        if re.fullmatch(
            rf"arn:{partition}:lambda:{self.region}::runtime:[a-f0-9]{{64}}",
            self.broker_runtime_version_arn,
        ) is None:
            raise BrokerError("RUNTIME_VERSION_BINDING_INVALID")
        values = {
            field: getattr(self, field) for field in BROKER_VERSION_BINDING_FIELDS
        }
        if self.broker_version_binding_sha256 != broker_version_binding_digest(values):
            raise BrokerError("BROKER_VERSION_BINDING_MISMATCH")
        if self.authorization_mode == AUTHORIZATION_MODE_SINGLE_OPERATOR:
            # Reconstructing the complete digest-only authorization here makes
            # every versioned environment binding fail closed before AWS.
            self.single_operator_exception

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "BrokerConfig":
        source = os.environ if env is None else env

        def required(name: str) -> str:
            value = source.get(name)
            if not isinstance(value, str) or not value:
                raise BrokerError("CONFIGURATION_INCOMPLETE")
            return value

        return cls(
            authority_account_id=required("AUTHORITY_ACCOUNT_ID"),
            region=required("AUTHORITY_REGION"),
            change_set_name=required("CHANGE_SET_NAME"),
            expected_template_sha256=required("EXPECTED_TEMPLATE_SHA256"),
            expected_evidence_sha256=required("EXPECTED_EVIDENCE_SHA256"),
            expected_code_sha256=required("EXPECTED_CODE_SHA256"),
            expected_broker_policy_sha256=required("EXPECTED_BROKER_POLICY_SHA256"),
            identity_store_arn=required("IDENTITY_STORE_ARN"),
            identity_center_instance_arn=required("IDENTITY_CENTER_INSTANCE_ARN"),
            identity_center_application_arn=required("IDENTITY_CENTER_APPLICATION_ARN"),
            identity_center_redirect_uri=required("IDENTITY_CENTER_REDIRECT_URI"),
            classifier_identity_store_user_id=required("CLASSIFIER_IDENTITY_STORE_USER_ID"),
            approver_identity_store_user_id=required("APPROVER_IDENTITY_STORE_USER_ID"),
            classifier_assignment_sha256=required("CLASSIFIER_ASSIGNMENT_SHA256"),
            approver_assignment_sha256=required("APPROVER_ASSIGNMENT_SHA256"),
            classifier_invoker_policy_sha256=required("CLASSIFIER_INVOKER_POLICY_SHA256"),
            approver_invoker_policy_sha256=required("APPROVER_INVOKER_POLICY_SHA256"),
            classifier_proof_policy_sha256=required("CLASSIFIER_PROOF_POLICY_SHA256"),
            approver_proof_policy_sha256=required("APPROVER_PROOF_POLICY_SHA256"),
            identity_center_application_actor_policy_sha256=required(
                "IDENTITY_CENTER_APPLICATION_ACTOR_POLICY_SHA256"
            ),
            classifier_invoker_role_name=required("CLASSIFIER_INVOKER_ROLE_NAME"),
            approver_invoker_role_name=required("APPROVER_INVOKER_ROLE_NAME"),
            classifier_proof_role_name=required("CLASSIFIER_PROOF_ROLE_NAME"),
            approver_proof_role_name=required("APPROVER_PROOF_ROLE_NAME"),
            classifier_permission_set_role_arn=required(
                "CLASSIFIER_PERMISSION_SET_ROLE_ARN"
            ),
            approver_permission_set_role_arn=required(
                "APPROVER_PERMISSION_SET_ROLE_ARN"
            ),
            broker_execution_role_name=required("BROKER_EXECUTION_ROLE_NAME"),
            code_signing_config_arn=required("CODE_SIGNING_CONFIG_ARN"),
            broker_runtime_version_arn=required("BROKER_RUNTIME_VERSION_ARN"),
            broker_version_binding_sha256=required(
                "BROKER_VERSION_BINDING_SHA256"
            ),
            retirement_id=required("RETIREMENT_ID"),
            authorization_mode=source.get(
                "AUTHORIZATION_MODE", AUTHORIZATION_MODE_TWO_HUMAN
            ),
            single_operator_owner_authorization_sha256=source.get(
                "SINGLE_OPERATOR_OWNER_AUTHORIZATION_SHA256", ""
            ),
            single_operator_expected_authorization_sha256=source.get(
                "SINGLE_OPERATOR_EXPECTED_AUTHORIZATION_SHA256", ""
            ),
            single_operator_exception_created_at=source.get(
                "SINGLE_OPERATOR_EXCEPTION_CREATED_AT", ""
            ),
            single_operator_exception_not_before=source.get(
                "SINGLE_OPERATOR_EXCEPTION_NOT_BEFORE", ""
            ),
            single_operator_exception_expires_at=source.get(
                "SINGLE_OPERATOR_EXCEPTION_EXPIRES_AT", ""
            ),
        )

    @property
    def is_single_operator(self) -> bool:
        return self.authorization_mode == AUTHORIZATION_MODE_SINGLE_OPERATOR

    @property
    def allowed_aliases(self) -> frozenset[str]:
        return SINGLE_OPERATOR_ALIASES if self.is_single_operator else NORMAL_ALIASES

    def normalized_runtime_environment(self) -> dict[str, str]:
        """Return every environment value expected on the immutable version."""

        values = {
            "AUTHORIZATION_MODE": self.authorization_mode,
            "AUTHORITY_ACCOUNT_ID": self.authority_account_id,
            "AUTHORITY_REGION": self.region,
            "CHANGE_SET_NAME": self.change_set_name,
            "RETIREMENT_ID": self.retirement_id,
            "EXPECTED_TEMPLATE_SHA256": self.expected_template_sha256,
            "EXPECTED_EVIDENCE_SHA256": self.expected_evidence_sha256,
            "EXPECTED_CODE_SHA256": self.expected_code_sha256,
            "EXPECTED_BROKER_POLICY_SHA256": self.expected_broker_policy_sha256,
            "IDENTITY_STORE_ARN": self.identity_store_arn,
            "IDENTITY_CENTER_INSTANCE_ARN": self.identity_center_instance_arn,
            "IDENTITY_CENTER_APPLICATION_ARN": self.identity_center_application_arn,
            "IDENTITY_CENTER_REDIRECT_URI": self.identity_center_redirect_uri,
            "CLASSIFIER_IDENTITY_STORE_USER_ID": self.classifier_identity_store_user_id,
            "APPROVER_IDENTITY_STORE_USER_ID": self.approver_identity_store_user_id,
            "CLASSIFIER_ASSIGNMENT_SHA256": self.classifier_assignment_sha256,
            "APPROVER_ASSIGNMENT_SHA256": self.approver_assignment_sha256,
            "CLASSIFIER_INVOKER_POLICY_SHA256": self.classifier_invoker_policy_sha256,
            "APPROVER_INVOKER_POLICY_SHA256": self.approver_invoker_policy_sha256,
            "CLASSIFIER_PROOF_POLICY_SHA256": self.classifier_proof_policy_sha256,
            "APPROVER_PROOF_POLICY_SHA256": self.approver_proof_policy_sha256,
            "IDENTITY_CENTER_APPLICATION_ACTOR_POLICY_SHA256": self.identity_center_application_actor_policy_sha256,
            "CLASSIFIER_INVOKER_ROLE_NAME": self.classifier_invoker_role_name,
            "APPROVER_INVOKER_ROLE_NAME": self.approver_invoker_role_name,
            "CLASSIFIER_PROOF_ROLE_NAME": self.classifier_proof_role_name,
            "APPROVER_PROOF_ROLE_NAME": self.approver_proof_role_name,
            "CLASSIFIER_PERMISSION_SET_ROLE_ARN": self.classifier_permission_set_role_arn,
            "APPROVER_PERMISSION_SET_ROLE_ARN": self.approver_permission_set_role_arn,
            "BROKER_EXECUTION_ROLE_NAME": self.broker_execution_role_name,
            "CODE_SIGNING_CONFIG_ARN": self.code_signing_config_arn,
            "BROKER_RUNTIME_VERSION_ARN": self.broker_runtime_version_arn,
            "BROKER_VERSION_BINDING_SHA256": self.broker_version_binding_sha256,
        }
        if self.is_single_operator:
            values.update(
                {
                    "SINGLE_OPERATOR_OWNER_AUTHORIZATION_SHA256": self.single_operator_owner_authorization_sha256,
                    "SINGLE_OPERATOR_EXPECTED_AUTHORIZATION_SHA256": self.single_operator_expected_authorization_sha256,
                    "SINGLE_OPERATOR_EXCEPTION_CREATED_AT": self.single_operator_exception_created_at,
                    "SINGLE_OPERATOR_EXCEPTION_NOT_BEFORE": self.single_operator_exception_not_before,
                    "SINGLE_OPERATOR_EXCEPTION_EXPIRES_AT": self.single_operator_exception_expires_at,
                }
            )
        return values

    @property
    def partition(self) -> str:
        return _partition(self.region)

    @property
    def stack_arn(self) -> str:
        return (
            f"arn:{self.partition}:cloudformation:{self.region}:"
            f"{self.authority_account_id}:stack/{self.stack_name}/*"
        )

    @property
    def table_arn(self) -> str:
        return (
            f"arn:{self.partition}:dynamodb:{self.region}:"
            f"{self.authority_account_id}:table/{self.ledger_table_name}"
        )

    @property
    def function_arn(self) -> str:
        return (
            f"arn:{self.partition}:lambda:{self.region}:"
            f"{self.authority_account_id}:function:{self.function_name}"
        )

    @property
    def execution_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.broker_execution_role_name}"
        )

    @property
    def classifier_invoker_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.classifier_invoker_role_name}"
        )

    @property
    def approver_invoker_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.approver_invoker_role_name}"
        )

    @property
    def classifier_proof_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.classifier_proof_role_name}"
        )

    @property
    def approver_proof_role_arn(self) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:"
            f"role/{self.approver_proof_role_name}"
        )

    def _permissions_boundary_arn(self, policy_name: str) -> str:
        return (
            f"arn:{self.partition}:iam::{self.authority_account_id}:policy"
            f"{PERMISSIONS_BOUNDARY_POLICY_PATH}{policy_name}"
        )

    @property
    def broker_permissions_boundary_arn(self) -> str:
        return self._permissions_boundary_arn(BROKER_BOUNDARY_POLICY_NAME)

    @property
    def classifier_invoker_permissions_boundary_arn(self) -> str:
        return self._permissions_boundary_arn(
            CLASSIFIER_INVOKER_BOUNDARY_POLICY_NAME
        )

    @property
    def approver_invoker_permissions_boundary_arn(self) -> str:
        return self._permissions_boundary_arn(
            APPROVER_INVOKER_BOUNDARY_POLICY_NAME
        )

    @property
    def proof_permissions_boundary_arn(self) -> str:
        return self._permissions_boundary_arn(PROOF_BOUNDARY_POLICY_NAME)

    @property
    def identity_binding(self) -> dict[str, Any]:
        binding = {
            "identity_store_arn_digest": secret_digest(
                "identity_store_arn", self.identity_store_arn
            ),
            "identity_center_instance_arn_digest": secret_digest(
                "identity_center_instance_arn", self.identity_center_instance_arn
            ),
            "identity_center_application_arn_digest": secret_digest(
                "identity_center_application_arn", self.identity_center_application_arn
            ),
            "classifier_identity_store_user_id_digest": secret_digest(
                "identity_store_user_id", self.classifier_identity_store_user_id.lower()
            ),
            "approver_identity_store_user_id_digest": secret_digest(
                "identity_store_user_id", self.approver_identity_store_user_id.lower()
            ),
            "classifier_assignment_sha256": self.classifier_assignment_sha256,
            "approver_assignment_sha256": self.approver_assignment_sha256,
            "classifier_invoker_policy_sha256": self.classifier_invoker_policy_sha256,
            "approver_invoker_policy_sha256": self.approver_invoker_policy_sha256,
            "classifier_proof_policy_sha256": self.classifier_proof_policy_sha256,
            "approver_proof_policy_sha256": self.approver_proof_policy_sha256,
            "identity_center_application_actor_policy_sha256": (
                self.identity_center_application_actor_policy_sha256
            ),
        }
        if self.is_single_operator:
            binding.update(
                {
                    "authorization_mode": AUTHORIZATION_MODE_SINGLE_OPERATOR,
                    "two_human_status": "NOT_PROVEN",
                    "independent_approval_present": False,
                }
            )
        return binding

    @property
    def identity_binding_digest(self) -> str:
        return canonical_digest(self.identity_binding)

    @staticmethod
    def _exception_datetime(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise BrokerError("EXCEPTION_TIME_INVALID") from None
        if parsed.tzinfo is None or parsed.microsecond != 0:
            raise BrokerError("EXCEPTION_TIME_INVALID")
        return parsed.astimezone(UTC)

    @property
    def single_operator_exception(self) -> dict[str, object] | None:
        if not self.is_single_operator:
            return None
        try:
            exception = build_single_operator_retirement_exception(
                authority_account_id=self.authority_account_id,
                region=self.region,
                retirement_id=self.retirement_id,
                change_set_name_digest=secret_digest(
                    "change_set_name", self.change_set_name
                ),
                template_sha256=self.expected_template_sha256,
                resource_inventory_sha256=self.expected_evidence_sha256,
                identity_binding_digest=self.identity_binding_digest,
                broker_runtime_version_arn=self.broker_runtime_version_arn,
                broker_version_binding_sha256=self.broker_version_binding_sha256,
                operator_identity_store_user_id=(
                    self.classifier_identity_store_user_id
                ),
                owner_authorization_sha256=(
                    self.single_operator_owner_authorization_sha256
                ),
                created_at=self._exception_datetime(
                    self.single_operator_exception_created_at
                ),
                not_before=self._exception_datetime(
                    self.single_operator_exception_not_before
                ),
                expires_at=self._exception_datetime(
                    self.single_operator_exception_expires_at
                ),
            )
            if (
                exception["authorization_digest"]
                != self.single_operator_expected_authorization_sha256
            ):
                raise BrokerError("REVIEWED_AUTHORIZATION_DIGEST_MISMATCH")
            return exception
        except SingleOperatorExceptionError as exc:
            raise BrokerError(exc.code) from None

    @property
    def single_operator_authorization_sha256(self) -> str | None:
        exception = self.single_operator_exception
        return (
            str(exception["authorization_digest"])
            if exception is not None
            else None
        )


class AwsClients(Protocol):
    cloudformation: Any
    dynamodb: Any
    iam: Any
    kms: Any
    lambda_client: Any
    s3control: Any
    sso_oidc: Any
    sts: Any


@dataclass(slots=True)
class BotoClients:
    cloudformation: Any
    dynamodb: Any
    iam: Any
    kms: Any
    lambda_client: Any
    s3control: Any
    sso_oidc: Any
    sts: Any

    @classmethod
    def create(cls, region: str) -> "BotoClients":
        try:
            import boto3  # type: ignore[import-not-found]
            from botocore.config import Config  # type: ignore[import-not-found]
        except ImportError as exc:
            raise BrokerError("RUNTIME_DEPENDENCY_MISSING") from exc
        no_retry = Config(region_name=region, retries={"max_attempts": 0, "mode": "standard"})
        return cls(
            cloudformation=boto3.client("cloudformation", config=no_retry),
            dynamodb=boto3.client("dynamodb", config=no_retry),
            iam=boto3.client("iam", config=no_retry),
            kms=boto3.client("kms", config=no_retry),
            lambda_client=boto3.client("lambda", config=no_retry),
            s3control=boto3.client("s3control", config=no_retry),
            sso_oidc=boto3.client("sso-oidc", config=no_retry),
            sts=boto3.client("sts", config=no_retry),
        )


def _strict_json_object(value: str, code: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise BrokerError(code) from exc
    if not isinstance(parsed, dict):
        raise BrokerError(code)
    return parsed


def _actions(statement: Mapping[str, Any]) -> set[str]:
    value = statement.get("Action")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise BrokerError("POLICY_READBACK_INVALID")


def _policy_document_digest(value: object) -> str:
    if isinstance(value, str):
        document = _strict_json_object(value, "POLICY_READBACK_INVALID")
    elif isinstance(value, Mapping):
        document = dict(value)
    else:
        raise BrokerError("POLICY_READBACK_INVALID")
    return canonical_digest(document)


class RetirementBroker:
    """Purely bounded side-effect coordinator around injected AWS clients."""

    def __init__(
        self,
        *,
        config: BrokerConfig,
        clients: AwsClients,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self.clients = clients
        self.now: Callable[[], datetime] = now or (lambda: datetime.now(tz=UTC))

    def handle(
        self,
        *,
        alias: str,
        event: object,
        identity_proof_sha256: str,
    ) -> dict[str, Any]:
        if alias not in self.config.allowed_aliases:
            raise BrokerError("ALIAS_NOT_AUTHORIZED")
        if event != {}:
            raise BrokerError("REQUEST_AUTHORITY_FORBIDDEN")
        _require_digest(identity_proof_sha256, "IDENTITY_PROOF_DIGEST_INVALID")
        self.preflight(alias=alias)
        if alias in {ALIAS_CLASSIFY, ALIAS_SINGLE_CLASSIFY}:
            return self._classify(identity_proof_sha256)
        if alias in {ALIAS_RETIRE, ALIAS_SINGLE_RETIRE}:
            return self._retire(identity_proof_sha256)
        return self._reconcile(identity_proof_sha256)

    def preflight(self, *, alias: str) -> None:
        """Read back every mutable PEP boundary without issuing a proof."""

        if alias not in self.config.allowed_aliases:
            raise BrokerError("ALIAS_NOT_AUTHORIZED")
        if self.config.is_single_operator and alias != ALIAS_SINGLE_RECONCILE:
            exception = self.config.single_operator_exception
            if exception is None:
                raise BrokerError("CONFIGURATION_INCOMPLETE")
            try:
                require_exception_effect_window(exception, now=self.now())
            except SingleOperatorExceptionError as exc:
                raise BrokerError(exc.code) from None
        self._verify_runtime_boundary(alias)
        self._verify_table_controls()

    def _verify_invoker_role(
        self,
        *,
        role_name: str,
        role_arn: str,
        permission_set_role_arn: str,
        expected_policy_sha256: str,
        expected_permissions_boundary_arn: str,
    ) -> None:
        role = self.clients.iam.get_role(RoleName=role_name).get("Role")
        if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
            raise BrokerError("INVOKER_ROLE_READBACK_INVALID")
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeFromExactPermissionSet",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": (
                            f"arn:{self.config.partition}:iam::"
                            f"{self.config.authority_account_id}:root"
                        )
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "ArnEquals": {"aws:PrincipalArn": permission_set_role_arn}
                    },
                },
            ],
        }
        if (
            role.get("AssumeRolePolicyDocument") != expected_trust
            or role.get("PermissionsBoundary")
            != {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": expected_permissions_boundary_arn,
            }
        ):
            raise BrokerError("INVOKER_ROLE_BOUNDARY_CHANGED")
        inline, attached = self._role_policy_inventory(
            role_name=role_name,
            failure_code="INVOKER_ROLE_POLICY_INVENTORY_CHANGED",
        )
        if inline != [] or attached != [
            {
                "PolicyName": expected_permissions_boundary_arn.rsplit("/", 1)[-1],
                "PolicyArn": expected_permissions_boundary_arn,
            }
        ]:
            raise BrokerError("INVOKER_ROLE_POLICY_INVENTORY_CHANGED")
        self._verify_managed_policy_document(
            policy_arn=expected_permissions_boundary_arn,
            expected_policy_sha256=expected_policy_sha256,
            expected_identity_role_names=[role_name],
            expected_boundary_role_names=[role_name],
            failure_code="INVOKER_ROLE_POLICY_CHANGED",
        )

    def _role_policy_inventory(
        self, *, role_name: str, failure_code: str
    ) -> tuple[object, object]:
        inline_response = self.clients.iam.list_role_policies(
            RoleName=role_name
        )
        attached_response = self.clients.iam.list_attached_role_policies(
            RoleName=role_name
        )
        if (
            not isinstance(inline_response, Mapping)
            or inline_response.get("IsTruncated") is not False
            or "Marker" in inline_response
            or not isinstance(attached_response, Mapping)
            or attached_response.get("IsTruncated") is not False
            or "Marker" in attached_response
        ):
            raise BrokerError(failure_code)
        return (
            inline_response.get("PolicyNames"),
            attached_response.get("AttachedPolicies"),
        )

    def _verify_managed_policy_document(
        self,
        *,
        policy_arn: str,
        expected_policy_sha256: str,
        expected_identity_role_names: list[str],
        expected_boundary_role_names: list[str],
        failure_code: str,
        expected_role_ids: Mapping[str, str] | None = None,
    ) -> None:
        policy = self.clients.iam.get_policy(PolicyArn=policy_arn).get("Policy")
        if not isinstance(policy, Mapping):
            raise BrokerError(failure_code)
        version_id = policy.get("DefaultVersionId")
        if (
            policy.get("Arn") != policy_arn
            or version_id != "v1"
            or policy.get("AttachmentCount")
            != len(expected_identity_role_names)
            or policy.get("PermissionsBoundaryUsageCount")
            != len(expected_boundary_role_names)
            or policy.get("IsAttachable") is not True
        ):
            raise BrokerError(failure_code)
        versions = self.clients.iam.list_policy_versions(PolicyArn=policy_arn)
        version_rows = versions.get("Versions") if isinstance(versions, Mapping) else None
        if (
            not isinstance(versions, Mapping)
            or versions.get("IsTruncated") is not False
            or "Marker" in versions
            or not isinstance(version_rows, list)
            or len(version_rows) != 1
            or not isinstance(version_rows[0], Mapping)
            or set(version_rows[0]) - {"VersionId", "IsDefaultVersion", "CreateDate"}
            or version_rows[0].get("VersionId") != "v1"
            or version_rows[0].get("IsDefaultVersion") is not True
        ):
            raise BrokerError(failure_code)
        # ListPolicyVersions includes optional provider timestamps; they do not
        # change the required singleton v1 or its separately verified document.
        if "CreateDate" in version_rows[0]:
            created = version_rows[0]["CreateDate"]
            if isinstance(created, str):
                try:
                    created = _parse_timestamp(created)
                except BrokerError:
                    raise BrokerError(failure_code) from None
            if not isinstance(created, datetime) or created.tzinfo is None:
                raise BrokerError(failure_code)
        for usage, expected_role_names in (
            ("PermissionsPolicy", expected_identity_role_names),
            ("PermissionsBoundary", expected_boundary_role_names),
        ):
            entities = self.clients.iam.list_entities_for_policy(
                PolicyArn=policy_arn,
                EntityFilter="Role",
                PolicyUsageFilter=usage,
            )
            roles = entities.get("PolicyRoles") if isinstance(entities, Mapping) else None
            if (
                not isinstance(entities, Mapping)
                or entities.get("IsTruncated") is not False
                or "Marker" in entities
                or entities.get("PolicyGroups") != []
                or entities.get("PolicyUsers") != []
                or not isinstance(roles, list)
                or any(
                    not isinstance(item, Mapping)
                    or set(item) - {"RoleName", "RoleId"}
                    or not isinstance(item.get("RoleName"), str)
                    or (
                        "RoleId" in item
                        and (
                            not isinstance(item["RoleId"], str)
                            or re.fullmatch(r"[A-Za-z0-9_]{16,128}", item["RoleId"]) is None
                            or (expected_role_ids is not None
                                and item["RoleId"] != expected_role_ids.get(item["RoleName"]))
                        )
                    )
                    for item in roles
                )
                or sorted(item["RoleName"] for item in roles) != sorted(expected_role_names)
            ):
                raise BrokerError(failure_code)
        version = self.clients.iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id,
        ).get("PolicyVersion")
        if (
            not isinstance(version, Mapping)
            or version.get("VersionId") != version_id
            or version.get("IsDefaultVersion") is not True
            or _policy_document_digest(version.get("Document"))
            != expected_policy_sha256
        ):
            raise BrokerError(failure_code)

    def _verify_proof_role(
        self,
        *,
        role_name: str,
        role_arn: str,
        identity_store_user_id: str,
        expected_policy_sha256: str,
        trust_sid: str,
        expected_permissions_boundary_arn: str,
    ) -> None:
        role = self.clients.iam.get_role(RoleName=role_name).get("Role")
        if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
            raise BrokerError("PROOF_ROLE_READBACK_INVALID")
        principal = (
            f"arn:{self.config.partition}:iam::"
            f"{self.config.authority_account_id}:root"
        )
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AssumeFromExactBroker",
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "ArnEquals": {
                            "aws:PrincipalArn": self.config.execution_role_arn
                        }
                    },
                },
                {
                    "Sid": trust_sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "sts:SetContext",
                    "Condition": {
                        "ForAllValues:ArnEquals": {
                            "sts:RequestContextProviders": [
                                "arn:aws:iam::aws:contextProvider/IdentityCenter"
                            ]
                        },
                        "StringEquals": {
                            "sts:RequestContext/identitystore:UserId": identity_store_user_id
                        },
                        "ArnEquals": {
                            "aws:PrincipalArn": self.config.execution_role_arn,
                            "sts:RequestContext/identitystore:IdentityStoreArn": self.config.identity_store_arn,
                            "sts:RequestContext/identitycenter:InstanceArn": self.config.identity_center_instance_arn,
                            "sts:RequestContext/identitycenter:ApplicationArn": self.config.identity_center_application_arn,
                        },
                        "Null": {
                            "sts:RequestContextProviders": "false",
                            "sts:RequestContext/identitystore:UserId": "false",
                            "sts:RequestContext/identitystore:IdentityStoreArn": "false",
                            "sts:RequestContext/identitycenter:InstanceArn": "false",
                            "sts:RequestContext/identitycenter:ApplicationArn": "false",
                        },
                    },
                },
            ],
        }
        if (
            role.get("AssumeRolePolicyDocument") != expected_trust
            or role.get("PermissionsBoundary")
            != {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": expected_permissions_boundary_arn,
            }
            or role.get("MaxSessionDuration") != 3600
        ):
            raise BrokerError("PROOF_ROLE_BOUNDARY_CHANGED")
        inline, attached = self._role_policy_inventory(
            role_name=role_name,
            failure_code="PROOF_ROLE_POLICY_INVENTORY_CHANGED",
        )
        if inline != [] or attached != [
            {
                "PolicyName": expected_permissions_boundary_arn.rsplit("/", 1)[-1],
                "PolicyArn": expected_permissions_boundary_arn,
            }
        ]:
            raise BrokerError("PROOF_ROLE_POLICY_INVENTORY_CHANGED")
        self._verify_managed_policy_document(
            policy_arn=expected_permissions_boundary_arn,
            expected_policy_sha256=expected_policy_sha256,
            expected_identity_role_names=[
                self.config.classifier_proof_role_name,
                self.config.approver_proof_role_name,
            ],
            expected_boundary_role_names=[
                self.config.classifier_proof_role_name,
                self.config.approver_proof_role_name,
                LEDGER_FACTORY_ROLE_NAME,
            ],
            failure_code="PROOF_ROLE_POLICY_CHANGED",
        )

    def _verify_function_url(self, *, alias: str, invoker_role_arn: str) -> None:
        config = self.clients.lambda_client.get_function_url_config(
            FunctionName=self.config.function_name,
            Qualifier=alias,
        )
        function_arn = f"{self.config.function_arn}:{alias}"
        url = config.get("FunctionUrl")
        if (
            config.get("AuthType") != "AWS_IAM"
            or config.get("InvokeMode") != "BUFFERED"
            or config.get("FunctionArn") != function_arn
            or config.get("Cors") not in (None, {})
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not url.endswith(f".lambda-url.{self.config.region}.on.aws/")
        ):
            raise BrokerError("FUNCTION_URL_BOUNDARY_CHANGED")
        response = self.clients.lambda_client.get_policy(
            FunctionName=self.config.function_name,
            Qualifier=alias,
        )
        document = _strict_json_object(
            response.get("Policy"), "FUNCTION_URL_POLICY_INVALID"
        )
        statements = document.get("Statement")
        if document.get("Version") != "2012-10-17" or not isinstance(
            statements, list
        ):
            raise BrokerError("FUNCTION_URL_POLICY_INVALID")
        normalized = {
            (
                statement.get("Effect"),
                json.dumps(statement.get("Principal"), sort_keys=True),
                statement.get("Action"),
                statement.get("Resource"),
                json.dumps(statement.get("Condition"), sort_keys=True),
            )
            for statement in statements
            if isinstance(statement, Mapping)
        }
        expected = {
            (
                "Allow",
                json.dumps({"AWS": invoker_role_arn}, sort_keys=True),
                "lambda:InvokeFunctionUrl",
                function_arn,
                json.dumps(
                    {
                        "StringEquals": {
                            "lambda:FunctionUrlAuthType": "AWS_IAM"
                        }
                    },
                    sort_keys=True,
                ),
            ),
            (
                "Allow",
                json.dumps({"AWS": invoker_role_arn}, sort_keys=True),
                "lambda:InvokeFunction",
                function_arn,
                json.dumps(
                    {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}},
                    sort_keys=True,
                ),
            ),
        }
        if normalized != expected:
            raise BrokerError("FUNCTION_URL_POLICY_CHANGED")

    def _verify_runtime_boundary(self, alias: str) -> None:
        role = self.clients.iam.get_role(
            RoleName=self.config.broker_execution_role_name
        )
        value = role.get("Role")
        if not isinstance(value, Mapping):
            raise BrokerError("BROKER_ROLE_READBACK_INVALID")
        trust = value.get("AssumeRolePolicyDocument")
        expected_trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        if (
            trust != expected_trust
            or value.get("PermissionsBoundary")
            != {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": (
                    self.config.broker_permissions_boundary_arn
                ),
            }
        ):
            raise BrokerError("BROKER_ROLE_BOUNDARY_CHANGED")
        inline, attached = self._role_policy_inventory(
            role_name=self.config.broker_execution_role_name,
            failure_code="BROKER_ROLE_POLICY_INVENTORY_CHANGED",
        )
        boundary_arn = self.config.broker_permissions_boundary_arn
        if inline != [] or attached != [
            {
                "PolicyName": boundary_arn.rsplit("/", 1)[-1],
                "PolicyArn": boundary_arn,
            }
        ]:
            raise BrokerError("BROKER_ROLE_POLICY_INVENTORY_CHANGED")
        self._verify_managed_policy_document(
            policy_arn=boundary_arn,
            expected_policy_sha256=self.config.expected_broker_policy_sha256,
            expected_identity_role_names=[
                self.config.broker_execution_role_name
            ],
            expected_boundary_role_names=[
                self.config.broker_execution_role_name
            ],
            failure_code="BROKER_ROLE_POLICY_CHANGED",
        )
        self._verify_invoker_role(
            role_name=self.config.classifier_invoker_role_name,
            role_arn=self.config.classifier_invoker_role_arn,
            permission_set_role_arn=self.config.classifier_permission_set_role_arn,
            expected_policy_sha256=self.config.classifier_invoker_policy_sha256,
            expected_permissions_boundary_arn=(
                self.config.classifier_invoker_permissions_boundary_arn
            ),
        )
        self._verify_invoker_role(
            role_name=self.config.approver_invoker_role_name,
            role_arn=self.config.approver_invoker_role_arn,
            permission_set_role_arn=self.config.approver_permission_set_role_arn,
            expected_policy_sha256=self.config.approver_invoker_policy_sha256,
            expected_permissions_boundary_arn=(
                self.config.approver_invoker_permissions_boundary_arn
            ),
        )
        self._verify_proof_role(
            role_name=self.config.classifier_proof_role_name,
            role_arn=self.config.classifier_proof_role_arn,
            identity_store_user_id=self.config.classifier_identity_store_user_id,
            expected_policy_sha256=self.config.classifier_proof_policy_sha256,
            trust_sid="SetExactClassifierIdentityContext",
            expected_permissions_boundary_arn=(
                self.config.proof_permissions_boundary_arn
            ),
        )
        self._verify_proof_role(
            role_name=self.config.approver_proof_role_name,
            role_arn=self.config.approver_proof_role_arn,
            identity_store_user_id=self.config.approver_identity_store_user_id,
            expected_policy_sha256=self.config.approver_proof_policy_sha256,
            trust_sid="SetExactApproverIdentityContext",
            expected_permissions_boundary_arn=(
                self.config.proof_permissions_boundary_arn
            ),
        )
        function = self.clients.lambda_client.get_function_configuration(
            FunctionName=f"{self.config.function_name}:{alias}"
        )
        if (
            function.get("Version") in (None, "$LATEST")
            or function.get("FunctionArn")
            != f"{self.config.function_arn}:{function.get('Version')}"
            or function.get("CodeSha256") != self.config.expected_code_sha256
            or function.get("Role") != self.config.execution_role_arn
            or function.get("RuntimeVersionConfig")
            != {"RuntimeVersionArn": self.config.broker_runtime_version_arn}
            or function.get("LoggingConfig")
            != {
                "LogFormat": "JSON",
                "ApplicationLogLevel": "ERROR",
                "SystemLogLevel": "WARN",
                "LogGroup": BROKER_LOG_GROUP_NAME,
            }
            or function.get("Architectures") != ["x86_64"]
            or function.get("DeadLetterConfig") not in (None, {})
            or function.get("EphemeralStorage") != {"Size": 512}
            or function.get("FileSystemConfigs") not in (None, [])
            or function.get("Handler")
            != "tooling.platform_authority_identity_context_pep_runtime.handler"
            or function.get("KMSKeyArn") not in (None, "")
            or function.get("Layers") not in (None, [])
            or function.get("MemorySize") != 256
            or function.get("PackageType") != "Zip"
            or function.get("Runtime") != "python3.12"
            or function.get("SnapStart")
            not in (
                None,
                {},
                {"ApplyOn": "None", "OptimizationStatus": "Off"},
            )
            or function.get("Timeout") != 60
            or function.get("TracingConfig") != {"Mode": "PassThrough"}
            or function.get("VpcConfig")
            != {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""}
            or function.get("Environment", {}).get("Variables")
            != self.config.normalized_runtime_environment()
        ):
            raise BrokerError("BROKER_CODE_BOUNDARY_CHANGED")
        runtime_management = (
            self.clients.lambda_client.get_runtime_management_config(
                FunctionName=self.config.function_name,
                Qualifier=str(function["Version"]),
            )
        )
        if (
            runtime_management.get("FunctionArn") != function.get("FunctionArn")
            or runtime_management.get("UpdateRuntimeOn") != "Manual"
            or runtime_management.get("RuntimeVersionArn")
            != self.config.broker_runtime_version_arn
        ):
            raise BrokerError("BROKER_RUNTIME_MANAGEMENT_CHANGED")
        concurrency = self.clients.lambda_client.get_function_concurrency(
            FunctionName=self.config.function_name
        )
        if concurrency.get("ReservedConcurrentExecutions") != 1:
            raise BrokerError("BROKER_CONCURRENCY_CHANGED")
        alias_record = self.clients.lambda_client.get_alias(
            FunctionName=self.config.function_name,
            Name=alias,
        )
        if (
            alias_record.get("FunctionVersion") != function.get("Version")
            or alias_record.get("RoutingConfig")
            not in (None, {}, {"AdditionalVersionWeights": {}})
        ):
            raise BrokerError("BROKER_ALIAS_CHANGED")
        signing = self.clients.lambda_client.get_function_code_signing_config(
            FunctionName=self.config.function_name
        )
        if signing.get("CodeSigningConfigArn") != self.config.code_signing_config_arn:
            raise BrokerError("BROKER_CODE_SIGNING_CHANGED")
        for qualifier in (None, str(function["Version"])):
            try:
                self.clients.lambda_client.get_policy(
                    FunctionName=self.config.function_name,
                    **({"Qualifier": qualifier} if qualifier is not None else {}),
                )
            except Exception as exc:  # No policy is ResourceNotFound for each scope.
                response = getattr(exc, "response", None)
                code = (
                    response.get("Error", {}).get("Code")
                    if isinstance(response, Mapping)
                    else None
                )
                if code != "ResourceNotFoundException":
                    raise BrokerError("BROKER_RESOURCE_POLICY_READ_FAILED") from exc
            else:
                raise BrokerError("BROKER_RESOURCE_POLICY_CHANGED")
        invoker_role_arn = (
            self.config.classifier_invoker_role_arn
            if alias in {ALIAS_CLASSIFY, ALIAS_SINGLE_CLASSIFY}
            else self.config.approver_invoker_role_arn
        )
        self._verify_function_url(alias=alias, invoker_role_arn=invoker_role_arn)

    def _verify_table_controls(self) -> None:
        response = self.clients.dynamodb.describe_table(
            TableName=self.config.ledger_table_name
        )
        table = response.get("Table")
        if not isinstance(table, Mapping):
            raise BrokerError("LEDGER_TABLE_INVALID")
        sse = table.get("SSEDescription")
        billing = table.get("BillingModeSummary")
        table_class = table.get("TableClassSummary")
        key_arn = sse.get("KMSMasterKeyArn") if isinstance(sse, Mapping) else None
        key_arn_pattern = re.compile(
            rf"^arn:{self.config.partition}:kms:{self.config.region}:"
            rf"{self.config.authority_account_id}:key/[0-9a-f-]{{36}}$",
            re.IGNORECASE,
        )
        if (
            table.get("TableStatus") != "ACTIVE"
            or table.get("TableName") != self.config.ledger_table_name
            or table.get("TableArn") != self.config.table_arn
            or table.get("KeySchema")
            != [{"AttributeName": "retirement_id", "KeyType": "HASH"}]
            or table.get("AttributeDefinitions")
            != [{"AttributeName": "retirement_id", "AttributeType": "S"}]
            or table.get("DeletionProtectionEnabled") is not True
            or not isinstance(sse, Mapping)
            or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or not isinstance(key_arn, str)
            or key_arn_pattern.fullmatch(key_arn) is None
            or not isinstance(billing, Mapping)
            or billing.get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("LatestStreamArn") not in (None, "")
            or table.get("LatestStreamLabel") not in (None, "")
            or table.get("LocalSecondaryIndexes") not in (None, [])
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("Replicas") not in (None, [])
            or table.get("GlobalTableWitnesses") not in (None, [])
            or not isinstance(table_class, Mapping)
            or table_class.get("TableClass") != "STANDARD"
        ):
            raise BrokerError("LEDGER_TABLE_CONTROLS_CHANGED")
        key_metadata = self.clients.kms.describe_key(KeyId=key_arn).get("KeyMetadata")
        if (
            not isinstance(key_metadata, Mapping)
            or key_metadata.get("Arn") != key_arn
            or key_metadata.get("AWSAccountId") != self.config.authority_account_id
            or key_metadata.get("Enabled") is not True
            or key_metadata.get("KeyManager") != "AWS"
            or key_metadata.get("KeyState") != "Enabled"
            or key_metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or key_metadata.get("Origin") != "AWS_KMS"
            or key_metadata.get("MultiRegion") is not False
        ):
            raise BrokerError("LEDGER_KMS_CONTROLS_CHANGED")
        ttl_response = self.clients.dynamodb.describe_time_to_live(
            TableName=self.config.ledger_table_name
        )
        ttl = (
            ttl_response.get("TimeToLiveDescription")
            if isinstance(ttl_response, Mapping)
            else None
        )
        if (
            not isinstance(ttl, Mapping)
            or ttl.get("TimeToLiveStatus") != "DISABLED"
            or ttl.get("AttributeName") not in (None, "")
        ):
            raise BrokerError("LEDGER_TTL_CONTROLS_CHANGED")
        backups = self.clients.dynamodb.describe_continuous_backups(
            TableName=self.config.ledger_table_name
        ).get("ContinuousBackupsDescription")
        pitr = (
            backups.get("PointInTimeRecoveryDescription")
            if isinstance(backups, Mapping)
            else None
        )
        if (
            not isinstance(backups, Mapping)
            or backups.get("ContinuousBackupsStatus") != "ENABLED"
            or not isinstance(pitr, Mapping)
            or pitr.get("PointInTimeRecoveryStatus") != "ENABLED"
            or pitr.get("RecoveryPeriodInDays") != 35
        ):
            raise BrokerError("LEDGER_RECOVERY_CONTROLS_CHANGED")
        tag_response = self.clients.dynamodb.list_tags_of_resource(
            ResourceArn=self.config.table_arn
        )
        tags = tag_response.get("Tags") if isinstance(tag_response, Mapping) else None
        if (
            not isinstance(tags, list)
            or tag_response.get("NextToken") not in (None, "")
            or any(
                not isinstance(item, Mapping)
                or not isinstance(item.get("Key"), str)
                or not isinstance(item.get("Value"), str)
                for item in tags
            )
        ):
            raise BrokerError("LEDGER_TAGS_CHANGED")
        normalized_tags = {
            item["Key"]: item["Value"]
            for item in tags
        }
        expected_tags = {
            **self._ledger_control_tags(),
            "account_id": self.config.authority_account_id,
            "region": self.config.region,
        }
        if len(normalized_tags) != len(tags) or normalized_tags != expected_tags:
            raise BrokerError("LEDGER_TAGS_CHANGED")
        policy = self.clients.dynamodb.get_resource_policy(
            ResourceArn=self.config.table_arn
        ).get("Policy")
        document = _strict_json_object(policy, "LEDGER_RESOURCE_POLICY_CHANGED")
        statements = document.get("Statement")
        if not isinstance(statements, list) or len(statements) != 1:
            raise BrokerError("LEDGER_RESOURCE_POLICY_CHANGED")
        statement = statements[0]
        if (
            not isinstance(statement, Mapping)
            or statement.get("Effect") != "Deny"
            or statement.get("Principal") != {"AWS": "*"}
            or _actions(statement) != set(self._ledger_write_actions())
            or statement.get("Resource") != self.config.table_arn
            or statement.get("Condition")
            != {
                "ArnNotEquals": {
                    "aws:PrincipalArn": self.config.execution_role_arn
                }
            }
        ):
            raise BrokerError("LEDGER_RESOURCE_POLICY_CHANGED")

    def _ledger_control_tags(self) -> dict[str, str]:
        return dict(EXPECTED_LEDGER_TAGS)

    def _ledger_write_actions(self) -> frozenset[str]:
        return WRITE_ACTIONS

    def _stack(self) -> Mapping[str, Any]:
        response = self.clients.cloudformation.describe_stacks(
            StackName=self.config.stack_name
        )
        stacks = response.get("Stacks")
        if not isinstance(stacks, list) or len(stacks) != 1:
            raise BrokerError("STACK_SHELL_AMBIGUOUS")
        stack = stacks[0]
        if not isinstance(stack, Mapping):
            raise BrokerError("STACK_SHELL_AMBIGUOUS")
        stack_id = stack.get("StackId")
        if (
            stack.get("StackName") != self.config.stack_name
            or stack.get("StackStatus") != "REVIEW_IN_PROGRESS"
            or not isinstance(stack_id, str)
            or not stack_id.startswith(self.config.stack_arn.removesuffix("*"))
            or stack.get("RoleARN") not in (None, "")
            or stack.get("NotificationARNs", []) != []
            or stack.get("ParentId") not in (None, "")
            or stack.get("RootId") not in (None, "")
        ):
            raise BrokerError("STACK_SHELL_CHANGED")
        resources = self.clients.cloudformation.list_stack_resources(
            StackName=stack_id
        ).get("StackResourceSummaries")
        if resources != []:
            raise BrokerError("STACK_RESOURCE_INVENTORY_CHANGED")
        return stack

    def _change_set_inventory(self, stack_id: str) -> list[Mapping[str, Any]]:
        items: list[Mapping[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(100):
            kwargs: dict[str, Any] = {"StackName": stack_id}
            if token is not None:
                kwargs["NextToken"] = token
            response = self.clients.cloudformation.list_change_sets(**kwargs)
            summaries = response.get("Summaries")
            if not isinstance(summaries, list) or any(
                not isinstance(item, Mapping) for item in summaries
            ):
                raise BrokerError("CHANGE_SET_INVENTORY_AMBIGUOUS")
            items.extend(summaries)
            next_token = response.get("NextToken")
            if next_token is None:
                return items
            if (
                not isinstance(next_token, str)
                or not next_token
                or next_token in seen
            ):
                raise BrokerError("CHANGE_SET_PAGINATION_INVALID")
            seen.add(next_token)
            token = next_token
        raise BrokerError("CHANGE_SET_PAGINATION_EXCEEDED")

    def _target_evidence(self) -> dict[str, Any]:
        stack = self._stack()
        stack_id = stack.get("StackId")
        if not isinstance(stack_id, str):
            raise BrokerError("STACK_SHELL_CHANGED")
        inventory = self._change_set_inventory(stack_id)
        if len(inventory) != 1:
            raise BrokerError("CHANGE_SET_INVENTORY_NOT_EXACT")
        summary = inventory[0]
        if (
            summary.get("ChangeSetName") != self.config.change_set_name
            or summary.get("Status") != "CREATE_COMPLETE"
            or summary.get("ExecutionStatus") != "AVAILABLE"
        ):
            raise BrokerError("CHANGE_SET_SUMMARY_CHANGED")
        summary_change_set_id = summary.get("ChangeSetId")
        if not isinstance(summary_change_set_id, str):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        response = self.clients.cloudformation.describe_change_set(
            ChangeSetName=summary_change_set_id,
            StackName=stack_id,
        )
        change_set_id = response.get("ChangeSetId")
        response_stack_id = response.get("StackId")
        if (
            response.get("ChangeSetName") != self.config.change_set_name
            or response.get("StackName") != self.config.stack_name
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("ChangeSetType") != "CREATE"
            or response.get("Capabilities", []) != []
            or response.get("RoleARN") not in (None, "")
            or response.get("NotificationARNs", []) != []
            or response.get("IncludeNestedStacks") not in (None, False)
            or response.get("ParentChangeSetId") not in (None, "")
            or response.get("RootChangeSetId") not in (None, "")
            or not isinstance(change_set_id, str)
            or not isinstance(response_stack_id, str)
            or response_stack_id != stack_id
            or summary_change_set_id != change_set_id
        ):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        suffix = change_set_id.rsplit("/", 1)[-1]
        if UUID.fullmatch(suffix) is None:
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        changes = response.get("Changes")
        if not isinstance(changes, list):
            raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
        normalized: list[tuple[str, str, str, str]] = []
        for change in changes:
            if not isinstance(change, Mapping) or change.get("Type") != "Resource":
                raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
            resource = change.get("ResourceChange")
            if not isinstance(resource, Mapping):
                raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
            normalized.append(_canonical_resource_change(resource))
        if tuple(sorted(normalized)) != EXPECTED_RESOURCE_CHANGES:
            raise BrokerError("CHANGE_SET_RESOURCES_CHANGED")
        tags = response.get("Tags")
        parameters = response.get("Parameters")
        if not isinstance(tags, list) or not isinstance(parameters, list):
            raise BrokerError("CHANGE_SET_METADATA_CHANGED")
        normalized_tags = {
            item.get("Key"): item.get("Value")
            for item in tags
            if isinstance(item, Mapping)
        }
        normalized_parameters = {
            item.get("ParameterKey"): item.get("ParameterValue")
            for item in parameters
            if isinstance(item, Mapping)
        }
        if normalized_tags != EXPECTED_TAGS or normalized_parameters != {
            "AuthorityAccountId": self.config.authority_account_id,
            "NoncurrentVersionRetentionDays": "365",
            "StateKey": CANONICAL_STATE_KEY,
        }:
            raise BrokerError("CHANGE_SET_METADATA_CHANGED")
        if isinstance(self.config, WorkforceRetirementConfig):
            _workforce_require(response.get("NextToken") is None
                               and len(tags) == len(normalized_tags)
                               and len(parameters) == len(normalized_parameters), "CHANGE_SET_METADATA_CHANGED")
        template = self.clients.cloudformation.get_template(
            ChangeSetName=change_set_id,
            StackName=stack_id,
            TemplateStage="Original",
        ).get("TemplateBody")
        if not isinstance(template, str):
            raise BrokerError("CHANGE_SET_TEMPLATE_AMBIGUOUS")
        template_digest = "sha256:" + hashlib.sha256(template.encode("utf-8")).hexdigest()
        evidence = {
            "_change_set_id": change_set_id,
            "_stack_id": response_stack_id,
            "stack_id_digest": secret_digest("stack_id", response_stack_id),
            "change_set_id_digest": secret_digest("change_set_id", change_set_id),
            "change_set_name_digest": secret_digest(
                "change_set_name", self.config.change_set_name
            ),
            "template_sha256": template_digest,
            "resource_inventory_sha256": canonical_digest(
                {
                    "resource_changes": [list(item) for item in EXPECTED_RESOURCE_CHANGES],
                    "tags": EXPECTED_TAGS,
                    "parameters": normalized_parameters,
                    "capabilities": [],
                }
            ),
            "retirement_id": "gug215#sha256:"
            + hashlib.sha256(change_set_id.encode("utf-8")).hexdigest(),
        }
        if (
            evidence["template_sha256"] != self.config.expected_template_sha256
            or evidence["resource_inventory_sha256"]
            != self.config.expected_evidence_sha256
        ):
            raise BrokerError("REVIEWED_BASELINE_CHANGED")
        return evidence

    @staticmethod
    def _require_evidence_matches_ledger(
        record: Mapping[str, Any], evidence: Mapping[str, Any]
    ) -> None:
        for field in (
            "retirement_id",
            "stack_id_digest",
            "change_set_id_digest",
            "change_set_name_digest",
            "template_sha256",
            "resource_inventory_sha256",
        ):
            if record.get(field) != evidence.get(field):
                raise BrokerError("LIVE_TARGET_CHANGED")

    @staticmethod
    def _require_reconciliation_stack(
        record: Mapping[str, Any], stack: Mapping[str, Any]
    ) -> str:
        stack_id = stack.get("StackId")
        if (
            not isinstance(stack_id, str)
            or secret_digest("stack_id", stack_id) != record.get("stack_id_digest")
        ):
            raise BrokerError("RECONCILIATION_SHELL_CHANGED")
        return stack_id

    def _account_pab(self) -> dict[str, bool] | None:
        try:
            response = self.clients.s3control.get_public_access_block(
                AccountId=self.config.authority_account_id
            )
        except Exception as exc:  # SDK-specific missing response remains non-authoritative.
            response = getattr(exc, "response", None)
            code = (
                response.get("Error", {}).get("Code")
                if isinstance(response, Mapping)
                else None
            )
            if code == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise BrokerError("PAB_READ_FAILED") from exc
        value = response.get("PublicAccessBlockConfiguration")
        if (
            not isinstance(value, Mapping)
            or set(value) != set(PUBLIC_ACCESS_BLOCK_KEYS)
            or any(not isinstance(value[key], bool) for key in PUBLIC_ACCESS_BLOCK_KEYS)
        ):
            raise BrokerError("PAB_READBACK_INVALID")
        return {key: bool(value[key]) for key in sorted(PUBLIC_ACCESS_BLOCK_KEYS)}

    def _base_ledger(
        self,
        evidence: Mapping[str, Any],
        identity_proof_sha256: str,
    ) -> dict[str, Any]:
        timestamp = _timestamp(self.now())
        exception = self.config.single_operator_exception
        record: dict[str, Any] = {
            "schema_version": "3" if exception is not None else "2",
            "record_type": "platform_authority_change_set_retirement_pep_ledger",
            "environment": "non-production",
            "production": False,
            "authority_account_id_digest": secret_digest(
                "authority_account_id", self.config.authority_account_id
            ),
            "region": self.config.region,
            "stack_name": self.config.stack_name,
            "retirement_id": evidence["retirement_id"],
            "stack_id_digest": evidence["stack_id_digest"],
            "change_set_id_digest": evidence["change_set_id_digest"],
            "change_set_name_digest": evidence["change_set_name_digest"],
            "template_sha256": evidence["template_sha256"],
            "resource_inventory_sha256": evidence["resource_inventory_sha256"],
            "identity_binding_digest": self.config.identity_binding_digest,
            **self.config.identity_binding,
            "broker_code_sha256": self.config.expected_code_sha256,
            "broker_policy_sha256": self.config.expected_broker_policy_sha256,
            "identity_separation": (
                "SINGLE_OPERATOR_DECLARED_NOT_INDEPENDENT"
                if exception is not None
                else "VERIFIED_DISTINCT_IDENTITYSTORE_USERS"
            ),
            "human_authentication_evidence": "STS_EVALUATED_IDENTITY_CONTEXT",
            "aws_effect_principal": "BROKER_EXECUTION_ROLE",
            "native_on_behalf_of": False,
            "classifier_identity_proof_sha256": identity_proof_sha256,
            "approver_identity_proof_sha256": None,
            "reconciliation_identity_proof_sha256": None,
            "state": "CLASSIFIED",
            "version": 1,
            "attempt_count": 0,
            "approval_digest": None,
            "attempt_digest": None,
            "verification_digest": None,
            "classified_at": timestamp,
            "approved_at": None,
            "attempted_at": None,
            "verified_at": None,
            "effect_attribution": None,
            "next_required_control": (
                "SINGLE_OPERATOR_FRESH_REAUTHENTICATION_REQUIRED"
                if exception is not None
                else "INDEPENDENT_APPROVAL_REQUIRED"
            ),
            "updated_at": timestamp,
        }
        if exception is not None:
            record.update(
                {
                    "authorization_mode": AUTHORIZATION_MODE_SINGLE_OPERATOR,
                    "two_human_status": "NOT_PROVEN",
                    "independent_approval_present": False,
                    "single_operator_authorization_sha256": exception[
                        "authorization_digest"
                    ],
                    "broker_runtime_version_arn_digest": exception[
                        "broker_runtime_version_arn_digest"
                    ],
                    "broker_version_binding_sha256": exception[
                        "broker_version_binding_sha256"
                    ],
                    "owner_authorization_sha256": exception[
                        "owner_authorization_sha256"
                    ],
                    "exception_created_at": exception["created_at"],
                    "exception_not_before": exception["not_before"],
                    "exception_expires_at": exception["expires_at"],
                }
            )
        record["ledger_digest"] = canonical_digest(record)
        return record

    def _validate_ledger(self, value: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(value)
        expected_keys = (
            LEDGER_V3_KEYS if self.config.is_single_operator else LEDGER_V2_KEYS
        )
        if set(record) != set(expected_keys):
            raise BrokerError("LEDGER_MALFORMED")
        digest = record.pop("ledger_digest", None)
        if not isinstance(digest, str) or canonical_digest(record) != digest:
            raise BrokerError("LEDGER_DIGEST_INVALID")
        record["ledger_digest"] = digest
        state = record.get("state")
        allowed_states = (
            LEDGER_V3_STATES if self.config.is_single_operator else LEDGER_V2_STATES
        )
        if state not in allowed_states:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_version = {
            "CLASSIFIED": 1,
            "APPROVED": 2,
            "EXCEPTION_ACCEPTED": 2,
            "ATTEMPTED": 3,
            "RETIRED_RECONCILED": 4,
        }[state]
        if record.get("version") != expected_version or record.get("attempt_count") != (
            0 if state in {"CLASSIFIED", "APPROVED", "EXCEPTION_ACCEPTED"} else 1
        ):
            raise BrokerError("LEDGER_STATE_INVALID")
        exception = self.config.single_operator_exception
        expected_bindings = {
            "schema_version": "3" if exception is not None else "2",
            "record_type": "platform_authority_change_set_retirement_pep_ledger",
            "environment": "non-production",
            "production": False,
            "authority_account_id_digest": secret_digest(
                "authority_account_id", self.config.authority_account_id
            ),
            "region": self.config.region,
            "stack_name": self.config.stack_name,
            "retirement_id": self.config.retirement_id,
            "change_set_name_digest": secret_digest(
                "change_set_name", self.config.change_set_name
            ),
            "template_sha256": self.config.expected_template_sha256,
            "resource_inventory_sha256": self.config.expected_evidence_sha256,
            "identity_binding_digest": self.config.identity_binding_digest,
            **self.config.identity_binding,
            "broker_code_sha256": self.config.expected_code_sha256,
            "broker_policy_sha256": self.config.expected_broker_policy_sha256,
            "identity_separation": (
                "SINGLE_OPERATOR_DECLARED_NOT_INDEPENDENT"
                if exception is not None
                else "VERIFIED_DISTINCT_IDENTITYSTORE_USERS"
            ),
            "human_authentication_evidence": "STS_EVALUATED_IDENTITY_CONTEXT",
            "aws_effect_principal": "BROKER_EXECUTION_ROLE",
            "native_on_behalf_of": False,
        }
        if exception is not None:
            expected_bindings.update(
                {
                    "authorization_mode": AUTHORIZATION_MODE_SINGLE_OPERATOR,
                    "two_human_status": "NOT_PROVEN",
                    "independent_approval_present": False,
                    "single_operator_authorization_sha256": exception[
                        "authorization_digest"
                    ],
                    "broker_runtime_version_arn_digest": exception[
                        "broker_runtime_version_arn_digest"
                    ],
                    "broker_version_binding_sha256": exception[
                        "broker_version_binding_sha256"
                    ],
                    "owner_authorization_sha256": exception[
                        "owner_authorization_sha256"
                    ],
                    "exception_created_at": exception["created_at"],
                    "exception_not_before": exception["not_before"],
                    "exception_expires_at": exception["expires_at"],
                }
            )
        if any(record.get(key) != expected for key, expected in expected_bindings.items()):
            raise BrokerError("LEDGER_BINDING_CHANGED")
        for field in ("stack_id_digest", "change_set_id_digest"):
            value_digest = record.get(field)
            if not isinstance(value_digest, str) or DIGEST.fullmatch(value_digest) is None:
                raise BrokerError("LEDGER_BINDING_CHANGED")
        users_equal = (
            record.get("classifier_identity_store_user_id_digest")
            == record.get("approver_identity_store_user_id_digest")
        )
        if users_equal != self.config.is_single_operator:
            raise BrokerError("LEDGER_BINDING_CHANGED")
        proof_presence: dict[str, tuple[bool, bool, bool]] = {
            "CLASSIFIED": (True, False, False),
            "APPROVED": (True, True, False),
            "EXCEPTION_ACCEPTED": (True, True, False),
            "ATTEMPTED": (True, True, False),
            "RETIRED_RECONCILED": (True, True, True),
        }
        for field, present in zip(
            (
                "classifier_identity_proof_sha256",
                "approver_identity_proof_sha256",
                "reconciliation_identity_proof_sha256",
            ),
            proof_presence[state],
            strict=True,
        ):
            value = record.get(field)
            if present:
                if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
                    raise BrokerError("IDENTITY_PROOF_LEDGER_INVALID")
            elif value is not None:
                raise BrokerError("IDENTITY_PROOF_LEDGER_INVALID")
        expected_fields: dict[str, tuple[bool, ...]] = {
            "CLASSIFIED": (False, False, False),
            "APPROVED": (True, False, False),
            "EXCEPTION_ACCEPTED": (True, False, False),
            "ATTEMPTED": (True, True, False),
            "RETIRED_RECONCILED": (True, True, True),
        }
        approval_present, attempt_present, verification_present = expected_fields[state]
        for field, present in (
            ("approval_digest", approval_present),
            ("attempt_digest", attempt_present),
            ("verification_digest", verification_present),
        ):
            field_value = record.get(field)
            if present:
                if not isinstance(field_value, str) or DIGEST.fullmatch(field_value) is None:
                    raise BrokerError("LEDGER_STATE_INVALID")
            elif field_value is not None:
                raise BrokerError("LEDGER_STATE_INVALID")
        timestamps = [_parse_timestamp(record.get("classified_at"))]
        for field, present in (
            ("approved_at", approval_present),
            ("attempted_at", attempt_present),
            ("verified_at", verification_present),
        ):
            field_value = record.get(field)
            if present:
                timestamps.append(_parse_timestamp(field_value))
            elif field_value is not None:
                raise BrokerError("LEDGER_STATE_INVALID")
        updated_at = _parse_timestamp(record.get("updated_at"))
        if timestamps != sorted(timestamps) or updated_at < timestamps[-1]:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_next_controls: dict[str, set[str]] = {
            "CLASSIFIED": {
                "SINGLE_OPERATOR_FRESH_REAUTHENTICATION_REQUIRED"
                if self.config.is_single_operator
                else "INDEPENDENT_APPROVAL_REQUIRED"
            },
            "APPROVED": {"ONE_SHOT_ATTEMPT_REQUIRED"},
            "EXCEPTION_ACCEPTED": {"ONE_SHOT_ATTEMPT_REQUIRED"},
            "ATTEMPTED": {"READ_ONLY_RECONCILIATION_REQUIRED"},
            "RETIRED_RECONCILED": {
                "SINGLE_OPERATOR_EXCEPTION_REVOCATION_REQUIRED"
                if self.config.is_single_operator
                else "RETIREMENT_ROLE_REVOCATION_REQUIRED",
                "SINGLE_OPERATOR_PAB_AND_REVOCATION_REQUIRED"
                if self.config.is_single_operator
                else "PAB_AND_REVOCATION_REQUIRED",
            },
        }
        if record.get("next_required_control") not in expected_next_controls[state]:
            raise BrokerError("LEDGER_STATE_INVALID")
        expected_attribution = (
            (
                "BROKER_SERVICE_PRINCIPAL_AFTER_SINGLE_OPERATOR_STS_PROOF"
                if self.config.is_single_operator
                else "BROKER_SERVICE_PRINCIPAL_AFTER_STS_PROOF"
            )
            if verification_present
            else None
        )
        if record.get("effect_attribution") != expected_attribution:
            raise BrokerError("LEDGER_STATE_INVALID")
        return record

    def _get_ledger(self, retirement_id: str) -> dict[str, Any] | None:
        response = self.clients.dynamodb.get_item(
            TableName=self.config.ledger_table_name,
            Key={"retirement_id": {"S": retirement_id}},
            ConsistentRead=True,
            ProjectionExpression="document",
        )
        item = response.get("Item")
        raw = item.get("document", {}).get("S") if isinstance(item, Mapping) else None
        if raw is None:
            return None
        return self._validate_ledger(_strict_json_object(raw, "LEDGER_MALFORMED"))

    def _create_ledger(self, ledger: Mapping[str, Any]) -> None:
        try:
            self.clients.dynamodb.put_item(
                TableName=self.config.ledger_table_name,
                Item={
                    "retirement_id": {"S": str(ledger["retirement_id"])},
                    "state": {"S": str(ledger["state"])},
                    "version": {"N": str(ledger["version"])},
                    "attempt_count": {"N": str(ledger["attempt_count"])},
                    "ledger_digest": {"S": str(ledger["ledger_digest"])},
                    "document": {
                        "S": json.dumps(ledger, sort_keys=True, separators=(",", ":"))
                    },
                },
                ConditionExpression="attribute_not_exists(retirement_id)",
                ReturnConsumedCapacity="NONE",
            )
        except Exception as exc:
            if isinstance(self.config, WorkforceRetirementConfig):
                raise BrokerError("LEDGER_CREATE_UNCERTAIN") from None
            try:
                observed = self._get_ledger(str(ledger["retirement_id"]))
            except Exception as read_exc:
                raise BrokerError("LEDGER_CREATE_UNCERTAIN") from read_exc
            if observed != dict(ledger):
                raise BrokerError("LEDGER_CREATE_UNCERTAIN") from exc

    def _transition(
        self,
        before: Mapping[str, Any],
        *,
        state: str,
        **updates: Any,
    ) -> dict[str, Any]:
        current = self._validate_ledger(before)
        expected_next = {
            "CLASSIFIED": (
                "EXCEPTION_ACCEPTED"
                if self.config.is_single_operator
                else "APPROVED"
            ),
            "APPROVED": "ATTEMPTED",
            "EXCEPTION_ACCEPTED": "ATTEMPTED",
            "ATTEMPTED": "RETIRED_RECONCILED",
        }.get(str(current["state"]))
        if state != expected_next:
            raise BrokerError("LEDGER_TRANSITION_FORBIDDEN")
        candidate = {
            key: value for key, value in current.items() if key != "ledger_digest"
        }
        candidate.update(updates)
        candidate["state"] = state
        candidate["version"] = int(current["version"]) + 1
        candidate["attempt_count"] = 1 if state in {
            "ATTEMPTED",
            "RETIRED_RECONCILED",
        } else 0
        candidate["updated_at"] = _timestamp(self.now())
        candidate["ledger_digest"] = canonical_digest(candidate)
        validated = self._validate_ledger(candidate)
        try:
            self.clients.dynamodb.update_item(
                TableName=self.config.ledger_table_name,
                Key={"retirement_id": {"S": str(current["retirement_id"])}},
                UpdateExpression=(
                    "SET #state = :state, #version = :version, "
                    "#attempt_count = :attempt_count, #ledger_digest = :ledger_digest, "
                    "#document = :document"
                ),
                ConditionExpression=(
                    "#state = :expected_state AND #version = :expected_version AND "
                    "#attempt_count = :expected_attempt_count AND "
                    "#ledger_digest = :expected_ledger_digest"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#version": "version",
                    "#attempt_count": "attempt_count",
                    "#ledger_digest": "ledger_digest",
                    "#document": "document",
                },
                ExpressionAttributeValues={
                    ":state": {"S": state},
                    ":version": {"N": str(validated["version"])},
                    ":attempt_count": {"N": str(validated["attempt_count"])},
                    ":ledger_digest": {"S": str(validated["ledger_digest"])},
                    ":document": {
                        "S": json.dumps(
                            validated, sort_keys=True, separators=(",", ":")
                        )
                    },
                    ":expected_state": {"S": str(current["state"])},
                    ":expected_version": {"N": str(current["version"])},
                    ":expected_attempt_count": {
                        "N": str(current["attempt_count"])
                    },
                    ":expected_ledger_digest": {
                        "S": str(current["ledger_digest"])
                    },
                },
                ReturnValues="NONE",
            )
        except Exception as exc:
            if isinstance(self.config, WorkforceRetirementConfig):
                raise BrokerError("LEDGER_TRANSITION_UNCERTAIN") from None
            try:
                observed = self._get_ledger(str(validated["retirement_id"]))
            except Exception as read_exc:
                raise BrokerError("LEDGER_TRANSITION_UNCERTAIN") from read_exc
            if observed != validated:
                raise BrokerError("LEDGER_TRANSITION_UNCERTAIN") from exc
        return validated

    def _classify(self, identity_proof_sha256: str) -> dict[str, Any]:
        existing = self._get_ledger(self.config.retirement_id)
        if existing is not None:
            if existing["state"] != "CLASSIFIED":
                raise BrokerError("CLASSIFICATION_ALREADY_ADVANCED")
            evidence = self._target_evidence()
            self._require_evidence_matches_ledger(existing, evidence)
            return {
                "status": "CLASSIFIED_ALREADY_RECORDED",
                "ledger_digest": existing["ledger_digest"],
                "next_required_control": existing["next_required_control"],
            }
        evidence = self._target_evidence()
        if evidence.get("retirement_id") != self.config.retirement_id:
            raise BrokerError("RETIREMENT_ID_CHANGED")
        ledger = self._base_ledger(evidence, identity_proof_sha256)
        self._create_ledger(ledger)
        return {
            "status": "CLASSIFIED",
            "ledger_digest": ledger["ledger_digest"],
            "next_required_control": ledger["next_required_control"],
        }

    def _retire(self, identity_proof_sha256: str) -> dict[str, Any]:
        # Read the durable claim before inspecting the live target. Once an
        # attempt exists, a missing Change Set is the expected ambiguous
        # outcome and must never cause a second DeleteChangeSet invocation.
        current = self._get_ledger(self.config.retirement_id)
        if current is None:
            raise BrokerError("CLASSIFICATION_LEDGER_MISSING")
        if current["state"] == "ATTEMPTED":
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": current["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        allowed_states = (
            {"CLASSIFIED", "EXCEPTION_ACCEPTED"}
            if self.config.is_single_operator
            else {"CLASSIFIED", "APPROVED"}
        )
        if current["state"] not in allowed_states:
            raise BrokerError("RETIREMENT_STATE_NOT_AUTHORIZED")
        if (
            self.config.is_single_operator
            and identity_proof_sha256
            == current.get("classifier_identity_proof_sha256")
        ):
            raise BrokerError("FRESH_REAUTHENTICATION_REQUIRED")
        evidence = self._target_evidence()
        self._require_evidence_matches_ledger(current, evidence)
        approved = current
        if current["state"] == "CLASSIFIED":
            approved_at = _timestamp(self.now())
            approval_input = {
                    "retirement_id": current["retirement_id"],
                    "classification_ledger_digest": current["ledger_digest"],
                    "approver_identity_store_user_id_digest": current[
                        "approver_identity_store_user_id_digest"
                    ],
                    "identity_binding_digest": current["identity_binding_digest"],
                    "approver_identity_proof_sha256": identity_proof_sha256,
                    "decision": "RETIRE_EXACT_UNEXECUTED_CHANGE_SET",
                    "allowed_action": "scanalyze:RetireExactChangeSet",
                    "approved_at": approved_at,
            }
            if self.config.is_single_operator:
                approval_input.update(
                    {
                        "authorization_mode": (
                            self.config.authorization_mode
                        ),
                        "two_human_status": "NOT_PROVEN",
                        "independent_approval_present": False,
                        "single_operator_authorization_sha256": current[
                            "single_operator_authorization_sha256"
                        ],
                    }
                )
            approval_digest = canonical_digest(approval_input)
            approved = self._transition(
                current,
                state=(
                    "EXCEPTION_ACCEPTED"
                    if self.config.is_single_operator
                    else "APPROVED"
                ),
                approval_digest=approval_digest,
                approver_identity_proof_sha256=identity_proof_sha256,
                approved_at=approved_at,
                next_required_control="ONE_SHOT_ATTEMPT_REQUIRED",
            )
        attempted_at = _timestamp(self.now())
        attempt_digest = canonical_digest(
            {
                "retirement_id": approved["retirement_id"],
                "approval_digest": approved["approval_digest"],
                "attempt_count": 1,
                "attempted_at": attempted_at,
            }
        )
        attempted = self._transition(
            approved,
            state="ATTEMPTED",
            attempt_digest=attempt_digest,
            attempted_at=attempted_at,
            next_required_control="READ_ONLY_RECONCILIATION_REQUIRED",
        )
        # Re-read the exact target after the durable one-shot claim. The SDK
        # client is configured with zero retries and this call occurs once.
        final_evidence = self._target_evidence()
        self._require_evidence_matches_ledger(attempted, final_evidence)
        exact_change_set_id = final_evidence.get("_change_set_id")
        exact_stack_id = final_evidence.get("_stack_id")
        if not isinstance(exact_change_set_id, str) or not isinstance(
            exact_stack_id, str
        ):
            raise BrokerError("CHANGE_SET_IDENTITY_CHANGED")
        if self.config.is_single_operator:
            if isinstance(self.config, WorkforceRetirementConfig):
                self.require_current()
            else:
                self._require_legacy_exception_effect_window()
        try:
            self.clients.cloudformation.delete_change_set(
                ChangeSetName=exact_change_set_id,
                StackName=exact_stack_id,
            )
        except BaseException as exc:
            if not isinstance(self.config, WorkforceRetirementConfig) and not isinstance(exc, Exception):
                raise
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": attempted["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        return {
            "status": "RETIREMENT_ATTEMPTED",
            "ledger_digest": attempted["ledger_digest"],
            "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
        }

    def _require_legacy_exception_effect_window(self) -> None:
        exception = self.config.single_operator_exception
        if exception is None:
            raise BrokerError("CONFIGURATION_INCOMPLETE")
        try:
            require_exception_effect_window(exception, now=self.now())
        except SingleOperatorExceptionError as exc:
            # ATTEMPTED is durable. An expired or ambiguous operation can
            # only reconcile; it can never reopen or issue a second delete.
            raise BrokerError(exc.code) from None

    def _reconcile(self, identity_proof_sha256: str) -> dict[str, Any]:
        # The durable deployment-bound key is authoritative. Live names or
        # IDs can never select a different ledger record.
        current = self._get_ledger(self.config.retirement_id)
        if current is None or current.get("state") != "ATTEMPTED":
            raise BrokerError("RECONCILIATION_STATE_NOT_AUTHORIZED")
        stack = self._stack()
        stack_id = self._require_reconciliation_stack(current, stack)
        inventory = self._change_set_inventory(stack_id)
        target = [
            item
            for item in inventory
            if item.get("ChangeSetName") == self.config.change_set_name
        ]
        if len(target) > 1 or len(inventory) != len(target):
            raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
        if target:
            change_set_id = target[0].get("ChangeSetId")
            if (
                not isinstance(change_set_id, str)
                or secret_digest("change_set_id", change_set_id)
                != current.get("change_set_id_digest")
            ):
                raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
            return {
                "status": "RECONCILIATION_REQUIRED",
                "ledger_digest": current["ledger_digest"],
                "next_required_control": "READ_ONLY_RECONCILIATION_REQUIRED",
            }
        pab = self._account_pab()
        verified_at = _timestamp(self.now())
        verification_digest = canonical_digest(
            {
                "retirement_id": current["retirement_id"],
                "attempt_digest": current["attempt_digest"],
                "stack_status": "REVIEW_IN_PROGRESS",
                "stack_resource_count": 0,
                "active_change_set_count": 0,
                "target_absent": True,
                "account_public_access_block": pab,
                "reconciliation_identity_proof_sha256": identity_proof_sha256,
                "verified_at": verified_at,
            }
        )
        # Repeat the exact shell and inventory proof immediately before the
        # terminal CAS. A recreated stack or reappearing Change Set leaves the
        # durable state ATTEMPTED and requires a fresh read-only investigation.
        final_stack = self._stack()
        final_stack_id = self._require_reconciliation_stack(current, final_stack)
        if self._change_set_inventory(final_stack_id) != []:
            raise BrokerError("RECONCILIATION_INVENTORY_AMBIGUOUS")
        if isinstance(self.config, WorkforceRetirementConfig):
            next_control = (
                "WORKFORCE_RETIREMENT_ROLE_REVOCATION_REQUIRED"
                if pab is not None and all(pab.values())
                else "WORKFORCE_PAB_AND_REVOCATION_REQUIRED"
            )
        elif self.config.is_single_operator:
            next_control = (
                "SINGLE_OPERATOR_EXCEPTION_REVOCATION_REQUIRED"
                if pab is not None and all(pab.values())
                else "SINGLE_OPERATOR_PAB_AND_REVOCATION_REQUIRED"
            )
        else:
            next_control = (
                "RETIREMENT_ROLE_REVOCATION_REQUIRED"
                if pab is not None and all(pab.values())
                else "PAB_AND_REVOCATION_REQUIRED"
            )
        reconciled = self._transition(
            current,
            state="RETIRED_RECONCILED",
            verification_digest=verification_digest,
            reconciliation_identity_proof_sha256=identity_proof_sha256,
            verified_at=verified_at,
            effect_attribution=(
                "BROKER_SERVICE_PRINCIPAL_AFTER_WORKFORCE_IAM"
                if isinstance(self.config, WorkforceRetirementConfig)
                else
                "BROKER_SERVICE_PRINCIPAL_AFTER_SINGLE_OPERATOR_STS_PROOF"
                if self.config.is_single_operator
                else "BROKER_SERVICE_PRINCIPAL_AFTER_STS_PROOF"
            ),
            next_required_control=next_control,
        )
        return {
            "status": "RETIRED_RECONCILED",
            "ledger_digest": reconciled["ledger_digest"],
            "next_required_control": next_control,
        }


def _alias_from_context(context: object) -> str:
    arn = getattr(context, "invoked_function_arn", None)
    if not isinstance(arn, str):
        raise BrokerError("INVOCATION_CONTEXT_MISSING")
    alias = arn.rsplit(":", 1)[-1]
    if alias not in ALLOWED_ALIASES:
        raise BrokerError("ALIAS_NOT_AUTHORIZED")
    return alias


def handler(event: object, context: object) -> dict[str, Any]:
    """Retained fail-closed shim; the template uses the GUG-217 URL handler."""
    del event, context
    return {"status": "DENY", "reason_code": "DIRECT_ENTRYPOINT_DISABLED"}


WORKFORCE_RETIREMENT_MODE = "WORKFORCE_SINGLE_OWNER_RETIREMENT_V1"
WORKFORCE_RETIREMENT_OPERATIONS = ("classify", "retire", "reconcile")
WORKFORCE_RETIREMENT_ROLES = {"classify": "ScanalyzeAuthorityRetireClass", "retire": "ScanalyzeAuthorityRetireApprove"}
WORKFORCE_READER_ARN = "arn:aws:iam::839393571433:role/ScanalyzeGug215WorkforceAssignmentReader"
WORKFORCE_INSTANCE = "arn:aws:sso:::instance/ssoins-7223feaee61e2475"
WORKFORCE_STORE = "d-906633fcab"
WORKFORCE_CONFIG_FIELDS = frozenset({
    "schema_version", "authorization_mode", "authority_account_id", "region", "stack_id", "change_set_id",
    "expected_template_sha256", "expected_evidence_sha256", "expected_code_sha256", "expected_broker_policy_sha256",
    "broker_role_id", "broker_trust_policy_sha256", "broker_runtime_version_arn", "code_signing_config_arn",
    "signing_profile_version_arn", "function_version", "api_id", "owner_operator_id", "owner_subject_digest",
    "authorized_at", "not_before", "expires_at", "roles", "management_reader_role_arn",
})
WORKFORCE_CONFIG_V2_FIELDS = WORKFORCE_CONFIG_FIELDS - {"function_version"}


def _workforce_require(value: bool, code: str = "WORKFORCE_RETIREMENT_BINDING_INVALID") -> None:
    if not value:
        raise BrokerError(code)


def _workforce_plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _workforce_plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_workforce_plain(item) for item in value]
    return value


def _workforce_freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _workforce_freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_workforce_freeze(item) for item in value)
    return value


def _workforce_json_object(value: str) -> dict[str, Any]:
    def pairs(items: list) -> dict:
        result = {}
        for key, item in items:
            _workforce_require(key not in result, "WORKFORCE_JSON_INVALID")
            result[key] = item
        return result
    def constant(_value: str) -> None:
        raise BrokerError("WORKFORCE_JSON_INVALID")
    try:
        _workforce_require(type(value) is str and len(value.encode("utf-8")) <= 65536)
        result = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
        _workforce_require(type(result) is dict)
        return result
    except Exception:
        raise BrokerError("WORKFORCE_JSON_INVALID") from None


def _workforce_policy_digest(value: Any) -> str:
    if type(value) is str:
        return canonical_digest(_workforce_json_object(value))
    _workforce_require(type(value) is dict, "WORKFORCE_POLICY_INVALID")
    return canonical_digest(_workforce_json_object(json.dumps(value, allow_nan=False)))


def workforce_owner_subject_digest(user_id: str) -> str:
    """Hash the private opaque USER ID only; never return its raw value."""
    _workforce_require(type(user_id) is str and 1 <= len(user_id) <= 128)
    return canonical_digest({"domain": "scanalyze.gug215.workforce-owner.v1",
                             "identity_store_id": WORKFORCE_STORE, "user_id": user_id})


@dataclass(frozen=True, slots=True)
class WorkforceRetirementConfig:
    """Integrity-bound immutable input, not proof of its installer's authority."""
    document: Mapping[str, Any]
    expected_digest: str
    _runtime_function_version: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            data = _workforce_plain(self.document)
            _workforce_require(type(data) is dict and data.get("schema_version") in ("1", "2"))
            fields = WORKFORCE_CONFIG_FIELDS if data["schema_version"] == "1" else WORKFORCE_CONFIG_V2_FIELDS
            _workforce_require(set(data) == fields)
            _workforce_require(canonical_digest(data) == _require_digest(self.expected_digest, "WORKFORCE_CONFIG_PIN_INVALID"))
            _workforce_require(data["authorization_mode"] == WORKFORCE_RETIREMENT_MODE)
            _workforce_require(data["authority_account_id"] == "042360977644" and data["region"] == "us-east-1")
            _workforce_require(data["owner_operator_id"] == "cesar-guzman" and data["management_reader_role_arn"] == WORKFORCE_READER_ARN)
            for key in ("expected_template_sha256", "expected_evidence_sha256", "expected_broker_policy_sha256",
                        "broker_trust_policy_sha256", "owner_subject_digest"):
                _require_digest(data[key], "WORKFORCE_CONFIG_DIGEST_INVALID")
            for key, pattern in {
                "stack_id": r"arn:aws:cloudformation:us-east-1:042360977644:stack/scanalyze-platform-authority-state-backend/[0-9a-f-]{36}",
                "change_set_id": r"arn:aws:cloudformation:us-east-1:042360977644:changeSet/scanalyze-platform-authority-bootstrap-[0-9]{14}/[0-9a-f-]{36}",
                "broker_role_id": r"AROA[A-Z0-9]{17}", "expected_code_sha256": r"[A-Za-z0-9+/]{43}=",
                "broker_runtime_version_arn": r"arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}",
                "code_signing_config_arn": r"arn:aws:lambda:us-east-1:042360977644:code-signing-config:csc-[a-z0-9]{17}",
                "signing_profile_version_arn": r"arn:aws:signer:us-east-1:042360977644:/signing-profiles/[A-Za-z0-9_]{2,64}/[A-Za-z0-9]{10}",
                "api_id": r"[a-z0-9]{10}",
            }.items():
                _workforce_require(type(data[key]) is str and re.fullmatch(pattern, data[key]) is not None)
            if data["schema_version"] == "1":
                _workforce_require(type(data["function_version"]) is str
                                   and re.fullmatch(r"[1-9][0-9]{0,7}", data["function_version"]) is not None)
            for key in ("stack_id", "change_set_id"):
                _workforce_require(UUID.fullmatch(data[key].rsplit("/", 1)[1]) is not None)
            created, start, end = (self.parse_time(data[key]) for key in ("authorized_at", "not_before", "expires_at"))
            _workforce_require(created <= start < end and (start - created).total_seconds() <= 3600
                               and (end - start).total_seconds() <= 900)
            _workforce_require(type(data["roles"]) is dict and set(data["roles"]) == set(WORKFORCE_RETIREMENT_ROLES))
            for operation, name in WORKFORCE_RETIREMENT_ROLES.items():
                role = data["roles"][operation]
                _workforce_require(type(role) is dict and set(role) == {"role_arn", "role_id", "permission_set_arn", "policy_sha256", "trust_sha256"})
                _workforce_require(re.fullmatch(r"arn:aws:iam::042360977644:role/aws-reserved/sso\.amazonaws\.com/(?:us-east-1/)?AWSReservedSSO_"
                                               + name + r"_[0-9a-f]{16}", role["role_arn"]) is not None)
                _workforce_require(re.fullmatch(r"AROA[A-Z0-9]{17}", role["role_id"]) is not None)
                _workforce_require(re.fullmatch(r"arn:aws:sso:::permissionSet/ssoins-7223feaee61e2475/ps-[a-z0-9]{16}", role["permission_set_arn"]) is not None)
                for key in ("policy_sha256", "trust_sha256"):
                    _require_digest(role[key], "WORKFORCE_ROLE_DIGEST_INVALID")
            _workforce_require(data["roles"]["classify"]["permission_set_arn"] != data["roles"]["retire"]["permission_set_arn"])
            _workforce_require(data["roles"]["classify"]["role_id"] != data["roles"]["retire"]["role_id"])
            object.__setattr__(self, "document", _workforce_freeze(data))
        except Exception:
            raise BrokerError("WORKFORCE_RETIREMENT_BINDING_INVALID") from None

    @staticmethod
    def parse_time(value: str) -> datetime:
        _workforce_require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None)
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def require_time(self, now: datetime, *, reconcile: bool = False) -> None:
        _workforce_require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() is not None
                           and now.utcoffset().total_seconds() == 0, "WORKFORCE_CLOCK_INVALID")
        _workforce_require(self.parse_time(self.document["not_before"]) <= now, "WORKFORCE_WINDOW_INACTIVE")
        if not reconcile:
            _workforce_require(now < self.parse_time(self.document["expires_at"]), "WORKFORCE_WINDOW_EXPIRED")

    def __getattr__(self, name: str) -> Any:
        if name in self.document:
            return self.document[name]
        raise AttributeError(name)

    partition = "aws"
    authority_account_id = "042360977644"
    region = "us-east-1"
    stack_name = CANONICAL_STACK_NAME
    function_name = BROKER_FUNCTION_NAME
    ledger_table_name = RETIREMENT_LEDGER_TABLE
    broker_execution_role_name = "ScanalyzeGug215BrokerExecution"
    is_single_operator = True
    authorization_mode = WORKFORCE_RETIREMENT_MODE
    single_operator_exception = None
    allowed_aliases = frozenset(WORKFORCE_RETIREMENT_OPERATIONS)
    table_arn = "arn:aws:dynamodb:us-east-1:042360977644:table/" + RETIREMENT_LEDGER_TABLE
    function_arn = "arn:aws:lambda:us-east-1:042360977644:function:" + BROKER_FUNCTION_NAME
    execution_role_arn = "arn:aws:iam::042360977644:role/ScanalyzeGug215BrokerExecution"
    broker_permissions_boundary_arn = "arn:aws:iam::042360977644:policy/scanalyze/platform-authority/" + BROKER_BOUNDARY_POLICY_NAME

    @property
    def change_set_name(self) -> str:
        return self.document["change_set_id"].split("/")[1]

    @property
    def retirement_id(self) -> str:
        return "gug215#sha256:" + hashlib.sha256(self.document["change_set_id"].encode("utf-8")).hexdigest()

    @property
    def stack_arn(self) -> str:
        return self.document["stack_id"]

    @property
    def identity_binding_digest(self) -> str:
        return self.expected_digest

    @property
    def function_version(self) -> str:
        if self.document["schema_version"] == "1":
            return self.document["function_version"]
        _workforce_require(self._runtime_function_version is not None, "WORKFORCE_VERSION_UNBOUND")
        return self._runtime_function_version

    def bind_lambda_context(self, context: object) -> "WorkforceRetirementConfig":
        """Bind provider context in memory; neither context nor a hash grants authority.

        Schema 2 can be installed before PublishVersion. Its environment never
        contains the version; deployed-stage, signed-code and policy readbacks
        must independently confirm this exact numeric invocation before a CAS.
        """
        if self.document["schema_version"] == "1":
            _workforce_require(getattr(context, "invoked_function_arn", None) == self.version_arn,
                               "WORKFORCE_VERSION_INVALID")
            return self
        version = getattr(context, "function_version", None)
        _workforce_require(type(version) is str and re.fullmatch(r"[1-9][0-9]{0,7}", version) is not None,
                           "WORKFORCE_VERSION_INVALID")
        _workforce_require(getattr(context, "invoked_function_arn", None) == self.function_arn + ":" + version,
                           "WORKFORCE_VERSION_INVALID")
        # A previously bound object cannot silently switch versions.
        _workforce_require(self._runtime_function_version in (None, version), "WORKFORCE_VERSION_INVALID")
        bound = WorkforceRetirementConfig(self.document, self.expected_digest)
        object.__setattr__(bound, "_runtime_function_version", version)
        return bound

    @property
    def version_arn(self) -> str:
        return self.function_arn + ":" + self.function_version

    def runtime_environment(self) -> dict[str, str]:
        raw = json.dumps(_workforce_plain(self.document), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return {"GUG215_IDENTITY_MODE": WORKFORCE_RETIREMENT_MODE,
                "GUG215_WORKFORCE_CONFIG_B64Z": base64.b64encode(zlib.compress(raw, 9)).decode("ascii"),
                "GUG215_WORKFORCE_CONFIG_DIGEST": self.expected_digest}


def workforce_retirement_resource_policy(config: WorkforceRetirementConfig) -> dict[str, Any]:
    """Exact numeric-version boundary required before trusting HTTP IAM context."""
    prefix = f"arn:aws:execute-api:us-east-1:042360977644:{config.api_id}/retirement/POST/"
    routes = [prefix + operation for operation in WORKFORCE_RETIREMENT_OPERATIONS]
    def deny(sid: str, condition: dict) -> dict:
        return {"Sid": sid, "Effect": "Deny", "Principal": "*", "Action": "lambda:InvokeFunction",
                "Resource": config.version_arn, "Condition": condition}
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowExactRetirementApi", "Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"},
         "Action": "lambda:InvokeFunction", "Resource": config.version_arn,
         "Condition": {"StringEquals": {"aws:SourceAccount": "042360977644"}, "ArnEquals": {"aws:SourceArn": routes}}},
        deny("DenyDirectInvocation", {"StringNotEquals": {"aws:PrincipalServiceName": "apigateway.amazonaws.com"}}),
        deny("DenyForeignAccount", {"StringNotEquals": {"aws:SourceAccount": "042360977644"}}),
        deny("DenyForeignRoute", {"ArnNotEquals": {"aws:SourceArn": routes}}),
        deny("DenyBeforeWindow", {"DateLessThan": {"aws:CurrentTime": config.not_before}}),
        deny("DenyExpiredMutation", {"DateGreaterThanEquals": {"aws:CurrentTime": config.expires_at},
                                      "ArnEquals": {"aws:SourceArn": routes[:2]}}),
        {"Sid": "DenyAsync", "Effect": "Deny", "Principal": "*", "Action": "lambda:InvokeAsync", "Resource": config.version_arn},
    ]}


@dataclass(frozen=True, slots=True)
class WorkforceRetirementRequest:
    operation: str
    caller_arn: str
    caller_role_id: str
    requested_at: datetime
    validated_at: datetime
    request_id_digest: str
    binding_digest: str


class WorkforceRetirementBroker(RetirementBroker):
    """The same GUG-215 target/store/CAS, with a separate honest IAM binding."""

    def __init__(self, *, config: WorkforceRetirementConfig, clients: Any,
                 request: WorkforceRetirementRequest, now: Callable[[], datetime],
                 deadline: float | None = None) -> None:
        _workforce_require(type(config) is WorkforceRetirementConfig and type(request) is WorkforceRetirementRequest)
        super().__init__(config=config, clients=clients, now=now)
        self.request = request
        self._last_time = request.validated_at
        self._deadline = time.monotonic() + 25 if deadline is None else deadline

    def _time(self, *, reconcile: bool = False) -> datetime:
        value = self.now()
        self.config.require_time(value, reconcile=reconcile)
        _workforce_require(self.request.requested_at <= self._last_time <= value
                           and (value - self.request.requested_at).total_seconds() < 300
                           and time.monotonic() < self._deadline, "WORKFORCE_REQUEST_EXPIRED")
        self._last_time = value
        return value

    def _pages(self, client: Any, method: str, field: str, **kwargs: Any) -> list:
        rows, seen, token = [], set(), None
        for _ in range(4):
            self._time(reconcile=self.request.operation == "reconcile")
            response = getattr(client, method)(**kwargs, **({"NextToken": token} if token else {}))
            _workforce_require(type(response) is dict and type(response.get(field)) is list, "WORKFORCE_METADATA_INVALID")
            rows.extend(response[field])
            _workforce_require(len(rows) <= 256, "WORKFORCE_METADATA_LIMIT")
            token = response.get("NextToken")
            if token is None:
                return rows
            _workforce_require(type(token) is str and 0 < len(token) <= 2048 and token not in seen, "WORKFORCE_PAGINATION_INVALID")
            seen.add(token)
        raise BrokerError("WORKFORCE_METADATA_LIMIT")

    def _iam_role(self, role: Mapping, *, permission_set: bool = True) -> None:
        name = role["role_arn"].rsplit("/", 1)[1]
        actual = self.clients.iam.get_role(RoleName=name).get("Role")
        _workforce_require(type(actual) is dict and actual.get("Arn") == role["role_arn"]
                           and actual.get("RoleId") == role["role_id"]
                           and _workforce_policy_digest(actual.get("AssumeRolePolicyDocument")) == role["trust_sha256"], "WORKFORCE_ROLE_CHANGED")
        if not permission_set:
            _workforce_require(actual.get("PermissionsBoundary") == {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": self.config.broker_permissions_boundary_arn})
            inline, attached = self._role_policy_inventory(role_name=name, failure_code="WORKFORCE_ROLE_CHANGED")
            _workforce_require(inline == [] and attached == [{"PolicyName": BROKER_BOUNDARY_POLICY_NAME,
                                                             "PolicyArn": self.config.broker_permissions_boundary_arn}])
            self._verify_managed_policy_document(policy_arn=self.config.broker_permissions_boundary_arn,
                expected_policy_sha256=self.config.expected_broker_policy_sha256,
                expected_identity_role_names=[name], expected_boundary_role_names=[name], failure_code="WORKFORCE_ROLE_CHANGED",
                expected_role_ids={name: role["role_id"]})
            return
        _workforce_require(actual.get("PermissionsBoundary") is None, "WORKFORCE_ROLE_CHANGED")
        inline, attached = self._role_policy_inventory(role_name=name, failure_code="WORKFORCE_ROLE_CHANGED")
        _workforce_require(len(inline) == 1 and attached == [], "WORKFORCE_ROLE_CHANGED")
        policy = self.clients.iam.get_role_policy(RoleName=name, PolicyName=inline[0])
        _workforce_require(policy.get("RoleName") == name and policy.get("PolicyName") == inline[0]
                           and _workforce_policy_digest(policy.get("PolicyDocument")) == role["policy_sha256"], "WORKFORCE_ROLE_CHANGED")

    def _assignments(self) -> None:
        # This private SDK context assumes only the fixed management reader.
        # It does not return a Boolean authority decision or expose credentials.
        with self.clients.assignment_reader() as sso:
            for operation, expected_name in WORKFORCE_RETIREMENT_ROLES.items():
                role = self.config.roles[operation]
                kwargs = {"InstanceArn": WORKFORCE_INSTANCE, "PermissionSetArn": role["permission_set_arn"]}
                record = sso.describe_permission_set(**kwargs).get("PermissionSet")
                _workforce_require(type(record) is dict and record.get("PermissionSetArn") == role["permission_set_arn"]
                                   and record.get("Name") == expected_name and record.get("SessionDuration") == "PT1H", "WORKFORCE_PERMISSION_SET_CHANGED")
                assignments = self._pages(sso, "list_account_assignments", "AccountAssignments", **kwargs, AccountId="042360977644")
                _workforce_require(len(assignments) == 1 and type(assignments[0]) is dict, "WORKFORCE_ASSIGNMENT_CHANGED")
                assignment = assignments[0]
                _workforce_require(assignment.get("AccountId") == "042360977644"
                                   and assignment.get("PermissionSetArn") == role["permission_set_arn"]
                                   and assignment.get("PrincipalType") == "USER"
                                   and workforce_owner_subject_digest(assignment.get("PrincipalId")) == self.config.owner_subject_digest,
                                   "WORKFORCE_ASSIGNMENT_CHANGED")
                _workforce_require(self._pages(sso, "list_accounts_for_provisioned_permission_set", "AccountIds", **kwargs) == ["042360977644"], "WORKFORCE_ACCOUNT_SCOPE_CHANGED")
                policy = sso.get_inline_policy_for_permission_set(**kwargs).get("InlinePolicy")
                _workforce_require(_workforce_policy_digest(policy) == role["policy_sha256"], "WORKFORCE_PERMISSION_SET_CHANGED")
                _workforce_require(self._pages(sso, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", **kwargs) == [])
                _workforce_require(self._pages(sso, "list_customer_managed_policy_references_in_permission_set", "CustomerManagedPolicyReferences", **kwargs) == [])
                try:
                    boundary = sso.get_permissions_boundary_for_permission_set(**kwargs)
                except Exception as exc:
                    # The real API uses this exact 404 for an absent boundary.
                    # A missing permission set, denied read or generic 404 is
                    # NOT absence. Reconfirm the pinned permission set after
                    # this response; never retry the boundary call implicitly.
                    response = getattr(exc, "response", None)
                    _workforce_require(type(response) is dict
                        and type(response.get("Error")) is dict
                        and response["Error"].get("Code") == "ResourceNotFoundException"
                        and response["Error"].get("Message") == "PermissionsBoundary not present in permission set " + role["permission_set_arn"]
                        and type(response.get("ResponseMetadata")) is dict
                        and type(response["ResponseMetadata"].get("HTTPStatusCode")) is int
                        and response["ResponseMetadata"]["HTTPStatusCode"] == 404,
                        "WORKFORCE_PERMISSION_SET_CHANGED")
                    self._time(reconcile=self.request.operation == "reconcile")
                    existing = sso.describe_permission_set(**kwargs).get("PermissionSet")
                    self._time(reconcile=self.request.operation == "reconcile")
                    _workforce_require(type(existing) is dict
                        and existing.get("PermissionSetArn") == role["permission_set_arn"]
                        and existing.get("Name") == expected_name and existing.get("SessionDuration") == "PT1H",
                        "WORKFORCE_PERMISSION_SET_CHANGED")
                    boundary = {}
                _workforce_require(type(boundary) is dict and boundary.get("PermissionsBoundary") is None, "WORKFORCE_PERMISSION_SET_CHANGED")
                self._iam_role(role)

    def require_current(self, *, reconcile: bool = False) -> None:
        self._time(reconcile=reconcile)
        _workforce_require(self.request.binding_digest == self.config.expected_digest)
        operation = "classify" if self.request.operation == "classify" else "retire"
        role = self.config.roles[operation]
        prefix = "arn:aws:sts::042360977644:assumed-role/" + role["role_arn"].rsplit("/", 1)[1] + "/"
        _workforce_require(self.request.caller_arn.startswith(prefix) and self.request.caller_role_id == role["role_id"], "WORKFORCE_CALLER_CHANGED")
        identity = self.clients.sts.get_caller_identity()
        _workforce_require(identity.get("Account") == "042360977644"
                           and type(identity.get("Arn")) is str
                           and re.fullmatch(r"arn:aws:sts::042360977644:assumed-role/ScanalyzeGug215BrokerExecution/[A-Za-z0-9+=,.@_-]{2,64}", identity["Arn"])
                           and identity.get("UserId") == self.config.broker_role_id + ":" + identity["Arn"].rsplit("/", 1)[1], "WORKFORCE_EXECUTOR_CHANGED")
        self._assignments()
        if self.config.schema_version == "2":
            self._verify_deployed_stage(reconcile=reconcile)
        self._time(reconcile=reconcile)

    def _verify_deployed_stage(self, *, reconcile: bool) -> None:
        # Local import keeps the seven-source legacy package importable. Only
        # schema 2 requires the separately reviewed eighth source in its ZIP.
        from tooling.platform_authority_workforce_stage_binding import (
            MAX_EXPORT_BYTES,
            verify_workforce_deployed_stage,
        )

        stream = None
        try:
            client, cfg = self.clients.apigatewayv2, self.config

            def read(method: str, **kwargs: Any) -> Any:
                self._time(reconcile=reconcile)
                response = getattr(client, method)(**kwargs)
                self._time(reconcile=reconcile)
                return response

            # Editable configuration alone is insufficient: the stage export
            # identifies the deployed snapshot, bracketed by the same stage's
            # DeploymentId. No response/body digest supplies authorization.
            api = copy.deepcopy(read("get_api", ApiId=cfg.api_id))
            routes = copy.deepcopy(read("get_routes", ApiId=cfg.api_id))
            integrations = copy.deepcopy(read("get_integrations", ApiId=cfg.api_id))
            stages_before = copy.deepcopy(read("get_stages", ApiId=cfg.api_id))
            export_request = {"ApiId": cfg.api_id, "Specification": "OAS30", "OutputType": "JSON",
                              "IncludeExtensions": True, "StageName": "retirement"}
            response = read("export_api", **export_request)
            stream = response["body"]
            self._time(reconcile=reconcile)
            export_body = stream.read(MAX_EXPORT_BYTES + 1)
            self._time(reconcile=reconcile)
            _workforce_require(type(export_body) is bytes and 0 < len(export_body) <= MAX_EXPORT_BYTES,
                               "WORKFORCE_STAGE_READ_FAILED")
            _workforce_require(stream.read(1) == b"", "WORKFORCE_STAGE_READ_FAILED")
            self._time(reconcile=reconcile)
            stream.close()
            stream = None
            self._time(reconcile=reconcile)
            stages_after = copy.deepcopy(read("get_stages", ApiId=cfg.api_id))
            verify_workforce_deployed_stage(expected_api_id=cfg.api_id, expected_version_arn=cfg.version_arn,
                api=api, routes=routes, integrations=integrations, stages_before=stages_before,
                stages_after=stages_after, export_request=export_request, export_body=export_body)
            self._time(reconcile=reconcile)
        except BrokerError:
            raise
        except Exception:
            raise BrokerError("WORKFORCE_STAGE_READ_FAILED") from None
        finally:
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

    def _verify_runtime_boundary(self, alias: str) -> None:
        cfg = self.config
        self._iam_role({"role_arn": cfg.execution_role_arn, "role_id": cfg.broker_role_id,
                        "trust_sha256": cfg.broker_trust_policy_sha256}, permission_set=False)
        function = self.clients.lambda_client.get_function_configuration(FunctionName=cfg.version_arn)
        expected = {"FunctionArn": cfg.version_arn, "Version": cfg.function_version, "CodeSha256": cfg.expected_code_sha256,
            "Role": cfg.execution_role_arn, "RuntimeVersionConfig": {"RuntimeVersionArn": cfg.broker_runtime_version_arn},
            "LoggingConfig": {"LogFormat": "JSON", "ApplicationLogLevel": "ERROR", "SystemLogLevel": "WARN", "LogGroup": BROKER_LOG_GROUP_NAME},
            "Architectures": ["x86_64"], "EphemeralStorage": {"Size": 512},
            "Handler": "tooling.platform_authority_identity_context_pep_runtime.handler", "MemorySize": 256,
            "PackageType": "Zip", "Runtime": "python3.12", "Timeout": 60, "TracingConfig": {"Mode": "PassThrough"},
            "Environment": {"Variables": cfg.runtime_environment()}}
        _workforce_require(all(function.get(key) == value for key, value in expected.items()), "WORKFORCE_RUNTIME_CHANGED")
        vpc = function.get("VpcConfig")
        _workforce_require(isinstance(vpc, dict)
                           and {key: value for key, value in vpc.items() if key != "Ipv6AllowedForDualStack"}
                           == {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""}
                           and ("Ipv6AllowedForDualStack" not in vpc or vpc["Ipv6AllowedForDualStack"] is False),
                           "WORKFORCE_RUNTIME_CHANGED")
        for key in ("Layers", "FileSystemConfigs", "DeadLetterConfig", "KMSKeyArn"):
            _workforce_require(function.get(key) in (None, [], {}, ""), "WORKFORCE_RUNTIME_CHANGED")
        _workforce_require(function.get("SnapStart") in (None, {}, {"ApplyOn": "None", "OptimizationStatus": "Off"}))
        management = self.clients.lambda_client.get_runtime_management_config(FunctionName=cfg.function_name, Qualifier=cfg.function_version)
        _workforce_require(management.get("FunctionArn") == cfg.version_arn and management.get("UpdateRuntimeOn") == "Manual"
                           and management.get("RuntimeVersionArn") == cfg.broker_runtime_version_arn, "WORKFORCE_RUNTIME_CHANGED")
        _workforce_require(self.clients.lambda_client.get_function_concurrency(FunctionName=cfg.function_name).get("ReservedConcurrentExecutions") == 1)
        signing = self.clients.lambda_client.get_function_code_signing_config(FunctionName=cfg.function_name)
        _workforce_require(signing.get("CodeSigningConfigArn") == cfg.code_signing_config_arn, "WORKFORCE_SIGNING_CHANGED")
        csc = self.clients.lambda_client.get_code_signing_config(CodeSigningConfigArn=cfg.code_signing_config_arn).get("CodeSigningConfig", {})
        _workforce_require(csc.get("CodeSigningConfigArn") == cfg.code_signing_config_arn
                           and csc.get("AllowedPublishers") == {"SigningProfileVersionArns": [cfg.signing_profile_version_arn]}
                           and csc.get("CodeSigningPolicies") == {"UntrustedArtifactOnDeployment": "Enforce"}, "WORKFORCE_SIGNING_CHANGED")
        policy = self.clients.lambda_client.get_policy(FunctionName=cfg.version_arn)
        _workforce_require(_workforce_json_object(policy.get("Policy")) == workforce_retirement_resource_policy(cfg), "WORKFORCE_RESOURCE_POLICY_CHANGED")

    def preflight(self, *, alias: str) -> None:
        _workforce_require(alias == self.request.operation and alias in WORKFORCE_RETIREMENT_OPERATIONS)
        self.require_current(reconcile=alias == "reconcile")
        self._verify_runtime_boundary(alias)
        self._verify_table_controls()
        self._time(reconcile=alias == "reconcile")

    def _ledger_control_tags(self) -> dict[str, str]:
        # Initial installation creates this exact production contract. This
        # validator never retags, adopts or treats a mismatch as absence.
        return {**EXPECTED_LEDGER_TAGS, "environment": "production", "production": "true"}

    def _ledger_write_actions(self) -> frozenset[str]:
        return WORKFORCE_WRITE_ACTIONS

    def _target_evidence(self) -> dict[str, Any]:
        evidence = super()._target_evidence()
        _workforce_require(evidence["_change_set_id"] == self.config.change_set_id
                           and evidence["_stack_id"] == self.config.stack_id
                           and evidence["retirement_id"] == self.config.retirement_id, "WORKFORCE_TARGET_CHANGED")
        return evidence

    def _stack(self) -> Mapping[str, Any]:
        # Preserve the legacy predicates and close pagination/identity ambiguity
        # for this new mode without broadening the legacy execution path.
        stack = super()._stack()
        _workforce_require(stack.get("StackId") == self.config.stack_id, "WORKFORCE_TARGET_CHANGED")
        resources = self.clients.cloudformation.list_stack_resources(StackName=self.config.stack_id)
        _workforce_require(resources.get("StackResourceSummaries") == []
                           and resources.get("NextToken") is None, "STACK_RESOURCE_INVENTORY_CHANGED")
        self._time(reconcile=self.request.operation == "reconcile")
        return stack

    def _change_set_inventory(self, stack_id: str) -> list[Mapping[str, Any]]:
        _workforce_require(stack_id == self.config.stack_id, "WORKFORCE_TARGET_CHANGED")
        return self._pages(self.clients.cloudformation, "list_change_sets", "Summaries", StackName=stack_id)

    def _get_ledger(self, retirement_id: str) -> dict[str, Any] | None:
        _workforce_require(retirement_id == self.config.retirement_id)
        response = self.clients.dynamodb.get_item(TableName=self.config.ledger_table_name,
            Key={"retirement_id": {"S": retirement_id}}, ConsistentRead=True, ProjectionExpression="document")
        if "Item" not in response:
            return None
        item = response["Item"]
        _workforce_require(type(item) is dict and type(item.get("document")) is dict
                           and type(item["document"].get("S")) is str, "LEDGER_MALFORMED")
        # Foreign versions/modes are occupied keys, never absence or a reset.
        return self._validate_ledger(_workforce_json_object(item["document"]["S"]))

    def _create_ledger(self, ledger: Mapping[str, Any]) -> None:
        self.require_current()
        super()._create_ledger(ledger)

    def _transition(self, before: Mapping[str, Any], *, state: str, **updates: Any) -> dict[str, Any]:
        self.require_current(reconcile=state == "RETIRED_RECONCILED")
        return super()._transition(before, state=state, **updates)

    def _ledger_binding(self) -> dict[str, Any]:
        cfg = self.config
        return {
            "schema_version": "4", "record_type": "platform_authority_change_set_retirement_workforce_ledger",
            "environment": "production", "production": True, "destination_account_id": "905418363887",
            "authority_account_id_digest": secret_digest("authority_account_id", cfg.authority_account_id),
            "region": cfg.region, "stack_name": cfg.stack_name, "retirement_id": cfg.retirement_id,
            "stack_id_digest": secret_digest("stack_id", cfg.stack_id),
            "change_set_id_digest": secret_digest("change_set_id", cfg.change_set_id),
            "change_set_name_digest": secret_digest("change_set_name", cfg.change_set_name),
            "template_sha256": cfg.expected_template_sha256, "resource_inventory_sha256": cfg.expected_evidence_sha256,
            "identity_binding_digest": cfg.expected_digest, "single_operator_authorization_sha256": cfg.expected_digest,
            "owner_operator_id": cfg.owner_operator_id, "owner_subject_digest": cfg.owner_subject_digest,
            "classifier_identity_store_user_id_digest": cfg.owner_subject_digest,
            "approver_identity_store_user_id_digest": cfg.owner_subject_digest,
            "broker_code_sha256": cfg.expected_code_sha256, "broker_policy_sha256": cfg.expected_broker_policy_sha256,
            "broker_function_version_arn_digest": canonical_digest({"function_version_arn": cfg.version_arn}),
            "authorization_mode": WORKFORCE_RETIREMENT_MODE, "independent_approval_present": False,
            "two_human_status": "NOT_PROVEN", "identity_separation": "SINGLE_OWNER_DECLARED_NOT_INDEPENDENT",
            "human_authentication_evidence": "API_GATEWAY_IAM_EXCLUSIVE_USER_ASSIGNMENT",
            "evidence_digest_semantics": "VALIDATED_IAM_REQUEST_AND_PROTECTED_BINDING",
            "owner_subject_digest_semantics": "GUG215_IDENTITY_STORE_AND_OPAQUE_USER_V1",
            "aws_effect_principal": "BROKER_EXECUTION_ROLE", "native_on_behalf_of": False,
            "authorized_at": cfg.authorized_at, "not_before": cfg.not_before, "expires_at": cfg.expires_at,
        }

    def _base_ledger(self, evidence: Mapping[str, Any], identity_proof_sha256: str) -> dict[str, Any]:
        self._require_evidence_matches_ledger(self._ledger_binding(), evidence)
        timestamp = _timestamp(self._time())
        record = {**self._ledger_binding(), "state": "CLASSIFIED", "version": 1, "attempt_count": 0,
            "classifier_identity_proof_sha256": identity_proof_sha256, "approver_identity_proof_sha256": None,
            "reconciliation_identity_proof_sha256": None, "approval_digest": None, "attempt_digest": None,
            "verification_digest": None, "classified_at": timestamp, "approved_at": None, "attempted_at": None,
            "verified_at": None, "updated_at": timestamp, "effect_attribution": None,
            "next_required_control": "WORKFORCE_OWNER_REVIEW_REQUIRED"}
        record["ledger_digest"] = canonical_digest(record)
        return self._validate_ledger(record)

    def _validate_ledger(self, value: Mapping[str, Any]) -> dict[str, Any]:
        record = dict(value)
        mutable = {"state", "version", "attempt_count", "classifier_identity_proof_sha256",
            "approver_identity_proof_sha256", "reconciliation_identity_proof_sha256", "approval_digest",
            "attempt_digest", "verification_digest", "classified_at", "approved_at", "attempted_at",
            "verified_at", "updated_at", "effect_attribution", "next_required_control", "ledger_digest"}
        expected = self._ledger_binding()
        _workforce_require(set(record) == set(expected) | mutable, "LEDGER_MALFORMED")
        _workforce_require(all(record[key] == item for key, item in expected.items()), "LEDGER_BINDING_CHANGED")
        digest = record.pop("ledger_digest")
        _workforce_require(canonical_digest(record) == digest, "LEDGER_DIGEST_INVALID")
        record["ledger_digest"] = digest
        states = ("CLASSIFIED", "EXCEPTION_ACCEPTED", "ATTEMPTED", "RETIRED_RECONCILED")
        state = record["state"]
        _workforce_require(type(state) is str and state in states, "LEDGER_STATE_INVALID")
        index = states.index(state)
        _workforce_require(type(record["version"]) is int and record["version"] == index + 1
                           and type(record["attempt_count"]) is int and record["attempt_count"] == int(index >= 2), "LEDGER_STATE_INVALID")
        for name, present in (
            ("classifier_identity_proof_sha256", True), ("approver_identity_proof_sha256", index >= 1),
            ("reconciliation_identity_proof_sha256", index == 3), ("approval_digest", index >= 1),
            ("attempt_digest", index >= 2), ("verification_digest", index == 3),
        ):
            if present:
                _require_digest(record[name], "LEDGER_STATE_INVALID")
            else:
                _workforce_require(record[name] is None, "LEDGER_STATE_INVALID")
        times = []
        for i, name in enumerate(("classified_at", "approved_at", "attempted_at", "verified_at")):
            if i <= index:
                value = _parse_timestamp(record[name])
                _workforce_require(value >= self.config.parse_time(self.config.not_before), "LEDGER_TIME_INVALID")
                if i != 3:
                    _workforce_require(value < self.config.parse_time(self.config.expires_at), "LEDGER_TIME_INVALID")
                times.append(value)
            else:
                _workforce_require(record[name] is None, "LEDGER_TIME_INVALID")
        updated = _parse_timestamp(record["updated_at"])
        _workforce_require(times == sorted(times) and updated >= times[-1], "LEDGER_TIME_INVALID")
        if index != 3:
            _workforce_require(updated < self.config.parse_time(self.config.expires_at), "LEDGER_TIME_INVALID")
        controls = ({"WORKFORCE_OWNER_REVIEW_REQUIRED"}, {"ONE_SHOT_ATTEMPT_REQUIRED"},
                    {"READ_ONLY_RECONCILIATION_REQUIRED"},
                    {"WORKFORCE_RETIREMENT_ROLE_REVOCATION_REQUIRED", "WORKFORCE_PAB_AND_REVOCATION_REQUIRED"})
        _workforce_require(record["next_required_control"] in controls[index], "LEDGER_STATE_INVALID")
        _workforce_require(record["effect_attribution"] == ("BROKER_SERVICE_PRINCIPAL_AFTER_WORKFORCE_IAM" if index == 3 else None), "LEDGER_STATE_INVALID")
        return record
