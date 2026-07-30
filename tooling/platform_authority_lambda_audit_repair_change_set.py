"""Fail-closed GUG-221 CloudFormation Change Set handoff.

This module has two deliberately separate responsibilities:

* derive one private, create-only parameter handoff from a validated AWS
  Signer receipt plus a typed private deployment contract; and
* verify an already-created Change Set using read-only AWS APIs.

It never creates, executes, deletes, or retries a Change Set.  The parameter
handoff is evidence of deterministic derivation, not deployment authority.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
from typing import Any, Mapping, Sequence

from tooling.platform_authority_lambda_audit_repair_package import (
    SOURCE_PATHS,
    RepairPackageError,
    build_repair_package,
    canonical_json,
)
from tooling.platform_authority_lambda_audit_permission_set import (
    COLLECTOR_PERMISSION_SET_DESCRIPTION,
    COLLECTOR_PERMISSION_SET_NAME,
    EXPECTED_TAGS as GUG220_EXPECTED_TAGS,
    SESSION_DURATION as GUG220_SESSION_DURATION,
    validate_execution_ledger,
    validate_provisioning_intent,
    validate_provisioning_receipt,
)
from tooling.platform_authority_lambda_invocation_authority import (
    canonical_digest as prefixed_canonical_digest,
    digest_text,
)
from tooling.platform_authority_lambda_audit_repair_broker import (
    canonical_digest as plain_canonical_digest,
)
from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (
    BROKER_TOPOLOGY_SIGNATURE_ALGORITHM,
    PhaseBIdentityBinding,
    PhaseBPepError,
    calculate_broker_topology_sha256,
    canonical_digest as phase_b_canonical_digest,
)
from tooling.platform_authority_lambda_audit_repair_iam_verifier import (
    AwsIamEffectiveVerifier,
    expected_role_specs,
)
from tooling.platform_authority_lambda_audit_repair_signed_artifact import (
    build_signed_artifact_receipt_from_aws,
    validate_signed_artifact_receipt,
)


WORK_PACKAGE = "GUG-221"
AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
EXPECTED_PROFILE = "042360977644_ReadOnlyAccess"
EXPECTED_MANAGEMENT_PROFILE = "839393571433_ReadOnlyAccess"
STACK_NAME = "scanalyze-platform-authority-lambda-audit-repair-pep"
CHANGE_SET_NAME = "gug221-lambda-audit-repair-pep-create"
TEMPLATE_PATH = "bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml"
DELEGATION_STACK_NAME = "scanalyze-platform-authority-lambda-audit-repair-delegation"
DELEGATION_CHANGE_SET_NAME = "gug221-lambda-audit-repair-delegation-create"
DELEGATION_TEMPLATE_PATH = (
    "bootstrap/cfn-platform-authority-lambda-audit-repair-delegation.yaml"
)
DELEGATION_HANDOFF_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_delegation_parameters.v1"
)
PEP_HANDOFF_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_pep_parameters.v1"
)
DEPLOYMENT_CONTRACT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_deployment_contract.v1"
)
GUG220_EVIDENCE_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_gug220_evidence.v1"
)
DELEGATION_CHANGE_SET_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_delegation_change_set_receipt.v1"
)
DELEGATION_EXECUTION_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_delegation_execution_receipt.v1"
)
DELEGATION_LIVE_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_delegation_live_receipt.v1"
)
PEP_CHANGE_SET_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_pep_change_set_receipt.v1"
)
PEP_EXECUTION_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_pep_execution_receipt.v1"
)
PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_"
    "phase_b_identity_materialization_receipt.v1"
)
PHASE_B_PRECONDITION_HANDOFF_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_"
    "phase_b_precondition_parameters.v1"
)
PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_TYPE = (
    "scanalyze.platform_authority.lambda_audit_repair_"
    "phase_b_precondition_change_set_receipt.v1"
)
PHASE_B_PRECONDITION_STACK_NAME = (
    "scanalyze-platform-authority-gug221-phase-b-broker-pep"
)
PHASE_B_PRECONDITION_CHANGE_SET_NAME = (
    "gug221-phase-b-broker-pep-create"
)
PHASE_B_PRECONDITION_TEMPLATE_PATH = (
    "bootstrap/cfn-platform-authority-lambda-audit-repair-"
    "phase-b-broker-pep.yaml"
)
PHASE_B_BROKER_EXECUTION_ROLE_ARN = (
    "arn:aws:iam::042360977644:role/"
    "ScanalyzeGug221PhaseBBrokerExecution"
)
PHASE_B_LEDGER_TABLE_NAME = (
    "scanalyze-platform-authority-gug221-phase-b-execution-ledger"
)
PRODUCTION_STATUS = "NO-GO"
MAX_PRIVATE_JSON_BYTES = 128 * 1024
MAX_CHANGE_SET_PAGES = 100
ORGANIZATION_ACCOUNT_STATES = frozenset(
    {"PENDING_ACTIVATION", "ACTIVE", "SUSPENDED", "PENDING_CLOSURE", "CLOSED"}
)

SIGNED_PARAMETER_KEYS = (
    "SourceCommit",
    "ExpectedBoto3Version",
    "ExpectedBotocoreVersion",
    "RepairArtifactBucket",
    "RepairArtifactKey",
    "RepairArtifactVersion",
    "RepairArtifactCodeSha256",
    "ReconcileArtifactBucket",
    "ReconcileArtifactKey",
    "ReconcileArtifactVersion",
    "ReconcileArtifactCodeSha256",
    "SigningProfileVersionArn",
)
PRIVATE_PARAMETER_KEYS = (
    "AuthorityAccountId",
    "ManagementAccountId",
    "RepairId",
    "PrincipalId",
    "IdentityStoreId",
    "IdentityCenterInstanceArn",
    "CollectorPermissionSetArn",
    "RepairInvokerPermissionSetArn",
    "CollectorPolicyDigest",
    "RepairInvokerPolicyDigest",
    "OriginalGug220LedgerDigest",
    "ExpectedPermissionSetTagsJson",
    "RepairNotBefore",
    "RepairNotAfter",
    "CollectorSamlProviderArn",
    "IdentityCenterKmsMode",
    "IdentityCenterKmsKeyArn",
)
PARAMETER_KEYS = (
    "AuthorityAccountId",
    "ManagementAccountId",
    "SourceCommit",
    "RepairId",
    "PrincipalId",
    "IdentityStoreId",
    "IdentityCenterInstanceArn",
    "CollectorPermissionSetArn",
    "RepairInvokerPermissionSetArn",
    "CollectorPolicyDigest",
    "RepairInvokerPolicyDigest",
    "OriginalGug220LedgerDigest",
    "ExpectedPermissionSetTagsJson",
    "RepairNotBefore",
    "RepairNotAfter",
    "CollectorSamlProviderArn",
    "IdentityCenterKmsMode",
    "IdentityCenterKmsKeyArn",
    "ExpectedBoto3Version",
    "ExpectedBotocoreVersion",
    "RepairArtifactBucket",
    "RepairArtifactKey",
    "RepairArtifactVersion",
    "RepairArtifactCodeSha256",
    "ReconcileArtifactBucket",
    "ReconcileArtifactKey",
    "ReconcileArtifactVersion",
    "ReconcileArtifactCodeSha256",
    "SigningProfileVersionArn",
)
DELEGATION_PARAMETER_KEYS = (
    "ManagementAccountId",
    "AuthorityAccountId",
    "SourceCommit",
    "IdentityCenterInstanceArn",
    "IdentityStoreArn",
    "RepairPrincipalId",
    "RepairPrincipalUserArn",
    "AuditPermissionSetArn",
    "UseIdentityCenterCustomerManagedKms",
    "IdentityCenterKmsKeyArn",
)
PHASE_B_PRECONDITION_PARAMETER_KEYS = (
    "AuthorityAccountId",
    "ManagementAccountId",
    "IdentityCenterApplicationArn",
    "IdentityCenterInstanceArn",
    "IdentityStoreArn",
    "IdentityCenterRedirectUri",
    "OperatorIdentityStoreUserId",
    "InvokerPrincipalArn",
    "ExactStackArn",
    "ExactChangeSetArn",
    "ExactClientRequestToken",
    "ExactExecutionId",
    "ExecutionNotBefore",
    "ExecutionNotAfter",
    "PhaseBIntentDigest",
    "ChangeSetReceiptDigest",
    "TemplateDigest",
    "ParametersDigest",
    "ResourceInventoryDigest",
    "LedgerControlsDigest",
    "OauthStateDigest",
    "BrokerArtifactBucket",
    "BrokerArtifactKey",
    "BrokerArtifactVersion",
    "BrokerArtifactCodeSha256",
    "BrokerCodeSigningConfigArn",
    "RepairArtifactBucket",
    "RepairArtifactKey",
    "ReconcileArtifactBucket",
    "ReconcileArtifactKey",
    "InvokerPolicySha256",
    "BrokerPolicySha256",
    "ProofPolicySha256",
    "ApplicationActorPolicySha256",
    "BrokerTopologySigningKeyArn",
    "BrokerTopologySignatureAlgorithm",
    "ExpectedBrokerTopologySha256",
)
PHASE_B_PRECONDITION_POLICY_PATHS = {
    "InvokerPolicySha256": Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-invoker-role.json"
    ),
    "BrokerPolicySha256": Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-"
        "phase-b-broker-execution-role.json"
    ),
    "ProofPolicySha256": Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-proof-role.json"
    ),
    "ApplicationActorPolicySha256": Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-"
        "phase-b-application-actor-policy.json"
    ),
}
PHASE_B_PRECONDITION_RESOURCE_TYPES = {
    "PhaseBBrokerEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
    "PhaseBBrokerExecuteAlias": "AWS::Lambda::Alias",
    "PhaseBBrokerExecutionRole": "AWS::IAM::Role",
    "PhaseBBrokerFunction": "AWS::Lambda::Function",
    "PhaseBBrokerInvokePermission": "AWS::Lambda::Permission",
    "PhaseBBrokerLogGroup": "AWS::Logs::LogGroup",
    "PhaseBBrokerVersion": "AWS::Lambda::Version",
    "PhaseBExecutionLedger": "AWS::DynamoDB::Table",
    "PhaseBProofRole": "AWS::IAM::Role",
}
EXPECTED_CAPABILITIES = ("CAPABILITY_NAMED_IAM",)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPAIR_ID_RE = re.compile(r"^gug221-[0-9a-f]{64}$")
_PRINCIPAL_ID_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_STORE_ID_RE = re.compile(r"^d-[0-9a-f]{10}$")
_INSTANCE_ARN_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_PERMISSION_SET_ARN_RE = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}$"
)
_SAML_ARN_RE = re.compile(
    r"^arn:aws:iam::042360977644:saml-provider/"
    r"AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
)
_KMS_ARN_RE = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9a-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_MANAGEMENT_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::839393571433:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9a-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_MANAGEMENT_CREATOR_ARN_RE = re.compile(
    r"^arn:aws:sts::839393571433:assumed-role/"
    r"AWSReservedSSO_ScanalyzeFounderPepSeed_[0-9a-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_AUTHORITY_CREATOR_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeFounderBootstrapPlan_[0-9a-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_COLLECTOR_ROLE_NAME_RE = re.compile(
    rf"^AWSReservedSSO_{re.escape(COLLECTOR_PERMISSION_SET_NAME)}_"
    r"[0-9a-fA-F]{16}$"
)
_STACK_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:042360977644:stack/"
    rf"{re.escape(STACK_NAME)}/(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_CHANGE_SET_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
    rf"{re.escape(CHANGE_SET_NAME)}/(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_DELEGATION_STACK_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:839393571433:stack/"
    rf"{re.escape(DELEGATION_STACK_NAME)}/"
    rf"(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_DELEGATION_CHANGE_SET_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
    rf"{re.escape(DELEGATION_CHANGE_SET_NAME)}/"
    rf"(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_PHASE_B_PRECONDITION_STACK_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:042360977644:stack/"
    rf"{re.escape(PHASE_B_PRECONDITION_STACK_NAME)}/"
    rf"(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_PHASE_B_PRECONDITION_CHANGE_SET_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
    rf"{re.escape(PHASE_B_PRECONDITION_CHANGE_SET_NAME)}/"
    rf"(?P<uuid>[0-9a-fA-F]{{8}}-[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{4}}-"
    rf"[0-9a-fA-F]{{4}}-[0-9a-fA-F]{{12}})$"
)
_PHASE_B_POLICY_PLACEHOLDER_RE = re.compile(r"\$\{([a-z_]+)\}")
_PHASE_B_APPLICATION_ARN_RE = re.compile(
    r"^arn:aws:sso::839393571433:application/"
    r"ssoins-[A-Za-z0-9]{16}/apl-[A-Za-z0-9]{16}$"
)
_PHASE_B_IDENTITY_STORE_ARN_RE = re.compile(
    r"^arn:aws:identitystore::839393571433:identitystore/d-[0-9a-f]{10}$"
)
_PHASE_B_REDIRECT_URI_RE = re.compile(
    r"^http://127\.0\.0\.1:[1-9][0-9]{3,4}/callback$"
)
_PHASE_B_INVOKER_ARN_RE = re.compile(
    r"^arn:aws:iam::042360977644:role/aws-reserved/"
    r"sso\.amazonaws\.com/us-east-1/"
    r"AWSReservedSSO_ScanalyzeGug221PhaseBInvoker_[0-9a-f]{16}$"
)
_PHASE_B_CODE_SIGNING_CONFIG_ARN_RE = re.compile(
    r"^arn:aws:lambda:us-east-1:042360977644:"
    r"code-signing-config:csc-[A-Za-z0-9]{17}$"
)
_PHASE_B_TOPOLOGY_SIGNING_KEY_ARN_RE = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ChangeSetHandoffError(ValueError):
    """A stable fail-closed Change Set handoff violation."""


def _digest(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ChangeSetHandoffError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ChangeSetHandoffError(code) from exc
    if parsed.microsecond or parsed.utcoffset() is None:
        raise ChangeSetHandoffError(code)
    return parsed.astimezone(UTC)


def _strict_tags(value: Any, code: str) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or not value
        or len(value) > 50
        or any(
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(item, str)
            or not 1 <= len(item) <= 256
            for key, item in value.items()
        )
    ):
        raise ChangeSetHandoffError(code)
    return dict(sorted(value.items()))


def validate_deployment_contract(contract: Mapping[str, Any]) -> None:
    """Validate only non-GUG-220 operator choices.

    Principal, collector permission-set ARN, GUG-220 ledger digest, repair ID,
    and repair-invoker ARN are intentionally absent. They are derived from
    sealed evidence or live provider readback in their respective phases.
    """

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "authority_account_id",
        "management_account_id",
        "source_commit",
        "repair_not_before",
        "repair_not_after",
        "delegation_change_set_creator_arn",
        "delegation_change_set_executor_arn",
        "pep_change_set_creator_arn",
        "production_status",
    }
    if (
        not isinstance(contract, Mapping)
        or set(contract) != required
        or contract.get("artifact_type") != DEPLOYMENT_CONTRACT_TYPE
        or contract.get("schema_version") != 1
        or contract.get("work_package") != WORK_PACKAGE
        or contract.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or contract.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or contract.get("production_status") != PRODUCTION_STATUS
        or _COMMIT_RE.fullmatch(str(contract.get("source_commit"))) is None
        or _MANAGEMENT_CREATOR_ARN_RE.fullmatch(
            str(contract.get("delegation_change_set_creator_arn"))
        )
        is None
        or _MANAGEMENT_CREATOR_ARN_RE.fullmatch(
            str(contract.get("delegation_change_set_executor_arn"))
        )
        is None
        or _AUTHORITY_CREATOR_ARN_RE.fullmatch(
            str(contract.get("pep_change_set_creator_arn"))
        )
        is None
    ):
        raise ChangeSetHandoffError("DEPLOYMENT_CONTRACT_INVALID")
    not_before = _timestamp(
        contract.get("repair_not_before"), "DEPLOYMENT_CONTRACT_WINDOW_INVALID"
    )
    not_after = _timestamp(
        contract.get("repair_not_after"), "DEPLOYMENT_CONTRACT_WINDOW_INVALID"
    )
    if not not_before < not_after or (not_after - not_before).total_seconds() > 900:
        raise ChangeSetHandoffError("DEPLOYMENT_CONTRACT_WINDOW_INVALID")


def _phase_b_identity_materialization_receipt_digest(
    receipt: Mapping[str, Any],
) -> str:
    return _digest(
        {
            key: value
            for key, value in receipt.items()
            if key != "receipt_sha256"
        }
    )


def validate_phase_b_identity_materialization_receipt(
    receipt: Mapping[str, Any],
    *,
    source_commit: str,
) -> None:
    """Validate provider-derived identity inputs before any PEP handoff.

    This receipt is deliberately an input-only contract.  This module has no
    producer for it: a synthetic or operator-authored document cannot establish
    that Identity Center, the application assignment, the invoker role, code
    signing configuration, and topology signing key exist in provider state.
    """

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "phase",
        "source_commit",
        "authority_account_id",
        "management_account_id",
        "region",
        "identity_center_application_arn",
        "identity_center_instance_arn",
        "identity_store_arn",
        "identity_center_redirect_uri",
        "operator_identity_store_user_id",
        "invoker_principal_arn",
        "broker_code_signing_config_arn",
        "broker_topology_signing_key_arn",
        "oauth_state_digest",
        "provider_state_sha256",
        "checks",
        "verifiers",
        "evaluated_at",
        "evidence_status",
        "authority_status",
        "production_status",
        "receipt_sha256",
    }
    checks = receipt.get("checks")
    verifiers = receipt.get("verifiers")
    expected_checks = {
        "application_verified": True,
        "single_operator_assignment_verified": True,
        "invoker_role_verified": True,
        "code_signing_config_verified": True,
        "topology_signing_key_verified": True,
        "pending_operations_absent": True,
        "alternate_assignments_absent": True,
    }
    expected_verifier_keys = {"management", "authority"}
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type")
        != PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "PRE_B_IDENTITY_MATERIALIZATION"
        or receipt.get("source_commit") != source_commit
        or receipt.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or receipt.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or receipt.get("region") != REGION
        or _PHASE_B_APPLICATION_ARN_RE.fullmatch(
            str(receipt.get("identity_center_application_arn"))
        )
        is None
        or _INSTANCE_ARN_RE.fullmatch(
            str(receipt.get("identity_center_instance_arn"))
        )
        is None
        or _PHASE_B_IDENTITY_STORE_ARN_RE.fullmatch(
            str(receipt.get("identity_store_arn"))
        )
        is None
        or _PHASE_B_REDIRECT_URI_RE.fullmatch(
            str(receipt.get("identity_center_redirect_uri"))
        )
        is None
        or _PRINCIPAL_ID_RE.fullmatch(
            str(receipt.get("operator_identity_store_user_id"))
        )
        is None
        or _PHASE_B_INVOKER_ARN_RE.fullmatch(
            str(receipt.get("invoker_principal_arn"))
        )
        is None
        or _PHASE_B_CODE_SIGNING_CONFIG_ARN_RE.fullmatch(
            str(receipt.get("broker_code_signing_config_arn"))
        )
        is None
        or _PHASE_B_TOPOLOGY_SIGNING_KEY_ARN_RE.fullmatch(
            str(receipt.get("broker_topology_signing_key_arn"))
        )
        is None
        or _PREFIXED_DIGEST_RE.fullmatch(
            str(receipt.get("oauth_state_digest"))
        )
        is None
        or _DIGEST_RE.fullmatch(
            str(receipt.get("provider_state_sha256"))
        )
        is None
        or checks != expected_checks
        or not isinstance(verifiers, Mapping)
        or set(verifiers) != expected_verifier_keys
        or receipt.get("evidence_status")
        != "PHASE_B_IDENTITY_MATERIALIZATION_PROVIDER_VERIFIED"
        or receipt.get("authority_status")
        != "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("receipt_sha256")
        != _phase_b_identity_materialization_receipt_digest(receipt)
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_INVALID"
        )
    for name, account_id, profile, caller_pattern in (
        (
            "management",
            MANAGEMENT_ACCOUNT_ID,
            EXPECTED_MANAGEMENT_PROFILE,
            _MANAGEMENT_CALLER_ARN_RE,
        ),
        ("authority", AUTHORITY_ACCOUNT_ID, EXPECTED_PROFILE, _CALLER_ARN_RE),
    ):
        verifier = verifiers.get(name)
        if (
            not isinstance(verifier, Mapping)
            or set(verifier) != {"profile", "account_id", "caller_arn"}
            or verifier.get("profile") != profile
            or verifier.get("account_id") != account_id
            or caller_pattern.fullmatch(str(verifier.get("caller_arn"))) is None
        ):
            raise ChangeSetHandoffError(
                "PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_INVALID"
            )
    _timestamp(
        receipt.get("evaluated_at"),
        "PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_TIME_INVALID",
    )
    # Shape and self-digest prove only that the target contract is well formed.
    # No live producer currently emits a KMS-authenticated receipt and this
    # module deliberately has no direct provider revalidation path.  Therefore
    # even a structurally valid document is not authorization to build the PEP
    # or PRE_B handoffs.
    raise ChangeSetHandoffError(
        "BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED"
    )


def _permission_set_tags(source_commit: str) -> dict[str, str]:
    return {
        "environment": "non-production",
        "managed_by": "cloudformation",
        "production": "false",
        "service": "scanalyze-platform-authority",
        "source_commit": source_commit,
        "work_package": WORK_PACKAGE,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reviewed_git_object_bytes(
    *,
    source_root: Path,
    source_commit: str,
    relative_path: str,
    error_code: str,
    allow_empty: bool = False,
) -> bytes:
    """Read immutable reviewed bytes from the exact Git object, never the worktree."""

    candidate = Path(relative_path)
    if (
        _COMMIT_RE.fullmatch(source_commit) is None
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != relative_path
    ):
        raise ChangeSetHandoffError(error_code)
    try:
        result = subprocess.run(
            ["git", "show", f"{source_commit}:{relative_path}"],
            cwd=source_root,
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ChangeSetHandoffError(error_code) from exc
    if not result.stdout and not allow_empty:
        raise ChangeSetHandoffError(error_code)
    return result.stdout


def _reviewed_policy_object(
    *, source_root: Path, source_commit: str, relative_path: Path
) -> Mapping[str, Any]:
    raw = _reviewed_git_object_bytes(
        source_root=source_root,
        source_commit=source_commit,
        relative_path=relative_path.as_posix(),
        error_code="REVIEWED_IAM_POLICY_UNAVAILABLE",
    )
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ChangeSetHandoffError("REVIEWED_IAM_POLICY_INVALID") from exc
    if not isinstance(value, Mapping):
        raise ChangeSetHandoffError("REVIEWED_IAM_POLICY_INVALID")
    return value


def _repair_invoker_policy(
    source_root: Path, source_commit: str
) -> Mapping[str, Any]:
    return _reviewed_policy_object(
        source_root=source_root,
        source_commit=source_commit,
        relative_path=Path(
            "policies/iam/platform-authority-lambda-audit-repair-invoker-role.json"
        ),
    )


def _repair_id(
    *, intent: Mapping[str, Any], ledger: Mapping[str, Any], receipt: Mapping[str, Any]
) -> str:
    sealed = {
        "work_package": WORK_PACKAGE,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "region": REGION,
        "intent_digest": intent["intent_digest"],
        "ledger_digest": ledger["ledger_digest"],
        "receipt_digest": receipt["receipt_digest"],
    }
    return "gug221-" + sha256(canonical_json(sealed).encode("utf-8")).hexdigest()


def _gug220_ledger_parameter_digest(value: str) -> str:
    """Normalize the typed GUG-220 digest only at the CFN/broker boundary."""

    if _PREFIXED_DIGEST_RE.fullmatch(value) is None:
        raise ChangeSetHandoffError("GUG220_LEDGER_DIGEST_INVALID")
    normalized = value.removeprefix("sha256:")
    if _DIGEST_RE.fullmatch(normalized) is None:
        raise ChangeSetHandoffError("GUG220_LEDGER_DIGEST_INVALID")
    return normalized


def _validate_gug220_consumed_chain(
    *,
    source_root: Path,
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    """Validate the immutable GUG-220 chain before any provider revelation."""

    try:
        validated_intent = validate_provisioning_intent(
            intent, repo_root=source_root
        )
        validated_ledger = validate_execution_ledger(
            ledger, intent=validated_intent
        )
        validated_receipt = validate_provisioning_receipt(
            receipt, intent=validated_intent
        )
    except ValueError as exc:
        raise ChangeSetHandoffError("GUG220_EVIDENCE_CHAIN_INVALID") from exc
    expected_tags_digest = prefixed_canonical_digest(GUG220_EXPECTED_TAGS)
    permission_set_digest = validated_receipt.get("permission_set_arn_digest")
    if (
        validated_ledger.get("status") != "MUTATION_WINDOW_CONSUMED"
        or validated_ledger.get("mutation_attempt_limit") != 1
        or validated_ledger.get("mutation_retry_authorized") is not False
        or validated_receipt.get("status") != "UNCERTAIN_RECONCILE_ONLY"
        or validated_receipt.get("aws_mutation_attempted") is not True
        or validated_receipt.get("ambiguous_response") is not True
        or validated_receipt.get("mutation_retry_attempted") is not False
        or not isinstance(permission_set_digest, str)
        or _PREFIXED_DIGEST_RE.fullmatch(permission_set_digest) is None
        or validated_intent.get("expected_tags_digest") != expected_tags_digest
    ):
        raise ChangeSetHandoffError("GUG220_CONSUMED_CHAIN_INVALID")
    return validated_intent, validated_ledger, validated_receipt


def validate_gug220_evidence_chain(
    *,
    source_root: Path,
    deployment_contract: Mapping[str, Any],
    intent: Mapping[str, Any],
    ledger: Mapping[str, Any],
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> Mapping[str, str]:
    """Validate a provider-produced GUG-220 live readback receipt.

    This validator is not an authority boundary on its own.  Every Change Set
    verifier performs a fresh provider readback and requires canonical equality
    with this create-only private receipt in the same invocation.
    """

    validate_deployment_contract(deployment_contract)
    validated_intent, validated_ledger, validated_receipt = (
        _validate_gug220_consumed_chain(
            source_root=source_root,
            intent=intent,
            ledger=ledger,
            receipt=receipt,
        )
    )
    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "gug220_intent_digest",
        "gug220_ledger_digest",
        "gug220_receipt_digest",
        "management_account_id",
        "authority_account_id",
        "region",
        "identity_center_instance_arn",
        "identity_store_id",
        "collector_saml_provider_arn",
        "identity_center_kms_mode",
        "identity_center_kms_key_arn",
        "principal_id",
        "collector_permission_set_arn",
        "collector_permission_set_exists",
        "collector_inline_policy_present",
        "collector_account_assignments",
        "collector_provisioned_account_ids",
        "collector_role_present",
        "instance_metadata_sha256",
        "principal_metadata_sha256",
        "saml_provider_metadata_sha256",
        "collector_permission_set_metadata_sha256",
        "collector_permission_set_tags_sha256",
        "provider_state_sha256",
        "verifiers",
        "evaluated_at",
        "evidence_status",
        "authority_status",
        "production_status",
        "evidence_digest",
    }
    if not isinstance(evidence, Mapping) or set(evidence) != required:
        raise ChangeSetHandoffError("GUG220_EVIDENCE_SHAPE_INVALID")
    principal_id = str(evidence.get("principal_id"))
    collector_arn = str(evidence.get("collector_permission_set_arn"))
    verifiers = evidence.get("verifiers")
    stable = {key: value for key, value in evidence.items() if key != "evidence_digest"}
    kms_mode = evidence.get("identity_center_kms_mode")
    kms_key = evidence.get("identity_center_kms_key_arn")
    digest_fields = (
        "instance_metadata_sha256",
        "principal_metadata_sha256",
        "saml_provider_metadata_sha256",
        "collector_permission_set_metadata_sha256",
        "collector_permission_set_tags_sha256",
        "provider_state_sha256",
    )
    if (
        evidence.get("artifact_type") != GUG220_EVIDENCE_TYPE
        or evidence.get("schema_version") != 1
        or evidence.get("work_package") != WORK_PACKAGE
        or evidence.get("gug220_intent_digest") != validated_intent["intent_digest"]
        or evidence.get("gug220_ledger_digest") != validated_ledger["ledger_digest"]
        or evidence.get("gug220_receipt_digest") != validated_receipt["receipt_digest"]
        or evidence.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or evidence.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or evidence.get("region") != REGION
        or _INSTANCE_ARN_RE.fullmatch(
            str(evidence.get("identity_center_instance_arn"))
        )
        is None
        or _STORE_ID_RE.fullmatch(str(evidence.get("identity_store_id"))) is None
        or _SAML_ARN_RE.fullmatch(
            str(evidence.get("collector_saml_provider_arn"))
        )
        is None
        or kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or (kms_mode == "AWS_OWNED_KMS_KEY" and kms_key is not None)
        or (
            kms_mode == "CUSTOMER_MANAGED_KEY"
            and _KMS_ARN_RE.fullmatch(str(kms_key)) is None
        )
        or _PRINCIPAL_ID_RE.fullmatch(principal_id) is None
        or _PERMISSION_SET_ARN_RE.fullmatch(collector_arn) is None
        or digest_text(principal_id) != validated_intent["principal_id_digest"]
        or digest_text(collector_arn)
        != validated_receipt["permission_set_arn_digest"]
        or digest_text(str(evidence["identity_center_instance_arn"]))
        != validated_intent["identity_center_instance_arn_digest"]
        or digest_text(str(evidence["identity_store_id"]))
        != validated_intent["identity_store_id_digest"]
        or digest_text(str(evidence["collector_saml_provider_arn"]))
        != validated_intent["saml_provider_arn_digest"]
        or evidence.get("collector_permission_set_exists") is not True
        or evidence.get("collector_inline_policy_present") is not False
        or evidence.get("collector_account_assignments") != []
        or evidence.get("collector_provisioned_account_ids") != []
        or evidence.get("collector_role_present") is not False
        or evidence.get("evidence_status")
        != "GUG220_PARTIAL_STATE_READ_ONLY_RECONCILED"
        or evidence.get("authority_status")
        != "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY"
        or evidence.get("production_status") != PRODUCTION_STATUS
        or any(_DIGEST_RE.fullmatch(str(evidence.get(field))) is None for field in digest_fields)
        or not isinstance(verifiers, Mapping)
        or set(verifiers) != {"management", "authority"}
        or not isinstance(verifiers.get("management"), Mapping)
        or verifiers["management"].get("account_id") != MANAGEMENT_ACCOUNT_ID
        or verifiers["management"].get("profile") != EXPECTED_MANAGEMENT_PROFILE
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(
            str(verifiers["management"].get("caller_arn"))
        )
        is None
        or not isinstance(verifiers.get("authority"), Mapping)
        or verifiers["authority"].get("account_id") != AUTHORITY_ACCOUNT_ID
        or verifiers["authority"].get("profile") != EXPECTED_PROFILE
        or _CALLER_ARN_RE.fullmatch(
            str(verifiers["authority"].get("caller_arn"))
        )
        is None
        or evidence.get("evidence_digest") != prefixed_canonical_digest(stable)
    ):
        raise ChangeSetHandoffError("GUG220_EVIDENCE_BINDING_INVALID")
    _timestamp(evidence.get("evaluated_at"), "GUG220_EVIDENCE_TIME_INVALID")
    return {
        "principal_id": principal_id,
        "collector_permission_set_arn": collector_arn,
        "collector_policy_digest": str(
            validated_intent["collector_inline_policy_digest"]
        ).removeprefix("sha256:"),
        "original_gug220_ledger_digest": str(validated_ledger["ledger_digest"]),
        "identity_center_instance_arn": str(
            evidence["identity_center_instance_arn"]
        ),
        "identity_store_id": str(evidence["identity_store_id"]),
        "collector_saml_provider_arn": str(
            evidence["collector_saml_provider_arn"]
        ),
        "identity_center_kms_mode": str(evidence["identity_center_kms_mode"]),
        "identity_center_kms_key_arn": str(kms_key or ""),
        "repair_id": _repair_id(
            intent=validated_intent,
            ledger=validated_ledger,
            receipt=validated_receipt,
        ),
    }


def _provider_tags(value: Any, code: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise ChangeSetHandoffError(code)
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not isinstance(item.get("Value"), str)
            or item["Key"] in result
        ):
            raise ChangeSetHandoffError(code)
        result[item["Key"]] = item["Value"]
    return dict(sorted(result.items()))


def _paginate_iam_marker(
    client: Any, method_name: str, result_key: str, **kwargs: Any
) -> list[Any]:
    values: list[Any] = []
    marker: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request = dict(kwargs)
        if marker is not None:
            request["Marker"] = marker
        response = _aws_call(getattr(client, method_name), **request)
        page = response.get(result_key)
        if not isinstance(page, list):
            raise ChangeSetHandoffError("PROVIDER_PAGINATION_INVALID")
        values.extend(page)
        truncated = response.get("IsTruncated", False)
        next_marker = response.get("Marker")
        if truncated is False:
            if next_marker not in (None, ""):
                raise ChangeSetHandoffError("PROVIDER_PAGINATION_INVALID")
            return values
        if (
            truncated is not True
            or not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen
        ):
            raise ChangeSetHandoffError("PROVIDER_PAGINATION_INVALID")
        seen.add(next_marker)
        marker = next_marker
    raise ChangeSetHandoffError("PROVIDER_PAGINATION_EXCEEDED")


def _gug220_pending_operations(
    *, sso_admin_client: Any, instance_arn: str
) -> Mapping[str, list[Any]]:
    return {
        "assignment_creations": _paginate_next_token(
            sso_admin_client,
            "list_account_assignment_creation_status",
            "AccountAssignmentsCreationStatus",
            InstanceArn=instance_arn,
            Filter={"Status": "IN_PROGRESS"},
        ),
        "assignment_deletions": _paginate_next_token(
            sso_admin_client,
            "list_account_assignment_deletion_status",
            "AccountAssignmentsDeletionStatus",
            InstanceArn=instance_arn,
            Filter={"Status": "IN_PROGRESS"},
        ),
        "permission_set_provisioning": _paginate_next_token(
            sso_admin_client,
            "list_permission_set_provisioning_status",
            "PermissionSetsProvisioningStatus",
            InstanceArn=instance_arn,
            Filter={"Status": "IN_PROGRESS"},
        ),
    }


def collect_gug220_live_evidence_read_only(
    *,
    source_root: Path,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    management_profile_name: str,
    authority_profile_name: str,
    region: str,
    management_sts_client: Any,
    management_sso_admin_client: Any,
    management_identitystore_client: Any,
    management_kms_client: Any,
    management_organizations_client: Any,
    authority_sts_client: Any,
    authority_iam_client: Any,
    now: datetime | None = None,
    _single_snapshot: bool = False,
) -> Mapping[str, Any]:
    """Enumerate the exact GUG-220 partial state using read-only APIs only."""

    if not _single_snapshot:
        arguments = {
            "source_root": source_root,
            "deployment_contract": deployment_contract,
            "gug220_intent": gug220_intent,
            "gug220_ledger": gug220_ledger,
            "gug220_receipt": gug220_receipt,
            "management_profile_name": management_profile_name,
            "authority_profile_name": authority_profile_name,
            "region": region,
            "management_sts_client": management_sts_client,
            "management_sso_admin_client": management_sso_admin_client,
            "management_identitystore_client": management_identitystore_client,
            "management_kms_client": management_kms_client,
            "management_organizations_client": management_organizations_client,
            "authority_sts_client": authority_sts_client,
            "authority_iam_client": authority_iam_client,
            "now": now,
            "_single_snapshot": True,
        }
        first = collect_gug220_live_evidence_read_only(**arguments)
        second = collect_gug220_live_evidence_read_only(**arguments)
        if first["provider_state_sha256"] != second["provider_state_sha256"]:
            raise ChangeSetHandoffError("GUG220_PROVIDER_STATE_CHANGED_DURING_READBACK")
        return second

    validate_deployment_contract(deployment_contract)
    intent, ledger, receipt = _validate_gug220_consumed_chain(
        source_root=source_root,
        intent=gug220_intent,
        ledger=gug220_ledger,
        receipt=gug220_receipt,
    )
    if (
        management_profile_name != EXPECTED_MANAGEMENT_PROFILE
        or authority_profile_name != EXPECTED_PROFILE
        or region != REGION
    ):
        raise ChangeSetHandoffError("GUG220_PROVIDER_PROFILE_OR_REGION_INVALID")
    management_identity = _aws_call(management_sts_client.get_caller_identity)
    authority_identity = _aws_call(authority_sts_client.get_caller_identity)
    if (
        management_identity.get("Account") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(
            str(management_identity.get("Arn"))
        )
        is None
        or authority_identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(authority_identity.get("Arn"))) is None
    ):
        raise ChangeSetHandoffError("GUG220_PROVIDER_IDENTITY_INVALID")

    instances = _paginate_next_token(
        management_sso_admin_client, "list_instances", "Instances"
    )
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("InstanceArn"), str)
        or not isinstance(item.get("IdentityStoreId"), str)
        or not isinstance(item.get("OwnerAccountId"), str)
        or not isinstance(item.get("Status"), str)
        for item in instances
    ):
        raise ChangeSetHandoffError("GUG220_INSTANCE_ENUMERATION_MALFORMED")
    instance_matches = [
        item
        for item in instances
        if isinstance(item, Mapping)
        and digest_text(str(item.get("InstanceArn")))
        == intent["identity_center_instance_arn_digest"]
        and digest_text(str(item.get("IdentityStoreId")))
        == intent["identity_store_id_digest"]
    ]
    if len(instance_matches) != 1:
        raise ChangeSetHandoffError("GUG220_INSTANCE_NOT_UNIQUE")
    instance_summary = instance_matches[0]
    instance_arn = str(instance_summary.get("InstanceArn"))
    identity_store_id = str(instance_summary.get("IdentityStoreId"))
    pending_before = _gug220_pending_operations(
        sso_admin_client=management_sso_admin_client,
        instance_arn=instance_arn,
    )
    if any(pending_before.values()):
        raise ChangeSetHandoffError("GUG220_PENDING_OPERATION_PRESENT")
    instance = _aws_call(
        management_sso_admin_client.describe_instance, InstanceArn=instance_arn
    )
    encryption = instance.get("EncryptionConfigurationDetails")
    if (
        _INSTANCE_ARN_RE.fullmatch(instance_arn) is None
        or _STORE_ID_RE.fullmatch(identity_store_id) is None
        or instance.get("InstanceArn") != instance_arn
        or instance.get("IdentityStoreId") != identity_store_id
        or instance.get("OwnerAccountId") != MANAGEMENT_ACCOUNT_ID
        or instance.get("Status") != "ACTIVE"
        or not isinstance(encryption, Mapping)
        or encryption.get("EncryptionStatus") != "ENABLED"
        or encryption.get("EncryptionStatusReason") not in (None, "")
    ):
        raise ChangeSetHandoffError("GUG220_INSTANCE_DRIFT")
    kms_mode = encryption.get("KeyType")
    kms_key = encryption.get("KmsKeyArn")
    if (
        kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or (kms_mode == "AWS_OWNED_KMS_KEY" and kms_key not in (None, ""))
        or (
            kms_mode == "CUSTOMER_MANAGED_KEY"
            and _KMS_ARN_RE.fullmatch(str(kms_key)) is None
        )
    ):
        raise ChangeSetHandoffError("GUG220_INSTANCE_KMS_DRIFT")
    kms_key = None if kms_mode == "AWS_OWNED_KMS_KEY" else str(kms_key)
    kms_snapshot: Mapping[str, Any] | None = None
    if kms_mode == "CUSTOMER_MANAGED_KEY":
        kms_response = _aws_call(management_kms_client.describe_key, KeyId=kms_key)
        metadata = kms_response.get("KeyMetadata")
        kms_snapshot = {
            "Arn": kms_key,
            "AWSAccountId": MANAGEMENT_ACCOUNT_ID,
            "Enabled": True,
            "KeyManager": "CUSTOMER",
            "KeyState": "Enabled",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Origin": "AWS_KMS",
            "MultiRegion": False,
        }
        if not isinstance(metadata, Mapping) or any(
            metadata.get(key) != value for key, value in kms_snapshot.items()
        ):
            raise ChangeSetHandoffError("GUG220_INSTANCE_KMS_KEY_DRIFT")
    instance_snapshot = {
        "InstanceArn": instance_arn,
        "IdentityStoreId": identity_store_id,
        "OwnerAccountId": MANAGEMENT_ACCOUNT_ID,
        "Status": "ACTIVE",
        "EncryptionConfigurationDetails": {
            "KeyType": kms_mode,
            "KmsKeyArn": kms_key,
            "EncryptionStatus": "ENABLED",
        },
    }

    users = _paginate_next_token(
        management_identitystore_client,
        "list_users",
        "Users",
        IdentityStoreId=identity_store_id,
    )
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("UserId"), str)
        for item in users
    ):
        raise ChangeSetHandoffError("GUG220_PRINCIPAL_ENUMERATION_MALFORMED")
    principal_matches = [
        item
        for item in users
        if isinstance(item, Mapping)
        and isinstance(item.get("UserId"), str)
        and digest_text(item["UserId"]) == intent["principal_id_digest"]
    ]
    if len(principal_matches) != 1:
        raise ChangeSetHandoffError("GUG220_PRINCIPAL_NOT_UNIQUE")
    principal_id = str(principal_matches[0]["UserId"])
    principal = _aws_call(
        management_identitystore_client.describe_user,
        IdentityStoreId=identity_store_id,
        UserId=principal_id,
    )
    if (
        _PRINCIPAL_ID_RE.fullmatch(principal_id) is None
        or principal.get("UserId") != principal_id
    ):
        raise ChangeSetHandoffError("GUG220_PRINCIPAL_DRIFT")
    principal_snapshot = {"IdentityStoreId": identity_store_id, "UserId": principal_id}

    permission_set_arns = _paginate_next_token(
        management_sso_admin_client,
        "list_permission_sets",
        "PermissionSets",
        InstanceArn=instance_arn,
    )
    if any(
        not isinstance(arn, str) or _PERMISSION_SET_ARN_RE.fullmatch(arn) is None
        for arn in permission_set_arns
    ):
        raise ChangeSetHandoffError("GUG220_PERMISSION_SET_ENUMERATION_MALFORMED")
    collector_matches = [
        arn
        for arn in permission_set_arns
        if isinstance(arn, str)
        and digest_text(arn) == receipt["permission_set_arn_digest"]
    ]
    if len(collector_matches) != 1:
        raise ChangeSetHandoffError("GUG220_COLLECTOR_NOT_UNIQUE")
    collector_arn = collector_matches[0]
    permission_set_response = _aws_call(
        management_sso_admin_client.describe_permission_set,
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    )
    permission_set = permission_set_response.get("PermissionSet")
    permission_set_snapshot = {
        "PermissionSetArn": collector_arn,
        "Name": COLLECTOR_PERMISSION_SET_NAME,
        "Description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
        "SessionDuration": GUG220_SESSION_DURATION,
        "RelayState": None,
    }
    if (
        _PERMISSION_SET_ARN_RE.fullmatch(collector_arn) is None
        or not isinstance(permission_set, Mapping)
        or any(
            permission_set.get(key) != value
            for key, value in permission_set_snapshot.items()
        )
    ):
        raise ChangeSetHandoffError("GUG220_COLLECTOR_METADATA_DRIFT")
    tags = _paginate_next_token(
        management_sso_admin_client,
        "list_tags_for_resource",
        "Tags",
        InstanceArn=instance_arn,
        ResourceArn=collector_arn,
    )
    normalized_tags = _provider_tags(tags, "GUG220_COLLECTOR_TAG_DRIFT")
    if normalized_tags != dict(sorted(GUG220_EXPECTED_TAGS.items())):
        raise ChangeSetHandoffError("GUG220_COLLECTOR_TAG_DRIFT")
    inline_policy = _aws_call(
        management_sso_admin_client.get_inline_policy_for_permission_set,
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    ).get("InlinePolicy")
    managed = _paginate_next_token(
        management_sso_admin_client,
        "list_managed_policies_in_permission_set",
        "AttachedManagedPolicies",
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    )
    customer_managed = _paginate_next_token(
        management_sso_admin_client,
        "list_customer_managed_policy_references_in_permission_set",
        "CustomerManagedPolicyReferences",
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    )
    boundary = _aws_call(
        management_sso_admin_client.get_permissions_boundary_for_permission_set,
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    ).get("PermissionsBoundary")
    organization_accounts = _paginate_next_token(
        management_organizations_client, "list_accounts", "Accounts"
    )
    if any(
        not isinstance(account, Mapping)
        or re.fullmatch(r"[0-9]{12}", str(account.get("Id"))) is None
        or account.get("State") not in ORGANIZATION_ACCOUNT_STATES
        for account in organization_accounts
    ):
        raise ChangeSetHandoffError("GUG220_ORGANIZATION_ACCOUNT_ENUMERATION_MALFORMED")
    assignments: list[Any] = []
    for account_id in sorted(str(item["Id"]) for item in organization_accounts):
        assignments.extend(
            _paginate_next_token(
                management_sso_admin_client,
                "list_account_assignments",
                "AccountAssignments",
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=collector_arn,
            )
        )
    provisioned = _paginate_next_token(
        management_sso_admin_client,
        "list_accounts_for_provisioned_permission_set",
        "AccountIds",
        InstanceArn=instance_arn,
        PermissionSetArn=collector_arn,
    )
    pending_after = _gug220_pending_operations(
        sso_admin_client=management_sso_admin_client,
        instance_arn=instance_arn,
    )
    if (
        inline_policy not in (None, "")
        or managed != []
        or customer_managed != []
        or boundary not in (None, {})
        or assignments != []
        or provisioned != []
        or any(pending_after.values())
        or pending_before != pending_after
    ):
        raise ChangeSetHandoffError("GUG220_PARTIAL_STATE_DRIFT")

    saml_providers = _paginate_iam_marker(
        authority_iam_client, "list_saml_providers", "SAMLProviderList"
    )
    if any(
        not isinstance(item, Mapping)
        or re.fullmatch(
            rf"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:saml-provider/[A-Za-z0-9+=,.@_/-]+",
            str(item.get("Arn")),
        )
        is None
        for item in saml_providers
    ):
        raise ChangeSetHandoffError("GUG220_SAML_PROVIDER_ENUMERATION_MALFORMED")
    saml_matches = [
        str(item.get("Arn"))
        for item in saml_providers
        if isinstance(item, Mapping)
        and isinstance(item.get("Arn"), str)
        and digest_text(item["Arn"]) == intent["saml_provider_arn_digest"]
    ]
    if len(saml_matches) != 1 or _SAML_ARN_RE.fullmatch(saml_matches[0]) is None:
        raise ChangeSetHandoffError("GUG220_SAML_PROVIDER_NOT_UNIQUE")
    saml_provider_arn = saml_matches[0]
    saml_provider = _aws_call(
        authority_iam_client.get_saml_provider,
        SAMLProviderArn=saml_provider_arn,
    )
    saml_document = saml_provider.get("SAMLMetadataDocument")
    if not isinstance(saml_document, str) or not saml_document:
        raise ChangeSetHandoffError("GUG220_SAML_PROVIDER_DRIFT")
    saml_snapshot = {
        "Arn": saml_provider_arn,
        "SAMLMetadataDocumentSha256": sha256(
            saml_document.encode("utf-8")
        ).hexdigest(),
    }
    roles = _paginate_iam_marker(
        authority_iam_client,
        "list_roles",
        "Roles",
        PathPrefix="/aws-reserved/sso.amazonaws.com/",
    )
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("RoleName"), str)
        for item in roles
    ):
        raise ChangeSetHandoffError("GUG220_ROLE_ENUMERATION_MALFORMED")
    collector_roles = [
        item
        for item in roles
        if isinstance(item, Mapping)
        and _COLLECTOR_ROLE_NAME_RE.fullmatch(str(item.get("RoleName"))) is not None
    ]
    if collector_roles:
        raise ChangeSetHandoffError("GUG220_COLLECTOR_ROLE_PRESENT")

    provider_state = {
        "instance": instance_snapshot,
        "principal": principal_snapshot,
        "saml_provider_arn": saml_provider_arn,
        "saml_provider": saml_snapshot,
        "identity_center_kms_key": kms_snapshot,
        "collector_permission_set": permission_set_snapshot,
        "collector_tags": normalized_tags,
        "collector_inline_policy_present": False,
        "collector_managed_policies": [],
        "collector_customer_managed_policy_references": [],
        "collector_permissions_boundary": None,
        "collector_account_assignments": [],
        "collector_provisioned_account_ids": [],
        "pending_operations_before": pending_before,
        "pending_operations_after": pending_after,
        "collector_roles": [],
    }
    evidence: dict[str, Any] = {
        "artifact_type": GUG220_EVIDENCE_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "gug220_intent_digest": intent["intent_digest"],
        "gug220_ledger_digest": ledger["ledger_digest"],
        "gug220_receipt_digest": receipt["receipt_digest"],
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "identity_center_instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "collector_saml_provider_arn": saml_provider_arn,
        "identity_center_kms_mode": kms_mode,
        "identity_center_kms_key_arn": kms_key,
        "principal_id": principal_id,
        "collector_permission_set_arn": collector_arn,
        "collector_permission_set_exists": True,
        "collector_inline_policy_present": False,
        "collector_account_assignments": [],
        "collector_provisioned_account_ids": [],
        "collector_role_present": False,
        "instance_metadata_sha256": _digest(instance_snapshot),
        "principal_metadata_sha256": _digest(principal_snapshot),
        "saml_provider_metadata_sha256": _digest(saml_snapshot),
        "collector_permission_set_metadata_sha256": _digest(
            permission_set_snapshot
        ),
        "collector_permission_set_tags_sha256": _digest(normalized_tags),
        "provider_state_sha256": _digest(provider_state),
        "verifiers": {
            "management": {
                "profile": management_profile_name,
                "account_id": management_identity["Account"],
                "caller_arn": management_identity["Arn"],
            },
            "authority": {
                "profile": authority_profile_name,
                "account_id": authority_identity["Account"],
                "caller_arn": authority_identity["Arn"],
            },
        },
        "evaluated_at": _utc_text(now),
        "evidence_status": "GUG220_PARTIAL_STATE_READ_ONLY_RECONCILED",
        "authority_status": "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY",
        "production_status": PRODUCTION_STATUS,
    }
    evidence["evidence_digest"] = prefixed_canonical_digest(evidence)
    validate_gug220_evidence_chain(
        source_root=source_root,
        deployment_contract=deployment_contract,
        intent=intent,
        ledger=ledger,
        receipt=receipt,
        evidence=evidence,
    )
    return evidence


def _require_fresh_gug220_evidence(
    *,
    supplied: Mapping[str, Any],
    fresh: Mapping[str, Any],
    validation_kwargs: Mapping[str, Any],
) -> None:
    validate_gug220_evidence_chain(evidence=supplied, **validation_kwargs)
    validate_gug220_evidence_chain(evidence=fresh, **validation_kwargs)
    supplied_stable = dict(supplied)
    fresh_stable = dict(fresh)
    for value in (supplied_stable, fresh_stable):
        value.pop("evaluated_at", None)
        value.pop("evidence_digest", None)
    if canonical_json(supplied_stable) != canonical_json(fresh_stable):
        raise ChangeSetHandoffError("GUG220_EVIDENCE_PROVIDER_READBACK_DRIFT")


def _signed_parameter_values(receipt: Mapping[str, Any]) -> dict[str, str]:
    validate_signed_artifact_receipt(receipt)
    parameters = receipt.get("cloudformation_parameters")
    if not isinstance(parameters, list):
        raise ChangeSetHandoffError("SIGNED_PARAMETER_BINDING_INVALID")
    result: dict[str, str] = {}
    for item in parameters:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or not isinstance(item.get("ParameterKey"), str)
            or not isinstance(item.get("ParameterValue"), str)
            or item["ParameterKey"] in result
        ):
            raise ChangeSetHandoffError("SIGNED_PARAMETER_BINDING_INVALID")
        result[item["ParameterKey"]] = item["ParameterValue"]
    if tuple(result) != SIGNED_PARAMETER_KEYS:
        raise ChangeSetHandoffError("SIGNED_PARAMETER_BINDING_INVALID")
    return result


def _require_fresh_signed_receipt(
    *, local_receipt: Mapping[str, Any], fresh_receipt: Mapping[str, Any]
) -> None:
    """Reject a locally forged or stale receipt after direct provider readback.

    ``evaluated_at`` is intentionally refreshed by the direct AWS/GitHub
    verifier. Every other field, including the verifier identity and all
    canonical artifact/source-review bindings, must remain byte-equivalent in
    canonical JSON.
    """

    validate_signed_artifact_receipt(local_receipt)
    validate_signed_artifact_receipt(fresh_receipt)
    local_stable = dict(local_receipt)
    fresh_stable = dict(fresh_receipt)
    local_stable.pop("evaluated_at", None)
    fresh_stable.pop("evaluated_at", None)
    if canonical_json(local_stable) != canonical_json(fresh_stable):
        raise ChangeSetHandoffError("SIGNED_RECEIPT_PROVIDER_READBACK_DRIFT")


def _signed_receipt_binding_digest(receipt: Mapping[str, Any]) -> str:
    """Digest immutable Signer/S3 authority while excluding observation time."""

    validate_signed_artifact_receipt(receipt)
    stable = dict(receipt)
    stable.pop("evaluated_at", None)
    return _digest(stable)


def _delegation_execution_receipt_binding_projection(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the immutable Phase A execution authority projection.

    ``evaluated_at`` records when a verifier observed the already-completed
    execution. It is preserved in the evidence receipt, but it cannot be part
    of the binding used by a later Phase B readback because every legitimate
    observation has a different evaluation time.
    """

    stable = dict(receipt)
    stable.pop("evaluated_at", None)
    return stable


def _delegation_execution_receipt_binding_digest(
    receipt: Mapping[str, Any],
) -> str:
    return _digest(_delegation_execution_receipt_binding_projection(receipt))


def _delegation_live_receipt_binding_projection(
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize observation-only timestamps for sequential readback."""

    stable = dict(receipt)
    stable.pop("evaluated_at", None)
    execution_receipt = stable.get("delegation_execution_receipt")
    if isinstance(execution_receipt, Mapping):
        stable["delegation_execution_receipt"] = (
            _delegation_execution_receipt_binding_projection(execution_receipt)
        )
    return stable


def _delegation_live_receipt_binding_digest(
    receipt: Mapping[str, Any],
) -> str:
    return _digest(_delegation_live_receipt_binding_projection(receipt))


def refresh_signed_artifact_receipt_read_only(
    *,
    source_root: Path,
    local_receipt: Mapping[str, Any],
    sts_client: Any,
    signer_client: Any,
    s3_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Rebuild and re-read Signer/S3 before Phase B verification.

    Callers cannot supply a second self-authored receipt as provider evidence;
    this boundary creates the fresh receipt itself through the reviewed
    read-only collector and then requires canonical equality with the private
    handoff receipt.
    """

    validate_signed_artifact_receipt(local_receipt)
    job = local_receipt.get("signing_job")
    versions = local_receipt.get("expected_sdk_versions")
    if not isinstance(job, Mapping) or not isinstance(versions, Mapping):
        raise ChangeSetHandoffError("SIGNED_RECEIPT_INPUT_INVALID")
    fresh = build_signed_artifact_receipt_from_aws(
        source_root=source_root,
        source_commit=str(local_receipt.get("source_commit")),
        expected_boto3_version=str(versions.get("boto3")),
        expected_botocore_version=str(versions.get("botocore")),
        profile_name=EXPECTED_PROFILE,
        job_id=str(job.get("job_id")),
        expected_profile_version_arn=str(job.get("profile_version_arn")),
        sts_client=sts_client,
        signer_client=signer_client,
        s3_client=s3_client,
        now=now,
    )
    _require_fresh_signed_receipt(
        local_receipt=local_receipt,
        fresh_receipt=fresh,
    )
    return fresh


def _reviewed_template_bytes(
    *, source_root: Path, source_commit: str, template_path: str = TEMPLATE_PATH
) -> bytes:
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise ChangeSetHandoffError("SOURCE_COMMIT_INVALID")
    return _reviewed_git_object_bytes(
        source_root=source_root,
        source_commit=source_commit,
        relative_path=template_path,
        error_code="REVIEWED_TEMPLATE_UNAVAILABLE",
    )


def _template_contract(
    template_bytes: bytes,
    *,
    expected_parameter_keys: tuple[str, ...] = PARAMETER_KEYS,
) -> tuple[tuple[str, ...], dict[str, str]]:
    try:
        lines = template_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ChangeSetHandoffError("REVIEWED_TEMPLATE_INVALID") from exc

    def section(name: str) -> list[str]:
        marker = f"{name}:"
        try:
            start = lines.index(marker) + 1
        except ValueError as exc:
            raise ChangeSetHandoffError("REVIEWED_TEMPLATE_INVALID") from exc
        result: list[str] = []
        for line in lines[start:]:
            if line and not line.startswith((" ", "\t", "#")):
                break
            result.append(line)
        return result

    parameter_lines = section("Parameters")
    parameters = tuple(
        match.group(1)
        for line in parameter_lines
        if (match := re.fullmatch(r"  ([A-Za-z0-9]+):", line)) is not None
    )
    if parameters != expected_parameter_keys or len(parameters) != len(set(parameters)):
        raise ChangeSetHandoffError("REVIEWED_TEMPLATE_PARAMETER_DRIFT")

    resource_lines = section("Resources")
    normalized: dict[str, str] = {}
    current: str | None = None
    for line in resource_lines:
        logical_match = re.fullmatch(r"  ([A-Za-z0-9]+):", line)
        if logical_match is not None:
            current = logical_match.group(1)
            if current in normalized:
                raise ChangeSetHandoffError("REVIEWED_TEMPLATE_RESOURCE_DRIFT")
            continue
        type_match = re.fullmatch(r"    Type: (AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)", line)
        if type_match is not None:
            if current is None or current in normalized:
                raise ChangeSetHandoffError("REVIEWED_TEMPLATE_RESOURCE_DRIFT")
            normalized[current] = type_match.group(1)
    logical_ids = {
        match.group(1)
        for line in resource_lines
        if (match := re.fullmatch(r"  ([A-Za-z0-9]+):", line)) is not None
    }
    if not normalized or set(normalized) != logical_ids:
        raise ChangeSetHandoffError("REVIEWED_TEMPLATE_RESOURCE_DRIFT")
    if any(not value.startswith("AWS::") for value in normalized.values()):
            raise ChangeSetHandoffError("REVIEWED_TEMPLATE_RESOURCE_DRIFT")
    return parameters, dict(sorted(normalized.items()))


def _stack_tags(source_commit: str) -> dict[str, str]:
    return {
        "environment": "non-production",
        "managed_by": "cloudformation",
        "production": "false",
        "service": "scanalyze-platform-authority",
        "source_commit": source_commit,
        "work_package": WORK_PACKAGE,
    }


def _reviewed_signed_package_manifest(
    *,
    source_root: Path,
    signed_receipt: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Rebuild the unsigned package from Git and bind it to the Signer receipt.

    Schema validation alone cannot prove that a locally supplied Signer
    receipt represents the reviewed source commit.  This reconstruction reads
    every package entry from the exact Git object, rebuilds the deterministic
    archive, and compares both public digests before any Phase B parameter is
    derived.
    """

    validate_signed_artifact_receipt(signed_receipt)
    source_commit = str(signed_receipt.get("source_commit"))
    versions = signed_receipt.get("expected_sdk_versions")
    if not isinstance(versions, Mapping):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_SIGNED_PACKAGE_INVALID"
        )
    try:
        committed_sources = {
            path: _reviewed_git_object_bytes(
                source_root=source_root,
                source_commit=source_commit,
                relative_path=path.as_posix(),
                error_code="REVIEWED_PACKAGE_SOURCE_UNAVAILABLE",
                allow_empty=path == Path("tooling/__init__.py"),
            )
            for path in SOURCE_PATHS
        }
        package = build_repair_package(
            source_root=source_root,
            source_commit=source_commit,
            expected_boto3_version=str(versions.get("boto3")),
            expected_botocore_version=str(versions.get("botocore")),
            committed_sources=committed_sources,
        )
    except RepairPackageError as exc:
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_SIGNED_PACKAGE_INVALID"
        ) from exc
    if (
        sha256(canonical_json(package.manifest).encode("utf-8")).hexdigest()
        != signed_receipt.get("unsigned_manifest_sha256")
        or sha256(package.archive).hexdigest()
        != signed_receipt.get("unsigned_archive_sha256")
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_SIGNED_PACKAGE_DRIFT"
        )
    return package.manifest


def _render_phase_b_policy_value(
    value: Any,
    *,
    replacements: Mapping[str, str],
) -> Any:
    """Render the reviewed placeholder dialect and reject every unknown key."""

    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ChangeSetHandoffError("REVIEWED_IAM_POLICY_INVALID")
        return {
            key: _render_phase_b_policy_value(
                nested,
                replacements=replacements,
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [
            _render_phase_b_policy_value(
                nested,
                replacements=replacements,
            )
            for nested in value
        ]
    if isinstance(value, str):
        unknown = {
            match.group(1)
            for match in _PHASE_B_POLICY_PLACEHOLDER_RE.finditer(value)
            if match.group(1) not in replacements
        }
        if unknown:
            raise ChangeSetHandoffError(
                "REVIEWED_IAM_POLICY_PLACEHOLDER_INVALID"
            )
        rendered = _PHASE_B_POLICY_PLACEHOLDER_RE.sub(
            lambda match: replacements[match.group(1)],
            value,
        )
        if "${" in rendered:
            raise ChangeSetHandoffError(
                "REVIEWED_IAM_POLICY_PLACEHOLDER_INVALID"
            )
        return rendered
    if value is None or type(value) in {bool, int, float}:
        return value
    raise ChangeSetHandoffError("REVIEWED_IAM_POLICY_INVALID")


def _phase_b_precondition_policy_replacements(
    values: Mapping[str, str],
) -> dict[str, str]:
    required = {
        "IdentityCenterApplicationArn",
        "ExecutionNotBefore",
        "ExecutionNotAfter",
        "ExactExecutionId",
        "RepairArtifactBucket",
        "RepairArtifactKey",
        "ReconcileArtifactBucket",
        "ReconcileArtifactKey",
        "BrokerTopologySigningKeyArn",
    }
    if (
        not isinstance(values, Mapping)
        or not required.issubset(values)
        or any(
            not isinstance(values[key], str) or not values[key]
            for key in required
        )
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_POLICY_BINDING_INVALID"
        )
    return {
        "aws_partition": "aws",
        "region": REGION,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "broker_execution_role_arn": PHASE_B_BROKER_EXECUTION_ROLE_ARN,
        "topology_signing_key_arn": values[
            "BrokerTopologySigningKeyArn"
        ],
        "identity_center_application_arn": values[
            "IdentityCenterApplicationArn"
        ],
        "execution_not_before": values["ExecutionNotBefore"],
        "execution_not_after": values["ExecutionNotAfter"],
        "execution_id": values["ExactExecutionId"],
        "repair_artifact_bucket": values["RepairArtifactBucket"],
        "repair_artifact_key": values["RepairArtifactKey"],
        "reconcile_artifact_bucket": values["ReconcileArtifactBucket"],
        "reconcile_artifact_key": values["ReconcileArtifactKey"],
    }


def _phase_b_precondition_policy_documents(
    *,
    source_root: Path,
    source_commit: str,
    values: Mapping[str, str],
) -> dict[str, Mapping[str, Any]]:
    replacements = _phase_b_precondition_policy_replacements(values)
    documents: dict[str, Mapping[str, Any]] = {}
    for parameter_key, relative_path in (
        PHASE_B_PRECONDITION_POLICY_PATHS.items()
    ):
        rendered = _render_phase_b_policy_value(
            _reviewed_policy_object(
                source_root=source_root,
                source_commit=source_commit,
                relative_path=relative_path,
            ),
            replacements=replacements,
        )
        if not isinstance(rendered, Mapping):
            raise ChangeSetHandoffError("REVIEWED_IAM_POLICY_INVALID")
        documents[parameter_key] = rendered
    return documents


def _phase_b_precondition_policy_digests(
    *,
    source_root: Path,
    source_commit: str,
    values: Mapping[str, str],
) -> dict[str, str]:
    """Hash exact rendered policies, never unresolved Git placeholders."""

    return {
        parameter_key: plain_canonical_digest(document)
        for parameter_key, document in (
            _phase_b_precondition_policy_documents(
                source_root=source_root,
                source_commit=source_commit,
                values=values,
            ).items()
        )
    }


def _phase_b_precondition_execution_id(values: Mapping[str, str]) -> str:
    execution_request_digest = phase_b_canonical_digest(
        {
            "ChangeSetName": values["ExactChangeSetArn"],
            "StackName": values["ExactStackArn"],
            "ClientRequestToken": values["ExactClientRequestToken"],
        }
    )
    digest = phase_b_canonical_digest(
        {
            "phase": "B_PEP_EXECUTION",
            "execution_request_digest": execution_request_digest,
            "not_before": values["ExecutionNotBefore"],
            "not_after": values["ExecutionNotAfter"],
        }
    ).removeprefix("sha256:")
    return "gug221-phase-b-" + digest


def _phase_b_precondition_topology_sha256(
    values: Mapping[str, str],
) -> str:
    return calculate_broker_topology_sha256(
        {
            "authority_account_id": AUTHORITY_ACCOUNT_ID,
            "management_account_id": MANAGEMENT_ACCOUNT_ID,
            "region": REGION,
            "identity_center_application_arn": values[
                "IdentityCenterApplicationArn"
            ],
            "identity_center_instance_arn": values[
                "IdentityCenterInstanceArn"
            ],
            "identity_store_arn": values["IdentityStoreArn"],
            "operator_user_id_digest": phase_b_canonical_digest(
                {
                    "identity_store_user_id": values[
                        "OperatorIdentityStoreUserId"
                    ].lower()
                }
            ),
            "invoker_role_arn": values["InvokerPrincipalArn"],
            "broker_execution_role_arn": PHASE_B_BROKER_EXECUTION_ROLE_ARN,
            "proof_role_arn": (
                "arn:aws:iam::042360977644:role/"
                "ScanalyzeGug221PhaseBProof"
            ),
            "ledger_table_arn": (
                "arn:aws:dynamodb:us-east-1:042360977644:table/"
                + PHASE_B_LEDGER_TABLE_NAME
            ),
            "broker_alias_arn": (
                "arn:aws:lambda:us-east-1:042360977644:function:"
                "scanalyze-platform-authority-gug221-phase-b-broker:"
                "broker-v1"
            ),
            "broker_artifact_bucket": values["BrokerArtifactBucket"],
            "broker_artifact_key": values["BrokerArtifactKey"],
            "broker_artifact_version": values["BrokerArtifactVersion"],
            "broker_artifact_code_sha256": values[
                "BrokerArtifactCodeSha256"
            ],
            "broker_code_signing_config_arn": values[
                "BrokerCodeSigningConfigArn"
            ],
            "invoker_policy_sha256": values["InvokerPolicySha256"],
            "broker_policy_sha256": values["BrokerPolicySha256"],
            "proof_policy_sha256": values["ProofPolicySha256"],
            "application_actor_policy_sha256": values[
                "ApplicationActorPolicySha256"
            ],
            "topology_signing_key_arn": values[
                "BrokerTopologySigningKeyArn"
            ],
            "topology_signature_algorithm": (
                BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
            ),
        }
    )


def _validate_phase_b_precondition_binding(
    values: Mapping[str, str],
) -> None:
    """Reuse the runtime binding validator before any Change Set can be trusted."""

    try:
        PhaseBIdentityBinding(
            authority_account_id=AUTHORITY_ACCOUNT_ID,
            management_account_id=MANAGEMENT_ACCOUNT_ID,
            region=REGION,
            identity_center_application_arn=values[
                "IdentityCenterApplicationArn"
            ],
            identity_center_instance_arn=values[
                "IdentityCenterInstanceArn"
            ],
            identity_store_arn=values["IdentityStoreArn"],
            redirect_uri=values["IdentityCenterRedirectUri"],
            operator_user_id=values["OperatorIdentityStoreUserId"],
            invoker_role_arn=values["InvokerPrincipalArn"],
            broker_execution_role_arn=PHASE_B_BROKER_EXECUTION_ROLE_ARN,
            proof_role_arn=(
                "arn:aws:iam::042360977644:role/"
                "ScanalyzeGug221PhaseBProof"
            ),
            ledger_table_arn=(
                "arn:aws:dynamodb:us-east-1:042360977644:table/"
                + PHASE_B_LEDGER_TABLE_NAME
            ),
            stack_arn=values["ExactStackArn"],
            change_set_arn=values["ExactChangeSetArn"],
            client_request_token=values["ExactClientRequestToken"],
            phase_b_intent_digest=values["PhaseBIntentDigest"],
            change_set_receipt_digest=values["ChangeSetReceiptDigest"],
            template_digest=values["TemplateDigest"],
            parameters_digest=values["ParametersDigest"],
            resource_inventory_digest=values["ResourceInventoryDigest"],
            ledger_controls_digest=values["LedgerControlsDigest"],
            oauth_state_digest=values["OauthStateDigest"],
            invoker_policy_sha256=values["InvokerPolicySha256"],
            broker_policy_sha256=values["BrokerPolicySha256"],
            proof_policy_sha256=values["ProofPolicySha256"],
            application_actor_policy_sha256=values[
                "ApplicationActorPolicySha256"
            ],
            broker_artifact_bucket=values["BrokerArtifactBucket"],
            broker_artifact_key=values["BrokerArtifactKey"],
            broker_artifact_version=values["BrokerArtifactVersion"],
            broker_artifact_code_sha256=values[
                "BrokerArtifactCodeSha256"
            ],
            broker_code_signing_config_arn=values[
                "BrokerCodeSigningConfigArn"
            ],
            broker_topology_provider_evidence_digest=None,
            broker_topology_signing_key_arn=values[
                "BrokerTopologySigningKeyArn"
            ],
            broker_topology_signature_algorithm=values[
                "BrokerTopologySignatureAlgorithm"
            ],
            expected_broker_topology_sha256=values[
                "ExpectedBrokerTopologySha256"
            ],
            configured_execution_id=values["ExactExecutionId"],
            execution_not_before=_timestamp(
                values["ExecutionNotBefore"],
                "PHASE_B_PRECONDITION_WINDOW_INVALID",
            ),
            execution_not_after=_timestamp(
                values["ExecutionNotAfter"],
                "PHASE_B_PRECONDITION_WINDOW_INVALID",
            ),
        )
    except (KeyError, PhaseBPepError) as exc:
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_PROVIDER_BINDING_INVALID"
        ) from exc


def build_phase_b_precondition_parameter_handoff(
    *,
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> Mapping[str, Any]:
    """Derive all PRE_B parameters exclusively from validated upstream proof."""

    signed = _signed_parameter_values(signed_receipt)
    source_commit = signed["SourceCommit"]
    validate_deployment_contract(deployment_contract)
    if source_commit != deployment_contract.get("source_commit"):
        raise ChangeSetHandoffError("SOURCE_COMMIT_CHAIN_MISMATCH")
    validate_phase_b_identity_materialization_receipt(
        phase_b_identity_materialization_receipt,
        source_commit=source_commit,
    )
    _validate_pep_change_set_receipt_binding(
        receipt=pep_change_set_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
    )
    identity_receipt_sha256 = (
        _phase_b_identity_materialization_receipt_digest(
            phase_b_identity_materialization_receipt
        )
    )
    if (
        not isinstance(pep_parameter_handoff, Mapping)
        or pep_parameter_handoff.get("source_commit") != source_commit
        or pep_parameter_handoff.get("deployment_contract_sha256")
        != _digest(deployment_contract)
        or pep_parameter_handoff.get(
            "phase_b_identity_materialization_receipt_sha256"
        )
        != identity_receipt_sha256
        or pep_change_set_receipt.get("parameter_handoff_sha256")
        != _digest(pep_parameter_handoff)
        or pep_change_set_receipt.get(
            "phase_b_identity_materialization_receipt_sha256"
        )
        != identity_receipt_sha256
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_PEP_CHAIN_INVALID"
        )
    pep_change_set = pep_change_set_receipt["change_set"]
    execution_contract = pep_change_set_receipt["execution_contract"]
    reviewed_package_manifest = _reviewed_signed_package_manifest(
        source_root=source_root,
        signed_receipt=signed_receipt,
    )
    reviewed_template = _reviewed_template_bytes(
        source_root=source_root,
        source_commit=source_commit,
        template_path=PHASE_B_PRECONDITION_TEMPLATE_PATH,
    )
    if reviewed_template_bytes != reviewed_template:
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_REVIEWED_TEMPLATE_DRIFT"
        )
    _, resource_types = _template_contract(
        reviewed_template_bytes,
        expected_parameter_keys=PHASE_B_PRECONDITION_PARAMETER_KEYS,
    )
    if resource_types != PHASE_B_PRECONDITION_RESOURCE_TYPES:
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_RESOURCE_INVENTORY_DRIFT"
        )
    phase_b_intent_digest = phase_b_canonical_digest(
        {
            "work_package": WORK_PACKAGE,
            "phase": "B_PEP_EXECUTION",
            "source_commit": source_commit,
            "deployment_contract_sha256": _digest(deployment_contract),
            "phase_b_identity_materialization_receipt_sha256": (
                identity_receipt_sha256
            ),
            "pep_parameter_handoff_sha256": _digest(
                pep_parameter_handoff
            ),
            "pep_change_set_receipt_sha256": _digest(
                pep_change_set_receipt
            ),
        }
    )
    ledger_controls_digest = phase_b_canonical_digest(
        {
            "work_package": WORK_PACKAGE,
            "phase": "PRE_B_BROKER_CHANGE_SET",
            "main_execution_contract": execution_contract,
            "main_template_sha256": pep_change_set_receipt[
                "template_sha256"
            ],
            "precondition_template_sha256": sha256(
                reviewed_template_bytes
            ).hexdigest(),
            "one_shot": True,
            "retry_permitted": False,
            "ambiguous_outcome_requires_read_only_reconciliation": True,
        }
    )
    values = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "IdentityCenterApplicationArn": (
            phase_b_identity_materialization_receipt[
                "identity_center_application_arn"
            ]
        ),
        "IdentityCenterInstanceArn": (
            phase_b_identity_materialization_receipt[
                "identity_center_instance_arn"
            ]
        ),
        "IdentityStoreArn": phase_b_identity_materialization_receipt[
            "identity_store_arn"
        ],
        "IdentityCenterRedirectUri": (
            phase_b_identity_materialization_receipt[
                "identity_center_redirect_uri"
            ]
        ),
        "OperatorIdentityStoreUserId": (
            phase_b_identity_materialization_receipt[
                "operator_identity_store_user_id"
            ]
        ),
        "InvokerPrincipalArn": phase_b_identity_materialization_receipt[
            "invoker_principal_arn"
        ],
        "ExactStackArn": pep_change_set["stack_arn"],
        "ExactChangeSetArn": pep_change_set["arn"],
        "ExactClientRequestToken": execution_contract[
            "client_request_token"
        ],
        "ExecutionNotBefore": deployment_contract["repair_not_before"],
        "ExecutionNotAfter": deployment_contract["repair_not_after"],
        "PhaseBIntentDigest": phase_b_intent_digest,
        "ChangeSetReceiptDigest": phase_b_canonical_digest(
            pep_change_set_receipt
        ),
        "TemplateDigest": (
            "sha256:" + str(pep_change_set_receipt["template_sha256"])
        ),
        "ParametersDigest": phase_b_canonical_digest(
            pep_parameter_handoff["parameters"]
        ),
        "ResourceInventoryDigest": phase_b_canonical_digest(
            pep_change_set["resource_changes"]
        ),
        "LedgerControlsDigest": ledger_controls_digest,
        "OauthStateDigest": phase_b_identity_materialization_receipt[
            "oauth_state_digest"
        ],
        "BrokerCodeSigningConfigArn": (
            phase_b_identity_materialization_receipt[
                "broker_code_signing_config_arn"
            ]
        ),
        "BrokerTopologySigningKeyArn": (
            phase_b_identity_materialization_receipt[
                "broker_topology_signing_key_arn"
            ]
        ),
        "BrokerArtifactBucket": signed["RepairArtifactBucket"],
        "BrokerArtifactKey": signed["RepairArtifactKey"],
        "BrokerArtifactVersion": signed["RepairArtifactVersion"],
        "BrokerArtifactCodeSha256": signed["RepairArtifactCodeSha256"],
        "RepairArtifactBucket": signed["RepairArtifactBucket"],
        "RepairArtifactKey": signed["RepairArtifactKey"],
        "ReconcileArtifactBucket": signed["ReconcileArtifactBucket"],
        "ReconcileArtifactKey": signed["ReconcileArtifactKey"],
        "BrokerTopologySignatureAlgorithm": (
            BROKER_TOPOLOGY_SIGNATURE_ALGORITHM
        ),
    }
    values["ExactExecutionId"] = _phase_b_precondition_execution_id(values)
    policy_digests = _phase_b_precondition_policy_digests(
        source_root=source_root,
        source_commit=source_commit,
        values=values,
    )
    values.update(policy_digests)
    values["ExpectedBrokerTopologySha256"] = (
        _phase_b_precondition_topology_sha256(values)
    )
    if set(values) != set(PHASE_B_PRECONDITION_PARAMETER_KEYS):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_PARAMETER_SET_INCOMPLETE"
        )
    _validate_phase_b_precondition_binding(values)
    parameters = [
        {"ParameterKey": key, "ParameterValue": values[key]}
        for key in PHASE_B_PRECONDITION_PARAMETER_KEYS
    ]
    return {
        "artifact_type": PHASE_B_PRECONDITION_HANDOFF_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "PRE_B_BROKER_CHANGE_SET",
        "source_commit": source_commit,
        "stack_name": PHASE_B_PRECONDITION_STACK_NAME,
        "change_set_name": PHASE_B_PRECONDITION_CHANGE_SET_NAME,
        "signed_artifact_receipt_sha256": (
            _signed_receipt_binding_digest(signed_receipt)
        ),
        "reviewed_package_manifest_sha256": sha256(
            canonical_json(reviewed_package_manifest).encode("utf-8")
        ).hexdigest(),
        "phase_b_identity_materialization_receipt_sha256": (
            identity_receipt_sha256
        ),
        "pep_parameter_handoff_sha256": _digest(
            pep_parameter_handoff
        ),
        "pep_change_set_receipt_sha256": _digest(
            pep_change_set_receipt
        ),
        "reviewed_template_path": PHASE_B_PRECONDITION_TEMPLATE_PATH,
        "reviewed_template_sha256": sha256(
            reviewed_template_bytes
        ).hexdigest(),
        "reviewed_policy_sha256": dict(sorted(policy_digests.items())),
        "broker_topology_sha256": values[
            "ExpectedBrokerTopologySha256"
        ],
        "stack_tags": _stack_tags(source_commit),
        "parameters": parameters,
        "parameters_sha256": _digest(parameters),
        "authority_status": "NON_AUTHORITATIVE_DERIVATION_ONLY",
        "production_status": PRODUCTION_STATUS,
    }


def validate_phase_b_precondition_parameter_handoff(
    *,
    handoff: Mapping[str, Any],
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> None:
    expected = build_phase_b_precondition_parameter_handoff(
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    if handoff != expected:
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_PARAMETER_HANDOFF_DRIFT"
        )


def _delegation_parameter_values(
    *, source_commit: str, derived: Mapping[str, str]
) -> dict[str, str]:
    kms_mode = derived["identity_center_kms_mode"]
    principal_id = derived["principal_id"]
    return {
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "SourceCommit": source_commit,
        "IdentityCenterInstanceArn": derived["identity_center_instance_arn"],
        "IdentityStoreArn": (
            "arn:aws:identitystore::839393571433:identitystore/"
            + derived["identity_store_id"]
        ),
        "RepairPrincipalId": principal_id,
        "RepairPrincipalUserArn": "arn:aws:identitystore:::user/" + principal_id,
        "AuditPermissionSetArn": derived["collector_permission_set_arn"],
        "UseIdentityCenterCustomerManagedKms": (
            "true" if kms_mode == "CUSTOMER_MANAGED_KEY" else "false"
        ),
        "IdentityCenterKmsKeyArn": str(
            derived["identity_center_kms_key_arn"]
        ),
    }


def build_delegation_parameter_handoff(
    *,
    source_root: Path,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_template_bytes: bytes,
) -> Mapping[str, Any]:
    """Phase A: derive only the 10 management delegation parameters."""

    derived = validate_gug220_evidence_chain(
        source_root=source_root,
        deployment_contract=deployment_contract,
        intent=gug220_intent,
        ledger=gug220_ledger,
        receipt=gug220_receipt,
        evidence=gug220_evidence,
    )
    source_commit = str(deployment_contract["source_commit"])
    _, _ = _template_contract(
        delegation_template_bytes,
        expected_parameter_keys=DELEGATION_PARAMETER_KEYS,
    )
    delegation_values = _delegation_parameter_values(
        source_commit=source_commit,
        derived=derived,
    )
    delegation_parameters = [
        {"ParameterKey": key, "ParameterValue": delegation_values[key]}
        for key in DELEGATION_PARAMETER_KEYS
    ]
    if any(item["ParameterValue"] == "****" for item in delegation_parameters):
        raise ChangeSetHandoffError("PARAMETER_VALUE_MASKED")
    return {
        "artifact_type": DELEGATION_HANDOFF_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "source_commit": source_commit,
        "stack_name": DELEGATION_STACK_NAME,
        "change_set_name": DELEGATION_CHANGE_SET_NAME,
        "deployment_contract_sha256": _digest(deployment_contract),
        "gug220_intent_sha256": _digest(gug220_intent),
        "gug220_ledger_sha256": _digest(gug220_ledger),
        "gug220_receipt_sha256": _digest(gug220_receipt),
        "gug220_evidence_sha256": _digest(gug220_evidence),
        "template_sha256": sha256(delegation_template_bytes).hexdigest(),
        "stack_tags": _stack_tags(source_commit),
        "parameters": delegation_parameters,
        "repair_id": derived["repair_id"],
        "authority_status": "NON_AUTHORITATIVE_DERIVATION_ONLY",
        "production_status": PRODUCTION_STATUS,
    }


def validate_delegation_parameter_handoff(
    *,
    handoff: Mapping[str, Any],
    source_root: Path,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_template_bytes: bytes,
) -> None:
    expected = build_delegation_parameter_handoff(
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_template_bytes=delegation_template_bytes,
    )
    if handoff != expected:
        raise ChangeSetHandoffError("DELEGATION_PARAMETER_HANDOFF_DRIFT")


def build_pep_parameter_handoff(
    *,
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    template_bytes: bytes,
) -> Mapping[str, Any]:
    """Phase B: derive 29 PEP parameters after Phase A live readback."""

    signed = _signed_parameter_values(signed_receipt)
    validate_deployment_contract(deployment_contract)
    source_commit = signed["SourceCommit"]
    if source_commit != deployment_contract["source_commit"]:
        raise ChangeSetHandoffError("SOURCE_COMMIT_CHAIN_MISMATCH")
    validate_phase_b_identity_materialization_receipt(
        phase_b_identity_materialization_receipt,
        source_commit=source_commit,
    )
    derived = validate_gug220_evidence_chain(
        source_root=source_root,
        deployment_contract=deployment_contract,
        intent=gug220_intent,
        ledger=gug220_ledger,
        receipt=gug220_receipt,
        evidence=gug220_evidence,
    )
    validate_delegation_live_receipt(
        receipt=delegation_live_receipt,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
    )
    invoker_arn = str(delegation_live_receipt["repair_invoker_permission_set_arn"])
    if (
        _PERMISSION_SET_ARN_RE.fullmatch(invoker_arn) is None
        or invoker_arn == derived["collector_permission_set_arn"]
    ):
        raise ChangeSetHandoffError("DELEGATION_LIVE_INVOKER_INVALID")
    invoker_policy = _repair_invoker_policy(source_root, source_commit)
    private = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "RepairId": derived["repair_id"],
        "PrincipalId": derived["principal_id"],
        "IdentityStoreId": derived["identity_store_id"],
        "IdentityCenterInstanceArn": derived["identity_center_instance_arn"],
        "CollectorPermissionSetArn": derived["collector_permission_set_arn"],
        "RepairInvokerPermissionSetArn": invoker_arn,
        "CollectorPolicyDigest": derived["collector_policy_digest"],
        "RepairInvokerPolicyDigest": plain_canonical_digest(invoker_policy),
        "OriginalGug220LedgerDigest": _gug220_ledger_parameter_digest(
            derived["original_gug220_ledger_digest"]
        ),
        "ExpectedPermissionSetTagsJson": canonical_json(
            _permission_set_tags(source_commit)
        ),
        "RepairNotBefore": str(deployment_contract["repair_not_before"]),
        "RepairNotAfter": str(deployment_contract["repair_not_after"]),
        "CollectorSamlProviderArn": derived["collector_saml_provider_arn"],
        "IdentityCenterKmsMode": derived["identity_center_kms_mode"],
        "IdentityCenterKmsKeyArn": derived["identity_center_kms_key_arn"],
    }
    _, _ = _template_contract(template_bytes)
    values = {**private, **signed}
    if set(values) != set(PARAMETER_KEYS):
        raise ChangeSetHandoffError("PEP_PARAMETER_SET_INCOMPLETE")
    parameters = [
        {"ParameterKey": key, "ParameterValue": values[key]}
        for key in PARAMETER_KEYS
    ]
    if any(item["ParameterValue"] == "****" for item in parameters):
        raise ChangeSetHandoffError("PARAMETER_VALUE_MASKED")
    return {
        "artifact_type": PEP_HANDOFF_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "source_commit": source_commit,
        "stack_name": STACK_NAME,
        "change_set_name": CHANGE_SET_NAME,
        "signed_artifact_receipt_sha256": _signed_receipt_binding_digest(
            signed_receipt
        ),
        "deployment_contract_sha256": _digest(deployment_contract),
        "gug220_intent_sha256": _digest(gug220_intent),
        "gug220_ledger_sha256": _digest(gug220_ledger),
        "gug220_receipt_sha256": _digest(gug220_receipt),
        "gug220_evidence_sha256": _digest(gug220_evidence),
        "delegation_live_receipt_sha256": (
            _delegation_live_receipt_binding_digest(delegation_live_receipt)
        ),
        "phase_b_identity_materialization_receipt_sha256": (
            _phase_b_identity_materialization_receipt_digest(
                phase_b_identity_materialization_receipt
            )
        ),
        "template_sha256": sha256(template_bytes).hexdigest(),
        "stack_tags": _stack_tags(source_commit),
        "parameters": parameters,
        "authority_status": "NON_AUTHORITATIVE_DERIVATION_ONLY",
        "production_status": PRODUCTION_STATUS,
    }


def validate_pep_parameter_handoff(
    *, handoff: Mapping[str, Any], **kwargs: Any
) -> None:
    if handoff != build_pep_parameter_handoff(**kwargs):
        raise ChangeSetHandoffError("PEP_PARAMETER_HANDOFF_DRIFT")


def _private_path(path: Path, *, source_root: Path, must_exist: bool) -> Path:
    root = source_root.resolve(strict=True)
    resolved = path.resolve(strict=must_exist)
    try:
        resolved.relative_to(root)
    except ValueError:
        pass
    else:
        raise ChangeSetHandoffError("PRIVATE_PATH_INSIDE_SOURCE_ROOT")
    if must_exist:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= MAX_PRIVATE_JSON_BYTES
        ):
            raise ChangeSetHandoffError("PRIVATE_INPUT_UNSAFE")
    return resolved


def read_private_json(path: Path, *, source_root: Path) -> Mapping[str, Any]:
    resolved = _private_path(path, source_root=source_root, must_exist=True)
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.getuid()
                or opened.st_mode & 0o077
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
            ):
                raise ChangeSetHandoffError("PRIVATE_INPUT_TOCTOU_DETECTED")
            payload = stream.read(MAX_PRIVATE_JSON_BYTES + 1)
    except ChangeSetHandoffError:
        raise
    except OSError as exc:
        raise ChangeSetHandoffError("PRIVATE_INPUT_READ_FAILED") from exc
    if len(payload) > MAX_PRIVATE_JSON_BYTES:
        raise ChangeSetHandoffError("PRIVATE_INPUT_TOO_LARGE")
    try:
        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ChangeSetHandoffError("PRIVATE_INPUT_DUPLICATE_KEY")
                result[key] = item
            return result

        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except ChangeSetHandoffError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChangeSetHandoffError("PRIVATE_INPUT_INVALID_JSON") from exc
    if not isinstance(value, Mapping):
        raise ChangeSetHandoffError("PRIVATE_INPUT_INVALID_JSON")
    return value


def write_private_json(
    *, value: Mapping[str, Any], output_path: Path, source_root: Path
) -> None:
    resolved = _private_path(output_path, source_root=source_root, must_exist=False)
    payload = (canonical_json(value) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            resolved,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise ChangeSetHandoffError("PRIVATE_OUTPUT_WRITE_FAILED") from exc


def write_private_json_pair_atomic(
    *,
    first_value: Mapping[str, Any],
    first_output_path: Path,
    second_value: Mapping[str, Any],
    second_output_path: Path,
    source_root: Path,
) -> None:
    """Failure-atomically publish two private receipts.

    Both payloads are durably staged in their destination directories before
    either destination is reserved.  Existing destinations are never
    overwritten.  Any handled reservation or rename failure removes every
    reservation/publication before returning an error.  Destination
    directories must be private to the current user so another principal
    cannot swap a reserved name between ``O_EXCL`` and ``rename``.
    """

    targets = (
        _private_path(
            first_output_path, source_root=source_root, must_exist=False
        ),
        _private_path(
            second_output_path, source_root=source_root, must_exist=False
        ),
    )
    if targets[0] == targets[1]:
        raise ChangeSetHandoffError("PRIVATE_OUTPUT_PATH_COLLISION")
    for target in targets:
        try:
            parent = target.parent
            metadata = parent.lstat()
        except OSError as exc:
            raise ChangeSetHandoffError("PRIVATE_OUTPUT_PAIR_WRITE_FAILED") from exc
        if (
            parent.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ChangeSetHandoffError("PRIVATE_OUTPUT_DIRECTORY_UNSAFE")
    payloads = (
        (canonical_json(first_value) + "\n").encode("utf-8"),
        (canonical_json(second_value) + "\n").encode("utf-8"),
    )
    staged: list[Path] = []
    reserved: list[Path] = []
    try:
        for target, payload in zip(targets, payloads, strict=True):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
            )
            temporary = Path(temporary_name)
            staged.append(temporary)
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())

        for target in targets:
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            reserved.append(target)
            os.close(descriptor)

        for temporary, target in zip(staged, targets, strict=True):
            os.rename(temporary, target)
        for parent in {target.parent for target in targets}:
            descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError as exc:
        for target in reversed(reserved):
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        for temporary in staged:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        for parent in {target.parent for target in targets}:
            try:
                descriptor = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                pass
        raise ChangeSetHandoffError("PRIVATE_OUTPUT_PAIR_WRITE_FAILED") from exc


def _read_gug220_private_chain(
    *,
    source_root: Path,
    deployment_contract_path: Path,
    gug220_intent_path: Path,
    gug220_ledger_path: Path,
    gug220_receipt_path: Path,
    gug220_evidence_path: Path,
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        read_private_json(path, source_root=source_root)
        for path in (
            deployment_contract_path,
            gug220_intent_path,
            gug220_ledger_path,
            gug220_receipt_path,
            gug220_evidence_path,
        )
    )


def prepare_pep_parameter_handoff(
    *,
    source_root: Path,
    signed_receipt_path: Path,
    delegation_live_receipt_path: Path,
    phase_b_identity_materialization_receipt_path: Path,
    deployment_contract_path: Path,
    gug220_intent_path: Path,
    gug220_ledger_path: Path,
    gug220_receipt_path: Path,
    gug220_evidence_path: Path,
    output_path: Path,
) -> Mapping[str, Any]:
    contract, intent, ledger, receipt, evidence = _read_gug220_private_chain(
        source_root=source_root,
        deployment_contract_path=deployment_contract_path,
        gug220_intent_path=gug220_intent_path,
        gug220_ledger_path=gug220_ledger_path,
        gug220_receipt_path=gug220_receipt_path,
        gug220_evidence_path=gug220_evidence_path,
    )
    signed = read_private_json(signed_receipt_path, source_root=source_root)
    live = read_private_json(delegation_live_receipt_path, source_root=source_root)
    identity_materialization_receipt = read_private_json(
        phase_b_identity_materialization_receipt_path,
        source_root=source_root,
    )
    validate_signed_artifact_receipt(signed)
    template = _reviewed_template_bytes(
        source_root=source_root, source_commit=str(signed.get("source_commit"))
    )
    handoff = build_pep_parameter_handoff(
        source_root=source_root,
        signed_receipt=signed,
        deployment_contract=contract,
        gug220_intent=intent,
        gug220_ledger=ledger,
        gug220_receipt=receipt,
        gug220_evidence=evidence,
        delegation_live_receipt=live,
        phase_b_identity_materialization_receipt=(
            identity_materialization_receipt
        ),
        template_bytes=template,
    )
    write_private_json(value=handoff, output_path=output_path, source_root=source_root)
    return handoff


def _aws_call(call: Any, /, **kwargs: Any) -> Mapping[str, Any]:
    try:
        response = call(**kwargs)
    except Exception as exc:
        raise ChangeSetHandoffError("AWS_READBACK_FAILED") from exc
    if not isinstance(response, Mapping):
        raise ChangeSetHandoffError("AWS_READBACK_INVALID")
    return response


def _normalize_tags(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise ChangeSetHandoffError("CHANGE_SET_TAGS_INVALID")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not isinstance(item.get("Value"), str)
            or item["Key"] in result
        ):
            raise ChangeSetHandoffError("CHANGE_SET_TAGS_INVALID")
        result[item["Key"]] = item["Value"]
    return dict(sorted(result.items()))


def _normalize_parameters(
    value: Any, *, expected_keys: tuple[str, ...] = PARAMETER_KEYS
) -> dict[str, str]:
    if not isinstance(value, list):
        raise ChangeSetHandoffError("CHANGE_SET_PARAMETERS_INVALID")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or not isinstance(item.get("ParameterKey"), str)
            or not isinstance(item.get("ParameterValue"), str)
            or item["ParameterKey"] in result
            or item["ParameterValue"] == "****"
        ):
            code = (
                "CHANGE_SET_PARAMETER_MASKED"
                if isinstance(item, Mapping) and item.get("ParameterValue") == "****"
                else "CHANGE_SET_PARAMETERS_INVALID"
            )
            raise ChangeSetHandoffError(code)
        result[item["ParameterKey"]] = item["ParameterValue"]
    if set(result) != set(expected_keys):
        raise ChangeSetHandoffError("CHANGE_SET_PARAMETERS_NOT_EXACT")
    return result


def _core_change_set_metadata(
    response: Mapping[str, Any], *, change_set_arn: str,
    change_set_name: str = CHANGE_SET_NAME,
    stack_name: str = STACK_NAME,
    change_set_arn_re: re.Pattern[str] = _CHANGE_SET_ARN_RE,
    stack_arn_re: re.Pattern[str] = _STACK_ARN_RE,
) -> tuple[str, str]:
    if change_set_arn_re.fullmatch(change_set_arn) is None:
        raise ChangeSetHandoffError("CHANGE_SET_ARN_INVALID")
    stack_arn = response.get("StackId")
    if (
        response.get("ChangeSetId") != change_set_arn
        or response.get("ChangeSetName") != change_set_name
        or response.get("StackName") != stack_name
        or not isinstance(stack_arn, str)
        or stack_arn_re.fullmatch(stack_arn) is None
        or response.get("ChangeSetType") != "CREATE"
        or response.get("Status") != "CREATE_COMPLETE"
        or response.get("ExecutionStatus") != "AVAILABLE"
        or response.get("Capabilities") != list(EXPECTED_CAPABILITIES)
        or "RoleARN" in response
        or response.get("OnStackFailure") != "ROLLBACK"
        or response.get("ImportExistingResources", False) is not False
        or response.get("RollbackConfiguration")
        != {"RollbackTriggers": [], "MonitoringTimeInMinutes": 0}
        or "DeploymentMode" in response
        or response.get("NotificationARNs", []) != []
        or response.get("IncludeNestedStacks", False) is not False
        or response.get("ParentChangeSetId") not in (None, "")
        or response.get("RootChangeSetId") not in (None, "")
    ):
        raise ChangeSetHandoffError("CHANGE_SET_METADATA_INVALID")
    change_uuid = change_set_arn_re.fullmatch(change_set_arn)
    assert change_uuid is not None
    return stack_arn, change_uuid.group("uuid")


def _read_change_set_pages(
    *, cloudformation_client: Any, change_set_arn: str,
    change_set_name: str = CHANGE_SET_NAME,
    stack_name: str = STACK_NAME,
    change_set_arn_re: re.Pattern[str] = _CHANGE_SET_ARN_RE,
    stack_arn_re: re.Pattern[str] = _STACK_ARN_RE,
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]]:
    if change_set_arn_re.fullmatch(change_set_arn) is None:
        raise ChangeSetHandoffError("CHANGE_SET_ARN_INVALID")
    first: Mapping[str, Any] | None = None
    changes: list[Mapping[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request: dict[str, Any] = {
            "ChangeSetName": change_set_arn,
            "StackName": stack_name,
            "IncludePropertyValues": True,
        }
        if token is not None:
            request["NextToken"] = token
        response = _aws_call(cloudformation_client.describe_change_set, **request)
        _core_change_set_metadata(
            response,
            change_set_arn=change_set_arn,
            change_set_name=change_set_name,
            stack_name=stack_name,
            change_set_arn_re=change_set_arn_re,
            stack_arn_re=stack_arn_re,
        )
        page_changes = response.get("Changes")
        if not isinstance(page_changes, list) or any(
            not isinstance(item, Mapping) for item in page_changes
        ):
            raise ChangeSetHandoffError("CHANGE_SET_CHANGES_INVALID")
        if first is None:
            first = response
        else:
            for key in (
                "ChangeSetId",
                "ChangeSetName",
                "StackId",
                "StackName",
                "ChangeSetType",
                "Status",
                "ExecutionStatus",
                "Capabilities",
                "CreationTime",
                "Description",
                "Parameters",
                "Tags",
                "OnStackFailure",
                "RollbackConfiguration",
                "NotificationARNs",
                "IncludeNestedStacks",
                "ImportExistingResources",
            ):
                if response.get(key) != first.get(key):
                    raise ChangeSetHandoffError("CHANGE_SET_PAGINATION_DRIFT")
        changes.extend(page_changes)
        next_token = response.get("NextToken")
        if next_token is None:
            assert first is not None
            return first, changes
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            raise ChangeSetHandoffError("CHANGE_SET_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    raise ChangeSetHandoffError("CHANGE_SET_PAGINATION_EXCEEDED")


def _normalize_changes(
    value: Sequence[Mapping[str, Any]], *, expected_resources: Mapping[str, str]
) -> list[dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for item in value:
        if item.get("Type") != "Resource" or not isinstance(
            item.get("ResourceChange"), Mapping
        ):
            raise ChangeSetHandoffError("CHANGE_SET_RESOURCE_CHANGE_INVALID")
        resource = item["ResourceChange"]
        logical_id = resource.get("LogicalResourceId")
        resource_type = resource.get("ResourceType")
        replacement = resource.get("Replacement")
        if (
            not isinstance(logical_id, str)
            or not isinstance(resource_type, str)
            or resource.get("Action") != "Add"
            or replacement not in (None, "False", False)
            or resource.get("PhysicalResourceId") not in (None, "")
            or resource.get("Scope", []) != []
            or logical_id in result
        ):
            raise ChangeSetHandoffError("CHANGE_SET_RESOURCE_CHANGE_INVALID")
        result[logical_id] = {
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "action": "Add",
            "replacement": "False",
        }
    if {
        logical_id: item["resource_type"] for logical_id, item in result.items()
    } != dict(expected_resources):
        raise ChangeSetHandoffError("CHANGE_SET_RESOURCE_INVENTORY_DRIFT")
    return [result[key] for key in sorted(result)]


def _utc_text(value: datetime | None = None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ChangeSetHandoffError("EVALUATION_TIME_INVALID")
    return (
        current.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _cloudtrail_parameters(parameters: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    return [
        {"parameterKey": item["ParameterKey"], "parameterValue": item["ParameterValue"]}
        for item in parameters
    ]


def _cloudtrail_tags(tags: Mapping[str, str]) -> list[dict[str, str]]:
    return [{"key": key, "value": value} for key, value in sorted(tags.items())]


def _verify_create_change_set_event(
    *,
    cloudtrail_client: Any,
    account_id: str,
    creator_arn: str,
    change_set_arn: str,
    change_set_name: str,
    stack_name: str,
    reviewed_template_bytes: bytes,
    parameters: Sequence[Mapping[str, str]],
    tags: Mapping[str, str],
    creation_time: datetime,
) -> Mapping[str, str]:
    if creation_time.tzinfo is None:
        raise ChangeSetHandoffError("CHANGE_SET_CREATION_TIME_INVALID")
    events: list[Mapping[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request: dict[str, Any] = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "CreateChangeSet"}
            ],
            "StartTime": creation_time - timedelta(minutes=5),
            "EndTime": creation_time + timedelta(minutes=5),
        }
        if token is not None:
            request["NextToken"] = token
        response = _aws_call(cloudtrail_client.lookup_events, **request)
        page = response.get("Events")
        if not isinstance(page, list) or any(not isinstance(item, Mapping) for item in page):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_PAGE_INVALID")
        events.extend(page)
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token in seen:
            raise ChangeSetHandoffError("CLOUDTRAIL_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    else:
        raise ChangeSetHandoffError("CLOUDTRAIL_PAGINATION_EXCEEDED")

    matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for envelope in events:
        raw = envelope.get("CloudTrailEvent")
        if not isinstance(raw, str):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID")
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID") from exc
        if not isinstance(event, Mapping):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID")
        response = event.get("responseElements")
        if isinstance(response, Mapping) and response.get("id") == change_set_arn:
            matches.append((envelope, event))
    if len(matches) != 1:
        raise ChangeSetHandoffError("CLOUDTRAIL_CREATE_EVENT_NOT_UNIQUE")
    envelope, event = matches[0]
    request = event.get("requestParameters")
    identity = event.get("userIdentity")
    expected_request = {
        "stackName": stack_name,
        "changeSetName": change_set_name,
        "changeSetType": "CREATE",
        "description": f"GUG-221 reviewed {change_set_name}",
        "templateBody": reviewed_template_bytes.decode("utf-8"),
        "parameters": _cloudtrail_parameters(parameters),
        "capabilities": list(EXPECTED_CAPABILITIES),
        "notificationARNs": [],
        "rollbackConfiguration": {
            "rollbackTriggers": [],
            "monitoringTimeInMinutes": 0,
        },
        "includeNestedStacks": False,
        "importExistingResources": False,
        "onStackFailure": "ROLLBACK",
        "tags": _cloudtrail_tags(tags),
    }
    event_time = envelope.get("EventTime")
    if isinstance(event_time, str):
        event_time = _timestamp(event_time, "CLOUDTRAIL_EVENT_TIME_INVALID")
    if (
        event.get("eventSource") != "cloudformation.amazonaws.com"
        or event.get("eventName") != "CreateChangeSet"
        or event.get("eventCategory") != "Management"
        or event.get("awsRegion") != REGION
        or event.get("recipientAccountId") != account_id
        or event.get("readOnly") is not False
        or not isinstance(identity, Mapping)
        or identity.get("arn") != creator_arn
        or request != expected_request
        or "roleARN" in request
        or "roleArn" in request
        or "deploymentMode" in request
        or not isinstance(event_time, datetime)
        or abs((event_time - creation_time).total_seconds()) > 300
        or not isinstance(envelope.get("EventId"), str)
        or not envelope.get("EventId")
    ):
        raise ChangeSetHandoffError("CLOUDTRAIL_CREATE_EVENT_DRIFT")
    return {
        "event_id": str(envelope["EventId"]),
        "event_time": _utc_text(event_time),
        "event_digest": _digest(event),
    }


def _verify_exact_change_set(
    *,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    account_id: str,
    creator_arn: str,
    change_set_arn: str,
    change_set_name: str,
    stack_name: str,
    change_set_arn_re: re.Pattern[str],
    stack_arn_re: re.Pattern[str],
    reviewed_template_bytes: bytes,
    expected_parameter_keys: tuple[str, ...],
    parameters: Sequence[Mapping[str, str]],
    tags: Mapping[str, str],
) -> Mapping[str, Any]:
    first, changes = _read_change_set_pages(
        cloudformation_client=cloudformation_client,
        change_set_arn=change_set_arn,
        change_set_name=change_set_name,
        stack_name=stack_name,
        change_set_arn_re=change_set_arn_re,
        stack_arn_re=stack_arn_re,
    )
    stack_arn, change_uuid = _core_change_set_metadata(
        first,
        change_set_arn=change_set_arn,
        change_set_name=change_set_name,
        stack_name=stack_name,
        change_set_arn_re=change_set_arn_re,
        stack_arn_re=stack_arn_re,
    )
    creation_time = first.get("CreationTime")
    if not isinstance(creation_time, datetime) or creation_time.tzinfo is None:
        raise ChangeSetHandoffError("CHANGE_SET_CREATION_TIME_INVALID")
    expected_parameters = {
        item["ParameterKey"]: item["ParameterValue"] for item in parameters
    }
    actual_parameters = _normalize_parameters(
        first.get("Parameters"), expected_keys=expected_parameter_keys
    )
    if actual_parameters != expected_parameters:
        raise ChangeSetHandoffError("CHANGE_SET_PARAMETER_DRIFT")
    if _normalize_tags(first.get("Tags")) != tags:
        raise ChangeSetHandoffError("CHANGE_SET_TAG_DRIFT")
    _, expected_resources = _template_contract(
        reviewed_template_bytes,
        expected_parameter_keys=expected_parameter_keys,
    )
    normalized_changes = _normalize_changes(changes, expected_resources=expected_resources)
    template_response = _aws_call(
        cloudformation_client.get_template,
        ChangeSetName=change_set_arn,
        StackName=stack_arn,
        TemplateStage="Original",
    )
    body = template_response.get("TemplateBody")
    if not isinstance(body, str) or body.encode("utf-8") != reviewed_template_bytes:
        raise ChangeSetHandoffError("CHANGE_SET_TEMPLATE_DRIFT")
    event = _verify_create_change_set_event(
        cloudtrail_client=cloudtrail_client,
        account_id=account_id,
        creator_arn=creator_arn,
        change_set_arn=change_set_arn,
        change_set_name=change_set_name,
        stack_name=stack_name,
        reviewed_template_bytes=reviewed_template_bytes,
        parameters=parameters,
        tags=tags,
        creation_time=creation_time,
    )
    return {
        "arn": change_set_arn,
        "uuid": change_uuid,
        "name": change_set_name,
        "stack_arn": stack_arn,
        "stack_name": stack_name,
        "type": "CREATE",
        "status": "CREATE_COMPLETE",
        "execution_status": "AVAILABLE",
        "on_stack_failure": "ROLLBACK",
        "capabilities": list(EXPECTED_CAPABILITIES),
        "tags": dict(tags),
        "parameters_sha256": _digest(parameters),
        "resource_changes": normalized_changes,
        "create_event": event,
    }


def _validate_phase_b_precondition_change_set_projection(
    change_set: Mapping[str, Any],
    *,
    parameter_handoff: Mapping[str, Any],
) -> None:
    if not isinstance(change_set, Mapping):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_INVALID"
        )
    arn_match = _PHASE_B_PRECONDITION_CHANGE_SET_ARN_RE.fullmatch(
        str(change_set.get("arn"))
    )
    stack_match = _PHASE_B_PRECONDITION_STACK_ARN_RE.fullmatch(
        str(change_set.get("stack_arn"))
    )
    expected_changes = [
        {
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "action": "Add",
            "replacement": "False",
        }
        for logical_id, resource_type in sorted(
            PHASE_B_PRECONDITION_RESOURCE_TYPES.items()
        )
    ]
    create_event = change_set.get("create_event")
    if (
        set(change_set)
        != {
            "arn",
            "uuid",
            "name",
            "stack_arn",
            "stack_name",
            "type",
            "status",
            "execution_status",
            "on_stack_failure",
            "capabilities",
            "tags",
            "parameters_sha256",
            "resource_changes",
            "create_event",
        }
        or arn_match is None
        or stack_match is None
        or change_set.get("uuid") != arn_match.group("uuid")
        or change_set.get("name")
        != PHASE_B_PRECONDITION_CHANGE_SET_NAME
        or change_set.get("stack_name") != PHASE_B_PRECONDITION_STACK_NAME
        or change_set.get("type") != "CREATE"
        or change_set.get("status") != "CREATE_COMPLETE"
        or change_set.get("execution_status") != "AVAILABLE"
        or change_set.get("on_stack_failure") != "ROLLBACK"
        or change_set.get("capabilities") != list(EXPECTED_CAPABILITIES)
        or change_set.get("tags") != parameter_handoff.get("stack_tags")
        or change_set.get("parameters_sha256")
        != parameter_handoff.get("parameters_sha256")
        or change_set.get("resource_changes") != expected_changes
        or not isinstance(create_event, Mapping)
        or set(create_event) != {"event_id", "event_time", "event_digest"}
        or not isinstance(create_event.get("event_id"), str)
        or not create_event.get("event_id")
        or _DIGEST_RE.fullmatch(str(create_event.get("event_digest"))) is None
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_INVALID"
        )
    _timestamp(
        create_event.get("event_time"),
        "PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_TIME_INVALID",
    )


def validate_phase_b_precondition_change_set_receipt(
    *,
    receipt: Mapping[str, Any],
    parameter_handoff: Mapping[str, Any],
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> None:
    validate_phase_b_precondition_parameter_handoff(
        handoff=parameter_handoff,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    change_set = receipt.get("change_set")
    verifier = receipt.get("verifier")
    stable = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt)
        != {
            "artifact_type",
            "schema_version",
            "work_package",
            "phase",
            "source_commit",
            "signed_artifact_receipt_sha256",
            "reviewed_package_manifest_sha256",
            "phase_b_identity_materialization_receipt_sha256",
            "pep_parameter_handoff_sha256",
            "pep_change_set_receipt_sha256",
            "parameter_handoff_sha256",
            "reviewed_template_sha256",
            "reviewed_policy_sha256",
            "broker_topology_sha256",
            "change_set",
            "verifier",
            "evaluated_at",
            "evidence_status",
            "authority_status",
            "production_status",
            "receipt_digest",
        }
        or receipt.get("artifact_type")
        != PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "PRE_B_BROKER_CHANGE_SET"
        or receipt.get("source_commit")
        != parameter_handoff.get("source_commit")
        or receipt.get("signed_artifact_receipt_sha256")
        != parameter_handoff.get("signed_artifact_receipt_sha256")
        or receipt.get("reviewed_package_manifest_sha256")
        != parameter_handoff.get("reviewed_package_manifest_sha256")
        or receipt.get("phase_b_identity_materialization_receipt_sha256")
        != parameter_handoff.get(
            "phase_b_identity_materialization_receipt_sha256"
        )
        or receipt.get("pep_parameter_handoff_sha256")
        != parameter_handoff.get("pep_parameter_handoff_sha256")
        or receipt.get("pep_change_set_receipt_sha256")
        != parameter_handoff.get("pep_change_set_receipt_sha256")
        or receipt.get("parameter_handoff_sha256")
        != _digest(parameter_handoff)
        or receipt.get("reviewed_template_sha256")
        != parameter_handoff.get("reviewed_template_sha256")
        or receipt.get("reviewed_policy_sha256")
        != parameter_handoff.get("reviewed_policy_sha256")
        or receipt.get("broker_topology_sha256")
        != parameter_handoff.get("broker_topology_sha256")
        or not isinstance(change_set, Mapping)
        or not isinstance(verifier, Mapping)
        or set(verifier) != {"profile", "account_id", "caller_arn"}
        or verifier.get("profile") != EXPECTED_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn")))
        is None
        or receipt.get("evidence_status")
        != "PRE_B_CHANGE_SET_READ_ONLY_VERIFIED"
        or receipt.get("authority_status")
        != "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("receipt_digest") != _digest(stable)
    ):
        raise ChangeSetHandoffError(
            "PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_INVALID"
        )
    _timestamp(
        receipt.get("evaluated_at"),
        "PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_TIME_INVALID",
    )
    _validate_phase_b_precondition_change_set_projection(
        change_set,
        parameter_handoff=parameter_handoff,
    )


def verify_phase_b_precondition_change_set_read_only(
    *,
    source_root: Path,
    profile_name: str,
    region: str,
    change_set_arn: str,
    parameter_handoff: Mapping[str, Any],
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    sts_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Verify the already-created 9-resource precondition Change Set."""

    validate_phase_b_precondition_parameter_handoff(
        handoff=parameter_handoff,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    if profile_name != EXPECTED_PROFILE or region != REGION:
        raise ChangeSetHandoffError("VERIFIER_PROFILE_OR_REGION_INVALID")
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise ChangeSetHandoffError("VERIFIER_IDENTITY_INVALID")
    change_set = _verify_exact_change_set(
        cloudformation_client=cloudformation_client,
        cloudtrail_client=cloudtrail_client,
        account_id=AUTHORITY_ACCOUNT_ID,
        creator_arn=str(deployment_contract["pep_change_set_creator_arn"]),
        change_set_arn=change_set_arn,
        change_set_name=PHASE_B_PRECONDITION_CHANGE_SET_NAME,
        stack_name=PHASE_B_PRECONDITION_STACK_NAME,
        change_set_arn_re=_PHASE_B_PRECONDITION_CHANGE_SET_ARN_RE,
        stack_arn_re=_PHASE_B_PRECONDITION_STACK_ARN_RE,
        reviewed_template_bytes=reviewed_template_bytes,
        expected_parameter_keys=PHASE_B_PRECONDITION_PARAMETER_KEYS,
        parameters=parameter_handoff["parameters"],
        tags=parameter_handoff["stack_tags"],
    )
    result = {
        "artifact_type": (
            PHASE_B_PRECONDITION_CHANGE_SET_RECEIPT_TYPE
        ),
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "PRE_B_BROKER_CHANGE_SET",
        "source_commit": parameter_handoff["source_commit"],
        "signed_artifact_receipt_sha256": parameter_handoff[
            "signed_artifact_receipt_sha256"
        ],
        "reviewed_package_manifest_sha256": parameter_handoff[
            "reviewed_package_manifest_sha256"
        ],
        "phase_b_identity_materialization_receipt_sha256": (
            parameter_handoff[
                "phase_b_identity_materialization_receipt_sha256"
            ]
        ),
        "pep_parameter_handoff_sha256": parameter_handoff[
            "pep_parameter_handoff_sha256"
        ],
        "pep_change_set_receipt_sha256": parameter_handoff[
            "pep_change_set_receipt_sha256"
        ],
        "parameter_handoff_sha256": _digest(parameter_handoff),
        "reviewed_template_sha256": parameter_handoff[
            "reviewed_template_sha256"
        ],
        "reviewed_policy_sha256": parameter_handoff[
            "reviewed_policy_sha256"
        ],
        "broker_topology_sha256": parameter_handoff[
            "broker_topology_sha256"
        ],
        "change_set": change_set,
        "verifier": {
            "profile": profile_name,
            "account_id": identity["Account"],
            "caller_arn": identity["Arn"],
        },
        "evaluated_at": _utc_text(now),
        "evidence_status": "PRE_B_CHANGE_SET_READ_ONLY_VERIFIED",
        "authority_status": (
            "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY"
        ),
        "production_status": PRODUCTION_STATUS,
    }
    result["receipt_digest"] = _digest(result)
    validate_phase_b_precondition_change_set_receipt(
        receipt=result,
        parameter_handoff=parameter_handoff,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    return result


def validate_phase_b_execution_preconditions(
    *,
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    reviewed_phase_b_precondition_template_bytes: bytes,
) -> None:
    """Validate the complete PRE_B chain before any effect/readback client."""

    validate_phase_b_identity_materialization_receipt(
        phase_b_identity_materialization_receipt,
        source_commit=str(deployment_contract.get("source_commit")),
    )
    validate_phase_b_precondition_change_set_receipt(
        receipt=phase_b_precondition_change_set_receipt,
        parameter_handoff=phase_b_precondition_parameter_handoff,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        reviewed_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
    )


def verify_delegation_change_set_read_only(
    *,
    source_root: Path,
    profile_name: str,
    authority_profile_name: str,
    region: str,
    change_set_arn: str,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    parameter_handoff: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    sts_client: Any,
    management_sso_admin_client: Any,
    management_identitystore_client: Any,
    management_kms_client: Any,
    management_organizations_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    authority_sts_client: Any,
    authority_iam_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Phase A: verify only the delegation CREATE Change Set."""

    if profile_name != EXPECTED_MANAGEMENT_PROFILE or region != REGION:
        raise ChangeSetHandoffError("MANAGEMENT_VERIFIER_PROFILE_OR_REGION_INVALID")
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise ChangeSetHandoffError("MANAGEMENT_VERIFIER_IDENTITY_INVALID")
    fresh_gug220_evidence = collect_gug220_live_evidence_read_only(
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        management_profile_name=profile_name,
        authority_profile_name=authority_profile_name,
        region=region,
        management_sts_client=sts_client,
        management_sso_admin_client=management_sso_admin_client,
        management_identitystore_client=management_identitystore_client,
        management_kms_client=management_kms_client,
        management_organizations_client=management_organizations_client,
        authority_sts_client=authority_sts_client,
        authority_iam_client=authority_iam_client,
        now=now,
    )
    _require_fresh_gug220_evidence(
        supplied=gug220_evidence,
        fresh=fresh_gug220_evidence,
        validation_kwargs={
            "source_root": source_root,
            "deployment_contract": deployment_contract,
            "intent": gug220_intent,
            "ledger": gug220_ledger,
            "receipt": gug220_receipt,
        },
    )
    validate_delegation_parameter_handoff(
        handoff=parameter_handoff,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_template_bytes=reviewed_template_bytes,
    )
    change_set = _verify_exact_change_set(
        cloudformation_client=cloudformation_client,
        cloudtrail_client=cloudtrail_client,
        account_id=MANAGEMENT_ACCOUNT_ID,
        creator_arn=str(deployment_contract["delegation_change_set_creator_arn"]),
        change_set_arn=change_set_arn,
        change_set_name=DELEGATION_CHANGE_SET_NAME,
        stack_name=DELEGATION_STACK_NAME,
        change_set_arn_re=_DELEGATION_CHANGE_SET_ARN_RE,
        stack_arn_re=_DELEGATION_STACK_ARN_RE,
        reviewed_template_bytes=reviewed_template_bytes,
        expected_parameter_keys=DELEGATION_PARAMETER_KEYS,
        parameters=parameter_handoff["parameters"],
        tags=parameter_handoff["stack_tags"],
    )
    deployment_contract_sha256 = _digest(deployment_contract)
    parameter_handoff_sha256 = _digest(parameter_handoff)
    template_sha256 = sha256(reviewed_template_bytes).hexdigest()
    execution_contract = _delegation_execution_contract(
        source_commit=str(deployment_contract["source_commit"]),
        deployment_contract_sha256=deployment_contract_sha256,
        parameter_handoff_sha256=parameter_handoff_sha256,
        template_sha256=template_sha256,
        change_set=change_set,
        executor_arn=str(deployment_contract["delegation_change_set_executor_arn"]),
    )
    return {
        "artifact_type": DELEGATION_CHANGE_SET_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "A_DELEGATION_CHANGE_SET",
        "source_commit": deployment_contract["source_commit"],
        "deployment_contract_sha256": deployment_contract_sha256,
        "gug220_intent_sha256": _digest(gug220_intent),
        "gug220_ledger_sha256": _digest(gug220_ledger),
        "gug220_receipt_sha256": _digest(gug220_receipt),
        "gug220_evidence_sha256": _digest(gug220_evidence),
        "gug220_provider_state_sha256": fresh_gug220_evidence[
            "provider_state_sha256"
        ],
        "parameter_handoff_sha256": parameter_handoff_sha256,
        "template_sha256": template_sha256,
        "change_set": change_set,
        "execution_contract": execution_contract,
        "verifier": {
            "profile": profile_name,
            "account_id": identity["Account"],
            "caller_arn": identity["Arn"],
        },
        "evaluated_at": _utc_text(now),
        "evidence_status": "DELEGATION_CHANGE_SET_READ_ONLY_VERIFIED",
        "authority_status": "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY",
        "production_status": PRODUCTION_STATUS,
    }


def _delegation_execution_contract(
    *,
    source_commit: str,
    deployment_contract_sha256: str,
    parameter_handoff_sha256: str,
    template_sha256: str,
    change_set: Mapping[str, Any],
    executor_arn: str,
) -> Mapping[str, str]:
    """Derive the exact, non-secret ExecuteChangeSet request binding.

    The token is deterministic over the reviewed provider receipt rather than
    operator input. This function derives evidence only; it never executes a
    Change Set.
    """

    token_payload = {
        "work_package": WORK_PACKAGE,
        "phase": "A_DELEGATION_EXECUTION",
        "source_commit": source_commit,
        "deployment_contract_sha256": deployment_contract_sha256,
        "parameter_handoff_sha256": parameter_handoff_sha256,
        "template_sha256": template_sha256,
        "change_set_sha256": _digest(change_set),
    }
    client_request_token = "gug221-a-" + _digest(token_payload)[:48]
    request = {
        "changeSetName": change_set.get("arn"),
        "stackName": change_set.get("stack_arn"),
        "clientRequestToken": client_request_token,
    }
    return {
        "client_request_token": client_request_token,
        "client_request_token_sha256": sha256(
            client_request_token.encode("utf-8")
        ).hexdigest(),
        "execute_request_sha256": _digest(request),
        "executor_arn_sha256": sha256(executor_arn.encode("utf-8")).hexdigest(),
    }


def _pep_execution_contract(
    *,
    source_commit: str,
    deployment_contract_sha256: str,
    parameter_handoff_sha256: str,
    phase_b_identity_materialization_receipt_sha256: str,
    template_sha256: str,
    change_set: Mapping[str, Any],
) -> Mapping[str, str]:
    """Derive the immutable base execution binding without a PRE_B cycle.

    Broker topology is intentionally absent here.  It is derived only after
    this reviewed Change Set receipt exists and is then bound by the mandatory
    PRE_B handoff and PRE_B Change Set receipt.
    """

    if _DIGEST_RE.fullmatch(
        phase_b_identity_materialization_receipt_sha256
    ) is None:
        raise ChangeSetHandoffError("PEP_BROKER_BINDING_INVALID")
    effect_principal_arn = PHASE_B_BROKER_EXECUTION_ROLE_ARN
    token_payload = {
        "work_package": WORK_PACKAGE,
        "phase": "B_PEP_EXECUTION",
        "source_commit": source_commit,
        "deployment_contract_sha256": deployment_contract_sha256,
        "parameter_handoff_sha256": parameter_handoff_sha256,
        "phase_b_identity_materialization_receipt_sha256": (
            phase_b_identity_materialization_receipt_sha256
        ),
        "template_sha256": template_sha256,
        "change_set_sha256": _digest(change_set),
        "effect_principal_arn_sha256": sha256(
            effect_principal_arn.encode("utf-8")
        ).hexdigest(),
    }
    client_request_token = "gug221-b-" + _digest(token_payload)[:48]
    request = {
        "changeSetName": change_set.get("arn"),
        "stackName": change_set.get("stack_arn"),
        "clientRequestToken": client_request_token,
    }
    return {
        "client_request_token": client_request_token,
        "client_request_token_sha256": sha256(
            client_request_token.encode("utf-8")
        ).hexdigest(),
        "execute_request_sha256": _digest(request),
        "effect_principal_arn_sha256": sha256(
            effect_principal_arn.encode("utf-8")
        ).hexdigest(),
        "phase_b_identity_materialization_receipt_sha256": (
            phase_b_identity_materialization_receipt_sha256
        ),
    }


def _validate_delegation_change_set_receipt_binding(
    *,
    receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validate fields needed after CloudFormation consumes the Change Set."""

    validate_deployment_contract(deployment_contract)
    required = {
        "artifact_type", "schema_version", "work_package", "phase",
        "source_commit", "deployment_contract_sha256", "gug220_intent_sha256",
        "gug220_ledger_sha256", "gug220_receipt_sha256",
        "gug220_evidence_sha256", "gug220_provider_state_sha256",
        "parameter_handoff_sha256", "template_sha256", "change_set",
        "execution_contract", "verifier", "evaluated_at", "evidence_status",
        "authority_status", "production_status",
    }
    change_set = receipt.get("change_set")
    verifier = receipt.get("verifier")
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type") != DELEGATION_CHANGE_SET_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "A_DELEGATION_CHANGE_SET"
        or receipt.get("source_commit") != deployment_contract["source_commit"]
        or receipt.get("deployment_contract_sha256") != _digest(deployment_contract)
        or any(
            _DIGEST_RE.fullmatch(str(receipt.get(field))) is None
            for field in (
                "gug220_intent_sha256", "gug220_ledger_sha256",
                "gug220_receipt_sha256", "gug220_evidence_sha256",
                "gug220_provider_state_sha256", "parameter_handoff_sha256",
                "template_sha256",
            )
        )
        or not isinstance(change_set, Mapping)
        or not isinstance(verifier, Mapping)
        or verifier.get("profile") != EXPECTED_MANAGEMENT_PROFILE
        or verifier.get("account_id") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
        or receipt.get("evidence_status")
        != "DELEGATION_CHANGE_SET_READ_ONLY_VERIFIED"
        or receipt.get("authority_status")
        != "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        raise ChangeSetHandoffError("DELEGATION_CHANGE_SET_RECEIPT_INVALID")
    expected_change_keys = {
        "arn", "uuid", "name", "stack_arn", "stack_name", "type", "status",
        "execution_status", "on_stack_failure", "capabilities", "tags",
        "parameters_sha256", "resource_changes", "create_event",
    }
    arn_match = _DELEGATION_CHANGE_SET_ARN_RE.fullmatch(str(change_set.get("arn")))
    stack_match = _DELEGATION_STACK_ARN_RE.fullmatch(str(change_set.get("stack_arn")))
    create_event = change_set.get("create_event")
    expected_changes = [
        {
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "action": "Add",
            "replacement": "False",
        }
        for logical_id, resource_type in sorted(
            {
                "MutationServiceRole": "AWS::IAM::Role",
                "ReadbackServiceRole": "AWS::IAM::Role",
                "RepairInvokerAssignment": "AWS::SSO::Assignment",
                "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
            }.items()
        )
    ]
    if (
        set(change_set) != expected_change_keys
        or arn_match is None
        or stack_match is None
        or change_set.get("uuid") != arn_match.group("uuid")
        or change_set.get("name") != DELEGATION_CHANGE_SET_NAME
        or change_set.get("stack_name") != DELEGATION_STACK_NAME
        or change_set.get("type") != "CREATE"
        or change_set.get("status") != "CREATE_COMPLETE"
        or change_set.get("execution_status") != "AVAILABLE"
        or change_set.get("on_stack_failure") != "ROLLBACK"
        or change_set.get("capabilities") != list(EXPECTED_CAPABILITIES)
        or change_set.get("tags")
        != _permission_set_tags(str(deployment_contract["source_commit"]))
        or _DIGEST_RE.fullmatch(str(change_set.get("parameters_sha256"))) is None
        or change_set.get("resource_changes") != expected_changes
        or not isinstance(create_event, Mapping)
        or set(create_event) != {"event_id", "event_time", "event_digest"}
        or not isinstance(create_event.get("event_id"), str)
        or not create_event.get("event_id")
        or _DIGEST_RE.fullmatch(str(create_event.get("event_digest"))) is None
    ):
        raise ChangeSetHandoffError("DELEGATION_CHANGE_SET_RECEIPT_INVALID")
    _timestamp(
        create_event.get("event_time"),
        "DELEGATION_CHANGE_SET_RECEIPT_TIME_INVALID",
    )
    _timestamp(
        receipt.get("evaluated_at"),
        "DELEGATION_CHANGE_SET_RECEIPT_TIME_INVALID",
    )
    expected_execution = _delegation_execution_contract(
        source_commit=str(receipt["source_commit"]),
        deployment_contract_sha256=str(receipt["deployment_contract_sha256"]),
        parameter_handoff_sha256=str(receipt["parameter_handoff_sha256"]),
        template_sha256=str(receipt["template_sha256"]),
        change_set=change_set,
        executor_arn=str(deployment_contract["delegation_change_set_executor_arn"]),
    )
    if receipt.get("execution_contract") != expected_execution:
        raise ChangeSetHandoffError("DELEGATION_EXECUTION_CONTRACT_INVALID")
    return change_set


def validate_delegation_change_set_receipt(
    *,
    receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    parameter_handoff: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> Mapping[str, Any]:
    change_set = _validate_delegation_change_set_receipt_binding(
        receipt=receipt,
        deployment_contract=deployment_contract,
    )
    if (
        receipt.get("gug220_intent_sha256") != _digest(gug220_intent)
        or receipt.get("gug220_ledger_sha256") != _digest(gug220_ledger)
        or receipt.get("gug220_receipt_sha256") != _digest(gug220_receipt)
        or receipt.get("gug220_evidence_sha256") != _digest(gug220_evidence)
        or receipt.get("gug220_provider_state_sha256")
        != gug220_evidence.get("provider_state_sha256")
        or receipt.get("parameter_handoff_sha256") != _digest(parameter_handoff)
        or receipt.get("template_sha256")
        != sha256(reviewed_template_bytes).hexdigest()
    ):
        raise ChangeSetHandoffError("DELEGATION_CHANGE_SET_RECEIPT_CHAIN_INVALID")
    return change_set


def _paginate_next_token(
    client: Any, method_name: str, result_key: str, **kwargs: Any
) -> list[Any]:
    values: list[Any] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request = dict(kwargs)
        if token is not None:
            request["NextToken"] = token
        response = _aws_call(getattr(client, method_name), **request)
        page = response.get(result_key)
        if not isinstance(page, list):
            raise ChangeSetHandoffError("PROVIDER_PAGINATION_INVALID")
        values.extend(page)
        next_token = response.get("NextToken")
        if next_token is None:
            return values
        if not isinstance(next_token, str) or not next_token or next_token in seen:
            raise ChangeSetHandoffError("PROVIDER_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    raise ChangeSetHandoffError("PROVIDER_PAGINATION_EXCEEDED")


def _provider_datetime(value: Any, code: str) -> datetime:
    if isinstance(value, str):
        return _timestamp(value, code)
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ChangeSetHandoffError(code)
    return value.astimezone(UTC)


def _verify_execute_change_set_event(
    *,
    cloudtrail_client: Any,
    deployment_contract: Mapping[str, Any],
    change_set_receipt: Mapping[str, Any],
    stack_creation_time: datetime,
    verification_time: datetime,
) -> Mapping[str, str]:
    change_set = _validate_delegation_change_set_receipt_binding(
        receipt=change_set_receipt,
        deployment_contract=deployment_contract,
    )
    execution = change_set_receipt["execution_contract"]
    create_event_time = _timestamp(
        change_set["create_event"]["event_time"],
        "DELEGATION_CHANGE_SET_RECEIPT_TIME_INVALID",
    )
    if (
        verification_time.tzinfo is None
        or verification_time.utcoffset() is None
        or verification_time < create_event_time
        or stack_creation_time < create_event_time - timedelta(minutes=5)
        or stack_creation_time > verification_time
    ):
        raise ChangeSetHandoffError("CLOUDTRAIL_EXECUTION_WINDOW_INVALID")
    verification_time = verification_time.astimezone(UTC)
    expected_request = {
        "changeSetName": change_set["arn"],
        "stackName": change_set["stack_arn"],
        "clientRequestToken": execution["client_request_token"],
    }
    if execution["execute_request_sha256"] != _digest(expected_request):
        raise ChangeSetHandoffError("DELEGATION_EXECUTION_CONTRACT_INVALID")
    events: list[Mapping[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request: dict[str, Any] = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "ExecuteChangeSet"}
            ],
            "StartTime": create_event_time - timedelta(minutes=5),
            "EndTime": verification_time + timedelta(minutes=5),
        }
        if token is not None:
            request["NextToken"] = token
        response = _aws_call(cloudtrail_client.lookup_events, **request)
        page = response.get("Events")
        if not isinstance(page, list) or any(
            not isinstance(item, Mapping) for item in page
        ):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_PAGE_INVALID")
        events.extend(page)
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token in seen:
            raise ChangeSetHandoffError("CLOUDTRAIL_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    else:
        raise ChangeSetHandoffError("CLOUDTRAIL_PAGINATION_EXCEEDED")

    matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for envelope in events:
        raw = envelope.get("CloudTrailEvent")
        if not isinstance(raw, str):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID")
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID") from exc
        if not isinstance(event, Mapping):
            raise ChangeSetHandoffError("CLOUDTRAIL_EVENT_INVALID")
        request = event.get("requestParameters")
        if (
            isinstance(request, Mapping)
            and request.get("clientRequestToken")
            == execution["client_request_token"]
        ):
            matches.append((envelope, event))
    if len(matches) != 1:
        raise ChangeSetHandoffError("CLOUDTRAIL_EXECUTE_EVENT_NOT_UNIQUE")
    envelope, event = matches[0]
    identity = event.get("userIdentity")
    event_time = _provider_datetime(
        envelope.get("EventTime"), "CLOUDTRAIL_EVENT_TIME_INVALID"
    )
    if (
        event.get("eventSource") != "cloudformation.amazonaws.com"
        or event.get("eventName") != "ExecuteChangeSet"
        or event.get("eventCategory") != "Management"
        or event.get("awsRegion") != REGION
        or event.get("recipientAccountId") != MANAGEMENT_ACCOUNT_ID
        or event.get("readOnly") is not False
        or not isinstance(identity, Mapping)
        or identity.get("arn")
        != deployment_contract["delegation_change_set_executor_arn"]
        or event.get("requestParameters") != expected_request
        or event.get("errorCode") not in (None, "")
        or event.get("errorMessage") not in (None, "")
        or event_time < create_event_time
        or event_time < stack_creation_time
        or event_time > verification_time
        or not isinstance(envelope.get("EventId"), str)
        or not envelope.get("EventId")
    ):
        raise ChangeSetHandoffError("CLOUDTRAIL_EXECUTE_EVENT_DRIFT")
    return {
        "event_id": str(envelope["EventId"]),
        "event_time": _utc_text(event_time),
        "event_digest": _digest(event),
    }


def _validate_phase_b_broker_effect_receipt(
    *,
    receipt: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
) -> str:
    """Validate the private broker result before trusting provider traces.

    The broker receipt is never copied into a durable CloudFormation receipt.
    Only its canonical digest crosses the readback boundary.
    """

    execution = pep_change_set_receipt.get("execution_contract")
    change_set = pep_change_set_receipt.get("change_set")
    precondition_parameters = _normalize_parameters(
        phase_b_precondition_parameter_handoff.get("parameters"),
        expected_keys=PHASE_B_PRECONDITION_PARAMETER_KEYS,
    )
    if (
        phase_b_precondition_change_set_receipt.get(
            "parameter_handoff_sha256"
        )
        != _digest(phase_b_precondition_parameter_handoff)
        or phase_b_precondition_change_set_receipt.get(
            "pep_change_set_receipt_sha256"
        )
        != _digest(pep_change_set_receipt)
        or phase_b_precondition_change_set_receipt.get(
            "broker_topology_sha256"
        )
        != phase_b_precondition_parameter_handoff.get(
            "broker_topology_sha256"
        )
        or phase_b_precondition_change_set_receipt.get("receipt_digest")
        != _digest(
            {
                key: value
                for key, value in phase_b_precondition_change_set_receipt.items()
                if key != "receipt_digest"
            }
        )
    ):
        raise ChangeSetHandoffError(
            "PEP_PHASE_B_PRECONDITION_BINDING_INVALID"
        )
    required = {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "execution_id",
        "binding_digest",
        "proof_receipt_digest",
        "ledger_digest",
        "closure_pending_receipt_digest",
        "execution_request_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "stack_arn",
        "change_set_arn",
        "client_request_token",
        "effect_principal_type",
        "effect_principal_arn",
        "proof_credentials_used_for_effect",
        "attempts",
        "execution_ambiguous",
        "retry_permitted",
        "one_shot_execution_gate_consumed",
        "native_on_behalf_of",
        "provider_revocation_pending",
        "authority_revoked",
        "production_status",
        "receipt_digest",
    }
    stable = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or not isinstance(execution, Mapping)
        or not isinstance(change_set, Mapping)
        or receipt.get("schema_version") != "1"
        or receipt.get("record_type")
        != (
            "platform_authority_lambda_audit_repair_phase_b_"
            "broker_effect_receipt"
        )
        or receipt.get("environment") != "non-production"
        or receipt.get("production") is not False
        or receipt.get("status") != "DISPATCH_ACCEPTED"
        or _PREFIXED_DIGEST_RE.fullmatch(
            str(receipt.get("binding_digest"))
        )
        is None
        or any(
            _PREFIXED_DIGEST_RE.fullmatch(str(receipt.get(field))) is None
            for field in (
                "proof_receipt_digest",
                "ledger_digest",
                "closure_pending_receipt_digest",
                "execution_request_digest",
                "broker_topology_sha256",
                "broker_topology_provider_evidence_digest",
                "receipt_digest",
            )
        )
        or any(
            _DIGEST_RE.fullmatch(str(receipt.get(field))) is None
            for field in (
                "invoker_policy_sha256",
                "broker_policy_sha256",
                "proof_policy_sha256",
                "application_actor_policy_sha256",
            )
        )
        or receipt.get("execution_request_digest")
        != "sha256:" + str(execution.get("execute_request_sha256"))
        or receipt.get("broker_topology_sha256")
        != precondition_parameters["ExpectedBrokerTopologySha256"]
        or receipt.get("broker_topology_provider_evidence_digest")
        == "sha256:" + "0" * 64
        or any(
            receipt.get(receipt_field)
            != precondition_parameters[parameter_key]
            for receipt_field, parameter_key in (
                ("invoker_policy_sha256", "InvokerPolicySha256"),
                ("broker_policy_sha256", "BrokerPolicySha256"),
                ("proof_policy_sha256", "ProofPolicySha256"),
                (
                    "application_actor_policy_sha256",
                    "ApplicationActorPolicySha256",
                ),
            )
        )
        or receipt.get("stack_arn") != change_set.get("stack_arn")
        or receipt.get("change_set_arn") != change_set.get("arn")
        or receipt.get("client_request_token")
        != execution.get("client_request_token")
        or receipt.get("effect_principal_type") != "AWS_SERVICE_ROLE"
        or receipt.get("effect_principal_arn")
        != PHASE_B_BROKER_EXECUTION_ROLE_ARN
        or receipt.get("execution_id")
        != precondition_parameters["ExactExecutionId"]
        or receipt.get("proof_credentials_used_for_effect") is not False
        or receipt.get("attempts") != 1
        or receipt.get("execution_ambiguous") is not False
        or receipt.get("retry_permitted") is not False
        or receipt.get("one_shot_execution_gate_consumed") is not True
        or receipt.get("native_on_behalf_of") is not False
        or receipt.get("provider_revocation_pending") is not True
        or receipt.get("authority_revoked") is not False
        or receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("receipt_digest")
        != "sha256:" + plain_canonical_digest(stable)
    ):
        raise ChangeSetHandoffError("PEP_BROKER_EFFECT_RECEIPT_INVALID")
    execution_id = receipt.get("execution_id")
    if (
        not isinstance(execution_id, str)
        or re.fullmatch(r"gug221-phase-b-[0-9a-f]{64}", execution_id)
        is None
    ):
        raise ChangeSetHandoffError("PEP_BROKER_EFFECT_RECEIPT_INVALID")
    return _digest(receipt)


def _readback_phase_b_ledger_provider_state(
    *,
    dynamodb_client: Any,
    broker_effect_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    execute_event: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Read and bind the exact terminal one-shot ledger item."""

    execution_id = str(broker_effect_receipt.get("execution_id"))
    try:
        response = dynamodb_client.get_item(
            TableName=PHASE_B_LEDGER_TABLE_NAME,
            Key={"execution_id": {"S": execution_id}},
            ConsistentRead=True,
            ReturnConsumedCapacity="NONE",
        )
    except Exception:
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_UNCERTAIN") from None
    if not isinstance(response, Mapping) or not isinstance(
        response.get("Item"), Mapping
    ):
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_UNCERTAIN")
    item = response["Item"]
    string_fields = {
        "schema_version",
        "record_type",
        "environment",
        "execution_id",
        "binding_digest",
        "proof_receipt_digest",
        "execution_request_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "stack_arn",
        "change_set_arn",
        "client_request_token",
        "execution_not_before",
        "execution_not_after",
        "claimed_at",
        "terminal_at",
        "status",
        "ledger_digest",
        "closure_pending_receipt_digest",
        "closure_status",
    }
    boolean_fields = {
        "production",
        "execution_gate_consumed",
        "wall_clock_window_expired",
        "execution_ambiguous",
        "retry_permitted",
        "native_on_behalf_of",
    }
    required = string_fields | boolean_fields | {"attempts"}
    if set(item) != required:
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_INVALID")
    normalized: dict[str, Any] = {}
    for field in string_fields:
        value = item.get(field)
        if (
            not isinstance(value, Mapping)
            or set(value) != {"S"}
            or not isinstance(value.get("S"), str)
        ):
            raise ChangeSetHandoffError("PEP_LEDGER_READBACK_INVALID")
        normalized[field] = value["S"]
    for field in boolean_fields:
        value = item.get(field)
        if (
            not isinstance(value, Mapping)
            or set(value) != {"BOOL"}
            or not isinstance(value.get("BOOL"), bool)
        ):
            raise ChangeSetHandoffError("PEP_LEDGER_READBACK_INVALID")
        normalized[field] = value["BOOL"]
    attempts = item.get("attempts")
    if (
        not isinstance(attempts, Mapping)
        or set(attempts) != {"N"}
        or attempts.get("N") != "1"
    ):
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_INVALID")
    normalized["attempts"] = 1

    ledger_fields = required - {
        "closure_pending_receipt_digest",
        "closure_status",
    }
    stable_ledger = {
        key: normalized[key]
        for key in ledger_fields
        if key != "ledger_digest"
    }
    common_fields = {
        "execution_id",
        "binding_digest",
        "proof_receipt_digest",
        "execution_request_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "invoker_policy_sha256",
        "broker_policy_sha256",
        "proof_policy_sha256",
        "application_actor_policy_sha256",
        "stack_arn",
        "change_set_arn",
        "client_request_token",
        "status",
        "ledger_digest",
        "closure_pending_receipt_digest",
    }
    expected_execution_id = (
        "gug221-phase-b-"
        + plain_canonical_digest(
            {
                "phase": "B_PEP_EXECUTION",
                "execution_request_digest": normalized[
                    "execution_request_digest"
                ],
                "not_before": normalized["execution_not_before"],
                "not_after": normalized["execution_not_after"],
            }
        )
    )
    not_before = _timestamp(
        normalized["execution_not_before"], "PEP_LEDGER_READBACK_INVALID"
    )
    not_after = _timestamp(
        normalized["execution_not_after"], "PEP_LEDGER_READBACK_INVALID"
    )
    claimed_at = _timestamp(
        normalized["claimed_at"], "PEP_LEDGER_READBACK_INVALID"
    )
    terminal_at = _timestamp(
        normalized["terminal_at"], "PEP_LEDGER_READBACK_INVALID"
    )
    executed_at = _timestamp(
        str(execute_event.get("event_time")), "PEP_LEDGER_READBACK_INVALID"
    )
    if (
        any(
            normalized[field] != broker_effect_receipt.get(field)
            for field in common_fields
        )
        or normalized["execution_id"] != expected_execution_id
        or normalized["execution_not_before"]
        != deployment_contract.get("repair_not_before")
        or normalized["execution_not_after"]
        != deployment_contract.get("repair_not_after")
        or not_before >= not_after
        or claimed_at < not_before
        or claimed_at > executed_at
        or executed_at > terminal_at
        or terminal_at >= not_after
        or normalized["schema_version"] != "1"
        or normalized["record_type"]
        != (
            "platform_authority_lambda_audit_repair_phase_b_"
            "one_shot_execution_ledger"
        )
        or normalized["environment"] != "non-production"
        or normalized["production"] is not False
        or normalized["status"] != "DISPATCH_ACCEPTED"
        or normalized["attempts"] != 1
        or normalized["execution_gate_consumed"] is not True
        or normalized["wall_clock_window_expired"] is not False
        or normalized["execution_ambiguous"] is not False
        or normalized["retry_permitted"] is not False
        or normalized["native_on_behalf_of"] is not False
        or normalized["closure_status"] != "PROVIDER_REVOCATION_PENDING"
        or normalized["ledger_digest"]
        != "sha256:" + plain_canonical_digest(stable_ledger)
    ):
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_INVALID")

    readback = {
        "table_name_sha256": sha256(
            PHASE_B_LEDGER_TABLE_NAME.encode("utf-8")
        ).hexdigest(),
        "execution_id_sha256": sha256(execution_id.encode("utf-8")).hexdigest(),
        "binding_digest": normalized["binding_digest"],
        "proof_receipt_digest": normalized["proof_receipt_digest"],
        "ledger_digest": normalized["ledger_digest"],
        "closure_pending_receipt_digest": normalized[
            "closure_pending_receipt_digest"
        ],
        "execution_request_digest": normalized["execution_request_digest"],
        "broker_topology_sha256": normalized["broker_topology_sha256"],
        "broker_topology_provider_evidence_digest": normalized[
            "broker_topology_provider_evidence_digest"
        ],
        "status": normalized["status"],
        "attempts": normalized["attempts"],
        "execution_gate_consumed": normalized["execution_gate_consumed"],
        "execution_ambiguous": normalized["execution_ambiguous"],
        "retry_permitted": normalized["retry_permitted"],
        "native_on_behalf_of": normalized["native_on_behalf_of"],
        "closure_status": normalized["closure_status"],
    }
    return readback


def _verify_pep_execute_change_set_event(
    *,
    cloudtrail_client: Any,
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    broker_effect_receipt: Mapping[str, Any],
    stack_creation_time: datetime,
    verification_time: datetime,
) -> Mapping[str, str]:
    """Prove one exact Phase B execution event without performing a mutation."""

    change_set = _validate_pep_change_set_receipt_binding(
        receipt=change_set_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
    )
    execution = change_set_receipt["execution_contract"]
    create_event_time = _timestamp(
        change_set["create_event"]["event_time"],
        "PEP_CHANGE_SET_RECEIPT_TIME_INVALID",
    )
    repair_not_before = _timestamp(
        deployment_contract["repair_not_before"],
        "DEPLOYMENT_CONTRACT_WINDOW_INVALID",
    )
    repair_not_after = _timestamp(
        deployment_contract["repair_not_after"],
        "DEPLOYMENT_CONTRACT_WINDOW_INVALID",
    )
    if (
        verification_time.tzinfo is None
        or verification_time.utcoffset() is None
        or verification_time < create_event_time
        or stack_creation_time < create_event_time - timedelta(minutes=5)
        or stack_creation_time > verification_time
    ):
        raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EXECUTION_WINDOW_INVALID")
    verification_time = verification_time.astimezone(UTC)
    expected_request = {
        "changeSetName": change_set["arn"],
        "stackName": change_set["stack_arn"],
        "clientRequestToken": execution["client_request_token"],
    }
    if execution["execute_request_sha256"] != _digest(expected_request):
        raise ChangeSetHandoffError("PEP_EXECUTION_CONTRACT_INVALID")

    events: list[Mapping[str, Any]] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        request: dict[str, Any] = {
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "ExecuteChangeSet"}
            ],
            "StartTime": create_event_time - timedelta(minutes=5),
            "EndTime": verification_time + timedelta(minutes=5),
        }
        if token is not None:
            request["NextToken"] = token
        response = _aws_call(cloudtrail_client.lookup_events, **request)
        page = response.get("Events")
        if not isinstance(page, list) or any(
            not isinstance(item, Mapping) for item in page
        ):
            raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EVENT_PAGE_INVALID")
        events.extend(page)
        next_token = response.get("NextToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token in seen:
            raise ChangeSetHandoffError("PEP_CLOUDTRAIL_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    else:
        raise ChangeSetHandoffError("PEP_CLOUDTRAIL_PAGINATION_EXCEEDED")

    matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for envelope in events:
        raw = envelope.get("CloudTrailEvent")
        if not isinstance(raw, str):
            raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EVENT_INVALID")
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EVENT_INVALID") from exc
        if not isinstance(event, Mapping):
            raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EVENT_INVALID")
        request = event.get("requestParameters")
        if (
            isinstance(request, Mapping)
            and (
                request.get("clientRequestToken")
                == execution["client_request_token"]
                or request.get("changeSetName") == change_set["arn"]
            )
        ):
            matches.append((envelope, event))
    if len(matches) != 1:
        raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EXECUTE_EVENT_NOT_UNIQUE")

    _validate_phase_b_broker_effect_receipt(
        receipt=broker_effect_receipt,
        pep_change_set_receipt=change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
    )
    envelope, event = matches[0]
    identity = event.get("userIdentity")
    session_context = (
        identity.get("sessionContext") if isinstance(identity, Mapping) else None
    )
    session_issuer = (
        session_context.get("sessionIssuer")
        if isinstance(session_context, Mapping)
        else None
    )
    event_time = _provider_datetime(
        envelope.get("EventTime"), "PEP_CLOUDTRAIL_EVENT_TIME_INVALID"
    )
    if (
        event.get("eventSource") != "cloudformation.amazonaws.com"
        or event.get("eventName") != "ExecuteChangeSet"
        or event.get("eventCategory") != "Management"
        or event.get("awsRegion") != REGION
        or event.get("recipientAccountId") != AUTHORITY_ACCOUNT_ID
        or event.get("readOnly") is not False
        or not isinstance(identity, Mapping)
        or identity.get("type") != "AssumedRole"
        or identity.get("accountId") != AUTHORITY_ACCOUNT_ID
        or not isinstance(session_issuer, Mapping)
        or session_issuer.get("type") != "Role"
        or session_issuer.get("accountId") != AUTHORITY_ACCOUNT_ID
        or session_issuer.get("arn")
        != PHASE_B_BROKER_EXECUTION_ROLE_ARN
        or event.get("requestParameters") != expected_request
        or event.get("errorCode") not in (None, "")
        or event.get("errorMessage") not in (None, "")
        or event_time < create_event_time
        or event_time < stack_creation_time
        or event_time < repair_not_before
        or event_time >= repair_not_after
        or event_time > verification_time
        or not isinstance(envelope.get("EventId"), str)
        or not envelope.get("EventId")
    ):
        raise ChangeSetHandoffError("PEP_CLOUDTRAIL_EXECUTE_EVENT_DRIFT")
    return {
        "event_id": str(envelope["EventId"]),
        "event_time": _utc_text(event_time),
        "event_digest": _digest(event),
    }


def _verify_stack_operation_events(
    *,
    cloudformation_client: Any,
    stack_arn: str,
    client_request_token: str,
    execute_event_time: datetime,
    expected_resource_types: Mapping[str, str],
    stack_name: str = DELEGATION_STACK_NAME,
    error_prefix: str = "DELEGATION",
    require_progress_events: bool = False,
    include_stack_events: bool = False,
) -> Mapping[str, Any]:
    events = _paginate_next_token(
        cloudformation_client,
        "describe_stack_events",
        "StackEvents",
        StackName=stack_arn,
    )
    all_expected_types = {
        stack_name: "AWS::CloudFormation::Stack",
        **dict(expected_resource_types),
    }
    operation_events: list[dict[str, Any]] = []
    terminal: dict[str, dict[str, Any]] = {}
    progress: dict[str, list[dict[str, Any]]] = {}
    seen_event_ids: set[str] = set()
    for item in events:
        if not isinstance(item, Mapping):
            raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_INVALID")
        event_id = item.get("EventId")
        event_time = _provider_datetime(
            item.get("Timestamp"), f"{error_prefix}_STACK_EVENT_TIME_INVALID"
        )
        logical_id = item.get("LogicalResourceId")
        resource_type = item.get("ResourceType")
        status = item.get("ResourceStatus")
        token = item.get("ClientRequestToken")
        if (
            not isinstance(event_id, str)
            or not event_id
            or event_id in seen_event_ids
            or item.get("StackId") != stack_arn
            or item.get("StackName") != stack_name
            or not isinstance(logical_id, str)
            or not isinstance(resource_type, str)
            or not isinstance(status, str)
        ):
            raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_INVALID")
        seen_event_ids.add(event_id)
        if token != client_request_token:
            if not (
                logical_id == stack_name
                and resource_type == "AWS::CloudFormation::Stack"
                and status == "REVIEW_IN_PROGRESS"
                and event_time <= execute_event_time
            ):
                raise ChangeSetHandoffError(
                    f"{error_prefix}_STACK_EVENT_TOKEN_DRIFT"
                )
            continue
        if (
            event_time
            < (
                execute_event_time
                if require_progress_events
                else execute_event_time - timedelta(minutes=5)
            )
            or logical_id not in all_expected_types
            or resource_type != all_expected_types[logical_id]
            or status not in {"CREATE_IN_PROGRESS", "CREATE_COMPLETE"}
        ):
            raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_DRIFT")
        physical_id = item.get("PhysicalResourceId")
        if physical_id is not None and (
            not isinstance(physical_id, str) or not physical_id
        ):
            raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_DRIFT")
        normalized = {
            "event_id": event_id,
            "event_time": _utc_text(event_time),
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "resource_status": status,
            "physical_resource_id_sha256": (
                sha256(physical_id.encode("utf-8")).hexdigest()
                if isinstance(physical_id, str)
                else None
            ),
        }
        operation_events.append(normalized)
        if status == "CREATE_IN_PROGRESS":
            progress.setdefault(logical_id, []).append(normalized)
        else:
            if logical_id in terminal or physical_id is None:
                raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_DRIFT")
            terminal[logical_id] = normalized
    if set(terminal) != set(all_expected_types):
        raise ChangeSetHandoffError(
            f"{error_prefix}_STACK_TERMINAL_EVENT_MISSING"
        )
    if require_progress_events:
        if set(progress) != set(all_expected_types):
            raise ChangeSetHandoffError(
                f"{error_prefix}_STACK_PROGRESS_EVENT_MISSING"
            )
        for logical_id, progress_events in progress.items():
            terminal_time = _timestamp(
                terminal[logical_id]["event_time"],
                f"{error_prefix}_STACK_EVENT_TIME_INVALID",
            )
            if any(
                _timestamp(
                    event["event_time"],
                    f"{error_prefix}_STACK_EVENT_TIME_INVALID",
                )
                >= terminal_time
                for event in progress_events
            ):
                raise ChangeSetHandoffError(
                    f"{error_prefix}_STACK_EVENT_SEQUENCE_INVALID"
                )
    if terminal[stack_name]["physical_resource_id_sha256"] != sha256(
        stack_arn.encode("utf-8")
    ).hexdigest():
        raise ChangeSetHandoffError(
            f"{error_prefix}_STACK_TERMINAL_EVENT_DRIFT"
        )
    if len(operation_events) > 240:
        raise ChangeSetHandoffError(f"{error_prefix}_STACK_EVENT_COUNT_EXCEEDED")
    operation_events.sort(key=lambda item: (item["event_time"], item["event_id"]))
    terminal_resources = [terminal[key] for key in sorted(terminal)]
    result: dict[str, Any] = {
        "stack_event_count": len(operation_events),
        "stack_events_sha256": _digest(operation_events),
        "terminal_resources": terminal_resources,
    }
    if include_stack_events:
        token_sha256 = sha256(client_request_token.encode("utf-8")).hexdigest()
        stack_events = []
        for logical_id in sorted(all_expected_types):
            in_progress_events = sorted(
                (
                    {
                        "event_id": event["event_id"],
                        "event_time": event["event_time"],
                        "physical_resource_id_sha256": event[
                            "physical_resource_id_sha256"
                        ],
                    }
                    for event in progress.get(logical_id, [])
                ),
                key=lambda item: (item["event_time"], item["event_id"]),
            )
            complete = terminal[logical_id]
            stack_events.append(
                {
                    "logical_resource_id": logical_id,
                    "resource_type": all_expected_types[logical_id],
                    "client_request_token_sha256": token_sha256,
                    "in_progress_events": in_progress_events,
                    "complete_event": {
                        "event_id": complete["event_id"],
                        "event_time": complete["event_time"],
                        "physical_resource_id_sha256": complete[
                            "physical_resource_id_sha256"
                        ],
                    },
                }
            )
        result["stack_events"] = stack_events
        result["stack_events_sha256"] = _digest(stack_events)
    return result


def verify_delegation_execution_read_only(
    *,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_handoff: Mapping[str, Any],
    delegation_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    stack: Mapping[str, Any],
    verifier: Mapping[str, str],
    cloudformation_client: Any,
    cloudtrail_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Prove exact Phase A execution via CloudTrail and StackEvents only."""

    change_set = validate_delegation_change_set_receipt(
        receipt=delegation_change_set_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        parameter_handoff=delegation_handoff,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    stack_arn = stack.get("StackId")
    stack_creation_time = _provider_datetime(
        stack.get("CreationTime"), "DELEGATION_STACK_CREATION_TIME_INVALID"
    )
    verification_time = now or datetime.now(UTC)
    if stack_arn != change_set["stack_arn"]:
        raise ChangeSetHandoffError("DELEGATION_EXECUTED_STACK_ID_DRIFT")
    execute_event = _verify_execute_change_set_event(
        cloudtrail_client=cloudtrail_client,
        deployment_contract=deployment_contract,
        change_set_receipt=delegation_change_set_receipt,
        stack_creation_time=stack_creation_time,
        verification_time=verification_time,
    )
    _, expected_resource_types = _template_contract(
        reviewed_template_bytes,
        expected_parameter_keys=DELEGATION_PARAMETER_KEYS,
    )
    execution = delegation_change_set_receipt["execution_contract"]
    stack_event_proof = _verify_stack_operation_events(
        cloudformation_client=cloudformation_client,
        stack_arn=str(stack_arn),
        client_request_token=str(execution["client_request_token"]),
        execute_event_time=_timestamp(
            execute_event["event_time"], "CLOUDTRAIL_EVENT_TIME_INVALID"
        ),
        expected_resource_types=expected_resource_types,
    )
    terminal = stack_event_proof["terminal_resources"]
    stack_terminal = next(
        item
        for item in terminal
        if item["logical_resource_id"] == DELEGATION_STACK_NAME
    )
    result = {
        "artifact_type": DELEGATION_EXECUTION_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "A_DELEGATION_EXECUTION_TRACE",
        "source_commit": deployment_contract["source_commit"],
        "deployment_contract_sha256": _digest(deployment_contract),
        "delegation_change_set_receipt_sha256": _digest(
            delegation_change_set_receipt
        ),
        "change_set_arn": change_set["arn"],
        "change_set_uuid": change_set["uuid"],
        "stack_arn": stack_arn,
        "client_request_token": execution["client_request_token"],
        "client_request_token_sha256": execution["client_request_token_sha256"],
        "execute_request_sha256": execution["execute_request_sha256"],
        "executor_arn_sha256": execution["executor_arn_sha256"],
        "execute_event": execute_event,
        **stack_event_proof,
        "executed_at": execute_event["event_time"],
        "stack_completed_at": stack_terminal["event_time"],
        "verifier": dict(verifier),
        "evaluated_at": _utc_text(verification_time),
        "evidence_status": "DELEGATION_EXECUTION_READ_ONLY_VERIFIED",
        "authority_status": "PROVIDER_DERIVED_EXECUTION_TRACE_NOT_EXECUTION_AUTHORITY",
        "production_status": PRODUCTION_STATUS,
    }
    validate_delegation_execution_receipt(
        receipt=result,
        deployment_contract=deployment_contract,
        delegation_change_set_receipt=delegation_change_set_receipt,
    )
    return result


def validate_delegation_execution_receipt(
    *,
    receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    delegation_change_set_receipt: Mapping[str, Any],
) -> None:
    change_set = _validate_delegation_change_set_receipt_binding(
        receipt=delegation_change_set_receipt,
        deployment_contract=deployment_contract,
    )
    required = {
        "artifact_type", "schema_version", "work_package", "phase",
        "source_commit", "deployment_contract_sha256",
        "delegation_change_set_receipt_sha256", "change_set_arn",
        "change_set_uuid", "stack_arn", "client_request_token",
        "client_request_token_sha256", "execute_request_sha256",
        "executor_arn_sha256", "execute_event", "stack_event_count",
        "stack_events_sha256", "terminal_resources", "executed_at",
        "stack_completed_at", "verifier", "evaluated_at", "evidence_status",
        "authority_status", "production_status",
    }
    execution = delegation_change_set_receipt["execution_contract"]
    execute_event = receipt.get("execute_event")
    terminal = receipt.get("terminal_resources")
    verifier = receipt.get("verifier")
    expected_terminal = {
        DELEGATION_STACK_NAME: "AWS::CloudFormation::Stack",
        "MutationServiceRole": "AWS::IAM::Role",
        "ReadbackServiceRole": "AWS::IAM::Role",
        "RepairInvokerAssignment": "AWS::SSO::Assignment",
        "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type") != DELEGATION_EXECUTION_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "A_DELEGATION_EXECUTION_TRACE"
        or receipt.get("source_commit") != deployment_contract["source_commit"]
        or receipt.get("deployment_contract_sha256") != _digest(deployment_contract)
        or receipt.get("delegation_change_set_receipt_sha256")
        != _digest(delegation_change_set_receipt)
        or receipt.get("change_set_arn") != change_set["arn"]
        or receipt.get("change_set_uuid") != change_set["uuid"]
        or receipt.get("stack_arn") != change_set["stack_arn"]
        or receipt.get("client_request_token")
        != execution["client_request_token"]
        or receipt.get("client_request_token_sha256")
        != execution["client_request_token_sha256"]
        or receipt.get("execute_request_sha256")
        != execution["execute_request_sha256"]
        or receipt.get("executor_arn_sha256")
        != execution["executor_arn_sha256"]
        or not isinstance(execute_event, Mapping)
        or set(execute_event) != {"event_id", "event_time", "event_digest"}
        or not isinstance(execute_event.get("event_id"), str)
        or not execute_event.get("event_id")
        or _DIGEST_RE.fullmatch(str(execute_event.get("event_digest"))) is None
        or not isinstance(receipt.get("stack_event_count"), int)
        or receipt.get("stack_event_count", 0) < len(expected_terminal)
        or _DIGEST_RE.fullmatch(str(receipt.get("stack_events_sha256"))) is None
        or not isinstance(terminal, list)
        or len(terminal) != len(expected_terminal)
        or not isinstance(verifier, Mapping)
        or verifier.get("profile") != EXPECTED_MANAGEMENT_PROFILE
        or verifier.get("account_id") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
        or receipt.get("evidence_status")
        != "DELEGATION_EXECUTION_READ_ONLY_VERIFIED"
        or receipt.get("authority_status")
        != "PROVIDER_DERIVED_EXECUTION_TRACE_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        raise ChangeSetHandoffError("DELEGATION_EXECUTION_RECEIPT_INVALID")
    observed_terminal: dict[str, str] = {}
    for item in terminal:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "event_id", "event_time", "logical_resource_id",
                "resource_type", "resource_status",
                "physical_resource_id_sha256",
            }
            or not isinstance(item.get("event_id"), str)
            or not item.get("event_id")
            or item.get("resource_status") != "CREATE_COMPLETE"
            or _DIGEST_RE.fullmatch(
                str(item.get("physical_resource_id_sha256"))
            )
            is None
            or not isinstance(item.get("logical_resource_id"), str)
            or item["logical_resource_id"] in observed_terminal
        ):
            raise ChangeSetHandoffError("DELEGATION_EXECUTION_RECEIPT_INVALID")
        _timestamp(
            item.get("event_time"),
            "DELEGATION_EXECUTION_RECEIPT_TIME_INVALID",
        )
        observed_terminal[item["logical_resource_id"]] = str(item.get("resource_type"))
    if observed_terminal != expected_terminal:
        raise ChangeSetHandoffError("DELEGATION_EXECUTION_RECEIPT_INVALID")
    executed_at = _timestamp(
        receipt.get("executed_at"), "DELEGATION_EXECUTION_RECEIPT_TIME_INVALID"
    )
    completed_at = _timestamp(
        receipt.get("stack_completed_at"),
        "DELEGATION_EXECUTION_RECEIPT_TIME_INVALID",
    )
    if (
        receipt.get("executed_at") != execute_event.get("event_time")
        or completed_at < executed_at
    ):
        raise ChangeSetHandoffError("DELEGATION_EXECUTION_RECEIPT_TIME_INVALID")
    _timestamp(
        receipt.get("evaluated_at"), "DELEGATION_EXECUTION_RECEIPT_TIME_INVALID"
    )


def _expected_management_role_snapshots(
    *,
    source_root: Path,
    source_commit: str,
    derived: Mapping[str, str],
    invoker_arn: str,
    management_iam_client: Any,
) -> list[Mapping[str, Any]]:
    config = SimpleNamespace(
        repair_id=derived["repair_id"],
        expected_code_signing_config_arn=(
            "arn:aws:lambda:us-east-1:042360977644:code-signing-config:"
            "csc-00000000000000000"
        ),
        repair_ledger_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000000"
        ),
        identity_store_id=derived["identity_store_id"],
        principal_id=derived["principal_id"],
        instance_arn=derived["identity_center_instance_arn"],
        collector_permission_set_arn=derived["collector_permission_set_arn"],
        repair_invoker_permission_set_arn=invoker_arn,
        identity_center_kms_key_arn=derived["identity_center_kms_key_arn"],
        identity_center_kms_mode=derived["identity_center_kms_mode"],
    )
    try:
        specs = expected_role_specs(
            config,
            repo_root=source_root,
            policy_loader=lambda path: _reviewed_policy_object(
                source_root=source_root,
                source_commit=source_commit,
                relative_path=path,
            ),
        )[4:]
        verifier = AwsIamEffectiveVerifier(
            authority_iam=management_iam_client,
            management_iam=management_iam_client,
            repo_root=source_root,
        )
        return [verifier._read_role(management_iam_client, spec).as_dict() for spec in specs]
    except ValueError as exc:
        raise ChangeSetHandoffError("DELEGATION_IAM_READBACK_DRIFT") from exc


def readback_delegation_live(
    *,
    source_root: Path,
    profile_name: str,
    authority_profile_name: str,
    region: str,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_handoff: Mapping[str, Any],
    delegation_change_set_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    sts_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    sso_admin_client: Any,
    identitystore_client: Any,
    kms_client: Any,
    organizations_client: Any,
    iam_client: Any,
    authority_sts_client: Any,
    authority_iam_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Read back the executed Phase A stack and all effective identities."""

    if profile_name != EXPECTED_MANAGEMENT_PROFILE or region != REGION:
        raise ChangeSetHandoffError("MANAGEMENT_VERIFIER_PROFILE_OR_REGION_INVALID")
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise ChangeSetHandoffError("MANAGEMENT_VERIFIER_IDENTITY_INVALID")
    fresh_gug220_evidence = collect_gug220_live_evidence_read_only(
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        management_profile_name=profile_name,
        authority_profile_name=authority_profile_name,
        region=region,
        management_sts_client=sts_client,
        management_sso_admin_client=sso_admin_client,
        management_identitystore_client=identitystore_client,
        management_kms_client=kms_client,
        management_organizations_client=organizations_client,
        authority_sts_client=authority_sts_client,
        authority_iam_client=authority_iam_client,
        now=now,
    )
    _require_fresh_gug220_evidence(
        supplied=gug220_evidence,
        fresh=fresh_gug220_evidence,
        validation_kwargs={
            "source_root": source_root,
            "deployment_contract": deployment_contract,
            "intent": gug220_intent,
            "ledger": gug220_ledger,
            "receipt": gug220_receipt,
        },
    )
    validate_delegation_parameter_handoff(
        handoff=delegation_handoff,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_template_bytes=reviewed_template_bytes,
    )
    derived = validate_gug220_evidence_chain(
        source_root=source_root,
        deployment_contract=deployment_contract,
        intent=gug220_intent,
        ledger=gug220_ledger,
        receipt=gug220_receipt,
        evidence=gug220_evidence,
    )
    pending_before = _gug220_pending_operations(
        sso_admin_client=sso_admin_client,
        instance_arn=derived["identity_center_instance_arn"],
    )
    if any(pending_before.values()):
        raise ChangeSetHandoffError("DELEGATION_PENDING_OPERATION_PRESENT")
    stacks = _aws_call(
        cloudformation_client.describe_stacks, StackName=DELEGATION_STACK_NAME
    ).get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
        raise ChangeSetHandoffError("DELEGATION_STACK_READBACK_INVALID")
    stack = stacks[0]
    expected_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in delegation_handoff["parameters"]
    }
    outputs = stack.get("Outputs")
    if not isinstance(outputs, list):
        raise ChangeSetHandoffError("DELEGATION_STACK_OUTPUT_DRIFT")
    output_map: dict[str, str] = {}
    for item in outputs:
        if (
            not isinstance(item, Mapping)
            or set(item) - {"OutputKey", "OutputValue", "Description", "ExportName"}
            or not isinstance(item.get("OutputKey"), str)
            or not isinstance(item.get("OutputValue"), str)
            or item["OutputKey"] in output_map
        ):
            raise ChangeSetHandoffError("DELEGATION_STACK_OUTPUT_DRIFT")
        output_map[item["OutputKey"]] = item["OutputValue"]
    invoker_arn = output_map.get("RepairInvokerPermissionSetArn", "")
    expected_outputs = {
        "MutationServiceRoleArn": (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeLambdaAuditRepairMutationServiceRole"
        ),
        "ReadbackServiceRoleArn": (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeLambdaAuditRepairReadbackServiceRole"
        ),
        "RepairInvokerPermissionSetArn": invoker_arn,
        "RepairPrincipalIdDigestRequired": "true",
        "ProductionAuthorized": "false",
    }
    if (
        stack.get("StackName") != DELEGATION_STACK_NAME
        or stack.get("StackStatus") != "CREATE_COMPLETE"
        or stack.get("Capabilities") != list(EXPECTED_CAPABILITIES)
        or _normalize_parameters(
            stack.get("Parameters"), expected_keys=DELEGATION_PARAMETER_KEYS
        )
        != expected_parameters
        or _normalize_tags(stack.get("Tags")) != delegation_handoff["stack_tags"]
        or output_map != expected_outputs
        or _PERMISSION_SET_ARN_RE.fullmatch(invoker_arn) is None
        or invoker_arn == derived["collector_permission_set_arn"]
    ):
        raise ChangeSetHandoffError("DELEGATION_STACK_DRIFT")
    verifier = {
        "profile": profile_name,
        "account_id": identity["Account"],
        "caller_arn": identity["Arn"],
    }
    execution_receipt = verify_delegation_execution_read_only(
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_handoff=delegation_handoff,
        delegation_change_set_receipt=delegation_change_set_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
        stack=stack,
        verifier=verifier,
        cloudformation_client=cloudformation_client,
        cloudtrail_client=cloudtrail_client,
        now=now,
    )
    template = _aws_call(
        cloudformation_client.get_template,
        StackName=DELEGATION_STACK_NAME,
        TemplateStage="Original",
    ).get("TemplateBody")
    if not isinstance(template, str) or template.encode("utf-8") != reviewed_template_bytes:
        raise ChangeSetHandoffError("DELEGATION_STACK_TEMPLATE_DRIFT")
    resources = _paginate_next_token(
        cloudformation_client,
        "list_stack_resources",
        "StackResourceSummaries",
        StackName=DELEGATION_STACK_NAME,
    )
    _, expected_resource_types = _template_contract(
        reviewed_template_bytes,
        expected_parameter_keys=DELEGATION_PARAMETER_KEYS,
    )
    resource_map: dict[str, tuple[str, str]] = {}
    for item in resources:
        if (
            not isinstance(item, Mapping)
            or item.get("ResourceStatus") != "CREATE_COMPLETE"
            or not isinstance(item.get("LogicalResourceId"), str)
            or not isinstance(item.get("ResourceType"), str)
            or not isinstance(item.get("PhysicalResourceId"), str)
            or item["LogicalResourceId"] in resource_map
        ):
            raise ChangeSetHandoffError("DELEGATION_STACK_RESOURCE_DRIFT")
        resource_map[item["LogicalResourceId"]] = (
            item["ResourceType"], item["PhysicalResourceId"]
        )
    if {key: value[0] for key, value in resource_map.items()} != expected_resource_types:
        raise ChangeSetHandoffError("DELEGATION_STACK_RESOURCE_DRIFT")
    if resource_map["RepairInvokerPermissionSet"][1] != invoker_arn:
        raise ChangeSetHandoffError("DELEGATION_STACK_OUTPUT_DRIFT")

    permission_set_response = _aws_call(
        sso_admin_client.describe_permission_set,
        InstanceArn=derived["identity_center_instance_arn"],
        PermissionSetArn=invoker_arn,
    )
    permission_set = permission_set_response.get("PermissionSet")
    if (
        not isinstance(permission_set, Mapping)
        or permission_set.get("PermissionSetArn") != invoker_arn
        or permission_set.get("Name") != "ScanalyzeLambdaAuditRepair"
        or permission_set.get("Description")
        != "GUG-221 invoke-only private repair PEP boundary"
        or permission_set.get("SessionDuration") != "PT1H"
        or permission_set.get("RelayState") not in (None, "")
    ):
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_METADATA_DRIFT")
    tags = _paginate_next_token(
        sso_admin_client,
        "list_tags_for_resource",
        "Tags",
        InstanceArn=derived["identity_center_instance_arn"],
        ResourceArn=invoker_arn,
    )
    if _normalize_tags(tags) != _permission_set_tags(
        str(deployment_contract["source_commit"])
    ):
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_TAG_DRIFT")
    policy_raw = _aws_call(
        sso_admin_client.get_inline_policy_for_permission_set,
        InstanceArn=derived["identity_center_instance_arn"],
        PermissionSetArn=invoker_arn,
    ).get("InlinePolicy")
    try:
        policy = json.loads(policy_raw) if isinstance(policy_raw, str) else None
    except json.JSONDecodeError as exc:
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_POLICY_DRIFT") from exc
    if policy != _repair_invoker_policy(
        source_root, str(deployment_contract["source_commit"])
    ):
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_POLICY_DRIFT")
    if _paginate_next_token(
        sso_admin_client, "list_managed_policies_in_permission_set", "AttachedManagedPolicies",
        InstanceArn=derived["identity_center_instance_arn"], PermissionSetArn=invoker_arn
    ) != [] or _paginate_next_token(
        sso_admin_client, "list_customer_managed_policy_references_in_permission_set", "CustomerManagedPolicyReferences",
        InstanceArn=derived["identity_center_instance_arn"], PermissionSetArn=invoker_arn
    ) != []:
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_ATTACHMENT_DRIFT")
    boundary = _aws_call(
        sso_admin_client.get_permissions_boundary_for_permission_set,
        InstanceArn=derived["identity_center_instance_arn"],
        PermissionSetArn=invoker_arn,
    ).get("PermissionsBoundary")
    if boundary not in (None, {}):
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_BOUNDARY_DRIFT")
    organization_accounts = _paginate_next_token(
        organizations_client,
        "list_accounts",
        "Accounts",
    )
    if any(
        not isinstance(account, Mapping)
        or re.fullmatch(r"[0-9]{12}", str(account.get("Id"))) is None
        or account.get("State") not in ORGANIZATION_ACCOUNT_STATES
        for account in organization_accounts
    ):
        raise ChangeSetHandoffError(
            "DELEGATION_ORGANIZATION_ACCOUNT_ENUMERATION_MALFORMED"
        )
    assignments: list[Any] = []
    for account_id in sorted(str(item["Id"]) for item in organization_accounts):
        assignments.extend(
            _paginate_next_token(
                sso_admin_client,
                "list_account_assignments",
                "AccountAssignments",
                InstanceArn=derived["identity_center_instance_arn"],
                AccountId=account_id,
                PermissionSetArn=invoker_arn,
            )
        )
    expected_assignment = {
        "AccountId": AUTHORITY_ACCOUNT_ID,
        "PermissionSetArn": invoker_arn,
        "PrincipalType": "USER",
        "PrincipalId": derived["principal_id"],
    }
    if assignments != [expected_assignment]:
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_ASSIGNMENT_DRIFT")
    accounts = _paginate_next_token(
        sso_admin_client, "list_accounts_for_provisioned_permission_set", "AccountIds",
        InstanceArn=derived["identity_center_instance_arn"], PermissionSetArn=invoker_arn,
    )
    if accounts != [AUTHORITY_ACCOUNT_ID]:
        raise ChangeSetHandoffError("DELEGATION_PERMISSION_SET_PROVISIONING_DRIFT")
    pending_after = _gug220_pending_operations(
        sso_admin_client=sso_admin_client,
        instance_arn=derived["identity_center_instance_arn"],
    )
    if any(pending_after.values()) or pending_before != pending_after:
        raise ChangeSetHandoffError("DELEGATION_PENDING_OPERATION_DRIFT")
    user = _aws_call(
        identitystore_client.describe_user,
        IdentityStoreId=derived["identity_store_id"],
        UserId=derived["principal_id"],
    )
    if user.get("UserId") != derived["principal_id"]:
        raise ChangeSetHandoffError("DELEGATION_PRINCIPAL_DRIFT")
    roles = _expected_management_role_snapshots(
        source_root=source_root,
        source_commit=str(deployment_contract["source_commit"]),
        derived=derived,
        invoker_arn=invoker_arn,
        management_iam_client=iam_client,
    )
    provider_state = {
        "stack_arn": stack.get("StackId"),
        "stack_parameters_sha256": _digest(delegation_handoff["parameters"]),
        "stack_tags": delegation_handoff["stack_tags"],
        "stack_outputs": expected_outputs,
        "stack_resources_sha256": _digest(resource_map),
        "repair_invoker_permission_set_arn": invoker_arn,
        "repair_invoker_permission_set_sha256": _digest(permission_set),
        "repair_invoker_policy_sha256": _digest(policy),
        "repair_invoker_assignment_sha256": _digest(assignments),
        "management_roles": roles,
        "pending_operations_before": pending_before,
        "pending_operations_after": pending_after,
    }
    result = {
        "artifact_type": DELEGATION_LIVE_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "A_DELEGATION_LIVE_READBACK",
        "source_commit": deployment_contract["source_commit"],
        "deployment_contract_sha256": _digest(deployment_contract),
        "gug220_intent_sha256": _digest(gug220_intent),
        "gug220_ledger_sha256": _digest(gug220_ledger),
        "gug220_receipt_sha256": _digest(gug220_receipt),
        "gug220_evidence_sha256": _digest(gug220_evidence),
        "gug220_provider_state_sha256": fresh_gug220_evidence[
            "provider_state_sha256"
        ],
        "delegation_handoff_sha256": _digest(delegation_handoff),
        "delegation_change_set_receipt": dict(delegation_change_set_receipt),
        "delegation_change_set_receipt_sha256": _digest(
            delegation_change_set_receipt
        ),
        "delegation_execution_receipt": dict(execution_receipt),
        "delegation_execution_receipt_sha256": (
            _delegation_execution_receipt_binding_digest(execution_receipt)
        ),
        "template_sha256": sha256(reviewed_template_bytes).hexdigest(),
        **provider_state,
        "provider_state_sha256": _digest(provider_state),
        "verifier": verifier,
        "evaluated_at": _utc_text(now),
        "evidence_status": "DELEGATION_LIVE_READ_ONLY_VERIFIED",
        "authority_status": "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY",
        "production_status": PRODUCTION_STATUS,
    }
    validate_delegation_live_receipt(
        receipt=result,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
    )
    return result


def validate_delegation_live_receipt(
    *,
    receipt: Mapping[str, Any],
    source_root: Path,
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
) -> None:
    derived = validate_gug220_evidence_chain(
        source_root=source_root,
        deployment_contract=deployment_contract,
        intent=gug220_intent,
        ledger=gug220_ledger,
        receipt=gug220_receipt,
        evidence=gug220_evidence,
    )
    required = {
        "artifact_type", "schema_version", "work_package", "phase", "source_commit",
        "deployment_contract_sha256", "gug220_intent_sha256", "gug220_ledger_sha256",
        "gug220_receipt_sha256", "gug220_evidence_sha256",
        "gug220_provider_state_sha256", "delegation_handoff_sha256",
        "delegation_change_set_receipt", "delegation_change_set_receipt_sha256",
        "delegation_execution_receipt", "delegation_execution_receipt_sha256",
        "template_sha256", "stack_arn", "stack_parameters_sha256", "stack_tags",
        "stack_outputs", "stack_resources_sha256", "repair_invoker_permission_set_arn",
        "repair_invoker_permission_set_sha256", "repair_invoker_policy_sha256",
        "repair_invoker_assignment_sha256", "management_roles",
        "pending_operations_before", "pending_operations_after",
        "provider_state_sha256",
        "verifier", "evaluated_at", "evidence_status", "authority_status", "production_status",
    }
    invoker = str(receipt.get("repair_invoker_permission_set_arn"))
    verifier = receipt.get("verifier")
    change_set_receipt = receipt.get("delegation_change_set_receipt")
    execution_receipt = receipt.get("delegation_execution_receipt")
    provider_keys = {
        "stack_arn", "stack_parameters_sha256", "stack_tags", "stack_outputs",
        "stack_resources_sha256", "repair_invoker_permission_set_arn",
        "repair_invoker_permission_set_sha256", "repair_invoker_policy_sha256",
        "repair_invoker_assignment_sha256", "management_roles",
        "pending_operations_before", "pending_operations_after",
    }
    provider_state = {key: receipt.get(key) for key in provider_keys}
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type") != DELEGATION_LIVE_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "A_DELEGATION_LIVE_READBACK"
        or receipt.get("source_commit") != deployment_contract["source_commit"]
        or receipt.get("deployment_contract_sha256") != _digest(deployment_contract)
        or receipt.get("gug220_intent_sha256") != _digest(gug220_intent)
        or receipt.get("gug220_ledger_sha256") != _digest(gug220_ledger)
        or receipt.get("gug220_receipt_sha256") != _digest(gug220_receipt)
        or receipt.get("gug220_evidence_sha256") != _digest(gug220_evidence)
        or receipt.get("gug220_provider_state_sha256")
        != gug220_evidence.get("provider_state_sha256")
        or not isinstance(change_set_receipt, Mapping)
        or not isinstance(execution_receipt, Mapping)
        or receipt.get("delegation_change_set_receipt_sha256")
        != _digest(change_set_receipt)
        or receipt.get("delegation_execution_receipt_sha256")
        != _delegation_execution_receipt_binding_digest(execution_receipt)
        or _PERMISSION_SET_ARN_RE.fullmatch(invoker) is None
        or invoker == derived["collector_permission_set_arn"]
        or receipt.get("provider_state_sha256") != _digest(provider_state)
        or not isinstance(receipt.get("management_roles"), list)
        or len(receipt["management_roles"]) != 2
        or receipt.get("pending_operations_before")
        != {
            "assignment_creations": [],
            "assignment_deletions": [],
            "permission_set_provisioning": [],
        }
        or receipt.get("pending_operations_after")
        != receipt.get("pending_operations_before")
        or not isinstance(verifier, Mapping)
        or verifier.get("profile") != EXPECTED_MANAGEMENT_PROFILE
        or verifier.get("account_id") != MANAGEMENT_ACCOUNT_ID
        or _MANAGEMENT_CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
        or receipt.get("evidence_status") != "DELEGATION_LIVE_READ_ONLY_VERIFIED"
        or receipt.get("authority_status") != "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        raise ChangeSetHandoffError("DELEGATION_LIVE_RECEIPT_INVALID")
    _validate_delegation_change_set_receipt_binding(
        receipt=change_set_receipt,
        deployment_contract=deployment_contract,
    )
    validate_delegation_execution_receipt(
        receipt=execution_receipt,
        deployment_contract=deployment_contract,
        delegation_change_set_receipt=change_set_receipt,
    )
    if execution_receipt.get("verifier") != verifier:
        raise ChangeSetHandoffError("DELEGATION_LIVE_RECEIPT_INVALID")
    _timestamp(receipt.get("evaluated_at"), "DELEGATION_LIVE_RECEIPT_TIME_INVALID")


def verify_pep_change_set_read_only(
    *,
    source_root: Path,
    profile_name: str,
    management_profile_name: str,
    region: str,
    change_set_arn: str,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_handoff: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_handoff: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    reviewed_delegation_template_bytes: bytes,
    authority_sts_client: Any,
    authority_signer_client: Any,
    authority_s3_client: Any,
    authority_cloudformation_client: Any,
    authority_cloudtrail_client: Any,
    management_sts_client: Any,
    management_cloudformation_client: Any,
    management_cloudtrail_client: Any,
    management_sso_admin_client: Any,
    management_identitystore_client: Any,
    management_kms_client: Any,
    management_organizations_client: Any,
    management_iam_client: Any,
    authority_iam_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Phase B: revalidate live Phase A, then verify only the PEP Change Set."""

    validate_phase_b_identity_materialization_receipt(
        phase_b_identity_materialization_receipt,
        source_commit=str(deployment_contract.get("source_commit")),
    )
    if profile_name != EXPECTED_PROFILE or region != REGION:
        raise ChangeSetHandoffError("VERIFIER_PROFILE_OR_REGION_INVALID")
    identity = _aws_call(authority_sts_client.get_caller_identity)
    if identity.get("Account") != AUTHORITY_ACCOUNT_ID or _CALLER_ARN_RE.fullmatch(
        str(identity.get("Arn"))
    ) is None:
        raise ChangeSetHandoffError("VERIFIER_IDENTITY_INVALID")
    validate_delegation_live_receipt(
        receipt=delegation_live_receipt,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
    )
    supplied_delegation_change_set_receipt = delegation_live_receipt.get(
        "delegation_change_set_receipt"
    )
    if not isinstance(supplied_delegation_change_set_receipt, Mapping):
        raise ChangeSetHandoffError("DELEGATION_LIVE_RECEIPT_INVALID")
    fresh_signed_receipt = refresh_signed_artifact_receipt_read_only(
        source_root=source_root,
        local_receipt=signed_receipt,
        sts_client=authority_sts_client,
        signer_client=authority_signer_client,
        s3_client=authority_s3_client,
        now=now,
    )
    fresh_live = readback_delegation_live(
        source_root=source_root,
        profile_name=management_profile_name,
        authority_profile_name=profile_name,
        region=region,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_handoff=delegation_handoff,
        delegation_change_set_receipt=supplied_delegation_change_set_receipt,
        reviewed_template_bytes=reviewed_delegation_template_bytes,
        sts_client=management_sts_client,
        cloudformation_client=management_cloudformation_client,
        cloudtrail_client=management_cloudtrail_client,
        sso_admin_client=management_sso_admin_client,
        identitystore_client=management_identitystore_client,
        kms_client=management_kms_client,
        organizations_client=management_organizations_client,
        iam_client=management_iam_client,
        authority_sts_client=authority_sts_client,
        authority_iam_client=authority_iam_client,
        now=now,
    )
    supplied = _delegation_live_receipt_binding_projection(
        delegation_live_receipt
    )
    refreshed = _delegation_live_receipt_binding_projection(fresh_live)
    if canonical_json(supplied) != canonical_json(refreshed):
        raise ChangeSetHandoffError("DELEGATION_LIVE_RECEIPT_STALE_OR_DRIFTED")
    validate_pep_parameter_handoff(
        handoff=pep_handoff,
        source_root=source_root,
        signed_receipt=fresh_signed_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_live_receipt=fresh_live,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        template_bytes=reviewed_template_bytes,
    )
    change_set = _verify_exact_change_set(
        cloudformation_client=authority_cloudformation_client,
        cloudtrail_client=authority_cloudtrail_client,
        account_id=AUTHORITY_ACCOUNT_ID,
        creator_arn=str(deployment_contract["pep_change_set_creator_arn"]),
        change_set_arn=change_set_arn,
        change_set_name=CHANGE_SET_NAME,
        stack_name=STACK_NAME,
        change_set_arn_re=_CHANGE_SET_ARN_RE,
        stack_arn_re=_STACK_ARN_RE,
        reviewed_template_bytes=reviewed_template_bytes,
        expected_parameter_keys=PARAMETER_KEYS,
        parameters=pep_handoff["parameters"],
        tags=pep_handoff["stack_tags"],
    )
    deployment_contract_sha256 = _digest(deployment_contract)
    parameter_handoff_sha256 = _digest(pep_handoff)
    template_sha256 = sha256(reviewed_template_bytes).hexdigest()
    execution_contract = _pep_execution_contract(
        source_commit=str(fresh_signed_receipt["source_commit"]),
        deployment_contract_sha256=deployment_contract_sha256,
        parameter_handoff_sha256=parameter_handoff_sha256,
        phase_b_identity_materialization_receipt_sha256=(
            _phase_b_identity_materialization_receipt_digest(
                phase_b_identity_materialization_receipt
            )
        ),
        template_sha256=template_sha256,
        change_set=change_set,
    )
    return {
        "artifact_type": PEP_CHANGE_SET_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "B_PEP_CHANGE_SET",
        "source_commit": fresh_signed_receipt["source_commit"],
        "signed_artifact_receipt_sha256": _signed_receipt_binding_digest(
            fresh_signed_receipt
        ),
        "deployment_contract_sha256": deployment_contract_sha256,
        "gug220_intent_sha256": _digest(gug220_intent),
        "gug220_ledger_sha256": _digest(gug220_ledger),
        "gug220_receipt_sha256": _digest(gug220_receipt),
        "gug220_evidence_sha256": _digest(gug220_evidence),
        "gug220_provider_state_sha256": fresh_live[
            "gug220_provider_state_sha256"
        ],
        "delegation_live_receipt_sha256": (
            _delegation_live_receipt_binding_digest(fresh_live)
        ),
        "parameter_handoff_sha256": parameter_handoff_sha256,
        "phase_b_identity_materialization_receipt_sha256": (
            _phase_b_identity_materialization_receipt_digest(
                phase_b_identity_materialization_receipt
            )
        ),
        "template_sha256": template_sha256,
        "change_set": change_set,
        "execution_contract": execution_contract,
        "verifier": {
            "profile": profile_name,
            "account_id": identity["Account"],
            "caller_arn": identity["Arn"],
        },
        "evaluated_at": _utc_text(now),
        "evidence_status": "PEP_CHANGE_SET_READ_ONLY_VERIFIED_AFTER_LIVE_DELEGATION",
        "authority_status": "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY",
        "production_status": PRODUCTION_STATUS,
    }


def _pep_expected_resource_types() -> dict[str, str]:
    return {
        "InvocationAuthorityInspectorRole": "AWS::IAM::Role",
        "PlanAlias": "AWS::Lambda::Alias",
        "PlanEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
        "PlanExecutionRole": "AWS::IAM::Role",
        "PlanFunction": "AWS::Lambda::Function",
        "PlanFunctionVersion": "AWS::Lambda::Version",
        "PlanLogGroup": "AWS::Logs::LogGroup",
        "ReconcileAlias": "AWS::Lambda::Alias",
        "ReconcileEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
        "ReconcileExecutionRole": "AWS::IAM::Role",
        "ReconcileFunction": "AWS::Lambda::Function",
        "ReconcileFunctionVersion": "AWS::Lambda::Version",
        "ReconcileLogGroup": "AWS::Logs::LogGroup",
        "RepairAlias": "AWS::Lambda::Alias",
        "RepairCodeSigningConfig": "AWS::Lambda::CodeSigningConfig",
        "RepairEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
        "RepairExecutionRole": "AWS::IAM::Role",
        "RepairFunction": "AWS::Lambda::Function",
        "RepairFunctionVersion": "AWS::Lambda::Version",
        "RepairLedger": "AWS::DynamoDB::Table",
        "RepairLedgerKey": "AWS::KMS::Key",
        "RepairLedgerKeyAlias": "AWS::KMS::Alias",
        "RepairLogGroup": "AWS::Logs::LogGroup",
    }


def _validate_pep_change_set_receipt_binding(
    *,
    receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validate immutable Phase B review and execution bindings."""

    validate_deployment_contract(deployment_contract)
    validate_phase_b_identity_materialization_receipt(
        phase_b_identity_materialization_receipt,
        source_commit=str(deployment_contract["source_commit"]),
    )
    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "phase",
        "source_commit",
        "signed_artifact_receipt_sha256",
        "deployment_contract_sha256",
        "gug220_intent_sha256",
        "gug220_ledger_sha256",
        "gug220_receipt_sha256",
        "gug220_evidence_sha256",
        "gug220_provider_state_sha256",
        "delegation_live_receipt_sha256",
        "parameter_handoff_sha256",
        "phase_b_identity_materialization_receipt_sha256",
        "template_sha256",
        "change_set",
        "execution_contract",
        "verifier",
        "evaluated_at",
        "evidence_status",
        "authority_status",
        "production_status",
    }
    change_set = receipt.get("change_set")
    verifier = receipt.get("verifier")
    digest_fields = {
        "signed_artifact_receipt_sha256",
        "deployment_contract_sha256",
        "gug220_intent_sha256",
        "gug220_ledger_sha256",
        "gug220_receipt_sha256",
        "gug220_evidence_sha256",
        "gug220_provider_state_sha256",
        "delegation_live_receipt_sha256",
        "parameter_handoff_sha256",
        "phase_b_identity_materialization_receipt_sha256",
        "template_sha256",
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type") != PEP_CHANGE_SET_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "B_PEP_CHANGE_SET"
        or receipt.get("source_commit") != deployment_contract["source_commit"]
        or receipt.get("deployment_contract_sha256") != _digest(deployment_contract)
        or receipt.get("phase_b_identity_materialization_receipt_sha256")
        != _phase_b_identity_materialization_receipt_digest(
            phase_b_identity_materialization_receipt
        )
        or any(
            _DIGEST_RE.fullmatch(str(receipt.get(field))) is None
            for field in digest_fields
        )
        or not isinstance(change_set, Mapping)
        or not isinstance(verifier, Mapping)
        or verifier.get("profile") != EXPECTED_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
        or receipt.get("evidence_status")
        != "PEP_CHANGE_SET_READ_ONLY_VERIFIED_AFTER_LIVE_DELEGATION"
        or receipt.get("authority_status")
        != "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        raise ChangeSetHandoffError("PEP_CHANGE_SET_RECEIPT_INVALID")

    expected_change_keys = {
        "arn",
        "uuid",
        "name",
        "stack_arn",
        "stack_name",
        "type",
        "status",
        "execution_status",
        "on_stack_failure",
        "capabilities",
        "tags",
        "parameters_sha256",
        "resource_changes",
        "create_event",
    }
    arn_match = _CHANGE_SET_ARN_RE.fullmatch(str(change_set.get("arn")))
    stack_match = _STACK_ARN_RE.fullmatch(str(change_set.get("stack_arn")))
    create_event = change_set.get("create_event")
    expected_changes = [
        {
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "action": "Add",
            "replacement": "False",
        }
        for logical_id, resource_type in sorted(
            _pep_expected_resource_types().items()
        )
    ]
    if (
        set(change_set) != expected_change_keys
        or arn_match is None
        or stack_match is None
        or change_set.get("uuid") != arn_match.group("uuid")
        or change_set.get("name") != CHANGE_SET_NAME
        or change_set.get("stack_name") != STACK_NAME
        or change_set.get("type") != "CREATE"
        or change_set.get("status") != "CREATE_COMPLETE"
        or change_set.get("execution_status") != "AVAILABLE"
        or change_set.get("on_stack_failure") != "ROLLBACK"
        or change_set.get("capabilities") != list(EXPECTED_CAPABILITIES)
        or change_set.get("tags")
        != _permission_set_tags(str(deployment_contract["source_commit"]))
        or _DIGEST_RE.fullmatch(str(change_set.get("parameters_sha256"))) is None
        or change_set.get("resource_changes") != expected_changes
        or not isinstance(create_event, Mapping)
        or set(create_event) != {"event_id", "event_time", "event_digest"}
        or not isinstance(create_event.get("event_id"), str)
        or not create_event.get("event_id")
        or _DIGEST_RE.fullmatch(str(create_event.get("event_digest"))) is None
    ):
        raise ChangeSetHandoffError("PEP_CHANGE_SET_RECEIPT_INVALID")
    _timestamp(create_event.get("event_time"), "PEP_CHANGE_SET_RECEIPT_TIME_INVALID")
    _timestamp(receipt.get("evaluated_at"), "PEP_CHANGE_SET_RECEIPT_TIME_INVALID")
    expected_execution = _pep_execution_contract(
        source_commit=str(receipt["source_commit"]),
        deployment_contract_sha256=str(receipt["deployment_contract_sha256"]),
        parameter_handoff_sha256=str(receipt["parameter_handoff_sha256"]),
        phase_b_identity_materialization_receipt_sha256=str(
            receipt["phase_b_identity_materialization_receipt_sha256"]
        ),
        template_sha256=str(receipt["template_sha256"]),
        change_set=change_set,
    )
    if receipt.get("execution_contract") != expected_execution:
        raise ChangeSetHandoffError("PEP_EXECUTION_CONTRACT_INVALID")
    return change_set


def validate_pep_change_set_receipt(
    *,
    receipt: Mapping[str, Any],
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_handoff: Mapping[str, Any],
    reviewed_template_bytes: bytes,
) -> Mapping[str, Any]:
    change_set = _validate_pep_change_set_receipt_binding(
        receipt=receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
    )
    validate_signed_artifact_receipt(signed_receipt)
    validate_delegation_live_receipt(
        receipt=delegation_live_receipt,
        source_root=source_root,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
    )
    validate_pep_parameter_handoff(
        handoff=pep_handoff,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_live_receipt=delegation_live_receipt,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        template_bytes=reviewed_template_bytes,
    )
    if (
        receipt.get("signed_artifact_receipt_sha256")
        != _signed_receipt_binding_digest(signed_receipt)
        or receipt.get("gug220_intent_sha256") != _digest(gug220_intent)
        or receipt.get("gug220_ledger_sha256") != _digest(gug220_ledger)
        or receipt.get("gug220_receipt_sha256") != _digest(gug220_receipt)
        or receipt.get("gug220_evidence_sha256") != _digest(gug220_evidence)
        or receipt.get("gug220_provider_state_sha256")
        != delegation_live_receipt.get("gug220_provider_state_sha256")
        or receipt.get("delegation_live_receipt_sha256")
        != _delegation_live_receipt_binding_digest(delegation_live_receipt)
        or receipt.get("parameter_handoff_sha256") != _digest(pep_handoff)
        or receipt.get("phase_b_identity_materialization_receipt_sha256")
        != _phase_b_identity_materialization_receipt_digest(
            phase_b_identity_materialization_receipt
        )
        or receipt.get("template_sha256")
        != sha256(reviewed_template_bytes).hexdigest()
    ):
        raise ChangeSetHandoffError("PEP_CHANGE_SET_RECEIPT_CHAIN_INVALID")
    return change_set


def _pep_output_readback(
    *,
    stack: Mapping[str, Any],
    resource_map: Mapping[str, tuple[str, str]],
) -> dict[str, str]:
    outputs = stack.get("Outputs")
    if not isinstance(outputs, list):
        raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
    output_map: dict[str, str] = {}
    for item in outputs:
        if (
            not isinstance(item, Mapping)
            or set(item) - {"OutputKey", "OutputValue", "Description", "ExportName"}
            or not isinstance(item.get("OutputKey"), str)
            or not isinstance(item.get("OutputValue"), str)
            or not item["OutputValue"]
            or item["OutputKey"] in output_map
        ):
            raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
        output_map[item["OutputKey"]] = item["OutputValue"]
    expected_keys = {
        "RepairLedgerName",
        "RepairLedgerKeyArn",
        "RepairFunctionAliasArn",
        "PlanFunctionAliasArn",
        "ReconcileFunctionAliasArn",
        "RepairExecutionRoleArn",
        "PlanExecutionRoleArn",
        "ReconcileExecutionRoleArn",
        "InvocationAuthorityInspectorRoleArn",
        "ProductionAuthorized",
    }
    if set(output_map) != expected_keys or output_map["ProductionAuthorized"] != "false":
        raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
    direct_bindings = {
        "RepairLedgerName": "RepairLedger",
        "RepairFunctionAliasArn": "RepairAlias",
        "PlanFunctionAliasArn": "PlanAlias",
        "ReconcileFunctionAliasArn": "ReconcileAlias",
    }
    if any(
        output_map[output_key] != resource_map[logical_id][1]
        for output_key, logical_id in direct_bindings.items()
    ):
        raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
    key_id = resource_map["RepairLedgerKey"][1]
    if output_map["RepairLedgerKeyArn"] != (
        f"arn:aws:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:key/{key_id}"
    ):
        raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
    role_bindings = {
        "RepairExecutionRoleArn": "RepairExecutionRole",
        "PlanExecutionRoleArn": "PlanExecutionRole",
        "ReconcileExecutionRoleArn": "ReconcileExecutionRole",
        "InvocationAuthorityInspectorRoleArn": "InvocationAuthorityInspectorRole",
    }
    for output_key, logical_id in role_bindings.items():
        value = output_map[output_key]
        physical_id = resource_map[logical_id][1]
        if (
            not value.startswith(f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/")
            or not value.endswith("/" + physical_id)
        ):
            raise ChangeSetHandoffError("PEP_STACK_OUTPUT_DRIFT")
    return dict(sorted(output_map.items()))


def _pep_output_snapshot(output_map: Mapping[str, str]) -> list[dict[str, str]]:
    """Return a deterministic receipt-safe projection of PEP stack outputs."""

    return [
        {
            "output_key": key,
            "output_value_sha256": sha256(value.encode("utf-8")).hexdigest(),
        }
        for key, value in sorted(output_map.items())
    ]


def _pep_resource_snapshot(
    resource_map: Mapping[str, tuple[str, str]],
) -> list[dict[str, str]]:
    """Return exact logical/type bindings without exposing physical identifiers."""

    return [
        {
            "logical_resource_id": logical_id,
            "resource_type": resource_type,
            "physical_resource_id_sha256": sha256(
                physical_id.encode("utf-8")
            ).hexdigest(),
        }
        for logical_id, (resource_type, physical_id) in sorted(
            resource_map.items()
        )
    ]


def _validate_phase_b_ledger_readback_binding(
    *,
    readback: Any,
    readback_sha256: Any,
    broker_effect_receipt: Mapping[str, Any],
) -> None:
    required = {
        "table_name_sha256",
        "execution_id_sha256",
        "binding_digest",
        "proof_receipt_digest",
        "ledger_digest",
        "closure_pending_receipt_digest",
        "execution_request_digest",
        "broker_topology_sha256",
        "broker_topology_provider_evidence_digest",
        "status",
        "attempts",
        "execution_gate_consumed",
        "execution_ambiguous",
        "retry_permitted",
        "native_on_behalf_of",
        "closure_status",
    }
    if (
        not isinstance(readback, Mapping)
        or set(readback) != required
        or readback_sha256 != _digest(readback)
        or _DIGEST_RE.fullmatch(str(readback_sha256)) is None
        or readback.get("table_name_sha256")
        != sha256(PHASE_B_LEDGER_TABLE_NAME.encode("utf-8")).hexdigest()
        or readback.get("execution_id_sha256")
        != sha256(
            str(broker_effect_receipt.get("execution_id")).encode("utf-8")
        ).hexdigest()
        or any(
            readback.get(field) != broker_effect_receipt.get(field)
            for field in (
                "binding_digest",
                "proof_receipt_digest",
                "ledger_digest",
                "closure_pending_receipt_digest",
                "execution_request_digest",
                "broker_topology_sha256",
                "broker_topology_provider_evidence_digest",
                "status",
                "attempts",
                "execution_ambiguous",
                "retry_permitted",
                "native_on_behalf_of",
            )
        )
        or readback.get("execution_gate_consumed") is not True
        or readback.get("closure_status") != "PROVIDER_REVOCATION_PENDING"
    ):
        raise ChangeSetHandoffError("PEP_LEDGER_READBACK_BINDING_INVALID")


def validate_pep_execution_receipt(
    *,
    receipt: Mapping[str, Any],
    source_root: Path,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_parameter_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    reviewed_phase_b_precondition_template_bytes: bytes,
    broker_effect_receipt: Mapping[str, Any],
) -> None:
    validate_phase_b_execution_preconditions(
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_parameter_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        reviewed_phase_b_precondition_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
    )
    change_set = _validate_pep_change_set_receipt_binding(
        receipt=pep_change_set_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
    )
    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "phase",
        "source_commit",
        "deployment_contract_sha256",
        "pep_change_set_receipt_sha256",
        "phase_b_precondition_parameter_handoff_sha256",
        "phase_b_precondition_change_set_receipt_sha256",
        "broker_effect_receipt_sha256",
        "broker_ledger_provider_readback",
        "broker_ledger_provider_readback_sha256",
        "change_set_arn",
        "change_set_uuid",
        "stack_arn",
        "client_request_token",
        "client_request_token_sha256",
        "execute_request_sha256",
        "effect_principal_arn_sha256",
        "execute_event",
        "stack_event_count",
        "stack_events",
        "stack_events_sha256",
        "terminal_resources",
        "stack_parameters_sha256",
        "stack_tags",
        "stack_outputs",
        "stack_outputs_sha256",
        "stack_resources",
        "stack_resources_sha256",
        "cloudformation_projection_sha256",
        "executed_at",
        "stack_completed_at",
        "verifier",
        "evaluated_at",
        "evidence_status",
        "authority_status",
        "production_status",
    }
    execution = pep_change_set_receipt["execution_contract"]
    execute_event = receipt.get("execute_event")
    stack_events = receipt.get("stack_events")
    terminal = receipt.get("terminal_resources")
    stack_outputs = receipt.get("stack_outputs")
    stack_resources = receipt.get("stack_resources")
    verifier = receipt.get("verifier")
    expected_terminal = {
        **_pep_expected_resource_types(),
        STACK_NAME: "AWS::CloudFormation::Stack",
    }
    cloudformation_projection = {
        key: receipt.get(key)
        for key in (
            "stack_parameters_sha256",
            "stack_tags",
            "stack_outputs_sha256",
            "stack_resources_sha256",
        )
    }
    _validate_phase_b_ledger_readback_binding(
        readback=receipt.get("broker_ledger_provider_readback"),
        readback_sha256=receipt.get(
            "broker_ledger_provider_readback_sha256"
        ),
        broker_effect_receipt=broker_effect_receipt,
    )
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != required
        or receipt.get("artifact_type") != PEP_EXECUTION_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("phase") != "B_PEP_EXECUTION_TRACE"
        or receipt.get("source_commit") != deployment_contract["source_commit"]
        or receipt.get("deployment_contract_sha256") != _digest(deployment_contract)
        or receipt.get("pep_change_set_receipt_sha256")
        != _digest(pep_change_set_receipt)
        or receipt.get(
            "phase_b_precondition_parameter_handoff_sha256"
        )
        != _digest(phase_b_precondition_parameter_handoff)
        or receipt.get(
            "phase_b_precondition_change_set_receipt_sha256"
        )
        != _digest(phase_b_precondition_change_set_receipt)
        or receipt.get("broker_effect_receipt_sha256")
        != _validate_phase_b_broker_effect_receipt(
            receipt=broker_effect_receipt,
            pep_change_set_receipt=pep_change_set_receipt,
            phase_b_precondition_parameter_handoff=(
                phase_b_precondition_parameter_handoff
            ),
            phase_b_precondition_change_set_receipt=(
                phase_b_precondition_change_set_receipt
            ),
        )
        or receipt.get("change_set_arn") != change_set["arn"]
        or receipt.get("change_set_uuid") != change_set["uuid"]
        or receipt.get("stack_arn") != change_set["stack_arn"]
        or receipt.get("client_request_token")
        != execution["client_request_token"]
        or receipt.get("client_request_token_sha256")
        != execution["client_request_token_sha256"]
        or receipt.get("execute_request_sha256")
        != execution["execute_request_sha256"]
        or receipt.get("effect_principal_arn_sha256")
        != execution["effect_principal_arn_sha256"]
        or not isinstance(execute_event, Mapping)
        or set(execute_event) != {"event_id", "event_time", "event_digest"}
        or not isinstance(execute_event.get("event_id"), str)
        or not execute_event.get("event_id")
        or _DIGEST_RE.fullmatch(str(execute_event.get("event_digest"))) is None
        or not isinstance(receipt.get("stack_event_count"), int)
        or receipt.get("stack_event_count", 0) < 2 * len(expected_terminal)
        or receipt.get("stack_event_count", 0) > 240
        or not isinstance(stack_events, list)
        or len(stack_events) != len(expected_terminal)
        or receipt.get("stack_events_sha256") != _digest(stack_events)
        or _DIGEST_RE.fullmatch(str(receipt.get("stack_events_sha256"))) is None
        or not isinstance(terminal, list)
        or len(terminal) != len(expected_terminal)
        or _DIGEST_RE.fullmatch(str(receipt.get("stack_parameters_sha256")))
        is None
        or receipt.get("stack_tags")
        != _permission_set_tags(str(deployment_contract["source_commit"]))
        or not isinstance(stack_outputs, list)
        or receipt.get("stack_outputs_sha256") != _digest(stack_outputs)
        or _DIGEST_RE.fullmatch(str(receipt.get("stack_outputs_sha256"))) is None
        or not isinstance(stack_resources, list)
        or len(stack_resources) != len(_pep_expected_resource_types())
        or receipt.get("stack_resources_sha256") != _digest(stack_resources)
        or _DIGEST_RE.fullmatch(str(receipt.get("stack_resources_sha256")))
        is None
        or receipt.get("cloudformation_projection_sha256")
        != _digest(cloudformation_projection)
        or not isinstance(verifier, Mapping)
        or verifier.get("profile") != EXPECTED_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
        or receipt.get("evidence_status")
        != "CLOUDFORMATION_EXECUTION_TRACE_VERIFIED"
        or receipt.get("authority_status")
        != "PROVIDER_DERIVED_CLOUDFORMATION_TRACE_NOT_EFFECTIVE_STATE"
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
    observed_terminal: dict[str, str] = {}
    for item in terminal:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "event_id",
                "event_time",
                "logical_resource_id",
                "resource_type",
                "resource_status",
                "physical_resource_id_sha256",
            }
            or not isinstance(item.get("event_id"), str)
            or not item.get("event_id")
            or item.get("resource_status") != "CREATE_COMPLETE"
            or _DIGEST_RE.fullmatch(
                str(item.get("physical_resource_id_sha256"))
            )
            is None
            or not isinstance(item.get("logical_resource_id"), str)
            or item["logical_resource_id"] in observed_terminal
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        _timestamp(item.get("event_time"), "PEP_EXECUTION_RECEIPT_TIME_INVALID")
        observed_terminal[item["logical_resource_id"]] = str(
            item.get("resource_type")
        )
    if (
        observed_terminal != expected_terminal
        or list(observed_terminal) != list(expected_terminal)
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")

    expected_resource_snapshot_types = _pep_expected_resource_types()
    observed_resource_snapshot: dict[str, str] = {}
    for item in stack_resources:
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {
                "logical_resource_id",
                "resource_type",
                "physical_resource_id_sha256",
            }
            or not isinstance(item.get("logical_resource_id"), str)
            or item["logical_resource_id"] in observed_resource_snapshot
            or _DIGEST_RE.fullmatch(
                str(item.get("physical_resource_id_sha256"))
            )
            is None
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        observed_resource_snapshot[item["logical_resource_id"]] = str(
            item.get("resource_type")
        )
    if (
        observed_resource_snapshot != expected_resource_snapshot_types
        or list(observed_resource_snapshot) != sorted(
            expected_resource_snapshot_types
        )
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")

    expected_output_keys = {
        "InvocationAuthorityInspectorRoleArn",
        "PlanExecutionRoleArn",
        "PlanFunctionAliasArn",
        "ProductionAuthorized",
        "ReconcileExecutionRoleArn",
        "ReconcileFunctionAliasArn",
        "RepairExecutionRoleArn",
        "RepairFunctionAliasArn",
        "RepairLedgerKeyArn",
        "RepairLedgerName",
    }
    observed_output_keys: list[str] = []
    for item in stack_outputs:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"output_key", "output_value_sha256"}
            or not isinstance(item.get("output_key"), str)
            or item["output_key"] in observed_output_keys
            or _DIGEST_RE.fullmatch(str(item.get("output_value_sha256")))
            is None
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        observed_output_keys.append(item["output_key"])
    if (
        set(observed_output_keys) != expected_output_keys
        or observed_output_keys != sorted(expected_output_keys)
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
    production_output = next(
        item
        for item in stack_outputs
        if item["output_key"] == "ProductionAuthorized"
    )
    if production_output["output_value_sha256"] != sha256(
        b"false"
    ).hexdigest():
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")

    expected_transition_types = {
        **_pep_expected_resource_types(),
        STACK_NAME: "AWS::CloudFormation::Stack",
    }
    observed_transition_types: dict[str, str] = {}
    event_ids: set[str] = {str(execute_event["event_id"])}
    transition_event_count = 0
    complete_by_logical_id: dict[str, Mapping[str, Any]] = {}
    for transition in stack_events:
        if (
            not isinstance(transition, Mapping)
            or set(transition)
            != {
                "logical_resource_id",
                "resource_type",
                "client_request_token_sha256",
                "in_progress_events",
                "complete_event",
            }
            or not isinstance(transition.get("logical_resource_id"), str)
            or transition["logical_resource_id"] in observed_transition_types
            or transition.get("client_request_token_sha256")
            != receipt.get("client_request_token_sha256")
            or not isinstance(transition.get("in_progress_events"), list)
            or not transition["in_progress_events"]
            or not isinstance(transition.get("complete_event"), Mapping)
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        logical_id = transition["logical_resource_id"]
        observed_transition_types[logical_id] = str(
            transition.get("resource_type")
        )
        complete_event = transition["complete_event"]
        if (
            set(complete_event)
            != {
                "event_id",
                "event_time",
                "physical_resource_id_sha256",
            }
            or not isinstance(complete_event.get("event_id"), str)
            or not complete_event["event_id"]
            or complete_event["event_id"] in event_ids
            or _DIGEST_RE.fullmatch(
                str(complete_event.get("physical_resource_id_sha256"))
            )
            is None
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        complete_time = _timestamp(
            complete_event.get("event_time"),
            "PEP_EXECUTION_RECEIPT_TIME_INVALID",
        )
        event_ids.add(complete_event["event_id"])
        transition_event_count += 1
        complete_by_logical_id[logical_id] = complete_event
        for progress_event in transition["in_progress_events"]:
            if (
                not isinstance(progress_event, Mapping)
                or set(progress_event)
                != {
                    "event_id",
                    "event_time",
                    "physical_resource_id_sha256",
                }
                or not isinstance(progress_event.get("event_id"), str)
                or not progress_event["event_id"]
                or progress_event["event_id"] in event_ids
                or (
                    progress_event.get("physical_resource_id_sha256")
                    is not None
                    and _DIGEST_RE.fullmatch(
                        str(progress_event.get("physical_resource_id_sha256"))
                    )
                    is None
                )
            ):
                raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
            progress_time = _timestamp(
                progress_event.get("event_time"),
                "PEP_EXECUTION_RECEIPT_TIME_INVALID",
            )
            if progress_time > complete_time:
                raise ChangeSetHandoffError(
                    "PEP_EXECUTION_RECEIPT_TIME_INVALID"
                )
            event_ids.add(progress_event["event_id"])
            transition_event_count += 1
    if (
        observed_transition_types != expected_transition_types
        or list(observed_transition_types) != sorted(expected_transition_types)
        or transition_event_count != receipt.get("stack_event_count")
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")

    terminal_by_logical_id = {
        item["logical_resource_id"]: item for item in terminal
    }
    resource_by_logical_id = {
        item["logical_resource_id"]: item for item in stack_resources
    }
    for logical_id, complete_event in complete_by_logical_id.items():
        terminal_event = terminal_by_logical_id.get(logical_id)
        if (
            terminal_event is None
            or terminal_event["event_id"] != complete_event["event_id"]
            or terminal_event["event_time"] != complete_event["event_time"]
            or terminal_event["physical_resource_id_sha256"]
            != complete_event["physical_resource_id_sha256"]
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")
        if (
            logical_id in expected_resource_snapshot_types
            and resource_by_logical_id[logical_id][
                "physical_resource_id_sha256"
            ]
            != complete_event["physical_resource_id_sha256"]
        ):
            raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_INVALID")

    executed_at = _timestamp(
        receipt.get("executed_at"), "PEP_EXECUTION_RECEIPT_TIME_INVALID"
    )
    completed_at = _timestamp(
        receipt.get("stack_completed_at"), "PEP_EXECUTION_RECEIPT_TIME_INVALID"
    )
    evaluated_at = _timestamp(
        receipt.get("evaluated_at"), "PEP_EXECUTION_RECEIPT_TIME_INVALID"
    )
    repair_not_before = _timestamp(
        deployment_contract["repair_not_before"],
        "DEPLOYMENT_CONTRACT_WINDOW_INVALID",
    )
    repair_not_after = _timestamp(
        deployment_contract["repair_not_after"],
        "DEPLOYMENT_CONTRACT_WINDOW_INVALID",
    )
    max_terminal_time = max(
        _timestamp(
            item["event_time"], "PEP_EXECUTION_RECEIPT_TIME_INVALID"
        )
        for item in terminal
    )
    if (
        receipt.get("executed_at") != execute_event.get("event_time")
        or completed_at < executed_at
        or executed_at < repair_not_before
        or executed_at >= repair_not_after
        or max_terminal_time != completed_at
        or executed_at > evaluated_at
        or completed_at > evaluated_at
    ):
        raise ChangeSetHandoffError("PEP_EXECUTION_RECEIPT_TIME_INVALID")
    for transition in stack_events:
        for event in [
            *transition["in_progress_events"],
            transition["complete_event"],
        ]:
            event_time = _timestamp(
                event["event_time"], "PEP_EXECUTION_RECEIPT_TIME_INVALID"
            )
            if event_time < executed_at or event_time > completed_at:
                raise ChangeSetHandoffError(
                    "PEP_EXECUTION_RECEIPT_TIME_INVALID"
                )


def _readback_pep_execution_trace_and_private_ids(
    *,
    source_root: Path,
    profile_name: str,
    region: str,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    broker_effect_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    reviewed_phase_b_precondition_template_bytes: bytes,
    sts_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    dynamodb_client: Any,
    now: datetime | None = None,
) -> tuple[Mapping[str, Any], Mapping[str, str]]:
    """Read back an already-executed Phase B stack using read-only APIs only."""

    validate_phase_b_execution_preconditions(
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        reviewed_phase_b_precondition_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
    )
    if profile_name != EXPECTED_PROFILE or region != REGION:
        raise ChangeSetHandoffError("VERIFIER_PROFILE_OR_REGION_INVALID")
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise ChangeSetHandoffError("VERIFIER_IDENTITY_INVALID")
    change_set = validate_pep_change_set_receipt(
        receipt=pep_change_set_receipt,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_live_receipt=delegation_live_receipt,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_handoff=pep_handoff,
        reviewed_template_bytes=reviewed_template_bytes,
    )
    stacks = _aws_call(
        cloudformation_client.describe_stacks, StackName=STACK_NAME
    ).get("Stacks")
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], Mapping)
    ):
        raise ChangeSetHandoffError("PEP_STACK_READBACK_INVALID")
    stack = stacks[0]
    expected_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in pep_handoff["parameters"]
    }
    stack_arn = stack.get("StackId")
    if (
        stack_arn != change_set["stack_arn"]
        or stack.get("StackName") != STACK_NAME
        or stack.get("StackStatus") != "CREATE_COMPLETE"
        or stack.get("Capabilities") != list(EXPECTED_CAPABILITIES)
        or _normalize_parameters(stack.get("Parameters")) != expected_parameters
        or _normalize_tags(stack.get("Tags")) != pep_handoff["stack_tags"]
    ):
        raise ChangeSetHandoffError("PEP_STACK_DRIFT")
    stack_creation_time = _provider_datetime(
        stack.get("CreationTime"), "PEP_STACK_CREATION_TIME_INVALID"
    )

    template = _aws_call(
        cloudformation_client.get_template,
        StackName=str(stack_arn),
        TemplateStage="Original",
    ).get("TemplateBody")
    if not isinstance(template, str) or template.encode("utf-8") != reviewed_template_bytes:
        raise ChangeSetHandoffError("PEP_STACK_TEMPLATE_DRIFT")
    _, expected_resource_types = _template_contract(reviewed_template_bytes)
    if expected_resource_types != _pep_expected_resource_types():
        raise ChangeSetHandoffError("PEP_REVIEWED_RESOURCE_INVENTORY_DRIFT")
    resources = _paginate_next_token(
        cloudformation_client,
        "list_stack_resources",
        "StackResourceSummaries",
        StackName=str(stack_arn),
    )
    resource_map: dict[str, tuple[str, str]] = {}
    for item in resources:
        if (
            not isinstance(item, Mapping)
            or item.get("ResourceStatus") != "CREATE_COMPLETE"
            or not isinstance(item.get("LogicalResourceId"), str)
            or not isinstance(item.get("ResourceType"), str)
            or not isinstance(item.get("PhysicalResourceId"), str)
            or not item["PhysicalResourceId"]
            or item["LogicalResourceId"] in resource_map
        ):
            raise ChangeSetHandoffError("PEP_STACK_RESOURCE_DRIFT")
        resource_map[item["LogicalResourceId"]] = (
            item["ResourceType"],
            item["PhysicalResourceId"],
        )
    if {
        logical_id: details[0]
        for logical_id, details in resource_map.items()
    } != expected_resource_types:
        raise ChangeSetHandoffError("PEP_STACK_RESOURCE_DRIFT")
    output_map = _pep_output_readback(stack=stack, resource_map=resource_map)

    verification_time = now or datetime.now(UTC)
    execute_event = _verify_pep_execute_change_set_event(
        cloudtrail_client=cloudtrail_client,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        broker_effect_receipt=broker_effect_receipt,
        stack_creation_time=stack_creation_time,
        verification_time=verification_time,
    )
    broker_ledger_provider_readback = (
        _readback_phase_b_ledger_provider_state(
            dynamodb_client=dynamodb_client,
            broker_effect_receipt=broker_effect_receipt,
            deployment_contract=deployment_contract,
            execute_event=execute_event,
        )
    )
    execution = pep_change_set_receipt["execution_contract"]
    stack_event_proof = _verify_stack_operation_events(
        cloudformation_client=cloudformation_client,
        stack_arn=str(stack_arn),
        client_request_token=str(execution["client_request_token"]),
        execute_event_time=_timestamp(
            execute_event["event_time"], "PEP_CLOUDTRAIL_EVENT_TIME_INVALID"
        ),
        expected_resource_types=expected_resource_types,
        stack_name=STACK_NAME,
        error_prefix="PEP",
        require_progress_events=True,
        include_stack_events=True,
    )
    stack_completed_at = max(
        _timestamp(
            item["event_time"], "PEP_EXECUTION_RECEIPT_TIME_INVALID"
        )
        for item in stack_event_proof["terminal_resources"]
    )
    stack_outputs = _pep_output_snapshot(output_map)
    stack_resources = _pep_resource_snapshot(resource_map)
    cloudformation_projection = {
        "stack_parameters_sha256": _digest(pep_handoff["parameters"]),
        "stack_tags": dict(pep_handoff["stack_tags"]),
        "stack_outputs_sha256": _digest(stack_outputs),
        "stack_resources_sha256": _digest(stack_resources),
    }
    verifier = {
        "profile": profile_name,
        "account_id": identity["Account"],
        "caller_arn": identity["Arn"],
    }
    result = {
        "artifact_type": PEP_EXECUTION_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "phase": "B_PEP_EXECUTION_TRACE",
        "source_commit": deployment_contract["source_commit"],
        "deployment_contract_sha256": _digest(deployment_contract),
        "pep_change_set_receipt_sha256": _digest(pep_change_set_receipt),
        "phase_b_precondition_parameter_handoff_sha256": _digest(
            phase_b_precondition_parameter_handoff
        ),
        "phase_b_precondition_change_set_receipt_sha256": _digest(
            phase_b_precondition_change_set_receipt
        ),
        "broker_effect_receipt_sha256": _digest(broker_effect_receipt),
        "broker_ledger_provider_readback": broker_ledger_provider_readback,
        "broker_ledger_provider_readback_sha256": _digest(
            broker_ledger_provider_readback
        ),
        "change_set_arn": change_set["arn"],
        "change_set_uuid": change_set["uuid"],
        "stack_arn": stack_arn,
        "client_request_token": execution["client_request_token"],
        "client_request_token_sha256": execution["client_request_token_sha256"],
        "execute_request_sha256": execution["execute_request_sha256"],
        "effect_principal_arn_sha256": execution[
            "effect_principal_arn_sha256"
        ],
        "execute_event": execute_event,
        **stack_event_proof,
        **cloudformation_projection,
        "stack_outputs": stack_outputs,
        "stack_resources": stack_resources,
        "cloudformation_projection_sha256": _digest(
            cloudformation_projection
        ),
        "executed_at": execute_event["event_time"],
        "stack_completed_at": _utc_text(stack_completed_at),
        "verifier": verifier,
        "evaluated_at": _utc_text(verification_time),
        "evidence_status": "CLOUDFORMATION_EXECUTION_TRACE_VERIFIED",
        "authority_status": (
            "PROVIDER_DERIVED_CLOUDFORMATION_TRACE_NOT_EFFECTIVE_STATE"
        ),
        "production_status": PRODUCTION_STATUS,
    }
    validate_pep_execution_receipt(
        receipt=result,
        source_root=source_root,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_parameter_handoff=pep_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        reviewed_phase_b_precondition_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
        broker_effect_receipt=broker_effect_receipt,
    )
    private_physical_ids = {
        logical_id: physical_id
        for logical_id, (_, physical_id) in resource_map.items()
    }
    return result, private_physical_ids


def readback_pep_execution_read_only(
    *,
    source_root: Path,
    profile_name: str,
    region: str,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    broker_effect_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    reviewed_phase_b_precondition_template_bytes: bytes,
    sts_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    dynamodb_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Return only the sanitized CloudFormation execution trace."""

    trace, _ = _readback_pep_execution_trace_and_private_ids(
        source_root=source_root,
        profile_name=profile_name,
        region=region,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_live_receipt=delegation_live_receipt,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_handoff=pep_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        broker_effect_receipt=broker_effect_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
        reviewed_phase_b_precondition_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
        sts_client=sts_client,
        cloudformation_client=cloudformation_client,
        cloudtrail_client=cloudtrail_client,
        dynamodb_client=dynamodb_client,
        now=now,
    )
    return trace


def readback_pep_execution_with_effective_state_read_only(
    *,
    source_root: Path,
    profile_name: str,
    region: str,
    signed_receipt: Mapping[str, Any],
    deployment_contract: Mapping[str, Any],
    gug220_intent: Mapping[str, Any],
    gug220_ledger: Mapping[str, Any],
    gug220_receipt: Mapping[str, Any],
    gug220_evidence: Mapping[str, Any],
    delegation_live_receipt: Mapping[str, Any],
    phase_b_identity_materialization_receipt: Mapping[str, Any],
    pep_handoff: Mapping[str, Any],
    pep_change_set_receipt: Mapping[str, Any],
    phase_b_precondition_parameter_handoff: Mapping[str, Any],
    phase_b_precondition_change_set_receipt: Mapping[str, Any],
    broker_effect_receipt: Mapping[str, Any],
    reviewed_template_bytes: bytes,
    reviewed_phase_b_precondition_template_bytes: bytes,
    sts_client: Any,
    cloudformation_client: Any,
    cloudtrail_client: Any,
    iam_client: Any,
    lambda_client: Any,
    dynamodb_client: Any,
    kms_client: Any,
    logs_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Mapping[str, Any]]:
    """Chain sanitized CloudFormation trace to exact direct-provider state."""

    trace, physical_ids = _readback_pep_execution_trace_and_private_ids(
        source_root=source_root,
        profile_name=profile_name,
        region=region,
        signed_receipt=signed_receipt,
        deployment_contract=deployment_contract,
        gug220_intent=gug220_intent,
        gug220_ledger=gug220_ledger,
        gug220_receipt=gug220_receipt,
        gug220_evidence=gug220_evidence,
        delegation_live_receipt=delegation_live_receipt,
        phase_b_identity_materialization_receipt=(
            phase_b_identity_materialization_receipt
        ),
        pep_handoff=pep_handoff,
        pep_change_set_receipt=pep_change_set_receipt,
        phase_b_precondition_parameter_handoff=(
            phase_b_precondition_parameter_handoff
        ),
        phase_b_precondition_change_set_receipt=(
            phase_b_precondition_change_set_receipt
        ),
        broker_effect_receipt=broker_effect_receipt,
        reviewed_template_bytes=reviewed_template_bytes,
        reviewed_phase_b_precondition_template_bytes=(
            reviewed_phase_b_precondition_template_bytes
        ),
        sts_client=sts_client,
        cloudformation_client=cloudformation_client,
        cloudtrail_client=cloudtrail_client,
        dynamodb_client=dynamodb_client,
        now=now,
    )
    from tooling.platform_authority_lambda_audit_repair_effective_state import (
        collect_effective_state_read_only,
    )

    effective_state = collect_effective_state_read_only(
        phase_b_execution_receipt=trace,
        physical_resource_ids=physical_ids,
        reviewed_template_bytes=reviewed_template_bytes,
        pep_parameter_handoff=pep_handoff,
        iam_client=iam_client,
        lambda_client=lambda_client,
        dynamodb_client=dynamodb_client,
        kms_client=kms_client,
        logs_client=logs_client,
        evaluated_at=now,
    )
    return {
        "cloudformation_trace_receipt": trace,
        "effective_state_receipt": effective_state,
    }
