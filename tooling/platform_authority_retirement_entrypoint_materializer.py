"""Fail-closed GUG-363 direct retirement-entrypoint materialization.

The module owns the deterministic repository contract for the one dedicated
GUG-357 single-operator non-production entrypoint stack.  It deliberately
exposes one possible AWS write, ``cloudformation:CreateStack``.  It never
creates or executes a Change Set, updates or deletes a stack, invokes the
retirement broker, uploads an artifact, or performs a blind retry.

All AWS-facing functions accept injected clients.  Repository tests therefore
exercise the complete state machine without credentials or network access.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import subprocess
from typing import Any, Callable, Mapping, Protocol, Sequence
import zipfile

from tooling.platform_authority_change_set_retirement_package import (
    RetirementPackageError,
    runtime_version_arn_digest,
    validate_retirement_package_manifest,
)


IMPLEMENTATION_ISSUE = "GUG-363"
LIVE_ISSUE = "GUG-357"
WORK_PACKAGE = "GUG-363"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
AUTHORIZATION_MODE = "SINGLE_OPERATOR_NONPROD_EXCEPTION"
DEDICATED_STACK_NAME = "scanalyze-platform-authority-gug357-retirement-entrypoint"
RETAINED_SHELL_STACK_NAME = "scanalyze-platform-authority-state-backend"
CLOUDFORMATION_SERVICE_ROLE_NAME = (
    "scanalyze-platform-authority-gug363-cfn-materializer"
)
CLOUDFORMATION_SERVICE_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/"
    f"{CLOUDFORMATION_SERVICE_ROLE_NAME}"
)
TEMPLATE_PATH = Path(
    "bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml"
)
FUNCTION_CONFIGURATOR_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug357-function-configurator.json"
)
LOG_GROUP_NAME = "/aws/lambda/scanalyze-platform-authority-gug215-retirement"
BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
BROKER_FUNCTION_ARN = (
    f"arn:aws:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:{BROKER_FUNCTION_NAME}"
)
BROKER_EXECUTION_ROLE_NAME = "ScanalyzeGug215BrokerExecution"
BROKER_EXECUTION_ROLE_ARN = (
    f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{BROKER_EXECUTION_ROLE_NAME}"
)
BROKER_HANDLER = "tooling.platform_authority_identity_context_pep_runtime.handler"
LOG_RETENTION_DAYS = 365
LOG_ENCRYPTION_MODE = "AWS_OWNED_AT_REST"
PRODUCTION_STATUS = "NO-GO"
MAX_TEMPLATE_BYTES = 51_200
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_STACK_RESOURCE_PAGES = 20
MAX_STACK_EVENT_PAGES = 20
MAX_S3_VERSION_PAGES = 20
MAX_AUTHORIZATION_WINDOW = timedelta(minutes=15)
SIGNING_PLATFORM = "AWSLambda-SHA384-ECDSA"
ARTIFACT_SIGNING_CONTRACT_DOMAIN = (
    b"scanalyze.gug363.artifact-signing-contract.v1\x00"
)
PRE_FUNCTION_BINDING_DOMAIN = (
    b"scanalyze.gug363.pre-function-binding.v1\x00"
)
PRIVATE_PARAMETER_PROJECTION_DOMAIN = (
    b"scanalyze.gug363.private-parameter-projection.v1\x00"
)
PRIVATE_PARAMETER_PROJECTION_KEY = "PrivateParameterProjectionSha256"

INTENT_TYPE = "scanalyze.platform_authority.retirement_entrypoint_intent.v1"
PLAN_TYPE = "scanalyze.platform_authority.retirement_entrypoint_plan.v1"
AUTHORIZATION_TYPE = (
    "scanalyze.platform_authority.retirement_entrypoint_execution_authorization.v1"
)
LEDGER_TYPE = "scanalyze.platform_authority.retirement_entrypoint_execution_ledger.v1"
RECEIPT_TYPE = (
    "scanalyze.platform_authority.retirement_entrypoint_materialization_receipt.v1"
)

ACTIVE_ALIASES = (
    "single-classify",
    "single-reconcile",
    "single-retire",
)
NORMAL_ALIASES = ("classify", "reconcile", "retire")
CAPABILITIES: tuple[str, ...] = ()
ALLOWED_MUTATIONS = ("cloudformation:CreateStack",)
PROHIBITED_OPERATIONS = (
    "cloudformation:CreateChangeSet",
    "cloudformation:DeleteChangeSet",
    "cloudformation:DeleteStack",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:UpdateStack",
    "lambda:InvokeFunction",
    "lambda:InvokeFunctionUrl",
    "lambda:CreateCodeSigningConfig",
    "lambda:DeleteCodeSigningConfig",
    "lambda:DeleteFunctionCodeSigningConfig",
    "lambda:PutFunctionCodeSigningConfig",
    "lambda:UpdateCodeSigningConfig",
    "signer:StartSigningJob",
    "s3:CopyObject",
    "s3:PutObject",
    "terraform:apply",
    "terraform:import",
)
PREFLIGHT_OPERATIONS = (
    "sts:GetCallerIdentity",
    "cloudformation:DescribeStacks",
    "signer:DescribeSigningJob",
    "signer:GetSigningProfile",
    "s3:GetBucketVersioning",
    "s3:HeadObject",
    "s3:GetObject",
    "s3:ListObjectVersions",
    "s3:HeadObject",
    "s3:GetObject",
    "lambda:GetCodeSigningConfig",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionCodeSigningConfig",
    "lambda:GetFunctionConcurrency",
    "lambda:GetRuntimeManagementConfig",
    "lambda:ListTags",
    "lambda:ListVersionsByFunction",
    "lambda:ListAliases",
    "lambda:ListFunctionUrlConfigs",
    "lambda:GetPolicy",
    "cloudformation:DescribeStacks",
)
POST_WRITE_READBACK_OPERATIONS = (
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListStackResources",
    "cloudformation:DescribeStackEvents",
)
RECONCILE_OPERATIONS = (
    "sts:GetCallerIdentity",
    "cloudformation:DescribeStacks",
    "signer:DescribeSigningJob",
    "signer:GetSigningProfile",
    "s3:GetBucketVersioning",
    "s3:HeadObject",
    "s3:GetObject",
    "s3:ListObjectVersions",
    "s3:HeadObject",
    "s3:GetObject",
    "lambda:GetCodeSigningConfig",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionCodeSigningConfig",
    "lambda:GetFunctionConcurrency",
    "lambda:GetRuntimeManagementConfig",
    "lambda:ListTags",
    "lambda:ListVersionsByFunction",
    "lambda:ListAliases",
    "lambda:ListFunctionUrlConfigs",
    "lambda:GetPolicy",
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListStackResources",
    "cloudformation:DescribeStackEvents",
)

PARAMETER_KEYS = (
    "AuthorizationMode",
    "AuthorityAccountId",
    "ChangeSetName",
    "RetirementId",
    "ExpectedTemplateSha256",
    "ExpectedEvidenceSha256",
    "ExpectedBrokerPolicySha256",
    PRIVATE_PARAMETER_PROJECTION_KEY,
    "BrokerArtifactBucket",
    "BrokerArtifactKey",
    "BrokerArtifactVersion",
    "BrokerArtifactCodeSha256",
    "BrokerCodeSigningConfigArn",
    "BrokerRuntimeVersionArn",
    "BrokerVersionBindingSha256",
    "IdentityStoreArn",
    "IdentityCenterInstanceArn",
    "IdentityCenterApplicationArn",
    "IdentityCenterRedirectUri",
    "ClassifierIdentityStoreUserId",
    "ApproverIdentityStoreUserId",
    "ClassifierAssignmentSha256",
    "ApproverAssignmentSha256",
    "ClassifierInvokerPolicySha256",
    "ApproverInvokerPolicySha256",
    "ClassifierProofPolicySha256",
    "ApproverProofPolicySha256",
    "IdentityCenterApplicationActorPolicySha256",
    "ClassifierPermissionSetRoleArn",
    "ApproverPermissionSetRoleArn",
    "SingleOperatorOwnerAuthorizationSha256",
    "SingleOperatorExpectedAuthorizationSha256",
    "SingleOperatorExceptionCreatedAt",
    "SingleOperatorExceptionNotBefore",
    "SingleOperatorExceptionExpiresAt",
)

FUNCTION_PARAMETER_ENVIRONMENT = {
    "AUTHORIZATION_MODE": "AuthorizationMode",
    "AUTHORITY_ACCOUNT_ID": "AuthorityAccountId",
    "CHANGE_SET_NAME": "ChangeSetName",
    "RETIREMENT_ID": "RetirementId",
    "EXPECTED_TEMPLATE_SHA256": "ExpectedTemplateSha256",
    "EXPECTED_EVIDENCE_SHA256": "ExpectedEvidenceSha256",
    "EXPECTED_CODE_SHA256": "BrokerArtifactCodeSha256",
    "EXPECTED_BROKER_POLICY_SHA256": "ExpectedBrokerPolicySha256",
    "IDENTITY_STORE_ARN": "IdentityStoreArn",
    "IDENTITY_CENTER_INSTANCE_ARN": "IdentityCenterInstanceArn",
    "IDENTITY_CENTER_APPLICATION_ARN": "IdentityCenterApplicationArn",
    "IDENTITY_CENTER_REDIRECT_URI": "IdentityCenterRedirectUri",
    "CLASSIFIER_IDENTITY_STORE_USER_ID": "ClassifierIdentityStoreUserId",
    "APPROVER_IDENTITY_STORE_USER_ID": "ApproverIdentityStoreUserId",
    "CLASSIFIER_ASSIGNMENT_SHA256": "ClassifierAssignmentSha256",
    "APPROVER_ASSIGNMENT_SHA256": "ApproverAssignmentSha256",
    "CLASSIFIER_INVOKER_POLICY_SHA256": "ClassifierInvokerPolicySha256",
    "APPROVER_INVOKER_POLICY_SHA256": "ApproverInvokerPolicySha256",
    "CLASSIFIER_PROOF_POLICY_SHA256": "ClassifierProofPolicySha256",
    "APPROVER_PROOF_POLICY_SHA256": "ApproverProofPolicySha256",
    "IDENTITY_CENTER_APPLICATION_ACTOR_POLICY_SHA256": (
        "IdentityCenterApplicationActorPolicySha256"
    ),
    "CLASSIFIER_PERMISSION_SET_ROLE_ARN": "ClassifierPermissionSetRoleArn",
    "APPROVER_PERMISSION_SET_ROLE_ARN": "ApproverPermissionSetRoleArn",
    "CODE_SIGNING_CONFIG_ARN": "BrokerCodeSigningConfigArn",
    "BROKER_RUNTIME_VERSION_ARN": "BrokerRuntimeVersionArn",
    "BROKER_VERSION_BINDING_SHA256": "BrokerVersionBindingSha256",
    "SINGLE_OPERATOR_OWNER_AUTHORIZATION_SHA256": (
        "SingleOperatorOwnerAuthorizationSha256"
    ),
    "SINGLE_OPERATOR_EXPECTED_AUTHORIZATION_SHA256": (
        "SingleOperatorExpectedAuthorizationSha256"
    ),
    "SINGLE_OPERATOR_EXCEPTION_CREATED_AT": "SingleOperatorExceptionCreatedAt",
    "SINGLE_OPERATOR_EXCEPTION_NOT_BEFORE": "SingleOperatorExceptionNotBefore",
    "SINGLE_OPERATOR_EXCEPTION_EXPIRES_AT": "SingleOperatorExceptionExpiresAt",
}
FUNCTION_STATIC_ENVIRONMENT = {
    "AUTHORITY_REGION": REGION,
    "CLASSIFIER_INVOKER_ROLE_NAME": "ScanalyzeGug215ClassifierInvoker",
    "APPROVER_INVOKER_ROLE_NAME": "ScanalyzeGug215ApproverInvoker",
    "CLASSIFIER_PROOF_ROLE_NAME": "ScanalyzeGug217ClassifierProof",
    "APPROVER_PROOF_ROLE_NAME": "ScanalyzeGug217ApproverProof",
    "BROKER_EXECUTION_ROLE_NAME": BROKER_EXECUTION_ROLE_NAME,
}
DURABLE_FUNCTION_INPUT_KEYS = (
    "BrokerArtifactBucket",
    "BrokerArtifactKey",
    "BrokerArtifactVersion",
    "BrokerArtifactCodeSha256",
    "BrokerCodeSigningConfigArn",
    "BrokerRuntimeVersionArn",
    "BrokerVersionBindingSha256",
    "ExpectedBrokerPolicySha256",
    "ClassifierInvokerPolicySha256",
    "ApproverInvokerPolicySha256",
    "ClassifierProofPolicySha256",
    "ApproverProofPolicySha256",
    "IdentityCenterApplicationActorPolicySha256",
)
FUNCTION_READBACK_OPERATIONS = (
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionCodeSigningConfig",
    "lambda:GetFunctionConcurrency",
    "lambda:GetRuntimeManagementConfig",
    "lambda:ListTags",
    "lambda:ListVersionsByFunction",
    "lambda:ListAliases",
    "lambda:ListFunctionUrlConfigs",
    "lambda:GetPolicy",
)

NO_ECHO_PARAMETER_KEYS = frozenset(
    {
        "RetirementId",
        "BrokerArtifactVersion",
        "IdentityStoreArn",
        "IdentityCenterInstanceArn",
        "IdentityCenterApplicationArn",
        "IdentityCenterRedirectUri",
        "ClassifierIdentityStoreUserId",
        "ApproverIdentityStoreUserId",
        "ClassifierPermissionSetRoleArn",
        "ApproverPermissionSetRoleArn",
        "SingleOperatorOwnerAuthorizationSha256",
        "SingleOperatorExpectedAuthorizationSha256",
        "SingleOperatorExceptionCreatedAt",
        "SingleOperatorExceptionNotBefore",
        "SingleOperatorExceptionExpiresAt",
    }
)

EXPECTED_RESOURCE_TYPES = tuple(
    sorted(
        {
            "RetirementBrokerLogGroup": "AWS::Logs::LogGroup",
            "RetirementBrokerSingleClassifyAlias": "AWS::Lambda::Alias",
            "RetirementBrokerSingleClassifyUrl": "AWS::Lambda::Url",
            "RetirementBrokerSingleReconcileAlias": "AWS::Lambda::Alias",
            "RetirementBrokerSingleReconcileUrl": "AWS::Lambda::Url",
            "RetirementBrokerSingleRetireAlias": "AWS::Lambda::Alias",
            "RetirementBrokerSingleRetireUrl": "AWS::Lambda::Url",
            "RetirementBrokerVersion": "AWS::Lambda::Version",
            "SingleApproverReconcileFunctionUrlFunctionPermission": (
                "AWS::Lambda::Permission"
            ),
            "SingleApproverReconcileFunctionUrlInvokePermission": (
                "AWS::Lambda::Permission"
            ),
            "SingleApproverRetireFunctionUrlFunctionPermission": (
                "AWS::Lambda::Permission"
            ),
            "SingleApproverRetireFunctionUrlInvokePermission": (
                "AWS::Lambda::Permission"
            ),
            "SingleClassifierFunctionUrlFunctionPermission": (
                "AWS::Lambda::Permission"
            ),
            "SingleClassifierFunctionUrlInvokePermission": (
                "AWS::Lambda::Permission"
            ),
        }.items()
    )
)

TWO_HUMAN_RESOURCE_IDS = frozenset(
    {
        "RetirementBrokerClassifyAlias",
        "RetirementBrokerRetireAlias",
        "RetirementBrokerReconcileAlias",
        "RetirementBrokerClassifyUrl",
        "RetirementBrokerRetireUrl",
        "RetirementBrokerReconcileUrl",
        "ClassifierFunctionUrlInvokePermission",
        "ClassifierFunctionUrlFunctionPermission",
        "ApproverRetireFunctionUrlInvokePermission",
        "ApproverRetireFunctionUrlFunctionPermission",
        "ApproverReconcileFunctionUrlInvokePermission",
        "ApproverReconcileFunctionUrlFunctionPermission",
    }
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_TREE_RE = _COMMIT_RE
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_SHA_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_ACCOUNT_RE = re.compile(r"^(?!000000000000$)[0-9]{12}$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ARTIFACT_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-215/[A-Za-z0-9._/-]+\.zip$"
)
_UNSIGNED_ARTIFACT_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-215/unsigned/[0-9a-f]{40}/"
    r"scanalyze-gug215-change-set-retirement-broker\.zip$"
)
_SIGNED_ARTIFACT_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-215/signed/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.zip$"
)
_SIGNING_JOB_RE = re.compile(
    r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_SIGNING_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_]{2,64}$")
_SIGNING_PROFILE_VERSION_RE = re.compile(r"^[A-Za-z0-9]{10}$")
_SIGNING_PROFILE_VERSION_ARN_RE = re.compile(
    rf"^arn:aws:signer:{re.escape(REGION)}:{AUTHORITY_ACCOUNT_ID}:"
    r"/signing-profiles/(?P<name>[A-Za-z0-9_]{2,64})/"
    r"(?P<version>[A-Za-z0-9]{10})$"
)
_CHANGE_SET_NAME_RE = re.compile(
    r"^scanalyze-platform-authority-bootstrap-[0-9]{14}$"
)
_RETIREMENT_ID_RE = re.compile(r"^gug215#sha256:[0-9a-f]{64}$")
_USER_ID_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RUNTIME_ARN_RE = re.compile(
    rf"^arn:aws:lambda:{re.escape(REGION)}::runtime:[0-9a-f]{{64}}$"
)
_CSC_ARN_RE = re.compile(
    rf"^arn:aws:lambda:{re.escape(REGION)}:{AUTHORITY_ACCOUNT_ID}:"
    r"code-signing-config:csc-[A-Za-z0-9]+$"
)
_KMS_ARN_RE = re.compile(
    rf"^arn:aws:kms:{re.escape(REGION)}:{AUTHORITY_ACCOUNT_ID}:key/"
    r"[0-9a-fA-F-]{36}$"
)
_IDENTITY_STORE_ARN_RE = re.compile(
    rf"^arn:aws:identitystore::{AUTHORITY_ACCOUNT_ID}:identitystore/d-[a-z0-9]{{10,}}$"
)
_INSTANCE_ARN_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_APPLICATION_ARN_RE = re.compile(
    rf"^arn:aws:sso::{AUTHORITY_ACCOUNT_ID}:application/"
    r"ssoins-[A-Za-z0-9]{16}/apl-[A-Za-z0-9]{16}$"
)
_REDIRECT_RE = re.compile(r"^http://127\.0\.0\.1:[0-9]{4,5}/callback$")
_CLASSIFIER_ROLE_RE = re.compile(
    rf"^arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/aws-reserved/"
    r"sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
    r"AWSReservedSSO_ScanalyzeAuthorityRetireClass_[0-9a-fA-F]{16}$"
)
_APPROVER_ROLE_RE = re.compile(
    rf"^arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/aws-reserved/"
    r"sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
    r"AWSReservedSSO_ScanalyzeAuthorityRetireApprove_[0-9a-fA-F]{16}$"
)
_CALLER_ARN_RE = re.compile(
    rf"^arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
    r"[A-Za-z0-9+=,.@_/-]{1,128}/[A-Za-z0-9+=,.@_-]{2,64}$"
)
_STACK_ID_RE = re.compile(
    rf"^arn:aws:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:stack/"
    rf"{re.escape(DEDICATED_STACK_NAME)}/"
    r"[0-9a-fA-F-]{36}$"
)
_TOKEN_RE = re.compile(r"^gug363-[0-9a-f]{48}$")


class RetirementEntrypointMaterializationError(ValueError):
    """A stable sanitized repository-contract failure."""

    def __init__(self, code: str, *, aws_mutation_attempted: bool = False) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) is None:
            code = "GUG363_MATERIALIZATION_INVALID"
        self.code = code
        self.aws_mutation_attempted = aws_mutation_attempted
        super().__init__(code)


class ClientFactory(Protocol):
    def sts(self) -> Any: ...

    def cloudformation(self) -> Any: ...

    def signer(self) -> Any: ...

    def s3(self) -> Any: ...

    def lambda_client(self) -> Any: ...


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def artifact_signing_contract_digest(contract: Mapping[str, Any]) -> str:
    return "sha256:" + sha256(
        ARTIFACT_SIGNING_CONTRACT_DOMAIN
        + canonical_json(contract).encode("utf-8")
    ).hexdigest()


def artifact_signing_evidence_digest(contract: Mapping[str, Any]) -> str:
    """Digest the normalized provider facts required by the signed handoff."""

    signer = contract["signer"]
    unsigned = contract["unsigned_source"]
    return canonical_digest(
        {
            "artifact_signing_contract_digest": artifact_signing_contract_digest(
                contract
            ),
            "signing_job": {
                **signer,
                "source": {
                    "bucket": unsigned["bucket"],
                    "key": unsigned["key"],
                    "version_id": unsigned["version_id"],
                },
                "signed_destination": {
                    "bucket": contract["signed_destination"]["bucket"],
                    "key": contract["signed_destination"]["key"],
                },
            },
            "signing_profile": {
                "profile_name": signer["profile_name"],
                "profile_version_id": signer["profile_version_id"],
                "profile_version_arn": signer["profile_version_arn"],
                "platform_id": signer["platform_id"],
                "status": "Active",
            },
            "bucket_versioning": {
                "bucket": unsigned["bucket"],
                "status": "Enabled",
            },
            "unsigned_source": unsigned,
            "signed_destination": contract["signed_destination"],
            "code_signing_config": contract["code_signing_config"],
        }
    )


def gug363_pre_function_binding_sha256(
    *,
    source: Mapping[str, Any],
    artifact_signing_contract_digest_value: str,
    parameters: Mapping[str, Any],
) -> str:
    """Bind only durable function inputs shared by GUG-363 and GUG-365.

    The private CloudFormation projection and every exception-window value are
    intentionally excluded.  GUG-365 can therefore materialize the inert
    function before GUG-357 issues the fresh configuration authorization.
    """

    durable_inputs = {
        key: parameters[key]
        for key in DURABLE_FUNCTION_INPUT_KEYS
        if key in parameters
    }
    if set(durable_inputs) != set(DURABLE_FUNCTION_INPUT_KEYS):
        raise RetirementEntrypointMaterializationError(
            "PRE_FUNCTION_BINDING_INPUTS_INVALID"
        )
    _validate_source_contract(source)
    _require_digest(
        artifact_signing_contract_digest_value,
        "ARTIFACT_SIGNING_CONTRACT_DIGEST_INVALID",
    )
    return "sha256:" + sha256(
        PRE_FUNCTION_BINDING_DOMAIN
        + canonical_json(
            {
                "source": dict(source),
                "artifact_signing_contract_digest": (
                    artifact_signing_contract_digest_value
                ),
                "durable_function_inputs": durable_inputs,
            }
        ).encode("utf-8")
    ).hexdigest()


def _function_environment(parameters: Mapping[str, Any]) -> dict[str, str]:
    missing = set(FUNCTION_PARAMETER_ENVIRONMENT.values()) - set(parameters)
    if missing:
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_PARAMETERS_INCOMPLETE"
        )
    environment = {
        environment_key: str(parameters[parameter_key])
        for environment_key, parameter_key in FUNCTION_PARAMETER_ENVIRONMENT.items()
    }
    environment.update(FUNCTION_STATIC_ENVIRONMENT)
    return environment


def _expected_broker_safe_configuration_defaults() -> dict[str, dict[str, Any]]:
    """Return optional Lambda surfaces that must remain semantically absent."""

    return {
        "CapacityProviderConfig": {},
        "DurableConfig": {},
        "ImageConfigResponse": {},
        "TenancyConfig": {},
    }


def _function_configurator_policy_document() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
            {
                "Sid": "ReadAndConfigureExactBrokerFunction",
                "Effect": "Allow",
                "Action": [
                    "lambda:GetFunction",
                    "lambda:GetFunctionCodeSigningConfig",
                    "lambda:GetFunctionConcurrency",
                    "lambda:GetFunctionConfiguration",
                    "lambda:GetPolicy",
                    "lambda:GetRuntimeManagementConfig",
                    "lambda:ListAliases",
                    "lambda:ListFunctionUrlConfigs",
                    "lambda:ListTags",
                    "lambda:ListVersionsByFunction",
                    "lambda:UpdateFunctionConfiguration",
                ],
                "Resource": BROKER_FUNCTION_ARN,
            },
            {
                "Sid": "DenyPrivilegeAndDeploymentMutations",
                "Effect": "Deny",
                "Action": [
                    "cloudformation:*",
                    "dynamodb:*",
                    "iam:*",
                    "lambda:AddLayerVersionPermission",
                    "lambda:AddPermission",
                    "lambda:CreateAlias",
                    "lambda:CreateFunction",
                    "lambda:CreateFunctionUrlConfig",
                    "lambda:DeleteAlias",
                    "lambda:DeleteFunction",
                    "lambda:DeleteFunctionCodeSigningConfig",
                    "lambda:DeleteFunctionConcurrency",
                    "lambda:DeleteFunctionUrlConfig",
                    "lambda:InvokeAsync",
                    "lambda:InvokeFunction",
                    "lambda:InvokeFunctionUrl",
                    "lambda:PublishLayerVersion",
                    "lambda:PublishVersion",
                    "lambda:PutFunctionCodeSigningConfig",
                    "lambda:PutFunctionConcurrency",
                    "lambda:PutRuntimeManagementConfig",
                    "lambda:RemoveLayerVersionPermission",
                    "lambda:RemovePermission",
                    "lambda:TagResource",
                    "lambda:UntagResource",
                    "lambda:UpdateAlias",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionEventInvokeConfig",
                    "lambda:UpdateFunctionUrlConfig",
                    "sts:AssumeRole",
                    "sts:TagSession",
                ],
                "Resource": "*",
            },
        ],
    }


def _function_configurator_contract(
    *,
    parameters: Mapping[str, Any],
    pre_function_binding_sha256: str,
    authority_policy_document_digest: str,
) -> dict[str, Any]:
    environment = _function_environment(parameters)
    request_projection = {
        "FunctionName": BROKER_FUNCTION_NAME,
        "Environment": {"Variables": environment},
    }
    return {
        "contract_version": 1,
        "phase": "FUNCTION_CONFIGURATOR",
        "function_name": BROKER_FUNCTION_NAME,
        "function_arn": BROKER_FUNCTION_ARN,
        "gug363_pre_function_binding_sha256": pre_function_binding_sha256,
        "environment_variable_count": len(environment),
        "environment_projection_digest": canonical_digest(environment),
        "update_request_projection": request_projection,
        "update_request_projection_digest": canonical_digest(request_projection),
        "expected_safe_configuration_defaults": (
            _expected_broker_safe_configuration_defaults()
        ),
        "revision_id_mode": "FRESH_PREWRITE_PROVIDER_VALUE_REQUIRED",
        "allowed_action": "lambda:UpdateFunctionConfiguration",
        "authority_policy": {
            "source_path": FUNCTION_CONFIGURATOR_POLICY_PATH.as_posix(),
            "policy_document_digest": authority_policy_document_digest,
            "sole_identity_policy_required": True,
            "identical_permissions_boundary_required": True,
        },
        "attempt_limit": 1,
        "retry_permitted": False,
        "waiter": {
            "api_action": "lambda:GetFunctionConfiguration",
            "poll_interval_seconds": 3,
            "max_poll_attempts": 20,
            "timeout_seconds": 60,
            "expected_state": "Active",
            "expected_last_update_status": "Successful",
        },
        "post_update_readback_operations": list(FUNCTION_READBACK_OPERATIONS),
        "unknown_outcome_mode": "STOP_NO_RETRY_RECONCILE_ONLY",
        "authority_expiry_required_before_create_stack": True,
    }


def _expected_broker_function_tags(plan: Mapping[str, Any]) -> dict[str, str]:
    return {
        "managed_by": "reviewed-direct-lambda",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-365",
        "environment": "non-production",
        "production": "false",
        "source_commit": str(plan["source"]["commit"]),
        "gug363_pre_function_binding_sha256": str(
            plan["gug363_pre_function_binding_sha256"]
        ),
    }


def broker_function_evidence_digest(
    *, plan: Mapping[str, Any], revision_id: str
) -> str:
    """Digest the exact post-configurator Lambda facts without raw locations."""

    if (
        not isinstance(revision_id, str)
        or not revision_id
        or len(revision_id) > 256
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in revision_id)
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_REVISION_ID_INVALID"
        )
    configurator = plan.get("function_configurator")
    signed = plan.get("artifact_signing_contract", {}).get(
        "signed_destination", {}
    )
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan.get("parameter_projection", [])
        if isinstance(item, Mapping)
        and set(item) == {"ParameterKey", "ParameterValue"}
    }
    if not isinstance(configurator, Mapping) or set(parameters) != set(PARAMETER_KEYS):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_EVIDENCE_INPUT_INVALID"
        )
    environment = configurator["update_request_projection"]["Environment"][
        "Variables"
    ]
    return canonical_digest(
        {
            "gug363_pre_function_binding_sha256": plan[
                "gug363_pre_function_binding_sha256"
            ],
            "function_configurator_contract_digest": plan[
                "function_configurator_contract_digest"
            ],
            "function": {
                "function_name": BROKER_FUNCTION_NAME,
                "function_arn": BROKER_FUNCTION_ARN,
                "description": "GUG-215 exact retained Change Set retirement PEP",
                "runtime": "python3.12",
                "role": BROKER_EXECUTION_ROLE_ARN,
                "handler": BROKER_HANDLER,
                "code_size": signed["archive_size_bytes"],
                "code_sha256": signed["lambda_code_sha256"],
                "timeout": 60,
                "memory_size": 256,
                "version": "$LATEST",
                "package_type": "Zip",
                "architectures": ["x86_64"],
                "environment_variables": environment,
                "logging_config": {
                    "LogFormat": "JSON",
                    "ApplicationLogLevel": "ERROR",
                    "SystemLogLevel": "WARN",
                    "LogGroup": LOG_GROUP_NAME,
                },
                "state": "Active",
                "last_update_status": "Successful",
                "revision_id_sha256": digest_text(revision_id),
                "vpc_config": {
                    "SubnetIds": [],
                    "SecurityGroupIds": [],
                    "VpcId": "",
                },
                "layers": [],
                "file_system_configs": [],
                "kms_key_arn": "ABSENT",
                "dead_letter_config": {},
                "tracing_config": {"Mode": "PassThrough"},
                "snap_start": {
                    "ApplyOn": "None",
                    "OptimizationStatus": "Off",
                },
                "ephemeral_storage": {"Size": 512},
                "safe_configuration_defaults": (
                    _expected_broker_safe_configuration_defaults()
                ),
            },
            "signed_code": {
                "s3_bucket": signed["bucket"],
                "s3_key": signed["key"],
                "s3_object_version": signed["version_id"],
                "code_sha256": signed["lambda_code_sha256"],
            },
            "code_signing_config_arn": parameters["BrokerCodeSigningConfigArn"],
            "runtime_management": {
                "UpdateRuntimeOn": "Manual",
                "RuntimeVersionArn": parameters["BrokerRuntimeVersionArn"],
            },
            "reserved_concurrent_executions": 1,
            "tags": _expected_broker_function_tags(plan),
            "versions": ["$LATEST"],
            "aliases": [],
            "function_urls": [],
            "resource_policy": "ABSENT_RESOURCE_NOT_FOUND",
        }
    )


def private_parameter_projection_digest(parameters: Mapping[str, Any]) -> str:
    """Commit visibly to every parameter that CloudFormation may redact."""

    projection = [
        {"ParameterKey": key, "ParameterValue": parameters[key]}
        for key in PARAMETER_KEYS
        if key != PRIVATE_PARAMETER_PROJECTION_KEY
    ]
    return "sha256:" + sha256(
        PRIVATE_PARAMETER_PROJECTION_DOMAIN
        + canonical_json(projection).encode("utf-8")
    ).hexdigest()


def digest_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RetirementEntrypointMaterializationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RetirementEntrypointMaterializationError(code) from None
    if parsed.tzinfo is None or parsed.microsecond:
        raise RetirementEntrypointMaterializationError(code)
    return parsed.astimezone(UTC)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise RetirementEntrypointMaterializationError("CLOCK_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise RetirementEntrypointMaterializationError(code)
    return value


def _self_digest(value: Mapping[str, Any], field: str, code: str) -> None:
    observed = _require_digest(value.get(field), code)
    expected = canonical_digest({key: item for key, item in value.items() if key != field})
    if observed != expected:
        raise RetirementEntrypointMaterializationError(code)


def _target_contract() -> dict[str, str]:
    return {
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "stack_name": DEDICATED_STACK_NAME,
        "cloudformation_service_role_arn": CLOUDFORMATION_SERVICE_ROLE_ARN,
    }


def _validate_source_contract(source: Mapping[str, Any]) -> None:
    if set(source) != {"commit", "tree", "template_path", "template_sha256"}:
        raise RetirementEntrypointMaterializationError("SOURCE_FIELDS_INVALID")
    if (
        _COMMIT_RE.fullmatch(str(source.get("commit"))) is None
        or _TREE_RE.fullmatch(str(source.get("tree"))) is None
        or source.get("template_path") != TEMPLATE_PATH.as_posix()
    ):
        raise RetirementEntrypointMaterializationError("SOURCE_BINDING_INVALID")
    _require_digest(source.get("template_sha256"), "TEMPLATE_DIGEST_INVALID")


def _validate_version_id(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1024
        or value.strip() != value
        or value.casefold() == "null"
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise RetirementEntrypointMaterializationError(code)
    return value


def _validate_artifact_object(
    value: Mapping[str, Any], *, signed: bool
) -> None:
    required = {
        "bucket",
        "key",
        "version_id",
        "archive_sha256",
        "lambda_code_sha256",
        "archive_size_bytes",
        "sse_algorithm",
        "sse_kms_key_arn",
    }
    if not signed:
        required |= {"artifact_type", "work_package", "manifest_digest"}
    archive_size = value.get("archive_size_bytes")
    key_pattern = _SIGNED_ARTIFACT_KEY_RE if signed else _UNSIGNED_ARTIFACT_KEY_RE
    if (
        set(value) != required
        or _BUCKET_RE.fullmatch(str(value.get("bucket"))) is None
        or key_pattern.fullmatch(str(value.get("key"))) is None
        or _HEX_DIGEST_RE.fullmatch(str(value.get("archive_sha256"))) is None
        or _CODE_SHA_RE.fullmatch(str(value.get("lambda_code_sha256"))) is None
        or not isinstance(archive_size, int)
        or isinstance(archive_size, bool)
        or not 0 < archive_size <= MAX_ARTIFACT_BYTES
        or value.get("sse_algorithm") != "aws:kms"
        or _KMS_ARN_RE.fullmatch(str(value.get("sse_kms_key_arn"))) is None
    ):
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_INVALID" if signed else "UNSIGNED_ARTIFACT_INVALID"
        )
    _validate_version_id(
        value.get("version_id"),
        "SIGNED_ARTIFACT_VERSION_INVALID" if signed else "UNSIGNED_ARTIFACT_VERSION_INVALID",
    )
    try:
        decoded_code_sha256 = base64.b64decode(
            str(value["lambda_code_sha256"]), validate=True
        ).hex()
    except (ValueError, TypeError):
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_INVALID" if signed else "UNSIGNED_ARTIFACT_INVALID"
        ) from None
    if decoded_code_sha256 != value["archive_sha256"]:
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_DIGEST_BINDING_INVALID"
            if signed
            else "UNSIGNED_ARTIFACT_DIGEST_BINDING_INVALID"
        )
    if not signed:
        if (
            value.get("artifact_type")
            != "scanalyze.platform_authority.change_set_retirement_package.v1"
            or value.get("work_package") != "GUG-215"
        ):
            raise RetirementEntrypointMaterializationError("UNSIGNED_ARTIFACT_INVALID")
        _require_digest(
            value.get("manifest_digest"), "PACKAGE_MANIFEST_DIGEST_INVALID"
        )


def _validate_artifact_signing_contract(contract: Mapping[str, Any]) -> None:
    if set(contract) != {
        "contract_version",
        "unsigned_source",
        "signer",
        "signed_destination",
        "code_signing_config",
    } or contract.get("contract_version") != 1:
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_CONTRACT_FIELDS_INVALID"
        )
    unsigned = contract.get("unsigned_source")
    signer = contract.get("signer")
    signed = contract.get("signed_destination")
    code_signing = contract.get("code_signing_config")
    if not all(isinstance(item, Mapping) for item in (unsigned, signer, signed, code_signing)):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_CONTRACT_NESTING_INVALID"
        )
    _validate_artifact_object(unsigned, signed=False)
    _validate_artifact_object(signed, signed=True)
    assert isinstance(signer, Mapping) and isinstance(code_signing, Mapping)
    if set(signer) != {
        "job_id",
        "status",
        "job_owner",
        "job_invoker",
        "platform_id",
        "profile_name",
        "profile_version_id",
        "profile_version_arn",
        "signature_expires_at",
    }:
        raise RetirementEntrypointMaterializationError("ARTIFACT_SIGNER_INVALID")
    profile_arn = str(signer.get("profile_version_arn"))
    profile_match = _SIGNING_PROFILE_VERSION_ARN_RE.fullmatch(profile_arn)
    if (
        _SIGNING_JOB_RE.fullmatch(str(signer.get("job_id"))) is None
        or signer.get("status") != "Succeeded"
        or signer.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or signer.get("job_invoker") != AUTHORITY_ACCOUNT_ID
        or signer.get("platform_id") != SIGNING_PLATFORM
        or _SIGNING_PROFILE_NAME_RE.fullmatch(str(signer.get("profile_name"))) is None
        or _SIGNING_PROFILE_VERSION_RE.fullmatch(str(signer.get("profile_version_id"))) is None
        or profile_match is None
        or profile_match.group("name") != signer.get("profile_name")
        or profile_match.group("version") != signer.get("profile_version_id")
    ):
        raise RetirementEntrypointMaterializationError("ARTIFACT_SIGNER_INVALID")
    _parse_timestamp(
        signer.get("signature_expires_at"), "ARTIFACT_SIGNATURE_EXPIRY_INVALID"
    )
    if (
        set(code_signing)
        != {
            "arn",
            "allowed_signing_profile_version_arns",
            "untrusted_artifact_on_deployment",
        }
        or code_signing.get("arn") is None
        or _CSC_ARN_RE.fullmatch(str(code_signing.get("arn"))) is None
        or code_signing.get("allowed_signing_profile_version_arns") != [profile_arn]
        or code_signing.get("untrusted_artifact_on_deployment") != "Enforce"
    ):
        raise RetirementEntrypointMaterializationError(
            "CODE_SIGNING_CONFIG_CONTRACT_INVALID"
        )
    job_id = str(signer["job_id"])
    if (
        unsigned["bucket"] != signed["bucket"]
        or unsigned["sse_kms_key_arn"] != signed["sse_kms_key_arn"]
        or unsigned["key"] == signed["key"]
        or unsigned["version_id"] == signed["version_id"]
        or signed["key"]
        != f"scanalyze/platform-authority/gug-215/signed/{job_id}.zip"
        or unsigned["archive_sha256"] == signed["archive_sha256"]
        or unsigned["lambda_code_sha256"] == signed["lambda_code_sha256"]
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_CAUSAL_BINDING_INVALID"
        )


def _git(root: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=text,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RetirementEntrypointMaterializationError(
            "SOURCE_PROVENANCE_UNAVAILABLE"
        ) from exc
    return result.stdout


def _template_resource_types(template_body: str) -> dict[str, str]:
    resources: dict[str, str] = {}
    in_resources = False
    current: str | None = None
    for line in template_body.splitlines():
        if line == "Resources:":
            in_resources = True
            continue
        if in_resources and line == "Outputs:":
            break
        if not in_resources:
            continue
        logical = re.fullmatch(r"  ([A-Za-z][A-Za-z0-9]+):", line)
        if logical:
            current = logical.group(1)
            continue
        resource_type = re.fullmatch(r"    Type: (AWS::[A-Za-z0-9:]+)", line)
        if current and resource_type:
            resources[current] = resource_type.group(1)
            current = None
    return resources


def _validate_template_contract(template_body: str) -> None:
    encoded = template_body.encode("utf-8")
    if not encoded or len(encoded) > MAX_TEMPLATE_BYTES:
        raise RetirementEntrypointMaterializationError("TEMPLATE_SIZE_INVALID")
    resources = _template_resource_types(template_body)
    expected_all = dict(EXPECTED_RESOURCE_TYPES)
    expected_all.update(
        {
            "RetirementBrokerClassifyAlias": "AWS::Lambda::Alias",
            "RetirementBrokerRetireAlias": "AWS::Lambda::Alias",
            "RetirementBrokerReconcileAlias": "AWS::Lambda::Alias",
            "RetirementBrokerClassifyUrl": "AWS::Lambda::Url",
            "RetirementBrokerRetireUrl": "AWS::Lambda::Url",
            "RetirementBrokerReconcileUrl": "AWS::Lambda::Url",
            "ClassifierFunctionUrlInvokePermission": "AWS::Lambda::Permission",
            "ClassifierFunctionUrlFunctionPermission": "AWS::Lambda::Permission",
            "ApproverRetireFunctionUrlInvokePermission": "AWS::Lambda::Permission",
            "ApproverRetireFunctionUrlFunctionPermission": "AWS::Lambda::Permission",
            "ApproverReconcileFunctionUrlInvokePermission": "AWS::Lambda::Permission",
            "ApproverReconcileFunctionUrlFunctionPermission": "AWS::Lambda::Permission",
        }
    )
    if resources != expected_all:
        raise RetirementEntrypointMaterializationError(
            "TEMPLATE_RESOURCE_SET_INVALID"
        )
    required_fragments = (
        "AllowedValues:\n      - TWO_HUMAN\n      - SINGLE_OPERATOR_NONPROD_EXCEPTION",
        "PrivateParameterProjectionSha256:\n    Type: String\n"
        "    AllowedPattern: '^sha256:[a-f0-9]{64}$'",
        "RetirementBrokerLogGroup:\n    Type: AWS::Logs::LogGroup\n"
        "    DeletionPolicy: Retain\n    UpdateReplacePolicy: Retain",
        "LogGroupName: /aws/lambda/scanalyze-platform-authority-gug215-retirement",
        f"RetentionInDays: {LOG_RETENTION_DAYS}",
        f"FunctionName: {BROKER_FUNCTION_NAME}",
        "TargetFunctionArn: !Sub arn:${AWS::Partition}:lambda:${AWS::Region}:"
        "${AuthorityAccountId}:function:"
        f"{BROKER_FUNCTION_NAME}",
        "Name: single-classify",
        "Name: single-reconcile",
        "Name: single-retire",
        "AuthType: AWS_IAM",
        "Principal: !Sub arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeGug215ClassifierInvoker",
        "Principal: !Sub arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeGug215ApproverInvoker",
    )
    if any(fragment not in template_body for fragment in required_fragments):
        raise RetirementEntrypointMaterializationError(
            "TEMPLATE_CONTROL_SET_INVALID"
        )
    function_arn = (
        "arn:${AWS::Partition}:lambda:${AWS::Region}:${AuthorityAccountId}:"
        f"function:{BROKER_FUNCTION_NAME}"
    )
    if (
        template_body.count(f"      FunctionName: {BROKER_FUNCTION_NAME}") != 7
        or template_body.count(f"      TargetFunctionArn: !Sub {function_arn}")
        != 6
        or template_body.count(f"      FunctionName: !Sub {function_arn}:") != 12
        or template_body.count(f"    Value: {BROKER_FUNCTION_NAME}") != 1
    ):
        raise RetirementEntrypointMaterializationError(
            "TEMPLATE_PRECREATED_FUNCTION_BINDING_INVALID"
        )
    if "$LATEST" in template_body:
        raise RetirementEntrypointMaterializationError("LATEST_ALIAS_FORBIDDEN")
    if (
        "Type: AWS::Lambda::Function" in template_body
        or "RetirementBrokerFunction" in template_body
    ):
        raise RetirementEntrypointMaterializationError(
            "TEMPLATE_FUNCTION_CREATE_FORBIDDEN"
        )
    if "KmsKeyId:" in template_body:
        raise RetirementEntrypointMaterializationError(
            "LOG_GROUP_ENCRYPTION_MODE_INVALID"
        )
    if (
        "Type: AWS::IAM::" in template_body
        or "Type: AWS::DynamoDB::" in template_body
        or "ResourcePolicy:" in template_body
        or "dynamodb:PutResourcePolicy" in template_body
    ):
        raise RetirementEntrypointMaterializationError(
            "TEMPLATE_EXTERNAL_AUTHORITY_MUTATION_FORBIDDEN"
        )


def _source_snapshot(repo_root: Path, source: Mapping[str, Any]) -> tuple[str, str]:
    root = repo_root.resolve(strict=True)
    head = str(_git(root, "rev-parse", "HEAD")).strip()
    tree = str(_git(root, "rev-parse", "HEAD^{tree}")).strip()
    dirty = str(
        _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    )
    if dirty:
        raise RetirementEntrypointMaterializationError("SOURCE_TREE_DIRTY")
    if head != source.get("commit") or tree != source.get("tree"):
        raise RetirementEntrypointMaterializationError("SOURCE_SNAPSHOT_MISMATCH")
    if source.get("template_path") != TEMPLATE_PATH.as_posix():
        raise RetirementEntrypointMaterializationError("TEMPLATE_PATH_INVALID")
    committed = bytes(
        _git(root, "show", f"{head}:{TEMPLATE_PATH.as_posix()}", text=False)
    )
    candidate = root / TEMPLATE_PATH
    try:
        if candidate.is_symlink() or not candidate.is_file():
            raise OSError
        working = candidate.read_bytes()
    except OSError as exc:
        raise RetirementEntrypointMaterializationError("TEMPLATE_UNAVAILABLE") from exc
    if working != committed:
        raise RetirementEntrypointMaterializationError("TEMPLATE_COMMIT_DRIFT")
    policy_path = FUNCTION_CONFIGURATOR_POLICY_PATH.as_posix()
    policy_committed = bytes(
        _git(root, "show", f"{head}:{policy_path}", text=False)
    )
    policy_candidate = root / FUNCTION_CONFIGURATOR_POLICY_PATH
    try:
        if policy_candidate.is_symlink() or not policy_candidate.is_file():
            raise OSError
        policy_working = policy_candidate.read_bytes()
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_POLICY_UNAVAILABLE"
        ) from exc
    if policy_working != policy_committed:
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_POLICY_COMMIT_DRIFT"
        )
    try:
        policy_document = json.loads(policy_committed.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_POLICY_INVALID"
        ) from exc
    if policy_document != _function_configurator_policy_document():
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_POLICY_INVALID"
        )
    try:
        body = committed.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RetirementEntrypointMaterializationError("TEMPLATE_ENCODING_INVALID") from exc
    expected_digest = "sha256:" + sha256(committed).hexdigest()
    if source.get("template_sha256") != expected_digest:
        raise RetirementEntrypointMaterializationError("TEMPLATE_DIGEST_MISMATCH")
    _validate_template_contract(body)
    return body, canonical_digest(policy_document)


def _validate_parameters(
    parameters: Mapping[str, Any],
    *,
    source: Mapping[str, Any],
    artifact_signing_contract: Mapping[str, Any],
    owner_authorization_sha256: str,
    exception_digest: str,
) -> None:
    if set(parameters) != set(PARAMETER_KEYS) or any(
        not isinstance(parameters[key], str) for key in PARAMETER_KEYS
    ):
        raise RetirementEntrypointMaterializationError("PARAMETER_SET_INVALID")
    signed_destination = artifact_signing_contract["signed_destination"]
    code_signing_config = artifact_signing_contract["code_signing_config"]
    constants = {
        "AuthorizationMode": AUTHORIZATION_MODE,
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "ExpectedTemplateSha256": source.get("template_sha256"),
        "BrokerArtifactBucket": signed_destination.get("bucket"),
        "BrokerArtifactKey": signed_destination.get("key"),
        "BrokerArtifactVersion": signed_destination.get("version_id"),
        "BrokerArtifactCodeSha256": signed_destination.get("lambda_code_sha256"),
        "BrokerCodeSigningConfigArn": code_signing_config.get("arn"),
        "SingleOperatorOwnerAuthorizationSha256": owner_authorization_sha256,
        "SingleOperatorExpectedAuthorizationSha256": exception_digest,
    }
    if any(parameters.get(key) != value for key, value in constants.items()):
        raise RetirementEntrypointMaterializationError("PARAMETER_BINDING_MISMATCH")
    if parameters[PRIVATE_PARAMETER_PROJECTION_KEY] != (
        private_parameter_projection_digest(parameters)
    ):
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_PARAMETER_PROJECTION_DIGEST_MISMATCH"
        )
    if _CHANGE_SET_NAME_RE.fullmatch(parameters["ChangeSetName"]) is None:
        raise RetirementEntrypointMaterializationError("CHANGE_SET_NAME_INVALID")
    if _RETIREMENT_ID_RE.fullmatch(parameters["RetirementId"]) is None:
        raise RetirementEntrypointMaterializationError("RETIREMENT_ID_INVALID")
    for key in (
        "ExpectedTemplateSha256",
        "ExpectedEvidenceSha256",
        "ExpectedBrokerPolicySha256",
        PRIVATE_PARAMETER_PROJECTION_KEY,
        "BrokerVersionBindingSha256",
        "ClassifierAssignmentSha256",
        "ApproverAssignmentSha256",
        "ClassifierInvokerPolicySha256",
        "ApproverInvokerPolicySha256",
        "ClassifierProofPolicySha256",
        "ApproverProofPolicySha256",
        "IdentityCenterApplicationActorPolicySha256",
        "SingleOperatorOwnerAuthorizationSha256",
        "SingleOperatorExpectedAuthorizationSha256",
    ):
        _require_digest(parameters[key], "PARAMETER_DIGEST_INVALID")
    if _CODE_SHA_RE.fullmatch(parameters["BrokerArtifactCodeSha256"]) is None:
        raise RetirementEntrypointMaterializationError("CODE_SHA256_INVALID")
    if _CSC_ARN_RE.fullmatch(parameters["BrokerCodeSigningConfigArn"]) is None:
        raise RetirementEntrypointMaterializationError("CODE_SIGNING_ARN_INVALID")
    if _RUNTIME_ARN_RE.fullmatch(parameters["BrokerRuntimeVersionArn"]) is None:
        raise RetirementEntrypointMaterializationError("RUNTIME_VERSION_ARN_INVALID")
    if _IDENTITY_STORE_ARN_RE.fullmatch(parameters["IdentityStoreArn"]) is None:
        raise RetirementEntrypointMaterializationError("IDENTITY_STORE_ARN_INVALID")
    if _INSTANCE_ARN_RE.fullmatch(parameters["IdentityCenterInstanceArn"]) is None:
        raise RetirementEntrypointMaterializationError("INSTANCE_ARN_INVALID")
    if _APPLICATION_ARN_RE.fullmatch(parameters["IdentityCenterApplicationArn"]) is None:
        raise RetirementEntrypointMaterializationError("APPLICATION_ARN_INVALID")
    if _REDIRECT_RE.fullmatch(parameters["IdentityCenterRedirectUri"]) is None:
        raise RetirementEntrypointMaterializationError("REDIRECT_URI_INVALID")
    classifier = parameters["ClassifierIdentityStoreUserId"]
    approver = parameters["ApproverIdentityStoreUserId"]
    if (
        _USER_ID_RE.fullmatch(classifier) is None
        or _USER_ID_RE.fullmatch(approver) is None
        or classifier.lower() != approver.lower()
    ):
        raise RetirementEntrypointMaterializationError(
            "SINGLE_OPERATOR_USER_BINDING_INVALID"
        )
    if _CLASSIFIER_ROLE_RE.fullmatch(parameters["ClassifierPermissionSetRoleArn"]) is None:
        raise RetirementEntrypointMaterializationError("CLASSIFIER_ROLE_ARN_INVALID")
    if _APPROVER_ROLE_RE.fullmatch(parameters["ApproverPermissionSetRoleArn"]) is None:
        raise RetirementEntrypointMaterializationError("APPROVER_ROLE_ARN_INVALID")
    created = _parse_timestamp(
        parameters["SingleOperatorExceptionCreatedAt"], "EXCEPTION_WINDOW_INVALID"
    )
    not_before = _parse_timestamp(
        parameters["SingleOperatorExceptionNotBefore"], "EXCEPTION_WINDOW_INVALID"
    )
    expires = _parse_timestamp(
        parameters["SingleOperatorExceptionExpiresAt"], "EXCEPTION_WINDOW_INVALID"
    )
    if (
        created > not_before
        or expires <= not_before
        or expires - not_before > MAX_AUTHORIZATION_WINDOW
    ):
        raise RetirementEntrypointMaterializationError("EXCEPTION_WINDOW_INVALID")


def validate_materialization_intent(intent: Mapping[str, Any]) -> None:
    required = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "live_issue",
        "environment",
        "production",
        "deployment_authorized",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "target",
        "source",
        "artifact_signing_contract",
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
        "gug363_pre_function_binding_sha256",
        "parameters",
        "owner_authorization_sha256",
        "single_operator_exception_digest",
        "intent_digest",
    }
    if not isinstance(intent, Mapping) or set(intent) != required:
        raise RetirementEntrypointMaterializationError("INTENT_FIELDS_INVALID")
    constants = {
        "record_type": INTENT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": False,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    if any(intent.get(key) != value for key, value in constants.items()):
        raise RetirementEntrypointMaterializationError("INTENT_SCOPE_INVALID")
    target = intent.get("target")
    source = intent.get("source")
    artifact_signing_contract = intent.get("artifact_signing_contract")
    parameters = intent.get("parameters")
    if not all(
        isinstance(value, Mapping)
        for value in (target, source, artifact_signing_contract, parameters)
    ):
        raise RetirementEntrypointMaterializationError("INTENT_NESTING_INVALID")
    if target != _target_contract():
        raise RetirementEntrypointMaterializationError("TARGET_BINDING_INVALID")
    if DEDICATED_STACK_NAME == RETAINED_SHELL_STACK_NAME:
        raise RetirementEntrypointMaterializationError("TARGET_NOT_DEDICATED")
    _validate_source_contract(source)
    _validate_artifact_signing_contract(artifact_signing_contract)
    expected_unsigned_key = (
        "scanalyze/platform-authority/gug-215/unsigned/"
        f"{source['commit']}/scanalyze-gug215-change-set-retirement-broker.zip"
    )
    if artifact_signing_contract["unsigned_source"]["key"] != expected_unsigned_key:
        raise RetirementEntrypointMaterializationError(
            "UNSIGNED_ARTIFACT_SOURCE_COMMIT_MISMATCH"
        )
    contract_digest = _require_digest(
        intent.get("artifact_signing_contract_digest"),
        "ARTIFACT_SIGNING_CONTRACT_DIGEST_INVALID",
    )
    evidence_digest = _require_digest(
        intent.get("artifact_signing_evidence_digest"),
        "ARTIFACT_SIGNING_EVIDENCE_DIGEST_INVALID",
    )
    if contract_digest != artifact_signing_contract_digest(artifact_signing_contract):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_CONTRACT_DIGEST_MISMATCH"
        )
    if evidence_digest != artifact_signing_evidence_digest(
        artifact_signing_contract
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_EVIDENCE_DIGEST_MISMATCH"
        )
    owner_digest = _require_digest(
        intent.get("owner_authorization_sha256"), "OWNER_AUTHORIZATION_INVALID"
    )
    exception_digest = _require_digest(
        intent.get("single_operator_exception_digest"), "EXCEPTION_DIGEST_INVALID"
    )
    _validate_parameters(
        parameters,
        source=source,
        artifact_signing_contract=artifact_signing_contract,
        owner_authorization_sha256=owner_digest,
        exception_digest=exception_digest,
    )
    expected_pre_function_binding = gug363_pre_function_binding_sha256(
        source=source,
        artifact_signing_contract_digest_value=contract_digest,
        parameters=parameters,
    )
    if (
        _require_digest(
            intent.get("gug363_pre_function_binding_sha256"),
            "PRE_FUNCTION_BINDING_DIGEST_INVALID",
        )
        != expected_pre_function_binding
    ):
        raise RetirementEntrypointMaterializationError(
            "PRE_FUNCTION_BINDING_DIGEST_MISMATCH"
        )
    _self_digest(intent, "intent_digest", "INTENT_DIGEST_MISMATCH")


def build_materialization_plan(
    *,
    intent: Mapping[str, Any],
    package_manifest: Mapping[str, Any],
    package_archive: bytes,
    repo_root: Path,
) -> dict[str, Any]:
    """Build the exact private plan and CreateStack projection offline."""

    validate_materialization_intent(intent)
    if not isinstance(package_archive, bytes) or len(package_archive) > MAX_ARTIFACT_BYTES:
        raise RetirementEntrypointMaterializationError("PACKAGE_ARCHIVE_SIZE_INVALID")
    try:
        validate_retirement_package_manifest(package_manifest, archive=package_archive)
    except RetirementPackageError as exc:
        raise RetirementEntrypointMaterializationError("PACKAGE_BINDING_INVALID") from exc
    source = dict(intent["source"])
    template_body, authority_policy_document_digest = _source_snapshot(
        repo_root, source
    )
    parameters = dict(intent["parameters"])
    artifact_signing_contract = dict(intent["artifact_signing_contract"])
    unsigned_source = artifact_signing_contract["unsigned_source"]
    if (
        package_manifest.get("source_commit") != source["commit"]
        or package_manifest.get("lambda_code_sha256")
        != unsigned_source["lambda_code_sha256"]
        or package_manifest.get("broker_version_binding_sha256")
        != parameters["BrokerVersionBindingSha256"]
        or package_manifest.get("broker_runtime_version_arn_digest")
        != runtime_version_arn_digest(parameters["BrokerRuntimeVersionArn"])
    ):
        raise RetirementEntrypointMaterializationError("PACKAGE_BINDING_MISMATCH")
    projection = [
        {"ParameterKey": key, "ParameterValue": parameters[key]}
        for key in PARAMETER_KEYS
    ]
    projection_digest = canonical_digest(projection)
    pre_function_binding = str(intent["gug363_pre_function_binding_sha256"])
    function_configurator = _function_configurator_contract(
        parameters=parameters,
        pre_function_binding_sha256=pre_function_binding,
        authority_policy_document_digest=authority_policy_document_digest,
    )
    function_configurator_contract_digest = canonical_digest(
        function_configurator
    )
    resources = [
        {"logical_resource_id": logical_id, "resource_type": resource_type}
        for logical_id, resource_type in EXPECTED_RESOURCE_TYPES
    ]
    resource_digest = canonical_digest(resources)
    if unsigned_source != {
        **{
            key: unsigned_source[key]
            for key in (
                "bucket",
                "key",
                "version_id",
                "sse_algorithm",
                "sse_kms_key_arn",
            )
        },
        "artifact_type": package_manifest["artifact_type"],
        "work_package": package_manifest["work_package"],
        "manifest_digest": package_manifest["manifest_digest"],
        "archive_sha256": package_manifest["archive_sha256"],
        "lambda_code_sha256": package_manifest["lambda_code_sha256"],
        "archive_size_bytes": package_manifest["archive_size_bytes"],
    }:
        raise RetirementEntrypointMaterializationError(
            "UNSIGNED_PACKAGE_CONTRACT_MISMATCH"
        )
    binding = {
        "intent_digest": intent["intent_digest"],
        "source": source,
        "target": dict(intent["target"]),
        "parameter_projection_digest": projection_digest,
        "expected_resource_set_digest": resource_digest,
        "artifact_signing_contract": artifact_signing_contract,
        "artifact_signing_contract_digest": intent[
            "artifact_signing_contract_digest"
        ],
        "artifact_signing_evidence_digest": intent[
            "artifact_signing_evidence_digest"
        ],
        "gug363_pre_function_binding_sha256": pre_function_binding,
        "function_configurator_contract_digest": (
            function_configurator_contract_digest
        ),
        "function_configuration_state": "PRE_FUNCTION",
        "broker_function_evidence_digest": None,
        "function_configurator_checkpoint_digest": None,
        "authorization_mode": AUTHORIZATION_MODE,
        "log_group": {
            "name": LOG_GROUP_NAME,
            "retention_days": LOG_RETENTION_DAYS,
            "encryption_mode": LOG_ENCRYPTION_MODE,
        },
    }
    binding_digest = canonical_digest(binding)
    token = "gug363-" + binding_digest.removeprefix("sha256:")[:48]
    request = {
        "StackName": DEDICATED_STACK_NAME,
        "TemplateBody": template_body,
        "Parameters": projection,
        "Capabilities": list(CAPABILITIES),
        "RoleARN": CLOUDFORMATION_SERVICE_ROLE_ARN,
        "OnFailure": "DO_NOTHING",
        "EnableTerminationProtection": True,
        "ClientRequestToken": token,
    }
    request_digest = canonical_digest(request)
    materialization_operations = [
        {
            "sequence": 1,
            "service": "cloudformation",
            "api_action": "CreateStack",
            "effect": "CREATE_DEDICATED_ENTRYPOINT_STACK_ONLY",
            "target_digest": canonical_digest(intent["target"]),
            "request_projection_digest": request_digest,
            "conditional_behavior": "TARGET_ABSENT_AFTER_TWO_EXACT_DESCRIBES",
            "client_request_token_sha256": digest_text(token),
            "attempt_limit": 1,
            "retry_permitted": False,
            "expected_response_class": "CreateStackOutput.StackId",
            "immediate_readback": list(POST_WRITE_READBACK_OPERATIONS),
            "unknown_outcome_reconciliation": list(RECONCILE_OPERATIONS),
            "rollback": {
                "automatic": False,
                "delete_stack_authorized": False,
                "mode": "SEPARATE_OWNER_CHECKPOINT_REQUIRED",
            },
        }
    ]
    plan: dict[str, Any] = {
        "record_type": PLAN_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": False,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "intent_digest": intent["intent_digest"],
        "owner_authorization_sha256": intent["owner_authorization_sha256"],
        "single_operator_exception_digest": intent[
            "single_operator_exception_digest"
        ],
        "source": source,
        "target": dict(intent["target"]),
        "artifact_signing_contract": artifact_signing_contract,
        "artifact_signing_contract_digest": intent[
            "artifact_signing_contract_digest"
        ],
        "artifact_signing_evidence_digest": intent[
            "artifact_signing_evidence_digest"
        ],
        "gug363_pre_function_binding_sha256": pre_function_binding,
        "function_configurator": function_configurator,
        "function_configurator_contract_digest": (
            function_configurator_contract_digest
        ),
        "function_configuration_state": "PRE_FUNCTION",
        "broker_function_evidence_digest": None,
        "function_configurator_checkpoint_digest": None,
        "parameter_projection": projection,
        "parameter_projection_digest": projection_digest,
        "expected_resources": resources,
        "expected_resource_count": len(resources),
        "expected_resource_set_digest": resource_digest,
        "active_aliases": list(ACTIVE_ALIASES),
        "normal_aliases_present": False,
        "log_group": binding["log_group"],
        "preflight_operations": list(PREFLIGHT_OPERATIONS),
        "allowed_mutations": list(ALLOWED_MUTATIONS),
        "prohibited_operations": list(PROHIBITED_OPERATIONS),
        "post_write_readback_operations": list(POST_WRITE_READBACK_OPERATIONS),
        "materialization_operations": materialization_operations,
        "operation_list_digest": canonical_digest(materialization_operations),
        "ambiguous_outcome_mode": "RECONCILE_ONLY",
        "mutation_retry_permitted": False,
        "materialization_binding_digest": binding_digest,
        "create_stack_request": request,
        "create_stack_request_digest": request_digest,
        "client_request_token": token,
        "plan_digest": "",
    }
    plan["plan_digest"] = canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )
    validate_materialization_plan(plan, repo_root=repo_root)
    return plan


def finalize_materialization_plan(
    *,
    pre_function_plan: Mapping[str, Any],
    broker_function_evidence_digest: str,
    function_configurator_checkpoint_digest: str,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Seal the post-configurator plan without weakening the stable pre-binding."""

    validate_materialization_plan(pre_function_plan, repo_root=repo_root)
    if pre_function_plan.get("function_configuration_state") != "PRE_FUNCTION":
        raise RetirementEntrypointMaterializationError(
            "PLAN_ALREADY_FUNCTION_CONFIGURED"
        )
    _require_digest(
        broker_function_evidence_digest,
        "BROKER_FUNCTION_EVIDENCE_DIGEST_INVALID",
    )
    _require_digest(
        function_configurator_checkpoint_digest,
        "FUNCTION_CONFIGURATOR_CHECKPOINT_DIGEST_INVALID",
    )
    plan: dict[str, Any] = json.loads(canonical_json(pre_function_plan))
    plan["function_configuration_state"] = "CONFIGURED"
    plan["broker_function_evidence_digest"] = broker_function_evidence_digest
    plan["function_configurator_checkpoint_digest"] = (
        function_configurator_checkpoint_digest
    )
    binding = {
        "intent_digest": plan["intent_digest"],
        "source": plan["source"],
        "target": plan["target"],
        "parameter_projection_digest": plan["parameter_projection_digest"],
        "expected_resource_set_digest": plan["expected_resource_set_digest"],
        "artifact_signing_contract": plan["artifact_signing_contract"],
        "artifact_signing_contract_digest": plan[
            "artifact_signing_contract_digest"
        ],
        "artifact_signing_evidence_digest": plan[
            "artifact_signing_evidence_digest"
        ],
        "gug363_pre_function_binding_sha256": plan[
            "gug363_pre_function_binding_sha256"
        ],
        "function_configurator_contract_digest": plan[
            "function_configurator_contract_digest"
        ],
        "function_configuration_state": plan["function_configuration_state"],
        "broker_function_evidence_digest": plan[
            "broker_function_evidence_digest"
        ],
        "function_configurator_checkpoint_digest": plan[
            "function_configurator_checkpoint_digest"
        ],
        "authorization_mode": AUTHORIZATION_MODE,
        "log_group": plan["log_group"],
    }
    binding_digest = canonical_digest(binding)
    token = "gug363-" + binding_digest.removeprefix("sha256:")[:48]
    plan["materialization_binding_digest"] = binding_digest
    plan["client_request_token"] = token
    request = plan["create_stack_request"]
    request["ClientRequestToken"] = token
    request_digest = canonical_digest(request)
    plan["create_stack_request_digest"] = request_digest
    operation = plan["materialization_operations"][0]
    operation["request_projection_digest"] = request_digest
    operation["client_request_token_sha256"] = digest_text(token)
    plan["operation_list_digest"] = canonical_digest(
        plan["materialization_operations"]
    )
    plan["plan_digest"] = canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )
    validate_materialization_plan(plan, repo_root=repo_root)
    return plan


def validate_materialization_plan(
    plan: Mapping[str, Any], *, repo_root: Path | None = None
) -> None:
    required = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "live_issue",
        "environment",
        "production",
        "deployment_authorized",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "intent_digest",
        "owner_authorization_sha256",
        "single_operator_exception_digest",
        "source",
        "target",
        "artifact_signing_contract",
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
        "gug363_pre_function_binding_sha256",
        "function_configurator",
        "function_configurator_contract_digest",
        "function_configuration_state",
        "broker_function_evidence_digest",
        "function_configurator_checkpoint_digest",
        "parameter_projection",
        "parameter_projection_digest",
        "expected_resources",
        "expected_resource_count",
        "expected_resource_set_digest",
        "active_aliases",
        "normal_aliases_present",
        "log_group",
        "preflight_operations",
        "allowed_mutations",
        "prohibited_operations",
        "post_write_readback_operations",
        "materialization_operations",
        "operation_list_digest",
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
        "ambiguous_outcome_mode",
        "mutation_retry_permitted",
        "materialization_binding_digest",
        "create_stack_request",
        "create_stack_request_digest",
        "client_request_token",
        "plan_digest",
    }
    if not isinstance(plan, Mapping) or set(plan) != required:
        raise RetirementEntrypointMaterializationError("PLAN_FIELDS_INVALID")
    constants = {
        "record_type": PLAN_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": False,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "expected_resource_count": len(EXPECTED_RESOURCE_TYPES),
        "active_aliases": list(ACTIVE_ALIASES),
        "normal_aliases_present": False,
        "preflight_operations": list(PREFLIGHT_OPERATIONS),
        "allowed_mutations": list(ALLOWED_MUTATIONS),
        "prohibited_operations": list(PROHIBITED_OPERATIONS),
        "post_write_readback_operations": list(POST_WRITE_READBACK_OPERATIONS),
        "ambiguous_outcome_mode": "RECONCILE_ONLY",
        "mutation_retry_permitted": False,
    }
    if any(plan.get(key) != value for key, value in constants.items()):
        raise RetirementEntrypointMaterializationError("PLAN_SCOPE_INVALID")
    for field in (
        "intent_digest",
        "owner_authorization_sha256",
        "single_operator_exception_digest",
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
        "gug363_pre_function_binding_sha256",
        "function_configurator_contract_digest",
        "parameter_projection_digest",
        "expected_resource_set_digest",
        "materialization_binding_digest",
        "create_stack_request_digest",
        "operation_list_digest",
        "plan_digest",
    ):
        _require_digest(plan.get(field), "PLAN_DIGEST_INVALID")
    function_configuration_state = plan.get("function_configuration_state")
    broker_function_evidence_digest_value = plan.get(
        "broker_function_evidence_digest"
    )
    function_configurator_checkpoint_digest_value = plan.get(
        "function_configurator_checkpoint_digest"
    )
    if function_configuration_state == "PRE_FUNCTION":
        if (
            broker_function_evidence_digest_value is not None
            or function_configurator_checkpoint_digest_value is not None
        ):
            raise RetirementEntrypointMaterializationError(
                "PLAN_FUNCTION_CONFIGURATION_STATE_INVALID"
            )
    elif function_configuration_state == "CONFIGURED":
        _require_digest(
            broker_function_evidence_digest_value,
            "BROKER_FUNCTION_EVIDENCE_DIGEST_INVALID",
        )
        _require_digest(
            function_configurator_checkpoint_digest_value,
            "FUNCTION_CONFIGURATOR_CHECKPOINT_DIGEST_INVALID",
        )
    else:
        raise RetirementEntrypointMaterializationError(
            "PLAN_FUNCTION_CONFIGURATION_STATE_INVALID"
        )
    if plan.get("target") != _target_contract():
        raise RetirementEntrypointMaterializationError("PLAN_TARGET_INVALID")
    source = plan.get("source")
    artifact_signing_contract = plan.get("artifact_signing_contract")
    projection = plan.get("parameter_projection")
    resources = plan.get("expected_resources")
    request = plan.get("create_stack_request")
    materialization_operations = plan.get("materialization_operations")
    if (
        not isinstance(source, Mapping)
        or not isinstance(artifact_signing_contract, Mapping)
        or not isinstance(projection, list)
        or not isinstance(resources, list)
        or not isinstance(request, Mapping)
        or not isinstance(materialization_operations, list)
    ):
        raise RetirementEntrypointMaterializationError("PLAN_NESTING_INVALID")
    _validate_source_contract(source)
    _validate_artifact_signing_contract(artifact_signing_contract)
    expected_unsigned_key = (
        "scanalyze/platform-authority/gug-215/unsigned/"
        f"{source['commit']}/scanalyze-gug215-change-set-retirement-broker.zip"
    )
    if artifact_signing_contract["unsigned_source"]["key"] != expected_unsigned_key:
        raise RetirementEntrypointMaterializationError(
            "UNSIGNED_ARTIFACT_SOURCE_COMMIT_MISMATCH"
        )
    if plan.get("artifact_signing_contract_digest") != artifact_signing_contract_digest(
        artifact_signing_contract
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_CONTRACT_DIGEST_MISMATCH"
        )
    if plan.get("artifact_signing_evidence_digest") != artifact_signing_evidence_digest(
        artifact_signing_contract
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_EVIDENCE_DIGEST_MISMATCH"
        )
    expected_resources = [
        {"logical_resource_id": logical_id, "resource_type": resource_type}
        for logical_id, resource_type in EXPECTED_RESOURCE_TYPES
    ]
    if resources != expected_resources or canonical_digest(resources) != plan.get(
        "expected_resource_set_digest"
    ):
        raise RetirementEntrypointMaterializationError("PLAN_RESOURCE_SET_INVALID")
    if (
        not isinstance(projection, list)
        or [item.get("ParameterKey") for item in projection if isinstance(item, Mapping)]
        != list(PARAMETER_KEYS)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or not isinstance(item["ParameterValue"], str)
            for item in projection
        )
        or canonical_digest(projection) != plan.get("parameter_projection_digest")
    ):
        raise RetirementEntrypointMaterializationError("PLAN_PARAMETER_SET_INVALID")
    parameter_values = {
        item["ParameterKey"]: item["ParameterValue"] for item in projection
    }
    _validate_parameters(
        parameter_values,
        source=source,
        artifact_signing_contract=artifact_signing_contract,
        owner_authorization_sha256=str(plan["owner_authorization_sha256"]),
        exception_digest=str(plan["single_operator_exception_digest"]),
    )
    expected_pre_function_binding = gug363_pre_function_binding_sha256(
        source=source,
        artifact_signing_contract_digest_value=str(
            plan["artifact_signing_contract_digest"]
        ),
        parameters=parameter_values,
    )
    if plan.get("gug363_pre_function_binding_sha256") != expected_pre_function_binding:
        raise RetirementEntrypointMaterializationError(
            "PRE_FUNCTION_BINDING_DIGEST_MISMATCH"
        )
    function_configurator = plan.get("function_configurator")
    expected_function_configurator = _function_configurator_contract(
        parameters=parameter_values,
        pre_function_binding_sha256=expected_pre_function_binding,
        authority_policy_document_digest=str(
            plan.get("function_configurator", {})
            .get("authority_policy", {})
            .get("policy_document_digest")
        ),
    )
    if (
        not isinstance(function_configurator, Mapping)
        or function_configurator != expected_function_configurator
        or canonical_digest(function_configurator)
        != plan.get("function_configurator_contract_digest")
    ):
        raise RetirementEntrypointMaterializationError(
            "FUNCTION_CONFIGURATOR_CONTRACT_INVALID"
        )
    if (
        artifact_signing_contract["signed_destination"]["lambda_code_sha256"]
        != parameter_values["BrokerArtifactCodeSha256"]
        or digest_text(str(request.get("TemplateBody")))
        != source["template_sha256"]
    ):
        raise RetirementEntrypointMaterializationError("PLAN_CAUSAL_BINDING_INVALID")
    if not isinstance(request, Mapping) or set(request) != {
        "StackName",
        "TemplateBody",
        "Parameters",
        "Capabilities",
        "RoleARN",
        "OnFailure",
        "EnableTerminationProtection",
        "ClientRequestToken",
    }:
        raise RetirementEntrypointMaterializationError("CREATE_STACK_REQUEST_FIELDS_INVALID")
    if (
        request.get("StackName") != DEDICATED_STACK_NAME
        or request.get("Parameters") != projection
        or request.get("Capabilities") != list(CAPABILITIES)
        or request.get("RoleARN") != CLOUDFORMATION_SERVICE_ROLE_ARN
        or request.get("OnFailure") != "DO_NOTHING"
        or request.get("EnableTerminationProtection") is not True
        or request.get("ClientRequestToken") != plan.get("client_request_token")
        or _TOKEN_RE.fullmatch(str(plan.get("client_request_token"))) is None
        or canonical_digest(request) != plan.get("create_stack_request_digest")
        or not isinstance(request.get("TemplateBody"), str)
    ):
        raise RetirementEntrypointMaterializationError("CREATE_STACK_REQUEST_INVALID")
    _validate_template_contract(request["TemplateBody"])
    if "Tags" in request or "DisableRollback" in request:
        raise RetirementEntrypointMaterializationError("CREATE_STACK_REQUEST_AUTHORITY_DRIFT")
    expected_materialization_operations = [
        {
            "sequence": 1,
            "service": "cloudformation",
            "api_action": "CreateStack",
            "effect": "CREATE_DEDICATED_ENTRYPOINT_STACK_ONLY",
            "target_digest": canonical_digest(plan["target"]),
            "request_projection_digest": plan["create_stack_request_digest"],
            "conditional_behavior": "TARGET_ABSENT_AFTER_TWO_EXACT_DESCRIBES",
            "client_request_token_sha256": digest_text(
                str(plan["client_request_token"])
            ),
            "attempt_limit": 1,
            "retry_permitted": False,
            "expected_response_class": "CreateStackOutput.StackId",
            "immediate_readback": list(POST_WRITE_READBACK_OPERATIONS),
            "unknown_outcome_reconciliation": list(RECONCILE_OPERATIONS),
            "rollback": {
                "automatic": False,
                "delete_stack_authorized": False,
                "mode": "SEPARATE_OWNER_CHECKPOINT_REQUIRED",
            },
        }
    ]
    if (
        materialization_operations != expected_materialization_operations
        or canonical_digest(materialization_operations)
        != plan.get("operation_list_digest")
    ):
        raise RetirementEntrypointMaterializationError(
            "MATERIALIZATION_OPERATION_LIST_INVALID"
        )
    log_group = plan.get("log_group")
    if log_group != {
        "name": LOG_GROUP_NAME,
        "retention_days": LOG_RETENTION_DAYS,
        "encryption_mode": LOG_ENCRYPTION_MODE,
    }:
        raise RetirementEntrypointMaterializationError("LOG_GROUP_BINDING_INVALID")
    expected_binding = canonical_digest(
        {
            "intent_digest": plan["intent_digest"],
            "source": source,
            "target": plan["target"],
            "parameter_projection_digest": plan["parameter_projection_digest"],
            "expected_resource_set_digest": plan["expected_resource_set_digest"],
            "artifact_signing_contract": artifact_signing_contract,
            "artifact_signing_contract_digest": plan[
                "artifact_signing_contract_digest"
            ],
            "artifact_signing_evidence_digest": plan[
                "artifact_signing_evidence_digest"
            ],
            "gug363_pre_function_binding_sha256": plan[
                "gug363_pre_function_binding_sha256"
            ],
            "function_configurator_contract_digest": plan[
                "function_configurator_contract_digest"
            ],
            "function_configuration_state": plan["function_configuration_state"],
            "broker_function_evidence_digest": plan[
                "broker_function_evidence_digest"
            ],
            "function_configurator_checkpoint_digest": plan[
                "function_configurator_checkpoint_digest"
            ],
            "authorization_mode": AUTHORIZATION_MODE,
            "log_group": log_group,
        }
    )
    if expected_binding != plan.get("materialization_binding_digest"):
        raise RetirementEntrypointMaterializationError("PLAN_BINDING_DIGEST_MISMATCH")
    expected_token = "gug363-" + expected_binding.removeprefix("sha256:")[:48]
    if expected_token != plan.get("client_request_token"):
        raise RetirementEntrypointMaterializationError("CLIENT_REQUEST_TOKEN_MISMATCH")
    _self_digest(plan, "plan_digest", "PLAN_DIGEST_MISMATCH")
    if repo_root is not None:
        body, authority_policy_document_digest = _source_snapshot(repo_root, source)
        if body != request["TemplateBody"]:
            raise RetirementEntrypointMaterializationError("PLAN_TEMPLATE_BODY_DRIFT")
        if (
            plan["function_configurator"]["authority_policy"]
            ["policy_document_digest"]
            != authority_policy_document_digest
        ):
            raise RetirementEntrypointMaterializationError(
                "FUNCTION_CONFIGURATOR_POLICY_DIGEST_MISMATCH"
            )


def validate_execution_authorization(
    authorization: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    now: datetime,
    require_active: bool,
) -> None:
    validate_materialization_plan(plan)
    if plan.get("function_configuration_state") != "CONFIGURED":
        raise RetirementEntrypointMaterializationError(
            "AUTHORIZATION_REQUIRES_CONFIGURED_FUNCTION_PLAN"
        )
    required = {
        "record_type",
        "schema_version",
        "issue_id",
        "environment",
        "production",
        "deployment_authorized",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "target",
        "plan_digest",
        "create_stack_request_digest",
        "operation_list_digest",
        "artifact_signing_contract_digest",
        "artifact_signing_evidence_digest",
        "gug363_pre_function_binding_sha256",
        "function_configurator_contract_digest",
        "function_configuration_request_projection_digest",
        "broker_function_evidence_digest",
        "function_configurator_checkpoint_digest",
        "function_configurator_authority_status",
        "function_configurator_authority_ended_at",
        "activator_checkpoint_digest",
        "activator_authority_status",
        "activator_authority_ended_at",
        "owner_authorization_sha256",
        "caller_arn_sha256",
        "caller_user_id_sha256",
        "live_checkpoint_digest",
        "live_before_state_digest",
        "service_role_evidence_digest",
        "service_role_evidence_scope",
        "service_role_evidence_collected_at",
        "post_activator_bundle_readback_complete",
        "operator_authority_evidence_digest",
        "allowed_action",
        "forbidden_actions",
        "max_attempts",
        "not_before",
        "expires_at",
        "authorization_digest",
    }
    if not isinstance(authorization, Mapping) or set(authorization) != required:
        raise RetirementEntrypointMaterializationError("AUTHORIZATION_FIELDS_INVALID")
    constants = {
        "record_type": AUTHORIZATION_TYPE,
        "schema_version": 1,
        "issue_id": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": True,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "target": plan["target"],
        "plan_digest": plan["plan_digest"],
        "create_stack_request_digest": plan["create_stack_request_digest"],
        "operation_list_digest": plan["operation_list_digest"],
        "artifact_signing_contract_digest": plan[
            "artifact_signing_contract_digest"
        ],
        "artifact_signing_evidence_digest": plan[
            "artifact_signing_evidence_digest"
        ],
        "gug363_pre_function_binding_sha256": plan[
            "gug363_pre_function_binding_sha256"
        ],
        "function_configurator_contract_digest": plan[
            "function_configurator_contract_digest"
        ],
        "function_configuration_request_projection_digest": plan[
            "function_configurator"
        ]["update_request_projection_digest"],
        "broker_function_evidence_digest": plan[
            "broker_function_evidence_digest"
        ],
        "function_configurator_checkpoint_digest": plan[
            "function_configurator_checkpoint_digest"
        ],
        "function_configurator_authority_status": "EXPIRED_OR_REVOKED",
        "activator_authority_status": "EXPIRED_OR_REVOKED",
        "service_role_evidence_scope": (
            "POST_ACTIVATOR_FULL_BUNDLE_READBACK"
        ),
        "post_activator_bundle_readback_complete": True,
        "owner_authorization_sha256": plan["owner_authorization_sha256"],
        "allowed_action": "cloudformation:CreateStack",
        "forbidden_actions": list(PROHIBITED_OPERATIONS),
        "max_attempts": 1,
    }
    if any(authorization.get(key) != value for key, value in constants.items()):
        raise RetirementEntrypointMaterializationError("AUTHORIZATION_SCOPE_INVALID")
    for field in (
        "caller_arn_sha256",
        "caller_user_id_sha256",
        "live_checkpoint_digest",
        "live_before_state_digest",
        "service_role_evidence_digest",
        "operator_authority_evidence_digest",
        "activator_checkpoint_digest",
    ):
        _require_digest(authorization.get(field), "AUTHORIZATION_EVIDENCE_INVALID")
    _self_digest(
        authorization, "authorization_digest", "AUTHORIZATION_DIGEST_MISMATCH"
    )
    not_before = _parse_timestamp(authorization.get("not_before"), "AUTHORIZATION_WINDOW_INVALID")
    expires = _parse_timestamp(authorization.get("expires_at"), "AUTHORIZATION_WINDOW_INVALID")
    configurator_authority_ended = _parse_timestamp(
        authorization.get("function_configurator_authority_ended_at"),
        "AUTHORIZATION_AUTHORITY_ORDER_INVALID",
    )
    activator_authority_ended = _parse_timestamp(
        authorization.get("activator_authority_ended_at"),
        "AUTHORIZATION_AUTHORITY_ORDER_INVALID",
    )
    service_role_evidence_collected = _parse_timestamp(
        authorization.get("service_role_evidence_collected_at"),
        "AUTHORIZATION_SERVICE_ROLE_EVIDENCE_ORDER_INVALID",
    )
    if expires <= not_before or expires - not_before > MAX_AUTHORIZATION_WINDOW:
        raise RetirementEntrypointMaterializationError("AUTHORIZATION_WINDOW_INVALID")
    if not (
        configurator_authority_ended
        <= activator_authority_ended
        <= service_role_evidence_collected
        <= not_before
    ):
        raise RetirementEntrypointMaterializationError(
            "AUTHORIZATION_AUTHORITY_ORDER_INVALID"
        )
    signature_expires = _parse_timestamp(
        plan["artifact_signing_contract"]["signer"]["signature_expires_at"],
        "AUTHORIZATION_SIGNATURE_WINDOW_INVALID",
    )
    if expires > signature_expires:
        raise RetirementEntrypointMaterializationError(
            "AUTHORIZATION_SIGNATURE_WINDOW_INVALID"
        )
    parameter_values = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan["parameter_projection"]
    }
    exception_not_before = _parse_timestamp(
        parameter_values["SingleOperatorExceptionNotBefore"],
        "AUTHORIZATION_WINDOW_INVALID",
    )
    exception_expires = _parse_timestamp(
        parameter_values["SingleOperatorExceptionExpiresAt"],
        "AUTHORIZATION_WINDOW_INVALID",
    )
    if not_before < exception_not_before or expires > exception_expires:
        raise RetirementEntrypointMaterializationError(
            "AUTHORIZATION_OUTSIDE_EXCEPTION_WINDOW"
        )
    if require_active:
        if now.tzinfo is None:
            raise RetirementEntrypointMaterializationError("CLOCK_INVALID")
        observed = now.astimezone(UTC)
        if not not_before <= observed < expires:
            raise RetirementEntrypointMaterializationError("AUTHORIZATION_NOT_ACTIVE")


def build_execution_ledger(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    caller_arn_sha256: str,
    claimed_at: datetime,
) -> dict[str, Any]:
    ledger: dict[str, Any] = {
        "record_type": LEDGER_TYPE,
        "schema_version": 1,
        "issue_id": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "status": "MUTATION_WINDOW_CONSUMED",
        "plan_digest": plan["plan_digest"],
        "authorization_digest": authorization["authorization_digest"],
        "create_stack_request_digest": plan["create_stack_request_digest"],
        "operation_list_digest": plan["operation_list_digest"],
        "artifact_signing_contract_digest": plan[
            "artifact_signing_contract_digest"
        ],
        "gug363_pre_function_binding_sha256": plan[
            "gug363_pre_function_binding_sha256"
        ],
        "function_configurator_contract_digest": plan[
            "function_configurator_contract_digest"
        ],
        "function_configuration_request_projection_digest": authorization[
            "function_configuration_request_projection_digest"
        ],
        "broker_function_evidence_digest": authorization[
            "broker_function_evidence_digest"
        ],
        "function_configurator_checkpoint_digest": authorization[
            "function_configurator_checkpoint_digest"
        ],
        "function_configurator_authority_ended_at": authorization[
            "function_configurator_authority_ended_at"
        ],
        "activator_checkpoint_digest": authorization[
            "activator_checkpoint_digest"
        ],
        "activator_authority_ended_at": authorization[
            "activator_authority_ended_at"
        ],
        "service_role_evidence_scope": authorization[
            "service_role_evidence_scope"
        ],
        "service_role_evidence_collected_at": authorization[
            "service_role_evidence_collected_at"
        ],
        "post_activator_bundle_readback_complete": authorization[
            "post_activator_bundle_readback_complete"
        ],
        "service_role_evidence_digest": authorization[
            "service_role_evidence_digest"
        ],
        "client_request_token_sha256": digest_text(plan["client_request_token"]),
        "caller_arn_sha256": caller_arn_sha256,
        "caller_user_id_sha256": authorization["caller_user_id_sha256"],
        "target_digest": canonical_digest(plan["target"]),
        "allowed_action": "cloudformation:CreateStack",
        "attempt_limit": 1,
        "attempts": 1,
        "execution_gate_consumed": True,
        "mutation_retry_authorized": False,
        "broker_invocations": 0,
        "retirement_effects_attempted": 0,
        "claimed_at": timestamp(claimed_at),
        "ledger_digest": "",
    }
    ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )
    validate_execution_ledger(ledger, plan=plan, authorization=authorization)
    return ledger


def validate_execution_ledger(
    ledger: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> None:
    required = {
        "record_type",
        "schema_version",
        "issue_id",
        "live_issue",
        "environment",
        "production",
        "status",
        "plan_digest",
        "authorization_digest",
        "create_stack_request_digest",
        "operation_list_digest",
        "artifact_signing_contract_digest",
        "gug363_pre_function_binding_sha256",
        "function_configurator_contract_digest",
        "function_configuration_request_projection_digest",
        "broker_function_evidence_digest",
        "function_configurator_checkpoint_digest",
        "function_configurator_authority_ended_at",
        "activator_checkpoint_digest",
        "activator_authority_ended_at",
        "service_role_evidence_scope",
        "service_role_evidence_collected_at",
        "post_activator_bundle_readback_complete",
        "service_role_evidence_digest",
        "client_request_token_sha256",
        "caller_arn_sha256",
        "caller_user_id_sha256",
        "target_digest",
        "allowed_action",
        "attempt_limit",
        "attempts",
        "execution_gate_consumed",
        "mutation_retry_authorized",
        "broker_invocations",
        "retirement_effects_attempted",
        "claimed_at",
        "ledger_digest",
    }
    if not isinstance(ledger, Mapping) or set(ledger) != required:
        raise RetirementEntrypointMaterializationError("LEDGER_FIELDS_INVALID")
    constants = {
        "record_type": LEDGER_TYPE,
        "schema_version": 1,
        "issue_id": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "status": "MUTATION_WINDOW_CONSUMED",
        "plan_digest": plan["plan_digest"],
        "authorization_digest": authorization["authorization_digest"],
        "create_stack_request_digest": plan["create_stack_request_digest"],
        "operation_list_digest": plan["operation_list_digest"],
        "artifact_signing_contract_digest": plan[
            "artifact_signing_contract_digest"
        ],
        "gug363_pre_function_binding_sha256": plan[
            "gug363_pre_function_binding_sha256"
        ],
        "function_configurator_contract_digest": plan[
            "function_configurator_contract_digest"
        ],
        "function_configuration_request_projection_digest": authorization[
            "function_configuration_request_projection_digest"
        ],
        "broker_function_evidence_digest": authorization[
            "broker_function_evidence_digest"
        ],
        "function_configurator_checkpoint_digest": authorization[
            "function_configurator_checkpoint_digest"
        ],
        "function_configurator_authority_ended_at": authorization[
            "function_configurator_authority_ended_at"
        ],
        "activator_checkpoint_digest": authorization[
            "activator_checkpoint_digest"
        ],
        "activator_authority_ended_at": authorization[
            "activator_authority_ended_at"
        ],
        "service_role_evidence_scope": authorization[
            "service_role_evidence_scope"
        ],
        "service_role_evidence_collected_at": authorization[
            "service_role_evidence_collected_at"
        ],
        "post_activator_bundle_readback_complete": authorization[
            "post_activator_bundle_readback_complete"
        ],
        "service_role_evidence_digest": authorization[
            "service_role_evidence_digest"
        ],
        "client_request_token_sha256": digest_text(plan["client_request_token"]),
        "target_digest": canonical_digest(plan["target"]),
        "allowed_action": "cloudformation:CreateStack",
        "attempt_limit": 1,
        "attempts": 1,
        "execution_gate_consumed": True,
        "mutation_retry_authorized": False,
        "broker_invocations": 0,
        "retirement_effects_attempted": 0,
    }
    if any(ledger.get(key) != value for key, value in constants.items()):
        raise RetirementEntrypointMaterializationError("LEDGER_SCOPE_INVALID")
    _require_digest(ledger.get("caller_arn_sha256"), "LEDGER_CALLER_DIGEST_INVALID")
    _require_digest(
        ledger.get("caller_user_id_sha256"), "LEDGER_CALLER_DIGEST_INVALID"
    )
    if ledger.get("caller_user_id_sha256") != authorization.get(
        "caller_user_id_sha256"
    ):
        raise RetirementEntrypointMaterializationError(
            "LEDGER_CALLER_DIGEST_INVALID"
        )
    claimed_at = _parse_timestamp(ledger.get("claimed_at"), "LEDGER_TIME_INVALID")
    authorization_not_before = _parse_timestamp(
        authorization.get("not_before"), "LEDGER_TIME_INVALID"
    )
    authorization_expires = _parse_timestamp(
        authorization.get("expires_at"), "LEDGER_TIME_INVALID"
    )
    if not authorization_not_before <= claimed_at < authorization_expires:
        raise RetirementEntrypointMaterializationError("LEDGER_TIME_INVALID")
    _self_digest(ledger, "ledger_digest", "LEDGER_DIGEST_MISMATCH")


def build_materialization_receipt(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    execution_mode: str,
    status: str,
    target_state: str,
    ledger_digest: str | None,
    stack_id: str | None,
    stack_status: str | None,
    observed_resources: Sequence[Mapping[str, str]],
    aws_operations: Sequence[str],
    aws_mutation_attempted: bool,
    ambiguous_response: bool,
    no_touch: bool,
    artifact_signing_readback_complete: bool,
    broker_function_readback_complete: bool,
    readback_complete: bool,
    created_at: datetime,
) -> dict[str, Any]:
    observed = [dict(item) for item in observed_resources]
    if (
        observed
        != sorted(observed, key=lambda item: str(item.get("logical_resource_id")))
        or any(
            set(item) != {"logical_resource_id", "resource_type"}
            or not all(isinstance(value, str) and value for value in item.values())
            for item in observed
        )
        or len({item["logical_resource_id"] for item in observed}) != len(observed)
    ):
        raise RetirementEntrypointMaterializationError(
            "RECEIPT_RESOURCE_SET_INVALID"
        )
    receipt: dict[str, Any] = {
        "record_type": RECEIPT_TYPE,
        "schema_version": 1,
        "issue_id": IMPLEMENTATION_ISSUE,
        "live_issue": LIVE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "materializer_readback_scope": (
            "LAMBDA_AND_CLOUDFORMATION_CONTROL_PLANE"
        ),
        "provider_certification_complete": False,
        "gug357_certification_required": True,
        "execution_mode": execution_mode,
        "status": status,
        "target_state": target_state,
        "plan_digest": plan["plan_digest"],
        "authorization_digest": authorization["authorization_digest"],
        "gug363_pre_function_binding_sha256": authorization[
            "gug363_pre_function_binding_sha256"
        ],
        "function_configurator_contract_digest": authorization[
            "function_configurator_contract_digest"
        ],
        "function_configuration_request_projection_digest": authorization[
            "function_configuration_request_projection_digest"
        ],
        "broker_function_evidence_digest": authorization[
            "broker_function_evidence_digest"
        ],
        "function_configurator_checkpoint_digest": authorization[
            "function_configurator_checkpoint_digest"
        ],
        "function_configurator_authority_ended_at": authorization[
            "function_configurator_authority_ended_at"
        ],
        "activator_checkpoint_digest": authorization[
            "activator_checkpoint_digest"
        ],
        "activator_authority_ended_at": authorization[
            "activator_authority_ended_at"
        ],
        "service_role_evidence_scope": authorization[
            "service_role_evidence_scope"
        ],
        "service_role_evidence_collected_at": authorization[
            "service_role_evidence_collected_at"
        ],
        "post_activator_bundle_readback_complete": authorization[
            "post_activator_bundle_readback_complete"
        ],
        "service_role_evidence_digest": authorization[
            "service_role_evidence_digest"
        ],
        "execution_ledger_digest": ledger_digest,
        "stack_id_sha256": digest_text(stack_id) if stack_id else None,
        "stack_status": stack_status,
        "expected_resource_set_digest": plan["expected_resource_set_digest"],
        "observed_resource_set_digest": canonical_digest(observed) if observed else None,
        "expected_resource_count": plan["expected_resource_count"],
        "observed_resource_count": len(observed),
        "aws_operations": list(aws_operations),
        "aws_mutation_attempted": aws_mutation_attempted,
        "aws_mutation_count": 1 if aws_mutation_attempted else 0,
        "ambiguous_response": ambiguous_response,
        "no_touch": no_touch,
        "artifact_signing_readback_complete": artifact_signing_readback_complete,
        "broker_function_readback_complete": broker_function_readback_complete,
        "readback_complete": readback_complete,
        "mutation_retry_attempted": False,
        "retry_permitted": False,
        "broker_invocations": 0,
        "retirement_effects_attempted": 0,
        "prohibited_operation_attempted": False,
        "created_at": timestamp(created_at),
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    validate_materialization_receipt(receipt, plan=plan, authorization=authorization)
    return receipt


def validate_materialization_receipt(
    receipt: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> None:
    required = {
        "record_type", "schema_version", "issue_id", "live_issue", "environment",
        "production", "production_status", "materializer_readback_scope",
        "provider_certification_complete", "gug357_certification_required",
        "execution_mode", "status", "target_state", "plan_digest",
        "authorization_digest", "gug363_pre_function_binding_sha256",
        "function_configurator_contract_digest",
        "function_configuration_request_projection_digest",
        "broker_function_evidence_digest",
        "function_configurator_checkpoint_digest",
        "function_configurator_authority_ended_at",
        "activator_checkpoint_digest", "activator_authority_ended_at",
        "service_role_evidence_scope", "service_role_evidence_collected_at",
        "post_activator_bundle_readback_complete",
        "service_role_evidence_digest",
        "execution_ledger_digest", "stack_id_sha256",
        "stack_status", "expected_resource_set_digest", "observed_resource_set_digest",
        "expected_resource_count", "observed_resource_count", "aws_operations",
        "aws_mutation_attempted", "aws_mutation_count", "ambiguous_response",
        "no_touch", "artifact_signing_readback_complete",
        "broker_function_readback_complete", "readback_complete",
        "mutation_retry_attempted", "retry_permitted",
        "broker_invocations", "retirement_effects_attempted",
        "prohibited_operation_attempted", "created_at", "receipt_digest",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise RetirementEntrypointMaterializationError("RECEIPT_FIELDS_INVALID")
    if (
        receipt.get("record_type") != RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("issue_id") != IMPLEMENTATION_ISSUE
        or receipt.get("live_issue") != LIVE_ISSUE
        or receipt.get("environment") != "synthetic-non-production"
        or receipt.get("production") is not False
        or receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("materializer_readback_scope")
        != "LAMBDA_AND_CLOUDFORMATION_CONTROL_PLANE"
        or receipt.get("provider_certification_complete") is not False
        or receipt.get("gug357_certification_required") is not True
        or receipt.get("execution_mode") not in {"APPLY", "RECONCILE"}
        or receipt.get("plan_digest") != plan["plan_digest"]
        or receipt.get("authorization_digest") != authorization["authorization_digest"]
        or receipt.get("gug363_pre_function_binding_sha256")
        != authorization["gug363_pre_function_binding_sha256"]
        or receipt.get("function_configurator_contract_digest")
        != authorization["function_configurator_contract_digest"]
        or receipt.get("function_configuration_request_projection_digest")
        != authorization["function_configuration_request_projection_digest"]
        or receipt.get("broker_function_evidence_digest")
        != authorization["broker_function_evidence_digest"]
        or receipt.get("function_configurator_checkpoint_digest")
        != authorization["function_configurator_checkpoint_digest"]
        or receipt.get("function_configurator_authority_ended_at")
        != authorization["function_configurator_authority_ended_at"]
        or receipt.get("activator_checkpoint_digest")
        != authorization["activator_checkpoint_digest"]
        or receipt.get("activator_authority_ended_at")
        != authorization["activator_authority_ended_at"]
        or receipt.get("service_role_evidence_scope")
        != "POST_ACTIVATOR_FULL_BUNDLE_READBACK"
        or receipt.get("service_role_evidence_collected_at")
        != authorization["service_role_evidence_collected_at"]
        or receipt.get("post_activator_bundle_readback_complete") is not True
        or receipt.get("service_role_evidence_digest")
        != authorization["service_role_evidence_digest"]
        or receipt.get("expected_resource_set_digest")
        != plan["expected_resource_set_digest"]
        or receipt.get("expected_resource_count") != len(EXPECTED_RESOURCE_TYPES)
        or receipt.get("mutation_retry_attempted") is not False
        or receipt.get("retry_permitted") is not False
        or receipt.get("broker_invocations") != 0
        or receipt.get("retirement_effects_attempted") != 0
        or receipt.get("prohibited_operation_attempted") is not False
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_SCOPE_INVALID")
    allowed_statuses = {
        "AUTHORIZATION_EXPIRED_AFTER_CLAIM_NO_MUTATION",
        "CREATESTACK_ACCEPTED_RECONCILE_REQUIRED",
        "READBACK_PENDING_NO_MUTATION",
        "READBACK_VERIFIED",
        "UNCERTAIN_RECONCILE_ONLY",
        "NONDESTRUCTIVE_RECOVERY_REQUIRED",
        "BLOCKED_DRIFT",
    }
    if receipt.get("status") not in allowed_statuses:
        raise RetirementEntrypointMaterializationError("RECEIPT_STATUS_INVALID")
    attempted = receipt.get("aws_mutation_attempted") is True
    execution_mode = receipt.get("execution_mode")
    if not isinstance(receipt.get("aws_mutation_attempted"), bool) or any(
        not isinstance(receipt.get(field), bool)
        for field in (
            "ambiguous_response",
            "no_touch",
            "artifact_signing_readback_complete",
            "broker_function_readback_complete",
            "readback_complete",
        )
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_BOOLEAN_INVALID")
    if receipt.get("aws_mutation_count") != (1 if attempted else 0):
        raise RetirementEntrypointMaterializationError("RECEIPT_ATTEMPT_INVALID")
    if attempted and receipt.get("execution_ledger_digest") is None:
        raise RetirementEntrypointMaterializationError("RECEIPT_LEDGER_REQUIRED")
    ledger_digest = receipt.get("execution_ledger_digest")
    if ledger_digest is not None:
        _require_digest(ledger_digest, "RECEIPT_LEDGER_DIGEST_INVALID")
    post_claim_expiry = (
        receipt.get("status")
        == "AUTHORIZATION_EXPIRED_AFTER_CLAIM_NO_MUTATION"
    )
    if (
        execution_mode == "APPLY"
        and not attempted
        and ledger_digest is not None
        and not post_claim_expiry
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_LEDGER_OVERCLAIM")
    if execution_mode == "RECONCILE" and (attempted or ledger_digest is None):
        raise RetirementEntrypointMaterializationError("RECEIPT_RECONCILE_INVALID")
    if receipt.get("no_touch") is not (not attempted):
        raise RetirementEntrypointMaterializationError("RECEIPT_NO_TOUCH_INVALID")
    if (
        receipt.get("readback_complete") is True
        and (
            receipt.get("artifact_signing_readback_complete") is not True
            or receipt.get("broker_function_readback_complete") is not True
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "RECEIPT_PROVIDER_READBACK_REQUIRED"
        )
    stack_id_digest = receipt.get("stack_id_sha256")
    observed_digest = receipt.get("observed_resource_set_digest")
    if stack_id_digest is not None:
        _require_digest(stack_id_digest, "RECEIPT_STACK_DIGEST_INVALID")
    observed_count = receipt.get("observed_resource_count")
    if (
        not isinstance(observed_count, int)
        or isinstance(observed_count, bool)
        or not 0 <= observed_count <= 512
        or (observed_count == 0) != (observed_digest is None)
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_RESOURCE_COUNT_INVALID")
    if observed_digest is not None:
        _require_digest(observed_digest, "RECEIPT_RESOURCE_DIGEST_INVALID")
    stack_status = receipt.get("stack_status")
    if stack_status is not None and (
        not isinstance(stack_status, str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", stack_status) is None
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_STACK_STATUS_INVALID")
    if (stack_id_digest is None) != (stack_status is None):
        raise RetirementEntrypointMaterializationError("RECEIPT_STACK_BINDING_INVALID")
    if receipt.get("target_state") in {"COMPLETE", "IN_PROGRESS", "PARTIAL"} and (
        stack_id_digest is None or stack_status is None
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_STACK_BINDING_INVALID")
    if receipt.get("target_state") == "COMPLETE" and (
        receipt.get("readback_complete") is not True
        or receipt.get("ambiguous_response") is not False
        or receipt.get("observed_resource_set_digest")
        != plan["expected_resource_set_digest"]
        or receipt.get("observed_resource_count") != len(EXPECTED_RESOURCE_TYPES)
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_COMPLETE_OVERCLAIM")
    if receipt.get("status") == "UNCERTAIN_RECONCILE_ONLY" and (
        not attempted or receipt.get("ambiguous_response") is not True
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_UNCERTAINTY_INVALID")
    status_rules: dict[str, tuple[set[str], bool | None, bool | None]] = {
        "AUTHORIZATION_EXPIRED_AFTER_CLAIM_NO_MUTATION": (
            {"ABSENT"},
            False,
            False,
        ),
        "CREATESTACK_ACCEPTED_RECONCILE_REQUIRED": ({"IN_PROGRESS"}, True, False),
        "READBACK_PENDING_NO_MUTATION": ({"IN_PROGRESS", "AMBIGUOUS"}, False, None),
        "READBACK_VERIFIED": ({"COMPLETE"}, None, True),
        "UNCERTAIN_RECONCILE_ONLY": ({"AMBIGUOUS", "UNKNOWN"}, True, False),
        "NONDESTRUCTIVE_RECOVERY_REQUIRED": ({"ABSENT", "PARTIAL"}, None, False),
        "BLOCKED_DRIFT": ({"DRIFTED"}, None, False),
    }
    allowed_states, required_attempted, required_complete = status_rules[
        str(receipt["status"])
    ]
    if (
        receipt.get("target_state") not in allowed_states
        or (required_attempted is not None and attempted is not required_attempted)
        or (
            execution_mode == "APPLY"
            and not attempted
            and receipt.get("target_state") == "COMPLETE"
        )
        or (
            required_complete is not None
            and receipt.get("readback_complete") is not required_complete
        )
        or (
            receipt.get("readback_complete") is True
            and receipt.get("target_state") != "COMPLETE"
        )
        or receipt.get("ambiguous_response")
        is not (receipt.get("target_state") in {"AMBIGUOUS", "UNKNOWN"})
        or (
            receipt.get("target_state") == "COMPLETE"
            and stack_status != "CREATE_COMPLETE"
        )
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_STATE_INVALID")
    operations = receipt.get("aws_operations")
    if not isinstance(operations, list) or any(
        not isinstance(operation, str) or operation in PROHIBITED_OPERATIONS
        for operation in operations
    ):
        raise RetirementEntrypointMaterializationError("RECEIPT_OPERATIONS_INVALID")
    assert isinstance(operations, list)
    readback_suffix = list(POST_WRITE_READBACK_OPERATIONS[1:])
    if receipt.get("readback_complete") is True:
        if execution_mode == "RECONCILE":
            complete_sequence = list(RECONCILE_OPERATIONS)
        elif attempted:
            complete_sequence = [
                *PREFLIGHT_OPERATIONS,
                "cloudformation:CreateStack",
                *POST_WRITE_READBACK_OPERATIONS,
            ]
        else:
            raise RetirementEntrypointMaterializationError("RECEIPT_STATE_INVALID")
        if operations != complete_sequence:
            raise RetirementEntrypointMaterializationError(
                "RECEIPT_COMPLETE_READBACK_SEQUENCE_INVALID"
            )
    if execution_mode == "RECONCILE":
        expected = list(RECONCILE_OPERATIONS)
        valid_sequence = operations == expected[: len(operations)]
    elif attempted:
        base = [*PREFLIGHT_OPERATIONS, "cloudformation:CreateStack"]
        suffix = list(POST_WRITE_READBACK_OPERATIONS)
        valid_sequence = operations[: len(base)] == base and operations[len(base) :] == (
            suffix[: len(operations) - len(base)]
        )
    else:
        base = list(PREFLIGHT_OPERATIONS)
        valid_sequence = (
            operations[: len(base)] == base
            and operations[len(base) :]
            == readback_suffix[: len(operations) - len(base)]
        )
    if not valid_sequence:
        raise RetirementEntrypointMaterializationError(
            "RECEIPT_OPERATION_ORDER_INVALID"
        )
    signing_readback_complete = receipt.get(
        "artifact_signing_readback_complete"
    ) is True
    signing_operation_count = PREFLIGHT_OPERATIONS.index(
        "lambda:GetCodeSigningConfig"
    ) + 1
    if signing_readback_complete and not (
        len(operations) >= signing_operation_count
        and operations[:signing_operation_count]
        == list(PREFLIGHT_OPERATIONS[:signing_operation_count])
    ):
        raise RetirementEntrypointMaterializationError(
            "RECEIPT_SIGNING_READBACK_OVERCLAIM"
        )
    function_readback_complete = receipt.get(
        "broker_function_readback_complete"
    ) is True
    function_operation_count = PREFLIGHT_OPERATIONS.index("lambda:GetPolicy") + 1
    if function_readback_complete and not (
        len(operations) >= function_operation_count
        and operations[:function_operation_count]
        == list(PREFLIGHT_OPERATIONS[:function_operation_count])
    ):
        raise RetirementEntrypointMaterializationError(
            "RECEIPT_BROKER_FUNCTION_READBACK_OVERCLAIM"
        )
    _parse_timestamp(receipt.get("created_at"), "RECEIPT_TIME_INVALID")
    _self_digest(receipt, "receipt_digest", "RECEIPT_DIGEST_MISMATCH")


def _aws_error(exc: BaseException) -> tuple[str | None, str | None]:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None, None
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return None, None
    code = error.get("Code")
    message = error.get("Message")
    return (
        code if isinstance(code, str) else None,
        message if isinstance(message, str) else None,
    )


def _is_absent_stack_error(exc: BaseException) -> bool:
    code, message = _aws_error(exc)
    return (
        code == "ValidationError"
        and isinstance(message, str)
        and DEDICATED_STACK_NAME in message
        and "does not exist" in message.lower()
    )


def _describe_stack(client: Any, identifier: str) -> Mapping[str, Any] | None:
    try:
        response = client.describe_stacks(StackName=identifier)
    except Exception as exc:
        if identifier == DEDICATED_STACK_NAME and _is_absent_stack_error(exc):
            return None
        raise RetirementEntrypointMaterializationError("STACK_READBACK_UNAVAILABLE") from exc
    stacks = response.get("Stacks") if isinstance(response, Mapping) else None
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
        raise RetirementEntrypointMaterializationError("STACK_READBACK_AMBIGUOUS")
    return stacks[0]


def _list_resources(
    client: Any, stack_id: str
) -> tuple[list[dict[str, str]], dict[str, str], set[str]]:
    token: str | None = None
    resources: list[dict[str, str]] = []
    statuses: dict[str, str] = {}
    physical_ids_present: set[str] = set()
    seen: set[str] = set()
    for _ in range(MAX_STACK_RESOURCE_PAGES):
        kwargs: dict[str, Any] = {"StackName": stack_id}
        if token is not None:
            kwargs["NextToken"] = token
        try:
            response = client.list_stack_resources(**kwargs)
        except Exception as exc:
            raise RetirementEntrypointMaterializationError(
                "STACK_RESOURCES_UNAVAILABLE"
            ) from exc
        summaries = (
            response.get("StackResourceSummaries")
            if isinstance(response, Mapping)
            else None
        )
        if not isinstance(summaries, list):
            raise RetirementEntrypointMaterializationError("STACK_RESOURCES_AMBIGUOUS")
        for summary in summaries:
            if not isinstance(summary, Mapping):
                raise RetirementEntrypointMaterializationError("STACK_RESOURCES_AMBIGUOUS")
            logical_id = summary.get("LogicalResourceId")
            resource_type = summary.get("ResourceType")
            resource_status = summary.get("ResourceStatus")
            physical_id = summary.get("PhysicalResourceId")
            if (
                not isinstance(logical_id, str)
                or not isinstance(resource_type, str)
                or not isinstance(resource_status, str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", resource_status) is None
                or logical_id in seen
            ):
                raise RetirementEntrypointMaterializationError("STACK_RESOURCES_AMBIGUOUS")
            seen.add(logical_id)
            statuses[logical_id] = resource_status
            if isinstance(physical_id, str) and physical_id:
                physical_ids_present.add(logical_id)
            resources.append(
                {"logical_resource_id": logical_id, "resource_type": resource_type}
            )
        token_value = response.get("NextToken") if isinstance(response, Mapping) else None
        if token_value is None:
            return (
                sorted(resources, key=lambda item: item["logical_resource_id"]),
                statuses,
                physical_ids_present,
            )
        if not isinstance(token_value, str) or not token_value:
            raise RetirementEntrypointMaterializationError("STACK_RESOURCES_AMBIGUOUS")
        token = token_value
    raise RetirementEntrypointMaterializationError("STACK_RESOURCE_PAGE_LIMIT")


def _event_token_present(client: Any, stack_id: str, expected_token: str) -> bool:
    token: str | None = None
    for _ in range(MAX_STACK_EVENT_PAGES):
        kwargs: dict[str, Any] = {"StackName": stack_id}
        if token is not None:
            kwargs["NextToken"] = token
        try:
            response = client.describe_stack_events(**kwargs)
        except Exception as exc:
            raise RetirementEntrypointMaterializationError("STACK_EVENTS_UNAVAILABLE") from exc
        events = response.get("StackEvents") if isinstance(response, Mapping) else None
        if not isinstance(events, list):
            raise RetirementEntrypointMaterializationError("STACK_EVENTS_AMBIGUOUS")
        if any(
            isinstance(event, Mapping)
            and event.get("ClientRequestToken") == expected_token
            for event in events
        ):
            return True
        token_value = response.get("NextToken") if isinstance(response, Mapping) else None
        if token_value is None:
            return False
        if not isinstance(token_value, str) or not token_value:
            raise RetirementEntrypointMaterializationError("STACK_EVENTS_AMBIGUOUS")
        token = token_value
    raise RetirementEntrypointMaterializationError("STACK_EVENT_PAGE_LIMIT")


def _stack_parameters_match(
    stack: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    masked_parameters_causally_bound: bool,
) -> tuple[bool, bool]:
    """Return ``(matches, has_unbound_masked_values)`` for stack parameters."""

    observed_records = stack.get("Parameters")
    if not isinstance(observed_records, list):
        return False, False
    observed: dict[str, str] = {}
    for record in observed_records:
        if not isinstance(record, Mapping):
            return False, False
        key = record.get("ParameterKey")
        value = record.get("ParameterValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in observed:
            return False, False
        observed[key] = value
    expected = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan["parameter_projection"]
    }
    if set(observed) != set(expected):
        return False, False
    if observed.get(PRIVATE_PARAMETER_PROJECTION_KEY) != expected.get(
        PRIVATE_PARAMETER_PROJECTION_KEY
    ):
        return False, False
    has_unbound_masked_values = False
    for key, expected_value in expected.items():
        if observed[key] == expected_value:
            continue
        if key not in NO_ECHO_PARAMETER_KEYS or set(observed[key]) != {"*"}:
            return False, False
        if not masked_parameters_causally_bound:
            has_unbound_masked_values = True
    return True, has_unbound_masked_values


def _stack_metadata_matches(
    stack: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    masked_parameters_causally_bound: bool,
) -> tuple[bool, bool]:
    """Match the authority-bearing CreateStack metadata exposed by boto3."""

    rollback_configuration = stack.get("RollbackConfiguration")
    rollback_configuration_is_empty = rollback_configuration in (None, {}) or (
        isinstance(rollback_configuration, Mapping)
        and rollback_configuration
        in (
            {"RollbackTriggers": []},
            {"RollbackTriggers": [], "MonitoringTimeInMinutes": 0},
        )
    )
    absent_direct_create_fields = (
        "ChangeSetId",
        "DeletionTime",
        "LastUpdatedTime",
        "ParentId",
        "RootId",
        "TimeoutInMinutes",
    )
    parameter_matches, has_unbound_masked_values = _stack_parameters_match(
        stack,
        plan,
        masked_parameters_causally_bound=masked_parameters_causally_bound,
    )
    metadata_matches = (
        stack.get("EnableTerminationProtection") is True
        and stack.get("RoleARN") == CLOUDFORMATION_SERVICE_ROLE_ARN
        and stack.get("Capabilities") == list(CAPABILITIES)
        and stack.get("NotificationARNs") == []
        and stack.get("Tags") == []
        and stack.get("DisableRollback") is True
        and stack.get("RetainExceptOnCreate") in (None, False)
        and (
            "DeletionMode" not in stack
            or stack.get("DeletionMode") == "STANDARD"
        )
        and rollback_configuration_is_empty
        and not any(field in stack for field in absent_direct_create_fields)
        and parameter_matches
    )
    return metadata_matches, metadata_matches and has_unbound_masked_values


def _readback(
    client: Any,
    *,
    stack: Mapping[str, Any],
    plan: Mapping[str, Any],
    operations: list[str],
    masked_parameters_causally_bound: bool,
) -> tuple[str, str | None, str | None, list[dict[str, str]]]:
    stack_id = stack.get("StackId")
    stack_name = stack.get("StackName")
    stack_status = stack.get("StackStatus")
    if (
        not isinstance(stack_id, str)
        or _STACK_ID_RE.fullmatch(stack_id) is None
        or stack_name != DEDICATED_STACK_NAME
        or not isinstance(stack_status, str)
    ):
        return "DRIFTED", None, None, []
    metadata_matches, has_unbound_masked_values = _stack_metadata_matches(
        stack,
        plan,
        masked_parameters_causally_bound=masked_parameters_causally_bound,
    )
    if not metadata_matches:
        return "DRIFTED", stack_id, stack_status, []
    if has_unbound_masked_values:
        return "AMBIGUOUS", stack_id, stack_status, []
    operations.append("cloudformation:GetTemplate")
    try:
        template = client.get_template(StackName=stack_id, TemplateStage="Original")
    except Exception as exc:
        raise RetirementEntrypointMaterializationError("STACK_TEMPLATE_UNAVAILABLE") from exc
    body = template.get("TemplateBody") if isinstance(template, Mapping) else None
    if not isinstance(body, str) or body != plan["create_stack_request"]["TemplateBody"]:
        return "DRIFTED", stack_id, stack_status, []
    operations.append("cloudformation:ListStackResources")
    resources, resource_statuses, physical_ids_present = _list_resources(
        client, stack_id
    )
    expected = plan["expected_resources"]
    expected_map = {
        item["logical_resource_id"]: item["resource_type"] for item in expected
    }
    if any(
        item["logical_resource_id"] not in expected_map
        or expected_map[item["logical_resource_id"]] != item["resource_type"]
        for item in resources
    ):
        return "DRIFTED", stack_id, stack_status, resources
    if any(
        status.endswith(("FAILED", "DELETE_COMPLETE", "DELETE_IN_PROGRESS"))
        for status in resource_statuses.values()
    ):
        return "DRIFTED", stack_id, stack_status, resources
    operations.append("cloudformation:DescribeStackEvents")
    token_present = _event_token_present(client, stack_id, plan["client_request_token"])
    if not token_present:
        return "AMBIGUOUS", stack_id, stack_status, resources
    if stack_status == "CREATE_COMPLETE":
        if (
            resources == expected
            and set(resource_statuses) == set(expected_map)
            and set(resource_statuses.values()) == {"CREATE_COMPLETE"}
            and physical_ids_present == set(expected_map)
        ):
            return "COMPLETE", stack_id, stack_status, resources
        return "DRIFTED", stack_id, stack_status, resources
    if stack_status == "CREATE_IN_PROGRESS":
        if set(resource_statuses.values()).issubset(
            {"CREATE_IN_PROGRESS", "CREATE_COMPLETE"}
        ):
            return "IN_PROGRESS", stack_id, stack_status, resources
        return "AMBIGUOUS", stack_id, stack_status, resources
    if stack_status.endswith(("FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED")):
        return "PARTIAL", stack_id, stack_status, resources
    return "AMBIGUOUS", stack_id, stack_status, resources


def _provider_timestamp_matches(observed: object, expected: str) -> bool:
    if isinstance(observed, datetime):
        return timestamp(observed) == expected
    return observed == expected


def _validate_signing_job(
    response: Any, contract: Mapping[str, Any]
) -> None:
    signer = contract["signer"]
    unsigned = contract["unsigned_source"]
    signed = contract["signed_destination"]
    expected_source = {
        "s3": {
            "bucketName": unsigned["bucket"],
            "key": unsigned["key"],
            "version": unsigned["version_id"],
        }
    }
    expected_destination = {
        "s3": {"bucketName": signed["bucket"], "key": signed["key"]}
    }
    if not isinstance(response, Mapping) or any(
        (
            response.get("jobId") != signer["job_id"],
            response.get("status") != signer["status"],
            response.get("jobOwner") != signer["job_owner"],
            response.get("jobInvoker") != signer["job_invoker"],
            response.get("platformId") != signer["platform_id"],
            response.get("profileName") != signer["profile_name"],
            response.get("profileVersion") != signer["profile_version_id"],
            response.get("source") != expected_source,
            response.get("signedObject") != expected_destination,
            not _provider_timestamp_matches(
                response.get("signatureExpiresAt"),
                signer["signature_expires_at"],
            ),
            response.get("revocationRecord") not in (None, {}),
            response.get("overrides") not in (None, {}),
            response.get("signingParameters") not in (None, {}),
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "SIGNING_JOB_READBACK_MISMATCH"
        )


def _validate_signing_profile(
    response: Any, contract: Mapping[str, Any]
) -> None:
    signer = contract["signer"]
    current_version = (
        response.get("profileVersion") if isinstance(response, Mapping) else None
    )
    current_arn = (
        response.get("profileVersionArn") if isinstance(response, Mapping) else None
    )
    current_arn_match = _SIGNING_PROFILE_VERSION_ARN_RE.fullmatch(
        str(current_arn)
    )
    if not isinstance(response, Mapping) or any(
        (
            response.get("profileName") != signer["profile_name"],
            _SIGNING_PROFILE_VERSION_RE.fullmatch(str(current_version)) is None,
            current_arn_match is None,
            current_arn_match is not None
            and current_arn_match.group("name") != signer["profile_name"],
            current_arn_match is not None
            and current_arn_match.group("version") != current_version,
            response.get("platformId") != signer["platform_id"],
            response.get("status") != "Active",
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "SIGNING_PROFILE_READBACK_MISMATCH"
        )


def _validate_artifact_metadata(
    response: Any, expected: Mapping[str, Any], *, code: str
) -> None:
    checksum = response.get("ChecksumSHA256") if isinstance(response, Mapping) else None
    checksum_type = response.get("ChecksumType") if isinstance(response, Mapping) else None
    if not isinstance(response, Mapping) or any(
        (
            response.get("VersionId") != expected["version_id"],
            response.get("ContentLength") != expected["archive_size_bytes"],
            response.get("ServerSideEncryption") != expected["sse_algorithm"],
            response.get("SSEKMSKeyId") != expected["sse_kms_key_arn"],
            response.get("DeleteMarker") is True,
            response.get("ContentRange") is not None,
        )
    ):
        raise RetirementEntrypointMaterializationError(code)
    if checksum is None:
        if checksum_type is not None:
            raise RetirementEntrypointMaterializationError(code)
        return
    composite_checksum_valid = (
        isinstance(checksum, str)
        and 1 <= len(checksum) <= 1024
        and checksum.strip() == checksum
        and not any(
            ord(character) < 0x21 or ord(character) == 0x7F
            for character in checksum
        )
    )
    if (
        not isinstance(checksum, str)
        or checksum_type not in (None, "FULL_OBJECT", "COMPOSITE")
        or (checksum_type == "COMPOSITE" and not composite_checksum_valid)
        or (
            checksum_type in (None, "FULL_OBJECT")
            and (
                _CODE_SHA_RE.fullmatch(checksum) is None
                or checksum != expected["lambda_code_sha256"]
            )
        )
    ):
        raise RetirementEntrypointMaterializationError(code)


def _validate_artifact_body(
    response: Any, expected: Mapping[str, Any], *, code: str
) -> bytes:
    _validate_artifact_metadata(response, expected, code=code)
    assert isinstance(response, Mapping)
    body = response.get("Body")
    read = getattr(body, "read", None)
    close = getattr(body, "close", None)
    if not callable(read) or not callable(close):
        raise RetirementEntrypointMaterializationError(code)
    try:
        payload = read(expected["archive_size_bytes"] + 1)
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(code) from exc
    finally:
        try:
            close()
        except Exception as exc:
            raise RetirementEntrypointMaterializationError(code) from exc
    if (
        not isinstance(payload, bytes)
        or len(payload) != expected["archive_size_bytes"]
        or sha256(payload).hexdigest() != expected["archive_sha256"]
        or base64.b64encode(sha256(payload).digest()).decode("ascii")
        != expected["lambda_code_sha256"]
    ):
        raise RetirementEntrypointMaterializationError(code)
    return payload


def _zip_member_payloads(payload: bytes, *, code: str) -> dict[str, bytes]:
    """Read a ZIP without extraction and reject ambiguous filesystem entries."""

    try:
        with zipfile.ZipFile(BytesIO(payload), mode="r") as archive:
            members = archive.infolist()
            if not members:
                raise RetirementEntrypointMaterializationError(code)
            names: set[str] = set()
            total_size = 0
            result: dict[str, bytes] = {}
            for member in members:
                name = member.filename
                pure = PurePosixPath(name)
                unix_mode = member.external_attr >> 16
                total_size += member.file_size
                if (
                    not name
                    or name.endswith("/")
                    or "\\" in name
                    or pure.is_absolute()
                    or str(pure) != name
                    or any(part in ("", ".", "..") for part in pure.parts)
                    or name in names
                    or member.flag_bits & 0x1
                    or stat.S_IFMT(unix_mode) == stat.S_IFLNK
                    or member.file_size < 0
                    or member.file_size > MAX_ARTIFACT_BYTES
                    or total_size > MAX_ARTIFACT_BYTES
                ):
                    raise RetirementEntrypointMaterializationError(code)
                names.add(name)
                member_payload = archive.read(member)
                if len(member_payload) != member.file_size:
                    raise RetirementEntrypointMaterializationError(code)
                result[name] = member_payload
            return result
    except RetirementEntrypointMaterializationError:
        raise
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        raise RetirementEntrypointMaterializationError(code) from None


def _read_signed_version_listing(client: Any, expected: Mapping[str, Any]) -> None:
    exact_versions: list[Mapping[str, Any]] = []
    exact_delete_markers: list[Mapping[str, Any]] = []
    key_marker: str | None = None
    version_id_marker: str | None = None
    seen_markers: set[tuple[str, str | None]] = set()
    for _ in range(MAX_S3_VERSION_PAGES):
        kwargs: dict[str, Any] = {
            "Bucket": expected["bucket"],
            "Prefix": expected["key"],
            "MaxKeys": 1000,
            "ExpectedBucketOwner": AUTHORITY_ACCOUNT_ID,
        }
        if key_marker is not None:
            kwargs["KeyMarker"] = key_marker
        if version_id_marker is not None:
            kwargs["VersionIdMarker"] = version_id_marker
        try:
            response = client.list_object_versions(**kwargs)
        except Exception as exc:
            raise RetirementEntrypointMaterializationError(
                "SIGNED_ARTIFACT_VERSION_LIST_UNAVAILABLE"
            ) from exc
        if (
            not isinstance(response, Mapping)
            or response.get("Name") != expected["bucket"]
            or response.get("Prefix") != expected["key"]
            or not isinstance(response.get("IsTruncated"), bool)
        ):
            raise RetirementEntrypointMaterializationError(
                "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
            )
        versions = response.get("Versions", [])
        delete_markers = response.get("DeleteMarkers", [])
        if not isinstance(versions, list) or not isinstance(delete_markers, list):
            raise RetirementEntrypointMaterializationError(
                "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
            )
        for item in versions:
            if not isinstance(item, Mapping) or not isinstance(item.get("Key"), str):
                raise RetirementEntrypointMaterializationError(
                    "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
                )
            if item["Key"] == expected["key"]:
                exact_versions.append(item)
        for item in delete_markers:
            if not isinstance(item, Mapping) or not isinstance(item.get("Key"), str):
                raise RetirementEntrypointMaterializationError(
                    "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
                )
            if item["Key"] == expected["key"]:
                exact_delete_markers.append(item)
        if response["IsTruncated"] is False:
            break
        next_key_marker = response.get("NextKeyMarker")
        next_version_marker = response.get("NextVersionIdMarker")
        if (
            not isinstance(next_key_marker, str)
            or not next_key_marker
            or (
                next_version_marker is not None
                and (
                    not isinstance(next_version_marker, str)
                    or not next_version_marker
                )
            )
            or (next_key_marker, next_version_marker) in seen_markers
        ):
            raise RetirementEntrypointMaterializationError(
                "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
            )
        seen_markers.add((next_key_marker, next_version_marker))
        key_marker = next_key_marker
        version_id_marker = next_version_marker
    else:
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_VERSION_PAGE_LIMIT"
        )
    expected_version = {
        "Key": expected["key"],
        "VersionId": expected["version_id"],
        "IsLatest": True,
        "Size": expected["archive_size_bytes"],
    }
    if (
        len(exact_versions) != 1
        or any(
            exact_versions[0].get(key) != value
            for key, value in expected_version.items()
        )
        or exact_delete_markers
    ):
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_VERSION_LIST_MISMATCH"
        )


def _validate_code_signing_config(
    response: Any, contract: Mapping[str, Any]
) -> None:
    expected = contract["code_signing_config"]
    config = response.get("CodeSigningConfig") if isinstance(response, Mapping) else None
    if not isinstance(config, Mapping) or any(
        (
            config.get("CodeSigningConfigId")
            != str(expected["arn"]).rsplit(":", 1)[-1],
            config.get("CodeSigningConfigArn") != expected["arn"],
            config.get("AllowedPublishers")
            != {
                "SigningProfileVersionArns": expected[
                    "allowed_signing_profile_version_arns"
                ]
            },
            config.get("CodeSigningPolicies")
            != {
                "UntrustedArtifactOnDeployment": expected[
                    "untrusted_artifact_on_deployment"
                ]
            },
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "CODE_SIGNING_CONFIG_READBACK_MISMATCH"
        )


def _refresh_artifact_signing_readback(
    *,
    plan: Mapping[str, Any],
    client_factory: ClientFactory,
    operations: list[str],
) -> None:
    """Refresh the reviewed signed handoff using only exact read APIs."""

    contract = plan["artifact_signing_contract"]
    unsigned = contract["unsigned_source"]
    signer_contract = contract["signer"]
    signed = contract["signed_destination"]

    signer_client = client_factory.signer()
    operations.append("signer:DescribeSigningJob")
    try:
        job = signer_client.describe_signing_job(jobId=signer_contract["job_id"])
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "SIGNING_JOB_READBACK_UNAVAILABLE"
        ) from exc
    _validate_signing_job(job, contract)

    operations.append("signer:GetSigningProfile")
    try:
        profile = signer_client.get_signing_profile(
            profileName=signer_contract["profile_name"],
            profileOwner=AUTHORITY_ACCOUNT_ID,
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "SIGNING_PROFILE_READBACK_UNAVAILABLE"
        ) from exc
    _validate_signing_profile(profile, contract)

    s3 = client_factory.s3()
    operations.append("s3:GetBucketVersioning")
    try:
        versioning = s3.get_bucket_versioning(
            Bucket=unsigned["bucket"], ExpectedBucketOwner=AUTHORITY_ACCOUNT_ID
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_BUCKET_VERSIONING_UNAVAILABLE"
        ) from exc
    if not isinstance(versioning, Mapping) or (
        versioning.get("Status") != "Enabled"
        or (
            "MFADelete" in versioning
            and versioning.get("MFADelete") not in ("Disabled", "Enabled")
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_BUCKET_VERSIONING_MISMATCH"
        )

    def object_kwargs(expected: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "Bucket": expected["bucket"],
            "Key": expected["key"],
            "VersionId": expected["version_id"],
            "ExpectedBucketOwner": AUTHORITY_ACCOUNT_ID,
            "ChecksumMode": "ENABLED",
        }

    operations.append("s3:HeadObject")
    try:
        source_head = s3.head_object(**object_kwargs(unsigned))
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "UNSIGNED_ARTIFACT_HEAD_UNAVAILABLE"
        ) from exc
    _validate_artifact_metadata(
        source_head, unsigned, code="UNSIGNED_ARTIFACT_HEAD_MISMATCH"
    )

    operations.append("s3:GetObject")
    try:
        source_object = s3.get_object(**object_kwargs(unsigned))
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "UNSIGNED_ARTIFACT_GET_UNAVAILABLE"
        ) from exc
    source_payload = _validate_artifact_body(
        source_object, unsigned, code="UNSIGNED_ARTIFACT_BODY_MISMATCH"
    )

    operations.append("s3:ListObjectVersions")
    _read_signed_version_listing(s3, signed)

    operations.append("s3:HeadObject")
    try:
        destination_head = s3.head_object(**object_kwargs(signed))
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_HEAD_UNAVAILABLE"
        ) from exc
    _validate_artifact_metadata(
        destination_head, signed, code="SIGNED_ARTIFACT_HEAD_MISMATCH"
    )

    operations.append("s3:GetObject")
    try:
        destination_object = s3.get_object(**object_kwargs(signed))
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_GET_UNAVAILABLE"
        ) from exc
    destination_payload = _validate_artifact_body(
        destination_object, signed, code="SIGNED_ARTIFACT_BODY_MISMATCH"
    )
    if _zip_member_payloads(
        source_payload, code="UNSIGNED_ARTIFACT_ZIP_INVALID"
    ) != _zip_member_payloads(
        destination_payload, code="SIGNED_ARTIFACT_ZIP_INVALID"
    ):
        raise RetirementEntrypointMaterializationError(
            "SIGNED_ARTIFACT_SEMANTIC_MISMATCH"
        )

    lambda_client = client_factory.lambda_client()
    operations.append("lambda:GetCodeSigningConfig")
    try:
        code_signing = lambda_client.get_code_signing_config(
            CodeSigningConfigArn=contract["code_signing_config"]["arn"]
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "CODE_SIGNING_CONFIG_READBACK_UNAVAILABLE"
        ) from exc
    _validate_code_signing_config(code_signing, contract)
    if plan["artifact_signing_evidence_digest"] != artifact_signing_evidence_digest(
        contract
    ):
        raise RetirementEntrypointMaterializationError(
            "ARTIFACT_SIGNING_EVIDENCE_DIGEST_MISMATCH"
        )


def _validate_broker_configuration(
    configuration: Any, *, plan: Mapping[str, Any]
) -> str:
    if not isinstance(configuration, Mapping):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CONFIGURATION_MISMATCH"
        )
    signed = plan["artifact_signing_contract"]["signed_destination"]
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan["parameter_projection"]
    }
    environment = plan["function_configurator"]["update_request_projection"][
        "Environment"
    ]
    expected = {
        "FunctionName": BROKER_FUNCTION_NAME,
        "FunctionArn": BROKER_FUNCTION_ARN,
        "Runtime": "python3.12",
        "Role": BROKER_EXECUTION_ROLE_ARN,
        "Handler": BROKER_HANDLER,
        "CodeSize": signed["archive_size_bytes"],
        "Description": "GUG-215 exact retained Change Set retirement PEP",
        "Timeout": 60,
        "MemorySize": 256,
        "CodeSha256": signed["lambda_code_sha256"],
        "Version": "$LATEST",
        "Environment": environment,
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "EphemeralStorage": {"Size": 512},
        "LoggingConfig": {
            "LogFormat": "JSON",
            "ApplicationLogLevel": "ERROR",
            "SystemLogLevel": "WARN",
            "LogGroup": LOG_GROUP_NAME,
        },
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "RuntimeVersionConfig": {
            "RuntimeVersionArn": parameters["BrokerRuntimeVersionArn"]
        },
        "VpcConfig": {
            "SubnetIds": [],
            "SecurityGroupIds": [],
            "VpcId": "",
        },
        "Layers": [],
        "FileSystemConfigs": [],
        "DeadLetterConfig": {},
        "TracingConfig": {"Mode": "PassThrough"},
        "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
    }
    safe_defaults = _expected_broker_safe_configuration_defaults()
    configured_optional_surfaces = {
        key: configuration.get(key) for key in safe_defaults
    }
    image_config = configured_optional_surfaces["ImageConfigResponse"]
    image_config_is_empty = image_config in (None, {}) or (
        isinstance(image_config, Mapping)
        and set(image_config) == {"ImageConfig"}
        and image_config.get("ImageConfig") == {}
    )
    if (
        any(configuration.get(key) != value for key, value in expected.items())
        or configuration.get("KMSKeyArn") not in (None, "")
        or any(
            configured_optional_surfaces[key] not in (None, {})
            for key in ("CapacityProviderConfig", "DurableConfig", "TenancyConfig")
        )
        or not image_config_is_empty
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CONFIGURATION_MISMATCH"
        )
    revision_id = configuration.get("RevisionId")
    if (
        not isinstance(revision_id, str)
        or not revision_id
        or len(revision_id) > 256
        or any(
            ord(character) < 0x21 or ord(character) == 0x7F
            for character in revision_id
        )
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_REVISION_ID_INVALID"
        )
    return revision_id


def _exact_provider_business_response(
    response: object,
    *,
    expected: Mapping[str, Any],
) -> bool:
    """Compare exact business fields while permitting only SDK metadata."""

    if not isinstance(response, Mapping):
        return False
    allowed = {*expected, "ResponseMetadata"}
    if set(response) != set(expected) and set(response) != allowed:
        return False
    metadata = response.get("ResponseMetadata")
    return (metadata is None or isinstance(metadata, Mapping)) and all(
        response.get(key) == value for key, value in expected.items()
    )


def _refresh_broker_function_readback(
    *,
    plan: Mapping[str, Any],
    client_factory: ClientFactory,
    operations: list[str],
) -> None:
    """Re-read the configured inert function immediately before CreateStack."""

    lambda_client = client_factory.lambda_client()
    operations.append("lambda:GetFunction")
    try:
        function = lambda_client.get_function(FunctionName=BROKER_FUNCTION_NAME)
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_READBACK_UNAVAILABLE"
        ) from exc
    if not isinstance(function, Mapping):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_READBACK_MISMATCH"
        )
    revision_id = _validate_broker_configuration(
        function.get("Configuration"), plan=plan
    )
    code = function.get("Code")
    expected_signed = plan["artifact_signing_contract"]["signed_destination"]
    if not isinstance(code, Mapping) or code.get("RepositoryType") != "S3":
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CODE_READBACK_MISMATCH"
        )
    resolved = code.get("ResolvedS3Object")
    if resolved is not None and resolved != {
        "Bucket": expected_signed["bucket"],
        "Key": expected_signed["key"],
        "Version": expected_signed["version_id"],
    }:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CODE_READBACK_MISMATCH"
        )
    if function.get("Tags") != _expected_broker_function_tags(plan):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_TAG_READBACK_MISMATCH"
        )

    operations.append("lambda:GetFunctionConfiguration")
    try:
        configuration = lambda_client.get_function_configuration(
            FunctionName=BROKER_FUNCTION_NAME
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CONFIGURATION_READBACK_UNAVAILABLE"
        ) from exc
    if _validate_broker_configuration(configuration, plan=plan) != revision_id:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_REVISION_CHANGED"
        )

    operations.append("lambda:GetFunctionCodeSigningConfig")
    try:
        function_csc = lambda_client.get_function_code_signing_config(
            FunctionName=BROKER_FUNCTION_NAME
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CSC_READBACK_UNAVAILABLE"
        ) from exc
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in plan["parameter_projection"]
    }
    if not _exact_provider_business_response(
        function_csc,
        expected={
            "CodeSigningConfigArn": parameters["BrokerCodeSigningConfigArn"]
        },
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CSC_READBACK_MISMATCH"
        )

    operations.append("lambda:GetFunctionConcurrency")
    try:
        concurrency = lambda_client.get_function_concurrency(
            FunctionName=BROKER_FUNCTION_NAME
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CONCURRENCY_READBACK_UNAVAILABLE"
        ) from exc
    if not _exact_provider_business_response(
        concurrency,
        expected={"ReservedConcurrentExecutions": 1},
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_CONCURRENCY_READBACK_MISMATCH"
        )

    operations.append("lambda:GetRuntimeManagementConfig")
    try:
        runtime = lambda_client.get_runtime_management_config(
            FunctionName=BROKER_FUNCTION_NAME
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_RUNTIME_READBACK_UNAVAILABLE"
        ) from exc
    if not _exact_provider_business_response(
        runtime,
        expected={
            "FunctionArn": BROKER_FUNCTION_ARN,
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": parameters["BrokerRuntimeVersionArn"],
        },
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_RUNTIME_READBACK_MISMATCH"
        )

    operations.append("lambda:ListTags")
    try:
        tags = lambda_client.list_tags(Resource=BROKER_FUNCTION_ARN)
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_TAG_READBACK_UNAVAILABLE"
        ) from exc
    if not _exact_provider_business_response(
        tags,
        expected={"Tags": _expected_broker_function_tags(plan)},
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_TAG_READBACK_MISMATCH"
        )

    operations.append("lambda:ListVersionsByFunction")
    try:
        versions = lambda_client.list_versions_by_function(
            FunctionName=BROKER_FUNCTION_NAME, MaxItems=50
        )
    except Exception as exc:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_VERSION_READBACK_UNAVAILABLE"
        ) from exc
    version_items = versions.get("Versions") if isinstance(versions, Mapping) else None
    if (
        not isinstance(version_items, list)
        or len(version_items) != 1
        or version_items[0].get("Version") != "$LATEST"
        or version_items[0].get("CodeSha256") != expected_signed["lambda_code_sha256"]
        or (isinstance(versions, Mapping) and versions.get("NextMarker") is not None)
    ):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_VERSION_READBACK_MISMATCH"
        )

    for action, method_name, response_key, unavailable_code, mismatch_code in (
        (
            "lambda:ListAliases",
            "list_aliases",
            "Aliases",
            "BROKER_FUNCTION_ALIAS_READBACK_UNAVAILABLE",
            "BROKER_FUNCTION_ALIAS_READBACK_MISMATCH",
        ),
        (
            "lambda:ListFunctionUrlConfigs",
            "list_function_url_configs",
            "FunctionUrlConfigs",
            "BROKER_FUNCTION_URL_READBACK_UNAVAILABLE",
            "BROKER_FUNCTION_URL_READBACK_MISMATCH",
        ),
    ):
        operations.append(action)
        try:
            response = getattr(lambda_client, method_name)(
                FunctionName=BROKER_FUNCTION_NAME, MaxItems=50
            )
        except Exception as exc:
            raise RetirementEntrypointMaterializationError(unavailable_code) from exc
        if (
            not isinstance(response, Mapping)
            or response.get(response_key) != []
            or response.get("NextMarker") is not None
        ):
            raise RetirementEntrypointMaterializationError(mismatch_code)

    operations.append("lambda:GetPolicy")
    try:
        lambda_client.get_policy(FunctionName=BROKER_FUNCTION_NAME)
    except Exception as exc:
        code_value, _ = _aws_error(exc)
        if code_value != "ResourceNotFoundException":
            raise RetirementEntrypointMaterializationError(
                "BROKER_FUNCTION_POLICY_READBACK_UNAVAILABLE"
            ) from exc
    else:
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_POLICY_PRESENT"
        )
    observed_evidence = broker_function_evidence_digest(
        plan=plan, revision_id=revision_id
    )
    if observed_evidence != plan.get("broker_function_evidence_digest"):
        raise RetirementEntrypointMaterializationError(
            "BROKER_FUNCTION_EVIDENCE_DIGEST_MISMATCH"
        )


def _identity_digest(identity: Any, authorization: Mapping[str, Any]) -> str:
    if not isinstance(identity, Mapping):
        raise RetirementEntrypointMaterializationError("CALLER_IDENTITY_INVALID")
    account = identity.get("Account")
    arn = identity.get("Arn")
    user_id = identity.get("UserId")
    if (
        account != AUTHORITY_ACCOUNT_ID
        or not isinstance(arn, str)
        or _CALLER_ARN_RE.fullmatch(arn) is None
        or not isinstance(user_id, str)
        or not user_id
    ):
        raise RetirementEntrypointMaterializationError("CALLER_IDENTITY_INVALID")
    observed = digest_text(arn)
    if observed != authorization.get("caller_arn_sha256"):
        raise RetirementEntrypointMaterializationError("CALLER_IDENTITY_MISMATCH")
    if digest_text(user_id) != authorization.get("caller_user_id_sha256"):
        raise RetirementEntrypointMaterializationError("CALLER_IDENTITY_MISMATCH")
    return observed


def apply_materialization(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    repo_root: Path,
    client_factory: ClientFactory,
    claim_attempt: Callable[[Mapping[str, Any]], None],
    clock: Callable[[], datetime],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Attempt the one direct CreateStack write, or prove no-touch state."""

    validate_materialization_plan(plan, repo_root=repo_root)
    validate_execution_authorization(
        authorization, plan=plan, now=clock(), require_active=True
    )
    operations: list[str] = []
    ledger: dict[str, Any] | None = None
    mutation_attempted = False
    artifact_signing_readback_complete = False
    broker_function_readback_complete = False
    try:
        sts = client_factory.sts()
        operations.append("sts:GetCallerIdentity")
        caller_digest = _identity_digest(sts.get_caller_identity(), authorization)
        cfn = client_factory.cloudformation()
        operations.append("cloudformation:DescribeStacks")
        first_stack = _describe_stack(cfn, DEDICATED_STACK_NAME)

        _refresh_artifact_signing_readback(
            plan=plan,
            client_factory=client_factory,
            operations=operations,
        )
        artifact_signing_readback_complete = True
        _refresh_broker_function_readback(
            plan=plan,
            client_factory=client_factory,
            operations=operations,
        )
        broker_function_readback_complete = True

        operations.append("cloudformation:DescribeStacks")
        second_stack = _describe_stack(cfn, DEDICATED_STACK_NAME)
        validate_execution_authorization(
            authorization, plan=plan, now=clock(), require_active=True
        )

        first_id = first_stack.get("StackId") if first_stack is not None else None
        second_id = second_stack.get("StackId") if second_stack is not None else None
        if first_stack is not None and (
            second_stack is None
            or not isinstance(first_id, str)
            or first_id != second_id
        ):
            return build_materialization_receipt(
                plan=plan,
                authorization=authorization,
                execution_mode="APPLY",
                status="READBACK_PENDING_NO_MUTATION",
                target_state="AMBIGUOUS",
                ledger_digest=None,
                stack_id=None,
                stack_status=None,
                observed_resources=(),
                aws_operations=operations,
                aws_mutation_attempted=False,
                ambiguous_response=True,
                no_touch=True,
                artifact_signing_readback_complete=True,
                broker_function_readback_complete=True,
                readback_complete=False,
                created_at=clock(),
            ), None
        if second_stack is not None:
            state, stack_id, stack_status, resources = _readback(
                cfn,
                stack=second_stack,
                plan=plan,
                operations=operations,
                masked_parameters_causally_bound=False,
            )
            if state == "COMPLETE":
                # APPLY has no durable causal binding for a stack it did not
                # create under this execution ledger, even if a synthetic or
                # future provider response exposes every NoEcho value.
                state = "AMBIGUOUS"
            status = {
                "IN_PROGRESS": "READBACK_PENDING_NO_MUTATION",
                "PARTIAL": "NONDESTRUCTIVE_RECOVERY_REQUIRED",
                "DRIFTED": "BLOCKED_DRIFT",
                "AMBIGUOUS": "READBACK_PENDING_NO_MUTATION",
            }[state]
            return build_materialization_receipt(
                plan=plan,
                authorization=authorization,
                execution_mode="APPLY",
                status=status,
                target_state=state,
                ledger_digest=None,
                stack_id=stack_id,
                stack_status=stack_status,
                observed_resources=resources,
                aws_operations=operations,
                aws_mutation_attempted=False,
                ambiguous_response=state == "AMBIGUOUS",
                no_touch=True,
                artifact_signing_readback_complete=True,
                broker_function_readback_complete=True,
                readback_complete=state == "COMPLETE",
                created_at=clock(),
            ), None

        ledger = build_execution_ledger(
            plan=plan,
            authorization=authorization,
            caller_arn_sha256=caller_digest,
            claimed_at=clock(),
        )
        claim_attempt(ledger)
        try:
            validate_execution_authorization(
                authorization,
                plan=plan,
                now=clock(),
                require_active=True,
            )
        except RetirementEntrypointMaterializationError as exc:
            if exc.code != "AUTHORIZATION_NOT_ACTIVE":
                raise
            return build_materialization_receipt(
                plan=plan,
                authorization=authorization,
                execution_mode="APPLY",
                status="AUTHORIZATION_EXPIRED_AFTER_CLAIM_NO_MUTATION",
                target_state="ABSENT",
                ledger_digest=ledger["ledger_digest"],
                stack_id=None,
                stack_status=None,
                observed_resources=(),
                aws_operations=operations,
                aws_mutation_attempted=False,
                ambiguous_response=False,
                no_touch=True,
                artifact_signing_readback_complete=True,
                broker_function_readback_complete=True,
                readback_complete=False,
                created_at=clock(),
            ), ledger
        operations.append("cloudformation:CreateStack")
        mutation_attempted = True
        response = cfn.create_stack(**plan["create_stack_request"])
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        if not isinstance(stack_id, str) or _STACK_ID_RE.fullmatch(stack_id) is None:
            raise RetirementEntrypointMaterializationError("CREATE_STACK_RESPONSE_AMBIGUOUS")
        operations.append("cloudformation:DescribeStacks")
        stack = _describe_stack(cfn, stack_id)
        if stack is None:
            raise RetirementEntrypointMaterializationError("CREATE_STACK_NOT_VISIBLE")
        state, observed_id, stack_status, resources = _readback(
            cfn,
            stack=stack,
            plan=plan,
            operations=operations,
            masked_parameters_causally_bound=True,
        )
        status = {
            "COMPLETE": "READBACK_VERIFIED",
            "IN_PROGRESS": "CREATESTACK_ACCEPTED_RECONCILE_REQUIRED",
            "PARTIAL": "NONDESTRUCTIVE_RECOVERY_REQUIRED",
            "DRIFTED": "BLOCKED_DRIFT",
            "AMBIGUOUS": "UNCERTAIN_RECONCILE_ONLY",
        }[state]
        return build_materialization_receipt(
            plan=plan,
            authorization=authorization,
            execution_mode="APPLY",
            status=status,
            target_state=state,
            ledger_digest=ledger["ledger_digest"],
            stack_id=observed_id,
            stack_status=stack_status,
            observed_resources=resources,
            aws_operations=operations,
            aws_mutation_attempted=True,
            ambiguous_response=state == "AMBIGUOUS",
            no_touch=False,
            artifact_signing_readback_complete=True,
            broker_function_readback_complete=True,
            readback_complete=state == "COMPLETE",
            created_at=clock(),
        ), ledger
    except RetirementEntrypointMaterializationError:
        if not mutation_attempted or ledger is None:
            raise
        receipt = build_materialization_receipt(
            plan=plan,
            authorization=authorization,
            execution_mode="APPLY",
            status="UNCERTAIN_RECONCILE_ONLY",
            target_state="UNKNOWN",
            ledger_digest=ledger["ledger_digest"],
            stack_id=None,
            stack_status=None,
            observed_resources=(),
            aws_operations=operations,
            aws_mutation_attempted=True,
            ambiguous_response=True,
            no_touch=False,
            artifact_signing_readback_complete=artifact_signing_readback_complete,
            broker_function_readback_complete=broker_function_readback_complete,
            readback_complete=False,
            created_at=clock(),
        )
        return receipt, ledger
    except Exception:
        if not mutation_attempted or ledger is None:
            raise RetirementEntrypointMaterializationError("AWS_READBACK_UNAVAILABLE") from None
        receipt = build_materialization_receipt(
            plan=plan,
            authorization=authorization,
            execution_mode="APPLY",
            status="UNCERTAIN_RECONCILE_ONLY",
            target_state="UNKNOWN",
            ledger_digest=ledger["ledger_digest"],
            stack_id=None,
            stack_status=None,
            observed_resources=(),
            aws_operations=operations,
            aws_mutation_attempted=True,
            ambiguous_response=True,
            no_touch=False,
            artifact_signing_readback_complete=artifact_signing_readback_complete,
            broker_function_readback_complete=broker_function_readback_complete,
            readback_complete=False,
            created_at=clock(),
        )
        return receipt, ledger


def reconcile_materialization(
    *,
    plan: Mapping[str, Any],
    authorization: Mapping[str, Any],
    ledger: Mapping[str, Any],
    repo_root: Path,
    client_factory: ClientFactory,
    clock: Callable[[], datetime],
) -> dict[str, Any]:
    """Perform read-only reconciliation after a consumed attempt."""

    validate_materialization_plan(plan, repo_root=repo_root)
    validate_execution_authorization(
        authorization, plan=plan, now=clock(), require_active=False
    )
    validate_execution_ledger(ledger, plan=plan, authorization=authorization)
    operations: list[str] = []
    sts = client_factory.sts()
    operations.append("sts:GetCallerIdentity")
    _identity_digest(sts.get_caller_identity(), authorization)
    cfn = client_factory.cloudformation()
    artifact_signing_readback_complete = False
    broker_function_readback_complete = False
    try:
        operations.append("cloudformation:DescribeStacks")
        first_stack = _describe_stack(cfn, DEDICATED_STACK_NAME)
        _refresh_artifact_signing_readback(
            plan=plan,
            client_factory=client_factory,
            operations=operations,
        )
        artifact_signing_readback_complete = True
        _refresh_broker_function_readback(
            plan=plan,
            client_factory=client_factory,
            operations=operations,
        )
        broker_function_readback_complete = True
        operations.append("cloudformation:DescribeStacks")
        second_stack = _describe_stack(cfn, DEDICATED_STACK_NAME)
        first_id = first_stack.get("StackId") if first_stack is not None else None
        second_id = second_stack.get("StackId") if second_stack is not None else None
        if first_stack is not None and (
            second_stack is None
            or not isinstance(first_id, str)
            or first_id != second_id
        ):
            state, stack_id, stack_status, resources = "AMBIGUOUS", None, None, []
        elif second_stack is None:
            state, stack_id, stack_status, resources = "ABSENT", None, None, []
        else:
            state, stack_id, stack_status, resources = _readback(
                cfn,
                stack=second_stack,
                plan=plan,
                operations=operations,
                masked_parameters_causally_bound=True,
            )
    except RetirementEntrypointMaterializationError:
        state, stack_id, stack_status, resources = "AMBIGUOUS", None, None, []
    status = {
        "COMPLETE": "READBACK_VERIFIED",
        "IN_PROGRESS": "CREATESTACK_ACCEPTED_RECONCILE_REQUIRED",
        "PARTIAL": "NONDESTRUCTIVE_RECOVERY_REQUIRED",
        "DRIFTED": "BLOCKED_DRIFT",
        "AMBIGUOUS": "READBACK_PENDING_NO_MUTATION",
        "ABSENT": "NONDESTRUCTIVE_RECOVERY_REQUIRED",
    }[state]
    return build_materialization_receipt(
        plan=plan,
        authorization=authorization,
        execution_mode="RECONCILE",
        status=status,
        target_state=state,
        ledger_digest=str(ledger["ledger_digest"]),
        stack_id=stack_id,
        stack_status=stack_status,
        observed_resources=resources,
        aws_operations=operations,
        aws_mutation_attempted=False,
        ambiguous_response=state == "AMBIGUOUS",
        no_touch=True,
        artifact_signing_readback_complete=artifact_signing_readback_complete,
        broker_function_readback_complete=broker_function_readback_complete,
        readback_complete=state == "COMPLETE",
        created_at=clock(),
    )
