"""Deterministic offline compiler for the GUG-365 CloudFormation service role.

This module deliberately has no AWS client, session, filesystem-write, or live
apply path.  It consumes an already valid GUG-363 plan plus an independently
supplied expected digest and compiles the exact IAM objects required before
GUG-357 may be considered again:

* six customer-managed permissions boundaries; and
* seven roles pre-created outside CloudFormation with exact trust, one managed
  policy used as both identity policy and permissions boundary, and exact tags;
* the retained ledger table with its deny-by-default resource policy and PITR,
  created only by a separately signed one-shot factory; and
* the exact signed Lambda broker and immutable factory version, created while
  both execution roles are still proof-bound and inert, before CloudFormation
  receives any durable authority.

The compiler never adopts, updates, deletes, repairs, or retries a pre-existing
IAM object.  Provider readbacks are represented only as normalized offline
contracts so a later, separately authorized live lane can fail closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from tooling import platform_authority_retirement_entrypoint_materializer as gug363
from tooling import platform_authority_gug365_phase_execution_ledger as phase_ledger
from tooling import platform_authority_retirement_ledger_factory as ledger_factory
from tooling import platform_authority_retirement_ledger_factory_package as ledger_factory_package


IMPLEMENTATION_ISSUE = "GUG-365"
PARENT_ISSUE = "GUG-357"
SOURCE_ISSUE = "GUG-363"
AUTHORITY_ACCOUNT_ID = gug363.AUTHORITY_ACCOUNT_ID
REGION = gug363.REGION
PARTITION = "aws"
SERVICE_ROLE_NAME = gug363.CLOUDFORMATION_SERVICE_ROLE_NAME
SERVICE_ROLE_ARN = gug363.CLOUDFORMATION_SERVICE_ROLE_ARN
SERVICE_ROLE_PATH = "/"
MANAGED_POLICY_PATH = "/scanalyze/platform-authority/"
PLAN_TYPE = (
    "scanalyze.platform_authority.retirement_entrypoint_service_role_plan.v1"
)

SERVICE_ROLE_BOUNDARY_NAME = (
    "scanalyze-platform-authority-gug365-cfn-service-role-boundary"
)
BROKER_BOUNDARY_NAME = "scanalyze-platform-authority-gug365-broker-boundary"
CLASSIFIER_BOUNDARY_NAME = (
    "scanalyze-platform-authority-gug365-classifier-invoker-boundary"
)
APPROVER_BOUNDARY_NAME = (
    "scanalyze-platform-authority-gug365-approver-invoker-boundary"
)
PROOF_BOUNDARY_NAME = "scanalyze-platform-authority-gug365-proof-boundary"
LEDGER_FACTORY_BOUNDARY_NAME = (
    "scanalyze-platform-authority-gug365-ledger-factory-boundary"
)

BROKER_ROLE_NAME = "ScanalyzeGug215BrokerExecution"
CLASSIFIER_ROLE_NAME = "ScanalyzeGug215ClassifierInvoker"
APPROVER_ROLE_NAME = "ScanalyzeGug215ApproverInvoker"
CLASSIFIER_PROOF_ROLE_NAME = "ScanalyzeGug217ClassifierProof"
APPROVER_PROOF_ROLE_NAME = "ScanalyzeGug217ApproverProof"
LEDGER_FACTORY_ROLE_NAME = ledger_factory.FACTORY_ROLE_NAME
BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
LEDGER_FACTORY_FUNCTION_NAME = ledger_factory.FACTORY_FUNCTION_NAME
LEDGER_TABLE_NAME = "scanalyze-platform-authority-change-set-retirements"
LOG_GROUP_NAME = "/aws/lambda/scanalyze-platform-authority-gug215-retirement"
LEDGER_FACTORY_LOG_GROUP_NAME = (
    "/aws/lambda/scanalyze-platform-authority-gug365-ledger-factory"
)

BROKER_BOUNDARY_PATH = Path(
    "policies/iam/platform-authority-gug365-broker-boundary.json"
)
CLASSIFIER_BOUNDARY_PATH = Path(
    "policies/iam/platform-authority-gug365-classifier-invoker-boundary.json"
)
APPROVER_BOUNDARY_PATH = Path(
    "policies/iam/platform-authority-gug365-approver-invoker-boundary.json"
)
PROOF_BOUNDARY_PATH = Path(
    "policies/iam/platform-authority-gug365-proof-boundary.json"
)
LEDGER_FACTORY_BOUNDARY_PATH = Path(
    "policies/iam/platform-authority-gug365-ledger-factory-boundary.json"
)
POLICY_FACTORY_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-policy-factory.json"
)
FOUNDATION_FACTORY_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-foundation-factory.json"
)
FUNCTION_FACTORY_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-function-factory.json"
)
LEDGER_FACTORY_FUNCTION_FACTORY_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-ledger-factory-function-factory.json"
)
ACTIVATOR_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-activator.json"
)
REVOCATOR_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-revocator.json"
)
LEDGER_FACTORY_ACTIVATOR_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-ledger-factory-activator.json"
)
LEDGER_FACTORY_INVOKER_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-ledger-factory-invoker.json"
)
LEDGER_FACTORY_REVOKER_POLICY_PATH = Path(
    "policies/iam/platform-authority-gug365-ledger-factory-revoker.json"
)

BOUNDARY_ORDER = (
    "service_role",
    "broker",
    "classifier_invoker",
    "approver_invoker",
    "proof",
    "ledger_factory",
)
BOUNDARY_NAMES = {
    "service_role": SERVICE_ROLE_BOUNDARY_NAME,
    "broker": BROKER_BOUNDARY_NAME,
    "classifier_invoker": CLASSIFIER_BOUNDARY_NAME,
    "approver_invoker": APPROVER_BOUNDARY_NAME,
    "proof": PROOF_BOUNDARY_NAME,
    "ledger_factory": LEDGER_FACTORY_BOUNDARY_NAME,
}
BOUNDARY_TEMPLATE_PATHS = {
    "broker": BROKER_BOUNDARY_PATH,
    "classifier_invoker": CLASSIFIER_BOUNDARY_PATH,
    "approver_invoker": APPROVER_BOUNDARY_PATH,
    "proof": PROOF_BOUNDARY_PATH,
    "ledger_factory": LEDGER_FACTORY_BOUNDARY_PATH,
}
CHILD_ROLE_BOUNDARY_KEYS = {
    BROKER_ROLE_NAME: "broker",
    CLASSIFIER_ROLE_NAME: "classifier_invoker",
    APPROVER_ROLE_NAME: "approver_invoker",
    CLASSIFIER_PROOF_ROLE_NAME: "proof",
    APPROVER_PROOF_ROLE_NAME: "proof",
    LEDGER_FACTORY_ROLE_NAME: "proof",
}
ROLE_ORDER = (
    SERVICE_ROLE_NAME,
    BROKER_ROLE_NAME,
    CLASSIFIER_ROLE_NAME,
    APPROVER_ROLE_NAME,
    CLASSIFIER_PROOF_ROLE_NAME,
    APPROVER_PROOF_ROLE_NAME,
    LEDGER_FACTORY_ROLE_NAME,
)
CHILD_BOUNDARY_ALLOWED_ACTIONS = {
    "broker": frozenset(
        {
            "cloudformation:DeleteChangeSet",
            "cloudformation:DescribeChangeSet",
            "cloudformation:DescribeStacks",
            "cloudformation:GetTemplate",
            "cloudformation:ListChangeSets",
            "cloudformation:ListStackResources",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:GetItem",
            "dynamodb:GetResourcePolicy",
            "dynamodb:ListTagsOfResource",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListAttachedRolePolicies",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:ListRolePolicies",
            "kms:DescribeKey",
            "lambda:GetAlias",
            "lambda:GetFunctionCodeSigningConfig",
            "lambda:GetFunctionConcurrency",
            "lambda:GetFunctionConfiguration",
            "lambda:GetFunctionUrlConfig",
            "lambda:GetPolicy",
            "lambda:GetRuntimeManagementConfig",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "kms:DescribeKey",
            "s3:GetAccountPublicAccessBlock",
            "sso-oauth:CreateTokenWithIAM",
            "sts:AssumeRole",
            "sts:SetContext",
        }
    ),
    "classifier_invoker": frozenset(
        {"lambda:InvokeFunction", "lambda:InvokeFunctionUrl"}
    ),
    "approver_invoker": frozenset(
        {"lambda:InvokeFunction", "lambda:InvokeFunctionUrl"}
    ),
    "proof": frozenset(),
    "ledger_factory": frozenset(
        {
            "sts:GetCallerIdentity",
            "dynamodb:CreateTable",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:GetResourcePolicy",
            "dynamodb:ListTagsOfResource",
            "dynamodb:PutResourcePolicy",
            "dynamodb:Scan",
            "dynamodb:TagResource",
            "dynamodb:UpdateContinuousBackups",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "kms:DescribeKey",
        }
    ),
}

ALLOWED_MUTATIONS = (
    "iam:CreatePolicy",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePermissionsBoundary",
    "lambda:CreateFunction",
    "lambda:PutFunctionConcurrency",
    "lambda:PutRuntimeManagementConfig",
    "lambda:InvokeFunction",
    "iam:DetachRolePolicy",
    "logs:CreateLogGroup",
    "logs:PutRetentionPolicy",
    "logs:TagResource",
)
PROHIBITED_MUTATIONS = (
    "iam:AddRoleToInstanceProfile",
    "iam:CreatePolicyVersion",
    "iam:DeletePolicy",
    "iam:DeletePolicyVersion",
    "iam:DeleteRole",
    "iam:DeleteRolePermissionsBoundary",
    "iam:DeleteRolePolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:SetDefaultPolicyVersion",
    "iam:TagPolicy",
    "iam:TagRole",
    "iam:PutRolePolicy",
    "iam:UntagPolicy",
    "iam:UntagRole",
    "iam:UpdateAssumeRolePolicy",
    "iam:UpdateRole",
    "iam:UpdateRoleDescription",
    "lambda:AddPermission",
    "lambda:CreateAlias",
    "lambda:CreateFunctionUrlConfig",
    "lambda:DeleteFunction",
    "lambda:DeleteFunctionConcurrency",
    "lambda:PublishVersion",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
)
PROHIBITED_STANDALONE_MUTATIONS = (
    "dynamodb:PutResourcePolicy",
    "lambda:TagResource",
)
POLICY_READBACK_ACTIONS = (
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListPolicyVersions",
    "iam:ListEntitiesForPolicy:PermissionsPolicy",
    "iam:ListEntitiesForPolicy:PermissionsBoundary",
    "iam:ListPolicyTags",
)
ROLE_READBACK_ACTIONS = (
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListRoleTags",
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_VERSION_RE = re.compile(r"^[^\s]{1,1024}$")
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LAMBDA_CODE_SHA256_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SIGNING_JOB_RE = re.compile(r"^[0-9a-f]{32}$")
_FACTORY_VERSION = "1"
_POLICY_MAX_NON_WHITESPACE_BYTES = 6_144


class ServiceRoleMaterializationError(ValueError):
    """A stable, sanitized failure in the offline GUG-365 contract."""

    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) is None:
            code = "GUG365_SERVICE_ROLE_PLAN_INVALID"
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise ServiceRoleMaterializationError(code)


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


def _canonical_snapshot(value: Any, code: str) -> Any:
    """Detach one immutable JSON snapshot at a trust boundary."""

    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(code)


def _byte_digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _is_exact_int(value: object, expected: int) -> bool:
    """Reject booleans while checking an exact JSON integer contract."""

    return type(value) is int and value == expected


def _is_bounded_int(value: object, minimum: int, maximum: int) -> bool:
    """Reject booleans and integers outside the runtime's bounded poll path."""

    return type(value) is int and minimum <= value <= maximum


def _policy_arn(name: str) -> str:
    path = MANAGED_POLICY_PATH.strip("/")
    return f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:policy/{path}/{name}"


def _role_arn(name: str) -> str:
    return f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:role/{name}"


def _table_arn() -> str:
    return (
        f"arn:{PARTITION}:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"table/{LEDGER_TABLE_NAME}"
    )


def _function_arn() -> str:
    return (
        f"arn:{PARTITION}:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{BROKER_FUNCTION_NAME}"
    )


def _ledger_factory_function_arn(*, version: str | None = None) -> str:
    base = (
        f"arn:{PARTITION}:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{LEDGER_FACTORY_FUNCTION_NAME}"
    )
    return base if version is None else f"{base}:{version}"


def _ledger_factory_log_stream_arn() -> str:
    return (
        f"arn:{PARTITION}:logs:{REGION}:{AUTHORITY_ACCOUNT_ID}:log-group:"
        f"{LEDGER_FACTORY_LOG_GROUP_NAME}:log-stream:*"
    )


def _ledger_factory_log_group_arn() -> str:
    return (
        f"arn:{PARTITION}:logs:{REGION}:{AUTHORITY_ACCOUNT_ID}:log-group:"
        f"{LEDGER_FACTORY_LOG_GROUP_NAME}"
    )


def _table_tags(gug363_plan: Mapping[str, Any]) -> list[dict[str, str]]:
    # The broker treats these tags as part of the live ledger contract.  Keep
    # the pre-created table byte-for-byte compatible with that existing
    # readback instead of reusing the GUG-365 IAM-resource provenance tags.
    del gug363_plan
    return [
        {"Key": "managed_by", "Value": "reviewed-direct-dynamodb"},
        {"Key": "service", "Value": "scanalyze-platform-authority"},
        {"Key": "data_class", "Value": "control-metadata"},
        {"Key": "work_package", "Value": "GUG-215"},
        {"Key": "environment", "Value": "non-production"},
        {"Key": "production", "Value": "false"},
        {"Key": "account_id", "Value": AUTHORITY_ACCOUNT_ID},
        {"Key": "region", "Value": REGION},
    ]


def _ledger_resource_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyWritesOutsideRetirementBroker",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": [
                    "dynamodb:BatchWriteItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:PartiQLDelete",
                    "dynamodb:PartiQLInsert",
                    "dynamodb:PartiQLUpdate",
                    "dynamodb:PutItem",
                    "dynamodb:TransactWriteItems",
                    "dynamodb:UpdateItem",
                ],
                "Resource": _table_arn(),
                "Condition": {
                    "ArnNotEquals": {
                        "aws:PrincipalArn": _role_arn(BROKER_ROLE_NAME)
                    }
                },
            }
        ],
    }


def _table_contract(gug363_plan: Mapping[str, Any]) -> dict[str, Any]:
    policy = _ledger_resource_policy()
    return {
        "table_name": LEDGER_TABLE_NAME,
        "arn": _table_arn(),
        "billing_mode": "PAY_PER_REQUEST",
        "attribute_definitions": [
            {"AttributeName": "retirement_id", "AttributeType": "S"}
        ],
        "key_schema": [{"AttributeName": "retirement_id", "KeyType": "HASH"}],
        "deletion_protection_enabled": True,
        "sse_specification": {
            "Enabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": ledger_factory.KMS_KEY_ALIAS,
        },
        "kms_key_contract": {
            "alias": ledger_factory.KMS_KEY_ALIAS,
            "alias_sha256": ledger_factory.canonical_digest(
                {"kms_key_alias": ledger_factory.KMS_KEY_ALIAS}
            ),
            "metadata_projection": {
                "AWSAccountId": AUTHORITY_ACCOUNT_ID,
                "Enabled": True,
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "Origin": "AWS_KMS",
                "KeyManager": "AWS",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "MultiRegion": False,
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                "arn_pattern": (
                    f"arn:{PARTITION}:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                    "key/<AWS_MANAGED_UUID>"
                ),
            },
            "receipt_fields_required": [
                "kms_key_arn_sha256",
                "kms_key_metadata_sha256",
            ],
            "raw_key_identifiers_persistence_permitted": False,
        },
        "table_class": "STANDARD",
        "resource_policy": policy,
        "resource_policy_digest": canonical_digest(policy),
        "point_in_time_recovery": {
            "PointInTimeRecoveryEnabled": True,
            "RecoveryPeriodInDays": 35,
        },
        "time_to_live": {
            "TimeToLiveStatus": "DISABLED",
            "AttributeName": None,
        },
        "latest_stream_label": None,
        "global_secondary_indexes": [],
        "local_secondary_indexes": [],
        "replicas": [],
        "tags": _table_tags(gug363_plan),
    }


def _create_table_request(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "TableName": contract["table_name"],
        "AttributeDefinitions": contract["attribute_definitions"],
        "KeySchema": contract["key_schema"],
        "BillingMode": contract["billing_mode"],
        "SSESpecification": contract["sse_specification"],
        "DeletionProtectionEnabled": contract["deletion_protection_enabled"],
        "TableClass": contract["table_class"],
        "ResourcePolicy": canonical_json(contract["resource_policy"]),
        "Tags": contract["tags"],
    }


def _update_pitr_request(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "TableName": contract["table_name"],
        "PointInTimeRecoverySpecification": contract["point_in_time_recovery"],
    }


def _function_tags(gug363_plan: Mapping[str, Any]) -> dict[str, str]:
    source = gug363_plan.get("source")
    if not isinstance(source, Mapping) or not isinstance(source.get("commit"), str):
        _fail("GUG363_SOURCE_INVALID")
    return {
        "managed_by": "reviewed-direct-lambda",
        "service": "scanalyze-platform-authority",
        "work_package": IMPLEMENTATION_ISSUE,
        "environment": "non-production",
        "production": "false",
        "source_commit": str(source["commit"]),
        "gug363_pre_function_binding_sha256": _gug363_pre_function_binding_digest(
            gug363_plan
        ),
    }


def _gug363_pre_function_binding_digest(
    gug363_plan: Mapping[str, Any],
) -> str:
    source = gug363_plan.get("source")
    if not isinstance(source, Mapping):
        _fail("GUG363_SOURCE_INVALID")
    try:
        return gug363.gug363_pre_function_binding_sha256(
            source=source,
            artifact_signing_contract_digest_value=str(
                gug363_plan["artifact_signing_contract_digest"]
            ),
            parameters=_parameter_values(gug363_plan),
        )
    except (
        KeyError,
        gug363.RetirementEntrypointMaterializationError,
    ) as exc:
        raise ServiceRoleMaterializationError(
            "GUG363_PRE_FUNCTION_BINDING_INVALID"
        ) from exc


def ledger_factory_artifact_signing_contract_digest(
    contract: Mapping[str, Any],
) -> str:
    """Domain-separate the dedicated factory artifact from the GUG-215 ZIP."""

    return "sha256:" + sha256(
        b"scanalyze:gug365:ledger-factory-artifact-signing-contract:v1\x00"
        + canonical_json(contract).encode("utf-8")
    ).hexdigest()


def _ledger_factory_signing_evidence_digest(
    contract: Mapping[str, Any],
) -> str:
    return canonical_digest(
        {
            "artifact_signing_contract_digest": (
                ledger_factory_artifact_signing_contract_digest(contract)
            ),
            "package_manifest_digest": contract["package_manifest"][
                "manifest_digest"
            ],
            "unsigned_source": contract["unsigned_source"],
            "signer": contract["signer"],
            "signed_destination": contract["signed_destination"],
            "code_signing_config": contract["code_signing_config"],
            "runtime_version_arn_sha256": canonical_digest(
                {"runtime_version_arn": contract["runtime_version_arn"]}
            ),
        }
    )


def _validate_ledger_factory_artifact_signing_contract(
    *,
    contract: Mapping[str, Any],
    expected_contract_digest: str,
    gug363_plan: Mapping[str, Any],
    repo_root: Path,
) -> None:
    _require_digest(
        expected_contract_digest,
        "EXPECTED_LEDGER_FACTORY_SIGNING_CONTRACT_DIGEST_INVALID",
    )
    required = {
        "contract_version",
        "package_manifest",
        "runtime_version_arn",
        "unsigned_source",
        "signer",
        "signed_destination",
        "code_signing_config",
    }
    if not isinstance(contract, Mapping) or set(contract) != required:
        _fail("LEDGER_FACTORY_SIGNING_CONTRACT_FIELDS_INVALID")
    if (
        contract.get("contract_version") != 1
        or ledger_factory_artifact_signing_contract_digest(contract)
        != expected_contract_digest
    ):
        _fail("LEDGER_FACTORY_SIGNING_CONTRACT_DIGEST_MISMATCH")
    manifest = contract.get("package_manifest")
    unsigned = contract.get("unsigned_source")
    signer = contract.get("signer")
    signed = contract.get("signed_destination")
    code_signing = contract.get("code_signing_config")
    if not all(
        isinstance(value, Mapping)
        for value in (manifest, unsigned, signer, signed, code_signing)
    ):
        _fail("LEDGER_FACTORY_SIGNING_CONTRACT_NESTING_INVALID")
    assert isinstance(manifest, Mapping)
    assert isinstance(unsigned, Mapping)
    assert isinstance(signer, Mapping)
    assert isinstance(signed, Mapping)
    assert isinstance(code_signing, Mapping)
    broker_signing_contract = gug363_plan.get("artifact_signing_contract")
    if not isinstance(broker_signing_contract, Mapping):
        _fail("LEDGER_FACTORY_GUG363_SIGNING_BINDING_INVALID")
    broker_signed = broker_signing_contract.get("signed_destination")
    broker_code_signing = broker_signing_contract.get("code_signing_config")
    if not isinstance(broker_signed, Mapping) or not isinstance(
        broker_code_signing, Mapping
    ):
        _fail("LEDGER_FACTORY_GUG363_SIGNING_BINDING_INVALID")
    try:
        ledger_factory_package.validate_ledger_factory_package_manifest(manifest)
    except ledger_factory_package.LedgerFactoryPackageError as exc:
        raise ServiceRoleMaterializationError(
            "LEDGER_FACTORY_PACKAGE_MANIFEST_INVALID"
        ) from exc
    source = gug363_plan.get("source")
    if not isinstance(source, Mapping) or manifest.get("source_commit") != source.get(
        "commit"
    ):
        _fail("LEDGER_FACTORY_PACKAGE_SOURCE_MISMATCH")
    runtime_version_arn = contract.get("runtime_version_arn")
    if (
        not isinstance(runtime_version_arn, str)
        or canonical_digest({"runtime_version_arn": runtime_version_arn})
        != manifest.get("runtime_version_arn_sha256")
    ):
        _fail("LEDGER_FACTORY_RUNTIME_BINDING_INVALID")
    try:
        committed = ledger_factory_package.verify_clean_source_commit(
            source_root=repo_root,
            source_commit=str(source["commit"]),
        )
        rebuilt = ledger_factory_package.build_ledger_factory_package(
            source_root=repo_root,
            source_commit=str(source["commit"]),
            runtime_version_arn=runtime_version_arn,
            committed_sources=committed,
        )
    except (OSError, ledger_factory_package.LedgerFactoryPackageError) as exc:
        raise ServiceRoleMaterializationError(
            "LEDGER_FACTORY_PACKAGE_SOURCE_NOT_PROVEN"
        ) from exc
    if rebuilt.manifest != manifest:
        _fail("LEDGER_FACTORY_PACKAGE_MANIFEST_SOURCE_MISMATCH")
    expected_unsigned_keys = {
        "artifact_type",
        "work_package",
        "manifest_digest",
        "archive_sha256",
        "lambda_code_sha256",
        "archive_size_bytes",
        "bucket",
        "key",
        "version_id",
        "sse_algorithm",
        "sse_kms_key_arn",
    }
    expected_signed_keys = {
        "bucket",
        "key",
        "version_id",
        "archive_sha256",
        "lambda_code_sha256",
        "archive_size_bytes",
        "sse_algorithm",
        "sse_kms_key_arn",
    }
    if set(unsigned) != expected_unsigned_keys or set(signed) != expected_signed_keys:
        _fail("LEDGER_FACTORY_ARTIFACT_OBJECT_FIELDS_INVALID")
    for key in (
        "artifact_type",
        "work_package",
        "manifest_digest",
        "archive_sha256",
        "lambda_code_sha256",
        "archive_size_bytes",
    ):
        if unsigned.get(key) != manifest.get(key):
            _fail("LEDGER_FACTORY_UNSIGNED_MANIFEST_BINDING_INVALID")
    commit = str(source["commit"])
    expected_unsigned_key = (
        "scanalyze/platform-authority/gug-365/ledger-factory/unsigned/"
        f"{commit}/{ledger_factory_package.ARCHIVE_NAME}"
    )
    job_id = signer.get("job_id")
    expected_signed_key = (
        "scanalyze/platform-authority/gug-365/ledger-factory/signed/"
        f"{job_id}.zip"
    )
    if (
        _COMMIT_RE.fullmatch(commit) is None
        or _SIGNING_JOB_RE.fullmatch(str(job_id)) is None
        or unsigned.get("key") != expected_unsigned_key
        or signed.get("key") != expected_signed_key
        or unsigned.get("bucket") != signed.get("bucket")
        or unsigned.get("bucket") != broker_signed.get("bucket")
        or signed.get("bucket") != broker_signed.get("bucket")
        or _S3_BUCKET_RE.fullmatch(str(unsigned.get("bucket"))) is None
        or unsigned.get("version_id") == signed.get("version_id")
        or not all(
            _VERSION_RE.fullmatch(str(value)) is not None
            for value in (unsigned.get("version_id"), signed.get("version_id"))
        )
        or unsigned.get("sse_algorithm") != "aws:kms"
        or signed.get("sse_algorithm") != "aws:kms"
        or unsigned.get("sse_kms_key_arn") != signed.get("sse_kms_key_arn")
        or unsigned.get("sse_kms_key_arn")
        != broker_signed.get("sse_kms_key_arn")
        or signed.get("sse_kms_key_arn")
        != broker_signed.get("sse_kms_key_arn")
        or unsigned.get("archive_sha256") == signed.get("archive_sha256")
        or unsigned.get("lambda_code_sha256")
        == signed.get("lambda_code_sha256")
        or _HEX_SHA256_RE.fullmatch(str(signed.get("archive_sha256"))) is None
        or _LAMBDA_CODE_SHA256_RE.fullmatch(
            str(signed.get("lambda_code_sha256"))
        )
        is None
        or type(signed.get("archive_size_bytes")) is not int
        or signed["archive_size_bytes"] <= 0
    ):
        _fail("LEDGER_FACTORY_SIGNED_ARTIFACT_BINDING_INVALID")
    required_signer = {
        "job_id",
        "status",
        "job_owner",
        "job_invoker",
        "platform_id",
        "profile_name",
        "profile_version_id",
        "profile_version_arn",
        "signature_expires_at",
    }
    if (
        set(signer) != required_signer
        or signer.get("status") != "Succeeded"
        or signer.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or signer.get("job_invoker") != AUTHORITY_ACCOUNT_ID
        or signer.get("platform_id") != gug363.SIGNING_PLATFORM
    ):
        _fail("LEDGER_FACTORY_SIGNER_EVIDENCE_INVALID")
    profile_arn = str(signer.get("profile_version_arn"))
    profile_match = gug363._SIGNING_PROFILE_VERSION_ARN_RE.fullmatch(  # noqa: SLF001
        profile_arn
    )
    try:
        signature_expires = gug363._parse_timestamp(  # noqa: SLF001
            signer.get("signature_expires_at"),
            "LEDGER_FACTORY_SIGNATURE_EXPIRY_INVALID",
        )
        required_valid_until = gug363._parse_timestamp(  # noqa: SLF001
            _parameter_values(gug363_plan)["SingleOperatorExceptionExpiresAt"],
            "LEDGER_FACTORY_SIGNATURE_EXPIRY_INVALID",
        )
    except gug363.RetirementEntrypointMaterializationError as exc:
        raise ServiceRoleMaterializationError(
            "LEDGER_FACTORY_SIGNATURE_EXPIRY_INVALID"
        ) from exc
    if (
        gug363._SIGNING_PROFILE_NAME_RE.fullmatch(  # noqa: SLF001
            str(signer.get("profile_name"))
        )
        is None
        or gug363._SIGNING_PROFILE_VERSION_RE.fullmatch(  # noqa: SLF001
            str(signer.get("profile_version_id"))
        )
        is None
        or profile_match is None
        or profile_match.group("name") != signer.get("profile_name")
        or profile_match.group("version") != signer.get("profile_version_id")
        or signature_expires < required_valid_until
    ):
        _fail("LEDGER_FACTORY_SIGNER_EVIDENCE_INVALID")
    if (
        set(code_signing)
        != {
            "arn",
            "allowed_signing_profile_version_arns",
            "untrusted_artifact_on_deployment",
        }
        or code_signing.get("allowed_signing_profile_version_arns")
        != [signer.get("profile_version_arn")]
        or code_signing.get("untrusted_artifact_on_deployment") != "Enforce"
        or code_signing != broker_code_signing
    ):
        _fail("LEDGER_FACTORY_CODE_SIGNING_CONFIG_INVALID")


def validate_ledger_factory_artifact_signing_contract(
    *,
    contract: Mapping[str, Any],
    expected_contract_digest: str,
    gug363_plan: Mapping[str, Any],
    repo_root: Path,
) -> None:
    """Public fail-closed validator for the exact ledger-factory contract."""

    contract_snapshot = _canonical_snapshot(
        contract, "LEDGER_FACTORY_SIGNING_CONTRACT_SNAPSHOT_INVALID"
    )
    gug363_snapshot = _canonical_snapshot(
        gug363_plan, "LEDGER_FACTORY_GUG363_PLAN_SNAPSHOT_INVALID"
    )
    if not isinstance(contract_snapshot, Mapping):
        _fail("LEDGER_FACTORY_SIGNING_CONTRACT_FIELDS_INVALID")
    if not isinstance(gug363_snapshot, Mapping):
        _fail("LEDGER_FACTORY_GUG363_PLAN_FIELDS_INVALID")
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        _fail("LEDGER_FACTORY_REPOSITORY_ROOT_INVALID")
    try:
        root = repo_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ServiceRoleMaterializationError(
            "LEDGER_FACTORY_REPOSITORY_ROOT_INVALID"
        ) from exc
    if root != repo_root or not root.is_dir():
        _fail("LEDGER_FACTORY_REPOSITORY_ROOT_INVALID")
    try:
        _validate_ledger_factory_artifact_signing_contract(
            contract=contract_snapshot,
            expected_contract_digest=expected_contract_digest,
            gug363_plan=gug363_snapshot,
            repo_root=root,
        )
    except ServiceRoleMaterializationError:
        raise
    except Exception as exc:
        raise ServiceRoleMaterializationError(
            "LEDGER_FACTORY_SIGNING_CONTRACT_VALIDATION_FAILED"
        ) from exc


def _function_contract(gug363_plan: Mapping[str, Any]) -> dict[str, Any]:
    parameters = _parameter_values(gug363_plan)
    signed = gug363_plan["artifact_signing_contract"]["signed_destination"]
    function_arn = _function_arn()
    code = {
        "S3Bucket": signed["bucket"],
        "S3Key": signed["key"],
        "S3ObjectVersion": signed["version_id"],
    }
    create_request = {
        "FunctionName": BROKER_FUNCTION_NAME,
        "Description": "GUG-215 exact retained Change Set retirement PEP",
        "Runtime": "python3.12",
        "Role": _role_arn(BROKER_ROLE_NAME),
        "Handler": "tooling.platform_authority_identity_context_pep_runtime.handler",
        "Code": code,
        "Timeout": 60,
        "MemorySize": 256,
        "Publish": False,
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "Environment": {"Variables": {}},
        "CodeSigningConfigArn": parameters["BrokerCodeSigningConfigArn"],
        "LoggingConfig": {
            "LogFormat": "JSON",
            "ApplicationLogLevel": "ERROR",
            "SystemLogLevel": "WARN",
            "LogGroup": LOG_GROUP_NAME,
        },
        "Tags": _function_tags(gug363_plan),
    }
    normalized_configuration = {
        "FunctionName": BROKER_FUNCTION_NAME,
        "FunctionArn": function_arn,
        "Runtime": "python3.12",
        "Role": _role_arn(BROKER_ROLE_NAME),
        "Handler": create_request["Handler"],
        "CodeSize": signed["archive_size_bytes"],
        "Description": create_request["Description"],
        "Timeout": 60,
        "MemorySize": 256,
        "CodeSha256": signed["lambda_code_sha256"],
        "Version": "$LATEST",
        "Environment": create_request["Environment"],
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "EphemeralStorage": {"Size": 512},
        "LoggingConfig": create_request["LoggingConfig"],
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "RuntimeVersionConfig": {
            "RuntimeVersionArn": parameters["BrokerRuntimeVersionArn"]
        },
        "VpcConfig": {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""},
        "Layers": [],
        "FileSystemConfigs": [],
        "KMSKeyArn": None,
        "DeadLetterConfig": None,
        "TracingConfig": {"Mode": "PassThrough"},
        "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
    }
    return {
        "function_name": BROKER_FUNCTION_NAME,
        "arn": function_arn,
        "create_request": create_request,
        "create_request_digest": canonical_digest(create_request),
        "signed_code": {
            "s3_bucket": signed["bucket"],
            "s3_key": signed["key"],
            "s3_object_version": signed["version_id"],
            "archive_sha256": signed["archive_sha256"],
            "lambda_code_sha256": signed["lambda_code_sha256"],
            "archive_size_bytes": signed["archive_size_bytes"],
        },
        "normalized_configuration": normalized_configuration,
        "code_signing_config_arn": parameters["BrokerCodeSigningConfigArn"],
        "code_signing_config_contract": gug363_plan[
            "artifact_signing_contract"
        ]["code_signing_config"],
        "runtime_management": {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": parameters["BrokerRuntimeVersionArn"],
        },
        "reserved_concurrent_executions": 1,
        "tags": _function_tags(gug363_plan),
        "expected_versions": ["$LATEST"],
        "expected_aliases": [],
        "expected_function_urls": [],
        "resource_policy_expected": "ABSENT_RESOURCE_NOT_FOUND",
        "execution_role_must_remain_proof_bound_until_activation": True,
        "complete_environment_configuration_deferred_to_gug357": True,
        "precreated_environment_variables": {},
        "fresh_gug357_configuration_is_not_part_of_gug365_bundle": True,
        "preexisting_mode": "STOP_NO_ADOPTION_NO_UPDATE_NO_CFN",
    }


def _ledger_factory_function_contract(
    *,
    gug363_plan: Mapping[str, Any],
    artifact_contract: Mapping[str, Any],
) -> dict[str, Any]:
    signed = artifact_contract["signed_destination"]
    code_signing = artifact_contract["code_signing_config"]
    function_arn = _ledger_factory_function_arn()
    version_arn = _ledger_factory_function_arn(version=_FACTORY_VERSION)
    code = {
        "S3Bucket": signed["bucket"],
        "S3Key": signed["key"],
        "S3ObjectVersion": signed["version_id"],
    }
    create_request = {
        "FunctionName": LEDGER_FACTORY_FUNCTION_NAME,
        "Description": "GUG-365 one-shot protected retirement ledger factory",
        "Runtime": "python3.12",
        "Role": _role_arn(LEDGER_FACTORY_ROLE_NAME),
        "Handler": ledger_factory_package.HANDLER,
        "Code": code,
        "Timeout": 120,
        "MemorySize": 256,
        "Publish": True,
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "Environment": {"Variables": {}},
        "CodeSigningConfigArn": code_signing["arn"],
        "LoggingConfig": {
            "LogFormat": "JSON",
            "ApplicationLogLevel": "ERROR",
            "SystemLogLevel": "WARN",
            "LogGroup": LEDGER_FACTORY_LOG_GROUP_NAME,
        },
        "Tags": _function_tags(gug363_plan),
    }
    normalized_configuration = {
        "FunctionName": LEDGER_FACTORY_FUNCTION_NAME,
        "FunctionArn": version_arn,
        "Runtime": "python3.12",
        "Role": _role_arn(LEDGER_FACTORY_ROLE_NAME),
        "Handler": ledger_factory_package.HANDLER,
        "CodeSize": signed["archive_size_bytes"],
        "Description": create_request["Description"],
        "Timeout": 120,
        "MemorySize": 256,
        "CodeSha256": signed["lambda_code_sha256"],
        "Version": _FACTORY_VERSION,
        "Environment": create_request["Environment"],
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
        "EphemeralStorage": {"Size": 512},
        "LoggingConfig": create_request["LoggingConfig"],
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "RuntimeVersionConfig": {
            "RuntimeVersionArn": artifact_contract["runtime_version_arn"]
        },
        "VpcConfig": {"SubnetIds": [], "SecurityGroupIds": [], "VpcId": ""},
        "Layers": [],
        "FileSystemConfigs": [],
        "KMSKeyArn": None,
        "DeadLetterConfig": None,
        "TracingConfig": {"Mode": "PassThrough"},
        "SnapStart": {"ApplyOn": "None", "OptimizationStatus": "Off"},
    }
    return {
        "function_name": LEDGER_FACTORY_FUNCTION_NAME,
        "arn": function_arn,
        "immutable_version": _FACTORY_VERSION,
        "immutable_version_arn": version_arn,
        "create_request": create_request,
        "create_request_digest": canonical_digest(create_request),
        "signed_code": {
            "s3_bucket": signed["bucket"],
            "s3_key": signed["key"],
            "s3_object_version": signed["version_id"],
            "archive_sha256": signed["archive_sha256"],
            "lambda_code_sha256": signed["lambda_code_sha256"],
            "archive_size_bytes": signed["archive_size_bytes"],
        },
        "package_manifest": artifact_contract["package_manifest"],
        "package_manifest_digest": artifact_contract["package_manifest"][
            "manifest_digest"
        ],
        "normalized_configuration": normalized_configuration,
        "code_signing_config_arn": code_signing["arn"],
        "artifact_sse_kms_key_arn": signed["sse_kms_key_arn"],
        "code_signing_config_contract": code_signing,
        "runtime_management": {
            "UpdateRuntimeOn": "Manual",
            "RuntimeVersionArn": artifact_contract["runtime_version_arn"],
            "Qualifier": _FACTORY_VERSION,
        },
        "reserved_concurrent_executions": 1,
        "tags": _function_tags(gug363_plan),
        "expected_versions": ["$LATEST", _FACTORY_VERSION],
        "expected_aliases": [],
        "expected_function_urls": [],
        "resource_policy_expected": "ABSENT_RESOURCE_NOT_FOUND",
        "execution_role_must_remain_proof_bound_until_factory_activation": True,
        "event_contract": {},
        "invocation_type": "RequestResponse",
        "sdk_retry_mode": "DISABLED_MAX_ATTEMPTS_1",
        "preexisting_mode": "STOP_NO_ADOPTION_NO_UPDATE",
    }


def _function_write_requests(
    contract: Mapping[str, Any], *, first_sequence: int
) -> list[dict[str, Any]]:
    return [
        _operation(
            sequence=first_sequence,
            action="lambda:CreateFunction",
            target_arn=str(contract["arn"]),
            request=contract["create_request"],
        ),
        _operation(
            sequence=first_sequence + 1,
            action="lambda:PutRuntimeManagementConfig",
            target_arn=str(contract["arn"]),
            request={
                "FunctionName": contract["function_name"],
                **contract["runtime_management"],
            },
        ),
        _operation(
            sequence=first_sequence + 2,
            action="lambda:PutFunctionConcurrency",
            target_arn=str(contract["arn"]),
            request={
                "FunctionName": contract["function_name"],
                "ReservedConcurrentExecutions": contract[
                    "reserved_concurrent_executions"
                ],
            },
        ),
    ]


def _ledger_factory_log_group_contract(
    gug363_plan: Mapping[str, Any],
) -> dict[str, Any]:
    tags = {**_function_tags(gug363_plan), "managed_by": "reviewed-direct-logs"}
    return {
        "log_group_name": LEDGER_FACTORY_LOG_GROUP_NAME,
        "arn": _ledger_factory_log_group_arn(),
        "retention_in_days": 365,
        "deletion_protection_enabled": True,
        "kms_key_id": None,
        "tags": tags,
        "stored_bytes": 0,
        "log_group_class": "STANDARD",
        "data_protection_policy": None,
        "inherited_properties": [],
        "preexisting_mode": "STOP_NO_ADOPTION_NO_UPDATE",
    }


def _ledger_factory_log_group_write_requests(
    contract: Mapping[str, Any], *, first_sequence: int
) -> list[dict[str, Any]]:
    tags = dict(contract["tags"])
    return [
        _operation(
            sequence=first_sequence,
            action="logs:CreateLogGroup",
            target_arn=str(contract["arn"]),
            request={
                "logGroupName": contract["log_group_name"],
                "logGroupClass": contract["log_group_class"],
                "deletionProtectionEnabled": contract[
                    "deletion_protection_enabled"
                ],
                "tags": tags,
            },
        ),
        _operation(
            sequence=first_sequence + 1,
            action="logs:PutRetentionPolicy",
            target_arn=str(contract["arn"]),
            request={
                "logGroupName": contract["log_group_name"],
                "retentionInDays": contract["retention_in_days"],
            },
        ),
    ]


def _policy_tags(gug363_plan: Mapping[str, Any]) -> list[dict[str, str]]:
    source = gug363_plan.get("source")
    if not isinstance(source, Mapping) or not isinstance(source.get("commit"), str):
        _fail("GUG363_SOURCE_INVALID")
    return [
        {"Key": "managed_by", "Value": "reviewed-direct-iam"},
        {"Key": "service", "Value": "scanalyze-platform-authority"},
        {"Key": "work_package", "Value": IMPLEMENTATION_ISSUE},
        {"Key": "environment", "Value": "non-production"},
        {"Key": "production", "Value": "false"},
        {"Key": "source_commit", "Value": str(source["commit"])},
        {
            "Key": "gug363_pre_function_binding_sha256",
            "Value": _gug363_pre_function_binding_digest(gug363_plan),
        },
    ]


def _role_tags(
    gug363_plan: Mapping[str, Any], *, role_name: str = SERVICE_ROLE_NAME
) -> list[dict[str, str]]:
    tags = _policy_tags(gug363_plan)
    if role_name not in ROLE_ORDER:
        _fail("ROLE_NAME_INVALID")
    tags.insert(
        5,
        {
            "Key": "purpose",
            "Value": "gug365-direct-iam-materialized-role",
        },
    )
    return tags


def _parameter_values(plan: Mapping[str, Any]) -> dict[str, str]:
    projection = plan.get("parameter_projection")
    if not isinstance(projection, list):
        _fail("GUG363_PARAMETER_PROJECTION_INVALID")
    result: dict[str, str] = {}
    for item in projection:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or not isinstance(item.get("ParameterKey"), str)
            or not isinstance(item.get("ParameterValue"), str)
            or item["ParameterKey"] in result
        ):
            _fail("GUG363_PARAMETER_PROJECTION_INVALID")
        result[item["ParameterKey"]] = item["ParameterValue"]
    return result


def _validate_gug363_input(
    plan: Mapping[str, Any], expected_plan_digest: str, *, repo_root: Path
) -> None:
    expected = _require_digest(
        expected_plan_digest, "EXPECTED_GUG363_PLAN_DIGEST_INVALID"
    )
    if plan.get("plan_digest") != expected:
        _fail("GUG363_PLAN_DIGEST_MISMATCH")
    try:
        gug363.validate_materialization_plan(plan, repo_root=repo_root)
    except gug363.RetirementEntrypointMaterializationError as exc:
        raise ServiceRoleMaterializationError("GUG363_PLAN_INVALID") from exc
    if (
        plan.get("implementation_issue") != SOURCE_ISSUE
        or plan.get("live_issue") != PARENT_ISSUE
        or plan.get("environment") != "synthetic-non-production"
        or plan.get("production") is not False
        or plan.get("deployment_authorized") is not False
        or plan.get("authorization_mode") != gug363.AUTHORIZATION_MODE
        or plan.get("target")
        != {
            "authority_account_id": AUTHORITY_ACCOUNT_ID,
            "region": REGION,
            "stack_name": gug363.DEDICATED_STACK_NAME,
            "cloudformation_service_role_arn": SERVICE_ROLE_ARN,
        }
    ):
        _fail("GUG363_PLAN_SCOPE_INVALID")

    parameters = _parameter_values(plan)
    contract = plan.get("artifact_signing_contract")
    if not isinstance(contract, Mapping):
        _fail("GUG363_SIGNING_CONTRACT_INVALID")
    signed = contract.get("signed_destination")
    unsigned = contract.get("unsigned_source")
    code_signing = contract.get("code_signing_config")
    if not all(isinstance(value, Mapping) for value in (signed, unsigned, code_signing)):
        _fail("GUG363_SIGNING_CONTRACT_INVALID")
    assert isinstance(signed, Mapping)
    assert isinstance(unsigned, Mapping)
    assert isinstance(code_signing, Mapping)
    if (
        signed.get("key") == unsigned.get("key")
        or "/signed/" not in str(signed.get("key"))
        or "/unsigned/" in str(signed.get("key"))
        or parameters.get("BrokerArtifactBucket") != signed.get("bucket")
        or parameters.get("BrokerArtifactKey") != signed.get("key")
        or parameters.get("BrokerArtifactVersion") != signed.get("version_id")
        or parameters.get("BrokerCodeSigningConfigArn") != code_signing.get("arn")
        or signed.get("sse_kms_key_arn") != unsigned.get("sse_kms_key_arn")
    ):
        _fail("SIGNED_ARTIFACT_BINDING_INVALID")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("BOUNDARY_TEMPLATE_DUPLICATE_KEY")
        result[key] = value
    return result


def _read_template(
    *, repo_root: Path, path: Path, replacements: Mapping[str, str]
) -> tuple[dict[str, Any], str]:
    try:
        root = Path(repo_root).resolve(strict=True)
        absolute = root / path
        if absolute.is_symlink() or not absolute.is_file():
            raise OSError
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        committed = subprocess.run(
            ["git", "show", f"{head}:{path.as_posix()}"],
            cwd=root,
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        raw_bytes = absolute.read_bytes()
        if raw_bytes != committed:
            _fail("POLICY_TEMPLATE_COMMIT_DRIFT")
        raw = committed.decode("utf-8")
    except ServiceRoleMaterializationError:
        raise
    except (OSError, UnicodeError, subprocess.SubprocessError):
        _fail("BOUNDARY_TEMPLATE_UNAVAILABLE")
    placeholders = frozenset(_PLACEHOLDER_RE.findall(raw))
    expected = frozenset(f"${{{key}}}" for key in replacements)
    if placeholders != expected:
        _fail("BOUNDARY_TEMPLATE_PLACEHOLDER_INVALID")
    for key, value in replacements.items():
        raw = raw.replace(f"${{{key}}}", value)
    if "${" in raw:
        _fail("BOUNDARY_TEMPLATE_PLACEHOLDER_INVALID")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_pairs)
    except json.JSONDecodeError:
        _fail("BOUNDARY_TEMPLATE_INVALID")
    if not isinstance(document, dict):
        _fail("BOUNDARY_TEMPLATE_INVALID")
    return document, _byte_digest(committed)


def _strings(value: object, code: str) -> tuple[str, ...]:
    values = (value,) if isinstance(value, str) else value
    if (
        not isinstance(values, (list, tuple))
        or not values
        or not all(isinstance(item, str) and item for item in values)
    ):
        _fail(code)
    return tuple(values)


def _statements(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if set(document) != {"Version", "Statement"} or document.get("Version") != "2012-10-17":
        _fail("BOUNDARY_DOCUMENT_INVALID")
    statements = document.get("Statement")
    if (
        not isinstance(statements, list)
        or not statements
        or not all(isinstance(item, Mapping) for item in statements)
    ):
        _fail("BOUNDARY_DOCUMENT_INVALID")
    return list(statements)


def _validate_document_shape(
    key: str, document: Mapping[str, Any], *, exact_arns: Sequence[str]
) -> None:
    encoded = canonical_json(document).encode("utf-8")
    if len(encoded) > _POLICY_MAX_NON_WHITESPACE_BYTES:
        _fail("BOUNDARY_DOCUMENT_TOO_LARGE")
    statements = _statements(document)
    seen_sids: set[str] = set()
    for statement in statements:
        allowed_keys = {
            "Sid",
            "Effect",
            "Action",
            "NotAction",
            "Resource",
            "NotResource",
            "Condition",
        }
        action_key = "Action" if "Action" in statement else "NotAction"
        resource_key = "Resource" if "Resource" in statement else "NotResource"
        if (
            not set(statement).issubset(allowed_keys)
            or not {"Sid", "Effect"}.issubset(statement)
            or ("Action" in statement) == ("NotAction" in statement)
            or ("Resource" in statement) == ("NotResource" in statement)
            or not isinstance(statement.get("Sid"), str)
            or statement["Sid"] in seen_sids
            or statement.get("Effect") not in {"Allow", "Deny"}
        ):
            _fail("BOUNDARY_STATEMENT_INVALID")
        seen_sids.add(str(statement["Sid"]))
        actions = _strings(statement.get(action_key), "BOUNDARY_ACTION_INVALID")
        resources = _strings(statement.get(resource_key), "BOUNDARY_RESOURCE_INVALID")
        if statement.get("Effect") == "Allow":
            if action_key != "Action" or resource_key != "Resource":
                _fail("BOUNDARY_STATEMENT_INVALID")
            if any("*" in action or "?" in action for action in actions):
                _fail("BOUNDARY_ALLOW_ACTION_WILDCARD")
            if key in CHILD_BOUNDARY_ALLOWED_ACTIONS and not set(actions).issubset(
                CHILD_BOUNDARY_ALLOWED_ACTIONS[key]
            ):
                _fail("BOUNDARY_ALLOW_ACTION_OUT_OF_SCOPE")
            for resource in resources:
                if resource == "*" and (
                    key not in {"broker", "service_role", "ledger_factory"}
                    or statement.get("Sid")
                    not in (
                        {str(statement.get("Sid"))}
                        if key == "service_role"
                        else {
                            "ConfirmDedicatedFactoryCallerIdentity",
                            "ReadOnlyAwsManagedDynamoDbKeyMetadata",
                        }
                        if key == "ledger_factory"
                        else {
                        "ReadAccountPublicAccessBlockOnly",
                        "ReadOnlyLedgerAwsOwnedKmsKey",
                        }
                    )
                ):
                    _fail("BOUNDARY_ALLOW_RESOURCE_WILDCARD")
                if resource != "*" and not any(
                    resource == arn or resource.startswith(arn.rstrip("*") )
                    for arn in exact_arns
                ):
                    _fail("BOUNDARY_RESOURCE_OUT_OF_SCOPE")
        elif (action_key == "NotAction" or resource_key == "NotResource") and key != "ledger_factory":
            _fail("BOUNDARY_STATEMENT_INVALID")
        condition = statement.get("Condition")
        if condition is not None and not isinstance(condition, Mapping):
            _fail("BOUNDARY_CONDITION_INVALID")
    if key == "proof":
        if document != {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyEveryProofSessionAction",
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }:
            _fail("PROOF_BOUNDARY_NOT_DENY_ALL")


def cloudformation_trust_policy() -> dict[str, Any]:
    """Return the only trust relationship accepted for the service role."""

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudFormationOnly",
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _lambda_trust_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _invoker_trust_policy(permission_set_role_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeFromExactPermissionSet",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:root"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "ArnEquals": {"aws:PrincipalArn": permission_set_role_arn}
                },
            }
        ],
    }


def _proof_trust_policy(
    *,
    identity_store_user_id: str,
    identity_store_arn: str,
    identity_center_instance_arn: str,
    identity_center_application_arn: str,
    trust_sid: str,
) -> dict[str, Any]:
    root = f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:root"
    broker_arn = _role_arn(BROKER_ROLE_NAME)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeFromExactBroker",
                "Effect": "Allow",
                "Principal": {"AWS": root},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnEquals": {"aws:PrincipalArn": broker_arn}},
            },
            {
                "Sid": trust_sid,
                "Effect": "Allow",
                "Principal": {"AWS": root},
                "Action": "sts:SetContext",
                "Condition": {
                    "ForAllValues:ArnEquals": {
                        "sts:RequestContextProviders": [
                            "arn:aws:iam::aws:contextProvider/IdentityCenter"
                        ]
                    },
                    "StringEquals": {
                        "sts:RequestContext/identitystore:UserId": (
                            identity_store_user_id
                        )
                    },
                    "ArnEquals": {
                        "aws:PrincipalArn": broker_arn,
                        "sts:RequestContext/identitystore:IdentityStoreArn": (
                            identity_store_arn
                        ),
                        "sts:RequestContext/identitycenter:InstanceArn": (
                            identity_center_instance_arn
                        ),
                        "sts:RequestContext/identitycenter:ApplicationArn": (
                            identity_center_application_arn
                        ),
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


def _service_role_permissions_policy(
    *, bindings: Mapping[str, str], boundary_arns: Mapping[str, str]
) -> dict[str, Any]:
    account = bindings["authority_account_id"]
    region = bindings["region"]
    function_arn = bindings["broker_function_arn"]
    log_arn = f"arn:{PARTITION}:logs:{region}:{account}:log-group:{LOG_GROUP_NAME}"
    classifier_arn = f"{function_arn}:single-classify"
    approver_arns = [
        f"{function_arn}:single-retire",
        f"{function_arn}:single-reconcile",
    ]

    statements: list[dict[str, Any]] = [
        {
            "Sid": "ListBrokerLogs",
            "Effect": "Allow",
            "Action": "logs:DescribeLogGroups",
            "Resource": "*",
        },
        {
            "Sid": "ManageBrokerLog",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:ListTagsForResource",
                "logs:PutRetentionPolicy",
                "logs:TagResource",
            ],
            "Resource": [log_arn, f"{log_arn}:*"],
        },
        {
            "Sid": "ManageBrokerGraph",
            "Effect": "Allow",
            "Action": [
                "lambda:CreateAlias",
                "lambda:GetAlias",
                "lambda:GetFunction",
                "lambda:GetFunctionCodeSigningConfig",
                "lambda:GetFunctionConcurrency",
                "lambda:GetFunctionConfiguration",
                "lambda:GetFunctionUrlConfig",
                "lambda:GetPolicy",
                "lambda:GetRuntimeManagementConfig",
                "lambda:ListAliases",
                "lambda:ListFunctionUrlConfigs",
                "lambda:ListTags",
                "lambda:ListVersionsByFunction",
                "lambda:PublishVersion",
            ],
            "Resource": [function_arn, f"{function_arn}:*"],
        },
    ]
    statements.extend(
        [
            {
                "Sid": "CreateIamUrls",
                "Effect": "Allow",
                "Action": "lambda:CreateFunctionUrlConfig",
                "Resource": [classifier_arn, *approver_arns],
                "Condition": {
                    "StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}
                },
            },
            {
                "Sid": "AllowClassifierUrl",
                "Effect": "Allow",
                "Action": "lambda:AddPermission",
                "Resource": classifier_arn,
                "Condition": {
                    "StringEquals": {
                        "lambda:Principal": _role_arn(CLASSIFIER_ROLE_NAME),
                        "lambda:FunctionUrlAuthType": "AWS_IAM",
                    }
                },
            },
            {
                "Sid": "AllowClassifierViaUrl",
                "Effect": "Allow",
                "Action": "lambda:AddPermission",
                "Resource": classifier_arn,
                "Condition": {
                    "StringEquals": {
                        "lambda:Principal": _role_arn(CLASSIFIER_ROLE_NAME)
                    },
                    "Bool": {"lambda:InvokedViaFunctionUrl": "true"},
                },
            },
            {
                "Sid": "AllowApproverUrls",
                "Effect": "Allow",
                "Action": "lambda:AddPermission",
                "Resource": approver_arns,
                "Condition": {
                    "StringEquals": {
                        "lambda:Principal": _role_arn(APPROVER_ROLE_NAME),
                        "lambda:FunctionUrlAuthType": "AWS_IAM",
                    }
                },
            },
            {
                "Sid": "AllowApproverViaUrls",
                "Effect": "Allow",
                "Action": "lambda:AddPermission",
                "Resource": approver_arns,
                "Condition": {
                    "StringEquals": {
                        "lambda:Principal": _role_arn(APPROVER_ROLE_NAME)
                    },
                    "Bool": {"lambda:InvokedViaFunctionUrl": "true"},
                },
            },
        ]
    )
    return {"Version": "2012-10-17", "Statement": statements}


def _render_bindings(plan: Mapping[str, Any]) -> dict[str, str]:
    parameters = _parameter_values(plan)
    contract = plan["artifact_signing_contract"]
    signed = contract["signed_destination"]
    code_signing = contract["code_signing_config"]
    base_function = (
        f"arn:{PARTITION}:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:function:"
        f"{BROKER_FUNCTION_NAME}"
    )
    if plan.get("authorization_mode") == "SINGLE_OPERATOR_NONPROD_EXCEPTION":
        classifier_suffix = "single-classify"
        approver_suffixes = ("single-retire", "single-reconcile")
    else:
        _fail("GUG363_AUTHORIZATION_MODE_INVALID")
    bindings = {
        "aws_partition": PARTITION,
        "region": REGION,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "change_set_name": parameters["ChangeSetName"],
        "retirement_id": parameters["RetirementId"],
        "identity_center_application_arn": parameters[
            "IdentityCenterApplicationArn"
        ],
        "broker_function_arn": base_function,
        "classifier_function_arn": f"{base_function}:{classifier_suffix}",
        "approver_retire_function_arn": f"{base_function}:{approver_suffixes[0]}",
        "approver_reconcile_function_arn": f"{base_function}:{approver_suffixes[1]}",
        "signed_bucket": str(signed["bucket"]),
        "signed_key": str(signed["key"]),
        "signed_version_id": str(signed["version_id"]),
        "signed_kms_key_arn": str(signed["sse_kms_key_arn"]),
        "code_signing_config_arn": str(code_signing["arn"]),
    }
    if (
        _S3_BUCKET_RE.fullmatch(bindings["signed_bucket"]) is None
        or not bindings["signed_key"].startswith(
            "scanalyze/platform-authority/gug-215/signed/"
        )
        or _VERSION_RE.fullmatch(bindings["signed_version_id"]) is None
        or bindings["broker_function_arn"].count(":") != 6
    ):
        _fail("RENDER_BINDING_INVALID")
    return bindings


def _render_boundaries(
    *, gug363_plan: Mapping[str, Any], repo_root: Path
) -> list[dict[str, Any]]:
    bindings = _render_bindings(gug363_plan)
    boundary_arns = {key: _policy_arn(name) for key, name in BOUNDARY_NAMES.items()}
    service_permissions = _service_role_permissions_policy(
        bindings=bindings, boundary_arns=boundary_arns
    )
    documents: dict[str, dict[str, Any]] = {
        "service_role": service_permissions
    }
    template_digests: dict[str, str | None] = {"service_role": None}
    replacements = {
        "broker": {
            key: bindings[key]
            for key in (
                "aws_partition",
                "region",
                "authority_account_id",
                "change_set_name",
                "retirement_id",
                "identity_center_application_arn",
                "broker_function_arn",
            )
        },
        "classifier_invoker": {
            "classifier_function_arn": bindings["classifier_function_arn"]
        },
        "approver_invoker": {
            "approver_retire_function_arn": bindings[
                "approver_retire_function_arn"
            ],
            "approver_reconcile_function_arn": bindings[
                "approver_reconcile_function_arn"
            ],
        },
        "proof": {},
        "ledger_factory": {
            "ledger_table_arn": _table_arn(),
            "ledger_factory_log_stream_arn": _ledger_factory_log_stream_arn(),
        },
    }
    for key in BOUNDARY_ORDER[1:]:
        document, template_digest = _read_template(
            repo_root=repo_root,
            path=BOUNDARY_TEMPLATE_PATHS[key],
            replacements=replacements[key],
        )
        documents[key] = document
        template_digests[key] = template_digest

    exact_arns = (
        f"arn:{PARTITION}:cloudformation:{REGION}:{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:iam::{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:kms:{REGION}:{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:lambda:{REGION}:{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:logs:{REGION}:{AUTHORITY_ACCOUNT_ID}:",
        f"arn:{PARTITION}:s3:::{bindings['signed_bucket']}/",
        f"arn:{PARTITION}:sso::{AUTHORITY_ACCOUNT_ID}:",
    )
    boundaries: list[dict[str, Any]] = []
    for key in BOUNDARY_ORDER:
        document = documents[key]
        _validate_document_shape(key, document, exact_arns=exact_arns)
        boundaries.append(
            {
                "key": key,
                "policy_name": BOUNDARY_NAMES[key],
                "path": MANAGED_POLICY_PATH,
                "arn": boundary_arns[key],
                "description": (
                    f"GUG-365 exact {key.replace('_', ' ')} permissions boundary"
                ),
                "tags": _policy_tags(gug363_plan),
                "document": document,
                "document_digest": canonical_digest(document),
                "template_path": (
                    None
                    if key == "service_role"
                    else BOUNDARY_TEMPLATE_PATHS[key].as_posix()
                ),
                "template_sha256": template_digests[key],
            }
        )
    return boundaries


def _child_role_contracts(
    *, gug363_plan: Mapping[str, Any], boundaries: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    parameters = _parameter_values(gug363_plan)
    documents = {str(item["key"]): item["document"] for item in boundaries}
    boundary_arns = {str(item["key"]): str(item["arn"]) for item in boundaries}
    proof_document = documents["proof"]
    definitions = (
        (
            BROKER_ROLE_NAME,
            "broker",
            _lambda_trust_policy(),
            documents["broker"],
            "ExpectedBrokerPolicySha256",
        ),
        (
            CLASSIFIER_ROLE_NAME,
            "classifier_invoker",
            _invoker_trust_policy(parameters["ClassifierPermissionSetRoleArn"]),
            documents["classifier_invoker"],
            "ClassifierInvokerPolicySha256",
        ),
        (
            APPROVER_ROLE_NAME,
            "approver_invoker",
            _invoker_trust_policy(parameters["ApproverPermissionSetRoleArn"]),
            documents["approver_invoker"],
            "ApproverInvokerPolicySha256",
        ),
        (
            CLASSIFIER_PROOF_ROLE_NAME,
            "proof",
            _proof_trust_policy(
                identity_store_user_id=parameters["ClassifierIdentityStoreUserId"],
                identity_store_arn=parameters["IdentityStoreArn"],
                identity_center_instance_arn=parameters[
                    "IdentityCenterInstanceArn"
                ],
                identity_center_application_arn=parameters[
                    "IdentityCenterApplicationArn"
                ],
                trust_sid="SetExactClassifierIdentityContext",
            ),
            proof_document,
            "ClassifierProofPolicySha256",
        ),
        (
            APPROVER_PROOF_ROLE_NAME,
            "proof",
            _proof_trust_policy(
                identity_store_user_id=parameters["ApproverIdentityStoreUserId"],
                identity_store_arn=parameters["IdentityStoreArn"],
                identity_center_instance_arn=parameters[
                    "IdentityCenterInstanceArn"
                ],
                identity_center_application_arn=parameters[
                    "IdentityCenterApplicationArn"
                ],
                trust_sid="SetExactApproverIdentityContext",
            ),
            proof_document,
            "ApproverProofPolicySha256",
        ),
        (
            LEDGER_FACTORY_ROLE_NAME,
            "proof",
            _lambda_trust_policy(),
            documents["ledger_factory"],
            None,
        ),
    )
    contracts: list[dict[str, Any]] = []
    for (
        role_name,
        boundary_key,
        trust_policy,
        policy_document,
        plan_digest_key,
    ) in definitions:
        policy_digest = canonical_digest(policy_document)
        if (
            plan_digest_key is not None
            and parameters[plan_digest_key] != policy_digest
        ):
            _fail("CHILD_ROLE_POLICY_PLAN_DIGEST_MISMATCH")
        is_factory = role_name == LEDGER_FACTORY_ROLE_NAME
        contracts.append(
            {
                "role_name": role_name,
                "arn": _role_arn(role_name),
                "path": "/",
                "max_session_duration": 3600,
                "trust_policy": trust_policy,
                "trust_policy_digest": canonical_digest(trust_policy),
                "permissions_boundary_arn": boundary_arns[boundary_key],
                "boundary_key": boundary_key,
                "attached_policy_arns": (
                    [] if is_factory else [boundary_arns[boundary_key]]
                ),
                "inline_policy_names": [],
                "managed_policy_document_digest": policy_digest,
                "gug363_parameter_digest_key": plan_digest_key,
                "activation_policy_arn": (
                    boundary_arns["ledger_factory"] if is_factory else None
                ),
                "activation_permissions_boundary_arn": (
                    boundary_arns["ledger_factory"] if is_factory else None
                ),
                "final_state_after_one_shot": (
                    "PROOF_BOUND_DETACHED" if is_factory else "ACTIVE_EXACT"
                ),
                "tags": _role_tags(gug363_plan, role_name=role_name),
            }
        )
    return contracts


def _request_tag_condition(tags: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    keys = [str(tag["Key"]) for tag in tags]
    return {
        "StringEquals": {
            f"aws:RequestTag/{tag['Key']}": str(tag["Value"])
            for tag in tags
        },
        "ForAllValues:StringEquals": {"aws:TagKeys": keys},
    }


def _statement_for_actions(
    statements: Sequence[Mapping[str, Any]], actions: set[str]
) -> Mapping[str, Any]:
    matches = [
        statement
        for statement in statements
        if statement.get("Effect") == "Allow"
        and set(_strings(statement.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID"))
        == actions
    ]
    if len(matches) != 1:
        _fail("PROVISIONING_EXECUTOR_STATEMENT_INVALID")
    return matches[0]


def _validate_executor_conditions(
    *,
    phase: str,
    statements: Sequence[Mapping[str, Any]],
    gug363_plan: Mapping[str, Any],
    boundary_arns: Mapping[str, str],
    factory_function: Mapping[str, Any],
) -> None:
    policy_arns = set(boundary_arns.values())
    role_arns = {_role_arn(name) for name in ROLE_ORDER}
    caller_matches = [
        statement
        for statement in statements
        if statement.get("Effect") == "Allow"
        and "sts:GetCallerIdentity"
        in _strings(
            statement.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID"
        )
    ]
    if len(caller_matches) != 1:
        _fail("PROVISIONING_EXECUTOR_IDENTITY_CHECK_INVALID")
    caller = caller_matches[0]
    if caller.get("Resource") != "*" or "Condition" in caller:
        _fail("PROVISIONING_EXECUTOR_IDENTITY_CHECK_INVALID")
    caller_actions = set(
        _strings(caller.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID")
    )
    if caller_actions != (
        {"sts:GetCallerIdentity", "logs:DescribeLogGroups"}
        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
        else {"sts:GetCallerIdentity"}
    ):
        _fail("PROVISIONING_EXECUTOR_IDENTITY_CHECK_INVALID")
    if phase == "POLICY_FACTORY":
        create = _statement_for_actions(
            statements, {"iam:CreatePolicy", "iam:TagPolicy"}
        )
        reads = _statement_for_actions(
            statements,
            {
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListEntitiesForPolicy",
                "iam:ListPolicyTags",
                "iam:ListPolicyVersions",
            },
        )
        if (
            set(_strings(create.get("Resource"), "PROVISIONING_EXECUTOR_RESOURCE_INVALID"))
            != policy_arns
            or create.get("Condition") != _request_tag_condition(_policy_tags(gug363_plan))
            or set(_strings(reads.get("Resource"), "PROVISIONING_EXECUTOR_RESOURCE_INVALID"))
            != policy_arns
            or "Condition" in reads
        ):
            _fail("PROVISIONING_EXECUTOR_POLICY_FACTORY_CONDITION_INVALID")
    elif phase == "FOUNDATION_FACTORY":
        create_roles = _statement_for_actions(
            statements, {"iam:CreateRole", "iam:TagRole"}
        )
        expected_role_condition = _request_tag_condition(
            _role_tags(gug363_plan)
        )
        expected_role_condition["ArnEquals"] = {
            "iam:PermissionsBoundary": boundary_arns["proof"]
        }
        if (
            set(_strings(create_roles.get("Resource"), "PROVISIONING_EXECUTOR_RESOURCE_INVALID"))
            != role_arns
            or create_roles.get("Condition") != expected_role_condition
        ):
            _fail("PROVISIONING_EXECUTOR_FOUNDATION_CONDITION_INVALID")
    elif phase in {"FUNCTION_FACTORY", "LEDGER_FACTORY_FUNCTION_FACTORY"}:
        bindings = _render_bindings(gug363_plan)
        request_tags = _function_tags(gug363_plan)
        tag_condition = {
            "StringEquals": {
                f"aws:RequestTag/{key}": value
                for key, value in request_tags.items()
            },
            "ForAllValues:StringEquals": {
                "aws:TagKeys": list(request_tags)
            },
        }
        def exact_statement(
            *, actions: set[str], resource: object
        ) -> Mapping[str, Any]:
            matches = [
                statement
                for statement in statements
                if statement.get("Effect") == "Allow"
                and set(
                    _strings(
                        statement.get("Action"),
                        "PROVISIONING_EXECUTOR_ACTION_INVALID",
                    )
                )
                == actions
                and statement.get("Resource") == resource
            ]
            if len(matches) != 1:
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
            return matches[0]

        expected = (
            (
                _role_arn(BROKER_ROLE_NAME),
                _function_arn(),
            ),
            (
                _role_arn(LEDGER_FACTORY_ROLE_NAME),
                _ledger_factory_function_arn(),
            ),
        )
        expected = expected[:1] if phase == "FUNCTION_FACTORY" else expected[1:]
        for role_arn, function_arn in expected:
            statement = exact_statement(
                actions={"iam:PassRole"}, resource=role_arn
            )
            if (
                statement.get("Resource") != role_arn
                or statement.get("Condition")
                != {
                    "StringEquals": {
                        "iam:PassedToService": "lambda.amazonaws.com"
                    },
                    "ArnEquals": {"iam:AssociatedResourceArn": function_arn},
                }
            ):
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
        create_targets = (
            (
                _function_arn(),
                bindings["code_signing_config_arn"],
            ),
            (
                _ledger_factory_function_arn(),
                factory_function["code_signing_config_arn"],
            ),
        )
        create_targets = (
            create_targets[:1]
            if phase == "FUNCTION_FACTORY"
            else create_targets[1:]
        )
        for function_arn, csc_arn in create_targets:
            create_condition = {
                "ArnEquals": {"lambda:CodeSigningConfigArn": csc_arn},
                **tag_condition,
                "Null": {
                    "lambda:Layer": "true",
                    "lambda:VpcIds": "true",
                    "lambda:SubnetIds": "true",
                    "lambda:SecurityGroupIds": "true",
                },
            }
            statement = exact_statement(
                actions={"lambda:CreateFunction"}, resource=function_arn
            )
            if (
                statement.get("Resource") != function_arn
                or statement.get("Condition") != create_condition
            ):
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
        artifact_targets = (
            (
                f"arn:{PARTITION}:s3:::{bindings['signed_bucket']}/{bindings['signed_key']}",
                bindings["signed_version_id"],
            ),
            (
                f"arn:{PARTITION}:s3:::{factory_function['signed_code']['s3_bucket']}/"
                f"{factory_function['signed_code']['s3_key']}",
                factory_function["signed_code"]["s3_object_version"],
            ),
        )
        artifact_targets = (
            artifact_targets[:1]
            if phase == "FUNCTION_FACTORY"
            else artifact_targets[1:]
        )
        for resource, version_id in artifact_targets:
            statement = exact_statement(
                actions={"s3:GetObjectVersion"}, resource=resource
            )
            if (
                statement.get("Resource") != resource
                or statement.get("Condition")
                != {
                    "StringEquals": {
                        "s3:VersionId": version_id,
                        "s3:ResourceAccount": AUTHORITY_ACCOUNT_ID,
                    }
                }
            ):
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY":
            factory_lambda_actions = {
                "lambda:PutFunctionConcurrency",
                "lambda:PutRuntimeManagementConfig",
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
                "lambda:GetCodeSigningConfig",
            }
            factory_lambda = _statement_for_actions(
                statements, factory_lambda_actions
            )
            if (
                set(
                    _strings(
                        factory_lambda.get("Resource"),
                        "PROVISIONING_EXECUTOR_RESOURCE_INVALID",
                    )
                )
                != {
                    _ledger_factory_function_arn(),
                    _ledger_factory_function_arn(version=_FACTORY_VERSION),
                    str(factory_function["code_signing_config_arn"]),
                }
                or "Condition" in factory_lambda
            ):
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
            log_group_arn = _ledger_factory_log_group_arn()
            log_tag_condition = {
                "StringEquals": {
                    f"aws:RequestTag/{key}": value
                    for key, value in _ledger_factory_log_group_contract(
                        gug363_plan
                    )["tags"].items()
                },
                "ForAllValues:StringEquals": {
                    "aws:TagKeys": list(
                        _ledger_factory_log_group_contract(gug363_plan)[
                            "tags"
                        ]
                    )
                },
            }
            create_log = exact_statement(
                actions={"logs:CreateLogGroup", "logs:TagResource"},
                resource=log_group_arn,
            )
            retention = exact_statement(
                actions={"logs:PutRetentionPolicy", "logs:ListTagsForResource"},
                resource=log_group_arn,
            )
            if (
                create_log.get("Condition") != log_tag_condition
                or "Condition" in retention
            ):
                _fail("PROVISIONING_EXECUTOR_FUNCTION_CONDITION_INVALID")
    elif phase == "ACTIVATOR":
        final_for_role = {
            SERVICE_ROLE_NAME: boundary_arns["service_role"],
            BROKER_ROLE_NAME: boundary_arns["broker"],
            CLASSIFIER_ROLE_NAME: boundary_arns["classifier_invoker"],
            APPROVER_ROLE_NAME: boundary_arns["approver_invoker"],
            CLASSIFIER_PROOF_ROLE_NAME: boundary_arns["proof"],
            APPROVER_PROOF_ROLE_NAME: boundary_arns["proof"],
        }
        attach_statements = [
            statement
            for statement in statements
            if statement.get("Effect") == "Allow"
            and set(_strings(statement.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID"))
            == {"iam:AttachRolePolicy"}
        ]
        put_statements = [
            statement
            for statement in statements
            if statement.get("Effect") == "Allow"
            and set(_strings(statement.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID"))
            == {"iam:PutRolePermissionsBoundary"}
        ]
        expected_attach = {
            (
                _role_arn(role_name),
                canonical_json(
                    {
                        "ArnEquals": {
                            "iam:PermissionsBoundary": boundary_arns["proof"],
                            "iam:PolicyARN": policy_arn,
                        }
                    }
                ),
            )
            for role_name, policy_arn in final_for_role.items()
        }
        observed_attach = {
            (str(statement.get("Resource")), canonical_json(statement.get("Condition")))
            for statement in attach_statements
        }
        expected_put = {
            (
                _role_arn(role_name),
                canonical_json(
                    {"ArnEquals": {"iam:PermissionsBoundary": policy_arn}}
                ),
            )
            for role_name, policy_arn in final_for_role.items()
            if role_name
            not in {CLASSIFIER_PROOF_ROLE_NAME, APPROVER_PROOF_ROLE_NAME}
        }
        observed_put = {
            (str(statement.get("Resource")), canonical_json(statement.get("Condition")))
            for statement in put_statements
        }
        if observed_attach != expected_attach or observed_put != expected_put:
            _fail("PROVISIONING_EXECUTOR_ACTIVATOR_CONDITION_INVALID")
    elif phase in {
        "LEDGER_FACTORY_ACTIVATOR",
        "LEDGER_FACTORY_INVOKER",
        "LEDGER_FACTORY_REVOKER",
    }:
        by_sid = {str(item.get("Sid")): item for item in statements}
        factory_role_arn = _role_arn(LEDGER_FACTORY_ROLE_NAME)
        if phase == "LEDGER_FACTORY_ACTIVATOR":
            attach = by_sid.get("AttachExactFactoryPolicyWhileProofBound", {})
            put = by_sid.get("ActivateExactFactoryBoundaryLast", {})
            if (
                attach.get("Resource") != factory_role_arn
                or attach.get("Condition")
                != {
                    "ArnEquals": {
                        "iam:PermissionsBoundary": boundary_arns["proof"],
                        "iam:PolicyARN": boundary_arns["ledger_factory"],
                    }
                }
                or put.get("Resource") != factory_role_arn
                or put.get("Condition")
                != {
                    "ArnEquals": {
                        "iam:PermissionsBoundary": boundary_arns[
                            "ledger_factory"
                        ]
                    }
                }
            ):
                _fail("PROVISIONING_EXECUTOR_LEDGER_ACTIVATOR_INVALID")
        elif phase == "LEDGER_FACTORY_INVOKER":
            invoke = by_sid.get("InvokeOnlyExactQualifiedFactoryVersion", {})
            scan = by_sid.get("CountOnlyExactLedgerCertification", {})
            if (
                invoke.get("Resource")
                != factory_function["immutable_version_arn"]
                or scan.get("Resource") != _table_arn()
                or scan.get("Condition")
                != {"StringEquals": {"dynamodb:Select": "COUNT"}}
            ):
                _fail("PROVISIONING_EXECUTOR_LEDGER_INVOKER_INVALID")
        else:
            put = by_sid.get("RevokeFactoryToProofBoundaryFirst", {})
            detach = by_sid.get("DetachFactoryPolicyOnlyAfterProofBoundary", {})
            if (
                put.get("Resource") != factory_role_arn
                or put.get("Condition")
                != {
                    "ArnEquals": {
                        "iam:PermissionsBoundary": boundary_arns["proof"]
                    }
                }
                or detach.get("Resource") != factory_role_arn
                or detach.get("Condition")
                != {
                    "ArnEquals": {
                        "iam:PermissionsBoundary": boundary_arns["proof"],
                        "iam:PolicyARN": boundary_arns["ledger_factory"],
                    }
                }
            ):
                _fail("PROVISIONING_EXECUTOR_LEDGER_REVOKER_INVALID")
    elif phase == "REVOCATOR":
        proof_reads = _statement_for_actions(
            statements,
            {
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListEntitiesForPolicy",
                "iam:ListPolicyVersions",
            },
        )
        put = _statement_for_actions(
            statements, {"iam:PutRolePermissionsBoundary"}
        )
        expected_roles = {
            SERVICE_ROLE_ARN,
            _role_arn(BROKER_ROLE_NAME),
            _role_arn(CLASSIFIER_ROLE_NAME),
            _role_arn(APPROVER_ROLE_NAME),
        }
        if (
            proof_reads.get("Resource") != boundary_arns["proof"]
            or "Condition" in proof_reads
            or set(_strings(put.get("Resource"), "PROVISIONING_EXECUTOR_RESOURCE_INVALID"))
            != expected_roles
            or put.get("Condition")
            != {"ArnEquals": {"iam:PermissionsBoundary": boundary_arns["proof"]}}
        ):
            _fail("PROVISIONING_EXECUTOR_REVOCATOR_CONDITION_INVALID")


def _render_executor_policy(
    *,
    phase: str,
    gug363_plan: Mapping[str, Any],
    repo_root: Path,
    boundaries: Sequence[Mapping[str, Any]],
    factory_function: Mapping[str, Any],
) -> dict[str, Any]:
    boundary_arns = {str(item["key"]): str(item["arn"]) for item in boundaries}
    source = gug363_plan.get("source")
    if not isinstance(source, Mapping):
        _fail("GUG363_SOURCE_INVALID")
    all_replacements = {
        "service_role_boundary_arn": boundary_arns["service_role"],
        "broker_boundary_arn": boundary_arns["broker"],
        "classifier_boundary_arn": boundary_arns["classifier_invoker"],
        "approver_boundary_arn": boundary_arns["approver_invoker"],
        "proof_boundary_arn": boundary_arns["proof"],
        "ledger_factory_boundary_arn": boundary_arns["ledger_factory"],
        "service_role_arn": SERVICE_ROLE_ARN,
        "broker_role_arn": _role_arn(BROKER_ROLE_NAME),
        "classifier_role_arn": _role_arn(CLASSIFIER_ROLE_NAME),
        "approver_role_arn": _role_arn(APPROVER_ROLE_NAME),
        "classifier_proof_role_arn": _role_arn(CLASSIFIER_PROOF_ROLE_NAME),
        "approver_proof_role_arn": _role_arn(APPROVER_PROOF_ROLE_NAME),
        "ledger_factory_role_arn": _role_arn(LEDGER_FACTORY_ROLE_NAME),
        "ledger_table_arn": _table_arn(),
        "broker_function_arn": _function_arn(),
        "ledger_factory_function_arn": _ledger_factory_function_arn(),
        "ledger_factory_function_version_arn": (
            _ledger_factory_function_arn(version=_FACTORY_VERSION)
        ),
        "ledger_factory_log_group_arn": _ledger_factory_log_group_arn(),
        "signed_object_arn": (
            f"arn:{PARTITION}:s3:::{_render_bindings(gug363_plan)['signed_bucket']}/"
            f"{_render_bindings(gug363_plan)['signed_key']}"
        ),
        "signed_bucket_arn": (
            f"arn:{PARTITION}:s3:::{_render_bindings(gug363_plan)['signed_bucket']}"
        ),
        "signed_version_id": _render_bindings(gug363_plan)["signed_version_id"],
        "signed_kms_key_arn": _render_bindings(gug363_plan)["signed_kms_key_arn"],
        "code_signing_config_arn": _render_bindings(gug363_plan)[
            "code_signing_config_arn"
        ],
        "ledger_factory_signed_object_arn": (
            f"arn:{PARTITION}:s3:::{factory_function['signed_code']['s3_bucket']}/"
            f"{factory_function['signed_code']['s3_key']}"
        ),
        "ledger_factory_signed_bucket_arn": (
            f"arn:{PARTITION}:s3:::{factory_function['signed_code']['s3_bucket']}"
        ),
        "ledger_factory_signed_version_id": factory_function["signed_code"][
            "s3_object_version"
        ],
        "ledger_factory_signed_kms_key_arn": factory_function[
            "artifact_sse_kms_key_arn"
        ],
        "ledger_factory_code_signing_config_arn": factory_function[
            "code_signing_config_arn"
        ],
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "source_commit": str(source.get("commit")),
        "gug363_pre_function_binding_sha256": (
            _gug363_pre_function_binding_digest(gug363_plan)
        ),
    }
    paths = {
        "POLICY_FACTORY": POLICY_FACTORY_POLICY_PATH,
        "FOUNDATION_FACTORY": FOUNDATION_FACTORY_POLICY_PATH,
        "FUNCTION_FACTORY": FUNCTION_FACTORY_POLICY_PATH,
        "LEDGER_FACTORY_FUNCTION_FACTORY": (
            LEDGER_FACTORY_FUNCTION_FACTORY_POLICY_PATH
        ),
        "ACTIVATOR": ACTIVATOR_POLICY_PATH,
        "REVOCATOR": REVOCATOR_POLICY_PATH,
        "LEDGER_FACTORY_ACTIVATOR": LEDGER_FACTORY_ACTIVATOR_POLICY_PATH,
        "LEDGER_FACTORY_INVOKER": LEDGER_FACTORY_INVOKER_POLICY_PATH,
        "LEDGER_FACTORY_REVOKER": LEDGER_FACTORY_REVOKER_POLICY_PATH,
    }
    allowed_by_phase = {
        "POLICY_FACTORY": {
            "sts:GetCallerIdentity",
            "iam:CreatePolicy",
            "iam:TagPolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyTags",
            "iam:ListPolicyVersions",
        },
        "FOUNDATION_FACTORY": {
            "sts:GetCallerIdentity",
            "iam:CreateRole",
            "iam:TagRole",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
        },
        "FUNCTION_FACTORY": {
            "sts:GetCallerIdentity",
            "iam:PassRole",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "s3:GetObjectVersion",
            "kms:Decrypt",
            "lambda:CreateFunction",
            "lambda:PutFunctionConcurrency",
            "lambda:PutRuntimeManagementConfig",
            "lambda:TagResource",
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
            "lambda:GetCodeSigningConfig",
        },
        "LEDGER_FACTORY_FUNCTION_FACTORY": {
            "sts:GetCallerIdentity",
            "iam:PassRole",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "s3:GetObjectVersion",
            "kms:Decrypt",
            "lambda:CreateFunction",
            "lambda:PutFunctionConcurrency",
            "lambda:PutRuntimeManagementConfig",
            "lambda:TagResource",
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
            "lambda:GetCodeSigningConfig",
            "logs:CreateLogGroup",
            "logs:PutRetentionPolicy",
            "logs:TagResource",
            "logs:ListTagsForResource",
            "logs:DescribeLogGroups",
        },
        "ACTIVATOR": {
            "sts:GetCallerIdentity",
            "iam:AttachRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyTags",
            "iam:ListPolicyVersions",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:PutRolePermissionsBoundary",
        },
        "REVOCATOR": {
            "sts:GetCallerIdentity",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:PutRolePermissionsBoundary",
        },
        "LEDGER_FACTORY_ACTIVATOR": {
            "sts:GetCallerIdentity",
            "iam:AttachRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:PutRolePermissionsBoundary",
        },
        "LEDGER_FACTORY_INVOKER": {
            "sts:GetCallerIdentity",
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
            "lambda:GetRuntimeManagementConfig",
            "lambda:InvokeFunction",
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:GetResourcePolicy",
            "dynamodb:ListTagsOfResource",
            "dynamodb:Scan",
            "kms:DescribeKey",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
        },
        "LEDGER_FACTORY_REVOKER": {
            "sts:GetCallerIdentity",
            "iam:DetachRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListEntitiesForPolicy",
            "iam:ListPolicyVersions",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
            "iam:PutRolePermissionsBoundary",
        },
    }
    if phase not in paths:
        _fail("AUTHORIZATION_PHASE_INVALID")
    replacement_keys = {
        "POLICY_FACTORY": {
            "service_role_boundary_arn",
            "broker_boundary_arn",
            "classifier_boundary_arn",
            "approver_boundary_arn",
            "proof_boundary_arn",
            "ledger_factory_boundary_arn",
            "source_commit",
            "gug363_pre_function_binding_sha256",
        },
        "FOUNDATION_FACTORY": {
            "proof_boundary_arn",
            "service_role_arn",
            "broker_role_arn",
            "classifier_role_arn",
            "approver_role_arn",
            "classifier_proof_role_arn",
            "approver_proof_role_arn",
            "ledger_factory_role_arn",
            "source_commit",
            "gug363_pre_function_binding_sha256",
        },
        "FUNCTION_FACTORY": {
            "proof_boundary_arn",
            "broker_role_arn",
            "broker_function_arn",
            "signed_object_arn",
            "signed_bucket_arn",
            "signed_version_id",
            "signed_kms_key_arn",
            "code_signing_config_arn",
            "authority_account_id",
            "region",
            "source_commit",
            "gug363_pre_function_binding_sha256",
        },
        "LEDGER_FACTORY_FUNCTION_FACTORY": {
            "proof_boundary_arn",
            "ledger_factory_role_arn",
            "ledger_factory_function_arn",
            "ledger_factory_function_version_arn",
            "ledger_factory_signed_object_arn",
            "ledger_factory_signed_bucket_arn",
            "ledger_factory_signed_version_id",
            "ledger_factory_signed_kms_key_arn",
            "ledger_factory_code_signing_config_arn",
            "ledger_factory_log_group_arn",
            "authority_account_id",
            "region",
            "source_commit",
            "gug363_pre_function_binding_sha256",
        },
        "ACTIVATOR": {
            "service_role_boundary_arn",
            "broker_boundary_arn",
            "classifier_boundary_arn",
            "approver_boundary_arn",
            "proof_boundary_arn",
            "service_role_arn",
            "broker_role_arn",
            "classifier_role_arn",
            "approver_role_arn",
            "classifier_proof_role_arn",
            "approver_proof_role_arn",
        },
        "REVOCATOR": {
            "proof_boundary_arn",
            "service_role_arn",
            "broker_role_arn",
            "classifier_role_arn",
            "approver_role_arn",
        },
        "LEDGER_FACTORY_ACTIVATOR": {
            "ledger_factory_boundary_arn",
            "proof_boundary_arn",
            "ledger_factory_role_arn",
        },
        "LEDGER_FACTORY_INVOKER": {
            "ledger_factory_function_version_arn",
            "ledger_table_arn",
            "ledger_factory_role_arn",
        },
        "LEDGER_FACTORY_REVOKER": {
            "ledger_factory_boundary_arn",
            "proof_boundary_arn",
            "ledger_factory_role_arn",
        },
    }
    replacements = {
        key: all_replacements[key] for key in replacement_keys[phase]
    }
    document, template_digest = _read_template(
        repo_root=repo_root,
        path=paths[phase],
        replacements=replacements,
    )
    if len(canonical_json(document).encode("utf-8")) > _POLICY_MAX_NON_WHITESPACE_BYTES:
        _fail("PROVISIONING_EXECUTOR_POLICY_TOO_LARGE")
    statements = _statements(document)
    allow_actions: set[str] = set()
    deny_actions: set[str] = set()
    exact_resources = (
        set(boundary_arns.values())
        | {_role_arn(name) for name in ROLE_ORDER}
        | {_table_arn()}
        | {
            _function_arn(),
            f"{_function_arn()}:*",
            _ledger_factory_function_arn(),
            f"{_ledger_factory_function_arn()}:*",
            _ledger_factory_function_arn(version=_FACTORY_VERSION),
            all_replacements["signed_object_arn"],
            all_replacements["ledger_factory_signed_object_arn"],
            all_replacements["signed_kms_key_arn"],
            all_replacements["ledger_factory_signed_kms_key_arn"],
            all_replacements["code_signing_config_arn"],
            all_replacements["ledger_factory_code_signing_config_arn"],
            all_replacements["ledger_factory_log_group_arn"],
        }
    )
    for statement in statements:
        if "NotAction" in statement:
            not_actions = set(
                _strings(
                    statement.get("NotAction"),
                    "PROVISIONING_EXECUTOR_ACTION_INVALID",
                )
            )
            if (
                phase == "FOUNDATION_FACTORY"
                or statement.get("Effect") != "Deny"
                or "Action" in statement
                or not not_actions
            ):
                _fail("PROVISIONING_EXECUTOR_DENY_INVALID")
            continue
        actions = set(
            _strings(statement.get("Action"), "PROVISIONING_EXECUTOR_ACTION_INVALID")
        )
        resource_field = (
            statement.get("Resource")
            if "Resource" in statement
            else statement.get("NotResource")
        )
        resources = set(
            _strings(
                resource_field,
                "PROVISIONING_EXECUTOR_RESOURCE_INVALID",
            )
        )
        if statement.get("Effect") == "Allow":
            allow_actions.update(actions)
            if any("*" in action or "?" in action for action in actions):
                _fail("PROVISIONING_EXECUTOR_ALLOW_WILDCARD")
            if resources == {"*"} and actions == {"sts:GetCallerIdentity"}:
                continue
            if (
                phase == "LEDGER_FACTORY_INVOKER"
                and resources == {"*"}
                and actions == {"kms:DescribeKey"}
            ):
                continue
            if (
                phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                and resources == {"*"}
                and actions
                == {"sts:GetCallerIdentity", "logs:DescribeLogGroups"}
            ):
                continue
            if not resources.issubset(exact_resources):
                _fail("PROVISIONING_EXECUTOR_RESOURCE_OUT_OF_SCOPE")
        elif statement.get("Effect") == "Deny":
            deny_actions.update(actions)
            if (
                resources != {"*"}
                and not (
                    phase == "LEDGER_FACTORY_INVOKER"
                    and "NotResource" in statement
                    and resources == {_table_arn()}
                )
            ):
                _fail("PROVISIONING_EXECUTOR_DENY_INVALID")
        else:
            _fail("PROVISIONING_EXECUTOR_POLICY_INVALID")
    common_required_denies = {
        "cloudformation:*",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:SetDefaultPolicyVersion",
        "iam:TagPolicy",
        "iam:TagRole",
        "iam:UpdateAssumeRolePolicy",
        "lambda:InvokeFunction",
        "lambda:InvokeFunctionUrl",
        "s3:DeleteObject",
        "s3:PutObject",
        "signer:StartSigningJob",
        "sts:AssumeRole",
    }
    phase_required_denies = {
        "POLICY_FACTORY": {
            "iam:AttachRolePolicy",
            "iam:CreateRole",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
            "iam:PassRole",
        },
        "FOUNDATION_FACTORY": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
            "iam:PassRole",
        },
        "FUNCTION_FACTORY": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
        },
        "LEDGER_FACTORY_FUNCTION_FACTORY": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
        },
        "ACTIVATOR": {
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PutRolePolicy",
            "iam:PassRole",
        },
        "REVOCATOR": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PutRolePolicy",
            "iam:PassRole",
        },
        "LEDGER_FACTORY_ACTIVATOR": {
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PassRole",
            "iam:PutRolePolicy",
        },
        "LEDGER_FACTORY_INVOKER": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:DetachRolePolicy",
            "iam:PassRole",
            "iam:PutRolePermissionsBoundary",
            "iam:PutRolePolicy",
        },
        "LEDGER_FACTORY_REVOKER": {
            "iam:AttachRolePolicy",
            "iam:CreatePolicy",
            "iam:CreateRole",
            "iam:PassRole",
            "iam:PutRolePolicy",
        },
    }
    dependent_create_tag_actions = {
        "POLICY_FACTORY": {"iam:TagPolicy"},
        "FOUNDATION_FACTORY": {"iam:TagRole"},
    }
    required_denies = (
        common_required_denies
        - (
            {"lambda:InvokeFunction"}
            if phase == "LEDGER_FACTORY_INVOKER"
            else set()
        )
        - dependent_create_tag_actions.get(phase, set())
    ) | phase_required_denies[phase]
    not_action_denies = [
        set(
            _strings(
                statement.get("NotAction"),
                "PROVISIONING_EXECUTOR_ACTION_INVALID",
            )
        )
        for statement in statements
        if statement.get("Effect") == "Deny" and "NotAction" in statement
    ]
    ledger_phase_closed = (
        phase.startswith("LEDGER_FACTORY_")
        and len(not_action_denies) >= 1
        and allow_actions.issubset(set().union(*not_action_denies))
    )
    if allow_actions != allowed_by_phase[phase] or (
        not ledger_phase_closed and not required_denies.issubset(deny_actions)
    ):
        _fail("PROVISIONING_EXECUTOR_AUTHORITY_INVALID")
    _validate_executor_conditions(
        phase=phase,
        statements=statements,
        gug363_plan=gug363_plan,
        boundary_arns=boundary_arns,
        factory_function=factory_function,
    )
    return {
        "phase": phase,
        "template_path": paths[phase].as_posix(),
        "template_sha256": template_digest,
        "document": document,
        "document_digest": canonical_digest(document),
        "projection_only": True,
        "created_by_this_plan": False,
    }


def _create_policy_request(
    boundary: Mapping[str, Any], *, gug363_plan: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "PolicyName": boundary["policy_name"],
        "Path": boundary["path"],
        "PolicyDocument": canonical_json(boundary["document"]),
        "Description": boundary["description"],
        "Tags": _policy_tags(gug363_plan),
    }


def _create_role_request_from_contract(
    contract: Mapping[str, Any],
    *,
    gug363_plan: Mapping[str, Any],
    initial_permissions_boundary_arn: str,
) -> dict[str, Any]:
    return {
        "RoleName": contract["role_name"],
        "Path": contract["path"],
        "AssumeRolePolicyDocument": canonical_json(contract["trust_policy"]),
        "Description": (
            "GUG-357 dedicated CloudFormation service role"
            if contract["role_name"] == SERVICE_ROLE_NAME
            else f"GUG-365 pre-created {contract['role_name']} role"
        ),
        "MaxSessionDuration": contract["max_session_duration"],
        "PermissionsBoundary": initial_permissions_boundary_arn,
        "Tags": _role_tags(
            gug363_plan, role_name=str(contract["role_name"])
        ),
    }


def _attach_role_policy_request(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": contract["role_name"],
        "PolicyArn": contract["permissions_boundary_arn"],
    }


def _put_permissions_boundary_request(
    contract: Mapping[str, Any], *, boundary_arn: str
) -> dict[str, Any]:
    return {
        "RoleName": contract["role_name"],
        "PermissionsBoundary": boundary_arn,
    }


def _operation(
    *, sequence: int, action: str, target_arn: str, request: Mapping[str, Any]
) -> dict[str, Any]:
    service, api_action = action.split(":", 1)
    return {
        "sequence": sequence,
        "service": service,
        "api_action": api_action,
        "allowed_action": action,
        "target_arn": target_arn,
        "request": dict(request),
        "request_digest": canonical_digest(request),
        "attempt_limit": 1,
        "retry_permitted": False,
        "repair_permitted": False,
        "delete_permitted": False,
        "ambiguous_outcome": "STOP_AND_RECONCILE_READ_ONLY",
    }


def _table_active_wait_operation(*, sequence: int) -> dict[str, Any]:
    """Bind the read-only stabilization gate between table creation and PITR."""

    request = {"TableName": LEDGER_TABLE_NAME}
    return {
        "sequence": sequence,
        "service": "dynamodb",
        "api_action": "WaitUntilTableExists",
        "allowed_action": "dynamodb:DescribeTable",
        "target_arn": _table_arn(),
        "request": request,
        "request_digest": canonical_digest(request),
        "mutation": False,
        "requires_conclusive_create_receipt_from_this_attempt": True,
        "bounded_read_polling": True,
        "poll_interval_seconds": 3,
        "max_poll_attempts": 20,
        "timeout_seconds": 60,
        "expected_table_status": "ACTIVE",
        "write_retry_permitted": False,
        "timeout_or_mismatch_mode": "STOP_NO_PITR_NO_ACTIVATION_NO_REPAIR",
    }


def _function_active_wait_operation(
    *, sequence: int, function: Mapping[str, Any]
) -> dict[str, Any]:
    function_name = str(function["function_name"])
    request = {"FunctionName": function_name}
    return {
        "sequence": sequence,
        "service": "lambda",
        "api_action": "WaitUntilFunctionActiveV2",
        "allowed_action": "lambda:GetFunctionConfiguration",
        "target_arn": str(function["arn"]),
        "request": request,
        "request_digest": canonical_digest(request),
        "mutation": False,
        "requires_conclusive_create_receipt_from_this_attempt": True,
        "bounded_read_polling": True,
        "poll_interval_seconds": 3,
        "max_poll_attempts": 20,
        "timeout_seconds": 60,
        "expected_state": "Active",
        "expected_last_update_status": "Successful",
        "write_retry_permitted": False,
        "timeout_or_mismatch_mode": (
            "STOP_NO_CONFIG_NO_ACTIVATION_NO_REPAIR"
        ),
    }


def _function_factory_preflight_operations(
    *,
    sequence: int,
    functions: Sequence[Mapping[str, Any]],
    proof_boundary: Mapping[str, Any],
    roles: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    operations = _proof_policy_verification_operations(
        sequence=sequence,
        stage="BEFORE_FUNCTION_FACTORY_WRITE",
        proof_boundary=proof_boundary,
    )
    for item in operations:
        item["mismatch_or_incomplete_mode"] = "STOP_NO_FUNCTION_MUTATION"
    next_sequence = sequence + len(operations)
    if not functions or len(functions) != len(roles):
        _fail("FUNCTION_FACTORY_PREFLIGHT_CONTRACT_MISSING")
    for function, role in zip(functions, roles, strict=True):
        role_name = str(role["role_name"])
        role_requests = (
            ("GetRole", {"RoleName": role_name}),
            ("ListRolePolicies", {"RoleName": role_name}),
            ("ListAttachedRolePolicies", {"RoleName": role_name}),
            ("ListRoleTags", {"RoleName": role_name}),
        )
        for action, request in role_requests:
            operations.append(
                {
                    "sequence": next_sequence,
                    "service": "iam",
                    "api_action": action,
                    "allowed_action": f"iam:{action}",
                    "target_arn": role["arn"],
                    "request": request,
                    "request_digest": canonical_digest(request),
                    "mutation": False,
                    "expected_role_contract_digest": canonical_digest(role),
                    "expected_permissions_boundary_arn": proof_boundary["arn"],
                    "expected_attached_policy_arns": [],
                    "expected_inline_policy_names": [],
                    "complete_pagination_required": action.startswith("List"),
                    "mismatch_mode": "STOP_NO_FUNCTION_MUTATION",
                }
            )
            next_sequence += 1
        for ordinal in (1, 2):
            request = {"FunctionName": function["function_name"]}
            operations.append(
                {
                    "sequence": next_sequence,
                    "service": "lambda",
                    "api_action": "GetFunction",
                    "allowed_action": "lambda:GetFunction",
                    "target_arn": function["arn"],
                    "request": request,
                    "request_digest": canonical_digest(request),
                    "mutation": False,
                    "absence_probe_ordinal": ordinal,
                    "expected_error_code": "ResourceNotFoundException",
                    "mismatch_mode": "STOP_NO_ADOPTION_NO_FUNCTION_MUTATION",
                }
            )
            next_sequence += 1
        csc_request = {
            "CodeSigningConfigArn": function["code_signing_config_arn"]
        }
        operations.append(
            {
                "sequence": next_sequence,
                "service": "lambda",
                "api_action": "GetCodeSigningConfig",
                "allowed_action": "lambda:GetCodeSigningConfig",
                "target_arn": function["code_signing_config_arn"],
                "request": csc_request,
                "request_digest": canonical_digest(csc_request),
                "mutation": False,
                "expected_contract_digest": canonical_digest(
                    function["code_signing_config_contract"]
                ),
                "mismatch_mode": "STOP_NO_FUNCTION_MUTATION",
            }
        )
        next_sequence += 1
        signed = function["signed_code"]
        object_request = {
            "Bucket": signed["s3_bucket"],
            "Key": signed["s3_key"],
            "VersionId": signed["s3_object_version"],
            "ChecksumMode": "ENABLED",
        }
        operations.append(
            {
                "sequence": next_sequence,
                "service": "s3",
                "api_action": "GetObjectVersion",
                "allowed_action": "s3:GetObjectVersion",
                "target_arn": (
                    f"arn:{PARTITION}:s3:::{signed['s3_bucket']}/{signed['s3_key']}"
                ),
                "request": object_request,
                "request_digest": canonical_digest(object_request),
                "mutation": False,
                "expected_archive_sha256": signed["archive_sha256"],
                "expected_lambda_code_sha256": signed["lambda_code_sha256"],
                "expected_archive_size_bytes": signed["archive_size_bytes"],
                "object_body_persistence_permitted": False,
                "mismatch_mode": "STOP_NO_FUNCTION_MUTATION",
            }
        )
        next_sequence += 1
    return operations


def _factory_log_group_absence_operations(
    *, sequence: int, contract: Mapping[str, Any]
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for ordinal in (1, 2):
        request = {
            "logGroupNamePrefix": contract["log_group_name"],
            "limit": 1,
        }
        operations.append(
            {
                "sequence": sequence + ordinal - 1,
                "service": "logs",
                "api_action": "DescribeLogGroups",
                "allowed_action": "logs:DescribeLogGroups",
                "target_arn": contract["arn"],
                "request": request,
                "request_digest": canonical_digest(request),
                "mutation": False,
                "absence_probe_ordinal": ordinal,
                "exact_name_must_be_absent": contract["log_group_name"],
                "prefix_collisions_ignored": True,
                "mismatch_mode": "STOP_NO_ADOPTION_NO_FACTORY_MUTATION",
            }
        )
    return operations


def _proof_policy_verification_operations(
    *, sequence: int, stage: str, proof_boundary: Mapping[str, Any]
) -> list[dict[str, Any]]:
    arn = str(proof_boundary["arn"])
    digest = str(proof_boundary["document_digest"])
    requests = (
        ("GetPolicy", {"PolicyArn": arn}),
        ("GetPolicyVersion", {"PolicyArn": arn, "VersionId": "v1"}),
        ("ListPolicyVersions", {"PolicyArn": arn}),
        (
            "ListEntitiesForPolicy",
            {"PolicyArn": arn, "PolicyUsageFilter": "PermissionsPolicy"},
        ),
        (
            "ListEntitiesForPolicy",
            {"PolicyArn": arn, "PolicyUsageFilter": "PermissionsBoundary"},
        ),
    )
    operations: list[dict[str, Any]] = []
    for offset, (api_action, request) in enumerate(requests):
        operations.append(
            {
                "sequence": sequence + offset,
                "service": "iam",
                "api_action": api_action,
                "allowed_action": f"iam:{api_action}",
                "target_arn": arn,
                "request": request,
                "request_digest": canonical_digest(request),
                "mutation": False,
                "verification_stage": stage,
                "expected_default_version_id": "v1",
                "expected_policy_versions": ["v1"],
                "expected_document_digest": digest,
                "complete_pagination_required": api_action.startswith("List"),
                "mismatch_or_incomplete_mode": "STOP_NO_REVOCATION",
            }
        )
    return operations


def _phase_operation_contract(
    *,
    phase: str,
    writes: Sequence[Mapping[str, Any]],
    proof_boundary: Mapping[str, Any] | None = None,
    function: Mapping[str, Any] | None = None,
    broker_role: Mapping[str, Any] | None = None,
    factory_function: Mapping[str, Any] | None = None,
    factory_role: Mapping[str, Any] | None = None,
    factory_log_group: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Bind every short-lived authority to identity before any mutation."""

    operations: list[dict[str, Any]] = [
        {
            "sequence": 1,
            "service": "sts",
            "api_action": "GetCallerIdentity",
            "allowed_action": "sts:GetCallerIdentity",
            "target_arn": "*",
            "request": {},
            "request_digest": canonical_digest({}),
            "expected_account_id": AUTHORITY_ACCOUNT_ID,
            "authority_phase": phase,
            "identity_timeout_seconds": 15,
            "mismatch_or_timeout_mode": "STOP_NO_MUTATION",
            "attempt_limit": 1,
            "retry_permitted": False,
        }
    ]
    phase_sequence = 2
    if phase in {"REVOCATOR", "LEDGER_FACTORY_REVOKER"}:
        if not isinstance(proof_boundary, Mapping):
            _fail("REVOCATOR_PROOF_BOUNDARY_MISSING")
        proof_checks = _proof_policy_verification_operations(
            sequence=phase_sequence,
            stage="BEFORE_FIRST_REVOCATION_WRITE",
            proof_boundary=proof_boundary,
        )
        operations.extend(proof_checks)
        phase_sequence += len(proof_checks)
    if phase in {"FUNCTION_FACTORY", "LEDGER_FACTORY_FUNCTION_FACTORY"}:
        if not all(
            isinstance(value, Mapping)
            for value in (
                proof_boundary,
                function,
                broker_role,
                factory_function if phase == "LEDGER_FACTORY_FUNCTION_FACTORY" else function,
                factory_role if phase == "LEDGER_FACTORY_FUNCTION_FACTORY" else broker_role,
            )
        ):
            _fail("FUNCTION_FACTORY_PREFLIGHT_CONTRACT_MISSING")
        assert isinstance(proof_boundary, Mapping)
        assert isinstance(function, Mapping)
        assert isinstance(broker_role, Mapping)
        selected_function = (
            factory_function
            if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
            else function
        )
        selected_role = (
            factory_role
            if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
            else broker_role
        )
        assert isinstance(selected_function, Mapping)
        assert isinstance(selected_role, Mapping)
        function_checks = _function_factory_preflight_operations(
            sequence=phase_sequence,
            functions=(selected_function,),
            proof_boundary=proof_boundary,
            roles=(selected_role,),
        )
        operations.extend(function_checks)
        phase_sequence += len(function_checks)
        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY":
            if not isinstance(factory_log_group, Mapping):
                _fail("LEDGER_FACTORY_LOG_GROUP_CONTRACT_MISSING")
            log_checks = _factory_log_group_absence_operations(
                sequence=phase_sequence,
                contract=factory_log_group,
            )
            operations.extend(log_checks)
            phase_sequence += len(log_checks)
    for write in writes:
        item = dict(write)
        item["planned_write_sequence"] = write["sequence"]
        item["sequence"] = phase_sequence
        if phase == "POLICY_FACTORY" and write.get(
            "allowed_action"
        ) == "iam:CreatePolicy":
            item["dependent_authorization_actions"] = ["iam:TagPolicy"]
            item["dependent_action_permitted_standalone"] = False
            item["dependent_action_bound_to_create_request_tags"] = True
        elif phase == "FOUNDATION_FACTORY" and write.get(
            "allowed_action"
        ) == "iam:CreateRole":
            item["dependent_authorization_actions"] = ["iam:TagRole"]
            item["dependent_action_permitted_standalone"] = False
            item["dependent_action_bound_to_create_request_tags"] = True
        operations.append(item)
        phase_sequence += 1
        if (
            phase == "FOUNDATION_FACTORY"
            and write.get("allowed_action") == "dynamodb:CreateTable"
        ):
            operations.append(_table_active_wait_operation(sequence=phase_sequence))
            phase_sequence += 1
        if (
            phase in {"FUNCTION_FACTORY", "LEDGER_FACTORY_FUNCTION_FACTORY"}
            and write.get("allowed_action") == "lambda:CreateFunction"
        ):
            operations.append(
                _function_active_wait_operation(
                    sequence=phase_sequence,
                    function=(
                        function
                        if write.get("target_arn") == function.get("arn")
                        else factory_function
                    ),
                )
            )
            phase_sequence += 1
    if phase in {"REVOCATOR", "LEDGER_FACTORY_REVOKER"}:
        assert isinstance(proof_boundary, Mapping)
        proof_checks = _proof_policy_verification_operations(
            sequence=phase_sequence,
            stage="AFTER_ALL_REVOCATION_WRITES",
            proof_boundary=proof_boundary,
        )
        operations.extend(proof_checks)
    return operations


def _executor_effective_authority_requirement(
    executor_policy: Mapping[str, Any], *, phase: str
) -> dict[str, Any]:
    """Describe the authenticated effective-authority closure required live.

    An IAM identity policy is additive.  The phase document is therefore safe
    only when it is also the maximum-permissions cap and no other grant is
    effective for the session.  This repository does not mint that session;
    it records the fail-closed evidence contract a future live lane must prove.
    """

    document_digest = _require_digest(
        executor_policy.get("document_digest"),
        "EXECUTOR_POLICY_DIGEST_INVALID",
    )
    return {
        "phase": phase,
        "required_policy_document_digest": document_digest,
        "sole_identity_grant_required": True,
        "identical_maximum_permissions_cap_required": True,
        "accepted_cap_sources": [
            "DEDICATED_ROLE_PERMISSIONS_BOUNDARY",
            "IDENTITY_CENTER_PERMISSION_BOUNDARY",
            "TRUSTED_BROKER_ENFORCED_SESSION_CAP",
        ],
        "complete_effective_policy_inventory_required": True,
        "additional_inline_policy_count": 0,
        "additional_attached_policy_count": 0,
        "group_policy_count": 0,
        "session_chain_depth": 0,
        "maximum_session_lifetime_seconds": 900,
        "caller_account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "caller_arn_digest_required": True,
        "raw_caller_arn_persistence_permitted": False,
        "fresh_post_sts_evidence_required": True,
        "missing_incomplete_or_drift_mode": "STOP_NO_MUTATION",
    }


def validate_executor_authority_evidence(
    plan: Mapping[str, Any],
    *,
    phase: str,
    evidence: Mapping[str, Any],
    expected_caller_arn_digest: str,
    expected_evidence_digest: str,
    evaluation_at: datetime,
    ledger_not_before: datetime | None = None,
    ledger_expires_at: datetime | None = None,
) -> None:
    """Reject additive, stale, chained, or otherwise unbounded executors.

    Both expected digests must come from the trusted live runner and the
    independently delivered owner authorization.  A caller-supplied evidence
    object is never authoritative by itself.
    """

    candidates = {
        str(item.get("phase")): item
        for item in plan.get("authorization_phases", [])
        if isinstance(item, Mapping)
    }
    revocation = plan.get("revocation")
    if isinstance(revocation, Mapping):
        candidates[str(revocation.get("phase"))] = revocation
    selected = candidates.get(phase)
    if not isinstance(selected, Mapping):
        _fail("EXECUTOR_AUTHORITY_PHASE_INVALID")
    requirement = selected.get("executor_effective_authority_requirement")
    if not isinstance(requirement, Mapping):
        _fail("EXECUTOR_AUTHORITY_REQUIREMENT_MISSING")
    required_keys = {
        "record_type",
        "phase",
        "caller_account_id",
        "region",
        "caller_arn_digest",
        "session_identifier_digest",
        "session_issued_at",
        "session_expires_at",
        "evidence_collected_at",
        "session_lifetime_seconds",
        "session_remaining_seconds",
        "session_chain_depth",
        "evidence_collected_after_sts",
        "effective_policy_inventory_complete",
        "sole_identity_policy_document_digest",
        "additional_inline_policy_count",
        "additional_attached_policy_count",
        "group_policy_count",
        "maximum_authority_source",
        "maximum_authority_document_digest",
        "raw_caller_arn_persisted",
        "evidence_digest",
    }
    if not isinstance(evidence, Mapping) or set(evidence) != required_keys:
        _fail("EXECUTOR_AUTHORITY_EVIDENCE_FIELDS_INVALID")
    expected_digest = requirement["required_policy_document_digest"]
    supplied_digest = evidence.get("evidence_digest")
    _require_digest(supplied_digest, "EXECUTOR_AUTHORITY_EVIDENCE_DIGEST_INVALID")
    _require_digest(
        expected_caller_arn_digest,
        "EXPECTED_CALLER_ARN_DIGEST_INVALID",
    )
    _require_digest(
        expected_evidence_digest,
        "EXPECTED_EXECUTOR_AUTHORITY_EVIDENCE_DIGEST_INVALID",
    )
    calculated = canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    if supplied_digest != calculated or supplied_digest != expected_evidence_digest:
        _fail("EXECUTOR_AUTHORITY_EVIDENCE_DIGEST_MISMATCH")
    _require_digest(evidence.get("caller_arn_digest"), "CALLER_ARN_DIGEST_INVALID")
    for field in (
        "session_identifier_digest",
        "sole_identity_policy_document_digest",
        "maximum_authority_document_digest",
    ):
        _require_digest(evidence.get(field), "EXECUTOR_AUTHORITY_POLICY_DIGEST_INVALID")
    lifetime = evidence.get("session_lifetime_seconds")
    remaining = evidence.get("session_remaining_seconds")
    evaluated = _authority_timestamp(evaluation_at, "AUTHORITY_EVALUATION_TIME_INVALID")
    issued = _authority_timestamp(
        evidence.get("session_issued_at"), "AUTHORITY_SESSION_ISSUED_AT_INVALID"
    )
    expires = _authority_timestamp(
        evidence.get("session_expires_at"), "AUTHORITY_SESSION_EXPIRES_AT_INVALID"
    )
    collected = _authority_timestamp(
        evidence.get("evidence_collected_at"),
        "AUTHORITY_EVIDENCE_COLLECTED_AT_INVALID",
    )
    calculated_lifetime = int((expires - issued).total_seconds())
    calculated_remaining = int((expires - evaluated).total_seconds())
    ledger_window_valid = True
    if ledger_not_before is not None or ledger_expires_at is not None:
        if ledger_not_before is None or ledger_expires_at is None:
            _fail("EXECUTOR_AUTHORITY_LEDGER_WINDOW_INVALID")
        ledger_start = _authority_timestamp(
            ledger_not_before, "LEDGER_NOT_BEFORE_INVALID"
        )
        ledger_end = _authority_timestamp(
            ledger_expires_at, "LEDGER_EXPIRES_AT_INVALID"
        )
        ledger_window_valid = evaluated <= ledger_start < ledger_end <= expires
    if (
        evidence.get("record_type")
        != "scanalyze.platform_authority.gug365_executor_authority_evidence.v1"
        or evidence.get("phase") != phase
        or evidence.get("caller_account_id") != AUTHORITY_ACCOUNT_ID
        or evidence.get("region") != REGION
        or evidence.get("caller_arn_digest") != expected_caller_arn_digest
        or not issued <= collected <= evaluated < expires
        or calculated_lifetime != lifetime
        or calculated_remaining != remaining
        or calculated_lifetime > requirement["maximum_session_lifetime_seconds"]
        or not ledger_window_valid
        or not isinstance(lifetime, int)
        or isinstance(lifetime, bool)
        or not 1 <= lifetime <= requirement["maximum_session_lifetime_seconds"]
        or not isinstance(remaining, int)
        or isinstance(remaining, bool)
        or not 1 <= remaining <= lifetime
        or evidence.get("session_chain_depth") != 0
        or evidence.get("evidence_collected_after_sts") is not True
        or evidence.get("effective_policy_inventory_complete") is not True
        or evidence.get("sole_identity_policy_document_digest") != expected_digest
        or evidence.get("additional_inline_policy_count") != 0
        or evidence.get("additional_attached_policy_count") != 0
        or evidence.get("group_policy_count") != 0
        or evidence.get("maximum_authority_source")
        not in requirement["accepted_cap_sources"]
        or evidence.get("maximum_authority_document_digest") != expected_digest
        or evidence.get("raw_caller_arn_persisted") is not False
    ):
        _fail("EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED")


def _authority_timestamp(value: Any, code: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            _fail(code)
        result = value.astimezone(timezone.utc).replace(microsecond=0)
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            result = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            _fail(code)
        if result.microsecond:
            _fail(code)
    else:
        _fail(code)
    return result


def validate_ledger_factory_causal_receipt(
    plan: Mapping[str, Any],
    *,
    receipt: Mapping[str, Any],
    expected_receipt_sha256: str,
) -> None:
    """Accept only the causal one-create/one-PITR immutable-factory receipt."""

    _require_digest(
        expected_receipt_sha256,
        "EXPECTED_LEDGER_FACTORY_RECEIPT_DIGEST_INVALID",
    )
    expected_fields = {
        "artifact_type",
        "schema_version",
        "status",
        "reason_code",
        "attempt",
        "create_table_call_count",
        "update_pitr_call_count",
        "retry_permitted",
        "next_required_action",
        "request_sha256",
        "contract_sha256",
        "qualified_function_sha256",
        "resource_policy_sha256",
        "kms_key_arn_sha256",
        "kms_key_metadata_sha256",
        "revision_id_sha256",
        "active_readback_attempt_count",
        "policy_readback_attempt_count",
        "pitr_readback_attempt_count",
        "receipt_sha256",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_fields:
        _fail("LEDGER_FACTORY_RECEIPT_FIELDS_INVALID")
    receipt_sha256 = _require_digest(
        receipt.get("receipt_sha256"),
        "LEDGER_FACTORY_RECEIPT_DIGEST_INVALID",
    )
    calculated = canonical_digest(
        {
            key: value
            for key, value in receipt.items()
            if key != "receipt_sha256"
        }
    )
    factory_function = plan.get("ledger_factory_function")
    if not isinstance(factory_function, Mapping):
        _fail("LEDGER_FACTORY_FUNCTION_CONTRACT_INVALID")
    qualified_digest = ledger_factory.canonical_digest(
        {
            "qualified_function_arn": factory_function[
                "immutable_version_arn"
            ]
        }
    )
    if (
        receipt_sha256 != calculated
        or receipt_sha256 != expected_receipt_sha256
        or receipt.get("artifact_type") != ledger_factory.RECEIPT_ARTIFACT_TYPE
        or not _is_exact_int(receipt.get("schema_version"), 1)
        or receipt.get("status") not in {"CREATED", "CREATED_RECONCILED"}
        or receipt.get("reason_code") != "LEDGER_EXACT_FULL_READBACK"
        or not _is_exact_int(receipt.get("attempt"), 1)
        or not _is_exact_int(receipt.get("create_table_call_count"), 1)
        or not _is_exact_int(receipt.get("update_pitr_call_count"), 1)
        or receipt.get("retry_permitted") is not False
        or receipt.get("next_required_action")
        != "REVOKE_FACTORY_AUTHORITY"
        or receipt.get("request_sha256") != canonical_digest({})
        or receipt.get("contract_sha256") != ledger_factory.CONTRACT_SHA256
        or receipt.get("qualified_function_sha256") != qualified_digest
        or receipt.get("resource_policy_sha256")
        != canonical_digest(_ledger_resource_policy())
        or not isinstance(receipt.get("kms_key_arn_sha256"), str)
        or _DIGEST_RE.fullmatch(str(receipt.get("kms_key_arn_sha256"))) is None
        or not isinstance(receipt.get("kms_key_metadata_sha256"), str)
        or _DIGEST_RE.fullmatch(str(receipt.get("kms_key_metadata_sha256")))
        is None
        or not isinstance(receipt.get("revision_id_sha256"), str)
        or _DIGEST_RE.fullmatch(str(receipt.get("revision_id_sha256"))) is None
        or not _is_bounded_int(
            receipt.get("active_readback_attempt_count"), 2, 60
        )
        or not _is_bounded_int(
            receipt.get("policy_readback_attempt_count"), 2, 12
        )
        or not _is_bounded_int(
            receipt.get("pitr_readback_attempt_count"), 1, 12
        )
    ):
        _fail("LEDGER_FACTORY_CAUSAL_RECEIPT_NOT_ACCEPTED")


def _readback_contracts(
    boundaries: Sequence[Mapping[str, Any]],
    roles: Sequence[Mapping[str, Any]],
    functions: Sequence[Mapping[str, Any]],
    ledger_table: Mapping[str, Any],
    factory_log_group: Mapping[str, Any],
) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    sequence = 1
    for boundary in boundaries:
        arn = str(boundary["arn"])
        requests = (
            ("GetPolicy", {"PolicyArn": arn}),
            ("GetPolicyVersion", {"PolicyArn": arn, "VersionId": "v1"}),
            ("ListPolicyVersions", {"PolicyArn": arn}),
            (
                "ListEntitiesForPolicy",
                {"PolicyArn": arn, "PolicyUsageFilter": "PermissionsPolicy"},
            ),
            (
                "ListEntitiesForPolicy",
                {"PolicyArn": arn, "PolicyUsageFilter": "PermissionsBoundary"},
            ),
            ("ListPolicyTags", {"PolicyArn": arn}),
        )
        for action, request in requests:
            contracts.append(
                {
                    "sequence": sequence,
                    "service": "iam",
                    "api_action": action,
                    "target_arn": arn,
                    "request": request,
                    "complete_pagination_required": action.startswith("List"),
                    "attempt_limit": 1,
                    "retry_permitted": False,
                }
            )
            sequence += 1
    for role in roles:
        role_name = str(role["role_name"])
        for action in (
            "GetRole",
            "ListRolePolicies",
            "ListAttachedRolePolicies",
            "ListRoleTags",
        ):
            contracts.append(
                {
                    "sequence": sequence,
                    "service": "iam",
                    "api_action": action,
                    "target_arn": role["arn"],
                    "request": {"RoleName": role_name},
                    "complete_pagination_required": action.startswith("List"),
                    "attempt_limit": 1,
                    "retry_permitted": False,
                }
            )
            sequence += 1
    table_arn = _table_arn()
    table_requests = (
        ("WaitUntilTableExists", {"TableName": LEDGER_TABLE_NAME}),
        ("DescribeTable", {"TableName": LEDGER_TABLE_NAME}),
        ("DescribeContinuousBackups", {"TableName": LEDGER_TABLE_NAME}),
        ("DescribeTimeToLive", {"TableName": LEDGER_TABLE_NAME}),
        ("GetResourcePolicy", {"ResourceArn": table_arn}),
        ("ListTagsOfResource", {"ResourceArn": table_arn}),
        (
            "Scan",
            {
                "TableName": LEDGER_TABLE_NAME,
                "ConsistentRead": True,
                "Select": "COUNT",
                "Limit": 1,
            },
        ),
        ("DescribeTable", {"TableName": LEDGER_TABLE_NAME}),
        ("DescribeContinuousBackups", {"TableName": LEDGER_TABLE_NAME}),
        ("DescribeTimeToLive", {"TableName": LEDGER_TABLE_NAME}),
        ("GetResourcePolicy", {"ResourceArn": table_arn}),
        ("ListTagsOfResource", {"ResourceArn": table_arn}),
    )
    for action, request in table_requests:
        contract = {
                "sequence": sequence,
                "service": "dynamodb",
                "api_action": action,
                "target_arn": table_arn,
                "request": request,
                "complete_pagination_required": action == "ListTagsOfResource",
                "verification_stage": (
                    "AFTER_ACCEPTED_CAUSAL_RECEIPT_AND_FACTORY_REVOCATION"
                ),
                "accepted_causal_factory_receipt_required": True,
                **(
                    {
                        "only_after_create_receipt_from_this_attempt": True,
                        "expected_response": {
                            "Count": 0,
                            "ScannedCount": 0,
                            "LastEvaluatedKey": "ABSENT",
                        },
                        "mismatch_mode": "STOP_NO_ACTIVATION_NO_REPAIR",
                    }
                    if action == "Scan"
                    else {}
                ),
            }
        if action == "WaitUntilTableExists":
            contract.update(
                {
                    "bounded_read_polling": True,
                    "poll_interval_seconds": 3,
                    "max_poll_attempts": 20,
                    "timeout_seconds": 60,
                    "expected_table_status": "ACTIVE",
                    "write_retry_permitted": False,
                    "timeout_or_mismatch_mode": (
                        "STOP_NO_PITR_NO_ACTIVATION_NO_REPAIR"
                    ),
                }
            )
        else:
            contract.update({"attempt_limit": 1, "retry_permitted": False})
        contracts.append(contract)
        sequence += 1
    observed_kms_arn = "<OBSERVED_TABLE_SSE_DESCRIPTION_KMS_MASTER_KEY_ARN>"
    kms_metadata = ledger_table["kms_key_contract"]["metadata_projection"]
    kms_metadata_static_projection = {
        "account_sha256": canonical_digest(
            {"kms_aws_account_id": AUTHORITY_ACCOUNT_ID}
        ),
        "enabled": kms_metadata["Enabled"],
        "key_usage": kms_metadata["KeyUsage"],
        "key_state": kms_metadata["KeyState"],
        "origin": kms_metadata["Origin"],
        "key_manager": kms_metadata["KeyManager"],
        "key_spec": kms_metadata["KeySpec"],
        "multi_region": kms_metadata["MultiRegion"],
        "encryption_algorithms": kms_metadata["EncryptionAlgorithms"],
    }
    for stage in (
        "AFTER_ACCEPTED_CAUSAL_RECEIPT_AND_FACTORY_REVOCATION",
        "AFTER_FINAL_ROLE_POLICY_SET_CERTIFIED",
    ):
        contracts.append(
            {
                "sequence": sequence,
                "service": "kms",
                "api_action": "DescribeKey",
                "target_arn": observed_kms_arn,
                "request": {"KeyId": observed_kms_arn},
                "verification_stage": stage,
                "complete_pagination_required": False,
                "attempt_limit": 1,
                "retry_permitted": False,
                "iam_resource_scope_required": "*",
                "observed_table_kms_arn_source": (
                    "dynamodb:DescribeTable.Table.SSEDescription."
                    "KMSMasterKeyArn"
                ),
                "observed_table_kms_arn_pattern": kms_metadata["arn_pattern"],
                "key_metadata_arn_must_equal_observed_table_kms_arn": True,
                "key_id_uuid_must_equal_arn_suffix": True,
                "expected_aws_managed_metadata": dict(kms_metadata),
                "metadata_digest_projection_static_fields": (
                    kms_metadata_static_projection
                ),
                "metadata_digest_projection_dynamic_fields": {
                    "arn_sha256": "kms_key_arn_sha256"
                },
                "kms_key_arn_digest_input": {
                    "kms_key_arn": observed_kms_arn
                },
                "receipt_digest_comparisons": {
                    "kms_key_arn_sha256": "EXACT_CANONICAL_DIGEST_MATCH",
                    "kms_key_metadata_sha256": (
                        "EXACT_CANONICAL_DIGEST_MATCH"
                    ),
                },
                "forbidden_key_metadata_fields": sorted(
                    {
                        "CloudHsmClusterId",
                        "CustomKeyStoreId",
                        "DeletionDate",
                        "ExpirationModel",
                        "KeyAgreementAlgorithms",
                        "MacAlgorithms",
                        "MultiRegionConfiguration",
                        "PendingDeletionWindowInDays",
                        "SigningAlgorithms",
                        "ValidTo",
                        "XksKeyConfiguration",
                    }
                ),
                "accepted_causal_factory_receipt_required": True,
                "main_activation_checkpoint_required": (
                    stage == "AFTER_FINAL_ROLE_POLICY_SET_CERTIFIED"
                ),
                "raw_key_identifiers_persistence_permitted": False,
                "mismatch_mode": "STOP_NO_ACTIVATION_NO_REPAIR",
            }
        )
        sequence += 1
    for function in functions:
        function_arn = str(function["arn"])
        function_name = str(function["function_name"])
        immutable_version = function.get("immutable_version")
        is_ledger_factory = function_name == LEDGER_FACTORY_FUNCTION_NAME
        if is_ledger_factory and immutable_version != _FACTORY_VERSION:
            _fail("LEDGER_FACTORY_IMMUTABLE_VERSION_INVALID")
        qualified_factory_actions = {
            "GetFunction",
            "GetFunctionConfiguration",
            "GetRuntimeManagementConfig",
            "GetPolicy",
        }
        function_requests = (
            ("GetFunction", {"FunctionName": function_name}),
            ("GetFunctionConfiguration", {"FunctionName": function_name}),
            ("GetFunctionCodeSigningConfig", {"FunctionName": function_name}),
            ("GetFunctionConcurrency", {"FunctionName": function_name}),
            ("GetRuntimeManagementConfig", {"FunctionName": function_name}),
            ("ListTags", {"Resource": function_arn}),
            ("ListVersionsByFunction", {"FunctionName": function_name}),
            ("ListAliases", {"FunctionName": function_name}),
            ("ListFunctionUrlConfigs", {"FunctionName": function_name}),
            ("GetPolicy", {"FunctionName": function_name}),
            (
                "GetCodeSigningConfig",
                {"CodeSigningConfigArn": function["code_signing_config_arn"]},
            ),
        )
        for stage in (
            "BEFORE_FUNCTION_CREATE_ABSENCE_OR_RECONCILIATION",
            "AFTER_FUNCTION_FACTORY_AUTHORITY_EXPIRED",
        ):
            for action, request in function_requests:
                qualified_factory_read = (
                    is_ledger_factory and action in qualified_factory_actions
                )
                exact_request = dict(request)
                if qualified_factory_read:
                    exact_request["Qualifier"] = _FACTORY_VERSION
                contracts.append({
                    "sequence": sequence,
                    "service": "lambda",
                    "api_action": action,
                    "target_arn": (
                        str(function["code_signing_config_arn"])
                        if action == "GetCodeSigningConfig"
                        else (
                            str(function["immutable_version_arn"])
                            if qualified_factory_read
                            else function_arn
                        )
                    ),
                    "request": exact_request,
                    "verification_stage": stage,
                    "complete_pagination_required": action.startswith("List"),
                    "attempt_limit": 1,
                    "retry_permitted": False,
                    "code_location_persistence_permitted": False,
                    "environment_values_persistence_permitted": False,
                    "absence_expected_before_create": (
                        stage.startswith("BEFORE")
                        and action != "GetCodeSigningConfig"
                    ),
                    "code_signing_config_exact_and_enforcing": (
                        action == "GetCodeSigningConfig"
                    ),
                    "post_expiry_exact_contract_digest": (
                        canonical_digest(function)
                        if stage.startswith("AFTER")
                        else None
                    ),
                    "get_policy_expected": (
                        "ResourceNotFoundException"
                        if action == "GetPolicy"
                        else None
                    ),
                    "immutable_version_certified": qualified_factory_read,
                    "resolved_s3_object": (
                        "IF_PRESENT_MUST_MATCH_EXACT_SIGNED_TUPLE"
                        if action == "GetFunction"
                        else None
                    ),
                    "mismatch_mode": (
                        "STOP_NO_ADOPTION_NO_UPDATE_NO_CFN"
                    ),
                })
                sequence += 1
    for stage in (
        "BEFORE_FACTORY_LOG_GROUP_CREATE_ABSENCE",
        "AFTER_LEDGER_FACTORY_FUNCTION_FACTORY_AUTHORITY_EXPIRED",
    ):
        for action, request in (
            (
                "DescribeLogGroups",
                {
                    "logGroupNamePrefix": factory_log_group["log_group_name"],
                    "limit": 1,
                },
            ),
            (
                "ListTagsForResource",
                {"resourceArn": factory_log_group["arn"]},
            ),
        ):
            contracts.append(
                {
                    "sequence": sequence,
                    "service": "logs",
                    "api_action": action,
                    "target_arn": factory_log_group["arn"],
                    "request": request,
                    "verification_stage": stage,
                    "attempt_limit": 1,
                    "retry_permitted": False,
                    "expected_contract_digest": canonical_digest(
                        factory_log_group
                    ),
                    "absence_expected_before_create": stage.startswith("BEFORE"),
                    "mismatch_mode": "STOP_NO_ADOPTION_NO_UPDATE",
                }
            )
            sequence += 1
    return contracts


def _compile_unvalidated(
    *,
    gug363_plan: Mapping[str, Any],
    expected_gug363_plan_digest: str,
    ledger_factory_artifact_signing_contract: Mapping[str, Any],
    expected_ledger_factory_artifact_signing_contract_digest: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Compile the exact offline GUG-365 plan; never contact AWS."""

    _validate_gug363_input(
        gug363_plan,
        expected_gug363_plan_digest,
        repo_root=repo_root,
    )
    _validate_ledger_factory_artifact_signing_contract(
        contract=ledger_factory_artifact_signing_contract,
        expected_contract_digest=(
            expected_ledger_factory_artifact_signing_contract_digest
        ),
        gug363_plan=gug363_plan,
        repo_root=repo_root,
    )
    boundaries = _render_boundaries(gug363_plan=gug363_plan, repo_root=repo_root)
    boundary_arns = {item["key"]: item["arn"] for item in boundaries}
    assignments = [
        {
            "role_name": role_name,
            "role_arn": _role_arn(role_name),
            "boundary_key": boundary_key,
            "boundary_arn": boundary_arns[boundary_key],
        }
        for role_name, boundary_key in CHILD_ROLE_BOUNDARY_KEYS.items()
    ]
    service_boundary_arn = boundary_arns["service_role"]
    service_permissions_document = _service_role_permissions_policy(
        bindings=_render_bindings(gug363_plan),
        boundary_arns=boundary_arns,
    )
    if (
        len(canonical_json(service_permissions_document).encode("utf-8"))
        > _POLICY_MAX_NON_WHITESPACE_BYTES
    ):
        _fail("SERVICE_ROLE_MANAGED_POLICY_TOO_LARGE")
    function = _function_contract(gug363_plan)
    factory_function = _ledger_factory_function_contract(
        gug363_plan=gug363_plan,
        artifact_contract=ledger_factory_artifact_signing_contract,
    )
    executor_policies = {
        phase: _render_executor_policy(
            phase=phase,
            gug363_plan=gug363_plan,
            repo_root=repo_root,
            boundaries=boundaries,
            factory_function=factory_function,
        )
        for phase in (
            "POLICY_FACTORY",
            "FOUNDATION_FACTORY",
            "FUNCTION_FACTORY",
            "LEDGER_FACTORY_FUNCTION_FACTORY",
            "LEDGER_FACTORY_ACTIVATOR",
            "LEDGER_FACTORY_INVOKER",
            "LEDGER_FACTORY_REVOKER",
            "ACTIVATOR",
            "REVOCATOR",
        )
    }
    service_role = {
        "role_name": SERVICE_ROLE_NAME,
        "arn": SERVICE_ROLE_ARN,
        "path": SERVICE_ROLE_PATH,
        "max_session_duration": 3600,
        "trust_policy": cloudformation_trust_policy(),
        "trust_policy_digest": canonical_digest(cloudformation_trust_policy()),
        "permissions_boundary_arn": service_boundary_arn,
        "boundary_key": "service_role",
        "attached_policy_arns": [service_boundary_arn],
        "inline_policy_names": [],
        "managed_policy_document_digest": canonical_digest(
            service_permissions_document
        ),
        "tags": _role_tags(gug363_plan),
    }
    child_roles = _child_role_contracts(
        gug363_plan=gug363_plan, boundaries=boundaries
    )
    roles = [service_role, *child_roles]
    table = _table_contract(gug363_plan)
    factory_log_group = _ledger_factory_log_group_contract(gug363_plan)

    policy_factory_operations: list[dict[str, Any]] = []
    foundation_factory_operations: list[dict[str, Any]] = []
    function_factory_operations: list[dict[str, Any]] = []
    ledger_factory_function_factory_operations: list[dict[str, Any]] = []
    ledger_factory_activator_operations: list[dict[str, Any]] = []
    ledger_factory_invoker_operations: list[dict[str, Any]] = []
    ledger_factory_revoker_operations: list[dict[str, Any]] = []
    activator_operations: list[dict[str, Any]] = []
    sequence = 1
    for boundary in boundaries:
        request = _create_policy_request(boundary, gug363_plan=gug363_plan)
        policy_factory_operations.append(
            _operation(
                sequence=sequence,
                action="iam:CreatePolicy",
                target_arn=str(boundary["arn"]),
                request=request,
            )
        )
        sequence += 1
    for role in roles:
        foundation_factory_operations.append(
            _operation(
                sequence=sequence,
                action="iam:CreateRole",
                target_arn=str(role["arn"]),
                request=_create_role_request_from_contract(
                    role,
                    gug363_plan=gug363_plan,
                    initial_permissions_boundary_arn=boundary_arns["proof"],
                ),
            )
        )
        sequence += 1
    function_factory_operations.extend(
        _function_write_requests(function, first_sequence=sequence)
    )
    sequence += len(function_factory_operations)

    child_by_name = {str(role["role_name"]): role for role in child_roles}
    ledger_factory_function_factory_operations.extend(
        _ledger_factory_log_group_write_requests(
            factory_log_group, first_sequence=sequence
        )
    )
    sequence += len(ledger_factory_function_factory_operations)
    factory_function_writes = _function_write_requests(
        factory_function, first_sequence=sequence
    )
    ledger_factory_function_factory_operations.extend(factory_function_writes)
    sequence += len(factory_function_writes)

    factory_role = child_by_name[LEDGER_FACTORY_ROLE_NAME]
    ledger_factory_activator_operations.extend(
        [
            _operation(
                sequence=sequence,
                action="iam:AttachRolePolicy",
                target_arn=str(factory_role["arn"]),
                request={
                    "RoleName": LEDGER_FACTORY_ROLE_NAME,
                    "PolicyArn": boundary_arns["ledger_factory"],
                },
            ),
            _operation(
                sequence=sequence + 1,
                action="iam:PutRolePermissionsBoundary",
                target_arn=str(factory_role["arn"]),
                request=_put_permissions_boundary_request(
                    factory_role,
                    boundary_arn=str(boundary_arns["ledger_factory"]),
                ),
            ),
        ]
    )
    sequence += 2
    ledger_factory_invoker_operations.append(
        _operation(
            sequence=sequence,
            action="lambda:InvokeFunction",
            target_arn=str(factory_function["immutable_version_arn"]),
            request={
                "FunctionName": factory_function["immutable_version_arn"],
                "InvocationType": "RequestResponse",
                "Payload": "{}",
            },
        )
    )
    sequence += 1
    ledger_factory_revoker_operations.extend(
        [
            _operation(
                sequence=sequence,
                action="iam:PutRolePermissionsBoundary",
                target_arn=str(factory_role["arn"]),
                request=_put_permissions_boundary_request(
                    factory_role, boundary_arn=str(boundary_arns["proof"])
                ),
            ),
            _operation(
                sequence=sequence + 1,
                action="iam:DetachRolePolicy",
                target_arn=str(factory_role["arn"]),
                request={
                    "RoleName": LEDGER_FACTORY_ROLE_NAME,
                    "PolicyArn": boundary_arns["ledger_factory"],
                },
            ),
        ]
    )
    sequence += 2
    activation_attach_order = (
        BROKER_ROLE_NAME,
        CLASSIFIER_ROLE_NAME,
        APPROVER_ROLE_NAME,
        CLASSIFIER_PROOF_ROLE_NAME,
        APPROVER_PROOF_ROLE_NAME,
    )
    for role_name in activation_attach_order:
        role = child_by_name[role_name]
        activator_operations.append(
            _operation(
                sequence=sequence,
                action="iam:AttachRolePolicy",
                target_arn=str(role["arn"]),
                request=_attach_role_policy_request(role),
            )
        )
        sequence += 1
    for role_name in (
        BROKER_ROLE_NAME,
        CLASSIFIER_ROLE_NAME,
        APPROVER_ROLE_NAME,
    ):
        role = child_by_name[role_name]
        activator_operations.append(
            _operation(
                sequence=sequence,
                action="iam:PutRolePermissionsBoundary",
                target_arn=str(role["arn"]),
                request=_put_permissions_boundary_request(
                    role, boundary_arn=str(role["permissions_boundary_arn"])
                ),
            )
        )
        sequence += 1
    activator_operations.append(
        _operation(
            sequence=sequence,
            action="iam:AttachRolePolicy",
            target_arn=SERVICE_ROLE_ARN,
            request=_attach_role_policy_request(service_role),
        )
    )
    sequence += 1
    activator_operations.append(
        _operation(
            sequence=sequence,
            action="iam:PutRolePermissionsBoundary",
            target_arn=SERVICE_ROLE_ARN,
            request=_put_permissions_boundary_request(
                service_role, boundary_arn=str(service_boundary_arn)
            ),
        )
    )
    writes = [
        *policy_factory_operations,
        *foundation_factory_operations,
        *function_factory_operations,
        *ledger_factory_function_factory_operations,
        *ledger_factory_activator_operations,
        *ledger_factory_invoker_operations,
        *ledger_factory_revoker_operations,
        *activator_operations,
    ]
    revocation_operations = [
        _operation(
            sequence=index,
            action="iam:PutRolePermissionsBoundary",
            target_arn=str(role["arn"]),
            request=_put_permissions_boundary_request(
                role, boundary_arn=str(boundary_arns["proof"])
            ),
        )
        for index, role in enumerate(
            (
                child_by_name[BROKER_ROLE_NAME],
                child_by_name[CLASSIFIER_ROLE_NAME],
                child_by_name[APPROVER_ROLE_NAME],
                service_role,
            ),
            start=1,
        )
    ]

    bindings = _render_bindings(gug363_plan)
    signed_artifact_binding = {
        "bucket": bindings["signed_bucket"],
        "key": bindings["signed_key"],
        "version_id": bindings["signed_version_id"],
        "sse_kms_key_arn": bindings["signed_kms_key_arn"],
        "code_signing_config_arn": bindings["code_signing_config_arn"],
        "binding_digest": canonical_digest(
            {
                "bucket": bindings["signed_bucket"],
                "key": bindings["signed_key"],
                "version_id": bindings["signed_version_id"],
                "sse_kms_key_arn": bindings["signed_kms_key_arn"],
                "code_signing_config_arn": bindings["code_signing_config_arn"],
            }
        ),
    }
    readbacks = _readback_contracts(
        boundaries,
        roles,
        (function, factory_function),
        table,
        factory_log_group,
    )
    phase_writes = {
        "POLICY_FACTORY": policy_factory_operations,
        "FOUNDATION_FACTORY": foundation_factory_operations,
        "FUNCTION_FACTORY": function_factory_operations,
        "LEDGER_FACTORY_FUNCTION_FACTORY": (
            ledger_factory_function_factory_operations
        ),
        "LEDGER_FACTORY_ACTIVATOR": ledger_factory_activator_operations,
        "LEDGER_FACTORY_INVOKER": ledger_factory_invoker_operations,
        "LEDGER_FACTORY_REVOKER": ledger_factory_revoker_operations,
        "ACTIVATOR": activator_operations,
    }
    phase_checkpoints: dict[str, dict[str, Any]] = {
        "POLICY_FACTORY": {
            "checkpoint": "POLICY_SET_CERTIFIED_AUTHORITY_EXPIRED",
            "all_default_version_ids": "v1",
            "all_policy_versions": ["v1"],
            "permissions_policy_entities": [],
            "permissions_boundary_entities": [],
            "stable_readback_required": True,
            "authority_expiry_or_revocation_required": True,
        },
        "FOUNDATION_FACTORY": {
            "checkpoint": "FOUNDATION_PROOF_BOUND_EMPTY_CERTIFIED",
            "all_role_permissions_boundary_arn": boundary_arns["proof"],
            "all_role_attached_policy_arns": [],
            "all_role_inline_policy_names": [],
            "trust_tags_and_role_shape_exact": True,
            "post_authority_expiry_readback_required": True,
            "human_dynamodb_actions": [],
        },
        "FUNCTION_FACTORY": {
            "checkpoint": "EXACT_PRECREATED_BROKER_CERTIFIED_AUTHORITY_EXPIRED",
            "function_contract_digest": canonical_digest(function),
            "execution_role_permissions_boundary_arn": boundary_arns["proof"],
            "execution_role_attached_policy_arns": [],
            "execution_role_inline_policy_names": [],
            "signed_code_sha256": function["signed_code"][
                "lambda_code_sha256"
            ],
            "code_signing_config_exact_and_enforcing": True,
            "runtime_management_exact": function["runtime_management"],
            "reserved_concurrent_executions": 1,
            "versions": ["$LATEST"],
            "aliases": [],
            "function_urls": [],
            "resource_policy": "ABSENT_RESOURCE_NOT_FOUND",
            "stable_post_expiry_readback_required": True,
            "raw_environment_persistence_permitted": False,
            "code_location_persistence_permitted": False,
            "unknown_outcome_mode": "RECONCILE_ONLY_NO_RETRY_NO_ACTIVATION",
        },
        "LEDGER_FACTORY_FUNCTION_FACTORY": {
            "checkpoint": (
                "EXACT_IMMUTABLE_LEDGER_FACTORY_AND_LOG_GROUP_CERTIFIED_"
                "AUTHORITY_EXPIRED"
            ),
            "function_contract_digest": canonical_digest(factory_function),
            "log_group_contract_digest": canonical_digest(factory_log_group),
            "execution_role_permissions_boundary_arn": boundary_arns["proof"],
            "execution_role_attached_policy_arns": [],
            "execution_role_inline_policy_names": [],
            "signed_code_sha256": factory_function["signed_code"][
                "lambda_code_sha256"
            ],
            "immutable_version": _FACTORY_VERSION,
            "environment": {},
            "runtime_management_exact": factory_function[
                "runtime_management"
            ],
            "reserved_concurrent_executions": 1,
            "log_group_retention_in_days": 365,
            "stable_post_expiry_readback_required": True,
            "unknown_outcome_mode": "RECONCILE_ONLY_NO_RETRY_NO_ACTIVATION",
        },
        "LEDGER_FACTORY_ACTIVATOR": {
            "checkpoint": "LEDGER_FACTORY_ONLY_ACTIVE_AUTHORITY_EXPIRED",
            "role_name": LEDGER_FACTORY_ROLE_NAME,
            "attached_policy_arns": [boundary_arns["ledger_factory"]],
            "permissions_boundary_arn": boundary_arns["ledger_factory"],
            "attach_before_boundary_swap_required": True,
            "main_role_activation_permitted": False,
            "stable_post_expiry_readback_required": True,
        },
        "LEDGER_FACTORY_INVOKER": {
            "checkpoint": "CAUSAL_LEDGER_FACTORY_RECEIPT_CERTIFIED_AUTHORITY_EXPIRED",
            "qualified_function_arn": factory_function[
                "immutable_version_arn"
            ],
            "invocation_type": "RequestResponse",
            "payload": {},
            "sdk_retry_mode": "DISABLED_MAX_ATTEMPTS_1",
            "accepted_statuses": ["CREATED", "CREATED_RECONCILED"],
            "accepted_create_table_call_count": 1,
            "accepted_update_pitr_call_count": 1,
            "already_exact_mode": "BLOCK_OWNER_RECOVERY_NO_ACTIVATION",
            "receipt_sha256_required": True,
            "receipt_contract_sha256": ledger_factory.CONTRACT_SHA256,
            "main_role_activation_permitted": False,
        },
        "LEDGER_FACTORY_REVOKER": {
            "checkpoint": "LEDGER_FACTORY_PROOF_BOUND_DETACHED_CERTIFIED",
            "permissions_boundary_arn": boundary_arns["proof"],
            "attached_policy_arns": [],
            "inline_policy_names": [],
            "proof_boundary_write_is_first_mutation": True,
            "detach_is_second_mutation": True,
            "requires_accepted_causal_factory_receipt": True,
            "stable_post_expiry_readback_required": True,
            "main_role_activation_permitted_after_checkpoint_only": True,
        },
        "ACTIVATOR": {
            "checkpoint": "FINAL_ROLE_POLICY_SET_CERTIFIED",
            "requires_broker_function_evidence_digest": True,
            "requires_function_configurator_checkpoint_digest": True,
            "requires_matching_gug363_pre_function_binding_sha256": (
                _gug363_pre_function_binding_digest(gug363_plan)
            ),
            "requires_function_configurator_authority_expired": True,
            "requires_post_configurator_stable_function_readback": True,
            "each_persistent_main_role_has_exactly_one_attachment_equal_to_boundary": True,
            "ledger_factory_role_proof_bound_and_detached": True,
            "all_inline_policy_names": [],
            "service_role_boundary_update_is_last_mutation": True,
            "stable_readback_required": True,
            "authority_expiry_or_revocation_required": True,
            "post_activation_bundle_readback_required": {
                "managed_policies": 6,
                "roles": 7,
                "ledger_table": 1,
                "broker_function": 1,
                "ledger_factory_function": 1,
                "ledger_factory_log_group": 1,
                "raw_environment_persistence_permitted": False,
                "code_location_persistence_permitted": False,
            },
        },
    }
    authorization_phases: list[dict[str, Any]] = []
    proof_boundary_contract = next(
        item for item in boundaries if item["key"] == "proof"
    )
    broker_role_contract = child_by_name[BROKER_ROLE_NAME]
    for index, (phase, mutations) in enumerate(phase_writes.items(), start=1):
        executor_policy = executor_policies[phase]
        authority_requirement = _executor_effective_authority_requirement(
            executor_policy, phase=phase
        )
        authorization_phases.append(
            {
            "sequence": index,
            "phase": phase,
            "executor_policy": executor_policy,
            "executor_policy_digest": canonical_digest(executor_policy),
            "executor_effective_authority_requirement": authority_requirement,
            "executor_effective_authority_requirement_digest": canonical_digest(
                authority_requirement
            ),
            "operations": _phase_operation_contract(
                phase=phase,
                writes=mutations,
                proof_boundary=(
                    proof_boundary_contract
                    if phase in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                        "LEDGER_FACTORY_REVOKER",
                    }
                    else None
                ),
                function=(
                    function
                    if phase in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                    }
                    else None
                ),
                broker_role=(
                    broker_role_contract
                    if phase in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                    }
                    else None
                ),
                factory_function=(
                    factory_function
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
                factory_role=(
                    factory_role
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
                factory_log_group=(
                    factory_log_group
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
            ),
            "operation_digest": canonical_digest(
                _phase_operation_contract(
                    phase=phase,
                    writes=mutations,
                    proof_boundary=(
                        proof_boundary_contract
                        if phase in {
                            "FUNCTION_FACTORY",
                            "LEDGER_FACTORY_FUNCTION_FACTORY",
                            "LEDGER_FACTORY_REVOKER",
                        }
                        else None
                    ),
                    function=(
                        function
                        if phase in {
                            "FUNCTION_FACTORY",
                            "LEDGER_FACTORY_FUNCTION_FACTORY",
                        }
                        else None
                    ),
                    broker_role=(
                        broker_role_contract
                        if phase in {
                            "FUNCTION_FACTORY",
                            "LEDGER_FACTORY_FUNCTION_FACTORY",
                        }
                        else None
                    ),
                    factory_function=(
                        factory_function
                        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                        else None
                    ),
                    factory_role=(
                        factory_role
                        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                        else None
                    ),
                    factory_log_group=(
                        factory_log_group
                        if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                        else None
                    ),
                )
            ),
            "mutations": mutations,
            "mutation_digest": canonical_digest(mutations),
            "checkpoint": phase_checkpoints[phase],
            "checkpoint_digest": canonical_digest(phase_checkpoints[phase]),
            "checkpoint_required_before_next_phase": True,
            "same_session_reuse_permitted": False,
            "authority_overlap_permitted": False,
            }
        )
    revocation_phase_operations = _phase_operation_contract(
        phase="REVOCATOR",
        writes=revocation_operations,
        proof_boundary=proof_boundary_contract,
    )
    revocation_authority_requirement = _executor_effective_authority_requirement(
        executor_policies["REVOCATOR"], phase="REVOCATOR"
    )
    revocation = {
        "phase": "REVOCATOR",
        "executor_policy": executor_policies["REVOCATOR"],
        "executor_policy_digest": canonical_digest(
            executor_policies["REVOCATOR"]
        ),
        "executor_effective_authority_requirement": (
            revocation_authority_requirement
        ),
        "executor_effective_authority_requirement_digest": canonical_digest(
            revocation_authority_requirement
        ),
        "operations": revocation_phase_operations,
        "operation_digest": canonical_digest(revocation_phase_operations),
        "mutations": revocation_operations,
        "mutation_digest": canonical_digest(revocation_operations),
        "checkpoint": {
            "checkpoint": "ACTIVE_ROLE_BOUNDARIES_REVOKED_TO_PROOF",
            "roles": [
                BROKER_ROLE_NAME,
                CLASSIFIER_ROLE_NAME,
                APPROVER_ROLE_NAME,
                SERVICE_ROLE_NAME,
            ],
            "permissions_boundary_arn": boundary_arns["proof"],
            "proof_policy_default_version_id": "v1",
            "proof_policy_versions": ["v1"],
            "proof_policy_document_digest": proof_boundary_contract[
                "document_digest"
            ],
            "proof_policy_verified_before_first_write": True,
            "proof_policy_verified_after_all_writes": True,
            "proof_policy_mismatch_mode": "STOP_NO_REVOCATION",
            "stable_readback_required": True,
        },
        "forward_execution_permitted": False,
        "same_session_reuse_permitted": False,
    }
    plan: dict[str, Any] = {
        "record_type": PLAN_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "source_issue": SOURCE_ISSUE,
        "environment": "synthetic-non-production",
        "production": False,
        "deployment_authorized": False,
        "aws_calls_performed": False,
        "gug363_pre_function_binding_sha256": (
            _gug363_pre_function_binding_digest(gug363_plan)
        ),
        "gug363_artifact_signing_contract_digest": gug363_plan[
            "artifact_signing_contract_digest"
        ],
        "ledger_factory_artifact_signing_contract": dict(
            ledger_factory_artifact_signing_contract
        ),
        "ledger_factory_artifact_signing_contract_digest": (
            expected_ledger_factory_artifact_signing_contract_digest
        ),
        "ledger_factory_artifact_signing_evidence_digest": (
            _ledger_factory_signing_evidence_digest(
                ledger_factory_artifact_signing_contract
            )
        ),
        "target": {
            "authority_account_id": AUTHORITY_ACCOUNT_ID,
            "region": REGION,
            "partition": PARTITION,
            "service_role_arn": SERVICE_ROLE_ARN,
        },
        "signed_artifact_binding": signed_artifact_binding,
        "boundaries": boundaries,
        "boundary_set_digest": canonical_digest(boundaries),
        "child_role_boundary_assignments": assignments,
        "child_role_boundary_assignment_digest": canonical_digest(assignments),
        "service_role": service_role,
        "service_role_digest": canonical_digest(service_role),
        "child_roles": child_roles,
        "child_role_set_digest": canonical_digest(child_roles),
        "ledger_table": table,
        "ledger_table_digest": canonical_digest(table),
        "broker_function": function,
        "broker_function_digest": canonical_digest(function),
        "ledger_factory_function": factory_function,
        "ledger_factory_function_digest": canonical_digest(factory_function),
        "ledger_factory_log_group": factory_log_group,
        "ledger_factory_log_group_digest": canonical_digest(factory_log_group),
        "authorization_phases": authorization_phases,
        "authorization_phase_digest": canonical_digest(authorization_phases),
        "revocation": revocation,
        "revocation_digest": canonical_digest(revocation),
        "allowed_mutations": list(ALLOWED_MUTATIONS),
        "prohibited_mutations": list(PROHIBITED_MUTATIONS),
        "prohibited_standalone_mutations": list(PROHIBITED_STANDALONE_MUTATIONS),
        "planned_iam_writes": writes,
        "planned_iam_write_digest": canonical_digest(writes),
        "planned_readbacks": readbacks,
        "planned_readback_digest": canonical_digest(readbacks),
        "preexisting_object_mode": "STOP_NO_ADOPTION_NO_REPAIR",
        "ambiguous_outcome_mode": "STOP_AND_RECONCILE_READ_ONLY",
        "mutation_retry_permitted": False,
        "update_permitted": False,
        "delete_permitted": False,
        "repair_permitted": False,
        "ledger_factory_causal_receipt_gate": phase_checkpoints[
            "LEDGER_FACTORY_INVOKER"
        ],
        "residual_risk": (
            "Lambda RequestResponse and client retry mode cannot be enforced "
            "by IAM alone; the exact qualified-version operation, one-shot "
            "attempt ledger, causal receipt and immediate separated revocation "
            "are mandatory live controls"
        ),
        "plan_digest": "",
    }
    plan["plan_digest"] = canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )
    return plan


def compile_service_role_materialization_plan(
    *,
    gug363_plan: Mapping[str, Any],
    expected_gug363_plan_digest: str,
    ledger_factory_artifact_signing_contract: Mapping[str, Any],
    expected_ledger_factory_artifact_signing_contract_digest: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Compile and self-validate the exact offline GUG-365 plan."""

    plan = _compile_unvalidated(
        gug363_plan=gug363_plan,
        expected_gug363_plan_digest=expected_gug363_plan_digest,
        ledger_factory_artifact_signing_contract=(
            ledger_factory_artifact_signing_contract
        ),
        expected_ledger_factory_artifact_signing_contract_digest=(
            expected_ledger_factory_artifact_signing_contract_digest
        ),
        repo_root=repo_root,
    )
    validate_service_role_materialization_plan(
        plan,
        gug363_plan=gug363_plan,
        expected_gug363_plan_digest=expected_gug363_plan_digest,
        ledger_factory_artifact_signing_contract=(
            ledger_factory_artifact_signing_contract
        ),
        expected_ledger_factory_artifact_signing_contract_digest=(
            expected_ledger_factory_artifact_signing_contract_digest
        ),
        repo_root=repo_root,
    )
    return plan


def validate_service_role_materialization_plan(
    plan: Mapping[str, Any],
    *,
    gug363_plan: Mapping[str, Any],
    expected_gug363_plan_digest: str,
    ledger_factory_artifact_signing_contract: Mapping[str, Any],
    expected_ledger_factory_artifact_signing_contract_digest: str,
    repo_root: Path,
) -> None:
    """Fail closed by recompiling the complete deterministic contract."""

    if not isinstance(plan, Mapping):
        _fail("PLAN_FIELDS_INVALID")
    expected = _compile_unvalidated(
        gug363_plan=gug363_plan,
        expected_gug363_plan_digest=expected_gug363_plan_digest,
        ledger_factory_artifact_signing_contract=(
            ledger_factory_artifact_signing_contract
        ),
        expected_ledger_factory_artifact_signing_contract_digest=(
            expected_ledger_factory_artifact_signing_contract_digest
        ),
        repo_root=repo_root,
    )
    if set(plan) != set(expected):
        _fail("PLAN_FIELDS_INVALID")
    digest_fields = (
        "gug363_pre_function_binding_sha256",
        "gug363_artifact_signing_contract_digest",
        "ledger_factory_artifact_signing_contract_digest",
        "ledger_factory_artifact_signing_evidence_digest",
        "boundary_set_digest",
        "child_role_boundary_assignment_digest",
        "service_role_digest",
        "child_role_set_digest",
        "ledger_table_digest",
        "broker_function_digest",
        "ledger_factory_function_digest",
        "ledger_factory_log_group_digest",
        "authorization_phase_digest",
        "revocation_digest",
        "planned_iam_write_digest",
        "planned_readback_digest",
        "plan_digest",
    )
    for field in digest_fields:
        _require_digest(plan.get(field), "PLAN_DIGEST_INVALID")
    section_codes = {
        "planned_iam_writes": "PLANNED_IAM_WRITES_INVALID",
        "planned_readbacks": "PLANNED_READBACKS_INVALID",
        "boundaries": "BOUNDARY_SET_INVALID",
        "child_role_boundary_assignments": "BOUNDARY_ASSIGNMENT_INVALID",
        "service_role": "SERVICE_ROLE_CONTRACT_INVALID",
        "child_roles": "CHILD_ROLE_SET_INVALID",
        "ledger_table": "LEDGER_TABLE_CONTRACT_INVALID",
        "broker_function": "BROKER_FUNCTION_CONTRACT_INVALID",
        "ledger_factory_function": "LEDGER_FACTORY_FUNCTION_CONTRACT_INVALID",
        "ledger_factory_log_group": "LEDGER_FACTORY_LOG_GROUP_CONTRACT_INVALID",
        "ledger_factory_artifact_signing_contract": (
            "LEDGER_FACTORY_SIGNING_CONTRACT_INVALID"
        ),
        "authorization_phases": "AUTHORIZATION_PHASES_INVALID",
        "revocation": "REVOCATION_CONTRACT_INVALID",
        "signed_artifact_binding": "SIGNED_ARTIFACT_PLAN_BINDING_INVALID",
        "ledger_factory_causal_receipt_gate": (
            "LEDGER_FACTORY_CAUSAL_RECEIPT_GATE_INVALID"
        ),
    }
    for field, code in section_codes.items():
        if plan.get(field) != expected[field]:
            _fail(code)
    for field, value in expected.items():
        if field not in section_codes and plan.get(field) != value:
            _fail("PLAN_CONTENT_INVALID")
    calculated = canonical_digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )
    if plan.get("plan_digest") != calculated:
        _fail("PLAN_DIGEST_MISMATCH")


def expected_normalized_inventory(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact normalized final IAM and DynamoDB inventory."""

    boundaries = plan.get("boundaries")
    service_role = plan.get("service_role")
    child_roles = plan.get("child_roles")
    table = plan.get("ledger_table")
    function = plan.get("broker_function")
    factory_function = plan.get("ledger_factory_function")
    factory_log_group = plan.get("ledger_factory_log_group")
    if (
        not isinstance(boundaries, list)
        or not isinstance(service_role, Mapping)
        or not isinstance(child_roles, list)
        or not isinstance(table, Mapping)
        or not isinstance(function, Mapping)
        or not isinstance(factory_function, Mapping)
        or not isinstance(factory_log_group, Mapping)
    ):
        _fail("PLAN_NESTING_INVALID")
    roles = [service_role, *child_roles]
    role_by_boundary: dict[str, list[str]] = {}
    for role in roles:
        if not isinstance(role, Mapping):
            _fail("PLAN_NESTING_INVALID")
        role_by_boundary.setdefault(str(role["boundary_key"]), []).append(
            str(role["arn"])
        )
    policies: dict[str, Any] = {}
    for boundary in boundaries:
        arn = str(boundary["arn"])
        entity_arns = role_by_boundary.get(str(boundary["key"]), [])
        policies[arn] = {
            "arn": arn,
            "policy_name": boundary["policy_name"],
            "path": MANAGED_POLICY_PATH,
            "default_version_id": "v1",
            "document": boundary["document"],
            "versions": ["v1"],
            "permissions_policy_role_arns": entity_arns,
            "permissions_boundary_role_arns": entity_arns,
            "tags": boundary["tags"],
        }
    normalized_roles = {
        str(role["arn"]): {
            "arn": role["arn"],
            "role_name": role["role_name"],
            "path": role["path"],
            "max_session_duration": role["max_session_duration"],
            "trust_policy": role["trust_policy"],
            "permissions_boundary_arn": role["permissions_boundary_arn"],
            "attached_policy_arns": role["attached_policy_arns"],
            "inline_policy_names": [],
            "inline_policy_documents": {},
            "tags": role["tags"],
            "role_last_used": None,
        }
        for role in roles
    }
    normalized_table = {
        "table_name": table["table_name"],
        "arn": table["arn"],
        "table_status": "ACTIVE",
        "billing_mode": table["billing_mode"],
        "attribute_definitions": table["attribute_definitions"],
        "key_schema": table["key_schema"],
        "deletion_protection_enabled": table["deletion_protection_enabled"],
        "sse_specification": table["sse_specification"],
        "kms_key_contract": table["kms_key_contract"],
        "table_class": table["table_class"],
        "resource_policy": table["resource_policy"],
        "point_in_time_recovery": table["point_in_time_recovery"],
        "time_to_live": table["time_to_live"],
        "latest_stream_label": table["latest_stream_label"],
        "global_secondary_indexes": table["global_secondary_indexes"],
        "local_secondary_indexes": table["local_secondary_indexes"],
        "replicas": table["replicas"],
        "tags": table["tags"],
        "item_count": 0,
        "scan_count": 0,
        "scan_scanned_count": 0,
        "scan_last_evaluated_key": None,
    }
    return {
        "policies": policies,
        "roles": normalized_roles,
        "ledger_table": normalized_table,
        "broker_function": dict(function),
        "ledger_factory_function": dict(factory_function),
        "ledger_factory_log_group": dict(factory_log_group),
    }


def classify_preexisting_inventory(
    plan: Mapping[str, Any],
    observed: Mapping[str, Any],
    *,
    expected_authorized_plan_digest: str | None = None,
    executor_authority_evidence: Mapping[str, Any] | None = None,
    expected_executor_authority_phase: str | None = None,
    expected_caller_arn_digest: str | None = None,
    expected_executor_authority_evidence_digest: str | None = None,
    authority_evaluation_at: datetime | None = None,
    causal_phase_records: Sequence[Mapping[str, Any]] | None = None,
    expected_causal_phase_bindings: Sequence[Mapping[str, Any]] | None = None,
    expected_causal_ledger_bundle_digest: str | None = None,
    causal_phase_authority_evidence: Sequence[Mapping[str, Any]] | None = None,
    causal_phase_authority_evaluation_at: Sequence[datetime] | None = None,
    expected_initial_bundle_absence_digest: str | None = None,
    ledger_factory_causal_receipt: Mapping[str, Any] | None = None,
    expected_ledger_factory_causal_receipt_digest: str | None = None,
) -> dict[str, Any]:
    """Classify normalized readback without authorizing adoption or repair.

    ``observed`` must contain every planned policy ARN, role ARN, and table;
    each value is either ``None`` (provider-proven absence) or the normalized
    object returned by :func:`expected_normalized_inventory`.
    """

    plan = _canonical_snapshot(plan, "CLASSIFIER_PLAN_SNAPSHOT_INVALID")
    observed = _canonical_snapshot(
        observed, "CLASSIFIER_OBSERVED_SNAPSHOT_INVALID"
    )
    executor_authority_evidence = (
        None
        if executor_authority_evidence is None
        else _canonical_snapshot(
            executor_authority_evidence,
            "CLASSIFIER_AUTHORITY_SNAPSHOT_INVALID",
        )
    )
    causal_phase_records = (
        None
        if causal_phase_records is None
        else _canonical_snapshot(
            causal_phase_records, "CLASSIFIER_CAUSAL_RECORDS_SNAPSHOT_INVALID"
        )
    )
    expected_causal_phase_bindings = (
        None
        if expected_causal_phase_bindings is None
        else _canonical_snapshot(
            expected_causal_phase_bindings,
            "CLASSIFIER_CAUSAL_BINDINGS_SNAPSHOT_INVALID",
        )
    )
    causal_phase_authority_evidence = (
        None
        if causal_phase_authority_evidence is None
        else _canonical_snapshot(
            causal_phase_authority_evidence,
            "CLASSIFIER_CAUSAL_AUTHORITY_SNAPSHOT_INVALID",
        )
    )
    ledger_factory_causal_receipt = (
        None
        if ledger_factory_causal_receipt is None
        else _canonical_snapshot(
            ledger_factory_causal_receipt,
            "CLASSIFIER_FACTORY_RECEIPT_SNAPSHOT_INVALID",
        )
    )
    if authority_evaluation_at is not None:
        authority_evaluation_at = _authority_timestamp(
            authority_evaluation_at, "AUTHORITY_EVALUATION_TIME_INVALID"
        )
    if causal_phase_authority_evaluation_at is not None:
        if isinstance(causal_phase_authority_evaluation_at, (str, bytes)):
            _fail("CLASSIFIER_CAUSAL_EVALUATION_SET_INVALID")
        causal_phase_authority_evaluation_at = tuple(
            _authority_timestamp(item, "AUTHORITY_EVALUATION_TIME_INVALID")
            for item in causal_phase_authority_evaluation_at
        )

    authority_inputs = (
        executor_authority_evidence,
        expected_executor_authority_phase,
        expected_caller_arn_digest,
        expected_executor_authority_evidence_digest,
        authority_evaluation_at,
    )
    causal_inputs = (
        causal_phase_records,
        expected_causal_phase_bindings,
        expected_causal_ledger_bundle_digest,
        causal_phase_authority_evidence,
        causal_phase_authority_evaluation_at,
        expected_initial_bundle_absence_digest,
        ledger_factory_causal_receipt,
        expected_ledger_factory_causal_receipt_digest,
    )
    if not all(value is None for value in (*authority_inputs, *causal_inputs)):
        if expected_authorized_plan_digest is None:
            _fail("EXPECTED_AUTHORIZED_PLAN_DIGEST_REQUIRED")
        authorized_plan_digest = _require_digest(
            expected_authorized_plan_digest,
            "EXPECTED_AUTHORIZED_PLAN_DIGEST_INVALID",
        )
        if (
            plan.get("plan_digest") != authorized_plan_digest
            or canonical_digest(
                {key: value for key, value in plan.items() if key != "plan_digest"}
            )
            != authorized_plan_digest
        ):
            _fail("AUTHORIZED_PLAN_DIGEST_MISMATCH")
    else:
        authorized_plan_digest = None
    if all(value is None for value in authority_inputs):
        authorization_bound = False
    elif any(value is None for value in authority_inputs):
        _fail("EXECUTION_AUTHORIZATION_BINDING_INVALID")
    else:
        assert isinstance(executor_authority_evidence, Mapping)
        assert isinstance(expected_executor_authority_phase, str)
        assert isinstance(expected_caller_arn_digest, str)
        assert isinstance(expected_executor_authority_evidence_digest, str)
        assert isinstance(authority_evaluation_at, datetime)
        validate_executor_authority_evidence(
            plan,
            phase=expected_executor_authority_phase,
            evidence=executor_authority_evidence,
            expected_caller_arn_digest=expected_caller_arn_digest,
            expected_evidence_digest=expected_executor_authority_evidence_digest,
            evaluation_at=authority_evaluation_at,
        )
        authorization_bound = True
    if all(value is None for value in causal_inputs):
        causal_ledger_bound = False
    elif any(value is None for value in causal_inputs):
        _fail("CAUSAL_LEDGER_BINDING_INVALID")
    else:
        assert isinstance(causal_phase_records, Sequence)
        assert isinstance(expected_causal_phase_bindings, Sequence)
        assert isinstance(expected_causal_ledger_bundle_digest, str)
        assert isinstance(causal_phase_authority_evidence, Sequence)
        assert isinstance(causal_phase_authority_evaluation_at, Sequence)
        assert isinstance(expected_initial_bundle_absence_digest, str)
        assert isinstance(ledger_factory_causal_receipt, Mapping)
        assert isinstance(expected_ledger_factory_causal_receipt_digest, str)
        expected_phases = [
            item.get("phase") for item in plan.get("authorization_phases", [])
        ]
        if (
            tuple(expected_phases) != phase_ledger.FORWARD_PHASES
            or
            len(causal_phase_records) != len(expected_phases)
            or len(expected_causal_phase_bindings) != len(expected_phases)
            or len(causal_phase_authority_evidence) != len(expected_phases)
            or len(causal_phase_authority_evaluation_at) != len(expected_phases)
            or [record.get("phase") for record in causal_phase_records]
            != expected_phases
            or [binding.get("phase") for binding in expected_causal_phase_bindings]
            != expected_phases
            or [evidence.get("phase") for evidence in causal_phase_authority_evidence]
            != expected_phases
        ):
            _fail("CAUSAL_PHASE_AUTHORITY_SET_INVALID")
        for index, (record, binding, evidence, evaluation_input) in enumerate(
            zip(
                causal_phase_records,
                expected_causal_phase_bindings,
                causal_phase_authority_evidence,
                causal_phase_authority_evaluation_at,
                strict=True,
            )
        ):
            if not isinstance(binding, Mapping) or not isinstance(record, Mapping):
                _fail("CAUSAL_PHASE_AUTHORITY_BINDING_INVALID")
            evaluation = _authority_timestamp(
                evaluation_input, "AUTHORITY_EVALUATION_TIME_INVALID"
            )
            if evaluation != _authority_timestamp(
                record.get("authority_evaluation_at"),
                "AUTHORITY_EVALUATION_TIME_INVALID",
            ):
                _fail("CAUSAL_PHASE_AUTHORITY_EVALUATION_BINDING_INVALID")
            validate_executor_authority_evidence(
                plan,
                phase=str(binding.get("phase")),
                evidence=evidence,
                expected_caller_arn_digest=str(binding.get("caller_arn_digest")),
                expected_evidence_digest=str(
                    binding.get("executor_authority_evidence_digest")
                ),
                evaluation_at=evaluation,
                ledger_not_before=_authority_timestamp(
                    record.get("not_before"), "LEDGER_NOT_BEFORE_INVALID"
                ),
                ledger_expires_at=_authority_timestamp(
                    record.get("expires_at"), "LEDGER_EXPIRES_AT_INVALID"
                ),
            )
            if (
                record.get("caller_arn_digest")
                != binding.get("caller_arn_digest")
                or record.get("executor_authority_evidence_digest")
                != binding.get("executor_authority_evidence_digest")
                or record.get("authority_session_identifier_digest")
                != evidence.get("session_identifier_digest")
                or record.get("authority_session_issued_at")
                != evidence.get("session_issued_at")
                or record.get("authority_session_expires_at")
                != evidence.get("session_expires_at")
                or record.get("authority_evidence_collected_at")
                != evidence.get("evidence_collected_at")
            ):
                _fail("CAUSAL_PHASE_AUTHORITY_BINDING_INVALID")
        validate_ledger_factory_causal_receipt(
            plan,
            receipt=ledger_factory_causal_receipt,
            expected_receipt_sha256=(
                expected_ledger_factory_causal_receipt_digest
            ),
        )
        invoker_index = next(
            (
                index
                for index, item in enumerate(plan["authorization_phases"])
                if item.get("phase") == "LEDGER_FACTORY_INVOKER"
            ),
            -1,
        )
        if invoker_index < 0:
            _fail("LEDGER_FACTORY_INVOKER_PHASE_MISSING")
        invoker_operations = plan["authorization_phases"][invoker_index][
            "operations"
        ]
        invoke_sequences = [
            position
            for position, operation in enumerate(invoker_operations, 1)
            if operation.get("api_action") == "InvokeFunction"
            or operation.get("action") == "lambda:InvokeFunction"
        ]
        invoker_record = causal_phase_records[invoker_index]
        if len(invoke_sequences) != 1:
            _fail("LEDGER_FACTORY_INVOKER_OPERATION_INVALID")
        invoke_sequence = invoke_sequences[0]
        matching_outcomes = [
            item
            for item in invoker_record.get("operation_outcomes", [])
            if item.get("operation_sequence") == invoke_sequence
        ]
        if (
            len(matching_outcomes) != 1
            or matching_outcomes[0].get("provider_result_digest")
            != expected_ledger_factory_causal_receipt_digest
        ):
            _fail("LEDGER_FACTORY_RECEIPT_OUTCOME_BINDING_MISMATCH")
        try:
            phase_ledger.validate_consumed_causal_bundle(
                plan,
                expected_plan_digest=str(authorized_plan_digest),
                expected_bundle_digest=expected_causal_ledger_bundle_digest,
                phase_records=causal_phase_records,
                expected_phase_bindings=expected_causal_phase_bindings,
                expected_initial_bundle_absence_digest=(
                    expected_initial_bundle_absence_digest
                ),
            )
        except phase_ledger.PhaseLedgerError as exc:
            raise ServiceRoleMaterializationError(
                "CAUSAL_LEDGER_BINDING_INVALID"
            ) from exc
        causal_ledger_bound = True
    expected = expected_normalized_inventory(plan)
    if not isinstance(observed, Mapping) or set(observed) != {
        "policies",
        "roles",
        "ledger_table",
        "broker_function",
        "ledger_factory_function",
        "ledger_factory_log_group",
    }:
        _fail("PREEXISTING_INVENTORY_INVALID")
    policies = observed.get("policies")
    roles = observed.get("roles")
    if not isinstance(policies, Mapping) or set(policies) != set(expected["policies"]):
        _fail("PREEXISTING_INVENTORY_INVALID")
    if not isinstance(roles, Mapping) or set(roles) != set(expected["roles"]):
        _fail("PREEXISTING_INVENTORY_INVALID")
    table = observed.get("ledger_table")
    function = observed.get("broker_function")
    factory_function = observed.get("ledger_factory_function")
    factory_log_group = observed.get("ledger_factory_log_group")
    objects = list(policies.values()) + list(roles.values()) + [
        table,
        function,
        factory_function,
        factory_log_group,
    ]
    if all(value is None for value in objects):
        phase_precondition_met = (
            not authorization_bound
            or expected_executor_authority_phase == "POLICY_FACTORY"
        )
        return {
            "classification": (
                "ABSENT_READY"
                if authorization_bound and phase_precondition_met
                else "NOT_AUTHORIZED"
            ),
            "observed_state": "ALL_TARGETS_ABSENT",
            "reason_code": (
                "PHASE_PRECONDITION_MISSING"
                if authorization_bound and not phase_precondition_met
                else "AUTHORIZED_FIRST_PHASE"
                if authorization_bound
                else "EXECUTION_AUTHORIZATION_REQUIRED"
            ),
            "writes_permitted_by_state": True,
            "writes_authorized": authorization_bound and phase_precondition_met,
            "adoption_permitted": False,
            "repair_permitted": False,
        }
    exact = all(
        policies[arn] == expected_value
        for arn, expected_value in expected["policies"].items()
    ) and all(
        roles[arn] == expected_value
        for arn, expected_value in expected["roles"].items()
    ) and table == expected["ledger_table"] and function == expected[
        "broker_function"
    ] and factory_function == expected["ledger_factory_function"] and factory_log_group == expected[
        "ledger_factory_log_group"
    ]
    return {
        "classification": (
            "EXACT_PRESENT_NO_TOUCH"
            if exact and causal_ledger_bound
            else "PREEXISTING_NO_TOUCH"
            if exact
            else "DRIFT_BLOCKED_NO_REPAIR"
        ),
        "writes_permitted_by_state": False,
        "writes_authorized": False,
        "causal_ledger_bound": exact and causal_ledger_bound,
        "adoption_permitted": False,
        "repair_permitted": False,
    }


def effective_allow_actions(
    boundary: Mapping[str, Any], identity_policy: Mapping[str, Any]
) -> tuple[str, ...]:
    """Conservatively show the action cap imposed by a boundary.

    This is not an IAM policy simulator.  It is an offline negative-control
    helper for reviewed documents: an identity policy granting ``*`` can yield
    no action outside the boundary's explicit Allow actions, and any explicit
    boundary Deny is removed from the result.
    """

    boundary_statements = _statements(boundary)
    identity_statements = _statements(identity_policy)
    boundary_allows = {
        action
        for statement in boundary_statements
        if statement.get("Effect") == "Allow"
        for action in _strings(statement.get("Action"), "BOUNDARY_ACTION_INVALID")
    }
    boundary_denies = {
        action
        for statement in boundary_statements
        if statement.get("Effect") == "Deny"
        for action in _strings(statement.get("Action"), "BOUNDARY_ACTION_INVALID")
    }
    identity_allows = {
        action
        for statement in identity_statements
        if statement.get("Effect") == "Allow"
        for action in _strings(statement.get("Action"), "IDENTITY_ACTION_INVALID")
    }
    effective = {
        boundary_action
        for boundary_action in boundary_allows
        if any(fnmatchcase(boundary_action, pattern) for pattern in identity_allows)
        and not any(fnmatchcase(boundary_action, pattern) for pattern in boundary_denies)
    }
    return tuple(sorted(effective))


# Short aliases for callers that use the GUG-363 naming convention.
build_materialization_plan = compile_service_role_materialization_plan
validate_materialization_plan = validate_service_role_materialization_plan
