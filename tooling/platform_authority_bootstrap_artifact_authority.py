"""External CAS authority for normal platform-authority bootstrap artifacts.

The Plan and Approval files remain private operational evidence.  Their local
digests make accidental changes visible, but only the service-owned ledger
state created through the three version-pinned broker entrypoints grants
authority.  This module keeps the contract and state machine deterministic;
provider clients are injected and are never created by the pure validators.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from tooling.platform_authority_bootstrap import (
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    BootstrapBinding,
    ChangeSetIdentity,
    build_bootstrap_plan,
    canonical_digest,
    change_set_identity_from_arn,
    require_exact_empty_review_stack,
    validate_bootstrap_change_set_name,
)
from tooling.platform_authority_bootstrap_identity_proof import (
    BootstrapIdentityProofBinding,
    BootstrapIdentityProofVerifier,
    BootstrapIdentityProofError,
    validate_identity_proof_receipt,
)


PLAN_DOMAIN = "scanalyze.platform-authority.bootstrap.plan.v2"
APPROVAL_DOMAIN = "scanalyze.platform-authority.bootstrap.approval.v2"
LEDGER_DOMAIN = "scanalyze.platform-authority.bootstrap.artifact-authority.v1"
RECEIPT_DOMAIN = "scanalyze.platform-authority.bootstrap.authority-receipt.v1"
KEY_DOMAIN = "scanalyze.platform-authority.bootstrap.authority-key.v1"
TRUST_CONTRACT_VERSION = "1"
TRUST_ROOT_GENERATION = 1
TRUST_ALGORITHM = "AWS_DYNAMODB_STRONGLY_CONSISTENT_CAS_SHA256"
NONCURRENT_VERSION_RETENTION_DAYS = "365"
LEDGER_TABLE_NAME = "scanalyze-platform-authority-bootstrap-artifacts"
PLAN_AUTHORITY_FUNCTION = "scanalyze-platform-authority-bootstrap-plan-authority"
APPROVAL_AUTHORITY_FUNCTION = (
    "scanalyze-platform-authority-bootstrap-approval-authority"
)
APPLY_EXECUTOR_FUNCTION = "scanalyze-platform-authority-bootstrap-apply-executor"
BROKER_FUNCTION_VERSION = "1"
MAX_OPERATIONAL_ARTIFACT_BYTES = 64 * 1024
NONCE = re.compile(r"^[a-f0-9]{64}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
CANONICAL_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


PLAN_V2_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "domain_separator",
        "trust_contract_version",
        "trust_root_id",
        "trust_root_generation",
        "trust_algorithm",
        "authority_record_id",
        "artifact_nonce",
        "authority_account_id",
        "aws_partition",
        "region",
        "stack_name",
        "state_bucket_name",
        "state_key",
        "destination_account_ids",
        "native_lockfile_enabled",
        "template_sha256",
        "initiator_principal_digest",
        "change_set_id",
        "change_set_name",
        "change_set_uuid",
        "change_set_type",
        "change_set_parameters",
        "planned_resource_changes",
        "planned_resource_inventory_digest",
        "account_public_access_block_before",
        "account_public_access_block_after",
        "initiator_id",
        "created_at",
        "expires_at",
        "plan_artifact_digest",
    }
)

APPROVAL_V2_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "domain_separator",
        "trust_contract_version",
        "trust_root_id",
        "trust_root_generation",
        "trust_algorithm",
        "authority_record_id",
        "approval_nonce",
        "plan_artifact_digest",
        "authority_account_id",
        "aws_partition",
        "region",
        "stack_name",
        "state_bucket_name",
        "state_key",
        "destination_account_ids",
        "native_lockfile_enabled",
        "template_sha256",
        "change_set_id",
        "change_set_name",
        "change_set_uuid",
        "change_set_type",
        "change_set_parameters",
        "planned_resource_inventory_digest",
        "initiator_id",
        "approver_id",
        "initiator_principal_digest",
        "approver_principal_digest",
        "plan_created_at",
        "plan_expires_at",
        "decision",
        "approved_at",
        "expires_at",
        "approval_artifact_digest",
    }
)

LEDGER_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "domain_separator",
        "trust_contract_version",
        "trust_root_id",
        "trust_root_generation",
        "trust_algorithm",
        "authority_record_id",
        "state",
        "version",
        "attempt_count",
        "plan",
        "approval",
        "identity_binding_digest",
        "plan_identity_proof",
        "approval_identity_proof",
        "apply_identity_proof",
        "created_at",
        "updated_at",
        "claimed_at",
        "previous_ledger_digest",
        "ledger_digest",
    }
)


class BootstrapArtifactAuthorityError(BootstrapAuthorizationError):
    """The durable artifact authority did not authorize the operation."""

    code = "BOOTSTRAP_ARTIFACT_AUTHORITY_DENIED"


class BootstrapArtifactAuthorityUncertainError(BootstrapArtifactAuthorityError):
    """An external write outcome is ambiguous and must never be retried as success."""

    code = "BOOTSTRAP_ARTIFACT_AUTHORITY_UNCERTAIN"


def _partition(region: str) -> str:
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def trust_root_id(binding: BootstrapBinding) -> str:
    """Return the sole binding-derived ledger trust-root identifier."""
    return (
        f"arn:{_partition(binding.region)}:dynamodb:{binding.region}:"
        f"{binding.authority_account_id}:table/{LEDGER_TABLE_NAME}#generation/"
        f"{TRUST_ROOT_GENERATION}"
    )


def broker_function_arn(binding: BootstrapBinding, function_name: str) -> str:
    """Derive an immutable broker function version; callers cannot override it."""
    if function_name not in {
        PLAN_AUTHORITY_FUNCTION,
        APPROVAL_AUTHORITY_FUNCTION,
        APPLY_EXECUTOR_FUNCTION,
    }:
        raise BootstrapArtifactAuthorityError("artifact authority function is not canonical")
    return (
        f"arn:{_partition(binding.region)}:lambda:{binding.region}:"
        f"{binding.authority_account_id}:function:{function_name}:"
        f"{BROKER_FUNCTION_VERSION}"
    )


def render_bootstrap_approval_iam_policy(
    *, policy_template: Mapping[str, Any], binding: BootstrapBinding
) -> dict[str, Any]:
    """Render and validate the invoke-only Approval permission boundary."""
    replacements = {
        "${aws_partition}": _partition(binding.region),
        "${region}": binding.region,
        "${authority_account_id}": binding.authority_account_id,
    }

    def render(value: Any) -> Any:
        if isinstance(value, str):
            result = value
            for marker, replacement in replacements.items():
                result = result.replace(marker, replacement)
            if "${" in result:
                raise BootstrapArtifactAuthorityError(
                    "Approval IAM policy contains an unbound placeholder"
                )
            return result
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, Mapping):
            return {str(key): render(item) for key, item in value.items()}
        return value

    policy = render(dict(policy_template))
    exact_function_arn = broker_function_arn(binding, APPROVAL_AUTHORITY_FUNCTION)
    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeExactBootstrapApprovalAuthorityVersion",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": exact_function_arn,
            },
            {
                "Sid": "DenyAnyOtherLambdaInvocation",
                "Effect": "Deny",
                "Action": "lambda:InvokeFunction",
                "NotResource": exact_function_arn,
            },
            {
                "Sid": "DenyCloudFormationAndDirectArtifactAuthority",
                "Effect": "Deny",
                "Action": [
                    "cloudformation:*",
                    "dynamodb:*",
                    "iam:*",
                    "kms:Sign",
                    "s3:PutAccountPublicAccessBlock",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyEveryNonApprovalAction",
                "Effect": "Deny",
                "NotAction": [
                    "lambda:InvokeFunction",
                    "sts:GetCallerIdentity",
                ],
                "Resource": "*",
            },
        ],
    }
    if policy != expected_policy:
        raise BootstrapArtifactAuthorityError(
            "Approval IAM policy fail-closed boundary is not exact"
        )
    return dict(policy)


def render_bootstrap_apply_iam_policy(
    *, policy_template: Mapping[str, Any], binding: BootstrapBinding
) -> dict[str, Any]:
    """Render and validate the read-only/invoke-only human Apply boundary."""
    replacements = {
        "${aws_partition}": _partition(binding.region),
        "${region}": binding.region,
        "${authority_account_id}": binding.authority_account_id,
        "${state_bucket_name}": binding.state_bucket_name,
    }

    def render(value: Any) -> Any:
        if isinstance(value, str):
            result = value
            for marker, replacement in replacements.items():
                result = result.replace(marker, replacement)
            if "${" in result:
                raise BootstrapArtifactAuthorityError(
                    "Apply IAM policy contains an unbound placeholder"
                )
            return result
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, Mapping):
            return {str(key): render(item) for key, item in value.items()}
        return value

    policy = render(dict(policy_template))
    expected_arn = broker_function_arn(binding, APPLY_EXECUTOR_FUNCTION)
    state_bucket_arn = f"arn:{_partition(binding.region)}:s3:::{binding.state_bucket_name}"
    cloudformation_reads = [
        "cloudformation:DescribeChangeSet",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplateSummary",
        "cloudformation:ListStackResources",
    ]
    bucket_reads = [
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:ListBucket",
    ]
    object_reads = [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionAttributes",
        "s3:ListBucketVersions",
    ]
    kms_reads = [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
    ]
    denied_effects = [
        "cloudformation:CreateChangeSet",
        "cloudformation:CreateStack",
        "cloudformation:DeleteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:SetStackPolicy",
        "cloudformation:UpdateStack",
        "cloudformation:UpdateTerminationProtection",
        "dynamodb:*",
        "iam:*",
        "kms:CreateAlias",
        "kms:CreateKey",
        "kms:DeleteAlias",
        "kms:DisableKey",
        "kms:EnableKeyRotation",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
        "kms:UpdateAlias",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "s3:PutAccountPublicAccessBlock",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutEncryptionConfiguration",
        "s3:PutObject",
    ]
    allowed_actions = {
        *cloudformation_reads,
        *bucket_reads,
        *object_reads,
        *kms_reads,
        "lambda:InvokeFunction",
        "s3:GetAccountPublicAccessBlock",
    }
    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeExactBootstrapApplyExecutorVersion",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": expected_arn,
            },
            {
                "Sid": "DenyAnyOtherLambdaInvocation",
                "Effect": "Deny",
                "Action": "lambda:InvokeFunction",
                "NotResource": expected_arn,
            },
            {
                "Sid": "ReadBootstrapExecutionStatus",
                "Effect": "Allow",
                "Action": cloudformation_reads,
                "Resource": "*",
            },
            {
                "Sid": "ReadAccountPublicAccessBlock",
                "Effect": "Allow",
                "Action": "s3:GetAccountPublicAccessBlock",
                "Resource": "*",
            },
            {
                "Sid": "ReadExactStateBucketForVerification",
                "Effect": "Allow",
                "Action": bucket_reads,
                "Resource": state_bucket_arn,
            },
            {
                "Sid": "ReadExactStateObjectsForVerification",
                "Effect": "Allow",
                "Action": object_reads,
                "Resource": [
                    state_bucket_arn,
                    f"{state_bucket_arn}/{binding.state_key}",
                    f"{state_bucket_arn}/{binding.state_key}.tflock",
                ],
            },
            {
                "Sid": "ReadTaggedStateKeyForVerification",
                "Effect": "Allow",
                "Action": kms_reads,
                "Resource": (
                    f"arn:{_partition(binding.region)}:kms:{binding.region}:"
                    f"{binding.authority_account_id}:key/*"
                ),
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/service": "scanalyze-platform-authority",
                        "aws:ResourceTag/data_class": "control-metadata",
                        "aws:ResourceTag/account_id": binding.authority_account_id,
                        "aws:ResourceTag/region": binding.region,
                    }
                },
            },
            {
                "Sid": "DenyDirectBootstrapEffects",
                "Effect": "Deny",
                "Action": denied_effects,
                "Resource": "*",
            },
            {
                "Sid": "DenyEveryNonReadOrBrokerAction",
                "Effect": "Deny",
                "NotAction": sorted(allowed_actions | {"sts:GetCallerIdentity"}),
                "Resource": "*",
            },
        ],
    }
    if policy != expected_policy:
        raise BootstrapArtifactAuthorityError(
            "human Apply IAM policy is not the exact read-only broker boundary"
        )
    return dict(policy)


def _validate_json_value(value: Any, *, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BootstrapArtifactAuthorityError(
                "artifact contains a non-finite JSON number"
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise BootstrapArtifactAuthorityError("artifact JSON keys must be strings")
        for key, item in value.items():
            _validate_json_value(item, path=f"{path}.{key}")
        return
    raise BootstrapArtifactAuthorityError("artifact contains a non-JSON value")


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    _validate_json_value(value)
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BootstrapArtifactAuthorityError("artifact canonicalization failed") from exc
    if len(payload) > MAX_OPERATIONAL_ARTIFACT_BYTES:
        raise BootstrapArtifactAuthorityError("operational artifact exceeds the size bound")
    return payload


def _domain_digest(domain: str, value: Mapping[str, Any]) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(
        domain.encode("ascii") + b"\x00" + _canonical_bytes(value)
    ).hexdigest()


def _require_artifact_digest(
    document: Mapping[str, Any], *, field: str, domain: str, label: str
) -> None:
    claimed = document.get(field)
    unsigned = {key: value for key, value in document.items() if key != field}
    if claimed != _domain_digest(domain, unsigned):
        raise BootstrapArtifactAuthorityError(f"{label} artifact digest mismatch")


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or CANONICAL_TIMESTAMP.fullmatch(value) is None:
        raise BootstrapArtifactAuthorityError(f"{label} is not a canonical timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise BootstrapArtifactAuthorityError(f"{label} is invalid") from exc


def _timestamp_text(value: datetime, label: str) -> str:
    if value.tzinfo is None:
        raise BootstrapArtifactAuthorityError(f"{label} must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _principal_digest(caller_arn: str, authority_account_id: str) -> str:
    if not isinstance(caller_arn, str) or f"::{authority_account_id}:" not in caller_arn:
        raise BootstrapArtifactAuthorityError(
            "artifact principal is not bound to the authority account"
        )
    return canonical_digest({"caller_arn": caller_arn})


def _authority_record_id(plan_without_id_or_digest: Mapping[str, Any]) -> str:
    key_material = {
        "domain_separator": KEY_DOMAIN,
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "authority_account_id": plan_without_id_or_digest["authority_account_id"],
        "aws_partition": plan_without_id_or_digest["aws_partition"],
        "region": plan_without_id_or_digest["region"],
        "stack_name": plan_without_id_or_digest["stack_name"],
        "change_set_id": plan_without_id_or_digest["change_set_id"],
    }
    return "gug274#g1#" + _domain_digest(KEY_DOMAIN, key_material)


def _inventory_digest(changes: Sequence[Mapping[str, Any]]) -> str:
    return _domain_digest(
        "scanalyze.platform-authority.bootstrap.resource-inventory.v1",
        {"planned_resource_changes": list(changes)},
    )


def canonical_change_set_parameters(binding: BootstrapBinding) -> dict[str, str]:
    """Return the only parameter projection the bootstrap may execute."""
    return {
        "AuthorityAccountId": binding.authority_account_id,
        "NoncurrentVersionRetentionDays": NONCURRENT_VERSION_RETENTION_DAYS,
        "StateKey": binding.state_key,
    }


def _require_canonical_change_set_parameters(
    value: object, *, binding: BootstrapBinding, label: str
) -> None:
    if type(value) is not dict or value != canonical_change_set_parameters(binding):
        raise BootstrapArtifactAuthorityError(
            f"{label} Change Set parameters are not canonical"
        )


def _live_change_set_parameters(
    response: Mapping[str, Any], *, binding: BootstrapBinding
) -> dict[str, str]:
    raw_parameters = response.get("Parameters")
    if not isinstance(raw_parameters, list):
        raise BootstrapArtifactAuthorityError("live Change Set parameters are missing")
    parameters: dict[str, str] = {}
    for item in raw_parameters:
        if not isinstance(item, Mapping) or set(item) != {
            "ParameterKey",
            "ParameterValue",
        }:
            raise BootstrapArtifactAuthorityError(
                "live Change Set parameters are malformed"
            )
        key = item.get("ParameterKey")
        value = item.get("ParameterValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in parameters:
            raise BootstrapArtifactAuthorityError(
                "live Change Set parameters are malformed"
            )
        parameters[key] = value
    _require_canonical_change_set_parameters(
        parameters, binding=binding, label="live"
    )
    return parameters


def _require_canonical_change_set_request(response: Mapping[str, Any]) -> None:
    if response.get("RollbackConfiguration") not in (None, {}):
        raise BootstrapArtifactAuthorityError(
            "live Change Set request options are not canonical"
        )
    if (
        response.get("Capabilities", []) != []
        or "RoleARN" in response
        or response.get("NotificationARNs", []) != []
        or response.get("IncludeNestedStacks") is not False
        or response.get("ImportExistingResources") is not False
        or response.get("OnStackFailure") != "ROLLBACK"
        or "DeploymentMode" in response
        or response.get("ParentChangeSetId") not in (None, "")
        or response.get("RootChangeSetId") not in (None, "")
    ):
        raise BootstrapArtifactAuthorityError(
            "live Change Set request options are not canonical"
        )


def build_bootstrap_plan_v2(
    *,
    binding: BootstrapBinding,
    caller_account_id: str,
    caller_arn: str,
    template_sha256: str,
    change_set_id: str,
    change_set_type: str,
    resource_changes: Sequence[Mapping[str, Any]],
    account_public_access_block_before: Mapping[str, Any] | None,
    created_at: datetime,
    expires_at: datetime,
    initiator_id: str,
    artifact_nonce: str,
) -> dict[str, Any]:
    """Build a closed Plan v2 candidate for external anchoring."""
    if NONCE.fullmatch(artifact_nonce) is None:
        raise BootstrapArtifactAuthorityError("Plan anti-replay nonce is invalid")
    legacy = build_bootstrap_plan(
        binding=binding,
        caller_account_id=caller_account_id,
        caller_arn=caller_arn,
        template_sha256=template_sha256,
        change_set_id=change_set_id,
        change_set_type=change_set_type,
        resource_changes=resource_changes,
        account_public_access_block_before=account_public_access_block_before,
        created_at=created_at,
        expires_at=expires_at,
        initiator_id=initiator_id,
    )
    identity = change_set_identity_from_arn(change_set_id, binding=binding)
    changes = legacy["planned_resource_changes"]
    plan: dict[str, Any] = {
        "schema_version": "2",
        "record_type": "platform_authority_bootstrap_plan",
        "domain_separator": PLAN_DOMAIN,
        "trust_contract_version": TRUST_CONTRACT_VERSION,
        "trust_root_id": trust_root_id(binding),
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "trust_algorithm": TRUST_ALGORITHM,
        "artifact_nonce": artifact_nonce,
        "authority_account_id": binding.authority_account_id,
        "aws_partition": identity.partition,
        "region": binding.region,
        "stack_name": binding.stack_name,
        "state_bucket_name": binding.state_bucket_name,
        "state_key": binding.state_key,
        "destination_account_ids": list(binding.destination_account_ids),
        "native_lockfile_enabled": True,
        "template_sha256": legacy["template_sha256"],
        "initiator_principal_digest": legacy["caller_principal_digest"],
        "change_set_id": identity.full_arn,
        "change_set_name": identity.name,
        "change_set_uuid": identity.uuid,
        "change_set_type": change_set_type,
        "change_set_parameters": canonical_change_set_parameters(binding),
        "planned_resource_changes": changes,
        "planned_resource_inventory_digest": _inventory_digest(changes),
        "account_public_access_block_before": legacy[
            "account_public_access_block_before"
        ],
        "account_public_access_block_after": legacy[
            "account_public_access_block_after"
        ],
        "initiator_id": initiator_id,
        "created_at": legacy["created_at"],
        "expires_at": legacy["expires_at"],
    }
    plan["authority_record_id"] = _authority_record_id(plan)
    plan["plan_artifact_digest"] = _domain_digest(PLAN_DOMAIN, plan)
    validate_bootstrap_plan_v2(plan=plan, binding=binding)
    return plan


def validate_bootstrap_plan_v2(
    *, plan: Mapping[str, Any], binding: BootstrapBinding
) -> ChangeSetIdentity:
    """Validate every locally provable Plan v2 invariant."""
    if type(plan) is not dict:
        raise BootstrapArtifactAuthorityError(
            "bootstrap Plan v2 must be a plain JSON object"
        )
    if plan.get("schema_version") != "2":
        raise BootstrapArtifactAuthorityError(
            "active bootstrap authenticity requires Plan v2"
        )
    if set(plan) != PLAN_V2_FIELDS:
        raise BootstrapArtifactAuthorityError("bootstrap Plan v2 contract is not closed")
    _canonical_bytes(plan)
    if (
        plan.get("record_type") != "platform_authority_bootstrap_plan"
        or plan.get("domain_separator") != PLAN_DOMAIN
        or plan.get("trust_contract_version") != TRUST_CONTRACT_VERSION
        or type(plan.get("trust_root_generation")) is not int
        or plan.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or plan.get("trust_algorithm") != TRUST_ALGORITHM
        or plan.get("trust_root_id") != trust_root_id(binding)
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan trust metadata is invalid")
    _require_artifact_digest(
        plan, field="plan_artifact_digest", domain=PLAN_DOMAIN, label="bootstrap Plan"
    )
    if NONCE.fullmatch(str(plan.get("artifact_nonce", ""))) is None:
        raise BootstrapArtifactAuthorityError("Plan anti-replay nonce is invalid")
    if (
        not isinstance(plan.get("authority_account_id"), str)
        or not isinstance(plan.get("region"), str)
        or not isinstance(plan.get("stack_name"), str)
        or not isinstance(plan.get("state_bucket_name"), str)
        or not isinstance(plan.get("state_key"), str)
        or not isinstance(plan.get("destination_account_ids"), list)
        or not all(
            isinstance(account_id, str)
            for account_id in plan.get("destination_account_ids", [])
        )
        or plan.get("native_lockfile_enabled") is not True
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan binding types are invalid")
    for field, expected in {
        **binding.as_record(),
        "aws_partition": _partition(binding.region),
    }.items():
        if plan.get(field) != expected:
            raise BootstrapArtifactAuthorityError(f"bootstrap Plan binding mismatch: {field}")
    change_set_id = plan.get("change_set_id")
    if not isinstance(change_set_id, str):
        raise BootstrapArtifactAuthorityError("bootstrap Plan Change Set ID is missing")
    identity = change_set_identity_from_arn(change_set_id, binding=binding)
    if plan.get("change_set_name") != identity.name or plan.get("change_set_uuid") != identity.uuid:
        raise BootstrapArtifactAuthorityError("bootstrap Plan Change Set tuple is invalid")
    if plan.get("change_set_type") != "CREATE":
        raise BootstrapArtifactAuthorityError("bootstrap Plan Change Set type is invalid")
    _require_canonical_change_set_parameters(
        plan.get("change_set_parameters"), binding=binding, label="bootstrap Plan"
    )
    if DIGEST.fullmatch(str(plan.get("template_sha256", ""))) is None:
        raise BootstrapArtifactAuthorityError("bootstrap Plan template digest is invalid")
    if DIGEST.fullmatch(str(plan.get("initiator_principal_digest", ""))) is None:
        raise BootstrapArtifactAuthorityError("bootstrap Plan principal digest is invalid")
    changes = plan.get("planned_resource_changes")
    if not isinstance(changes, list) or _inventory_digest(changes) != plan.get(
        "planned_resource_inventory_digest"
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan inventory digest is invalid")
    # The legacy builder normalized and sorted these exact four allowed resource shapes.
    if changes != sorted(changes, key=lambda item: str(item.get("logical_resource_id", ""))):
        raise BootstrapArtifactAuthorityError("bootstrap Plan inventory is not canonical")
    if not 3 <= len(changes) <= 4 or any(
        not isinstance(change, Mapping)
        or set(change)
        != {"action", "logical_resource_id", "resource_type", "replacement"}
        for change in changes
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan inventory contract is invalid")
    allowed_resource_types = {
        "AWS::KMS::Key",
        "AWS::KMS::Alias",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
    }
    required_resource_types = {
        "AWS::KMS::Key",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
    }
    logical_ids = [change.get("logical_resource_id") for change in changes]
    if (
        len(set(logical_ids)) != len(logical_ids)
        or any(
            change.get("action") != "Add"
            or change.get("replacement") != "False"
            or change.get("resource_type") not in allowed_resource_types
            or not isinstance(change.get("logical_resource_id"), str)
            or re.fullmatch(r"[A-Za-z0-9]{1,255}", change["logical_resource_id"])
            is None
            for change in changes
        )
        or not required_resource_types
        <= {str(change.get("resource_type")) for change in changes}
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan inventory is not safe")
    if not isinstance(plan.get("initiator_id"), str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", plan["initiator_id"]
    ) is None:
        raise BootstrapArtifactAuthorityError("bootstrap Plan initiator ID is invalid")
    if (
        type(plan.get("account_public_access_block_after")) is not dict
        or set(plan["account_public_access_block_after"]) != set(PUBLIC_ACCESS_BLOCK)
        or any(
            plan["account_public_access_block_after"].get(key) is not value
            for key, value in PUBLIC_ACCESS_BLOCK.items()
        )
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan public-access target is invalid")
    before = plan.get("account_public_access_block_before")
    if before is not None and (
        type(before) is not dict
        or set(before) != set(PUBLIC_ACCESS_BLOCK)
        or any(type(before.get(key)) is not bool for key in PUBLIC_ACCESS_BLOCK)
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan prior public-access state is invalid")
    created = _timestamp(plan.get("created_at"), "Plan created_at")
    expires = _timestamp(plan.get("expires_at"), "Plan expires_at")
    if not 300 <= (expires - created).total_seconds() <= 7200:
        raise BootstrapArtifactAuthorityError("bootstrap Plan lifetime is invalid")
    if plan.get("authority_record_id") != _authority_record_id(plan):
        raise BootstrapArtifactAuthorityError("bootstrap Plan authority key is not derived")
    return identity


def build_bootstrap_approval_v2(
    *,
    plan: Mapping[str, Any],
    binding: BootstrapBinding,
    approver_id: str,
    approver_arn: str,
    approved_at: datetime,
    expires_at: datetime,
    approval_nonce: str,
) -> dict[str, Any]:
    """Build a closed Approval v2 candidate bound to one exact Plan v2."""
    validate_bootstrap_plan_v2(plan=plan, binding=binding)
    if NONCE.fullmatch(approval_nonce) is None or approval_nonce == plan.get(
        "artifact_nonce"
    ):
        raise BootstrapArtifactAuthorityError("Approval anti-replay nonce is invalid")
    if not isinstance(approver_id, str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", approver_id
    ) is None:
        raise BootstrapArtifactAuthorityError("bootstrap approver ID is invalid")
    if approver_id == plan.get("initiator_id"):
        raise BootstrapArtifactAuthorityError("bootstrap approval requires another actor")
    approver_digest = _principal_digest(
        approver_arn, str(plan["authority_account_id"])
    )
    if approver_digest == plan.get("initiator_principal_digest"):
        raise BootstrapArtifactAuthorityError(
            "bootstrap approval requires another AWS principal"
        )
    approved = _timestamp_text(approved_at, "approved_at")
    approval_expires = _timestamp_text(expires_at, "approval expires_at")
    if not (
        _timestamp(plan["created_at"], "Plan created_at")
        <= _timestamp(approved, "approved_at")
        < _timestamp(approval_expires, "approval expires_at")
        <= _timestamp(plan["expires_at"], "Plan expires_at")
    ):
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval lifetime exceeds Plan lifetime"
        )
    approval: dict[str, Any] = {
        "schema_version": "2",
        "record_type": "platform_authority_bootstrap_approval",
        "domain_separator": APPROVAL_DOMAIN,
        "trust_contract_version": TRUST_CONTRACT_VERSION,
        "trust_root_id": plan["trust_root_id"],
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "trust_algorithm": TRUST_ALGORITHM,
        "authority_record_id": plan["authority_record_id"],
        "approval_nonce": approval_nonce,
        "plan_artifact_digest": plan["plan_artifact_digest"],
        "authority_account_id": plan["authority_account_id"],
        "aws_partition": plan["aws_partition"],
        "region": plan["region"],
        "stack_name": plan["stack_name"],
        "state_bucket_name": plan["state_bucket_name"],
        "state_key": plan["state_key"],
        "destination_account_ids": list(plan["destination_account_ids"]),
        "native_lockfile_enabled": True,
        "template_sha256": plan["template_sha256"],
        "change_set_id": plan["change_set_id"],
        "change_set_name": plan["change_set_name"],
        "change_set_uuid": plan["change_set_uuid"],
        "change_set_type": plan["change_set_type"],
        "change_set_parameters": dict(plan["change_set_parameters"]),
        "planned_resource_inventory_digest": plan[
            "planned_resource_inventory_digest"
        ],
        "initiator_id": plan["initiator_id"],
        "approver_id": approver_id,
        "initiator_principal_digest": plan["initiator_principal_digest"],
        "approver_principal_digest": approver_digest,
        "plan_created_at": plan["created_at"],
        "plan_expires_at": plan["expires_at"],
        "decision": "APPROVED",
        "approved_at": approved,
        "expires_at": approval_expires,
    }
    approval["approval_artifact_digest"] = _domain_digest(APPROVAL_DOMAIN, approval)
    validate_bootstrap_approval_v2(plan=plan, approval=approval, binding=binding)
    return approval


def validate_bootstrap_approval_v2(
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    binding: BootstrapBinding,
) -> None:
    """Validate the exact Approval v2 projection and its Plan binding."""
    if type(approval) is not dict:
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval v2 must be a plain JSON object"
        )
    validate_bootstrap_plan_v2(plan=plan, binding=binding)
    if approval.get("schema_version") != "2":
        raise BootstrapArtifactAuthorityError(
            "active bootstrap authenticity requires Approval v2"
        )
    if set(approval) != APPROVAL_V2_FIELDS:
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval v2 contract is not closed"
        )
    _canonical_bytes(approval)
    if (
        approval.get("record_type") != "platform_authority_bootstrap_approval"
        or approval.get("domain_separator") != APPROVAL_DOMAIN
        or approval.get("trust_contract_version") != TRUST_CONTRACT_VERSION
        or approval.get("trust_root_id") != trust_root_id(binding)
        or type(approval.get("trust_root_generation")) is not int
        or approval.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or approval.get("trust_algorithm") != TRUST_ALGORITHM
        or approval.get("decision") != "APPROVED"
    ):
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval trust metadata is invalid"
        )
    if (
        not isinstance(approval.get("authority_account_id"), str)
        or not isinstance(approval.get("aws_partition"), str)
        or not isinstance(approval.get("region"), str)
        or not isinstance(approval.get("stack_name"), str)
        or not isinstance(approval.get("state_bucket_name"), str)
        or not isinstance(approval.get("state_key"), str)
        or not isinstance(approval.get("destination_account_ids"), list)
        or not all(
            isinstance(account_id, str)
            for account_id in approval.get("destination_account_ids", [])
        )
        or approval.get("native_lockfile_enabled") is not True
    ):
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval binding types are invalid"
        )
    _require_artifact_digest(
        approval,
        field="approval_artifact_digest",
        domain=APPROVAL_DOMAIN,
        label="bootstrap Approval",
    )
    if NONCE.fullmatch(str(approval.get("approval_nonce", ""))) is None or approval.get(
        "approval_nonce"
    ) == plan.get("artifact_nonce"):
        raise BootstrapArtifactAuthorityError("Approval anti-replay nonce is invalid")
    cross_fields = {
        "authority_record_id": "authority_record_id",
        "plan_artifact_digest": "plan_artifact_digest",
        "authority_account_id": "authority_account_id",
        "aws_partition": "aws_partition",
        "region": "region",
        "stack_name": "stack_name",
        "state_bucket_name": "state_bucket_name",
        "state_key": "state_key",
        "destination_account_ids": "destination_account_ids",
        "native_lockfile_enabled": "native_lockfile_enabled",
        "template_sha256": "template_sha256",
        "change_set_id": "change_set_id",
        "change_set_name": "change_set_name",
        "change_set_uuid": "change_set_uuid",
        "change_set_type": "change_set_type",
        "change_set_parameters": "change_set_parameters",
        "planned_resource_inventory_digest": "planned_resource_inventory_digest",
        "initiator_id": "initiator_id",
        "initiator_principal_digest": "initiator_principal_digest",
        "plan_created_at": "created_at",
        "plan_expires_at": "expires_at",
    }
    for approval_field, plan_field in cross_fields.items():
        if approval.get(approval_field) != plan.get(plan_field):
            raise BootstrapArtifactAuthorityError(
                f"bootstrap Approval Plan binding mismatch: {approval_field}"
            )
    if approval.get("approver_id") == plan.get("initiator_id") or approval.get(
        "approver_principal_digest"
    ) == plan.get("initiator_principal_digest"):
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval actor separation is invalid"
        )
    if not isinstance(approval.get("approver_id"), str) or re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", approval["approver_id"]
    ) is None:
        raise BootstrapArtifactAuthorityError("bootstrap approver ID is invalid")
    if DIGEST.fullmatch(str(approval.get("approver_principal_digest", ""))) is None:
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval principal digest is invalid"
        )
    plan_created = _timestamp(plan["created_at"], "Plan created_at")
    approved = _timestamp(approval.get("approved_at"), "Approval approved_at")
    approval_expires = _timestamp(approval.get("expires_at"), "Approval expires_at")
    plan_expires = _timestamp(plan["expires_at"], "Plan expires_at")
    if not plan_created <= approved < approval_expires <= plan_expires:
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval lifetime exceeds Plan lifetime"
        )


def prevalidate_bootstrap_apply_v2(
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    binding: BootstrapBinding,
    current_template_sha256: str,
    now: datetime,
) -> ChangeSetIdentity:
    """Perform every local check before constructing an external client."""
    identity = validate_bootstrap_plan_v2(plan=plan, binding=binding)
    validate_bootstrap_approval_v2(plan=plan, approval=approval, binding=binding)
    normalized_template = current_template_sha256.removeprefix("sha256:")
    if plan.get("template_sha256") != f"sha256:{normalized_template}":
        raise BootstrapArtifactAuthorityError("bootstrap template digest mismatch")
    current = now.astimezone(UTC).replace(microsecond=0)
    if not (
        _timestamp(plan["created_at"], "Plan created_at")
        <= current
        < _timestamp(plan["expires_at"], "Plan expires_at")
    ):
        raise BootstrapArtifactAuthorityError("bootstrap Plan is expired or not yet valid")
    if not (
        _timestamp(approval["approved_at"], "Approval approved_at")
        <= current
        < _timestamp(approval["expires_at"], "Approval expires_at")
    ):
        raise BootstrapArtifactAuthorityError(
            "bootstrap Approval is expired or not yet valid"
        )
    return identity


def _ledger_digest(record: Mapping[str, Any]) -> str:
    return _domain_digest(
        LEDGER_DOMAIN,
        {key: value for key, value in record.items() if key != "ledger_digest"},
    )


def build_plan_anchor(
    plan: Mapping[str, Any],
    *,
    binding: BootstrapBinding,
    identity_proof: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    validate_bootstrap_plan_v2(plan=plan, binding=binding)
    anchored_at = _timestamp_text(
        now if now is not None else _timestamp(plan["created_at"], "Plan created_at"),
        "Plan anchor time",
    )
    if not (
        _timestamp(plan["created_at"], "Plan created_at")
        <= _timestamp(anchored_at, "Plan anchor time")
        < _timestamp(plan["expires_at"], "Plan expires_at")
    ):
        raise BootstrapArtifactAuthorityError("Plan is expired or not yet valid")
    proof = validate_identity_proof_receipt(
        identity_proof,
        operation="plan",
        now=_timestamp(anchored_at, "Plan anchor time"),
    )
    record: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_artifact_authority",
        "domain_separator": LEDGER_DOMAIN,
        "trust_contract_version": TRUST_CONTRACT_VERSION,
        "trust_root_id": plan["trust_root_id"],
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "trust_algorithm": TRUST_ALGORITHM,
        "authority_record_id": plan["authority_record_id"],
        "state": "PLAN_ANCHORED",
        "version": 1,
        "attempt_count": 0,
        "plan": dict(plan),
        "approval": None,
        "identity_binding_digest": proof["identity_binding_digest"],
        "plan_identity_proof": proof,
        "approval_identity_proof": None,
        "apply_identity_proof": None,
        "created_at": plan["created_at"],
        "updated_at": anchored_at,
        "claimed_at": None,
        "previous_ledger_digest": None,
    }
    record["ledger_digest"] = _ledger_digest(record)
    validate_authority_ledger(record=record, binding=binding)
    return record


def validate_authority_ledger(
    *, record: Mapping[str, Any], binding: BootstrapBinding
) -> dict[str, Any]:
    if type(record) is not dict:
        raise BootstrapArtifactAuthorityError(
            "artifact authority ledger must be a plain JSON object"
        )
    if set(record) != LEDGER_FIELDS:
        raise BootstrapArtifactAuthorityError("artifact authority ledger is not closed")
    if (
        record.get("schema_version") != "1"
        or record.get("record_type")
        != "platform_authority_bootstrap_artifact_authority"
        or record.get("domain_separator") != LEDGER_DOMAIN
        or record.get("trust_contract_version") != TRUST_CONTRACT_VERSION
        or record.get("trust_root_id") != trust_root_id(binding)
        or type(record.get("trust_root_generation")) is not int
        or record.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or record.get("trust_algorithm") != TRUST_ALGORITHM
        or record.get("ledger_digest") != _ledger_digest(record)
    ):
        raise BootstrapArtifactAuthorityError("artifact authority ledger metadata is invalid")
    plan = record.get("plan")
    if not isinstance(plan, Mapping):
        raise BootstrapArtifactAuthorityError("artifact authority Plan snapshot is missing")
    validate_bootstrap_plan_v2(plan=plan, binding=binding)
    if record.get("authority_record_id") != plan.get("authority_record_id"):
        raise BootstrapArtifactAuthorityError("artifact authority key mismatch")
    state = record.get("state")
    expected = {
        "PLAN_ANCHORED": (1, 0, False, False),
        "APPROVED": (2, 0, True, False),
        "CLAIMED": (3, 1, True, True),
    }.get(str(state))
    if expected is None:
        raise BootstrapArtifactAuthorityError("artifact authority state is invalid")
    version, attempts, approval_required, claimed_required = expected
    if (
        type(record.get("version")) is not int
        or type(record.get("attempt_count")) is not int
        or record.get("version") != version
        or record.get("attempt_count") != attempts
    ):
        raise BootstrapArtifactAuthorityError("artifact authority state counters are invalid")
    approval = record.get("approval")
    if approval_required:
        if not isinstance(approval, Mapping):
            raise BootstrapArtifactAuthorityError(
                "artifact authority Approval snapshot is missing"
            )
        validate_bootstrap_approval_v2(plan=plan, approval=approval, binding=binding)
    elif approval is not None:
        raise BootstrapArtifactAuthorityError(
            "artifact authority contains an early Approval"
        )
    plan_proof_value = record.get("plan_identity_proof")
    if not isinstance(plan_proof_value, Mapping):
        raise BootstrapArtifactAuthorityError("Plan identity proof is missing")
    try:
        plan_proof = validate_identity_proof_receipt(
            plan_proof_value, operation="plan"
        )
    except BootstrapAuthorizationError:
        raise BootstrapArtifactAuthorityError("Plan identity proof is invalid") from None
    if record.get("identity_binding_digest") != plan_proof.get(
        "identity_binding_digest"
    ):
        raise BootstrapArtifactAuthorityError("identity proof binding changed")

    approval_proof_value = record.get("approval_identity_proof")
    if approval_required:
        if not isinstance(approval_proof_value, Mapping):
            raise BootstrapArtifactAuthorityError("Approval identity proof is missing")
        try:
            approval_proof = validate_identity_proof_receipt(
                approval_proof_value, operation="approval"
            )
        except BootstrapAuthorizationError:
            raise BootstrapArtifactAuthorityError(
                "Approval identity proof is invalid"
            ) from None
        if (
            approval_proof.get("identity_binding_digest")
            != record.get("identity_binding_digest")
            or approval_proof.get("expected_user_id_digest")
            != plan_proof.get("peer_user_id_digest")
            or approval_proof.get("peer_user_id_digest")
            != plan_proof.get("expected_user_id_digest")
            or approval_proof.get("proof_role_arn_digest")
            == plan_proof.get("proof_role_arn_digest")
            or approval_proof.get("broker_execution_role_arn_digest")
            == plan_proof.get("broker_execution_role_arn_digest")
        ):
            raise BootstrapArtifactAuthorityError(
                "Plan and Approval identity proofs are not independent"
            )
    elif approval_proof_value is not None:
        raise BootstrapArtifactAuthorityError(
            "artifact authority contains an early Approval identity proof"
        )

    apply_proof_value = record.get("apply_identity_proof")
    if claimed_required:
        if not isinstance(apply_proof_value, Mapping):
            raise BootstrapArtifactAuthorityError("Apply identity proof is missing")
        try:
            apply_proof = validate_identity_proof_receipt(
                apply_proof_value, operation="apply"
            )
        except BootstrapAuthorizationError:
            raise BootstrapArtifactAuthorityError("Apply identity proof is invalid") from None
        assert isinstance(approval_proof_value, Mapping)
        if (
            apply_proof.get("identity_binding_digest")
            != record.get("identity_binding_digest")
            or apply_proof.get("expected_user_id_digest")
            != approval_proof_value.get("expected_user_id_digest")
            or apply_proof.get("peer_user_id_digest")
            != approval_proof_value.get("peer_user_id_digest")
            or apply_proof.get("proof_role_arn_digest")
            in {
                plan_proof.get("proof_role_arn_digest"),
                approval_proof_value.get("proof_role_arn_digest"),
            }
            or apply_proof.get("broker_execution_role_arn_digest")
            in {
                plan_proof.get("broker_execution_role_arn_digest"),
                approval_proof_value.get("broker_execution_role_arn_digest"),
            }
        ):
            raise BootstrapArtifactAuthorityError(
                "Apply identity proof is not independently scoped"
            )
    elif apply_proof_value is not None:
        raise BootstrapArtifactAuthorityError(
            "artifact authority contains an early Apply identity proof"
        )
    if claimed_required != isinstance(record.get("claimed_at"), str):
        raise BootstrapArtifactAuthorityError("artifact authority claim timestamp is invalid")
    created = _timestamp(record.get("created_at"), "ledger created_at")
    updated = _timestamp(record.get("updated_at"), "ledger updated_at")
    if updated < created:
        raise BootstrapArtifactAuthorityError("artifact authority timestamps are invalid")
    if claimed_required and _timestamp(record.get("claimed_at"), "claimed_at") != updated:
        raise BootstrapArtifactAuthorityError("artifact authority claim timestamp is invalid")
    if state == "PLAN_ANCHORED" and record.get("previous_ledger_digest") is not None:
        raise BootstrapArtifactAuthorityError("initial authority has a prior digest")
    if state != "PLAN_ANCHORED" and DIGEST.fullmatch(
        str(record.get("previous_ledger_digest", ""))
    ) is None:
        raise BootstrapArtifactAuthorityError("authority prior digest is missing")
    return dict(record)


def build_approved_anchor(
    before: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    identity_proof: Mapping[str, Any],
    binding: BootstrapBinding,
    now: datetime,
) -> dict[str, Any]:
    current = validate_authority_ledger(record=before, binding=binding)
    validate_bootstrap_approval_v2(plan=plan, approval=approval, binding=binding)
    if current["state"] != "PLAN_ANCHORED" or current["plan"] != dict(plan):
        raise BootstrapArtifactAuthorityError("Plan anchor is absent or superseded")
    at = _timestamp_text(now, "ledger update time")
    if not (
        _timestamp(approval["approved_at"], "approved_at")
        <= _timestamp(at, "ledger update time")
        < _timestamp(approval["expires_at"], "approval expires_at")
    ):
        raise BootstrapArtifactAuthorityError("Approval is expired or not yet valid")
    proof = validate_identity_proof_receipt(
        identity_proof,
        operation="approval",
        now=_timestamp(at, "ledger update time"),
    )
    candidate = dict(current)
    candidate.update(
        {
            "state": "APPROVED",
            "version": 2,
            "approval": dict(approval),
            "approval_identity_proof": proof,
            "updated_at": at,
            "previous_ledger_digest": current["ledger_digest"],
        }
    )
    candidate["ledger_digest"] = _ledger_digest(candidate)
    return validate_authority_ledger(record=candidate, binding=binding)


def build_claimed_anchor(
    before: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    identity_proof: Mapping[str, Any],
    binding: BootstrapBinding,
    now: datetime,
) -> dict[str, Any]:
    current = validate_authority_ledger(record=before, binding=binding)
    prevalidate_bootstrap_apply_v2(
        plan=plan,
        approval=approval,
        binding=binding,
        current_template_sha256=str(plan["template_sha256"]),
        now=now,
    )
    if (
        current["state"] != "APPROVED"
        or current["plan"] != dict(plan)
        or current["approval"] != dict(approval)
    ):
        raise BootstrapArtifactAuthorityError("Approval is absent, consumed, or superseded")
    at = _timestamp_text(now, "claim time")
    proof = validate_identity_proof_receipt(
        identity_proof,
        operation="apply",
        now=_timestamp(at, "claim time"),
    )
    candidate = dict(current)
    candidate.update(
        {
            "state": "CLAIMED",
            "version": 3,
            "attempt_count": 1,
            "apply_identity_proof": proof,
            "updated_at": at,
            "claimed_at": at,
            "previous_ledger_digest": current["ledger_digest"],
        }
    )
    candidate["ledger_digest"] = _ledger_digest(candidate)
    return validate_authority_ledger(record=candidate, binding=binding)


class ArtifactAuthorityStore(Protocol):
    """Provider boundary implemented only by the service-owned broker."""

    def get(self, authority_record_id: str) -> Mapping[str, Any] | None: ...

    def create(self, record: Mapping[str, Any]) -> None: ...

    def compare_and_swap(
        self, before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> None: ...


class BootstrapIdentityProofProvider(Protocol):
    """Verify one runtime-owned Identity Center proof before ledger access."""

    def verify(
        self,
        *,
        operation: str,
        identity_grant: object,
        binding: BootstrapIdentityProofBinding,
        now: datetime,
    ) -> Mapping[str, Any]: ...


class BootstrapApplyEffects(Protocol):
    """Exact provider effects owned solely by the Apply executor service."""

    def execute(
        self, *, plan: Mapping[str, Any], approval: Mapping[str, Any]
    ) -> None: ...


class BootstrapApplyEffectsFactory(Protocol):
    """Construct provider-effect clients only after a terminal CAS claim."""

    def __call__(self) -> BootstrapApplyEffects: ...


@dataclass(frozen=True, slots=True)
class BootstrapArtifactAuthorityBroker:
    """Identity-gated CAS state machine and sole Apply-effect coordinator."""

    binding: BootstrapBinding
    identity_binding: BootstrapIdentityProofBinding
    identity_verifier: BootstrapIdentityProofProvider
    store: ArtifactAuthorityStore
    now: Callable[[], datetime]
    effects_factory: BootstrapApplyEffectsFactory | None = None

    def _identity_proof(
        self, *, operation: str, identity_grant: object, now: datetime
    ) -> dict[str, Any]:
        proof = self.identity_verifier.verify(
            operation=operation,
            identity_grant=identity_grant,
            binding=self.identity_binding,
            now=now,
        )
        validated = validate_identity_proof_receipt(
            proof, operation=operation, now=now
        )
        if validated.get("identity_binding_digest") != self.identity_binding.binding_digest:
            raise BootstrapArtifactAuthorityError(
                "identity proof is not bound to immutable runtime configuration"
            )
        return validated

    def anchor_plan(
        self, plan: Mapping[str, Any], identity_grant: object
    ) -> dict[str, Any]:
        operation_time = self.now()
        validate_bootstrap_plan_v2(plan=plan, binding=self.binding)
        proof = self._identity_proof(
            operation="plan",
            identity_grant=identity_grant,
            now=operation_time,
        )
        record = build_plan_anchor(
            plan,
            binding=self.binding,
            identity_proof=proof,
            now=operation_time,
        )
        try:
            self.store.create(record)
        except BootstrapArtifactAuthorityUncertainError:
            raise
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "Plan anchor result is uncertain"
            ) from None
        return _receipt(record)

    def approve_plan(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant: object,
    ) -> dict[str, Any]:
        operation_time = self.now()
        validate_bootstrap_approval_v2(
            plan=plan, approval=approval, binding=self.binding
        )
        proof = self._identity_proof(
            operation="approval",
            identity_grant=identity_grant,
            now=operation_time,
        )
        current = self.store.get(str(plan.get("authority_record_id", "")))
        if current is None:
            raise BootstrapArtifactAuthorityError("authenticated Plan anchor is missing")
        candidate = build_approved_anchor(
            current,
            plan=plan,
            approval=approval,
            identity_proof=proof,
            binding=self.binding,
            now=operation_time,
        )
        try:
            self.store.compare_and_swap(current, candidate)
        except BootstrapArtifactAuthorityUncertainError:
            raise
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "Approval anchor result is uncertain"
            ) from None
        return _receipt(candidate)

    def claim_and_execute(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant: object,
    ) -> dict[str, Any]:
        operation_time = self.now()
        prevalidate_bootstrap_apply_v2(
            plan=plan,
            approval=approval,
            binding=self.binding,
            current_template_sha256=str(plan.get("template_sha256", "")),
            now=operation_time,
        )
        proof = self._identity_proof(
            operation="apply",
            identity_grant=identity_grant,
            now=operation_time,
        )
        current = self.store.get(str(plan.get("authority_record_id", "")))
        if current is None:
            raise BootstrapArtifactAuthorityError("authenticated Approval anchor is missing")
        candidate = build_claimed_anchor(
            current,
            plan=plan,
            approval=approval,
            identity_proof=proof,
            binding=self.binding,
            now=operation_time,
        )
        try:
            self.store.compare_and_swap(current, candidate)
        except BootstrapArtifactAuthorityUncertainError:
            raise
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "Apply claim result is uncertain"
            ) from None
        if self.effects_factory is None:
            raise BootstrapArtifactAuthorityError(
                "Apply effect provider is unavailable after terminal claim"
            )
        # Constructing a CloudFormation or S3 Control client is itself kept
        # behind the unambiguous terminal CAS.  A failed identity proof, a
        # missing anchor, or an ambiguous/racing claim therefore receives no
        # provider-effect client and cannot acquire a second authority path.
        effects = self.effects_factory()
        effects.execute(plan=plan, approval=approval)
        return _receipt(candidate)


def _receipt(record: Mapping[str, Any]) -> dict[str, Any]:
    plan = record["plan"]
    approval = record["approval"]
    assert isinstance(plan, Mapping)
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_bootstrap_authority_receipt",
        "domain_separator": RECEIPT_DOMAIN,
        "trust_root_id": record["trust_root_id"],
        "trust_root_generation": record["trust_root_generation"],
        "authority_record_id": record["authority_record_id"],
        "plan_artifact_digest": plan["plan_artifact_digest"],
        "approval_artifact_digest": (
            approval["approval_artifact_digest"]
            if isinstance(approval, Mapping)
            else None
        ),
        "identity_binding_digest": record["identity_binding_digest"],
        "plan_identity_proof_digest": record["plan_identity_proof"][
            "proof_receipt_digest"
        ],
        "approval_identity_proof_digest": (
            record["approval_identity_proof"]["proof_receipt_digest"]
            if isinstance(record["approval_identity_proof"], Mapping)
            else None
        ),
        "apply_identity_proof_digest": (
            record["apply_identity_proof"]["proof_receipt_digest"]
            if isinstance(record["apply_identity_proof"], Mapping)
            else None
        ),
        "state": record["state"],
        "version": record["version"],
        "ledger_digest": record["ledger_digest"],
    }
    receipt["receipt_digest"] = _domain_digest(RECEIPT_DOMAIN, receipt)
    return receipt


@dataclass(frozen=True, slots=True)
class Boto3BootstrapApplyEffects:
    """Exact no-retry CloudFormation/S3 effects owned by the Apply service."""

    binding: BootstrapBinding
    expected_change_set_name: str
    cloudformation_client: Any
    s3control_client: Any
    now: Callable[[], datetime]

    def _stack(self) -> Mapping[str, Any]:
        try:
            response = self.cloudformation_client.describe_stacks(
                StackName=self.binding.stack_name
            )
            resources_response = self.cloudformation_client.list_stack_resources(
                StackName=self.binding.stack_name
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "bootstrap review-stack readback is uncertain"
            ) from None
        stacks = response.get("Stacks") if isinstance(response, Mapping) else None
        resources = (
            resources_response.get("StackResourceSummaries")
            if isinstance(resources_response, Mapping)
            else None
        )
        if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(
            stacks[0], Mapping
        ):
            raise BootstrapArtifactAuthorityError(
                "bootstrap review-stack readback is ambiguous"
            )
        try:
            require_exact_empty_review_stack(
                stack=stacks[0],
                resources=resources,
                authority_account_id=self.binding.authority_account_id,
                region=self.binding.region,
                stack_name=self.binding.stack_name,
            )
        except BootstrapAuthorizationError:
            raise BootstrapArtifactAuthorityError(
                "bootstrap stack is not the exact empty review shell"
            ) from None
        return stacks[0]

    @staticmethod
    def _changes(response: Mapping[str, Any]) -> list[dict[str, str]]:
        changes = response.get("Changes")
        if not isinstance(changes, list) or response.get("NextToken") is not None:
            raise BootstrapArtifactAuthorityError(
                "live Change Set inventory is ambiguous"
            )
        normalized: list[dict[str, str]] = []
        for item in changes:
            resource = item.get("ResourceChange") if isinstance(item, Mapping) else None
            if not isinstance(resource, Mapping):
                raise BootstrapArtifactAuthorityError(
                    "live Change Set inventory is malformed"
                )
            action = resource.get("Action")
            logical_id = resource.get("LogicalResourceId")
            resource_type = resource.get("ResourceType")
            replacement = resource.get("Replacement", "False")
            if not all(
                isinstance(value, str)
                for value in (action, logical_id, resource_type, replacement)
            ):
                raise BootstrapArtifactAuthorityError(
                    "live Change Set inventory is malformed"
                )
            normalized.append(
                {
                    "action": action,
                    "logical_resource_id": logical_id,
                    "resource_type": resource_type,
                    "replacement": replacement,
                }
            )
        return sorted(normalized, key=lambda item: item["logical_resource_id"])

    def _change_set(
        self, plan: Mapping[str, Any], identity: ChangeSetIdentity
    ) -> Mapping[str, Any]:
        try:
            response = self.cloudformation_client.describe_change_set(
                ChangeSetName=identity.full_arn,
                StackName=self.binding.stack_name,
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "exact Change Set readback is uncertain"
            ) from None
        if not isinstance(response, Mapping):
            raise BootstrapArtifactAuthorityError(
                "exact Change Set readback is malformed"
            )
        raw_tags = response.get("Tags")
        tags: dict[str, str] = {}
        if not isinstance(raw_tags, list):
            raise BootstrapArtifactAuthorityError("live Change Set tags are missing")
        for item in raw_tags:
            if not isinstance(item, Mapping):
                raise BootstrapArtifactAuthorityError(
                    "live Change Set tags are malformed"
                )
            key = item.get("Key")
            value = item.get("Value")
            if not isinstance(key, str) or not isinstance(value, str) or key in tags:
                raise BootstrapArtifactAuthorityError(
                    "live Change Set tags are malformed"
                )
            tags[key] = value
        if (
            response.get("ChangeSetId") != identity.full_arn
            or response.get("ChangeSetName") != identity.name
            or response.get("StackName") != self.binding.stack_name
            or response.get("ChangeSetType") != "CREATE"
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or tags
            != {
                "managed_by": "cloudformation",
                "service": "scanalyze-platform-authority",
                "work_package": "GUG-206",
            }
            or self._changes(response) != plan.get("planned_resource_changes")
        ):
            raise BootstrapArtifactAuthorityError(
                "live Change Set differs from authenticated Plan"
            )
        _require_canonical_change_set_request(response)
        live_parameters = _live_change_set_parameters(
            response, binding=self.binding
        )
        if live_parameters != plan.get("change_set_parameters"):
            raise BootstrapArtifactAuthorityError(
                "live Change Set parameters differ from authenticated Plan"
            )
        return response

    def _template(self, plan: Mapping[str, Any], identity: ChangeSetIdentity) -> None:
        try:
            response = self.cloudformation_client.get_template(
                ChangeSetName=identity.full_arn,
                StackName=self.binding.stack_name,
                TemplateStage="Original",
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "exact original template readback is uncertain"
            ) from None
        body = response.get("TemplateBody") if isinstance(response, Mapping) else None
        if (
            not isinstance(body, str)
            or "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
            != plan.get("template_sha256")
        ):
            raise BootstrapArtifactAuthorityError(
                "original template differs from authenticated Plan"
            )

    def execute(
        self, *, plan: Mapping[str, Any], approval: Mapping[str, Any]
    ) -> None:
        identity = validate_bootstrap_plan_v2(plan=plan, binding=self.binding)
        validate_bootstrap_approval_v2(
            plan=plan, approval=approval, binding=self.binding
        )
        if identity.name != self.expected_change_set_name:
            raise BootstrapArtifactAuthorityError(
                "Change Set name differs from immutable Apply configuration"
            )

        # The terminal CAS is performed by the broker before this first read.
        self._stack()
        self._change_set(plan, identity)
        self._template(plan, identity)
        prevalidate_bootstrap_apply_v2(
            plan=plan,
            approval=approval,
            binding=self.binding,
            current_template_sha256=str(plan["template_sha256"]),
            now=self.now(),
        )
        try:
            self.s3control_client.put_public_access_block(
                AccountId=self.binding.authority_account_id,
                PublicAccessBlockConfiguration=dict(PUBLIC_ACCESS_BLOCK),
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "account public-access-block result is uncertain; reconcile only"
            ) from None

        # Preserve GUG-210: final full-ARN/UUID/template readback, then exactly
        # one Execute request using only the derived bare Change Set name.
        self._stack()
        self._change_set(plan, identity)
        self._template(plan, identity)
        prevalidate_bootstrap_apply_v2(
            plan=plan,
            approval=approval,
            binding=self.binding,
            current_template_sha256=str(plan["template_sha256"]),
            now=self.now(),
        )
        try:
            self.cloudformation_client.execute_change_set(
                ChangeSetName=identity.name,
                StackName=self.binding.stack_name,
                DisableRollback=False,
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "Change Set execution result is uncertain; reconcile only"
            ) from None


class BootstrapArtifactAuthorityClient(Protocol):
    """Narrow operational interface; callers cannot choose provider coordinates."""

    def anchor_plan(
        self, plan: Mapping[str, Any], identity_grant_json: str
    ) -> Mapping[str, Any]: ...

    def approve_plan(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant_json: str,
    ) -> Mapping[str, Any]: ...

    def claim_and_execute(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant_json: str,
    ) -> Mapping[str, Any]: ...


def authorize_bootstrap_apply_v2(
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    binding: BootstrapBinding,
    current_template_sha256: str,
    now: datetime,
    authority: BootstrapArtifactAuthorityClient,
    identity_grant_json: str,
) -> ChangeSetIdentity:
    """Authenticate and ask the service-owned broker to execute exactly once."""
    identity = prevalidate_bootstrap_apply_v2(
        plan=plan,
        approval=approval,
        binding=binding,
        current_template_sha256=current_template_sha256,
        now=now,
    )
    authority.claim_and_execute(plan, approval, identity_grant_json)
    return identity


@dataclass(frozen=True, slots=True)
class LambdaBootstrapArtifactAuthorityClient:
    """Strict synchronous adapter to exact, immutable broker function versions."""

    binding: BootstrapBinding
    lambda_client: Any

    def _invoke(
        self,
        *,
        function_name: str,
        payload: dict[str, Any],
        expected_state: str,
        expected_version: int,
    ) -> Mapping[str, Any]:
        plan = payload.get("plan")
        approval = payload.get("approval")
        grant_json = payload.get("identity_grant_json")
        if not isinstance(plan, Mapping) or not isinstance(grant_json, str):
            raise BootstrapArtifactAuthorityError(
                "artifact authority invocation request is invalid"
            )
        expected_record_id = plan.get("authority_record_id")
        expected_plan_digest = plan.get("plan_artifact_digest")
        expected_approval_digest = (
            approval.get("approval_artifact_digest")
            if isinstance(approval, Mapping)
            else None
        )
        try:
            body = _canonical_bytes(payload)
            try:
                response = self.lambda_client.invoke(
                    FunctionName=broker_function_arn(self.binding, function_name),
                    InvocationType="RequestResponse",
                    Payload=body,
                )
            except Exception:
                raise BootstrapArtifactAuthorityUncertainError(
                    "artifact authority invocation result is uncertain"
                ) from None
            if response.get("StatusCode") != 200 or "FunctionError" in response:
                raise BootstrapArtifactAuthorityUncertainError(
                    "artifact authority invocation result is uncertain"
                )
            stream = response.get("Payload")
            try:
                raw = stream.read() if hasattr(stream, "read") else stream

                def reject_duplicates(
                    pairs: list[tuple[str, Any]],
                ) -> dict[str, Any]:
                    result_object: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in result_object:
                            raise ValueError("duplicate")
                        result_object[key] = value
                    return result_object

                result = json.loads(raw, object_pairs_hook=reject_duplicates)
            except Exception:
                raise BootstrapArtifactAuthorityUncertainError(
                    "artifact authority receipt result is uncertain"
                ) from None
        finally:
            payload["identity_grant_json"] = ""
        if not isinstance(result, Mapping):
            raise BootstrapArtifactAuthorityUncertainError(
                "artifact authority receipt result is uncertain"
            )
        expected_fields = {
            "schema_version",
            "record_type",
            "domain_separator",
            "trust_root_id",
            "trust_root_generation",
            "authority_record_id",
            "plan_artifact_digest",
            "approval_artifact_digest",
            "identity_binding_digest",
            "plan_identity_proof_digest",
            "approval_identity_proof_digest",
            "apply_identity_proof_digest",
            "state",
            "version",
            "ledger_digest",
            "receipt_digest",
        }
        if (
            set(result) != expected_fields
            or result.get("schema_version") != "1"
            or result.get("record_type")
            != "platform_authority_bootstrap_authority_receipt"
            or result.get("domain_separator") != RECEIPT_DOMAIN
            or result.get("trust_root_id") != trust_root_id(self.binding)
            or result.get("trust_root_generation") != TRUST_ROOT_GENERATION
            or result.get("authority_record_id") != expected_record_id
            or result.get("plan_artifact_digest") != expected_plan_digest
            or result.get("approval_artifact_digest") != expected_approval_digest
            or DIGEST.fullmatch(str(result.get("identity_binding_digest", "")))
            is None
            or DIGEST.fullmatch(str(result.get("plan_identity_proof_digest", "")))
            is None
            or (
                expected_version == 1
                and (
                    result.get("approval_identity_proof_digest") is not None
                    or result.get("apply_identity_proof_digest") is not None
                )
            )
            or (
                expected_version == 2
                and (
                    DIGEST.fullmatch(
                        str(result.get("approval_identity_proof_digest", ""))
                    )
                    is None
                    or result.get("apply_identity_proof_digest") is not None
                )
            )
            or (
                expected_version == 3
                and (
                    DIGEST.fullmatch(
                        str(result.get("approval_identity_proof_digest", ""))
                    )
                    is None
                    or DIGEST.fullmatch(
                        str(result.get("apply_identity_proof_digest", ""))
                    )
                    is None
                )
            )
            or result.get("state") != expected_state
            or result.get("version") != expected_version
            or DIGEST.fullmatch(str(result.get("ledger_digest", ""))) is None
            or result.get("receipt_digest")
            != _domain_digest(
                RECEIPT_DOMAIN,
                {key: value for key, value in result.items() if key != "receipt_digest"},
            )
        ):
            raise BootstrapArtifactAuthorityUncertainError(
                "artifact authority receipt result is uncertain"
            )
        return dict(result)

    def anchor_plan(
        self, plan: Mapping[str, Any], identity_grant_json: str
    ) -> Mapping[str, Any]:
        validate_bootstrap_plan_v2(plan=plan, binding=self.binding)
        return self._invoke(
            function_name=PLAN_AUTHORITY_FUNCTION,
            payload={"plan": dict(plan), "identity_grant_json": identity_grant_json},
            expected_state="PLAN_ANCHORED",
            expected_version=1,
        )

    def approve_plan(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant_json: str,
    ) -> Mapping[str, Any]:
        validate_bootstrap_approval_v2(
            plan=plan, approval=approval, binding=self.binding
        )
        return self._invoke(
            function_name=APPROVAL_AUTHORITY_FUNCTION,
            payload={
                "plan": dict(plan),
                "approval": dict(approval),
                "identity_grant_json": identity_grant_json,
            },
            expected_state="APPROVED",
            expected_version=2,
        )

    def claim_and_execute(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any],
        identity_grant_json: str,
    ) -> Mapping[str, Any]:
        validate_bootstrap_approval_v2(
            plan=plan, approval=approval, binding=self.binding
        )
        return self._invoke(
            function_name=APPLY_EXECUTOR_FUNCTION,
            payload={
                "plan": dict(plan),
                "approval": dict(approval),
                "identity_grant_json": identity_grant_json,
            },
            expected_state="CLAIMED",
            expected_version=3,
        )


@dataclass(frozen=True, slots=True)
class DynamoDbArtifactAuthorityStore:
    """Low-level DynamoDB adapter used only inside the pinned broker functions."""

    binding: BootstrapBinding
    dynamodb_client: Any

    def _key(self, authority_record_id: str) -> dict[str, dict[str, str]]:
        if not authority_record_id.startswith("gug274#g1#sha256:"):
            raise BootstrapArtifactAuthorityError("artifact authority key is invalid")
        return {
            "trust_root_id": {"S": trust_root_id(self.binding)},
            "authority_record_id": {"S": authority_record_id},
        }

    def get(self, authority_record_id: str) -> Mapping[str, Any] | None:
        try:
            response = self.dynamodb_client.get_item(
                TableName=LEDGER_TABLE_NAME,
                Key=self._key(authority_record_id),
                ConsistentRead=True,
                ProjectionExpression="document",
                ReturnConsumedCapacity="NONE",
            )
        except Exception:
            raise BootstrapArtifactAuthorityUncertainError(
                "artifact authority read is unavailable"
            ) from None
        item = response.get("Item")
        raw = item.get("document", {}).get("S") if isinstance(item, Mapping) else None
        if raw is None:
            return None
        try:
            pairs: list[tuple[str, Any]] = []

            def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
                pairs.clear()
                result: dict[str, Any] = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate")
                    result[key] = value
                return result

            document = json.loads(raw, object_pairs_hook=reject_duplicates)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BootstrapArtifactAuthorityError(
                "artifact authority ledger is malformed"
            ) from None
        if not isinstance(document, Mapping):
            raise BootstrapArtifactAuthorityError(
                "artifact authority ledger is malformed"
            )
        return validate_authority_ledger(record=document, binding=self.binding)

    @staticmethod
    def _item(record: Mapping[str, Any]) -> dict[str, dict[str, str]]:
        return {
            "trust_root_id": {"S": str(record["trust_root_id"])},
            "authority_record_id": {"S": str(record["authority_record_id"])},
            "state": {"S": str(record["state"])},
            "version": {"N": str(record["version"])},
            "attempt_count": {"N": str(record["attempt_count"])},
            "ledger_digest": {"S": str(record["ledger_digest"])},
            "document": {
                "S": json.dumps(record, sort_keys=True, separators=(",", ":"))
            },
        }

    def create(self, record: Mapping[str, Any]) -> None:
        validated = validate_authority_ledger(record=record, binding=self.binding)
        try:
            self.dynamodb_client.put_item(
                TableName=LEDGER_TABLE_NAME,
                Item=self._item(validated),
                ConditionExpression=(
                    "attribute_not_exists(trust_root_id) AND "
                    "attribute_not_exists(authority_record_id)"
                ),
                ReturnConsumedCapacity="NONE",
            )
        except Exception:
            # Never reinterpret an ambiguous provider result as new authority.
            raise BootstrapArtifactAuthorityUncertainError(
                "Plan anchor result is uncertain"
            ) from None

    def compare_and_swap(
        self, before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> None:
        current = validate_authority_ledger(record=before, binding=self.binding)
        candidate = validate_authority_ledger(record=after, binding=self.binding)
        if candidate["authority_record_id"] != current["authority_record_id"]:
            raise BootstrapArtifactAuthorityError("artifact authority key changed")
        try:
            self.dynamodb_client.update_item(
                TableName=LEDGER_TABLE_NAME,
                Key=self._key(str(current["authority_record_id"])),
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
                    ":state": {"S": str(candidate["state"])},
                    ":version": {"N": str(candidate["version"])},
                    ":attempt_count": {"N": str(candidate["attempt_count"])},
                    ":ledger_digest": {"S": str(candidate["ledger_digest"])},
                    ":document": {
                        "S": json.dumps(
                            candidate, sort_keys=True, separators=(",", ":")
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
                ReturnConsumedCapacity="NONE",
            )
        except Exception:
            # A lost response may mean the terminal claim exists.  The caller
            # must stop before CloudFormation and must not retry.
            raise BootstrapArtifactAuthorityUncertainError(
                "artifact authority transition result is uncertain"
            ) from None


RUNTIME_ENV_FIELDS = frozenset(
    {
        "GUG274_AUTHORITY_ACCOUNT_ID",
        "GUG274_AUTHORITY_REGION",
        "GUG274_DESTINATION_ACCOUNT_IDS",
        "GUG274_CHANGE_SET_NAME",
        "GUG274_IDENTITY_CENTER_APPLICATION_ARN",
        "GUG274_IDENTITY_CENTER_INSTANCE_ARN",
        "GUG274_IDENTITY_STORE_ARN",
        "GUG274_IDENTITY_REDIRECT_URI",
        "GUG274_PLAN_IDENTITY_STORE_USER_ID",
        "GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID",
        "GUG274_SOURCE_COMMIT",
        "GUG274_EXPECTED_BOTO3_VERSION",
        "GUG274_EXPECTED_BOTOCORE_VERSION",
    }
)
FORBIDDEN_PROVIDER_ENV = frozenset(
    {
        "AWS_ENDPOINT_URL",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_CA_BUNDLE",
        "AWS_DATA_PATH",
        "REQUESTS_CA_BUNDLE",
        "BOTO_CONFIG",
    }
)
RUNTIME_LOCK_RELATIVE_PATH = Path("gug274_runtime_lock.json")
RUNTIME_LOCK_RECORD_TYPE = (
    "scanalyze.platform_authority.bootstrap_artifact_authority_runtime_lock.v1"
)
SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
SDK_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True, slots=True)
class BootstrapArtifactAuthorityRuntimeConfig:
    """Environment snapshot owned by the immutable published function version."""

    binding: BootstrapBinding
    identity_binding: BootstrapIdentityProofBinding
    change_set_name: str
    source_commit: str
    expected_boto3_version: str
    expected_botocore_version: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str]
    ) -> "BootstrapArtifactAuthorityRuntimeConfig":
        values = {name: environment.get(name) for name in RUNTIME_ENV_FIELDS}
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise BootstrapArtifactAuthorityError(
                "artifact authority runtime configuration is unavailable"
            )
        account_id = str(values["GUG274_AUTHORITY_ACCOUNT_ID"])
        region = str(values["GUG274_AUTHORITY_REGION"])
        if environment.get("AWS_REGION") not in (None, region):
            raise BootstrapArtifactAuthorityError(
                "artifact authority runtime Region is inconsistent"
            )
        destinations = tuple(
            str(values["GUG274_DESTINATION_ACCOUNT_IDS"]).split(",")
        )
        source_commit = str(values["GUG274_SOURCE_COMMIT"])
        expected_boto3_version = str(values["GUG274_EXPECTED_BOTO3_VERSION"])
        expected_botocore_version = str(
            values["GUG274_EXPECTED_BOTOCORE_VERSION"]
        )
        if (
            SOURCE_COMMIT.fullmatch(source_commit) is None
            or SDK_VERSION.fullmatch(expected_boto3_version) is None
            or SDK_VERSION.fullmatch(expected_botocore_version) is None
        ):
            raise BootstrapArtifactAuthorityError(
                "artifact authority runtime provenance is invalid"
            )
        try:
            binding = BootstrapBinding(
                authority_account_id=account_id,
                region=region,
                stack_name="scanalyze-platform-authority-state-backend",
                state_bucket_name=(
                    f"scanalyze-platform-authority-{account_id}-{region}-state"
                ),
                state_key="platform-authority/terraform.tfstate",
                destination_account_ids=destinations,
            )
            change_set_name = validate_bootstrap_change_set_name(
                str(values["GUG274_CHANGE_SET_NAME"])
            )
            partition = _partition(region)
            role_prefix = f"arn:{partition}:iam::{account_id}:role/"
            identity_binding = BootstrapIdentityProofBinding(
                authority_account_id=account_id,
                region=region,
                identity_center_application_arn=str(
                    values["GUG274_IDENTITY_CENTER_APPLICATION_ARN"]
                ),
                identity_center_instance_arn=str(
                    values["GUG274_IDENTITY_CENTER_INSTANCE_ARN"]
                ),
                identity_store_arn=str(values["GUG274_IDENTITY_STORE_ARN"]),
                redirect_uri=str(values["GUG274_IDENTITY_REDIRECT_URI"]),
                plan_user_id=str(
                    values["GUG274_PLAN_IDENTITY_STORE_USER_ID"]
                ),
                second_party_user_id=str(
                    values["GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID"]
                ),
                plan_execution_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapPlanAuthority"
                ),
                approval_execution_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapApprovalAuthority"
                ),
                apply_execution_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapApplyExecutor"
                ),
                plan_proof_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapPlanIdentityProof"
                ),
                approval_proof_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapApprovalIdentityProof"
                ),
                apply_proof_role_arn=(
                    role_prefix + "ScanalyzeGug274BootstrapApplyIdentityProof"
                ),
            )
        except BootstrapAuthorizationError:
            raise BootstrapArtifactAuthorityError(
                "artifact authority runtime configuration is invalid"
            ) from None
        return cls(
            binding=binding,
            identity_binding=identity_binding,
            change_set_name=change_set_name,
            source_commit=source_commit,
            expected_boto3_version=expected_boto3_version,
            expected_botocore_version=expected_botocore_version,
        )


def _validate_runtime_lock(config: BootstrapArtifactAuthorityRuntimeConfig) -> None:
    """Bind imported SDK behavior and source commit to reviewed package bytes."""

    path = Path(__file__).resolve().parents[1] / RUNTIME_LOCK_RELATIVE_PATH
    try:
        raw = path.read_text(encoding="utf-8")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result

        lock = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise BootstrapArtifactAuthorityError(
            "artifact authority runtime lock is unavailable"
        ) from None
    expected = {
        "record_type": RUNTIME_LOCK_RECORD_TYPE,
        "schema_version": 1,
        "work_package": "GUG-274",
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "source_commit": config.source_commit,
        "expected_boto3_version": config.expected_boto3_version,
        "expected_botocore_version": config.expected_botocore_version,
    }
    if type(lock) is not dict or lock != expected:
        raise BootstrapArtifactAuthorityError(
            "artifact authority runtime lock is invalid"
        )


def _reject_provider_overrides(environment: Mapping[str, str]) -> None:
    if any(environment.get(name) for name in FORBIDDEN_PROVIDER_ENV) or any(
        name.startswith("AWS_ENDPOINT_URL_") and value
        for name, value in environment.items()
    ):
        raise BootstrapArtifactAuthorityError(
            "provider endpoint or configuration override is forbidden"
        )


def _strict_event(event: object, fields: set[str]) -> dict[str, Any]:
    if type(event) is not dict or set(event) != fields:
        raise BootstrapArtifactAuthorityError("artifact authority request is not closed")
    _canonical_bytes(event)
    return event


def _runtime_broker(
    *,
    config: BootstrapArtifactAuthorityRuntimeConfig,
    operation: str,
    invoked_function_arn: object,
) -> BootstrapArtifactAuthorityBroker:
    expected_function = {
        "plan": PLAN_AUTHORITY_FUNCTION,
        "approval": APPROVAL_AUTHORITY_FUNCTION,
        "apply": APPLY_EXECUTOR_FUNCTION,
    }[operation]
    if invoked_function_arn != broker_function_arn(config.binding, expected_function):
        raise BootstrapArtifactAuthorityError(
            "artifact authority function version is not exact"
        )
    # Imports and provider construction occur only after the complete local
    # contract and immutable function-version check.
    _reject_provider_overrides(os.environ)
    _validate_runtime_lock(config)
    try:
        import boto3
        import botocore
        from botocore.config import Config

        if (
            boto3.__version__ != config.expected_boto3_version
            or botocore.__version__ != config.expected_botocore_version
        ):
            raise BootstrapArtifactAuthorityError(
                "artifact authority runtime SDK version is not reviewed"
            )

        no_retry = Config(
            region_name=config.binding.region,
            retries={"max_attempts": 0, "mode": "standard"},
            ignore_configured_endpoint_urls=True,
        )
        dynamodb = boto3.client(
            "dynamodb",
            config=no_retry,
        )
        oidc = boto3.client("sso-oidc", config=no_retry)
        sts = boto3.client("sts", config=no_retry)
    except Exception:
        raise BootstrapArtifactAuthorityError(
            "artifact authority provider is unavailable"
        ) from None

    def effects_factory() -> BootstrapApplyEffects:
        try:
            cloudformation = boto3.client("cloudformation", config=no_retry)
            s3control = boto3.client("s3control", config=no_retry)
        except Exception:
            raise BootstrapArtifactAuthorityError(
                "Apply effect provider is unavailable after terminal claim"
            ) from None
        return Boto3BootstrapApplyEffects(
            binding=config.binding,
            expected_change_set_name=config.change_set_name,
            cloudformation_client=cloudformation,
            s3control_client=s3control,
            now=lambda: datetime.now(tz=UTC).replace(microsecond=0),
        )

    return BootstrapArtifactAuthorityBroker(
        binding=config.binding,
        identity_binding=config.identity_binding,
        identity_verifier=BootstrapIdentityProofVerifier(
            oidc_client=oidc,
            sts_client=sts,
        ),
        store=DynamoDbArtifactAuthorityStore(
            binding=config.binding, dynamodb_client=dynamodb
        ),
        now=lambda: datetime.now(tz=UTC).replace(microsecond=0),
        effects_factory=effects_factory if operation == "apply" else None,
    )


def _handle_plan_anchor(event: object, context: object) -> Mapping[str, Any]:
    request = _strict_event(event, {"plan", "identity_grant_json"})
    plan = request["plan"]
    grant_json = request["identity_grant_json"]
    request["identity_grant_json"] = ""
    if not isinstance(plan, Mapping) or not isinstance(grant_json, str):
        raise BootstrapArtifactAuthorityError("Plan candidate is missing")
    config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(os.environ)
    validate_bootstrap_plan_v2(plan=plan, binding=config.binding)
    if plan.get("change_set_name") != config.change_set_name:
        raise BootstrapArtifactAuthorityError(
            "Plan Change Set differs from immutable runtime configuration"
        )
    broker = _runtime_broker(
        config=config,
        operation="plan",
        invoked_function_arn=getattr(context, "invoked_function_arn", None),
    )
    return broker.anchor_plan(plan, grant_json)


def _handle_approval_anchor(event: object, context: object) -> Mapping[str, Any]:
    request = _strict_event(event, {"plan", "approval", "identity_grant_json"})
    plan = request["plan"]
    approval = request["approval"]
    grant_json = request["identity_grant_json"]
    request["identity_grant_json"] = ""
    if (
        not isinstance(plan, Mapping)
        or not isinstance(approval, Mapping)
        or not isinstance(grant_json, str)
    ):
        raise BootstrapArtifactAuthorityError("Approval candidate is missing")
    config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(os.environ)
    validate_bootstrap_approval_v2(
        plan=plan, approval=approval, binding=config.binding
    )
    if plan.get("change_set_name") != config.change_set_name:
        raise BootstrapArtifactAuthorityError(
            "Approval Change Set differs from immutable runtime configuration"
        )
    broker = _runtime_broker(
        config=config,
        operation="approval",
        invoked_function_arn=getattr(context, "invoked_function_arn", None),
    )
    return broker.approve_plan(plan, approval, grant_json)


def _handle_apply_executor(event: object, context: object) -> Mapping[str, Any]:
    request = _strict_event(event, {"plan", "approval", "identity_grant_json"})
    plan = request["plan"]
    approval = request["approval"]
    grant_json = request["identity_grant_json"]
    request["identity_grant_json"] = ""
    if (
        not isinstance(plan, Mapping)
        or not isinstance(approval, Mapping)
        or not isinstance(grant_json, str)
    ):
        raise BootstrapArtifactAuthorityError("Apply authority evidence is missing")
    config = BootstrapArtifactAuthorityRuntimeConfig.from_environment(os.environ)
    now = datetime.now(tz=UTC).replace(microsecond=0)
    prevalidate_bootstrap_apply_v2(
        plan=plan,
        approval=approval,
        binding=config.binding,
        current_template_sha256=str(plan.get("template_sha256", "")),
        now=now,
    )
    if plan.get("change_set_name") != config.change_set_name:
        raise BootstrapArtifactAuthorityError(
            "Apply Change Set differs from immutable runtime configuration"
        )
    broker = _runtime_broker(
        config=config,
        operation="apply",
        invoked_function_arn=getattr(context, "invoked_function_arn", None),
    )
    return broker.claim_and_execute(plan, approval, grant_json)


def _sanitized_handler(
    handler: Callable[[object, object], Mapping[str, Any]],
    event: object,
    context: object,
) -> Mapping[str, Any]:
    try:
        return handler(event, context)
    except BootstrapAuthorizationError as exc:
        code = getattr(exc, "code", "BOOTSTRAP_ARTIFACT_AUTHORITY_DENIED")
        raise BootstrapArtifactAuthorityError(str(code)) from None
    except Exception:
        raise BootstrapArtifactAuthorityError(
            "BOOTSTRAP_ARTIFACT_AUTHORITY_RUNTIME_UNAVAILABLE"
        ) from None


def plan_anchor_handler(event: object, context: object) -> Mapping[str, Any]:
    """Sanitized Lambda handler for the immutable Plan-anchor version."""
    return _sanitized_handler(_handle_plan_anchor, event, context)


def approval_anchor_handler(event: object, context: object) -> Mapping[str, Any]:
    """Sanitized Lambda handler for the immutable Approval-anchor version."""
    return _sanitized_handler(_handle_approval_anchor, event, context)


def apply_executor_handler(event: object, context: object) -> Mapping[str, Any]:
    """Sanitized Lambda handler for the immutable Apply-executor version."""
    return _sanitized_handler(_handle_apply_executor, event, context)
