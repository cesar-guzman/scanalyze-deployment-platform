"""Focused offline contracts for the circularity-breaking GUG-376 bootstrap."""

from __future__ import annotations

import base64
import ast
import copy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from hashlib import sha256
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
from typing import Any, Mapping

import pytest
import yaml

from tooling import platform_authority_plan_permission_repair_artifact_bootstrap as pure
from tooling import platform_authority_plan_permission_repair_artifact_bootstrap_aws as aws
from tests.test_deployment.gug376_foundation_fixtures import (
    build_foundation_contract,
)


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / pure.BRIDGE_TEMPLATE_PATH
FOUNDATION = ROOT / pure.FOUNDATION_TEMPLATE_PATH
ROUTE_TEMPLATE = ROOT / pure.ROUTE_TEMPLATE_SOURCE_PATH
DELEGATION_TEMPLATE = ROOT / pure.DELEGATION_TEMPLATE_SOURCE_PATH
CLI = (
    ROOT
    / "scripts/deployment/"
    "platform-authority-plan-permission-repair-artifact-bootstrap.py"
)
COMMIT = "a" * 40
INSTANCE = "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
PRINCIPAL = "12345678-1234-4123-8123-123456789012"
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
REQUEST_ID = "11111111-1111-4111-8111-111111111111"
KMS_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "22222222-2222-4222-8222-222222222222"
)


class Loader(yaml.SafeLoader):
    pass


def _intrinsic(loader: Loader, suffix: str, node: Any) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    return {name: value}


Loader.add_multi_constructor("!", _intrinsic)


def _load(path: Path) -> dict[str, Any]:
    result = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
    assert isinstance(result, dict)
    return result


def _load_cli_module() -> Any:
    spec = importlib.util.spec_from_file_location("gug376_artifact_cli", CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _ContractHarnessProvider(aws.ConnectedArtifactBootstrapProvider):
    """Exercise mutation contracts with a deterministic admitted binding."""

    def _assert_collision_admission(
        self,
        *,
        operation: str,
        effect_request: Mapping[str, Any],
        bootstrap_intent_digest: str,
    ) -> dict[str, str]:
        return {
            "operation": operation,
            "effect_request_digest": pure.digest_value(effect_request),
            "bootstrap_intent_digest": bootstrap_intent_digest,
            "admission_digest": "sha256:" + "9" * 64,
        }


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result[field] = pure.digest_value(result)
    return result


def _input() -> dict[str, Any]:
    return _seal(
        {
            "schema_version": 1,
            "record_type": pure.INPUT_TYPE,
            "source_commit": COMMIT,
            "management_account_id": pure.MANAGEMENT_ACCOUNT_ID,
            "authority_account_id": pure.AUTHORITY_ACCOUNT_ID,
            "region": pure.REGION,
            "identity_center_instance_arn": INSTANCE,
            "bootstrap_principal_id": PRINCIPAL,
            "access_not_before": "2026-08-30T11:55:00Z",
            "access_not_after": "2026-08-30T13:00:00Z",
            "production_authorized": False,
        },
        "input_digest",
    )


def _intent() -> dict[str, Any]:
    return pure.materialize_bootstrap_intent(
        _input(),
        bridge_template=BRIDGE.read_bytes(),
        foundation_template=FOUNDATION.read_bytes(),
    )


def _foundation_readback() -> dict[str, Any]:
    intent = _intent()
    value = {
        "schema_version": 1,
        "record_type": pure.FOUNDATION_READBACK_TYPE,
        "source_commit": COMMIT,
        "bootstrap_intent_digest": intent["intent_digest"],
        "verifier": {
            "account_id": pure.AUTHORITY_ACCOUNT_ID,
            "caller_arn": AUTH_CALLER,
            "profile": pure.AUTHORITY_PROFILE,
            "region": pure.REGION,
        },
        "artifact_bucket": intent["names"]["artifact_bucket"],
        "artifact_kms_key_arn": KMS_ARN,
        "artifact_kms_alias": intent["names"]["artifact_kms_alias"],
        "signing_profile_name": intent["names"]["signing_profile_name"],
        "signing_profile_version_arn": (
            "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
            f"{intent['names']['signing_profile_name']}/ABCDEFGHIJ"
        ),
        "code_signing_config_arn": (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-0123456789abcdef0"
        ),
        "source_marker": "AWS_STS_KMS_S3_SIGNER_LAMBDA_EXACT_READBACK",
        "read_at": "2026-08-30T12:00:00Z",
        "aws_calls": 13,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": pure.PRODUCTION_STATUS,
    }
    return _seal(value, "readback_digest")


def _reviewed_sources() -> dict[str, Any]:
    return pure.seal_reviewed_sources(
        bootstrap_intent=_intent(),
        bridge_template=BRIDGE.read_bytes(),
        foundation_template=FOUNDATION.read_bytes(),
        route_template=ROUTE_TEMPLATE.read_bytes(),
        delegation_template=DELEGATION_TEMPLATE.read_bytes(),
    )


def _bridge_pin() -> dict[str, Any]:
    return pure.materialize_bridge_pin(
        bootstrap_intent=_intent(),
        foundation_readback=_foundation_readback(),
        bridge_template=BRIDGE.read_bytes(),
    )


def _bridge_pin_readback() -> dict[str, Any]:
    pin = _bridge_pin()
    value = {
        "schema_version": 1,
        "record_type": pure.STACK_READBACK_TYPE,
        "source_commit": COMMIT,
        "operation": "bridge-pin",
        "intent_digest": pin["intent_digest"],
        "verifier": {
            "account_id": pure.MANAGEMENT_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::839393571433:assumed-role/"
                "AWSReservedSSO_AWSAdministratorAccess_0123456789ABCDEF/operator"
            ),
            "profile": pure.MANAGEMENT_PROFILE,
            "region": pure.REGION,
        },
        "stack_status": "UPDATE_COMPLETE",
        "stack_completed_at": "2026-08-30T12:02:00Z",
        "template_digest": _intent()["template_digests"]["bridge"],
        "resources": [
            {
                "logical_resource_id": "ArtifactBootstrapAssignment",
                "resource_type": "AWS::SSO::Assignment",
            },
            {
                "logical_resource_id": "ArtifactBootstrapPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
            {
                "logical_resource_id": "BrokerSeedCleanupAssignment",
                "resource_type": "AWS::SSO::Assignment",
            },
            {
                "logical_resource_id": "BrokerSeedCleanupPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
            {
                "logical_resource_id": "ManagementRecoveryRole",
                "resource_type": "AWS::IAM::Role",
            },
            {
                "logical_resource_id": "RouteSeedCleanupAssignment",
                "resource_type": "AWS::SSO::Assignment",
            },
            {
                "logical_resource_id": "RouteSeedCleanupPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
        ],
        "outputs_digest": pure.digest_value({"AssignmentMode": "true"}),
        "sso_assignment_count": 1,
        "permission_set_provisioned": True,
        "permission_set_arn_digest": pure.digest_value("permission-set-arn"),
        "permission_set_policy_digest": pure.digest_value("inline-policy"),
        "permission_set_tags_digest": pure.digest_value("tags"),
        "permission_set_metadata_exact": True,
        "managed_policy_count": 0,
        "customer_managed_policy_count": 0,
        "permissions_boundary_absent": True,
        "signing_profile_version_digest": pure.digest_value("ABCDEFGHIJ"),
        "temporary_principal_authorized": True,
        "cleanup_assignment_count": 2,
        "cleanup_permission_set_count": 2,
        "cleanup_permission_sets_digest": pure.digest_value("cleanup-permission-sets"),
        "management_recovery_role_present": True,
        "management_recovery_role_digest": pure.digest_value("management-recovery-role"),
        "cleanup_authority_active": True,
        "credential_window_expired": False,
        "read_at": "2026-08-30T12:03:00Z",
        "aws_calls": 12,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": pure.PRODUCTION_STATUS,
    }
    return _seal(value, "readback_digest")


def _bridge_revoke_readback() -> dict[str, Any]:
    intent = _intent()
    value = {
        **{
            key: item
            for key, item in _bridge_pin_readback().items()
            if key != "readback_digest"
        },
        "operation": "bridge-revoke",
        "intent_digest": intent["intent_digest"],
        "stack_completed_at": "2026-08-30T12:10:00Z",
        "resources": [
            {
                "logical_resource_id": "ArtifactBootstrapPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
            {
                "logical_resource_id": "BrokerSeedCleanupAssignment",
                "resource_type": "AWS::SSO::Assignment",
            },
            {
                "logical_resource_id": "BrokerSeedCleanupPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
            {
                "logical_resource_id": "ManagementRecoveryRole",
                "resource_type": "AWS::IAM::Role",
            },
            {
                "logical_resource_id": "RouteSeedCleanupAssignment",
                "resource_type": "AWS::SSO::Assignment",
            },
            {
                "logical_resource_id": "RouteSeedCleanupPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            },
        ],
        "outputs_digest": pure.digest_value({"AssignmentMode": "false"}),
        "sso_assignment_count": 0,
        "signing_profile_version_digest": pure.digest_value("NOT_CONFIGURED"),
        "temporary_principal_authorized": False,
        "credential_window_expired": True,
        "read_at": "2026-08-30T13:10:00Z",
    }
    return _seal(value, "readback_digest")


def _expired_cleanup_retire(
    *, evaluated_at: datetime | None = None
) -> dict[str, Any]:
    intent = _intent()
    boundary = datetime.fromisoformat(
        intent["cleanup_not_after"][:-1] + "+00:00"
    )
    return pure.materialize_bridge_cleanup_retire(
        bootstrap_intent=intent,
        bridge_revoke_readback=_bridge_revoke_readback(),
        bridge_template=BRIDGE.read_bytes(),
        mode="EXPIRED",
        evaluated_at=evaluated_at or boundary,
    )


def _signing_intent() -> tuple[dict[str, Any], dict[str, Any]]:
    unsigned = _object_receipt("unsigned.zip")
    return unsigned, pure.materialize_signing_intent(
        bootstrap_intent=_intent(),
        foundation_readback=_foundation_readback(),
        bridge_pin=_bridge_pin(),
        bridge_pin_readback=_bridge_pin_readback(),
        unsigned_receipt=unsigned,
        destination_prefix=f"{pure.ARTIFACT_PREFIX}pep/signed/{COMMIT}/",
        profile_name=_intent()["names"]["signing_profile_name"],
    )


def _object_intent(filename: str, body: bytes = b"template") -> dict[str, Any]:
    return pure.materialize_object_intent(
        bootstrap_intent=_intent(),
        foundation_readback=_foundation_readback(),
        key=(
            f"{pure.ARTIFACT_PREFIX}templates/{COMMIT}/{filename}"
        ),
        body=body,
        content_type="text/yaml",
        mutation_nonce="1" * 64,
    )


AUTH_CALLER = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_0123456789ABCDEF/operator"
)


def _object_receipt(filename: str, version: str = "Version-A") -> dict[str, Any]:
    intent = _intent()
    body = {
        ROUTE_TEMPLATE.name: ROUTE_TEMPLATE.read_bytes(),
        DELEGATION_TEMPLATE.name: DELEGATION_TEMPLATE.read_bytes(),
    }.get(filename, b"template")
    object_intent = _object_intent(filename, body)
    receipt = {
        "schema_version": 1,
        "record_type": pure.OBJECT_RECEIPT_TYPE,
        "source_commit": COMMIT,
        "bootstrap_intent_digest": intent["intent_digest"],
        "foundation_readback_digest": _foundation_readback()["readback_digest"],
        "object_intent_digest": object_intent["intent_digest"],
        "dispatch_receipt_digest": "sha256:" + "d" * 64,
        "effect_digest": object_intent["effect_digest"],
        "mutation_nonce": object_intent["mutation_nonce"],
        "causal_claim_digest": object_intent["causal_claim_digest"],
        "verifier": {
            "account_id": pure.AUTHORITY_ACCOUNT_ID,
            "caller_arn": AUTH_CALLER,
            "profile": pure.AUTHORITY_PROFILE,
            "region": pure.REGION,
        },
        "bucket": intent["names"]["artifact_bucket"],
        "key": object_intent["request"]["Key"],
        "version": version,
        "object_sha256": object_intent["object_sha256"],
        "checksum_sha256": object_intent["request"]["ChecksumSHA256"],
        "content_length": object_intent["request"]["ContentLength"],
        "content_type": "text/yaml",
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": KMS_ARN,
        "bucket_key_enabled": True,
        "metadata": object_intent["request"]["Metadata"],
        "tags": {
            "managed_by": "gug376-artifact-bootstrap",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": COMMIT,
            "mutation_nonce": object_intent["mutation_nonce"],
            "effect_digest": object_intent["effect_digest"],
            "causal_claim_digest": object_intent["causal_claim_digest"],
        },
        "source_marker": "AWS_STS_S3_VERSIONED_SSE_KMS_OBJECT_READBACK",
        "read_at": "2026-08-30T12:00:00Z",
        "aws_calls": 6,
        "aws_mutations": 0,
        "production_authorized": False,
        "production_status": pure.PRODUCTION_STATUS,
    }
    return _seal(receipt, "receipt_digest")


def test_bridge_has_exact_bridge_owned_recovery_and_cleanup_resources() -> None:
    template = _load(BRIDGE)
    resources = template["Resources"]
    assert {
        key: value["Type"] for key, value in resources.items()
    } == {
        "ArtifactBootstrapPermissionSet": "AWS::SSO::PermissionSet",
        "ArtifactBootstrapAssignment": "AWS::SSO::Assignment",
        "RouteSeedCleanupPermissionSet": "AWS::SSO::PermissionSet",
        "RouteSeedCleanupAssignment": "AWS::SSO::Assignment",
        "BrokerSeedCleanupPermissionSet": "AWS::SSO::PermissionSet",
        "BrokerSeedCleanupAssignment": "AWS::SSO::Assignment",
        "ManagementRecoveryRole": "AWS::IAM::Role",
    }
    assert resources["ArtifactBootstrapAssignment"]["Condition"] == "CreateAssignment"
    for logical_id in (
        "RouteSeedCleanupPermissionSet",
        "RouteSeedCleanupAssignment",
        "BrokerSeedCleanupPermissionSet",
        "BrokerSeedCleanupAssignment",
        "ManagementRecoveryRole",
    ):
        assert resources[logical_id]["Condition"] == "CreateCleanupAssignments"
    assert "TemplateURL" not in BRIDGE.read_text(encoding="utf-8")
    assert BRIDGE.stat().st_size <= 51_200


def test_artifact_templates_expose_non_secret_causal_parameters_for_exact_readback() -> None:
    bridge_parameters = _load(BRIDGE)["Parameters"]
    foundation_parameters = _load(FOUNDATION)["Parameters"]

    for parameter in ("BootstrapPrincipalId", "SigningProfileVersion"):
        assert "NoEcho" not in bridge_parameters[parameter]
    for parameter in ("RouteTemplateVersion", "DelegationTemplateVersion"):
        assert "NoEcho" not in foundation_parameters[parameter]


def test_account_regional_artifact_bucket_name_and_template_contract_are_exact() -> None:
    expected_name = "scanalyze-g376-art-aaaaaaaaaaaa-042360977644-us-east-1-an"
    assert pure.ARTIFACT_BUCKET_NAMESPACE == "account-regional"
    assert pure.deterministic_names(COMMIT)["artifact_bucket"] == expected_name

    expected_pattern = (
        "^scanalyze-g376-art-[a-f0-9]{12}-042360977644-us-east-1-an$"
    )
    bridge = _load(BRIDGE)
    foundation = _load(FOUNDATION)
    assert bridge["Parameters"]["ArtifactBucketName"]["AllowedPattern"] == (
        expected_pattern
    )
    assert foundation["Parameters"]["ArtifactBucketName"]["AllowedPattern"] == (
        expected_pattern
    )
    bucket = foundation["Resources"]["ArtifactBucket"]["Properties"]
    assert bucket["BucketName"] == {"Ref": "ArtifactBucketName"}
    assert bucket["BucketNamespace"] == pure.ARTIFACT_BUCKET_NAMESPACE


def test_account_regional_bucket_creation_is_cfn_name_time_and_namespace_bounded() -> None:
    statements = {
        item["Sid"]: item
        for item in _load(BRIDGE)["Resources"]["ArtifactBootstrapPermissionSet"][
            "Properties"
        ]["InlinePolicy"]["Statement"]
    }
    create = statements[
        "CreateOnlyExactAccountRegionalArtifactBucketThroughCloudFormation"
    ]
    assert create == {
        "Sid": "CreateOnlyExactAccountRegionalArtifactBucketThroughCloudFormation",
        "Effect": "Allow",
        "Action": "s3:CreateBucket",
        "Resource": {
            "Fn::Sub": "arn:${AWS::Partition}:s3:::${ArtifactBucketName}"
        },
        "Condition": {
            "ForAnyValue:StringEquals": {
                "aws:CalledVia": "cloudformation.amazonaws.com"
            },
            "StringEquals": {
                "aws:RequestedRegion": pure.REGION,
                "s3:x-amz-bucket-namespace": pure.ARTIFACT_BUCKET_NAMESPACE,
            },
            "DateGreaterThanEquals": {
                "aws:CurrentTime": {"Ref": "AccessNotBefore"}
            },
            "DateLessThan": {
                "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
            },
        },
    }
    assert statements["DenyNonAccountRegionalArtifactBucketCreation"] == {
        "Sid": "DenyNonAccountRegionalArtifactBucketCreation",
        "Effect": "Deny",
        "Action": "s3:CreateBucket",
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {
                "s3:x-amz-bucket-namespace": pure.ARTIFACT_BUCKET_NAMESPACE
            }
        },
    }
    assert "s3:CreateBucket" not in statements[
        "ManageExactArtifactBucketThroughCloudFormation"
    ]["Action"]


@pytest.mark.parametrize("template", ["foundation", "bridge"])
def test_intent_rejects_account_regional_bucket_contract_drift(template: str) -> None:
    bridge = BRIDGE.read_bytes()
    foundation = FOUNDATION.read_bytes()
    if template == "foundation":
        foundation = foundation.replace(
            b"BucketNamespace: account-regional",
            b"BucketNamespace: global",
        )
    else:
        bridge = bridge.replace(
            b"s3:x-amz-bucket-namespace: account-regional",
            b"s3:x-amz-bucket-namespace: global",
            1,
        )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.materialize_bootstrap_intent(
            _input(), bridge_template=bridge, foundation_template=foundation
        )
    assert raised.value.code == "ACCOUNT_REGIONAL_BUCKET_CONTRACT_INVALID"


def test_intent_rejects_account_regional_bucket_name_drift() -> None:
    intent = _intent()
    intent["names"]["artifact_bucket"] = "scanalyze-g376-art-wrong"
    intent = _seal(
        {key: value for key, value in intent.items() if key != "intent_digest"},
        "intent_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.validate_bootstrap_intent(intent)
    assert raised.value.code == "INTENT_NAME_BINDING_INVALID"


def test_bridge_policy_is_time_region_action_and_resource_bounded() -> None:
    template = _load(BRIDGE)
    policy = template["Resources"]["ArtifactBootstrapPermissionSet"]["Properties"][
        "InlinePolicy"
    ]
    statements = {item["Sid"]: item for item in policy["Statement"]}
    assert statements["DenyEveryUnreviewedAction"]["Effect"] == "Deny"
    assert statements["DenyOutsideHomeRegion"]["NotAction"] == "sts:GetCallerIdentity"
    deny_mutations = statements["DenyMutationsAtAbsoluteExpiry"]
    assert set(deny_mutations["Action"]) == {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:TagResource",
        "kms:GenerateDataKey",
        "s3:PutObject",
        "s3:PutObjectTagging",
        "signer:StartSigningJob",
    }
    assert deny_mutations["Condition"] == {
        "DateGreaterThanEquals": {
            "aws:CurrentTime": {"Ref": "AccessNotAfter"}
        }
    }
    assert statements["DenyAllAtRecoveryExpiry"] == {
        "Sid": "DenyAllAtRecoveryExpiry",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "DateGreaterThanEquals": {
                "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
            }
        },
    }
    signer_create = statements[
        "CreateOnlyExactTaggedSigningProfileThroughCloudFormation"
    ]
    assert signer_create["Action"] == "signer:PutSigningProfile"
    assert signer_create["Resource"] == "*"
    assert signer_create["Condition"]["ForAllValues:StringEquals"][
        "aws:TagKeys"
    ] == ["managed_by", "service", "work_package", "source_commit"]
    signer_read = statements[
        "CreateExactTaggedSigningFoundationThroughCloudFormation"
    ]
    assert "signer:PutSigningProfile" not in signer_read["Action"]
    assert "signer:CancelSigningProfile" in signer_read["Action"]
    create_change_sets = statements["CreateOnlyNamedFoundationChangeSets"]
    execute_change_sets = statements["ExecuteOnlyNamedFoundationChangeSets"]
    exact_names = [
        "gug376-artifact-foundation-create",
        "gug376-artifact-foundation-access-update",
    ]
    assert create_change_sets["Condition"]["StringEquals"][
        "cloudformation:ChangeSetName"
    ] == exact_names
    assert create_change_sets["Condition"]["Null"] == {
        "cloudformation:RoleArn": "true",
        "cloudformation:TemplateUrl": "true",
    }
    execute_patterns = [
        item["Fn::Sub"]
        .replace("${AWS::Partition}", "aws")
        .replace("${AuthorityAccountId}", pure.AUTHORITY_ACCOUNT_ID)
        for item in execute_change_sets["Condition"]["StringLike"][
            "cloudformation:ChangeSetName"
        ]
    ]
    expected_patterns = [
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            f"{name}/*"
        )
        for name in exact_names
    ]
    assert execute_patterns == expected_patterns
    for name, pattern in zip(exact_names, execute_patterns, strict=True):
        change_set_arn = (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            f"{name}/11111111-1111-4111-8111-111111111111"
        )
        assert fnmatchcase(change_set_arn, pattern)
        assert not fnmatchcase(name, pattern)
        assert not fnmatchcase(change_set_arn.replace("042360977644", "000000000000"), pattern)
    tag_on_create = statements["TagOnlyNamedFoundationChangeSetsOnCreate"]
    assert tag_on_create["Action"] == "cloudformation:TagResource"
    assert set(tag_on_create["Condition"]["StringEquals"][
        "cloudformation:CreateAction"
    ]) == {"CreateChangeSet", "ExecuteChangeSet"}
    assert tag_on_create["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": pure.REGION,
        "cloudformation:CreateAction": ["CreateChangeSet", "ExecuteChangeSet"],
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-376",
    }
    assert tag_on_create["Condition"]["ForAllValues:StringEquals"][
        "aws:TagKeys"
    ] == ["managed_by", "service", "work_package"]
    assert set(statements["ReadOnlyExactKmsFoundationDirect"]["Action"]) == {
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
    }
    assert statements["ListOnlyKmsAliasesDirectForExactReadback"]["Resource"] == "*"
    assert set(
        statements["ReadOnlyExactArtifactBucketConfigurationDirect"]["Action"]
    ) == {
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
    }
    bucket_version_actions = statements["ReadOnlyExactArtifactBucketVersions"][
        "Action"
    ]
    assert set(
        bucket_version_actions
        if isinstance(bucket_version_actions, list)
        else [bucket_version_actions]
    ) == {"s3:ListBucketVersions"}
    assert set(statements["ReadOnlyExactSigningProfileDirect"]["Action"]) == {
        "signer:GetSigningProfile",
        "signer:ListTagsForResource",
    }
    revocation = statements["ReadOnlyExactSignerRevocationEvidence"]
    assert revocation["Action"] == "signer:GetRevocationStatus"
    assert revocation["Resource"] == [
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:signer:us-east-1:${AuthorityAccountId}:"
                "/signing-profiles/${SigningProfileName}"
            )
        },
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:signer:us-east-1:${AuthorityAccountId}:"
                "/signing-jobs/*"
            )
        },
    ]
    certificate = statements["ReadOnlyAuthoritySignerCertificates"]
    assert certificate["Action"] == "acm:GetCertificate"
    assert certificate["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:acm:us-east-1:${AuthorityAccountId}:"
            "certificate/*"
        )
    }
    for statement in (revocation, certificate):
        assert statement["Condition"] == {
            "StringEquals": {"aws:RequestedRegion": pure.REGION},
            "DateGreaterThanEquals": {"aws:CurrentTime": {"Ref": "AccessNotBefore"}},
            "DateLessThan": {"aws:CurrentTime": {"Ref": "RecoveryNotAfter"}},
        }
    deny_allowlist = set(statements["DenyEveryUnreviewedAction"]["NotAction"])
    assert {"acm:GetCertificate", "signer:GetRevocationStatus"} <= deny_allowlist
    assert set(statements["ReadOnlyTaggedCodeSigningConfigDirect"]["Action"]) == {
        "lambda:GetCodeSigningConfig",
        "lambda:ListTags",
    }
    encrypt_key_use = statements["EncryptOnlyWithArtifactKeyThroughExactS3"]
    read_key_use = statements["ReadOnlyWithArtifactKeyThroughExactS3"]
    assert encrypt_key_use["Action"] == "kms:GenerateDataKey"
    assert set(read_key_use["Action"]) == {"kms:Decrypt", "kms:DescribeKey"}
    assert encrypt_key_use["Condition"]["ForAnyValue:StringLike"][
        "kms:ResourceAliases"
    ] == {
        "Ref": "ArtifactKmsAlias"
    }
    assert statements["PublishOnlyExactGug376Objects"]["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:s3:::${ArtifactBucketName}/"
            "scanalyze/platform-authority/gug-376/plan-policy-repair/*"
        )
    }
    assert statements["ReadOnlyExactGug376Objects"]["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:s3:::${ArtifactBucketName}/"
            "scanalyze/platform-authority/gug-376/plan-policy-repair/*"
        )
    }
    mutation_sids = {
        "CreateOnlyNamedFoundationChangeSets",
        "TagOnlyNamedFoundationChangeSetsOnCreate",
        "ExecuteOnlyNamedFoundationChangeSets",
        "PublishOnlyExactGug376Objects",
        "EncryptOnlyWithArtifactKeyThroughExactS3",
        "StartOnlyPinnedSigningProfileVersion",
    }
    recovery_sids = {
        "RecoverOnlyExactBootstrapMutations",
        "ReadOnlyExactFoundationStack",
        "ReadOnlyExactKmsFoundationDirect",
        "ListOnlyKmsAliasesDirectForExactReadback",
        "ReadOnlyExactSigningProfileDirect",
        "ReadOnlyTaggedCodeSigningConfigDirect",
        "ReadOnlyExactGug376Objects",
        "ReadOnlyExactArtifactBucketVersions",
        "ReadOnlyExactArtifactBucketConfigurationDirect",
        "ReadOnlyWithArtifactKeyThroughExactS3",
        "ReadOnlyExactSigningJobs",
        "ReadOnlyExactSignerRevocationEvidence",
        "ReadOnlyAuthoritySignerCertificates",
        "CreateExactTaggedKmsFoundationThroughCloudFormation",
        "ManageOnlyTaggedKmsFoundationThroughCloudFormation",
        "CreateOnlyExactKmsAliasThroughCloudFormation",
        "DeleteOnlyExactKmsAliasThroughCloudFormation",
        "CreateOnlyExactAccountRegionalArtifactBucketThroughCloudFormation",
        "ManageExactArtifactBucketThroughCloudFormation",
        "CreateExactTaggedSigningFoundationThroughCloudFormation",
        "CreateOnlyExactTaggedSigningProfileThroughCloudFormation",
        "CreateTaggedCodeSigningConfigThroughCloudFormation",
        "ReadTaggedCodeSigningConfigThroughCloudFormation",
        "DeleteTaggedCodeSigningConfigThroughCloudFormation",
    }
    for sid in mutation_sids:
        assert statements[sid]["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "AccessNotAfter"}
        }
    for sid in recovery_sids:
        assert statements[sid]["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
        }
    text = BRIDGE.read_text(encoding="utf-8")
    for forbidden in (
            "iam:*",
            "sso:CreatePermissionSet",
            "cloudformation:CreateStack",
        "s3:DeleteObject",
        "signer:RevokeSigningProfile",
    ):
        assert forbidden not in text


def test_foundation_provider_completion_and_cleanup_are_cfn_only_until_recovery() -> None:
    template = _load(BRIDGE)
    statements = {
        item["Sid"]: item
        for item in template["Resources"]["ArtifactBootstrapPermissionSet"][
            "Properties"
        ]["InlinePolicy"]["Statement"]
    }
    provider_sids = {
        "CreateExactTaggedKmsFoundationThroughCloudFormation",
        "ManageOnlyTaggedKmsFoundationThroughCloudFormation",
        "CreateOnlyExactKmsAliasThroughCloudFormation",
        "DeleteOnlyExactKmsAliasThroughCloudFormation",
        "CreateOnlyExactAccountRegionalArtifactBucketThroughCloudFormation",
        "ManageExactArtifactBucketThroughCloudFormation",
        "CreateExactTaggedSigningFoundationThroughCloudFormation",
        "CreateOnlyExactTaggedSigningProfileThroughCloudFormation",
        "CreateTaggedCodeSigningConfigThroughCloudFormation",
        "ReadTaggedCodeSigningConfigThroughCloudFormation",
        "DeleteTaggedCodeSigningConfigThroughCloudFormation",
    }
    for sid in provider_sids:
        statement = statements[sid]
        assert statement["Condition"]["ForAnyValue:StringEquals"] == {
            "aws:CalledVia": "cloudformation.amazonaws.com"
        }
        assert statement["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
        }

    assert "kms:ScheduleKeyDeletion" in statements[
        "ManageOnlyTaggedKmsFoundationThroughCloudFormation"
    ]["Action"]
    assert statements["DeleteOnlyExactKmsAliasThroughCloudFormation"] == {
        "Sid": "DeleteOnlyExactKmsAliasThroughCloudFormation",
        "Effect": "Allow",
        "Action": "kms:DeleteAlias",
        "Resource": {
            "Fn::Sub": (
                "arn:${AWS::Partition}:kms:us-east-1:${AuthorityAccountId}:"
                "${ArtifactKmsAlias}"
            )
        },
        "Condition": {
            "ForAnyValue:StringEquals": {
                "aws:CalledVia": "cloudformation.amazonaws.com"
            },
            "StringEquals": {"aws:RequestedRegion": pure.REGION},
            "DateGreaterThanEquals": {
                "aws:CurrentTime": {"Ref": "AccessNotBefore"}
            },
            "DateLessThan": {
                "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
            },
        },
    }
    bucket_cleanup = statements["ManageExactArtifactBucketThroughCloudFormation"]
    assert {"s3:DeleteBucket", "s3:DeleteBucketPolicy"} <= set(
        bucket_cleanup["Action"]
    )
    assert "s3:DeleteObject" not in bucket_cleanup["Action"]
    assert "signer:CancelSigningProfile" in statements[
        "CreateExactTaggedSigningFoundationThroughCloudFormation"
    ]["Action"]
    lambda_cleanup = statements["DeleteTaggedCodeSigningConfigThroughCloudFormation"]
    assert lambda_cleanup["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": pure.REGION,
        "aws:ResourceTag/work_package": "GUG-376",
        "aws:ResourceTag/source_commit": {"Ref": "SourceCommit"},
    }

    direct_deny = statements["DenyDirectFoundationProviderMutations"]
    cleanup_actions = {
        "kms:DeleteAlias",
        "kms:ScheduleKeyDeletion",
        "lambda:DeleteCodeSigningConfig",
        "s3:DeleteBucket",
        "s3:DeleteBucketPolicy",
        "signer:CancelSigningProfile",
    }
    assert cleanup_actions <= set(direct_deny["Action"])
    assert direct_deny["Condition"] == {
        "ForAllValues:StringNotEquals": {
            "aws:CalledVia": "cloudformation.amazonaws.com"
        }
    }
    assert cleanup_actions.isdisjoint(
        statements["DenyMutationsAtAbsoluteExpiry"]["Action"]
    )


def test_foundation_is_six_resources_and_retain_bound() -> None:
    template = _load(FOUNDATION)
    resources = template["Resources"]
    assert {item["Type"] for item in resources.values()} == {
        "AWS::KMS::Key",
        "AWS::KMS::Alias",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
        "AWS::Signer::SigningProfile",
        "AWS::Lambda::CodeSigningConfig",
    }
    assert len(resources) == 6
    for logical_id in ("ArtifactKey", "ArtifactBucket", "SigningProfile", "CodeSigningConfig"):
        assert resources[logical_id]["DeletionPolicy"] == "RetainExceptOnCreate"
        assert resources[logical_id]["UpdateReplacePolicy"] == "Retain"
    assert template["Outputs"]["SigningProfileName"]["Value"] == {
        "Fn::GetAtt": "SigningProfile.ProfileName"
    }
    assert template["Outputs"]["CodeSigningConfigArn"]["Value"] == {
        "Fn::GetAtt": "CodeSigningConfig.CodeSigningConfigArn"
    }
    signing_tags = resources["SigningProfile"]["Properties"]["Tags"]
    assert isinstance(signing_tags, list) and len(signing_tags) == 4
    assert {item["Key"] for item in signing_tags} == {
        "managed_by",
        "service",
        "work_package",
        "source_commit",
    }


def test_all_submitted_cloudformation_templates_forbid_yaml_anchors_and_aliases() -> None:
    submitted = (
        BRIDGE,
        FOUNDATION,
        ROOT / "bootstrap/cfn-platform-authority-gug376-temporary-change-set-route.yaml",
        ROOT / "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml",
    )
    anchor_or_alias = re.compile(
        r"(?:^|\s)[&*][A-Za-z][A-Za-z0-9_-]*", re.MULTILINE
    )
    for path in submitted:
        assert anchor_or_alias.search(path.read_text(encoding="utf-8")) is None, path


def test_bucket_key_context_and_signer_header_exception_are_exact() -> None:
    template = _load(FOUNDATION)
    key_statements = template["Resources"]["ArtifactKey"]["Properties"]["KeyPolicy"][
        "Statement"
    ]
    assert pure.canonical_json(key_statements).count(
        "kms:EncryptionContext:aws:s3:arn"
    ) == 3
    text = FOUNDATION.read_text(encoding="utf-8")
    expected_context = (
        "kms:EncryptionContext:aws:s3:arn: !Sub "
        "arn:${AWS::Partition}:s3:::${ArtifactBucketName}"
    )
    assert text.count(expected_context) == 3
    assert "kms:EncryptionContext:aws:s3:arn: !Sub arn:${AWS::Partition}:s3:::${ArtifactBucketName}/" not in text
    bucket_statements = template["Resources"]["ArtifactBucketPolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    by_sid = {
        item["Sid"]: item
        for item in bucket_statements
        if isinstance(item, Mapping) and "Sid" in item
    }
    for sid in ("DenyUnencryptedObjectWrites", "DenyWrongKmsKey"):
        assert by_sid[sid]["NotPrincipal"] == {"Service": "signer.amazonaws.com"}
        assert "Principal" not in by_sid[sid]


def test_kms_readers_require_identity_policy_and_have_no_principal_star_bypass() -> None:
    template = _load(FOUNDATION)
    statements = template["Resources"]["ArtifactKey"]["Properties"]["KeyPolicy"][
        "Statement"
    ]
    conditional = [item["Fn::If"] for item in statements if "Fn::If" in item]
    assert all(
        branch[1].get("Sid") != "AllowExactReadersWithoutIdentityKmsDecrypt"
        for branch in conditional
    )
    assert all(branch[1].get("Principal") != "*" for branch in conditional)
    delegated = next(
        branch[1]
        for branch in conditional
        if branch[1].get("Sid") == "AllowExactGug376ReadersThroughBucketKeyS3Only"
    )
    assert delegated["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1",
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": {
            "Fn::Sub": "arn:${AWS::Partition}:s3:::${ArtifactBucketName}"
        },
    }


def test_offline_intent_uses_template_body_and_causal_order() -> None:
    intent = _intent()
    assert pure.validate_bootstrap_intent(intent) == intent
    assert intent["recovery_not_after"] == "2026-08-31T13:00:00Z"
    bridge_parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in intent["requests"]["bridge-create"]["Parameters"]
    }
    assert bridge_parameters["AccessNotAfter"] == "2026-08-30T13:00:00Z"
    assert bridge_parameters["RecoveryNotAfter"] == "2026-08-31T13:00:00Z"
    assert intent["required_order"] == [
        "bridge-create",
        "foundation-create",
        "bridge-pin-signing-profile-version",
        "publish-and-readback-route-and-delegation",
        "foundation-access-update",
        "publish-and-sign-artifacts",
        "bridge-revoke",
        "normal-route",
    ]
    assert "TemplateURL" not in pure.canonical_json(intent["requests"])
    assert intent["requests"]["foundation-create"]["Parameters"][-3:] == [
        {"ParameterKey": "CrossAccountAccessEnabled", "ParameterValue": "false"},
        {"ParameterKey": "RouteTemplateVersion", "ParameterValue": "NOT_CONFIGURED"},
        {"ParameterKey": "DelegationTemplateVersion", "ParameterValue": "NOT_CONFIGURED"},
    ]
    assert intent["requests"]["bridge-revoke"]["ChangeSetType"] == "UPDATE"
    assert intent["requests"]["bridge-create"]["Capabilities"] == [
        "CAPABILITY_NAMED_IAM"
    ]
    assert intent["requests"]["bridge-revoke"]["Capabilities"] == [
        "CAPABILITY_NAMED_IAM"
    ]
    assert intent["requests"]["foundation-create"]["Capabilities"] == []


def test_bridge_intent_rejects_missing_named_iam_acknowledgement() -> None:
    intent = _intent()
    intent["requests"]["bridge-create"]["Capabilities"] = []
    intent["request_digests"]["bridge-create"] = pure.digest_value(
        intent["requests"]["bridge-create"]
    )
    intent = _seal(
        {key: value for key, value in intent.items() if key != "intent_digest"},
        "intent_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.validate_bootstrap_intent(intent)
    assert raised.value.code == "INTENT_REQUEST_RECONSTRUCTION_MISMATCH"


def test_create_requests_fail_delete_without_disable_rollback() -> None:
    intent = _intent()
    for operation in ("bridge-create", "foundation-create"):
        request = intent["requests"][operation]
        assert request["OnStackFailure"] == "DELETE"
        assert "DisableRollback" not in request
        trail = aws._cloudtrail_cfn_request(request)
        assert trail["onStackFailure"] == "DELETE"
    update = intent["requests"]["bridge-revoke"]
    assert "OnStackFailure" not in update
    assert "DisableRollback" not in update
    assert "onStackFailure" not in aws._cloudtrail_cfn_request(update)


@pytest.mark.parametrize(
    ("operation", "mutation"),
    [
        ("bridge-create", {"OnStackFailure": None}),
        ("bridge-create", {"OnStackFailure": "DO_NOTHING"}),
        ("bridge-create", {"DisableRollback": False}),
        ("bridge-revoke", {"OnStackFailure": "DELETE"}),
        ("bridge-revoke", {"DisableRollback": False}),
    ],
)
def test_cloudtrail_contract_rejects_rollback_surface_drift(
    operation: str, mutation: dict[str, Any]
) -> None:
    request = copy.deepcopy(_intent()["requests"][operation])
    for key, value in mutation.items():
        if value is None:
            request.pop(key, None)
        else:
            request[key] = value
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        aws._cloudtrail_cfn_request(request)
    assert raised.value.code == "CLOUDFORMATION_REQUEST_INVALID"


def test_execute_request_omits_disable_rollback_and_rejects_injection() -> None:
    request = {
        "ChangeSetName": "arn:aws:cloudformation:us-east-1:042360977644:changeSet/x/y",
        "StackName": "arn:aws:cloudformation:us-east-1:042360977644:stack/x/y",
        "ClientRequestToken": "gug376-" + "a" * 48,
    }
    assert aws._cloudtrail_execute_request(request) == {
        "changeSetName": request["ChangeSetName"],
        "stackName": request["StackName"],
        "clientRequestToken": request["ClientRequestToken"],
    }
    request["DisableRollback"] = False
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        aws._cloudtrail_execute_request(request)
    assert raised.value.code == "CLOUDFORMATION_EXECUTE_REQUEST_INVALID"


def test_intent_rejects_recovery_horizon_drift_even_when_resealed() -> None:
    intent = _intent()
    candidate = copy.deepcopy(intent)
    candidate["recovery_not_after"] = "2026-08-31T13:00:01Z"
    candidate = _seal(
        {key: value for key, value in candidate.items() if key != "intent_digest"},
        "intent_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.validate_bootstrap_intent(candidate)
    assert raised.value.code == "INTENT_WINDOW_INVALID"


def test_materializer_requires_an_operational_window_with_completion_reserve() -> None:
    assert pure.MIN_ACCESS_WINDOW_SECONDS == 3600
    assert pure.MUTATION_COMPLETION_RESERVE_SECONDS == 1800
    value = _input()
    value["access_not_after"] = "2026-08-30T12:54:59Z"
    value = _seal(
        {key: item for key, item in value.items() if key != "input_digest"},
        "input_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.materialize_bootstrap_intent(
            value,
            bridge_template=BRIDGE.read_bytes(),
            foundation_template=FOUNDATION.read_bytes(),
        )
    assert raised.value.code == "INPUT_INVALID"


def test_authorization_cannot_cross_the_mutation_admission_cutoff() -> None:
    intent = _intent()
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.materialize_authorization(
            intent=intent,
            operation="bridge-create:dispatch",
            authorization=f"AUTHORIZE GUG-376 bridge-create:dispatch {COMMIT}",
            authorized_at=datetime(2026, 8, 30, 12, 29, tzinfo=timezone.utc),
            expires_at=datetime(2026, 8, 30, 12, 31, tzinfo=timezone.utc),
        )
    assert raised.value.code == "AUTHORIZATION_INVALID"


def test_runtime_reserves_completion_horizon_but_keeps_recovery_open(
    tmp_path: Path,
) -> None:
    intent = _intent()
    cutoff = datetime(2026, 8, 30, 12, 30, tzinfo=timezone.utc)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(object(), object()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: cutoff,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider._require_window(intent, read_only=False)
    assert raised.value.code == "WRITE_WINDOW_CLOSED"
    assert provider._require_window(intent, read_only=True) == cutoff


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        (
            "dispatch_change_set_once",
            {"operation": "bridge-create", "authorization": {}},
        ),
        (
            "execute_change_set_once",
            {
                "operation": "bridge-create",
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "dispatch_bridge_pin_once",
            {"foundation_readback": {}, "bridge_pin": {}, "authorization": {}},
        ),
        (
            "execute_bridge_pin_once",
            {
                "foundation_readback": {},
                "bridge_pin": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "dispatch_foundation_access_update_once",
            {
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
                "authorization": {},
            },
        ),
        (
            "execute_foundation_access_update_once",
            {
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "publish_object_once",
            {
                "foundation_readback": {},
                "object_intent": {},
                "body": b"",
                "authorization": {},
            },
        ),
        (
            "start_signing_job_once",
            {
                "foundation_readback": {},
                "bridge_pin": {},
                "bridge_pin_readback": {},
                "unsigned_receipt": {},
                "signing_intent": {},
                "authorization": {},
            },
        ),
    ],
)
def test_product_provider_defers_collision_admission_until_after_validation(
    tmp_path: Path, method: str, kwargs: dict[str, Any]
) -> None:
    authority_methods = {
        "dispatch_foundation_access_update_once",
        "execute_foundation_access_update_once",
        "publish_object_once",
        "start_signing_job_once",
    }
    provider = aws.ConnectedArtifactBootstrapProvider(
        clients=aws.Clients(
            object(),
            object(),
            s3=object() if method == "publish_object_once" else None,
            signer=object() if method == "start_signing_job_once" else None,
        ),
        claims=_claim_store(tmp_path),
        profile=(
            pure.AUTHORITY_PROFILE
            if method in authority_methods
            else pure.MANAGEMENT_PROFILE
        ),
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: pytest.fail("source must not be read"),
        collision_admission_loader=lambda **_kwargs: pytest.fail(
            "admission must be loaded only after validated preflights"
        ),
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        getattr(provider, method)(
            bootstrap_intent={}, source_root=ROOT, **kwargs
        )
    assert raised.value.code == "INTENT_INVALID"


@pytest.mark.parametrize(
    ("method", "extra"),
    [
        (
            "dispatch_change_set_once",
            {"authorization": {}},
        ),
        (
            "execute_change_set_once",
            {
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
    ],
)
def test_product_provider_opens_only_exact_bridge_revoke_before_validation(
    tmp_path: Path, method: str, extra: Mapping[str, Any]
) -> None:
    provider = aws.ConnectedArtifactBootstrapProvider(
        clients=aws.Clients(object(), object()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: pytest.fail("source must not be read"),
    )
    with pytest.raises(pure.ArtifactBootstrapError) as opened:
        getattr(provider, method)(
            bootstrap_intent={},
            source_root=ROOT,
            operation="bridge-revoke",
            **dict(extra),
        )
    assert opened.value.code == "INTENT_INVALID"


@pytest.mark.parametrize(
    "read_at",
    ["2026-08-31T13:00:00Z", "2026-08-31T13:00:01Z"],
)
def test_resealed_artifact_readbacks_reject_recovery_horizon(
    read_at: str,
) -> None:
    intent = _intent()
    candidates: list[tuple[dict[str, Any], Any, dict[str, Any], str]] = []

    foundation = _foundation_readback()
    foundation["read_at"] = read_at
    foundation = _seal(
        {key: value for key, value in foundation.items() if key != "readback_digest"},
        "readback_digest",
    )
    candidates.append(
        (
            foundation,
            pure.validate_foundation_readback,
            {"bootstrap_intent": intent},
            "FOUNDATION_READBACK_INVALID",
        )
    )

    obj = _object_receipt("template.yaml")
    obj["read_at"] = read_at
    obj = _seal(
        {key: value for key, value in obj.items() if key != "receipt_digest"},
        "receipt_digest",
    )
    candidates.append(
        (
            obj,
            pure.validate_object_receipt,
            {
                "bootstrap_intent": intent,
                "foundation_readback": _foundation_readback(),
            },
            "OBJECT_RECEIPT_INVALID",
        )
    )

    stack = _bridge_pin_readback()
    stack["read_at"] = read_at
    stack = _seal(
        {key: value for key, value in stack.items() if key != "readback_digest"},
        "readback_digest",
    )
    candidates.append(
        (
            stack,
            pure.validate_stack_readback,
            {
                "bootstrap_intent": intent,
                "operation": "bridge-pin",
                "bridge_pin": _bridge_pin(),
                "foundation_readback": _foundation_readback(),
            },
            "STACK_READBACK_INVALID",
        )
    )

    for candidate, validator, kwargs, expected_code in candidates:
        with pytest.raises(pure.ArtifactBootstrapError) as raised:
            validator(candidate, **kwargs)
        assert raised.value.code == expected_code


@pytest.mark.parametrize("seconds_after", [0, 1])
def test_resealed_access_readback_rejects_recovery_horizon(
    seconds_after: int,
) -> None:
    contract = build_foundation_contract(source_commit=COMMIT, observed_at=NOW)
    intent = contract["bootstrap_intent"]
    boundary = datetime.fromisoformat(
        intent["recovery_not_after"][:-1] + "+00:00"
    ) + timedelta(seconds=seconds_after)
    candidate = copy.deepcopy(contract["access_readback"])
    candidate["read_at"] = boundary.isoformat().replace("+00:00", "Z")
    candidate = _seal(
        {key: value for key, value in candidate.items() if key != "readback_digest"},
        "readback_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.validate_foundation_access_readback(
            candidate,
            bootstrap_intent=intent,
            foundation_readback=contract["foundation_readback"],
            access_update=contract["access_update"],
            route_template_receipt=contract["route_object_receipt"],
            delegation_template_receipt=contract["delegation_object_receipt"],
            reviewed_sources=contract["reviewed_sources"],
        )
    assert raised.value.code == "FOUNDATION_ACCESS_READBACK_INVALID"


def test_access_update_binds_two_exact_receipts_and_versions() -> None:
    route = _object_receipt(
        "cfn-platform-authority-gug376-temporary-change-set-route.yaml",
        "Route-Version-A",
    )
    delegation = _object_receipt(
        "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml",
        "Delegation-Version-B",
    )
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=_intent(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        foundation_readback=_foundation_readback(),
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    assert pure.validate_foundation_access_update(
        update,
        bootstrap_intent=_intent(),
        foundation_readback=_foundation_readback(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
    ) == update
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in update["request"]["Parameters"]
    }
    assert parameters["CrossAccountAccessEnabled"] == "true"
    assert parameters["RouteTemplateVersion"] == "Route-Version-A"
    assert parameters["DelegationTemplateVersion"] == "Delegation-Version-B"
    assert update["route_template_version_digest"] == pure.digest_value(
        "Route-Version-A"
    )
    assert "TemplateURL" not in update["request"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("receipt_digest", "sha256:" + "0" * 64),
        ("version", "null"),
        ("sse_kms_key_arn", KMS_ARN.replace("2222", "3333")),
        ("bucket_key_enabled", False),
    ],
)
def test_access_update_rejects_tampered_receipt(field: str, replacement: Any) -> None:
    route = _object_receipt(
        "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
    )
    route[field] = replacement
    if field != "receipt_digest":
        route = _seal(
            {key: item for key, item in route.items() if key != "receipt_digest"},
            "receipt_digest",
        )
    with pytest.raises(pure.ArtifactBootstrapError):
        pure.materialize_foundation_access_update(
            bootstrap_intent=_intent(),
            route_template_receipt=route,
            delegation_template_receipt=_object_receipt(
                "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
            ),
            foundation_readback=_foundation_readback(),
            reviewed_sources=_reviewed_sources(),
            foundation_template=FOUNDATION.read_bytes(),
        )


def test_object_validator_rejects_each_critical_request_drift() -> None:
    original = _object_intent("template.yaml")
    mutations = (
        ("ChecksumSHA256", base64.b64encode(b"x" * 32).decode("ascii")),
        ("SSEKMSKeyId", KMS_ARN.replace("2222", "3333")),
        ("ContentLength", 0),
        ("ContentType", "application/octet-stream"),
        ("BucketKeyEnabled", False),
        ("Tagging", "work_package=GUG-376"),
    )
    for key, value in mutations:
        candidate = copy.deepcopy(original)
        candidate["request"][key] = value
        candidate["request_digest"] = pure.digest_value(candidate["request"])
        candidate = _seal(
            {item: data for item, data in candidate.items() if item != "intent_digest"},
            "intent_digest",
        )
        with pytest.raises(pure.ArtifactBootstrapError):
            pure.validate_object_intent(
                candidate,
                bootstrap_intent=_intent(),
                foundation_readback=_foundation_readback(),
            )


def test_signing_intent_requires_canonical_unsigned_receipt() -> None:
    receipt = _object_receipt("unsigned.zip")
    receipt["receipt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.materialize_signing_intent(
            bootstrap_intent=_intent(),
            foundation_readback=_foundation_readback(),
            bridge_pin=_bridge_pin(),
            bridge_pin_readback=_bridge_pin_readback(),
            unsigned_receipt=receipt,
            destination_prefix=f"{pure.ARTIFACT_PREFIX}pep/signed/{COMMIT}/",
            profile_name=_intent()["names"]["signing_profile_name"],
        )
    assert raised.value.code == "SIGNING_UNSIGNED_RECEIPT_INVALID"


class Sts:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def get_caller_identity(self) -> dict[str, Any]:
        self.events.append("sts")
        return {
            "Account": pure.AUTHORITY_ACCOUNT_ID,
            "Arn": AUTH_CALLER,
            "UserId": "operator",
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class S3Put:
    def __init__(self, events: list[str], intent: Mapping[str, Any]) -> None:
        self.events = events
        self.intent = intent
        self.calls = 0

    def list_object_versions(self, **_request: Any) -> dict[str, Any]:
        self.events.append("list")
        return {
            "Versions": [],
            "DeleteMarkers": [],
            "IsTruncated": False,
            "ResponseMetadata": {"RequestId": "4V7EXAMPLEREQUEST"},
        }

    def put_object(self, **request: Any) -> dict[str, Any]:
        self.events.append("put")
        self.calls += 1
        assert request["Body"] == b"template"
        return {
            "VersionId": "Version-A",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.intent["request"]["SSEKMSKeyId"],
            "ChecksumSHA256": self.intent["request"]["ChecksumSHA256"],
            "ResponseMetadata": {"RequestId": "4V7EXAMPLEREQUEST"},
        }


class CloudFormationUnused:
    pass


def _claim_store(tmp_path: Path) -> aws.OExclClaimStore:
    tmp_path.chmod(0o700)
    return aws.OExclClaimStore(tmp_path)


@pytest.mark.parametrize(
    ("action", "profile", "kwargs"),
    [
        (
            "dispatch_change_set_once",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "operation": "bridge-create",
                "authorization": {},
            },
        ),
        (
            "execute_change_set_once",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "operation": "bridge-create",
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "dispatch_bridge_pin_once",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "authorization": {},
            },
        ),
        (
            "execute_bridge_pin_once",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "dispatch_foundation_access_update_once",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
                "authorization": {},
            },
        ),
        (
            "execute_foundation_access_update_once",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
        (
            "publish_object_once",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "object_intent": {},
                "body": b"",
                "authorization": {},
            },
        ),
        (
            "start_signing_job_once",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "bridge_pin_readback": {},
                "unsigned_receipt": {},
                "signing_intent": {},
                "authorization": {},
            },
        ),
    ],
)
def test_every_connected_write_closes_exactly_at_access_not_after_before_sts(
    tmp_path: Path,
    action: str,
    profile: str,
    kwargs: dict[str, Any],
) -> None:
    aws_events: list[str] = []
    source_events: list[str] = []

    def source_attestor(**_kwargs: Any) -> dict[str, Any]:
        source_events.append("source")
        return _reviewed_sources()

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(aws_events),
            CloudFormationUnused(),
            cloudtrail=object(),
            kms=object(),
            s3=object(),
            signer=object(),
            lambda_client=object(),
        ),
        claims=_claim_store(tmp_path),
        profile=profile,
        clock=lambda: datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc),
        source_attestor=source_attestor,
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        getattr(provider, action)(bootstrap_intent=_intent(), **kwargs)
    assert raised.value.code == "WRITE_WINDOW_CLOSED"
    assert aws_events == []
    assert source_events == []


@pytest.mark.parametrize(
    ("action", "profile", "kwargs"),
    [
        (
            "attest_change_set",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "operation": "bridge-create",
                "dispatch_receipt": {},
            },
        ),
        (
            "recover_change_set",
            pure.MANAGEMENT_PROFILE,
            {"source_root": ROOT, "operation": "bridge-create"},
        ),
        (
            "recover_change_set_execution",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "operation": "bridge-create",
                "dispatch_receipt": {},
                "change_set_attestation": {},
            },
        ),
        (
            "recover_bridge_pin",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
            },
        ),
        (
            "recover_bridge_pin_execution",
            pure.MANAGEMENT_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
            },
        ),
        (
            "recover_foundation_access_update",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
            },
        ),
        (
            "recover_foundation_access_update_execution",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
                "dispatch_receipt": {},
                "change_set_attestation": {},
            },
        ),
        (
            "readback_foundation_access_update",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "access_update": {},
                "route_template_receipt": {},
                "delegation_template_receipt": {},
            },
        ),
        (
            "readback_stack",
            pure.MANAGEMENT_PROFILE,
            {"source_root": ROOT, "operation": "bridge-create"},
        ),
        (
            "readback_foundation",
            pure.AUTHORITY_PROFILE,
            {"source_root": ROOT},
        ),
        (
            "readback_object",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "object_intent": {},
                "dispatch_receipt": {},
            },
        ),
        (
            "recover_object_publish",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "object_intent": {},
            },
        ),
        (
            "readback_signing_job",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "bridge_pin_readback": {},
                "unsigned_receipt": {},
                "signing_intent": {},
                "dispatch_receipt": {},
            },
        ),
        (
            "recover_signing_job",
            pure.AUTHORITY_PROFILE,
            {
                "source_root": ROOT,
                "foundation_readback": {},
                "bridge_pin": {},
                "bridge_pin_readback": {},
                "unsigned_receipt": {},
                "signing_intent": {},
            },
        ),
    ],
)
def test_every_connected_read_and_recovery_closes_at_recovery_not_after_before_sts(
    tmp_path: Path,
    action: str,
    profile: str,
    kwargs: dict[str, Any],
) -> None:
    aws_events: list[str] = []
    source_events: list[str] = []

    def source_attestor(**_kwargs: Any) -> dict[str, Any]:
        source_events.append("source")
        return _reviewed_sources()

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(aws_events),
            CloudFormationUnused(),
            cloudtrail=object(),
            kms=object(),
            s3=object(),
            signer=object(),
            lambda_client=object(),
        ),
        claims=_claim_store(tmp_path),
        profile=profile,
        clock=lambda: datetime(2026, 8, 31, 13, 0, tzinfo=timezone.utc),
        source_attestor=source_attestor,
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        getattr(provider, action)(bootstrap_intent=_intent(), **kwargs)
    assert raised.value.code == "RECOVERY_WINDOW_CLOSED"
    assert aws_events == []
    assert source_events == []


def test_claim_store_rejects_symlink_root(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        aws.OExclClaimStore(linked)
    assert raised.value.code == "CLAIM_ROOT_INVALID"


def test_claim_store_detects_root_swap_before_create(tmp_path: Path) -> None:
    root = tmp_path / "claims"
    root.mkdir(mode=0o700)
    store = aws.OExclClaimStore(root)
    displaced = tmp_path / "displaced"
    root.rename(displaced)
    root.mkdir(mode=0o700)
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        store.reserve(
            operation="bridge-create",
            digest="sha256:" + "1" * 64,
            claimed_at="2026-08-30T12:00:00Z",
        )
    assert raised.value.code == "CLAIM_ROOT_CHANGED"
    assert not list(root.iterdir())
    assert not list(displaced.iterdir())
    store.close()


def test_claim_store_completes_short_writes_and_fsyncs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _claim_store(tmp_path)
    real_write = os.write
    calls = 0

    def short_write(descriptor: int, payload: Any) -> int:
        nonlocal calls
        calls += 1
        limited = bytes(payload[:7]) if calls == 1 else bytes(payload)
        return real_write(descriptor, limited)

    monkeypatch.setattr(aws.os, "write", short_write)
    claim = store.reserve(
        operation="foundation-create",
        digest="sha256:" + "2" * 64,
        claimed_at="2026-08-30T12:00:00Z",
    )
    assert calls >= 2
    assert json.loads(claim.read_text(encoding="utf-8"))["target_digest"] == (
        "sha256:" + "2" * 64
    )
    assert claim.stat().st_mode & 0o777 == 0o600
    store.close()


def _mutation_auth(operation: str, target: str) -> dict[str, Any]:
    phrase = f"AUTHORIZE GUG-376 {operation} {target}"
    return pure.materialize_mutation_authorization(
        bootstrap_intent=_intent(),
        operation=operation,
        target_digest=target,
        authorization=phrase,
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )


def _fresh_mutation_auth(
    operation: str, target: str, *, seconds_before: int
) -> dict[str, Any]:
    phrase = f"AUTHORIZE GUG-376 {operation} {target}"
    return pure.materialize_mutation_authorization(
        bootstrap_intent=_intent(),
        operation=operation,
        target_digest=target,
        authorization=phrase,
        authorized_at=NOW - timedelta(seconds=seconds_before),
        expires_at=NOW + timedelta(minutes=5),
    )


def _admission_binding(
    operation: str, effect_request: Mapping[str, Any]
) -> dict[str, str]:
    return {
        "operation": operation,
        "effect_request_digest": pure.digest_value(effect_request),
        "bootstrap_intent_digest": _intent()["intent_digest"],
        "admission_digest": "sha256:" + "9" * 64,
    }


def _execution_dispatch(
    *,
    operation: str,
    intent_digest: str,
    request_digest: str,
    authorization_digest: str = "sha256:" + "3" * 64,
    dispatched_at: str = "2026-08-30T11:59:00Z",
    request_id: str = REQUEST_ID,
) -> dict[str, Any]:
    authority = operation in {"foundation-create", "foundation-access-update"}
    account = (
        pure.AUTHORITY_ACCOUNT_ID if authority else pure.MANAGEMENT_ACCOUNT_ID
    )
    profile = pure.AUTHORITY_PROFILE if authority else pure.MANAGEMENT_PROFILE
    caller = AUTH_CALLER if authority else MGMT_CALLER
    stack_name = (
        pure.FOUNDATION_STACK_NAME if authority else pure.BRIDGE_STACK_NAME
    )
    change_set_name = {
        "bridge-create": pure.BRIDGE_CHANGE_SET_NAME,
        "foundation-create": pure.FOUNDATION_CHANGE_SET_NAME,
        "bridge-revoke": pure.REVOKE_CHANGE_SET_NAME,
        "bridge-pin": "gug376-artifact-bootstrap-bridge-pin",
        "foundation-access-update": "gug376-artifact-foundation-access-update",
        "bridge-cleanup-retire": pure.CLEANUP_RETIRE_CHANGE_SET_NAME,
    }[operation]
    return _seal(
        {
            "schema_version": 1,
            "record_type": aws.DISPATCH_RECEIPT_TYPE,
            "source_commit": COMMIT,
            "operation": operation,
            "intent_digest": intent_digest,
            "request_digest": request_digest,
            "authorization_digest": authorization_digest,
            "collision_admission": (
                None
                if operation in {"bridge-revoke", "bridge-cleanup-retire"}
                else {
                    "operation": f"{operation}:dispatch",
                    "effect_request_digest": request_digest,
                    "bootstrap_intent_digest": _intent()["intent_digest"],
                    "admission_digest": "sha256:" + "9" * 64,
                }
            ),
            "verifier": {
                "account_id": account,
                "caller_arn": caller,
                "profile": profile,
                "region": pure.REGION,
            },
            "stack_id": (
                f"arn:aws:cloudformation:us-east-1:{account}:stack/"
                f"{stack_name}/11111111-1111-4111-8111-111111111111"
            ),
            "change_set_id": (
                f"arn:aws:cloudformation:us-east-1:{account}:changeSet/"
                f"{change_set_name}/22222222-2222-4222-8222-222222222222"
            ),
            "request_id": request_id,
            "dispatched_at": dispatched_at,
            "aws_calls": 2,
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": pure.PRODUCTION_STATUS,
        },
        "receipt_digest",
    )


def _expected_execution_changes(operation: str) -> list[dict[str, Any]]:
    def add(logical: str, resource_type: str) -> dict[str, Any]:
        return {
            "Type": "Resource",
            "ResourceChange": {
                "LogicalResourceId": logical,
                "ResourceType": resource_type,
                "Action": "Add",
            },
        }

    def modify(
        logical: str,
        resource_type: str,
        property_name: str,
        references: tuple[str, ...],
    ) -> dict[str, Any]:
        return {
            "Type": "Resource",
            "ResourceChange": {
                "LogicalResourceId": logical,
                "ResourceType": resource_type,
                "Action": "Modify",
                "Replacement": "False",
                "Scope": ["Properties"],
                "Details": [
                    {
                        "ChangeSource": "ParameterReference",
                        "Evaluation": "Static",
                        "CausingEntity": reference,
                        "Target": {
                            "Attribute": "Properties",
                            "Name": property_name,
                            "RequiresRecreation": "Never",
                        },
                    }
                    for reference in references
                ],
            },
        }

    changes = {
        "bridge-create": [
            add("ArtifactBootstrapPermissionSet", "AWS::SSO::PermissionSet"),
            add("ArtifactBootstrapAssignment", "AWS::SSO::Assignment"),
            add("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
            add("RouteSeedCleanupAssignment", "AWS::SSO::Assignment"),
            add("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
            add("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment"),
            add("ManagementRecoveryRole", "AWS::IAM::Role"),
        ],
        "foundation-create": [
            add("ArtifactKey", "AWS::KMS::Key"),
            add("ArtifactKeyAlias", "AWS::KMS::Alias"),
            add("ArtifactBucket", "AWS::S3::Bucket"),
            add("ArtifactBucketPolicy", "AWS::S3::BucketPolicy"),
            add("SigningProfile", "AWS::Signer::SigningProfile"),
            add("CodeSigningConfig", "AWS::Lambda::CodeSigningConfig"),
        ],
        "bridge-pin": [
            modify(
                "ArtifactBootstrapPermissionSet",
                "AWS::SSO::PermissionSet",
                "InlinePolicy",
                ("SigningProfileVersion",),
            )
        ],
        "foundation-access-update": [
            modify(
                "ArtifactKey",
                "AWS::KMS::Key",
                "KeyPolicy",
                ("CrossAccountAccessEnabled",),
            ),
            modify(
                "ArtifactBucketPolicy",
                "AWS::S3::BucketPolicy",
                "PolicyDocument",
                (
                    "CrossAccountAccessEnabled",
                    "RouteTemplateVersion",
                    "DelegationTemplateVersion",
                ),
            ),
        ],
        "bridge-revoke": [
            modify(
                "ArtifactBootstrapPermissionSet",
                "AWS::SSO::PermissionSet",
                "InlinePolicy",
                ("SigningProfileVersion",),
            ),
            {
                "Type": "Resource",
                "ResourceChange": {
                    "LogicalResourceId": "ArtifactBootstrapAssignment",
                    "ResourceType": "AWS::SSO::Assignment",
                    "Action": "Remove",
                },
            },
        ],
    }
    return copy.deepcopy(changes[operation])


def _execution_request(operation: str) -> Mapping[str, Any]:
    if operation in _intent()["requests"]:
        return _intent()["requests"][operation]
    if operation == "bridge-pin":
        return _bridge_pin()["request"]
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(DELEGATION_TEMPLATE.name, "Delegation-Version-B")
    return pure.materialize_foundation_access_update(
        bootstrap_intent=_intent(),
        foundation_readback=_foundation_readback(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )["request"]


def _execution_attestation(
    *,
    operation: str,
    intent_digest: str,
    request_digest: str,
    dispatch: Mapping[str, Any],
    request: Mapping[str, Any] | None = None,
    changes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    request = request or _execution_request(operation)
    changes = changes or _expected_execution_changes(operation)
    authority = operation in {"foundation-create", "foundation-access-update"}
    semantic = []
    for item in changes:
        resource = item["ResourceChange"]
        details = resource.get("Details", [])
        semantic.append(
            {
                "logical_resource_id": resource["LogicalResourceId"],
                "resource_type": resource["ResourceType"],
                "action": resource["Action"],
                "replacement": resource.get("Replacement"),
                "scope": resource.get("Scope", []) or [],
                "details_digest": pure.digest_value(details or []),
            }
        )
    semantic.sort(
        key=lambda item: (
            item["logical_resource_id"],
            item["resource_type"],
            item["action"],
        )
    )
    return _seal(
        {
            "schema_version": 1,
            "record_type": aws.CHANGE_SET_ATTESTATION_TYPE,
            "source_commit": COMMIT,
            "operation": operation,
            "intent_digest": intent_digest,
            "request_digest": request_digest,
            "dispatch_receipt_digest": dispatch["receipt_digest"],
            "verifier": {
                "account_id": (
                    pure.AUTHORITY_ACCOUNT_ID
                    if authority
                    else pure.MANAGEMENT_ACCOUNT_ID
                ),
                "caller_arn": AUTH_CALLER if authority else MGMT_CALLER,
                "profile": (
                    pure.AUTHORITY_PROFILE
                    if authority
                    else pure.MANAGEMENT_PROFILE
                ),
                "region": pure.REGION,
            },
            "stack_id": dispatch["stack_id"],
            "change_set_id": dispatch["change_set_id"],
            "template_digest": pure.bytes_digest(
                request["TemplateBody"].encode("utf-8")
            ),
            "parameters_digest": pure.digest_value(
                {
                    item["ParameterKey"]: item["ParameterValue"]
                    for item in request["Parameters"]
                }
            ),
            "changes": semantic,
            "attested_at": "2026-08-30T11:59:30Z",
            "aws_calls": 3,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": pure.PRODUCTION_STATUS,
        },
        "attestation_digest",
    )


class ExecuteCloudFormation:
    def __init__(
        self,
        *,
        request: Mapping[str, Any] | None = None,
        dispatch: Mapping[str, Any] | None = None,
        changes: list[dict[str, Any]] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.request = copy.deepcopy(dict(request)) if request is not None else None
        self.dispatch = dispatch
        self.changes = copy.deepcopy(changes) if changes is not None else None

    def execute_change_set(self, **request: Any) -> dict[str, Any]:
        self.calls.append(request)
        return {"ResponseMetadata": {"RequestId": REQUEST_ID}}

    def describe_change_set(self, **_request: Any) -> dict[str, Any]:
        assert self.request is not None
        assert self.dispatch is not None
        assert self.changes is not None
        return {
            "ChangeSetId": self.dispatch["change_set_id"],
            "StackId": self.dispatch["stack_id"],
            "ChangeSetName": self.request["ChangeSetName"],
            "StackName": self.request["StackName"],
            "ChangeSetType": self.request["ChangeSetType"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Description": self.request["Description"],
            "Capabilities": self.request["Capabilities"],
            "Tags": self.request["Tags"],
            "IncludeNestedStacks": self.request["IncludeNestedStacks"],
            "NotificationARNs": self.request["NotificationARNs"],
            "RollbackConfiguration": self.request["RollbackConfiguration"],
            "OnStackFailure": self.request.get("OnStackFailure"),
            "Parameters": copy.deepcopy(self.request["Parameters"]),
            "Changes": copy.deepcopy(self.changes),
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }

    def get_template(self, **_request: Any) -> dict[str, Any]:
        assert self.request is not None
        return {
            "TemplateBody": self.request["TemplateBody"],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class ExecuteRecoveryCloudTrail:
    def __init__(self, *, account: str, caller: str) -> None:
        self.account = account
        self.caller = caller
        self.request: dict[str, Any] | None = None
        self.create_delegate: RecoverCloudTrail | None = None
        self.duplicate = False
        self.calls = 0

    def lookup_events(self, **lookup: Any) -> dict[str, Any]:
        attributes = lookup.get("LookupAttributes", [])
        event_name = (
            attributes[0].get("AttributeValue")
            if isinstance(attributes, list)
            and attributes
            and isinstance(attributes[0], Mapping)
            else None
        )
        if event_name == "CreateChangeSet":
            assert self.create_delegate is not None
            return self.create_delegate.lookup_events(**lookup)
        self.calls += 1
        assert self.request is not None

        def event(event_id: str, request_id: str) -> dict[str, Any]:
            return {
                "eventSource": "cloudformation.amazonaws.com",
                "eventName": "ExecuteChangeSet",
                "awsRegion": pure.REGION,
                "recipientAccountId": self.account,
                "readOnly": False,
                "managementEvent": True,
                "errorCode": None,
                "errorMessage": None,
                "eventID": event_id,
                "requestID": request_id,
                "eventTime": "2026-08-30T12:00:00Z",
                "userIdentity": {"arn": self.caller},
                "requestParameters": aws._cloudtrail_execute_request(self.request),
                "responseElements": None,
            }

        events = [
            {
                "CloudTrailEvent": json.dumps(
                    event(
                        "99999999-9999-4999-8999-999999999999",
                        REQUEST_ID,
                    )
                )
            }
        ]
        if self.duplicate:
            events.append(
                {
                    "CloudTrailEvent": json.dumps(
                        event(
                            "88888888-8888-4888-8888-888888888888",
                            "77777777-7777-4777-8777-777777777777",
                        )
                    )
                }
            )
        return {
            "Events": events,
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class AttestCloudFormation:
    def __init__(
        self,
        *,
        request: Mapping[str, Any],
        dispatch: Mapping[str, Any],
        changes: list[dict[str, Any]],
        parameters: list[dict[str, Any]] | None = None,
    ) -> None:
        self.request = copy.deepcopy(dict(request))
        self.dispatch = dispatch
        self.changes = copy.deepcopy(changes)
        self.parameters = copy.deepcopy(
            list(parameters) if parameters is not None else request["Parameters"]
        )

    def describe_change_set(self, **_request: Any) -> dict[str, Any]:
        return {
            "ChangeSetId": self.dispatch["change_set_id"],
            "StackId": self.dispatch["stack_id"],
            "ChangeSetName": self.request["ChangeSetName"],
            "StackName": self.request["StackName"],
            "ChangeSetType": self.request["ChangeSetType"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Description": self.request["Description"],
            "Capabilities": self.request["Capabilities"],
            "Tags": self.request["Tags"],
            "IncludeNestedStacks": self.request["IncludeNestedStacks"],
            "NotificationARNs": self.request["NotificationARNs"],
            "RollbackConfiguration": self.request["RollbackConfiguration"],
            "OnStackFailure": self.request.get("OnStackFailure"),
            "Parameters": copy.deepcopy(self.parameters),
            "Changes": copy.deepcopy(self.changes),
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }

    def get_template(self, **_request: Any) -> dict[str, Any]:
        return {
            "TemplateBody": self.request["TemplateBody"],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class AccessReadbackCloudFormation:
    def __init__(
        self,
        *,
        bootstrap_intent: Mapping[str, Any],
        foundation_readback: Mapping[str, Any],
        parameters: list[dict[str, Any]],
    ) -> None:
        self.bootstrap_intent = bootstrap_intent
        self.foundation_readback = foundation_readback
        self.parameters = copy.deepcopy(parameters)

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        bucket = self.bootstrap_intent["names"]["artifact_bucket"]
        outputs = {
            "ArtifactBucketName": bucket,
            "ArtifactBucketArn": f"arn:aws:s3:::{bucket}",
            "ArtifactKmsKeyArn": self.foundation_readback[
                "artifact_kms_key_arn"
            ],
            "ArtifactKmsAlias": self.bootstrap_intent["names"][
                "artifact_kms_alias"
            ],
            "SigningProfileName": self.bootstrap_intent["names"][
                "signing_profile_name"
            ],
            "SigningProfileVersionArn": self.foundation_readback[
                "signing_profile_version_arn"
            ],
            "CodeSigningConfigArn": self.foundation_readback[
                "code_signing_config_arn"
            ],
            "CrossAccountAccessMode": "true",
            "ProductionAuthorized": "false",
        }
        return {
            "Stacks": [
                {
                    "StackStatus": "UPDATE_COMPLETE",
                    "Outputs": [
                        {"OutputKey": key, "OutputValue": value}
                        for key, value in outputs.items()
                    ],
                    "Parameters": copy.deepcopy(self.parameters),
                }
            ],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


def _modify_change(
    *, logical: str, resource_type: str, property_name: str,
    references: tuple[str, ...] = (), direct: bool = False,
    replacement: str | bool = "False",
) -> dict[str, Any]:
    details = (
        [
            {
                "ChangeSource": "DirectModification",
                "Evaluation": "Dynamic",
                "CausingEntity": None,
                "Target": {
                    "Attribute": "Properties",
                    "Name": property_name,
                    "RequiresRecreation": "Never",
                },
            }
        ]
        if direct
        else [
            {
                "ChangeSource": "ParameterReference",
                "Evaluation": "Static",
                "CausingEntity": reference,
                "Target": {
                    "Attribute": "Properties",
                    "Name": property_name,
                    "RequiresRecreation": "Never",
                },
            }
            for reference in references
        ]
    )
    return {
        "Type": "Resource",
        "ResourceChange": {
            "LogicalResourceId": logical,
            "ResourceType": resource_type,
            "Action": "Modify",
            "Replacement": replacement,
            "Scope": ["Properties"],
            "Details": details,
        },
    }


def _remove_change(*, logical: str, resource_type: str) -> dict[str, Any]:
    return {
        "Type": "Resource",
        "ResourceChange": {
            "LogicalResourceId": logical,
            "ResourceType": resource_type,
            "Action": "Remove",
        },
    }


def test_attestor_accepts_exact_bridge_revoke_modify_and_remove(
    tmp_path: Path,
) -> None:
    intent = _intent()
    operation = "bridge-revoke"
    request = intent["requests"][operation]
    dispatch = _execution_dispatch(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
    )
    changes = [
        _modify_change(
            logical="ArtifactBootstrapPermissionSet",
            resource_type="AWS::SSO::PermissionSet",
            property_name="InlinePolicy",
            references=("SigningProfileVersion",),
        ),
        _remove_change(
            logical="ArtifactBootstrapAssignment",
            resource_type="AWS::SSO::Assignment",
        ),
    ]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(),
            AttestCloudFormation(
                request=request, dispatch=dispatch, changes=changes
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    receipt = provider.attest_change_set(
        bootstrap_intent=intent,
        operation=operation,
        dispatch_receipt=dispatch,
        source_root=ROOT,
    )
    assert len(receipt["changes"]) == 2


def test_attestor_accepts_exact_parameter_reference_sets_for_access_update(
    tmp_path: Path,
) -> None:
    intent = _intent()
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(DELEGATION_TEMPLATE.name, "Delegation-Version-B")
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=_foundation_readback(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    dispatch = _execution_dispatch(
        operation="foundation-access-update",
        intent_digest=update["intent_digest"],
        request_digest=update["request_digest"],
    )
    changes = [
        _modify_change(
            logical="ArtifactKey",
            resource_type="AWS::KMS::Key",
            property_name="KeyPolicy",
            references=("CrossAccountAccessEnabled",),
        ),
        _modify_change(
            logical="ArtifactBucketPolicy",
            resource_type="AWS::S3::BucketPolicy",
            property_name="PolicyDocument",
            references=(
                "CrossAccountAccessEnabled",
                "RouteTemplateVersion",
                "DelegationTemplateVersion",
            ),
        ),
    ]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts([]),
            AttestCloudFormation(
                request=update["request"], dispatch=dispatch, changes=changes
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    receipt = provider.attest_change_set(
        bootstrap_intent=intent,
        operation="foundation-access-update",
        dispatch_receipt=dispatch,
        source_root=ROOT,
        access_update=update,
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        foundation_readback=_foundation_readback(),
    )
    assert len(receipt["changes"]) == 2


@pytest.mark.parametrize(
    ("parameter_key", "observed_value", "duplicate"),
    [
        ("BootstrapPrincipalId", "****", False),
        ("SigningProfileVersion", "*****", False),
        (
            "BootstrapPrincipalId",
            "87654321-4321-4123-8123-210987654321",
            False,
        ),
        ("BootstrapPrincipalId", None, True),
    ],
)
def test_attestor_rejects_masked_duplicate_or_wrong_bridge_parameters(
    tmp_path: Path,
    parameter_key: str,
    observed_value: str | None,
    duplicate: bool,
) -> None:
    intent = _intent()
    operation = "bridge-create"
    request = intent["requests"][operation]
    dispatch = _execution_dispatch(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
    )
    parameters = copy.deepcopy(request["Parameters"])
    matching = next(
        item for item in parameters if item["ParameterKey"] == parameter_key
    )
    if duplicate:
        parameters.append(copy.deepcopy(matching))
    else:
        matching["ParameterValue"] = observed_value

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(),
            AttestCloudFormation(
                request=request,
                dispatch=dispatch,
                changes=[],
                parameters=parameters,
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.attest_change_set(
            bootstrap_intent=intent,
            operation=operation,
            dispatch_receipt=dispatch,
            source_root=ROOT,
        )
    assert raised.value.code == "CHANGE_SET_PARAMETER_MISMATCH"


@pytest.mark.parametrize(
    ("parameter_key", "observed_value", "duplicate"),
    [
        ("RouteTemplateVersion", "****", False),
        ("DelegationTemplateVersion", "*****", False),
        ("RouteTemplateVersion", "Wrong-Version", False),
        ("DelegationTemplateVersion", None, True),
    ],
)
def test_attestor_rejects_masked_duplicate_or_wrong_access_update_parameters(
    tmp_path: Path,
    parameter_key: str,
    observed_value: str | None,
    duplicate: bool,
) -> None:
    intent = _intent()
    foundation_readback = _foundation_readback()
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(
        DELEGATION_TEMPLATE.name, "Delegation-Version-B"
    )
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=foundation_readback,
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    dispatch = _execution_dispatch(
        operation="foundation-access-update",
        intent_digest=update["intent_digest"],
        request_digest=update["request_digest"],
    )
    parameters = copy.deepcopy(update["request"]["Parameters"])
    matching = next(
        item for item in parameters if item["ParameterKey"] == parameter_key
    )
    if duplicate:
        parameters.append(copy.deepcopy(matching))
    else:
        matching["ParameterValue"] = observed_value

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts([]),
            AttestCloudFormation(
                request=update["request"],
                dispatch=dispatch,
                changes=[],
                parameters=parameters,
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.attest_change_set(
            bootstrap_intent=intent,
            operation="foundation-access-update",
            dispatch_receipt=dispatch,
            source_root=ROOT,
            access_update=update,
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            foundation_readback=foundation_readback,
        )
    assert raised.value.code == "CHANGE_SET_PARAMETER_MISMATCH"


@pytest.mark.parametrize(
    ("parameter_key", "observed_value", "duplicate"),
    [
        ("RouteTemplateVersion", "****", False),
        ("DelegationTemplateVersion", "*****", False),
        ("RouteTemplateVersion", "Wrong-Version", False),
        ("DelegationTemplateVersion", None, True),
    ],
)
def test_access_readback_rejects_masked_duplicate_or_wrong_stack_parameters(
    tmp_path: Path,
    parameter_key: str,
    observed_value: str | None,
    duplicate: bool,
) -> None:
    intent = _intent()
    foundation_readback = _foundation_readback()
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(
        DELEGATION_TEMPLATE.name, "Delegation-Version-B"
    )
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=foundation_readback,
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    parameters = copy.deepcopy(update["request"]["Parameters"])
    matching = next(
        item for item in parameters if item["ParameterKey"] == parameter_key
    )
    if duplicate:
        parameters.append(copy.deepcopy(matching))
    else:
        matching["ParameterValue"] = observed_value

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            sts=Sts([]),
            cloudformation=AccessReadbackCloudFormation(
                bootstrap_intent=intent,
                foundation_readback=foundation_readback,
                parameters=parameters,
            ),
            kms=object(),
            s3=object(),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.readback_foundation_access_update(
            bootstrap_intent=intent,
            foundation_readback=foundation_readback,
            access_update=update,
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            source_root=ROOT,
        )
    assert raised.value.code == "FOUNDATION_ACCESS_PARAMETER_MISMATCH"


@pytest.mark.parametrize("drift", ["extra-reference", "replacement"])
def test_attestor_rejects_access_update_semantic_drift(
    tmp_path: Path, drift: str
) -> None:
    intent = _intent()
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(DELEGATION_TEMPLATE.name, "Delegation-Version-B")
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=_foundation_readback(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    dispatch = _execution_dispatch(
        operation="foundation-access-update",
        intent_digest=update["intent_digest"],
        request_digest=update["request_digest"],
    )
    references = [
        "CrossAccountAccessEnabled",
        "RouteTemplateVersion",
        "DelegationTemplateVersion",
    ]
    if drift == "extra-reference":
        references.append("UnreviewedParameter")
    changes = [
        _modify_change(
            logical="ArtifactKey",
            resource_type="AWS::KMS::Key",
            property_name="KeyPolicy",
            references=("CrossAccountAccessEnabled",),
        ),
        _modify_change(
            logical="ArtifactBucketPolicy",
            resource_type="AWS::S3::BucketPolicy",
            property_name="PolicyDocument",
            references=tuple(references),
            replacement="True" if drift == "replacement" else "False",
        ),
    ]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts([]),
            AttestCloudFormation(
                request=update["request"], dispatch=dispatch, changes=changes
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.attest_change_set(
            bootstrap_intent=intent,
            operation="foundation-access-update",
            dispatch_receipt=dispatch,
            source_root=ROOT,
            access_update=update,
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            foundation_readback=_foundation_readback(),
        )
    assert raised.value.code in {
        "CHANGE_SET_REPLACEMENT_FORBIDDEN",
        "CHANGE_SET_SEMANTIC_DRIFT",
    }


def test_attestor_accepts_bounded_dynamic_direct_modification(
    tmp_path: Path,
) -> None:
    pin = _bridge_pin()
    dispatch = _execution_dispatch(
        operation="bridge-pin",
        intent_digest=pin["intent_digest"],
        request_digest=pin["request_digest"],
    )
    changes = [
        _modify_change(
            logical="ArtifactBootstrapPermissionSet",
            resource_type="AWS::SSO::PermissionSet",
            property_name="InlinePolicy",
            direct=True,
        )
    ]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(),
            AttestCloudFormation(
                request=pin["request"], dispatch=dispatch, changes=changes
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    receipt = provider.attest_change_set(
        bootstrap_intent=_intent(),
        operation="bridge-pin",
        dispatch_receipt=dispatch,
        source_root=ROOT,
        bridge_pin=pin,
        foundation_readback=_foundation_readback(),
    )
    assert len(receipt["changes"]) == 1


MGMT_CALLER = (
    "arn:aws:sts::839393571433:assumed-role/"
    "AWSReservedSSO_AWSAdministratorAccess_0123456789ABCDEF/operator"
)


class RecoverCloudTrail:
    def __init__(
        self,
        *,
        request: Mapping[str, Any],
        stack_id: str,
        change_set_id: str,
        account: str = pure.MANAGEMENT_ACCOUNT_ID,
        caller: str = MGMT_CALLER,
        request_id: str = "44444444-4444-4444-8444-444444444444",
        event_time: str = "2026-08-30T11:58:01Z",
    ) -> None:
        event = {
            "eventSource": "cloudformation.amazonaws.com",
            "eventName": "CreateChangeSet",
            "awsRegion": pure.REGION,
            "recipientAccountId": account,
            "readOnly": False,
            "managementEvent": True,
            "errorCode": None,
            "errorMessage": None,
            "eventID": "33333333-3333-4333-8333-333333333333",
            "requestID": request_id,
            "eventTime": event_time,
            "userIdentity": {"arn": caller},
            "requestParameters": aws._cloudtrail_cfn_request(request),
            "responseElements": {"id": change_set_id, "stackId": stack_id},
        }
        self.response = {
            "Events": [{"CloudTrailEvent": json.dumps(event)}],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }
        self.calls = 0

    def lookup_events(self, **_request: Any) -> dict[str, Any]:
        self.calls += 1
        return copy.deepcopy(self.response)


def _prime_execution_evidence(
    *,
    store: aws.OExclClaimStore,
    bootstrap: Mapping[str, Any],
    operation: str,
    intent_digest: str,
    request_digest: str,
    request: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    ExecuteCloudFormation,
    RecoverCloudTrail,
]:
    mutation = operation in {"bridge-pin", "foundation-access-update"}
    if mutation:
        dispatch_authorization = _fresh_mutation_auth(
            f"{operation}:dispatch", intent_digest, seconds_before=120
        )
    else:
        dispatch_authorization = pure.materialize_authorization(
            intent=bootstrap,
            operation=f"{operation}:dispatch",
            authorization=f"AUTHORIZE GUG-376 {operation}:dispatch {COMMIT}",
            authorized_at=NOW - timedelta(minutes=2),
            expires_at=NOW + timedelta(minutes=5),
        )
    authority = operation in {"foundation-create", "foundation-access-update"}
    caller = AUTH_CALLER if authority else MGMT_CALLER
    account = (
        pure.AUTHORITY_ACCOUNT_ID if authority else pure.MANAGEMENT_ACCOUNT_ID
    )
    claimed_at = "2026-08-30T11:59:00Z"
    dispatch = _execution_dispatch(
        operation=operation,
        intent_digest=intent_digest,
        request_digest=request_digest,
        authorization_digest=dispatch_authorization["authorization_digest"],
        dispatched_at=claimed_at,
    )
    store.reserve(
        operation=f"{operation}-dispatch",
        digest=request_digest,
        claimed_at=claimed_at,
        caller_arn=caller,
        request_digest=request_digest,
        authorization_digest=dispatch_authorization["authorization_digest"],
        authorization_record=dispatch_authorization,
        request_token=request["ClientToken"],
        collision_admission=_admission_binding(
            f"{operation}:dispatch", request
        ),
    )
    changes = _expected_execution_changes(operation)
    attestation = _execution_attestation(
        operation=operation,
        intent_digest=intent_digest,
        request_digest=request_digest,
        dispatch=dispatch,
        request=request,
        changes=changes,
    )
    cloudformation = ExecuteCloudFormation(
        request=request,
        dispatch=dispatch,
        changes=changes,
    )
    cloudtrail = RecoverCloudTrail(
        request=request,
        stack_id=dispatch["stack_id"],
        change_set_id=dispatch["change_set_id"],
        account=account,
        caller=caller,
        request_id=dispatch["request_id"],
        event_time=claimed_at,
    )
    return dispatch, attestation, cloudformation, cloudtrail


def _prepared_execute_case(tmp_path: Path, mode: str) -> dict[str, Any]:
    bootstrap = _intent()
    store = _claim_store(tmp_path)
    if mode == "generic":
        operation = "bridge-create"
        intent_digest = bootstrap["intent_digest"]
        request_digest = bootstrap["request_digests"][operation]
        request = bootstrap["requests"][operation]
        profile = pure.MANAGEMENT_PROFILE
        sts = MgmtSts()
    elif mode == "bridge-pin":
        operation = "bridge-pin"
        pin = _bridge_pin()
        intent_digest = pin["intent_digest"]
        request_digest = pin["request_digest"]
        request = pin["request"]
        profile = pure.MANAGEMENT_PROFILE
        sts = MgmtSts()
    else:
        operation = "foundation-access-update"
        route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
        delegation = _object_receipt(
            DELEGATION_TEMPLATE.name, "Delegation-Version-B"
        )
        update = pure.materialize_foundation_access_update(
            bootstrap_intent=bootstrap,
            foundation_readback=_foundation_readback(),
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            reviewed_sources=_reviewed_sources(),
            foundation_template=FOUNDATION.read_bytes(),
        )
        intent_digest = update["intent_digest"]
        request_digest = update["request_digest"]
        request = update["request"]
        profile = pure.AUTHORITY_PROFILE
        sts = Sts([])
    dispatch, attestation, cloudformation, cloudtrail = _prime_execution_evidence(
        store=store,
        bootstrap=bootstrap,
        operation=operation,
        intent_digest=intent_digest,
        request_digest=request_digest,
        request=request,
    )
    provider = _ContractHarnessProvider(
        clients=aws.Clients(sts, cloudformation, cloudtrail=cloudtrail),
        claims=store,
        profile=profile,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    if mode == "generic":
        authorization = pure.materialize_authorization(
            intent=bootstrap,
            operation=f"{operation}:execute",
            authorization=f"AUTHORIZE GUG-376 {operation}:execute {COMMIT}",
            authorized_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )
        method = provider.execute_change_set_once
        kwargs = {
            "bootstrap_intent": bootstrap,
            "source_root": ROOT,
            "operation": operation,
        }
    elif mode == "bridge-pin":
        authorization = _mutation_auth(
            "bridge-pin:execute", intent_digest
        )
        method = provider.execute_bridge_pin_once
        kwargs = {
            "bootstrap_intent": bootstrap,
            "source_root": ROOT,
            "foundation_readback": _foundation_readback(),
            "bridge_pin": pin,
        }
    else:
        authorization = _mutation_auth(
            "foundation-access-update:execute", intent_digest
        )
        method = provider.execute_foundation_access_update_once
        kwargs = {
            "bootstrap_intent": bootstrap,
            "foundation_readback": _foundation_readback(),
            "access_update": update,
            "route_template_receipt": route,
            "delegation_template_receipt": delegation,
            "source_root": ROOT,
        }
    return {
        "bootstrap": bootstrap,
        "store": store,
        "operation": operation,
        "intent_digest": intent_digest,
        "request_digest": request_digest,
        "provider": provider,
        "profile": profile,
        "method": method,
        "kwargs": kwargs,
        "authorization": authorization,
        "dispatch": dispatch,
        "attestation": attestation,
        "cloudformation": cloudformation,
        "cloudtrail": cloudtrail,
    }


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
@pytest.mark.parametrize(
    "attested_at",
    [
        "2026-08-30T12:01:00Z",
        "2026-08-30T11:58:59Z",
    ],
    ids=["future-within-recovery-window", "before-causal-dispatch"],
)
def test_execute_rejects_attestation_outside_causal_chronology_without_mutation(
    tmp_path: Path,
    mode: str,
    attested_at: str,
) -> None:
    case = _prepared_execute_case(tmp_path, mode)
    attestation = copy.deepcopy(case["attestation"])
    attestation["attested_at"] = attested_at
    attestation = _seal(
        {
            key: value
            for key, value in attestation.items()
            if key != "attestation_digest"
        },
        "attestation_digest",
    )

    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        case["method"](
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=attestation,
            authorization=case["authorization"],
        )

    assert raised.value.code == "CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID"
    assert case["cloudformation"].calls == []


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
def test_execute_recovery_rejects_attestation_after_original_execute_claim(
    tmp_path: Path,
    mode: str,
) -> None:
    case = _prepared_execute_case(tmp_path, mode)
    execution_digest = aws.ConnectedArtifactBootstrapProvider._execution_effect_digest(
        operation=case["operation"],
        intent_digest=case["intent_digest"],
        request_digest=case["request_digest"],
        dispatch=case["dispatch"],
    )
    execute_request = {
        "ChangeSetName": case["dispatch"]["change_set_id"],
        "StackName": case["dispatch"]["stack_id"],
        "ClientRequestToken": "gug376-" + execution_digest[7:55],
    }
    case["store"].reserve(
        operation=f"{case['operation']}-execute",
        digest=execution_digest,
        claimed_at="2026-08-30T11:59:15Z",
        caller_arn=case["dispatch"]["verifier"]["caller_arn"],
        request_digest=pure.digest_value(execute_request),
        authorization_digest=case["authorization"]["authorization_digest"],
        authorization_record=case["authorization"],
        request_token=execute_request["ClientRequestToken"],
        preflight_digest=aws.ConnectedArtifactBootstrapProvider._execution_preflight_digest(
            dispatch=case["dispatch"],
            attestation=case["attestation"],
        ),
        preflight_calls=5,
        collision_admission=_admission_binding(
            f"{case['operation']}:execute", execute_request
        ),
    )
    recovery_name = {
        "generic": "recover_change_set_execution",
        "bridge-pin": "recover_bridge_pin_execution",
        "access-update": "recover_foundation_access_update_execution",
    }[mode]

    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        getattr(case["provider"], recovery_name)(
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=case["attestation"],
        )

    assert raised.value.code == "CHANGE_SET_ATTESTATION_CHRONOLOGY_INVALID"
    assert case["cloudformation"].calls == []


class ProgressiveExpiryClock:
    def __init__(self, *, expire_on_call: int) -> None:
        self.expire_on_call = expire_on_call
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return (
            NOW
            if self.calls < self.expire_on_call
            else NOW + timedelta(minutes=6)
        )


class NoCreateCloudFormation:
    def __init__(self) -> None:
        self.create_calls: list[dict[str, Any]] = []

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.create_calls.append(request)
        raise AssertionError("expired authorization must prevent CreateChangeSet")


class NoStartSigner:
    def __init__(self, *, intent: Mapping[str, Any]) -> None:
        self.intent = intent
        self.start_calls = 0

    def get_signing_profile(self, **_request: Any) -> dict[str, Any]:
        return {
            "status": "Active",
            "revocationRecord": None,
            "profileVersionArn": self.intent["signing_profile_version_arn"],
        }

    def start_signing_job(self, **_request: Any) -> dict[str, Any]:
        self.start_calls += 1
        raise AssertionError(
            "expired authorization must prevent StartSigningJob"
        )


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
def test_dispatch_revalidates_authorization_at_claim_time_before_create(
    tmp_path: Path,
    mode: str,
) -> None:
    bootstrap = _intent()
    store = _claim_store(tmp_path)
    cloudformation = NoCreateCloudFormation()
    if mode == "generic":
        operation = "bridge-create"
        profile = pure.MANAGEMENT_PROFILE
        sts = MgmtSts()
        authorization = pure.materialize_authorization(
            intent=bootstrap,
            operation=f"{operation}:dispatch",
            authorization=f"AUTHORIZE GUG-376 {operation}:dispatch {COMMIT}",
            authorized_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )
        method = "dispatch_change_set_once"
        kwargs = {
            "bootstrap_intent": bootstrap,
            "source_root": ROOT,
            "operation": operation,
            "authorization": authorization,
        }
    elif mode == "bridge-pin":
        pin = _bridge_pin()
        operation = "bridge-pin"
        profile = pure.MANAGEMENT_PROFILE
        sts = MgmtSts()
        authorization = _mutation_auth(
            "bridge-pin:dispatch", pin["intent_digest"]
        )
        method = "dispatch_bridge_pin_once"
        kwargs = {
            "bootstrap_intent": bootstrap,
            "source_root": ROOT,
            "foundation_readback": _foundation_readback(),
            "bridge_pin": pin,
            "authorization": authorization,
        }
    else:
        route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
        delegation = _object_receipt(
            DELEGATION_TEMPLATE.name, "Delegation-Version-B"
        )
        update = pure.materialize_foundation_access_update(
            bootstrap_intent=bootstrap,
            foundation_readback=_foundation_readback(),
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            reviewed_sources=_reviewed_sources(),
            foundation_template=FOUNDATION.read_bytes(),
        )
        operation = "foundation-access-update"
        profile = pure.AUTHORITY_PROFILE
        sts = Sts([])
        authorization = _mutation_auth(
            "foundation-access-update:dispatch", update["intent_digest"]
        )
        method = "dispatch_foundation_access_update_once"
        kwargs = {
            "bootstrap_intent": bootstrap,
            "foundation_readback": _foundation_readback(),
            "access_update": update,
            "route_template_receipt": route,
            "delegation_template_receipt": delegation,
            "source_root": ROOT,
            "authorization": authorization,
        }
    provider = _ContractHarnessProvider(
        clients=aws.Clients(sts, cloudformation),
        claims=store,
        profile=profile,
        clock=ProgressiveExpiryClock(expire_on_call=3),
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(pure.ArtifactBootstrapError):
        getattr(provider, method)(**kwargs)

    assert cloudformation.create_calls == []
    assert not list(tmp_path.glob(f"*{operation}-dispatch*.claim.json"))


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
def test_execute_revalidates_authorization_at_claim_time_before_mutation(
    tmp_path: Path,
    mode: str,
) -> None:
    case = _prepared_execute_case(tmp_path, mode)
    case["provider"]._clock = ProgressiveExpiryClock(expire_on_call=5)

    with pytest.raises(pure.ArtifactBootstrapError):
        case["method"](
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=case["attestation"],
            authorization=case["authorization"],
        )

    assert case["cloudformation"].calls == []
    assert not list(
        tmp_path.glob(f"*{case['operation']}-execute*.claim.json")
    )


def test_publish_revalidates_authorization_at_claim_time_before_put(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    intent = _object_intent("template.yaml")
    s3 = S3Put(events, intent)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=s3),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=ProgressiveExpiryClock(expire_on_call=3),
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(pure.ArtifactBootstrapError):
        provider.publish_object_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
            body=b"template",
            authorization=_mutation_auth(
                "publish-object", intent["intent_digest"]
            ),
        )

    assert events == ["sts", "list"]
    assert s3.calls == 0
    assert not list(tmp_path.glob("*publish-object*.claim.json"))


def test_signing_revalidates_authorization_at_claim_time_before_start(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    unsigned, intent = _signing_intent()
    signer = NoStartSigner(intent=intent)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(events), CloudFormationUnused(), signer=signer
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=ProgressiveExpiryClock(expire_on_call=3),
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    with pytest.raises(pure.ArtifactBootstrapError):
        provider.start_signing_job_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            bridge_pin=_bridge_pin(),
            bridge_pin_readback=_bridge_pin_readback(),
            unsigned_receipt=unsigned,
            signing_intent=intent,
            authorization=_mutation_auth(
                "start-signing-job", intent["intent_digest"]
            ),
        )

    assert events == ["sts"]
    assert signer.start_calls == 0
    assert not list(tmp_path.glob("*start-signing-job*.claim.json"))


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
@pytest.mark.parametrize(
    "tamper",
    [
        "dispatch-source",
        "dispatch-profile",
        "dispatch-account",
        "dispatch-region",
        "dispatch-caller",
        "dispatch-arn-account",
        "dispatch-arn-region",
        "dispatch-arn-name",
        "dispatch-request-id",
        "dispatch-authorization",
        "attestation-source",
        "attestation-profile",
        "attestation-template",
        "attestation-parameters",
        "attestation-changes",
        "attestation-replacement",
    ],
)
def test_execute_rejects_resealed_noncausal_evidence_without_mutation(
    tmp_path: Path, mode: str, tamper: str
) -> None:
    case = _prepared_execute_case(tmp_path, mode)
    dispatch = copy.deepcopy(case["dispatch"])
    attestation = copy.deepcopy(case["attestation"])
    if tamper.startswith("dispatch-"):
        if tamper == "dispatch-source":
            dispatch["source_commit"] = "0" * 40
        elif tamper == "dispatch-profile":
            dispatch["verifier"]["profile"] = "unexpected"
        elif tamper == "dispatch-account":
            dispatch["verifier"]["account_id"] = "000000000000"
        elif tamper == "dispatch-region":
            dispatch["verifier"]["region"] = "us-west-2"
        elif tamper == "dispatch-caller":
            dispatch["verifier"]["caller_arn"] = (
                AUTH_CALLER
                if mode != "access-update"
                else MGMT_CALLER
            )
        elif tamper == "dispatch-arn-account":
            dispatch["stack_id"] = dispatch["stack_id"].replace(
                dispatch["verifier"]["account_id"], "000000000000"
            )
        elif tamper == "dispatch-arn-region":
            dispatch["change_set_id"] = dispatch["change_set_id"].replace(
                ":us-east-1:", ":us-west-2:"
            )
        elif tamper == "dispatch-arn-name":
            dispatch["change_set_id"] = dispatch["change_set_id"].replace(
                ":changeSet/", ":changeSet/unreviewed-"
            )
        elif tamper == "dispatch-request-id":
            dispatch["request_id"] = "not-a-request-id"
        else:
            dispatch["authorization_digest"] = "sha256:" + "f" * 64
        dispatch.pop("receipt_digest")
        dispatch["receipt_digest"] = pure.digest_value(dispatch)
        attestation["dispatch_receipt_digest"] = dispatch["receipt_digest"]
        attestation["stack_id"] = dispatch["stack_id"]
        attestation["change_set_id"] = dispatch["change_set_id"]
    elif tamper == "attestation-source":
        attestation["source_commit"] = "0" * 40
    elif tamper == "attestation-profile":
        attestation["verifier"]["profile"] = "unexpected"
    elif tamper == "attestation-template":
        attestation["template_digest"] = "sha256:" + "a" * 64
    elif tamper == "attestation-parameters":
        attestation["parameters_digest"] = "sha256:" + "b" * 64
    elif tamper == "attestation-changes":
        attestation["changes"] = []
    else:
        attestation["changes"][0]["replacement"] = "True"
    attestation.pop("attestation_digest")
    attestation["attestation_digest"] = pure.digest_value(attestation)
    with pytest.raises(aws.ConnectedArtifactBootstrapError):
        case["method"](
            **case["kwargs"],
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=case["authorization"],
        )
    assert case["cloudformation"].calls == []


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
@pytest.mark.parametrize(
    "drift", ["ids", "role-arn", "parameters", "template", "changes"]
)
def test_execute_rechecks_live_change_set_before_mutation(
    tmp_path: Path, mode: str, drift: str
) -> None:
    case = _prepared_execute_case(tmp_path, mode)
    cloudformation = case["cloudformation"]
    if drift == "ids":
        cloudformation.dispatch = copy.deepcopy(cloudformation.dispatch)
        cloudformation.dispatch["stack_id"] = cloudformation.dispatch[
            "stack_id"
        ].replace(
            "11111111-1111-4111-8111-111111111111",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
    elif drift == "role-arn":
        original = cloudformation.describe_change_set

        def with_role(**request: Any) -> dict[str, Any]:
            response = original(**request)
            response["RoleARN"] = (
                "arn:aws:iam::839393571433:role/UnreviewedRole"
            )
            return response

        cloudformation.describe_change_set = with_role
    elif drift == "parameters":
        cloudformation.request["Parameters"][0]["ParameterValue"] = "drift"
    elif drift == "template":
        cloudformation.request["TemplateBody"] += "\n# drift\n"
    else:
        cloudformation.changes = []
    with pytest.raises(aws.ConnectedArtifactBootstrapError):
        case["method"](
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=case["attestation"],
            authorization=case["authorization"],
        )
    assert cloudformation.calls == []


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
def test_execute_requires_original_dispatch_claim_before_sts_or_mutation(
    tmp_path: Path, mode: str
) -> None:
    primed = tmp_path / "primed"
    empty = tmp_path / "empty"
    primed.mkdir(mode=0o700)
    empty.mkdir(mode=0o700)
    case = _prepared_execute_case(primed, mode)
    sts_calls: list[str] = []

    class NoCallSts:
        def get_caller_identity(self) -> dict[str, Any]:
            sts_calls.append("sts")
            raise AssertionError("STS must not be called without the claim")

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            NoCallSts(),
            case["cloudformation"],
            cloudtrail=case["cloudtrail"],
        ),
        claims=_claim_store(empty),
        profile=case["profile"],
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    method_name = case["method"].__name__
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        getattr(provider, method_name)(
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=case["attestation"],
            authorization=case["authorization"],
        )
    assert raised.value.code == "CAUSAL_CLAIM_REQUIRED"
    assert sts_calls == []
    assert case["cloudformation"].calls == []


def test_direct_dispatch_claim_time_may_precede_causal_event_time(
    tmp_path: Path,
) -> None:
    case = _prepared_execute_case(tmp_path, "generic")
    event = json.loads(
        case["cloudtrail"].response["Events"][0]["CloudTrailEvent"]
    )
    event["eventTime"] = "2026-08-30T11:59:01Z"
    case["cloudtrail"].response["Events"][0]["CloudTrailEvent"] = json.dumps(
        event
    )
    receipt = case["method"](
        **case["kwargs"],
        dispatch_receipt=case["dispatch"],
        change_set_attestation=case["attestation"],
        authorization=case["authorization"],
    )
    assert receipt["record_type"] == aws.EXECUTION_RECEIPT_TYPE
    assert len(case["cloudformation"].calls) == 1


def test_execute_rejects_create_event_that_predates_dispatch_claim(
    tmp_path: Path,
) -> None:
    case = _prepared_execute_case(tmp_path, "generic")
    event = json.loads(
        case["cloudtrail"].response["Events"][0]["CloudTrailEvent"]
    )
    event["eventTime"] = "2026-08-30T11:58:59Z"
    case["cloudtrail"].response["Events"][0]["CloudTrailEvent"] = json.dumps(
        event
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        case["method"](
            **case["kwargs"],
            dispatch_receipt=case["dispatch"],
            change_set_attestation=case["attestation"],
            authorization=case["authorization"],
        )
    assert raised.value.code == "CLOUDFORMATION_RECOVERY_EVENT_AMBIGUOUS"
    assert case["cloudformation"].calls == []


class RecoverCloudFormation(ExecuteCloudFormation):
    def __init__(
        self,
        *,
        request: Mapping[str, Any],
        stack_id: str,
        change_set_id: str,
    ) -> None:
        super().__init__()
        self.request = request
        self.stack_id = stack_id
        self.change_set_id = change_set_id

    def describe_change_set(self, **_request: Any) -> dict[str, Any]:
        return {
            "StackName": self.request["StackName"],
            "ChangeSetName": self.request["ChangeSetName"],
            "StackId": self.stack_id,
            "ChangeSetId": self.change_set_id,
            "ChangeSetType": self.request["ChangeSetType"],
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE",
            "Description": self.request["Description"],
            "Capabilities": self.request["Capabilities"],
            "Tags": self.request["Tags"],
            "IncludeNestedStacks": self.request["IncludeNestedStacks"],
            "NotificationARNs": self.request["NotificationARNs"],
            "RollbackConfiguration": self.request["RollbackConfiguration"],
            "OnStackFailure": self.request["OnStackFailure"],
            "Parameters": copy.deepcopy(self.request["Parameters"]),
            "Changes": _expected_execution_changes("bridge-create"),
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }

    def get_template(self, **_request: Any) -> dict[str, Any]:
        return {
            "TemplateBody": self.request["TemplateBody"],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


def test_recovery_requires_causal_claim_and_execute_effect_is_replay_stable(
    tmp_path: Path,
) -> None:
    intent = _intent()
    operation = "bridge-create"
    request = intent["requests"][operation]
    request_digest = intent["request_digests"][operation]
    stack_id = (
        "arn:aws:cloudformation:us-east-1:839393571433:stack/"
        f"{pure.BRIDGE_STACK_NAME}/11111111-1111-4111-8111-111111111111"
    )
    change_set_id = (
        "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
        f"{pure.BRIDGE_CHANGE_SET_NAME}/"
        "22222222-2222-4222-8222-222222222222"
    )
    first_dispatch_auth = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:dispatch",
        authorization=f"AUTHORIZE GUG-376 bridge-create:dispatch {COMMIT}",
        authorized_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=5),
    )
    store = _claim_store(tmp_path)
    store.reserve(
        operation="bridge-create-dispatch",
        digest=request_digest,
        claimed_at="2026-08-30T11:58:00Z",
        caller_arn=MGMT_CALLER,
        request_digest=request_digest,
        authorization_digest=first_dispatch_auth["authorization_digest"],
        authorization_record=first_dispatch_auth,
        request_token=request["ClientToken"],
        collision_admission=_admission_binding(
            "bridge-create:dispatch", request
        ),
    )
    cloudformation = RecoverCloudFormation(
        request=request,
        stack_id=stack_id,
        change_set_id=change_set_id,
    )
    cloudtrail = RecoverCloudTrail(
        request=request,
        stack_id=stack_id,
        change_set_id=change_set_id,
    )
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), cloudformation, cloudtrail=cloudtrail),
        claims=store,
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    recover_auth_two = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:dispatch",
        authorization=f"AUTHORIZE GUG-376 bridge-create:dispatch {COMMIT}",
        authorized_at=NOW - timedelta(minutes=3),
        expires_at=NOW + timedelta(minutes=5),
    )
    provider._clock = lambda: NOW - timedelta(seconds=15)
    recovered_one = provider.recover_change_set(
        bootstrap_intent=intent,
        source_root=ROOT,
        operation=operation,
    )
    recovered_two = provider.recover_change_set(
        bootstrap_intent=intent,
        source_root=ROOT,
        operation=operation,
    )
    assert recovered_one["dispatch_receipt"] == recovered_two["dispatch_receipt"]
    assert recovered_one["dispatch_receipt"]["request_id"] == (
        "44444444-4444-4444-8444-444444444444"
    )
    assert recovered_one["dispatch_receipt"]["authorization_digest"] == (
        first_dispatch_auth["authorization_digest"]
    )
    assert recovered_one["aws_mutations"] == 0
    provider._clock = lambda: NOW

    execute_one = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:execute",
        authorization=f"AUTHORIZE GUG-376 bridge-create:execute {COMMIT}",
        authorized_at=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=5),
    )
    execute_two = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:execute",
        authorization=f"AUTHORIZE GUG-376 bridge-create:execute {COMMIT}",
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    provider.execute_change_set_once(
        bootstrap_intent=intent,
        source_root=ROOT,
        operation=operation,
        dispatch_receipt=recovered_one["dispatch_receipt"],
        change_set_attestation=recovered_one["change_set_attestation"],
        authorization=execute_one,
    )
    alternate_dispatch = copy.deepcopy(recovered_two["dispatch_receipt"])
    alternate_dispatch["authorization_digest"] = recover_auth_two[
        "authorization_digest"
    ]
    alternate_dispatch["dispatched_at"] = "2026-08-30T11:59:00Z"
    alternate_dispatch.pop("receipt_digest")
    alternate_dispatch["receipt_digest"] = pure.digest_value(alternate_dispatch)
    alternate_attestation = copy.deepcopy(
        recovered_two["change_set_attestation"]
    )
    alternate_attestation["dispatch_receipt_digest"] = alternate_dispatch[
        "receipt_digest"
    ]
    alternate_attestation["attested_at"] = "2026-08-30T12:00:00Z"
    alternate_attestation.pop("attestation_digest")
    alternate_attestation["attestation_digest"] = pure.digest_value(
        alternate_attestation
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.execute_change_set_once(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=alternate_dispatch,
            change_set_attestation=alternate_attestation,
            authorization=execute_two,
        )
    assert raised.value.code == "DISPATCH_CAUSAL_CLAIM_MISMATCH"
    assert len(cloudformation.calls) == 1


def test_recovery_rejects_without_original_causal_claim(tmp_path: Path) -> None:
    intent = _intent()
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), CloudFormationUnused()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.recover_change_set(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation="bridge-create",
        )
    assert raised.value.code == "CAUSAL_CLAIM_REQUIRED"


def test_execute_change_set_claim_is_stable_across_fresh_authorization(
    tmp_path: Path,
) -> None:
    intent = _intent()
    operation = "bridge-create"
    store = _claim_store(tmp_path)
    request = intent["requests"][operation]
    dispatch, attestation, cloudformation, cloudtrail = _prime_execution_evidence(
        store=store,
        bootstrap=intent,
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
        request=request,
    )
    first = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:execute",
        authorization=f"AUTHORIZE GUG-376 bridge-create:execute {COMMIT}",
        authorized_at=NOW - timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=5),
    )
    second = pure.materialize_authorization(
        intent=intent,
        operation="bridge-create:execute",
        authorization=f"AUTHORIZE GUG-376 bridge-create:execute {COMMIT}",
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    assert first["authorization_digest"] != second["authorization_digest"]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(), cloudformation, cloudtrail=cloudtrail
        ),
        claims=store,
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    provider.execute_change_set_once(
        bootstrap_intent=intent,
        source_root=ROOT,
        operation=operation,
        dispatch_receipt=dispatch,
        change_set_attestation=attestation,
        authorization=first,
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.execute_change_set_once(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=second,
        )
    assert raised.value.code == "MUTATION_ALREADY_CLAIMED"
    assert len(cloudformation.calls) == 1


@pytest.mark.parametrize(
    ("timestamp_field", "timestamp", "expected_code"),
    [
        ("dispatched_at", "2026-08-30T13:00:00Z", "DISPATCH_RECEIPT_INVALID"),
        (
            "attested_at",
            "2026-08-31T13:00:00Z",
            "CHANGE_SET_ATTESTATION_INVALID",
        ),
    ],
)
def test_resealed_cfn_evidence_cannot_cross_write_or_recovery_boundary_before_sts(
    tmp_path: Path,
    timestamp_field: str,
    timestamp: str,
    expected_code: str,
) -> None:
    intent = _intent()
    operation = "bridge-create"
    dispatch = _execution_dispatch(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
    )
    attestation = _execution_attestation(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
        dispatch=dispatch,
    )
    if timestamp_field == "dispatched_at":
        dispatch[timestamp_field] = timestamp
        dispatch = _seal(
            {
                key: value
                for key, value in dispatch.items()
                if key != "receipt_digest"
            },
            "receipt_digest",
        )
        attestation["dispatch_receipt_digest"] = dispatch["receipt_digest"]
        attestation = _seal(
            {
                key: value
                for key, value in attestation.items()
                if key != "attestation_digest"
            },
            "attestation_digest",
        )
    else:
        attestation[timestamp_field] = timestamp
        attestation = _seal(
            {
                key: value
                for key, value in attestation.items()
                if key != "attestation_digest"
            },
            "attestation_digest",
        )

    sts_calls: list[str] = []

    class RecordingManagementSts:
        def get_caller_identity(self) -> dict[str, Any]:
            sts_calls.append("sts")
            return {
                "Account": pure.MANAGEMENT_ACCOUNT_ID,
                "Arn": MGMT_CALLER,
                "ResponseMetadata": {"RequestId": REQUEST_ID},
            }

    provider = _ContractHarnessProvider(
        clients=aws.Clients(RecordingManagementSts(), ExecuteCloudFormation()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    authorization = pure.materialize_authorization(
        intent=intent,
        operation=f"{operation}:execute",
        authorization=f"AUTHORIZE GUG-376 {operation}:execute {COMMIT}",
        authorized_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.execute_change_set_once(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=authorization,
        )
    assert raised.value.code == expected_code
    assert sts_calls == []


def test_bridge_pin_execute_claim_is_stable_across_fresh_authorization(
    tmp_path: Path,
) -> None:
    intent = _intent()
    pin = _bridge_pin()
    store = _claim_store(tmp_path)
    dispatch, attestation, cloudformation, cloudtrail = _prime_execution_evidence(
        store=store,
        bootstrap=intent,
        operation="bridge-pin",
        intent_digest=pin["intent_digest"],
        request_digest=pin["request_digest"],
        request=pin["request"],
    )
    first = _fresh_mutation_auth(
        "bridge-pin:execute", pin["intent_digest"], seconds_before=120
    )
    second = _fresh_mutation_auth(
        "bridge-pin:execute", pin["intent_digest"], seconds_before=60
    )
    assert first["authorization_digest"] != second["authorization_digest"]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(), cloudformation, cloudtrail=cloudtrail
        ),
        claims=store,
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    kwargs = {
        "bootstrap_intent": intent,
        "source_root": ROOT,
        "foundation_readback": _foundation_readback(),
        "bridge_pin": pin,
        "dispatch_receipt": dispatch,
        "change_set_attestation": attestation,
    }
    provider.execute_bridge_pin_once(**kwargs, authorization=first)
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.execute_bridge_pin_once(**kwargs, authorization=second)
    assert raised.value.code == "MUTATION_ALREADY_CLAIMED"
    assert len(cloudformation.calls) == 1


def test_access_update_execute_claim_is_stable_across_fresh_authorization(
    tmp_path: Path,
) -> None:
    intent = _intent()
    route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
    delegation = _object_receipt(DELEGATION_TEMPLATE.name, "Delegation-Version-B")
    update = pure.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=_foundation_readback(),
        route_template_receipt=route,
        delegation_template_receipt=delegation,
        reviewed_sources=_reviewed_sources(),
        foundation_template=FOUNDATION.read_bytes(),
    )
    store = _claim_store(tmp_path)
    dispatch, attestation, cloudformation, cloudtrail = _prime_execution_evidence(
        store=store,
        bootstrap=intent,
        operation="foundation-access-update",
        intent_digest=update["intent_digest"],
        request_digest=update["request_digest"],
        request=update["request"],
    )
    first = _fresh_mutation_auth(
        "foundation-access-update:execute",
        update["intent_digest"],
        seconds_before=120,
    )
    second = _fresh_mutation_auth(
        "foundation-access-update:execute",
        update["intent_digest"],
        seconds_before=60,
    )
    assert first["authorization_digest"] != second["authorization_digest"]
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts([]), cloudformation, cloudtrail=cloudtrail
        ),
        claims=store,
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    kwargs = {
        "bootstrap_intent": intent,
        "foundation_readback": _foundation_readback(),
        "access_update": update,
        "route_template_receipt": route,
        "delegation_template_receipt": delegation,
        "source_root": ROOT,
        "dispatch_receipt": dispatch,
        "change_set_attestation": attestation,
    }
    provider.execute_foundation_access_update_once(**kwargs, authorization=first)
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.execute_foundation_access_update_once(
            **kwargs, authorization=second
        )
    assert raised.value.code == "MUTATION_ALREADY_CLAIMED"
    assert len(cloudformation.calls) == 1


@pytest.mark.parametrize("mode", ["generic", "bridge-pin", "access-update"])
def test_execute_recovery_uses_original_claim_after_window_and_never_reexecutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    intent = _intent()
    store = _claim_store(tmp_path)
    cloudformation = ExecuteCloudFormation()
    if mode == "access-update":
        sts = Sts([])
        profile = pure.AUTHORITY_PROFILE
        account = pure.AUTHORITY_ACCOUNT_ID
        caller = AUTH_CALLER
    else:
        sts = MgmtSts()
        profile = pure.MANAGEMENT_PROFILE
        account = pure.MANAGEMENT_ACCOUNT_ID
        caller = MGMT_CALLER
    cloudtrail = ExecuteRecoveryCloudTrail(account=account, caller=caller)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(sts, cloudformation, cloudtrail=cloudtrail),
        claims=store,
        profile=profile,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )

    if mode == "generic":
        operation = "bridge-create"
        request = intent["requests"][operation]
        dispatch, attestation, prepared_cfn, create_cloudtrail = (
            _prime_execution_evidence(
                store=store,
                bootstrap=intent,
                operation=operation,
                intent_digest=intent["intent_digest"],
                request_digest=intent["request_digests"][operation],
                request=request,
            )
        )
        cloudformation.request = prepared_cfn.request
        cloudformation.dispatch = prepared_cfn.dispatch
        cloudformation.changes = prepared_cfn.changes
        cloudtrail.create_delegate = create_cloudtrail
        original_authorization = pure.materialize_authorization(
            intent=intent,
            operation=f"{operation}:execute",
            authorization=f"AUTHORIZE GUG-376 {operation}:execute {COMMIT}",
            authorized_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )
        original = provider.execute_change_set_once(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=original_authorization,
        )
        monkeypatch.setattr(
            provider, "readback_stack", lambda **_kwargs: {"aws_calls": 4}
        )
        recover = lambda: provider.recover_change_set_execution(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
        )
        result_key = "stack_readback"
    elif mode == "bridge-pin":
        pin = _bridge_pin()
        dispatch, attestation, prepared_cfn, create_cloudtrail = (
            _prime_execution_evidence(
                store=store,
                bootstrap=intent,
                operation="bridge-pin",
                intent_digest=pin["intent_digest"],
                request_digest=pin["request_digest"],
                request=pin["request"],
            )
        )
        cloudformation.request = prepared_cfn.request
        cloudformation.dispatch = prepared_cfn.dispatch
        cloudformation.changes = prepared_cfn.changes
        cloudtrail.create_delegate = create_cloudtrail
        original = provider.execute_bridge_pin_once(
            bootstrap_intent=intent,
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            bridge_pin=pin,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=_mutation_auth("bridge-pin:execute", pin["intent_digest"]),
        )
        monkeypatch.setattr(
            provider, "readback_stack", lambda **_kwargs: {"aws_calls": 4}
        )
        recover = lambda: provider.recover_bridge_pin_execution(
            bootstrap_intent=intent,
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            bridge_pin=pin,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
        )
        result_key = "stack_readback"
    else:
        route = _object_receipt(ROUTE_TEMPLATE.name, "Route-Version-A")
        delegation = _object_receipt(
            DELEGATION_TEMPLATE.name, "Delegation-Version-B"
        )
        update = pure.materialize_foundation_access_update(
            bootstrap_intent=intent,
            foundation_readback=_foundation_readback(),
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            reviewed_sources=_reviewed_sources(),
            foundation_template=FOUNDATION.read_bytes(),
        )
        dispatch, attestation, prepared_cfn, create_cloudtrail = (
            _prime_execution_evidence(
                store=store,
                bootstrap=intent,
                operation="foundation-access-update",
                intent_digest=update["intent_digest"],
                request_digest=update["request_digest"],
                request=update["request"],
            )
        )
        cloudformation.request = prepared_cfn.request
        cloudformation.dispatch = prepared_cfn.dispatch
        cloudformation.changes = prepared_cfn.changes
        cloudtrail.create_delegate = create_cloudtrail
        original = provider.execute_foundation_access_update_once(
            bootstrap_intent=intent,
            foundation_readback=_foundation_readback(),
            access_update=update,
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            source_root=ROOT,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
            authorization=_mutation_auth(
                "foundation-access-update:execute", update["intent_digest"]
            ),
        )
        monkeypatch.setattr(
            provider,
            "readback_foundation_access_update",
            lambda **_kwargs: {"aws_calls": 6},
        )
        recover = lambda: provider.recover_foundation_access_update_execution(
            bootstrap_intent=intent,
            foundation_readback=_foundation_readback(),
            access_update=update,
            route_template_receipt=route,
            delegation_template_receipt=delegation,
            source_root=ROOT,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
        )
        result_key = "foundation_access_readback"

    assert len(cloudformation.calls) == 1
    cloudtrail.request = copy.deepcopy(cloudformation.calls[0])
    monkeypatch.setattr(
        provider,
        "_clock",
        lambda: datetime(2026, 8, 30, 13, 0, 1, tzinfo=timezone.utc),
    )
    recovered_one = recover()
    recovered_two = recover()
    assert recovered_one["execution_receipt"] == original
    assert recovered_two["execution_receipt"] == original
    assert recovered_one[result_key]["aws_calls"] in {4, 6}
    assert len(cloudformation.calls) == 1
    assert cloudtrail.calls == 2
    cloudtrail.duplicate = True
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        recover()
    assert raised.value.code == (
        "CLOUDFORMATION_EXECUTION_RECOVERY_EVENT_AMBIGUOUS"
    )
    assert len(cloudformation.calls) == 1


def test_execute_recovery_requires_original_execution_claim_before_sts(
    tmp_path: Path,
) -> None:
    intent = _intent()
    operation = "bridge-create"
    dispatch = _execution_dispatch(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
    )
    attestation = _execution_attestation(
        operation=operation,
        intent_digest=intent["intent_digest"],
        request_digest=intent["request_digests"][operation],
        dispatch=dispatch,
    )
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), CloudFormationUnused(), cloudtrail=object()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.recover_change_set_execution(
            bootstrap_intent=intent,
            source_root=ROOT,
            operation=operation,
            dispatch_receipt=dispatch,
            change_set_attestation=attestation,
        )
    assert raised.value.code == "CAUSAL_CLAIM_REQUIRED"


def test_connected_publish_is_sts_first_one_attempt_and_claimed(tmp_path: Path) -> None:
    events: list[str] = []
    intent = _object_intent("template.yaml")
    s3 = S3Put(events, intent)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=s3),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    receipt = provider.publish_object_once(
        bootstrap_intent=_intent(),
        source_root=ROOT,
        foundation_readback=_foundation_readback(),
        object_intent=intent,
        body=b"template",
        authorization=_mutation_auth("publish-object", intent["intent_digest"]),
    )
    assert events == ["sts", "list", "put"]
    assert receipt["aws_mutations"] == 1
    assert receipt["provider_request_id"] == "4V7EXAMPLEREQUEST"
    assert receipt["recovery_evidence_type"] == "S3_PUT_RESPONSE"
    aws.ConnectedArtifactBootstrapProvider._validate_object_dispatch_receipt(
        receipt,
        bootstrap=_intent(),
        intent=intent,
    )
    assert s3.calls == 1
    assert len(list(tmp_path.glob("*.claim.json"))) == 1
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.publish_object_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
            body=b"template",
            authorization=_mutation_auth("publish-object", intent["intent_digest"]),
        )
    assert raised.value.code == "MUTATION_ALREADY_CLAIMED"
    assert s3.calls == 1


def test_publish_consumes_exact_admission_after_preflight_immediately_before_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    loader_calls: list[dict[str, Any]] = []
    assertion_calls: list[dict[str, Any]] = []
    intent = _object_intent("template.yaml")
    base_claims = _claim_store(tmp_path)
    capability = object()

    class RecordingClaims:
        def reserve(self, **kwargs: Any) -> Path:
            events.append("claim")
            return base_claims.reserve(**kwargs)

        def read_exact(self, **kwargs: Any) -> dict[str, Any]:
            return base_claims.read_exact(**kwargs)

    def loader(**kwargs: Any) -> object:
        events.append("admission-load")
        loader_calls.append(kwargs)
        return capability

    def assert_active(value: object, **kwargs: Any) -> str:
        events.append("admission-assert")
        assert value is capability
        assertion_calls.append(kwargs)
        return "sha256:" + "8" * 64

    monkeypatch.setattr(aws, "assert_route_collision_admission_active", assert_active)
    provider = aws.ConnectedArtifactBootstrapProvider(
        clients=aws.Clients(
            Sts(events), CloudFormationUnused(), s3=S3Put(events, intent)
        ),
        claims=RecordingClaims(),  # type: ignore[arg-type]
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
        collision_admission_loader=loader,  # type: ignore[arg-type]
    )
    receipt = provider.publish_object_once(
        bootstrap_intent=_intent(),
        source_root=ROOT,
        foundation_readback=_foundation_readback(),
        object_intent=intent,
        body=b"template",
        authorization=_mutation_auth("publish-object", intent["intent_digest"]),
    )

    expected = {
        "operation": "publish-object",
        "effect_request_digest": intent["request_digest"],
        "bootstrap_intent_digest": _intent()["intent_digest"],
        "now": NOW,
    }
    assert loader_calls == [expected]
    assert assertion_calls == [expected]
    assert events == [
        "sts",
        "list",
        "admission-load",
        "admission-assert",
        "claim",
        "put",
    ]
    binding = {
        key: value for key, value in expected.items() if key != "now"
    }
    binding["admission_digest"] = "sha256:" + "8" * 64
    assert receipt["collision_admission"] == binding
    claim = base_claims.read_exact(
        operation="publish-object", digest=intent["effect_digest"]
    )
    assert claim["collision_admission"] == binding


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("missing", "COLLISION_ADMISSION_REQUIRED"),
        ("rejected", "ROUTE_COLLISION_ADMISSION_NOT_ACTIVE"),
    ],
)
def test_publish_admission_failure_blocks_claim_and_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    code: str,
) -> None:
    events: list[str] = []
    intent = _object_intent("template.yaml")
    s3 = S3Put(events, intent)
    loader = None
    if mode == "rejected":
        loader = lambda **_kwargs: object()

        def reject(*_args: Any, **_kwargs: Any) -> str:
            raise aws.RouteCollisionAdmissionError(code)

        monkeypatch.setattr(aws, "assert_route_collision_admission_active", reject)
    provider = aws.ConnectedArtifactBootstrapProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=s3),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
        collision_admission_loader=loader,  # type: ignore[arg-type]
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.publish_object_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
            body=b"template",
            authorization=_mutation_auth(
                "publish-object", intent["intent_digest"]
            ),
        )
    assert raised.value.code == code
    assert events == ["sts", "list"]
    assert s3.calls == 0
    assert not list(tmp_path.glob("*.claim.json"))


def test_connected_publish_rejects_body_before_any_aws_call(tmp_path: Path) -> None:
    events: list[str] = []
    intent = _object_intent("template.yaml")
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=S3Put(events, intent)),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.publish_object_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
            body=b"drifted",
            authorization=_mutation_auth("publish-object", intent["intent_digest"]),
        )
    assert raised.value.code == "OBJECT_BODY_MISMATCH"
    assert events == []


class S3ObjectRecovery:
    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        drift: str | None = None,
    ) -> None:
        self.intent = intent
        self.drift = drift
        self.put_calls = 0
        self.list_calls = 0

    def list_object_versions(self, **_request: Any) -> dict[str, Any]:
        self.list_calls += 1
        request = self.intent["request"]
        version = {
            "Key": request["Key"],
            "VersionId": "Version-A",
            "LastModified": (
                NOW + timedelta(hours=2)
                if self.drift == "window"
                else NOW
            ),
            "IsLatest": True,
            "Size": request["ContentLength"],
            "ETag": '"causal-etag"',
            "StorageClass": "STANDARD",
        }
        versions = [] if self.drift == "zero" else [version]
        if self.drift == "multiple":
            versions.append({**version, "VersionId": "Version-B"})
        deletes = (
            [{"Key": request["Key"], "VersionId": "Delete-A"}]
            if self.drift == "delete"
            else []
        )
        return {
            "Versions": versions,
            "DeleteMarkers": deletes,
            "IsTruncated": False,
            "ResponseMetadata": {"RequestId": "4V7EXAMPLEREQUEST"},
        }

    def get_bucket_versioning(self, **_request: Any) -> dict[str, Any]:
        return {"Status": "Enabled"}

    def head_object(self, **_request: Any) -> dict[str, Any]:
        request = self.intent["request"]
        metadata = copy.deepcopy(request["Metadata"])
        if self.drift == "metadata":
            metadata["effect-digest"] = "sha256:" + "f" * 64
        checksum = (
            base64.b64encode(b"x" * 32).decode("ascii")
            if self.drift == "checksum"
            else request["ChecksumSHA256"]
        )
        return {
            "VersionId": "Version-A",
            "ContentLength": request["ContentLength"],
            "ContentType": request["ContentType"],
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": request["SSEKMSKeyId"],
            "BucketKeyEnabled": True,
            "Metadata": metadata,
            "ChecksumSHA256": checksum,
            "ChecksumType": "FULL_OBJECT",
        }

    def get_object_attributes(self, **_request: Any) -> dict[str, Any]:
        request = self.intent["request"]
        checksum = (
            base64.b64encode(b"x" * 32).decode("ascii")
            if self.drift == "checksum"
            else request["ChecksumSHA256"]
        )
        return {
            "VersionId": "Version-A",
            "ObjectSize": request["ContentLength"],
            "StorageClass": "STANDARD",
            "Checksum": {
                "ChecksumSHA256": checksum,
                "ChecksumType": "FULL_OBJECT",
            },
        }

    def get_object_tagging(self, **_request: Any) -> dict[str, Any]:
        tags = {
            "managed_by": "gug376-artifact-bootstrap",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-376",
            "source_commit": COMMIT,
            "mutation_nonce": self.intent["mutation_nonce"],
            "effect_digest": self.intent["effect_digest"],
            "causal_claim_digest": self.intent["causal_claim_digest"],
        }
        if self.drift == "tag":
            tags["effect_digest"] = "sha256:" + "f" * 64
        return {
            "TagSet": [
                {"Key": key, "Value": value} for key, value in tags.items()
            ]
        }

    def get_object(self, **_request: Any) -> dict[str, Any]:
        request = self.intent["request"]
        metadata = copy.deepcopy(request["Metadata"])
        if self.drift == "metadata":
            metadata["effect-digest"] = "sha256:" + "f" * 64
        checksum = (
            base64.b64encode(b"x" * 32).decode("ascii")
            if self.drift == "checksum"
            else request["ChecksumSHA256"]
        )
        return {
            "VersionId": "Version-A",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": request["SSEKMSKeyId"],
            "Metadata": metadata,
            "ChecksumSHA256": checksum,
            "ChecksumType": "FULL_OBJECT",
            "Body": StreamingBody(b"template"),
        }


def _reserve_object_claim(
    store: aws.OExclClaimStore, intent: Mapping[str, Any]
) -> None:
    authorization = _mutation_auth("publish-object", intent["intent_digest"])
    store.reserve(
        operation="publish-object",
        digest=intent["effect_digest"],
        claimed_at="2026-08-30T11:59:00Z",
        caller_arn=AUTH_CALLER,
        request_digest=intent["request_digest"],
        authorization_digest=authorization["authorization_digest"],
        authorization_record=authorization,
        preflight_digest="sha256:" + "b" * 64,
        preflight_calls=1,
        mutation_nonce=intent["mutation_nonce"],
        causal_claim_digest=intent["causal_claim_digest"],
        collision_admission=_admission_binding("publish-object", intent["request"]),
    )


def test_object_recovery_is_causal_deterministic_and_never_puts(
    tmp_path: Path,
) -> None:
    intent = _object_intent("template.yaml")
    store = _claim_store(tmp_path)
    _reserve_object_claim(store, intent)
    s3 = S3ObjectRecovery(intent=intent)
    events: list[str] = []
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=s3),
        claims=store,
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    first = provider.recover_object_publish(
        bootstrap_intent=_intent(),
        source_root=ROOT,
        foundation_readback=_foundation_readback(),
        object_intent=intent,
    )
    second = provider.recover_object_publish(
        bootstrap_intent=_intent(),
        source_root=ROOT,
        foundation_readback=_foundation_readback(),
        object_intent=intent,
    )
    assert first == second
    assert first["dispatch_receipt"]["provider_request_id"] is None
    assert first["dispatch_receipt"]["recovery_evidence_type"] == (
        "S3_DATA_PLANE_CAUSAL_RECOVERY"
    )
    assert first["object_readback"]["dispatch_receipt_digest"] == (
        first["dispatch_receipt"]["receipt_digest"]
    )
    assert s3.put_calls == 0
    assert s3.list_calls == 2


@pytest.mark.parametrize(
    "drift", ["zero", "multiple", "delete", "window", "metadata", "tag", "checksum"]
)
def test_object_recovery_rejects_ambiguity_and_readback_drift(
    tmp_path: Path, drift: str
) -> None:
    intent = _object_intent("template.yaml")
    store = _claim_store(tmp_path)
    _reserve_object_claim(store, intent)
    s3 = S3ObjectRecovery(intent=intent, drift=drift)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts([]), CloudFormationUnused(), s3=s3),
        claims=store,
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.recover_object_publish(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
        )
    assert raised.value.code in {
        "OBJECT_RECOVERY_AMBIGUOUS",
        "OBJECT_READBACK_MISMATCH",
    }
    assert s3.put_calls == 0


@pytest.mark.parametrize("variant", ["partial", "extra", "resealed-drift"])
def test_object_readback_rejects_noncanonical_dispatch_before_sts(
    tmp_path: Path, variant: str
) -> None:
    events: list[str] = []
    intent = _object_intent("template.yaml")
    valid = {
        "schema_version": 1,
        "record_type": aws.OBJECT_DISPATCH_TYPE,
        "source_commit": COMMIT,
        "bootstrap_intent_digest": _intent()["intent_digest"],
        "object_intent_digest": intent["intent_digest"],
        "effect_digest": intent["effect_digest"],
        "mutation_nonce": intent["mutation_nonce"],
        "causal_claim_digest": intent["causal_claim_digest"],
        "authorization_digest": "sha256:" + "a" * 64,
        "collision_admission": {
            "operation": "publish-object",
            "effect_request_digest": intent["request_digest"],
            "bootstrap_intent_digest": _intent()["intent_digest"],
            "admission_digest": "sha256:" + "9" * 64,
        },
        "preflight_absence_digest": "sha256:" + "b" * 64,
        "preflight_calls": 1,
        "verifier": {
            "account_id": pure.AUTHORITY_ACCOUNT_ID,
            "caller_arn": AUTH_CALLER,
            "profile": pure.AUTHORITY_PROFILE,
            "region": pure.REGION,
        },
        "bucket": intent["request"]["Bucket"],
        "key": intent["request"]["Key"],
        "version": "Version-A",
        "provider_request_id": "4V7EXAMPLEREQUEST",
        "recovery_evidence_type": "S3_PUT_RESPONSE",
        "recovery_evidence_digest": None,
        "dispatched_at": "2026-08-30T12:00:00Z",
        "aws_calls": 3,
        "aws_mutations": 1,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": pure.PRODUCTION_STATUS,
    }
    valid["receipt_digest"] = pure.digest_value(valid)
    if variant == "partial":
        dispatch = {
            key: valid[key]
            for key in (
                "record_type",
                "object_intent_digest",
                "bucket",
                "key",
                "version",
            )
        }
    else:
        dispatch = copy.deepcopy(valid)
        if variant == "extra":
            dispatch["unreviewed"] = True
        else:
            dispatch["object_intent_digest"] = "sha256:" + "f" * 64
            dispatch.pop("receipt_digest")
            dispatch["receipt_digest"] = pure.digest_value(dispatch)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(Sts(events), CloudFormationUnused(), s3=object()),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.readback_object(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            object_intent=intent,
            dispatch_receipt=dispatch,
        )
    assert raised.value.code == "OBJECT_DISPATCH_RECEIPT_INVALID"
    assert events == []


@pytest.mark.parametrize("variant", ["partial", "extra", "resealed-drift"])
def test_signing_readback_rejects_noncanonical_dispatch_before_sts(
    tmp_path: Path, variant: str
) -> None:
    events: list[str] = []
    unsigned, intent = _signing_intent()
    job_id = "55555555-5555-4555-8555-555555555555"
    valid = {
        "schema_version": 1,
        "record_type": aws.SIGNING_DISPATCH_TYPE,
        "source_commit": COMMIT,
        "bootstrap_intent_digest": _intent()["intent_digest"],
        "signing_intent_digest": intent["intent_digest"],
        "authorization_digest": "sha256:" + "a" * 64,
        "collision_admission": {
            "operation": "start-signing-job",
            "effect_request_digest": intent["request_digest"],
            "bootstrap_intent_digest": _intent()["intent_digest"],
            "admission_digest": "sha256:" + "9" * 64,
        },
        "verifier": {
            "account_id": pure.AUTHORITY_ACCOUNT_ID,
            "caller_arn": AUTH_CALLER,
            "profile": pure.AUTHORITY_PROFILE,
            "region": pure.REGION,
        },
        "job_id": job_id,
        "job_arn": (
            "arn:aws:signer:us-east-1:042360977644:/signing-jobs/" + job_id
        ),
        "request_id": REQUEST_ID,
        "dispatched_at": "2026-08-30T12:00:00Z",
        "aws_calls": 3,
        "aws_mutations": 1,
        "retry_permitted": False,
        "production_authorized": False,
        "production_status": pure.PRODUCTION_STATUS,
    }
    valid["receipt_digest"] = pure.digest_value(valid)
    if variant == "partial":
        dispatch = {
            "record_type": aws.SIGNING_DISPATCH_TYPE,
            "signing_intent_digest": intent["intent_digest"],
            "job_id": job_id,
        }
    else:
        dispatch = copy.deepcopy(valid)
        if variant == "extra":
            dispatch["unreviewed"] = True
        else:
            dispatch["signing_intent_digest"] = "sha256:" + "f" * 64
            dispatch.pop("receipt_digest")
            dispatch["receipt_digest"] = pure.digest_value(dispatch)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(events), CloudFormationUnused(), s3=object(), signer=object()
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.readback_signing_job(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            bridge_pin=_bridge_pin(),
            bridge_pin_readback=_bridge_pin_readback(),
            unsigned_receipt=unsigned,
            signing_intent=intent,
            dispatch_receipt=dispatch,
        )
    assert raised.value.code == "SIGNING_DISPATCH_RECEIPT_INVALID"
    assert events == []
    assert not list(tmp_path.iterdir())


class SigningRecoveryCloudTrail:
    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        job_id: str,
        duplicate: bool = False,
    ) -> None:
        self.intent = intent
        self.job_id = job_id
        self.duplicate = duplicate
        self.calls = 0

    def lookup_events(self, **_request: Any) -> dict[str, Any]:
        self.calls += 1

        def event(event_id: str, request_id: str, job_id: str) -> dict[str, Any]:
            return {
                "eventSource": "signer.amazonaws.com",
                "eventName": "StartSigningJob",
                "awsRegion": pure.REGION,
                "recipientAccountId": pure.AUTHORITY_ACCOUNT_ID,
                "errorCode": None,
                "errorMessage": None,
                "eventID": event_id,
                "requestID": request_id,
                "eventTime": "2026-08-30T11:59:30Z",
                "userIdentity": {"arn": AUTH_CALLER},
                "requestParameters": copy.deepcopy(self.intent["request"]),
                "responseElements": {"jobId": job_id},
            }

        events = [
            {
                "CloudTrailEvent": json.dumps(
                    event(
                        "11111111-1111-4111-8111-111111111111",
                        "22222222-2222-4222-8222-222222222222",
                        self.job_id,
                    )
                )
            }
        ]
        if self.duplicate:
            events.append(
                {
                    "CloudTrailEvent": json.dumps(
                        event(
                            "33333333-3333-4333-8333-333333333333",
                            "44444444-4444-4444-8444-444444444444",
                            "66666666-6666-4666-8666-666666666666",
                        )
                    )
                }
            )
        return {
            "Events": events,
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class SigningRecoverySigner:
    def __init__(
        self,
        *,
        intent: Mapping[str, Any],
        job_id: str,
        revoked: bool = False,
    ) -> None:
        self.intent = intent
        self.job_id = job_id
        self.revoked = revoked
        self.start_calls = 0
        self.signed_key = intent["request"]["destination"]["s3"]["prefix"] + (
            f"{job_id}.zip"
        )

    def describe_signing_job(self, **_request: Any) -> dict[str, Any]:
        return {
            "status": "Succeeded",
            "source": copy.deepcopy(self.intent["request"]["source"]),
            "signedObject": {
                "s3": {
                    "bucketName": self.intent["request"]["destination"]["s3"][
                        "bucketName"
                    ],
                    "key": self.signed_key,
                }
            },
            "profileName": self.intent["request"]["profileName"],
            "profileVersion": "ABCDEFGHIJ",
            "jobOwner": pure.AUTHORITY_ACCOUNT_ID,
            "jobInvoker": pure.AUTHORITY_ACCOUNT_ID,
            "platformId": "AWSLambda-SHA384-ECDSA",
            "revocationRecord": None,
        }

    def get_signing_profile(self, **_request: Any) -> dict[str, Any]:
        profile_name = self.intent["request"]["profileName"]
        return {
            "profileName": profile_name,
            "arn": (
                f"arn:aws:signer:{pure.REGION}:{pure.AUTHORITY_ACCOUNT_ID}:"
                f"/signing-profiles/{profile_name}"
            ),
            "profileVersionArn": self.intent["signing_profile_version_arn"],
            "platformId": "AWSLambda-SHA384-ECDSA",
            "status": "Active",
            "revocationRecord": (
                {"revokedAt": NOW, "revokedBy": "drift"}
                if self.revoked
                else None
            ),
        }

    def list_tags_for_resource(self, **_request: Any) -> dict[str, Any]:
        return {
            "tags": {
                "managed_by": "cloudformation",
                "service": "scanalyze-platform-authority",
                "work_package": "GUG-376",
                "source_commit": COMMIT,
            }
        }


class SigningRecoveryS3:
    def __init__(self, *, signer: SigningRecoverySigner) -> None:
        self.signer = signer
        self.payload = b"signed-artifact"

    def list_object_versions(self, **_request: Any) -> dict[str, Any]:
        return {
            "Versions": [
                {
                    "Key": self.signer.signed_key,
                    "VersionId": "Signed-Version-A",
                }
            ],
            "DeleteMarkers": [],
            "IsTruncated": False,
        }

    def head_object(self, **_request: Any) -> dict[str, Any]:
        return {
            "VersionId": "Signed-Version-A",
            "ContentLength": len(self.payload),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_ARN,
            "BucketKeyEnabled": True,
        }

    def get_object(self, **_request: Any) -> dict[str, Any]:
        return {
            "VersionId": "Signed-Version-A",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": KMS_ARN,
            "Body": StreamingBody(self.payload),
        }


def _reserve_signing_claim(
    store: aws.OExclClaimStore, intent: Mapping[str, Any]
) -> None:
    authorization = _mutation_auth(
        "start-signing-job", intent["intent_digest"]
    )
    store.reserve(
        operation="start-signing-job",
        digest=intent["intent_digest"],
        claimed_at="2026-08-30T11:59:00Z",
        caller_arn=AUTH_CALLER,
        request_digest=intent["request_digest"],
        authorization_digest=authorization["authorization_digest"],
        authorization_record=authorization,
        request_token=intent["request"]["clientRequestToken"],
        collision_admission=_admission_binding(
            "start-signing-job", intent["request"]
        ),
    )


def test_signing_recovery_is_claimed_deterministic_and_revalidates_profile(
    tmp_path: Path,
) -> None:
    unsigned, intent = _signing_intent()
    job_id = "55555555-5555-4555-8555-555555555555"
    store = _claim_store(tmp_path)
    _reserve_signing_claim(store, intent)
    cloudtrail = SigningRecoveryCloudTrail(intent=intent, job_id=job_id)
    signer = SigningRecoverySigner(intent=intent, job_id=job_id)
    s3 = SigningRecoveryS3(signer=signer)
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts([]),
            CloudFormationUnused(),
            cloudtrail=cloudtrail,
            s3=s3,
            signer=signer,
        ),
        claims=store,
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    kwargs = {
        "bootstrap_intent": _intent(),
        "source_root": ROOT,
        "foundation_readback": _foundation_readback(),
        "bridge_pin": _bridge_pin(),
        "bridge_pin_readback": _bridge_pin_readback(),
        "unsigned_receipt": unsigned,
        "signing_intent": intent,
    }
    first = provider.recover_signing_job(**kwargs)
    second = provider.recover_signing_job(**kwargs)
    assert first == second
    assert first["dispatch_receipt"]["request_id"] == (
        "22222222-2222-4222-8222-222222222222"
    )
    assert first["signing_readback"]["profile_version_arn"] == (
        intent["signing_profile_version_arn"]
    )
    assert signer.start_calls == 0
    assert cloudtrail.calls == 2


@pytest.mark.parametrize("drift", ["missing-claim", "duplicate-event", "revoked"])
def test_signing_recovery_rejects_missing_cause_ambiguity_and_profile_drift(
    tmp_path: Path, drift: str
) -> None:
    unsigned, intent = _signing_intent()
    job_id = "55555555-5555-4555-8555-555555555555"
    store = _claim_store(tmp_path)
    if drift != "missing-claim":
        _reserve_signing_claim(store, intent)
    cloudtrail = SigningRecoveryCloudTrail(
        intent=intent, job_id=job_id, duplicate=drift == "duplicate-event"
    )
    signer = SigningRecoverySigner(
        intent=intent, job_id=job_id, revoked=drift == "revoked"
    )
    events: list[str] = []
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(events),
            CloudFormationUnused(),
            cloudtrail=cloudtrail,
            s3=SigningRecoveryS3(signer=signer),
            signer=signer,
        ),
        claims=store,
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.recover_signing_job(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            foundation_readback=_foundation_readback(),
            bridge_pin=_bridge_pin(),
            bridge_pin_readback=_bridge_pin_readback(),
            unsigned_receipt=unsigned,
            signing_intent=intent,
        )
    assert raised.value.code in {
        "CAUSAL_CLAIM_REQUIRED",
        "SIGNING_RECOVERY_AMBIGUOUS",
        "SIGNING_PROFILE_TERMINAL_DRIFT",
    }
    if drift == "missing-claim":
        assert events == []


class CloudFormationResources:
    def __init__(self, *, extra: bool = False) -> None:
        self.extra = extra

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        return {
            "Stacks": [
                {
                    "StackStatus": "CREATE_COMPLETE",
                    "CreationTime": NOW - timedelta(minutes=1),
                    "Outputs": [
                        {"OutputKey": "AssignmentMode", "OutputValue": "true"},
                        {"OutputKey": "ProductionAuthorized", "OutputValue": "false"},
                    ],
                }
            ]
        }

    def get_template(self, **_request: Any) -> dict[str, Any]:
        return {"TemplateBody": BRIDGE.read_text(encoding="utf-8")}

    def list_stack_resources(self, **_request: Any) -> dict[str, Any]:
        resources = [
            {
                "LogicalResourceId": "ArtifactBootstrapPermissionSet",
                "ResourceType": "AWS::SSO::PermissionSet",
            },
            {
                "LogicalResourceId": "ArtifactBootstrapAssignment",
                "ResourceType": "AWS::SSO::Assignment",
            },
        ]
        if self.extra:
            resources.append(
                {"LogicalResourceId": "Backdoor", "ResourceType": "AWS::IAM::Role"}
            )
        return {"StackResourceSummaries": resources}


class MgmtSts:
    def get_caller_identity(self) -> dict[str, Any]:
        return {
            "Account": pure.MANAGEMENT_ACCOUNT_ID,
            "Arn": (
                "arn:aws:sts::839393571433:assumed-role/"
                "AWSReservedSSO_AWSAdministratorAccess_0123456789ABCDEF/operator"
            ),
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


def test_stack_readback_rejects_one_extra_resource(tmp_path: Path) -> None:
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), CloudFormationResources(extra=True)),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: NOW,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.readback_stack(
            bootstrap_intent=_intent(), source_root=ROOT, operation="bridge-create"
        )
    assert raised.value.code == "STACK_RESOURCE_SET_MISMATCH"


class StreamingBody:
    def __init__(self, payload: bytes) -> None:
        self._stream = io.BytesIO(payload)

    def read(self, size: int) -> bytes:
        return self._stream.read(size)


def test_cleanup_retire_expired_materializes_only_one_way_access_removal() -> None:
    intent = _intent()
    recovery = datetime.fromisoformat(
        intent["recovery_not_after"][:-1] + "+00:00"
    )
    cleanup = datetime.fromisoformat(
        intent["cleanup_not_after"][:-1] + "+00:00"
    )
    assert cleanup - recovery == timedelta(hours=24)
    retire = _expired_cleanup_retire(evaluated_at=cleanup)
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in retire["request"]["Parameters"]
    }
    assert retire["mode"] == "EXPIRED"
    assert retire["terminal_readback_digests"] is None
    assert retire["terminal_revalidation_aws_calls"] == 0
    assert retire["request"]["ChangeSetName"] == (
        pure.CLEANUP_RETIRE_CHANGE_SET_NAME
    )
    assert retire["request"]["ChangeSetType"] == "UPDATE"
    assert "RoleARN" not in retire["request"]
    assert "TemplateURL" not in retire["request"]
    assert "OnStackFailure" not in retire["request"]
    assert parameters["AssignmentEnabled"] == "false"
    assert parameters["CleanupAssignmentsEnabled"] == "false"
    assert pure.validate_bridge_cleanup_retire(
        retire,
        bootstrap_intent=intent,
        bridge_revoke_readback=_bridge_revoke_readback(),
    ) == retire


def test_cleanup_retire_expired_rejects_early_or_supplied_success_evidence() -> None:
    intent = _intent()
    cleanup = datetime.fromisoformat(
        intent["cleanup_not_after"][:-1] + "+00:00"
    )
    with pytest.raises(pure.ArtifactBootstrapError) as early:
        _expired_cleanup_retire(evaluated_at=cleanup - timedelta(seconds=1))
    assert early.value.code == "CLEANUP_RETIRE_EXPIRED_EVIDENCE_INVALID"

    with pytest.raises(pure.ArtifactBootstrapError) as mixed:
        pure.materialize_bridge_cleanup_retire(
            bootstrap_intent=intent,
            bridge_revoke_readback=_bridge_revoke_readback(),
            bridge_template=BRIDGE.read_bytes(),
            mode="EXPIRED",
            evaluated_at=cleanup,
            bootstrap_route_release={},
        )
    assert mixed.value.code == "CLEANUP_RETIRE_EXPIRED_EVIDENCE_INVALID"


def test_cleanup_retire_validator_reconstructs_request_and_rejects_rolearn() -> None:
    retire = _expired_cleanup_retire()
    changed = copy.deepcopy(retire)
    changed["request"]["RoleARN"] = (
        "arn:aws:iam::839393571433:role/ArbitraryCloudFormationRole"
    )
    changed["request_digest"] = pure.digest_value(changed["request"])
    changed = _seal(
        {key: value for key, value in changed.items() if key != "intent_digest"},
        "intent_digest",
    )
    with pytest.raises(pure.ArtifactBootstrapError) as raised:
        pure.validate_bridge_cleanup_retire(
            changed,
            bootstrap_intent=_intent(),
            bridge_revoke_readback=_bridge_revoke_readback(),
        )
    assert raised.value.code == "CLEANUP_RETIRE_REQUEST_RECONSTRUCTION_MISMATCH"


@pytest.mark.parametrize(
    ("forbidden_action", "replacement", "expected_code"),
    [
        ("Add", None, "CHANGE_SET_SEMANTIC_DRIFT"),
        ("Modify", "False", "CHANGE_SET_SEMANTIC_DRIFT"),
        ("Remove", "True", "CHANGE_SET_REPLACEMENT_FORBIDDEN"),
    ],
)
def test_cleanup_attestation_rejects_add_modify_or_replacement_and_never_reenables(
    tmp_path: Path,
    forbidden_action: str,
    replacement: str | None,
    expected_code: str,
) -> None:
    retire = _expired_cleanup_retire()
    boundary = datetime.fromisoformat(
        retire["cleanup_not_after"][:-1] + "+00:00"
    )
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in retire["request"]["Parameters"]
    }
    assert parameters["AssignmentEnabled"] == "false"
    assert parameters["CleanupAssignmentsEnabled"] == "false"

    dispatch = _execution_dispatch(
        operation="bridge-cleanup-retire",
        intent_digest=retire["intent_digest"],
        request_digest=retire["request_digest"],
        dispatched_at=boundary.isoformat().replace("+00:00", "Z"),
    )
    changes = [
        _remove_change(
            logical=logical,
            resource_type=resource_type,
        )
        for logical, resource_type in (
            ("BrokerSeedCleanupAssignment", "AWS::SSO::Assignment"),
            ("BrokerSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
            ("ManagementRecoveryRole", "AWS::IAM::Role"),
            ("RouteSeedCleanupAssignment", "AWS::SSO::Assignment"),
            ("RouteSeedCleanupPermissionSet", "AWS::SSO::PermissionSet"),
        )
    ]
    forged = changes[0]["ResourceChange"]
    forged["Action"] = forbidden_action
    if forbidden_action == "Modify":
        forged["Scope"] = ["Properties"]
        forged["Details"] = [
            {
                "ChangeSource": "ParameterReference",
                "Evaluation": "Static",
                "CausingEntity": "CleanupAssignmentsEnabled",
                "Target": {
                    "Attribute": "Properties",
                    "Name": "PrincipalId",
                    "RequiresRecreation": "Never",
                },
            }
        ]
    if replacement is not None:
        forged["Replacement"] = replacement

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(),
            AttestCloudFormation(
                request=retire["request"],
                dispatch=dispatch,
                changes=changes,
            ),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: boundary,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.attest_change_set(
            bootstrap_intent=_intent(),
            operation="bridge-cleanup-retire",
            dispatch_receipt=dispatch,
            source_root=ROOT,
            cleanup_retire=retire,
            bridge_revoke_readback=_bridge_revoke_readback(),
        )
    assert raised.value.code == expected_code


def test_cleanup_retire_authorization_is_exact_and_boundary_closed() -> None:
    retire = _expired_cleanup_retire()
    boundary = datetime.fromisoformat(
        retire["cleanup_not_after"][:-1] + "+00:00"
    )
    phrase = (
        "AUTHORIZE GUG-376 bridge-cleanup-retire:dispatch "
        + retire["intent_digest"]
    )
    authorization = pure.materialize_bridge_cleanup_retire_authorization(
        cleanup_retire=retire,
        operation="dispatch",
        authorization=phrase,
        authorized_at=boundary,
        expires_at=boundary + timedelta(minutes=10),
    )
    assert pure.validate_bridge_cleanup_retire_authorization(
        authorization,
        cleanup_retire=retire,
        operation="dispatch",
        now=boundary,
    ) == authorization
    with pytest.raises(pure.ArtifactBootstrapError):
        pure.materialize_bridge_cleanup_retire_authorization(
            cleanup_retire=retire,
            operation="dispatch",
            authorization=phrase,
            authorized_at=boundary - timedelta(seconds=1),
            expires_at=boundary + timedelta(minutes=1),
        )


def _terminal_revalidation_receipt(*, read_at: str, marker: str) -> dict[str, Any]:
    return _seal(
        {
            "schema_version": 1,
            "record_type": (
                "scanalyze.platform_authority."
                "plan_permission_repair_seed_terminal_readback.v1"
            ),
            "target": marker,
            "read_at": read_at,
            "aws_calls": 4,
            "immutable": marker,
        },
        "readback_digest",
    )


def test_cleanup_success_jit_revalidation_allows_only_freshness_fields(
    tmp_path: Path,
) -> None:
    supplied = {
        target: _terminal_revalidation_receipt(
            read_at="2026-08-30T12:00:00Z", marker=target
        )
        for target in ("route", "broker", "broker-protection")
    }
    live = {
        target: _terminal_revalidation_receipt(
            read_at="2026-08-30T12:01:00Z", marker=target
        )
        for target in ("route", "broker", "broker-protection")
    }
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), CloudFormationUnused()),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: datetime(2026, 8, 30, 12, 2, tzinfo=timezone.utc),
        cleanup_success_revalidator=lambda **_kwargs: live,
    )
    assert provider._revalidate_cleanup_success(  # noqa: SLF001
        cleanup_retire={
            "mode": "SUCCESS",
            "terminal_revalidation_aws_calls": 12,
        },
        seed_intent={"intent_digest": "sha256:" + "1" * 64},
        terminal_readbacks=supplied,
    ) == 12
    drift = copy.deepcopy(live)
    drift["broker"]["immutable"] = "foreign"
    drift["broker"] = _seal(
        {
            key: value
            for key, value in drift["broker"].items()
            if key != "readback_digest"
        },
        "readback_digest",
    )
    provider._cleanup_success_revalidator = lambda **_kwargs: drift  # noqa: SLF001
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider._revalidate_cleanup_success(  # noqa: SLF001
            cleanup_retire={
                "mode": "SUCCESS",
                "terminal_revalidation_aws_calls": 12,
            },
            seed_intent={"intent_digest": "sha256:" + "1" * 64},
            terminal_readbacks=supplied,
        )
    assert raised.value.code == "CLEANUP_RETIRE_LIVE_REVALIDATION_MISMATCH"


class CleanupRetireCloudFormation:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create_change_set(self, **request: Any) -> dict[str, Any]:
        self.calls.append(request)
        return {
            "StackId": (
                "arn:aws:cloudformation:us-east-1:839393571433:stack/"
                f"{pure.BRIDGE_STACK_NAME}/"
                "11111111-1111-4111-8111-111111111111"
            ),
            "Id": (
                "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
                f"{pure.CLEANUP_RETIRE_CHANGE_SET_NAME}/"
                "22222222-2222-4222-8222-222222222222"
            ),
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


def test_expired_cleanup_dispatch_is_one_shot_without_success_profiles(
    tmp_path: Path,
) -> None:
    retire = _expired_cleanup_retire()
    boundary = datetime.fromisoformat(
        retire["cleanup_not_after"][:-1] + "+00:00"
    )
    phrase = (
        "AUTHORIZE GUG-376 bridge-cleanup-retire:dispatch "
        + retire["intent_digest"]
    )
    auth = pure.materialize_bridge_cleanup_retire_authorization(
        cleanup_retire=retire,
        operation="dispatch",
        authorization=phrase,
        authorized_at=boundary,
        expires_at=boundary + timedelta(minutes=10),
    )
    cloudformation = CleanupRetireCloudFormation()
    provider = _ContractHarnessProvider(
        clients=aws.Clients(MgmtSts(), cloudformation),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: boundary,
        source_attestor=lambda **_kwargs: _reviewed_sources(),
        cleanup_success_revalidator=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("EXPIRED must not open success revalidation profiles")
        ),
    )
    receipt = provider.dispatch_change_set_once(
        bootstrap_intent=_intent(),
        source_root=ROOT,
        operation="bridge-cleanup-retire",
        authorization=auth,
        cleanup_retire=retire,
        bridge_revoke_readback=_bridge_revoke_readback(),
    )
    assert receipt["aws_calls"] == 2
    assert len(cloudformation.calls) == 1
    second_auth = pure.materialize_bridge_cleanup_retire_authorization(
        cleanup_retire=retire,
        operation="dispatch",
        authorization=phrase,
        authorized_at=boundary,
        expires_at=boundary + timedelta(minutes=11),
    )
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        provider.dispatch_change_set_once(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            operation="bridge-cleanup-retire",
            authorization=second_auth,
            cleanup_retire=retire,
            bridge_revoke_readback=_bridge_revoke_readback(),
        )
    assert raised.value.code == "MUTATION_ALREADY_CLAIMED"
    assert len(cloudformation.calls) == 1


ARTIFACT_PERMISSION_SET_ARN = (
    "arn:aws:sso:::permissionSet/ssoins-ABCDEFGHIJKLMNOP/"
    "ps-AAAAAAAAAAAAAAAA"
)


class RetiredBridgeCloudFormation:
    def __init__(self, retire: Mapping[str, Any], completed: datetime) -> None:
        self.retire = retire
        self.completed = completed

    def describe_stacks(self, **_request: Any) -> dict[str, Any]:
        return {
            "Stacks": [
                {
                    "StackStatus": "UPDATE_COMPLETE",
                    "LastUpdatedTime": self.completed,
                    "Outputs": [
                        {
                            "OutputKey": "ArtifactBootstrapPermissionSetArn",
                            "OutputValue": ARTIFACT_PERMISSION_SET_ARN,
                        },
                        {"OutputKey": "AssignmentMode", "OutputValue": "false"},
                        {
                            "OutputKey": "CleanupAssignmentMode",
                            "OutputValue": "false",
                        },
                        {
                            "OutputKey": "CleanupNotAfter",
                            "OutputValue": self.retire["cleanup_not_after"],
                        },
                        {
                            "OutputKey": "AuthorityProfileName",
                            "OutputValue": pure.AUTHORITY_PROFILE,
                        },
                        {
                            "OutputKey": "ProductionAuthorized",
                            "OutputValue": "false",
                        },
                    ],
                }
            ],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }

    def get_template(self, **_request: Any) -> dict[str, Any]:
        return {
            "TemplateBody": self.retire["request"]["TemplateBody"],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }

    def list_stack_resources(self, **_request: Any) -> dict[str, Any]:
        return {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": "ArtifactBootstrapPermissionSet",
                    "ResourceType": "AWS::SSO::PermissionSet",
                }
            ],
            "ResponseMetadata": {"RequestId": REQUEST_ID},
        }


class RetiredBridgeSso:
    def __init__(self, retire: Mapping[str, Any], *, foreign_cleanup: bool = False) -> None:
        self.retire = retire
        self.foreign_cleanup = foreign_cleanup

    def describe_permission_set(self, **request: Any) -> dict[str, Any]:
        arn = request["PermissionSetArn"]
        name = (
            "ScanalyzeGug376RouteSeedCleanup"
            if arn != ARTIFACT_PERMISSION_SET_ARN
            else "ScanalyzeGug376ArtifactBootstrap"
        )
        return {
            "PermissionSet": {
                "PermissionSetArn": arn,
                "Name": name,
                "Description": (
                    "GUG-376 temporary artifact-foundation bootstrap; "
                    "no production authority"
                    if arn == ARTIFACT_PERMISSION_SET_ARN
                    else None
                ),
                "SessionDuration": "PT1H",
                "RelayState": None,
            }
        }

    def get_inline_policy_for_permission_set(self, **_request: Any) -> dict[str, Any]:
        parameters = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in self.retire["request"]["Parameters"]
        }
        policy = aws._resolve_bridge_policy(  # noqa: SLF001
            template_body=self.retire["request"]["TemplateBody"],
            parameters=parameters,
        )
        return {"InlinePolicy": pure.canonical_json(policy)}

    def list_tags_for_resource(self, **_request: Any) -> dict[str, Any]:
        return {
            "Tags": [
                {"Key": "managed_by", "Value": "cloudformation"},
                {"Key": "service", "Value": "scanalyze-platform-authority"},
                {"Key": "work_package", "Value": "GUG-376"},
                {"Key": "source_commit", "Value": COMMIT},
            ]
        }

    def list_managed_policies_in_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"AttachedManagedPolicies": []}

    def list_customer_managed_policy_references_in_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"CustomerManagedPolicyReferences": []}

    def get_permissions_boundary_for_permission_set(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"PermissionsBoundary": None}

    def list_account_assignments(self, **_request: Any) -> dict[str, Any]:
        return {"AccountAssignments": []}

    def list_permission_sets_provisioned_to_account(
        self, **_request: Any
    ) -> dict[str, Any]:
        return {"PermissionSets": [ARTIFACT_PERMISSION_SET_ARN]}

    def list_permission_sets(self, **_request: Any) -> dict[str, Any]:
        values = [ARTIFACT_PERMISSION_SET_ARN]
        if self.foreign_cleanup:
            values.append(
                "arn:aws:sso:::permissionSet/ssoins-ABCDEFGHIJKLMNOP/"
                "ps-BBBBBBBBBBBBBBBB"
            )
        return {"PermissionSets": values}


class NoSuchManagementRecoveryRole:
    def get_role(self, **_request: Any) -> dict[str, Any]:
        error = RuntimeError("NoSuchEntity")
        error.response = {"Error": {"Code": "NoSuchEntity"}}  # type: ignore[attr-defined]
        raise error


@pytest.mark.parametrize("foreign_cleanup", [False, True])
def test_cleanup_retire_readback_proves_exact_absence_before_acceptance(
    tmp_path: Path,
    foreign_cleanup: bool,
) -> None:
    retire = _expired_cleanup_retire()
    boundary = datetime.fromisoformat(
        retire["cleanup_not_after"][:-1] + "+00:00"
    )
    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            MgmtSts(),
            RetiredBridgeCloudFormation(
                retire, completed=boundary + timedelta(seconds=1)
            ),
            sso_admin=RetiredBridgeSso(
                retire, foreign_cleanup=foreign_cleanup
            ),
            iam=NoSuchManagementRecoveryRole(),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.MANAGEMENT_PROFILE,
        clock=lambda: boundary + timedelta(seconds=2),
        source_attestor=lambda **_kwargs: _reviewed_sources(),
    )
    if foreign_cleanup:
        with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
            provider.readback_stack(
                bootstrap_intent=_intent(),
                source_root=ROOT,
                operation="bridge-cleanup-retire",
                cleanup_retire=retire,
                bridge_revoke_readback=_bridge_revoke_readback(),
            )
        assert raised.value.code == "CLEANUP_PERMISSION_SET_ABSENCE_INVALID"
    else:
        receipt = provider.readback_stack(
            bootstrap_intent=_intent(),
            source_root=ROOT,
            operation="bridge-cleanup-retire",
            cleanup_retire=retire,
            bridge_revoke_readback=_bridge_revoke_readback(),
        )
        assert receipt["resources"] == [
            {
                "logical_resource_id": "ArtifactBootstrapPermissionSet",
                "resource_type": "AWS::SSO::PermissionSet",
            }
        ]
        assert receipt["cleanup_assignment_count"] == 0
        assert receipt["cleanup_permission_set_count"] == 0
        assert receipt["management_recovery_role_present"] is False
        assert receipt["cleanup_authority_active"] is False
        assert receipt["aws_mutations"] == 0


def test_signed_readback_code_binds_exact_kms_key() -> None:
    source = Path(
        aws.__file__ or ""
    ).read_text(encoding="utf-8")
    assert 'kms_key_arn != intent["sse_kms_key_arn"]' in source
    assert 'head.get("BucketKeyEnabled") is not True' in source
    assert 'head.get("ChecksumType") != "FULL_OBJECT"' in source


def test_no_provider_retry_or_sleep_paths() -> None:
    source = Path(aws.__file__ or "").read_text(encoding="utf-8")
    for forbidden in ("time.sleep", "backoff", "while True"):
        assert forbidden not in source
    assert 'retries.get("total_max_attempts") != 1' in source
    assert "O_EXCL" in source
    assert "uncertain=mutation" in source


class SdkConfig:
    def __init__(self, **values: Any) -> None:
        for key, value in values.items():
            setattr(self, key, value)


class SdkClient:
    def __init__(self, service: str, *, endpoint_drift: bool = False) -> None:
        hosts = {
            "sts": "sts.us-east-1.amazonaws.com",
            "cloudformation": "cloudformation.us-east-1.amazonaws.com",
            "cloudtrail": "cloudtrail.us-east-1.amazonaws.com",
            "sso-admin": "sso.us-east-1.amazonaws.com",
            "kms": "kms.us-east-1.amazonaws.com",
            "s3": "s3.us-east-1.amazonaws.com",
            "signer": "signer.us-east-1.amazonaws.com",
            "lambda": "lambda.us-east-1.amazonaws.com",
        }
        self.meta = type(
            "Meta",
            (),
            {
                "region_name": pure.REGION,
                "endpoint_url": (
                    "https://redirect.invalid"
                    if endpoint_drift
                    else f"https://{hosts[service]}"
                ),
            },
        )()


class SdkSession:
    def __init__(
        self,
        *,
        profile: str = pure.MANAGEMENT_PROFILE,
        credential_method: str = "sso",
        endpoint_drift: str | None = None,
    ) -> None:
        self.profile_name = profile
        self.region_name = pure.REGION
        account = (
            pure.MANAGEMENT_ACCOUNT_ID
            if profile == pure.MANAGEMENT_PROFILE
            else pure.AUTHORITY_ACCOUNT_ID
        )
        role = (
            "AWSAdministratorAccess"
            if profile == pure.MANAGEMENT_PROFILE
            else "ScanalyzeGug376ArtifactBootstrap"
        )
        self._session = type(
            "Internal",
            (),
            {
                "full_config": {
                    "profiles": {
                        profile: {
                            "region": pure.REGION,
                            "sso_account_id": account,
                            "sso_role_name": role,
                            "sso_region": pure.REGION,
                            "sso_start_url": "https://scanalyze.awsapps.com/start",
                        }
                    }
                }
            },
        )()
        self._credential_method = credential_method
        self._endpoint_drift = endpoint_drift
        self.client_names: list[str] = []

    def get_credentials(self) -> Any:
        return type("Credentials", (), {"method": self._credential_method})()

    def client(self, service: str, **_kwargs: Any) -> SdkClient:
        self.client_names.append(service)
        return SdkClient(
            service,
            endpoint_drift=service == self._endpoint_drift,
        )


def test_sdk_boundary_requires_direct_sso_and_canonical_endpoints() -> None:
    config = aws.sdk_client_config(SdkConfig)
    session = SdkSession(profile=pure.AUTHORITY_PROFILE)
    clients = aws.clients_from_session(session, config, environment={})
    assert session.client_names == [
        "sts",
        "cloudformation",
        "cloudtrail",
        "kms",
        "s3",
        "signer",
        "lambda",
    ]
    assert clients.sts is not None and clients.sso_admin is None
    assert config.retries == {"total_max_attempts": 1, "mode": "standard"}
    assert config.ignore_configured_endpoint_urls is True


@pytest.mark.parametrize(
    ("session", "environment", "code"),
    [
        (
            SdkSession(credential_method="env"),
            {},
            "AWS_CREDENTIAL_SOURCE_INVALID",
        ),
        (
            SdkSession(),
            {"AWS_ENDPOINT_URL_STS": "https://redirect.invalid"},
            "AMBIENT_AWS_CONFIGURATION_FORBIDDEN",
        ),
        (
            SdkSession(endpoint_drift="cloudformation"),
            {},
            "AWS_CLIENT_BOUNDARY_INVALID",
        ),
    ],
)
def test_sdk_boundary_rejects_credential_environment_and_endpoint_drift(
    session: SdkSession,
    environment: dict[str, str],
    code: str,
) -> None:
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        aws.clients_from_session(
            session,
            aws.sdk_client_config(SdkConfig),
            environment=environment,
        )
    assert raised.value.code == code


@pytest.mark.parametrize(
    "operation",
    [
        "publish-object",
        "readback-object",
        "recover-object",
        "start-signing",
        "readback-signing",
        "recover-signing",
    ],
)
@pytest.mark.parametrize("source_drift", ["dirty", "wrong-branch", "origin-drift"])
def test_every_object_and_signing_action_rechecks_exact_clean_source_before_sts(
    tmp_path: Path, operation: str, source_drift: str
) -> None:
    events: list[str] = []

    def reject_source(**_kwargs: Any) -> dict[str, Any]:
        raise aws.ConnectedArtifactBootstrapError(
            f"CLEAN_EXACT_MAIN_REQUIRED:{source_drift}"
        )

    provider = _ContractHarnessProvider(
        clients=aws.Clients(
            Sts(events),
            CloudFormationUnused(),
            cloudtrail=object(),
            s3=object(),
            signer=object(),
        ),
        claims=_claim_store(tmp_path),
        profile=pure.AUTHORITY_PROFILE,
        clock=lambda: NOW,
        source_attestor=reject_source,
    )
    object_intent = _object_intent("template.yaml")
    unsigned, signing_intent = _signing_intent()
    shared = {
        "bootstrap_intent": _intent(),
        "source_root": ROOT,
        "foundation_readback": _foundation_readback(),
    }
    calls: dict[str, tuple[Any, dict[str, Any]]] = {
        "publish-object": (
            provider.publish_object_once,
            {
                **shared,
                "object_intent": object_intent,
                "body": b"template",
                "authorization": _mutation_auth(
                    "publish-object", object_intent["intent_digest"]
                ),
            },
        ),
        "readback-object": (
            provider.readback_object,
            {**shared, "object_intent": object_intent, "dispatch_receipt": {}},
        ),
        "recover-object": (
            provider.recover_object_publish,
            {**shared, "object_intent": object_intent},
        ),
        "start-signing": (
            provider.start_signing_job_once,
            {
                **shared,
                "bridge_pin": _bridge_pin(),
                "bridge_pin_readback": _bridge_pin_readback(),
                "unsigned_receipt": unsigned,
                "signing_intent": signing_intent,
                "authorization": _mutation_auth(
                    "start-signing-job", signing_intent["intent_digest"]
                ),
            },
        ),
        "readback-signing": (
            provider.readback_signing_job,
            {
                **shared,
                "bridge_pin": _bridge_pin(),
                "bridge_pin_readback": _bridge_pin_readback(),
                "unsigned_receipt": unsigned,
                "signing_intent": signing_intent,
                "dispatch_receipt": {},
            },
        ),
        "recover-signing": (
            provider.recover_signing_job,
            {
                **shared,
                "bridge_pin": _bridge_pin(),
                "bridge_pin_readback": _bridge_pin_readback(),
                "unsigned_receipt": unsigned,
                "signing_intent": signing_intent,
            },
        ),
    }
    method, kwargs = calls[operation]
    with pytest.raises(aws.ConnectedArtifactBootstrapError) as raised:
        method(**kwargs)
    assert raised.value.code.startswith("CLEAN_EXACT_MAIN_REQUIRED")
    assert events == []


def test_cli_help_is_sdk_independent_and_exposes_the_closed_action_set() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(CLI), "--help"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "temporary" in result.stdout
    assert "GUG-376 artifact foundation" in result.stdout
    cli = _load_cli_module()
    action = next(item for item in cli._parser()._actions if item.dest == "action")
    expected = {
        "materialize-intent",
        "authorize-change-set",
        "authorize-mutation",
        "materialize-bridge-pin",
        "materialize-object-intent",
        "materialize-signing-intent",
        "materialize-access-update",
            "materialize-publish-binding",
            "materialize-route-release",
            "materialize-cleanup-retire",
            "authorize-cleanup-retire",
            *cli._CONNECTED_FIELDS,
    }
    assert set(action.choices) == expected


@pytest.mark.parametrize(
    "action",
    [
        "dispatch-bridge-pin",
        "execute-bridge-pin",
        "dispatch-access-update",
        "execute-access-update",
        "publish-object",
        "start-signing-job",
    ],
)
def test_cli_requires_admission_digest_in_every_expansive_bundle(
    action: str,
    tmp_path: Path,
) -> None:
    cli = _load_cli_module()
    assert cli._MUTATING_CONNECTED_ACTIONS == {
        "dispatch-change-set",
        "execute-change-set",
        "dispatch-bridge-pin",
        "execute-bridge-pin",
        "dispatch-access-update",
        "execute-access-update",
        "publish-object",
        "start-signing-job",
    }
    with pytest.raises(cli.CliError) as raised:
        cli._connected(
            action,
            {},
            source_root=ROOT,
            private_root=tmp_path,
            profile=pure.MANAGEMENT_PROFILE,
            claim_root=tmp_path / "missing-claim-root",
        )
    assert str(raised.value) == "BUNDLE_FIELDS_INVALID"


@pytest.mark.parametrize(
    ("action", "extra"),
    [
        ("dispatch-change-set", {"authorization": {}}),
        (
            "execute-change-set",
            {
                "dispatch_receipt": {},
                "change_set_attestation": {},
                "authorization": {},
            },
        ),
    ],
)
def test_cli_generic_change_set_surface_opens_only_exact_bridge_revoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    extra: Mapping[str, Any],
) -> None:
    cli = _load_cli_module()
    with pytest.raises(cli.CliError) as blocked:
        cli._connected(
            action,
            {
                "bootstrap_intent": {},
                "operation": "bridge-create",
                **dict(extra),
            },
            source_root=ROOT,
            private_root=tmp_path,
            profile=pure.MANAGEMENT_PROFILE,
            claim_root=tmp_path,
        )
    assert str(blocked.value) == "COLLISION_ADMISSION_REQUIRED"

    calls: list[tuple[str, Mapping[str, Any]]] = []

    class Session:
        def __init__(self, **_kwargs: Any) -> None:
            pass

    class Config:
        pass

    class Claims:
        def __init__(self, _root: Path) -> None:
            pass

        def close(self) -> None:
            pass

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            assert "collision_admission_loader" not in kwargs

        def dispatch_change_set_once(self, **kwargs: Any) -> dict[str, Any]:
            calls.append(("dispatch", kwargs))
            return {"status": "dispatched"}

        def execute_change_set_once(self, **kwargs: Any) -> dict[str, Any]:
            calls.append(("execute", kwargs))
            return {"status": "executed"}

    boto3 = types.ModuleType("boto3")
    boto3.Session = Session  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    botocore.__path__ = []  # type: ignore[attr-defined]
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = Config  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setattr(
        cli,
        "_aws_module",
        lambda: types.SimpleNamespace(
            clients_from_session=lambda *_args, **_kwargs: object(),
            sdk_client_config=lambda value: value,
            OExclClaimStore=Claims,
            ConnectedArtifactBootstrapProvider=Provider,
        ),
    )

    result = cli._connected(
        action,
        {
            "bootstrap_intent": {},
            "operation": "bridge-revoke",
            **dict(extra),
        },
        source_root=ROOT,
        private_root=tmp_path,
        profile=pure.MANAGEMENT_PROFILE,
        claim_root=tmp_path,
    )
    assert result["status"] in {"dispatched", "executed"}
    assert calls == [
        (
            "dispatch" if action == "dispatch-change-set" else "execute",
            {
                "bootstrap_intent": {},
                "operation": "bridge-revoke",
                **dict(extra),
                "source_root": ROOT,
            },
        )
    ]


def test_cli_wires_private_admission_loader_only_for_expansive_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    calls: list[dict[str, Any]] = []
    method_calls: list[dict[str, Any]] = []
    capability = object()

    class Session:
        def __init__(self, **_kwargs: Any) -> None:
            pass

    class Config:
        pass

    class Claims:
        def __init__(self, _root: Path) -> None:
            pass

        def close(self) -> None:
            pass

    class Provider:
        def __init__(self, **kwargs: Any) -> None:
            self.loader = kwargs["collision_admission_loader"]

        def dispatch_bridge_pin_once(self, **kwargs: Any) -> dict[str, Any]:
            method_calls.append(kwargs)
            loaded = self.loader(
                operation="bridge-pin:dispatch",
                effect_request_digest="sha256:" + "6" * 64,
                bootstrap_intent_digest="sha256:" + "5" * 64,
                now=NOW,
            )
            assert loaded is capability
            return {"status": "dispatched"}

    def atomic_loader(**_kwargs: Any) -> object:
        return capability

    def build_atomic_loader(**kwargs: Any) -> object:
        calls.append(kwargs)
        return atomic_loader

    boto3 = types.ModuleType("boto3")
    boto3.Session = Session  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    botocore.__path__ = []  # type: ignore[attr-defined]
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = Config  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    monkeypatch.setattr(
        cli,
        "_collision_atomic_context_module",
        lambda: types.SimpleNamespace(
            build_atomic_loader_from_private_context=build_atomic_loader
        ),
    )
    monkeypatch.setattr(
        cli,
        "_aws_module",
        lambda: types.SimpleNamespace(
            clients_from_session=lambda *_args, **_kwargs: object(),
            sdk_client_config=lambda value: value,
            OExclClaimStore=Claims,
            ConnectedArtifactBootstrapProvider=Provider,
        ),
    )
    authorization = {
        "authorization_digest": "sha256:" + "1" * 64,
        "authorized_at": "2026-08-31T12:00:00Z",
        "expires_at": "2026-08-31T12:10:00Z",
    }
    bootstrap_intent = {"source_commit": "a" * 40}
    bundle = {
        "bootstrap_intent": bootstrap_intent,
        "foundation_readback": {},
        "bridge_pin": {},
        "authorization": authorization,
    }
    admission_root = tmp_path / "admission"
    gug395_root = tmp_path / "gug395"
    result = cli._connected(
        "dispatch-bridge-pin",
        bundle,
        source_root=ROOT,
        private_root=tmp_path,
        profile=pure.MANAGEMENT_PROFILE,
        claim_root=tmp_path,
        collision_admission_root=admission_root,
        gug395_private_root=gug395_root,
    )
    assert result == {"status": "dispatched"}
    assert method_calls == [
        {
            "bootstrap_intent": bootstrap_intent,
            "foundation_readback": {},
            "bridge_pin": {},
            "authorization": authorization,
            "source_root": ROOT,
        }
    ]
    assert calls == [
        {
            "admission_private_root": admission_root,
            "effect_private_root": tmp_path,
            "gug395_private_root": gug395_root,
            "expected_approval_reference_digest": authorization[
                "authorization_digest"
            ],
            "expected_authorized_at": authorization["authorized_at"],
            "expected_expires_at": authorization["expires_at"],
            "expected_operation": "bridge-pin:dispatch",
            "expected_source_commit_sha": bootstrap_intent["source_commit"],
            "environment": cli.os.environ,
        }
    ]


def test_cli_uses_only_public_pure_contract_exports() -> None:
    tree = ast.parse(CLI.read_text(encoding="utf-8"))
    contract_attributes = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "contract"
    }
    assert contract_attributes <= set(pure.__all__)


def test_cli_reserves_output_before_allowed_connected_action_and_finishes_same_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli_module()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    bundle_name = "bundle.json"
    output_name = "receipt.json"
    bundle = private / bundle_name
    bundle.write_text("{}\n", encoding="utf-8")
    bundle.chmod(0o600)
    claim_root = tmp_path / "claims"
    calls = 0
    reserved_inode = 0

    def connected(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls, reserved_inode
        calls += 1
        output = private / output_name
        assert output.is_file()
        assert output.stat().st_mode & 0o777 == 0o600
        reserved_inode = output.stat().st_ino
        marker = json.loads(output.read_text(encoding="utf-8"))
        assert marker["status"] == "ATTEMPTING"
        assert marker["record_type"] == (
            "gug376-artifact-bootstrap-output-reservation"
        )
        marker_digest = marker.pop("reservation_digest")
        assert marker_digest == pure.digest_value(marker)
        return {"sealed": True}

    monkeypatch.setattr(cli, "_connected", connected)
    result = cli.main(
        [
            "--private-root",
            str(private),
            "--source-root",
            str(ROOT),
            "dispatch-cleanup-retire",
            "--bundle-name",
            bundle_name,
            "--output-name",
            output_name,
            "--profile",
            pure.MANAGEMENT_PROFILE,
            "--claim-root",
            str(claim_root),
        ]
    )
    assert result == 0
    assert calls == 1
    output = private / output_name
    assert output.stat().st_ino == reserved_inode
    assert json.loads(output.read_text(encoding="utf-8")) == {"sealed": True}
    assert capsys.readouterr().out == ""

    result = cli.main(
        [
            "--private-root",
            str(private),
            "--source-root",
            str(ROOT),
            "dispatch-cleanup-retire",
            "--bundle-name",
            bundle_name,
            "--output-name",
            output_name,
            "--profile",
            pure.MANAGEMENT_PROFILE,
            "--claim-root",
            str(claim_root),
        ]
    )
    assert result == 2
    assert calls == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "PRIVATE_OUTPUT_EXISTS" in captured.err


def test_cli_rejects_arbitrary_body_builder_without_reading_source() -> None:
    cli = _load_cli_module()
    with pytest.raises(cli.CliError) as raised:
        cli._body(
            {"kind": "raw", "body": "unreviewed"},
            source_root=ROOT,
            bootstrap_intent=_intent(),
        )
    assert str(raised.value) == "BODY_BUILDER_INVALID"


def test_cli_private_reader_rejects_hard_linked_input(tmp_path: Path) -> None:
    cli = _load_cli_module()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    original = private / "bundle.json"
    original.write_text("{}\n", encoding="utf-8")
    original.chmod(0o600)
    os.link(original, private / "alias.json")
    _root, descriptor = cli._open_private_root(private)
    try:
        with pytest.raises(cli.CliError) as raised:
            cli._read_bytes(descriptor, "bundle.json")
    finally:
        os.close(descriptor)
    assert str(raised.value) == "PRIVATE_INPUT_INVALID"
