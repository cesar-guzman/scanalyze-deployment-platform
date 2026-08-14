"""Closed-world, offline compiler for the GUG-376 upstream prerequisite lane.

This module performs no filesystem, network, subprocess, credential, or AWS
operations.  Provider request payloads are accepted only transiently: public
contracts retain canonical digests and typed provider-generated slots.  A
phase authorization can therefore cover only the contiguous exact requests
whose slots are already resolved; later requests in the same phase require a
fresh authorization after causal provider readback.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


SOURCE_HEAD_SHA = "51cfbb5d8912bf4a300ae5f258b4ccc250d2f4b4"
SOURCE_MERGE_SHA = "a1999d0f9a885a98e443a5c8e9d4c9f7dba04d86"
SOURCE_TREE_SHA = "0a1171aae5c3fb8ccb8c7e62cbfbd780f91c700e"
GAP_CHECKPOINT_DIGEST = (
    "sha256:9e1ad097fe1f7dfd98ed267bcf2c0aaa4e0a3a92344d589d7e4357c1894bc5d3"
)
ORIGINAL_RUN_DIGEST = (
    "sha256:203c5da1fe530ae27a0166554a091375a432ee3a01507d485596ea19ace8b15c"
)
REGION = "us-east-1"

PHASE_SPECS = (
    ("IDENTITY_CENTER_FOUNDATION", "identity_center_topology", None),
    ("KMS_FOUNDATION", "kms_key", "IDENTITY_CENTER_FOUNDATION"),
    ("S3_ARTIFACT_FOUNDATION", "artifact_bucket", "KMS_FOUNDATION"),
    ("SIGNER_PROFILE_FOUNDATION", "signing_profile", "S3_ARTIFACT_FOUNDATION"),
    ("LAMBDA_CSC_FOUNDATION", "code_signing_config", "SIGNER_PROFILE_FOUNDATION"),
    ("BROKER_UNSIGNED_PUBLISH", "broker_unsigned_object", "LAMBDA_CSC_FOUNDATION"),
    ("BROKER_SIGNING_JOB", "broker_signing_job", "BROKER_UNSIGNED_PUBLISH"),
    (
        "LEDGER_FACTORY_UNSIGNED_PUBLISH",
        "ledger_factory_unsigned_object",
        "BROKER_SIGNING_JOB",
    ),
    (
        "LEDGER_FACTORY_SIGNING_JOB",
        "ledger_factory_signing_job",
        "LEDGER_FACTORY_UNSIGNED_PUBLISH",
    ),
)
PHASE_NAMES = tuple(item[0] for item in PHASE_SPECS)

REQUIRED_ACTIONS: dict[str, Counter[str]] = {
    "IDENTITY_CENTER_FOUNDATION": Counter(
        {
            "sso:CreateApplication": 1,
            "sso:PutApplicationAuthenticationMethod": 1,
            "sso:PutApplicationGrant": 1,
            "sso:PutApplicationAccessScope": 1,
            "sso:PutApplicationAssignmentConfiguration": 1,
            "sso:CreateApplicationAssignment": 1,
            "sso:CreatePermissionSet": 2,
            "sso:PutInlinePolicyToPermissionSet": 2,
            "sso:CreateAccountAssignment": 2,
            "sso:ProvisionPermissionSet": 2,
        }
    ),
    "KMS_FOUNDATION": Counter(
        {"kms:CreateKey": 1, "kms:EnableKeyRotation": 1, "kms:CreateAlias": 1}
    ),
    "S3_ARTIFACT_FOUNDATION": Counter(
        {
            "s3:CreateBucket": 1,
            "s3:PutBucketOwnershipControls": 1,
            "s3:PutPublicAccessBlock": 1,
            "s3:PutBucketVersioning": 1,
            "s3:PutBucketEncryption": 1,
            "s3:PutBucketPolicy": 1,
            "s3:PutBucketTagging": 1,
        }
    ),
    "SIGNER_PROFILE_FOUNDATION": Counter({"signer:PutSigningProfile": 1}),
    "LAMBDA_CSC_FOUNDATION": Counter({"lambda:CreateCodeSigningConfig": 1}),
    "BROKER_UNSIGNED_PUBLISH": Counter({"s3:PutObject": 1}),
    "BROKER_SIGNING_JOB": Counter({"signer:StartSigningJob": 1}),
    "LEDGER_FACTORY_UNSIGNED_PUBLISH": Counter({"s3:PutObject": 1}),
    "LEDGER_FACTORY_SIGNING_JOB": Counter({"signer:StartSigningJob": 1}),
}

REQUEST_KEYS: dict[str, frozenset[str]] = {
    "sso:CreateApplication": frozenset(
        {"ApplicationProviderArn", "ClientToken", "Description", "InstanceArn", "Name", "PortalOptions", "Status", "Tags"}
    ),
    "sso:PutApplicationAuthenticationMethod": frozenset(
        {"ApplicationArn", "AuthenticationMethod", "AuthenticationMethodType"}
    ),
    "sso:PutApplicationGrant": frozenset({"ApplicationArn", "Grant", "GrantType"}),
    "sso:PutApplicationAccessScope": frozenset(
        {"ApplicationArn", "AuthorizedTargets", "Scope"}
    ),
    "sso:PutApplicationAssignmentConfiguration": frozenset(
        {"ApplicationArn", "AssignmentRequired"}
    ),
    "sso:CreateApplicationAssignment": frozenset(
        {"ApplicationArn", "PrincipalId", "PrincipalType"}
    ),
    "sso:CreatePermissionSet": frozenset(
        {"Description", "InstanceArn", "Name", "SessionDuration", "Tags"}
    ),
    "sso:PutInlinePolicyToPermissionSet": frozenset(
        {"InlinePolicy", "InstanceArn", "PermissionSetArn"}
    ),
    "sso:CreateAccountAssignment": frozenset(
        {"InstanceArn", "PermissionSetArn", "PrincipalId", "PrincipalType", "TargetId", "TargetType"}
    ),
    "sso:ProvisionPermissionSet": frozenset(
        {"InstanceArn", "PermissionSetArn", "TargetId", "TargetType"}
    ),
    "kms:CreateKey": frozenset(
        {"BypassPolicyLockoutSafetyCheck", "Description", "KeySpec", "KeyUsage", "MultiRegion", "Origin", "Policy", "Tags"}
    ),
    "kms:EnableKeyRotation": frozenset({"KeyId", "RotationPeriodInDays"}),
    "kms:CreateAlias": frozenset({"AliasName", "TargetKeyId"}),
    "s3:CreateBucket": frozenset({"Bucket", "ObjectOwnership"}),
    "s3:PutBucketOwnershipControls": frozenset({"Bucket", "OwnershipControls"}),
    "s3:PutPublicAccessBlock": frozenset({"Bucket", "PublicAccessBlockConfiguration"}),
    "s3:PutBucketVersioning": frozenset({"Bucket", "VersioningConfiguration"}),
    "s3:PutBucketEncryption": frozenset({"Bucket", "ServerSideEncryptionConfiguration"}),
    "s3:PutBucketPolicy": frozenset({"Bucket", "Policy"}),
    "s3:PutBucketTagging": frozenset({"Bucket", "Tagging"}),
    "signer:PutSigningProfile": frozenset(
        {"platformId", "profileName", "signatureValidityPeriod", "tags"}
    ),
    "lambda:CreateCodeSigningConfig": frozenset(
        {"AllowedPublishers", "CodeSigningPolicies", "Description", "Tags"}
    ),
    "s3:PutObject": frozenset(
        {"BodySha256", "Bucket", "ChecksumAlgorithm", "ChecksumSHA256", "ContentLength", "ContentType", "Key", "ServerSideEncryption", "SSEKMSKeyId", "Tagging"}
    ),
    "signer:StartSigningJob": frozenset(
        {"clientRequestToken", "destination", "profileName", "profileOwner", "source"}
    ),
}

PHASE_READBACK_ACTIONS: dict[str, tuple[str, ...]] = {
    "IDENTITY_CENTER_FOUNDATION": (
        "sso:DescribeApplication", "sso:DescribePermissionSet",
        "sso:GetApplicationAssignmentConfiguration", "sso:GetInlinePolicyForPermissionSet",
        "sso:ListAccountAssignments", "sso:ListApplicationAssignments",
        "sso:ListPermissionSetsProvisionedToAccount",
    ),
    "KMS_FOUNDATION": ("kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListAliases", "kms:ListResourceTags"),
    "S3_ARTIFACT_FOUNDATION": (
        "s3:GetBucketEncryption", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicy",
        "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetPublicAccessBlock", "s3:HeadBucket",
    ),
    "SIGNER_PROFILE_FOUNDATION": ("signer:GetSigningProfile", "signer:ListProfilePermissions", "signer:ListTagsForResource"),
    "LAMBDA_CSC_FOUNDATION": ("lambda:GetCodeSigningConfig", "lambda:ListTags"),
    "BROKER_UNSIGNED_PUBLISH": ("s3:GetObjectAttributes", "s3:GetObjectTagging", "s3:HeadObject"),
    "BROKER_SIGNING_JOB": ("signer:DescribeSigningJob", "s3:GetObjectAttributes", "s3:HeadObject"),
    "LEDGER_FACTORY_UNSIGNED_PUBLISH": ("s3:GetObjectAttributes", "s3:GetObjectTagging", "s3:HeadObject"),
    "LEDGER_FACTORY_SIGNING_JOB": ("signer:DescribeSigningJob", "s3:GetObjectAttributes", "s3:HeadObject"),
}

# AWS SDK operation names do not always equal IAM action names.  Keep the
# request contract expressed in SDK terms and compile authority from this
# explicit, closed mapping.  In particular, S3 Head* operations authorize the
# corresponding Get/List action and bucket Public Access Block has Bucket in
# the IAM action name.
IAM_ACTIONS_BY_API_ACTION: dict[str, tuple[str, ...]] = {
    "s3:PutPublicAccessBlock": ("s3:PutBucketPublicAccessBlock",),
    "s3:GetPublicAccessBlock": ("s3:GetBucketPublicAccessBlock",),
    "s3:HeadBucket": ("s3:ListBucket",),
    "s3:HeadObject": ("s3:GetObject", "kms:Decrypt"),
    "s3:GetObjectAttributes": ("s3:GetObject", "kms:Decrypt"),
}


def iam_actions_for_api_action(action: str) -> tuple[str, ...]:
    if not isinstance(action, str) or not action:
        _fail("IAM_ACTION_MAPPING_INVALID")
    return IAM_ACTIONS_BY_API_ACTION.get(action, (action,))

# AWS create APIs whose target ARN does not exist when their IAM decision is
# evaluated.  Only these may use Resource "*", and only with the GUG-376
# request-tag/region/time controls recorded in the phase policy contract.
CREATE_ACTIONS_REQUIRING_STAR_RESOURCE = frozenset(
    {
        "sso:CreateApplication",
        "sso:CreatePermissionSet",
        "kms:CreateKey",
        "signer:PutSigningProfile",
        "lambda:CreateCodeSigningConfig",
    }
)

RESOURCE_NAMES = (
    "artifact_bucket",
    "kms_key",
    "signing_profile",
    "code_signing_config",
    "identity_center_application",
    "classifier_permission_set",
    "approver_permission_set",
    "classifier_permission_set_role",
    "approver_permission_set_role",
    "broker_unsigned_object",
    "broker_signing_job",
    "broker_signed_object",
    "ledger_factory_unsigned_object",
    "ledger_factory_signing_job",
    "ledger_factory_signed_object",
)

RESOURCE_SURFACE = {
    "artifact_bucket": "s3",
    "kms_key": "kms",
    "signing_profile": "signer",
    "code_signing_config": "lambda_code_signing",
    "identity_center_application": "identity_center",
    "classifier_permission_set": "identity_center",
    "approver_permission_set": "identity_center",
    "classifier_permission_set_role": "iam_roles",
    "approver_permission_set_role": "iam_roles",
    "broker_unsigned_object": "artifact_objects",
    "broker_signing_job": "signer",
    "broker_signed_object": "artifact_objects",
    "ledger_factory_unsigned_object": "artifact_objects",
    "ledger_factory_signing_job": "signer",
    "ledger_factory_signed_object": "artifact_objects",
}

PHASE_INVENTORY_RESOURCES: dict[str, tuple[str, ...]] = {
    "IDENTITY_CENTER_FOUNDATION": (
        "identity_center_application", "classifier_permission_set",
        "approver_permission_set", "classifier_permission_set_role",
        "approver_permission_set_role",
    ),
    "KMS_FOUNDATION": ("kms_key",),
    "S3_ARTIFACT_FOUNDATION": ("artifact_bucket",),
    "SIGNER_PROFILE_FOUNDATION": ("signing_profile",),
    "LAMBDA_CSC_FOUNDATION": ("code_signing_config",),
    "BROKER_UNSIGNED_PUBLISH": ("broker_unsigned_object",),
    "BROKER_SIGNING_JOB": ("broker_signing_job", "broker_signed_object"),
    "LEDGER_FACTORY_UNSIGNED_PUBLISH": ("ledger_factory_unsigned_object",),
    "LEDGER_FACTORY_SIGNING_JOB": (
        "ledger_factory_signing_job", "ledger_factory_signed_object",
    ),
}

# An operation is authorized against one exact inventory resource, not merely
# any target that happens to share its phase.  Actions with repeated instances
# (the two permission sets and their provisioned roles) retain a reviewed set
# of possible resources; the concrete operation still names exactly one.
ACTION_INVENTORY_RESOURCES: dict[str, dict[str, tuple[str, ...]]] = {
    "IDENTITY_CENTER_FOUNDATION": {
        "sso:CreateApplication": ("identity_center_application",),
        "sso:PutApplicationAuthenticationMethod": ("identity_center_application",),
        "sso:PutApplicationGrant": ("identity_center_application",),
        "sso:PutApplicationAccessScope": ("identity_center_application",),
        "sso:PutApplicationAssignmentConfiguration": ("identity_center_application",),
        "sso:CreateApplicationAssignment": ("identity_center_application",),
        "sso:CreatePermissionSet": (
            "classifier_permission_set", "approver_permission_set",
        ),
        "sso:PutInlinePolicyToPermissionSet": (
            "classifier_permission_set", "approver_permission_set",
        ),
        "sso:CreateAccountAssignment": (
            "classifier_permission_set_role", "approver_permission_set_role",
        ),
        "sso:ProvisionPermissionSet": (
            "classifier_permission_set_role", "approver_permission_set_role",
        ),
    },
    "KMS_FOUNDATION": {
        action: ("kms_key",) for action in REQUIRED_ACTIONS["KMS_FOUNDATION"]
    },
    "S3_ARTIFACT_FOUNDATION": {
        action: ("artifact_bucket",)
        for action in REQUIRED_ACTIONS["S3_ARTIFACT_FOUNDATION"]
    },
    "SIGNER_PROFILE_FOUNDATION": {
        "signer:PutSigningProfile": ("signing_profile",),
    },
    "LAMBDA_CSC_FOUNDATION": {
        "lambda:CreateCodeSigningConfig": ("code_signing_config",),
    },
    "BROKER_UNSIGNED_PUBLISH": {
        "s3:PutObject": ("broker_unsigned_object",),
    },
    "BROKER_SIGNING_JOB": {
        "signer:StartSigningJob": ("broker_signing_job",),
    },
    "LEDGER_FACTORY_UNSIGNED_PUBLISH": {
        "s3:PutObject": ("ledger_factory_unsigned_object",),
    },
    "LEDGER_FACTORY_SIGNING_JOB": {
        "signer:StartSigningJob": ("ledger_factory_signing_job",),
    },
}

# Provider-generated values may flow only through these reviewed routes.  Each
# value must be projected independently from the normalized write response and
# the normalized provider readback.  Additional slots require a source review
# and a code change; callers cannot invent routes at runtime.
PROVIDER_SLOT_ROUTES: dict[str, dict[str, Any]] = {
    "IDENTITY_CENTER_APPLICATION_ARN": {
        "producer_phase": "IDENTITY_CENTER_FOUNDATION",
        "producer_action": "sso:CreateApplication",
        "producer_inventory_resource": "identity_center_application",
        "write_response_path": "/ApplicationArn",
        "readback_path": "/ApplicationArn",
        "value_pattern": (
            r"^arn:aws:sso::[0-9]{12}:application/"
            r"ssoins-[A-Za-z0-9.-]{16}/apl-[A-Za-z0-9]{16}$"
        ),
        "consumers": {
            ("IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationAuthenticationMethod"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationGrant"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationAccessScope"),
            (
                "IDENTITY_CENTER_FOUNDATION",
                "sso:PutApplicationAssignmentConfiguration",
            ),
            ("IDENTITY_CENTER_FOUNDATION", "sso:CreateApplicationAssignment"),
            (
                "IDENTITY_CENTER_FOUNDATION",
                "sso:PutInlinePolicyToPermissionSet",
            ),
        },
        "consumer_inventory_resources": {
            "identity_center_application",
            "classifier_permission_set",
            "approver_permission_set",
        },
    },
    "CLASSIFIER_PERMISSION_SET_ARN": {
        "producer_phase": "IDENTITY_CENTER_FOUNDATION",
        "producer_action": "sso:CreatePermissionSet",
        "producer_inventory_resource": "classifier_permission_set",
        "write_response_path": "/PermissionSet/PermissionSetArn",
        "readback_path": "/PermissionSet/PermissionSetArn",
        "value_pattern": (
            r"^arn:aws:sso:::permissionSet/"
            r"ssoins-[A-Za-z0-9.-]{16}/ps-[A-Za-z0-9./-]{16}$"
        ),
        "consumers": {
            ("IDENTITY_CENTER_FOUNDATION", "sso:PutInlinePolicyToPermissionSet"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:CreateAccountAssignment"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:ProvisionPermissionSet"),
        },
        "consumer_inventory_resources": {
            "classifier_permission_set",
            "classifier_permission_set_role",
        },
    },
    "APPROVER_PERMISSION_SET_ARN": {
        "producer_phase": "IDENTITY_CENTER_FOUNDATION",
        "producer_action": "sso:CreatePermissionSet",
        "producer_inventory_resource": "approver_permission_set",
        "write_response_path": "/PermissionSet/PermissionSetArn",
        "readback_path": "/PermissionSet/PermissionSetArn",
        "value_pattern": (
            r"^arn:aws:sso:::permissionSet/"
            r"ssoins-[A-Za-z0-9.-]{16}/ps-[A-Za-z0-9./-]{16}$"
        ),
        "consumers": {
            ("IDENTITY_CENTER_FOUNDATION", "sso:PutInlinePolicyToPermissionSet"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:CreateAccountAssignment"),
            ("IDENTITY_CENTER_FOUNDATION", "sso:ProvisionPermissionSet"),
        },
        "consumer_inventory_resources": {
            "approver_permission_set",
            "approver_permission_set_role",
        },
    },
    "KMS_KEY_ID": {
        "producer_phase": "KMS_FOUNDATION",
        "producer_action": "kms:CreateKey",
        "write_response_path": "/KeyMetadata/KeyId",
        "readback_path": "/KeyMetadata/KeyId",
        "value_pattern": r"^[A-Za-z0-9:/_-]{8,2048}$",
        "consumers": {
            ("KMS_FOUNDATION", "kms:EnableKeyRotation"),
            ("KMS_FOUNDATION", "kms:CreateAlias"),
        },
    },
    "KMS_KEY_ARN": {
        "producer_phase": "KMS_FOUNDATION",
        "producer_action": "kms:CreateKey",
        "write_response_path": "/KeyMetadata/Arn",
        "readback_path": "/KeyMetadata/Arn",
        "value_pattern": r"^arn:aws:kms:us-east-1:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$",
        "consumers": {
            ("KMS_FOUNDATION", "kms:EnableKeyRotation"),
            ("KMS_FOUNDATION", "kms:CreateAlias"),
            ("S3_ARTIFACT_FOUNDATION", "s3:PutBucketEncryption"),
            ("BROKER_UNSIGNED_PUBLISH", "s3:PutObject"),
            ("LEDGER_FACTORY_UNSIGNED_PUBLISH", "s3:PutObject"),
        },
    },
    "SIGNING_PROFILE_VERSION_ARN": {
        "producer_phase": "SIGNER_PROFILE_FOUNDATION",
        "producer_action": "signer:PutSigningProfile",
        "write_response_path": "/arn",
        "readback_path": "/arn",
        "value_pattern": r"^arn:aws:signer:us-east-1:[0-9]{12}:/signing-profiles/[A-Za-z0-9_]{2,64}/[A-Za-z0-9]{10}$",
        "consumers": {
            ("LAMBDA_CSC_FOUNDATION", "lambda:CreateCodeSigningConfig"),
        },
    },
    "BROKER_UNSIGNED_VERSION_ID": {
        "producer_phase": "BROKER_UNSIGNED_PUBLISH",
        "producer_action": "s3:PutObject",
        "write_response_path": "/VersionId",
        "readback_path": "/VersionId",
        "value_pattern": r"^[A-Za-z0-9._-]{1,1024}$",
        "consumers": {
            ("BROKER_SIGNING_JOB", "signer:StartSigningJob"),
        },
    },
    "LEDGER_FACTORY_UNSIGNED_VERSION_ID": {
        "producer_phase": "LEDGER_FACTORY_UNSIGNED_PUBLISH",
        "producer_action": "s3:PutObject",
        "write_response_path": "/VersionId",
        "readback_path": "/VersionId",
        "value_pattern": r"^[A-Za-z0-9._-]{1,1024}$",
        "consumers": {
            ("LEDGER_FACTORY_SIGNING_JOB", "signer:StartSigningJob"),
        },
    },
}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_DECISION_KEY = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_ACTION = re.compile(r"^[a-z0-9-]+:[A-Z][A-Za-z0-9]+$")
_AWS_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_KMS_KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:(?P<account_id>[0-9]{12}):"
    r"key/[A-Za-z0-9-]{8,128}$"
)
_IDENTITY_CENTER_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/(?P<instance_id>ssoins-[A-Za-z0-9.-]{16})$"
)
_IDENTITY_CENTER_APPLICATION_ARN = re.compile(
    r"^arn:aws:sso::(?P<account_id>[0-9]{12}):application/"
    r"(?P<instance_id>ssoins-[A-Za-z0-9.-]{16})/apl-[A-Za-z0-9]{16}$"
)
_IDENTITY_CENTER_PERMISSION_SET_ARN = re.compile(
    r"^arn:aws:sso:::permissionSet/"
    r"(?P<instance_id>ssoins-[A-Za-z0-9.-]{16})/ps-[A-Za-z0-9./-]{16}$"
)
_IDENTITY_STORE_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
    r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"
)
_IDENTITY_CENTER_APPLICATION_PROVIDER_ARN = re.compile(
    r"^arn:aws:sso::aws:applicationProvider/[A-Za-z0-9/-]+$"
)

# Owner-selected inputs consumed by an operation are deliberately reviewed in
# code.  Adding a new mutable name or principal requires extending this map;
# callers cannot attach an arbitrary digest and call it approved.
OWNER_REQUEST_VALUE_BINDINGS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "sso:CreateApplication": (
        ("identity_center_application_provider_arn", ("ApplicationProviderArn",)),
        ("identity_center_instance_arn", ("InstanceArn",)),
        ("identity_center_application_name", ("Name",)),
    ),
    "sso:CreateApplicationAssignment": (
        ("identity_store_user_id", ("PrincipalId",)),
    ),
    "sso:CreatePermissionSet": (
        ("identity_center_instance_arn", ("InstanceArn",)),
    ),
    "sso:PutInlinePolicyToPermissionSet": (
        ("identity_center_instance_arn", ("InstanceArn",)),
    ),
    "sso:CreateAccountAssignment": (
        ("identity_center_instance_arn", ("InstanceArn",)),
        ("identity_store_user_id", ("PrincipalId",)),
        ("authority_target_id", ("TargetId",)),
    ),
    "sso:ProvisionPermissionSet": (
        ("identity_center_instance_arn", ("InstanceArn",)),
        ("authority_target_id", ("TargetId",)),
    ),
    "kms:CreateAlias": (("kms_alias_name", ("AliasName",)),),
    "s3:CreateBucket": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutBucketOwnershipControls": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutPublicAccessBlock": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutBucketVersioning": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutBucketEncryption": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutBucketPolicy": (("artifact_bucket_name", ("Bucket",)),),
    "s3:PutBucketTagging": (("artifact_bucket_name", ("Bucket",)),),
    "signer:PutSigningProfile": (("signing_profile_name", ("profileName",)),),
}

KMS_KEY_POLICY_ALLOWED_ACTIONS = frozenset(
    {
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
    }
)

# This is only a rejection boundary for repository simulation.  Current main
# does not yet contain the exact reviewed bucket policy, so even this narrow
# set cannot be promoted into public operation or authority builders.
S3_BUCKET_POLICY_ALLOWED_ACTIONS = frozenset(
    {
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "s3:GetObjectTagging",
        "s3:PutObject",
        "s3:PutObjectTagging",
    }
)


class UpstreamPrerequisiteError(ValueError):
    """Stable public error containing no provider-controlled value."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "UPSTREAM_CONTRACT_INVALID"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise UpstreamPrerequisiteError(code)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("VALUE_NOT_CANONICAL")
    raise AssertionError("unreachable")


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _snapshot(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(code)
    raise AssertionError("unreachable")


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _timestamp(value: datetime, code: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)
    if result.tzinfo is None:
        _fail(code)
    return result.astimezone(UTC)


def _record_digest(record: Mapping[str, Any], field: str) -> str:
    return canonical_digest({key: value for key, value in record.items() if key != field})


def _verify_record_digest(record: Mapping[str, Any], field: str, code: str) -> None:
    if record.get(field) != _record_digest(record, field):
        _fail(code)


def _require_keys(record: Mapping[str, Any], keys: set[str], code: str) -> None:
    if not isinstance(record, Mapping) or set(record) != keys:
        _fail(code)


def _base(*, deployment_authorized: bool) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "deployment_authorized": deployment_authorized,
    }


def _validate_source(record: Mapping[str, Any], code: str) -> None:
    if (
        record.get("source_head_sha") != SOURCE_HEAD_SHA
        or record.get("source_merge_sha") != SOURCE_MERGE_SHA
        or record.get("source_tree_sha") != SOURCE_TREE_SHA
    ):
        _fail(code)


def _build_repository_execution_trust_anchor(
    *,
    owner_identity_binding_digest: str,
    owner_authorization_verifier_identity_digest: str,
    executor_session_verifier_identity_digest: str,
    executor_session_attestation_root_digest: str,
    ledger_store_identity_digest: str,
    private_ledger_root_digest: str,
) -> dict[str, Any]:
    """Seal external trust roots without providing a permissive implementation."""

    for value in (
        owner_identity_binding_digest,
        owner_authorization_verifier_identity_digest,
        executor_session_verifier_identity_digest,
        executor_session_attestation_root_digest,
        ledger_store_identity_digest,
        private_ledger_root_digest,
    ):
        _digest(value, "EXECUTION_TRUST_ANCHOR_DIGEST_INVALID")
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_execution_trust_anchor.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "owner": "Cesar_Guzman",
        "owner_identity_binding_digest": owner_identity_binding_digest,
        "owner_authorization_verifier_identity_digest": (
            owner_authorization_verifier_identity_digest
        ),
        "executor_session_verifier_identity_digest": (
            executor_session_verifier_identity_digest
        ),
        "executor_session_attestation_root_digest": (
            executor_session_attestation_root_digest
        ),
        "ledger_store_identity_digest": ledger_store_identity_digest,
        "private_ledger_root_digest": private_ledger_root_digest,
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
    }
    record["execution_trust_anchor_digest"] = canonical_digest(record)
    _validate_repository_execution_trust_anchor(record)
    return record


def _validate_repository_execution_trust_anchor(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "owner",
        "owner_identity_binding_digest",
        "owner_authorization_verifier_identity_digest",
        "executor_session_verifier_identity_digest",
        "executor_session_attestation_root_digest", "ledger_store_identity_digest",
        "private_ledger_root_digest", "source_head_sha", "source_merge_sha",
        "source_tree_sha", "execution_trust_anchor_digest",
    }
    _require_keys(record, keys, "EXECUTION_TRUST_ANCHOR_FIELDS_INVALID")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_execution_trust_anchor.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("owner") != "Cesar_Guzman"
    ):
        _fail("EXECUTION_TRUST_ANCHOR_INVALID")
    _validate_source(record, "EXECUTION_TRUST_ANCHOR_SOURCE_INVALID")
    for field in (
        "owner_identity_binding_digest",
        "owner_authorization_verifier_identity_digest",
        "executor_session_verifier_identity_digest",
        "executor_session_attestation_root_digest", "ledger_store_identity_digest",
        "private_ledger_root_digest",
    ):
        _digest(record.get(field), "EXECUTION_TRUST_ANCHOR_DIGEST_INVALID")
    _verify_record_digest(
        record,
        "execution_trust_anchor_digest",
        "EXECUTION_TRUST_ANCHOR_DIGEST_MISMATCH",
    )


def _validate_repository_provider_transcript_verification(
    record: Mapping[str, Any]
) -> None:
    """Validate a repository-only synthetic transcript binding.

    The record contains no provider payload or projected value.  Its digest
    fields exercise causal state-machine checks in tests; they do not
    authenticate an owner, provider or external verifier.  This public
    validator deliberately rejects every non-synthetic origin.
    """

    keys = {
        "record_type", "schema_version", "implementation_issue", "environment",
        "production", "production_status", "stage", "evidence_origin",
        "verifier_identity_digest", "attestation_root_digest",
        "session_identifier_digest", "account_or_management_binding_digest",
        "caller_identity_digest", "region", "phase", "authorization_digest",
        "operation_sequence", "operation_action", "request_digest",
        "provider_result_digest", "observed_readback_digest",
        "raw_provider_digest", "sts_call_receipt_digest",
        "sts_was_first_signed_call", "effective_authority_readback_digest",
        "projections", "verified_at", "external_attestation_receipt_digest",
        "verification_digest",
    }
    _require_keys(record, keys, "PROVIDER_TRANSCRIPT_VERIFICATION_FIELDS_INVALID")
    stage = record.get("stage")
    origin = record.get("evidence_origin")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_provider_transcript_verification.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or stage not in {"INVENTORY", "PREFLIGHT", "OPERATION"}
        or origin != "SYNTHETIC_TEST"
        or record.get("region") != REGION
        or record.get("sts_was_first_signed_call") is not True
    ):
        _fail("PROVIDER_TRANSCRIPT_VERIFICATION_INVALID")
    for field in (
        "verifier_identity_digest", "attestation_root_digest",
        "session_identifier_digest", "account_or_management_binding_digest",
        "caller_identity_digest", "sts_call_receipt_digest",
        "effective_authority_readback_digest", "external_attestation_receipt_digest",
    ):
        _digest(record.get(field), "PROVIDER_TRANSCRIPT_VERIFICATION_DIGEST_INVALID")
    nullable_digests = (
        "authorization_digest", "request_digest", "provider_result_digest",
        "observed_readback_digest", "raw_provider_digest",
    )
    for field in nullable_digests:
        if record.get(field) is not None:
            _digest(record[field], "PROVIDER_TRANSCRIPT_VERIFICATION_DIGEST_INVALID")
    projections = record.get("projections")
    if not isinstance(projections, list):
        _fail("PROVIDER_TRANSCRIPT_PROJECTIONS_INVALID")
    seen_projections: set[tuple[str, str, str]] = set()
    for projection in projections:
        if not isinstance(projection, Mapping) or set(projection) != {
            "slot", "source", "field_path", "value_digest", "projection_digest"
        }:
            _fail("PROVIDER_TRANSCRIPT_PROJECTION_FIELDS_INVALID")
        slot = projection.get("slot")
        source = projection.get("source")
        field_path = projection.get("field_path")
        if (
            not isinstance(slot, str)
            or _TOKEN.fullmatch(slot) is None
            or source not in {"WRITE_RESPONSE", "READBACK"}
            or not isinstance(field_path, str)
            or not field_path.startswith("/")
            or "//" in field_path
        ):
            _fail("PROVIDER_TRANSCRIPT_PROJECTION_INVALID")
        _digest(projection.get("value_digest"), "PROVIDER_TRANSCRIPT_PROJECTION_DIGEST_INVALID")
        identity = (slot, source, field_path)
        if identity in seen_projections:
            _fail("PROVIDER_TRANSCRIPT_PROJECTION_DUPLICATE")
        seen_projections.add(identity)
        _verify_record_digest(
            projection,
            "projection_digest",
            "PROVIDER_TRANSCRIPT_PROJECTION_DIGEST_MISMATCH",
        )
    phase = record.get("phase")
    operation_sequence = record.get("operation_sequence")
    operation_action = record.get("operation_action")
    if stage == "INVENTORY":
        if any(
            record.get(field) is not None
            for field in (
                "phase", "authorization_digest", "operation_sequence",
                "operation_action", "request_digest", "provider_result_digest",
                "observed_readback_digest",
            )
        ) or record.get("raw_provider_digest") is None or projections:
            _fail("PROVIDER_TRANSCRIPT_INVENTORY_INVALID")
    elif stage == "PREFLIGHT":
        if (
            phase not in PHASE_NAMES
            or record.get("authorization_digest") is None
            or any(
                record.get(field) is not None
                for field in (
                    "operation_sequence", "operation_action", "request_digest",
                    "provider_result_digest", "observed_readback_digest",
                    "raw_provider_digest",
                )
            )
            or projections
        ):
            _fail("PROVIDER_TRANSCRIPT_PREFLIGHT_INVALID")
    else:
        if (
            phase not in PHASE_NAMES
            or record.get("authorization_digest") is None
            or not isinstance(operation_sequence, int)
            or isinstance(operation_sequence, bool)
            or operation_sequence < 1
            or not isinstance(operation_action, str)
            or operation_action not in REQUIRED_ACTIONS[phase]
            or any(
                record.get(field) is None
                for field in (
                    "request_digest", "provider_result_digest",
                    "observed_readback_digest",
                )
            )
            or record.get("raw_provider_digest") is not None
        ):
            _fail("PROVIDER_TRANSCRIPT_OPERATION_INVALID")
    _parse_timestamp(record.get("verified_at"), "PROVIDER_TRANSCRIPT_TIME_INVALID")
    _verify_record_digest(
        record,
        "verification_digest",
        "PROVIDER_TRANSCRIPT_VERIFICATION_DIGEST_MISMATCH",
    )


def _build_repository_owner_decisions(
    *,
    upstream_run_digest: str,
    private_root_digest: str,
    decisions: Sequence[Mapping[str, Any]],
    collision_proof_digest: str,
    created_at: datetime,
) -> dict[str, Any]:
    """Seal owner-selected values and collision proofs without AWS authority."""

    _digest(upstream_run_digest, "OWNER_RUN_DIGEST_INVALID")
    _digest(private_root_digest, "OWNER_PRIVATE_ROOT_DIGEST_INVALID")
    _digest(collision_proof_digest, "OWNER_COLLISION_DIGEST_INVALID")
    if not 1 <= len(decisions) <= 16:
        _fail("OWNER_DECISION_COUNT_INVALID")
    compiled: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in decisions:
        required = {
            "inventory_resource",
            "key",
            "value",
            "constraints",
            "collision_proof_digest",
            "impact",
            "rollback_boundary",
        }
        _require_keys(raw, required, "OWNER_DECISION_FIELDS_INVALID")
        inventory_resource = raw.get("inventory_resource")
        key = raw.get("key")
        constraints = raw.get("constraints")
        if (
            inventory_resource not in RESOURCE_NAMES
            or not isinstance(key, str)
            or _DECISION_KEY.fullmatch(key) is None
            or key in seen
            or not isinstance(raw.get("value"), str)
            or not raw["value"]
            or len(raw["value"]) > 2048
            or not isinstance(constraints, Sequence)
            or isinstance(constraints, (str, bytes))
            or not constraints
            or not all(isinstance(item, str) and item for item in constraints)
            or len(set(constraints)) != len(constraints)
            or not isinstance(raw.get("impact"), str)
            or not raw["impact"]
            or not isinstance(raw.get("rollback_boundary"), str)
            or not raw["rollback_boundary"]
        ):
            _fail("OWNER_DECISION_INVALID")
        _digest(raw["collision_proof_digest"], "OWNER_COLLISION_DIGEST_INVALID")
        seen.add(key)
        value_digest = canonical_digest(raw["value"])
        target_material = {
            "inventory_resource": inventory_resource,
            "key": key,
            "value_digest": value_digest,
            "constraints": list(constraints),
        }
        decision = {
            "inventory_resource": inventory_resource,
            "key": key,
            "value_digest": value_digest,
            "constraints": list(constraints),
            "classification": "ABSENT_READY",
            "target_digest": canonical_digest(target_material),
            "collision_proof_digest": raw["collision_proof_digest"],
            "no_touch_if_exact": True,
            "impact": raw["impact"],
            "rollback_boundary": raw["rollback_boundary"],
        }
        decision["decision_digest"] = canonical_digest(decision)
        compiled.append(decision)
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_owner_decisions.v1",
        **_base(deployment_authorized=False),
        "aws_calls_performed": 0,
        "aws_mutations": 0,
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "upstream_run_digest": upstream_run_digest,
        "private_root_digest": private_root_digest,
        "decisions": compiled,
        "decision_count": len(compiled),
        "collision_proof_digest": collision_proof_digest,
        "approval_status": "PENDING",
        "created_at": _timestamp(created_at, "OWNER_TIME_INVALID"),
    }
    record["owner_decisions_digest"] = canonical_digest(record)
    _validate_repository_owner_decisions(record)
    return record


def expected_owner_decisions_approval_digest(
    owner_decisions: Mapping[str, Any]
) -> str:
    """Return the parameters-only approval binding for one exact owner record.

    This digest is intentionally not an AWS-write authorization and is not
    evidence of a second human.  It prevents a caller from attaching an opaque
    approval digest to a different owner-decision record.
    """

    normalized = _snapshot(owner_decisions, "OWNER_DECISIONS_INVALID")
    _validate_repository_owner_decisions(normalized)
    return canonical_digest(
        {
            "approval_scope": "OWNER_SELECTED_PARAMETERS_ONLY",
            "owner_decisions_digest": normalized["owner_decisions_digest"],
            "private_root_digest": normalized["private_root_digest"],
            "aws_writes_authorized": False,
            "deployment_authorized": False,
        }
    )


def _validate_repository_owner_decisions(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "deployment_authorized",
        "aws_calls_performed", "aws_mutations", "source_head_sha", "source_merge_sha",
        "source_tree_sha", "upstream_run_digest", "private_root_digest", "decisions",
        "decision_count", "collision_proof_digest", "approval_status", "created_at",
        "owner_decisions_digest",
    }
    _require_keys(record, keys, "OWNER_DECISIONS_FIELDS_INVALID")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_owner_decisions.v1"
        or any(record.get(key) != value for key, value in _base(deployment_authorized=False).items())
        or record.get("aws_calls_performed") != 0
        or record.get("aws_mutations") != 0
        or record.get("approval_status") != "PENDING"
        or not isinstance(record.get("decisions"), list)
        or record.get("decision_count") != len(record["decisions"])
        or not 1 <= len(record["decisions"]) <= 16
    ):
        _fail("OWNER_DECISIONS_INVALID")
    _validate_source(record, "OWNER_SOURCE_INVALID")
    for field in ("upstream_run_digest", "private_root_digest", "collision_proof_digest"):
        _digest(record.get(field), "OWNER_DIGEST_INVALID")
    _parse_timestamp(record.get("created_at"), "OWNER_TIME_INVALID")
    seen: set[str] = set()
    for decision in record["decisions"]:
        if not isinstance(decision, Mapping):
            _fail("OWNER_DECISION_INVALID")
        decision_keys = {
            "inventory_resource", "key", "value_digest", "constraints",
            "classification", "target_digest",
            "collision_proof_digest", "no_touch_if_exact", "impact",
            "rollback_boundary", "decision_digest",
        }
        _require_keys(decision, decision_keys, "OWNER_DECISION_FIELDS_INVALID")
        key = decision.get("key")
        if (
            decision.get("inventory_resource") not in RESOURCE_NAMES
            or not isinstance(key, str)
            or _DECISION_KEY.fullmatch(key) is None
            or key in seen
            or not isinstance(decision.get("constraints"), list)
            or not decision["constraints"]
            or not all(
                isinstance(item, str) and item for item in decision["constraints"]
            )
            or len(set(decision["constraints"])) != len(decision["constraints"])
            or decision.get("classification") != "ABSENT_READY"
            or decision.get("no_touch_if_exact") is not True
            or not isinstance(decision.get("impact"), str)
            or not decision["impact"]
            or not isinstance(decision.get("rollback_boundary"), str)
            or not decision["rollback_boundary"]
        ):
            _fail("OWNER_DECISION_INVALID")
        seen.add(key)
        _digest(decision.get("value_digest"), "OWNER_DECISION_VALUE_DIGEST_INVALID")
        _digest(decision.get("target_digest"), "OWNER_DECISION_DIGEST_INVALID")
        _digest(decision.get("collision_proof_digest"), "OWNER_DECISION_DIGEST_INVALID")
        expected_target_digest = canonical_digest(
            {
                "inventory_resource": decision["inventory_resource"],
                "key": key,
                "value_digest": decision["value_digest"],
                "constraints": decision["constraints"],
            }
        )
        if decision["target_digest"] != expected_target_digest:
            _fail("OWNER_DECISION_TARGET_DIGEST_MISMATCH")
        if decision["collision_proof_digest"] != record["collision_proof_digest"]:
            _fail("OWNER_DECISION_COLLISION_PROOF_MISMATCH")
        _verify_record_digest(decision, "decision_digest", "OWNER_DECISION_DIGEST_MISMATCH")
    _verify_record_digest(record, "owner_decisions_digest", "OWNER_DECISIONS_DIGEST_MISMATCH")


def _owner_decisions_for_resource(
    owner_decisions: Mapping[str, Any], inventory_resource: str
) -> tuple[list[str], list[str]]:
    selected = [
        decision
        for decision in owner_decisions["decisions"]
        if decision["inventory_resource"] == inventory_resource
    ]
    return (
        sorted(decision["decision_digest"] for decision in selected),
        sorted(decision["target_digest"] for decision in selected),
    )


def build_inventory_target_contract(
    *,
    inventory_resource: str,
    source_contract_digest: str,
    owner_decisions: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a closed, digest-only target contract for one inventory resource."""

    if inventory_resource not in RESOURCE_NAMES:
        _fail("INVENTORY_TARGET_RESOURCE_INVALID")
    _digest(source_contract_digest, "INVENTORY_SOURCE_CONTRACT_DIGEST_INVALID")
    normalized_owner_decisions = _snapshot(
        owner_decisions, "OWNER_DECISIONS_INVALID"
    )
    _validate_repository_owner_decisions(normalized_owner_decisions)
    decision_digests, decision_target_digests = _owner_decisions_for_resource(
        normalized_owner_decisions, inventory_resource
    )
    target = {
        "inventory_resource": inventory_resource,
        "surface": RESOURCE_SURFACE[inventory_resource],
        "source_target_digest": source_contract_digest,
        "owner_decisions_digest": normalized_owner_decisions[
            "owner_decisions_digest"
        ],
        "owner_decision_digests": decision_digests,
        "owner_decision_target_digests": decision_target_digests,
    }
    target["target_digest"] = canonical_digest(target)
    _validate_inventory_target_contract(
        inventory_resource,
        target,
        owner_decisions=normalized_owner_decisions,
    )
    return target


def _validate_inventory_target_contract(
    name: str,
    target: Mapping[str, Any],
    *,
    owner_decisions_digest: str | None = None,
    owner_decisions: Mapping[str, Any] | None = None,
) -> None:
    keys = {
        "inventory_resource", "surface", "source_target_digest",
        "owner_decisions_digest", "owner_decision_digests",
        "owner_decision_target_digests", "target_digest",
    }
    _require_keys(target, keys, "INVENTORY_TARGET_CONTRACT_FIELDS_INVALID")
    decision_digests = target.get("owner_decision_digests")
    decision_target_digests = target.get("owner_decision_target_digests")
    if (
        name not in RESOURCE_NAMES
        or target.get("inventory_resource") != name
        or target.get("surface") != RESOURCE_SURFACE[name]
        or not isinstance(decision_digests, list)
        or decision_digests != sorted(set(decision_digests))
        or not isinstance(decision_target_digests, list)
        or decision_target_digests != sorted(set(decision_target_digests))
        or len(decision_digests) != len(decision_target_digests)
    ):
        _fail("INVENTORY_TARGET_CONTRACT_INVALID")
    for value in (
        target.get("source_target_digest"),
        target.get("owner_decisions_digest"),
        target.get("target_digest"),
        *decision_digests,
        *decision_target_digests,
    ):
        _digest(value, "INVENTORY_TARGET_CONTRACT_DIGEST_INVALID")
    if owner_decisions_digest is not None and (
        target["owner_decisions_digest"] != owner_decisions_digest
    ):
        _fail("INVENTORY_TARGET_OWNER_DECISIONS_MISMATCH")
    if target["target_digest"] != canonical_digest(
        {key: value for key, value in target.items() if key != "target_digest"}
    ):
        _fail("INVENTORY_TARGET_DIGEST_MISMATCH")
    if owner_decisions is not None:
        _validate_repository_owner_decisions(owner_decisions)
        expected_digests, expected_target_digests = _owner_decisions_for_resource(
            owner_decisions, name
        )
        if (
            target["owner_decisions_digest"]
            != owner_decisions["owner_decisions_digest"]
            or decision_digests != expected_digests
            or decision_target_digests != expected_target_digests
        ):
            _fail("INVENTORY_TARGET_OWNER_DECISION_BINDING_MISMATCH")


def _validate_resource(
    name: str,
    resource: Mapping[str, Any],
    *,
    owner_decisions_digest: str | None = None,
    owner_decisions: Mapping[str, Any] | None = None,
) -> None:
    keys = {
        "classification", "target_contract", "target_digest",
        "provider_fact_digest", "readback_complete", "pagination_complete",
        "access_denied", "ambiguous", "no_touch", "repair_permitted",
    }
    _require_keys(resource, keys, "INVENTORY_RESOURCE_FIELDS_INVALID")
    classification = resource.get("classification")
    allowed = {
        "ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "PREEXISTING_NO_TOUCH",
        "DRIFT_BLOCKED_NO_REPAIR", "UNCERTAIN_RECONCILE_ONLY", "NOT_AUTHORIZED",
    }
    if (
        classification not in allowed
        or resource.get("no_touch") is not True
        or resource.get("repair_permitted") is not False
    ):
        _fail("INVENTORY_RESOURCE_INVALID")
    target_contract = resource.get("target_contract")
    if not isinstance(target_contract, Mapping):
        _fail("INVENTORY_TARGET_CONTRACT_INVALID")
    _validate_inventory_target_contract(
        name,
        target_contract,
        owner_decisions_digest=owner_decisions_digest,
        owner_decisions=owner_decisions,
    )
    if resource.get("target_digest") != target_contract["target_digest"]:
        _fail("INVENTORY_RESOURCE_TARGET_DIGEST_MISMATCH")
    _digest(resource.get("provider_fact_digest"), "INVENTORY_FACT_DIGEST_INVALID")
    complete = classification in {
        "ABSENT_READY", "EXACT_PRESENT_NO_TOUCH", "PREEXISTING_NO_TOUCH",
        "DRIFT_BLOCKED_NO_REPAIR",
    }
    if complete and (
        resource.get("readback_complete") is not True
        or resource.get("pagination_complete") is not True
        or resource.get("access_denied") is not False
        or resource.get("ambiguous") is not False
    ):
        _fail("INVENTORY_RESOURCE_COMPLETENESS_INVALID")
    if classification == "NOT_AUTHORIZED" and (
        resource.get("readback_complete") is not False
        or resource.get("access_denied") is not True
        or resource.get("ambiguous") is not False
    ):
        _fail("INVENTORY_RESOURCE_AUTHORITY_INVALID")
    if classification == "UNCERTAIN_RECONCILE_ONLY" and (
        resource.get("readback_complete") is not False
        or resource.get("ambiguous") is not True
    ):
        _fail("INVENTORY_RESOURCE_AMBIGUITY_INVALID")
    if name not in RESOURCE_NAMES:
        _fail("INVENTORY_RESOURCE_NAME_INVALID")


def _validate_raw_runtime_evidence(evidence: Mapping[str, Any]) -> None:
    keys = {
        "runtime", "update_runtime_on", "runtime_version_arn",
        "runtime_version_arn_digest", "source_function_arn_digest",
        "source_function_version", "function_configuration_digest",
        "runtime_management_config_digest", "provider_backed", "readback_complete",
        "evidence_collected_at", "runtime_evidence_digest",
    }
    _require_keys(evidence, keys, "RUNTIME_EVIDENCE_FIELDS_INVALID")
    runtime_arn = evidence.get("runtime_version_arn")
    if (
        evidence.get("runtime") != "python3.12"
        or evidence.get("update_runtime_on") != "Manual"
        or not isinstance(runtime_arn, str)
        or re.fullmatch(r"arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}", runtime_arn)
        is None
        or evidence.get("provider_backed") is not True
        or evidence.get("readback_complete") is not True
        or not isinstance(evidence.get("source_function_version"), str)
        or re.fullmatch(r"[1-9][0-9]*", evidence["source_function_version"]) is None
    ):
        _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
    for field in (
        "runtime_version_arn_digest", "source_function_arn_digest",
        "function_configuration_digest", "runtime_management_config_digest",
    ):
        _digest(evidence.get(field), "RUNTIME_EVIDENCE_DIGEST_INVALID")
    if evidence["runtime_version_arn_digest"] != canonical_digest(runtime_arn):
        _fail("RUNTIME_ARN_DIGEST_MISMATCH")
    _parse_timestamp(evidence.get("evidence_collected_at"), "RUNTIME_TIME_INVALID")
    _verify_record_digest(evidence, "runtime_evidence_digest", "RUNTIME_EVIDENCE_DIGEST_MISMATCH")


def _repository_runtime_checkpoint() -> dict[str, Any]:
    """Return a public runtime requirement without pretending provider proof."""

    record = {
        "runtime": "python3.12",
        "update_runtime_on": "Manual",
        "runtime_version_arn": None,
        "runtime_version_arn_digest": None,
        "source_function_arn_digest": None,
        "source_function_version": None,
        "function_configuration_digest": None,
        "runtime_management_config_digest": None,
        "provider_backed": False,
        "readback_complete": False,
        "evidence_status": "NOT_PROVEN",
        "evidence_collected_at": None,
    }
    record["runtime_evidence_digest"] = canonical_digest(record)
    return record


def _validate_repository_runtime_checkpoint(evidence: Mapping[str, Any]) -> None:
    keys = {
        "runtime", "update_runtime_on", "runtime_version_arn",
        "runtime_version_arn_digest", "source_function_arn_digest",
        "source_function_version", "function_configuration_digest",
        "runtime_management_config_digest", "provider_backed", "readback_complete",
        "evidence_status", "evidence_collected_at", "runtime_evidence_digest",
    }
    _require_keys(evidence, keys, "RUNTIME_EVIDENCE_FIELDS_INVALID")
    if (
        evidence.get("runtime") != "python3.12"
        or evidence.get("update_runtime_on") != "Manual"
        or any(
            evidence.get(field) is not None
            for field in (
                "runtime_version_arn",
                "runtime_version_arn_digest",
                "source_function_arn_digest",
                "source_function_version",
                "function_configuration_digest",
                "runtime_management_config_digest",
                "evidence_collected_at",
            )
        )
        or evidence.get("provider_backed") is not False
        or evidence.get("readback_complete") is not False
        or evidence.get("evidence_status") != "NOT_PROVEN"
    ):
        _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
    _verify_record_digest(
        evidence,
        "runtime_evidence_digest",
        "RUNTIME_EVIDENCE_DIGEST_MISMATCH",
    )


def _build_repository_stable_inventory(
    *,
    upstream_run_digest: str,
    owner_decisions: Mapping[str, Any],
    account_binding_digest: str,
    caller_identity_digest: str,
    first_raw_provider_snapshot: Mapping[str, Any],
    second_raw_provider_snapshot: Mapping[str, Any],
    target_contracts: Mapping[str, Mapping[str, Any]],
    created_at: datetime,
) -> dict[str, Any]:
    """Project two independent raw provider sessions into the public inventory."""

    for value in (upstream_run_digest, account_binding_digest, caller_identity_digest):
        _digest(value, "INVENTORY_BINDING_DIGEST_INVALID")
    normalized_owner_decisions = _snapshot(
        owner_decisions, "OWNER_DECISIONS_INVALID"
    )
    _validate_repository_owner_decisions(normalized_owner_decisions)
    if normalized_owner_decisions["upstream_run_digest"] != upstream_run_digest:
        _fail("INVENTORY_OWNER_DECISIONS_CAUSAL_MISMATCH")
    owner_decisions_digest = normalized_owner_decisions["owner_decisions_digest"]
    first = _snapshot(first_raw_provider_snapshot, "INVENTORY_SNAPSHOT_INVALID")
    second = _snapshot(second_raw_provider_snapshot, "INVENTORY_SNAPSHOT_INVALID")
    try:
        from tooling.platform_authority_gug365_upstream_inventory import (
            UpstreamInventoryError,
            certify_raw_provider_sessions,
            validate_raw_provider_snapshot,
        )

        validate_raw_provider_snapshot(first)
        validate_raw_provider_snapshot(second)
        stability = certify_raw_provider_sessions(first, second)
    except UpstreamInventoryError:
        _fail("INVENTORY_RAW_PROVIDER_EVIDENCE_INVALID")
    if (
        first["account_binding_digest"] != account_binding_digest
        or second["account_binding_digest"] != account_binding_digest
        or first["caller_identity_digest"] != caller_identity_digest
        or second["caller_identity_digest"] != caller_identity_digest
    ):
        _fail("INVENTORY_RAW_PROVIDER_IDENTITY_MISMATCH")
    targets = _snapshot(target_contracts, "INVENTORY_TARGET_CONTRACTS_INVALID")
    if not isinstance(targets, Mapping) or set(targets) != set(RESOURCE_NAMES):
        _fail("INVENTORY_RESOURCE_SET_INVALID")
    resources: dict[str, Any] = {}
    for name in RESOURCE_NAMES:
        target = targets[name]
        if not isinstance(target, Mapping):
            _fail("INVENTORY_TARGET_CONTRACT_INVALID")
        _validate_inventory_target_contract(
            name,
            target,
            owner_decisions=normalized_owner_decisions,
        )
        surface = target.get("surface")
        target_digest = target.get("target_digest")
        raw_facts = first["resource_evidence"][surface]["resources"]
        observations = [
            fact
            for fact in raw_facts
            if isinstance(fact, Mapping) and fact.get("inventory_target") == name
        ]
        if len(observations) != 1:
            _fail("INVENTORY_TARGET_OBSERVATION_INVALID")
        observation = observations[0]
        observation_keys = {
            "inventory_target", "surface", "presence", "target_digest",
            "observed_contract_digest", "causal_provenance_digest",
            "causal_upstream_run_digest", "collision_count",
        }
        if (
            set(observation) != observation_keys
            or observation.get("surface") != surface
            or observation.get("target_digest") != target_digest
            or not isinstance(observation.get("collision_count"), int)
            or isinstance(observation.get("collision_count"), bool)
            or observation["collision_count"] < 0
        ):
            _fail("INVENTORY_TARGET_OBSERVATION_INVALID")
        presence = observation.get("presence")
        if presence == "ABSENT":
            if (
                observation["collision_count"] != 0
                or observation.get("observed_contract_digest") is not None
                or observation.get("causal_provenance_digest") is not None
                or observation.get("causal_upstream_run_digest") is not None
            ):
                _fail("INVENTORY_ABSENCE_PROOF_INVALID")
            classification = "ABSENT_READY"
        elif presence == "PRESENT":
            for field in (
                "observed_contract_digest", "causal_provenance_digest",
                "causal_upstream_run_digest",
            ):
                _digest(
                    observation.get(field),
                    "INVENTORY_PRESENT_PROVENANCE_INVALID",
                )
            if (
                observation["collision_count"] != 1
                or observation["observed_contract_digest"] != target_digest
                or observation["causal_upstream_run_digest"] != upstream_run_digest
            ):
                _fail("INVENTORY_PREEXISTING_OR_DRIFT_BLOCKED")
            classification = "EXACT_PRESENT_NO_TOUCH"
        else:
            _fail("INVENTORY_TARGET_PRESENCE_INVALID")
        resource = {
            "classification": classification,
            "target_contract": target,
            "target_digest": target_digest,
            "provider_fact_digest": canonical_digest(
                {
                    "surface": surface,
                    "stable_target_observation": observation,
                    "classification": classification,
                    "target_digest": target_digest,
                }
            ),
            "readback_complete": True,
            "pagination_complete": True,
            "access_denied": False,
            "ambiguous": False,
            "no_touch": True,
            "repair_permitted": False,
        }
        _validate_resource(
            name,
            resource,
            owner_decisions=normalized_owner_decisions,
        )
        resources[name] = resource
    normalized_runtime = first.get("runtime_evidence")
    if not isinstance(normalized_runtime, Mapping):
        _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
    _validate_raw_runtime_evidence(normalized_runtime)
    runtime_checkpoint = _repository_runtime_checkpoint()
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_inventory.v1",
        **_base(deployment_authorized=False),
        "aws_access_mode": "READ_ONLY",
        "aws_mutations": 0,
        "sts_was_first_signed_call": True,
        "session_source": "DIRECT_SSO_PERMISSION_SET",
        "session_chain_depth": 0,
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "upstream_run_digest": upstream_run_digest,
        "owner_decisions_digest": owner_decisions_digest,
        "account_binding_digest": account_binding_digest,
        "region": REGION,
        "caller_identity_digest": caller_identity_digest,
        "snapshot_count": 2,
        "first_snapshot_digest": first["raw_provider_digest"],
        "second_snapshot_digest": second["raw_provider_digest"],
        "snapshots_stable": True,
        "inventory_complete": False,
        "certification_eligible": False,
        "raw_provider_responses_persisted": False,
        "sensitive_values_persisted": False,
        "evidence_origin": "REPOSITORY_OBSERVED_UNATTESTED",
        "provider_transcript_verified": False,
        "provider_transcript_verification_digests": [],
        "provider_verifier_identity_digest": None,
        "provider_attestation_root_digest": None,
        "resources": resources,
        "runtime_evidence": runtime_checkpoint,
        "created_at": _timestamp(created_at, "INVENTORY_TIME_INVALID"),
    }
    record["inventory_digest"] = canonical_digest(record)
    _validate_repository_stable_inventory(record)
    if stability["stable"] is not True or stability["aws_mutations"] != 0:
        _fail("INVENTORY_NOT_STABLE")
    return record


def _validate_repository_stable_inventory(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "deployment_authorized",
        "aws_access_mode", "aws_mutations", "sts_was_first_signed_call",
        "session_source", "session_chain_depth", "source_head_sha", "source_merge_sha",
        "source_tree_sha", "upstream_run_digest", "owner_decisions_digest",
        "account_binding_digest", "region", "caller_identity_digest", "snapshot_count",
        "first_snapshot_digest", "second_snapshot_digest", "snapshots_stable",
        "inventory_complete", "certification_eligible", "raw_provider_responses_persisted",
        "sensitive_values_persisted", "evidence_origin",
        "provider_transcript_verified", "provider_transcript_verification_digests",
        "provider_verifier_identity_digest", "provider_attestation_root_digest",
        "resources", "runtime_evidence", "created_at", "inventory_digest",
    }
    _require_keys(record, keys, "INVENTORY_FIELDS_INVALID")
    if (
        record.get("record_type") != "scanalyze.platform_authority.gug365_upstream_inventory.v1"
        or any(record.get(key) != value for key, value in _base(deployment_authorized=False).items())
        or record.get("aws_access_mode") != "READ_ONLY"
        or record.get("aws_mutations") != 0
        or record.get("sts_was_first_signed_call") is not True
        or record.get("session_source") != "DIRECT_SSO_PERMISSION_SET"
        or record.get("session_chain_depth") != 0
        or record.get("region") != REGION
        or record.get("snapshot_count") != 2
        or record.get("snapshots_stable") is not True
        or record.get("inventory_complete") is not False
        or record.get("certification_eligible") is not False
        or record.get("raw_provider_responses_persisted") is not False
        or record.get("sensitive_values_persisted") is not False
    ):
        _fail("INVENTORY_INVALID")
    transcript_digests = record.get("provider_transcript_verification_digests")
    if (
        not isinstance(transcript_digests, list)
        or record.get("provider_transcript_verified") is not False
        or record.get("evidence_origin") != "REPOSITORY_OBSERVED_UNATTESTED"
        or transcript_digests
        or record.get("provider_verifier_identity_digest") is not None
        or record.get("provider_attestation_root_digest") is not None
    ):
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_INVALID")
    _validate_source(record, "INVENTORY_SOURCE_INVALID")
    for field in (
        "upstream_run_digest", "owner_decisions_digest", "account_binding_digest",
        "caller_identity_digest", "first_snapshot_digest", "second_snapshot_digest",
    ):
        _digest(record.get(field), "INVENTORY_DIGEST_INVALID")
    if record["first_snapshot_digest"] == record["second_snapshot_digest"]:
        _fail("INVENTORY_SESSIONS_NOT_INDEPENDENT")
    resources = record.get("resources")
    if not isinstance(resources, Mapping) or set(resources) != set(RESOURCE_NAMES):
        _fail("INVENTORY_RESOURCE_SET_INVALID")
    for name in RESOURCE_NAMES:
        _validate_resource(
            name,
            resources[name],
            owner_decisions_digest=record["owner_decisions_digest"],
        )
        if resources[name]["classification"] not in {
            "ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"
        }:
            _fail("INVENTORY_NOT_CERTIFICATION_ELIGIBLE")
    runtime = record.get("runtime_evidence")
    if not isinstance(runtime, Mapping):
        _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
    _validate_repository_runtime_checkpoint(runtime)
    _parse_timestamp(record.get("created_at"), "INVENTORY_TIME_INVALID")
    _verify_record_digest(record, "inventory_digest", "INVENTORY_DIGEST_MISMATCH")


def _slot_names(value: Any) -> set[str]:
    slots: set[str] = set()
    if isinstance(value, Mapping):
        if "$provider_slot" in value and set(value) != {"$provider_slot"}:
            _fail("PROVIDER_SLOT_INVALID")
        if set(value) == {"$provider_slot"}:
            slot = value["$provider_slot"]
            if not isinstance(slot, str) or _TOKEN.fullmatch(slot) is None:
                _fail("PROVIDER_SLOT_INVALID")
            slots.add(slot)
        else:
            for item in value.values():
                slots.update(_slot_names(item))
    elif isinstance(value, list):
        for item in value:
            slots.update(_slot_names(item))
    return slots


def _strict_json_object(value: object, code: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return _snapshot(value, code)
    if not isinstance(value, str):
        _fail(code)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail(code)
            result[key] = item
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=reject_duplicates)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(code)
    if not isinstance(decoded, Mapping):
        _fail(code)
    return decoded


def _string_list(value: object, code: str) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(item, str) and item for item in values)
    ):
        _fail(code)
    return list(values)


def _validate_policy_document(
    value: object,
    *,
    policy_kind: str,
    allowed_principal_digests: Sequence[str] = (),
) -> Mapping[str, Any]:
    """Reject additive, public, wildcard-action, and malformed policies.

    KMS key policies legitimately use ``Resource: *`` because the policy is
    attached to the key being created.  Public principals and wildcard Allow
    actions are never accepted.  Identity Center inline policies are narrower:
    every Allow resource must be an exact ARN and their action set is fixed by
    the already-reviewed GUG-215 invocation contract.
    """

    policy = _strict_json_object(value, "POLICY_DOCUMENT_INVALID")
    if set(policy) - {"Version", "Id", "Statement"} or policy.get("Version") != "2012-10-17":
        _fail("POLICY_DOCUMENT_INVALID")
    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        _fail("POLICY_DOCUMENT_INVALID")
    inline_allow_actions: set[str] = set()
    kms_allow_actions: set[str] = set()
    s3_allow_actions: set[str] = set()
    expected_principal_digests = sorted(set(allowed_principal_digests))
    for digest in expected_principal_digests:
        _digest(digest, "POLICY_ALLOWED_PRINCIPAL_DIGEST_INVALID")
    for statement in statements:
        if not isinstance(statement, Mapping) or set(statement) - {
            "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
            "Resource", "NotResource", "Condition",
        }:
            _fail("POLICY_STATEMENT_INVALID")
        effect = statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            _fail("POLICY_STATEMENT_INVALID")
        if effect == "Allow":
            if any(field in statement for field in ("NotAction", "NotPrincipal", "NotResource")):
                _fail("POLICY_ALLOW_NEGATION_FORBIDDEN")
            actions = _string_list(statement.get("Action"), "POLICY_ACTION_INVALID")
            if any("*" in action for action in actions):
                _fail("POLICY_WILDCARD_ACTION_FORBIDDEN")
            if policy_kind == "KMS_KEY":
                kms_allow_actions.update(actions)
            if policy_kind == "S3_BUCKET":
                s3_allow_actions.update(actions)
            principal = statement.get("Principal")
            if principal == "*" or (
                isinstance(principal, Mapping)
                and any(item == "*" or (isinstance(item, list) and "*" in item) for item in principal.values())
            ):
                _fail("POLICY_PUBLIC_PRINCIPAL_FORBIDDEN")
            if policy_kind in {"KMS_KEY", "S3_BUCKET"}:
                if not expected_principal_digests or principal is None:
                    _fail("POLICY_APPROVED_PRINCIPAL_REQUIRED")
                if isinstance(principal, Mapping):
                    if set(principal) != {"AWS"}:
                        _fail("POLICY_PRINCIPAL_KIND_INVALID")
                    principal_values = _string_list(
                        principal["AWS"], "POLICY_PRINCIPAL_INVALID"
                    )
                else:
                    principal_values = _string_list(
                        principal, "POLICY_PRINCIPAL_INVALID"
                    )
                if (
                    sorted(canonical_digest(item) for item in principal_values)
                    != expected_principal_digests
                ):
                    _fail("POLICY_PRINCIPAL_NOT_APPROVED")
            resources = _string_list(statement.get("Resource"), "POLICY_RESOURCE_INVALID")
            if policy_kind in {"IDENTITY_INLINE", "S3_BUCKET"} and any(
                resource == "*" or "*" in resource for resource in resources
            ):
                _fail("POLICY_WILDCARD_RESOURCE_FORBIDDEN")
            if policy_kind == "IDENTITY_INLINE":
                inline_allow_actions.update(actions)
    if policy_kind == "IDENTITY_INLINE" and inline_allow_actions != {
        "sso-oauth:CreateTokenWithIAM", "sts:AssumeRole", "sts:SetContext"
    }:
        _fail("IDENTITY_INLINE_POLICY_ACTION_SET_INVALID")
    if policy_kind == "KMS_KEY" and (
        not kms_allow_actions
        or not kms_allow_actions.issubset(KMS_KEY_POLICY_ALLOWED_ACTIONS)
    ):
        if kms_allow_actions & {"kms:Decrypt", "kms:GenerateDataKey"}:
            _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")
        _fail("KMS_KEY_POLICY_ACTION_SET_INVALID")
    if policy_kind == "S3_BUCKET" and (
        not s3_allow_actions
        or not s3_allow_actions.issubset(S3_BUCKET_POLICY_ALLOWED_ACTIONS)
    ):
        _fail("S3_BUCKET_POLICY_ACTION_SET_INVALID")
    return policy


def _validate_request_payload(
    phase: str,
    action: str,
    payload: Mapping[str, Any],
    *,
    allowed_principal_digests: Sequence[str] = (),
) -> None:
    expected_keys = REQUEST_KEYS.get(action)
    if expected_keys is None or set(payload) != set(expected_keys):
        _fail("REQUEST_CLOSED_WORLD_FIELDS_INVALID")
    if action == "kms:CreateKey" and (
        payload.get("BypassPolicyLockoutSafetyCheck") is not False
        or payload.get("KeySpec") != "SYMMETRIC_DEFAULT"
        or payload.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or payload.get("MultiRegion") is not False
        or payload.get("Origin") != "AWS_KMS"
        or not isinstance(payload.get("Policy"), (str, Mapping))
        or not isinstance(payload.get("Tags"), list)
        or not payload["Tags"]
    ):
        _fail("KMS_CREATE_KEY_REQUEST_INVALID")
    if action == "kms:CreateKey":
        _validate_policy_document(
            payload["Policy"],
            policy_kind="KMS_KEY",
            allowed_principal_digests=allowed_principal_digests,
        )
    if action == "kms:EnableKeyRotation" and payload.get("RotationPeriodInDays") != 365:
        _fail("KMS_ROTATION_REQUEST_INVALID")
    if action == "kms:CreateAlias" and (
        not isinstance(payload.get("AliasName"), str)
        or not payload["AliasName"].startswith("alias/scanalyze-")
    ):
        _fail("KMS_ALIAS_REQUEST_INVALID")
    if action == "s3:CreateBucket" and payload.get("ObjectOwnership") != "BucketOwnerEnforced":
        _fail("S3_BUCKET_OWNERSHIP_REQUEST_INVALID")
    if action == "s3:PutBucketOwnershipControls" and payload.get(
        "OwnershipControls"
    ) != {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}:
        _fail("S3_BUCKET_OWNERSHIP_REQUEST_INVALID")
    if action == "s3:PutPublicAccessBlock" and payload.get(
        "PublicAccessBlockConfiguration"
    ) != {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }:
        _fail("S3_PUBLIC_ACCESS_BLOCK_REQUEST_INVALID")
    if action == "s3:PutBucketVersioning" and payload.get(
        "VersioningConfiguration"
    ) != {"Status": "Enabled"}:
        _fail("S3_VERSIONING_REQUEST_INVALID")
    if action == "s3:PutBucketEncryption":
        configuration = payload.get("ServerSideEncryptionConfiguration")
        if (
            not isinstance(configuration, Mapping)
            or not isinstance(configuration.get("Rules"), list)
            or len(configuration["Rules"]) != 1
            or configuration["Rules"][0].get("BucketKeyEnabled") is not True
            or configuration["Rules"][0]
            .get("ApplyServerSideEncryptionByDefault", {})
            .get("SSEAlgorithm")
            != "aws:kms"
        ):
            _fail("S3_ENCRYPTION_REQUEST_INVALID")
    if action in {"s3:PutBucketPolicy", "s3:PutBucketTagging"} and not payload.get(
        "Policy" if action.endswith("Policy") else "Tagging"
    ):
        _fail("S3_CONFIGURATION_REQUEST_INVALID")
    if action == "s3:PutBucketPolicy":
        _validate_policy_document(
            payload["Policy"],
            policy_kind="S3_BUCKET",
            allowed_principal_digests=allowed_principal_digests,
        )
    if action == "signer:PutSigningProfile" and (
        payload.get("platformId") != "AWSLambda-SHA384-ECDSA"
        or not isinstance(payload.get("signatureValidityPeriod"), Mapping)
        or not isinstance(payload.get("tags"), Mapping)
        or not payload["tags"]
    ):
        _fail("SIGNER_PROFILE_REQUEST_INVALID")
    if action == "lambda:CreateCodeSigningConfig":
        publishers = payload.get("AllowedPublishers")
        policies = payload.get("CodeSigningPolicies")
        if (
            not isinstance(publishers, Mapping)
            or not isinstance(publishers.get("SigningProfileVersionArns"), list)
            or len(publishers["SigningProfileVersionArns"]) != 1
            or policies != {"UntrustedArtifactOnDeployment": "Enforce"}
            or not isinstance(payload.get("Tags"), Mapping)
            or not payload["Tags"]
        ):
            _fail("CODE_SIGNING_CONFIG_REQUEST_INVALID")
    if action == "s3:PutObject" and (
        payload.get("ChecksumAlgorithm") != "SHA256"
        or payload.get("ServerSideEncryption") != "aws:kms"
        or not isinstance(payload.get("BodySha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["BodySha256"]) is None
        or not isinstance(payload.get("ContentLength"), int)
        or isinstance(payload.get("ContentLength"), bool)
        or payload["ContentLength"] <= 0
    ):
        _fail("S3_PUT_OBJECT_REQUEST_INVALID")
    if action == "signer:StartSigningJob" and (
        not isinstance(payload.get("source"), Mapping)
        or not isinstance(payload.get("destination"), Mapping)
        or not isinstance(payload.get("clientRequestToken"), str)
        or not payload["clientRequestToken"]
    ):
        _fail("SIGNING_JOB_REQUEST_INVALID")
    if action == "signer:StartSigningJob":
        source = payload["source"].get("s3")
        destination = payload["destination"].get("s3")
        if (
            not isinstance(source, Mapping)
            or set(source) != {"bucketName", "key", "version"}
            or not isinstance(destination, Mapping)
            or set(destination) != {"bucketName", "prefix"}
            or source.get("bucketName") != destination.get("bucketName")
            or source.get("key") == destination.get("prefix")
            or not all(isinstance(source.get(key), str) and source[key] for key in source)
            or not all(isinstance(destination.get(key), str) and destination[key] for key in destination)
        ):
            _fail("SIGNING_JOB_TOPOLOGY_INVALID")
    if action == "sso:CreateApplication" and payload.get("Status") != "ENABLED":
        _fail("IDENTITY_APPLICATION_REQUEST_INVALID")
    if action == "sso:PutApplicationAssignmentConfiguration" and payload.get(
        "AssignmentRequired"
    ) is not True:
        _fail("IDENTITY_ASSIGNMENT_CONFIGURATION_INVALID")
    if action in {"sso:CreateApplicationAssignment", "sso:CreateAccountAssignment"} and payload.get(
        "PrincipalType"
    ) != "USER":
        _fail("IDENTITY_PRINCIPAL_TYPE_INVALID")
    if action in {"sso:CreateAccountAssignment", "sso:ProvisionPermissionSet"} and payload.get(
        "TargetType"
    ) != "AWS_ACCOUNT":
        _fail("IDENTITY_TARGET_TYPE_INVALID")
    if action == "sso:CreatePermissionSet" and (
        payload.get("Name")
        not in {"ScanalyzeAuthorityRetireClass", "ScanalyzeAuthorityRetireApprove"}
        or payload.get("SessionDuration") != "PT1H"
        or not isinstance(payload.get("Tags"), list)
        or not payload["Tags"]
    ):
        _fail("IDENTITY_PERMISSION_SET_REQUEST_INVALID")
    if action == "sso:PutInlinePolicyToPermissionSet":
        if not isinstance(payload.get("InlinePolicy"), Mapping):
            _fail("IDENTITY_INLINE_POLICY_SOURCE_CONTRACT_INVALID")
    if action == "sso:PutApplicationAccessScope" and payload.get("Scope") != "sts:identity_context":
        _fail("IDENTITY_ACCESS_SCOPE_INVALID")


def _validate_phase_request_set(
    phase: str,
    operations: Sequence[Mapping[str, Any]],
    templates: Sequence[Mapping[str, Any]],
) -> None:
    if len(operations) != len(templates):
        _fail("REQUEST_TEMPLATE_COUNT_INVALID")
    for operation, template in zip(operations, templates, strict=True):
        _validate_request_payload(
            phase,
            operation["action"],
            template,
            allowed_principal_digests=operation["approved_principal_digests"],
        )
    if phase == "IDENTITY_CENTER_FOUNDATION":
        expected_permission_names = {
            "classifier_permission_set": "ScanalyzeAuthorityRetireClass",
            "approver_permission_set": "ScanalyzeAuthorityRetireApprove",
        }
        for operation, template in zip(operations, templates, strict=True):
            if operation["action"] == "sso:CreatePermissionSet" and (
                template["Name"]
                != expected_permission_names.get(operation["inventory_resource"])
            ):
                _fail("IDENTITY_PERMISSION_SET_TARGET_SUBSTITUTION")
        permission_names = {
            template["Name"]
            for operation, template in zip(operations, templates, strict=True)
            if operation["action"] == "sso:CreatePermissionSet"
        }
        if permission_names != {
            "ScanalyzeAuthorityRetireClass",
            "ScanalyzeAuthorityRetireApprove",
        }:
            _fail("IDENTITY_PERMISSION_SET_SET_INVALID")
        principal_digests = {
            canonical_digest(template["PrincipalId"])
            for operation, template in zip(operations, templates, strict=True)
            if operation["action"]
            in {"sso:CreateApplicationAssignment", "sso:CreateAccountAssignment"}
        }
        if len(principal_digests) != 1:
            _fail("IDENTITY_SINGLE_OPERATOR_MISMATCH")
        instance_values = [
            template["InstanceArn"]
            for template in templates
            if "InstanceArn" in template
        ]
        target_values = [
            template["TargetId"] for template in templates if "TargetId" in template
        ]
        if not all(isinstance(value, str) for value in [*instance_values, *target_values]):
            _fail("IDENTITY_TOPOLOGY_TARGET_BINDING_INVALID")
        instance_arns = set(instance_values)
        target_ids = set(target_values)
        if (
            len(instance_arns) != 1
            or _IDENTITY_CENTER_INSTANCE_ARN.fullmatch(next(iter(instance_arns)))
            is None
            or len(target_ids) != 1
            or _AWS_ACCOUNT_ID.fullmatch(next(iter(target_ids))) is None
        ):
            _fail("IDENTITY_TOPOLOGY_TARGET_BINDING_INVALID")


def _validated_owner_decision_values(
    owner_decisions: Mapping[str, Any], values: Mapping[str, str]
) -> dict[str, str]:
    """Validate the transient plaintext for every sealed owner decision."""

    if not isinstance(values, Mapping):
        _fail("OPERATION_OWNER_DECISION_VALUES_INVALID")
    normalized = _snapshot(values, "OPERATION_OWNER_DECISION_VALUES_INVALID")
    decisions = {decision["key"]: decision for decision in owner_decisions["decisions"]}
    if set(normalized) != set(decisions) or not all(
        isinstance(value, str) and value for value in normalized.values()
    ):
        _fail("OPERATION_OWNER_DECISION_VALUES_INVALID")
    if any(
        canonical_digest(normalized[key]) != decision["value_digest"]
        for key, decision in decisions.items()
    ):
        _fail("OPERATION_OWNER_DECISION_VALUE_MISMATCH")
    return normalized


def _owner_value(values: Mapping[str, str], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        _fail("OPERATION_REQUIRED_OWNER_DECISION_MISSING")
    return value


def _request_path_value(payload: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = payload
    for part in path:
        if not isinstance(value, Mapping) or part not in value:
            _fail("OPERATION_OWNER_REQUEST_BINDING_INVALID")
        value = value[part]
    return value


def _validate_identity_owner_values(owner_values: Mapping[str, str]) -> None:
    instance_arn = _owner_value(owner_values, "identity_center_instance_arn")
    application_provider_arn = _owner_value(
        owner_values, "identity_center_application_provider_arn"
    )
    application_name = _owner_value(
        owner_values, "identity_center_application_name"
    )
    redirect_uri = _owner_value(owner_values, "identity_center_redirect_uri")
    user_id = _owner_value(owner_values, "identity_store_user_id")
    target_id = _owner_value(owner_values, "authority_target_id")
    authority_account_id = _owner_value(owner_values, "authority_account_id")
    classifier_name = _owner_value(
        owner_values, "classifier_permission_set_name"
    )
    approver_name = _owner_value(owner_values, "approver_permission_set_name")
    try:
        parsed_redirect = urlsplit(redirect_uri)
        redirect_port = parsed_redirect.port
    except ValueError:
        _fail("IDENTITY_OWNER_REDIRECT_URI_INVALID")
    if (
        _IDENTITY_CENTER_INSTANCE_ARN.fullmatch(instance_arn) is None
        or _IDENTITY_CENTER_APPLICATION_PROVIDER_ARN.fullmatch(
            application_provider_arn
        )
        is None
        or not 1 <= len(application_name) <= 100
        or parsed_redirect.scheme != "http"
        or parsed_redirect.hostname != "127.0.0.1"
        or parsed_redirect.path != "/callback"
        or parsed_redirect.query
        or parsed_redirect.fragment
        or parsed_redirect.username
        or parsed_redirect.password
        or redirect_port is None
        or not 1024 <= redirect_port <= 65535
        or _IDENTITY_STORE_USER_ID.fullmatch(user_id) is None
        or _AWS_ACCOUNT_ID.fullmatch(target_id) is None
        or target_id != authority_account_id
        or classifier_name != "ScanalyzeAuthorityRetireClass"
        or approver_name != "ScanalyzeAuthorityRetireApprove"
    ):
        _fail("IDENTITY_OWNER_DECISION_VALUES_INVALID")


def _validate_identity_slot_value_context(
    *, slot: str, value: Any, templates: Sequence[Mapping[str, Any]]
) -> None:
    """Bind provider-created Identity Center ARNs to exact transient inputs."""

    if slot not in {
        "IDENTITY_CENTER_APPLICATION_ARN",
        "CLASSIFIER_PERMISSION_SET_ARN",
        "APPROVER_PERMISSION_SET_ARN",
    }:
        return
    instance_values = [
        template["InstanceArn"]
        for template in templates
        if isinstance(template, Mapping) and "InstanceArn" in template
    ]
    target_values = [
        template["TargetId"]
        for template in templates
        if isinstance(template, Mapping) and "TargetId" in template
    ]
    if not all(isinstance(item, str) for item in [*instance_values, *target_values]):
        _fail("IDENTITY_PROVIDER_SLOT_CONTEXT_INVALID")
    instance_arns = set(instance_values)
    target_ids = set(target_values)
    if len(instance_arns) != 1 or len(target_ids) != 1:
        _fail("IDENTITY_PROVIDER_SLOT_CONTEXT_INVALID")
    instance_arn = next(iter(instance_arns))
    target_id = next(iter(target_ids))
    instance_match = (
        _IDENTITY_CENTER_INSTANCE_ARN.fullmatch(instance_arn)
        if isinstance(instance_arn, str)
        else None
    )
    if instance_match is None or not isinstance(value, str):
        _fail("IDENTITY_PROVIDER_SLOT_CONTEXT_INVALID")
    if slot == "IDENTITY_CENTER_APPLICATION_ARN":
        value_match = _IDENTITY_CENTER_APPLICATION_ARN.fullmatch(value)
        if (
            value_match is None
            or value_match.group("account_id") != target_id
            or value_match.group("instance_id")
            != instance_match.group("instance_id")
        ):
            _fail("IDENTITY_APPLICATION_ARN_CONTEXT_MISMATCH")
    else:
        value_match = _IDENTITY_CENTER_PERMISSION_SET_ARN.fullmatch(value)
        if (
            value_match is None
            or value_match.group("instance_id")
            != instance_match.group("instance_id")
        ):
            _fail("IDENTITY_PERMISSION_SET_ARN_CONTEXT_MISMATCH")


def _validate_slot_route_operation_binding(
    *,
    slot: str,
    phase: str,
    action: str,
    inventory_resource: str,
    producer: bool,
) -> None:
    route = PROVIDER_SLOT_ROUTES.get(slot)
    if route is None:
        _fail("OPERATION_PROVIDER_SLOT_ROUTE_UNKNOWN")
    if producer:
        if (
            phase != route["producer_phase"]
            or action != route["producer_action"]
            or inventory_resource != route.get(
                "producer_inventory_resource", inventory_resource
            )
        ):
            _fail("PROVIDER_SLOT_PRODUCER_ROUTE_MISMATCH")
        return
    if (phase, action) not in route["consumers"]:
        _fail("PROVIDER_SLOT_CONSUMER_ROUTE_MISMATCH")
    consumer_resources = route.get("consumer_inventory_resources")
    if (
        consumer_resources is not None
        and inventory_resource not in consumer_resources
    ):
        _fail("PROVIDER_SLOT_CONSUMER_TARGET_MISMATCH")


def _validate_identity_target_request_bindings(
    *,
    phase: str,
    action: str,
    inventory_resource: str,
    payload: Mapping[str, Any],
    owner_values: Mapping[str, str],
) -> None:
    if phase != "IDENTITY_CENTER_FOUNDATION":
        return
    _validate_identity_owner_values(owner_values)
    exact_tags = [
        {"Key": "managed_by", "Value": "identity-center"},
        {"Key": "service", "Value": "scanalyze-platform-authority"},
        {"Key": "work_package", "Value": "GUG-376"},
        {"Key": "environment", "Value": "non-production"},
        {"Key": "production", "Value": "false"},
    ]
    if action == "sso:CreateApplication":
        redirect_uri = _owner_value(owner_values, "identity_center_redirect_uri")
        if (
            payload.get("Description")
            != "GUG-376 non-production authority application"
            or payload.get("PortalOptions")
            != {
                "SignInOptions": {
                    "Origin": "APPLICATION",
                    "ApplicationUrl": redirect_uri.removesuffix("/callback"),
                },
                "Visibility": "ENABLED",
            }
            or payload.get("Tags") != exact_tags
            or not isinstance(payload.get("ClientToken"), str)
            or re.fullmatch(r"[A-Za-z0-9-]{32,64}", payload["ClientToken"])
            is None
        ):
            _fail("IDENTITY_APPLICATION_SOURCE_CONTRACT_INVALID")
    if action == "sso:PutApplicationAuthenticationMethod":
        # Current source requires the two exact AWSReservedSSO role ARNs in the
        # application actor policy.  They do not exist until provisioning, and
        # ProvisionPermissionSet does not return either RoleArn.  Accepting a
        # caller-supplied ARN or deriving one without provider evidence would
        # turn this repository-only compiler into an authority oracle.
        _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")
    if action == "sso:CreatePermissionSet":
        expected_name_key = {
            "classifier_permission_set": "classifier_permission_set_name",
            "approver_permission_set": "approver_permission_set_name",
        }.get(inventory_resource)
        expected_description = {
            "classifier_permission_set": (
                "GUG-215 classifier single-operator permission set"
            ),
            "approver_permission_set": (
                "GUG-215 approver single-operator permission set"
            ),
        }.get(inventory_resource)
        if (
            expected_name_key is None
            or payload.get("Name") != _owner_value(owner_values, expected_name_key)
            or payload.get("Description") != expected_description
            or payload.get("Tags") != exact_tags
        ):
            _fail("IDENTITY_PERMISSION_SET_TARGET_SUBSTITUTION")
    if action == "sso:PutApplicationGrant" and (
        payload.get("GrantType") != "authorization_code"
        or payload.get("Grant")
        != {
            "AuthorizationCode": {
                "RedirectUris": [
                    _owner_value(owner_values, "identity_center_redirect_uri")
                ]
            }
        }
    ):
        _fail("IDENTITY_APPLICATION_REDIRECT_SUBSTITUTION")
    if action == "sso:PutApplicationAccessScope" and payload.get(
        "AuthorizedTargets"
    ) != [_owner_value(owner_values, "identity_center_instance_arn")]:
        _fail("IDENTITY_APPLICATION_SCOPE_TARGET_SUBSTITUTION")
    application_slot = {"$provider_slot": "IDENTITY_CENTER_APPLICATION_ARN"}
    if "ApplicationArn" in payload and payload["ApplicationArn"] != application_slot:
        _fail("IDENTITY_APPLICATION_ARN_CAUSAL_SLOT_REQUIRED")
    if "PermissionSetArn" in payload:
        expected_permission_slot = {
            "classifier_permission_set": {
                "$provider_slot": "CLASSIFIER_PERMISSION_SET_ARN"
            },
            "classifier_permission_set_role": {
                "$provider_slot": "CLASSIFIER_PERMISSION_SET_ARN"
            },
            "approver_permission_set": {
                "$provider_slot": "APPROVER_PERMISSION_SET_ARN"
            },
            "approver_permission_set_role": {
                "$provider_slot": "APPROVER_PERMISSION_SET_ARN"
            },
        }.get(inventory_resource)
        if payload["PermissionSetArn"] != expected_permission_slot:
            _fail("IDENTITY_PERMISSION_SET_ARN_CAUSAL_SLOT_REQUIRED")
    if action == "sso:PutInlinePolicyToPermissionSet":
        permission_kind = {
            "classifier_permission_set": (
                "Classifier",
                "ScanalyzeGug215ClassifierInvoker",
            ),
            "approver_permission_set": (
                "Approver",
                "ScanalyzeGug215ApproverInvoker",
            ),
        }.get(inventory_resource)
        if permission_kind is None:
            _fail("IDENTITY_INLINE_POLICY_SOURCE_CONTRACT_INVALID")
        label, role_name = permission_kind
        expected_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "CreateTokenForExactRetirementApplication",
                    "Effect": "Allow",
                    "Action": "sso-oauth:CreateTokenWithIAM",
                    "Resource": application_slot,
                },
                {
                    "Sid": f"AssumeExactIdentityEnhanced{label}Invoker",
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:SetContext"],
                    "Resource": (
                        "arn:aws:iam::"
                        f"{_owner_value(owner_values, 'authority_account_id')}:"
                        f"role/{role_name}"
                    ),
                },
                {
                    "Sid": "DenyDirectRetirementEffects",
                    "Effect": "Deny",
                    "Action": [
                        "cloudformation:DeleteChangeSet",
                        "cloudformation:DeleteStack",
                        "cloudformation:ExecuteChangeSet",
                        "dynamodb:BatchWriteItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:PartiQLDelete",
                        "dynamodb:PartiQLInsert",
                        "dynamodb:PartiQLUpdate",
                        "dynamodb:PutItem",
                        "dynamodb:TransactWriteItems",
                        "dynamodb:UpdateItem",
                        "lambda:InvokeAsync",
                        "lambda:InvokeFunction",
                    ],
                    "Resource": "*",
                },
            ],
        }
        if payload.get("InlinePolicy") != expected_policy:
            _fail("IDENTITY_INLINE_POLICY_SOURCE_CONTRACT_INVALID")


def _validate_owner_request_bindings(
    phase: str,
    action: str,
    payload: Mapping[str, Any],
    owner_values: Mapping[str, str],
) -> None:
    bindings = list(OWNER_REQUEST_VALUE_BINDINGS.get(action, ()))
    if action == "s3:PutObject":
        object_key = (
            "broker_unsigned_object_key"
            if phase == "BROKER_UNSIGNED_PUBLISH"
            else "ledger_factory_unsigned_object_key"
        )
        bindings.extend(
            (("artifact_bucket_name", ("Bucket",)), (object_key, ("Key",)))
        )
    elif action == "signer:StartSigningJob":
        bindings.extend(
            (
                ("artifact_bucket_name", ("source", "s3", "bucketName")),
                ("artifact_bucket_name", ("destination", "s3", "bucketName")),
                ("signing_profile_name", ("profileName",)),
                ("authority_account_id", ("profileOwner",)),
            )
        )
    for decision_key, path in bindings:
        if _request_path_value(payload, path) != _owner_value(
            owner_values, decision_key
        ):
            _fail("OPERATION_OWNER_REQUEST_VALUE_MISMATCH")


def _derived_approved_principal_digests(
    action: str, owner_values: Mapping[str, str]
) -> list[str]:
    decision_key = {
        "kms:CreateKey": "kms_admin_principal_arn",
        "s3:PutBucketPolicy": "artifact_bucket_policy_principal_arn",
    }.get(action)
    if decision_key is None:
        return []
    account_id = _owner_value(owner_values, "authority_account_id")
    if _AWS_ACCOUNT_ID.fullmatch(account_id) is None:
        _fail("OPERATION_AUTHORITY_ACCOUNT_ID_INVALID")
    principal = _owner_value(owner_values, decision_key)
    if principal != f"arn:aws:iam::{account_id}:root":
        _fail("OPERATION_APPROVED_PRINCIPAL_ACCOUNT_MISMATCH")
    return [canonical_digest(principal)]


def _kms_key_resource(
    value: Any, *, authority_account_id: str | None
) -> str | Mapping[str, str]:
    if isinstance(value, Mapping):
        if value != {"$provider_slot": "KMS_KEY_ARN"}:
            _fail("OPERATION_KMS_RESOURCE_SLOT_INVALID")
        return value
    if not isinstance(value, str):
        _fail("OPERATION_KMS_RESOURCE_INVALID")
    match = _KMS_KEY_ARN.fullmatch(value)
    if match is None:
        _fail("OPERATION_KMS_RESOURCE_INVALID")
    if (
        authority_account_id is not None
        and match.group("account_id") != authority_account_id
    ):
        _fail("OPERATION_KMS_RESOURCE_ACCOUNT_MISMATCH")
    return value


def _derived_authorized_resources(
    action: str,
    payload: Mapping[str, Any],
    *,
    authority_account_id: str | None,
) -> list[Any]:
    if action in CREATE_ACTIONS_REQUIRING_STAR_RESOURCE:
        return ["*"]
    if action == "kms:EnableKeyRotation":
        return [
            _kms_key_resource(
                payload.get("KeyId"), authority_account_id=authority_account_id
            )
        ]
    if action == "kms:CreateAlias":
        account_id = authority_account_id
        target = _kms_key_resource(
            payload.get("TargetKeyId"), authority_account_id=account_id
        )
        if account_id is None and isinstance(target, str):
            match = _KMS_KEY_ARN.fullmatch(target)
            assert match is not None
            account_id = match.group("account_id")
        if account_id is None or _AWS_ACCOUNT_ID.fullmatch(account_id) is None:
            _fail("OPERATION_AUTHORITY_ACCOUNT_ID_INVALID")
        alias_name = payload.get("AliasName")
        if not isinstance(alias_name, str):
            _fail("OPERATION_KMS_ALIAS_RESOURCE_INVALID")
        return [f"arn:aws:kms:{REGION}:{account_id}:{alias_name}", target]
    if action.startswith("s3:"):
        bucket = payload.get("Bucket")
        if not isinstance(bucket, str) or not bucket:
            _fail("OPERATION_S3_RESOURCE_INVALID")
        suffix = ""
        if action == "s3:PutObject":
            key = payload.get("Key")
            if not isinstance(key, str) or not key or key.startswith("/"):
                _fail("OPERATION_S3_RESOURCE_INVALID")
            suffix = f"/{key}"
        return [f"arn:aws:s3:::{bucket}{suffix}"]
    direct_fields = {
        "sso:PutApplicationAuthenticationMethod": "ApplicationArn",
        "sso:PutApplicationGrant": "ApplicationArn",
        "sso:PutApplicationAccessScope": "ApplicationArn",
        "sso:PutApplicationAssignmentConfiguration": "ApplicationArn",
        "sso:CreateApplicationAssignment": "ApplicationArn",
        "sso:PutInlinePolicyToPermissionSet": "PermissionSetArn",
        "sso:CreateAccountAssignment": "PermissionSetArn",
        "sso:ProvisionPermissionSet": "PermissionSetArn",
    }
    if action in direct_fields:
        resource = payload.get(direct_fields[action])
        if isinstance(resource, Mapping):
            if set(resource) != {"$provider_slot"}:
                _fail("OPERATION_AUTHORIZED_RESOURCE_SLOT_INVALID")
            return [resource]
        if not isinstance(resource, str) or not resource.startswith("arn:"):
            _fail("OPERATION_AUTHORIZED_RESOURCES_INVALID")
        return [resource]
    if action == "signer:StartSigningJob":
        account_id = payload.get("profileOwner")
        profile_name = payload.get("profileName")
        if (
            not isinstance(account_id, str)
            or _AWS_ACCOUNT_ID.fullmatch(account_id) is None
            or not isinstance(profile_name, str)
            or not profile_name
            or (
                authority_account_id is not None
                and account_id != authority_account_id
            )
        ):
            _fail("OPERATION_SIGNER_RESOURCE_INVALID")
        return [
            f"arn:aws:signer:{REGION}:{account_id}:"
            f"/signing-profiles/{profile_name}"
        ]
    _fail("OPERATION_AUTHORIZED_RESOURCE_DERIVATION_UNAVAILABLE")
    raise AssertionError("unreachable")


def _authorized_resource_arn_digests(
    action: str, resources: Sequence[Any]
) -> list[str]:
    if (
        isinstance(resources, (str, bytes))
        or not isinstance(resources, Sequence)
        or not resources
    ):
        _fail("OPERATION_AUTHORIZED_RESOURCES_INVALID")
    normalized = _snapshot(list(resources), "OPERATION_AUTHORIZED_RESOURCES_INVALID")
    if len({canonical_json(resource) for resource in normalized}) != len(normalized):
        _fail("OPERATION_AUTHORIZED_RESOURCES_INVALID")
    if any(resource == "*" for resource in normalized):
        if (
            normalized != ["*"]
            or action not in CREATE_ACTIONS_REQUIRING_STAR_RESOURCE
        ):
            _fail("OPERATION_AUTHORIZED_RESOURCE_WILDCARD_FORBIDDEN")
    else:
        for resource in normalized:
            if isinstance(resource, Mapping):
                if (
                    set(resource) != {"$provider_slot"}
                    or resource["$provider_slot"] not in PROVIDER_SLOT_ROUTES
                ):
                    _fail("OPERATION_AUTHORIZED_RESOURCE_SLOT_INVALID")
            elif (
                not isinstance(resource, str)
                or not resource.startswith("arn:")
                or "*" in resource
            ):
                _fail("OPERATION_AUTHORIZED_RESOURCES_INVALID")
    return sorted(canonical_digest(resource) for resource in normalized)


def _expected_operation_executor_policy_digest(
    *,
    phase: str,
    action: str,
    inventory_resource: str,
    target_digest: str,
    request_digest: str,
    approved_principal_digests: Sequence[str],
    authorized_resource_arn_digests: Sequence[str],
) -> str:
    return canonical_digest(
        {
            "contract": "GUG376_OPERATION_EXECUTOR_POLICY_V1",
            "phase": phase,
            "action": action,
            "iam_actions": list(iam_actions_for_api_action(action)),
            "inventory_resource": inventory_resource,
            "target_digest": target_digest,
            "request_digest": request_digest,
            "approved_principal_digests": list(approved_principal_digests),
            "authorized_resource_arn_digests": list(
                authorized_resource_arn_digests
            ),
            "requested_region": REGION,
            "deny_unlisted_mutations": True,
        }
    )


def _build_repository_operation_contract(
    *,
    phase: str,
    sequence: int,
    action: str,
    inventory_resource: str,
    target_contract: Mapping[str, Any],
    owner_decisions: Mapping[str, Any],
    owner_decision_values: Mapping[str, str],
    request_template: Mapping[str, Any],
    expected_readback_digest: str,
) -> dict[str, Any]:
    if phase not in PHASE_NAMES or action not in REQUIRED_ACTIONS[phase]:
        _fail("PHASE_ACTION_NOT_ALLOWED")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        _fail("OPERATION_SEQUENCE_INVALID")
    if _ACTION.fullmatch(action) is None:
        _fail("OPERATION_ACTION_INVALID")
    if inventory_resource not in ACTION_INVENTORY_RESOURCES[phase][action]:
        _fail("OPERATION_INVENTORY_RESOURCE_INVALID")
    _digest(expected_readback_digest, "OPERATION_DIGEST_INVALID")
    normalized_owner = _snapshot(owner_decisions, "OWNER_DECISIONS_INVALID")
    _validate_repository_owner_decisions(normalized_owner)
    normalized_target = _snapshot(
        target_contract, "INVENTORY_TARGET_CONTRACT_INVALID"
    )
    _validate_inventory_target_contract(
        inventory_resource,
        normalized_target,
        owner_decisions=normalized_owner,
    )
    owner_values = _validated_owner_decision_values(
        normalized_owner, owner_decision_values
    )
    transient = _snapshot(request_template, "REQUEST_TEMPLATE_INVALID")
    _validate_owner_request_bindings(phase, action, transient, owner_values)
    principals = _derived_approved_principal_digests(action, owner_values)
    _validate_request_payload(
        phase,
        action,
        transient,
        allowed_principal_digests=principals,
    )
    slots = sorted(_slot_names(transient))
    for slot in slots:
        _validate_slot_route_operation_binding(
            slot=slot,
            phase=phase,
            action=action,
            inventory_resource=inventory_resource,
            producer=False,
        )
    _validate_identity_target_request_bindings(
        phase=phase,
        action=action,
        inventory_resource=inventory_resource,
        payload=transient,
        owner_values=owner_values,
    )
    template_digest = canonical_digest(transient)
    account_id = owner_values.get("authority_account_id")
    if account_id is not None and _AWS_ACCOUNT_ID.fullmatch(account_id) is None:
        _fail("OPERATION_AUTHORITY_ACCOUNT_ID_INVALID")
    authorized_resource_arn_digests = _authorized_resource_arn_digests(
        action,
        _derived_authorized_resources(
            action, transient, authority_account_id=account_id
        ),
    )
    executor_policy_digest = _expected_operation_executor_policy_digest(
        phase=phase,
        action=action,
        inventory_resource=inventory_resource,
        target_digest=normalized_target["target_digest"],
        request_digest=template_digest,
        approved_principal_digests=principals,
        authorized_resource_arn_digests=authorized_resource_arn_digests,
    )
    resolved = not slots
    operation = {
        "sequence": sequence,
        "action": action,
        "inventory_resource": inventory_resource,
        "target_digest": normalized_target["target_digest"],
        "request_template": {
            "template_digest": template_digest,
            "resolution_status": "EXACT_RESOLVED" if resolved else "UNRESOLVED_PROVIDER_SLOTS",
            "provider_generated_slots": slots,
            "sensitive_values_persisted": False,
        },
        "request_digest": template_digest,
        "request_digest_kind": "EXACT_REQUEST" if resolved else "REQUEST_TEMPLATE",
        "required_slots": slots,
        "approved_principal_digests": principals,
        "authorized_resource_arn_digests": authorized_resource_arn_digests,
        "expected_readback_digest": expected_readback_digest,
        "executor_policy_digest": executor_policy_digest,
        "retry_permitted": False,
        "automatic_rollback": False,
        "ambiguous_outcome": "RECONCILE_ONLY",
    }
    operation["operation_digest"] = canonical_digest(operation)
    return operation


def _validate_operation(phase: str, operation: Mapping[str, Any], expected_sequence: int) -> None:
    keys = {
        "sequence", "action", "inventory_resource", "target_digest",
        "request_template", "request_digest", "request_digest_kind",
        "required_slots", "approved_principal_digests", "expected_readback_digest",
        "authorized_resource_arn_digests",
        "executor_policy_digest", "retry_permitted", "automatic_rollback",
        "ambiguous_outcome", "operation_digest",
    }
    _require_keys(operation, keys, "OPERATION_FIELDS_INVALID")
    action = operation.get("action")
    template = operation.get("request_template")
    required_slots = operation.get("required_slots")
    approved_principal_digests = operation.get("approved_principal_digests")
    authorized_resource_arn_digests = operation.get(
        "authorized_resource_arn_digests"
    )
    if (
        operation.get("sequence") != expected_sequence
        or not isinstance(action, str)
        or action not in REQUIRED_ACTIONS[phase]
        or operation.get("inventory_resource")
        not in ACTION_INVENTORY_RESOURCES[phase].get(action, ())
        or not isinstance(template, Mapping)
        or not isinstance(required_slots, list)
        or not isinstance(approved_principal_digests, list)
        or approved_principal_digests != sorted(set(approved_principal_digests))
        or not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in approved_principal_digests
        )
        or (
            action in {"kms:CreateKey", "s3:PutBucketPolicy"}
            and not approved_principal_digests
        )
        or (
            action not in {"kms:CreateKey", "s3:PutBucketPolicy"}
            and approved_principal_digests
        )
        or not isinstance(authorized_resource_arn_digests, list)
        or not authorized_resource_arn_digests
        or authorized_resource_arn_digests
        != sorted(set(authorized_resource_arn_digests))
        or not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in authorized_resource_arn_digests
        )
        or not all(isinstance(slot, str) and _TOKEN.fullmatch(slot) for slot in required_slots)
        or len(set(required_slots)) != len(required_slots)
        or operation.get("retry_permitted") is not False
        or operation.get("automatic_rollback") is not False
        or operation.get("ambiguous_outcome") != "RECONCILE_ONLY"
    ):
        _fail("OPERATION_INVALID")
    for slot in required_slots:
        _validate_slot_route_operation_binding(
            slot=slot,
            phase=phase,
            action=action,
            inventory_resource=operation["inventory_resource"],
            producer=False,
        )
    _require_keys(
        template,
        {"template_digest", "resolution_status", "provider_generated_slots", "sensitive_values_persisted"},
        "REQUEST_TEMPLATE_FIELDS_INVALID",
    )
    for field in (
        "target_digest", "request_digest", "expected_readback_digest",
        "executor_policy_digest", "operation_digest",
    ):
        _digest(operation.get(field), "OPERATION_DIGEST_INVALID")
    if operation["executor_policy_digest"] != (
        _expected_operation_executor_policy_digest(
            phase=phase,
            action=action,
            inventory_resource=operation["inventory_resource"],
            target_digest=operation["target_digest"],
            request_digest=operation["request_digest"],
            approved_principal_digests=approved_principal_digests,
            authorized_resource_arn_digests=authorized_resource_arn_digests,
        )
    ):
        _fail("OPERATION_EXECUTOR_POLICY_DIGEST_MISMATCH")
    _digest(template.get("template_digest"), "REQUEST_TEMPLATE_DIGEST_INVALID")
    slots = template.get("provider_generated_slots")
    if (
        not isinstance(slots, list)
        or not all(isinstance(slot, str) and _TOKEN.fullmatch(slot) for slot in slots)
        or len(set(slots)) != len(slots)
        or not set(slots).issubset(set(required_slots))
        or template.get("sensitive_values_persisted") is not False
    ):
        _fail("REQUEST_TEMPLATE_SLOT_INVALID")
    status = template.get("resolution_status")
    if status == "EXACT_RESOLVED":
        if slots or operation.get("request_digest_kind") != "EXACT_REQUEST":
            _fail("REQUEST_RESOLUTION_INVALID")
        if not required_slots and operation["request_digest"] != template["template_digest"]:
            _fail("REQUEST_DIGEST_MISMATCH")
    elif status == "UNRESOLVED_PROVIDER_SLOTS":
        if (
            not slots
            or operation.get("request_digest_kind") != "REQUEST_TEMPLATE"
            or not set(slots).issubset(set(required_slots))
        ):
            _fail("REQUEST_RESOLUTION_INVALID")
        if operation["request_digest"] != template["template_digest"]:
            _fail("REQUEST_DIGEST_MISMATCH")
    else:
        _fail("REQUEST_RESOLUTION_INVALID")
    _verify_record_digest(operation, "operation_digest", "OPERATION_DIGEST_MISMATCH")


def _validate_repository_operation_contract(
    phase: str, operation: Mapping[str, Any]
) -> None:
    """Validate an operation used only by the repository simulation."""

    if phase not in PHASE_NAMES or not isinstance(operation, Mapping):
        _fail("OPERATION_INVALID")
    sequence = operation.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        _fail("OPERATION_SEQUENCE_INVALID")
    _validate_operation(phase, operation, sequence)


def build_operation_contract(*_args: Any, **_kwargs: Any) -> None:
    """Reject public operation compilation while source contracts are absent."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_operation_contract(
    _phase: str, _operation: Mapping[str, Any]
) -> None:
    """Reject serialized operations as executable authority."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def build_phase_contract(
    *,
    phase: str,
    inventory_classification: str,
    operations: Sequence[Mapping[str, Any]],
    rollback_boundary: str,
) -> dict[str, Any]:
    try:
        phase_index = PHASE_NAMES.index(phase)
    except ValueError:
        _fail("PHASE_NAME_INVALID")
    if not isinstance(rollback_boundary, str) or not rollback_boundary:
        _fail("PHASE_ROLLBACK_BOUNDARY_INVALID")
    normalized = _snapshot(list(operations), "PHASE_OPERATIONS_INVALID")
    if inventory_classification == "EXACT_PRESENT_NO_TOUCH":
        if normalized:
            _fail("PHASE_NO_TOUCH_HAS_OPERATIONS")
        resolution = "EXACT_PRESENT_NO_TOUCH"
    elif inventory_classification == "ABSENT_READY":
        if not normalized:
            _fail("PHASE_MUTATION_OPERATIONS_MISSING")
        resolution = "MUTATE"
    else:
        _fail("PHASE_INVENTORY_CLASSIFICATION_BLOCKED")
    for sequence, operation in enumerate(normalized, start=1):
        _validate_operation(phase, operation, sequence)
    if resolution == "MUTATE" and Counter(item["action"] for item in normalized) != REQUIRED_ACTIONS[phase]:
        _fail("PHASE_COMPLETE_WRITE_SET_INVALID")
    ordered = [item["request_digest"] for item in normalized]
    spec = PHASE_SPECS[phase_index]
    result = {
        "phase": phase,
        "sequence": phase_index + 1,
        "inventory_target": spec[1],
        "inventory_classification": inventory_classification,
        "resolution": resolution,
        "causal_predecessor": spec[2],
        "operations": normalized,
        "ordered_request_digests": ordered,
        "phase_operation_digest": canonical_digest(normalized),
        "phase_mutation_digest": canonical_digest(ordered),
        "rollback_boundary": rollback_boundary,
    }
    _validate_phase(result, phase_index + 1)
    return result


def _validate_phase(phase: Mapping[str, Any], expected_sequence: int) -> None:
    keys = {
        "phase", "sequence", "inventory_target", "inventory_classification",
        "resolution", "causal_predecessor", "operations", "ordered_request_digests",
        "phase_operation_digest", "phase_mutation_digest", "rollback_boundary",
    }
    _require_keys(phase, keys, "PHASE_FIELDS_INVALID")
    if not 1 <= expected_sequence <= len(PHASE_SPECS):
        _fail("PHASE_SEQUENCE_INVALID")
    spec = PHASE_SPECS[expected_sequence - 1]
    operations = phase.get("operations")
    ordered = phase.get("ordered_request_digests")
    if (
        phase.get("phase") != spec[0]
        or phase.get("sequence") != expected_sequence
        or phase.get("inventory_target") != spec[1]
        or phase.get("causal_predecessor") != spec[2]
        or not isinstance(operations, list)
        or not isinstance(ordered, list)
        or ordered != [item.get("request_digest") for item in operations if isinstance(item, Mapping)]
        or not isinstance(phase.get("rollback_boundary"), str)
        or not phase["rollback_boundary"]
    ):
        _fail("PHASE_INVALID")
    if phase.get("resolution") == "EXACT_PRESENT_NO_TOUCH":
        if phase.get("inventory_classification") != "EXACT_PRESENT_NO_TOUCH" or operations:
            _fail("PHASE_NO_TOUCH_INVALID")
    elif phase.get("resolution") == "MUTATE":
        if phase.get("inventory_classification") != "ABSENT_READY" or not operations:
            _fail("PHASE_MUTATION_INVALID")
        for index, operation in enumerate(operations, start=1):
            _validate_operation(spec[0], operation, index)
        if Counter(item["action"] for item in operations) != REQUIRED_ACTIONS[spec[0]]:
            _fail("PHASE_COMPLETE_WRITE_SET_INVALID")
    else:
        _fail("PHASE_RESOLUTION_INVALID")
    if (
        phase.get("phase_operation_digest") != canonical_digest(operations)
        or phase.get("phase_mutation_digest") != canonical_digest(ordered)
    ):
        _fail("PHASE_DIGEST_MISMATCH")


def validate_phase_contract(phase: Mapping[str, Any]) -> None:
    """Public phase validator used by the authorization and runner boundary."""

    if not isinstance(phase, Mapping):
        _fail("PHASE_INVALID")
    sequence = phase.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        _fail("PHASE_SEQUENCE_INVALID")
    _validate_phase(phase, sequence)


def _phase_inventory_binding(
    inventory: Mapping[str, Any], phase: Mapping[str, Any]
) -> dict[str, Any]:
    names = list(PHASE_INVENTORY_RESOURCES[phase["phase"]])
    resources = {name: inventory["resources"][name] for name in names}
    classifications = {item["classification"] for item in resources.values()}
    if classifications != {phase["inventory_classification"]}:
        _fail("PLAN_PHASE_INVENTORY_CLASSIFICATION_MISMATCH")
    target_digests = sorted({item["target_digest"] for item in resources.values()})
    resource_target_bindings = [
        {
            "inventory_resource": name,
            "target_digest": resources[name]["target_digest"],
        }
        for name in names
    ]
    if phase["resolution"] == "MUTATE" and any(
        operation["inventory_resource"] not in resources
        or operation["target_digest"]
        != resources[operation["inventory_resource"]]["target_digest"]
        for operation in phase["operations"]
    ):
        _fail("PLAN_PHASE_OPERATION_TARGET_MISMATCH")
    binding = {
        "phase": phase["phase"],
        "resource_names": names,
        "resource_target_digests": target_digests,
        "resource_target_bindings": resource_target_bindings,
        "inventory_projection_digest": canonical_digest(resources),
        "provider_before_state_digest": canonical_digest(
            {
                name: {
                    "classification": resource["classification"],
                    "provider_fact_digest": resource["provider_fact_digest"],
                    "target_digest": resource["target_digest"],
                }
                for name, resource in resources.items()
            }
        ),
    }
    binding["phase_inventory_binding_digest"] = canonical_digest(binding)
    return binding


def _validate_phase_inventory_binding(
    binding: Mapping[str, Any], phase: Mapping[str, Any]
) -> None:
    keys = {
        "phase", "resource_names", "resource_target_digests",
        "resource_target_bindings",
        "inventory_projection_digest", "provider_before_state_digest",
        "phase_inventory_binding_digest",
    }
    _require_keys(binding, keys, "PLAN_PHASE_INVENTORY_BINDING_FIELDS_INVALID")
    names = binding.get("resource_names")
    targets = binding.get("resource_target_digests")
    resource_target_bindings = binding.get("resource_target_bindings")
    if (
        binding.get("phase") != phase["phase"]
        or names != list(PHASE_INVENTORY_RESOURCES[phase["phase"]])
        or not isinstance(targets, list)
        or not targets
        or targets != sorted(set(targets))
        or not isinstance(resource_target_bindings, list)
        or len(resource_target_bindings) != len(names)
    ):
        _fail("PLAN_PHASE_INVENTORY_BINDING_INVALID")
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"inventory_resource", "target_digest"}
        or item.get("inventory_resource") != names[index]
        for index, item in enumerate(resource_target_bindings)
    ):
        _fail("PLAN_PHASE_INVENTORY_BINDING_INVALID")
    target_by_resource = {
        item["inventory_resource"]: item["target_digest"]
        for item in resource_target_bindings
    }
    if sorted(set(target_by_resource.values())) != targets:
        _fail("PLAN_PHASE_INVENTORY_BINDING_INVALID")
    for value in (
        *targets,
        binding.get("inventory_projection_digest"),
        binding.get("provider_before_state_digest"),
    ):
        _digest(value, "PLAN_PHASE_INVENTORY_BINDING_DIGEST_INVALID")
    if phase["resolution"] == "MUTATE" and any(
        operation["inventory_resource"] not in target_by_resource
        or operation["target_digest"]
        != target_by_resource[operation["inventory_resource"]]
        for operation in phase["operations"]
    ):
        _fail("PLAN_PHASE_OPERATION_TARGET_MISMATCH")
    _verify_record_digest(
        binding,
        "phase_inventory_binding_digest",
        "PLAN_PHASE_INVENTORY_BINDING_DIGEST_MISMATCH",
    )


def _build_repository_upstream_plan(
    *,
    upstream_run_digest: str,
    owner_decisions: Mapping[str, Any],
    owner_decisions_approval_digest: str,
    inventory: Mapping[str, Any],
    private_ledger_root_digest: str,
    phases: Sequence[Mapping[str, Any]],
    created_at: datetime,
) -> dict[str, Any]:
    for value in (
        upstream_run_digest, owner_decisions_approval_digest,
        private_ledger_root_digest,
    ):
        _digest(value, "PLAN_BINDING_DIGEST_INVALID")
    normalized_owner_decisions = _snapshot(
        owner_decisions, "OWNER_DECISIONS_INVALID"
    )
    _validate_repository_owner_decisions(normalized_owner_decisions)
    owner_decisions_digest = normalized_owner_decisions["owner_decisions_digest"]
    if (
        normalized_owner_decisions["upstream_run_digest"] != upstream_run_digest
        or owner_decisions_approval_digest
        != expected_owner_decisions_approval_digest(normalized_owner_decisions)
    ):
        _fail("PLAN_OWNER_DECISIONS_APPROVAL_BINDING_MISMATCH")
    normalized_inventory = _snapshot(inventory, "PLAN_INVENTORY_INVALID")
    _validate_repository_stable_inventory(normalized_inventory)
    if (
        normalized_inventory["upstream_run_digest"] != upstream_run_digest
        or normalized_inventory["owner_decisions_digest"] != owner_decisions_digest
    ):
        _fail("PLAN_INVENTORY_CAUSAL_BINDING_MISMATCH")
    for name in RESOURCE_NAMES:
        _validate_inventory_target_contract(
            name,
            normalized_inventory["resources"][name]["target_contract"],
            owner_decisions=normalized_owner_decisions,
        )
    normalized = _snapshot(list(phases), "PLAN_PHASES_INVALID")
    if len(normalized) != 9:
        _fail("PLAN_PHASE_COUNT_INVALID")
    for sequence, phase in enumerate(normalized, start=1):
        _validate_phase(phase, sequence)
    mutation_phases = [phase["phase"] for phase in normalized if phase["resolution"] == "MUTATE"]
    if not mutation_phases:
        _fail("PLAN_HAS_NO_MUTATION_PHASE")
    topology = {
        "same_bucket_required": True,
        "same_kms_key_required": True,
        "same_code_signing_config_required": True,
        "allowed_publisher_count": 1,
        "signer_platform": "AWSLambda-SHA384-ECDSA",
        "distinct_signing_jobs_required": True,
        "distinct_signed_objects_required": True,
        "unsigned_signed_outer_digests_must_differ": True,
        "zip_members_must_match": True,
    }
    complete_write_set = [
        {
            "phase": phase["phase"],
            "phase_operation_digest": phase["phase_operation_digest"],
            "phase_mutation_digest": phase["phase_mutation_digest"],
        }
        for phase in normalized
    ]
    phase_inventory_bindings = [
        _phase_inventory_binding(normalized_inventory, phase) for phase in normalized
    ]
    plan = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_plan.v1",
        **_base(deployment_authorized=False),
        "authorization_mode": "SINGLE_OPERATOR_NONPROD_EXCEPTION",
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "aws_calls_performed": 0,
        "aws_mutations": 0,
        "state": "STOPPED_BEFORE_FIRST_AWS_WRITE",
        "owner_authorization_issued": False,
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "gap_checkpoint_digest": GAP_CHECKPOINT_DIGEST,
        "original_run_digest": ORIGINAL_RUN_DIGEST,
        "upstream_run_digest": upstream_run_digest,
        "owner_decisions_digest": owner_decisions_digest,
        "owner_decisions_approval_digest": owner_decisions_approval_digest,
        "inventory_digest": normalized_inventory["inventory_digest"],
        "inventory_account_binding_digest": normalized_inventory[
            "account_binding_digest"
        ],
        "inventory_caller_identity_digest": normalized_inventory[
            "caller_identity_digest"
        ],
        "runtime_evidence_digest": normalized_inventory["runtime_evidence"][
            "runtime_evidence_digest"
        ],
        "private_ledger_root_digest": private_ledger_root_digest,
        "phase_inventory_bindings": phase_inventory_bindings,
        "artifact_topology": topology,
        "phase_count": 9,
        "first_mutation_phase": mutation_phases[0],
        "phases": normalized,
        "complete_write_set_digest": canonical_digest(complete_write_set),
        "created_at": _timestamp(created_at, "PLAN_TIME_INVALID"),
    }
    plan["plan_digest"] = canonical_digest(plan)
    _validate_repository_upstream_plan(plan)
    return plan


def _validate_repository_upstream_plan(plan: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "deployment_authorized",
        "authorization_mode", "two_human_status", "independent_approval_present",
        "aws_calls_performed", "aws_mutations", "state", "owner_authorization_issued",
        "source_head_sha", "source_merge_sha", "source_tree_sha", "gap_checkpoint_digest",
        "original_run_digest", "upstream_run_digest", "owner_decisions_digest",
        "owner_decisions_approval_digest", "inventory_digest",
        "inventory_account_binding_digest", "inventory_caller_identity_digest",
        "runtime_evidence_digest", "private_ledger_root_digest",
        "phase_inventory_bindings", "artifact_topology", "phase_count",
        "first_mutation_phase", "phases", "complete_write_set_digest", "created_at",
        "plan_digest",
    }
    _require_keys(plan, keys, "PLAN_FIELDS_INVALID")
    topology = plan.get("artifact_topology")
    expected_topology = {
        "same_bucket_required": True, "same_kms_key_required": True,
        "same_code_signing_config_required": True, "allowed_publisher_count": 1,
        "signer_platform": "AWSLambda-SHA384-ECDSA",
        "distinct_signing_jobs_required": True, "distinct_signed_objects_required": True,
        "unsigned_signed_outer_digests_must_differ": True, "zip_members_must_match": True,
    }
    phases = plan.get("phases")
    inventory_bindings = plan.get("phase_inventory_bindings")
    if (
        plan.get("record_type") != "scanalyze.platform_authority.gug365_upstream_plan.v1"
        or any(plan.get(key) != value for key, value in _base(deployment_authorized=False).items())
        or plan.get("authorization_mode") != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
        or plan.get("two_human_status") != "NOT_PROVEN"
        or plan.get("independent_approval_present") is not False
        or plan.get("aws_calls_performed") != 0
        or plan.get("aws_mutations") != 0
        or plan.get("state") != "STOPPED_BEFORE_FIRST_AWS_WRITE"
        or plan.get("owner_authorization_issued") is not False
        or plan.get("gap_checkpoint_digest") != GAP_CHECKPOINT_DIGEST
        or plan.get("original_run_digest") != ORIGINAL_RUN_DIGEST
        or topology != expected_topology
        or plan.get("phase_count") != 9
        or not isinstance(phases, list)
        or len(phases) != 9
        or not isinstance(inventory_bindings, list)
        or len(inventory_bindings) != 9
    ):
        _fail("PLAN_INVALID")
    _validate_source(plan, "PLAN_SOURCE_INVALID")
    for field in (
        "upstream_run_digest", "owner_decisions_digest", "owner_decisions_approval_digest",
        "inventory_digest", "inventory_account_binding_digest",
        "inventory_caller_identity_digest", "runtime_evidence_digest",
        "private_ledger_root_digest",
        "complete_write_set_digest",
    ):
        _digest(plan.get(field), "PLAN_DIGEST_INVALID")
    for sequence, phase in enumerate(phases, start=1):
        _validate_phase(phase, sequence)
        _validate_phase_inventory_binding(inventory_bindings[sequence - 1], phase)
    mutation_phases = [phase["phase"] for phase in phases if phase["resolution"] == "MUTATE"]
    if not mutation_phases or plan.get("first_mutation_phase") != mutation_phases[0]:
        _fail("PLAN_FIRST_MUTATION_INVALID")
    complete_write_set = [
        {
            "phase": phase["phase"],
            "phase_operation_digest": phase["phase_operation_digest"],
            "phase_mutation_digest": phase["phase_mutation_digest"],
        }
        for phase in phases
    ]
    if plan["complete_write_set_digest"] != canonical_digest(complete_write_set):
        _fail("PLAN_WRITE_SET_DIGEST_MISMATCH")
    _parse_timestamp(plan.get("created_at"), "PLAN_TIME_INVALID")
    _verify_record_digest(plan, "plan_digest", "PLAN_DIGEST_MISMATCH")


def _resolve_slots(value: Any, slot_values: Mapping[str, Any]) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$provider_slot"}:
            slot = value["$provider_slot"]
            if slot not in slot_values:
                return value
            return _snapshot(slot_values[slot], "PROVIDER_SLOT_VALUE_INVALID")
        return {key: _resolve_slots(item, slot_values) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_slots(item, slot_values) for item in value]
    return value


def _build_repository_provider_slot_binding(
    *,
    slot: str,
    value: Any,
    producer_phase: str,
    producer_operation_sequence: int,
    producer_authorization_digest: str,
    producer_operation_receipt_digest: str,
    producer_provider_result_digest: str,
    producer_readback_digest: str,
    producer_transcript_verification: Mapping[str, Any],
    consumer_phase: str,
    consumer_operation_sequences: Sequence[int],
    producer_phase_certification_digest: str | None = None,
) -> dict[str, Any]:
    """Seal one externally projected provider output without its raw value."""

    if (
        not isinstance(slot, str)
        or _TOKEN.fullmatch(slot) is None
        or slot not in PROVIDER_SLOT_ROUTES
        or producer_phase not in PHASE_NAMES
        or consumer_phase not in PHASE_NAMES
        or not isinstance(producer_operation_sequence, int)
        or isinstance(producer_operation_sequence, bool)
        or producer_operation_sequence < 1
    ):
        _fail("PROVIDER_SLOT_BINDING_INVALID")
    consumers = list(consumer_operation_sequences)
    if (
        not consumers
        or not all(
            isinstance(item, int) and not isinstance(item, bool) and item >= 1
            for item in consumers
        )
        or len(set(consumers)) != len(consumers)
        or consumers != sorted(consumers)
    ):
        _fail("PROVIDER_SLOT_BINDING_CONSUMERS_INVALID")
    for digest in (
        producer_authorization_digest,
        producer_operation_receipt_digest,
        producer_provider_result_digest,
        producer_readback_digest,
    ):
        _digest(digest, "PROVIDER_SLOT_BINDING_DIGEST_INVALID")
    if producer_phase_certification_digest is not None:
        _digest(
            producer_phase_certification_digest,
            "PROVIDER_SLOT_BINDING_DIGEST_INVALID",
        )
    _validate_repository_provider_transcript_verification(
        producer_transcript_verification
    )
    route = PROVIDER_SLOT_ROUTES[slot]
    if producer_transcript_verification["stage"] != "OPERATION":
        _fail("PROVIDER_SLOT_TRANSCRIPT_INVALID")
    if (
        producer_phase != route["producer_phase"]
        or producer_transcript_verification["phase"] != producer_phase
        or producer_transcript_verification["operation_sequence"]
        != producer_operation_sequence
        or producer_transcript_verification["operation_action"]
        != route["producer_action"]
        or producer_transcript_verification["authorization_digest"]
        != producer_authorization_digest
        or producer_transcript_verification["provider_result_digest"]
        != producer_provider_result_digest
        or producer_transcript_verification["observed_readback_digest"]
        != producer_readback_digest
        or not isinstance(value, str)
        or re.fullmatch(route["value_pattern"], value) is None
    ):
        _fail("PROVIDER_SLOT_VALUE_NOT_ATTESTED")
    value_digest = canonical_digest(value)
    expected_projection_keys = {
        ("WRITE_RESPONSE", route["write_response_path"]),
        ("READBACK", route["readback_path"]),
    }
    matching_projections = [
        projection
        for projection in producer_transcript_verification["projections"]
        if projection["slot"] == slot
        and projection["value_digest"] == value_digest
    ]
    if {
        (projection["source"], projection["field_path"])
        for projection in matching_projections
    } != expected_projection_keys:
        _fail("PROVIDER_SLOT_VALUE_NOT_ATTESTED")
    projection_digests = sorted(
        projection["projection_digest"] for projection in matching_projections
    )
    record = {
        "record_type": (
            "scanalyze.platform_authority.gug365_upstream_provider_slot_binding.v1"
        ),
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "slot": slot,
        "value_digest": value_digest,
        "producer_phase": producer_phase,
        "producer_action": route["producer_action"],
        "producer_operation_sequence": producer_operation_sequence,
        "producer_authorization_digest": producer_authorization_digest,
        "producer_operation_receipt_digest": producer_operation_receipt_digest,
        "producer_provider_result_digest": producer_provider_result_digest,
        "producer_readback_digest": producer_readback_digest,
        "producer_transcript_verification_digest": (
            producer_transcript_verification["verification_digest"]
        ),
        "producer_projection_digests": projection_digests,
        "producer_phase_certification_digest": producer_phase_certification_digest,
        "consumer_phase": consumer_phase,
        "consumer_operation_sequences": consumers,
        "single_assignment": True,
        "raw_value_persisted": False,
        "provider_value_attested": True,
    }
    record["slot_binding_digest"] = canonical_digest(record)
    _validate_repository_provider_slot_binding(record)
    return record


def _validate_repository_provider_slot_binding(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "slot", "value_digest",
        "producer_phase", "producer_action", "producer_operation_sequence",
        "producer_authorization_digest", "producer_operation_receipt_digest",
        "producer_provider_result_digest", "producer_readback_digest",
        "producer_transcript_verification_digest", "producer_projection_digests",
        "producer_phase_certification_digest",
        "consumer_phase", "consumer_operation_sequences", "single_assignment",
        "raw_value_persisted", "provider_value_attested", "slot_binding_digest",
    }
    _require_keys(record, keys, "PROVIDER_SLOT_BINDING_FIELDS_INVALID")
    consumers = record.get("consumer_operation_sequences")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_provider_slot_binding.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or not isinstance(record.get("slot"), str)
        or _TOKEN.fullmatch(record["slot"]) is None
        or record.get("slot") not in PROVIDER_SLOT_ROUTES
        or record.get("producer_phase") not in PHASE_NAMES
        or record.get("consumer_phase") not in PHASE_NAMES
        or not isinstance(record.get("producer_operation_sequence"), int)
        or isinstance(record.get("producer_operation_sequence"), bool)
        or record["producer_operation_sequence"] < 1
        or not isinstance(consumers, list)
        or not consumers
        or consumers != sorted(set(consumers))
        or not all(isinstance(item, int) and not isinstance(item, bool) and item >= 1 for item in consumers)
        or record.get("single_assignment") is not True
        or record.get("raw_value_persisted") is not False
        or record.get("provider_value_attested") is not True
    ):
        _fail("PROVIDER_SLOT_BINDING_INVALID")
    route = PROVIDER_SLOT_ROUTES[record["slot"]]
    projection_digests = record.get("producer_projection_digests")
    if (
        record["producer_phase"] != route["producer_phase"]
        or record.get("producer_action") != route["producer_action"]
    ):
        _fail("PROVIDER_SLOT_ROUTE_INVALID")
    if (
        not isinstance(projection_digests, list)
        or len(projection_digests) != 2
        or projection_digests != sorted(set(projection_digests))
    ):
        _fail("PROVIDER_SLOT_PROJECTION_BINDING_INVALID")
    for field in (
        "value_digest", "producer_authorization_digest",
        "producer_operation_receipt_digest", "producer_provider_result_digest",
        "producer_readback_digest", "producer_transcript_verification_digest",
    ):
        _digest(record.get(field), "PROVIDER_SLOT_BINDING_DIGEST_INVALID")
    for value in projection_digests:
        _digest(value, "PROVIDER_SLOT_BINDING_DIGEST_INVALID")
    certification_digest = record.get("producer_phase_certification_digest")
    is_cross_phase = record["producer_phase"] != record["consumer_phase"]
    if is_cross_phase != (certification_digest is not None):
        _fail("PROVIDER_SLOT_CERTIFICATION_BINDING_INVALID")
    if certification_digest is not None:
        _digest(certification_digest, "PROVIDER_SLOT_BINDING_DIGEST_INVALID")
    if PHASE_NAMES.index(record["producer_phase"]) > PHASE_NAMES.index(record["consumer_phase"]):
        _fail("PROVIDER_SLOT_CAUSAL_ORDER_INVALID")
    _verify_record_digest(
        record, "slot_binding_digest", "PROVIDER_SLOT_BINDING_DIGEST_MISMATCH"
    )


def resolve_phase_requests(
    *,
    phase: Mapping[str, Any],
    request_templates: Sequence[Mapping[str, Any]],
    slot_values: Mapping[str, Any],
    slot_bindings: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Resolve available causal slots without persisting request payloads.

    Templates and provider values remain transient.  Operations with missing
    slots stay template-bound and cannot appear in an authorization.
    """

    expected_sequence = phase.get("sequence") if isinstance(phase, Mapping) else None
    if not isinstance(expected_sequence, int):
        _fail("PHASE_SEQUENCE_INVALID")
    _validate_phase(phase, expected_sequence)
    operations = phase["operations"]
    templates = _snapshot(list(request_templates), "REQUEST_TEMPLATES_INVALID")
    if len(templates) != len(operations):
        _fail("REQUEST_TEMPLATE_COUNT_INVALID")
    if not isinstance(slot_values, Mapping) or not all(
        isinstance(key, str) and _TOKEN.fullmatch(key) for key in slot_values
    ):
        _fail("PROVIDER_SLOT_VALUES_INVALID")
    bindings = _snapshot(list(slot_bindings), "PROVIDER_SLOT_BINDINGS_INVALID")
    by_slot: dict[str, Mapping[str, Any]] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping):
            _fail("PROVIDER_SLOT_BINDINGS_INVALID")
        _validate_repository_provider_slot_binding(binding)
        slot = binding["slot"]
        if slot in by_slot:
            _fail("PROVIDER_SLOT_REASSIGNMENT")
        if binding["producer_phase"] == phase["phase"]:
            producer_sequence = binding["producer_operation_sequence"]
            if not 1 <= producer_sequence <= len(operations):
                _fail("PROVIDER_SLOT_PRODUCER_ROUTE_MISMATCH")
            producer_operation = operations[producer_sequence - 1]
            _validate_slot_route_operation_binding(
                slot=slot,
                phase=phase["phase"],
                action=producer_operation["action"],
                inventory_resource=producer_operation["inventory_resource"],
                producer=True,
            )
        by_slot[slot] = binding
    if set(slot_values) != set(by_slot):
        _fail("PROVIDER_SLOT_PROVENANCE_REQUIRED")
    for slot, value in slot_values.items():
        if by_slot[slot]["value_digest"] != canonical_digest(value):
            _fail("PROVIDER_SLOT_VALUE_BINDING_MISMATCH")
    _validate_phase_request_set(phase["phase"], operations, templates)
    for slot, value in slot_values.items():
        _validate_identity_slot_value_context(
            slot=slot,
            value=value,
            templates=templates,
        )
    resolved_operations: list[dict[str, Any]] = []
    for operation, raw_template in zip(operations, templates, strict=True):
        transient = _snapshot(raw_template, "REQUEST_TEMPLATE_INVALID")
        if canonical_digest(transient) != operation["request_template"]["template_digest"]:
            _fail("REQUEST_TEMPLATE_DIGEST_MISMATCH")
        required = set(operation["required_slots"])
        if not _slot_names(transient) == required:
            _fail("REQUEST_TEMPLATE_SLOT_MISMATCH")
        for slot in required & set(slot_values):
            binding = by_slot[slot]
            route = PROVIDER_SLOT_ROUTES[slot]
            if (
                binding["consumer_phase"] != phase["phase"]
                or operation["sequence"] not in binding["consumer_operation_sequences"]
                or (phase["phase"], operation["action"]) not in route["consumers"]
            ):
                _fail("PROVIDER_SLOT_CONSUMER_BINDING_MISMATCH")
        concrete = _resolve_slots(transient, slot_values)
        remaining = sorted(_slot_names(concrete))
        _validate_request_payload(
            phase["phase"],
            operation["action"],
            concrete,
            allowed_principal_digests=operation["approved_principal_digests"],
        )
        updated = dict(operation)
        updated["request_template"] = {
            "template_digest": operation["request_template"]["template_digest"],
            "resolution_status": "EXACT_RESOLVED" if not remaining else "UNRESOLVED_PROVIDER_SLOTS",
            "provider_generated_slots": remaining,
            "sensitive_values_persisted": False,
        }
        updated["required_slots"] = list(operation["required_slots"])
        updated["request_digest"] = (
            canonical_digest(concrete) if not remaining else operation["request_template"]["template_digest"]
        )
        updated["request_digest_kind"] = "EXACT_REQUEST" if not remaining else "REQUEST_TEMPLATE"
        if not remaining:
            updated["authorized_resource_arn_digests"] = (
                _authorized_resource_arn_digests(
                    operation["action"],
                    _derived_authorized_resources(
                        operation["action"],
                        concrete,
                        authority_account_id=None,
                    ),
                )
            )
        updated["executor_policy_digest"] = (
            _expected_operation_executor_policy_digest(
                phase=phase["phase"],
                action=operation["action"],
                inventory_resource=operation["inventory_resource"],
                target_digest=operation["target_digest"],
                request_digest=updated["request_digest"],
                approved_principal_digests=operation[
                    "approved_principal_digests"
                ],
                authorized_resource_arn_digests=updated[
                    "authorized_resource_arn_digests"
                ],
            )
        )
        updated["operation_digest"] = canonical_digest(
            {key: value for key, value in updated.items() if key != "operation_digest"}
        )
        resolved_operations.append(updated)
    result = dict(phase)
    result["operations"] = resolved_operations
    result["ordered_request_digests"] = [item["request_digest"] for item in resolved_operations]
    result["phase_operation_digest"] = canonical_digest(resolved_operations)
    result["phase_mutation_digest"] = canonical_digest(result["ordered_request_digests"])
    _validate_phase(result, expected_sequence)
    return result


def _pending_exact_operations(
    phase: Mapping[str, Any], completed_count: int
) -> list[Mapping[str, Any]]:
    operations = phase["operations"]
    if completed_count >= len(operations):
        _fail("AUTHORIZATION_NO_PENDING_OPERATION")
    pending: list[Mapping[str, Any]] = []
    for operation in operations[completed_count:]:
        if operation["request_digest_kind"] != "EXACT_REQUEST":
            break
        pending.append(operation)
    if not pending:
        _fail("AUTHORIZATION_PROVIDER_SLOTS_UNRESOLVED")
    return pending


def _executor_policy_document(
    *,
    phase: str,
    bindings: Sequence[Mapping[str, Any]],
    not_before: str,
    expires_at: str,
) -> dict[str, Any]:
    """Compile the only IAM document accepted for one execution window."""

    mutation_iam_actions = {
        iam_action
        for binding in bindings
        for iam_action in iam_actions_for_api_action(binding["action"])
    }
    readback_iam_actions = {
        iam_action
        for api_action in PHASE_READBACK_ACTIONS[phase]
        for iam_action in iam_actions_for_api_action(api_action)
    }
    allowed_actions = sorted(
        {"sts:GetCallerIdentity", *mutation_iam_actions, *readback_iam_actions}
    )
    statements: list[dict[str, Any]] = [
        {
            "Sid": "ConfirmOnlyCurrentCaller",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*",
            "Condition": {
                "DateGreaterThanEquals": {"aws:CurrentTime": not_before},
                "DateLessThan": {"aws:CurrentTime": expires_at},
            },
        }
    ]
    for binding in bindings:
        condition: dict[str, Any] = {
            "StringEquals": {"aws:RequestedRegion": REGION},
            "DateGreaterThanEquals": {"aws:CurrentTime": not_before},
            "DateLessThan": {"aws:CurrentTime": expires_at},
        }
        if binding["resource_arns"] == ["*"]:
            condition["StringEquals"]["aws:RequestTag/ScanalyzeIssue"] = "GUG-376"
            condition["ForAllValues:StringEquals"] = {
                "aws:TagKeys": ["ScanalyzeIssue"]
            }
        statements.append(
            {
                "Sid": f"AllowExactMutation{binding['sequence']:03d}",
                "Effect": "Allow",
                "Action": list(iam_actions_for_api_action(binding["action"])),
                "Resource": binding["resource_arns"],
                "Condition": condition,
            }
        )
    all_bound_resources = sorted(
        {
            resource
            for binding in bindings
            for resource in binding["resource_arns"]
            if resource != "*"
        }
    )
    exact_readback_resources = {
        "kms:Decrypt": [
            item for item in all_bound_resources if item.startswith("arn:aws:kms:")
        ],
        "s3:GetObject": [
            item
            for item in all_bound_resources
            if item.startswith("arn:aws:s3:::") and "/" in item.removeprefix("arn:aws:s3:::")
        ],
        "s3:ListBucket": [
            item
            for item in all_bound_resources
            if item.startswith("arn:aws:s3:::") and "/" not in item.removeprefix("arn:aws:s3:::")
        ],
    }
    common_readback_condition = {
        "StringEquals": {"aws:RequestedRegion": REGION},
        "DateGreaterThanEquals": {"aws:CurrentTime": not_before},
        "DateLessThan": {"aws:CurrentTime": expires_at},
    }
    unscoped_readbacks = sorted(
        readback_iam_actions - set(exact_readback_resources)
    )
    if unscoped_readbacks:
        statements.append(
            {
                "Sid": "AllowPhaseControlPlaneReadbackOnly",
                "Effect": "Allow",
                "Action": unscoped_readbacks,
                "Resource": "*",
                "Condition": common_readback_condition,
            }
        )
    for iam_action in sorted(readback_iam_actions & set(exact_readback_resources)):
        resources = exact_readback_resources[iam_action]
        if not resources:
            _fail("EXECUTOR_AUTHORITY_READBACK_RESOURCE_MISSING")
        statements.append(
            {
                "Sid": "AllowExact" + iam_action.replace(":", "").replace("*", ""),
                "Effect": "Allow",
                "Action": iam_action,
                "Resource": resources,
                "Condition": common_readback_condition,
            }
        )
    statements.extend(
        [
            {
                "Sid": "DenyEveryUnreviewedAction",
                "Effect": "Deny",
                "NotAction": allowed_actions,
                "Resource": "*",
            },
            {
                "Sid": "DenyOutsideHomeRegion",
                "Effect": "Deny",
                "NotAction": "sts:GetCallerIdentity",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:RequestedRegion": REGION}
                },
            },
            {
                "Sid": "DenyBeforeAbsoluteStart",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:CurrentTime": not_before}},
            },
            {
                "Sid": "DenyAtAbsoluteExpiry",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThanEquals": {"aws:CurrentTime": expires_at}
                },
            },
        ]
    )
    return {"Version": "2012-10-17", "Statement": statements}


def _build_repository_phase_executor_authority_evidence(
    *,
    resolved_phase: Mapping[str, Any],
    completed_operation_count: int,
    resource_arns_by_sequence: Mapping[int, Sequence[str]],
    account_or_management_binding_digest: str,
    caller_identity_digest: str,
    session_identifier_digest: str,
    sts_call_receipt_digest: str,
    permission_set_policy_readback_digest: str,
    permissions_boundary_readback_digest: str,
    additive_grants_readback_digest: str,
    effective_authority_readback_digest: str,
    session_verifier_identity_digest: str,
    session_attestation_root_digest: str,
    session_expires_at: datetime,
    not_before: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Compile a phase-only least-privilege authority proof.

    This is an offline policy contract, not an AWS credential.  Live execution
    must prove that both the permission-set inline policy and its boundary
    equal ``policy_contract_digest`` before the runner can consume it.
    """

    sequence = resolved_phase.get("sequence")
    if not isinstance(sequence, int):
        _fail("EXECUTOR_AUTHORITY_PHASE_INVALID")
    _validate_phase(resolved_phase, sequence)
    if (
        not isinstance(completed_operation_count, int)
        or isinstance(completed_operation_count, bool)
        or completed_operation_count < 0
    ):
        _fail("EXECUTOR_AUTHORITY_SEQUENCE_INVALID")
    pending = _pending_exact_operations(resolved_phase, completed_operation_count)
    expected_sequences = {operation["sequence"] for operation in pending}
    if not isinstance(resource_arns_by_sequence, Mapping) or set(resource_arns_by_sequence) != expected_sequences:
        _fail("EXECUTOR_AUTHORITY_RESOURCE_BINDING_INVALID")
    bindings: list[dict[str, Any]] = []
    for operation in pending:
        resources = resource_arns_by_sequence[operation["sequence"]]
        if (
            isinstance(resources, (str, bytes))
            or not isinstance(resources, Sequence)
            or not resources
            or not all(isinstance(resource, str) and resource for resource in resources)
        ):
            _fail("EXECUTOR_AUTHORITY_RESOURCE_BINDING_INVALID")
        normalized_resources = sorted(set(resources))
        if any("*" in resource for resource in normalized_resources):
            if (
                normalized_resources != ["*"]
                or operation["action"] not in CREATE_ACTIONS_REQUIRING_STAR_RESOURCE
            ):
                _fail("EXECUTOR_AUTHORITY_WILDCARD_RESOURCE_FORBIDDEN")
        elif not all(resource.startswith("arn:") for resource in normalized_resources):
            _fail("EXECUTOR_AUTHORITY_RESOURCE_BINDING_INVALID")
        if (
            sorted(canonical_digest(resource) for resource in normalized_resources)
            != operation["authorized_resource_arn_digests"]
        ):
            _fail("EXECUTOR_AUTHORITY_RESOURCE_OPERATION_BINDING_MISMATCH")
        bindings.append(
            {
                "sequence": operation["sequence"],
                "action": operation["action"],
                "target_digest": operation["target_digest"],
                "request_digest": operation["request_digest"],
                "executor_policy_digest": operation["executor_policy_digest"],
                "resource_arns": normalized_resources,
            }
        )
    for value in (
        account_or_management_binding_digest,
        caller_identity_digest,
        session_identifier_digest,
        sts_call_receipt_digest,
        session_verifier_identity_digest,
        session_attestation_root_digest,
    ):
        _digest(value, "EXECUTOR_AUTHORITY_BINDING_DIGEST_INVALID")
    start = _timestamp(not_before, "EXECUTOR_AUTHORITY_TIME_INVALID")
    end = _timestamp(expires_at, "EXECUTOR_AUTHORITY_TIME_INVALID")
    start_time = _parse_timestamp(start, "EXECUTOR_AUTHORITY_TIME_INVALID")
    end_time = _parse_timestamp(end, "EXECUTOR_AUTHORITY_TIME_INVALID")
    session_end = _timestamp(session_expires_at, "EXECUTOR_AUTHORITY_TIME_INVALID")
    session_end_time = _parse_timestamp(session_end, "EXECUTOR_AUTHORITY_TIME_INVALID")
    if not 1 <= int((end_time - start_time).total_seconds()) <= 900:
        _fail("EXECUTOR_AUTHORITY_WINDOW_INVALID")
    if end_time > session_end_time:
        _fail("EXECUTOR_AUTHORITY_SESSION_EXPIRES_EARLY")
    policy_document = _executor_policy_document(
        phase=resolved_phase["phase"],
        bindings=bindings,
        not_before=start,
        expires_at=end,
    )
    policy_document_digest = canonical_digest(policy_document)
    expected_additive_grants_digest = canonical_digest([])
    expected_effective_authority_digest = canonical_digest(
        {
            "phase": resolved_phase["phase"],
            "session_identifier_digest": session_identifier_digest,
            "allowed_mutation_bindings": bindings,
            "allowed_readback_actions": list(
                PHASE_READBACK_ACTIONS[resolved_phase["phase"]]
            ),
            "sts_get_caller_identity_only_before_other_signed_calls": True,
        }
    )
    if (
        permission_set_policy_readback_digest != policy_document_digest
        or permissions_boundary_readback_digest != policy_document_digest
        or additive_grants_readback_digest != expected_additive_grants_digest
        or effective_authority_readback_digest
        != expected_effective_authority_digest
    ):
        _fail("EXECUTOR_AUTHORITY_READBACK_MISMATCH")
    policy_contract = {
        "allowed_mutation_bindings": bindings,
        "allowed_readback_actions": list(PHASE_READBACK_ACTIONS[resolved_phase["phase"]]),
        "allow_sts_get_caller_identity": True,
        "deny_unlisted_mutations": True,
        "wildcard_actions_allowed": False,
        "wildcard_resources_only_for_tagged_create": True,
        "required_request_tag": {"ScanalyzeIssue": "GUG-376"},
        "requested_region": REGION,
        "not_before": start,
        "expires_at": end,
        "policy_document": policy_document,
        "permissions_boundary_document": policy_document,
        "policy_document_digest": policy_document_digest,
        "permissions_boundary_document_digest": policy_document_digest,
    }
    record = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug365_upstream_repository_simulation_executor_authority_evidence.v1"
        ),
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "phase": resolved_phase["phase"],
        "phase_only": True,
        "session_source": "DIRECT_SSO_PERMISSION_SET",
        "session_chain_depth": 0,
        "sts_was_first_signed_call": True,
        "permission_set_policy_matches_contract": True,
        "permissions_boundary_matches_contract": True,
        "additive_grants_present": False,
        "account_or_management_binding_digest": account_or_management_binding_digest,
        "caller_identity_digest": caller_identity_digest,
        "session_identifier_digest": session_identifier_digest,
        "session_expires_at": session_end,
        "sts_call_receipt_digest": sts_call_receipt_digest,
        "permission_set_policy_readback_digest": permission_set_policy_readback_digest,
        "permissions_boundary_readback_digest": permissions_boundary_readback_digest,
        "additive_grants_readback_digest": additive_grants_readback_digest,
        "effective_authority_readback_digest": effective_authority_readback_digest,
        "session_verifier_identity_digest": session_verifier_identity_digest,
        "session_attestation_root_digest": session_attestation_root_digest,
        "policy_contract": policy_contract,
        "policy_contract_digest": canonical_digest(policy_contract),
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
    }
    record["executor_authority_evidence_digest"] = canonical_digest(record)
    _validate_repository_phase_executor_authority_evidence(record)
    return record


def _validate_repository_phase_executor_authority_evidence(
    record: Mapping[str, Any],
) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "phase", "phase_only",
        "session_source", "session_chain_depth", "sts_was_first_signed_call",
        "permission_set_policy_matches_contract", "permissions_boundary_matches_contract",
        "additive_grants_present", "account_or_management_binding_digest",
        "caller_identity_digest", "session_identifier_digest", "session_expires_at",
        "sts_call_receipt_digest", "permission_set_policy_readback_digest",
        "permissions_boundary_readback_digest", "additive_grants_readback_digest",
        "effective_authority_readback_digest", "policy_contract",
        "session_verifier_identity_digest", "session_attestation_root_digest",
        "policy_contract_digest",
        "source_head_sha", "source_merge_sha", "source_tree_sha",
        "executor_authority_evidence_digest",
    }
    _require_keys(record, keys, "EXECUTOR_AUTHORITY_FIELDS_INVALID")
    if (
        record.get("record_type")
        != (
            "scanalyze.platform_authority."
            "gug365_upstream_repository_simulation_executor_authority_evidence.v1"
        )
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("phase") not in PHASE_NAMES
        or record.get("phase_only") is not True
        or record.get("session_source") != "DIRECT_SSO_PERMISSION_SET"
        or record.get("session_chain_depth") != 0
        or record.get("sts_was_first_signed_call") is not True
        or record.get("permission_set_policy_matches_contract") is not True
        or record.get("permissions_boundary_matches_contract") is not True
        or record.get("additive_grants_present") is not False
    ):
        _fail("EXECUTOR_AUTHORITY_INVALID")
    _validate_source(record, "EXECUTOR_AUTHORITY_SOURCE_INVALID")
    for field in (
        "account_or_management_binding_digest", "caller_identity_digest",
        "session_identifier_digest", "sts_call_receipt_digest",
        "permission_set_policy_readback_digest",
        "permissions_boundary_readback_digest", "additive_grants_readback_digest",
        "effective_authority_readback_digest", "policy_contract_digest",
        "session_verifier_identity_digest", "session_attestation_root_digest",
    ):
        _digest(record.get(field), "EXECUTOR_AUTHORITY_DIGEST_INVALID")
    policy = record.get("policy_contract")
    if not isinstance(policy, Mapping) or set(policy) != {
        "allowed_mutation_bindings", "allowed_readback_actions",
        "allow_sts_get_caller_identity", "deny_unlisted_mutations",
        "wildcard_actions_allowed", "wildcard_resources_only_for_tagged_create",
        "required_request_tag", "requested_region", "not_before", "expires_at",
        "policy_document", "permissions_boundary_document",
        "policy_document_digest", "permissions_boundary_document_digest",
    }:
        _fail("EXECUTOR_AUTHORITY_POLICY_INVALID")
    bindings = policy.get("allowed_mutation_bindings")
    readbacks = policy.get("allowed_readback_actions")
    if (
        not isinstance(bindings, list)
        or not bindings
        or not isinstance(readbacks, list)
        or readbacks != list(PHASE_READBACK_ACTIONS[record["phase"]])
        or policy.get("allow_sts_get_caller_identity") is not True
        or policy.get("deny_unlisted_mutations") is not True
        or policy.get("wildcard_actions_allowed") is not False
        or policy.get("wildcard_resources_only_for_tagged_create") is not True
        or policy.get("required_request_tag") != {"ScanalyzeIssue": "GUG-376"}
        or policy.get("requested_region") != REGION
    ):
        _fail("EXECUTOR_AUTHORITY_POLICY_INVALID")
    seen_sequences: list[int] = []
    for binding in bindings:
        if not isinstance(binding, Mapping) or set(binding) != {
            "sequence", "action", "target_digest", "request_digest",
            "executor_policy_digest", "resource_arns",
        }:
            _fail("EXECUTOR_AUTHORITY_BINDING_INVALID")
        sequence = binding.get("sequence")
        action = binding.get("action")
        resources = binding.get("resource_arns")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not isinstance(action, str)
            or action not in REQUIRED_ACTIONS[record["phase"]]
            or not isinstance(resources, list)
            or not resources
            or resources != sorted(set(resources))
        ):
            _fail("EXECUTOR_AUTHORITY_BINDING_INVALID")
        for field in ("target_digest", "request_digest", "executor_policy_digest"):
            _digest(binding.get(field), "EXECUTOR_AUTHORITY_BINDING_DIGEST_INVALID")
        if any("*" in resource for resource in resources) and (
            resources != ["*"] or action not in CREATE_ACTIONS_REQUIRING_STAR_RESOURCE
        ):
            _fail("EXECUTOR_AUTHORITY_WILDCARD_RESOURCE_FORBIDDEN")
        if resources != ["*"] and not all(
            isinstance(resource, str) and resource.startswith("arn:")
            for resource in resources
        ):
            _fail("EXECUTOR_AUTHORITY_RESOURCE_BINDING_INVALID")
        seen_sequences.append(sequence)
    if seen_sequences != list(range(seen_sequences[0], seen_sequences[0] + len(seen_sequences))):
        _fail("EXECUTOR_AUTHORITY_SEQUENCE_INVALID")
    start = _parse_timestamp(policy.get("not_before"), "EXECUTOR_AUTHORITY_TIME_INVALID")
    end = _parse_timestamp(policy.get("expires_at"), "EXECUTOR_AUTHORITY_TIME_INVALID")
    if not 1 <= int((end - start).total_seconds()) <= 900:
        _fail("EXECUTOR_AUTHORITY_WINDOW_INVALID")
    session_end = _parse_timestamp(
        record.get("session_expires_at"), "EXECUTOR_AUTHORITY_TIME_INVALID"
    )
    if end > session_end:
        _fail("EXECUTOR_AUTHORITY_SESSION_EXPIRES_EARLY")
    expected_policy_document = _executor_policy_document(
        phase=record["phase"],
        bindings=bindings,
        not_before=policy["not_before"],
        expires_at=policy["expires_at"],
    )
    expected_policy_digest = canonical_digest(expected_policy_document)
    expected_effective_authority_digest = canonical_digest(
        {
            "phase": record["phase"],
            "session_identifier_digest": record["session_identifier_digest"],
            "allowed_mutation_bindings": bindings,
            "allowed_readback_actions": list(PHASE_READBACK_ACTIONS[record["phase"]]),
            "sts_get_caller_identity_only_before_other_signed_calls": True,
        }
    )
    if (
        policy.get("policy_document") != expected_policy_document
        or policy.get("permissions_boundary_document") != expected_policy_document
        or policy.get("policy_document_digest") != expected_policy_digest
        or policy.get("permissions_boundary_document_digest")
        != expected_policy_digest
        or record["permission_set_policy_readback_digest"]
        != expected_policy_digest
        or record["permissions_boundary_readback_digest"]
        != expected_policy_digest
        or record["additive_grants_readback_digest"] != canonical_digest([])
        or record["effective_authority_readback_digest"]
        != expected_effective_authority_digest
    ):
        _fail("EXECUTOR_AUTHORITY_READBACK_MISMATCH")
    if record["policy_contract_digest"] != canonical_digest(policy):
        _fail("EXECUTOR_AUTHORITY_POLICY_DIGEST_MISMATCH")
    _verify_record_digest(
        record,
        "executor_authority_evidence_digest",
        "EXECUTOR_AUTHORITY_EVIDENCE_DIGEST_MISMATCH",
    )


def _validate_repository_operation_receipt(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "phase", "sequence",
        "request_digest", "expected_readback_digest", "observed_readback_digest",
        "provider_result_digest", "authorization_digest", "claim_ledger_digest", "status",
        "provider_preflight_verification", "provider_operation_verification",
        "provider_evidence_origin",
        "write_attempt_count", "blind_retry_permitted", "automatic_rollback",
        "observed_at", "receipt_digest",
    }
    _require_keys(record, keys, "OPERATION_RECEIPT_FIELDS_INVALID")
    if (
        record.get("record_type") != "scanalyze.platform_authority.gug365_upstream_operation_receipt.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("phase") not in PHASE_NAMES
        or not isinstance(record.get("sequence"), int)
        or isinstance(record.get("sequence"), bool)
        or record["sequence"] < 1
        or record.get("status") != "SUCCEEDED"
        or record.get("write_attempt_count") != 1
        or record.get("blind_retry_permitted") is not False
        or record.get("automatic_rollback") is not False
        or record.get("provider_evidence_origin") != "SYNTHETIC_TEST"
    ):
        _fail("OPERATION_RECEIPT_INVALID")
    for field in (
        "request_digest", "expected_readback_digest", "observed_readback_digest",
        "provider_result_digest", "authorization_digest", "claim_ledger_digest",
    ):
        _digest(record.get(field), "OPERATION_RECEIPT_DIGEST_INVALID")
    if record["expected_readback_digest"] != record["observed_readback_digest"]:
        _fail("OPERATION_RECEIPT_READBACK_MISMATCH")
    preflight = record.get("provider_preflight_verification")
    operation = record.get("provider_operation_verification")
    if not isinstance(preflight, Mapping) or not isinstance(operation, Mapping):
        _fail("OPERATION_RECEIPT_PROVIDER_VERIFICATION_INVALID")
    _validate_repository_provider_transcript_verification(preflight)
    _validate_repository_provider_transcript_verification(operation)
    if (
        preflight["stage"] != "PREFLIGHT"
        or operation["stage"] != "OPERATION"
        or preflight["evidence_origin"] != record["provider_evidence_origin"]
        or operation["evidence_origin"] != record["provider_evidence_origin"]
        or preflight["phase"] != record["phase"]
        or operation["phase"] != record["phase"]
        or preflight["authorization_digest"] != record["authorization_digest"]
        or operation["authorization_digest"] != record["authorization_digest"]
        or operation["operation_sequence"] != record["sequence"]
        or operation["request_digest"] != record["request_digest"]
        or operation["provider_result_digest"] != record["provider_result_digest"]
        or operation["observed_readback_digest"]
        != record["observed_readback_digest"]
        or preflight["verifier_identity_digest"]
        != operation["verifier_identity_digest"]
        or preflight["attestation_root_digest"]
        != operation["attestation_root_digest"]
        or preflight["session_identifier_digest"]
        != operation["session_identifier_digest"]
        or preflight["account_or_management_binding_digest"]
        != operation["account_or_management_binding_digest"]
        or preflight["caller_identity_digest"]
        != operation["caller_identity_digest"]
    ):
        _fail("OPERATION_RECEIPT_PROVIDER_VERIFICATION_BINDING_INVALID")
    _parse_timestamp(record.get("observed_at"), "OPERATION_RECEIPT_TIME_INVALID")
    _verify_record_digest(record, "receipt_digest", "OPERATION_RECEIPT_DIGEST_MISMATCH")


def _build_repository_phase_authorization(
    *,
    plan: Mapping[str, Any],
    resolved_phase: Mapping[str, Any],
    request_templates: Sequence[Mapping[str, Any]],
    slot_values: Mapping[str, Any],
    completed_operation_receipts: Sequence[Mapping[str, Any]],
    completed_operation_authorizations: Sequence[Mapping[str, Any]],
    completed_owner_authorization_responses: Sequence[str],
    account_or_management_binding_digest: str,
    caller_identity_digest: str,
    executor_authority_evidence: Mapping[str, Any],
    execution_trust_anchor: Mapping[str, Any],
    before_state_digest: str,
    private_ledger_root_digest: str,
    not_before: datetime,
    expires_at: datetime,
    slot_bindings: Sequence[Mapping[str, Any]] = (),
    prior_phase_certifications: Sequence[Mapping[str, Any]] = (),
    causal_predecessor_certification_digest: str | None = None,
) -> dict[str, Any]:
    """Authorize the next contiguous exact request batch for one phase."""

    _validate_repository_upstream_plan(plan)
    _validate_repository_execution_trust_anchor(execution_trust_anchor)
    phase_sequence = resolved_phase.get("sequence")
    if not isinstance(phase_sequence, int):
        _fail("AUTHORIZATION_PHASE_INVALID")
    _validate_phase(resolved_phase, phase_sequence)
    planned = plan["phases"][phase_sequence - 1]
    inventory_binding = plan["phase_inventory_bindings"][phase_sequence - 1]
    if planned["phase"] != resolved_phase["phase"]:
        _fail("AUTHORIZATION_PHASE_PLAN_MISMATCH")
    recomputed = resolve_phase_requests(
        phase=planned,
        request_templates=request_templates,
        slot_values=slot_values,
        slot_bindings=slot_bindings,
    )
    if canonical_digest(recomputed) != canonical_digest(resolved_phase):
        _fail("AUTHORIZATION_RESOLVED_PHASE_PLAN_MISMATCH")
    _digest(
        causal_predecessor_certification_digest,
        "AUTHORIZATION_PREDECESSOR_CERTIFICATION_INVALID",
    )
    completed_receipts = _snapshot(
        list(completed_operation_receipts), "AUTHORIZATION_COMPLETED_RECEIPTS_INVALID"
    )
    completed_authorizations = _snapshot(
        list(completed_operation_authorizations),
        "AUTHORIZATION_COMPLETED_AUTHORIZATIONS_INVALID",
    )
    completed_responses = list(completed_owner_authorization_responses)
    if not (
        len(completed_receipts)
        == len(completed_authorizations)
        == len(completed_responses)
    ):
        _fail("AUTHORIZATION_COMPLETED_CAUSAL_CHAIN_INVALID")
    if len(completed_receipts) >= len(resolved_phase["operations"]):
        _fail("AUTHORIZATION_NO_PENDING_OPERATION")
    for expected_sequence, (receipt, prior_authorization, prior_response) in enumerate(
        zip(
            completed_receipts,
            completed_authorizations,
            completed_responses,
            strict=True,
        ),
        start=1,
    ):
        if not isinstance(receipt, Mapping):
            _fail("AUTHORIZATION_COMPLETED_RECEIPTS_INVALID")
        _validate_repository_operation_receipt(receipt)
        if not isinstance(prior_authorization, Mapping) or not isinstance(prior_response, str):
            _fail("AUTHORIZATION_COMPLETED_CAUSAL_CHAIN_INVALID")
        _validate_repository_phase_authorization(prior_authorization)
        _validate_repository_owner_authorization_response(
            prior_response, prior_authorization
        )
        operation = resolved_phase["operations"][expected_sequence - 1]
        if (
            receipt["phase"] != resolved_phase["phase"]
            or receipt["sequence"] != expected_sequence
            or receipt["request_digest"] != operation["request_digest"]
            or receipt["expected_readback_digest"] != operation["expected_readback_digest"]
            or receipt["authorization_digest"] != prior_authorization["authorization_digest"]
            or prior_authorization["phase"] != resolved_phase["phase"]
            or receipt["request_digest"] not in prior_authorization["ordered_request_digests"]
            or prior_authorization["upstream_plan_digest"] != plan["plan_digest"]
            or prior_authorization["run_id_digest"] != plan["upstream_run_digest"]
            or prior_authorization["complete_write_set_digest"]
            != plan["complete_write_set_digest"]
            or prior_authorization["account_or_management_binding_digest"]
            != account_or_management_binding_digest
            or prior_authorization["caller_identity_digest"] != caller_identity_digest
            or prior_authorization["private_ledger_root_digest"]
            != private_ledger_root_digest
            or prior_authorization["execution_trust_anchor_digest"]
            != execution_trust_anchor.get("execution_trust_anchor_digest")
            or prior_authorization["causal_predecessor_certification_digest"]
            != causal_predecessor_certification_digest
        ):
            _fail("AUTHORIZATION_COMPLETED_RECEIPT_BINDING_MISMATCH")
    prior_certifications = _snapshot(
        list(prior_phase_certifications),
        "AUTHORIZATION_PRIOR_PHASE_CERTIFICATIONS_INVALID",
    )
    certification_by_phase: dict[str, Mapping[str, Any]] = {}
    for certification in prior_certifications:
        if not isinstance(certification, Mapping):
            _fail("AUTHORIZATION_PRIOR_PHASE_CERTIFICATIONS_INVALID")
        _validate_repository_phase_certification(certification)
        certification_phase = certification["phase"]
        certification_index = PHASE_NAMES.index(certification_phase)
        planned_certification_phase = plan["phases"][certification_index]
        planned_certification_inventory = plan["phase_inventory_bindings"][
            certification_index
        ]
        if (
            certification_phase in certification_by_phase
            or certification_index >= PHASE_NAMES.index(resolved_phase["phase"])
        ):
            _fail("AUTHORIZATION_PRIOR_PHASE_CERTIFICATIONS_INVALID")
        if (
            certification["inventory_digest"] != plan["inventory_digest"]
            or certification["phase_inventory_binding_digest"]
            != planned_certification_inventory["phase_inventory_binding_digest"]
            or certification["template_phase_operation_digest"]
            != planned_certification_phase["phase_operation_digest"]
            or certification["template_phase_mutation_digest"]
            != planned_certification_phase["phase_mutation_digest"]
            or certification["resolution"]
            != planned_certification_phase["resolution"]
        ):
            _fail("AUTHORIZATION_PRIOR_PHASE_CERTIFICATION_PLAN_MISMATCH")
        certification_by_phase[certification_phase] = certification
    cross_phase_slot_requested = any(
        isinstance(binding, Mapping)
        and binding.get("producer_phase") != resolved_phase["phase"]
        for binding in slot_bindings
    )
    if cross_phase_slot_requested:
        expected_prior_phases = list(PHASE_NAMES[: phase_sequence - 1])
        if [item["phase"] for item in prior_certifications] != expected_prior_phases:
            _fail("AUTHORIZATION_PRIOR_PHASE_CERTIFICATION_CHAIN_INCOMPLETE")
        expected_predecessor = canonical_digest(
            {
                "domain": "GUG376_PHASE_CHAIN_GENESIS",
                "plan_digest": plan["plan_digest"],
                "inventory_digest": plan["inventory_digest"],
            }
        )
        for certification in prior_certifications:
            if (
                certification["causal_predecessor_certification_digest"]
                != expected_predecessor
            ):
                _fail("AUTHORIZATION_PRIOR_PHASE_PREDECESSOR_MISMATCH")
            expected_predecessor = certification["phase_certification_digest"]
        if causal_predecessor_certification_digest != expected_predecessor:
            _fail("AUTHORIZATION_PREDECESSOR_CERTIFICATION_MISMATCH")
    completed_receipt_by_sequence = {
        receipt["sequence"]: receipt for receipt in completed_receipts
    }
    for raw_binding in slot_bindings:
        if not isinstance(raw_binding, Mapping):
            _fail("AUTHORIZATION_SLOT_BINDING_INVALID")
        _validate_repository_provider_slot_binding(raw_binding)
        route = PROVIDER_SLOT_ROUTES[raw_binding["slot"]]
        if raw_binding["producer_phase"] == resolved_phase["phase"]:
            producer_sequence = raw_binding["producer_operation_sequence"]
            if not 1 <= producer_sequence <= len(resolved_phase["operations"]):
                _fail("AUTHORIZATION_SLOT_PRODUCER_ROUTE_INVALID")
            producer_operation = resolved_phase["operations"][producer_sequence - 1]
            _validate_slot_route_operation_binding(
                slot=raw_binding["slot"],
                phase=resolved_phase["phase"],
                action=producer_operation["action"],
                inventory_resource=producer_operation["inventory_resource"],
                producer=True,
            )
        if any(
            sequence > len(resolved_phase["operations"])
            or (
                resolved_phase["phase"],
                resolved_phase["operations"][sequence - 1]["action"],
            ) not in route["consumers"]
            or (
                route.get("consumer_inventory_resources") is not None
                and resolved_phase["operations"][sequence - 1][
                    "inventory_resource"
                ]
                not in route["consumer_inventory_resources"]
            )
            for sequence in raw_binding["consumer_operation_sequences"]
        ):
            _fail("AUTHORIZATION_SLOT_CONSUMER_ROUTE_INVALID")
        producer: Mapping[str, Any] | None = None
        if raw_binding["producer_phase"] == resolved_phase["phase"]:
            receipt = completed_receipt_by_sequence.get(
                raw_binding["producer_operation_sequence"]
            )
            if receipt is not None:
                provider_verification = receipt["provider_operation_verification"]
                matching_projection_digests = sorted(
                    projection["projection_digest"]
                    for projection in provider_verification["projections"]
                    if projection["slot"] == raw_binding["slot"]
                    and projection["value_digest"] == raw_binding["value_digest"]
                )
                producer = {
                    "action": provider_verification["operation_action"],
                    "authorization_digest": receipt["authorization_digest"],
                    "operation_receipt_digest": receipt["receipt_digest"],
                    "provider_result_digest": receipt["provider_result_digest"],
                    "observed_readback_digest": receipt["observed_readback_digest"],
                    "provider_transcript_verification_digest": provider_verification[
                        "verification_digest"
                    ],
                    "provider_projection_digests": matching_projection_digests,
                }
        else:
            certification = certification_by_phase.get(raw_binding["producer_phase"])
            if (
                certification is not None
                and certification["phase_certification_digest"]
                == raw_binding["producer_phase_certification_digest"]
            ):
                producer = next(
                    (
                        evidence
                        for evidence in certification["operation_evidence"]
                        if evidence["sequence"]
                        == raw_binding["producer_operation_sequence"]
                    ),
                    None,
                )
        if producer is None or any(
            producer.get(field) != raw_binding[binding_field]
            for field, binding_field in (
                ("action", "producer_action"),
                ("authorization_digest", "producer_authorization_digest"),
                ("operation_receipt_digest", "producer_operation_receipt_digest"),
                ("provider_result_digest", "producer_provider_result_digest"),
                ("observed_readback_digest", "producer_readback_digest"),
                (
                    "provider_transcript_verification_digest",
                    "producer_transcript_verification_digest",
                ),
                ("provider_projection_digests", "producer_projection_digests"),
            )
        ):
            _fail("AUTHORIZATION_SLOT_PRODUCER_NOT_ATTESTED")
    exact_pending = _pending_exact_operations(resolved_phase, len(completed_receipts))
    _validate_repository_phase_executor_authority_evidence(
        executor_authority_evidence
    )
    for value in (
        account_or_management_binding_digest, caller_identity_digest,
        before_state_digest, private_ledger_root_digest,
    ):
        _digest(value, "AUTHORIZATION_BINDING_DIGEST_INVALID")
    if (
        account_or_management_binding_digest
        != plan["inventory_account_binding_digest"]
        or caller_identity_digest != plan["inventory_caller_identity_digest"]
        or private_ledger_root_digest != plan["private_ledger_root_digest"]
        or
        execution_trust_anchor["private_ledger_root_digest"]
        != private_ledger_root_digest
        or executor_authority_evidence["session_verifier_identity_digest"]
        != execution_trust_anchor["executor_session_verifier_identity_digest"]
        or executor_authority_evidence["session_attestation_root_digest"]
        != execution_trust_anchor["executor_session_attestation_root_digest"]
    ):
        _fail("AUTHORIZATION_PLAN_OR_TRUST_BINDING_MISMATCH")
    expected_before_state_digest = inventory_binding[
        "provider_before_state_digest"
    ]
    if completed_receipts:
        expected_before_state_digest = completed_receipts[-1][
            "observed_readback_digest"
        ]
    if before_state_digest != expected_before_state_digest:
        _fail("AUTHORIZATION_BEFORE_STATE_NOT_CAUSAL")
    start = _timestamp(not_before, "AUTHORIZATION_TIME_INVALID")
    end = _timestamp(expires_at, "AUTHORIZATION_TIME_INVALID")
    start_time = _parse_timestamp(start, "AUTHORIZATION_TIME_INVALID")
    end_time = _parse_timestamp(end, "AUTHORIZATION_TIME_INVALID")
    validity = int((end_time - start_time).total_seconds())
    if not 1 <= validity <= 900:
        _fail("AUTHORIZATION_WINDOW_INVALID")
    evidence_policy = executor_authority_evidence["policy_contract"]
    expected_bindings = [
        {
            "sequence": operation["sequence"],
            "action": operation["action"],
            "target_digest": operation["target_digest"],
            "request_digest": operation["request_digest"],
            "executor_policy_digest": operation["executor_policy_digest"],
            "resource_arns": binding["resource_arns"],
        }
        for operation, binding in zip(
            exact_pending, evidence_policy["allowed_mutation_bindings"], strict=True
        )
    ] if len(evidence_policy["allowed_mutation_bindings"]) == len(exact_pending) else []
    if (
        executor_authority_evidence["phase"] != resolved_phase["phase"]
        or executor_authority_evidence["account_or_management_binding_digest"]
        != account_or_management_binding_digest
        or executor_authority_evidence["caller_identity_digest"] != caller_identity_digest
        or evidence_policy["allowed_mutation_bindings"] != expected_bindings
        or evidence_policy["not_before"] != start
        or evidence_policy["expires_at"] != end
    ):
        _fail("AUTHORIZATION_EXECUTOR_AUTHORITY_MISMATCH")
    ordered = [operation["request_digest"] for operation in exact_pending]
    authorization = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug365_upstream_repository_simulation_phase_authorization.v1"
        ),
        **_base(deployment_authorized=False),
        "upstream_issue": "GUG-376",
        "production_authorized": False,
        "consumer_writes_authorized": False,
        "decision": "SIMULATE",
        "phase": resolved_phase["phase"],
        "phase_only": True,
        "request_resolution_status": "EXACT_RESOLVED",
        "provider_generated_slots_remaining": 0,
        "run_id_digest": plan["upstream_run_digest"],
        "account_or_management_binding_digest": account_or_management_binding_digest,
        "region": REGION,
        "caller_identity_digest": caller_identity_digest,
        "executor_authority_evidence_digest": executor_authority_evidence[
            "executor_authority_evidence_digest"
        ],
        "execution_trust_anchor_digest": execution_trust_anchor[
            "execution_trust_anchor_digest"
        ],
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "gap_checkpoint_digest": GAP_CHECKPOINT_DIGEST,
        "upstream_plan_digest": plan["plan_digest"],
        "before_state_digest": before_state_digest,
        "causal_predecessor_certification_digest": (
            causal_predecessor_certification_digest
        ),
        "complete_write_set_digest": plan["complete_write_set_digest"],
        "phase_operation_digest": resolved_phase["phase_operation_digest"],
        "phase_mutation_digest": resolved_phase["phase_mutation_digest"],
        "ordered_request_digests": ordered,
        "private_ledger_root_digest": private_ledger_root_digest,
        "not_before": start,
        "expires_at": end,
        "authorization_validity_seconds": validity,
        "attempts": 1,
        "sdk_retries": 0,
        "automatic_rollback": False,
        "ambiguous_outcome": "RECONCILE_ONLY",
        "owner": "Cesar_Guzman",
    }
    authorization["authorization_digest"] = canonical_digest(authorization)
    _validate_repository_phase_authorization(authorization)
    return authorization


def _validate_repository_phase_authorization(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "upstream_issue",
        "consumer_issue", "environment", "production", "production_authorized",
        "production_status", "deployment_authorized", "consumer_writes_authorized",
        "decision", "phase", "phase_only", "request_resolution_status",
        "provider_generated_slots_remaining", "run_id_digest",
        "account_or_management_binding_digest", "region", "caller_identity_digest",
        "executor_authority_evidence_digest", "execution_trust_anchor_digest",
        "source_head_sha", "source_merge_sha",
        "source_tree_sha", "gap_checkpoint_digest", "upstream_plan_digest",
        "before_state_digest", "causal_predecessor_certification_digest",
        "complete_write_set_digest", "phase_operation_digest",
        "phase_mutation_digest", "ordered_request_digests", "private_ledger_root_digest",
        "not_before", "expires_at", "authorization_validity_seconds", "attempts",
        "sdk_retries", "automatic_rollback", "ambiguous_outcome", "owner",
        "authorization_digest",
    }
    _require_keys(record, keys, "AUTHORIZATION_FIELDS_INVALID")
    ordered = record.get("ordered_request_digests")
    if (
        record.get("record_type")
        != (
            "scanalyze.platform_authority."
            "gug365_upstream_repository_simulation_phase_authorization.v1"
        )
        or any(
            record.get(key) != value
            for key, value in _base(deployment_authorized=False).items()
        )
        or record.get("upstream_issue") != "GUG-376"
        or record.get("production_authorized") is not False
        or record.get("consumer_writes_authorized") is not False
        or record.get("decision") != "SIMULATE"
        or record.get("phase") not in PHASE_NAMES
        or record.get("phase_only") is not True
        or record.get("request_resolution_status") != "EXACT_RESOLVED"
        or record.get("provider_generated_slots_remaining") != 0
        or record.get("region") != REGION
        or record.get("gap_checkpoint_digest") != GAP_CHECKPOINT_DIGEST
        or not isinstance(ordered, list)
        or not ordered
        or len(set(ordered)) != len(ordered)
        or record.get("attempts") != 1
        or record.get("sdk_retries") != 0
        or record.get("automatic_rollback") is not False
        or record.get("ambiguous_outcome") != "RECONCILE_ONLY"
        or record.get("owner") != "Cesar_Guzman"
    ):
        _fail("AUTHORIZATION_INVALID")
    _validate_source(record, "AUTHORIZATION_SOURCE_INVALID")
    for field in (
        "run_id_digest", "account_or_management_binding_digest", "caller_identity_digest",
        "executor_authority_evidence_digest", "execution_trust_anchor_digest",
        "upstream_plan_digest",
        "before_state_digest", "causal_predecessor_certification_digest",
        "complete_write_set_digest", "phase_operation_digest",
        "phase_mutation_digest", "private_ledger_root_digest",
    ):
        _digest(record.get(field), "AUTHORIZATION_DIGEST_INVALID")
    for value in ordered:
        _digest(value, "AUTHORIZATION_REQUEST_DIGEST_INVALID")
    start = _parse_timestamp(record.get("not_before"), "AUTHORIZATION_TIME_INVALID")
    end = _parse_timestamp(record.get("expires_at"), "AUTHORIZATION_TIME_INVALID")
    validity = int((end - start).total_seconds())
    if validity != record.get("authorization_validity_seconds") or not 1 <= validity <= 900:
        _fail("AUTHORIZATION_WINDOW_INVALID")
    _verify_record_digest(record, "authorization_digest", "AUTHORIZATION_DIGEST_MISMATCH")


def _validate_repository_owner_authorization_response(
    response: str, authorization: Mapping[str, Any]
) -> None:
    _validate_repository_phase_authorization(authorization)
    expected = "\n".join(
        (
            "SIMULATE_GUG365_UPSTREAM_REPOSITORY_V1",
            f"phase={authorization['phase']}",
            f"authorization_digest={authorization['authorization_digest']}",
        )
    )
    if response != expected:
        _fail("OWNER_AUTHORIZATION_RESPONSE_INVALID")


SOURCE_CONTRACT_GAPS = (
    "IDENTITY_CENTER_PROVIDER_OUTPUT_POLLING",
    "IDENTITY_CENTER_PROVISIONED_ROLE_ARN_CAUSALITY",
    "KMS_ARTIFACT_USE_POLICY",
    "S3_ARTIFACT_BUCKET_POLICY",
    "SIGNER_DESTINATION_POLICY_AND_RESULT_PROJECTION",
    "LIVE_PRIVATE_ORCHESTRATOR",
)


def build_phase_executor_authority_evidence(*_args: Any, **_kwargs: Any) -> None:
    """Reject public authority compilation until current main closes its gaps."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_phase_executor_authority_evidence(
    _record: Mapping[str, Any],
) -> None:
    """No serialized executor evidence is public authority in this branch."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def build_phase_authorization(*_args: Any, **_kwargs: Any) -> None:
    """Reject phase authorization before any private ledger claim or write."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_phase_authorization(record: Mapping[str, Any]) -> None:
    """Validate only the public fail-closed source-contract checkpoint."""

    keys = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "upstream_issue",
        "consumer_issue",
        "environment",
        "production",
        "production_authorized",
        "production_status",
        "deployment_authorized",
        "consumer_writes_authorized",
        "decision",
        "state",
        "owner_authorization_issued",
        "phase",
        "source_head_sha",
        "source_merge_sha",
        "source_tree_sha",
        "gap_checkpoint_digest",
        "aws_calls_performed",
        "aws_mutations",
        "gug365_aws_writes",
        "gug357_create_stack",
        "gug215_effects",
        "gug206_effects",
        "missing_source_contracts",
        "next_action",
        "created_at",
        "checkpoint_digest",
    }
    _require_keys(record, keys, "AUTHORIZATION_STOP_CHECKPOINT_FIELDS_INVALID")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_phase_authorization.v1"
        or any(
            record.get(key) != value
            for key, value in _base(deployment_authorized=False).items()
        )
        or record.get("upstream_issue") != "GUG-376"
        or record.get("production_authorized") is not False
        or record.get("consumer_writes_authorized") is not False
        or record.get("decision") != "STOP"
        or record.get("state") != "STOP_UPSTREAM_SOURCE_CONTRACT_GAP"
        or record.get("owner_authorization_issued") is not False
        or record.get("phase") != "IDENTITY_CENTER_FOUNDATION"
        or record.get("gap_checkpoint_digest") != GAP_CHECKPOINT_DIGEST
        or any(
            record.get(field) != 0
            for field in (
                "aws_calls_performed",
                "aws_mutations",
                "gug365_aws_writes",
                "gug357_create_stack",
                "gug215_effects",
                "gug206_effects",
            )
        )
        or record.get("missing_source_contracts") != list(SOURCE_CONTRACT_GAPS)
        or record.get("next_action") != "MATERIALIZE_REVIEWED_SOURCE_CONTRACTS"
    ):
        _fail("AUTHORIZATION_STOP_CHECKPOINT_INVALID")
    _validate_source(record, "AUTHORIZATION_SOURCE_INVALID")
    _parse_timestamp(record.get("created_at"), "AUTHORIZATION_TIME_INVALID")
    _verify_record_digest(
        record,
        "checkpoint_digest",
        "AUTHORIZATION_STOP_CHECKPOINT_DIGEST_MISMATCH",
    )


def validate_owner_authorization_response(
    _response: str, _authorization: Mapping[str, Any]
) -> None:
    """No owner write authorization can be consumed from current main."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def _build_repository_phase_readback(
    *,
    execution_evidence: Mapping[str, Any],
    provider_readback_attestation_digest: str,
    observed_at: datetime,
) -> dict[str, Any]:
    try:
        from tooling.platform_authority_gug365_upstream_runner import (
            UpstreamRunnerError,
            validate_phase_execution_evidence,
        )

        validate_phase_execution_evidence(execution_evidence)
    except (ImportError, UpstreamRunnerError):
        _fail("PHASE_READBACK_EXECUTION_EVIDENCE_INVALID")
    _digest(provider_readback_attestation_digest, "PHASE_READBACK_ATTESTATION_DIGEST_INVALID")
    expected_attestation_digest = canonical_digest(
        {
            "preflight": execution_evidence[
                "provider_preflight_verification_digests"
            ],
            "operation": execution_evidence[
                "provider_operation_verification_digests"
            ],
            "projections": execution_evidence["provider_projection_digests"],
        }
    )
    if provider_readback_attestation_digest != expected_attestation_digest:
        _fail("PHASE_READBACK_ATTESTATION_BINDING_MISMATCH")
    results = list(execution_evidence["provider_result_digests"])
    readbacks = list(execution_evidence["observed_readback_digests"])
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_phase_readback.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "phase": execution_evidence["phase"],
        "authorization_digest": execution_evidence["authorization_digest"],
        "phase_execution_evidence_digest": execution_evidence[
            "phase_execution_evidence_digest"
        ],
        "provider_readback_attestation_digest": (
            provider_readback_attestation_digest
        ),
        "before_state_digest": execution_evidence[
            "authorization_before_state_digest"
        ],
        "final_state_digest": execution_evidence[
            "final_observed_readback_digest"
        ],
        "receipt_digest": execution_evidence["phase_receipt_digest"],
        "provider_result_digests": results,
        "observed_readback_digests": readbacks,
        "request_count": len(results),
        "readback_complete": True,
        "provider_certified": execution_evidence["provider_transcript_verified"],
        "provider_transcript_verified": execution_evidence[
            "provider_transcript_verified"
        ],
        "evidence_scope": execution_evidence["evidence_scope"],
        "raw_provider_responses_persisted": False,
        "sensitive_values_persisted": False,
        "observed_at": _timestamp(observed_at, "PHASE_READBACK_TIME_INVALID"),
    }
    record["phase_readback_digest"] = canonical_digest(record)
    _validate_repository_phase_readback(record)
    return record


def _validate_repository_phase_readback(record: Mapping[str, Any]) -> None:
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "phase",
        "authorization_digest", "phase_execution_evidence_digest",
        "provider_readback_attestation_digest", "before_state_digest",
        "final_state_digest", "receipt_digest", "provider_result_digests",
        "observed_readback_digests", "request_count",
        "readback_complete", "provider_certified", "provider_transcript_verified",
        "evidence_scope", "raw_provider_responses_persisted",
        "sensitive_values_persisted", "observed_at", "phase_readback_digest",
    }
    _require_keys(record, keys, "PHASE_READBACK_FIELDS_INVALID")
    results = record.get("provider_result_digests")
    readbacks = record.get("observed_readback_digests")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_phase_readback.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("phase") not in PHASE_NAMES
        or not isinstance(results, list)
        or not results
        or not isinstance(readbacks, list)
        or len(readbacks) != len(results)
        or not readbacks
        or record.get("final_state_digest") != readbacks[-1]
        or record.get("request_count") != len(results)
        or record.get("readback_complete") is not True
        or record.get("provider_certified") is not False
        or record.get("provider_transcript_verified") is not False
        or record.get("evidence_scope")
        != "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        or record.get("raw_provider_responses_persisted") is not False
        or record.get("sensitive_values_persisted") is not False
    ):
        _fail("PHASE_READBACK_INVALID")
    for field in (
        "authorization_digest", "phase_execution_evidence_digest",
        "provider_readback_attestation_digest", "before_state_digest",
        "final_state_digest", "receipt_digest",
    ):
        _digest(record.get(field), "PHASE_READBACK_DIGEST_INVALID")
    for value in [*results, *readbacks]:
        _digest(value, "PHASE_READBACK_RESULT_DIGEST_INVALID")
    _parse_timestamp(record.get("observed_at"), "PHASE_READBACK_TIME_INVALID")
    _verify_record_digest(record, "phase_readback_digest", "PHASE_READBACK_DIGEST_MISMATCH")


def _validate_resolved_phase_against_template(
    template_phase: Mapping[str, Any], resolved_phase: Mapping[str, Any]
) -> list[dict[str, Any]]:
    validate_phase_contract(template_phase)
    validate_phase_contract(resolved_phase)
    metadata = {
        "phase", "sequence", "inventory_target", "inventory_classification",
        "resolution", "causal_predecessor", "rollback_boundary",
    }
    if any(template_phase[field] != resolved_phase[field] for field in metadata):
        _fail("PHASE_CERTIFICATION_RESOLUTION_METADATA_MISMATCH")
    if len(template_phase["operations"]) != len(resolved_phase["operations"]):
        _fail("PHASE_CERTIFICATION_RESOLUTION_COUNT_MISMATCH")
    bindings: list[dict[str, Any]] = []
    immutable_operation_fields = {
        "sequence", "action", "target_digest", "required_slots",
        "expected_readback_digest",
    }
    for template, resolved in zip(
        template_phase["operations"], resolved_phase["operations"], strict=True
    ):
        if (
            any(template[field] != resolved[field] for field in immutable_operation_fields)
            or template["request_template"]["template_digest"]
            != resolved["request_template"]["template_digest"]
            or resolved["request_template"]["resolution_status"] != "EXACT_RESOLVED"
            or resolved["request_template"]["provider_generated_slots"]
            or resolved["request_digest_kind"] != "EXACT_REQUEST"
        ):
            _fail("PHASE_CERTIFICATION_RESOLUTION_BINDING_MISMATCH")
        bindings.append(
            {
                "sequence": template["sequence"],
                "template_digest": template["request_template"]["template_digest"],
                "resolved_request_digest": resolved["request_digest"],
                "resolved_operation_digest": resolved["operation_digest"],
            }
        )
    return bindings


def _validate_resolution_snapshot(
    template_phase: Mapping[str, Any],
    snapshot_phase: Mapping[str, Any],
    final_phase: Mapping[str, Any],
) -> None:
    validate_phase_contract(template_phase)
    validate_phase_contract(snapshot_phase)
    validate_phase_contract(final_phase)
    metadata = {
        "phase", "sequence", "inventory_target", "inventory_classification",
        "resolution", "causal_predecessor", "rollback_boundary",
    }
    if any(
        template_phase[field] != snapshot_phase[field]
        or template_phase[field] != final_phase[field]
        for field in metadata
    ) or not (
        len(template_phase["operations"])
        == len(snapshot_phase["operations"])
        == len(final_phase["operations"])
    ):
        _fail("PHASE_CERTIFICATION_RESOLUTION_SNAPSHOT_INVALID")
    immutable = {
        "sequence", "action", "target_digest", "required_slots",
        "expected_readback_digest",
    }
    for template, snapshot, final in zip(
        template_phase["operations"],
        snapshot_phase["operations"],
        final_phase["operations"],
        strict=True,
    ):
        if (
            any(
                template[field] != snapshot[field]
                or template[field] != final[field]
                for field in immutable
            )
            or template["request_template"]["template_digest"]
            != snapshot["request_template"]["template_digest"]
            or template["request_template"]["template_digest"]
            != final["request_template"]["template_digest"]
            or final["request_digest_kind"] != "EXACT_REQUEST"
            or final["request_template"]["provider_generated_slots"]
        ):
            _fail("PHASE_CERTIFICATION_RESOLUTION_SNAPSHOT_INVALID")
        if snapshot["request_digest_kind"] == "EXACT_REQUEST":
            if canonical_json(snapshot) != canonical_json(final):
                _fail("PHASE_CERTIFICATION_RESOLVED_REQUEST_DRIFT")
        elif (
            snapshot["request_digest_kind"] != "REQUEST_TEMPLATE"
            or not set(snapshot["request_template"]["provider_generated_slots"])
            .issubset(set(template["required_slots"]))
        ):
            _fail("PHASE_CERTIFICATION_RESOLUTION_SNAPSHOT_INVALID")


def _build_repository_phase_certification(
    *,
    plan: Mapping[str, Any],
    inventory: Mapping[str, Any],
    resolved_phase: Mapping[str, Any],
    phase_execution_bundles: Sequence[Mapping[str, Any]],
    phase_readbacks: Sequence[Mapping[str, Any]],
    provider_slot_bindings: Sequence[Mapping[str, Any]],
    causal_predecessor_certification_digest: str,
    observed_at: datetime,
) -> dict[str, Any]:
    """Certify one phase from inventory, exact auth batches, and attested readback."""

    _validate_repository_upstream_plan(plan)
    _validate_repository_stable_inventory(inventory)
    _digest(
        causal_predecessor_certification_digest,
        "PHASE_CERTIFICATION_PREDECESSOR_INVALID",
    )
    if (
        plan["inventory_digest"] != inventory["inventory_digest"]
        or plan["upstream_run_digest"] != inventory["upstream_run_digest"]
        or plan["owner_decisions_digest"] != inventory["owner_decisions_digest"]
        or plan["inventory_account_binding_digest"]
        != inventory["account_binding_digest"]
        or plan["inventory_caller_identity_digest"]
        != inventory["caller_identity_digest"]
        or plan["runtime_evidence_digest"]
        != inventory["runtime_evidence"]["runtime_evidence_digest"]
    ):
        _fail("PHASE_CERTIFICATION_INVENTORY_MISMATCH")
    sequence = resolved_phase.get("sequence")
    if not isinstance(sequence, int) or not 1 <= sequence <= len(PHASE_NAMES):
        _fail("PHASE_CERTIFICATION_SEQUENCE_INVALID")
    template_phase = plan["phases"][sequence - 1]
    inventory_binding = plan["phase_inventory_bindings"][sequence - 1]
    expected_inventory_binding = _phase_inventory_binding(inventory, template_phase)
    if canonical_json(inventory_binding) != canonical_json(expected_inventory_binding):
        _fail("PHASE_CERTIFICATION_INVENTORY_BINDING_MISMATCH")
    resolution_bindings = _validate_resolved_phase_against_template(
        template_phase, resolved_phase
    )
    slot_bindings = _snapshot(
        list(provider_slot_bindings), "PHASE_CERTIFICATION_SLOT_BINDINGS_INVALID"
    )
    by_slot: dict[str, Mapping[str, Any]] = {}
    required_slots: dict[str, list[int]] = {}
    for operation in template_phase["operations"]:
        for slot in operation["required_slots"]:
            required_slots.setdefault(slot, []).append(operation["sequence"])
    for binding in slot_bindings:
        if not isinstance(binding, Mapping):
            _fail("PHASE_CERTIFICATION_SLOT_BINDINGS_INVALID")
        _validate_repository_provider_slot_binding(binding)
        slot = binding["slot"]
        route = PROVIDER_SLOT_ROUTES[slot]
        if binding["producer_phase"] == template_phase["phase"]:
            producer_sequence = binding["producer_operation_sequence"]
            if not 1 <= producer_sequence <= len(template_phase["operations"]):
                _fail("PHASE_CERTIFICATION_SLOT_PRODUCER_MISMATCH")
            producer_operation = template_phase["operations"][producer_sequence - 1]
            _validate_slot_route_operation_binding(
                slot=slot,
                phase=template_phase["phase"],
                action=producer_operation["action"],
                inventory_resource=producer_operation["inventory_resource"],
                producer=True,
            )
        for consumer_sequence in binding["consumer_operation_sequences"]:
            if not 1 <= consumer_sequence <= len(template_phase["operations"]):
                _fail("PHASE_CERTIFICATION_SLOT_BINDING_MISMATCH")
            consumer_operation = template_phase["operations"][
                consumer_sequence - 1
            ]
            _validate_slot_route_operation_binding(
                slot=slot,
                phase=template_phase["phase"],
                action=consumer_operation["action"],
                inventory_resource=consumer_operation["inventory_resource"],
                producer=False,
            )
        if (
            slot in by_slot
            or binding["consumer_phase"] != template_phase["phase"]
            or binding["consumer_operation_sequences"] != required_slots.get(slot)
        ):
            _fail("PHASE_CERTIFICATION_SLOT_BINDING_MISMATCH")
        by_slot[slot] = binding
    if set(by_slot) != set(required_slots):
        _fail("PHASE_CERTIFICATION_SLOT_PROVENANCE_INCOMPLETE")

    execution_bundles = _snapshot(
        list(phase_execution_bundles), "PHASE_CERTIFICATION_EXECUTION_INVALID"
    )
    readbacks = _snapshot(
        list(phase_readbacks), "PHASE_CERTIFICATION_READBACK_INVALID"
    )
    operation_receipt_digests: list[str] = []
    authorization_digests: list[str] = []
    execution_digests: list[str] = []
    readback_digests: list[str] = []
    ledger_genesis_digests: list[str] = []
    ledger_terminal_digests: list[str] = []
    ledger_history_digests: list[str] = []
    operation_evidence: list[dict[str, Any]] = []
    provider_transcript_verification_digests = list(
        inventory.get("provider_transcript_verification_digests", [])
    )
    provider_verifier_identity_digest = inventory.get(
        "provider_verifier_identity_digest"
    )
    provider_attestation_root_digest = inventory.get(
        "provider_attestation_root_digest"
    )
    all_execution_provider_verified = True
    selected_resources = {
        name: inventory["resources"][name]
        for name in PHASE_INVENTORY_RESOURCES[template_phase["phase"]]
    }
    if template_phase["resolution"] == "EXACT_PRESENT_NO_TOUCH":
        if execution_bundles or readbacks or resolution_bindings or slot_bindings:
            _fail("PHASE_CERTIFICATION_NO_TOUCH_INVALID")
        if any(
            item["classification"] != "EXACT_PRESENT_NO_TOUCH"
            for item in selected_resources.values()
        ):
            _fail("PHASE_CERTIFICATION_NO_TOUCH_INVENTORY_INVALID")
        before_state_digest = inventory_binding["provider_before_state_digest"]
        final_state_digest = before_state_digest
        provider_readback_digest = canonical_digest(
            {
                "inventory_digest": inventory["inventory_digest"],
                "phase_inventory_binding_digest": inventory_binding[
                    "phase_inventory_binding_digest"
                ],
                "resources": selected_resources,
            }
        )
        operation_evidence = []
    else:
        if not execution_bundles or len(execution_bundles) != len(readbacks):
            _fail("PHASE_CERTIFICATION_EXECUTION_COUNT_INVALID")
        if any(
            item["classification"] != "ABSENT_READY"
            for item in selected_resources.values()
        ):
            _fail("PHASE_CERTIFICATION_MUTATION_INVENTORY_INVALID")
        try:
            from tooling.platform_authority_gug365_upstream_runner import (
                UpstreamRunnerError,
                build_phase_execution_evidence,
            )
        except ImportError:
            _fail("PHASE_CERTIFICATION_EXECUTION_VALIDATOR_UNAVAILABLE")
        combined_requests: list[str] = []
        expected_before_state = inventory_binding["provider_before_state_digest"]
        previous_snapshot: Mapping[str, Any] | None = None
        bundle_keys = {
            "history", "authorization", "owner_authorization_response",
            "owner_authorization_verification", "executor_authority_evidence",
            "execution_trust_anchor", "resolved_phase_snapshot",
        }
        for bundle, readback in zip(execution_bundles, readbacks, strict=True):
            if not isinstance(bundle, Mapping) or set(bundle) != bundle_keys:
                _fail("PHASE_CERTIFICATION_EXECUTION_BUNDLE_INVALID")
            snapshot_phase = bundle["resolved_phase_snapshot"]
            _validate_resolution_snapshot(
                template_phase, snapshot_phase, resolved_phase
            )
            if previous_snapshot is not None:
                for previous, current in zip(
                    previous_snapshot["operations"],
                    snapshot_phase["operations"],
                    strict=True,
                ):
                    if not set(
                        current["request_template"]["provider_generated_slots"]
                    ).issubset(
                        set(previous["request_template"]["provider_generated_slots"])
                    ):
                        _fail("PHASE_CERTIFICATION_SLOT_RESOLUTION_NOT_MONOTONIC")
            previous_snapshot = snapshot_phase
            try:
                execution = build_phase_execution_evidence(
                    history=bundle["history"],
                    authorization=bundle["authorization"],
                    owner_authorization_response=bundle[
                        "owner_authorization_response"
                    ],
                    owner_authorization_verification=bundle[
                        "owner_authorization_verification"
                    ],
                    executor_authority_evidence=bundle[
                        "executor_authority_evidence"
                    ],
                    execution_trust_anchor=bundle["execution_trust_anchor"],
                    resolved_phase=snapshot_phase,
                )
            except UpstreamRunnerError:
                _fail("PHASE_CERTIFICATION_EXECUTION_INVALID")
            authorization = bundle["authorization"]
            trust_anchor = bundle["execution_trust_anchor"]
            authority = bundle["executor_authority_evidence"]
            _validate_repository_phase_readback(readback)
            if (
                authorization["upstream_plan_digest"] != plan["plan_digest"]
                or authorization["run_id_digest"] != plan["upstream_run_digest"]
                or authorization["complete_write_set_digest"]
                != plan["complete_write_set_digest"]
                or authorization["account_or_management_binding_digest"]
                != plan["inventory_account_binding_digest"]
                or authorization["caller_identity_digest"]
                != plan["inventory_caller_identity_digest"]
                or authorization["private_ledger_root_digest"]
                != plan["private_ledger_root_digest"]
                or trust_anchor["private_ledger_root_digest"]
                != plan["private_ledger_root_digest"]
                or execution["causal_predecessor_certification_digest"]
                != causal_predecessor_certification_digest
                or execution["authorization_before_state_digest"]
                != expected_before_state
                or readback["phase"] != execution["phase"]
                or readback["authorization_digest"]
                != execution["authorization_digest"]
                or readback["phase_execution_evidence_digest"]
                != execution["phase_execution_evidence_digest"]
                or readback["before_state_digest"]
                != execution["authorization_before_state_digest"]
                or readback["final_state_digest"]
                != execution["final_observed_readback_digest"]
                or readback["receipt_digest"] != execution["phase_receipt_digest"]
                or readback["provider_result_digests"]
                != execution["provider_result_digests"]
                or readback["observed_readback_digests"]
                != execution["observed_readback_digests"]
                or readback["provider_certified"]
                is not execution["provider_transcript_verified"]
                or readback["provider_transcript_verified"]
                is not execution["provider_transcript_verified"]
                or readback["evidence_scope"] != execution["evidence_scope"]
                or readback["provider_readback_attestation_digest"]
                != canonical_digest(
                    {
                        "preflight": execution[
                            "provider_preflight_verification_digests"
                        ],
                        "operation": execution[
                            "provider_operation_verification_digests"
                        ],
                        "projections": execution["provider_projection_digests"],
                    }
                )
            ):
                _fail("PHASE_CERTIFICATION_CAUSAL_BINDING_MISMATCH")
            readback_time = _parse_timestamp(
                readback["observed_at"], "PHASE_CERTIFICATION_READBACK_TIME_INVALID"
            )
            if not (
                _parse_timestamp(
                    authorization["not_before"],
                    "PHASE_CERTIFICATION_READBACK_TIME_INVALID",
                )
                <= readback_time
                <= _parse_timestamp(
                    authority["session_expires_at"],
                    "PHASE_CERTIFICATION_READBACK_TIME_INVALID",
                )
            ):
                _fail("PHASE_CERTIFICATION_READBACK_TIME_INVALID")
            selected_by_request = {
                item["request_digest"]: item for item in snapshot_phase["operations"]
            }
            terminal = bundle["history"][-1]
            receipt_by_request = {
                outcome["operation_receipt"]["request_digest"]: outcome[
                    "operation_receipt"
                ]
                for outcome in terminal["outcomes"]
                if outcome.get("operation_receipt") is not None
            }
            for request_digest, receipt_digest, provider_digest, observed_digest in zip(
                execution["ordered_request_digests"],
                execution["operation_receipt_digests"],
                execution["provider_result_digests"],
                execution["observed_readback_digests"],
                strict=True,
            ):
                operation = selected_by_request[request_digest]
                operation_receipt = receipt_by_request.get(request_digest)
                if operation_receipt is None:
                    _fail("PHASE_CERTIFICATION_OPERATION_RECEIPT_MISSING")
                transcript = operation_receipt["provider_operation_verification"]
                if inventory.get("provider_transcript_verified") is True and (
                    transcript["verifier_identity_digest"]
                    != provider_verifier_identity_digest
                    or transcript["attestation_root_digest"]
                    != provider_attestation_root_digest
                ):
                    _fail("PHASE_CERTIFICATION_PROVIDER_TRUST_ROOT_DRIFT")
                projection_digests = sorted(
                    projection["projection_digest"]
                    for projection in transcript["projections"]
                )
                operation_evidence.append(
                    {
                        "sequence": operation["sequence"],
                        "action": operation["action"],
                        "request_digest": request_digest,
                        "authorization_digest": execution["authorization_digest"],
                        "operation_receipt_digest": receipt_digest,
                        "provider_result_digest": provider_digest,
                        "observed_readback_digest": observed_digest,
                        "provider_transcript_verification_digest": transcript[
                            "verification_digest"
                        ],
                        "provider_projection_digests": projection_digests,
                        "terminal_ledger_digest": terminal["ledger_digest"],
                    }
                )
            combined_requests.extend(execution["ordered_request_digests"])
            operation_receipt_digests.extend(execution["operation_receipt_digests"])
            authorization_digests.append(execution["authorization_digest"])
            execution_digests.append(execution["phase_execution_evidence_digest"])
            readback_digests.append(readback["phase_readback_digest"])
            ledger_genesis_digests.append(execution["ledger_genesis_digest"])
            ledger_terminal_digests.append(execution["ledger_terminal_digest"])
            ledger_history_digests.append(execution["ledger_history_digest"])
            provider_transcript_verification_digests.extend(
                execution["provider_preflight_verification_digests"]
            )
            provider_transcript_verification_digests.extend(
                execution["provider_operation_verification_digests"]
            )
            all_execution_provider_verified = (
                all_execution_provider_verified
                and execution["provider_transcript_verified"] is True
            )
            expected_before_state = execution["final_observed_readback_digest"]
        if combined_requests != [
            operation["request_digest"] for operation in resolved_phase["operations"]
        ]:
            _fail("PHASE_CERTIFICATION_COMPLETE_WRITE_SET_MISMATCH")
        if any(
            len(set(values)) != len(values)
            for values in (
                authorization_digests, execution_digests, readback_digests,
                ledger_genesis_digests, ledger_terminal_digests,
                ledger_history_digests, operation_receipt_digests,
            )
        ):
            _fail("PHASE_CERTIFICATION_REPLAY_DETECTED")
        evidence_by_sequence = {item["sequence"]: item for item in operation_evidence}
        for slot_binding in slot_bindings:
            if slot_binding["producer_phase"] == template_phase["phase"]:
                producer = evidence_by_sequence.get(
                    slot_binding["producer_operation_sequence"]
                )
                if producer is None or any(
                    producer[field] != slot_binding[binding_field]
                    for field, binding_field in (
                        ("authorization_digest", "producer_authorization_digest"),
                        ("operation_receipt_digest", "producer_operation_receipt_digest"),
                        ("provider_result_digest", "producer_provider_result_digest"),
                        ("observed_readback_digest", "producer_readback_digest"),
                        (
                            "provider_transcript_verification_digest",
                            "producer_transcript_verification_digest",
                        ),
                        (
                            "provider_projection_digests",
                            "producer_projection_digests",
                        ),
                    )
                ):
                    _fail("PHASE_CERTIFICATION_SLOT_PRODUCER_MISMATCH")
        before_state_digest = inventory_binding["provider_before_state_digest"]
        final_state_digest = expected_before_state
        provider_readback_digest = canonical_digest(readback_digests)

    ledger_digest = canonical_digest(
        {
            "genesis": ledger_genesis_digests,
            "terminal": ledger_terminal_digests,
            "history": ledger_history_digests,
        }
    )
    provider_transcript_verified = (
        inventory.get("provider_transcript_verified") is True
        and (
            template_phase["resolution"] == "EXACT_PRESENT_NO_TOUCH"
            or all_execution_provider_verified
        )
    )
    evidence_scope = (
        "LIVE_AUTHORITY_NON_PRODUCTION"
        if provider_transcript_verified
        else "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
    )
    provider_transcript_chain_digest = canonical_digest(
        provider_transcript_verification_digests
    )
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_phase_certification.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "phase": template_phase["phase"],
        "sequence": template_phase["sequence"],
        "resolution": template_phase["resolution"],
        "causal_predecessor_certification_digest": (
            causal_predecessor_certification_digest
        ),
        "phase_inventory_binding_digest": inventory_binding[
            "phase_inventory_binding_digest"
        ],
        "template_phase_operation_digest": template_phase["phase_operation_digest"],
        "template_phase_mutation_digest": template_phase["phase_mutation_digest"],
        "resolved_phase_operation_digest": resolved_phase["phase_operation_digest"],
        "resolved_phase_mutation_digest": resolved_phase["phase_mutation_digest"],
        "provider_slot_binding_digests": [
            item["slot_binding_digest"] for item in slot_bindings
        ],
        "causal_resolution_digest": canonical_digest(
            {
                "operation_bindings": resolution_bindings,
                "provider_slot_binding_digests": [
                    item["slot_binding_digest"] for item in slot_bindings
                ],
            }
        ),
        "before_state_digest": before_state_digest,
        "final_state_digest": final_state_digest,
        "provider_readback_digest": provider_readback_digest,
        "inventory_digest": inventory["inventory_digest"],
        "authorization_digests": authorization_digests,
        "phase_execution_evidence_digests": execution_digests,
        "phase_readback_digests": readback_digests,
        "ledger_genesis_digests": ledger_genesis_digests,
        "ledger_terminal_digests": ledger_terminal_digests,
        "ledger_history_digests": ledger_history_digests,
        "ledger_digest": ledger_digest,
        "operation_receipt_digests": operation_receipt_digests,
        "operation_evidence": operation_evidence,
        "provider_transcript_verification_digests": (
            provider_transcript_verification_digests
        ),
        "provider_transcript_chain_digest": provider_transcript_chain_digest,
        "provider_verifier_identity_digest": provider_verifier_identity_digest,
        "provider_attestation_root_digest": provider_attestation_root_digest,
        "operation_count": len(template_phase["operations"]),
        "aws_write_attempt_count": len(operation_receipt_digests),
        "readback_complete": True,
        "provider_certified": provider_transcript_verified,
        "provider_transcript_verified": provider_transcript_verified,
        "evidence_scope": evidence_scope,
        "no_touch": template_phase["resolution"] == "EXACT_PRESENT_NO_TOUCH",
        "raw_provider_responses_persisted": False,
        "sensitive_values_persisted": False,
        "observed_at": _timestamp(observed_at, "PHASE_CERTIFICATION_TIME_INVALID"),
    }
    record["phase_certification_digest"] = canonical_digest(record)
    _validate_repository_phase_certification(record)
    return record


def _validate_repository_phase_certification(record: Mapping[str, Any]) -> None:
    digest_lists = {
        "authorization_digests", "phase_execution_evidence_digests",
        "phase_readback_digests", "ledger_genesis_digests",
        "ledger_terminal_digests", "ledger_history_digests",
        "operation_receipt_digests",
        "provider_slot_binding_digests",
        "provider_transcript_verification_digests",
    }
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "phase", "sequence",
        "resolution", "template_phase_operation_digest",
        "causal_predecessor_certification_digest",
        "phase_inventory_binding_digest",
        "template_phase_mutation_digest", "resolved_phase_operation_digest",
        "resolved_phase_mutation_digest", "causal_resolution_digest",
        "before_state_digest", "final_state_digest", "provider_readback_digest",
        "inventory_digest", "ledger_digest", "operation_evidence", "operation_count",
        "aws_write_attempt_count", "readback_complete", "provider_certified",
        "provider_transcript_verified", "provider_transcript_chain_digest",
        "provider_verifier_identity_digest", "provider_attestation_root_digest",
        "evidence_scope", "no_touch", "raw_provider_responses_persisted",
        "sensitive_values_persisted", "observed_at", "phase_certification_digest",
        *digest_lists,
    }
    _require_keys(record, keys, "PHASE_CERTIFICATION_FIELDS_INVALID")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_phase_certification.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("phase") not in PHASE_NAMES
        or record.get("sequence") != PHASE_NAMES.index(record["phase"]) + 1
        or record.get("resolution") not in {"MUTATE", "EXACT_PRESENT_NO_TOUCH"}
        or not isinstance(record.get("operation_count"), int)
        or isinstance(record.get("operation_count"), bool)
        or not isinstance(record.get("aws_write_attempt_count"), int)
        or isinstance(record.get("aws_write_attempt_count"), bool)
        or record.get("readback_complete") is not True
        or record.get("provider_certified") is not False
        or record.get("provider_transcript_verified") is not False
        or record.get("evidence_scope")
        != "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        or record.get("raw_provider_responses_persisted") is not False
        or record.get("sensitive_values_persisted") is not False
    ):
        _fail("PHASE_CERTIFICATION_INVALID")
    for field in (
        "template_phase_operation_digest", "template_phase_mutation_digest",
        "resolved_phase_operation_digest", "resolved_phase_mutation_digest",
        "causal_resolution_digest", "before_state_digest", "final_state_digest",
        "provider_readback_digest", "inventory_digest", "ledger_digest",
        "causal_predecessor_certification_digest",
        "phase_inventory_binding_digest",
        "provider_transcript_chain_digest",
    ):
        _digest(record.get(field), "PHASE_CERTIFICATION_DIGEST_INVALID")
    verifier_identity = record.get("provider_verifier_identity_digest")
    attestation_root = record.get("provider_attestation_root_digest")
    if verifier_identity is not None or attestation_root is not None:
        _fail("PHASE_CERTIFICATION_UNATTESTED_TRUST_ROOT_INVALID")
    for field in digest_lists:
        values = record.get(field)
        if not isinstance(values, list):
            _fail("PHASE_CERTIFICATION_DIGEST_LIST_INVALID")
        for value in values:
            _digest(value, "PHASE_CERTIFICATION_DIGEST_LIST_INVALID")
    batch_count = len(record["authorization_digests"])
    if any(
        len(record[field]) != batch_count
        for field in digest_lists
        - {
            "operation_receipt_digests",
            "provider_slot_binding_digests",
            "provider_transcript_verification_digests",
        }
    ):
        _fail("PHASE_CERTIFICATION_BATCH_COUNT_INVALID")
    if record["resolution"] == "EXACT_PRESENT_NO_TOUCH":
        if (
            batch_count != 0
            or record["operation_receipt_digests"]
            or record["provider_slot_binding_digests"]
            or record["operation_count"] != 0
            or record["aws_write_attempt_count"] != 0
            or record.get("no_touch") is not True
            or record["before_state_digest"] != record["final_state_digest"]
        ):
            _fail("PHASE_CERTIFICATION_NO_TOUCH_INVALID")
    elif (
        batch_count == 0
        or len(record["operation_receipt_digests"]) != record["operation_count"]
        or record["aws_write_attempt_count"] != record["operation_count"]
        or record.get("no_touch") is not False
    ):
        _fail("PHASE_CERTIFICATION_MUTATION_INVALID")
    operation_evidence = record.get("operation_evidence")
    evidence_keys = {
        "sequence", "action", "request_digest", "authorization_digest",
        "operation_receipt_digest", "provider_result_digest",
        "observed_readback_digest", "provider_transcript_verification_digest",
        "provider_projection_digests", "terminal_ledger_digest",
    }
    if not isinstance(operation_evidence, list) or len(operation_evidence) != record[
        "operation_count"
    ]:
        _fail("PHASE_CERTIFICATION_OPERATION_EVIDENCE_INVALID")
    for sequence, evidence in enumerate(operation_evidence, start=1):
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != evidence_keys
            or evidence.get("sequence") != sequence
            or not isinstance(evidence.get("action"), str)
            or evidence["action"] not in REQUIRED_ACTIONS[record["phase"]]
        ):
            _fail("PHASE_CERTIFICATION_OPERATION_EVIDENCE_INVALID")
        projection_digests = evidence.get("provider_projection_digests")
        if (
            not isinstance(projection_digests, list)
            or projection_digests != sorted(set(projection_digests))
        ):
            _fail("PHASE_CERTIFICATION_OPERATION_EVIDENCE_INVALID")
        for value in projection_digests:
            _digest(value, "PHASE_CERTIFICATION_OPERATION_EVIDENCE_INVALID")
        for field in evidence_keys - {
            "sequence", "action", "provider_projection_digests"
        }:
            _digest(
                evidence.get(field),
                "PHASE_CERTIFICATION_OPERATION_EVIDENCE_INVALID",
            )
    expected_ledger_digest = canonical_digest(
        {
            "genesis": record["ledger_genesis_digests"],
            "terminal": record["ledger_terminal_digests"],
            "history": record["ledger_history_digests"],
        }
    )
    if record["ledger_digest"] != expected_ledger_digest:
        _fail("PHASE_CERTIFICATION_LEDGER_DIGEST_MISMATCH")
    if record["provider_transcript_chain_digest"] != canonical_digest(
        record["provider_transcript_verification_digests"]
    ):
        _fail("PHASE_CERTIFICATION_PROVIDER_TRANSCRIPT_CHAIN_MISMATCH")
    _parse_timestamp(record.get("observed_at"), "PHASE_CERTIFICATION_TIME_INVALID")
    _verify_record_digest(
        record, "phase_certification_digest", "PHASE_CERTIFICATION_DIGEST_MISMATCH"
    )


def _validate_consumer_source_contracts(
    *,
    gug363_intent: Mapping[str, Any],
    gug363_plan: Mapping[str, Any],
    ledger_factory_signing_contract: Mapping[str, Any],
    repo_root: Path | None,
) -> dict[str, Any]:
    try:
        from tooling import platform_authority_retirement_entrypoint_materializer as gug363
        from tooling import (
            platform_authority_retirement_entrypoint_service_role_materializer as service_role,
        )

        gug363.validate_materialization_intent(gug363_intent)
        gug363.validate_materialization_plan(gug363_plan, repo_root=repo_root)
        if (
            gug363_plan.get("intent_digest") != gug363_intent.get("intent_digest")
            or gug363_plan.get("artifact_signing_contract_digest")
            != gug363_intent.get("artifact_signing_contract_digest")
        ):
            _fail("HANDOFF_GUG363_CONTRACT_CHAIN_MISMATCH")
        factory_digest = service_role.ledger_factory_artifact_signing_contract_digest(
            ledger_factory_signing_contract
        )
        if repo_root is not None:
            service_role._validate_ledger_factory_artifact_signing_contract(
                contract=ledger_factory_signing_contract,
                expected_contract_digest=factory_digest,
                gug363_plan=gug363_plan,
                repo_root=repo_root,
            )
        broker_contract = gug363_plan["artifact_signing_contract"]
        broker_unsigned = broker_contract["unsigned_source"]
        broker_signer = broker_contract["signer"]
        broker_signed = broker_contract["signed_destination"]
        ledger_unsigned = ledger_factory_signing_contract["unsigned_source"]
        ledger_signer = ledger_factory_signing_contract["signer"]
        ledger_signed = ledger_factory_signing_contract["signed_destination"]
        parameter_values = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in gug363_plan["parameter_projection"]
        }
    except UpstreamPrerequisiteError:
        raise
    except Exception:
        _fail("HANDOFF_SOURCE_CONTRACT_VALIDATION_FAILED")
    return {
        "gug363_intent_digest": str(gug363_intent["intent_digest"]),
        "gug363_plan_digest": str(gug363_plan["plan_digest"]),
        "ledger_factory_signing_contract_digest": factory_digest,
        "broker_unsigned_package_manifest_digest": str(
            broker_unsigned["manifest_digest"]
        ),
        "broker_unsigned_object_digest": canonical_digest(broker_unsigned),
        "broker_signing_job_digest": canonical_digest(broker_signer),
        "broker_signed_object_digest": canonical_digest(broker_signed),
        "broker_unsigned_readback_digest": canonical_digest(broker_unsigned),
        "broker_signing_readback_digest": gug363.artifact_signing_evidence_digest(
            broker_contract
        ),
        "ledger_factory_unsigned_package_manifest_digest": str(
            ledger_factory_signing_contract["package_manifest"]["manifest_digest"]
        ),
        "ledger_factory_unsigned_object_digest": canonical_digest(ledger_unsigned),
        "ledger_factory_signing_job_digest": canonical_digest(ledger_signer),
        "ledger_factory_signed_object_digest": canonical_digest(ledger_signed),
        "ledger_factory_unsigned_readback_digest": canonical_digest(
            ledger_unsigned
        ),
        "ledger_factory_signing_readback_digest": (
            service_role._ledger_factory_signing_evidence_digest(
                ledger_factory_signing_contract
            )
        ),
        "foundation_target_digests": {
            "artifact_bucket": canonical_digest(
                {"bucket": broker_unsigned["bucket"]}
            ),
            "kms_key": canonical_digest(
                {"sse_kms_key_arn": broker_unsigned["sse_kms_key_arn"]}
            ),
            "signing_profile": canonical_digest(
                {
                    key: broker_signer[key]
                    for key in (
                        "platform_id", "profile_name", "profile_version_id",
                        "profile_version_arn",
                    )
                }
            ),
            "code_signing_config": canonical_digest(
                broker_contract["code_signing_config"]
            ),
            "identity_center_application": canonical_digest(
                {
                    "application_arn": parameter_values[
                        "IdentityCenterApplicationArn"
                    ],
                    "redirect_uri": parameter_values[
                        "IdentityCenterRedirectUri"
                    ],
                }
            ),
            "classifier_permission_set": canonical_digest(
                {"name": "ScanalyzeAuthorityRetireClass"}
            ),
            "approver_permission_set": canonical_digest(
                {"name": "ScanalyzeAuthorityRetireApprove"}
            ),
            "classifier_permission_set_role": canonical_digest(
                {
                    "role_arn": parameter_values[
                        "ClassifierPermissionSetRoleArn"
                    ]
                }
            ),
            "approver_permission_set_role": canonical_digest(
                {
                    "role_arn": parameter_values[
                        "ApproverPermissionSetRoleArn"
                    ]
                }
            ),
            "broker_unsigned_object": canonical_digest(broker_unsigned),
            "broker_signing_job": canonical_digest(broker_signer),
            "broker_signed_object": canonical_digest(broker_signed),
            "ledger_factory_unsigned_object": canonical_digest(ledger_unsigned),
            "ledger_factory_signing_job": canonical_digest(ledger_signer),
            "ledger_factory_signed_object": canonical_digest(ledger_signed),
        },
        "runtime_version_arn_digest": canonical_digest(
            broker_contract["runtime_version_arn"]
            if "runtime_version_arn" in broker_contract
            else parameter_values["BrokerRuntimeVersionArn"]
        ),
    }


def validate_negative_evidence_verification(record: Mapping[str, Any]) -> None:
    """Validate the external proof that no unplanned provider state exists."""

    _fail("STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED")

    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "evidence_origin",
        "verifier_identity_digest", "attestation_root_digest",
        "upstream_plan_digest", "inventory_digest", "account_binding_digest",
        "caller_identity_digest", "phase_certification_digests",
        "provider_transcript_chain_digest", "unexpected_resources_found",
        "unexpected_assignments_found", "unexpected_publishers_found",
        "unexpected_additive_grants_found", "readback_complete",
        "external_attestation_receipt_digest", "verified_at",
        "verification_digest",
    }
    _require_keys(record, keys, "NEGATIVE_EVIDENCE_FIELDS_INVALID")
    phase_digests = record.get("phase_certification_digests")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_negative_evidence_verification.v1"
        or record.get("schema_version") != 1
        or record.get("implementation_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "authority-non-production"
        or record.get("production") is not False
        or record.get("production_status") != "NO-GO"
        or record.get("evidence_origin") != "EXTERNALLY_ATTESTED_PROVIDER"
        or not isinstance(phase_digests, list)
        or len(phase_digests) != len(PHASE_NAMES)
        or len(set(phase_digests)) != len(PHASE_NAMES)
        or record.get("unexpected_resources_found") is not False
        or record.get("unexpected_assignments_found") is not False
        or record.get("unexpected_publishers_found") is not False
        or record.get("unexpected_additive_grants_found") is not False
        or record.get("readback_complete") is not True
    ):
        _fail("NEGATIVE_EVIDENCE_INVALID")
    for field in (
        "verifier_identity_digest", "attestation_root_digest",
        "upstream_plan_digest", "inventory_digest", "account_binding_digest",
        "caller_identity_digest", "provider_transcript_chain_digest",
        "external_attestation_receipt_digest",
    ):
        _digest(record.get(field), "NEGATIVE_EVIDENCE_DIGEST_INVALID")
    for value in phase_digests:
        _digest(value, "NEGATIVE_EVIDENCE_DIGEST_INVALID")
    _parse_timestamp(record.get("verified_at"), "NEGATIVE_EVIDENCE_TIME_INVALID")
    _verify_record_digest(
        record, "verification_digest", "NEGATIVE_EVIDENCE_DIGEST_MISMATCH"
    )


def _verify_final_negative_evidence(
    *,
    verifier: Any,
    opaque_receipt: Mapping[str, Any],
    plan: Mapping[str, Any],
    inventory: Mapping[str, Any],
    certifications: Sequence[Mapping[str, Any]],
    provider_transcript_chain_digest: str,
    evaluated_at: datetime,
) -> dict[str, Any]:
    identity = getattr(verifier, "identity_digest", None)
    verify = getattr(verifier, "verify_negative_evidence", None)
    if not callable(identity) or not callable(verify):
        _fail("NEGATIVE_EVIDENCE_VERIFIER_REQUIRED")
    try:
        identity_digest = identity()
    except Exception:
        _fail("NEGATIVE_EVIDENCE_VERIFIER_IDENTITY_INVALID")
    if not isinstance(opaque_receipt, Mapping):
        _fail("NEGATIVE_EVIDENCE_RECEIPT_INVALID")
    expected_identity = certifications[0]["provider_verifier_identity_digest"]
    expected_root = certifications[0]["provider_attestation_root_digest"]
    if (
        identity_digest != expected_identity
        or any(
            certification["provider_verifier_identity_digest"] != expected_identity
            or certification["provider_attestation_root_digest"] != expected_root
            for certification in certifications
        )
    ):
        _fail("NEGATIVE_EVIDENCE_TRUST_ROOT_MISMATCH")
    try:
        record = dict(
            verify(
                opaque_receipt=opaque_receipt,
                plan=plan,
                inventory=inventory,
                phase_certifications=certifications,
                provider_transcript_chain_digest=provider_transcript_chain_digest,
                evaluated_at=evaluated_at,
            )
        )
        validate_negative_evidence_verification(record)
    except UpstreamPrerequisiteError:
        raise
    except Exception:
        _fail("NEGATIVE_EVIDENCE_VERIFICATION_FAILED")
    if (
        record["verifier_identity_digest"] != expected_identity
        or record["attestation_root_digest"] != expected_root
        or record["upstream_plan_digest"] != plan["plan_digest"]
        or record["inventory_digest"] != inventory["inventory_digest"]
        or record["account_binding_digest"] != inventory["account_binding_digest"]
        or record["caller_identity_digest"] != inventory["caller_identity_digest"]
        or record["phase_certification_digests"]
        != [item["phase_certification_digest"] for item in certifications]
        or record["provider_transcript_chain_digest"]
        != provider_transcript_chain_digest
        or _parse_timestamp(record["verified_at"], "NEGATIVE_EVIDENCE_TIME_INVALID")
        > evaluated_at.astimezone(UTC)
    ):
        _fail("NEGATIVE_EVIDENCE_CAUSAL_BINDING_MISMATCH")
    return record


def _build_repository_final_handoff(
    *,
    plan: Mapping[str, Any],
    phase_certification_bundles: Sequence[Mapping[str, Any]],
    gug363_intent: Mapping[str, Any],
    gug363_plan: Mapping[str, Any],
    ledger_factory_signing_contract: Mapping[str, Any],
    repo_root: Path,
    residual_risks: Sequence[str],
    created_at: datetime,
    negative_evidence_verifier: Any | None = None,
    negative_evidence_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a repository or LIVE handoff from a complete causal evidence chain."""

    _validate_repository_upstream_plan(plan)
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        _fail("HANDOFF_REPO_ROOT_INVALID")
    bundles = list(phase_certification_bundles)
    if len(bundles) != len(PHASE_NAMES):
        _fail("HANDOFF_PHASE_CERTIFICATIONS_INVALID")
    bundle_keys = {
        "inventory", "resolved_phase", "phase_execution_bundles",
        "phase_readbacks", "provider_slot_bindings",
        "causal_predecessor_certification_digest", "observed_at",
    }
    certifications: list[dict[str, Any]] = []
    resolved_phases: dict[str, Mapping[str, Any]] = {}
    prior_operation_evidence: dict[tuple[str, int], Mapping[str, Any]] = {}
    slot_assignments: dict[str, tuple[Any, ...]] = {}
    previous_certification_digest = canonical_digest(
        {
            "domain": "GUG376_PHASE_CHAIN_GENESIS",
            "plan_digest": plan["plan_digest"],
            "inventory_digest": plan["inventory_digest"],
        }
    )
    for planned_phase, bundle in zip(plan["phases"], bundles, strict=True):
        if not isinstance(bundle, Mapping) or set(bundle) != bundle_keys:
            _fail("HANDOFF_PHASE_CERTIFICATION_BUNDLE_INVALID")
        if (
            bundle["causal_predecessor_certification_digest"]
            != previous_certification_digest
        ):
            _fail("HANDOFF_PHASE_PREDECESSOR_MISMATCH")
        for slot_binding in bundle["provider_slot_bindings"]:
            _validate_repository_provider_slot_binding(slot_binding)
            route = PROVIDER_SLOT_ROUTES[slot_binding["slot"]]
            if any(
                sequence > len(planned_phase["operations"])
                or (
                    planned_phase["phase"],
                    planned_phase["operations"][sequence - 1]["action"],
                ) not in route["consumers"]
                for sequence in slot_binding["consumer_operation_sequences"]
            ):
                _fail("HANDOFF_PROVIDER_SLOT_CONSUMER_ROUTE_INVALID")
            assignment = (
                slot_binding["value_digest"],
                slot_binding["producer_phase"],
                slot_binding["producer_operation_sequence"],
                slot_binding["producer_authorization_digest"],
                slot_binding["producer_operation_receipt_digest"],
                slot_binding["producer_provider_result_digest"],
                slot_binding["producer_readback_digest"],
                slot_binding["producer_transcript_verification_digest"],
                tuple(slot_binding["producer_projection_digests"]),
                slot_binding["producer_phase_certification_digest"],
            )
            previous_assignment = slot_assignments.setdefault(
                slot_binding["slot"], assignment
            )
            if previous_assignment != assignment:
                _fail("HANDOFF_PROVIDER_SLOT_REASSIGNMENT")
            if slot_binding["producer_phase"] != planned_phase["phase"]:
                producer_certification = next(
                    (
                        item
                        for item in certifications
                        if item["phase"] == slot_binding["producer_phase"]
                    ),
                    None,
                )
                producer = prior_operation_evidence.get(
                    (
                        slot_binding["producer_phase"],
                        slot_binding["producer_operation_sequence"],
                    )
                )
                if (
                    producer_certification is None
                    or producer_certification["phase_certification_digest"]
                    != slot_binding["producer_phase_certification_digest"]
                    or producer is None
                    or any(
                        producer[field] != slot_binding[binding_field]
                        for field, binding_field in (
                        ("authorization_digest", "producer_authorization_digest"),
                        ("operation_receipt_digest", "producer_operation_receipt_digest"),
                        ("provider_result_digest", "producer_provider_result_digest"),
                        ("observed_readback_digest", "producer_readback_digest"),
                            (
                                "provider_transcript_verification_digest",
                                "producer_transcript_verification_digest",
                            ),
                            (
                                "provider_projection_digests",
                                "producer_projection_digests",
                            ),
                        )
                    )
                ):
                    _fail("HANDOFF_PROVIDER_SLOT_PRODUCER_MISMATCH")
        certification = _build_repository_phase_certification(
            plan=plan,
            inventory=bundle["inventory"],
            resolved_phase=bundle["resolved_phase"],
            phase_execution_bundles=bundle["phase_execution_bundles"],
            phase_readbacks=bundle["phase_readbacks"],
            provider_slot_bindings=bundle["provider_slot_bindings"],
            causal_predecessor_certification_digest=bundle[
                "causal_predecessor_certification_digest"
            ],
            observed_at=bundle["observed_at"],
        )
        if (
            certification["phase"] != planned_phase["phase"]
            or certification["sequence"] != planned_phase["sequence"]
            or certification["resolution"] != planned_phase["resolution"]
            or certification["template_phase_operation_digest"]
            != planned_phase["phase_operation_digest"]
            or certification["template_phase_mutation_digest"]
            != planned_phase["phase_mutation_digest"]
            or certification["inventory_digest"] != plan["inventory_digest"]
        ):
            _fail("HANDOFF_PHASE_PLAN_BINDING_MISMATCH")
        certifications.append(certification)
        for evidence in certification["operation_evidence"]:
            key = (certification["phase"], evidence["sequence"])
            if key in prior_operation_evidence:
                _fail("HANDOFF_OPERATION_EVIDENCE_REPLAY")
            prior_operation_evidence[key] = evidence
        resolved_phases[certification["phase"]] = bundle["resolved_phase"]
        previous_certification_digest = certification["phase_certification_digest"]
    source_digests = _validate_consumer_source_contracts(
        gug363_intent=gug363_intent,
        gug363_plan=gug363_plan,
        ledger_factory_signing_contract=ledger_factory_signing_contract,
        repo_root=repo_root,
    )
    stable_inventory = bundles[0]["inventory"]
    if any(
        stable_inventory["resources"][resource_name]["target_contract"][
            "source_target_digest"
        ]
        != target_digest
        for resource_name, target_digest in source_digests[
            "foundation_target_digests"
        ].items()
    ):
        _fail("HANDOFF_FOUNDATION_TARGET_BINDING_MISMATCH")
    if (
        stable_inventory["runtime_evidence"]["runtime_version_arn_digest"]
        != source_digests["runtime_version_arn_digest"]
    ):
        _fail("HANDOFF_RUNTIME_SOURCE_BINDING_MISMATCH")
    risks = _snapshot(list(residual_risks), "HANDOFF_RESIDUAL_RISKS_INVALID")
    if (
        not risks
        or not all(isinstance(value, str) and value for value in risks)
        or len(set(risks)) != len(risks)
    ):
        _fail("HANDOFF_RESIDUAL_RISKS_INVALID")
    artifact_readback_bindings = {
        "BROKER_UNSIGNED_PUBLISH": (
            source_digests["broker_unsigned_readback_digest"],
            {
                "broker_unsigned_object": source_digests[
                    "broker_unsigned_object_digest"
                ]
            },
        ),
        "BROKER_SIGNING_JOB": (
            source_digests["broker_signing_readback_digest"],
            {
                "broker_signing_job": source_digests["broker_signing_job_digest"],
                "broker_signed_object": source_digests[
                    "broker_signed_object_digest"
                ],
            },
        ),
        "LEDGER_FACTORY_UNSIGNED_PUBLISH": (
            source_digests["ledger_factory_unsigned_readback_digest"],
            {
                "ledger_factory_unsigned_object": source_digests[
                    "ledger_factory_unsigned_object_digest"
                ]
            },
        ),
        "LEDGER_FACTORY_SIGNING_JOB": (
            source_digests["ledger_factory_signing_readback_digest"],
            {
                "ledger_factory_signing_job": source_digests[
                    "ledger_factory_signing_job_digest"
                ],
                "ledger_factory_signed_object": source_digests[
                    "ledger_factory_signed_object_digest"
                ],
            },
        ),
    }
    certification_by_name = {item["phase"]: item for item in certifications}
    for phase_name, (
        expected_readback_digest,
        expected_no_touch_targets,
    ) in artifact_readback_bindings.items():
        certification = certification_by_name[phase_name]
        if certification["resolution"] == "MUTATE":
            operations = resolved_phases[phase_name]["operations"]
            if (
                len(operations) != 1
                or operations[0]["expected_readback_digest"]
                != expected_readback_digest
            ):
                _fail("HANDOFF_ARTIFACT_READBACK_BINDING_MISMATCH")
        elif any(
            stable_inventory["resources"][resource_name]["target_contract"][
                "source_target_digest"
            ]
            != expected_target_digest
            for resource_name, expected_target_digest in (
                expected_no_touch_targets.items()
            )
        ):
            _fail("HANDOFF_ARTIFACT_READBACK_BINDING_MISMATCH")
    by_action_counter: Counter[str] = Counter()
    for phase, certification in zip(plan["phases"], certifications, strict=True):
        if certification["resolution"] == "MUTATE":
            by_action_counter.update(operation["action"] for operation in phase["operations"])
    by_action = [
        {"action": action, "count": count}
        for action, count in sorted(by_action_counter.items())
    ]
    counts = {"total": sum(by_action_counter.values()), "by_action": by_action}
    counts["write_count_digest"] = canonical_digest(counts)
    phase_readback_by_name = {
        certification["phase"]: certification["provider_readback_digest"]
        for certification in certifications
    }
    identity_certification = certifications[0]
    identity_center_binding_digest = canonical_digest(
        {
            "phase_certification_digest": identity_certification[
                "phase_certification_digest"
            ],
            "resolved_phase_operation_digest": identity_certification[
                "resolved_phase_operation_digest"
            ],
            "provider_readback_digest": identity_certification[
                "provider_readback_digest"
            ],
        }
    )

    provider_certification_complete = all(
        item["provider_certified"] is True
        and item["provider_transcript_verified"] is True
        and item["evidence_scope"] == "LIVE_AUTHORITY_NON_PRODUCTION"
        for item in certifications
    )
    provider_transcript_chain_digest = canonical_digest(
        [item["provider_transcript_chain_digest"] for item in certifications]
    )
    if (negative_evidence_verifier is None) != (negative_evidence_receipt is None):
        _fail("NEGATIVE_EVIDENCE_INPUT_INCOMPLETE")
    negative_evidence: dict[str, Any] | None = None
    if negative_evidence_verifier is not None:
        if not provider_certification_complete:
            _fail("SYNTHETIC_EVIDENCE_CANNOT_CERTIFY_LIVE")
        negative_evidence = _verify_final_negative_evidence(
            verifier=negative_evidence_verifier,
            opaque_receipt=negative_evidence_receipt,
            plan=plan,
            inventory=stable_inventory,
            certifications=certifications,
            provider_transcript_chain_digest=provider_transcript_chain_digest,
            evaluated_at=created_at,
        )
    negative_evidence_complete = negative_evidence is not None
    live_certified = provider_certification_complete and negative_evidence_complete
    status = (
        "LIVE_GUG365_UPSTREAM_PREREQUISITES_CERTIFIED"
        if live_certified
        else "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
    )

    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_final_handoff.v1",
        **_base(deployment_authorized=False),
        "consumer_writes_authorized": False,
        "status": status,
        "evidence_scope": (
            "LIVE_AUTHORITY_NON_PRODUCTION"
            if live_certified
            else "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        ),
        "provider_certification_complete": provider_certification_complete,
        "negative_evidence_complete": negative_evidence_complete,
        "provider_transcript_chain_digest": provider_transcript_chain_digest,
        "negative_evidence_verification_digest": (
            negative_evidence["verification_digest"]
            if negative_evidence is not None
            else None
        ),
        "consumer_fresh_checkpoint_required": True,
        "authorization_mode": "SINGLE_OPERATOR_NONPROD_EXCEPTION",
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_merge_sha": SOURCE_MERGE_SHA,
        "source_tree_sha": SOURCE_TREE_SHA,
        "identity_center_binding_digest": identity_center_binding_digest,
        "code_signing_config_policy": "Enforce",
        "allowed_publisher_count": 1,
        "signing_job_count": 2,
        "distinct_signing_jobs_proven": True,
        "distinct_signed_objects_proven": True,
        "gug363_plan_deployment_authorized": False,
        "gug363_plan_production": False,
        "gug365_aws_writes": 0,
        "gug357_create_stack": 0,
        "gug215_effects": 0,
        "gug206_effects": 0,
        "residual_risks": risks,
        "original_gug365_run_digest": ORIGINAL_RUN_DIGEST,
        "gap_checkpoint_digest": GAP_CHECKPOINT_DIGEST,
        "upstream_run_digest": plan["upstream_run_digest"],
        "upstream_plan_digest": plan["plan_digest"],
        "before_state_digest": canonical_digest(
            [item["before_state_digest"] for item in certifications]
        ),
        "final_state_digest": canonical_digest(
            [item["final_state_digest"] for item in certifications]
        ),
        "ledger_digest": canonical_digest(
            [item["ledger_digest"] for item in certifications]
        ),
        "runtime_evidence_digest": plan["runtime_evidence_digest"],
        "identity_center_readback_digest": phase_readback_by_name["IDENTITY_CENTER_FOUNDATION"],
        "kms_readback_digest": phase_readback_by_name["KMS_FOUNDATION"],
        "s3_readback_digest": phase_readback_by_name["S3_ARTIFACT_FOUNDATION"],
        "signer_readback_digest": phase_readback_by_name["SIGNER_PROFILE_FOUNDATION"],
        "code_signing_config_readback_digest": phase_readback_by_name["LAMBDA_CSC_FOUNDATION"],
        **{
            key: source_digests[key]
            for key in (
                "gug363_intent_digest", "gug363_plan_digest",
                "ledger_factory_signing_contract_digest",
                "broker_unsigned_package_manifest_digest",
                "broker_unsigned_object_digest", "broker_signing_job_digest",
                "broker_signed_object_digest",
                "ledger_factory_unsigned_package_manifest_digest",
                "ledger_factory_unsigned_object_digest",
                "ledger_factory_signing_job_digest",
                "ledger_factory_signed_object_digest",
            )
        },
        "phase_receipt_digests": [
            {
                "phase": item["phase"],
                "receipt_digest": item["phase_certification_digest"],
            }
            for item in certifications
        ],
        "aws_write_counts": counts,
        "created_at": _timestamp(created_at, "HANDOFF_TIME_INVALID"),
    }
    if "handoff_digest" in record:
        _fail("HANDOFF_DIGEST_PRESET_FORBIDDEN")
    record["handoff_digest"] = canonical_digest(record)
    _validate_repository_final_handoff(record)
    return record


def _validate_repository_final_handoff(record: Mapping[str, Any]) -> None:
    variable_digest_fields = {
        "original_gug365_run_digest", "gap_checkpoint_digest", "upstream_run_digest",
        "upstream_plan_digest", "before_state_digest", "final_state_digest",
        "ledger_digest", "runtime_evidence_digest", "identity_center_binding_digest",
        "identity_center_readback_digest", "kms_readback_digest", "s3_readback_digest",
        "signer_readback_digest", "code_signing_config_readback_digest",
        "broker_unsigned_package_manifest_digest", "broker_unsigned_object_digest",
        "broker_signing_job_digest", "broker_signed_object_digest",
        "ledger_factory_unsigned_package_manifest_digest",
        "ledger_factory_unsigned_object_digest", "ledger_factory_signing_job_digest",
        "ledger_factory_signed_object_digest", "gug363_intent_digest", "gug363_plan_digest",
        "ledger_factory_signing_contract_digest",
    }
    keys = {
        "record_type", "schema_version", "implementation_issue", "consumer_issue",
        "environment", "production", "production_status", "deployment_authorized",
        "consumer_writes_authorized", "status", "provider_certification_complete",
        "negative_evidence_complete", "consumer_fresh_checkpoint_required",
        "evidence_scope", "provider_transcript_chain_digest",
        "negative_evidence_verification_digest",
        "authorization_mode", "two_human_status", "independent_approval_present",
        "source_head_sha", "source_merge_sha", "source_tree_sha",
        "code_signing_config_policy", "allowed_publisher_count", "signing_job_count",
        "distinct_signing_jobs_proven", "distinct_signed_objects_proven",
        "gug363_plan_deployment_authorized", "gug363_plan_production",
        "phase_receipt_digests", "aws_write_counts", "gug365_aws_writes",
        "gug357_create_stack", "gug215_effects", "gug206_effects", "residual_risks",
        "created_at", "handoff_digest",
        *variable_digest_fields,
    }
    _require_keys(record, keys, "HANDOFF_FIELDS_INVALID")
    receipts = record.get("phase_receipt_digests")
    counts = record.get("aws_write_counts")
    residual = record.get("residual_risks")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_final_handoff.v1"
        or any(record.get(key) != value for key, value in _base(deployment_authorized=False).items())
        or record.get("consumer_writes_authorized") is not False
        or record.get("status")
        != "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        or record.get("evidence_scope")
        != "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        or record.get("provider_certification_complete") is not False
        or record.get("negative_evidence_complete") is not False
        or record.get("consumer_fresh_checkpoint_required") is not True
        or record.get("authorization_mode") != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
        or record.get("two_human_status") != "NOT_PROVEN"
        or record.get("independent_approval_present") is not False
        or record.get("code_signing_config_policy") != "Enforce"
        or record.get("allowed_publisher_count") != 1
        or record.get("signing_job_count") != 2
        or record.get("distinct_signing_jobs_proven") is not True
        or record.get("distinct_signed_objects_proven") is not True
        or record.get("gug363_plan_deployment_authorized") is not False
        or record.get("gug363_plan_production") is not False
        or any(record.get(field) != 0 for field in (
            "gug365_aws_writes", "gug357_create_stack", "gug215_effects", "gug206_effects"
        ))
        or not isinstance(receipts, list)
        or len(receipts) != 9
        or not isinstance(counts, Mapping)
        or not isinstance(residual, list)
        or not residual
    ):
        _fail("HANDOFF_INVALID")
    _validate_source(record, "HANDOFF_SOURCE_INVALID")
    _digest(
        record.get("provider_transcript_chain_digest"),
        "HANDOFF_PROVIDER_TRANSCRIPT_CHAIN_INVALID",
    )
    negative_evidence_digest = record.get("negative_evidence_verification_digest")
    if negative_evidence_digest is not None:
        _fail("HANDOFF_NEGATIVE_EVIDENCE_OVERCLAIM")
    if record.get("original_gug365_run_digest") != ORIGINAL_RUN_DIGEST:
        _fail("HANDOFF_ORIGINAL_RUN_MISMATCH")
    if record.get("gap_checkpoint_digest") != GAP_CHECKPOINT_DIGEST:
        _fail("HANDOFF_GAP_CHECKPOINT_MISMATCH")
    for field in variable_digest_fields:
        _digest(record.get(field), "HANDOFF_DIGEST_INVALID")
    observed_phases: list[str] = []
    for receipt in receipts:
        if not isinstance(receipt, Mapping) or set(receipt) != {"phase", "receipt_digest"}:
            _fail("HANDOFF_RECEIPT_INVALID")
        observed_phases.append(receipt.get("phase"))
        _digest(receipt.get("receipt_digest"), "HANDOFF_RECEIPT_DIGEST_INVALID")
    if observed_phases != list(PHASE_NAMES):
        _fail("HANDOFF_RECEIPT_PHASES_INVALID")
    if len({record["broker_signing_job_digest"], record["ledger_factory_signing_job_digest"]}) != 2:
        _fail("HANDOFF_SIGNING_JOBS_NOT_DISTINCT")
    if len({record["broker_signed_object_digest"], record["ledger_factory_signed_object_digest"]}) != 2:
        _fail("HANDOFF_SIGNED_OBJECTS_NOT_DISTINCT")
    if len(
        {
            record["broker_unsigned_object_digest"],
            record["broker_signed_object_digest"],
            record["ledger_factory_unsigned_object_digest"],
            record["ledger_factory_signed_object_digest"],
        }
    ) != 4:
        _fail("HANDOFF_ARTIFACT_OBJECTS_NOT_DISTINCT")
    if set(counts) != {"total", "by_action", "write_count_digest"}:
        _fail("HANDOFF_WRITE_COUNTS_INVALID")
    by_action = counts.get("by_action")
    if not isinstance(counts.get("total"), int) or not isinstance(by_action, list):
        _fail("HANDOFF_WRITE_COUNTS_INVALID")
    total = 0
    actions: set[str] = set()
    allowed_write_actions = set().union(
        *(set(counter) for counter in REQUIRED_ACTIONS.values())
    )
    for item in by_action:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"action", "count"}
            or not isinstance(item.get("action"), str)
            or item["action"] in actions
            or item["action"] not in allowed_write_actions
            or not isinstance(item.get("count"), int)
            or isinstance(item.get("count"), bool)
            or item["count"] < 1
        ):
            _fail("HANDOFF_WRITE_COUNTS_INVALID")
        actions.add(item["action"])
        total += item["count"]
    if total != counts["total"] or total < 1:
        _fail("HANDOFF_WRITE_COUNT_TOTAL_MISMATCH")
    _digest(counts.get("write_count_digest"), "HANDOFF_WRITE_COUNT_DIGEST_INVALID")
    expected_count_digest = canonical_digest(
        {key: value for key, value in counts.items() if key != "write_count_digest"}
    )
    if counts["write_count_digest"] != expected_count_digest:
        _fail("HANDOFF_WRITE_COUNT_DIGEST_MISMATCH")
    _parse_timestamp(record.get("created_at"), "HANDOFF_TIME_INVALID")
    _verify_record_digest(record, "handoff_digest", "HANDOFF_DIGEST_MISMATCH")


def _public_source_gap() -> None:
    """Reject promotion of repository scaffolding into public authority."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def build_execution_trust_anchor(*_args: Any, **_kwargs: Any) -> None:
    _public_source_gap()


def validate_execution_trust_anchor(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def validate_provider_transcript_verification(
    _record: Mapping[str, Any]
) -> None:
    _public_source_gap()


def build_owner_decisions(*_args: Any, **_kwargs: Any) -> None:
    _public_source_gap()


def validate_owner_decisions(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def build_stable_inventory(*_args: Any, **_kwargs: Any) -> None:
    _public_source_gap()


def validate_stable_inventory(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def build_upstream_plan(*_args: Any, **_kwargs: Any) -> None:
    _public_source_gap()


def validate_upstream_plan(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def build_provider_slot_binding(*_args: Any, **_kwargs: Any) -> None:
    _public_source_gap()


def validate_provider_slot_binding(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def validate_operation_receipt(_record: Mapping[str, Any]) -> None:
    _public_source_gap()


def build_phase_readback(*_args: Any, **_kwargs: Any) -> None:
    """No provider readback can be built without an authorized write path."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_phase_readback(_record: Mapping[str, Any]) -> None:
    """Serialized readback summaries are not provider evidence in this branch."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def build_phase_certification(*_args: Any, **_kwargs: Any) -> None:
    """No phase can be certified from repository-only simulation."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_phase_certification(_record: Mapping[str, Any]) -> None:
    """Serialized phase summaries cannot be promoted to certification."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def build_final_handoff(*_args: Any, **_kwargs: Any) -> None:
    """No successful handoff can be built while current-main gaps remain."""

    _fail("STOP_UPSTREAM_SOURCE_CONTRACT_GAP")


def validate_final_handoff(record: Mapping[str, Any]) -> None:
    """Validate only the zero-effect blocked handoff checkpoint."""

    keys = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "consumer_issue",
        "environment",
        "production",
        "production_status",
        "deployment_authorized",
        "consumer_writes_authorized",
        "status",
        "state",
        "evidence_scope",
        "provider_certification_complete",
        "negative_evidence_complete",
        "consumer_fresh_checkpoint_required",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "source_head_sha",
        "source_merge_sha",
        "source_tree_sha",
        "gap_checkpoint_digest",
        "aws_write_counts",
        "gug365_aws_writes",
        "gug357_create_stack",
        "gug215_effects",
        "gug206_effects",
        "signing_job_count",
        "distinct_signing_jobs_proven",
        "distinct_signed_objects_proven",
        "gug363_plan_deployment_authorized",
        "gug363_plan_production",
        "missing_source_contracts",
        "next_action",
        "created_at",
        "handoff_digest",
    }
    _require_keys(record, keys, "HANDOFF_STOP_CHECKPOINT_FIELDS_INVALID")
    counts = record.get("aws_write_counts")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_final_handoff.v1"
        or any(
            record.get(key) != value
            for key, value in _base(deployment_authorized=False).items()
        )
        or record.get("consumer_writes_authorized") is not False
        or record.get("status") != "STOP_UPSTREAM_SOURCE_CONTRACT_GAP"
        or record.get("state") != "STOPPED_BEFORE_FIRST_AWS_WRITE"
        or record.get("evidence_scope")
        != "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
        or record.get("provider_certification_complete") is not False
        or record.get("negative_evidence_complete") is not False
        or record.get("consumer_fresh_checkpoint_required") is not True
        or record.get("authorization_mode")
        != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
        or record.get("two_human_status") != "NOT_PROVEN"
        or record.get("independent_approval_present") is not False
        or record.get("gap_checkpoint_digest") != GAP_CHECKPOINT_DIGEST
        or any(
            record.get(field) != 0
            for field in (
                "gug365_aws_writes",
                "gug357_create_stack",
                "gug215_effects",
                "gug206_effects",
                "signing_job_count",
            )
        )
        or record.get("distinct_signing_jobs_proven") is not False
        or record.get("distinct_signed_objects_proven") is not False
        or record.get("gug363_plan_deployment_authorized") is not False
        or record.get("gug363_plan_production") is not False
        or record.get("missing_source_contracts") != list(SOURCE_CONTRACT_GAPS)
        or record.get("next_action") != "MATERIALIZE_REVIEWED_SOURCE_CONTRACTS"
        or not isinstance(counts, Mapping)
        or set(counts) != {"total", "by_action", "write_count_digest"}
        or counts.get("total") != 0
        or counts.get("by_action") != []
    ):
        _fail("HANDOFF_STOP_CHECKPOINT_INVALID")
    _validate_source(record, "HANDOFF_SOURCE_INVALID")
    _digest(
        counts.get("write_count_digest"),
        "HANDOFF_WRITE_COUNT_DIGEST_INVALID",
    )
    if counts["write_count_digest"] != canonical_digest(
        {"total": 0, "by_action": []}
    ):
        _fail("HANDOFF_WRITE_COUNT_DIGEST_MISMATCH")
    _parse_timestamp(record.get("created_at"), "HANDOFF_TIME_INVALID")
    _verify_record_digest(record, "handoff_digest", "HANDOFF_DIGEST_MISMATCH")
