"""Offline materializer for the sealed GUG-376 route-broker seed.

The committed ``*.template.yaml`` contains only closed replacement sentinels.
This module validates one private input against an exact, clean ``main`` Git
object and writes the rendered CloudFormation template once into an
owner-only directory.  It has no AWS SDK dependency and performs no network or
cloud action.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping, Sequence
from urllib.parse import quote
import zipfile

from tooling.platform_authority_plan_permission_repair_route_broker import (
    BrokerConfig,
    CONFIG_RECORD_TYPE,
    MIN_ROUTE_WINDOW_SECONDS,
    RouteBrokerError,
    decode_runtime_config,
    encode_runtime_config,
)


_DATETIME_TYPE = datetime


RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_broker_seed_input.v1"
)
RECEIPT_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_broker_seed_receipt.v1"
)
PEP_TEMPLATE_RECEIPT_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_pep_template_materialization_receipt.v1"
)
BROKER_SIGNING_RECEIPT_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_broker_signed_artifact_receipt.v1"
)
PEP_RUNTIME_BINDING_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_broker_pep_runtime_binding.v1"
)
BROKER_CONFIG_RECORD_TYPE = CONFIG_RECORD_TYPE
SOURCE_TEMPLATE_PATH = Path(
    "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml"
)
PEP_SOURCE_TEMPLATE_PATH = Path(
    "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
)
OUTPUT_NAME = "cfn-platform-authority-gug376-route-broker.yaml"
PROTECTION_OUTPUT_NAME = (
    "cfn-platform-authority-gug376-route-broker-protection.yaml"
)
PACKAGE_OUTPUT_NAME = "route-broker-unsigned.zip"
PACKAGE_RECEIPT_OUTPUT_NAME = "route-broker-package-receipt.json"
MATERIALIZATION_RECEIPT_OUTPUT_NAME = "route-broker-materialization-receipt.json"
PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME = (
    "route-broker-protection-materialization-receipt.json"
)
PEP_OUTPUT_NAME = "cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
PEP_PROTECTION_OUTPUT_NAME = (
    "cfn-platform-authority-bootstrap-plan-repair-pep-protection.yaml"
)
PEP_MATERIALIZATION_RECEIPT_OUTPUT_NAME = (
    "pep-template-materialization-receipt.json"
)
PEP_PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME = (
    "pep-protection-template-materialization-receipt.json"
)
PEP_LIFECYCLE_RESOURCE_IDS = (
    "PlanLogGroup",
    "ReconcileLogGroup",
    "RepairLedger",
    "RepairLedgerKey",
    "RepairLedgerKeyAlias",
    "RepairLogGroup",
)
PACKAGE_SOURCE_PATHS = (
    Path("tooling/__init__.py"),
    Path("tooling/platform_authority_bootstrap.py"),
    Path("tooling/platform_authority_plan_permission_repair.py"),
    Path("tooling/platform_authority_plan_permission_repair_route_broker.py"),
)
MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
BROKER_LEDGER_ID = "gug376-route-broker"
MAX_ROUTE_WINDOW_SECONDS = 2 * 60 * 60
MAX_INPUT_BYTES = 256 * 1024
MAX_BROKER_CONFIG_BYTES = 3_800
MAX_LAMBDA_ENVIRONMENT_BYTES = 4_096
# The broker is always submitted through an exact, versioned S3 TemplateURL;
# CloudFormation permits up to 1 MiB for that transport (never TemplateBody).
MAX_TEMPLATE_URL_BYTES = 1_048_576
MAX_SIGNING_RECEIPT_AGE_SECONDS = 15 * 60
MAX_CLOCK_SKEW_SECONDS = 60
PRODUCTION_STATUS = "NO-GO"
EFFECTIVE_POLICY_PROJECTION_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_broker_effective_policy_projection.v1"
)

CREATOR_ALIASES = (
    "seed-revoke-create-v1",
    "delegation-create-v1",
    "pep-create-v1",
    "pep-protection-create-v1",
    "closeout-gate-v1",
    "delegation-revoke-create-v1",
    "route-revoke-create-v1",
)
EXECUTOR_ALIASES = (
    "seed-revoke-execute-v1",
    "delegation-execute-v1",
    "pep-execute-v1",
    "pep-protection-execute-v1",
    "delegation-revoke-execute-v1",
    "route-revoke-execute-v1",
)
ALL_ALIASES = frozenset((*CREATOR_ALIASES, *EXECUTOR_ALIASES))
_OPERATION_BINDINGS = {
    "seed-revoke-create-v1": (
        "seed-revoke-execute-v1",
        "scanalyze-platform-authority-gug376-temporary-change-set-route",
        "gug376-temporary-route-seed-revoke",
    ),
    "delegation-create-v1": (
        "delegation-execute-v1",
        "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
        "gug376-plan-repair-delegation-create",
    ),
    "pep-create-v1": (
        "pep-execute-v1",
        "scanalyze-platform-authority-bootstrap-plan-repair-pep",
        "gug376-plan-repair-pep-create",
    ),
    "pep-protection-create-v1": (
        "pep-protection-execute-v1",
        "scanalyze-platform-authority-bootstrap-plan-repair-pep",
        "gug376-plan-repair-pep-protection-enable",
    ),
    "delegation-revoke-create-v1": (
        "delegation-revoke-execute-v1",
        "scanalyze-platform-authority-bootstrap-plan-repair-delegation",
        "gug376-plan-repair-delegation-revoke",
    ),
    "route-revoke-create-v1": (
        "route-revoke-execute-v1",
        "scanalyze-platform-authority-gug376-temporary-change-set-route",
        "gug376-temporary-route-invoker-revoke",
    ),
}

_INPUT_KEYS = frozenset(
    {
        "record_type",
        "source_commit",
        "management_account_id",
        "authority_account_id",
        "region",
        "route_not_before",
        "route_not_after",
        "repair_id",
        "artifact_bootstrap_intent",
        "foundation_publish_binding",
        "foundation_publish_binding_digest",
        "source_template",
        "broker_code",
        "pep_template",
        "pep_protection_template",
        "pep_artifact",
        "pep_runtime_binding",
        "broker_config",
    }
)
_MATERIALIZATION_RECEIPT_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "source_commit",
        "template_variant",
        "output_name",
        "template_sha256",
        "template_bytes",
        "unsigned_package_sha256",
        "signed_package_sha256",
        "signed_package_code_sha256",
        "signing_receipt_digest",
        "pep_runtime_binding_digest",
        "foundation_publish_binding_digest",
        "effective_policy_projection",
        "effective_policy_projection_digest",
        "parameters_section_absent",
        "private_mode",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "receipt_digest",
    }
)
_PEP_TEMPLATE_RECEIPT_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "source_commit",
        "source_path",
        "source_sha256",
        "template_variant",
        "output_name",
        "template_sha256",
        "template_bytes",
        "ledger_deletion_protection_enabled",
        "lifecycle_deletion_policy",
        "lifecycle_update_replace_policy",
        "lifecycle_resource_ids",
        "variant_controls_parameterless",
        "private_mode",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "receipt_digest",
    }
)
_POLICY_PROJECTION_KEYS = frozenset(
    {
        "record_type",
        "schema_version",
        "source_commit",
        "partition",
        "account_id",
        "region",
        "policies",
        "projection_digest",
    }
)
_POLICY_PROJECTION_NAMES = frozenset(
    {
        "creator_role_inline_policy",
        "executor_role_inline_policy",
        "create_dispatch_recovery_role_inline_policy",
        "execute_dispatch_recovery_role_inline_policy",
        "broker_ledger_resource_policy",
        "broker_ledger_key_policy",
    }
)
_POLICY_ENTRY_KEYS = frozenset(
    {
        "logical_resource_id",
        "policy_type",
        "selector",
        "document",
        "document_digest",
    }
)
_SOURCE_KEYS = frozenset({"path", "sha256"})
_OBJECT_KEYS = frozenset({"bucket", "key", "version"})
_BROKER_SIGNING_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "verifier",
        "unsigned_artifact",
        "signing_job",
        "signed_artifact",
        "upstream_storage_binding",
        "revocation_check",
        "observed_at",
        "source_marker",
        "aws_calls",
        "aws_mutations",
        "receipt_digest",
    }
)
_SIGNED_ARTIFACT_KEYS = frozenset(
    {
        "bucket", "key", "version", "sha256", "code_sha256", "bytes",
        "sse_algorithm", "sse_kms_key_arn",
    }
)
_UPSTREAM_STORAGE_BINDING_KEYS = frozenset(
    {
        "schema_version", "record_type", "gug363_plan_digest",
        "gug363_artifact_signing_contract_digest", "gug365_plan_digest",
        "gug365_ledger_factory_artifact_signing_contract_digest",
        "gug365_signed_artifact_binding_digest", "bucket", "sse_algorithm",
        "sse_kms_key_arn", "source_marker", "binding_digest",
    }
)
_FOUNDATION_STORAGE_BINDING_KEYS = frozenset(
    {
        "schema_version", "record_type", "source_commit",
        "bootstrap_intent_digest", "foundation_readback_digest",
        "reviewed_sources_digest", "access_update_intent_digest",
        "access_readback_digest", "route_template_receipt_digest",
        "delegation_template_receipt_digest", "route_template_sha256",
        "delegation_template_sha256", "route_template_version_digest",
        "delegation_template_version_digest", "access_not_after", "bucket",
        "sse_algorithm", "sse_kms_key_arn", "signing_profile_version_arn",
        "code_signing_config_arn", "source_marker", "aws_calls",
        "aws_mutations", "production_authorized", "production_status",
        "foundation_readback", "reviewed_sources", "access_update",
        "access_readback", "route_template_receipt",
        "delegation_template_receipt",
        "binding_digest",
    }
)
_VERIFIER_KEYS = frozenset({"account_id", "caller_arn", "profile", "region"})
_SIGNING_JOB_KEYS = frozenset(
    {
        "job_id",
        "job_owner",
        "job_invoker",
        "status",
        "platform_id",
        "profile_version_arn",
        "certificate_arn",
        "created_at",
        "completed_at",
        "signature_expires_at",
        "profile_status",
        "job_revocation_record_absent",
        "profile_revocation_record_absent",
    }
)
_REVOCATION_KEYS = frozenset(
    {
        "status",
        "checked_at",
        "profile_version_arn_digest",
        "job_arn_digest",
        "certificate_hash_digest",
        "source_marker",
    }
)
_PEP_RUNTIME_KEYS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "expected_boto3_version",
        "expected_botocore_version",
        "pep_signed_artifact_receipt_digest",
        "pep_runtime_readback_digest",
        "upstream_storage_binding_digest",
        "source_marker",
        "binding_digest",
    }
)
_TEMPLATE_KEYS = frozenset({"bucket", "key", "version", "url"})
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_KMS_KEY_ARN_RE = re.compile(
    r"^arn:aws:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CODE_SHA256_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SIGNING_PROFILE_RE = re.compile(
    r"^arn:aws[a-z-]*:signer:us-east-1:042360977644:/signing-profiles/"
    r"[A-Za-z0-9_]{2,64}/[A-Za-z0-9]{10}$"
)
_SIGNING_CERTIFICATE_RE = re.compile(
    r"^arn:aws:acm:us-east-1:042360977644:certificate/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_REPAIR_ID_RE = re.compile(
    r"^gug376-plan-permission-repair-[0-9a-f]{64}$"
)
_BROKER_CODE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/broker/signed/"
    r"([0-9a-f]{40})/"
    r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.zip$"
)
_BROKER_UNSIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/broker/unsigned/"
    r"([0-9a-f]{40})/route-broker-unsigned\.zip$"
)
_SIGNING_JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_LEGACY_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_PEP_TEMPLATE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
    r"([0-9a-f]{40})/cfn-platform-authority-bootstrap-plan-repair-pep\.yaml$"
)
_PEP_PROTECTION_TEMPLATE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
    r"([0-9a-f]{40})/"
    r"cfn-platform-authority-bootstrap-plan-repair-pep-protection\.yaml$"
)
_PEP_ARTIFACT_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/signed/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12}\.zip$"
)
_PLACEHOLDER_RE = re.compile(rb"@@[A-Z0-9_]+@@")
_PEP_VARIANT_SENTINEL_RE = re.compile(rb"PEP_[A-Z0-9_]+_SENTINEL")
_ERROR_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")


class BrokerSeedError(ValueError):
    """Stable, sanitized materialization failure."""

    def __init__(self, code: str) -> None:
        self.code = code if _ERROR_RE.fullmatch(code) else "BROKER_SEED_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise BrokerSeedError(code)


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def digest_value(value: object) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _exact_keys(value: object, keys: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(code)
    return value


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        _fail(code)
    return parsed


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("BROKER_SEED_WINDOW_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_config(
    value: object,
    *,
    source_commit: str,
    repair_id: str,
    route_not_before: str,
    route_not_after: str,
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        _fail("BROKER_CONFIG_FIELDS_INVALID")
    config = dict(value)
    try:
        parsed = BrokerConfig.from_mapping(config)
        envelope = encode_runtime_config(config)
        decoded = decode_runtime_config(envelope)
    except RouteBrokerError as exc:
        raise BrokerSeedError("BROKER_CONFIG_INVALID") from exc
    if (
        parsed.source_commit != source_commit
        or parsed.repair_id != repair_id
        or parsed.ledger_id != BROKER_LEDGER_ID
        or config.get("route_not_before") != route_not_before
        or config.get("route_not_after") != route_not_after
        or config.get("recovery_not_after")
        != _timestamp(
            _utc(route_not_after, "BROKER_CONFIG_BINDING_INVALID")
            + timedelta(hours=24)
        )
        or decoded != config
    ):
        _fail("BROKER_CONFIG_BINDING_INVALID")
    if any(
        parsed.request(creator)["StackName"] != stack
        or parsed.request(executor)["StackName"] != stack
        or parsed.request(creator)["ChangeSetName"] != change_set_name
        or parsed.request(executor)["ChangeSetName"] != change_set_name
        for creator, (executor, stack, change_set_name) in _OPERATION_BINDINGS.items()
    ):
        _fail("BROKER_CONFIG_OPERATION_BINDING_INVALID")
    encoded_envelope = canonical_json(envelope)
    if len(encoded_envelope.encode("utf-8")) > MAX_BROKER_CONFIG_BYTES:
        _fail("BROKER_CONFIG_TOO_LARGE")
    return config, encoded_envelope


def _validate_object(
    value: object,
    *,
    keys: frozenset[str],
    key_pattern: re.Pattern[str],
    source_commit: str | None,
    code: str,
) -> Mapping[str, str]:
    descriptor = _exact_keys(value, keys, code)
    bucket = descriptor.get("bucket")
    key = descriptor.get("key")
    version = descriptor.get("version")
    if (
        not isinstance(bucket, str)
        or not _BUCKET_RE.fullmatch(bucket)
        or not isinstance(key, str)
        or (match := key_pattern.fullmatch(key)) is None
        or not isinstance(version, str)
        or not _VERSION_RE.fullmatch(version)
        or version.casefold() == "null"
    ):
        _fail(code)
    if source_commit is not None and match.group(1) != source_commit:
        _fail(code)
    return {name: str(descriptor[name]) for name in keys}


def _expected_url(bucket: str, key: str, version: str) -> str:
    encoded_key = quote(key, safe="/-_.~")
    encoded_version = quote(version, safe="-_.~")
    return (
        f"https://{bucket}.s3.us-east-1.amazonaws.com/"
        f"{encoded_key}?versionId={encoded_version}"
    )


def _code_sha256(digest: str) -> str:
    return base64.b64encode(bytes.fromhex(digest[7:])).decode("ascii")


def _validate_signed_artifact_descriptor(
    value: object,
    *,
    source_commit: str,
    signed: bool,
) -> dict[str, Any]:
    code = "BROKER_SIGNING_RECEIPT_INVALID"
    descriptor = _exact_keys(value, _SIGNED_ARTIFACT_KEYS, code)
    bucket = descriptor.get("bucket")
    key = descriptor.get("key")
    version = descriptor.get("version")
    digest = descriptor.get("sha256")
    code_digest = descriptor.get("code_sha256")
    size = descriptor.get("bytes")
    key_pattern = _BROKER_CODE_KEY_RE if signed else _BROKER_UNSIGNED_KEY_RE
    if (
        not isinstance(bucket, str)
        or not _BUCKET_RE.fullmatch(bucket)
        or not isinstance(key, str)
        or (match := key_pattern.fullmatch(key)) is None
        or match.group(1) != source_commit
        or not isinstance(version, str)
        or not _VERSION_RE.fullmatch(version)
        or version.casefold() == "null"
        or not isinstance(digest, str)
        or not _DIGEST_RE.fullmatch(digest)
        or not isinstance(code_digest, str)
        or not _CODE_SHA256_RE.fullmatch(code_digest)
        or _code_sha256(digest) != code_digest
        or type(size) is not int
        or not 0 < size <= 10 * 1024 * 1024
        or descriptor.get("sse_algorithm") != "aws:kms"
        or not isinstance(descriptor.get("sse_kms_key_arn"), str)
        or not _KMS_KEY_ARN_RE.fullmatch(descriptor["sse_kms_key_arn"])
    ):
        _fail(code)
    return dict(descriptor)


def _validate_broker_signing_receipt(
    value: object,
    *,
    source_commit: str,
    now: datetime | None = None,
    causal_not_before: datetime | None = None,
    causal_not_after: datetime | None = None,
    valid_through: datetime | None = None,
    expected_storage_binding: Mapping[str, Any] | None = None,
    allow_legacy_upstream_storage_binding: bool = False,
) -> dict[str, Any]:
    code = "BROKER_SIGNING_RECEIPT_INVALID"
    receipt = dict(_exact_keys(value, _BROKER_SIGNING_KEYS, code))
    verifier = _exact_keys(receipt.get("verifier"), _VERIFIER_KEYS, code)
    expected_verifier_profile = (
        "042360977644_AWSReadOnlyAccess"
        if allow_legacy_upstream_storage_binding
        else "042360977644_ScanalyzeGug376ArtifactBootstrap"
    )
    expected_caller = (
        _LEGACY_CALLER_ARN_RE
        if allow_legacy_upstream_storage_binding
        else _CALLER_ARN_RE
    )
    if (
        receipt.get("schema_version") != 1
        or receipt.get("record_type") != BROKER_SIGNING_RECEIPT_TYPE
        or receipt.get("source_commit") != source_commit
        or receipt.get("source_marker")
        != "AWS_STS_S3_SIGNER_ACM_REVOCATION_AND_VERSIONED_OBJECT_READBACK"
        or type(receipt.get("aws_calls")) is not int
        or receipt["aws_calls"] != 11
        or receipt.get("aws_mutations") != 0
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or verifier.get("profile") != expected_verifier_profile
        or verifier.get("region") != REGION
        or not isinstance(verifier.get("caller_arn"), str)
        or not expected_caller.fullmatch(verifier["caller_arn"])
    ):
        _fail(code)
    unsigned = _validate_signed_artifact_descriptor(
        receipt.get("unsigned_artifact"),
        source_commit=source_commit,
        signed=False,
    )
    signed = _validate_signed_artifact_descriptor(
        receipt.get("signed_artifact"),
        source_commit=source_commit,
        signed=True,
    )
    raw_storage = receipt.get("upstream_storage_binding")
    if not isinstance(raw_storage, Mapping):
        _fail("BROKER_UPSTREAM_STORAGE_BINDING_INVALID")
    storage = dict(raw_storage)
    legacy_storage = (
        set(storage) == _UPSTREAM_STORAGE_BINDING_KEYS
        and storage.get("schema_version") == 1
        and storage.get("record_type")
        == (
            "scanalyze.platform_authority."
            "plan_permission_repair_gug365_template_storage_binding.v1"
        )
        and storage.get("source_marker")
        == "VALIDATED_GUG363_AND_GUG365_CAUSAL_PLANS"
        and all(
            isinstance(storage.get(field), str)
            and _DIGEST_RE.fullmatch(storage[field]) is not None
            for field in (
                "gug363_plan_digest",
                "gug363_artifact_signing_contract_digest",
                "gug365_plan_digest",
                "gug365_ledger_factory_artifact_signing_contract_digest",
                "gug365_signed_artifact_binding_digest",
                "binding_digest",
            )
        )
    )
    foundation_storage = (
        expected_storage_binding is not None
        and storage == dict(expected_storage_binding)
        and
        set(storage) == _FOUNDATION_STORAGE_BINDING_KEYS
        and storage.get("schema_version") == 1
        and storage.get("record_type")
        == (
            "scanalyze.platform_authority."
            "gug376_artifact_foundation_publish_binding.v1"
        )
        and storage.get("source_commit") == source_commit
        and storage.get("source_marker")
        == "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY"
        and all(
            isinstance(storage.get(field), str)
            and _DIGEST_RE.fullmatch(storage[field]) is not None
            for field in (
                "bootstrap_intent_digest",
                "foundation_readback_digest",
                "access_update_intent_digest",
                "access_readback_digest",
                "reviewed_sources_digest",
                "route_template_receipt_digest",
                "delegation_template_receipt_digest",
                "binding_digest",
            )
        )
        and storage.get("aws_calls") == 0
        and storage.get("aws_mutations") == 0
        and storage.get("production_authorized") is False
        and storage.get("production_status") == PRODUCTION_STATUS
    )
    if (
        not (
            foundation_storage
            or (allow_legacy_upstream_storage_binding and legacy_storage)
        )
        or storage.get("bucket") != unsigned["bucket"]
        or storage.get("bucket") != signed["bucket"]
        or storage.get("sse_algorithm") != "aws:kms"
        or storage.get("sse_kms_key_arn") != unsigned["sse_kms_key_arn"]
        or storage.get("sse_kms_key_arn") != signed["sse_kms_key_arn"]
        or digest_value(
            {key: item for key, item in storage.items() if key != "binding_digest"}
        )
        != storage.get("binding_digest")
    ):
        _fail("BROKER_UPSTREAM_STORAGE_BINDING_INVALID")
    if (
        unsigned["sha256"] == signed["sha256"]
        or unsigned["code_sha256"] == signed["code_sha256"]
    ):
        _fail("BROKER_SIGNING_DIGESTS_NOT_DISTINCT")
    job = _exact_keys(receipt.get("signing_job"), _SIGNING_JOB_KEYS, code)
    if (
        not isinstance(job.get("job_id"), str)
        or not _SIGNING_JOB_RE.fullmatch(job["job_id"])
        or job.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or job.get("job_invoker") != AUTHORITY_ACCOUNT_ID
        or job.get("status") != "Succeeded"
        or job.get("platform_id") != "AWSLambda-SHA384-ECDSA"
        or not isinstance(job.get("profile_version_arn"), str)
        or not _SIGNING_PROFILE_RE.fullmatch(job["profile_version_arn"])
        or not isinstance(job.get("certificate_arn"), str)
        or not _SIGNING_CERTIFICATE_RE.fullmatch(job["certificate_arn"])
        or job.get("profile_status") != "Active"
        or job.get("job_revocation_record_absent") is not True
        or job.get("profile_revocation_record_absent") is not True
    ):
        _fail(code)
    signed_key_match = _BROKER_CODE_KEY_RE.fullmatch(signed["key"])
    if signed_key_match is None or signed_key_match.group(2) != job["job_id"]:
        _fail(code)
    created_at = _utc(job.get("created_at"), code)
    completed_at = _utc(job.get("completed_at"), code)
    expires_at = _utc(job.get("signature_expires_at"), code)
    observed_at = _utc(receipt.get("observed_at"), code)
    admission_mode = now is not None
    causal_times = (causal_not_before, causal_not_after, valid_through)
    has_any_causal_time = any(item is not None for item in causal_times)
    archival_mode = all(item is not None for item in causal_times)
    if has_any_causal_time != archival_mode or admission_mode == archival_mode:
        _fail("BROKER_SIGNING_VALIDATION_CONTEXT_INVALID")
    if admission_mode:
        assert now is not None
        if (
            not isinstance(now, _DATETIME_TYPE)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            _fail("BROKER_SIGNING_ADMISSION_TIME_INVALID")
        consumed_at = now.astimezone(timezone.utc).replace(microsecond=0)
    else:
        assert causal_not_before is not None
        assert causal_not_after is not None
        assert valid_through is not None
        if any(
            not isinstance(item, _DATETIME_TYPE)
            or item.tzinfo is None
            or item.utcoffset() is None
            for item in causal_times
        ):
            _fail("BROKER_SIGNING_CAUSAL_TIME_INVALID")
        causal_start = causal_not_before.astimezone(timezone.utc).replace(
            microsecond=0
        )
        causal_end = causal_not_after.astimezone(timezone.utc).replace(
            microsecond=0
        )
        required_valid_through = valid_through.astimezone(timezone.utc).replace(
            microsecond=0
        )
    if (
        not created_at <= completed_at < expires_at
        or completed_at > observed_at
        or (observed_at - completed_at).total_seconds()
        > MAX_SIGNING_RECEIPT_AGE_SECONDS
    ):
        _fail("BROKER_SIGNING_RECEIPT_STALE")
    if admission_mode:
        if (
            observed_at
            > consumed_at + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
            or (consumed_at - observed_at).total_seconds()
            > MAX_SIGNING_RECEIPT_AGE_SECONDS
            or expires_at <= consumed_at
        ):
            _fail("BROKER_SIGNING_RECEIPT_STALE")
    elif (
        not causal_start < causal_end
        or not causal_start <= observed_at < causal_end
        or required_valid_through < causal_end
        or expires_at <= required_valid_through
    ):
        _fail("BROKER_SIGNING_CAUSAL_TIME_INVALID")
    revocation = _exact_keys(
        receipt.get("revocation_check"), _REVOCATION_KEYS, code
    )
    job_arn = (
        f"arn:aws:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"/signing-jobs/{job['job_id']}"
    )
    if (
        revocation.get("status")
        != "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED"
        or revocation.get("checked_at") != receipt.get("observed_at")
        or revocation.get("profile_version_arn_digest")
        != digest_value(job["profile_version_arn"])
        or revocation.get("job_arn_digest") != digest_value(job_arn)
        or not isinstance(revocation.get("certificate_hash_digest"), str)
        or not _DIGEST_RE.fullmatch(
            revocation["certificate_hash_digest"]
        )
        or revocation.get("source_marker")
        != (
            "DESCRIBE_SIGNING_JOB_GET_SIGNING_PROFILE_ACM_CERTIFICATE_"
            "AND_SIGNER_DATA_REVOCATION"
        )
    ):
        _fail("BROKER_REVOCATION_BINDING_INVALID")
    claimed = receipt.get("receipt_digest")
    if (
        not isinstance(claimed, str)
        or not _DIGEST_RE.fullmatch(claimed)
        or digest_value(
            {key: item for key, item in receipt.items() if key != "receipt_digest"}
        )
        != claimed
    ):
        _fail("BROKER_SIGNING_RECEIPT_DIGEST_INVALID")
    receipt["verifier"] = dict(verifier)
    receipt["unsigned_artifact"] = unsigned
    receipt["signed_artifact"] = signed
    receipt["signing_job"] = dict(job)
    receipt["revocation_check"] = dict(revocation)
    receipt["upstream_storage_binding"] = storage
    return receipt


def _validate_pep_runtime_binding(
    value: object, *, source_commit: str
) -> dict[str, Any]:
    code = "PEP_RUNTIME_BINDING_INVALID"
    binding = dict(_exact_keys(value, _PEP_RUNTIME_KEYS, code))
    if (
        binding.get("schema_version") != 1
        or binding.get("record_type") != PEP_RUNTIME_BINDING_TYPE
        or binding.get("source_commit") != source_commit
        or binding.get("source_marker")
        != "VALIDATED_GUG376_PEP_SIGNED_ARTIFACT_RUNTIME_EVIDENCE"
        or not isinstance(binding.get("expected_boto3_version"), str)
        or not _SDK_VERSION_RE.fullmatch(binding["expected_boto3_version"])
        or not isinstance(binding.get("expected_botocore_version"), str)
        or not _SDK_VERSION_RE.fullmatch(binding["expected_botocore_version"])
        or not isinstance(binding.get("pep_signed_artifact_receipt_digest"), str)
        or not _DIGEST_RE.fullmatch(binding["pep_signed_artifact_receipt_digest"])
        or not isinstance(binding.get("pep_runtime_readback_digest"), str)
        or not _DIGEST_RE.fullmatch(binding["pep_runtime_readback_digest"])
        or not isinstance(
            binding.get("upstream_storage_binding_digest"), str
        )
        or not _DIGEST_RE.fullmatch(
            binding["upstream_storage_binding_digest"]
        )
    ):
        _fail(code)
    claimed = binding.get("binding_digest")
    if (
        not isinstance(claimed, str)
        or not _DIGEST_RE.fullmatch(claimed)
        or digest_value(
            {key: item for key, item in binding.items() if key != "binding_digest"}
        )
        != claimed
    ):
        _fail(code)
    return binding


def validate_broker_signing_receipt(
    value: object,
    *,
    source_commit: str,
    now: datetime | None = None,
    bootstrap_intent: Mapping[str, Any] | None = None,
    foundation_publish_binding: Mapping[str, Any] | None = None,
    allow_legacy_upstream_storage_binding: bool = False,
) -> dict[str, Any]:
    """Admit one connected receipt against an explicit current time."""

    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("SOURCE_COMMIT_INVALID")
    if now is None:
        _fail("BROKER_SIGNING_ADMISSION_TIME_REQUIRED")
    if allow_legacy_upstream_storage_binding:
        if bootstrap_intent is not None or foundation_publish_binding is not None:
            _fail("BROKER_UPSTREAM_STORAGE_BINDING_INVALID")
        expected_storage = None
    else:
        if not isinstance(bootstrap_intent, Mapping) or not isinstance(
            foundation_publish_binding, Mapping
        ):
            _fail("BROKER_UPSTREAM_STORAGE_BINDING_INVALID")
        try:
            from tooling import (
                platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
            )

            expected_storage = artifact_bootstrap.validate_foundation_publish_binding(
                foundation_publish_binding,
                bootstrap_intent=bootstrap_intent,
            )
        except Exception as exc:
            raise BrokerSeedError("BROKER_UPSTREAM_STORAGE_BINDING_INVALID") from exc
    return _validate_broker_signing_receipt(
        value,
        source_commit=source_commit,
        now=now,
        expected_storage_binding=expected_storage,
        allow_legacy_upstream_storage_binding=allow_legacy_upstream_storage_binding,
    )


def validate_archived_broker_signing_receipt(
    value: object,
    *,
    source_commit: str,
    bootstrap_intent: Mapping[str, Any],
    foundation_publish_binding: Mapping[str, Any],
    valid_through: datetime,
) -> dict[str, Any]:
    """Reconstruct an admitted receipt from its independent causal window.

    Archival reconstruction intentionally does not consult wall-clock time.  It
    binds the receipt observation to the sealed bootstrap access window and
    requires the signature to remain valid through the sealed route horizon.
    """

    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("SOURCE_COMMIT_INVALID")
    try:
        from tooling import (
            platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
        )

        bootstrap = artifact_bootstrap.validate_bootstrap_intent(bootstrap_intent)
        expected_storage = artifact_bootstrap.validate_foundation_publish_binding(
            foundation_publish_binding,
            bootstrap_intent=bootstrap,
        )
    except Exception as exc:
        raise BrokerSeedError("BROKER_UPSTREAM_STORAGE_BINDING_INVALID") from exc
    if bootstrap.get("source_commit") != source_commit:
        _fail("BROKER_UPSTREAM_STORAGE_BINDING_INVALID")
    return _validate_broker_signing_receipt(
        value,
        source_commit=source_commit,
        causal_not_before=_utc(
            bootstrap.get("access_not_before"),
            "BROKER_SIGNING_CAUSAL_TIME_INVALID",
        ),
        causal_not_after=_utc(
            bootstrap.get("access_not_after"),
            "BROKER_SIGNING_CAUSAL_TIME_INVALID",
        ),
        valid_through=valid_through,
        expected_storage_binding=expected_storage,
    )


def validate_pep_runtime_binding(
    value: object, *, source_commit: str
) -> dict[str, Any]:
    """Validate the same-commit PEP runtime dependency binding."""

    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("SOURCE_COMMIT_INVALID")
    return _validate_pep_runtime_binding(value, source_commit=source_commit)


def validate_input(value: Mapping[str, Any]) -> dict[str, Any]:
    data = dict(_exact_keys(value, _INPUT_KEYS, "BROKER_SEED_FIELDS_INVALID"))
    source_commit = data.get("source_commit")
    route_not_before = data.get("route_not_before")
    route_not_after = data.get("route_not_after")
    repair_id = data.get("repair_id")
    foundation_binding_digest = data.get("foundation_publish_binding_digest")
    bootstrap_intent = data.get("artifact_bootstrap_intent")
    foundation_publish_binding = data.get("foundation_publish_binding")
    try:
        from tooling import (
            platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
        )

        validated_bootstrap = artifact_bootstrap.validate_bootstrap_intent(
            bootstrap_intent
        )
        validated_foundation = artifact_bootstrap.validate_foundation_publish_binding(
            foundation_publish_binding,
            bootstrap_intent=validated_bootstrap,
        )
    except Exception as exc:
        raise BrokerSeedError("FOUNDATION_PUBLISH_BINDING_INVALID") from exc
    if (
        data.get("record_type") != RECORD_TYPE
        or not isinstance(source_commit, str)
        or not _SHA_RE.fullmatch(source_commit)
        or data.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or data.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or data.get("region") != REGION
        or not isinstance(route_not_before, str)
        or not isinstance(route_not_after, str)
        or not isinstance(repair_id, str)
        or not _REPAIR_ID_RE.fullmatch(repair_id)
        or not isinstance(foundation_binding_digest, str)
        or _DIGEST_RE.fullmatch(foundation_binding_digest) is None
        or validated_bootstrap.get("source_commit") != source_commit
        or validated_foundation.get("source_commit") != source_commit
        or validated_foundation.get("binding_digest")
        != foundation_binding_digest
    ):
        _fail("BROKER_SEED_BINDING_INVALID")
    before = _utc(route_not_before, "BROKER_SEED_WINDOW_INVALID")
    after = _utc(route_not_after, "BROKER_SEED_WINDOW_INVALID")
    duration = (after - before).total_seconds()
    if not MIN_ROUTE_WINDOW_SECONDS <= duration <= MAX_ROUTE_WINDOW_SECONDS:
        _fail("BROKER_SEED_WINDOW_INVALID")

    source = _exact_keys(
        data.get("source_template"), _SOURCE_KEYS, "BROKER_SEED_SOURCE_INVALID"
    )
    if (
        source.get("path") != SOURCE_TEMPLATE_PATH.as_posix()
        or not _DIGEST_RE.fullmatch(str(source.get("sha256", "")))
    ):
        _fail("BROKER_SEED_SOURCE_INVALID")
    broker_code = _validate_broker_signing_receipt(
        data.get("broker_code"),
        source_commit=source_commit,
        causal_not_before=_utc(
            validated_bootstrap.get("access_not_before"),
            "BROKER_SIGNING_CAUSAL_TIME_INVALID",
        ),
        causal_not_after=_utc(
            validated_bootstrap.get("access_not_after"),
            "BROKER_SIGNING_CAUSAL_TIME_INVALID",
        ),
        valid_through=after,
        expected_storage_binding=validated_foundation,
    )
    pep_runtime = _validate_pep_runtime_binding(
        data.get("pep_runtime_binding"), source_commit=source_commit
    )
    pep_template = _validate_object(
        data.get("pep_template"),
        keys=_TEMPLATE_KEYS,
        key_pattern=_PEP_TEMPLATE_KEY_RE,
        source_commit=source_commit,
        code="PEP_TEMPLATE_INVALID",
    )
    if pep_template["url"] != _expected_url(
        pep_template["bucket"], pep_template["key"], pep_template["version"]
    ):
        _fail("PEP_TEMPLATE_INVALID")
    pep_protection_template = _validate_object(
        data.get("pep_protection_template"),
        keys=_TEMPLATE_KEYS,
        key_pattern=_PEP_PROTECTION_TEMPLATE_KEY_RE,
        source_commit=source_commit,
        code="PEP_PROTECTION_TEMPLATE_INVALID",
    )
    if pep_protection_template["url"] != _expected_url(
        pep_protection_template["bucket"],
        pep_protection_template["key"],
        pep_protection_template["version"],
    ):
        _fail("PEP_PROTECTION_TEMPLATE_INVALID")
    pep_artifact = _validate_object(
        data.get("pep_artifact"),
        keys=_OBJECT_KEYS,
        key_pattern=_PEP_ARTIFACT_KEY_RE,
        source_commit=None,
        code="PEP_ARTIFACT_INVALID",
    )
    config, _encoded_config = _validate_config(
        data.get("broker_config"),
        source_commit=source_commit,
        repair_id=repair_id,
        route_not_before=route_not_before,
        route_not_after=route_not_after,
    )
    if (
        config["requests"]["pep-create-v1"]["TemplateURL"]
        != pep_template["url"]
        or config["requests"]["pep-protection-create-v1"]["TemplateURL"]
        != pep_protection_template["url"]
        or pep_template["url"] == pep_protection_template["url"]
        or pep_template["key"] == pep_protection_template["key"]
        or pep_template["version"] == pep_protection_template["version"]
    ):
        _fail("PEP_TEMPLATE_CONFIG_BINDING_INVALID")
    storage = broker_code["upstream_storage_binding"]
    if (
        pep_runtime["upstream_storage_binding_digest"]
        != storage["binding_digest"]
        or foundation_binding_digest != storage["binding_digest"]
        or config["foundation_publish_binding_digest"]
        != foundation_binding_digest
        or pep_template["bucket"] != storage["bucket"]
        or pep_protection_template["bucket"] != storage["bucket"]
        or pep_artifact["bucket"] != storage["bucket"]
    ):
        _fail("PEP_STORAGE_BINDING_INVALID")
    data["source_template"] = dict(source)
    data["artifact_bootstrap_intent"] = validated_bootstrap
    data["foundation_publish_binding"] = validated_foundation
    data["broker_code"] = dict(broker_code)
    data["pep_template"] = dict(pep_template)
    data["pep_protection_template"] = dict(pep_protection_template)
    data["pep_artifact"] = dict(pep_artifact)
    data["pep_runtime_binding"] = dict(pep_runtime)
    data["broker_config"] = config
    return data


def _git(source_root: Path, args: Sequence[str], code: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=source_root,
            check=True,
            capture_output=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BrokerSeedError(code) from exc
    return completed.stdout


def _clean_main(source_root: Path, source_commit: str) -> None:
    if (
        not source_root.is_absolute()
        or source_root.is_symlink()
        or not source_root.is_dir()
    ):
        _fail("SOURCE_ROOT_INVALID")
    try:
        if source_root.resolve(strict=True) != source_root:
            _fail("SOURCE_ROOT_INVALID")
    except OSError:
        _fail("SOURCE_ROOT_INVALID")
    head = _git(source_root, ["rev-parse", "HEAD"], "SOURCE_GIT_INVALID").decode(
        "ascii"
    ).strip()
    branch = _git(
        source_root, ["branch", "--show-current"], "SOURCE_GIT_INVALID"
    ).decode("utf-8").strip()
    dirty = _git(
        source_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        "SOURCE_GIT_INVALID",
    )
    if head != source_commit or branch != "main" or dirty:
        _fail("SOURCE_NOT_EXACT_CLEAN_MAIN")


def _source_bytes(source_root: Path, data: Mapping[str, Any]) -> bytes:
    _clean_main(source_root, data["source_commit"])
    head = data["source_commit"]
    relative = SOURCE_TEMPLATE_PATH.as_posix()
    committed = _git(
        source_root,
        ["show", f"{head}:{relative}"],
        "SOURCE_TEMPLATE_GIT_OBJECT_INVALID",
    )
    path = source_root / SOURCE_TEMPLATE_PATH
    try:
        metadata = path.lstat()
        working = path.read_bytes()
    except OSError as exc:
        raise BrokerSeedError("SOURCE_TEMPLATE_INVALID") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        _fail("SOURCE_TEMPLATE_INVALID")
    digest = "sha256:" + sha256(committed).hexdigest()
    if working != committed or digest != data["source_template"]["sha256"]:
        _fail("SOURCE_TEMPLATE_DIGEST_MISMATCH")
    return committed


def _exact_git_file(
    source_root: Path, *, source_commit: str, relative_path: Path
) -> bytes:
    relative = relative_path.as_posix()
    committed = _git(
        source_root,
        ["show", f"{source_commit}:{relative}"],
        "BROKER_PACKAGE_SOURCE_INVALID",
    )
    path = source_root / relative_path
    try:
        metadata = path.lstat()
        working = path.read_bytes()
    except OSError as exc:
        raise BrokerSeedError("BROKER_PACKAGE_SOURCE_INVALID") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or working != committed
    ):
        _fail("BROKER_PACKAGE_SOURCE_INVALID")
    return committed


def build_broker_package(*, source_root: Path, source_commit: str) -> bytes:
    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("SOURCE_COMMIT_INVALID")
    _clean_main(source_root, source_commit)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative_path in PACKAGE_SOURCE_PATHS:
            payload = _exact_git_file(
                source_root,
                source_commit=source_commit,
                relative_path=relative_path,
            )
            info = zipfile.ZipInfo(relative_path.as_posix())
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, payload)
    package = output.getvalue()
    return package


def _load_rendered_yaml(payload: bytes) -> Mapping[str, Any]:
    """Load generated YAML only when rendering is actually requested.

    Keeping PyYAML behind this boundary lets the CLI expose its offline help
    under ``python -I -S`` without importing any site package.
    """

    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:
        raise BrokerSeedError("YAML_RUNTIME_UNAVAILABLE") from exc

    class Loader(yaml.SafeLoader):
        def construct_mapping(
            self, node: Any, deep: bool = False
        ) -> dict[Any, Any]:
            result: dict[Any, Any] = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r}",
                        key_node.start_mark,
                    )
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    def intrinsic(loader: Loader, suffix: str, node: Any) -> object:
        if isinstance(node, yaml.ScalarNode):
            value: object = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node)
        else:
            value = loader.construct_mapping(node)
        return {"Ref" if suffix == "Ref" else f"Fn::{suffix}": value}

    Loader.add_multi_constructor("!", intrinsic)
    try:
        loaded = yaml.load(payload.decode("utf-8"), Loader=Loader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise BrokerSeedError("GENERATED_TEMPLATE_INVALID") from exc
    if not isinstance(loaded, Mapping):
        _fail("GENERATED_TEMPLATE_INVALID")
    return loaded


def _exact_source_bytes(
    source_root: Path,
    *,
    source_commit: str,
    relative_path: Path,
    code: str,
) -> bytes:
    """Read one reviewed working/Git object pair after the clean-main gate."""

    if not isinstance(source_commit, str) or _SHA_RE.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_INVALID")
    _clean_main(source_root, source_commit)
    committed = _git(
        source_root,
        ["show", f"{source_commit}:{relative_path.as_posix()}"],
        code,
    )
    path = source_root / relative_path
    try:
        metadata = path.lstat()
        working = path.read_bytes()
    except OSError as exc:
        raise BrokerSeedError(code) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or working != committed
    ):
        _fail(code)
    return committed


def render_pep_template_from_source(
    *, source: bytes, protection_enabled: bool
) -> bytes:
    """Render one immutable PEP lifecycle variant from reviewed source bytes."""

    if (
        type(protection_enabled) is not bool
        or type(source) is not bytes
        or not source
        or len(source) > MAX_TEMPLATE_URL_BYTES
        or b"\x00" in source
    ):
        _fail("PEP_TEMPLATE_SOURCE_INVALID")
    replacements = {
        b"PEP_LEDGER_PROTECTION_BOOLEAN_SENTINEL": (
            b"true" if protection_enabled else b"false"
        ),
        b"PEP_LEDGER_PROTECTION_TEXT_SENTINEL": (
            b"'true'" if protection_enabled else b"'false'"
        ),
        b"PEP_DELETION_POLICY_SENTINEL": (
            b"Retain" if protection_enabled else b"Delete"
        ),
        b"PEP_UPDATE_REPLACE_POLICY_SENTINEL": (
            b"Retain" if protection_enabled else b"Delete"
        ),
    }
    if set(_PEP_VARIANT_SENTINEL_RE.findall(source)) != set(replacements):
        _fail("PEP_TEMPLATE_PLACEHOLDERS_INVALID")
    rendered = source
    for token, value in replacements.items():
        rendered = rendered.replace(token, value)
    if (
        _PEP_VARIANT_SENTINEL_RE.search(rendered)
        or len(rendered) > MAX_TEMPLATE_URL_BYTES
    ):
        _fail("PEP_GENERATED_TEMPLATE_INVALID")
    loaded = _load_rendered_yaml(rendered)
    resources = loaded.get("Resources")
    parameters = loaded.get("Parameters")
    outputs = loaded.get("Outputs")
    expected_policy = "Retain" if protection_enabled else "Delete"
    if (
        loaded.get("AWSTemplateFormatVersion") != "2010-09-09"
        or not isinstance(parameters, Mapping)
        or "LedgerDeletionProtectionEnabled" in parameters
        or "Conditions" in loaded
        or not isinstance(resources, Mapping)
        or not isinstance(outputs, Mapping)
        or resources.get("RepairLedger", {}).get("Properties", {}).get(
            "DeletionProtectionEnabled"
        )
        is not protection_enabled
        or outputs.get("LedgerDeletionProtectionMode", {}).get("Value")
        != ("true" if protection_enabled else "false")
    ):
        _fail("PEP_GENERATED_TEMPLATE_INVALID")
    lifecycle_ids = sorted(
        logical_id
        for logical_id, resource in resources.items()
        if isinstance(resource, Mapping)
        and (
            "DeletionPolicy" in resource or "UpdateReplacePolicy" in resource
        )
    )
    if lifecycle_ids != list(PEP_LIFECYCLE_RESOURCE_IDS) or any(
        not isinstance(resources[logical_id], Mapping)
        or resources[logical_id].get("DeletionPolicy") != expected_policy
        or resources[logical_id].get("UpdateReplacePolicy") != expected_policy
        for logical_id in PEP_LIFECYCLE_RESOURCE_IDS
    ):
        _fail("PEP_GENERATED_TEMPLATE_INVALID")
    return rendered


def validate_pep_template_materialization_receipt(
    value: object, *, expected_protection_enabled: bool
) -> dict[str, Any]:
    """Validate one exact CREATE/protection PEP materialization receipt."""

    if type(expected_protection_enabled) is not bool:
        _fail("PEP_TEMPLATE_VARIANT_INVALID")
    receipt = dict(
        _exact_keys(
            value,
            _PEP_TEMPLATE_RECEIPT_KEYS,
            "PEP_TEMPLATE_MATERIALIZATION_RECEIPT_INVALID",
        )
    )
    variant = "protection" if expected_protection_enabled else "create"
    output_name = (
        PEP_PROTECTION_OUTPUT_NAME if expected_protection_enabled else PEP_OUTPUT_NAME
    )
    policy = "Retain" if expected_protection_enabled else "Delete"
    if (
        receipt.get("record_type") != PEP_TEMPLATE_RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or _SHA_RE.fullmatch(str(receipt.get("source_commit", ""))) is None
        or receipt.get("source_path") != PEP_SOURCE_TEMPLATE_PATH.as_posix()
        or _DIGEST_RE.fullmatch(str(receipt.get("source_sha256", ""))) is None
        or receipt.get("template_variant") != variant
        or receipt.get("output_name") != output_name
        or _DIGEST_RE.fullmatch(str(receipt.get("template_sha256", ""))) is None
        or type(receipt.get("template_bytes")) is not int
        or not 0 < receipt["template_bytes"] <= MAX_TEMPLATE_URL_BYTES
        or receipt.get("ledger_deletion_protection_enabled")
        is not expected_protection_enabled
        or receipt.get("lifecycle_deletion_policy") != policy
        or receipt.get("lifecycle_update_replace_policy") != policy
        or receipt.get("lifecycle_resource_ids")
        != list(PEP_LIFECYCLE_RESOURCE_IDS)
        or receipt.get("variant_controls_parameterless") is not True
        or receipt.get("private_mode") != "0600"
        or receipt.get("aws_calls") != 0
        or receipt.get("aws_mutations") != 0
        or receipt.get("deployment_authorized") is not False
        or receipt.get("production_status") != PRODUCTION_STATUS
        or receipt.get("receipt_digest")
        != digest_value(
            {
                key: item
                for key, item in receipt.items()
                if key != "receipt_digest"
            }
        )
    ):
        _fail("PEP_TEMPLATE_MATERIALIZATION_RECEIPT_INVALID")
    return json.loads(canonical_json(receipt))


def materialize_pep_template(
    *,
    source_root: Path,
    private_root: Path,
    source_commit: str,
    protection_enabled: bool,
) -> tuple[Path, dict[str, Any]]:
    """Materialize one exact PEP variant without any provider interaction."""

    source = _exact_source_bytes(
        source_root,
        source_commit=source_commit,
        relative_path=PEP_SOURCE_TEMPLATE_PATH,
        code="PEP_TEMPLATE_SOURCE_INVALID",
    )
    rendered = render_pep_template_from_source(
        source=source, protection_enabled=protection_enabled
    )
    output_name = (
        PEP_PROTECTION_OUTPUT_NAME if protection_enabled else PEP_OUTPUT_NAME
    )
    destination = _write_private_payload(
        private_root=private_root,
        name=output_name,
        payload=rendered,
    )
    receipt = {
        "record_type": PEP_TEMPLATE_RECEIPT_TYPE,
        "schema_version": 1,
        "source_commit": source_commit,
        "source_path": PEP_SOURCE_TEMPLATE_PATH.as_posix(),
        "source_sha256": "sha256:" + sha256(source).hexdigest(),
        "template_variant": "protection" if protection_enabled else "create",
        "output_name": output_name,
        "template_sha256": "sha256:" + sha256(rendered).hexdigest(),
        "template_bytes": len(rendered),
        "ledger_deletion_protection_enabled": protection_enabled,
        "lifecycle_deletion_policy": "Retain" if protection_enabled else "Delete",
        "lifecycle_update_replace_policy": (
            "Retain" if protection_enabled else "Delete"
        ),
        "lifecycle_resource_ids": list(PEP_LIFECYCLE_RESOURCE_IDS),
        "variant_controls_parameterless": True,
        "private_mode": "0600",
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    receipt["receipt_digest"] = digest_value(receipt)
    return destination, validate_pep_template_materialization_receipt(
        receipt, expected_protection_enabled=protection_enabled
    )


def materialize_pep_template_pair(
    *, source_root: Path, private_root: Path, source_commit: str
) -> dict[str, tuple[Path, dict[str, Any]]]:
    """Materialize the immutable PEP CREATE/protection pair."""

    create = materialize_pep_template(
        source_root=source_root,
        private_root=private_root,
        source_commit=source_commit,
        protection_enabled=False,
    )
    protection = materialize_pep_template(
        source_root=source_root,
        private_root=private_root,
        source_commit=source_commit,
        protection_enabled=True,
    )
    if (
        create[1]["template_sha256"] == protection[1]["template_sha256"]
        or create[1]["receipt_digest"] == protection[1]["receipt_digest"]
    ):
        _fail("PEP_TEMPLATE_VARIANTS_NOT_DISTINCT")
    return {
        "pep_template": create,
        "pep_protection_template": protection,
    }


def _resolve_policy_intrinsics(value: object) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"Fn::Sub"}:
            template = value["Fn::Sub"]
            if not isinstance(template, str):
                _fail("EFFECTIVE_POLICY_INTRINSIC_INVALID")
            resolved = template.replace("${AWS::Partition}", "aws")
            if re.search(r"\$\{[^}]+\}", resolved):
                _fail("EFFECTIVE_POLICY_INTRINSIC_INVALID")
            return resolved
        if any(key == "Ref" or str(key).startswith("Fn::") for key in value):
            _fail("EFFECTIVE_POLICY_INTRINSIC_INVALID")
        return {
            str(key): _resolve_policy_intrinsics(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_resolve_policy_intrinsics(child) for child in value]
    if value is None or isinstance(value, (bool, int, str)):
        return value
    _fail("EFFECTIVE_POLICY_VALUE_INVALID")


def _policy_string_set(value: object, code: str) -> list[str]:
    items = [value] if isinstance(value, str) else value
    if (
        not isinstance(items, list)
        or not items
        or any(not isinstance(item, str) or not item for item in items)
        or len(set(items)) != len(items)
    ):
        _fail(code)
    return sorted(items)


def _canonical_condition(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        _fail("EFFECTIVE_POLICY_CONDITION_INVALID")
    result: dict[str, Any] = {}
    for operator, conditions in value.items():
        if not isinstance(operator, str) or not isinstance(conditions, Mapping):
            _fail("EFFECTIVE_POLICY_CONDITION_INVALID")
        projected: dict[str, Any] = {}
        for key, raw in conditions.items():
            if not isinstance(key, str) or not key:
                _fail("EFFECTIVE_POLICY_CONDITION_INVALID")
            items = raw if isinstance(raw, list) else [raw]
            if (
                not items
                or any(
                    item is not None and not isinstance(item, (bool, int, str))
                    for item in items
                )
            ):
                _fail("EFFECTIVE_POLICY_CONDITION_INVALID")
            projected[key] = sorted(items, key=canonical_json)
        result[operator] = projected
    return result


def canonicalize_policy_document(value: object) -> dict[str, Any]:
    """Return a semantic, order-stable projection of one IAM policy document."""

    resolved = _resolve_policy_intrinsics(value)
    if not isinstance(resolved, Mapping) or set(resolved) != {"Version", "Statement"}:
        _fail("EFFECTIVE_POLICY_DOCUMENT_INVALID")
    statements = resolved["Statement"]
    if (
        resolved["Version"] != "2012-10-17"
        or not isinstance(statements, list)
        or not statements
    ):
        _fail("EFFECTIVE_POLICY_DOCUMENT_INVALID")
    allowed_keys = {
        "Sid",
        "Effect",
        "Principal",
        "NotPrincipal",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Condition",
    }
    projected: list[dict[str, Any]] = []
    seen_sids: set[str] = set()
    for raw in statements:
        if not isinstance(raw, Mapping) or not set(raw) <= allowed_keys:
            _fail("EFFECTIVE_POLICY_STATEMENT_INVALID")
        sid = raw.get("Sid")
        if (
            not isinstance(sid, str)
            or not sid
            or sid in seen_sids
            or raw.get("Effect") not in {"Allow", "Deny"}
            or not ({"Action", "NotAction"} & set(raw))
            or not ({"Resource", "NotResource"} & set(raw))
        ):
            _fail("EFFECTIVE_POLICY_STATEMENT_INVALID")
        seen_sids.add(sid)
        statement: dict[str, Any] = {"Sid": sid, "Effect": raw["Effect"]}
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in raw:
                statement[key] = _policy_string_set(
                    raw[key], "EFFECTIVE_POLICY_STATEMENT_INVALID"
                )
        for key in ("Principal", "NotPrincipal"):
            if key not in raw:
                continue
            principal = raw[key]
            if isinstance(principal, str):
                statement[key] = principal
            elif isinstance(principal, Mapping) and principal:
                statement[key] = {
                    str(principal_type): _policy_string_set(
                        identities, "EFFECTIVE_POLICY_PRINCIPAL_INVALID"
                    )
                    for principal_type, identities in principal.items()
                    if isinstance(principal_type, str) and principal_type
                }
                if len(statement[key]) != len(principal):
                    _fail("EFFECTIVE_POLICY_PRINCIPAL_INVALID")
            else:
                _fail("EFFECTIVE_POLICY_PRINCIPAL_INVALID")
        if "Condition" in raw:
            statement["Condition"] = _canonical_condition(raw["Condition"])
        projected.append(statement)
    projected.sort(key=lambda item: item["Sid"])
    return {"Version": "2012-10-17", "Statement": projected}


def _policy_entry(
    *,
    logical_resource_id: str,
    policy_type: str,
    selector: Mapping[str, str],
    document: object,
) -> dict[str, Any]:
    projected = canonicalize_policy_document(document)
    return {
        "logical_resource_id": logical_resource_id,
        "policy_type": policy_type,
        "selector": dict(selector),
        "document": projected,
        "document_digest": digest_value(projected),
    }


def derive_effective_policy_projection(
    *, rendered_template: bytes, source_commit: str
) -> dict[str, Any]:
    """Project the six live-readback policies from one rendered seed template."""

    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("EFFECTIVE_POLICY_SOURCE_INVALID")
    loaded = _load_rendered_yaml(rendered_template)
    resources = loaded.get("Resources")
    if not isinstance(resources, Mapping):
        _fail("EFFECTIVE_POLICY_RESOURCES_INVALID")

    def resource(logical_id: str, resource_type: str) -> Mapping[str, Any]:
        value = resources.get(logical_id)
        if (
            not isinstance(value, Mapping)
            or value.get("Type") != resource_type
            or not isinstance(value.get("Properties"), Mapping)
        ):
            _fail("EFFECTIVE_POLICY_RESOURCE_INVALID")
        return value["Properties"]

    creator = resource("CreatorRole", "AWS::IAM::Role")
    executor = resource("ExecutorRole", "AWS::IAM::Role")
    create_recovery = resource("CreateDispatchRecoveryRole", "AWS::IAM::Role")
    execute_recovery = resource("ExecuteDispatchRecoveryRole", "AWS::IAM::Role")

    def inline_policy(
        properties: Mapping[str, Any],
        *,
        logical_id: str,
        role_name: str,
        policy_name: str,
    ) -> dict[str, Any]:
        policies = properties.get("Policies")
        if (
            properties.get("RoleName") != role_name
            or not isinstance(policies, list)
            or len(policies) != 1
            or not isinstance(policies[0], Mapping)
            or policies[0].get("PolicyName") != policy_name
        ):
            _fail("EFFECTIVE_POLICY_INLINE_INVALID")
        return _policy_entry(
            logical_resource_id=logical_id,
            policy_type="iam_inline_policy",
            selector={
                "role_arn": f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/{role_name}",
                "role_name": role_name,
                "policy_name": policy_name,
            },
            document=policies[0].get("PolicyDocument"),
        )

    ledger = resource("BrokerLedger", "AWS::DynamoDB::Table")
    key = resource("BrokerLedgerKey", "AWS::KMS::Key")
    key_alias = resource("BrokerLedgerKeyAlias", "AWS::KMS::Alias")
    table_name = "scanalyze-platform-authority-gug376-route-broker-ledger"
    alias_name = "alias/scanalyze/platform-authority/gug376-route-broker-ledger"
    resource_policy = ledger.get("ResourcePolicy")
    if (
        ledger.get("TableName") != table_name
        or not isinstance(resource_policy, Mapping)
        or key_alias.get("AliasName") != alias_name
    ):
        _fail("EFFECTIVE_POLICY_RESOURCE_INVALID")
    policies = {
        "creator_role_inline_policy": inline_policy(
            creator,
            logical_id="CreatorRole",
            role_name="ScanalyzeGug376RouteBrokerCreator",
            policy_name="ExactBrokerCreation",
        ),
        "executor_role_inline_policy": inline_policy(
            executor,
            logical_id="ExecutorRole",
            role_name="ScanalyzeGug376RouteBrokerExecutor",
            policy_name="ExactBrokerExecution",
        ),
        "create_dispatch_recovery_role_inline_policy": inline_policy(
            create_recovery,
            logical_id="CreateDispatchRecoveryRole",
            role_name="ScanalyzeGug376RouteCreateDispatchRecovery",
            policy_name="ExactCreateDispatchRecoveryReadback",
        ),
        "execute_dispatch_recovery_role_inline_policy": inline_policy(
            execute_recovery,
            logical_id="ExecuteDispatchRecoveryRole",
            role_name="ScanalyzeGug376RouteExecuteDispatchRecovery",
            policy_name="ExactExecuteDispatchRecoveryReadback",
        ),
        "broker_ledger_resource_policy": _policy_entry(
            logical_resource_id="BrokerLedger",
            policy_type="dynamodb_resource_policy",
            selector={
                "resource_arn": (
                    f"arn:aws:dynamodb:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
                    f"table/{table_name}"
                ),
                "table_name": table_name,
            },
            document=resource_policy.get("PolicyDocument"),
        ),
        "broker_ledger_key_policy": _policy_entry(
            logical_resource_id="BrokerLedgerKey",
            policy_type="kms_key_policy",
            selector={"key_id": alias_name, "policy_name": "default"},
            document=key.get("KeyPolicy"),
        ),
    }
    projection: dict[str, Any] = {
        "record_type": EFFECTIVE_POLICY_PROJECTION_TYPE,
        "schema_version": 1,
        "source_commit": source_commit,
        "partition": "aws",
        "account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "policies": policies,
    }
    projection["projection_digest"] = digest_value(projection)
    return validate_effective_policy_projection(
        projection, source_commit=source_commit
    )


def validate_effective_policy_projection(
    value: object, *, source_commit: str
) -> dict[str, Any]:
    projection = dict(
        _exact_keys(
            value, _POLICY_PROJECTION_KEYS, "EFFECTIVE_POLICY_PROJECTION_INVALID"
        )
    )
    policies = _exact_keys(
        projection.get("policies"),
        _POLICY_PROJECTION_NAMES,
        "EFFECTIVE_POLICY_PROJECTION_INVALID",
    )
    if (
        projection.get("record_type") != EFFECTIVE_POLICY_PROJECTION_TYPE
        or projection.get("schema_version") != 1
        or projection.get("source_commit") != source_commit
        or projection.get("partition") != "aws"
        or projection.get("account_id") != AUTHORITY_ACCOUNT_ID
        or projection.get("region") != REGION
    ):
        _fail("EFFECTIVE_POLICY_PROJECTION_INVALID")
    expected_entries = {
        "creator_role_inline_policy": {
            "logical_resource_id": "CreatorRole",
            "policy_type": "iam_inline_policy",
            "selector": {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/"
                    "ScanalyzeGug376RouteBrokerCreator"
                ),
                "role_name": "ScanalyzeGug376RouteBrokerCreator",
                "policy_name": "ExactBrokerCreation",
            },
        },
        "executor_role_inline_policy": {
            "logical_resource_id": "ExecutorRole",
            "policy_type": "iam_inline_policy",
            "selector": {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/"
                    "ScanalyzeGug376RouteBrokerExecutor"
                ),
                "role_name": "ScanalyzeGug376RouteBrokerExecutor",
                "policy_name": "ExactBrokerExecution",
            },
        },
        "create_dispatch_recovery_role_inline_policy": {
            "logical_resource_id": "CreateDispatchRecoveryRole",
            "policy_type": "iam_inline_policy",
            "selector": {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/"
                    "ScanalyzeGug376RouteCreateDispatchRecovery"
                ),
                "role_name": "ScanalyzeGug376RouteCreateDispatchRecovery",
                "policy_name": "ExactCreateDispatchRecoveryReadback",
            },
        },
        "execute_dispatch_recovery_role_inline_policy": {
            "logical_resource_id": "ExecuteDispatchRecoveryRole",
            "policy_type": "iam_inline_policy",
            "selector": {
                "role_arn": (
                    "arn:aws:iam::042360977644:role/"
                    "ScanalyzeGug376RouteExecuteDispatchRecovery"
                ),
                "role_name": "ScanalyzeGug376RouteExecuteDispatchRecovery",
                "policy_name": "ExactExecuteDispatchRecoveryReadback",
            },
        },
        "broker_ledger_resource_policy": {
            "logical_resource_id": "BrokerLedger",
            "policy_type": "dynamodb_resource_policy",
            "selector": {
                "resource_arn": (
                    "arn:aws:dynamodb:us-east-1:042360977644:table/"
                    "scanalyze-platform-authority-gug376-route-broker-ledger"
                ),
                "table_name": (
                    "scanalyze-platform-authority-gug376-route-broker-ledger"
                ),
            },
        },
        "broker_ledger_key_policy": {
            "logical_resource_id": "BrokerLedgerKey",
            "policy_type": "kms_key_policy",
            "selector": {
                "key_id": (
                    "alias/scanalyze/platform-authority/gug376-route-broker-ledger"
                ),
                "policy_name": "default",
            },
        },
    }
    validated: dict[str, Any] = {}
    for name, raw in policies.items():
        entry = dict(
            _exact_keys(raw, _POLICY_ENTRY_KEYS, "EFFECTIVE_POLICY_ENTRY_INVALID")
        )
        selector = entry.get("selector")
        if (
            not isinstance(selector, Mapping)
            or dict(selector) != expected_entries[name]["selector"]
            or any(not isinstance(item, str) or not item for item in selector.values())
            or entry.get("logical_resource_id")
            != expected_entries[name]["logical_resource_id"]
            or entry.get("policy_type") != expected_entries[name]["policy_type"]
        ):
            _fail("EFFECTIVE_POLICY_SELECTOR_INVALID")
        document = canonicalize_policy_document(entry.get("document"))
        if (
            document != entry.get("document")
            or entry.get("document_digest") != digest_value(document)
        ):
            _fail("EFFECTIVE_POLICY_DOCUMENT_DIGEST_INVALID")
        entry["selector"] = dict(selector)
        entry["document"] = document
        validated[name] = entry
    projection["policies"] = validated
    claimed = projection.get("projection_digest")
    expected = digest_value(
        {key: item for key, item in projection.items() if key != "projection_digest"}
    )
    if claimed != expected:
        _fail("EFFECTIVE_POLICY_PROJECTION_DIGEST_INVALID")
    return json.loads(canonical_json(projection))


def render_template_from_source(
    *,
    source: bytes,
    private_input: Mapping[str, Any],
    protection_enabled: bool = False,
) -> bytes:
    """Purely render reviewed source bytes without Git, filesystem, or AWS I/O."""

    data = validate_input(private_input)
    if type(protection_enabled) is not bool:
        _fail("BROKER_TEMPLATE_VARIANT_INVALID")
    if (
        type(source) is not bytes
        or not source
        or len(source) > MAX_TEMPLATE_URL_BYTES
        or b"\x00" in source
        or "sha256:" + sha256(source).hexdigest()
        != data["source_template"]["sha256"]
    ):
        _fail("SOURCE_TEMPLATE_DIGEST_MISMATCH")
    _config, runtime_config_json = _validate_config(
        data["broker_config"],
        source_commit=data["source_commit"],
        repair_id=data["repair_id"],
        route_not_before=data["route_not_before"],
        route_not_after=data["route_not_after"],
    )
    replacements = {
        b"@@SOURCE_COMMIT@@": data["source_commit"],
        b"@@ROUTE_NOT_BEFORE@@": data["route_not_before"],
        b"@@ROUTE_NOT_AFTER@@": data["route_not_after"],
        b"@@RECOVERY_NOT_AFTER@@": data["broker_config"][
            "recovery_not_after"
        ],
        b"@@REPAIR_ID@@": data["repair_id"],
        b"@@BROKER_CODE_BUCKET@@": data["broker_code"]["signed_artifact"][
            "bucket"
        ],
        b"@@BROKER_CODE_KEY@@": data["broker_code"]["signed_artifact"]["key"],
        b"@@BROKER_CODE_VERSION@@": data["broker_code"]["signed_artifact"][
            "version"
        ],
        b"@@BROKER_CODE_SHA256@@": data["broker_code"]["signed_artifact"][
            "code_sha256"
        ],
        b"@@BROKER_SIGNING_PROFILE_VERSION_ARN@@": data["broker_code"][
            "signing_job"
        ]["profile_version_arn"],
        b"@@BROKER_CONFIG_DIGEST@@": data["broker_config"]["config_digest"],
        b"@@ARTIFACT_KMS_KEY_ARN@@": data["foundation_publish_binding"][
            "sse_kms_key_arn"
        ],
        b"@@PEP_TEMPLATE_BUCKET@@": data["pep_template"]["bucket"],
        b"@@PEP_TEMPLATE_KEY@@": data["pep_template"]["key"],
        b"@@PEP_TEMPLATE_VERSION@@": data["pep_template"]["version"],
        b"@@PEP_TEMPLATE_URL@@": data["pep_template"]["url"],
        b"@@PEP_PROTECTION_TEMPLATE_BUCKET@@": data[
            "pep_protection_template"
        ]["bucket"],
        b"@@PEP_PROTECTION_TEMPLATE_KEY@@": data[
            "pep_protection_template"
        ]["key"],
        b"@@PEP_PROTECTION_TEMPLATE_VERSION@@": data[
            "pep_protection_template"
        ]["version"],
        b"@@PEP_PROTECTION_TEMPLATE_URL@@": data[
            "pep_protection_template"
        ]["url"],
        b"@@PEP_ARTIFACT_BUCKET@@": data["pep_artifact"]["bucket"],
        b"@@PEP_ARTIFACT_KEY@@": data["pep_artifact"]["key"],
        b"@@PEP_ARTIFACT_VERSION@@": data["pep_artifact"]["version"],
        b"@@BROKER_CONFIG_JSON_YAML@@": json.dumps(runtime_config_json),
        b"@@BROKER_LEDGER_PROTECTION_BOOLEAN@@": (
            b"true" if protection_enabled else b"false"
        ),
        b"@@BROKER_LEDGER_PROTECTION_TEXT@@": (
            b"true" if protection_enabled else b"false"
        ),
        b"@@BROKER_DELETION_POLICY@@": (
            b"Retain" if protection_enabled else b"Delete"
        ),
        b"@@BROKER_UPDATE_REPLACE_POLICY@@": (
            b"Retain" if protection_enabled else b"Delete"
        ),
    }
    if set(_PLACEHOLDER_RE.findall(source)) != set(replacements):
        _fail("SOURCE_TEMPLATE_PLACEHOLDERS_INVALID")
    rendered = source
    for token, value in replacements.items():
        if isinstance(value, str):
            replacement = value.encode("utf-8")
        else:
            replacement = value
        rendered = rendered.replace(token, replacement)
    if (
        _PLACEHOLDER_RE.search(rendered)
        or len(rendered) > MAX_TEMPLATE_URL_BYTES
    ):
        _fail("GENERATED_TEMPLATE_INVALID")
    loaded = _load_rendered_yaml(rendered)
    if (
        not isinstance(loaded, Mapping)
        or "Parameters" in loaded
        or loaded.get("AWSTemplateFormatVersion") != "2010-09-09"
        or not isinstance(loaded.get("Resources"), Mapping)
        or loaded["Resources"]["BrokerLedger"]["Properties"].get(
            "DeletionProtectionEnabled"
        )
        is not protection_enabled
        or loaded.get("Outputs", {})
        .get("BrokerLedgerDeletionProtectionMode", {})
        .get("Value")
        != ("true" if protection_enabled else "false")
        or loaded.get("Outputs", {}).get("ParametersAccepted", {}).get("Value")
        != "false"
        or any(
            resource.get("DeletionPolicy")
            != ("Retain" if protection_enabled else "Delete")
            or resource.get("UpdateReplacePolicy")
            != ("Retain" if protection_enabled else "Delete")
            for resource in loaded["Resources"].values()
            if "DeletionPolicy" in resource or "UpdateReplacePolicy" in resource
        )
    ):
        _fail("GENERATED_TEMPLATE_INVALID")
    environment = loaded["Resources"]["CreatorFunction"]["Properties"][
        "Environment"
    ]["Variables"]
    environment_size = sum(
        len(str(key).encode("utf-8")) + len(str(value).encode("utf-8"))
        for key, value in environment.items()
    )
    if environment_size > MAX_LAMBDA_ENVIRONMENT_BYTES:
        _fail("BROKER_ENVIRONMENT_TOO_LARGE")
    derive_effective_policy_projection(
        rendered_template=rendered,
        source_commit=data["source_commit"],
    )
    return rendered


def render_template(
    *,
    source_root: Path,
    private_input: Mapping[str, Any],
    protection_enabled: bool = False,
) -> bytes:
    data = validate_input(private_input)
    source = _source_bytes(source_root, data)
    # Bind the unsigned package bytes to the reviewed Git object before the
    # pure source renderer can emit any deployment input.
    package = build_broker_package(
        source_root=source_root,
        source_commit=data["source_commit"],
    )
    unsigned_digest = "sha256:" + sha256(package).hexdigest()
    unsigned = data["broker_code"]["unsigned_artifact"]
    if (
        unsigned_digest != unsigned["sha256"]
        or _code_sha256(unsigned_digest) != unsigned["code_sha256"]
        or len(package) != unsigned["bytes"]
    ):
        _fail("BROKER_UNSIGNED_PACKAGE_DIGEST_MISMATCH")
    return render_template_from_source(
        source=source,
        private_input=data,
        protection_enabled=protection_enabled,
    )


def _private_root(path: Path) -> int:
    if not path.is_absolute() or path.is_symlink():
        _fail("PRIVATE_ROOT_INVALID")
    try:
        if path.resolve(strict=True) != path:
            _fail("PRIVATE_ROOT_INVALID")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise BrokerSeedError("PRIVATE_ROOT_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        _fail("PRIVATE_ROOT_MODE_INVALID")
    return descriptor


def _write_private_payload(*, private_root: Path, name: str, payload: bytes) -> Path:
    root_fd = _private_root(private_root)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
                dir_fd=root_fd,
            )
            created = True
        except FileExistsError as exc:
            raise BrokerSeedError("PRIVATE_OUTPUT_EXISTS") from exc
        except OSError as exc:
            raise BrokerSeedError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError
                remaining = remaining[written:]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(payload)
            ):
                _fail("PRIVATE_OUTPUT_INVALID")
        except (OSError, BrokerSeedError) as exc:
            if created:
                try:
                    os.unlink(name, dir_fd=root_fd)
                except OSError:
                    pass
            if isinstance(exc, BrokerSeedError):
                raise
            raise BrokerSeedError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
        finally:
            os.close(descriptor)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    return private_root / name


def write_private_template(
    *, private_root: Path, payload: bytes, protection_enabled: bool
) -> Path:
    if type(protection_enabled) is not bool:
        _fail("BROKER_TEMPLATE_VARIANT_INVALID")
    return _write_private_payload(
        private_root=private_root,
        name=(PROTECTION_OUTPUT_NAME if protection_enabled else OUTPUT_NAME),
        payload=payload,
    )


def write_private_receipt(
    *, private_root: Path, name: str, receipt: Mapping[str, Any]
) -> Path:
    if name not in {
        PACKAGE_RECEIPT_OUTPUT_NAME,
        MATERIALIZATION_RECEIPT_OUTPUT_NAME,
        PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME,
    }:
        _fail("PRIVATE_RECEIPT_NAME_INVALID")
    return _write_private_payload(
        private_root=private_root,
        name=name,
        payload=(canonical_json(dict(receipt)) + "\n").encode("utf-8"),
    )


def build_private_broker_package(
    *, source_root: Path, private_root: Path, source_commit: str
) -> tuple[Path, dict[str, Any]]:
    package = build_broker_package(
        source_root=source_root,
        source_commit=source_commit,
    )
    path = _write_private_payload(
        private_root=private_root,
        name=PACKAGE_OUTPUT_NAME,
        payload=package,
    )
    receipt = {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_broker_package_receipt.v1"
        ),
        "schema_version": 1,
        "source_commit": source_commit,
        "package_name": PACKAGE_OUTPUT_NAME,
        "package_sha256": "sha256:" + sha256(package).hexdigest(),
        "package_code_sha256": base64.b64encode(sha256(package).digest()).decode(
            "ascii"
        ),
        "package_bytes": len(package),
        "package_entries": [item.as_posix() for item in PACKAGE_SOURCE_PATHS],
        "deterministic_zip": True,
        "signed": False,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    receipt["receipt_digest"] = digest_value(receipt)
    return path, receipt


def validate_broker_seed_receipt(
    value: object, *, expected_protection_enabled: bool | None = None
) -> dict[str, Any]:
    """Validate the closed offline materialization receipt and policy seal."""

    receipt = dict(
        _exact_keys(
            value,
            _MATERIALIZATION_RECEIPT_KEYS,
            "BROKER_SEED_RECEIPT_INVALID",
        )
    )
    source_commit = receipt.get("source_commit")
    if not isinstance(source_commit, str) or not _SHA_RE.fullmatch(source_commit):
        _fail("BROKER_SEED_RECEIPT_INVALID")
    projection = validate_effective_policy_projection(
        receipt.get("effective_policy_projection"),
        source_commit=source_commit,
    )
    variant = receipt.get("template_variant")
    expected_output = {
        "create": OUTPUT_NAME,
        "protection": PROTECTION_OUTPUT_NAME,
    }.get(variant)
    if expected_protection_enabled is not None:
        if type(expected_protection_enabled) is not bool:
            _fail("BROKER_TEMPLATE_VARIANT_INVALID")
        expected_variant = (
            "protection" if expected_protection_enabled else "create"
        )
        if variant != expected_variant:
            _fail("BROKER_SEED_RECEIPT_VARIANT_MISMATCH")
    digest_fields = (
        "template_sha256",
        "unsigned_package_sha256",
        "signed_package_sha256",
        "signing_receipt_digest",
        "pep_runtime_binding_digest",
        "foundation_publish_binding_digest",
        "effective_policy_projection_digest",
    )
    if (
        receipt.get("record_type") != RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or expected_output is None
        or receipt.get("output_name") != expected_output
        or type(receipt.get("template_bytes")) is not int
        or receipt["template_bytes"] <= 0
        or any(
            not isinstance(receipt.get(key), str)
            or _DIGEST_RE.fullmatch(receipt[key]) is None
            for key in digest_fields
        )
        or not isinstance(receipt.get("signed_package_code_sha256"), str)
        or _CODE_SHA256_RE.fullmatch(receipt["signed_package_code_sha256"])
        is None
        or receipt["unsigned_package_sha256"] == receipt["signed_package_sha256"]
        or receipt.get("effective_policy_projection_digest")
        != projection["projection_digest"]
        or receipt.get("parameters_section_absent") is not True
        or receipt.get("private_mode") != "0600"
        or receipt.get("aws_calls") != 0
        or receipt.get("aws_mutations") != 0
        or receipt.get("deployment_authorized") is not False
        or receipt.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("BROKER_SEED_RECEIPT_INVALID")
    receipt["effective_policy_projection"] = projection
    claimed = receipt.get("receipt_digest")
    if (
        not isinstance(claimed, str)
        or _DIGEST_RE.fullmatch(claimed) is None
        or claimed
        != digest_value(
            {key: item for key, item in receipt.items() if key != "receipt_digest"}
        )
    ):
        _fail("BROKER_SEED_RECEIPT_DIGEST_INVALID")
    return json.loads(canonical_json(receipt))


def materialize_broker_seed(
    *,
    source_root: Path,
    private_root: Path,
    private_input: Mapping[str, Any],
    protection_enabled: bool = False,
) -> tuple[Path, dict[str, Any]]:
    if type(protection_enabled) is not bool:
        _fail("BROKER_TEMPLATE_VARIANT_INVALID")
    rendered = render_template(
        source_root=source_root,
        private_input=private_input,
        protection_enabled=protection_enabled,
    )
    projection = derive_effective_policy_projection(
        rendered_template=rendered,
        source_commit=str(private_input["source_commit"]),
    )
    package = build_broker_package(
        source_root=source_root,
        source_commit=str(private_input["source_commit"]),
    )
    destination = write_private_template(
        private_root=private_root,
        payload=rendered,
        protection_enabled=protection_enabled,
    )
    receipt = {
        "record_type": RECEIPT_TYPE,
        "schema_version": 1,
        "source_commit": private_input["source_commit"],
        "template_variant": (
            "protection" if protection_enabled else "create"
        ),
        "output_name": (
            PROTECTION_OUTPUT_NAME if protection_enabled else OUTPUT_NAME
        ),
        "template_sha256": "sha256:" + sha256(rendered).hexdigest(),
        "template_bytes": len(rendered),
        "unsigned_package_sha256": "sha256:" + sha256(package).hexdigest(),
        "signed_package_sha256": private_input["broker_code"]["signed_artifact"][
            "sha256"
        ],
        "signed_package_code_sha256": private_input["broker_code"][
            "signed_artifact"
        ]["code_sha256"],
        "signing_receipt_digest": private_input["broker_code"]["receipt_digest"],
        "pep_runtime_binding_digest": private_input["pep_runtime_binding"][
            "binding_digest"
        ],
        "foundation_publish_binding_digest": private_input[
            "foundation_publish_binding_digest"
        ],
        "effective_policy_projection": projection,
        "effective_policy_projection_digest": projection["projection_digest"],
        "parameters_section_absent": True,
        "private_mode": "0600",
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    receipt["receipt_digest"] = digest_value(receipt)
    return destination, validate_broker_seed_receipt(
        receipt,
        expected_protection_enabled=protection_enabled,
    )


def materialize_broker_seed_pair(
    *,
    source_root: Path,
    private_root: Path,
    private_input: Mapping[str, Any],
) -> dict[str, tuple[Path, dict[str, Any]]]:
    """Materialize the closed CREATE/protection template pair.

    Both templates are rendered from the same reviewed Git object and private
    input.  The variant bit is a pure materializer input and never becomes a
    CloudFormation parameter.
    """

    create = materialize_broker_seed(
        source_root=source_root,
        private_root=private_root,
        private_input=private_input,
        protection_enabled=False,
    )
    protection = materialize_broker_seed(
        source_root=source_root,
        private_root=private_root,
        private_input=private_input,
        protection_enabled=True,
    )
    if (
        create[1]["template_sha256"] == protection[1]["template_sha256"]
        or create[1]["receipt_digest"] == protection[1]["receipt_digest"]
    ):
        _fail("BROKER_TEMPLATE_VARIANTS_NOT_DISTINCT")
    return {
        "broker_template": create,
        "broker_protection_template": protection,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("PRIVATE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    _fail("PRIVATE_JSON_NONFINITE_NUMBER")


def load_private_input(*, private_root: Path, name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json", name):
        _fail("PRIVATE_INPUT_NAME_INVALID")
    root_fd = _private_root(private_root)
    try:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise BrokerSeedError("PRIVATE_INPUT_INVALID") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size <= 0
                or metadata.st_size > MAX_INPUT_BYTES
            ):
                _fail("PRIVATE_INPUT_INVALID")
            payload = b""
            while len(payload) <= MAX_INPUT_BYTES:
                chunk = os.read(descriptor, min(65_536, MAX_INPUT_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload += chunk
            final = os.fstat(descriptor)
            if final.st_size != metadata.st_size or len(payload) > MAX_INPUT_BYTES:
                _fail("PRIVATE_INPUT_CHANGED")
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    try:
        loaded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except BrokerSeedError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerSeedError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(loaded, dict):
        _fail("PRIVATE_JSON_OBJECT_REQUIRED")
    return loaded


__all__ = [
    "ALL_ALIASES",
    "AUTHORITY_ACCOUNT_ID",
    "BROKER_CONFIG_RECORD_TYPE",
    "BROKER_LEDGER_ID",
    "BROKER_SIGNING_RECEIPT_TYPE",
    "BrokerSeedError",
    "EFFECTIVE_POLICY_PROJECTION_TYPE",
    "MANAGEMENT_ACCOUNT_ID",
    "OUTPUT_NAME",
    "PEP_LIFECYCLE_RESOURCE_IDS",
    "PEP_MATERIALIZATION_RECEIPT_OUTPUT_NAME",
    "PEP_OUTPUT_NAME",
    "PEP_PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME",
    "PEP_PROTECTION_OUTPUT_NAME",
    "PEP_SOURCE_TEMPLATE_PATH",
    "PEP_TEMPLATE_RECEIPT_TYPE",
    "PACKAGE_OUTPUT_NAME",
    "PACKAGE_SOURCE_PATHS",
    "PACKAGE_RECEIPT_OUTPUT_NAME",
    "MATERIALIZATION_RECEIPT_OUTPUT_NAME",
    "PROTECTION_MATERIALIZATION_RECEIPT_OUTPUT_NAME",
    "PROTECTION_OUTPUT_NAME",
    "PRODUCTION_STATUS",
    "PEP_RUNTIME_BINDING_TYPE",
    "RECEIPT_TYPE",
    "RECORD_TYPE",
    "REGION",
    "SOURCE_TEMPLATE_PATH",
    "canonical_json",
    "build_broker_package",
    "build_private_broker_package",
    "canonicalize_policy_document",
    "derive_effective_policy_projection",
    "digest_value",
    "load_private_input",
    "materialize_broker_seed",
    "materialize_broker_seed_pair",
    "materialize_pep_template",
    "materialize_pep_template_pair",
    "render_pep_template_from_source",
    "render_template",
    "render_template_from_source",
    "validate_input",
    "validate_pep_template_materialization_receipt",
    "validate_archived_broker_signing_receipt",
    "validate_broker_signing_receipt",
    "validate_broker_seed_receipt",
    "validate_effective_policy_projection",
    "write_private_receipt",
    "validate_pep_runtime_binding",
    "write_private_template",
]
