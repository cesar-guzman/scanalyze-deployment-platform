"""Deterministic, repository-only GUG-377 upstream materializer.

The module compiles the source contracts needed by the future GUG-376 live
orchestrator without constructing an AWS client, loading credentials, opening
a private evidence root, or performing a provider call.  Its only executable
adapter is the in-memory ``ScriptedProviderAdapter`` used by tests.  Every live
adapter construction remains stopped by
``STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from tooling.platform_authority_gug365_upstream_dry_run_runner import (
    AttemptLedger,
    RunnerResult,
    reconcile_uncertain as _reconcile_uncertain,
    run_repository_plan,
)
from tooling.platform_authority_gug365_upstream_prerequisites import (
    PHASE_SPECS,
    REQUEST_KEYS,
    canonical_digest,
)
from tooling.platform_authority_gug365_upstream_provider_contracts import (
    STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
    InertProviderAdapter,
    OPERATION_DEFINITIONS,
    ProviderAdapter,
    ProviderContractError,
    ProviderStatus,
    ScriptedProviderAdapter,
    bind_consumed_slot_projections,
    consumed_slot_binding_digest,
    operation_from_record,
    provider_result_projection_digest,
    provider_slot_projections,
)


RECORD_TYPE = "scanalyze.platform_authority.gug365_upstream_plan.v2"
SCHEMA_VERSION = 2
SOURCE_HEAD_SHA = "27cfe380557c18f4b5318f3369bf27f3caa3b08f"
SOURCE_TREE_SHA = "e4d6ffdef4057e2d16cdc02a4a125a530b34b081"
PR78_HEAD_SHA = "4d2ec5c7d8a65e7c7f2ec17f09dfa372a2a9a3ae"
PR78_MERGE_SHA = "0f708c22ec20a2671c6cabd72493d2eff9cb4059"
REGION = "us-east-1"
ROOT = Path(__file__).resolve().parents[1]
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class MaterializationError(ValueError):
    """Stable repository-materializer failure without caller-controlled data."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "MATERIALIZATION_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise MaterializationError(code)


@dataclass(frozen=True, slots=True)
class MaterializationResult:
    """Public, digest-only products from one scripted repository run."""

    status: str
    plan: dict[str, Any]
    inventory: dict[str, Any]
    operation_results: tuple[dict[str, Any], ...]
    provider_slot_projections: dict[str, str]
    ledger: dict[str, Any]
    completion_package: dict[str, Any]
    rollback_package: dict[str, Any]
    handoff: dict[str, Any]

    def public_records(self) -> dict[str, Any]:
        return {
            "plan": self.plan,
            "inventory": self.inventory,
            "operation_results": list(self.operation_results),
            "provider_slot_projections": self.provider_slot_projections,
            "ledger": self.ledger,
            "completion_package": self.completion_package,
            "rollback_package": self.rollback_package,
            "handoff": self.handoff,
        }


# Each kind is unique even when two operations use the same provider API.  The
# tuple itself is the reviewed global ordering contract; callers cannot supply
# or reorder it at runtime.
_OPERATIONS: tuple[tuple[str, str, str, str, str], ...] = (
    ("CREATE_APPLICATION", "IDENTITY_CENTER_FOUNDATION", "sso:CreateApplication", "identity_center_application", "NONE"),
    ("PUT_APPLICATION_GRANT", "IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationGrant", "identity_center_application", "NONE"),
    ("PUT_APPLICATION_ACCESS_SCOPE", "IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationAccessScope", "identity_center_application", "NONE"),
    ("PUT_APPLICATION_ASSIGNMENT_CONFIG", "IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationAssignmentConfiguration", "identity_center_application", "NONE"),
    ("CREATE_APPLICATION_ASSIGNMENT", "IDENTITY_CENTER_FOUNDATION", "sso:CreateApplicationAssignment", "identity_center_application", "NONE"),
    ("CLASSIFIER_CREATE_PERMISSION_SET", "IDENTITY_CENTER_FOUNDATION", "sso:CreatePermissionSet", "classifier_permission_set", "NONE"),
    ("APPROVER_CREATE_PERMISSION_SET", "IDENTITY_CENTER_FOUNDATION", "sso:CreatePermissionSet", "approver_permission_set", "NONE"),
    ("CLASSIFIER_PUT_INLINE_POLICY", "IDENTITY_CENTER_FOUNDATION", "sso:PutInlinePolicyToPermissionSet", "classifier_permission_set", "NONE"),
    ("APPROVER_PUT_INLINE_POLICY", "IDENTITY_CENTER_FOUNDATION", "sso:PutInlinePolicyToPermissionSet", "approver_permission_set", "NONE"),
    ("CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT", "IDENTITY_CENTER_FOUNDATION", "sso:CreateAccountAssignment", "classifier_permission_set_role", "ASYNC_IDENTITY"),
    ("APPROVER_CREATE_ACCOUNT_ASSIGNMENT", "IDENTITY_CENTER_FOUNDATION", "sso:CreateAccountAssignment", "approver_permission_set_role", "ASYNC_IDENTITY"),
    ("CLASSIFIER_PROVISION_PERMISSION_SET", "IDENTITY_CENTER_FOUNDATION", "sso:ProvisionPermissionSet", "classifier_permission_set_role", "ASYNC_IDENTITY"),
    ("APPROVER_PROVISION_PERMISSION_SET", "IDENTITY_CENTER_FOUNDATION", "sso:ProvisionPermissionSet", "approver_permission_set_role", "ASYNC_IDENTITY"),
    ("PUT_APPLICATION_AUTH_METHOD", "IDENTITY_CENTER_FOUNDATION", "sso:PutApplicationAuthenticationMethod", "identity_center_application", "NONE"),
    ("CREATE_KMS_KEY", "KMS_FOUNDATION", "kms:CreateKey", "kms_key", "NONE"),
    ("ENABLE_KMS_KEY_ROTATION", "KMS_FOUNDATION", "kms:EnableKeyRotation", "kms_key", "NONE"),
    ("CREATE_KMS_ALIAS", "KMS_FOUNDATION", "kms:CreateAlias", "kms_key", "NONE"),
    ("CREATE_ARTIFACT_BUCKET", "S3_ARTIFACT_FOUNDATION", "s3:CreateBucket", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_OWNERSHIP_CONTROLS", "S3_ARTIFACT_FOUNDATION", "s3:PutBucketOwnershipControls", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_PUBLIC_ACCESS_BLOCK", "S3_ARTIFACT_FOUNDATION", "s3:PutPublicAccessBlock", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_VERSIONING", "S3_ARTIFACT_FOUNDATION", "s3:PutBucketVersioning", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_ENCRYPTION", "S3_ARTIFACT_FOUNDATION", "s3:PutBucketEncryption", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_POLICY", "S3_ARTIFACT_FOUNDATION", "s3:PutBucketPolicy", "artifact_bucket", "NONE"),
    ("PUT_BUCKET_TAGGING", "S3_ARTIFACT_FOUNDATION", "s3:PutBucketTagging", "artifact_bucket", "NONE"),
    ("PUT_SIGNING_PROFILE", "SIGNER_PROFILE_FOUNDATION", "signer:PutSigningProfile", "signing_profile", "NONE"),
    ("CREATE_CODE_SIGNING_CONFIG", "LAMBDA_CSC_FOUNDATION", "lambda:CreateCodeSigningConfig", "code_signing_config", "NONE"),
    ("BROKER_PUT_UNSIGNED_OBJECT", "BROKER_UNSIGNED_PUBLISH", "s3:PutObject", "broker_unsigned_object", "NONE"),
    ("BROKER_START_SIGNING_JOB", "BROKER_SIGNING_JOB", "signer:StartSigningJob", "broker_signing_job", "ASYNC_SIGNER"),
    ("LEDGER_FACTORY_PUT_UNSIGNED_OBJECT", "LEDGER_FACTORY_UNSIGNED_PUBLISH", "s3:PutObject", "ledger_factory_unsigned_object", "NONE"),
    ("LEDGER_FACTORY_START_SIGNING_JOB", "LEDGER_FACTORY_SIGNING_JOB", "signer:StartSigningJob", "ledger_factory_signing_job", "ASYNC_SIGNER"),
)

if tuple((item.kind.value, item.action) for item in OPERATION_DEFINITIONS) != tuple(
    (kind, action) for kind, _phase, action, _resource, _polling in _OPERATIONS
):  # pragma: no cover - import-time closed-catalog invariant
    raise RuntimeError("MATERIALIZER_OPERATION_CATALOG_INVALID")


_PHASE_SPECS_V2 = tuple(tuple(item) for item in PHASE_SPECS)
_REQUEST_KEYS_V2 = MappingProxyType(
    {action: tuple(sorted(fields)) for action, fields in sorted(REQUEST_KEYS.items())}
)
_UPSTREAM_CATALOG_DIGEST = canonical_digest(
    {
        "phase_specs": [list(item) for item in _PHASE_SPECS_V2],
        "request_keys": {
            action: list(fields) for action, fields in _REQUEST_KEYS_V2.items()
        },
    }
)
if _UPSTREAM_CATALOG_DIGEST != (
    "sha256:d8580f361efff5bf4c3d2b112fdc98661b6b403206190efde5d208abfa47144f"
):  # pragma: no cover - exact PR #78 catalog pin
    raise RuntimeError("MATERIALIZER_UPSTREAM_CATALOG_DRIFT")


_SOURCE_CONTRACT_PATHS: tuple[tuple[str, int, str], ...] = (
    ("platform_authority_change_set_retirement_package_manifest", 1, "schemas/platform-authority-change-set-retirement-package-manifest.v1.schema.json"),
    ("platform_authority_retirement_entrypoint_intent", 1, "schemas/platform-authority-retirement-entrypoint-intent.v1.schema.json"),
    ("platform_authority_retirement_entrypoint_plan", 1, "schemas/platform-authority-retirement-entrypoint-plan.v1.schema.json"),
    ("platform_authority_retirement_ledger_factory_package", 1, "schemas/platform-authority-retirement-ledger-factory-package.v1.schema.json"),
    ("platform_authority_retirement_entrypoint_service_role_plan", 1, "schemas/platform-authority-retirement-entrypoint-service-role-plan.v1.schema.json"),
)

_IMPLEMENTATION_SOURCE_PATHS = (
    "tooling/platform_authority_gug365_upstream_prerequisites.py",
    "tooling/platform_authority_gug365_phase_execution_ledger.py",
    "tooling/platform_authority_gug365_upstream_provider_contracts.py",
    "tooling/platform_authority_gug365_upstream_dry_run_runner.py",
    "tooling/platform_authority_gug365_upstream_materializer.py",
    "scripts/deployment/platform-authority-gug365-upstream-materializer.py",
    "schemas/platform-authority-gug365-upstream-inventory.v2.schema.json",
    "schemas/platform-authority-gug365-upstream-plan.v2.schema.json",
    "schemas/platform-authority-gug365-upstream-final-handoff.v2.schema.json",
)

_PINNED_DEPENDENCY_DIGESTS = {
    "tooling/platform_authority_gug365_upstream_prerequisites.py": (
        "sha256:83a0bad74847c636aa37c0526983e607d54809f9597b2833b182efff594d39b5"
    ),
    "tooling/platform_authority_gug365_phase_execution_ledger.py": (
        "sha256:1de11322acc73e9714bbed83a75cf5b1989b06f31116ade9cc630deca43a9364"
    ),
}

_RESOURCE_NAMES = (
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

_PRODUCED_SLOTS: dict[str, tuple[str, ...]] = {
    "CREATE_APPLICATION": ("IDENTITY_CENTER_APPLICATION_ARN",),
    "CLASSIFIER_CREATE_PERMISSION_SET": ("CLASSIFIER_PERMISSION_SET_ARN",),
    "APPROVER_CREATE_PERMISSION_SET": ("APPROVER_PERMISSION_SET_ARN",),
    "CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT": (
        "CLASSIFIER_ACCOUNT_ASSIGNMENT_REQUEST_ID",
    ),
    "APPROVER_CREATE_ACCOUNT_ASSIGNMENT": (
        "APPROVER_ACCOUNT_ASSIGNMENT_REQUEST_ID",
    ),
    "CLASSIFIER_PROVISION_PERMISSION_SET": (
        "CLASSIFIER_PERMISSION_SET_PROVISION_REQUEST_ID",
        "CLASSIFIER_PERMISSION_SET_ROLE_ARN",
    ),
    "APPROVER_PROVISION_PERMISSION_SET": (
        "APPROVER_PERMISSION_SET_PROVISION_REQUEST_ID",
        "APPROVER_PERMISSION_SET_ROLE_ARN",
    ),
    "CREATE_KMS_KEY": ("KMS_KEY_ID", "KMS_KEY_ARN"),
    "PUT_SIGNING_PROFILE": (
        "SIGNING_PROFILE_VERSION_ID",
        "SIGNING_PROFILE_VERSION_ARN",
    ),
    "CREATE_CODE_SIGNING_CONFIG": ("CODE_SIGNING_CONFIG_ARN",),
    "BROKER_PUT_UNSIGNED_OBJECT": ("BROKER_UNSIGNED_VERSION_ID",),
    "BROKER_START_SIGNING_JOB": (
        "BROKER_SIGNING_JOB_ID",
        "BROKER_SIGNED_KEY",
        "BROKER_SIGNED_VERSION_ID",
    ),
    "LEDGER_FACTORY_PUT_UNSIGNED_OBJECT": (
        "LEDGER_FACTORY_UNSIGNED_VERSION_ID",
    ),
    "LEDGER_FACTORY_START_SIGNING_JOB": (
        "LEDGER_FACTORY_SIGNING_JOB_ID",
        "LEDGER_FACTORY_SIGNED_KEY",
        "LEDGER_FACTORY_SIGNED_VERSION_ID",
    ),
}

_CONSUMED_SLOTS: dict[str, tuple[str, ...]] = {
    "PUT_APPLICATION_GRANT": ("IDENTITY_CENTER_APPLICATION_ARN",),
    "PUT_APPLICATION_ACCESS_SCOPE": ("IDENTITY_CENTER_APPLICATION_ARN",),
    "PUT_APPLICATION_ASSIGNMENT_CONFIG": ("IDENTITY_CENTER_APPLICATION_ARN",),
    "CREATE_APPLICATION_ASSIGNMENT": ("IDENTITY_CENTER_APPLICATION_ARN",),
    "CLASSIFIER_PUT_INLINE_POLICY": ("CLASSIFIER_PERMISSION_SET_ARN",),
    "APPROVER_PUT_INLINE_POLICY": ("APPROVER_PERMISSION_SET_ARN",),
    "CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT": ("CLASSIFIER_PERMISSION_SET_ARN",),
    "APPROVER_CREATE_ACCOUNT_ASSIGNMENT": ("APPROVER_PERMISSION_SET_ARN",),
    "CLASSIFIER_PROVISION_PERMISSION_SET": ("CLASSIFIER_PERMISSION_SET_ARN",),
    "APPROVER_PROVISION_PERMISSION_SET": ("APPROVER_PERMISSION_SET_ARN",),
    "PUT_APPLICATION_AUTH_METHOD": (
        "IDENTITY_CENTER_APPLICATION_ARN",
        "CLASSIFIER_PERMISSION_SET_ROLE_ARN",
        "APPROVER_PERMISSION_SET_ROLE_ARN",
    ),
    "ENABLE_KMS_KEY_ROTATION": ("KMS_KEY_ID",),
    "CREATE_KMS_ALIAS": ("KMS_KEY_ID",),
    "PUT_BUCKET_ENCRYPTION": ("KMS_KEY_ARN",),
    "PUT_BUCKET_POLICY": ("KMS_KEY_ARN",),
    "CREATE_CODE_SIGNING_CONFIG": ("SIGNING_PROFILE_VERSION_ARN",),
    "BROKER_PUT_UNSIGNED_OBJECT": ("KMS_KEY_ARN",),
    "BROKER_START_SIGNING_JOB": (
        "BROKER_UNSIGNED_VERSION_ID",
        "SIGNING_PROFILE_VERSION_ARN",
    ),
    "LEDGER_FACTORY_PUT_UNSIGNED_OBJECT": ("KMS_KEY_ARN",),
    "LEDGER_FACTORY_START_SIGNING_JOB": (
        "LEDGER_FACTORY_UNSIGNED_VERSION_ID",
        "SIGNING_PROFILE_VERSION_ARN",
    ),
}


def _file_digest(relative_path: str) -> str:
    path = ROOT / relative_path
    try:
        return "sha256:" + sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MaterializationError("SOURCE_CONTRACT_UNAVAILABLE") from exc


def _source_manifest() -> dict[str, Any]:
    contracts = [
        {
            "artifact_type": artifact_type,
            "schema_version": version,
            "repository_path": path,
            "content_digest": _file_digest(path),
        }
        for artifact_type, version, path in _SOURCE_CONTRACT_PATHS
    ]
    implementation_sources = [
        {"repository_path": path, "content_digest": _file_digest(path)}
        for path in _IMPLEMENTATION_SOURCE_PATHS
    ]
    for source in implementation_sources:
        pinned_digest = _PINNED_DEPENDENCY_DIGESTS.get(source["repository_path"])
        if pinned_digest is not None and source["content_digest"] != pinned_digest:
            _fail("PINNED_IMPLEMENTATION_SOURCE_DRIFT")
    result: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_source_manifest.v1",
        "source_head_sha": SOURCE_HEAD_SHA,
        "source_head_role": "BASELINE_MAIN",
        "source_tree_sha": SOURCE_TREE_SHA,
        "pr78_head_sha": PR78_HEAD_SHA,
        "pr78_merge_sha": PR78_MERGE_SHA,
        "upstream_catalog_digest": _UPSTREAM_CATALOG_DIGEST,
        "contracts": contracts,
        "implementation_sources": implementation_sources,
        "implementation_source_set_digest": canonical_digest(
            implementation_sources
        ),
    }
    result["source_manifest_digest"] = canonical_digest(result)
    return result


def _resource_target(resource: str) -> dict[str, Any]:
    constraints: dict[str, tuple[str, ...]] = {
        "identity_center_application": ("SINGLE_OPERATOR_NONPROD_EXCEPTION", "EXACT_APPLICATION_CONFIGURATION", "SAME_USER_DIGEST_BINDING"),
        "classifier_permission_set": ("DISTINCT_CLASSIFIER_PERMISSION_SET", "INLINE_POLICY_ONLY", "NO_ADDITIVE_GRANTS"),
        "approver_permission_set": ("DISTINCT_APPROVER_PERMISSION_SET", "INLINE_POLICY_ONLY", "NO_ADDITIVE_GRANTS"),
        "classifier_permission_set_role": ("PROVISIONED_ROLE_READBACK", "CLASSIFIER_BINDING"),
        "approver_permission_set_role": ("PROVISIONED_ROLE_READBACK", "APPROVER_BINDING"),
        "kms_key": ("SYMMETRIC_ENCRYPT_DECRYPT", "ROTATION_ENABLED", "EXACT_POLICY_USE_BINDING"),
        "artifact_bucket": ("AUTHORITY_OWNED", "VERSIONING_ENABLED", "KMS_ENCRYPTED", "PUBLIC_ACCESS_BLOCKED", "IMMUTABLE_VERSION_REFERENCES"),
        "signing_profile": ("AWSLAMBDA_SHA384_ECDSA", "IMMUTABLE_PROFILE_VERSION"),
        "code_signing_config": ("UNTRUSTED_ARTIFACT_ENFORCE", "ONE_EXACT_PUBLISHER"),
        "broker_unsigned_object": ("GUG215_MANIFEST_DIGEST_BOUND", "VERSION_ID_REQUIRED", "CHECKSUM_REQUIRED"),
        "broker_signing_job": ("DISTINCT_JOB", "SUCCEEDED_ONLY", "DESTINATION_VERSION_BOUND"),
        "broker_signed_object": (
            "IMMUTABLE_DESTINATION_VERSION",
            "CHECKSUM_BOUND_TO_SIGNING_RESULT",
            "DISTINCT_FROM_UNSIGNED_OBJECT",
        ),
        "ledger_factory_unsigned_object": ("LEDGER_FACTORY_MANIFEST_DIGEST_BOUND", "VERSION_ID_REQUIRED", "CHECKSUM_REQUIRED"),
        "ledger_factory_signing_job": ("DISTINCT_JOB", "SUCCEEDED_ONLY", "DESTINATION_VERSION_BOUND"),
        "ledger_factory_signed_object": (
            "IMMUTABLE_DESTINATION_VERSION",
            "CHECKSUM_BOUND_TO_SIGNING_RESULT",
            "DISTINCT_FROM_UNSIGNED_OBJECT",
        ),
    }
    value = {
        "resource_kind": resource,
        "constraints": list(constraints[resource]),
        "provider_value_storage": "DIGEST_PROJECTION_ONLY",
        "mutable_reference_permitted": False,
    }
    return {**value, "target_state_digest": canonical_digest(value)}


def _target_manifest() -> dict[str, Any]:
    resources = {name: _resource_target(name) for name in _RESOURCE_NAMES}
    runtime = {
        "runtime": "python3.12",
        "architecture": "x86_64",
        "qualifier_policy": "PUBLISHED_VERSION_ONLY",
        "runtime_management_mode": "Manual",
        "provider_provenance": "REQUIRED_LIVE_NOT_PRODUCED",
        "reference_storage": "DIGEST_ONLY",
        "required_provider_projections": [
            "PUBLISHED_QUALIFIER_DIGEST",
            "RUNTIME_CONFIGURATION_DIGEST",
            "RUNTIME_VERSION_REFERENCE_DIGEST",
        ],
    }
    identity_center = {
        "authorization_mode": "SINGLE_OPERATOR_NONPROD_EXCEPTION",
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "same_user_digest_binding_required": True,
        "distinct_permission_sets_required": True,
        "provisioned_role_readback_required": True,
    }
    package_inputs = [
        {
            "artifact_type": artifact_type,
            "schema_version": version,
            "content_digest": _file_digest(path),
        }
        for artifact_type, version, path in _SOURCE_CONTRACT_PATHS
    ]
    slot_producers = {
        slot: kind
        for kind, slots in _PRODUCED_SLOTS.items()
        for slot in slots
    }
    provider_slots = [
        {
            "slot": slot,
            "producer_operation_kind": producer,
            "derivation_kind": (
                "PROVISIONED_ROLE_READBACK"
                if slot.endswith("PERMISSION_SET_ROLE_ARN")
                else "WRITE_RESPONSE_AND_EXACT_READBACK"
            ),
            "consumer_operation_kinds": sorted(
                kind for kind, slots in _CONSUMED_SLOTS.items() if slot in slots
            ),
            "value_storage": "TRANSIENT_DIGEST_PROJECTION_ONLY",
            "live_value_status": "NOT_PRODUCED",
        }
        for slot, producer in sorted(slot_producers.items())
    ]
    result: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_target_manifest.v1",
        "region": REGION,
        "authority_environment": "authority-non-production",
        "account_binding": "EXTERNAL_DIGEST_REQUIRED_LIVE_NOT_PRODUCED",
        "resources": resources,
        "runtime": runtime,
        "identity_center": identity_center,
        "package_inputs": package_inputs,
        "provider_slots": provider_slots,
    }
    result["target_manifest_digest"] = canonical_digest(result)
    return result


def _polling_policy(kind: str) -> dict[str, Any]:
    if kind == "NONE":
        return {
            "kind": "NONE",
            "max_attempts": 0,
            "max_elapsed_seconds": 0,
            "backoff_seconds": [],
            "nonterminal_states": [],
            "success_states": ["SUCCEEDED"],
            "failure_states": ["FAILED"],
            "unknown_state": "UNCERTAIN_RECONCILE_ONLY",
        }
    return {
        "kind": kind,
        "max_attempts": 4,
        "max_elapsed_seconds": 3,
        "backoff_seconds": [1, 1, 1],
        "nonterminal_states": ["IN_PROGRESS"],
        "success_states": ["SUCCEEDED"],
        "failure_states": ["FAILED"],
        "unknown_state": "UNCERTAIN_RECONCILE_ONLY",
    }


def _compile_plan() -> dict[str, Any]:
    source = _source_manifest()
    target = _target_manifest()
    phase_index = {
        name: index
        for index, (name, _target, _pred) in enumerate(_PHASE_SPECS_V2, start=1)
    }
    operations: list[dict[str, Any]] = []
    previous_id: str | None = None
    phase_local_sequence: dict[str, int] = {name: 0 for name in phase_index}
    for global_sequence, (kind, phase, action, resource, polling_kind) in enumerate(_OPERATIONS, start=1):
        phase_local_sequence[phase] += 1
        operation_id = f"GUG377_OP_{global_sequence:02d}_{kind}"
        request_contract = {
            "operation_kind": kind,
            "request_type": action,
            "allowed_fields": list(_REQUEST_KEYS_V2[action]),
            "raw_payload_persisted": False,
        }
        before_state = {
            "resource_kind": resource,
            "classification": "SCRIPTED_BEFORE_STATE_REQUIRED",
            "target_state_digest": target["resources"][resource]["target_state_digest"],
        }
        result_contract = {
            "operation_kind": kind,
            "causal_fields": [
                "operation_id",
                "operation_kind",
                "request_digest",
                "before_state_digest",
                "target_state_digest",
            ],
            "public_projection": "DIGEST_ONLY",
            "provider_payload_permitted": False,
            "produced_slots": list(_PRODUCED_SLOTS.get(kind, ())),
            "consumed_slots": list(_CONSUMED_SLOTS.get(kind, ())),
        }
        rollback_boundary = {
            "operation_kind": kind,
            "automatic_rollback": False,
            "disposition": "PRESERVE_AND_ESCALATE",
            "future_owner_authorization_required": True,
        }
        operation: dict[str, Any] = {
            "operation_id": operation_id,
            "operation_kind": kind,
            "phase": phase,
            "phase_sequence": phase_local_sequence[phase],
            "global_sequence": global_sequence,
            "action": action,
            "inventory_resource": resource,
            "dependencies": [] if previous_id is None else [previous_id],
            "produced_slots": list(_PRODUCED_SLOTS.get(kind, ())),
            "consumed_slots": list(_CONSUMED_SLOTS.get(kind, ())),
            "result_projection_kind": (
                "ASYNC_RESULT_AND_EXACT_READBACK"
                if polling_kind != "NONE"
                else "IMMEDIATE_RESULT_AND_EXACT_READBACK"
            ),
            "request_contract_digest": canonical_digest(request_contract),
            "before_state_digest": canonical_digest(before_state),
            "target_state_digest": target["resources"][resource]["target_state_digest"],
            "result_contract_digest": canonical_digest(result_contract),
            "attempt_limit": 1,
            "sdk_retry_count": 0,
            "retry_permitted": False,
            "ambiguous_outcome": "UNCERTAIN_RECONCILE_ONLY",
            "polling_policy": _polling_policy(polling_kind),
            "rollback_boundary_digest": canonical_digest(rollback_boundary),
        }
        operation["operation_digest"] = canonical_digest(operation)
        operations.append(operation)
        previous_id = operation_id

    phases: list[dict[str, Any]] = []
    for sequence, (phase, inventory_target, predecessor) in enumerate(
        _PHASE_SPECS_V2, start=1
    ):
        ids = [item["operation_id"] for item in operations if item["phase"] == phase]
        phase_record: dict[str, Any] = {
            "phase": phase,
            "sequence": sequence,
            "inventory_target": inventory_target,
            "causal_predecessor": predecessor,
            "operation_ids": ids,
            "automatic_rollback": False,
        }
        phase_record["phase_digest"] = canonical_digest(phase_record)
        phases.append(phase_record)

    rollback_manifest: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_rollback_revocation.v1",
        "automatic_rollback": False,
        "deployment_authorized": False,
        "provider_mutations": [],
        "phase_dispositions": [
            {
                "phase": phase["phase"],
                "disposition": "PRESERVE_AND_ESCALATE",
                "future_owner_authorization_required": True,
            }
            for phase in reversed(phases)
        ],
    }
    rollback_manifest["rollback_manifest_digest"] = canonical_digest(rollback_manifest)
    plan: dict[str, Any] = {
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "implementation_issue": "GUG-377",
        "upstream_contract_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "repository-only",
        "production": False,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "evidence_scope": "REPOSITORY_SCRIPTED_SYNTHETIC_ONLY",
        "live_promotion_status": STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
        "source_manifest": source,
        "target_manifest": target,
        "phases": phases,
        "operations": operations,
        "rollback_manifest": rollback_manifest,
    }
    plan["plan_digest"] = canonical_digest(plan)
    return plan


def build_repository_plan() -> dict[str, Any]:
    """Compile the one exact, zero-effect GUG-377 repository plan."""

    plan = _compile_plan()
    validate_repository_plan(plan)
    return plan


def validate_repository_plan(plan: Mapping[str, Any]) -> None:
    """Reject unsupported versions, stale source and every plan substitution."""

    if (
        not isinstance(plan, Mapping)
        or plan.get("record_type") != RECORD_TYPE
        or plan.get("schema_version") != SCHEMA_VERSION
    ):
        _fail("UNSUPPORTED_CONTRACT_VERSION")
    try:
        snapshot = json.loads(
            json.dumps(plan, sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
    except (TypeError, ValueError) as exc:
        raise MaterializationError("PLAN_NOT_CANONICAL") from exc
    if snapshot != _compile_plan():
        _fail("PLAN_CONTRACT_MISMATCH")


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def validate_repository_inventory(record: Mapping[str, Any]) -> None:
    """Validate only the v2 scripted inventory; it can never prove live state."""

    required = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "upstream_contract_issue",
        "consumer_issue",
        "environment",
        "production",
        "deployment_authorized",
        "provider_mode",
        "evidence_scope",
        "source_manifest_digest",
        "target_manifest_digest",
        "resources",
        "runtime_provenance",
        "provider_certification_complete",
        "inventory_digest",
    }
    if not isinstance(record, Mapping) or set(record) != required:
        _fail("INVENTORY_V2_FIELDS_INVALID")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_inventory.v2"
        or record.get("schema_version") != 2
        or record.get("implementation_issue") != "GUG-377"
        or record.get("upstream_contract_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("environment") != "repository-only"
        or record.get("production") is not False
        or record.get("deployment_authorized") is not False
        or record.get("provider_mode") != "SCRIPTED_SYNTHETIC"
        or record.get("evidence_scope")
        != "REPOSITORY_SCRIPTED_SYNTHETIC_ONLY"
        or record.get("provider_certification_complete") is not False
    ):
        _fail("INVENTORY_V2_INVALID")
    _require_digest(record.get("source_manifest_digest"), "INVENTORY_SOURCE_DIGEST_INVALID")
    _require_digest(record.get("target_manifest_digest"), "INVENTORY_TARGET_DIGEST_INVALID")
    resources = record.get("resources")
    if (
        not isinstance(resources, list)
        or len(resources) != len(_RESOURCE_NAMES)
        or [item.get("resource_kind") for item in resources if isinstance(item, Mapping)]
        != sorted(_RESOURCE_NAMES)
    ):
        _fail("INVENTORY_RESOURCES_INVALID")
    allowed_classifications = {
        "SCRIPTED_SYNTHETIC",
        "SCRIPTED_SYNTHETIC_DERIVED_TARGET",
    }
    for resource in resources:
        if (
            not isinstance(resource, Mapping)
            or set(resource)
            != {
                "resource_kind",
                "classification",
                "before_state_projection_digest",
                "target_state_projection_digest",
                "provider_certified",
            }
            or resource.get("classification") not in allowed_classifications
            or resource.get("provider_certified") is not False
        ):
            _fail("INVENTORY_RESOURCE_INVALID")
        _require_digest(
            resource.get("before_state_projection_digest"),
            "INVENTORY_BEFORE_STATE_DIGEST_INVALID",
        )
        _require_digest(
            resource.get("target_state_projection_digest"),
            "INVENTORY_TARGET_STATE_DIGEST_INVALID",
        )
    if record.get("runtime_provenance") != {
        "runtime": "python3.12",
        "architecture": "x86_64",
        "qualifier_policy": "PUBLISHED_VERSION_ONLY",
        "runtime_management_mode": "Manual",
        "provider_backed": False,
        "provenance_status": "NOT_PROVEN_LIVE",
    }:
        _fail("INVENTORY_RUNTIME_PROVENANCE_INVALID")
    expected = canonical_digest(
        {key: value for key, value in record.items() if key != "inventory_digest"}
    )
    if record.get("inventory_digest") != expected:
        _fail("INVENTORY_DIGEST_MISMATCH")


def validate_repository_handoff(record: Mapping[str, Any]) -> None:
    """Validate the digest-only repository handoff without elevating authority."""

    required = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "upstream_contract_issue",
        "consumer_issue",
        "status",
        "state",
        "evidence_scope",
        "source_contracts_closed",
        "synthetic_materialization_complete",
        "provider_certification_complete",
        "live_provider_evidence",
        "consumer_fresh_checkpoint_required",
        "deployment_authorized",
        "production",
        "two_human_status",
        "independent_approval_present",
        "plan_digest",
        "inventory_digest",
        "completion_package_digest",
        "rollback_package_digest",
        "synthetic_signing_job_count",
        "live_signing_job_count",
        "aws_calls_performed",
        "aws_mutations",
        "provider_network_calls",
        "gug365_effects",
        "gug357_effects",
        "gug215_effects",
        "gug206_effects",
        "missing_live_prerequisites",
        "handoff_digest",
    }
    if not isinstance(record, Mapping) or set(record) != required:
        _fail("HANDOFF_V2_FIELDS_INVALID")
    complete = record.get("synthetic_materialization_complete")
    if (
        record.get("record_type")
        != "scanalyze.platform_authority.gug365_upstream_final_handoff.v2"
        or record.get("schema_version") != 2
        or record.get("implementation_issue") != "GUG-377"
        or record.get("upstream_contract_issue") != "GUG-376"
        or record.get("consumer_issue") != "GUG-365"
        or record.get("status") != STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED
        or record.get("state") != "SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY"
        or record.get("evidence_scope")
        != "REPOSITORY_VALIDATED_SYNTHETIC_ONLY"
        or record.get("source_contracts_closed") is not True
        or not isinstance(complete, bool)
        or record.get("provider_certification_complete") is not False
        or record.get("live_provider_evidence") is not False
        or record.get("consumer_fresh_checkpoint_required") is not True
        or record.get("deployment_authorized") is not False
        or record.get("production") is not False
        or record.get("two_human_status") != "NOT_PROVEN"
        or record.get("independent_approval_present") is not False
        or record.get("synthetic_signing_job_count") != (2 if complete else 0)
        or record.get("missing_live_prerequisites")
        != ["LIVE_PRIVATE_ORCHESTRATOR"]
        or any(
            record.get(field) != 0
            for field in (
                "live_signing_job_count",
                "aws_calls_performed",
                "aws_mutations",
                "provider_network_calls",
                "gug365_effects",
                "gug357_effects",
                "gug215_effects",
                "gug206_effects",
            )
        )
    ):
        _fail("HANDOFF_V2_INVALID")
    for field in (
        "plan_digest",
        "inventory_digest",
        "completion_package_digest",
        "rollback_package_digest",
    ):
        _require_digest(record.get(field), "HANDOFF_V2_DIGEST_INVALID")
    expected = canonical_digest(
        {key: value for key, value in record.items() if key != "handoff_digest"}
    )
    if record.get("handoff_digest") != expected:
        _fail("HANDOFF_V2_DIGEST_MISMATCH")


def validate_repository_contract(record: Mapping[str, Any]) -> None:
    """Closed version dispatcher; v1/v2 and unknown records never substitute."""

    key = (record.get("record_type"), record.get("schema_version")) if isinstance(record, Mapping) else (None, None)
    validators = {
        (RECORD_TYPE, SCHEMA_VERSION): validate_repository_plan,
        (
            "scanalyze.platform_authority.gug365_upstream_inventory.v2",
            2,
        ): validate_repository_inventory,
        (
            "scanalyze.platform_authority.gug365_upstream_final_handoff.v2",
            2,
        ): validate_repository_handoff,
    }
    validator = validators.get(key)
    if validator is None:
        _fail("UNSUPPORTED_CONTRACT_VERSION")
    validator(record)


def _inventory(plan: Mapping[str, Any], runner: RunnerResult) -> dict[str, Any]:
    resources = [
        {
            "resource_kind": name,
            "classification": (
                "SCRIPTED_SYNTHETIC"
                if name in runner.before_state_projections
                else "SCRIPTED_SYNTHETIC_DERIVED_TARGET"
            ),
            "before_state_projection_digest": (
                runner.before_state_projections[name]["projection_digest"]
                if name in runner.before_state_projections
                else canonical_digest(
                    {
                        "resource_kind": name,
                        "classification": "SCRIPTED_SYNTHETIC_DERIVED_TARGET",
                        "provider_evidence": "NOT_PRODUCED",
                    }
                )
            ),
            "target_state_projection_digest": value["target_state_digest"],
            "provider_certified": False,
        }
        for name, value in sorted(plan["target_manifest"]["resources"].items())
    ]
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_inventory.v2",
        "schema_version": 2,
        "implementation_issue": "GUG-377",
        "upstream_contract_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "repository-only",
        "production": False,
        "deployment_authorized": False,
        "provider_mode": "SCRIPTED_SYNTHETIC",
        "evidence_scope": "REPOSITORY_SCRIPTED_SYNTHETIC_ONLY",
        "source_manifest_digest": plan["source_manifest"]["source_manifest_digest"],
        "target_manifest_digest": plan["target_manifest"]["target_manifest_digest"],
        "resources": resources,
        "runtime_provenance": {
            "runtime": "python3.12",
            "architecture": "x86_64",
            "qualifier_policy": "PUBLISHED_VERSION_ONLY",
            "runtime_management_mode": "Manual",
            "provider_backed": False,
            "provenance_status": "NOT_PROVEN_LIVE",
        },
        "provider_certification_complete": False,
    }
    record["inventory_digest"] = canonical_digest(record)
    return record


def _rollback_package(plan: Mapping[str, Any], runner: RunnerResult) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_rollback_revocation.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-377",
        "plan_digest": plan["plan_digest"],
        "ledger_digest": runner.ledger["ledger_digest"],
        "automatic_rollback": False,
        "deployment_authorized": False,
        "production": False,
        "provider_mutations": [],
        "disposition": (
            "NO_ACTION_SYNTHETIC_COMPLETE"
            if runner.status == "COMPLETE"
            else "PRESERVE_AND_ESCALATE"
        ),
        "read_only_reconciliation_only": runner.status == "UNCERTAIN_RECONCILE_ONLY",
        "future_owner_authorization_required": True,
    }
    record["package_digest"] = canonical_digest(record)
    return record


def _completion_package(plan: Mapping[str, Any], runner: RunnerResult, rollback_digest: str) -> dict[str, Any]:
    complete = runner.status == "COMPLETE"
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_completion.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-377",
        "upstream_contract_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "plan_digest": plan["plan_digest"],
        "ledger_digest": runner.ledger["ledger_digest"],
        "ordered_operation_result_digests": [
            item["operation_result_digest"] for item in runner.operation_results
        ],
        "provider_slot_projection_set_digest": canonical_digest(
            [
                {"slot": slot, "projection_digest": projection_digest}
                for slot, projection_digest in sorted(
                    runner.provider_slot_projections.items()
                )
            ]
        ),
        "rollback_package_digest": rollback_digest,
        "synthetic_materialization_complete": complete,
        "provider_certification_complete": False,
        "live_provider_evidence": False,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "downstream_effects": {
            "gug365": 0,
            "gug357": 0,
            "gug215": 0,
            "gug206": 0,
        },
    }
    record["package_digest"] = canonical_digest(record)
    return record


def _handoff(plan: Mapping[str, Any], inventory: Mapping[str, Any], completion: Mapping[str, Any], rollback: Mapping[str, Any]) -> dict[str, Any]:
    complete = completion["synthetic_materialization_complete"] is True
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_final_handoff.v2",
        "schema_version": 2,
        "implementation_issue": "GUG-377",
        "upstream_contract_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "status": STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
        "state": "SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY",
        "evidence_scope": "REPOSITORY_VALIDATED_SYNTHETIC_ONLY",
        "source_contracts_closed": True,
        "synthetic_materialization_complete": complete,
        "provider_certification_complete": False,
        "live_provider_evidence": False,
        "consumer_fresh_checkpoint_required": True,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "plan_digest": plan["plan_digest"],
        "inventory_digest": inventory["inventory_digest"],
        "completion_package_digest": completion["package_digest"],
        "rollback_package_digest": rollback["package_digest"],
        "synthetic_signing_job_count": 2 if complete else 0,
        "live_signing_job_count": 0,
        "aws_calls_performed": 0,
        "aws_mutations": 0,
        "provider_network_calls": 0,
        "gug365_effects": 0,
        "gug357_effects": 0,
        "gug215_effects": 0,
        "gug206_effects": 0,
        "missing_live_prerequisites": ["LIVE_PRIVATE_ORCHESTRATOR"],
    }
    record["handoff_digest"] = canonical_digest(record)
    return record


def _expected_before_state_projections(
    plan: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    projections: dict[str, dict[str, str]] = {}
    for operation_record in plan["operations"]:
        operation = operation_from_record(operation_record)
        if operation.resource_kind in projections:
            continue
        projection_digest = canonical_digest(
            {
                "operation_id": operation.operation_id,
                "operation_kind": operation.operation_kind.value,
                "resource_kind": operation.resource_kind,
                "classification": "SCRIPTED_SYNTHETIC",
                "request_digest": operation.request_digest,
                "before_state_digest": operation.before_state_digest,
                "target_state_digest": operation.target_state_digest,
            }
        )
        projections[operation.resource_kind] = {
            "before_state_digest": operation.before_state_digest,
            "target_state_digest": operation.target_state_digest,
            "projection_digest": projection_digest,
        }
    return projections


def _expected_operation_receipt(
    operation: Any, status: ProviderStatus
) -> tuple[dict[str, Any], dict[str, str]]:
    result_projection_digest = provider_result_projection_digest(operation, status)
    readback_projection_digest = canonical_digest(
        {
            "operation_id": operation.operation_id,
            "target_state_digest": operation.target_state_digest,
        }
    )
    slot_projections = provider_slot_projections(
        operation, status, result_projection_digest
    )
    receipt: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_operation_receipt.v2",
        "schema_version": 2,
        "implementation_issue": "GUG-377",
        "operation_id": operation.operation_id,
        "operation_kind": operation.operation_kind.value,
        "request_digest": operation.request_digest,
        "before_state_digest": operation.before_state_digest,
        "target_state_digest": operation.target_state_digest,
        "provider_result_projection_digest": result_projection_digest,
        "readback_projection_digest": readback_projection_digest,
        "consumed_slot_binding_digest": consumed_slot_binding_digest(operation),
        "produced_slot_projection_digests": [
            {
                "slot": projection.slot,
                "value_projection_digest": projection.value_projection_digest,
                "projection_digest": projection.projection_digest,
            }
            for projection in slot_projections
        ],
        "status": status.value,
        "attempt_count": 1,
        "write_retry_permitted": False,
        "provider_evidence_origin": "SCRIPTED_SYNTHETIC",
        "provider_response_values_persisted": False,
    }
    receipt["operation_result_digest"] = canonical_digest(receipt)
    return receipt, {
        projection.slot: projection.projection_digest
        for projection in slot_projections
    }


def validate_materialization_result(result: MaterializationResult) -> None:
    """Validate one complete cross-record bundle and every causal digest link."""

    if not isinstance(result, MaterializationResult):
        _fail("MATERIALIZATION_BUNDLE_INVALID")
    validate_repository_plan(result.plan)
    validate_repository_inventory(result.inventory)
    validate_repository_handoff(result.handoff)

    try:
        ledger = AttemptLedger(result.ledger).snapshot()
    except ProviderContractError as exc:
        raise MaterializationError(exc.code) from exc
    if ledger != result.ledger or ledger["plan_digest"] != result.plan["plan_digest"]:
        _fail("MATERIALIZATION_LEDGER_BINDING_MISMATCH")

    plan_operations = result.plan["operations"]
    ledger_operations = ledger["operations"]
    if len(plan_operations) != len(ledger_operations):
        _fail("MATERIALIZATION_LEDGER_OPERATION_SET_MISMATCH")

    receipts = list(result.operation_results)
    receipt_offset = 0
    slot_projections: dict[str, str] = {}
    attempted_prefix_closed = False
    previous_status: str | None = None
    for plan_operation, ledger_operation in zip(
        plan_operations, ledger_operations, strict=True
    ):
        static_operation = operation_from_record(plan_operation)
        if (
            ledger_operation["operation_id"] != static_operation.operation_id
            or ledger_operation["operation_digest"]
            != plan_operation["operation_digest"]
            or ledger_operation["request_digest"] != static_operation.request_digest
            or ledger_operation["dependencies"]
            != list(static_operation.dependencies)
        ):
            _fail("MATERIALIZATION_LEDGER_OPERATION_BINDING_MISMATCH")
        if ledger_operation["attempt_count"] == 0:
            if (
                ledger_operation["consumed_slot_binding_digest"] is not None
                or ledger_operation["operation_result_digest"] is not None
                or ledger_operation["status"] != "READY"
            ):
                _fail("MATERIALIZATION_UNATTEMPTED_OPERATION_INVALID")
            attempted_prefix_closed = True
            previous_status = ledger_operation["status"]
            continue
        if attempted_prefix_closed or (
            previous_status is not None and previous_status != "SUCCEEDED"
        ):
            _fail("MATERIALIZATION_CAUSAL_PREFIX_INVALID")
        operation = bind_consumed_slot_projections(
            static_operation, slot_projections
        )
        if ledger_operation["attempt_count"] == 1 and ledger_operation[
            "consumed_slot_binding_digest"
        ] != consumed_slot_binding_digest(operation):
            _fail("MATERIALIZATION_SLOT_BINDING_MISMATCH")

        ledger_status = ledger_operation["status"]
        previous_status = ledger_status
        if ledger_status != "SUCCEEDED":
            attempted_prefix_closed = True
        expected_receipt_status = {
            "SUCCEEDED": ProviderStatus.SUCCEEDED,
            "FAILED_TERMINAL": ProviderStatus.FAILED,
        }.get(ledger_status)
        if expected_receipt_status is None:
            if ledger_operation["operation_result_digest"] is not None:
                _fail("MATERIALIZATION_UNEXPECTED_RESULT_DIGEST")
            continue
        if receipt_offset >= len(receipts):
            _fail("MATERIALIZATION_RECEIPT_MISSING")
        supplied_receipt = receipts[receipt_offset]
        expected_receipt, produced = _expected_operation_receipt(
            operation, expected_receipt_status
        )
        if supplied_receipt != expected_receipt:
            _fail("MATERIALIZATION_RECEIPT_BINDING_MISMATCH")
        if ledger_operation["operation_result_digest"] != expected_receipt[
            "operation_result_digest"
        ]:
            _fail("MATERIALIZATION_LEDGER_RESULT_BINDING_MISMATCH")
        receipt_offset += 1
        for slot, projection_digest in produced.items():
            if slot in slot_projections:
                _fail("MATERIALIZATION_SLOT_REPLAY_FORBIDDEN")
            slot_projections[slot] = projection_digest

    if receipt_offset != len(receipts):
        _fail("MATERIALIZATION_RECEIPT_ORDER_MISMATCH")
    if result.provider_slot_projections != slot_projections:
        _fail("MATERIALIZATION_SLOT_SET_MISMATCH")

    status_counts = {
        status: sum(
            1 for operation in ledger_operations if operation["status"] == status
        )
        for status in {
            "READY",
            "SUCCEEDED",
            "FAILED_TERMINAL",
            "UNCERTAIN_RECONCILE_ONLY",
        }
    }
    if result.status == "SYNTHETIC_MATERIALIZATION_COMPLETE":
        if status_counts["SUCCEEDED"] != len(plan_operations):
            _fail("MATERIALIZATION_COMPLETE_STATE_MISMATCH")
        runner_status = "COMPLETE"
    elif result.status == "FAILED_TERMINAL":
        if status_counts["FAILED_TERMINAL"] != 1:
            _fail("MATERIALIZATION_FAILED_STATE_MISMATCH")
        runner_status = "FAILED_TERMINAL"
    elif result.status == "UNCERTAIN_RECONCILE_ONLY":
        if status_counts["UNCERTAIN_RECONCILE_ONLY"] != 1:
            _fail("MATERIALIZATION_UNCERTAIN_STATE_MISMATCH")
        runner_status = "UNCERTAIN_RECONCILE_ONLY"
    else:
        _fail("MATERIALIZATION_STATUS_INVALID")

    runner = RunnerResult(
        status=runner_status,
        before_state_projections=_expected_before_state_projections(result.plan),
        provider_slot_projections=dict(slot_projections),
        operation_results=tuple(receipts),
        ledger=ledger,
    )
    expected_inventory = _inventory(result.plan, runner)
    expected_rollback = _rollback_package(result.plan, runner)
    expected_completion = _completion_package(
        result.plan, runner, expected_rollback["package_digest"]
    )
    expected_handoff = _handoff(
        result.plan,
        expected_inventory,
        expected_completion,
        expected_rollback,
    )
    if result.inventory != expected_inventory:
        _fail("MATERIALIZATION_INVENTORY_BINDING_MISMATCH")
    if result.rollback_package != expected_rollback:
        _fail("MATERIALIZATION_ROLLBACK_BINDING_MISMATCH")
    if result.completion_package != expected_completion:
        _fail("MATERIALIZATION_COMPLETION_BINDING_MISMATCH")
    if result.handoff != expected_handoff:
        _fail("MATERIALIZATION_HANDOFF_BINDING_MISMATCH")
    validate_public_evidence(result.public_records())


def materialize_repository_plan(
    *,
    plan: Mapping[str, Any],
    adapter: ProviderAdapter,
    ledger: AttemptLedger,
    now: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> MaterializationResult:
    """Run one deterministic in-memory script; arbitrary adapters are rejected."""

    validate_repository_plan(plan)
    if type(adapter) is InertProviderAdapter:
        raise MaterializationError(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)
    if type(adapter) is not ScriptedProviderAdapter:
        _fail("ADAPTER_NOT_ALLOWLISTED")
    try:
        runner = run_repository_plan(
            plan=plan,
            adapter=adapter,
            ledger=ledger,
            now=now,
            sleep=sleep,
        )
    except ProviderContractError as exc:
        raise MaterializationError(exc.code) from exc
    inventory = _inventory(plan, runner)
    rollback = _rollback_package(plan, runner)
    completion = _completion_package(plan, runner, rollback["package_digest"])
    handoff = _handoff(plan, inventory, completion, rollback)
    validate_repository_inventory(inventory)
    validate_repository_handoff(handoff)
    result = MaterializationResult(
        status=(
            "SYNTHETIC_MATERIALIZATION_COMPLETE"
            if runner.status == "COMPLETE"
            else runner.status
        ),
        plan=dict(plan),
        inventory=inventory,
        operation_results=tuple(runner.operation_results),
        provider_slot_projections=dict(runner.provider_slot_projections),
        ledger=runner.ledger,
        completion_package=completion,
        rollback_package=rollback,
        handoff=handoff,
    )
    validate_materialization_result(result)
    return result


def reconcile_uncertain_operation(
    *,
    plan: Mapping[str, Any],
    operation_id: str,
    adapter: ProviderAdapter,
    ledger: AttemptLedger,
) -> dict[str, Any]:
    """Run only the typed read-only reconciliation path for a consumed write."""

    validate_repository_plan(plan)
    if type(adapter) is not ScriptedProviderAdapter:
        _fail("ADAPTER_NOT_ALLOWLISTED")
    try:
        return _reconcile_uncertain(
            plan=plan,
            operation_id=operation_id,
            adapter=adapter,
            ledger=ledger,
        )
    except ProviderContractError as exc:
        raise MaterializationError(exc.code) from exc


def validate_public_evidence(value: Any) -> None:
    """Reject raw provider/private values from every repository-visible product."""

    forbidden_keys = {
        "account_id",
        "user_id",
        "provider_payload",
        "raw_response",
        "signed_url",
        "private_root",
        "credentials",
    }

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                normalized_key = key.casefold() if isinstance(key, str) else ""
                if (
                    not isinstance(key, str)
                    or normalized_key in forbidden_keys
                    or normalized_key.endswith("_account_id")
                    or normalized_key.endswith("_user_id")
                    or normalized_key.endswith("_signed_url")
                    or normalized_key.endswith("_private_root")
                ):
                    _fail("PUBLIC_EVIDENCE_FIELD_FORBIDDEN")
                walk(nested)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            for nested in item:
                walk(nested)
        elif isinstance(item, str):
            lowered = item.casefold()
            if (
                "arn:" in lowered
                or "x-amz-signature" in lowered
                or "/users/" in lowered
                or lowered.startswith("akia")
                or "://" in lowered
                or (item.isdigit() and len(item) == 12)
            ):
                _fail("PUBLIC_EVIDENCE_VALUE_FORBIDDEN")

    walk(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--summary", action="store_true", help="print the sanitized repository-only checkpoint")
    group.add_argument("--emit-plan", action="store_true", help="print the full public dry-run plan")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    plan = build_repository_plan()
    if args.emit_plan:
        output: Mapping[str, Any] = plan
    else:
        output = {
            "status": "REPOSITORY_SOURCE_CONTRACTS_CLOSED",
            "plan_digest": plan["plan_digest"],
            "operation_count": len(plan["operations"]),
            "phase_count": len(plan["phases"]),
            "live_promotion_status": STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
            "aws_calls_performed": 0,
            "aws_mutations": 0,
            "provider_network_calls": 0,
            "private_root_created": False,
            "deployment_authorized": False,
            "production": False,
        }
    validate_public_evidence(output)
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
