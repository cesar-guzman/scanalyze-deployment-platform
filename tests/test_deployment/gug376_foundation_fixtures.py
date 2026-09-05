"""Canonical foundation evidence builders shared by GUG-376 product-path tests."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from tooling import platform_authority_plan_permission_repair_artifact_bootstrap as foundation
from tooling import platform_authority_plan_permission_repair_signed_artifact as pep_signed
from tooling import platform_authority_plan_permission_repair_broker_seed as broker_seed
from tooling import platform_authority_plan_permission_repair_template_readback as template_readback


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-ABCDEFGHIJKLMNOP"
PRINCIPAL_ID = "12345678-1234-4123-8123-123456789012"
KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "00000000-0000-4000-8000-000000000001"
)
AUTHORITY_CALLER = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_0123456789ABCDEF/operator"
)


def _stamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(value)
    result[field] = foundation.digest_value(result)
    return result


def build_foundation_contract(
    *, source_commit: str, observed_at: datetime
) -> dict[str, Any]:
    """Build a fully reconstructable pre-revoke foundation publish binding."""

    observed = observed_at.astimezone(timezone.utc).replace(microsecond=0)
    before = observed - timedelta(minutes=15)
    after = observed + timedelta(minutes=45)
    bridge_body = (REPO_ROOT / foundation.BRIDGE_TEMPLATE_PATH).read_bytes()
    foundation_body = (REPO_ROOT / foundation.FOUNDATION_TEMPLATE_PATH).read_bytes()
    route_body = (REPO_ROOT / foundation.ROUTE_TEMPLATE_SOURCE_PATH).read_bytes()
    delegation_body = (
        REPO_ROOT / foundation.DELEGATION_TEMPLATE_SOURCE_PATH
    ).read_bytes()
    raw_input = _seal(
        {
            "schema_version": 1,
            "record_type": foundation.INPUT_TYPE,
            "source_commit": source_commit,
            "management_account_id": foundation.MANAGEMENT_ACCOUNT_ID,
            "authority_account_id": foundation.AUTHORITY_ACCOUNT_ID,
            "region": foundation.REGION,
            "identity_center_instance_arn": INSTANCE_ARN,
            "bootstrap_principal_id": PRINCIPAL_ID,
            "access_not_before": _stamp(before),
            "access_not_after": _stamp(after),
            "production_authorized": False,
        },
        "input_digest",
    )
    intent = foundation.materialize_bootstrap_intent(
        raw_input,
        bridge_template=bridge_body,
        foundation_template=foundation_body,
    )
    readback = _seal(
        {
            "schema_version": 1,
            "record_type": foundation.FOUNDATION_READBACK_TYPE,
            "source_commit": source_commit,
            "bootstrap_intent_digest": intent["intent_digest"],
            "verifier": {
                "account_id": foundation.AUTHORITY_ACCOUNT_ID,
                "caller_arn": AUTHORITY_CALLER,
                "profile": foundation.AUTHORITY_PROFILE,
                "region": foundation.REGION,
            },
            "artifact_bucket": intent["names"]["artifact_bucket"],
            "artifact_kms_key_arn": KMS_KEY_ARN,
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
            "read_at": _stamp(observed),
            "aws_calls": 13,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": foundation.PRODUCTION_STATUS,
        },
        "readback_digest",
    )
    reviewed = foundation.seal_reviewed_sources(
        bootstrap_intent=intent,
        bridge_template=bridge_body,
        foundation_template=foundation_body,
        route_template=route_body,
        delegation_template=delegation_body,
    )

    def object_receipt(*, filename: str, body: bytes, version: str) -> dict[str, Any]:
        object_intent = foundation.materialize_object_intent(
            bootstrap_intent=intent,
            foundation_readback=readback,
            key=(
                f"{foundation.ARTIFACT_PREFIX}templates/{source_commit}/{filename}"
            ),
            body=body,
            content_type="text/yaml",
            mutation_nonce=sha256(
                f"{source_commit}:{filename}".encode("utf-8")
            ).hexdigest(),
        )
        return _seal(
            {
                "schema_version": 1,
                "record_type": foundation.OBJECT_RECEIPT_TYPE,
                "source_commit": source_commit,
                "bootstrap_intent_digest": intent["intent_digest"],
                "foundation_readback_digest": readback["readback_digest"],
                "object_intent_digest": object_intent["intent_digest"],
                "dispatch_receipt_digest": "sha256:" + "d" * 64,
                "effect_digest": object_intent["effect_digest"],
                "mutation_nonce": object_intent["mutation_nonce"],
                "causal_claim_digest": object_intent["causal_claim_digest"],
                "verifier": {
                    "account_id": foundation.AUTHORITY_ACCOUNT_ID,
                    "caller_arn": AUTHORITY_CALLER,
                    "profile": foundation.AUTHORITY_PROFILE,
                    "region": foundation.REGION,
                },
                "bucket": intent["names"]["artifact_bucket"],
                "key": object_intent["request"]["Key"],
                "version": version,
                "object_sha256": object_intent["object_sha256"],
                "checksum_sha256": base64.b64encode(
                    bytes.fromhex(object_intent["object_sha256"][7:])
                ).decode("ascii"),
                "content_length": len(body),
                "content_type": "text/yaml",
                "sse_algorithm": "aws:kms",
                "sse_kms_key_arn": KMS_KEY_ARN,
                "bucket_key_enabled": True,
                "metadata": object_intent["request"]["Metadata"],
                "tags": {
                    "managed_by": "gug376-artifact-bootstrap",
                    "service": "scanalyze-platform-authority",
                    "work_package": "GUG-376",
                    "source_commit": source_commit,
                    "mutation_nonce": object_intent["mutation_nonce"],
                    "effect_digest": object_intent["effect_digest"],
                    "causal_claim_digest": object_intent[
                        "causal_claim_digest"
                    ],
                },
                "source_marker": "AWS_STS_S3_VERSIONED_SSE_KMS_OBJECT_READBACK",
                "read_at": _stamp(observed),
                "aws_calls": 6,
                "aws_mutations": 0,
                "production_authorized": False,
                "production_status": foundation.PRODUCTION_STATUS,
            },
            "receipt_digest",
        )

    route_receipt = object_receipt(
        filename=Path(foundation.ROUTE_TEMPLATE_SOURCE_PATH).name,
        body=route_body,
        version="route-template-version-1",
    )
    delegation_receipt = object_receipt(
        filename=Path(foundation.DELEGATION_TEMPLATE_SOURCE_PATH).name,
        body=delegation_body,
        version="delegation-template-version-1",
    )
    access_update = foundation.materialize_foundation_access_update(
        bootstrap_intent=intent,
        foundation_readback=readback,
        route_template_receipt=route_receipt,
        delegation_template_receipt=delegation_receipt,
        reviewed_sources=reviewed,
        foundation_template=foundation_body,
    )
    parameters = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in access_update["request"]["Parameters"]
    }
    access_readback = _seal(
        {
            "schema_version": 1,
            "record_type": foundation.FOUNDATION_ACCESS_READBACK_TYPE,
            "source_commit": source_commit,
            "bootstrap_intent_digest": intent["intent_digest"],
            "access_update_intent_digest": access_update["intent_digest"],
            "verifier": {
                "account_id": foundation.AUTHORITY_ACCOUNT_ID,
                "caller_arn": AUTHORITY_CALLER,
                "profile": foundation.AUTHORITY_PROFILE,
                "region": foundation.REGION,
            },
            "route_template_receipt_digest": route_receipt["receipt_digest"],
            "delegation_template_receipt_digest": delegation_receipt[
                "receipt_digest"
            ],
            "route_template_sha256": route_receipt["object_sha256"],
            "delegation_template_sha256": delegation_receipt["object_sha256"],
            "route_template_version_digest": foundation.digest_value(
                route_receipt["version"]
            ),
            "delegation_template_version_digest": foundation.digest_value(
                delegation_receipt["version"]
            ),
            "template_digest": intent["template_digests"]["foundation"],
            "parameters_digest": foundation.digest_value(parameters),
            "bucket_policy_digest": foundation.digest_value("bucket-policy"),
            "key_policy_digest": foundation.digest_value("key-policy"),
            "direct_kms_grant_proven": True,
            "exact_resource_count": 6,
            "source_marker": (
                "AWS_STS_CLOUDFORMATION_S3_KMS_EXACT_ACCESS_READBACK"
            ),
            "read_at": _stamp(observed),
            "aws_calls": 6,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": foundation.PRODUCTION_STATUS,
        },
        "readback_digest",
    )
    publish = foundation.materialize_foundation_publish_binding(
        bootstrap_intent=intent,
        foundation_readback=readback,
        reviewed_sources=reviewed,
        access_update=access_update,
        access_readback=access_readback,
        route_template_receipt=route_receipt,
        delegation_template_receipt=delegation_receipt,
    )
    return {
        "bootstrap_intent": intent,
        "foundation_readback": readback,
        "reviewed_sources": reviewed,
        "route_object_receipt": route_receipt,
        "delegation_object_receipt": delegation_receipt,
        "access_update": access_update,
        "access_readback": access_readback,
        "foundation_publish_binding": publish,
    }


def build_pep_signed_receipt(
    *,
    source_commit: str,
    observed_at: datetime,
    bootstrap_intent: dict[str, Any],
    foundation_publish_binding: dict[str, Any],
) -> dict[str, Any]:
    """Adapt the exhaustive signed-artifact fixture to foundation causality."""

    from tests.test_deployment.test_gug376_plan_permission_repair_signed_artifact import (
        _receipt,
    )

    observed = observed_at.astimezone(timezone.utc).replace(microsecond=0)
    receipt = deepcopy(_receipt())
    profile = foundation_publish_binding["signing_profile_version_arn"]
    bucket = foundation_publish_binding["bucket"]
    kms = foundation_publish_binding["sse_kms_key_arn"]
    receipt["source_commit"] = source_commit
    receipt["source_review"]["source_commit"] = source_commit
    receipt["source_review"]["merged_at"] = _stamp(observed - timedelta(minutes=10))
    receipt["upstream_storage_binding"] = foundation_publish_binding
    receipt["verifier"] = {
        "profile": pep_signed.EXPECTED_VERIFIER_PROFILE,
        "account_id": foundation.AUTHORITY_ACCOUNT_ID,
        "caller_arn": (
            "arn:aws:sts::042360977644:assumed-role/"
            "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
            "0123456789ABCDEF/verifier"
        ),
    }
    receipt["signing_job"]["profile_version_arn"] = profile
    receipt["signing_job"]["signature_timestamp"] = _stamp(
        observed - timedelta(minutes=3)
    )
    receipt["signing_job"]["signature_expires_at"] = _stamp(
        observed + timedelta(days=365)
    )
    receipt["signing_job"]["source"]["bucket"] = bucket
    receipt["signing_job"]["source"]["sse_kms_key_arn"] = kms
    receipt["signed_artifact"]["bucket"] = bucket
    receipt["signed_artifact"]["sse_kms_key_arn"] = kms
    receipt["revocation_check"]["checked_at"] = _stamp(observed)
    receipt["revocation_check"]["profile_version_arn_digest"] = (
        pep_signed._digest_text(profile)  # noqa: SLF001
    )
    receipt["evaluated_at"] = _stamp(observed)
    parameters = {
        item["ParameterKey"]: item for item in receipt["cloudformation_parameters"]
    }
    parameters["SourceCommit"]["ParameterValue"] = source_commit
    parameters["ArtifactBucket"]["ParameterValue"] = bucket
    parameters["SigningProfileVersionArn"]["ParameterValue"] = profile
    receipt["receipt_digest"] = pep_signed._canonical_digest(  # noqa: SLF001
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )
    pep_signed.validate_signed_artifact_receipt(
        receipt,
        now=observed,
        bootstrap_intent=bootstrap_intent,
        foundation_publish_binding=foundation_publish_binding,
    )
    return receipt


def build_template_readback(
    *,
    artifact_kind: str,
    source_commit: str,
    observed_at: datetime,
    artifact_payload: bytes,
    foundation_publish_binding: dict[str, Any],
    materialization_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one exact ReadOnly template attestation on foundation storage."""

    paths = {
        "route_template": foundation.ROUTE_TEMPLATE_SOURCE_PATH,
        "delegation_template": foundation.DELEGATION_TEMPLATE_SOURCE_PATH,
        "pep_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "pep_protection_template": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "broker_template": (
            "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml"
        ),
        "broker_protection_template": (
            "bootstrap/cfn-platform-authority-gug376-route-broker-seed.template.yaml"
        ),
    }
    path = paths[artifact_kind]
    private_filenames = {
        "pep_template": broker_seed.PEP_OUTPUT_NAME,
        "pep_protection_template": broker_seed.PEP_PROTECTION_OUTPUT_NAME,
        "broker_template": "cfn-platform-authority-gug376-route-broker.yaml",
        "broker_protection_template": (
            "cfn-platform-authority-gug376-route-broker-protection.yaml"
        ),
    }
    scope = (
        "private"
        if artifact_kind in {"broker_template", "broker_protection_template"}
        else "templates"
    )
    filename = private_filenames.get(artifact_kind, Path(path).name)
    bucket = foundation_publish_binding["bucket"]
    version = {
        "route_template": "route-template-version-1",
        "delegation_template": "delegation-template-version-1",
        "pep_template": "pep-template-version-1",
        "pep_protection_template": "pep-protection-template-version-1",
        "broker_template": "broker-template-version-1",
        "broker_protection_template": "broker-protection-template-version-1",
    }[artifact_kind]
    key = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/"
        f"{scope}/{source_commit}/{filename}"
    )
    source_payload = (REPO_ROOT / path).read_bytes()
    if artifact_kind in {"pep_template", "pep_protection_template"}:
        protection_enabled = artifact_kind == "pep_protection_template"
        rendered = broker_seed.render_pep_template_from_source(
            source=source_payload,
            protection_enabled=protection_enabled,
        )
        if materialization_receipt is None:
            policy = "Retain" if protection_enabled else "Delete"
            materialization_receipt = {
                "record_type": broker_seed.PEP_TEMPLATE_RECEIPT_TYPE,
                "schema_version": 1,
                "source_commit": source_commit,
                "source_path": broker_seed.PEP_SOURCE_TEMPLATE_PATH.as_posix(),
                "source_sha256": foundation.bytes_digest(source_payload),
                "template_variant": (
                    "protection" if protection_enabled else "create"
                ),
                "output_name": filename,
                "template_sha256": foundation.bytes_digest(rendered),
                "template_bytes": len(rendered),
                "ledger_deletion_protection_enabled": protection_enabled,
                "lifecycle_deletion_policy": policy,
                "lifecycle_update_replace_policy": policy,
                "lifecycle_resource_ids": list(
                    broker_seed.PEP_LIFECYCLE_RESOURCE_IDS
                ),
                "variant_controls_parameterless": True,
                "private_mode": "0600",
                "aws_calls": 0,
                "aws_mutations": 0,
                "deployment_authorized": False,
                "production_status": broker_seed.PRODUCTION_STATUS,
            }
            materialization_receipt["receipt_digest"] = foundation.digest_value(
                materialization_receipt
            )
        artifact_payload = rendered
    receipt = {
        "schema_version": 1,
        "record_type": template_readback.RECORD_TYPE,
        "source_commit": source_commit,
        "source_path": path,
        "source_sha256": foundation.bytes_digest(source_payload),
        "bucket": bucket,
        "key": key,
        "version": version,
        "template_url": (
            f"https://{bucket}.s3.us-east-1.amazonaws.com/{key}"
            f"?versionId={version}"
        ),
        "artifact_sha256": foundation.bytes_digest(artifact_payload),
        "content_length": len(artifact_payload),
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": foundation_publish_binding["sse_kms_key_arn"],
        "upstream_storage_binding": foundation_publish_binding,
        "materialization_receipt": materialization_receipt,
        "verifier": {
            "account_id": foundation.AUTHORITY_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_"
                "0123456789ABCDEF/reader"
            ),
            "profile": foundation.AUTHORITY_PROFILE,
            "region": foundation.REGION,
        },
        "observed_at": _stamp(observed_at),
        "source_marker": template_readback.SOURCE_MARKER,
        "aws_calls": 4,
        "aws_mutations": 0,
    }
    receipt["receipt_digest"] = foundation.digest_value(receipt)
    return template_readback.validate_template_readback_receipt(
        receipt,
        artifact_kind=artifact_kind,
        source_commit=source_commit,
        now=observed_at,
        expected_storage_binding=foundation_publish_binding,
    )


def build_route_release(
    *,
    foundation_contract: dict[str, Any],
    publication_observed_at: datetime,
    template_readbacks: dict[str, Any],
    pep_signed_artifact_receipt: dict[str, Any],
    broker_seed_input: dict[str, Any],
    broker_seed_receipts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build the post-revoke, post-session-expiry normal-route release."""

    intent = foundation_contract["bootstrap_intent"]
    readback = foundation_contract["foundation_readback"]
    readbacks = deepcopy(template_readbacks)
    if "pep_protection_template" not in readbacks:
        readbacks["pep_protection_template"] = build_template_readback(
            artifact_kind="pep_protection_template",
            source_commit=intent["source_commit"],
            observed_at=publication_observed_at,
            artifact_payload=b"materialized-by-fixture",
            foundation_publish_binding=foundation_contract[
                "foundation_publish_binding"
            ],
        )
    bridge_body = (REPO_ROOT / foundation.BRIDGE_TEMPLATE_PATH).read_bytes()
    pin = foundation.materialize_bridge_pin(
        bootstrap_intent=intent,
        foundation_readback=readback,
        bridge_template=bridge_body,
    )
    published = publication_observed_at.astimezone(timezone.utc).replace(
        microsecond=0
    )
    pin_completed = published - timedelta(minutes=5)
    revoke_completed = published + timedelta(minutes=5)
    release_at = max(
        datetime.fromisoformat(intent["access_not_after"][:-1] + "+00:00"),
        revoke_completed + timedelta(hours=1),
    )

    def bridge_readback(*, operation: str) -> dict[str, Any]:
        is_pin = operation == "bridge-pin"
        completed = pin_completed if is_pin else revoke_completed
        value = {
            "schema_version": 1,
            "record_type": foundation.STACK_READBACK_TYPE,
            "source_commit": intent["source_commit"],
            "operation": operation,
            "intent_digest": pin["intent_digest"] if is_pin else intent["intent_digest"],
            "verifier": {
                "account_id": foundation.MANAGEMENT_ACCOUNT_ID,
                "caller_arn": (
                    "arn:aws:sts::839393571433:assumed-role/"
                    "AWSReservedSSO_AWSAdministratorAccess_0123456789ABCDEF/operator"
                ),
                "profile": foundation.MANAGEMENT_PROFILE,
                "region": foundation.REGION,
            },
            "stack_status": "UPDATE_COMPLETE",
            "stack_completed_at": _stamp(completed),
            "template_digest": intent["template_digests"]["bridge"],
            "resources": (
                [
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
                ]
                if is_pin
                else [
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
                ]
            ),
            "outputs_digest": foundation.digest_value(
                {"AssignmentMode": "true" if is_pin else "false"}
            ),
            "sso_assignment_count": 1 if is_pin else 0,
            "permission_set_provisioned": True,
            "permission_set_arn_digest": foundation.digest_value(
                "permission-set-arn"
            ),
            "permission_set_policy_digest": foundation.digest_value(
                "inline-policy-pin" if is_pin else "inline-policy-revoke"
            ),
            "permission_set_tags_digest": foundation.digest_value("tags"),
            "permission_set_metadata_exact": True,
            "managed_policy_count": 0,
            "customer_managed_policy_count": 0,
            "permissions_boundary_absent": True,
            "signing_profile_version_digest": foundation.digest_value(
                "ABCDEFGHIJ" if is_pin else "NOT_CONFIGURED"
            ),
            "temporary_principal_authorized": is_pin,
            "cleanup_assignment_count": 2,
            "cleanup_permission_set_count": 2,
            "cleanup_permission_sets_digest": foundation.digest_value(
                "cleanup-permission-sets"
            ),
            "management_recovery_role_present": True,
            "management_recovery_role_digest": foundation.digest_value(
                "management-recovery-role"
            ),
            "cleanup_authority_active": True,
            "credential_window_expired": not is_pin,
            "read_at": _stamp(published if is_pin else release_at),
            "aws_calls": 12,
            "aws_mutations": 0,
            "production_authorized": False,
            "production_status": foundation.PRODUCTION_STATUS,
        }
        return _seal(value, "readback_digest")

    pin_readback = bridge_readback(operation="bridge-pin")
    revoke_readback = bridge_readback(operation="bridge-revoke")
    return foundation.materialize_route_release(
        bootstrap_intent=intent,
        foundation_readback=readback,
        reviewed_sources=foundation_contract["reviewed_sources"],
        access_update=foundation_contract["access_update"],
        access_readback=foundation_contract["access_readback"],
        foundation_publish_binding=foundation_contract[
            "foundation_publish_binding"
        ],
        bridge_pin=pin,
        bridge_pin_readback=pin_readback,
        bridge_revoke_readback=revoke_readback,
        route_template_receipt=foundation_contract["route_object_receipt"],
        delegation_template_receipt=foundation_contract[
            "delegation_object_receipt"
        ],
        template_readbacks=readbacks,
        pep_signed_artifact_receipt=pep_signed_artifact_receipt,
        broker_seed_input=broker_seed_input,
        broker_seed_receipts=broker_seed_receipts,
        now=release_at,
    )
