"""Closed-world compiler tests for GUG-376 upstream prerequisites."""

from __future__ import annotations

import copy
from collections import Counter
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from tooling import platform_authority_gug365_upstream_prerequisites as public_upstream

from tooling.platform_authority_gug365_upstream_inventory import (
    SURFACES,
    UpstreamInventoryError,
    build_raw_provider_snapshot,
    certify_stable_inventory_provider_transcripts,
    collect_paginated,
)
from tooling.platform_authority_gug365_upstream_prerequisites import (
    ACTION_INVENTORY_RESOURCES,
    PHASE_NAMES,
    PHASE_INVENTORY_RESOURCES,
    PHASE_READBACK_ACTIONS,
    PHASE_SPECS,
    REQUIRED_ACTIONS,
    RESOURCE_NAMES,
    RESOURCE_SURFACE,
    UpstreamPrerequisiteError,
    _build_repository_operation_contract as build_operation_contract,
    _build_repository_phase_authorization as build_phase_authorization,
    _build_repository_phase_executor_authority_evidence as build_phase_executor_authority_evidence,
    build_final_handoff,
    _build_repository_execution_trust_anchor as build_execution_trust_anchor,
    build_inventory_target_contract,
    build_operation_contract as public_build_operation_contract,
    _build_repository_owner_decisions as build_owner_decisions,
    _build_repository_provider_slot_binding as build_provider_slot_binding,
    build_phase_authorization as public_build_phase_authorization,
    build_phase_executor_authority_evidence as public_build_phase_executor_authority_evidence,
    build_phase_contract,
    _build_repository_stable_inventory as build_stable_inventory,
    _build_repository_upstream_plan as build_upstream_plan,
    canonical_digest,
    canonical_json,
    expected_owner_decisions_approval_digest,
    _executor_policy_document,
    resolve_phase_requests,
    validate_final_handoff,
    _validate_repository_owner_authorization_response as validate_owner_authorization_response,
    _validate_repository_phase_authorization as validate_phase_authorization,
    _validate_repository_owner_decisions as validate_owner_decisions,
    _validate_repository_operation_receipt as validate_operation_receipt,
    validate_phase_authorization as validate_public_phase_authorization,
    _validate_repository_stable_inventory as validate_stable_inventory,
    _validate_repository_upstream_plan as validate_upstream_plan,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
D4 = "sha256:" + "4" * 64


def _schema(name: str) -> Draft202012Validator:
    path = ROOT / "schemas" / f"platform-authority-gug365-upstream-{name}.v1.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    "name,field,overclaim",
    [
        ("owner-decisions", "deployment_authorized", True),
        ("inventory", "aws_access_mode", "READ_WRITE"),
        ("plan", "production", True),
        ("phase-authorization", "deployment_authorized", True),
        ("final-handoff", "two_human_status", "PROVEN"),
    ],
)
def test_complete_schema_records_reject_single_field_overclaims(
    name: str, field: str, overclaim: object
) -> None:
    valid_path = ROOT / "fixtures/valid" / (
        f"platform-authority-gug365-upstream-{name}-v1-synthetic.json"
    )
    record = json.loads(valid_path.read_text(encoding="utf-8"))
    assert not list(_schema(name).iter_errors(record))
    record[field] = overclaim
    errors = list(_schema(name).iter_errors(record))
    assert errors
    assert any(list(error.path) == [field] for error in errors)


def test_public_mutation_contract_surfaces_stop_on_source_gap() -> None:
    for builder in (
        public_build_operation_contract,
        public_build_phase_executor_authority_evidence,
        public_build_phase_authorization,
    ):
        with pytest.raises(
            UpstreamPrerequisiteError,
            match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
        ):
            builder()

    public_scaffolding = {
        "build_execution_trust_anchor": (),
        "validate_execution_trust_anchor": ({},),
        "validate_provider_transcript_verification": ({},),
        "build_owner_decisions": (),
        "validate_owner_decisions": ({},),
        "build_stable_inventory": (),
        "validate_stable_inventory": ({},),
        "build_upstream_plan": (),
        "validate_upstream_plan": ({},),
        "build_provider_slot_binding": (),
        "validate_provider_slot_binding": ({},),
        "validate_operation_receipt": ({},),
    }
    for name, args in public_scaffolding.items():
        with pytest.raises(
            UpstreamPrerequisiteError,
            match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
        ):
            getattr(public_upstream, name)(*args)

    checkpoint_path = ROOT / "fixtures" / "valid" / (
        "platform-authority-gug365-upstream-"
        "phase-authorization-v1-synthetic.json"
    )
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    validate_public_phase_authorization(checkpoint)
    assert checkpoint["decision"] == "STOP"
    assert checkpoint["deployment_authorized"] is False
    assert checkpoint["aws_mutations"] == 0

    forged = copy.deepcopy(checkpoint)
    forged["decision"] = "AUTHORIZE"
    forged["deployment_authorized"] = True
    forged["checkpoint_digest"] = canonical_digest(
        {
            key: value
            for key, value in forged.items()
            if key != "checkpoint_digest"
        }
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="AUTHORIZATION_STOP_CHECKPOINT_INVALID",
    ):
        validate_public_phase_authorization(forged)


@pytest.mark.parametrize("phase", PHASE_NAMES)
def test_every_public_phase_authority_compiler_stops(phase: str) -> None:
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        public_build_phase_executor_authority_evidence(
            resolved_phase={"phase": phase}
        )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        public_build_phase_authorization(
            resolved_phase={"phase": phase}
        )


def _resource(classification: str = "ABSENT_READY") -> dict[str, object]:
    return {
        "classification": classification,
        "target_digest": D1,
        "provider_fact_digest": D2,
        "readback_complete": True,
        "pagination_complete": True,
        "access_denied": False,
        "ambiguous": False,
        "no_touch": True,
        "repair_permitted": False,
    }


def _owner_decisions(
    *,
    private_root_digest: str = D2,
    created_at: datetime = NOW,
    value: str = "scanalyze-gug376-example",
    constraints: list[str] | None = None,
    inventory_resource: str = "artifact_bucket",
) -> dict[str, object]:
    values = _owner_decision_values(artifact_bucket_name=value)
    return build_owner_decisions(
        upstream_run_digest=D1,
        private_root_digest=private_root_digest,
        decisions=[
            {
                "inventory_resource": inventory_resource,
                "key": "artifact_bucket_name",
                "value": values["artifact_bucket_name"],
                "constraints": constraints
                or ["globally unique", "non-production only"],
                "collision_proof_digest": D4,
                "impact": "Creates one resource after separate authorization.",
                "rollback_boundary": "Deletion requires a separate recovery lane.",
            },
            {
                "inventory_resource": "kms_key",
                "key": "authority_account_id",
                "value": values["authority_account_id"],
                "constraints": ["exact non-production authority account"],
                "collision_proof_digest": D4,
                "impact": "Binds regional resource and principal identities.",
                "rollback_boundary": "Account substitution requires a new owner record.",
            },
            {
                "inventory_resource": "kms_key",
                "key": "kms_alias_name",
                "value": values["kms_alias_name"],
                "constraints": ["exact non-production KMS alias"],
                "collision_proof_digest": D4,
                "impact": "Creates one exact alias after separate authorization.",
                "rollback_boundary": "Alias deletion requires a separate lane.",
            },
            {
                "inventory_resource": "kms_key",
                "key": "kms_admin_principal_arn",
                "value": values["kms_admin_principal_arn"],
                "constraints": ["exact authority-account root principal"],
                "collision_proof_digest": D4,
                "impact": "Binds the only accepted key-policy principal.",
                "rollback_boundary": "Principal changes require a new owner record.",
            },
            {
                "inventory_resource": "artifact_bucket",
                "key": "artifact_bucket_policy_principal_arn",
                "value": values["artifact_bucket_policy_principal_arn"],
                "constraints": ["exact authority-account root principal"],
                "collision_proof_digest": D4,
                "impact": "Binds the only accepted bucket-policy principal.",
                "rollback_boundary": "Principal changes require a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "identity_center_application_name",
                "value": values["identity_center_application_name"],
                "constraints": ["exact non-production application label"],
                "collision_proof_digest": D4,
                "impact": "Creates only the reviewed Identity Center application label.",
                "rollback_boundary": "Label substitution requires a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "identity_center_redirect_uri",
                "value": values["identity_center_redirect_uri"],
                "constraints": ["exact loopback authorization-code callback"],
                "collision_proof_digest": D4,
                "impact": "Binds the only accepted local OAuth redirect.",
                "rollback_boundary": "Redirect changes require a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "identity_center_application_provider_arn",
                "value": values["identity_center_application_provider_arn"],
                "constraints": ["exact reviewed application provider"],
                "collision_proof_digest": D4,
                "impact": "Binds application creation to one provider.",
                "rollback_boundary": "Provider changes require a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "identity_center_instance_arn",
                "value": values["identity_center_instance_arn"],
                "constraints": ["exact non-production Identity Center instance"],
                "collision_proof_digest": D4,
                "impact": "Binds all application and permission-set requests to one instance.",
                "rollback_boundary": "Instance substitution requires a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "identity_store_user_id",
                "value": values["identity_store_user_id"],
                "constraints": ["same immutable single-operator UserId"],
                "collision_proof_digest": D4,
                "impact": "Assigns one immutable user under the non-production exception.",
                "rollback_boundary": "User substitution requires a new owner record.",
            },
            {
                "inventory_resource": "identity_center_application",
                "key": "authority_target_id",
                "value": values["authority_target_id"],
                "constraints": ["exact authority account TargetId"],
                "collision_proof_digest": D4,
                "impact": "Binds both permission-set assignments to the authority account.",
                "rollback_boundary": "Account substitution requires a new owner record.",
            },
            {
                "inventory_resource": "classifier_permission_set",
                "key": "classifier_permission_set_name",
                "value": values["classifier_permission_set_name"],
                "constraints": ["exact classifier permission-set name"],
                "collision_proof_digest": D4,
                "impact": "Creates the classifier permission set only.",
                "rollback_boundary": "Name changes require a new owner record.",
            },
            {
                "inventory_resource": "approver_permission_set",
                "key": "approver_permission_set_name",
                "value": values["approver_permission_set_name"],
                "constraints": ["exact approver permission-set name"],
                "collision_proof_digest": D4,
                "impact": "Creates the approver permission set only.",
                "rollback_boundary": "Name changes require a new owner record.",
            },
            {
                "inventory_resource": "signing_profile",
                "key": "signing_profile_name",
                "value": values["signing_profile_name"],
                "constraints": ["exact non-production signing profile name"],
                "collision_proof_digest": D4,
                "impact": "Binds signing jobs to one reviewed profile name.",
                "rollback_boundary": "Profile changes require a new owner record.",
            },
        ],
        collision_proof_digest=D4,
        created_at=created_at,
    )


def _owner_decision_values(
    *, artifact_bucket_name: str = "scanalyze-gug376-example"
) -> dict[str, str]:
    return {
        "artifact_bucket_name": artifact_bucket_name,
        "authority_account_id": "123456789012",
        "kms_alias_name": "alias/scanalyze-gug376",
        "kms_admin_principal_arn": "arn:aws:iam::123456789012:root",
        "artifact_bucket_policy_principal_arn": (
            "arn:aws:iam::123456789012:root"
        ),
        "identity_center_application_name": "ScanalyzeAuthorityRetirement",
        "identity_center_redirect_uri": "http://127.0.0.1:18443/callback",
        "identity_center_application_provider_arn": (
            "arn:aws:sso::aws:applicationProvider/custom"
        ),
        "identity_center_instance_arn": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "identity_store_user_id": (
            "0123456789-12345678-1234-1234-1234-1234567890ab"
        ),
        "authority_target_id": "123456789012",
        "classifier_permission_set_name": "ScanalyzeAuthorityRetireClass",
        "approver_permission_set_name": "ScanalyzeAuthorityRetireApprove",
        "signing_profile_name": "scanalyze_gug376",
    }


def _target_contracts(
    owner_decisions: dict[str, object],
) -> dict[str, dict[str, object]]:
    return {
        name: build_inventory_target_contract(
            inventory_resource=name,
            source_contract_digest=canonical_digest(
                {"inventory_resource": name, "source": "current-main"}
            ),
            owner_decisions=owner_decisions,
        )
        for name in RESOURCE_NAMES
    }


def _runtime() -> dict[str, object]:
    arn = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
    record = {
        "runtime": "python3.12",
        "update_runtime_on": "Manual",
        "runtime_version_arn": arn,
        "runtime_version_arn_digest": canonical_digest(arn),
        "source_function_arn_digest": D1,
        "source_function_version": "7",
        "function_configuration_digest": D2,
        "runtime_management_config_digest": D3,
        "provider_backed": True,
        "readback_complete": True,
        "evidence_collected_at": "2026-08-13T20:00:00Z",
    }
    record["runtime_evidence_digest"] = canonical_digest(record)
    return record


def _inventory() -> dict[str, object]:
    owner_decisions = _owner_decisions()
    targets = _target_contracts(owner_decisions)
    target_digests = {
        name: target["target_digest"] for name, target in targets.items()
    }
    first = _raw_snapshot(NOW, D1, target_digests=target_digests)
    second = _raw_snapshot(
        NOW + timedelta(minutes=2), D2, target_digests=target_digests
    )
    return build_stable_inventory(
        upstream_run_digest=D1,
        owner_decisions=owner_decisions,
        account_binding_digest=D3,
        caller_identity_digest=D4,
        first_raw_provider_snapshot=first,
        second_raw_provider_snapshot=second,
        target_contracts=targets,
        created_at=NOW + timedelta(minutes=3),
    )


def _raw_snapshot(
    started_at: datetime,
    session_identifier_digest: str,
    *,
    fact_suffix: str = "",
    present_target: str | None = None,
    observed_contract_digest: str = D1,
    target_digests: dict[str, str] | None = None,
) -> dict[str, object]:
    actions = {
        "s3": "s3:ListAllMyBuckets",
        "kms": "kms:ListKeys",
        "signer": "signer:ListSigningProfiles",
        "lambda_code_signing": "lambda:ListCodeSigningConfigs",
        "lambda_runtime": "lambda:ListFunctions",
        "identity_center": "sso:ListInstances",
        "identity_store": "identitystore:DescribeUser",
        "iam_roles": "iam:ListRoles",
        "artifact_objects": "s3:ListBucketVersions",
    }
    calls = [{
        "action": "sts:GetCallerIdentity",
        "surface": None,
        "called_at": started_at + timedelta(seconds=1),
        "response_digest": D4,
        "pagination_complete": True,
    }]
    for offset, (surface, action) in enumerate(actions.items(), start=2):
        calls.append({
            "action": action,
            "surface": surface,
            "called_at": started_at + timedelta(seconds=offset),
            "response_digest": canonical_digest({"surface": surface}),
            "pagination_complete": True,
        })
    target_observations = {
        surface: [
            {
                "inventory_target": name,
                "surface": surface,
                "presence": "PRESENT" if name == present_target else "ABSENT",
                "target_digest": (
                    target_digests[name] if target_digests is not None else D1
                ),
                "observed_contract_digest": (
                    observed_contract_digest if name == present_target else None
                ),
                "causal_provenance_digest": D3 if name == present_target else None,
                "causal_upstream_run_digest": D1 if name == present_target else None,
                "collision_count": 1 if name == present_target else 0,
            }
            for name in RESOURCE_NAMES
            if RESOURCE_SURFACE[name] == surface
        ]
        for surface in SURFACES
    }
    pages = {
        surface: collect_paginated(
            lambda _token, current=surface: {
                "Items": [
                    *target_observations[current],
                    {
                        "surface_scan_marker": current,
                        "provider_fact_digest": canonical_digest(
                            current + fact_suffix
                        ),
                    },
                ]
            },
            items_key="Items",
        )
        for surface in SURFACES
    }
    runtime = _runtime()
    runtime["evidence_collected_at"] = (
        started_at + timedelta(seconds=11)
    ).isoformat().replace("+00:00", "Z")
    runtime["runtime_evidence_digest"] = canonical_digest(
        {key: value for key, value in runtime.items() if key != "runtime_evidence_digest"}
    )
    return build_raw_provider_snapshot(
        session_source="DIRECT_SSO",
        session_chain_depth=0,
        credential_source_digest=D1,
        account_binding_digest=D3,
        caller_identity_digest=D4,
        session_identifier_digest=session_identifier_digest,
        session_started_at=started_at,
        session_expires_at=started_at + timedelta(minutes=30),
        collected_at=started_at + timedelta(seconds=20),
        signed_calls=calls,
        provider_pages=pages,
        runtime_evidence=runtime,
    )


def _operation(phase: str, sequence: int, action: str, template: dict[str, object]) -> dict[str, object]:
    inventory_resource = ACTION_INVENTORY_RESOURCES.get(phase, {}).get(
        action, PHASE_INVENTORY_RESOURCES.get(phase, ("kms_key",))
    )[0]
    owner_decisions = _owner_decisions()
    target = _target_contracts(owner_decisions)[inventory_resource]
    return build_operation_contract(
        phase=phase,
        sequence=sequence,
        action=action,
        inventory_resource=inventory_resource,
        target_contract=target,
        owner_decisions=owner_decisions,
        owner_decision_values=_owner_decision_values(),
        request_template=template,
        expected_readback_digest=D2,
    )


def _kms_phase(*, unresolved: bool) -> tuple[dict[str, object], list[dict[str, object]]]:
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ExactKeyAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                "Resource": "*",
            }
        ],
    }
    templates = [
        {
            "BypassPolicyLockoutSafetyCheck": False,
            "Description": "GUG-376 non-production artifact key",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "MultiRegion": False,
            "Origin": "AWS_KMS",
            "Policy": key_policy,
            "Tags": [{"TagKey": "ScanalyzeIssue", "TagValue": "GUG-376"}],
        },
        {
            "KeyId": (
                {"$provider_slot": "KMS_KEY_ARN"}
                if unresolved
                else (
                    "arn:aws:kms:us-east-1:123456789012:key/"
                    "12345678-1234-1234-1234-1234567890ab"
                )
            ),
            "RotationPeriodInDays": 365,
        },
        {
            "AliasName": "alias/scanalyze-gug376",
            "TargetKeyId": (
                {"$provider_slot": "KMS_KEY_ARN"}
                if unresolved
                else (
                    "arn:aws:kms:us-east-1:123456789012:key/"
                    "12345678-1234-1234-1234-1234567890ab"
                )
            ),
        },
    ]
    actions = ["kms:CreateKey", "kms:EnableKeyRotation", "kms:CreateAlias"]
    operations = [
        _operation("KMS_FOUNDATION", index, action, template)
        for index, (action, template) in enumerate(zip(actions, templates, strict=True), start=1)
    ]
    return (
        build_phase_contract(
            phase="KMS_FOUNDATION",
            inventory_classification="ABSENT_READY",
            operations=operations,
            rollback_boundary="No automatic rollback; read-only reconciliation only.",
        ),
        templates,
    )


def _identity_operation_inputs() -> tuple[
    list[dict[str, object]], list[tuple[str, str]]
]:
    values = _owner_decision_values()
    application_slot = {"$provider_slot": "IDENTITY_CENTER_APPLICATION_ARN"}
    classifier_slot = {"$provider_slot": "CLASSIFIER_PERMISSION_SET_ARN"}
    approver_slot = {"$provider_slot": "APPROVER_PERMISSION_SET_ARN"}
    actor_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["sts:SetContext"],
            "Resource": ["arn:aws:iam::123456789012:role/ScanalyzeAuthorityActor"],
        }],
    }
    direct_effect_denies = [
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
    ]
    classifier_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CreateTokenForExactRetirementApplication",
                "Effect": "Allow",
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": application_slot,
            },
            {
                "Sid": "AssumeExactIdentityEnhancedClassifierInvoker",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:SetContext"],
                "Resource": (
                    "arn:aws:iam::123456789012:"
                    "role/ScanalyzeGug215ClassifierInvoker"
                ),
            },
            {
                "Sid": "DenyDirectRetirementEffects",
                "Effect": "Deny",
                "Action": direct_effect_denies,
                "Resource": "*",
            },
        ],
    }
    approver_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CreateTokenForExactRetirementApplication",
                "Effect": "Allow",
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": application_slot,
            },
            {
                "Sid": "AssumeExactIdentityEnhancedApproverInvoker",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:SetContext"],
                "Resource": (
                    "arn:aws:iam::123456789012:"
                    "role/ScanalyzeGug215ApproverInvoker"
                ),
            },
            {
                "Sid": "DenyDirectRetirementEffects",
                "Effect": "Deny",
                "Action": direct_effect_denies,
                "Resource": "*",
            },
        ],
    }
    tags = [
        {"Key": "managed_by", "Value": "identity-center"},
        {"Key": "service", "Value": "scanalyze-platform-authority"},
        {"Key": "work_package", "Value": "GUG-376"},
        {"Key": "environment", "Value": "non-production"},
        {"Key": "production", "Value": "false"},
    ]
    templates: list[dict[str, object]] = [
        {
            "ApplicationProviderArn": values[
                "identity_center_application_provider_arn"
            ],
            "ClientToken": "gug376-create-application-once-0001",
            "Description": "GUG-376 non-production authority application",
            "InstanceArn": values["identity_center_instance_arn"],
            "Name": values["identity_center_application_name"],
            "PortalOptions": {
                "SignInOptions": {
                    "Origin": "APPLICATION",
                    "ApplicationUrl": "http://127.0.0.1:18443",
                },
                "Visibility": "ENABLED",
            },
            "Status": "ENABLED",
            "Tags": tags,
        },
        {
            "ApplicationArn": application_slot,
            "AuthenticationMethod": {"Iam": {"ActorPolicy": actor_policy}},
            "AuthenticationMethodType": "IAM",
        },
        {
            "ApplicationArn": application_slot,
            "Grant": {
                "AuthorizationCode": {
                    "RedirectUris": [values["identity_center_redirect_uri"]]
                }
            },
            "GrantType": "authorization_code",
        },
        {
            "ApplicationArn": application_slot,
            "AuthorizedTargets": [values["identity_center_instance_arn"]],
            "Scope": "sts:identity_context",
        },
        {"ApplicationArn": application_slot, "AssignmentRequired": True},
        {
            "ApplicationArn": application_slot,
            "PrincipalId": values["identity_store_user_id"],
            "PrincipalType": "USER",
        },
        {
            "Description": "GUG-215 classifier single-operator permission set",
            "InstanceArn": values["identity_center_instance_arn"],
            "Name": values["classifier_permission_set_name"],
            "SessionDuration": "PT1H",
            "Tags": tags,
        },
        {
            "InlinePolicy": classifier_policy,
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": classifier_slot,
        },
        {
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": classifier_slot,
            "PrincipalId": values["identity_store_user_id"],
            "PrincipalType": "USER",
            "TargetId": values["authority_target_id"],
            "TargetType": "AWS_ACCOUNT",
        },
        {
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": classifier_slot,
            "TargetId": values["authority_target_id"],
            "TargetType": "AWS_ACCOUNT",
        },
        {
            "Description": "GUG-215 approver single-operator permission set",
            "InstanceArn": values["identity_center_instance_arn"],
            "Name": values["approver_permission_set_name"],
            "SessionDuration": "PT1H",
            "Tags": tags,
        },
        {
            "InlinePolicy": approver_policy,
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": approver_slot,
        },
        {
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": approver_slot,
            "PrincipalId": values["identity_store_user_id"],
            "PrincipalType": "USER",
            "TargetId": values["authority_target_id"],
            "TargetType": "AWS_ACCOUNT",
        },
        {
            "InstanceArn": values["identity_center_instance_arn"],
            "PermissionSetArn": approver_slot,
            "TargetId": values["authority_target_id"],
            "TargetType": "AWS_ACCOUNT",
        },
    ]
    action_resources = [
        ("sso:CreateApplication", "identity_center_application"),
        ("sso:PutApplicationAuthenticationMethod", "identity_center_application"),
        ("sso:PutApplicationGrant", "identity_center_application"),
        ("sso:PutApplicationAccessScope", "identity_center_application"),
        ("sso:PutApplicationAssignmentConfiguration", "identity_center_application"),
        ("sso:CreateApplicationAssignment", "identity_center_application"),
        ("sso:CreatePermissionSet", "classifier_permission_set"),
        ("sso:PutInlinePolicyToPermissionSet", "classifier_permission_set"),
        ("sso:CreateAccountAssignment", "classifier_permission_set_role"),
        ("sso:ProvisionPermissionSet", "classifier_permission_set_role"),
        ("sso:CreatePermissionSet", "approver_permission_set"),
        ("sso:PutInlinePolicyToPermissionSet", "approver_permission_set"),
        ("sso:CreateAccountAssignment", "approver_permission_set_role"),
        ("sso:ProvisionPermissionSet", "approver_permission_set_role"),
    ]
    return templates, action_resources


def _build_identity_operation(
    sequence: int,
    *,
    template: dict[str, object] | None = None,
    inventory_resource: str | None = None,
) -> dict[str, object]:
    templates, action_resources = _identity_operation_inputs()
    action, default_resource = action_resources[sequence - 1]
    owner_decisions = _owner_decisions()
    target_resource = inventory_resource or default_resource
    return build_operation_contract(
        phase="IDENTITY_CENTER_FOUNDATION",
        sequence=sequence,
        action=action,
        inventory_resource=target_resource,
        target_contract=_target_contracts(owner_decisions)[target_resource],
        owner_decisions=owner_decisions,
        owner_decision_values=_owner_decision_values(),
        request_template=template or templates[sequence - 1],
        expected_readback_digest=canonical_digest(
            {"identity_operation": sequence}
        ),
    )


def _identity_slot_binding(
    *,
    slot: str,
    value: str,
    producer_sequence: int,
    producer_action: str,
    consumers: list[int],
) -> dict[str, object]:
    paths = {
        "IDENTITY_CENTER_APPLICATION_ARN": "/ApplicationArn",
        "CLASSIFIER_PERMISSION_SET_ARN": "/PermissionSet/PermissionSetArn",
        "APPROVER_PERMISSION_SET_ARN": "/PermissionSet/PermissionSetArn",
    }
    projections = []
    for source in ("WRITE_RESPONSE", "READBACK"):
        projection = {
            "slot": slot,
            "source": source,
            "field_path": paths[slot],
            "value_digest": canonical_digest(value),
        }
        projection["projection_digest"] = canonical_digest(projection)
        projections.append(projection)
    transcript = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug365_upstream_provider_transcript_verification.v1"
        ),
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "stage": "OPERATION",
        "evidence_origin": "SYNTHETIC_TEST",
        "verifier_identity_digest": D1,
        "attestation_root_digest": D2,
        "session_identifier_digest": D3,
        "account_or_management_binding_digest": D4,
        "caller_identity_digest": D1,
        "region": "us-east-1",
        "phase": "IDENTITY_CENTER_FOUNDATION",
        "authorization_digest": D2,
        "operation_sequence": producer_sequence,
        "operation_action": producer_action,
        "request_digest": D3,
        "provider_result_digest": D4,
        "observed_readback_digest": D1,
        "raw_provider_digest": None,
        "sts_call_receipt_digest": D2,
        "sts_was_first_signed_call": True,
        "effective_authority_readback_digest": D3,
        "projections": projections,
        "verified_at": "2026-08-13T20:00:00Z",
        "external_attestation_receipt_digest": D4,
    }
    transcript["verification_digest"] = canonical_digest(transcript)
    return build_provider_slot_binding(
        slot=slot,
        value=value,
        producer_phase="IDENTITY_CENTER_FOUNDATION",
        producer_operation_sequence=producer_sequence,
        producer_authorization_digest=D2,
        producer_operation_receipt_digest=D3,
        producer_provider_result_digest=D4,
        producer_readback_digest=D1,
        producer_transcript_verification=transcript,
        consumer_phase="IDENTITY_CENTER_FOUNDATION",
        consumer_operation_sequences=consumers,
    )


def _authority(
    phase: dict[str, object], *, completed_count: int, not_before: datetime = NOW
) -> dict[str, object]:
    key_arn = (
        "arn:aws:kms:us-east-1:123456789012:key/"
        "12345678-1234-1234-1234-1234567890ab"
    )
    alias_arn = "arn:aws:kms:us-east-1:123456789012:alias/scanalyze-gug376"
    resources = {
        operation["sequence"]: (
            ["*"]
            if operation["action"] == "kms:CreateKey"
            else (
                [key_arn, alias_arn]
                if operation["action"] == "kms:CreateAlias"
                else [key_arn]
            )
        )
        for operation in phase["operations"][completed_count:]
        if operation["request_digest_kind"] == "EXACT_REQUEST"
    }
    bindings = [
        {
            "sequence": operation["sequence"],
            "action": operation["action"],
            "target_digest": operation["target_digest"],
            "request_digest": operation["request_digest"],
            "executor_policy_digest": operation["executor_policy_digest"],
            "resource_arns": sorted(set(resources[operation["sequence"]])),
        }
        for operation in phase["operations"][completed_count:]
        if operation["request_digest_kind"] == "EXACT_REQUEST"
    ]
    expires_at = not_before + timedelta(minutes=15)
    start = not_before.isoformat().replace("+00:00", "Z")
    end = expires_at.isoformat().replace("+00:00", "Z")
    policy_digest = canonical_digest(
        _executor_policy_document(
            phase=phase["phase"],
            bindings=bindings,
            not_before=start,
            expires_at=end,
        )
    )
    effective_authority_digest = canonical_digest(
        {
            "phase": phase["phase"],
            "session_identifier_digest": D4,
            "allowed_mutation_bindings": bindings,
            "allowed_readback_actions": list(PHASE_READBACK_ACTIONS[phase["phase"]]),
            "sts_get_caller_identity_only_before_other_signed_calls": True,
        }
    )
    return build_phase_executor_authority_evidence(
        resolved_phase=phase,
        completed_operation_count=completed_count,
        resource_arns_by_sequence=resources,
        account_or_management_binding_digest=D1,
        caller_identity_digest=D2,
        session_identifier_digest=D4,
        sts_call_receipt_digest=D3,
        permission_set_policy_readback_digest=policy_digest,
        permissions_boundary_readback_digest=policy_digest,
        additive_grants_readback_digest=canonical_digest([]),
        effective_authority_readback_digest=effective_authority_digest,
        session_verifier_identity_digest=D3,
        session_attestation_root_digest=D4,
        session_expires_at=expires_at + timedelta(minutes=1),
        not_before=not_before,
        expires_at=expires_at,
    )


def _trust_anchor(private_root_digest: str = D1) -> dict[str, object]:
    return build_execution_trust_anchor(
        owner_identity_binding_digest=D1,
        owner_authorization_verifier_identity_digest=D2,
        executor_session_verifier_identity_digest=D3,
        executor_session_attestation_root_digest=D4,
        ledger_store_identity_digest=D1,
        private_ledger_root_digest=private_root_digest,
    )


def _operation_receipt(
    *, phase: dict[str, object], sequence: int, authorization_digest: str = D3
) -> dict[str, object]:
    operation = phase["operations"][sequence - 1]
    def provider_verification(stage: str) -> dict[str, object]:
        projection_records: list[dict[str, object]] = []
        if stage == "OPERATION":
            for slot, value, field_path in (
                ("KMS_KEY_ID", "provider-generated-key-id", "/KeyMetadata/KeyId"),
                (
                    "KMS_KEY_ARN",
                    (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "12345678-1234-1234-1234-1234567890ab"
                    ),
                    "/KeyMetadata/Arn",
                ),
            ):
                for source in ("WRITE_RESPONSE", "READBACK"):
                    projection = {
                        "slot": slot,
                        "source": source,
                        "field_path": field_path,
                        "value_digest": canonical_digest(value),
                    }
                    projection["projection_digest"] = canonical_digest(projection)
                    projection_records.append(projection)
        verification = {
            "record_type": (
                "scanalyze.platform_authority."
                "gug365_upstream_provider_transcript_verification.v1"
            ),
            "schema_version": 1,
            "implementation_issue": "GUG-376",
            "environment": "authority-non-production",
            "production": False,
            "production_status": "NO-GO",
            "stage": stage,
            "evidence_origin": "SYNTHETIC_TEST",
            "verifier_identity_digest": D3,
            "attestation_root_digest": D4,
            "session_identifier_digest": D4,
            "account_or_management_binding_digest": D1,
            "caller_identity_digest": D2,
            "region": "us-east-1",
            "phase": phase["phase"],
            "authorization_digest": authorization_digest,
            "operation_sequence": sequence if stage == "OPERATION" else None,
            "operation_action": operation["action"] if stage == "OPERATION" else None,
            "request_digest": operation["request_digest"] if stage == "OPERATION" else None,
            "provider_result_digest": D4 if stage == "OPERATION" else None,
            "observed_readback_digest": (
                operation["expected_readback_digest"] if stage == "OPERATION" else None
            ),
            "raw_provider_digest": None,
            "sts_call_receipt_digest": D3,
            "sts_was_first_signed_call": True,
            "effective_authority_readback_digest": D1,
            "projections": projection_records,
            "verified_at": "2026-08-13T20:00:00Z",
            "external_attestation_receipt_digest": D2,
        }
        verification["verification_digest"] = canonical_digest(verification)
        return verification
    preflight = provider_verification("PREFLIGHT")
    provider_operation = provider_verification("OPERATION")
    record = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_operation_receipt.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-376",
        "consumer_issue": "GUG-365",
        "environment": "authority-non-production",
        "production": False,
        "production_status": "NO-GO",
        "phase": phase["phase"],
        "sequence": sequence,
        "request_digest": operation["request_digest"],
        "expected_readback_digest": operation["expected_readback_digest"],
        "observed_readback_digest": operation["expected_readback_digest"],
        "provider_result_digest": D4,
        "authorization_digest": authorization_digest,
        "claim_ledger_digest": D1,
        "provider_preflight_verification": preflight,
        "provider_operation_verification": provider_operation,
        "provider_evidence_origin": "SYNTHETIC_TEST",
        "status": "SUCCEEDED",
        "write_attempt_count": 1,
        "blind_retry_permitted": False,
        "automatic_rollback": False,
        "observed_at": "2026-08-13T20:00:00Z",
    }
    record["receipt_digest"] = canonical_digest(record)
    validate_operation_receipt(record)
    return record


def _phases(kms_phase: dict[str, object]) -> list[dict[str, object]]:
    phases = []
    for phase, _target, _predecessor in PHASE_SPECS:
        if phase == "KMS_FOUNDATION":
            phases.append(kms_phase)
        else:
            phases.append(
                build_phase_contract(
                    phase=phase,
                    inventory_classification="EXACT_PRESENT_NO_TOUCH",
                    operations=[],
                    rollback_boundary="Exact provider state remains untouched.",
                )
            )
    return phases


def _plan(kms_phase: dict[str, object]) -> dict[str, object]:
    inventory = _inventory()
    owner_decisions = _owner_decisions()
    inventory["account_binding_digest"] = D1
    inventory["caller_identity_digest"] = D2
    for phase in _phases(kms_phase):
        for name in PHASE_INVENTORY_RESOURCES[phase["phase"]]:
            inventory["resources"][name]["classification"] = phase[
                "inventory_classification"
            ]
    inventory["inventory_digest"] = canonical_digest(
        {key: value for key, value in inventory.items() if key != "inventory_digest"}
    )
    return build_upstream_plan(
        upstream_run_digest=D1,
        owner_decisions=owner_decisions,
        owner_decisions_approval_digest=expected_owner_decisions_approval_digest(
            owner_decisions
        ),
        inventory=inventory,
        private_ledger_root_digest=D1,
        phases=_phases(kms_phase),
        created_at=NOW + timedelta(minutes=2),
    )


def test_owner_decisions_are_digest_bound_and_schema_valid() -> None:
    record = _owner_decisions()
    validate_owner_decisions(record)
    assert not list(_schema("owner-decisions").iter_errors(record))
    tampered = copy.deepcopy(record)
    tampered["decisions"][0]["value_digest"] = canonical_digest("changed-alias")
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OWNER_DECISION_TARGET_DIGEST_MISMATCH",
    ):
        validate_owner_decisions(tampered)


def test_stable_repository_observations_do_not_claim_provider_certification() -> None:
    record = _inventory()
    validate_stable_inventory(record)
    assert not list(_schema("inventory").iter_errors(record))
    assert record["inventory_complete"] is False
    assert record["certification_eligible"] is False
    assert record["runtime_evidence"]["provider_backed"] is False
    assert record["runtime_evidence"]["readback_complete"] is False
    assert record["runtime_evidence"]["evidence_status"] == "NOT_PROVEN"
    assert record["runtime_evidence"]["runtime_version_arn"] is None

    owner_decisions = _owner_decisions()
    target_contracts = _target_contracts(owner_decisions)
    target_digests = {
        name: target["target_digest"] for name, target in target_contracts.items()
    }
    first = _raw_snapshot(NOW, D1, target_digests=target_digests)
    drifted = _raw_snapshot(
        NOW + timedelta(minutes=2),
        D2,
        fact_suffix="-drift",
        target_digests=target_digests,
    )
    with pytest.raises(
        UpstreamPrerequisiteError, match="INVENTORY_RAW_PROVIDER_EVIDENCE_INVALID"
    ):
        build_stable_inventory(
            upstream_run_digest=D1,
            owner_decisions=owner_decisions,
            account_binding_digest=D3,
            caller_identity_digest=D4,
            first_raw_provider_snapshot=first,
            second_raw_provider_snapshot=drifted,
            target_contracts=target_contracts,
            created_at=NOW + timedelta(minutes=3),
        )


def _attempt_live_inventory_promotion() -> dict[str, object]:
    owner_decisions = _owner_decisions()
    target_contracts = _target_contracts(owner_decisions)
    target_digests = {
        name: target["target_digest"] for name, target in target_contracts.items()
    }
    first = _raw_snapshot(NOW, D1, target_digests=target_digests)
    second = _raw_snapshot(
        NOW + timedelta(minutes=2), D2, target_digests=target_digests
    )
    inventory = build_stable_inventory(
        upstream_run_digest=D1,
        owner_decisions=owner_decisions,
        account_binding_digest=D3,
        caller_identity_digest=D4,
        first_raw_provider_snapshot=first,
        second_raw_provider_snapshot=second,
        target_contracts=target_contracts,
        created_at=NOW + timedelta(minutes=3),
    )
    return certify_stable_inventory_provider_transcripts(
        inventory=inventory,
        first_raw_provider_snapshot=first,
        second_raw_provider_snapshot=second,
        execution_trust_anchor=_trust_anchor(),
        verifier=object(),
        first_transcript_receipt={"external_attestation_receipt_digest": D1},
        second_transcript_receipt={"external_attestation_receipt_digest": D2},
        evaluated_at=NOW + timedelta(minutes=4),
    )


def test_inventory_live_promotion_requires_unimplemented_private_orchestrator() -> None:
    base = _inventory()
    assert base["evidence_origin"] == "REPOSITORY_OBSERVED_UNATTESTED"
    assert base["provider_transcript_verified"] is False
    assert base["inventory_complete"] is False
    assert base["certification_eligible"] is False
    assert base["runtime_evidence"]["evidence_status"] == "NOT_PROVEN"

    with pytest.raises(
        UpstreamInventoryError,
        match="STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED",
    ):
        _attempt_live_inventory_promotion()


def test_resealed_inventory_cannot_claim_live_provider_provenance() -> None:
    resealed = copy.deepcopy(_inventory())
    resealed.update(
        {
            "evidence_origin": "EXTERNALLY_ATTESTED_PROVIDER",
            "provider_transcript_verified": True,
            "provider_transcript_verification_digests": [D1, D2],
            "provider_verifier_identity_digest": D3,
            "provider_attestation_root_digest": D4,
        }
    )
    resealed["inventory_digest"] = canonical_digest(
        {key: value for key, value in resealed.items() if key != "inventory_digest"}
    )

    with pytest.raises(
        UpstreamPrerequisiteError,
        match="INVENTORY_PROVIDER_TRANSCRIPT_INVALID",
    ):
        validate_stable_inventory(resealed)
    assert list(_schema("inventory").iter_errors(resealed))


def test_inventory_classification_is_derived_from_stable_target_facts() -> None:
    owner_decisions = _owner_decisions()
    targets = _target_contracts(owner_decisions)
    target_digests = {
        name: target["target_digest"] for name, target in targets.items()
    }
    first = _raw_snapshot(
        NOW,
        D1,
        present_target="kms_key",
        observed_contract_digest=target_digests["kms_key"],
        target_digests=target_digests,
    )
    second = _raw_snapshot(
        NOW + timedelta(minutes=2),
        D2,
        present_target="kms_key",
        observed_contract_digest=target_digests["kms_key"],
        target_digests=target_digests,
    )
    inventory = build_stable_inventory(
        upstream_run_digest=D1,
        owner_decisions=owner_decisions,
        account_binding_digest=D3,
        caller_identity_digest=D4,
        first_raw_provider_snapshot=first,
        second_raw_provider_snapshot=second,
        target_contracts=targets,
        created_at=NOW + timedelta(minutes=3),
    )
    assert inventory["resources"]["kms_key"]["classification"] == (
        "EXACT_PRESENT_NO_TOUCH"
    )
    assert inventory["resources"]["artifact_bucket"]["classification"] == (
        "ABSENT_READY"
    )

    drifted_first = _raw_snapshot(
        NOW,
        D1,
        present_target="kms_key",
        observed_contract_digest=D2,
        target_digests=target_digests,
    )
    drifted_second = _raw_snapshot(
        NOW + timedelta(minutes=2),
        D2,
        present_target="kms_key",
        observed_contract_digest=D2,
        target_digests=target_digests,
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="INVENTORY_PREEXISTING_OR_DRIFT_BLOCKED",
    ):
        build_stable_inventory(
            upstream_run_digest=D1,
            owner_decisions=owner_decisions,
            account_binding_digest=D3,
            caller_identity_digest=D4,
            first_raw_provider_snapshot=drifted_first,
            second_raw_provider_snapshot=drifted_second,
            target_contracts=targets,
            created_at=NOW + timedelta(minutes=3),
        )


def test_plan_is_nine_phase_closed_world_and_persists_no_request_payload() -> None:
    kms_phase, _templates = _kms_phase(unresolved=True)
    plan = _plan(kms_phase)
    validate_upstream_plan(plan)
    assert not list(_schema("plan").iter_errors(plan))
    assert [phase["phase"] for phase in plan["phases"]] == list(PHASE_NAMES)
    assert Counter(op["action"] for op in plan["phases"][1]["operations"]) == REQUIRED_ACTIONS[
        "KMS_FOUNDATION"
    ]
    serialized = canonical_json(plan)
    assert "alias/scanalyze-gug376" not in serialized
    assert "key-id-digest-bound" not in serialized


def test_identity_center_compiles_to_the_honest_source_gap_without_raw_values() -> None:
    compiled = [
        _build_identity_operation(sequence)
        for sequence in range(1, 15)
        if sequence != 2
    ]
    expected = REQUIRED_ACTIONS["IDENTITY_CENTER_FOUNDATION"].copy()
    expected.subtract({"sso:PutApplicationAuthenticationMethod": 1})
    assert Counter(operation["action"] for operation in compiled) == expected
    by_sequence = {operation["sequence"]: operation for operation in compiled}
    assert by_sequence[7]["required_slots"] == []
    assert set(by_sequence[8]["required_slots"]) == {
        "CLASSIFIER_PERMISSION_SET_ARN",
        "IDENTITY_CENTER_APPLICATION_ARN",
    }
    assert set(by_sequence[12]["required_slots"]) == {
        "APPROVER_PERMISSION_SET_ARN",
        "IDENTITY_CENTER_APPLICATION_ARN",
    }

    application_arn = (
        "arn:aws:sso::123456789012:application/"
        "ssoins-1234567890abcdef/apl-abcdef1234567890"
    )
    classifier_arn = (
        "arn:aws:sso:::permissionSet/"
        "ssoins-1234567890abcdef/ps-aaaaaaaaaaaaaaaa"
    )
    approver_arn = (
        "arn:aws:sso:::permissionSet/"
        "ssoins-1234567890abcdef/ps-bbbbbbbbbbbbbbbb"
    )
    bindings = [
        _identity_slot_binding(
            slot="IDENTITY_CENTER_APPLICATION_ARN",
            value=application_arn,
            producer_sequence=1,
            producer_action="sso:CreateApplication",
            consumers=[2, 3, 4, 5, 6, 8, 12],
        ),
        _identity_slot_binding(
            slot="CLASSIFIER_PERMISSION_SET_ARN",
            value=classifier_arn,
            producer_sequence=7,
            producer_action="sso:CreatePermissionSet",
            consumers=[8, 9, 10],
        ),
        _identity_slot_binding(
            slot="APPROVER_PERMISSION_SET_ARN",
            value=approver_arn,
            producer_sequence=11,
            producer_action="sso:CreatePermissionSet",
            consumers=[12, 13, 14],
        ),
    ]
    assert {binding["slot"] for binding in bindings} == {
        "IDENTITY_CENTER_APPLICATION_ARN",
        "CLASSIFIER_PERMISSION_SET_ARN",
        "APPROVER_PERMISSION_SET_ARN",
    }
    serialized = canonical_json(compiled)
    for raw_value in _owner_decision_values().values():
        assert raw_value not in serialized
    assert application_arn not in serialized
    assert classifier_arn not in serialized
    assert approver_arn not in serialized


def test_identity_center_actor_policy_stops_at_the_source_contract_gap() -> None:
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        _build_identity_operation(2)


def test_identity_center_rejects_unknown_or_interchanged_slots_and_raw_arns() -> None:
    templates, _ = _identity_operation_inputs()

    unknown = copy.deepcopy(templates[2])
    unknown["ApplicationArn"] = {"$provider_slot": "UNKNOWN_APPLICATION_ARN"}
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_PROVIDER_SLOT_ROUTE_UNKNOWN",
    ):
        _build_identity_operation(3, template=unknown)

    interchanged = copy.deepcopy(templates[7])
    interchanged["PermissionSetArn"] = {
        "$provider_slot": "APPROVER_PERMISSION_SET_ARN"
    }
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="PROVIDER_SLOT_CONSUMER_TARGET_MISMATCH",
    ):
        _build_identity_operation(8, template=interchanged)

    same_boundary_application = copy.deepcopy(templates[2])
    same_boundary_application["ApplicationArn"] = (
        "arn:aws:sso::123456789012:application/"
        "ssoins-1234567890abcdef/apl-0000000000000000"
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="IDENTITY_APPLICATION_ARN_CAUSAL_SLOT_REQUIRED",
    ):
        _build_identity_operation(3, template=same_boundary_application)

    same_instance_permission_set = copy.deepcopy(templates[7])
    same_instance_permission_set["PermissionSetArn"] = (
        "arn:aws:sso:::permissionSet/"
        "ssoins-1234567890abcdef/ps-0000000000000000"
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="IDENTITY_PERMISSION_SET_ARN_CAUSAL_SLOT_REQUIRED",
    ):
        _build_identity_operation(8, template=same_instance_permission_set)


def test_identity_center_rejects_owner_and_source_contract_substitution() -> None:
    templates, _ = _identity_operation_inputs()

    cases: list[tuple[int, dict[str, object], str]] = []
    application_name = copy.deepcopy(templates[0])
    application_name["Name"] = "ForeignApplication"
    cases.append((1, application_name, "OPERATION_OWNER_REQUEST_VALUE_MISMATCH"))

    application_provider = copy.deepcopy(templates[0])
    application_provider["ApplicationProviderArn"] = (
        "arn:aws:sso::aws:applicationProvider/foreign"
    )
    cases.append((1, application_provider, "OPERATION_OWNER_REQUEST_VALUE_MISMATCH"))

    instance_arn = copy.deepcopy(templates[8])
    instance_arn["InstanceArn"] = (
        "arn:aws:sso:::instance/ssoins-ffffffffffffffff"
    )
    cases.append((9, instance_arn, "OPERATION_OWNER_REQUEST_VALUE_MISMATCH"))

    user_id = copy.deepcopy(templates[8])
    user_id["PrincipalId"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
    cases.append((9, user_id, "OPERATION_OWNER_REQUEST_VALUE_MISMATCH"))

    target_id = copy.deepcopy(templates[8])
    target_id["TargetId"] = "210987654321"
    cases.append((9, target_id, "OPERATION_OWNER_REQUEST_VALUE_MISMATCH"))

    permission_name = copy.deepcopy(templates[6])
    permission_name["Name"] = "ScanalyzeAuthorityRetireApprove"
    cases.append((7, permission_name, "IDENTITY_PERMISSION_SET_TARGET_SUBSTITUTION"))

    redirect = copy.deepcopy(templates[2])
    redirect["Grant"]["AuthorizationCode"]["RedirectUris"] = [
        "http://127.0.0.1:18444/callback"
    ]
    cases.append((3, redirect, "IDENTITY_APPLICATION_REDIRECT_SUBSTITUTION"))

    portal = copy.deepcopy(templates[0])
    portal["PortalOptions"]["SignInOptions"]["ApplicationUrl"] = (
        "http://127.0.0.1:18444"
    )
    cases.append((1, portal, "IDENTITY_APPLICATION_SOURCE_CONTRACT_INVALID"))

    scope = copy.deepcopy(templates[3])
    scope["AuthorizedTargets"] = [
        "arn:aws:sso:::instance/ssoins-ffffffffffffffff"
    ]
    cases.append((4, scope, "IDENTITY_APPLICATION_SCOPE_TARGET_SUBSTITUTION"))

    policy = copy.deepcopy(templates[7])
    policy["InlinePolicy"]["Statement"][1]["Resource"] = (
        "arn:aws:iam::123456789012:role/ForeignClassifier"
    )
    cases.append((8, policy, "IDENTITY_INLINE_POLICY_SOURCE_CONTRACT_INVALID"))

    for sequence, template, error in cases:
        with pytest.raises(UpstreamPrerequisiteError, match=error):
            _build_identity_operation(sequence, template=template)


def test_signing_job_profile_owner_is_bound_to_the_authority_account() -> None:
    owner_decisions = _owner_decisions()
    target = _target_contracts(owner_decisions)["broker_signing_job"]
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_OWNER_REQUEST_VALUE_MISMATCH",
    ):
        build_operation_contract(
            phase="BROKER_SIGNING_JOB",
            sequence=1,
            action="signer:StartSigningJob",
            inventory_resource="broker_signing_job",
            target_contract=target,
            owner_decisions=owner_decisions,
            owner_decision_values=_owner_decision_values(),
            request_template={
                "clientRequestToken": "gug376-broker-signing-job-once",
                "destination": {
                    "s3": {
                        "bucketName": "scanalyze-gug376-example",
                        "prefix": "scanalyze/platform-authority/gug-215/signed.zip",
                    }
                },
                "profileName": "scanalyze_gug376",
                "profileOwner": "210987654321",
                "source": {
                    "s3": {
                        "bucketName": "scanalyze-gug376-example",
                        "key": "scanalyze/platform-authority/gug-215/unsigned.zip",
                        "version": {
                            "$provider_slot": "BROKER_UNSIGNED_VERSION_ID"
                        },
                    }
                },
            },
            expected_readback_digest=D2,
        )


def test_provider_slots_require_causal_resolution_and_fresh_exact_authorization() -> None:
    unresolved_phase, templates = _kms_phase(unresolved=True)
    plan = _plan(unresolved_phase)
    first_authorization = build_phase_authorization(
        plan=plan,
        resolved_phase=unresolved_phase,
        request_templates=templates,
        slot_values={},
        completed_operation_receipts=[],
        completed_operation_authorizations=[],
        completed_owner_authorization_responses=[],
        account_or_management_binding_digest=D1,
        caller_identity_digest=D2,
        executor_authority_evidence=_authority(unresolved_phase, completed_count=0),
        execution_trust_anchor=_trust_anchor(),
        before_state_digest=plan["phase_inventory_bindings"][1][
            "provider_before_state_digest"
        ],
        private_ledger_root_digest=D1,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=15),
        causal_predecessor_certification_digest=D3,
    )
    first_response = "\n".join(
        (
            "SIMULATE_GUG365_UPSTREAM_REPOSITORY_V1",
            "phase=KMS_FOUNDATION",
            f"authorization_digest={first_authorization['authorization_digest']}",
        )
    )
    first_receipt = _operation_receipt(
        phase=unresolved_phase,
        sequence=1,
        authorization_digest=first_authorization["authorization_digest"],
    )
    with pytest.raises(UpstreamPrerequisiteError, match="AUTHORIZATION_PROVIDER_SLOTS_UNRESOLVED"):
        build_phase_authorization(
            plan=plan,
            resolved_phase=unresolved_phase,
            request_templates=templates,
            slot_values={},
            completed_operation_receipts=[first_receipt],
            completed_operation_authorizations=[first_authorization],
            completed_owner_authorization_responses=[first_response],
            account_or_management_binding_digest=D1,
            caller_identity_digest=D2,
            executor_authority_evidence=_authority(unresolved_phase, completed_count=0),
            execution_trust_anchor=_trust_anchor(),
            before_state_digest=D2,
            private_ledger_root_digest=D1,
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=15),
            causal_predecessor_certification_digest=D3,
        )

    key_arn = (
        "arn:aws:kms:us-east-1:123456789012:key/"
        "12345678-1234-1234-1234-1234567890ab"
    )
    slot_binding = build_provider_slot_binding(
        slot="KMS_KEY_ARN",
        value=key_arn,
        producer_phase="KMS_FOUNDATION",
        producer_operation_sequence=1,
        producer_authorization_digest=first_authorization["authorization_digest"],
        producer_operation_receipt_digest=first_receipt["receipt_digest"],
        producer_provider_result_digest=first_receipt["provider_result_digest"],
        producer_readback_digest=first_receipt["observed_readback_digest"],
        producer_transcript_verification=first_receipt[
            "provider_operation_verification"
        ],
        consumer_phase="KMS_FOUNDATION",
        consumer_operation_sequences=[2, 3],
    )
    resolved = resolve_phase_requests(
        phase=unresolved_phase,
        request_templates=templates,
        slot_values={"KMS_KEY_ARN": key_arn},
        slot_bindings=[slot_binding],
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match=(
            "AUTHORIZATION_COMPLETED_RECEIPT_BINDING_MISMATCH|"
            "OPERATION_RECEIPT_PROVIDER_VERIFICATION_BINDING_INVALID"
        ),
    ):
        wrong_receipt = _operation_receipt(
            phase=resolved,
            sequence=2,
            authorization_digest=first_authorization["authorization_digest"],
        )
        wrong_receipt["sequence"] = 1
        wrong_receipt["receipt_digest"] = canonical_digest(
            {key: value for key, value in wrong_receipt.items() if key != "receipt_digest"}
        )
        build_phase_authorization(
            plan=plan,
            resolved_phase=resolved,
            request_templates=templates,
            slot_values={"KMS_KEY_ARN": key_arn},
            slot_bindings=[slot_binding],
            completed_operation_receipts=[wrong_receipt],
            completed_operation_authorizations=[first_authorization],
            completed_owner_authorization_responses=[first_response],
            account_or_management_binding_digest=D1,
            caller_identity_digest=D2,
            executor_authority_evidence=_authority(resolved, completed_count=1),
            execution_trust_anchor=_trust_anchor(),
            before_state_digest=D2,
            private_ledger_root_digest=D1,
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=15),
            causal_predecessor_certification_digest=D3,
        )
    authorization = build_phase_authorization(
        plan=plan,
        resolved_phase=resolved,
        request_templates=templates,
        slot_values={"KMS_KEY_ARN": key_arn},
        slot_bindings=[slot_binding],
        completed_operation_receipts=[first_receipt],
        completed_operation_authorizations=[first_authorization],
        completed_owner_authorization_responses=[first_response],
        account_or_management_binding_digest=D1,
        caller_identity_digest=D2,
        executor_authority_evidence=_authority(resolved, completed_count=1),
        execution_trust_anchor=_trust_anchor(),
        before_state_digest=D2,
        private_ledger_root_digest=D1,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=15),
        causal_predecessor_certification_digest=D3,
    )
    validate_phase_authorization(authorization)
    assert len(authorization["ordered_request_digests"]) == 2
    validate_owner_authorization_response(
        "\n".join(
            (
                "SIMULATE_GUG365_UPSTREAM_REPOSITORY_V1",
                "phase=KMS_FOUNDATION",
                f"authorization_digest={authorization['authorization_digest']}",
            )
        ),
        authorization,
    )
    with pytest.raises(UpstreamPrerequisiteError, match="OWNER_AUTHORIZATION_RESPONSE_INVALID"):
        validate_owner_authorization_response("ok", authorization)


def test_action_outside_exact_phase_write_set_is_rejected() -> None:
    with pytest.raises(UpstreamPrerequisiteError, match="PHASE_ACTION_NOT_ALLOWED"):
        _operation("KMS_FOUNDATION", 1, "iam:CreateRole", {"RoleName": "forbidden"})


def test_dangerous_policy_and_plan_substitution_are_rejected() -> None:
    dangerous = {
        "BypassPolicyLockoutSafetyCheck": False,
        "Description": "forged",
        "KeySpec": "SYMMETRIC_DEFAULT",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "MultiRegion": False,
        "Origin": "AWS_KMS",
        "Policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"
            }],
        },
        "Tags": [{"TagKey": "ScanalyzeIssue", "TagValue": "GUG-376"}],
    }
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="POLICY_WILDCARD_ACTION_FORBIDDEN|POLICY_PUBLIC_PRINCIPAL_FORBIDDEN",
    ):
        _operation("KMS_FOUNDATION", 1, "kms:CreateKey", dangerous)

    bucket_delete = {
        "Bucket": "scanalyze-gug376-example",
        "Policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "s3:DeleteObject",
                    "Resource": (
                        "arn:aws:s3:::scanalyze-gug376-example/"
                        "unplanned/customer-data"
                    ),
                }
            ],
        },
    }
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="S3_BUCKET_POLICY_ACTION_SET_INVALID",
    ):
        _operation(
            "S3_ARTIFACT_FOUNDATION",
            6,
            "s3:PutBucketPolicy",
            bucket_delete,
        )

    kms_use_policy = copy.deepcopy(_kms_phase(unresolved=True)[1][0])
    kms_use_policy["Policy"]["Statement"][0]["Action"] = [
        "kms:Decrypt",
        "kms:GenerateDataKey",
    ]
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        _operation("KMS_FOUNDATION", 1, "kms:CreateKey", kms_use_policy)

    foreign_principal = copy.deepcopy(_kms_phase(unresolved=True)[1][0])
    foreign_principal["Policy"]["Statement"][0]["Principal"] = {
        "AWS": "arn:aws:iam::210987654321:root"
    }
    with pytest.raises(
        UpstreamPrerequisiteError, match="POLICY_PRINCIPAL_NOT_APPROVED"
    ):
        _operation("KMS_FOUNDATION", 1, "kms:CreateKey", foreign_principal)


def test_exact_gug376_cross_account_s3_kms_contract_is_version_and_role_bound() -> None:
    commit = "a" * 40
    kms_key_arn = (
        "arn:aws:kms:us-east-1:042360977644:key/"
        "00000000-0000-4000-8000-000000000001"
    )
    contract = public_upstream.build_gug376_cross_account_artifact_read_contract(
        source_commit=commit,
        artifact_bucket="scanalyze-gug365-artifacts",
        artifact_kms_key_arn=kms_key_arn,
        route_template_version="route-version-1",
        delegation_template_version="delegation-version-1",
    )
    assert contract["aws_calls"] == contract["aws_mutations"] == 0
    assert contract["contract_digest"] == canonical_digest(
        {
            key: value
            for key, value in contract.items()
            if key != "contract_digest"
        }
    )
    kms = contract["kms_key_policy_statements"][0]
    assert kms["Action"] == "kms:Decrypt"
    assert kms["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-east-1",
        "kms:EncryptionContext:aws:s3:arn": (
            "arn:aws:s3:::scanalyze-gug365-artifacts"
        ),
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
    }
    principals = kms["Condition"]["ArnLike"]["aws:PrincipalArn"]
    assert (
        "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
        "AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_*"
    ) in principals
    assert not any(
        "AWSReservedSSO_AWSReadOnlyAccess_" in value for value in principals
    )
    assert any(
        value.endswith("AWSReservedSSO_ScanalyzeGug376BrokerSeedCreator_*")
        for value in principals
    )
    assert any(
        value.endswith("AWSReservedSSO_ScanalyzeGug376BrokerSeedExec_*")
        for value in principals
    )
    assert (
        "arn:aws:iam::042360977644:role/ScanalyzeGug376RouteBrokerCreator"
        in principals
    )
    assert (
        "arn:aws:iam::042360977644:role/ScanalyzeGug376RouteBrokerExecutor"
        in principals
    )
    assert not any("ScanalyzeAuthorityBootstrapPlan" in value for value in principals)
    assert all("839393571433" in value or "042360977644" in value for value in principals)
    assert not any(value == "*" for value in principals)
    assert all(
        statement["Action"] == "s3:GetObjectVersion"
        for statement in contract["s3_bucket_policy_statements"]
    )
    route_read, delegation_read = contract["s3_bucket_policy_statements"]
    assert route_read["Condition"]["StringEquals"]["s3:VersionId"] == "route-version-1"
    assert delegation_read["Condition"]["StringEquals"]["s3:VersionId"] == "delegation-version-1"
    assert route_read["Resource"].endswith(
        f"/{commit}/cfn-platform-authority-gug376-temporary-change-set-route.yaml"
    )
    assert delegation_read["Resource"].endswith(
        f"/{commit}/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
    )
    public_upstream._validate_policy_document(  # noqa: SLF001
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ExactAuthorityKeyAdministration",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::042360977644:root"
                    },
                    "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                    "Resource": "*",
                },
                *contract["kms_key_policy_statements"],
            ],
        },
        policy_kind="KMS_KEY",
        allowed_principal_digests=[
            canonical_digest("arn:aws:iam::042360977644:root"),
            canonical_digest("arn:aws:iam::839393571433:root"),
        ],
    )
    public_upstream._validate_policy_document(  # noqa: SLF001
        {
            "Version": "2012-10-17",
            "Statement": contract["s3_bucket_policy_statements"],
        },
        policy_kind="S3_BUCKET",
        allowed_principal_digests=[
            canonical_digest("arn:aws:iam::839393571433:root")
        ],
    )


@pytest.mark.parametrize(
    "invalid_direct_role",
    [
        (
            "arn:aws:iam::042360977644:role/"
            "ScanalyzeGug376RouteBrokerCreatorExtra"
        ),
        (
            "arn:aws:iam::210987654321:role/"
            "ScanalyzeGug376RouteBrokerCreator"
        ),
    ],
)
def test_gug376_cross_account_kms_contract_rejects_unapproved_direct_roles(
    invalid_direct_role: str,
) -> None:
    contract = public_upstream.build_gug376_cross_account_artifact_read_contract(
        source_commit="a" * 40,
        artifact_bucket="scanalyze-gug365-artifacts",
        artifact_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        route_template_version="route-version-1",
        delegation_template_version="delegation-version-1",
    )
    kms_statement = copy.deepcopy(contract["kms_key_policy_statements"][0])
    principals = kms_statement["Condition"]["ArnLike"]["aws:PrincipalArn"]
    principals[principals.index(
        "arn:aws:iam::042360977644:role/ScanalyzeGug376RouteBrokerCreator"
    )] = invalid_direct_role
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        public_upstream._validate_policy_document(  # noqa: SLF001
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ExactAuthorityKeyAdministration",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::042360977644:root"
                        },
                        "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                        "Resource": "*",
                    },
                    kms_statement,
                ],
            },
            policy_kind="KMS_KEY",
            allowed_principal_digests=[
                canonical_digest("arn:aws:iam::042360977644:root"),
                canonical_digest("arn:aws:iam::839393571433:root"),
            ],
        )


@pytest.mark.parametrize(
    "invalid_principal",
    [
        (
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AWSReadOnlyAccess_*"
        ),
        (
            "arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_UnreviewedPermissionSet_*"
        ),
        (
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "UnreviewedRouteBrokerRole"
        ),
    ],
)
def test_gug376_kms_contract_rejects_sso_and_path_role_substitution(
    invalid_principal: str,
) -> None:
    contract = public_upstream.build_gug376_cross_account_artifact_read_contract(
        source_commit="a" * 40,
        artifact_bucket="scanalyze-gug365-artifacts",
        artifact_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        route_template_version="route-version-1",
        delegation_template_version="delegation-version-1",
    )
    statement = copy.deepcopy(contract["kms_key_policy_statements"][0])
    principals = statement["Condition"]["ArnLike"]["aws:PrincipalArn"]
    principals[0] = invalid_principal
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        public_upstream._validate_policy_document(  # noqa: SLF001
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::042360977644:root"
                        },
                        "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                        "Resource": "*",
                    },
                    statement,
                ],
            },
            policy_kind="KMS_KEY",
            allowed_principal_digests=[
                canonical_digest("arn:aws:iam::042360977644:root"),
                canonical_digest("arn:aws:iam::839393571433:root"),
            ],
        )


@pytest.mark.parametrize("action", ["kms:Encrypt", "kms:GenerateDataKey"])
def test_gug376_kms_read_contract_rejects_write_action_escalation(
    action: str,
) -> None:
    contract = public_upstream.build_gug376_cross_account_artifact_read_contract(
        source_commit="a" * 40,
        artifact_bucket="scanalyze-gug365-artifacts",
        artifact_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        route_template_version="route-version-1",
        delegation_template_version="delegation-version-1",
    )
    statement = copy.deepcopy(contract["kms_key_policy_statements"][0])
    statement["Action"] = ["kms:Decrypt", action]
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
    ):
        public_upstream._validate_policy_document(  # noqa: SLF001
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::042360977644:root"
                        },
                        "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                        "Resource": "*",
                    },
                    statement,
                ],
            },
            policy_kind="KMS_KEY",
            allowed_principal_digests=[
                canonical_digest("arn:aws:iam::042360977644:root"),
                canonical_digest("arn:aws:iam::839393571433:root"),
            ],
        )


@pytest.mark.parametrize(
    ("statement_index", "invalid_principal"),
    [
        (
            0,
            "arn:aws:iam::839393571433:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_AWSReadOnlyAccess_*",
        ),
        (
            0,
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "ScanalyzeGug376RouteBrokerCreator",
        ),
        (
            1,
            "arn:aws:iam::839393571433:role/aws-reserved/"
            "sso.amazonaws.com/AWSReservedSSO_AWSAdministratorAccess_*",
        ),
        (
            1,
            "arn:aws:iam::839393571433:role/scanalyze/platform-authority/"
            "UnreviewedRouteBrokerRole",
        ),
    ],
)
def test_gug376_s3_contract_rejects_profile_and_route_delegation_swap(
    statement_index: int,
    invalid_principal: str,
) -> None:
    contract = public_upstream.build_gug376_cross_account_artifact_read_contract(
        source_commit="a" * 40,
        artifact_bucket="scanalyze-gug365-artifacts",
        artifact_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        route_template_version="route-version-1",
        delegation_template_version="delegation-version-1",
    )
    statements = copy.deepcopy(contract["s3_bucket_policy_statements"])
    statements[statement_index]["Condition"]["ArnLike"][
        "aws:PrincipalArn"
    ] = invalid_principal
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="S3_BUCKET_POLICY_VERSION_BINDING_INVALID",
    ):
        public_upstream._validate_policy_document(  # noqa: SLF001
            {"Version": "2012-10-17", "Statement": statements},
            policy_kind="S3_BUCKET",
            allowed_principal_digests=[
                canonical_digest("arn:aws:iam::839393571433:root")
            ],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_commit", "b" * 39),
        ("artifact_bucket", "Foreign_Bucket"),
        (
            "artifact_kms_key_arn",
            "arn:aws:kms:us-east-1:839393571433:key/"
            "00000000-0000-4000-8000-000000000001",
        ),
        ("route_template_version", "null"),
        ("delegation_template_version", "v" * 1025),
    ],
)
def test_gug376_cross_account_artifact_contract_rejects_substitution(
    field: str, value: str
) -> None:
    kwargs = {
        "source_commit": "a" * 40,
        "artifact_bucket": "scanalyze-gug365-artifacts",
        "artifact_kms_key_arn": (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        "route_template_version": "route-version-1",
        "delegation_template_version": "delegation-version-1",
    }
    kwargs[field] = value
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="GUG376_ARTIFACT_ACCESS_INPUT_INVALID",
    ):
        public_upstream.build_gug376_cross_account_artifact_read_contract(
            **kwargs
        )


def test_dangerous_resource_and_plan_substitution_are_rejected() -> None:
    exact_resource_phase, _ = _kms_phase(unresolved=False)
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="EXECUTOR_AUTHORITY_RESOURCE_OPERATION_BINDING_MISMATCH",
    ):
        build_phase_executor_authority_evidence(
            resolved_phase=exact_resource_phase,
            completed_operation_count=0,
            resource_arns_by_sequence={
                1: ["*"],
                2: ["arn:aws:kms:us-east-1:123456789012:key/foreign"],
                3: ["arn:aws:kms:us-east-1:123456789012:key/foreign"],
            },
            account_or_management_binding_digest=D1,
            caller_identity_digest=D2,
            session_identifier_digest=D4,
            sts_call_receipt_digest=D3,
            permission_set_policy_readback_digest=D1,
            permissions_boundary_readback_digest=D1,
            additive_grants_readback_digest=canonical_digest([]),
            effective_authority_readback_digest=D1,
            session_verifier_identity_digest=D3,
            session_attestation_root_digest=D4,
            session_expires_at=NOW + timedelta(minutes=16),
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=15),
        )

    exact_phase, templates = _kms_phase(unresolved=False)
    plan = _plan(exact_phase)
    substituted = copy.deepcopy(exact_phase)
    substituted["operations"][0]["target_digest"] = D4
    substituted["operations"][0]["operation_digest"] = canonical_digest(
        {
            key: value
            for key, value in substituted["operations"][0].items()
            if key != "operation_digest"
        }
    )
    substituted["phase_operation_digest"] = canonical_digest(substituted["operations"])
    with pytest.raises(
        UpstreamPrerequisiteError,
        match=(
            "AUTHORIZATION_RESOLVED_PHASE_PLAN_MISMATCH|"
            "OPERATION_EXECUTOR_POLICY_DIGEST_MISMATCH"
        ),
    ):
        build_phase_authorization(
            plan=plan,
            resolved_phase=substituted,
            request_templates=templates,
            slot_values={},
            completed_operation_receipts=[],
            completed_operation_authorizations=[],
            completed_owner_authorization_responses=[],
            account_or_management_binding_digest=D1,
            caller_identity_digest=D2,
            executor_authority_evidence=_authority(substituted, completed_count=0),
            execution_trust_anchor=_trust_anchor(),
            before_state_digest=plan["phase_inventory_bindings"][1][
                "provider_before_state_digest"
            ],
            private_ledger_root_digest=D1,
            not_before=NOW,
            expires_at=NOW + timedelta(minutes=15),
            causal_predecessor_certification_digest=D3,
        )


def test_operation_authority_is_derived_from_owner_target_and_request() -> None:
    foreign_key = {
        "KeyId": (
            "arn:aws:kms:us-east-1:210987654321:key/"
            "12345678-1234-1234-1234-1234567890ab"
        ),
        "RotationPeriodInDays": 365,
    }
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_KMS_RESOURCE_ACCOUNT_MISMATCH",
    ):
        _operation("KMS_FOUNDATION", 2, "kms:EnableKeyRotation", foreign_key)

    substituted_alias = {
        "AliasName": "alias/scanalyze-substituted",
        "TargetKeyId": (
            "arn:aws:kms:us-east-1:123456789012:key/"
            "12345678-1234-1234-1234-1234567890ab"
        ),
    }
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_OWNER_REQUEST_VALUE_MISMATCH",
    ):
        _operation("KMS_FOUNDATION", 3, "kms:CreateAlias", substituted_alias)

    owner_decisions = _owner_decisions()
    target = _target_contracts(owner_decisions)["kms_key"]
    mismatched_owner_values = _owner_decision_values()
    mismatched_owner_values["authority_account_id"] = "210987654321"
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_OWNER_DECISION_VALUE_MISMATCH",
    ):
        build_operation_contract(
            phase="KMS_FOUNDATION",
            sequence=2,
            action="kms:EnableKeyRotation",
            inventory_resource="kms_key",
            target_contract=target,
            owner_decisions=owner_decisions,
            owner_decision_values=mismatched_owner_values,
            request_template={
                "KeyId": (
                    "arn:aws:kms:us-east-1:123456789012:key/"
                    "12345678-1234-1234-1234-1234567890ab"
                ),
                "RotationPeriodInDays": 365,
            },
            expected_readback_digest=D2,
        )

    destructive_policy = copy.deepcopy(_kms_phase(unresolved=True)[1][0])
    destructive_policy["Policy"]["Statement"][0]["Action"] = [
        "kms:ScheduleKeyDeletion"
    ]
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="KMS_KEY_POLICY_ACTION_SET_INVALID",
    ):
        _operation("KMS_FOUNDATION", 1, "kms:CreateKey", destructive_policy)

    operation = _operation(
        "KMS_FOUNDATION",
        2,
        "kms:EnableKeyRotation",
        {
            "KeyId": (
                "arn:aws:kms:us-east-1:123456789012:key/"
                "12345678-1234-1234-1234-1234567890ab"
            ),
            "RotationPeriodInDays": 365,
        },
    )
    operation["sequence"] = 1
    operation["executor_policy_digest"] = D4
    operation["operation_digest"] = canonical_digest(
        {key: value for key, value in operation.items() if key != "operation_digest"}
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="OPERATION_EXECUTOR_POLICY_DIGEST_MISMATCH",
    ):
        build_phase_contract(
            phase="KMS_FOUNDATION",
            inventory_classification="ABSENT_READY",
            operations=[operation],
            rollback_boundary="No automatic rollback.",
        )


def test_final_handoff_is_fact_only_and_preserves_single_operator_truth() -> None:
    fixture = json.loads(
        (
            ROOT
            / "fixtures/valid/platform-authority-gug365-upstream-final-handoff-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    counts = fixture["aws_write_counts"]
    counts["write_count_digest"] = canonical_digest(
        {key: value for key, value in counts.items() if key != "write_count_digest"}
    )
    fixture["handoff_digest"] = canonical_digest(
        {key: value for key, value in fixture.items() if key != "handoff_digest"}
    )
    validate_final_handoff(fixture)
    assert not list(_schema("final-handoff").iter_errors(fixture))
    assert fixture["two_human_status"] == "NOT_PROVEN"
    assert fixture["consumer_writes_authorized"] is False
    assert fixture["aws_write_counts"] == {
        "total": 0,
        "by_action": [],
        "write_count_digest": canonical_digest({"total": 0, "by_action": []}),
    }
    assert fixture["signing_job_count"] == 0
    assert fixture["distinct_signing_jobs_proven"] is False
    assert fixture["distinct_signed_objects_proven"] is False
    tampered = copy.deepcopy(fixture)
    tampered["two_human_status"] = "PROVEN"
    tampered["handoff_digest"] = canonical_digest(
        {key: value for key, value in tampered.items() if key != "handoff_digest"}
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match="HANDOFF_STOP_CHECKPOINT_INVALID",
    ):
        validate_final_handoff(tampered)

    resealed_live = copy.deepcopy(fixture)
    resealed_live.update(
        {
            "status": "LIVE_GUG365_UPSTREAM_PREREQUISITES_CERTIFIED",
            "evidence_scope": "LIVE_AUTHORITY_NON_PRODUCTION",
            "provider_certification_complete": True,
            "negative_evidence_complete": True,
            "negative_evidence_verification_digest": D1,
        }
    )
    resealed_live["handoff_digest"] = canonical_digest(
        {
            key: value
            for key, value in resealed_live.items()
            if key != "handoff_digest"
        }
    )
    with pytest.raises(
        UpstreamPrerequisiteError,
        match=(
            "HANDOFF_STOP_CHECKPOINT_FIELDS_INVALID|"
            "HANDOFF_STOP_CHECKPOINT_INVALID"
        ),
    ):
        validate_final_handoff(resealed_live)
    assert list(_schema("final-handoff").iter_errors(resealed_live))

    exact_phase, _templates = _kms_phase(unresolved=False)
    plan = _plan(exact_phase)
    with pytest.raises(
        UpstreamPrerequisiteError, match="STOP_UPSTREAM_SOURCE_CONTRACT_GAP"
    ):
        build_final_handoff(
            plan=plan,
            phase_certification_bundles=[],
            gug363_intent={},
            gug363_plan={},
            ledger_factory_signing_contract={},
            repo_root=ROOT,
            residual_risks=["Fresh GUG-365 checkpoint required."],
            created_at=NOW + timedelta(minutes=30),
        )
