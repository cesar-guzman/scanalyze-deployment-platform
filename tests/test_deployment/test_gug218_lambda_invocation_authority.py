"""GUG-218 fail-closed Lambda authority inventory tests."""
from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

import pytest

from tooling.platform_authority_lambda_invocation_authority import (
    EXPECTED_AUTHORITY_EDGE_COUNT,
    EXPECTED_FORBIDDEN_AUTHORITY_CLASSES,
    EVIDENCE_SOURCE_AWS_READ_ONLY,
    EVIDENCE_SOURCE_OFFLINE_UNVERIFIED,
    INVENTORY_DRIFT,
    INVENTORY_FOREIGN_AUTHORITY,
    INVENTORY_INCOMPLETE,
    INVENTORY_OFFLINE_UNVERIFIED,
    INVENTORY_REVIEW_SAFE,
    INVENTORY_SCOPE,
    INVENTORY_UNSUPPORTED,
    RECEIPT_ACCESS_DENIED,
    RECEIPT_REVIEW_REQUIRED,
    RECEIPT_UNSAFE,
    RECEIPT_AMBIGUOUS,
    RECEIPT_UNVERIFIED_SOURCE,
    RECEIPT_DRIFT,
    RECEIPT_INCOMPLETE,
    RAW_SNAPSHOT_FORMAT,
    REVIEWED_FUNCTION_CONFIGURATION_RESPONSE_FIELDS,
    AuthorityInventoryError,
    AwsReadOnlyInventoryAdapter,
    TargetBinding,
    _coverage,
    _published_configuration_digest,
    _strict_policy_document,
    _strict_paginate,
    analyze_authority_inventory,
    canonical_digest,
    digest_text,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/deployment/platform-authority-lambda-invocation-authority.py"
ACCOUNT = "111122223333"
REGION = "us-east-1"
FUNCTION = "scanalyze-platform-authority-gug215-retirement"
CLASSIFIER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ClassifierInvoker"
APPROVER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ApproverInvoker"
CLASSIFIER_PERMISSION_SET = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeClassifier_0123456789abcdef"
)
APPROVER_PERMISSION_SET = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeApprover_fedcba9876543210"
)
STARTED = "2030-01-01T00:00:00Z"
COMPLETED = "2030-01-01T00:01:00Z"
DECISION = "2030-01-01T00:01:01Z"
EXPIRES = "2030-01-01T00:06:00Z"
BROKER_CODE_SHA256 = "A" * 43 + "="
BROKER_PROVIDER_CONFIGURATION_SHA256 = "C" * 43 + "="
BROKER_EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215Broker"
BROKER_PUBLISHED_CONFIGURATION = {
    "Architectures": ["x86_64"],
    "ConfigSha256": BROKER_PROVIDER_CONFIGURATION_SHA256,
    "Environment": {
        "Variables": {
            "SCANALYZE_AUTHORITY_ACCOUNT_ID": ACCOUNT,
            "SCANALYZE_AUTHORITY_REGION": REGION,
        }
    },
    "Handler": "tooling.platform_authority_identity_context_pep_runtime.handler",
    "MemorySize": 128,
    "PackageType": "Zip",
    "Role": BROKER_EXECUTION_ROLE,
    "Runtime": "python3.12",
    "Timeout": 30,
}
BROKER_PUBLISHED_CONFIGURATION_SHA256 = canonical_digest(
    BROKER_PUBLISHED_CONFIGURATION
)
COLLECTOR_PRINCIPAL_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/ScanalyzeAuthorityReadOnly"
)


def _binding() -> TargetBinding:
    return TargetBinding(
        authority_account_id=ACCOUNT,
        region=REGION,
        function_name=FUNCTION,
    )


def _condition(action: str) -> dict[str, Any]:
    if action == "lambda:InvokeFunctionUrl":
        return {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
    return {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}


def _resource_policy(role: str, alias: str) -> dict[str, Any]:
    resource = _binding().alias_arn(alias)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FunctionUrl",
                "Effect": "Allow",
                "Principal": {"AWS": role},
                "Action": "lambda:InvokeFunctionUrl",
                "Resource": resource,
                "Condition": _condition("lambda:InvokeFunctionUrl"),
            },
            {
                "Sid": "ViaFunctionUrl",
                "Effect": "Allow",
                "Principal": {"AWS": role},
                "Action": "lambda:InvokeFunction",
                "Resource": resource,
                "Condition": _condition("lambda:InvokeFunction"),
            },
        ],
    }


def _identity_policy(role: str, aliases: list[str]) -> dict[str, Any]:
    del role
    resources = [_binding().alias_arn(alias) for alias in aliases]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FunctionUrl",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunctionUrl",
                "Resource": resources[0] if len(resources) == 1 else resources,
                "Condition": _condition("lambda:InvokeFunctionUrl"),
            },
            {
                "Sid": "ViaFunctionUrl",
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": resources[0] if len(resources) == 1 else resources,
                "Condition": _condition("lambda:InvokeFunction"),
            },
        ],
    }


def _trust(permission_set: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeFromExactPermissionSet",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnEquals": {"aws:PrincipalArn": permission_set}},
            }
        ],
    }


def _expected_edges() -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    bindings = (
        ("classifier", CLASSIFIER_ROLE, CLASSIFIER_PERMISSION_SET, ["classify"]),
        (
            "independent_approver",
            APPROVER_ROLE,
            APPROVER_PERMISSION_SET,
            ["retire", "reconcile"],
        ),
    )
    for duty, role, permission_set, aliases in bindings:
        identity_document = _identity_policy(role, aliases)
        for alias in aliases:
            resource = _binding().alias_arn(alias)
            target_scope = f"EXACT_{alias.upper()}_ALIAS"
            resource_document = _resource_policy(role, alias)
            for action, condition_class in (
                ("lambda:InvokeFunctionUrl", "FUNCTION_URL_AUTH_TYPE_AWS_IAM"),
                ("lambda:InvokeFunction", "INVOKED_VIA_FUNCTION_URL_TRUE"),
            ):
                edges.append(
                    {
                        "authority_class": "INVOCATION",
                        "source_type": "LAMBDA_RESOURCE_POLICY",
                        "duty": duty,
                        "target_scope": target_scope,
                        "action": action,
                        "condition_class": condition_class,
                        "principal_digest": digest_text(role),
                        "resource_digest": digest_text(resource),
                        "source_document_digest": canonical_digest(resource_document),
                    }
                )
                edges.append(
                    {
                        "authority_class": "INVOCATION",
                        "source_type": "IAM_ROLE_INLINE_POLICY",
                        "duty": duty,
                        "target_scope": target_scope,
                        "action": action,
                        "condition_class": condition_class,
                        "principal_digest": digest_text(role),
                        "resource_digest": digest_text(resource),
                        "source_document_digest": canonical_digest(identity_document),
                    }
                )
        role_scope = (
            "CLASSIFIER_INVOKER_ROLE"
            if duty == "classifier"
            else "APPROVER_INVOKER_ROLE"
        )
        edges.append(
            {
                "authority_class": "TRUST",
                "source_type": "IAM_ROLE_TRUST_POLICY",
                "duty": duty,
                "target_scope": role_scope,
                "action": "sts:AssumeRole",
                "condition_class": "EXACT_PERMISSION_SET_TRUST",
                "principal_digest": digest_text(permission_set),
                "resource_digest": digest_text(role),
                "source_document_digest": canonical_digest(_trust(permission_set)),
            }
        )
    assert len(edges) == EXPECTED_AUTHORITY_EDGE_COUNT
    return edges


def _allowlist() -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_allowlist",
        "environment": "non-production",
        "production": False,
        "inventory_scope": INVENTORY_SCOPE,
        "authority_account_id_digest": digest_text(ACCOUNT),
        "target_region": REGION,
        "source_template_sha256": "sha256:" + "a" * 64,
        "source_policy_bundle_sha256": "sha256:" + "b" * 64,
        "broker_artifact_code_sha256": BROKER_CODE_SHA256,
        "broker_published_configuration_sha256": (
            BROKER_PUBLISHED_CONFIGURATION_SHA256
        ),
        "collector_role_principal_digest": digest_text(COLLECTOR_PRINCIPAL_ARN),
        "expected_authority_edges": _expected_edges(),
        "forbidden_authority_classes": sorted(
            EXPECTED_FORBIDDEN_AUTHORITY_CLASSES
        ),
        "live_effect_authorized": False,
        "created_at": STARTED,
    }
    value["allowlist_digest"] = canonical_digest(value)
    return value


@pytest.mark.parametrize(
    ("field", "value"),
    (
        (
            "CapacityProviderConfig",
            {"LambdaManagedInstancesCapacityProviderConfig": {}},
        ),
        ("ConfigSha256", "D" * 43 + "="),
        ("DurableConfig", {"ExecutionTimeout": 900}),
        ("TenancyConfig", {"TenantIsolationMode": "PER_TENANT"}),
    ),
)
def test_published_configuration_digest_covers_current_provider_fields(
    field: str,
    value: object,
) -> None:
    changed = copy.deepcopy(BROKER_PUBLISHED_CONFIGURATION)
    changed[field] = value

    assert _published_configuration_digest(
        changed,
        "SYNTHETIC_CONFIGURATION_INVALID",
    ) != _published_configuration_digest(
        BROKER_PUBLISHED_CONFIGURATION,
        "SYNTHETIC_CONFIGURATION_INVALID",
    )


def test_published_configuration_digest_requires_provider_config_sha256() -> None:
    missing = copy.deepcopy(BROKER_PUBLISHED_CONFIGURATION)
    del missing["ConfigSha256"]

    with pytest.raises(
        AuthorityInventoryError,
        match="SYNTHETIC_CONFIGURATION_INVALID",
    ):
        _published_configuration_digest(
            missing,
            "SYNTHETIC_CONFIGURATION_INVALID",
        )


def test_published_configuration_digest_rejects_unreviewed_provider_fields() -> None:
    future = copy.deepcopy(BROKER_PUBLISHED_CONFIGURATION)
    future["FutureExecutionMode"] = "UNREVIEWED"

    with pytest.raises(
        AuthorityInventoryError,
        match="LAMBDA_CONFIGURATION_FIELD_UNREVIEWED",
    ):
        _published_configuration_digest(
            future,
            "SYNTHETIC_CONFIGURATION_INVALID",
        )


def test_reviewed_configuration_fields_match_pinned_botocore_model() -> None:
    botocore_session = pytest.importorskip("botocore.session")
    service = botocore_session.get_session().get_service_model("lambda")

    for operation_name, collection_name in (
        ("ListFunctions", "Functions"),
        ("ListVersionsByFunction", "Versions"),
    ):
        output = service.operation_model(operation_name).output_shape
        collection = output.members[collection_name]
        assert set(collection.member.members) == set(
            REVIEWED_FUNCTION_CONFIGURATION_RESPONSE_FIELDS
        )


def _complete_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    lam = snapshot["lambda"]
    iam = snapshot["iam"]
    surfaces = {
        "region_discovery": snapshot["enabled_regions"],
        "lambda_functions": lam["functions"],
        "lambda_aliases": lam["aliases"],
        "lambda_versions": lam["versions"],
        "lambda_function_urls": lam["function_urls"],
        "lambda_resource_policies": lam["resource_policies"],
        "lambda_event_source_mappings": [
            *lam["event_source_mappings"],
            *lam["event_invoke_configs"],
        ],
        "iam_account_authorization": [
            *iam["users"],
            *iam["groups"],
            *iam["roles"],
            *iam["policies"],
            iam["managed_policy_documents"],
        ],
    }
    return {key: _coverage("COMPLETE", value, 1) for key, value in surfaces.items()}


def _reseal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot.pop("snapshot_digest", None)
    snapshot["snapshot_digest"] = canonical_digest(snapshot)
    return snapshot


def _seal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot["coverage"] = _complete_coverage(snapshot)
    return _reseal_snapshot(snapshot)


def _snapshot() -> dict[str, Any]:
    classifier_identity = _identity_policy(CLASSIFIER_ROLE, ["classify"])
    approver_identity = _identity_policy(APPROVER_ROLE, ["retire", "reconcile"])
    binding = _binding()
    value: dict[str, Any] = {
        "snapshot_format": RAW_SNAPSHOT_FORMAT,
        "capture_started_at": STARTED,
        "capture_completed_at": COMPLETED,
        "capture_expires_at": EXPIRES,
        "collector_nonce": "synthetic-gug218-scan-0001",
        "collector_principal_arn": COLLECTOR_PRINCIPAL_ARN,
        "collector_principal_arn_digest": digest_text(COLLECTOR_PRINCIPAL_ARN),
        "enabled_regions": [REGION],
        "scanned_regions": [REGION],
        "lambda": {
            "functions": [
                {
                    "FunctionName": FUNCTION,
                    "FunctionArn": binding.function_arn,
                    "Version": "$LATEST",
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": (
                        BROKER_PUBLISHED_CONFIGURATION_SHA256
                    ),
                }
            ],
            "aliases": [
                {
                    "Name": alias,
                    "FunctionVersion": "1",
                    "FunctionArn": binding.alias_arn(alias),
                }
                for alias in sorted(("classify", "retire", "reconcile"))
            ],
            "versions": [
                {
                    "Version": "$LATEST",
                    "FunctionArn": binding.function_arn,
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": (
                        BROKER_PUBLISHED_CONFIGURATION_SHA256
                    ),
                },
                {
                    "Version": "1",
                    "FunctionArn": f"{binding.function_arn}:1",
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": (
                        BROKER_PUBLISHED_CONFIGURATION_SHA256
                    ),
                },
            ],
            "function_urls": [
                {
                    "FunctionArn": binding.alias_arn(alias),
                    "AuthType": "AWS_IAM",
                    "InvokeMode": "BUFFERED",
                }
                for alias in sorted(("classify", "retire", "reconcile"))
            ],
            "resource_policies": [
                {
                    "resource_arn": binding.alias_arn("classify"),
                    "policy_document": _resource_policy(CLASSIFIER_ROLE, "classify"),
                },
                *[
                    {
                        "resource_arn": binding.alias_arn(alias),
                        "policy_document": _resource_policy(APPROVER_ROLE, alias),
                    }
                    for alias in ("retire", "reconcile")
                ],
            ],
            "event_source_mappings": [],
            "event_invoke_configs": [],
        },
        "iam": {
            "users": [],
            "groups": [],
            "roles": [
                {
                    "Arn": CLASSIFIER_ROLE,
                    "RoleName": "ScanalyzeGug215ClassifierInvoker",
                    "AssumeRolePolicyDocument": _trust(CLASSIFIER_PERMISSION_SET),
                    "RolePolicyList": [
                        {
                            "PolicyName": "Gug215ClassifierInvokeOnly",
                            "PolicyDocument": classifier_identity,
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
                {
                    "Arn": APPROVER_ROLE,
                    "RoleName": "ScanalyzeGug215ApproverInvoker",
                    "AssumeRolePolicyDocument": _trust(APPROVER_PERMISSION_SET),
                    "RolePolicyList": [
                        {
                            "PolicyName": "Gug215ApproverInvokeOnly",
                            "PolicyDocument": approver_identity,
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
            ],
            "policies": [],
            "managed_policy_documents": {},
        },
    }
    return _seal_snapshot(value)


def _analyze(
    snapshot: dict[str, Any],
    *,
    evidence_source_mode: str = EVIDENCE_SOURCE_AWS_READ_ONLY,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return analyze_authority_inventory(
        allowlist=_allowlist(),
        snapshot=snapshot,
        binding=_binding(),
        evidence_source_mode=evidence_source_mode,
        decision_at=DECISION,
    )


def _append_identity_statement(
    snapshot: dict[str, Any], statement: dict[str, Any]
) -> dict[str, Any]:
    snapshot["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-authority-probe",
            "UserPolicyList": [
                {
                    "PolicyName": "SyntheticAuthorityProbe",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": statement,
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    return _seal_snapshot(snapshot)


def test_exact_fourteen_edges_are_report_only_and_sanitized() -> None:
    inventory, receipt = _analyze(_snapshot())

    assert inventory["status"] == INVENTORY_REVIEW_SAFE
    assert inventory["expected_edge_count"] == EXPECTED_AUTHORITY_EDGE_COUNT
    assert inventory["prohibited_edge_count"] == 0
    assert inventory["unknown_edge_count"] == 0
    assert inventory["mutating_authority_count"] == 0
    assert inventory["unsupported_policy_semantics_detected"] is False
    assert inventory["structural_drift_detected"] is False
    assert receipt["status"] == RECEIPT_REVIEW_REQUIRED
    assert inventory["evidence_source_mode"] == EVIDENCE_SOURCE_AWS_READ_ONLY
    assert receipt["evidence_source_mode"] == EVIDENCE_SOURCE_AWS_READ_ONLY
    assert receipt["reason_code"] == "EXACT_AUTHORITY_REPORT_ONLY"
    assert inventory["source_snapshot_digest"] == _snapshot()["snapshot_digest"]
    assert inventory["collector_principal_digest"] == digest_text(
        COLLECTOR_PRINCIPAL_ARN
    )
    assert receipt["expected_authority_exact"] is True
    assert receipt["deployment_authorized"] is False
    assert receipt["live_retirement_authorized"] is False
    serialized = json.dumps({"inventory": inventory, "receipt": receipt}, sort_keys=True)
    for forbidden in (
        ACCOUNT,
        FUNCTION,
        CLASSIFIER_ROLE,
        APPROVER_ROLE,
        "ScanalyzeGug215ClassifierInvoker",
        "FunctionUrl",
    ):
        assert forbidden not in serialized


def test_offline_snapshot_never_emits_the_authenticated_preflight_status() -> None:
    inventory, receipt = _analyze(
        _snapshot(), evidence_source_mode=EVIDENCE_SOURCE_OFFLINE_UNVERIFIED
    )

    assert inventory["status"] == INVENTORY_OFFLINE_UNVERIFIED
    assert receipt["status"] == RECEIPT_UNVERIFIED_SOURCE
    assert receipt["reason_code"] == "UNVERIFIED_EVIDENCE_SOURCE"
    assert receipt["next_required_control"] == "COLLECT_AUTHENTICATED_AWS_INVENTORY"
    assert receipt["coverage_complete"] is False
    assert receipt["expected_authority_exact"] is False
    assert receipt["snapshot_fresh"] is False
    assert receipt["deployment_authorized"] is False


@pytest.mark.parametrize(
    "resource",
    (
        f"{_binding().function_arn}:backdoor-*",
        f"{_binding().function_arn}:backdoor-?",
        f"{_binding().function_arn}:backdoor-[0-9]",
    ),
)
def test_future_qualifier_wildcard_is_visible_and_prohibited(resource: str) -> None:
    snapshot = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": resource,
        },
    )

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(
        edge["target_scope"] == "WILDCARD"
        and edge["verdict"] == "PROHIBITED"
        and edge["reason_code"] == "QUALIFIER_WILDCARD_PREAUTHORIZATION"
        for edge in inventory["authority_edges"]
    )
    assert receipt["status"] == RECEIPT_UNSAFE


@pytest.mark.parametrize(
    "resource",
    (
        (
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:"
            "${aws:PrincipalTag/FunctionName}:*"
        ),
        (
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:"
            f"${{aws:PrincipalTag/FunctionName, '{FUNCTION}'}}:*"
        ),
    ),
    ids=("principal-tag", "principal-tag-with-default"),
)
def test_policy_variable_resource_semantics_fail_closed(resource: str) -> None:
    snapshot = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": resource,
        },
    )

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_UNSUPPORTED
    assert inventory["unsupported_policy_semantics_detected"] is True
    assert receipt["status"] == RECEIPT_AMBIGUOUS
    assert receipt["reason_code"] == "AMBIGUOUS_EVIDENCE"


@pytest.mark.parametrize(
    "resource",
    (
        "arn:aws:lambda",
        f"arn:aws:lambda:{REGION}:{ACCOUNT}",
        f"arn:aws:lambda:{REGION}:{ACCOUNT}:function",
    ),
)
def test_incomplete_arn_expansion_semantics_fail_closed(resource: str) -> None:
    snapshot = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": resource,
        },
    )

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_UNSUPPORTED
    assert inventory["unsupported_policy_semantics_detected"] is True
    assert receipt["status"] == RECEIPT_AMBIGUOUS


@pytest.mark.parametrize(
    ("resource", "expected_scope"),
    (
        (f"{_binding().function_arn}:future", "ALTERNATE_ALIAS"),
        (f"{_binding().function_arn}:backdoor-*", "WILDCARD"),
    ),
)
def test_latent_lambda_mutation_authority_is_visible_and_prohibited(
    resource: str, expected_scope: str
) -> None:
    snapshot = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:AddPermission",
            "Resource": resource,
        },
    )

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(
        edge["source_type"] == "LAMBDA_AUTHORITY_MUTATION"
        and edge["target_scope"] == expected_scope
        and edge["verdict"] == "PROHIBITED"
        for edge in inventory["authority_edges"]
    )
    assert receipt["status"] == RECEIPT_UNSAFE


@pytest.mark.parametrize(
    "resource",
    (
        (
            f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:"
            "${aws:PrincipalTag/FunctionName}:*"
        ),
        "arn:aws:lambda",
    ),
)
def test_lambda_mutator_dynamic_or_incomplete_resource_fails_closed(
    resource: str,
) -> None:
    snapshot = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:AddPermission",
            "Resource": resource,
        },
    )

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_UNSUPPORTED
    assert receipt["status"] == RECEIPT_AMBIGUOUS


def test_generated_inventory_and_receipt_match_versioned_contracts() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from tooling.validate_schema import validate_gug218_evidence_bundle

    inventory, receipt = _analyze(_snapshot())
    records = (
        (
            inventory,
            REPO_ROOT
            / "schemas/platform-authority-lambda-invocation-inventory.v1.schema.json",
        ),
        (
            receipt,
            REPO_ROOT
            / "schemas/platform-authority-lambda-invocation-guard-receipt.v1.schema.json",
        ),
    )
    for record, schema_path in records:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        ).validate(record)
    assert validate_gug218_evidence_bundle(
        allowlist=_allowlist(),
        inventory=inventory,
        receipt=receipt,
        evaluation_at=datetime.fromisoformat(DECISION.replace("Z", "+00:00")),
    ) == []


def test_every_terminal_receipt_matches_schema_and_semantics() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    from tooling.validate_schema import validate_gug218_evidence_bundle

    unsafe = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": _binding().alias_arn("retire"),
        },
    )
    denied = _snapshot()
    denied["coverage"]["iam_account_authorization"] = _coverage(
        "ACCESS_DENIED", [], 0
    )
    _reseal_snapshot(denied)
    incomplete = _snapshot()
    incomplete["enabled_regions"].append("us-west-2")
    _seal_snapshot(incomplete)
    ambiguous = _append_identity_statement(
        _snapshot(),
        {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": (
                f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:"
                "${aws:PrincipalTag/FunctionName}:*"
            ),
        },
    )
    drift = _snapshot()
    drift["lambda"]["versions"][1]["CodeSha256"] = "B" * 43 + "="
    _seal_snapshot(drift)

    records = [
        _analyze(_snapshot()),
        _analyze(unsafe),
        _analyze(denied),
        _analyze(incomplete),
        _analyze(ambiguous),
        _analyze(drift),
        _analyze(
            _snapshot(), evidence_source_mode=EVIDENCE_SOURCE_OFFLINE_UNVERIFIED
        ),
    ]
    expected_receipt_statuses = {
        RECEIPT_REVIEW_REQUIRED,
        RECEIPT_UNSAFE,
        RECEIPT_ACCESS_DENIED,
        RECEIPT_INCOMPLETE,
        RECEIPT_AMBIGUOUS,
        RECEIPT_DRIFT,
        RECEIPT_UNVERIFIED_SOURCE,
    }
    assert {receipt["status"] for _, receipt in records} == expected_receipt_statuses

    schemas = (
        REPO_ROOT
        / "schemas/platform-authority-lambda-invocation-inventory.v1.schema.json",
        REPO_ROOT
        / "schemas/platform-authority-lambda-invocation-guard-receipt.v1.schema.json",
    )
    for inventory, receipt in records:
        for record, schema_path in zip((inventory, receipt), schemas, strict=True):
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            ).validate(record)
        assert validate_gug218_evidence_bundle(
            allowlist=_allowlist(),
            inventory=inventory,
            receipt=receipt,
            evaluation_at=datetime.fromisoformat(
                DECISION.replace("Z", "+00:00")
            ),
        ) == []


def test_foreign_invoker_fails_closed() -> None:
    snapshot = _snapshot()
    snapshot["iam"]["roles"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:role/ForeignInvoker",
            "RoleName": "ForeignInvoker",
            "AssumeRolePolicyDocument": _trust(CLASSIFIER_PERMISSION_SET),
            "RolePolicyList": [
                {
                    "PolicyName": "Foreign",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "lambda:InvokeFunction",
                            "Resource": _binding().alias_arn("retire"),
                            "Condition": _condition("lambda:InvokeFunction"),
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert inventory["prohibited_edge_count"] == 1
    assert receipt["status"] == RECEIPT_UNSAFE
    assert "ForeignInvoker" not in json.dumps(inventory)


@pytest.mark.parametrize(
    ("resource", "expected_scope"),
    (
        (f"{_binding().function_arn}:1", "NUMERIC_VERSION"),
        (f"{_binding().function_arn}:0", "NUMERIC_VERSION"),
        (f"{_binding().function_arn}:$LATEST", "LATEST_VERSION"),
        (f"{_binding().function_arn}:alternate", "ALTERNATE_ALIAS"),
    ),
    ids=("current-version", "old-version", "latest", "alternate-alias"),
)
def test_direct_qualified_invocation_authority_is_never_invisible(
    resource: str, expected_scope: str
) -> None:
    snapshot = _snapshot()
    snapshot["iam"]["roles"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:role/ForeignQualifiedInvoker",
            "RoleName": "ForeignQualifiedInvoker",
            "AssumeRolePolicyDocument": _trust(CLASSIFIER_PERMISSION_SET),
            "RolePolicyList": [
                {
                    "PolicyName": "DirectQualifiedInvoke",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "lambda:InvokeFunction",
                            "Resource": resource,
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(
        edge["target_scope"] == expected_scope
        and edge["verdict"] == "PROHIBITED"
        for edge in inventory["authority_edges"]
    )
    assert receipt["status"] == RECEIPT_UNSAFE


@pytest.mark.parametrize(
    "action",
    [
        "lambda:AddPermission",
        "iam:UpdateAssumeRolePolicy",
        "cloudformation:ExecuteChangeSet",
        "lambda:*",
    ],
)
def test_control_plane_mutators_are_prohibited(action: str) -> None:
    snapshot = _snapshot()
    resource = (
        _binding().function_arn
        if action.startswith("lambda:")
        else "*"
        if action.startswith("cloudformation:")
        else CLASSIFIER_ROLE
    )
    snapshot["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin",
            "UserPolicyList": [
                {
                    "PolicyName": "SyntheticMutation",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": action,
                            "Resource": resource,
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert inventory["mutating_authority_count"] >= 1
    assert receipt["status"] == RECEIPT_UNSAFE


@pytest.mark.parametrize(
    ("action", "resource"),
    (
        (
            "iam:CreatePolicyVersion",
            f"arn:aws:iam::{ACCOUNT}:policy/exact-authority-policy",
        ),
        ("iam:CreateRole", "*"),
        ("iam:AttachUserPolicy", f"arn:aws:iam::{ACCOUNT}:user/exact-user"),
        ("iam:AttachGroupPolicy", f"arn:aws:iam::{ACCOUNT}:group/exact-group"),
        ("iam:AddUserToGroup", f"arn:aws:iam::{ACCOUNT}:group/exact-group"),
        ("iam:CreateAccessKey", f"arn:aws:iam::{ACCOUNT}:user/exact-user"),
    ),
)
def test_any_effective_iam_authority_mutation_is_prohibited(
    action: str, resource: str
) -> None:
    snapshot = _snapshot()
    snapshot["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/authority-mutator",
            "UserPolicyList": [
                {
                    "PolicyName": "ExactMutation",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": action,
                            "Resource": resource,
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(
        edge["source_type"] == "IAM_AUTHORITY_MUTATION"
        and edge["action_class"] == "MUTATE_IAM_AUTHORITY"
        and edge["verdict"] == "PROHIBITED"
        for edge in inventory["authority_edges"]
    )
    assert receipt["status"] == RECEIPT_UNSAFE


def test_public_or_alternate_function_url_is_prohibited() -> None:
    snapshot = _snapshot()
    snapshot["lambda"]["function_urls"].append(
        {
            "FunctionArn": f"{_binding().function_arn}:foreign",
            "AuthType": "NONE",
            "InvokeMode": "BUFFERED",
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(
        edge["source_type"] == "FUNCTION_URL_CONFIGURATION"
        and edge["principal_kind"] == "PUBLIC"
        for edge in inventory["authority_edges"]
    )
    assert receipt["status"] == RECEIPT_UNSAFE


@pytest.mark.parametrize(
    "mutation",
    (
        "weighted-alias",
        "split-version",
        "wrong-version-code",
        "wrong-latest-code",
        "wrong-version-configuration",
        "wrong-latest-configuration",
        "wrong-base-configuration",
    ),
)
def test_aliases_and_versions_must_bind_to_one_reviewed_artifact(
    mutation: str,
) -> None:
    snapshot = _snapshot()
    if mutation == "weighted-alias":
        snapshot["lambda"]["aliases"][0]["RoutingConfig"] = {
            "AdditionalVersionWeights": {"2": 0.1}
        }
    elif mutation == "split-version":
        snapshot["lambda"]["aliases"][0]["FunctionVersion"] = "2"
        snapshot["lambda"]["versions"].append(
            {
                "Version": "2",
                "FunctionArn": f"{_binding().function_arn}:2",
                "CodeSha256": BROKER_CODE_SHA256,
            }
        )
    elif mutation == "wrong-version-code":
        snapshot["lambda"]["versions"][1]["CodeSha256"] = "B" * 43 + "="
    elif mutation == "wrong-latest-code":
        snapshot["lambda"]["versions"][0]["CodeSha256"] = "B" * 43 + "="
    elif mutation == "wrong-version-configuration":
        snapshot["lambda"]["versions"][1]["PublishedConfigurationDigest"] = (
            "sha256:" + "c" * 64
        )
    elif mutation == "wrong-latest-configuration":
        snapshot["lambda"]["versions"][0]["PublishedConfigurationDigest"] = (
            "sha256:" + "c" * 64
        )
    else:
        snapshot["lambda"]["functions"][0]["PublishedConfigurationDigest"] = (
            "sha256:" + "c" * 64
        )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_DRIFT
    assert inventory["structural_drift_detected"] is True
    assert receipt["status"] == RECEIPT_DRIFT
    assert receipt["reason_code"] == "AUTHORITY_DRIFT_DETECTED"
    assert receipt["next_required_control"] == "RESOLVE_AUTHORITY_DRIFT"
    assert receipt["expected_authority_exact"] is False


def test_event_source_mapping_is_prohibited() -> None:
    snapshot = _snapshot()
    snapshot["lambda"]["event_source_mappings"] = [
        {
            "UUID": "00000000-0000-4000-8000-000000000000",
            "FunctionArn": _binding().alias_arn("retire"),
            "EventSourceArn": "arn:aws:sqs:us-east-1:111122223333:foreign",
        }
    ]
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_FOREIGN_AUTHORITY
    assert any(edge["action_class"] == "EVENT_SOURCE_INVOKE" for edge in inventory["authority_edges"])
    assert receipt["status"] == RECEIPT_UNSAFE


def test_access_denied_surface_cannot_be_reported_safe() -> None:
    snapshot = _snapshot()
    snapshot["coverage"]["iam_account_authorization"] = _coverage(
        "ACCESS_DENIED", [], 0
    )
    _reseal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_INCOMPLETE
    assert receipt["status"] == RECEIPT_ACCESS_DENIED
    assert receipt["coverage_complete"] is False
    assert receipt["expected_authority_exact"] is False


def test_claimed_complete_coverage_digest_cannot_hide_snapshot_tampering() -> None:
    snapshot = _snapshot()
    snapshot["lambda"]["aliases"].append(
        {
            "Name": "foreign",
            "FunctionVersion": "1",
            "FunctionArn": f"{_binding().function_arn}:foreign",
        }
    )
    _reseal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["coverage"]["lambda_aliases"]["status"] == "AMBIGUOUS"
    assert receipt["status"] != RECEIPT_REVIEW_REQUIRED


@pytest.mark.parametrize(
    "mutation", ("missing", "stale", "future", "inconsistent", "long-duration")
)
def test_snapshot_origin_time_is_required_and_cannot_be_rebased(
    mutation: str,
) -> None:
    snapshot = _snapshot()
    if mutation == "missing":
        snapshot.pop("capture_started_at")
    elif mutation == "stale":
        snapshot["capture_expires_at"] = "2030-01-01T00:01:00Z"
    elif mutation == "future":
        snapshot["capture_started_at"] = "2030-01-01T00:02:00Z"
        snapshot["capture_completed_at"] = "2030-01-01T00:03:00Z"
        snapshot["capture_expires_at"] = "2030-01-01T00:08:00Z"
    elif mutation == "inconsistent":
        snapshot["capture_started_at"] = "2030-01-01T00:02:00Z"
        snapshot["capture_completed_at"] = "2030-01-01T00:01:00Z"
    else:
        snapshot["capture_started_at"] = "2029-12-31T23:55:59Z"
    _reseal_snapshot(snapshot)

    with pytest.raises(AuthorityInventoryError):
        _analyze(snapshot)


def test_raw_snapshot_digest_detects_replay_envelope_tampering() -> None:
    snapshot = _snapshot()
    snapshot["collector_nonce"] = "tampered-after-seal"

    with pytest.raises(AuthorityInventoryError, match="SNAPSHOT_DIGEST_MISMATCH"):
        _analyze(snapshot)


def test_collector_principal_digest_is_revalidated_after_resealing() -> None:
    snapshot = _snapshot()
    snapshot["collector_principal_arn_digest"] = "sha256:" + "0" * 64
    _reseal_snapshot(snapshot)

    with pytest.raises(
        AuthorityInventoryError, match="COLLECTOR_PRINCIPAL_DIGEST_MISMATCH"
    ):
        _analyze(snapshot)


def test_collector_assumed_role_must_match_the_allowlist() -> None:
    snapshot = _snapshot()
    alternate = f"arn:aws:sts::{ACCOUNT}:assumed-role/AlternateReadOnlyRole"
    snapshot["collector_principal_arn"] = alternate
    snapshot["collector_principal_arn_digest"] = digest_text(alternate)
    _reseal_snapshot(snapshot)

    with pytest.raises(AuthorityInventoryError, match="COLLECTOR_PRINCIPAL_NOT_ALLOWLISTED"):
        _analyze(snapshot)


def test_missing_enabled_region_scan_fails_closed() -> None:
    snapshot = _snapshot()
    snapshot["enabled_regions"].append("us-west-2")
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_INCOMPLETE
    assert receipt["status"] != RECEIPT_REVIEW_REQUIRED


def test_not_action_is_over_approximated_never_accepted_silently() -> None:
    snapshot = _snapshot()
    snapshot["iam"]["groups"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:group/unsafe",
            "GroupPolicyList": [
                {
                    "PolicyName": "NotAction",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "NotAction": "s3:GetObject",
                            "Resource": "*",
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["prohibited_edge_count"] > 0
    assert inventory["mutating_authority_count"] > 0
    assert receipt["status"] == RECEIPT_AMBIGUOUS


def test_future_unreviewed_authority_action_is_ambiguous_never_ignored() -> None:
    snapshot = _snapshot()
    snapshot["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/future-authority",
            "UserPolicyList": [
                {
                    "PolicyName": "FutureAuthority",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:FutureAuthorityMutation",
                            "Resource": "*",
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    _seal_snapshot(snapshot)

    inventory, receipt = _analyze(snapshot)

    assert inventory["status"] == INVENTORY_UNSUPPORTED
    assert receipt["status"] == RECEIPT_AMBIGUOUS
    assert receipt["live_retirement_authorized"] is False


def test_allowlist_digest_is_revalidated() -> None:
    allowlist = _allowlist()
    allowlist["target_region"] = "us-west-2"

    with pytest.raises(AuthorityInventoryError):
        analyze_authority_inventory(
            allowlist=allowlist,
            snapshot=_snapshot(),
            binding=_binding(),
            evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
            decision_at=DECISION,
        )


def test_resealed_but_noncanonical_allowlist_matrix_is_rejected() -> None:
    allowlist = _allowlist()
    allowlist["expected_authority_edges"][0]["target_scope"] = "EXACT_RETIRE_ALIAS"
    allowlist["allowlist_digest"] = canonical_digest(
        {key: value for key, value in allowlist.items() if key != "allowlist_digest"}
    )

    with pytest.raises(AuthorityInventoryError, match="ALLOWLIST_EDGE_MATRIX_INVALID"):
        analyze_authority_inventory(
            allowlist=allowlist,
            snapshot=_snapshot(),
            binding=_binding(),
            evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
            decision_at=DECISION,
        )


def test_collector_role_cannot_overlap_an_authorized_invoker_duty() -> None:
    allowlist = _allowlist()
    allowlist["collector_role_principal_digest"] = digest_text(CLASSIFIER_ROLE)
    allowlist["allowlist_digest"] = canonical_digest(
        {key: value for key, value in allowlist.items() if key != "allowlist_digest"}
    )

    with pytest.raises(
        AuthorityInventoryError,
        match="ALLOWLIST_COLLECTOR_DUTY_SEPARATION_INVALID",
    ):
        analyze_authority_inventory(
            allowlist=allowlist,
            snapshot=_snapshot(),
            binding=_binding(),
            evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
            decision_at=DECISION,
        )


@pytest.mark.parametrize(
    "alternate_action",
    (
        "sts:AssumeRoleWithWebIdentity",
        "sts:AssumeRoleWithSAML",
        "sts:*",
        "sts:FutureAssumptiveAction",
    ),
)
def test_alternate_trust_action_blocks_even_when_allowlist_digest_is_resealed(
    alternate_action: str,
) -> None:
    snapshot = _snapshot()
    trust_document = _trust(CLASSIFIER_PERMISSION_SET)
    trust_document["Statement"][0]["Action"] = [
        "sts:AssumeRole",
        alternate_action,
    ]
    snapshot["iam"]["roles"][0]["AssumeRolePolicyDocument"] = trust_document
    _seal_snapshot(snapshot)
    allowlist = _allowlist()
    for edge in allowlist["expected_authority_edges"]:
        if edge["authority_class"] == "TRUST" and edge["duty"] == "classifier":
            edge["source_document_digest"] = canonical_digest(trust_document)
    allowlist["allowlist_digest"] = canonical_digest(
        {key: value for key, value in allowlist.items() if key != "allowlist_digest"}
    )

    inventory, receipt = analyze_authority_inventory(
        allowlist=allowlist,
        snapshot=snapshot,
        binding=_binding(),
        evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
        decision_at=DECISION,
    )

    assert inventory["status"] == INVENTORY_UNSUPPORTED
    assert inventory["unsupported_policy_semantics_detected"] is True
    assert receipt["status"] == RECEIPT_AMBIGUOUS


def test_strict_pagination_exhausts_every_page() -> None:
    pages = {
        None: {"Items": [1], "NextMarker": "second"},
        "second": {"Items": [2]},
    }
    calls: list[str | None] = []

    def operation(**kwargs: Any) -> dict[str, Any]:
        token = kwargs.get("Marker")
        calls.append(token)
        return pages[token]

    items, count = _strict_paginate(
        operation,
        result_key="Items",
        request_token="Marker",
        response_token="NextMarker",
    )

    assert items == [1, 2]
    assert count == 2
    assert calls == [None, "second"]


@pytest.mark.parametrize(
    "response",
    [
        {"Items": [], "NextMarker": 7},
        {"Items": [], "NextMarker": "repeat"},
        {"Items": [], "IsTruncated": True},
        {"Items": [], "IsTruncated": False, "Marker": "unexpected"},
    ],
)
def test_strict_pagination_rejects_ambiguous_state(response: dict[str, Any]) -> None:
    if "IsTruncated" in response:
        kwargs = {
            "result_key": "Items",
            "request_token": "Marker",
            "response_token": "Marker",
            "truncated_key": "IsTruncated",
        }
    else:
        kwargs = {
            "result_key": "Items",
            "request_token": "Marker",
            "response_token": "NextMarker",
        }

    with pytest.raises(AuthorityInventoryError):
        _strict_paginate(lambda **_: response, **kwargs)


def test_url_encoded_iam_policy_document_is_decoded_exactly_once() -> None:
    document = _identity_policy(CLASSIFIER_ROLE, ["classify"])
    encoded = quote(json.dumps(document, separators=(",", ":")), safe="")

    assert _strict_policy_document(encoded) == document


@pytest.mark.parametrize(
    ("value", "code"),
    (
        ("%7B%ZZ", "POLICY_DOCUMENT_PERCENT_ENCODING_INVALID"),
        (
            quote(quote(json.dumps(_identity_policy(CLASSIFIER_ROLE, ["classify"])), safe=""), safe=""),
            "POLICY_DOCUMENT_DOUBLE_ENCODING_FORBIDDEN",
        ),
        (
            quote(
                '{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}',
                safe="",
            ),
            "JSON_DUPLICATE_KEY",
        ),
    ),
)
def test_url_encoded_policy_document_rejects_ambiguous_encoding(
    value: str, code: str
) -> None:
    with pytest.raises(AuthorityInventoryError, match=code):
        _strict_policy_document(value)


def _load_cli_module() -> Any:
    spec = importlib.util.spec_from_file_location("gug218_authority_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_cli_inputs(tmp_path: Path, snapshot: dict[str, Any]) -> tuple[Path, Path]:
    allowlist_path = tmp_path / "allowlist.json"
    snapshot_path = tmp_path / "snapshot.json"
    allowlist_path.write_text(json.dumps(_allowlist()), encoding="utf-8")
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    return allowlist_path, snapshot_path


def _offline_cli_args(
    module: Any,
    allowlist_path: Path,
    snapshot_path: Path,
    *,
    expected_allowlist_digest: str | None = None,
) -> Any:
    return module._parser().parse_args(
        [
            "snapshot-check",
            "--allowlist",
            str(allowlist_path),
            "--expected-allowlist-digest",
            expected_allowlist_digest or _allowlist()["allowlist_digest"],
            "--snapshot",
            str(snapshot_path),
            "--authority-account-id",
            ACCOUNT,
            "--region",
            REGION,
            "--function-name",
            FUNCTION,
        ]
    )


def test_cli_rejects_substituted_allowlist_before_snapshot_collection(
    tmp_path: Path,
) -> None:
    module = _load_cli_module()
    allowlist_path, snapshot_path = _write_cli_inputs(tmp_path, _snapshot())
    args = _offline_cli_args(
        module,
        allowlist_path,
        snapshot_path,
        expected_allowlist_digest="sha256:" + "0" * 64,
    )
    snapshot_loader_called = False

    def unexpected_loader(_: Any) -> dict[str, Any]:
        nonlocal snapshot_loader_called
        snapshot_loader_called = True
        return _snapshot()

    args.snapshot_loader = unexpected_loader

    with pytest.raises(
        AuthorityInventoryError,
        match="REVIEWED_ALLOWLIST_DIGEST_MISMATCH",
    ):
        module._run(args)
    assert snapshot_loader_called is False


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        (lambda value: value.__setitem__("target_region", "us-west-2"), "ALLOWLIST_BINDING_INVALID"),
        (
            lambda value: value.__setitem__(
                "broker_published_configuration_sha256", "not-a-digest"
            ),
            "BROKER_PUBLISHED_CONFIGURATION_SHA256_INVALID",
        ),
    ),
)
def test_cli_revalidates_allowlist_contents_before_snapshot_collection(
    tmp_path: Path,
    mutation: Any,
    expected_code: str,
) -> None:
    module = _load_cli_module()
    allowlist = _allowlist()
    expected_digest = allowlist["allowlist_digest"]
    mutation(allowlist)
    allowlist_path = tmp_path / "allowlist.json"
    snapshot_path = tmp_path / "snapshot.json"
    allowlist_path.write_text(json.dumps(allowlist), encoding="utf-8")
    snapshot_path.write_text(json.dumps(_snapshot()), encoding="utf-8")
    args = _offline_cli_args(
        module,
        allowlist_path,
        snapshot_path,
        expected_allowlist_digest=expected_digest,
    )
    snapshot_loader_called = False

    def unexpected_loader(_: Any) -> dict[str, Any]:
        nonlocal snapshot_loader_called
        snapshot_loader_called = True
        return _snapshot()

    args.snapshot_loader = unexpected_loader

    with pytest.raises(AuthorityInventoryError, match=expected_code):
        module._run(args)
    assert snapshot_loader_called is False


def test_cli_rejects_binding_mismatch_before_snapshot_collection(
    tmp_path: Path,
) -> None:
    module = _load_cli_module()
    allowlist_path, snapshot_path = _write_cli_inputs(tmp_path, _snapshot())
    args = _offline_cli_args(module, allowlist_path, snapshot_path)
    args.region = "us-west-2"
    snapshot_loader_called = False

    def unexpected_loader(_: Any) -> dict[str, Any]:
        nonlocal snapshot_loader_called
        snapshot_loader_called = True
        return _snapshot()

    args.snapshot_loader = unexpected_loader

    with pytest.raises(AuthorityInventoryError, match="ALLOWLIST_BINDING_INVALID"):
        module._run(args)
    assert snapshot_loader_called is False


def test_offline_cli_sets_unverified_mode_and_cannot_claim_safe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_cli_module()
    now = datetime.now(tz=UTC).replace(microsecond=0)
    snapshot = _snapshot()
    snapshot["capture_started_at"] = (now - timedelta(minutes=2)).isoformat().replace(
        "+00:00", "Z"
    )
    snapshot["capture_completed_at"] = (now - timedelta(minutes=1)).isoformat().replace(
        "+00:00", "Z"
    )
    snapshot["capture_expires_at"] = (now + timedelta(minutes=4)).isoformat().replace(
        "+00:00", "Z"
    )
    _reseal_snapshot(snapshot)
    allowlist_path, snapshot_path = _write_cli_inputs(tmp_path, snapshot)
    args = _offline_cli_args(module, allowlist_path, snapshot_path)

    assert args.evidence_source_mode == EVIDENCE_SOURCE_OFFLINE_UNVERIFIED
    assert module._run(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["inventory"]["status"] == INVENTORY_OFFLINE_UNVERIFIED
    assert result["receipt"]["status"] == RECEIPT_UNVERIFIED_SOURCE


def test_offline_cli_rejects_stale_capture_instead_of_minting_freshness(
    tmp_path: Path,
) -> None:
    module = _load_cli_module()
    now = datetime.now(tz=UTC).replace(microsecond=0)
    snapshot = _snapshot()
    snapshot["capture_started_at"] = (now - timedelta(hours=1)).isoformat().replace(
        "+00:00", "Z"
    )
    snapshot["capture_completed_at"] = (now - timedelta(minutes=59)).isoformat().replace(
        "+00:00", "Z"
    )
    snapshot["capture_expires_at"] = (now - timedelta(minutes=54)).isoformat().replace(
        "+00:00", "Z"
    )
    _reseal_snapshot(snapshot)
    allowlist_path, snapshot_path = _write_cli_inputs(tmp_path, snapshot)
    args = _offline_cli_args(module, allowlist_path, snapshot_path)

    with pytest.raises(AuthorityInventoryError, match="INVENTORY_TIME_WINDOW_INVALID"):
        module._run(args)


@pytest.mark.parametrize(
    "name",
    ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_CA_BUNDLE"),
)
def test_aws_cli_rejects_transport_trust_overrides(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_cli_module()
    for variable in (*module.FORBIDDEN_CREDENTIAL_ENV, *module.FORBIDDEN_AWS_TRANSPORT_ENV):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv(name, "https://unreviewed.invalid")

    with pytest.raises(
        AuthorityInventoryError, match="AWS_TRANSPORT_OVERRIDE_FORBIDDEN"
    ):
        module._require_assumed_role_environment(
            profile="synthetic-profile", region=REGION
        )


def test_boto3_adapter_pins_canonical_aws_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    calls: list[tuple[str, dict[str, Any]]] = []

    class Meta:
        def __init__(self, endpoint_url: str) -> None:
            self.endpoint_url = endpoint_url

    class Client:
        def __init__(self, endpoint_url: str) -> None:
            self.meta = Meta(endpoint_url)

    class Session:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs == {
                "profile_name": "synthetic-profile",
                "region_name": REGION,
            }

        def client(self, service: str, **kwargs: Any) -> Client:
            calls.append((service, kwargs))
            return Client(kwargs["endpoint_url"])

    monkeypatch.setattr(boto3, "Session", Session)

    AwsReadOnlyInventoryAdapter.from_boto3(
        profile_name="synthetic-profile", region=REGION, partition="aws"
    )

    assert {(service, kwargs["endpoint_url"]) for service, kwargs in calls} == {
        ("sts", f"https://sts.{REGION}.amazonaws.com"),
        ("ec2", f"https://ec2.{REGION}.amazonaws.com"),
        ("iam", "https://iam.amazonaws.com"),
        ("lambda", f"https://lambda.{REGION}.amazonaws.com"),
    }
    assert all(kwargs["verify"] is True for _, kwargs in calls)


def test_boto3_adapter_rejects_client_endpoint_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3

    class Meta:
        endpoint_url = "https://sts.us-east-1.amazonaws.com.unreviewed.invalid"

    class Client:
        meta = Meta()

    class Session:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def client(self, service: str, **kwargs: Any) -> Client:
            return Client()

    monkeypatch.setattr(boto3, "Session", Session)

    with pytest.raises(
        AuthorityInventoryError, match="AWS_ENDPOINT_OVERRIDE_FORBIDDEN"
    ):
        AwsReadOnlyInventoryAdapter.from_boto3(
            profile_name="synthetic-profile", region=REGION, partition="aws"
        )


class _Sts:
    def get_caller_identity(self) -> dict[str, Any]:
        return {"Account": ACCOUNT, "Arn": f"{COLLECTOR_PRINCIPAL_ARN}/test"}


@pytest.mark.parametrize(
    "arn",
    (
        f"arn:aws:iam::{ACCOUNT}:root",
        f"arn:aws:iam::{ACCOUNT}:user/read-only-name-is-not-proof",
    ),
)
def test_aws_adapter_rejects_non_assumed_role_collectors(arn: str) -> None:
    class UnsafeSts:
        def get_caller_identity(self) -> dict[str, Any]:
            return {"Account": ACCOUNT, "Arn": arn}

    adapter = AwsReadOnlyInventoryAdapter(
        sts=UnsafeSts(), ec2=None, lambda_client=None, iam=None
    )

    with pytest.raises(AuthorityInventoryError, match="COLLECTOR_PRINCIPAL_ARN_INVALID"):
        adapter.collect(
            binding=_binding(),
            scan_id="synthetic-invalid-collector",
            expected_collector_principal_digest=_allowlist()[
                "collector_role_principal_digest"
            ],
        )


def test_aws_adapter_rejects_wrong_account_before_inventory() -> None:
    class WrongAccountSts:
        def get_caller_identity(self) -> dict[str, Any]:
            return {
                "Account": "999900001111",
                "Arn": (
                    "arn:aws:sts::999900001111:assumed-role/"
                    "ScanalyzeAuthorityReadOnly/session"
                ),
            }

    adapter = AwsReadOnlyInventoryAdapter(
        sts=WrongAccountSts(), ec2=None, lambda_client=None, iam=None
    )

    with pytest.raises(AuthorityInventoryError, match="AWS_ACCOUNT_MISMATCH"):
        adapter.collect(
            binding=_binding(),
            scan_id="synthetic-wrong-account",
            expected_collector_principal_digest=_allowlist()[
                "collector_role_principal_digest"
            ],
        )


def test_aws_adapter_rejects_wrong_same_account_role_after_sts_only() -> None:
    class WrongRoleSts:
        calls = 0

        def get_caller_identity(self) -> dict[str, Any]:
            self.calls += 1
            return {
                "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/WrongReadOnly/session",
            }

    class UnexpectedEc2:
        def describe_regions(self, **kwargs: Any) -> dict[str, Any]:
            raise AssertionError(f"inventory must not start: {kwargs}")

    sts = WrongRoleSts()
    adapter = AwsReadOnlyInventoryAdapter(
        sts=sts,
        ec2=UnexpectedEc2(),
        lambda_client=None,
        iam=None,
    )

    with pytest.raises(
        AuthorityInventoryError, match="COLLECTOR_PRINCIPAL_NOT_ALLOWLISTED"
    ):
        adapter.collect(
            binding=_binding(),
            scan_id="synthetic-wrong-same-account-role",
            expected_collector_principal_digest=_allowlist()[
                "collector_role_principal_digest"
            ],
        )
    assert sts.calls == 1


class _Ec2:
    def describe_regions(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"AllRegions": True}
        return {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}


class _Lambda:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _page(self, operation: str, key: str, items: list[Any]) -> dict[str, Any]:
        self.calls.append(operation)
        return {key: copy.deepcopy(items)}

    def list_functions(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {}
        functions = copy.deepcopy(_snapshot()["lambda"]["functions"])
        for function in functions:
            function.pop("PublishedConfigurationDigest", None)
            function.update(copy.deepcopy(BROKER_PUBLISHED_CONFIGURATION))
        return self._page(
            "list_functions",
            "Functions",
            functions,
        )

    def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"FunctionName": FUNCTION}
        return self._page("list_aliases", "Aliases", _snapshot()["lambda"]["aliases"])

    def list_versions_by_function(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"FunctionName": FUNCTION}
        versions = copy.deepcopy(_snapshot()["lambda"]["versions"])
        for version in versions:
            version.pop("PublishedConfigurationDigest", None)
            version.update(copy.deepcopy(BROKER_PUBLISHED_CONFIGURATION))
        return self._page("list_versions_by_function", "Versions", versions)

    def list_function_url_configs(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"FunctionName": FUNCTION}
        return self._page(
            "list_function_url_configs",
            "FunctionUrlConfigs",
            _snapshot()["lambda"]["function_urls"],
        )

    def list_event_source_mappings(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"FunctionName": FUNCTION}
        return self._page("list_event_source_mappings", "EventSourceMappings", [])

    def list_function_event_invoke_configs(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"FunctionName": FUNCTION}
        return self._page(
            "list_function_event_invoke_configs", "FunctionEventInvokeConfigs", []
        )

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("get_policy")
        qualifier = kwargs.get("Qualifier")
        if qualifier in {"classify", "retire", "reconcile"}:
            role = CLASSIFIER_ROLE if qualifier == "classify" else APPROVER_ROLE
            return {"Policy": json.dumps(_resource_policy(role, qualifier))}
        error = RuntimeError("not found")
        error.response = {"Error": {"Code": "ResourceNotFoundException"}}  # type: ignore[attr-defined]
        raise error


class _Iam:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def get_account_authorization_details(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("get_account_authorization_details")
        assert "Filter" in kwargs and "Marker" not in kwargs
        snapshot = _snapshot()["iam"]
        return {
            "IsTruncated": False,
            "UserDetailList": snapshot["users"],
            "GroupDetailList": snapshot["groups"],
            "RoleDetailList": snapshot["roles"],
            "Policies": snapshot["policies"],
        }

    def get_policy(self, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError(f"unexpected managed policy call: {kwargs}")

    def get_policy_version(self, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError(f"unexpected managed policy version call: {kwargs}")


def test_aws_adapter_uses_only_read_only_inventory_operations() -> None:
    lambda_client = _Lambda()
    iam = _Iam()
    adapter = AwsReadOnlyInventoryAdapter(
        sts=_Sts(), ec2=_Ec2(), lambda_client=lambda_client, iam=iam
    )

    snapshot = adapter.collect(
        binding=_binding(),
        scan_id="synthetic-adapter-scan",
        expected_collector_principal_digest=_allowlist()[
            "collector_role_principal_digest"
        ],
    )

    assert snapshot["snapshot_format"] == RAW_SNAPSHOT_FORMAT
    assert snapshot["collector_nonce"] == "synthetic-adapter-scan"
    assert snapshot["collector_principal_arn"] == COLLECTOR_PRINCIPAL_ARN
    assert snapshot["collector_principal_arn_digest"] == digest_text(
        snapshot["collector_principal_arn"]
    )
    assert snapshot["snapshot_digest"] == canonical_digest(
        {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    )
    assert snapshot["coverage"]["iam_account_authorization"]["status"] == "COMPLETE"
    assert snapshot["coverage"]["lambda_resource_policies"]["status"] == "COMPLETE"
    assert set(lambda_client.calls) == {
        "list_functions",
        "list_aliases",
        "list_versions_by_function",
        "list_function_url_configs",
        "list_event_source_mappings",
        "list_function_event_invoke_configs",
        "get_policy",
    }
    assert iam.calls == ["get_account_authorization_details"]


def test_aws_adapter_projects_sensitive_response_fields_before_snapshot() -> None:
    sentinel = "must-not-survive-projection"

    class SensitiveLambda(_Lambda):
        def list_functions(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {}
            self.calls.append("list_functions")
            return {
                "Functions": [
                    {
                        "FunctionName": FUNCTION,
                        "FunctionArn": _binding().function_arn,
                        "Version": "$LATEST",
                        "CodeSha256": BROKER_CODE_SHA256,
                        "Architectures": ["x86_64"],
                        "ConfigSha256": BROKER_PROVIDER_CONFIGURATION_SHA256,
                        "Handler": (
                            "tooling.platform_authority_identity_context_pep_runtime."
                            "handler"
                        ),
                        "PackageType": "Zip",
                        "Runtime": "python3.12",
                        "Role": f"arn:aws:iam::{ACCOUNT}:role/{sentinel}",
                        "Environment": {"Variables": {"TOKEN": sentinel}},
                        "VpcConfig": {"VpcId": sentinel},
                        "KMSKeyArn": sentinel,
                        "LoggingConfig": {"LogGroup": sentinel},
                    }
                ]
            }

        def list_function_url_configs(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {"FunctionName": FUNCTION}
            self.calls.append("list_function_url_configs")
            items = copy.deepcopy(_snapshot()["lambda"]["function_urls"])
            for item in items:
                item["FunctionUrl"] = f"https://{sentinel}.lambda-url.example/"
                item["Cors"] = {"AllowOrigins": [sentinel]}
            return {"FunctionUrlConfigs": items}

        def list_event_source_mappings(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {"FunctionName": FUNCTION}
            self.calls.append("list_event_source_mappings")
            return {
                "EventSourceMappings": [
                    {
                        "FunctionArn": _binding().alias_arn("retire"),
                        "EventSourceArn": f"arn:aws:sqs:{REGION}:{ACCOUNT}:{sentinel}",
                        "State": "Disabled",
                        "FilterCriteria": {"Filters": [{"Pattern": sentinel}]},
                        "SourceAccessConfigurations": [{"URI": sentinel}],
                    }
                ]
            }

    class SensitiveIam(_Iam):
        def get_account_authorization_details(self, **kwargs: Any) -> dict[str, Any]:
            response = super().get_account_authorization_details(**kwargs)
            response["RoleDetailList"][0]["Tags"] = [{"Key": sentinel, "Value": sentinel}]
            response["RoleDetailList"][0]["Description"] = sentinel
            response["RoleDetailList"][0]["RoleLastUsed"] = {"Region": sentinel}
            for role in response["RoleDetailList"]:
                role["AssumeRolePolicyDocument"] = quote(
                    json.dumps(role["AssumeRolePolicyDocument"]), safe=""
                )
                for policy in role["RolePolicyList"]:
                    policy["PolicyDocument"] = quote(
                        json.dumps(policy["PolicyDocument"]), safe=""
                    )
            return response

    adapter = AwsReadOnlyInventoryAdapter(
        sts=_Sts(),
        ec2=_Ec2(),
        lambda_client=SensitiveLambda(),
        iam=SensitiveIam(),
    )

    snapshot = adapter.collect(
        binding=_binding(),
        scan_id="synthetic-minimized-scan",
        expected_collector_principal_digest=_allowlist()[
            "collector_role_principal_digest"
        ],
    )
    serialized = json.dumps(snapshot, sort_keys=True)

    assert sentinel not in serialized
    assert "Environment" not in serialized
    assert snapshot["lambda"]["functions"][0][
        "PublishedConfigurationDigest"
    ].startswith("sha256:")
    assert all(
        "FunctionUrl" not in item for item in snapshot["lambda"]["function_urls"]
    )
    assert "FilterCriteria" not in serialized
    assert "SourceAccessConfigurations" not in serialized
    assert "RoleLastUsed" not in serialized
    assert isinstance(
        snapshot["iam"]["roles"][0]["AssumeRolePolicyDocument"], Mapping
    )


def test_aws_adapter_rejects_unknown_alias_routing_semantics() -> None:
    class FutureRoutingLambda(_Lambda):
        def list_aliases(self, **kwargs: Any) -> dict[str, Any]:
            response = super().list_aliases(**kwargs)
            response["Aliases"][0]["RoutingConfig"] = {
                "AdditionalVersionWeights": {},
                "FutureRoutingMode": "UNREVIEWED",
            }
            return response

    adapter = AwsReadOnlyInventoryAdapter(
        sts=_Sts(), ec2=_Ec2(), lambda_client=FutureRoutingLambda(), iam=_Iam()
    )

    snapshot = adapter.collect(
        binding=_binding(),
        scan_id="synthetic-future-routing",
        expected_collector_principal_digest=_allowlist()[
            "collector_role_principal_digest"
        ],
    )

    assert snapshot["coverage"]["lambda_aliases"]["status"] == "AMBIGUOUS"
    assert snapshot["lambda"]["aliases"] == []


def test_aws_adapter_lists_functions_in_every_enabled_region() -> None:
    class TwoRegionEc2(_Ec2):
        def describe_regions(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {"AllRegions": True}
            return {
                "Regions": [
                    {"RegionName": REGION, "OptInStatus": "opt-in-not-required"},
                    {"RegionName": "us-west-2", "OptInStatus": "opted-in"},
                ]
            }

    class OtherRegionLambda:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def list_functions(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs == {}
            self.calls.append("list_functions")
            return {"Functions": []}

    target = _Lambda()
    other = OtherRegionLambda()
    requested_regions: list[str] = []

    def factory(region: str) -> OtherRegionLambda:
        requested_regions.append(region)
        assert region == "us-west-2"
        return other

    adapter = AwsReadOnlyInventoryAdapter(
        sts=_Sts(),
        ec2=TwoRegionEc2(),
        lambda_client=target,
        iam=_Iam(),
        lambda_client_factory=factory,
    )

    snapshot = adapter.collect(
        binding=_binding(),
        scan_id="synthetic-multi-region",
        expected_collector_principal_digest=_allowlist()[
            "collector_role_principal_digest"
        ],
    )

    assert snapshot["enabled_regions"] == ["us-east-1", "us-west-2"]
    assert snapshot["scanned_regions"] == ["us-east-1", "us-west-2"]
    assert snapshot["coverage"]["lambda_functions"]["status"] == "COMPLETE"
    assert requested_regions == ["us-west-2"]
    assert other.calls == ["list_functions"]


def test_cli_and_adapter_contain_no_aws_mutation_or_lambda_invocation_call() -> None:
    adapter_source = inspect.getsource(AwsReadOnlyInventoryAdapter)
    script_source = SCRIPT.read_text(encoding="utf-8")
    for forbidden_call in (
        ".invoke(",
        ".invoke_async(",
        ".add_permission(",
        ".remove_permission(",
        ".create_function_url_config(",
        ".update_function_configuration(",
        ".put_role_policy(",
        ".attach_role_policy(",
        ".create_change_set(",
        ".execute_change_set(",
    ):
        assert forbidden_call not in adapter_source
        assert forbidden_call not in script_source
