"""Offline contract tests for the guarded GUG-390 executor."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import stat
from typing import Any, Mapping
from urllib.parse import quote

from jsonschema import Draft202012Validator
import pytest

from tests.test_deployment import (
    test_gug365_retirement_entrypoint_service_role_materializer as materializer_test_support,
)
from tests.test_deployment import (
    test_gug390_gug365_live_provider as live_provider_test_support,
)
from tooling import platform_authority_gug365_phase_execution_ledger as ledger
from tooling import platform_authority_gug365_live_provider as live_provider
from tooling import platform_authority_gug390_live_executor as executor


ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = (
    ROOT
    / "fixtures/valid/platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
)
SCHEMA_PATH = ROOT / "schemas/platform-authority-gug390-live-run.v1.schema.json"
NOW = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)
BEFORE_STATE = executor.canonical_digest({"state": "ALL_TARGETS_ABSENT"})
CALLER = executor.canonical_digest({"caller": "GUG390Synthetic"})
SESSION = executor.canonical_digest({"session": "GUG390Synthetic"})
HOST = executor.canonical_digest({"host": "GUG390Synthetic"})
NONCE = executor.canonical_digest({"nonce": "GUG390Synthetic"})
OWNER_CHECKPOINT = executor.canonical_digest({"owner": "GUG390Synthetic"})
LIVE_REQUEST = executor.canonical_digest({"request": "GUG390Synthetic"})
RECONCILE_OWNER_CHECKPOINT = executor.canonical_digest(
    {"owner": "GUG390Reconcile"}
)
RECONCILE_LIVE_REQUEST = executor.canonical_digest(
    {"request": "GUG390Reconcile"}
)


def _plan() -> dict[str, Any]:
    return json.loads(PLAN_PATH.read_text(encoding="utf-8"))


@dataclass
class InventoryProvider:
    account_id: str
    capture_index: int
    state_marker: str = "ABSENT"
    target_outcome: str = "ABSENT"
    mode: str = "SYNTHETIC"
    reads: list[dict[str, Any]] = field(default_factory=list)

    def identity(self) -> Mapping[str, Any]:
        return {
            "account_id": self.account_id,
            "region": executor.REGION,
            "caller_arn_digest": CALLER,
            "session_identifier_digest": SESSION,
            "source": "INJECTED_NON_LIVE",
            "chain_depth": 0,
            "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        }

    def read_operation(self, operation: Mapping[str, Any]) -> executor.ReadResult:
        detached = json.loads(executor.canonical_json(operation))
        self.reads.append(detached)
        assert detached["attempt_limit"] == 1
        assert detached["retry_permitted"] is False
        outcome = (
            "PRESENT"
            if detached["resource_scope"] == "PREREQUISITE"
            else self.target_outcome
        )
        return executor.ReadResult(
            outcome=outcome,
            result_digest=executor.canonical_digest(
                {
                    "request_digest": detached["request_digest"],
                    "outcome": outcome,
                    "state": self.state_marker,
                }
            ),
            private_result={"outcome": outcome, "state": self.state_marker},
            page_count=1,
        )

    def transcript_summary(self) -> Mapping[str, Any]:
        calls = len(self.reads) + 1
        return {
            "transcript_digest": executor.canonical_digest(
                {"capture_index": self.capture_index, "calls": calls}
            ),
            "call_count": calls,
            "write_call_count": 0,
            "live_provider_evidence": False,
        }


@dataclass(frozen=True)
class RealLikeReadResult:
    outcome: str
    response_digest: str
    operation_calls: int
    response: Mapping[str, Any]


@dataclass
class RealLikeLogsProvider:
    log_groups: list[Mapping[str, Any]]
    calls: list[Mapping[str, Any]] = field(default_factory=list)

    def read_operation(self, operation: Mapping[str, Any]) -> RealLikeReadResult:
        self.calls.append(copy.deepcopy(operation))
        response = {"logGroups": copy.deepcopy(self.log_groups)}
        return RealLikeReadResult(
            outcome="SUCCEEDED",
            response_digest=executor.canonical_digest(response),
            operation_calls=1,
            response=response,
        )


def _capture(
    plan: Mapping[str, Any],
    index: int,
    marker: str = "ABSENT",
    *,
    target_outcome: str = "ABSENT",
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    provider = InventoryProvider(
        account_id=str(plan["target"]["authority_account_id"]),
        capture_index=index,
        state_marker=marker,
        target_outcome=target_outcome,
    )
    return executor.capture_inventory_once(
        plan=plan,
        provider=provider,
        expected_plan_digest=str(plan["plan_digest"]),
        expected_account_id=str(plan["target"]["authority_account_id"]),
        expected_region=executor.REGION,
        capture_index=index,
        captured_at=captured_at or NOW + timedelta(minutes=index),
        owner_checkpoint_digest=OWNER_CHECKPOINT,
        live_request_digest=LIVE_REQUEST,
    )


TABLE_KMS_ARN = (
    "arn:aws:kms:us-east-1:042360977644:key/"
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)


def _role_contracts(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [plan["service_role"], *plan["child_roles"]]


def _function_contract(
    plan: Mapping[str, Any], operation: executor.InventoryOperation
) -> Mapping[str, Any]:
    for key in ("broker_function", "ledger_factory_function"):
        contract = plan[key]
        if operation.request.get("FunctionName") == contract["function_name"]:
            return contract
        if operation.request.get("Resource") == contract["arn"]:
            return contract
    raise AssertionError(operation)


def _lambda_configuration(
    contract: Mapping[str, Any], *, version: str | None = None
) -> dict[str, Any]:
    value = copy.deepcopy(contract["normalized_configuration"])
    if version is not None:
        value["Version"] = version
        value["FunctionArn"] = contract["arn"] + (
            "" if version == "$LATEST" else f":{version}"
        )
    variables = value["Environment"]["Variables"]
    value["Environment"]["Variables"] = {
        "redacted": True,
        "value_digest": executor.canonical_digest(variables),
    }
    return value


def _semantic_iam_response(
    plan: Mapping[str, Any], operation: executor.InventoryOperation
) -> dict[str, Any]:
    request = operation.request
    action = operation.api_action
    if "PolicyArn" in request:
        boundary = next(
            item for item in plan["boundaries"] if item["arn"] == request["PolicyArn"]
        )
        roles = _role_contracts(plan)
        if action == "GetPolicy":
            return {
                "Policy": {
                    "Arn": boundary["arn"],
                    "PolicyName": boundary["policy_name"],
                    "Path": boundary["path"],
                    "DefaultVersionId": "v1",
                    "AttachmentCount": sum(
                        boundary["arn"] in role["attached_policy_arns"]
                        for role in roles
                    ),
                    "PermissionsBoundaryUsageCount": sum(
                        boundary["arn"] == role["permissions_boundary_arn"]
                        for role in roles
                    ),
                    "IsAttachable": True,
                    "Description": boundary["description"],
                }
            }
        if action == "GetPolicyVersion":
            return {
                "PolicyVersion": {
                    "Document": boundary["document"],
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                }
            }
        if action == "ListPolicyVersions":
            return {"Versions": [{"VersionId": "v1", "IsDefaultVersion": True}]}
        if action == "ListEntitiesForPolicy":
            usage = request["PolicyUsageFilter"]
            selected = [
                role
                for role in roles
                if (
                    boundary["arn"] in role["attached_policy_arns"]
                    if usage == "PermissionsPolicy"
                    else boundary["arn"] == role["permissions_boundary_arn"]
                )
            ]
            return {
                "PolicyGroups": [],
                "PolicyUsers": [],
                "PolicyRoles": [
                    {"RoleName": role["role_name"], "RoleId": f"opaque-{index}"}
                    for index, role in enumerate(selected, 1)
                ],
            }
        if action == "ListPolicyTags":
            return {"Tags": copy.deepcopy(boundary["tags"])}
    role = next(
        item for item in _role_contracts(plan) if item["role_name"] == request["RoleName"]
    )
    if action == "GetRole":
        return {
            "Role": {
                "Arn": role["arn"],
                "RoleName": role["role_name"],
                "Path": role["path"],
                "MaxSessionDuration": role["max_session_duration"],
                "AssumeRolePolicyDocument": role["trust_policy"],
                "PermissionsBoundary": {
                    "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                    "PermissionsBoundaryArn": role["permissions_boundary_arn"],
                },
                "Tags": copy.deepcopy(role["tags"]),
            }
        }
    if action == "ListRolePolicies":
        return {"PolicyNames": copy.deepcopy(role["inline_policy_names"])}
    if action == "ListAttachedRolePolicies":
        return {
            "AttachedPolicies": [
                {"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}
                for arn in role["attached_policy_arns"]
            ]
        }
    if action == "ListRoleTags":
        return {"Tags": copy.deepcopy(role["tags"])}
    raise AssertionError(operation)


def _semantic_lambda_response(
    plan: Mapping[str, Any], operation: executor.InventoryOperation
) -> dict[str, Any]:
    action = operation.api_action
    if action == "GetCodeSigningConfig":
        contract = plan["broker_function"]["code_signing_config_contract"]
        return {
            "CodeSigningConfig": {
                "CodeSigningConfigArn": contract["arn"],
                "AllowedPublishers": {
                    "SigningProfileVersionArns": copy.deepcopy(
                        contract["allowed_signing_profile_version_arns"]
                    )
                },
                "CodeSigningPolicies": {
                    "UntrustedArtifactOnDeployment": contract[
                        "untrusted_artifact_on_deployment"
                    ]
                },
            }
        }
    contract = _function_contract(plan, operation)
    if action == "GetFunction":
        signed = contract["signed_code"]
        return {
            "Configuration": _lambda_configuration(contract),
            "Code": {
                "RepositoryType": "S3",
                "ResolvedS3Object": {
                    "Bucket": signed["s3_bucket"],
                    "Key": signed["s3_key"],
                    "Version": signed["s3_object_version"],
                },
            },
            "Tags": copy.deepcopy(contract["tags"]),
        }
    if action == "GetFunctionConfiguration":
        return _lambda_configuration(contract)
    if action == "GetFunctionCodeSigningConfig":
        return {"CodeSigningConfigArn": contract["code_signing_config_arn"]}
    if action == "GetFunctionConcurrency":
        return {
            "ReservedConcurrentExecutions": contract["reserved_concurrent_executions"]
        }
    if action == "GetRuntimeManagementConfig":
        return {
            "FunctionArn": operation.target_arn,
            "UpdateRuntimeOn": contract["runtime_management"]["UpdateRuntimeOn"],
            "RuntimeVersionArn": contract["runtime_management"]["RuntimeVersionArn"],
        }
    if action == "ListTags":
        return {"Tags": copy.deepcopy(contract["tags"])}
    if action == "ListVersionsByFunction":
        return {
            "Versions": [
                _lambda_configuration(contract, version=version)
                for version in contract["expected_versions"]
            ]
        }
    if action == "ListAliases":
        return {"Aliases": copy.deepcopy(contract["expected_aliases"])}
    if action == "ListFunctionUrlConfigs":
        return {"FunctionUrlConfigs": copy.deepcopy(contract["expected_function_urls"])}
    raise AssertionError(operation)


def _semantic_response(
    plan: Mapping[str, Any], operation: executor.InventoryOperation
) -> dict[str, Any]:
    action = operation.api_action
    if operation.service == "iam":
        return _semantic_iam_response(plan, operation)
    if operation.service == "lambda":
        return _semantic_lambda_response(plan, operation)
    if operation.service == "logs":
        contract = plan["ledger_factory_log_group"]
        if action == "DescribeLogGroups":
            return {
                "logGroups": [
                    {
                        "logGroupName": contract["log_group_name"],
                        "arn": contract["arn"] + ":*",
                        "logGroupArn": contract["arn"],
                        "retentionInDays": contract["retention_in_days"],
                        "deletionProtectionEnabled": contract[
                            "deletion_protection_enabled"
                        ],
                        "kmsKeyId": contract["kms_key_id"],
                        "storedBytes": contract["stored_bytes"],
                        "logGroupClass": contract["log_group_class"],
                        "inheritedProperties": copy.deepcopy(
                            contract["inherited_properties"]
                        ),
                    }
                ]
            }
        return {"tags": copy.deepcopy(contract["tags"])}
    if operation.service == "dynamodb":
        contract = plan["ledger_table"]
        if action == "DescribeTable":
            return {
                "Table": {
                    "TableName": contract["table_name"],
                    "TableArn": contract["arn"],
                    "TableStatus": "ACTIVE",
                    "BillingModeSummary": {"BillingMode": contract["billing_mode"]},
                    "AttributeDefinitions": copy.deepcopy(
                        contract["attribute_definitions"]
                    ),
                    "KeySchema": copy.deepcopy(contract["key_schema"]),
                    "DeletionProtectionEnabled": contract[
                        "deletion_protection_enabled"
                    ],
                    "SSEDescription": {
                        "Status": "ENABLED",
                        "SSEType": contract["sse_specification"]["SSEType"],
                        "KMSMasterKeyArn": TABLE_KMS_ARN,
                    },
                    "TableClassSummary": {"TableClass": contract["table_class"]},
                    "GlobalSecondaryIndexes": [],
                    "LocalSecondaryIndexes": [],
                    "Replicas": [],
                    "ItemCount": 0,
                }
            }
        if action == "DescribeContinuousBackups":
            return {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED",
                        "RecoveryPeriodInDays": contract["point_in_time_recovery"][
                            "RecoveryPeriodInDays"
                        ],
                    },
                }
            }
        if action == "DescribeTimeToLive":
            return {"TimeToLiveDescription": copy.deepcopy(contract["time_to_live"])}
        if action == "GetResourcePolicy":
            return {"Policy": json.dumps(contract["resource_policy"])}
        if action == "ListTagsOfResource":
            return {"Tags": copy.deepcopy(contract["tags"])}
        if action == "Scan":
            return {"Count": 0, "ScannedCount": 0}
    if operation.service == "s3":
        contract = executor._artifact_contract(plan, operation)  # noqa: SLF001
        return {
            "VersionId": contract["s3_object_version"],
            "ContentLength": contract["archive_size_bytes"],
            "ChecksumSHA256": contract["lambda_code_sha256"],
            "ChecksumType": "FULL_OBJECT",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": contract["sse_kms_key_arn"],
            "Body": {
                "byte_length": contract["archive_size_bytes"],
                "byte_digest": "sha256:" + contract["archive_sha256"],
            },
        }
    if operation.service == "kms":
        key_id = operation.request["KeyId"]
        table_alias = plan["ledger_table"]["sse_specification"]["KMSMasterKeyId"]
        if key_id == table_alias:
            metadata = copy.deepcopy(
                plan["ledger_table"]["kms_key_contract"]["metadata_projection"]
            )
            metadata.pop("arn_pattern")
            metadata.update(
                {"Arn": TABLE_KMS_ARN, "KeyId": TABLE_KMS_ARN.rsplit("/", 1)[-1]}
            )
        else:
            metadata = {
                "AWSAccountId": plan["target"]["authority_account_id"],
                "KeyId": key_id.rsplit("/", 1)[-1],
                "Arn": key_id,
                "Enabled": True,
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeyState": "Enabled",
                "Origin": "AWS_KMS",
                "KeyManager": "CUSTOMER",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "MultiRegion": False,
                "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
            }
        return {"KeyMetadata": metadata}
    raise AssertionError((operation.service, action))


def _reseal_snapshot(snapshot: dict[str, Any]) -> None:
    facts = [
        {
            key: operation[key]
            for key in (
                "sequence",
                "service",
                "api_action",
                "target_digest",
                "request_digest",
                "outcome",
                "result_digest",
                "page_count",
                "resource_scope",
            )
        }
        for operation in snapshot["operations"]
    ]
    target_presence: dict[str, str] = {}
    for operation in snapshot["operations"]:
        if (
            operation["resource_scope"] == "TARGET"
            and (operation["service"], operation["api_action"])
            in executor._EXISTENCE_ANCHORS  # noqa: SLF001
        ):
            target_presence[operation["target_digest"]] = operation["outcome"]
    prerequisites = [
        {
            key: operation[key]
            for key in (
                "sequence",
                "service",
                "api_action",
                "target_digest",
                "request_digest",
                "outcome",
                "result_digest",
            )
        }
        for operation in snapshot["operations"]
        if operation["resource_scope"] == "PREREQUISITE"
    ]
    snapshot["facts_digest"] = executor.canonical_digest(facts)
    snapshot["target_presence_digest"] = executor.canonical_digest(target_presence)
    snapshot["all_targets_absent"] = set(target_presence.values()) == {"ABSENT"}
    snapshot["all_targets_present"] = set(target_presence.values()) == {"PRESENT"}
    snapshot["prerequisite_facts_digest"] = executor.canonical_digest(prerequisites)
    snapshot["all_prerequisites_present"] = all(
        item["outcome"] == "PRESENT" for item in prerequisites
    )
    snapshot["snapshot_digest"] = executor.canonical_digest(
        {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    )


def _live_snapshot(
    plan: Mapping[str, Any], index: int, *, targets_present: bool
) -> dict[str, Any]:
    snapshot = _capture(plan, index)
    expected_operations = executor.inventory_operations(plan)
    snapshot["provider_mode"] = "LIVE"
    snapshot["provider_backed"] = True
    snapshot["identity"]["source"] = "DIRECT_SSO"
    snapshot["identity_digest"] = executor.canonical_digest(snapshot["identity"])
    for expected, actual in zip(
        expected_operations, snapshot["operations"], strict=True
    ):
        absent = (
            expected.resource_scope == "TARGET" and not targets_present
        ) or (expected.service, expected.api_action) == ("lambda", "GetPolicy")
        operation_digest = live_provider.planned_call_from_record(
            "READBACK", expected.as_mapping()
        ).operation_digest
        if absent and (expected.service, expected.api_action) == (
            "logs",
            "DescribeLogGroups",
        ):
            private_response = {"logGroups": []}
            actual["outcome"] = "ABSENT"
            actual["result_digest"] = executor.canonical_digest(private_response)
            error = None
            provider_outcome = "SUCCEEDED"
        elif absent:
            error = (
                "NoSuchEntity"
                if expected.service == "iam"
                else "ResourceNotFoundException"
            )
            actual["outcome"] = "ABSENT"
            actual["result_digest"] = executor.canonical_digest(
                {
                    "absence": error,
                    "request_digest": expected.request_digest,
                    "target_digest": executor.canonical_digest(expected.target_arn),
                }
            )
            private_response = (
                {"partial_facts": {}}
                if expected.complete_pagination_required
                else {}
            )
            provider_outcome = "FAILED"
        else:
            private_response = _semantic_response(plan, expected)
            actual["outcome"] = "PRESENT"
            actual["result_digest"] = executor.canonical_digest(private_response)
            error = None
            provider_outcome = "SUCCEEDED"
        actual["private_result"] = {
            "outcome": provider_outcome,
            "phase": "READBACK",
            "sequence": expected.sequence,
            "operation_digest": operation_digest,
            "request_digest": expected.request_digest,
            "response_digest": executor.canonical_digest(private_response),
            "operation_calls": actual["page_count"],
            "provider_calls": expected.sequence + 1,
            "reconciliation_required": False,
            "error_code": error,
            "response": private_response,
        }
    _reseal_snapshot(snapshot)
    return snapshot


def _mutate_live_response(
    snapshot: dict[str, Any],
    *,
    service: str,
    action: str,
    path: tuple[Any, ...],
    value: Any,
) -> None:
    operation = next(
        item
        for item in snapshot["operations"]
        if item["service"] == service and item["api_action"] == action
    )
    selected = operation["private_result"]["response"]
    for key in path[:-1]:
        selected = selected[key]
    selected[path[-1]] = value
    digest = executor.canonical_digest(operation["private_result"]["response"])
    operation["private_result"]["response_digest"] = digest
    operation["result_digest"] = digest
    _reseal_snapshot(snapshot)


def test_real_plan_validates_and_inventory_is_closed_to_six_services() -> None:
    plan = _plan()
    normalized = executor.validate_plan(
        plan,
        expected_plan_digest=plan["plan_digest"],
        expected_account_id=plan["target"]["authority_account_id"],
        expected_region=executor.REGION,
    )
    operations = executor.inventory_operations(normalized)
    assert {item.service for item in operations} == {
        "iam",
        "lambda",
        "logs",
        "dynamodb",
        "s3",
        "kms",
    }
    assert len(operations) <= executor.MAX_INVENTORY_OPERATIONS
    assert [item.sequence for item in operations] == list(
        range(1, len(operations) + 1)
    )
    assert all(item.attempt_limit == 1 and not item.retry_permitted for item in operations)
    assert all(
        item.request_digest == executor.canonical_digest(item.request)
        for item in operations
    )
    scans = [
        item
        for item in operations
        if (item.service, item.api_action) == ("dynamodb", "Scan")
    ]
    assert len(scans) == 1
    assert scans[0].request == {
        "TableName": plan["ledger_table"]["table_name"],
        "ConsistentRead": True,
        "Select": "COUNT",
        "Limit": 1,
    }


@pytest.mark.parametrize(
    ("targets_present", "expected_classification"),
    [(False, "ABSENT_READY"), (True, "EXACT_PRESENT_NO_TOUCH")],
)
def test_live_semantic_inventory_matches_the_complete_plan(
    targets_present: bool, expected_classification: str
) -> None:
    plan = _plan()
    first = _live_snapshot(plan, 1, targets_present=targets_present)
    second = _live_snapshot(plan, 2, targets_present=targets_present)
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    assert classification["classification"] == expected_classification
    assert classification["provider_backed"] is True


@pytest.mark.parametrize(
    ("service", "action", "path", "value"),
    [
        ("iam", "GetRole", ("Role", "MaxSessionDuration"), 7200),
        ("iam", "GetRole", ("Role", "Description"), "drifted"),
        ("lambda", "GetFunctionConfiguration", ("CodeSha256",), "forged"),
        ("logs", "DescribeLogGroups", ("logGroups", 0, "retentionInDays"), 1),
        ("dynamodb", "Scan", ("Count",), 1),
        ("s3", "GetObjectVersion", ("Body", "byte_digest"), "sha256:" + "0" * 64),
        ("kms", "DescribeKey", ("KeyMetadata", "KeyState"), "Disabled"),
    ],
)
def test_stable_live_semantic_drift_never_classifies_exact(
    service: str,
    action: str,
    path: tuple[Any, ...],
    value: Any,
) -> None:
    plan = _plan()
    first = _live_snapshot(plan, 1, targets_present=True)
    second = _live_snapshot(plan, 2, targets_present=True)
    for snapshot in (first, second):
        _mutate_live_response(
            snapshot,
            service=service,
            action=action,
            path=path,
            value=value,
        )
    with pytest.raises(executor.Gug390Error, match="LIVE_INVENTORY_SEMANTIC_DRIFT"):
        executor.classify_stable_inventory(
            first,
            second,
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            expected_facts_digest=second["facts_digest"],
            authorized_before_state_digest=BEFORE_STATE,
        )


def test_live_stability_uses_plan_semantics_not_volatile_provider_metadata() -> None:
    plan = _plan()
    first = _live_snapshot(plan, 1, targets_present=True)
    second = _live_snapshot(plan, 2, targets_present=True)
    _mutate_live_response(
        second,
        service="iam",
        action="GetRole",
        path=("Role", "RoleLastUsed"),
        value={"LastUsedDate": "2035-01-02T03:05:00Z"},
    )
    _mutate_live_response(
        second,
        service="logs",
        action="DescribeLogGroups",
        path=("logGroups", 0, "storedBytes"),
        value=4096,
    )
    assert first["facts_digest"] != second["facts_digest"]
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    assert classification["classification"] == "EXACT_PRESENT_NO_TOUCH"


def test_live_semantics_normalize_encoded_policy_and_composite_checksum() -> None:
    plan = _plan()
    first = _live_snapshot(plan, 1, targets_present=True)
    second = _live_snapshot(plan, 2, targets_present=True)
    encoded = quote(json.dumps(plan["boundaries"][0]["document"]))
    for snapshot in (first, second):
        _mutate_live_response(
            snapshot,
            service="iam",
            action="GetPolicyVersion",
            path=("PolicyVersion", "Document"),
            value=encoded,
        )
        _mutate_live_response(
            snapshot,
            service="s3",
            action="GetObjectVersion",
            path=("ChecksumType",),
            value="COMPOSITE",
        )
        _mutate_live_response(
            snapshot,
            service="s3",
            action="GetObjectVersion",
            path=("ChecksumSHA256",),
            value="composite-checksum-2",
        )
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    assert classification["classification"] == "EXACT_PRESENT_NO_TOUCH"


@pytest.mark.parametrize("present", [False, True])
def test_real_like_describe_log_groups_classifies_exact_presence(
    present: bool,
) -> None:
    plan = _plan()
    normalized = executor.validate_plan(
        plan,
        expected_plan_digest=plan["plan_digest"],
        expected_account_id=plan["target"]["authority_account_id"],
        expected_region=executor.REGION,
    )
    operation = next(
        item
        for item in executor.inventory_operations(normalized)
        if (item.service, item.api_action) == ("logs", "DescribeLogGroups")
    )
    exact_name = operation.request["logGroupNamePrefix"]
    groups = [{"logGroupName": exact_name}] if present else []
    provider = RealLikeLogsProvider(groups)
    result = executor._read_from_provider(  # noqa: SLF001
        provider, operation.as_mapping()
    )
    assert len(provider.calls) == 1
    assert result.outcome == ("PRESENT" if present else "ABSENT")
    assert result.page_count == 1


def test_two_synthetic_snapshots_are_stable_and_absent_ready() -> None:
    plan = _plan()
    first, second = _capture(plan, 1), _capture(plan, 2)
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    assert first["snapshot_digest"] != second["snapshot_digest"]
    assert first["facts_digest"] == second["facts_digest"]
    assert classification["classification"] == "ABSENT_READY"
    assert classification["stable"] is True
    assert classification["provider_backed"] is False
    assert classification["writes_permitted_by_state"] is True
    assert classification["writes_authorized"] is False


def test_inventory_or_plan_drift_fails_closed() -> None:
    plan = _plan()
    drifted_plan = copy.deepcopy(plan)
    drifted_plan["authorization_phases"][0]["operations"][0]["request"] = {
        "forged": True
    }
    with pytest.raises(executor.Gug390Error, match="PLAN_DIGEST_MISMATCH"):
        executor.validate_plan(
            drifted_plan,
            expected_plan_digest=plan["plan_digest"],
            expected_account_id=plan["target"]["authority_account_id"],
            expected_region=executor.REGION,
        )
    with pytest.raises(executor.Gug390Error, match="INVENTORY_NOT_STABLE"):
        executor.classify_stable_inventory(
            _capture(plan, 1),
            _capture(plan, 2, marker="DRIFTED"),
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
            expected_facts_digest=executor.canonical_digest(
                {"facts": "independently-authorized"}
            ),
            authorized_before_state_digest=BEFORE_STATE,
        )


def test_public_inventory_manifest_validates_the_draft_2020_schema() -> None:
    plan = _plan()
    first, second = _capture(plan, 1), _capture(plan, 2)
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    manifest = executor.public_inventory_manifest(
        classification=classification,
        plan=plan,
        first_snapshot=first,
        second_snapshot=second,
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
        source_commit_sha="1" * 40,
        source_tree_sha="2" * 40,
        plan_digest=plan["plan_digest"],
        phase="POLICY_FACTORY",
        created_at=NOW,
        owner_checkpoint_digest=OWNER_CHECKPOINT,
        live_request_digest=LIVE_REQUEST,
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)
    public = json.dumps(manifest, sort_keys=True)
    assert plan["target"]["authority_account_id"] not in public
    assert manifest["classification"] == "SYNTHETIC_VALIDATED"
    assert manifest["live_provider_evidence"] is False
    assert manifest["aws_calls"] == manifest["aws_mutations"] == 0


def test_public_inventory_rejects_sts_only_forged_live_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    first, second = _capture(plan, 1), _capture(plan, 2)
    classification = executor.classify_stable_inventory(
        first,
        second,
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_facts_digest=second["facts_digest"],
        authorized_before_state_digest=BEFORE_STATE,
    )
    providers: list[live_provider.LiveProvider] = []
    states: list[live_provider_test_support.FakeState] = []
    for _ in range(2):
        provider, state = _concrete_reconciliation_provider(monkeypatch)
        providers.append(provider)
        states.append(state)
    transcripts = [executor._provider_transcript(item) for item in providers]  # noqa: SLF001
    forged = {
        **classification,
        "provider_backed": True,
        "transcript_digests": [
            item["transcript_digest"] for item in transcripts
        ],
        "provider_calls": sum(item["call_count"] for item in transcripts),
    }

    with pytest.raises(
        executor.Gug390Error, match="INVENTORY_CLASSIFICATION_INVALID"
    ):
        executor.public_inventory_manifest(
            classification=forged,
            plan=plan,
            first_snapshot=first,
            second_snapshot=second,
            expected_facts_digest=second["facts_digest"],
            authorized_before_state_digest=BEFORE_STATE,
            source_commit_sha="1" * 40,
            source_tree_sha="2" * 40,
            plan_digest=plan["plan_digest"],
            phase="POLICY_FACTORY",
            created_at=NOW,
            owner_checkpoint_digest=OWNER_CHECKPOINT,
            live_request_digest=LIVE_REQUEST,
            live_providers=providers,
        )
    assert all(state.calls == [("sts", "get_caller_identity", {})] for state in states)


def _authority_evidence(
    plan: Mapping[str, Any],
    *,
    caller_digest: str = CALLER,
    session_digest: str = SESSION,
) -> dict[str, Any]:
    requirement = plan["authorization_phases"][0][
        "executor_effective_authority_requirement"
    ]
    policy_digest = requirement["required_policy_document_digest"]
    evidence: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_executor_authority_evidence.v1",
        "phase": "POLICY_FACTORY",
        "caller_account_id": plan["target"]["authority_account_id"],
        "region": executor.REGION,
        "caller_arn_digest": caller_digest,
        "session_identifier_digest": session_digest,
        "session_issued_at": (NOW - timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
        "session_expires_at": (NOW + timedelta(seconds=840)).isoformat().replace("+00:00", "Z"),
        "evidence_collected_at": (NOW - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        "session_lifetime_seconds": 900,
        "session_remaining_seconds": 840,
        "session_chain_depth": 0,
        "evidence_collected_after_sts": True,
        "effective_policy_inventory_complete": True,
        "sole_identity_policy_document_digest": policy_digest,
        "additional_inline_policy_count": 0,
        "additional_attached_policy_count": 0,
        "group_policy_count": 0,
        "maximum_authority_source": "DEDICATED_ROLE_PERMISSIONS_BOUNDARY",
        "maximum_authority_document_digest": policy_digest,
        "raw_caller_arn_persisted": False,
        "evidence_digest": "",
    }
    evidence["evidence_digest"] = executor.canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    return evidence


def _prepared_store(
    tmp_path: Path,
    *,
    caller_digest: str = CALLER,
    session_digest: str = SESSION,
) -> tuple[
    ledger.DurablePhaseLedgerStore,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    raw_plan = _plan()
    plan = executor.validate_plan(
        raw_plan,
        expected_plan_digest=raw_plan["plan_digest"],
        expected_account_id=raw_plan["target"]["authority_account_id"],
        expected_region=executor.REGION,
    )
    evidence = _authority_evidence(
        plan,
        caller_digest=caller_digest,
        session_digest=session_digest,
    )
    prepared = ledger.build_prepared_ledger(
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        phase="POLICY_FACTORY",
        profile_class="GUG390PolicyFactory",
        caller_arn_digest=caller_digest,
        executor_authority_evidence_digest=evidence["evidence_digest"],
        executor_authority_evidence=evidence,
        authority_evaluation_at=NOW,
        authority_session_identifier_digest=session_digest,
        authority_session_issued_at=NOW - timedelta(seconds=60),
        authority_session_expires_at=NOW + timedelta(seconds=840),
        authority_evidence_collected_at=NOW - timedelta(seconds=30),
        host_digest=HOST,
        predecessor_phase=None,
        predecessor_terminal_receipt_digest=None,
        predecessor_ledger_digest=None,
        before_state_digest=BEFORE_STATE,
        required_predecessor_checkpoint_digest=BEFORE_STATE,
        expected_initial_bundle_absence_digest=BEFORE_STATE,
        predecessor_record=None,
        expected_predecessor_binding=None,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    private_root = tmp_path / "durable-ledger"
    private_root.mkdir(mode=0o700)
    private_root.chmod(0o700)
    store = ledger.DurablePhaseLedgerStore(private_root)
    store.create(prepared)
    authorization = {
        field: (
            NONCE if field == "claim_nonce_digest" else copy.deepcopy(prepared[field])
        )
        for field in ledger._EXECUTION_AUTHORIZATION_FIELDS  # noqa: SLF001
    }
    return store, plan, prepared, evidence | {"authorization": authorization}


@dataclass
class PhaseProvider:
    account_id: str
    ambiguous_on_first_write: bool = False
    raise_on_first_operation: bool = False
    mode: str = "SYNTHETIC"
    caller_digest: str = CALLER
    session_digest: str = SESSION
    calls: list[dict[str, Any]] = field(default_factory=list)

    def identity(self) -> Mapping[str, Any]:
        return {
            "account_id": self.account_id,
            "region": executor.REGION,
            "caller_arn_digest": self.caller_digest,
            "session_identifier_digest": self.session_digest,
            "source": "INJECTED_NON_LIVE",
            "chain_depth": 0,
            "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        }

    def invoke_operation(self, operation: Mapping[str, Any]) -> ledger.OperationResult:
        detached = json.loads(executor.canonical_json(operation))
        self.calls.append(detached)
        assert detached.get("attempt_limit", 1) == 1
        assert detached.get("retry_permitted", False) is False
        if self.raise_on_first_operation and len(self.calls) == 1:
            raise RuntimeError("synthetic provider boundary failure")
        if self.ambiguous_on_first_write and detached["api_action"] == "CreatePolicy":
            return ledger.OperationResult("AMBIGUOUS", None)
        return ledger.OperationResult(
            "SUCCEEDED",
            executor.canonical_digest(
                {"sequence": detached["sequence"], "outcome": "SUCCEEDED"}
            ),
        )

    def transcript_summary(self) -> Mapping[str, Any]:
        writes = sum(item["api_action"] == "CreatePolicy" for item in self.calls)
        return {
            "transcript_digest": executor.canonical_digest(self.calls),
            "call_count": len(self.calls) + 1,
            "write_call_count": writes,
            "live_provider_evidence": False,
        }


def _execute_arguments(
    store: ledger.DurablePhaseLedgerStore,
    plan: Mapping[str, Any],
    prepared: Mapping[str, Any],
    evidence: Mapping[str, Any],
    provider: PhaseProvider,
) -> dict[str, Any]:
    return {
        "store": store,
        "plan": plan,
        "expected_plan_digest": plan["plan_digest"],
        "ledger_id": prepared["ledger_id"],
        "execution_authorization": evidence["authorization"],
        "executor_authority_evidence": {
            key: value for key, value in evidence.items() if key != "authorization"
        },
        "authority_evaluation_at": NOW,
        "expected_initial_bundle_absence_digest": BEFORE_STATE,
        "predecessor_record": None,
        "expected_predecessor_binding": None,
        "provider": provider,
        "clock": lambda: NOW + timedelta(seconds=2),
        "inventory_classification": {
            "classification": "ABSENT_READY",
            "stable": True,
            "provider_backed": False,
            "authorized_before_state_digest": BEFORE_STATE,
            "owner_checkpoint_digest": OWNER_CHECKPOINT,
            "live_request_digest": LIVE_REQUEST,
        },
        "claim_nonce_digest": NONCE,
        "owner_checkpoint_digest": OWNER_CHECKPOINT,
        "live_request_digest": LIVE_REQUEST,
    }


def test_execute_one_phase_requires_explicit_synthetic_gate_and_persists_once(
    tmp_path: Path,
) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, evidence, provider)
    with pytest.raises(
        executor.Gug390Error, match="LIVE_PROVIDER_REQUIRED"
    ):
        executor.execute_one_phase(**arguments)
    assert provider.calls == []
    result = executor.execute_one_phase(**arguments, require_live_provider=False)
    expected = plan["authorization_phases"][0]["operations"]
    assert [item["sequence"] for item in provider.calls] == list(
        range(1, len(expected) + 1)
    )
    assert result["status"] == "CONSUMED"
    assert result["classification"] == "PHASE_CONSUMED"
    assert result["retry_permitted"] is False
    assert store.read(prepared["ledger_id"])["status"] == "CONSUMED"


def _live_execute_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[
    ledger.DurablePhaseLedgerStore,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    live_provider.LiveProvider,
    live_provider_test_support.FakeState,
]:
    provider, state = _concrete_reconciliation_provider(monkeypatch)
    receipt = provider.identity_receipt
    store, plan, prepared, authority = _prepared_store(
        tmp_path,
        caller_digest=receipt.principal_digest,
        session_digest=receipt.session_digest,
    )
    mutation_record = plan["authorization_phases"][0]["operations"][1]
    mutation = live_provider.planned_call_from_record(
        "POLICY_FACTORY", mutation_record, plan=plan
    )
    live_provider_test_support._configure_positive_mutation(  # noqa: SLF001
        state, mutation, plan
    )
    return store, plan, prepared, authority, provider, state


def test_live_provider_payloads_are_private_durable_and_publicly_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store, plan, prepared, authority, provider, _state = _live_execute_context(
        monkeypatch, tmp_path
    )
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    arguments["inventory_classification"] = {
        **arguments["inventory_classification"],
        "provider_backed": True,
    }

    private_run = executor.execute_one_phase(**arguments)
    record = store.read(str(prepared["ledger_id"]))
    mutation = record["operation_outcomes"][1]["durable_provider_evidence"]
    name = mutation["private_provider_evidence_file"]
    path = store.root / name
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    private = executor._read_private_custody_record(  # noqa: SLF001
        store.root, name
    )
    assert private is not None
    assert private["evidence_digest"] == mutation[
        "private_provider_evidence_digest"
    ]
    response = private["provider_private_record"]["response"]
    assert "mutation_response" in response
    assert response["immediate_readbacks"]

    public = executor.public_phase_manifest(
        private_run=private_run,
        ledger_record=record,
        plan=plan,
        expected_plan_digest=str(plan["plan_digest"]),
        source_commit_sha="1" * 40,
        source_tree_sha="2" * 40,
        plan_digest=str(plan["plan_digest"]),
        created_at=NOW + timedelta(seconds=3),
        private_evidence_root=store.root,
    )
    public_json = executor.canonical_json(public)
    assert "mutation_response" not in public_json
    assert "immediate_readbacks" not in public_json
    assert "private_provider" not in public_json


def test_private_evidence_bound_covers_provider_response_and_readback_limits() -> None:
    assert executor._PROVIDER_MAX_RESPONSE_BYTES == (  # noqa: SLF001
        live_provider.MAX_RESPONSE_BYTES
    )
    assert executor._MAX_PRIVATE_EVIDENCE_BYTES >= (  # noqa: SLF001
        2 * 4 * live_provider.MAX_RESPONSE_BYTES
        + live_provider.MAX_RESPONSE_BYTES
    )


def test_terminal_recovery_rejects_tampered_private_provider_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store, plan, prepared, authority, provider, _state = _live_execute_context(
        monkeypatch, tmp_path
    )
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    arguments["inventory_classification"] = {
        **arguments["inventory_classification"],
        "provider_backed": True,
    }
    executor.execute_one_phase(**arguments)
    record = store.read(str(prepared["ledger_id"]))
    name = record["operation_outcomes"][1]["durable_provider_evidence"][
        "private_provider_evidence_file"
    ]
    with (store.root / name).open("ab") as stream:
        stream.write(b"\n")

    with pytest.raises(
        executor.Gug390Error, match="PRIVATE_EVIDENCE_NONCANONICAL"
    ):
        executor.execute_one_phase(
            **{**arguments, "provider": None},
        )


def test_execute_one_phase_rejects_concrete_live_provider_in_synthetic_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    provider, state = _concrete_reconciliation_provider(monkeypatch)
    receipt = provider.identity_receipt
    store, plan, prepared, evidence = _prepared_store(
        tmp_path,
        caller_digest=receipt.principal_digest,
        session_digest=receipt.session_digest,
    )

    with pytest.raises(
        executor.Gug390Error, match="SYNTHETIC_PROVIDER_REQUIRED"
    ):
        executor.execute_one_phase(
            **_execute_arguments(store, plan, prepared, evidence, provider),
            require_live_provider=False,
        )

    assert store.read(prepared["ledger_id"])["status"] == "PREPARED"
    assert state.calls == [("sts", "get_caller_identity", {})]
    assert provider.transcript_summary().provider_mutation_calls == 0


def test_inventory_and_execute_requests_use_distinct_valid_contexts(
    tmp_path: Path,
) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, evidence, provider)
    phase_owner = executor.canonical_digest({"owner": "execute-phase-B"})
    phase_request = executor.canonical_digest({"request": "execute-phase-B"})
    arguments["owner_checkpoint_digest"] = phase_owner
    arguments["live_request_digest"] = phase_request

    private = executor.execute_one_phase(
        **arguments, require_live_provider=False
    )

    assert private["owner_checkpoint_digest"] == phase_owner
    assert private["live_request_digest"] == phase_request
    assert arguments["inventory_classification"]["owner_checkpoint_digest"] == (
        OWNER_CHECKPOINT
    )
    assert arguments["inventory_classification"]["live_request_digest"] == (
        LIVE_REQUEST
    )


def test_ambiguous_write_is_reconcile_only_and_never_retried(tmp_path: Path) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    provider = PhaseProvider(
        plan["target"]["authority_account_id"], ambiguous_on_first_write=True
    )
    arguments = _execute_arguments(store, plan, prepared, evidence, provider)
    result = executor.execute_one_phase(**arguments, require_live_provider=False)
    assert [item["sequence"] for item in provider.calls] == [1, 2]
    assert sum(item["api_action"] == "CreatePolicy" for item in provider.calls) == 1
    assert result["status"] == "AMBIGUOUS"
    assert result["classification"] == "UNCERTAIN_RECONCILE_ONLY"
    assert result["retry_permitted"] is False
    before_retry = copy.deepcopy(provider.calls)
    recovered = executor.execute_one_phase(
        **{**arguments, "provider": None}, require_live_provider=False
    )
    assert recovered == result
    assert provider.calls == before_retry
    assert store.read(prepared["ledger_id"])["status"] == "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class _CrashAfterFirstOutcomeStore(ledger.DurablePhaseLedgerStore):
    crash_armed: list[bool] = field(default_factory=lambda: [True])

    def _compare_and_swap_under_lease(  # noqa: SLF001
        self, transition: ledger.CasTransition, lease_descriptor: int
    ) -> dict[str, Any]:
        persisted = ledger.DurablePhaseLedgerStore._compare_and_swap_under_lease(  # noqa: SLF001
            self, transition, lease_descriptor
        )
        if (
            self.crash_armed[0]
            and persisted.get("status") == "CLAIMED"
            and len(persisted.get("operation_outcomes", [])) == 1
        ):
            self.crash_armed[0] = False
            raise RuntimeError("synthetic crash after outcome CAS")
        return persisted


@dataclass(frozen=True, slots=True)
class _CrashAfterEvidenceBeforeOutcomeStore(ledger.DurablePhaseLedgerStore):
    crash_armed: list[bool] = field(default_factory=lambda: [True])

    def _compare_and_swap_under_lease(  # noqa: SLF001
        self, transition: ledger.CasTransition, lease_descriptor: int
    ) -> dict[str, Any]:
        proposed = transition.proposed_record
        if (
            self.crash_armed[0]
            and proposed.get("status") in {"CLAIMED", "CONSUMED", "AMBIGUOUS"}
            and len(proposed.get("operation_outcomes", [])) == 1
        ):
            self.crash_armed[0] = False
            raise RuntimeError("synthetic crash before outcome CAS")
        return ledger.DurablePhaseLedgerStore._compare_and_swap_under_lease(  # noqa: SLF001
            self, transition, lease_descriptor
        )


def test_in_flight_recovers_persisted_raw_evidence_without_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original, plan, prepared, authority, provider, state = _live_execute_context(
        monkeypatch, tmp_path
    )
    store = _CrashAfterEvidenceBeforeOutcomeStore(original.root)
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    arguments["inventory_classification"] = {
        **arguments["inventory_classification"],
        "provider_backed": True,
    }

    with pytest.raises(RuntimeError, match="synthetic crash before outcome CAS"):
        executor.execute_one_phase(**arguments)
    in_flight = store.read(str(prepared["ledger_id"]))
    assert in_flight["status"] == "IN_FLIGHT"
    evidence_name = executor._provider_evidence_file(  # noqa: SLF001
        str(prepared["ledger_id"]), 1
    )
    assert (store.root / evidence_name).is_file()
    calls_before = copy.deepcopy(state.calls)

    recovered = executor.execute_one_phase(
        **{
            **arguments,
            "provider": None,
            "clock": lambda: NOW + timedelta(seconds=3),
        }
    )
    terminal = store.read(str(prepared["ledger_id"]))
    assert recovered["status"] == terminal["status"] == "AMBIGUOUS"
    durable = terminal["operation_outcomes"][0]["durable_provider_evidence"]
    assert durable["private_provider_evidence_file"] == evidence_name
    assert durable["provider_result_digest"] is None
    assert state.calls == calls_before


def test_in_flight_rejects_resealed_raw_response_before_outcome_cas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original, plan, prepared, authority, provider, state = _live_execute_context(
        monkeypatch, tmp_path
    )
    store = _CrashAfterEvidenceBeforeOutcomeStore(original.root)
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    arguments["inventory_classification"] = {
        **arguments["inventory_classification"],
        "provider_backed": True,
    }

    with pytest.raises(RuntimeError, match="synthetic crash before outcome CAS"):
        executor.execute_one_phase(**arguments)
    evidence_name = executor._provider_evidence_file(  # noqa: SLF001
        str(prepared["ledger_id"]), 1
    )
    evidence_path = store.root / evidence_name
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    private = evidence["provider_private_record"]
    private["response"] = {"forged": True}
    evidence["provider_private_record_digest"] = executor.canonical_digest(
        {"provider_private_record": private}
    )
    evidence["evidence_digest"] = executor.canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    evidence_path.write_text(
        executor.canonical_json(evidence) + "\n", encoding="utf-8"
    )
    calls_before = copy.deepcopy(state.calls)

    with pytest.raises(
        executor.Gug390Error, match="PRIVATE_PROVIDER_PAYLOAD_INVALID"
    ):
        executor.execute_one_phase(
            **{
                **arguments,
                "provider": None,
                "clock": lambda: NOW + timedelta(seconds=3),
            }
        )
    assert store.read(str(prepared["ledger_id"]))["status"] == "IN_FLIGHT"
    assert state.calls == calls_before


def test_claimed_crash_resume_starts_at_exact_next_operation(
    tmp_path: Path,
) -> None:
    original, plan, prepared, authority = _prepared_store(tmp_path)
    store = _CrashAfterFirstOutcomeStore(original.root)
    first_provider = PhaseProvider(plan["target"]["authority_account_id"])
    first = _execute_arguments(store, plan, prepared, authority, first_provider)
    with pytest.raises(RuntimeError, match="synthetic crash after outcome CAS"):
        executor.execute_one_phase(**first, require_live_provider=False)
    claimed = store.read(prepared["ledger_id"])
    assert claimed["status"] == "CLAIMED"
    assert claimed["claim"]["next_operation_sequence"] == 2
    assert [item["sequence"] for item in first_provider.calls] == [1]

    resumed_provider = PhaseProvider(plan["target"]["authority_account_id"])
    resumed = executor.execute_one_phase(
        **_execute_arguments(store, plan, prepared, authority, resumed_provider),
        require_live_provider=False,
    )
    assert [item["sequence"] for item in resumed_provider.calls] == list(
        range(2, len(plan["authorization_phases"][0]["operations"]) + 1)
    )
    assert resumed["status"] == "CONSUMED"
    terminal = store.read(prepared["ledger_id"])
    assert [item["operation_sequence"] for item in terminal[
        "operation_outcomes"
    ]] == list(
        range(1, len(plan["authorization_phases"][0]["operations"]) + 1)
    )
    assert resumed["transcript"]["operation_evidence_count"] == len(
        plan["authorization_phases"][0]["operations"]
    )
    assert resumed["transcript"]["provider_segment_count"] == 2
    recovered = executor.execute_one_phase(
        **{
            **_execute_arguments(
                store,
                plan,
                prepared,
                authority,
                PhaseProvider(plan["target"]["authority_account_id"]),
            ),
            "provider": None,
        },
        require_live_provider=False,
    )
    assert recovered == resumed
    assert executor.canonical_json(recovered) == executor.canonical_json(resumed)


@pytest.mark.parametrize("omission", ["both", "owner", "request"])
def test_claimed_resume_requires_exact_caller_execution_context(
    tmp_path: Path,
    omission: str,
) -> None:
    original, plan, prepared, authority = _prepared_store(tmp_path)
    store = _CrashAfterFirstOutcomeStore(original.root)
    first_provider = PhaseProvider(plan["target"]["authority_account_id"])
    with pytest.raises(RuntimeError, match="synthetic crash after outcome CAS"):
        executor.execute_one_phase(
            **_execute_arguments(
                store, plan, prepared, authority, first_provider
            ),
            require_live_provider=False,
        )
    claimed = store.read(prepared["ledger_id"])
    resumed_provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(
        store, plan, prepared, authority, resumed_provider
    )
    if omission in {"both", "owner"}:
        arguments.pop("owner_checkpoint_digest")
    if omission in {"both", "request"}:
        arguments.pop("live_request_digest")

    with pytest.raises(
        executor.Gug390Error,
        match="EXECUTION_CONTEXT_(REQUIRED|INCOMPLETE)",
    ):
        executor.execute_one_phase(**arguments, require_live_provider=False)
    assert resumed_provider.calls == []
    assert store.read(prepared["ledger_id"]) == claimed


@pytest.mark.parametrize(
    "mutation",
    ["omit_both", "omit_owner", "omit_request", "owner", "request"],
)
def test_terminal_recovery_requires_exact_caller_execution_context(
    tmp_path: Path,
    mutation: str,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    executor.execute_one_phase(**arguments, require_live_provider=False)
    terminal = store.read(prepared["ledger_id"])
    recovery = {**arguments, "provider": None}
    if mutation in {"omit_both", "omit_owner"}:
        recovery.pop("owner_checkpoint_digest")
    if mutation in {"omit_both", "omit_request"}:
        recovery.pop("live_request_digest")
    if mutation == "owner":
        recovery["owner_checkpoint_digest"] = executor.canonical_digest(
            {"substitution": mutation}
        )
    if mutation == "request":
        recovery["live_request_digest"] = executor.canonical_digest(
            {"substitution": mutation}
        )

    with pytest.raises(
        executor.Gug390Error,
        match="EXECUTION_CONTEXT_(REQUIRED|INCOMPLETE|MISMATCH)",
    ):
        executor.execute_one_phase(**recovery, require_live_provider=False)
    assert store.read(prepared["ledger_id"]) == terminal


@pytest.mark.parametrize(
    "recovery_at",
    [NOW + timedelta(seconds=3), NOW + timedelta(days=1)],
)
def test_in_flight_recovery_without_evidence_is_controlled_and_non_certifiable(
    tmp_path: Path,
    recovery_at: datetime,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    context = executor._execution_context(  # noqa: SLF001
        owner_checkpoint_digest=OWNER_CHECKPOINT,
        live_request_digest=LIVE_REQUEST,
        activator_checkpoint_digest=None,
    )
    claimed = store.compare_and_swap(
        ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=NONCE,
            profile_class=str(prepared["profile_class"]),
            caller_arn_digest=str(prepared["caller_arn_digest"]),
            executor_authority_evidence_digest=str(
                prepared["executor_authority_evidence_digest"]
            ),
            host_digest=HOST,
            execution_authorization=authority["authorization"],
            plan=plan,
            expected_plan_digest=str(plan["plan_digest"]),
            executor_authority_evidence={
                key: value
                for key, value in authority.items()
                if key != "authorization"
            },
            authority_evaluation_at=NOW,
            expected_initial_bundle_absence_digest=BEFORE_STATE,
            predecessor_record=None,
            expected_predecessor_binding=None,
            execution_context=context,
        )
    )
    in_flight = store.compare_and_swap(
        ledger.prepare_operation_in_flight(
            claimed,
            expected_version=claimed["ledger_version"],
            expected_digest=claimed["ledger_digest"],
            at=NOW + timedelta(seconds=2),
            operation_sequence=1,
        )
    )
    arguments = _execute_arguments(
        store,
        plan,
        prepared,
        authority,
        PhaseProvider(plan["target"]["authority_account_id"]),
    )
    arguments["provider"] = None
    arguments["clock"] = lambda: recovery_at

    with pytest.raises(
        executor.Gug390Error, match="DURABLE_PROVIDER_EVIDENCE_MISSING"
    ):
        executor.execute_one_phase(**arguments, require_live_provider=False)

    recovered = store.read(str(in_flight["ledger_id"]))
    assert recovered["status"] == "AMBIGUOUS"
    assert recovered["operation_outcomes"][-1].get(
        "durable_provider_evidence"
    ) is None
    with pytest.raises(
        executor.Gug390Error, match="DURABLE_PROVIDER_EVIDENCE_MISSING"
    ):
        executor._private_phase_run_from_terminal_evidence(  # noqa: SLF001
            recovered,
            plan=plan,
            expected_plan_digest=str(plan["plan_digest"]),
        )


def test_provider_exception_ambiguity_without_evidence_fails_controlled(
    tmp_path: Path,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(
        plan["target"]["authority_account_id"],
        raise_on_first_operation=True,
    )

    with pytest.raises(
        executor.Gug390Error, match="DURABLE_PROVIDER_EVIDENCE_MISSING"
    ):
        executor.execute_one_phase(
            **_execute_arguments(store, plan, prepared, authority, provider),
            require_live_provider=False,
        )

    ambiguous = store.read(prepared["ledger_id"])
    assert [item["sequence"] for item in provider.calls] == [1]
    assert ambiguous["status"] == "AMBIGUOUS"
    assert ambiguous["operation_outcomes"][-1].get(
        "durable_provider_evidence"
    ) is None


def test_terminal_output_recovery_is_byte_identical_expired_and_provider_free(
    tmp_path: Path,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    original = executor.execute_one_phase(
        **arguments, require_live_provider=False
    )
    recovered = executor.execute_one_phase(
        **{
            **arguments,
            "provider": None,
            "clock": lambda: NOW + timedelta(days=1),
        },
        require_live_provider=False,
    )
    assert recovered == original
    assert executor.canonical_json(recovered) == executor.canonical_json(original)


@pytest.mark.parametrize(
    ("terminal_mode", "require_live", "error"),
    [
        ("SYNTHETIC", True, "LIVE_PROVIDER_REQUIRED"),
        ("LIVE", False, "SYNTHETIC_PROVIDER_REQUIRED"),
    ],
)
def test_terminal_recovery_enforces_provider_mode_bidirectionally(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    terminal_mode: str,
    require_live: bool,
    error: str,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    original = executor.execute_one_phase(
        **arguments, require_live_provider=False
    )
    terminal = store.read(prepared["ledger_id"])
    if terminal_mode == "LIVE":
        monkeypatch.setattr(
            executor,
            "_private_phase_run_from_terminal_evidence",
            lambda *_args, **_kwargs: {**original, "provider_mode": "LIVE"},
        )

    with pytest.raises(executor.Gug390Error, match=error):
        executor.execute_one_phase(
            **{**arguments, "provider": None},
            require_live_provider=require_live,
        )
    assert store.read(prepared["ledger_id"]) == terminal


def test_public_phase_rejects_resigned_run_not_derived_from_terminal_ledger(
    tmp_path: Path,
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    original = executor.execute_one_phase(
        **_execute_arguments(store, plan, prepared, authority, provider),
        require_live_provider=False,
    )
    forged = copy.deepcopy(original)
    forged["transcript"]["call_count"] += 10
    forged["run_digest"] = executor.canonical_digest(
        {key: value for key, value in forged.items() if key != "run_digest"}
    )

    with pytest.raises(
        executor.Gug390Error, match="PRIVATE_RUN_DURABLE_ORIGIN_MISMATCH"
    ):
        executor.public_phase_manifest(
            private_run=forged,
            ledger_record=store.read(prepared["ledger_id"]),
            plan=plan,
            expected_plan_digest=str(plan["plan_digest"]),
            source_commit_sha="1" * 40,
            source_tree_sha="2" * 40,
            plan_digest=str(plan["plan_digest"]),
            created_at=NOW + timedelta(seconds=3),
        )


def test_expired_claimed_resume_performs_no_provider_operation(
    tmp_path: Path,
) -> None:
    original, plan, prepared, authority = _prepared_store(tmp_path)
    store = _CrashAfterFirstOutcomeStore(original.root)
    first_provider = PhaseProvider(plan["target"]["authority_account_id"])
    with pytest.raises(RuntimeError, match="synthetic crash after outcome CAS"):
        executor.execute_one_phase(
            **_execute_arguments(store, plan, prepared, authority, first_provider),
            require_live_provider=False,
        )
    resumed_provider = PhaseProvider(plan["target"]["authority_account_id"])
    expired = _execute_arguments(store, plan, prepared, authority, resumed_provider)
    expired["clock"] = lambda: NOW + timedelta(days=1)
    with pytest.raises(ledger.PhaseLedgerError, match="RUNNER_LEDGER_EXPIRED"):
        executor.execute_one_phase(**expired, require_live_provider=False)
    assert resumed_provider.calls == []
    assert store.read(prepared["ledger_id"])["status"] == "CLAIMED"


@pytest.mark.parametrize(
    "field",
    [
        "owner_checkpoint_digest",
        "live_request_digest",
        "execution_context_digest",
        "operation_digest",
        "session_identifier_digest",
        "transcript",
        "causal_receipt_evidence",
    ],
)
def test_terminal_recovery_rejects_durable_evidence_substitution(
    tmp_path: Path, field: str
) -> None:
    store, plan, prepared, authority = _prepared_store(tmp_path)
    provider = PhaseProvider(plan["target"]["authority_account_id"])
    arguments = _execute_arguments(store, plan, prepared, authority, provider)
    executor.execute_one_phase(**arguments, require_live_provider=False)
    record = store.read(prepared["ledger_id"])
    evidence = record["operation_outcomes"][-1]["durable_provider_evidence"]
    if field == "transcript":
        evidence[field]["transcript_digest"] = executor.canonical_digest(
            {"substitution": field}
        )
    elif field == "causal_receipt_evidence":
        evidence[field] = {"substitution": field}
    else:
        evidence[field] = executor.canonical_digest({"substitution": field})
    with pytest.raises((executor.Gug390Error, ledger.PhaseLedgerError)):
        executor._private_phase_run_from_terminal_evidence(  # noqa: SLF001
            record,
            plan=plan,
            expected_plan_digest=plan["plan_digest"],
        )


def _concrete_reconciliation_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[live_provider.LiveProvider, live_provider_test_support.FakeState]:
    for name in live_provider_test_support.AWS_ENV:
        monkeypatch.delenv(name, raising=False)
    provider, state = live_provider_test_support._open(monkeypatch)  # noqa: SLF001
    receipt_body = asdict(provider.identity_receipt)
    receipt_body.pop("receipt_digest")
    receipt_body["concrete_provider"] = True
    provider._identity_receipt = live_provider.IdentityReceipt(  # noqa: SLF001
        **receipt_body,
        receipt_digest=executor.canonical_digest(receipt_body),
    )
    provider._concrete = True  # noqa: SLF001
    return provider, state


def _ambiguous_policy_reconciliation_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    ledger.DurablePhaseLedgerStore,
    dict[str, Any],
    dict[str, Any],
    live_provider.LiveProvider,
    live_provider_test_support.FakeState,
    live_provider.PlannedCall,
    tuple[live_provider.PlannedCall, ...],
    dict[str, Any],
]:
    provider, state = _concrete_reconciliation_provider(monkeypatch)
    receipt = provider.identity_receipt
    store, plan, prepared, evidence = _prepared_store(
        tmp_path,
        caller_digest=receipt.principal_digest,
        session_digest=receipt.session_digest,
    )
    phase_provider = PhaseProvider(
        str(plan["target"]["authority_account_id"]),
        ambiguous_on_first_write=True,
        caller_digest=receipt.principal_digest,
        session_digest=receipt.session_digest,
    )
    executor.execute_one_phase(
        **_execute_arguments(store, plan, prepared, evidence, phase_provider),
        require_live_provider=False,
    )
    ambiguous = store.read(str(prepared["ledger_id"]))
    assert ambiguous["status"] == "AMBIGUOUS"
    outcome = ambiguous["operation_outcomes"][-1]
    operation = plan["authorization_phases"][0]["operations"][
        outcome["operation_sequence"] - 1
    ]
    planned = live_provider.planned_call_from_record(
        str(ambiguous["phase"]), operation
    )
    readbacks = provider.reconciliation_readback_calls(planned)
    live_provider_test_support._configure_positive_mutation(  # noqa: SLF001
        state, planned, plan
    )
    for method, pages in list(state.pages.items()):
        assert len(pages) == 1, method
        state.pages[method] = [copy.deepcopy(pages[0]), copy.deepcopy(pages[0])]
    contract = executor._reconciliation_readback_contract(  # noqa: SLF001
        planned, readbacks, live_provider
    )
    return (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    )


def _expected_reconciliation_state_digest(
    *,
    state: live_provider_test_support.FakeState,
    planned: live_provider.PlannedCall,
    readbacks: tuple[live_provider.PlannedCall, ...],
    contract_digest: str,
) -> str:
    results: list[dict[str, Any]] = []
    for ordinal, call in enumerate(readbacks, 1):
        _service, method = live_provider._READ_METHODS[  # noqa: SLF001
            call.allowed_action
        ]
        response = copy.deepcopy(dict(state.pages[method][0]))
        response.pop("ResponseMetadata", None)
        if call.complete_pagination_required:
            request_key, response_key, truncated_key = live_provider._PAGINATION[  # noqa: SLF001
                call.allowed_action
            ]
            assert request_key
            response = live_provider._merge_pagination_facts(  # noqa: SLF001
                [response],
                response_token_key=response_key,
                truncated_key=truncated_key,
            )
        results.append(
            {
                "readback_ordinal": ordinal,
                "operation_digest": call.operation_digest,
                "request_digest": call.request_digest,
                "outcome": "PRESENT",
                "result_digest": executor.canonical_digest(response),
            }
        )
    body = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug390_reconciliation_observed_state.v1"
        ),
        "ambiguous_operation_digest": planned.operation_digest,
        "readback_contract_digest": contract_digest,
        "result_count": len(results),
        "results": results,
        "complete": True,
    }
    return executor.canonical_digest(body)


def _reconciliation_arguments(
    *,
    store: ledger.DurablePhaseLedgerStore,
    plan: Mapping[str, Any],
    ambiguous: Mapping[str, Any],
    provider: live_provider.LiveProvider,
    planned: live_provider.PlannedCall,
    contract: Mapping[str, Any],
    effect: str,
    no_effect: str,
) -> dict[str, Any]:
    outcome = ambiguous["operation_outcomes"][-1]
    binding_body = executor._reconciliation_expectation_binding_body(  # noqa: SLF001
        ambiguous,
        ambiguous=outcome,
        ambiguous_operation_digest=planned.operation_digest,
        readback_contract_digest=str(contract["contract_digest"]),
        identity_receipt_digest=provider.identity_receipt.receipt_digest,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        execution_context=executor._execution_context(  # noqa: SLF001
            owner_checkpoint_digest=RECONCILE_OWNER_CHECKPOINT,
            live_request_digest=RECONCILE_LIVE_REQUEST,
            activator_checkpoint_digest=None,
        ),
    )
    return {
        "store": store,
        "ledger_id": ambiguous["ledger_id"],
        "plan": plan,
        "expected_plan_digest": plan["plan_digest"],
        "expected_phase": ambiguous["phase"],
        "provider": provider,
        "expected_ambiguous_ledger_digest": ambiguous["ledger_digest"],
        "expected_ambiguous_operation_digest": planned.operation_digest,
        "expected_reconciliation_readback_contract_digest": contract[
            "contract_digest"
        ],
        "expected_session_identifier_digest": ambiguous[
            "authority_session_identifier_digest"
        ],
        "expected_effect_state_digest": effect,
        "expected_no_effect_state_digest": no_effect,
        "expected_reconciliation_binding_digest": executor.canonical_digest(
            binding_body
        ),
        "at": NOW + timedelta(seconds=3),
        "owner_checkpoint_digest": RECONCILE_OWNER_CHECKPOINT,
        "live_request_digest": RECONCILE_LIVE_REQUEST,
    }


def test_causal_reconciliation_uses_two_stable_complete_captures_and_zero_writes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    no_effect = executor.canonical_digest({"state": "no-effect"})

    reconciliation_arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=effect,
        no_effect=no_effect,
    )
    evidence_closed_at = NOW + timedelta(seconds=4)
    reconciliation_arguments["clock"] = lambda: evidence_closed_at
    private_run = executor.reconcile_ambiguous(**reconciliation_arguments)

    record = store.read(str(ambiguous["ledger_id"]))
    assert private_run["status"] == record["status"] == "RECONCILED"
    assert private_run["classification"] == "RECONCILIATION_CONCLUSIVE"
    assert record["reconciliation"]["classification"] == "EFFECT_PROVEN"
    assert record["reconciliation"]["binding_mode"] == (
        "CAUSAL_EXPECTATIONS_BOUND"
    )
    assert record["reconciliation"]["provider_writes_performed"] == 0
    assert record["reconciliation"]["recorded_at"] == (
        evidence_closed_at.isoformat().replace("+00:00", "Z")
    )
    assert private_run["transcript"]["write_call_count"] == 0
    assert record["reconciliation"]["provider_transcript_digest"] == (
        private_run["transcript"]["transcript_digest"]
    )
    evidence_name = record["reconciliation"][
        "private_reconciliation_evidence_file"
    ]
    assert stat.S_IMODE((store.root / evidence_name).stat().st_mode) == 0o600
    custody = executor._read_private_custody_record(  # noqa: SLF001
        store.root, evidence_name
    )
    assert custody is not None
    assert custody["evidence_digest"] == record["reconciliation"][
        "private_reconciliation_evidence_digest"
    ]
    assert custody["first_capture"]["private_results"]
    assert custody["second_capture"]["private_results"]
    assert len([item for item in state.calls if item[0] == "sts"]) == 3
    resource_calls = [item for item in state.calls if item[0] != "sts"]
    assert len(resource_calls) == 2 * len(readbacks)
    assert all(item[1] != "create_policy" for item in resource_calls)
    public = executor.public_phase_manifest(
        private_run=private_run,
        ledger_record=record,
        plan=plan,
        expected_plan_digest=str(plan["plan_digest"]),
        source_commit_sha="1" * 40,
        source_tree_sha="2" * 40,
        plan_digest=str(plan["plan_digest"]),
        created_at=NOW + timedelta(seconds=4),
        private_evidence_root=store.root,
    )
    assert public["status"] == "LIVE_RECONCILIATION_RECORDED"
    assert public["reconciliation_only"] is True
    calls_before_recovery = copy.deepcopy(state.calls)
    recovered = executor.reconcile_ambiguous(
        **{
            **reconciliation_arguments,
            "provider": None,
            "at": NOW + timedelta(days=1),
            "clock": lambda: NOW + timedelta(days=1),
        }
    )
    assert recovered == private_run
    assert executor.canonical_json(recovered) == executor.canonical_json(
        private_run
    )
    assert state.calls == calls_before_recovery
    assert public["deployment_authorized"] is False


@dataclass(frozen=True, slots=True)
class _CrashBeforeReconciliationCasStore(ledger.DurablePhaseLedgerStore):
    crash_armed: list[bool] = field(default_factory=lambda: [True])

    def compare_and_swap(self, transition: ledger.CasTransition) -> dict[str, Any]:
        if (
            self.crash_armed[0]
            and transition.proposed_record.get("status") == "RECONCILED"
        ):
            self.crash_armed[0] = False
            raise RuntimeError("synthetic crash before reconciliation CAS")
        return ledger.DurablePhaseLedgerStore.compare_and_swap(self, transition)


def test_reconciliation_recovers_two_persisted_captures_without_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        original,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    store = _CrashBeforeReconciliationCasStore(original.root)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=effect,
        no_effect=executor.canonical_digest({"state": "no-effect"}),
    )
    arguments["clock"] = lambda: NOW + timedelta(seconds=4)

    with pytest.raises(
        RuntimeError, match="synthetic crash before reconciliation CAS"
    ):
        executor.reconcile_ambiguous(**arguments)
    assert store.read(str(ambiguous["ledger_id"]))["status"] == "AMBIGUOUS"
    evidence_name = executor._reconciliation_evidence_file(  # noqa: SLF001
        str(ambiguous["ledger_id"])
    )
    assert (store.root / evidence_name).is_file()
    calls_before = copy.deepcopy(state.calls)

    recovered = executor.reconcile_ambiguous(
        **{
            **arguments,
            "provider": None,
            "at": NOW + timedelta(seconds=4),
            "clock": lambda: NOW + timedelta(seconds=5),
        }
    )
    terminal = store.read(str(ambiguous["ledger_id"]))
    assert recovered["status"] == terminal["status"] == "RECONCILED"
    assert terminal["reconciliation"][
        "private_reconciliation_evidence_file"
    ] == evidence_name
    assert state.calls == calls_before


def test_reconciliation_rejects_resealed_raw_response_before_cas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        original,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    store = _CrashBeforeReconciliationCasStore(original.root)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=effect,
        no_effect=executor.canonical_digest({"state": "no-effect"}),
    )
    arguments["clock"] = lambda: NOW + timedelta(seconds=4)

    with pytest.raises(
        RuntimeError, match="synthetic crash before reconciliation CAS"
    ):
        executor.reconcile_ambiguous(**arguments)
    evidence_name = executor._reconciliation_evidence_file(  # noqa: SLF001
        str(ambiguous["ledger_id"])
    )
    evidence_path = store.root / evidence_name
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    first_capture = evidence["first_capture"]
    private_item = first_capture["private_results"][0]
    private = private_item["private_provider_record"]
    private["response"] = {"forged": True}
    private_item["private_provider_record_digest"] = executor.canonical_digest(
        private
    )
    first_capture["capture_digest"] = executor.canonical_digest(
        {
            key: value
            for key, value in first_capture.items()
            if key != "capture_digest"
        }
    )
    evidence["evidence_digest"] = executor.canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    evidence_path.write_text(
        executor.canonical_json(evidence) + "\n", encoding="utf-8"
    )
    calls_before = copy.deepcopy(state.calls)

    with pytest.raises(
        executor.Gug390Error,
        match="PRIVATE_RECONCILIATION_CAPTURE_INVALID",
    ):
        executor.reconcile_ambiguous(
            **{**arguments, "provider": None, "at": NOW + timedelta(days=1)}
        )
    assert store.read(str(ambiguous["ledger_id"]))["status"] == "AMBIGUOUS"
    assert state.calls == calls_before


def test_reconciliation_terminal_recovery_rejects_tampered_private_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=effect,
        no_effect=executor.canonical_digest({"state": "no-effect"}),
    )
    arguments["clock"] = lambda: NOW + timedelta(seconds=4)
    executor.reconcile_ambiguous(**arguments)
    terminal = store.read(str(ambiguous["ledger_id"]))
    evidence_name = terminal["reconciliation"][
        "private_reconciliation_evidence_file"
    ]
    with (store.root / evidence_name).open("ab") as stream:
        stream.write(b"\n")

    with pytest.raises(
        executor.Gug390Error, match="PRIVATE_EVIDENCE_NONCANONICAL"
    ):
        executor.reconcile_ambiguous(
            **{**arguments, "provider": None, "at": NOW + timedelta(days=1)}
        )


def test_reconciliation_expiry_after_final_evidence_blocks_cas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=effect,
        no_effect=executor.canonical_digest({"state": "no-effect"}),
    )
    expires = datetime.fromisoformat(
        str(ambiguous["expires_at"]).replace("Z", "+00:00")
    )
    persistence_complete = [False]
    persist = executor._persist_private_custody_record  # noqa: SLF001

    def delayed_persist(
        root: Path, name: str, value: Mapping[str, Any]
    ) -> dict[str, Any]:
        result = persist(root, name, value)
        persistence_complete[0] = True
        return result

    monkeypatch.setattr(executor, "_persist_private_custody_record", delayed_persist)
    arguments["clock"] = lambda: (
        expires if persistence_complete[0] else NOW + timedelta(seconds=4)
    )
    with pytest.raises(
        executor.Gug390Error, match="RECONCILIATION_WINDOW_EXPIRED"
    ):
        executor.reconcile_ambiguous(**arguments)
    assert persistence_complete == [True]
    evidence_name = executor._reconciliation_evidence_file(  # noqa: SLF001
        str(ambiguous["ledger_id"])
    )
    assert (store.root / evidence_name).is_file()
    unchanged = store.read(str(ambiguous["ledger_id"]))
    assert unchanged["status"] == "AMBIGUOUS"
    assert unchanged["ledger_digest"] == ambiguous["ledger_digest"]
    resource_calls = [item for item in state.calls if item[0] != "sts"]
    assert len(resource_calls) == 2 * len(readbacks)
    assert all(item[1] != "create_policy" for item in resource_calls)


def test_unstable_reconciliation_readback_never_cas_closes_the_ledger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    effect = _expected_reconciliation_state_digest(
        state=state,
        planned=planned,
        readbacks=readbacks,
        contract_digest=str(contract["contract_digest"]),
    )
    state.pages["get_policy"][1]["Policy"]["Description"] = "drifted"

    with pytest.raises(
        executor.Gug390Error, match="RECONCILIATION_READBACK_UNSTABLE"
    ):
        executor.reconcile_ambiguous(
            **_reconciliation_arguments(
                store=store,
                plan=plan,
                ambiguous=ambiguous,
                provider=provider,
                planned=planned,
                contract=contract,
                effect=effect,
                no_effect=executor.canonical_digest({"state": "no-effect"}),
            )
        )
    after = store.read(str(ambiguous["ledger_id"]))
    assert after["status"] == "AMBIGUOUS"
    assert after["ledger_digest"] == ambiguous["ledger_digest"]
    assert provider.transcript_summary().provider_mutation_calls == 0


def test_reconciliation_read_error_never_cas_closes_the_ledger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        _readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    state.errors["get_policy"] = TimeoutError("synthetic-private-timeout")

    with pytest.raises(
        executor.Gug390Error, match="RECONCILIATION_READBACK_UNCERTAIN"
    ):
        executor.reconcile_ambiguous(
            **_reconciliation_arguments(
                store=store,
                plan=plan,
                ambiguous=ambiguous,
                provider=provider,
                planned=planned,
                contract=contract,
                effect=executor.canonical_digest({"state": "effect"}),
                no_effect=executor.canonical_digest({"state": "no-effect"}),
            )
        )
    after = store.read(str(ambiguous["ledger_id"]))
    assert after["status"] == "AMBIGUOUS"
    assert after["ledger_digest"] == ambiguous["ledger_digest"]
    assert provider.transcript_summary().provider_mutation_calls == 0


def test_inconclusive_reconciliation_remains_publicly_uncertain_and_no_go(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        _state,
        planned,
        _readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    private_run = executor.reconcile_ambiguous(
        **_reconciliation_arguments(
            store=store,
            plan=plan,
            ambiguous=ambiguous,
            provider=provider,
            planned=planned,
            contract=contract,
            effect=executor.canonical_digest({"state": "different-effect"}),
            no_effect=executor.canonical_digest(
                {"state": "different-no-effect"}
            ),
        )
    )
    record = store.read(str(ambiguous["ledger_id"]))
    assert record["reconciliation"]["classification"] == "INCONCLUSIVE"
    assert private_run["classification"] == "UNCERTAIN_RECONCILE_ONLY"
    public = executor.public_phase_manifest(
        private_run=private_run,
        ledger_record=record,
        plan=plan,
        expected_plan_digest=str(plan["plan_digest"]),
        source_commit_sha="1" * 40,
        source_tree_sha="2" * 40,
        plan_digest=str(plan["plan_digest"]),
        created_at=NOW + timedelta(seconds=4),
        private_evidence_root=store.root,
    )
    assert public["status"] == "UNCERTAIN_RECONCILE_ONLY"
    assert public["production_status"] == "NO-GO"
    assert public["deployment_authorized"] is False


def test_reconciliation_request_phase_must_match_the_ambiguous_ledger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        store,
        plan,
        ambiguous,
        provider,
        state,
        planned,
        _readbacks,
        contract,
    ) = _ambiguous_policy_reconciliation_context(monkeypatch, tmp_path)
    arguments = _reconciliation_arguments(
        store=store,
        plan=plan,
        ambiguous=ambiguous,
        provider=provider,
        planned=planned,
        contract=contract,
        effect=executor.canonical_digest({"state": "effect"}),
        no_effect=executor.canonical_digest({"state": "no-effect"}),
    )
    arguments["expected_phase"] = "FOUNDATION_FACTORY"

    with pytest.raises(
        executor.Gug390Error, match="RECONCILIATION_PHASE_BINDING_MISMATCH"
    ):
        executor.reconcile_ambiguous(**arguments)
    assert state.calls == [("sts", "get_caller_identity", {})]
    assert store.read(str(ambiguous["ledger_id"]))["status"] == "AMBIGUOUS"


def test_generic_provider_cannot_select_or_reconcile_an_ambiguous_operation(
    tmp_path: Path,
) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    phase_provider = PhaseProvider(
        str(plan["target"]["authority_account_id"]),
        ambiguous_on_first_write=True,
    )
    executor.execute_one_phase(
        **_execute_arguments(store, plan, prepared, evidence, phase_provider),
        require_live_provider=False,
    )
    ambiguous = store.read(str(prepared["ledger_id"]))
    generic = PhaseProvider(
        str(plan["target"]["authority_account_id"]), mode="LIVE"
    )
    digest = executor.canonical_digest({"placeholder": "bound"})
    with pytest.raises(executor.Gug390Error, match="PROVIDER_MODE_INVALID"):
        executor.reconcile_ambiguous(
            store=store,
            ledger_id=str(ambiguous["ledger_id"]),
            plan=plan,
            expected_plan_digest=str(plan["plan_digest"]),
            expected_phase=str(ambiguous["phase"]),
            provider=generic,
            expected_ambiguous_ledger_digest=str(ambiguous["ledger_digest"]),
            expected_ambiguous_operation_digest=digest,
            expected_reconciliation_readback_contract_digest=digest,
            expected_session_identifier_digest=SESSION,
            expected_effect_state_digest=digest,
            expected_no_effect_state_digest=executor.canonical_digest(
                {"placeholder": "different"}
            ),
            expected_reconciliation_binding_digest=digest,
            at=NOW + timedelta(seconds=3),
            owner_checkpoint_digest=OWNER_CHECKPOINT,
            live_request_digest=LIVE_REQUEST,
        )
    assert generic.calls == []
    assert store.read(str(ambiguous["ledger_id"]))["status"] == "AMBIGUOUS"


def test_reconcile_in_flight_recovers_without_provider_and_requires_new_binding(
    tmp_path: Path,
) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    context = executor._execution_context(  # noqa: SLF001
        owner_checkpoint_digest=OWNER_CHECKPOINT,
        live_request_digest=LIVE_REQUEST,
        activator_checkpoint_digest=None,
    )
    claimed = store.compare_and_swap(
        ledger.prepare_claim(
            prepared,
            expected_version=prepared["ledger_version"],
            expected_digest=prepared["ledger_digest"],
            at=NOW + timedelta(seconds=1),
            claim_nonce_digest=NONCE,
            profile_class=str(prepared["profile_class"]),
            caller_arn_digest=str(prepared["caller_arn_digest"]),
            executor_authority_evidence_digest=str(
                prepared["executor_authority_evidence_digest"]
            ),
            host_digest=HOST,
            execution_authorization=evidence["authorization"],
            plan=plan,
            expected_plan_digest=str(plan["plan_digest"]),
            executor_authority_evidence={
                key: value
                for key, value in evidence.items()
                if key != "authorization"
            },
            authority_evaluation_at=NOW,
            expected_initial_bundle_absence_digest=BEFORE_STATE,
            predecessor_record=None,
            expected_predecessor_binding=None,
            execution_context=context,
        )
    )
    in_flight = store.compare_and_swap(
        ledger.prepare_operation_in_flight(
            claimed,
            expected_version=claimed["ledger_version"],
            expected_digest=claimed["ledger_digest"],
            at=NOW + timedelta(seconds=2),
            operation_sequence=1,
        )
    )
    digest = executor.canonical_digest({"unused": "recovery-only"})

    with pytest.raises(
        executor.Gug390Error,
        match="IN_FLIGHT_RECOVERED_NEW_AMBIGUOUS_BINDING_REQUIRED",
    ):
        executor.reconcile_ambiguous(
            store=store,
            ledger_id=str(in_flight["ledger_id"]),
            plan={},
            expected_plan_digest=digest,
            expected_phase=str(in_flight["phase"]),
            provider=None,
            expected_ambiguous_ledger_digest=digest,
            expected_ambiguous_operation_digest=digest,
            expected_reconciliation_readback_contract_digest=digest,
            expected_session_identifier_digest=digest,
            expected_effect_state_digest=digest,
            expected_no_effect_state_digest=digest,
            expected_reconciliation_binding_digest=digest,
            at=NOW + timedelta(days=1),
            owner_checkpoint_digest=OWNER_CHECKPOINT,
            live_request_digest=LIVE_REQUEST,
        )

    recovered = store.read(str(in_flight["ledger_id"]))
    assert recovered["status"] == "AMBIGUOUS"
    assert recovered["reconciliation"] is None
    assert recovered["operation_outcomes"][-1].get(
        "durable_provider_evidence"
    ) is None


def test_generic_provider_cannot_self_assert_live_inventory() -> None:
    plan = _plan()
    provider = InventoryProvider(
        account_id=str(plan["target"]["authority_account_id"]),
        capture_index=1,
        mode="LIVE",
    )
    with pytest.raises(executor.Gug390Error, match="PROVIDER_MODE_INVALID"):
        executor.capture_inventory_once(
            plan=plan,
            provider=provider,
            expected_plan_digest=str(plan["plan_digest"]),
            expected_account_id=str(plan["target"]["authority_account_id"]),
            expected_region=executor.REGION,
                capture_index=1,
                captured_at=NOW,
                owner_checkpoint_digest=OWNER_CHECKPOINT,
                live_request_digest=LIVE_REQUEST,
            )
    assert provider.reads == []


def test_generic_provider_cannot_self_assert_live_phase_execution(
    tmp_path: Path,
) -> None:
    store, plan, prepared, evidence = _prepared_store(tmp_path)
    provider = PhaseProvider(
        str(plan["target"]["authority_account_id"]), mode="LIVE"
    )
    with pytest.raises(executor.Gug390Error, match="PROVIDER_MODE_INVALID"):
        executor.execute_one_phase(
            **_execute_arguments(store, plan, prepared, evidence, provider)
        )
    assert provider.calls == []
    assert store.read(str(prepared["ledger_id"]))["status"] == "PREPARED"


def _activator_checkpoint() -> dict[str, Any]:
    body: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug357_function_configurator_checkpoint.v1"
        ),
        "function_configurator_checkpoint_digest": executor.canonical_digest(
            {"checkpoint": "function-configurator"}
        ),
        "broker_function_evidence_digest": executor.canonical_digest(
            {"evidence": "broker-function"}
        ),
        "authority_ended_at": (NOW - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z"),
        "stable_provider_readback_digest": executor.canonical_digest(
            {"readback": "stable"}
        ),
        "factory_role_proof_bound_and_detached": True,
    }
    return {**body, "checkpoint_digest": executor.canonical_digest(body)}


@dataclass
class ActivatorStore:
    record: dict[str, Any]
    swaps: list[dict[str, Any]] = field(default_factory=list)

    def read(self, ledger_id: str) -> dict[str, Any]:
        assert ledger_id == self.record["ledger_id"]
        return copy.deepcopy(self.record)

    def compare_and_swap(self, value: Mapping[str, Any]) -> dict[str, Any]:
        detached = copy.deepcopy(dict(value))
        self.swaps.append(detached)
        self.record = detached
        return copy.deepcopy(detached)


def test_activator_requires_independent_digest_and_binds_it_to_private_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = _activator_checkpoint()
    checkpoint_digest = str(checkpoint["checkpoint_digest"])
    authority_account_id = str(_plan()["target"]["authority_account_id"])
    ledger_digest = executor.canonical_digest({"ledger": "activator"})
    record = {
        "phase": "ACTIVATOR",
        "status": "PREPARED",
        "ledger_id": "gug390-activator-synthetic",
        "ledger_version": 1,
        "ledger_digest": ledger_digest,
        "account_id": authority_account_id,
        "region": executor.REGION,
        "profile_class": "GUG390Activator",
        "caller_arn_digest": CALLER,
        "authority_session_identifier_digest": SESSION,
        "executor_authority_evidence_digest": executor.canonical_digest(
            {"evidence": "activator"}
        ),
        "host_digest": HOST,
        "before_state_digest": BEFORE_STATE,
    }
    store = ActivatorStore(copy.deepcopy(record))
    provider = PhaseProvider(authority_account_id)
    arguments = {
        "store": store,
        "plan": {"plan_digest": executor.canonical_digest({"plan": "activator"})},
        "expected_plan_digest": executor.canonical_digest({"plan": "activator"}),
        "ledger_id": record["ledger_id"],
        "execution_authorization": {},
        "executor_authority_evidence": {},
        "authority_evaluation_at": NOW,
        "expected_initial_bundle_absence_digest": BEFORE_STATE,
        "predecessor_record": {},
        "expected_predecessor_binding": {},
        "provider": provider,
        "clock": lambda: NOW,
        "inventory_classification": {
            "classification": "EXACT_PRESENT_NO_TOUCH",
            "stable": True,
            "provider_backed": False,
            "authorized_before_state_digest": BEFORE_STATE,
        },
        "claim_nonce_digest": NONCE,
        "activator_checkpoint": checkpoint,
        "require_live_provider": False,
    }

    with pytest.raises(
        executor.Gug390Error,
        match="EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
    ):
        executor.execute_one_phase(**arguments)
    assert store.swaps == []
    assert provider.calls == []

    monkeypatch.setattr(
        executor.phase_ledger,
        "prepare_claim",
        lambda current, **_kwargs: {**current, "status": "IN_FLIGHT"},
    )

    def consume(**_kwargs: Any) -> dict[str, Any]:
        return {
            **store.record,
            "phase": "ACTIVATOR",
            "status": "CONSUMED",
            "ledger_digest": executor.canonical_digest(
                {"ledger": "activator-consumed"}
            ),
            "receipt_chain": [
                {"receipt_digest": executor.canonical_digest({"receipt": 1})}
            ],
        }

    monkeypatch.setattr(executor.phase_ledger, "execute_claimed_phase", consume)
    private_run = executor.execute_one_phase(
        **arguments,
        expected_activator_checkpoint_digest=checkpoint_digest,
    )
    assert private_run["phase"] == "ACTIVATOR"
    assert private_run["status"] == "CONSUMED"
    assert private_run["activator_checkpoint_digest"] == checkpoint_digest
    assert private_run["run_digest"] == executor.canonical_digest(
        {key: value for key, value in private_run.items() if key != "run_digest"}
    )


def _synthetic_consumed_phase_evidence(
    *, activator_checkpoint_digest: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for ordinal, phase in enumerate(executor.FORWARD_PHASES, start=1):
        context = executor._execution_context(  # noqa: SLF001
            owner_checkpoint_digest=OWNER_CHECKPOINT,
            live_request_digest=LIVE_REQUEST,
            activator_checkpoint_digest=(
                activator_checkpoint_digest if phase == "ACTIVATOR" else None
            ),
        )
        receipt_digest = executor.canonical_digest(
            {"phase": phase, "receipt": ordinal}
        )
        record = {
            "phase": phase,
            "ledger_id": f"gug390-{ordinal}",
            "ledger_digest": executor.canonical_digest(
                {"phase": phase, "ledger": ordinal}
            ),
            "receipt_chain": [
                {
                    "receipt_digest": receipt_digest,
                    "at": (NOW - timedelta(minutes=3))
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            ],
            "claim": {"execution_context": context},
        }
        transcript = {
            "transcript_digest": executor.canonical_digest(
                {"phase": phase, "transcript": ordinal}
            ),
            "call_count": 1,
            "write_call_count": 0,
            "live_provider_evidence": False,
        }
        run: dict[str, Any] = {
            "record_type": executor.PRIVATE_RUN_TYPE,
            "schema_version": 1,
            "issue": executor.ISSUE,
            "command": "execute-phase",
            "phase": phase,
            "status": "CONSUMED",
            "classification": "PHASE_CONSUMED",
            "ledger_id": record["ledger_id"],
            "ledger_digest": record["ledger_digest"],
            "terminal_receipt_digest": receipt_digest,
            "provider_mode": "SYNTHETIC",
            "transcript": transcript,
            "causal_receipt_evidence": None,
            "activator_checkpoint_digest": (
                activator_checkpoint_digest if phase == "ACTIVATOR" else None
            ),
            "owner_checkpoint_digest": OWNER_CHECKPOINT,
            "live_request_digest": LIVE_REQUEST,
            "execution_context_digest": context["context_digest"],
            "recovered_in_flight": False,
            "retry_permitted": False,
            "automatic_rollback_permitted": False,
            "deployment_authorized": False,
            "production_status": "NO-GO",
            "run_digest": "",
        }
        run["run_digest"] = executor.canonical_digest(
            {key: value for key, value in run.items() if key != "run_digest"}
        )
        records.append(record)
        runs.append(run)
    return records, runs


def _stub_certification_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
    *, activator_digest: str,
) -> list[dict[str, Any]]:
    public_calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        executor,
        "classify_stable_inventory",
        lambda *_args, **_kwargs: {
            "classification": "EXACT_PRESENT_NO_TOUCH",
            "stable": True,
            "provider_backed": False,
            "owner_checkpoint_digest": OWNER_CHECKPOINT,
            "live_request_digest": LIVE_REQUEST,
            "facts_digest": executor.canonical_digest({"facts": "final"}),
            "snapshot_digests": [
                executor.canonical_digest({"snapshot": 1}),
                executor.canonical_digest({"snapshot": 2}),
            ],
            "transcript_digests": [
                executor.canonical_digest({"transcript": 1}),
                executor.canonical_digest({"transcript": 2}),
            ],
            "captured_at": [
                (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
                (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            ],
        },
    )
    monkeypatch.setattr(
        executor,
        "_validate_activator_checkpoint",
        lambda *_args, **_kwargs: activator_digest,
    )
    monkeypatch.setattr(
        executor.phase_ledger,
        "validate_consumed_causal_bundle",
        lambda *_args, **_kwargs: executor.canonical_digest({"bundle": "causal"}),
    )

    def forbidden_public_manifest(**kwargs: Any) -> dict[str, Any]:
        public_calls.append(kwargs)
        raise AssertionError("incomplete certification reached public manifest")

    monkeypatch.setattr(executor, "_public_manifest", forbidden_public_manifest)
    return public_calls


def _certification_arguments(
    *,
    phase_records: list[dict[str, Any]],
    phase_runs: list[dict[str, Any]],
    activator_checkpoint_digest: str,
) -> dict[str, Any]:
    plan = _plan()
    return {
        "plan": plan,
        "expected_plan_digest": plan["plan_digest"],
        "expected_bundle_digest": executor.canonical_digest({"bundle": "expected"}),
        "phase_records": phase_records,
        "phase_runs": phase_runs,
        "expected_phase_run_digests": (
            [str(item["run_digest"]) for item in phase_runs]
            if phase_runs
            else [
                executor.canonical_digest({"missing_phase_run": index})
                for index in range(1, 9)
            ]
        ),
        "expected_phase_bindings": [],
        "expected_initial_bundle_absence_digest": BEFORE_STATE,
        "expected_final_facts_digest": executor.canonical_digest({"facts": "final"}),
        "expected_final_snapshot_digests": [
            executor.canonical_digest({"snapshot": 1}),
            executor.canonical_digest({"snapshot": 2}),
        ],
        "first_snapshot": {},
        "second_snapshot": {},
        "source_commit_sha": "1" * 40,
        "source_tree_sha": "2" * 40,
        "execution_mode": "SYNTHETIC",
        "activator_checkpoint": {},
        "expected_activator_checkpoint_digest": activator_checkpoint_digest,
        "created_at": NOW,
        "owner_checkpoint_digest": OWNER_CHECKPOINT,
        "live_request_digest": LIVE_REQUEST,
    }


def test_certify_rejects_missing_private_phase_runs_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activator_digest = executor.canonical_digest({"activator": "checkpoint"})
    phase_records, _phase_runs = _synthetic_consumed_phase_evidence(
        activator_checkpoint_digest=activator_digest
    )
    public_calls = _stub_certification_prerequisites(
        monkeypatch, activator_digest=activator_digest
    )
    with pytest.raises(executor.Gug390Error, match="PHASE_RUN_SET_INVALID"):
        executor.certify_bundle(
            **_certification_arguments(
                phase_records=phase_records,
                phase_runs=[],
                activator_checkpoint_digest=activator_digest,
            )
        )
    assert public_calls == []


def test_live_certify_rejects_resigned_run_not_derived_from_durable_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activator_digest = executor.canonical_digest({"activator": "checkpoint"})
    records, runs = _synthetic_consumed_phase_evidence(
        activator_checkpoint_digest=activator_digest
    )
    for run in runs:
        run["provider_mode"] = "LIVE"
        run["run_digest"] = executor.canonical_digest(
            {key: value for key, value in run.items() if key != "run_digest"}
        )
    reconstructed = {
        str(record["ledger_id"]): copy.deepcopy(run)
        for record, run in zip(records, runs, strict=True)
    }
    runs[0]["transcript"]["transcript_digest"] = executor.canonical_digest(
        {"resigned": "not-durable"}
    )
    runs[0]["run_digest"] = executor.canonical_digest(
        {key: value for key, value in runs[0].items() if key != "run_digest"}
    )
    monkeypatch.setattr(
        executor,
        "_private_phase_run_from_terminal_evidence",
        lambda record, **_kwargs: copy.deepcopy(
            reconstructed[str(record["ledger_id"])]
        ),
    )

    with pytest.raises(
        executor.Gug390Error,
        match="PRIVATE_PHASE_RUN_DURABLE_EVIDENCE_MISMATCH",
    ):
        executor._validate_private_phase_runs(  # noqa: SLF001
            plan=_plan(),
            phase_records=records,
            phase_runs=runs,
            expected_phase_run_digests=[
                str(run["run_digest"]) for run in runs
            ],
            execution_mode="LIVE",
            expected_activator_checkpoint_digest=activator_digest,
        )


def test_certify_rejects_missing_invoker_causal_receipt_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    activator_digest = executor.canonical_digest({"activator": "checkpoint"})
    phase_records, phase_runs = _synthetic_consumed_phase_evidence(
        activator_checkpoint_digest=activator_digest
    )
    public_calls = _stub_certification_prerequisites(
        monkeypatch, activator_digest=activator_digest
    )
    with pytest.raises(
        executor.Gug390Error, match="CAUSAL_RECEIPT_EVIDENCE_REQUIRED"
    ):
        executor.certify_bundle(
            **_certification_arguments(
                phase_records=phase_records,
                phase_runs=phase_runs,
                activator_checkpoint_digest=activator_digest,
            )
        )
    assert public_calls == []


def _private_causal_receipt_binding(
    plan: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    invoker = next(
        item
        for item in plan["authorization_phases"]
        if item["phase"] == "LEDGER_FACTORY_INVOKER"
    )
    operation = next(
        item
        for item in invoker["operations"]
        if item["api_action"] == "InvokeFunction"
    )
    planned = live_provider.planned_call_from_record(
        "LEDGER_FACTORY_INVOKER", operation
    )
    identity_receipt_digest = executor.canonical_digest(
        {"identity_receipt": "GUG390SyntheticCertification"}
    )
    binding: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug390_private_causal_receipt_binding.v1"
        ),
        "plan_digest": plan["plan_digest"],
        "operation_digest": planned.operation_digest,
        "provider_result_digest": receipt["receipt_sha256"],
        "receipt_digest": receipt["receipt_sha256"],
        "identity_receipt_digest": identity_receipt_digest,
        "certification_required": True,
        "activation_authorized": False,
    }
    binding["binding_digest"] = executor.canonical_digest(binding)
    evidence = {**binding, "receipt": copy.deepcopy(receipt)}
    evidence["private_evidence_digest"] = executor.canonical_digest(evidence)
    return evidence


def _private_phase_runs_for_certification(
    phase_records: list[dict[str, Any]],
    *,
    causal_receipt_evidence: Mapping[str, Any],
    activator_checkpoint_digest: str,
) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for ordinal, (phase, record) in enumerate(
        zip(executor.FORWARD_PHASES, phase_records, strict=True), start=1
    ):
        outcomes = record["operation_outcomes"]
        transcript: dict[str, Any] = {
            "transcript_digest": executor.canonical_digest(
                {
                    "phase": phase,
                    "ledger_digest": record["ledger_digest"],
                    "ordinal": ordinal,
                }
            ),
            "call_count": len(outcomes) + 1,
            "write_call_count": len(outcomes),
            "live_provider_evidence": False,
        }
        evidence: Mapping[str, Any] | None = None
        if phase == "LEDGER_FACTORY_INVOKER":
            evidence = copy.deepcopy(causal_receipt_evidence)
            transcript["identity_receipt_digest"] = evidence[
                "identity_receipt_digest"
            ]
            transcript["accepted_causal_receipt_binding_digest"] = evidence[
                "binding_digest"
            ]
        run: dict[str, Any] = {
            "record_type": executor.PRIVATE_RUN_TYPE,
            "schema_version": 1,
            "issue": executor.ISSUE,
            "command": "execute-phase",
            "phase": phase,
            "status": "CONSUMED",
            "classification": "PHASE_CONSUMED",
            "ledger_id": record["ledger_id"],
            "ledger_digest": record["ledger_digest"],
            "terminal_receipt_digest": record["receipt_chain"][-1][
                "receipt_digest"
            ],
            "provider_mode": "SYNTHETIC",
            "transcript": transcript,
            "causal_receipt_evidence": evidence,
            "activator_checkpoint_digest": (
                activator_checkpoint_digest if phase == "ACTIVATOR" else None
            ),
            "recovered_in_flight": False,
            "retry_permitted": False,
            "automatic_rollback_permitted": False,
            "deployment_authorized": False,
            "production_status": "NO-GO",
            "run_digest": "",
        }
        run["run_digest"] = executor.canonical_digest(
            {key: value for key, value in run.items() if key != "run_digest"}
        )
        runs.append(run)
    return runs


def test_certify_accepts_complete_synthetic_causal_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_plan = _plan()
    plan = executor.validate_plan(
        raw_plan,
        expected_plan_digest=raw_plan["plan_digest"],
        expected_account_id=raw_plan["target"]["authority_account_id"],
        expected_region=executor.REGION,
    )
    (
        phase_records,
        phase_bindings,
        _authority_evidence,
        bundle_digest,
        initial_absence_digest,
        factory_receipt,
    ) = materializer_test_support._complete_causal_bundle(plan)  # noqa: SLF001
    causal_receipt = _private_causal_receipt_binding(plan, factory_receipt)
    checkpoint = _activator_checkpoint()
    checkpoint_digest = str(checkpoint["checkpoint_digest"])
    phase_runs = _private_phase_runs_for_certification(
        phase_records,
        causal_receipt_evidence=causal_receipt,
        activator_checkpoint_digest=checkpoint_digest,
    )
    phase_run_digests = [str(item["run_digest"]) for item in phase_runs]
    assert len(phase_records) == len(phase_runs) == len(phase_bindings) == 8
    assert len(set(phase_run_digests)) == 8
    assert all(record["status"] == "CONSUMED" for record in phase_records)

    terminal_at = datetime.fromisoformat(
        phase_records[-1]["receipt_chain"][-1]["at"].replace("Z", "+00:00")
    )
    first_snapshot = _capture(
        plan,
        1,
        marker="PRESENT",
        target_outcome="PRESENT",
        captured_at=terminal_at + timedelta(minutes=1),
    )
    second_snapshot = _capture(
        plan,
        2,
        marker="PRESENT",
        target_outcome="PRESENT",
        captured_at=terminal_at + timedelta(minutes=2),
    )
    receipt_validations: list[str] = []
    validate_receipt = (
        materializer_test_support.materializer.validate_ledger_factory_causal_receipt
    )

    def validate_and_record(
        *args: Any, **kwargs: Any
    ) -> Mapping[str, Any] | None:
        receipt_validations.append(str(kwargs["expected_receipt_sha256"]))
        return validate_receipt(*args, **kwargs)

    monkeypatch.setattr(
        materializer_test_support.materializer,
        "validate_ledger_factory_causal_receipt",
        validate_and_record,
    )
    certify_owner = executor.canonical_digest({"owner": "certify-C"})
    certify_request = executor.canonical_digest({"request": "certify-C"})
    manifest = executor.certify_bundle(
        plan=plan,
        expected_plan_digest=plan["plan_digest"],
        expected_bundle_digest=bundle_digest,
        phase_records=phase_records,
        phase_runs=phase_runs,
        expected_phase_run_digests=phase_run_digests,
        expected_phase_bindings=phase_bindings,
        expected_initial_bundle_absence_digest=initial_absence_digest,
        expected_final_facts_digest=second_snapshot["facts_digest"],
        expected_final_snapshot_digests=[
            first_snapshot["snapshot_digest"],
            second_snapshot["snapshot_digest"],
        ],
        first_snapshot=first_snapshot,
        second_snapshot=second_snapshot,
        source_commit_sha="1" * 40,
        source_tree_sha="2" * 40,
        execution_mode="SYNTHETIC",
        activator_checkpoint=checkpoint,
        expected_activator_checkpoint_digest=checkpoint_digest,
        created_at=terminal_at + timedelta(minutes=3),
        owner_checkpoint_digest=certify_owner,
        live_request_digest=certify_request,
    )

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text())).validate(manifest)
    assert receipt_validations == [factory_receipt["receipt_sha256"]]
    assert manifest["command"] == "certify"
    assert manifest["phase"] == "NONE"
    assert manifest["classification"] == "SYNTHETIC_VALIDATED"
    assert manifest["status"] == "LIVE_PROVIDER_NOT_PROVEN"
    assert manifest["checkpoint_digest"] == checkpoint_digest
    assert manifest["owner_checkpoint_digest"] == certify_owner
    assert manifest["live_request_digest"] == certify_request
    assert first_snapshot["owner_checkpoint_digest"] == OWNER_CHECKPOINT
    assert first_snapshot["live_request_digest"] == LIVE_REQUEST
    assert manifest["live_provider_evidence"] is False
    assert manifest["aws_calls"] == manifest["aws_mutations"] == 0
