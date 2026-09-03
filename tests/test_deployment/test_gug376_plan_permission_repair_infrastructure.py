"""Closed infrastructure contracts for the GUG-376 Plan policy repair PEP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import pytest
import yaml

from tooling import platform_authority_plan_permission_repair_aws as runtime
from tooling import platform_authority_plan_permission_repair_broker_seed as broker_seed
from tooling.platform_authority_plan_permission_repair import (
    LAMBDA_ENVIRONMENT_LIMIT_BYTES,
    MAX_PUBLISHED_FUNCTION_VERSION_BYTES,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_TEMPLATE = (
    REPO_ROOT / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
)
MANAGEMENT_TEMPLATE = (
    REPO_ROOT
    / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
)
POLICY_ROOT = REPO_ROOT / "policies/iam"

AUTHORITY_ACCOUNT = "042360977644"
MANAGEMENT_ACCOUNT = "839393571433"
REGION = "us-east-1"
PLAN_PERMISSION_SET = "ScanalyzeAuthorityBootstrapPlan"
INVOKER_PERMISSION_SET = "ScanalyzeBootstrapPlanRepair"
MUTATIONS = {
    "sso:ProvisionPermissionSet",
    "sso:PutInlinePolicyToPermissionSet",
}
FORBIDDEN_MUTATIONS = {
    "sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
    "sso:AttachManagedPolicyToPermissionSet",
    "sso:CreateAccountAssignment",
    "sso:CreatePermissionSet",
    "sso:DeleteAccountAssignment",
    "sso:DeleteInlinePolicyFromPermissionSet",
    "sso:DeletePermissionSet",
    "sso:DeletePermissionsBoundaryFromPermissionSet",
    "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet",
    "sso:DetachManagedPolicyFromPermissionSet",
    "sso:PutPermissionsBoundaryToPermissionSet",
    "sso:TagResource",
    "sso:UntagResource",
    "sso:UpdatePermissionSet",
}
DYNAMODB_WRITES = {
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:PartiQLDelete",
    "dynamodb:PartiQLInsert",
    "dynamodb:PartiQLUpdate",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
}
FUNCTIONS = {
    "PlanFunction": (
        "scanalyze-platform-authority-plan-policy-plan",
        "tooling.platform_authority_plan_permission_repair_aws.plan_handler",
        "plan-v1",
        300,
    ),
    "RepairFunction": (
        "scanalyze-platform-authority-plan-policy-repair",
        "tooling.platform_authority_plan_permission_repair_aws.repair_handler",
        "repair-v1",
        600,
    ),
    "ReconcileFunction": (
        "scanalyze-platform-authority-plan-policy-reconcile",
        "tooling.platform_authority_plan_permission_repair_aws.reconcile_handler",
        "reconcile-v1",
        300,
    ),
}
COMMON_ENVIRONMENT = {
    "BOOTSTRAP_CHANGE_SET_NAME",
    "CURRENT_POLICY_DIGEST",
    "DESIRED_POLICY_DIGEST",
    "EXPECTED_ARTIFACT_CODE_SHA256",
    "EXPECTED_BOTO3_VERSION",
    "EXPECTED_BOTOCORE_VERSION",
    "EXPECTED_CODE_SIGNING_CONFIG_ARN",
    "EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON",
    "EXPECTED_PERMISSION_SET_DESCRIPTION",
    "EXPECTED_SIGNING_PROFILE_VERSION_ARN",
    "IDENTITY_CENTER_INSTANCE_ARN",
    "IDENTITY_CENTER_KMS_KEY_ARN",
    "IDENTITY_CENTER_KMS_MODE",
    "IDENTITY_STORE_ID",
    "IMMU_CONFIG_DIGEST",
    "PLAN_PERMISSION_SET_ARN",
    "PLAN_SAML_PROVIDER_ARN",
    "PRINCIPAL_ID",
    "REPAIR_ID",
    "REPAIR_INVOKER_PERMISSION_SET_ARN",
    "REPAIR_LEDGER_KMS_KEY_ARN",
    "REPAIR_LEDGER_TABLE_NAME",
    "REPAIR_NOT_AFTER",
    "REPAIR_NOT_BEFORE",
    "SOURCE_COMMIT",
    "SOURCE_BUNDLE_DIGEST",
}


class _CloudFormationLoader(yaml.SafeLoader):
    """Preserve intrinsics and reject duplicate keys."""

    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_intrinsic(
    loader: _CloudFormationLoader,
    tag_suffix: str,
    node: yaml.Node,
) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    name = {
        "Ref": "Ref",
        "Sub": "Fn::Sub",
        "GetAtt": "Fn::GetAtt",
    }.get(tag_suffix, f"Fn::{tag_suffix}")
    return {name: value}


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_template(path: Path) -> dict[str, Any]:
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)
    assert isinstance(loaded, dict)
    return loaded


def _load_policy(name: str) -> dict[str, Any]:
    return json.loads((POLICY_ROOT / name).read_text(encoding="utf-8"))


def _actions(statement: dict[str, Any]) -> set[str]:
    value = statement.get("Action", [])
    if isinstance(value, str):
        return {value}
    return set(value)


def _allow_statements(policy: dict[str, Any]) -> Iterable[dict[str, Any]]:
    return (
        statement
        for statement in policy["Statement"]
        if isinstance(statement, dict) and statement.get("Effect") == "Allow"
    )


def _policy_for_role(template: dict[str, Any], logical_id: str) -> dict[str, Any]:
    policies = template["Resources"][logical_id]["Properties"]["Policies"]
    assert len(policies) == 1
    return policies[0]["PolicyDocument"]


def _by_sid(policy: dict[str, Any], sid: str) -> dict[str, Any]:
    return next(
        statement
        for statement in policy["Statement"]
        if isinstance(statement, dict) and statement.get("Sid") == sid
    )


@pytest.fixture(scope="module")
def authority() -> dict[str, Any]:
    rendered = broker_seed.render_pep_template_from_source(
        source=AUTHORITY_TEMPLATE.read_bytes(),
        protection_enabled=True,
    )
    loaded = yaml.load(
        rendered.decode("utf-8"),
        Loader=_CloudFormationLoader,
    )
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="module")
def management() -> dict[str, Any]:
    return _load_template(MANAGEMENT_TEMPLATE)


def test_templates_parse_without_duplicate_keys() -> None:
    assert _load_template(AUTHORITY_TEMPLATE)["AWSTemplateFormatVersion"] == "2010-09-09"
    assert _load_template(MANAGEMENT_TEMPLATE)["AWSTemplateFormatVersion"] == "2010-09-09"

    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load(
            "Resources:\n  Exact: first\n  Exact: second\n",
            Loader=_CloudFormationLoader,
        )


def test_templates_have_closed_resource_inventories(
    authority: dict[str, Any], management: dict[str, Any]
) -> None:
    assert {
        name: resource["Type"] for name, resource in management["Resources"].items()
    } == {
        "MutationServiceRole": "AWS::IAM::Role",
        "ReadbackServiceRole": "AWS::IAM::Role",
        "RepairInvokerPermissionSet": "AWS::SSO::PermissionSet",
        "RepairInvokerAssignment": "AWS::SSO::Assignment",
    }
    assert {
        name: resource["Type"] for name, resource in authority["Resources"].items()
    } == {
        "RepairLedgerKey": "AWS::KMS::Key",
        "RepairLedgerKeyAlias": "AWS::KMS::Alias",
        "RepairLedger": "AWS::DynamoDB::Table",
        "PlanLogGroup": "AWS::Logs::LogGroup",
        "RepairLogGroup": "AWS::Logs::LogGroup",
        "ReconcileLogGroup": "AWS::Logs::LogGroup",
        "PlanExecutionRole": "AWS::IAM::Role",
        "RepairExecutionRole": "AWS::IAM::Role",
        "ReconcileExecutionRole": "AWS::IAM::Role",
        "InvocationAuthorityInspectorRole": "AWS::IAM::Role",
        "RepairCodeSigningConfig": "AWS::Lambda::CodeSigningConfig",
        "PlanFunction": "AWS::Lambda::Function",
        "PlanRuntimeManagementConfig": (
            "AWS::Lambda::RuntimeManagementConfig"
        ),
        "PlanFunctionVersion": "AWS::Lambda::Version",
        "PlanAlias": "AWS::Lambda::Alias",
        "PlanEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
        "RepairFunction": "AWS::Lambda::Function",
        "RepairRuntimeManagementConfig": (
            "AWS::Lambda::RuntimeManagementConfig"
        ),
        "RepairFunctionVersion": "AWS::Lambda::Version",
        "RepairAlias": "AWS::Lambda::Alias",
        "RepairEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
        "ReconcileFunction": "AWS::Lambda::Function",
        "ReconcileRuntimeManagementConfig": (
            "AWS::Lambda::RuntimeManagementConfig"
        ),
        "ReconcileFunctionVersion": "AWS::Lambda::Version",
        "ReconcileAlias": "AWS::Lambda::Alias",
        "ReconcileEventInvokeConfig": "AWS::Lambda::EventInvokeConfig",
    }


def test_templates_are_hard_bound_to_accounts_region_and_no_production(
    authority: dict[str, Any], management: dict[str, Any]
) -> None:
    for template, own_account in (
        (authority, AUTHORITY_ACCOUNT),
        (management, MANAGEMENT_ACCOUNT),
    ):
        assert template["Parameters"]["AuthorityAccountId"]["AllowedValues"] == [
            AUTHORITY_ACCOUNT
        ]
        assert template["Parameters"]["ManagementAccountId"]["AllowedValues"] == [
            MANAGEMENT_ACCOUNT
        ]
        assert "AccountAndRegionMustMatch" in template["Rules"]
        assert template["Outputs"]["ProductionAuthorized"]["Value"] == "false"
        serialized = json.dumps(template, sort_keys=True)
        assert own_account in serialized
        assert REGION in serialized


def test_management_trust_is_management_first_but_role_exact(
    management: dict[str, Any]
) -> None:
    mutation = management["Resources"]["MutationServiceRole"]["Properties"]
    readback = management["Resources"]["ReadbackServiceRole"]["Properties"]
    assert mutation["RoleName"] == "ScanalyzeBootstrapPlanRepairMutation"
    assert readback["RoleName"] == "ScanalyzeBootstrapPlanRepairReadback"
    assert mutation["Path"] == readback["Path"] == "/scanalyze/platform-authority/"

    mutation_trust = mutation["AssumeRolePolicyDocument"]["Statement"][0]
    readback_trust = readback["AssumeRolePolicyDocument"]["Statement"][0]
    for statement in (mutation_trust, readback_trust):
        assert _actions(statement) == {"sts:AssumeRole", "sts:SetSourceIdentity"}
        assert statement["Principal"] == {
            "AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::042360977644:root"}
        }
        assert statement["Condition"]["StringEquals"]["aws:PrincipalAccount"] == (
            AUTHORITY_ACCOUNT
        )
        assert "aws:PrincipalArn" in statement["Condition"]["ArnEquals"]
        assert "AWSReservedSSO" not in json.dumps(statement)

    assert "ScanalyzeBootstrapPlanRepairExecution" in json.dumps(mutation_trust)
    assert {
        "ScanalyzeBootstrapPlanRepairPlan",
        "ScanalyzeBootstrapPlanRepairReconcile",
    }.issubset(
        {
            name
            for name in (
                "ScanalyzeBootstrapPlanRepairPlan",
                "ScanalyzeBootstrapPlanRepairReconcile",
            )
            if name in json.dumps(readback_trust)
        }
    )


def test_management_mutation_role_has_exactly_two_writes(
    management: dict[str, Any]
) -> None:
    policy = _policy_for_role(management, "MutationServiceRole")
    effect = _by_sid(policy, "PerformOnlyTwoExactPlanPolicyRepairMutations")
    assert _actions(effect) == MUTATIONS
    assert effect["Resource"] == [
        {"Ref": "IdentityCenterInstanceArn"},
        {"Ref": "PlanPermissionSetArn"},
        {
            "Fn::Sub": (
                "arn:${AWS::Partition}:sso:::account/${AuthorityAccountId}"
            )
        },
    ]
    assert effect["Condition"] == {
        "StringEquals": {
            "aws:RequestedRegion": REGION,
            "sso:PrimaryRegion": REGION,
        }
    }
    denied = _by_sid(policy, "DenyEveryOtherIdentityCenterMutation")
    assert FORBIDDEN_MUTATIONS.issubset(_actions(denied))
    assert "sso:CreateAccountAssignment" in _actions(denied)
    assert "sso:CreateAccountAssignment" not in set().union(
        *(_actions(statement) for statement in _allow_statements(policy))
    )


def test_management_readback_role_has_no_write_or_relay(
    management: dict[str, Any]
) -> None:
    policy = _policy_for_role(management, "ReadbackServiceRole")
    allowed = set().union(*(_actions(item) for item in _allow_statements(policy)))
    assert not MUTATIONS.intersection(allowed)
    assert "sso:CreateAccountAssignment" not in allowed
    assert "sts:AssumeRole" not in allowed
    denied = _by_sid(policy, "DenyEveryProtectedEffectAndRelay")
    assert MUTATIONS | FORBIDDEN_MUTATIONS <= _actions(denied)


def test_human_permission_set_is_invoke_only_and_exactly_assigned(
    management: dict[str, Any]
) -> None:
    permission_set = management["Resources"]["RepairInvokerPermissionSet"][
        "Properties"
    ]
    assert permission_set["Name"] == INVOKER_PERMISSION_SET
    assert len(permission_set["Name"]) <= 32
    assert permission_set["SessionDuration"] == "PT1H"
    assert "RelayState" not in permission_set
    policy = permission_set["InlinePolicy"]
    allowed = set().union(*(_actions(item) for item in _allow_statements(policy)))
    assert allowed == {"lambda:InvokeFunction"}
    invoke = _by_sid(policy, "InvokeOnlyExactPrivatePlanRepairAliases")
    assert {
        item["Fn::Sub"] for item in invoke["Resource"]
    } == {
        "arn:${AWS::Partition}:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-plan-policy-plan:plan-v1",
        "arn:${AWS::Partition}:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-plan-policy-repair:repair-v1",
        "arn:${AWS::Partition}:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-plan-policy-reconcile:reconcile-v1",
    }
    assert _by_sid(policy, "DenyAllFunctionUrls") == {
        "Sid": "DenyAllFunctionUrls",
        "Effect": "Deny",
        "Action": "lambda:InvokeFunctionUrl",
        "Resource": "*",
    }

    assignment_resource = management["Resources"]["RepairInvokerAssignment"]
    assert assignment_resource["Condition"] == "CreateRepairInvokerAssignment"
    assignment = assignment_resource["Properties"]
    assert assignment["PrincipalType"] == "USER"
    assert assignment["TargetId"] == AUTHORITY_ACCOUNT
    assert assignment["TargetType"] == "AWS_ACCOUNT"
    assert assignment["PrincipalId"] == {"Ref": "RepairPrincipalId"}


def test_temporary_assignment_switch_is_explicit_and_fail_closed(
    management: dict[str, Any]
) -> None:
    parameter = management["Parameters"]["RepairInvokerAssignmentEnabled"]
    assert parameter == {
        "Type": "String",
        "AllowedValues": ["false", "true"],
    }
    assert "Default" not in parameter
    assert management["Conditions"]["CreateRepairInvokerAssignment"] == {
        "Fn::Equals": [
            {"Ref": "RepairInvokerAssignmentEnabled"},
            "true",
        ]
    }
    assert management["Outputs"]["RepairInvokerAssignmentMode"]["Value"] == {
        "Ref": "RepairInvokerAssignmentEnabled"
    }


def test_assignment_true_to_false_update_removes_only_temporary_assignment(
    management: dict[str, Any]
) -> None:
    resources = management["Resources"]
    conditions = {
        name: resource.get("Condition") for name, resource in resources.items()
    }
    assert conditions == {
        "MutationServiceRole": None,
        "ReadbackServiceRole": None,
        "RepairInvokerPermissionSet": None,
        "RepairInvokerAssignment": "CreateRepairInvokerAssignment",
    }

    unconditional = {
        name for name, condition in conditions.items() if condition is None
    }
    assignment_enabled = unconditional | {
        name
        for name, condition in conditions.items()
        if condition == "CreateRepairInvokerAssignment"
    }
    assignment_disabled = unconditional

    assert assignment_enabled == set(resources)
    assert assignment_disabled == {
        "MutationServiceRole",
        "ReadbackServiceRole",
        "RepairInvokerPermissionSet",
    }
    assert assignment_enabled - assignment_disabled == {"RepairInvokerAssignment"}
    assert assignment_disabled - assignment_enabled == set()


def test_portable_policies_preserve_exact_boundaries() -> None:
    invoker = _load_policy(
        "platform-authority-bootstrap-plan-repair-invoker-role.json"
    )
    mutation = _load_policy(
        "platform-authority-bootstrap-plan-repair-mutation-service-role.json"
    )
    readback = _load_policy(
        "platform-authority-bootstrap-plan-repair-readback-service-role.json"
    )

    invoker_allowed = set().union(
        *(_actions(statement) for statement in _allow_statements(invoker))
    )
    assert invoker_allowed == {"lambda:InvokeFunction"}
    assert _actions(
        _by_sid(mutation, "PerformOnlyTwoExactPlanPolicyRepairMutations")
    ) == MUTATIONS
    mutation_allowed = set().union(
        *(_actions(statement) for statement in _allow_statements(mutation))
    )
    readback_allowed = set().union(
        *(_actions(statement) for statement in _allow_statements(readback))
    )
    assert not ({"sso:CreateAccountAssignment"} | FORBIDDEN_MUTATIONS).intersection(
        mutation_allowed
    )
    assert not (MUTATIONS | FORBIDDEN_MUTATIONS).intersection(readback_allowed)

    effect = _by_sid(mutation, "PerformOnlyTwoExactPlanPolicyRepairMutations")
    assert effect["Resource"] == [
        "${identity_center_instance_arn}",
        "${plan_permission_set_arn}",
        "arn:aws:sso:::account/042360977644",
    ]
    for policy in (mutation, readback):
        assignments = _by_sid(policy, "ListAssignmentsAcrossObservedAccounts")
        assert assignments["Resource"].count("arn:aws:sso:::account/*") == 1
        for statement in _allow_statements(policy):
            if _actions(statement).intersection(MUTATIONS):
                assert statement.get("Resource") != "*"
                assert "*" not in json.dumps(statement["Resource"])


def test_authority_functions_are_private_version_pinned_and_zero_retry(
    authority: dict[str, Any]
) -> None:
    resources = authority["Resources"]
    resource_types = [item["Type"] for item in resources.values()]
    assert resource_types.count("AWS::Lambda::Function") == 3
    assert resource_types.count("AWS::Lambda::Version") == 3
    assert resource_types.count("AWS::Lambda::RuntimeManagementConfig") == 3
    assert resource_types.count("AWS::Lambda::Alias") == 3
    assert resource_types.count("AWS::Lambda::EventInvokeConfig") == 3
    assert "AWS::Lambda::Permission" not in resource_types
    assert "AWS::Lambda::Url" not in resource_types
    assert "AWS::Lambda::EventSourceMapping" not in resource_types

    for logical_id, (name, handler, alias_name, timeout) in FUNCTIONS.items():
        function = resources[logical_id]["Properties"]
        assert function["FunctionName"] == name
        assert function["Handler"] == handler
        assert function["Runtime"] == "python3.12"
        assert function["MemorySize"] == 1024
        assert function["Timeout"] == timeout
        assert function["ReservedConcurrentExecutions"] == 1
        assert function["CodeSigningConfigArn"] == {"Ref": "RepairCodeSigningConfig"}
        assert function["Code"] == {
            "S3Bucket": {"Ref": "ArtifactBucket"},
            "S3Key": {"Ref": "ArtifactKey"},
            "S3ObjectVersion": {"Ref": "ArtifactVersion"},
        }

        stem = logical_id.removesuffix("Function")
        version = resources[f"{logical_id}Version"]["Properties"]
        version_resource = resources[f"{logical_id}Version"]
        runtime_management = resources[
            f"{stem}RuntimeManagementConfig"
        ]
        alias = resources[f"{stem}Alias"]["Properties"]
        event = resources[f"{stem}EventInvokeConfig"]["Properties"]
        assert version["CodeSha256"] == {"Ref": "ArtifactCodeSha256"}
        assert version_resource["DependsOn"] == (
            f"{stem}RuntimeManagementConfig"
        )
        assert runtime_management == {
            "Type": "AWS::Lambda::RuntimeManagementConfig",
            "Properties": {
                "FunctionName": {"Ref": logical_id},
                "UpdateRuntimeOn": "FunctionUpdate",
            },
        }
        assert version["Description"] == {
            "Fn::Sub": (
                f"GUG-376 {stem.lower()} version "
                "${ImmutableConfigurationDigest}"
            )
        }
        assert alias["Name"] == alias_name
        assert alias["FunctionVersion"] == {
            "Fn::GetAtt": f"{logical_id}Version.Version"
        }
        assert event["FunctionName"] == {"Ref": logical_id}
        assert event["Qualifier"] == alias_name
        assert event["MaximumEventAgeInSeconds"] == 60
        assert event["MaximumRetryAttempts"] == 0
        assert "DestinationConfig" not in event


def test_function_environments_are_closed_and_version_chained(
    authority: dict[str, Any]
) -> None:
    assert authority["Parameters"]["RepairId"]["AllowedPattern"] == (
        "^gug376-plan-permission-repair-[a-f0-9]{64}$"
    )
    assert authority["Parameters"]["SourceBundleDigest"]["AllowedPattern"] == (
        "^sha256:[a-f0-9]{64}$"
    )
    assert authority["Parameters"]["ExpectedPermissionSetDescription"] == {
        "Type": "String",
        "MinLength": 1,
        "MaxLength": 700,
        "AllowedPattern": "^[ -~]{1,700}$",
    }
    resources = authority["Resources"]
    plan = resources["PlanFunction"]["Properties"]["Environment"]["Variables"]
    repair = resources["RepairFunction"]["Properties"]["Environment"]["Variables"]
    reconcile = resources["ReconcileFunction"]["Properties"]["Environment"][
        "Variables"
    ]
    assert set(plan) == COMMON_ENVIRONMENT
    assert set(repair) == COMMON_ENVIRONMENT | {"PLAN_FUNCTION_VERSION"}
    assert set(reconcile) == COMMON_ENVIRONMENT | {
        "PLAN_FUNCTION_VERSION",
        "REPAIR_FUNCTION_VERSION",
    }
    for environment in (plan, repair, reconcile):
        assert "FUNCTION_MODE" not in environment
        assert "PRODUCTION_AUTHORIZED" not in environment
        assert "MUTATION_SERVICE_ROLE_ARN" not in environment
        assert environment["CURRENT_POLICY_DIGEST"] == {"Ref": "CurrentPolicyDigest"}
        assert environment["DESIRED_POLICY_DIGEST"] == {"Ref": "DesiredPolicyDigest"}
        assert environment["SOURCE_BUNDLE_DIGEST"] == {
            "Ref": "SourceBundleDigest"
        }
        assert environment["EXPECTED_PERMISSION_SET_DESCRIPTION"] == {
            "Ref": "ExpectedPermissionSetDescription"
        }
        assert environment["EXPECTED_PLAN_PERMISSION_SET_TAGS_JSON"] == {
            "Ref": "ExpectedPlanPermissionSetTagsJson"
        }
        assert environment["IMMU_CONFIG_DIGEST"] == {
            "Ref": "ImmutableConfigurationDigest"
        }
        assert "EXPECTED_PERMISSION_SET_TAGS_JSON" not in environment


def test_invoker_tags_are_derived_only_from_source_commit_and_constants(
    management: dict[str, Any],
) -> None:
    tags = management["Resources"]["RepairInvokerPermissionSet"][
        "Properties"
    ]["Tags"]
    assert {item["Key"]: item["Value"] for item in tags} == {
        **runtime.INVOKER_PERMISSION_SET_TAGS,
        "source_commit": {"Ref": "SourceCommit"},
    }


def test_template_worst_case_lambda_environments_fit_provider_limit(
    authority: dict[str, Any],
) -> None:
    parameters = authority["Parameters"]
    assert parameters["ExpectedPlanPermissionSetTagsJson"]["MaxLength"] == 1024
    assert parameters["ExpectedPlanPermissionSetTagsJson"][
        "AllowedPattern"
    ] == "^[ -~]{2,1024}$"
    assert parameters["ImmutableConfigurationDigest"] == {
        "Type": "String",
        "MaxLength": 71,
        "AllowedPattern": "^sha256:[a-f0-9]{64}$",
    }
    generated_maximums = {
        "RepairLedger": len(
            "scanalyze-platform-authority-plan-policy-repair-ledger"
        ),
        "RepairCodeSigningConfig": len(
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-"
        )
        + 17,
        "RepairLedgerKey.Arn": len(
            "arn:aws:kms:us-east-1:042360977644:key/"
        )
        + 36,
        "PlanFunctionVersion.Version": (
            MAX_PUBLISHED_FUNCTION_VERSION_BYTES
        ),
        "RepairFunctionVersion.Version": (
            MAX_PUBLISHED_FUNCTION_VERSION_BYTES
        ),
    }

    def maximum_value_bytes(value: Mapping[str, Any]) -> int:
        if set(value) == {"Ref"}:
            reference = str(value["Ref"])
            if reference in generated_maximums:
                return generated_maximums[reference]
            parameter = parameters[reference]
            if "MaxLength" in parameter:
                return int(parameter["MaxLength"])
            return max(
                len(str(item).encode("utf-8"))
                for item in parameter["AllowedValues"]
            )
        assert set(value) == {"Fn::GetAtt"}
        return generated_maximums[str(value["Fn::GetAtt"])]

    totals: dict[str, int] = {}
    for mode, logical_id in (
        ("plan", "PlanFunction"),
        ("repair", "RepairFunction"),
        ("reconcile", "ReconcileFunction"),
    ):
        environment = authority["Resources"][logical_id]["Properties"][
            "Environment"
        ]["Variables"]
        totals[mode] = sum(
            len(key.encode("utf-8")) + maximum_value_bytes(value)
            for key, value in environment.items()
        )
        assert totals[mode] <= LAMBDA_ENVIRONMENT_LIMIT_BYTES
    assert totals == {"plan": 3856, "repair": 3897, "reconcile": 3940}


def test_ledger_is_retained_encrypted_protected_and_stage_writer_bound(
    authority: dict[str, Any]
) -> None:
    key = authority["Resources"]["RepairLedgerKey"]
    alias = authority["Resources"]["RepairLedgerKeyAlias"]
    ledger = authority["Resources"]["RepairLedger"]
    for resource in (key, alias, ledger):
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"
    properties = ledger["Properties"]
    assert properties["TableName"] == (
        "scanalyze-platform-authority-plan-policy-repair-ledger"
    )
    assert properties["BillingMode"] == "PAY_PER_REQUEST"
    assert properties["DeletionProtectionEnabled"] is True
    assert properties["PointInTimeRecoverySpecification"] == {
        "PointInTimeRecoveryEnabled": True,
        "RecoveryPeriodInDays": 35,
    }
    assert properties["SSESpecification"] == {
        "SSEEnabled": True,
        "SSEType": "KMS",
        "KMSMasterKeyId": {"Fn::GetAtt": "RepairLedgerKey.Arn"},
    }
    statements = properties["ResourcePolicy"]["PolicyDocument"]["Statement"]
    by_sid = {statement["Sid"]: statement for statement in statements}
    assert _actions(by_sid["DenyItemCreationOutsideExactWriters"]) == {
        "dynamodb:PutItem"
    }
    assert by_sid["DenyItemCreationOutsideExactWriters"]["Condition"] == {
        "ArnNotEquals": {
            "aws:PrincipalArn": [
                {"Fn::GetAtt": "PlanExecutionRole.Arn"},
                {"Fn::GetAtt": "ReconcileExecutionRole.Arn"},
            ]
        }
    }
    assert by_sid["DenyPlanWritesOutsideBaseKey"]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {"Fn::GetAtt": "PlanExecutionRole.Arn"}
        },
        "ForAllValues:StringNotEquals": {
            "dynamodb:LeadingKeys": [{"Ref": "RepairId"}]
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }
    assert by_sid["DenyPlanWritesWithoutBaseKey"]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {"Fn::GetAtt": "PlanExecutionRole.Arn"}
        },
        "Null": {"dynamodb:LeadingKeys": "true"},
    }
    assert by_sid[
        "DenyReconcileWritesOutsideAttestationKey"
    ]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {
                "Fn::GetAtt": "ReconcileExecutionRole.Arn"
            }
        },
        "ForAllValues:StringNotEquals": {
            "dynamodb:LeadingKeys": [
                {"Fn::Sub": "${RepairId}#reconcile-v1"},
                {"Fn::Sub": "${RepairId}#reconcile-attempt-v1"},
            ]
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }
    assert by_sid[
        "DenyReconcileWritesWithoutAttestationKey"
    ]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {
                "Fn::GetAtt": "ReconcileExecutionRole.Arn"
            }
        },
        "Null": {"dynamodb:LeadingKeys": "true"},
    }
    assert _actions(by_sid["DenyPlanConsumptionOutsideRepairExecution"]) == {
        "dynamodb:UpdateItem"
    }
    assert by_sid["DenyPlanConsumptionOutsideRepairExecution"]["Condition"] == {
        "ArnNotEquals": {
            "aws:PrincipalArn": {"Fn::GetAtt": "RepairExecutionRole.Arn"}
        }
    }
    assert by_sid["DenyRepairWritesOutsideBaseKey"]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {"Fn::GetAtt": "RepairExecutionRole.Arn"}
        },
        "ForAllValues:StringNotEquals": {
            "dynamodb:LeadingKeys": [{"Ref": "RepairId"}]
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }
    assert by_sid["DenyRepairWritesWithoutBaseKey"]["Condition"] == {
        "ArnEquals": {
            "aws:PrincipalArn": {"Fn::GetAtt": "RepairExecutionRole.Arn"}
        },
        "Null": {"dynamodb:LeadingKeys": "true"},
    }
    assert _actions(by_sid["DenyEveryUnsupportedLedgerMutation"]) == (
        DYNAMODB_WRITES - {"dynamodb:PutItem", "dynamodb:UpdateItem"}
    )


def test_runtime_expected_ledger_policy_is_exactly_the_resolved_template_policy(
    authority: dict[str, Any],
) -> None:
    repair_id = "gug376-plan-permission-repair-" + "1" * 64
    table_arn = (
        "arn:aws:dynamodb:us-east-1:042360977644:table/"
        "scanalyze-platform-authority-plan-policy-repair-ledger"
    )
    roles = {
        "PlanExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeBootstrapPlanRepairPlan"
        ),
        "RepairExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeBootstrapPlanRepairExecution"
        ),
        "ReconcileExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeBootstrapPlanRepairReconcile"
        ),
    }

    def resolve(value: Any) -> Any:
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if not isinstance(value, dict):
            return value
        if set(value) == {"Ref"} and value["Ref"] == "RepairId":
            return repair_id
        if set(value) == {"Fn::GetAtt"}:
            return roles[value["Fn::GetAtt"]]
        if set(value) == {"Fn::Sub"}:
            return (
                value["Fn::Sub"]
                .replace("${AWS::Partition}", "aws")
                .replace("${AuthorityAccountId}", AUTHORITY_ACCOUNT)
                .replace("${RepairId}", repair_id)
            )
        return {key: resolve(item) for key, item in value.items()}

    rendered = resolve(
        authority["Resources"]["RepairLedger"]["Properties"]["ResourcePolicy"][
            "PolicyDocument"
        ]
    )
    expected = runtime._expected_ledger_resource_policy(table_arn, repair_id)
    assert runtime.canonical_json(rendered) == runtime.canonical_json(expected)
    for drifted in (
        {**rendered, "Statement": rendered["Statement"][:-1]},
        {
            **rendered,
            "Statement": [
                {
                    **rendered["Statement"][0],
                    "Resource": table_arn + "-foreign",
                },
                *rendered["Statement"][1:],
            ],
        },
    ):
        assert runtime.canonical_json(drifted) != runtime.canonical_json(expected)


@pytest.mark.parametrize(
    ("outside_sid", "missing_sid", "role", "exact_keys"),
    [
        (
            "DenyPlanWritesOutsideBaseKey",
            "DenyPlanWritesWithoutBaseKey",
            "PlanExecutionRole",
            [{"Ref": "RepairId"}],
        ),
        (
            "DenyRepairWritesOutsideBaseKey",
            "DenyRepairWritesWithoutBaseKey",
            "RepairExecutionRole",
            [{"Ref": "RepairId"}],
        ),
        (
            "DenyReconcileWritesOutsideAttestationKey",
            "DenyReconcileWritesWithoutAttestationKey",
            "ReconcileExecutionRole",
            [
                {"Fn::Sub": "${RepairId}#reconcile-v1"},
                {"Fn::Sub": "${RepairId}#reconcile-attempt-v1"},
            ],
        ),
    ],
)
def test_external_ledger_grant_cannot_bypass_exact_writer_key(
    authority: dict[str, Any],
    outside_sid: str,
    missing_sid: str,
    role: str,
    exact_keys: list[dict[str, str]],
) -> None:
    statements = authority["Resources"]["RepairLedger"]["Properties"][
        "ResourcePolicy"
    ]["PolicyDocument"]["Statement"]
    by_sid = {statement["Sid"]: statement for statement in statements}
    expected_principal = {"Fn::GetAtt": f"{role}.Arn"}
    outside = by_sid[outside_sid]
    missing = by_sid[missing_sid]
    assert outside["Effect"] == missing["Effect"] == "Deny"
    assert outside["Condition"]["ArnEquals"]["aws:PrincipalArn"] == (
        expected_principal
    )
    assert missing["Condition"]["ArnEquals"]["aws:PrincipalArn"] == (
        expected_principal
    )
    assert outside["Condition"]["ForAllValues:StringNotEquals"] == {
        "dynamodb:LeadingKeys": exact_keys
    }
    assert outside["Condition"]["Null"] == {
        "dynamodb:LeadingKeys": "false"
    }
    assert missing["Condition"]["Null"] == {
        "dynamodb:LeadingKeys": "true"
    }


def test_execution_roles_preserve_plan_repair_reconcile_separation(
    authority: dict[str, Any]
) -> None:
    plan = _policy_for_role(authority, "PlanExecutionRole")
    repair = _policy_for_role(authority, "RepairExecutionRole")
    reconcile = _policy_for_role(authority, "ReconcileExecutionRole")
    plan_allowed = set().union(*(_actions(item) for item in _allow_statements(plan)))
    repair_allowed = set().union(
        *(_actions(item) for item in _allow_statements(repair))
    )
    reconcile_allowed = set().union(
        *(_actions(item) for item in _allow_statements(reconcile))
    )
    assert "dynamodb:PutItem" in plan_allowed
    assert "dynamodb:UpdateItem" not in plan_allowed
    assert "dynamodb:UpdateItem" in repair_allowed
    assert "dynamodb:PutItem" not in repair_allowed
    assert DYNAMODB_WRITES.intersection(reconcile_allowed) == {
        "dynamodb:PutItem"
    }
    reconcile_write = _by_sid(reconcile, "WriteExactReconcileAttestation")
    assert reconcile_write["Condition"] == {
        "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [
                {"Fn::Sub": "${RepairId}#reconcile-v1"},
                {"Fn::Sub": "${RepairId}#reconcile-attempt-v1"},
            ]
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }
    reconcile_read = _by_sid(reconcile, "ReadExactRepairLedgerItem")
    assert reconcile_read["Condition"] == {
        "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [
                {"Ref": "RepairId"},
                {"Fn::Sub": "${RepairId}#reconcile-v1"},
                {"Fn::Sub": "${RepairId}#reconcile-attempt-v1"},
            ]
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }
    assert not any(action.startswith("sso:") for action in plan_allowed)
    assert not any(action.startswith("sso:") for action in repair_allowed)
    assert not any(action.startswith("sso:") for action in reconcile_allowed)
    assert "ScanalyzeBootstrapPlanRepairMutation" in json.dumps(repair)
    assert "ScanalyzeBootstrapPlanRepairMutation" not in json.dumps(plan)
    assert "ScanalyzeBootstrapPlanRepairMutation" not in json.dumps(reconcile)
    assert "ScanalyzeBootstrapPlanRepairReadback" in json.dumps(plan)
    assert "ScanalyzeBootstrapPlanRepairReadback" in json.dumps(reconcile)
    assert "#reconcile-attempt-v1" not in json.dumps(plan)
    assert "#reconcile-attempt-v1" not in json.dumps(repair)
    assert "#reconcile-attempt-v1" in json.dumps(reconcile)
    for policy, sid, function_name in (
        (
            plan,
            "DenyRoleUseOutsideExactPlanFunction",
            "scanalyze-platform-authority-plan-policy-plan",
        ),
        (
            repair,
            "DenyRoleUseOutsideExactRepairFunction",
            "scanalyze-platform-authority-plan-policy-repair",
        ),
        (
            reconcile,
            "DenyRoleUseOutsideExactReconcileFunction",
            "scanalyze-platform-authority-plan-policy-reconcile",
        ),
    ):
        source_bound = _by_sid(policy, sid)
        assert source_bound["Effect"] == "Deny"
        assert _actions(source_bound) == {"*"}
        assert source_bound["Resource"] == "*"
        assert source_bound["Condition"] == {
            "ArnNotEquals": {
                "lambda:SourceFunctionArn": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:lambda:us-east-1:"
                        "${AuthorityAccountId}:function:"
                        f"{function_name}"
                    )
                }
            }
        }
        assert {
            "lambda:GetFunctionCodeSigningConfig",
            "lambda:GetFunctionConcurrency",
            "lambda:GetFunctionConfiguration",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:GetRuntimeManagementConfig",
        }.issubset(
            _actions(_by_sid(policy, "ReadExactPepRuntimeConfiguration"))
        )


def test_invocation_inspector_is_read_only_and_cannot_chain(
    authority: dict[str, Any]
) -> None:
    role = authority["Resources"]["InvocationAuthorityInspectorRole"]["Properties"]
    trust = role["AssumeRolePolicyDocument"]["Statement"][0]
    assert _actions(trust) == {"sts:AssumeRole", "sts:SetSourceIdentity"}
    assert trust["Principal"] == {
        "AWS": {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::${AuthorityAccountId}:root"
            )
        }
    }
    assert trust["Condition"]["StringEquals"] == {
        "aws:PrincipalAccount": {"Ref": "AuthorityAccountId"}
    }
    principals = trust["Condition"]["ArnEquals"]["aws:PrincipalArn"]
    assert principals == [
        {"Fn::GetAtt": "PlanExecutionRole.Arn"},
        {"Fn::GetAtt": "RepairExecutionRole.Arn"},
        {"Fn::GetAtt": "ReconcileExecutionRole.Arn"},
    ]
    policy = _policy_for_role(authority, "InvocationAuthorityInspectorRole")
    allowed = set().union(*(_actions(item) for item in _allow_statements(policy)))
    assert "lambda:InvokeFunction" not in allowed
    assert "sts:AssumeRole" not in allowed
    assert not DYNAMODB_WRITES.intersection(allowed)
    assert not MUTATIONS.intersection(allowed)
    assert _actions(_by_sid(policy, "DenyRoleChaining")) == {"sts:AssumeRole"}
    assert set(_by_sid(policy, "DenyUnreviewedActions")["NotAction"]) == {
        "ec2:DescribeRegions",
        "iam:GetAccountAuthorizationDetails",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "lambda:GetPolicy",
        "lambda:ListAliases",
        "lambda:ListEventSourceMappings",
        "lambda:ListFunctionEventInvokeConfigs",
        "lambda:ListFunctions",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListVersionsByFunction",
        "sts:GetCallerIdentity",
    }


def test_causal_and_dynamic_bindings_are_exact_readback_parameters_not_outputs(
    authority: dict[str, Any], management: dict[str, Any]
) -> None:
    for key in (
        "PrincipalId",
        "ExpectedPermissionSetDescription",
        "ExpectedPlanPermissionSetTagsJson",
        "ArtifactVersion",
    ):
        assert "NoEcho" not in authority["Parameters"][key]
    for key in ("RepairPrincipalId", "RepairPrincipalUserArn"):
        assert "NoEcho" not in management["Parameters"][key]
    assert management["Parameters"]["RepairPrincipalId"]["AllowedPattern"]
    for template in (authority, management):
        output_values = json.dumps(
            {
                name: definition["Value"]
                for name, definition in template["Outputs"].items()
            },
            sort_keys=True,
        )
        assert '"Ref": "PrincipalId"' not in output_values
        assert '"Ref": "RepairPrincipalId"' not in output_values
        assert '"Ref": "ExpectedPlanPermissionSetTagsJson"' not in output_values
    assert authority["Parameters"]["BootstrapChangeSetName"]["AllowedPattern"] == (
        "^scanalyze-platform-authority-bootstrap-[0-9]{14}$"
    )
    assert authority["Parameters"]["CurrentPolicyDigest"]["AllowedPattern"] == (
        "^sha256:[a-f0-9]{64}$"
    )
    assert authority["Parameters"]["DesiredPolicyDigest"]["AllowedPattern"] == (
        "^sha256:[a-f0-9]{64}$"
    )


def test_templates_do_not_claim_runtime_or_production_authorization() -> None:
    for path in (AUTHORITY_TEMPLATE, MANAGEMENT_TEMPLATE):
        source = path.read_text(encoding="utf-8")
        assert "ProductionAuthorized:\n    Value: 'false'" in source
        assert "AWS::Lambda::Permission" not in source
        assert "AWS::Lambda::Url" not in source
        assert "FunctionUrlAuthType" not in source
