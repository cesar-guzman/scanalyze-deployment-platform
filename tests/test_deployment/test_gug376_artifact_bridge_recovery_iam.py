"""Focused offline IAM contracts for the GUG-376 artifact bridge recovery lanes."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "bootstrap/cfn-platform-authority-gug376-artifact-bootstrap-bridge.yaml"


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader: _Loader, node: yaml.MappingNode, deep: bool = False) -> Any:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


def _intrinsic(loader: _Loader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {"Ref" if suffix == "Ref" else f"Fn::{suffix}": value}


_Loader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping
)
_Loader.add_multi_constructor("!", _intrinsic)


def _load() -> dict[str, Any]:
    value = yaml.load(BRIDGE.read_text(encoding="utf-8"), Loader=_Loader)
    assert isinstance(value, dict)
    return value


def _statements(resource: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = resource["Properties"]["InlinePolicy"]["Statement"]
    return {item["Sid"]: item for item in raw}


def _actions(statement: Mapping[str, Any]) -> set[str]:
    value = statement.get("Action", [])
    if isinstance(value, str):
        return {value}
    assert isinstance(value, list)
    return set(value)


def _resources(statement: Mapping[str, Any]) -> list[Any]:
    value = statement.get("Resource")
    return value if isinstance(value, list) else [value]


def _sub(value: Any) -> str:
    assert isinstance(value, Mapping) and set(value) == {"Fn::Sub"}
    result = value["Fn::Sub"]
    return result[0] if isinstance(result, list) else result


def _present_resources(*, artifact: bool, cleanup: bool) -> set[str]:
    template = _load()
    enabled = {
        "CreateAssignment": artifact,
        "CreateCleanupAssignments": cleanup,
    }
    return {
        logical_id
        for logical_id, resource in template["Resources"].items()
        if resource.get("Condition") is None
        or enabled[resource["Condition"]]
    }


def _present_outputs(*, cleanup: bool) -> set[str]:
    outputs = _load()["Outputs"]
    return {
        key
        for key, output in outputs.items()
        if output.get("Condition") is None or cleanup
    }


def test_template_is_strict_body_safe_and_has_no_alias_shortcuts() -> None:
    raw = BRIDGE.read_bytes()
    assert len(raw) < 49 * 1024
    text = raw.decode("utf-8")
    assert "TemplateURL" not in text
    assert re.search(r"(?:^|\s)[&*][A-Za-z][A-Za-z0-9_-]*", text) is None
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load("a: 1\na: 2\n", Loader=_Loader)


def test_cleanup_lifecycle_is_independent_and_retires_every_cleanup_identity() -> None:
    template = _load()
    assert template["Parameters"]["CleanupAssignmentsEnabled"] == {
        "Type": "String",
        "Default": "true",
        "Description": "Independent retirement switch for failed-seed cleanup identities",
        "AllowedValues": ["true", "false"],
    }
    assert template["Conditions"] == {
        "CreateAssignment": {
            "Fn::Equals": [{"Ref": "AssignmentEnabled"}, "true"]
        },
        "CreateCleanupAssignments": {
            "Fn::Equals": [{"Ref": "CleanupAssignmentsEnabled"}, "true"]
        },
    }
    assert _present_resources(artifact=True, cleanup=True) == {
        "ArtifactBootstrapPermissionSet",
        "ArtifactBootstrapAssignment",
        "ManagementRecoveryRole",
        "RouteSeedCleanupPermissionSet",
        "RouteSeedCleanupAssignment",
        "BrokerSeedCleanupPermissionSet",
        "BrokerSeedCleanupAssignment",
    }
    assert _present_resources(artifact=False, cleanup=True) == {
        "ArtifactBootstrapPermissionSet",
        "ManagementRecoveryRole",
        "RouteSeedCleanupPermissionSet",
        "RouteSeedCleanupAssignment",
        "BrokerSeedCleanupPermissionSet",
        "BrokerSeedCleanupAssignment",
    }
    assert _present_resources(artifact=True, cleanup=False) == {
        "ArtifactBootstrapPermissionSet",
        "ArtifactBootstrapAssignment",
    }
    assert _present_resources(artifact=False, cleanup=False) == {
        "ArtifactBootstrapPermissionSet"
    }

    conditional_outputs = {
        "ManagementRecoveryRoleArn",
        "ManagementRecoveryRoleName",
        "RouteSeedCleanupPermissionSetArn",
        "BrokerSeedCleanupPermissionSetArn",
        "RouteSeedCleanupProfileName",
        "BrokerSeedCleanupProfileName",
    }
    assert {
        key
        for key, value in template["Outputs"].items()
        if value.get("Condition") == "CreateCleanupAssignments"
    } == conditional_outputs
    assert conditional_outputs.isdisjoint(_present_outputs(cleanup=False))
    assert set(template["Outputs"]) == {
        "ArtifactBootstrapPermissionSetArn",
        "AssignmentMode",
        "CleanupAssignmentMode",
        "CleanupNotAfter",
        "ManagementRecoveryRoleArn",
        "ManagementRecoveryRoleName",
        "RouteSeedCleanupPermissionSetArn",
        "BrokerSeedCleanupPermissionSetArn",
        "RouteSeedCleanupProfileName",
        "BrokerSeedCleanupProfileName",
        "AuthorityProfileName",
        "ProductionAuthorized",
    }
    assert template["Outputs"]["CleanupAssignmentMode"]["Value"] == {
        "Ref": "CleanupAssignmentsEnabled"
    }
    assert template["Outputs"]["CleanupNotAfter"]["Value"] == {
        "Ref": "CleanupNotAfter"
    }


def test_recovery_role_has_exact_cross_account_trust_and_is_read_only() -> None:
    role = _load()["Resources"]["ManagementRecoveryRole"]
    assert role["Condition"] == "CreateCleanupAssignments"
    properties = role["Properties"]
    assert properties["RoleName"] == "ScanalyzeGug376RouteBrokerRecovery"
    assert properties["Path"] == "/scanalyze/platform-authority/"
    trust = properties["AssumeRolePolicyDocument"]["Statement"]
    assert len(trust) == 2
    expected = {
        "TrustOnlyCreateDispatchRecovery": (
            "ScanalyzeGug376RouteCreateDispatchRecovery",
            "gug376-create-recovery-${SourceCommit}",
        ),
        "TrustOnlyExecuteDispatchRecovery": (
            "ScanalyzeGug376RouteExecuteDispatchRecovery",
            "gug376-execute-recovery-${SourceCommit}",
        ),
    }
    assert {statement["Sid"] for statement in trust} == set(expected)
    for statement in trust:
        role_name, source_identity = expected[statement["Sid"]]
        assert statement["Effect"] == "Allow"
        assert statement["Action"] == ["sts:AssumeRole", "sts:SetSourceIdentity"]
        assert _sub(statement["Principal"]["AWS"]) == (
            "arn:${AWS::Partition}:iam::${AuthorityAccountId}:root"
        )
        condition = statement["Condition"]
        assert _sub(condition["ArnEquals"]["aws:PrincipalArn"]) == (
            "arn:${AWS::Partition}:iam::${AuthorityAccountId}:role/" + role_name
        )
        assert _sub(condition["StringEquals"]["sts:SourceIdentity"]) == source_identity
        assert condition["DateGreaterThanEquals"] == {
            "aws:CurrentTime": {"Ref": "AccessNotBefore"}
        }
        assert condition["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "CleanupNotAfter"}
        }

    policy = properties["Policies"]
    assert len(policy) == 1
    statements = policy[0]["PolicyDocument"]["Statement"]
    allowed = set().union(
        *(_actions(item) for item in statements if item["Effect"] == "Allow")
    )
    assert allowed == {
        "sts:GetCallerIdentity",
        "cloudtrail:LookupEvents",
        "cloudformation:DescribeChangeSet",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "sso:DescribePermissionSet",
        "sso:DescribePermissionSetProvisioningStatus",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:GetPermissionsBoundaryForPermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListPermissionSetProvisioningStatus",
        "sso:ListTagsForResource",
    }
    denied = set().union(
        *(_actions(item) for item in statements if item["Effect"] == "Deny")
    )
    assert {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteStack",
        "kms:CancelKeyDeletion",
        "kms:ScheduleKeyDeletion",
        "lambda:DeleteFunction",
        "iam:DeleteRole",
    } <= denied
    assert not {
        "cloudformation:CreateChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteStack",
    } & allowed
    assert any(
        item.get("Condition")
        == {"DateGreaterThanEquals": {"aws:CurrentTime": {"Ref": "CleanupNotAfter"}}}
        for item in statements
    )
    wildcard_allows = {
        item["Sid"]: _actions(item)
        for item in statements
        if item["Effect"] == "Allow" and "*" in _resources(item)
    }
    assert wildcard_allows == {
        "ConfirmOnlyCurrentCaller": {"sts:GetCallerIdentity"},
        "ReadOnlyExactDispatchAudit": {"cloudtrail:LookupEvents"},
    }


def test_cleanup_permission_sets_and_assignments_are_exact() -> None:
    resources = _load()["Resources"]
    expected = {
        "route": (
            "RouteSeedCleanupPermissionSet",
            "RouteSeedCleanupAssignment",
            "ScanalyzeGug376RouteSeedCleanup",
            "ManagementAccountId",
        ),
        "broker": (
            "BrokerSeedCleanupPermissionSet",
            "BrokerSeedCleanupAssignment",
            "ScanalyzeGug376BrokerSeedCleanup",
            "AuthorityAccountId",
        ),
    }
    for permission_id, assignment_id, name, target in expected.values():
        permission = resources[permission_id]
        assignment = resources[assignment_id]
        assert permission["Condition"] == "CreateCleanupAssignments"
        assert permission["Properties"]["Name"] == name
        assert permission["Properties"]["SessionDuration"] == "PT1H"
        assert assignment["Condition"] == "CreateCleanupAssignments"
        assert assignment["Properties"] == {
            "InstanceArn": {"Ref": "IdentityCenterInstanceArn"},
            "PermissionSetArn": {
                "Fn::GetAtt": f"{permission_id}.PermissionSetArn"
            },
            "PrincipalId": {"Ref": "BootstrapPrincipalId"},
            "PrincipalType": "USER",
            "TargetId": {"Ref": target},
            "TargetType": "AWS_ACCOUNT",
        }
    assert len(resources["ArtifactBootstrapAssignment"]["Properties"]) == 6
    assert list(resources["ArtifactBootstrapAssignment"]["Properties"]).count(
        "InstanceArn"
    ) == 1


def test_delete_stack_is_one_exact_direct_mutation_per_cleanup_lane() -> None:
    resources = _load()["Resources"]
    expected = {
        "RouteSeedCleanupPermissionSet": (
            "${ManagementAccountId}",
            "scanalyze-platform-authority-gug376-temporary-change-set-route",
        ),
        "BrokerSeedCleanupPermissionSet": (
            "${AuthorityAccountId}",
            "scanalyze-platform-authority-gug376-route-broker",
        ),
    }
    for logical_id, (account, stack_name) in expected.items():
        statements = list(_statements(resources[logical_id]).values())
        delete = [
            item
            for item in statements
            if item["Effect"] == "Allow"
            and "cloudformation:DeleteStack" in _actions(item)
        ]
        assert len(delete) == 1
        assert _sub(delete[0]["Resource"]) == (
            "arn:${AWS::Partition}:cloudformation:us-east-1:"
            f"{account}:stack/{stack_name}/*"
        )
        assert delete[0]["Condition"] == {
            "StringEquals": {"aws:RequestedRegion": "us-east-1"},
            "Null": {"cloudformation:RoleArn": "true"},
            "DateGreaterThanEquals": {
                "aws:CurrentTime": {"Ref": "AccessNotBefore"}
            },
            "DateLessThan": {
                "aws:CurrentTime": {"Ref": "CleanupNotAfter"}
            },
        }
        allowed = set().union(
            *(_actions(item) for item in statements if item["Effect"] == "Allow")
        )
        assert "cloudformation:CreateChangeSet" not in allowed
        assert "cloudformation:ExecuteChangeSet" not in allowed
        assert "kms:CancelKeyDeletion" not in allowed
        assert all(not action.endswith("*") for action in allowed)


def test_route_cleanup_is_transitively_bounded_to_route_stack_inventory() -> None:
    statements = _statements(_load()["Resources"]["RouteSeedCleanupPermissionSet"])
    role_arns = [_sub(item) for item in _resources(statements["RouteRoleDeleteCfn"])]
    assert role_arns == [
        "arn:${AWS::Partition}:iam::${ManagementAccountId}:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerCreator",
        "arn:${AWS::Partition}:iam::${ManagementAccountId}:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerExecutor",
    ]
    assert statements["RouteRoleDeleteCfn"]["Condition"][
        "ForAnyValue:StringEquals"
    ] == {"aws:CalledVia": "cloudformation.amazonaws.com"}
    sso_delete = statements["RouteSsoDeleteCfn"]
    assert sso_delete["Condition"]["ForAnyValue:StringEquals"] == {
        "aws:CalledVia": "cloudformation.amazonaws.com"
    }
    sso_resources = _resources(sso_delete)
    assert {item.get("Ref") for item in sso_resources if isinstance(item, Mapping)} >= {
        "IdentityCenterInstanceArn"
    }
    assert any(
        isinstance(item, Mapping)
        and set(item) == {"Fn::Sub"}
        and "permissionSet/${InstanceId}/ps-*" in _sub(item)
        for item in sso_resources
    )
    assert _sub(sso_resources[-1]) == (
        "arn:${AWS::Partition}:sso:::account/${AuthorityAccountId}"
    )
    wildcard_allows = {
        sid: _actions(item)
        for sid, item in statements.items()
        if item["Effect"] == "Allow" and "*" in _resources(item)
    }
    assert wildcard_allows == {
        "ConfirmOnlyCurrentCaller": {"sts:GetCallerIdentity"},
        "DeleteAudit": {"cloudtrail:LookupEvents"},
    }


def test_broker_cleanup_covers_exact_survivors_and_no_global_provider_delete() -> None:
    statements = _statements(_load()["Resources"]["BrokerSeedCleanupPermissionSet"])
    table_arn = (
        "arn:${AWS::Partition}:dynamodb:us-east-1:${AuthorityAccountId}:table/"
        "scanalyze-platform-authority-gug376-route-broker-ledger"
    )
    assert _sub(statements["BrokerLedgerDeleteCfn"]["Resource"]) == table_arn
    assert {
        "dynamodb:DeleteResourcePolicy",
        "dynamodb:DeleteTable",
        "dynamodb:DescribeTable",
    } <= _actions(statements["BrokerLedgerDeleteCfn"])
    assert "kms:ScheduleKeyDeletion" in _actions(statements["BrokerKeyDeleteCfn"])
    assert "kms:CancelKeyDeletion" not in _actions(statements["BrokerKeyDeleteCfn"])
    assert _sub(statements["BrokerAliasDeleteCfn"]["Resource"]) == (
        "arn:${AWS::Partition}:kms:us-east-1:${AuthorityAccountId}:alias/"
        "scanalyze/platform-authority/gug376-route-broker-ledger"
    )
    log_resources = [
        _sub(item) for item in _resources(statements["BrokerLogDeleteCfn"])
    ]
    assert len(log_resources) == 4
    assert all("/aws/lambda/scanalyze-platform-authority-gug376-route-" in item for item in log_resources)
    role_resources = [
        _sub(item) for item in _resources(statements["BrokerRoleDeleteCfn"])
    ]
    assert len(role_resources) == 4
    assert all(item.startswith("arn:${AWS::Partition}:iam::${AuthorityAccountId}:role/ScanalyzeGug376Route") for item in role_resources)
    lambda_resources = [
        _sub(item) for item in _resources(statements["BrokerLambdaDeleteCfn"])
    ]
    assert len(lambda_resources) == 9
    assert {
        "lambda:DeleteAlias",
        "lambda:DeleteCodeSigningConfig",
        "lambda:DeleteFunction",
        "lambda:DeleteFunctionEventInvokeConfig",
        "lambda:DeleteRuntimeManagementConfig",
    } <= _actions(statements["BrokerLambdaDeleteCfn"])

    provider_sids = {
        "BrokerLedgerDeleteCfn",
        "BrokerKeyDeleteCfn",
        "BrokerAliasDeleteCfn",
        "BrokerAliasListCfn",
        "BrokerLogDeleteCfn",
        "BrokerLogListCfn",
        "BrokerRoleDeleteCfn",
        "BrokerLambdaDeleteCfn",
    }
    for sid in provider_sids:
        statement = statements[sid]
        assert statement["Condition"]["ForAnyValue:StringEquals"] == {
            "aws:CalledVia": "cloudformation.amazonaws.com"
        }
        assert statement["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "CleanupNotAfter"}
        }

    wildcard_allows = {
        sid: _actions(item)
        for sid, item in statements.items()
        if item["Effect"] == "Allow" and "*" in _resources(item)
    }
    assert wildcard_allows == {
        "ConfirmOnlyCurrentCaller": {"sts:GetCallerIdentity"},
        "DeleteAudit": {"cloudtrail:LookupEvents"},
        "BrokerLogRead": {"logs:DescribeLogGroups"},
        "BrokerAliasListCfn": {"kms:ListAliases"},
        "BrokerLogListCfn": {"logs:DescribeLogGroups"},
    }
    for sid, statement in statements.items():
        if statement["Effect"] != "Allow" or "*" not in _resources(statement):
            continue
        assert not any(
            action.startswith(("dynamodb:Delete", "iam:Delete", "kms:Delete", "kms:Schedule", "lambda:Delete", "logs:Delete"))
            for action in _actions(statement)
        ), sid
