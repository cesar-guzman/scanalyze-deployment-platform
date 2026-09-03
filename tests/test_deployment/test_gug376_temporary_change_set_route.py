"""Closed infrastructure contracts for the temporary GUG-376 broker route."""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from pathlib import Path
import re
from typing import Any, Iterable

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (
    REPO_ROOT
    / "bootstrap/cfn-platform-authority-gug376-temporary-change-set-route.yaml"
)
MANAGEMENT_ACCOUNT = "839393571433"
AUTHORITY_ACCOUNT = "042360977644"
REGION = "us-east-1"
BROKER_STACK = "scanalyze-platform-authority-gug376-route-broker"
CREATOR_FUNCTION = "scanalyze-platform-authority-gug376-route-creator"
EXECUTOR_FUNCTION = "scanalyze-platform-authority-gug376-route-executor"
CREATOR_ALIASES = {
    "seed-revoke-create-v1",
    "delegation-create-v1",
    "pep-create-v1",
    "pep-protection-create-v1",
    "closeout-gate-v1",
    "delegation-revoke-create-v1",
    "route-revoke-create-v1",
}
EXECUTOR_ALIASES = {
    "seed-revoke-execute-v1",
    "delegation-execute-v1",
    "pep-execute-v1",
    "pep-protection-execute-v1",
    "delegation-revoke-execute-v1",
    "route-revoke-execute-v1",
}

# Frozen from the AWS Service Authorization Reference on 2026-08-30. This is
# deliberately local: CI must reject invented IAM action names without making
# a network call or treating an SDK operation name as an IAM action.
_SERVICE_AUTHORIZATION_ACTIONS = {
    "dynamodb": {
        "BatchWriteItem",
        "CreateTable",
        "DeleteItem",
        "DeleteResourcePolicy",
        "DeleteTable",
        "DescribeContinuousBackups",
        "DescribeTable",
        "DescribeTimeToLive",
        "GetItem",
        "GetResourcePolicy",
        "ListTagsOfResource",
        "PartiQLDelete",
        "PartiQLInsert",
        "PartiQLUpdate",
        "PutItem",
        "PutResourcePolicy",
        "TagResource",
        "UntagResource",
        "UpdateContinuousBackups",
        "UpdateItem",
        "UpdateTable",
        "UpdateTimeToLive",
    },
    "lambda": {
        "AddPermission",
        "CreateAlias",
        "CreateCodeSigningConfig",
        "CreateEventSourceMapping",
        "CreateFunction",
        "CreateFunctionUrlConfig",
        "DeleteAlias",
        "DeleteCodeSigningConfig",
        "DeleteFunction",
        "DeleteFunctionCodeSigningConfig",
        "DeleteFunctionConcurrency",
        "DeleteFunctionEventInvokeConfig",
        "DeleteFunctionUrlConfig",
        "GetAlias",
        "GetCodeSigningConfig",
        "GetFunction",
        "GetFunctionCodeSigningConfig",
        "GetFunctionConcurrency",
        "GetFunctionEventInvokeConfig",
        "GetFunctionUrlConfig",
        "GetPolicy",
        "GetRuntimeManagementConfig",
        "InvokeAsync",
        "InvokeFunction",
        "InvokeFunctionUrl",
        "ListAliases",
        "ListCodeSigningConfigs",
        "ListEventSourceMappings",
        "ListFunctionUrlConfigs",
        "ListProvisionedConcurrencyConfigs",
        "ListTags",
        "ListVersionsByFunction",
        "PublishVersion",
        "PutFunctionCodeSigningConfig",
        "PutFunctionConcurrency",
        "PutFunctionEventInvokeConfig",
        "PutRuntimeManagementConfig",
        "RemovePermission",
        "TagResource",
        "UntagResource",
        "UpdateAlias",
        "UpdateEventSourceMapping",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "UpdateFunctionEventInvokeConfig",
        "UpdateFunctionUrlConfig",
    },
}
_SERVICE_AUTHORIZATION_WILDCARDS = {
    "dynamodb:*",
    "dynamodb:Delete*",
    "dynamodb:Update*",
    "lambda:*",
    "lambda:Create*",
    "lambda:Delete*",
    "lambda:Put*",
    "lambda:Update*",
}


class _Loader(yaml.SafeLoader):
    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
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


def _intrinsic(loader: _Loader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {
        {"Ref": "Ref", "Sub": "Fn::Sub", "GetAtt": "Fn::GetAtt"}.get(
            suffix, f"Fn::{suffix}"
        ): value
    }


_Loader.add_multi_constructor("!", _intrinsic)


def _load() -> dict[str, Any]:
    loaded = yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=_Loader)
    assert isinstance(loaded, dict)
    return loaded


def _policy(route: dict[str, Any], logical_id: str) -> dict[str, Any]:
    resource = route["Resources"][logical_id]
    if resource["Type"] == "AWS::SSO::PermissionSet":
        return resource["Properties"]["InlinePolicy"]
    return resource["Properties"]["Policies"][0]["PolicyDocument"]


def _actions(statement: dict[str, Any]) -> set[str]:
    value = statement.get("Action", [])
    return {value} if isinstance(value, str) else set(value)


def _statements(policy: dict[str, Any], effect: str) -> Iterable[dict[str, Any]]:
    return (
        statement
        for statement in policy["Statement"]
        if statement.get("Effect") == effect
    )


def _allowed(policy: dict[str, Any]) -> set[str]:
    return set().union(*(_actions(value) for value in _statements(policy, "Allow")))


def _denied(policy: dict[str, Any]) -> set[str]:
    return set().union(*(_actions(value) for value in _statements(policy, "Deny")))


def _by_sid(policy: dict[str, Any], sid: str) -> dict[str, Any]:
    return next(value for value in policy["Statement"] if value["Sid"] == sid)


def assert_closed_lambda_and_dynamodb_actions(value: Any) -> None:
    """Validate every Lambda/DynamoDB action against the frozen AWS reference."""

    actions: list[str] = []

    def collect(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "Action":
                    if isinstance(child, str):
                        actions.append(child)
                    elif isinstance(child, list):
                        actions.extend(
                            value
                            for value in child
                            if isinstance(value, str)
                        )
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)

    collect(value)
    for action in actions:
        service, _, name = action.partition(":")
        if service not in _SERVICE_AUTHORIZATION_ACTIONS:
            continue
        assert action in _SERVICE_AUTHORIZATION_WILDCARDS or name in (
            _SERVICE_AUTHORIZATION_ACTIONS[service]
        ), action


_NO_VALUE = object()


def _resolve(
    value: Any,
    *,
    identity_center_kms_mode: str = "CUSTOMER_MANAGED_KEY",
    identity_center_kms_key_arn: str = (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "00000000-0000-4000-8000-000000000002"
    ),
) -> Any:
    replacements = {
        "AWS::Partition": "aws",
        "AuthorityAccountId": AUTHORITY_ACCOUNT,
        "ManagementAccountId": MANAGEMENT_ACCOUNT,
        "SourceCommit": "a" * 40,
        "IdentityCenterInstanceArn": (
            "arn:aws:sso:::instance/ssoins-0123456789ABCDEF"
        ),
        "IdentityCenterKmsMode": identity_center_kms_mode,
        "IdentityCenterKmsKeyArn": (
            identity_center_kms_key_arn
            if identity_center_kms_mode == "CUSTOMER_MANAGED_KEY"
            else ""
        ),
        "RouteNotBefore": "2030-01-01T00:00:00Z",
        "RouteNotAfter": "2030-01-01T02:00:00Z",
        "RecoveryNotAfter": "2030-01-02T02:00:00Z",
        "ArtifactKmsKeyArn": (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "00000000-0000-4000-8000-000000000001"
        ),
        "RouteTemplateBucket": "b" * 63,
        "RouteTemplateKey": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
            + "a" * 40
            + "/cfn-platform-authority-gug376-temporary-change-set-route.yaml"
        ),
        "RouteTemplateVersion": "v" * 1024,
        "RouteTemplateUrl": "https://" + "u" * 504,
        "DelegationTemplateBucket": "b" * 63,
        "DelegationTemplateKey": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/templates/"
            + "a" * 40
            + "/cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
        ),
        "DelegationTemplateVersion": "v" * 1024,
        "DelegationTemplateUrl": "https://" + "u" * 504,
        "BrokerSeedTemplateBucket": "b" * 63,
        "BrokerSeedTemplateKey": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/private/"
            + "a" * 40
            + "/cfn-platform-authority-gug376-route-broker.yaml"
        ),
        "BrokerSeedTemplateVersion": "v" * 1024,
        "BrokerSeedTemplateUrl": "https://" + "u" * 504,
        "BrokerProtectionTemplateBucket": "b" * 63,
        "BrokerProtectionTemplateKey": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/private/"
            + "a" * 40
            + "/cfn-platform-authority-gug376-route-broker-protection.yaml"
        ),
        "BrokerProtectionTemplateVersion": "v" * 1024,
        "BrokerProtectionTemplateUrl": "https://" + "u" * 504,
        "BrokerCodeBucket": "b" * 63,
        "BrokerCodeKey": (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/broker/signed/"
            + "a" * 40
            + "/12345678-1234-1234-1234-1234567890ab.zip"
        ),
        "BrokerCodeVersion": "v" * 1024,
        "BrokerSigningProfileVersionArn": (
            "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
            "ScanalyzeGug376/ABCDEFGHIJ"
        ),
    }

    def resolve(item: Any) -> Any:
        if isinstance(item, list):
            resolved = [resolve(child) for child in item]
            return [child for child in resolved if child is not _NO_VALUE]
        if not isinstance(item, dict):
            return item
        if set(item) == {"Ref"}:
            if item["Ref"] == "AWS::NoValue":
                return _NO_VALUE
            return replacements[item["Ref"]]
        if set(item) == {"Fn::If"}:
            condition, true_value, false_value = item["Fn::If"]
            assert condition == "UseIdentityCenterCustomerManagedKey"
            return resolve(
                true_value
                if identity_center_kms_mode == "CUSTOMER_MANAGED_KEY"
                else false_value
            )
        if set(item) == {"Fn::Sub"}:
            specification = item["Fn::Sub"]
            if isinstance(specification, str):
                template = specification
                variables: dict[str, Any] = {}
            else:
                template, raw_variables = specification
                variables = {
                    key: resolve(child)
                    for key, child in raw_variables.items()
                }
            substitutions = {**replacements, **variables}
            return re.sub(
                r"\$\{([^}]+)\}",
                lambda match: substitutions[match.group(1)],
                template,
            )
        if set(item) == {"Fn::Split"}:
            delimiter, source = item["Fn::Split"]
            return resolve(source).split(delimiter)
        if set(item) == {"Fn::Select"}:
            index, items = item["Fn::Select"]
            return resolve(items)[index]
        if set(item) == {"Fn::Join"}:
            delimiter, items = item["Fn::Join"]
            return delimiter.join(resolve(items))
        resolved = {key: resolve(child) for key, child in item.items()}
        return {
            key: child
            for key, child in resolved.items()
            if child is not _NO_VALUE
        }

    return resolve(value)


@pytest.fixture(scope="module")
def route() -> dict[str, Any]:
    return _load()


def test_template_parses_without_duplicates_and_fits_cloudformation_limit() -> None:
    assert _load()["AWSTemplateFormatVersion"] == "2010-09-09"
    # This route is always consumed through an exact versioned TemplateURL;
    # CloudFormation's S3 template limit is 1 MiB, not the TemplateBody limit.
    assert len(TEMPLATE.read_bytes()) <= 1_048_576
    tokens = yaml.scan(TEMPLATE.read_text(encoding="utf-8"))
    assert not any(
        isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
        for token in tokens
    )
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load("Resources:\n  X: one\n  X: two\n", Loader=_Loader)


def test_route_iam_actions_match_frozen_service_authorization_reference(
    route: dict[str, Any],
) -> None:
    assert_closed_lambda_and_dynamodb_actions(route)
    raw = TEMPLATE.read_text(encoding="utf-8")
    assert "dynamodb:TransactWriteItems" not in raw
    assert "lambda:DeleteRuntimeManagementConfig" not in raw


def test_route_replaces_five_direct_grants_with_broker_boundary(
    route: dict[str, Any],
) -> None:
    resources = route["Resources"]
    assert {key for key, value in resources.items() if value["Type"] == "AWS::IAM::Role"} == {
        "ManagementBrokerCreatorRole",
        "ManagementBrokerExecutorRole",
        "ManagementCollisionReaderRole",
    }
    assert {
        key for key, value in resources.items() if value["Type"] == "AWS::SSO::PermissionSet"
    } == {
        "BrokerSeedCreatorPermissionSet",
        "BrokerSeedExecutorPermissionSet",
        "BrokerInvokerPermissionSet",
    }
    assert {key for key, value in resources.items() if value["Type"] == "AWS::SSO::Assignment"} == {
        "BrokerSeedCreatorAssignment",
        "BrokerSeedExecutorAssignment",
        "BrokerInvokerAssignment",
    }
    assert not {
        "ManagementCreatorPermissionSet",
        "AuthorityCreatorPermissionSet",
        "DelegationExecutorPermissionSet",
        "RouteRevocationExecutorPermissionSet",
        "AuthorityExecutorPermissionSet",
    } & resources.keys()


def test_activation_flags_are_required_and_seed_closeout_is_independent(
    route: dict[str, Any],
) -> None:
    for name in ("SeedAssignmentsEnabled", "BrokerInvokerAssignmentEnabled"):
        assert "Default" not in route["Parameters"][name]
        assert route["Parameters"][name]["AllowedValues"] == ["false", "true"]
    assert route["Resources"]["BrokerSeedCreatorAssignment"]["Condition"] == (
        "CreateSeedAssignments"
    )
    assert route["Resources"]["BrokerSeedExecutorAssignment"]["Condition"] == (
        "CreateSeedAssignments"
    )
    assert route["Resources"]["BrokerInvokerAssignment"]["Condition"] == (
        "CreateBrokerInvokerAssignment"
    )
    assert route["Outputs"]["CleanupOrder"]["Value"] == (
        "SEED_FALSE_KEEP_INVOKER_THEN_CLOSEOUT_FALSE_FALSE"
    )


def test_versioned_template_url_limits_cover_percent_encoded_s3_versions(
    route: dict[str, Any],
) -> None:
    for prefix in ("Route", "Delegation", "BrokerSeed", "BrokerProtection"):
        version = route["Parameters"][prefix + "TemplateVersion"]
        url = route["Parameters"][prefix + "TemplateUrl"]
        assert version["MaxLength"] == 1024
        assert url["MaxLength"] == 5120
        assert "NoEcho" not in version
        assert "NoEcho" not in url


def test_route_parameters_are_exactly_readable_non_secret_coordinates(
    route: dict[str, Any],
) -> None:
    assert all(
        "NoEcho" not in parameter
        for parameter in route["Parameters"].values()
    )


def test_management_collision_list_permission_sets_uses_exact_instance(
    route: dict[str, Any],
) -> None:
    policy = _policy(route, "ManagementCollisionReaderRole")
    wildcard_inventory = _by_sid(policy, "DiscoverExactNames")
    assert wildcard_inventory["Resource"] == "*"
    assert "sso:ListPermissionSets" not in wildcard_inventory["Action"]
    permission_sets = _by_sid(
        policy, "ListBoundIdentityCenterPermissionSets"
    )
    assert permission_sets["Action"] == "sso:ListPermissionSets"
    assert permission_sets["Resource"] == {"Ref": "IdentityCenterInstanceArn"}
    assert permission_sets["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": REGION,
        "sso:PrimaryRegion": REGION,
    }
    exact_details = _by_sid(policy, "ReadExactCandidateDetails")
    instance_id = {
        "InstanceId": {
            "Fn::Select": [
                1,
                {"Fn::Split": ["/", {"Ref": "IdentityCenterInstanceArn"}]},
            ]
        }
    }
    assert {
        "Fn::Sub": [
            (
                "arn:${AWS::Partition}:sso::${ManagementAccountId}:"
                "application/${InstanceId}/*"
            ),
            instance_id,
        ]
    } in exact_details["Resource"]
    assert {
        "Fn::Sub": (
            "arn:${AWS::Partition}:sso::${ManagementAccountId}:application/*"
        )
    } not in exact_details["Resource"]


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:aws:kms:us-east-1:839393571433:key/"
        "00000000-0000-4000-8000-000000000002",
        "arn:aws:kms:us-east-1:839393571433:key/"
        "mrk-0123456789abcdef0123456789abcdef",
    ),
)
def test_management_collision_reader_grants_only_bound_identity_center_cmk(
    route: dict[str, Any], key_arn: str
) -> None:
    parameters = route["Parameters"]
    assert parameters["IdentityCenterKmsMode"]["AllowedValues"] == [
        "AWS_OWNED_KMS_KEY",
        "CUSTOMER_MANAGED_KEY",
    ]
    assert re.fullmatch(
        parameters["IdentityCenterKmsKeyArn"]["AllowedPattern"], key_arn
    )
    assert route["Rules"]["IdentityCenterKmsBindingMustMatch"]

    policy = _resolve(
        _policy(route, "ManagementCollisionReaderRole"),
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=key_arn,
    )
    decrypt = _by_sid(
        policy, "DecryptIdentityCenterMetadataThroughExactInstance"
    )
    assert decrypt == {
        "Sid": "DecryptIdentityCenterMetadataThroughExactInstance",
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": key_arn,
        "Condition": {
            "StringEquals": {
                "aws:PrincipalAccount": MANAGEMENT_ACCOUNT,
                "aws:RequestedRegion": REGION,
                "kms:CallerAccount": MANAGEMENT_ACCOUNT,
                "kms:ViaService": "sso.us-east-1.amazonaws.com",
                "kms:EncryptionContext:aws:sso:instance-arn": (
                    "arn:aws:sso:::instance/ssoins-0123456789ABCDEF"
                ),
            },
            "DateGreaterThanEquals": {
                "aws:CurrentTime": "2030-01-01T00:00:00Z"
            },
            "DateLessThan": {
                "aws:CurrentTime": "2030-01-01T02:00:00Z"
            },
        },
    }
    deny_boundary = _by_sid(
        policy, "DenyEveryOtherAction"
    )
    assert "kms:Decrypt" in deny_boundary["NotAction"]


def test_management_collision_reader_aws_owned_mode_has_zero_kms_authority(
    route: dict[str, Any],
) -> None:
    policy = _resolve(
        _policy(route, "ManagementCollisionReaderRole"),
        identity_center_kms_mode="AWS_OWNED_KMS_KEY",
    )
    assert "kms:" not in json.dumps(policy, sort_keys=True)


def test_management_roles_trust_only_exact_authority_broker_roles(
    route: dict[str, Any],
) -> None:
    expected = {
        "ManagementBrokerCreatorRole": (
            "ScanalyzeGug376RouteBrokerCreator",
            "gug376-creator-${SourceCommit}",
        ),
        "ManagementBrokerExecutorRole": (
            "ScanalyzeGug376RouteBrokerExecutor",
            "gug376-executor-${SourceCommit}",
        ),
    }
    for logical_id, (role_name, source_identity) in expected.items():
        properties = route["Resources"][logical_id]["Properties"]
        assert properties["RoleName"] == role_name
        assert properties["Path"] == "/scanalyze/platform-authority/"
        statement = properties["AssumeRolePolicyDocument"]["Statement"][0]
        assert statement["Principal"]["AWS"] == {
            "Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AuthorityAccountId}}:root"
        }
        assert statement["Action"] == ["sts:AssumeRole", "sts:SetSourceIdentity"]
        assert statement["Condition"]["ArnEquals"]["aws:PrincipalArn"] == {
            "Fn::Sub": (
                "arn:${AWS::Partition}:iam::${AuthorityAccountId}:role/" + role_name
            )
        }
        assert statement["Condition"]["StringEquals"]["sts:SourceIdentity"] == {
            "Fn::Sub": source_identity
        }
        assert statement["Condition"]["DateGreaterThanEquals"]["aws:CurrentTime"] == {
            "Ref": "RouteNotBefore"
        }
        assert statement["Condition"]["DateLessThan"]["aws:CurrentTime"] == {
            "Ref": "RecoveryNotAfter"
        }


def test_management_executor_can_observe_permission_set_provisioning(
    route: dict[str, Any],
) -> None:
    policies = route["Resources"]["ManagementBrokerExecutorRole"]["Properties"][
        "Policies"
    ]
    assert len(policies) == 1
    statements = policies[0]["PolicyDocument"]["Statement"]
    statement = next(
        item
        for item in statements
        if item.get("Sid") == "ManageDelegationPermissionSetThroughCloudFormation"
    )
    assert "sso:ProvisionPermissionSet" in statement["Action"]
    assert "sso:DescribePermissionSetProvisioningStatus" in statement["Action"]
    assert "sso:ListManagedPoliciesInPermissionSet" in statement["Action"]


def test_recovery_horizon_extends_only_readback_assume_and_invocation(
    route: dict[str, Any],
) -> None:
    def horizon(statement: dict[str, Any]) -> str:
        return statement["Condition"]["DateLessThan"]["aws:CurrentTime"]["Ref"]

    creator = _policy(route, "ManagementBrokerCreatorRole")
    executor = _policy(route, "ManagementBrokerExecutorRole")
    seed_creator = _policy(route, "BrokerSeedCreatorPermissionSet")
    seed_executor = _policy(route, "BrokerSeedExecutorPermissionSet")

    for policy, sids in (
        (
            creator,
            (
                "ReadCreateEvents",
                "ReadExactManagementStacks",
                "ReadExactIdentityCenterTerminalState",
                "TagM",
                "ReadExactRouteTemplate",
                "ReadExactDelegationTemplate",
                "DecryptExactArtifactBucketKeyThroughS3",
            ),
        ),
        (
            executor,
            (
                "ReadExecutionEvents",
                "ReadExactManagementChangeSets",
                "ReadExactIdentityCenterTerminalState",
            ),
        ),
        (
            seed_creator,
            (
                "ReadSeedCreationEvent",
                "ReadExactBrokerStack",
                "TagB",
                "ReadExactParameterlessBrokerTemplate",
                "ReadExactParameterlessBrokerProtectionTemplate",
                "DecryptExactBrokerTemplateKeyThroughS3",
                "DecryptExactBrokerProtectionTemplateKeyThroughS3",
            ),
        ),
        (
            seed_executor,
            (
                "ReadSeedExecutionEvent",
                "ReadExactBrokerChangeSet",
                "ReadExactBrokerRolesDirect",
                "ReadExactBrokerFunctionsDirect",
                "ReadBrokerCodeSigningConfigDirect",
                "ReadExactBrokerLedgerDirect",
                "ReadBrokerKmsKeyDirect",
                "ReadBrokerKmsGrantsDirect",
                "ListBrokerKmsAliasDirect",
                "ReadBrokerLogGroupsDirect",
                "ReadExactBrokerLogTagsDirect",
                "ReadBrokerLogResourcePoliciesDirect",
                "ManageExactBrokerRolesThroughCloudFormation",
                "PassOnlyExactBrokerRolesThroughCloudFormation",
                "ManageExactBrokerFunctionsThroughCloudFormation",
                "CreateBrokerCodeSigningConfigThroughCloudFormation",
                "ReadExactBrokerSigningProfileThroughCloudFormation",
                "ManageExactBrokerLogsThroughCloudFormation",
                "ReadBrokerLogGroupsThroughCloudFormation",
                "ManageExactBrokerLedgerThroughCloudFormation",
                "CreateBrokerLedgerKeyThroughCloudFormation",
                "ManageBrokerLedgerKeyThroughCloudFormation",
                "ReadExactBrokerCodeThroughCloudFormation",
                "DecryptExactBrokerCodeKeyThroughS3",
            ),
        ),
    ):
        assert all(horizon(_by_sid(policy, sid)) == "RecoveryNotAfter" for sid in sids)

    for policy, sids in (
        (
            creator,
            (
                "CreateExactRouteUpdateChangeSets",
                "CreateExactDelegationChangeSets",
            ),
        ),
        (
            executor,
            (
                "ExecuteExactRouteUpdates",
                "ExecuteDelegation",
            ),
        ),
        (
            seed_creator,
            (
                "CreateExactParameterlessBrokerChangeSet",
                "CreateExactParameterlessBrokerProtectionChangeSet",
            ),
        ),
        (
            seed_executor,
            (
                "ExecuteExactBrokerChangeSet",
                "ExecuteExactBrokerProtectionChangeSet",
            ),
        ),
    ):
        assert all(horizon(_by_sid(policy, sid)) == "RouteNotAfter" for sid in sids)

    invoker = _by_sid(_policy(route, "BrokerInvokerPermissionSet"), "InvokeOnlyExactBrokerAliases")
    assert horizon(invoker) == "RecoveryNotAfter"


def test_signer_read_uses_base_profile_arn_and_exact_version_condition(
    route: dict[str, Any],
) -> None:
    policy = _policy(route, "BrokerSeedExecutorPermissionSet")
    statement = _by_sid(
        policy, "ReadExactBrokerSigningProfileThroughCloudFormation"
    )
    resolved = _resolve(statement)
    assert resolved["Action"] == "signer:GetSigningProfile"
    assert resolved["Resource"] == (
        "arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
        "ScanalyzeGug376"
    )
    assert resolved["Condition"]["StringEquals"]["signer:ProfileVersion"] == (
        "ABCDEFGHIJ"
    )


@pytest.mark.parametrize("drift", ["principal", "source_identity", "action"])
def test_management_role_trust_rejects_single_field_drift(
    route: dict[str, Any], drift: str
) -> None:
    statement = _resolve(
        route["Resources"]["ManagementBrokerCreatorRole"]["Properties"][
            "AssumeRolePolicyDocument"
        ]["Statement"][0]
    )
    request = {
        "principal": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/"
            "ScanalyzeGug376RouteBrokerCreator"
        ),
        "source_identity": "gug376-creator-" + "a" * 40,
        "action": "sts:AssumeRole",
    }
    if drift == "principal":
        request["principal"] += "-other"
    elif drift == "source_identity":
        request["source_identity"] = "gug376-creator-*"
    else:
        request["action"] = "sts:AssumeRoleWithWebIdentity"
    assert not (
        request["principal"]
        == statement["Condition"]["ArnEquals"]["aws:PrincipalArn"]
        and request["source_identity"]
        == statement["Condition"]["StringEquals"]["sts:SourceIdentity"]
        and request["action"] in statement["Action"]
    )


def test_seed_creator_can_only_create_exact_parameterless_broker_change_set(
    route: dict[str, Any],
) -> None:
    policy = _policy(route, "BrokerSeedCreatorPermissionSet")
    allowed = _allowed(policy)
    denied = _denied(policy)
    assert "cloudformation:CreateChangeSet" in allowed
    assert "cloudformation:DeleteChangeSet" not in allowed
    assert "cloudformation:ExecuteChangeSet" not in allowed
    assert "cloudformation:ExecuteChangeSet" in denied
    assert not any(
        action.startswith(("dynamodb:", "iam:", "lambda:", "logs:", "sso:"))
        for action in allowed
    )
    statement = _by_sid(policy, "CreateExactParameterlessBrokerChangeSet")
    assert statement["Action"] == "cloudformation:CreateChangeSet"
    assert BROKER_STACK in str(statement["Resource"])
    assert statement["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": REGION,
        "cloudformation:ChangeSetName": [
            "gug376-route-broker-create",
            "gug376-route-broker-create-recovery-1",
        ],
        "cloudformation:TemplateUrl": {"Ref": "BrokerSeedTemplateUrl"},
    }
    protection_statement = _by_sid(
        policy, "CreateExactParameterlessBrokerProtectionChangeSet"
    )
    assert protection_statement["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": REGION,
        "cloudformation:ChangeSetName": [
            "gug376-route-broker-protection-enable",
            "gug376-route-broker-protection-enable-recovery-1",
        ],
        "cloudformation:TemplateUrl": {
            "Ref": "BrokerProtectionTemplateUrl"
        },
    }
    assert "aws:TagKeys" not in str(statement["Condition"])

    tag = _resolve(_by_sid(policy, "TagB"))
    assert tag["Action"] == "cloudformation:TagResource"
    assert set(tag["Resource"]) == {
        (
            "arn:aws:cloudformation:us-east-1:042360977644:stack/"
            "scanalyze-platform-authority-gug376-route-broker/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-route-broker-create/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-route-broker-create-recovery-1/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-route-broker-protection-enable/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            "gug376-route-broker-protection-enable-recovery-1/*"
        ),
    }
    assert tag["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": REGION,
        "cloudformation:CreateAction": [
            "CreateChangeSet",
            "ExecuteChangeSet",
        ],
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-376",
    }
    assert tag["Condition"]["ForAllValues:StringEquals"] == {
        "aws:TagKeys": ["managed_by", "service", "work_package"]
    }
    assert "cloudformation:ChangeSetName" not in str(tag["Condition"])
    assert "cloudformation:TemplateUrl" not in str(tag["Condition"])
    template_read = _by_sid(policy, "ReadExactParameterlessBrokerTemplate")
    assert template_read["Action"] == "s3:GetObjectVersion"
    assert template_read["Condition"]["StringEquals"]["s3:VersionId"] == {
        "Ref": "BrokerSeedTemplateVersion"
    }
    assert template_read["Condition"]["ForAnyValue:StringEquals"][
        "aws:CalledVia"
    ] == "cloudformation.amazonaws.com"
    protection_read = _by_sid(
        policy, "ReadExactParameterlessBrokerProtectionTemplate"
    )
    assert protection_read["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:s3:::${BrokerProtectionTemplateBucket}/"
            "${BrokerProtectionTemplateKey}"
        )
    }
    assert protection_read["Condition"]["StringEquals"]["s3:VersionId"] == {
        "Ref": "BrokerProtectionTemplateVersion"
    }


def test_every_artifact_reader_has_exact_identity_kms_decrypt_authority(
    route: dict[str, Any],
) -> None:
    expected = {
        "ManagementBrokerCreatorRole": (
            "DecryptExactArtifactBucketKeyThroughS3",
            "RouteTemplateBucket",
        ),
        "BrokerSeedCreatorPermissionSet": (
            "DecryptExactBrokerTemplateKeyThroughS3",
            "BrokerSeedTemplateBucket",
        ),
        "BrokerSeedCreatorPermissionSet:protection": (
            "DecryptExactBrokerProtectionTemplateKeyThroughS3",
            "BrokerProtectionTemplateBucket",
        ),
        "BrokerSeedExecutorPermissionSet": (
            "DecryptExactBrokerCodeKeyThroughS3",
            "BrokerCodeBucket",
        ),
    }
    for logical_id, (sid, bucket_parameter) in expected.items():
        resource_id = logical_id.split(":", 1)[0]
        statement = _by_sid(_policy(route, resource_id), sid)
        assert statement["Effect"] == "Allow"
        assert statement["Action"] == "kms:Decrypt"
        assert statement["Resource"] == {"Ref": "ArtifactKmsKeyArn"}
        assert statement["Condition"]["StringEquals"] == {
            "aws:RequestedRegion": REGION,
            "kms:ViaService": "s3.us-east-1.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": {
                "Fn::Sub": (
                    "arn:${AWS::Partition}:s3:::${" + bucket_parameter + "}"
                )
            },
        }
        assert statement["Condition"]["DateGreaterThanEquals"] == {
            "aws:CurrentTime": {"Ref": "RouteNotBefore"}
        }
        assert statement["Condition"]["DateLessThan"] == {
            "aws:CurrentTime": {"Ref": "RecoveryNotAfter"}
        }

    parameter = route["Parameters"]["ArtifactKmsKeyArn"]
    assert "NoEcho" not in parameter
    assert "042360977644:key/" in parameter["AllowedPattern"]


@pytest.mark.parametrize("drift", ["resource", "region", "service", "context"])
def test_management_artifact_decrypt_rejects_each_single_field_drift(
    route: dict[str, Any], drift: str
) -> None:
    expected = _resolve(
        _by_sid(
            _policy(route, "ManagementBrokerCreatorRole"),
            "DecryptExactArtifactBucketKeyThroughS3",
        )
    )
    request = {
        "resource": expected["Resource"],
        "region": REGION,
        "service": "s3.us-east-1.amazonaws.com",
        "context": expected["Condition"]["StringEquals"][
            "kms:EncryptionContext:aws:s3:arn"
        ],
    }
    condition = expected["Condition"]["StringEquals"]
    if drift == "resource":
        request["resource"] = request["resource"].replace(
            AUTHORITY_ACCOUNT, MANAGEMENT_ACCOUNT
        )
    elif drift == "region":
        request["region"] = "us-west-2"
    elif drift == "service":
        request["service"] = "s3.us-west-2.amazonaws.com"
    else:
        request["context"] += "/foreign"
    assert not (
        request["resource"] == expected["Resource"]
        and request["region"] == condition["aws:RequestedRegion"]
        and request["service"] == condition["kms:ViaService"]
        and request["context"]
        == condition["kms:EncryptionContext:aws:s3:arn"]
    )


def test_seed_executor_only_executes_exact_broker_stack_through_fas(
    route: dict[str, Any],
) -> None:
    policy = _policy(route, "BrokerSeedExecutorPermissionSet")
    allowed = _allowed(policy)
    assert "cloudformation:ExecuteChangeSet" in allowed
    assert "cloudformation:CreateChangeSet" not in allowed
    assert "cloudformation:DeleteChangeSet" not in allowed
    execute = _by_sid(policy, "ExecuteExactBrokerChangeSet")
    assert BROKER_STACK in str(execute["Resource"])
    patterns = _resolve(execute)["Condition"]["StringLike"][
        "cloudformation:ChangeSetName"
    ]
    exact_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
        "gug376-route-broker-create/11111111-1111-4111-8111-111111111111"
    )
    assert any(fnmatchcase(exact_arn, pattern) for pattern in patterns)
    assert not any(
        fnmatchcase("gug376-route-broker-create", pattern)
        for pattern in patterns
    )
    assert not any(
        fnmatchcase(exact_arn.replace(REGION, "us-west-2"), pattern)
        for pattern in patterns
    )
    protection_execute = _resolve(
        _by_sid(policy, "ExecuteExactBrokerProtectionChangeSet")
    )
    protection_patterns = protection_execute["Condition"]["StringLike"][
        "cloudformation:ChangeSetName"
    ]
    protection_arn = (
        "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
        "gug376-route-broker-protection-enable/"
        "11111111-1111-4111-8111-111111111111"
    )
    assert any(
        fnmatchcase(protection_arn, pattern)
        for pattern in protection_patterns
    )
    for sid in (
        "ManageExactBrokerRolesThroughCloudFormation",
        "ManageExactBrokerFunctionsThroughCloudFormation",
        "ManageExactBrokerLogsThroughCloudFormation",
        "ReadExactBrokerCodeThroughCloudFormation",
    ):
        statement = _by_sid(policy, sid)
        assert statement["Condition"]["ForAnyValue:StringEquals"][
            "aws:CalledVia"
        ] == "cloudformation.amazonaws.com"
    assert CREATOR_FUNCTION in str(_by_sid(policy, "ManageExactBrokerFunctionsThroughCloudFormation"))
    assert EXECUTOR_FUNCTION in str(_by_sid(policy, "ManageExactBrokerFunctionsThroughCloudFormation"))
    assert {
        "lambda:GetRuntimeManagementConfig",
        "lambda:PutRuntimeManagementConfig",
        "lambda:PutFunctionCodeSigningConfig",
        "lambda:DeleteFunctionCodeSigningConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:PutFunctionConcurrency",
        "lambda:DeleteFunctionConcurrency",
        "lambda:DeleteFunctionEventInvokeConfig",
    } <= _actions(_by_sid(policy, "ManageExactBrokerFunctionsThroughCloudFormation"))
    function_actions = _actions(
        _by_sid(policy, "ManageExactBrokerFunctionsThroughCloudFormation")
    )
    assert "lambda:DeleteRuntimeManagementConfig" not in function_actions
    assert "lambda:UpdateFunctionCodeSigningConfig" not in function_actions
    assert {
        "dynamodb:GetResourcePolicy",
        "dynamodb:PutResourcePolicy",
        "dynamodb:DeleteResourcePolicy",
    } <= _actions(_by_sid(policy, "ManageExactBrokerLedgerThroughCloudFormation"))
    kms_global = _by_sid(policy, "CreateBrokerLedgerKeyThroughCloudFormation")
    assert kms_global["Resource"] == "*"
    assert _actions(kms_global) == {"kms:CreateKey", "kms:ListAliases"}
    assert "kms:ListAliases" not in _actions(
        _by_sid(policy, "ManageBrokerLedgerKeyThroughCloudFormation")
    )
    assert "lambda:InvokeFunction" in _denied(policy)

    direct_read_sids = {
        "ReadExactBrokerRolesDirect": {
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoleTags",
        },
        "ReadExactBrokerFunctionsDirect": {
            "lambda:GetAlias",
            "lambda:GetFunction",
            "lambda:GetFunctionCodeSigningConfig",
            "lambda:GetFunctionConcurrency",
            "lambda:GetFunctionEventInvokeConfig",
            "lambda:GetFunctionUrlConfig",
            "lambda:GetPolicy",
            "lambda:GetRuntimeManagementConfig",
            "lambda:ListAliases",
            "lambda:ListEventSourceMappings",
            "lambda:ListFunctionUrlConfigs",
            "lambda:ListProvisionedConcurrencyConfigs",
            "lambda:ListTags",
            "lambda:ListVersionsByFunction",
        },
        "ReadBrokerCodeSigningConfigDirect": {
            "lambda:GetCodeSigningConfig"
        },
        "ReadExactBrokerLedgerDirect": {
            "dynamodb:DescribeContinuousBackups",
            "dynamodb:DescribeTable",
            "dynamodb:DescribeTimeToLive",
            "dynamodb:GetResourcePolicy",
            "dynamodb:ListTagsOfResource",
        },
        "ReadBrokerKmsKeyDirect": {
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListResourceTags",
        },
        "ReadBrokerKmsGrantsDirect": {"kms:ListGrants"},
        "ListBrokerKmsAliasDirect": {"kms:ListAliases"},
        "ReadBrokerLogGroupsDirect": {"logs:DescribeLogGroups"},
        "ReadExactBrokerLogTagsDirect": {
            "logs:DescribeSubscriptionFilters",
            "logs:ListTagsForResource",
        },
        "ReadBrokerLogResourcePoliciesDirect": {
            "logs:DescribeResourcePolicies"
        },
    }
    for sid, expected in direct_read_sids.items():
        statement = _by_sid(policy, sid)
        assert _actions(statement) == expected
        assert "aws:CalledVia" not in str(statement["Condition"])
        assert statement["Condition"]["StringEquals"]["aws:RequestedRegion"] == REGION
        assert "RouteNotBefore" in str(statement["Condition"])
        assert "RecoveryNotAfter" in str(statement["Condition"])
    grant_read = _by_sid(policy, "ReadBrokerKmsGrantsDirect")
    assert grant_read["Condition"]["ForAnyValue:StringEquals"][
        "kms:ResourceAliases"
    ] == "alias/scanalyze/platform-authority/gug376-route-broker-ledger"
    assert grant_read["Resource"] == {
        "Fn::Sub": "arn:${AWS::Partition}:kms:us-east-1:${AuthorityAccountId}:key/*"
    }
    assert _by_sid(policy, "ReadBrokerLogResourcePoliciesDirect")["Resource"] == "*"
    direct_deny = _by_sid(policy, "DenySeedCreationAndDirectProviderAccess")
    denied_direct = _actions(direct_deny)
    assert not {"iam:*", "dynamodb:*", "lambda:*", "logs:*", "kms:*"} & denied_direct
    assert not set().union(*direct_read_sids.values()) & denied_direct
    assert {
        "dynamodb:PutItem",
        "iam:PassRole",
        "kms:ScheduleKeyDeletion",
        "lambda:PublishVersion",
        "s3:Put*",
        "signer:StartSigningJob",
    } <= denied_direct


def test_invoker_has_only_qualified_alias_invocation_and_explicit_denies(
    route: dict[str, Any],
) -> None:
    policy = _policy(route, "BrokerInvokerPermissionSet")
    assert _allowed(policy) == {"lambda:InvokeFunction"}
    allow = _by_sid(policy, "InvokeOnlyExactBrokerAliases")
    resources = _resolve(allow["Resource"])
    assert len(resources) == 13
    rendered = set(resources)
    assert all(f":function:{CREATOR_FUNCTION}:" in value for value in rendered if "creator:" in value)
    assert all(f":function:{EXECUTOR_FUNCTION}:" in value for value in rendered if "executor:" in value)
    assert {value.rsplit(":", 1)[1] for value in rendered} == CREATOR_ALIASES | EXECUTOR_ALIASES
    assert all(not value.endswith((CREATOR_FUNCTION, EXECUTOR_FUNCTION, ":*")) for value in rendered)
    deny_other = _by_sid(policy, "DenyOtherLambdaResources")
    assert deny_other["Action"] == "lambda:InvokeFunction"
    assert _resolve(deny_other["NotResource"]) == resources
    unsafe = _actions(_by_sid(policy, "DenyAsyncUrlsAndLambdaMutation"))
    assert {
        "lambda:InvokeAsync",
        "lambda:InvokeFunctionUrl",
        "lambda:CreateFunctionUrlConfig",
        "lambda:PutFunctionEventInvokeConfig",
    } <= unsafe
    assert {
        "cloudformation:*",
        "iam:*",
        "sso:*",
        "sts:AssumeRole",
    } <= _denied(policy)


def test_assignments_target_only_exact_authority_user(
    route: dict[str, Any],
) -> None:
    for logical_id in (
        "BrokerSeedCreatorAssignment",
        "BrokerSeedExecutorAssignment",
        "BrokerInvokerAssignment",
    ):
        properties = route["Resources"][logical_id]["Properties"]
        assert properties["PrincipalType"] == "USER"
        assert properties["PrincipalId"] == {"Ref": "BootstrapPrincipalId"}
        assert properties["TargetId"] == {"Ref": "AuthorityAccountId"}
        assert properties["TargetType"] == "AWS_ACCOUNT"


def test_management_creator_and_executor_remain_separated(
    route: dict[str, Any],
) -> None:
    creator = _policy(route, "ManagementBrokerCreatorRole")
    executor = _policy(route, "ManagementBrokerExecutorRole")
    assert "cloudformation:CreateChangeSet" in _allowed(creator)
    assert "cloudformation:ExecuteChangeSet" not in _allowed(creator)
    assert "cloudformation:ExecuteChangeSet" in _denied(creator)
    assert "cloudformation:ExecuteChangeSet" in _allowed(executor)
    assert "cloudformation:CreateChangeSet" not in _allowed(executor)
    assert "cloudformation:CreateChangeSet" in _denied(executor)
    assert "sts:AssumeRole" in _denied(creator)
    assert "sts:AssumeRole" in _denied(executor)
    assert "ScanalyzeBootstrapPlanRepairMutation" in str(executor)
    assert "ScanalyzeBootstrapPlanRepairReadback" in str(executor)
    expected_route_names = [
        "gug376-temporary-route-seed-revoke",
        "gug376-temporary-route-invoker-revoke",
    ]
    create_statement = _by_sid(creator, "CreateExactRouteUpdateChangeSets")
    assert create_statement["Condition"]["StringEquals"][
        "cloudformation:ChangeSetName"
    ] == expected_route_names
    execute_statement = _resolve(
        _by_sid(executor, "ExecuteExactRouteUpdates")
    )
    route_patterns = execute_statement["Condition"]["StringLike"][
        "cloudformation:ChangeSetName"
    ]
    assert len(route_patterns) == 2
    for name, pattern in zip(expected_route_names, route_patterns, strict=True):
        arn = (
            f"arn:aws:cloudformation:{REGION}:{MANAGEMENT_ACCOUNT}:changeSet/"
            f"{name}/11111111-1111-4111-8111-111111111111"
        )
        assert fnmatchcase(arn, pattern)
        assert not fnmatchcase(name, pattern)
    assert expected_route_names[0] != expected_route_names[1]

    route_create = _by_sid(creator, "CreateExactRouteUpdateChangeSets")
    delegation_create = _by_sid(creator, "CreateExactDelegationChangeSets")
    assert route_create["Action"] == "cloudformation:CreateChangeSet"
    assert delegation_create["Action"] == "cloudformation:CreateChangeSet"
    assert "aws:RequestTag/" not in str(route_create["Condition"])
    assert "aws:RequestTag/" not in str(delegation_create["Condition"])

    tag = _resolve(_by_sid(creator, "TagM"))
    assert tag["Action"] == "cloudformation:TagResource"
    assert set(tag["Resource"]) == {
        (
            "arn:aws:cloudformation:us-east-1:839393571433:stack/"
            "scanalyze-platform-authority-gug376-temporary-change-set-route/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
            "gug376-temporary-route-seed-revoke/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
            "gug376-temporary-route-invoker-revoke/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:839393571433:stack/"
            "scanalyze-platform-authority-bootstrap-plan-repair-delegation/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
            "gug376-plan-repair-delegation-create/*"
        ),
        (
            "arn:aws:cloudformation:us-east-1:839393571433:changeSet/"
            "gug376-plan-repair-delegation-revoke/*"
        ),
    }
    assert tag["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": REGION,
        "cloudformation:CreateAction": [
            "CreateChangeSet",
            "ExecuteChangeSet",
        ],
        "aws:RequestTag/managed_by": "cloudformation",
        "aws:RequestTag/service": "scanalyze-platform-authority",
        "aws:RequestTag/work_package": "GUG-376",
    }
    assert tag["Condition"]["ForAllValues:StringEquals"] == {
        "aws:TagKeys": ["managed_by", "service", "work_package"]
    }
    assert "cloudformation:ChangeSetName" not in str(tag["Condition"])
    assert "cloudformation:TemplateUrl" not in str(tag["Condition"])

    delegation_patterns = _resolve(
        _by_sid(executor, "ExecuteDelegation")
    )["Condition"]["StringLike"]["cloudformation:ChangeSetName"]
    for name, pattern in zip(
        [
            "gug376-plan-repair-delegation-create",
            "gug376-plan-repair-delegation-revoke",
        ],
        delegation_patterns,
        strict=True,
    ):
        arn = (
            f"arn:aws:cloudformation:{REGION}:{MANAGEMENT_ACCOUNT}:changeSet/"
            f"{name}/11111111-1111-4111-8111-111111111111"
        )
        assert fnmatchcase(arn, pattern)
        assert not fnmatchcase(
            arn.replace(MANAGEMENT_ACCOUNT, AUTHORITY_ACCOUNT), pattern
        )

    sso_reads = {
        "sso:DescribeAccountAssignmentCreationStatus",
        "sso:DescribeAccountAssignmentDeletionStatus",
        "sso:DescribePermissionSet",
        "sso:ListAccountAssignments",
        "sso:ListAccountAssignmentsForPrincipal",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListPermissionSetProvisioningStatus",
        "sso:ListTagsForResource",
    }
    assert sso_reads <= _allowed(creator)
    assert sso_reads <= _allowed(executor)
    assert "sso:*" not in _denied(creator)
    assert "sso:*" not in _denied(executor)
    direct_provider_deny = _by_sid(executor, "DenyDirectProviderAndCreation")
    assert not (sso_reads & _actions(direct_provider_deny))
    assert {
        "sso:CreateAccountAssignment",
        "sso:DeleteAccountAssignment",
        "sso:PutInlinePolicyToPermissionSet",
    } <= _actions(direct_provider_deny)


@pytest.mark.parametrize(
    ("logical_id", "sid", "drift"),
    [
        ("BrokerSeedCreatorPermissionSet", "TagB", drift)
        for drift in ("account", "region", "name", "tag")
    ]
    + [
        ("ManagementBrokerCreatorRole", "TagM", drift)
        for drift in ("account", "region", "name", "tag")
    ],
)
def test_tag_only_statements_reject_foreign_change_set_or_tag(
    route: dict[str, Any], logical_id: str, sid: str, drift: str
) -> None:
    statement = _resolve(_by_sid(_policy(route, logical_id), sid))
    resource = next(
        value for value in statement["Resource"] if ":changeSet/" in value
    )
    requested_region = REGION
    tags = {
        "managed_by": "cloudformation",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-376",
    }
    if drift == "account":
        resource = resource.replace(
            f":{AUTHORITY_ACCOUNT}:", f":{MANAGEMENT_ACCOUNT}:"
        ) if logical_id == "BrokerSeedCreatorPermissionSet" else resource.replace(
            f":{MANAGEMENT_ACCOUNT}:", f":{AUTHORITY_ACCOUNT}:"
        )
    elif drift == "region":
        requested_region = "us-west-2"
    elif drift == "name":
        resource = re.sub(
            r"changeSet/[^/]+/", "changeSet/foreign-change-set/", resource
        )
    else:
        tags["work_package"] = "GUG-999"
    string_equals = statement["Condition"]["StringEquals"]
    assert not (
        resource in statement["Resource"]
        and requested_region == string_equals["aws:RequestedRegion"]
        and tags
        == {
            key.removeprefix("aws:RequestTag/"): value
            for key, value in string_equals.items()
            if key.startswith("aws:RequestTag/")
        }
        and set(tags)
        == set(
            statement["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"]
        )
    )


@pytest.mark.parametrize("drift", ["stack", "name", "template_url"])
def test_management_creator_rejects_each_single_field_change_set_drift(
    route: dict[str, Any], drift: str
) -> None:
    policy = _policy(route, "ManagementBrokerCreatorRole")
    statement = _resolve(_by_sid(policy, "CreateExactRouteUpdateChangeSets"))
    expected_names = statement["Condition"]["StringEquals"][
        "cloudformation:ChangeSetName"
    ]
    request = {
        "stack": statement["Resource"],
        "name": expected_names[0],
        "template_url": statement["Condition"]["StringEquals"][
            "cloudformation:TemplateUrl"
        ],
    }
    if drift == "stack":
        request["stack"] = request["stack"].replace(
            "gug376-temporary-change-set-route", "bootstrap-plan-repair-delegation"
        )
    elif drift == "name":
        request["name"] = "gug376-plan-repair-delegation-create"
    else:
        request["template_url"] += "-other"
    assert not (
        request["stack"] == statement["Resource"]
        and request["name"] in expected_names
        and request["template_url"]
        == statement["Condition"]["StringEquals"]["cloudformation:TemplateUrl"]
    )


def test_permission_sets_and_inline_policies_fit_aws_limits(
    route: dict[str, Any],
) -> None:
    expected_names = {
        "BrokerSeedCreatorPermissionSet": "ScanalyzeGug376BrokerSeedCreator",
        # The originally proposed suffix "Executor" produces 33 characters;
        # Identity Center enforces a hard 32-character Name limit.
        "BrokerSeedExecutorPermissionSet": "ScanalyzeGug376BrokerSeedExec",
        # "ScanalyzeGug376RouteBrokerInvoker" is also 33 characters.
        "BrokerInvokerPermissionSet": "ScanalyzeGug376BrokerInvoker",
    }
    for logical_id, name in expected_names.items():
        properties = route["Resources"][logical_id]["Properties"]
        assert properties["Name"] == name
        assert len(name) <= 32
        assert properties["SessionDuration"] == "PT1H"
    for logical_id, resource in route["Resources"].items():
        if resource.get("Type") != "AWS::IAM::Role":
            continue
        policy_sizes = [
            len(
                json.dumps(
                    _resolve(policy["PolicyDocument"]),
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            )
            for policy in resource["Properties"].get("Policies", [])
        ]
        assert policy_sizes
        assert all(size <= 10_240 for size in policy_sizes)
        assert sum(policy_sizes) <= 10_240, (logical_id, policy_sizes)
        trust = json.dumps(
            _resolve(
                resource["Properties"]["AssumeRolePolicyDocument"]
            ),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        assert len(trust) <= 2_048, (logical_id, len(trust))
    for logical_id in expected_names:
        compact = json.dumps(
            _resolve(_policy(route, logical_id)),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        # IAM Identity Center supports one inline policy up to 32,768 bytes.
        assert len(compact) <= 32_768, (logical_id, len(compact))


def test_route_is_nonproduction_and_every_role_is_bounded_by_window(
    route: dict[str, Any],
) -> None:
    assert route["Outputs"]["ProductionAuthorized"]["Value"] == "false"
    assert route["Outputs"]["BrokerStackName"]["Value"] == BROKER_STACK
    assert route["Rules"]["AccountAndRegionMustMatch"]
    assert route["Parameters"]["ManagementAccountId"]["AllowedValues"] == [
        MANAGEMENT_ACCOUNT
    ]
    assert route["Parameters"]["AuthorityAccountId"]["AllowedValues"] == [
        AUTHORITY_ACCOUNT
    ]
    for logical_id in (
        "ManagementBrokerCreatorRole",
        "ManagementBrokerExecutorRole",
        "BrokerSeedCreatorPermissionSet",
        "BrokerSeedExecutorPermissionSet",
    ):
        assert "RouteNotBefore" in str(_policy(route, logical_id))
        assert "RouteNotAfter" in str(_policy(route, logical_id))
