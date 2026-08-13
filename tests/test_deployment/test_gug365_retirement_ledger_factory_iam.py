"""Structural least-privilege tests for dedicated ledger-factory authorities."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
POLICY_ROOT = ROOT / "policies/iam"
FILES = {
    "boundary": POLICY_ROOT
    / "platform-authority-gug365-ledger-factory-boundary.json",
    "activator": POLICY_ROOT
    / "platform-authority-gug365-ledger-factory-activator.json",
    "invoker": POLICY_ROOT
    / "platform-authority-gug365-ledger-factory-invoker.json",
    "revoker": POLICY_ROOT
    / "platform-authority-gug365-ledger-factory-revoker.json",
    "function_factory": POLICY_ROOT
    / "platform-authority-gug365-ledger-factory-function-factory.json",
}
EXPECTED_PLACEHOLDERS = {
    "boundary": {"ledger_table_arn", "ledger_factory_log_stream_arn"},
    "activator": {
        "ledger_factory_boundary_arn",
        "proof_boundary_arn",
        "ledger_factory_role_arn",
    },
    "invoker": {
        "ledger_factory_function_version_arn",
        "ledger_table_arn",
        "ledger_factory_role_arn",
    },
    "revoker": {
        "ledger_factory_boundary_arn",
        "proof_boundary_arn",
        "ledger_factory_role_arn",
    },
    "function_factory": {
        "authority_account_id",
        "gug363_pre_function_binding_sha256",
        "ledger_factory_code_signing_config_arn",
        "ledger_factory_function_arn",
        "ledger_factory_function_version_arn",
        "ledger_factory_log_group_arn",
        "ledger_factory_role_arn",
        "ledger_factory_signed_bucket_arn",
        "ledger_factory_signed_kms_key_arn",
        "ledger_factory_signed_object_arn",
        "ledger_factory_signed_version_id",
        "proof_boundary_arn",
        "region",
        "source_commit",
    },
}
PLACEHOLDER = re.compile(r"\$\{([a-z0-9_]+)\}")
MAX_POLICY_BYTES = 6_144
MAX_LENGTH_BUCKET = "a" * 63
FUNCTION_FACTORY_RENDER_VALUES = {
    "authority_account_id": "042360977644",
    "region": "us-east-1",
    "source_commit": "a" * 40,
    "gug363_pre_function_binding_sha256": "sha256:" + "b" * 64,
    "proof_boundary_arn": (
        "arn:aws:iam::042360977644:policy/"
        "scanalyze-platform-authority-gug365-proof-boundary"
    ),
    "ledger_factory_role_arn": (
        "arn:aws:iam::042360977644:role/ScanalyzeGug365LedgerFactory"
    ),
    "ledger_factory_function_arn": (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        "scanalyze-platform-authority-gug365-ledger-factory"
    ),
    "ledger_factory_function_version_arn": (
        "arn:aws:lambda:us-east-1:042360977644:function:"
        "scanalyze-platform-authority-gug365-ledger-factory:1"
    ),
    "ledger_factory_signed_object_arn": (
        f"arn:aws:s3:::{MAX_LENGTH_BUCKET}/scanalyze/platform-authority/"
        "gug-365/ledger-factory/signed/"
        f"{'c' * 32}.zip"
    ),
    "ledger_factory_signed_bucket_arn": f"arn:aws:s3:::{MAX_LENGTH_BUCKET}",
    "ledger_factory_signed_version_id": (
        "synthetic-factory-signed-version-0001"
    ),
    "ledger_factory_signed_kms_key_arn": (
        "arn:aws:kms:us-east-1:042360977644:key/"
        "12345678-1234-1234-1234-123456789abc"
    ),
    "ledger_factory_code_signing_config_arn": (
        "arn:aws:lambda:us-east-1:042360977644:"
        "code-signing-config:csc-0123456789abcdef0"
    ),
    "ledger_factory_log_group_arn": (
        "arn:aws:logs:us-east-1:042360977644:log-group:/aws/lambda/"
        "scanalyze-platform-authority-gug365-ledger-factory"
    ),
}


def load(name: str) -> dict[str, Any]:
    value = json.loads(FILES[name].read_text(encoding="utf-8"))
    assert value["Version"] == "2012-10-17"
    assert isinstance(value["Statement"], list)
    sids = [
        statement["Sid"]
        for statement in value["Statement"]
        if "Sid" in statement
    ]
    assert len(set(sids)) == len(sids)
    return value


def statements(name: str, *, effect: str | None = None) -> list[Mapping[str, Any]]:
    values = load(name)["Statement"]
    return [value for value in values if effect is None or value["Effect"] == effect]


def strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    assert isinstance(value, list) and all(isinstance(item, str) for item in value)
    return list(value)


def actions(name: str, *, effect: str = "Allow") -> set[str]:
    result: set[str] = set()
    for statement in statements(name, effect=effect):
        if "Action" in statement:
            result.update(strings(statement["Action"]))
    return result


def by_sid(name: str, sid: str) -> Mapping[str, Any]:
    matches = [value for value in statements(name) if value["Sid"] == sid]
    assert len(matches) == 1
    return matches[0]


def statement_for_action(name: str, action: str) -> Mapping[str, Any]:
    matches = [
        value
        for value in statements(name, effect="Allow")
        if action in strings(value["Action"])
    ]
    assert len(matches) == 1
    return matches[0]


def walk_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def test_placeholders_are_closed_and_deterministic() -> None:
    for name in FILES:
        assert len(
            json.dumps(load(name), separators=(",", ":")).encode("utf-8")
        ) <= MAX_POLICY_BYTES
        observed = {
            match.group(1)
            for value in walk_strings(load(name))
            for match in PLACEHOLDER.finditer(value)
        }
        assert observed == EXPECTED_PLACEHOLDERS[name]
        interpolated = {
            value
            for value in walk_strings(load(name))
            if "${" in value and PLACEHOLDER.fullmatch(value) is None
        }
        assert interpolated == (
            {"s3.${region}.amazonaws.com"}
            if name == "function_factory"
            else set()
        )


def test_wildcard_allows_are_limited_to_required_global_reads() -> None:
    for name in FILES:
        for statement in statements(name, effect="Allow"):
            allowed_actions = strings(statement["Action"])
            resources = strings(statement["Resource"])
            assert all("*" not in action for action in allowed_actions)
            if resources == ["*"]:
                if name == "function_factory":
                    assert set(allowed_actions) == {
                        "sts:GetCallerIdentity",
                        "logs:DescribeLogGroups",
                    }
                elif name == "boundary" and allowed_actions == [
                    "kms:DescribeKey"
                ]:
                    assert statement["Sid"] == (
                        "ReadOnlyAwsManagedDynamoDbKeyMetadata"
                    )
                elif name == "invoker" and allowed_actions == [
                    "kms:DescribeKey"
                ]:
                    assert statement == {
                        "Sid": "ReadOnlyAwsManagedDynamoDbKeyMetadata",
                        "Effect": "Allow",
                        "Action": "kms:DescribeKey",
                        "Resource": "*",
                    }
                else:
                    assert allowed_actions == ["sts:GetCallerIdentity"]
            else:
                assert all("*" not in resource for resource in resources)


def test_factory_boundary_is_both_identity_and_boundary_contract() -> None:
    expected_dynamodb = {
        "dynamodb:CreateTable",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:GetResourcePolicy",
        "dynamodb:ListTagsOfResource",
        "dynamodb:PutResourcePolicy",
        "dynamodb:Scan",
        "dynamodb:TagResource",
        "dynamodb:UpdateContinuousBackups",
    }
    assert actions("boundary") == {
        "sts:GetCallerIdentity",
        "kms:DescribeKey",
        *expected_dynamodb,
        "logs:CreateLogStream",
        "logs:PutLogEvents",
    }
    ledger = by_sid("boundary", "CreateConfigureAndReadExactLedger")
    assert ledger["Resource"] == "${ledger_table_arn}"
    assert set(strings(ledger["Action"])) == expected_dynamodb - {"dynamodb:Scan"}
    scan = by_sid("boundary", "CountOnlyExactEmptyLedger")
    assert scan["Resource"] == "${ledger_table_arn}"
    assert scan["Condition"] == {"StringEquals": {"dynamodb:Select": "COUNT"}}
    logs = by_sid("boundary", "WriteOnlyDedicatedFactoryLogStreams")
    assert logs["Resource"] == "${ledger_factory_log_stream_arn}"

    outside = by_sid("boundary", "DenyDynamoDbOutsideExactLedger")
    assert outside == {
        "Sid": "DenyDynamoDbOutsideExactLedger",
        "Effect": "Deny",
        "Action": "dynamodb:*",
        "NotResource": "${ledger_table_arn}",
    }
    unsupported = by_sid("boundary", "DenyUnsupportedActionsOnExactLedger")
    assert unsupported["Resource"] == "${ledger_table_arn}"
    assert set(strings(unsupported["NotAction"])) == expected_dynamodb
    kms = by_sid("boundary", "ReadOnlyAwsManagedDynamoDbKeyMetadata")
    assert kms == {
        "Sid": "ReadOnlyAwsManagedDynamoDbKeyMetadata",
        "Effect": "Allow",
        "Action": "kms:DescribeKey",
        "Resource": "*",
    }
    cap = by_sid(
        "boundary", "DenyEverythingOutsideDedicatedRuntimeContract"
    )
    assert set(strings(cap["NotAction"])) == actions("boundary")


def test_put_policy_and_tag_are_only_create_table_dependent_permissions() -> None:
    for name in ("activator", "invoker", "revoker", "function_factory"):
        assert "dynamodb:PutResourcePolicy" not in actions(name)
        assert "dynamodb:TagResource" not in actions(name)
        assert "dynamodb:CreateTable" not in actions(name)
        assert "dynamodb:UpdateContinuousBackups" not in actions(name)
    dependency = by_sid("boundary", "CreateConfigureAndReadExactLedger")
    assert {"dynamodb:PutResourcePolicy", "dynamodb:TagResource"}.issubset(
        strings(dependency["Action"])
    )


def test_activator_can_only_attach_then_activate_exact_factory_role() -> None:
    assert actions("activator") == {
        "sts:GetCallerIdentity",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    }
    attach = by_sid("activator", "AttachExactFactoryPolicyWhileProofBound")
    assert attach["Resource"] == "${ledger_factory_role_arn}"
    assert attach["Condition"] == {
        "ArnEquals": {
            "iam:PermissionsBoundary": "${proof_boundary_arn}",
            "iam:PolicyARN": "${ledger_factory_boundary_arn}",
        }
    }
    activate = by_sid("activator", "ActivateExactFactoryBoundaryLast")
    assert activate["Condition"] == {
        "ArnEquals": {
            "iam:PermissionsBoundary": "${ledger_factory_boundary_arn}"
        }
    }


def test_invoker_only_targets_exact_version_and_read_only_certification() -> None:
    invoke = by_sid("invoker", "InvokeOnlyExactQualifiedFactoryVersion")
    assert invoke == {
        "Sid": "InvokeOnlyExactQualifiedFactoryVersion",
        "Effect": "Allow",
        "Action": "lambda:InvokeFunction",
        "Resource": "${ledger_factory_function_version_arn}",
    }
    assert actions("invoker") == {
        "sts:GetCallerIdentity",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:GetRuntimeManagementConfig",
        "lambda:InvokeFunction",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:GetResourcePolicy",
        "dynamodb:ListTagsOfResource",
        "dynamodb:Scan",
        "kms:DescribeKey",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
    }
    assert all(
        not action.startswith(("iam:Put", "iam:Attach", "iam:Detach"))
        and action
        not in {
            "lambda:InvokeAsync",
            "lambda:InvokeFunctionUrl",
        }
        for action in actions("invoker")
    )
    cap = by_sid("invoker", "DenyEveryMutationAndUnqualifiedInvocation")
    assert set(strings(cap["NotAction"])) == actions("invoker")


def test_revoker_enforces_proof_boundary_before_exact_detach() -> None:
    assert actions("revoker") == {
        "sts:GetCallerIdentity",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:PutRolePermissionsBoundary",
        "iam:DetachRolePolicy",
    }
    proof = by_sid("revoker", "RevokeFactoryToProofBoundaryFirst")
    assert proof["Condition"] == {
        "ArnEquals": {"iam:PermissionsBoundary": "${proof_boundary_arn}"}
    }
    detach = by_sid("revoker", "DetachFactoryPolicyOnlyAfterProofBoundary")
    assert detach["Condition"] == {
        "ArnEquals": {
            "iam:PermissionsBoundary": "${proof_boundary_arn}",
            "iam:PolicyARN": "${ledger_factory_boundary_arn}",
        }
    }
    assert "iam:DeleteRolePermissionsBoundary" not in actions("revoker")
    assert "iam:DeleteRole" not in actions("revoker")


def test_authorities_have_disjoint_forward_mutation_surfaces() -> None:
    mutation_actions = {
        name: {
            action
            for action in actions(name)
            if action.startswith(("dynamodb:", "iam:", "lambda:"))
            and not action.startswith(
                (
                    "dynamodb:Describe",
                    "dynamodb:Get",
                    "dynamodb:List",
                    "iam:Get",
                    "iam:List",
                    "lambda:Get",
                    "lambda:List",
                )
            )
            and action != "dynamodb:Scan"
        }
        for name in FILES
    }
    assert mutation_actions["boundary"] == {
        "dynamodb:CreateTable",
        "dynamodb:PutResourcePolicy",
        "dynamodb:TagResource",
        "dynamodb:UpdateContinuousBackups",
    }
    assert mutation_actions["activator"] == {
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    }
    assert mutation_actions["invoker"] == {"lambda:InvokeFunction"}
    assert mutation_actions["revoker"] == {
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
    }
    assert mutation_actions["function_factory"] == {
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:PutFunctionConcurrency",
        "lambda:PutRuntimeManagementConfig",
        "lambda:TagResource",
    }


def test_function_factory_action_cap_is_exact_and_self_closing() -> None:
    expected = {
        "sts:GetCallerIdentity",
        "iam:PassRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "s3:GetObjectVersion",
        "kms:Decrypt",
        "lambda:CreateFunction",
        "lambda:GetCodeSigningConfig",
        "lambda:GetFunction",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:GetRuntimeManagementConfig",
        "lambda:ListAliases",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListTags",
        "lambda:ListVersionsByFunction",
        "lambda:PutFunctionConcurrency",
        "lambda:PutRuntimeManagementConfig",
        "lambda:TagResource",
        "logs:CreateLogGroup",
        "logs:DescribeLogGroups",
        "logs:ListTagsForResource",
        "logs:PutRetentionPolicy",
        "logs:TagResource",
    }
    assert actions("function_factory") == expected
    assert "lambda:ListEventSourceMappings" not in expected

    denies = statements("function_factory", effect="Deny")
    assert len(denies) == 1
    deny = denies[0]
    assert set(deny) == {"Effect", "NotAction", "Resource"}
    assert deny["Resource"] == "*"
    assert set(strings(deny["NotAction"])) == expected

    forbidden = {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreateRole",
        "iam:PutRolePermissionsBoundary",
        "iam:PutRolePolicy",
        "lambda:AddPermission",
        "lambda:InvokeFunction",
        "lambda:PublishVersion",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "logs:DeleteLogGroup",
        "s3:DeleteObject",
        "s3:PutObject",
        "sts:AssumeRole",
    }
    assert expected.isdisjoint(forbidden)
    assert not any(action.startswith("dynamodb:") for action in expected)
    assert not any(
        action.startswith(("kms:Create", "kms:Put", "kms:ScheduleKeyDeletion"))
        for action in expected
    )


def test_function_factory_resources_and_conditions_remain_exact() -> None:
    assert all("Sid" not in item for item in statements("function_factory"))

    global_reads = statement_for_action(
        "function_factory", "sts:GetCallerIdentity"
    )
    assert global_reads["Resource"] == "*"
    assert set(strings(global_reads["Action"])) == {
        "sts:GetCallerIdentity",
        "logs:DescribeLogGroups",
    }
    assert "Condition" not in global_reads

    pass_role = statement_for_action("function_factory", "iam:PassRole")
    assert pass_role["Resource"] == "${ledger_factory_role_arn}"
    assert pass_role["Condition"] == {
        "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"},
        "ArnEquals": {
            "iam:AssociatedResourceArn": "${ledger_factory_function_arn}"
        },
    }

    iam_reads = statement_for_action("function_factory", "iam:GetPolicy")
    assert set(strings(iam_reads["Resource"])) == {
        "${proof_boundary_arn}",
        "${ledger_factory_role_arn}",
    }
    assert "Condition" not in iam_reads

    artifact = statement_for_action("function_factory", "s3:GetObjectVersion")
    assert artifact["Resource"] == "${ledger_factory_signed_object_arn}"
    assert artifact["Condition"] == {
        "StringEquals": {
            "s3:VersionId": "${ledger_factory_signed_version_id}",
            "s3:ResourceAccount": "${authority_account_id}",
        }
    }

    decrypt = statement_for_action("function_factory", "kms:Decrypt")
    assert decrypt["Resource"] == "${ledger_factory_signed_kms_key_arn}"
    assert decrypt["Condition"] == {
        "StringEquals": {
            "kms:CallerAccount": "${authority_account_id}",
            "kms:ViaService": "s3.${region}.amazonaws.com",
            "kms:EncryptionContext:aws:s3:arn": [
                "${ledger_factory_signed_object_arn}",
                "${ledger_factory_signed_bucket_arn}",
            ],
        }
    }

    create = statement_for_action("function_factory", "lambda:CreateFunction")
    tag = statement_for_action("function_factory", "lambda:TagResource")
    assert create["Resource"] == tag["Resource"] == (
        "${ledger_factory_function_arn}"
    )
    assert set(create["Condition"]) == {
        "ArnEquals",
        "StringEquals",
        "ForAllValues:StringEquals",
        "Null",
    }
    assert set(tag["Condition"]) == {
        "StringEquals",
        "ForAllValues:StringEquals",
    }
    assert create["Condition"]["StringEquals"] == tag["Condition"][
        "StringEquals"
    ]
    assert create["Condition"]["ForAllValues:StringEquals"] == tag[
        "Condition"
    ]["ForAllValues:StringEquals"]
    assert create["Condition"]["ArnEquals"] == {
        "lambda:CodeSigningConfigArn": (
            "${ledger_factory_code_signing_config_arn}"
        )
    }
    assert create["Condition"]["Null"] == {
        "lambda:Layer": "true",
        "lambda:VpcIds": "true",
        "lambda:SubnetIds": "true",
        "lambda:SecurityGroupIds": "true",
    }

    function_state = statement_for_action(
        "function_factory", "lambda:PutFunctionConcurrency"
    )
    assert set(strings(function_state["Resource"])) == {
        "${ledger_factory_function_arn}",
        "${ledger_factory_function_version_arn}",
        "${ledger_factory_code_signing_config_arn}",
    }
    assert "${ledger_factory_function_arn}:*" not in strings(
        function_state["Resource"]
    )
    assert "Condition" not in function_state

    create_logs = statement_for_action("function_factory", "logs:CreateLogGroup")
    assert set(strings(create_logs["Action"])) == {
        "logs:CreateLogGroup",
        "logs:TagResource",
    }
    assert create_logs["Resource"] == "${ledger_factory_log_group_arn}"
    assert set(create_logs["Condition"]) == {
        "StringEquals",
        "ForAllValues:StringEquals",
    }
    log_readback = statement_for_action(
        "function_factory", "logs:PutRetentionPolicy"
    )
    assert set(strings(log_readback["Action"])) == {
        "logs:PutRetentionPolicy",
        "logs:ListTagsForResource",
    }
    assert log_readback["Resource"] == "${ledger_factory_log_group_arn}"
    assert "Condition" not in log_readback


def test_function_factory_fits_managed_policy_limit_after_exact_arn_render() -> None:
    source = FILES["function_factory"].read_text(encoding="utf-8")
    for key in EXPECTED_PLACEHOLDERS["function_factory"]:
        source = source.replace(
            "${" + key + "}", FUNCTION_FACTORY_RENDER_VALUES[key]
        )
    assert "${" not in source
    rendered = json.loads(source)
    canonical = json.dumps(
        rendered, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert len(canonical) <= MAX_POLICY_BYTES


def test_policies_render_without_unknown_placeholders() -> None:
    values = {
        "ledger_table_arn": "arn:aws:dynamodb:us-east-1:111122223333:table/exact",
        "ledger_factory_log_stream_arn": "arn:aws:logs:us-east-1:111122223333:log-group:exact:log-stream:exact",
        "ledger_factory_boundary_arn": "arn:aws:iam::111122223333:policy/exact/factory",
        "proof_boundary_arn": "arn:aws:iam::111122223333:policy/exact/proof",
        "ledger_factory_role_arn": "arn:aws:iam::111122223333:role/ExactFactory",
        "ledger_factory_function_version_arn": "arn:aws:lambda:us-east-1:111122223333:function:exact:7",
        **FUNCTION_FACTORY_RENDER_VALUES,
    }
    for name, path in FILES.items():
        source = path.read_text(encoding="utf-8")
        for key in EXPECTED_PLACEHOLDERS[name]:
            source = source.replace("${" + key + "}", values[key])
        assert "${" not in source
        json.loads(source)
