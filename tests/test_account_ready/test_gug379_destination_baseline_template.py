"""Offline structural checks for the GUG-379 parent and terminal-role templates."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PARENT_PATH = REPO_ROOT / "bootstrap" / "cfn-tf-state-backend.yaml"
COMPANION_PATH = REPO_ROOT / "bootstrap" / "cfn-terminal-roles.yaml"

KEYS = {
    "StateKmsKey": "StateKmsAlias",
    "EvidenceKmsKey": "EvidenceKmsAlias",
    "ContractsKmsKey": "ContractsKmsAlias",
}
BUCKETS = {
    "StateBucket": ("StateKmsKey", "StateBucketPolicy"),
    "PlanBucket": ("EvidenceKmsKey", "PlanBucketPolicy"),
    "EvidenceBucket": ("EvidenceKmsKey", "EvidenceBucketPolicy"),
    "ContractsBucket": ("ContractsKmsKey", "ContractsBucketPolicy"),
}
ROLES = {
    "PlanRole": "ScanalyzeCustomer-Plan",
    "ApplyRole": "ScanalyzeCustomer-Apply",
    "IdentityPlanRole": "ScanalyzeCustomer-Identity-Plan",
    "IdentityApplyRole": "ScanalyzeCustomer-Identity-Apply",
    "PromotionRole": "ScanalyzeCustomer-Promotion",
    "ValidationRole": "ScanalyzeCustomer-Validation",
    "DiagnosticRole": "ScanalyzeCustomer-Diagnostic",
    "StateRecoveryRole": "ScanalyzeCustomer-StateRecovery",
}
ROLE_POLICIES = {
    "PlanRole": ["PlanPolicy"],
    "ApplyRole": [
        "ApplyStateContractPolicy",
        "ApplyFoundationPolicy",
        "ApplyDeliveryPolicy",
    ],
    "IdentityPlanRole": ["IdentityPlanPolicy"],
    "IdentityApplyRole": [
        "IdentityApplyCorePolicy",
        "IdentityApplyResourcesPolicy",
    ],
    "PromotionRole": ["PromotionPolicy"],
    "ValidationRole": ["ValidationPolicy"],
    "DiagnosticRole": ["DiagnosticPolicy"],
    "StateRecoveryRole": ["StateRecoveryPolicy"],
}
ROLE_BOUNDARIES = {
    "PlanRole": "PlanPolicy",
    "ApplyRole": "ApplyBoundary",
    "IdentityPlanRole": "IdentityPlanPolicy",
    "IdentityApplyRole": "IdentityApplyBoundary",
    "PromotionRole": "PromotionPolicy",
    "ValidationRole": "ValidationPolicy",
    "DiagnosticRole": "DiagnosticPolicy",
    "StateRecoveryRole": "StateRecoveryPolicy",
}
IAM_FIXTURES = {
    "PlanRole": "plan-role.json",
    "ApplyRole": "apply-role.json",
    "IdentityPlanRole": "identity-control-plane-plan-role.json",
    "IdentityApplyRole": "identity-control-plane-apply-role.json",
    "PromotionRole": "promotion-role.json",
    "ValidationRole": "validation-role.json",
    "DiagnosticRole": "diagnostic-role.json",
    "StateRecoveryRole": "state-recovery-role.json",
}
TRUST_FIXTURES = {
    "PlanRole": "plan-trust.json",
    "ApplyRole": "apply-trust.json",
    "IdentityPlanRole": "identity-plan-trust.json",
    "IdentityApplyRole": "identity-apply-trust.json",
    "PromotionRole": "promotion-trust.json",
    "ValidationRole": "validation-trust.json",
    "DiagnosticRole": "diagnostic-trust.json",
}
BOUND_TAGS = {
    "customer_id": {"Ref": "CustomerId"},
    "deployment_id": {"Ref": "DeploymentId"},
    "account_id": {"Ref": "AWS::AccountId"},
    "region": {"Ref": "AWS::Region"},
    "environment": {"Ref": "Environment"},
}
CHILD_PARAMETERS = {
    "CustomerId",
    "DeploymentId",
    "SharedServicesAccountId",
    "Environment",
    "StateBucketArn",
    "PlanBucketArn",
    "EvidenceBucketArn",
    "ContractsBucketArn",
    "StateKmsKeyArn",
    "EvidenceKmsKeyArn",
    "ContractsKmsKeyArn",
}
MAX_QUOTA_VALUES = {
    "AWS::Partition": "aws-us-gov",
    "AWS::AccountId": "123456789012",
    "AWS::Region": "ap-southeast-5",
    "AWS::URLSuffix": "amazonaws.com.cn",
    "CustomerId": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "DeploymentId": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "SharedServicesAccountId": "210987654321",
    "StateBucketArn": "arn:aws-us-gov:s3:::scanalyze-123456789012-tf-state",
    "PlanBucketArn": "arn:aws-us-gov:s3:::scanalyze-123456789012-tf-plan",
    "EvidenceBucketArn": "arn:aws-us-gov:s3:::scanalyze-123456789012-tf-evidence",
    "ContractsBucketArn": "arn:aws-us-gov:s3:::scanalyze-123456789012-contracts",
    "StateKmsKeyArn": (
        "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/"
        "11111111-1111-1111-1111-111111111111"
    ),
    "EvidenceKmsKeyArn": (
        "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/"
        "22222222-2222-2222-2222-222222222222"
    ),
    "ContractsKmsKeyArn": (
        "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/"
        "33333333-3333-3333-3333-333333333333"
    ),
}


class _CloudFormationLoader(yaml.SafeLoader):
    """Preserve CloudFormation intrinsics as ordinary mappings."""

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


@pytest.fixture(scope="module")
def parent_source() -> str:
    return PARENT_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def parent() -> dict[str, Any]:
    return _load_template(PARENT_PATH)


@pytest.fixture(scope="module")
def companion_source() -> str:
    return COMPANION_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def companion() -> dict[str, Any]:
    return _load_template(COMPANION_PATH)


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(document["Statement"])


def _tags(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        tag["Key"]: tag["Value"]
        for tag in resource["Properties"].get("Tags", [])
    }


def _fixture(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _policy_document(
    companion: dict[str, Any], policy_name: str
) -> dict[str, Any]:
    resource = companion["Resources"][policy_name]
    assert resource["Type"] == "AWS::IAM::ManagedPolicy"
    return resource["Properties"]["PolicyDocument"]


def _role_statements(
    companion: dict[str, Any], role_name: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for policy_name in ROLE_POLICIES[role_name]:
        for statement in _statements(_policy_document(companion, policy_name)):
            sid = statement["Sid"]
            assert sid not in result, f"duplicate Sid {sid} for {role_name}"
            result[sid] = statement
    return result


def _normalize_policy_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"Fn::Sub"} and isinstance(value["Fn::Sub"], str):
            rendered = value["Fn::Sub"]
            replacements = (
                (
                    "${StateBucketArn}",
                    "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-state",
                ),
                (
                    "${PlanBucketArn}",
                    "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-plan",
                ),
                (
                    "${EvidenceBucketArn}",
                    "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-evidence",
                ),
                (
                    "${ContractsBucketArn}",
                    "arn:${aws_partition}:s3:::scanalyze-${account_id}-contracts",
                ),
                (
                    "${StateKmsKeyArn}",
                    "arn:${aws_partition}:kms:${region}:${account_id}:key/"
                    "${state_kms_key_id}",
                ),
                (
                    "${EvidenceKmsKeyArn}",
                    "arn:${aws_partition}:kms:${region}:${account_id}:key/"
                    "${evidence_kms_key_id}",
                ),
                (
                    "${ContractsKmsKeyArn}",
                    "arn:${aws_partition}:kms:${region}:${account_id}:key/"
                    "${contracts_kms_key_id}",
                ),
                ("${AWS::Partition}", "${aws_partition}"),
                ("${AWS::AccountId}", "${account_id}"),
                ("${AWS::Region}", "${region}"),
                ("${AWS::URLSuffix}", "${aws_url_suffix}"),
                ("${DeploymentId}", "${deployment_id}"),
                ("${CustomerId}", "${customer_id}"),
                ("${!aws:", "${aws:"),
            )
            for source, destination in replacements:
                rendered = rendered.replace(source, destination)
            return rendered
        return {key: _normalize_policy_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_policy_value(item) for item in value]
    return value


def _normalize_trust_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"Fn::Sub"} and isinstance(value["Fn::Sub"], str):
            rendered = value["Fn::Sub"]
            replacements = (
                ("${AWS::Partition}", "aws"),
                ("${SharedServicesAccountId}", "${shared_services_account_id}"),
                ("${DeploymentId}", "${deployment_id}"),
                ("${!aws:", "${aws:"),
            )
            for source, destination in replacements:
                rendered = rendered.replace(source, destination)
            return rendered
        return {key: _normalize_trust_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_trust_value(item) for item in value]
    return value


def _without_quota_only_trust_fields(statement: dict[str, Any]) -> dict[str, Any]:
    result = {key: value for key, value in statement.items() if key != "Sid"}
    condition = result.get("Condition")
    if isinstance(condition, dict):
        condition = dict(condition)
        condition.pop("Null", None)
        result["Condition"] = condition
    return result


def _render_for_iam_quota(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"Ref"}:
            return MAX_QUOTA_VALUES.get(value["Ref"], value["Ref"])
        if set(value) == {"Fn::Sub"} and isinstance(value["Fn::Sub"], str):
            rendered = value["Fn::Sub"]
            for name, replacement in MAX_QUOTA_VALUES.items():
                rendered = rendered.replace(f"${{{name}}}", replacement)
            return rendered.replace("${!", "${")
        return {key: _render_for_iam_quota(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_for_iam_quota(item) for item in value]
    return value


def _compact_json_size(value: Any) -> int:
    return len(
        json.dumps(
            _render_for_iam_quota(value),
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )


def _policy_bundle_sha() -> str:
    bundle = {
        fixture_name: _fixture(REPO_ROOT / "policies" / "iam" / fixture_name)
        for fixture_name in IAM_FIXTURES.values()
    }
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def test_templates_parse_and_fit_transport_limits(
    parent_source: str, companion_source: str
) -> None:
    assert len(parent_source.encode()) < 51_200
    assert len(parent_source.replace("\n", "\r\n").encode()) < 51_200
    assert len(companion_source.encode()) < 1_000_000
    assert len(companion_source.replace("\n", "\r\n").encode()) < 1_000_000


def test_cloudformation_loader_rejects_duplicate_yaml_keys() -> None:
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load("Resource:\n  Type: first\n  Type: second\n", Loader=_CloudFormationLoader)


def test_parent_is_only_durable_baseline_plus_exact_nested_interface(
    parent: dict[str, Any], parent_source: str
) -> None:
    assert set(parent["Parameters"]) == {
        "CustomerId",
        "DeploymentId",
        "SharedServicesAccountId",
        "Environment",
        "TerminalRolesTemplateUrl",
    }
    url_parameter = parent["Parameters"]["TerminalRolesTemplateUrl"]
    assert "Default" not in url_parameter
    assert url_parameter["MaxLength"] == 1024
    assert "BackendConfig" not in parent["Outputs"]
    assert "SanitizedDeploymentId" not in parent["Parameters"]

    resources = parent["Resources"]
    assert Counter(resource["Type"] for resource in resources.values()) == {
        "AWS::KMS::Key": 3,
        "AWS::KMS::Alias": 3,
        "AWS::S3::Bucket": 4,
        "AWS::S3::BucketPolicy": 4,
        "AWS::CloudFormation::Stack": 1,
    }
    assert "dynamodb" not in parent_source.lower()
    assert not any("LogGroup" in resource["Type"] for resource in resources.values())
    assert not any(resource["Type"].startswith("AWS::IAM::") for resource in resources.values())

    nested = resources["TerminalRoles"]
    assert nested["DeletionPolicy"] == "Retain"
    assert nested["UpdateReplacePolicy"] == "Retain"
    assert nested["DependsOn"] == [
        "StateBucketPolicy",
        "PlanBucketPolicy",
        "EvidenceBucketPolicy",
        "ContractsBucketPolicy",
    ]
    assert nested["Properties"]["TemplateURL"] == {"Ref": "TerminalRolesTemplateUrl"}
    assert nested["Properties"]["Parameters"] == {
        "CustomerId": {"Ref": "CustomerId"},
        "DeploymentId": {"Ref": "DeploymentId"},
        "SharedServicesAccountId": {"Ref": "SharedServicesAccountId"},
        "Environment": {"Ref": "Environment"},
        "StateBucketArn": {"Fn::GetAtt": "StateBucket.Arn"},
        "PlanBucketArn": {"Fn::GetAtt": "PlanBucket.Arn"},
        "EvidenceBucketArn": {"Fn::GetAtt": "EvidenceBucket.Arn"},
        "ContractsBucketArn": {"Fn::GetAtt": "ContractsBucket.Arn"},
        "StateKmsKeyArn": {"Fn::GetAtt": "StateKmsKey.Arn"},
        "EvidenceKmsKeyArn": {"Fn::GetAtt": "EvidenceKmsKey.Arn"},
        "ContractsKmsKeyArn": {"Fn::GetAtt": "ContractsKmsKey.Arn"},
    }
    assert _tags(nested) == BOUND_TAGS


def test_parent_pins_exact_child_bytes_and_non_null_s3_version(
    parent: dict[str, Any], companion_source: str
) -> None:
    child_sha = hashlib.sha256(companion_source.encode()).hexdigest()
    metadata = parent["Metadata"]["Scanalyze"]
    assert metadata["TerminalRolesTemplateSha256"] == f"sha256:{child_sha}"
    assert metadata["TerminalRolesPolicyBundleSha256"] == (
        f"sha256:{_policy_bundle_sha()}"
    )

    parameter = parent["Parameters"]["TerminalRolesTemplateUrl"]
    pattern = parameter["AllowedPattern"]
    valid_url = (
        "https://scanalyze-shared-releases.s3.us-east-1.amazonaws.com/"
        f"terminal-roles/sha256/{child_sha}/cfn-terminal-roles.yaml?versionId=3Lg+/v1="
    )
    assert len(valid_url) <= parameter["MaxLength"]
    assert re.fullmatch(pattern, valid_url)
    version_prefix = valid_url.split("versionId=", maxsplit=1)[0] + "versionId="
    rejected = (
        valid_url.replace("scanalyze-shared-releases", "attacker"),
        valid_url.replace(child_sha, "0" * 64),
        valid_url.split("?", maxsplit=1)[0],
        version_prefix + "null",
        version_prefix + "NuLl",
        version_prefix + "%6e%75%6c%6c",
    )
    assert not any(re.fullmatch(pattern, value) for value in rejected)
    assert len(version_prefix + "a" * 900) > 1024


def test_three_keys_four_buckets_and_guard_policies_share_retained_lifecycle(
    parent: dict[str, Any]
) -> None:
    resources = parent["Resources"]
    for key_name, alias_name in KEYS.items():
        key = resources[key_name]
        assert key["DeletionPolicy"] == "Retain"
        assert key["UpdateReplacePolicy"] == "Retain"
        assert key["Properties"]["EnableKeyRotation"] is True
        assert key["Properties"]["KeySpec"] == "SYMMETRIC_DEFAULT"
        assert _tags(key) | BOUND_TAGS == _tags(key)
        assert resources[alias_name]["Properties"]["TargetKeyId"] == {"Ref": key_name}

    for bucket_name, (key_name, policy_name) in BUCKETS.items():
        bucket = resources[bucket_name]
        policy = resources[policy_name]
        for resource in (bucket, policy):
            assert resource["DeletionPolicy"] == "Retain"
            assert resource["UpdateReplacePolicy"] == "Retain"
        properties = bucket["Properties"]
        assert properties["VersioningConfiguration"] == {"Status": "Enabled"}
        assert properties["BucketEncryption"] == {
            "ServerSideEncryptionConfiguration": [
                {
                    "ServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": {"Fn::GetAtt": f"{key_name}.Arn"},
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        }
        assert set(properties["PublicAccessBlockConfiguration"].values()) == {True}
        assert _tags(bucket) | BOUND_TAGS == _tags(bucket)

        if bucket_name == "StateBucket":
            assert "ObjectLockEnabled" not in properties
            assert "LifecycleConfiguration" not in properties
        elif bucket_name == "PlanBucket":
            assert "ObjectLockEnabled" not in properties
            assert properties["LifecycleConfiguration"] == {
                "Rules": [
                    {
                        "Id": "ExpireEphemeralPlanExecution",
                        "Prefix": "plan-execution/",
                        "Status": "Enabled",
                        "ExpirationInDays": 1,
                        "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
                    }
                ]
            }
        elif bucket_name == "EvidenceBucket":
            assert properties["ObjectLockEnabled"] is True
            assert properties["ObjectLockConfiguration"] == {
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 90}},
            }
        else:
            assert "ObjectLockEnabled" not in properties


def test_bucket_policies_preserve_transport_kms_and_worm_denies(
    parent: dict[str, Any]
) -> None:
    resources = parent["Resources"]
    for bucket_name, (key_name, policy_name) in BUCKETS.items():
        properties = resources[policy_name]["Properties"]
        assert properties["Bucket"] == {"Ref": bucket_name}
        statements = {
            statement["Sid"]: statement
            for statement in _statements(properties["PolicyDocument"])
        }
        expected = {
            "DenyInsecureTransport",
            "DenyMissingKmsEncryption",
            "DenyWrongKmsKey",
        }
        if bucket_name == "EvidenceBucket":
            expected.add("DenyObjectLockOverride")
        assert set(statements) == expected
        assert all(statement["Effect"] == "Deny" for statement in statements.values())
        assert statements["DenyWrongKmsKey"]["Condition"]["StringNotEquals"] == {
            "s3:x-amz-server-side-encryption-aws-kms-key-id": {
                "Fn::GetAtt": f"{key_name}.Arn"
            }
        }


def test_companion_has_exact_roles_policies_boundaries_and_outputs(
    companion: dict[str, Any]
) -> None:
    assert set(companion["Parameters"]) == CHILD_PARAMETERS
    resources = companion["Resources"]
    assert Counter(resource["Type"] for resource in resources.values()) == {
        "AWS::IAM::ManagedPolicy": 13,
        "AWS::IAM::Role": 8,
    }
    assert set(companion["Outputs"]) == {f"{name}Arn" for name in ROLES}
    assert companion["Metadata"]["Scanalyze"]["PolicyBundleSha256"] == (
        f"sha256:{_policy_bundle_sha()}"
    )

    for role_name, role_value in ROLES.items():
        properties = resources[role_name]["Properties"]
        assert properties["RoleName"] == role_value
        assert properties["MaxSessionDuration"] == 3600
        assert properties["PermissionsBoundary"] == {
            "Ref": ROLE_BOUNDARIES[role_name]
        }
        assert properties["ManagedPolicyArns"] == [
            {"Ref": policy_name} for policy_name in ROLE_POLICIES[role_name]
        ]
        assert len(properties["ManagedPolicyArns"]) <= 10
        assert "Policies" not in properties
        assert _tags(resources[role_name]) == BOUND_TAGS
        assert companion["Outputs"][f"{role_name}Arn"] == {
            "Value": {"Fn::GetAtt": f"{role_name}.Arn"}
        }


def test_parent_role_outputs_are_exact_nested_passthrough(
    parent: dict[str, Any]
) -> None:
    for role_name in ROLES:
        output_name = f"{role_name}Arn"
        assert parent["Outputs"][output_name] == {
            "Value": {"Fn::GetAtt": f"TerminalRoles.Outputs.{output_name}"}
        }


def test_rendered_managed_policies_and_trusts_fit_default_iam_quotas(
    companion: dict[str, Any]
) -> None:
    for name, resource in companion["Resources"].items():
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            size = _compact_json_size(resource["Properties"]["PolicyDocument"])
            assert size <= 6_144, f"{name} renders to {size} policy characters"
        elif resource["Type"] == "AWS::IAM::Role":
            size = _compact_json_size(resource["Properties"]["AssumeRolePolicyDocument"])
            assert size <= 2_048, f"{name} trust renders to {size} policy characters"


def test_attached_cfn_union_equals_iam_fixtures_action_resource_condition(
    companion: dict[str, Any]
) -> None:
    for role_name, fixture_name in IAM_FIXTURES.items():
        expected = {
            statement["Sid"]: statement
            for statement in _statements(
                _fixture(REPO_ROOT / "policies" / "iam" / fixture_name)
            )
        }
        actual = {
            sid: _normalize_policy_value(statement)
            for sid, statement in _role_statements(companion, role_name).items()
        }
        assert actual == expected, role_name


def test_apply_boundaries_cover_fixture_resources_and_preserve_baseline(
    companion: dict[str, Any]
) -> None:
    for role_name, boundary_name in (
        ("ApplyRole", "ApplyBoundary"),
        ("IdentityApplyRole", "IdentityApplyBoundary"),
    ):
        boundary = _normalize_policy_value(_policy_document(companion, boundary_name))
        boundary_allows = [
            statement
            for statement in _statements(boundary)
            if statement["Effect"] == "Allow"
        ]
        fixture = _fixture(
            REPO_ROOT / "policies" / "iam" / IAM_FIXTURES[role_name]
        )
        for statement in _statements(fixture):
            if statement["Effect"] != "Allow":
                continue
            for action in _items(statement["Action"]):
                for resource in _items(statement["Resource"]):
                    assert any(
                        any(
                            fnmatch.fnmatchcase(action.lower(), pattern.lower())
                            for pattern in _items(boundary_statement["Action"])
                        )
                        and any(
                            pattern == "*"
                            or fnmatch.fnmatchcase(resource, pattern)
                            for pattern in _items(boundary_statement["Resource"])
                        )
                        for boundary_statement in boundary_allows
                    ), f"{boundary_name} blocks {statement['Sid']} {action} {resource}"

        boundary_denies = {
            statement["Sid"]: statement
            for statement in _statements(boundary)
            if statement["Effect"] == "Deny"
        }
        assert set(boundary_denies) == {
            "DenyBaselineBucketMutation",
            "DenyBaselineKeyMutation",
            "DenyEvidencePublication",
            "DenyPlanObjectMutation",
        }
        assert set(
            _items(boundary_denies["DenyBaselineBucketMutation"]["Action"])
        ) == {
            "s3:DeleteBucket*",
            "s3:PutBucket*",
            "s3:PutEncryptionConfiguration",
        }
        assert set(
            _items(boundary_denies["DenyBaselineBucketMutation"]["Resource"])
        ) == {
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-state",
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-plan",
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-evidence",
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-contracts",
        }
        plan_object_deny = boundary_denies["DenyPlanObjectMutation"]
        assert set(_items(plan_object_deny["Action"])) == {
            "s3:DeleteObject*",
            "s3:GetObject",
            "s3:PutObject*",
        }
        assert _items(plan_object_deny["Resource"]) == [
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-plan/*"
        ]
        assert {"kms:CreateGrant", "kms:TagResource"} <= set(
            _items(boundary_denies["DenyBaselineKeyMutation"]["Action"])
        )
        evidence_deny = _normalize_policy_value(
            boundary_denies["DenyEvidencePublication"]
        )
        assert set(_items(evidence_deny["Action"])) == {
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "s3:PutObject",
        }
        assert set(_items(evidence_deny["Resource"])) == {
            "arn:${aws_partition}:kms:${region}:${account_id}:key/"
            "${evidence_kms_key_id}",
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-evidence/*",
        }


def test_live_trust_matches_fixtures_except_inert_state_recovery(
    companion: dict[str, Any]
) -> None:
    for role_name, fixture_name in TRUST_FIXTURES.items():
        expected = [
            _without_quota_only_trust_fields(statement)
            for statement in _statements(
                _fixture(REPO_ROOT / "policies" / "trust" / fixture_name)
            )
        ]
        actual = _normalize_trust_value(
            _statements(
                companion["Resources"][role_name]["Properties"][
                    "AssumeRolePolicyDocument"
                ]
            )
        )
        assert actual == expected, role_name
        assert [statement["Action"] for statement in actual] == [
            "sts:AssumeRole",
            "sts:TagSession",
            "sts:SetSourceIdentity",
        ]

    recovery = companion["Resources"]["StateRecoveryRole"]["Properties"][
        "AssumeRolePolicyDocument"
    ]
    assert _statements(recovery) == [
        {
            "Sid": "DenyStateRecoveryUntilIndependentApprovalIsWired",
            "Effect": "Deny",
            "Action": [
                "sts:AssumeRole",
                "sts:TagSession",
                "sts:SetSourceIdentity",
            ],
            "Principal": "*",
        }
    ]


def test_validation_promotion_shared_release_and_saved_plan_boundaries(
    companion: dict[str, Any]
) -> None:
    validation_trust = companion["Resources"]["ValidationRole"]["Properties"][
        "AssumeRolePolicyDocument"
    ]
    for statement in _statements(validation_trust):
        if statement["Action"] in {"sts:AssumeRole", "sts:TagSession"}:
            equals = statement["Condition"]["StringEquals"]
            assert equals["aws:RequestTag/operation"] == "validate"
            assert set(equals["aws:RequestTag/layer"]) == {
                "artifact-publication",
                "synthetic-validation",
            }

    invalidation = _normalize_policy_value(
        _role_statements(companion, "PromotionRole")["InvalidateExactDistribution"]
    )
    assert invalidation["Condition"]["StringEquals"][
        "aws:ResourceTag/deployment_id"
    ] == "${deployment_id}"
    assert "cloudfront:CreateInvalidation" not in _items(
        _normalize_policy_value(
            _role_statements(companion, "ApplyRole")["ManageEdgeLayer"]
        )["Action"]
    )

    release_arn = "arn:${aws_partition}:s3:::scanalyze-shared-releases/*"
    for role_name, sid in (
        ("IdentityPlanRole", "ReadIdentityContractsAndArtifacts"),
        ("IdentityApplyRole", "ReadApprovedArtifacts"),
    ):
        statement = _normalize_policy_value(_role_statements(companion, role_name)[sid])
        assert release_arn in _items(statement["Resource"])
        assert "s3:GetObject" in _items(statement["Action"])
        assert not {"s3:ListBucket", "s3:PutObject", "s3:DeleteObject"} & set(
            _items(statement["Action"])
        )

    for plan_role, plan_sid, apply_role, apply_sid in (
        (
            "PlanRole",
            "WriteOwnSavedPlan",
            "ApplyRole",
            "ReadOwnSavedPlanVersion",
        ),
        (
            "IdentityPlanRole",
            "WriteIdentityPlanExecutionZone",
            "IdentityApplyRole",
            "ReadIdentityPlanExecutionZone",
        ),
    ):
        plan = _normalize_policy_value(_role_statements(companion, plan_role)[plan_sid])
        apply = _normalize_policy_value(_role_statements(companion, apply_role)[apply_sid])
        assert _items(plan["Action"]) == ["s3:GetObject", "s3:PutObject"]
        assert _items(apply["Action"]) == ["s3:GetObjectVersion"]
        assert apply["Resource"] == plan["Resource"]
        assert "-tf-plan/plan-execution/" in plan["Resource"]
        assert "-tf-state/plan-execution/" not in plan["Resource"]


def test_generic_apply_cannot_create_persistent_iam_or_touch_foreign_kms(
    companion: dict[str, Any]
) -> None:
    statements = {
        sid: _normalize_policy_value(statement)
        for sid, statement in _role_statements(companion, "ApplyRole").items()
    }
    actions = {
        action
        for statement in statements.values()
        if statement["Effect"] == "Allow"
        for action in _items(statement["Action"])
    }
    assert not actions & {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:CreateRole",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "kms:CreateKey",
        "kms:PutKeyPolicy",
    }

    for sid in (
        "ManageBoundLayerKey",
        "TagBoundLayerKey",
        "CreateBoundLayerGrant",
        "BindLayerAliasToBoundKey",
    ):
        statement = statements[sid]
        assert statement["Resource"] == (
            "arn:${aws_partition}:kms:${region}:${account_id}:key/*"
        )
        equals = statement["Condition"]["StringEquals"]
        assert equals["aws:ResourceTag/customer_id"] == "${customer_id}"
        assert equals["aws:ResourceTag/deployment_id"] == "${deployment_id}"
        assert equals["aws:ResourceTag/layer"] == "${aws:PrincipalTag/layer}"
    assert statements["CreateBoundLayerGrant"]["Condition"]["Bool"] == {
        "kms:GrantIsForAWSResource": "true"
    }
    assert _items(statements["ManageBoundLayerKey"]["Action"]) == [
        "kms:EnableKeyRotation"
    ]

    for boundary_name in ("ApplyBoundary", "IdentityApplyBoundary"):
        boundary_actions = {
            action
            for statement in _statements(_policy_document(companion, boundary_name))
            if statement["Effect"] == "Allow"
            for action in _items(statement["Action"])
        }
        assert not boundary_actions & {"kms:CreateKey", "kms:PutKeyPolicy"}


def test_saved_plan_writers_are_exact_and_nonwriters_cannot_publish_plans(
    companion: dict[str, Any]
) -> None:
    plan_bucket = (
        "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-plan"
    )
    evidence_key = (
        "arn:${aws_partition}:kms:${region}:${account_id}:key/"
        "${evidence_kms_key_id}"
    )
    plan_writers = {"PlanRole", "IdentityPlanRole"}
    for role_name in (*sorted(plan_writers), "ApplyRole", "IdentityApplyRole", "StateRecoveryRole"):
        statements = {
            sid: _normalize_policy_value(statement)
            for sid, statement in _role_statements(companion, role_name).items()
        }
        serialized = json.dumps(statements, sort_keys=True)
        assert "s3:GetObjectVersion" in serialized
        plan_writes: list[str] = []
        for statement in statements.values():
            if statement["Effect"] != "Allow":
                continue
            actions = set(_items(statement["Action"]))
            resources = _items(statement["Resource"])
            if "s3:PutObject" in actions:
                matching = [
                    resource
                    for resource in resources
                    if resource.startswith(plan_bucket)
                ]
                plan_writes.extend(matching)
                if role_name in plan_writers:
                    assert all(
                        "/plan-execution/${deployment_id}/"
                        "${aws:PrincipalTag/change_id}/" in resource
                        and resource.endswith("/plan.tfplan")
                        for resource in matching
                    ), role_name
                else:
                    assert not matching, role_name
            if actions & {
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKey*",
                "kms:GenerateDataKeyWithoutPlaintext",
            }:
                if evidence_key in resources:
                    assert role_name in plan_writers, role_name
                if role_name not in plan_writers:
                    assert evidence_key not in resources, role_name
        if role_name in plan_writers:
            assert len(plan_writes) == 1, role_name
        else:
            assert not plan_writes, role_name


def test_state_recovery_policy_is_future_authority_but_unreachable(
    companion: dict[str, Any]
) -> None:
    lock_delete = _normalize_policy_value(
        _role_statements(companion, "StateRecoveryRole")[
            "DeleteOnlyReviewedNativeLockfile"
        ]
    )
    assert lock_delete["Action"] == "s3:DeleteObject"
    assert lock_delete["Resource"].endswith(
        "/${deployment_id}/*/terraform.tfstate.tflock"
    )
    assert lock_delete["Condition"]["StringEquals"][
        "aws:PrincipalTag/recovery_approved"
    ] == "true"
    trust = companion["Resources"]["StateRecoveryRole"]["Properties"][
        "AssumeRolePolicyDocument"
    ]
    assert not any(statement["Effect"] == "Allow" for statement in _statements(trust))


def test_retained_terminal_roles_require_explicit_trust_first_decommission(
    parent: dict[str, Any]
) -> None:
    nested = parent["Resources"]["TerminalRoles"]
    assert nested["DeletionPolicy"] == "Retain"
    assert nested["UpdateReplacePolicy"] == "Retain"

    adr = (REPO_ROOT / "ADR" / "ADR-031-github-oidc-terminal-identity.md").read_text()
    threat = (REPO_ROOT / "docs" / "security" / "gug-379-threat-model-delta.md").read_text()
    assert "Deleting or replacing the parent" in adr
    assert "revoke" in adr.lower()
    assert "Parent deletion alone is never accepted" in adr
    assert "survive parent delete or replacement" in threat
    assert "decommission must revoke trusts first" in threat


def test_workload_iam_and_service_resource_binding_remain_deployment_no_go(
    companion: dict[str, Any]
) -> None:
    apply_actions = {
        action
        for statement in _role_statements(companion, "ApplyRole").values()
        if statement["Effect"] == "Allow"
        for action in _items(statement["Action"])
    }
    assert not apply_actions & {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreateRole",
        "iam:UpdateAssumeRolePolicy",
    }
    role_names = {
        resource["Properties"]["RoleName"]
        for resource in companion["Resources"].values()
        if resource["Type"] == "AWS::IAM::Role"
    }
    assert role_names == set(ROLES.values())
    assert 'resource "aws_iam_role"' in (
        REPO_ROOT / "modules" / "global" / "iam.tf"
    ).read_text()
    assert 'resource "aws_iam_role"' in (
        REPO_ROOT / "modules" / "cicd" / "main.tf"
    ).read_text()
    identity_apply_actions = {
        action
        for statement in _role_statements(companion, "IdentityApplyRole").values()
        if statement["Effect"] == "Allow"
        for action in _items(statement["Action"])
    }
    assert not identity_apply_actions & {
        "cognito-idp:AddCustomAttributes",
        "cognito-idp:CreateGroup",
        "cognito-idp:CreateResourceServer",
        "cognito-idp:CreateUserPool",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:CreateUserPoolDomain",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:TagResource",
        "cognito-idp:UntagResource",
        "cognito-idp:UpdateGroup",
        "cognito-idp:UpdateResourceServer",
        "cognito-idp:UpdateUserPool",
        "cognito-idp:UpdateUserPoolClient",
        "cognito-idp:UpdateUserPoolDomain",
        "cloudwatch:PutMetricAlarm",
        "dynamodb:PutResourcePolicy",
        "ecr:SetRepositoryPolicy",
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "logs:PutResourcePolicy",
        "s3:PutBucketPolicy",
        "secretsmanager:PutResourcePolicy",
        "sqs:AddPermission",
        "sqs:CreateQueue",
        "sqs:RemovePermission",
        "sqs:SetQueueAttributes",
    }
    identity_boundary_actions = {
        action
        for statement in _statements(
            _policy_document(companion, "IdentityApplyBoundary")
        )
        if statement["Effect"] == "Allow"
        for action in _items(statement["Action"])
    }
    assert not identity_boundary_actions & {
        "cognito-idp:AddCustomAttributes",
        "cognito-idp:CreateGroup",
        "cognito-idp:CreateResourceServer",
        "cognito-idp:CreateUserPool",
        "cognito-idp:CreateUserPoolClient",
        "cognito-idp:CreateUserPoolDomain",
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:TagResource",
        "cognito-idp:UntagResource",
        "cognito-idp:UpdateGroup",
        "cognito-idp:UpdateResourceServer",
        "cognito-idp:UpdateUserPool",
        "cognito-idp:UpdateUserPoolClient",
        "cognito-idp:UpdateUserPoolDomain",
        "cloudwatch:PutMetricAlarm",
        "dynamodb:PutResourcePolicy",
        "ecr:SetRepositoryPolicy",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "logs:PutResourcePolicy",
        "s3:PutBucketPolicy",
        "secretsmanager:PutResourcePolicy",
        "sqs:AddPermission",
        "sqs:CreateQueue",
        "sqs:RemovePermission",
        "sqs:SetQueueAttributes",
    }
    assert 'resource "aws_lambda_permission"' in (
        REPO_ROOT / "modules" / "identity-control-plane" / "pre_token.tf"
    ).read_text()
    assert 'resource "aws_sqs_queue"' in (
        REPO_ROOT / "modules" / "identity-control-plane" / "bootstrap.tf"
    ).read_text()
    identity_cognito = (
        REPO_ROOT / "modules" / "identity-control-plane" / "cognito.tf"
    ).read_text()
    assert 'resource "aws_cognito_user_group"' in identity_cognito
    assert 'resource "aws_cognito_resource_server"' in identity_cognito
    assert 'resource "aws_cognito_user_pool_client"' in identity_cognito
    for module_file in (
        REPO_ROOT / "modules" / "identity-control-plane" / "pre_token.tf",
        REPO_ROOT / "modules" / "identity-control-plane" / "control_processor.tf",
    ):
        assert 'resource "aws_iam_role"' in module_file.read_text()

    adr = (REPO_ROOT / "ADR" / "ADR-031-github-oidc-terminal-identity.md").read_text()
    threat = (REPO_ROOT / "docs" / "security" / "gug-379-threat-model-delta.md").read_text()
    for document in (adr, threat):
        assert "DEPLOYMENT_NO_GO" in document
        assert "session" in document.lower()
        assert "data-foundation" in document
        assert "CI/CD" in document
    assert "current Terraform KMS creation and tags" in threat
    assert "lambda:AddPermission" in threat
    assert "sqs:SetQueueAttributes" in threat
    assert "cognito-idp:CreateUserPoolClient" in threat
    assert "cognito-idp:DescribeUserPoolClient" in threat
    assert "policies are not widened" in threat
