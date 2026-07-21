"""GUG-219 reviewed Lambda authority materialization tests.

These tests encode the fail-closed contract. All provider records are
synthetic and contain no live AWS evidence.
"""
from __future__ import annotations

import copy
import importlib
import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from tooling.platform_authority_lambda_invocation_authority import (
    EXPECTED_AUTHORITY_EDGE_COUNT,
    RAW_SNAPSHOT_FORMAT,
    TargetBinding,
    _coverage as coverage_record,
    canonical_digest,
    digest_text,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT = "111122223333"
REGION = "us-east-1"
IDENTITY_CENTER_REGION = "us-east-1"
FUNCTION = "scanalyze-platform-authority-gug215-retirement"
SOURCE_COMMIT = subprocess.run(
    ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()

CLASSIFIER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ClassifierInvoker"
APPROVER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215ApproverInvoker"
CLASSIFIER_PERMISSION_SET = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireClass_0123456789abcdef"
)
APPROVER_PERMISSION_SET = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeAuthorityRetireApprove_fedcba9876543210"
)

COLLECTOR_NAME = "ScanalyzeAuthorityLambdaAudit"
COLLECTOR_SUFFIX = "0011223344556677"
ROTATED_COLLECTOR_SUFFIX = "8899aabbccddeeff"
COLLECTOR_ROLE_NAME = f"AWSReservedSSO_{COLLECTOR_NAME}_{COLLECTOR_SUFFIX}"
ROTATED_COLLECTOR_ROLE_NAME = (
    f"AWSReservedSSO_{COLLECTOR_NAME}_{ROTATED_COLLECTOR_SUFFIX}"
)
COLLECTOR_IAM_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    f"{COLLECTOR_ROLE_NAME}"
)
ROTATED_COLLECTOR_IAM_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    f"{ROTATED_COLLECTOR_ROLE_NAME}"
)
COLLECTOR_SESSION_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/{COLLECTOR_ROLE_NAME}/"
    "synthetic.operator@example.invalid"
)
ROTATED_COLLECTOR_SESSION_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROTATED_COLLECTOR_ROLE_NAME}/"
    "synthetic.operator@example.invalid"
)
CANONICAL_COLLECTOR_STS_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/{COLLECTOR_ROLE_NAME}"
)
ROTATED_CANONICAL_COLLECTOR_STS_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROTATED_COLLECTOR_ROLE_NAME}"
)

BROKER_CODE_SHA256 = "A" * 43 + "="
BROKER_CONFIGURATION_SHA256 = "sha256:" + "b" * 64
BROKER_EXECUTION_ROLE = (
    f"arn:aws:iam::{ACCOUNT}:role/ScanalyzeGug215BrokerExecution"
)

CANDIDATE_STARTED = "2030-01-01T00:00:00Z"
CANDIDATE_COMPLETED = "2030-01-01T00:01:00Z"
CANDIDATE_EXPIRES = "2030-01-01T00:06:00Z"
RELEASE_CREATED = "2030-01-01T00:01:30Z"
RELEASE_EXPIRES = "2030-01-01T00:05:30Z"
FRESH_STARTED = "2030-01-01T00:02:00Z"
FRESH_COMPLETED = "2030-01-01T00:03:00Z"
FRESH_EXPIRES = "2030-01-01T00:08:00Z"
EVALUATION_AT = "2030-01-01T00:03:01Z"


@lru_cache(maxsize=1)
def materializer() -> Any:
    """Load the tests-first target and report absence as a failing test."""

    try:
        return importlib.import_module(
            "tooling.platform_authority_lambda_invocation_materializer"
        )
    except ModuleNotFoundError as exc:
        pytest.fail(
            "GUG-219 materializer is not implemented yet: "
            "tooling.platform_authority_lambda_invocation_materializer",
            pytrace=False,
        )
        raise AssertionError("unreachable") from exc


def binding() -> TargetBinding:
    return TargetBinding(
        authority_account_id=ACCOUNT,
        region=REGION,
        function_name=FUNCTION,
    )


def _condition(action: str) -> dict[str, Any]:
    if action == "lambda:InvokeFunctionUrl":
        return {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
    return {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}


def _resource_policy(role_arn: str, alias: str) -> dict[str, Any]:
    resource = binding().alias_arn(alias)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FunctionUrl",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "lambda:InvokeFunctionUrl",
                "Resource": resource,
                "Condition": _condition("lambda:InvokeFunctionUrl"),
            },
            {
                "Sid": "ViaFunctionUrl",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "lambda:InvokeFunction",
                "Resource": resource,
                "Condition": _condition("lambda:InvokeFunction"),
            },
        ],
    }


def _identity_policy(aliases: list[str]) -> dict[str, Any]:
    resources = [binding().alias_arn(alias) for alias in aliases]
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
            {
                "Sid": "DenyDirectRetirementEffects",
                "Effect": "Deny",
                "Action": sorted(
                    materializer().EXPECTED_DIRECT_EFFECT_DENY_ACTIONS
                ),
                "Resource": "*",
            },
        ],
    }


def _trust(permission_set_arn: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeFromExactPermissionSet",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "ArnEquals": {"aws:PrincipalArn": permission_set_arn}
                },
            }
        ],
    }


def _collector_trust() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/AWSSSO"
                },
                "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                },
            }
        ],
    }


def collector_inline_policy(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    template_path = (
        repo_root
        / "policies/iam/platform-authority-lambda-invocation-inventory-role.json"
    )
    rendered = template_path.read_text(encoding="utf-8")
    replacements = {
        "${aws_partition}": "aws",
        "${region}": REGION,
        "${authority_account_id}": ACCOUNT,
        "${broker_function_name}": FUNCTION,
    }
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return json.loads(rendered)


def _snapshot_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
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
    return {
        key: coverage_record("COMPLETE", value, 1)
        for key, value in surfaces.items()
    }


def reseal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot.pop("snapshot_digest", None)
    snapshot["snapshot_digest"] = canonical_digest(snapshot)
    return snapshot


def seal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    snapshot["coverage"] = _snapshot_coverage(snapshot)
    return reseal_snapshot(snapshot)


def candidate_snapshot() -> dict[str, Any]:
    target = binding()
    value: dict[str, Any] = {
        "snapshot_format": RAW_SNAPSHOT_FORMAT,
        "capture_started_at": CANDIDATE_STARTED,
        "capture_completed_at": CANDIDATE_COMPLETED,
        "capture_expires_at": CANDIDATE_EXPIRES,
        "collector_nonce": "synthetic-gug219-candidate-0001",
        "collector_principal_arn": CANONICAL_COLLECTOR_STS_ARN,
        "collector_principal_arn_digest": digest_text(
            CANONICAL_COLLECTOR_STS_ARN
        ),
        "enabled_regions": [REGION],
        "scanned_regions": [REGION],
        "lambda": {
            "functions": [
                {
                    "FunctionName": FUNCTION,
                    "FunctionArn": target.function_arn,
                    "Version": "$LATEST",
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": BROKER_CONFIGURATION_SHA256,
                }
            ],
            "aliases": [
                {
                    "Name": alias,
                    "FunctionVersion": "1",
                    "FunctionArn": target.alias_arn(alias),
                }
                for alias in sorted(("classify", "retire", "reconcile"))
            ],
            "versions": [
                {
                    "Version": "$LATEST",
                    "FunctionArn": target.function_arn,
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": BROKER_CONFIGURATION_SHA256,
                },
                {
                    "Version": "1",
                    "FunctionArn": f"{target.function_arn}:1",
                    "CodeSha256": BROKER_CODE_SHA256,
                    "PublishedConfigurationDigest": BROKER_CONFIGURATION_SHA256,
                },
            ],
            "function_urls": [
                {
                    "FunctionArn": target.alias_arn(alias),
                    "AuthType": "AWS_IAM",
                    "InvokeMode": "BUFFERED",
                }
                for alias in sorted(("classify", "retire", "reconcile"))
            ],
            "resource_policies": [
                {
                    "resource_arn": target.alias_arn("classify"),
                    "policy_document": _resource_policy(
                        CLASSIFIER_ROLE, "classify"
                    ),
                },
                *[
                    {
                        "resource_arn": target.alias_arn(alias),
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
                            "PolicyDocument": _identity_policy(["classify"]),
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
                            "PolicyDocument": _identity_policy(
                                ["retire", "reconcile"]
                            ),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
                {
                    "Arn": COLLECTOR_IAM_ROLE_ARN,
                    "RoleName": COLLECTOR_ROLE_NAME,
                    "AssumeRolePolicyDocument": _collector_trust(),
                    "RolePolicyList": [
                        {
                            "PolicyName": COLLECTOR_NAME,
                            "PolicyDocument": collector_inline_policy(),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
            ],
            "policies": [],
            "managed_policy_documents": {},
        },
    }
    return seal_snapshot(value)


def fresh_snapshot() -> dict[str, Any]:
    value = copy.deepcopy(candidate_snapshot())
    value.update(
        {
            "capture_started_at": FRESH_STARTED,
            "capture_completed_at": FRESH_COMPLETED,
            "capture_expires_at": FRESH_EXPIRES,
            "collector_nonce": "synthetic-gug219-fresh-0002",
        }
    )
    return reseal_snapshot(value)


def collector_contract(
    *,
    iam_role_arn: str = COLLECTOR_IAM_ROLE_ARN,
    session_arn: str = COLLECTOR_SESSION_ARN,
    created_at: str = "2029-12-31T23:59:59Z",
) -> dict[str, Any]:
    module = materializer()
    return module.build_collector_contract(
        binding=binding(),
        identity_center_region=IDENTITY_CENTER_REGION,
        collector_iam_role_arn=iam_role_arn,
        collector_sts_session_arn=session_arn,
        created_at=created_at,
        repo_root=REPO_ROOT,
    )


def candidate_collector_contract() -> dict[str, Any]:
    return collector_contract()


def materialized_bundle() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    module = materializer()
    contract = collector_contract()
    allowlist, release = module.materialize_allowlist_release(
        snapshot=candidate_snapshot(),
        binding=binding(),
        collector_contract=contract,
        source_commit=SOURCE_COMMIT,
        created_at=RELEASE_CREATED,
        expires_at=RELEASE_EXPIRES,
        repo_root=REPO_ROOT,
    )
    return contract, allowlist, release


def _assert_materialization_error(code: str) -> Any:
    module = materializer()
    return pytest.raises(module.LambdaAuthorityMaterializationError, match=code)


def test_build_collector_contract_binds_exact_sso_iam_and_sts_role() -> None:
    contract = collector_contract()

    assert contract["permission_set_name"] == COLLECTOR_NAME
    assert contract["collector_role_iam_arn_digest"] == digest_text(
        COLLECTOR_IAM_ROLE_ARN
    )
    assert contract["collector_role_sts_arn_digest"] == digest_text(
        CANONICAL_COLLECTOR_STS_ARN
    )
    assert contract["managed_policy_arns"] == []
    assert contract["live_effect_authorized"] is False
    assert contract["collector_contract_digest"] == canonical_digest(
        {
            key: value
            for key, value in contract.items()
            if key != "collector_contract_digest"
        }
    )


def test_build_collector_contract_rejects_mismatched_sso_role_suffixes() -> None:
    with _assert_materialization_error("COLLECTOR_ROLE_BINDING_MISMATCH"):
        collector_contract(session_arn=ROTATED_COLLECTOR_SESSION_ARN)


@pytest.mark.parametrize(
    ("iam_role_arn", "session_arn"),
    (
        (
            f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
            "AWSReservedSSO_AWSReadOnlyAccess_0011223344556677",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/"
            "AWSReservedSSO_AWSReadOnlyAccess_0011223344556677/operator",
        ),
        (
            f"arn:aws:iam::{ACCOUNT}:role/ReadOnlyAccess",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/ReadOnlyAccess/operator",
        ),
    ),
)
def test_generic_readonly_roles_cannot_become_the_collector_contract(
    iam_role_arn: str,
    session_arn: str,
) -> None:
    with _assert_materialization_error("COLLECTOR_PERMISSION_SET_INVALID"):
        collector_contract(iam_role_arn=iam_role_arn, session_arn=session_arn)


def test_permission_set_suffix_rotation_produces_a_new_bound_contract() -> None:
    current = collector_contract()
    rotated = collector_contract(
        iam_role_arn=ROTATED_COLLECTOR_IAM_ROLE_ARN,
        session_arn=ROTATED_COLLECTOR_SESSION_ARN,
    )

    assert current["collector_inline_policy_digest"] == rotated[
        "collector_inline_policy_digest"
    ]
    assert current["collector_role_iam_arn_digest"] != rotated[
        "collector_role_iam_arn_digest"
    ]
    assert current["collector_role_sts_arn_digest"] != rotated[
        "collector_role_sts_arn_digest"
    ]
    assert current["collector_contract_digest"] != rotated[
        "collector_contract_digest"
    ]


def test_candidate_rejects_split_iam_and_sts_collector_suffixes() -> None:
    contract = collector_contract()
    contract["collector_role_sts_arn_digest"] = digest_text(
        ROTATED_CANONICAL_COLLECTOR_STS_ARN
    )
    contract["collector_contract_digest"] = canonical_digest(
        {
            key: value
            for key, value in contract.items()
            if key != "collector_contract_digest"
        }
    )
    snapshot = candidate_snapshot()
    snapshot["collector_principal_arn"] = ROTATED_CANONICAL_COLLECTOR_STS_ARN
    snapshot["collector_principal_arn_digest"] = digest_text(
        ROTATED_CANONICAL_COLLECTOR_STS_ARN
    )
    reseal_snapshot(snapshot)

    with _assert_materialization_error("COLLECTOR_ROLE_BINDING_MISMATCH"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=contract,
            repo_root=REPO_ROOT,
        )


def test_rendered_collector_policy_has_only_exact_reviewed_placeholders() -> None:
    policy = materializer().render_collector_inline_policy(
        binding=binding(), repo_root=REPO_ROOT
    )
    serialized = json.dumps(policy, sort_keys=True)

    assert "${" not in serialized
    assert binding().function_arn in serialized
    assert f"{binding().function_arn}:*" in serialized
    assert "lambda:GetPolicy" in serialized
    assert "lambda:Invoke*" in serialized
    assert "iam:Create*" in serialized
    assert not any(
        statement["Effect"] == "Allow"
        and any(
            str(action).startswith(("lambda:Invoke", "lambda:Create", "iam:Create"))
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        )
        for statement in policy["Statement"]
    )


def test_policy_renderer_rejects_an_unreviewed_template_placeholder(
    tmp_path: Path,
) -> None:
    template = (
        REPO_ROOT
        / "policies/iam/platform-authority-lambda-invocation-inventory-role.json"
    ).read_text(encoding="utf-8")
    policy_dir = tmp_path / "policies/iam"
    policy_dir.mkdir(parents=True)
    (policy_dir / "platform-authority-lambda-invocation-inventory-role.json").write_text(
        template.replace('"Version": "2012-10-17"', '"Version": "${future}"'),
        encoding="utf-8",
    )

    with _assert_materialization_error("POLICY_TEMPLATE_PLACEHOLDER_INVALID"):
        materializer().render_collector_inline_policy(
            binding=binding(), repo_root=tmp_path
        )


def test_materialization_is_deterministic_and_has_exactly_fourteen_edges() -> None:
    module = materializer()
    contract = collector_contract()
    arguments = {
        "snapshot": candidate_snapshot(),
        "binding": binding(),
        "collector_contract": contract,
        "source_commit": SOURCE_COMMIT,
        "created_at": RELEASE_CREATED,
        "expires_at": RELEASE_EXPIRES,
        "repo_root": REPO_ROOT,
    }

    first = module.materialize_allowlist_release(**arguments)
    second = module.materialize_allowlist_release(**copy.deepcopy(arguments))

    assert first == second
    allowlist, release = first
    assert len(allowlist["expected_authority_edges"]) == EXPECTED_AUTHORITY_EDGE_COUNT
    assert sum(
        edge["authority_class"] == "INVOCATION"
        for edge in allowlist["expected_authority_edges"]
    ) == 12
    assert sum(
        edge["authority_class"] == "TRUST"
        for edge in allowlist["expected_authority_edges"]
    ) == 2
    assert release["candidate_snapshot_digest"] == candidate_snapshot()[
        "snapshot_digest"
    ]
    assert release["allowlist_digest"] == allowlist["allowlist_digest"]
    assert release["collector_contract_digest"] == contract[
        "collector_contract_digest"
    ]


def test_candidate_capture_is_materialization_only_and_binds_exact_collector() -> None:
    assert materializer().validate_candidate_capture(
        snapshot=candidate_snapshot(),
        binding=binding(),
        collector_contract=candidate_collector_contract(),
        repo_root=REPO_ROOT,
    ) is True


def test_candidate_capture_rejects_contract_created_after_capture_start() -> None:
    with _assert_materialization_error("CANDIDATE_CAPTURE_TIME_INVALID"):
        materializer().validate_candidate_capture(
            snapshot=candidate_snapshot(),
            binding=binding(),
            collector_contract=collector_contract(created_at=RELEASE_CREATED),
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_contract_created_after_capture_start() -> None:
    with _assert_materialization_error("CANDIDATE_CAPTURE_TIME_INVALID"):
        materializer().materialize_allowlist_release(
            snapshot=candidate_snapshot(),
            binding=binding(),
            collector_contract=collector_contract(created_at=RELEASE_CREATED),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_candidate_capture_rejects_tampered_collector_inline_policy() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["roles"][2]["RolePolicyList"][0]["PolicyDocument"][
        "Statement"
    ][0]["Action"] = "lambda:GetFunction"
    seal_snapshot(snapshot)

    with _assert_materialization_error("COLLECTOR_INLINE_POLICY_NOT_EXACT"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


def test_candidate_capture_rejects_foreign_collector_trust() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["roles"][2]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"
    ] = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
    seal_snapshot(snapshot)

    with _assert_materialization_error("COLLECTOR_TRUST_POLICY_INVALID"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


def test_candidate_capture_rejects_additional_collector_trust_principal() -> None:
    snapshot = candidate_snapshot()
    principal = snapshot["iam"]["roles"][2]["AssumeRolePolicyDocument"][
        "Statement"
    ][0]["Principal"]
    principal["AWS"] = f"arn:aws:iam::{ACCOUNT}:root"
    seal_snapshot(snapshot)

    with _assert_materialization_error("COLLECTOR_TRUST_POLICY_INVALID"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


@pytest.mark.parametrize(
    ("partition", "audience"),
    (
        ("aws", "https://signin.aws.amazon.com/saml"),
        ("aws-us-gov", "https://signin.amazonaws-us-gov.com/saml"),
        ("aws-cn", "https://signin.amazonaws.cn/saml"),
    ),
)
def test_collector_trust_uses_the_partition_specific_saml_audience(
    partition: str, audience: str
) -> None:
    role = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            f"arn:{partition}:iam::{ACCOUNT}:"
                            "saml-provider/AWSSSO_0123456789abcdef_DO_NOT_DELETE"
                        )
                    },
                    "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                    "Condition": {"StringEquals": {"SAML:aud": audience}},
                }
            ],
        }
    }
    contract = {
        "partition": partition,
        "authority_account_id_digest": digest_text(ACCOUNT),
    }

    materializer()._validate_collector_trust(role, contract)


def test_collector_trust_rejects_a_foreign_partition_saml_audience() -> None:
    role = {
        "AssumeRolePolicyDocument": _collector_trust(),
    }
    contract = {
        "partition": "aws-cn",
        "authority_account_id_digest": digest_text(ACCOUNT),
    }

    with _assert_materialization_error("COLLECTOR_TRUST_POLICY_INVALID"):
        materializer()._validate_collector_trust(role, contract)


def test_candidate_capture_rejects_forged_complete_coverage_digest() -> None:
    snapshot = candidate_snapshot()
    snapshot["coverage"]["iam_account_authorization"]["evidence_digest"] = (
        "sha256:" + "0" * 64
    )
    reseal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_SNAPSHOT_INCOMPLETE"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


def test_candidate_capture_rejects_unscanned_enabled_region() -> None:
    snapshot = candidate_snapshot()
    snapshot["enabled_regions"].append("us-west-2")
    snapshot["coverage"] = _snapshot_coverage(snapshot)
    reseal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_SNAPSHOT_INCOMPLETE"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


def test_candidate_capture_rejects_unknown_snapshot_fields() -> None:
    snapshot = candidate_snapshot()
    snapshot["legacy_authority_complete"] = True
    reseal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_SNAPSHOT_FORMAT_INVALID"):
        materializer().validate_candidate_capture(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_managed_policy_attachment_on_collector() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["roles"][2]["AttachedManagedPolicies"] = [
        {
            "PolicyName": "ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        }
    ]
    seal_snapshot(snapshot)

    with _assert_materialization_error("COLLECTOR_MANAGED_POLICY_FORBIDDEN"):
        materializer().materialize_allowlist_release(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_incomplete_candidate_coverage() -> None:
    snapshot = candidate_snapshot()
    snapshot["coverage"]["iam_account_authorization"] = coverage_record(
        "ACCESS_DENIED", [], 0
    )
    reseal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_SNAPSHOT_INCOMPLETE"):
        materializer().materialize_allowlist_release(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_extra_lambda_authority() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-foreign-authority",
            "UserPolicyList": [
                {
                    "PolicyName": "ForeignInvoke",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "lambda:InvokeFunction",
                            "Resource": binding().alias_arn("retire"),
                        },
                    },
                }
            ],
            "AttachedManagedPolicies": [],
        }
    )
    seal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_AUTHORITY_NOT_EXACT"):
        materializer().materialize_allowlist_release(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_explicit_deny_on_expected_invocation() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["roles"][0]["RolePolicyList"][0]["PolicyDocument"][
        "Statement"
    ].append(
        {
            "Effect": "Deny",
            "Action": "lambda:InvokeFunction",
            "Resource": binding().alias_arn("classify"),
        }
    )
    seal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_POLICY_INVALID"):
        materializer().materialize_allowlist_release(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_materialization_rejects_foreign_identity_center_region_path() -> None:
    snapshot = candidate_snapshot()
    snapshot["iam"]["roles"][0]["AssumeRolePolicyDocument"]["Statement"][0][
        "Condition"
    ]["ArnEquals"]["aws:PrincipalArn"] = CLASSIFIER_PERMISSION_SET.replace(
        "sso.amazonaws.com/", "sso.amazonaws.com/us-west-2/"
    )
    seal_snapshot(snapshot)

    with _assert_materialization_error("CANDIDATE_TRUST_POLICY_INVALID"):
        materializer().materialize_allowlist_release(
            snapshot=snapshot,
            binding=binding(),
            collector_contract=collector_contract(),
            source_commit=SOURCE_COMMIT,
            created_at=RELEASE_CREATED,
            expires_at=RELEASE_EXPIRES,
            repo_root=REPO_ROOT,
        )


def test_release_bundle_validation_returns_the_exact_collector_sts_digest() -> None:
    contract, allowlist, release = materialized_bundle()

    result = materializer().validate_release_bundle(
        allowlist=allowlist,
        release=release,
        collector_contract=contract,
        binding=binding(),
        expected_release_digest=release["release_digest"],
        evaluation_at=EVALUATION_AT,
    )

    assert result == contract["collector_role_sts_arn_digest"]


def test_release_digest_mismatch_is_rejected_before_capture_validation() -> None:
    contract, allowlist, release = materialized_bundle()

    with _assert_materialization_error("REVIEWED_RELEASE_DIGEST_MISMATCH"):
        materializer().validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest="sha256:" + "0" * 64,
            evaluation_at=EVALUATION_AT,
        )


def test_release_rejects_a_nonexistent_source_commit_even_when_resealed() -> None:
    contract, allowlist, release = materialized_bundle()
    release["source_commit"] = "f" * 40
    release["release_digest"] = canonical_digest(
        {key: value for key, value in release.items() if key != "release_digest"}
    )

    with _assert_materialization_error("SOURCE_COMMIT_BINDING_INVALID"):
        materializer().validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_current_source_commit_binds_all_runtime_sources() -> None:
    materializer().validate_source_commit_binding(
        source_commit=SOURCE_COMMIT,
        repo_root=REPO_ROOT,
        include_runtime=True,
    )


def test_expired_release_fails_closed() -> None:
    contract, allowlist, release = materialized_bundle()

    with _assert_materialization_error("RELEASE_EXPIRED"):
        materializer().validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at="2030-01-01T00:05:30Z",
        )


def test_resealed_release_cannot_extend_the_five_minute_window() -> None:
    contract, allowlist, release = materialized_bundle()
    release["expires_at"] = "2030-01-01T00:07:00Z"
    release["release_digest"] = canonical_digest(
        {key: value for key, value in release.items() if key != "release_digest"}
    )

    with _assert_materialization_error("RELEASE_EXPIRED"):
        materializer().validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_release_does_not_survive_permission_set_suffix_rotation() -> None:
    _, allowlist, release = materialized_bundle()
    rotated = collector_contract(
        iam_role_arn=ROTATED_COLLECTOR_IAM_ROLE_ARN,
        session_arn=ROTATED_COLLECTOR_SESSION_ARN,
    )

    with _assert_materialization_error("COLLECTOR_CONTRACT_DIGEST_MISMATCH"):
        materializer().validate_release_bundle(
            allowlist=allowlist,
            release=release,
            collector_contract=rotated,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_accepts_a_distinct_snapshot_with_the_same_closed_graph() -> None:
    contract, allowlist, release = materialized_bundle()

    result = materializer().validate_fresh_capture(
        candidate_snapshot=candidate_snapshot(),
        fresh_snapshot=fresh_snapshot(),
        allowlist=allowlist,
        release=release,
        collector_contract=contract,
        binding=binding(),
        expected_release_digest=release["release_digest"],
        evaluation_at=EVALUATION_AT,
    )

    assert result is True


def test_fresh_capture_requires_an_independently_supplied_release_digest() -> None:
    contract, allowlist, release = materialized_bundle()

    with _assert_materialization_error("REVIEWED_RELEASE_DIGEST_MISMATCH"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh_snapshot(),
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest="sha256:" + "0" * 64,
            evaluation_at=EVALUATION_AT,
        )


def test_same_snapshot_cannot_materialize_and_revalidate_a_release() -> None:
    contract, allowlist, release = materialized_bundle()
    candidate = candidate_snapshot()

    with _assert_materialization_error("FRESH_CAPTURE_REQUIRED"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate,
            fresh_snapshot=copy.deepcopy(candidate),
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_requires_a_new_collector_nonce() -> None:
    contract, allowlist, release = materialized_bundle()
    candidate = candidate_snapshot()
    fresh = fresh_snapshot()
    fresh["collector_nonce"] = candidate["collector_nonce"]
    reseal_snapshot(fresh)

    with _assert_materialization_error("FRESH_CAPTURE_REQUIRED"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate,
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_must_start_after_candidate_completion() -> None:
    contract, allowlist, release = materialized_bundle()
    fresh = fresh_snapshot()
    fresh["capture_started_at"] = "2030-01-01T00:00:30Z"
    fresh["capture_completed_at"] = "2030-01-01T00:00:45Z"
    fresh["capture_expires_at"] = "2030-01-01T00:05:45Z"
    reseal_snapshot(fresh)

    with _assert_materialization_error("FRESH_CAPTURE_ORDER_INVALID"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_a_release_created_during_candidate_a() -> None:
    contract, allowlist, release = materialized_bundle()
    allowlist["created_at"] = "2030-01-01T00:00:30Z"
    allowlist["allowlist_digest"] = canonical_digest(
        {key: value for key, value in allowlist.items() if key != "allowlist_digest"}
    )
    release["created_at"] = "2030-01-01T00:00:30Z"
    release["expires_at"] = "2030-01-01T00:05:00Z"
    release["allowlist_digest"] = allowlist["allowlist_digest"]
    release["release_digest"] = canonical_digest(
        {key: value for key, value in release.items() if key != "release_digest"}
    )

    with _assert_materialization_error("FRESH_CAPTURE_ORDER_INVALID"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh_snapshot(),
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_a_release_outliving_candidate_a() -> None:
    contract, allowlist, release = materialized_bundle()
    release["expires_at"] = "2030-01-01T00:06:30Z"
    release["release_digest"] = canonical_digest(
        {key: value for key, value in release.items() if key != "release_digest"}
    )

    with _assert_materialization_error("FRESH_CAPTURE_ORDER_INVALID"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh_snapshot(),
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_incomplete_coverage() -> None:
    contract, allowlist, release = materialized_bundle()
    fresh = fresh_snapshot()
    fresh["coverage"]["lambda_resource_policies"] = coverage_record(
        "ACCESS_DENIED", [], 0
    )
    reseal_snapshot(fresh)

    with _assert_materialization_error("FRESH_CAPTURE_INCOMPLETE"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_collector_policy_drift() -> None:
    contract, allowlist, release = materialized_bundle()
    fresh = fresh_snapshot()
    fresh["iam"]["roles"][2]["RolePolicyList"][0]["PolicyDocument"][
        "Statement"
    ][0]["Action"] = "s3:*"
    seal_snapshot(fresh)

    with _assert_materialization_error("COLLECTOR_INLINE_POLICY_NOT_EXACT"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_collector_trust_drift() -> None:
    contract, allowlist, release = materialized_bundle()
    fresh = fresh_snapshot()
    fresh["iam"]["roles"][2]["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"
    ]["AWS"] = "*"
    seal_snapshot(fresh)

    with _assert_materialization_error("COLLECTOR_TRUST_POLICY_INVALID"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_fresh_capture_rejects_graph_drift() -> None:
    contract, allowlist, release = materialized_bundle()
    fresh = fresh_snapshot()
    fresh["lambda"]["resource_policies"][0]["policy_document"]["Statement"].append(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
            "Action": "lambda:InvokeFunction",
            "Resource": binding().alias_arn("classify"),
        }
    )
    seal_snapshot(fresh)

    with _assert_materialization_error("FRESH_AUTHORITY_GRAPH_MISMATCH"):
        materializer().validate_fresh_capture(
            candidate_snapshot=candidate_snapshot(),
            fresh_snapshot=fresh,
            allowlist=allowlist,
            release=release,
            collector_contract=contract,
            binding=binding(),
            expected_release_digest=release["release_digest"],
            evaluation_at=EVALUATION_AT,
        )


def test_private_bundle_is_create_only_outside_repo_with_restrictive_modes(
    tmp_path: Path,
) -> None:
    contract, allowlist, release = materialized_bundle()
    output = tmp_path / "gug219-private-evidence"

    materializer().write_private_bundle(
        output_dir=output,
        repo_root=REPO_ROOT,
        artifacts={
            "collector-contract.json": contract,
            "allowlist.json": allowlist,
            "release.json": release,
        },
    )

    assert output.is_dir()
    assert os.stat(output).st_mode & 0o777 == 0o700
    assert sorted(path.name for path in output.iterdir()) == [
        "allowlist.json",
        "collector-contract.json",
        "release.json",
    ]
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in output.iterdir())


def test_private_bundle_rejects_an_existing_destination(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()

    with _assert_materialization_error("OUTPUT_PATH_EXISTS"):
        materializer().write_private_bundle(
            output_dir=output,
            repo_root=REPO_ROOT,
            artifacts={"release.json": {"synthetic": True}},
        )


def test_private_bundle_rejects_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "symlink"
    output.symlink_to(target, target_is_directory=True)

    with _assert_materialization_error("OUTPUT_PATH_SYMLINK"):
        materializer().write_private_bundle(
            output_dir=output,
            repo_root=REPO_ROOT,
            artifacts={"release.json": {"synthetic": True}},
        )


def test_private_bundle_rejects_repository_destination() -> None:
    output = REPO_ROOT / "gug219-private-evidence-must-not-exist"

    with _assert_materialization_error("OUTPUT_MUST_BE_OUTSIDE_REPOSITORY"):
        materializer().write_private_bundle(
            output_dir=output,
            repo_root=REPO_ROOT,
            artifacts={"release.json": {"synthetic": True}},
        )
