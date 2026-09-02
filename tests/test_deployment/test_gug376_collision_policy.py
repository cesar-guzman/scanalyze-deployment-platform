from __future__ import annotations

import copy
from datetime import UTC, datetime
import json
import math
from pathlib import Path

import pytest

from tooling import platform_authority_gug376_collision_aws_provider as route_provider
from tooling import platform_authority_gug376_collision_catalog as catalog_contract
from tooling import platform_authority_gug376_collision_policy as subject
from tooling import (
    platform_authority_gug376_collision_transcript_contract as transcript_contract,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
BOOTSTRAP_INTENT_DIGEST = "sha256:" + "c" * 64
DISCOVERY_PROVENANCE_DIGEST = "sha256:" + "d" * 64
PRIVATE_KMS_BINDING_DIGEST = "sha256:" + "e" * 64
ARTIFACT_BUCKET = (
    "scanalyze-g376-art-aaaaaaaaaaaa-042360977644-us-east-1-an"
)

MUTATION_ACTIONS = {
    "cloudformation:CreateStack",
    "dynamodb:CreateTable",
    "iam:CreateRole",
    "iam:PassRole",
    "kms:CreateKey",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "logs:CreateLogGroup",
    "s3:CreateBucket",
    "signer:StartSigningJob",
    "sso:CreatePermissionSet",
    "sts:AssumeRole",
}


def _catalog() -> dict[str, object]:
    return catalog_contract.materialize_route_collision_catalog(
        source_commit_sha=SOURCE_COMMIT,
        source_tree_sha=SOURCE_TREE,
        bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
        not_before="2026-09-01T00:00:00Z",
        expires_at="2026-09-01T02:00:00Z",
        artifact_bucket_name=ARTIFACT_BUCKET,
    )


def _candidates() -> dict[str, dict[str, list[str]]]:
    return {
        "authority": {
            "cloudformation_stack": [
                "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                "scanalyze-platform-authority-gug376-artifact-foundation/"
                "12345678-abcd-1234-abcd-1234567890ab",
                "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                "scanalyze-platform-authority-gug376-route-broker/"
                "abcdef12-abcd-1234-abcd-1234567890ab",
            ],
            "kms_key": [
                "arn:aws:kms:us-east-1:042360977644:key/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "lambda_code_signing_config": [
                "arn:aws:lambda:us-east-1:042360977644:"
                "code-signing-config:csc-0123456789abcdef0"
            ],
        },
        "management": {
            "cloudformation_stack": [
                "arn:aws:cloudformation:us-east-1:839393571433:stack/"
                "scanalyze-platform-authority-gug376-artifact-bootstrap-bridge/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "identity_center_kms_key": [
                "arn:aws:kms:us-east-1:839393571433:key/"
                "12345678-abcd-1234-abcd-1234567890ab"
            ],
            "sso_application": [
                "arn:aws:sso::839393571433:application/"
                "ssoins-1234567890abcdef/apl-1234567890abcdef"
            ],
            "sso_instance": [
                "arn:aws:sso:::instance/ssoins-1234567890abcdef"
            ],
            "sso_permission_set": [
                "arn:aws:sso:::permissionSet/"
                "ssoins-1234567890abcdef/ps-1234567890abcdef"
            ],
        },
    }


def _discovery_evidence(
    catalog: dict[str, object] | None = None,
    candidates: dict[str, dict[str, list[str]]] | None = None,
) -> dict[str, object]:
    catalog = catalog or _catalog()
    candidates = candidates or _candidates()
    domains: dict[str, dict[str, object]] = {}
    for domain in subject.DOMAINS:
        domains[domain] = {}
        for kind in sorted(subject._DYNAMIC_RESOURCE_KINDS[domain]):
            selector = subject._expected_discovery_selector(
                catalog, domain=domain, kind=kind
            )
            arns = candidates.get(domain, {}).get(kind, [])
            items: list[dict[str, str]] = []
            if kind == "cloudformation_stack":
                items = [
                    {
                        "StackName": arn.split(":stack/", 1)[1].split("/", 1)[0],
                        "StackId": arn,
                    }
                    for arn in arns
                ]
            elif kind == "kms_key":
                items = [
                    {"AliasName": name, "TargetKeyId": arn}
                    for name, arn in zip(selector["alias_names"], arns)
                ]
            elif kind == "lambda_code_signing_config":
                items = [
                    {
                        "StackName": stack["stack_name"],
                        "LogicalResourceId": stack["logical_resource_id"],
                        "PhysicalResourceId": arn,
                    }
                    for stack, arn in zip(selector["stack_resources"], arns)
                ]
            elif kind == "identity_center_kms_key":
                items = [
                    {
                        "BindingName": "identity_center_kms_key_arn",
                        "Mode": "CUSTOMER_MANAGED_KEY",
                        "KeyArn": arn,
                        "PrivateBindingDigest": PRIVATE_KMS_BINDING_DIGEST,
                    }
                    for arn in arns
                ]
            elif kind == "sso_instance":
                items = [
                    {
                        "InstanceArn": arn,
                        "OwnerAccountId": selector["owner_account_ids"][0],
                    }
                    for arn in arns
                ]
            elif kind == "sso_application":
                instance = candidates["management"]["sso_instance"][0]
                items = [
                    {
                        "Name": name,
                        "ApplicationArn": arn,
                        "InstanceArn": instance,
                    }
                    for name, arn in zip(selector["application_names"], arns)
                ]
            elif kind == "sso_permission_set":
                instance = candidates["management"]["sso_instance"][0]
                items = [
                    {
                        "Name": name,
                        "PermissionSetArn": arn,
                        "InstanceArn": instance,
                    }
                    for name, arn in zip(selector["permission_set_names"], arns)
                ]
            domains[domain][kind] = {
                "operation": subject._DISCOVERY_OPERATIONS[kind],
                "selector": selector,
                "pages": [
                    {
                        "page_index": 1,
                        "input_cursor_digest": None,
                        "output_cursor_digest": None,
                        "items": items,
                    }
                ],
            }
    return {
        "schema_version": 1,
        "record_type": subject.DISCOVERY_EVIDENCE_RECORD_TYPE,
        "catalog_digest": catalog["catalog_digest"],
        "domains": domains,
    }


def _structural_candidate_policy(
    catalog: dict[str, object],
    evidence: dict[str, object],
) -> dict[str, object]:
    """Build only a structural validator fixture, never an authority capability."""

    value = subject._build_policy_set(  # noqa: SLF001
        catalog,
        discovery_evidence=evidence,
        discovery_provenance_digest=DISCOVERY_PROVENANCE_DIGEST,
    )
    subject.validate_route_collision_policy_set(value, catalog=catalog)
    return value


def _allow_statements(policy: dict[str, object]) -> list[dict[str, object]]:
    statements = policy["Statement"]
    assert isinstance(statements, list)
    return [item for item in statements if item["Effect"] == "Allow"]


def _deny(policy: dict[str, object], sid: str) -> dict[str, object]:
    statements = policy["Statement"]
    assert isinstance(statements, list)
    return next(item for item in statements if item["Sid"] == sid)


def _reseal(value: dict[str, object]) -> None:
    unsigned = dict(value)
    unsigned.pop("policy_set_digest", None)
    value["policy_set_digest"] = subject.canonical_digest(unsigned)


def test_inventory_policy_set_is_stable_sealed_and_covers_every_target() -> None:
    catalog = _catalog()
    first = subject.materialize_route_collision_policy_set(catalog)
    second = subject.materialize_route_collision_policy_set(catalog)

    assert first == second
    assert first["stage"] == "inventory"
    assert first["discovery_evidence"] is None
    assert first["target_count"] == len(catalog["targets"])
    assert len(first["target_coverage"]) == len(catalog["targets"])
    assert {item["target_id"] for item in first["target_coverage"]} == {
        item["target_id"] for item in catalog["targets"]
    }
    assert first["catalog_digest"] == catalog["catalog_digest"]
    assert first["policy_set_digest"] == subject.canonical_digest(
        {
            key: value
            for key, value in first.items()
            if key != "policy_set_digest"
        }
    )
    for domain, policies in first["policies"].items():
        assert set(policies) == {"inventory"}
        assert (
            len(subject.canonical_json(policies["inventory"]).encode("utf-8"))
            <= subject.MAX_IAM_POLICY_CHARS
        )
        assert first["policy_digests"][domain]["inventory"] == (
            subject.canonical_digest(policies["inventory"])
        )
    assert subject.validate_route_collision_policy_set(
        first, catalog=catalog
    ) is None


def test_target_coverage_derives_exact_and_deferred_resources_from_catalog() -> None:
    value = subject.materialize_route_collision_policy_set(_catalog())
    coverage = {item["target_id"]: item for item in value["target_coverage"]}

    bucket = coverage["authority.s3.artifact-bucket"]
    assert bucket["account_id"] == catalog_contract.AUTHORITY_ACCOUNT_ID
    assert bucket["region"] == catalog_contract.REGION
    assert bucket["exact_resources"] == [f"arn:aws:s3:::{ARTIFACT_BUCKET}"]
    assert bucket["inventory_actions"] == ["s3:ListAllMyBuckets"]
    assert bucket["detail_actions"] == ["s3:GetBucketTagging"]
    assert bucket["deferred_resource_kinds"] == []

    stack = coverage["management.cfn.artifact-bridge-stack"]
    assert stack["exact_resources"] == []
    assert stack["inventory_actions"] == ["cloudformation:ListStacks"]
    assert stack["detail_actions"] == ["cloudformation:DescribeStacks"]
    assert stack["deferred_resource_kinds"] == ["cloudformation_stack"]

    code_signing = coverage[
        "authority.lambda.artifact-code-signing-config"
    ]
    assert code_signing["exact_resources"] == []
    assert code_signing["inventory_actions"] == [
        "cloudformation:DescribeStackResource"
    ]
    assert code_signing["deferred_resource_kinds"] == [
        "lambda_code_signing_config"
    ]

    alias = coverage[
        "authority.lambda.alias.plan-policy-repair.repair-v1"
    ]
    assert alias["exact_resources"] == [
        "arn:aws:lambda:us-east-1:042360977644:function:"
        "scanalyze-platform-authority-plan-policy-repair:repair-v1"
    ]

    permission_set = coverage["management.sso.plan-repair"]
    assert permission_set["deferred_resource_kinds"] == [
        "identity_center_kms_key",
        "sso_instance",
        "sso_permission_set",
    ]


def test_allow_wildcards_are_closed_and_all_are_documented() -> None:
    value = subject.materialize_route_collision_policy_set(_catalog())
    documented = {
        (item["domain"], item["stage"], item["statement_sid"]): item
        for item in value["wildcard_resource_exceptions"]
    }
    list_class_actions = {
        "cloudformation:ListStacks",
        "kms:ListAliases",
        "lambda:ListCodeSigningConfigs",
        "logs:DescribeLogGroups",
        "s3:ListAllMyBuckets",
        "signer:ListSigningProfiles",
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListPermissionSets",
    }

    for domain, stages in value["policies"].items():
        for stage, policy in stages.items():
            for statement in _allow_statements(policy):
                resources = statement["Resource"]
                key = (domain, stage, statement["Sid"])
                if resources == "*":
                    assert key in documented
                    actions = statement["Action"]
                    actions = actions if isinstance(actions, list) else [actions]
                    if statement["Sid"] == "ConfirmOnlyTheCurrentCaller":
                        assert actions == ["sts:GetCallerIdentity"]
                        reason = "ACTION_HAS_NO_RESOURCE_LEVEL_AUTHORIZATION"
                    else:
                        assert set(actions) <= list_class_actions
                        reason = "AWS_LIST_CLASS_API_REQUIRES_WILDCARD_RESOURCE"
                    assert documented[key]["reason_code"] == reason
                elif statement["Sid"] == "ReadCatalogNamedStackResourceSelectors":
                    assert key in documented
                    assert resources == [
                        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                        "scanalyze-platform-authority-bootstrap-plan-repair-pep/*",
                        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                        "scanalyze-platform-authority-gug376-artifact-foundation/*",
                        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
                        "scanalyze-platform-authority-gug376-route-broker/*"
                    ]
                    assert statement["Action"] == (
                        "cloudformation:DescribeStackResource"
                    )
                    assert documented[key]["resource"] == resources
                    assert documented[key]["reason_code"] == (
                        "AWS_ASSIGNED_STACK_ID_REQUIRES_EXACT_NAME_WILDCARD"
                    )
                else:
                    assert isinstance(resources, list)
                    assert all(
                        "*" not in resource
                        and "?" not in resource
                        and "${" not in resource
                        for resource in resources
                    )


def test_inventory_can_prove_absence_for_exact_stack_resource_selector() -> None:
    value = subject.materialize_route_collision_policy_set(_catalog())
    authority = value["policies"]["authority"]["inventory"]
    statement = next(
        item
        for item in _allow_statements(authority)
        if item["Sid"] == "ReadCatalogNamedStackResourceSelectors"
    )
    assert statement["Resource"] == [
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        "scanalyze-platform-authority-bootstrap-plan-repair-pep/*",
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        "scanalyze-platform-authority-gug376-artifact-foundation/*",
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        "scanalyze-platform-authority-gug376-route-broker/*"
    ]
    assert statement["Condition"]["StringEquals"] == {
        "aws:PrincipalAccount": catalog_contract.AUTHORITY_ACCOUNT_ID,
        "aws:RequestedRegion": catalog_contract.REGION,
    }
    assert "cloudformation:DescribeStackResource" in value["allowed_actions"][
        "authority"
    ]["inventory"]


def test_every_policy_has_explicit_mutation_boundary_window_and_account_guard() -> None:
    value = subject.materialize_route_collision_policy_set(_catalog())
    for domain, stages in value["policies"].items():
        account = (
            catalog_contract.AUTHORITY_ACCOUNT_ID
            if domain == "authority"
            else catalog_contract.MANAGEMENT_ACCOUNT_ID
        )
        for policy in stages.values():
            boundary = _deny(policy, "DenyEveryMutationAndUnreviewedAction")
            assert boundary["Effect"] == "Deny"
            assert boundary["Resource"] == "*"
            assert not MUTATION_ACTIONS & set(boundary["NotAction"])
            assert set(boundary["NotAction"]) == {
                action
                for statement in _allow_statements(policy)
                for action in (
                    statement["Action"]
                    if isinstance(statement["Action"], list)
                    else [statement["Action"]]
                )
            }
            account_guard = _deny(policy, "DenyMismatchedPrincipalAccount")
            assert account_guard["Condition"] == {
                "StringNotEquals": {"aws:PrincipalAccount": account}
            }
            assert _deny(policy, "DenyAllActionsBeforeAbsoluteStart")
            assert _deny(policy, "DenyAllActionsAtAbsoluteExpiry")

    all_allowed = {
        action
        for domains in value["allowed_actions"].values()
        for actions in domains.values()
        for action in actions
    }
    assert not MUTATION_ACTIONS & all_allowed


def test_account_region_and_bucket_bindings_are_exact_in_allow_conditions() -> None:
    value = subject.materialize_route_collision_policy_set(_catalog())
    for domain, policy in (
        (name, stages["inventory"])
        for name, stages in value["policies"].items()
    ):
        account = (
            catalog_contract.AUTHORITY_ACCOUNT_ID
            if domain == "authority"
            else catalog_contract.MANAGEMENT_ACCOUNT_ID
        )
        for statement in _allow_statements(policy):
            equals = statement["Condition"]["StringEquals"]
            assert equals["aws:PrincipalAccount"] == account
            assert statement["Condition"]["DateGreaterThanEquals"] == {
                "aws:CurrentTime": "2026-09-01T00:00:00Z"
            }
            assert statement["Condition"]["DateLessThan"] == {
                "aws:CurrentTime": "2026-09-01T02:00:00Z"
            }
            actions = statement["Action"]
            actions = actions if isinstance(actions, list) else [actions]
            if not all(action.startswith(("iam:", "sts:")) for action in actions):
                assert equals["aws:RequestedRegion"] == "us-east-1"

    authority = value["policies"]["authority"]["inventory"]
    bucket_statement = next(
        item
        for item in _allow_statements(authority)
        if "s3:GetBucketTagging"
        in (item["Action"] if isinstance(item["Action"], list) else [item["Action"]])
    )
    assert bucket_statement["Resource"] == [f"arn:aws:s3:::{ARTIFACT_BUCKET}"]
    assert bucket_statement["Condition"]["StringEquals"] == {
        "aws:PrincipalAccount": catalog_contract.AUTHORITY_ACCOUNT_ID,
        "aws:RequestedRegion": "us-east-1",
        "aws:ResourceAccount": catalog_contract.AUTHORITY_ACCOUNT_ID,
    }


def test_identity_center_inventory_is_read_only_and_later_binds_instance() -> None:
    catalog = _catalog()
    initial = subject.materialize_route_collision_policy_set(catalog)
    initial_actions = set(
        initial["allowed_actions"]["management"]["inventory"]
    )
    assert {action for action in initial_actions if action.startswith("sso:")} == {
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListPermissionSets",
    }
    assert "kms:Decrypt" not in initial_actions
    initial_permission_sets = next(
        item
        for item in _allow_statements(
            initial["policies"]["management"]["inventory"]
        )
        if item["Sid"] == "DiscoverIdentityCenterPermissionSets"
    )
    assert initial_permission_sets["Resource"] == "*"

    bound = _structural_candidate_policy(
        catalog,
        _discovery_evidence(catalog),
    )
    inventory = bound["policies"]["management"]["inventory"]
    actions = set(bound["allowed_actions"]["management"]["inventory"])
    assert {
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListPermissionSets",
    } <= actions
    assert "kms:Decrypt" not in actions
    permission_sets = next(
        item
        for item in _allow_statements(inventory)
        if item["Sid"] == "DiscoverIdentityCenterPermissionSets"
    )
    assert permission_sets["Resource"] == (
        "arn:aws:sso:::instance/ssoins-1234567890abcdef"
    )


def test_candidate_detail_stage_accepts_only_finite_exact_arns_and_is_stable() -> None:
    catalog = _catalog()
    candidates = _candidates()
    evidence = _discovery_evidence(catalog, candidates)
    reverse_order = copy.deepcopy(evidence)
    reverse_order["domains"] = {
        domain: {
            kind: {
                **group,
                "pages": [
                    {
                        **page,
                        "items": list(reversed(page["items"])),
                    }
                    for page in group["pages"]
                ],
            }
            for kind, group in reversed(list(groups.items()))
        }
        for domain, groups in reversed(
            list(reverse_order["domains"].items())
        )
    }
    first = _structural_candidate_policy(catalog, evidence)
    second = _structural_candidate_policy(catalog, reverse_order)

    assert first == second
    assert first["stage"] == "inventory-and-candidate-detail"
    assert first["candidate_resources_digest"] == subject.canonical_digest(
        first["candidate_resources"]
    )
    assert first["discovery_evidence_digest"] == subject.canonical_digest(
        first["discovery_evidence"]
    )
    for domain, stages in first["policies"].items():
        assert set(stages) == {"inventory", "candidate_detail"}
        for statement in _allow_statements(stages["candidate_detail"]):
            if statement["Sid"] == "ConfirmOnlyTheCurrentCaller":
                assert statement["Resource"] == "*"
                continue
            assert isinstance(statement["Resource"], list)
            assert statement["Resource"]
            assert all(
                "*" not in resource
                and "?" not in resource
                and "${" not in resource
                for resource in statement["Resource"]
            )
        assert first["policy_digests"][domain]["candidate_detail"] == (
            subject.canonical_digest(stages["candidate_detail"])
        )
        assert all(
            len(subject.canonical_json(policy).encode("utf-8"))
            <= subject.MAX_IAM_POLICY_CHARS
            for policy in stages.values()
        )
    authority_detail = first["policies"]["authority"]["candidate_detail"]
    stack_resource = next(
        item
        for item in _allow_statements(authority_detail)
        if item["Sid"] == "ReadExactDiscoveredStackResourceSelectors"
    )
    assert stack_resource["Action"] == (
        "cloudformation:DescribeStackResource"
    )
    assert stack_resource["Resource"] == [
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        "scanalyze-platform-authority-gug376-artifact-foundation/"
        "12345678-abcd-1234-abcd-1234567890ab",
        "arn:aws:cloudformation:us-east-1:042360977644:stack/"
        "scanalyze-platform-authority-gug376-route-broker/"
        "abcdef12-abcd-1234-abcd-1234567890ab"
    ]
    management_actions = set(
        first["allowed_actions"]["management"]["candidate_detail"]
    )
    assert "cloudformation:DescribeStackResource" not in management_actions
    subject.validate_route_collision_policy_set(first, catalog=catalog)


def test_candidate_resources_cannot_be_self_certified_with_an_opaque_digest() -> None:
    catalog = _catalog()
    value = _structural_candidate_policy(
        catalog,
        _discovery_evidence(catalog),
    )
    evidence_item = value["discovery_evidence"]["domains"]["authority"][
        "kms_key"
    ]["pages"][0]["items"][0]
    assert value["candidate_resources"]["authority"]["kms_key"] == [
        evidence_item["TargetKeyId"]
    ]

    changed = copy.deepcopy(value)
    changed["candidate_resources"]["authority"]["kms_key"] = [
        "arn:aws:kms:us-east-1:042360977644:key/"
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    ]
    changed["candidate_resources_digest"] = subject.canonical_digest(
        changed["candidate_resources"]
    )
    changed["discovery_evidence_digest"] = subject.canonical_digest(
        changed["discovery_evidence"]
    )
    _reseal(changed)
    with pytest.raises(subject.CollisionPolicyError) as captured:
        subject.validate_route_collision_policy_set(changed, catalog=catalog)
    assert captured.value.code == "COLLISION_POLICY_SET_BINDING_INVALID"


def test_synthetic_candidate_evidence_cannot_become_operational_authority() -> None:
    """Recomputed JSON seals never replace the provider-owned capability."""

    catalog = _catalog()
    candidates = _candidates()
    candidates["authority"]["kms_key"] = [
        "arn:aws:kms:us-east-1:042360977644:key/"
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    ]
    candidates["authority"]["lambda_code_signing_config"] = [
        "arn:aws:lambda:us-east-1:042360977644:"
        "code-signing-config:csc-fffffffffffffffff"
    ]
    candidates["management"]["identity_center_kms_key"] = [
        "arn:aws:kms:us-east-1:839393571433:key/"
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    ]
    candidates["management"]["sso_instance"] = [
        "arn:aws:sso:::instance/ssoins-fedcba0987654321"
    ]
    candidates["management"]["sso_application"] = [
        "arn:aws:sso::839393571433:application/"
        "ssoins-fedcba0987654321/apl-fedcba0987654321"
    ]
    candidates["management"]["sso_permission_set"] = [
        "arn:aws:sso:::permissionSet/"
        "ssoins-fedcba0987654321/ps-fedcba0987654321"
    ]

    structurally_valid = _structural_candidate_policy(
        catalog,
        _discovery_evidence(catalog, candidates),
    )
    assert structurally_valid["candidate_resources"] == candidates

    for forged_capability in (None, {"self_sealed": True}):
        with pytest.raises(route_provider.CollisionAwsProviderError) as captured:
            route_provider.build_attested_provider_factory(
                session_opener=lambda **_kwargs: pytest.fail(
                    "a rejected policy must not open an AWS session"
                ),
                clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
                policy_set=structurally_valid,
                discovery_capability=forged_capability,
            )
        assert captured.value.code == (
            "COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID"
        )


def test_cloudformation_owned_csc_permissions_match_transcript_contract() -> None:
    catalog = _catalog()
    candidates = _candidates()
    value = _structural_candidate_policy(
        catalog,
        _discovery_evidence(catalog, candidates),
    )
    ownership_target = next(
        target
        for target in catalog["targets"]
        if target["scope"] == "code_signing_config"
        and target["selector"]["kind"] == "cloudformation_ownership_tags"
    )
    target_id = ownership_target["target_id"]
    coverage = next(
        item for item in value["target_coverage"] if item["target_id"] == target_id
    )
    assert coverage["inventory_actions"] == [
        "cloudformation:DescribeStackResource"
    ]
    assert transcript_contract._required_groups(ownership_target) == (
        frozenset({"cloudformation:DescribeStackResource"}),
    )
    assert transcript_contract._ownership_operations(ownership_target) == (
        frozenset({"lambda:ListTags"})
    )

    inventory_actions = set(value["allowed_actions"]["authority"]["inventory"])
    assert "cloudformation:DescribeStackResource" in inventory_actions
    assert "lambda:ListCodeSigningConfigs" not in inventory_actions

    candidate_arn = candidates["authority"]["lambda_code_signing_config"][0]
    detail_statement = next(
        statement
        for statement in _allow_statements(
            value["policies"]["authority"]["candidate_detail"]
        )
        if candidate_arn in statement["Resource"]
    )
    assert detail_statement["Action"] == ["lambda:ListTags"]


def test_aws_owned_identity_center_kms_is_explicit_and_has_no_candidate_arn(
) -> None:
    catalog = _catalog()
    evidence = _discovery_evidence(catalog)
    items = evidence["domains"]["management"]["identity_center_kms_key"][
        "pages"
    ][0]["items"]
    items[:] = [
        {
            "BindingName": "identity_center_kms_key_arn",
            "Mode": "AWS_OWNED_KMS_KEY",
            "PrivateBindingDigest": PRIVATE_KMS_BINDING_DIGEST,
        }
    ]

    value = _structural_candidate_policy(catalog, evidence)

    assert value["candidate_resources"]["management"][
        "identity_center_kms_key"
    ] == []
    assert value["discovery_evidence"]["domains"]["management"][
        "identity_center_kms_key"
    ]["pages"][0]["items"] == items


def test_discovery_contract_binds_catalog_operation_selector_and_pagination() -> None:
    catalog = _catalog()
    evidence = _discovery_evidence(catalog)

    changed = copy.deepcopy(evidence)
    changed["catalog_digest"] = "sha256:" + "f" * 64
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, changed)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_EVIDENCE_INVALID"

    changed = copy.deepcopy(evidence)
    changed["domains"]["authority"]["kms_key"]["operation"] = (
        "kms:DescribeKey"
    )
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, changed)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_OPERATION_INVALID"

    changed = copy.deepcopy(evidence)
    changed["domains"]["authority"]["kms_key"]["selector"][
        "alias_names"
    ] = ["alias/untrusted"]
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, changed)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID"

    changed = copy.deepcopy(evidence)
    group = changed["domains"]["authority"]["kms_key"]
    group["pages"] = [
        {
            **group["pages"][0],
            "output_cursor_digest": "sha256:" + "1" * 64,
        },
        {
            "page_index": 2,
            "input_cursor_digest": "sha256:" + "2" * 64,
            "output_cursor_digest": None,
            "items": [],
        },
    ]
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, changed)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_PAGINATION_INVALID"


@pytest.mark.parametrize(
    ("domain", "kind", "bad_arn"),
    [
        (
            "authority",
            "cloudformation_stack",
            "arn:aws:cloudformation:us-east-1:042360977644:stack/"
            "scanalyze-platform-authority-gug376-artifact-foundation/*",
        ),
        (
            "authority",
            "cloudformation_stack",
            "arn:aws:cloudformation:us-east-1:042360977644:stack/"
            "scanalyze-platform-authority-gug376-artifact-foundation/"
            + "a" * 128,
        ),
        (
            "authority",
            "kms_key",
            "arn:aws:kms:us-west-2:042360977644:key/"
            "12345678-abcd-1234-abcd-1234567890ab",
        ),
        (
            "authority",
            "lambda_code_signing_config",
            "arn:aws:lambda:us-east-1:839393571433:"
            "code-signing-config:csc-0123456789abcdef0",
        ),
        (
            "authority",
            "lambda_code_signing_config",
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-"
            + "a" * 64,
        ),
        (
            "management",
            "sso_application",
            "arn:aws:sso::042360977644:application/"
            "ssoins-1234567890abcdef/apl-1234567890abcdef",
        ),
    ],
)
def test_candidate_detail_stage_rejects_wildcard_wrong_region_or_wrong_account(
    domain: str, kind: str, bad_arn: str
) -> None:
    catalog = _catalog()
    candidates = _candidates()
    candidates[domain][kind] = [bad_arn]
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(
            catalog,
            _discovery_evidence(catalog, candidates),
        )
    assert captured.value.code == "COLLISION_POLICY_CANDIDATE_ARN_INVALID"


def test_candidate_detail_rejects_unknown_duplicates_and_unbound_evidence(
) -> None:
    catalog = _catalog()
    evidence = _discovery_evidence(catalog)
    evidence["domains"]["authority"]["future_resource"] = {}
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, evidence)
    assert captured.value.code == "COLLISION_POLICY_CANDIDATE_KIND_INVALID"

    evidence = _discovery_evidence(catalog)
    items = evidence["domains"]["authority"]["kms_key"]["pages"][0][
        "items"
    ]
    items.append(copy.deepcopy(items[0]))
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, evidence)
    assert captured.value.code == "COLLISION_POLICY_CANDIDATE_DUPLICATE"

    evidence = _discovery_evidence(catalog)
    evidence["domains"]["authority"]["kms_key"]["pages"][0]["items"][
        0
    ]["TargetKeyId"] = {"not": "an ARN"}
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, evidence)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_ITEM_INVALID"

    with pytest.raises(TypeError):
        subject.materialize_route_collision_policy_set(
            catalog, candidate_resources=_candidates()  # type: ignore[call-arg]
        )

    for missing in ("identity_center_kms_key", "sso_instance"):
        evidence = _discovery_evidence(catalog)
        evidence["domains"]["management"][missing]["pages"][0]["items"] = []
        with pytest.raises(subject.CollisionPolicyError) as captured:
            _structural_candidate_policy(catalog, evidence)
        assert (
            captured.value.code
            == "COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID"
        )


def test_candidate_detail_rejects_mismatched_stack_and_incomplete_evidence() -> None:
    catalog = _catalog()
    evidence = _discovery_evidence(catalog)
    evidence["domains"]["authority"]["cloudformation_stack"]["pages"][0][
        "items"
    ][0]["StackName"] = "scanalyze-platform-authority-gug376-route-broker"
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, evidence)
    assert captured.value.code == "COLLISION_POLICY_CANDIDATE_BINDING_INVALID"

    evidence = _discovery_evidence(catalog)
    evidence["domains"]["authority"]["kms_key"]["pages"][0][
        "output_cursor_digest"
    ] = "sha256:" + "e" * 64
    with pytest.raises(subject.CollisionPolicyError) as captured:
        _structural_candidate_policy(catalog, evidence)
    assert captured.value.code == "COLLISION_POLICY_DISCOVERY_INCOMPLETE"


def test_validator_rejects_resealed_policy_and_catalog_binding_tampering() -> None:
    catalog = _catalog()
    value = subject.materialize_route_collision_policy_set(catalog)

    changed = copy.deepcopy(value)
    changed["policies"]["authority"]["inventory"]["Statement"][0][
        "Action"
    ] = "sts:AssumeRole"
    changed["policy_digests"]["authority"]["inventory"] = (
        subject.canonical_digest(changed["policies"]["authority"]["inventory"])
    )
    _reseal(changed)
    with pytest.raises(subject.CollisionPolicyError) as captured:
        subject.validate_route_collision_policy_set(changed, catalog=catalog)
    assert captured.value.code == "COLLISION_POLICY_SET_BINDING_INVALID"

    changed = copy.deepcopy(value)
    changed["policy_set_digest"] = "sha256:" + "e" * 64
    with pytest.raises(subject.CollisionPolicyError) as captured:
        subject.validate_route_collision_policy_set(changed, catalog=catalog)
    assert captured.value.code == "COLLISION_POLICY_SET_DIGEST_INVALID"

    other_catalog = catalog_contract.materialize_route_collision_catalog(
        source_commit_sha="f" * 40,
        source_tree_sha=SOURCE_TREE,
        bootstrap_intent_digest=BOOTSTRAP_INTENT_DIGEST,
        not_before="2026-09-01T00:00:00Z",
        expires_at="2026-09-01T02:00:00Z",
        artifact_bucket_name=(
            "scanalyze-g376-art-ffffffffffff-042360977644-us-east-1-an"
        ),
    )
    with pytest.raises(subject.CollisionPolicyError) as captured:
        subject.validate_route_collision_policy_set(
            value, catalog=other_catalog
        )
    assert captured.value.code == "COLLISION_POLICY_SET_BINDING_INVALID"


def test_canonical_json_rejects_non_json_numbers() -> None:
    with pytest.raises(subject.CollisionPolicyError) as captured:
        subject.canonical_json({"invalid": math.nan})
    assert captured.value.code == "COLLISION_POLICY_JSON_INVALID"


def test_gug376_runtime_wires_materialized_policy_not_legacy_broad_json() -> None:
    catalog = _catalog()
    policy_set = subject.materialize_route_collision_policy_set(catalog)
    factory = route_provider.build_attested_provider_factory(
        session_opener=lambda **_kwargs: pytest.fail(
            "policy wiring must not open an AWS session"
        ),
        clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
        policy_set=policy_set,
    )
    checked_factory = route_provider.assert_attested_provider_factory(factory)
    attestation = checked_factory.provider_attestation()
    assert attestation["policy_set_digest"] == policy_set["policy_set_digest"]
    assert attestation["policy_digests"] == policy_set["policy_digests"]
    assert attestation["target_count"] == catalog["target_count"]

    legacy_policy_paths = (
        REPO_ROOT
        / "policies"
        / "iam"
        / "platform-authority-gug395-preplan-collision-authority-read-only.json",
        REPO_ROOT
        / "policies"
        / "iam"
        / "platform-authority-gug395-preplan-collision-identity-read-only.json",
    )
    for legacy_path in legacy_policy_paths:
        legacy_policy = json.loads(legacy_path.read_text(encoding="utf-8"))
        with pytest.raises(route_provider.CollisionAwsProviderError) as captured:
            route_provider.build_attested_provider_factory(
                session_opener=lambda **_kwargs: None,
                clock=lambda: datetime(2026, 9, 1, tzinfo=UTC),
                policy_set=legacy_policy,
            )
        assert captured.value.code == "COLLISION_PROVIDER_POLICY_SET_INVALID"

    runtime_paths = set(
        REPO_ROOT.glob("tooling/platform_authority_gug376_collision_*.py")
    )
    runtime_paths.update(
        {
            REPO_ROOT
            / "tooling"
            / "platform_authority_plan_permission_repair_artifact_bootstrap_aws.py",
            REPO_ROOT
            / "tooling"
            / "platform_authority_plan_permission_repair_deployment_recovery.py",
            REPO_ROOT
            / "tooling"
            / "platform_authority_plan_permission_repair_deployment_route_aws.py",
            REPO_ROOT
            / "tooling"
            / "platform_authority_plan_permission_repair_route_broker.py",
            REPO_ROOT
            / "scripts"
            / "deployment"
            / "platform-authority-plan-permission-repair-artifact-bootstrap.py",
            REPO_ROOT
            / "scripts"
            / "deployment"
            / "platform-authority-plan-permission-repair-deployment-recovery.py",
            REPO_ROOT
            / "scripts"
            / "deployment"
            / "platform-authority-plan-permission-repair-deployment-route-aws.py",
        }
    )
    assert all(path.is_file() for path in runtime_paths)
    legacy_names = {path.name for path in legacy_policy_paths}
    for runtime_path in sorted(runtime_paths):
        source = runtime_path.read_text(encoding="utf-8")
        assert all(name not in source for name in legacy_names), runtime_path

    exact_wiring = {
        REPO_ROOT
        / "tooling"
        / "platform_authority_gug376_collision_admission.py": (
            "validate_route_collision_policy_set("
        ),
        REPO_ROOT
        / "tooling"
        / "platform_authority_gug376_collision_aws_provider.py": (
            "policy_contract.validate_route_collision_policy_set("
        ),
    }
    for runtime_path, validator_call in exact_wiring.items():
        assert validator_call in runtime_path.read_text(encoding="utf-8")


def test_module_is_offline_and_has_no_sdk_or_cloud_side_effect_imports() -> None:
    source = (
        REPO_ROOT
        / "tooling"
        / "platform_authority_gug376_collision_policy.py"
    ).read_text(encoding="utf-8")
    assert "import boto3" not in source
    assert ".client(" not in source
    assert "subprocess" not in source
    assert "aws_mutations\": 0" in source
