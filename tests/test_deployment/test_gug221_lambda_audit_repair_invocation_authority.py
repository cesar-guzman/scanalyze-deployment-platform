"""Focused security tests for GUG-221 invocation-authority verification."""
from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

import pytest

from tooling.platform_authority_lambda_audit_repair_invocation_authority import (
    EXPECTED_AUTHORITY_EDGE_COUNT,
    PLAN_FUNCTION_NAME,
    RECONCILE_FUNCTION_NAME,
    REPAIR_FUNCTION_NAME,
    VERIFIED_STATUS,
    ProviderInvocationSnapshots,
    RepairInvocationAuthorityBinding,
    collect_provider_invocation_snapshots,
    require_stable_authority,
    verify_provider_invocation_authority,
)
from tooling.platform_authority_lambda_invocation_authority import (
    COVERAGE_SURFACES,
    EVIDENCE_SOURCE_OFFLINE_UNVERIFIED,
    RAW_SNAPSHOT_FORMAT,
    AuthorityInventoryError,
    _coverage,
    _seal_raw_snapshot,
    canonical_digest,
    digest_text,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT = "042360977644"
REGION = "us-east-1"
SCAN_ID = "gug221-invocation-authority-001"
DECISION_AT = "2030-01-01T00:01:01Z"
COLLECTOR_ARN = (
    f"arn:aws:sts::{ACCOUNT}:assumed-role/"
    "ScanalyzeLambdaAuditRepairAuthorityInspector"
)
INVOKER_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_ScanalyzeLambdaAuditRepair_0123456789abcdef"
)
SAML_PROVIDER_ARN = (
    f"arn:aws:iam::{ACCOUNT}:saml-provider/"
    "AWSSSO_0123456789abcdef_DO_NOT_DELETE"
)


def _invoker_policy() -> dict[str, Any]:
    return json.loads(
        (
            REPO_ROOT
            / "policies/iam/platform-authority-lambda-audit-repair-invoker-role.json"
        ).read_text(encoding="utf-8")
    )


def _trust() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": SAML_PROVIDER_ARN},
                "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {
                        "SAML:aud": "https://signin.aws.amazon.com/saml"
                    }
                },
            }
        ],
    }


def _binding(policy: dict[str, Any] | None = None) -> RepairInvocationAuthorityBinding:
    effective_policy = _invoker_policy() if policy is None else policy
    return RepairInvocationAuthorityBinding(
        authority_account_id=ACCOUNT,
        region=REGION,
        invoker_role_arn=INVOKER_ROLE_ARN,
        invoker_policy_digest=canonical_digest(effective_policy),
        collector_principal_digest=digest_text(COLLECTOR_ARN),
        saml_provider_arn=SAML_PROVIDER_ARN,
    )


def _iam(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "users": [],
        "groups": [],
        "roles": [
            {
                "Arn": INVOKER_ROLE_ARN,
                "AssumeRolePolicyDocument": _trust(),
                "RolePolicyList": [
                    {"PolicyDocument": _invoker_policy() if policy is None else policy}
                ],
                "AttachedManagedPolicies": [],
            }
        ],
        "policies": [],
        "managed_policy_documents": {},
    }


def _function_arn(name: str) -> str:
    return f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}"


def _surface_items(snapshot: dict[str, Any]) -> dict[str, list[Any]]:
    lam = snapshot["lambda"]
    iam = snapshot["iam"]
    return {
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


def _reseal(snapshot: dict[str, Any]) -> dict[str, Any]:
    for name, items in _surface_items(snapshot).items():
        status = snapshot["coverage"].get(name, {}).get("status", "COMPLETE")
        pages = snapshot["coverage"].get(name, {}).get("page_count", 1)
        snapshot["coverage"][name] = _coverage(status, items, pages)
    snapshot.pop("snapshot_digest", None)
    return _seal_raw_snapshot(snapshot)


def _snapshot(
    *,
    target: str,
    nonce: str,
    started: str,
    completed: str,
    expires: str,
    iam: dict[str, Any] | None = None,
) -> dict[str, Any]:
    aliases = {
        PLAN_FUNCTION_NAME: ("plan-v1",),
        REPAIR_FUNCTION_NAME: ("repair-v1",),
        RECONCILE_FUNCTION_NAME: ("reconcile-v1",),
    }[target]
    functions = [
        {
            "FunctionName": PLAN_FUNCTION_NAME,
            "FunctionArn": _function_arn(PLAN_FUNCTION_NAME),
        },
        {
            "FunctionName": REPAIR_FUNCTION_NAME,
            "FunctionArn": _function_arn(REPAIR_FUNCTION_NAME),
        },
        {
            "FunctionName": RECONCILE_FUNCTION_NAME,
            "FunctionArn": _function_arn(RECONCILE_FUNCTION_NAME),
        },
    ]
    snapshot: dict[str, Any] = {
        "snapshot_format": RAW_SNAPSHOT_FORMAT,
        "capture_started_at": started,
        "capture_completed_at": completed,
        "capture_expires_at": expires,
        "collector_nonce": nonce,
        "collector_principal_arn": COLLECTOR_ARN,
        "collector_principal_arn_digest": digest_text(COLLECTOR_ARN),
        "enabled_regions": [REGION],
        "scanned_regions": [REGION],
        "coverage": {name: {} for name in COVERAGE_SURFACES},
        "lambda": {
            "functions": functions,
            "aliases": [
                {
                    "Name": alias,
                    "FunctionVersion": "1",
                    "FunctionArn": f"{_function_arn(target)}:{alias}",
                }
                for alias in aliases
            ],
            "versions": [
                {
                    "Version": "$LATEST",
                    "FunctionArn": f"{_function_arn(target)}:$LATEST",
                },
                {
                    "Version": "1",
                    "FunctionArn": f"{_function_arn(target)}:1",
                },
            ],
            "function_urls": [],
            "resource_policies": [],
            "event_source_mappings": [],
            "event_invoke_configs": [],
        },
        "iam": copy.deepcopy(_iam() if iam is None else iam),
    }
    return _reseal(snapshot)


def _snapshots(iam: dict[str, Any] | None = None) -> ProviderInvocationSnapshots:
    return ProviderInvocationSnapshots(
        scan_id=SCAN_ID,
        plan=_snapshot(
            target=PLAN_FUNCTION_NAME,
            nonce=f"{SCAN_ID}:plan",
            started="2030-01-01T00:00:00Z",
            completed="2030-01-01T00:00:20Z",
            expires="2030-01-01T00:05:20Z",
            iam=iam,
        ),
        repair=_snapshot(
            target=REPAIR_FUNCTION_NAME,
            nonce=f"{SCAN_ID}:repair",
            started="2030-01-01T00:00:21Z",
            completed="2030-01-01T00:00:40Z",
            expires="2030-01-01T00:05:40Z",
            iam=iam,
        ),
        reconcile=_snapshot(
            target=RECONCILE_FUNCTION_NAME,
            nonce=f"{SCAN_ID}:reconcile",
            started="2030-01-01T00:00:41Z",
            completed="2030-01-01T00:01:00Z",
            expires="2030-01-01T00:06:00Z",
            iam=iam,
        ),
    )


def _mutate_all_iam(
    snapshots: ProviderInvocationSnapshots,
    mutation: Callable[[dict[str, Any]], None],
) -> ProviderInvocationSnapshots:
    plan = copy.deepcopy(snapshots.plan)
    repair = copy.deepcopy(snapshots.repair)
    reconcile = copy.deepcopy(snapshots.reconcile)
    mutation(plan["iam"])
    mutation(repair["iam"])
    mutation(reconcile["iam"])
    return ProviderInvocationSnapshots(
        scan_id=snapshots.scan_id,
        plan=_reseal(plan),
        repair=_reseal(repair),
        reconcile=_reseal(reconcile),
    )


def _verify(
    snapshots: ProviderInvocationSnapshots | None = None,
    binding: RepairInvocationAuthorityBinding | None = None,
) -> Any:
    return verify_provider_invocation_authority(
        binding=_binding() if binding is None else binding,
        snapshots=_snapshots() if snapshots is None else snapshots,
        decision_at=DECISION_AT,
    )


def _allow_policy(action: Any, resource: Any) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": action,
                "Resource": resource,
            }
        ],
    }


def _foreign_role(arn: str, policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "Arn": arn,
        "AssumeRolePolicyDocument": _trust(),
        "RolePolicyList": [{"PolicyDocument": policy}],
        "AttachedManagedPolicies": [],
    }


def test_exact_provider_graph_returns_only_sanitized_verified_evidence() -> None:
    verified = _verify()
    evidence = verified.as_dict()

    assert verified.status == VERIFIED_STATUS
    assert verified.expected_edge_count == EXPECTED_AUTHORITY_EDGE_COUNT
    assert evidence["expected_edge_count"] == 3
    assert evidence["foreign_edge_count"] == 0
    assert evidence["coverage_complete"] is True
    assert evidence["provider_derived"] is True
    assert evidence["live_effect_authorized"] is False
    serialized = json.dumps(evidence, sort_keys=True)
    assert ACCOUNT not in serialized
    assert INVOKER_ROLE_ARN not in serialized


def test_collection_reuses_gug218_adapter_for_all_exact_functions() -> None:
    expected = _snapshots()

    class FakeAdapter:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, str, int]] = []

        def collect(self, **kwargs: Any) -> dict[str, Any]:
            target = kwargs["binding"].function_name
            self.calls.append(
                (
                    target,
                    kwargs["scan_id"],
                    kwargs["expected_collector_principal_digest"],
                    kwargs["ttl_minutes"],
                )
            )
            return dict(
                expected.plan
                if target == PLAN_FUNCTION_NAME
                else expected.repair
                if target == REPAIR_FUNCTION_NAME
                else expected.reconcile
            )

    adapter = FakeAdapter()
    observed = collect_provider_invocation_snapshots(
        adapter=adapter,  # type: ignore[arg-type]
        binding=_binding(),
        scan_id=SCAN_ID,
    )

    assert observed.plan == expected.plan
    assert observed.repair == expected.repair
    assert observed.reconcile == expected.reconcile
    assert [item[0] for item in adapter.calls] == [
        PLAN_FUNCTION_NAME,
        REPAIR_FUNCTION_NAME,
        RECONCILE_FUNCTION_NAME,
    ]
    assert [item[1] for item in adapter.calls] == [
        f"{SCAN_ID}:plan",
        f"{SCAN_ID}:repair",
        f"{SCAN_ID}:reconcile",
    ]
    assert all(item[2] == _binding().collector_principal_digest for item in adapter.calls)


@pytest.mark.parametrize("entity", ["users", "groups", "roles"])
def test_foreign_identity_inline_policy_cannot_invoke_exact_alias(entity: str) -> None:
    foreign_arn = {
        "users": f"arn:aws:iam::{ACCOUNT}:user/foreign",
        "groups": f"arn:aws:iam::{ACCOUNT}:group/foreign",
        "roles": f"arn:aws:iam::{ACCOUNT}:role/ForeignInvoker",
    }[entity]
    policy = _allow_policy(
        "lambda:InvokeFunction", _binding().repair_binding.function_arn + ":repair-v1"
    )

    def mutate(iam: dict[str, Any]) -> None:
        if entity == "roles":
            iam[entity].append(_foreign_role(foreign_arn, policy))
            return
        inline_key = "UserPolicyList" if entity == "users" else "GroupPolicyList"
        iam[entity].append(
            {
                "Arn": foreign_arn,
                inline_key: [{"PolicyDocument": policy}],
                "AttachedManagedPolicies": [],
            }
        )

    with pytest.raises(
        AuthorityInventoryError, match="FOREIGN_INVOCATION_AUTHORITY"
    ):
        _verify(_mutate_all_iam(_snapshots(), mutate))


def test_foreign_managed_policy_grant_is_not_ignored() -> None:
    policy_arn = f"arn:aws:iam::{ACCOUNT}:policy/ForeignInvoke"
    document = _allow_policy("lambda:InvokeFunction", "*")

    def mutate(iam: dict[str, Any]) -> None:
        iam["users"].append(
            {
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/foreign",
                "UserPolicyList": [],
                "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
            }
        )
        iam["managed_policy_documents"][policy_arn] = document

    with pytest.raises(
        AuthorityInventoryError, match="FOREIGN_INVOCATION_AUTHORITY"
    ):
        _verify(_mutate_all_iam(_snapshots(), mutate))


@pytest.mark.parametrize(
    ("action", "resource", "expected_code"),
    [
        ("lambda:Invoke*", "*", "FOREIGN_INVOCATION_AUTHORITY"),
        (
            "lambda:InvokeFunction",
            "arn:aws:lambda:*:*:function:*",
            "FOREIGN_INVOCATION_AUTHORITY",
        ),
        ("iam:*", "*", "AUTHORITY_MUTATION_PRESENT"),
        ("cloudformation:*", "*", "AUTHORITY_MUTATION_PRESENT"),
        ("lambda:AddPermission", "*", "AUTHORITY_MUTATION_PRESENT"),
    ],
)
def test_wildcard_or_mutating_authority_fails_closed(
    action: str, resource: str, expected_code: str
) -> None:
    foreign = _foreign_role(
        f"arn:aws:iam::{ACCOUNT}:role/ForeignAdmin",
        _allow_policy(action, resource),
    )

    def mutate(iam: dict[str, Any]) -> None:
        iam["roles"].append(copy.deepcopy(foreign))

    with pytest.raises(AuthorityInventoryError, match=expected_code):
        _verify(_mutate_all_iam(_snapshots(), mutate))


def test_not_action_policy_is_unsupported_not_silently_filtered() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }

    def mutate(iam: dict[str, Any]) -> None:
        iam["roles"].append(
            _foreign_role(f"arn:aws:iam::{ACCOUNT}:role/NotAction", policy)
        )

    with pytest.raises(AuthorityInventoryError, match="POLICY_SEMANTICS_UNSUPPORTED"):
        _verify(_mutate_all_iam(_snapshots(), mutate))


@pytest.mark.parametrize(
    "surface",
    [
        "resource_policies",
        "function_urls",
        "event_source_mappings",
        "event_invoke_configs",
    ],
)
def test_non_identity_lambda_invocation_surface_is_rejected(surface: str) -> None:
    snapshots = _snapshots()
    repair = copy.deepcopy(snapshots.repair)
    value = {
        "resource_policies": {
            "resource_arn": _binding().repair_binding.function_arn,
            "policy_document": _allow_policy("lambda:InvokeFunction", "*"),
        },
        "function_urls": {
            "FunctionArn": _binding().repair_binding.function_arn + ":repair-v1",
            "AuthType": "AWS_IAM",
            "InvokeMode": "BUFFERED",
        },
        "event_source_mappings": {
            "FunctionArn": _binding().repair_binding.function_arn + ":repair-v1",
            "AuthorityEndpointDigest": "sha256:" + "a" * 64,
        },
        "event_invoke_configs": {
            "FunctionArn": _binding().repair_binding.function_arn + ":repair-v1",
            "Qualifier": "repair-v1",
            "AuthorityEndpointDigest": "sha256:" + "b" * 64,
        },
    }[surface]
    repair["lambda"][surface].append(value)
    poisoned = replace(snapshots, repair=_reseal(repair))

    with pytest.raises(
        AuthorityInventoryError, match="FOREIGN_INVOCATION_SURFACE_PRESENT"
    ):
        _verify(poisoned)


def test_incomplete_provider_coverage_is_never_treated_as_absence() -> None:
    snapshots = _snapshots()
    repair = copy.deepcopy(snapshots.repair)
    repair["coverage"]["iam_account_authorization"] = _coverage(
        "ACCESS_DENIED", [], 0
    )
    repair.pop("snapshot_digest")
    poisoned = replace(snapshots, repair=_seal_raw_snapshot(repair))

    with pytest.raises(AuthorityInventoryError, match="COVERAGE_NOT_COMPLETE"):
        _verify(poisoned)


def test_offline_or_caller_authored_evidence_is_never_authoritative() -> None:
    with pytest.raises(AuthorityInventoryError, match="UNVERIFIED_EVIDENCE_SOURCE"):
        verify_provider_invocation_authority(
            binding=_binding(),
            snapshots=_snapshots(),
            decision_at=DECISION_AT,
            evidence_source_mode=EVIDENCE_SOURCE_OFFLINE_UNVERIFIED,
        )


def test_stale_provider_capture_fails_closed() -> None:
    with pytest.raises(AuthorityInventoryError, match="INVENTORY_TIME_WINDOW_INVALID"):
        verify_provider_invocation_authority(
            binding=_binding(),
            snapshots=_snapshots(),
            decision_at="2030-01-01T00:06:01Z",
        )


def test_multiple_matching_sso_roles_are_ambiguous() -> None:
    duplicate_arn = INVOKER_ROLE_ARN.replace(
        "0123456789abcdef", "fedcba9876543210"
    )

    def mutate(iam: dict[str, Any]) -> None:
        duplicate = copy.deepcopy(iam["roles"][0])
        duplicate["Arn"] = duplicate_arn
        iam["roles"].append(duplicate)

    with pytest.raises(AuthorityInventoryError, match="INVOKER_ROLE_SET_MISMATCH"):
        _verify(_mutate_all_iam(_snapshots(), mutate))


def test_foreign_saml_trust_path_is_rejected() -> None:
    def mutate(iam: dict[str, Any]) -> None:
        iam["roles"][0]["AssumeRolePolicyDocument"]["Statement"][0][
            "Principal"
        ] = {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Foreign"}

    with pytest.raises(AuthorityInventoryError, match="INVOKER_SAML_TRUST_MISMATCH"):
        _verify(_mutate_all_iam(_snapshots(), mutate))


def test_self_copied_digest_cannot_make_wildcard_invocation_safe() -> None:
    broad = _allow_policy("lambda:InvokeFunction", "*")
    iam = _iam(broad)

    with pytest.raises(
        AuthorityInventoryError, match="FOREIGN_INVOCATION_AUTHORITY"
    ):
        _verify(_snapshots(iam), _binding(broad))


def test_missing_expected_edge_is_rejected_even_with_matching_policy_digest() -> None:
    policy = _invoker_policy()
    allow = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Effect") == "Allow"
    )
    allow["Resource"] = allow["Resource"][:-1]

    with pytest.raises(
        AuthorityInventoryError, match="EXPECTED_INVOCATION_AUTHORITY_MISSING"
    ):
        _verify(_snapshots(_iam(policy)), _binding(policy))


def test_changed_iam_graph_between_function_captures_is_rejected() -> None:
    snapshots = _snapshots()
    reconcile = copy.deepcopy(snapshots.reconcile)
    reconcile["iam"]["users"].append(
        {
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/read-only",
            "UserPolicyList": [],
            "AttachedManagedPolicies": [],
        }
    )
    poisoned = replace(snapshots, reconcile=_reseal(reconcile))

    with pytest.raises(
        AuthorityInventoryError, match="IAM_AUTHORITY_CHANGED_DURING_CAPTURE"
    ):
        _verify(poisoned)


def test_stable_a_b_authority_passes_and_any_graph_drift_blocks() -> None:
    before = _verify()
    after_snapshots = replace(_snapshots(), scan_id="gug221-capture-b")
    plan = copy.deepcopy(after_snapshots.plan)
    repair = copy.deepcopy(after_snapshots.repair)
    reconcile = copy.deepcopy(after_snapshots.reconcile)
    plan["collector_nonce"] = "gug221-capture-b:plan"
    repair["collector_nonce"] = "gug221-capture-b:repair"
    reconcile["collector_nonce"] = "gug221-capture-b:reconcile"
    after_snapshots = ProviderInvocationSnapshots(
        scan_id="gug221-capture-b",
        plan=_reseal(plan),
        repair=_reseal(repair),
        reconcile=_reseal(reconcile),
    )
    after = _verify(after_snapshots)
    require_stable_authority(before, after)

    drifted = replace(after, authority_graph_digest="sha256:" + "f" * 64)
    with pytest.raises(
        AuthorityInventoryError, match="AUTHORITY_CHANGED_DURING_EXECUTION"
    ):
        require_stable_authority(before, drifted)


def test_inspector_policy_is_read_only_and_scoped_to_all_functions() -> None:
    policy = json.loads(
        (
            REPO_ROOT
            / "policies/iam/"
            "platform-authority-lambda-audit-repair-invocation-inspector-role.json"
        ).read_text(encoding="utf-8")
    )
    allows = [
        statement for statement in policy["Statement"] if statement["Effect"] == "Allow"
    ]
    allowed_actions = {
        action
        for statement in allows
        for action in (
            [statement["Action"]]
            if isinstance(statement["Action"], str)
            else statement["Action"]
        )
    }
    assert allowed_actions == {
        "sts:GetCallerIdentity",
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
    }
    assert not any(
        action.startswith(("lambda:Invoke", "iam:Put", "iam:Create"))
        for action in allowed_actions
    )
    get_policy = next(
        statement
        for statement in allows
        if statement["Sid"] == "ReadExactGug221LambdaPolicies"
    )
    assert len(get_policy["Resource"]) == 6
    assert any(PLAN_FUNCTION_NAME in item for item in get_policy["Resource"])
    assert any(REPAIR_FUNCTION_NAME in item for item in get_policy["Resource"])
    assert any(RECONCILE_FUNCTION_NAME in item for item in get_policy["Resource"])
    denies = {
        statement["Sid"]: statement
        for statement in policy["Statement"]
        if statement["Effect"] == "Deny"
    }
    assert "DenyLambdaInvocationAndMutation" in denies
    assert "DenyIamMutation" in denies
    assert "DenyRoleChaining" in denies
