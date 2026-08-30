"""Exact effective-authority tests for the GUG-376 Plan repair PEP."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

import pytest
import yaml

from tooling.platform_authority_plan_permission_repair import (
    PlanPermissionRepairError,
    digest_value,
)
from tooling.platform_authority_plan_permission_repair_iam_effective_authority import (
    AUTHORITY_ACCOUNT_ID,
    MANAGEMENT_ACCOUNT_ID,
    AwsPlanRepairIamEffectiveAuthorityVerifier,
    IamEffectiveAuthorityGuardedIdentityCenterPort,
    PlanRepairIamBindings,
    load_expected_roles,
    normalize_policy_bindings,
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


class _CloudFormationLoader(yaml.SafeLoader):
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
                    f"duplicate key {key!r}",
                    key_node.start_mark,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _construct_intrinsic(
    loader: _CloudFormationLoader, tag_suffix: str, node: yaml.Node
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
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=_CloudFormationLoader)
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def bindings() -> PlanRepairIamBindings:
    return PlanRepairIamBindings(
        repair_id="gug376-plan-permission-repair-" + "1" * 64,
        code_signing_config_arn=(
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-1234567890abcdefg"
        ),
        repair_ledger_kms_key_arn=(
            "arn:aws:kms:us-east-1:042360977644:key/"
            "11111111-2222-3333-4444-555555555555"
        ),
        identity_center_instance_arn=(
            "arn:aws:sso:::instance/ssoins-1234567890ABCDEF"
        ),
        plan_permission_set_arn=(
            "arn:aws:sso:::permissionSet/ssoins-1234567890ABCDEF/"
            "ps-1111111111111111"
        ),
        repair_invoker_permission_set_arn=(
            "arn:aws:sso:::permissionSet/ssoins-1234567890ABCDEF/"
            "ps-2222222222222222"
        ),
        identity_store_id="d-1234567890",
        repair_principal_id="11111111-2222-3333-4444-555555555555",
        identity_center_kms_mode="CUSTOMER_MANAGED_KEY",
        identity_center_kms_key_arn=(
            "arn:aws:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
    )


_DROP = object()


def _project(
    value: Any,
    *,
    account_id: str,
    bindings: PlanRepairIamBindings,
    customer_managed_kms: bool,
) -> Any:
    references = {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
        "AWS::AccountId": account_id,
        "RepairId": bindings.repair_id,
        "RepairCodeSigningConfig": bindings.code_signing_config_arn,
        "IdentityCenterInstanceArn": bindings.identity_center_instance_arn,
        "PlanPermissionSetArn": bindings.plan_permission_set_arn,
        "IdentityStoreArn": bindings.identity_store_arn,
        "RepairPrincipalUserArn": bindings.repair_principal_user_arn,
        "IdentityCenterKmsKeyArn": bindings.identity_center_kms_key_arn,
    }
    attributes = {
        "PlanExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/ScanalyzeBootstrapPlanRepairPlan"
        ),
        "RepairExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/"
            "ScanalyzeBootstrapPlanRepairExecution"
        ),
        "ReconcileExecutionRole.Arn": (
            "arn:aws:iam::042360977644:role/"
            "ScanalyzeBootstrapPlanRepairReconcile"
        ),
        "InvocationAuthorityInspectorRole.Arn": (
            "arn:aws:iam::042360977644:role/scanalyze/platform-authority/"
            "ScanalyzeBootstrapPlanRepairInspector"
        ),
        "RepairLedgerKey.Arn": bindings.repair_ledger_kms_key_arn,
        "RepairInvokerPermissionSet.PermissionSetArn": (
            bindings.repair_invoker_permission_set_arn
        ),
    }
    if isinstance(value, list):
        result = []
        for item in value:
            projected = _project(
                item,
                account_id=account_id,
                bindings=bindings,
                customer_managed_kms=customer_managed_kms,
            )
            if projected is not _DROP:
                result.append(projected)
        return result
    if isinstance(value, Mapping):
        if set(value) == {"Ref"}:
            name = value["Ref"]
            if name == "AWS::NoValue":
                return _DROP
            return references[name]
        if set(value) == {"Fn::GetAtt"}:
            return attributes[value["Fn::GetAtt"]]
        if set(value) == {"Fn::Sub"}:
            rendered = value["Fn::Sub"]
            assert isinstance(rendered, str)
            for name, replacement in {
                "AWS::Partition": "aws",
                "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
                "ManagementAccountId": MANAGEMENT_ACCOUNT_ID,
                "AWS::AccountId": account_id,
            }.items():
                rendered = rendered.replace("${" + name + "}", replacement)
            assert "${" not in rendered
            return rendered
        if set(value) == {"Fn::If"}:
            condition, when_true, when_false = value["Fn::If"]
            assert condition == "IdentityCenterCustomerManagedKmsEnabled"
            return _project(
                when_true if customer_managed_kms else when_false,
                account_id=account_id,
                bindings=bindings,
                customer_managed_kms=customer_managed_kms,
            )
        return {
            str(key): _project(
                item,
                account_id=account_id,
                bindings=bindings,
                customer_managed_kms=customer_managed_kms,
            )
            for key, item in value.items()
        }
    return value


def _role_documents(
    bindings: PlanRepairIamBindings,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {
        AUTHORITY_ACCOUNT_ID: {},
        MANAGEMENT_ACCOUNT_ID: {},
    }
    for template_path, account_id in (
        (AUTHORITY_TEMPLATE, AUTHORITY_ACCOUNT_ID),
        (MANAGEMENT_TEMPLATE, MANAGEMENT_ACCOUNT_ID),
    ):
        template = _load_template(template_path)
        for logical_id, resource in template["Resources"].items():
            if resource["Type"] != "AWS::IAM::Role":
                continue
            properties = resource["Properties"]
            path = properties.get("Path", "/")
            role_name = properties["RoleName"]
            result[account_id][role_name] = {
                "logical_resource_id": logical_id,
                "Role": {
                    "RoleName": role_name,
                    "Path": path,
                    "Arn": f"arn:aws:iam::{account_id}:role{path}{role_name}",
                    "MaxSessionDuration": properties["MaxSessionDuration"],
                    "AssumeRolePolicyDocument": _project(
                        properties["AssumeRolePolicyDocument"],
                        account_id=account_id,
                        bindings=bindings,
                        customer_managed_kms=True,
                    ),
                },
                "PolicyName": properties["Policies"][0]["PolicyName"],
                "PolicyDocument": _project(
                    properties["Policies"][0]["PolicyDocument"],
                    account_id=account_id,
                    bindings=bindings,
                    customer_managed_kms=True,
                ),
            }
    return result[AUTHORITY_ACCOUNT_ID], result[MANAGEMENT_ACCOUNT_ID]


class _FakeIam:
    def __init__(self, roles: Mapping[str, Mapping[str, Any]]) -> None:
        self.roles = deepcopy(dict(roles))
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.cycle_role: str | None = None
        self.terminal_marker_role: str | None = None

    def get_role(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("get_role", dict(kwargs)))
        return {"Role": deepcopy(self.roles[kwargs["RoleName"]]["Role"])}

    def list_attached_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("list_attached_role_policies", dict(kwargs)))
        role_name = kwargs["RoleName"]
        attached = self.roles[role_name].get("AttachedPolicies", [])
        marker = kwargs.get("Marker")
        if self.cycle_role == role_name:
            return {
                "AttachedPolicies": [],
                "IsTruncated": True,
                "Marker": "cycle",
            }
        if marker is None:
            return {
                "AttachedPolicies": [],
                "IsTruncated": True,
                "Marker": "attached-final",
            }
        response: dict[str, Any] = {
            "AttachedPolicies": deepcopy(attached),
            "IsTruncated": False,
        }
        if self.terminal_marker_role == role_name:
            response["Marker"] = "unexpected"
        return response

    def list_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("list_role_policies", dict(kwargs)))
        role_name = kwargs["RoleName"]
        marker = kwargs.get("Marker")
        if marker is None:
            return {
                "PolicyNames": [],
                "IsTruncated": True,
                "Marker": "inline-final",
            }
        names = self.roles[role_name].get(
            "PolicyNames", [self.roles[role_name]["PolicyName"]]
        )
        return {"PolicyNames": deepcopy(names), "IsTruncated": False}

    def get_role_policy(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(("get_role_policy", dict(kwargs)))
        role = self.roles[kwargs["RoleName"]]
        return {
            "RoleName": kwargs["RoleName"],
            "PolicyName": kwargs["PolicyName"],
            "PolicyDocument": quote(
                json.dumps(role["PolicyDocument"], separators=(",", ":")),
                safe="",
            ),
        }


def _verifier(
    bindings: PlanRepairIamBindings,
) -> tuple[
    AwsPlanRepairIamEffectiveAuthorityVerifier, _FakeIam, _FakeIam
]:
    authority_roles, management_roles = _role_documents(bindings)
    authority = _FakeIam(authority_roles)
    management = _FakeIam(management_roles)
    return (
        AwsPlanRepairIamEffectiveAuthorityVerifier(
            authority_iam=authority,
            management_iam=management,
            repo_root=REPO_ROOT,
        ),
        authority,
        management,
    )


def test_reviewed_control_is_exact_projection_of_both_templates(
    bindings: PlanRepairIamBindings,
) -> None:
    specs = load_expected_roles(repo_root=REPO_ROOT)
    by_logical_id = {spec.logical_resource_id: spec for spec in specs}
    assert len(by_logical_id) == 6
    for template_path, account_id in (
        (AUTHORITY_TEMPLATE, AUTHORITY_ACCOUNT_ID),
        (MANAGEMENT_TEMPLATE, MANAGEMENT_ACCOUNT_ID),
    ):
        template = _load_template(template_path)
        for logical_id, resource in template["Resources"].items():
            if resource["Type"] != "AWS::IAM::Role":
                continue
            spec = by_logical_id[logical_id]
            properties = resource["Properties"]
            assert spec.account_id == account_id
            assert spec.role_name == properties["RoleName"]
            assert spec.path == properties.get("Path", "/")
            assert spec.inline_policy_name == properties["Policies"][0]["PolicyName"]
            trust = _project(
                properties["AssumeRolePolicyDocument"],
                account_id=account_id,
                bindings=bindings,
                customer_managed_kms=True,
            )
            assert digest_value(trust) == spec.trust_policy_digest
            for mode, enabled in (
                ("AWS_OWNED_KMS_KEY", False),
                ("CUSTOMER_MANAGED_KEY", True),
            ):
                policy = _project(
                    properties["Policies"][0]["PolicyDocument"],
                    account_id=account_id,
                    bindings=bindings,
                    customer_managed_kms=enabled,
                )
                normalized = normalize_policy_bindings(policy, bindings)
                assert digest_value(normalized) == spec.policy_digest_for(mode)


def test_management_portable_policies_have_template_parity(
    bindings: PlanRepairIamBindings,
) -> None:
    specs = {
        spec.logical_resource_id: spec
        for spec in load_expected_roles(repo_root=REPO_ROOT)
    }
    for logical_id, filename in (
        (
            "MutationServiceRole",
            "platform-authority-bootstrap-plan-repair-mutation-service-role.json",
        ),
        (
            "ReadbackServiceRole",
            "platform-authority-bootstrap-plan-repair-readback-service-role.json",
        ),
    ):
        document = json.loads((POLICY_ROOT / filename).read_text(encoding="utf-8"))
        customer_digest = digest_value(document)
        without_kms = {
            **document,
            "Statement": [
                statement
                for statement in document["Statement"]
                if statement["Sid"]
                not in {
                    "DecryptOnlyThroughExactIdentityCenterInstance",
                    "DecryptOnlyThroughExactIdentityStore",
                }
            ],
        }
        assert customer_digest == specs[logical_id].policy_digest_for(
            "CUSTOMER_MANAGED_KEY"
        )
        assert digest_value(without_kms) == specs[logical_id].policy_digest_for(
            "AWS_OWNED_KMS_KEY"
        )


def test_each_runtime_role_can_read_all_four_local_pep_roles() -> None:
    authority = _load_template(AUTHORITY_TEMPLATE)
    expected_resources = {
        "arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeBootstrapPlanRepairPlan",
        "arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeBootstrapPlanRepairExecution",
        "arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/ScanalyzeBootstrapPlanRepairReconcile",
        "arn:${AWS::Partition}:iam::${AuthorityAccountId}:"
        "role/scanalyze/platform-authority/"
        "ScanalyzeBootstrapPlanRepairInspector",
    }
    for logical_id in (
        "PlanExecutionRole",
        "RepairExecutionRole",
        "ReconcileExecutionRole",
    ):
        policy = authority["Resources"][logical_id]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]
        statement = next(
            item
            for item in policy["Statement"]
            if item.get("Sid") == "ReadExactLocalPepExecutionRoles"
        )
        assert {item["Fn::Sub"] for item in statement["Resource"]} == (
            expected_resources
        )


def test_exact_six_role_snapshot_uses_exhaustive_pagination(
    bindings: PlanRepairIamBindings,
) -> None:
    verifier, authority, management = _verifier(bindings)
    snapshot = verifier.snapshot(bindings)
    assert len(snapshot.authority_roles) == 4
    assert len(snapshot.management_roles) == 2
    assert snapshot.digest().startswith("sha256:")
    for client, expected_count in ((authority, 4), (management, 2)):
        assert sum(call[0] == "get_role" for call in client.calls) == expected_count
        assert sum(
            call[0] == "get_role_policy" for call in client.calls
        ) == expected_count
        assert sum(
            call[0] == "list_role_policies" and call[1].get("Marker") == "inline-final"
            for call in client.calls
        ) == expected_count
        assert sum(
            call[0] == "list_attached_role_policies"
            and call[1].get("Marker") == "attached-final"
            for call in client.calls
        ) == expected_count


@pytest.mark.parametrize(
    ("drift", "code"),
    (
        ("trust", "IAM_TRUST_MISMATCH"),
        ("inline_name", "IAM_INLINE_POLICY_SET_MISMATCH"),
        ("inline_document", "IAM_INLINE_POLICY_MISMATCH"),
        ("managed_attachment", "IAM_MANAGED_POLICY_PRESENT"),
        ("boundary", "IAM_ROLE_BOUNDARY_PRESENT"),
    ),
)
def test_any_effective_authority_drift_fails_closed(
    bindings: PlanRepairIamBindings, drift: str, code: str
) -> None:
    verifier, authority, _ = _verifier(bindings)
    role = authority.roles["ScanalyzeBootstrapPlanRepairPlan"]
    if drift == "trust":
        role["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Action"] = "*"
    elif drift == "inline_name":
        role["PolicyNames"] = [role["PolicyName"], "ForeignPolicy"]
    elif drift == "inline_document":
        role["PolicyDocument"]["Statement"][0]["Action"] = "*"
    elif drift == "managed_attachment":
        role["AttachedPolicies"] = [
            {
                "PolicyName": "ReadOnlyAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            }
        ]
    else:
        role["Role"]["PermissionsBoundary"] = {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        }
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        verifier.snapshot(bindings)
    assert exc_info.value.code == code


def test_repeated_pagination_marker_fails_closed(
    bindings: PlanRepairIamBindings,
) -> None:
    verifier, authority, _ = _verifier(bindings)
    authority.cycle_role = "ScanalyzeBootstrapPlanRepairPlan"
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        verifier.snapshot(bindings)
    assert exc_info.value.code == "IAM_PAGINATION_CYCLE"


def test_terminal_page_marker_fails_closed(
    bindings: PlanRepairIamBindings,
) -> None:
    verifier, authority, _ = _verifier(bindings)
    authority.terminal_marker_role = "ScanalyzeBootstrapPlanRepairPlan"
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        verifier.snapshot(bindings)
    assert exc_info.value.code == "IAM_PROVIDER_RESPONSE_MALFORMED"


def test_malformed_or_colliding_bindings_fail_before_readback(
    bindings: PlanRepairIamBindings,
) -> None:
    payload = {
        name: getattr(bindings, name)
        for name in PlanRepairIamBindings.__dataclass_fields__
    }
    payload["repair_invoker_permission_set_arn"] = bindings.plan_permission_set_arn
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        PlanRepairIamBindings(**payload)
    assert exc_info.value.code == "IAM_BINDING_COLLISION"


def test_private_seed_materializes_exact_effective_iam_bindings(
    bindings: PlanRepairIamBindings,
) -> None:
    seed = {
        "repair_id": bindings.repair_id,
        "expected_code_signing_config_arn": bindings.code_signing_config_arn,
        "ledger_kms_key_arn": bindings.repair_ledger_kms_key_arn,
        "instance_arn": bindings.identity_center_instance_arn,
        "permission_set_arn": bindings.plan_permission_set_arn,
        "repair_invoker_permission_set_arn": (
            bindings.repair_invoker_permission_set_arn
        ),
        "identity_store_id": bindings.identity_store_id,
        "principal_id": bindings.repair_principal_id,
        "identity_center_kms_mode": bindings.identity_center_kms_mode,
        "identity_center_kms_key_arn": bindings.identity_center_kms_key_arn,
    }
    assert PlanRepairIamBindings.from_seed(seed) == bindings


def test_guard_rechecks_before_snapshots_and_each_protected_effect(
    bindings: PlanRepairIamBindings,
) -> None:
    calls: list[str] = []

    class Verifier:
        def snapshot(self, supplied: PlanRepairIamBindings) -> object:
            assert supplied == bindings
            calls.append("guard")
            return object()

    class Delegate:
        def discover(self, seed: Mapping[str, Any]) -> str:
            calls.append("discover")
            return "discovered"

        def snapshot(self, intent: Mapping[str, Any]) -> str:
            calls.append("snapshot")
            return "snapshotted"

        def put_inline_policy(
            self, intent: Mapping[str, Any], policy_json: str
        ) -> None:
            calls.append("put")

        def provision_permission_set(self, intent: Mapping[str, Any]) -> str:
            calls.append("provision")
            return "operation"

        def describe_provisioning(
            self, intent: Mapping[str, Any], request_id: str
        ) -> str:
            calls.append("describe")
            return "SUCCEEDED"

    port = IamEffectiveAuthorityGuardedIdentityCenterPort(
        delegate=Delegate(), verifier=Verifier(), bindings=bindings
    )
    assert port.discover({}) == "discovered"
    assert port.snapshot({}) == "snapshotted"
    port.put_inline_policy({}, "{}")
    assert port.provision_permission_set({}) == "operation"
    assert port.describe_provisioning({}, "request") == "SUCCEEDED"
    assert calls == [
        "guard",
        "discover",
        "guard",
        "snapshot",
        "guard",
        "put",
        "guard",
        "provision",
        "describe",
    ]


def test_control_symlink_is_rejected(tmp_path: Path) -> None:
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "platform-authority-bootstrap-plan-repair-effective-iam.json").symlink_to(
        REPO_ROOT
        / "governance/platform-authority-bootstrap-plan-repair-effective-iam.json"
    )
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        load_expected_roles(repo_root=tmp_path)
    assert exc_info.value.code == "IAM_CONTROL_UNAVAILABLE"
