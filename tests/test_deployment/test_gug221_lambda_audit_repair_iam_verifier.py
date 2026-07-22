from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import sys
from typing import Any, Mapping
from urllib.parse import quote

import pytest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tooling"))

from platform_authority_lambda_audit_repair_broker import (  # noqa: E402
    BrokerConfig,
    BrokerContractError,
    canonical_digest,
)
from platform_authority_lambda_audit_repair_iam_verifier import (  # noqa: E402
    AUTHORITY_ACCOUNT_ID,
    MANAGEMENT_ACCOUNT_ID,
    AwsIamEffectiveVerifier,
    ExpectedIamRole,
    IamEffectiveSnapshot,
    expected_role_specs,
    validate_iam_effective_snapshot,
)


def config_for(*, customer_managed_kms: bool = False) -> BrokerConfig:
    env = {
        "FUNCTION_MODE": "repair",
        "FUNCTION_QUALIFIER": "repair-v1",
        "SOURCE_COMMIT": "a" * 40,
        "REPAIR_ID": (
            "gug221-"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "PRINCIPAL_ID": (
            "1234567890-11111111-2222-3333-4444-555555555555"
        ),
        "IDENTITY_STORE_ID": "d-1234567890",
        "IDENTITY_CENTER_INSTANCE_ARN": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "COLLECTOR_PERMISSION_SET_ARN": (
            "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
            "ps-fedcba0987654321"
        ),
        "REPAIR_INVOKER_PERMISSION_SET_ARN": (
            "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/"
            "ps-0123456789abcdef"
        ),
        "COLLECTOR_POLICY_DIGEST": "b" * 64,
        "REPAIR_INVOKER_POLICY_DIGEST": "c" * 64,
        "ORIGINAL_GUG220_LEDGER_DIGEST": "d" * 64,
        "EXPECTED_PERMISSION_SET_TAGS_JSON": json.dumps(
            {"scanalyze:control": "lambda-audit"}
        ),
        "REPAIR_LEDGER_TABLE_NAME": (
            "scanalyze-platform-authority-gug221-repair-ledger"
        ),
        "REPAIR_LEDGER_KMS_KEY_ARN": (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "11111111-2222-3333-4444-555555555555"
        ),
        "EXPECTED_ARTIFACT_CODE_SHA256": "A" * 43 + "=",
        "EXPECTED_CODE_SIGNING_CONFIG_ARN": (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-1234567890abcdef0"
        ),
        "EXPECTED_SIGNING_PROFILE_VERSION_ARN": (
            "arn:aws:signer:us-east-1:042360977644:"
            "/signing-profiles/ScanalyzeGug221/ABCDEFGHIJ"
        ),
        "REPAIR_NOT_BEFORE": "2026-07-21T19:55:00Z",
        "REPAIR_NOT_AFTER": "2026-07-21T20:10:00Z",
        "AWS_LAMBDA_FUNCTION_VERSION": "42",
        "REPAIR_FUNCTION_VERSION": "42",
        "PLAN_FUNCTION_VERSION": "41",
        "EXPECTED_BOTO3_VERSION": "1.40.1",
        "EXPECTED_BOTOCORE_VERSION": "1.40.1",
        "COLLECTOR_SAML_PROVIDER_ARN": (
            "arn:aws:iam::042360977644:saml-provider/"
            "AWSSSO_1234567890abcdef_DO_NOT_DELETE"
        ),
        "IDENTITY_CENTER_KMS_MODE": (
            "CUSTOMER_MANAGED_KEY"
            if customer_managed_kms
            else "AWS_OWNED_KMS_KEY"
        ),
    }
    if customer_managed_kms:
        env["IDENTITY_CENTER_KMS_KEY_ARN"] = (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        )
    return BrokerConfig.from_env(env)


class FakeIam:
    def __init__(self, specs: tuple[ExpectedIamRole, ...]) -> None:
        self.specs = {spec.role_name: spec for spec in specs}
        self.roles: dict[str, dict[str, Any]] = {
            spec.role_name: {
                "RoleName": spec.role_name,
                "Path": spec.path,
                "Arn": spec.arn,
                "MaxSessionDuration": 3600,
                "AssumeRolePolicyDocument": deepcopy(spec.trust_policy),
            }
            for spec in specs
        }
        self.policies = {
            spec.role_name: deepcopy(spec.inline_policy) for spec in specs
        }
        self.inline_names = {
            spec.role_name: [spec.inline_policy_name] for spec in specs
        }
        self.attached = {spec.role_name: [] for spec in specs}
        self.pagination_mode: dict[tuple[str, str], str] = {}
        self.url_encode: set[str] = set()
        self.policy_binding_changes: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.raise_method: str | None = None

    def _record(self, method: str, kwargs: Mapping[str, Any]) -> None:
        self.calls.append((method, dict(kwargs)))
        if self.raise_method == method:
            raise RuntimeError("sensitive-provider-detail")

    def get_role(self, **kwargs: Any) -> Mapping[str, Any]:
        self._record("get_role", kwargs)
        return {"Role": deepcopy(self.roles[kwargs["RoleName"]])}

    def _page(
        self,
        method: str,
        role_name: str,
        values: list[Any],
        marker: Any,
    ) -> Mapping[str, Any]:
        mode = self.pagination_mode.get((method, role_name), "terminal")
        result_key = (
            "AttachedPolicies"
            if method == "list_attached_role_policies"
            else "PolicyNames"
        )
        if mode == "missing_state":
            return {result_key: deepcopy(values)}
        if mode == "terminal_marker":
            return {
                result_key: deepcopy(values),
                "IsTruncated": False,
                "Marker": "unexpected",
            }
        if mode == "missing_marker":
            return {result_key: [], "IsTruncated": True}
        if mode == "empty_marker":
            return {result_key: [], "IsTruncated": True, "Marker": ""}
        if mode == "cycle":
            return {result_key: [], "IsTruncated": True, "Marker": "cycle"}
        if mode == "two_pages" and marker is None:
            return {result_key: [], "IsTruncated": True, "Marker": "next"}
        return {result_key: deepcopy(values), "IsTruncated": False}

    def list_attached_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        self._record("list_attached_role_policies", kwargs)
        name = kwargs["RoleName"]
        return self._page(
            "list_attached_role_policies",
            name,
            self.attached[name],
            kwargs.get("Marker"),
        )

    def list_role_policies(self, **kwargs: Any) -> Mapping[str, Any]:
        self._record("list_role_policies", kwargs)
        name = kwargs["RoleName"]
        return self._page(
            "list_role_policies",
            name,
            self.inline_names[name],
            kwargs.get("Marker"),
        )

    def get_role_policy(self, **kwargs: Any) -> Mapping[str, Any]:
        self._record("get_role_policy", kwargs)
        name = kwargs["RoleName"]
        binding = {
            "RoleName": name,
            "PolicyName": self.specs[name].inline_policy_name,
        }
        binding.update(self.policy_binding_changes.get(name, {}))
        policy: Any = deepcopy(self.policies[name])
        if name in self.url_encode:
            policy = quote(json.dumps(policy, separators=(",", ":")))
        return {**binding, "PolicyDocument": policy}


def verifier_for(
    config: BrokerConfig,
) -> tuple[AwsIamEffectiveVerifier, FakeIam, FakeIam, tuple[ExpectedIamRole, ...]]:
    specs = expected_role_specs(config, repo_root=ROOT)
    authority = FakeIam(specs[:4])
    management = FakeIam(specs[4:])
    return (
        AwsIamEffectiveVerifier(
            authority_iam=authority,
            management_iam=management,
            repo_root=ROOT,
        ),
        authority,
        management,
        specs,
    )


def client_for(
    spec: ExpectedIamRole, authority: FakeIam, management: FakeIam
) -> FakeIam:
    return authority if spec.account_id == AUTHORITY_ACCOUNT_ID else management


def assert_code(exc: pytest.ExceptionInfo[BrokerContractError], code: str) -> None:
    assert exc.value.code == code


def test_snapshot_verifies_all_six_roles_and_is_deterministic() -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)

    snapshot = verifier.snapshot(config)

    assert [item.role_name for item in snapshot.authority_roles] == [
        item.role_name for item in specs[:4]
    ]
    assert [item.role_name for item in snapshot.management_roles] == [
        item.role_name for item in specs[4:]
    ]
    assert snapshot.digest() == canonical_digest(snapshot.as_dict())
    assert len(snapshot.digest()) == 64
    assert {call[1]["RoleName"] for call in authority.calls} == {
        item.role_name for item in specs[:4]
    }
    assert {call[1]["RoleName"] for call in management.calls} == {
        item.role_name for item in specs[4:]
    }


def test_snapshot_accepts_strict_two_page_inventory_and_url_encoded_documents() -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    for spec in specs:
        client = client_for(spec, authority, management)
        client.pagination_mode[("list_attached_role_policies", spec.role_name)] = (
            "two_pages"
        )
        client.pagination_mode[("list_role_policies", spec.role_name)] = "two_pages"
        client.url_encode.add(spec.role_name)

    snapshot = verifier.snapshot(config)

    assert len(snapshot.authority_roles) == 4
    assert len(snapshot.management_roles) == 2


def test_aws_owned_kms_omits_conditional_decrypt_statements() -> None:
    specs = expected_role_specs(config_for(), repo_root=ROOT)
    for spec in specs[4:]:
        sids = {statement["Sid"] for statement in spec.inline_policy["Statement"]}
        assert "DecryptOnlyThroughExactIdentityCenterInstance" not in sids
        assert "DecryptOnlyThroughExactIdentityStore" not in sids


def test_customer_managed_kms_renders_exact_conditional_decrypt_statements() -> None:
    config = config_for(customer_managed_kms=True)
    specs = expected_role_specs(config, repo_root=ROOT)
    for spec in specs[4:]:
        statements = {
            statement["Sid"]: statement for statement in spec.inline_policy["Statement"]
        }
        assert (
            statements["DecryptOnlyThroughExactIdentityCenterInstance"]["Resource"]
            == config.identity_center_kms_key_arn
        )
        assert (
            statements["DecryptOnlyThroughExactIdentityStore"]["Resource"]
            == config.identity_center_kms_key_arn
        )


@pytest.mark.parametrize("field", ["RoleName", "Path", "Arn"])
@pytest.mark.parametrize("role_index", range(6))
def test_snapshot_rejects_any_role_binding_drift(field: str, role_index: int) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client = client_for(spec, authority, management)
    client.roles[spec.role_name][field] = "foreign"

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_ROLE_BINDING_MISMATCH")


@pytest.mark.parametrize("role_index", range(6))
def test_snapshot_rejects_session_duration_drift(role_index: int) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client_for(spec, authority, management).roles[spec.role_name][
        "MaxSessionDuration"
    ] = 7200

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_ROLE_SESSION_MISMATCH")


@pytest.mark.parametrize("role_index", range(6))
def test_snapshot_rejects_permissions_boundary(role_index: int) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client_for(spec, authority, management).roles[spec.role_name][
        "PermissionsBoundary"
    ] = {
        "PermissionsBoundaryType": "Policy",
        "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
    }

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_ROLE_BOUNDARY_PRESENT")


@pytest.mark.parametrize("role_index", range(6))
@pytest.mark.parametrize(
    "trust_mutation",
    ["principal", "action", "condition", "extra_statement"],
)
def test_snapshot_rejects_any_trust_expansion(
    role_index: int, trust_mutation: str
) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client = client_for(spec, authority, management)
    trust = client.roles[spec.role_name]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    if trust_mutation == "principal":
        statement["Principal"] = {"AWS": "*"}
    elif trust_mutation == "action":
        statement["Action"] = ["sts:AssumeRole", "sts:TagSession"]
    elif trust_mutation == "condition":
        statement["Condition"] = {}
    else:
        trust["Statement"].append(deepcopy(statement))

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_TRUST_MISMATCH")


@pytest.mark.parametrize("role_index", range(6))
def test_snapshot_rejects_any_inline_policy_drift(role_index: int) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client = client_for(spec, authority, management)
    client.policies[spec.role_name]["Statement"].append(
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    )

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_INLINE_POLICY_MISMATCH")


@pytest.mark.parametrize("role_index", range(6))
@pytest.mark.parametrize("names", [[], ["Foreign"], ["Expected", "Foreign"]])
def test_snapshot_rejects_missing_or_foreign_inline_policy_names(
    role_index: int, names: list[str]
) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client = client_for(spec, authority, management)
    client.inline_names[spec.role_name] = [
        spec.inline_policy_name if name == "Expected" else name for name in names
    ]

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_INLINE_POLICY_SET_MISMATCH")


@pytest.mark.parametrize("role_index", range(6))
def test_snapshot_rejects_managed_policy_attachment(role_index: int) -> None:
    config = config_for()
    verifier, authority, management, specs = verifier_for(config)
    spec = specs[role_index]
    client_for(spec, authority, management).attached[spec.role_name] = [
        {
            "PolicyName": "ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        }
    ]

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_MANAGED_POLICY_PRESENT")


@pytest.mark.parametrize(
    ("method", "mode", "expected_code"),
    [
        ("list_role_policies", "missing_state", "IAM_PROVIDER_RESPONSE_MALFORMED"),
        ("list_role_policies", "terminal_marker", "IAM_PROVIDER_RESPONSE_MALFORMED"),
        ("list_role_policies", "missing_marker", "IAM_PROVIDER_RESPONSE_MALFORMED"),
        ("list_role_policies", "empty_marker", "IAM_PROVIDER_RESPONSE_MALFORMED"),
        ("list_role_policies", "cycle", "IAM_PAGINATION_CYCLE"),
        (
            "list_attached_role_policies",
            "missing_state",
            "IAM_PROVIDER_RESPONSE_MALFORMED",
        ),
        (
            "list_attached_role_policies",
            "terminal_marker",
            "IAM_PROVIDER_RESPONSE_MALFORMED",
        ),
        (
            "list_attached_role_policies",
            "cycle",
            "IAM_PAGINATION_CYCLE",
        ),
    ],
)
def test_snapshot_rejects_ambiguous_pagination(
    method: str, mode: str, expected_code: str
) -> None:
    config = config_for()
    verifier, authority, _management, specs = verifier_for(config)
    authority.pagination_mode[(method, specs[0].role_name)] = mode

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, expected_code)


def test_snapshot_rejects_duplicate_inline_inventory() -> None:
    config = config_for()
    verifier, authority, _management, specs = verifier_for(config)
    name = specs[0].role_name
    authority.inline_names[name] = [
        specs[0].inline_policy_name,
        specs[0].inline_policy_name,
    ]

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_INLINE_POLICY_INVENTORY_DUPLICATE")


def test_snapshot_rejects_duplicate_managed_policy_inventory() -> None:
    config = config_for()
    verifier, authority, _management, specs = verifier_for(config)
    name = specs[0].role_name
    attachment = {
        "PolicyName": "ReadOnlyAccess",
        "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
    }
    authority.attached[name] = [attachment, deepcopy(attachment)]

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_MANAGED_POLICY_INVENTORY_DUPLICATE")


@pytest.mark.parametrize("binding_field", ["RoleName", "PolicyName"])
def test_snapshot_rejects_inline_policy_response_binding_drift(
    binding_field: str,
) -> None:
    config = config_for()
    verifier, authority, _management, specs = verifier_for(config)
    authority.policy_binding_changes[specs[0].role_name] = {
        binding_field: "foreign"
    }

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_INLINE_POLICY_BINDING_MISMATCH")


@pytest.mark.parametrize("document_kind", ["scalar", "duplicate"])
def test_snapshot_rejects_malformed_or_duplicate_inline_policy_document(
    document_kind: str,
) -> None:
    config = config_for()
    verifier, authority, _management, specs = verifier_for(config)
    name = specs[0].role_name
    if document_kind == "scalar":
        authority.policies[name] = "not-an-object"
    else:
        authority.policies[name] = quote(
            '{"Version":"2012-10-17","Version":"2012-10-17",'
            '"Statement":[]}'
        )
        authority.url_encode.add(name)

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert exc.value.code in {
        "IAM_INLINE_POLICY_MALFORMED",
        "IAM_POLICY_MALFORMED",
    }


def test_snapshot_collapses_provider_exception_to_stable_code() -> None:
    config = config_for()
    verifier, authority, _management, _specs = verifier_for(config)
    authority.raise_method = "get_role"

    with pytest.raises(BrokerContractError) as exc:
        verifier.snapshot(config)

    assert_code(exc, "IAM_PROVIDER_FAILURE")
    assert "sensitive-provider-detail" not in str(exc.value)


def test_snapshot_validator_rejects_forged_authority_snapshot() -> None:
    config = config_for()
    verifier, _authority, _management, _specs = verifier_for(config)
    snapshot = verifier.snapshot(config)
    forged_role = replace(snapshot.authority_roles[0], trust_policy_digest="f" * 64)
    forged = IamEffectiveSnapshot(
        authority_roles=(forged_role, *snapshot.authority_roles[1:]),
        management_roles=snapshot.management_roles,
    )

    with pytest.raises(BrokerContractError) as exc:
        validate_iam_effective_snapshot(config, forged, repo_root=ROOT)

    assert_code(exc, "AUTHORITY_IAM_SNAPSHOT_MISMATCH")


def test_snapshot_validator_rejects_forged_management_snapshot() -> None:
    config = config_for()
    verifier, _authority, _management, _specs = verifier_for(config)
    snapshot = verifier.snapshot(config)
    forged_role = replace(
        snapshot.management_roles[0], inline_policy_digest="e" * 64
    )
    forged = IamEffectiveSnapshot(
        authority_roles=snapshot.authority_roles,
        management_roles=(forged_role, snapshot.management_roles[1]),
    )

    with pytest.raises(BrokerContractError) as exc:
        validate_iam_effective_snapshot(config, forged, repo_root=ROOT)

    assert_code(exc, "MANAGEMENT_IAM_SNAPSHOT_MISMATCH")


def test_expected_policy_artifact_is_required() -> None:
    with pytest.raises(BrokerContractError) as exc:
        expected_role_specs(config_for(), repo_root=ROOT / "does-not-exist")

    assert_code(exc, "IAM_POLICY_ARTIFACT_UNAVAILABLE")
