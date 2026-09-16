"""Offline contract checks for the explicit GUG-274 JWT deployment mode.

Exercise the real fixed-template renderer and CloudFormation Rule expressions.
These checks do not authenticate an issuer or authorize an installation.
"""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import itertools
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "bootstrap/cfn-platform-authority-bootstrap-artifact-authority.yaml"
RENDERER = ROOT / "scripts/deployment/render-bootstrap-authority-template.py"
FUNCTIONS = (
    "PlanAuthorityFunction",
    "ApprovalAuthorityFunction",
    "ApplyExecutorFunction",
)
JWT_METADATA = {
    "JwtTrustedTokenIssuerArn": "synthetic-reviewed-trusted-token-issuer-arn",
    "JwtIssuerUrl": "https://synthetic-issuer.example.invalid",
    "JwtAudience": "synthetic-bootstrap-authority",
}
ENVIRONMENT_PARAMETERS = {
    "GUG274_IDENTITY_GRANT_VERSION": "IdentityGrantVersion",
    "GUG274_JWT_TRUSTED_TOKEN_ISSUER_ARN": "JwtTrustedTokenIssuerArn",
    "GUG274_JWT_ISSUER_URL": "JwtIssuerUrl",
    "GUG274_JWT_AUDIENCE": "JwtAudience",
    "GUG274_OPERATOR_POLICY_MODE": "OperatorPolicyMode",
    "GUG274_SINGLE_OWNER_AUTHORIZED_AT": "SingleOwnerAuthorizedAt",
    "GUG274_SINGLE_OWNER_EXPIRES_AT": "SingleOwnerExpiresAt",
}
SINGLE_OWNER = {
    "OperatorPolicyMode": "single_owner_v1",
    "IdentityGrantVersion": "2",
    "SecondPartyIdentityStoreUserId": "",
    "SingleOwnerAuthorizedAt": "2026-09-16T00:00:00Z",
    "SingleOwnerExpiresAt": "2026-09-16T12:00:00Z",
} | JWT_METADATA


@pytest.fixture(scope="module")
def template():
    spec = importlib.util.spec_from_file_location("_jwt_template_renderer", RENDERER)
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    source = TEMPLATE.read_bytes()
    # This digest exercises the renderer; it is not an installation approval pin.
    return json.loads(renderer.render(source, sha256(source).hexdigest()))


def _evaluate(expression, parameters):
    """Evaluate only the rule intrinsics used by this fixed template."""
    if not isinstance(expression, dict):
        return expression
    assert len(expression) == 1
    operation, arguments = next(iter(expression.items()))
    if operation == "Ref":
        return parameters[arguments]
    if operation == "Fn::Equals":
        assert len(arguments) == 2
        return _evaluate(arguments[0], parameters) == _evaluate(arguments[1], parameters)
    if operation == "Fn::Not":
        assert len(arguments) == 1
        result = _evaluate(arguments[0], parameters)
        assert type(result) is bool
        return not result
    raise AssertionError(f"Unsupported rule intrinsic: {operation}")


def _parameters(template, supplied):
    defaults = {
        name: definition["Default"]
        for name, definition in template["Parameters"].items()
        if "Default" in definition
    }
    # Synthetic values used exclusively to evaluate the existing account/user rules.
    return defaults | {
        "AuthorityAccountId": "123456789012",
        "AWS::AccountId": "123456789012",
        "PlanIdentityStoreUserId": "00000000-0000-4000-8000-000000000001",
        "SecondPartyIdentityStoreUserId": "00000000-0000-4000-8000-000000000002",
    } | supplied


def _rules_accept(template, supplied):
    parameters = _parameters(template, supplied)
    # The parameter constraints plus actual Rules form the mode-admission boundary.
    # This is deliberately not a general CloudFormation deployment validator.
    for name in ENVIRONMENT_PARAMETERS.values():
        definition = template["Parameters"][name]
        assert definition["Type"] == "String"
        value = parameters[name]
        if not isinstance(value, str):
            return False
        if "AllowedValues" in definition and value not in definition["AllowedValues"]:
            return False
    for rule in template["Rules"].values():
        if not _evaluate(rule.get("RuleCondition", True), parameters):
            continue
        for assertion in rule["Assertions"]:
            if _evaluate(assertion["Assert"], parameters) is not True:
                return False
    return True


def test_absent_new_parameters_preserve_legacy_mode(template):
    parameters = _parameters(template, {})
    assert parameters["IdentityGrantVersion"] == "1"
    assert all(parameters[name] == "" for name in JWT_METADATA)
    assert template["Parameters"]["IdentityGrantVersion"]["AllowedValues"] == ["1", "2"]
    assert _rules_accept(template, {})


@pytest.mark.parametrize("version", ["1", "2"])
@pytest.mark.parametrize("present", itertools.product((False, True), repeat=3))
def test_mode_accepts_only_its_complete_metadata_configuration(template, version, present):
    supplied = {"IdentityGrantVersion": version} | {
        name: value for (name, value), included in zip(JWT_METADATA.items(), present)
        if included
    }
    expected = all(present) if version == "2" else not any(present)
    assert _rules_accept(template, supplied) is expected


@pytest.mark.parametrize("name", JWT_METADATA)
def test_omitted_mode_cannot_silently_activate_jwt_metadata(template, name):
    assert not _rules_accept(template, {name: JWT_METADATA[name]})


@pytest.mark.parametrize("version", ["", "0", "3", "02", "legacy", 2])
def test_unsupported_mode_is_rejected_even_with_complete_metadata(template, version):
    assert not _rules_accept(template, {"IdentityGrantVersion": version} | JWT_METADATA)


@pytest.mark.parametrize("function_name", FUNCTIONS)
@pytest.mark.parametrize("version", ["1", "2"])
def test_all_three_lambdas_receive_the_selected_version_and_exact_metadata(
    template, function_name, version,
):
    supplied = {"IdentityGrantVersion": version}
    if version == "2":
        supplied |= JWT_METADATA
    assert _rules_accept(template, supplied)
    parameters = _parameters(template, supplied)
    environment = template["Resources"][function_name]["Properties"]["Environment"]["Variables"]
    for variable, parameter in ENVIRONMENT_PARAMETERS.items():
        assert environment[variable] == {"Ref": parameter}
        assert _evaluate(environment[variable], parameters) == parameters[parameter]


def test_shared_environment_survives_fixed_json_rendering(template):
    functions = {
        name: resource for name, resource in template["Resources"].items()
        if resource["Type"] == "AWS::Lambda::Function"
    }
    assert set(functions) == set(FUNCTIONS)
    environments = [resource["Properties"]["Environment"] for resource in functions.values()]
    assert all(environment == environments[0] for environment in environments)
    # Existing account, instance and two-person bindings remain present in every mode.
    variables = environments[0]["Variables"]
    for variable, parameter in {
        "GUG274_AUTHORITY_ACCOUNT_ID": "AuthorityAccountId",
        "GUG274_IDENTITY_CENTER_INSTANCE_ARN": "IdentityCenterInstanceArn",
        "GUG274_PLAN_IDENTITY_STORE_USER_ID": "PlanIdentityStoreUserId",
        "GUG274_SECOND_PARTY_IDENTITY_STORE_USER_ID": "SecondPartyIdentityStoreUserId",
    }.items():
        assert variables[variable] == {"Ref": parameter}


@pytest.mark.parametrize("version", ["1", "2"])
@pytest.mark.parametrize("violation", ["same_human", "wrong_account", "unconfigured_signer"])
def test_jwt_selection_does_not_bypass_existing_deployment_rules(template, version, violation):
    supplied = {"IdentityGrantVersion": version}
    if version == "2":
        supplied |= JWT_METADATA
    if violation == "same_human":
        supplied["SecondPartyIdentityStoreUserId"] = _parameters(template, {})["PlanIdentityStoreUserId"]
    elif violation == "wrong_account":
        supplied["AuthorityAccountId"] = "210987654321"
    else:
        supplied["AuthoritySigningTrustRootConfigured"] = "false"
    assert not _rules_accept(template, supplied)


@pytest.mark.parametrize("version_name,function_name", [
    ("PlanAuthorityVersion", "PlanAuthorityFunction"),
    ("ApprovalAuthorityVersion", "ApprovalAuthorityFunction"),
    ("ApplyExecutorVersion", "ApplyExecutorFunction"),
])
def test_published_versions_still_bind_the_signed_artifact(template, version_name, function_name):
    version = template["Resources"][version_name]
    assert version["Type"] == "AWS::Lambda::Version"
    assert version["Properties"]["FunctionName"] == {"Ref": function_name}
    assert version["Properties"]["CodeSha256"] == {"Ref": "SignedAuthorityArtifactCodeSha256"}
    assert version["DeletionPolicy"] == "Retain"
    assert version["UpdateReplacePolicy"] == "Retain"


def test_independent_default_still_rejects_empty_second_party(template):
    assert not _rules_accept(template, {"SecondPartyIdentityStoreUserId": ""})


def test_single_owner_v2_accepts_empty_second_party_with_owner_window(template):
    assert _rules_accept(template, SINGLE_OWNER)
    parameters = _parameters(template, SINGLE_OWNER)
    assert parameters["OperatorPolicyMode"] == "single_owner_v1"
    assert parameters["SecondPartyIdentityStoreUserId"] == ""
    environment = template["Resources"]["PlanAuthorityFunction"]["Properties"]["Environment"]["Variables"]
    assert environment["GUG274_OPERATOR_POLICY_MODE"] == {"Ref": "OperatorPolicyMode"}
    assert environment["GUG274_SINGLE_OWNER_AUTHORIZED_AT"] == {"Ref": "SingleOwnerAuthorizedAt"}
    assert environment["GUG274_SINGLE_OWNER_EXPIRES_AT"] == {"Ref": "SingleOwnerExpiresAt"}


@pytest.mark.parametrize("missing", [
    "JwtTrustedTokenIssuerArn",
    "JwtIssuerUrl",
    "JwtAudience",
    "SingleOwnerAuthorizedAt",
    "SingleOwnerExpiresAt",
])
def test_single_owner_rejects_incomplete_jwt_or_window(template, missing):
    supplied = dict(SINGLE_OWNER)
    if missing.startswith("Single"):
        supplied[missing] = ""
    else:
        supplied[missing] = ""
    assert not _rules_accept(template, supplied)


def test_single_owner_rejects_populated_second_party(template):
    assert not _rules_accept(
        template,
        SINGLE_OWNER | {"SecondPartyIdentityStoreUserId": "00000000-0000-4000-8000-000000000002"},
    )


def test_single_owner_rejects_identity_grant_version_1(template):
    supplied = dict(SINGLE_OWNER)
    supplied["IdentityGrantVersion"] = "1"
    for name in JWT_METADATA:
        supplied[name] = ""
    assert not _rules_accept(template, supplied)


def test_independent_rejects_single_owner_window_fields(template):
    assert not _rules_accept(
        template,
        {
            "OperatorPolicyMode": "independent",
            "SingleOwnerAuthorizedAt": "2026-09-16T00:00:00Z",
            "SingleOwnerExpiresAt": "2026-09-16T12:00:00Z",
        },
    )


def test_approval_and_apply_proof_roles_bind_owner_when_single_owner(template):
    approval = template["Resources"]["ApprovalIdentityProofRole"]
    apply_role = template["Resources"]["ApplyIdentityProofRole"]
    for role in (approval, apply_role):
        statements = role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        set_context = [s for s in statements if s.get("Sid", "").startswith("SetExact")]
        assert len(set_context) == 1
        user = set_context[0]["Condition"]["StringEquals"][
            "sts:RequestContext/identitystore:UserId"
        ]
        assert user == {
            "Fn::If": [
                "SingleOwnerMode",
                {"Ref": "PlanIdentityStoreUserId"},
                {"Ref": "SecondPartyIdentityStoreUserId"},
            ]
        }
    assert template["Conditions"]["SingleOwnerMode"] == {
        "Fn::Equals": [{"Ref": "OperatorPolicyMode"}, "single_owner_v1"]
    }
