"""GUG-123 fail-closed GitHub OIDC and terminal-role authorization tests."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tooling.validate_github_deployment_identity import (
    GitHubDeploymentIdentityError,
    authorize_github_deployment_identity,
    canonical_digest,
    derive_oidc_subject,
    environment_configuration_digest,
    validate_repository_controls,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
ACCOUNT_ID = "123456789012"
SHARED_ACCOUNT_ID = "210987654321"
REGION = "us-east-1"
ENVIRONMENT = "dev"
GITHUB_ENVIRONMENT = f"scanalyze-{DEPLOYMENT_ID}-{ENVIRONMENT}"
OWNER = "synthetic-owner"
REPOSITORY = "scanalyze-deployment-platform"
OWNER_ID = "1000001"
REPOSITORY_ID = "2000002"
WORKFLOW_PATH = ".github/workflows/nonprod-release.yml"
WORKFLOW_REF = f"{OWNER}/{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
NOW = datetime(2026, 7, 14, 20, 5, tzinfo=UTC)
TERRAFORM_LAYER_NAMES = [
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "identity-control-plane",
    "services",
    "edge-identity",
    "edge",
    "addons",
]
GENERIC_TERRAFORM_LAYER_NAMES = [
    layer for layer in TERRAFORM_LAYER_NAMES if layer != "identity-control-plane"
]


def _digest(document: dict) -> str:
    return canonical_digest(document)


def _target(account_ready: dict | None = None) -> dict:
    selected_account_ready = (
        _account_ready() if account_ready is None else account_ready
    )
    document = {
        "schema_version": "1",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "status": "READY",
        "registry_version": 7,
        "account_ready": {
            "schema_version": "2",
            "baseline_version": selected_account_ready["baseline_version"],
            "contract_digest": selected_account_ready["contract_digest"],
        },
        "state_binding": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "state_kms_key": (
                f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
                "11111111-2222-3333-4444-555555555555"
            ),
        },
    }
    document["record_digest"] = _digest(document)
    return document


def _anchor(target: dict) -> dict:
    return {
        "schema_version": "1",
        "deployment_id": target["deployment_id"],
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }


def _role(name: str) -> dict:
    return {
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{name}",
        "customer_id_tag": CUSTOMER_ID,
        "deployment_id_tag": DEPLOYMENT_ID,
        "account_id_tag": ACCOUNT_ID,
        "region_tag": REGION,
        "environment_tag": ENVIRONMENT,
    }


def _account_ready() -> dict:
    document = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-07-14T20:00:00Z",
        "roles": {
            "plan": _role("Plan"),
            "apply": _role("Apply"),
            "identity_plan": _role("Identity-Plan"),
            "identity_apply": _role("Identity-Apply"),
            "promotion": _role("Promotion"),
            "validation": _role("Validation"),
            "diagnostic": _role("Diagnostic"),
            "state_recovery": _role("StateRecovery"),
        },
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
            "state_kms_key": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/state-key",
            "evidence_kms_key": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/evidence-key",
            "contracts_kms_key": f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/contracts-key",
        },
        "controls": {
            "state_versioning_enabled": True,
            "state_default_encryption": "aws:kms",
            "state_bucket_key_enabled": True,
            "state_public_access_blocked": True,
            "state_object_lock_enabled": False,
            "native_lockfile_enabled": True,
        },
    }
    document["contract_digest"] = _digest(document)
    return document


def _terminal(role: str, operation: str, layers: list[str]) -> dict:
    return {
        "role_arn": _account_ready()["roles"][role]["arn"],
        "operation": operation,
        "allowed_layers": layers,
        "max_session_duration_seconds": 900,
        "required_session_tags": [
            "customer_id",
            "deployment_id",
            "account_id",
            "region",
            "environment",
            "operation",
            "layer",
            "change_id",
        ],
        "source_identity_pattern": "^exec_[0-9A-HJKMNP-TV-Z]{26}$",
        "required_resource_tags": {
            "customer_id": CUSTOMER_ID,
            "deployment_id": DEPLOYMENT_ID,
            "account_id": ACCOUNT_ID,
            "region": REGION,
            "environment": ENVIRONMENT,
        },
    }


def _identity() -> dict:
    document = {
        "schema_version": "1",
        "record_type": "github_deployment_identity",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "repository": {
            "owner": OWNER,
            "name": REPOSITORY,
            "owner_id": OWNER_ID,
            "repository_id": REPOSITORY_ID,
            "visibility": "private",
        },
        "workflow": {
            "path": WORKFLOW_PATH,
            "ref": "refs/heads/main",
            "workflow_ref": WORKFLOW_REF,
            "event_name": "workflow_dispatch",
            "execution_mode": "live",
            "github_environment": GITHUB_ENVIRONMENT,
        },
        "oidc": {
            "issuer": "https://token.actions.githubusercontent.com",
            "audience": "sts.amazonaws.com",
            "use_default_subject": False,
            "include_claim_keys": [
                "repository_owner_id",
                "repository_id",
                "context",
                "workflow_ref",
                "event_name",
            ],
            "subject": "pending",
            "orchestrator_role_arn": (
                f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/"
                f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
            ),
            "max_session_duration_seconds": 900,
            "required_role_tags": {
                "service": "scanalyze-orchestrator",
                "customer_id": CUSTOMER_ID,
                "deployment_id": DEPLOYMENT_ID,
                "account_id": ACCOUNT_ID,
                "region": REGION,
                "environment": ENVIRONMENT,
            },
        },
        "environment_protection": {
            "name": GITHUB_ENVIRONMENT,
            "custom_branch_policies": True,
            "protected_branches": ["main"],
            "protected_tags": [],
            "required_reviewers": [
                {"type": "User", "id": "9002", "login": "independent-reviewer"}
            ],
            "prevent_self_review": True,
            "prevent_admin_bypass": True,
            "initiator_login": "release-initiator",
            "reserved_variables_absent_at_repository": True,
            "reserved_variables_absent_at_organization": True,
            "variables": {
                "CUSTOMER_ID": CUSTOMER_ID,
                "DEPLOYMENT_ID": DEPLOYMENT_ID,
                "AWS_ACCOUNT_ID": ACCOUNT_ID,
                "AWS_REGION": REGION,
                "LOGICAL_ENVIRONMENT": ENVIRONMENT,
                "OIDC_ORCHESTRATOR_ROLE_ARN": (
                    f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/"
                    f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
                ),
            },
            "secret_names": [],
        },
        "terminal_roles": {
            "plan": _terminal("plan", "plan", GENERIC_TERRAFORM_LAYER_NAMES),
            "apply": _terminal("apply", "apply", GENERIC_TERRAFORM_LAYER_NAMES),
            "identity_plan": _terminal(
                "identity_plan", "plan", ["identity-control-plane"]
            ),
            "identity_apply": _terminal(
                "identity_apply", "apply", ["identity-control-plane"]
            ),
            "promotion": _terminal(
                "promotion", "promote", ["artifact-publication"]
            ),
            "validation": _terminal(
                "validation", "validate", ["synthetic-validation"]
            ),
        },
        "diagnostic_access": {
            "role_arn": _account_ready()["roles"]["diagnostic"]["arn"],
            "principal": (
                f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/ScanalyzeBreakGlass"
            ),
            "operation": "diagnostic",
            "human_only": True,
            "requires_mfa": True,
            "requires_incident_id": True,
            "max_session_duration_seconds": 900,
        },
        "state_recovery_access": {
            "role_arn": _account_ready()["roles"]["state_recovery"]["arn"],
            "principal": (
                f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/ScanalyzeBreakGlass"
            ),
            "operation": "state-recovery",
            "human_only": True,
            "requires_mfa": True,
            "requires_incident_id": True,
            "requires_recovery_approval": True,
            "max_session_duration_seconds": 900,
        },
    }
    document["oidc"]["subject"] = derive_oidc_subject(document)
    document["contract_digest"] = _digest(document)
    return document


def _environment_anchor(identity: dict) -> dict:
    anchor = {
        "schema_version": "1",
        "record_type": "github_environment_anchor",
        "source": "github-api",
        "repository_owner_id": identity["repository"]["owner_id"],
        "repository_id": identity["repository"]["repository_id"],
        "environment_name": identity["workflow"]["github_environment"],
        "configuration_digest": environment_configuration_digest(identity),
        "captured_at": "2026-07-14T20:04:00Z",
        "expires_at": "2026-07-14T20:09:00Z",
    }
    anchor["evidence_digest"] = _digest(anchor)
    return anchor


def _platform_authority(identity: dict) -> dict:
    authority = {
        "schema_version": "1",
        "record_type": "github_platform_authority",
        "source": "platform-identity-registry",
        "authority_version": 3,
        "shared_services_account_id": SHARED_ACCOUNT_ID,
        "repository_owner_id": identity["repository"]["owner_id"],
        "repository_id": identity["repository"]["repository_id"],
        "oidc_provider_arn": (
            f"arn:aws:iam::{SHARED_ACCOUNT_ID}:"
            "oidc-provider/token.actions.githubusercontent.com"
        ),
        "orchestrator_role_arn": identity["oidc"]["orchestrator_role_arn"],
        "orchestrator_role_tags": copy.deepcopy(
            identity["oidc"]["required_role_tags"]
        ),
    }
    authority["authority_digest"] = _digest(authority)
    return authority


def _platform_authority_anchor(authority: dict) -> dict:
    return {
        "schema_version": "1",
        "authority_version": authority["authority_version"],
        "authority_digest": authority["authority_digest"],
    }


def _authorize(
    identity: dict | None = None,
    environment_anchor: dict | None = None,
    platform_authority: dict | None = None,
    platform_authority_anchor: dict | None = None,
    account_ready: dict | None = None,
) -> dict:
    selected_identity = _identity() if identity is None else identity
    selected_account_ready = (
        _account_ready() if account_ready is None else account_ready
    )
    default_authority = _platform_authority(_identity())
    selected_authority = (
        default_authority if platform_authority is None else platform_authority
    )
    target = _target(selected_account_ready)
    return authorize_github_deployment_identity(
        identity=selected_identity,
        deployment_target=target,
        target_anchor=_anchor(target),
        account_ready=selected_account_ready,
        environment_anchor=(
            _environment_anchor(_identity())
            if environment_anchor is None
            else environment_anchor
        ),
        platform_authority=selected_authority,
        platform_authority_anchor=(
            _platform_authority_anchor(default_authority)
            if platform_authority_anchor is None
            else platform_authority_anchor
        ),
        schema_path=REPO_ROOT / "schemas/github-deployment-identity.v1.schema.json",
        environment_anchor_schema_path=(
            REPO_ROOT / "schemas/github-environment-anchor.v1.schema.json"
        ),
        platform_authority_schema_path=(
            REPO_ROOT / "schemas/github-platform-authority.v1.schema.json"
        ),
        trust_dir=REPO_ROOT / "policies/trust",
        now=NOW,
    )


def _redigest(identity: dict) -> dict:
    identity["contract_digest"] = _digest(identity)
    return identity


def test_owned_exact_identity_is_authorized() -> None:
    decision = _authorize()
    assert decision == {
        "authorized": True,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "github_environment": GITHUB_ENVIRONMENT,
        "oidc_subject": derive_oidc_subject(_identity()),
    }


def test_synthetic_identity_fixture_has_a_valid_canonical_digest() -> None:
    fixture = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/github-deployment-identity-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    assert fixture["contract_digest"] == canonical_digest(fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
        ("deployment_id", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
        ("account_id", "999888777666"),
        ("region", "us-west-2"),
        ("environment", "staging"),
    ],
)
def test_cross_boundary_identity_is_denied(field: str, value: str) -> None:
    identity = _identity()
    identity[field] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("repository", "owner_id"), "9999"),
        (("repository", "repository_id"), "9999"),
        (("repository", "owner"), "foreign-owner"),
        (("workflow", "path"), ".github/workflows/pr-validation.yml"),
        (("workflow", "ref"), "refs/heads/feature"),
        (("workflow", "event_name"), "pull_request"),
        (("workflow", "execution_mode"), "dry-run"),
        (("workflow", "github_environment"), "dev"),
        (("oidc", "use_default_subject"), True),
        (("oidc", "audience"), "https://github.com/synthetic-owner"),
        (("oidc", "max_session_duration_seconds"), 3600),
    ],
)
def test_wrong_repository_workflow_or_oidc_boundary_is_denied(
    path: tuple[str, str], value: object
) -> None:
    identity = _identity()
    identity[path[0]][path[1]] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError):
        _authorize(identity)


def test_subject_wildcard_or_claim_template_drift_is_denied() -> None:
    identity = _identity()
    identity["oidc"]["subject"] = "repo:synthetic-owner/*"
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity)

    identity = _identity()
    identity["oidc"]["include_claim_keys"].remove("workflow_ref")
    identity["oidc"]["subject"] = derive_oidc_subject(identity)
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("custom_branch_policies", False),
        ("protected_branches", ["*"]),
        ("protected_tags", ["v*"]),
        ("required_reviewers", []),
        ("prevent_self_review", False),
        ("prevent_admin_bypass", False),
        ("reserved_variables_absent_at_repository", False),
        ("reserved_variables_absent_at_organization", False),
        ("secret_names", ["AWS_ACCESS_KEY_ID"]),
    ],
)
def test_weak_environment_protection_is_denied(field: str, value: object) -> None:
    identity = _identity()
    identity["environment_protection"][field] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError):
        _authorize(identity)


def test_self_review_and_variable_spoofing_are_denied() -> None:
    identity = _identity()
    identity["environment_protection"]["required_reviewers"][0]["login"] = (
        "release-initiator"
    )
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="independent reviewer"):
        _authorize(identity)

    identity = _identity()
    identity["environment_protection"]["variables"]["AWS_ACCOUNT_ID"] = (
        "999888777666"
    )
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="environment variable"):
        _authorize(identity)


def test_team_reviewer_is_denied_because_membership_is_not_proven() -> None:
    identity = _identity()
    identity["environment_protection"]["required_reviewers"][0]["type"] = "Team"
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "workflow-input"),
        ("repository_owner_id", "9999"),
        ("repository_id", "9999"),
        ("environment_name", "scanalyze-dep_01ARZ3NDEKTSV4RRFFQ69G5FAV-staging"),
        ("configuration_digest", "sha256:" + "0" * 64),
        ("captured_at", "2026-07-14T20:06:00Z"),
        ("expires_at", "2026-07-14T20:05:00Z"),
    ],
)
def test_untrusted_mismatched_or_stale_environment_anchor_is_denied(
    field: str, value: str
) -> None:
    identity = _identity()
    anchor = _environment_anchor(identity)
    anchor[field] = value
    anchor["evidence_digest"] = _digest(anchor)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity, anchor)


def test_environment_anchor_lifetime_is_capped_at_ten_minutes() -> None:
    identity = _identity()
    anchor = _environment_anchor(identity)
    anchor["expires_at"] = "2026-07-14T20:14:01Z"
    anchor["evidence_digest"] = _digest(anchor)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity, anchor)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "workflow-input"),
        ("shared_services_account_id", "999888777666"),
        ("repository_owner_id", "9999"),
        ("repository_id", "9999"),
        (
            "oidc_provider_arn",
            "arn:aws:iam::999888777666:oidc-provider/token.actions.githubusercontent.com",
        ),
        (
            "orchestrator_role_arn",
            "arn:aws:iam::999888777666:role/ScanalyzeOrchestrator-foreign",
        ),
    ],
)
def test_untrusted_or_mismatched_platform_authority_is_denied(
    field: str, value: str
) -> None:
    identity = _identity()
    authority = _platform_authority(identity)
    authority[field] = value
    authority["authority_digest"] = _digest(authority)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity, platform_authority=authority)


def test_unanchored_platform_authority_or_role_tag_drift_is_denied() -> None:
    identity = _identity()
    authority = _platform_authority(identity)
    stale_anchor = _platform_authority_anchor(authority)
    authority["authority_version"] += 1
    authority["authority_digest"] = _digest(authority)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(
            identity,
            platform_authority=authority,
            platform_authority_anchor=stale_anchor,
        )

    authority = _platform_authority(identity)
    authority["orchestrator_role_tags"]["account_id"] = "999888777666"
    authority["authority_digest"] = _digest(authority)
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity, platform_authority=authority)


@pytest.mark.parametrize(
    ("role", "field", "value"),
    [
        ("plan", "operation", "apply"),
        ("apply", "role_arn", "arn:aws:iam::999888777666:role/foreign"),
        ("promotion", "allowed_layers", ["network"]),
        ("validation", "max_session_duration_seconds", 3600),
        ("plan", "required_session_tags", ["deployment_id"]),
        ("apply", "source_identity_pattern", ".*"),
        ("identity_plan", "allowed_layers", ["services"]),
        (
            "identity_apply",
            "role_arn",
            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-Apply",
        ),
        (
            "plan",
            "required_resource_tags",
            {
                "customer_id": CUSTOMER_ID,
                "deployment_id": DEPLOYMENT_ID,
                "account_id": "999888777666",
                "region": REGION,
                "environment": ENVIRONMENT,
            },
        ),
    ],
)
def test_terminal_role_confusion_or_weak_session_is_denied(
    role: str, field: str, value: object
) -> None:
    identity = _identity()
    identity["terminal_roles"][role][field] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError):
        _authorize(identity)


def test_identity_control_plane_uses_dedicated_terminal_roles_only() -> None:
    identity = _identity()

    assert "identity-control-plane" not in identity["terminal_roles"]["plan"][
        "allowed_layers"
    ]
    assert "identity-control-plane" not in identity["terminal_roles"]["apply"][
        "allowed_layers"
    ]
    assert identity["terminal_roles"]["identity_plan"]["allowed_layers"] == [
        "identity-control-plane"
    ]
    assert identity["terminal_roles"]["identity_apply"]["allowed_layers"] == [
        "identity-control-plane"
    ]
    assert _authorize(identity)["authorized"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id_tag", "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
        ("deployment_id_tag", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
        ("account_id_tag", "999888777666"),
        ("region_tag", "us-west-2"),
        ("environment_tag", "staging"),
    ],
)
def test_account_ready_terminal_role_ownership_drift_is_denied(
    field: str, value: str
) -> None:
    identity = _identity()
    account_ready = _account_ready()
    account_ready["roles"]["plan"][field] = value
    account_ready["contract_digest"] = _digest(account_ready)

    with pytest.raises(
        GitHubDeploymentIdentityError,
        match="ACCOUNT_READY role ownership mismatch",
    ):
        _authorize(identity, account_ready=account_ready)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("human_only", False),
        ("requires_mfa", False),
        ("requires_incident_id", False),
        ("max_session_duration_seconds", 3600),
        (
            "principal",
            f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/ScanalyzeOrchestrator",
        ),
    ],
)
def test_diagnostic_access_remains_human_break_glass_only(
    field: str, value: object
) -> None:
    identity = _identity()
    identity["diagnostic_access"][field] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError):
        _authorize(identity)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("human_only", False),
        ("requires_mfa", False),
        ("requires_incident_id", False),
        ("requires_recovery_approval", False),
        ("operation", "diagnostic"),
        ("max_session_duration_seconds", 3600),
        (
            "principal",
            f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/ScanalyzeOrchestrator",
        ),
    ],
)
def test_state_recovery_remains_independently_approved_human_only(
    field: str, value: object
) -> None:
    identity = _identity()
    identity["state_recovery_access"][field] = value
    _redigest(identity)
    with pytest.raises(GitHubDeploymentIdentityError):
        _authorize(identity)


def test_missing_malformed_or_conflicting_contract_is_denied_without_details() -> None:
    for identity in ({}, {"schema_version": "1"}):
        with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
            _authorize(identity)

    identity = _identity()
    identity["contract_digest"] = "sha256:" + "0" * 64
    with pytest.raises(GitHubDeploymentIdentityError, match="authorization denied"):
        _authorize(identity)


def test_repository_controls_are_exact_and_dry_run_remains_unprivileged() -> None:
    result = validate_repository_controls(REPO_ROOT)
    assert result["trust_policies"] == [
        "apply",
        "identity_apply",
        "identity_plan",
        "plan",
        "promotion",
        "validation",
    ]
    assert result["dry_run_oidc"] is False
    assert result["privileged_workflows"] == []
    assert result["orchestrator_actions"] == [
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    ]


def test_no_repository_workflow_can_bypass_the_gug123_authorizer() -> None:
    forbidden = ("id-token: write", "aws-actions/configure-aws-credentials")
    for workflow_path in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
        workflow = workflow_path.read_text(encoding="utf-8")
        assert not any(marker in workflow for marker in forbidden), workflow_path.name


def test_multivalued_session_tag_allowlists_are_non_vacuous() -> None:
    policy_paths = [
        REPO_ROOT / "policies/iam/orchestrator-role.json",
        REPO_ROOT / "policies/iam/break-glass-role.json",
        *(REPO_ROOT / "policies/trust").glob("*-trust.json"),
    ]
    checked = 0
    for policy_path in policy_paths:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        for statement in policy["Statement"]:
            if statement.get("Action") != "sts:TagSession":
                continue
            checked += 1
            conditions = statement["Condition"]
            assert conditions["Null"]["aws:TagKeys"] == "false", policy_path.name
    assert checked == 10

    oidc_trust = json.loads(
        (REPO_ROOT / "policies/trust/github-oidc-orchestrator-trust.json").read_text(
            encoding="utf-8"
        )
    )
    conditions = oidc_trust["Statement"][0]["Condition"]["StringEquals"]
    assert conditions == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "${github_oidc_subject}",
    }
    assert "*" not in conditions["token.actions.githubusercontent.com:sub"]


def test_break_glass_permissions_are_account_bound_and_operation_separated() -> None:
    policy = json.loads(
        (REPO_ROOT / "policies/iam/break-glass-role.json").read_text(
            encoding="utf-8"
        )
    )
    allow_sts = [
        statement
        for statement in policy["Statement"]
        if statement["Effect"] == "Allow"
        and str(statement["Action"]).startswith("sts:")
    ]
    actions = {statement["Action"] for statement in allow_sts}
    assert actions == {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }
    resources = [
        resource
        for statement in allow_sts
        for resource in (
            statement["Resource"]
            if isinstance(statement["Resource"], list)
            else [statement["Resource"]]
        )
    ]
    assert resources
    assert all("::${aws:PrincipalTag/account_id}:role/" in value for value in resources)
    assert all("Diagnostic" in value or "StateRecovery" in value for value in resources)
    assert not any("::*:" in value for value in resources)


def test_original_documents_are_not_mutated() -> None:
    identity = _identity()
    target = _target()
    anchor = _anchor(target)
    account_ready = _account_ready()
    environment_anchor = _environment_anchor(identity)
    platform_authority = _platform_authority(identity)
    platform_authority_anchor = _platform_authority_anchor(platform_authority)
    originals = tuple(
        copy.deepcopy(item)
        for item in (
            identity,
            target,
            anchor,
            account_ready,
            environment_anchor,
            platform_authority,
            platform_authority_anchor,
        )
    )

    authorize_github_deployment_identity(
        identity=identity,
        deployment_target=target,
        target_anchor=anchor,
        account_ready=account_ready,
        environment_anchor=environment_anchor,
        platform_authority=platform_authority,
        platform_authority_anchor=platform_authority_anchor,
        schema_path=REPO_ROOT / "schemas/github-deployment-identity.v1.schema.json",
        environment_anchor_schema_path=(
            REPO_ROOT / "schemas/github-environment-anchor.v1.schema.json"
        ),
        platform_authority_schema_path=(
            REPO_ROOT / "schemas/github-platform-authority.v1.schema.json"
        ),
        trust_dir=REPO_ROOT / "policies/trust",
        now=NOW,
    )

    assert (
        identity,
        target,
        anchor,
        account_ready,
        environment_anchor,
        platform_authority,
        platform_authority_anchor,
    ) == originals
