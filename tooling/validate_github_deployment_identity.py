#!/usr/bin/env python3
"""Authorize one GitHub deployment identity and its terminal IAM boundaries.

The deployment registry, independent target anchor, ACCOUNT_READY contract,
GitHub Environment snapshot, customized OIDC subject, and terminal role set
must agree exactly. Request, workflow, or environment values are assertions;
none can independently establish deployment authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = REPO_ROOT / "schemas/github-deployment-identity.v1.schema.json"
DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA = (
    REPO_ROOT / "schemas/github-environment-anchor.v1.schema.json"
)
DEFAULT_PLATFORM_AUTHORITY_SCHEMA = (
    REPO_ROOT / "schemas/github-platform-authority.v1.schema.json"
)
DEFAULT_TRUST_DIR = REPO_ROOT / "policies/trust"
EXPECTED_CLAIM_KEYS = (
    "repository_owner_id",
    "repository_id",
    "context",
    "workflow_ref",
    "event_name",
)
EXPECTED_SESSION_TAGS = frozenset(
    {
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "operation",
        "layer",
        "change_id",
    }
)
TERRAFORM_LAYERS = (
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
)
GENERIC_TERRAFORM_LAYERS = tuple(
    layer for layer in TERRAFORM_LAYERS if layer != "identity-control-plane"
)
ROLE_LAYERS = {
    "plan": GENERIC_TERRAFORM_LAYERS,
    "apply": GENERIC_TERRAFORM_LAYERS,
    "identity_plan": ("identity-control-plane",),
    "identity_apply": ("identity-control-plane",),
    "promotion": ("artifact-publication",),
    "validation": ("synthetic-validation",),
}
ROLE_OPERATIONS = {
    "plan": "plan",
    "apply": "apply",
    "identity_plan": "plan",
    "identity_apply": "apply",
    "promotion": "promote",
    "validation": "validate",
}
APPROVED_WORKFLOW_EVENTS = {
    ".github/workflows/nonprod-release.yml": frozenset({"workflow_dispatch"}),
    ".github/workflows/microservices-build.yml": frozenset(
        {"workflow_dispatch", "push"}
    ),
}
ROLE_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:iam::(?P<account>[0-9]{12}):role/"
    r"(?P<name>[A-Za-z0-9+=,.@_/-]+)$"
)


class GitHubDeploymentIdentityError(ValueError):
    """The deployment identity could not be proven safe."""


def canonical_digest(document: dict[str, Any]) -> str:
    """Return a digest of canonical JSON excluding top-level digest claims."""
    payload = {
        key: value
        for key, value in document.items()
        if key
        not in {
            "authority_digest",
            "contract_digest",
            "record_digest",
            "evidence_digest",
        }
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubDeploymentIdentityError("authorization denied")
        document[key] = value
    return document


def load_json_strict(path: Path) -> dict[str, Any]:
    """Load a JSON object while rejecting duplicates and non-objects."""
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubDeploymentIdentityError("authorization denied") from exc
    if not isinstance(document, dict):
        raise GitHubDeploymentIdentityError("authorization denied")
    return document


def _digest_matches(document: dict[str, Any], field: str) -> None:
    if document.get(field) != canonical_digest(document):
        raise GitHubDeploymentIdentityError("authorization denied")


def _encode_subject_value(value: object) -> str:
    rendered = str(value)
    if not rendered or any(character in rendered for character in "\r\n\t"):
        raise GitHubDeploymentIdentityError("OIDC subject value is invalid")
    return rendered.replace(":", "%3A")


def derive_oidc_subject(identity: dict[str, Any]) -> str:
    """Derive the only accepted customized GitHub OIDC subject."""
    try:
        repository = identity["repository"]
        workflow = identity["workflow"]
        parts = (
            ("repository_owner_id", repository["owner_id"]),
            ("repository_id", repository["repository_id"]),
            ("environment", workflow["github_environment"]),
            ("workflow_ref", workflow["workflow_ref"]),
            ("event_name", workflow["event_name"]),
        )
    except (KeyError, TypeError) as exc:
        raise GitHubDeploymentIdentityError("OIDC subject cannot be derived") from exc
    return ":".join(
        component
        for key, value in parts
        for component in (key, _encode_subject_value(value))
    )


def environment_configuration_digest(identity: dict[str, Any]) -> str:
    """Digest only GitHub API-observable environment and OIDC configuration."""
    try:
        repository = identity["repository"]
        protection = identity["environment_protection"]
        oidc = identity["oidc"]
        configuration = {
            "repository_owner_id": repository["owner_id"],
            "repository_id": repository["repository_id"],
            "environment": {
                key: value
                for key, value in protection.items()
                if key != "initiator_login"
            },
            "oidc_subject_customization": {
                "use_default_subject": oidc["use_default_subject"],
                "include_claim_keys": oidc["include_claim_keys"],
            },
        }
    except (KeyError, TypeError) as exc:
        raise GitHubDeploymentIdentityError("authorization denied") from exc
    return canonical_digest(configuration)


def _validate_schema(identity: dict[str, Any], schema_path: Path) -> None:
    try:
        schema = load_json_strict(schema_path)
        validator = jsonschema.Draft202012Validator(schema)
        if next(iter(validator.iter_errors(identity)), None) is not None:
            raise GitHubDeploymentIdentityError("authorization denied")
    except jsonschema.SchemaError as exc:
        raise GitHubDeploymentIdentityError("authorization denied") from exc


def _exact_registry_binding(
    identity: dict[str, Any],
    target: dict[str, Any],
    anchor: dict[str, Any],
    account_ready: dict[str, Any],
) -> None:
    _digest_matches(target, "record_digest")
    _digest_matches(account_ready, "contract_digest")
    expected_anchor = {
        "schema_version": "1",
        "deployment_id": target.get("deployment_id"),
        "registry_version": target.get("registry_version"),
        "record_digest": target.get("record_digest"),
    }
    if anchor != expected_anchor or target.get("status") not in {"READY", "ACTIVE"}:
        raise GitHubDeploymentIdentityError("authorization denied")
    if target.get("account_ready") != {
        "schema_version": "2",
        "baseline_version": account_ready.get("baseline_version"),
        "contract_digest": account_ready.get("contract_digest"),
    }:
        raise GitHubDeploymentIdentityError("authorization denied")

    comparisons = {
        "customer_id": (
            identity.get("customer_id"),
            target.get("customer_id"),
            account_ready.get("customer_id"),
        ),
        "deployment_id": (
            identity.get("deployment_id"),
            target.get("deployment_id"),
            account_ready.get("deployment_id"),
        ),
        "account_id": (
            identity.get("account_id"),
            target.get("account_id"),
            account_ready.get("account_id"),
        ),
        "region": (
            identity.get("region"),
            target.get("region"),
            account_ready.get("region"),
        ),
        "environment": (
            identity.get("environment"),
            target.get("environment"),
            account_ready.get("environment"),
        ),
    }
    if any(
        any(value in {None, ""} for value in values) or len(set(values)) != 1
        for values in comparisons.values()
    ):
        raise GitHubDeploymentIdentityError("authorization denied")


def _exact_platform_authority(
    identity: dict[str, Any],
    authority: dict[str, Any],
    anchor: dict[str, Any],
    *,
    schema_path: Path,
) -> None:
    """Bind GitHub and orchestrator identity to an external platform authority."""
    _validate_schema(authority, schema_path)
    _digest_matches(authority, "authority_digest")
    expected_anchor = {
        "schema_version": "1",
        "authority_version": authority.get("authority_version"),
        "authority_digest": authority.get("authority_digest"),
    }
    if anchor != expected_anchor:
        raise GitHubDeploymentIdentityError("authorization denied")

    repository = identity["repository"]
    oidc = identity["oidc"]
    role = ROLE_ARN.fullmatch(oidc["orchestrator_role_arn"])
    if not role:
        raise GitHubDeploymentIdentityError("authorization denied")
    expected_provider = (
        f"arn:aws:iam::{authority['shared_services_account_id']}:"
        "oidc-provider/token.actions.githubusercontent.com"
    )
    expected = {
        "repository_owner_id": repository["owner_id"],
        "repository_id": repository["repository_id"],
        "oidc_provider_arn": expected_provider,
        "orchestrator_role_arn": oidc["orchestrator_role_arn"],
        "orchestrator_role_tags": oidc["required_role_tags"],
    }
    if authority.get("source") != "platform-identity-registry" or any(
        authority.get(key) != value for key, value in expected.items()
    ):
        raise GitHubDeploymentIdentityError("authorization denied")
    if role.group("account") != authority["shared_services_account_id"]:
        raise GitHubDeploymentIdentityError("authorization denied")


def _validate_workflow_and_oidc(identity: dict[str, Any]) -> None:
    repository = identity["repository"]
    workflow = identity["workflow"]
    oidc = identity["oidc"]
    expected_workflow_ref = (
        f"{repository['owner']}/{repository['name']}/{workflow['path']}@"
        f"{workflow['ref']}"
    )
    if workflow["workflow_ref"] != expected_workflow_ref:
        raise GitHubDeploymentIdentityError("workflow identity is not exact")
    allowed_events = APPROVED_WORKFLOW_EVENTS.get(workflow["path"])
    if not allowed_events or workflow["event_name"] not in allowed_events:
        raise GitHubDeploymentIdentityError("workflow event is not authorized")
    if workflow["execution_mode"] != "live":
        raise GitHubDeploymentIdentityError("dry-run identity is forbidden")
    expected_environment = (
        f"scanalyze-{identity['deployment_id']}-{identity['environment']}"
    )
    if workflow["github_environment"] != expected_environment:
        raise GitHubDeploymentIdentityError("GitHub Environment is not deployment-bound")
    if tuple(oidc["include_claim_keys"]) != EXPECTED_CLAIM_KEYS:
        raise GitHubDeploymentIdentityError("OIDC claim template is not exact")
    if oidc["use_default_subject"] is not False:
        raise GitHubDeploymentIdentityError("default OIDC subject is forbidden")
    expected_subject = derive_oidc_subject(identity)
    if oidc["subject"] != expected_subject or "*" in oidc["subject"]:
        raise GitHubDeploymentIdentityError("OIDC subject is not exact")
    match = ROLE_ARN.fullmatch(oidc["orchestrator_role_arn"])
    if not match or match.group("name") != (
        f"ScanalyzeOrchestrator-{identity['deployment_id']}"
    ):
        raise GitHubDeploymentIdentityError("orchestrator identity is not deployment-bound")
    expected_role_tags = {
        "service": "scanalyze-orchestrator",
        "customer_id": identity["customer_id"],
        "deployment_id": identity["deployment_id"],
        "account_id": identity["account_id"],
        "region": identity["region"],
        "environment": identity["environment"],
    }
    if oidc["required_role_tags"] != expected_role_tags:
        raise GitHubDeploymentIdentityError("orchestrator role tags are not exact")


def _validate_environment(identity: dict[str, Any]) -> None:
    protection = identity["environment_protection"]
    workflow = identity["workflow"]
    if protection["name"] != workflow["github_environment"]:
        raise GitHubDeploymentIdentityError("environment snapshot does not match workflow")
    if (
        protection["custom_branch_policies"] is not True
        or protection["protected_branches"] != ["main"]
        or protection["protected_tags"] != []
        or protection["prevent_self_review"] is not True
        or protection["prevent_admin_bypass"] is not True
        or protection["reserved_variables_absent_at_repository"] is not True
        or protection["reserved_variables_absent_at_organization"] is not True
        or protection["secret_names"] != []
    ):
        raise GitHubDeploymentIdentityError("environment protection is insufficient")
    reviewers = protection["required_reviewers"]
    initiator = protection["initiator_login"].casefold()
    if not reviewers or any(
        reviewer["login"].casefold() == initiator for reviewer in reviewers
    ):
        raise GitHubDeploymentIdentityError("independent reviewer is required")
    expected_variables = {
        "CUSTOMER_ID": identity["customer_id"],
        "DEPLOYMENT_ID": identity["deployment_id"],
        "AWS_ACCOUNT_ID": identity["account_id"],
        "AWS_REGION": identity["region"],
        "LOGICAL_ENVIRONMENT": identity["environment"],
        "OIDC_ORCHESTRATOR_ROLE_ARN": identity["oidc"][
            "orchestrator_role_arn"
        ],
    }
    if protection["variables"] != expected_variables:
        raise GitHubDeploymentIdentityError("environment variable binding mismatch")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GitHubDeploymentIdentityError("authorization denied")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GitHubDeploymentIdentityError("authorization denied") from exc
    return parsed.astimezone(UTC)


def _validate_environment_anchor(
    identity: dict[str, Any],
    anchor: dict[str, Any],
    *,
    schema_path: Path,
    now: datetime,
) -> None:
    """Require fresh, independently retrieved GitHub configuration evidence."""
    _validate_schema(anchor, schema_path)
    _digest_matches(anchor, "evidence_digest")
    repository = identity["repository"]
    workflow = identity["workflow"]
    expected = {
        "repository_owner_id": repository["owner_id"],
        "repository_id": repository["repository_id"],
        "environment_name": workflow["github_environment"],
        "configuration_digest": environment_configuration_digest(identity),
    }
    if anchor.get("source") != "github-api" or any(
        anchor.get(key) != value for key, value in expected.items()
    ):
        raise GitHubDeploymentIdentityError("authorization denied")

    current = now.astimezone(UTC)
    captured_at = _parse_timestamp(anchor["captured_at"])
    expires_at = _parse_timestamp(anchor["expires_at"])
    lifetime = (expires_at - captured_at).total_seconds()
    if captured_at > current or current >= expires_at or not 0 < lifetime <= 600:
        raise GitHubDeploymentIdentityError("authorization denied")


def _validate_terminal_roles(
    identity: dict[str, Any], account_ready: dict[str, Any]
) -> None:
    terminal_roles = identity["terminal_roles"]
    account_roles = account_ready.get("roles", {})
    for role_name, expected_operation in ROLE_OPERATIONS.items():
        role = terminal_roles[role_name]
        account_role = account_roles.get(role_name)
        if not isinstance(account_role, dict) or role["role_arn"] != account_role.get(
            "arn"
        ):
            raise GitHubDeploymentIdentityError("terminal role binding mismatch")
        expected_account_role_tags = {
            "customer_id_tag": identity["customer_id"],
            "deployment_id_tag": identity["deployment_id"],
            "account_id_tag": identity["account_id"],
            "region_tag": identity["region"],
            "environment_tag": identity["environment"],
        }
        if any(
            account_role.get(key) != value
            for key, value in expected_account_role_tags.items()
        ):
            raise GitHubDeploymentIdentityError("ACCOUNT_READY role ownership mismatch")
        role_match = ROLE_ARN.fullmatch(role["role_arn"])
        if not role_match or role_match.group("account") != identity["account_id"]:
            raise GitHubDeploymentIdentityError("terminal role account mismatch")
        if role["operation"] != expected_operation:
            raise GitHubDeploymentIdentityError("terminal role operation mismatch")
        if role["max_session_duration_seconds"] != 900:
            raise GitHubDeploymentIdentityError("terminal session is too long")
        if frozenset(role["required_session_tags"]) != EXPECTED_SESSION_TAGS:
            raise GitHubDeploymentIdentityError("terminal session tags are incomplete")
        if role["source_identity_pattern"] != (
            "^exec_[0-9A-HJKMNP-TV-Z]{26}$"
        ):
            raise GitHubDeploymentIdentityError("terminal source identity is weak")
        layers = role["allowed_layers"]
        if layers != list(ROLE_LAYERS[role_name]):
            raise GitHubDeploymentIdentityError("terminal operation layer mismatch")
        expected_resource_tags = {
            "customer_id": identity["customer_id"],
            "deployment_id": identity["deployment_id"],
            "account_id": identity["account_id"],
            "region": identity["region"],
            "environment": identity["environment"],
        }
        if role["required_resource_tags"] != expected_resource_tags:
            raise GitHubDeploymentIdentityError("terminal role tags are not exact")
    for plan_role, apply_role in (
        ("plan", "apply"),
        ("identity_plan", "identity_apply"),
    ):
        if terminal_roles[plan_role]["allowed_layers"] != terminal_roles[apply_role][
            "allowed_layers"
        ]:
            raise GitHubDeploymentIdentityError("plan and apply layer binding mismatch")


def _validate_break_glass_access(
    identity: dict[str, Any], account_ready: dict[str, Any]
) -> None:
    expected = {
        "diagnostic_access": ("diagnostic", "diagnostic", False),
        "state_recovery_access": ("state_recovery", "state-recovery", True),
    }
    for field, (account_role_name, operation, requires_recovery) in expected.items():
        access = identity[field]
        expected_role = (
            account_ready.get("roles", {}).get(account_role_name, {}).get("arn")
        )
        principal = ROLE_ARN.fullmatch(access["principal"])
        if (
            access["role_arn"] != expected_role
            or access["operation"] != operation
            or access["human_only"] is not True
            or access["requires_mfa"] is not True
            or access["requires_incident_id"] is not True
            or access["max_session_duration_seconds"] != 900
            or bool(access.get("requires_recovery_approval", False))
            is not requires_recovery
            or not principal
            or principal.group("name") != "ScanalyzeBreakGlass"
            or "Orchestrator" in access["principal"]
        ):
            raise GitHubDeploymentIdentityError(
                "recovery access is not independently controlled"
            )


def _actions(statement: dict[str, Any]) -> list[str]:
    action = statement.get("Action", [])
    return [action] if isinstance(action, str) else list(action)


def _validate_terminal_trust(
    path: Path, operation: str, allowed_layers: tuple[str, ...]
) -> None:
    policy = load_json_strict(path)
    statements = policy.get("Statement")
    if not isinstance(statements, list) or len(statements) != 3:
        raise GitHubDeploymentIdentityError("terminal trust policy is incomplete")
    by_action: dict[str, dict[str, Any]] = {}
    for statement in statements:
        actions = _actions(statement)
        if len(actions) != 1 or actions[0] in by_action:
            raise GitHubDeploymentIdentityError("terminal trust actions are ambiguous")
        by_action[actions[0]] = statement
        principal = statement.get("Principal", {}).get("AWS")
        if principal != (
            "arn:aws:iam::${shared_services_account_id}:role/"
            "ScanalyzeOrchestrator-${deployment_id}"
        ):
            raise GitHubDeploymentIdentityError("terminal trust principal is not exact")
    if set(by_action) != {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }:
        raise GitHubDeploymentIdentityError("terminal trust actions are incomplete")
    assume = by_action["sts:AssumeRole"]["Condition"]
    equals = assume.get("StringEquals", {})
    allowed_layer_condition: object = (
        allowed_layers[0] if len(allowed_layers) == 1 else list(allowed_layers)
    )
    required_equals: dict[str, object] = {
        "customer_id": "${aws:ResourceTag/customer_id}",
        "deployment_id": "${aws:ResourceTag/deployment_id}",
        "account_id": "${aws:ResourceTag/account_id}",
        "region": "${aws:ResourceTag/region}",
        "environment": "${aws:ResourceTag/environment}",
        "operation": operation,
        "layer": allowed_layer_condition,
    }
    if any(
        equals.get(f"aws:RequestTag/{key}") != value
        for key, value in required_equals.items()
    ):
        raise GitHubDeploymentIdentityError("terminal trust binding is incomplete")
    if assume.get("StringLike", {}).get("sts:SourceIdentity") != "exec_*":
        raise GitHubDeploymentIdentityError("terminal trust source identity is weak")
    tag_conditions = by_action["sts:TagSession"]["Condition"]
    tag_equals = tag_conditions.get("StringEquals", {})
    if any(
        tag_equals.get(f"aws:RequestTag/{key}") != value
        for key, value in required_equals.items()
    ):
        raise GitHubDeploymentIdentityError("terminal tag-session binding is incomplete")
    if frozenset(
        tag_conditions.get("ForAllValues:StringEquals", {}).get("aws:TagKeys", [])
    ) != EXPECTED_SESSION_TAGS:
        raise GitHubDeploymentIdentityError("terminal trust tag allowlist is incomplete")
    nulls = tag_conditions.get("Null", {})
    if any(nulls.get(f"aws:RequestTag/{key}") != "false" for key in EXPECTED_SESSION_TAGS):
        raise GitHubDeploymentIdentityError("terminal trust does not require every tag")
    if nulls.get("aws:TagKeys") != "false":
        raise GitHubDeploymentIdentityError("terminal tag allowlist may match vacuously")
    source_conditions = by_action["sts:SetSourceIdentity"].get("Condition", {})
    if source_conditions != {"StringLike": {"sts:SourceIdentity": "exec_*"}}:
        raise GitHubDeploymentIdentityError("terminal source-identity trust is not exact")


def _validate_break_glass_trust(
    path: Path, operation: str, *, require_recovery_approval: bool
) -> None:
    policy = load_json_strict(path)
    statements = policy.get("Statement")
    if not isinstance(statements, list) or len(statements) != 3:
        raise GitHubDeploymentIdentityError("break-glass trust is incomplete")
    by_action = {action: statement for statement in statements for action in _actions(statement)}
    if len(by_action) != 3 or set(by_action) != {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }:
        raise GitHubDeploymentIdentityError("break-glass trust actions are not exact")
    principal = (
        "arn:aws:iam::${shared_services_account_id}:role/ScanalyzeBreakGlass"
    )
    if any(
        statement.get("Principal", {}).get("AWS") != principal
        for statement in by_action.values()
    ):
        raise GitHubDeploymentIdentityError("break-glass principal is not exact")

    ownership = {
        "customer_id": "${aws:ResourceTag/customer_id}",
        "deployment_id": "${aws:ResourceTag/deployment_id}",
        "account_id": "${aws:ResourceTag/account_id}",
        "region": "${aws:ResourceTag/region}",
        "environment": "${aws:ResourceTag/environment}",
    }
    required_tags = {
        *ownership,
        "operation",
        "incident_id",
        "operator_id",
    }
    if require_recovery_approval:
        required_tags.add("recovery_approved")
    for action in ("sts:AssumeRole", "sts:TagSession"):
        condition = by_action[action].get("Condition", {})
        equals = condition.get("StringEquals", {})
        expected_equals = {
            "aws:PrincipalTag/break_glass_approved": "true",
            "aws:PrincipalTag/mfa_authenticated": "true",
            **{
                f"aws:RequestTag/{key}": value
                for key, value in ownership.items()
            },
            "aws:RequestTag/operation": operation,
        }
        if require_recovery_approval:
            expected_equals["aws:RequestTag/recovery_approved"] = "true"
        if any(equals.get(key) != value for key, value in expected_equals.items()):
            raise GitHubDeploymentIdentityError("break-glass binding is incomplete")
        patterns = condition.get("StringLike", {})
        if (
            patterns.get("aws:RequestTag/incident_id") != "inc_*"
            or patterns.get("aws:RequestTag/operator_id") != "op_*"
        ):
            raise GitHubDeploymentIdentityError("break-glass evidence is incomplete")
        if action == "sts:AssumeRole" and patterns.get("sts:SourceIdentity") != "bg_*":
            raise GitHubDeploymentIdentityError("break-glass source identity is weak")
    tag_conditions = by_action["sts:TagSession"]["Condition"]
    if set(
        tag_conditions.get("ForAllValues:StringEquals", {}).get("aws:TagKeys", [])
    ) != required_tags:
        raise GitHubDeploymentIdentityError("break-glass tag allowlist is incomplete")
    if any(
        tag_conditions.get("Null", {}).get(f"aws:RequestTag/{key}") != "false"
        for key in required_tags
    ):
        raise GitHubDeploymentIdentityError("break-glass tags are not mandatory")
    if tag_conditions.get("Null", {}).get("aws:TagKeys") != "false":
        raise GitHubDeploymentIdentityError("break-glass tag allowlist may match vacuously")
    if by_action["sts:SetSourceIdentity"].get("Condition") != {
        "StringEquals": {
            "aws:PrincipalTag/break_glass_approved": "true",
            "aws:PrincipalTag/mfa_authenticated": "true",
        },
        "StringLike": {"sts:SourceIdentity": "bg_*"},
    }:
        raise GitHubDeploymentIdentityError("break-glass source trust is not exact")


def _validate_break_glass_policy(path: Path) -> None:
    policy = load_json_strict(path)
    statements = policy.get("Statement", [])
    allow_sts = {
        action: statement
        for statement in statements
        if statement.get("Effect") == "Allow"
        for action in _actions(statement)
        if action.startswith("sts:")
    }
    if set(allow_sts) != {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }:
        raise GitHubDeploymentIdentityError("break-glass policy actions are incomplete")
    for statement in allow_sts.values():
        resources = statement.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        if not resources or any(
            "::${aws:PrincipalTag/account_id}:role/ScanalyzeCustomer-" not in resource
            or ("Diagnostic" not in resource and "StateRecovery" not in resource)
            for resource in resources
        ):
            raise GitHubDeploymentIdentityError("break-glass role resources are too broad")
    for action in ("sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"):
        equals = allow_sts[action].get("Condition", {}).get("StringEquals", {})
        if (
            equals.get("aws:PrincipalTag/service") != "scanalyze-break-glass"
            or equals.get("aws:PrincipalTag/break_glass_approved") != "true"
            or equals.get("aws:PrincipalTag/mfa_authenticated") != "true"
        ):
            raise GitHubDeploymentIdentityError("break-glass principal is unbound")
    if (
        allow_sts["sts:TagSession"]
        .get("Condition", {})
        .get("Null", {})
        .get("aws:TagKeys")
        != "false"
    ):
        raise GitHubDeploymentIdentityError("break-glass tag allowlist may match vacuously")


def _validate_orchestrator_policy(path: Path) -> None:
    policy = load_json_strict(path)
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise GitHubDeploymentIdentityError("orchestrator policy is malformed")
    terminal: dict[str, dict[str, Any]] = {}
    for statement in statements:
        actions = _actions(statement)
        if len(actions) != 1 or actions[0] not in {
            "sts:AssumeRole",
            "sts:TagSession",
            "sts:SetSourceIdentity",
        }:
            continue
        action = actions[0]
        if action in terminal:
            raise GitHubDeploymentIdentityError("orchestrator STS actions are ambiguous")
        terminal[action] = statement
        resources = statement.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        if not resources or any(
            "::${aws:PrincipalTag/account_id}:role/ScanalyzeCustomer-" not in resource
            or "::*:" in resource
            or "Diagnostic" in resource
            or "StateRecovery" in resource
            for resource in resources
        ):
            raise GitHubDeploymentIdentityError("orchestrator role resources are too broad")
    if set(terminal) != {
        "sts:AssumeRole",
        "sts:TagSession",
        "sts:SetSourceIdentity",
    }:
        raise GitHubDeploymentIdentityError("orchestrator STS actions are incomplete")

    expected_bindings = {
        "customer_id": "${aws:PrincipalTag/customer_id}",
        "deployment_id": "${aws:PrincipalTag/deployment_id}",
        "account_id": "${aws:PrincipalTag/account_id}",
        "region": "${aws:PrincipalTag/region}",
        "environment": "${aws:PrincipalTag/environment}",
    }
    for action in ("sts:AssumeRole", "sts:TagSession"):
        conditions = terminal[action].get("Condition", {})
        equals = conditions.get("StringEquals", {})
        if equals.get("aws:PrincipalTag/service") != "scanalyze-orchestrator" or any(
            equals.get(f"aws:RequestTag/{key}") != value
            for key, value in expected_bindings.items()
        ):
            raise GitHubDeploymentIdentityError("orchestrator principal binding is incomplete")
        patterns = conditions.get("StringLike", {})
        if (
            set(patterns.get("aws:RequestTag/operation", []))
            != set(ROLE_OPERATIONS.values())
            or set(patterns.get("aws:RequestTag/layer", []))
            != set(TERRAFORM_LAYERS)
            | {"artifact-publication", "synthetic-validation"}
            or patterns.get("aws:RequestTag/change_id") != "chg_*"
        ):
            raise GitHubDeploymentIdentityError("orchestrator operation binding is incomplete")
    tag_conditions = terminal["sts:TagSession"].get("Condition", {})
    if frozenset(
        tag_conditions.get("ForAllValues:StringEquals", {}).get("aws:TagKeys", [])
    ) != EXPECTED_SESSION_TAGS:
        raise GitHubDeploymentIdentityError("orchestrator tag allowlist is incomplete")
    nulls = tag_conditions.get("Null", {})
    if any(
        nulls.get(f"aws:RequestTag/{key}") != "false"
        for key in EXPECTED_SESSION_TAGS
    ) or nulls.get("aws:TagKeys") != "false":
        raise GitHubDeploymentIdentityError("orchestrator tags are not mandatory")
    source_conditions = terminal["sts:SetSourceIdentity"].get("Condition", {})
    if source_conditions != {
        "StringEquals": {
            "aws:PrincipalTag/service": "scanalyze-orchestrator"
        },
        "StringLike": {"sts:SourceIdentity": "exec_*"},
    }:
        raise GitHubDeploymentIdentityError("orchestrator source identity is not exact")


def validate_repository_controls(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Validate repository-owned trust and offline/live workflow separation."""
    trust_dir = repo_root / "policies/trust"
    oidc_trust = load_json_strict(trust_dir / "github-oidc-orchestrator-trust.json")
    statements = oidc_trust.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        raise GitHubDeploymentIdentityError("GitHub OIDC trust is ambiguous")
    statement = statements[0]
    if _actions(statement) != ["sts:AssumeRoleWithWebIdentity"]:
        raise GitHubDeploymentIdentityError("GitHub OIDC action is invalid")
    if statement.get("Principal") != {
        "Federated": (
            "arn:aws:iam::${shared_services_account_id}:"
            "oidc-provider/token.actions.githubusercontent.com"
        )
    }:
        raise GitHubDeploymentIdentityError("GitHub OIDC principal is not exact")
    conditions = statement.get("Condition", {})
    if set(conditions) != {"StringEquals"}:
        raise GitHubDeploymentIdentityError("GitHub OIDC trust must use exact equality")
    if conditions["StringEquals"] != {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "${github_oidc_subject}",
    }:
        raise GitHubDeploymentIdentityError("GitHub OIDC trust is not exact")

    for role_name, operation in ROLE_OPERATIONS.items():
        trust_name = role_name.replace("_", "-")
        _validate_terminal_trust(
            trust_dir / f"{trust_name}-trust.json",
            operation,
            ROLE_LAYERS[role_name],
        )
    _validate_orchestrator_policy(repo_root / "policies/iam/orchestrator-role.json")

    _validate_break_glass_trust(
        trust_dir / "diagnostic-trust.json",
        "diagnostic",
        require_recovery_approval=False,
    )
    _validate_break_glass_trust(
        trust_dir / "state-recovery-trust.json",
        "state-recovery",
        require_recovery_approval=True,
    )
    _validate_break_glass_policy(repo_root / "policies/iam/break-glass-role.json")

    privileged_workflows = sorted(
        path.relative_to(repo_root).as_posix()
        for path in (repo_root / ".github/workflows").glob("*.yml")
        if any(
            marker in path.read_text(encoding="utf-8")
            for marker in (
                "id-token: write",
                "aws-actions/configure-aws-credentials",
            )
        )
    )
    if privileged_workflows:
        raise GitHubDeploymentIdentityError(
            "repository workflow can bypass deployment authorization"
        )
    return {
        "trust_policies": sorted(ROLE_OPERATIONS),
        "dry_run_oidc": False,
        "privileged_workflows": [],
        "orchestrator_actions": [
            "sts:AssumeRole",
            "sts:TagSession",
            "sts:SetSourceIdentity",
        ],
        "break_glass_actions": [
            "sts:AssumeRole",
            "sts:TagSession",
            "sts:SetSourceIdentity",
        ],
    }


def authorize_github_deployment_identity(
    *,
    identity: dict[str, Any],
    deployment_target: dict[str, Any],
    target_anchor: dict[str, Any],
    account_ready: dict[str, Any],
    environment_anchor: dict[str, Any],
    platform_authority: dict[str, Any],
    platform_authority_anchor: dict[str, Any],
    schema_path: Path = DEFAULT_SCHEMA,
    environment_anchor_schema_path: Path = DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA,
    platform_authority_schema_path: Path = DEFAULT_PLATFORM_AUTHORITY_SCHEMA,
    trust_dir: Path = DEFAULT_TRUST_DIR,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a minimal decision only after every identity boundary is proven."""
    try:
        _validate_schema(identity, schema_path)
        _digest_matches(identity, "contract_digest")
        _exact_registry_binding(
            identity,
            deployment_target,
            target_anchor,
            account_ready,
        )
        _exact_platform_authority(
            identity,
            platform_authority,
            platform_authority_anchor,
            schema_path=platform_authority_schema_path,
        )
        _validate_workflow_and_oidc(identity)
        _validate_environment(identity)
        _validate_environment_anchor(
            identity,
            environment_anchor,
            schema_path=environment_anchor_schema_path,
            now=datetime.now(UTC) if now is None else now,
        )
        _validate_terminal_roles(identity, account_ready)
        _validate_break_glass_access(identity, account_ready)
        for role_name, operation in ROLE_OPERATIONS.items():
            trust_name = role_name.replace("_", "-")
            _validate_terminal_trust(
                trust_dir / f"{trust_name}-trust.json",
                operation,
                ROLE_LAYERS[role_name],
            )
    except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise GitHubDeploymentIdentityError("authorization denied") from exc
    return {
        "authorized": True,
        "customer_id": identity["customer_id"],
        "deployment_id": identity["deployment_id"],
        "account_id": identity["account_id"],
        "region": identity["region"],
        "environment": identity["environment"],
        "github_environment": identity["workflow"]["github_environment"],
        "oidc_subject": identity["oidc"]["subject"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-controls-only", action="store_true")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--deployment-target", type=Path)
    parser.add_argument("--target-anchor", type=Path)
    parser.add_argument("--account-ready", type=Path)
    parser.add_argument("--environment-anchor", type=Path)
    parser.add_argument("--platform-authority", type=Path)
    parser.add_argument("--platform-authority-anchor", type=Path)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument(
        "--environment-anchor-schema",
        type=Path,
        default=DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA,
    )
    parser.add_argument(
        "--platform-authority-schema",
        type=Path,
        default=DEFAULT_PLATFORM_AUTHORITY_SCHEMA,
    )
    parser.add_argument("--trust-dir", type=Path, default=DEFAULT_TRUST_DIR)
    parser.add_argument("--expected-customer-id")
    parser.add_argument("--expected-deployment-id")
    parser.add_argument("--expected-account-id")
    parser.add_argument("--expected-region")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.repository_controls_only:
            validate_repository_controls(REPO_ROOT)
            print("PASS: repository GitHub OIDC and terminal IAM controls validated")
            return 0
        required = (
            args.identity,
            args.deployment_target,
            args.target_anchor,
            args.account_ready,
            args.environment_anchor,
            args.platform_authority,
            args.platform_authority_anchor,
            args.expected_customer_id,
            args.expected_deployment_id,
            args.expected_account_id,
            args.expected_region,
        )
        if any(value is None for value in required):
            parser.error(
                "identity authorization requires all contract paths and expected bindings"
            )
        decision = authorize_github_deployment_identity(
            identity=load_json_strict(args.identity),
            deployment_target=load_json_strict(args.deployment_target),
            target_anchor=load_json_strict(args.target_anchor),
            account_ready=load_json_strict(args.account_ready),
            environment_anchor=load_json_strict(args.environment_anchor),
            platform_authority=load_json_strict(args.platform_authority),
            platform_authority_anchor=load_json_strict(
                args.platform_authority_anchor
            ),
            schema_path=args.schema,
            environment_anchor_schema_path=args.environment_anchor_schema,
            platform_authority_schema_path=args.platform_authority_schema,
            trust_dir=args.trust_dir,
        )
        assertions = {
            "customer_id": args.expected_customer_id,
            "deployment_id": args.expected_deployment_id,
            "account_id": args.expected_account_id,
            "region": args.expected_region,
        }
        if any(decision[key] != value for key, value in assertions.items()):
            raise GitHubDeploymentIdentityError("request assertion mismatch")
    except GitHubDeploymentIdentityError:
        print("DENY: GitHub deployment identity authorization failed", file=sys.stderr)
        return 2
    print("PASS: GitHub deployment identity and terminal roles authorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
