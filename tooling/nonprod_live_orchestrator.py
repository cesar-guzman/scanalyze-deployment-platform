"""Pure protected orchestration decisions for one live non-production plan.

This module deliberately performs no filesystem, subprocess, network, GitHub,
Terraform, or AWS I/O.  It turns independently retrieved records into exact
command specifications and compare-and-swap (CAS) transitions.  Runtime
adapters remain responsible for private-file custody, identity readback, and
committing the returned CAS before executing a command.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any, Mapping

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_engine import (
    LEDGER_BINDING_FIELDS,
    PLAN_BINDING_FIELDS,
    TERRAFORM_LAYERS,
    authorize_saved_plan_apply,
    derive_approval_authority_digest,
    prepare_ledger_transition,
    require_terminal_role_for_layer,
)


DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
ACCOUNT_ID = re.compile(r"^(?!000000000000$)[0-9]{12}$")
CUSTOMER_ID = re.compile(r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
DEPLOYMENT_ID = re.compile(r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
EXECUTION_ID = re.compile(r"^exec_[0-9A-HJKMNP-TV-Z]{26}$")
CHANGE_ID = re.compile(r"^chg_[0-9A-HJKMNP-TV-Z]{26}$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-[0-9]+$")
WORKFLOW_REF = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
    r"\.github/workflows/nonprod-release\.yml@refs/heads/main$"
)
DOMAIN_NAME = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
RELEASE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LIVE_NONPRODUCTION_ENVIRONMENTS = frozenset({"dev", "staging"})

CONTEXT_BODY_FIELDS = (
    "event_name",
    "git_ref",
    "workflow_ref",
    "workflow_sha",
    "main_sha",
    "repository_owner_id",
    "repository_id",
    "workflow_run_id",
    "workflow_run_attempt",
    "initiator_user_id",
    "customer_id",
    "deployment_id",
    "execution_id",
    "change_id",
    "destination_account_id",
    "platform_authority_account_id",
    "region",
    "environment",
    "github_environment",
    "layer",
    "release_digest",
    "source_revision_digest",
    "github_deployment_identity_digest",
    "environment_configuration_digest",
    "github_environment_anchor_digest",
    "expected_approver_user_id",
    "approval_authority_digest",
    "platform_authority_digest",
    "registry_record_digest",
    "account_ready_digest",
    "orchestrator_role_arn",
    "plan_role_arn",
    "apply_role_arn",
    "oidc_audience",
    "control_plane_session_duration_seconds",
    "terminal_session_duration_seconds",
)
CONTEXT_FIELDS = frozenset(
    (
        "schema_version",
        "record_type",
        "authorized",
        "code",
        *CONTEXT_BODY_FIELDS,
        "context_digest",
    )
)
PLAN_INPUT_FIELDS = frozenset(
    {
        "plan_dir",
        "resolved_input",
        "manifest",
        "target_record",
        "target_anchor",
        "account_ready",
        "execution_lock",
    }
)
APPLY_INPUT_FIELDS = frozenset(
    {
        "apply_intent",
        "context",
        "approved_ledger",
        "applying_ledger",
        "plan_record",
        "approval_record",
        "plan_readback",
        "state_readback",
        "manifest",
        "target_record",
        "target_anchor",
        "account_ready",
        "execution_lock",
    }
)


def derive_source_revision_digest(workflow_sha: str) -> str:
    """Bind the saved-plan source claim to one exact Git commit SHA."""
    if not isinstance(workflow_sha, str) or not GIT_SHA.fullmatch(workflow_sha):
        raise AuthorizationError("workflow source SHA is invalid")
    return canonical_digest({"source_revision": workflow_sha})


def _require_digest(value: object, label: str) -> None:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise AuthorizationError(f"{label} digest is invalid")


def _require_positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AuthorizationError(f"{label} is invalid")


def require_live_nonproduction_environment(value: object) -> str:
    """Return an exact live non-production environment or fail closed."""
    if (
        not isinstance(value, str)
        or value not in LIVE_NONPRODUCTION_ENVIRONMENTS
    ):
        raise AuthorizationError("live orchestration is limited to dev or staging")
    return value


def _terminal_role_arn(account_id: str, layer: str, operation: str) -> str:
    role_suffix = "Plan" if operation == "plan" else "Apply"
    role_name = (
        f"ScanalyzeCustomer-Identity-{role_suffix}"
        if layer == "identity-control-plane"
        else f"ScanalyzeCustomer-{role_suffix}"
    )
    require_terminal_role_for_layer(
        layer=layer,
        operation=operation,
        role=role_name,
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _validate_context_body(context: Mapping[str, Any]) -> None:
    if context.get("event_name") != "workflow_dispatch":
        raise AuthorizationError("live orchestration requires workflow_dispatch")
    if context.get("git_ref") != "refs/heads/main":
        raise AuthorizationError("live orchestration requires the main branch")
    workflow_ref = context.get("workflow_ref")
    if not isinstance(workflow_ref, str) or not WORKFLOW_REF.fullmatch(workflow_ref):
        raise AuthorizationError("live orchestration workflow ref is invalid")
    workflow_sha = context.get("workflow_sha")
    main_sha = context.get("main_sha")
    if (
        not isinstance(workflow_sha, str)
        or not GIT_SHA.fullmatch(workflow_sha)
        or workflow_sha != main_sha
    ):
        raise AuthorizationError("workflow SHA is not the exact current main SHA")

    for field in (
        "repository_owner_id",
        "repository_id",
        "workflow_run_id",
        "workflow_run_attempt",
        "initiator_user_id",
        "expected_approver_user_id",
    ):
        _require_positive_integer(context.get(field), field)
    if context.get("workflow_run_attempt") != 1:
        raise AuthorizationError("live orchestration requires workflow run attempt 1")

    identifiers = {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
    }
    for field, pattern in identifiers.items():
        value = context.get(field)
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise AuthorizationError(f"live orchestration {field} is invalid")

    destination = context.get("destination_account_id")
    authority = context.get("platform_authority_account_id")
    if (
        not isinstance(destination, str)
        or not ACCOUNT_ID.fullmatch(destination)
        or not isinstance(authority, str)
        or not ACCOUNT_ID.fullmatch(authority)
    ):
        raise AuthorizationError("live orchestration account binding is invalid")
    if destination == authority:
        raise AuthorizationError(
            "platform authority must be separate from the destination account"
        )

    region = context.get("region")
    if not isinstance(region, str) or not REGION.fullmatch(region):
        raise AuthorizationError("live orchestration region is invalid")
    environment = require_live_nonproduction_environment(
        context.get("environment")
    )
    expected_environment = f"scanalyze-{context['deployment_id']}-{environment}"
    if context.get("github_environment") != expected_environment:
        raise AuthorizationError("GitHub Environment is not deployment-bound")

    layer = context.get("layer")
    if layer not in TERRAFORM_LAYERS:
        raise AuthorizationError("live orchestration layer is not canonical")

    for field in (
        "release_digest",
        "source_revision_digest",
        "github_deployment_identity_digest",
        "environment_configuration_digest",
        "github_environment_anchor_digest",
        "approval_authority_digest",
        "platform_authority_digest",
        "registry_record_digest",
        "account_ready_digest",
    ):
        _require_digest(context.get(field), field)
    if context.get("approval_authority_digest") != derive_approval_authority_digest(
        github_environment=context["github_environment"],
        expected_approver_user_id=context["expected_approver_user_id"],
        github_deployment_identity_digest=context[
            "github_deployment_identity_digest"
        ],
        environment_configuration_digest=context[
            "environment_configuration_digest"
        ],
    ):
        raise AuthorizationError("approval authority is not sealed to the reviewer")
    if context.get("source_revision_digest") != derive_source_revision_digest(
        workflow_sha
    ):
        raise AuthorizationError("source revision digest is not bound to workflow SHA")

    expected_orchestrator = (
        f"arn:aws:iam::{authority}:role/"
        f"ScanalyzeOrchestrator-{context['deployment_id']}"
    )
    if context.get("orchestrator_role_arn") != expected_orchestrator:
        raise AuthorizationError("orchestrator role is not deployment-bound")
    if context.get("plan_role_arn") != _terminal_role_arn(
        destination, layer, "plan"
    ):
        raise AuthorizationError("Plan terminal role binding is invalid")
    if context.get("apply_role_arn") != _terminal_role_arn(
        destination, layer, "apply"
    ):
        raise AuthorizationError("Apply terminal role binding is invalid")
    if context.get("oidc_audience") != "sts.amazonaws.com":
        raise AuthorizationError("OIDC audience is invalid")
    if context.get("control_plane_session_duration_seconds") != 3600:
        raise AuthorizationError(
            "control-plane session duration must be exactly 3600 seconds"
        )
    if context.get("terminal_session_duration_seconds") != 3600:
        raise AuthorizationError(
            "terminal session duration must be exactly 3600 seconds"
        )


def _validate_live_context(context: Mapping[str, Any]) -> None:
    if set(context) != CONTEXT_FIELDS:
        raise AuthorizationError("live orchestration context is incomplete")
    if (
        context.get("schema_version") != "1"
        or context.get("record_type") != "nonprod_live_context"
        or context.get("authorized") is not True
        or context.get("code") != "LIVE_CONTEXT_AUTHORIZED"
    ):
        raise AuthorizationError("live orchestration context is invalid")
    _validate_context_body(context)
    expected = canonical_digest(
        {key: value for key, value in context.items() if key != "context_digest"}
    )
    if context.get("context_digest") != expected:
        raise AuthorizationError("live orchestration context digest mismatch")


def build_live_context(
    *,
    event_name: str,
    git_ref: str,
    workflow_ref: str,
    workflow_sha: str,
    main_sha: str,
    repository_owner_id: int,
    repository_id: int,
    workflow_run_id: int,
    workflow_run_attempt: int,
    initiator_user_id: int,
    customer_id: str,
    deployment_id: str,
    execution_id: str,
    change_id: str,
    destination_account_id: str,
    platform_authority_account_id: str,
    region: str,
    environment: str,
    github_environment: str,
    layer: str,
    release_digest: str,
    source_revision_digest: str,
    github_deployment_identity_digest: str,
    environment_configuration_digest: str,
    github_environment_anchor_digest: str,
    expected_approver_user_id: int,
    approval_authority_digest: str,
    platform_authority_digest: str,
    registry_record_digest: str,
    account_ready_digest: str,
    orchestrator_role_arn: str,
    plan_role_arn: str,
    apply_role_arn: str,
    oidc_audience: str,
    control_plane_session_duration_seconds: int,
    terminal_session_duration_seconds: int,
) -> dict[str, Any]:
    """Authorize one exact, protected, deployment-bound live context."""
    context: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_context",
        "authorized": True,
        "code": "LIVE_CONTEXT_AUTHORIZED",
        **{field: value for field, value in locals().items() if field != "context"},
    }
    _validate_context_body(context)
    context["context_digest"] = canonical_digest(context)
    _validate_live_context(context)
    return context


def _validate_expected_bindings(
    context: Mapping[str, Any], expected_bindings: Mapping[str, Any]
) -> None:
    if set(expected_bindings) != set(PLAN_BINDING_FIELDS):
        raise AuthorizationError("saved-plan expected bindings are incomplete")
    exact = {
        "customer_id": context["customer_id"],
        "deployment_id": context["deployment_id"],
        "account_id": context["destination_account_id"],
        "region": context["region"],
        "environment": context["environment"],
        "execution_id": context["execution_id"],
        "change_id": context["change_id"],
        "layer": context["layer"],
        "release_digest": context["release_digest"],
        "github_environment": context["github_environment"],
        "github_deployment_identity_digest": context[
            "github_deployment_identity_digest"
        ],
        "environment_configuration_digest": context[
            "environment_configuration_digest"
        ],
        "expected_approver_user_id": context["expected_approver_user_id"],
        "approval_authority_digest": context["approval_authority_digest"],
        "platform_authority_digest": context["platform_authority_digest"],
        "registry_record_digest": context["registry_record_digest"],
        "account_ready_digest": context["account_ready_digest"],
        "source_revision_digest": context["source_revision_digest"],
    }
    for field, expected in exact.items():
        if expected_bindings.get(field) != expected:
            raise AuthorizationError(f"saved-plan context binding mismatch: {field}")
    for field in PLAN_BINDING_FIELDS:
        if field.endswith("_digest"):
            _require_digest(expected_bindings.get(field), field)
    release_version = expected_bindings.get("release_version")
    if not isinstance(release_version, str) or not RELEASE_VERSION.fullmatch(
        release_version
    ):
        raise AuthorizationError("saved-plan release version is invalid")
    state_status = expected_bindings.get("state_status")
    state_lineage = expected_bindings.get("state_lineage")
    state_serial = expected_bindings.get("state_serial")
    if state_status == "PRESENT":
        if (
            not isinstance(state_lineage, str)
            or not re.fullmatch(
                r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$", state_lineage
            )
        ):
            raise AuthorizationError("saved-plan present state lineage is invalid")
        if (
            isinstance(state_serial, bool)
            or not isinstance(state_serial, int)
            or state_serial < 0
        ):
            raise AuthorizationError("saved-plan present state serial is invalid")
    elif state_status == "ABSENT":
        if state_lineage is not None or state_serial is not None:
            raise AuthorizationError("saved-plan absent state binding is invalid")
    else:
        raise AuthorizationError("saved-plan state status is invalid")


def _absolute_path(value: object, label: str, *, directory: bool = False) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\x00\r\n"):
        raise AuthorizationError(f"{label} path is invalid")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or (directory and path == PurePosixPath("/")):
        raise AuthorizationError(f"{label} path must be an exact absolute path")
    return str(path)


def _validated_paths(
    supplied: Mapping[str, Any], required: frozenset[str], label: str
) -> dict[str, str]:
    if set(supplied) != set(required):
        raise AuthorizationError(f"{label} operational paths are incomplete")
    return {
        key: _absolute_path(value, f"{label} {key}", directory=key == "plan_dir")
        for key, value in supplied.items()
    }


def build_plan_intent(
    *,
    context: Mapping[str, Any],
    expected_bindings: Mapping[str, Any],
    plan_inputs: Mapping[str, Any],
    domain_name: str | None = None,
) -> dict[str, Any]:
    """Build the complete existing plan-wrapper command; never execute it."""
    _validate_live_context(context)
    _validate_expected_bindings(context, expected_bindings)
    paths = _validated_paths(plan_inputs, PLAN_INPUT_FIELDS, "plan")
    if domain_name is not None and not DOMAIN_NAME.fullmatch(domain_name):
        raise AuthorizationError("plan domain name is invalid")
    expected_role = _terminal_role_arn(
        context["destination_account_id"], context["layer"], "plan"
    )
    if context["plan_role_arn"] != expected_role:
        raise AuthorizationError("Plan terminal role binding is invalid")
    expected_plan_path = str(
        PurePosixPath(paths["plan_dir"]) / f"{context['layer']}.tfplan"
    )

    argv = [
        "plan",
        "--layer",
        context["layer"],
        "--plan-out",
        expected_plan_path,
        "--customer-id",
        context["customer_id"],
        "--deployment-id",
        context["deployment_id"],
        "--account-id",
        context["destination_account_id"],
        "--region",
        context["region"],
        "--environment",
        context["environment"],
        "--expected-role-arn",
        expected_role,
        "--expected-source-sha",
        context["workflow_sha"],
    ]
    if domain_name is not None:
        argv.extend(("--domain-name", domain_name))
    argv.extend(
        (
            "--release-version",
            expected_bindings["release_version"],
            "--release-digest",
            context["release_digest"],
            "--resolved-input",
            paths["resolved_input"],
            "--manifest",
            paths["manifest"],
            "--target-record",
            paths["target_record"],
            "--target-anchor",
            paths["target_anchor"],
            "--account-ready",
            paths["account_ready"],
            "--execution-lock",
            paths["execution_lock"],
            "--execution-id",
            context["execution_id"],
        )
    )
    intent: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_plan_intent",
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_REQUIRED",
        "context_digest": context["context_digest"],
        "workflow_run_attempt": context["workflow_run_attempt"],
        "binding_digest": canonical_digest(dict(expected_bindings)),
        "expected_terminal_role_arn": expected_role,
        "expected_source_sha": context["workflow_sha"],
        "expected_plan_path": expected_plan_path,
        "expected_object_key": (
            f"plan-execution/{context['deployment_id']}/{context['change_id']}/"
            f"{context['layer']}/plan.tfplan"
        ),
        "operational_paths": paths,
        "domain_name": domain_name,
        "storage_mode": "CREATE_ONLY_KMS_VERSIONED",
        "ledger_create_mode": "CREATE_ONLY_PLANNED",
        "command": {
            "program": "scripts/deployment/terraform-saved-plan.sh",
            "argv": argv,
        },
        "replan_allowed": False,
        "retry_allowed": False,
    }
    intent["intent_digest"] = canonical_digest(intent)
    return intent


def validate_plan_intent(
    *,
    intent: Mapping[str, Any],
    context: Mapping[str, Any],
    expected_bindings: Mapping[str, Any],
) -> dict[str, Any]:
    """Rebuild and compare a plan intent before terminal-role execution."""
    _validate_live_context(context)
    claimed = intent.get("intent_digest")
    expected_digest = canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )
    if claimed != expected_digest:
        raise AuthorizationError("saved-plan plan intent digest mismatch")
    paths = intent.get("operational_paths")
    domain_name = intent.get("domain_name")
    if not isinstance(paths, dict) or (
        domain_name is not None and not isinstance(domain_name, str)
    ):
        raise AuthorizationError("saved-plan plan intent inputs are invalid")
    expected = build_plan_intent(
        context=context,
        expected_bindings=expected_bindings,
        plan_inputs=paths,
        domain_name=domain_name,
    )
    if dict(intent) != expected:
        raise AuthorizationError("saved-plan plan intent binding mismatch")
    return {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_PLAN_INTENT_VALIDATED",
        "intent_digest": claimed,
        "context_digest": context["context_digest"],
        "binding_digest": expected["binding_digest"],
    }


def _apply_command(
    *,
    context: Mapping[str, Any],
    plan_binary_path: str,
    paths: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "program": "scripts/deployment/terraform-saved-plan.sh",
        "argv": [
            "apply",
            "--layer",
            context["layer"],
            "--plan",
            plan_binary_path,
            "--apply-intent",
            paths["apply_intent"],
            "--context",
            paths["context"],
            "--approved-ledger",
            paths["approved_ledger"],
            "--applying-ledger",
            paths["applying_ledger"],
            "--plan-record",
            paths["plan_record"],
            "--approval-record",
            paths["approval_record"],
            "--plan-readback",
            paths["plan_readback"],
            "--state-readback",
            paths["state_readback"],
            "--manifest",
            paths["manifest"],
            "--target-record",
            paths["target_record"],
            "--target-anchor",
            paths["target_anchor"],
            "--account-ready",
            paths["account_ready"],
            "--execution-lock",
            paths["execution_lock"],
            "--customer-id",
            context["customer_id"],
            "--deployment-id",
            context["deployment_id"],
            "--execution-id",
            context["execution_id"],
            "--expected-account-id",
            context["destination_account_id"],
            "--region",
            context["region"],
            "--expected-role",
            context["apply_role_arn"],
            "--expected-source-sha",
            context["workflow_sha"],
        ],
    }


def _validate_approval_run_binding(
    context: Mapping[str, Any], approval_record: Mapping[str, Any]
) -> None:
    expected = {
        "repository_owner_id": context["repository_owner_id"],
        "repository_id": context["repository_id"],
        "workflow_ref": context["workflow_ref"],
        "workflow_sha": context["workflow_sha"],
        "workflow_run_id": context["workflow_run_id"],
        "workflow_run_attempt": context["workflow_run_attempt"],
        "github_environment": context["github_environment"],
        "environment_configuration_digest": context[
            "environment_configuration_digest"
        ],
        "initiator_user_id": context["initiator_user_id"],
        "expected_approver_user_id": context["expected_approver_user_id"],
        "apply_environment_anchor_digest": context[
            "github_environment_anchor_digest"
        ],
        "approval_authority_digest": context["approval_authority_digest"],
    }
    if any(approval_record.get(field) != value for field, value in expected.items()):
        raise AuthorizationError("saved-plan approval is not bound to the current run")
    if approval_record.get("approver_user_id") == context["initiator_user_id"]:
        raise AuthorizationError("saved-plan approval requires an independent reviewer")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise AuthorizationError("orchestration time must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_apply_intent(
    *,
    context: Mapping[str, Any],
    plan_record: Mapping[str, Any],
    ledger: Mapping[str, Any],
    approval_record: Mapping[str, Any],
    expected_bindings: Mapping[str, Any],
    plan_readback: Mapping[str, Any],
    state_readback: Mapping[str, Any],
    plan_binary_path: str,
    apply_inputs: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Authorize and describe the only allowed CAS-before-apply sequence."""
    _validate_live_context(context)
    _validate_expected_bindings(context, expected_bindings)
    _validate_approval_run_binding(context, approval_record)
    plan_path = _absolute_path(plan_binary_path, "saved plan")
    if PurePosixPath(plan_path).suffix != ".tfplan":
        raise AuthorizationError("saved plan path is invalid")
    paths = _validated_paths(apply_inputs, APPLY_INPUT_FIELDS, "apply")
    decision = authorize_saved_plan_apply(
        plan_record=plan_record,
        ledger=ledger,
        approval_record=approval_record,
        expected_bindings=expected_bindings,
        plan_readback=plan_readback,
        state_readback=state_readback,
        now=now,
    )
    applying, condition = prepare_ledger_transition(
        current=ledger,
        next_status="APPLYING",
        expected_version=ledger["ledger_version"],
        expected_digest=ledger["ledger_digest"],
        at=now,
    )
    command = _apply_command(
        context=context,
        plan_binary_path=plan_path,
        paths=paths,
    )
    intent: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_apply_intent",
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_APPLY_AUTHORIZED",
        "authorized_at": _timestamp(now),
        "context_digest": context["context_digest"],
        "workflow_run_attempt": context["workflow_run_attempt"],
        "plan_record_digest": plan_record["record_digest"],
        "approval_digest": approval_record["approval_digest"],
        "approved_ledger_digest": ledger["ledger_digest"],
        "approved_ledger_version": ledger["ledger_version"],
        "expected_bindings": dict(expected_bindings),
        "plan_readback": dict(plan_readback),
        "state_readback": dict(state_readback),
        "authorization_decision": decision,
        "proposed_ledger": applying,
        "proposed_ledger_digest": applying["ledger_digest"],
        "proposed_ledger_version": applying["ledger_version"],
        "proposed_ledger_status": "APPLYING",
        "cas_condition": condition,
        "expected_terminal_role_arn": context["apply_role_arn"],
        "expected_source_sha": context["workflow_sha"],
        "operational_paths": {"plan": plan_path, **paths},
        "command": command,
        "required_sequence": [
            "COMMIT_APPLYING_CAS",
            "READ_BACK_APPLYING_LEDGER",
            "VALIDATE_APPLY_INTENT",
            "EXECUTE_EXACT_SAVED_PLAN_ONCE",
            "COMMIT_OUTCOME_CAS",
        ],
        "replan_allowed": False,
        "retry_allowed": False,
    }
    intent["intent_digest"] = canonical_digest(intent)
    return intent


def validate_apply_intent(
    *,
    intent: Mapping[str, Any],
    context: Mapping[str, Any],
    plan_record: Mapping[str, Any],
    approval_record: Mapping[str, Any],
    approved_ledger: Mapping[str, Any],
    applying_ledger: Mapping[str, Any],
    plan_readback: Mapping[str, Any],
    state_readback: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Revalidate an intent after the ``APPLYING`` CAS readback."""
    _validate_live_context(context)
    claimed = intent.get("intent_digest")
    expected_digest = canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )
    if claimed != expected_digest:
        raise AuthorizationError("saved-plan apply intent digest mismatch")
    if (
        intent.get("schema_version") != "1"
        or intent.get("record_type") != "nonprod_live_apply_intent"
        or intent.get("allowed") is not True
        or intent.get("code") != "EXACT_SAVED_PLAN_APPLY_AUTHORIZED"
        or intent.get("context_digest") != context["context_digest"]
        or intent.get("workflow_run_attempt") != context["workflow_run_attempt"]
        or intent.get("plan_record_digest") != plan_record.get("record_digest")
        or intent.get("approval_digest") != approval_record.get("approval_digest")
        or intent.get("approved_ledger_digest") != approved_ledger.get("ledger_digest")
        or intent.get("approved_ledger_version") != approved_ledger.get("ledger_version")
    ):
        raise AuthorizationError("saved-plan apply intent binding mismatch")
    if intent.get("plan_readback") != dict(plan_readback) or intent.get(
        "state_readback"
    ) != dict(state_readback):
        raise AuthorizationError("saved-plan apply intent readback mismatch")
    _validate_approval_run_binding(context, approval_record)
    expected_bindings = intent.get("expected_bindings")
    if not isinstance(expected_bindings, dict):
        raise AuthorizationError("saved-plan apply intent bindings are invalid")
    _validate_expected_bindings(context, expected_bindings)
    decision = authorize_saved_plan_apply(
        plan_record=plan_record,
        ledger=approved_ledger,
        approval_record=approval_record,
        expected_bindings=expected_bindings,
        plan_readback=plan_readback,
        state_readback=state_readback,
        now=now,
    )
    authorized_at = intent.get("authorized_at")
    if not isinstance(authorized_at, str):
        raise AuthorizationError("saved-plan apply intent time is invalid")
    try:
        transition_at = datetime.fromisoformat(authorized_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError("saved-plan apply intent time is invalid") from exc
    proposed, condition = prepare_ledger_transition(
        current=approved_ledger,
        next_status="APPLYING",
        expected_version=approved_ledger["ledger_version"],
        expected_digest=approved_ledger["ledger_digest"],
        at=transition_at,
    )
    if (
        intent.get("proposed_ledger") != proposed
        or intent.get("proposed_ledger_digest") != proposed["ledger_digest"]
        or intent.get("proposed_ledger_version") != proposed["ledger_version"]
        or intent.get("proposed_ledger_status") != "APPLYING"
        or intent.get("cas_condition") != condition
        or dict(applying_ledger) != proposed
    ):
        raise AuthorizationError("APPLYING ledger readback does not match the authorized CAS")
    operational_paths = intent.get("operational_paths")
    if not isinstance(operational_paths, dict) or "plan" not in operational_paths:
        raise AuthorizationError("saved-plan apply operational paths are invalid")
    path_values = {
        key: value for key, value in operational_paths.items() if key != "plan"
    }
    paths = _validated_paths(path_values, APPLY_INPUT_FIELDS, "apply")
    plan_path = _absolute_path(operational_paths["plan"], "saved plan")
    rebuilt = build_apply_intent(
        context=context,
        plan_record=plan_record,
        ledger=approved_ledger,
        approval_record=approval_record,
        expected_bindings=expected_bindings,
        plan_readback=plan_readback,
        state_readback=state_readback,
        plan_binary_path=plan_path,
        apply_inputs=paths,
        now=transition_at,
    )
    if dict(intent) != rebuilt:
        raise AuthorizationError("saved-plan apply intent binding mismatch")
    return {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_APPLY_INTENT_VALIDATED",
        "intent_digest": claimed,
        "plan_record_digest": decision["plan_record_digest"],
        "applying_ledger_digest": applying_ledger["ledger_digest"],
    }


def classify_apply_observation(
    *,
    applying_ledger: Mapping[str, Any],
    observation: str,
    at: datetime,
) -> dict[str, Any]:
    """Produce the only post-apply CAS; an uncertain result is never retried."""
    outcomes = {
        "SUCCESS": ("APPLIED", "TERRAFORM_APPLY_SUCCEEDED"),
        "FAILURE": ("FAILED", "TERRAFORM_APPLY_FAILED"),
        "RESPONSE_LOST": ("UNCERTAIN", "APPLY_RESPONSE_LOST"),
    }
    if observation not in outcomes:
        raise AuthorizationError("Terraform apply observation is invalid")
    next_status, outcome_code = outcomes[observation]
    proposed, condition = prepare_ledger_transition(
        current=applying_ledger,
        next_status=next_status,
        expected_version=applying_ledger["ledger_version"],
        expected_digest=applying_ledger["ledger_digest"],
        at=at,
        outcome_code=outcome_code,
    )
    decision: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_apply_outcome_intent",
        "code": outcome_code,
        "observation": observation,
        "next_status": next_status,
        "source_ledger_digest": applying_ledger["ledger_digest"],
        "proposed_ledger": proposed,
        "cas_condition": condition,
        "retry_allowed": False,
        "replan_allowed": False,
        "reconciliation_required": next_status == "UNCERTAIN",
    }
    decision["intent_digest"] = canonical_digest(decision)
    return decision
