"""Pure fail-closed contracts for the GUG-220 Lambda audit permission set.

This module has no AWS client and performs no effects.  It binds the exact
GUG-219 collector policy to one Identity Center permission set, one direct
human assignment, and one non-production authority account.  Public records
contain digests instead of account, principal, permission-set, or role ARNs.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from tooling.platform_authority_lambda_invocation_authority import (
    TargetBinding,
    canonical_digest,
    digest_text,
)
from tooling.platform_authority_lambda_invocation_materializer import (
    BROKER_FUNCTION_NAME,
    COLLECTOR_PERMISSION_SET_DESCRIPTION,
    COLLECTOR_PERMISSION_SET_NAME,
    COLLECTOR_POLICY_PATH,
    LambdaAuthorityMaterializationError,
    RUNTIME_SOURCE_PATHS,
    SOURCE_POLICY_PATHS,
    SOURCE_TEMPLATE_PATH,
    render_collector_inline_policy,
    validate_source_commit_binding,
)


MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
AUTHORITY_REGION = "us-east-1"
IDENTITY_CENTER_REGION = "us-east-1"
SESSION_DURATION = "PT1H"
INTENT_TTL = timedelta(minutes=15)
EXPECTED_TAGS = {
    "managed_by": "scanalyze",
    "work_package": "GUG-220",
    "purpose": "lambda-authority-inventory",
}
EXPECTED_MUTATIONS = [
    "sso-admin:CreatePermissionSet",
    "sso-admin:PutInlinePolicyToPermissionSet",
    "sso-admin:CreateAccountAssignment",
    "sso-admin:ProvisionPermissionSet",
]
RECEIPT_STATUSES = frozenset(
    {
        "PLAN_ONLY",
        "READBACK_VERIFIED",
        "READBACK_INCOMPLETE",
        "UNCERTAIN_RECONCILE_ONLY",
        "BLOCKED_DRIFT",
    }
)
_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_PERMISSION_SET_ARN = re.compile(
    r"arn:aws:sso:::permissionSet/ssoins-[0-9a-f]{16}/ps-[0-9a-f]{16}"
)
_ROLE_ARN = re.compile(
    rf"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:role/aws-reserved/sso\.amazonaws\.com/"
    rf"AWSReservedSSO_{re.escape(COLLECTOR_PERMISSION_SET_NAME)}_[0-9a-fA-F]{{16}}"
)
_SAML_PROVIDER_ARN = re.compile(
    rf"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:saml-provider/"
    r"AWSSSO_[0-9a-fA-F]{16}_DO_NOT_DELETE"
)
PROVISIONING_RUNTIME_SOURCE_PATHS = (
    Path("tooling/platform_authority_lambda_audit_permission_set.py"),
    Path("scripts/deployment/platform-authority-lambda-audit-permission-set.py"),
)
PROVISIONING_SOURCE_PATHS = tuple(
    dict.fromkeys(
        (
            SOURCE_TEMPLATE_PATH,
            *SOURCE_POLICY_PATHS,
            *RUNTIME_SOURCE_PATHS,
            *PROVISIONING_RUNTIME_SOURCE_PATHS,
        )
    )
)


class AuditPermissionSetError(ValueError):
    """Stable, sanitized fail-closed GUG-220 validation error."""


def _fail(code: str) -> None:
    raise AuditPermissionSetError(code)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("TIMESTAMP_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _byte_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        _fail("COLLECTOR_POLICY_TEMPLATE_UNAVAILABLE")
    raise AssertionError("unreachable")


def target_binding() -> TargetBinding:
    return TargetBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=AUTHORITY_REGION,
        function_name=BROKER_FUNCTION_NAME,
    )


def render_exact_collector_policy(repo_root: Path) -> dict[str, Any]:
    """Render the immutable GUG-219 policy for the authority account."""

    return render_collector_inline_policy(binding=target_binding(), repo_root=repo_root)


def validate_provisioning_source_commit_binding(
    *, source_commit: str, repo_root: Path
) -> None:
    """Prove every security-critical runtime byte belongs to one ancestor commit."""

    if not isinstance(source_commit, str) or _COMMIT.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_BINDING_INVALID")
    root = Path(repo_root).resolve()
    try:
        validate_source_commit_binding(
            source_commit=source_commit,
            repo_root=root,
            include_runtime=True,
        )
        for relative in PROVISIONING_RUNTIME_SOURCE_PATHS:
            committed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "show",
                    f"{source_commit}:{relative.as_posix()}",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
            ).stdout
            if committed != (root / relative).read_bytes():
                _fail("SOURCE_COMMIT_BINDING_INVALID")
    except (AuditPermissionSetError, LambdaAuthorityMaterializationError):
        _fail("SOURCE_COMMIT_BINDING_INVALID")
    except (OSError, subprocess.SubprocessError):
        _fail("SOURCE_COMMIT_BINDING_INVALID")


def current_provisioning_source_commit(repo_root: Path) -> str:
    root = Path(repo_root).resolve()
    try:
        source_commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        _fail("SOURCE_COMMIT_BINDING_INVALID")
    validate_provisioning_source_commit_binding(
        source_commit=source_commit,
        repo_root=root,
    )
    return source_commit


def sealed_collector_policy_for_intent(
    intent: Mapping[str, Any], *, repo_root: Path
) -> dict[str, Any]:
    """Return one reviewed policy object without reopening runtime sources later."""

    root = Path(repo_root).resolve()
    source_commit = intent.get("source_commit")
    if not isinstance(source_commit, str):
        _fail("SOURCE_COMMIT_BINDING_INVALID")
    validate_provisioning_source_commit_binding(
        source_commit=source_commit,
        repo_root=root,
    )
    policy = render_exact_collector_policy(root)
    if (
        canonical_digest(policy) != intent.get("collector_inline_policy_digest")
        or _byte_digest(root / COLLECTOR_POLICY_PATH)
        != intent.get("inline_policy_template_sha256")
    ):
        _fail("SEALED_COLLECTOR_POLICY_MISMATCH")
    validate_provisioning_source_commit_binding(
        source_commit=source_commit,
        repo_root=root,
    )
    return json.loads(json.dumps(policy, sort_keys=True, separators=(",", ":")))


def build_provisioning_intent(
    *,
    principal_id: str,
    identity_center_instance_arn: str,
    identity_store_id: str,
    saml_provider_arn: str,
    source_commit: str,
    execution_ledger_directory_id: str,
    created_at: datetime,
    repo_root: Path,
) -> dict[str, Any]:
    """Build a sanitized, digest-sealed authorization intent."""

    if not isinstance(principal_id, str) or not principal_id.strip():
        _fail("PRINCIPAL_INVALID")
    if not isinstance(identity_center_instance_arn, str) or not identity_center_instance_arn:
        _fail("IDENTITY_CENTER_INSTANCE_INVALID")
    if not isinstance(identity_store_id, str) or not identity_store_id:
        _fail("IDENTITY_STORE_INVALID")
    if (
        not isinstance(saml_provider_arn, str)
        or _SAML_PROVIDER_ARN.fullmatch(saml_provider_arn) is None
    ):
        _fail("SAML_PROVIDER_INVALID")
    if not isinstance(source_commit, str) or _COMMIT.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_INVALID")
    if (
        not isinstance(execution_ledger_directory_id, str)
        or not execution_ledger_directory_id
    ):
        _fail("EXECUTION_LEDGER_DIRECTORY_INVALID")
    created = _timestamp(created_at)
    expires = _timestamp(created_at + INTENT_TTL)
    root = Path(repo_root).resolve()
    policy = render_exact_collector_policy(root)
    intent: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_audit_provisioning_intent",
        "environment": "non-production",
        "production": False,
        "management_account_id_digest": digest_text(MANAGEMENT_ACCOUNT_ID),
        "authority_account_id_digest": digest_text(AUTHORITY_ACCOUNT_ID),
        "target_region": AUTHORITY_REGION,
        "identity_center_region": IDENTITY_CENTER_REGION,
        "identity_center_instance_arn_digest": digest_text(
            identity_center_instance_arn
        ),
        "identity_store_id_digest": digest_text(identity_store_id),
        "saml_provider_arn_digest": digest_text(saml_provider_arn),
        "source_commit": source_commit,
        "execution_ledger_directory_digest": digest_text(
            execution_ledger_directory_id
        ),
        "permission_set_name": COLLECTOR_PERMISSION_SET_NAME,
        "permission_set_description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
        "session_duration": SESSION_DURATION,
        "relay_state_present": False,
        "expected_tags_digest": canonical_digest(EXPECTED_TAGS),
        "inline_policy_template_sha256": _byte_digest(root / COLLECTOR_POLICY_PATH),
        "collector_inline_policy_digest": canonical_digest(policy),
        "managed_policy_arns": [],
        "customer_managed_policy_references": [],
        "permissions_boundary_present": False,
        "principal_type": "USER",
        "principal_id_digest": digest_text(principal_id),
        "direct_assignment_count": 1,
        "provisioned_account_count": 1,
        "expected_mutations": list(EXPECTED_MUTATIONS),
        "independent_review_present": False,
        "approval_authorized": False,
        "protected_retirement_authorized": False,
        "lambda_invocation_authorized": False,
        "customer_deployment_authorized": False,
        "production_authorized": False,
        "created_at": created,
        "expires_at": expires,
    }
    intent["intent_digest"] = canonical_digest(intent)
    return validate_provisioning_intent(intent, repo_root=root)


def validate_provisioning_intent(
    value: Mapping[str, Any], *, repo_root: Path
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "management_account_id_digest",
        "authority_account_id_digest",
        "target_region",
        "identity_center_region",
        "identity_center_instance_arn_digest",
        "identity_store_id_digest",
        "saml_provider_arn_digest",
        "source_commit",
        "execution_ledger_directory_digest",
        "permission_set_name",
        "permission_set_description",
        "session_duration",
        "relay_state_present",
        "expected_tags_digest",
        "inline_policy_template_sha256",
        "collector_inline_policy_digest",
        "managed_policy_arns",
        "customer_managed_policy_references",
        "permissions_boundary_present",
        "principal_type",
        "principal_id_digest",
        "direct_assignment_count",
        "provisioned_account_count",
        "expected_mutations",
        "independent_review_present",
        "approval_authorized",
        "protected_retirement_authorized",
        "lambda_invocation_authorized",
        "customer_deployment_authorized",
        "production_authorized",
        "created_at",
        "expires_at",
        "intent_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("INTENT_SHAPE_INVALID")
    root = Path(repo_root).resolve()
    policy = render_exact_collector_policy(root)
    exact = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_audit_provisioning_intent",
        "environment": "non-production",
        "production": False,
        "management_account_id_digest": digest_text(MANAGEMENT_ACCOUNT_ID),
        "authority_account_id_digest": digest_text(AUTHORITY_ACCOUNT_ID),
        "target_region": AUTHORITY_REGION,
        "identity_center_region": IDENTITY_CENTER_REGION,
        "permission_set_name": COLLECTOR_PERMISSION_SET_NAME,
        "permission_set_description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
        "session_duration": SESSION_DURATION,
        "relay_state_present": False,
        "expected_tags_digest": canonical_digest(EXPECTED_TAGS),
        "inline_policy_template_sha256": _byte_digest(root / COLLECTOR_POLICY_PATH),
        "collector_inline_policy_digest": canonical_digest(policy),
        "managed_policy_arns": [],
        "customer_managed_policy_references": [],
        "permissions_boundary_present": False,
        "principal_type": "USER",
        "direct_assignment_count": 1,
        "provisioned_account_count": 1,
        "expected_mutations": list(EXPECTED_MUTATIONS),
        "independent_review_present": False,
        "approval_authorized": False,
        "protected_retirement_authorized": False,
        "lambda_invocation_authorized": False,
        "customer_deployment_authorized": False,
        "production_authorized": False,
    }
    if any(value.get(key) != item for key, item in exact.items()):
        _fail("INTENT_AUTHORITY_EXPANSION")
    if not isinstance(value.get("principal_id_digest"), str) or _DIGEST.fullmatch(
        str(value["principal_id_digest"])
    ) is None:
        _fail("INTENT_PRINCIPAL_DIGEST_INVALID")
    if not isinstance(value.get("source_commit"), str) or _COMMIT.fullmatch(
        str(value["source_commit"])
    ) is None:
        _fail("INTENT_SOURCE_COMMIT_INVALID")
    for field in (
        "identity_center_instance_arn_digest",
        "identity_store_id_digest",
        "saml_provider_arn_digest",
        "execution_ledger_directory_digest",
    ):
        item = value.get(field)
        if not isinstance(item, str) or _DIGEST.fullmatch(item) is None:
            _fail("INTENT_AUTHORITY_DIGEST_INVALID")
    try:
        created = datetime.fromisoformat(
            str(value["created_at"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
    except ValueError:
        _fail("INTENT_TIMESTAMP_INVALID")
    if (
        created.tzinfo is None
        or expires.tzinfo is None
        or not str(value["created_at"]).endswith("Z")
        or not str(value["expires_at"]).endswith("Z")
        or not created < expires
        or expires - created > INTENT_TTL
    ):
        _fail("INTENT_TIMESTAMP_INVALID")
    digest = value.get("intent_digest")
    calculated = canonical_digest({key: item for key, item in value.items() if key != "intent_digest"})
    if digest != calculated:
        _fail("INTENT_DIGEST_MISMATCH")
    return dict(value)


def validate_intent_authority_binding(
    intent: Mapping[str, Any],
    *,
    identity_center_instance_arn: str,
    identity_store_id: str,
    saml_provider_arn: str,
) -> None:
    """Bind any readback to the exact live Identity Center authority."""

    if (
        not isinstance(identity_center_instance_arn, str)
        or not identity_center_instance_arn
        or not isinstance(identity_store_id, str)
        or not identity_store_id
        or not isinstance(saml_provider_arn, str)
        or _SAML_PROVIDER_ARN.fullmatch(saml_provider_arn) is None
    ):
        _fail("INTENT_IDENTITY_CENTER_BINDING_MISMATCH")
    if (
        intent.get("identity_center_instance_arn_digest")
        != digest_text(identity_center_instance_arn)
        or intent.get("identity_store_id_digest") != digest_text(identity_store_id)
        or intent.get("saml_provider_arn_digest") != digest_text(saml_provider_arn)
    ):
        _fail("INTENT_IDENTITY_CENTER_BINDING_MISMATCH")


def validate_execution_ledger_directory_binding(
    intent: Mapping[str, Any], *, execution_ledger_directory_id: str
) -> None:
    if intent.get("execution_ledger_directory_digest") != digest_text(
        execution_ledger_directory_id
    ):
        _fail("INTENT_EXECUTION_LEDGER_DIRECTORY_MISMATCH")


def validate_intent_execution_binding(
    intent: Mapping[str, Any],
    *,
    now: datetime,
    identity_center_instance_arn: str,
    identity_store_id: str,
    saml_provider_arn: str,
) -> None:
    """Bind a fresh intent to the exact live Identity Center authority."""

    if not isinstance(now, datetime) or now.tzinfo is None:
        _fail("INTENT_EXECUTION_TIME_INVALID")
    validate_intent_authority_binding(
        intent,
        identity_center_instance_arn=identity_center_instance_arn,
        identity_store_id=identity_store_id,
        saml_provider_arn=saml_provider_arn,
    )
    try:
        created = datetime.fromisoformat(
            str(intent.get("created_at", "")).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(intent.get("expires_at", "")).replace("Z", "+00:00")
        )
    except ValueError:
        _fail("INTENT_TIMESTAMP_INVALID")
    current = now.astimezone(UTC)
    if created.tzinfo is None or expires.tzinfo is None or current < created or current >= expires:
        _fail("INTENT_EXPIRED_OR_NOT_YET_VALID")


def required_provisioning_actions(partial_state: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the exact ordered effects required for an owned partial state."""

    expected = {
        "inline_policy_present",
        "assignment_present",
        "provisioning_present",
    }
    if not isinstance(partial_state, Mapping) or not expected.issubset(partial_state):
        _fail("PERMISSION_SET_PARTIAL_STATE_INVALID")
    if any(not isinstance(partial_state[key], bool) for key in expected):
        _fail("PERMISSION_SET_PARTIAL_STATE_INVALID")
    actions: list[str] = []
    policy_changed = not partial_state["inline_policy_present"]
    if policy_changed:
        actions.append("put_inline_policy")
    if not partial_state["assignment_present"]:
        actions.append("create_assignment")
    if policy_changed or not partial_state["provisioning_present"]:
        actions.append("provision")
    return tuple(actions)


def validate_collector_trust_policy(
    trust: Mapping[str, Any],
    *,
    expected_saml_provider_arn: str,
    authority_account_id: str = AUTHORITY_ACCOUNT_ID,
) -> None:
    """Accept only the exact same-account Identity Center SAML trust."""

    if (
        authority_account_id != AUTHORITY_ACCOUNT_ID
        or not isinstance(expected_saml_provider_arn, str)
        or _SAML_PROVIDER_ARN.fullmatch(expected_saml_provider_arn) is None
        or not isinstance(trust, Mapping)
    ):
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    if set(trust) != {"Version", "Statement"} or trust.get("Version") != "2012-10-17":
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    statements = trust.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    statement = statements[0]
    if not isinstance(statement, Mapping):
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    allowed_statement_fields = {"Sid", "Effect", "Principal", "Action", "Condition"}
    if set(statement) - allowed_statement_fields:
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    if "Sid" in statement and not isinstance(statement["Sid"], str):
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    principal = statement.get("Principal")
    federated = principal.get("Federated") if isinstance(principal, Mapping) else None
    actions = statement.get("Action")
    if isinstance(actions, str):
        action_values = [actions]
    elif isinstance(actions, list) and all(isinstance(item, str) for item in actions):
        action_values = actions
    else:
        _fail("COLLECTOR_ROLE_TRUST_INVALID")
    if (
        statement.get("Effect") != "Allow"
        or not isinstance(principal, Mapping)
        or set(principal) != {"Federated"}
        or not isinstance(federated, str)
        or _SAML_PROVIDER_ARN.fullmatch(federated) is None
        or federated != expected_saml_provider_arn
        or len(action_values) != 2
        or set(action_values) != {"sts:AssumeRoleWithSAML", "sts:TagSession"}
        or statement.get("Condition")
        != {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}
    ):
        _fail("COLLECTOR_ROLE_TRUST_INVALID")


def build_execution_ledger(
    *, intent: Mapping[str, Any], created_at: datetime
) -> dict[str, Any]:
    ledger: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_audit_execution_ledger",
        "environment": "non-production",
        "production": False,
        "intent_digest": intent.get("intent_digest"),
        "status": "MUTATION_WINDOW_CONSUMED",
        "mutation_attempt_limit": 1,
        "mutation_retry_authorized": False,
        "created_at": _timestamp(created_at),
    }
    ledger["ledger_digest"] = canonical_digest(ledger)
    return validate_execution_ledger(ledger, intent=intent)


def validate_execution_ledger(
    value: Mapping[str, Any], *, intent: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "intent_digest",
        "status",
        "mutation_attempt_limit",
        "mutation_retry_authorized",
        "created_at",
        "ledger_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("EXECUTION_LEDGER_SHAPE_INVALID")
    if (
        value.get("schema_version") != "1"
        or value.get("record_type")
        != "platform_authority_lambda_audit_execution_ledger"
        or value.get("environment") != "non-production"
        or value.get("production") is not False
        or value.get("intent_digest") != intent.get("intent_digest")
        or value.get("status") != "MUTATION_WINDOW_CONSUMED"
        or value.get("mutation_attempt_limit") != 1
        or value.get("mutation_retry_authorized") is not False
    ):
        _fail("EXECUTION_LEDGER_AUTHORITY_EXPANSION")
    try:
        created = datetime.fromisoformat(
            str(value.get("created_at", "")).replace("Z", "+00:00")
        )
    except ValueError:
        _fail("EXECUTION_LEDGER_TIMESTAMP_INVALID")
    if created.tzinfo is None or not str(value.get("created_at", "")).endswith("Z"):
        _fail("EXECUTION_LEDGER_TIMESTAMP_INVALID")
    calculated = canonical_digest(
        {key: item for key, item in value.items() if key != "ledger_digest"}
    )
    if value.get("ledger_digest") != calculated:
        _fail("EXECUTION_LEDGER_DIGEST_MISMATCH")
    return dict(value)


def _normalize_tags(tags: object) -> dict[str, str]:
    if not isinstance(tags, Sequence) or isinstance(tags, (str, bytes)):
        _fail("PERMISSION_SET_TAGS_INVALID")
    result: dict[str, str] = {}
    for item in tags:
        if not isinstance(item, Mapping):
            _fail("PERMISSION_SET_TAGS_INVALID")
        key, value = item.get("Key"), item.get("Value")
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            _fail("PERMISSION_SET_TAGS_INVALID")
        result[key] = value
    return result


def exact_permission_set_readback(
    *,
    permission_set: Mapping[str, Any],
    tags: object,
    inline_policy: Mapping[str, Any] | None,
    managed_policies: object,
    customer_managed_policy_references: object,
    permissions_boundary: object,
    assignments: object,
    provisioned_account_ids: object,
    expected_principal_id: str,
    expected_inline_policy: Mapping[str, Any],
) -> dict[str, str]:
    """Reject any permission-set state beyond the exact reviewed contract."""

    arn = permission_set.get("PermissionSetArn")
    if (
        not isinstance(arn, str)
        or _PERMISSION_SET_ARN.fullmatch(arn) is None
        or permission_set.get("Name") != COLLECTOR_PERMISSION_SET_NAME
        or permission_set.get("Description") != COLLECTOR_PERMISSION_SET_DESCRIPTION
        or permission_set.get("SessionDuration") != SESSION_DURATION
        or permission_set.get("RelayState") not in (None, "")
    ):
        _fail("PERMISSION_SET_METADATA_DRIFT")
    if _normalize_tags(tags) != EXPECTED_TAGS:
        _fail("PERMISSION_SET_TAG_DRIFT")
    if inline_policy != expected_inline_policy:
        _fail("PERMISSION_SET_INLINE_POLICY_DRIFT")
    if managed_policies != [] or customer_managed_policy_references != []:
        _fail("PERMISSION_SET_ATTACHMENT_DRIFT")
    if permissions_boundary not in (None, {}):
        _fail("PERMISSION_SET_BOUNDARY_DRIFT")
    expected_assignment = {
        "AccountId": AUTHORITY_ACCOUNT_ID,
        "PermissionSetArn": arn,
        "PrincipalType": "USER",
        "PrincipalId": expected_principal_id,
    }
    if assignments != [expected_assignment]:
        _fail("PERMISSION_SET_ASSIGNMENT_DRIFT")
    if provisioned_account_ids != [AUTHORITY_ACCOUNT_ID]:
        _fail("PERMISSION_SET_PROVISIONING_DRIFT")
    return {
        "permission_set_arn": arn,
        "permission_set_arn_digest": digest_text(arn),
        "collector_inline_policy_digest": canonical_digest(expected_inline_policy),
    }


def build_provisioning_receipt(
    *,
    intent: Mapping[str, Any],
    status: str,
    permission_set_arn: str | None,
    role_arn: str | None,
    aws_mutation_attempted: bool,
    ambiguous_response: bool,
    binding_written: bool,
    created_at: datetime,
) -> dict[str, Any]:
    if status not in RECEIPT_STATUSES:
        _fail("RECEIPT_STATUS_INVALID")
    if permission_set_arn is not None and (
        not isinstance(permission_set_arn, str)
        or _PERMISSION_SET_ARN.fullmatch(permission_set_arn) is None
    ):
        _fail("RECEIPT_PERMISSION_SET_ARN_INVALID")
    if role_arn is not None and (
        not isinstance(role_arn, str) or _ROLE_ARN.fullmatch(role_arn) is None
    ):
        _fail("RECEIPT_ROLE_ARN_INVALID")
    if status == "READBACK_VERIFIED" and (
        permission_set_arn is None or role_arn is None
    ):
        _fail("RECEIPT_READBACK_RESOURCE_INVALID")
    receipt: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_audit_provisioning_receipt",
        "environment": "non-production",
        "production": False,
        "status": status,
        "intent_digest": intent.get("intent_digest"),
        "permission_set_arn_digest": (
            digest_text(permission_set_arn) if permission_set_arn else None
        ),
        "collector_role_iam_arn_digest": digest_text(role_arn) if role_arn else None,
        "account_assignment_verified": status == "READBACK_VERIFIED",
        "permission_set_provisioning_verified": status == "READBACK_VERIFIED",
        "collector_role_verified": status == "READBACK_VERIFIED" and role_arn is not None,
        "binding_written": binding_written,
        "aws_mutation_attempted": aws_mutation_attempted,
        "ambiguous_response": ambiguous_response,
        "mutation_retry_attempted": False,
        "independent_review_present": False,
        "approval_authorized": False,
        "protected_retirement_authorized": False,
        "lambda_invocation_authorized": False,
        "customer_deployment_authorized": False,
        "production_authorized": False,
        "created_at": _timestamp(created_at),
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return validate_provisioning_receipt(receipt, intent=intent)


def validate_provisioning_receipt(
    value: Mapping[str, Any], *, intent: Mapping[str, Any]
) -> dict[str, Any]:
    expected = {
        "schema_version",
        "record_type",
        "environment",
        "production",
        "status",
        "intent_digest",
        "permission_set_arn_digest",
        "collector_role_iam_arn_digest",
        "account_assignment_verified",
        "permission_set_provisioning_verified",
        "collector_role_verified",
        "binding_written",
        "aws_mutation_attempted",
        "ambiguous_response",
        "mutation_retry_attempted",
        "independent_review_present",
        "approval_authorized",
        "protected_retirement_authorized",
        "lambda_invocation_authorized",
        "customer_deployment_authorized",
        "production_authorized",
        "created_at",
        "receipt_digest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        _fail("RECEIPT_SHAPE_INVALID")
    false_fields = (
        "production",
        "mutation_retry_attempted",
        "independent_review_present",
        "approval_authorized",
        "protected_retirement_authorized",
        "lambda_invocation_authorized",
        "customer_deployment_authorized",
        "production_authorized",
    )
    if (
        value.get("schema_version") != "1"
        or value.get("record_type") != "platform_authority_lambda_audit_provisioning_receipt"
        or value.get("environment") != "non-production"
        or value.get("status") not in RECEIPT_STATUSES
        or value.get("intent_digest") != intent.get("intent_digest")
        or any(value.get(field) is not False for field in false_fields)
    ):
        _fail("RECEIPT_AUTHORITY_EXPANSION")
    if value.get("status") == "READBACK_VERIFIED":
        if not all(
            value.get(field) is True
            for field in (
                "account_assignment_verified",
                "permission_set_provisioning_verified",
                "collector_role_verified",
            )
        ) or any(
            not isinstance(value.get(field), str)
            or _DIGEST.fullmatch(str(value.get(field))) is None
            for field in (
                "permission_set_arn_digest",
                "collector_role_iam_arn_digest",
            )
        ):
            _fail("RECEIPT_READBACK_INCOMPLETE")
        if value.get("ambiguous_response") is not False:
            _fail("RECEIPT_READBACK_INCOMPLETE")
    elif (
        any(
            value.get(field) is not False
            for field in (
                "account_assignment_verified",
                "permission_set_provisioning_verified",
                "collector_role_verified",
                "binding_written",
            )
        )
        or value.get("collector_role_iam_arn_digest") is not None
    ):
        _fail("RECEIPT_NON_VERIFIED_OVERCLAIM")
    status = value.get("status")
    if status in {"PLAN_ONLY", "BLOCKED_DRIFT"} and (
        value.get("aws_mutation_attempted") is not False
        or value.get("ambiguous_response") is not False
    ):
        _fail("RECEIPT_EFFECT_STATUS_MISMATCH")
    if status == "UNCERTAIN_RECONCILE_ONLY" and (
        value.get("aws_mutation_attempted") is not True
        or value.get("ambiguous_response") is not True
    ):
        _fail("RECEIPT_EFFECT_STATUS_MISMATCH")
    if status == "READBACK_INCOMPLETE" and (
        value.get("aws_mutation_attempted") is not False
        or value.get("ambiguous_response") is not True
    ):
        _fail("RECEIPT_EFFECT_STATUS_MISMATCH")
    if value.get("ambiguous_response") is True and value.get("status") not in {
        "READBACK_INCOMPLETE",
        "UNCERTAIN_RECONCILE_ONLY",
    }:
        _fail("RECEIPT_AMBIGUITY_INVALID")
    for field in ("permission_set_arn_digest", "collector_role_iam_arn_digest"):
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or _DIGEST.fullmatch(item) is None):
            _fail("RECEIPT_DIGEST_INVALID")
    calculated = canonical_digest({key: item for key, item in value.items() if key != "receipt_digest"})
    if value.get("receipt_digest") != calculated:
        _fail("RECEIPT_DIGEST_MISMATCH")
    return dict(value)
