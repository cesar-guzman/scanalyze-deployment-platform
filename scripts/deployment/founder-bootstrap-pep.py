#!/usr/bin/env python3
"""Durable one-shot PEP for the exceptional founder authority bootstrap.

Operational artifacts are private files outside Git.  The only live mutations
are an exact DynamoDB CAS transition and, behind explicit flags, one exact
CloudFormation Change Set creation or execution.  Ambiguous responses are
persisted as UNCERTAIN and are never retried.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.founder_bootstrap_exception import (  # noqa: E402
    build_founder_bootstrap_exception,
    validate_founder_bootstrap_exception,
)
from tooling.founder_bootstrap_pep import (  # noqa: E402
    AUTHORITY_ACCOUNT_ID,
    AUTHORITY_REGION,
    EXCEPTION_ID,
    EXPECTED_RESOURCE_CHANGES,
    FOUNDER_APPLY_PERMISSION_SET,
    FOUNDER_PLAN_PERMISSION_SET,
    MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET,
    PEP_TABLE_NAME,
    AwsCliFounderPepStore,
    FounderPepAuthorizationError,
    build_founder_pep_intent,
    build_founder_pep_ledger,
    build_founder_pep_revocation,
    finalize_founder_revocation,
    render_live_founder_policy,
    run_founder_apply_once,
    run_founder_plan_once,
    validate_founder_pep_intent,
    validate_founder_pep_revocation,
)
from tooling.platform_authority_bootstrap import (  # noqa: E402
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    BootstrapBinding,
    build_bootstrap_plan,
    build_bootstrap_verification,
    canonical_digest,
    require_exact_empty_review_stack,
)


TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-state-backend.yaml"
MANAGEMENT_ACCOUNT_ID = "839393571433"
NORMAL_PLAN_PERMISSION_SET = "ScanalyzeAuthorityBootstrapPlan"
FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
SSO_ARN = re.compile(
    r"^arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"(?P<role>AWSReservedSSO_[A-Za-z0-9+=,.@_-]+_[0-9A-Fa-f]{16})/"
    r"[A-Za-z0-9+=,.@_-]{2,64}$"
)
MAX_CHANGE_SET_PAGES = 100


class AwsEffectError(RuntimeError):
    """An AWS effect failed without exposing its response."""


def _now() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise FounderPepAuthorizationError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FounderPepAuthorizationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise FounderPepAuthorizationError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FounderPepAuthorizationError("operational JSON has duplicate keys")
        result[key] = value
    return result


def _private_input(path: Path) -> Path:
    source = path.expanduser().resolve(strict=False)
    try:
        source.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise FounderPepAuthorizationError("operational artifact must be outside the repository")
    if source.is_symlink() or not source.is_file():
        raise FounderPepAuthorizationError("operational input must be a private regular file")
    if stat.S_IMODE(source.stat().st_mode) & 0o077:
        raise FounderPepAuthorizationError("operational input must be mode 0600")
    return source


def _output_path(path: Path) -> Path:
    target = path.expanduser().resolve(strict=False)
    try:
        target.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise FounderPepAuthorizationError("operational output must be outside the repository")
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise FounderPepAuthorizationError("operational output path is unsafe or already exists")
    return target


def _read_json(path: Path) -> dict[str, Any]:
    source = _private_input(path)
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise FounderPepAuthorizationError("operational JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FounderPepAuthorizationError("operational JSON must be an object")
    return value


def _read_line(path: Path) -> str:
    try:
        value = _private_input(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise FounderPepAuthorizationError("private operational value cannot be read") from exc
    if not value or "\n" in value or "\r" in value:
        raise FounderPepAuthorizationError("private operational input must contain one value")
    return value


def _write_private(path: Path, content: str) -> None:
    target = _output_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        os.write(descriptor, content.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_private(path, json.dumps(value, sort_keys=True, indent=2) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_sso_environment(*, ambient_profile_required: bool = True) -> None:
    if ambient_profile_required and not os.environ.get("AWS_PROFILE"):
        raise FounderPepAuthorizationError("AWS_PROFILE is required")
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise FounderPepAuthorizationError("static or ambient AWS credentials are forbidden")
    regions = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if regions and regions != {AUTHORITY_REGION}:
        raise FounderPepAuthorizationError("ambient AWS region conflicts with the PEP binding")


class AwsCli:
    def __init__(self, *, profile: str | None = None) -> None:
        self.profile = profile

    def _base(self) -> list[str]:
        base = ["aws"]
        if self.profile is not None:
            base.extend(("--profile", self.profile))
        return base

    def run(self, *parts: str) -> dict[str, Any]:
        command = [
            *self._base(), *parts, "--region", AUTHORITY_REGION,
            "--output", "json", "--no-cli-pager",
        ]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, env=os.environ.copy()
        )
        if completed.returncode != 0:
            raise AwsEffectError(f"AWS operation failed: {' '.join(parts[:2])}")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsEffectError("AWS operation returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AwsEffectError("AWS operation returned an invalid response")
        return value

    def run_optional_not_found(self, *parts: str) -> dict[str, Any] | None:
        command = [
            *self._base(), *parts, "--region", AUTHORITY_REGION,
            "--output", "json", "--no-cli-pager",
        ]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, env=os.environ.copy()
        )
        if completed.returncode != 0:
            if "ResourceNotFoundException" in completed.stderr:
                return None
            raise AwsEffectError(f"AWS operation failed: {' '.join(parts[:2])}")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsEffectError("AWS operation returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AwsEffectError("AWS operation returned an invalid response")
        return value

    def wait(self, *parts: str) -> None:
        completed = subprocess.run(
            [*self._base(), *parts, "--region", AUTHORITY_REGION, "--no-cli-pager"],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            raise AwsEffectError(f"AWS waiter failed: {' '.join(parts[:3])}")


def _management_identity(client: AwsCli) -> str:
    # Identity Center administration deliberately uses an explicit, separately
    # verified management-account profile.  Requiring an unrelated ambient
    # AWS_PROFILE would make that boundary ambiguous without adding a control.
    _require_sso_environment(ambient_profile_required=False)
    response = client.run("sts", "get-caller-identity")
    arn = response.get("Arn")
    match = SSO_ARN.fullmatch(arn) if isinstance(arn, str) else None
    if response.get("Account") != MANAGEMENT_ACCOUNT_ID or match is None:
        raise FounderPepAuthorizationError("identity administrator is outside management account")
    expected_role_prefix = f"AWSReservedSSO_{MANAGEMENT_IDENTITY_ADMIN_PERMISSION_SET}_"
    if not match.group("role").startswith(expected_role_prefix):
        raise FounderPepAuthorizationError("identity administrator does not use the reviewed SSO role")
    return arn


def _identity_center_instance(client: AwsCli) -> tuple[str, str]:
    response = client.run("sso-admin", "list-instances")
    instances = response.get("Instances")
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], Mapping):
        raise FounderPepAuthorizationError("Identity Center instance ownership is ambiguous")
    instance_arn = instances[0].get("InstanceArn")
    identity_store_id = instances[0].get("IdentityStoreId")
    owner = instances[0].get("OwnerAccountId")
    if (
        not isinstance(instance_arn, str)
        or not isinstance(identity_store_id, str)
        or owner != MANAGEMENT_ACCOUNT_ID
    ):
        raise FounderPepAuthorizationError("Identity Center instance binding is invalid")
    return instance_arn, identity_store_id


def _permission_set_records(client: AwsCli, instance_arn: str) -> dict[str, dict[str, Any]]:
    response = client.run("sso-admin", "list-permission-sets", "--instance-arn", instance_arn)
    arns = response.get("PermissionSets")
    if not isinstance(arns, list) or any(not isinstance(item, str) for item in arns):
        raise FounderPepAuthorizationError("Identity Center permission-set inventory is malformed")
    records: dict[str, dict[str, Any]] = {}
    for arn in arns:
        described = client.run(
            "sso-admin", "describe-permission-set", "--instance-arn", instance_arn,
            "--permission-set-arn", arn,
        ).get("PermissionSet")
        if not isinstance(described, dict) or not isinstance(described.get("Name"), str):
            raise FounderPepAuthorizationError("Identity Center permission-set readback is incomplete")
        name = described["Name"]
        if name in records:
            raise FounderPepAuthorizationError("duplicate Identity Center permission-set name")
        tags = _permission_set_tags(client, instance_arn, arn)
        founder_owned = (
            tags.get("managed_by") == "scanalyze-founder-pep"
            or tags.get("work_package") == "GUG-211"
        )
        if founder_owned and name not in {
            FOUNDER_PLAN_PERMISSION_SET,
            FOUNDER_APPLY_PERMISSION_SET,
        }:
            raise FounderPepAuthorizationError(
                "foreign GUG-211 permission set exists in Identity Center"
            )
        records[name] = described
    return records


def _permission_set_tags(client: AwsCli, instance_arn: str, permission_set_arn: str) -> dict[str, str]:
    response = client.run(
        "sso-admin", "list-tags-for-resource", "--instance-arn", instance_arn,
        "--resource-arn", permission_set_arn,
    )
    tags = response.get("Tags")
    if not isinstance(tags, list):
        raise FounderPepAuthorizationError("Identity Center permission-set tags are missing")
    normalized = {
        item.get("Key"): item.get("Value")
        for item in tags
        if isinstance(item, Mapping)
    }
    if len(normalized) != len(tags):
        raise FounderPepAuthorizationError("Identity Center permission-set tags are ambiguous")
    return normalized  # type: ignore[return-value]


def _inline_policy(client: AwsCli, instance_arn: str, permission_set_arn: str) -> dict[str, Any] | None:
    response = client.run(
        "sso-admin", "get-inline-policy-for-permission-set",
        "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
    )
    raw = response.get("InlinePolicy")
    if raw is None or raw == "":
        return None
    try:
        policy = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise FounderPepAuthorizationError("Identity Center inline policy is malformed") from exc
    if not isinstance(policy, dict):
        raise FounderPepAuthorizationError("Identity Center inline policy is invalid")
    return policy


def _account_assignments(
    client: AwsCli, instance_arn: str, permission_set_arn: str
) -> list[dict[str, Any]]:
    response = client.run(
        "sso-admin", "list-account-assignments", "--instance-arn", instance_arn,
        "--account-id", AUTHORITY_ACCOUNT_ID, "--permission-set-arn", permission_set_arn,
    )
    assignments = response.get("AccountAssignments")
    if not isinstance(assignments, list) or any(not isinstance(item, dict) for item in assignments):
        raise FounderPepAuthorizationError("Identity Center assignment readback is malformed")
    return assignments


def _provisioned_accounts(
    client: AwsCli, instance_arn: str, permission_set_arn: str
) -> set[str]:
    response = client.run(
        "sso-admin", "list-accounts-for-provisioned-permission-set",
        "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
    )
    values = response.get("AccountIds")
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise FounderPepAuthorizationError("Identity Center provisioning readback is malformed")
    return set(values)


def _verify_no_permission_set_attachments(
    client: AwsCli, instance_arn: str, permission_set_arn: str
) -> None:
    managed = client.run(
        "sso-admin", "list-managed-policies-in-permission-set",
        "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
    ).get("AttachedManagedPolicies")
    customer = client.run(
        "sso-admin", "list-customer-managed-policy-references-in-permission-set",
        "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
    ).get("CustomerManagedPolicyReferences")
    boundary_response = client.run_optional_not_found(
        "sso-admin", "get-permissions-boundary-for-permission-set",
        "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
    )
    boundary = (
        boundary_response.get("PermissionsBoundary")
        if isinstance(boundary_response, Mapping)
        else None
    )
    if managed != [] or customer != [] or boundary not in (None, {}):
        raise FounderPepAuthorizationError(
            "founder permission set has authority outside its exact inline policy"
        )


def _wait_identity_center(
    client: AwsCli,
    *,
    operation: str,
    instance_arn: str,
    request_id: object,
) -> None:
    definitions = {
        "provision": (
            "describe-permission-set-provisioning-status",
            "--provision-permission-set-request-id",
            "PermissionSetProvisioningStatus",
        ),
        "create-assignment": (
            "describe-account-assignment-creation-status",
            "--account-assignment-creation-request-id",
            "AccountAssignmentCreationStatus",
        ),
        "delete-assignment": (
            "describe-account-assignment-deletion-status",
            "--account-assignment-deletion-request-id",
            "AccountAssignmentDeletionStatus",
        ),
    }
    if operation not in definitions or not isinstance(request_id, str):
        raise FounderPepAuthorizationError("Identity Center operation receipt is invalid")
    api, request_flag, response_key = definitions[operation]
    for _ in range(40):
        response = client.run(
            "sso-admin", api, "--instance-arn", instance_arn,
            request_flag, request_id,
        )
        status = response.get(response_key)
        value = status.get("Status") if isinstance(status, Mapping) else None
        if value == "SUCCEEDED":
            return
        if value == "FAILED":
            raise FounderPepAuthorizationError("Identity Center operation failed")
        if value != "IN_PROGRESS":
            raise FounderPepAuthorizationError("Identity Center operation state is ambiguous")
        time.sleep(3)
    raise FounderPepAuthorizationError("Identity Center operation timed out")


def _provision_permission_set(client: AwsCli, instance_arn: str, permission_set_arn: str) -> None:
    response = client.run(
        "sso-admin", "provision-permission-set", "--instance-arn", instance_arn,
        "--permission-set-arn", permission_set_arn, "--target-type", "AWS_ACCOUNT",
        "--target-id", AUTHORITY_ACCOUNT_ID,
    )
    status = response.get("PermissionSetProvisioningStatus")
    request_id = status.get("RequestId") if isinstance(status, Mapping) else None
    _wait_identity_center(
        client,
        operation="provision",
        instance_arn=instance_arn,
        request_id=request_id,
    )


def _permission_set_shell_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyFounderShellMutations",
                "Effect": "Deny",
                "NotAction": "sts:GetCallerIdentity",
                "Resource": "*",
            }
        ],
    }


def _expected_permission_set_tags(exception_id: str, mode: str) -> dict[str, str]:
    return {
        "managed_by": "scanalyze-founder-pep",
        "work_package": "GUG-211",
        "exception_id": exception_id,
        "mode": mode,
    }


def _validate_permission_set(
    client: AwsCli,
    *,
    instance_arn: str,
    record: Mapping[str, Any],
    name: str,
    exception_id: str,
    mode: str,
) -> str:
    arn = record.get("PermissionSetArn")
    if (
        not isinstance(arn, str)
        or record.get("Name") != name
        or record.get("SessionDuration") != "PT1H"
        or record.get("RelayState") not in (None, "")
        or record.get("Description") != f"GUG-211 {exception_id} founder {mode} one-shot authority"
    ):
        raise FounderPepAuthorizationError("founder permission-set contract differs")
    if _permission_set_tags(client, instance_arn, arn) != _expected_permission_set_tags(
        exception_id, mode
    ):
        raise FounderPepAuthorizationError("founder permission-set tags differ")
    _verify_no_permission_set_attachments(client, instance_arn, arn)
    return arn


def _principal_arn_from_permission_set(
    permission_set_arn: str, *, name: str, session_name: str
) -> str:
    match = re.fullmatch(r"arn:aws:sso:::permissionSet/ssoins-[0-9a-f]{16}/ps-([0-9a-f]{16})", permission_set_arn)
    if match is None or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,64}", session_name) is None:
        raise FounderPepAuthorizationError("founder permission-set principal cannot be derived")
    return (
        f"arn:aws:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
        f"AWSReservedSSO_{name}_{match.group(1)}/{session_name}"
    )


def _identity(client: AwsCli, permission_set: str, intent: Mapping[str, Any]) -> str:
    _require_sso_environment()
    response = client.run("sts", "get-caller-identity")
    arn = response.get("Arn")
    match = SSO_ARN.fullmatch(arn) if isinstance(arn, str) else None
    if response.get("Account") != AUTHORITY_ACCOUNT_ID or match is None:
        raise FounderPepAuthorizationError("caller is outside the authority account")
    expected_role = re.compile(
        rf"AWSReservedSSO_{re.escape(permission_set)}_[0-9A-Fa-f]{{16}}"
    )
    if expected_role.fullmatch(match.group("role")) is None:
        raise FounderPepAuthorizationError("caller does not use the exact founder permission set")
    digest_field = (
        "plan_principal_digest"
        if permission_set == FOUNDER_PLAN_PERMISSION_SET
        else "apply_principal_digest"
    )
    if canonical_digest({"caller_arn": arn}) != intent.get(digest_field):
        raise FounderPepAuthorizationError("caller principal differs from the founder intent")
    return arn


def _store() -> AwsCliFounderPepStore:
    return AwsCliFounderPepStore(
        region=AUTHORITY_REGION,
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        table_name=PEP_TABLE_NAME,
    )


def _pab(client: AwsCli) -> dict[str, bool]:
    response = client.run(
        "s3control", "get-public-access-block", "--account-id", AUTHORITY_ACCOUNT_ID
    )
    configuration = response.get("PublicAccessBlockConfiguration")
    if not isinstance(configuration, dict) or configuration != PUBLIC_ACCESS_BLOCK:
        raise FounderPepAuthorizationError(
            "effective organization/account public-access block is not fully enabled"
        )
    return {key: True for key in PUBLIC_ACCESS_BLOCK}


def _stack_and_resources(client: AwsCli) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    stack_response = client.run(
        "cloudformation", "describe-stacks", "--stack-name", "scanalyze-platform-authority-state-backend"
    )
    stacks = stack_response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise FounderPepAuthorizationError("bootstrap stack response is ambiguous")
    resource_response = client.run(
        "cloudformation", "list-stack-resources", "--stack-name", "scanalyze-platform-authority-state-backend"
    )
    resources = resource_response.get("StackResourceSummaries")
    if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
        raise FounderPepAuthorizationError("bootstrap resource response is ambiguous")
    return stacks[0], resources


def _require_exact_founder_review_stack(
    stack: Mapping[str, Any],
    resources: object,
) -> None:
    require_exact_empty_review_stack(
        stack=stack,
        resources=resources,
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=AUTHORITY_REGION,
    )


def _require_no_active_change_sets(client: AwsCli) -> None:
    token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(MAX_CHANGE_SET_PAGES):
        arguments = [
            "--stack-name",
            "scanalyze-platform-authority-state-backend",
            "--max-items",
            "100",
        ]
        if token is not None:
            arguments.extend(("--starting-token", token))
        response = client.run("cloudformation", "list-change-sets", *arguments)
        summaries = response.get("Summaries")
        if not isinstance(summaries, list):
            raise FounderPepAuthorizationError("Change Set inventory is ambiguous")
        if summaries:
            raise FounderPepAuthorizationError(
                "active Change Set inventory is not exactly empty"
            )
        next_token = response.get("NextToken")
        if next_token is None:
            return
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen_tokens
        ):
            raise FounderPepAuthorizationError("Change Set pagination is ambiguous")
        seen_tokens.add(next_token)
        token = next_token
    raise FounderPepAuthorizationError("Change Set pagination exceeded the safety limit")


def _exact_tags(value: object, expected: Mapping[str, str], label: str) -> None:
    if not isinstance(value, list):
        raise FounderPepAuthorizationError(f"{label} tags are missing")
    normalized = {
        item.get("Key", item.get("TagKey")): item.get("Value", item.get("TagValue"))
        for item in value
        if isinstance(item, Mapping)
        and isinstance(item.get("Key", item.get("TagKey")), str)
        and isinstance(item.get("Value", item.get("TagValue")), str)
    }
    if normalized != dict(expected) or len(normalized) != len(value):
        raise FounderPepAuthorizationError(f"{label} tags differ from the reviewed contract")


def _stack_outputs(stack: Mapping[str, Any]) -> dict[str, str]:
    raw = stack.get("Outputs")
    if not isinstance(raw, list):
        raise FounderPepAuthorizationError("bootstrap stack outputs are missing")
    outputs: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            raise FounderPepAuthorizationError("bootstrap stack outputs are malformed")
        key = item.get("OutputKey")
        value = item.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in outputs:
            raise FounderPepAuthorizationError("bootstrap stack outputs are ambiguous")
        outputs[key] = value
    required = {
        "AuthorityAccountId",
        "AuthorityRegion",
        "StateBucketName",
        "StateBucketArn",
        "StateKmsKeyArn",
        "StateKey",
        "AccountPublicAccessBlockRequired",
        "BackendConfig",
    }
    if set(outputs) != required:
        raise FounderPepAuthorizationError("bootstrap stack output contract differs")
    return outputs


def _validate_plan_contract(plan: Mapping[str, Any], intent: Mapping[str, Any]) -> None:
    digest = plan.get("record_digest")
    if not isinstance(digest, str) or digest != canonical_digest(
        {key: value for key, value in plan.items() if key != "record_digest"}
    ):
        raise FounderPepAuthorizationError("founder Plan record digest mismatch")
    exact = {
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "region": AUTHORITY_REGION,
        "stack_name": "scanalyze-platform-authority-state-backend",
        "state_bucket_name": (
            f"scanalyze-platform-authority-{AUTHORITY_ACCOUNT_ID}-{AUTHORITY_REGION}-state"
        ),
        "state_key": "platform-authority/terraform.tfstate",
        "native_lockfile_enabled": True,
        "template_sha256": intent["template_sha256"],
        "change_set_type": "CREATE",
        "planned_resource_changes": list(EXPECTED_RESOURCE_CHANGES),
        "account_public_access_block_before": PUBLIC_ACCESS_BLOCK,
        "account_public_access_block_after": PUBLIC_ACCESS_BLOCK,
        "initiator_id": intent["operator_id"],
    }
    if any(plan.get(field) != value for field, value in exact.items()):
        raise FounderPepAuthorizationError("founder Plan differs from the exact reviewed contract")
    change_set_id = plan.get("change_set_id")
    if (
        not isinstance(change_set_id, str)
        or f"changeSet/{intent['change_set_name']}/" not in change_set_id
    ):
        raise FounderPepAuthorizationError("founder Plan Change Set binding is invalid")


def _verify_backend_controls(
    client: AwsCli,
    *,
    stack: Mapping[str, Any],
    plan: Mapping[str, Any],
    caller_arn: str,
) -> dict[str, Any]:
    outputs = _stack_outputs(stack)
    bucket = str(plan["state_bucket_name"])
    key_arn = outputs["StateKmsKeyArn"]
    expected_bucket_arn = f"arn:aws:s3:::{bucket}"
    expected_backend_config = (
        f'bucket              = "{bucket}"\n'
        f'key                 = "{plan["state_key"]}"\n'
        f'region              = "{AUTHORITY_REGION}"\n'
        "encrypt             = true\n"
        f'kms_key_id          = "{key_arn}"\n'
        "use_lockfile        = true\n"
        f'allowed_account_ids = ["{AUTHORITY_ACCOUNT_ID}"]\n'
    )
    if outputs != {
        "AuthorityAccountId": AUTHORITY_ACCOUNT_ID,
        "AuthorityRegion": AUTHORITY_REGION,
        "StateBucketName": bucket,
        "StateBucketArn": expected_bucket_arn,
        "StateKmsKeyArn": key_arn,
        "StateKey": str(plan["state_key"]),
        "AccountPublicAccessBlockRequired": "true",
        "BackendConfig": expected_backend_config,
    }:
        raise FounderPepAuthorizationError("bootstrap stack outputs differ from the exact binding")
    if re.fullmatch(
        rf"arn:aws:kms:{AUTHORITY_REGION}:{AUTHORITY_ACCOUNT_ID}:key/[0-9a-f-]{{36}}",
        key_arn,
    ) is None:
        raise FounderPepAuthorizationError("bootstrap KMS output is not the exact authority key")

    location = client.run("s3api", "get-bucket-location", "--bucket", bucket)
    if location.get("LocationConstraint") not in {None, ""}:
        raise FounderPepAuthorizationError("state bucket is outside the authority Region")
    bucket_pab = client.run("s3api", "get-public-access-block", "--bucket", bucket)
    if bucket_pab.get("PublicAccessBlockConfiguration") != PUBLIC_ACCESS_BLOCK:
        raise FounderPepAuthorizationError("state bucket public-access block is incomplete")
    if client.run("s3api", "get-bucket-versioning", "--bucket", bucket).get("Status") != "Enabled":
        raise FounderPepAuthorizationError("state bucket versioning is not enabled")
    ownership = client.run("s3api", "get-bucket-ownership-controls", "--bucket", bucket)
    if ownership.get("OwnershipControls") != {
        "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]
    }:
        raise FounderPepAuthorizationError("state bucket ownership is not enforced")
    encryption = client.run("s3api", "get-bucket-encryption", "--bucket", bucket)
    if encryption.get("ServerSideEncryptionConfiguration") != {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": key_arn,
                },
                "BucketKeyEnabled": True,
            }
        ]
    }:
        raise FounderPepAuthorizationError("state bucket encryption differs from the reviewed key")
    lifecycle = client.run("s3api", "get-bucket-lifecycle-configuration", "--bucket", bucket)
    lifecycle_rules = lifecycle.get("Rules")
    expected_lifecycle = {
        "RetainNoncurrentStateVersions": {
            "Status": "Enabled",
            "NoncurrentVersionExpiration": {"NoncurrentDays": 365},
        },
        "AbortIncompleteMultipartUploads": {
            "Status": "Enabled",
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        },
    }
    normalized_lifecycle: dict[str, dict[str, Any]] = {}
    if isinstance(lifecycle_rules, list):
        for rule in lifecycle_rules:
            if not isinstance(rule, Mapping):
                continue
            rule_id = rule.get("ID")
            if (
                not isinstance(rule_id, str)
                or rule_id in normalized_lifecycle
                or rule.get("Prefix") not in {None, ""}
                or (
                    rule.get("Filter") is not None
                    and rule.get("Filter") != {}
                )
            ):
                raise FounderPepAuthorizationError(
                    "state bucket lifecycle scope differs from the reviewed contract"
                )
            normalized_lifecycle[rule_id] = {
                key: value
                for key, value in rule.items()
                if key not in {"ID", "Filter", "Prefix"}
            }
    if normalized_lifecycle != expected_lifecycle:
        raise FounderPepAuthorizationError("state bucket lifecycle differs from the reviewed contract")
    expected_tags = {
        "managed_by": "cloudformation",
        "service": "scanalyze-platform-authority",
        "data_class": "control-metadata",
        "account_id": AUTHORITY_ACCOUNT_ID,
        "region": AUTHORITY_REGION,
    }
    _exact_tags(
        client.run("s3api", "get-bucket-tagging", "--bucket", bucket).get("TagSet"),
        expected_tags,
        "state bucket",
    )
    status = client.run("s3api", "get-bucket-policy-status", "--bucket", bucket)
    if status.get("PolicyStatus") != {"IsPublic": False}:
        raise FounderPepAuthorizationError("state bucket policy is public or ambiguous")
    policy_result = client.run("s3api", "get-bucket-policy", "--bucket", bucket)
    try:
        policy = json.loads(str(policy_result.get("Policy", "")))
    except json.JSONDecodeError as exc:
        raise FounderPepAuthorizationError("state bucket policy is malformed") from exc
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    expected_sids = {
        "DenyInsecureTransport",
        "DenyCrossAccountAccess",
        "DenyUnencryptedObjectWrites",
        "DenyWrongKmsKey",
        "DenyUnexpectedObjectKeys",
        "DenyStateDeletion",
    }
    if (
        not isinstance(statements, list)
        or {item.get("Sid") for item in statements if isinstance(item, Mapping)} != expected_sids
        or any(item.get("Effect") != "Deny" for item in statements if isinstance(item, Mapping))
        or len(statements) != len(expected_sids)
    ):
        raise FounderPepAuthorizationError("state bucket deny policy differs from the reviewed contract")
    serialized_policy = json.dumps(policy, sort_keys=True)
    if (
        expected_bucket_arn not in serialized_policy
        or key_arn not in serialized_policy
        or str(plan["state_key"]) not in serialized_policy
    ):
        raise FounderPepAuthorizationError("state bucket deny policy is not bound to the exact backend")

    key = client.run("kms", "describe-key", "--key-id", key_arn).get("KeyMetadata")
    if not isinstance(key, Mapping) or any(
        (
            key.get("Arn") != key_arn,
            key.get("AWSAccountId") != AUTHORITY_ACCOUNT_ID,
            key.get("KeyState") != "Enabled",
            key.get("KeyUsage") != "ENCRYPT_DECRYPT",
            key.get("KeySpec") != "SYMMETRIC_DEFAULT",
            key.get("MultiRegion") is not False,
        )
    ):
        raise FounderPepAuthorizationError("state KMS key metadata differs from the reviewed contract")
    rotation = client.run("kms", "get-key-rotation-status", "--key-id", key_arn)
    if rotation.get("KeyRotationEnabled") is not True:
        raise FounderPepAuthorizationError("state KMS key rotation is not enabled")
    key_policy_result = client.run(
        "kms", "get-key-policy", "--key-id", key_arn, "--policy-name", "default"
    )
    try:
        key_policy = json.loads(str(key_policy_result.get("Policy", "")))
    except json.JSONDecodeError as exc:
        raise FounderPepAuthorizationError("state KMS key policy is malformed") from exc
    if key_policy != {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableAuthorityAccountIamPermissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{AUTHORITY_ACCOUNT_ID}:root"
                },
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }:
        raise FounderPepAuthorizationError("state KMS key policy differs from the reviewed contract")
    _exact_tags(
        client.run("kms", "list-resource-tags", "--key-id", key_arn).get("Tags"),
        expected_tags,
        "state KMS key",
    )
    return build_bootstrap_verification(
        plan=plan,
        binding=BootstrapBinding(
            authority_account_id=AUTHORITY_ACCOUNT_ID,
            region=AUTHORITY_REGION,
            stack_name=str(plan["stack_name"]),
            state_bucket_name=bucket,
            state_key=str(plan["state_key"]),
            destination_account_ids=tuple(plan["destination_account_ids"]),
        ),
        caller_arn=caller_arn,
        stack_status=str(stack.get("StackStatus", "")),
        state_bucket_name=bucket,
        state_key=str(plan["state_key"]),
        state_kms_key_arn=key_arn,
        controls={
            "account_public_access_blocked": True,
            "bucket_public_access_blocked": True,
            "bucket_owner_enforced": True,
            "bucket_versioning_enabled": True,
            "default_encryption": "aws:kms",
            "bucket_key_enabled": True,
            "kms_rotation_enabled": True,
            "native_lockfile_enabled": True,
        },
        verified_at=_now(),
    )


def _changes(response: Mapping[str, Any]) -> list[dict[str, str]]:
    raw = response.get("Changes")
    if not isinstance(raw, list):
        raise FounderPepAuthorizationError("Change Set resource inventory is missing")
    result: list[dict[str, str]] = []
    for item in raw:
        resource = item.get("ResourceChange") if isinstance(item, Mapping) else None
        if not isinstance(resource, Mapping):
            raise FounderPepAuthorizationError("Change Set resource inventory is malformed")
        result.append(
            {
                "action": str(resource.get("Action", "")),
                "logical_resource_id": str(resource.get("LogicalResourceId", "")),
                "resource_type": str(resource.get("ResourceType", "")),
                "replacement": str(resource.get("Replacement", "False")),
            }
        )
    normalized = sorted(result, key=lambda item: item["logical_resource_id"])
    if normalized != list(EXPECTED_RESOURCE_CHANGES):
        raise FounderPepAuthorizationError("Change Set is outside the exact resource inventory")
    return normalized


def _describe_change_set(
    client: AwsCli, *, change_set_id: str, intent: Mapping[str, Any]
) -> dict[str, Any]:
    response = client.run(
        "cloudformation", "describe-change-set", "--change-set-name", change_set_id,
        "--stack-name", "scanalyze-platform-authority-state-backend",
    )
    if (
        response.get("ChangeSetId") != change_set_id
        or response.get("ChangeSetName") != intent.get("change_set_name")
        or response.get("StackName") != "scanalyze-platform-authority-state-backend"
        or response.get("Status") != "CREATE_COMPLETE"
        or response.get("ExecutionStatus") != "AVAILABLE"
    ):
        raise FounderPepAuthorizationError("live Change Set identity or state is invalid")
    tags = response.get("Tags")
    normalized_tags = {
        item.get("Key"): item.get("Value")
        for item in tags
        if isinstance(item, Mapping)
    } if isinstance(tags, list) else {}
    if normalized_tags != {
        "managed_by": "cloudformation",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-206",
    }:
        raise FounderPepAuthorizationError("live Change Set tags are invalid")
    _changes(response)
    template = client.run(
        "cloudformation", "get-template", "--change-set-name", change_set_id,
        "--stack-name", "scanalyze-platform-authority-state-backend",
        "--template-stage", "Original",
    )
    template_body = template.get("TemplateBody")
    if not isinstance(template_body, str):
        raise FounderPepAuthorizationError("live Change Set original template is unavailable")
    template_digest = "sha256:" + hashlib.sha256(template_body.encode("utf-8")).hexdigest()
    if template_digest != intent.get("template_sha256"):
        raise FounderPepAuthorizationError("live Change Set template digest is invalid")
    return response


def _binding(args: argparse.Namespace) -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=AUTHORITY_ACCOUNT_ID,
        region=AUTHORITY_REGION,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name=f"scanalyze-platform-authority-{AUTHORITY_ACCOUNT_ID}-{AUTHORITY_REGION}-state",
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=tuple(args.destination_account_id),
    )


def _cmd_prepare_intent(args: argparse.Namespace) -> None:
    intent = build_founder_pep_intent(
        exception_id=args.exception_id,
        operator_id=args.operator_id,
        operator_identity_store_user_id=_read_line(args.operator_subject_file),
        founder_plan_principal_arn=_read_line(args.founder_plan_principal_file),
        founder_apply_principal_arn=_read_line(args.founder_apply_principal_file),
        risk_acceptance_id=args.risk_acceptance_id,
        template_sha256=_sha256(TEMPLATE),
        normal_plan_revoked_at=_parse_time(args.normal_plan_revoked_at, "normal Plan revoked_at"),
        plan_not_before=_parse_time(args.plan_not_before, "Plan not_before"),
        plan_expires_at=_parse_time(args.plan_expires_at, "Plan expires_at"),
        apply_not_before=_parse_time(args.apply_not_before, "Apply not_before"),
        apply_expires_at=_parse_time(args.apply_expires_at, "Apply expires_at"),
        deny_retain_until=_parse_time(args.deny_retain_until, "deny retain_until"),
        created_at=_parse_time(args.created_at, "intent created_at"),
    )
    _write_json(args.intent_out, intent)
    print("PASS: founder PEP intent created privately")
    print(f"INTENT_DIGEST: {intent['intent_digest']}")
    print("NO_AWS_CHANGE: no policy, assignment, ledger, Change Set, or infrastructure changed")


def _cmd_render_policy(args: argparse.Namespace) -> None:
    intent = validate_founder_pep_intent(_read_json(args.intent))
    policy = render_live_founder_policy(
        mode=args.mode,
        intent=intent,
        operator_identity_store_user_id=_read_line(args.operator_subject_file),
    )
    _write_json(args.policy_out, policy)
    print("PASS: exact time-bound founder policy rendered privately")
    print("NO_AWS_CHANGE: the policy was not provisioned or assigned")


def _identity_admin(args: argparse.Namespace) -> tuple[AwsCli, str]:
    client = AwsCli(profile=args.identity_admin_profile)
    _management_identity(client)
    instance_arn, _ = _identity_center_instance(client)
    return client, instance_arn


def _create_or_validate_shell(
    client: AwsCli,
    *,
    instance_arn: str,
    records: dict[str, dict[str, Any]],
    name: str,
    exception_id: str,
    mode: str,
) -> str:
    record = records.get(name)
    if record is None:
        tags = _expected_permission_set_tags(exception_id, mode)
        response = client.run(
            "sso-admin", "create-permission-set", "--instance-arn", instance_arn,
            "--name", name,
            "--description", f"GUG-211 {exception_id} founder {mode} one-shot authority",
            "--session-duration", "PT1H",
            "--tags", *[f"Key={key},Value={value}" for key, value in tags.items()],
        )
        record = response.get("PermissionSet")
        if not isinstance(record, dict):
            raise FounderPepAuthorizationError("founder permission-set creation response is incomplete")
    permission_set_arn = _validate_permission_set(
        client,
        instance_arn=instance_arn,
        record=record,
        name=name,
        exception_id=exception_id,
        mode=mode,
    )
    current_policy = _inline_policy(client, instance_arn, permission_set_arn)
    shell = _permission_set_shell_policy()
    if current_policy is None:
        client.run(
            "sso-admin", "put-inline-policy-to-permission-set",
            "--instance-arn", instance_arn,
            "--permission-set-arn", permission_set_arn,
            "--inline-policy", json.dumps(shell, sort_keys=True, separators=(",", ":")),
        )
    elif current_policy != shell:
        raise FounderPepAuthorizationError("founder permission-set shell policy differs")
    if _account_assignments(client, instance_arn, permission_set_arn):
        raise FounderPepAuthorizationError("founder permission-set shell already has an assignment")
    _provision_permission_set(client, instance_arn, permission_set_arn)
    if _provisioned_accounts(client, instance_arn, permission_set_arn) != {AUTHORITY_ACCOUNT_ID}:
        raise FounderPepAuthorizationError("founder permission-set shell has foreign provisioning")
    return permission_set_arn


def _cmd_prepare_authority_shells(args: argparse.Namespace) -> None:
    if not args.allow_founder_shell_create:
        raise FounderPepAuthorizationError(
            "prepare-authority-shells requires --allow-founder-shell-create"
        )
    for path in (args.founder_plan_principal_out, args.founder_apply_principal_out):
        _output_path(path)
    if EXCEPTION_ID.fullmatch(args.exception_id) is None:
        raise FounderPepAuthorizationError("founder exception ID is invalid")
    session_name = _read_line(args.operator_session_name_file)
    client, instance_arn = _identity_admin(args)
    records = _permission_set_records(client, instance_arn)
    plan_arn = _create_or_validate_shell(
        client,
        instance_arn=instance_arn,
        records=records,
        name=FOUNDER_PLAN_PERMISSION_SET,
        exception_id=args.exception_id,
        mode="plan",
    )
    records = _permission_set_records(client, instance_arn)
    apply_arn = _create_or_validate_shell(
        client,
        instance_arn=instance_arn,
        records=records,
        name=FOUNDER_APPLY_PERMISSION_SET,
        exception_id=args.exception_id,
        mode="apply",
    )
    _write_private(
        args.founder_plan_principal_out,
        _principal_arn_from_permission_set(
            plan_arn, name=FOUNDER_PLAN_PERMISSION_SET, session_name=session_name
        ) + "\n",
    )
    _write_private(
        args.founder_apply_principal_out,
        _principal_arn_from_permission_set(
            apply_arn, name=FOUNDER_APPLY_PERMISSION_SET, session_name=session_name
        ) + "\n",
    )
    print("PASS: founder permission-set shells are deny-only, unassigned, and account-bound")
    print("AWS_CHANGE: two tagged deny-only permission sets provisioned without assignments")
    print("LIVE_EXECUTION_BLOCKED: no founder Plan or Apply authority was assigned")


def _normal_plan_assignments(client: AwsCli, instance_arn: str) -> list[dict[str, Any]]:
    records = _permission_set_records(client, instance_arn)
    normal = records.get(NORMAL_PLAN_PERMISSION_SET)
    if normal is None or not isinstance(normal.get("PermissionSetArn"), str):
        raise FounderPepAuthorizationError("normal bootstrap Plan permission set is missing")
    return _account_assignments(client, instance_arn, normal["PermissionSetArn"])


def _cmd_activate_authority(args: argparse.Namespace) -> None:
    if not args.allow_founder_authority_activation:
        raise FounderPepAuthorizationError(
            "activate-authority requires --allow-founder-authority-activation"
        )
    intent = validate_founder_pep_intent(_read_json(args.intent))
    operator_subject = _read_line(args.operator_subject_file)
    if canonical_digest({"identity_store_user_id": operator_subject}) != intent["operator_subject_digest"]:
        raise FounderPepAuthorizationError("founder operator subject differs from the reviewed intent")
    now = _now()
    start = _parse_time(intent[f"{args.mode}_not_before"], f"{args.mode} not_before")
    end = _parse_time(intent[f"{args.mode}_expires_at"], f"{args.mode} expires_at")
    if not start <= now < end:
        raise FounderPepAuthorizationError("founder authority activation is outside its AWS window")
    client, instance_arn = _identity_admin(args)
    if _normal_plan_assignments(client, instance_arn):
        raise FounderPepAuthorizationError("normal bootstrap Plan access is still assigned")
    records = _permission_set_records(client, instance_arn)
    name = FOUNDER_PLAN_PERMISSION_SET if args.mode == "plan" else FOUNDER_APPLY_PERMISSION_SET
    opposite = FOUNDER_APPLY_PERMISSION_SET if args.mode == "plan" else FOUNDER_PLAN_PERMISSION_SET
    record = records.get(name)
    opposite_record = records.get(opposite)
    if record is None or opposite_record is None:
        raise FounderPepAuthorizationError("founder permission-set shells are missing")
    permission_set_arn = _validate_permission_set(
        client,
        instance_arn=instance_arn,
        record=record,
        name=name,
        exception_id=intent["exception_id"],
        mode=args.mode,
    )
    opposite_arn = opposite_record.get("PermissionSetArn")
    if not isinstance(opposite_arn, str) or _account_assignments(
        client, instance_arn, opposite_arn
    ):
        raise FounderPepAuthorizationError("founder Plan and Apply authority would overlap")
    policy = render_live_founder_policy(
        mode=args.mode,
        intent=intent,
        operator_identity_store_user_id=operator_subject,
    )
    current_policy = _inline_policy(client, instance_arn, permission_set_arn)
    if current_policy not in (_permission_set_shell_policy(), policy):
        raise FounderPepAuthorizationError("founder permission-set policy differs before activation")
    if current_policy != policy:
        client.run(
            "sso-admin", "put-inline-policy-to-permission-set",
            "--instance-arn", instance_arn,
            "--permission-set-arn", permission_set_arn,
            "--inline-policy", json.dumps(policy, sort_keys=True, separators=(",", ":")),
        )
    _provision_permission_set(client, instance_arn, permission_set_arn)
    assignments = _account_assignments(client, instance_arn, permission_set_arn)
    expected_assignment = {
        "AccountId": AUTHORITY_ACCOUNT_ID,
        "PermissionSetArn": permission_set_arn,
        "PrincipalType": "USER",
        "PrincipalId": operator_subject,
    }
    if assignments and assignments != [expected_assignment]:
        raise FounderPepAuthorizationError("founder permission-set has a foreign assignment")
    if not assignments:
        response = client.run(
            "sso-admin", "create-account-assignment", "--instance-arn", instance_arn,
            "--target-id", AUTHORITY_ACCOUNT_ID, "--target-type", "AWS_ACCOUNT",
            "--permission-set-arn", permission_set_arn, "--principal-type", "USER",
            "--principal-id", operator_subject,
        )
        status = response.get("AccountAssignmentCreationStatus")
        request_id = status.get("RequestId") if isinstance(status, Mapping) else None
        _wait_identity_center(
            client,
            operation="create-assignment",
            instance_arn=instance_arn,
            request_id=request_id,
        )
    if _account_assignments(client, instance_arn, permission_set_arn) != [expected_assignment]:
        raise FounderPepAuthorizationError("founder permission-set assignment readback differs")
    if _inline_policy(client, instance_arn, permission_set_arn) != policy:
        raise FounderPepAuthorizationError("founder permission-set policy readback differs")
    print(f"PASS: founder {args.mode.title()} authority is exact, direct-user, and time-bound")
    print(f"POLICY_DIGEST: {canonical_digest(policy)}")
    print("AWS_CHANGE: one temporary direct-user Identity Center assignment")


def _revoke_assignment(
    client: AwsCli,
    *,
    instance_arn: str,
    permission_set_arn: str,
    operator_subject: str,
) -> None:
    assignments = _account_assignments(client, instance_arn, permission_set_arn)
    expected = {
        "AccountId": AUTHORITY_ACCOUNT_ID,
        "PermissionSetArn": permission_set_arn,
        "PrincipalType": "USER",
        "PrincipalId": operator_subject,
    }
    if any(item != expected for item in assignments):
        raise FounderPepAuthorizationError("founder permission-set has a foreign assignment")
    if assignments:
        response = client.run(
            "sso-admin", "delete-account-assignment", "--instance-arn", instance_arn,
            "--target-id", AUTHORITY_ACCOUNT_ID, "--target-type", "AWS_ACCOUNT",
            "--permission-set-arn", permission_set_arn, "--principal-type", "USER",
            "--principal-id", operator_subject,
        )
        status = response.get("AccountAssignmentDeletionStatus")
        request_id = status.get("RequestId") if isinstance(status, Mapping) else None
        _wait_identity_center(
            client,
            operation="delete-assignment",
            instance_arn=instance_arn,
            request_id=request_id,
        )
    if _account_assignments(client, instance_arn, permission_set_arn):
        raise FounderPepAuthorizationError("founder permission-set assignment revocation is incomplete")
    _provision_permission_set(client, instance_arn, permission_set_arn)
    if _provisioned_accounts(client, instance_arn, permission_set_arn) != {AUTHORITY_ACCOUNT_ID}:
        raise FounderPepAuthorizationError("founder retained deny is not provisioned exactly")


def _validate_revocation_window(
    *, intent: Mapping[str, Any], mode: str, now: datetime
) -> None:
    if mode == "plan":
        revoke_not_before = _parse_time(intent["plan_expires_at"], "Plan expires_at")
        revoke_before = _parse_time(intent["apply_not_before"], "Apply not_before")
    elif mode == "apply":
        revoke_not_before = _parse_time(intent["apply_not_before"], "Apply not_before")
        revoke_before = _parse_time(intent["apply_expires_at"], "Apply expires_at")
    else:
        raise FounderPepAuthorizationError("founder revocation mode is invalid")
    if not revoke_not_before <= now < revoke_before:
        raise FounderPepAuthorizationError(
            f"founder {mode} revocation is outside its exact closeout window"
        )


def _cmd_revoke_authority(args: argparse.Namespace) -> None:
    if not args.allow_founder_authority_revocation:
        raise FounderPepAuthorizationError(
            "revoke-authority requires --allow-founder-authority-revocation"
        )
    intent = validate_founder_pep_intent(_read_json(args.intent))
    operator_subject = _read_line(args.operator_subject_file)
    if canonical_digest({"identity_store_user_id": operator_subject}) != intent["operator_subject_digest"]:
        raise FounderPepAuthorizationError("founder operator subject differs from the reviewed intent")
    _validate_revocation_window(intent=intent, mode=args.mode, now=_now())
    client, instance_arn = _identity_admin(args)
    records = _permission_set_records(client, instance_arn)
    name = FOUNDER_PLAN_PERMISSION_SET if args.mode == "plan" else FOUNDER_APPLY_PERMISSION_SET
    record = records.get(name)
    if record is None:
        raise FounderPepAuthorizationError("founder permission set is missing during revocation")
    permission_set_arn = _validate_permission_set(
        client,
        instance_arn=instance_arn,
        record=record,
        name=name,
        exception_id=intent["exception_id"],
        mode=args.mode,
    )
    policy = render_live_founder_policy(
        mode=args.mode,
        intent=intent,
        operator_identity_store_user_id=operator_subject,
    )
    if _inline_policy(client, instance_arn, permission_set_arn) != policy:
        raise FounderPepAuthorizationError("founder retained time-deny policy differs")
    _revoke_assignment(
        client,
        instance_arn=instance_arn,
        permission_set_arn=permission_set_arn,
        operator_subject=operator_subject,
    )
    print(f"PASS: founder {args.mode.title()} direct-user assignment is absent")
    print(f"POLICY_DIGEST: {canonical_digest(policy)}")
    print("AWS_CHANGE: temporary assignment removed; time-deny policy retained and provisioned")


def _cmd_close_revocation(args: argparse.Namespace) -> None:
    if not args.allow_founder_revocation_close:
        raise FounderPepAuthorizationError(
            "close-revocation requires --allow-founder-revocation-close"
        )
    _output_path(args.revocation_out)
    intent = validate_founder_pep_intent(_read_json(args.intent))
    operator_subject = _read_line(args.operator_subject_file)
    if canonical_digest({"identity_store_user_id": operator_subject}) != intent["operator_subject_digest"]:
        raise FounderPepAuthorizationError("founder operator subject differs from the reviewed intent")
    client, instance_arn = _identity_admin(args)
    records = _permission_set_records(client, instance_arn)
    policies: dict[str, dict[str, Any]] = {}
    for mode, name in (
        ("plan", FOUNDER_PLAN_PERMISSION_SET),
        ("apply", FOUNDER_APPLY_PERMISSION_SET),
    ):
        record = records.get(name)
        if record is None:
            raise FounderPepAuthorizationError("founder permission set is missing during closeout")
        permission_set_arn = _validate_permission_set(
            client,
            instance_arn=instance_arn,
            record=record,
            name=name,
            exception_id=intent["exception_id"],
            mode=mode,
        )
        if _account_assignments(client, instance_arn, permission_set_arn):
            raise FounderPepAuthorizationError("founder assignment remains during closeout")
        if _provisioned_accounts(client, instance_arn, permission_set_arn) != {AUTHORITY_ACCOUNT_ID}:
            raise FounderPepAuthorizationError("founder time-deny policy is not retained")
        expected = render_live_founder_policy(
            mode=mode,
            intent=intent,
            operator_identity_store_user_id=operator_subject,
        )
        if _inline_policy(client, instance_arn, permission_set_arn) != expected:
            raise FounderPepAuthorizationError("founder retained policy differs during closeout")
        policies[mode] = expected
    normal_count = len(_normal_plan_assignments(client, instance_arn))
    store = _store()
    current = store.get_ledger(intent["exception_id"])
    now = _now()
    if now >= _parse_time(intent["apply_expires_at"], "Apply expires_at"):
        raise FounderPepAuthorizationError("founder revocation close missed the Apply session window")
    receipt = build_founder_pep_revocation(
        intent=intent,
        ledger=current,
        founder_plan_policy=policies["plan"],
        founder_apply_policy=policies["apply"],
        normal_plan_assignment_count=normal_count,
        founder_plan_assignment_count=0,
        founder_apply_assignment_count=0,
        founder_plan_deny_retained=True,
        founder_apply_deny_retained=True,
        verified_at=now,
    )
    closed = finalize_founder_revocation(
        intent=intent,
        ledger=current,
        receipt=receipt,
        now=now,
    )
    store.replace_ledger(
        ledger=closed,
        expected_version=current["version"],
        expected_digest=current["ledger_digest"],
        expected_state=current["state"],
        expected_plan_attempt_count=current["plan_attempt_count"],
        expected_apply_attempt_count=current["apply_attempt_count"],
    )
    _write_json(args.revocation_out, receipt)
    print("PASS: founder assignments are absent and revocation is durably closed")
    print(f"REVOCATION_DIGEST: {receipt['revocation_digest']}")
    print("AWS_CHANGE: one CAS ledger close; AWS-side time denials remain provisioned")


def _cmd_retire_authority(args: argparse.Namespace) -> None:
    if not args.allow_founder_authority_retirement:
        raise FounderPepAuthorizationError(
            "retire-authority requires --allow-founder-authority-retirement"
        )
    intent = validate_founder_pep_intent(_read_json(args.intent))
    receipt = validate_founder_pep_revocation(_read_json(args.revocation))
    if (
        receipt["intent_digest"] != intent["intent_digest"]
        or _now() < _parse_time(intent["deny_retain_until"], "deny retain_until")
    ):
        raise FounderPepAuthorizationError("founder authority retirement is early or unbound")
    client, instance_arn = _identity_admin(args)
    records = _permission_set_records(client, instance_arn)
    for mode, name in (
        ("plan", FOUNDER_PLAN_PERMISSION_SET),
        ("apply", FOUNDER_APPLY_PERMISSION_SET),
    ):
        record = records.get(name)
        if record is None:
            continue
        permission_set_arn = _validate_permission_set(
            client,
            instance_arn=instance_arn,
            record=record,
            name=name,
            exception_id=intent["exception_id"],
            mode=mode,
        )
        if _account_assignments(client, instance_arn, permission_set_arn):
            raise FounderPepAuthorizationError("founder assignment remains before retirement")
        client.run(
            "sso-admin", "delete-inline-policy-from-permission-set",
            "--instance-arn", instance_arn, "--permission-set-arn", permission_set_arn,
        )
        client.run(
            "sso-admin", "delete-permission-set", "--instance-arn", instance_arn,
            "--permission-set-arn", permission_set_arn,
        )
    remaining = _permission_set_records(client, instance_arn)
    if FOUNDER_PLAN_PERMISSION_SET in remaining or FOUNDER_APPLY_PERMISSION_SET in remaining:
        raise FounderPepAuthorizationError("founder permission-set retirement readback is incomplete")
    print("PASS: retained founder permission sets are absent after deny retention")
    print("AWS_CHANGE: temporary permission sets deleted; durable ledger and backend retained")


def _cmd_initialize(args: argparse.Namespace) -> None:
    if not args.allow_durable_ledger_create:
        raise FounderPepAuthorizationError("initialize requires --allow-durable-ledger-create")
    intent = validate_founder_pep_intent(_read_json(args.intent))
    store = _store()
    store.verify_table_controls()
    ledger = build_founder_pep_ledger(intent=intent, created_at=_now())
    store.create_ledger(ledger)
    print("PASS: durable founder PEP ledger created exactly once")
    print(f"LEDGER_DIGEST: {ledger['ledger_digest']}")
    print("AWS_CHANGE: one create-only DynamoDB item; no Change Set or infrastructure effect")


def _cmd_verify(args: argparse.Namespace) -> None:
    intent = validate_founder_pep_intent(_read_json(args.intent))
    store = _store()
    store.verify_table_controls()
    ledger = store.get_ledger(intent["exception_id"])
    if ledger["intent_digest"] != intent["intent_digest"]:
        raise FounderPepAuthorizationError("durable ledger differs from the reviewed intent")
    print("PASS: founder PEP table and exact ledger verified read-only")
    print(f"LEDGER_STATE: {ledger['state']}")
    print(f"LEDGER_DIGEST: {ledger['ledger_digest']}")
    print("NO_AWS_CHANGE: verification performed no mutation")


def _cmd_plan(args: argparse.Namespace) -> None:
    if not args.allow_founder_plan:
        raise FounderPepAuthorizationError("plan requires --allow-founder-plan")
    for path in (args.plan_out, args.exception_out):
        _output_path(path)
    intent = validate_founder_pep_intent(_read_json(args.intent))
    operator_subject = _read_line(args.operator_subject_file)
    founder_apply_principal_arn = _read_line(args.founder_apply_principal_file)
    if canonical_digest({"identity_store_user_id": operator_subject}) != intent["operator_subject_digest"]:
        raise FounderPepAuthorizationError("founder operator subject differs from the reviewed intent")
    if canonical_digest({"caller_arn": founder_apply_principal_arn}) != intent["apply_principal_digest"]:
        raise FounderPepAuthorizationError("founder Apply principal differs from the reviewed intent")
    client = AwsCli()
    caller_arn = _identity(client, FOUNDER_PLAN_PERMISSION_SET, intent)
    _pab(client)
    stack, resources = _stack_and_resources(client)
    _require_exact_founder_review_stack(stack, resources)
    _require_no_active_change_sets(client)
    if intent["template_sha256"] != "sha256:" + _sha256(TEMPLATE):
        raise FounderPepAuthorizationError("reviewed founder template digest changed")
    binding = _binding(args)
    store = _store()
    store.verify_table_controls()
    outputs: dict[str, dict[str, Any]] = {}

    def effect() -> Mapping[str, str]:
        current_stack, current_resources = _stack_and_resources(client)
        _require_exact_founder_review_stack(current_stack, current_resources)
        _require_no_active_change_sets(client)
        create_change_set_operation = ("cloudformation", "create-change-set")
        response = client.run(
            *create_change_set_operation,
            "--stack-name", binding.stack_name,
            "--change-set-name", intent["change_set_name"],
            "--change-set-type", "CREATE",
            "--description", "GUG-211 durable one-shot founder bootstrap",
            "--template-body", f"file://{TEMPLATE}",
            "--parameters",
            f"ParameterKey=AuthorityAccountId,ParameterValue={AUTHORITY_ACCOUNT_ID}",
            f"ParameterKey=StateKey,ParameterValue={binding.state_key}",
            "--tags",
            "Key=managed_by,Value=cloudformation",
            "Key=service,Value=scanalyze-platform-authority",
            "Key=work_package,Value=GUG-206",
        )
        change_set_id = response.get("Id")
        if not isinstance(change_set_id, str):
            raise FounderPepAuthorizationError("CloudFormation did not return a Change Set ID")
        client.wait(
            "cloudformation", "wait", "change-set-create-complete",
            "--change-set-name", change_set_id, "--stack-name", binding.stack_name,
        )
        described = _describe_change_set(client, change_set_id=change_set_id, intent=intent)
        created_at = _now()
        plan = build_bootstrap_plan(
            binding=binding,
            caller_account_id=AUTHORITY_ACCOUNT_ID,
            caller_arn=caller_arn,
            template_sha256=_sha256(TEMPLATE),
            change_set_id=change_set_id,
            change_set_type="CREATE",
            resource_changes=_changes(described),
            account_public_access_block_before=PUBLIC_ACCESS_BLOCK,
            created_at=created_at,
            expires_at=_parse_time(intent["apply_expires_at"], "Apply expires_at"),
            initiator_id=intent["operator_id"],
        )
        exception = build_founder_bootstrap_exception(
            plan=plan,
            exception_id=intent["exception_id"],
            operator_id=intent["operator_id"],
            operator_identity_store_user_id=operator_subject,
            founder_plan_principal_arn=caller_arn,
            founder_apply_principal_arn=founder_apply_principal_arn,
            risk_acceptance_id=intent["risk_acceptance_id"],
            created_at=created_at,
            standard_plan_access_revoked_at=_parse_time(intent["normal_plan_revoked_at"], "normal Plan revoked_at"),
            standard_plan_session_quarantine_until=_parse_time(intent["plan_not_before"], "Plan not_before"),
            founder_plan_not_before=_parse_time(intent["plan_not_before"], "Plan not_before"),
            founder_plan_expires_at=_parse_time(intent["plan_expires_at"], "Plan expires_at"),
            founder_apply_not_before=_parse_time(intent["apply_not_before"], "Apply not_before"),
            founder_apply_expires_at=_parse_time(intent["apply_expires_at"], "Apply expires_at"),
        )
        outputs["plan"] = plan
        outputs["exception"] = exception
        return {
            "change_set_id": change_set_id,
            "plan_record_digest": plan["record_digest"],
            "exception_digest": exception["exception_digest"],
        }

    ledger = run_founder_plan_once(
        intent=intent,
        store=store,
        caller_arn=caller_arn,
        now=_now(),
        effect=effect,
        clock=_now,
    )
    _write_json(args.plan_out, outputs["plan"])
    _write_json(args.exception_out, outputs["exception"])
    print("PASS: one exact founder Change Set created, reviewed, and durably bound")
    print(f"LEDGER_DIGEST: {ledger['ledger_digest']}")
    print("AWS_CHANGE: Change Set metadata only; infrastructure was not executed")


def _cmd_apply(args: argparse.Namespace) -> None:
    if not args.allow_founder_apply:
        raise FounderPepAuthorizationError("apply requires --allow-founder-apply")
    intent = validate_founder_pep_intent(_read_json(args.intent))
    plan = _read_json(args.plan)
    exception = _read_json(args.exception)
    validate_founder_bootstrap_exception(exception)
    _validate_plan_contract(plan, intent)
    if plan.get("record_digest") != exception.get("plan_record_digest"):
        raise FounderPepAuthorizationError("founder Plan and exception digests conflict")
    change_set_id = plan.get("change_set_id")
    if not isinstance(change_set_id, str) or change_set_id != exception.get("change_set_id"):
        raise FounderPepAuthorizationError("founder Change Set binding conflicts")
    client = AwsCli()
    caller_arn = _identity(client, FOUNDER_APPLY_PERMISSION_SET, intent)
    _pab(client)
    stack, resources = _stack_and_resources(client)
    _require_exact_founder_review_stack(stack, resources)
    _describe_change_set(client, change_set_id=change_set_id, intent=intent)
    store = _store()
    store.verify_table_controls()
    reviewed_ledger = store.get_ledger(intent["exception_id"])
    if (
        reviewed_ledger.get("intent_digest") != intent["intent_digest"]
        or reviewed_ledger.get("plan_record_digest") != plan.get("record_digest")
        or reviewed_ledger.get("exception_digest") != exception.get("exception_digest")
        or reviewed_ledger.get("change_set_id") != change_set_id
    ):
        raise FounderPepAuthorizationError("durable reviewed evidence differs from private inputs")
    verification: dict[str, Any] = {}

    def effect() -> None:
        _describe_change_set(client, change_set_id=change_set_id, intent=intent)
        current_stack, current_resources = _stack_and_resources(client)
        _require_exact_founder_review_stack(current_stack, current_resources)
        client.run(
            "cloudformation", "execute-change-set", "--change-set-name", change_set_id,
            "--stack-name", "scanalyze-platform-authority-state-backend", "--no-disable-rollback",
        )
        client.wait(
            "cloudformation", "wait", "stack-create-complete",
            "--stack-name", "scanalyze-platform-authority-state-backend",
        )
        final_stack, final_resources = _stack_and_resources(client)
        if final_stack.get("StackStatus") != "CREATE_COMPLETE":
            raise FounderPepAuthorizationError("founder bootstrap did not reach CREATE_COMPLETE")
        actual = sorted(
            (
                item.get("LogicalResourceId"),
                item.get("ResourceType"),
                item.get("ResourceStatus"),
            )
            for item in final_resources
        )
        expected = sorted(
            (
                item["logical_resource_id"],
                item["resource_type"],
                "CREATE_COMPLETE",
            )
            for item in EXPECTED_RESOURCE_CHANGES
        )
        if actual != expected:
            raise FounderPepAuthorizationError("founder bootstrap resource readback is invalid")
        _pab(client)
        verification.update(
            _verify_backend_controls(
                client,
                stack=final_stack,
                plan=plan,
                caller_arn=caller_arn,
            )
        )

    ledger = run_founder_apply_once(
        intent=intent,
        store=store,
        caller_arn=caller_arn,
        change_set_id=change_set_id,
        now=_now(),
        effect=effect,
        clock=_now,
    )
    print("PASS: exact founder Change Set executed once with durable CAS")
    print(f"LEDGER_DIGEST: {ledger['ledger_digest']}")
    print(f"VERIFICATION_DIGEST: {verification['verification_digest']}")
    print("LIVE_STATUS: backend stack reached CREATE_COMPLETE; revocation remains mandatory")


def _common_intent_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--intent", type=Path, required=True)


def _identity_admin_input(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--identity-admin-profile", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Durable one-shot founder bootstrap PEP")
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare-intent", help="Create the private reviewed PEP intent")
    prepare.add_argument("--exception-id", required=True)
    prepare.add_argument("--operator-id", required=True)
    prepare.add_argument("--operator-subject-file", type=Path, required=True)
    prepare.add_argument("--founder-plan-principal-file", type=Path, required=True)
    prepare.add_argument("--founder-apply-principal-file", type=Path, required=True)
    prepare.add_argument("--risk-acceptance-id", required=True)
    for name in (
        "created-at", "normal-plan-revoked-at", "plan-not-before", "plan-expires-at",
        "apply-not-before", "apply-expires-at", "deny-retain-until",
    ):
        prepare.add_argument(f"--{name}", required=True)
    prepare.add_argument("--intent-out", type=Path, required=True)
    prepare.set_defaults(handler=_cmd_prepare_intent)

    render = commands.add_parser("render-policy", help="Render a private live permission policy")
    _common_intent_inputs(render)
    render.add_argument("--mode", choices=("plan", "apply"), required=True)
    render.add_argument("--operator-subject-file", type=Path, required=True)
    render.add_argument("--policy-out", type=Path, required=True)
    render.set_defaults(handler=_cmd_render_policy)

    shells = commands.add_parser(
        "prepare-authority-shells",
        help="Create deny-only unassigned founder permission-set shells",
    )
    shells.add_argument("--exception-id", required=True)
    shells.add_argument("--operator-session-name-file", type=Path, required=True)
    shells.add_argument("--founder-plan-principal-out", type=Path, required=True)
    shells.add_argument("--founder-apply-principal-out", type=Path, required=True)
    shells.add_argument("--allow-founder-shell-create", action="store_true")
    _identity_admin_input(shells)
    shells.set_defaults(handler=_cmd_prepare_authority_shells)

    activate = commands.add_parser(
        "activate-authority",
        help="Provision and assign one exact time-bound founder authority",
    )
    _common_intent_inputs(activate)
    activate.add_argument("--mode", choices=("plan", "apply"), required=True)
    activate.add_argument("--operator-subject-file", type=Path, required=True)
    activate.add_argument("--allow-founder-authority-activation", action="store_true")
    _identity_admin_input(activate)
    activate.set_defaults(handler=_cmd_activate_authority)

    revoke = commands.add_parser(
        "revoke-authority",
        help="Remove one direct-user assignment and retain its time denial",
    )
    _common_intent_inputs(revoke)
    revoke.add_argument("--mode", choices=("plan", "apply"), required=True)
    revoke.add_argument("--operator-subject-file", type=Path, required=True)
    revoke.add_argument("--allow-founder-authority-revocation", action="store_true")
    _identity_admin_input(revoke)
    revoke.set_defaults(handler=_cmd_revoke_authority)

    close = commands.add_parser(
        "close-revocation",
        help="Read back both revocations and durably close the successful exception",
    )
    _common_intent_inputs(close)
    close.add_argument("--operator-subject-file", type=Path, required=True)
    close.add_argument("--revocation-out", type=Path, required=True)
    close.add_argument("--allow-founder-revocation-close", action="store_true")
    _identity_admin_input(close)
    close.set_defaults(handler=_cmd_close_revocation)

    retire = commands.add_parser(
        "retire-authority",
        help="Delete temporary permission sets after the deny-retention window",
    )
    _common_intent_inputs(retire)
    retire.add_argument("--revocation", type=Path, required=True)
    retire.add_argument("--allow-founder-authority-retirement", action="store_true")
    _identity_admin_input(retire)
    retire.set_defaults(handler=_cmd_retire_authority)

    initialize = commands.add_parser("initialize-ledger", help="Create the durable zero-attempt ledger")
    _common_intent_inputs(initialize)
    initialize.add_argument("--allow-durable-ledger-create", action="store_true")
    initialize.set_defaults(handler=_cmd_initialize)

    verify = commands.add_parser("verify-ledger", help="Read-only durable table and ledger verification")
    _common_intent_inputs(verify)
    verify.set_defaults(handler=_cmd_verify)

    plan = commands.add_parser("plan", help="CAS then create exactly one reviewed Change Set")
    _common_intent_inputs(plan)
    plan.add_argument("--operator-subject-file", type=Path, required=True)
    plan.add_argument("--founder-apply-principal-file", type=Path, required=True)
    plan.add_argument("--destination-account-id", action="append", required=True)
    plan.add_argument("--plan-out", type=Path, required=True)
    plan.add_argument("--exception-out", type=Path, required=True)
    plan.add_argument("--allow-founder-plan", action="store_true")
    plan.set_defaults(handler=_cmd_plan)

    apply_parser = commands.add_parser("apply", help="CAS then execute exactly one reviewed Change Set")
    _common_intent_inputs(apply_parser)
    apply_parser.add_argument("--plan", type=Path, required=True)
    apply_parser.add_argument("--exception", type=Path, required=True)
    apply_parser.add_argument("--allow-founder-apply", action="store_true")
    apply_parser.set_defaults(handler=_cmd_apply)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except (BootstrapAuthorizationError, FounderPepAuthorizationError, AwsEffectError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
