#!/usr/bin/env python3
"""Plan, approve, apply, and verify the dedicated authority state backend.

The CLI accepts only an SSO profile through ``AWS_PROFILE``.  It never reads a
credential file, never prints AWS responses or principal identifiers, and
writes operational receipts only to exclusive mode-0600 paths outside Git.
``plan`` creates a CloudFormation change set but does not execute it. ``apply``
requires a different live AWS principal to approve and execute that exact
change set.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_bootstrap import (  # noqa: E402
    PUBLIC_ACCESS_BLOCK,
    BootstrapAuthorizationError,
    BootstrapBinding,
    authorize_bootstrap_apply,
    build_bootstrap_approval,
    build_bootstrap_plan,
    build_bootstrap_verification,
    canonical_digest,
    render_backend_config,
    render_bootstrap_iam_policy,
)


TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-state-backend.yaml"
PLAN_POLICY_TEMPLATE = REPO_ROOT / "policies/iam/platform-authority-bootstrap-plan-role.json"
APPLY_POLICY_TEMPLATE = REPO_ROOT / "policies/iam/platform-authority-bootstrap-apply-role.json"
FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
SSO_ASSUMED_ROLE_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):sts::(?P<account>[0-9]{12}):assumed-role/"
    r"(?P<role>AWSReservedSSO_[A-Za-z0-9+=,.@_-]+_[0-9A-Fa-f]{16})/"
    r"[A-Za-z0-9+=,.@_-]{2,64}$"
)
AWS_PERMISSION_SET_NAME = re.compile(r"^[A-Za-z0-9_+=,.@-]{1,32}$")
PLAN_PERMISSION_SET = "ScanalyzeAuthorityBootstrapPlan"
APPLY_PERMISSION_SET = "ScanalyzeAuthorityBootstrapApply"
REQUIRED_BUCKET_POLICY_SIDS = frozenset(
    {
        "DenyInsecureTransport",
        "DenyCrossAccountAccess",
        "DenyUnencryptedObjectWrites",
        "DenyWrongKmsKey",
        "DenyUnexpectedObjectKeys",
        "DenyStateDeletion",
    }
)


class AwsCliError(RuntimeError):
    """An AWS CLI operation failed without exposing its response."""


def _validate_permission_set_name(permission_set: str) -> None:
    """Reject names that IAM Identity Center cannot create portably."""
    if AWS_PERMISSION_SET_NAME.fullmatch(permission_set) is None:
        raise BootstrapAuthorizationError(
            "permission-set name violates the AWS portable contract"
        )


def _strict_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapAuthorizationError(f"invalid operational JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise BootstrapAuthorizationError("operational JSON must be an object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapAuthorizationError(f"duplicate operational JSON key: {key}")
        result[key] = value
    return result


def _outside_repo(path: Path) -> Path:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise BootstrapAuthorizationError("operational output must be outside the repository")
    if destination.exists() or destination.is_symlink():
        raise BootstrapAuthorizationError("operational output path must not already exist")
    if not destination.parent.is_dir():
        raise BootstrapAuthorizationError("operational output parent does not exist")
    return destination


def _write_private(path: Path, content: str) -> None:
    destination = _outside_repo(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.write(descriptor, content.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    _write_private(path, json.dumps(document, sort_keys=True, indent=2) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise BootstrapAuthorizationError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapAuthorizationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BootstrapAuthorizationError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


class AwsCli:
    """Small AWS CLI adapter with sanitized failures."""

    def __init__(self, *, region: str) -> None:
        self.region = region

    def _command(self, *parts: str) -> list[str]:
        return [
            "aws",
            *parts,
            "--region",
            self.region,
            "--output",
            "json",
            "--no-cli-pager",
        ]

    def run(self, *parts: str) -> dict[str, Any]:
        completed = subprocess.run(
            self._command(*parts),
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            operation = " ".join(parts[:2])
            raise AwsCliError(f"AWS operation failed: {operation}")
        if not completed.stdout.strip():
            return {}
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AwsCliError("AWS operation returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AwsCliError("AWS operation returned a non-object response")
        return value

    def run_allow_missing(self, *parts: str, missing_markers: Sequence[str]) -> dict[str, Any] | None:
        completed = subprocess.run(
            self._command(*parts),
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            if any(marker in completed.stderr for marker in missing_markers):
                return None
            operation = " ".join(parts[:2])
            raise AwsCliError(f"AWS operation failed: {operation}")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AwsCliError("AWS operation returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise AwsCliError("AWS operation returned a non-object response")
        return value

    def wait(self, *parts: str) -> None:
        completed = subprocess.run(
            ["aws", *parts, "--region", self.region, "--no-cli-pager"],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            operation = " ".join(parts[:3])
            raise AwsCliError(f"AWS waiter failed: {operation}")


def _require_sso_environment(region: str) -> None:
    if not os.environ.get("AWS_PROFILE"):
        raise BootstrapAuthorizationError("AWS_PROFILE is required for the SSO bootstrap session")
    present = sorted(name for name in FORBIDDEN_CREDENTIAL_ENV if os.environ.get(name))
    if present:
        raise BootstrapAuthorizationError("static or ambient AWS credential material is forbidden")
    configured_regions = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if configured_regions and configured_regions != {region}:
        raise BootstrapAuthorizationError("ambient AWS region conflicts with authority binding")


def _binding(args: argparse.Namespace) -> BootstrapBinding:
    return BootstrapBinding(
        authority_account_id=args.authority_account_id,
        region=args.region,
        stack_name="scanalyze-platform-authority-state-backend",
        state_bucket_name=(
            f"scanalyze-platform-authority-{args.authority_account_id}-{args.region}-state"
        ),
        state_key="platform-authority/terraform.tfstate",
        destination_account_ids=tuple(args.destination_account_id),
    )


def _identity(client: AwsCli, binding: BootstrapBinding) -> tuple[str, str]:
    identity = client.run("sts", "get-caller-identity")
    account_id = identity.get("Account")
    caller_arn = identity.get("Arn")
    if not isinstance(account_id, str) or not isinstance(caller_arn, str):
        raise BootstrapAuthorizationError("STS identity response is incomplete")
    match = SSO_ASSUMED_ROLE_ARN.fullmatch(caller_arn)
    if match is None or match.group("account") != account_id:
        raise BootstrapAuthorizationError("caller is not an IAM Identity Center session")
    binding.authorize_identity(caller_account_id=account_id, caller_region=client.region)
    return account_id, caller_arn


def _require_permission_set(caller_arn: str, permission_set: str) -> None:
    _validate_permission_set_name(permission_set)
    match = SSO_ASSUMED_ROLE_ARN.fullmatch(caller_arn)
    expected_role = re.compile(
        rf"AWSReservedSSO_{re.escape(permission_set)}_[0-9A-Fa-f]{{16}}"
    )
    if match is None or expected_role.fullmatch(match.group("role")) is None:
        raise BootstrapAuthorizationError(
            f"caller does not use the canonical {permission_set} permission set"
        )


def _account_public_access_block(
    client: AwsCli, account_id: str
) -> dict[str, bool] | None:
    response = client.run_allow_missing(
        "s3control",
        "get-public-access-block",
        "--account-id",
        account_id,
        missing_markers=("NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"),
    )
    if response is None:
        return None
    configuration = response.get("PublicAccessBlockConfiguration")
    if not isinstance(configuration, dict) or set(configuration) != set(PUBLIC_ACCESS_BLOCK):
        raise BootstrapAuthorizationError("account public-access block response is ambiguous")
    return {key: configuration.get(key) is True for key in PUBLIC_ACCESS_BLOCK}


def _stack(client: AwsCli, stack_name: str) -> dict[str, Any] | None:
    response = client.run_allow_missing(
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        stack_name,
        missing_markers=("does not exist", "ValidationError"),
    )
    if response is None:
        return None
    stacks = response.get("Stacks")
    if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], dict):
        raise BootstrapAuthorizationError("CloudFormation stack response is ambiguous")
    return stacks[0]


def _preflight(
    client: AwsCli,
    binding: BootstrapBinding,
    *,
    allow_empty_review_stack: bool = False,
) -> tuple[str, str, dict[str, bool] | None]:
    _require_sso_environment(binding.region)
    account_id, caller_arn = _identity(client, binding)
    existing_stack = _stack(client, binding.stack_name)
    existing_pab = _account_public_access_block(client, account_id)
    if existing_stack is not None:
        if not allow_empty_review_stack or existing_stack.get("StackStatus") != "REVIEW_IN_PROGRESS":
            raise BootstrapAuthorizationError(
                "bootstrap stack already exists; use verify or the reviewed recovery procedure"
            )
        resources = client.run(
            "cloudformation",
            "list-stack-resources",
            "--stack-name",
            binding.stack_name,
        ).get("StackResourceSummaries")
        if not isinstance(resources, list) or resources:
            raise BootstrapAuthorizationError(
                "existing review stack is not empty; recovery plan is forbidden"
            )
    client.run(
        "cloudformation",
        "validate-template",
        "--template-body",
        f"file://{TEMPLATE}",
    )
    return account_id, caller_arn, existing_pab


def _normalize_changes(response: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    changes = response.get("Changes")
    if not isinstance(changes, list):
        raise BootstrapAuthorizationError("CloudFormation change set has no reviewable changes")
    normalized: list[dict[str, str]] = []
    for item in changes:
        resource = item.get("ResourceChange") if isinstance(item, dict) else None
        if not isinstance(resource, dict):
            raise BootstrapAuthorizationError("CloudFormation resource change is malformed")
        normalized.append(
            {
                "action": str(resource.get("Action", "")),
                "logical_resource_id": str(resource.get("LogicalResourceId", "")),
                "resource_type": str(resource.get("ResourceType", "")),
                "replacement": str(resource.get("Replacement", "False")),
            }
        )
    return tuple(sorted(normalized, key=lambda item: item["logical_resource_id"]))


def _require_plan_matches_binding(
    plan: Mapping[str, Any], binding: BootstrapBinding
) -> None:
    expected_digest = canonical_digest(
        {key: value for key, value in plan.items() if key != "record_digest"}
    )
    if plan.get("record_digest") != expected_digest:
        raise BootstrapAuthorizationError("bootstrap plan digest mismatch")
    for field, expected in binding.as_record().items():
        if plan.get(field) != expected:
            raise BootstrapAuthorizationError(f"bootstrap plan binding mismatch: {field}")
    if plan.get("template_sha256") != "sha256:" + _sha256(TEMPLATE):
        raise BootstrapAuthorizationError("bootstrap template digest mismatch")


def _cmd_preflight(args: argparse.Namespace) -> None:
    binding = _binding(args)
    client = AwsCli(region=binding.region)
    _, _, existing_pab = _preflight(client, binding)
    status = "configured" if existing_pab == PUBLIC_ACCESS_BLOCK else "requires planned update"
    print("PASS: exact dedicated platform-authority identity and template verified")
    print(f"INFO: account public-access block {status}")
    print("NO_CHANGE: no AWS resources or settings were modified")


def _cmd_render_plan_policy(args: argparse.Namespace) -> None:
    binding = _binding(args)
    _outside_repo(args.policy_out)
    policy = render_bootstrap_iam_policy(
        policy_template=_strict_object(PLAN_POLICY_TEMPLATE),
        binding=binding,
    )
    _write_json(args.policy_out, policy)
    print("PASS: exact bootstrap Plan permission policy rendered privately")
    print("NO_CHANGE: no AWS call or mutation was performed")


def _cmd_render_apply_policy(args: argparse.Namespace) -> None:
    binding = _binding(args)
    _outside_repo(args.policy_out)
    plan = _strict_object(args.plan)
    _require_plan_matches_binding(plan, binding)
    if _now() >= _parse_time(plan.get("expires_at"), "plan expires_at"):
        raise BootstrapAuthorizationError("expired bootstrap plan cannot render Apply authority")
    policy = render_bootstrap_iam_policy(
        policy_template=_strict_object(APPLY_POLICY_TEMPLATE),
        binding=binding,
        change_set_id=str(plan.get("change_set_id", "")),
    )
    _write_json(args.policy_out, policy)
    print("PASS: exact Change Set-bound Apply permission policy rendered privately")
    print("NO_CHANGE: no AWS call or mutation was performed")


def _cmd_plan(args: argparse.Namespace) -> None:
    if not args.allow_change_set_write:
        raise BootstrapAuthorizationError("plan requires --allow-change-set-write")
    _outside_repo(args.plan_out)
    binding = _binding(args)
    client = AwsCli(region=binding.region)
    account_id, caller_arn, existing_pab = _preflight(
        client,
        binding,
        allow_empty_review_stack=True,
    )
    _require_permission_set(caller_arn, PLAN_PERMISSION_SET)
    created_at = _now()
    change_set_name = "scanalyze-platform-authority-bootstrap-" + created_at.strftime(
        "%Y%m%d%H%M%S"
    )
    response = client.run(
        "cloudformation",
        "create-change-set",
        "--stack-name",
        binding.stack_name,
        "--change-set-name",
        change_set_name,
        "--change-set-type",
        "CREATE",
        "--description",
        "GUG-206 exact dedicated platform-authority backend bootstrap",
        "--template-body",
        f"file://{TEMPLATE}",
        "--parameters",
        f"ParameterKey=AuthorityAccountId,ParameterValue={binding.authority_account_id}",
        f"ParameterKey=StateKey,ParameterValue={binding.state_key}",
        "--tags",
        "Key=managed_by,Value=cloudformation",
        "Key=service,Value=scanalyze-platform-authority",
        "Key=work_package,Value=GUG-206",
    )
    change_set_id = response.get("Id")
    if not isinstance(change_set_id, str):
        raise BootstrapAuthorizationError("CloudFormation did not return a change set ID")
    client.wait(
        "cloudformation",
        "wait",
        "change-set-create-complete",
        "--change-set-name",
        change_set_id,
        "--stack-name",
        binding.stack_name,
    )
    described = client.run(
        "cloudformation",
        "describe-change-set",
        "--change-set-name",
        change_set_id,
        "--stack-name",
        binding.stack_name,
    )
    if described.get("Status") != "CREATE_COMPLETE" or described.get("ExecutionStatus") != "AVAILABLE":
        raise BootstrapAuthorizationError("CloudFormation change set is not executable")
    plan = build_bootstrap_plan(
        binding=binding,
        caller_account_id=account_id,
        caller_arn=caller_arn,
        template_sha256=_sha256(TEMPLATE),
        change_set_id=change_set_id,
        change_set_type="CREATE",
        resource_changes=_normalize_changes(described),
        account_public_access_block_before=existing_pab,
        created_at=created_at,
        expires_at=created_at + timedelta(hours=1),
        initiator_id=args.initiator_id,
    )
    _write_json(args.plan_out, plan)
    print("PASS: exact CloudFormation change set created but not executed")
    print(f"PLAN_DIGEST: {plan['record_digest']}")
    print("AWS_CHANGE: change-set metadata only; infrastructure remains unchanged")


def _cmd_approve(args: argparse.Namespace) -> None:
    binding = _binding(args)
    _outside_repo(args.approval_out)
    _require_sso_environment(binding.region)
    client = AwsCli(region=binding.region)
    _, caller_arn = _identity(client, binding)
    _require_permission_set(caller_arn, APPLY_PERMISSION_SET)
    plan = _strict_object(args.plan)
    _require_plan_matches_binding(plan, binding)
    now = _now()
    plan_expires = _parse_time(plan.get("expires_at"), "plan expires_at")
    approval = build_bootstrap_approval(
        plan=plan,
        initiator_id=str(plan.get("initiator_id", "")),
        approver_id=args.approver_id,
        approver_arn=caller_arn,
        approved_at=now,
        expires_at=min(plan_expires, now + timedelta(minutes=30)),
    )
    _write_json(args.approval_out, approval)
    print("PASS: independent live AWS principal approved the exact bootstrap plan")
    print(f"APPROVAL_DIGEST: {approval['approval_digest']}")
    print("NO_CHANGE: approval did not execute the change set")


def _stack_outputs(stack: Mapping[str, Any]) -> dict[str, str]:
    outputs = stack.get("Outputs")
    if not isinstance(outputs, list):
        raise BootstrapAuthorizationError("bootstrap stack outputs are missing")
    result: dict[str, str] = {}
    for output in outputs:
        if not isinstance(output, dict):
            raise BootstrapAuthorizationError("bootstrap stack output is malformed")
        key = output.get("OutputKey")
        value = output.get("OutputValue")
        if not isinstance(key, str) or not isinstance(value, str) or key in result:
            raise BootstrapAuthorizationError("bootstrap stack outputs are ambiguous")
        result[key] = value
    return result


def _all_public_access_blocked(value: Mapping[str, Any] | None) -> bool:
    return value is not None and dict(value) == PUBLIC_ACCESS_BLOCK


def _verify_live(
    *, client: AwsCli, binding: BootstrapBinding, plan: Mapping[str, Any], caller_arn: str
) -> tuple[dict[str, Any], str]:
    stack = _stack(client, binding.stack_name)
    if stack is None:
        raise BootstrapAuthorizationError("bootstrap stack does not exist")
    outputs = _stack_outputs(stack)
    bucket = outputs.get("StateBucketName")
    state_key = outputs.get("StateKey")
    kms_key_arn = outputs.get("StateKmsKeyArn")
    if not all(isinstance(value, str) for value in (bucket, state_key, kms_key_arn)):
        raise BootstrapAuthorizationError("bootstrap stack output binding is incomplete")
    assert isinstance(bucket, str) and isinstance(state_key, str) and isinstance(kms_key_arn, str)
    account_pab = _account_public_access_block(client, binding.authority_account_id)
    bucket_pab_response = client.run("s3api", "get-public-access-block", "--bucket", bucket)
    bucket_pab = bucket_pab_response.get("PublicAccessBlockConfiguration")
    versioning = client.run("s3api", "get-bucket-versioning", "--bucket", bucket)
    encryption = client.run("s3api", "get-bucket-encryption", "--bucket", bucket)
    ownership = client.run("s3api", "get-bucket-ownership-controls", "--bucket", bucket)
    policy_response = client.run("s3api", "get-bucket-policy", "--bucket", bucket)
    rotation = client.run("kms", "get-key-rotation-status", "--key-id", kms_key_arn)
    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    encryption_rule = rules[0] if isinstance(rules, list) and len(rules) == 1 else {}
    encryption_default = encryption_rule.get("ApplyServerSideEncryptionByDefault", {})
    ownership_rules = ownership.get("OwnershipControls", {}).get("Rules", [])
    policy_value = policy_response.get("Policy")
    try:
        policy = json.loads(policy_value) if isinstance(policy_value, str) else {}
    except json.JSONDecodeError as exc:
        raise BootstrapAuthorizationError("state bucket policy response is malformed") from exc
    statements = policy.get("Statement", []) if isinstance(policy, dict) else []
    policy_sids = {
        statement.get("Sid") for statement in statements if isinstance(statement, dict)
    }
    if not REQUIRED_BUCKET_POLICY_SIDS <= policy_sids:
        raise BootstrapAuthorizationError("state bucket policy is missing a required deny")
    controls = {
        "account_public_access_blocked": _all_public_access_blocked(account_pab),
        "bucket_public_access_blocked": (
            isinstance(bucket_pab, dict) and _all_public_access_blocked(bucket_pab)
        ),
        "bucket_owner_enforced": (
            isinstance(ownership_rules, list)
            and len(ownership_rules) == 1
            and ownership_rules[0].get("ObjectOwnership") == "BucketOwnerEnforced"
        ),
        "bucket_versioning_enabled": versioning.get("Status") == "Enabled",
        "default_encryption": encryption_default.get("SSEAlgorithm"),
        "bucket_key_enabled": encryption_rule.get("BucketKeyEnabled") is True,
        "kms_rotation_enabled": rotation.get("KeyRotationEnabled") is True,
        "native_lockfile_enabled": True,
    }
    record = build_bootstrap_verification(
        plan=plan,
        binding=binding,
        caller_arn=caller_arn,
        stack_status=str(stack.get("StackStatus", "")),
        state_bucket_name=bucket,
        state_key=state_key,
        state_kms_key_arn=kms_key_arn,
        controls=controls,
        verified_at=_now(),
    )
    return record, render_backend_config(binding=binding, kms_key_arn=kms_key_arn)


def _describe_exact_change_set(
    client: AwsCli, binding: BootstrapBinding, plan: Mapping[str, Any]
) -> dict[str, Any]:
    change_set_id = plan.get("change_set_id")
    if not isinstance(change_set_id, str):
        raise BootstrapAuthorizationError("bootstrap plan change set ID is missing")
    response = client.run(
        "cloudformation",
        "describe-change-set",
        "--change-set-name",
        change_set_id,
        "--stack-name",
        binding.stack_name,
    )
    if response.get("Status") != "CREATE_COMPLETE" or response.get("ExecutionStatus") != "AVAILABLE":
        raise BootstrapAuthorizationError("reviewed bootstrap change set is no longer executable")
    if list(_normalize_changes(response)) != plan.get("planned_resource_changes"):
        raise BootstrapAuthorizationError("live change set differs from reviewed bootstrap plan")
    return response


def _cmd_apply(args: argparse.Namespace) -> None:
    if not args.allow_bootstrap_apply:
        raise BootstrapAuthorizationError("apply requires --allow-bootstrap-apply")
    verification_path = _outside_repo(args.verification_out)
    backend_path = _outside_repo(args.backend_config_out)
    if verification_path == backend_path:
        raise BootstrapAuthorizationError("operational output paths must be distinct")
    binding = _binding(args)
    _require_sso_environment(binding.region)
    client = AwsCli(region=binding.region)
    account_id, caller_arn = _identity(client, binding)
    _require_permission_set(caller_arn, APPLY_PERMISSION_SET)
    review_stack = _stack(client, binding.stack_name)
    if review_stack is None or review_stack.get("StackStatus") != "REVIEW_IN_PROGRESS":
        raise BootstrapAuthorizationError("bootstrap stack is not in exact review state")
    plan = _strict_object(args.plan)
    approval = _strict_object(args.approval)
    authorize_bootstrap_apply(
        plan=plan,
        approval=approval,
        binding=binding,
        caller_account_id=account_id,
        caller_region=binding.region,
        caller_arn=caller_arn,
        current_template_sha256=_sha256(TEMPLATE),
        now=_now(),
    )
    _describe_exact_change_set(client, binding, plan)
    client.run(
        "s3control",
        "put-public-access-block",
        "--account-id",
        binding.authority_account_id,
        "--public-access-block-configuration",
        json.dumps(PUBLIC_ACCESS_BLOCK, separators=(",", ":")),
    )
    client.run(
        "cloudformation",
        "execute-change-set",
        "--change-set-name",
        str(plan["change_set_id"]),
        "--stack-name",
        binding.stack_name,
        "--no-disable-rollback",
    )
    client.wait(
        "cloudformation",
        "wait",
        "stack-create-complete",
        "--stack-name",
        binding.stack_name,
    )
    verification, backend = _verify_live(
        client=client,
        binding=binding,
        plan=plan,
        caller_arn=caller_arn,
    )
    _write_json(args.verification_out, verification)
    _write_private(args.backend_config_out, backend)
    print("PASS: exact approved platform-authority backend change set executed once")
    print(f"VERIFICATION_DIGEST: {verification['verification_digest']}")
    print("LIVE_STATUS: backend controls verified; platform-authority root not yet applied")


def _cmd_cancel(args: argparse.Namespace) -> None:
    if not args.allow_cancel_unexecuted:
        raise BootstrapAuthorizationError("cancel requires --allow-cancel-unexecuted")
    binding = _binding(args)
    _require_sso_environment(binding.region)
    client = AwsCli(region=binding.region)
    _, caller_arn = _identity(client, binding)
    _require_permission_set(caller_arn, PLAN_PERMISSION_SET)
    plan = _strict_object(args.plan)
    _require_plan_matches_binding(plan, binding)
    _describe_exact_change_set(client, binding, plan)
    stack = _stack(client, binding.stack_name)
    if stack is None or stack.get("StackStatus") != "REVIEW_IN_PROGRESS":
        raise BootstrapAuthorizationError("only an unexecuted review stack may be cancelled")
    resources = client.run(
        "cloudformation",
        "list-stack-resources",
        "--stack-name",
        binding.stack_name,
    ).get("StackResourceSummaries")
    if resources != []:
        raise BootstrapAuthorizationError("review stack is not empty; cancel is forbidden")
    client.run(
        "cloudformation",
        "delete-change-set",
        "--change-set-name",
        str(plan["change_set_id"]),
        "--stack-name",
        binding.stack_name,
    )
    print("PASS: exact unexecuted Change Set cancelled")
    print("AWS_CHANGE: Change Set metadata removed; no stack or resources deleted")


def _cmd_verify(args: argparse.Namespace) -> None:
    binding = _binding(args)
    verification_path = _outside_repo(args.verification_out)
    backend_path = _outside_repo(args.backend_config_out)
    if verification_path == backend_path:
        raise BootstrapAuthorizationError("operational output paths must be distinct")
    _require_sso_environment(binding.region)
    client = AwsCli(region=binding.region)
    _, caller_arn = _identity(client, binding)
    _require_permission_set(caller_arn, APPLY_PERMISSION_SET)
    plan = _strict_object(args.plan)
    _require_plan_matches_binding(plan, binding)
    verification, backend = _verify_live(
        client=client,
        binding=binding,
        plan=plan,
        caller_arn=caller_arn,
    )
    _write_json(args.verification_out, verification)
    _write_private(args.backend_config_out, backend)
    print("PASS: existing platform-authority backend controls verified read-only")
    print(f"VERIFICATION_DIGEST: {verification['verification_digest']}")
    print("NO_CHANGE: verification performed no AWS mutation")


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument(
        "--destination-account-id",
        action="append",
        required=True,
        help="Repeat for every independently owned customer destination account.",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed dedicated Scanalyze platform-authority bootstrap"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    render_plan = subparsers.add_parser(
        "render-plan-policy",
        help="Render the exact initial Identity Center Plan inline policy offline",
    )
    _common(render_plan)
    render_plan.add_argument("--policy-out", type=Path, required=True)
    render_plan.set_defaults(handler=_cmd_render_plan_policy)

    render_apply = subparsers.add_parser(
        "render-apply-policy",
        help="Render the exact Change Set-bound Apply inline policy offline",
    )
    _common(render_apply)
    render_apply.add_argument("--plan", type=Path, required=True)
    render_apply.add_argument("--policy-out", type=Path, required=True)
    render_apply.set_defaults(handler=_cmd_render_apply_policy)

    preflight = subparsers.add_parser("preflight", help="Read-only identity and template checks")
    _common(preflight)
    preflight.set_defaults(handler=_cmd_preflight)

    plan = subparsers.add_parser("plan", help="Create but never execute a reviewed change set")
    _common(plan)
    plan.add_argument("--initiator-id", required=True)
    plan.add_argument("--plan-out", type=Path, required=True)
    plan.add_argument("--allow-change-set-write", action="store_true")
    plan.set_defaults(handler=_cmd_plan)

    approve = subparsers.add_parser("approve", help="Approve using a distinct live SSO principal")
    _common(approve)
    approve.add_argument("--plan", type=Path, required=True)
    approve.add_argument("--approver-id", required=True)
    approve.add_argument("--approval-out", type=Path, required=True)
    approve.set_defaults(handler=_cmd_approve)

    apply_parser = subparsers.add_parser("apply", help="Execute the exact approved change set once")
    _common(apply_parser)
    apply_parser.add_argument("--plan", type=Path, required=True)
    apply_parser.add_argument("--approval", type=Path, required=True)
    apply_parser.add_argument("--verification-out", type=Path, required=True)
    apply_parser.add_argument("--backend-config-out", type=Path, required=True)
    apply_parser.add_argument("--allow-bootstrap-apply", action="store_true")
    apply_parser.set_defaults(handler=_cmd_apply)

    verify = subparsers.add_parser("verify", help="Read-only verification after an uncertain result")
    _common(verify)
    verify.add_argument("--plan", type=Path, required=True)
    verify.add_argument("--verification-out", type=Path, required=True)
    verify.add_argument("--backend-config-out", type=Path, required=True)
    verify.set_defaults(handler=_cmd_verify)

    cancel = subparsers.add_parser(
        "cancel", help="Remove only an exact unexecuted Change Set; never delete the stack"
    )
    _common(cancel)
    cancel.add_argument("--plan", type=Path, required=True)
    cancel.add_argument("--allow-cancel-unexecuted", action="store_true")
    cancel.set_defaults(handler=_cmd_cancel)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except (BootstrapAuthorizationError, AwsCliError) as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
