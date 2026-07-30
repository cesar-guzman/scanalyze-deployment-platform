#!/usr/bin/env python3
"""Seed the founder PEP root of trust from the Organizations management account.

The seed is intentionally separate from founder Plan/Apply.  It can target
only account 042360977644 in its current OU and us-east-1, attaches one S3
organization policy with all Block Public Access controls, and deploys one
retained DynamoDB table through a service-managed StackSet.  It never creates
customer resources, Identity Center assignments, or the authority backend.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "bootstrap/cfn-platform-authority-founder-pep.yaml"
MANAGEMENT_ACCOUNT_ID = "839393571433"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
STACK_SET_NAME = "scanalyze-platform-authority-founder-pep"
S3_POLICY_NAME = "ScanalyzePlatformAuthorityS3PublicAccessBlock"
MANAGEMENT_SEED_PERMISSION_SET = "ScanalyzeFounderPepSeed"
S3_POLICY_CONTENT = {
    "s3_attributes": {
        "public_access_block_configuration": {"@@assign": "all"}
    }
}
FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
MANAGEMENT_SEED_ARN = re.compile(
    rf"^arn:aws:sts::{MANAGEMENT_ACCOUNT_ID}:assumed-role/"
    rf"AWSReservedSSO_{MANAGEMENT_SEED_PERMISSION_SET}_[0-9A-Fa-f]{{16}}/"
    rf"[A-Za-z0-9+=,.@_-]{{2,64}}$"
)


class SeedAuthorizationError(ValueError):
    """The management seed boundary could not be proven exact."""


class AwsCli:
    def run(self, *parts: str, allow_failure: bool = False) -> tuple[int, dict[str, Any], str]:
        completed = subprocess.run(
            ["aws", *parts, "--region", REGION, "--output", "json", "--no-cli-pager"],
            check=False,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        if completed.returncode != 0 and not allow_failure:
            raise SeedAuthorizationError(f"AWS operation failed: {' '.join(parts[:2])}")
        try:
            value = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise SeedAuthorizationError("AWS operation returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise SeedAuthorizationError("AWS operation returned an invalid response")
        return completed.returncode, value, completed.stderr


def _environment() -> None:
    if not os.environ.get("AWS_PROFILE"):
        raise SeedAuthorizationError("AWS_PROFILE is required for the management session")
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise SeedAuthorizationError("static or ambient AWS credentials are forbidden")
    configured = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if configured and configured != {REGION}:
        raise SeedAuthorizationError("ambient AWS region conflicts with the seed binding")


def _template_sha256() -> str:
    return hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()


def _preflight(client: AwsCli) -> dict[str, Any]:
    _environment()
    _, identity, _ = client.run("sts", "get-caller-identity")
    caller_arn = identity.get("Arn")
    if (
        identity.get("Account") != MANAGEMENT_ACCOUNT_ID
        or not isinstance(caller_arn, str)
        or MANAGEMENT_SEED_ARN.fullmatch(caller_arn) is None
    ):
        raise SeedAuthorizationError("caller is not the exact founder PEP seed SSO role")
    _, organization, _ = client.run("organizations", "describe-organization")
    record = organization.get("Organization")
    if not isinstance(record, Mapping) or record.get("FeatureSet") != "ALL":
        raise SeedAuthorizationError("AWS Organizations is not in all-features mode")
    management = record.get("MasterAccountId", record.get("ManagementAccountId"))
    if management != MANAGEMENT_ACCOUNT_ID:
        raise SeedAuthorizationError("Organizations management ownership is ambiguous")
    _, parents, _ = client.run(
        "organizations", "list-parents", "--child-id", AUTHORITY_ACCOUNT_ID
    )
    parent_values = parents.get("Parents")
    if (
        not isinstance(parent_values, list)
        or len(parent_values) != 1
        or not isinstance(parent_values[0], Mapping)
        or parent_values[0].get("Type") != "ORGANIZATIONAL_UNIT"
        or not isinstance(parent_values[0].get("Id"), str)
    ):
        raise SeedAuthorizationError("authority account OU ownership is ambiguous")
    _, roots, _ = client.run("organizations", "list-roots")
    root_values = roots.get("Roots")
    if not isinstance(root_values, list) or len(root_values) != 1 or not isinstance(root_values[0], Mapping):
        raise SeedAuthorizationError("organization root response is ambiguous")
    root_id = root_values[0].get("Id")
    if not isinstance(root_id, str):
        raise SeedAuthorizationError("organization root ID is missing")
    policy_types = root_values[0].get("PolicyTypes", [])
    s3_enabled = any(
        isinstance(item, Mapping)
        and item.get("Type") == "S3_POLICY"
        and item.get("Status") == "ENABLED"
        for item in policy_types
    )
    _, service_access, _ = client.run(
        "organizations", "list-aws-service-access-for-organization"
    )
    principals = service_access.get("EnabledServicePrincipals", [])
    organizations_reports_stacksets = any(
        isinstance(item, Mapping)
        and item.get("ServicePrincipal")
        in {
            "member.org.stacksets.cloudformation.amazonaws.com",
            "stacksets.cloudformation.amazonaws.com",
        }
        for item in principals
    )
    _, stacksets_access, _ = client.run(
        "cloudformation", "describe-organizations-access"
    )
    stacksets_status = stacksets_access.get("Status")
    if stacksets_status not in {"ENABLED", "DISABLED"}:
        raise SeedAuthorizationError("StackSets Organizations access is ambiguous")
    stacksets_enabled = stacksets_status == "ENABLED"
    if stacksets_enabled != organizations_reports_stacksets:
        raise SeedAuthorizationError("StackSets trusted-access sources conflict")
    return {
        "root_id": root_id,
        "authority_ou_id": parent_values[0]["Id"],
        "s3_policy_type_enabled": s3_enabled,
        "stacksets_trusted_access_enabled": stacksets_enabled,
        "template_sha256": _template_sha256(),
    }


def _find_s3_policy(client: AwsCli) -> dict[str, Any] | None:
    _, response, _ = client.run("organizations", "list-policies", "--filter", "S3_POLICY")
    matches = [
        item
        for item in response.get("Policies", [])
        if isinstance(item, Mapping) and item.get("Name") == S3_POLICY_NAME
    ]
    if len(matches) > 1:
        raise SeedAuthorizationError("multiple founder S3 organization policies exist")
    return dict(matches[0]) if matches else None


def _inspect_s3_policy(client: AwsCli) -> tuple[str, set[object]] | None:
    policy = _find_s3_policy(client)
    if policy is None:
        return None
    policy_id = policy.get("Id")
    if not isinstance(policy_id, str):
        raise SeedAuthorizationError("S3 organization policy ID is missing")
    _, described, _ = client.run("organizations", "describe-policy", "--policy-id", policy_id)
    content = described.get("Policy", {}).get("Content")
    try:
        normalized = json.loads(content) if isinstance(content, str) else None
    except json.JSONDecodeError as exc:
        raise SeedAuthorizationError("S3 organization policy content is malformed") from exc
    if normalized != S3_POLICY_CONTENT:
        raise SeedAuthorizationError("existing S3 organization policy differs from the reviewed content")
    _, policy_tags, _ = client.run(
        "organizations", "list-tags-for-resource", "--resource-id", policy_id
    )
    tags = {
        item.get("Key"): item.get("Value")
        for item in policy_tags.get("Tags", [])
        if isinstance(item, Mapping)
    }
    if tags != {
        "managed_by": "scanalyze-founder-pep",
        "work_package": "GUG-211",
    }:
        raise SeedAuthorizationError("existing S3 organization policy tags differ")
    _, targets, _ = client.run("organizations", "list-targets-for-policy", "--policy-id", policy_id)
    target_ids = {
        item.get("TargetId")
        for item in targets.get("Targets", [])
        if isinstance(item, Mapping)
    }
    foreign = target_ids - {AUTHORITY_ACCOUNT_ID}
    if foreign:
        raise SeedAuthorizationError("founder S3 organization policy has a foreign target")
    return policy_id, target_ids


def _ensure_s3_policy(client: AwsCli, preflight: Mapping[str, Any]) -> str:
    if not preflight["s3_policy_type_enabled"]:
        client.run(
            "organizations", "enable-policy-type", "--root-id", str(preflight["root_id"]),
            "--policy-type", "S3_POLICY",
        )
    inspected = _inspect_s3_policy(client)
    if inspected is None:
        exact_content = json.dumps(S3_POLICY_CONTENT, sort_keys=True, separators=(",", ":"))
        _, created, _ = client.run(
            "organizations", "create-policy", "--name", S3_POLICY_NAME,
            "--description", "Block all public S3 access in the dedicated Scanalyze platform-authority account",
            "--type", "S3_POLICY", "--content", exact_content,
            "--tags", "Key=managed_by,Value=scanalyze-founder-pep",
            "Key=work_package,Value=GUG-211",
        )
        policy = created.get("Policy", {}).get("PolicySummary")
        if not isinstance(policy, Mapping) or not isinstance(policy.get("Id"), str):
            raise SeedAuthorizationError("S3 organization policy creation response is incomplete")
        policy_id = str(policy["Id"])
        target_ids: set[object] = set()
        inspected = _inspect_s3_policy(client)
        if inspected is None or inspected[0] != policy_id:
            raise SeedAuthorizationError("created S3 organization policy readback differs")
        _, target_ids = inspected
    else:
        policy_id, target_ids = inspected
    if AUTHORITY_ACCOUNT_ID not in target_ids:
        client.run(
            "organizations", "attach-policy", "--policy-id", policy_id,
            "--target-id", AUTHORITY_ACCOUNT_ID,
        )
    final = _inspect_s3_policy(client)
    if final is None or final != (policy_id, {AUTHORITY_ACCOUNT_ID}):
        raise SeedAuthorizationError("founder S3 organization policy target readback differs")
    return policy_id


def _validate_stack_set(stack_set: object, template_sha256: str) -> None:
    if not isinstance(stack_set, Mapping):
        raise SeedAuthorizationError("existing founder PEP StackSet response is incomplete")
    if (
        stack_set.get("StackSetName") != STACK_SET_NAME
        or stack_set.get("PermissionModel") != "SERVICE_MANAGED"
        or stack_set.get("Status") != "ACTIVE"
    ):
        raise SeedAuthorizationError("existing founder PEP StackSet identity is invalid")
    if stack_set.get("AutoDeployment") != {
        "Enabled": False,
        "RetainStacksOnAccountRemoval": True,
    }:
        raise SeedAuthorizationError("existing founder PEP StackSet auto-deployment is unsafe")
    template_body = stack_set.get("TemplateBody")
    if not isinstance(template_body, str) or hashlib.sha256(
        template_body.encode("utf-8")
    ).hexdigest() != template_sha256:
        raise SeedAuthorizationError("existing founder PEP StackSet template differs")
    parameters = stack_set.get("Parameters")
    if (
        not isinstance(parameters, list)
        or len(parameters) != 1
        or not isinstance(parameters[0], Mapping)
        or parameters[0].get("ParameterKey") != "AuthorityAccountId"
        or parameters[0].get("ParameterValue") != AUTHORITY_ACCOUNT_ID
        or parameters[0].get("UsePreviousValue") not in {None, False}
        or set(parameters[0]) - {
            "ParameterKey",
            "ParameterValue",
            "UsePreviousValue",
            "ResolvedValue",
        }
    ):
        raise SeedAuthorizationError("existing founder PEP StackSet parameter binding differs")
    tags = {
        item.get("Key"): item.get("Value")
        for item in stack_set.get("Tags", [])
        if isinstance(item, Mapping)
    }
    if tags != {
        "managed_by": "cloudformation-stacksets",
        "service": "scanalyze-platform-authority",
        "work_package": "GUG-211",
    }:
        raise SeedAuthorizationError("existing founder PEP StackSet tags differ")


def _inspect_stack_set(
    client: AwsCli, preflight: Mapping[str, Any]
) -> list[dict[str, Any]] | None:
    code, described, error = client.run(
        "cloudformation", "describe-stack-set", "--stack-set-name", STACK_SET_NAME,
        "--call-as", "SELF", allow_failure=True,
    )
    if code != 0:
        if not any(
            marker in error
            for marker in (
                "StackSetNotFoundException",
                "does not exist",
                "not found",
            )
        ):
            raise SeedAuthorizationError("founder PEP StackSet lookup failed closed")
        return None
    _validate_stack_set(described.get("StackSet"), str(preflight["template_sha256"]))
    _, instances, _ = client.run(
        "cloudformation", "list-stack-instances", "--stack-set-name", STACK_SET_NAME,
        "--call-as", "SELF",
    )
    summaries = instances.get("Summaries")
    if not isinstance(summaries, list) or any(not isinstance(item, Mapping) for item in summaries):
        raise SeedAuthorizationError("founder PEP StackSet instance inventory is malformed")
    normalized = [dict(item) for item in summaries]
    matches = [
        item for item in normalized
        if item.get("Account") == AUTHORITY_ACCOUNT_ID and item.get("Region") == REGION
    ]
    foreign = [
        item for item in normalized
        if item.get("Account") != AUTHORITY_ACCOUNT_ID or item.get("Region") != REGION
    ]
    if foreign or len(matches) > 1:
        raise SeedAuthorizationError("founder PEP StackSet has a foreign or ambiguous stack instance")
    if matches:
        instance = matches[0]
        if (
            instance.get("Status") != "CURRENT"
            or instance.get("OrganizationalUnitId") != preflight["authority_ou_id"]
            or not isinstance(instance.get("StackId"), str)
            or not isinstance(instance.get("StackInstanceStatus"), Mapping)
            or instance["StackInstanceStatus"].get("DetailedStatus") != "SUCCEEDED"
        ):
            raise SeedAuthorizationError("founder PEP StackSet instance is not CURRENT/SUCCEEDED")
    return matches


def _ensure_stack_set(client: AwsCli, preflight: Mapping[str, Any]) -> None:
    if not preflight["stacksets_trusted_access_enabled"]:
        client.run("cloudformation", "activate-organizations-access")
    matches = _inspect_stack_set(client, preflight)
    if matches is None:
        client.run(
            "cloudformation", "create-stack-set", "--stack-set-name", STACK_SET_NAME,
            "--description", "GUG-211 retained founder PEP CAS ledger",
            "--template-body", f"file://{TEMPLATE}",
            "--permission-model", "SERVICE_MANAGED", "--call-as", "SELF",
            "--auto-deployment", "Enabled=false,RetainStacksOnAccountRemoval=true",
            "--parameters", f"ParameterKey=AuthorityAccountId,ParameterValue={AUTHORITY_ACCOUNT_ID}",
            "--tags", "Key=managed_by,Value=cloudformation-stacksets",
            "Key=service,Value=scanalyze-platform-authority", "Key=work_package,Value=GUG-211",
        )
        matches = _inspect_stack_set(client, preflight)
        if matches is None:
            raise SeedAuthorizationError("created founder PEP StackSet readback is missing")
    if not matches:
        _, created, _ = client.run(
            "cloudformation", "create-stack-instances", "--stack-set-name", STACK_SET_NAME,
            "--deployment-targets",
            (
                f"OrganizationalUnitIds={preflight['authority_ou_id']},"
                f"Accounts={AUTHORITY_ACCOUNT_ID},AccountFilterType=INTERSECTION"
            ),
            "--regions", REGION, "--call-as", "SELF",
            "--operation-preferences",
            "FailureToleranceCount=0,MaxConcurrentCount=1,RegionConcurrencyType=SEQUENTIAL,ConcurrencyMode=STRICT_FAILURE_TOLERANCE",
        )
        operation_id = created.get("OperationId")
        if not isinstance(operation_id, str):
            raise SeedAuthorizationError("StackSet operation ID is missing")
        while True:
            _, operation, _ = client.run(
                "cloudformation", "describe-stack-set-operation",
                "--stack-set-name", STACK_SET_NAME, "--operation-id", operation_id,
                "--call-as", "SELF",
            )
            status = operation.get("StackSetOperation", {}).get("Status")
            if status == "SUCCEEDED":
                break
            if status in {"FAILED", "STOPPED"}:
                raise SeedAuthorizationError("founder PEP StackSet operation failed")
            if status not in {"RUNNING", "QUEUED", "STOPPING"}:
                raise SeedAuthorizationError("founder PEP StackSet operation is ambiguous")
            time.sleep(5)
    final = _inspect_stack_set(client, preflight)
    if final is None or len(final) != 1:
        raise SeedAuthorizationError("founder PEP StackSet final instance readback is missing")


def _cmd_preflight(_: argparse.Namespace) -> None:
    client = AwsCli()
    evidence = _preflight(client)
    policy = _inspect_s3_policy(client) if evidence["s3_policy_type_enabled"] else None
    stack_instances = _inspect_stack_set(client, evidence)
    print("PASS: exact management account, organization, authority account, OU, and template verified")
    print(
        "INFO: S3 policy type "
        + ("enabled" if evidence["s3_policy_type_enabled"] else "requires reviewed enablement")
    )
    print(
        "INFO: StackSets trusted access "
        + ("enabled" if evidence["stacksets_trusted_access_enabled"] else "requires reviewed activation")
    )
    print("INFO: existing S3 policy " + ("exact" if policy else "absent"))
    print(
        "INFO: existing PEP StackSet "
        + ("exact" if stack_instances is not None else "absent")
    )
    print("NO_AWS_CHANGE: preflight performed read-only APIs only")


def _cmd_seed(args: argparse.Namespace) -> None:
    if not args.allow_management_seed:
        raise SeedAuthorizationError("seed requires --allow-management-seed")
    client = AwsCli()
    preflight = _preflight(client)
    _ensure_s3_policy(client, preflight)
    _ensure_stack_set(client, preflight)
    final = _preflight(client)
    if not final["s3_policy_type_enabled"] or not final["stacksets_trusted_access_enabled"]:
        raise SeedAuthorizationError("management seed control-plane readback is incomplete")
    print("PASS: exact founder PEP root of trust seeded for the dedicated authority account")
    print("AWS_CHANGE: one account-targeted S3 policy and one retained DynamoDB StackSet instance")
    print("LIVE_EXECUTION_BLOCKED: founder permission sets, ledger intent, Plan, and Apply remain absent")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Management-account founder PEP seed")
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight", help="Read-only Organizations and StackSets checks")
    preflight.set_defaults(handler=_cmd_preflight)
    seed = commands.add_parser("seed", help="Seed the exact account-scoped root of trust")
    seed.add_argument("--allow-management-seed", action="store_true")
    seed.set_defaults(handler=_cmd_seed)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except SeedAuthorizationError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
