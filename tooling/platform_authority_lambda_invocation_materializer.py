"""Materialize a reviewed GUG-218 allowlist from private AWS evidence.

The transformation functions are deterministic and side-effect free. Release
validation may perform read-only Git provenance checks, while
``write_private_bundle`` is the only filesystem mutation. The module does not
create AWS sessions and cannot mutate AWS. A candidate snapshot is used to
render a short-lived release; a distinct, later snapshot must re-prove the
same closed authority graph before the GUG-218 report-only result is usable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from tooling.platform_authority_lambda_invocation_authority import (
    COVERAGE_SURFACES,
    EVIDENCE_SOURCE_AWS_READ_ONLY,
    EXPECTED_ALIASES,
    EXPECTED_AUTHORITY_EDGE_COUNT,
    EXPECTED_FORBIDDEN_AUTHORITY_CLASSES,
    INVENTORY_REVIEW_SAFE,
    INVENTORY_SCOPE,
    RAW_SNAPSHOT_FORMAT,
    RECEIPT_REVIEW_REQUIRED,
    AuthorityInventoryError,
    TargetBinding,
    analyze_authority_inventory,
    canonical_digest,
    digest_text,
    validate_reviewed_allowlist,
)


COLLECTOR_PERMISSION_SET_NAME = "ScanalyzeAuthorityLambdaAudit"
COLLECTOR_PERMISSION_SET_DESCRIPTION = (
    "GUG-219 read-only account-wide Lambda invocation-authority inventory"
)
BROKER_FUNCTION_NAME = "scanalyze-platform-authority-gug215-retirement"
CLASSIFIER_ROLE_NAME = "ScanalyzeGug215ClassifierInvoker"
APPROVER_ROLE_NAME = "ScanalyzeGug215ApproverInvoker"
CLASSIFIER_PERMISSION_SET_NAME = "ScanalyzeAuthorityRetireClass"
APPROVER_PERMISSION_SET_NAME = "ScanalyzeAuthorityRetireApprove"
COLLECTOR_POLICY_PATH = Path(
    "policies/iam/platform-authority-lambda-invocation-inventory-role.json"
)
SOURCE_TEMPLATE_PATH = Path(
    "bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml"
)
SOURCE_POLICY_PATHS = (
    Path("policies/iam/platform-authority-change-set-retirement-classifier-role.json"),
    Path("policies/iam/platform-authority-change-set-retirement-role.json"),
    COLLECTOR_POLICY_PATH,
)
RUNTIME_SOURCE_PATHS = (
    Path("tooling/platform_authority_lambda_invocation_authority.py"),
    Path("tooling/platform_authority_lambda_invocation_materializer.py"),
    Path("scripts/deployment/platform-authority-lambda-invocation-authority.py"),
    Path("scripts/deployment/platform-authority-lambda-invocation-materializer.py"),
)
EXPECTED_DIRECT_EFFECT_DENY_ACTIONS = frozenset(
    {
        "cloudformation:DeleteChangeSet",
        "cloudformation:DeleteStack",
        "cloudformation:ExecuteChangeSet",
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PartiQLDelete",
        "dynamodb:PartiQLInsert",
        "dynamodb:PartiQLUpdate",
        "dynamodb:PutItem",
        "dynamodb:TransactWriteItems",
        "dynamodb:UpdateItem",
    }
)
SAML_AUDIENCE_BY_PARTITION = {
    "aws": "https://signin.aws.amazon.com/saml",
    "aws-us-gov": "https://signin.amazonaws-us-gov.com/saml",
    "aws-cn": "https://signin.amazonaws.cn/saml",
}

_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+")
_ROLE_SUFFIX = re.compile(r"[0-9a-fA-F]{16}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_ALLOWED_POLICY_PLACEHOLDERS = frozenset(
    {
        "${aws_partition}",
        "${region}",
        "${authority_account_id}",
        "${broker_function_name}",
    }
)


class LambdaAuthorityMaterializationError(ValueError):
    """A sanitized, stable fail-closed GUG-219 reason code."""


def _fail(code: str) -> None:
    raise LambdaAuthorityMaterializationError(code)


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail(code)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        _fail(code)
    raise AssertionError("unreachable")


def _strict_json(path: Path, code: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(code)
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail(code)
    raise AssertionError("unreachable")


def _byte_digest(path: Path, code: str) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        _fail(code)
    raise AssertionError("unreachable")


def _statements(document: object, code: str) -> list[Mapping[str, Any]]:
    if not isinstance(document, Mapping) or document.get("Version") != "2012-10-17":
        _fail(code)
    value = document.get("Statement")
    values = [value] if isinstance(value, Mapping) else value
    if not isinstance(values, list) or not values or not all(
        isinstance(item, Mapping) for item in values
    ):
        _fail(code)
    return list(values)


def _string_values(value: object, code: str) -> tuple[str, ...]:
    values = (value,) if isinstance(value, str) else value
    if not isinstance(values, (list, tuple)) or not values or not all(
        isinstance(item, str) and item for item in values
    ):
        _fail(code)
    return tuple(values)


def render_collector_inline_policy(
    *, binding: TargetBinding, repo_root: Path
) -> dict[str, Any]:
    """Render the exact reviewed collector policy without template expansion."""

    path = Path(repo_root).resolve() / COLLECTOR_POLICY_PATH
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _fail("COLLECTOR_POLICY_TEMPLATE_UNAVAILABLE")
    placeholders = frozenset(re.findall(r"\$\{[^}]+\}", raw))
    if placeholders != _ALLOWED_POLICY_PLACEHOLDERS:
        _fail("POLICY_TEMPLATE_PLACEHOLDER_INVALID")
    replacements = {
        "${aws_partition}": binding.partition,
        "${region}": binding.region,
        "${authority_account_id}": binding.authority_account_id,
        "${broker_function_name}": binding.function_name,
    }
    for placeholder, replacement in replacements.items():
        raw = raw.replace(placeholder, replacement)
    if "${" in raw or len(raw.encode("utf-8")) > 32_768:
        _fail("POLICY_TEMPLATE_PLACEHOLDER_INVALID")
    try:
        policy = json.loads(raw, object_pairs_hook=lambda pairs: _unique_pairs(pairs))
    except json.JSONDecodeError:
        _fail("COLLECTOR_POLICY_TEMPLATE_INVALID")
    if not isinstance(policy, dict):
        _fail("COLLECTOR_POLICY_TEMPLATE_INVALID")
    _statements(policy, "COLLECTOR_POLICY_TEMPLATE_INVALID")
    return policy


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("COLLECTOR_POLICY_TEMPLATE_INVALID")
        result[key] = value
    return result


def _collector_role_binding(
    *,
    binding: TargetBinding,
    identity_center_region: str,
    iam_arn: str,
    sts_arn: str,
) -> tuple[str, str]:
    if _REGION.fullmatch(identity_center_region) is None:
        _fail("IDENTITY_CENTER_REGION_INVALID")
    partition = re.escape(binding.partition)
    account = re.escape(binding.authority_account_id)
    regional_path = "" if identity_center_region == "us-east-1" else f"/{identity_center_region}"
    pattern = re.compile(
        rf"arn:{partition}:iam::{account}:role/aws-reserved/sso\.amazonaws\.com"
        rf"{re.escape(regional_path)}/(AWSReservedSSO_([^/]+)_([0-9a-fA-F]{{16}}))"
    )
    match = pattern.fullmatch(iam_arn) if isinstance(iam_arn, str) else None
    if match is None:
        _fail("COLLECTOR_PERMISSION_SET_INVALID")
    role_name, permission_set_name, suffix = match.groups()
    if permission_set_name != COLLECTOR_PERMISSION_SET_NAME or _ROLE_SUFFIX.fullmatch(suffix) is None:
        _fail("COLLECTOR_PERMISSION_SET_INVALID")
    sts_match = re.fullmatch(
        rf"arn:{partition}:sts::{account}:assumed-role/([^/]+)/([^/\s]{{1,128}})",
        sts_arn if isinstance(sts_arn, str) else "",
    )
    if sts_match is None:
        _fail("COLLECTOR_PERMISSION_SET_INVALID")
    if sts_match.group(1) != role_name:
        _fail("COLLECTOR_ROLE_BINDING_MISMATCH")
    canonical_sts = (
        f"arn:{binding.partition}:sts::{binding.authority_account_id}:assumed-role/{role_name}"
    )
    return role_name, canonical_sts


def build_collector_contract(
    *,
    binding: TargetBinding,
    identity_center_region: str,
    collector_iam_role_arn: str,
    collector_sts_session_arn: str,
    created_at: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Bind a dedicated Identity Center role and its only reviewed policy."""

    _parse_time(created_at, "COLLECTOR_CONTRACT_TIMESTAMP_INVALID")
    _, canonical_sts = _collector_role_binding(
        binding=binding,
        identity_center_region=identity_center_region,
        iam_arn=collector_iam_role_arn,
        sts_arn=collector_sts_session_arn,
    )
    policy = render_collector_inline_policy(binding=binding, repo_root=repo_root)
    template_path = Path(repo_root).resolve() / COLLECTOR_POLICY_PATH
    contract: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_collector_contract",
        "environment": "non-production",
        "production": False,
        "authority_account_id_digest": digest_text(binding.authority_account_id),
        "target_region": binding.region,
        "identity_center_region": identity_center_region,
        "partition": binding.partition,
        "broker_function_name_digest": digest_text(binding.function_name),
        "permission_set_name": COLLECTOR_PERMISSION_SET_NAME,
        "permission_set_description": COLLECTOR_PERMISSION_SET_DESCRIPTION,
        "session_duration": "PT1H",
        "relay_state_present": False,
        "inline_policy_template_sha256": _byte_digest(
            template_path, "COLLECTOR_POLICY_TEMPLATE_UNAVAILABLE"
        ),
        "collector_inline_policy_digest": canonical_digest(policy),
        "managed_policy_arns": [],
        "customer_managed_policy_references": [],
        "permissions_boundary_present": False,
        "collector_role_iam_arn_digest": digest_text(collector_iam_role_arn),
        "collector_role_sts_arn_digest": digest_text(canonical_sts),
        "aws_profile_authoritative": False,
        "lambda_invocation_authorized": False,
        "aws_mutation_authorized": False,
        "live_effect_authorized": False,
        "created_at": created_at,
    }
    contract["collector_contract_digest"] = canonical_digest(contract)
    return contract


def _validate_collector_contract(
    contract: Mapping[str, Any], *, binding: TargetBinding, repo_root: Path
) -> None:
    expected_keys = {
        "schema_version", "record_type", "environment", "production",
        "authority_account_id_digest", "target_region", "identity_center_region",
        "partition", "broker_function_name_digest", "permission_set_name",
        "permission_set_description", "session_duration", "relay_state_present",
        "inline_policy_template_sha256", "collector_inline_policy_digest",
        "managed_policy_arns", "customer_managed_policy_references",
        "permissions_boundary_present", "collector_role_iam_arn_digest",
        "collector_role_sts_arn_digest", "aws_profile_authoritative",
        "lambda_invocation_authorized", "aws_mutation_authorized",
        "live_effect_authorized", "created_at", "collector_contract_digest",
    }
    if set(contract) != expected_keys:
        _fail("COLLECTOR_CONTRACT_MALFORMED")
    false_fields = (
        "production", "relay_state_present", "permissions_boundary_present",
        "aws_profile_authoritative", "lambda_invocation_authorized",
        "aws_mutation_authorized", "live_effect_authorized",
    )
    if (
        contract.get("schema_version") != "1"
        or contract.get("record_type") != "platform_authority_lambda_invocation_collector_contract"
        or contract.get("environment") != "non-production"
        or any(contract.get(field) is not False for field in false_fields)
        or contract.get("authority_account_id_digest") != digest_text(binding.authority_account_id)
        or contract.get("target_region") != binding.region
        or contract.get("partition") != binding.partition
        or contract.get("broker_function_name_digest") != digest_text(binding.function_name)
        or contract.get("permission_set_name") != COLLECTOR_PERMISSION_SET_NAME
        or contract.get("permission_set_description") != COLLECTOR_PERMISSION_SET_DESCRIPTION
        or contract.get("session_duration") != "PT1H"
        or contract.get("managed_policy_arns") != []
        or contract.get("customer_managed_policy_references") != []
    ):
        _fail("COLLECTOR_CONTRACT_BINDING_INVALID")
    if _REGION.fullmatch(str(contract.get("identity_center_region", ""))) is None:
        _fail("COLLECTOR_CONTRACT_BINDING_INVALID")
    for key in (
        "inline_policy_template_sha256", "collector_inline_policy_digest",
        "collector_role_iam_arn_digest", "collector_role_sts_arn_digest",
        "collector_contract_digest",
    ):
        if not isinstance(contract.get(key), str) or _DIGEST.fullmatch(str(contract[key])) is None:
            _fail("COLLECTOR_CONTRACT_DIGEST_INVALID")
    _parse_time(contract.get("created_at"), "COLLECTOR_CONTRACT_TIMESTAMP_INVALID")
    policy = render_collector_inline_policy(binding=binding, repo_root=repo_root)
    if contract["collector_inline_policy_digest"] != canonical_digest(policy):
        _fail("COLLECTOR_INLINE_POLICY_DIGEST_MISMATCH")
    if contract["inline_policy_template_sha256"] != _byte_digest(
        Path(repo_root).resolve() / COLLECTOR_POLICY_PATH,
        "COLLECTOR_POLICY_TEMPLATE_UNAVAILABLE",
    ):
        _fail("COLLECTOR_POLICY_TEMPLATE_DIGEST_MISMATCH")
    calculated = canonical_digest(
        {key: value for key, value in contract.items() if key != "collector_contract_digest"}
    )
    if calculated != contract["collector_contract_digest"]:
        _fail("COLLECTOR_CONTRACT_DIGEST_MISMATCH")


def _validate_snapshot_envelope(
    snapshot: Mapping[str, Any], *, binding: TargetBinding, contract: Mapping[str, Any], prefix: str
) -> None:
    incomplete_code = (
        "FRESH_CAPTURE_INCOMPLETE"
        if prefix == "FRESH"
        else f"{prefix}_SNAPSHOT_INCOMPLETE"
    )
    expected_snapshot_keys = {
        "snapshot_format",
        "capture_started_at",
        "capture_completed_at",
        "capture_expires_at",
        "collector_nonce",
        "collector_principal_arn",
        "collector_principal_arn_digest",
        "enabled_regions",
        "scanned_regions",
        "coverage",
        "lambda",
        "iam",
        "snapshot_digest",
    }
    if set(snapshot) != expected_snapshot_keys:
        _fail(f"{prefix}_SNAPSHOT_FORMAT_INVALID")
    if snapshot.get("snapshot_format") != RAW_SNAPSHOT_FORMAT:
        _fail(f"{prefix}_SNAPSHOT_FORMAT_INVALID")
    digest = snapshot.get("snapshot_digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        _fail(f"{prefix}_SNAPSHOT_DIGEST_INVALID")
    unsealed = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    if canonical_digest(unsealed) != digest:
        _fail(f"{prefix}_SNAPSHOT_DIGEST_MISMATCH")
    collector_nonce = snapshot.get("collector_nonce")
    if (
        not isinstance(collector_nonce, str)
        or not 1 <= len(collector_nonce) <= 256
        or any(character.isspace() for character in collector_nonce)
    ):
        _fail(f"{prefix}_COLLECTOR_NONCE_INVALID")
    collector_principal = snapshot.get("collector_principal_arn")
    collector_digest = snapshot.get("collector_principal_arn_digest")
    if (
        not isinstance(collector_principal, str)
        or not isinstance(collector_digest, str)
        or digest_text(collector_principal) != collector_digest
        or collector_digest != contract.get("collector_role_sts_arn_digest")
    ):
        _fail("COLLECTOR_PRINCIPAL_DIGEST_MISMATCH")
    partition = re.escape(binding.partition)
    account = re.escape(binding.authority_account_id)
    principal_match = re.fullmatch(
        rf"arn:{partition}:sts::{account}:assumed-role/"
        rf"(AWSReservedSSO_{re.escape(COLLECTOR_PERMISSION_SET_NAME)}_"
        rf"[0-9a-fA-F]{{16}})",
        collector_principal,
    )
    if principal_match is None:
        _fail("COLLECTOR_ROLE_BINDING_MISMATCH")
    regional_path = (
        ""
        if contract.get("identity_center_region") == "us-east-1"
        else f"/{contract.get('identity_center_region')}"
    )
    expected_iam_arn = (
        f"arn:{binding.partition}:iam::{binding.authority_account_id}:role/"
        f"aws-reserved/sso.amazonaws.com{regional_path}/{principal_match.group(1)}"
    )
    if digest_text(expected_iam_arn) != contract.get("collector_role_iam_arn_digest"):
        _fail("COLLECTOR_ROLE_BINDING_MISMATCH")
    enabled_regions = snapshot.get("enabled_regions")
    scanned_regions = snapshot.get("scanned_regions")
    if (
        not isinstance(enabled_regions, list)
        or not isinstance(scanned_regions, list)
        or not all(
            isinstance(region, str) and _REGION.fullmatch(region) is not None
            for region in enabled_regions
        )
        or len(set(enabled_regions)) != len(enabled_regions)
        or binding.region not in enabled_regions
        or sorted(scanned_regions) != sorted(enabled_regions)
    ):
        _fail(incomplete_code)
    coverage = snapshot.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != set(COVERAGE_SURFACES):
        _fail(incomplete_code)
    lambda_inventory = snapshot.get("lambda")
    iam_inventory = snapshot.get("iam")
    if not isinstance(lambda_inventory, Mapping) or not isinstance(iam_inventory, Mapping):
        _fail(incomplete_code)
    lambda_keys = {
        "functions",
        "aliases",
        "versions",
        "function_urls",
        "resource_policies",
        "event_source_mappings",
        "event_invoke_configs",
    }
    iam_keys = {"users", "groups", "roles", "policies", "managed_policy_documents"}
    if set(lambda_inventory) != lambda_keys or set(iam_inventory) != iam_keys:
        _fail(incomplete_code)
    for key in lambda_keys:
        if not isinstance(lambda_inventory.get(key), list):
            _fail(incomplete_code)
    for key in ("users", "groups", "roles", "policies"):
        if not isinstance(iam_inventory.get(key), list):
            _fail(incomplete_code)
    if not isinstance(iam_inventory.get("managed_policy_documents"), Mapping):
        _fail(incomplete_code)

    evidence_items: dict[str, list[Any]] = {
        "region_discovery": enabled_regions,
        "lambda_functions": lambda_inventory["functions"],
        "lambda_aliases": lambda_inventory["aliases"],
        "lambda_versions": lambda_inventory["versions"],
        "lambda_function_urls": lambda_inventory["function_urls"],
        "lambda_resource_policies": lambda_inventory["resource_policies"],
        "lambda_event_source_mappings": [
            *lambda_inventory["event_source_mappings"],
            *lambda_inventory["event_invoke_configs"],
        ],
        "iam_account_authorization": [
            *iam_inventory["users"],
            *iam_inventory["groups"],
            *iam_inventory["roles"],
            *iam_inventory["policies"],
            iam_inventory["managed_policy_documents"],
        ],
    }
    for surface, items in evidence_items.items():
        entry = coverage.get(surface)
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"status", "page_count", "item_count", "evidence_digest"}
            or entry.get("status") != "COMPLETE"
            or not isinstance(entry.get("page_count"), int)
            or isinstance(entry.get("page_count"), bool)
            or entry["page_count"] < 1
            or entry.get("item_count") != len(items)
            or entry.get("evidence_digest") != canonical_digest(items)
        ):
            _fail(incomplete_code)


def _find_exact_role(iam: Mapping[str, Any], binding: TargetBinding, role_name: str) -> Mapping[str, Any]:
    expected = f"arn:{binding.partition}:iam::{binding.authority_account_id}:role/{role_name}"
    roles = iam.get("roles")
    matches = [item for item in roles if isinstance(item, Mapping) and item.get("Arn") == expected] if isinstance(roles, list) else []
    if len(matches) != 1:
        _fail("CANDIDATE_REQUIRED_ROLE_MISSING")
    role = matches[0]
    if role.get("AttachedManagedPolicies") != [] or "PermissionsBoundary" in role:
        _fail("CANDIDATE_AUTHORITY_NOT_EXACT")
    return role


def _find_collector_role(
    iam: Mapping[str, Any], contract: Mapping[str, Any], rendered_policy: Mapping[str, Any]
) -> None:
    roles = iam.get("roles")
    matches = [
        role for role in roles if isinstance(role, Mapping)
        and isinstance(role.get("Arn"), str)
        and digest_text(role["Arn"]) == contract.get("collector_role_iam_arn_digest")
    ] if isinstance(roles, list) else []
    if len(matches) != 1:
        _fail("COLLECTOR_ROLE_NOT_FOUND")
    role = matches[0]
    if role.get("AttachedManagedPolicies") != []:
        _fail("COLLECTOR_MANAGED_POLICY_FORBIDDEN")
    if "PermissionsBoundary" in role:
        _fail("COLLECTOR_PERMISSIONS_BOUNDARY_FORBIDDEN")
    policies = role.get("RolePolicyList")
    if not isinstance(policies, list) or len(policies) != 1:
        _fail("COLLECTOR_INLINE_POLICY_NOT_EXACT")
    document = policies[0].get("PolicyDocument") if isinstance(policies[0], Mapping) else None
    if not isinstance(document, Mapping) or canonical_digest(document) != canonical_digest(rendered_policy):
        _fail("COLLECTOR_INLINE_POLICY_NOT_EXACT")
    _validate_collector_trust(role, contract)


def _validate_collector_trust(
    role: Mapping[str, Any], contract: Mapping[str, Any]
) -> None:
    """Require the standard same-account Identity Center SAML trust only."""

    document = role.get("AssumeRolePolicyDocument")
    statements = _statements(document, "COLLECTOR_TRUST_POLICY_INVALID")
    if len(statements) != 1:
        _fail("COLLECTOR_TRUST_POLICY_INVALID")
    statement = statements[0]
    principal = statement.get("Principal")
    actions = set(
        _string_values(statement.get("Action"), "COLLECTOR_TRUST_POLICY_INVALID")
    )
    condition = statement.get("Condition")
    federated = principal.get("Federated") if isinstance(principal, Mapping) else None
    partition = re.escape(str(contract.get("partition", "")))
    saml_pattern = re.compile(
        rf"arn:{partition}:iam::[0-9]{{12}}:saml-provider/"
        r"AWSSSO(?:_[0-9a-fA-F]{16}_DO_NOT_DELETE)?"
    )
    account_id = federated.split(":", 5)[4] if isinstance(federated, str) else ""
    expected_audience = SAML_AUDIENCE_BY_PARTITION.get(str(contract.get("partition")))
    if (
        statement.get("Effect") != "Allow"
        or actions != {"sts:AssumeRoleWithSAML", "sts:TagSession"}
        or not isinstance(principal, Mapping)
        or set(principal) != {"Federated"}
        or not isinstance(federated, str)
        or saml_pattern.fullmatch(federated) is None
        or digest_text(account_id) != contract.get("authority_account_id_digest")
        or condition
        != {"StringEquals": {"SAML:aud": expected_audience}}
        or set(statement) - {"Sid", "Effect", "Principal", "Action", "Condition"}
    ):
        _fail("COLLECTOR_TRUST_POLICY_INVALID")


def validate_candidate_capture(
    *,
    snapshot: Mapping[str, Any],
    binding: TargetBinding,
    collector_contract: Mapping[str, Any],
    repo_root: Path,
) -> bool:
    """Validate candidate provenance and the collector, but emit no safe result.

    This intentionally does not classify the target authority graph.  That
    graph cannot be trusted until materialization freezes a reviewed allowlist.
    """

    _validate_collector_contract(
        collector_contract, binding=binding, repo_root=repo_root
    )
    _validate_capture_provenance(
        snapshot=snapshot,
        binding=binding,
        collector_contract=collector_contract,
        repo_root=repo_root,
        prefix="CANDIDATE",
    )
    return True


def _validate_capture_provenance(
    *,
    snapshot: Mapping[str, Any],
    binding: TargetBinding,
    collector_contract: Mapping[str, Any],
    repo_root: Path,
    prefix: str,
) -> None:
    _validate_snapshot_envelope(
        snapshot, binding=binding, contract=collector_contract, prefix=prefix
    )
    started = _parse_time(
        snapshot.get("capture_started_at"), f"{prefix}_CAPTURE_TIME_INVALID"
    )
    completed = _parse_time(
        snapshot.get("capture_completed_at"), f"{prefix}_CAPTURE_TIME_INVALID"
    )
    expires = _parse_time(
        snapshot.get("capture_expires_at"), f"{prefix}_CAPTURE_TIME_INVALID"
    )
    contract_created = _parse_time(
        collector_contract.get("created_at"), "COLLECTOR_CONTRACT_TIMESTAMP_INVALID"
    )
    if (
        contract_created > started
        or not started <= completed < expires
        or completed - started > timedelta(minutes=5)
        or expires - completed > timedelta(minutes=5)
    ):
        _fail(f"{prefix}_CAPTURE_TIME_INVALID")
    iam = snapshot.get("iam")
    if not isinstance(iam, Mapping):
        _fail(f"{prefix}_SNAPSHOT_MALFORMED")
    _find_collector_role(
        iam,
        collector_contract,
        render_collector_inline_policy(binding=binding, repo_root=repo_root),
    )


def _trust_binding(
    role: Mapping[str, Any],
    binding: TargetBinding,
    permission_set_name: str,
    identity_center_region: str,
) -> tuple[str, str]:
    document = role.get("AssumeRolePolicyDocument")
    statements = _statements(document, "CANDIDATE_TRUST_POLICY_INVALID")
    if len(statements) != 1:
        _fail("CANDIDATE_TRUST_POLICY_INVALID")
    statement = statements[0]
    condition = statement.get("Condition")
    principal = statement.get("Principal")
    permission_set = (
        condition.get("ArnEquals", {}).get("aws:PrincipalArn")
        if isinstance(condition, Mapping) and isinstance(condition.get("ArnEquals"), Mapping)
        else None
    )
    expected_root = f"arn:{binding.partition}:iam::{binding.authority_account_id}:root"
    regional_path = (
        "" if identity_center_region == "us-east-1" else f"/{re.escape(identity_center_region)}"
    )
    role_pattern = re.compile(
        rf"arn:{re.escape(binding.partition)}:iam::{binding.authority_account_id}:role/"
        rf"aws-reserved/sso\.amazonaws\.com{regional_path}/"
        rf"AWSReservedSSO_{re.escape(permission_set_name)}_[0-9a-fA-F]{{16}}"
    )
    if (
        statement.get("Effect") != "Allow"
        or statement.get("Action") != "sts:AssumeRole"
        or principal != {"AWS": expected_root}
        or not isinstance(permission_set, str)
        or role_pattern.fullmatch(permission_set) is None
        or set(condition or {}) != {"ArnEquals"}
        or set(condition["ArnEquals"]) != {"aws:PrincipalArn"}
    ):
        _fail("CANDIDATE_TRUST_POLICY_INVALID")
    return permission_set, canonical_digest(document)


def _allow_statements(
    document: object, *, require_direct_effect_deny: bool = False
) -> list[Mapping[str, Any]]:
    statements = _statements(document, "CANDIDATE_POLICY_INVALID")
    allow = [statement for statement in statements if statement.get("Effect") == "Allow"]
    deny = [statement for statement in statements if statement.get("Effect") == "Deny"]
    if require_direct_effect_deny:
        if len(deny) != 1:
            _fail("CANDIDATE_POLICY_INVALID")
        statement = deny[0]
        if (
            statement.get("Sid") != "DenyDirectRetirementEffects"
            or set(
                _string_values(
                    statement.get("Action"), "CANDIDATE_POLICY_INVALID"
                )
            )
            != EXPECTED_DIRECT_EFFECT_DENY_ACTIONS
            or statement.get("Resource") != "*"
            or set(statement) != {"Sid", "Effect", "Action", "Resource"}
        ):
            _fail("CANDIDATE_POLICY_INVALID")
    elif deny:
        _fail("CANDIDATE_POLICY_INVALID")
    if len(allow) + len(deny) != len(statements):
        _fail("CANDIDATE_POLICY_INVALID")
    return allow


def _expected_edges(
    snapshot: Mapping[str, Any], binding: TargetBinding, identity_center_region: str
) -> list[dict[str, Any]]:
    iam = snapshot.get("iam")
    lam = snapshot.get("lambda")
    if not isinstance(iam, Mapping) or not isinstance(lam, Mapping):
        _fail("CANDIDATE_SNAPSHOT_MALFORMED")
    classifier = _find_exact_role(iam, binding, CLASSIFIER_ROLE_NAME)
    approver = _find_exact_role(iam, binding, APPROVER_ROLE_NAME)
    classifier_arn = str(classifier["Arn"])
    approver_arn = str(approver["Arn"])
    classifier_ps, classifier_trust_digest = _trust_binding(
        classifier, binding, CLASSIFIER_PERMISSION_SET_NAME, identity_center_region
    )
    approver_ps, approver_trust_digest = _trust_binding(
        approver, binding, APPROVER_PERMISSION_SET_NAME, identity_center_region
    )
    role_specs = (
        (classifier, classifier_arn, classifier_ps, "classifier", ("classify",), classifier_trust_digest, "CLASSIFIER_INVOKER_ROLE"),
        (approver, approver_arn, approver_ps, "independent_approver", ("retire", "reconcile"), approver_trust_digest, "APPROVER_INVOKER_ROLE"),
    )
    edges: list[dict[str, Any]] = []
    for role, role_arn, permission_set, duty, aliases, trust_digest, role_scope in role_specs:
        inline = role.get("RolePolicyList")
        if not isinstance(inline, list) or len(inline) != 1 or not isinstance(inline[0], Mapping):
            _fail("CANDIDATE_POLICY_INVALID")
        document = inline[0].get("PolicyDocument")
        source_digest = canonical_digest(document)
        observed: set[tuple[str, str]] = set()
        for statement in _allow_statements(
            document, require_direct_effect_deny=True
        ):
            actions = _string_values(statement.get("Action"), "CANDIDATE_POLICY_INVALID")
            resources = _string_values(statement.get("Resource"), "CANDIDATE_POLICY_INVALID")
            if len(actions) != 1 or actions[0] not in {
                "lambda:InvokeFunctionUrl", "lambda:InvokeFunction"
            }:
                _fail("CANDIDATE_POLICY_INVALID")
            action = actions[0]
            condition = statement.get("Condition")
            expected_condition = (
                {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
                if action == "lambda:InvokeFunctionUrl"
                else {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}
            )
            if condition not in (expected_condition, {"Bool": {"lambda:InvokedViaFunctionUrl": True}}):
                _fail("CANDIDATE_POLICY_INVALID")
            for resource in resources:
                alias = resource.rsplit(":", 1)[-1]
                if alias not in aliases or resource != binding.alias_arn(alias):
                    _fail("CANDIDATE_POLICY_INVALID")
                observed.add((alias, action))
                edges.append(
                    {
                        "authority_class": "INVOCATION",
                        "source_type": "IAM_ROLE_INLINE_POLICY",
                        "duty": duty,
                        "target_scope": f"EXACT_{alias.upper()}_ALIAS",
                        "action": action,
                        "condition_class": (
                            "FUNCTION_URL_AUTH_TYPE_AWS_IAM"
                            if action == "lambda:InvokeFunctionUrl"
                            else "INVOKED_VIA_FUNCTION_URL_TRUE"
                        ),
                        "principal_digest": digest_text(role_arn),
                        "resource_digest": digest_text(resource),
                        "source_document_digest": source_digest,
                    }
                )
        expected_pairs = {(alias, action) for alias in aliases for action in (
            "lambda:InvokeFunctionUrl", "lambda:InvokeFunction"
        )}
        if observed != expected_pairs:
            _fail("CANDIDATE_POLICY_INVALID")
        edges.append(
            {
                "authority_class": "TRUST",
                "source_type": "IAM_ROLE_TRUST_POLICY",
                "duty": duty,
                "target_scope": role_scope,
                "action": "sts:AssumeRole",
                "condition_class": "EXACT_PERMISSION_SET_TRUST",
                "principal_digest": digest_text(permission_set),
                "resource_digest": digest_text(role_arn),
                "source_document_digest": trust_digest,
            }
        )

    policies = lam.get("resource_policies")
    if not isinstance(policies, list):
        _fail("CANDIDATE_POLICY_INVALID")
    expected_resources = {
        binding.alias_arn("classify"): (classifier_arn, "classifier"),
        binding.alias_arn("retire"): (approver_arn, "independent_approver"),
        binding.alias_arn("reconcile"): (approver_arn, "independent_approver"),
    }
    target_policies = {
        item.get("resource_arn"): item.get("policy_document")
        for item in policies
        if isinstance(item, Mapping)
        and isinstance(item.get("resource_arn"), str)
        and item["resource_arn"].startswith(binding.function_arn)
    }
    if set(target_policies) != set(expected_resources):
        _fail("CANDIDATE_POLICY_INVALID")
    for resource, (role_arn, duty) in expected_resources.items():
        document = target_policies[resource]
        source_digest = canonical_digest(document)
        observed_actions: set[str] = set()
        for statement in _allow_statements(document):
            actions = _string_values(statement.get("Action"), "CANDIDATE_POLICY_INVALID")
            principal = statement.get("Principal")
            if len(actions) != 1 or principal != {"AWS": role_arn} or statement.get("Resource") != resource:
                _fail("CANDIDATE_POLICY_INVALID")
            action = actions[0]
            if action not in {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}:
                _fail("CANDIDATE_POLICY_INVALID")
            expected_condition = (
                {"StringEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}
                if action == "lambda:InvokeFunctionUrl"
                else {"Bool": {"lambda:InvokedViaFunctionUrl": "true"}}
            )
            if statement.get("Condition") not in (
                expected_condition, {"Bool": {"lambda:InvokedViaFunctionUrl": True}}
            ):
                _fail("CANDIDATE_POLICY_INVALID")
            observed_actions.add(action)
            alias = resource.rsplit(":", 1)[-1]
            edges.append(
                {
                    "authority_class": "INVOCATION",
                    "source_type": "LAMBDA_RESOURCE_POLICY",
                    "duty": duty,
                    "target_scope": f"EXACT_{alias.upper()}_ALIAS",
                    "action": action,
                    "condition_class": (
                        "FUNCTION_URL_AUTH_TYPE_AWS_IAM"
                        if action == "lambda:InvokeFunctionUrl"
                        else "INVOKED_VIA_FUNCTION_URL_TRUE"
                    ),
                    "principal_digest": digest_text(role_arn),
                    "resource_digest": digest_text(resource),
                    "source_document_digest": source_digest,
                }
            )
        if observed_actions != {"lambda:InvokeFunctionUrl", "lambda:InvokeFunction"}:
            _fail("CANDIDATE_POLICY_INVALID")
    if len(edges) != EXPECTED_AUTHORITY_EDGE_COUNT:
        _fail("CANDIDATE_AUTHORITY_NOT_EXACT")
    return sorted(edges, key=canonical_digest)


def _runtime_artifact(snapshot: Mapping[str, Any], binding: TargetBinding) -> tuple[str, str]:
    lam = snapshot.get("lambda")
    if not isinstance(lam, Mapping):
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    aliases = lam.get("aliases")
    versions = lam.get("versions")
    functions = lam.get("functions")
    if not all(isinstance(value, list) for value in (aliases, versions, functions)):
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    target_aliases = {
        item.get("Name"): item.get("FunctionVersion")
        for item in aliases
        if isinstance(item, Mapping) and item.get("FunctionArn") in {
            binding.alias_arn(alias) for alias in EXPECTED_ALIASES
        }
    }
    if set(target_aliases) != set(EXPECTED_ALIASES) or len(set(target_aliases.values())) != 1:
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    version = next(iter(target_aliases.values()))
    if not isinstance(version, str) or not version.isdigit():
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    published = [
        item for item in versions if isinstance(item, Mapping)
        and item.get("Version") == version
        and item.get("FunctionArn") == f"{binding.function_arn}:{version}"
    ]
    target_functions = [
        item for item in functions if isinstance(item, Mapping)
        and item.get("FunctionName") == binding.function_name
        and item.get("FunctionArn") == binding.function_arn
    ]
    if len(published) != 1 or len(target_functions) != 1:
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    code = published[0].get("CodeSha256")
    configuration = published[0].get("PublishedConfigurationDigest")
    if (
        not isinstance(code, str) or re.fullmatch(r"[A-Za-z0-9+/]{43}=", code) is None
        or not isinstance(configuration, str) or _DIGEST.fullmatch(configuration) is None
        or target_functions[0].get("CodeSha256") != code
        or target_functions[0].get("PublishedConfigurationDigest") != configuration
    ):
        _fail("CANDIDATE_RUNTIME_ARTIFACT_INVALID")
    return code, configuration


def _source_digests(repo_root: Path) -> tuple[str, str]:
    root = Path(repo_root).resolve()
    template_digest = _byte_digest(root / SOURCE_TEMPLATE_PATH, "SOURCE_TEMPLATE_UNAVAILABLE")
    bundle: list[dict[str, Any]] = []
    for relative in SOURCE_POLICY_PATHS:
        bundle.append({"path": relative.as_posix(), "document": _strict_json(root / relative, "SOURCE_POLICY_INVALID")})
    return template_digest, canonical_digest(bundle)


def validate_source_commit_binding(
    *, source_commit: str, repo_root: Path, include_runtime: bool = False
) -> None:
    """Bind the declared commit to the exact reviewed bytes in this checkout."""

    if not isinstance(source_commit, str) or _COMMIT.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_BINDING_INVALID")
    root = Path(repo_root).resolve()
    paths = (
        SOURCE_TEMPLATE_PATH,
        *SOURCE_POLICY_PATHS,
        *(RUNTIME_SOURCE_PATHS if include_runtime else ()),
    )
    try:
        verified = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", f"{source_commit}^{{commit}}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", source_commit, "HEAD"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        if verified != source_commit:
            _fail("SOURCE_COMMIT_BINDING_INVALID")
        for relative in paths:
            committed = subprocess.run(
                ["git", "-C", str(root), "show", f"{source_commit}:{relative.as_posix()}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
            ).stdout
            if committed != (root / relative).read_bytes():
                _fail("SOURCE_COMMIT_BINDING_INVALID")
    except LambdaAuthorityMaterializationError:
        raise
    except (OSError, subprocess.SubprocessError):
        _fail("SOURCE_COMMIT_BINDING_INVALID")


def materialize_allowlist_release(
    *,
    snapshot: Mapping[str, Any],
    binding: TargetBinding,
    collector_contract: Mapping[str, Any],
    source_commit: str,
    created_at: str,
    expires_at: str,
    repo_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a deterministic allowlist and short-lived review anchor."""

    if binding.function_name != BROKER_FUNCTION_NAME:
        _fail("BROKER_FUNCTION_BINDING_INVALID")
    if not isinstance(source_commit, str) or _COMMIT.fullmatch(source_commit) is None:
        _fail("SOURCE_COMMIT_INVALID")
    validate_candidate_capture(
        snapshot=snapshot,
        binding=binding,
        collector_contract=collector_contract,
        repo_root=repo_root,
    )
    created = _parse_time(created_at, "RELEASE_TIMESTAMP_INVALID")
    expires = _parse_time(expires_at, "RELEASE_TIMESTAMP_INVALID")
    candidate_completed = _parse_time(snapshot.get("capture_completed_at"), "CANDIDATE_CAPTURE_TIME_INVALID")
    candidate_expires = _parse_time(snapshot.get("capture_expires_at"), "CANDIDATE_CAPTURE_TIME_INVALID")
    if not (candidate_completed < created < expires < candidate_expires) or expires - created > timedelta(minutes=5):
        _fail("RELEASE_WINDOW_INVALID")
    rendered_policy = render_collector_inline_policy(binding=binding, repo_root=repo_root)
    iam = snapshot.get("iam")
    if not isinstance(iam, Mapping):
        _fail("CANDIDATE_SNAPSHOT_MALFORMED")
    _find_collector_role(iam, collector_contract, rendered_policy)
    edges = _expected_edges(
        snapshot, binding, str(collector_contract["identity_center_region"])
    )
    code_sha, configuration_sha = _runtime_artifact(snapshot, binding)
    template_sha, policy_bundle_sha = _source_digests(Path(repo_root))
    allowlist: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_allowlist",
        "environment": "non-production",
        "production": False,
        "inventory_scope": INVENTORY_SCOPE,
        "authority_account_id_digest": digest_text(binding.authority_account_id),
        "target_region": binding.region,
        "source_template_sha256": template_sha,
        "source_policy_bundle_sha256": policy_bundle_sha,
        "broker_artifact_code_sha256": code_sha,
        "broker_published_configuration_sha256": configuration_sha,
        "collector_role_principal_digest": collector_contract["collector_role_sts_arn_digest"],
        "expected_authority_edges": edges,
        "forbidden_authority_classes": sorted(EXPECTED_FORBIDDEN_AUTHORITY_CLASSES),
        "live_effect_authorized": False,
        "created_at": created_at,
    }
    allowlist["allowlist_digest"] = canonical_digest(allowlist)
    try:
        validate_reviewed_allowlist(
            allowlist=allowlist,
            binding=binding,
            expected_allowlist_digest=allowlist["allowlist_digest"],
        )
        inventory, receipt = analyze_authority_inventory(
            allowlist=allowlist,
            snapshot=snapshot,
            binding=binding,
            evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
            decision_at=created_at,
        )
    except AuthorityInventoryError:
        _fail("CANDIDATE_AUTHORITY_NOT_EXACT")
    if inventory.get("status") != INVENTORY_REVIEW_SAFE or receipt.get("status") != RECEIPT_REVIEW_REQUIRED:
        _fail("CANDIDATE_AUTHORITY_NOT_EXACT")
    release: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "platform_authority_lambda_invocation_allowlist_release",
        "environment": "non-production",
        "production": False,
        "release_status": "MATERIALIZED_REVIEW_REQUIRED",
        "authority_account_id_digest": digest_text(binding.authority_account_id),
        "target_region": binding.region,
        "source_commit": source_commit,
        "source_template_sha256": template_sha,
        "source_policy_bundle_sha256": policy_bundle_sha,
        "broker_artifact_code_sha256": code_sha,
        "broker_published_configuration_sha256": configuration_sha,
        "collector_contract_digest": collector_contract["collector_contract_digest"],
        "collector_role_principal_digest": collector_contract["collector_role_sts_arn_digest"],
        "candidate_snapshot_digest": snapshot["snapshot_digest"],
        "expected_authority_edges_digest": canonical_digest(edges),
        "allowlist_digest": allowlist["allowlist_digest"],
        "created_at": created_at,
        "expires_at": expires_at,
        "aws_readonly_inventory_eligible": True,
        "live_effect_authorized": False,
        "deployment_authorized": False,
    }
    release["release_digest"] = canonical_digest(release)
    return allowlist, release


def validate_release_bundle(
    *,
    allowlist: Mapping[str, Any],
    release: Mapping[str, Any],
    collector_contract: Mapping[str, Any],
    binding: TargetBinding,
    expected_release_digest: str,
    evaluation_at: str,
) -> str:
    """Validate the independent release anchor before any AWS client exists."""

    root = Path(__file__).resolve().parents[1]
    _validate_collector_contract(collector_contract, binding=binding, repo_root=root)
    required = {
        "schema_version", "record_type", "environment", "production", "release_status",
        "authority_account_id_digest", "target_region", "source_commit", "source_template_sha256",
        "source_policy_bundle_sha256", "broker_artifact_code_sha256",
        "broker_published_configuration_sha256", "collector_contract_digest",
        "collector_role_principal_digest", "candidate_snapshot_digest",
        "expected_authority_edges_digest", "allowlist_digest", "created_at", "expires_at",
        "aws_readonly_inventory_eligible", "live_effect_authorized", "deployment_authorized",
        "release_digest",
    }
    if set(release) != required:
        _fail("RELEASE_FIELDS_INVALID")
    if not isinstance(release.get("source_commit"), str) or _COMMIT.fullmatch(
        str(release["source_commit"])
    ) is None:
        _fail("RELEASE_FIELDS_INVALID")
    for field in (
        "source_template_sha256",
        "source_policy_bundle_sha256",
        "broker_published_configuration_sha256",
        "collector_contract_digest",
        "collector_role_principal_digest",
        "candidate_snapshot_digest",
        "expected_authority_edges_digest",
        "allowlist_digest",
        "release_digest",
    ):
        value = release.get(field)
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            _fail("RELEASE_FIELDS_INVALID")
    code_sha = release.get("broker_artifact_code_sha256")
    if not isinstance(code_sha, str) or re.fullmatch(r"[A-Za-z0-9+/]{43}=", code_sha) is None:
        _fail("RELEASE_FIELDS_INVALID")
    calculated = canonical_digest({key: value for key, value in release.items() if key != "release_digest"})
    if release.get("release_digest") != calculated:
        _fail("RELEASE_DIGEST_MISMATCH")
    if not isinstance(expected_release_digest, str) or _DIGEST.fullmatch(expected_release_digest) is None or expected_release_digest != release["release_digest"]:
        _fail("REVIEWED_RELEASE_DIGEST_MISMATCH")
    if release.get("allowlist_digest") != allowlist.get("allowlist_digest"):
        _fail("RELEASE_ALLOWLIST_DIGEST_MISMATCH")
    if (
        release.get("schema_version") != "1"
        or release.get("record_type") != "platform_authority_lambda_invocation_allowlist_release"
        or release.get("environment") != "non-production"
        or release.get("production") is not False
        or release.get("release_status") != "MATERIALIZED_REVIEW_REQUIRED"
        or release.get("authority_account_id_digest") != digest_text(binding.authority_account_id)
        or release.get("target_region") != binding.region
        or release.get("aws_readonly_inventory_eligible") is not True
        or release.get("live_effect_authorized") is not False
        or release.get("deployment_authorized") is not False
    ):
        _fail("RELEASE_BINDING_INVALID")
    if (
        release.get("collector_contract_digest")
        != collector_contract.get("collector_contract_digest")
        or release.get("collector_role_principal_digest")
        != collector_contract.get("collector_role_sts_arn_digest")
    ):
        _fail("COLLECTOR_CONTRACT_DIGEST_MISMATCH")
    if (
        release.get("expected_authority_edges_digest")
        != canonical_digest(allowlist.get("expected_authority_edges"))
        or allowlist.get("created_at") != release.get("created_at")
    ):
        _fail("RELEASE_ALLOWLIST_BINDING_MISMATCH")
    template_sha, policy_sha = _source_digests(root)
    validate_source_commit_binding(
        source_commit=str(release["source_commit"]),
        repo_root=root,
        include_runtime=True,
    )
    if release.get("source_template_sha256") != template_sha or release.get("source_policy_bundle_sha256") != policy_sha:
        _fail("RELEASE_SOURCE_DIGEST_MISMATCH")
    if (
        allowlist.get("source_template_sha256") != template_sha
        or allowlist.get("source_policy_bundle_sha256") != policy_sha
        or release.get("broker_artifact_code_sha256") != allowlist.get("broker_artifact_code_sha256")
        or release.get("broker_published_configuration_sha256") != allowlist.get("broker_published_configuration_sha256")
    ):
        _fail("RELEASE_ALLOWLIST_BINDING_MISMATCH")
    try:
        validate_reviewed_allowlist(
            allowlist=allowlist,
            binding=binding,
            expected_allowlist_digest=release["allowlist_digest"],
        )
    except AuthorityInventoryError:
        _fail("RELEASE_ALLOWLIST_BINDING_MISMATCH")
    created = _parse_time(release.get("created_at"), "RELEASE_TIMESTAMP_INVALID")
    expires = _parse_time(release.get("expires_at"), "RELEASE_TIMESTAMP_INVALID")
    evaluation = _parse_time(evaluation_at, "RELEASE_TIMESTAMP_INVALID")
    if not (
        created < expires
        and expires - created <= timedelta(minutes=5)
        and created <= evaluation < expires
    ):
        _fail("RELEASE_EXPIRED")
    return str(collector_contract["collector_role_sts_arn_digest"])


def validate_fresh_capture(
    *,
    candidate_snapshot: Mapping[str, Any],
    fresh_snapshot: Mapping[str, Any],
    allowlist: Mapping[str, Any],
    release: Mapping[str, Any],
    collector_contract: Mapping[str, Any],
    binding: TargetBinding,
    expected_release_digest: str,
    evaluation_at: str,
) -> bool:
    """Prove a separate, later AWS capture still has the exact closed graph."""

    validate_release_bundle(
        allowlist=allowlist,
        release=release,
        collector_contract=collector_contract,
        binding=binding,
        expected_release_digest=expected_release_digest,
        evaluation_at=evaluation_at,
    )
    root = Path(__file__).resolve().parents[1]
    _validate_capture_provenance(
        snapshot=candidate_snapshot,
        binding=binding,
        collector_contract=collector_contract,
        repo_root=root,
        prefix="CANDIDATE",
    )
    _validate_capture_provenance(
        snapshot=fresh_snapshot,
        binding=binding,
        collector_contract=collector_contract,
        repo_root=root,
        prefix="FRESH",
    )
    if candidate_snapshot.get("snapshot_digest") != release.get("candidate_snapshot_digest"):
        _fail("CANDIDATE_SNAPSHOT_RELEASE_MISMATCH")
    if fresh_snapshot.get("snapshot_digest") == candidate_snapshot.get("snapshot_digest"):
        _fail("FRESH_CAPTURE_REQUIRED")
    if fresh_snapshot.get("collector_nonce") == candidate_snapshot.get("collector_nonce"):
        _fail("FRESH_CAPTURE_REQUIRED")
    candidate_completed = _parse_time(candidate_snapshot.get("capture_completed_at"), "CANDIDATE_CAPTURE_TIME_INVALID")
    candidate_expires = _parse_time(candidate_snapshot.get("capture_expires_at"), "CANDIDATE_CAPTURE_TIME_INVALID")
    fresh_started = _parse_time(fresh_snapshot.get("capture_started_at"), "FRESH_CAPTURE_TIME_INVALID")
    release_created = _parse_time(release.get("created_at"), "RELEASE_TIMESTAMP_INVALID")
    release_expires = _parse_time(release.get("expires_at"), "RELEASE_TIMESTAMP_INVALID")
    if not (
        candidate_completed < release_created <= fresh_started
        and release_expires < candidate_expires
    ):
        _fail("FRESH_CAPTURE_ORDER_INVALID")
    try:
        inventory, receipt = analyze_authority_inventory(
            allowlist=allowlist,
            snapshot=fresh_snapshot,
            binding=binding,
            evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
            decision_at=evaluation_at,
        )
    except AuthorityInventoryError:
        _fail("FRESH_AUTHORITY_GRAPH_MISMATCH")
    if inventory.get("status") != INVENTORY_REVIEW_SAFE or receipt.get("status") != RECEIPT_REVIEW_REQUIRED:
        _fail("FRESH_AUTHORITY_GRAPH_MISMATCH")
    return True


def validate_private_output_path(*, output_dir: Path, repo_root: Path) -> Path:
    """Validate a create-only private destination before any expensive I/O."""

    output = Path(output_dir)
    repo = Path(repo_root).resolve()
    if output.is_symlink():
        _fail("OUTPUT_PATH_SYMLINK")
    if output.exists():
        _fail("OUTPUT_PATH_EXISTS")
    resolved = output.resolve(strict=False)
    if resolved == repo or repo in resolved.parents:
        _fail("OUTPUT_MUST_BE_OUTSIDE_REPOSITORY")
    return resolved


def write_private_bundle(
    *, output_dir: Path, repo_root: Path, artifacts: Mapping[str, Mapping[str, Any]]
) -> None:
    """Create a private evidence directory once, never inside the repository."""

    resolved = validate_private_output_path(
        output_dir=output_dir, repo_root=repo_root
    )
    if not artifacts:
        _fail("OUTPUT_ARTIFACTS_INVALID")
    for name, value in artifacts.items():
        if Path(name).name != name or not name.endswith(".json") or not isinstance(value, Mapping):
            _fail("ARTIFACT_NAME_INVALID")
    try:
        os.mkdir(resolved, 0o700)
        os.chmod(resolved, 0o700)
        for name in sorted(artifacts):
            path = resolved / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            try:
                payload = (json.dumps(artifacts[name], sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        _fail("OUTPUT_WRITE_FAILED")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(path, 0o600)
    except LambdaAuthorityMaterializationError:
        raise
    except OSError:
        _fail("OUTPUT_WRITE_FAILED")
