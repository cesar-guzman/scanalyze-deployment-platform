#!/usr/bin/env python3
"""Schema validation tool for Scanalyze Deployment Platform.

Validates JSON fixtures against their corresponding JSON Schemas.
Valid fixtures must pass. Invalid fixtures must fail with the documented error.
"""

import base64
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_GUG393_DISCOVERY_RECEIPT_MAXIMUMS = (
    ("provider_calls", 5_000),
    ("credential_vending_calls", 6),
    ("network_calls", 5_006),
    ("page_calls", 4_300),
    ("projected_response_bytes", 33_554_432),
)

try:
    import jsonschema
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError
    from referencing import Registry, Resource
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def load_json(path: Path) -> dict:
    """Load and parse a JSON file."""
    with open(path) as f:
        return json.load(f)


@lru_cache(maxsize=4)
def _schema_registry(schemas_dir: Path):
    """Build an offline registry for schemas that compose versioned contracts."""
    resources = []
    for schema_path in sorted(schemas_dir.glob("*.json")):
        schema = load_json(schema_path)
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def find_schema_for_fixture(fixture_name: str, schemas_dir: Path) -> Path | None:
    """Map a fixture filename to its schema."""
    # Additive versioned schemas must be selected before the legacy prefix
    # mappings below. For example, task-definition-v2-* must never fall back to
    # task-definition-input.v1.schema.json.
    versioned_mappings = {
        "enterprise-authorization": "enterprise-authorization.v{version}.schema.json",
        "frontend-config": "frontend-config.v{version}.schema.json",
        "github-deployment-identity": "github-deployment-identity.v{version}.schema.json",
        "github-environment-anchor": "github-environment-anchor.v{version}.schema.json",
        "github-platform-authority": "github-platform-authority.v{version}.schema.json",
        "identity-contract": "identity-contract.v{version}.schema.json",
        "platform-authority-bootstrap-authority-receipt": "platform-authority-bootstrap-authority-receipt.v{version}.schema.json",
        "platform-authority-bootstrap-approval": "platform-authority-bootstrap-approval.v{version}.schema.json",
        "platform-authority-bootstrap-artifact-authority": "platform-authority-bootstrap-artifact-authority.v{version}.schema.json",
        "platform-authority-bootstrap-artifact-package": "platform-authority-bootstrap-artifact-package.v{version}.schema.json",
        "platform-authority-bootstrap-artifact-signing-trust-root": "platform-authority-bootstrap-artifact-signing-trust-root.v{version}.schema.json",
        "platform-authority-bootstrap-identity-proof-receipt": "platform-authority-bootstrap-identity-proof-receipt.v{version}.schema.json",
        "platform-authority-bootstrap-plan": "platform-authority-bootstrap-plan.v{version}.schema.json",
        "platform-authority-bootstrap-signed-artifact-receipt": "platform-authority-bootstrap-signed-artifact-receipt.v{version}.schema.json",
        "platform-authority-bootstrap-verification": "platform-authority-bootstrap-verification.v{version}.schema.json",
        "platform-authority-change-set-retirement-ledger": (
            "platform-authority-change-set-retirement-ledger.v{version}.schema.json"
        ),
        "platform-authority-change-set-retirement-package-manifest": (
            "platform-authority-change-set-retirement-package-manifest.v{version}.schema.json"
        ),
        "platform-authority-change-set-retirement-single-operator-exception": (
            "platform-authority-change-set-retirement-single-operator-exception.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-execution-authorization": (
            "platform-authority-retirement-entrypoint-execution-authorization.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-execution-ledger": (
            "platform-authority-retirement-entrypoint-execution-ledger.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-intent": (
            "platform-authority-retirement-entrypoint-intent.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-materialization-receipt": (
            "platform-authority-retirement-entrypoint-materialization-receipt.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-plan": (
            "platform-authority-retirement-entrypoint-plan.v{version}.schema.json"
        ),
        "platform-authority-retirement-entrypoint-service-role-plan": (
            "platform-authority-retirement-entrypoint-service-role-plan.v{version}.schema.json"
        ),
        "platform-authority-retirement-ledger-factory-package": (
            "platform-authority-retirement-ledger-factory-package.v{version}.schema.json"
        ),
        "platform-authority-retirement-ledger-factory-receipt": (
            "platform-authority-retirement-ledger-factory-receipt.v{version}.schema.json"
        ),
        "platform-authority-gug365-executor-authority-evidence": (
            "platform-authority-gug365-executor-authority-evidence.v{version}.schema.json"
        ),
        "platform-authority-gug365-phase-execution-ledger": (
            "platform-authority-gug365-phase-execution-ledger.v{version}.schema.json"
        ),
        "platform-authority-gug390-live-run": (
            "platform-authority-gug390-live-run.v{version}.schema.json"
        ),
        "platform-authority-gug393-discovery-receipt": (
            "platform-authority-gug393-discovery-receipt.v{version}.schema.json"
        ),
        "platform-authority-gug395-preplan-seed-receipt": (
            "platform-authority-gug395-preplan-seed-receipt.v{version}.schema.json"
        ),
        "platform-authority-gug395-downstream-materialization-receipt": (
            "platform-authority-gug395-downstream-materialization-receipt.v{version}.schema.json"
        ),
        "platform-authority-gug395-preplan-collision-probe-receipt": (
            "platform-authority-gug395-preplan-collision-probe-receipt.v{version}.schema.json"
        ),
        "platform-authority-gug376-live-readonly-run": (
            "platform-authority-gug376-live-readonly-run.v{version}.schema.json"
        ),
        "platform-authority-gug376-live-readonly-handoff": (
            "platform-authority-gug376-live-readonly-handoff.v{version}.schema.json"
        ),
        "platform-authority-gug365-upstream-owner-decisions": (
            "platform-authority-gug365-upstream-owner-decisions.v{version}.schema.json"
        ),
        "platform-authority-gug365-upstream-inventory": (
            "platform-authority-gug365-upstream-inventory.v{version}.schema.json"
        ),
        "platform-authority-gug365-upstream-plan": (
            "platform-authority-gug365-upstream-plan.v{version}.schema.json"
        ),
        "platform-authority-gug365-upstream-phase-authorization": (
            "platform-authority-gug365-upstream-phase-authorization.v{version}.schema.json"
        ),
        "platform-authority-gug365-upstream-final-handoff": (
            "platform-authority-gug365-upstream-final-handoff.v{version}.schema.json"
        ),
        "platform-authority-founder-bootstrap-exception": "platform-authority-founder-bootstrap-exception.v{version}.schema.json",
        "platform-authority-founder-execution-ledger": "platform-authority-founder-execution-ledger.v{version}.schema.json",
        "platform-authority-founder-pep-intent": "platform-authority-founder-pep-intent.v{version}.schema.json",
        "platform-authority-founder-pep-ledger": "platform-authority-founder-pep-ledger.v{version}.schema.json",
        "platform-authority-founder-pep-revocation": "platform-authority-founder-pep-revocation.v{version}.schema.json",
        "platform-authority-founder-revocation": "platform-authority-founder-revocation.v{version}.schema.json",
        "platform-authority-identity-context-compatibility-receipt": "platform-authority-identity-context-compatibility-receipt.v{version}.schema.json",
        "platform-authority-identity-context-pep-binding": "platform-authority-identity-context-pep-binding.v{version}.schema.json",
        "platform-authority-identity-context-pep-compatibility-receipt": "platform-authority-identity-context-pep-compatibility-receipt.v{version}.schema.json",
        "platform-authority-identity-context-proof-receipt": "platform-authority-identity-context-proof-receipt.v{version}.schema.json",
        "platform-authority-identity-enhanced-binding": "platform-authority-identity-enhanced-binding.v{version}.schema.json",
        "platform-authority-identity-enhanced-session-receipt": "platform-authority-identity-enhanced-session-receipt.v{version}.schema.json",
        "platform-authority-lambda-invocation-allowlist": "platform-authority-lambda-invocation-allowlist.v{version}.schema.json",
        "platform-authority-lambda-invocation-allowlist-release": "platform-authority-lambda-invocation-allowlist-release.v{version}.schema.json",
        "platform-authority-lambda-invocation-collector-contract": "platform-authority-lambda-invocation-collector-contract.v{version}.schema.json",
        "platform-authority-lambda-invocation-inventory": "platform-authority-lambda-invocation-inventory.v{version}.schema.json",
        "platform-authority-lambda-invocation-guard-receipt": "platform-authority-lambda-invocation-guard-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-execution-ledger": "platform-authority-lambda-audit-execution-ledger.v{version}.schema.json",
        "platform-authority-lambda-audit-provisioning-intent": "platform-authority-lambda-audit-provisioning-intent.v{version}.schema.json",
        "platform-authority-lambda-audit-provisioning-receipt": "platform-authority-lambda-audit-provisioning-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-broker-topology": "platform-authority-lambda-audit-repair-broker-topology.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-broker-intent": "platform-authority-lambda-audit-repair-broker-intent.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-broker-ledger": "platform-authority-lambda-audit-repair-broker-ledger.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-broker-receipt": "platform-authority-lambda-audit-repair-broker-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-delegation-parameters": "platform-authority-lambda-audit-repair-delegation-parameters.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-delegation-change-set-receipt": "platform-authority-lambda-audit-repair-delegation-change-set-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-delegation-execution-receipt": "platform-authority-lambda-audit-repair-delegation-execution-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-delegation-live-receipt": "platform-authority-lambda-audit-repair-delegation-live-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-deployment-contract": "platform-authority-lambda-audit-repair-deployment-contract.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-gug220-evidence": "platform-authority-lambda-audit-repair-gug220-evidence.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-pep-parameters": "platform-authority-lambda-audit-repair-pep-parameters.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-pep-change-set-receipt": "platform-authority-lambda-audit-repair-pep-change-set-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-pep-execution-receipt": "platform-authority-lambda-audit-repair-pep-execution-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-effective-state": "platform-authority-lambda-audit-repair-effective-state.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-identity-materialization-receipt": "platform-authority-lambda-audit-repair-phase-b-identity-materialization-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-precondition-parameters": "platform-authority-lambda-audit-repair-phase-b-precondition-parameters.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-precondition-change-set-receipt": "platform-authority-lambda-audit-repair-phase-b-precondition-change-set-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-identity-binding": "platform-authority-lambda-audit-repair-phase-b-identity-binding.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-one-shot-execution-ledger": "platform-authority-lambda-audit-repair-phase-b-one-shot-execution-ledger.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-proof-receipt": "platform-authority-lambda-audit-repair-phase-b-proof-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-broker-effect-receipt": "platform-authority-lambda-audit-repair-phase-b-broker-effect-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-broker-topology-evidence": "platform-authority-lambda-audit-repair-phase-b-broker-topology-evidence.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-phase-b-closure-pending-receipt": "platform-authority-lambda-audit-repair-phase-b-closure-pending-receipt.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-package-manifest": "platform-authority-lambda-audit-repair-package-manifest.v{version}.schema.json",
        "platform-authority-lambda-audit-repair-signed-artifact": "platform-authority-lambda-audit-repair-signed-artifact.v{version}.schema.json",
        "release-attestation": "release-attestation.v{version}.schema.json",
        "release-deployment-projection": "release-deployment-projection.v{version}.schema.json",
        "release-trust-policy": "release-trust-policy.v{version}.schema.json",
        "release": "release.v{version}.schema.json",
        "task-definition": "task-definition-input.v{version}.schema.json",
    }
    for prefix, template in versioned_mappings.items():
        match = re.match(rf"^{re.escape(prefix)}-v([0-9]+)(?:-|$)", fixture_name)
        if match:
            schema_path = schemas_dir / template.format(version=match.group(1))
            return schema_path if schema_path.exists() else None

    # Direct mapping rules
    mappings = {
        "account-ready": "account-ready.v1.schema.json",
        "deployment-request": "deployment-request.v1.schema.json",
        "deployment-record": "deployment-record.v1.schema.json",
        "contract-envelope": "contract-envelope.v1.schema.json",
        "release-manifest": "release.v1.schema.json",
        "release-attestation": "release-attestation.v1.schema.json",
        "observability-export": "observability-export.v1.schema.json",
        "region-capability": "region-capability.v1.schema.json",
        "task-definition": "task-definition-input.v1.schema.json",
    }

    for prefix, schema_file in mappings.items():
        if fixture_name.startswith(prefix):
            schema_path = schemas_dir / schema_file
            if schema_path.exists():
                return schema_path

    # Try contract-specific schemas
    contract_match = re.match(r"contract-(\w+[\w-]*)-v([0-9]+)", fixture_name)
    if contract_match:
        layer = contract_match.group(1)
        version = contract_match.group(2)
        schema_path = schemas_dir / f"contract-{layer}.v{version}.schema.json"
        if schema_path.exists():
            return schema_path

    return None


def _aws_dns_suffix(partition: object) -> str | None:
    if partition in {"aws", "aws-us-gov"}:
        return "amazonaws.com"
    if partition == "aws-cn":
        return "amazonaws.com.cn"
    return None


def _validate_cognito_binding(instance: dict, *, require_arn: bool) -> list[str]:
    """Validate the provider tuple without echoing rejected identity values."""
    errors: list[str] = []
    partition = instance.get("aws_partition")
    region = instance.get("region")
    account_id = instance.get("account_id")
    user_pool_id = instance.get("cognito_user_pool_id")
    issuer = instance.get("cognito_issuer_url")
    suffix = _aws_dns_suffix(partition)

    if all(isinstance(value, str) for value in (region, user_pool_id)) and (
        not user_pool_id.startswith(f"{region}_")
    ):
        errors.append("cognito user pool id must match the bound region")

    if all(
        isinstance(value, str)
        for value in (region, user_pool_id, issuer, suffix)
    ):
        expected_issuer = f"https://cognito-idp.{region}.{suffix}/{user_pool_id}"
        if issuer != expected_issuer:
            errors.append("cognito issuer must match the bound pool and region")

    if require_arn:
        user_pool_arn = instance.get("cognito_user_pool_arn")
        if all(
            isinstance(value, str)
            for value in (
                partition,
                region,
                account_id,
                user_pool_id,
                user_pool_arn,
            )
        ):
            expected_arn = (
                f"arn:{partition}:cognito-idp:{region}:{account_id}:"
                f"userpool/{user_pool_id}"
            )
            if user_pool_arn != expected_arn:
                errors.append("cognito pool ARN must match the bound provider tuple")

    spa_client = instance.get("cognito_spa_client_id")
    m2m_clients = instance.get("m2m_client_ids")
    if isinstance(spa_client, str) and isinstance(m2m_clients, list) and (
        spa_client in m2m_clients
    ):
        errors.append("SPA and M2M client identities must be disjoint")
    return errors


def _validate_m2m_registry(
    instance: dict,
    *,
    declared_clients: object,
) -> list[str]:
    """Validate the GUG-102 client-to-tenant binding snapshot.

    An empty client and binding set is the only valid bootstrap state. Once a
    client is promoted, every client must have one exact ownership binding and
    every grant must select complete canonical action scope sets.
    """

    errors: list[str] = []
    expected_customer = instance.get("customer_id")
    expected_deployment = instance.get("deployment_id")
    declared_client_ids = (
        declared_clients
        if isinstance(declared_clients, list)
        and all(isinstance(client, str) for client in declared_clients)
        else []
    )
    action_scope_sets_raw = instance.get("action_scope_sets")
    action_scope_sets = (
        {
            action: set(scopes)
            for action, scopes in action_scope_sets_raw.items()
            if isinstance(action, str)
            and isinstance(scopes, list)
            and all(isinstance(scope, str) for scope in scopes)
        }
        if isinstance(action_scope_sets_raw, dict)
        else {}
    )
    action_names = ("read", "write", "admin")
    for index, action in enumerate(action_names):
        for other_action in action_names[index + 1:]:
            if action_scope_sets.get(action, set()) & action_scope_sets.get(
                other_action,
                set(),
            ):
                errors.append("action_scope_sets must be pairwise disjoint")
    scope_universe = (
        set().union(*action_scope_sets.values()) if action_scope_sets else set()
    )

    bindings = instance.get("m2m_bindings", [])
    if not isinstance(bindings, list):
        return errors

    bound_clients: list[str] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        client_id = binding.get("client_id")
        if isinstance(client_id, str):
            bound_clients.append(client_id)
        if binding.get("customer_id") != expected_customer:
            errors.append(
                "m2m_bindings.customer_id must match the contract customer_id"
            )
        if binding.get("deployment_id") != expected_deployment:
            errors.append(
                "m2m_bindings.deployment_id must match the contract deployment_id"
            )
        required_scopes_raw = binding.get("required_scopes", [])
        required_scopes = (
            set(required_scopes_raw)
            if isinstance(required_scopes_raw, list)
            and all(isinstance(scope, str) for scope in required_scopes_raw)
            else set()
        )
        if not required_scopes <= scope_universe:
            errors.append(
                "m2m_bindings.required_scopes must be within the action scope universe"
            )
        granted_actions = 0
        for action in action_names:
            action_scopes = action_scope_sets.get(action, set())
            selected = required_scopes & action_scopes
            if selected and selected != action_scopes:
                errors.append(
                    "m2m_bindings must grant each action scope set all-or-none"
                )
            if action_scopes and action_scopes <= required_scopes:
                granted_actions += 1
        if granted_actions == 0:
            errors.append("each m2m binding must grant at least one action")

    duplicate_clients = [
        client_id
        for client_id, count in Counter(bound_clients).items()
        if count > 1
    ]
    if duplicate_clients:
        errors.append("m2m_bindings client_id values must be unique")
    if set(bound_clients) != set(declared_client_ids):
        errors.append(
            "m2m_bindings must cover each declared m2m_client_id exactly once"
        )
    return errors


def _gug215_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _gug215_canonical_digest(value: dict) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _gug221_canonical_digest(value: dict) -> str:
    """Match the raw lowercase digest used by the GUG-221 broker runtime."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _gug365_repository_template(
    path: Path, *, replacements: dict[str, str]
) -> tuple[dict, str]:
    """Render one exact GUG-365 repository policy without contacting Git/AWS."""

    absolute = ROOT / path
    if absolute.is_symlink() or not absolute.is_file():
        raise ValueError("repository policy is unavailable")
    raw_bytes = absolute.read_bytes()
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("repository policy is not UTF-8") from exc
    placeholders = frozenset(re.findall(r"\$\{[^}]+\}", raw))
    expected = frozenset(f"${{{key}}}" for key in replacements)
    if placeholders != expected:
        raise ValueError("repository policy placeholders are not exact")
    for key, value in replacements.items():
        raw = raw.replace(f"${{{key}}}", value)
    if "${" in raw:
        raise ValueError("repository policy has unresolved placeholders")

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("repository policy has duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=unique_pairs)
    except json.JSONDecodeError as exc:
        raise ValueError("repository policy is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("repository policy is not an object")
    return document, "sha256:" + hashlib.sha256(raw_bytes).hexdigest()


def _gug365_statement(document: object, sid: str) -> dict:
    if not isinstance(document, dict):
        raise ValueError("policy document is not an object")
    statements = document.get("Statement")
    if not isinstance(statements, list):
        raise ValueError("policy statements are unavailable")
    matches = [
        item
        for item in statements
        if isinstance(item, dict) and item.get("Sid") == sid
    ]
    if len(matches) != 1:
        raise ValueError("policy statement is not exact")
    return matches[0]


def _gug365_exact_plan_contract_errors(instance: dict) -> list[str]:
    """Compare every executable policy/request/operation with repo contracts.

    Digest closure alone is not authority closure: an attacker can alter an IAM
    document and recompute every enclosing digest.  This validator therefore
    independently renders the checked-in policy templates, rebuilds all 36
    planned writes and all phase operation graphs, and compares exact values.
    """

    errors: list[str] = []
    try:
        from tooling import (
            platform_authority_retirement_entrypoint_service_role_materializer as gug365,
        )

        binding_digest = instance["gug363_pre_function_binding_sha256"]
        broker_function = instance["broker_function"]
        factory_function = instance["ledger_factory_function"]
        factory_log_group = instance["ledger_factory_log_group"]
        source_commit = broker_function["tags"]["source_commit"]
        if (
            not isinstance(source_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
            or broker_function["tags"].get(
                "gug363_pre_function_binding_sha256"
            )
            != binding_digest
        ):
            raise ValueError("source binding is not exact")

        policy_tags = [
            {"Key": "managed_by", "Value": "reviewed-direct-iam"},
            {"Key": "service", "Value": "scanalyze-platform-authority"},
            {"Key": "work_package", "Value": "GUG-365"},
            {"Key": "environment", "Value": "non-production"},
            {"Key": "production", "Value": "false"},
            {"Key": "source_commit", "Value": source_commit},
            {
                "Key": "gug363_pre_function_binding_sha256",
                "Value": binding_digest,
            },
        ]
        role_tags = [
            *policy_tags[:5],
            {
                "Key": "purpose",
                "Value": "gug365-direct-iam-materialized-role",
            },
            *policy_tags[5:],
        ]
        function_tags = {
            "managed_by": "reviewed-direct-lambda",
            "service": "scanalyze-platform-authority",
            "work_package": "GUG-365",
            "environment": "non-production",
            "production": "false",
            "source_commit": source_commit,
            "gug363_pre_function_binding_sha256": binding_digest,
        }
        if broker_function.get("tags") != function_tags:
            errors.append("GUG-365 broker function tags are not exact")
        if factory_function.get("tags") != function_tags:
            errors.append("GUG-365 ledger factory function tags are not exact")
        if factory_log_group.get("tags") != {
            **function_tags,
            "managed_by": "reviewed-direct-logs",
        }:
            errors.append("GUG-365 ledger factory log tags are not exact")

        signed_binding = instance["signed_artifact_binding"]
        if signed_binding.get("binding_digest") != _canonical_sha256(
            {
                key: value
                for key, value in signed_binding.items()
                if key != "binding_digest"
            }
        ):
            errors.append("GUG-365 signed artifact binding is not digest closed")

        boundary_by_key = {
            item["key"]: item for item in instance["boundaries"]
        }
        if list(boundary_by_key) != list(gug365.BOUNDARY_ORDER):
            raise ValueError("boundary order is not exact")
        broker_document = boundary_by_key["broker"]["document"]
        change_set_name = _gug365_statement(
            broker_document, "DescribeOnlyExactRecoveryChangeSet"
        )["Condition"]["StringEquals"]["cloudformation:ChangeSetName"]
        retirement_id = _gug365_statement(
            broker_document, "UseOnlyExactLedgerItem"
        )["Condition"]["ForAllValues:StringEquals"][
            "dynamodb:LeadingKeys"
        ][0]
        identity_center_application_arn = _gug365_statement(
            broker_document, "ExchangeOnlyExactIdentityContextCode"
        )["Resource"]
        if (
            not isinstance(change_set_name, str)
            or re.fullmatch(
                r"scanalyze-platform-authority-bootstrap-[0-9]{14}",
                change_set_name,
            )
            is None
            or not isinstance(retirement_id, str)
            or re.fullmatch(r"gug215#sha256:[0-9a-f]{64}", retirement_id)
            is None
            or not isinstance(identity_center_application_arn, str)
            or re.fullmatch(
                rf"arn:aws:sso::{gug365.AUTHORITY_ACCOUNT_ID}:application/"
                r"ssoins-[A-Za-z0-9-]+/apl-[A-Za-z0-9-]+",
                identity_center_application_arn,
            )
            is None
        ):
            raise ValueError("GUG-363 policy substitutions are not exact")

        boundary_arns = {
            key: gug365._policy_arn(gug365.BOUNDARY_NAMES[key])
            for key in gug365.BOUNDARY_ORDER
        }
        broker_arn = gug365._function_arn()
        render_bindings = {
            "aws_partition": gug365.PARTITION,
            "region": gug365.REGION,
            "authority_account_id": gug365.AUTHORITY_ACCOUNT_ID,
            "change_set_name": change_set_name,
            "retirement_id": retirement_id,
            "identity_center_application_arn": identity_center_application_arn,
            "broker_function_arn": broker_arn,
            "classifier_function_arn": f"{broker_arn}:single-classify",
            "approver_retire_function_arn": f"{broker_arn}:single-retire",
            "approver_reconcile_function_arn": (
                f"{broker_arn}:single-reconcile"
            ),
        }
        boundary_replacements = {
            "broker": {
                key: render_bindings[key]
                for key in (
                    "aws_partition",
                    "region",
                    "authority_account_id",
                    "change_set_name",
                    "retirement_id",
                    "identity_center_application_arn",
                    "broker_function_arn",
                )
            },
            "classifier_invoker": {
                "classifier_function_arn": render_bindings[
                    "classifier_function_arn"
                ]
            },
            "approver_invoker": {
                "approver_retire_function_arn": render_bindings[
                    "approver_retire_function_arn"
                ],
                "approver_reconcile_function_arn": render_bindings[
                    "approver_reconcile_function_arn"
                ],
            },
            "proof": {},
            "ledger_factory": {
                "ledger_table_arn": gug365._table_arn(),
                "ledger_factory_log_stream_arn": (
                    gug365._ledger_factory_log_stream_arn()
                ),
            },
        }
        expected_boundaries: list[dict] = []
        for key in gug365.BOUNDARY_ORDER:
            if key == "service_role":
                document = gug365._service_role_permissions_policy(
                    bindings={
                        **render_bindings,
                        "signed_bucket": signed_binding["bucket"],
                        "signed_key": signed_binding["key"],
                        "signed_version_id": signed_binding["version_id"],
                        "signed_kms_key_arn": signed_binding[
                            "sse_kms_key_arn"
                        ],
                        "code_signing_config_arn": signed_binding[
                            "code_signing_config_arn"
                        ],
                    },
                    boundary_arns=boundary_arns,
                )
                template_path = None
                template_digest = None
            else:
                template_path = gug365.BOUNDARY_TEMPLATE_PATHS[key]
                document, template_digest = _gug365_repository_template(
                    template_path,
                    replacements=boundary_replacements[key],
                )
            expected_boundaries.append(
                {
                    "key": key,
                    "policy_name": gug365.BOUNDARY_NAMES[key],
                    "path": gug365.MANAGED_POLICY_PATH,
                    "arn": boundary_arns[key],
                    "description": (
                        "GUG-365 exact "
                        f"{key.replace('_', ' ')} permissions boundary"
                    ),
                    "tags": policy_tags,
                    "document": document,
                    "document_digest": _canonical_sha256(document),
                    "template_path": (
                        None if template_path is None else template_path.as_posix()
                    ),
                    "template_sha256": template_digest,
                }
            )
        if instance["boundaries"] != expected_boundaries:
            errors.append(
                "GUG-365 boundary documents do not match exact repo contracts"
            )

        roles = [instance["service_role"], *instance["child_roles"]]
        if [role.get("role_name") for role in roles] != list(gug365.ROLE_ORDER):
            raise ValueError("role order is not exact")
        role_boundary_keys = {
            gug365.SERVICE_ROLE_NAME: "service_role",
            **gug365.CHILD_ROLE_BOUNDARY_KEYS,
        }
        for role in roles:
            role_name = role["role_name"]
            boundary_key = role_boundary_keys[role_name]
            if (
                role.get("arn") != gug365._role_arn(role_name)
                or role.get("boundary_key") != boundary_key
                or role.get("permissions_boundary_arn")
                != boundary_arns[boundary_key]
                or role.get("tags") != role_tags
                or role.get("trust_policy_digest")
                != _canonical_sha256(role.get("trust_policy"))
            ):
                errors.append("GUG-365 role contract is not exact")
                break

        expected_writes: list[dict] = []
        sequence = 1
        for boundary in expected_boundaries:
            request = {
                "PolicyName": boundary["policy_name"],
                "Path": boundary["path"],
                "PolicyDocument": gug365.canonical_json(
                    boundary["document"]
                ),
                "Description": boundary["description"],
                "Tags": policy_tags,
            }
            expected_writes.append(
                gug365._operation(
                    sequence=sequence,
                    action="iam:CreatePolicy",
                    target_arn=boundary["arn"],
                    request=request,
                )
            )
            sequence += 1
        proof_arn = boundary_arns["proof"]
        for role in roles:
            request = {
                "RoleName": role["role_name"],
                "Path": role["path"],
                "AssumeRolePolicyDocument": gug365.canonical_json(
                    role["trust_policy"]
                ),
                "Description": (
                    "GUG-357 dedicated CloudFormation service role"
                    if role["role_name"] == gug365.SERVICE_ROLE_NAME
                    else f"GUG-365 pre-created {role['role_name']} role"
                ),
                "MaxSessionDuration": role["max_session_duration"],
                "PermissionsBoundary": proof_arn,
                "Tags": role_tags,
            }
            expected_writes.append(
                gug365._operation(
                    sequence=sequence,
                    action="iam:CreateRole",
                    target_arn=role["arn"],
                    request=request,
                )
            )
            sequence += 1

        broker_writes = gug365._function_write_requests(
            broker_function, first_sequence=sequence
        )
        expected_writes.extend(broker_writes)
        sequence += len(broker_writes)
        log_writes = gug365._ledger_factory_log_group_write_requests(
            factory_log_group, first_sequence=sequence
        )
        expected_writes.extend(log_writes)
        sequence += len(log_writes)
        factory_writes = gug365._function_write_requests(
            factory_function, first_sequence=sequence
        )
        expected_writes.extend(factory_writes)
        sequence += len(factory_writes)

        role_by_name = {role["role_name"]: role for role in roles}
        factory_role = role_by_name[gug365.LEDGER_FACTORY_ROLE_NAME]
        factory_activator_writes = [
            gug365._operation(
                sequence=sequence,
                action="iam:AttachRolePolicy",
                target_arn=factory_role["arn"],
                request={
                    "RoleName": gug365.LEDGER_FACTORY_ROLE_NAME,
                    "PolicyArn": boundary_arns["ledger_factory"],
                },
            ),
            gug365._operation(
                sequence=sequence + 1,
                action="iam:PutRolePermissionsBoundary",
                target_arn=factory_role["arn"],
                request={
                    "RoleName": gug365.LEDGER_FACTORY_ROLE_NAME,
                    "PermissionsBoundary": boundary_arns["ledger_factory"],
                },
            ),
        ]
        expected_writes.extend(factory_activator_writes)
        sequence += 2
        factory_invoker_writes = [
            gug365._operation(
                sequence=sequence,
                action="lambda:InvokeFunction",
                target_arn=factory_function["immutable_version_arn"],
                request={
                    "FunctionName": factory_function[
                        "immutable_version_arn"
                    ],
                    "InvocationType": "RequestResponse",
                    "Payload": "{}",
                },
            )
        ]
        expected_writes.extend(factory_invoker_writes)
        sequence += 1
        factory_revoker_writes = [
            gug365._operation(
                sequence=sequence,
                action="iam:PutRolePermissionsBoundary",
                target_arn=factory_role["arn"],
                request={
                    "RoleName": gug365.LEDGER_FACTORY_ROLE_NAME,
                    "PermissionsBoundary": proof_arn,
                },
            ),
            gug365._operation(
                sequence=sequence + 1,
                action="iam:DetachRolePolicy",
                target_arn=factory_role["arn"],
                request={
                    "RoleName": gug365.LEDGER_FACTORY_ROLE_NAME,
                    "PolicyArn": boundary_arns["ledger_factory"],
                },
            ),
        ]
        expected_writes.extend(factory_revoker_writes)
        sequence += 2
        activator_writes: list[dict] = []
        for role_name in (
            gug365.BROKER_ROLE_NAME,
            gug365.CLASSIFIER_ROLE_NAME,
            gug365.APPROVER_ROLE_NAME,
            gug365.CLASSIFIER_PROOF_ROLE_NAME,
            gug365.APPROVER_PROOF_ROLE_NAME,
        ):
            role = role_by_name[role_name]
            activator_writes.append(
                gug365._operation(
                    sequence=sequence,
                    action="iam:AttachRolePolicy",
                    target_arn=role["arn"],
                    request={
                        "RoleName": role_name,
                        "PolicyArn": role["permissions_boundary_arn"],
                    },
                )
            )
            sequence += 1
        for role_name in (
            gug365.BROKER_ROLE_NAME,
            gug365.CLASSIFIER_ROLE_NAME,
            gug365.APPROVER_ROLE_NAME,
        ):
            role = role_by_name[role_name]
            activator_writes.append(
                gug365._operation(
                    sequence=sequence,
                    action="iam:PutRolePermissionsBoundary",
                    target_arn=role["arn"],
                    request={
                        "RoleName": role_name,
                        "PermissionsBoundary": role[
                            "permissions_boundary_arn"
                        ],
                    },
                )
            )
            sequence += 1
        service_role = role_by_name[gug365.SERVICE_ROLE_NAME]
        activator_writes.append(
            gug365._operation(
                sequence=sequence,
                action="iam:AttachRolePolicy",
                target_arn=service_role["arn"],
                request={
                    "RoleName": gug365.SERVICE_ROLE_NAME,
                    "PolicyArn": boundary_arns["service_role"],
                },
            )
        )
        sequence += 1
        activator_writes.append(
            gug365._operation(
                sequence=sequence,
                action="iam:PutRolePermissionsBoundary",
                target_arn=service_role["arn"],
                request={
                    "RoleName": gug365.SERVICE_ROLE_NAME,
                    "PermissionsBoundary": boundary_arns["service_role"],
                },
            )
        )
        expected_writes.extend(activator_writes)
        if instance["planned_iam_writes"] != expected_writes:
            errors.append(
                "GUG-365 planned IAM/Lambda/log requests are not exact"
            )

        all_policy_replacements = {
            "service_role_boundary_arn": boundary_arns["service_role"],
            "broker_boundary_arn": boundary_arns["broker"],
            "classifier_boundary_arn": boundary_arns[
                "classifier_invoker"
            ],
            "approver_boundary_arn": boundary_arns["approver_invoker"],
            "proof_boundary_arn": proof_arn,
            "ledger_factory_boundary_arn": boundary_arns[
                "ledger_factory"
            ],
            "service_role_arn": gug365.SERVICE_ROLE_ARN,
            "broker_role_arn": gug365._role_arn(gug365.BROKER_ROLE_NAME),
            "classifier_role_arn": gug365._role_arn(
                gug365.CLASSIFIER_ROLE_NAME
            ),
            "approver_role_arn": gug365._role_arn(
                gug365.APPROVER_ROLE_NAME
            ),
            "classifier_proof_role_arn": gug365._role_arn(
                gug365.CLASSIFIER_PROOF_ROLE_NAME
            ),
            "approver_proof_role_arn": gug365._role_arn(
                gug365.APPROVER_PROOF_ROLE_NAME
            ),
            "ledger_factory_role_arn": gug365._role_arn(
                gug365.LEDGER_FACTORY_ROLE_NAME
            ),
            "ledger_table_arn": gug365._table_arn(),
            "broker_function_arn": gug365._function_arn(),
            "ledger_factory_function_arn": (
                gug365._ledger_factory_function_arn()
            ),
            "ledger_factory_function_version_arn": (
                gug365._ledger_factory_function_arn(version="1")
            ),
            "ledger_factory_log_group_arn": (
                gug365._ledger_factory_log_group_arn()
            ),
            "signed_object_arn": (
                f"arn:aws:s3:::{signed_binding['bucket']}/"
                f"{signed_binding['key']}"
            ),
            "signed_bucket_arn": f"arn:aws:s3:::{signed_binding['bucket']}",
            "signed_version_id": signed_binding["version_id"],
            "signed_kms_key_arn": signed_binding["sse_kms_key_arn"],
            "code_signing_config_arn": signed_binding[
                "code_signing_config_arn"
            ],
            "ledger_factory_signed_object_arn": (
                f"arn:aws:s3:::{factory_function['signed_code']['s3_bucket']}/"
                f"{factory_function['signed_code']['s3_key']}"
            ),
            "ledger_factory_signed_bucket_arn": (
                "arn:aws:s3:::"
                f"{factory_function['signed_code']['s3_bucket']}"
            ),
            "ledger_factory_signed_version_id": factory_function[
                "signed_code"
            ]["s3_object_version"],
            "ledger_factory_signed_kms_key_arn": factory_function[
                "artifact_sse_kms_key_arn"
            ],
            "ledger_factory_code_signing_config_arn": factory_function[
                "code_signing_config_arn"
            ],
            "authority_account_id": gug365.AUTHORITY_ACCOUNT_ID,
            "region": gug365.REGION,
            "source_commit": source_commit,
            "gug363_pre_function_binding_sha256": binding_digest,
        }
        policy_paths = {
            "POLICY_FACTORY": gug365.POLICY_FACTORY_POLICY_PATH,
            "FOUNDATION_FACTORY": gug365.FOUNDATION_FACTORY_POLICY_PATH,
            "FUNCTION_FACTORY": gug365.FUNCTION_FACTORY_POLICY_PATH,
            "LEDGER_FACTORY_FUNCTION_FACTORY": (
                gug365.LEDGER_FACTORY_FUNCTION_FACTORY_POLICY_PATH
            ),
            "LEDGER_FACTORY_ACTIVATOR": (
                gug365.LEDGER_FACTORY_ACTIVATOR_POLICY_PATH
            ),
            "LEDGER_FACTORY_INVOKER": (
                gug365.LEDGER_FACTORY_INVOKER_POLICY_PATH
            ),
            "LEDGER_FACTORY_REVOKER": (
                gug365.LEDGER_FACTORY_REVOKER_POLICY_PATH
            ),
            "ACTIVATOR": gug365.ACTIVATOR_POLICY_PATH,
            "REVOCATOR": gug365.REVOCATOR_POLICY_PATH,
        }
        replacement_keys = {
            phase: frozenset(
                match[2:-1]
                for match in re.findall(
                    r"\$\{[^}]+\}",
                    (ROOT / path).read_text(encoding="utf-8"),
                )
            )
            for phase, path in policy_paths.items()
        }

        def expected_executor_policy(phase: str) -> dict:
            path = policy_paths[phase]
            document, template_digest = _gug365_repository_template(
                path,
                replacements={
                    key: str(all_policy_replacements[key])
                    for key in replacement_keys[phase]
                },
            )
            return {
                "phase": phase,
                "template_path": path.as_posix(),
                "template_sha256": template_digest,
                "document": document,
                "document_digest": _canonical_sha256(document),
                "projection_only": True,
                "created_by_this_plan": False,
            }

        phase_writes = {
            "POLICY_FACTORY": expected_writes[0:6],
            "FOUNDATION_FACTORY": expected_writes[6:13],
            "FUNCTION_FACTORY": expected_writes[13:16],
            "LEDGER_FACTORY_FUNCTION_FACTORY": expected_writes[16:21],
            "LEDGER_FACTORY_ACTIVATOR": expected_writes[21:23],
            "LEDGER_FACTORY_INVOKER": expected_writes[23:24],
            "LEDGER_FACTORY_REVOKER": expected_writes[24:26],
            "ACTIVATOR": expected_writes[26:36],
        }
        proof_boundary = next(
            item for item in expected_boundaries if item["key"] == "proof"
        )
        broker_role = role_by_name[gug365.BROKER_ROLE_NAME]
        for phase_contract in instance["authorization_phases"]:
            phase = phase_contract["phase"]
            expected_policy = expected_executor_policy(phase)
            if phase_contract.get("executor_policy") != expected_policy:
                errors.append(
                    f"GUG-365 {phase} executor policy is not the exact repo contract"
                )
            writes = phase_writes[phase]
            if phase_contract.get("mutations") != writes:
                errors.append(f"GUG-365 {phase} mutations are not exact")
            expected_operations = gug365._phase_operation_contract(
                phase=phase,
                writes=writes,
                proof_boundary=(
                    proof_boundary
                    if phase
                    in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                        "LEDGER_FACTORY_REVOKER",
                    }
                    else None
                ),
                function=(
                    broker_function
                    if phase
                    in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                    }
                    else None
                ),
                broker_role=(
                    broker_role
                    if phase
                    in {
                        "FUNCTION_FACTORY",
                        "LEDGER_FACTORY_FUNCTION_FACTORY",
                    }
                    else None
                ),
                factory_function=(
                    factory_function
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
                factory_role=(
                    factory_role
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
                factory_log_group=(
                    factory_log_group
                    if phase == "LEDGER_FACTORY_FUNCTION_FACTORY"
                    else None
                ),
            )
            if phase_contract.get("operations") != expected_operations:
                errors.append(f"GUG-365 {phase} operation graph is not exact")

        revocation_writes = [
            gug365._operation(
                sequence=index,
                action="iam:PutRolePermissionsBoundary",
                target_arn=role_by_name[role_name]["arn"],
                request={
                    "RoleName": role_name,
                    "PermissionsBoundary": proof_arn,
                },
            )
            for index, role_name in enumerate(
                (
                    gug365.BROKER_ROLE_NAME,
                    gug365.CLASSIFIER_ROLE_NAME,
                    gug365.APPROVER_ROLE_NAME,
                    gug365.SERVICE_ROLE_NAME,
                ),
                start=1,
            )
        ]
        revocation = instance["revocation"]
        if revocation.get("executor_policy") != expected_executor_policy(
            "REVOCATOR"
        ):
            errors.append(
                "GUG-365 REVOCATOR executor policy is not the exact repo contract"
            )
        if revocation.get("mutations") != revocation_writes:
            errors.append("GUG-365 REVOCATOR mutations are not exact")
        expected_revocation_operations = gug365._phase_operation_contract(
            phase="REVOCATOR",
            writes=revocation_writes,
            proof_boundary=proof_boundary,
        )
        if revocation.get("operations") != expected_revocation_operations:
            errors.append("GUG-365 REVOCATOR operation graph is not exact")

        expected_readbacks = gug365._readback_contracts(
            expected_boundaries,
            roles,
            (broker_function, factory_function),
            instance["ledger_table"],
            factory_log_group,
        )
        if instance["planned_readbacks"] != expected_readbacks:
            errors.append("GUG-365 planned readback requests are not exact")
    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ):
        errors.append("GUG-365 exact repository contract validation failed closed")
    return errors


def _validate_gug365_cross_boundary_artifact(
    instance: dict, *, schema_name: str
) -> list[str]:
    """Close canonical digests and causal structure beyond JSON shape checks."""

    errors: list[str] = []
    if schema_name == (
        "platform-authority-gug365-phase-execution-ledger.v1.schema.json"
    ):
        try:
            from tooling.platform_authority_gug365_phase_execution_ledger import (
                validate_consumed_causal_record,
                validate_ledger,
            )

            validate_ledger(
                instance,
                expected_plan_digest=instance.get("plan_digest"),
                expected_bundle_digest=instance.get("bundle_digest"),
                expected_phase=instance.get("phase"),
            )
            serialized = json.dumps(instance, sort_keys=True).casefold()
            if "arn:" in serialized:
                errors.append("GUG-365 phase ledger must not persist raw ARNs")
            outcomes = instance.get("operation_outcomes", [])
            causally_accepted = (
                instance.get("status") == "CONSUMED"
                and len(outcomes) == instance.get("operation_count")
                and all(item.get("result") == "SUCCEEDED" for item in outcomes)
            )
            if causally_accepted:
                claim = instance.get("claim", {})
                receipts = instance.get("receipt_chain", [])
                validate_consumed_causal_record(
                    instance,
                    expected_plan_digest=instance["plan_digest"],
                    expected_bundle_digest=instance["bundle_digest"],
                    expected_phase=instance["phase"],
                    expected_ledger_id=instance["ledger_id"],
                    expected_initial_ledger_digest=instance[
                        "initial_ledger_digest"
                    ],
                    expected_claim_nonce_digest=claim.get(
                        "claim_nonce_digest"
                    ),
                    expected_terminal_receipt_digest=receipts[-1].get(
                        "receipt_digest"
                    ),
                )
        except (ImportError, KeyError, ValueError) as exc:
            errors.append(f"GUG-365 phase execution ledger invalid: {exc}")
        return errors

    if schema_name == (
        "platform-authority-retirement-ledger-factory-package.v1.schema.json"
    ):
        try:
            from tooling.platform_authority_retirement_ledger_factory_package import (
                LedgerFactoryPackageError,
                validate_ledger_factory_package_manifest,
            )

            validate_ledger_factory_package_manifest(instance)
        except (ImportError, LedgerFactoryPackageError) as exc:
            errors.append(f"GUG-365 package manifest invalid: {exc}")
        return errors

    digest_field = {
        "platform-authority-retirement-ledger-factory-receipt.v1.schema.json": (
            "receipt_sha256"
        ),
        "platform-authority-gug365-executor-authority-evidence.v1.schema.json": (
            "evidence_digest"
        ),
    }.get(schema_name)
    if digest_field is not None:
        projection = {
            key: value for key, value in instance.items() if key != digest_field
        }
        if instance.get(digest_field) != _canonical_sha256(projection):
            errors.append(f"GUG-365 {digest_field} must seal the exact record")
        if schema_name.endswith("executor-authority-evidence.v1.schema.json") and (
            instance.get("session_remaining_seconds", 0)
            > instance.get("session_lifetime_seconds", 0)
        ):
            errors.append("GUG-365 session remaining time exceeds lifetime")
        if schema_name.endswith("executor-authority-evidence.v1.schema.json"):
            try:
                issued = datetime.fromisoformat(
                    instance["session_issued_at"].replace("Z", "+00:00")
                )
                collected = datetime.fromisoformat(
                    instance["evidence_collected_at"].replace("Z", "+00:00")
                )
                expires = datetime.fromisoformat(
                    instance["session_expires_at"].replace("Z", "+00:00")
                )
                lifetime = int((expires - issued).total_seconds())
                if (
                    not issued <= collected < expires
                    or lifetime != instance.get("session_lifetime_seconds")
                    or not 1 <= lifetime <= 900
                ):
                    errors.append(
                        "GUG-365 authority evidence session window is stale or inconsistent"
                    )
            except (KeyError, TypeError, ValueError):
                errors.append(
                    "GUG-365 authority evidence session window is invalid"
                )
        return errors

    if schema_name != (
        "platform-authority-retirement-entrypoint-service-role-plan.v1.schema.json"
    ):
        return errors

    section_digests = {
        "boundaries": "boundary_set_digest",
        "child_role_boundary_assignments": (
            "child_role_boundary_assignment_digest"
        ),
        "service_role": "service_role_digest",
        "child_roles": "child_role_set_digest",
        "ledger_table": "ledger_table_digest",
        "broker_function": "broker_function_digest",
        "ledger_factory_function": "ledger_factory_function_digest",
        "ledger_factory_log_group": "ledger_factory_log_group_digest",
        "authorization_phases": "authorization_phase_digest",
        "revocation": "revocation_digest",
        "planned_iam_writes": "planned_iam_write_digest",
        "planned_readbacks": "planned_readback_digest",
    }
    for section, digest in section_digests.items():
        if instance.get(digest) != _canonical_sha256(instance.get(section)):
            errors.append(f"GUG-365 {digest} does not seal {section}")
    projection = {
        key: value for key, value in instance.items() if key != "plan_digest"
    }
    if instance.get("plan_digest") != _canonical_sha256(projection):
        errors.append("GUG-365 plan_digest does not seal the complete plan")

    phases = instance.get("authorization_phases", [])
    expected_phases = [
        "POLICY_FACTORY",
        "FOUNDATION_FACTORY",
        "FUNCTION_FACTORY",
        "LEDGER_FACTORY_FUNCTION_FACTORY",
        "LEDGER_FACTORY_ACTIVATOR",
        "LEDGER_FACTORY_INVOKER",
        "LEDGER_FACTORY_REVOKER",
        "ACTIVATOR",
    ]
    if [item.get("phase") for item in phases] != expected_phases or [
        item.get("sequence") for item in phases
    ] != list(range(1, 9)):
        errors.append("GUG-365 authorization phase order is not exact")

    writes = instance.get("planned_iam_writes", [])
    if [item.get("sequence") for item in writes] != list(range(1, 37)):
        errors.append("GUG-365 write sequence is not exact")
    action_counts = Counter(item.get("allowed_action") for item in writes)
    expected_counts = Counter(
        {
            "iam:CreatePolicy": 6,
            "iam:CreateRole": 7,
            "iam:AttachRolePolicy": 7,
            "iam:PutRolePermissionsBoundary": 6,
            "iam:DetachRolePolicy": 1,
            "lambda:CreateFunction": 2,
            "lambda:PutRuntimeManagementConfig": 2,
            "lambda:PutFunctionConcurrency": 2,
            "lambda:InvokeFunction": 1,
            "logs:CreateLogGroup": 1,
            "logs:PutRetentionPolicy": 1,
        }
    )
    if action_counts != expected_counts:
        errors.append("GUG-365 write action multiset is not exact")
    for write in writes:
        if write.get("request_digest") != _canonical_sha256(
            write.get("request")
        ):
            errors.append("GUG-365 write request digest mismatch")
            break

    readbacks = instance.get("planned_readbacks", [])
    if [item.get("sequence") for item in readbacks] != list(range(1, 127)):
        errors.append("GUG-365 readback sequence is not exact")

    boundaries = {
        item.get("key"): item.get("arn") for item in instance.get("boundaries", [])
    }
    assignments = instance.get("child_role_boundary_assignments", [])
    if set(boundaries) != {
        "service_role",
        "broker",
        "classifier_invoker",
        "approver_invoker",
        "proof",
        "ledger_factory",
    } or any(
        boundaries.get(item.get("boundary_key")) != item.get("boundary_arn")
        for item in assignments
    ):
        errors.append("GUG-365 role-to-boundary assignment is not closed")

    target = instance.get("target", {})
    service_role = instance.get("service_role", {})
    factory = instance.get("ledger_factory_function", {})
    gate = instance.get("ledger_factory_causal_receipt_gate", {})
    if target.get("service_role_arn") != service_role.get("arn"):
        errors.append("GUG-365 target service role does not match role contract")
    if gate.get("qualified_function_arn") != factory.get(
        "immutable_version_arn"
    ):
        errors.append("GUG-365 receipt gate is not bound to immutable factory v1")

    try:
        from tooling import (
            platform_authority_retirement_entrypoint_service_role_materializer as gug365,
        )

        expected_table = {
            "arn": gug365._table_arn(),
            "table_name": gug365.LEDGER_TABLE_NAME,
            "key_schema": [
                {"AttributeName": "retirement_id", "KeyType": "HASH"}
            ],
            "attribute_definitions": [
                {"AttributeName": "retirement_id", "AttributeType": "S"}
            ],
            "billing_mode": "PAY_PER_REQUEST",
            "deletion_protection_enabled": True,
            "sse_specification": {
                "Enabled": True,
                "SSEType": "KMS",
                "KMSMasterKeyId": "alias/aws/dynamodb",
            },
            "table_class": "STANDARD",
            "point_in_time_recovery": {
                "PointInTimeRecoveryEnabled": True,
                "RecoveryPeriodInDays": 35,
            },
            "time_to_live": {
                "TimeToLiveStatus": "DISABLED",
                "AttributeName": None,
            },
            "global_secondary_indexes": [],
            "local_secondary_indexes": [],
            "replicas": [],
            "latest_stream_label": None,
            "tags": gug365._table_tags({}),
            "resource_policy": gug365._ledger_resource_policy(),
        }
        for key, value in expected_table.items():
            if instance.get("ledger_table", {}).get(key) != value:
                errors.append(f"GUG-365 ledger table {key} is not exact")
        kms_contract = instance.get("ledger_table", {}).get("kms_key_contract")
        if (
            not isinstance(kms_contract, dict)
            or kms_contract.get("alias") != "alias/aws/dynamodb"
            or kms_contract.get("metadata_projection", {}).get("KeyManager")
            != "AWS"
            or kms_contract.get("metadata_projection", {}).get("Origin")
            != "AWS_KMS"
            or kms_contract.get("raw_key_identifiers_persistence_permitted")
            is not False
        ):
            errors.append("GUG-365 AWS-managed DynamoDB KMS contract is not exact")
        if target.get("authority_account_id") != gug365.AUTHORITY_ACCOUNT_ID:
            errors.append("GUG-365 target account is not the authority account")
    except (ImportError, AttributeError) as exc:
        errors.append(f"GUG-365 semantic validator unavailable: {exc}")

    kms_reads = [
        item
        for item in readbacks
        if item.get("service") == "kms"
        and item.get("api_action") == "DescribeKey"
    ]
    if len(kms_reads) != 2:
        errors.append("GUG-365 requires two terminal KMS DescribeKey readbacks")
    tag_reads = [
        item
        for item in readbacks
        if item.get("service") == "dynamodb"
        and item.get("api_action") == "ListTagsOfResource"
    ]
    if len(tag_reads) != 2 or any(
        item.get("complete_pagination_required") is not True
        for item in tag_reads
    ):
        errors.append("GUG-365 DynamoDB tag readbacks must close pagination twice")
    factory_version_arn = factory.get("immutable_version_arn")
    qualified_reads = [
        item
        for item in readbacks
        if item.get("service") == "lambda"
        and item.get("api_action")
        in {
            "GetFunction",
            "GetFunctionConfiguration",
            "GetRuntimeManagementConfig",
            "GetPolicy",
        }
        and item.get("target_arn") == factory_version_arn
    ]
    if len(qualified_reads) < 4 or any(
        item.get("request", {}).get("Qualifier") != "1"
        for item in qualified_reads
    ):
        errors.append("GUG-365 factory v1 readbacks are not fully qualified")
    errors.extend(_gug365_exact_plan_contract_errors(instance))
    return errors


def _gug221_initial_ledger_binding(instance: dict) -> dict:
    """Reconstruct the immutable Plan record whose digest survives CAS updates."""
    binding_fields = (
        "schema_version",
        "record_type",
        "repair_id",
        "intent_digest",
        "source_commit",
        "original_gug220_ledger_digest",
        "authority_account_id",
        "management_account_id",
        "region",
        "plan_function_version",
        "repair_function_version",
        "repair_not_before",
        "repair_not_after",
        "planned_state_digest",
        "provider_immutable",
        "claim_condition",
        "mutation_retry_attempted",
        "production_authorized",
        "planned_at",
    )
    initial = {field: instance.get(field) for field in binding_fields}
    initial.update(
        {
            "status": "PLAN_VERIFIED",
            "stage": "PLAN_STATE_VERIFIED",
            "effects_attempted": 0,
            "effects_completed": 0,
            "state_digest": instance.get("planned_state_digest"),
        }
    )
    return initial


def _validate_gug215_ledger(instance: dict) -> list[str]:
    errors: list[str] = []
    state = instance.get("state")
    schema_version = instance.get("schema_version")
    allowed_states = (
        {"CLASSIFIED", "EXCEPTION_ACCEPTED", "ATTEMPTED", "RETIRED_RECONCILED"}
        if schema_version == "3"
        else {"CLASSIFIED", "APPROVED", "ATTEMPTED", "RETIRED_RECONCILED"}
    )
    if state not in allowed_states:
        errors.append("ledger must preserve one of the four durable states")
    users_equal = (
        instance.get("classifier_identity_store_user_id_digest")
        == instance.get("approver_identity_store_user_id_digest")
    )
    if schema_version != "3" and users_equal:
        errors.append("ledger requires distinct immutable Identity Store users")
    if schema_version == "3" and not users_equal:
        errors.append("single-operator ledger must bind one immutable user")
    expected_separation = (
        "SINGLE_OPERATOR_DECLARED_NOT_INDEPENDENT"
        if schema_version == "3"
        else "VERIFIED_DISTINCT_IDENTITYSTORE_USERS"
    )
    if instance.get("identity_separation") != expected_separation:
        errors.append("ledger identity separation must be Identity Store verified")
    identity_binding_fields = (
        "identity_store_arn_digest",
        "identity_center_instance_arn_digest",
        "identity_center_application_arn_digest",
        "classifier_identity_store_user_id_digest",
        "approver_identity_store_user_id_digest",
        "classifier_assignment_sha256",
        "approver_assignment_sha256",
        "classifier_invoker_policy_sha256",
        "approver_invoker_policy_sha256",
    )
    if schema_version in {"2", "3"}:
        identity_binding_fields += (
            "classifier_proof_policy_sha256",
            "approver_proof_policy_sha256",
            "identity_center_application_actor_policy_sha256",
        )
    identity_binding = {
        field: instance.get(field) for field in identity_binding_fields
    }
    if schema_version == "3":
        identity_binding.update(
            {
                "authorization_mode": instance.get("authorization_mode"),
                "two_human_status": instance.get("two_human_status"),
                "independent_approval_present": instance.get(
                    "independent_approval_present"
                ),
            }
        )
    if instance.get("identity_binding_digest") != _gug215_canonical_digest(
        identity_binding
    ):
        errors.append("identity_binding_digest must cover every immutable identity binding")

    ordered_fields = ["classified_at"]
    if state in {
        "APPROVED",
        "EXCEPTION_ACCEPTED",
        "ATTEMPTED",
        "RETIRED_RECONCILED",
    }:
        ordered_fields.append("approved_at")
    if state in {"ATTEMPTED", "RETIRED_RECONCILED"}:
        ordered_fields.append("attempted_at")
    if state == "RETIRED_RECONCILED":
        ordered_fields.append("verified_at")
    ordered = [_gug215_timestamp(instance.get(field)) for field in ordered_fields]
    concrete = [value for value in ordered if value is not None]
    if len(concrete) == len(ordered):
        if concrete != sorted(concrete):
            errors.append("ledger lifecycle timestamps must be monotonic")
    updated = _gug215_timestamp(instance.get("updated_at"))
    if concrete and updated is not None and updated < concrete[-1]:
        errors.append("ledger updated_at must not precede the latest state event")
    ledger_without_digest = {
        key: value for key, value in instance.items() if key != "ledger_digest"
    }
    if instance.get("ledger_digest") != _gug215_canonical_digest(
        ledger_without_digest
    ):
        errors.append("ledger_digest must cover the complete durable record")
    if schema_version in {"2", "3"}:
        proofs = [
            instance.get(field)
            for field in (
                "classifier_identity_proof_sha256",
                "approver_identity_proof_sha256",
                "reconciliation_identity_proof_sha256",
            )
            if instance.get(field) is not None
        ]
        if len(proofs) != len(set(proofs)):
            errors.append("each durable identity proof must be unique")
    if schema_version == "3":
        exception = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_change_set_retirement_single_operator_exception"
            ),
            "issue_id": "GUG-215",
            "environment": "non-production",
            "production": False,
            "authorization_mode": "SINGLE_OPERATOR_NONPROD_EXCEPTION",
            "two_human_status": "NOT_PROVEN",
            "independent_approval_present": False,
            "single_execution": True,
            "deployment_authorized": False,
            "request_selectable": False,
            "allowed_action": "cloudformation:DeleteChangeSet",
            "broker_ledger_actions": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
            "forbidden_actions": [
                "cloudformation:CreateChangeSet",
                "cloudformation:DeleteStack",
                "cloudformation:ExecuteChangeSet",
                "cloudformation:UpdateStack",
            ],
            "aws_effect_principal": "BROKER_EXECUTION_ROLE",
            "max_attempts": 1,
            "authority_account_id_digest": instance.get(
                "authority_account_id_digest"
            ),
            "region": instance.get("region"),
            "stack_name": instance.get("stack_name"),
            "retirement_id": instance.get("retirement_id"),
            "change_set_name_digest": instance.get("change_set_name_digest"),
            "template_sha256": instance.get("template_sha256"),
            "resource_inventory_sha256": instance.get(
                "resource_inventory_sha256"
            ),
            "identity_binding_digest": instance.get("identity_binding_digest"),
            "broker_runtime_version_arn_digest": instance.get(
                "broker_runtime_version_arn_digest"
            ),
            "broker_version_binding_sha256": instance.get(
                "broker_version_binding_sha256"
            ),
            "operator_identity_store_user_id_digest": instance.get(
                "classifier_identity_store_user_id_digest"
            ),
            "owner_authorization_sha256": instance.get(
                "owner_authorization_sha256"
            ),
            "created_at": instance.get("exception_created_at"),
            "not_before": instance.get("exception_not_before"),
            "expires_at": instance.get("exception_expires_at"),
            "reconciliation_after_expiry": True,
            "revocation_required": True,
        }
        if instance.get("single_operator_authorization_sha256") != (
            _gug215_canonical_digest(exception)
        ):
            errors.append(
                "single_operator_authorization_sha256 must bind the exact exception"
            )
    return errors


def _validate_gug216_binding(instance: dict) -> list[str]:
    errors: list[str] = []
    classifier = instance.get("classifier")
    approver = instance.get("approver")
    classifier_user = (
        classifier.get("identity_store_user_id")
        if isinstance(classifier, dict)
        else None
    )
    approver_user = (
        approver.get("identity_store_user_id")
        if isinstance(approver, dict)
        else None
    )
    if (
        isinstance(classifier_user, str)
        and isinstance(approver_user, str)
        and classifier_user.lower() == approver_user.lower()
    ):
        errors.append("identity-enhanced binding requires two distinct UserIds")

    authority_account = instance.get("authority_account_id")
    management_account = instance.get("management_account_id")
    if authority_account == management_account:
        errors.append("authority and management accounts must remain distinct")
    application = instance.get("identity_center_application_arn")
    identity_store = instance.get("identity_store_arn")
    identity_instance = instance.get("identity_center_instance_arn")
    app_match = re.fullmatch(
        r"arn:aws[a-z-]*:sso::([0-9]{12}):application/"
        r"(ssoins-[A-Za-z0-9]{16})/(apl-[A-Za-z0-9]{16})",
        application if isinstance(application, str) else "",
    )
    store_match = re.fullmatch(
        r"arn:aws[a-z-]*:identitystore::([0-9]{12}):identitystore/d-[a-z0-9]{10,}",
        identity_store if isinstance(identity_store, str) else "",
    )
    instance_match = re.fullmatch(
        r"arn:aws[a-z-]*:sso:::instance/(ssoins-[A-Za-z0-9]{16})",
        identity_instance if isinstance(identity_instance, str) else "",
    )
    if app_match and store_match and instance_match:
        if app_match.group(1) != management_account or store_match.group(1) != management_account:
            errors.append("application and identity store must bind the management account")
        if app_match.group(2) != instance_match.group(1):
            errors.append("application and instance identifiers must match")
    for role in (classifier, approver):
        if not isinstance(role, dict):
            continue
        for field in ("source_role_arn", "target_role_arn"):
            role_arn = role.get(field)
            role_match = re.fullmatch(
                r"arn:aws[a-z-]*:iam::([0-9]{12}):role/.+",
                role_arn if isinstance(role_arn, str) else "",
            )
            if role_match and role_match.group(1) != authority_account:
                errors.append("retirement roles must bind the authority account")
    return errors


def _validate_gug216_receipt(instance: dict) -> list[str]:
    without_digest = {
        key: value for key, value in instance.items() if key != "receipt_digest"
    }
    if instance.get("receipt_digest") != _gug215_canonical_digest(without_digest):
        return ["receipt_digest must cover the complete sanitized receipt"]
    return []


def _validate_gug217_binding(instance: dict) -> list[str]:
    errors: list[str] = []
    classifier = instance.get("classifier_user_id")
    approver = instance.get("approver_user_id")
    users_equal = (
        isinstance(classifier, str)
        and isinstance(approver, str)
        and classifier.lower() == approver.lower()
    )
    if instance.get("schema_version") == "1" and users_equal:
        errors.append("identity-context PEP requires two distinct UserIds")
    if instance.get("schema_version") == "2" and not users_equal:
        errors.append("single-operator PEP requires one exact UserId")

    account = instance.get("authority_account_id")
    application = instance.get("identity_center_application_arn")
    identity_store = instance.get("identity_store_arn")
    identity_instance = instance.get("identity_center_instance_arn")
    app_match = re.fullmatch(
        r"arn:(aws(?:-[a-z]+)*):sso::([0-9]{12}):application/"
        r"(ssoins-[A-Za-z0-9]{16})/(apl-[A-Za-z0-9]{16})",
        application if isinstance(application, str) else "",
    )
    store_match = re.fullmatch(
        r"arn:(aws(?:-[a-z]+)*):identitystore::([0-9]{12}):identitystore/"
        r"d-[a-z0-9]{10,}",
        identity_store if isinstance(identity_store, str) else "",
    )
    instance_match = re.fullmatch(
        r"arn:(aws(?:-[a-z]+)*):sso:::instance/(ssoins-[A-Za-z0-9]{16})",
        identity_instance if isinstance(identity_instance, str) else "",
    )
    if app_match and store_match and instance_match:
        if (
            app_match.group(1) != store_match.group(1)
            or app_match.group(1) != instance_match.group(1)
            or app_match.group(2) != store_match.group(2)
            or app_match.group(3) != instance_match.group(2)
        ):
            errors.append("Identity Center application, store and instance must match")
        if app_match.group(2) == account:
            errors.append("authority and Identity Center management accounts must differ")

    for field in (
        "broker_execution_role_arn",
        "classifier_proof_role_arn",
        "approver_proof_role_arn",
    ):
        role = instance.get(field)
        match = re.fullmatch(
            r"arn:aws[a-z-]*:iam::([0-9]{12}):role/.+",
            role if isinstance(role, str) else "",
        )
        if match and match.group(1) != account:
            errors.append("all PEP roles must bind the authority account")

    digest_fields = (
        "authority_account_id",
        "region",
        "identity_center_application_arn",
        "identity_center_instance_arn",
        "identity_store_arn",
        "redirect_uri",
        "broker_execution_role_arn",
        "classifier_user_id",
        "approver_user_id",
        "classifier_proof_role_arn",
        "approver_proof_role_arn",
        "proof_duration_seconds",
        "max_token_lifetime_seconds",
    )
    digest_input = {
        field: (
            instance.get(field).lower()
            if field in {"classifier_user_id", "approver_user_id"}
            and isinstance(instance.get(field), str)
            else instance.get(field)
        )
        for field in digest_fields
    }
    if instance.get("schema_version") == "2":
        digest_input.update(
            {
                "authorization_mode": instance.get("authorization_mode"),
                "single_operator_authorization_sha256": instance.get(
                    "single_operator_authorization_sha256"
                ),
                "two_human_status": instance.get("two_human_status"),
                "independent_approval_present": instance.get(
                    "independent_approval_present"
                ),
            }
        )
    if instance.get("binding_digest") != _gug215_canonical_digest(digest_input):
        errors.append("binding_digest must cover every immutable PEP binding")
    return errors


def _validate_gug217_proof_receipt(instance: dict) -> list[str]:
    errors = _validate_gug216_receipt(instance)
    users_equal = (
        instance.get("expected_user_id_digest")
        == instance.get("peer_user_id_digest")
    )
    if instance.get("schema_version") == "1" and users_equal:
        errors.append("proof receipt requires distinct expected and peer users")
    if instance.get("schema_version") == "2" and not users_equal:
        errors.append("single-operator proof must bind the same expected and peer user")
    if instance.get("proof_role_arn_digest") == instance.get("proof_session_arn_digest"):
        errors.append("proof role and proof session digests must be distinct")
    return errors


def _validate_gug215_single_operator_exception(instance: dict) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value for key, value in instance.items() if key != "authorization_digest"
    }
    if instance.get("authorization_digest") != _gug215_canonical_digest(
        without_digest
    ):
        errors.append("authorization_digest must cover the complete exception")
    created = _gug215_timestamp(instance.get("created_at"))
    not_before = _gug215_timestamp(instance.get("not_before"))
    expires = _gug215_timestamp(instance.get("expires_at"))
    if all(value is not None for value in (created, not_before, expires)):
        assert created is not None and not_before is not None and expires is not None
        if (
            not_before < created
            or not_before - created > timedelta(hours=1)
            or expires <= not_before
            or expires - not_before > timedelta(minutes=15)
        ):
            errors.append("single-operator exception window must be closed and short")
    return errors


GUG218_FORBIDDEN_AUTHORITY_CLASSES = frozenset(
    {
        "PUBLIC_PRINCIPAL",
        "WILDCARD_ACTION",
        "WILDCARD_RESOURCE",
        "FUNCTION_URL_NONE",
        "UNQUALIFIED_FUNCTION",
        "LATEST_VERSION",
        "NUMERIC_VERSION",
        "ALTERNATE_ALIAS",
        "CROSS_ACCOUNT_PRINCIPAL",
        "SERVICE_PRINCIPAL",
        "FEDERATED_PRINCIPAL",
        "ALTERNATE_TRUST",
        "UNSUPPORTED_POLICY_SEMANTICS",
        "EVENT_SOURCE_MAPPING",
        "AUTHORITY_MUTATION",
    }
)
GUG218_COVERAGE_SURFACES = frozenset(
    {
        "region_discovery",
        "lambda_functions",
        "lambda_aliases",
        "lambda_versions",
        "lambda_function_urls",
        "lambda_resource_policies",
        "lambda_event_source_mappings",
        "iam_account_authorization",
    }
)
GUG218_LAMBDA_CODE_SHA256_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _gug218_expected_authority_edges(
    *, single_operator: bool = False
) -> frozenset[tuple[str, ...]]:
    expected: set[tuple[str, ...]] = set()
    aliases = (
        (
            "single_operator_classifier",
            "EXACT_SINGLE_CLASSIFY_ALIAS",
        ),
        (
            "single_operator_retirement",
            "EXACT_SINGLE_RETIRE_ALIAS",
        ),
        (
            "single_operator_retirement",
            "EXACT_SINGLE_RECONCILE_ALIAS",
        ),
    ) if single_operator else (
        ("classifier", "EXACT_CLASSIFY_ALIAS"),
        ("independent_approver", "EXACT_RETIRE_ALIAS"),
        ("independent_approver", "EXACT_RECONCILE_ALIAS"),
    )
    actions = (
        (
            "lambda:InvokeFunctionUrl",
            "FUNCTION_URL_AUTH_TYPE_AWS_IAM",
        ),
        (
            "lambda:InvokeFunction",
            "INVOKED_VIA_FUNCTION_URL_TRUE",
        ),
    )
    for source_type in (
        "LAMBDA_RESOURCE_POLICY",
        "IAM_ROLE_INLINE_POLICY",
    ):
        for duty, target_scope in aliases:
            for action, condition_class in actions:
                expected.add(
                    (
                        "INVOCATION",
                        source_type,
                        duty,
                        target_scope,
                        action,
                        condition_class,
                    )
                )
    expected.update(
        {
            (
                "TRUST",
                "IAM_ROLE_TRUST_POLICY",
                (
                    "single_operator_classifier"
                    if single_operator
                    else "classifier"
                ),
                "CLASSIFIER_INVOKER_ROLE",
                "sts:AssumeRole",
                "EXACT_PERMISSION_SET_TRUST",
            ),
            (
                "TRUST",
                "IAM_ROLE_TRUST_POLICY",
                (
                    "single_operator_retirement"
                    if single_operator
                    else "independent_approver"
                ),
                "APPROVER_INVOKER_ROLE",
                "sts:AssumeRole",
                "EXACT_PERMISSION_SET_TRUST",
            ),
        }
    )
    return frozenset(expected)


GUG218_EXPECTED_AUTHORITY_EDGES = _gug218_expected_authority_edges()
GUG218_SINGLE_OPERATOR_EXPECTED_AUTHORITY_EDGES = (
    _gug218_expected_authority_edges(single_operator=True)
)


def _gug218_allowlist_edge_tuple(edge: object) -> tuple[str, ...] | None:
    if not isinstance(edge, dict):
        return None
    values = tuple(
        edge.get(field)
        for field in (
            "authority_class",
            "source_type",
            "duty",
            "target_scope",
            "action",
            "condition_class",
        )
    )
    return values if all(isinstance(value, str) for value in values) else None


def _gug218_inventory_edge_tuple(edge: object) -> tuple[str, ...] | None:
    if not isinstance(edge, dict):
        return None
    action = {
        "INVOKE_FUNCTION_URL": "lambda:InvokeFunctionUrl",
        "INVOKE_FUNCTION": "lambda:InvokeFunction",
        "ASSUME_ROLE": "sts:AssumeRole",
    }.get(edge.get("action_class"))
    values = (
        edge.get("authority_class"),
        edge.get("source_type"),
        edge.get("duty"),
        edge.get("target_scope"),
        action,
        edge.get("condition_class"),
    )
    return values if all(isinstance(value, str) for value in values) else None


def _gug218_expected_principal_kind(edge: dict) -> str | None:
    duty = edge.get("duty")
    if duty in {"classifier", "single_operator_classifier"}:
        suffix = "CLASSIFIER"
    elif duty in {"independent_approver", "single_operator_retirement"}:
        suffix = "APPROVER"
    else:
        return None
    if edge.get("authority_class") == "TRUST":
        return f"EXACT_{suffix}_PERMISSION_SET"
    if edge.get("authority_class") == "INVOCATION":
        return f"EXACT_{suffix}_ROLE"
    return None


def _gug218_allowlist_edge_binding_tuple(
    edge: object,
) -> tuple[str, ...] | None:
    if not isinstance(edge, dict):
        return None
    principal_kind = _gug218_expected_principal_kind(edge)
    shape = _gug218_allowlist_edge_tuple(edge)
    if shape is None:
        return None
    values = (
        *shape,
        principal_kind,
        edge.get("principal_digest"),
        edge.get("resource_digest"),
        edge.get("source_document_digest"),
    )
    return values if len(values) == 10 and all(
        isinstance(value, str) for value in values
    ) else None


def _gug218_inventory_edge_binding_tuple(
    edge: object,
) -> tuple[str, ...] | None:
    if not isinstance(edge, dict):
        return None
    shape = _gug218_inventory_edge_tuple(edge)
    if shape is None:
        return None
    values = (
        *shape,
        edge.get("principal_kind"),
        edge.get("principal_digest"),
        edge.get("resource_digest"),
        edge.get("source_document_digest"),
    )
    return values if all(isinstance(value, str) for value in values) else None


def _gug218_validate_evaluation_time(
    *,
    evaluation_at: datetime | None,
    completed_at: datetime | None,
    expires_at: datetime | None,
    label: str,
) -> list[str]:
    if (
        not isinstance(evaluation_at, datetime)
        or evaluation_at.tzinfo is None
        or evaluation_at.utcoffset() is None
    ):
        return [f"{label} requires a trusted timezone-aware evaluation_at"]
    if completed_at is None or expires_at is None:
        return []
    trusted_now = evaluation_at.astimezone(UTC)
    if completed_at > trusted_now:
        return [f"{label} cannot be accepted before collection completes"]
    if trusted_now >= expires_at:
        return [f"{label} evidence is expired at evaluation time"]
    return []


def _validate_gug218_allowlist(instance: dict) -> list[str]:
    errors: list[str] = []
    single_operator = instance.get("schema_version") == "2"
    expected_authority_edges = (
        GUG218_SINGLE_OPERATOR_EXPECTED_AUTHORITY_EDGES
        if single_operator
        else GUG218_EXPECTED_AUTHORITY_EDGES
    )
    classifier_duty = (
        "single_operator_classifier" if single_operator else "classifier"
    )
    retirement_duty = (
        "single_operator_retirement"
        if single_operator
        else "independent_approver"
    )
    if single_operator:
        if (
            instance.get("authorization_mode")
            != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
            or instance.get("two_human_status") != "NOT_PROVEN"
            or instance.get("independent_approval_present") is not False
            or instance.get("active_aliases")
            != ["single-classify", "single-reconcile", "single-retire"]
        ):
            errors.append(
                "v2 allowlist must bind the exact non-independent single-operator mode"
            )
    broker_artifact_code_sha256 = instance.get("broker_artifact_code_sha256")
    if (
        not isinstance(broker_artifact_code_sha256, str)
        or GUG218_LAMBDA_CODE_SHA256_RE.fullmatch(broker_artifact_code_sha256)
        is None
    ):
        errors.append(
            "broker_artifact_code_sha256 must be the exact Lambda CodeSha256 base64 digest"
        )

    edges = instance.get("expected_authority_edges")
    edge_list = edges if isinstance(edges, list) else []
    edge_tuples = {
        value
        for edge in edge_list
        if (value := _gug218_allowlist_edge_tuple(edge)) is not None
    }
    if len(edge_list) != 14 or edge_tuples != expected_authority_edges:
        errors.append("allowlist must contain the exact fourteen reviewed authority edges")

    forbidden = instance.get("forbidden_authority_classes")
    if not isinstance(forbidden, list) or set(forbidden) != GUG218_FORBIDDEN_AUTHORITY_CLASSES:
        errors.append("allowlist must enumerate every fail-closed authority class")

    classifier_principals = {
        edge.get("principal_digest")
        for edge in edge_list
        if isinstance(edge, dict)
        and edge.get("authority_class") == "INVOCATION"
        and edge.get("duty") == classifier_duty
    }
    approver_principals = {
        edge.get("principal_digest")
        for edge in edge_list
        if isinstance(edge, dict)
        and edge.get("authority_class") == "INVOCATION"
        and edge.get("duty") == retirement_duty
    }
    if len(classifier_principals) != 1 or len(approver_principals) != 1:
        errors.append("each duty must bind exactly one invoker role digest")
    elif classifier_principals == approver_principals:
        errors.append("classifier and approver invoker roles must remain distinct")

    collector_principal = instance.get("collector_role_principal_digest")
    if collector_principal in classifier_principals | approver_principals:
        errors.append("collector role must remain distinct from both invoker duties")

    trust_targets = {
        edge.get("duty"): edge.get("resource_digest")
        for edge in edge_list
        if isinstance(edge, dict) and edge.get("authority_class") == "TRUST"
    }
    classifier_principal = next(iter(classifier_principals), None)
    approver_principal = next(iter(approver_principals), None)
    if trust_targets.get(classifier_duty) != classifier_principal:
        errors.append("classifier trust must target the reviewed invoker role")
    if trust_targets.get(retirement_duty) != approver_principal:
        errors.append("approver trust must target the reviewed invoker role")

    without_digest = {
        key: value for key, value in instance.items() if key != "allowlist_digest"
    }
    if instance.get("allowlist_digest") != _gug215_canonical_digest(without_digest):
        errors.append("allowlist_digest must cover the complete reviewed contract")
    return errors


def _validate_gug219_collector_contract(instance: dict) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value
        for key, value in instance.items()
        if key != "collector_contract_digest"
    }
    if instance.get("collector_contract_digest") != _gug215_canonical_digest(
        without_digest
    ):
        errors.append("collector_contract_digest must cover the complete collector contract")
    return errors


def _validate_gug219_release(
    instance: dict,
    *,
    expected_collector_contract: dict | None = None,
    expected_allowlist: dict | None = None,
) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value for key, value in instance.items() if key != "release_digest"
    }
    if instance.get("release_digest") != _gug215_canonical_digest(without_digest):
        errors.append("release_digest must cover the complete materialized release")
    if isinstance(expected_collector_contract, dict) and instance.get(
        "collector_contract_digest"
    ) != expected_collector_contract.get("collector_contract_digest"):
        errors.append("release must bind the reviewed collector contract digest")
    created = _gug215_timestamp(instance.get("created_at"))
    expires = _gug215_timestamp(instance.get("expires_at"))
    if (
        created is not None
        and expires is not None
        and (not created < expires or expires - created > timedelta(minutes=5))
    ):
        errors.append("release validity window must be positive and at most five minutes")
    if instance.get("schema_version") == "2":
        if not isinstance(expected_allowlist, dict):
            errors.append("v2 release requires the reviewed v2 allowlist context")
        else:
            for field in (
                "authorization_mode",
                "two_human_status",
                "independent_approval_present",
                "single_operator_exception_digest",
                "owner_authorization_sha256",
                "active_aliases",
                "allowlist_digest",
            ):
                if instance.get(field) != expected_allowlist.get(field):
                    errors.append(f"v2 release {field} must match the reviewed allowlist")
    return errors


def _validate_gug220_provisioning_intent(instance: dict) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value for key, value in instance.items() if key != "intent_digest"
    }
    if instance.get("intent_digest") != _gug215_canonical_digest(without_digest):
        errors.append("intent_digest must cover the complete provisioning intent")
    if any(
        instance.get(field) is not False
        for field in (
            "production",
            "independent_review_present",
            "approval_authorized",
            "protected_retirement_authorized",
            "lambda_invocation_authorized",
            "customer_deployment_authorized",
            "production_authorized",
        )
    ):
        errors.append("provisioning intent must not authorize runtime or production effects")
    created = _gug215_timestamp(instance.get("created_at"))
    expires = _gug215_timestamp(instance.get("expires_at"))
    if (
        created is not None
        and expires is not None
        and (not created < expires or expires - created > timedelta(minutes=15))
    ):
        errors.append("provisioning intent validity window must be positive and at most fifteen minutes")
    return errors


def _validate_gug220_execution_ledger(instance: dict) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value for key, value in instance.items() if key != "ledger_digest"
    }
    if instance.get("ledger_digest") != _gug215_canonical_digest(without_digest):
        errors.append("ledger_digest must cover the complete execution ledger")
    if (
        instance.get("production") is not False
        or instance.get("mutation_attempt_limit") != 1
        or instance.get("mutation_retry_authorized") is not False
    ):
        errors.append("execution ledger must consume exactly one non-production attempt")
    return errors


def _validate_gug220_provisioning_receipt(instance: dict) -> list[str]:
    errors: list[str] = []
    without_digest = {
        key: value for key, value in instance.items() if key != "receipt_digest"
    }
    if instance.get("receipt_digest") != _gug215_canonical_digest(without_digest):
        errors.append("receipt_digest must cover the complete provisioning receipt")
    if any(
        instance.get(field) is not False
        for field in (
            "production",
            "mutation_retry_attempted",
            "independent_review_present",
            "approval_authorized",
            "protected_retirement_authorized",
            "lambda_invocation_authorized",
            "customer_deployment_authorized",
            "production_authorized",
        )
    ):
        errors.append("provisioning receipt must not overclaim authority")
    if instance.get("status") == "READBACK_VERIFIED":
        digests = (
            instance.get("permission_set_arn_digest"),
            instance.get("collector_role_iam_arn_digest"),
        )
        if not all(
            instance.get(field) is True
            for field in (
                "account_assignment_verified",
                "permission_set_provisioning_verified",
                "collector_role_verified",
            )
        ) or any(
            not isinstance(value, str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None
            for value in digests
        ):
            errors.append(
                "verified receipt must bind permission set, collector role, assignment, provisioning, and role readback"
            )
    elif any(
        instance.get(field) is not False
        for field in (
            "account_assignment_verified",
            "permission_set_provisioning_verified",
            "collector_role_verified",
            "binding_written",
        )
    ) or instance.get("collector_role_iam_arn_digest") is not None:
        errors.append("non-verified receipt must not claim verified authority")
    status = instance.get("status")
    if status in {"PLAN_ONLY", "BLOCKED_DRIFT"} and (
        instance.get("aws_mutation_attempted") is not False
        or instance.get("ambiguous_response") is not False
    ):
        errors.append("plan or blocked receipt must not claim a mutation")
    if status == "UNCERTAIN_RECONCILE_ONLY" and (
        instance.get("aws_mutation_attempted") is not True
        or instance.get("ambiguous_response") is not True
    ):
        errors.append("uncertain receipt must prove one ambiguous mutation attempt")
    if status == "READBACK_INCOMPLETE" and (
        instance.get("aws_mutation_attempted") is not False
        or instance.get("ambiguous_response") is not True
    ):
        errors.append("incomplete readback must not claim a mutation attempt")
    if (
        instance.get("ambiguous_response") is True
        and instance.get("status")
        not in {"READBACK_INCOMPLETE", "UNCERTAIN_RECONCILE_ONLY"}
    ):
        errors.append("ambiguous response must require read-only reconciliation")
    return errors


GUG221_REPAIR_MUTATIONS = (
    "sso:PutInlinePolicyToPermissionSet",
    "sso:CreateAccountAssignment",
    "sso:ProvisionPermissionSet",
)


def _validate_gug221_broker_topology(instance: dict) -> list[str]:
    """Ensure the human has only exact private Lambda invocation authority."""
    errors: list[str] = []
    human = instance.get("human_permission_set")
    ledger = instance.get("ledger")
    if not isinstance(human, dict) or human.get("allowed_actions") != [
        "lambda:InvokeFunction"
    ]:
        errors.append("GUG-221 human authority must be exact Lambda invocation only")
    if instance.get("human_raw_api_authorized") is not False:
        errors.append("GUG-221 human authority must deny raw control-plane APIs")
    if instance.get("event") != {}:
        errors.append("GUG-221 broker event must be exactly empty")
    transport = instance.get("transport_guard")
    if not isinstance(transport, dict) or transport != {
        "client_context_custom": {
            "scanalyze_transport": "REQUEST_RESPONSE",
            "scanalyze_work_package": "GUG-221",
        },
        "maximum_retry_attempts": 0,
        "maximum_event_age_seconds": 60,
        "asynchronous_effects_authorized": False,
    }:
        errors.append("GUG-221 requires the exact synchronous-only transport guard")
    if instance.get("authorized_mutations") != list(GUG221_REPAIR_MUTATIONS):
        errors.append("GUG-221 server mutation sequence must remain exact")
    if not isinstance(ledger, dict) or (
        ledger.get("provider_immutable") is not True
        or ledger.get("claim_condition") != "attribute_not_exists(repair_id)"
    ):
        errors.append("GUG-221 requires the provider-backed one-shot CAS ledger")
    return errors


def _validate_gug221_broker_intent(instance: dict) -> list[str]:
    """Validate mode/alias/effect bindings and the bounded repair window."""
    errors: list[str] = []
    mode = instance.get("mode")
    expected_alias = {
        "plan": "plan-v1",
        "repair": "repair-v1",
        "reconcile": "reconcile-v1",
    }.get(mode)
    if expected_alias is None or instance.get("function_qualifier") != expected_alias:
        errors.append("GUG-221 mode must derive from the exact published alias")
    mutations = instance.get("authorized_mutations")
    if mode == "repair":
        if mutations != list(GUG221_REPAIR_MUTATIONS):
            errors.append("repair intent must preserve the exact mutation sequence")
    elif mutations != []:
        errors.append("read-only broker modes must not authorize mutations")
    collector_arn = instance.get("permission_set_arn")
    invoker_arn = instance.get("repair_invoker_permission_set_arn")
    if collector_arn == invoker_arn:
        errors.append("collector and repair invoker permission sets must differ")
    elif isinstance(collector_arn, str) and isinstance(invoker_arn, str):
        collector_instance = collector_arn.rsplit("/", 2)[-2]
        invoker_instance = invoker_arn.rsplit("/", 2)[-2]
        if collector_instance != invoker_instance:
            errors.append("collector and repair invoker must share one Identity Center instance")
    invoker_tags = instance.get("expected_repair_invoker_tags")
    if not isinstance(invoker_tags, dict) or invoker_tags.get("source_commit") != instance.get(
        "source_commit"
    ):
        errors.append("repair invoker tags must bind the exact source commit")
    not_before = _gug215_timestamp(instance.get("not_before"))
    not_after = _gug215_timestamp(instance.get("not_after"))
    if (
        not_before is not None
        and not_after is not None
        and (not not_before < not_after or not_after - not_before > timedelta(minutes=15))
    ):
        errors.append("GUG-221 intent window must be positive and at most fifteen minutes")
    return errors


def _validate_gug221_broker_ledger(instance: dict) -> list[str]:
    """Validate the durable CAS barrier without inferring provider effects."""
    errors: list[str] = []
    if instance.get("ledger_digest") != _gug221_canonical_digest(
        _gug221_initial_ledger_binding(instance)
    ):
        errors.append("GUG-221 ledger_digest must cover the immutable Plan binding")
    status = instance.get("status")
    stage = instance.get("stage")
    attempted = instance.get("effects_attempted")
    completed = instance.get("effects_completed")
    if (
        not isinstance(attempted, int)
        or isinstance(attempted, bool)
        or not isinstance(completed, int)
        or isinstance(completed, bool)
        or completed > attempted
    ):
        errors.append("GUG-221 ledger effect counters are invalid")
    if (
        instance.get("provider_immutable") is not True
        or instance.get("claim_condition") != "attribute_not_exists(repair_id)"
        or instance.get("mutation_retry_attempted") is not False
        or instance.get("production_authorized") is not False
    ):
        errors.append("GUG-221 ledger must remain provider-backed, one-shot, and non-production")
    exact_progress = {
        "PLAN_VERIFIED": ("PLAN_STATE_VERIFIED", 0, 0),
        "CLAIMED": ("BEFORE_FIRST_EFFECT", 0, 0),
        "ATTEMPTING_1": ("BEFORE_PUT_INLINE_POLICY", 0, 0),
        "COMPLETED_1": ("AFTER_PUT_INLINE_POLICY", 1, 1),
        "ATTEMPTING_2": ("BEFORE_CREATE_ACCOUNT_ASSIGNMENT", 1, 1),
        "COMPLETED_2": ("AFTER_CREATE_ACCOUNT_ASSIGNMENT", 2, 2),
        "ATTEMPTING_3": ("BEFORE_PROVISION_PERMISSION_SET", 2, 2),
        "COMPLETED_3": ("AFTER_PROVISION_PERMISSION_SET", 3, 3),
        "REPAIR_VERIFIED": ("FINAL_READBACK_VERIFIED", 3, 3),
    }
    uncertain_progress = {
        "UNCERTAIN_PUT_INLINE_POLICY": (1, 0),
        "UNCERTAIN_PUT_INLINE_POLICY_LEDGER_COMMIT": (1, 1),
        "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT": (2, 1),
        "UNCERTAIN_CREATE_ACCOUNT_ASSIGNMENT_LEDGER_COMMIT": (2, 2),
        "UNCERTAIN_PROVISION_PERMISSION_SET": (3, 2),
        "UNCERTAIN_PROVISION_PERMISSION_SET_LEDGER_COMMIT": (3, 3),
        "UNCERTAIN_FINAL_READBACK": (3, 3),
    }
    if status in exact_progress:
        if (stage, attempted, completed) != exact_progress[status]:
            errors.append("GUG-221 ledger status, stage, and counters are inconsistent")
    elif status == "UNCERTAIN_RECONCILE_ONLY":
        if stage not in uncertain_progress or (attempted, completed) != uncertain_progress.get(stage):
            errors.append("GUG-221 uncertain ledger progress is inconsistent")
    else:
        errors.append("GUG-221 ledger status is unsupported")

    claimed_at = _gug215_timestamp(instance.get("claimed_at"))
    updated_at = _gug215_timestamp(instance.get("updated_at"))
    state_digest = instance.get("state_digest")
    if status == "PLAN_VERIFIED":
        if "claimed_at" in instance or "updated_at" in instance:
            errors.append("GUG-221 plan ledger must precede the mutation claim")
        if state_digest != instance.get("planned_state_digest"):
            errors.append("GUG-221 plan ledger state must match the reviewed state")
    elif (
        claimed_at is None
        or updated_at is None
        or not isinstance(state_digest, str)
    ):
        errors.append("GUG-221 advanced ledger must contain transition evidence")
    elif updated_at < claimed_at:
        errors.append("GUG-221 ledger timestamps are out of order")
    return errors


def _validate_gug221_broker_receipt(instance: dict) -> list[str]:
    """Reject every public outcome outside the exact runtime state matrix."""
    errors: list[str] = []
    mode = instance.get("mode")
    status = instance.get("status")
    qualifier = instance.get("function_qualifier")
    attempted = instance.get("effects_attempted")
    completed = instance.get("effects_completed")
    ledger = instance.get("ledger_digest")
    attribution = instance.get("mutation_attribution")
    next_action = instance.get("required_next_action")
    if (
        type(attempted) is not int
        or type(completed) is not int
        or attempted not in range(4)
        or completed not in range(4)
        or completed > attempted
    ):
        errors.append("GUG-221 receipt cannot complete more effects than attempted")
    mode_qualifiers = {
        "plan": "plan-v1",
        "repair": "repair-v1",
        "reconcile": "reconcile-v1",
    }
    if mode_qualifiers.get(mode) != qualifier:
        errors.append("GUG-221 receipt mode must match the exact published alias")

    if status == "PLAN_VERIFIED":
        if (
            mode != "plan"
            or qualifier != "plan-v1"
            or not isinstance(ledger, str)
            or (attempted, completed) != (0, 0)
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
            or next_action != "INVOKE_REPAIR_ALIAS"
        ):
            errors.append("GUG-221 plan receipt must prove its durable ledger gate")
    elif status == "REPAIR_VERIFIED":
        if (
            mode != "repair"
            or qualifier != "repair-v1"
            or not isinstance(ledger, str)
            or (attempted, completed) != (3, 3)
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
            or next_action != "NONE"
        ):
            errors.append("GUG-221 verified repair must be proven by the durable ledger")
    elif status == "RECONCILE_VERIFIED":
        if (
            mode != "reconcile"
            or qualifier != "reconcile-v1"
            or not isinstance(ledger, str)
            or (attempted, completed) not in {(2, 2), (3, 2), (3, 3)}
            or attribution != "PROVEN_BY_DURABLE_LEDGER"
            or next_action != "NONE"
        ):
            errors.append("GUG-221 verified reconciliation must prove the final durable state")
    elif status == "BLOCKED":
        if next_action != "REVIEW_BLOCKER":
            errors.append("GUG-221 blocked receipt must require blocker review")
        if ledger is None:
            if (mode, qualifier, attempted, completed, attribution) != (
                "reconcile", "reconcile-v1", 0, 0, "UNPROVEN"
            ):
                errors.append("GUG-221 unbound blocker must not claim durable progress")
        else:
            proven_progress = {(1, 1), (2, 2)}
            if mode != "repair" or qualifier != "repair-v1" or (
                (attempted, completed) == (0, 0) and attribution != "UNPROVEN"
            ) or (
                (attempted, completed) in proven_progress
                and attribution != "PROVEN_BY_DURABLE_LEDGER"
            ) or (attempted, completed) not in ({(0, 0)} | proven_progress):
                errors.append("GUG-221 ledger-bound blocker has impossible progress")
    elif status == "UNCERTAIN_RECONCILE_ONLY":
        if next_action != "INVOKE_RECONCILE_ALIAS":
            errors.append("GUG-221 uncertainty must require the read-only reconcile alias")
        if ledger is None:
            if (mode, qualifier, attempted, completed, attribution) != (
                "repair", "repair-v1", 0, 0, "UNPROVEN"
            ):
                errors.append("GUG-221 invisible claim uncertainty must remain unproven")
        else:
            uncertain_progress = {(1, 0), (1, 1), (2, 1), (2, 2), (3, 2), (3, 3)}
            if (
                mode not in {"repair", "reconcile"}
                or qualifier != mode_qualifiers.get(mode)
                or (attempted, completed) not in uncertain_progress
                or attribution != "PROVEN_BY_DURABLE_LEDGER"
            ):
                errors.append("GUG-221 ledger-bound uncertainty has impossible progress")
    else:
        errors.append("GUG-221 receipt status is unsupported")
    if instance.get("production_status") != "NO-GO":
        errors.append("GUG-221 receipt must preserve Production NO-GO")
    return errors


def _validate_gug218_inventory(
    instance: dict,
    *,
    expected_allowlist: dict | None = None,
    evaluation_at: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    single_operator = instance.get("schema_version") == "2"
    expected_authority_edges = (
        GUG218_SINGLE_OPERATOR_EXPECTED_AUTHORITY_EDGES
        if single_operator
        else GUG218_EXPECTED_AUTHORITY_EDGES
    )
    if single_operator and (
        instance.get("authorization_mode")
        != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
        or instance.get("two_human_status") != "NOT_PROVEN"
        or instance.get("independent_approval_present") is not False
        or instance.get("active_aliases")
        != ["single-classify", "single-reconcile", "single-retire"]
    ):
        errors.append(
            "v2 inventory must bind the exact non-independent single-operator mode"
        )
    coverage = instance.get("coverage")
    coverage_map = coverage if isinstance(coverage, dict) else {}
    if set(coverage_map) != GUG218_COVERAGE_SURFACES:
        errors.append("inventory must cover every account-wide read surface")
    coverage_statuses = {
        value.get("status")
        for value in coverage_map.values()
        if isinstance(value, dict)
    }
    coverage_complete = coverage_statuses == {"COMPLETE"}

    edges = instance.get("authority_edges")
    edge_list = edges if isinstance(edges, list) else []
    expected_edges = [
        edge for edge in edge_list if isinstance(edge, dict) and edge.get("verdict") == "EXPECTED_EXACT"
    ]
    prohibited_edges = [
        edge for edge in edge_list if isinstance(edge, dict) and edge.get("verdict") == "PROHIBITED"
    ]
    unknown_edges = [
        edge for edge in edge_list if isinstance(edge, dict) and edge.get("verdict") == "UNKNOWN"
    ]
    mutating_edges = [
        edge
        for edge in edge_list
        if isinstance(edge, dict) and edge.get("authority_class") == "AUTHORITY_MUTATION"
    ]
    count_bindings = (
        ("observed_edge_count", len(edge_list)),
        ("expected_edge_count", len(expected_edges)),
        ("prohibited_edge_count", len(prohibited_edges)),
        ("unknown_edge_count", len(unknown_edges)),
        ("mutating_authority_count", len(mutating_edges)),
    )
    for field, expected in count_bindings:
        if instance.get(field) != expected:
            errors.append(f"{field} must match the sanitized authority edge inventory")

    source_started = _gug215_timestamp(instance.get("source_snapshot_started_at"))
    source_completed = _gug215_timestamp(
        instance.get("source_snapshot_completed_at")
    )
    started = _gug215_timestamp(instance.get("scan_started_at"))
    completed = _gug215_timestamp(instance.get("scan_completed_at"))
    expires = _gug215_timestamp(instance.get("expires_at"))
    if (
        source_started is None
        or source_completed is None
        or started is None
        or completed is None
        or expires is None
    ):
        errors.append("inventory timestamps must be valid UTC instants")
    elif not (source_started <= source_completed <= started <= completed < expires):
        errors.append("inventory timestamps must be monotonic and unexpired at completion")
    elif started - source_completed > timedelta(minutes=5):
        errors.append("authenticated source snapshot must not be older than five minutes")
    elif expires - completed > timedelta(minutes=5):
        errors.append("inventory evidence lifetime must not exceed five minutes")

    enabled_regions = instance.get("enabled_region_count")
    scanned_regions = instance.get("scanned_region_count")
    status = instance.get("status")
    evidence_source_mode = instance.get("evidence_source_mode")
    unsupported_policy_semantics_detected = instance.get(
        "unsupported_policy_semantics_detected"
    )
    structural_drift_detected = instance.get("structural_drift_detected")
    expected_tuples = {
        value
        for edge in expected_edges
        if (value := _gug218_inventory_edge_tuple(edge)) is not None
    }
    expected_bindings: set[tuple[str, ...]] = set()
    observed_bindings = {
        value
        for edge in expected_edges
        if (value := _gug218_inventory_edge_binding_tuple(edge)) is not None
    }
    allowlist_context_valid = (
        isinstance(expected_allowlist, dict)
        and expected_allowlist.get("schema_version")
        == instance.get("schema_version")
    )
    if allowlist_context_valid:
        allowlist_edges = expected_allowlist.get("expected_authority_edges")
        if isinstance(allowlist_edges, list):
            expected_bindings = {
                value
                for edge in allowlist_edges
                if (value := _gug218_allowlist_edge_binding_tuple(edge)) is not None
            }
        common_bindings = (
            ("allowlist_digest", "allowlist_digest"),
            ("authority_account_id_digest", "authority_account_id_digest"),
            ("target_region", "target_region"),
            ("source_template_sha256", "source_template_sha256"),
            ("collector_principal_digest", "collector_role_principal_digest"),
        )
        for inventory_field, allowlist_field in common_bindings:
            if instance.get(inventory_field) != expected_allowlist.get(allowlist_field):
                errors.append(
                    f"{inventory_field} must match the reviewed allowlist"
                )
        if single_operator:
            for field in (
                "authorization_mode",
                "two_human_status",
                "independent_approval_present",
                "single_operator_exception_digest",
                "owner_authorization_sha256",
                "active_aliases",
            ):
                if instance.get(field) != expected_allowlist.get(field):
                    errors.append(f"{field} must match the reviewed allowlist")
    authority_exact = (
        allowlist_context_valid
        and len(expected_edges) == 14
        and expected_tuples == expected_authority_edges
        and len(expected_bindings) == 14
        and observed_bindings == expected_bindings
        and not prohibited_edges
        and not unknown_edges
        and not mutating_edges
    )
    regions_complete = (
        isinstance(enabled_regions, int)
        and enabled_regions > 0
        and scanned_regions == enabled_regions
    )
    if status == "REVIEW_SAFE_REPORT_ONLY":
        if not allowlist_context_valid:
            errors.append(
                "report-only safe status requires the reviewed allowlist context"
            )
        errors.extend(
            _gug218_validate_evaluation_time(
                evaluation_at=evaluation_at,
                completed_at=completed,
                expires_at=expires,
                label="report-only safe inventory",
            )
        )
        if evidence_source_mode != "AWS_READ_ONLY":
            errors.append("report-only safe status requires authenticated AWS read evidence")
        if not coverage_complete:
            errors.append("report-only safe status requires complete read coverage")
        if not regions_complete:
            errors.append("report-only safe status requires every enabled region")
        if not authority_exact:
            errors.append("report-only safe status requires the exact fourteen authority edges")
        if unsupported_policy_semantics_detected is not False:
            errors.append("report-only safe status rejects unsupported policy semantics")
        if structural_drift_detected is not False:
            errors.append("report-only safe status rejects structural authority drift")
    elif status == "FOREIGN_AUTHORITY_PRESENT":
        if not prohibited_edges:
            errors.append("foreign authority status requires a prohibited edge")
    elif status == "INVENTORY_INCOMPLETE":
        if coverage_complete and regions_complete:
            errors.append("incomplete status requires incomplete coverage or region inventory")
    elif status == "POLICY_SEMANTICS_UNSUPPORTED":
        if (
            unsupported_policy_semantics_detected is not True
            and not unknown_edges
            and "AMBIGUOUS" not in coverage_statuses
        ):
            errors.append(
                "unsupported policy status requires a detector flag, unknown edge or ambiguous read"
            )
    elif status == "DRIFT_DETECTED":
        if structural_drift_detected is not True:
            errors.append("drift status requires explicit structural authority drift")
    elif status == "OFFLINE_UNVERIFIED":
        if evidence_source_mode != "OFFLINE_UNVERIFIED":
            errors.append("offline status requires explicitly unverified source evidence")

    if (
        evidence_source_mode == "OFFLINE_UNVERIFIED"
        and status != "OFFLINE_UNVERIFIED"
    ):
        errors.append("offline evidence can never produce an AWS inventory decision")

    without_digest = {
        key: value for key, value in instance.items() if key != "inventory_digest"
    }
    if instance.get("inventory_digest") != _gug215_canonical_digest(without_digest):
        errors.append("inventory_digest must cover the complete sanitized snapshot")
    return errors


def _validate_gug218_guard_receipt(
    instance: dict,
    *,
    expected_allowlist: dict | None = None,
    expected_inventory: dict | None = None,
    evaluation_at: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    single_operator = instance.get("schema_version") == "2"
    if single_operator and (
        instance.get("authorization_mode")
        != "SINGLE_OPERATOR_NONPROD_EXCEPTION"
        or instance.get("two_human_status") != "NOT_PROVEN"
        or instance.get("independent_approval_present") is not False
        or instance.get("active_aliases")
        != ["single-classify", "single-reconcile", "single-retire"]
    ):
        errors.append(
            "v2 receipt must bind the exact non-independent single-operator mode"
        )
    source_started = _gug215_timestamp(instance.get("source_snapshot_started_at"))
    source_completed = _gug215_timestamp(
        instance.get("source_snapshot_completed_at")
    )
    decision = _gug215_timestamp(instance.get("decision_at"))
    expires = _gug215_timestamp(instance.get("expires_at"))
    if (
        source_started is None
        or source_completed is None
        or decision is None
        or expires is None
    ):
        errors.append("guard receipt timestamps must be valid UTC instants")
    elif not (source_started <= source_completed <= decision < expires):
        errors.append("guard receipt must expire after its decision")
    elif decision - source_completed > timedelta(minutes=5):
        errors.append("guard receipt cannot rely on stale source evidence")
    elif expires - decision > timedelta(minutes=5):
        errors.append("guard receipt lifetime must not exceed five minutes")

    evidence_source_mode = instance.get("evidence_source_mode")
    if instance.get("status") == "PREFLIGHT_PASSED_REVIEW_REQUIRED":
        if not isinstance(expected_allowlist, dict) or not isinstance(
            expected_inventory, dict
        ):
            errors.append(
                "report-only pass requires the bound allowlist and inventory context"
            )
        errors.extend(
            _gug218_validate_evaluation_time(
                evaluation_at=evaluation_at,
                completed_at=decision,
                expires_at=expires,
                label="report-only pass receipt",
            )
        )
        if evidence_source_mode != "AWS_READ_ONLY":
            errors.append("report-only pass requires authenticated AWS read evidence")
        if not all(
            instance.get(field) is True
            for field in (
                "coverage_complete",
                "expected_authority_exact",
                "snapshot_fresh",
            )
        ):
            errors.append("report-only pass requires complete, exact and fresh evidence")
        if any(
            instance.get(field) != 0
            for field in (
                "prohibited_edge_count",
                "unknown_edge_count",
                "denied_surface_count",
            )
        ):
            errors.append("report-only pass cannot contain a blocked authority surface")

    if instance.get("status") == "BLOCKED_UNVERIFIED_SOURCE":
        if evidence_source_mode != "OFFLINE_UNVERIFIED":
            errors.append("unverified-source block requires explicit offline provenance")
        if any(
            instance.get(field) is not False
            for field in (
                "coverage_complete",
                "expected_authority_exact",
                "snapshot_fresh",
            )
        ):
            errors.append("unverified-source block cannot claim authoritative evidence")

    if instance.get("status") == "BLOCKED_DRIFT":
        if evidence_source_mode != "AWS_READ_ONLY":
            errors.append("drift block requires authenticated AWS read evidence")
        if instance.get("coverage_complete") is not True:
            errors.append("drift block requires complete inventory coverage")
        if instance.get("expected_authority_exact") is not False:
            errors.append("drift block cannot claim exact expected authority")
        if instance.get("snapshot_fresh") is not True:
            errors.append("drift block requires fresh evidence")

    if (
        evidence_source_mode == "OFFLINE_UNVERIFIED"
        and instance.get("status") != "BLOCKED_UNVERIFIED_SOURCE"
    ):
        errors.append("offline evidence can never produce a preflight decision")

    if isinstance(expected_allowlist, dict) and isinstance(expected_inventory, dict):
        if (
            expected_allowlist.get("schema_version")
            != instance.get("schema_version")
            or expected_inventory.get("schema_version")
            != instance.get("schema_version")
        ):
            errors.append("evidence bundle schema versions must match")
        common_bindings = (
            ("environment", "environment"),
            ("production", "production"),
            ("evidence_source_mode", "evidence_source_mode"),
            ("source_snapshot_digest", "source_snapshot_digest"),
            ("collector_principal_digest", "collector_principal_digest"),
            ("source_snapshot_started_at", "source_snapshot_started_at"),
            ("source_snapshot_completed_at", "source_snapshot_completed_at"),
            ("authority_account_id_digest", "authority_account_id_digest"),
            ("target_region", "target_region"),
            ("allowlist_digest", "allowlist_digest"),
            ("inventory_digest", "inventory_digest"),
        )
        for receipt_field, source_field in common_bindings:
            source = (
                expected_allowlist
                if receipt_field == "allowlist_digest"
                else expected_inventory
            )
            if instance.get(receipt_field) != source.get(source_field):
                errors.append(
                    f"{receipt_field} must match the bound evidence bundle"
                )
        if single_operator:
            for field in (
                "authorization_mode",
                "two_human_status",
                "independent_approval_present",
                "single_operator_exception_digest",
                "owner_authorization_sha256",
                "active_aliases",
            ):
                if (
                    instance.get(field) != expected_allowlist.get(field)
                    or instance.get(field) != expected_inventory.get(field)
                ):
                    errors.append(f"{field} must match the bound evidence bundle")
        inventory_completed = _gug215_timestamp(
            expected_inventory.get("scan_completed_at")
        )
        inventory_expires = _gug215_timestamp(expected_inventory.get("expires_at"))
        if (
            decision is not None
            and inventory_completed is not None
            and decision < inventory_completed
        ):
            errors.append("guard decision cannot precede inventory completion")
        if (
            expires is not None
            and inventory_expires is not None
            and expires > inventory_expires
        ):
            errors.append("guard receipt cannot outlive the bound inventory")

        coverage = expected_inventory.get("coverage")
        coverage_values = (
            list(coverage.values()) if isinstance(coverage, dict) else []
        )
        coverage_statuses = [
            value.get("status")
            for value in coverage_values
            if isinstance(value, dict)
        ]
        expected_coverage_complete = (
            expected_inventory.get("evidence_source_mode") == "AWS_READ_ONLY"
            and expected_inventory.get("status") != "INVENTORY_INCOMPLETE"
            and len(coverage_statuses) == len(GUG218_COVERAGE_SURFACES)
            and set(coverage_statuses) == {"COMPLETE"}
        )
        denied_surfaces = sum(
            status == "ACCESS_DENIED" for status in coverage_statuses
        )
        inventory_status = expected_inventory.get("status")
        if inventory_status == "REVIEW_SAFE_REPORT_ONLY":
            expected_status = "PREFLIGHT_PASSED_REVIEW_REQUIRED"
            expected_reason = "EXACT_AUTHORITY_REPORT_ONLY"
            expected_next = (
                "OWNER_REVIEW_AND_FRESH_SINGLE_OPERATOR_EXECUTION_AUTHORIZATION"
                if single_operator
                else "INDEPENDENT_REVIEW_AND_FRESH_DEPLOYMENT_AUTHORIZATION"
            )
        elif inventory_status == "FOREIGN_AUTHORITY_PRESENT":
            expected_status = "BLOCKED_UNSAFE_AUTHORITY"
            expected_reason = "UNSAFE_AUTHORITY_PRESENT"
            expected_next = "REMOVE_UNSAFE_AUTHORITY"
        elif inventory_status == "POLICY_SEMANTICS_UNSUPPORTED":
            expected_status = "BLOCKED_AMBIGUOUS"
            expected_reason = "AMBIGUOUS_EVIDENCE"
            expected_next = "RESOLVE_AMBIGUOUS_EVIDENCE"
        elif inventory_status == "DRIFT_DETECTED":
            expected_status = "BLOCKED_DRIFT"
            expected_reason = "AUTHORITY_DRIFT_DETECTED"
            expected_next = "RESOLVE_AUTHORITY_DRIFT"
        elif inventory_status == "OFFLINE_UNVERIFIED":
            expected_status = "BLOCKED_UNVERIFIED_SOURCE"
            expected_reason = "UNVERIFIED_EVIDENCE_SOURCE"
            expected_next = "COLLECT_AUTHENTICATED_AWS_INVENTORY"
        elif denied_surfaces:
            expected_status = "BLOCKED_ACCESS_DENIED"
            expected_reason = "READ_ACCESS_DENIED"
            expected_next = "RESOLVE_ACCESS_DENIAL"
        else:
            expected_status = "BLOCKED_INCOMPLETE"
            expected_reason = "INVENTORY_INCOMPLETE"
            expected_next = "COMPLETE_READ_ONLY_INVENTORY"
        expected_values = {
            "status": expected_status,
            "reason_code": expected_reason,
            "next_required_control": expected_next,
            "coverage_complete": expected_coverage_complete,
            "expected_authority_exact": inventory_status
            == "REVIEW_SAFE_REPORT_ONLY",
            "prohibited_edge_count": expected_inventory.get(
                "prohibited_edge_count"
            ),
            "unknown_edge_count": expected_inventory.get("unknown_edge_count"),
            "denied_surface_count": denied_surfaces,
        }
        for field, expected in expected_values.items():
            if instance.get(field) != expected:
                errors.append(f"{field} must match the bound inventory decision")

    without_digest = {
        key: value for key, value in instance.items() if key != "receipt_digest"
    }
    if instance.get("receipt_digest") != _gug215_canonical_digest(without_digest):
        errors.append("receipt_digest must cover the complete report-only decision")
    return errors


GUG274_PLAN_DOMAIN = "scanalyze.platform-authority.bootstrap.plan.v2"
GUG274_APPROVAL_DOMAIN = "scanalyze.platform-authority.bootstrap.approval.v2"
GUG274_LEDGER_DOMAIN = (
    "scanalyze.platform-authority.bootstrap.artifact-authority.v1"
)
GUG274_RECEIPT_DOMAIN = (
    "scanalyze.platform-authority.bootstrap.authority-receipt.v1"
)
GUG274_IDENTITY_PROOF_DOMAIN = (
    "scanalyze.platform-authority.bootstrap.identity-proof.v1"
)
GUG274_KEY_DOMAIN = "scanalyze.platform-authority.bootstrap.authority-key.v1"
GUG274_INVENTORY_DOMAIN = (
    "scanalyze.platform-authority.bootstrap.resource-inventory.v1"
)
GUG274_CHANGE_SET_ARN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):cloudformation:([a-z0-9-]+):"
    r"([0-9]{12}):changeSet/(scanalyze-platform-authority-bootstrap-[0-9]{14})/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12})$"
)


def _gug274_domain_digest(domain: str, value: dict) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(
        domain.encode("ascii") + b"\x00" + payload
    ).hexdigest()


def _gug274_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value,
    ) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def _gug274_partition(region: object) -> str | None:
    if not isinstance(region, str):
        return None
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    return "aws"


def _validate_gug274_plan(instance: dict) -> list[str]:
    errors: list[str] = []
    account_id = instance.get("authority_account_id")
    region = instance.get("region")
    partition = _gug274_partition(region)
    if instance.get("aws_partition") != partition:
        errors.append("Plan partition must be derived from its bound region")
    if isinstance(account_id, str) and isinstance(region, str):
        expected_root = (
            f"arn:{partition}:dynamodb:{region}:{account_id}:table/"
            "scanalyze-platform-authority-bootstrap-artifacts#generation/1"
        )
        if instance.get("trust_root_id") != expected_root:
            errors.append("Plan trust root must match its authority binding")
        if instance.get("state_bucket_name") != (
            f"scanalyze-platform-authority-{account_id}-{region}-state"
        ):
            errors.append("Plan state bucket must be authority-derived")
        destinations = instance.get("destination_account_ids")
        if isinstance(destinations, list) and account_id in destinations:
            errors.append("Plan authority and destination accounts must be disjoint")
        if instance.get("change_set_parameters") != {
            "AuthorityAccountId": account_id,
            "StateKey": "platform-authority/terraform.tfstate",
            "NoncurrentVersionRetentionDays": "365",
        }:
            errors.append(
                "Plan Change Set parameters must match the immutable bootstrap binding"
            )

    change_set = instance.get("change_set_id")
    match = (
        GUG274_CHANGE_SET_ARN.fullmatch(change_set)
        if isinstance(change_set, str)
        else None
    )
    if match is None:
        errors.append("Plan Change Set ARN must be complete and canonical")
    elif (
        match.group(1) != instance.get("aws_partition")
        or match.group(2) != region
        or match.group(3) != account_id
        or match.group(4) != instance.get("change_set_name")
        or match.group(5) != instance.get("change_set_uuid")
    ):
        errors.append("Plan Change Set tuple must match its full ARN")

    changes = instance.get("planned_resource_changes")
    if isinstance(changes, list) and all(isinstance(item, dict) for item in changes):
        if changes != sorted(
            changes, key=lambda item: str(item.get("logical_resource_id", ""))
        ):
            errors.append("Plan resource inventory must be canonically ordered")
        logical_ids = [item.get("logical_resource_id") for item in changes]
        if len(logical_ids) != len(set(logical_ids)):
            errors.append("Plan resource inventory logical IDs must be unique")
        required_types = {
            "AWS::KMS::Key",
            "AWS::S3::Bucket",
            "AWS::S3::BucketPolicy",
        }
        if not required_types <= {
            str(item.get("resource_type")) for item in changes
        }:
            errors.append("Plan resource inventory is incomplete")
        expected_inventory_digest = _gug274_domain_digest(
            GUG274_INVENTORY_DOMAIN, {"planned_resource_changes": changes}
        )
        if instance.get("planned_resource_inventory_digest") != (
            expected_inventory_digest
        ):
            errors.append("Plan resource inventory digest must cover the exact inventory")

    created = _gug274_timestamp(instance.get("created_at"))
    expires = _gug274_timestamp(instance.get("expires_at"))
    if created is None or expires is None:
        errors.append("Plan timestamps must be canonical UTC instants")
    elif not 300 <= (expires - created).total_seconds() <= 7200:
        errors.append("Plan lifetime must be between five minutes and two hours")

    if all(
        isinstance(instance.get(field), str)
        for field in (
            "authority_account_id",
            "aws_partition",
            "region",
            "stack_name",
            "change_set_id",
        )
    ):
        key_material = {
            "domain_separator": GUG274_KEY_DOMAIN,
            "trust_root_generation": 1,
            "authority_account_id": instance["authority_account_id"],
            "aws_partition": instance["aws_partition"],
            "region": instance["region"],
            "stack_name": instance["stack_name"],
            "change_set_id": instance["change_set_id"],
        }
        expected_record_id = "gug274#g1#" + _gug274_domain_digest(
            GUG274_KEY_DOMAIN, key_material
        )
        if instance.get("authority_record_id") != expected_record_id:
            errors.append("Plan authority record ID must be binding-derived")

    unsigned = {
        key: value for key, value in instance.items() if key != "plan_artifact_digest"
    }
    if instance.get("plan_artifact_digest") != _gug274_domain_digest(
        GUG274_PLAN_DOMAIN, unsigned
    ):
        errors.append("Plan artifact digest must cover the complete Plan v2")
    return errors


def _validate_gug274_approval(
    instance: dict, *, expected_plan: dict | None = None
) -> list[str]:
    errors: list[str] = []
    approved = _gug274_timestamp(instance.get("approved_at"))
    expires = _gug274_timestamp(instance.get("expires_at"))
    plan_created = _gug274_timestamp(instance.get("plan_created_at"))
    plan_expires = _gug274_timestamp(instance.get("plan_expires_at"))
    if None in {approved, expires, plan_created, plan_expires}:
        errors.append("Approval timestamps must be canonical UTC instants")
    elif not plan_created <= approved < expires <= plan_expires:
        errors.append("Approval lifetime must be contained by its Plan lifetime")
    if instance.get("approver_id") == instance.get("initiator_id"):
        errors.append("Approval operator IDs must be distinct")
    if instance.get("approver_principal_digest") == instance.get(
        "initiator_principal_digest"
    ):
        errors.append("Approval principal digests must be distinct")
    if expected_plan is not None:
        cross_fields = {
            "authority_record_id": "authority_record_id",
            "plan_artifact_digest": "plan_artifact_digest",
            "authority_account_id": "authority_account_id",
            "aws_partition": "aws_partition",
            "region": "region",
            "stack_name": "stack_name",
            "state_bucket_name": "state_bucket_name",
            "state_key": "state_key",
            "destination_account_ids": "destination_account_ids",
            "native_lockfile_enabled": "native_lockfile_enabled",
            "template_sha256": "template_sha256",
            "change_set_id": "change_set_id",
            "change_set_name": "change_set_name",
            "change_set_uuid": "change_set_uuid",
            "change_set_type": "change_set_type",
            "change_set_parameters": "change_set_parameters",
            "planned_resource_inventory_digest": "planned_resource_inventory_digest",
            "initiator_id": "initiator_id",
            "initiator_principal_digest": "initiator_principal_digest",
            "plan_created_at": "created_at",
            "plan_expires_at": "expires_at",
        }
        if any(
            instance.get(approval_field) != expected_plan.get(plan_field)
            for approval_field, plan_field in cross_fields.items()
        ):
            errors.append("Approval must be an exact projection of its anchored Plan")
        if instance.get("approval_nonce") == expected_plan.get("artifact_nonce"):
            errors.append("Approval nonce must differ from the Plan nonce")

    unsigned = {
        key: value
        for key, value in instance.items()
        if key != "approval_artifact_digest"
    }
    if instance.get("approval_artifact_digest") != _gug274_domain_digest(
        GUG274_APPROVAL_DOMAIN, unsigned
    ):
        errors.append("Approval artifact digest must cover the complete Approval v2")
    return errors


def _validate_gug274_identity_proof(instance: dict) -> list[str]:
    errors: list[str] = []
    expected_roles = {
        "plan": "plan_author",
        "approval": "independent_approver",
        "apply": "apply_verifier",
    }
    if expected_roles.get(instance.get("operation")) != instance.get("role_kind"):
        errors.append("identity proof role must match its exact operation")
    if instance.get("expected_user_id_digest") == instance.get(
        "peer_user_id_digest"
    ):
        errors.append("identity proof users must be distinct")
    unsigned = {
        key: value for key, value in instance.items() if key != "proof_receipt_digest"
    }
    if instance.get("proof_receipt_digest") != _gug274_domain_digest(
        GUG274_IDENTITY_PROOF_DOMAIN, unsigned
    ):
        errors.append("identity proof digest must cover the complete sanitized proof")
    return errors


def _validate_gug274_ledger(instance: dict) -> list[str]:
    errors: list[str] = []
    plan = instance.get("plan")
    approval = instance.get("approval")
    if isinstance(plan, dict):
        errors.extend(_validate_gug274_plan(plan))
        for field in (
            "trust_contract_version",
            "trust_root_id",
            "trust_root_generation",
            "trust_algorithm",
            "authority_record_id",
        ):
            if instance.get(field) != plan.get(field):
                errors.append(f"ledger {field} must match its Plan")
        if instance.get("created_at") != plan.get("created_at"):
            errors.append("ledger creation time must match its Plan creation time")
    if isinstance(approval, dict):
        errors.extend(
            _validate_gug274_approval(
                approval,
                expected_plan=plan if isinstance(plan, dict) else None,
            )
        )

    proof_names = (
        "plan_identity_proof",
        "approval_identity_proof",
        "apply_identity_proof",
    )
    proofs = {
        name: instance.get(name)
        for name in proof_names
        if isinstance(instance.get(name), dict)
    }
    for proof in proofs.values():
        errors.extend(_validate_gug274_identity_proof(proof))
        if proof.get("identity_binding_digest") != instance.get(
            "identity_binding_digest"
        ):
            errors.append("ledger identity proofs must share one immutable binding")

    plan_proof = proofs.get("plan_identity_proof")
    approval_proof = proofs.get("approval_identity_proof")
    apply_proof = proofs.get("apply_identity_proof")
    if isinstance(plan_proof, dict) and isinstance(approval_proof, dict):
        if (
            approval_proof.get("expected_user_id_digest")
            != plan_proof.get("peer_user_id_digest")
            or approval_proof.get("peer_user_id_digest")
            != plan_proof.get("expected_user_id_digest")
        ):
            errors.append("Plan and Approval proofs must bind opposite real users")
        if (
            approval_proof.get("proof_role_arn_digest")
            == plan_proof.get("proof_role_arn_digest")
            or approval_proof.get("broker_execution_role_arn_digest")
            == plan_proof.get("broker_execution_role_arn_digest")
        ):
            errors.append("Plan and Approval proofs must use distinct roles")
    if (
        isinstance(plan_proof, dict)
        and isinstance(approval_proof, dict)
        and isinstance(apply_proof, dict)
    ):
        if (
            apply_proof.get("expected_user_id_digest")
            != approval_proof.get("expected_user_id_digest")
            or apply_proof.get("peer_user_id_digest")
            != approval_proof.get("peer_user_id_digest")
        ):
            errors.append("Apply proof must bind the approved second party")
        if apply_proof.get("proof_role_arn_digest") in {
            plan_proof.get("proof_role_arn_digest"),
            approval_proof.get("proof_role_arn_digest"),
        } or apply_proof.get("broker_execution_role_arn_digest") in {
            plan_proof.get("broker_execution_role_arn_digest"),
            approval_proof.get("broker_execution_role_arn_digest"),
        }:
            errors.append("Apply proof must use an independently scoped role")

    created = _gug274_timestamp(instance.get("created_at"))
    updated = _gug274_timestamp(instance.get("updated_at"))
    claimed = _gug274_timestamp(instance.get("claimed_at"))
    if created is not None and updated is not None and updated < created:
        errors.append("ledger update time cannot precede creation")
    if instance.get("state") == "CLAIMED" and claimed != updated:
        errors.append("terminal claim time must equal its ledger update time")

    unsigned = {
        key: value for key, value in instance.items() if key != "ledger_digest"
    }
    if instance.get("ledger_digest") != _gug274_domain_digest(
        GUG274_LEDGER_DOMAIN, unsigned
    ):
        errors.append("ledger digest must cover the complete state snapshot")
    return errors


def _validate_gug274_authority_receipt(instance: dict) -> list[str]:
    unsigned = {
        key: value for key, value in instance.items() if key != "receipt_digest"
    }
    if instance.get("receipt_digest") != _gug274_domain_digest(
        GUG274_RECEIPT_DOMAIN, unsigned
    ):
        return ["authority receipt digest must cover the complete receipt"]
    return []


GUG274_PACKAGE_PATHS = (
    "gug274_runtime_lock.json",
    "policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json",
    "tooling/__init__.py",
    "tooling/platform_authority_bootstrap.py",
    "tooling/platform_authority_bootstrap_artifact_authority.py",
    "tooling/platform_authority_bootstrap_identity_proof.py",
    "tooling/platform_authority_identity_context_compatibility.py",
    "tooling/platform_authority_identity_context_pep.py",
)


def _validate_gug274_artifact_package(instance: dict) -> list[str]:
    errors: list[str] = []
    archive_digest = instance.get("archive_sha256")
    if isinstance(archive_digest, str) and re.fullmatch(
        r"[a-f0-9]{64}", archive_digest
    ):
        expected_code_digest = base64.b64encode(
            bytes.fromhex(archive_digest)
        ).decode("ascii")
        if instance.get("unsigned_archive_code_sha256") != expected_code_digest:
            errors.append(
                "unsigned archive CodeSha256 must encode the exact archive digest"
            )

    entries = instance.get("entries")
    if isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries):
        paths = tuple(entry.get("path") for entry in entries)
        if paths != GUG274_PACKAGE_PATHS:
            errors.append("package entries must be the exact sorted runtime closure")
        runtime = instance.get("runtime_dependencies")
        if isinstance(runtime, dict):
            runtime_lock = {
                "record_type": (
                    "scanalyze.platform_authority."
                    "bootstrap_artifact_authority_runtime_lock.v1"
                ),
                "schema_version": 1,
                "work_package": "GUG-274",
                "trust_root_generation": 1,
                "source_commit": instance.get("source_commit"),
                "expected_boto3_version": runtime.get("expected_boto3_version"),
                "expected_botocore_version": runtime.get(
                    "expected_botocore_version"
                ),
            }
            runtime_lock_bytes = (
                json.dumps(
                    runtime_lock,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            lock_entry = entries[0] if entries else None
            if not isinstance(lock_entry, dict) or (
                lock_entry.get("path") != runtime.get("runtime_lock_path")
                or lock_entry.get("sha256")
                != hashlib.sha256(runtime_lock_bytes).hexdigest()
                or lock_entry.get("size_bytes") != len(runtime_lock_bytes)
            ):
                errors.append(
                    "runtime lock entry must bind the exact source and SDK versions"
                )

        if len(entries) == len(GUG274_PACKAGE_PATHS) and all(
            type(entry.get("size_bytes")) is int for entry in entries
        ):
            expected_archive_size = (
                sum(entry["size_bytes"] for entry in entries)
                + sum(
                    76 + (2 * len(path.encode("utf-8")))
                    for path in GUG274_PACKAGE_PATHS
                )
                + 22
            )
            if instance.get("archive_size_bytes") != expected_archive_size:
                errors.append(
                    "archive size must match ZIP_STORED fixed-metadata entries"
                )
    return errors


def _validate_gug274_signing_trust_root(instance: dict) -> list[str]:
    """Apply the exact runtime trust-root state machine to schema fixtures."""

    try:
        from tooling.platform_authority_bootstrap_signed_artifact import (
            BootstrapSignedArtifactError,
            validate_signing_trust_root_contract,
        )
    except ImportError as exc:
        return [f"GUG-274 signing trust-root validator unavailable: {exc}"]
    try:
        validate_signing_trust_root_contract(
            instance, require_configured=False
        )
    except BootstrapSignedArtifactError as exc:
        return [f"GUG-274 signing trust-root contract invalid: {exc}"]
    return []


def _validate_gug274_signed_artifact_receipt(
    instance: dict, *, evaluation_at: datetime | None
) -> list[str]:
    """Validate digest, review, freshness, trust root, and CFN projection."""

    try:
        from tooling.platform_authority_bootstrap_signed_artifact import (
            BootstrapSignedArtifactError,
            validate_signed_artifact_receipt,
        )
    except ImportError as exc:
        return [f"GUG-274 signed-artifact validator unavailable: {exc}"]
    try:
        validate_signed_artifact_receipt(instance, now=evaluation_at)
    except BootstrapSignedArtifactError as exc:
        return [f"GUG-274 signed-artifact receipt invalid: {exc}"]
    return []


def _validate_gug390_live_run(instance: dict) -> list[str]:
    """Reject stale seals and cross-field AWS/mutation overclaims."""

    errors: list[str] = []
    run_body = {
        key: value for key, value in instance.items() if key != "run_digest"
    }
    if instance.get("run_digest") != _canonical_sha256(run_body):
        errors.append("GUG-390 run_digest must seal the complete public record")
    aws_calls = instance.get("aws_calls")
    aws_mutations = instance.get("aws_mutations")
    if type(aws_calls) is not int or type(aws_mutations) is not int:
        return errors

    if aws_mutations > aws_calls:
        errors.append("GUG-390 aws_mutations must not exceed aws_calls")
    if instance.get("status") == "STOP_NO_MUTATION" and aws_mutations != 0:
        errors.append("GUG-390 STOP_NO_MUTATION requires aws_mutations = 0")
    if aws_mutations > 0 and (
        instance.get("command") != "execute-phase"
        or instance.get("classification") != "LIVE_PROVIDER_EVIDENCE"
    ):
        errors.append(
            "GUG-390 aws_mutations > 0 requires command=execute-phase "
            "and classification=LIVE_PROVIDER_EVIDENCE"
        )
    return errors


def _validate_gug393_discovery_receipt(instance: dict) -> list[str]:
    """Apply the exact public receipt seal and counter invariants."""

    errors = [
        f"GUG-393 {field} must not exceed {maximum}"
        for field, maximum in _GUG393_DISCOVERY_RECEIPT_MAXIMUMS
        if type(instance.get(field)) is int and instance[field] > maximum
    ]
    if errors:
        return errors

    try:
        from tooling.platform_authority_gug393_private_input_discovery import (
            PrivateInputDiscoveryError,
            validate_public_discovery_receipt,
        )
    except ImportError as exc:
        return errors + [f"GUG-393 discovery receipt validator unavailable: {exc}"]
    try:
        validate_public_discovery_receipt(instance)
    except PrivateInputDiscoveryError as exc:
        errors.append(f"GUG-393 discovery receipt contract invalid: {exc.code}")
    return errors


def _validate_gug395_public_receipt(
    instance: dict, *, downstream: bool
) -> list[str]:
    """Apply the exact GUG-395 digest-only receipt seal and invariants."""

    try:
        from tooling.platform_authority_gug395_preplan_seed import (
            PreplanSeedError,
            validate_downstream_materialization_receipt_shape,
            validate_preplan_seed_receipt_shape,
        )
    except ImportError as exc:
        return [f"GUG-395 receipt validator unavailable: {exc}"]
    try:
        if downstream:
            validate_downstream_materialization_receipt_shape(instance)
            if instance.get("status") != "SYNTHETIC_CONTRACT_ONLY_BLOCKED":
                return [
                    "GUG-395 receipt contract invalid: "
                    "TERMINAL_HANDOFF_VERIFICATION_REQUIRED"
                ]
        else:
            validate_preplan_seed_receipt_shape(instance)
            if instance.get("status") != "SYNTHETIC_CONTRACT_ONLY_BLOCKED":
                return [
                    "GUG-395 receipt contract invalid: "
                    "SOURCE_VERIFICATION_REQUIRED"
                ]
    except PreplanSeedError as exc:
        return [f"GUG-395 receipt contract invalid: {exc.code}"]
    return []


def _validate_gug395_collision_probe_receipt(instance: dict) -> list[str]:
    """Apply the exact collision-probe receipt seal and overclaim lattice."""

    try:
        from tooling.platform_authority_gug395_preplan_collision_probe import (
            CollisionProbeError,
            validate_public_collision_probe_receipt,
        )
    except ImportError as exc:
        return [f"GUG-395 collision-probe validator unavailable: {exc}"]
    try:
        validate_public_collision_probe_receipt(instance)
    except CollisionProbeError as exc:
        return [f"GUG-395 collision-probe receipt invalid: {exc.code}"]
    return []


def _validate_gug392_live_record(instance: dict, *, handoff: bool) -> list[str]:
    """Apply the runtime v2 seal, policy and call-count invariants."""

    try:
        from tooling.platform_authority_gug376_live_executor import (
            LiveExecutorError,
            validate_live_public_handoff,
            validate_live_run_record,
        )
    except ImportError as exc:
        return [f"GUG-392 live-record validator unavailable: {exc}"]
    try:
        if handoff:
            validate_live_public_handoff(instance)
        else:
            validate_live_run_record(instance)
    except LiveExecutorError as exc:
        return [f"GUG-392 live-record contract invalid: {exc.code}"]
    return []


def validate_semantics(
    instance: dict,
    schema_path: Path,
    *,
    gug274_plan: dict | None = None,
    gug218_allowlist: dict | None = None,
    gug218_inventory: dict | None = None,
    gug219_collector_contract: dict | None = None,
    gug363_intent: dict | None = None,
    gug363_plan: dict | None = None,
    gug363_authorization: dict | None = None,
    gug363_ledger: dict | None = None,
    evaluation_at: datetime | None = None,
) -> list[str]:
    """Validate cross-field invariants not expressible in Draft 2020-12.

    Messages intentionally name fields without echoing rejected identity values.
    JSON Schema remains the first validation layer; this function only evaluates
    well-shaped portions that are present.
    """
    errors: list[str] = []
    schema_name = schema_path.name

    if schema_name == "enterprise-authorization.v1.schema.json":
        try:
            from tooling.validate_enterprise_authorization import (
                validate_enterprise_authorization,
            )
        except ModuleNotFoundError:  # Direct script execution from tooling/.
            from validate_enterprise_authorization import (  # type: ignore[no-redef]
                validate_enterprise_authorization,
            )

        errors.extend(validate_enterprise_authorization(instance))

    if schema_name == "identity-contract.v2.schema.json":
        cognito = instance.get("cognito")
        declared_clients = (
            cognito.get("m2m_client_ids", []) if isinstance(cognito, dict) else []
        )
        errors.extend(
            _validate_m2m_registry(instance, declared_clients=declared_clients)
        )

    if schema_name == "contract-identity-control-plane.v1.schema.json":
        errors.extend(_validate_cognito_binding(instance, require_arn=True))
        errors.extend(
            _validate_m2m_registry(
                instance,
                declared_clients=instance.get("m2m_client_ids"),
            )
        )

    if schema_name == "contract-edge-identity.v2.schema.json":
        errors.extend(_validate_cognito_binding(instance, require_arn=False))
        spa_client = instance.get("cognito_spa_client_id")
        m2m_clients = instance.get("m2m_client_ids")
        audiences = instance.get("authorizer_audiences")
        if (
            isinstance(spa_client, str)
            and isinstance(m2m_clients, list)
            and all(isinstance(client, str) for client in m2m_clients)
            and isinstance(audiences, list)
            and set(audiences) != {spa_client, *m2m_clients}
        ):
            errors.append("JWT authorizer audiences must cover SPA and M2M clients exactly")

        api_id = instance.get("api_gateway_id")
        region = instance.get("region")
        partition = instance.get("aws_partition")
        endpoint = instance.get("api_gateway_endpoint")
        suffix = _aws_dns_suffix(partition)
        if all(
            isinstance(value, str)
            for value in (api_id, region, endpoint, suffix)
        ):
            expected_endpoint = f"https://{api_id}.execute-api.{region}.{suffix}"
            if endpoint.rstrip("/") != expected_endpoint:
                errors.append("API endpoint must match the bound API and region")

    if schema_name == "frontend-config.v2.schema.json":
        cognito = instance.get("cognito")
        region = instance.get("region")
        if isinstance(cognito, dict) and cognito.get("region") != region:
            errors.append("frontend Cognito region must match the deployment region")

    if schema_name == "task-definition-input.v2.schema.json":
        environment = instance.get("environment", [])
        entries = [entry for entry in environment if isinstance(entry, dict)]
        names = [entry.get("name") for entry in entries]
        normalized_names = [
            name.upper() for name in names if isinstance(name, str)
        ]
        counts = Counter(normalized_names)
        canonical_names = {
            "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
            "SCANALYZE_DEPLOYMENT_ID",
        }
        for canonical_name in (
            "SCANALYZE_DEPLOYMENT_CUSTOMER_ID",
            "SCANALYZE_DEPLOYMENT_ID",
        ):
            if counts[canonical_name] != 1:
                errors.append(
                    f"environment must contain exactly one {canonical_name} entry"
                )
        if any(count > 1 for count in counts.values()):
            errors.append("environment variable names must be case-insensitively unique")
        if any(
            isinstance(name, str)
            and name.upper() in canonical_names
            and name != name.upper()
            for name in names
        ):
            errors.append(
                "canonical environment variable names must use exact uppercase spelling"
            )

        environment_by_name = {
            entry.get("name", "").upper(): entry.get("value")
            for entry in entries
            if isinstance(entry.get("name"), str)
        }
        customer_identity = instance.get("customer_identity")
        deployment_identity = instance.get("deployment_identity")
        customer_value = (
            customer_identity.get("canonical_value")
            if isinstance(customer_identity, dict)
            else None
        )
        deployment_value = (
            deployment_identity.get("canonical_value")
            if isinstance(deployment_identity, dict)
            else None
        )
        if (
            environment_by_name.get("SCANALYZE_DEPLOYMENT_CUSTOMER_ID")
            != customer_value
        ):
            errors.append(
                "SCANALYZE_DEPLOYMENT_CUSTOMER_ID must match customer_identity.canonical_value"
            )
        if environment_by_name.get("SCANALYZE_DEPLOYMENT_ID") != deployment_value:
            errors.append(
                "SCANALYZE_DEPLOYMENT_ID must match deployment_identity.canonical_value"
            )
        if customer_value is not None and customer_value == deployment_value:
            errors.append("customer and deployment canonical values must be distinct")

    if schema_name == "platform-authority-bootstrap-plan.v2.schema.json":
        errors.extend(_validate_gug274_plan(instance))

    if schema_name == "platform-authority-bootstrap-approval.v2.schema.json":
        errors.extend(
            _validate_gug274_approval(instance, expected_plan=gug274_plan)
        )

    if schema_name == (
        "platform-authority-bootstrap-identity-proof-receipt.v1.schema.json"
    ):
        errors.extend(_validate_gug274_identity_proof(instance))

    if schema_name == (
        "platform-authority-bootstrap-artifact-authority.v1.schema.json"
    ):
        errors.extend(_validate_gug274_ledger(instance))

    if schema_name == (
        "platform-authority-bootstrap-artifact-package.v1.schema.json"
    ):
        errors.extend(_validate_gug274_artifact_package(instance))

    if schema_name == (
        "platform-authority-bootstrap-artifact-signing-trust-root.v1.schema.json"
    ):
        errors.extend(_validate_gug274_signing_trust_root(instance))

    if schema_name == (
        "platform-authority-bootstrap-signed-artifact-receipt.v1.schema.json"
    ):
        errors.extend(
            _validate_gug274_signed_artifact_receipt(
                instance, evaluation_at=evaluation_at
            )
        )

    if schema_name == (
        "platform-authority-bootstrap-authority-receipt.v1.schema.json"
    ):
        errors.extend(_validate_gug274_authority_receipt(instance))

    if schema_name in {
        "platform-authority-change-set-retirement-ledger.v1.schema.json",
        "platform-authority-change-set-retirement-ledger.v2.schema.json",
        "platform-authority-change-set-retirement-ledger.v3.schema.json",
    }:
        errors.extend(_validate_gug215_ledger(instance))

    if schema_name == (
        "platform-authority-change-set-retirement-single-operator-exception.v1.schema.json"
    ):
        errors.extend(_validate_gug215_single_operator_exception(instance))

    if schema_name.startswith("platform-authority-retirement-entrypoint-"):
        try:
            from tooling.platform_authority_retirement_entrypoint_materializer import (
                RetirementEntrypointMaterializationError,
                POST_WRITE_READBACK_OPERATIONS,
                PREFLIGHT_OPERATIONS,
                RECONCILE_OPERATIONS,
                validate_execution_authorization,
                validate_execution_ledger,
                validate_materialization_intent,
                validate_materialization_plan,
                validate_materialization_receipt,
                private_parameter_projection_digest,
            )
        except ImportError as exc:
            errors.append(f"GUG-363 validator unavailable: {exc}")
        else:
            try:
                if schema_name == (
                    "platform-authority-retirement-entrypoint-intent.v1.schema.json"
                ):
                    validate_materialization_intent(instance)
                elif schema_name == (
                    "platform-authority-retirement-entrypoint-plan.v1.schema.json"
                ):
                    validate_materialization_plan(instance)
                    if gug363_intent is None:
                        raise RetirementEntrypointMaterializationError(
                            "INTENT_CONTEXT_REQUIRED"
                        )
                    validate_materialization_intent(gug363_intent)
                    if (
                        instance.get("intent_digest")
                        != gug363_intent.get("intent_digest")
                        or instance.get("owner_authorization_sha256")
                        != gug363_intent.get("owner_authorization_sha256")
                        or instance.get("single_operator_exception_digest")
                        != gug363_intent.get("single_operator_exception_digest")
                        or instance.get("source") != gug363_intent.get("source")
                        or instance.get("target") != gug363_intent.get("target")
                        or instance.get("artifact_signing_contract")
                        != gug363_intent.get("artifact_signing_contract")
                        or instance.get("artifact_signing_contract_digest")
                        != gug363_intent.get("artifact_signing_contract_digest")
                        or instance.get("artifact_signing_evidence_digest")
                        != gug363_intent.get("artifact_signing_evidence_digest")
                        or instance.get("gug363_pre_function_binding_sha256")
                        != gug363_intent.get(
                            "gug363_pre_function_binding_sha256"
                        )
                    ):
                        raise RetirementEntrypointMaterializationError(
                            "PLAN_INTENT_BINDING_INVALID"
                        )
                    projection = instance.get("parameter_projection")
                    intent_parameters = gug363_intent.get("parameters")
                    projection_parameters = {
                        item.get("ParameterKey"): item.get("ParameterValue")
                        for item in projection
                        if isinstance(item, dict)
                    } if isinstance(projection, list) else None
                    if (
                        not isinstance(intent_parameters, dict)
                        or intent_parameters.get(
                            "PrivateParameterProjectionSha256"
                        )
                        != private_parameter_projection_digest(intent_parameters)
                        or projection_parameters != intent_parameters
                    ):
                        raise RetirementEntrypointMaterializationError(
                            "PLAN_INTENT_PARAMETER_BINDING_INVALID"
                        )
                elif schema_name == (
                    "platform-authority-retirement-entrypoint-execution-authorization.v1.schema.json"
                ):
                    if gug363_plan is None:
                        raise RetirementEntrypointMaterializationError(
                            "PLAN_CONTEXT_REQUIRED"
                        )
                    validate_execution_authorization(
                        instance,
                        plan=gug363_plan,
                        now=evaluation_at or datetime.now(UTC),
                        require_active=evaluation_at is not None,
                    )
                elif schema_name == (
                    "platform-authority-retirement-entrypoint-execution-ledger.v1.schema.json"
                ):
                    if gug363_plan is None or gug363_authorization is None:
                        raise RetirementEntrypointMaterializationError(
                            "AUTHORIZATION_CONTEXT_REQUIRED"
                        )
                    validate_execution_authorization(
                        gug363_authorization,
                        plan=gug363_plan,
                        now=evaluation_at or datetime.now(UTC),
                        require_active=evaluation_at is not None,
                    )
                    validate_execution_ledger(
                        instance,
                        plan=gug363_plan,
                        authorization=gug363_authorization,
                    )
                elif schema_name == (
                    "platform-authority-retirement-entrypoint-materialization-receipt.v1.schema.json"
                ):
                    if gug363_plan is None or gug363_authorization is None:
                        raise RetirementEntrypointMaterializationError(
                            "AUTHORIZATION_CONTEXT_REQUIRED"
                        )
                    if instance.get("status") == "TARGET_PRESENT_NO_TOUCH":
                        raise RetirementEntrypointMaterializationError(
                            "RECEIPT_PREEXISTING_COMPLETE_STATUS_FORBIDDEN"
                        )
                    validate_execution_authorization(
                        gug363_authorization,
                        plan=gug363_plan,
                        now=evaluation_at or datetime.now(UTC),
                        require_active=evaluation_at is not None,
                    )
                    if gug363_ledger is not None:
                        validate_execution_ledger(
                            gug363_ledger,
                            plan=gug363_plan,
                            authorization=gug363_authorization,
                        )
                    validate_materialization_receipt(
                        instance,
                        plan=gug363_plan,
                        authorization=gug363_authorization,
                    )
                    if (
                        instance.get("readback_complete") is True
                        or instance.get("target_state") == "COMPLETE"
                    ):
                        if instance.get("execution_mode") == "RECONCILE":
                            expected_complete_operations = list(
                                RECONCILE_OPERATIONS
                            )
                        elif instance.get("aws_mutation_attempted") is True:
                            expected_complete_operations = [
                                *PREFLIGHT_OPERATIONS,
                                "cloudformation:CreateStack",
                                *POST_WRITE_READBACK_OPERATIONS,
                            ]
                        else:
                            raise RetirementEntrypointMaterializationError(
                                "RECEIPT_APPLY_NO_TOUCH_COMPLETE_OVERCLAIM"
                            )
                        if (
                            instance.get("aws_operations")
                            != expected_complete_operations
                        ):
                            raise RetirementEntrypointMaterializationError(
                                "RECEIPT_COMPLETE_OPERATION_SEQUENCE_INVALID"
                            )
                    ledger_digest = instance.get("execution_ledger_digest")
                    if ledger_digest is not None and (
                        gug363_ledger is None
                        or ledger_digest != gug363_ledger.get("ledger_digest")
                    ):
                        raise RetirementEntrypointMaterializationError(
                            "RECEIPT_LEDGER_BINDING_INVALID"
                        )
            except RetirementEntrypointMaterializationError as exc:
                errors.append(f"GUG-363 contract invalid: {exc}")

    if schema_name == "platform-authority-identity-enhanced-binding.v1.schema.json":
        errors.extend(_validate_gug216_binding(instance))

    if schema_name in {
        "platform-authority-identity-context-compatibility-receipt.v1.schema.json",
        "platform-authority-identity-enhanced-session-receipt.v1.schema.json",
        "platform-authority-identity-context-pep-compatibility-receipt.v1.schema.json",
    }:
        errors.extend(_validate_gug216_receipt(instance))

    if schema_name in {
        "platform-authority-identity-context-pep-binding.v1.schema.json",
        "platform-authority-identity-context-pep-binding.v2.schema.json",
    }:
        errors.extend(_validate_gug217_binding(instance))

    if schema_name in {
        "platform-authority-identity-context-proof-receipt.v1.schema.json",
        "platform-authority-identity-context-proof-receipt.v2.schema.json",
    }:
        errors.extend(_validate_gug217_proof_receipt(instance))

    if schema_name in {
        "platform-authority-lambda-invocation-allowlist.v1.schema.json",
        "platform-authority-lambda-invocation-allowlist.v2.schema.json",
    }:
        errors.extend(_validate_gug218_allowlist(instance))

    if schema_name == "platform-authority-lambda-invocation-collector-contract.v1.schema.json":
        errors.extend(_validate_gug219_collector_contract(instance))

    if schema_name in {
        "platform-authority-lambda-invocation-allowlist-release.v1.schema.json",
        "platform-authority-lambda-invocation-allowlist-release.v2.schema.json",
    }:
        errors.extend(
            _validate_gug219_release(
                instance,
                expected_collector_contract=gug219_collector_contract,
                expected_allowlist=gug218_allowlist,
            )
        )

    if schema_name == "platform-authority-lambda-audit-provisioning-intent.v1.schema.json":
        errors.extend(_validate_gug220_provisioning_intent(instance))

    if schema_name == "platform-authority-lambda-audit-execution-ledger.v1.schema.json":
        errors.extend(_validate_gug220_execution_ledger(instance))

    if schema_name == "platform-authority-lambda-audit-provisioning-receipt.v1.schema.json":
        errors.extend(_validate_gug220_provisioning_receipt(instance))

    if schema_name == "platform-authority-lambda-audit-repair-broker-topology.v1.schema.json":
        errors.extend(_validate_gug221_broker_topology(instance))

    if schema_name == "platform-authority-lambda-audit-repair-broker-intent.v1.schema.json":
        errors.extend(_validate_gug221_broker_intent(instance))

    if schema_name == "platform-authority-lambda-audit-repair-broker-ledger.v1.schema.json":
        errors.extend(_validate_gug221_broker_ledger(instance))

    if schema_name == "platform-authority-lambda-audit-repair-broker-receipt.v1.schema.json":
        errors.extend(_validate_gug221_broker_receipt(instance))

    if schema_name == "platform-authority-lambda-audit-repair-signed-artifact.v1.schema.json":
        try:
            from tooling.platform_authority_lambda_audit_repair_signed_artifact import (
                SignedArtifactError,
                validate_signed_artifact_receipt,
            )
        except ImportError as exc:
            errors.append(f"GUG-221 signed-artifact validator unavailable: {exc}")
        else:
            try:
                validate_signed_artifact_receipt(instance)
            except SignedArtifactError as exc:
                errors.append(f"GUG-221 signed-artifact receipt invalid: {exc}")

    if schema_name in {
        "platform-authority-lambda-invocation-inventory.v1.schema.json",
        "platform-authority-lambda-invocation-inventory.v2.schema.json",
    }:
        errors.extend(
            _validate_gug218_inventory(
                instance,
                expected_allowlist=gug218_allowlist,
                evaluation_at=evaluation_at,
            )
        )

    if schema_name in {
        "platform-authority-lambda-invocation-guard-receipt.v1.schema.json",
        "platform-authority-lambda-invocation-guard-receipt.v2.schema.json",
    }:
        errors.extend(
            _validate_gug218_guard_receipt(
                instance,
                expected_allowlist=gug218_allowlist,
                expected_inventory=gug218_inventory,
                evaluation_at=evaluation_at,
            )
        )

    if schema_name in {
        "platform-authority-retirement-entrypoint-service-role-plan.v1.schema.json",
        "platform-authority-retirement-ledger-factory-package.v1.schema.json",
        "platform-authority-retirement-ledger-factory-receipt.v1.schema.json",
        "platform-authority-gug365-executor-authority-evidence.v1.schema.json",
        "platform-authority-gug365-phase-execution-ledger.v1.schema.json",
    }:
        errors.extend(
            _validate_gug365_cross_boundary_artifact(
                instance, schema_name=schema_name
            )
        )

    if schema_name == "platform-authority-gug390-live-run.v1.schema.json":
        errors.extend(_validate_gug390_live_run(instance))

    if schema_name == "platform-authority-gug393-discovery-receipt.v1.schema.json":
        errors.extend(_validate_gug393_discovery_receipt(instance))

    if schema_name == "platform-authority-gug395-preplan-seed-receipt.v1.schema.json":
        errors.extend(_validate_gug395_public_receipt(instance, downstream=False))

    if schema_name == (
        "platform-authority-gug395-downstream-materialization-receipt.v1.schema.json"
    ):
        errors.extend(_validate_gug395_public_receipt(instance, downstream=True))

    if schema_name == (
        "platform-authority-gug395-preplan-collision-probe-receipt.v1.schema.json"
    ):
        errors.extend(_validate_gug395_collision_probe_receipt(instance))

    if schema_name == "platform-authority-gug376-live-readonly-run.v2.schema.json":
        errors.extend(_validate_gug392_live_record(instance, handoff=False))

    if schema_name == "platform-authority-gug376-live-readonly-handoff.v2.schema.json":
        errors.extend(_validate_gug392_live_record(instance, handoff=True))

    return errors


def validate_gug218_evidence_bundle(
    *,
    allowlist: dict,
    inventory: dict,
    receipt: dict,
    evaluation_at: datetime | None,
) -> list[str]:
    """Validate one complete GUG-218 evidence chain at a trusted instant."""

    errors: list[str] = []
    if not HAS_JSONSCHEMA:
        return ["jsonschema dependency is required for GUG-218 bundle validation"]
    schema_dir = Path(__file__).resolve().parents[1] / "schemas"
    version = "2" if allowlist.get("schema_version") == "2" else "1"
    records = (
        (
            "allowlist",
            allowlist,
            f"platform-authority-lambda-invocation-allowlist.v{version}.schema.json",
        ),
        (
            "inventory",
            inventory,
            f"platform-authority-lambda-invocation-inventory.v{version}.schema.json",
        ),
        (
            "receipt",
            receipt,
            f"platform-authority-lambda-invocation-guard-receipt.v{version}.schema.json",
        ),
    )
    for label, record, schema_name in records:
        schema = load_json(schema_dir / schema_name)
        errors.extend(
            f"{label}: {error.message}"
            for error in Draft202012Validator(
                schema, format_checker=FormatChecker()
            ).iter_errors(record)
        )
    errors.extend(
        f"allowlist: {error}"
        for error in _validate_gug218_allowlist(allowlist)
    )
    errors.extend(
        f"inventory: {error}"
        for error in _validate_gug218_inventory(
            inventory,
            expected_allowlist=allowlist,
            evaluation_at=evaluation_at,
        )
    )
    errors.extend(
        f"receipt: {error}"
        for error in _validate_gug218_guard_receipt(
            receipt,
            expected_allowlist=allowlist,
            expected_inventory=inventory,
            evaluation_at=evaluation_at,
        )
    )
    return errors


def validate_fixture(fixture_path: Path, schema_path: Path) -> tuple[bool, str]:
    """Validate a fixture against a schema. Returns (passed, message)."""
    fixture = load_json(fixture_path)
    schema = load_json(schema_path)

    # Remove _test_metadata before validation (it's not part of the schema)
    fixture_clean = {k: v for k, v in fixture.items() if k != "_test_metadata"}

    try:
        validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
            registry=_schema_registry(schema_path.parent),
        )
        validator.validate(fixture_clean)
        metadata = fixture.get("_test_metadata")
        evaluation_at = _gug215_timestamp(
            metadata.get("trusted_evaluation_at")
            if isinstance(metadata, dict)
            else None
        )
        if evaluation_at is None:
            if fixture_path.name in {
                "platform-authority-lambda-invocation-inventory-v1-synthetic.json",
                "platform-authority-lambda-invocation-guard-receipt-v1-synthetic.json",
            }:
                evaluation_at = datetime(2026, 7, 20, 10, 2, tzinfo=UTC)
            elif fixture_path.name in {
                "platform-authority-lambda-invocation-inventory-v2-single-operator-synthetic.json",
                "platform-authority-lambda-invocation-guard-receipt-v2-single-operator-synthetic.json",
            }:
                evaluation_at = datetime(2030, 1, 1, 0, 26, tzinfo=UTC)
        if schema_path.name.startswith(
            "platform-authority-retirement-entrypoint-"
        ):
            valid_dir = fixture_path.parent.parent / "valid"

            def load_gug363_context(name: str) -> dict:
                context = load_json(valid_dir / name)
                context.pop("_test_metadata", None)
                return context

            semantic_context: dict[str, dict] = {}
            if schema_path.name == (
                "platform-authority-retirement-entrypoint-plan.v1.schema.json"
            ):
                semantic_context["gug363_intent"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-intent-v1-synthetic.json"
                )
            elif schema_path.name == (
                "platform-authority-retirement-entrypoint-execution-authorization.v1.schema.json"
            ):
                semantic_context["gug363_plan"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-plan-v1-synthetic.json"
                )
            elif schema_path.name == (
                "platform-authority-retirement-entrypoint-execution-ledger.v1.schema.json"
            ):
                semantic_context["gug363_plan"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-plan-v1-synthetic.json"
                )
                semantic_context["gug363_authorization"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-execution-authorization-v1-synthetic.json"
                )
            elif schema_path.name == (
                "platform-authority-retirement-entrypoint-materialization-receipt.v1.schema.json"
            ):
                semantic_context["gug363_plan"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-plan-v1-synthetic.json"
                )
                semantic_context["gug363_authorization"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-execution-authorization-v1-synthetic.json"
                )
                semantic_context["gug363_ledger"] = load_gug363_context(
                    "platform-authority-retirement-entrypoint-execution-ledger-v1-synthetic.json"
                )
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                evaluation_at=evaluation_at,
                **semantic_context,
            )
        elif (
            schema_path.name
            == "platform-authority-bootstrap-approval.v2.schema.json"
        ):
            valid_dir = fixture_path.parent.parent / "valid"
            plan = load_json(
                valid_dir / "platform-authority-bootstrap-plan-v2-synthetic.json"
            )
            plan.pop("_test_metadata", None)
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                gug274_plan=plan,
                evaluation_at=evaluation_at,
            )
        elif (
            schema_path.name
            in {
                "platform-authority-lambda-invocation-allowlist-release.v1.schema.json",
                "platform-authority-lambda-invocation-allowlist-release.v2.schema.json",
            }
        ):
            valid_dir = fixture_path.parent.parent / "valid"
            collector = load_json(
                valid_dir
                / "platform-authority-lambda-invocation-collector-contract-v1-synthetic.json"
            )
            collector.pop("_test_metadata", None)
            version = fixture_clean.get("schema_version", "1")
            allowlist = None
            if version == "2":
                allowlist = load_json(
                    valid_dir
                    / "platform-authority-lambda-invocation-allowlist-v2-single-operator-synthetic.json"
                )
                allowlist.pop("_test_metadata", None)
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                gug219_collector_contract=collector,
                gug218_allowlist=allowlist,
                evaluation_at=evaluation_at,
            )
        elif (
            schema_path.name
            in {
                "platform-authority-lambda-invocation-inventory.v1.schema.json",
                "platform-authority-lambda-invocation-inventory.v2.schema.json",
            }
            and fixture_clean.get("status") == "REVIEW_SAFE_REPORT_ONLY"
        ):
            gug218_valid_dir = fixture_path.parent.parent / "valid"
            version = fixture_clean.get("schema_version", "1")
            allowlist = load_json(
                gug218_valid_dir
                / (
                    "platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
                    if version == "1"
                    else "platform-authority-lambda-invocation-allowlist-v2-single-operator-synthetic.json"
                )
            )
            allowlist.pop("_test_metadata", None)
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                gug218_allowlist=allowlist,
                evaluation_at=evaluation_at,
            )
        elif (
            schema_path.name
            in {
                "platform-authority-lambda-invocation-guard-receipt.v1.schema.json",
                "platform-authority-lambda-invocation-guard-receipt.v2.schema.json",
            }
            and fixture_clean.get("status")
            == "PREFLIGHT_PASSED_REVIEW_REQUIRED"
        ):
            gug218_valid_dir = fixture_path.parent.parent / "valid"
            version = fixture_clean.get("schema_version", "1")
            allowlist = load_json(
                gug218_valid_dir
                / (
                    "platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
                    if version == "1"
                    else "platform-authority-lambda-invocation-allowlist-v2-single-operator-synthetic.json"
                )
            )
            inventory = load_json(
                gug218_valid_dir
                / (
                    "platform-authority-lambda-invocation-inventory-v1-synthetic.json"
                    if version == "1"
                    else "platform-authority-lambda-invocation-inventory-v2-single-operator-synthetic.json"
                )
            )
            allowlist.pop("_test_metadata", None)
            inventory.pop("_test_metadata", None)
            semantic_errors = validate_gug218_evidence_bundle(
                allowlist=allowlist,
                inventory=inventory,
                receipt=fixture_clean,
                evaluation_at=evaluation_at,
            )
        else:
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                evaluation_at=evaluation_at,
            )
        if semantic_errors:
            return False, f"FAIL: {semantic_errors[0]}"
        return True, "PASS"
    except ValidationError as e:
        return False, f"FAIL: {e.message}"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate schemas and fixtures")
    parser.add_argument("--schemas-dir", default="schemas", help="Path to schemas directory")
    parser.add_argument("--fixtures-dir", default="fixtures", help="Path to fixtures directory")
    parser.add_argument("--filter", default="", help="Only validate schemas/fixtures matching this prefix")
    args = parser.parse_args()

    schemas_dir = Path(args.schemas_dir)
    fixtures_dir = Path(args.fixtures_dir)
    name_filter = args.filter

    if not HAS_JSONSCHEMA:
        print("WARNING: jsonschema not installed. Performing JSON syntax check only.")
        # Fallback: just check JSON syntax
        errors = 0
        for json_dir in [schemas_dir, fixtures_dir / "valid", fixtures_dir / "invalid"]:
            if not json_dir.exists():
                continue
            for f in sorted(json_dir.glob("*.json")):
                try:
                    load_json(f)
                    print(f"  JSON OK: {f.name}")
                except json.JSONDecodeError as e:
                    print(f"  JSON FAIL: {f.name} — {e}")
                    errors += 1
        sys.exit(1 if errors > 0 else 0)

    # Validate schemas themselves against metaschema
    print("=== Validating schema files against JSON Schema Draft 2020-12 ===")
    schema_errors = 0
    for schema_file in sorted(schemas_dir.glob("*.json")):
        if name_filter and name_filter not in schema_file.stem:
            continue
        try:
            schema = load_json(schema_file)
            Draft202012Validator.check_schema(schema)
            print(f"  Schema OK: {schema_file.name}")
        except Exception as e:
            print(f"  Schema FAIL: {schema_file.name} — {e}")
            schema_errors += 1

    # Validate valid fixtures (must pass)
    print("\n=== Validating valid fixtures (must PASS) ===")
    valid_errors = 0
    valid_dir = fixtures_dir / "valid"
    if valid_dir.exists():
        for fixture_file in sorted(valid_dir.glob("*.json")):
            if name_filter and name_filter not in fixture_file.stem:
                continue
            schema_path = find_schema_for_fixture(fixture_file.stem, schemas_dir)
            if schema_path is None:
                print(f"  SKIP: {fixture_file.name} — no matching schema found")
                continue
            passed, message = validate_fixture(fixture_file, schema_path)
            if passed:
                print(f"  PASS: {fixture_file.name} (against {schema_path.name})")
            else:
                print(f"  FAIL: {fixture_file.name} — {message}")
                valid_errors += 1

    # Validate invalid fixtures (must fail)
    print("\n=== Validating invalid fixtures (must FAIL) ===")
    invalid_errors = 0
    invalid_dir = fixtures_dir / "invalid"
    if invalid_dir.exists():
        for fixture_file in sorted(invalid_dir.glob("*.json")):
            if name_filter and name_filter not in fixture_file.stem:
                continue
            schema_path = find_schema_for_fixture(fixture_file.stem, schemas_dir)
            if schema_path is None:
                print(f"  SKIP: {fixture_file.name} — no matching schema found")
                continue
            passed, message = validate_fixture(fixture_file, schema_path)
            if not passed:
                print(f"  EXPECTED FAIL: {fixture_file.name} — {message}")
            else:
                print(f"  UNEXPECTED PASS: {fixture_file.name} — should have failed")
                invalid_errors += 1

    # Summary
    total_errors = schema_errors + valid_errors + invalid_errors
    print(f"\n=== Results: {total_errors} errors ===")
    if schema_errors:
        print(f"  Schema errors: {schema_errors}")
    if valid_errors:
        print(f"  Valid fixture errors: {valid_errors}")
    if invalid_errors:
        print(f"  Invalid fixture errors: {invalid_errors}")

    sys.exit(1 if total_errors > 0 else 0)


if __name__ == "__main__":
    main()
