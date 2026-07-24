#!/usr/bin/env python3
"""Schema validation tool for Scanalyze Deployment Platform.

Validates JSON fixtures against their corresponding JSON Schemas.
Valid fixtures must pass. Invalid fixtures must fail with the documented error.
"""

import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import jsonschema
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def load_json(path: Path) -> dict:
    """Load and parse a JSON file."""
    with open(path) as f:
        return json.load(f)


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
        "platform-authority-bootstrap-approval": "platform-authority-bootstrap-approval.v{version}.schema.json",
        "platform-authority-bootstrap-plan": "platform-authority-bootstrap-plan.v{version}.schema.json",
        "platform-authority-bootstrap-verification": "platform-authority-bootstrap-verification.v{version}.schema.json",
        "platform-authority-change-set-retirement-ledger": (
            "platform-authority-change-set-retirement-ledger.v{version}.schema.json"
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
    if state not in {"CLASSIFIED", "APPROVED", "ATTEMPTED", "RETIRED_RECONCILED"}:
        errors.append("ledger must preserve one of the four durable states")
    if (
        instance.get("classifier_identity_store_user_id_digest")
        == instance.get("approver_identity_store_user_id_digest")
    ):
        errors.append("ledger requires distinct immutable Identity Store users")
    if instance.get("identity_separation") != "VERIFIED_DISTINCT_IDENTITYSTORE_USERS":
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
    if instance.get("schema_version") == "2":
        identity_binding_fields += (
            "classifier_proof_policy_sha256",
            "approver_proof_policy_sha256",
            "identity_center_application_actor_policy_sha256",
        )
    identity_binding = {
        field: instance.get(field) for field in identity_binding_fields
    }
    if instance.get("identity_binding_digest") != _gug215_canonical_digest(
        identity_binding
    ):
        errors.append("identity_binding_digest must cover every immutable identity binding")

    ordered_fields = ["classified_at"]
    if state in {"APPROVED", "ATTEMPTED", "RETIRED_RECONCILED"}:
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
    if instance.get("schema_version") == "2":
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
    if (
        isinstance(classifier, str)
        and isinstance(approver, str)
        and classifier.lower() == approver.lower()
    ):
        errors.append("identity-context PEP requires two distinct UserIds")

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
    if instance.get("binding_digest") != _gug215_canonical_digest(digest_input):
        errors.append("binding_digest must cover every immutable PEP binding")
    return errors


def _validate_gug217_proof_receipt(instance: dict) -> list[str]:
    errors = _validate_gug216_receipt(instance)
    if instance.get("expected_user_id_digest") == instance.get("peer_user_id_digest"):
        errors.append("proof receipt requires distinct expected and peer users")
    if instance.get("proof_role_arn_digest") == instance.get("proof_session_arn_digest"):
        errors.append("proof role and proof session digests must be distinct")
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


def _gug218_expected_authority_edges() -> frozenset[tuple[str, ...]]:
    expected: set[tuple[str, ...]] = set()
    aliases = (
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
                "classifier",
                "CLASSIFIER_INVOKER_ROLE",
                "sts:AssumeRole",
                "EXACT_PERMISSION_SET_TRUST",
            ),
            (
                "TRUST",
                "IAM_ROLE_TRUST_POLICY",
                "independent_approver",
                "APPROVER_INVOKER_ROLE",
                "sts:AssumeRole",
                "EXACT_PERMISSION_SET_TRUST",
            ),
        }
    )
    return frozenset(expected)


GUG218_EXPECTED_AUTHORITY_EDGES = _gug218_expected_authority_edges()


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
    if duty == "classifier":
        suffix = "CLASSIFIER"
    elif duty == "independent_approver":
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
    if len(edge_list) != 14 or edge_tuples != GUG218_EXPECTED_AUTHORITY_EDGES:
        errors.append("allowlist must contain the exact fourteen reviewed authority edges")

    forbidden = instance.get("forbidden_authority_classes")
    if not isinstance(forbidden, list) or set(forbidden) != GUG218_FORBIDDEN_AUTHORITY_CLASSES:
        errors.append("allowlist must enumerate every fail-closed authority class")

    classifier_principals = {
        edge.get("principal_digest")
        for edge in edge_list
        if isinstance(edge, dict)
        and edge.get("authority_class") == "INVOCATION"
        and edge.get("duty") == "classifier"
    }
    approver_principals = {
        edge.get("principal_digest")
        for edge in edge_list
        if isinstance(edge, dict)
        and edge.get("authority_class") == "INVOCATION"
        and edge.get("duty") == "independent_approver"
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
    if trust_targets.get("classifier") != classifier_principal:
        errors.append("classifier trust must target the reviewed invoker role")
    if trust_targets.get("independent_approver") != approver_principal:
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
    instance: dict, *, expected_collector_contract: dict | None = None
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
    allowlist_context_valid = isinstance(expected_allowlist, dict)
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
    authority_exact = (
        allowlist_context_valid
        and len(expected_edges) == 14
        and expected_tuples == GUG218_EXPECTED_AUTHORITY_EDGES
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
            expected_next = "INDEPENDENT_REVIEW_AND_FRESH_DEPLOYMENT_AUTHORIZATION"
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


def validate_semantics(
    instance: dict,
    schema_path: Path,
    *,
    gug218_allowlist: dict | None = None,
    gug218_inventory: dict | None = None,
    gug219_collector_contract: dict | None = None,
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

    if schema_name in {
        "platform-authority-change-set-retirement-ledger.v1.schema.json",
        "platform-authority-change-set-retirement-ledger.v2.schema.json",
    }:
        errors.extend(_validate_gug215_ledger(instance))

    if schema_name == "platform-authority-identity-enhanced-binding.v1.schema.json":
        errors.extend(_validate_gug216_binding(instance))

    if schema_name in {
        "platform-authority-identity-context-compatibility-receipt.v1.schema.json",
        "platform-authority-identity-enhanced-session-receipt.v1.schema.json",
        "platform-authority-identity-context-pep-compatibility-receipt.v1.schema.json",
    }:
        errors.extend(_validate_gug216_receipt(instance))

    if schema_name == "platform-authority-identity-context-pep-binding.v1.schema.json":
        errors.extend(_validate_gug217_binding(instance))

    if schema_name == "platform-authority-identity-context-proof-receipt.v1.schema.json":
        errors.extend(_validate_gug217_proof_receipt(instance))

    if schema_name == "platform-authority-lambda-invocation-allowlist.v1.schema.json":
        errors.extend(_validate_gug218_allowlist(instance))

    if schema_name == "platform-authority-lambda-invocation-collector-contract.v1.schema.json":
        errors.extend(_validate_gug219_collector_contract(instance))

    if schema_name == "platform-authority-lambda-invocation-allowlist-release.v1.schema.json":
        errors.extend(
            _validate_gug219_release(
                instance,
                expected_collector_contract=gug219_collector_contract,
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

    if schema_name == "platform-authority-lambda-invocation-inventory.v1.schema.json":
        errors.extend(
            _validate_gug218_inventory(
                instance,
                expected_allowlist=gug218_allowlist,
                evaluation_at=evaluation_at,
            )
        )

    if schema_name == "platform-authority-lambda-invocation-guard-receipt.v1.schema.json":
        errors.extend(
            _validate_gug218_guard_receipt(
                instance,
                expected_allowlist=gug218_allowlist,
                expected_inventory=gug218_inventory,
                evaluation_at=evaluation_at,
            )
        )

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
    records = (
        (
            "allowlist",
            allowlist,
            "platform-authority-lambda-invocation-allowlist.v1.schema.json",
        ),
        (
            "inventory",
            inventory,
            "platform-authority-lambda-invocation-inventory.v1.schema.json",
        ),
        (
            "receipt",
            receipt,
            "platform-authority-lambda-invocation-guard-receipt.v1.schema.json",
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
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        validator.validate(fixture_clean)
        metadata = fixture.get("_test_metadata")
        evaluation_at = _gug215_timestamp(
            metadata.get("trusted_evaluation_at")
            if isinstance(metadata, dict)
            else None
        )
        if (
            evaluation_at is None
            and fixture_path.name
            in {
                "platform-authority-lambda-invocation-inventory-v1-synthetic.json",
                "platform-authority-lambda-invocation-guard-receipt-v1-synthetic.json",
            }
        ):
            evaluation_at = datetime(2026, 7, 20, 10, 2, tzinfo=UTC)
        if (
            schema_path.name
            == "platform-authority-lambda-invocation-allowlist-release.v1.schema.json"
        ):
            valid_dir = fixture_path.parent.parent / "valid"
            collector = load_json(
                valid_dir
                / "platform-authority-lambda-invocation-collector-contract-v1-synthetic.json"
            )
            collector.pop("_test_metadata", None)
            semantic_errors = validate_semantics(
                fixture_clean,
                schema_path,
                gug219_collector_contract=collector,
                evaluation_at=evaluation_at,
            )
        elif (
            schema_path.name
            == "platform-authority-lambda-invocation-inventory.v1.schema.json"
            and fixture_clean.get("status") == "REVIEW_SAFE_REPORT_ONLY"
        ):
            gug218_valid_dir = fixture_path.parent.parent / "valid"
            allowlist = load_json(
                gug218_valid_dir
                / "platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
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
            == "platform-authority-lambda-invocation-guard-receipt.v1.schema.json"
            and fixture_clean.get("status")
            == "PREFLIGHT_PASSED_REVIEW_REQUIRED"
        ):
            gug218_valid_dir = fixture_path.parent.parent / "valid"
            allowlist = load_json(
                gug218_valid_dir
                / "platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
            )
            inventory = load_json(
                gug218_valid_dir
                / "platform-authority-lambda-invocation-inventory-v1-synthetic.json"
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
