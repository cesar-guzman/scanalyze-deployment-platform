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
from datetime import datetime
from pathlib import Path

try:
    import jsonschema
    from jsonschema import Draft202012Validator, ValidationError
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
    return errors


def validate_semantics(instance: dict, schema_path: Path) -> list[str]:
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

    if schema_name == "platform-authority-change-set-retirement-ledger.v1.schema.json":
        errors.extend(_validate_gug215_ledger(instance))

    return errors


def validate_fixture(fixture_path: Path, schema_path: Path) -> tuple[bool, str]:
    """Validate a fixture against a schema. Returns (passed, message)."""
    fixture = load_json(fixture_path)
    schema = load_json(schema_path)

    # Remove _test_metadata before validation (it's not part of the schema)
    fixture_clean = {k: v for k, v in fixture.items() if k != "_test_metadata"}

    try:
        validator = Draft202012Validator(schema)
        validator.validate(fixture_clean)
        semantic_errors = validate_semantics(fixture_clean, schema_path)
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
