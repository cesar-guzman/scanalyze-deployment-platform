#!/usr/bin/env python3
"""P0-002: Pre-deploy auth config validation script.

Validates that an ECS task definition JSON contains the required auth
environment variables before deploying to a customer deployment.

Usage:
    # Validate against the active task definition:
    aws ecs describe-task-definition --task-definition <arn> --output json > /tmp/scanalyze-taskdef.json
    python scripts/validate_deploy_auth_config.py --taskdef-json /tmp/scanalyze-taskdef.json

    # Validate against a rendered task definition artifact:
    python scripts/validate_deploy_auth_config.py --taskdef-json rendered-taskdef.json

    # Specify container name (default: scanalyze-ingest-api):
    python scripts/validate_deploy_auth_config.py --taskdef-json taskdef.json --container-name scanalyze-ingest-api

Rules enforced:
    - AUTH_MODE must be 'cognito_jwt'
    - SCANALYZE_DEPLOYMENT_CUSTOMER_ID must be present and non-empty (env or secret)
    - TENANT_CLAIM_NAME must be 'custom:customerId'
    - ENFORCE_AUTH_HEADER must NOT be present (any value)
    - COGNITO_USER_POOL_ID must be present (env or secret)
    - COGNITO_ALLOWED_CLIENT_IDS must be present (env or secret)

Security notes:
    - This script NEVER prints secret values.
    - It only checks presence by name, not by value, for secrets.
    - SCANALYZE_DEPLOYMENT_CUSTOMER_ID is treated as env var (non-secret).
    - Exit code 0 = all checks passed. Exit code 1 = validation failed.
"""
from __future__ import annotations

import argparse
import json
import sys


def _find_container(taskdef: dict, container_name: str) -> dict | None:
    """Find a container definition by name."""
    # Handle both wrapped (aws ecs describe-task-definition) and unwrapped formats
    if "taskDefinition" in taskdef:
        containers = taskdef["taskDefinition"].get("containerDefinitions", [])
    else:
        containers = taskdef.get("containerDefinitions", [])

    for c in containers:
        if c.get("name") == container_name:
            return c
    return None


def _get_env_var(container: dict, name: str) -> str | None:
    """Get an environment variable value from container definition."""
    for e in container.get("environment", []):
        if e.get("name") == name:
            return e.get("value")
    return None


def _has_env_var(container: dict, name: str) -> bool:
    """Check if an environment variable exists (any value)."""
    return any(e.get("name") == name for e in container.get("environment", []))


def _has_secret(container: dict, name: str) -> bool:
    """Check if a secret is referenced by name."""
    return any(s.get("name") == name for s in container.get("secrets", []))


def _has_env_or_secret(container: dict, name: str) -> bool:
    """Check if a variable exists in either environment or secrets."""
    return _has_env_var(container, name) or _has_secret(container, name)


def validate(taskdef: dict, container_name: str) -> list[str]:
    """Validate auth config in task definition. Returns list of errors."""
    errors: list[str] = []

    container = _find_container(taskdef, container_name)
    if container is None:
        errors.append(f"Container '{container_name}' not found in task definition")
        return errors

    # 1. AUTH_MODE must be cognito_jwt
    auth_mode = _get_env_var(container, "AUTH_MODE")
    if auth_mode != "cognito_jwt":
        errors.append(f"AUTH_MODE='{auth_mode}' (expected 'cognito_jwt')")
    else:
        print("[P0-002] ✓ AUTH_MODE=cognito_jwt")

    # 2. SCANALYZE_DEPLOYMENT_CUSTOMER_ID must be present and non-empty
    deployment_customer = _get_env_var(container, "SCANALYZE_DEPLOYMENT_CUSTOMER_ID")
    if deployment_customer is None:
        # Also check secrets (unlikely but possible)
        if _has_secret(container, "SCANALYZE_DEPLOYMENT_CUSTOMER_ID"):
            print("[P0-002] ✓ SCANALYZE_DEPLOYMENT_CUSTOMER_ID present (secret)")
        else:
            errors.append(
                "SCANALYZE_DEPLOYMENT_CUSTOMER_ID is missing from task definition. "
                "Add it as an environment variable with the expected customer identity."
            )
    elif not deployment_customer.strip():
        errors.append("SCANALYZE_DEPLOYMENT_CUSTOMER_ID is empty")
    else:
        print("[P0-002] ✓ SCANALYZE_DEPLOYMENT_CUSTOMER_ID present (env)")

    # 3. TENANT_CLAIM_NAME must be custom:customerId
    tenant_claim = _get_env_var(container, "TENANT_CLAIM_NAME")
    if tenant_claim is not None and tenant_claim != "custom:customerId":
        errors.append(f"TENANT_CLAIM_NAME='{tenant_claim}' (expected 'custom:customerId')")
    elif tenant_claim == "custom:customerId":
        print("[P0-002] ✓ TENANT_CLAIM_NAME=custom:customerId")
    else:
        # Not set = uses default, which is correct
        print("[P0-002] ✓ TENANT_CLAIM_NAME not set (default=custom:customerId)")

    # 4. ENFORCE_AUTH_HEADER must NOT be present
    if _has_env_var(container, "ENFORCE_AUTH_HEADER"):
        errors.append(
            "ENFORCE_AUTH_HEADER is present in task definition. "
            "This deprecated variable must be removed."
        )
    elif _has_secret(container, "ENFORCE_AUTH_HEADER"):
        errors.append(
            "ENFORCE_AUTH_HEADER is present as a secret. "
            "This deprecated variable must be removed."
        )
    else:
        print("[P0-002] ✓ ENFORCE_AUTH_HEADER absent (deprecated, correctly removed)")

    # 5. COGNITO_USER_POOL_ID must be present (env or secret)
    if _has_env_or_secret(container, "COGNITO_USER_POOL_ID"):
        print("[P0-002] ✓ COGNITO_USER_POOL_ID present")
    else:
        errors.append("COGNITO_USER_POOL_ID missing from task definition (env or secret)")

    # 6. COGNITO_ALLOWED_CLIENT_IDS must be present (env or secret)
    if _has_env_or_secret(container, "COGNITO_ALLOWED_CLIENT_IDS"):
        print("[P0-002] ✓ COGNITO_ALLOWED_CLIENT_IDS present")
    else:
        errors.append("COGNITO_ALLOWED_CLIENT_IDS missing from task definition (env or secret)")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="P0-002: Validate ECS task definition auth configuration.",
        epilog="Exit code 0 = passed. Exit code 1 = failed.",
    )
    parser.add_argument(
        "--taskdef-json",
        required=True,
        help="Path to the task definition JSON file (from aws ecs describe-task-definition or rendered artifact).",
    )
    parser.add_argument(
        "--container-name",
        default="scanalyze-ingest-api",
        help="Container name to validate (default: scanalyze-ingest-api).",
    )
    args = parser.parse_args()

    print(f"[P0-002] Validating task definition: {args.taskdef_json}")
    print(f"[P0-002] Container: {args.container_name}")

    try:
        with open(args.taskdef_json) as f:
            taskdef = json.load(f)
    except FileNotFoundError:
        print(f"[P0-002] FATAL: File not found: {args.taskdef_json}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[P0-002] FATAL: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    errors = validate(taskdef, args.container_name)

    if errors:
        print()
        print("[P0-002] ============================================")
        print("[P0-002] AUTH CONFIG VALIDATION FAILED")
        print("[P0-002] ============================================")
        for e in errors:
            print(f"[P0-002] FATAL: {e}")
        print("[P0-002] ============================================")
        print("[P0-002] Do NOT deploy without fixing auth config.")
        print("[P0-002] ============================================")
        sys.exit(1)
    else:
        print()
        print("[P0-002] All auth config checks passed ✓")


if __name__ == "__main__":
    main()
