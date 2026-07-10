#!/usr/bin/env python3
"""P0-002: One-shot task definition migration script.

Reads the active ECS task definition, adds SCANALYZE_DEPLOYMENT_CUSTOMER_ID
to the target container's environment, removes deprecated ENFORCE_AUTH_HEADER
if present, and registers a new revision. Optionally updates the ECS service.

This script is idempotent — if SCANALYZE_DEPLOYMENT_CUSTOMER_ID is already
present, it skips registration.

Usage:
    python3 scripts/migrate_taskdef_p0002.py \
        --cluster "<ECS_CLUSTER>" \
        --service scanalyze-ingest-api \
        --container scanalyze-ingest-api \
        --customer-id customer-example \
        --dry-run

    # To apply (remove --dry-run):
    python3 scripts/migrate_taskdef_p0002.py \
        --cluster "<ECS_CLUSTER>" \
        --service scanalyze-ingest-api \
        --container scanalyze-ingest-api \
        --customer-id customer-example

Security:
    - Does NOT print any secret values.
    - Does NOT modify auth mode or Cognito config.
    - Only adds/removes specific env vars.
    - Validates the result with validate_deploy_auth_config.py before applying.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_aws(args: list[str]) -> dict:
    """Run an AWS CLI command and return parsed JSON output."""
    cmd = ["aws"] + args + ["--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[P0-002] AWS CLI error: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def get_active_task_definition(cluster: str, service: str, region: str) -> dict:
    """Get the active task definition for an ECS service."""
    svc = run_aws([
        "ecs", "describe-services",
        "--cluster", cluster,
        "--services", service,
        "--region", region,
    ])
    task_def_arn = svc["services"][0]["taskDefinition"]
    print(f"[P0-002] Active task definition: {task_def_arn}")

    td = run_aws([
        "ecs", "describe-task-definition",
        "--task-definition", task_def_arn,
        "--region", region,
    ])
    return td["taskDefinition"]


def migrate_container_env(
    container: dict,
    customer_id: str,
) -> tuple[dict, list[str]]:
    """Add SCANALYZE_DEPLOYMENT_CUSTOMER_ID and remove deprecated vars.

    Returns (modified_container, list_of_changes).
    """
    env = container.get("environment", [])
    changes: list[str] = []

    # Check if already present
    existing = {e["name"]: e["value"] for e in env}

    if "SCANALYZE_DEPLOYMENT_CUSTOMER_ID" in existing:
        print(f"[P0-002] SCANALYZE_DEPLOYMENT_CUSTOMER_ID already present (not printing value)")
        if existing["SCANALYZE_DEPLOYMENT_CUSTOMER_ID"] == customer_id:
            print("[P0-002] Value matches expected customer_id ✓")
        else:
            print("[P0-002] WARNING: Value does NOT match expected customer_id!")
            print(f"[P0-002]   Expected length: {len(customer_id)}, Actual length: {len(existing['SCANALYZE_DEPLOYMENT_CUSTOMER_ID'])}")
            changes.append("SCANALYZE_DEPLOYMENT_CUSTOMER_ID value updated")
            env = [e for e in env if e["name"] != "SCANALYZE_DEPLOYMENT_CUSTOMER_ID"]
            env.append({"name": "SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "value": customer_id})
    else:
        env.append({"name": "SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "value": customer_id})
        changes.append("SCANALYZE_DEPLOYMENT_CUSTOMER_ID added")

    # Remove deprecated ENFORCE_AUTH_HEADER if present
    before_len = len(env)
    env = [e for e in env if e["name"] != "ENFORCE_AUTH_HEADER"]
    if len(env) < before_len:
        changes.append("ENFORCE_AUTH_HEADER removed (deprecated)")

    container["environment"] = env
    return container, changes


def build_register_input(task_def: dict) -> dict:
    """Build the input for register-task-definition from an existing task def.

    Strips read-only fields that can't be passed to register-task-definition.
    """
    # Fields that are read-only / not accepted by register-task-definition
    read_only_fields = {
        "taskDefinitionArn", "revision", "status",
        "requiresAttributes", "compatibilities",
        "registeredAt", "registeredBy", "deregisteredAt",
    }

    register_input = {
        k: v for k, v in task_def.items()
        if k not in read_only_fields
    }

    return register_input


def validate_task_def(task_def_json_path: str, container_name: str) -> bool:
    """Run validate_deploy_auth_config.py against the task definition."""
    script_path = Path(__file__).parent / "validate_deploy_auth_config.py"
    if not script_path.exists():
        print(f"[P0-002] WARNING: Validation script not found at {script_path}")
        return False

    result = subprocess.run(
        [
            sys.executable, str(script_path),
            "--taskdef-json", task_def_json_path,
            "--container-name", container_name,
        ],
        capture_output=True,
        text=True,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="P0-002: Migrate ECS task definition to include SCANALYZE_DEPLOYMENT_CUSTOMER_ID"
    )
    parser.add_argument("--cluster", required=True, help="ECS cluster name")
    parser.add_argument("--service", required=True, help="ECS service name")
    parser.add_argument("--container", required=True, help="Container name in task definition")
    parser.add_argument("--customer-id", required=True, help="Expected customer identity (e.g. customer-example)")
    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying")
    parser.add_argument("--skip-service-update", action="store_true",
                        help="Register new task def but don't update ECS service")

    args = parser.parse_args()

    print(f"[P0-002] Task Definition Migration Script")
    print(f"[P0-002] Cluster: {args.cluster}")
    print(f"[P0-002] Service: {args.service}")
    print(f"[P0-002] Container: {args.container}")
    print(f"[P0-002] Dry run: {args.dry_run}")
    print()

    # 1. Get active task definition
    task_def = get_active_task_definition(args.cluster, args.service, args.region)

    # 2. Find target container
    target_idx = None
    for i, c in enumerate(task_def["containerDefinitions"]):
        if c["name"] == args.container:
            target_idx = i
            break

    if target_idx is None:
        print(f"[P0-002] FATAL: Container '{args.container}' not found in task definition")
        sys.exit(1)

    # 3. Migrate env vars
    modified_container, changes = migrate_container_env(
        task_def["containerDefinitions"][target_idx],
        args.customer_id,
    )
    task_def["containerDefinitions"][target_idx] = modified_container

    if not changes:
        print("[P0-002] No changes needed — task definition already has SCANALYZE_DEPLOYMENT_CUSTOMER_ID ✓")
        sys.exit(0)

    print(f"[P0-002] Changes: {', '.join(changes)}")

    # 4. Validate the modified task definition
    register_input = build_register_input(task_def)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        # Wrap in taskDefinition key for the validator
        json.dump({"taskDefinition": register_input}, f, indent=2)
        temp_path = f.name

    print(f"\n[P0-002] Validating modified task definition...")
    if not validate_task_def(temp_path, args.container):
        print(f"\n[P0-002] FATAL: Modified task definition failed validation!")
        print(f"[P0-002] Temp file preserved for inspection: {temp_path}")
        sys.exit(1)

    print(f"\n[P0-002] Validation passed ✓")

    if args.dry_run:
        print(f"\n[P0-002] DRY RUN — no changes applied.")
        print(f"[P0-002] Would register new task definition revision with:")
        for change in changes:
            print(f"[P0-002]   - {change}")
        print(f"[P0-002] Review: {temp_path}")
        sys.exit(0)

    # 5. Register new task definition
    print(f"\n[P0-002] Registering new task definition revision...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(register_input, f)
        register_path = f.name

    result = subprocess.run(
        [
            "aws", "ecs", "register-task-definition",
            "--cli-input-json", f"file://{register_path}",
            "--region", args.region,
            "--output", "json",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"[P0-002] FATAL: Failed to register task definition: {result.stderr.strip()}")
        sys.exit(1)

    new_td = json.loads(result.stdout)
    new_arn = new_td["taskDefinition"]["taskDefinitionArn"]
    print(f"[P0-002] ✓ New task definition registered: {new_arn}")

    # 6. Update ECS service (optional)
    if args.skip_service_update:
        print(f"[P0-002] Skipping service update (--skip-service-update)")
        print(f"[P0-002] Next pipeline deploy will use the new task definition base.")
    else:
        print(f"[P0-002] Updating ECS service to use new task definition...")
        result = subprocess.run(
            [
                "aws", "ecs", "update-service",
                "--cluster", args.cluster,
                "--service", args.service,
                "--task-definition", new_arn,
                "--region", args.region,
                "--output", "json",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"[P0-002] FATAL: Failed to update service: {result.stderr.strip()}")
            sys.exit(1)

        print(f"[P0-002] ✓ Service updated. ECS will roll out new tasks.")

    print(f"\n[P0-002] Migration complete.")


if __name__ == "__main__":
    main()
