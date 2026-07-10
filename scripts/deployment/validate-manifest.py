#!/usr/bin/env python3
"""Validate a Scanalyze deployment manifest against the canonical schema.

Usage:
    python scripts/deployment/validate-manifest.py <manifest.yaml>
    python scripts/deployment/validate-manifest.py examples/deployments/synthetic-nonprod.yaml

Exit codes:
    0  Valid manifest
    1  Invalid manifest
    2  Usage error or missing dependency
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "deployment-manifest.schema.json"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: validate-manifest.py <manifest.yaml>", file=sys.stderr)
        return 2

    manifest_path = Path(sys.argv[1])
    if not manifest_path.exists():
        print(f"ERROR: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    # Import dependencies with clear error messages
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        print("BLOCKED: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        return 2

    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError:
        print("BLOCKED: jsonschema not installed. Run: pip install jsonschema", file=sys.stderr)
        return 2

    # Load schema
    if not SCHEMA_PATH.exists():
        print(f"ERROR: schema not found: {SCHEMA_PATH}", file=sys.stderr)
        return 2

    with open(SCHEMA_PATH) as f:
        schema = json.load(f)

    # Load manifest
    with open(manifest_path) as f:
        manifest = yaml.safe_load(f)

    if not isinstance(manifest, dict):
        print("ERROR: manifest must be a YAML mapping", file=sys.stderr)
        return 1

    # Validate against schema
    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(manifest), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"  {path}: {error.message}")

    # Additional fail-closed checks beyond schema
    account_id = manifest.get("aws_account_id", "")
    if account_id == "000000000000":
        errors.append("  aws_account_id: must not be 000000000000")

    base_image = manifest.get("base_image_uri", "")
    if base_image and ":latest" in base_image and "@sha256:" not in base_image:
        errors.append("  base_image_uri: 'latest' tag is forbidden; use digest")

    environment = manifest.get("environment", "")
    deployment_id = manifest.get("deployment_id", "")
    if not deployment_id:
        errors.append("  deployment_id: required field is missing")

    if not environment:
        errors.append("  environment: required field is missing")

    # Verify ECR prefix belongs to deployment_id
    ecr = manifest.get("ecr", {})
    ecr_prefix = ecr.get("prefix", "") if isinstance(ecr, dict) else ""
    if ecr_prefix and deployment_id:
        sanitized_dep = deployment_id.lower().replace("_", "-")
        if not ecr_prefix.startswith(sanitized_dep):
            errors.append(
                f"  ecr.prefix: must start with sanitized deployment_id ({sanitized_dep})"
            )

    # Verify OIDC role ARN account matches
    github = manifest.get("github", {})
    oidc_arn = github.get("oidc_role_arn", "") if isinstance(github, dict) else ""
    if oidc_arn and account_id:
        if f"::{account_id}:" not in oidc_arn and f":{account_id}:" not in oidc_arn:
            errors.append(
                "  github.oidc_role_arn: account ID in ARN does not match aws_account_id"
            )

    if errors:
        print(f"FAIL: {manifest_path} has {len(errors)} validation error(s):")
        for e in errors:
            print(e)
        return 1

    print(f"PASS: {manifest_path} is a valid deployment manifest")
    print(f"  customer_id:    {manifest.get('customer_id')}")
    print(f"  deployment_id:  {deployment_id}")
    print(f"  environment:    {environment}")
    print(f"  aws_account_id: {account_id}")
    print(f"  aws_region:     {manifest.get('aws_region')}")
    print(f"  domains:        {manifest.get('enabled_domains')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
