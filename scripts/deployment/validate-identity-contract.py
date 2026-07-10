#!/usr/bin/env python3
"""Validate a Scanalyze identity contract against the canonical schema.

Usage:
    python scripts/deployment/validate-identity-contract.py <contract.yaml>

Exit codes:
    0  Valid contract
    1  Invalid contract
    2  Usage error or missing dependency
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "identity-contract.schema.json"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: validate-identity-contract.py <contract.yaml>", file=sys.stderr)
        return 2

    contract_path = Path(sys.argv[1])
    if not contract_path.exists():
        print(f"ERROR: contract not found: {contract_path}", file=sys.stderr)
        return 2

    try:
        import yaml
    except ImportError:
        print("BLOCKED: PyYAML not installed.", file=sys.stderr)
        return 2

    try:
        import jsonschema
    except ImportError:
        print("BLOCKED: jsonschema not installed.", file=sys.stderr)
        return 2

    with open(SCHEMA_PATH) as f:
        schema = json.load(f)

    with open(contract_path) as f:
        contract = yaml.safe_load(f)

    if not isinstance(contract, dict):
        print("ERROR: contract must be a YAML mapping", file=sys.stderr)
        return 1

    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(contract), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        errors.append(f"  {path}: {error.message}")

    # Fail-closed checks
    restrictions = contract.get("restrictions", {})
    if restrictions.get("cross_account_access") is True:
        errors.append("  restrictions.cross_account_access: must be false")
    if restrictions.get("cross_deployment_access") is True:
        errors.append("  restrictions.cross_deployment_access: must be false")
    if restrictions.get("password_in_docs") is True:
        errors.append("  restrictions.password_in_docs: must be false")

    auth = contract.get("authorization", {})
    if auth.get("customer_id_source") == "payload":
        errors.append("  authorization.customer_id_source: 'payload' is forbidden — untrusted source")

    if errors:
        print(f"FAIL: {contract_path} has {len(errors)} error(s):")
        for e in errors:
            print(e)
        return 1

    print(f"PASS: {contract_path} is a valid identity contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
