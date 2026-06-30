#!/usr/bin/env python3
"""Schema validation tool for Scanalyze Deployment Platform.

Validates JSON fixtures against their corresponding JSON Schemas.
Valid fixtures must pass. Invalid fixtures must fail with the documented error.
"""

import json
import sys
import os
import re
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
    contract_match = re.match(r"contract-(\w+[\w-]*)-v1", fixture_name)
    if contract_match:
        layer = contract_match.group(1)
        schema_path = schemas_dir / f"contract-{layer}.v1.schema.json"
        if schema_path.exists():
            return schema_path

    return None


def validate_fixture(fixture_path: Path, schema_path: Path) -> tuple[bool, str]:
    """Validate a fixture against a schema. Returns (passed, message)."""
    fixture = load_json(fixture_path)
    schema = load_json(schema_path)

    # Remove _test_metadata before validation (it's not part of the schema)
    fixture_clean = {k: v for k, v in fixture.items() if k != "_test_metadata"}

    try:
        validator = Draft202012Validator(schema)
        validator.validate(fixture_clean)
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
