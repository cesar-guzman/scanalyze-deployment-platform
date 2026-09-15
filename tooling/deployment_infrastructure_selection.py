"""Offline verifier and variable emitter for infrastructure-selection/v1 documents.

Validates a closed infrastructure selection against the deployment target tuple,
verifies ARN/ID syntax against the target partition/region/account, checks the
target layer allowlist, and emits only the corresponding Terraform root variables.

No AWS calls, no network activity, no state reads. ARN syntax validation does
not prove resource existence, ownership, or correct configuration. Live
verification requires SSO/STS access and separate confirmation.

GUG-396: Production infrastructure selection transport.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import jsonschema


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "deployment-infrastructure-selection.v1.schema.json"

# Layer → variable name mapping: each selection emits exactly one root variable.
SELECTION_VARIABLE_MAP: dict[str, dict[str, str]] = {
    "internal_certificate_arn": {
        "target_layer": "platform",
        "variable_name": "internal_certificate_arn",
        "value_field": "arn",
    },
    "api_access_log_group_arn": {
        "target_layer": "edge-identity",
        "variable_name": "api_access_log_group_arn",
        "value_field": "arn",
    },
    "route53_zone_id": {
        "target_layer": "edge",
        "variable_name": "route53_zone_id",
        "value_field": "zone_id",
    },
}

# Partitions by region prefix
_PARTITION_PREFIXES = {
    "cn-": "aws-cn",
    "us-gov-": "aws-us-gov",
}


def _require(condition: bool, message: str) -> None:
    """Fail-closed assertion."""
    if not condition:
        raise ValueError(message)


def _partition_for_region(region: str) -> str:
    """Derive the AWS partition from the region."""
    for prefix, partition in _PARTITION_PREFIXES.items():
        if region.startswith(prefix):
            return partition
    return "aws"


def _canonical_bytes(value: object) -> bytes:
    """Deterministic JSON serialization for digest computation."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _compute_digest(data: bytes) -> str:
    """SHA-256 digest with prefix."""
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _validate_schema(doc: dict, schema_filename: str) -> None:
    import json as _json
    schema_path = REPO_ROOT / "schemas" / schema_filename
    with open(schema_path, "r", encoding="utf-8") as file:
        schema = _json.load(file)
    try:
        import jsonschema
        jsonschema.validate(instance=doc, schema=schema)
    except jsonschema.ValidationError as e:
        raise ValueError(f"Schema validation failed against {schema_filename}: {e.message}") from e


def _load_json_strict(path: Path) -> dict:
    """Load a JSON file with strict safety checks."""
    resolved = path.resolve(strict=True)
    _require(not path.is_symlink(), f"symlink input denied: {path}")
    _require(resolved.is_file(), f"not a regular file: {path}")
    file_stat = os.stat(resolved)
    _require(stat.S_ISREG(file_stat.st_mode), f"not a regular file: {path}")
    with open(resolved, "rb") as f:
        data = json.load(f)
    _require(isinstance(data, dict), f"root must be a JSON object: {path}")
    return data


def _validate_arn_partition(arn: str, expected_partition: str, label: str) -> None:
    """Verify the ARN partition matches the deployment target."""
    parts = arn.split(":")
    _require(len(parts) >= 6, f"{label}: ARN must have at least 6 colon-separated fields")
    _require(parts[0] == "arn", f"{label}: ARN must start with 'arn'")
    _require(parts[1] == expected_partition, f"{label}: ARN partition '{parts[1]}' does not match expected '{expected_partition}'")


def _validate_arn_region(arn: str, expected_region: str, label: str) -> None:
    """Verify the ARN region matches the deployment target."""
    parts = arn.split(":")
    _require(len(parts) >= 6, f"{label}: ARN too short")
    _require(parts[3] == expected_region, f"{label}: ARN region '{parts[3]}' does not match expected '{expected_region}'")


def _validate_arn_account(arn: str, expected_account: str, label: str) -> None:
    """Verify the ARN account matches the deployment target."""
    parts = arn.split(":")
    _require(len(parts) >= 6, f"{label}: ARN too short")
    _require(parts[4] == expected_account, f"{label}: ARN account '{parts[4]}' does not match expected '{expected_account}'")


def verify_infrastructure_selection(
    selection: dict,
    *,
    expected_digest: str | None = None,
) -> dict[str, dict[str, str]]:
    """Validate an infrastructure selection document and return per-layer variable bindings.

    Args:
        selection: Parsed infrastructure-selection/v1 document.
        expected_digest: Optional independently provided digest to verify.

    Returns:
        Dict mapping layer name -> {variable_name: value}.

    Raises:
        ValueError: On any validation failure (fail-closed).
        jsonschema.ValidationError: On schema violations.
    """
    # 1. Schema validation
    schema = _load_json_strict(SCHEMA_PATH)
    jsonschema.validate(selection, schema)

    # 2. Derive partition
    region = selection["region"]
    account_id = selection["account_id"]
    partition = _partition_for_region(region)
    _require(
        selection["partition"] == partition,
        "selection partition does not match region",
    )

    # 3. Verify external digest if provided
    if expected_digest is not None:
        _require(
            "record_digest" in selection,
            "record_digest required when expected_digest is provided",
        )
        _require(
            selection["record_digest"] == expected_digest,
            f"external digest mismatch: document has '{selection.get('record_digest')}' "
            f"but expected '{expected_digest}'",
        )

    # 4. Verify self-digest if present
    if "record_digest" in selection:
        digestible = {k: v for k, v in selection.items() if k != "record_digest"}
        computed = _compute_digest(_canonical_bytes(digestible))
        _require(
            selection["record_digest"] == computed,
            f"record_digest mismatch: document contains '{selection['record_digest']}' "
            f"but computed '{computed}'",
        )

    # 5. Validate each selection
    selections = selection["selections"]
    _require(
        set(selections) == set(SELECTION_VARIABLE_MAP),
        "infrastructure selection must contain all declared resource selections",
    )
    layer_bindings: dict[str, dict[str, str]] = {}

    for sel_key, mapping in SELECTION_VARIABLE_MAP.items():
        sel = selections[sel_key]
        target_layer = mapping["target_layer"]
        variable_name = mapping["variable_name"]
        value_field = mapping["value_field"]

        # Verify target_layer
        _require(
            sel["target_layer"] == target_layer,
            f"{sel_key}: target_layer must be '{target_layer}', got '{sel.get('target_layer')}'",
        )

        value = sel[value_field]

        # ARN-based selections need partition/region/account validation
        if value_field == "arn":
            _validate_arn_partition(value, partition, sel_key)
            _validate_arn_region(value, region, sel_key)
            _validate_arn_account(value, account_id, sel_key)

            # Reject placeholder/synthetic ARNs
            _require(
                "PLACEHOLDER" not in value.upper()
                and "EXAMPLE" not in value.upper()
                and "000000000000" not in value,
                f"{sel_key}: placeholder or synthetic ARN denied",
            )

        # Zone ID validation for Route53
        if sel_key == "route53_zone_id":
            _require(
                re.fullmatch(r"Z[A-Z0-9]{1,31}", value) is not None,
                f"{sel_key}: invalid Route53 zone ID format",
            )

        # Emit binding
        if target_layer not in layer_bindings:
            layer_bindings[target_layer] = {}

        _require(
            variable_name not in layer_bindings[target_layer],
            f"{sel_key}: variable '{variable_name}' collision in layer '{target_layer}'",
        )

        layer_bindings[target_layer][variable_name] = value

    return layer_bindings


def bind_infrastructure_variables(
    selection: dict,
    expected_digest: str,
    target: dict,
    expected_target_digest: str,
    layer: str,
    release: dict,
    expected_release_digest: str,
) -> dict[str, str]:
    """Bind a verified infrastructure selection to an exact target, layer, and release.
    
    This ensures that the variables are only emitted if the selection matches an
    independently verified destination and release, proving the binding for the
    requested exact layer.
    """
    _require(selection is not None, "selection is required for binding")
    _require(expected_digest is not None, "expected_digest is required for binding")
    _require(target is not None, "target is required for binding")
    _require(expected_target_digest is not None, "expected_target_digest is required for binding")
    _require(layer is not None, "layer is required for binding")
    _require(release is not None, "release is required for binding")
    _require(expected_release_digest is not None, "expected_release_digest is required for binding")

    # 1. Verify selection syntax and get layer bindings
    layer_bindings = verify_infrastructure_selection(selection, expected_digest=expected_digest)
    _require(selection["layer"] == layer, "selection layer does not match requested layer")

    # 2. Verify identity tuple matches target
    for key in ("customer_id", "deployment_id", "account_id", "region", "environment"):
        _require(selection.get(key) == target.get(key), f"identity mismatch on {key}")

    # Verify target via schema
    _validate_schema(target, "deployment-target.v2.schema.json")
    _require(target.get("record_type") == "deployment_target", "target is not a deployment_target")
    _require(selection.get("target_digest") == expected_target_digest, "selection target_digest does not match expected_target_digest")

    # 3. Verify target digest
    digestible_target = {k: v for k, v in target.items() if k != "record_digest"}
    target_computed = _compute_digest(_canonical_bytes(digestible_target))
    _require(target_computed == expected_target_digest, "target external digest mismatch")
    _require(target.get("record_digest") == expected_target_digest, "target internal digest mismatch")

    # Verify release via schema
    _require(selection.get("release_digest") == expected_release_digest, "selection release_digest does not match expected_release_digest")
    release_schema_version = release.get("schema_version")
    projection_versions = {"release-deployment-projection.v1", "release-deployment-projection.v2"}
    _require(release_schema_version == "release.v2" or release_schema_version in projection_versions,
             "unsupported release schema_version")
    release_for_validation = {k: v for k, v in release.items() if k != "record_digest"}
    if release_schema_version == "release.v2":
        _validate_schema(release_for_validation, "release.v2.schema.json")
    else:
        _validate_schema(release_for_validation, release_schema_version + ".schema.json")
        _require(release.get("target") == target.get("environment"), "release target does not match target environment")
        if release_schema_version == "release-deployment-projection.v2":
            expected_publication_target = {key: target[key] for key in (
                "customer_id", "deployment_id", "account_id", "region", "environment")}
            expected_publication_target["aws_partition"] = _partition_for_region(target["region"])
            _require(release["publication_binding"]["plan"]["target"] == expected_publication_target,
                     "publication target does not match infrastructure target")

    # 4. Verify release digest
    digestible_release = {k: v for k, v in release.items() if k != "record_digest"}
    release_computed = _compute_digest(_canonical_bytes(digestible_release))
    _require(release_computed == expected_release_digest, "release external digest mismatch")
    
    if release_schema_version not in projection_versions:
        if "record_digest" in release:
            _require(release.get("record_digest") == expected_release_digest, "release internal digest mismatch")

    # 5. Extract variables for the exact layer
    _require(layer in layer_bindings, f"no infrastructure selection found for layer {layer!r}")
    
    return layer_bindings[layer]


def emit_variables(
    layer_bindings: dict[str, dict[str, str]],
    layer: str,
) -> dict[str, str]:
    """Extract variables for a specific layer from the validated bindings.

    Returns an empty dict if the layer has no infrastructure selections.
    """
    return dict(layer_bindings.get(layer, {}))


def write_selection_output(
    variables: dict[str, str],
    destination: Path,
) -> None:
    """Write verified variables to a private output file."""
    destination = destination.resolve()
    _require(
        not destination.exists() and not destination.is_symlink(),
        f"output already exists: {destination}",
    )
    parent = destination.parent.resolve(strict=True)
    _require(
        parent != REPO_ROOT and REPO_ROOT not in parent.parents,
        "output must be outside the repository",
    )
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as f:
        f.write(_canonical_bytes(variables))


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for infrastructure selection verification."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selection", type=Path, required=True,
        help="Path to infrastructure-selection/v1 JSON document.",
    )
    parser.add_argument(
        "--expected-digest", required=False, default=None,
        help="Independently provided digest to verify against.",
    )
    parser.add_argument(
        "--target", type=Path, required=False, default=None,
        help="Path to target/v2 JSON document for independent binding.",
    )
    parser.add_argument(
        "--expected-target-digest", required=False, default=None,
        help="Independently provided digest for the target.",
    )
    parser.add_argument(
        "--release", type=Path, required=False, default=None,
        help="Path to release/v2 JSON document for independent binding.",
    )
    parser.add_argument(
        "--expected-release-digest", required=False, default=None,
        help="Independently provided digest for the release.",
    )
    parser.add_argument(
        "--layer", required=False, default=None,
        help="Emit variables only for this exact layer.",
    )
    parser.add_argument(
        "--out", type=Path, required=False, default=None,
        help="Write verified variables to this path (must not exist, outside repo).",
    )
    parser.add_argument(
        "--syntax-check-only", action="store_true", default=False,
        help="Only verify selection syntax, do not emit trusted variables.",
    )
    args = parser.parse_args(argv)

    try:
        doc = _load_json_strict(args.selection)
        
        if args.syntax_check_only:
            layer_bindings = verify_infrastructure_selection(
                doc, expected_digest=args.expected_digest,
            )
            print(json.dumps({
                "status": "VERIFIED_SYNTAX",
                "layers": sorted(layer_bindings.keys()),
                "variables_count": sum(len(v) for v in layer_bindings.values()),
            }, indent=2))
            return 0

        _require(args.layer is not None, "--layer is required for variable emission")
        _require(args.target is not None, "--target is required for variable emission")
        _require(args.expected_target_digest is not None, "--expected-target-digest is required for variable emission")
        _require(args.release is not None, "--release is required for variable emission")
        _require(args.expected_release_digest is not None, "--expected-release-digest is required for variable emission")
        _require(args.expected_digest is not None, "--expected-digest is required for variable emission")

        variables = bind_infrastructure_variables(
            selection=doc,
            expected_digest=args.expected_digest,
            target=_load_json_strict(args.target),
            expected_target_digest=args.expected_target_digest,
            layer=args.layer,
            release=_load_json_strict(args.release),
            expected_release_digest=args.expected_release_digest,
        )

        if args.out:
            write_selection_output(variables, args.out)

        # Emit summary to stdout (safe, no secrets)
        print(json.dumps({
            "status": "VERIFIED_AND_BOUND",
            "layer": args.layer,
            "variables_count": len(variables),
        }, indent=2))

    except (ValueError, jsonschema.ValidationError, OSError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
