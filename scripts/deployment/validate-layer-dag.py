#!/usr/bin/env python3
"""Validate the canonical Scanalyze Terraform layer DAG.

The validator is intentionally fail-closed.  It accepts only the canonical
``deployment/layers.yaml`` shape and does not translate legacy field names.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL_STAGES = [
    "account-ready-gate",
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "artifact-publication",
    "identity-control-plane",
    "services",
    "edge-identity",
    "edge",
    "addons",
    "synthetic-validation",
]
EXPECTED_KINDS = {
    "account-ready-gate": "gate",
    "artifact-publication": "artifact",
    "synthetic-validation": "validation",
}
EXPECTED_SCOPES = {
    "account-ready-gate": "regional",
    "global": "global",
    "network": "regional",
    "platform": "regional",
    "data-foundation": "regional",
    "cicd": "regional",
    "artifact-publication": "regional",
    "identity-control-plane": "regional",
    "services": "regional",
    "edge-identity": "regional",
    "edge": "global",
    "addons": "regional",
    "synthetic-validation": "regional",
}
EXPECTED_STATE_KEYS = {
    "global": "{deployment_id}/global/terraform.tfstate",
    "network": "{deployment_id}/{region}/network/terraform.tfstate",
    "platform": "{deployment_id}/{region}/platform/terraform.tfstate",
    "data-foundation": "{deployment_id}/{region}/data-foundation/terraform.tfstate",
    "cicd": "{deployment_id}/{region}/cicd/terraform.tfstate",
    "identity-control-plane": "{deployment_id}/{region}/identity-control-plane/terraform.tfstate",
    "services": "{deployment_id}/{region}/services/terraform.tfstate",
    "edge-identity": "{deployment_id}/{region}/edge-identity/terraform.tfstate",
    "edge": "{deployment_id}/edge/terraform.tfstate",
    "addons": "{deployment_id}/{region}/addons/terraform.tfstate",
}
EXPECTED_ROLES = {
    "gate": ("ScanalyzeCustomer-Validation", None),
    "terraform": ("ScanalyzeCustomer-Plan", "ScanalyzeCustomer-Apply"),
    "artifact": ("ScanalyzeCustomer-Validation", "ScanalyzeCustomer-Promotion"),
    "validation": ("ScanalyzeCustomer-Validation", None),
}
EXPECTED_LAYER_ROLES = {
    "identity-control-plane": (
        "ScanalyzeCustomer-Identity-Plan",
        "ScanalyzeCustomer-Identity-Apply",
    ),
}
EXPECTED_TERRAFORM_CONTRACTS = {
    layer: f"{layer}/v1"
    for layer in CANONICAL_STAGES
    if layer not in EXPECTED_KINDS
}
EXPECTED_TERRAFORM_CONTRACTS["data-foundation"] = "data-foundation/v2"
EXPECTED_TERRAFORM_CONTRACTS["edge-identity"] = "edge-identity/v2"
TOP_LEVEL_FIELDS = {"schema_version", "layers"}
LAYER_FIELDS = {
    "layer",
    "kind",
    "depends_on",
    "root",
    "scope",
    "state_key",
    "requires_contracts",
    "produces_contract",
    "plan_role",
    "apply_role",
    "allowed_operations",
    "destroy_policy",
    "artifact_dependencies",
    "produces_artifacts",
    "evidence_requirements",
}
KINDS = {"terraform", "gate", "artifact", "validation"}
SCOPES = {"global", "regional", "none"}
DESTROY_POLICIES = {"deny", "approval-required"}
EXTERNAL_CONTRACTS = {"account-ready/v1", "identity-contract/v2"}
EXTERNAL_CONTRACT_CONSUMERS = {
    "account-ready/v1": {"account-ready-gate", "global"},
    "identity-contract/v2": {"identity-control-plane"},
}
EXTERNAL_SUPPLY_CHAIN_ARTIFACTS = {
    "service-images",
    "base-image",
    "sboms",
    "vulnerability-scan-reports",
    "signatures",
    "provenance",
}
CONTRACT_PATTERN = re.compile(r"^[a-z][a-z0-9-]*/v[1-9][0-9]*$")
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")


def _string_list(value: Any, field: str, layer: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{layer}.{field} must be a list of non-empty strings")
        return []
    if len(value) != len(set(value)):
        errors.append(f"{layer}.{field} must not contain duplicates")
    return value


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_layer_dag(document: Any, repo_root: Path = REPO_ROOT) -> list[str]:
    """Return validation errors for a parsed canonical layer document."""
    errors: list[str] = []
    repo_root = repo_root.resolve()

    if not isinstance(document, dict):
        return ["document must be a mapping"]

    actual_top_fields = set(document)
    if actual_top_fields != TOP_LEVEL_FIELDS:
        missing = sorted(TOP_LEVEL_FIELDS - actual_top_fields)
        unknown = sorted(actual_top_fields - TOP_LEVEL_FIELDS)
        if missing:
            errors.append(f"missing top-level fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"unknown top-level fields: {', '.join(unknown)}")

    if document.get("schema_version") != "1":
        errors.append("schema_version must be exactly '1'")

    raw_layers = document.get("layers")
    if not isinstance(raw_layers, list):
        errors.append("layers must be a list")
        return errors

    layer_names = [item.get("layer") if isinstance(item, dict) else None for item in raw_layers]
    if layer_names != CANONICAL_STAGES:
        errors.append(
            f"layers must contain the canonical {len(CANONICAL_STAGES)} stages "
            "in canonical order"
        )

    layers: dict[str, dict[str, Any]] = {}
    roots_seen: dict[Path, str] = {}
    state_keys: dict[str, str] = {}

    for index, item in enumerate(raw_layers):
        label = f"layers[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be a mapping")
            continue

        actual_fields = set(item)
        missing_fields = sorted(LAYER_FIELDS - actual_fields)
        unknown_fields = sorted(actual_fields - LAYER_FIELDS)
        if missing_fields:
            errors.append(f"{label} missing fields: {', '.join(missing_fields)}")
        if unknown_fields:
            errors.append(f"{label} unknown fields: {', '.join(unknown_fields)}")

        layer = item.get("layer")
        if not isinstance(layer, str) or not NAME_PATTERN.fullmatch(layer):
            errors.append(f"{label}.layer must be a canonical kebab-case identifier")
            continue
        if layer in layers:
            errors.append(f"duplicate layer: {layer}")
            continue
        layers[layer] = item

        kind = item.get("kind")
        if kind not in KINDS:
            errors.append(f"{layer}.kind must be one of: {', '.join(sorted(KINDS))}")
        expected_kind = EXPECTED_KINDS.get(layer, "terraform")
        if kind != expected_kind:
            errors.append(f"{layer}.kind must be {expected_kind}")

        scope = item.get("scope")
        if scope not in SCOPES:
            errors.append(f"{layer}.scope must be one of: {', '.join(sorted(SCOPES))}")
        elif layer in EXPECTED_SCOPES and scope != EXPECTED_SCOPES[layer]:
            errors.append(f"{layer}.scope must be {EXPECTED_SCOPES[layer]}")

        for field in (
            "depends_on",
            "requires_contracts",
            "allowed_operations",
            "artifact_dependencies",
            "produces_artifacts",
            "evidence_requirements",
        ):
            _string_list(item.get(field), field, layer, errors)

        destroy_policy = item.get("destroy_policy")
        if destroy_policy not in DESTROY_POLICIES:
            errors.append(
                f"{layer}.destroy_policy must be one of: {', '.join(sorted(DESTROY_POLICIES))}"
            )

        root = item.get("root")
        state_key = item.get("state_key")
        if kind in {"terraform", "gate"}:
            if not isinstance(root, str) or not root:
                errors.append(f"{layer}.root must name an existing repository directory")
            else:
                root_path = (repo_root / root).resolve()
                if Path(root).is_absolute() or not _is_within(root_path, repo_root):
                    errors.append(f"{layer}.root must stay within the repository")
                elif not root_path.is_dir():
                    errors.append(f"{layer}.root does not exist")
                elif root_path in roots_seen:
                    errors.append(f"{layer}.root duplicates root owned by {roots_seen[root_path]}")
                else:
                    roots_seen[root_path] = layer
        elif root is not None:
            errors.append(f"{layer}.root must be null for kind {kind}")

        if kind == "terraform":
            if not isinstance(state_key, str) or not state_key:
                errors.append(f"{layer}.state_key must be a non-empty template")
            else:
                if "{deployment_id}" not in state_key:
                    errors.append(f"{layer}.state_key must include {{deployment_id}}")
                if scope == "regional" and "{region}" not in state_key:
                    errors.append(f"{layer}.state_key must include {{region}} for regional scope")
                if scope == "global" and "{region}" in state_key:
                    errors.append(f"{layer}.state_key must not include {{region}} for global scope")
                if state_key in state_keys:
                    errors.append(f"{layer}.state_key duplicates state owned by {state_keys[state_key]}")
                else:
                    state_keys[state_key] = layer
                expected_state_key = EXPECTED_STATE_KEYS.get(layer)
                if expected_state_key is not None and state_key != expected_state_key:
                    errors.append(f"{layer}.state_key must match the canonical template")
        elif state_key is not None:
            errors.append(f"{layer}.state_key must be null for kind {kind}")

        produces_contract = item.get("produces_contract")
        if produces_contract is not None and (
            not isinstance(produces_contract, str)
            or not CONTRACT_PATTERN.fullmatch(produces_contract)
        ):
            errors.append(f"{layer}.produces_contract must be null or '<layer>/vN'")
        expected_contract = EXPECTED_TERRAFORM_CONTRACTS.get(layer)
        if kind == "terraform" and produces_contract != expected_contract:
            errors.append(
                f"{layer}.produces_contract must be exactly {expected_contract}"
            )
        for contract in item.get("requires_contracts", []) if isinstance(item.get("requires_contracts"), list) else []:
            if isinstance(contract, str) and not CONTRACT_PATTERN.fullmatch(contract):
                errors.append(f"{layer}.requires_contracts contains invalid contract identifier")

        for role_field in ("plan_role", "apply_role"):
            role = item.get(role_field)
            if role is not None and (not isinstance(role, str) or not role):
                errors.append(f"{layer}.{role_field} must be null or a non-empty role template")
        expected_roles = EXPECTED_LAYER_ROLES.get(layer, EXPECTED_ROLES.get(kind))
        if expected_roles is not None:
            expected_plan_role, expected_apply_role = expected_roles
            if item.get("plan_role") != expected_plan_role:
                errors.append(f"{layer}.plan_role must be {expected_plan_role}")
            if item.get("apply_role") != expected_apply_role:
                expected = expected_apply_role if expected_apply_role is not None else "null"
                errors.append(f"{layer}.apply_role must be {expected}")

    if set(layers) != set(CANONICAL_STAGES):
        # Structural errors above are enough to explain which stage is missing.
        return errors
    if errors:
        # Do not dereference fields after a structural/type failure.  Returning
        # the sanitized errors also prevents malformed input from producing a
        # traceback that could expose runner paths or document contents.
        return errors

    producers: dict[str, str] = {}
    artifact_producers: dict[str, str] = {}
    dependencies: dict[str, set[str]] = {name: set() for name in layers}

    for layer, item in layers.items():
        produced = item["produces_contract"]
        if isinstance(produced, str):
            if produced in producers:
                errors.append(f"contract {produced} has multiple producers")
            else:
                producers[produced] = layer

        for artifact in item["produces_artifacts"]:
            if not NAME_PATTERN.fullmatch(artifact):
                errors.append(f"{layer}.produces_artifacts contains invalid artifact identifier")
            elif artifact in artifact_producers:
                errors.append(f"artifact {artifact} has multiple producers")
            else:
                artifact_producers[artifact] = layer

    for layer, item in layers.items():
        for dependency in item["depends_on"]:
            if dependency not in layers:
                errors.append(f"{layer}.depends_on references unknown layer {dependency}")
            elif dependency == layer:
                errors.append(f"{layer}.depends_on must not reference itself")
            else:
                dependencies[layer].add(dependency)

        for contract in item["requires_contracts"]:
            producer = producers.get(contract)
            if producer is None:
                if (
                    contract not in EXTERNAL_CONTRACTS
                    or layer not in EXTERNAL_CONTRACT_CONSUMERS[contract]
                ):
                    errors.append(f"{layer} requires contract {contract} with no producer")
            elif producer == layer:
                errors.append(f"{layer} cannot require its own contract {contract}")
            else:
                dependencies[layer].add(producer)

        for artifact in item["artifact_dependencies"]:
            producer = artifact_producers.get(artifact)
            if producer is None:
                if not (
                    layer == "artifact-publication"
                    and artifact in EXTERNAL_SUPPLY_CHAIN_ARTIFACTS
                ):
                    errors.append(f"{layer} requires artifact {artifact} with no producer")
            elif producer == layer:
                errors.append(f"{layer} cannot require its own artifact {artifact}")
            else:
                dependencies[layer].add(producer)

    # Cycle detection over explicit, contract, and artifact edges.
    colors: dict[str, int] = defaultdict(int)

    def visit(layer: str, trail: list[str]) -> None:
        if colors[layer] == 1:
            cycle_start = trail.index(layer) if layer in trail else 0
            cycle = trail[cycle_start:] + [layer]
            errors.append(f"dependency cycle detected: {' -> '.join(cycle)}")
            return
        if colors[layer] == 2:
            return
        colors[layer] = 1
        for dependency in sorted(dependencies[layer]):
            visit(dependency, trail + [layer])
        colors[layer] = 2

    for layer in CANONICAL_STAGES:
        visit(layer, [])

    positions = {name: index for index, name in enumerate(CANONICAL_STAGES)}
    for layer, required_layers in dependencies.items():
        for dependency in required_layers:
            if positions[dependency] >= positions[layer]:
                errors.append(f"{layer} must be declared after dependency {dependency}")

    def has_ancestor(layer: str, ancestor: str, seen: set[str] | None = None) -> bool:
        seen = seen or set()
        if layer in seen:
            return False
        seen.add(layer)
        if ancestor in dependencies[layer]:
            return True
        return any(has_ancestor(dep, ancestor, seen) for dep in dependencies[layer])

    if not has_ancestor("artifact-publication", "cicd"):
        errors.append("artifact-publication must run after cicd")
    if not has_ancestor("identity-control-plane", "artifact-publication"):
        errors.append("identity-control-plane must run after artifact-publication")
    if not has_ancestor("services", "identity-control-plane"):
        errors.append("services must run after identity-control-plane")
    if not has_ancestor("edge", "services"):
        errors.append("edge must run after services")

    if "identity-control-plane/v1" not in layers["services"]["requires_contracts"]:
        errors.append("services must require identity-control-plane/v1")
    if "identity-control-plane/v1" not in layers["edge-identity"]["requires_contracts"]:
        errors.append("edge-identity must require identity-control-plane/v1")

    service_artifacts = layers["services"]["artifact_dependencies"]
    if not any("image" in value and "digest" in value for value in service_artifacts):
        errors.append("services must require an immutable image-digests artifact")

    gate = layers["account-ready-gate"]
    gate_operations = set(gate["allowed_operations"])
    forbidden_gate_operations = {
        operation
        for operation in gate_operations
        if "apply" in operation.lower() or "destroy" in operation.lower()
    }
    if forbidden_gate_operations:
        errors.append("account-ready-gate must not allow apply or destroy")
    if gate["destroy_policy"] != "deny":
        errors.append("account-ready-gate.destroy_policy must be deny")

    return errors


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("layers_file", type=Path, help="canonical deployment/layers.yaml")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        print("BLOCKED_TOOLING: PyYAML is not installed", file=sys.stderr)
        return 2

    if not args.layers_file.is_file():
        print("ERROR: layer DAG file does not exist", file=sys.stderr)
        return 2

    try:
        document = yaml.safe_load(args.layers_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        print("ERROR: unable to parse layer DAG YAML", file=sys.stderr)
        return 2

    errors = validate_layer_dag(document)
    if errors:
        print(f"FAIL: layer DAG has {len(errors)} error(s)", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"PASS: canonical layer DAG validated ({len(CANONICAL_STAGES)} stages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
