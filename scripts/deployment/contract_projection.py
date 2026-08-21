"""Canonical contract validation and Terraform-variable projection."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn


REPO_ROOT = Path(__file__).resolve().parent.parent.parent

from tooling.validate_digest import canonicalize, compute_digest
from tooling.verify_account_ready import verify_account_ready


class ContractProjectionError(ValueError):
    """Contract evidence cannot produce an authorized consumer projection."""


RESERVED_PROJECTION_FIELDS = {
    "contract_id",
    "schema_version",
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "release_manifest_digest",
    "contract_digest",
}

ACCOUNT_READY_CONTRACT_ID = "account-ready/v2"


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ContractProjectionError("JSON document contains a duplicate object key")
        document[key] = value
    return document


def _reject_nonfinite_json_constant(_value: str) -> NoReturn:
    raise ContractProjectionError(
        "JSON document contains a non-finite numeric constant"
    )


def load_json(path: Path, description: str) -> Any:
    """Load JSON using the one duplicate-rejecting parser for this boundary."""
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractProjectionError(
            f"unable to read valid JSON from {description}"
        ) from exc


def _validate_schema(
    instance: Any,
    schema: dict[str, Any],
    description: str,
) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise ContractProjectionError(
            "BLOCKED_TOOLING: jsonschema is not installed"
        ) from exc
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    error = next(iter(validator.iter_errors(instance)), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "(root)"
        raise ContractProjectionError(
            f"{description} schema validation failed at {path} "
            f"(validator={error.validator})"
        )


def _declared_contract_records(
    dag: Any,
    catalog: dict[str, Any],
    layer: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Return validated catalog records declared for one DAG consumer."""
    if not isinstance(dag, dict) or not isinstance(dag.get("layers"), list):
        raise ContractProjectionError("canonical DAG document is invalid")
    stage = next(
        (
            item
            for item in dag["layers"]
            if isinstance(item, dict) and item.get("layer") == layer
        ),
        None,
    )
    if stage is None or not isinstance(stage.get("requires_contracts"), list):
        raise ContractProjectionError(
            "consumer layer contract declaration is invalid"
        )
    records = catalog.get("contracts")
    if not isinstance(records, dict):
        raise ContractProjectionError("contract catalog is invalid")

    declared: list[tuple[str, dict[str, Any]]] = []
    for contract_id in stage["requires_contracts"]:
        record = records.get(contract_id)
        if not isinstance(record, dict):
            raise ContractProjectionError(
                "canonical DAG references an unknown contract"
            )
        declared.append((contract_id, record))
    return declared


def expected_terraform_contracts(
    dag: Any,
    catalog: dict[str, Any],
    layer: str,
) -> set[str]:
    """Return the exact Terraform-root contracts declared for a consumer."""
    return {
        contract_id
        for contract_id, record in _declared_contract_records(dag, catalog, layer)
        if record.get("authority") == "terraform-root"
    }


def _is_supported_account_ready_record(
    contract_id: str,
    record: dict[str, Any],
) -> bool:
    return (
        contract_id == ACCOUNT_READY_CONTRACT_ID
        and record.get("authority") == "account-baseline"
        and record.get("producer") is None
        and record.get("scope") == "external"
        and record.get("transport") == {"kind": "deployment-record"}
    )


def expected_resolvable_contracts(
    dag: Any,
    catalog: dict[str, Any],
    layer: str,
) -> set[str]:
    """Return contracts supported by the active deterministic resolver.

    Release and identity authorities remain explicit unsupported boundaries;
    they are never accepted merely because the DAG names them.
    """
    return {
        contract_id
        for contract_id, record in _declared_contract_records(dag, catalog, layer)
        if record.get("authority") == "terraform-root"
        or _is_supported_account_ready_record(contract_id, record)
    }


def _catalog_output_schema(record: dict[str, Any]) -> Path:
    relative = record.get("output_schema")
    if not isinstance(relative, str):
        raise ContractProjectionError(
            "catalog output schema declaration is invalid"
        )
    schema_root = (REPO_ROOT / "schemas").resolve()
    path = (REPO_ROOT / relative).resolve()
    if not _is_within(path, schema_root) or not path.is_file():
        raise ContractProjectionError("declared output schema is not available")
    return path


def _metadata_value(
    contract: dict[str, Any],
    name: str,
    contract_id: str | None = None,
) -> str:
    output_schema_version = contract.get("output_schema_version", contract_id)
    if name == "output_schema_major":
        if not isinstance(output_schema_version, str) or "/v" not in output_schema_version:
            raise ContractProjectionError(
                "catalog metadata binding references an invalid schema version"
            )
        return output_schema_version.rsplit("/v", 1)[1]
    if name == "output_schema_version":
        if not isinstance(output_schema_version, str):
            raise ContractProjectionError(
                "catalog metadata binding references an invalid schema version"
            )
        return output_schema_version
    value = contract.get(name)
    if not isinstance(value, str):
        raise ContractProjectionError(
            "catalog metadata binding references an invalid field"
        )
    return value


def _contract_projection(
    contract: dict[str, Any],
    outputs: dict[str, Any],
) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "contract_id": contract["output_schema_version"],
        "schema_version": contract["output_schema_version"].rsplit("/v", 1)[1],
        "customer_id": contract["customer_id"],
        "deployment_id": contract["deployment_id"],
        "account_id": contract["aws_account_id"],
        "region": contract["region"],
        "release_manifest_digest": contract["release_digest"],
        "contract_digest": contract["contract_digest"],
    }
    for key, value in outputs.items():
        if key in RESERVED_PROJECTION_FIELDS and projection[key] != value:
            raise ContractProjectionError(
                "contract output conflicts with authoritative envelope metadata"
            )
        projection[key] = value
    return projection


def _add_variable(
    variables: dict[str, Any],
    destination: Any,
    value: Any,
) -> None:
    if not isinstance(destination, str):
        raise ContractProjectionError(
            "canonical consumer variable binding is invalid"
        )
    if destination in variables:
        raise ContractProjectionError(
            "consumer bindings contain an ambiguous destination variable"
        )
    variables[destination] = value


def bind_variables(
    variables: dict[str, Any],
    contract: dict[str, Any],
    outputs: dict[str, Any],
    binding: dict[str, Any],
    *,
    contract_id: str | None = None,
) -> None:
    """Project one verified envelope through its catalog binding."""
    contract_variable = binding.get("contract_variable")
    if contract_variable is not None:
        _add_variable(
            variables,
            contract_variable,
            _contract_projection(contract, outputs),
        )

    for source, destination in binding.get("output_variables", {}).items():
        if source not in outputs:
            raise ContractProjectionError(
                "catalog binding references a missing contract output"
            )
        _add_variable(variables, destination, outputs[source])

    for source, destinations in binding.get("metadata_variables", {}).items():
        value = _metadata_value(contract, source, contract_id)
        for destination in destinations:
            _add_variable(variables, destination, value)


def validate_account_ready_contract(
    evidence: Any,
    *,
    catalog: dict[str, Any],
    layer: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    region: str,
    required_contracts: set[str],
    expected_account_ready_digest: str | None,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate externally anchored ACCOUNT_READY v2 evidence."""
    if not isinstance(evidence, dict):
        raise ContractProjectionError("contract must be a JSON object")
    if "contract_id" in evidence or "contract" in evidence:
        if set(evidence) != {"contract_id", "contract"}:
            raise ContractProjectionError(
                "external contract wrapper is incomplete or unexpected"
            )
        if evidence.get("contract_id") != ACCOUNT_READY_CONTRACT_ID:
            raise ContractProjectionError(
                "contract does not match a declared contract identifier"
            )
        contract = evidence.get("contract")
    else:
        contract = evidence
    if ACCOUNT_READY_CONTRACT_ID not in required_contracts:
        raise ContractProjectionError(
            "contract does not match a declared contract identifier"
        )
    if not isinstance(contract, dict):
        raise ContractProjectionError("ACCOUNT_READY contract must be a JSON object")

    record = catalog.get("contracts", {}).get(ACCOUNT_READY_CONTRACT_ID)
    if not isinstance(record, dict) or not _is_supported_account_ready_record(
        ACCOUNT_READY_CONTRACT_ID,
        record,
    ):
        raise ContractProjectionError(
            "ACCOUNT_READY catalog authority is not supported"
        )
    binding = record.get("consumer_bindings", {}).get(layer)
    if not isinstance(binding, dict):
        raise ContractProjectionError(
            "contract is not authorized for consumer target"
        )
    if set(binding) - {"metadata_variables"}:
        raise ContractProjectionError(
            "ACCOUNT_READY consumer binding exceeds metadata authority"
        )
    if not isinstance(expected_account_ready_digest, str):
        raise ContractProjectionError(
            "independent ACCOUNT_READY digest binding is required"
        )

    schema = load_json(_catalog_output_schema(record), "ACCOUNT_READY schema")
    if not isinstance(schema, dict):
        raise ContractProjectionError("ACCOUNT_READY schema must be a JSON object")
    _validate_schema(contract, schema, "ACCOUNT_READY contract")
    expected_tuple = {
        "customer_id": customer_id,
        "deployment_id": deployment_id,
        "account_id": account_id,
        "region": region,
    }
    if any(contract.get(key) != value for key, value in expected_tuple.items()):
        raise ContractProjectionError("ACCOUNT_READY target binding mismatch")
    anchor = {
        **expected_tuple,
        "environment": contract.get("environment"),
        "baseline_version": contract.get("baseline_version"),
        "expected_contract_digest": expected_account_ready_digest,
    }
    if not verify_account_ready(contract, anchor, schema).passed:
        raise ContractProjectionError("ACCOUNT_READY verification failed")

    wrapper = {"contract_id": ACCOUNT_READY_CONTRACT_ID, "contract": contract}
    return ACCOUNT_READY_CONTRACT_ID, wrapper, {}, binding


def validate_contract(
    contract: Any,
    envelope_schema: dict[str, Any],
    *,
    catalog: dict[str, Any],
    layer: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    region: str,
    release_digest: str,
    release_version: str,
    resolved_at: datetime,
    max_contract_age_seconds: int,
    required_contracts: set[str],
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate one canonical Terraform contract for an exact consumer tuple."""
    if not isinstance(contract, dict):
        raise ContractProjectionError("contract must be a JSON object")
    _validate_schema(contract, envelope_schema, "contract envelope")

    contract_id = contract.get("output_schema_version")
    if not isinstance(contract_id, str) or contract_id not in required_contracts:
        raise ContractProjectionError(
            "contract does not match a declared contract identifier"
        )

    record = catalog["contracts"].get(contract_id)
    if not isinstance(record, dict) or record.get("authority") != "terraform-root":
        raise ContractProjectionError("contract is not owned by a Terraform root")
    binding = record.get("consumer_bindings", {}).get(layer)
    if not isinstance(binding, dict):
        raise ContractProjectionError(
            "contract is not authorized for consumer target"
        )

    producer_layer = record.get("producer")
    if contract.get("layer") != producer_layer:
        raise ContractProjectionError(
            "contract layer does not match the catalog producer"
        )
    if contract.get("producer") != f"roots/{producer_layer}":
        raise ContractProjectionError(
            "contract producer is not the canonical producer"
        )
    if contract.get("scope") != record.get("scope"):
        raise ContractProjectionError(
            "contract scope does not match the catalog declaration"
        )

    if contract.get("customer_id") != customer_id:
        raise ContractProjectionError("contract customer binding mismatch")
    if contract.get("deployment_id") != deployment_id:
        raise ContractProjectionError("contract deployment binding mismatch")
    if contract.get("aws_account_id") != account_id:
        raise ContractProjectionError("contract account binding mismatch")
    if contract.get("release_digest") != release_digest:
        raise ContractProjectionError("contract release binding mismatch")
    if contract.get("release_version") != release_version:
        raise ContractProjectionError(
            "contract release version binding mismatch"
        )

    scope = contract.get("scope")
    contract_region = contract.get("region")
    if scope == "regional" and contract_region != region:
        raise ContractProjectionError("regional contract region binding mismatch")
    if scope == "global" and contract_region != "global":
        raise ContractProjectionError("global contract must use the global region marker")

    expected_state_key = (
        f"{deployment_id}/{producer_layer}/terraform.tfstate"
        if scope == "global"
        else f"{deployment_id}/{region}/{producer_layer}/terraform.tfstate"
    )
    if contract.get("state_key") != expected_state_key:
        raise ContractProjectionError(
            "contract state ownership binding mismatch"
        )

    produced_at = _parse_timestamp(contract["produced_at"], "contract produced_at")
    age_seconds = (resolved_at - produced_at).total_seconds()
    if age_seconds < -300:
        raise ContractProjectionError(
            "contract production timestamp is in the future"
        )
    if age_seconds > max_contract_age_seconds:
        raise ContractProjectionError("contract is stale for this resolution window")

    outputs = contract.get("outputs")
    if not isinstance(outputs, dict):
        raise ContractProjectionError("contract outputs must be an object")
    output_schema = load_json(_catalog_output_schema(record), "output schema")
    if not isinstance(output_schema, dict):
        raise ContractProjectionError("output schema must be a JSON object")
    _validate_schema(outputs, output_schema, "contract outputs")
    if compute_digest(canonicalize(outputs)) != contract.get("contract_digest"):
        raise ContractProjectionError("contract digest verification failed")

    return contract_id, contract, outputs, binding


def _parse_timestamp(value: str, description: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ContractProjectionError(
            f"{description} is not a valid RFC 3339 timestamp"
        ) from exc
    if parsed.utcoffset() is None:
        raise ContractProjectionError(f"{description} must include a timezone")
    return parsed


def project_contracts(
    contracts: list[Any],
    envelope_schema: dict[str, Any],
    *,
    catalog: dict[str, Any],
    dag: Any,
    layer: str,
    customer_id: str,
    deployment_id: str,
    account_id: str,
    region: str,
    release_digest: str,
    release_version: str,
    resolved_at: datetime,
    max_contract_age_seconds: int,
    required_contracts: set[str],
    expected_account_ready_digest: str | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Validate exact evidence and reconstruct the only authorized variables."""
    expected = expected_resolvable_contracts(dag, catalog, layer)
    if required_contracts != expected:
        raise ContractProjectionError(
            "required contract set does not match the canonical DAG target"
        )

    resolved: dict[str, dict[str, Any]] = {}
    variables: dict[str, Any] = {}
    for evidence in contracts:
        if isinstance(evidence, dict) and "output_schema_version" in evidence:
            contract_id, envelope, outputs, binding = validate_contract(
                evidence,
                envelope_schema,
                catalog=catalog,
                layer=layer,
                customer_id=customer_id,
                deployment_id=deployment_id,
                account_id=account_id,
                region=region,
                release_digest=release_digest,
                release_version=release_version,
                resolved_at=resolved_at,
                max_contract_age_seconds=max_contract_age_seconds,
                required_contracts=required_contracts,
            )
        else:
            contract_id, envelope, outputs, binding = validate_account_ready_contract(
                evidence,
                catalog=catalog,
                layer=layer,
                customer_id=customer_id,
                deployment_id=deployment_id,
                account_id=account_id,
                region=region,
                required_contracts=required_contracts,
                expected_account_ready_digest=expected_account_ready_digest,
            )
        if contract_id in resolved:
            raise ContractProjectionError("duplicate contract evidence")
        metadata_source = (
            envelope["contract"]
            if contract_id == ACCOUNT_READY_CONTRACT_ID
            else envelope
        )
        bind_variables(
            variables,
            metadata_source,
            outputs,
            binding,
            contract_id=contract_id,
        )
        resolved[contract_id] = envelope

    if set(resolved) != required_contracts:
        raise ContractProjectionError(
            "one or more required contracts are missing"
        )
    return resolved, variables
