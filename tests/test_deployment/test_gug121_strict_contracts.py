"""GUG-121 fail-closed contract catalog and binding invariants."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "deployment" / "contract-catalog.v1.json"
CATALOG_SCHEMA_PATH = REPO_ROOT / "schemas" / "contract-catalog.v1.schema.json"
ENVELOPE_SCHEMA_PATH = REPO_ROOT / "schemas" / "layer-contract.v2.schema.json"
LAYERS_PATH = REPO_ROOT / "deployment" / "layers.yaml"
PUBLISH_SCRIPT = REPO_ROOT / "scripts" / "deployment" / "publish-contract.py"
RESOLVE_SCRIPT = REPO_ROOT / "scripts" / "deployment" / "resolve-contracts.py"
LAYER_WRAPPER = REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh"
DEPLOY_WRAPPER = REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh"

CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
ACCOUNT_ID = "111222333444"
RELEASE_DIGEST = "sha256:" + ("a" * 64)
MODULE_DIGEST = "sha256:" + ("b" * 64)
PRODUCED_AT = "2026-07-14T00:00:00Z"
RESOLVED_AT = "2026-07-14T00:05:00Z"
RELEASE_VERSION = "2026.07.14"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_catalog_is_schema_valid_and_covers_every_dag_contract() -> None:
    catalog = _load_json(CATALOG_PATH)
    schema = _load_json(CATALOG_SCHEMA_PATH)
    jsonschema.Draft202012Validator(schema).validate(catalog)

    dag = yaml.safe_load(LAYERS_PATH.read_text(encoding="utf-8"))
    contracts = catalog["contracts"]
    produced: dict[str, tuple[str, str]] = {}
    for layer in dag["layers"]:
        contract_id = layer["produces_contract"]
        if contract_id is not None:
            assert contract_id not in produced
            produced[contract_id] = (layer["layer"], layer["kind"])
        for required in layer["requires_contracts"]:
            assert required in contracts
            assert layer["layer"] in contracts[required]["consumers"]

    for contract_id, (producer, kind) in produced.items():
        record = contracts[contract_id]
        assert record["producer"] == producer
        if kind == "terraform":
            assert record["authority"] == "terraform-root"
        assert (REPO_ROOT / record["output_schema"]).is_file()

    for contract_id, record in contracts.items():
        assert set(record["consumer_bindings"]) == set(record["consumers"]), contract_id


def test_terraform_contract_paths_are_content_addressed_and_not_latest() -> None:
    contracts = _load_json(CATALOG_PATH)["contracts"]
    for contract_id, record in contracts.items():
        if record["authority"] != "terraform-root":
            continue
        template = record["transport"]["path_template"]
        assert record["transport"]["kind"] == "ssm"
        assert "{deployment_id}" in template
        assert "{release_digest}" in template
        assert "{contract_digest}" in template
        assert "latest" not in template.lower(), contract_id


def test_layer_contract_v2_requires_customer_deployment_account_tuple() -> None:
    schema = _load_json(ENVELOPE_SCHEMA_PATH)
    assert "customer_id" in schema["required"]
    assert schema["properties"]["customer_id"]["pattern"] == (
        r"^cust_[0-9A-HJKMNP-TV-Z]{26}$"
    )
    assert "deployment_id" in schema["required"]
    assert "aws_account_id" in schema["required"]
    assert "release_version" in schema["required"]
    assert "module_source_digest" in schema["required"]


def test_publisher_emits_v2_customer_bound_envelope(tmp_path: Path) -> None:
    source = tmp_path / "terraform-output.json"
    destination = tmp_path / "global-contract.json"
    source.write_text(
        json.dumps(
            {
                "ecs_execution_role_arn": {
                    "sensitive": False,
                    "value": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeExecution",
                },
                "ecs_task_role_arns": {
                    "sensitive": False,
                    "value": {
                        "scanalyze-ingest-api": (
                            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngest"
                        )
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(PUBLISH_SCRIPT),
            "--from-terraform-output-json",
            str(source),
            "--layer",
            "global",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "global",
            "--release-digest",
            RELEASE_DIGEST,
            "--release-version",
            RELEASE_VERSION,
            "--module-source-digest",
            MODULE_DIGEST,
            "--produced-at",
            PRODUCED_AT,
            "--state-key",
            f"{DEPLOYMENT_ID}/global/terraform.tfstate",
            "--out",
            str(destination),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    envelope = _load_json(destination)
    assert envelope["schema_version"] == "2"
    assert envelope["customer_id"] == CUSTOMER_ID
    assert envelope["deployment_id"] == DEPLOYMENT_ID
    assert envelope["aws_account_id"] == ACCOUNT_ID
    assert envelope["release_version"] == RELEASE_VERSION
    assert CUSTOMER_ID not in result.stdout + result.stderr
    assert ACCOUNT_ID not in result.stdout + result.stderr


def _publish_global(tmp_path: Path) -> Path:
    source = tmp_path / "terraform-output.json"
    destination = tmp_path / "global-contract.json"
    source.write_text(
        json.dumps(
            {
                "contract_payload": {
                    "sensitive": False,
                    "value": {
                        "layer": "global",
                        "schema_version": "1",
                        "state_scope": "global",
                        "outputs": {
                            "ecs_execution_role_arn": (
                                f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeExecution"
                            ),
                            "ecs_task_role_arns": {
                                "scanalyze-ingest-api": (
                                    f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngest"
                                )
                            },
                        },
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(PUBLISH_SCRIPT),
            "--from-terraform-output-json",
            str(source),
            "--layer",
            "global",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "global",
            "--release-digest",
            RELEASE_DIGEST,
            "--release-version",
            RELEASE_VERSION,
            "--module-source-digest",
            MODULE_DIGEST,
            "--produced-at",
            PRODUCED_AT,
            "--state-key",
            f"{DEPLOYMENT_ID}/global/terraform.tfstate",
            "--out",
            str(destination),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return destination


def _resolve_global(tmp_path: Path, contract: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    output = tmp_path / "network.resolution.json"
    values = {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "release_digest": RELEASE_DIGEST,
        "release_version": RELEASE_VERSION,
        "resolved_at": RESOLVED_AT,
        "layer": "network",
    }
    values.update(overrides)
    return subprocess.run(
        [
            sys.executable,
            str(RESOLVE_SCRIPT),
            "--contract",
            str(contract),
            "--allow-fixtures",
            "--layer",
            values["layer"],
            "--customer-id",
            values["customer_id"],
            "--deployment-id",
            values["deployment_id"],
            "--account-id",
            values["account_id"],
            "--region",
            values["region"],
            "--release-digest",
            values["release_digest"],
            "--release-version",
            values["release_version"],
            "--resolved-at",
            values["resolved_at"],
            "--max-contract-age-seconds",
            "3600",
            "--required-contract",
            "global/v1",
            "--out",
            str(output),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_real_root_contract_resolver_consumer_flow_is_content_bound(tmp_path: Path) -> None:
    contract = _publish_global(tmp_path)
    result = _resolve_global(tmp_path, contract)
    assert result.returncode == 0, result.stderr
    resolution = _load_json(tmp_path / "network.resolution.json")
    assert resolution["consumer_layer"] == "network"
    assert resolution["customer_id"] == CUSTOMER_ID
    assert resolution["required_contracts"][0]["contract_id"] == "global/v1"
    assert resolution["variables"]["upstream_contract_digest"] == (
        resolution["variables"]["expected_upstream_digest"]
    )
    assert resolution["resolution_digest"].startswith("sha256:")
    assert os.stat(tmp_path / "network.resolution.json").st_mode & 0o077 == 0


@pytest.mark.parametrize(
    ("override", "value", "expected"),
    [
        ("customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2", "customer binding mismatch"),
        ("release_digest", "sha256:" + ("c" * 64), "release binding mismatch"),
        ("release_version", "2026.07.13", "release version binding mismatch"),
        ("layer", "platform", "not authorized for consumer"),
        ("resolved_at", "2026-07-16T00:00:00Z", "stale"),
    ],
)
def test_resolver_rejects_wrong_customer_release_target_or_stale_contract(
    tmp_path: Path, override: str, value: str, expected: str
) -> None:
    contract = _publish_global(tmp_path)
    result = _resolve_global(tmp_path, contract, **{override: value})
    assert result.returncode == 1
    assert expected in result.stderr
    assert CUSTOMER_ID not in result.stderr
    assert ACCOUNT_ID not in result.stderr
    assert not (tmp_path / "network.resolution.json").exists()


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("producer", "roots/network", "canonical producer"),
        ("output_schema_version", "network/v1", "declared contract identifier"),
        ("contract_digest", "sha256:" + ("0" * 64), "digest verification"),
    ],
)
def test_resolver_rejects_wrong_producer_schema_or_altered_contract(
    tmp_path: Path, field: str, value: str, expected: str
) -> None:
    contract = _publish_global(tmp_path)
    document = _load_json(contract)
    document[field] = value
    contract.unlink()
    contract.write_text(json.dumps(document), encoding="utf-8")
    result = _resolve_global(tmp_path, contract)
    assert result.returncode == 1
    assert expected in result.stderr
    assert not (tmp_path / "network.resolution.json").exists()


def test_plan_wrapper_has_no_mock_fallback_and_requires_verified_resolution() -> None:
    source = LAYER_WRAPPER.read_text(encoding="utf-8")
    assert "mock" not in source.lower()
    assert "--resolved-input" in source
    assert "validate-contract-resolution.py" in source
    assert "allow-mocks" not in RESOLVE_SCRIPT.read_text(encoding="utf-8")


def test_deployment_entrypoint_forwards_all_verified_resolution_bindings() -> None:
    source = DEPLOY_WRAPPER.read_text(encoding="utf-8")
    for option in (
        "--customer-id",
        "--release-version",
        "--release-digest",
        "--resolved-input",
    ):
        assert option in source


def test_catalog_declares_multi_upstream_services_and_edge_owners() -> None:
    contracts = _load_json(CATALOG_PATH)["contracts"]
    services_sources = {
        contract_id
        for contract_id, record in contracts.items()
        if "services" in record["consumers"]
    }
    assert {
        "global/v1",
        "network/v2",
        "platform/v2",
        "data-foundation/v2",
        "cicd/v2",
        "release-manifest/v1",
        "identity-control-plane/v1",
    }.issubset(services_sources)

    edge_identity_sources = {
        contract_id
        for contract_id, record in contracts.items()
        if "edge-identity" in record["consumers"]
    }
    assert {
        "network/v2",
        "platform/v2",
        "services/v2",
        "identity-control-plane/v1",
    }.issubset(edge_identity_sources)


def test_active_terraform_producers_expose_every_versioned_schema_field() -> None:
    producer_sources = {
        "global/v1": REPO_ROOT / "modules" / "global" / "contract.tf",
        "network/v2": REPO_ROOT / "modules" / "network" / "contract.tf",
        "platform/v2": REPO_ROOT / "modules" / "container-platform" / "contract.tf",
        "data-foundation/v2": REPO_ROOT / "modules" / "data-foundation" / "contract.tf",
        "cicd/v2": REPO_ROOT / "roots" / "cicd" / "outputs.tf",
        "services/v2": REPO_ROOT / "modules" / "services" / "contract.tf",
        "edge/v2": REPO_ROOT / "modules" / "edge" / "contract.tf",
        "addons/v2": REPO_ROOT / "modules" / "addons" / "contract.tf",
    }
    catalog = _load_json(CATALOG_PATH)["contracts"]
    for contract_id, source_path in producer_sources.items():
        schema = _load_json(REPO_ROOT / catalog[contract_id]["output_schema"])
        source = source_path.read_text(encoding="utf-8")
        assert re.search(r"\boutputs\s*=\s*\{", source), contract_id
        for field in schema["required"]:
            assert re.search(rf"\b{re.escape(field)}\s*=", source), (
                contract_id,
                field,
            )


def test_replaced_v1_contract_schemas_remain_for_rollback_compatibility() -> None:
    for layer in ("network", "platform", "cicd", "services", "edge", "addons"):
        filename = (
            f"cicd-contract.v1.schema.json"
            if layer == "cicd"
            else f"contract-{layer}.v1.schema.json"
        )
        assert (REPO_ROOT / "schemas" / filename).is_file()
