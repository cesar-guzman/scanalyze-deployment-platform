"""GUG-121 fail-closed contract catalog and binding invariants."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
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
VALIDATE_RESOLUTION_SCRIPT = (
    REPO_ROOT / "scripts" / "deployment" / "validate-contract-resolution.py"
)
LAYER_WRAPPER = REPO_ROOT / "scripts" / "deployment" / "terraform-layer.sh"
DEPLOY_WRAPPER = REPO_ROOT / "scripts" / "deployment" / "scanalyze-deploy.sh"
DEPLOYMENT_SCRIPT_DIR = REPO_ROOT / "scripts" / "deployment"
if str(DEPLOYMENT_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(DEPLOYMENT_SCRIPT_DIR))

from contract_projection import (  # noqa: E402
    ContractProjectionError,
    bind_variables,
    expected_resolvable_contracts,
    project_contracts,
)
from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402
from tooling.verify_account_ready import canonical_digest as account_ready_digest  # noqa: E402

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


def test_global_resolvable_contract_set_is_exactly_account_ready_v2() -> None:
    assert expected_resolvable_contracts(
        yaml.safe_load(LAYERS_PATH.read_text(encoding="utf-8")),
        _load_json(CATALOG_PATH),
        "global",
    ) == {"account-ready/v2"}


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
    assert resolution["schema_version"] == "3"
    assert resolution["consumer_layer"] == "network"
    assert resolution["customer_id"] == CUSTOMER_ID
    assert resolution["required_contracts"][0]["output_schema_version"] == "global/v1"
    assert resolution["required_contracts"][0]["outputs"]
    assert "variables" not in resolution
    assert resolution["resolution_digest"].startswith("sha256:")
    assert os.stat(tmp_path / "network.resolution.json").st_mode & 0o077 == 0


@pytest.mark.parametrize(
    ("override", "value", "expected"),
    [
        ("customer_id", "cust_01J5A1B2C3D4E5F6G7H8J9K0M2", "customer binding mismatch"),
        ("release_digest", "sha256:" + ("c" * 64), "release binding mismatch"),
        ("release_version", "2026.07.13", "release version binding mismatch"),
        ("layer", "platform", "canonical DAG target"),
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


def _account_ready_v2() -> dict:
    role_names = {
        "plan": "Plan",
        "apply": "Apply",
        "identity_plan": "Identity-Plan",
        "identity_apply": "Identity-Apply",
        "promotion": "Promotion",
        "validation": "Validation",
        "diagnostic": "Diagnostic",
        "state_recovery": "StateRecovery",
    }
    tags = {
        "customer_id_tag": CUSTOMER_ID,
        "deployment_id_tag": DEPLOYMENT_ID,
        "account_id_tag": ACCOUNT_ID,
        "region_tag": "us-east-1",
        "environment_tag": "sandbox",
    }
    contract = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "environment": "sandbox",
        "baseline_version": "v2.1.0",
        "provisioned_at": PRODUCED_AT,
        "roles": {
            key: {
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-{name}",
                **tags,
            }
            for key, name in role_names.items()
        },
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
            "plan_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-plan",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
            "state_kms_key": (
                f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:"
                "key/00000000-0000-0000-0000-000000000001"
            ),
            "evidence_kms_key": (
                f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:"
                "key/00000000-0000-0000-0000-000000000002"
            ),
            "contracts_kms_key": (
                f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:"
                "key/00000000-0000-0000-0000-000000000003"
            ),
        },
        "controls": {
            "state_versioning_enabled": True,
            "state_default_encryption": "aws:kms",
            "state_bucket_key_enabled": True,
            "state_public_access_blocked": True,
            "state_object_lock_enabled": False,
            "native_lockfile_enabled": True,
            "plan_versioning_enabled": True,
            "plan_default_encryption": "aws:kms",
            "plan_kms_key": (
                f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:"
                "key/00000000-0000-0000-0000-000000000002"
            ),
            "plan_bucket_key_enabled": True,
            "plan_public_access_blocked": True,
            "plan_lifecycle_days": 1,
        },
    }
    contract["contract_digest"] = account_ready_digest(contract)
    return contract


def _account_ready_resolve_args(
    contract: Path,
    output: Path,
    expected_digest: str | None,
) -> list[str]:
    args = [
        sys.executable,
        str(RESOLVE_SCRIPT),
        "--contract",
        str(contract),
        "--allow-fixtures",
        "--layer",
        "global",
        "--customer-id",
        CUSTOMER_ID,
        "--deployment-id",
        DEPLOYMENT_ID,
        "--account-id",
        ACCOUNT_ID,
        "--region",
        "us-east-1",
        "--release-digest",
        RELEASE_DIGEST,
        "--release-version",
        RELEASE_VERSION,
        "--resolved-at",
        RESOLVED_AT,
        "--required-contract",
        "account-ready/v2",
        "--out",
        str(output),
    ]
    if expected_digest is not None:
        args.extend(["--expected-account-ready-digest", expected_digest])
    return args


def test_account_ready_v2_resolves_v3_and_materializes_only_global_metadata(
    tmp_path: Path,
) -> None:
    contract = _account_ready_v2()
    contract_path = tmp_path / "account-ready.json"
    resolution_path = tmp_path / "global.resolution.json"
    variables_path = tmp_path / "global.auto.tfvars.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    resolved = subprocess.run(
        _account_ready_resolve_args(
            contract_path,
            resolution_path,
            contract["contract_digest"],
        ),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert resolved.returncode == 0, resolved.stderr
    resolution = _load_json(resolution_path)
    assert resolution["schema_version"] == "3"
    assert resolution["required_contracts"] == [
        {"contract_id": "account-ready/v2", "contract": contract}
    ]

    validated = subprocess.run(
        [
            sys.executable,
            str(VALIDATE_RESOLUTION_SCRIPT),
            "--resolution",
            str(resolution_path),
            "--layer",
            "global",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "us-east-1",
            "--release-version",
            RELEASE_VERSION,
            "--release-digest",
            RELEASE_DIGEST,
            "--expected-account-ready-digest",
            contract["contract_digest"],
            "--materialize-out",
            str(variables_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert validated.returncode == 0, validated.stderr
    assert _load_json(variables_path) == {
        "expected_upstream_digest": contract["contract_digest"],
        "upstream_contract_digest": contract["contract_digest"],
        "upstream_schema_version": "2",
    }


@pytest.mark.parametrize(
    "case",
    ["missing-anchor", "wrong-anchor", "foreign-tuple", "partial", "v1", "altered"],
)
def test_account_ready_resolution_failures_create_no_output(
    tmp_path: Path,
    case: str,
) -> None:
    contract = _account_ready_v2()
    expected_digest: str | None = contract["contract_digest"]
    if case == "missing-anchor":
        expected_digest = None
    elif case == "wrong-anchor":
        expected_digest = "sha256:" + ("0" * 64)
    elif case == "foreign-tuple":
        contract["account_id"] = "999888777666"
    elif case == "partial":
        contract.pop("roles")
    elif case == "v1":
        contract["schema_version"] = "1"
    elif case == "altered":
        contract["baseline_version"] = "v2.0.1"
    contract_path = tmp_path / f"{case}.json"
    output_path = tmp_path / f"{case}.resolution.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    result = subprocess.run(
        _account_ready_resolve_args(contract_path, output_path, expected_digest),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert CUSTOMER_ID not in result.stdout + result.stderr
    assert ACCOUNT_ID not in result.stdout + result.stderr
    assert not output_path.exists()


def test_account_ready_duplicate_extra_and_wrong_consumer_fail_closed(
    tmp_path: Path,
) -> None:
    contract = _account_ready_v2()
    contract_path = tmp_path / "account-ready.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    for name, extra_args in (
        ("duplicate", ["--contract", str(contract_path)]),
        ("extra", ["--required-contract", "global/v1"]),
        ("consumer", []),
    ):
        output_path = tmp_path / f"{name}.resolution.json"
        args = _account_ready_resolve_args(
            contract_path,
            output_path,
            contract["contract_digest"],
        )
        if name == "consumer":
            args[args.index("global")] = "network"
        args.extend(extra_args)
        result = subprocess.run(
            args,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
        assert not output_path.exists()


def test_active_validator_rejects_resolution_v2_downgrade(tmp_path: Path) -> None:
    contract = _publish_global(tmp_path)
    assert _resolve_global(tmp_path, contract).returncode == 0
    resolution_path = tmp_path / "network.resolution.json"
    resolution = _load_json(resolution_path)
    resolution["schema_version"] = "2"
    digest_input = {
        key: value for key, value in resolution.items() if key != "resolution_digest"
    }
    resolution["resolution_digest"] = compute_digest(canonicalize(digest_input))
    resolution_path.write_text(json.dumps(resolution), encoding="utf-8")
    resolution_path.chmod(0o600)
    variables_path = tmp_path / "network.auto.tfvars.json"

    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATE_RESOLUTION_SCRIPT),
            "--resolution",
            str(resolution_path),
            "--schema",
            str(REPO_ROOT / "schemas/contract-resolution.v2.schema.json"),
            "--layer",
            "network",
            "--customer-id",
            CUSTOMER_ID,
            "--deployment-id",
            DEPLOYMENT_ID,
            "--account-id",
            ACCOUNT_ID,
            "--region",
            "us-east-1",
            "--release-version",
            RELEASE_VERSION,
            "--release-digest",
            RELEASE_DIGEST,
            "--materialize-out",
            str(variables_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "schema downgrade is forbidden" in result.stderr
    assert not variables_path.exists()


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


def _contract_evidence(
    *,
    contract_id: str,
    layer: str,
    outputs: dict,
    scope: str = "regional",
) -> dict:
    contract_region = "global" if scope == "global" else "us-east-1"
    state_key = (
        f"{DEPLOYMENT_ID}/{layer}/terraform.tfstate"
        if scope == "global"
        else f"{DEPLOYMENT_ID}/us-east-1/{layer}/terraform.tfstate"
    )
    return {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "aws_account_id": ACCOUNT_ID,
        "region": contract_region,
        "scope": scope,
        "layer": layer,
        "producer": f"roots/{layer}",
        "release_version": RELEASE_VERSION,
        "release_digest": RELEASE_DIGEST,
        "output_schema_version": contract_id,
        "outputs": outputs,
        "contract_digest": compute_digest(canonicalize(outputs)),
        "produced_at": PRODUCED_AT,
        "terraform_workspace": "default",
        "state_key": state_key,
        "module_source_digest": MODULE_DIGEST,
    }


def _resolved_at() -> datetime:
    return datetime.fromisoformat(
        RESOLVED_AT.replace("Z", "+00:00")
    ).astimezone(timezone.utc)


def test_projection_preserves_all_json_types_without_coercion() -> None:
    variables: dict = {}
    values = {
        "string": "value",
        "boolean": False,
        "number": 7,
        "list": ["a", 2],
        "map": {"enabled": True},
        "null": None,
    }
    binding = {
        "output_variables": {
            source: f"projected_{source}" for source in values
        }
    }

    bind_variables(variables, {}, values, binding)

    assert variables == {
        f"projected_{source}": value for source, value in values.items()
    }


def test_projection_reconstructs_all_catalog_binding_kinds() -> None:
    outputs = {
        "ecs_execution_role_arn": (
            f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeExecution"
        ),
        "ecs_task_role_arns": {
            "scanalyze-ingest-api": (
                f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeIngest"
            )
        },
    }
    evidence = _contract_evidence(
        contract_id="global/v1",
        layer="global",
        outputs=outputs,
        scope="global",
    )
    catalog = _load_json(CATALOG_PATH)
    catalog["contracts"]["global/v1"]["consumer_bindings"]["network"].update(
        {
            "contract_variable": "global_contract",
            "output_variables": {
                "ecs_execution_role_arn": "execution_role_arn",
                "ecs_task_role_arns": "task_role_arns",
            },
        }
    )

    _, variables = project_contracts(
        [evidence],
        _load_json(ENVELOPE_SCHEMA_PATH),
        catalog=catalog,
        dag=yaml.safe_load(LAYERS_PATH.read_text(encoding="utf-8")),
        layer="network",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        account_id=ACCOUNT_ID,
        region="us-east-1",
        release_digest=RELEASE_DIGEST,
        release_version=RELEASE_VERSION,
        resolved_at=_resolved_at(),
        max_contract_age_seconds=3600,
        required_contracts={"global/v1"},
    )

    assert variables["upstream_contract_digest"] == evidence["contract_digest"]
    assert variables["execution_role_arn"] == outputs["ecs_execution_role_arn"]
    assert variables["task_role_arns"] == outputs["ecs_task_role_arns"]
    assert variables["global_contract"]["contract_id"] == "global/v1"
    assert variables["global_contract"]["ecs_task_role_arns"] == outputs[
        "ecs_task_role_arns"
    ]


def test_projection_accepts_valid_multi_upstream_contracts() -> None:
    platform_outputs = {
        "ecs_cluster_arn": (
            f"arn:aws:ecs:us-east-1:{ACCOUNT_ID}:cluster/synthetic"
        ),
        "ecs_cluster_name": "synthetic",
        "alb_arn": (
            f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:"
            "loadbalancer/app/synthetic/0123456789abcdef"
        ),
        "alb_dns_name": "synthetic.invalid",
        "alb_listener_arn": (
            f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:"
            "listener/app/synthetic/0123456789abcdef/0123456789abcdef"
        ),
        "alb_security_group_id": "sg-0123456789abcdef0",
    }
    data_outputs = json.loads(
        (
            REPO_ROOT / "fixtures/valid/contract-data-foundation-v2.json"
        )
        .read_text(encoding="utf-8")
        .replace("123456789012", ACCOUNT_ID)
        .replace("dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", DEPLOYMENT_ID)
    )
    evidence = [
        _contract_evidence(
            contract_id="platform/v2",
            layer="platform",
            outputs=platform_outputs,
        ),
        _contract_evidence(
            contract_id="data-foundation/v2",
            layer="data-foundation",
            outputs=data_outputs,
        ),
    ]

    _, variables = project_contracts(
        evidence,
        _load_json(ENVELOPE_SCHEMA_PATH),
        catalog=_load_json(CATALOG_PATH),
        dag=yaml.safe_load(LAYERS_PATH.read_text(encoding="utf-8")),
        layer="cicd",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        account_id=ACCOUNT_ID,
        region="us-east-1",
        release_digest=RELEASE_DIGEST,
        release_version=RELEASE_VERSION,
        resolved_at=_resolved_at(),
        max_contract_age_seconds=3600,
        required_contracts={"platform/v2", "data-foundation/v2"},
    )

    assert variables["ecs_cluster_name"] == "synthetic"
    assert variables["upstream_contract_id"] == "data-foundation/v2"
    assert variables["upstream_schema_version"] == "2"


def test_projection_rejects_duplicate_destination_across_bindings() -> None:
    variables = {"shared_destination": "first"}
    with pytest.raises(
        ContractProjectionError,
        match="ambiguous destination variable",
    ):
        bind_variables(
            variables,
            {},
            {"second": "value"},
            {"output_variables": {"second": "shared_destination"}},
        )
