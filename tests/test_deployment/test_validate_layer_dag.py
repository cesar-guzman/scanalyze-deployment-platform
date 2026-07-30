"""Fail-closed tests for the canonical deployment layer DAG."""
from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "deployment" / "validate-layer-dag.py"
LAYERS_FILE = REPO_ROOT / "deployment" / "layers.yaml"


@pytest.fixture
def canonical_dag() -> dict:
    return yaml.safe_load(LAYERS_FILE.read_text(encoding="utf-8"))


def _layer(document: dict, name: str) -> dict:
    return next(item for item in document["layers"] if item["layer"] == name)


def _run(document: dict, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "layers.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_canonical_layer_dag_passes(canonical_dag, tmp_path):
    result = _run(canonical_dag, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "canonical layer DAG validated" in result.stdout


def test_dependency_cycle_fails(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "global")["depends_on"] = ["network"]

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "cycle" in result.stderr


def test_required_contract_without_producer_fails(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["produces_contract"] = None

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "must be exactly network/v2" in result.stderr


def test_data_foundation_v2_is_produced_and_required_by_consumers(
    canonical_dag,
    tmp_path,
):
    data_foundation = _layer(canonical_dag, "data-foundation")
    assert data_foundation["produces_contract"] == "data-foundation/v2"
    assert "data-foundation/v2" in _layer(canonical_dag, "cicd")[
        "requires_contracts"
    ]
    assert "data-foundation/v2" in _layer(canonical_dag, "services")[
        "requires_contracts"
    ]

    document = copy.deepcopy(canonical_dag)
    _layer(document, "data-foundation")[
        "produces_contract"
    ] = "data-foundation/v1"

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "must be exactly data-foundation/v2" in result.stderr


def test_missing_root_fails(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["root"] = "roots/not-a-real-layer"

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "root does not exist" in result.stderr


def test_duplicate_state_key_fails(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "platform")["state_key"] = _layer(document, "network")["state_key"]

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "duplicates state" in result.stderr


def test_services_must_require_image_digests(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "services")["artifact_dependencies"] = ["release-manifest"]

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "image-digests" in result.stderr


def test_identity_control_plane_is_a_mandatory_services_boundary(
    canonical_dag,
    tmp_path,
):
    document = copy.deepcopy(canonical_dag)
    services = _layer(document, "services")
    services["depends_on"] = ["artifact-publication"]
    services["requires_contracts"].remove("identity-control-plane/v1")

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "services must run after identity-control-plane" in result.stderr
    assert "services must require identity-control-plane/v1" in result.stderr


def test_identity_control_plane_uses_dedicated_role_templates(
    canonical_dag,
    tmp_path,
):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "identity-control-plane")["apply_role"] = (
        "ScanalyzeCustomer-Apply"
    )

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert (
        "identity-control-plane.apply_role must be "
        "ScanalyzeCustomer-Identity-Apply"
    ) in result.stderr


def test_identity_control_plane_requires_reviewed_m2m_registry_contract(
    canonical_dag,
    tmp_path,
):
    identity = _layer(canonical_dag, "identity-control-plane")
    assert "identity-contract/v2" in identity["requires_contracts"]

    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["requires_contracts"].append(
        "identity-contract/v2"
    )

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "requires contract identity-contract/v2 with no producer" in result.stderr


def test_edge_must_be_downstream_of_services(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    edge_identity = _layer(document, "edge-identity")
    edge_identity["depends_on"] = ["global"]
    edge_identity["requires_contracts"] = ["global/v1"]

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "edge must run after services" in result.stderr


def test_account_ready_gate_cannot_apply_or_destroy(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    gate = _layer(document, "account-ready-gate")
    gate["allowed_operations"].append("terraform-apply-saved-plan")

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "must not allow apply or destroy" in result.stderr


def test_terraform_state_key_must_match_exact_canonical_template(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["state_key"] = (
        "prefix/{deployment_id}/{region}/network/terraform.tfstate"
    )

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "must match the canonical template" in result.stderr


def test_stage_roles_are_exact(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["apply_role"] = "OverprivilegedAdmin"

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "network.apply_role must be ScanalyzeCustomer-Apply" in result.stderr


def test_noncanonical_alias_is_rejected(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    network = _layer(document, "network")
    network["required_contracts"] = network.pop("requires_contracts")

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "missing fields: requires_contracts" in result.stderr
    assert "unknown fields: required_contracts" in result.stderr


def test_unapproved_external_contract_fails(canonical_dag, tmp_path):
    document = copy.deepcopy(canonical_dag)
    _layer(document, "network")["requires_contracts"].append("unknown/v1")

    result = _run(document, tmp_path)

    assert result.returncode == 1
    assert "no producer" in result.stderr
