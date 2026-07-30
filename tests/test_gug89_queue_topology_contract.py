"""Offline contract and migration-safety tests for the GUG-89 queue boundary.

These checks intentionally inspect declarative source and synthetic JSON only.
They do not initialize Terraform providers or inspect a live AWS account.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
LOCALS_TF = REPO_ROOT / "modules" / "data-foundation" / "locals.tf"
CONTRACT_TF = REPO_ROOT / "modules" / "data-foundation" / "contract.tf"
SQS_TF = REPO_ROOT / "modules" / "data-foundation" / "sqs.tf"
OUTPUTS_TF = REPO_ROOT / "modules" / "data-foundation" / "outputs.tf"
ROOT_OUTPUTS_TF = REPO_ROOT / "roots" / "data-foundation" / "outputs.tf"
LAYERS_YAML = REPO_ROOT / "deployment" / "layers.yaml"
SERVICES_CONTRACT_GATE = REPO_ROOT / "roots" / "services" / "contract_validation.tf"
SERVICES_VARIABLES = REPO_ROOT / "roots" / "services" / "variables.tf"
CICD_CONTRACT_GATE = REPO_ROOT / "roots" / "cicd" / "contract_validation.tf"
CICD_VARIABLES = REPO_ROOT / "roots" / "cicd" / "variables.tf"
V1_SCHEMA_PATH = REPO_ROOT / "schemas" / "contract-data-foundation.v1.schema.json"
V1_FIXTURE_PATH = REPO_ROOT / "fixtures" / "valid" / "contract-data-foundation-v1.json"
V2_SCHEMA_PATH = REPO_ROOT / "schemas" / "contract-data-foundation.v2.schema.json"
V2_FIXTURE_PATH = REPO_ROOT / "fixtures" / "valid" / "contract-data-foundation-v2.json"
LAYER_CONTRACT_SCHEMA_PATH = REPO_ROOT / "schemas" / "layer-contract.schema.json"
PUBLISH_CONTRACT = REPO_ROOT / "scripts" / "deployment" / "publish-contract.py"
VALIDATE_SCHEMA = REPO_ROOT / "tooling" / "validate_schema.py"

CANONICAL_STAGES = {
    "ingest",
    "ocr",
    "classify",
    "bank-extract",
    "personal-extract",
    "gov-extract",
    "validate",
    "persist",
    "notify",
}
LEGACY_WORKERS = {"ocr", "postprocess", "classifier", "bank", "personal", "gov"}
QUEUE_MAP_FIELDS = (
    "sqs_queue_urls",
    "sqs_queue_arns",
    "sqs_dlq_urls",
    "sqs_dlq_arns",
)
V2_REQUIRED_FIELDS = {
    "documents_table_name",
    "documents_table_arn",
    "jobs_table_name",
    "documents_bucket_name",
    "documents_bucket_arn",
    "data_kms_key_arn",
    *QUEUE_MAP_FIELDS,
    "queue_topology",
}


def _topology_entries(source: str) -> dict[str, str]:
    marker = "queue_topology = {"
    assert marker in source, "data-foundation must declare local.queue_topology"
    block = source.split(marker, 1)[1].split("\n  }", 1)[0]
    matches = list(
        re.finditer(
            r'^    "?([a-z][a-z0-9-]*)"?\s*=\s*\{\s*$',
            block,
            flags=re.MULTILINE,
        )
    )
    entries: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
        entries[match.group(1)] = block[match.end() : end]
    return entries


def _validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _publisher_module():
    spec = importlib.util.spec_from_file_location("gug89_publish_contract", PUBLISH_CONTRACT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema_validator_module():
    spec = importlib.util.spec_from_file_location(
        "gug89_validate_schema", VALIDATE_SCHEMA
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_canonical_stage_has_one_complete_consumer_binding() -> None:
    entries = _topology_entries(LOCALS_TF.read_text(encoding="utf-8"))

    assert set(entries) == CANONICAL_STAGES
    for stage, body in entries.items():
        assert re.search(r"producers\s*=\s*\[[^\]]+\]", body), stage
        assert re.search(r'consumer\s*=\s*"[a-z][a-z0-9-]+"', body), stage
        assert re.search(r'consumer_mode\s*=\s*"[A-Z][A-Z0-9_]+"', body), stage
        assert re.search(r'queue_type\s*=\s*"standard"', body), stage
        assert re.search(r"visibility_timeout_seconds\s*=\s*300", body), stage
        assert re.search(r"max_receive_count\s*=\s*3", body), stage


def test_legacy_resource_addresses_names_and_keys_are_preserved() -> None:
    locals_source = LOCALS_TF.read_text(encoding="utf-8")
    sqs_source = SQS_TF.read_text(encoding="utf-8")

    legacy_block = locals_source.split("legacy_worker_queues = toset([", 1)[1].split(
        "])", 1
    )[0]
    assert set(re.findall(r'"([a-z-]+)"', legacy_block)) == LEGACY_WORKERS
    assert sqs_source.count("for_each = local.legacy_worker_queues") == 2
    assert 'resource "aws_sqs_queue" "worker"' in sqs_source
    assert 'resource "aws_sqs_queue" "dlq"' in sqs_source
    assert 'name                       = "${var.deployment_id}-${each.key}-queue"' in sqs_source
    assert 'name                      = "${var.deployment_id}-${each.key}-dlq"' in sqs_source
    assert sqs_source.count("prevent_destroy = true") == 2


def test_stage_resources_are_additive_and_cannot_collide_with_legacy_names() -> None:
    source = SQS_TF.read_text(encoding="utf-8")

    assert 'resource "aws_sqs_queue" "stage"' in source
    assert 'resource "aws_sqs_queue" "stage_dlq"' in source
    assert 'resource "aws_sqs_queue_redrive_allow_policy" "stage_dlq"' in source
    assert source.count("for_each = local.queue_topology") == 3
    assert 'name                       = "${var.deployment_id}-${each.key}-stage-queue"' in source
    assert 'name                      = "${var.deployment_id}-${each.key}-stage-dlq"' in source
    assert "visibility_timeout_seconds = each.value.visibility_timeout_seconds" in source
    assert "maxReceiveCount     = each.value.max_receive_count" in source
    assert 'redrivePermission = "byQueue"' in source
    assert re.search(
        r"sourceQueueArns\s*=\s*\[aws_sqs_queue\.stage\[each\.key\]\.arn\]",
        source,
    )


def test_canonical_outputs_use_stage_resources_and_deprecated_outputs_use_legacy() -> None:
    source = OUTPUTS_TF.read_text(encoding="utf-8")
    root_source = ROOT_OUTPUTS_TF.read_text(encoding="utf-8")

    assert "aws_sqs_queue.stage : k => v.url" in source
    assert "aws_sqs_queue.stage : k => v.arn" in source
    assert "aws_sqs_queue.stage_dlq : k => v.url" in source
    assert "aws_sqs_queue.stage_dlq : k => v.arn" in source
    assert "aws_sqs_queue.worker : k => v.url" in source
    assert "aws_sqs_queue.worker : k => v.arn" in source
    assert "aws_sqs_queue.dlq : k => v.arn" in source

    for output_name in V2_REQUIRED_FIELDS:
        assert re.search(rf'output\s+"{output_name}"\s*\{{', root_source)
        assert f"module.data_foundation.{output_name}" in root_source


def test_v1_schema_and_fixture_remain_the_legacy_contract() -> None:
    schema = json.loads(V1_SCHEMA_PATH.read_text(encoding="utf-8"))
    fixture = json.loads(V1_FIXTURE_PATH.read_text(encoding="utf-8"))

    _validator(V1_SCHEMA_PATH).validate(fixture)
    assert schema["$id"] == "scanalyze.contract.data-foundation.v1"
    assert "queue_topology" not in schema["properties"]
    assert "sqs_queue_arns" not in schema["properties"]
    assert set(schema["properties"]["sqs_queue_urls"]["properties"]) == LEGACY_WORKERS


def test_v2_schema_and_fixture_require_the_complete_closed_contract() -> None:
    schema = json.loads(V2_SCHEMA_PATH.read_text(encoding="utf-8"))
    fixture = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))

    _validator(V2_SCHEMA_PATH).validate(fixture)
    assert schema["$id"] == "scanalyze.contract.data-foundation.v2"
    assert set(schema["required"]) == V2_REQUIRED_FIELDS
    assert set(fixture) == V2_REQUIRED_FIELDS
    assert schema["additionalProperties"] is False

    for field in QUEUE_MAP_FIELDS:
        assert set(fixture[field]) == CANONICAL_STAGES
        stage_map = schema["$defs"][
            "stage_url_map" if field.endswith("urls") else "stage_arn_map"
        ]
        assert set(stage_map["required"]) == CANONICAL_STAGES
        assert set(stage_map["properties"]) == CANONICAL_STAGES
        assert stage_map["additionalProperties"] is False

    topology = schema["$defs"]["topology"]
    assert set(topology["required"]) == CANONICAL_STAGES
    assert set(topology["properties"]) == CANONICAL_STAGES
    assert topology["additionalProperties"] is False


def test_repository_schema_gate_selects_the_v2_contract_schema() -> None:
    validator = _schema_validator_module()

    selected = validator.find_schema_for_fixture(
        V2_FIXTURE_PATH.name,
        V2_SCHEMA_PATH.parent,
    )

    assert selected == V2_SCHEMA_PATH


def test_v2_fixture_matches_the_real_contract_publisher_input_shape() -> None:
    fixture = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))
    terraform_output = {
        name: {"sensitive": False, "value": value}
        for name, value in fixture.items()
    }
    terraform_output["contract_payload"] = {
        "sensitive": False,
        "value": {
            "schema_version": "2",
            "layer": "data-foundation",
            "state_scope": "regional",
        },
    }

    publisher = _publisher_module()
    outputs = publisher._extract_outputs(
        terraform_output,
        "data-foundation",
        "data-foundation/v2",
    )
    publisher._validate_schema(
        outputs,
        json.loads(V2_SCHEMA_PATH.read_text(encoding="utf-8")),
        "contract outputs",
    )
    assert outputs == fixture

    envelope = publisher._build_envelope(
        SimpleNamespace(
            account_id="123456789012",
            deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            layer="data-foundation",
            module_source_digest=None,
            output_schema_version="data-foundation/v2",
            produced_at="2026-07-12T00:00:00Z",
            producer="roots/data-foundation",
            region="us-east-1",
            release_digest="sha256:" + ("a" * 64),
            scope="regional",
            state_key=(
                "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/us-east-1/"
                "data-foundation/terraform.tfstate"
            ),
            terraform_workspace="default",
        ),
        outputs,
    )
    publisher._validate_schema(
        envelope,
        json.loads(LAYER_CONTRACT_SCHEMA_PATH.read_text(encoding="utf-8")),
        "contract envelope",
    )


@pytest.mark.parametrize("field", sorted(V2_REQUIRED_FIELDS))
def test_v2_rejects_every_missing_top_level_contract_field(field: str) -> None:
    fixture = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture.pop(field)

    with pytest.raises(jsonschema.ValidationError):
        _validator(V2_SCHEMA_PATH).validate(fixture)


@pytest.mark.parametrize("field", QUEUE_MAP_FIELDS)
@pytest.mark.parametrize("stage", sorted(CANONICAL_STAGES))
def test_v2_rejects_every_missing_stage_binding(field: str, stage: str) -> None:
    fixture = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))
    fixture[field].pop(stage)

    with pytest.raises(jsonschema.ValidationError):
        _validator(V2_SCHEMA_PATH).validate(fixture)


def test_v2_rejects_partial_topology_legacy_aliases_and_retry_drift() -> None:
    fixture = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))
    validator = _validator(V2_SCHEMA_PATH)

    missing_stage = copy.deepcopy(fixture)
    missing_stage["queue_topology"].pop("notify")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_stage)

    legacy_alias = copy.deepcopy(fixture)
    legacy_alias["sqs_queue_urls"]["postprocess"] = legacy_alias["sqs_queue_urls"][
        "validate"
    ]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(legacy_alias)

    retry_drift = copy.deepcopy(fixture)
    retry_drift["queue_topology"]["ingest"]["max_receive_count"] = 4
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(retry_drift)


def test_module_declares_data_foundation_v2_without_relabeling_v1() -> None:
    locals_source = LOCALS_TF.read_text(encoding="utf-8")
    contract_source = CONTRACT_TF.read_text(encoding="utf-8")

    assert 'contract_key = "data-foundation/v2"' in locals_source
    assert 'schema_version = "2"' in contract_source
    assert "data-foundation/v2" in contract_source

    envelope_schema = json.loads(
        LAYER_CONTRACT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    versions = envelope_schema["$defs"]["data_foundation_producer"]["properties"][
        "output_schema_version"
    ]["enum"]
    assert versions == ["data-foundation/v1", "data-foundation/v2"]


def test_deployment_dag_routes_data_foundation_v2_to_all_consumers() -> None:
    source = LAYERS_YAML.read_text(encoding="utf-8")

    assert source.count("produces_contract: data-foundation/v2") == 1
    assert source.count("- data-foundation/v2") == 2
    assert "produces_contract: data-foundation/v1" not in source


@pytest.mark.parametrize(
    ("gate_path", "variables_path"),
    (
        (SERVICES_CONTRACT_GATE, SERVICES_VARIABLES),
        (CICD_CONTRACT_GATE, CICD_VARIABLES),
    ),
)
def test_data_foundation_v2_consumers_fail_closed_on_contract_identity(
    gate_path: Path,
    variables_path: Path,
) -> None:
    gate = gate_path.read_text(encoding="utf-8")
    variables = variables_path.read_text(encoding="utf-8")

    assert 'resource "terraform_data" "contract_gate"' in gate
    assert 'var.upstream_contract_id == "data-foundation/v2"' in gate
    assert 'var.upstream_schema_version == "2"' in gate
    assert 'var.upstream_contract_digest != ""' in gate
    assert "var.upstream_contract_digest == var.expected_upstream_digest" in gate
    assert 'variable "upstream_contract_id"' in variables
    assert 'variable "upstream_schema_version"' in variables
    assert not re.search(
        r'variable\s+"upstream_contract_digest"\s*\{[^}]*default\s*=\s*""',
        variables,
        flags=re.DOTALL,
    )
