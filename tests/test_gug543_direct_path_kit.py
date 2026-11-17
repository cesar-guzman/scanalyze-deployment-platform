"""GUG-543 — the direct-path kit renders complete, self-consistent tfvars.

These offline checks render every direct-path root from the example config
(deployment/direct-path/deployment.example.yaml) and synthetic
`terraform output -json` fixtures (tests/fixtures/direct_path), then compare
each result with the root's own variables.tf. Terraform is not needed;
scripts/deployment/direct-path-selfcheck.sh runs the same tfvars through
`terraform test` with mock providers.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
KIT_PATH = REPO_ROOT / "scripts" / "deployment" / "direct-path.py"
EXAMPLE_CONFIG = REPO_ROOT / "deployment" / "direct-path" / "deployment.example.yaml"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "direct_path"
LAYERS_FILE = REPO_ROOT / "deployment" / "layers.yaml"

ORDER = (
    "global",
    "network",
    "platform",
    "data-foundation",
    "cicd",
    "identity-control-plane",
    "addons",
    "services",
    "edge-identity",
    "edge",
)
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _load_kit():
    spec = importlib.util.spec_from_file_location("direct_path_kit", KIT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


KIT = _load_kit()
from tooling.validate_digest import canonicalize, compute_digest  # noqa: E402


def _declared(layer: str) -> dict[str, bool]:
    """Independent of the kit: terraform fmt puts top-level blocks and their attributes at fixed indents."""
    text = (REPO_ROOT / "roots" / layer / "variables.tf").read_text(encoding="utf-8")
    blocks = re.findall(r'(?ms)^variable "([^"]+)" \{\n(.*?)^\}', text)
    return {name: bool(re.search(r"(?m)^  default\s*=", body)) for name, body in blocks}


def _workspace(base: Path) -> dict[str, Path]:
    config_dir = base / "config"
    outputs = base / "outputs"
    tfvars = base / "tfvars"
    for directory in (config_dir, outputs, tfvars):
        directory.mkdir(parents=True)
    shutil.copy(EXAMPLE_CONFIG, config_dir / "deployment.yaml")
    shutil.copy(FIXTURES / "services.inputs.json", config_dir / "services.inputs.json")
    for path in (FIXTURES / "outputs").glob("*.outputs.json"):
        shutil.copy(path, outputs / path.name)
    return {"config": config_dir / "deployment.yaml", "outputs": outputs, "tfvars": tfvars}


def _render(ws: dict[str, Path], layer: str, out_name: str | None = None) -> tuple[int, Path]:
    out = ws["tfvars"] / (out_name or f"{layer}.tfvars.json")
    code = KIT.main([
        "tfvars", layer,
        "--config", str(ws["config"]),
        "--outputs-dir", str(ws["outputs"]),
        "--out", str(out),
    ])
    return code, out


def _edit_config(ws: dict[str, Path], mutate) -> None:
    data = yaml.safe_load(ws["config"].read_text(encoding="utf-8"))
    mutate(data)
    ws["config"].write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _contract_outputs(ws: dict[str, Path], layer: str) -> dict:
    document = json.loads((ws["outputs"] / f"{layer}.outputs.json").read_text(encoding="utf-8"))
    return document["contract_payload"]["value"]["outputs"]


@pytest.fixture(scope="module")
def rendered(tmp_path_factory) -> dict:
    ws = _workspace(tmp_path_factory.mktemp("direct-path"))
    values = {}
    for layer in ORDER:
        code, out = _render(ws, layer)
        assert code == 0, f"{layer} did not render"
        values[layer] = json.loads(out.read_text(encoding="utf-8"))
    return {"ws": ws, "values": values}


@pytest.fixture
def ws(tmp_path) -> dict[str, Path]:
    return _workspace(tmp_path)


def test_order_matches_the_audited_direct_path_and_layers_yaml():
    assert KIT.DIRECT_PATH_ORDER == ORDER
    declared = {record["layer"]: record for record in yaml.safe_load(LAYERS_FILE.read_text())["layers"]}
    for layer in ORDER:
        assert declared[layer]["root"] == f"roots/{layer}"
        assert declared[layer]["state_key"]
    for skipped in ("account-ready-gate", "platform-authority"):
        assert skipped not in ORDER


def test_each_layer_reads_only_earlier_layers_outputs():
    assert {layer: KIT.upstream_layers(layer) for layer in ORDER} == {
        "global": [],
        "network": ["global"],
        "platform": ["network"],
        "data-foundation": ["platform"],
        "cicd": ["platform", "data-foundation"],
        "identity-control-plane": ["global"],
        # edge/v2 is applied after addons on the direct path, so addons self-attests it.
        "addons": [],
        "services": ["global", "network", "platform", "data-foundation", "cicd", "identity-control-plane"],
        "edge-identity": ["network", "platform", "identity-control-plane", "services"],
        "edge": ["edge-identity"],
    }


@pytest.mark.parametrize("layer", ORDER)
def test_kit_variable_parser_agrees_with_the_roots(layer):
    parsed = {name: info.has_default for name, info in KIT.root_variables(layer).items()}
    assert parsed == _declared(layer)


@pytest.mark.parametrize("layer", ORDER)
def test_rendered_tfvars_set_every_required_and_no_undeclared_variable(rendered, layer):
    values = rendered["values"][layer]
    declared = _declared(layer)
    required = {name for name, has_default in declared.items() if not has_default}
    assert required <= set(values), f"missing: {sorted(required - set(values))}"
    assert set(values) <= set(declared), f"undeclared: {sorted(set(values) - set(declared))}"


@pytest.mark.parametrize("layer", ORDER)
def test_rendered_digest_pairs_are_self_consistent(rendered, layer):
    values = rendered["values"][layer]
    pairs = 0
    for name, value in values.items():
        if name == "expected_upstream_digest":
            assert value == values["upstream_contract_digest"]
            pairs += 1
        elif name.startswith("expected_") and name.endswith("_digest"):
            assert values[name[len("expected_"):-len("_digest")]]["contract_digest"] == value
            pairs += 1
        if name.endswith("_digest") and isinstance(value, str):
            assert SHA256.fullmatch(value), name
    assert pairs >= 1


@pytest.mark.parametrize("layer", ORDER)
def test_upstream_schema_version_is_accepted_by_the_root_default(rendered, layer):
    values = rendered["values"][layer]
    if "upstream_schema_version" not in values or "accepted_schema_versions" not in _declared(layer):
        return
    text = (REPO_ROOT / "roots" / layer / "variables.tf").read_text(encoding="utf-8")
    default = re.search(r'(?ms)^variable "accepted_schema_versions" \{.*?^  default\s*=\s*(\[[^\]]*\])', text).group(1)
    assert values["upstream_schema_version"] in json.loads(default)


def test_upstream_digests_follow_the_publisher_rule(rendered):
    ws, values = rendered["ws"], rendered["values"]

    def digest(layer: str) -> str:
        return compute_digest(canonicalize(_contract_outputs(ws, layer)))

    assert values["network"]["upstream_contract_digest"] == digest("global")
    assert values["platform"]["upstream_contract_digest"] == digest("network")
    assert values["data-foundation"]["upstream_contract_digest"] == digest("platform")
    assert values["cicd"]["upstream_contract_digest"] == digest("data-foundation")
    assert values["identity-control-plane"]["expected_global_contract_digest"] == digest("global")
    assert values["services"]["upstream_contract_digest"] == digest("data-foundation")
    assert values["services"]["expected_identity_control_plane_contract_digest"] == digest("identity-control-plane")
    edge_identity = values["edge-identity"]
    assert edge_identity["expected_network_contract_digest"] == digest("network")
    assert edge_identity["expected_platform_contract_digest"] == digest("platform")
    assert edge_identity["expected_services_contract_digest"] == digest("services")
    assert edge_identity["expected_identity_contract_digest"] == digest("identity-control-plane")
    assert values["edge"]["upstream_contract_digest"] == digest("edge-identity")


def test_contract_projections_match_the_orchestrator_envelope(rendered):
    values = rendered["values"]
    ws = rendered["ws"]
    release = values["global"]["release_manifest_digest"]
    network = values["edge-identity"]["network_contract"]
    assert {key: network[key] for key in ("contract_id", "schema_version", "customer_id", "deployment_id", "account_id", "region", "release_manifest_digest")} == {
        "contract_id": "network/v2",
        "schema_version": "2",
        "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "account_id": "123456789012",
        "region": "us-east-1",
        "release_manifest_digest": release,
    }
    assert network["vpc_id"] == _contract_outputs(ws, "network")["vpc_id"]
    global_contract = values["identity-control-plane"]["global_contract"]
    assert (global_contract["contract_id"], global_contract["schema_version"], global_contract["region"]) == ("global/v1", "1", "global")
    identity = values["services"]["identity_control_plane_contract"]
    assert (identity["contract_id"], identity["schema_version"]) == ("identity-control-plane/v1", "1")
    assert identity["human_runtime_provisioning_enabled"] is False
    assert values["services"]["workload_role_arns"] == _contract_outputs(ws, "global")["ecs_task_role_arns"]


def test_release_digest_is_deterministic_recorded_and_shared(rendered):
    ws, values = rendered["ws"], rendered["values"]
    record = json.loads((ws["outputs"] / "direct-path-release.json").read_text(encoding="utf-8"))
    config = KIT.load_config(ws["config"])
    assert record["release_manifest_digest"] == KIT.release_manifest_digest(config) == KIT.release_manifest_digest(KIT.load_config(ws["config"]))
    assert record["self_attested"] is True
    digests = {values[layer]["release_manifest_digest"] for layer in ORDER if "release_manifest_digest" in values[layer]}
    assert digests == {record["release_manifest_digest"]}
    assert values["identity-control-plane"]["release_manifest_contract"]["manifest_digest"] == record["release_manifest_digest"]


def test_self_attested_identity_inputs_are_exact(rendered):
    values = rendered["values"]["identity-control-plane"]
    contract = values["release_manifest_contract"]
    body = {key: value for key, value in contract.items() if key != "contract_digest"}
    assert contract["contract_digest"] == compute_digest(canonicalize(body))
    assert (contract["contract_id"], contract["schema_version"]) == ("release-manifest/v1", "1")
    artifact = contract["pre_token_artifact"]
    assert artifact == contract["control_processor_artifact"]
    hex_digest = re.search(r"sha256-([0-9a-f]{64})", artifact["key"]).group(1)
    assert base64.b64decode(artifact["sha256_b64"]) == bytes.fromhex(hex_digest)

    registry = values["m2m_registry_contract"]
    body = {key: value for key, value in registry.items() if key != "contract_digest"}
    assert registry["contract_digest"] == compute_digest(canonicalize(body))
    assert registry["action_scope_sets"] == {
        "read": ["scanalyze.api.v1/read"],
        "write": ["scanalyze.api.v1/write"],
        "admin": ["scanalyze.api.v1/admin"],
    }
    assert values["policy_version"] == "1.0.0"
    assert values["policy_digest"] == "sha256:34a639992f6c2312176ac7dc12c361daa38201adea6af0c0b1765a17a14754f8"
    assert values["control_processor_enabled"] is True


def test_layer_specific_inputs(rendered):
    values = rendered["values"]
    assert values["cicd"]["enable_codecommit"] is False
    assert values["cicd"]["enable_codepipeline"] is False
    assert {svc["ecr_repo_name"] for svc in values["cicd"]["microservices"].values()} == {
        f"scanalyze/{name}" for name in values["cicd"]["microservices"]
    }
    assert values["edge-identity"]["legacy_identity_handoff_complete"] is True
    assert values["edge-identity"]["cors_allowed_origins"] == ["https://pilot.synthetic.example"]
    assert values["edge"]["frontend_bucket_domain_name"] == "scanalyze-123456789012-frontend.s3.us-east-1.amazonaws.com"
    assert re.fullmatch(r"v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", values["edge"]["release_version"])
    assert values["addons"]["upstream_schema_version"] == "2"
    if "browser_origins" in _declared("data-foundation"):  # PR #136
        assert values["data-foundation"]["browser_origins"] == ["https://pilot.synthetic.example"]
    else:
        assert "browser_origins" not in values["data-foundation"]
    if "runtime_wiring" in _declared("services"):  # PR #135
        assert values["services"]["runtime_wiring"]["stage_queue_urls"] == _contract_outputs(rendered["ws"], "data-foundation")["sqs_queue_urls"]
    else:
        assert "runtime_wiring" not in values["services"]


@pytest.mark.parametrize("layer", ORDER)
def test_backend_key_matches_layers_yaml(ws, layer, tmp_path):
    record = next(item for item in yaml.safe_load(LAYERS_FILE.read_text())["layers"] if item["layer"] == layer)
    expected_key = record["state_key"].replace("{deployment_id}", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV").replace("{region}", "us-east-1")
    out = tmp_path / f"{layer}.backend.hcl"
    assert KIT.main(["backend", layer, "--config", str(ws["config"]), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert f'key                 = "{expected_key}"' in text
    for line in (
        'bucket              = "scanalyze-123456789012-direct-tfstate"',
        'region              = "us-east-1"',
        "encrypt             = true",
        "use_lockfile        = true",
        'allowed_account_ids = ["123456789012"]',
    ):
        assert line in text
    # Re-rendering identical content is a no-op; different content is refused.
    assert KIT.main(["backend", layer, "--config", str(ws["config"]), "--out", str(out)]) == 0
    out.write_text(text + "# edited\n", encoding="utf-8")
    assert KIT.main(["backend", layer, "--config", str(ws["config"]), "--out", str(out)]) == 1
    assert out.read_text(encoding="utf-8").endswith("# edited\n")


@pytest.mark.parametrize("layer", ("account-ready-gate", "platform-authority", "unknown"))
def test_layers_outside_the_direct_path_are_refused(ws, layer, capsys):
    assert _render(ws, layer)[0] == 1
    assert "FAIL" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("layer", "missing"),
    [
        ("network", "global"),
        ("platform", "network"),
        ("cicd", "data-foundation"),
        ("identity-control-plane", "global"),
        ("services", "cicd"),
        ("services", "identity-control-plane"),
        ("edge-identity", "services"),
        ("edge", "edge-identity"),
    ],
)
def test_missing_upstream_outputs_fail_closed(ws, layer, missing, capsys):
    assert _render(ws, "global")[0] == 0
    (ws["outputs"] / f"{missing}.outputs.json").unlink()
    code, out = _render(ws, layer)
    assert code == 1
    assert not out.exists()
    assert f"upstream outputs for {missing} are missing" in capsys.readouterr().err


def test_outputs_without_a_contract_payload_fail_closed(ws, capsys):
    assert _render(ws, "global")[0] == 0
    (ws["outputs"] / "network.outputs.json").write_text('{"vpc_id": {"sensitive": false, "value": "vpc-0"}}\n')
    assert _render(ws, "platform")[0] == 1
    assert "no contract_payload output" in capsys.readouterr().err


def test_outputs_from_another_account_fail_closed(ws, capsys):
    assert _render(ws, "global")[0] == 0
    path = ws["outputs"] / "network.outputs.json"
    document = json.loads(path.read_text())
    document["contract_payload"]["value"]["outputs"]["vpc_endpoint_sg_id"] = "arn:aws:ec2:us-east-1:210987654321:security-group/sg-0"
    path.write_text(json.dumps(document))
    assert _render(ws, "platform")[0] == 1
    assert "belongs to account 210987654321" in capsys.readouterr().err


def test_existing_out_is_never_overwritten(ws, capsys):
    out = ws["tfvars"] / "global.tfvars.json"
    out.write_text("keep me\n", encoding="utf-8")
    assert _render(ws, "global")[0] == 1
    assert out.read_text(encoding="utf-8") == "keep me\n"
    assert "refusing to overwrite" in capsys.readouterr().err
    assert not (ws["outputs"] / "direct-path-release.json").exists()


def test_out_must_be_a_tfvars_json_file(ws, capsys):
    assert _render(ws, "global", out_name="global.tfvars")[0] == 1
    assert ".tfvars.json" in capsys.readouterr().err


def test_release_record_is_required_and_pins_the_config(ws, capsys):
    assert _render(ws, "network")[0] == 1
    assert "render global first" in capsys.readouterr().err
    assert _render(ws, "global")[0] == 0
    _edit_config(ws, lambda data: data.update(release_version="0.1.0-pilot.2"))
    assert _render(ws, "network")[0] == 1
    assert "records a different deployment or release" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("layer", "key", "mutate"),
    [
        ("global", "release_version", lambda data: data.pop("release_version")),
        ("platform", "internal_certificate_arn", lambda data: data.pop("internal_certificate_arn")),
        ("cicd", "microservices", lambda data: data.pop("microservices")),
        ("identity-control-plane", "identity.lambda_artifact", lambda data: data["identity"].pop("lambda_artifact")),
        ("services", "services.inputs_file", lambda data: data.pop("services")),
        ("edge-identity", "api_access_log_group_arn", lambda data: data.pop("api_access_log_group_arn")),
        ("edge-identity", "edge_identity.api_authorization_routes", lambda data: data["edge_identity"].pop("api_authorization_routes")),
        ("edge", "route53_zone_id", lambda data: data.pop("route53_zone_id")),
    ],
)
def test_missing_config_values_fail_closed(ws, layer, key, mutate, capsys):
    if layer != "global":
        assert _render(ws, "global")[0] == 0
    _edit_config(ws, mutate)
    code, out = _render(ws, layer)
    assert code == 1
    assert not out.exists()
    assert repr(key) in capsys.readouterr().err


def test_missing_services_inputs_file_fails_closed(ws, capsys):
    assert _render(ws, "global")[0] == 0
    (ws["config"].parent / "services.inputs.json").unlink()
    assert _render(ws, "services")[0] == 1
    assert "render-direct-service-definitions.py" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update(environment="production"), "non-production only"),
        (lambda data: data.update(release_version="pilot-1"), "release_version"),
        (lambda data: data.update(account_id=123456789012), "quote it"),
        (lambda data: data.update(unexpected=True), "unknown config keys"),
        (lambda data: data.update(internal_certificate_arn="arn:aws:acm:us-west-2:123456789012:certificate/00000000-0000-4000-8000-000000000000"), "internal_certificate_arn"),
        (lambda data: data["identity"]["lambda_artifact"].update(key="identity/lambda.zip"), "sha256-<64 lowercase hex>"),
        (lambda data: data["identity"]["lambda_artifact"].update(object_version="null"), "VersionId"),
        (lambda data: data["identity"]["lambda_artifact"].update(sha256_b64=base64.b64encode(b"0" * 32).decode()), "does not match"),
        (lambda data: data["edge_identity"].update(legacy_identity_handoff_complete=False), "must be true"),
        (lambda data: data["edge_identity"]["api_authorization_routes"].update({"GET /api/v1/x": ["scanalyze.api.v1/read", "scanalyze.api.v1/admin"]}), "exactly one"),
        (lambda data: data["microservices"]["ocr-worker"].update(ecr_repo_name="ocr-worker"), "scanalyze/ocr-worker"),
    ],
)
def test_invalid_config_values_fail_closed(ws, mutate, message, capsys):
    _edit_config(ws, mutate)
    assert _render(ws, "global")[0] == 1
    assert message in capsys.readouterr().err


def test_network_refuses_regions_without_the_default_az_ids(ws, capsys):
    def to_us_west_2(data):
        data["region"] = "us-west-2"
        data["internal_certificate_arn"] = data["internal_certificate_arn"].replace("us-east-1", "us-west-2")
        data["api_access_log_group_arn"] = data["api_access_log_group_arn"].replace("us-east-1", "us-west-2")

    _edit_config(ws, to_us_west_2)
    assert _render(ws, "global")[0] == 0
    assert _render(ws, "network")[0] == 1
    assert "use1-az1" in capsys.readouterr().err


def test_services_images_must_come_from_the_deployment_ecr(ws, capsys):
    assert _render(ws, "global")[0] == 0
    path = ws["config"].parent / "services.inputs.json"
    document = json.loads(path.read_text())
    document["service_definitions"][0]["image"] = "public.ecr.aws/other/ingest-api@sha256:" + "a" * 64
    path.write_text(json.dumps(document))
    assert _render(ws, "services")[0] == 1
    assert "ECR repositories" in capsys.readouterr().err


def test_ocr_poller_requires_the_runtime_wiring_input(ws, monkeypatch, capsys):
    assert _render(ws, "global")[0] == 0
    path = ws["config"].parent / "services.inputs.json"
    document = json.loads(path.read_text())
    poller = dict(next(item for item in document["service_definitions"] if item["name"] == "scanalyze-ocr-worker"))
    poller["name"] = "scanalyze-ocr-poll-worker"
    document["service_definitions"].append(poller)
    path.write_text(json.dumps(document))
    declared = KIT.root_variables("services")
    without = {name: info for name, info in declared.items() if name != "runtime_wiring"}
    monkeypatch.setattr(KIT, "root_variables", lambda layer, roots_dir=KIT.ROOTS_DIR: without if layer == "services" else declared_for(layer))
    assert _render(ws, "services")[0] == 1
    assert "--without-ocr-poller" in capsys.readouterr().err

    with_wiring = dict(without, runtime_wiring=KIT.VariableInfo("runtime_wiring", True, None))
    monkeypatch.setattr(KIT, "root_variables", lambda layer, roots_dir=KIT.ROOTS_DIR: with_wiring if layer == "services" else declared_for(layer))
    code, out = _render(ws, "services", out_name="services.poller.tfvars.json")
    assert code == 0
    values = json.loads(out.read_text())
    assert "scanalyze-ocr-poll-worker" in {item["name"] for item in values["service_definitions"]}
    assert values["runtime_wiring"]["runtime_environment"] == "dev"
    assert set(values["runtime_wiring"]["stage_queue_urls"]) == KIT.QUEUE_STAGES


_ORIGINAL_ROOT_VARIABLES = KIT.root_variables


def declared_for(layer):
    return _ORIGINAL_ROOT_VARIABLES(layer)


def test_optional_inputs_are_emitted_only_when_declared(ws, monkeypatch):
    assert _render(ws, "global")[0] == 0
    data_foundation = dict(declared_for("data-foundation"))
    data_foundation["browser_origins"] = KIT.VariableInfo("browser_origins", True, [])
    monkeypatch.setattr(KIT, "root_variables", lambda layer, roots_dir=KIT.ROOTS_DIR: data_foundation if layer == "data-foundation" else declared_for(layer))
    code, out = _render(ws, "data-foundation", out_name="df.declared.tfvars.json")
    assert code == 0
    assert json.loads(out.read_text())["browser_origins"] == ["https://pilot.synthetic.example"]

    data_foundation.pop("browser_origins")
    code, out = _render(ws, "data-foundation", out_name="df.undeclared.tfvars.json")
    assert code == 0
    assert "browser_origins" not in json.loads(out.read_text())


def test_m2m_binding_flows_from_config_to_services_and_edge_identity(ws):
    client = "7example0m2m0client000000a"
    scopes = ["scanalyze.api.v1/read", "scanalyze.api.v1/write"]
    _edit_config(ws, lambda data: data["identity"].update(m2m_bindings=[{"client_id": client, "required_scopes": scopes}]))
    assert _render(ws, "global")[0] == 0
    code, out = _render(ws, "identity-control-plane")
    assert code == 0
    registry = json.loads(out.read_text())["m2m_registry_contract"]
    binding = {"client_id": client, "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV", "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV", "required_scopes": scopes}
    assert registry["m2m_bindings"] == [binding]

    # After the identity re-apply, its saved outputs carry the binding.
    path = ws["outputs"] / "identity-control-plane.outputs.json"
    document = json.loads(path.read_text())
    outputs = document["contract_payload"]["value"]["outputs"]
    outputs["m2m_bindings"] = [binding]
    outputs["m2m_client_ids"] = [client]
    path.write_text(json.dumps(document))
    for layer in ("services", "edge-identity"):
        code, out = _render(ws, layer)
        assert code == 0
        values = json.loads(out.read_text())
        contract = values["identity_control_plane_contract" if layer == "services" else "identity_contract"]
        assert contract["m2m_client_ids"] == [client]
        assert contract["contract_digest"] == compute_digest(canonicalize(outputs))


def test_example_config_documents_every_owner_input():
    config = yaml.safe_load(EXAMPLE_CONFIG.read_text(encoding="utf-8"))
    for key in (
        "customer_id", "deployment_id", "account_id", "region", "environment", "release_version",
        "domain_name", "route53_zone_id", "state_bucket", "alb_tls_server_name",
        "internal_certificate_arn", "api_access_log_group_arn", "microservices",
    ):
        assert config.get(key) is not None, key
    assert set(config["identity"]["lambda_artifact"]) == {"bucket", "key", "object_version"}
    assert config["identity"]["m2m_bindings"] == []
    assert all(value["ecr_repo_name"] == f"scanalyze/{name}" for name, value in config["microservices"].items())
