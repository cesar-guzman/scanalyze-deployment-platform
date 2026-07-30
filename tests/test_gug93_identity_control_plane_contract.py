"""RED contract tests for the additive GUG-93 identity control plane.

These tests are intentionally offline. They validate only versioned JSON
contracts and the canonical deployment DAG; they never initialize a Terraform
provider or contact Cognito/AWS.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from tooling.validate_schema import find_schema_for_fixture, validate_semantics


REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = (
    REPO_ROOT / "policies/authorization/enterprise-authorization.v1.json"
)
IDENTITY_CONTROL_PLANE_SCHEMA = (
    REPO_ROOT / "schemas/contract-identity-control-plane.v1.schema.json"
)
IDENTITY_CONTROL_PLANE_FIXTURE = (
    REPO_ROOT / "fixtures/valid/contract-identity-control-plane-v1.json"
)
EDGE_IDENTITY_V1_SCHEMA = REPO_ROOT / "schemas/contract-edge-identity.v1.schema.json"
EDGE_IDENTITY_V1_FIXTURE = (
    REPO_ROOT / "fixtures/valid/contract-edge-identity-v1.json"
)
EDGE_IDENTITY_V2_SCHEMA = REPO_ROOT / "schemas/contract-edge-identity.v2.schema.json"
EDGE_IDENTITY_V2_FIXTURE = (
    REPO_ROOT / "fixtures/valid/contract-edge-identity-v2.json"
)
LAYER_CONTRACT_SCHEMA = REPO_ROOT / "schemas/layer-contract.schema.json"
LAYERS_YAML = REPO_ROOT / "deployment/layers.yaml"
DAG_VALIDATOR = REPO_ROOT / "scripts/deployment/validate-layer-dag.py"
CONTRACT_PUBLISHER = REPO_ROOT / "scripts/deployment/publish-contract.py"
IDENTITY_CONTROL_PLANE_ROOT_OUTPUTS = (
    REPO_ROOT / "roots/identity-control-plane/outputs.tf"
)
EDGE_IDENTITY_ROOT_OUTPUTS = REPO_ROOT / "roots/edge-identity/outputs.tf"
IDENTITY_CONTROL_PLANE_MODULE_OUTPUTS = (
    REPO_ROOT / "modules/identity-control-plane/outputs.tf"
)
EDGE_IDENTITY_MODULE_OUTPUTS = REPO_ROOT / "modules/edge-identity/contract.tf"

EXPECTED_ACTION_SCOPES = {
    "read": "scanalyze.api.v1/read",
    "write": "scanalyze.api.v1/write",
    "admin": "scanalyze.api.v1/admin",
}
IDENTITY_BINDING_FIELDS = (
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
)
REQUIRED_AUTHORIZATION_FIELDS = (
    "allowed_token_uses",
    "action_scopes",
    "policy_version",
    "policy_digest",
    "policy_canonicalization",
)
M2M_REGISTRY_FIELDS = ("action_scope_sets", "m2m_bindings")
RUNTIME_PROVISIONING_FIELDS = (
    "human_runtime_provisioning_enabled",
    "m2m_runtime_provisioning_enabled",
    "m2m_client_secret_values_exposed",
)
LEGACY_EDGE_V1_PROPERTIES = {
    "cognito_user_pool_id",
    "cognito_user_pool_arn",
    "cognito_spa_client_id",
    "cognito_m2m_client_id",
    "cognito_domain",
    "cognito_issuer_url",
    "api_gateway_id",
    "api_gateway_endpoint",
    "api_gateway_stage",
    "authorizer_type",
    "lambda_authorizer_arn",
}
FORBIDDEN_SECRET_OUTPUT_KEYS = {
    "client_secret",
    "client_secret_value",
    "client_secret_values",
    "generated_password",
    "password",
    "temporary_password",
}


def _load(path: Path) -> dict[str, Any]:
    assert path.is_file(), f"required additive GUG-93 artifact is missing: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def _publisher_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "gug93_contract_publisher",
        CONTRACT_PUBLISHER,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _declared_root_outputs(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    return set(re.findall(r'^output\s+"([^"]+)"\s*\{', source, flags=re.MULTILINE))


def _assert_real_root_outputs_publish_fixture(
    *,
    fixture_path: Path,
    schema_path: Path,
    root_outputs_path: Path,
    module_outputs_path: Path,
    layer: str,
    contract_id: str,
) -> None:
    """Exercise the real publisher boundary, not a synthetic all-fields map.

    GUG-93 publishes one non-sensitive envelope whose ``outputs`` member is the
    flat schema payload. The root must forward the module payload unchanged and
    the module must declare the nested publisher boundary. Terraform mock tests
    exercise the concrete field expressions; this test exercises the real
    publisher/parser and JSON Schema boundary without a provider.
    """

    fixture = _load(fixture_path)
    declared_outputs = _declared_root_outputs(root_outputs_path)
    root_source = root_outputs_path.read_text(encoding="utf-8")
    module_source = module_outputs_path.read_text(encoding="utf-8")
    assert declared_outputs == {"contract_payload"}
    assert re.search(
        r"value\s*=\s*module\.[A-Za-z0-9_]+\.contract_payload",
        root_source,
    )
    assert 'output "contract_payload"' in module_source
    assert re.search(r"\boutputs\s*=\s*\{", module_source)
    terraform_output = {
        name: {"sensitive": False, "value": fixture[name]}
        for name in declared_outputs
        if name != "contract_payload" and name in fixture
    }
    terraform_output["contract_payload"] = {
        "sensitive": False,
        "value": {
            "schema_version": contract_id.rsplit("/v", 1)[-1],
            "layer": layer,
            "state_scope": "regional",
            "outputs": fixture,
        },
    }

    publisher = _publisher_module()
    outputs = publisher._extract_outputs(terraform_output, layer, contract_id)
    publisher._validate_schema(outputs, _load(schema_path), "contract outputs")
    assert outputs == fixture


def _validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = _load(path)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _values_for_key(value: Any, key: str) -> list[Any]:
    values: list[Any] = []
    if isinstance(value, dict):
        for candidate_key, candidate_value in value.items():
            if candidate_key == key:
                values.append(candidate_value)
            values.extend(_values_for_key(candidate_value, key))
    elif isinstance(value, list):
        for item in value:
            values.extend(_values_for_key(item, key))
    return values


def _single_value(value: Any, key: str) -> Any:
    values = _values_for_key(value, key)
    assert len(values) == 1, f"{key} must occur exactly once in the contract"
    return values[0]


def _remove_key(value: Any, key: str) -> None:
    if isinstance(value, dict):
        value.pop(key, None)
        for candidate in value.values():
            _remove_key(candidate, key)
    elif isinstance(value, list):
        for candidate in value:
            _remove_key(candidate, key)


def _replace_key(value: Any, key: str, replacement: Any) -> None:
    if isinstance(value, dict):
        for candidate_key, candidate_value in value.items():
            if candidate_key == key:
                value[candidate_key] = copy.deepcopy(replacement)
            else:
                _replace_key(candidate_value, key, replacement)
    elif isinstance(value, list):
        for candidate in value:
            _replace_key(candidate, key, replacement)


def _assert_field_is_required(
    fixture: dict[str, Any],
    validator: jsonschema.Draft202012Validator,
    field: str,
) -> None:
    candidate = copy.deepcopy(fixture)
    _remove_key(candidate, field)
    assert list(validator.iter_errors(candidate)), f"{field} must be required"


def _walk_object_schemas(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False
        for value in node.values():
            _walk_object_schemas(value)
    elif isinstance(node, list):
        for value in node:
            _walk_object_schemas(value)


def _policy_canonical_bytes(policy: dict[str, Any]) -> bytes:
    """Canonicalize the reviewed policy's RFC 8785-compatible JSON subset.

    The published policy intentionally contains no floating-point values. For
    strings, integers, booleans, arrays, and objects, UTF-8 JSON with sorted
    keys and no insignificant whitespace is the JCS representation used for
    the contract digest.
    """

    def reject_float(value: Any) -> None:
        assert not isinstance(value, float), "policy digest requires exact JCS numbers"
        if isinstance(value, dict):
            for item in value.values():
                reject_float(item)
        elif isinstance(value, list):
            for item in value:
                reject_float(item)

    reject_float(policy)
    return json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _expected_policy_digest() -> str:
    canonical = _policy_canonical_bytes(_load(POLICY_PATH))
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _assert_bound_portable_identity(fixture: dict[str, Any]) -> None:
    customer_id = _single_value(fixture, "customer_id")
    deployment_id = _single_value(fixture, "deployment_id")
    account_id = _single_value(fixture, "account_id")
    region = _single_value(fixture, "region")

    assert re.fullmatch(r"cust_[0-9A-HJKMNP-TV-Z]{26}", customer_id)
    assert re.fullmatch(r"dep_[0-9A-HJKMNP-TV-Z]{26}", deployment_id)
    assert customer_id != deployment_id
    assert re.fullmatch(r"[0-9]{12}", account_id)
    assert re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-[0-9]+", region)


def _assert_access_only_authorization(fixture: dict[str, Any]) -> None:
    assert _single_value(fixture, "allowed_token_uses") == ["access"]
    assert _single_value(fixture, "action_scopes") == EXPECTED_ACTION_SCOPES
    if "action_scope_sets" in fixture:
        assert fixture["action_scope_sets"] == {
            action: [scope] for action, scope in EXPECTED_ACTION_SCOPES.items()
        }
    assert _single_value(fixture, "policy_canonicalization") == (
        "rfc8785_json_canonicalization"
    )
    assert _single_value(fixture, "policy_version") == _load(POLICY_PATH)[
        "policy_version"
    ]
    assert _single_value(fixture, "policy_digest") == _expected_policy_digest()


def _all_mapping_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for candidate in value.values():
            keys.update(_all_mapping_keys(candidate))
    elif isinstance(value, list):
        for candidate in value:
            keys.update(_all_mapping_keys(candidate))
    return keys


def test_additive_contract_schemas_and_synthetic_fixtures_validate() -> None:
    identity_schema = _load(IDENTITY_CONTROL_PLANE_SCHEMA)
    identity_fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    edge_schema = _load(EDGE_IDENTITY_V2_SCHEMA)
    edge_fixture = _load(EDGE_IDENTITY_V2_FIXTURE)

    assert identity_schema["$id"] == "scanalyze.contract.identity-control-plane.v1"
    assert edge_schema["$id"] == "scanalyze.contract.edge-identity.v2"
    _validator(IDENTITY_CONTROL_PLANE_SCHEMA).validate(identity_fixture)
    _validator(EDGE_IDENTITY_V2_SCHEMA).validate(edge_fixture)
    _walk_object_schemas(identity_schema)
    _walk_object_schemas(edge_schema)


def test_schema_gate_selects_each_new_contract_without_aliasing() -> None:
    assert find_schema_for_fixture(
        IDENTITY_CONTROL_PLANE_FIXTURE.stem,
        IDENTITY_CONTROL_PLANE_SCHEMA.parent,
    ) == IDENTITY_CONTROL_PLANE_SCHEMA
    assert find_schema_for_fixture(
        EDGE_IDENTITY_V2_FIXTURE.stem,
        EDGE_IDENTITY_V2_SCHEMA.parent,
    ) == EDGE_IDENTITY_V2_SCHEMA


def test_real_identity_root_outputs_are_publishable_as_v1_contract() -> None:
    _assert_real_root_outputs_publish_fixture(
        fixture_path=IDENTITY_CONTROL_PLANE_FIXTURE,
        schema_path=IDENTITY_CONTROL_PLANE_SCHEMA,
        root_outputs_path=IDENTITY_CONTROL_PLANE_ROOT_OUTPUTS,
        module_outputs_path=IDENTITY_CONTROL_PLANE_MODULE_OUTPUTS,
        layer="identity-control-plane",
        contract_id="identity-control-plane/v1",
    )


def test_real_edge_identity_root_outputs_are_publishable_as_v2_contract() -> None:
    _assert_real_root_outputs_publish_fixture(
        fixture_path=EDGE_IDENTITY_V2_FIXTURE,
        schema_path=EDGE_IDENTITY_V2_SCHEMA,
        root_outputs_path=EDGE_IDENTITY_ROOT_OUTPUTS,
        module_outputs_path=EDGE_IDENTITY_MODULE_OUTPUTS,
        layer="edge-identity",
        contract_id="edge-identity/v2",
    )


def test_identity_control_plane_requires_exact_portable_binding_tuple() -> None:
    fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    validator = _validator(IDENTITY_CONTROL_PLANE_SCHEMA)

    _assert_bound_portable_identity(fixture)
    for field in IDENTITY_BINDING_FIELDS:
        _assert_field_is_required(fixture, validator, field)

    malformed_values = {
        "customer_id": "customer-from-request",
        "deployment_id": "deployment-from-header",
        "account_id": "1234",
        "region": "global",
    }
    for field, malformed_value in malformed_values.items():
        candidate = copy.deepcopy(fixture)
        _replace_key(candidate, field, malformed_value)
        assert list(validator.iter_errors(candidate)), f"invalid {field} must fail"


def test_identity_control_plane_is_access_only_and_uses_exact_reviewed_scopes() -> None:
    fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    validator = _validator(IDENTITY_CONTROL_PLANE_SCHEMA)

    _assert_access_only_authorization(fixture)
    for field in (*REQUIRED_AUTHORIZATION_FIELDS, *M2M_REGISTRY_FIELDS):
        _assert_field_is_required(fixture, validator, field)

    for token_uses in (["id"], ["access", "id"]):
        candidate = copy.deepcopy(fixture)
        _replace_key(candidate, "allowed_token_uses", token_uses)
        assert list(validator.iter_errors(candidate)), "ID tokens must fail closed"

    for action_scopes in (
        {**EXPECTED_ACTION_SCOPES, "read": "scanalyze.api.v1/reader"},
        {**EXPECTED_ACTION_SCOPES, "superuser": "scanalyze.api.v1/superuser"},
    ):
        candidate = copy.deepcopy(fixture)
        _replace_key(candidate, "action_scopes", action_scopes)
        assert list(validator.iter_errors(candidate)), "scope drift must fail closed"


def test_policy_digest_is_sha256_over_rfc8785_canonical_policy() -> None:
    policy = _load(POLICY_PATH)
    fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    digest = _single_value(fixture, "policy_digest")

    assert policy["policy_integrity"]["canonicalization"] == (
        "rfc8785_json_canonicalization"
    )
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    assert digest == _expected_policy_digest()


def test_runtime_provisioning_forbids_humans_and_never_exports_m2m_secrets() -> None:
    fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    schema = _load(IDENTITY_CONTROL_PLANE_SCHEMA)
    validator = _validator(IDENTITY_CONTROL_PLANE_SCHEMA)

    assert _single_value(fixture, "human_runtime_provisioning_enabled") is False
    assert _single_value(fixture, "m2m_runtime_provisioning_enabled") is True
    assert _single_value(fixture, "m2m_client_secret_values_exposed") is False
    m2m_client_ids = _single_value(fixture, "m2m_client_ids")
    assert m2m_client_ids == []
    assert schema["properties"]["m2m_client_ids"]["minItems"] == 0
    assert not (FORBIDDEN_SECRET_OUTPUT_KEYS & _all_mapping_keys(fixture))
    assert not (FORBIDDEN_SECRET_OUTPUT_KEYS & _all_mapping_keys(schema))

    for field in (*RUNTIME_PROVISIONING_FIELDS, "m2m_client_ids"):
        _assert_field_is_required(fixture, validator, field)

    forbidden_runtime_values = {
        "human_runtime_provisioning_enabled": True,
        "m2m_runtime_provisioning_enabled": False,
        "m2m_client_secret_values_exposed": True,
    }
    for field, forbidden_value in forbidden_runtime_values.items():
        candidate = copy.deepcopy(fixture)
        _replace_key(candidate, field, forbidden_value)
        assert list(validator.iter_errors(candidate)), f"unsafe {field} must fail"

    promoted = copy.deepcopy(fixture)
    promoted["m2m_client_ids"] = ["syntheticm2mclient00000000001"]
    promoted["m2m_bindings"] = [
        {
            "client_id": "syntheticm2mclient00000000001",
            "customer_id": promoted["customer_id"],
            "deployment_id": promoted["deployment_id"],
            "required_scopes": ["scanalyze.api.v1/read"],
        }
    ]
    validator.validate(promoted)
    assert validate_semantics(promoted, IDENTITY_CONTROL_PLANE_SCHEMA) == []


def test_identity_m2m_registry_requires_exact_gug102_binding_coverage() -> None:
    fixture = _load(IDENTITY_CONTROL_PLANE_FIXTURE)
    client_id = "syntheticm2mclient00000000001"

    missing_binding = copy.deepcopy(fixture)
    missing_binding["m2m_client_ids"] = [client_id]
    assert any(
        "cover each declared" in error
        for error in validate_semantics(
            missing_binding,
            IDENTITY_CONTROL_PLANE_SCHEMA,
        )
    )

    foreign_binding = copy.deepcopy(fixture)
    foreign_binding["m2m_client_ids"] = [client_id]
    foreign_binding["m2m_bindings"] = [
        {
            "client_id": client_id,
            "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAA",
            "deployment_id": fixture["deployment_id"],
            "required_scopes": ["scanalyze.api.v1/read"],
        }
    ]
    assert any(
        "customer_id must match" in error
        for error in validate_semantics(foreign_binding, IDENTITY_CONTROL_PLANE_SCHEMA)
    )

    unbound_scope = copy.deepcopy(fixture)
    unbound_scope["m2m_client_ids"] = [client_id]
    unbound_scope["m2m_bindings"] = [
        {
            "client_id": client_id,
            "customer_id": fixture["customer_id"],
            "deployment_id": fixture["deployment_id"],
            "required_scopes": ["scanalyze.api.v1/superuser"],
        }
    ]
    assert list(
        _validator(IDENTITY_CONTROL_PLANE_SCHEMA).iter_errors(unbound_scope)
    )


def test_edge_identity_v2_rebinds_authorizer_to_the_control_plane_contract() -> None:
    fixture = _load(EDGE_IDENTITY_V2_FIXTURE)
    schema = _load(EDGE_IDENTITY_V2_SCHEMA)
    validator = _validator(EDGE_IDENTITY_V2_SCHEMA)

    _assert_bound_portable_identity(fixture)
    _assert_access_only_authorization(fixture)
    assert _single_value(fixture, "identity_control_plane_contract_id") == (
        "identity-control-plane/v1"
    )
    assert re.fullmatch(
        r"sha256:[0-9a-f]{64}",
        _single_value(fixture, "identity_control_plane_contract_digest"),
    )
    assert fixture["m2m_client_ids"] == []
    assert fixture["authorizer_audiences"] == [fixture["cognito_spa_client_id"]]
    assert schema["properties"]["m2m_client_ids"]["minItems"] == 0
    assert schema["properties"]["authorizer_audiences"]["minItems"] == 1
    assert not (FORBIDDEN_SECRET_OUTPUT_KEYS & _all_mapping_keys(fixture))
    assert not (FORBIDDEN_SECRET_OUTPUT_KEYS & _all_mapping_keys(schema))

    for field in (
        *IDENTITY_BINDING_FIELDS,
        *REQUIRED_AUTHORIZATION_FIELDS,
        "identity_control_plane_contract_id",
        "identity_control_plane_contract_digest",
    ):
        _assert_field_is_required(fixture, validator, field)

    assert fixture["route_authorization_scopes"] == {
        "GET /documents": ["scanalyze.api.v1/read"],
        "POST /documents": ["scanalyze.api.v1/write"],
        "POST /documents/export": ["scanalyze.api.v1/admin"],
    }


def test_edge_routes_are_explicit_and_use_exactly_one_canonical_scope() -> None:
    fixture = _load(EDGE_IDENTITY_V2_FIXTURE)
    validator = _validator(EDGE_IDENTITY_V2_SCHEMA)

    unsafe_routes = (
        {"$default": ["scanalyze.api.v1/read"]},
        {"GET /documents?all=true": ["scanalyze.api.v1/read"]},
        {"GET /documents": []},
        {
            "POST /documents/export": [
                "scanalyze.api.v1/read",
                "scanalyze.api.v1/admin",
            ]
        },
        {"GET /documents": ["scanalyze.api.v1/superuser"]},
    )
    for route_authorization_scopes in unsafe_routes:
        candidate = copy.deepcopy(fixture)
        candidate["route_authorization_scopes"] = route_authorization_scopes
        assert list(validator.iter_errors(candidate)), (
            "default, malformed, empty, multi-scope, and unknown-scope routes "
            "must fail closed"
        )


def test_m2m_audience_requires_reviewed_registry_promotion() -> None:
    fixture = _load(EDGE_IDENTITY_V2_FIXTURE)
    validator = _validator(EDGE_IDENTITY_V2_SCHEMA)
    m2m_client_id = "syntheticm2mclient00000000001"

    promoted = copy.deepcopy(fixture)
    promoted["m2m_client_ids"] = [m2m_client_id]
    promoted["authorizer_audiences"] = [
        promoted["cognito_spa_client_id"],
        m2m_client_id,
    ]
    validator.validate(promoted)
    assert validate_semantics(promoted, EDGE_IDENTITY_V2_SCHEMA) == []

    audience_without_registry = copy.deepcopy(fixture)
    audience_without_registry["authorizer_audiences"].append(m2m_client_id)
    assert any(
        "audiences" in error
        for error in validate_semantics(
            audience_without_registry,
            EDGE_IDENTITY_V2_SCHEMA,
        )
    )

    registry_without_audience = copy.deepcopy(fixture)
    registry_without_audience["m2m_client_ids"] = [m2m_client_id]
    assert any(
        "audiences" in error
        for error in validate_semantics(registry_without_audience, EDGE_IDENTITY_V2_SCHEMA)
    )


def test_edge_identity_v1_remains_the_original_closed_contract() -> None:
    schema = _load(EDGE_IDENTITY_V1_SCHEMA)
    fixture = _load(EDGE_IDENTITY_V1_FIXTURE)

    _validator(EDGE_IDENTITY_V1_SCHEMA).validate(fixture)
    assert schema["$id"] == "scanalyze.contract.edge-identity.v1"
    assert set(schema["required"]) == {
        "cognito_user_pool_id",
        "cognito_user_pool_arn",
        "api_gateway_id",
        "api_gateway_endpoint",
    }
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == LEGACY_EDGE_V1_PROPERTIES
    assert not (
        {
            "identity_binding",
            "identity_control_plane_contract_id",
            "action_scopes",
            "policy_digest",
            "runtime_provisioning",
        }
        & set(schema["properties"])
    )


def test_layer_envelope_accepts_new_versions_additively() -> None:
    schema = _load(LAYER_CONTRACT_SCHEMA)
    definitions = schema["$defs"]

    edge_versions = definitions["edge_identity_producer"]["properties"][
        "output_schema_version"
    ]["enum"]
    assert edge_versions == ["edge-identity/v1", "edge-identity/v2"]
    assert definitions["identity_control_plane_producer"]["properties"][
        "output_schema_version"
    ]["const"] == "identity-control-plane/v1"


def test_dag_places_identity_control_plane_before_services_and_edge_after() -> None:
    document = yaml.safe_load(LAYERS_YAML.read_text(encoding="utf-8"))
    layers = {item["layer"]: item for item in document["layers"]}
    order = [item["layer"] for item in document["layers"]]

    assert order.index("identity-control-plane") < order.index("services")
    assert order.index("services") < order.index("edge-identity")
    assert layers["identity-control-plane"]["produces_contract"] == (
        "identity-control-plane/v1"
    )
    assert "identity-control-plane" in layers["services"]["depends_on"]
    assert "identity-control-plane/v1" in layers["services"]["requires_contracts"]
    assert "services" in layers["edge-identity"]["depends_on"]
    assert "identity-control-plane/v1" in layers["edge-identity"][
        "requires_contracts"
    ]
    assert layers["edge-identity"]["produces_contract"] == "edge-identity/v2"

    result = subprocess.run(
        [sys.executable, str(DAG_VALIDATOR), str(LAYERS_YAML)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
