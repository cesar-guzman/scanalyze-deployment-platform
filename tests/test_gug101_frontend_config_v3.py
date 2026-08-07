"""Offline contract and renderer coverage for GUG-101 frontend-config/v3."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "deployment" / "validate-frontend-config.py"
SCHEMA = ROOT / "schemas" / "frontend-config.v3.schema.json"
VALID_A = ROOT / "fixtures" / "valid" / "frontend-config-v3-synthetic-a.json"
VALID_B = ROOT / "fixtures" / "valid" / "frontend-config-v3-synthetic-b.json"
NEGATIVE_CASES = ROOT / "fixtures" / "gug101" / "frontend-config-v3-negative-cases.json"
TERRAFORM_OUTPUT = ROOT / "fixtures" / "gug101" / "terraform-output-frontend-config-v3.json"
CORRUPT = ROOT / "fixtures" / "gug101" / "frontend-config-v3-corrupt.txt"
EMPTY = ROOT / "fixtures" / "gug101" / "frontend-config-v3-empty.txt"


def _load_module():
    spec = importlib.util.spec_from_file_location("gug101_frontend_config", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = _load_module()


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _apply_case(base: dict, case: dict) -> dict:
    candidate = copy.deepcopy(base)
    parent = candidate
    for segment in case["path"][:-1]:
        parent = parent[segment]
    leaf = case["path"][-1]
    if case["operation"] == "remove":
        del parent[leaf]
    else:
        parent[leaf] = case["value"]
    return candidate


def test_v3_schema_is_closed_and_v1_v2_remain_historical() -> None:
    v1 = _json(ROOT / "schemas" / "frontend-config.schema.json")
    v2 = _json(ROOT / "schemas" / "frontend-config.v2.schema.json")
    v3 = _json(SCHEMA)

    Draft202012Validator.check_schema(v3)
    assert v1["properties"]["schema_version"]["const"] == "1"
    assert v2["properties"]["schema_version"]["const"] == "2"
    assert v3["properties"]["schema_version"]["const"] == "3"
    assert v3["additionalProperties"] is False
    assert "config_version" in v3["required"]
    assert v3["properties"]["config_version"]["maxLength"] == 128
    assert v3["x-maxDocumentBytes"] == validator.MAX_CONFIG_BYTES == 65_536
    assert "redirect_uri" in v3["properties"]["cognito"]["required"]
    assert "post_logout_redirect_uri" in v3["properties"]["cognito"]["required"]


@pytest.mark.parametrize("fixture", (VALID_A, VALID_B), ids=lambda path: path.stem)
def test_valid_v3_fixtures_pass_shape_and_semantics(fixture: Path) -> None:
    schema = _json(SCHEMA)
    config = _json(fixture)

    assert list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(config)
    ) == []
    assert validator.validate_runtime_config(config) == config


def test_real_dotted_date_config_version_is_supported() -> None:
    assert _json(VALID_B)["config_version"] == "2026.07.14"
    validator.validate_runtime_config(_json(VALID_B))


def test_frontend_config_accepts_the_reviewed_release_manifest_version() -> None:
    release_manifest = _json(ROOT / "fixtures/valid/release-manifest-complete.json")
    config = _json(VALID_A)
    assert config["config_version"] == release_manifest["release_version"] == "v2.1.0"
    validator.validate_runtime_config(config)


def test_historical_v2_manifest_without_domain_remains_schema_valid() -> None:
    schema = _json(ROOT / "schemas/deployment-manifest.v2.schema.json")
    manifest = yaml.safe_load(
        (ROOT / "examples/deployments/synthetic-nonprod.yaml").read_text(
            encoding="utf-8"
        )
    )
    manifest.pop("domain")
    assert list(Draft202012Validator(schema).iter_errors(manifest)) == []


def test_negative_fixture_catalog_fails_with_stable_safe_codes() -> None:
    catalog = _json(NEGATIVE_CASES)
    base = _json(ROOT / catalog["base_fixture"])

    for case in catalog["cases"]:
        candidate = _apply_case(base, case)
        with pytest.raises(validator.FrontendConfigError) as caught:
            validator.validate_runtime_config(candidate)
        assert caught.value.code == case["expected_code"]
        assert str(caught.value) == case["expected_code"]


def test_strict_parser_rejects_corrupt_empty_duplicate_and_non_finite_json() -> None:
    cases = (
        (CORRUPT, "FRONTEND_CONFIG_INVALID_JSON"),
        (EMPTY, "FRONTEND_CONFIG_EMPTY_JSON"),
    )
    for fixture, expected in cases:
        with pytest.raises(validator.FrontendConfigError) as caught:
            validator.load_json_strict(fixture)
        assert caught.value.code == expected

    for serialized, expected in (
        ('{"schema_version":"3","schema_version":"3"}', "FRONTEND_CONFIG_DUPLICATE_KEY"),
        ('{"value":NaN}', "FRONTEND_CONFIG_NON_FINITE_JSON"),
        ('{"value":Infinity}', "FRONTEND_CONFIG_NON_FINITE_JSON"),
        ('{"value":1e999}', "FRONTEND_CONFIG_NON_FINITE_JSON"),
    ):
        with pytest.raises(validator.FrontendConfigError) as caught:
            validator.parse_json_strict(serialized)
        assert caught.value.code == expected


def test_sandbox_loopback_is_explicit_and_non_sandbox_http_is_rejected() -> None:
    sandbox = _json(VALID_A)
    sandbox["api_endpoint"] = "http://localhost:5173/api"
    sandbox["cognito"]["redirect_uri"] = "http://localhost:5173/callback"
    sandbox["cognito"]["post_logout_redirect_uri"] = "http://localhost:5173/"
    validator.validate_runtime_config(sandbox)

    non_sandbox = copy.deepcopy(sandbox)
    non_sandbox["environment"] = "dev"
    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.validate_runtime_config(non_sandbox)
    assert caught.value.code == "FRONTEND_CONFIG_SCHEMA_INVALID"


def test_renderer_selects_only_public_output_and_matches_fixture_deeply() -> None:
    document = validator.load_json_strict(TERRAFORM_OUTPUT)
    selected, exact_bytes = validator.extract_terraform_runtime_config(document)

    assert selected == _json(VALID_A)
    assert exact_bytes == validator.render_config_bytes(selected)
    assert json.loads(exact_bytes) == _json(VALID_A)
    assert document["frontend_runtime_config_sha256"]["value"] == validator._digest(exact_bytes)
    assert "unrelated_output" not in selected


def test_renderer_rejects_mismatched_terraform_bytes_and_digest() -> None:
    document = validator.load_json_strict(TERRAFORM_OUTPUT)

    mismatched_value = copy.deepcopy(document)
    mismatched_value["frontend_runtime_config_json"]["value"] = "{}"
    mismatched_value["frontend_runtime_config_sha256"]["value"] = validator._digest(b"{}")
    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.extract_terraform_runtime_config(mismatched_value)
    assert caught.value.code == "FRONTEND_CONFIG_TERRAFORM_VALUE_MISMATCH"

    mismatched_digest = copy.deepcopy(document)
    mismatched_digest["frontend_runtime_config_sha256"]["value"] = f"sha256:{'0' * 64}"
    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.extract_terraform_runtime_config(mismatched_digest)
    assert caught.value.code == "FRONTEND_CONFIG_TERRAFORM_DIGEST_MISMATCH"

    noncanonical = copy.deepcopy(document)
    pretty = json.dumps(noncanonical["frontend_runtime_config"]["value"], indent=2)
    noncanonical["frontend_runtime_config_json"]["value"] = pretty
    noncanonical["frontend_runtime_config_sha256"]["value"] = validator._digest(
        pretty.encode("utf-8")
    )
    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.extract_terraform_runtime_config(noncanonical)
    assert caught.value.code == "FRONTEND_CONFIG_TERRAFORM_BYTES_NONCANONICAL"


def test_renderer_rejects_config_bytes_the_browser_cannot_load() -> None:
    oversized = validator.load_json_strict(TERRAFORM_OUTPUT)
    oversized_bytes = b" " * (validator.MAX_CONFIG_BYTES + 1)
    oversized["frontend_runtime_config_json"]["value"] = oversized_bytes.decode("ascii")
    oversized["frontend_runtime_config_sha256"]["value"] = validator._digest(
        oversized_bytes
    )

    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.extract_terraform_runtime_config(oversized)
    assert caught.value.code == "FRONTEND_CONFIG_TOO_LARGE"


def test_contract_surfaces_share_the_canonical_v3_field_set() -> None:
    schema = _json(SCHEMA)
    canonical_fields = set(schema["properties"])
    fixture_fields = set(_json(VALID_A))
    assert fixture_fields == canonical_fields

    runtime_source = (ROOT / "frontend/scanalyze-frontend-ui/src/config/runtime.js").read_text(
        encoding="utf-8"
    )
    allowed_match = re.search(
        r"const COMMON_TOP_LEVEL_KEYS = \[(.*?)\];",
        runtime_source,
        flags=re.DOTALL,
    )
    assert allowed_match is not None
    assert set(re.findall(r"'([a-z_]+)'", allowed_match.group(1))) == canonical_fields

    type_source = (ROOT / "frontend/scanalyze-frontend-ui/src/config/runtime.d.ts").read_text(
        encoding="utf-8"
    )
    raw_type_match = re.search(
        r"export interface FrontendRuntimeConfigV3 \{(.*?)\n\}",
        type_source,
        flags=re.DOTALL,
    )
    assert raw_type_match is not None
    typed_fields = set(re.findall(r"readonly ([a-z_]+)\??:", raw_type_match.group(1)))
    assert typed_fields == canonical_fields

    terraform_source = (ROOT / "modules/edge/runtime_config.tf").read_text(encoding="utf-8")
    docs_source = (ROOT / "docs/deployment/frontend-config.md").read_text(encoding="utf-8")
    for field in sorted(canonical_fields):
        assert field in terraform_source
        assert field in docs_source

    cloudfront_source = (ROOT / "modules/edge/cloudfront.tf").read_text(encoding="utf-8")
    contract_catalog = _json(ROOT / "deployment/contract-catalog.v1.json")
    browser_loader = (
        ROOT / "frontend/scanalyze-frontend-ui/src/config/index.ts"
    ).read_text(encoding="utf-8")
    renderer_source = SCRIPT.read_text(encoding="utf-8")
    assert 'for_each = toset(["/api", "/api/*"])' in cloudfront_source
    assert 'function_arn = aws_cloudfront_function.api_path_rewrite.arn' in cloudfront_source
    assert 'path_pattern           = "/api*"' not in cloudfront_source
    assert "domain_name = local.api_gateway_domain" in cloudfront_source
    assert (
        contract_catalog["contracts"]["edge-identity/v2"]["consumer_bindings"]
        ["edge"]["output_variables"]["api_gateway_id"]
        == "api_gateway_id"
    )
    assert (
        'api_gateway_domain       = "${var.api_gateway_id}.execute-api.'
        '${var.region}.${local.aws_dns_suffix}"'
        in terraform_source
    )
    assert (
        'var.api_gateway_endpoint == "https://${local.api_gateway_domain}"'
        in terraform_source
    )
    assert "const MAX_CONFIG_BYTES = 65_536;" in browser_loader
    assert "MAX_CONFIG_BYTES = 65_536" in renderer_source
    assert 'local.frontend_config_schema["x-maxDocumentBytes"]' in terraform_source


def test_registered_cognito_urls_and_frontend_config_share_one_invariant() -> None:
    identity_schema = _json(ROOT / "schemas/contract-identity-control-plane.v1.schema.json")
    edge_schema = _json(ROOT / "schemas/contract-edge-identity.v2.schema.json")
    frontend = _json(VALID_A)
    versioned_contract_additions = {
        "cognito_hosted_ui_domain",
        "cognito_spa_callback_urls",
        "cognito_spa_logout_urls",
    }

    # Historical layer contracts remain immutable. URI registration and edge
    # rendering are instead bound to deployment-target/v2's digest-covered origin.
    for schema in (identity_schema, edge_schema):
        assert versioned_contract_additions.isdisjoint(schema["required"])
        assert versioned_contract_additions.isdisjoint(schema["properties"])

    frontend_origin = frontend["api_endpoint"].removesuffix("/api")
    hosted_ui_prefix = f"{frontend['deployment_id']}-identity".replace("_", "-").lower()
    expected_hosted_ui = (
        f"https://{hosted_ui_prefix}.auth.{frontend['region']}.amazoncognito.com"
    )
    assert frontend["cognito"]["hosted_ui_domain"] == expected_hosted_ui
    assert frontend["cognito"]["redirect_uri"] == f"{frontend_origin}/callback"
    assert frontend["cognito"]["post_logout_redirect_uri"] == f"{frontend_origin}/"

    identity_root = (ROOT / "roots/identity-control-plane/main.tf").read_text(
        encoding="utf-8"
    )
    identity_root_variables = (
        ROOT / "roots/identity-control-plane/variables.tf"
    ).read_text(encoding="utf-8")
    identity_locals = (ROOT / "modules/identity-control-plane/locals.tf").read_text(
        encoding="utf-8"
    )
    identity_cognito = (ROOT / "modules/identity-control-plane/cognito.tf").read_text(
        encoding="utf-8"
    )
    edge_runtime = (ROOT / "modules/edge/runtime_config.tf").read_text(encoding="utf-8")
    deploy_wrapper = (ROOT / "scripts/deployment/scanalyze-deploy.sh").read_text(
        encoding="utf-8"
    )
    terraform_wrapper = (ROOT / "scripts/deployment/terraform-layer.sh").read_text(
        encoding="utf-8"
    )
    authorizer = (ROOT / "tooling/authorize_deployment_backend.py").read_text(
        encoding="utf-8"
    )
    manifest_schema = _json(ROOT / "schemas/deployment-manifest.v2.schema.json")
    target_schema = _json(ROOT / "schemas/deployment-target.v2.schema.json")
    binding_schema = _json(ROOT / "schemas/terraform-backend-binding.v2.schema.json")

    assert "domain_name                      = var.domain_name" in identity_root
    assert 'spa_callback_urls = ["https://${var.domain_name}/callback"]' in identity_root
    assert 'spa_logout_urls   = ["https://${var.domain_name}/"]' in identity_root
    assert 'variable "spa_callback_urls"' not in identity_root_variables
    assert 'variable "spa_logout_urls"' not in identity_root_variables
    assert 'hosted_ui_prefix = lower(replace(local.identity_prefix, "_", "-"))' in identity_locals
    assert "callback_urls                = var.spa_callback_urls" in identity_cognito
    assert "logout_urls                  = var.spa_logout_urls" in identity_cognito
    assert 'one(var.spa_callback_urls) == "https://${var.domain_name}/callback"' in identity_cognito
    assert 'one(var.spa_logout_urls) == "https://${var.domain_name}/"' in identity_cognito
    assert 'cognito_hosted_ui_prefix = lower(replace("${var.deployment_id}-identity", "_", "-"))' in edge_runtime
    assert 'redirect_uri             = "${local.frontend_origin}/callback"' in edge_runtime
    assert 'post_logout_redirect_uri = "${local.frontend_origin}/"' in edge_runtime
    assert "domain" not in manifest_schema["required"]
    assert manifest_schema["properties"]["domain"] == {"type": "string"}
    assert "runtime_origin" in target_schema["required"]
    assert target_schema["properties"]["runtime_origin"]["properties"][
        "domain_name"
    ]["pattern"].startswith("^[a-z0-9]")
    assert "runtime_origin" in binding_schema["required"]
    assert 'manifest_domain_name="$(manifest_optional_field domain)"' in deploy_wrapper
    assert 'grep -q \'^variable "domain_name"\'' in deploy_wrapper
    assert '--domain-name "$DOMAIN_NAME"' in deploy_wrapper
    assert '[[ "$DOMAIN_NAME" == "$AUTHORIZED_DOMAIN_NAME" ]]' in terraform_wrapper
    assert 'terraform_variables+=("-var=domain_name=${DOMAIN_NAME}")' in terraform_wrapper
    assert 'target.get("runtime_origin", {}).get("domain_name")' in authorizer
    assert 'binding["runtime_origin"] = target["runtime_origin"]' in authorizer


def test_historical_manifest_schemas_remain_byte_for_byte_immutable() -> None:
    expected = {
        "deployment-manifest.schema.json": (
            "d0376dbff3e858f989efb553c9c4b2c70eb6ff36ac492c372c967edd336e9e55"
        ),
        "deployment-manifest.v2.schema.json": (
            "304e0bfd6f9753d427811968d1bfb4105ced4803bbdffb6cee00346223c5da68"
        ),
    }

    for name, digest in expected.items():
        content = (ROOT / "schemas" / name).read_bytes()
        assert hashlib.sha256(content).hexdigest() == digest


def test_edge_terraform_exclusively_owns_runtime_config_publication() -> None:
    terraform = (ROOT / "modules/edge/runtime_config.tf").read_text(encoding="utf-8")
    session_policy = _json(ROOT / "session-policies/edge-layer.json")
    bucket_policy = _json(ROOT / "policies/s3/frontend-bucket.json")
    promotion_policy = _json(ROOT / "policies/iam/promotion-role.json")
    exact_config_arn = (
        "arn:${aws_partition}:s3:::scanalyze-${account_id}-frontend/"
        "${deployment_id}/config.json"
    )

    assert 'resource "aws_s3_object" "frontend_runtime_config"' in terraform
    assert 'key                = "${var.deployment_id}/config.json"' in terraform
    assert "content            = local.frontend_runtime_config_json" in terraform
    assert 'cache_control      = "no-store, max-age=0, must-revalidate"' in terraform
    assert 'checksum_algorithm = "SHA256"' in terraform
    assert "source_hash        = local.frontend_runtime_config_sha256" in terraform
    assert "prevent_destroy = true" in terraform

    edge_write = next(
        statement
        for statement in session_policy["Statement"]
        if statement["Sid"] == "ManageExactFrontendRuntimeConfig"
    )
    assert edge_write["Action"] == ["s3:GetObject", "s3:PutObject"]
    assert edge_write["Resource"] == exact_config_arn

    bucket_write = next(
        statement
        for statement in bucket_policy["Statement"]
        if statement["Sid"] == "AllowEdgeApplyRuntimeConfig"
    )
    assert bucket_write["Resource"] == exact_config_arn
    assert bucket_write["Principal"]["AWS"].endswith(
        ":role/ScanalyzeCustomer-Apply"
    )

    promotion_resources = {
        resource
        for statement in promotion_policy["Statement"]
        for resource in (
            statement.get("Resource", [])
            if isinstance(statement.get("Resource", []), list)
            else [statement["Resource"]]
        )
    }
    assert exact_config_arn not in promotion_resources


@pytest.mark.parametrize("partition", ("aws", "aws-us-gov", "aws-cn"))
def test_runtime_config_policy_arns_render_for_every_supported_partition(
    partition: str,
) -> None:
    templates = (
        _json(ROOT / "session-policies/edge-layer.json"),
        _json(ROOT / "policies/s3/frontend-bucket.json"),
    )

    for template in templates:
        serialized = json.dumps(template, sort_keys=True)
        assert "arn:aws:" not in serialized
        rendered = json.loads(serialized.replace("${aws_partition}", partition))

        def arn_values(value: object) -> list[str]:
            if isinstance(value, str):
                return [value] if value.startswith("arn:") else []
            if isinstance(value, list):
                return [item for child in value for item in arn_values(child)]
            if isinstance(value, dict):
                return [item for child in value.values() for item in arn_values(child)]
            return []

        arns = arn_values(rendered)
        assert arns
        assert all(value.startswith(f"arn:{partition}:") for value in arns)


@pytest.mark.parametrize("layer", ("identity-control-plane", "edge-identity", "edge"))
def test_plan_wrapper_rejects_domain_owning_roots_without_manifest_domain(
    tmp_path: Path,
    layer: str,
) -> None:
    placeholder = tmp_path / "unread"
    command = [
        "bash",
        str(ROOT / "scripts/deployment/terraform-layer.sh"),
        "plan",
        "--layer",
        layer,
        "--plan-dir",
        str(tmp_path),
        "--customer-id",
        "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--deployment-id",
        "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "--account-id",
        "123456789012",
        "--region",
        "us-east-1",
        "--environment",
        "sandbox",
        "--release-version",
        "v2.1.0",
        "--release-digest",
        f"sha256:{'0' * 64}",
        "--resolved-input",
        str(placeholder),
        "--manifest",
        str(placeholder),
        "--target-record",
        str(placeholder),
        "--target-anchor",
        str(placeholder),
        "--account-ready",
        str(placeholder),
        "--execution-lock",
        str(placeholder),
        "--execution-id",
        "exec_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ]
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("TF_")
    }
    result = subprocess.run(command, text=True, capture_output=True, env=environment)
    assert result.returncode == 2
    assert f"--domain-name is required for layer {layer}" in result.stderr


def test_renderer_writes_only_outside_repo_mode_0600_and_no_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "config.json"
    command = [
        sys.executable,
        str(SCRIPT),
        "render",
        "--terraform-output",
        str(TERRAFORM_OUTPUT),
        "--output",
        str(output),
    ]

    first = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert first.returncode == 0, first.stderr
    assert re.fullmatch(r"FRONTEND_CONFIG_WRITTEN sha256:[0-9a-f]{64}\n", first.stdout)
    assert first.stderr == ""
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8")) == _json(VALID_A)

    second = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert second.returncode == 2
    assert second.stdout == ""
    assert second.stderr == "FRONTEND_CONFIG_OUTPUT_EXISTS\n"


def test_renderer_rejects_repository_output_without_creating_it() -> None:
    forbidden = ROOT / "config.gug101.invalid.json"
    assert not forbidden.exists()
    with pytest.raises(validator.FrontendConfigError) as caught:
        validator.write_config_outside_repo(forbidden, b"{}\n")
    assert caught.value.code == "FRONTEND_CONFIG_OUTPUT_INSIDE_REPOSITORY"
    assert not forbidden.exists()


def test_cli_errors_never_echo_rejected_values_or_paths(tmp_path: Path) -> None:
    candidate = _json(VALID_A)
    candidate["cognito"]["client_secret"] = "synthetic-denied-value"
    rejected = tmp_path / "rejected.json"
    rejected.write_text(json.dumps(candidate), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "validate", str(rejected)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "FRONTEND_CONFIG_SECRET_LIKE_KEY\n"
    assert "synthetic-denied-value" not in combined
    assert str(rejected) not in combined
    assert _json(VALID_A)["cognito"]["spa_client_id"] not in combined


def test_build_once_harness_uses_two_external_configs_and_one_unchanged_tree(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "dist"
    artifact.mkdir()
    (artifact / "index.html").write_text("<!doctype html><main id='root'></main>", encoding="utf-8")
    assets = artifact / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("globalThis.__scanalyzeBuild='synthetic';", encoding="utf-8")

    before = validator.artifact_tree_digest(artifact)
    proved = validator.prove_build_once(artifact, VALID_A, VALID_B)
    after = validator.artifact_tree_digest(artifact)

    assert proved == before == after
    assert not (artifact / "config.json").exists()


def test_renderer_has_no_terraform_aws_or_network_execution_path() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "import boto" not in source
    assert "import requests" not in source
    assert "subprocess" not in source
    assert "aws sts" not in source.lower()
    assert "terraform output" in source
