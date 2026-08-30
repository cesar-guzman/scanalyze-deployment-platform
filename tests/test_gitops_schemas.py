"""Schema and synthetic-fixture tests for the GitOps release contracts."""
from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from tooling.validate_digest import canonicalize, compute_digest


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"
EXAMPLE_DIR = REPO_ROOT / "examples" / "gitops"
LAYERS_PATH = REPO_ROOT / "deployment" / "layers.yaml"
NONPROD_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "nonprod-release.yml"
LAYER_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "_terraform-layer.yml"

SCHEMA_EXAMPLES = {
    "layer-contract.schema.json": "layer-contract.synthetic.json",
    "deployment-request.schema.json": "deployment-request.synthetic.json",
    "release-manifest.schema.json": "release-manifest.synthetic.json",
}

DIRECT_SCHEMA_NAMES = (
    *SCHEMA_EXAMPLES,
    "staging-certification.v1.schema.json",
    "staging-certification-trust-policy.v1.schema.json",
    "staging-certification-trust-anchor.v1.schema.json",
)

EXPECTED_LAYER_ORDER = [
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

REQUIRED_LAYER_FIELDS = {
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


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _load_json(SCHEMA_DIR / schema_name)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _load_workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _workflow_trigger(workflow: dict) -> dict:
    # PyYAML 1.1 parses the unquoted Actions key `on` as boolean true.
    return workflow.get("on", workflow.get(True, {}))


@pytest.mark.parametrize("schema_name", DIRECT_SCHEMA_NAMES)
def test_schema_is_valid_draft_2020_12(schema_name: str) -> None:
    Draft202012Validator.check_schema(_load_json(SCHEMA_DIR / schema_name))


@pytest.mark.parametrize("schema_name,example_name", SCHEMA_EXAMPLES.items())
def test_synthetic_example_matches_schema(
    schema_name: str, example_name: str
) -> None:
    instance = _load_json(EXAMPLE_DIR / example_name)
    errors = sorted(_validator(schema_name).iter_errors(instance), key=str)
    assert not errors, [error.message for error in errors]


def test_layer_contract_example_digest_matches_canonical_outputs() -> None:
    contract = _load_json(EXAMPLE_DIR / "layer-contract.synthetic.json")
    assert contract["contract_digest"] == compute_digest(
        canonicalize(contract["outputs"])
    )


def test_layer_contract_outputs_match_declared_network_schema() -> None:
    contract = _load_json(EXAMPLE_DIR / "layer-contract.synthetic.json")
    network_schema = _load_json(SCHEMA_DIR / "contract-network.v1.schema.json")
    errors = list(
        Draft202012Validator(network_schema).iter_errors(contract["outputs"])
    )
    assert not errors, [error.message for error in errors]


def test_layer_contract_rejects_mismatched_producer() -> None:
    contract = _load_json(EXAMPLE_DIR / "layer-contract.synthetic.json")
    contract["producer"] = "roots/platform"
    assert list(_validator("layer-contract.schema.json").iter_errors(contract))


def test_layer_contract_rejects_global_region_for_regional_scope() -> None:
    contract = _load_json(EXAMPLE_DIR / "layer-contract.synthetic.json")
    contract["region"] = "global"
    assert list(_validator("layer-contract.schema.json").iter_errors(contract))


def test_layer_contract_rejects_state_key_owned_by_another_layer() -> None:
    contract = _load_json(EXAMPLE_DIR / "layer-contract.synthetic.json")
    contract["state_key"] = (
        f"{contract['deployment_id']}/{contract['region']}/platform/terraform.tfstate"
    )
    assert list(_validator("layer-contract.schema.json").iter_errors(contract))


@pytest.mark.parametrize(
    "forbidden_field,forbidden_value",
    [
        ("aws_account_id", "111122223333"),
        ("credentials", {"token": "synthetic-do-not-use"}),
        ("tfvars", {"raw": "synthetic"}),
        ("raw_outputs", {"vpc_id": "vpc-synthetic"}),
        ("terraform_plan", "synthetic.tfplan"),
        ("terraform_state", {"version": 4}),
        ("generated_manifest", "synthetic-generated.yaml"),
    ],
)
def test_deployment_request_rejects_sensitive_or_resolved_fields(
    forbidden_field: str, forbidden_value: object
) -> None:
    request = _load_json(EXAMPLE_DIR / "deployment-request.synthetic.json")
    request[forbidden_field] = forbidden_value
    assert list(_validator("deployment-request.schema.json").iter_errors(request))


def test_deployment_request_requires_exactly_one_target_mode() -> None:
    validator = _validator("deployment-request.schema.json")
    request = _load_json(EXAMPLE_DIR / "deployment-request.synthetic.json")

    no_target = copy.deepcopy(request)
    del no_target["full_deployment"]
    assert list(validator.iter_errors(no_target))

    both_targets = copy.deepcopy(request)
    both_targets["target_layer"] = "network"
    assert list(validator.iter_errors(both_targets))


def test_deployment_request_rejects_production() -> None:
    request = _load_json(EXAMPLE_DIR / "deployment-request.synthetic.json")
    request["environment"] = "production"
    assert list(_validator("deployment-request.schema.json").iter_errors(request))


def test_release_manifest_rejects_mutable_image_reference() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    manifest["service_image_digests"]["scanalyze-ingest-api"] = "example:latest"
    assert list(_validator("release-manifest.schema.json").iter_errors(manifest))


def test_release_manifest_requires_all_service_digests() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    del manifest["service_image_digests"]["scanalyze-gov-worker"]
    assert list(_validator("release-manifest.schema.json").iter_errors(manifest))


def test_release_manifest_requires_scan_evidence_for_completed_scan() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    manifest["scan_status"] = "passed"
    assert list(_validator("release-manifest.schema.json").iter_errors(manifest))


def test_release_manifest_requires_provenance_evidence_when_generated() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    manifest["provenance_status"] = "generated"
    assert list(_validator("release-manifest.schema.json").iter_errors(manifest))


def test_synthetic_release_identity_is_digest_bound() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    assert manifest["immutable_artifact_identity"] == (
        f"scanalyze-release@{manifest['release_digest']}"
    )


def test_identity_runtime_artifacts_are_immutable_and_content_addressed() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    validator = _validator("release-manifest.schema.json")

    for field in ("pre_token_artifact", "control_processor_artifact"):
        artifact = manifest[field]
        assert set(artifact) == {
            "bucket",
            "key",
            "object_version",
            "sha256_b64",
        }
        candidate = copy.deepcopy(manifest)
        candidate[field]["key"] = "identity/runtime/latest.zip"
        assert list(validator.iter_errors(candidate))

        candidate = copy.deepcopy(manifest)
        candidate[field]["object_version"] = ""
        assert list(validator.iter_errors(candidate))


@pytest.mark.parametrize(
    "version_id",
    [
        "synthetic+provider/Version=42",
        "versión/proveedor/部署=42",
    ],
)
def test_identity_runtime_artifacts_accept_opaque_s3_version_ids(
    version_id: str,
) -> None:
    """S3 VersionIds are opaque UTF-8 and must not be normalized."""

    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    validator = _validator("release-manifest.schema.json")

    for field in ("pre_token_artifact", "control_processor_artifact"):
        candidate = copy.deepcopy(manifest)
        candidate[field]["object_version"] = version_id
        errors = list(validator.iter_errors(candidate))
        assert not errors, [error.message for error in errors]


@pytest.mark.parametrize("sentinel", ["null", "NULL", "Null"])
def test_identity_runtime_artifacts_reject_null_version_sentinel(
    sentinel: str,
) -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    manifest["pre_token_artifact"]["object_version"] = sentinel

    assert list(_validator("release-manifest.schema.json").iter_errors(manifest))


def test_identity_runtime_artifact_schema_bounds_version_id_length() -> None:
    manifest = _load_json(EXAMPLE_DIR / "release-manifest.synthetic.json")
    validator = _validator("release-manifest.schema.json")

    boundary = copy.deepcopy(manifest)
    boundary["pre_token_artifact"]["object_version"] = "a" * 1024
    assert not list(validator.iter_errors(boundary))

    oversized = copy.deepcopy(manifest)
    oversized["pre_token_artifact"]["object_version"] = "a" * 1025
    assert list(validator.iter_errors(oversized))


def test_identity_runtime_consumers_enforce_utf8_byte_limit() -> None:
    sources = [
        REPO_ROOT / "modules" / "identity-control-plane" / "variables.tf",
        REPO_ROOT / "roots" / "identity-control-plane" / "contract_validation.tf",
    ]

    for path in sources:
        source = path.read_text(encoding="utf-8")
        assert "base64encode" in source
        assert "1368" in source
        assert 'endswith(' in source
        assert '"=="' in source
        assert "^[-A-Za-z0-9._~+/=]+$" not in source


def test_layers_yaml_has_exact_canonical_order_and_shape() -> None:
    with LAYERS_PATH.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)

    assert set(document) == {"schema_version", "layers"}
    assert document["schema_version"] == "1"
    assert [layer["layer"] for layer in document["layers"]] == EXPECTED_LAYER_ORDER
    assert all(set(layer) == REQUIRED_LAYER_FIELDS for layer in document["layers"])


def test_artifact_publication_produces_release_artifact_contract() -> None:
    with LAYERS_PATH.open(encoding="utf-8") as stream:
        layers = {item["layer"]: item for item in yaml.safe_load(stream)["layers"]}

    stage = layers["artifact-publication"]
    assert stage["kind"] == "artifact"
    assert stage["produces_contract"] == "release-manifest/v1"
    assert (SCHEMA_DIR / "release-manifest.schema.json").is_file()


def test_nonprod_workflow_matches_canonical_stage_order() -> None:
    workflow = _load_workflow(NONPROD_WORKFLOW_PATH)
    jobs = workflow["jobs"]

    assert jobs[EXPECTED_LAYER_ORDER[0]]["needs"] == "go-no-go"
    for predecessor, stage in zip(EXPECTED_LAYER_ORDER, EXPECTED_LAYER_ORDER[1:]):
        assert jobs[stage]["needs"] == predecessor


def test_nonprod_workflow_separates_logical_and_github_environments() -> None:
    workflow = _load_workflow(NONPROD_WORKFLOW_PATH)
    dispatch_inputs = _workflow_trigger(workflow)["workflow_dispatch"]["inputs"]

    assert "environment" not in dispatch_inputs
    assert dispatch_inputs["logical_environment"] == {
        "description": "Logical non-production stage recorded in the Git-safe request",
        "required": True,
        "default": "sandbox",
        "type": "choice",
        "options": ["sandbox", "dev", "staging"],
    }
    assert dispatch_inputs["github_environment"] == {
        "description": "Deployment-scoped protected GitHub Environment",
        "required": True,
        "type": "environment",
    }
    assert dispatch_inputs["allow_live"]["description"] == (
        "Enable one protected dev or staging saved-plan phase"
    )

    jobs = workflow["jobs"]
    protected_jobs = {
        job_id: job["environment"]["name"]
        for job_id, job in jobs.items()
        if "environment" in job
    }
    # The protected Environment belongs to the concrete job in the reusable
    # workflow; GitHub does not allow it on a reusable-workflow caller job.
    assert protected_jobs == {}

    reusable_jobs = {
        job_id: job
        for job_id, job in jobs.items()
        if job.get("uses") == "./.github/workflows/_terraform-layer.yml"
    }
    assert set(reusable_jobs) == {
        "live-layer",
        "account-ready-gate",
        "global",
        "network",
        "platform",
        "data-foundation",
        "cicd",
        "identity-control-plane",
        "services",
        "edge-identity",
        "edge",
        "addons",
    }
    for job_id, job in reusable_jobs.items():
        assert job["with"]["logical_environment"] == "${{ inputs.logical_environment }}"
        assert "environment" not in job["with"]
        if job_id == "live-layer":
            assert job["with"]["github_environment"] == (
                "${{ inputs.github_environment }}"
            )
        else:
            assert "github_environment" not in job["with"]


def test_protected_environment_bindings_are_required_and_fail_closed() -> None:
    workflow = _load_workflow(LAYER_WORKFLOW_PATH)
    gate = workflow["jobs"]["live_saved_plan"]
    step = next(
        item
        for item in gate["steps"]
        if item["name"] == "Validate protected Environment bindings before OIDC"
    )

    assert step["env"] == {
        "DESTINATION_ACCOUNT_ID": "${{ vars.AWS_ACCOUNT_ID }}",
        "ENVIRONMENT_DEPLOYMENT_ID": "${{ vars.DEPLOYMENT_ID }}",
        "ENVIRONMENT_LOGICAL_ENVIRONMENT": "${{ vars.LOGICAL_ENVIRONMENT }}",
        "ENVIRONMENT_REGION": "${{ vars.AWS_REGION }}",
        "GENERIC_APPLY_ROLE_ARN": "${{ vars.GENERIC_APPLY_ROLE_ARN }}",
        "GENERIC_PLAN_ROLE_ARN": "${{ vars.GENERIC_PLAN_ROLE_ARN }}",
        "IDENTITY_APPLY_ROLE_ARN": "${{ vars.IDENTITY_APPLY_ROLE_ARN }}",
        "IDENTITY_PLAN_ROLE_ARN": "${{ vars.IDENTITY_PLAN_ROLE_ARN }}",
        "ORCHESTRATOR_ROLE_ARN": "${{ vars.ORCHESTRATOR_ROLE_ARN }}",
        "PLATFORM_AUTHORITY_ACCOUNT_ID": (
            "${{ vars.PLATFORM_AUTHORITY_ACCOUNT_ID }}"
        ),
        "REPOSITORY_ID": "${{ vars.REPOSITORY_ID }}",
        "REPOSITORY_OWNER_ID": "${{ vars.REPOSITORY_OWNER_ID }}",
        "SECOND_P0_REVIEWER_ID": "${{ vars.SECOND_P0_REVIEWER_ID }}",
        "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID": (
            "${{ vars.GITHUB_ENVIRONMENT_COLLECTOR_APP_ID }}"
        ),
        "DISPATCH_DEPLOYMENT_ID": "${{ inputs.deployment_id }}",
        "DISPATCH_LOGICAL_ENVIRONMENT": "${{ inputs.logical_environment }}",
        "DISPATCH_REGION": "${{ inputs.aws_region }}",
    }

    script = step["run"]
    for binding in (
        "DESTINATION_ACCOUNT_ID",
        "ENVIRONMENT_DEPLOYMENT_ID",
        "ENVIRONMENT_LOGICAL_ENVIRONMENT",
        "ENVIRONMENT_REGION",
        "ORCHESTRATOR_ROLE_ARN",
        "PLATFORM_AUTHORITY_ACCOUNT_ID",
        "SECOND_P0_REVIEWER_ID",
    ):
        assert binding in script
    assert 'if [[ -z "${!name:-}" ]]; then' in script
    assert '"$ENVIRONMENT_DEPLOYMENT_ID" != "$DISPATCH_DEPLOYMENT_ID"' in script
    assert (
        '"$ENVIRONMENT_LOGICAL_ENVIRONMENT" != '
        '"$DISPATCH_LOGICAL_ENVIRONMENT"'
    ) in script
    assert '"$ENVIRONMENT_REGION" != "$DISPATCH_REGION"' in script
    assert '"$DESTINATION_ACCOUNT_ID" == "$PLATFORM_AUTHORITY_ACCOUNT_ID"' in script

    error_lines = [line for line in script.splitlines() if "::error::" in line]
    assert error_lines
    assert all("$ENVIRONMENT_" not in line for line in error_lines)
    assert all("$DISPATCH_" not in line for line in error_lines)


def _run_environment_gate(**overrides: str) -> subprocess.CompletedProcess[str]:
    workflow = _load_workflow(LAYER_WORKFLOW_PATH)
    gate = workflow["jobs"]["live_saved_plan"]
    script = next(
        item["run"]
        for item in gate["steps"]
        if item["name"] == "Validate protected Environment bindings before OIDC"
    )
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    destination_account_id = "123456789012"
    platform_account_id = "210987654321"
    env = os.environ.copy()
    env.update(
        {
            "DESTINATION_ACCOUNT_ID": destination_account_id,
            "ENVIRONMENT_DEPLOYMENT_ID": deployment_id,
            "ENVIRONMENT_LOGICAL_ENVIRONMENT": "dev",
            "ENVIRONMENT_REGION": "us-east-1",
            "GENERIC_APPLY_ROLE_ARN": (
                f"arn:aws:iam::{destination_account_id}:"
                "role/ScanalyzeCustomer-Apply"
            ),
            "GENERIC_PLAN_ROLE_ARN": (
                f"arn:aws:iam::{destination_account_id}:role/ScanalyzeCustomer-Plan"
            ),
            "IDENTITY_APPLY_ROLE_ARN": (
                f"arn:aws:iam::{destination_account_id}:"
                "role/ScanalyzeCustomer-Identity-Apply"
            ),
            "IDENTITY_PLAN_ROLE_ARN": (
                f"arn:aws:iam::{destination_account_id}:"
                "role/ScanalyzeCustomer-Identity-Plan"
            ),
            "ORCHESTRATOR_ROLE_ARN": (
                f"arn:aws:iam::{platform_account_id}:"
                f"role/ScanalyzeOrchestrator-{deployment_id}"
            ),
            "PLATFORM_AUTHORITY_ACCOUNT_ID": platform_account_id,
            "REPOSITORY_ID": "2000002",
            "REPOSITORY_OWNER_ID": "1000001",
            "SECOND_P0_REVIEWER_ID": "3000003",
            "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID": "7000007",
            "DISPATCH_DEPLOYMENT_ID": deployment_id,
            "DISPATCH_LOGICAL_ENVIRONMENT": "dev",
            "DISPATCH_REGION": "us-east-1",
            "GITHUB_REPOSITORY_ID": "2000002",
            "GITHUB_REPOSITORY_OWNER_ID": "1000001",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_protected_environment_gate_accepts_exact_bindings() -> None:
    result = _run_environment_gate()
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_protected_environment_gate_accepts_exact_staging_bindings() -> None:
    result = _run_environment_gate(
        ENVIRONMENT_LOGICAL_ENVIRONMENT="staging",
        DISPATCH_LOGICAL_ENVIRONMENT="staging",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize(
    "overrides",
    [
        {"ENVIRONMENT_DEPLOYMENT_ID": ""},
        {"ENVIRONMENT_LOGICAL_ENVIRONMENT": ""},
        {"ENVIRONMENT_REGION": ""},
        {"SECOND_P0_REVIEWER_ID": ""},
        {"ENVIRONMENT_DEPLOYMENT_ID": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"},
        {"ENVIRONMENT_LOGICAL_ENVIRONMENT": "staging"},
        {"ENVIRONMENT_REGION": "us-west-2"},
        {"PLATFORM_AUTHORITY_ACCOUNT_ID": "123456789012"},
        {"REPOSITORY_ID": "9999999"},
    ],
)
def test_protected_environment_gate_rejects_missing_or_mismatched_bindings(
    overrides: dict[str, str],
) -> None:
    result = _run_environment_gate(**overrides)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW" not in combined
    assert "us-west-2" not in combined


def test_reusable_layer_uses_logical_nonprod_environment_only() -> None:
    workflow = _load_workflow(LAYER_WORKFLOW_PATH)
    call_inputs = _workflow_trigger(workflow)["workflow_call"]["inputs"]

    assert "logical_environment" in call_inputs
    assert "environment" not in call_inputs
    assert "github_environment" in call_inputs
    assert "environment" not in workflow["jobs"]["offline_validation"]
    assert workflow["jobs"]["live_saved_plan"]["environment"] == {
        "name": "${{ inputs.github_environment }}"
    }
    assert "live_input_gate" not in workflow["jobs"]

    validation_step = next(
        item
        for item in workflow["jobs"]["mode_boundary"]["steps"]
        if item["name"] == "Reject unauthorized modes before credentials"
    )
    assert validation_step["env"]["LOGICAL_ENVIRONMENT"] == (
        "${{ inputs.logical_environment }}"
    )
    assert "sandbox|dev|staging" in validation_step["run"]
    assert "sandbox|dev|staging|production" not in validation_step["run"]
    assert '"$LOGICAL_ENVIRONMENT" != "dev"' in validation_step["run"]
    assert '"$LOGICAL_ENVIRONMENT" != "staging"' in validation_step["run"]
    assert (
        '"scanalyze-${DEPLOYMENT_ID}-${LOGICAL_ENVIRONMENT}"'
        in validation_step["run"]
    )


def test_oidc_is_allowlisted_to_the_canonical_live_jobs() -> None:
    expected = {
        NONPROD_WORKFLOW_PATH: {"live-layer"},
        LAYER_WORKFLOW_PATH: {"live_saved_plan"},
    }
    for workflow_path, privileged_jobs in expected.items():
        workflow = _load_workflow(workflow_path)
        assert "id-token" not in workflow.get("permissions", {})
        observed = set()
        for job_name, job in workflow["jobs"].items():
            permissions = job.get("permissions", {})
            configure_steps = [
                step
                for step in job.get("steps", [])
                if isinstance(step, dict)
                and str(step.get("uses", "")).startswith(
                    "aws-actions/configure-aws-credentials@"
                )
            ]
            if "id-token" in permissions or configure_steps:
                observed.add(job_name)
            if job_name not in privileged_jobs:
                assert "id-token" not in permissions
                assert not configure_steps
        assert observed == privileged_jobs

    workflow = _load_workflow(LAYER_WORKFLOW_PATH)
    assert "live_input_gate" not in workflow["jobs"]
    reusable = workflow["jobs"]["live_saved_plan"]
    assert reusable["needs"] == "mode_boundary"
    assert reusable["permissions"] == {
        "actions": "read",
        "contents": "read",
        "id-token": "write",
    }
    steps = reusable["steps"]
    indexes = {step["name"]: index for index, step in enumerate(steps)}
    assert (
        indexes["Validate protected Environment bindings before OIDC"]
        < indexes["Create scoped GitHub App inventory token"]
        < indexes["Materialize and compare live inputs twice before OIDC"]
        < indexes["Materialize exact GitHub approval for apply"]
        < indexes["Validate exact GitHub approval for apply"]
        < indexes["Revoke GitHub App evidence token before OIDC"]
        < indexes["Set up Terraform after pre-OIDC evidence gates"]
        < indexes["Install live-engine dependencies after pre-OIDC evidence gates"]
        < indexes["Acquire exact platform-authority OIDC session"]
        < indexes["Execute the exact protected saved-plan phase"]
    )

    app_step = steps[indexes["Create scoped GitHub App inventory token"]]
    assert app_step["id"] == "github_app_token"
    assert app_step["uses"] == (
        "actions/create-github-app-token@"
        "bcd2ba49218906704ab6c1aa796996da409d3eb1"
    )
    assert app_step["with"]["app-id"] == (
        "${{ vars.GITHUB_ENVIRONMENT_COLLECTOR_APP_ID }}"
    )
    expected_key_input = (
        "${{ secrets."
        + "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_"
        + "PRIVATE"
        + "_KEY }}"
    )
    assert app_step["with"] == {
        "app-id": "${{ vars.GITHUB_ENVIRONMENT_COLLECTOR_APP_ID }}",
        "private-key": expected_key_input,
        "owner": "${{ github.repository_owner }}",
        "repositories": "${{ github.event.repository.name }}",
        "skip-token-revoke": True,
    }
    assert not any(key.startswith("permission-") for key in app_step["with"])

    rematerializer = steps[
        indexes["Materialize and compare live inputs twice before OIDC"]
    ]
    assert rematerializer["env"]["GITHUB_APP_TOKEN"] == (
        "${{ steps.github_app_token.outputs.token }}"
    )
    assert rematerializer["env"]["SCANALYZE_GITHUB_APP_INSTALLATION_ID"] == (
        "${{ steps.github_app_token.outputs.installation-id }}"
    )
    assert rematerializer["env"]["SCANALYZE_GITHUB_APP_PRIVATE_KEY"] == (
        expected_key_input
    )
    assert rematerializer["env"]["SCANALYZE_GITHUB_APP_SLUG"] == (
        "${{ steps.github_app_token.outputs.app-slug }}"
    )
    assert "GITHUB_TOKEN" not in rematerializer["env"]
    assert not any(
        key.startswith("SCANALYZE_GITHUB_ENVIRONMENT_VALUE_")
        for key in rematerializer["env"]
    )
    rematerialize_script = rematerializer["run"]
    assert rematerialize_script.count(
        "nonprod-live-input-materializer.py stage"
    ) == 2
    assert 'materialize_pass "$first_root"' in rematerialize_script
    assert 'materialize_pass "$private_root"' in rematerialize_script
    assert "--token-env-name GITHUB_APP_TOKEN" in rematerialize_script
    assert (
        "sealed_request_digest claim_digest approval_authority_digest; do"
        in rematerialize_script
    )
    assert "SCANALYZE_GITHUB_APP_PRIVATE_KEY" in rematerialize_script
    assert "receipt_digest receipt_digest" not in rematerialize_script

    approval_materialize = steps[
        indexes["Materialize exact GitHub approval for apply"]
    ]
    approval_validate = steps[
        indexes["Validate exact GitHub approval for apply"]
    ]
    assert approval_materialize["env"]["GH_TOKEN"] == (
        "${{ steps.github_app_token.outputs.token }}"
    )
    assert "GH_TOKEN" not in approval_validate["env"]
    for approval_step in (approval_materialize, approval_validate):
        assert '--run-attempt "$GITHUB_RUN_ATTEMPT"' in approval_step["run"]
        assert (
            '--apply-environment-anchor-digest '
            '"$GITHUB_ENVIRONMENT_ANCHOR_DIGEST"'
        ) in approval_step["run"]

    token_revoker = steps[
        indexes["Revoke GitHub App evidence token before OIDC"]
    ]
    assert token_revoker["if"] == "${{ always() }}"
    assert token_revoker["env"]["GH_TOKEN"] == (
        "${{ steps.github_app_token.outputs.token }}"
    )
    assert '"DELETE"' in token_revoker["run"]
    assert '"/installation/token"' in token_revoker["run"]
    assert "response.status != 204" in token_revoker["run"]

    controller = steps[indexes["Execute the exact protected saved-plan phase"]]
    assert controller["env"]["RECEIPT_DIGEST"] == (
        "${{ steps.rematerialize.outputs.receipt_digest }}"
    )
    for denied in (
        "SCANALYZE_LIVE_INPUT_BUNDLE_B64",
        "GITHUB_APP_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    ):
        assert denied not in controller["env"]

    workflow_text = LAYER_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert workflow_text.count(
        "${{ secrets.SCANALYZE_LIVE_INPUT_BUNDLE_B64 }}"
    ) == 1
    assert workflow_text.count(expected_key_input) == 2
    assert workflow_text.count("${{ github.token }}") == 0
    assert workflow_text.count(
        "${{ steps.github_app_token.outputs.token }}"
    ) == 3
    assert "stale_apply_recovery" not in workflow["jobs"]
    assert "recover-stale" not in workflow_text


def test_live_claim_digest_is_exact_and_never_a_caller_path() -> None:
    caller = _load_workflow(NONPROD_WORKFLOW_PATH)
    reusable = _load_workflow(LAYER_WORKFLOW_PATH)
    dispatch_inputs = _workflow_trigger(caller)["workflow_dispatch"]["inputs"]
    call_inputs = _workflow_trigger(reusable)["workflow_call"]["inputs"]

    assert dispatch_inputs["live_operation"]["options"] == [
        "none",
        "plan",
        "apply",
    ]

    assert dispatch_inputs["live_input_claim_digest"] == {
        "description": (
            "Exact tracked live-input claim digest; required only by live phases"
        ),
        "required": False,
        "type": "string",
    }
    assert call_inputs["live_input_claim_digest"]["default"] == ""
    assert caller["jobs"]["live-layer"]["with"]["live_input_claim_digest"] == (
        "${{ inputs.live_input_claim_digest }}"
    )
    assert "private_root" not in dispatch_inputs
    assert "bundle" not in dispatch_inputs

    dispatch_gate = next(
        step
        for step in caller["jobs"]["preflight"]["steps"]
        if step.get("name") == "Validate dispatch execution mode"
    )
    reusable_gate = reusable["jobs"]["mode_boundary"]["steps"][0]
    for gate in (dispatch_gate, reusable_gate):
        assert gate["env"]["LIVE_INPUT_CLAIM_DIGEST"].endswith(
            "inputs.live_input_claim_digest }}"
        )
        assert "^sha256:[0-9a-f]{64}$" in gate["run"]
        assert '"$LOGICAL_ENVIRONMENT" != "dev"' in gate["run"]
        assert '"$LOGICAL_ENVIRONMENT" != "staging"' in gate["run"]
        assert (
            '"scanalyze-${DEPLOYMENT_ID}-${LOGICAL_ENVIRONMENT}"'
            in gate["run"]
        )
        assert gate["env"]["RUN_ATTEMPT"] == "${{ github.run_attempt }}"
        assert '"$RUN_ATTEMPT" != "1"' in gate["run"]
        assert "sandbox|dev|staging|production" not in gate["run"]


def _run_dispatch_mode_gate(**overrides: str) -> subprocess.CompletedProcess[str]:
    workflow = _load_workflow(NONPROD_WORKFLOW_PATH)
    step = next(
        item
        for item in workflow["jobs"]["preflight"]["steps"]
        if item.get("name") == "Validate dispatch execution mode"
    )
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    env = os.environ.copy()
    env.update(
        {
            "ALLOW_LIVE": "true",
            "CHANGE_ID": "chg_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "DEPLOYMENT_ID": deployment_id,
            "DRY_RUN": "false",
            "EVENT_NAME": "workflow_dispatch",
            "EXECUTION_ID": "exec_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "GITHUB_ENVIRONMENT_INPUT": f"scanalyze-{deployment_id}-dev",
            "LIVE_INPUT_CLAIM_DIGEST": "sha256:" + ("c" * 64),
            "LIVE_OPERATION": "plan",
            "LOGICAL_ENVIRONMENT": "dev",
            "MAIN_SHA": "a" * 40,
            "PLAN_RECORD_DIGEST": "",
            "REVIEWER_PACKET_DIGEST": "",
            "REF_NAME": "refs/heads/main",
            "REF_PROTECTED": "true",
            "RUN_ATTEMPT": "1",
            "RUN_SHA": "a" * 40,
            "TARGET_LAYER": "network",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _run_reusable_mode_gate(**overrides: str) -> subprocess.CompletedProcess[str]:
    workflow = _load_workflow(LAYER_WORKFLOW_PATH)
    step = next(
        item
        for item in workflow["jobs"]["mode_boundary"]["steps"]
        if item.get("name") == "Reject unauthorized modes before credentials"
    )
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
    env = os.environ.copy()
    env.update(
        {
            "ALLOW_LIVE": "true",
            "AWS_REGION_INPUT": "us-east-1",
            "CHANGE_ID": "chg_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "DEPLOYMENT_ID": deployment_id,
            "DRY_RUN": "false",
            "EVENT_NAME": "workflow_dispatch",
            "EXECUTION_ID": "exec_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "GITHUB_ENVIRONMENT_INPUT": f"scanalyze-{deployment_id}-dev",
            "HEAD_REPOSITORY_ID": "2000002",
            "LIVE_INPUT_CLAIM_DIGEST": "sha256:" + ("c" * 64),
            "LIVE_OPERATION": "plan",
            "LOGICAL_ENVIRONMENT": "dev",
            "MAIN_SHA": "a" * 40,
            "PLAN_RECORD_DIGEST": "",
            "RELEASE_DIGEST": "sha256:" + ("d" * 64),
            "REVIEWER_PACKET_DIGEST": "",
            "REF_NAME": "refs/heads/main",
            "REF_PROTECTED": "true",
            "RUN_ATTEMPT": "1",
            "RUN_SHA": "a" * 40,
            "TARGET_LAYER": "network",
        }
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize(
    "gate_runner",
    [_run_dispatch_mode_gate, _run_reusable_mode_gate],
    ids=["dispatch", "reusable"],
)
def test_live_mode_gates_accept_dev_and_staging_but_reject_production(
    gate_runner,
) -> None:
    deployment_id = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"

    dev = gate_runner()
    assert dev.returncode == 0, dev.stdout + dev.stderr

    staging = gate_runner(
        LOGICAL_ENVIRONMENT="staging",
        GITHUB_ENVIRONMENT_INPUT=f"scanalyze-{deployment_id}-staging",
    )
    assert staging.returncode == 0, staging.stdout + staging.stderr

    wrong_environment = gate_runner(
        LOGICAL_ENVIRONMENT="staging",
        GITHUB_ENVIRONMENT_INPUT=f"scanalyze-{deployment_id}-dev",
    )
    assert wrong_environment.returncode != 0
    assert "Environment" in wrong_environment.stdout

    production = gate_runner(
        LOGICAL_ENVIRONMENT="production",
        GITHUB_ENVIRONMENT_INPUT=f"scanalyze-{deployment_id}-production",
    )
    assert production.returncode != 0
    assert "restricted to dev or staging" in production.stdout


def test_live_dispatch_requires_claim_and_rejects_removed_operations() -> None:
    valid = _run_dispatch_mode_gate()
    assert valid.returncode == 0, valid.stdout + valid.stderr

    missing_claim = _run_dispatch_mode_gate(LIVE_INPUT_CLAIM_DIGEST="")
    assert missing_claim.returncode != 0
    assert "tracked input claim digest" in missing_claim.stdout

    rerun = _run_dispatch_mode_gate(RUN_ATTEMPT="2")
    assert rerun.returncode != 0
    assert "fresh workflow run" in rerun.stdout

    removed_recovery = _run_dispatch_mode_gate(LIVE_OPERATION="recover-stale")
    assert removed_recovery.returncode != 0
    assert "requires plan or apply" in removed_recovery.stdout

    dry_run_with_claim = _run_dispatch_mode_gate(
        ALLOW_LIVE="false",
        DRY_RUN="true",
        LIVE_OPERATION="none",
    )
    assert dry_run_with_claim.returncode != 0
    assert "Dry-run cannot carry live saved-plan inputs" in (
        dry_run_with_claim.stdout
    )


def test_git_safe_examples_contain_no_arns() -> None:
    for example_path in EXAMPLE_DIR.glob("*.json"):
        assert "arn:aws" not in example_path.read_text(encoding="utf-8").lower()
