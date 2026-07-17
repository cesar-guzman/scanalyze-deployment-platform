"""GUG-125 portable platform-authority factory contract tests.

These tests intentionally inspect the repository-owned Terraform boundary. The
live AWS proof remains a separate evidence class and requires an explicitly
authorized platform-authority account.
"""
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = REPO_ROOT / "modules/platform-authority"
ROOT = REPO_ROOT / "roots/platform-authority"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_platform_authority_is_a_complete_repository_module_and_root() -> None:
    module_files = {
        "README.md",
        "versions.tf",
        "variables.tf",
        "outputs.tf",
        "locals.tf",
        "contract.tf",
        "identity.tf",
        "storage.tf",
    }
    root_files = {
        "README.md",
        "versions.tf",
        "variables.tf",
        "main.tf",
        "outputs.tf",
        "contract_validation.tf",
        "backend.example.hcl",
    }
    assert module_files <= {path.name for path in MODULE.iterdir()}
    assert root_files <= {path.name for path in ROOT.iterdir()}


def test_factory_is_multi_customer_and_not_bound_to_fixture_accounts() -> None:
    variables = _read(MODULE / "variables.tf")
    identity = _read(MODULE / "identity.tf")
    root = _read(ROOT / "main.tf")
    combined = variables + identity + root

    assert 'variable "deployments"' in variables
    assert "map(object({" in variables
    assert "customer_id" in variables
    assert "deployment_id" in variables
    assert "destination_account_id" in variables
    assert "github_oidc_subject" in variables
    assert "for_each = var.deployments" in identity
    assert "ScanalyzeOrchestrator-${each.value.deployment_id}" in identity
    assert "905418363887" not in combined
    assert "540150372644" not in combined


def test_factory_fails_closed_on_authority_or_binding_confusion() -> None:
    contract = _read(MODULE / "contract.tf")
    variables = _read(MODULE / "variables.tf")

    assert "authority_account_id != deployment.destination_account_id" in contract
    assert "deployment_key == deployment.deployment_id" in contract
    assert "length(distinct(" in contract
    assert 'regex("^cust_' in variables
    assert 'regex("^dep_' in variables
    assert "sandbox" in variables
    assert "staging" in variables
    assert '"production"' not in variables


def test_oidc_trust_and_orchestrator_roles_are_exact_and_short_lived() -> None:
    identity = _read(MODULE / "identity.tf")
    trust = identity + _read(MODULE / "locals.tf")

    assert 'url            = "https://token.actions.githubusercontent.com"' in identity
    assert 'client_id_list = ["sts.amazonaws.com"]' in identity
    assert '"token.actions.githubusercontent.com:aud"' in trust
    assert '"token.actions.githubusercontent.com:sub"' in trust
    assert '"token.actions.githubusercontent.com:repository_owner_id"' in trust
    assert '"token.actions.githubusercontent.com:repository_id"' in trust
    assert "deployment.github_oidc_subject" in trust
    assert "deployment.repository_owner_id" in trust
    assert "deployment.repository_id" in trust
    assert "(?:@[0-9]+)?" in _read(MODULE / "variables.tf")
    assert "StringLike" not in trust
    assert "max_session_duration = 3600" in identity
    assert "requested_session_duration_seconds = 900" in _read(MODULE / "locals.tf")
    assert "permissions_boundary = aws_iam_policy.orchestrator_boundary.arn" in identity
    assert "aws_iam_role_policy_attachment" in identity
    assert '"iam:*"' not in identity
    assert "iam:PassRole" not in identity


def test_control_storage_is_encrypted_recoverable_and_contains_no_workloads() -> None:
    storage = _read(MODULE / "storage.tf")
    locals = _read(MODULE / "locals.tf")
    combined = storage + locals

    assert combined.count('resource "aws_dynamodb_table"') == 2
    assert 'name         = "scanalyze-deployment-registry"' in storage
    assert 'name         = "scanalyze-deployment-executions"' in storage
    assert storage.count("point_in_time_recovery") == 2
    assert storage.count("deletion_protection_enabled = true") == 2
    assert storage.count("prevent_destroy = true") >= 4
    assert 'sse_algorithm     = "aws:kms"' in storage
    assert 'status = "Enabled"' in storage
    assert "aws_s3_bucket_public_access_block" in storage
    assert "aws_s3_bucket_ownership_controls" in storage
    for forbidden in ("aws_ecs_", "aws_sqs_", "aws_textract_", "aws_bedrock_"):
        assert forbidden not in combined


def test_release_bucket_and_runtime_policy_are_injected_not_global_constants() -> None:
    variables = _read(MODULE / "variables.tf")
    locals = _read(MODULE / "locals.tf")

    assert 'variable "release_bucket_name"' in variables
    assert "var.release_bucket_name" in locals
    assert "var.aws_partition" in locals
    assert "platform_authority_kms_key_arn" in locals
    assert "scanalyze-shared-releases" not in locals
    assert 'replace(' in locals
    assert '"$${release_bucket_name}"' in locals


def test_root_pins_the_exact_authority_account_and_does_not_bootstrap_itself() -> None:
    versions = _read(ROOT / "versions.tf")
    main = _read(ROOT / "main.tf")
    readme = _read(ROOT / "README.md")

    assert "allowed_account_ids = [var.authority_account_id]" in versions
    assert "module \"platform_authority\"" in main
    assert "Identity Center" in readme
    assert "bootstrap" in readme.lower()
    assert "customer" in readme.lower() and "workload" in readme.lower()
    assert "terraform apply" not in readme.lower()


def test_make_gates_and_interface_checker_include_platform_authority() -> None:
    makefile = _read(REPO_ROOT / "Makefile")
    checker = _read(REPO_ROOT / "tooling/check_module_interfaces.py")

    assert "platform-authority" in makefile
    assert '"platform-authority"' in checker


def test_platform_authority_lock_files_cover_ci_and_local_platforms() -> None:
    module_lock = _read(MODULE / ".terraform.lock.hcl")
    root_lock = _read(ROOT / ".terraform.lock.hcl")
    makefile = _read(REPO_ROOT / "Makefile")
    required_platform_hashes = {
        # darwin_arm64, generated by the signed HashiCorp provider release
        "h1:Ijt7pOlB7Tr7maGQIqtsLFbl7pSMIj06TVdkoSBcYOw=",
        # linux_amd64, generated by the signed HashiCorp provider release
        "h1:edXOJWE4ORX8Fm+dpVpICzMZJat4AX0VRCAy/xkcOc0=",
    }

    assert module_lock == root_lock
    assert all(checksum in module_lock for checksum in required_platform_hashes)
    assert "-lockfile=readonly" in makefile


def test_operational_docs_keep_human_and_machine_bootstrap_separate() -> None:
    runbook = _read(REPO_ROOT / "docs/deployment/platform-authority-bootstrap.md")
    threat_model = _read(REPO_ROOT / "docs/security/gug-125-threat-model-delta.md")

    assert "IAM Identity Center" in runbook
    assert "GitHub OIDC" in runbook
    assert "static" in runbook.lower() and "access key" in runbook.lower()
    assert "customer_id" in runbook
    assert "deployment_id" in runbook
    assert "platform-authority" in threat_model
    assert "customer documents" in threat_model.lower()
