"""Offline tests for the repository-global GitHub governance contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tooling.validate_github_policy import GitHubPolicyError, validate_policy


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "github-policy.schema.json"


def _write_fixture(tmp_path: Path, workflow_text: str) -> tuple[Path, Path, Path]:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(workflow_text, encoding="utf-8")
    policy = {
        "schema_version": "1",
        "scope": "repository",
        "default_branch": "main",
        "required_status_checks": {
            "strict": True,
            "expected_app_slug": "github-actions",
            "checks": [
                {
                    "context": "Stable gate",
                    "workflow": ".github/workflows/ci.yml",
                    "job": "gate",
                }
            ],
        },
        "migration": {
            "added_contexts": ["Stable gate"],
            "retired_contexts": ["Legacy matrix leg"],
        },
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path, SCHEMA_PATH, workflow_dir


def _valid_workflow() -> str:
    return """\
name: CI
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
jobs:
  upstream:
    name: Informational job
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
  gate:
    name: Stable gate
    needs: upstream
    if: ${{ always() }}
    permissions: {}
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
"""


def _validate_fixture(tmp_path: Path, workflow_text: str) -> dict:
    policy_path, schema_path, workflow_dir = _write_fixture(tmp_path, workflow_text)
    return validate_policy(
        repo_root=tmp_path,
        policy_path=policy_path,
        schema_path=schema_path,
        workflows_dir=workflow_dir,
    )


def test_repository_policy_matches_static_workflow_contract() -> None:
    policy = validate_policy()

    assert len(policy["_derived"]["target_contexts"]) == 6
    assert len(policy["_derived"]["legacy_contexts"]) == 14
    assert "Microservices validation gate" in policy["_derived"]["target_contexts"]
    assert "Validate ingest-api" not in policy["_derived"]["target_contexts"]


def test_minimal_static_always_gate_is_valid(tmp_path: Path) -> None:
    policy = _validate_fixture(tmp_path, _valid_workflow())
    assert policy["_derived"]["target_contexts"] == ["Stable gate"]


def test_required_workflow_path_filter_is_rejected(tmp_path: Path) -> None:
    workflow = _valid_workflow().replace(
        "    branches: [main]", "    branches: [main]\n    paths: ['src/**']"
    )
    with pytest.raises(GitHubPolicyError, match="cannot use pull_request.paths"):
        _validate_fixture(tmp_path, workflow)


def test_dependent_required_job_without_always_is_rejected(tmp_path: Path) -> None:
    workflow = _valid_workflow().replace("    if: ${{ always() }}\n", "")
    with pytest.raises(GitHubPolicyError, match="must use if: always"):
        _validate_fixture(tmp_path, workflow)


def test_matrix_required_job_is_rejected(tmp_path: Path) -> None:
    workflow = _valid_workflow().replace(
        "    permissions: {}\n    runs-on:",
        "    permissions: {}\n    strategy:\n      matrix:\n        item: [one, two]\n    runs-on:",
    )
    with pytest.raises(GitHubPolicyError, match="cannot be a matrix job"):
        _validate_fixture(tmp_path, workflow)


def test_privileged_required_job_is_rejected(tmp_path: Path) -> None:
    workflow = _valid_workflow().replace(
        "    permissions: {}", "    permissions:\n      id-token: write"
    )
    with pytest.raises(GitHubPolicyError, match="cannot grant id-token"):
        _validate_fixture(tmp_path, workflow)


@pytest.mark.parametrize(
    "value",
    [
        "${{ true }}",
        "${{ github.actor != 'nobody' }}",
        "yes",
    ],
)
def test_required_job_rejects_nonliteral_false_continue_on_error(
    tmp_path: Path,
    value: str,
) -> None:
    workflow = _valid_workflow().replace(
        "    permissions: {}\n",
        f"    permissions: {{}}\n    continue-on-error: {value}\n",
    )

    with pytest.raises(GitHubPolicyError, match="cannot continue on error"):
        _validate_fixture(tmp_path, workflow)


def test_required_job_allows_literal_false_continue_on_error(tmp_path: Path) -> None:
    workflow = _valid_workflow().replace(
        "    permissions: {}\n",
        "    permissions: {}\n    continue-on-error: false\n",
    )

    assert _validate_fixture(tmp_path, workflow)["_derived"]["target_contexts"] == [
        "Stable gate"
    ]


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("permissions:\n  contents: read", "permissions: write-all"),
        ("    permissions: {}", "    permissions: write-all"),
        (
            "    permissions: {}",
            "    permissions:\n      contents: write",
        ),
    ],
)
def test_write_capable_required_workflow_or_job_is_rejected(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    workflow = _valid_workflow().replace(original, replacement)

    with pytest.raises(GitHubPolicyError, match="read-only or empty"):
        _validate_fixture(tmp_path, workflow)


@pytest.mark.parametrize(
    "workflow",
    [
        _valid_workflow().replace(
            "permissions:\n  contents: read",
            "permissions: read-all",
        ),
        _valid_workflow()
        .replace(
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n  statuses: none",
        )
        .replace("    permissions: {}\n", ""),
        _valid_workflow().replace(
            "    permissions: {}",
            "    permissions:\n      contents: read\n      id-token: none",
        ),
    ],
)
def test_read_only_and_empty_permission_forms_remain_valid(
    tmp_path: Path,
    workflow: str,
) -> None:
    assert _validate_fixture(tmp_path, workflow)["_derived"]["target_contexts"] == [
        "Stable gate"
    ]


def test_required_workflow_restrictive_pr_activity_types_are_rejected(
    tmp_path: Path,
) -> None:
    workflow = _valid_workflow().replace(
        "    branches: [main]",
        "    branches: [main]\n    types: [closed]",
    )

    with pytest.raises(
        GitHubPolicyError,
        match="pull_request.types must include opened, synchronize, and reopened",
    ):
        _validate_fixture(tmp_path, workflow)


def test_dynamic_job_name_that_can_resolve_to_required_context_is_rejected(
    tmp_path: Path,
) -> None:
    workflow = _valid_workflow() + """\
  spoof:
    name: ${{ 'Stable gate' }}
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
"""

    with pytest.raises(
        GitHubPolicyError,
        match="dynamic job name could resolve to required context 'Stable gate'",
    ):
        _validate_fixture(tmp_path, workflow)


def test_dynamic_name_with_embedded_closing_delimiter_is_rejected(
    tmp_path: Path,
) -> None:
    workflow = _valid_workflow() + """\
  spoof:
    name: ${{ '}}' && matrix.context }}
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
"""

    with pytest.raises(
        GitHubPolicyError,
        match="dynamic job name could resolve to required context 'Stable gate'",
    ):
        _validate_fixture(tmp_path, workflow)


@pytest.mark.parametrize("trigger", ["push", "workflow_dispatch", "workflow_call"])
def test_dynamic_name_collision_is_rejected_in_every_workflow(
    tmp_path: Path,
    trigger: str,
) -> None:
    policy_path, schema_path, workflow_dir = _write_fixture(tmp_path, _valid_workflow())
    (workflow_dir / "spoof.yml").write_text(
        f"""\
name: Non-PR producer
on:
  {trigger}:
permissions: {{}}
jobs:
  spoof:
    name: ${{{{ 'Stable gate' }}}}
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
""",
        encoding="utf-8",
    )

    with pytest.raises(
        GitHubPolicyError,
        match="dynamic job name could resolve to required context 'Stable gate'",
    ):
        validate_policy(
            repo_root=tmp_path,
            policy_path=policy_path,
            schema_path=schema_path,
            workflows_dir=workflow_dir,
        )


def test_noncolliding_dynamic_diagnostic_name_remains_valid(tmp_path: Path) -> None:
    workflow = _valid_workflow() + """\
  diagnostic:
    name: Diagnostic service ${{ matrix.service }}
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        service: [one, two]
    steps:
      - run: exit 0
"""

    assert _validate_fixture(tmp_path, workflow)["_derived"]["target_contexts"] == [
        "Stable gate"
    ]


def test_implicit_job_id_collision_is_rejected(tmp_path: Path) -> None:
    workflow = (
        _valid_workflow()
        .replace("  gate:\n", "  required:\n")
        .replace("    name: Stable gate\n", "    name: gate\n")
    ) + """\
  gate:
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
"""
    policy_path, schema_path, workflow_dir = _write_fixture(tmp_path, workflow)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["required_status_checks"]["checks"][0].update(
        {"context": "gate", "job": "required"}
    )
    policy["migration"]["added_contexts"] = ["gate"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(GitHubPolicyError, match="exactly one static producer"):
        validate_policy(
            repo_root=tmp_path,
            policy_path=policy_path,
            schema_path=schema_path,
            workflows_dir=workflow_dir,
        )


@pytest.mark.parametrize(
    ("workflow", "error"),
    [
        (
            _valid_workflow().replace(
                "    name: Stable gate\n",
                "    name: Stable gate\n    name: Spoofed gate\n",
            ),
            "duplicate key 'name'",
        ),
        (
            _valid_workflow().replace(
                "  gate:\n",
                "  gate:\n    <<: &merged_job\n      name: Stable gate\n",
            ),
            "YAML merge keys are not permitted",
        ),
        (
            _valid_workflow().replace("  gate:\n", "  gate: !custom\n"),
            "custom YAML tag",
        ),
        (
            _valid_workflow()
            + "---\njobs:\n  spoof:\n    name: Stable gate\n",
            "expected a single document",
        ),
    ],
    ids=["duplicate-key", "merge-key", "custom-tag", "multiple-documents"],
)
def test_ambiguous_yaml_mapping_is_rejected(
    tmp_path: Path,
    workflow: str,
    error: str,
) -> None:
    with pytest.raises(GitHubPolicyError, match=error):
        _validate_fixture(tmp_path, workflow)


@pytest.mark.parametrize(
    ("job_fragment", "error"),
    [
        ("    permissions: write-all\n", "read-only or empty"),
        ("    environment: production\n", "cannot target a deployment Environment"),
        ("    continue-on-error: ${{ true }}\n", "cannot continue on error"),
    ],
)
def test_required_gate_rejects_unsafe_transitive_dependency(
    tmp_path: Path,
    job_fragment: str,
    error: str,
) -> None:
    workflow = _valid_workflow().replace(
        "  upstream:\n",
        "  root:\n"
        "    name: Root dependency\n"
        "    runs-on: ubuntu-24.04\n"
        f"{job_fragment}"
        "    steps:\n"
        "      - run: exit 0\n"
        "  upstream:\n"
        "    needs: root\n",
    )

    with pytest.raises(GitHubPolicyError, match=error):
        _validate_fixture(tmp_path, workflow)


def test_privileged_job_outside_required_dependency_closure_remains_valid(
    tmp_path: Path,
) -> None:
    workflow = _valid_workflow() + """\
  publish:
    name: Publish after merge
    if: github.event_name == 'push'
    permissions:
      contents: read
      id-token: write
    environment: production
    runs-on: ubuntu-24.04
    steps:
      - run: exit 0
"""

    assert _validate_fixture(tmp_path, workflow)["_derived"]["target_contexts"] == [
        "Stable gate"
    ]


def test_dynamic_required_context_is_rejected_by_schema(tmp_path: Path) -> None:
    policy_path, schema_path, workflow_dir = _write_fixture(tmp_path, _valid_workflow())
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["required_status_checks"]["checks"][0]["context"] = (
        "Validate ${{ matrix.service }}"
    )
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(GitHubPolicyError, match="schema validation failed"):
        validate_policy(
            repo_root=tmp_path,
            policy_path=policy_path,
            schema_path=schema_path,
            workflows_dir=workflow_dir,
        )


@pytest.mark.parametrize(
    "context",
    [
        "gate\nspoof",
        "gate\tspoof",
        "gate\x7fspoof",
        "gate\u0085spoof",
        " gate",
        "gate ",
        "gáte",
    ],
)
def test_noncanonical_required_context_is_rejected_by_schema(
    context: str,
    tmp_path: Path,
) -> None:
    policy_path, schema_path, workflow_dir = _write_fixture(tmp_path, _valid_workflow())
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["required_status_checks"]["checks"][0]["context"] = context
    policy["migration"]["added_contexts"] = [context]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(GitHubPolicyError, match="schema validation failed"):
        validate_policy(
            repo_root=tmp_path,
            policy_path=policy_path,
            schema_path=schema_path,
            workflows_dir=workflow_dir,
        )
