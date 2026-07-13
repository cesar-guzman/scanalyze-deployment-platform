"""Executable contracts for stable GitHub Actions governance gates."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
MICROSERVICES_WORKFLOW = WORKFLOW_DIR / "microservices-build.yml"
REPRO_WORKFLOW = WORKFLOW_DIR / "repro-check.yml"
STABLE_GATE_NAME = "Microservices validation gate"
SERVICE_IDS = (
    "ingest-api",
    "ocr-worker",
    "postprocess-worker",
    "classifier-worker",
    "bank-worker",
    "personal-worker",
    "gov-worker",
)


def _load_workflow(path: Path) -> dict[str, Any]:
    document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(document, dict)
    return document


def _gate() -> dict[str, Any]:
    return _load_workflow(MICROSERVICES_WORKFLOW)["jobs"]["validation_gate"]


def _run_dispatch_selection(
    tmp_path: Path, dispatch_service: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    workflow = _load_workflow(MICROSERVICES_WORKFLOW)
    selection_step = next(
        step
        for step in workflow["jobs"]["changes"]["steps"]
        if step["name"] == "Resolve service matrix"
    )
    output_path = tmp_path / "github-output.txt"
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_OUTPUT": str(output_path),
        "EVENT_NAME": "workflow_dispatch",
        "DISPATCH_SERVICE": dispatch_service,
        "PR_BASE_SHA": "",
        "PR_HEAD_SHA": "",
        "PUSH_BASE_SHA": "",
        "PUSH_HEAD_SHA": "",
    }
    result = subprocess.run(
        ["bash", "-c", selection_step["run"]],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    outputs = {}
    if output_path.exists():
        outputs = dict(
            line.split("=", 1)
            for line in output_path.read_text(encoding="utf-8").splitlines()
        )
    return result, outputs


def _run_gate(
    tmp_path: Path,
    *,
    selection_result: str = "success",
    services_json: str,
    has_changes: str,
    tooling_result: str = "success",
    validation_result: str,
) -> subprocess.CompletedProcess[str]:
    gate_script = _gate()["steps"][0]["run"]
    summary_path = tmp_path / "step-summary.md"
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_STEP_SUMMARY": str(summary_path),
        "SELECTION_RESULT": selection_result,
        "SERVICES_JSON": services_json,
        "HAS_CHANGES": has_changes,
        "TOOLING_RESULT": tooling_result,
        "VALIDATION_RESULT": validation_result,
    }
    return subprocess.run(
        ["bash", "-c", gate_script],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_microservices_gate_has_a_stable_fail_closed_contract() -> None:
    workflow = _load_workflow(MICROSERVICES_WORKFLOW)
    gate = workflow["jobs"]["validation_gate"]

    assert workflow["on"]["pull_request"] == {"branches": ["main"]}
    assert gate["name"] == STABLE_GATE_NAME
    assert gate["needs"] == ["changes", "tooling", "validate"]
    assert gate["if"] == "${{ always() }}"
    assert gate["permissions"] == {}
    assert all("uses" not in step for step in gate["steps"])
    assert gate["steps"][0]["env"] == {
        "SELECTION_RESULT": "${{ needs.changes.result }}",
        "SERVICES_JSON": "${{ needs.changes.outputs.services }}",
        "HAS_CHANGES": "${{ needs.changes.outputs.has_changes }}",
        "TOOLING_RESULT": "${{ needs.tooling.result }}",
        "VALIDATION_RESULT": "${{ needs.validate.result }}",
    }

    validate = workflow["jobs"]["validate"]
    assert validate["strategy"]["matrix"]["service"] == (
        "${{ fromJSON(needs.changes.outputs.services) }}"
    )
    isolated_test_step = next(
        step
        for step in validate["steps"]
        if step.get("name") == "Compile and test service"
    )
    assert "'jsonschema==4.26.0'" in isolated_test_step["run"]

    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["changes", "validation_gate"]
    assert "needs.validation_gate.result == 'success'" in publish["if"]
    assert publish["strategy"]["matrix"]["service"] == (
        "${{ fromJSON(needs.changes.outputs.publish_services) }}"
    )


@pytest.mark.parametrize(
    ("dispatch_service", "expected_publish_services"),
    [
        ("all", list(SERVICE_IDS)),
        ("ingest-api", ["ingest-api"]),
    ],
)
def test_workflow_dispatch_validates_all_services_and_publishes_only_selection(
    tmp_path: Path,
    dispatch_service: str,
    expected_publish_services: list[str],
) -> None:
    result, outputs = _run_dispatch_selection(tmp_path, dispatch_service)

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(outputs["services"]) == list(SERVICE_IDS)
    assert json.loads(outputs["publish_services"]) == expected_publish_services
    assert outputs["has_changes"] == "true"
    assert outputs["publishable"] == "false"


def test_diagnostic_matrix_names_cannot_match_required_or_legacy_contexts() -> None:
    workflow = _load_workflow(MICROSERVICES_WORKFLOW)
    matrix_name = workflow["jobs"]["validate"]["name"]
    assert matrix_name == "Service matrix evidence / ${{ matrix.service }}"

    policy = json.loads(
        (REPO_ROOT / "governance" / "github-policy.json").read_text(encoding="utf-8")
    )
    protected_contexts = {
        check["context"]
        for check in policy["required_status_checks"]["checks"]
    } | set(policy["migration"]["retired_contexts"])
    diagnostic_contexts = {
        matrix_name.replace("${{ matrix.service }}", service)
        for service in SERVICE_IDS
    }

    assert diagnostic_contexts.isdisjoint(protected_contexts)


def test_stable_gate_job_name_is_unique_across_workflows() -> None:
    definitions: list[tuple[Path, str]] = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        jobs = _load_workflow(path).get("jobs", {})
        for job_id, job in jobs.items():
            if isinstance(job, dict) and job.get("name") == STABLE_GATE_NAME:
                definitions.append((path, job_id))

    assert definitions == [(MICROSERVICES_WORKFLOW, "validation_gate")]


@pytest.mark.parametrize(
    ("services_json", "has_changes", "validation_result"),
    [
        ("[]", "false", "skipped"),
        ('["ingest-api"]', "true", "success"),
    ],
)
def test_validation_gate_accepts_only_valid_success_states(
    tmp_path: Path,
    services_json: str,
    has_changes: str,
    validation_result: str,
) -> None:
    result = _run_gate(
        tmp_path,
        services_json=services_json,
        has_changes=has_changes,
        validation_result=validation_result,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    summary = (tmp_path / "step-summary.md").read_text(encoding="utf-8")
    assert STABLE_GATE_NAME in summary
    assert f"`{validation_result}`" in summary


@pytest.mark.parametrize(
    (
        "selection_result",
        "services_json",
        "has_changes",
        "tooling_result",
        "validation_result",
    ),
    [
        ("failure", "[]", "false", "success", "skipped"),
        ("cancelled", "[]", "false", "success", "skipped"),
        ("skipped", "[]", "false", "success", "skipped"),
        ("success", "[]", "false", "failure", "skipped"),
        ("success", "[]", "false", "cancelled", "skipped"),
        ("success", "[]", "false", "skipped", "skipped"),
        ("success", "[]", "", "success", "skipped"),
        ("success", "[]", "invalid", "success", "skipped"),
        ("success", '["ingest-api"]', "false", "success", "skipped"),
        ("success", "[]", "false", "success", "success"),
        ("success", "[]", "false", "success", "failure"),
        ("success", "[]", "false", "success", "cancelled"),
        ("success", "[]", "true", "success", "success"),
        ("success", '["ingest-api"]', "true", "success", "failure"),
        ("success", '["ingest-api"]', "true", "success", "cancelled"),
        ("success", '["ingest-api"]', "true", "success", "skipped"),
    ],
)
def test_validation_gate_rejects_failures_cancellation_and_inconsistent_states(
    tmp_path: Path,
    selection_result: str,
    services_json: str,
    has_changes: str,
    tooling_result: str,
    validation_result: str,
) -> None:
    result = _run_gate(
        tmp_path,
        selection_result=selection_result,
        services_json=services_json,
        has_changes=has_changes,
        tooling_result=tooling_result,
        validation_result=validation_result,
    )

    assert result.returncode != 0
    assert "::error::" in result.stdout


def test_reproducibility_workflow_has_one_run_per_event_and_pinned_toolchain() -> None:
    workflow = _load_workflow(REPRO_WORKFLOW)
    triggers = workflow["on"]

    assert workflow["name"] == "Reproducibility check"
    assert set(triggers) == {"pull_request", "push", "schedule", "workflow_dispatch"}
    assert triggers["pull_request"] == {"branches": ["main"]}
    assert triggers["push"] == {"branches": ["main"]}
    assert "feat/**" not in REPRO_WORKFLOW.read_text(encoding="utf-8")

    terraform_step = next(
        step
        for step in workflow["jobs"]["clean-clone-check"]["steps"]
        if step["name"] == "Set up Terraform"
    )
    assert terraform_step["with"]["terraform_version"] == "1.14.6"
    assert (REPO_ROOT / ".terraform-version").read_text(encoding="utf-8").strip() == "1.14.6"
    assert "| Terraform | 1.14.6 " in (
        REPO_ROOT / "REPRODUCIBILITY.md"
    ).read_text(encoding="utf-8")
