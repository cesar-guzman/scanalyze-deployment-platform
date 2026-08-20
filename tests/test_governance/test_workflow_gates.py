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
SOURCE_SHA_EXPRESSION = "${{ github.event.pull_request.head.sha || github.sha }}"
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


def _validate_step(name: str) -> dict[str, Any]:
    workflow = _load_workflow(MICROSERVICES_WORKFLOW)
    return next(
        step
        for step in workflow["jobs"]["validate"]["steps"]
        if step.get("name") == name
    )


def _run_validate_step(
    name: str,
    *,
    service: str,
    ci_base_image: str,
) -> subprocess.CompletedProcess[str]:
    step = _validate_step(name)
    env = {
        "PATH": os.environ["PATH"],
        "CI_BASE_IMAGE": ci_base_image,
        "GITHUB_SHA": "b" * 40,
        "SCANALYZE_SOURCE_REVISION": "a" * 40,
        "SERVICE": service,
    }
    return subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _run_compile_and_test_step(
    tmp_path: Path,
    *,
    service: str,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    step = _validate_step("Compile and test service")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_log = tmp_path / "python.log"
    fake_python = bin_dir / "python"
    fake_python.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s' \"${1:-}\" >> \"$PYTHON_LOG\"\n"
        "shift || true\n"
        "for argument in \"$@\"; do\n"
        "  printf '\\t%s' \"$argument\" >> \"$PYTHON_LOG\"\n"
        "done\n"
        "printf '\\n' >> \"$PYTHON_LOG\"\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "PYTHON_LOG": str(python_log),
        "SERVICE": service,
    }
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    calls = (
        python_log.read_text(encoding="utf-8").splitlines()
        if python_log.exists()
        else []
    )
    return result, calls


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
    setup_python = next(
        step for step in validate["steps"] if step.get("name") == "Set up Python"
    )
    cache_paths = setup_python["with"]["cache-dependency-path"].splitlines()
    assert cache_paths == [
        "backend/workers/scanalyze-${{ matrix.service }}/requirements.txt",
        "backend/workers/scanalyze-ocr-worker/requirements.lock",
        "backend/workers/scanalyze-classifier-worker/requirements.lock",
    ]
    isolated_test_step = next(
        step
        for step in validate["steps"]
        if step.get("name") == "Compile and test service"
    )
    isolated_test_script = isolated_test_step["run"]
    assert "ocr-worker|classifier-worker)" in isolated_test_script
    assert (
        'python -m pip install --require-hashes -r "$service_dir/requirements.lock"'
        in isolated_test_script
    )
    assert (
        'python -m pip install -r "$service_dir/requirements.txt"'
        in isolated_test_script
    )
    assert "python -m pip install \\\n  'jsonschema==4.26.0' \\\n  'pytest==9.1.1'" in isolated_test_script

    checkout = next(step for step in validate["steps"] if step["name"] == "Check out source")
    assert checkout["with"]["ref"] == SOURCE_SHA_EXPRESSION

    materialize = _validate_step("Materialize approved hermetic base image")
    assert materialize["if"] == (
        "matrix.service == 'ocr-worker' || matrix.service == 'classifier-worker'"
    )
    assert materialize["env"]["CI_BASE_IMAGE"] == "${{ vars.CI_BASE_IMAGE }}"
    assert materialize["env"]["SERVICE"] == "${{ matrix.service }}"
    assert "CI_BASE_IMAGE must be an immutable sha256 reference" in materialize["run"]
    assert 'docker pull --platform linux/amd64 "$CI_BASE_IMAGE"' in materialize["run"]
    assert 'docker image inspect "$CI_BASE_IMAGE"' in materialize["run"]

    prepare = _validate_step("Prepare OCR hermetic wheelhouse")
    assert prepare["if"] == "matrix.service == 'ocr-worker'"
    assert prepare["env"]["CI_BASE_IMAGE"] == "${{ vars.CI_BASE_IMAGE }}"
    assert "CI_BASE_IMAGE is required when ocr-worker is selected" in prepare["run"]
    assert "scripts/microservices/prepare-ocr-wheelhouse.sh" in prepare["run"]

    classifier_prepare = _validate_step("Prepare classifier hermetic wheelhouse")
    assert classifier_prepare["if"] == "matrix.service == 'classifier-worker'"
    assert classifier_prepare["env"]["CI_BASE_IMAGE"] == "${{ vars.CI_BASE_IMAGE }}"
    assert "CI_BASE_IMAGE is required when classifier-worker is selected" in (
        classifier_prepare["run"]
    )
    assert "scripts/microservices/prepare-classifier-wheelhouse.sh" in (
        classifier_prepare["run"]
    )

    build = _validate_step("Build without publishing")
    assert "GITHUB_SHA" not in build["env"]
    assert build["env"]["SCANALYZE_SOURCE_REVISION"] == SOURCE_SHA_EXPRESSION
    assert build["env"]["GITHUB_REPOSITORY"] == "${{ github.repository }}"
    assert build["env"]["GITHUB_SERVER_URL"] == "${{ github.server_url }}"
    assert '--tag "sha-${SCANALYZE_SOURCE_REVISION:0:12}"' in build["run"]
    assert 'build_args+=(--hermetic)' in build["run"]
    assert 'scripts/microservices/build-push.sh "${build_args[@]}"' in build["run"]
    assert 'if [[ "$SERVICE" == "classifier-worker" ]]; then' in build["run"]
    assert "--pull=false" in build["run"]
    assert "--network=none" in build["run"]
    assert 'org.opencontainers.image.source=${source_url}' in build["run"]
    assert (
        'org.opencontainers.image.revision=${SCANALYZE_SOURCE_REVISION}'
        in build["run"]
    )
    assert 'docker image inspect "$CI_BASE_IMAGE"' in build["run"]

    verify = _validate_step("Verify OCR container evidence")
    assert verify["if"] == "matrix.service == 'ocr-worker'"
    assert "GITHUB_SHA" not in verify["env"]
    assert verify["env"]["SCANALYZE_SOURCE_REVISION"] == SOURCE_SHA_EXPRESSION
    assert (
        'image="scanalyze-ci/ocr-worker:sha-${SCANALYZE_SOURCE_REVISION:0:12}"'
        in verify["run"]
    )
    assert '--revision "$SCANALYZE_SOURCE_REVISION"' in verify["run"]

    classifier_verify = _validate_step("Verify classifier container evidence")
    assert classifier_verify["if"] == "matrix.service == 'classifier-worker'"
    assert "GITHUB_SHA" not in classifier_verify["env"]
    assert (
        classifier_verify["env"]["SCANALYZE_SOURCE_REVISION"]
        == SOURCE_SHA_EXPRESSION
    )
    assert (
        'image="scanalyze-ci/classifier-worker:sha-${SCANALYZE_SOURCE_REVISION:0:12}"'
        in classifier_verify["run"]
    )
    assert "scripts/microservices/verify-classifier-container.sh" in (
        classifier_verify["run"]
    )

    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["changes", "validation_gate"]
    assert "needs.validation_gate.result == 'success'" in publish["if"]
    assert publish["strategy"]["matrix"]["service"] == (
        "${{ fromJSON(needs.changes.outputs.publish_services) }}"
    )
    assert publish["permissions"] == {}
    assert "environment" not in publish
    assert len(publish["steps"]) == 1
    assert publish["steps"][0]["name"] == (
        "Deny legacy publishing until the authorized release engine exists"
    )
    assert "exit 1" in publish["steps"][0]["run"]


def test_ocr_compile_step_uses_hashed_lock_and_separate_test_dependencies(
    tmp_path: Path,
) -> None:
    result, calls = _run_compile_and_test_step(tmp_path, service="ocr-worker")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == [
        "-m\tcompileall\t-q\tbackend/workers/scanalyze-ocr-worker",
        (
            "-m\tpip\tinstall\t--require-hashes\t-r\t"
            "backend/workers/scanalyze-ocr-worker/requirements.lock"
        ),
        "-m\tpip\tinstall\tjsonschema==4.26.0\tpytest==9.1.1",
        "-m\tpytest\tbackend/workers/scanalyze-ocr-worker/tests\t-q",
    ]


def test_classifier_compile_step_uses_hashed_lock_and_separate_test_dependencies(
    tmp_path: Path,
) -> None:
    result, calls = _run_compile_and_test_step(tmp_path, service="classifier-worker")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == [
        "-m\tcompileall\t-q\tbackend/workers/scanalyze-classifier-worker",
        (
            "-m\tpip\tinstall\t--require-hashes\t-r\t"
            "backend/workers/scanalyze-classifier-worker/requirements.lock"
        ),
        "-m\tpip\tinstall\tjsonschema==4.26.0\tpytest==9.1.1",
        "-m\tpytest\tbackend/workers/scanalyze-classifier-worker/tests\t-q",
    ]


def test_non_ocr_compile_step_preserves_requirements_txt(
    tmp_path: Path,
) -> None:
    result, calls = _run_compile_and_test_step(tmp_path, service="ingest-api")

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == [
        "-m\tcompileall\t-q\tbackend/workers/scanalyze-ingest-api",
        (
            "-m\tpip\tinstall\t-r\t"
            "backend/workers/scanalyze-ingest-api/requirements.txt"
        ),
        "-m\tpip\tinstall\tjsonschema==4.26.0\tpytest==9.1.1",
        "-m\tpytest\tbackend/workers/scanalyze-ingest-api/tests\t-q",
    ]


def test_ocr_validation_fails_closed_without_ci_base_image() -> None:
    materialize = _run_validate_step(
        "Materialize approved hermetic base image",
        service="ocr-worker",
        ci_base_image="",
    )
    prepare = _run_validate_step(
        "Prepare OCR hermetic wheelhouse",
        service="ocr-worker",
        ci_base_image="",
    )
    build = _run_validate_step(
        "Build without publishing",
        service="ocr-worker",
        ci_base_image="",
    )

    assert materialize.returncode != 0
    assert prepare.returncode != 0
    assert build.returncode != 0
    assert "CI_BASE_IMAGE is required when ocr-worker is selected" in (
        materialize.stdout + materialize.stderr
    )
    assert "CI_BASE_IMAGE is required when ocr-worker is selected" in (
        prepare.stdout + prepare.stderr
    )
    assert "CI_BASE_IMAGE is required when ocr-worker is selected" in (
        build.stdout + build.stderr
    )


def test_classifier_validation_fails_closed_without_ci_base_image() -> None:
    materialize = _run_validate_step(
        "Materialize approved hermetic base image",
        service="classifier-worker",
        ci_base_image="",
    )
    prepare = _run_validate_step(
        "Prepare classifier hermetic wheelhouse",
        service="classifier-worker",
        ci_base_image="",
    )
    build = _run_validate_step(
        "Build without publishing",
        service="classifier-worker",
        ci_base_image="",
    )

    assert materialize.returncode != 0
    assert prepare.returncode != 0
    assert build.returncode != 0
    for result in (materialize, prepare, build):
        assert "CI_BASE_IMAGE is required when classifier-worker is selected" in (
            result.stdout + result.stderr
        )


def test_non_ocr_validation_preserves_no_base_image_skip() -> None:
    result = _run_validate_step(
        "Build without publishing",
        service="ingest-api",
        ci_base_image="",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Skipping Docker build" in result.stdout


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
    assert terraform_step["with"]["terraform_wrapper"] == "false"
    assert (REPO_ROOT / ".terraform-version").read_text(encoding="utf-8").strip() == "1.14.6"
    assert "| Terraform | 1.14.6 " in (
        REPO_ROOT / "REPRODUCIBILITY.md"
    ).read_text(encoding="utf-8")
