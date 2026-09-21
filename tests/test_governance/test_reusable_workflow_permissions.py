"""Prevent Actions startup failures without granting credentials to dry runs."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ".github/workflows/express-production-release.yml"
OFFLINE = ".github/workflows/_terraform-layer-offline.yml"
LIVE = ".github/workflows/_terraform-layer.yml"
REPOSITORY = "synthetic-owner/scanalyze-deployment-platform"


def _workflow(path: str) -> dict:
    return yaml.load((REPO_ROOT / path).read_text(), Loader=yaml.BaseLoader)


def _permission_errors(caller: dict) -> list[str]:
    """Model static reusable permission ceilings, including skipped jobs.

    GitHub validates every nested job before evaluating job conditions. A job's
    explicit permissions replace workflow defaults; omitted scopes become none.
    """
    errors = []
    levels = {"none": 0, "read": 1, "write": 2}

    def visit(job: dict, default_permissions: dict, stack: tuple[str, ...]) -> None:
        target = job.get("uses", "")
        if not target.startswith("./.github/workflows/"):
            return
        path = target.removeprefix("./")
        assert path not in stack, "Reusable workflow cycle"
        budget = job.get("permissions", default_permissions)
        nested = _workflow(path)
        for name, child in nested["jobs"].items():
            requested = child.get("permissions", nested.get("permissions", {}))
            for scope, level in requested.items():
                if levels[level] > levels[budget.get(scope, "none")]:
                    errors.append(f"{path}:{name}:{scope}:{level}")
            visit(child, nested.get("permissions", {}), (*stack, path))

    for job in caller["jobs"].values():
        visit(job, caller.get("permissions", {}), (PRODUCTION,))
    return errors


def _step(name: str) -> dict:
    return next(
        step
        for job in _workflow(OFFLINE)["jobs"].values()
        for step in job.get("steps", [])
        if step.get("name") == name
    )


def _run_gate(**overrides: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "EVENT_NAME": "workflow_dispatch",
        "DRY_RUN": "true",
        "ALLOW_LIVE": "false",
        "DEPLOYMENT_ID": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "RELEASE_DIGEST": "sha256:" + "a" * 64,
        "AWS_REGION_INPUT": "us-east-1",
        "TARGET_LAYER": "network",
        "LOGICAL_ENVIRONMENT": "production",
        "CALLER_REPOSITORY": REPOSITORY,
        "WORKFLOW_REF": f"{REPOSITORY}/{PRODUCTION}@refs/heads/main",
        "REF_NAME": "refs/heads/main",
    }
    env.update(overrides)
    return subprocess.run(
        ["bash", "-c", _step("Reject unauthorized modes before credentials")["run"]],
        env=env, text=True, capture_output=True, check=False,
    )


def test_production_reusable_graph_fits_static_permission_ceilings() -> None:
    assert _permission_errors(_workflow(PRODUCTION)) == []


def test_previous_offline_to_live_edge_reproduces_startup_failure() -> None:
    caller = copy.deepcopy(_workflow(PRODUCTION))
    caller["jobs"]["account-ready-gate"]["uses"] = f"./{LIVE}"
    assert _permission_errors(caller) == [
        f"{LIVE}:live_saved_plan:actions:read",
        f"{LIVE}:live_saved_plan:id-token:write",
    ]


def test_offline_graph_has_no_credential_or_live_execution_capability() -> None:
    caller = _workflow(PRODUCTION)
    offline = _workflow(OFFLINE)
    assert set(offline["on"]) == {"workflow_call"}
    assert set(offline["jobs"]) == {"mode_boundary", "offline_validation"}
    assert offline["permissions"] == {"contents": "read"}
    assert offline["jobs"]["mode_boundary"]["permissions"] == {}
    validation = offline["jobs"]["offline_validation"]
    assert validation["permissions"] == {"contents": "read"}
    assert validation["needs"] == "mode_boundary"
    assert validation["if"] == "${{ inputs.dry_run && !inputs.allow_live }}"
    assert set(offline["on"]["workflow_call"]["inputs"]) == {
        "deployment_id", "logical_environment", "layer", "release_digest",
        "request_path", "aws_region", "dry_run", "allow_live",
    }
    for job in offline["jobs"].values():
        assert not {"uses", "environment", "secrets"} & job.keys()
        for step in job["steps"]:
            assert "configure-aws-credentials" not in step.get("uses", "")
    assert "secrets." not in json.dumps(offline)
    assert "id-token" not in json.dumps(offline)

    offline_callers = {
        name for name, job in caller["jobs"].items()
        if job.get("uses") == f"./{OFFLINE}"
    }
    assert offline_callers == {
        "account-ready-gate", "global", "network", "platform", "data-foundation",
        "cicd", "identity-control-plane", "services", "edge-identity", "edge", "addons",
    }
    for name in offline_callers:
        job = caller["jobs"][name]
        assert job["permissions"] == {"contents": "read"}
        assert job["if"] == "${{ inputs.dry_run && !inputs.allow_live }}"
        assert set(job["with"]) == set(offline["on"]["workflow_call"]["inputs"])
        assert "secrets" not in job
    assert caller["jobs"]["live-layer"]["uses"] == f"./{LIVE}"


@pytest.mark.parametrize("environment", ["production", "sandbox", "dev", "staging"])
def test_offline_admission_accepts_only_matching_dispatch_lane(environment: str) -> None:
    workflow = PRODUCTION if environment == "production" else ".github/workflows/nonprod-release.yml"
    result = _run_gate(
        LOGICAL_ENVIRONMENT=environment,
        WORKFLOW_REF=f"{REPOSITORY}/{workflow}@refs/heads/main",
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("override", [
    {"DRY_RUN": "false", "ALLOW_LIVE": "true"},
    {"DRY_RUN": "true", "ALLOW_LIVE": "true"},
    {"DRY_RUN": "false", "ALLOW_LIVE": "false"},
    {"DRY_RUN": "invalid"}, {"ALLOW_LIVE": "invalid"},
    {"EVENT_NAME": "push"}, {"DEPLOYMENT_ID": "invalid"},
    {"RELEASE_DIGEST": "invalid"}, {"AWS_REGION_INPUT": "invalid"},
    {"TARGET_LAYER": "../../outside"}, {"LOGICAL_ENVIRONMENT": "unknown"},
    {"WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/nonprod-release.yml@refs/heads/main"},
    {"CALLER_REPOSITORY": "foreign-owner/foreign-repository"},
])
def test_offline_admission_rejects_live_flags_and_wrong_bindings(override: dict) -> None:
    assert _run_gate(**override).returncode != 0


@pytest.mark.parametrize("name", [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
])
def test_offline_refuses_ambient_credential_selectors(name: str) -> None:
    # Only a synthetic sentinel is supplied; the real shell step rejects it.
    result = subprocess.run(
        ["bash", "-c", _step("Refuse ambient AWS credentials in dry-run")["run"]],
        env={"PATH": os.environ["PATH"], name: "synthetic-do-not-use"},
        text=True, capture_output=True, check=False,
    )
    assert result.returncode != 0
    assert "synthetic-do-not-use" not in result.stdout + result.stderr


def test_offline_terraform_invocation_disables_backend_and_never_plans(tmp_path: Path) -> None:
    shim = tmp_path / "terraform"
    calls = tmp_path / "calls.jsonl"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "with open(os.environ['TERRAFORM_CALLS'], 'a') as output:\n"
        "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    shim.chmod(0o700)
    step = _step("Initialize and validate Terraform without backend")
    assert step["env"]["AWS_EC2_METADATA_DISABLED"] == "true"
    result = subprocess.run(
        ["bash", "-c", step["run"]],
        env={
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "TARGET_LAYER": "network", "TERRAFORM_CALLS": str(calls),
        },
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert [json.loads(line) for line in calls.read_text().splitlines()] == [
        ["-chdir=roots/network", "init", "-backend=false", "-input=false", "-no-color"],
        ["-chdir=roots/network", "validate", "-no-color"],
    ]
