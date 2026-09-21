"""Execute real workflow steps without credentials, providers or cloud effects."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ".github/workflows/express-production-release.yml"
OFFLINE = ".github/workflows/_terraform-layer-offline.yml"
REPOSITORY = "synthetic-owner/scanalyze-deployment-platform"
DEPLOYMENT = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def workflow(path):
    return yaml.load((ROOT / path).read_text(), Loader=yaml.BaseLoader)


def step(path, name):
    return next(s for job in workflow(path)["jobs"].values()
                for s in job.get("steps", []) if s.get("name") == name)


def environment(**overrides):
    values = {
        "PATH": os.environ["PATH"],
        "ALLOW_LIVE": "false", "DRY_RUN": "true",
        "CALLER_REPOSITORY": REPOSITORY,
        "WORKFLOW_REF": f"{REPOSITORY}/{PRODUCTION}@refs/heads/main",
        "LOGICAL_ENVIRONMENT": "production", "DEPLOYMENT_ID": DEPLOYMENT,
        "EVENT_NAME": "workflow_dispatch", "REF_NAME": "refs/heads/main",
        "LIVE_OPERATION": "none", "LIVE_INPUT_CLAIM_DIGEST": "",
        "PLAN_RECORD_DIGEST": "", "REVIEWER_PACKET_DIGEST": "",
        "RELEASE_DIGEST": "sha256:" + "d" * 64, "AWS_REGION_INPUT": "us-east-1",
        "TARGET_LAYER": "network", "REQUEST_PATH": "request.json",
    }
    values.update(overrides)
    return values


def gate(**overrides):
    return subprocess.run(
        ["bash", "-c", step(PRODUCTION, "Validate dispatch execution mode")["run"]],
        env=environment(**overrides), text=True, capture_output=True, timeout=10,
    )


def test_production_dry_run_is_admitted_without_live_authority():
    assert gate().returncode == 0


@pytest.mark.parametrize("override", [
    {"ALLOW_LIVE": "true", "DRY_RUN": "false", "LIVE_OPERATION": "plan"},
    {"ALLOW_LIVE": "true", "DRY_RUN": "false", "LIVE_OPERATION": "apply"},
    {"ALLOW_LIVE": "true"}, {"DRY_RUN": "false"},
    {"LOGICAL_ENVIRONMENT": "dev"}, {"LOGICAL_ENVIRONMENT": "staging"},
    {"EVENT_NAME": "push"}, {"CALLER_REPOSITORY": "foreign-owner/repository"},
    {"WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/nonprod-release.yml@refs/heads/main"},
    {"LIVE_OPERATION": "plan"}, {"LIVE_INPUT_CLAIM_DIGEST": "sha256:" + "a" * 64},
    {"PLAN_RECORD_DIGEST": "sha256:" + "a" * 64},
    {"REVIEWER_PACKET_DIGEST": "sha256:" + "a" * 64},
])
def test_dry_run_cannot_enable_live_or_cross_lanes(override):
    assert gate(**override).returncode != 0


@pytest.fixture
def request_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "schemas").mkdir()
    for name in ("deployment-request.schema.json", "deployment-request-production.v2.schema.json"):
        shutil.copyfile(ROOT / "schemas" / name, repo / "schemas" / name)
    request = json.loads((ROOT / "examples/gitops/deployment-request.synthetic.json").read_text())
    request.update(schema_version="2", environment="production",
                   deployment_id=DEPLOYMENT, release_digest="sha256:" + "d" * 64)
    request["non_sensitive_selectors"]["region"] = "us-east-1"
    (repo / "request.json").write_text(json.dumps(request))
    binaries = tmp_path / "bin"
    binaries.mkdir()
    (binaries / "python").symlink_to(sys.executable)
    env = environment(PATH=f"{binaries}:{os.environ['PATH']}")
    subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "add", "request.json"], env=env,
                   check=True, capture_output=True)
    return repo, env, request


def validate_request(path, request_repo, *, tracked=True):
    repo, env, request = request_repo
    (repo / "request.json").write_text(json.dumps(request))
    if not tracked:
        subprocess.run(["git", "rm", "--cached", "request.json"], cwd=repo,
                       env=env, check=True, capture_output=True)
    return run_request_step(path, repo, env)


def run_request_step(path, repo, env):
    name = ("Validate request and input binding" if path == PRODUCTION
            else "Validate Git-safe deployment request")
    return subprocess.run(["bash", "-c", step(path, name)["run"]], cwd=repo,
                          env=env, text=True, capture_output=True, timeout=10)


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
def test_actual_step_validates_tracked_production_v2_request(path, request_repo):
    result = validate_request(path, request_repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
@pytest.mark.parametrize("field,value", [
    ("schema_version", "1"), ("environment", "dev"),
    ("deployment_id", "dep_01ARZ3NDEKTSV4RRFFQ69G5FAX"),
    ("release_digest", "sha256:" + "c" * 64),
    ("full_deployment", False), ("account_id", "111111111111"),
    ("approval", {"status": "approved"}),
    ("non_sensitive_selectors", {"region": "us-west-2"}),
])
def test_actual_step_rejects_invalid_or_unbound_request(path, request_repo, field, value):
    request_repo[2][field] = value
    assert validate_request(path, request_repo).returncode != 0


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
def test_actual_step_refuses_untracked_requests(path, request_repo):
    assert validate_request(path, request_repo, tracked=False).returncode != 0


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
def test_tracked_symlink_cannot_substitute_untracked_request_bytes(path, request_repo):
    repo, _, request = request_repo
    (repo / "untracked.json").write_text(json.dumps(request))
    (repo / "request.json").unlink()
    (repo / "request.json").symlink_to("untracked.json")
    subprocess.run(["git", "add", "request.json"], cwd=repo, env=request_repo[1],
                   check=True, capture_output=True)
    assert run_request_step(path, repo, request_repo[1]).returncode != 0


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
def test_schema_rejection_does_not_echo_request_values(path, request_repo):
    marker = "SYNTHETIC-REJECTED-VALUE"
    request_repo[2]["requested_by"] = marker
    result = validate_request(path, request_repo)
    assert result.returncode != 0
    assert marker not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("path", [PRODUCTION, OFFLINE])
@pytest.mark.parametrize("extension", ["json", "yaml"])
def test_parse_errors_do_not_echo_request_values(path, request_repo, extension):
    repo, env, _ = request_repo
    marker = "SYNTHETIC-PARSE-ERROR"
    name = "malformed." + extension
    (repo / name).write_text('{"' + marker + '":' if extension == "json"
                             else marker + ": [\n")
    subprocess.run(["git", "add", name], cwd=repo, env=env, check=True, capture_output=True)
    result = run_request_step(path, repo, {**env, "REQUEST_PATH": name})
    assert result.returncode != 0
    assert marker not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def test_offline_evidence_does_not_claim_publication_or_deployment():
    caller = workflow(PRODUCTION)
    evidence = step(PRODUCTION, "Generate sanitized evidence")["run"]
    assert '"production_readiness": "NO-GO"' in evidence
    assert '"terraform_apply": False' in evidence
    assert caller["jobs"]["live-layer"]["uses"] == "./.github/workflows/_terraform-layer.yml"
    assert caller["jobs"]["live-layer"]["if"] == "${{ inputs.allow_live && !inputs.dry_run }}"


def test_actual_evidence_binds_production_lane_without_live_claims(request_repo, tmp_path):
    repo, env, _ = request_repo
    summary = tmp_path / "summary.md"
    source_sha = "c" * 40
    result = subprocess.run(
        ["bash", "-c", step(PRODUCTION, "Generate sanitized evidence")["run"]],
        cwd=repo, env={**env, "RUNNER_TEMP": str(tmp_path), "GITHUB_SHA": source_sha,
                      "GITHUB_STEP_SUMMARY": str(summary)},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    artifact = tmp_path / "express-production-dry-run-evidence.json"
    evidence = json.loads(artifact.read_text())
    assert evidence["workflow"] == "express-production-release"
    assert evidence["environment"] == "production"
    assert evidence["commit"] == source_sha
    assert evidence["release_digest"] == env["RELEASE_DIGEST"]
    assert evidence["production_readiness"] == "NO-GO"
    assert evidence["live_validation"] == "PENDING"
    for field in ("aws_api_calls", "terraform_backend", "terraform_plan",
                  "terraform_apply", "artifact_publication"):
        assert evidence[field] is False
    assert artifact.stat().st_mode & 0o777 == 0o600
    upload = step(PRODUCTION, "Upload sanitized evidence")["with"]
    assert upload["name"] == "express-production-dry-run-evidence"
    assert upload["path"] == "${{ runner.temp }}/" + artifact.name
    assert "Production offline orchestration result" in summary.read_text()
