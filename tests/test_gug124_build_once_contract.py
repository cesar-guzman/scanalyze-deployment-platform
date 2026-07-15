"""Repository integration contracts for GUG-124 build-once delivery."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_pr_validation_runs_supply_chain_gate_without_cloud_permissions() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/pr-validation.yml").read_text(encoding="utf-8")
    )

    assert workflow["permissions"] == {"contents": "read"}
    assert "id-token" not in workflow["permissions"]
    commands = [
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    ]
    assert "make supply-chain-check" in commands


def test_legacy_publish_job_remains_terminal_no_go() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/microservices-build.yml").read_text(
            encoding="utf-8"
        )
    )
    publish = workflow["jobs"]["publish"]

    assert publish["permissions"] == {}
    rendered = json.dumps(publish)
    assert "Publication NO-GO" in rendered
    assert "aws-actions/configure-aws-credentials" not in rendered
    assert "exit 1" in rendered


def test_release_planning_inventory_cannot_authorize_promotion(tmp_path) -> None:
    script = ROOT / "scripts/supply-chain/release-graph.py"
    dry_run = subprocess.run(
        [str(script), "--dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )
    live = subprocess.run(
        [str(script), "--no-dry-run"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert dry_run.returncode == 0
    inventory = json.loads(dry_run.stdout)
    assert inventory["eligible_for_promotion"] is False
    assert inventory["production_status"] == "NO-GO"
    assert live.returncode != 0
    assert "cannot authorize" in live.stderr
    assert not list(tmp_path.iterdir())


def test_services_terraform_rejects_mutable_container_references() -> None:
    variables = (ROOT / "modules/services/variables.tf").read_text(encoding="utf-8")
    task_definitions = (ROOT / "modules/services/ecs_services.tf").read_text(
        encoding="utf-8"
    )

    assert "@sha256:[0-9a-f]{64}$" in variables
    assert "image     = each.value.image" in task_definitions
    active_lines = "\n".join(
        line for line in task_definitions.splitlines() if not line.lstrip().startswith("#")
    )
    assert 'image     = "' not in active_lines
    assert "ignore_changes" not in active_lines


def test_static_projection_matches_verified_generator() -> None:
    command = [
        sys.executable,
        str(ROOT / "tooling/release_policy_gate.py"),
        "--manifest",
        str(ROOT / "fixtures/valid/release-v2-complete.synthetic.json"),
        "--attestation",
        str(ROOT / "fixtures/valid/release-attestation-v2-complete.synthetic.json"),
        "--policy",
        str(ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.json"),
        "--expected-policy-digest",
        (
            ROOT / "fixtures/valid/release-trust-policy-v1-synthetic.sha256"
        ).read_text(encoding="utf-8").strip(),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    decision = json.loads(completed.stdout)
    assert decision["allowed"] is True
    assert decision["code"] == "RELEASE_POLICY_PASSED"


def test_supply_chain_fixtures_are_explicitly_synthetic() -> None:
    names = {
        path.name
        for path in (ROOT / "fixtures/valid").glob("release-*-synthetic.json")
    }
    assert names == {
        "release-deployment-projection-v1-synthetic.json",
        "release-trust-policy-v1-synthetic.json",
    }
    assert (ROOT / "fixtures/valid/release-v2-complete.synthetic.json").exists()
    assert (
        ROOT / "fixtures/valid/release-attestation-v2-complete.synthetic.json"
    ).exists()
