"""Focused offline CLI tests for the GUG-395 collision probe."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
from typing import Any

import pytest


ROOT = Path(__file__).parents[2]
SCRIPT = (
    ROOT
    / "scripts/deployment/platform-authority-gug395-preplan-collision-probe.py"
)


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("gug395_live_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_all_collision_probe_help_paths_need_no_sdk() -> None:
    for command in ("materialize-request", "probe", "validate-receipt"):
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SCRIPT), command, "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert command in result.stdout
        assert result.stderr == ""


def test_probe_emits_blocked_receipt_and_returns_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _module()
    receipt = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_preplan_collision_probe_receipt.v1"
        ),
        "status": "LIVE_READ_ONLY_PROBE_BLOCKED",
        "classification": "UNCERTAIN_RECONCILE_ONLY",
        "aws_calls": None,
        "network_calls": None,
        "modeled_cost_usd_upper": None,
        "production_status": "NO-GO",
    }
    monkeypatch.setattr(cli, "_probe", lambda args: receipt)

    exit_code = cli.main(
        [
            "probe",
            "--private-root",
            str(tmp_path),
            "--request-digest",
            "sha256:" + "1" * 64,
            "--source-commit-sha",
            "a" * 40,
            "--source-tree-sha",
            "b" * 40,
            "--now",
            "2026-08-28T01:10:00Z",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    assert json.loads(captured.out) == receipt


def test_probe_seals_provider_construction_failure_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tooling import platform_authority_gug376_live_provider as provider_module
    from tooling import platform_authority_gug395_preplan_collision_executor as executor_module
    from tooling import platform_authority_gug395_preplan_collision_probe as contract
    from tests.test_deployment import test_gug395_preplan_collision_probe as data

    cli = _module()
    capability = object()
    request = data._request()
    blocked = contract.CollisionProbeResult(
        private_evidence={"execution_status": contract.EXECUTION_BLOCKED},
        public_receipt={
            "status": "LIVE_READ_ONLY_PROBE_BLOCKED",
            "classification": contract.UNCERTAIN,
        },
    )
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        contract, "verify_collision_probe_source", lambda **kwargs: object()
    )
    monkeypatch.setattr(
        contract,
        "read_and_claim_collision_probe_request",
        lambda **kwargs: capability,
    )
    monkeypatch.setattr(
        contract,
        "approved_collision_probe_request",
        lambda supplied: request,
    )

    def fail_provider(**kwargs: Any) -> Any:
        raise provider_module.LiveProviderError("AWS_SDK_RUNTIME_ROOT_INVALID")

    monkeypatch.setattr(
        provider_module, "build_collision_probe_provider_factory", fail_provider
    )

    def persist_blocked(**kwargs: Any) -> contract.CollisionProbeResult:
        captured.update(kwargs)
        return blocked

    monkeypatch.setattr(
        executor_module,
        "persist_pre_execution_collision_probe_failure",
        persist_blocked,
    )

    receipt = cli._probe(
        SimpleNamespace(
            private_root=tmp_path,
            request_digest=request["request_digest"],
            source_commit_sha=request["source_commit_sha"],
            source_tree_sha=request["source_tree_sha"],
            now="2026-08-28T01:10:00Z",
        )
    )

    assert receipt == blocked.public_receipt
    assert captured["execution_capability"] is capability
    assert captured["private_root"] == tmp_path
    assert isinstance(captured["budget"], contract.CollisionProbeBudget)
    assert isinstance(
        captured["blocker"], provider_module.LiveProviderError
    )
