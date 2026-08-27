"""Focused offline CLI tests for the GUG-393 private-input lane."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/deployment/platform-authority-gug392-live-provider.py"
COMMIT = "a" * 40
TREE = "b" * 40
DIGEST = "sha256:" + "d" * 64
REQUEST_DIGEST = "sha256:" + "1" * 64
CHECKPOINT_DIGEST = "sha256:" + "2" * 64
PROPOSAL_DIGEST = "sha256:" + "3" * 64
DECISION_DIGEST = "sha256:" + "4" * 64


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("gug393_discovery_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bundle(
    cli: Any, module_names: tuple[str, ...], modules: tuple[Any, ...]
) -> Any:
    assert len(module_names) == len(modules)
    return cli._ReviewedRepositoryModules(
        cli._REVIEWED_REPOSITORY_BUNDLE_SENTINEL,
        source_identity=(COMMIT, TREE),
        modules=dict(zip(module_names, modules, strict=True)),
    )


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return root


def test_all_five_gug393_command_help_paths_need_no_sdk() -> None:
    commands = (
        "materialize-discovery-request",
        "discover-inputs",
        "materialize-discovery-decision",
        "materialize-approved-inputs",
        "validate-discovery-receipt",
    )
    for command in commands:
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SCRIPT), command, "--help"],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert command in result.stdout
        assert "Traceback" not in result.stderr
        assert result.stderr == ""


def test_materialize_discovery_request_uses_reviewed_bundle_and_no_aws(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _module()
    private_root = _private_root(tmp_path)
    source_bundle = {"source": "reviewed-private-bundle"}
    profiles = {"profiles": "reviewed-private-profiles"}
    budget = {"budget": "owner-reviewed"}
    inputs = {
        "source-bundle.json": source_bundle,
        "profiles.json": profiles,
        "budget.json": budget,
    }
    reads: list[str] = []
    calls: dict[str, Any] = {}

    def read_private_json(root: Path, name: str) -> dict[str, Any]:
        assert root == private_root
        reads.append(name)
        return inputs[name]

    authority = SimpleNamespace(read_private_json=read_private_json)
    source_contract = {"source_contract_digest": "sha256:" + "5" * 64}

    def derive_source_contract(**kwargs: Any) -> dict[str, Any]:
        calls["derive"] = kwargs
        return source_contract

    materialization = SimpleNamespace(
        request={
            "source_contract_digest": source_contract[
                "source_contract_digest"
            ],
            "request_digest": REQUEST_DIGEST,
            "budget_digest": "sha256:" + "6" * 64,
        },
        owner_checkpoint={"checkpoint_digest": CHECKPOINT_DIGEST},
    )

    def materialize_discovery_request(**kwargs: Any) -> Any:
        calls["materialize"] = kwargs
        return materialization

    def persist_discovery_request(root: Path, supplied: Any) -> None:
        calls["persist"] = (root, supplied)

    discovery = SimpleNamespace(
        derive_source_contract=derive_source_contract,
        materialize_discovery_request=materialize_discovery_request,
        persist_discovery_request=persist_discovery_request,
        operational_host_digest=lambda: "sha256:" + "7" * 64,
    )
    offline_bundle = _bundle(
        cli,
        cli._DISCOVERY_OFFLINE_MODULES,
        (SimpleNamespace(), authority, discovery),
    )
    selected: list[tuple[str, ...]] = []

    def reviewed_bundle(module_names: tuple[str, ...]) -> Any:
        selected.append(module_names)
        return offline_bundle

    monkeypatch.setattr(cli, "_reviewed_command_bundle", reviewed_bundle)
    result = cli.main(
        [
            "materialize-discovery-request",
            "--private-root",
            str(private_root),
            "--source-bundle-file",
            "source-bundle.json",
            "--profile-bindings-file",
            "profiles.json",
            "--budget-file",
            "budget.json",
            "--sdk-runtime-root",
            "/reviewed/sdk-runtime",
            "--not-before",
            "2035-01-02T03:00:00Z",
            "--expires-at",
            "2035-01-02T03:15:00Z",
            "--approval-reference-digest",
            DIGEST,
        ]
    )

    assert result == 0
    captured = capsys.readouterr()
    emitted = json.loads(captured.out)
    assert captured.err == ""
    assert emitted == {
        "aws_calls": 0,
        "aws_mutations": 0,
        "budget_digest": "sha256:" + "6" * 64,
        "checkpoint_digest": CHECKPOINT_DIGEST,
        "deployment_authorized": False,
        "production_status": "NO-GO",
        "read_only": True,
        "record_type": (
            "scanalyze.platform_authority.gug393_discovery_"
            "request_materialization_result.v1"
        ),
        "request_digest": REQUEST_DIGEST,
        "source_contract_digest": source_contract[
            "source_contract_digest"
        ],
        "status": "PRIVATE_DISCOVERY_REQUEST_MATERIALIZED",
    }
    assert selected == [cli._DISCOVERY_OFFLINE_MODULES]
    assert reads == ["source-bundle.json", "profiles.json", "budget.json"]
    assert calls["derive"] == {
        "source_bundle": source_bundle,
        "source_commit_sha": COMMIT,
        "source_tree_sha": TREE,
        "repo_root": cli.REPO_ROOT,
    }
    assert calls["materialize"]["source_contract"] is source_contract
    assert calls["materialize"]["profiles"] is profiles
    assert calls["materialize"]["discovery_budget"] is budget
    assert calls["persist"] == (private_root, materialization)
    assert list(private_root.iterdir()) == []


def test_discover_inputs_shares_capability_budget_profiles_and_emits_only_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _module()
    private_root = _private_root(tmp_path)
    capability = object()
    validated_budget = object()
    shared_budget = object()
    provider_factory = object()
    private_marker = "PRIVATE-CANDIDATE-MUST-NOT-BE-EMITTED"
    receipt = {
        "record_type": (
            "scanalyze.platform_authority.gug393_discovery_receipt.v1"
        ),
        "status": "READY_FOR_OWNER_DECISION",
        "proposal_digest": PROPOSAL_DIGEST,
    }
    profiles = {
        "authority": {
            "name": "authority-reader",
            "expected_account_id": "111111111111",
            "expected_principal_digest": "sha256:" + "8" * 64,
            "expected_sso_role_name_digest": "sha256:" + "9" * 64,
            "authority_verification_digest": "sha256:" + "a" * 64,
        },
        "identity_center": {
            "name": "identity-reader",
            "expected_account_id": "222222222222",
            "expected_principal_digest": "sha256:" + "b" * 64,
            "expected_sso_role_name_digest": "sha256:" + "c" * 64,
            "authority_verification_digest": "sha256:" + "d" * 64,
        },
    }
    request = {
        "discovery_budget": {"reviewed": True},
        "profiles": profiles,
        "sdk_runtime_root": "/reviewed/sdk-runtime",
    }
    observed: dict[str, Any] = {}

    def read_and_claim(**kwargs: Any) -> tuple[dict[str, Any], object]:
        observed["claim"] = kwargs
        return request, capability

    discovery = SimpleNamespace(
        read_and_claim_discovery_request=read_and_claim,
        operational_host_digest=lambda: "sha256:" + "e" * 64,
    )

    def validate_budget(value: Any, **kwargs: Any) -> object:
        observed["budget_validation"] = (value, kwargs)
        return validated_budget

    def global_budget(value: object) -> object:
        assert value is validated_budget
        return shared_budget

    budget_module = SimpleNamespace(
        validate_discovery_budget=validate_budget,
        GlobalDiscoveryBudget=global_budget,
    )

    def build_provider(**kwargs: Any) -> object:
        observed["provider"] = kwargs
        return provider_factory

    provider_module = SimpleNamespace(
        build_discovery_provider_factory=build_provider
    )

    def execute(**kwargs: Any) -> Any:
        observed["executor"] = kwargs
        return SimpleNamespace(
            public_receipt=receipt,
            private_candidate={"marker": private_marker},
        )

    executor = SimpleNamespace(execute_private_input_discovery=execute)
    live_bundle = _bundle(
        cli,
        cli._DISCOVERY_LIVE_MODULES,
        (provider_module, budget_module, discovery, executor),
    )
    selected: list[tuple[str, ...]] = []

    def reviewed_bundle(module_names: tuple[str, ...]) -> Any:
        selected.append(module_names)
        return live_bundle

    monkeypatch.setattr(cli, "_reviewed_command_bundle", reviewed_bundle)
    assert cli.main(
        [
            "discover-inputs",
            "--private-root",
            str(private_root),
            "--expected-request-digest",
            REQUEST_DIGEST,
            "--expected-checkpoint-digest",
            CHECKPOINT_DIGEST,
            "--approval-reference-digest",
            DIGEST,
        ]
    ) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == receipt
    assert private_marker not in captured.out
    assert captured.err == ""
    assert selected == [cli._DISCOVERY_LIVE_MODULES]
    assert observed["budget_validation"][0] is request["discovery_budget"]
    assert observed["budget_validation"][1]["require_active"] is True
    assert observed["provider"]["discovery_budget"] is shared_budget
    assert observed["provider"]["execution_capability"] is capability
    assert observed["provider"]["authority_profile"] == profiles[
        "authority"
    ]["name"]
    assert observed["provider"]["identity_center_profile"] == profiles[
        "identity_center"
    ]["name"]
    assert observed["executor"]["provider_factory"] is provider_factory
    assert observed["executor"]["execution_capability"] is capability
    assert observed["executor"]["private_root"] == private_root
    assert observed["executor"]["now"] is observed[
        "budget_validation"
    ][1]["now"]


def test_decision_is_separate_and_approved_publication_is_create_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _module()
    private_root = _private_root(tmp_path)
    proposal_name = "gug393-private-input-proposal.json"
    decision_name = "gug393-private-input-owner-decision.json"
    manifest_name = "gug393-private-input-materialization-manifest.json"
    authority_plan_name = "gug392-authority-plan.json"
    identity_plan_name = "gug392-identity-center-plan.json"
    candidate = {"proposal_digest": PROPOSAL_DIGEST}
    owner_decision = {
        "proposal_digest": PROPOSAL_DIGEST,
        "decision_digest": DECISION_DIGEST,
        "approval_reference_digest": DIGEST,
    }
    private_store: dict[str, Any] = {proposal_name: candidate}
    published: dict[str, Any] = {}
    calls: dict[str, list[Any]] = {
        "decision": [],
        "materialize": [],
        "persist": [],
    }

    def read_private_json(root: Path, name: str) -> Any:
        assert root == private_root
        return private_store[name]

    authority = SimpleNamespace(read_private_json=read_private_json)

    def materialize_owner_decision(**kwargs: Any) -> dict[str, Any]:
        calls["decision"].append(kwargs)
        assert kwargs["candidate"] is candidate
        return owner_decision

    def persist_owner_decision(root: Path, decision: dict[str, Any]) -> None:
        assert root == private_root
        assert decision_name not in private_store
        private_store[decision_name] = decision

    manifest = {
        "proposal_digest": PROPOSAL_DIGEST,
        "decision_digest": DECISION_DIGEST,
        "manifest_digest": "sha256:" + "f" * 64,
        "artifact_digests": {
            authority_plan_name: "sha256:" + "1" * 64,
            identity_plan_name: "sha256:" + "2" * 64,
        },
    }
    materialization = SimpleNamespace(manifest=manifest)

    def materialize_approved(**kwargs: Any) -> Any:
        calls["materialize"].append(kwargs)
        assert kwargs["candidate"] is candidate
        assert kwargs["decision"] is owner_decision
        return materialization

    def persist_approved(root: Path, supplied: Any) -> None:
        assert root == private_root
        calls["persist"].append(supplied)
        if "materialization" in published:
            raise cli.CliError("PRIVATE_TARGET_EXISTS")
        published["materialization"] = supplied

    discovery = SimpleNamespace(
        DEFAULT_PROPOSAL_FILE=proposal_name,
        DEFAULT_DECISION_FILE=decision_name,
        DEFAULT_AUTHORITY_PLAN_FILE=authority_plan_name,
        DEFAULT_IDENTITY_PLAN_FILE=identity_plan_name,
        materialize_owner_decision=materialize_owner_decision,
        persist_owner_decision=persist_owner_decision,
        materialize_approved_gug392_inputs=materialize_approved,
        persist_approved_gug392_inputs=persist_approved,
    )
    offline_bundle = _bundle(
        cli,
        cli._DISCOVERY_OFFLINE_MODULES,
        (SimpleNamespace(), authority, discovery),
    )
    monkeypatch.setattr(
        cli, "_reviewed_command_bundle", lambda _: offline_bundle
    )

    decision_arguments = [
        "materialize-discovery-decision",
        "--private-root",
        str(private_root),
        "--expected-proposal-digest",
        PROPOSAL_DIGEST,
        "--approval-reference-digest",
        DIGEST,
        "--expires-at",
        "2035-01-02T03:15:00Z",
    ]
    assert cli.main(decision_arguments) == 0
    decision_output = json.loads(capsys.readouterr().out)
    assert decision_output["status"] == "PRIVATE_OWNER_DECISION_MATERIALIZED"
    assert private_store[decision_name] is owner_decision
    assert calls["decision"][0]["expected_proposal_digest"] == (
        PROPOSAL_DIGEST
    )
    assert calls["decision"][0]["source_commit_sha"] == COMMIT
    assert calls["decision"][0]["source_tree_sha"] == TREE

    approved_arguments = [
        "materialize-approved-inputs",
        "--private-root",
        str(private_root),
        "--expected-proposal-digest",
        PROPOSAL_DIGEST,
        "--expected-decision-digest",
        DECISION_DIGEST,
    ]
    assert cli.main(approved_arguments) == 0
    approved_capture = capsys.readouterr()
    approved_output = json.loads(approved_capture.out)
    assert approved_capture.err == ""
    assert approved_output["status"] == "APPROVED_GUG392_INPUTS_MATERIALIZED"
    assert approved_output["proposal_digest"] == PROPOSAL_DIGEST
    assert approved_output["decision_digest"] == DECISION_DIGEST
    assert published["materialization"] is materialization
    assert calls["materialize"][0]["source_commit_sha"] == COMMIT
    assert calls["materialize"][0]["source_tree_sha"] == TREE
    assert "decision_file" not in calls["materialize"][0]
    assert "manifest_file" not in calls["materialize"][0]

    assert cli.main(approved_arguments) == 2
    repeated = capsys.readouterr()
    assert repeated.out == ""
    assert json.loads(repeated.err) == {
        "error": "PRIVATE_TARGET_EXISTS",
        "status": "HUMAN_DECISION_REQUIRED",
    }
    assert published == {"materialization": materialization}


def test_invalid_or_unminted_bundle_fails_before_any_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _module()
    private_root = _private_root(tmp_path)
    emitted: list[Any] = []
    monkeypatch.setattr(cli, "_emit", emitted.append)
    forged = SimpleNamespace(
        _sentinel=cli._REVIEWED_REPOSITORY_BUNDLE_SENTINEL,
        _source_identity=(COMMIT, TREE),
        _modules={},
    )
    minted_with_wrong_modules = cli._ReviewedRepositoryModules(
        cli._REVIEWED_REPOSITORY_BUNDLE_SENTINEL,
        source_identity=(COMMIT, TREE),
        modules={},
    )
    arguments = [
        "materialize-discovery-request",
        "--private-root",
        str(private_root),
        "--source-bundle-file",
        "source-bundle.json",
        "--profile-bindings-file",
        "profiles.json",
        "--budget-file",
        "budget.json",
        "--sdk-runtime-root",
        "/reviewed/sdk-runtime",
        "--not-before",
        "2035-01-02T03:00:00Z",
        "--expires-at",
        "2035-01-02T03:15:00Z",
        "--approval-reference-digest",
        DIGEST,
    ]

    for invalid_bundle in (object(), forged, minted_with_wrong_modules):
        monkeypatch.setattr(
            cli,
            "_reviewed_command_bundle",
            lambda _modules, supplied=invalid_bundle: supplied,
        )
        assert cli.main(arguments) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert json.loads(captured.err) == {
            "error": "IMPORT_PROVENANCE_INVALID",
            "status": "HUMAN_DECISION_REQUIRED",
        }

    assert emitted == []
    assert list(private_root.iterdir()) == []
