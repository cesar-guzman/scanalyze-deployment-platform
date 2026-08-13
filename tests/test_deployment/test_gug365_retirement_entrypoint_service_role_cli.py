"""Offline CLI and private-custody tests for the GUG-365 compiler."""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any, Mapping

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-retirement-entrypoint-service-role.py"
)
BASE_TEST_PATH = (
    REPO_ROOT
    / "tests/test_deployment/"
    "test_gug365_retirement_entrypoint_service_role_materializer.py"
)


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_cli(name: str = "gug365_service_role_cli") -> ModuleType:
    return _load_module(CLI_PATH, name)


@pytest.fixture(scope="module")
def synthetic_bundle(tmp_path_factory: pytest.TempPathFactory) -> Mapping[str, Any]:
    helpers = _load_module(BASE_TEST_PATH, "gug365_service_role_cli_helpers")
    return helpers.bundle.__wrapped__(tmp_path_factory)


def _private_root(tmp_path: Path, name: str = "private") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _package_args(cli: ModuleType, root: Path, bundle: Mapping[str, Any]) -> list[str]:
    return [
        "package",
        "--private-root",
        str(root),
        "--source-commit",
        str(bundle["plan"]["source"]["commit"]),
        "--runtime-version-arn",
        str(bundle["factory_contract"]["runtime_version_arn"]),
    ]


def test_help_isolated_from_python_environment_and_exposes_offline_modes() -> None:
    for arguments in (["--help"], ["package", "--help"], ["plan", "--help"]):
        result = subprocess.run(
            [
                "env",
                "-u",
                "PYTHONPATH",
                "-u",
                "PYTHONHOME",
                "python3",
                "-I",
                "-S",
                str(CLI_PATH),
                *arguments,
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert "apply" not in result.stdout.casefold()
        assert "reconcile" not in result.stdout.casefold()
        assert "offline" in result.stdout.casefold()


def test_package_mode_builds_valid_create_only_private_artifacts(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_package")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    root = _private_root(tmp_path)

    real_import = builtins.__import__

    def reject_aws_sdk(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "boto3" or name.startswith("botocore"):
            raise AssertionError("offline CLI attempted to import an AWS SDK")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_aws_sdk)
    assert cli.main(_package_args(cli, root, synthetic_bundle)) == 0
    shown = capsys.readouterr()
    status = json.loads(shown.out)
    assert shown.err == ""
    assert status["status"] == "PACKAGE_BUILT_OFFLINE"
    assert status["aws_calls"] == 0
    assert status["aws_mutations"] == 0
    assert status["deployment_authorized"] is False

    archive_path = root / cli.factory_package.ARCHIVE_NAME
    manifest_path = root / cli.factory_package.MANIFEST_NAME
    for path in (archive_path, manifest_path):
        metadata = path.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
        assert metadata.st_uid == os.geteuid()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cli.factory_package.validate_ledger_factory_package_manifest(
        manifest, archive=archive_path.read_bytes()
    )


def test_plan_mode_compiles_then_independently_validates_private_plan(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_plan")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    root = _private_root(tmp_path)
    gug363_name = "gug363-plan.json"
    contract_name = "ledger-factory-signing-contract.json"
    _write_private_json(root / gug363_name, synthetic_bundle["plan"])
    _write_private_json(root / contract_name, synthetic_bundle["factory_contract"])

    assert (
        cli.main(
            [
                "plan",
                "--private-root",
                str(root),
                "--gug363-plan",
                gug363_name,
                "--expected-gug363-plan-digest",
                synthetic_bundle["plan"]["plan_digest"],
                "--ledger-factory-signing-contract",
                contract_name,
                "--expected-ledger-factory-signing-contract-digest",
                synthetic_bundle["factory_contract_digest"],
            ]
        )
        == 0
    )
    shown = capsys.readouterr()
    status = json.loads(shown.out)
    assert shown.err == ""
    assert status["status"] == "PLAN_COMPILED_AND_VALIDATED_OFFLINE"
    assert status["managed_policy_count"] == 6
    assert status["role_count"] == 7
    assert status["aws_calls"] == 0
    assert status["aws_mutations"] == 0

    output = root / cli.PLAN_NAME
    metadata = output.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    plan = json.loads(output.read_text(encoding="utf-8"))
    assert plan["plan_digest"] == status["plan_digest"]
    cli.materializer.validate_service_role_materialization_plan(
        plan,
        gug363_plan=synthetic_bundle["plan"],
        expected_gug363_plan_digest=synthetic_bundle["plan"]["plan_digest"],
        ledger_factory_artifact_signing_contract=synthetic_bundle[
            "factory_contract"
        ],
        expected_ledger_factory_artifact_signing_contract_digest=(
            synthetic_bundle["factory_contract_digest"]
        ),
        repo_root=synthetic_bundle["repo"],
    )


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o777])
def test_private_root_requires_exact_owner_only_mode(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: int,
) -> None:
    cli = _load_cli(f"gug365_service_role_cli_mode_{mode:o}")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    root = _private_root(tmp_path)
    root.chmod(mode)
    assert cli.main(_package_args(cli, root, synthetic_bundle)) == 2
    shown = capsys.readouterr()
    assert json.loads(shown.err)["reason"] == "PRIVATE_ROOT_MODE_INVALID"
    assert not (root / cli.factory_package.ARCHIVE_NAME).exists()


def test_symlink_and_locally_discoverable_cloud_roots_fail_before_build(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_root_aliases")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    real_root = _private_root(tmp_path, "real-private")
    linked_root = tmp_path / "linked-private"
    linked_root.symlink_to(real_root, target_is_directory=True)

    assert cli.main(_package_args(cli, linked_root, synthetic_bundle)) == 2
    first = json.loads(capsys.readouterr().err)
    assert first["reason"] == "PRIVATE_ROOT_SYMLINK_FORBIDDEN"

    cloud_parent = tmp_path / "CloudStorage"
    cloud_parent.mkdir()
    cloud_root = _private_root(cloud_parent)
    assert cli.main(_package_args(cli, cloud_root, synthetic_bundle)) == 2
    second = json.loads(capsys.readouterr().err)
    assert second["reason"] == "PRIVATE_ROOT_CLOUD_MANAGED_FORBIDDEN"
    assert not (cloud_root / cli.factory_package.ARCHIVE_NAME).exists()


def test_plan_rejects_symlink_input_without_disclosing_raw_path(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_input_symlink")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    root = _private_root(tmp_path)
    secret = "sensitive-caller-and-account-data"
    target = root / f"{secret}.json"
    _write_private_json(target, synthetic_bundle["plan"])
    alias = root / "gug363-plan.json"
    alias.symlink_to(target.name)
    contract = root / "contract.json"
    _write_private_json(contract, synthetic_bundle["factory_contract"])

    result = cli.main(
        [
            "plan",
            "--private-root",
            str(root),
            "--gug363-plan",
            alias.name,
            "--expected-gug363-plan-digest",
            synthetic_bundle["plan"]["plan_digest"],
            "--ledger-factory-signing-contract",
            contract.name,
            "--expected-ledger-factory-signing-contract-digest",
            synthetic_bundle["factory_contract_digest"],
        ]
    )
    assert result == 2
    shown = capsys.readouterr()
    failure = json.loads(shown.err)
    assert failure["reason"] == "PRIVATE_INPUT_INVALID"
    assert secret not in shown.err
    assert secret not in shown.out
    assert not (root / cli.PLAN_NAME).exists()


def test_preexisting_output_is_never_overwritten_or_read(
    tmp_path: Path,
    synthetic_bundle: Mapping[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_refuse_overwrite")
    monkeypatch.setattr(cli, "REPO_ROOT", synthetic_bundle["repo"])
    root = _private_root(tmp_path)
    output = root / cli.PLAN_NAME
    original = b"must-remain-byte-identical\n"
    output.write_bytes(original)
    output.chmod(0o600)

    result = cli.main(
        [
            "plan",
            "--private-root",
            str(root),
            "--gug363-plan",
            "missing.json",
            "--expected-gug363-plan-digest",
            "sha256:" + "1" * 64,
            "--ledger-factory-signing-contract",
            "also-missing.json",
            "--expected-ledger-factory-signing-contract-digest",
            "sha256:" + "2" * 64,
        ]
    )
    assert result == 2
    failure = json.loads(capsys.readouterr().err)
    assert failure["reason"] == "SERVICE_ROLE_PLAN_ALREADY_EXISTS"
    assert output.read_bytes() == original


def test_malformed_arguments_do_not_echo_sensitive_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cli = _load_cli("gug365_service_role_cli_sanitized_arguments")
    secret = "raw-sensitive-profile-or-caller-value"
    assert cli.main(["package", "--unknown-sensitive-value", secret]) == 2
    shown = capsys.readouterr()
    failure = json.loads(shown.err)
    assert failure["reason"] == "CLI_ARGUMENTS_INVALID"
    assert secret not in shown.out
    assert secret not in shown.err


def test_atomic_publication_failure_leaves_no_target_or_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cli = _load_cli("gug365_service_role_cli_atomic_failure")
    root_path = _private_root(tmp_path)

    def fail_link(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic publication failure")

    monkeypatch.setattr(cli.os, "link", fail_link)
    with cli._private_root(root_path) as root:
        with pytest.raises(cli.OfflineCustodyError, match="PRIVATE_OUTPUT_WRITE_FAILED"):
            cli._atomic_write_private(
                root,
                "receipt.json",
                b"{}\n",
                exists_code="RECEIPT_EXISTS",
            )
    assert not (root_path / "receipt.json").exists()
    assert list(root_path.iterdir()) == []


def test_cli_source_has_no_live_or_aws_client_construction_path() -> None:
    source = CLI_PATH.read_text(encoding="utf-8")
    assert "import boto3" not in source
    assert "import botocore" not in source
    assert ".client(" not in source
    assert "Session(" not in source
    assert "cloudformation" not in source.casefold()
    parser = _load_cli("gug365_service_role_cli_parser")._parser()
    choices = next(
        action.choices
        for action in parser._actions
        if getattr(action, "choices", None) is not None
    )
    assert set(choices) == {"package", "plan"}
