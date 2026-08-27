from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.platform_authority_gug376_authority_inventory_collector import (
    read_private_json,
    write_private_json,
)
from tests.test_deployment import test_gug392_live_request_materializer as request_data


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/deployment/platform-authority-gug392-live-provider.py"
VALID_RUN = (
    ROOT
    / "fixtures/valid/platform-authority-gug376-live-readonly-run-v2-contract-example.json"
)
VALID_HANDOFF = (
    ROOT
    / "fixtures/valid/platform-authority-gug376-live-readonly-handoff-v2-contract-example.json"
)


def _module():
    spec = importlib.util.spec_from_file_location("gug392_live_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def test_source_identity_ignores_real_git_replace_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _module()
    repo = tmp_path / "replace-repository"
    repo.mkdir()

    def git(*arguments: str, no_replace: bool = False) -> str:
        environment = dict(os.environ)
        if no_replace:
            environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        return result.stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Synthetic GUG392 Test")
    git("config", "user.email", "synthetic-gug392@example.invalid")
    tracked = repo / "tracked.txt"
    tracked.write_text("first\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("commit", "-q", "-m", "first")
    first_commit = git("rev-parse", "HEAD", no_replace=True)
    first_tree = git("show", "-s", "--format=%T", "HEAD", no_replace=True)
    tracked.write_text("second\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("commit", "-q", "-m", "second")
    second_commit = git("rev-parse", "HEAD", no_replace=True)
    second_tree = git("show", "-s", "--format=%T", "HEAD", no_replace=True)
    git("replace", second_commit, first_commit)
    assert git("show", "-s", "--format=%T", "HEAD") == first_tree
    assert second_tree != first_tree

    monkeypatch.setattr(cli, "REPO_ROOT", repo)
    monkeypatch.setattr(request_data.materializer, "REPO_ROOT", repo)
    assert cli._source_identity() == (second_commit, second_tree)
    assert request_data.materializer._current_source_identity() == (
        second_commit,
        second_tree,
    )


def _operational_arguments(command: str) -> list[str]:
    digest = "sha256:" + "0" * 64
    if command == "materialize-plans":
        return [
            command,
            "--private-root",
            "/tmp/gug392-source-boundary-noop",
            "--authority-input-file",
            "authority-input.json",
            "--identity-center-input-file",
            "identity-center-input.json",
        ]
    if command == "materialize-request":
        return [
            command,
            "--private-root",
            "/tmp/gug392-source-boundary-noop",
            "--authority-plan-file",
            "authority-plan.json",
            "--identity-center-plan-file",
            "identity-center-plan.json",
            "--authority-profile",
            "synthetic-authority",
            "--identity-center-profile",
            "synthetic-identity",
            "--authority-sso-role-name",
            "SyntheticAuthorityReadOnly",
            "--identity-center-sso-role-name",
            "SyntheticIdentityReadOnly",
            "--run-id",
            "synthetic-run-0001",
            "--not-before",
            "2026-08-27T00:00:00Z",
            "--expires-at",
            "2026-08-27T00:15:00Z",
            "--approval-reference-digest",
            digest,
            "--sdk-runtime-root",
            "/tmp/gug392-closed-sdk-runtime",
        ]
    if command == "validate-evidence-v2":
        return [
            command,
            "--private-root",
            "/tmp/gug392-source-boundary-noop",
            "fixtures/valid/platform-authority-gug376-live-readonly-run-v2-contract-example.json",
            "fixtures/valid/platform-authority-gug376-live-readonly-handoff-v2-contract-example.json",
        ]
    assert command == "live"
    return [
        command,
        "--private-root",
        "/tmp/gug392-source-boundary-noop",
        "--approval-reference-digest",
        digest,
        "--expected-request-digest",
        digest,
        "--expected-checkpoint-digest",
        digest,
    ]


def _run_isolated_operational_module(
    command: str,
    *,
    environment: dict[str, str] | None = None,
    preloaded_module: str | None = None,
    override_runtime: bool = True,
    no_site: bool = True,
) -> subprocess.CompletedProcess[str]:
    lines = [
        "import importlib.util, sys, types",
        f"spec = importlib.util.spec_from_file_location('gug392_cli_isolated', {str(SCRIPT)!r})",
        "module = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(module)",
    ]
    if override_runtime:
        lines.append("module._operational_python_version = lambda: (3, 11, 14)")
    if preloaded_module is not None:
        lines.append(
            f"sys.modules[{preloaded_module!r}] = types.ModuleType({preloaded_module!r})"
        )
    lines.append(
        f"raise SystemExit(module.main({_operational_arguments(command)!r}))"
    )
    flags = ["-I", *( ["-S"] if no_site else [] )]
    return subprocess.run(
        [sys.executable, *flags, "-c", "\n".join(lines)],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def _temporary_source_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "source-repository"
    (repository / "scripts/deployment").mkdir(parents=True)
    (repository / "tooling").mkdir()
    (repository / "scripts/deployment/platform-authority-gug392-live-provider.py").write_text(
        "ENTRYPOINT = True\n", encoding="utf-8"
    )
    (repository / "tooling/__init__.py").write_text("", encoding="utf-8")
    (repository / "tooling/reviewed.py").write_text(
        "VALUE = 'reviewed'\n", encoding="utf-8"
    )
    (repository / ".gitignore").write_text(
        "tooling/ignored.py\n", encoding="utf-8"
    )
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        [
            "git",
            "-c",
            "user.name=GUG392 Test",
            "-c",
            "user.email=gug392@example.invalid",
            "commit",
            "-q",
            "-m",
            "test source",
        ],
    ):
        subprocess.run(command, cwd=repository, check=True, capture_output=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repository.resolve(), commit


def _point_cli_at_repository(cli, repository: Path, monkeypatch) -> None:
    tooling_root = repository / "tooling"
    monkeypatch.setattr(cli, "REPO_ROOT", repository)
    monkeypatch.setattr(cli, "_TOOLING_ROOT", tooling_root)
    monkeypatch.setattr(
        cli,
        "_ENTRYPOINT_RELATIVE_PATH",
        Path("scripts/deployment/platform-authority-gug392-live-provider.py"),
    )
    monkeypatch.setattr(
        cli,
        "_REPOSITORY_MODULE_PATHS",
        {"tooling.reviewed": tooling_root / "reviewed.py"},
    )


def _synthetic_repository_bundle(
    cli,
    *,
    source_identity: tuple[str, str],
    modules: dict[str, object],
):
    return cli._ReviewedRepositoryModules(
        cli._REVIEWED_REPOSITORY_BUNDLE_SENTINEL,
        source_identity=source_identity,
        modules=modules,
    )


def test_help_is_isolated_and_does_not_import_the_aws_sdk() -> None:
    for arguments in (
        ["--help"],
        ["materialize-plans", "--help"],
        ["materialize-request", "--help"],
        ["live", "--help"],
        ["validate-run-v2", "--help"],
        ["validate-handoff-v2", "--help"],
        ["validate-evidence-v2", "--help"],
    ):
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(SCRIPT), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0
        assert "Traceback" not in result.stderr


def test_public_v2_validation_commands_emit_only_the_validated_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import tooling.platform_authority_gug376_live_executor as executor

    cli = _module()
    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=(request_data.SOURCE_SHA, request_data.TREE_SHA),
        modules={cli._VALIDATE_MODULES[0]: executor},
    )
    monkeypatch.setattr(
        cli, "_reviewed_command_bundle", lambda modules: bundle
    )
    for arguments, source in (
        (("validate-run-v2", str(VALID_RUN)), VALID_RUN),
        (
            ("validate-handoff-v2", str(VALID_RUN), str(VALID_HANDOFF)),
            VALID_HANDOFF,
        ),
    ):
        assert cli.main(list(arguments)) == 0
        captured = capsys.readouterr()
        assert json.loads(captured.out) == json.loads(source.read_text())
        assert captured.err == ""


def test_handoff_validation_rejects_self_sealed_foreign_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tooling.platform_authority_gug376_live_executor as executor

    cli = _module()
    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=(request_data.SOURCE_SHA, request_data.TREE_SHA),
        modules={cli._VALIDATE_MODULES[0]: executor},
    )
    monkeypatch.setattr(
        cli, "_reviewed_command_bundle", lambda modules: bundle
    )
    handoff = json.loads(VALID_HANDOFF.read_text())
    handoff["run_digest"] = canonical_digest("nonexistent-run")
    handoff["handoff_digest"] = canonical_digest(
        {key: value for key, value in handoff.items() if key != "handoff_digest"}
    )
    substituted = tmp_path / "substituted-handoff.json"
    substituted.write_text(json.dumps(handoff))

    assert cli.main(
        ["validate-handoff-v2", str(VALID_RUN), str(substituted)]
    ) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.err)["error"] == "LIVE_BUNDLE_V2_INVALID"
    assert "Traceback" not in captured.err


def test_private_evidence_validation_uses_private_custody_and_reviewed_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tooling.platform_authority_gug376_live_executor as executor

    cli = _module()
    root = _root(tmp_path)
    manifest = {"evidence_manifest_digest": "sha256:" + "e" * 64}
    receipt = {
        "record_type": "scanalyze.platform_authority.gug392_evidence_verification.v1",
        "status": "PRIVATE_EVIDENCE_VERIFIED",
    }
    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=(request_data.SOURCE_SHA, request_data.TREE_SHA),
        modules={cli._VALIDATE_MODULES[0]: executor},
    )
    monkeypatch.setattr(
        cli, "_reviewed_command_bundle", lambda modules: bundle
    )

    def private_read(private_root: Path, name: str) -> dict[str, Any]:
        assert private_root == root
        assert name == "gug376-live-evidence-manifest.json"
        return manifest

    monkeypatch.setattr(executor, "read_private_json", private_read)

    def validate(
        supplied_manifest: dict[str, Any],
        run: dict[str, Any],
        handoff: dict[str, Any],
        *,
        private_root: Path,
    ) -> dict[str, Any]:
        assert supplied_manifest is manifest
        assert run == json.loads(VALID_RUN.read_text())
        assert handoff == json.loads(VALID_HANDOFF.read_text())
        assert private_root == root
        return receipt

    monkeypatch.setattr(
        executor, "validate_private_live_evidence_bundle", validate
    )
    assert cli.main(
        [
            "validate-evidence-v2",
            "--private-root",
            str(root),
            str(VALID_RUN),
            str(VALID_HANDOFF),
        ]
    ) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == receipt
    assert captured.err == ""


@pytest.mark.parametrize(
    "command",
    (
        "materialize-plans",
        "materialize-request",
        "live",
        "validate-evidence-v2",
    ),
)
def test_operational_commands_require_python_isolated_mode(command: str) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *_operational_arguments(command)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "PYTHON_ISOLATION_REQUIRED"
    assert "Traceback" not in result.stderr


def test_operational_commands_require_exact_repository_python_runtime() -> None:
    expected = (3, 11, 14)
    if tuple(sys.version_info[:3]) == expected:
        pytest.skip("test runner already uses the exact operational runtime")
    result = _run_isolated_operational_module(
        "live", override_runtime=False
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "PYTHON_RUNTIME_UNSUPPORTED"
    assert "Traceback" not in result.stderr


def test_operational_commands_require_no_site_startup() -> None:
    result = _run_isolated_operational_module(
        "live", no_site=False
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "PYTHON_NO_SITE_REQUIRED"
    assert "Traceback" not in result.stderr


def test_operational_runtime_gate_matches_tool_versions() -> None:
    cli = _module()
    configured = next(
        line.split(maxsplit=1)[1]
        for line in (ROOT / ".tool-versions").read_text().splitlines()
        if line.startswith("python ")
    )
    assert ".".join(map(str, cli._EXPECTED_OPERATIONAL_PYTHON)) == configured


@pytest.mark.parametrize("variable", ("PYTHONHOME", "PYTHONPATH"))
def test_operational_commands_reject_unsafe_python_environment(
    variable: str,
) -> None:
    environment = os.environ.copy()
    environment[variable] = "/tmp/gug392-untrusted-python"
    result = _run_isolated_operational_module(
        "materialize-request", environment=environment
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "IMPORT_ENVIRONMENT_UNSAFE"
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "module_name",
    (
        "tooling.synthetic",
        "boto.synthetic",
        "boto3",
        "botocore.synthetic",
        "dateutil.synthetic",
        "jmespath",
        "s3transfer.synthetic",
        "six",
        "six.moves",
        "six.moves._thread",
        "urllib3.synthetic",
        "awscrt",
        "certifi.core",
    ),
)
def test_operational_commands_reject_preloaded_repository_or_sdk_modules(
    module_name: str,
) -> None:
    result = _run_isolated_operational_module(
        "live", preloaded_module=module_name
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "IMPORT_PRELOADED_UNSAFE"
    assert "Traceback" not in result.stderr


def test_reviewed_manifest_binds_entrypoint_and_all_tooling_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _module()
    repository, commit = _temporary_source_repository(tmp_path)
    _point_cli_at_repository(cli, repository, monkeypatch)

    manifest = cli._reviewed_repository_source_manifest(commit)

    assert set(manifest) == {
        (repository / "tooling/__init__.py").resolve(),
        (repository / "tooling/reviewed.py").resolve(),
    }
    assert manifest[(repository / "tooling/reviewed.py").resolve()] == (
        b"VALUE = 'reviewed'\n"
    )


def test_isolated_loader_mints_bundle_from_reviewed_bytes(
    tmp_path: Path,
) -> None:
    repository, commit = _temporary_source_repository(tmp_path)
    source_tree = "2" * 40
    code = "\n".join(
        (
            "import importlib.util, json",
            "from pathlib import Path",
            f"spec = importlib.util.spec_from_file_location('gug392_cli_loader', {str(SCRIPT)!r})",
            "cli = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(cli)",
            "cli._operational_python_version = lambda: (3, 11, 14)",
            f"cli.REPO_ROOT = Path({str(repository)!r})",
            "cli._TOOLING_ROOT = cli.REPO_ROOT / 'tooling'",
            "cli._ENTRYPOINT_RELATIVE_PATH = Path("
            "'scripts/deployment/platform-authority-gug392-live-provider.py')",
            "cli._REPOSITORY_MODULE_PATHS = {"
            "'tooling.reviewed': cli._TOOLING_ROOT / 'reviewed.py'}",
            f"manifest = cli._reviewed_repository_source_manifest({commit!r})",
            "bundle = cli._load_repository_modules("
            "manifest, ('tooling.reviewed',), "
            f"source_identity=({commit!r}, {source_tree!r}))",
            "identity, modules = cli._validated_repository_bundle(bundle, ('tooling.reviewed',))",
            "print(json.dumps({'identity': identity, "
            "'value': modules['tooling.reviewed'].VALUE, "
            "'loader': type(modules['tooling.reviewed'].__loader__).__name__}))",
        )
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "identity": [commit, source_tree],
        "value": "reviewed",
        "loader": "_ReviewedSourceLoader",
    }


@pytest.mark.parametrize(
    "relative_path",
    (
        "scripts/deployment/platform-authority-gug392-live-provider.py",
        "tooling/reviewed.py",
    ),
)
def test_reviewed_manifest_rejects_tracked_byte_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    cli = _module()
    repository, commit = _temporary_source_repository(tmp_path)
    _point_cli_at_repository(cli, repository, monkeypatch)
    (repository / relative_path).write_text(
        "VALUE = 'drifted'\n", encoding="utf-8"
    )

    with pytest.raises(cli.CliError, match="SOURCE_BLOB_MISMATCH"):
        cli._reviewed_repository_source_manifest(commit)


def test_reviewed_manifest_rejects_ignored_python_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _module()
    repository, commit = _temporary_source_repository(tmp_path)
    _point_cli_at_repository(cli, repository, monkeypatch)
    (repository / "tooling/ignored.py").write_text(
        "VALUE = 'ignored'\n", encoding="utf-8"
    )

    with pytest.raises(cli.CliError, match="SOURCE_PYTHON_CANDIDATE_INVALID"):
        cli._reviewed_repository_source_manifest(commit)


def test_reviewed_loader_compiles_only_manifest_bytes(tmp_path: Path) -> None:
    cli = _module()
    source = tmp_path / "reviewed_module.py"
    reviewed = b"VALUE = 'reviewed'\n"
    source.write_bytes(reviewed)
    manifest = {source.resolve(): reviewed}
    loader = cli._ReviewedSourceLoader(
        "gug392_reviewed_module",
        str(source),
        reviewed_sources=manifest,
    )
    spec = cli.spec_from_file_location(
        "gug392_reviewed_module", str(source), loader=loader
    )
    assert spec is not None
    module = cli.module_from_spec(spec)
    loader.exec_module(module)
    assert module.VALUE == "reviewed"
    assert not (tmp_path / "__pycache__").exists()

    source.write_text("VALUE = 'changed'\n", encoding="utf-8")
    changed_loader = cli._ReviewedSourceLoader(
        "gug392_changed_module",
        str(source),
        reviewed_sources=manifest,
    )
    changed_spec = cli.spec_from_file_location(
        "gug392_changed_module", str(source), loader=changed_loader
    )
    assert changed_spec is not None
    changed_module = cli.module_from_spec(changed_spec)
    with pytest.raises(ImportError, match="reviewed source changed"):
        changed_loader.exec_module(changed_module)


def test_materialize_plans_command_is_offline_private_create_only(
    tmp_path: Path,
) -> None:
    import tooling.platform_authority_gug365_upstream_inventory as upstream
    import tooling.platform_authority_gug376_authority_inventory_collector as authority
    import tooling.platform_authority_gug376_identity_center_inventory_collector as identity
    import tooling.platform_authority_gug376_live_readonly_orchestrator as orchestrator
    import tooling.platform_authority_gug376_live_request_materializer as materializer

    cli = _module()
    root = _root(tmp_path)
    authority_input, identity_input = request_data._plan_inputs()
    write_private_json(root, "authority-input.json", authority_input)
    write_private_json(root, "identity-center-input.json", identity_input)
    arguments = argparse.Namespace(
        private_root=root,
        authority_input_file="authority-input.json",
        identity_center_input_file="identity-center-input.json",
        authority_plan_file="authority-plan.json",
        identity_center_plan_file="identity-center-plan.json",
    )
    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=(request_data.SOURCE_SHA, request_data.TREE_SHA),
        modules={
            cli._PLAN_MATERIALIZE_MODULES[0]: upstream,
            cli._PLAN_MATERIALIZE_MODULES[1]: authority,
            cli._PLAN_MATERIALIZE_MODULES[2]: identity,
            cli._PLAN_MATERIALIZE_MODULES[3]: materializer,
            cli._PLAN_MATERIALIZE_MODULES[4]: orchestrator,
        },
    )

    result = cli._materialize_plans(arguments, repository_bundle=bundle)

    authority_plan = read_private_json(root, "authority-plan.json")
    identity_plan = read_private_json(root, "identity-center-plan.json")
    assert result["authority_plan_digest"] == canonical_digest(authority_plan)
    assert result["identity_center_plan_digest"] == canonical_digest(identity_plan)
    assert result["aws_calls"] == result["aws_mutations"] == 0
    assert result["production_status"] == "NO-GO"
    assert authority_plan["expected_policy_digest"] == result[
        "authority_policy_digest"
    ]
    assert identity_plan["expected_discovery_policy_digest"] == result[
        "identity_center_discovery_policy_digest"
    ]
    assert all(
        stat.S_IMODE((root / name).stat().st_mode) == 0o600
        for name in ("authority-plan.json", "identity-center-plan.json")
    )


def test_materialize_command_is_offline_private_create_only(
    tmp_path: Path, monkeypatch
) -> None:
    import tooling.platform_authority_gug365_upstream_inventory as upstream
    import tooling.platform_authority_gug376_authority_inventory_collector as authority
    import tooling.platform_authority_gug376_identity_center_inventory_collector as identity
    import tooling.platform_authority_gug376_live_readonly_orchestrator as orchestrator
    import tooling.platform_authority_gug376_live_request_materializer as materializer

    cli = _module()
    root = _root(tmp_path)
    write_private_json(root, "authority-plan.json", request_data._authority_plan())
    write_private_json(
        root, "identity-center-plan.json", request_data._identity_plan()
    )
    monkeypatch.setattr(cli.platform, "node", lambda: "synthetic-gug392-host")
    arguments = argparse.Namespace(
        private_root=root,
        authority_plan_file="authority-plan.json",
        identity_center_plan_file="identity-center-plan.json",
        authority_profile="synthetic-authority",
        identity_center_profile="synthetic-identity",
        authority_sso_role_name="SyntheticAuthorityReadOnly",
        identity_center_sso_role_name="SyntheticIdentityReadOnly",
        run_id="synthetic-run-0001",
        not_before=request_data._stamp(request_data.START + request_data.timedelta(minutes=1)),
        expires_at=request_data._stamp(request_data.REQUEST_END),
        approval_reference_digest=request_data.APPROVAL_REFERENCE_DIGEST,
        sdk_runtime_root=str(request_data._sdk_root(tmp_path)),
        request_file="gug376-live-request.json",
        owner_checkpoint_file="gug376-owner-checkpoint.json",
    )
    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=(request_data.SOURCE_SHA, request_data.TREE_SHA),
        modules={
            cli._MATERIALIZE_MODULES[0]: upstream,
            cli._MATERIALIZE_MODULES[1]: authority,
            cli._MATERIALIZE_MODULES[2]: identity,
            cli._MATERIALIZE_MODULES[3]: materializer,
            cli._MATERIALIZE_MODULES[4]: orchestrator,
        },
    )
    result = cli._materialize(arguments, repository_bundle=bundle)
    request = read_private_json(root, arguments.request_file)
    checkpoint = read_private_json(root, arguments.owner_checkpoint_file)
    assert result["request_digest"] == request["request_digest"]
    assert result["checkpoint_digest"] == checkpoint["checkpoint_digest"]
    assert result["aws_calls"] == result["aws_mutations"] == 0
    assert result["production_status"] == "NO-GO"
    assert stat.S_IMODE((root / arguments.request_file).stat().st_mode) == 0o600
    assert stat.S_IMODE((root / arguments.owner_checkpoint_file).stat().st_mode) == 0o600


def test_unminted_repository_bundle_never_reaches_materialization(
    tmp_path: Path,
) -> None:
    cli = _module()
    root = _root(tmp_path)
    arguments = argparse.Namespace(private_root=root)
    with pytest.raises(cli.CliError, match="IMPORT_PROVENANCE_INVALID"):
        cli._materialize(arguments, repository_bundle=object())
    assert list(root.iterdir()) == []


@pytest.mark.parametrize(
    "role_name",
    (
        "AWSAdministratorAccess",
        "ScanalyzeAuthorityBootstrapPlan",
        "ScanalyzeFounderPepSeed",
        "ScanalyzeSandboxDeploy",
        "ScanalyzeSandboxDestroy",
    ),
)
def test_mutating_or_broad_sso_role_names_are_rejected(role_name: str) -> None:
    cli = _module()
    with pytest.raises(cli.CliError, match="FORBIDDEN_SSO_ROLE_NAME"):
        cli._checked_sso_role_name(role_name)
    assert cli._checked_sso_role_name("AWSReadOnlyAccess") == "AWSReadOnlyAccess"


def test_live_passes_one_claimed_capability_to_provider_and_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tooling.platform_authority_gug365_upstream_inventory as upstream
    import tooling.platform_authority_gug376_live_executor as executor
    import tooling.platform_authority_gug376_live_provider as provider
    import tooling.platform_authority_gug376_live_request_materializer as materializer

    cli = _module()
    source = ("1" * 40, "2" * 40)

    request = {
        "request_digest": "sha256:" + "a" * 64,
        "sdk_runtime_root": str(request_data._sdk_root(tmp_path)),
        "profiles": {
            "authority": {"name": "synthetic-authority"},
            "identity_center": {"name": "synthetic-identity"},
        },
        "profile_expectations": {
            "authority": {
                "expected_principal_digest": "sha256:" + "b" * 64,
                "expected_sso_role_name_digest": "sha256:" + "c" * 64,
            },
            "identity_center": {
                "expected_principal_digest": "sha256:" + "d" * 64,
                "expected_sso_role_name_digest": "sha256:" + "e" * 64,
            },
        },
    }
    checkpoint = {"checkpoint_digest": "sha256:" + "f" * 64}
    runtime = {
        "authority_plan": {
            "expected_account_id": "111111111111",
            "authority_verification_digest": "sha256:" + "6" * 64,
        },
        "identity_center_plan": {
            "expected_account_id": "222222222222",
            "authority_verification_digest": "sha256:" + "7" * 64,
        },
    }
    initial = SimpleNamespace(
        request=request,
        owner_checkpoint=checkpoint,
        runtime_config=runtime,
    )
    monkeypatch.setattr(
        materializer,
        "read_materialized_live_request",
        lambda *args, **kwargs: initial,
    )

    capability = object()

    def claim_request(validated, *, private_root):
        assert validated is initial
        assert private_root == arguments.private_root
        return capability

    monkeypatch.setattr(
        materializer, "claim_materialized_live_request", claim_request
    )

    observed: dict[str, object] = {}

    def build_provider(**kwargs):
        assert kwargs["execution_capability"] is capability
        observed["provider"] = object()
        return observed["provider"]

    def execute_live(*args, **kwargs):
        assert args == (runtime, observed["provider"])
        assert kwargs["execution_capability"] is capability
        return {"record_type": "synthetic-run"}, {"record_type": "synthetic-handoff"}

    monkeypatch.setattr(provider, "build_live_provider_factory", build_provider)
    monkeypatch.setattr(executor, "execute_live", execute_live)
    arguments = argparse.Namespace(
        private_root=_root(tmp_path),
        request_file="gug376-live-request.json",
        approval_reference_digest="sha256:" + "0" * 64,
        expected_request_digest=request["request_digest"],
        expected_checkpoint_digest=checkpoint["checkpoint_digest"],
    )

    bundle = _synthetic_repository_bundle(
        cli,
        source_identity=source,
        modules={
            cli._LIVE_MODULES[0]: upstream,
            cli._LIVE_MODULES[1]: executor,
            cli._LIVE_MODULES[2]: provider,
            cli._LIVE_MODULES[3]: materializer,
        },
    )
    assert cli._live(arguments, repository_bundle=bundle) == {
        "run_record": {"record_type": "synthetic-run"},
        "public_handoff": {"record_type": "synthetic-handoff"},
    }
