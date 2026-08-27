"""Import-inert and sanitized parser tests for the GUG-390 CLI."""

from __future__ import annotations

import hashlib
import importlib.util
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/deployment/platform-authority-gug390-live-provider.py"
GUARDED_RUN = r"""
import builtins
import runpy
import socket
import sys

real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "boto3" or name.startswith("botocore"):
        raise AssertionError("provider import attempted")
    return real_import(name, *args, **kwargs)

def blocked_socket(*args, **kwargs):
    raise AssertionError("network attempted")

builtins.__import__ = guarded_import
socket.socket = blocked_socket
sys.argv = [sys.argv[1], *sys.argv[2:]]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
IMPORT_ONLY = r"""
import builtins
import importlib.util
import socket
import sys

real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "boto3" or name.startswith("botocore"):
        raise AssertionError("provider import attempted")
    return real_import(name, *args, **kwargs)

def blocked_socket(*args, **kwargs):
    raise AssertionError("network attempted")

builtins.__import__ = guarded_import
socket.socket = blocked_socket
spec = importlib.util.spec_from_file_location("gug390_cli", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print("IMPORT_OK")
"""
LOAD_REPOSITORY_MODULES = r"""
import builtins
import importlib.util
from pathlib import Path
import socket
import sys

real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "boto3" or name.startswith("botocore"):
        raise AssertionError("provider SDK import attempted")
    return real_import(name, *args, **kwargs)

def blocked_socket(*args, **kwargs):
    raise AssertionError("network attempted")

builtins.__import__ = guarded_import
socket.socket = blocked_socket
spec = importlib.util.spec_from_file_location("gug390_cli", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
reviewed_sources = {
    path.resolve(): path.read_bytes()
    for path in module._TOOLING_ROOT.glob("*.py")
}
loaded = module._load_repository_modules(reviewed_sources)
expected = tuple(module._REPOSITORY_MODULE_PATHS.values())
actual = tuple(Path(item.__file__).resolve() for item in loaded)
assert actual == expected, (actual, expected)
assert loaded[1].private_custody is loaded[2]
assert all(
    sys.modules[name] is selected
    for name, selected in zip(
        module._REPOSITORY_MODULE_PATHS, loaded, strict=True
    )
)
assert all(
    isinstance(item.__loader__, module._ReviewedSourceLoader)
    for name, item in sys.modules.items()
    if name == "tooling" or name.startswith("tooling.")
)
for raw_path in sys.path:
    candidate = Path.cwd() if raw_path == "" else Path(raw_path)
    try:
        candidate.resolve().relative_to(module.REPO_ROOT)
    except ValueError:
        pass
    else:
        raise AssertionError("repository import path retained")
print("REPOSITORY_IMPORTS_OK")
"""
UNSAFE_IMPORT_ENVIRONMENT = r"""
import os
import runpy
import sys

os.environ[sys.argv[2]] = "hostile-import-setting"
sys.argv = [
    sys.argv[1],
    "inventory",
    "--private-root",
    ".",
    "--request",
    "request.json",
]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
HOSTILE_TOOLING_PATH = r"""
import runpy
import sys

sys.path.insert(0, sys.argv[2])
sys.argv = [
    sys.argv[1],
    "inventory",
    "--private-root",
    ".",
    "--request",
    "request.json",
]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
PRELOADED_HOSTILE_TOOLING = r"""
import importlib
import runpy
import sys

sys.path.insert(0, sys.argv[2])
importlib.import_module("tooling")
sys.argv = [
    sys.argv[1],
    "inventory",
    "--private-root",
    ".",
    "--request",
    "request.json",
]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
FORGED_PRELOADED_TOOLING = r"""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import types

cli_path = Path(sys.argv[1]).resolve()
root = cli_path.parents[2]
tooling_root = root / "tooling"
spec = importlib.util.spec_from_file_location("gug390_cli", cli_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

paths = {
    "tooling": tooling_root / "__init__.py",
    **module._REPOSITORY_MODULE_PATHS,
}
for name, path in paths.items():
    forged = types.ModuleType(name)
    forged.__file__ = str(path)
    forged.__spec__ = importlib.machinery.ModuleSpec(
        name,
        loader=None,
        origin=str(path),
        is_package=name == "tooling",
    )
    forged.FORGED_MARKER = True
    if name == "tooling":
        forged.__path__ = [str(tooling_root)]
        forged.__spec__.submodule_search_locations = [str(tooling_root)]
    sys.modules[name] = forged

raise SystemExit(
    module.main(
        [
            "inventory",
            "--private-root",
            ".",
            "--request",
            "request.json",
        ]
    )
)
"""
FORGED_META_PATH = r"""
import builtins
import importlib.machinery
import importlib.util
from pathlib import Path
import socket
import sys

cli_path = Path(sys.argv[1]).resolve()
root = cli_path.parents[2]
tooling_root = root / "tooling"
targets = {
    "tooling": tooling_root / "__init__.py",
    "tooling.platform_authority_gug365_live_provider": (
        tooling_root / "platform_authority_gug365_live_provider.py"
    ),
    "tooling.platform_authority_gug390_live_executor": (
        tooling_root / "platform_authority_gug390_live_executor.py"
    ),
    "tooling.platform_authority_gug376_authority_inventory_collector": (
        tooling_root
        / "platform_authority_gug376_authority_inventory_collector.py"
    ),
}
calls = []

class ForgedLoader:
    def create_module(self, _spec):
        return None

    def exec_module(self, module):
        module.FORGED_MARKER = True

class ForgedFinder:
    def find_spec(self, fullname, _path=None, _target=None):
        path = targets.get(fullname)
        if path is None:
            return None
        calls.append(fullname)
        result = importlib.machinery.ModuleSpec(
            fullname,
            ForgedLoader(),
            origin=str(path),
            is_package=fullname == "tooling",
        )
        if fullname == "tooling":
            result.submodule_search_locations = [str(tooling_root)]
        return result

real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == "boto3" or name.startswith("botocore"):
        raise AssertionError("provider SDK import attempted")
    return real_import(name, *args, **kwargs)

def blocked_socket(*args, **kwargs):
    raise AssertionError("network attempted")

builtins.__import__ = guarded_import
socket.socket = blocked_socket
sys.meta_path.insert(0, ForgedFinder())
spec = importlib.util.spec_from_file_location("gug390_cli", cli_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
reviewed_sources = {
    path.resolve(): path.read_bytes()
    for path in module._TOOLING_ROOT.glob("*.py")
}
loaded = module._load_repository_modules(reviewed_sources)
assert calls == [], calls
assert all(not hasattr(item, "FORGED_MARKER") for item in loaded)
assert tuple(Path(item.__file__).resolve() for item in loaded) == tuple(
    module._REPOSITORY_MODULE_PATHS.values()
)
print("FORGED_META_PATH_REJECTED")
"""
SITE_SDK_DISCOVERY = r"""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys

cli_path = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("gug390_cli", cli_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert "boto3" not in sys.modules
module._prepare_repository_imports()
boto3_spec = importlib.machinery.PathFinder.find_spec("boto3", sys.path)
assert boto3_spec is not None
assert isinstance(boto3_spec.origin, str)
assert "boto3" not in sys.modules
print("SDK_DISCOVERY_AFTER_IMPORT_GATE_OK")
"""
IGNORED_ROOT_SDK_SHADOWS = r"""
import importlib.machinery
import importlib.util
from pathlib import Path
import sys

cli_path = Path(sys.argv[1]).resolve()
repository = Path(sys.argv[2]).resolve()
safe_sdk_root = Path(sys.argv[3]).resolve()
spec = importlib.util.spec_from_file_location("gug390_cli", cli_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.REPO_ROOT = repository
module._TOOLING_ROOT = repository / "tooling"
sys.path[:] = [str(repository), str(safe_sdk_root), *sys.path]
module._prepare_repository_imports()
for raw_path in sys.path:
    candidate = Path.cwd() if raw_path == "" else Path(raw_path)
    try:
        candidate.resolve().relative_to(repository)
    except ValueError:
        pass
    else:
        raise AssertionError("repository import path retained")
for name in ("boto3", "botocore"):
    selected = importlib.machinery.PathFinder.find_spec(name, sys.path)
    assert selected is not None
    assert isinstance(selected.origin, str)
    assert Path(selected.origin).resolve().is_relative_to(safe_sdk_root)
assert "boto3" not in sys.modules
assert "botocore" not in sys.modules
print("IGNORED_ROOT_SDK_SHADOWS_REMOVED")
"""


def _isolated(code: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-S", "-c", code, str(CLI), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )


def _isolated_with_site(
    code: str, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", code, str(CLI), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )


def test_cli_import_is_inert_without_boto_or_network() -> None:
    result = _isolated(IMPORT_ONLY)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "IMPORT_OK\n"
    assert result.stderr == ""


def test_repository_modules_resolve_only_from_repo_under_isolated_python() -> None:
    result = _isolated(LOAD_REPOSITORY_MODULES)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "REPOSITORY_IMPORTS_OK\n"
    assert result.stderr == ""


def test_reviewed_source_loader_ignores_valid_timestamp_bytecode_cache(
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    source = tmp_path / "reviewed_probe.py"
    malicious = 'VALUE = "PWNED!"\n'
    reviewed = 'VALUE = "SOURCE"\n'
    assert len(malicious.encode()) == len(reviewed.encode())
    source.write_text(malicious, encoding="utf-8")
    fixed_mtime = 1_700_000_000
    os.utime(source, (fixed_mtime, fixed_mtime))
    cache_path = Path(
        py_compile.compile(
            str(source),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        )
    )
    source.write_text(reviewed, encoding="utf-8")
    os.utime(source, (fixed_mtime, fixed_mtime))
    assert cache_path.is_file()

    loader = cli._ReviewedSourceLoader("reviewed_probe", str(source))  # noqa: SLF001
    spec = importlib.util.spec_from_file_location(
        "reviewed_probe",
        source,
        loader=loader,
    )
    assert spec is not None
    loaded = importlib.util.module_from_spec(spec)
    loader.exec_module(loaded)
    assert loaded.VALUE == "SOURCE"


def _git_in(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )


def _reviewed_source_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "reviewed-source-repository"
    entrypoint = (
        repository
        / "scripts/deployment/platform-authority-gug390-live-provider.py"
    )
    tooling = repository / "tooling"
    entrypoint.parent.mkdir(parents=True)
    tooling.mkdir(parents=True)
    entrypoint.write_text('VALUE = "ENTRYPOINT"\n', encoding="utf-8")
    (tooling / "__init__.py").write_text("", encoding="utf-8")
    (tooling / "reviewed.py").write_text('VALUE = "REVIEWED"\n', encoding="utf-8")
    _git_in(repository, "init", "-q")
    _git_in(repository, "config", "user.name", "GUG390 Test")
    _git_in(repository, "config", "user.email", "gug390@example.invalid")
    _git_in(repository, "add", "--", "scripts", "tooling")
    _git_in(repository, "commit", "-q", "-m", "reviewed source")
    commit = _git_in(repository, "rev-parse", "HEAD").stdout.strip()
    return repository.resolve(), commit


def _bind_temporary_repository(
    monkeypatch: pytest.MonkeyPatch, cli: Any, repository: Path
) -> None:
    monkeypatch.setattr(cli, "REPO_ROOT", repository)
    monkeypatch.setattr(cli, "_TOOLING_ROOT", repository / "tooling")


def test_reviewed_source_manifest_accepts_exact_git_blobs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    repository, commit = _reviewed_source_repository(tmp_path)
    _bind_temporary_repository(monkeypatch, cli, repository)

    manifest = cli._reviewed_repository_source_manifest(commit)  # noqa: SLF001
    assert set(manifest) == {
        (repository / "tooling/__init__.py").resolve(),
        (repository / "tooling/reviewed.py").resolve(),
    }
    assert manifest[(repository / "tooling/reviewed.py").resolve()] == (
        b'VALUE = "REVIEWED"\n'
    )


@pytest.mark.parametrize(
    "index_flag", ["--assume-unchanged", "--skip-worktree"]
)
def test_reviewed_source_manifest_ignores_index_hiding_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    index_flag: str,
) -> None:
    cli = _load_cli()
    repository, commit = _reviewed_source_repository(tmp_path)
    _bind_temporary_repository(monkeypatch, cli, repository)
    reviewed = repository / "tooling/reviewed.py"
    _git_in(repository, "update-index", index_flag, "tooling/reviewed.py")
    reviewed.write_text('VALUE = "HIDDEN DRIFT"\n', encoding="utf-8")
    assert _git_in(repository, "status", "--porcelain=v1").stdout == ""

    with pytest.raises(cli.CliError, match="SOURCE_BLOB_MISMATCH"):
        cli._reviewed_repository_source_manifest(commit)  # noqa: SLF001


def test_ignored_package_shadow_is_rejected_before_repository_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    repository, commit = _reviewed_source_repository(tmp_path)
    _bind_temporary_repository(monkeypatch, cli, repository)
    excluded = repository / ".git/info/exclude"
    excluded.write_text("tooling/reviewed/\n", encoding="utf-8")
    shadow = repository / "tooling/reviewed"
    shadow.mkdir()
    (shadow / "__init__.py").write_text(
        'raise AssertionError("IGNORED_PACKAGE_EXECUTED")\n',
        encoding="utf-8",
    )
    assert _git_in(repository, "status", "--porcelain=v1").stdout == ""

    with pytest.raises(cli.CliError, match="SOURCE_PYTHON_CANDIDATE_INVALID"):
        cli._reviewed_repository_source_manifest(commit)  # noqa: SLF001


def test_ignored_transitive_python_module_is_rejected_before_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    repository, commit = _reviewed_source_repository(tmp_path)
    _bind_temporary_repository(monkeypatch, cli, repository)
    excluded = repository / ".git/info/exclude"
    excluded.write_text("tooling/untracked_dependency.py\n", encoding="utf-8")
    (repository / "tooling/untracked_dependency.py").write_text(
        'raise AssertionError("UNTRACKED_MODULE_EXECUTED")\n',
        encoding="utf-8",
    )
    assert _git_in(repository, "status", "--porcelain=v1").stdout == ""

    with pytest.raises(cli.CliError, match="SOURCE_PYTHON_CANDIDATE_INVALID"):
        cli._reviewed_repository_source_manifest(commit)  # noqa: SLF001


def test_ignored_root_sdk_shadows_cannot_preempt_sanitized_import_path(
    tmp_path: Path,
) -> None:
    repository, _commit = _reviewed_source_repository(tmp_path)
    excluded = repository / ".git/info/exclude"
    excluded.write_text("boto3.py\nbotocore/\n", encoding="utf-8")
    (repository / "boto3.py").write_text(
        'raise AssertionError("IGNORED_BOTO3_EXECUTED")\n',
        encoding="utf-8",
    )
    hostile_botocore = repository / "botocore"
    hostile_botocore.mkdir()
    (hostile_botocore / "__init__.py").write_text(
        'raise AssertionError("IGNORED_BOTOCORE_EXECUTED")\n',
        encoding="utf-8",
    )
    assert _git_in(repository, "status", "--porcelain=v1").stdout == ""

    safe_sdk_root = tmp_path / "reviewed-sdk"
    for package in ("boto3", "botocore"):
        package_root = safe_sdk_root / package
        package_root.mkdir(parents=True)
        (package_root / "__init__.py").write_text(
            'ORIGIN = "REVIEWED_SDK"\n', encoding="utf-8"
        )

    result = _isolated(
        IGNORED_ROOT_SDK_SHADOWS,
        str(repository),
        str(safe_sdk_root),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "IGNORED_ROOT_SDK_SHADOWS_REMOVED\n"
    assert result.stderr == ""


@pytest.mark.parametrize("variable", ["PYTHONPATH", "PYTHONHOME"])
def test_import_environment_variables_fail_closed_before_repository_import(
    variable: str,
) -> None:
    result = _isolated(UNSAFE_IMPORT_ENVIRONMENT, variable)
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "IMPORT_ENVIRONMENT_UNSAFE",
        "production_status": "NO-GO",
        "status": "HUMAN_DECISION_REQUIRED",
    }


def test_hostile_tooling_sys_path_fails_before_shadow_package_import(
    tmp_path: Path,
) -> None:
    hostile_root = tmp_path / "hostile"
    hostile_package = hostile_root / "tooling"
    hostile_package.mkdir(parents=True)
    (hostile_package / "__init__.py").write_text(
        'raise AssertionError("HOSTILE_TOOLING_IMPORTED")\n',
        encoding="utf-8",
    )
    result = _isolated(HOSTILE_TOOLING_PATH, str(hostile_root))
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "IMPORT_PATH_PREEMPTED",
        "production_status": "NO-GO",
        "status": "HUMAN_DECISION_REQUIRED",
    }


def test_preloaded_hostile_tooling_package_fails_provenance_gate(
    tmp_path: Path,
) -> None:
    hostile_root = tmp_path / "preloaded"
    hostile_package = hostile_root / "tooling"
    hostile_package.mkdir(parents=True)
    (hostile_package / "__init__.py").write_text(
        'ORIGIN = "HOSTILE"\n',
        encoding="utf-8",
    )
    result = _isolated(PRELOADED_HOSTILE_TOOLING, str(hostile_root))
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "IMPORT_PRELOADED_UNSAFE",
        "production_status": "NO-GO",
        "status": "HUMAN_DECISION_REQUIRED",
    }


def test_forged_preloaded_tooling_metadata_cannot_bypass_bootstrap() -> None:
    result = _isolated(FORGED_PRELOADED_TOOLING)
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "IMPORT_PRELOADED_UNSAFE",
        "production_status": "NO-GO",
        "status": "HUMAN_DECISION_REQUIRED",
    }


def test_forged_meta_path_loader_never_runs_for_repository_modules() -> None:
    result = _isolated(FORGED_META_PATH)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "FORGED_META_PATH_REJECTED\n"
    assert result.stderr == ""


def test_isolated_runtime_keeps_sdk_discoverable_after_import_gate() -> None:
    result = _isolated_with_site(SITE_SDK_DISCOVERY)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "SDK_DISCOVERY_AFTER_IMPORT_GATE_OK\n"
    assert result.stderr == ""


def test_help_is_available_under_isolated_stdlib_only_python() -> None:
    result = _isolated(GUARDED_RUN, "--help")
    assert result.returncode == 0, result.stderr
    assert "{inventory,execute-phase,reconcile,certify}" in result.stdout
    assert "No command is selected by default" in result.stdout
    assert result.stderr == ""


def test_no_subcommand_fails_with_only_the_sanitized_stop_record() -> None:
    result = _isolated(GUARDED_RUN)
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "CLI_ARGUMENTS_INVALID",
        "production_status": "NO-GO",
        "status": "HUMAN_DECISION_REQUIRED",
    }


def _load_cli() -> Any:
    spec = importlib.util.spec_from_file_location("gug390_cli_contract", CLI)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def test_certify_parser_and_helper_bind_private_runs_and_activator_evidence(
    tmp_path: Path,
) -> None:
    cli = _load_cli()
    parsed = cli._parser().parse_args(  # noqa: SLF001
        [
            "certify",
            "--private-root",
            str(tmp_path),
            "--request",
            "certify-request.json",
        ]
    )
    assert parsed.command == "certify"
    assert parsed.private_root == tmp_path
    assert parsed.request == "certify-request.json"
    assert {
        "phase_run_files",
        "expected_phase_run_digests",
        "activator_checkpoint_file",
        "expected_activator_checkpoint_digest",
        "expected_final_snapshot_digests",
    }.issubset(cli._command_fields("certify"))  # noqa: SLF001

    phases = tuple(f"PHASE_{ordinal}" for ordinal in range(1, 9))
    record_names = [f"phase-record-{ordinal}.json" for ordinal in range(1, 9)]
    run_names = [f"phase-run-{ordinal}.json" for ordinal in range(1, 9)]
    bindings = [{"phase": phase} for phase in phases]
    activator_checkpoint = {"private": "activator-checkpoint"}
    snapshots = [
        {"capture_index": 1, "provider_backed": False},
        {"capture_index": 2, "provider_backed": False},
    ]
    private_files: dict[str, Any] = {
        **{
            name: {"phase": phase, "kind": "record"}
            for name, phase in zip(record_names, phases, strict=True)
        },
        **{
            name: {"phase": phase, "kind": "private-run"}
            for name, phase in zip(run_names, phases, strict=True)
        },
        "phase-bindings.json": {
            "record_type": "scanalyze.platform_authority.gug390_phase_bindings.v1",
            "plan_digest": _canonical_digest({"plan": "certify"}),
            "bindings": bindings,
            "binding_digest": _canonical_digest(bindings),
        },
        "snapshot-1.json": snapshots[0],
        "snapshot-2.json": snapshots[1],
        "activator-checkpoint.json": activator_checkpoint,
    }

    class Collector:
        def __init__(self) -> None:
            self.reads: list[str] = []

        def read_private_json(self, root: Path, name: str) -> Any:
            assert root == tmp_path
            self.reads.append(name)
            return private_files[name]

    class Executor:
        FORWARD_PHASES = phases

        def __init__(self) -> None:
            self.certify_arguments: dict[str, Any] | None = None

        @staticmethod
        def canonical_digest(value: Any) -> str:
            return _canonical_digest(value)

        def certify_bundle(self, **kwargs: Any) -> dict[str, Any]:
            self.certify_arguments = kwargs
            return {"status": "SYNTHETIC_CERTIFY_HELPER_CALLED"}

    plan_digest = _canonical_digest({"plan": "certify"})
    request = {
        "phase_record_files": record_names,
        "phase_run_files": run_names,
        "expected_phase_run_digests": [
            _canonical_digest({"phase_run": ordinal})
            for ordinal in range(1, 9)
        ],
        "phase_bindings_file": "phase-bindings.json",
        "inventory_snapshot_files": ["snapshot-1.json", "snapshot-2.json"],
        "activator_checkpoint_file": "activator-checkpoint.json",
        "expected_activator_checkpoint_digest": _canonical_digest(
            activator_checkpoint
        ),
        "expected_bundle_digest": _canonical_digest({"bundle": "expected"}),
        "expected_initial_bundle_absence_digest": _canonical_digest(
            {"initial": "absent"}
        ),
        "expected_final_facts_digest": _canonical_digest({"facts": "final"}),
        "expected_final_snapshot_digests": [
            _canonical_digest({"snapshot": 1}),
            _canonical_digest({"snapshot": 2}),
        ],
        "source_commit_sha": "1" * 40,
        "source_tree_sha": "2" * 40,
        "plan_digest": plan_digest,
    }
    plan = {"plan_digest": plan_digest}
    collector = Collector()
    executor = Executor()
    owner_checkpoint_digest = _canonical_digest({"owner": "certify"})
    live_request_digest = _canonical_digest({"request": "certify"})

    public = cli._certify(  # noqa: SLF001
        request,
        root=tmp_path,
        plan=plan,
        now=cli.datetime(2035, 1, 2, 3, 4, 5, tzinfo=cli.UTC),
        executor=executor,
        collector=collector,
        owner_checkpoint_digest=owner_checkpoint_digest,
        live_request_digest=live_request_digest,
    )

    assert public == {"status": "SYNTHETIC_CERTIFY_HELPER_CALLED"}
    assert collector.reads == [
        *record_names,
        *run_names,
        "phase-bindings.json",
        "snapshot-1.json",
        "snapshot-2.json",
        "activator-checkpoint.json",
    ]
    assert executor.certify_arguments is not None
    assert executor.certify_arguments["phase_runs"] == [
        private_files[name] for name in run_names
    ]
    assert (
        executor.certify_arguments["expected_phase_run_digests"]
        == request["expected_phase_run_digests"]
    )
    assert (
        executor.certify_arguments["activator_checkpoint"]
        == activator_checkpoint
    )
    assert (
        executor.certify_arguments["expected_activator_checkpoint_digest"]
        == request["expected_activator_checkpoint_digest"]
    )
    assert executor.certify_arguments["execution_mode"] == "SYNTHETIC"
    assert executor.certify_arguments["owner_checkpoint_digest"] == (
        owner_checkpoint_digest
    )
    assert executor.certify_arguments["live_request_digest"] == live_request_digest


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _main_request(
    *,
    cli: Any,
    executor: Any,
    command: str,
    plan: dict[str, Any],
    now: datetime,
    source_commit: str,
    source_tree: str,
) -> dict[str, Any]:
    digest = executor.canonical_digest
    phase = "NONE" if command == "certify" else "POLICY_FACTORY"
    profile = {
        "name": "gug390-synthetic-direct-sso",
        "source": "DIRECT_SSO",
        "chain_depth": 0,
    }
    request: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug390_live_request.v1",
        "schema_version": 1,
        "issue": "GUG-390",
        "command": command,
        "opt_in": cli._OPT_IN[command],  # noqa: SLF001
        "source_commit_sha": source_commit,
        "source_tree_sha": source_tree,
        "plan_file": "plan.json",
        "plan_digest": plan["plan_digest"],
        "expected_account_id": plan["target"]["authority_account_id"],
        "region": "us-east-1",
        "phase": phase,
        "not_before": _stamp(now - timedelta(minutes=1)),
        "expires_at": _stamp(now + timedelta(minutes=5)),
        "host_digest": cli._host_digest(executor),  # noqa: SLF001
        "output_file": f"{command}-output.json",
    }
    if command == "inventory":
        request.update(
            {
                "profile": profile,
                "expected_principal_digest": digest(
                    {"principal": "synthetic-direct-sso"}
                ),
                "expected_sso_role_name_digest": digest(
                    {"role": "synthetic-direct-sso"}
                ),
                "snapshot_files": ["inventory-1.json", "inventory-2.json"],
                "expected_inventory_facts_digest": digest(
                    {"facts": "inventory"}
                ),
                "authorized_before_state_digest": digest(
                    {"state": "authorized-before"}
                ),
            }
        )
    elif command == "execute-phase":
        request.update(
            {
                "profile": profile,
                "expected_principal_digest": digest(
                    {"principal": "synthetic-direct-sso"}
                ),
                "expected_sso_role_name_digest": digest(
                    {"role": "synthetic-direct-sso"}
                ),
                "ledger_id": digest({"ledger": "gug390-policy-factory"}),
                "execution_authorization_file": "authorization.json",
                "executor_authority_evidence_file": "authority.json",
                "authority_evaluation_at": _stamp(now),
                "expected_initial_bundle_absence_digest": digest(
                    {"bundle": "absent"}
                ),
                "predecessor_record_file": None,
                "predecessor_binding_file": None,
                "inventory_snapshot_files": [
                    "inventory-1.json",
                    "inventory-2.json",
                ],
                "expected_inventory_snapshot_digests": [
                    digest({"snapshot": 1}),
                    digest({"snapshot": 2}),
                ],
                "expected_inventory_facts_digest": digest(
                    {"facts": "inventory"}
                ),
                "claim_nonce_digest": digest({"nonce": "phase"}),
                "activator_checkpoint_file": None,
                "expected_activator_checkpoint_digest": None,
            }
        )
    elif command == "reconcile":
        request.update(
            {
                "profile": profile,
                "expected_principal_digest": digest(
                    {"principal": "synthetic-direct-sso"}
                ),
                "expected_sso_role_name_digest": digest(
                    {"role": "synthetic-direct-sso"}
                ),
                "ledger_id": digest({"ledger": "gug390-policy-factory"}),
                "expected_ambiguous_ledger_digest": digest(
                    {"ledger": "ambiguous-policy-factory"}
                ),
                "expected_ambiguous_operation_digest": digest(
                    {"operation": "ambiguous-create-policy"}
                ),
                "expected_reconciliation_readback_contract_digest": digest(
                    {"contract": "exact-ambiguous-operation-readback"}
                ),
                "expected_session_identifier_digest": digest(
                    {"session": "synthetic-direct-sso"}
                ),
                "expected_effect_state_digest": digest({"state": "effect"}),
                "expected_no_effect_state_digest": digest(
                    {"state": "no-effect"}
                ),
                "expected_reconciliation_binding_digest": digest(
                    {"binding": "ambiguous-operation-expectations"}
                ),
            }
        )
    else:
        request.update(
            {
                "phase_record_files": [
                    f"phase-record-{index}.json" for index in range(1, 9)
                ],
                "phase_run_files": [
                    f"phase-run-{index}.json" for index in range(1, 9)
                ],
                "expected_phase_run_digests": [
                    digest({"phase_run": index}) for index in range(1, 9)
                ],
                "phase_bindings_file": "phase-bindings.json",
                "inventory_snapshot_files": [
                    "inventory-final-1.json",
                    "inventory-final-2.json",
                ],
                "expected_final_snapshot_digests": [
                    digest({"snapshot": "final-1"}),
                    digest({"snapshot": "final-2"}),
                ],
                "activator_checkpoint_file": "activator-checkpoint.json",
                "expected_activator_checkpoint_digest": digest(
                    {"activator": "checkpoint"}
                ),
                "expected_bundle_digest": digest({"bundle": "complete"}),
                "expected_initial_bundle_absence_digest": digest(
                    {"bundle": "absent"}
                ),
                "expected_final_facts_digest": digest({"facts": "final"}),
            }
        )
    profile_digest = digest(profile) if command != "certify" else digest(
        {"mode": "NO_AWS"}
    )
    binding_digest = digest(request)
    checkpoint_body = {
        "record_type": "scanalyze.platform_authority.gug390_owner_checkpoint.v1",
        "issue": "GUG-390",
        "command": command,
        "phase": phase,
        "source_commit_sha": source_commit,
        "source_tree_sha": source_tree,
        "plan_digest": plan["plan_digest"],
        "account_digest": digest(plan["target"]["authority_account_id"]),
        "region": "us-east-1",
        "profile_binding_digest": profile_digest,
        "host_digest": request["host_digest"],
        "not_before": request["not_before"],
        "expires_at": request["expires_at"],
        "request_binding_digest": binding_digest,
        "mutation_authorized": command == "execute-phase",
    }
    if command != "certify":
        checkpoint_body.update(
            {
                "expected_principal_digest": request[
                    "expected_principal_digest"
                ],
                "expected_sso_role_name_digest": request[
                    "expected_sso_role_name_digest"
                ],
            }
        )
    request["owner_checkpoint"] = {
        **checkpoint_body,
        "checkpoint_digest": digest(checkpoint_body),
    }
    request["request_digest"] = digest(request)
    assert set(request) == cli._command_fields(command)  # noqa: SLF001
    return request


@pytest.mark.parametrize(
    "command", ["inventory", "execute-phase", "reconcile", "certify"]
)
def test_all_cli_subcommands_complete_local_custody_flow_without_aws(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    from tooling import platform_authority_gug365_live_provider as provider_module
    from tooling import platform_authority_gug390_live_executor as executor
    from tooling import (
        platform_authority_gug376_authority_inventory_collector as collector,
    )

    cli = _load_cli()
    monkeypatch.setattr(cli, "_prepare_repository_imports", lambda: None)
    monkeypatch.setattr(
        cli,
        "_load_repository_modules",
        lambda _reviewed: (provider_module, executor, collector),
    )
    monkeypatch.setattr(
        cli, "_reviewed_repository_source_manifest", lambda _commit: {}
    )
    raw_plan = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    source_commit, source_tree = "1" * 40, "2" * 40
    now = datetime.now(UTC).replace(microsecond=0)
    request = _main_request(
        cli=cli,
        executor=executor,
        command=command,
        plan=raw_plan,
        now=now,
        source_commit=source_commit,
        source_tree=source_tree,
    )
    private_root = tmp_path / command
    private_root.mkdir(mode=0o700)
    private_root.chmod(0o700)
    collector.write_private_json(private_root, "plan.json", raw_plan)
    collector.write_private_json(private_root, "request.json", request)

    monkeypatch.setattr(cli, "_source_state", lambda: (source_commit, source_tree))

    def aws_forbidden() -> Any:
        raise AssertionError("AWS SDK load attempted by local CLI test")

    monkeypatch.setattr(provider_module, "_load_boto3", aws_forbidden)
    seen: list[str] = []
    public = {"command": command, "status": "LOCAL_E2E_OK"}
    private = {"command": command, "status": "PRIVATE_LOCAL_E2E_OK"}
    provider_configs: list[Any] = []

    class LocalProvider:
        def __init__(self) -> None:
            self.finalized = False

        def finalize(self) -> dict[str, Any]:
            assert self.finalized is False
            self.finalized = True
            return {"status": "LOCAL_PROVIDER_FINALIZED"}

    def open_local_provider(config: Any) -> LocalProvider:
        provider_configs.append(config)
        return LocalProvider()

    monkeypatch.setattr(
        provider_module, "build_live_provider", open_local_provider
    )

    class LocalStore:
        def __init__(self, root: Path) -> None:
            assert root == private_root

        def read(self, ledger_id: str) -> dict[str, Any]:
            assert ledger_id == request.get("ledger_id")
            record = {
                "phase": request["phase"],
                "status": (
                    "AMBIGUOUS" if command == "reconcile" else "PREPARED"
                ),
                "before_state_digest": executor.canonical_digest(
                    {"state": "authorized-before"}
                ),
            }
            if command == "reconcile":
                record.update(
                    {
                        "plan_digest": request["plan_digest"],
                        "account_id": request["expected_account_id"],
                        "region": "us-east-1",
                        "ledger_digest": request[
                            "expected_ambiguous_ledger_digest"
                        ],
                        "authority_session_identifier_digest": request[
                            "expected_session_identifier_digest"
                        ],
                        "claim": {
                            "execution_context": executor._execution_context(  # noqa: SLF001
                                owner_checkpoint_digest=executor.canonical_digest(
                                    {"owner": "phase-context-A"}
                                ),
                                live_request_digest=executor.canonical_digest(
                                    {"request": "phase-context-A"}
                                ),
                                activator_checkpoint_digest=None,
                            )
                        },
                    }
                )
            return record

    monkeypatch.setattr(
        executor.phase_ledger, "DurablePhaseLedgerStore", LocalStore
    )

    def capture_inventory_once(**kwargs: Any) -> dict[str, Any]:
        index = kwargs["capture_index"]
        return {
            "capture_index": index,
            "provider_backed": False,
            "facts_digest": request["expected_inventory_facts_digest"],
            "snapshot_digest": executor.canonical_digest(
                {"inventory_snapshot": index}
            ),
        }

    def classify_inventory(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {
            "classification": "ABSENT_READY",
            "stable": True,
            "provider_backed": False,
        }

    def inventory_manifest(**_kwargs: Any) -> dict[str, Any]:
        seen.append("inventory")
        return public

    def execute_phase(**_kwargs: Any) -> dict[str, Any]:
        seen.append("execute-phase")
        return private

    def reconcile_phase(**_kwargs: Any) -> dict[str, Any]:
        seen.append("reconcile")
        return private

    def phase_manifest(**_kwargs: Any) -> dict[str, Any]:
        return public

    def certify_bundle(**_kwargs: Any) -> dict[str, Any]:
        seen.append("certify")
        return public

    monkeypatch.setattr(executor, "capture_inventory_once", capture_inventory_once)
    monkeypatch.setattr(executor, "classify_stable_inventory", classify_inventory)
    monkeypatch.setattr(executor, "public_inventory_manifest", inventory_manifest)
    monkeypatch.setattr(executor, "execute_one_phase", execute_phase)
    monkeypatch.setattr(executor, "reconcile_ambiguous", reconcile_phase)
    monkeypatch.setattr(executor, "public_phase_manifest", phase_manifest)
    monkeypatch.setattr(executor, "certify_bundle", certify_bundle)

    if command == "execute-phase":
        for index, name in enumerate(request["inventory_snapshot_files"], 1):
            collector.write_private_json(
                private_root,
                name,
                {
                    "capture_index": index,
                    "provider_backed": False,
                    "snapshot_digest": request[
                        "expected_inventory_snapshot_digests"
                    ][index - 1],
                },
            )
        collector.write_private_json(
            private_root, request["execution_authorization_file"], {"local": True}
        )
        collector.write_private_json(
            private_root,
            request["executor_authority_evidence_file"],
            {"local": True},
        )
    elif command == "certify":
        for index, name in enumerate(request["phase_record_files"], 1):
            collector.write_private_json(
                private_root, name, {"phase_record": index}
            )
        for index, name in enumerate(request["phase_run_files"], 1):
            collector.write_private_json(
                private_root,
                name,
                {
                    "phase_run": index,
                    "run_digest": request["expected_phase_run_digests"][
                        index - 1
                    ],
                },
            )
        bindings: list[dict[str, Any]] = []
        collector.write_private_json(
            private_root,
            request["phase_bindings_file"],
            {
                "record_type": (
                    "scanalyze.platform_authority.gug390_phase_bindings.v1"
                ),
                "plan_digest": request["plan_digest"],
                "bindings": bindings,
                "binding_digest": executor.canonical_digest(bindings),
            },
        )
        for index, name in enumerate(request["inventory_snapshot_files"], 1):
            collector.write_private_json(
                private_root,
                name,
                {"capture_index": index, "provider_backed": False},
            )
        collector.write_private_json(
            private_root,
            request["activator_checkpoint_file"],
            {"checkpoint": "local"},
        )

    result = cli.main(
        [
            command,
            "--private-root",
            str(private_root),
            "--request",
            "request.json",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0, captured.err
    assert captured.err == ""
    assert json.loads(captured.out) == public
    assert seen == [command]
    expected_provider_count = {"inventory": 2, "execute-phase": 1, "reconcile": 1, "certify": 0}[command]
    assert len(provider_configs) == expected_provider_count
    for config in provider_configs:
        assert config.expected_principal_digest == request["expected_principal_digest"]
        assert (
            config.expected_sso_role_name_digest
            == request["expected_sso_role_name_digest"]
        )
    expected_private = public if command in {"inventory", "certify"} else private
    assert collector.read_private_json(
        private_root, f"{command}-output.json"
    ) == expected_private


def test_expired_terminal_execute_recovery_never_builds_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tooling import platform_authority_gug390_live_executor as executor

    cli = _load_cli()
    ledger_id = _canonical_digest({"ledger": "terminal"})
    owner_digest = _canonical_digest({"owner": "terminal"})
    request_digest = _canonical_digest({"request": "terminal"})
    plan_digest = _canonical_digest({"plan": "terminal"})
    request = {
        "ledger_id": ledger_id,
        "phase": "POLICY_FACTORY",
        "plan_digest": plan_digest,
        "authority_evaluation_at": "2035-01-02T03:04:05Z",
        "expected_initial_bundle_absence_digest": _canonical_digest(
            {"state": "absent"}
        ),
        "claim_nonce_digest": _canonical_digest({"claim": "terminal"}),
        "activator_checkpoint_file": None,
        "expected_activator_checkpoint_digest": None,
        "source_commit_sha": "1" * 40,
        "source_tree_sha": "2" * 40,
        "not_before": "2035-01-02T03:04:05Z",
        "expires_at": "2035-01-02T03:14:05Z",
        "expected_account_id": "042360977644",
    }

    class Store:
        def __init__(self, root: Path) -> None:
            assert root == tmp_path

        def read(self, selected: str) -> dict[str, Any]:
            assert selected == ledger_id
            return {"phase": "POLICY_FACTORY", "status": "CONSUMED"}

    monkeypatch.setattr(executor.phase_ledger, "DurablePhaseLedgerStore", Store)
    private = {"record_type": executor.PRIVATE_RUN_TYPE, "recovered": True}
    calls: list[dict[str, Any]] = []

    def execute_one_phase(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        assert kwargs["provider"] is None
        assert kwargs["owner_checkpoint_digest"] == owner_digest
        assert kwargs["live_request_digest"] == request_digest
        return private

    monkeypatch.setattr(executor, "execute_one_phase", execute_one_phase)
    monkeypatch.setattr(
        executor,
        "public_phase_manifest",
        lambda **_kwargs: {"status": "RECOVERED_NO_PROVIDER"},
    )

    class ProviderModule:
        @staticmethod
        def build_live_provider(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("provider factory called during terminal recovery")

    class Collector:
        @staticmethod
        def read_private_json(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unneeded private dependency read")

    recovered, public = cli._execute_phase(  # noqa: SLF001
        request,
        {"name": "unused"},
        root=tmp_path,
        plan={"plan_digest": plan_digest},
        now=datetime(2036, 1, 1, tzinfo=UTC),
        executor=executor,
        provider_module=ProviderModule,
        collector=Collector,
        owner_checkpoint_digest=owner_digest,
        live_request_digest=request_digest,
    )
    assert recovered == private
    assert public == {"status": "RECOVERED_NO_PROVIDER"}
    assert len(calls) == 1


def test_expired_nonterminal_execute_stops_before_provider_factory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tooling import platform_authority_gug390_live_executor as executor

    cli = _load_cli()
    ledger_id = _canonical_digest({"ledger": "prepared"})

    class Store:
        def __init__(self, _root: Path) -> None:
            pass

        def read(self, _selected: str) -> dict[str, Any]:
            return {"phase": "POLICY_FACTORY", "status": "PREPARED"}

    monkeypatch.setattr(executor.phase_ledger, "DurablePhaseLedgerStore", Store)

    class ProviderModule:
        @staticmethod
        def build_live_provider(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("provider factory called for expired request")

    request = {
        "ledger_id": ledger_id,
        "phase": "POLICY_FACTORY",
        "activator_checkpoint_file": None,
        "expected_activator_checkpoint_digest": None,
        "not_before": "2035-01-02T03:04:05Z",
        "expires_at": "2035-01-02T03:14:05Z",
    }
    with pytest.raises(cli.CliError, match="REQUEST_WINDOW_INVALID"):
        cli._execute_phase(  # noqa: SLF001
            request,
            {"name": "unused"},
            root=tmp_path,
            plan={},
            now=datetime(2036, 1, 1, tzinfo=UTC),
            executor=executor,
            provider_module=ProviderModule,
            collector=object(),
            owner_checkpoint_digest=_canonical_digest({"owner": "prepared"}),
            live_request_digest=_canonical_digest({"request": "prepared"}),
        )


def test_reconcile_in_flight_recovers_locally_without_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tooling import platform_authority_gug390_live_executor as executor

    cli = _load_cli()
    plan = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    now = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)
    request = _main_request(
        cli=cli,
        executor=executor,
        command="reconcile",
        plan=plan,
        now=now,
        source_commit="1" * 40,
        source_tree="2" * 40,
    )
    owner_digest = request["owner_checkpoint"]["checkpoint_digest"]
    live_request_digest = request["request_digest"]
    record = {
        "phase": request["phase"],
        "status": "IN_FLIGHT",
        "plan_digest": request["plan_digest"],
        "account_id": request["expected_account_id"],
        "region": "us-east-1",
        "ledger_digest": request["expected_ambiguous_ledger_digest"],
        "authority_session_identifier_digest": request[
            "expected_session_identifier_digest"
        ],
        "claim": {
            "execution_context": executor._execution_context(  # noqa: SLF001
                owner_checkpoint_digest=owner_digest,
                live_request_digest=live_request_digest,
                activator_checkpoint_digest=None,
            )
        },
    }

    class Store:
        def __init__(self, root: Path) -> None:
            assert root == tmp_path

        def read(self, ledger_id: str) -> dict[str, Any]:
            assert ledger_id == request["ledger_id"]
            return record

    monkeypatch.setattr(executor.phase_ledger, "DurablePhaseLedgerStore", Store)

    def recover(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["ledger_id"] == request["ledger_id"]
        record["status"] = "AMBIGUOUS"
        record["ledger_digest"] = executor.canonical_digest(
            {"recovered": "ambiguous"}
        )
        return record

    monkeypatch.setattr(
        executor.phase_ledger, "recover_persisted_in_flight", recover
    )

    class ProviderModule:
        @staticmethod
        def build_live_provider(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("provider factory called for IN_FLIGHT recovery")

    with pytest.raises(
        cli.CliError,
        match="IN_FLIGHT_RECOVERED_NEW_AMBIGUOUS_BINDING_REQUIRED",
    ):
        cli._reconcile(  # noqa: SLF001
            request,
            request["profile"],
            root=tmp_path,
            plan=plan,
            now=now,
            executor=executor,
            provider_module=ProviderModule,
            owner_checkpoint_digest=owner_digest,
            live_request_digest=live_request_digest,
        )
    assert record["status"] == "AMBIGUOUS"
    assert record["ledger_digest"] != request[
        "expected_ambiguous_ledger_digest"
    ]


def test_reconcile_ledger_digest_mismatch_rejects_before_provider(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tooling import platform_authority_gug390_live_executor as executor

    cli = _load_cli()
    plan = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    now = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)
    request = _main_request(
        cli=cli,
        executor=executor,
        command="reconcile",
        plan=plan,
        now=now,
        source_commit="1" * 40,
        source_tree="2" * 40,
    )
    owner_digest = request["owner_checkpoint"]["checkpoint_digest"]
    live_request_digest = request["request_digest"]

    class Store:
        def __init__(self, _root: Path) -> None:
            pass

        def read(self, _ledger_id: str) -> dict[str, Any]:
            return {
                "phase": request["phase"],
                "status": "AMBIGUOUS",
                "plan_digest": request["plan_digest"],
                "account_id": request["expected_account_id"],
                "region": "us-east-1",
                "ledger_digest": executor.canonical_digest(
                    {"substitution": "ledger"}
                ),
                "authority_session_identifier_digest": request[
                    "expected_session_identifier_digest"
                ],
                "claim": {
                    "execution_context": executor._execution_context(  # noqa: SLF001
                        owner_checkpoint_digest=owner_digest,
                        live_request_digest=live_request_digest,
                        activator_checkpoint_digest=None,
                    )
                },
            }

    monkeypatch.setattr(executor.phase_ledger, "DurablePhaseLedgerStore", Store)

    class ProviderModule:
        @staticmethod
        def build_live_provider(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("provider factory called before ledger binding")

    with pytest.raises(cli.CliError, match="AMBIGUOUS_LEDGER_DIGEST_MISMATCH"):
        cli._reconcile(  # noqa: SLF001
            request,
            request["profile"],
            root=tmp_path,
            plan=plan,
            now=now,
            executor=executor,
            provider_module=ProviderModule,
            owner_checkpoint_digest=owner_digest,
            live_request_digest=live_request_digest,
        )


def test_reconcile_guarded_clock_rejects_request_expiry_before_cas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tooling import platform_authority_gug365_live_provider as provider_module
    from tooling import platform_authority_gug390_live_executor as executor

    cli = _load_cli()
    plan = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    now = datetime(2035, 1, 2, 3, 4, 5, tzinfo=UTC)
    request = _main_request(
        cli=cli,
        executor=executor,
        command="reconcile",
        plan=plan,
        now=now,
        source_commit="1" * 40,
        source_tree="2" * 40,
    )
    owner_digest = request["owner_checkpoint"]["checkpoint_digest"]
    live_request_digest = request["request_digest"]
    context = executor._execution_context(  # noqa: SLF001
        owner_checkpoint_digest=owner_digest,
        live_request_digest=live_request_digest,
        activator_checkpoint_digest=None,
    )

    class Store:
        def __init__(self, _root: Path) -> None:
            pass

        def read(self, _ledger_id: str) -> dict[str, Any]:
            return {
                "phase": request["phase"],
                "status": "AMBIGUOUS",
                "plan_digest": request["plan_digest"],
                "account_id": request["expected_account_id"],
                "region": "us-east-1",
                "ledger_digest": request["expected_ambiguous_ledger_digest"],
                "authority_session_identifier_digest": request[
                    "expected_session_identifier_digest"
                ],
                "claim": {"execution_context": context},
            }

    monkeypatch.setattr(executor.phase_ledger, "DurablePhaseLedgerStore", Store)

    class Provider:
        def finalize(self) -> None:
            raise AssertionError("expired reconciliation finalized")

    monkeypatch.setattr(
        provider_module,
        "build_live_provider",
        lambda _config: Provider(),
    )
    cas_reached = False

    def reconcile_ambiguous(**kwargs: Any) -> dict[str, Any]:
        nonlocal cas_reached
        kwargs["clock"]()
        cas_reached = True
        return {"status": "UNEXPECTED"}

    monkeypatch.setattr(executor, "reconcile_ambiguous", reconcile_ambiguous)
    real_datetime = datetime

    class ExpiredDateTime(real_datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            expired = real_datetime.fromisoformat(
                request["expires_at"].replace("Z", "+00:00")
            )
            return expired if tz is not None else expired.replace(tzinfo=None)

    monkeypatch.setattr(cli, "datetime", ExpiredDateTime)

    with pytest.raises(cli.CliError, match="REQUEST_WINDOW_INVALID"):
        cli._reconcile(  # noqa: SLF001
            request,
            request["profile"],
            root=tmp_path,
            plan=plan,
            now=now,
            executor=executor,
            provider_module=provider_module,
            owner_checkpoint_digest=owner_digest,
            live_request_digest=live_request_digest,
        )
    assert cas_reached is False


def test_existing_output_is_create_only_and_blocks_provider_factory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from tooling import platform_authority_gug365_live_provider as provider_module
    from tooling import platform_authority_gug390_live_executor as executor
    from tooling import (
        platform_authority_gug376_authority_inventory_collector as collector,
    )

    cli = _load_cli()
    monkeypatch.setattr(cli, "_prepare_repository_imports", lambda: None)
    monkeypatch.setattr(
        cli,
        "_load_repository_modules",
        lambda _reviewed: (provider_module, executor, collector),
    )
    monkeypatch.setattr(
        cli, "_reviewed_repository_source_manifest", lambda _commit: {}
    )
    plan = json.loads(
        (
            ROOT
            / "fixtures/valid/"
            "platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    now = datetime.now(UTC).replace(microsecond=0)
    request = _main_request(
        cli=cli,
        executor=executor,
        command="inventory",
        plan=plan,
        now=now,
        source_commit="1" * 40,
        source_tree="2" * 40,
    )
    private_root = tmp_path / "create-only"
    private_root.mkdir(mode=0o700)
    private_root.chmod(0o700)
    collector.write_private_json(private_root, "plan.json", plan)
    collector.write_private_json(private_root, "request.json", request)
    existing = {"existing": "must-not-be-overwritten"}
    collector.write_private_json(private_root, request["output_file"], existing)
    monkeypatch.setattr(cli, "_source_state", lambda: ("1" * 40, "2" * 40))

    def provider_forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("provider factory called before create-only gate")

    monkeypatch.setattr(provider_module, "build_live_provider", provider_forbidden)
    result = cli.main(
        [
            "inventory",
            "--private-root",
            str(private_root),
            "--request",
            "request.json",
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert json.loads(captured.err)["status"] == "HUMAN_DECISION_REQUIRED"
    assert collector.read_private_json(
        private_root, request["output_file"]
    ) == existing
