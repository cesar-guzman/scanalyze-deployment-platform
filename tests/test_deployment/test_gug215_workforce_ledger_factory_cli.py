"""Offline workforce factory CLI: real source gate, synthetic source I/O only."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest

from tooling import platform_authority_retirement_ledger_factory_package as package


ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / "scripts/deployment/platform-authority-retirement-entrypoint-service-role.py"
COMMIT = "a" * 40
RUNTIME_ARN = "arn:aws:lambda:us-east-1::runtime:" + "b" * 64


@pytest.fixture
def cli():
    name = "gug215_workforce_factory_cli"
    spec = importlib.util.spec_from_file_location(name, CLI_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def source_io(monkeypatch):
    state = {"change": "none", "calls": []}
    sources = {
        path: b"" if path == Path("tooling/__init__.py") else b"# Public synthetic test source.\n"
        for path in package.SOURCE_PATHS + package.WORKFORCE_PROVENANCE_PATHS
    }

    def git(_root, *args, text=True):
        state["calls"].append(args)
        if args == ("rev-parse", "HEAD"):
            return "c" * 40 if state["change"] == "wrong_head" else COMMIT
        if args[0] == "status":
            calls = sum(c[0] == "status" for c in state["calls"])
            dirty = state["change"] == "dirty" or (
                state["change"] == "dirty_after" and calls > 1
            )
            return " M public.py" if dirty else ""
        assert args[0] == "show" and text is False
        return sources[Path(args[1].split(":", 1)[1])]

    def read_source(_root, path):
        if state["change"] == "cli_drift" and path == CLI_PATH.relative_to(ROOT):
            return b"# Changed command.\n"
        return sources[path]

    monkeypatch.setattr(package, "_git", git)
    monkeypatch.setattr(package, "_read_source", read_source)
    return state


@pytest.fixture
def private_root(tmp_path):
    path = tmp_path.resolve() / "owner-evidence"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def args(root):
    return ["workforce-package", "--private-root", str(root),
            "--source-commit", COMMIT, "--runtime-version-arn", RUNTIME_ARN]


def test_package_checks_clean_source_and_reads_back_create_only_private_outputs(
    cli, source_io, private_root, capsys
):
    assert cli.main(args(private_root)) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "WORKFORCE_PACKAGE_BUILT_AND_READ_BACK_OFFLINE"
    assert output["aws_calls"] == output["aws_mutations"] == 0
    assert output["deployment_authorized"] is False
    assert output["production_status"] == "NO-GO"
    assert output["source_ci_status"] == "PENDING_CONNECTED_REVALIDATION"
    archive = private_root / package.WORKFORCE_ARCHIVE_NAME
    manifest = private_root / package.WORKFORCE_MANIFEST_NAME
    assert sorted(path.name for path in private_root.iterdir()) == sorted([archive.name, manifest.name])
    for path in (archive, manifest):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_nlink == 1
    document = json.loads(manifest.read_bytes())
    package.validate_workforce_ledger_factory_package_manifest(document, archive=archive.read_bytes())
    assert document["manifest_digest"] == output["manifest_digest"]
    assert document["handler"].endswith(".handler_workforce")
    assert document["source_snapshot_status"] == "CAPTURED_BYTES_NOT_AUTHENTICATED"
    assert document["function_version_arn"] is None
    assert [entry["path"] for entry in document["provenance"]] == [
        str(path) for path in package.WORKFORCE_PROVENANCE_PATHS
    ]
    with zipfile.ZipFile(archive) as container:
        assert container.namelist() == [str(path) for path in package.SOURCE_PATHS]
    assert source_io["calls"].count(("rev-parse", "HEAD")) == 2
    assert len([c for c in source_io["calls"] if c[0] == "show"]) == 6


@pytest.mark.parametrize("change", ["wrong_head", "dirty", "dirty_after", "cli_drift"])
def test_source_gate_failure_publishes_nothing(cli, source_io, private_root, capsys, change):
    source_io["change"] = change
    assert cli.main(args(private_root)) == 2
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["status"] == "BLOCKED"
    assert list(private_root.iterdir()) == []


@pytest.mark.parametrize("filename", [package.WORKFORCE_ARCHIVE_NAME, package.WORKFORCE_MANIFEST_NAME])
@pytest.mark.parametrize("existing", ["regular", "symlink"])
def test_existing_or_ambiguous_output_is_never_replaced(
    cli, source_io, private_root, capsys, filename, existing
):
    target = private_root / filename
    if existing == "regular":
        target.write_bytes(b"previous-public-fixture")
        target.chmod(0o600)
    else:
        target.symlink_to(private_root / "missing")
    assert cli.main(args(private_root)) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "BLOCKED"
    assert source_io["calls"] == []
    assert len(list(private_root.iterdir())) == 1
    if existing == "regular":
        assert target.read_bytes() == b"previous-public-fixture"
    else:
        assert target.is_symlink()


@pytest.mark.parametrize("point", ["archive", "manifest", "archive_final"])
def test_readback_corruption_never_reports_success_or_retries(
    cli, source_io, private_root, capsys, monkeypatch, point
):
    read = cli._read_private_bytes
    reads = []

    def corrupt(root, requested, *, maximum_bytes):
        result = read(root, requested, maximum_bytes=maximum_bytes)
        reads.append(requested.name)
        if ((point == "archive" and len(reads) == 1)
                or (point == "manifest" and len(reads) == 2)
                or (point == "archive_final" and len(reads) == 3)):
            return result[:-1] + bytes([result[-1] ^ 1])
        return result

    monkeypatch.setattr(cli, "_read_private_bytes", corrupt)
    assert cli.main(args(private_root)) == 2
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["reason"] == "WORKFORCE_FACTORY_OUTPUT_READBACK_MISMATCH"
    assert (private_root / package.WORKFORCE_MANIFEST_NAME).exists() is (point != "archive")
    calls_before = list(source_io["calls"])
    assert cli.main(args(private_root)) == 2
    assert "ALREADY_EXISTS" in json.loads(capsys.readouterr().err)["reason"]
    assert source_io["calls"] == calls_before


@pytest.mark.parametrize("change", ["public_mode", "symlink_root"])
def test_unprotected_roots_rejected_before_source_io(
    cli, source_io, private_root, capsys, change
):
    requested = private_root
    if change == "public_mode":
        private_root.chmod(0o755)
    else:
        requested = private_root.parent / "linked-root"
        requested.symlink_to(private_root, target_is_directory=True)
    assert cli.main(args(requested)) == 2
    assert json.loads(capsys.readouterr().err)["status"] == "BLOCKED"
    assert source_io["calls"] == []
    assert list(private_root.iterdir()) == []


@pytest.mark.parametrize("change", ["contents", "replace", "permissions"])
def test_manifest_change_during_final_archive_readback_is_detected(
    cli, source_io, private_root, capsys, monkeypatch, change
):
    read = cli._read_private_bytes
    calls = []

    def mutate_after_read(root, requested, *, maximum_bytes):
        result = read(root, requested, maximum_bytes=maximum_bytes)
        calls.append(requested.name)
        if len(calls) == 3:
            manifest = private_root / package.WORKFORCE_MANIFEST_NAME
            if change == "contents":
                before = manifest.read_bytes()
                manifest.write_bytes(b"!" + before[1:])
            elif change == "replace":
                replacement = private_root / "replacement-public-fixture"
                replacement.write_bytes(manifest.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(manifest)
            else:
                manifest.chmod(0o644)
        return result

    monkeypatch.setattr(cli, "_read_private_bytes", mutate_after_read)
    assert cli.main(args(private_root)) == 2
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["reason"] == "WORKFORCE_FACTORY_OUTPUT_CHANGED"


@pytest.mark.parametrize("extra", [["--apply"], ["--profile", "public-fixture"], ["--sign"], ["--publish"]])
def test_no_cloud_flags_accepted(cli, source_io, private_root, capsys, extra):
    assert cli.main(args(private_root) + extra) == 2
    output = capsys.readouterr()
    assert not output.out
    assert json.loads(output.err)["reason"] == "CLI_ARGUMENTS_INVALID"
    assert "public-fixture" not in output.err
    assert source_io["calls"] == []


def test_abbreviated_workforce_options_rejected(cli, source_io, private_root, capsys):
    command = args(private_root)
    command[command.index("--source-commit")] = "--source-com"
    assert cli.main(command) == 2
    assert json.loads(capsys.readouterr().err)["reason"] == "CLI_ARGUMENTS_INVALID"
    assert source_io["calls"] == []


def test_workforce_help_works_in_isolated_stdlib_process():
    result = subprocess.run([sys.executable, "-I", "-S", "-B", str(CLI_PATH),
                             "workforce-package", "--help"], cwd=ROOT,
                            capture_output=True, text=True, check=False, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "offline" in result.stdout
    assert "--source-commit" in result.stdout
    assert "--apply" not in result.stdout
    assert not result.stderr
