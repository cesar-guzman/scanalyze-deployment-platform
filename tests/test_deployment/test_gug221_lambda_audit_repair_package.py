"""Deterministic package and isolated Lambda import tests for GUG-221."""

from __future__ import annotations

import base64
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZipFile

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_package import (  # noqa: E402
    ARCHIVE_NAME,
    FIXED_ZIP_TIMESTAMP,
    HANDLERS,
    PACKAGE_PATHS,
    PROVENANCE_TOOL_PATHS,
    SOURCE_PATHS,
    RepairPackageError,
    build_repair_package,
    verify_clean_source_commit,
    write_repair_package,
)


SOURCE_COMMIT = "1" * 40
EXPECTED_BOTO3_VERSION = "1.40.0"
EXPECTED_BOTOCORE_VERSION = "1.40.0"


def _build(source_root: Path = ROOT, source_commit: str = SOURCE_COMMIT):
    return build_repair_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
    )


def test_package_is_byte_reproducible_and_manifest_binds_exact_archive() -> None:
    first = _build()
    second = _build()
    assert first.archive == second.archive
    assert first.manifest == second.manifest
    digest = sha256(first.archive).digest()
    assert first.manifest["archive_name"] == ARCHIVE_NAME
    assert first.manifest["archive_sha256"] == digest.hex()
    assert first.manifest["lambda_code_sha256"] == base64.b64encode(digest).decode()
    assert first.manifest["source_commit"] == SOURCE_COMMIT
    assert first.manifest["handlers"] == dict(sorted(HANDLERS.items()))
    assert first.manifest["production_status"] == "NO-GO"


def test_package_contains_only_allowlisted_sources_with_fixed_metadata(tmp_path: Path) -> None:
    built = _build()
    archive_path = tmp_path / ARCHIVE_NAME
    archive_path.write_bytes(built.archive)
    with ZipFile(archive_path) as archive:
        assert archive.namelist() == [path.as_posix() for path in sorted(PACKAGE_PATHS)]
        for item in archive.infolist():
            assert item.date_time == FIXED_ZIP_TIMESTAMP
            assert item.compress_type == 0
            assert item.extra == b""
            assert item.comment == b""
            assert (item.external_attr >> 16) & 0o777 == 0o644
            manifest_entry = next(
                entry for entry in built.manifest["entries"] if entry["path"] == item.filename
            )
            payload = archive.read(item.filename)
            assert manifest_entry["sha256"] == sha256(payload).hexdigest()
            assert manifest_entry["size_bytes"] == len(payload)


def test_package_imports_and_renders_policies_outside_source_tree(tmp_path: Path) -> None:
    built = _build()
    archive_path = tmp_path / ARCHIVE_NAME
    archive_path.write_bytes(built.archive)
    extracted = tmp_path / "isolated"
    with ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    code = """
import json
import sys
sys.path[:] = [sys.argv[1], *[item for item in sys.path if item != sys.argv[2]]]
from tooling import platform_authority_lambda_audit_repair_broker_runtime as runtime
from tooling import platform_authority_lambda_audit_repair_phase_b_runtime as phase_b_runtime
from tooling import platform_authority_lambda_audit_repair_phase_b_topology as phase_b_topology
collector = runtime.load_bundled_collector_policy()
invoker = runtime.load_bundled_repair_invoker_policy()
assert '${' not in json.dumps(collector, sort_keys=True)
assert '${' not in json.dumps(invoker, sort_keys=True)
assert callable(runtime.plan_handler)
assert callable(runtime.repair_handler)
assert callable(runtime.reconcile_handler)
assert callable(phase_b_runtime.handler)
assert callable(phase_b_topology.collect_unsigned_broker_topology_evidence)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(extracted), str(ROOT)],
        cwd=extracted,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_package_rejects_invalid_commit_missing_source_and_symlink(tmp_path: Path) -> None:
    with pytest.raises(RepairPackageError, match="SOURCE_COMMIT_INVALID"):
        _build(source_commit="main")

    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(RepairPackageError, match="PACKAGE_SOURCE_MISSING"):
        _build(source_root=source)


def test_manifest_shape_is_strict_json_serializable() -> None:
    built = _build()
    decoded = json.loads(json.dumps(built.manifest))
    assert len(decoded["entries"]) == len(PACKAGE_PATHS) == 25
    assert decoded["runtime_dependencies"] == {
        "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
        "runtime_lock_path": "gug221_runtime_lock.json",
        "expected_boto3_version": EXPECTED_BOTO3_VERSION,
        "expected_botocore_version": EXPECTED_BOTOCORE_VERSION,
    }


def test_manifest_schema_rejects_path_substitution() -> None:
    from jsonschema import Draft202012Validator

    built = _build()
    schema = json.loads(
        (ROOT / "schemas/platform-authority-lambda-audit-repair-package-manifest.v1.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(built.manifest)
    drifted = json.loads(json.dumps(built.manifest))
    drifted["entries"][0]["path"] = "tooling/foreign.py"
    assert list(Draft202012Validator(schema).iter_errors(drifted))


def _committed_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    tracked_paths = (*SOURCE_PATHS, *PROVENANCE_TOOL_PATHS)
    for relative in tracked_paths:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    commands = (
        ("init", "-q"),
        ("config", "user.email", "synthetic@example.invalid"),
        ("config", "user.name", "Synthetic Test"),
        ("add", "--", *[path.as_posix() for path in tracked_paths]),
        ("commit", "-q", "-m", "synthetic source"),
    )
    for command in commands:
        subprocess.run(["git", *command], cwd=source, check=True, timeout=30)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    return source, commit


def test_cli_provenance_requires_tracked_commit_bytes_and_external_output(tmp_path: Path) -> None:
    source, commit = _committed_source(tmp_path)
    verify_clean_source_commit(source_root=source, source_commit=commit)
    with pytest.raises(RepairPackageError, match="OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT"):
        write_repair_package(
            source_root=source,
            source_commit=commit,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            output_directory=source / "artifact",
        )

    drifted = SOURCE_PATHS[0]
    subprocess.run(
        ["git", "update-index", "--assume-unchanged", "--", drifted.as_posix()],
        cwd=source,
        check=True,
        timeout=30,
    )
    with (source / drifted).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(RepairPackageError, match="PACKAGE_SOURCE_COMMIT_DRIFT"):
        verify_clean_source_commit(source_root=source, source_commit=commit)


def test_verified_package_uses_git_object_bytes_after_worktree_toctou(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    committed = verify_clean_source_commit(source_root=source, source_commit=commit)
    target = SOURCE_PATHS[0]
    reviewed_payload = committed[target]
    (source / target).write_bytes(b"unreviewed workspace replacement\n")

    built = build_repair_package(
        source_root=source,
        source_commit=commit,
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        committed_sources=committed,
    )
    with ZipFile(BytesIO(built.archive)) as archive:
        assert archive.read(target.as_posix()) == reviewed_payload


def test_cli_provenance_rejects_source_not_tracked_by_commit(tmp_path: Path) -> None:
    source, _ = _committed_source(tmp_path)
    removed = SOURCE_PATHS[0]
    subprocess.run(
        ["git", "rm", "--cached", "--", removed.as_posix()],
        cwd=source,
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "remove source"],
        cwd=source,
        check=True,
        timeout=30,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    with pytest.raises(RepairPackageError, match="PACKAGE_SOURCE_NOT_IN_COMMIT"):
        verify_clean_source_commit(source_root=source, source_commit=commit)
