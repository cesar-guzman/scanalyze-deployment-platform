"""Deterministic package and isolated import contracts for GUG-376."""

from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from zipfile import ZIP_STORED, ZipFile

from jsonschema import Draft202012Validator
import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_plan_permission_repair_package import (  # noqa: E402
    ARCHIVE_NAME,
    CLOUDFORMATION_TEMPLATE_PATHS,
    FIXED_ZIP_TIMESTAMP,
    FUNCTION_ARCHITECTURE,
    FUNCTION_RUNTIME,
    HANDLERS,
    PACKAGE_PATHS,
    PROVENANCE_TOOL_PATHS,
    RUNTIME_LOCK_PATH,
    RUNTIME_LOCK_TYPE,
    SOURCE_BUNDLE_DIGEST_PROFILE,
    SOURCE_PATHS,
    PlanPermissionRepairPackageError,
    build_plan_permission_repair_package,
    reviewed_cloudformation_template_digests,
    source_bundle_digest,
    validate_plan_permission_repair_package,
    verify_clean_source_commit,
    write_plan_permission_repair_package,
)


SOURCE_COMMIT = "1" * 40
EXPECTED_BOTO3_VERSION = "1.42.57"
EXPECTED_BOTOCORE_VERSION = "1.42.97"
SCHEMA = (
    ROOT
    / "schemas/"
    "platform-authority-plan-permission-repair-package-manifest.v1.schema.json"
)
AUTHORITY_TEMPLATE = (
    ROOT
    / "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
)


def _build(
    source_root: Path = ROOT,
    *,
    source_commit: str = SOURCE_COMMIT,
    boto3_version: str = EXPECTED_BOTO3_VERSION,
    botocore_version: str = EXPECTED_BOTOCORE_VERSION,
):
    return build_plan_permission_repair_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=boto3_version,
        expected_botocore_version=botocore_version,
    )


def test_package_is_byte_reproducible_and_binds_complete_archive() -> None:
    first = _build()
    second = _build()
    assert first.archive == second.archive
    assert first.manifest == second.manifest
    digest = sha256(first.archive).digest()
    assert first.manifest["archive_name"] == ARCHIVE_NAME
    assert first.manifest["archive_sha256"] == digest.hex()
    assert first.manifest["lambda_code_sha256"] == base64.b64encode(
        digest
    ).decode("ascii")
    assert first.manifest["source_commit"] == SOURCE_COMMIT
    assert first.manifest["handlers"] == dict(sorted(HANDLERS.items()))
    assert first.manifest["function_runtime"] == FUNCTION_RUNTIME
    assert first.manifest["function_architecture"] == FUNCTION_ARCHITECTURE
    assert first.manifest["production_status"] == "NO-GO"
    validate_plan_permission_repair_package(
        archive=first.archive,
        manifest=first.manifest,
    )


def test_source_bundle_digest_excludes_only_generated_runtime_lock() -> None:
    base = _build()
    different_lock = _build(
        source_commit="2" * 40,
        boto3_version="1.42.58",
        botocore_version="1.42.98",
    )
    assert (
        base.manifest["source_bundle_digest"]
        == different_lock.manifest["source_bundle_digest"]
    )
    assert base.archive != different_lock.archive
    assert (
        base.manifest["archive_sha256"]
        != different_lock.manifest["archive_sha256"]
    )
    assert (
        base.manifest["source_bundle_digest_profile"]
        == SOURCE_BUNDLE_DIGEST_PROFILE
    )

    sources = {path: (ROOT / path).read_bytes() for path in SOURCE_PATHS}
    changed = dict(sources)
    changed[SOURCE_PATHS[-1]] += b"\n# source drift\n"
    assert source_bundle_digest(sources) != source_bundle_digest(changed)


def test_runtime_lock_binds_source_bundle_commit_and_managed_sdk() -> None:
    built = _build()
    with ZipFile(BytesIO(built.archive)) as package:
        lock = json.loads(package.read(RUNTIME_LOCK_PATH.as_posix()))
    assert lock == {
        "record_type": RUNTIME_LOCK_TYPE,
        "schema_version": 1,
        "source_commit": SOURCE_COMMIT,
        "source_bundle_digest": built.manifest["source_bundle_digest"],
        "expected_boto3_version": EXPECTED_BOTO3_VERSION,
        "expected_botocore_version": EXPECTED_BOTOCORE_VERSION,
    }
    assert built.manifest["runtime_dependencies"] == {
        "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
        "runtime_lock_path": RUNTIME_LOCK_PATH.as_posix(),
        "expected_boto3_version": EXPECTED_BOTO3_VERSION,
        "expected_botocore_version": EXPECTED_BOTOCORE_VERSION,
    }


def test_package_contains_only_closed_allowlist_with_fixed_metadata() -> None:
    built = _build()
    with ZipFile(BytesIO(built.archive)) as package:
        assert package.comment == b""
        assert package.namelist() == [
            path.as_posix() for path in PACKAGE_PATHS
        ]
        for info in package.infolist():
            assert info.date_time == FIXED_ZIP_TIMESTAMP
            assert info.compress_type == ZIP_STORED
            assert info.create_system == 3
            assert info.flag_bits == 0
            assert info.extra == b""
            assert info.comment == b""
            assert info.external_attr == (0o100644 & 0xFFFF) << 16
            entry = next(
                item
                for item in built.manifest["entries"]
                if item["path"] == info.filename
            )
            payload = package.read(info)
            assert entry["sha256"] == sha256(payload).hexdigest()
            assert entry["size_bytes"] == len(payload)


def test_package_imports_handlers_directly_from_zip_without_repo_path(
    tmp_path: Path,
) -> None:
    built = _build()
    archive_path = tmp_path / ARCHIVE_NAME
    archive_path.write_bytes(built.archive)
    code = r"""
import sys
archive = sys.argv[1]
for item in tuple(sys.path):
    if item and 'scanalyze-deployment-platform' in item:
        sys.path.remove(item)
sys.path.insert(0, archive)
from tooling import platform_authority_plan_permission_repair_aws as runtime
assert runtime.__file__.startswith(archive)
assert callable(runtime.plan_handler)
assert callable(runtime.repair_handler)
assert callable(runtime.reconcile_handler)
assert 'boto3' not in sys.modules
assert 'botocore' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", code, str(archive_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": str(Path(sys.executable).parent)},
    )
    assert result.returncode == 0, result.stderr


def _resource_block(source: str, logical_id: str) -> str:
    marker = f"  {logical_id}:\n"
    assert source.count(marker) == 1
    tail = source.split(marker, 1)[1]
    return re.split(r"\n  (?=[A-Za-z0-9]+:\n)", tail, maxsplit=1)[0]


def test_package_handlers_runtime_and_architecture_match_cloudformation() -> None:
    source = AUTHORITY_TEMPLATE.read_text(encoding="utf-8")
    expected = {
        "PlanFunction": HANDLERS["plan"],
        "RepairFunction": HANDLERS["repair"],
        "ReconcileFunction": HANDLERS["reconcile"],
    }
    for logical_id, handler in expected.items():
        block = _resource_block(source, logical_id)
        assert f"Handler: {handler}" in block
        assert f"Runtime: {FUNCTION_RUNTIME}" in block
        assert f"Architectures: [{FUNCTION_ARCHITECTURE}]" in block
    observed_handlers = [
        line.strip().removeprefix("Handler: ")
        for line in source.splitlines()
        if line.strip().startswith("Handler: ")
    ]
    assert sorted(observed_handlers) == sorted(HANDLERS.values())


def test_manifest_schema_is_closed_and_rejects_substitution() -> None:
    built = _build()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    assert list(validator.iter_errors(built.manifest)) == []

    drifted = deepcopy(built.manifest)
    drifted["entries"][0]["path"] = "tooling/unreviewed.py"
    assert list(validator.iter_errors(drifted))
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="PACKAGE_ENTRY_SET_INVALID",
    ):
        validate_plan_permission_repair_package(
            archive=built.archive,
            manifest=drifted,
        )


def test_archive_validator_rejects_manifest_digest_and_lock_aliases() -> None:
    built = _build()
    digest_drift = deepcopy(built.manifest)
    digest_drift["archive_sha256"] = "0" * 64
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="PACKAGE_ARCHIVE_DIGEST_MISMATCH",
    ):
        validate_plan_permission_repair_package(
            archive=built.archive,
            manifest=digest_drift,
        )

    lock_alias = deepcopy(built.manifest)
    lock_alias["runtime_dependencies"]["runtime_lock_path"] = (
        "gug376_plan_permission_repair_runtime_lock-copy.json"
    )
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="PACKAGE_MANIFEST_INVALID",
    ):
        validate_plan_permission_repair_package(
            archive=built.archive,
            manifest=lock_alias,
        )


def test_builder_rejects_invalid_inputs_and_incomplete_source_set(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="SOURCE_COMMIT_INVALID",
    ):
        _build(source_commit="main")
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="SDK_VERSION_INVALID",
    ):
        _build(boto3_version="latest")

    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="PACKAGE_SOURCE_MISSING",
    ):
        _build(source_root=source)

    committed = {path: (ROOT / path).read_bytes() for path in SOURCE_PATHS}
    committed.pop(SOURCE_PATHS[-1])
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="COMMITTED_SOURCE_SET_INVALID",
    ):
        build_plan_permission_repair_package(
            source_root=ROOT,
            source_commit=SOURCE_COMMIT,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            committed_sources=committed,
        )


def _committed_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    tracked_paths = (*SOURCE_PATHS, *PROVENANCE_TOOL_PATHS)
    for relative in tracked_paths:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    commands: tuple[tuple[str, ...], ...] = (
        ("init", "-q"),
        ("config", "user.email", "synthetic@example.invalid"),
        ("config", "user.name", "Synthetic Test"),
        ("add", "--", *[path.as_posix() for path in tracked_paths]),
        ("commit", "-q", "-m", "synthetic reviewed source"),
    )
    for command in commands:
        subprocess.run(
            ["git", *command],
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
    return source, commit


def test_clean_commit_provenance_uses_git_objects_and_external_output(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    committed = verify_clean_source_commit(
        source_root=source,
        source_commit=commit,
    )
    assert set(committed) == set(SOURCE_PATHS)

    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT",
    ):
        write_plan_permission_repair_package(
            source_root=source,
            source_commit=commit,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            output_directory=source / "artifact",
        )

    output = tmp_path / "artifact"
    archive, manifest, evidence = write_plan_permission_repair_package(
        source_root=source,
        source_commit=commit,
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        output_directory=output,
    )
    assert archive.stat().st_mode & 0o777 == 0o600
    assert manifest.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_mode & 0o777 == 0o700
    assert json.loads(manifest.read_text(encoding="utf-8")) == evidence


def test_clean_commit_provenance_defeats_assume_unchanged_drift(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    drifted = SOURCE_PATHS[0]
    subprocess.run(
        [
            "git",
            "update-index",
            "--assume-unchanged",
            "--",
            drifted.as_posix(),
        ],
        cwd=source,
        check=True,
        timeout=30,
    )
    with (source / drifted).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="PACKAGE_SOURCE_COMMIT_DRIFT",
    ):
        verify_clean_source_commit(
            source_root=source,
            source_commit=commit,
        )


def test_reviewed_cloudformation_templates_bind_git_objects_and_drift(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    assert reviewed_cloudformation_template_digests(
        source_root=source,
        source_commit=commit,
    ) == {
        path.as_posix(): sha256((source / path).read_bytes()).hexdigest()
        for path in CLOUDFORMATION_TEMPLATE_PATHS
    }

    drifted = CLOUDFORMATION_TEMPLATE_PATHS[0]
    subprocess.run(
        [
            "git",
            "update-index",
            "--assume-unchanged",
            "--",
            drifted.as_posix(),
        ],
        cwd=source,
        check=True,
        timeout=30,
    )
    with (source / drifted).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(
        PlanPermissionRepairPackageError,
        match="CLOUDFORMATION_TEMPLATE_COMMIT_DRIFT",
    ):
        reviewed_cloudformation_template_digests(
            source_root=source,
            source_commit=commit,
        )
