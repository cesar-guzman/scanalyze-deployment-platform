"""Deterministic package and provenance tests for the GUG-215 broker."""

from __future__ import annotations

import base64
import copy
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

from tooling.platform_authority_change_set_retirement_package import (  # noqa: E402
    ARCHIVE_NAME,
    FIXED_ZIP_TIMESTAMP,
    HANDLER,
    PROVENANCE_PATHS,
    SOURCE_PATHS,
    RetirementPackageError,
    build_retirement_package,
    canonical_digest,
    validate_retirement_package_manifest,
    verify_clean_source_commit,
    write_retirement_package,
)


SOURCE_COMMIT = "1" * 40
RUNTIME_ARN = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
VERSION_BINDING = "sha256:" + "b" * 64


def _build(source_root: Path = ROOT, source_commit: str = SOURCE_COMMIT):
    return build_retirement_package(
        source_root=source_root,
        source_commit=source_commit,
        broker_runtime_version_arn=RUNTIME_ARN,
        broker_version_binding_sha256=VERSION_BINDING,
    )


def test_package_is_reproducible_and_manifest_binds_exact_code_sha() -> None:
    first = _build()
    second = _build()

    assert first.archive == second.archive
    assert first.manifest == second.manifest
    digest = sha256(first.archive).digest()
    assert first.manifest["archive_sha256"] == digest.hex()
    assert first.manifest["lambda_code_sha256"] == base64.b64encode(digest).decode()
    assert first.manifest["handler"] == HANDLER
    assert first.manifest["authorization_mode"] == (
        "SINGLE_OPERATOR_NONPROD_EXCEPTION"
    )
    assert first.manifest["two_human_status"] == "NOT_PROVEN"
    assert first.manifest["independent_approval_present"] is False
    assert first.manifest["deployment_authorized"] is False
    assert first.manifest["production_status"] == "NO-GO"


def test_archive_contains_only_closed_imports_with_fixed_metadata() -> None:
    built = _build()
    with ZipFile(BytesIO(built.archive)) as archive:
        assert archive.namelist() == [path.as_posix() for path in SOURCE_PATHS]
        for item in archive.infolist():
            assert item.date_time == FIXED_ZIP_TIMESTAMP
            assert item.compress_type == 0
            assert item.extra == b""
            assert item.comment == b""
            assert (item.external_attr >> 16) & 0o777 == 0o644
            entry = next(
                value
                for value in built.manifest["entries"]
                if value["path"] == item.filename
            )
            payload = archive.read(item.filename)
            assert entry["sha256"] == sha256(payload).hexdigest()
            assert entry["size_bytes"] == len(payload)


def test_archive_handler_imports_under_isolated_python(tmp_path: Path) -> None:
    built = _build()
    archive_path = tmp_path / ARCHIVE_NAME
    archive_path.write_bytes(built.archive)
    code = """
import importlib
import sys
sys.path.insert(0, sys.argv[1])
module_name, attribute = sys.argv[2].rsplit('.', 1)
module = importlib.import_module(module_name)
assert callable(getattr(module, attribute))
assert not any(name in sys.modules for name in ('boto3', 'botocore'))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", code, str(archive_path), HANDLER],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_manifest_schema_and_semantics_reject_tampering() -> None:
    from jsonschema import Draft202012Validator

    built = _build()
    schema = json.loads(
        (
            ROOT
            / "schemas/platform-authority-change-set-retirement-package-manifest.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(built.manifest)

    drifted = copy.deepcopy(built.manifest)
    drifted["lambda_code_sha256"] = "A" * 43 + "="
    with pytest.raises(
        RetirementPackageError, match="PACKAGE_MANIFEST_ARCHIVE_DIGEST_INVALID"
    ):
        validate_retirement_package_manifest(drifted)

    drifted = copy.deepcopy(built.manifest)
    drifted["two_human_status"] = "VERIFIED"
    with pytest.raises(
        RetirementPackageError, match="PACKAGE_MANIFEST_SCOPE_INVALID"
    ):
        validate_retirement_package_manifest(drifted)


def _reseal_manifest_for_archive(
    manifest: dict[str, object], archive: bytes
) -> dict[str, object]:
    resealed = copy.deepcopy(manifest)
    archive_digest = sha256(archive).digest()
    resealed["archive_sha256"] = archive_digest.hex()
    resealed["lambda_code_sha256"] = base64.b64encode(archive_digest).decode()
    resealed["archive_size_bytes"] = len(archive)
    resealed["manifest_digest"] = canonical_digest(
        {key: value for key, value in resealed.items() if key != "manifest_digest"}
    )
    return resealed


def _rewritten_archive(
    archive: bytes,
    *,
    add_member: bool = False,
    alter_metadata: bool = False,
    alter_payload: bool = False,
) -> bytes:
    output = BytesIO()
    with ZipFile(BytesIO(archive)) as source, ZipFile(output, mode="w") as target:
        for index, item in enumerate(source.infolist()):
            rewritten = copy.copy(item)
            payload = source.read(item.filename)
            if index == 0 and alter_metadata:
                rewritten.date_time = (2026, 8, 12, 0, 0, 0)
            if index == 0 and alter_payload:
                payload += b"\n# tampered\n"
            target.writestr(rewritten, payload)
        if add_member:
            target.writestr("tooling/unreviewed.py", b"UNREVIEWED = True\n")
    return output.getvalue()


def test_archive_validator_rejects_bytes_members_metadata_and_payload_tampering(
) -> None:
    built = _build()

    corrupted_bytes = built.archive[:-1] + bytes([built.archive[-1] ^ 0x01])
    with pytest.raises(
        RetirementPackageError, match="PACKAGE_ARCHIVE_DIGEST_MISMATCH"
    ):
        validate_retirement_package_manifest(
            built.manifest,
            archive=corrupted_bytes,
        )

    unexpected_member = _rewritten_archive(built.archive, add_member=True)
    with pytest.raises(
        RetirementPackageError, match="PACKAGE_ARCHIVE_MEMBERS_INVALID"
    ):
        validate_retirement_package_manifest(
            _reseal_manifest_for_archive(dict(built.manifest), unexpected_member),
            archive=unexpected_member,
        )

    metadata_drift = _rewritten_archive(built.archive, alter_metadata=True)
    with pytest.raises(
        RetirementPackageError, match="PACKAGE_ARCHIVE_METADATA_INVALID"
    ):
        validate_retirement_package_manifest(
            _reseal_manifest_for_archive(dict(built.manifest), metadata_drift),
            archive=metadata_drift,
        )

    payload_drift = _rewritten_archive(built.archive, alter_payload=True)
    with pytest.raises(
        RetirementPackageError,
        match="PACKAGE_ARCHIVE_MEMBER_DIGEST_MISMATCH",
    ):
        validate_retirement_package_manifest(
            _reseal_manifest_for_archive(dict(built.manifest), payload_drift),
            archive=payload_drift,
        )


def _committed_source(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    tracked = (*SOURCE_PATHS, *PROVENANCE_PATHS)
    for relative in tracked:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    commands = (
        ("init", "-q"),
        ("config", "user.email", "synthetic@example.invalid"),
        ("config", "user.name", "Synthetic Test"),
        ("add", "--", *[path.as_posix() for path in tracked]),
        ("commit", "-q", "-m", "synthetic package source"),
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


def test_writer_requires_clean_exact_commit_and_private_external_output(
    tmp_path: Path,
) -> None:
    source, commit = _committed_source(tmp_path)
    committed = verify_clean_source_commit(source_root=source, source_commit=commit)
    assert set(committed) == set(SOURCE_PATHS)

    private_parent = tmp_path / "private"
    private_parent.mkdir(mode=0o700)
    archive, manifest, evidence = write_retirement_package(
        source_root=source,
        source_commit=commit,
        broker_runtime_version_arn=RUNTIME_ARN,
        broker_version_binding_sha256=VERSION_BINDING,
        output_directory=private_parent / "package",
    )
    assert archive.stat().st_mode & 0o777 == 0o600
    assert manifest.stat().st_mode & 0o777 == 0o600
    assert archive.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(manifest.read_text(encoding="utf-8"))["manifest_digest"] == (
        evidence["manifest_digest"]
    )

    (source / SOURCE_PATHS[0]).write_bytes(b"drift\n")
    with pytest.raises(RetirementPackageError, match="SOURCE_TREE_DIRTY"):
        verify_clean_source_commit(source_root=source, source_commit=commit)
