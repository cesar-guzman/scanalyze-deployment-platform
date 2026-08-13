"""Deterministic package tests for the dedicated GUG-365 ledger factory."""

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

from tooling.platform_authority_retirement_ledger_factory_package import (  # noqa: E402
    ARCHIVE_NAME,
    FIXED_ZIP_TIMESTAMP,
    HANDLER,
    PROVENANCE_PATHS,
    SOURCE_PATHS,
    LedgerFactoryPackageError,
    build_ledger_factory_package,
    validate_ledger_factory_package_manifest,
    verify_clean_source_commit,
)


SOURCE_COMMIT = "1" * 40
RUNTIME_ARN = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64


def build():
    return build_ledger_factory_package(
        source_root=ROOT,
        source_commit=SOURCE_COMMIT,
        runtime_version_arn=RUNTIME_ARN,
    )


def test_package_is_reproducible_closed_and_environment_empty() -> None:
    first = build()
    second = build()
    assert first.archive == second.archive
    assert first.manifest == second.manifest
    digest = sha256(first.archive).digest()
    assert first.manifest["archive_sha256"] == digest.hex()
    assert first.manifest["lambda_code_sha256"] == base64.b64encode(digest).decode()
    assert first.manifest["handler"] == HANDLER
    assert first.manifest["environment"] == {}
    assert first.manifest["deployment_authorized"] is False
    assert first.manifest["production_status"] == "NO-GO"


def test_archive_members_metadata_and_handler_import_are_exact(tmp_path: Path) -> None:
    built = build()
    with ZipFile(BytesIO(built.archive)) as archive:
        assert archive.namelist() == [path.as_posix() for path in SOURCE_PATHS]
        for info in archive.infolist():
            assert info.date_time == FIXED_ZIP_TIMESTAMP
            assert info.compress_type == 0
            assert info.extra == b""
            assert info.comment == b""
            assert (info.external_attr >> 16) & 0o777 == 0o644
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


def test_manifest_and_archive_tampering_fail_closed() -> None:
    built = build()
    changed = dict(built.manifest)
    changed["environment"] = {"UNREVIEWED": "value"}
    with pytest.raises(LedgerFactoryPackageError, match="PACKAGE_MANIFEST_SCOPE_INVALID"):
        validate_ledger_factory_package_manifest(changed)
    corrupted = built.archive[:-1] + bytes([built.archive[-1] ^ 1])
    with pytest.raises(LedgerFactoryPackageError, match="PACKAGE_ARCHIVE_DIGEST_MISMATCH"):
        validate_ledger_factory_package_manifest(built.manifest, archive=corrupted)


def test_package_has_no_gug215_broker_sources() -> None:
    names = {path.as_posix() for path in SOURCE_PATHS}
    assert names == {
        "tooling/__init__.py",
        "tooling/platform_authority_retirement_ledger_factory.py",
    }
    assert all("identity_context_pep" not in name for name in names)
    assert all("change_set_retirement_broker" not in name for name in names)


def _synthetic_commit(tmp_path: Path) -> tuple[Path, str]:
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
        ("commit", "-q", "-m", "synthetic factory package"),
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


def test_clean_commit_verification_rejects_dirty_source(tmp_path: Path) -> None:
    source, commit = _synthetic_commit(tmp_path)
    committed = verify_clean_source_commit(source_root=source, source_commit=commit)
    assert set(committed) == set(SOURCE_PATHS)
    (source / SOURCE_PATHS[-1]).write_text("drift\n", encoding="utf-8")
    with pytest.raises(LedgerFactoryPackageError, match="SOURCE_TREE_DIRTY"):
        verify_clean_source_commit(source_root=source, source_commit=commit)
