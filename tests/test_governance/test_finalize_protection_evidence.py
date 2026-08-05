"""Synthetic-only tests for post-write evidence finalization."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "governance" / "finalize_protection_evidence.py"
SPEC = importlib.util.spec_from_file_location("finalize_protection_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
finalizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = finalizer
SPEC.loader.exec_module(finalizer)

ENDPOINT = (
    "PUT /repos/cesar-guzman/scanalyze-deployment-platform/branches/main/protection"
)
TARGET_BYTES = b'{"target":true}\n'
TARGET_SHA256 = hashlib.sha256(TARGET_BYTES).hexdigest()


def _write_artifact(directory: Path, name: str, content: bytes) -> Path:
    directory.chmod(0o700)
    path = directory / name
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _artifacts(tmp_path: Path) -> dict[str, Path]:
    return {
        "target": _write_artifact(tmp_path, "target.json", TARGET_BYTES),
        "response": _write_artifact(
            tmp_path,
            "write-response.raw.json",
            b'{"message":"synthetic 422"}\n',
        ),
        "receipt": _write_artifact(
            tmp_path,
            "write-receipt.sanitized.json",
            b'{"http_status":422}\n',
        ),
        "readback": _write_artifact(
            tmp_path,
            "readback.raw.json",
            b'{"state":"EXACT_BEFORE"}\n',
        ),
        "classification": _write_artifact(
            tmp_path,
            "classification.sanitized.txt",
            b"UNAMBIGUOUS_REJECTED_HTTP_422\n",
        ),
        "ledger": _write_artifact(
            tmp_path,
            "execution-ledger.jsonl",
            b'{"event":"write_rejected"}\n{"event":"readback_exact_before"}\n',
        ),
        "frozen_ledger": tmp_path / "execution-ledger.frozen.jsonl",
        "manifest": tmp_path / "post-write-manifest.json",
    }


def _metadata(**overrides: object) -> dict[str, object]:
    metadata: dict[str, object] = {
        "endpoint": ENDPOINT,
        "expected_target_sha256": TARGET_SHA256,
        "request_attempted": True,
        "http_status": 422,
        "transport_error_class": None,
        "retry_count": 0,
        "readback_class": "EXACT_BEFORE",
        "admin_state_changed": "NO",
    }
    metadata.update(overrides)
    return metadata


def _finalize(
    paths: dict[str, Path],
    *,
    response_path: Path | None | object = ...,
    transport_error_path: Path | None = None,
    **metadata_overrides: object,
):
    if response_path is ...:
        response_path = paths["response"]
    return finalizer.finalize_evidence(
        target_path=paths["target"],
        response_path=response_path,
        transport_error_path=transport_error_path,
        sanitized_receipt_path=paths["receipt"],
        readback_path=paths["readback"],
        classification_path=paths["classification"],
        ledger_path=paths["ledger"],
        frozen_ledger_output_path=paths["frozen_ledger"],
        manifest_output_path=paths["manifest"],
        **_metadata(**metadata_overrides),
    )


def _verify(paths: dict[str, Path], manifest_sha256: str, **overrides: object):
    return finalizer.verify_evidence(
        target_path=paths["target"],
        response_path=paths["response"],
        transport_error_path=None,
        sanitized_receipt_path=paths["receipt"],
        readback_path=paths["readback"],
        classification_path=paths["classification"],
        frozen_ledger_path=paths["frozen_ledger"],
        manifest_path=paths["manifest"],
        expected_manifest_sha256=manifest_sha256,
        **_metadata(**overrides),
    )


def test_manifest_binds_complete_chain_and_is_published_last(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    write_order: list[Path] = []
    original_write = finalizer._write_private_output

    def recording_write(path: Path, content: bytes) -> None:
        write_order.append(path)
        original_write(path, content)

    with patch.object(finalizer, "_write_private_output", recording_write):
        result = _finalize(paths)

    assert write_order == [paths["frozen_ledger"], paths["manifest"]]
    assert result.manifest["publication_order"] == [
        "frozen_ledger",
        "final_manifest",
    ]
    assert result.manifest["dependency_order"] == [
        "target",
        "raw_response",
        "sanitized_receipt",
        "raw_readback",
        "sanitized_classification",
        "frozen_ledger",
        "final_manifest",
    ]
    assert result.manifest["manifest_digest_binding"] == (
        "EXTERNAL_SHA256_REQUIRED"
    )
    assert result.manifest["finalizer_network_activity"] == "NONE"
    assert result.manifest["execution"] == {
        "endpoint": ENDPOINT,
        "expected_target_sha256": TARGET_SHA256,
        "request_attempted": True,
        "transport_outcome": {"kind": "http", "status_code": 422},
        "retry_count": 0,
        "readback_class": "EXACT_BEFORE",
        "admin_state_changed": "NO",
    }
    expected_paths = {
        "target": paths["target"],
        "raw_response": paths["response"],
        "sanitized_receipt": paths["receipt"],
        "raw_readback": paths["readback"],
        "sanitized_classification": paths["classification"],
        "frozen_ledger": paths["frozen_ledger"],
    }
    for role, path in expected_paths.items():
        content = path.read_bytes()
        assert result.manifest["artifacts"][role] == {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    manifest_bytes = paths["manifest"].read_bytes()
    assert json.loads(manifest_bytes) == result.manifest
    assert result.manifest_sha256 == hashlib.sha256(manifest_bytes).hexdigest()
    assert paths["frozen_ledger"].read_bytes() == paths["ledger"].read_bytes()
    assert stat.S_IMODE(paths["frozen_ledger"].stat().st_mode) == 0o600
    assert stat.S_IMODE(paths["manifest"].stat().st_mode) == 0o600
    assert _verify(paths, result.manifest_sha256) == result


def test_atomic_writer_reserves_temporary_output_with_o_excl(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    observed_flags: list[int] = []
    original_open = finalizer.os.open

    def recording_open(path: object, flags: int, mode: int = 0o777) -> int:
        if str(path).endswith(".tmp"):
            observed_flags.append(flags)
        return original_open(path, flags, mode)

    with patch.object(finalizer.os, "open", recording_open):
        _finalize(paths)

    assert observed_flags
    assert all(flags & os.O_EXCL for flags in observed_flags)


def test_transport_error_is_supported_without_claiming_http_status(
    tmp_path: Path,
) -> None:
    paths = _artifacts(tmp_path)
    transport_error = _write_artifact(
        tmp_path,
        "transport-error.raw.txt",
        b"synthetic timeout\n",
    )

    result = _finalize(
        paths,
        response_path=None,
        transport_error_path=transport_error,
        http_status=None,
        transport_error_class="TIMEOUT",
    )

    assert result.transport_artifact == "raw_transport_error"
    assert result.manifest["execution"]["transport_outcome"] == {
        "kind": "transport_error",
        "classification": "TIMEOUT",
    }
    assert "raw_response" not in result.manifest["artifacts"]


def test_not_attempted_transport_result_is_semantically_explicit(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    blocked = _write_artifact(
        tmp_path,
        "not-attempted.raw.txt",
        b"synthetic local pre-request stop\n",
    )

    result = _finalize(
        paths,
        response_path=None,
        transport_error_path=blocked,
        request_attempted=False,
        http_status=None,
        transport_error_class="NOT_ATTEMPTED",
    )

    assert result.manifest["execution"]["request_attempted"] is False


@pytest.mark.parametrize("readback_class", ["DIFFERENT", "UNAVAILABLE", "UNKNOWN"])
def test_uncertain_readback_records_unknown_admin_change(
    tmp_path: Path,
    readback_class: str,
) -> None:
    paths = _artifacts(tmp_path)

    result = _finalize(
        paths,
        readback_class=readback_class,
        admin_state_changed="UNKNOWN",
    )

    assert result.manifest["execution"]["admin_state_changed"] == "UNKNOWN"


def test_exact_target_can_record_observed_admin_change(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)

    result = _finalize(
        paths,
        http_status=200,
        readback_class="EXACT_TARGET",
        admin_state_changed="YES",
    )

    assert result.manifest["execution"]["admin_state_changed"] == "YES"


@pytest.mark.parametrize("include_both", [False, True])
def test_exactly_one_response_or_transport_error_is_required(
    tmp_path: Path,
    include_both: bool,
) -> None:
    paths = _artifacts(tmp_path)
    transport_error = None
    if include_both:
        transport_error = _write_artifact(
            tmp_path,
            "transport-error.raw.txt",
            b"synthetic timeout\n",
        )

    with pytest.raises(finalizer.EvidenceFinalizationError, match="exactly one"):
        _finalize(
            paths,
            response_path=paths["response"] if include_both else None,
            transport_error_path=transport_error,
        )

    assert not paths["frozen_ledger"].exists()
    assert not paths["manifest"].exists()


@pytest.mark.parametrize(
    "role",
    ["target", "response", "receipt", "readback", "classification", "ledger"],
)
def test_missing_artifact_blocks_before_outputs(
    tmp_path: Path,
    role: str,
) -> None:
    paths = _artifacts(tmp_path)
    paths[role].unlink()

    with pytest.raises(finalizer.EvidenceFinalizationError, match="unable to inspect"):
        _finalize(paths)

    assert not paths["frozen_ledger"].exists()
    assert not paths["manifest"].exists()


def test_empty_artifact_is_rejected(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    paths["classification"].write_bytes(b"")

    with pytest.raises(finalizer.EvidenceFinalizationError, match="must not be empty"):
        _finalize(paths)

    assert not paths["manifest"].exists()


@pytest.mark.parametrize("link_type", ["symlink", "hardlink"])
def test_linked_input_is_rejected(tmp_path: Path, link_type: str) -> None:
    paths = _artifacts(tmp_path)
    linked_target = tmp_path / "linked-target.json"
    if link_type == "symlink":
        linked_target.symlink_to(paths["target"])
        match = "symlink"
    else:
        os.link(paths["target"], linked_target)
        match = "hard-linked"
    paths["target"] = linked_target

    with pytest.raises(finalizer.EvidenceFinalizationError, match=match):
        _finalize(paths)

    assert not paths["manifest"].exists()


def test_symlinked_output_is_rejected_without_touching_target(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    unrelated = _write_artifact(tmp_path, "unrelated.json", b"unchanged\n")
    paths["manifest"].symlink_to(unrelated)

    with pytest.raises(finalizer.EvidenceFinalizationError, match="symlink"):
        _finalize(paths)

    assert unrelated.read_bytes() == b"unchanged\n"


def test_cross_parent_artifact_is_rejected(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    other = tmp_path.parent / f"{tmp_path.name}-other"
    other.mkdir(mode=0o700)
    paths["readback"] = _write_artifact(
        other,
        "readback.raw.json",
        b'{"state":"EXACT_BEFORE"}\n',
    )

    with pytest.raises(finalizer.EvidenceFinalizationError, match="same private"):
        _finalize(paths)


@pytest.mark.parametrize("mode", [0o755, 0o710, 0o600])
def test_run_directory_requires_exact_mode_0700(tmp_path: Path, mode: int) -> None:
    paths = _artifacts(tmp_path)
    tmp_path.chmod(mode)

    with pytest.raises(finalizer.EvidenceFinalizationError, match="mode 0700"):
        _finalize(paths)

    tmp_path.chmod(0o700)
    assert not paths["manifest"].exists()


def test_input_requires_exact_mode_0600(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    paths["receipt"].chmod(0o640)

    with pytest.raises(finalizer.EvidenceFinalizationError, match="mode 0600"):
        _finalize(paths)


@pytest.mark.parametrize("existing_role", ["frozen_ledger", "manifest"])
def test_outputs_are_exclusive(tmp_path: Path, existing_role: str) -> None:
    paths = _artifacts(tmp_path)
    paths[existing_role].write_bytes(b"existing\n")
    paths[existing_role].chmod(0o600)

    with pytest.raises(finalizer.EvidenceFinalizationError, match="overwrite"):
        _finalize(paths)

    assert paths[existing_role].read_bytes() == b"existing\n"
    if existing_role == "manifest":
        assert not paths["frozen_ledger"].exists()


@pytest.mark.parametrize("fail_on_write", [1, 2])
def test_partial_write_never_publishes_valid_manifest(
    tmp_path: Path,
    fail_on_write: int,
) -> None:
    paths = _artifacts(tmp_path)
    original_write = finalizer._write_private_output
    call_count = 0

    def injected_failure(path: Path, content: bytes) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == fail_on_write:
            raise finalizer.EvidenceFinalizationError("synthetic write failure")
        original_write(path, content)

    with patch.object(finalizer, "_write_private_output", injected_failure):
        with pytest.raises(finalizer.EvidenceFinalizationError, match="synthetic"):
            _finalize(paths)

    assert paths["frozen_ledger"].exists() is (fail_on_write > 1)
    assert not paths["manifest"].exists()


def test_ledger_append_after_freeze_blocks_before_final_manifest(
    tmp_path: Path,
) -> None:
    paths = _artifacts(tmp_path)
    original_write = finalizer._write_private_output

    def append_after_freeze(path: Path, content: bytes) -> None:
        original_write(path, content)
        if path == paths["frozen_ledger"]:
            paths["ledger"].write_bytes(
                paths["ledger"].read_bytes() + b'{"late":true}\n'
            )

    with patch.object(finalizer, "_write_private_output", append_after_freeze):
        with pytest.raises(finalizer.EvidenceFinalizationError, match="source ledger"):
            _finalize(paths)

    assert paths["frozen_ledger"].exists()
    assert not paths["manifest"].exists()


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"endpoint": "PUT /repos/example/other/branches/main/protection"}, "endpoint"),
        ({"expected_target_sha256": "0" * 63}, "target SHA-256"),
        ({"expected_target_sha256": "f" * 64}, "authorized target"),
        ({"request_attempted": 1}, "request_attempted"),
        ({"request_attempted": False}, "raw response"),
        ({"http_status": 99}, "HTTP status"),
        ({"http_status": 199}, "HTTP status"),
        ({"retry_count": 1}, "retry_count"),
        ({"retry_count": True}, "retry_count"),
        ({"retry_count": 0.0}, "retry_count"),
        ({"readback_class": "looks-good"}, "readback_class"),
        ({"readback_class": ["EXACT_BEFORE"]}, "readback_class"),
        ({"admin_state_changed": False}, "admin_state_changed"),
        ({"admin_state_changed": "YES"}, "EXACT_BEFORE"),
        ({"admin_state_changed": "UNKNOWN"}, "EXACT_BEFORE"),
        ({"readback_class": "UNKNOWN"}, "admin_state_changed=UNKNOWN"),
        ({"readback_class": "UNAVAILABLE"}, "admin_state_changed=UNKNOWN"),
        ({"readback_class": "DIFFERENT"}, "admin_state_changed=UNKNOWN"),
        (
            {"readback_class": "EXACT_TARGET", "admin_state_changed": "YES"},
            "HTTP rejection",
        ),
    ],
)
def test_invalid_execution_metadata_is_rejected(
    tmp_path: Path,
    overrides: dict[str, object],
    error: str,
) -> None:
    paths = _artifacts(tmp_path)

    with pytest.raises(finalizer.EvidenceFinalizationError, match=error):
        _finalize(paths, **overrides)

    assert not paths["manifest"].exists()


@pytest.mark.parametrize(
    "role",
    ["target", "response", "receipt", "readback", "classification", "frozen_ledger"],
)
def test_verification_rejects_artifact_tamper(tmp_path: Path, role: str) -> None:
    paths = _artifacts(tmp_path)
    result = _finalize(paths)
    paths[role].write_bytes(paths[role].read_bytes() + b"tampered\n")

    with pytest.raises(finalizer.EvidenceFinalizationError, match="does not match"):
        _verify(paths, result.manifest_sha256)


def test_live_ledger_changes_do_not_rewrite_frozen_evidence(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    result = _finalize(paths)
    frozen_before = paths["frozen_ledger"].read_bytes()
    paths["ledger"].write_bytes(paths["ledger"].read_bytes() + b'{"late":true}\n')

    assert paths["frozen_ledger"].read_bytes() == frozen_before
    assert _verify(paths, result.manifest_sha256) == result


def test_verification_rejects_artifact_omission(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    result = _finalize(paths)
    paths["receipt"].unlink()

    with pytest.raises(finalizer.EvidenceFinalizationError, match="unable to inspect"):
        _verify(paths, result.manifest_sha256)


def test_verification_requires_external_manifest_digest(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    _finalize(paths)

    with pytest.raises(finalizer.EvidenceFinalizationError, match="external manifest"):
        _verify(paths, "0" * 64)


def test_verification_rejects_dependency_order_tamper(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    _finalize(paths)
    manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    manifest["dependency_order"][0:2] = reversed(manifest["dependency_order"][0:2])
    manifest_bytes = finalizer._canonical_bytes(manifest)
    paths["manifest"].write_bytes(manifest_bytes)
    tampered_digest = hashlib.sha256(manifest_bytes).hexdigest()

    with pytest.raises(finalizer.EvidenceFinalizationError, match="does not match"):
        _verify(paths, tampered_digest)


def test_verification_rejects_noncanonical_manifest(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    result = _finalize(paths)
    noncanonical = json.dumps(result.manifest, indent=2).encode("utf-8") + b"\n"
    paths["manifest"].write_bytes(noncanonical)
    noncanonical_digest = hashlib.sha256(noncanonical).hexdigest()

    with pytest.raises(finalizer.EvidenceFinalizationError, match="not canonical"):
        _verify(paths, noncanonical_digest)


def test_operational_output_inside_repository_is_rejected(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    forbidden = REPO_ROOT / "tests" / ".gug289-final-manifest.json"
    paths["manifest"] = forbidden

    with pytest.raises(finalizer.EvidenceFinalizationError, match="outside the repository"):
        _finalize(paths)

    assert not forbidden.exists()


def _cli_common(paths: dict[str, Path]) -> list[str]:
    return [
        "--target",
        str(paths["target"]),
        "--raw-response",
        str(paths["response"]),
        "--sanitized-receipt",
        str(paths["receipt"]),
        "--raw-readback",
        str(paths["readback"]),
        "--sanitized-classification",
        str(paths["classification"]),
        "--endpoint",
        ENDPOINT,
        "--expected-target-sha256",
        TARGET_SHA256,
        "--request-attempted",
        "true",
        "--http-status",
        "422",
        "--retry-count",
        "0",
        "--readback-class",
        "EXACT_BEFORE",
        "--admin-state-changed",
        "NO",
    ]


def test_cli_finalizes_and_verifies_without_network_activity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = _artifacts(tmp_path)
    finalize_args = [
        "finalize",
        *_cli_common(paths),
        "--ledger",
        str(paths["ledger"]),
        "--frozen-ledger-output",
        str(paths["frozen_ledger"]),
        "--manifest-output",
        str(paths["manifest"]),
    ]

    assert finalizer.main(finalize_args) == 0
    finalize_output = capsys.readouterr().out
    assert "PASS: post-write evidence finalized with manifest last" in finalize_output
    assert "finalizer_network_activity=NONE" in finalize_output
    digest_line = next(
        line for line in finalize_output.splitlines() if line.startswith("final_manifest_sha256=")
    )
    manifest_digest = digest_line.split("=", 1)[1]
    verify_args = [
        "verify",
        *_cli_common(paths),
        "--frozen-ledger",
        str(paths["frozen_ledger"]),
        "--manifest",
        str(paths["manifest"]),
        "--expected-manifest-sha256",
        manifest_digest,
    ]

    assert finalizer.main(verify_args) == 0
    verify_output = capsys.readouterr().out
    assert "PASS: post-write evidence matches external manifest SHA-256" in verify_output
    assert "finalizer_network_activity=NONE" in verify_output
