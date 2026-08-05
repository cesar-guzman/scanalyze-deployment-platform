#!/usr/bin/env python3
"""Finalize and verify GitHub branch-protection post-write evidence offline.

All inputs and outputs must be single-link, mode-0600 files in one
current-user-owned mode-0700 directory outside the repository. The finalizer
performs no network activity and publishes the final manifest last.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_ENDPOINT = (
    "PUT /repos/cesar-guzman/scanalyze-deployment-platform/branches/main/protection"
)
READBACK_CLASSES = frozenset(
    {"EXACT_BEFORE", "EXACT_TARGET", "DIFFERENT", "UNAVAILABLE", "UNKNOWN"}
)
ADMIN_STATE_CHANGE_RESULTS = frozenset({"YES", "NO", "UNKNOWN"})
TRANSPORT_ERROR_CLASS_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceFinalizationError(ValueError):
    """Raised when a post-write evidence chain cannot be proven complete."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    """Stable bytes and filesystem identity for one private artifact."""

    content: bytes
    sha256: str
    size_bytes: int
    device: int
    inode: int


@dataclass(frozen=True)
class FinalizationResult:
    """Final manifest metadata safe to print without raw artifact contents."""

    manifest: dict[str, Any]
    manifest_sha256: str
    transport_artifact: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise EvidenceFinalizationError(f"duplicate JSON key: {key!r}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise EvidenceFinalizationError(f"non-finite JSON value is prohibited: {value}")


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceFinalizationError(
                f"symlinked operational path is prohibited: {path}"
            )


def _ensure_outside_repository(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    repository = REPO_ROOT.resolve()
    for candidate in (absolute, *absolute.parents):
        try:
            if candidate.samefile(repository):
                raise EvidenceFinalizationError(
                    f"operational evidence must stay outside the repository: {path}"
                )
        except OSError:
            continue
    try:
        absolute.resolve(strict=False).relative_to(repository)
    except ValueError:
        return
    raise EvidenceFinalizationError(
        f"operational evidence must stay outside the repository: {path}"
    )


def _validate_private_parent(path: Path) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise EvidenceFinalizationError(
            f"unable to inspect operational directory {path}: {exc}"
        ) from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceFinalizationError(f"operational parent is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise EvidenceFinalizationError(
            f"operational directory must be owned by the current user: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise EvidenceFinalizationError(
            f"operational directory must use mode 0700: {path}"
        )


def _validate_same_private_parent(paths: list[Path]) -> None:
    reference_parent = paths[0].parent
    _validate_private_parent(reference_parent)
    for path in paths[1:]:
        _validate_private_parent(path.parent)
        try:
            same_parent = path.parent.samefile(reference_parent)
        except OSError as exc:
            raise EvidenceFinalizationError(
                f"unable to compare operational artifact parents: {exc}"
            ) from None
        if not same_parent:
            raise EvidenceFinalizationError(
                "post-write artifacts must share the same private directory"
            )


def _snapshot_private_artifact(path: Path, *, role: str) -> ArtifactSnapshot:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_parent(path.parent)
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise EvidenceFinalizationError(
            f"unable to inspect {role} artifact {path}: {exc}"
        ) from None
    if not stat.S_ISREG(path_metadata.st_mode):
        raise EvidenceFinalizationError(f"{role} artifact must be a regular file: {path}")
    if path_metadata.st_uid != os.getuid():
        raise EvidenceFinalizationError(
            f"{role} artifact must be owned by the current user: {path}"
        )
    if stat.S_IMODE(path_metadata.st_mode) != 0o600:
        raise EvidenceFinalizationError(
            f"{role} artifact must use mode 0600: {path}"
        )
    if path_metadata.st_nlink != 1:
        raise EvidenceFinalizationError(
            f"hard-linked {role} artifact is prohibited: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_metadata = os.fstat(descriptor)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ):
            raise EvidenceFinalizationError(f"{role} artifact changed while opening")
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_nlink != 1:
            raise EvidenceFinalizationError(f"unsafe {role} artifact changed while opening")
        with os.fdopen(descriptor, "rb") as artifact:
            descriptor = -1
            content = artifact.read()
    except EvidenceFinalizationError:
        raise
    except OSError as exc:
        raise EvidenceFinalizationError(
            f"unable to read {role} artifact {path}: {exc}"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if not content:
        raise EvidenceFinalizationError(f"{role} artifact must not be empty: {path}")
    if len(content) != opened_metadata.st_size:
        raise EvidenceFinalizationError(f"{role} artifact changed while reading: {path}")
    return ArtifactSnapshot(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        device=opened_metadata.st_dev,
        inode=opened_metadata.st_ino,
    )


def _validate_new_private_output(path: Path) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_parent(path.parent)
    if path.exists() or path.is_symlink():
        raise EvidenceFinalizationError(f"refusing to overwrite operational output: {path}")


def _write_private_output(path: Path, content: bytes) -> None:
    """Sync private bytes, then publish atomically without overwriting."""

    temporary_path: Path | None = None
    descriptor = -1
    published = False
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for _ in range(64):
            temporary_path = path.parent / (
                f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            )
            try:
                descriptor = os.open(temporary_path, flags, 0o600)
                break
            except FileExistsError:
                temporary_path = None
        if descriptor < 0 or temporary_path is None:
            raise EvidenceFinalizationError(
                f"unable to reserve exclusive temporary output for {path}"
            )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            if stat.S_IMODE(os.fstat(output.fileno()).st_mode) != 0o600:
                raise EvidenceFinalizationError(
                    f"generated temporary output is not mode 0600: {path}"
                )
        os.link(temporary_path, path, follow_symlinks=False)
        published = True
    except EvidenceFinalizationError:
        raise
    except OSError as exc:
        raise EvidenceFinalizationError(
            f"unable to atomically create private output {path}: {exc}"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
    if not published:
        raise EvidenceFinalizationError(f"private output was not published: {path}")


def _transport_paths(
    response_path: Path | None,
    transport_error_path: Path | None,
) -> tuple[str, Path]:
    if (response_path is None) == (transport_error_path is None):
        raise EvidenceFinalizationError(
            "exactly one raw response or raw transport-error artifact is required"
        )
    if response_path is not None:
        return "raw_response", response_path
    assert transport_error_path is not None
    return "raw_transport_error", transport_error_path


def _validate_execution_metadata(
    *,
    endpoint: object,
    expected_target_sha256: object,
    request_attempted: object,
    http_status: object,
    transport_error_class: object,
    retry_count: object,
    readback_class: object,
    admin_state_changed: object,
    transport_artifact: str,
) -> dict[str, Any]:
    if endpoint != EXPECTED_ENDPOINT:
        raise EvidenceFinalizationError(f"endpoint must be exactly {EXPECTED_ENDPOINT!r}")
    if not isinstance(expected_target_sha256, str) or not SHA256_PATTERN.fullmatch(
        expected_target_sha256
    ):
        raise EvidenceFinalizationError(
            "expected target SHA-256 must be 64 lowercase hexadecimal characters"
        )
    if not isinstance(request_attempted, bool):
        raise EvidenceFinalizationError("request_attempted must be a boolean")
    if (
        isinstance(retry_count, bool)
        or not isinstance(retry_count, int)
        or retry_count != 0
    ):
        raise EvidenceFinalizationError("retry_count must be exactly zero for GUG-277")
    if not isinstance(readback_class, str) or readback_class not in READBACK_CLASSES:
        raise EvidenceFinalizationError(
            "readback_class must be one of " + ", ".join(sorted(READBACK_CLASSES))
        )
    if not isinstance(admin_state_changed, str) or (
        admin_state_changed not in ADMIN_STATE_CHANGE_RESULTS
    ):
        raise EvidenceFinalizationError(
            "admin_state_changed must be YES, NO, or UNKNOWN"
        )
    if readback_class == "EXACT_BEFORE" and admin_state_changed != "NO":
        raise EvidenceFinalizationError(
            "EXACT_BEFORE requires admin_state_changed=NO"
        )
    if readback_class in {"DIFFERENT", "UNAVAILABLE", "UNKNOWN"} and (
        admin_state_changed != "UNKNOWN"
    ):
        raise EvidenceFinalizationError(
            f"{readback_class} requires admin_state_changed=UNKNOWN"
        )
    if not request_attempted and admin_state_changed != "NO":
        raise EvidenceFinalizationError(
            "request_attempted=false requires admin_state_changed=NO"
        )

    if transport_artifact == "raw_response":
        if not request_attempted:
            raise EvidenceFinalizationError(
                "a raw response cannot coexist with request_attempted=false"
            )
        if (
            isinstance(http_status, bool)
            or not isinstance(http_status, int)
            or not 200 <= http_status <= 599
        ):
            raise EvidenceFinalizationError(
                "HTTP status must be an integer from 200 through 599"
            )
        if transport_error_class is not None:
            raise EvidenceFinalizationError(
                "transport_error_class must be omitted with a raw response"
            )
        transport_outcome: dict[str, Any] = {
            "kind": "http",
            "status_code": http_status,
        }
        if http_status >= 400 and admin_state_changed == "YES":
            raise EvidenceFinalizationError(
                "an HTTP rejection cannot claim admin_state_changed=YES"
            )
    else:
        if http_status is not None:
            raise EvidenceFinalizationError(
                "HTTP status must be omitted with a raw transport error"
            )
        if not isinstance(transport_error_class, str) or not (
            TRANSPORT_ERROR_CLASS_PATTERN.fullmatch(transport_error_class)
        ):
            raise EvidenceFinalizationError(
                "transport_error_class must be a sanitized uppercase token"
            )
        if request_attempted == (transport_error_class == "NOT_ATTEMPTED"):
            raise EvidenceFinalizationError(
                "request_attempted is inconsistent with transport_error_class"
            )
        transport_outcome = {
            "kind": "transport_error",
            "classification": transport_error_class,
        }

    return {
        "endpoint": endpoint,
        "expected_target_sha256": expected_target_sha256,
        "request_attempted": request_attempted,
        "transport_outcome": transport_outcome,
        "retry_count": retry_count,
        "readback_class": readback_class,
        "admin_state_changed": admin_state_changed,
    }


def _artifact_entry(snapshot: ArtifactSnapshot) -> dict[str, Any]:
    return {"sha256": snapshot.sha256, "size_bytes": snapshot.size_bytes}


def _build_manifest(
    *,
    snapshots: dict[str, ArtifactSnapshot],
    transport_artifact: str,
    execution: dict[str, Any],
) -> dict[str, Any]:
    dependency_order = [
        "target",
        transport_artifact,
        "sanitized_receipt",
        "raw_readback",
        "sanitized_classification",
        "frozen_ledger",
        "final_manifest",
    ]
    return {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_post_write_evidence",
        "execution": execution,
        "artifacts": {
            role: _artifact_entry(snapshots[role]) for role in dependency_order[:-1]
        },
        "dependency_order": dependency_order,
        "publication_order": ["frozen_ledger", "final_manifest"],
        # Self-digests have no finite fixed point. The printed SHA-256 is the
        # external trust anchor and must never be appended to the frozen ledger.
        "manifest_digest_binding": "EXTERNAL_SHA256_REQUIRED",
        "finalizer_network_activity": "NONE",
    }


def _normalize_and_validate_paths(
    paths: dict[str, Path],
    output_paths: dict[str, Path] | None = None,
) -> tuple[dict[str, Path], dict[str, Path]]:
    normalized = {
        role: _absolute_without_resolving(path) for role, path in paths.items()
    }
    normalized_outputs = {
        role: _absolute_without_resolving(path)
        for role, path in (output_paths or {}).items()
    }
    all_paths = [*normalized.values(), *normalized_outputs.values()]
    if len(set(all_paths)) != len(all_paths):
        raise EvidenceFinalizationError("post-write artifact paths must all differ")
    _validate_same_private_parent(all_paths)
    for path in normalized_outputs.values():
        _validate_new_private_output(path)
    return normalized, normalized_outputs


def _snapshots(paths: dict[str, Path]) -> dict[str, ArtifactSnapshot]:
    snapshots = {
        role: _snapshot_private_artifact(path, role=role)
        for role, path in paths.items()
    }
    identities = {(item.device, item.inode) for item in snapshots.values()}
    if len(identities) != len(snapshots):
        raise EvidenceFinalizationError(
            "post-write artifact filesystem identities must differ"
        )
    return snapshots


def finalize_evidence(
    *,
    target_path: Path,
    response_path: Path | None,
    transport_error_path: Path | None,
    sanitized_receipt_path: Path,
    readback_path: Path,
    classification_path: Path,
    ledger_path: Path,
    frozen_ledger_output_path: Path,
    manifest_output_path: Path,
    endpoint: object,
    expected_target_sha256: object,
    request_attempted: object,
    http_status: object,
    transport_error_class: object,
    retry_count: object,
    readback_class: object,
    admin_state_changed: object,
) -> FinalizationResult:
    """Freeze the ledger and publish a complete final manifest last."""

    transport_artifact, transport_path = _transport_paths(
        response_path,
        transport_error_path,
    )
    paths, outputs = _normalize_and_validate_paths(
        {
            "target": target_path,
            transport_artifact: transport_path,
            "sanitized_receipt": sanitized_receipt_path,
            "raw_readback": readback_path,
            "sanitized_classification": classification_path,
            "ledger": ledger_path,
        },
        {
            "frozen_ledger": frozen_ledger_output_path,
            "final_manifest": manifest_output_path,
        },
    )
    execution = _validate_execution_metadata(
        endpoint=endpoint,
        expected_target_sha256=expected_target_sha256,
        request_attempted=request_attempted,
        http_status=http_status,
        transport_error_class=transport_error_class,
        retry_count=retry_count,
        readback_class=readback_class,
        admin_state_changed=admin_state_changed,
        transport_artifact=transport_artifact,
    )
    snapshots = _snapshots(paths)
    if snapshots["target"].sha256 != execution["expected_target_sha256"]:
        raise EvidenceFinalizationError(
            "target artifact does not match expected authorized target SHA-256"
        )

    source_ledger = snapshots.pop("ledger")
    _write_private_output(outputs["frozen_ledger"], source_ledger.content)
    frozen_ledger = _snapshot_private_artifact(
        outputs["frozen_ledger"],
        role="frozen_ledger",
    )
    if frozen_ledger.content != source_ledger.content:
        raise EvidenceFinalizationError("frozen ledger does not match source ledger")

    # Re-read every source after freezing the ledger. A source append,
    # replacement, permission change, or inode swap blocks before the manifest
    # commit marker is published.
    confirmed_snapshots = _snapshots(paths)
    for role, initial in snapshots.items():
        if confirmed_snapshots[role] != initial:
            raise EvidenceFinalizationError(
                f"{role} artifact changed before final manifest publication"
            )
    if confirmed_snapshots.pop("ledger") != source_ledger:
        raise EvidenceFinalizationError(
            "source ledger changed after its frozen snapshot was published"
        )
    snapshots = confirmed_snapshots
    snapshots["frozen_ledger"] = frozen_ledger

    manifest = _build_manifest(
        snapshots=snapshots,
        transport_artifact=transport_artifact,
        execution=execution,
    )
    manifest_content = _canonical_bytes(manifest)
    manifest_sha256 = hashlib.sha256(manifest_content).hexdigest()
    _write_private_output(outputs["final_manifest"], manifest_content)
    published_manifest = _snapshot_private_artifact(
        outputs["final_manifest"],
        role="final_manifest",
    )
    if (
        published_manifest.content != manifest_content
        or published_manifest.sha256 != manifest_sha256
    ):
        raise EvidenceFinalizationError(
            "published final manifest does not match generated bytes"
        )
    return FinalizationResult(
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        transport_artifact=transport_artifact,
    )


def verify_evidence(
    *,
    target_path: Path,
    response_path: Path | None,
    transport_error_path: Path | None,
    sanitized_receipt_path: Path,
    readback_path: Path,
    classification_path: Path,
    frozen_ledger_path: Path,
    manifest_path: Path,
    expected_manifest_sha256: object,
    endpoint: object,
    expected_target_sha256: object,
    request_attempted: object,
    http_status: object,
    transport_error_class: object,
    retry_count: object,
    readback_class: object,
    admin_state_changed: object,
) -> FinalizationResult:
    """Verify every artifact against an externally anchored final manifest."""

    if not isinstance(expected_manifest_sha256, str) or not SHA256_PATTERN.fullmatch(
        expected_manifest_sha256
    ):
        raise EvidenceFinalizationError(
            "expected external manifest SHA-256 must be 64 lowercase hexadecimal characters"
        )
    transport_artifact, transport_path = _transport_paths(
        response_path,
        transport_error_path,
    )
    paths, _ = _normalize_and_validate_paths(
        {
            "target": target_path,
            transport_artifact: transport_path,
            "sanitized_receipt": sanitized_receipt_path,
            "raw_readback": readback_path,
            "sanitized_classification": classification_path,
            "frozen_ledger": frozen_ledger_path,
            "final_manifest": manifest_path,
        }
    )
    execution = _validate_execution_metadata(
        endpoint=endpoint,
        expected_target_sha256=expected_target_sha256,
        request_attempted=request_attempted,
        http_status=http_status,
        transport_error_class=transport_error_class,
        retry_count=retry_count,
        readback_class=readback_class,
        admin_state_changed=admin_state_changed,
        transport_artifact=transport_artifact,
    )
    snapshots = _snapshots(paths)
    manifest_snapshot = snapshots.pop("final_manifest")
    if snapshots["target"].sha256 != execution["expected_target_sha256"]:
        raise EvidenceFinalizationError(
            "target artifact does not match expected authorized target SHA-256"
        )
    if manifest_snapshot.sha256 != expected_manifest_sha256:
        raise EvidenceFinalizationError(
            "final manifest does not match expected external manifest SHA-256"
        )
    try:
        observed_manifest = json.loads(
            manifest_snapshot.content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except EvidenceFinalizationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceFinalizationError(f"unable to parse final manifest: {exc}") from None
    if not isinstance(observed_manifest, dict):
        raise EvidenceFinalizationError("final manifest must be a JSON object")
    if manifest_snapshot.content != _canonical_bytes(observed_manifest):
        raise EvidenceFinalizationError("final manifest is not canonical JSON")
    expected_manifest = _build_manifest(
        snapshots=snapshots,
        transport_artifact=transport_artifact,
        execution=execution,
    )
    if observed_manifest != expected_manifest:
        raise EvidenceFinalizationError(
            "final manifest does not match supplied post-write artifacts and metadata"
        )
    return FinalizationResult(
        manifest=observed_manifest,
        manifest_sha256=manifest_snapshot.sha256,
        transport_artifact=transport_artifact,
    )


def _parse_cli_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected exactly 'true' or 'false'")


def _add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", required=True, type=Path)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--raw-response", type=Path)
    transport.add_argument("--raw-transport-error", type=Path)
    parser.add_argument("--sanitized-receipt", required=True, type=Path)
    parser.add_argument("--raw-readback", required=True, type=Path)
    parser.add_argument("--sanitized-classification", required=True, type=Path)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expected-target-sha256", required=True)
    parser.add_argument("--request-attempted", required=True, type=_parse_cli_bool)
    parser.add_argument("--http-status", type=int)
    parser.add_argument("--transport-error-class")
    parser.add_argument("--retry-count", required=True, type=int)
    parser.add_argument("--readback-class", required=True, choices=sorted(READBACK_CLASSES))
    parser.add_argument(
        "--admin-state-changed",
        required=True,
        choices=sorted(ADMIN_STATE_CHANGE_RESULTS),
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Finalize or verify branch-protection post-write evidence offline"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    finalize_parser = subparsers.add_parser("finalize")
    _add_shared_arguments(finalize_parser)
    finalize_parser.add_argument("--ledger", required=True, type=Path)
    finalize_parser.add_argument("--frozen-ledger-output", required=True, type=Path)
    finalize_parser.add_argument("--manifest-output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    _add_shared_arguments(verify_parser)
    verify_parser.add_argument("--frozen-ledger", required=True, type=Path)
    verify_parser.add_argument("--manifest", required=True, type=Path)
    verify_parser.add_argument("--expected-manifest-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    common = {
        "target_path": args.target,
        "response_path": args.raw_response,
        "transport_error_path": args.raw_transport_error,
        "sanitized_receipt_path": args.sanitized_receipt,
        "readback_path": args.raw_readback,
        "classification_path": args.sanitized_classification,
        "endpoint": args.endpoint,
        "expected_target_sha256": args.expected_target_sha256,
        "request_attempted": args.request_attempted,
        "http_status": args.http_status,
        "transport_error_class": args.transport_error_class,
        "retry_count": args.retry_count,
        "readback_class": args.readback_class,
        "admin_state_changed": args.admin_state_changed,
    }
    try:
        if args.command == "finalize":
            result = finalize_evidence(
                **common,
                ledger_path=args.ledger,
                frozen_ledger_output_path=args.frozen_ledger_output,
                manifest_output_path=args.manifest_output,
            )
        else:
            result = verify_evidence(
                **common,
                frozen_ledger_path=args.frozen_ledger,
                manifest_path=args.manifest,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
    except EvidenceFinalizationError as exc:
        print(f"FAIL: post-write evidence {args.command} failed\n{exc}", file=sys.stderr)
        return 1

    if args.command == "finalize":
        print("PASS: post-write evidence finalized with manifest last")
        for role, record in result.manifest["artifacts"].items():
            print(f"{role}_sha256={record['sha256']}")
            print(f"{role}_size_bytes={record['size_bytes']}")
        print("manifest_digest_binding=EXTERNAL_SHA256_REQUIRED")
    else:
        print("PASS: post-write evidence matches external manifest SHA-256")
    print(f"transport_artifact={result.transport_artifact}")
    print(f"final_manifest_sha256={result.manifest_sha256}")
    print("finalizer_network_activity=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
