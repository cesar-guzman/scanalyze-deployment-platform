#!/usr/bin/env python3
"""Validate only GUG-376 zero-effect STOP checkpoints without contacting AWS.

The command accepts one artifact below an explicitly selected owner-only
private root.  It rejects symlinks, hard links, duplicate JSON keys, oversized
files, permissive modes, and paths outside that root.  Repository plans,
inventories, trust anchors, receipts and provider-slot summaries are
deliberately unsupported because a serialized digest-only artifact cannot
prove provider, runtime or private-root authority.  Successful output remains
a source-gap STOP and never prints artifact contents or filesystem paths.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_gug365_upstream_prerequisites import (  # noqa: E402
    UpstreamPrerequisiteError,
    canonical_digest,
    validate_final_handoff,
    validate_phase_authorization,
)


MAXIMUM_BYTES = 2 * 1024 * 1024
SYNC_PATH_MARKERS = frozenset(
    {"cloudstorage", "mobile documents", "dropbox", "onedrive", "icloud drive"}
)
VALIDATORS: dict[str, Callable[[Mapping[str, Any]], None]] = {
    "scanalyze.platform_authority.gug365_upstream_phase_authorization.v1": (
        validate_phase_authorization
    ),
    "scanalyze.platform_authority.gug365_upstream_final_handoff.v1": (
        validate_final_handoff
    ),
}


class CliError(ValueError):
    """Sanitized CLI error suitable for a public status."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CliError(code)


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("PRIVATE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _private_root(path: Path) -> Path:
    if not path.is_absolute():
        _fail("PRIVATE_ROOT_NOT_ABSOLUTE")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CliError("PRIVATE_ROOT_UNAVAILABLE") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("PRIVATE_ROOT_CUSTODY_INVALID")
    try:
        if resolved == REPO_ROOT or resolved.is_relative_to(REPO_ROOT):
            _fail("PRIVATE_ROOT_INSIDE_REPOSITORY")
    except AttributeError:  # pragma: no cover - Python 3.11 provides is_relative_to
        if REPO_ROOT in resolved.parents:
            _fail("PRIVATE_ROOT_INSIDE_REPOSITORY")
    if any(part.casefold() in SYNC_PATH_MARKERS for part in resolved.parts):
        _fail("PRIVATE_ROOT_SYNCED_STORAGE_FORBIDDEN")
    return resolved


def _read_private_json(root: Path, relative_path: Path) -> dict[str, Any]:
    if (
        relative_path.is_absolute()
        or relative_path == Path(".")
        or not relative_path.parts
        or ".." in relative_path.parts
    ):
        _fail("PRIVATE_INPUT_PATH_INVALID")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        _fail("PRIVATE_NOFOLLOW_UNAVAILABLE")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | nofollow | directory | cloexec
    file_flags = os.O_RDONLY | nofollow | cloexec
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        current = os.open(root, directory_flags)
        directory_descriptors.append(current)
        root_metadata = os.fstat(current)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            _fail("PRIVATE_ROOT_CUSTODY_INVALID")
        for component in relative_path.parts[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            directory_descriptors.append(current)
            directory_metadata = os.fstat(current)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            ):
                _fail("PRIVATE_INPUT_DIRECTORY_CUSTODY_INVALID")
        descriptor = os.open(relative_path.parts[-1], file_flags, dir_fd=current)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAXIMUM_BYTES
        ):
            _fail("PRIVATE_INPUT_CUSTODY_INVALID")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                _fail("PRIVATE_INPUT_TRUNCATED")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _fail("PRIVATE_INPUT_CHANGED_DURING_READ")
        raw = b"".join(chunks)
    except CliError:
        raise
    except OSError as exc:
        raise CliError("PRIVATE_INPUT_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda _value: _fail("PRIVATE_JSON_NON_FINITE_NUMBER"),
        )
    except CliError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        _fail("PRIVATE_JSON_OBJECT_REQUIRED")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-root",
        required=True,
        type=Path,
        help="absolute owner-only (0700) root outside the repository",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="relative owner-only (0600) JSON artifact below the private root",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        artifact = _read_private_json(_private_root(args.private_root), args.input)
        record_type = artifact.get("record_type")
        validator = VALIDATORS.get(record_type) if isinstance(record_type, str) else None
        if validator is None:
            _fail("PRIVATE_ARTIFACT_RECORD_TYPE_UNSUPPORTED")
        validator(artifact)
        status = {
            "status": "STOP_UPSTREAM_SOURCE_CONTRACT_GAP",
            "record_type": record_type,
            "artifact_digest": canonical_digest(artifact),
            "state": artifact.get(
                "state", "REPOSITORY_VALIDATED_NO_LIVE_EXECUTION"
            ),
            "deployment_authorized": artifact.get(
                "deployment_authorized", False
            ),
            "aws_calls_performed": 0,
            "aws_mutations": 0,
            "provider_evidence": "NOT_PROVEN",
            "runtime_pin": "NOT_PROVEN",
            "private_root_authority": "NOT_PROVEN",
            "production_status": "NO-GO",
        }
        print(json.dumps(status, sort_keys=True, separators=(",", ":")))
        return 0
    except (CliError, UpstreamPrerequisiteError) as exc:
        code = exc.code if hasattr(exc, "code") else "UPSTREAM_ARTIFACT_INVALID"
        print(
            json.dumps(
                {"status": "BLOCKED", "code": code},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
