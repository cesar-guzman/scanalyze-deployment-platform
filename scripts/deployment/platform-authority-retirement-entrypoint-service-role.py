#!/usr/bin/env python3
"""Build the private offline GUG-365 package or service-role plan.

This entrypoint is offline-only.  It publishes create-only owner evidence
below one explicitly supplied private root and reports only sanitized
classifications and digests.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Iterator, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_retirement_entrypoint_service_role_materializer as materializer,
)
from tooling import (  # noqa: E402
    platform_authority_retirement_ledger_factory_package as factory_package,
)


MAX_PRIVATE_JSON_BYTES = 8 * 1024 * 1024
PLAN_NAME = "gug365-retirement-entrypoint-service-role.plan.v1.json"
PRODUCTION_STATUS = "NO-GO"
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_CLOUD_PATH_PARTS = frozenset(
    {
        "cloudstorage",
        "mobile documents",
        "onedrive",
        "dropbox",
        "google drive",
    }
)
_CLOUD_XATTR_MARKERS = (
    "fileprovider",
    "ubiquit",
    "onedrive",
    "dropbox",
    "googledrive",
)


class OfflineCustodyError(ValueError):
    """Stable, sanitized local-custody failure."""

    def __init__(self, code: str) -> None:
        self.code = code if _ERROR_CODE.fullmatch(code) else "GUG365_OFFLINE_BLOCKED"
        super().__init__(self.code)


class SanitizedArgumentParser(argparse.ArgumentParser):
    """Reject malformed invocations without echoing caller-supplied values."""

    def error(self, _message: str) -> None:
        raise OfflineCustodyError("CLI_ARGUMENTS_INVALID")


@dataclass(frozen=True, slots=True)
class PrivateRoot:
    path: Path
    descriptor: int
    device: int
    inode: int


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise OfflineCustodyError("PRIVATE_ROOT_INVALID") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise OfflineCustodyError("PRIVATE_ROOT_SYMLINK_FORBIDDEN")


def _reject_cloud_managed_root(path: Path) -> None:
    if any(part.casefold() in _CLOUD_PATH_PARTS for part in path.parts):
        raise OfflineCustodyError("PRIVATE_ROOT_CLOUD_MANAGED_FORBIDDEN")
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None and sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["xattr", os.fspath(path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OfflineCustodyError(
                "PRIVATE_ROOT_CLOUD_STATUS_UNVERIFIED"
            ) from exc
        if result.returncode != 0:
            raise OfflineCustodyError("PRIVATE_ROOT_CLOUD_STATUS_UNVERIFIED")
        if any(
            marker in attribute.casefold()
            for attribute in result.stdout.splitlines()
            for marker in _CLOUD_XATTR_MARKERS
        ):
            raise OfflineCustodyError("PRIVATE_ROOT_CLOUD_MANAGED_FORBIDDEN")
        return
    if listxattr is None:
        return
    for candidate in (path, *path.parents):
        try:
            attributes = listxattr(candidate, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in {
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }:
                continue
            raise OfflineCustodyError("PRIVATE_ROOT_CLOUD_STATUS_UNVERIFIED") from exc
        lowered = tuple(attribute.casefold() for attribute in attributes)
        if any(
            marker in attribute
            for attribute in lowered
            for marker in _CLOUD_XATTR_MARKERS
        ):
            raise OfflineCustodyError("PRIVATE_ROOT_CLOUD_MANAGED_FORBIDDEN")


def _outside_repository(path: Path) -> None:
    try:
        path.relative_to(REPO_ROOT.resolve(strict=True))
    except ValueError:
        return
    except OSError as exc:
        raise OfflineCustodyError("REPOSITORY_ROOT_INVALID") from exc
    raise OfflineCustodyError("PRIVATE_ROOT_INSIDE_REPOSITORY")


def _revalidate_root(root: PrivateRoot) -> None:
    try:
        metadata = os.fstat(root.descriptor)
        current = os.stat(root.path, follow_symlinks=False)
    except OSError as exc:
        raise OfflineCustodyError("PRIVATE_ROOT_CHANGED") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_dev != root.device
        or metadata.st_ino != root.inode
        or current.st_dev != root.device
        or current.st_ino != root.inode
        or current.st_uid != metadata.st_uid
    ):
        raise OfflineCustodyError("PRIVATE_ROOT_CHANGED")


@contextmanager
def _private_root(path: Path) -> Iterator[PrivateRoot]:
    candidate = _absolute(path)
    _reject_symlink_components(candidate)
    _reject_cloud_managed_root(candidate)
    _outside_repository(candidate)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise OfflineCustodyError("PRIVATE_ROOT_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(candidate, os.O_RDONLY | nofollow | directory)
    except OSError as exc:
        raise OfflineCustodyError("PRIVATE_ROOT_INVALID") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OfflineCustodyError("PRIVATE_ROOT_MODE_INVALID")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise OfflineCustodyError("PRIVATE_ROOT_INVALID") from exc
        if resolved != candidate:
            raise OfflineCustodyError("PRIVATE_ROOT_CHANGED")
        root = PrivateRoot(
            path=resolved,
            descriptor=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        _revalidate_root(root)
        yield root
    finally:
        os.close(descriptor)


def _root_file_name(root: PrivateRoot, requested: Path) -> str:
    candidate = requested if requested.is_absolute() else root.path / requested
    candidate = _absolute(candidate)
    if candidate.parent != root.path or candidate.name in {"", ".", ".."}:
        raise OfflineCustodyError("PRIVATE_ARTIFACT_OUTSIDE_ROOT")
    return candidate.name


def _read_private_bytes(
    root: PrivateRoot, requested: Path, *, maximum_bytes: int
) -> bytes:
    _revalidate_root(root)
    name = _root_file_name(root, requested)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OfflineCustodyError("PRIVATE_INPUT_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(name, os.O_RDONLY | nofollow, dir_fd=root.descriptor)
    except OSError as exc:
        raise OfflineCustodyError("PRIVATE_INPUT_INVALID") from exc
    try:
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=root.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or current.st_uid != metadata.st_uid
        ):
            raise OfflineCustodyError("PRIVATE_INPUT_INVALID")
        remaining = maximum_bytes + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise OfflineCustodyError("PRIVATE_INPUT_TOO_LARGE")
        final = os.fstat(descriptor)
        if (
            final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
        ):
            raise OfflineCustodyError("PRIVATE_INPUT_CHANGED")
        return payload
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OfflineCustodyError("PRIVATE_JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise OfflineCustodyError("PRIVATE_JSON_NONFINITE_NUMBER")


def _read_private_json(root: PrivateRoot, requested: Path) -> dict[str, Any]:
    payload = _read_private_bytes(
        root, requested, maximum_bytes=MAX_PRIVATE_JSON_BYTES
    )
    try:
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except OfflineCustodyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OfflineCustodyError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(parsed, dict):
        raise OfflineCustodyError("PRIVATE_JSON_INVALID")
    return parsed


def _target_absent(root: PrivateRoot, name: str, *, exists_code: str) -> None:
    _revalidate_root(root)
    try:
        os.stat(name, dir_fd=root.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OfflineCustodyError("PRIVATE_OUTPUT_INVALID") from exc
    raise OfflineCustodyError(exists_code)


def _atomic_write_private(
    root: PrivateRoot, name: str, payload: bytes, *, exists_code: str
) -> None:
    if Path(name).name != name or name in {"", ".", ".."}:
        raise OfflineCustodyError("PRIVATE_OUTPUT_NAME_INVALID")
    _target_absent(root, name, exists_code=exists_code)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OfflineCustodyError("PRIVATE_OUTPUT_NOFOLLOW_UNAVAILABLE")
    temporary = f".gug365-{os.getpid()}-{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    published = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=root.descriptor,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=root.descriptor,
                dst_dir_fd=root.descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise OfflineCustodyError(exists_code) from exc
        published = True
        os.unlink(temporary, dir_fd=root.descriptor)
        temporary = ""
        final = os.stat(name, dir_fd=root.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != os.geteuid()
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_size != len(payload)
        ):
            raise OfflineCustodyError("PRIVATE_OUTPUT_INVALID")
        os.fsync(root.descriptor)
        _revalidate_root(root)
    except OfflineCustodyError:
        raise
    except OSError as exc:
        raise OfflineCustodyError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=root.descriptor)
            except FileNotFoundError:
                pass
        if published:
            # Publication is intentionally retained when directory fsync fails;
            # overwriting or retrying that evidence would be less safe.
            pass


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _public_status(**values: Any) -> str:
    return json.dumps(
        {
            **values,
            "aws_calls": 0,
            "aws_mutations": 0,
            "deployment_authorized": False,
            "production_status": PRODUCTION_STATUS,
        },
        sort_keys=True,
    )


def _cmd_package(args: argparse.Namespace) -> int:
    with _private_root(args.private_root) as root:
        _target_absent(
            root,
            factory_package.ARCHIVE_NAME,
            exists_code="LEDGER_FACTORY_PACKAGE_ALREADY_EXISTS",
        )
        _target_absent(
            root,
            factory_package.MANIFEST_NAME,
            exists_code="LEDGER_FACTORY_MANIFEST_ALREADY_EXISTS",
        )
        committed = factory_package.verify_clean_source_commit(
            source_root=REPO_ROOT,
            source_commit=args.source_commit,
        )
        built = factory_package.build_ledger_factory_package(
            source_root=REPO_ROOT,
            source_commit=args.source_commit,
            runtime_version_arn=args.runtime_version_arn,
            committed_sources=committed,
        )
        factory_package.validate_ledger_factory_package_manifest(
            built.manifest, archive=built.archive
        )
        _atomic_write_private(
            root,
            factory_package.ARCHIVE_NAME,
            built.archive,
            exists_code="LEDGER_FACTORY_PACKAGE_ALREADY_EXISTS",
        )
        _atomic_write_private(
            root,
            factory_package.MANIFEST_NAME,
            _json_bytes(built.manifest),
            exists_code="LEDGER_FACTORY_MANIFEST_ALREADY_EXISTS",
        )
    print(
        _public_status(
            status="PACKAGE_BUILT_OFFLINE",
            archive_sha256="sha256:" + str(built.manifest["archive_sha256"]),
            manifest_digest=built.manifest["manifest_digest"],
        )
    )
    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    with _private_root(args.private_root) as root:
        _target_absent(
            root,
            PLAN_NAME,
            exists_code="SERVICE_ROLE_PLAN_ALREADY_EXISTS",
        )
        gug363_plan = _read_private_json(root, args.gug363_plan)
        signing_contract = _read_private_json(
            root, args.ledger_factory_signing_contract
        )
        plan = materializer.compile_service_role_materialization_plan(
            gug363_plan=gug363_plan,
            expected_gug363_plan_digest=args.expected_gug363_plan_digest,
            ledger_factory_artifact_signing_contract=signing_contract,
            expected_ledger_factory_artifact_signing_contract_digest=(
                args.expected_ledger_factory_signing_contract_digest
            ),
            repo_root=REPO_ROOT,
        )
        materializer.validate_service_role_materialization_plan(
            plan,
            gug363_plan=gug363_plan,
            expected_gug363_plan_digest=args.expected_gug363_plan_digest,
            ledger_factory_artifact_signing_contract=signing_contract,
            expected_ledger_factory_artifact_signing_contract_digest=(
                args.expected_ledger_factory_signing_contract_digest
            ),
            repo_root=REPO_ROOT,
        )
        _atomic_write_private(
            root,
            PLAN_NAME,
            _json_bytes(plan),
            exists_code="SERVICE_ROLE_PLAN_ALREADY_EXISTS",
        )
    print(
        _public_status(
            status="PLAN_COMPILED_AND_VALIDATED_OFFLINE",
            plan_digest=plan["plan_digest"],
            managed_policy_count=len(plan["boundaries"]),
            role_count=1 + len(plan["child_roles"]),
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = SanitizedArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    package = subparsers.add_parser(
        "package",
        help="Build the deterministic unsigned ledger-factory ZIP offline",
        description="Build the deterministic unsigned ledger-factory ZIP offline.",
    )
    package.add_argument(
        "--private-root",
        type=Path,
        required=True,
        help="existing owner-only 0700 directory outside Git and cloud storage",
    )
    package.add_argument("--source-commit", required=True)
    package.add_argument("--runtime-version-arn", required=True)
    package.set_defaults(handler=_cmd_package)

    plan = subparsers.add_parser(
        "plan",
        help="Compile and validate the exact GUG-365 private plan offline",
        description="Compile and validate the exact GUG-365 private plan offline.",
    )
    plan.add_argument(
        "--private-root",
        type=Path,
        required=True,
        help="existing owner-only 0700 directory containing every input",
    )
    plan.add_argument("--gug363-plan", type=Path, required=True)
    plan.add_argument("--expected-gug363-plan-digest", required=True)
    plan.add_argument(
        "--ledger-factory-signing-contract", type=Path, required=True
    )
    plan.add_argument(
        "--expected-ledger-factory-signing-contract-digest", required=True
    )
    plan.set_defaults(handler=_cmd_plan)
    return parser


def _failure_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if isinstance(code, str) and _ERROR_CODE.fullmatch(code):
        return code
    rendered = str(exc)
    if _ERROR_CODE.fullmatch(rendered):
        return rendered
    return "UNEXPECTED_SANITIZED_FAILURE"


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return int(args.handler(args))
    except (
        OfflineCustodyError,
        factory_package.LedgerFactoryPackageError,
        materializer.ServiceRoleMaterializationError,
    ) as exc:
        print(
            _public_status(status="BLOCKED", reason=_failure_code(exc)),
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            _public_status(status="BLOCKED", reason="UNEXPECTED_SANITIZED_FAILURE"),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
