#!/usr/bin/env python3
"""Run one explicitly authorized synthetic application smoke from clean main."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TOKEN_ENV = "SCANALYZE_SMOKE_ACCESS_TOKEN"
MAX_CONFIG_BYTES = 16_384
STAGES = ("CREATE", "UPLOAD", "SUBMIT", "STATUS", "RESULT", "REPLAY")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")


class CliError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise CliError("CLI_ARGUMENTS_INVALID")


def _parser() -> Parser:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    run = commands.add_parser("run", help="Create one new private execution journal.")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--authorize-application-writes", action="store_true",
                     help="Authorize this synthetic document's application writes.")
    return parser


def _git(directory: Path, *arguments: str, allow_failure: bool = False) -> str:
    # Never forward the application token, arbitrary Git configuration, or hooks.
    environment = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0"}
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
             "-C", str(directory), *arguments],
            env=environment, capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise CliError("SOURCE_VERIFICATION_FAILED") from exc
    if result.returncode:
        if allow_failure:
            return ""
        raise CliError("SOURCE_VERIFICATION_FAILED")
    return result.stdout.strip()


def _verify_source() -> str:
    if _git(ROOT, "rev-parse", "--show-toplevel") != str(ROOT):
        raise CliError("SOURCE_ROOT_MISMATCH")
    if _git(ROOT, "symbolic-ref", "--quiet", "--short", "HEAD") != "main":
        raise CliError("SOURCE_NOT_MAIN")
    head = _git(ROOT, "rev-parse", "--verify", "HEAD^{commit}")
    upstream = _git(ROOT, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    if re.fullmatch(r"[0-9a-f]{40}", head) is None or head != upstream:
        raise CliError("SOURCE_HEAD_MISMATCH")
    if _git(ROOT, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CliError("SOURCE_NOT_CLEAN")
    return head


def _private_parent(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise CliError("PRIVATE_PATH_INVALID")
    for part in path.parts:
        folded = part.casefold()
        if any(marker in folded for marker in ("cloudstorage", "onedrive", "file provider",
                                                "fileprovider", "mobile documents")):
            raise CliError("SYNCED_STORAGE_FORBIDDEN")
    # Walk using descriptors so a replaced parent or symlink cannot redirect opens.
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            replacement = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=descriptor)
            os.close(descriptor)
            descriptor = replacement
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise CliError("PRIVATE_DIRECTORY_PERMISSIONS_INVALID")
        # Refuse any repository, including a worktree with a .git file.
        for parent in (path.parent, *path.parent.parents):
            if os.path.lexists(parent / ".git"):
                raise CliError("PRIVATE_PATH_INSIDE_GIT")
        if _git(path.parent, "rev-parse", "--show-toplevel", allow_failure=True):
            raise CliError("PRIVATE_PATH_INSIDE_GIT")
        return descriptor
    except (OSError, CliError):
        os.close(descriptor)
        raise


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CliError("CONFIG_DUPLICATE_KEY")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise CliError("CONFIG_NONFINITE_NUMBER")


def _read_config(path: Path) -> dict[str, Any]:
    parent = _private_parent(path)
    descriptor = -1
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600):
            raise CliError("CONFIG_FILE_PERMISSIONS_INVALID")
        if not 0 < before.st_size <= MAX_CONFIG_BYTES:
            raise CliError("CONFIG_SIZE_INVALID")
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (len(raw) != before.st_size or len(raw) > MAX_CONFIG_BYTES
                or (before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
                != (after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)):
            raise CliError("CONFIG_CHANGED_DURING_READ")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
        if not isinstance(value, dict):
            raise CliError("CONFIG_OBJECT_REQUIRED")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CliError("CONFIG_JSON_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _encoded(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


class Journal:
    def __init__(self, path: Path) -> None:
        self.descriptor = -1
        self.broken = False
        parent = _private_parent(path)
        try:
            self.descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                      | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            os.fchmod(self.descriptor, 0o600)
            os.fsync(parent)
        except FileExistsError as exc:
            raise CliError("RECEIPT_ALREADY_EXISTS") from exc
        except OSError as exc:
            self.close()
            raise CliError("JOURNAL_CREATE_FAILED") from exc
        finally:
            os.close(parent)

    def append(self, event: dict[str, Any]) -> None:
        if self.broken:
            raise CliError("JOURNAL_WRITE_FAILED")
        try:
            metadata = os.fstat(self.descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600):
                raise CliError("JOURNAL_CUSTODY_CHANGED")
            data = _encoded(event) + b"\n"
            if len(data) > MAX_CONFIG_BYTES:
                raise CliError("JOURNAL_EVENT_INVALID")
            pending = memoryview(data)
            while pending:
                count = os.write(self.descriptor, pending)
                if count <= 0:
                    raise CliError("JOURNAL_WRITE_FAILED")
                pending = pending[count:]
            os.fsync(self.descriptor)
        except OSError as exc:
            self.broken = True
            raise CliError("JOURNAL_WRITE_FAILED") from exc
        except CliError:
            self.broken = True
            raise

    def progress(self, event: dict[str, Any]) -> None:
        if (not isinstance(event, dict) or set(event) != {"stage", "requests", "status"}
                or event["stage"] not in STAGES
                or event["status"] not in {"BEFORE_REQUEST", "STEP_PASSED"}
                or type(event["requests"]) is not int or not 0 <= event["requests"] <= 256):
            raise CliError("JOURNAL_EVENT_INVALID")
        self.append(event)

    def recovery(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict) or event.get("event") not in {"CREATE_PREPARED", "DOCUMENT_CREATED"}:
            raise CliError("JOURNAL_EVENT_INVALID")
        ev = event["event"]
        expected_keys = {"event", "idempotency_key", "request_sha256"} if ev == "CREATE_PREPARED" else {"event", "document_id"}
        if set(event) != expected_keys:
            raise CliError("JOURNAL_EVENT_INVALID")
        
        if ev == "CREATE_PREPARED":
            key = event["idempotency_key"]
            if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", key):
                raise CliError("JOURNAL_EVENT_INVALID")
            sha = event["request_sha256"]
            if not isinstance(sha, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", sha):
                raise CliError("JOURNAL_EVENT_INVALID")
        else:
            doc_id = event["document_id"]
            if not isinstance(doc_id, str) or not re.fullmatch(r"[0-9a-f]{32}", doc_id):
                raise CliError("JOURNAL_EVENT_INVALID")
        self.append(event)

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor, self.descriptor = self.descriptor, -1
            os.close(descriptor)


def _summary(value: Any) -> dict[str, Any]:
    expected = {"schema_version", "status", "scope", "production_authorized", "requests",
                "completed_steps", "document_id_sha256", "pdf_sha256", "elapsed_milliseconds"}
    if (not isinstance(value, dict) or set(value) != expected
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["status"] != "APPLICATION_SMOKE_PASSED"
            or value["scope"] != "single_synthetic_bank_document"
            or value["production_authorized"] is not False
            or type(value["requests"]) is not int or not 6 <= value["requests"] <= 256
            or value["completed_steps"] != list(STAGES)
            or type(value["elapsed_milliseconds"]) is not int
            or not 0 <= value["elapsed_milliseconds"] <= 3_600_000
            or any(not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None
                   for field in ("document_id_sha256", "pdf_sha256"))):
        raise CliError("SUMMARY_INVALID")
    return dict(value)


def main(argv: list[str] | None = None) -> int:
    journal: Journal | None = None
    subject = None
    try:
        args = _parser().parse_args(argv)
        if not args.authorize_application_writes:
            raise CliError("APPLICATION_WRITE_AUTHORIZATION_REQUIRED")
        source_commit = _verify_source()
        supplied_config = _read_config(args.config)
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from tooling import document_journey_smoke as subject

        config = subject.SmokeConfig.from_dict(supplied_config)
        config_digest = "sha256:" + hashlib.sha256(_encoded(supplied_config)).hexdigest()
        journal = Journal(args.receipt)
        journal.append({"event": "STARTED", "source_commit": source_commit,
                        "config_sha256": config_digest})
        token = os.environ.get(TOKEN_ENV)
        if not token:
            raise CliError("ACCESS_TOKEN_REQUIRED")
        summary = _summary(subject.run_smoke(config, token, subject.HttpsTransport(),
                                              on_progress=journal.progress,
                                              on_recovery=journal.recovery))
        journal.append({"event": "SUMMARY", **summary})
        journal.close()
        print(_encoded(summary).decode("ascii"))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        if isinstance(exc, CliError) or (subject is not None and isinstance(exc, subject.SmokeError)):
            candidate = exc.code
            code = candidate if isinstance(candidate, str) and _CODE.fullmatch(candidate) else "SMOKE_FAILED"
        elif isinstance(exc, KeyboardInterrupt):
            code = "SMOKE_INTERRUPTED"
        elif isinstance(exc, OSError):
            code = "PRIVATE_IO_FAILED"
        else:
            code = "SMOKE_FAILED"
        if journal is not None and journal.descriptor >= 0 and not journal.broken:
            try:
                journal.append({"event": "FAILED", "code": code})
            except (Exception, KeyboardInterrupt):
                pass
        print(code, file=sys.stderr)
        return 2
    finally:
        if journal is not None:
            try:
                journal.close()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
