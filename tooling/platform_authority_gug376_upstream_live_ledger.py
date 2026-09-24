"""Private, durable one-attempt ledger for the separate GUG-432 lane.

Hash chains detect corruption and enforce transition history; they do not
authenticate the owner or prevent an owner from restoring an old valid file.
The executor must independently anchor every snapshot before a provider write.
Interrupted local writes preserve their pending file and require reconciliation.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator

from tooling.platform_authority_gug365_phase_execution_ledger import (
    PhaseLedgerError,
    _durable_sync,
    _open_regular_private,
    _reject_cloud_xattrs,
    _reject_extended_acl,
    _reject_fd_acl,
    _reject_fd_cloud_xattrs,
    _require_local_filesystem,
    _require_local_filesystem_fd,
    _required_nofollow,
    _verify_lease_descriptor,
    _verify_open_file_binding,
    _write_all,
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OPERATION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,95}$")
_RECORD_TYPE = "scanalyze.platform_authority.gug376_upstream_live_ledger.v1"
_READY_PREDECESSORS = {"SUCCEEDED", "EXACT_PRESENT_NO_TOUCH"}


class LedgerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise LedgerError(code) from None


@contextmanager
def _safe_errors() -> Iterator[None]:
    try:
        yield
    except PhaseLedgerError as exc:
        raise LedgerError(exc.code) from None
    except OSError:
        raise LedgerError("LEDGER_IO_FAILED") from None


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _fail(code)
    return value


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail("TIME_NOT_TZ_AWARE")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        _fail("LEDGER_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("LEDGER_TIME_INVALID")
    if _timestamp(parsed) != value:
        _fail("LEDGER_TIME_INVALID")
    return _utc(parsed)


def _bytes(data: Any) -> bytes:
    try:
        return json.dumps(data, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail("LEDGER_VALUE_INVALID")


def _hash(data: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_bytes(data)).hexdigest()


def _root_path(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        _fail("LEDGER_ROOT_INVALID")
    return root


def _root_binding(root: Path, descriptor: int) -> dict[str, Any]:
    metadata = os.fstat(descriptor)
    current = os.lstat(root)
    if (not stat.S_ISDIR(metadata.st_mode) or not stat.S_ISDIR(current.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)
            != (current.st_dev, current.st_ino, current.st_uid, current.st_mode)):
        _fail("LEDGER_ROOT_MODE_INVALID")
    return {"absolute_path": str(root), "st_dev": metadata.st_dev,
            "st_ino": metadata.st_ino, "uid": metadata.st_uid,
            "mode": stat.S_IMODE(metadata.st_mode)}


def _open_root(root: Path) -> int:
    """Traverse without symlinks and bind the opened inode to the exact path."""
    root = _root_path(root)
    with _safe_errors():
        initial = os.lstat(root)
        if stat.S_ISLNK(initial.st_mode):
            _fail("LEDGER_ROOT_SYMLINK_FORBIDDEN")
        _reject_cloud_xattrs(root)
        _reject_extended_acl(root, "LEDGER_ROOT_ACL_FORBIDDEN")
        _require_local_filesystem(root)
        nofollow = _required_nofollow()
        directory = getattr(os, "O_DIRECTORY", None)
        if directory is None:
            _fail("LEDGER_ROOT_NOFOLLOW_UNAVAILABLE")
        descriptor: int | None = None
        try:
            descriptor = os.open(root.anchor, os.O_RDONLY | nofollow | directory)
            for part in root.parts[1:]:
                component = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(component.st_mode):
                    _fail("LEDGER_ROOT_SYMLINK_FORBIDDEN")
                child = os.open(part, os.O_RDONLY | nofollow | directory, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (component.st_dev, component.st_ino):
                    _fail("LEDGER_ROOT_CHANGED")
                if opened.st_uid not in {0, os.geteuid()}:
                    _fail("LEDGER_ANCESTOR_OWNER_INVALID")
                # Root-owned sticky temporary ancestors are permitted; their
                # children are traversed with nofollow and inode checks.
                if stat.S_IMODE(opened.st_mode) & 0o022 and not (
                        opened.st_uid == 0 and opened.st_mode & stat.S_ISVTX):
                    _fail("LEDGER_ANCESTOR_WRITABLE")
                _reject_fd_cloud_xattrs(descriptor)
                try:
                    os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    _fail("LEDGER_ROOT_INSIDE_REPOSITORY")
            binding = _root_binding(root, descriptor)
            if (binding["st_dev"], binding["st_ino"]) != (initial.st_dev, initial.st_ino):
                _fail("LEDGER_ROOT_CHANGED")
            _reject_fd_acl(descriptor, "LEDGER_ROOT_ACL_FORBIDDEN")
            _require_local_filesystem_fd(descriptor)
            result, descriptor = descriptor, None
            return result
        finally:
            if descriptor is not None:
                os.close(descriptor)


def ledger_root_digest(root: Path) -> str:
    """Hash validated custody metadata without creating a root or returning paths."""
    with _safe_errors():
        descriptor = _open_root(root)
        try:
            return _hash(_root_binding(root, descriptor))
        finally:
            os.close(descriptor)


def _verify_and_replay(record: dict[str, Any]) -> None:
    try:
        _replay(record)
    except (KeyError, TypeError, AttributeError, OverflowError, RecursionError):
        _fail("LEDGER_INTEGRITY_COMPROMISED")


def _replay(record: dict[str, Any]) -> None:
    """Reject even rehashed histories containing illegal transitions."""
    expected_fields = {"record_type", "schema_version", "run_digest", "plan_digest",
                       "custody_digest", "initial_operations", "operations", "initial_digest",
                       "snapshot_digest", "version", "history"}
    if not isinstance(record, dict) or set(record) != expected_fields:
        _fail("LEDGER_INTEGRITY_COMPROMISED")
    if (record["record_type"] != _RECORD_TYPE or type(record["schema_version"]) is not int
            or record["schema_version"] != 1 or type(record["version"]) is not int):
        _fail("LEDGER_INTEGRITY_COMPROMISED")
    for name in ("run_digest", "plan_digest", "custody_digest", "initial_digest", "snapshot_digest"):
        _require_digest(record[name], "LEDGER_INTEGRITY_COMPROMISED")
    initial, history = record["initial_operations"], record["history"]
    if (not isinstance(initial, list) or not 1 <= len(initial) <= 30
            or not isinstance(history, list) or len(history) > 3 * len(initial)):
        _fail("LEDGER_INTEGRITY_COMPROMISED")
    ops: list[dict[str, Any]] = []
    for item in initial:
        if (not isinstance(item, dict) or set(item) != {
                "operation_id", "request_contract_digest", "request_digest", "status", "attempt_count"}
                or not isinstance(item["operation_id"], str)
                or not _OPERATION_RE.fullmatch(item["operation_id"])
                or item["request_digest"] is not None or item["status"] != "READY"
                or type(item["attempt_count"]) is not int or item["attempt_count"] != 0):
            _fail("LEDGER_INTEGRITY_COMPROMISED")
        _require_digest(item["request_contract_digest"], "LEDGER_INTEGRITY_COMPROMISED")
        ops.append(dict(item))
    if len({item["operation_id"] for item in ops}) != len(ops):
        _fail("LEDGER_INTEGRITY_COMPROMISED")
    current = _hash({"run_digest": record["run_digest"], "plan_digest": record["plan_digest"],
                     "custody_digest": record["custody_digest"], "operations": initial})
    if current != record["initial_digest"]:
        _fail("LEDGER_INTEGRITY_COMPROMISED")
    event_keys = {
        "claim": {"request_digest", "authorization_digest"},
        "record_noop": {"request_digest", "authorization_digest", "receipt_digest"},
        "finish": {"outcome", "receipt_digest"},
        "reconcile": {"receipt_digest"},
    }
    last_time: datetime | None = None
    for version, event in enumerate(history, 1):
        if not isinstance(event, dict) or event.get("action") not in event_keys:
            _fail("LEDGER_INTEGRITY_COMPROMISED")
        action = event["action"]
        if (set(event) != event_keys[action] | {"action", "operation_id", "observed_at", "version", "event_digest"}
                or type(event["version"]) is not int or event["version"] != version):
            _fail("LEDGER_INTEGRITY_COMPROMISED")
        unhashed = {key: value for key, value in event.items() if key != "event_digest"}
        current = _hash({"previous": current, "event": unhashed})
        if current != event["event_digest"]:
            _fail("LEDGER_INTEGRITY_COMPROMISED")
        observed = _parse_timestamp(event["observed_at"])
        if last_time is not None and observed < last_time:
            _fail("TIME_ROLLBACK")
        last_time = observed
        matches = [index for index, item in enumerate(ops) if item["operation_id"] == event["operation_id"]]
        if len(matches) != 1:
            _fail("LEDGER_INTEGRITY_COMPROMISED")
        index = matches[0]
        op = ops[index]
        if action in {"claim", "record_noop"}:
            if op["status"] != "READY" or any(item["status"] not in _READY_PREDECESSORS for item in ops[:index]):
                _fail("LEDGER_TRANSITION_INVALID")
            _require_digest(event["request_digest"], "LEDGER_INTEGRITY_COMPROMISED")
            _require_digest(event["authorization_digest"], "LEDGER_INTEGRITY_COMPROMISED")
            op["request_digest"] = event["request_digest"]
            if action == "claim":
                op.update(status="IN_FLIGHT", attempt_count=1,
                          claim={"authorization_digest": event["authorization_digest"], "observed_at": event["observed_at"]})
            else:
                _require_digest(event["receipt_digest"], "LEDGER_INTEGRITY_COMPROMISED")
                op.update(status="EXACT_PRESENT_NO_TOUCH", noop={
                    key: event[key] for key in ("authorization_digest", "receipt_digest", "observed_at")})
        elif action == "finish":
            if op["status"] != "IN_FLIGHT" or event["outcome"] not in {"SUCCEEDED", "FAILED", "AMBIGUOUS"}:
                _fail("LEDGER_TRANSITION_INVALID")
            if event["outcome"] == "SUCCEEDED" or event["receipt_digest"] is not None:
                _require_digest(event["receipt_digest"], "LEDGER_INTEGRITY_COMPROMISED")
            op.update(status=event["outcome"], outcome=event["outcome"])
            if event["receipt_digest"] is not None:
                op["receipt_digest"] = event["receipt_digest"]
        else:
            if op["status"] not in {"IN_FLIGHT", "AMBIGUOUS"}:
                _fail("LEDGER_TRANSITION_INVALID")
            _require_digest(event["receipt_digest"], "LEDGER_INTEGRITY_COMPROMISED")
            op.update(status="RECONCILED", reconciliation={key: event[key] for key in ("receipt_digest", "observed_at")})
    if record["version"] != len(history) or record["snapshot_digest"] != current or record["operations"] != ops:
        _fail("LEDGER_INTEGRITY_COMPROMISED")


def _append_event(record: dict[str, Any], event: dict[str, Any]) -> None:
    if record["history"] and _parse_timestamp(event["observed_at"]) < _parse_timestamp(record["history"][-1]["observed_at"]):
        _fail("TIME_ROLLBACK")
    event = {**event, "version": record["version"] + 1}
    event["event_digest"] = _hash({"previous": record["snapshot_digest"], "event": event})
    record["history"].append(event)
    record["version"], record["snapshot_digest"] = event["version"], event["event_digest"]


def _read_record(descriptor: int) -> dict[str, Any]:
    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("LEDGER_FILE_JSON_INVALID")
            result[key] = value
        return result

    payload = bytearray()
    while len(payload) <= 1024 * 1024:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > 1024 * 1024:
        _fail("LEDGER_FILE_TOO_LARGE")
    try:
        result = json.loads(payload.decode(), object_pairs_hook=closed_object,
                            parse_constant=lambda _value: _fail("LEDGER_FILE_JSON_INVALID"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail("LEDGER_FILE_JSON_INVALID")
    if not isinstance(result, dict):
        _fail("LEDGER_FILE_JSON_INVALID")
    return result


class DurableMutationLedger:
    def __init__(self, root: Path, *, run_digest: str, plan_digest: str,
                 operations: tuple[tuple[str, str], ...]):
        self.root = _root_path(root)
        self.run_digest = _require_digest(run_digest, "RUN_DIGEST_INVALID")
        self.plan_digest = _require_digest(plan_digest, "PLAN_DIGEST_INVALID")
        if not isinstance(operations, tuple) or not 1 <= len(operations) <= 30:
            _fail("OPERATIONS_INVALID")
        seen: set[str] = set()
        for item in operations:
            if (not isinstance(item, tuple) or len(item) != 2
                    or not isinstance(item[0], str) or not _OPERATION_RE.fullmatch(item[0])):
                _fail("OPERATION_ID_INVALID")
            if item[0] in seen:
                _fail("DUPLICATE_OPERATION_ID")
            seen.add(item[0])
            _require_digest(item[1], "CONTRACT_DIGEST_INVALID")
        self.operations = operations
        self._root_digest = ledger_root_digest(root)

    def _name(self) -> str:
        return f"gug376-upstream-ledger-{self.run_digest[7:]}.json"

    def _lock_name(self) -> str:
        return f".gug376-upstream-ledger-{self.run_digest[7:]}.lease"

    def _pending_name(self) -> str:
        return f".gug376-upstream-ledger-{self.run_digest[7:]}.pending"

    def _check_root(self, root_fd: int) -> None:
        if _hash(_root_binding(self.root, root_fd)) != self._root_digest:
            _fail("LEDGER_CUSTODY_CHANGED")

    def _validated_root_fd(self) -> int:
        descriptor = _open_root(self.root)
        try:
            self._check_root(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def custody_digest(self) -> str:
        with _safe_errors():
            descriptor = self._validated_root_fd()
            try:
                return _hash(_root_binding(self.root, descriptor))
            finally:
                os.close(descriptor)

    @contextmanager
    def _execution_lease(self, root_fd: int) -> Iterator[int]:
        with _safe_errors():
            descriptor, _ = _open_regular_private(root_fd, self._lock_name(), writable=True)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _fail("RUNNER_ACTIVE")
                _verify_lease_descriptor(root_fd, self._lock_name(), descriptor)
                yield descriptor
                _verify_lease_descriptor(root_fd, self._lock_name(), descriptor)
            finally:
                os.close(descriptor)

    def _initial_record(self) -> dict[str, Any]:
        ops = [{"operation_id": op, "request_contract_digest": contract,
                "request_digest": None, "status": "READY", "attempt_count": 0}
               for op, contract in self.operations]
        initial_digest = _hash({"run_digest": self.run_digest, "plan_digest": self.plan_digest,
                                "custody_digest": self._root_digest, "operations": ops})
        return {"record_type": _RECORD_TYPE, "schema_version": 1,
                "run_digest": self.run_digest, "plan_digest": self.plan_digest,
                "custody_digest": self._root_digest, "initial_operations": ops,
                "operations": [dict(item) for item in ops], "initial_digest": initial_digest,
                "snapshot_digest": initial_digest, "version": 0, "history": []}

    def _require_no_pending(self, root_fd: int) -> None:
        try:
            os.stat(self._pending_name(), dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        _fail("LEDGER_PENDING_EXISTS")

    def create(self) -> dict[str, Any]:
        snapshot = self._initial_record()
        _verify_and_replay(snapshot)
        with _safe_errors():
            root_fd = self._validated_root_fd()
            lease_fd: int | None = None
            descriptor: int | None = None
            try:
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _required_nofollow()
                try:
                    lease_fd = os.open(self._lock_name(), flags, 0o600, dir_fd=root_fd)
                except FileExistsError:
                    lease_fd, _ = _open_regular_private(root_fd, self._lock_name(), writable=True)
                try:
                    fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    _fail("RUNNER_ACTIVE")
                _verify_lease_descriptor(root_fd, self._lock_name(), lease_fd)
                _durable_sync(lease_fd)
                _durable_sync(root_fd)
                try:
                    os.stat(self._name(), dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    _fail("LEDGER_ALREADY_EXISTS")
                self._require_no_pending(root_fd)
                descriptor = os.open(self._pending_name(), flags, 0o600, dir_fd=root_fd)
                _verify_open_file_binding(root_fd, self._pending_name(), descriptor, expected_link_count=1)
                _reject_fd_acl(descriptor, "LEDGER_FILE_ACL_FORBIDDEN")
                _write_all(descriptor, _bytes(snapshot))
                _durable_sync(descriptor)
                _durable_sync(root_fd)
                self._check_root(root_fd)
                _verify_lease_descriptor(root_fd, self._lock_name(), lease_fd)
                _verify_open_file_binding(root_fd, self._pending_name(), descriptor, expected_link_count=1)
                os.link(self._pending_name(), self._name(), src_dir_fd=root_fd,
                        dst_dir_fd=root_fd, follow_symlinks=False)
                _durable_sync(root_fd)
                _verify_open_file_binding(root_fd, self._name(), descriptor, expected_link_count=2)
                _verify_open_file_binding(root_fd, self._pending_name(), descriptor, expected_link_count=2)
                os.unlink(self._pending_name(), dir_fd=root_fd)
                _durable_sync(root_fd)
                _verify_open_file_binding(root_fd, self._name(), descriptor, expected_link_count=1)
                return snapshot
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if lease_fd is not None:
                    os.close(lease_fd)
                os.close(root_fd)

    def _read_locked(self, root_fd: int) -> dict[str, Any]:
        self._check_root(root_fd)
        self._require_no_pending(root_fd)
        descriptor, _ = _open_regular_private(root_fd, self._name())
        try:
            record = _read_record(descriptor)
            _verify_open_file_binding(root_fd, self._name(), descriptor, expected_link_count=1)
            _verify_and_replay(record)
            if (record["run_digest"], record["plan_digest"], record["custody_digest"]) != (
                    self.run_digest, self.plan_digest, self._root_digest):
                _fail("LEDGER_MISMATCH")
            if record["initial_operations"] != self._initial_record()["initial_operations"]:
                _fail("LEDGER_OPERATIONS_MISMATCH")
            return record
        finally:
            os.close(descriptor)

    def snapshot(self, expected_snapshot_digest: str | None = None) -> dict[str, Any]:
        if expected_snapshot_digest is not None:
            _require_digest(expected_snapshot_digest, "CAS_DIGEST_INVALID")
        with _safe_errors():
            root_fd = self._validated_root_fd()
            try:
                with self._execution_lease(root_fd):
                    record = self._read_locked(root_fd)
                    if expected_snapshot_digest is not None and record["snapshot_digest"] != expected_snapshot_digest:
                        _fail("CAS_VERSION_MISMATCH")
                    return record
            finally:
                os.close(root_fd)

    def _swap_locked(self, root_fd: int, lease_fd: int, record: dict[str, Any]) -> dict[str, Any]:
        # Validate before persistence, including caller/internal transition bugs.
        _verify_and_replay(record)
        self._check_root(root_fd)
        _verify_lease_descriptor(root_fd, self._lock_name(), lease_fd)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _required_nofollow()
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(self._pending_name(), flags, 0o600, dir_fd=root_fd)
            except FileExistsError:
                _fail("LEDGER_PENDING_EXISTS")
            _verify_open_file_binding(root_fd, self._pending_name(), descriptor, expected_link_count=1)
            _reject_fd_acl(descriptor, "LEDGER_FILE_ACL_FORBIDDEN")
            _write_all(descriptor, _bytes(record))
            _durable_sync(descriptor)
            _durable_sync(root_fd)
            self._check_root(root_fd)
            _verify_lease_descriptor(root_fd, self._lock_name(), lease_fd)
            _verify_open_file_binding(root_fd, self._pending_name(), descriptor, expected_link_count=1)
            os.rename(self._pending_name(), self._name(), src_dir_fd=root_fd, dst_dir_fd=root_fd)
            _durable_sync(root_fd)
            _verify_open_file_binding(root_fd, self._name(), descriptor, expected_link_count=1)
            return record
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _transition(self, operation_id: str, *, expected_snapshot_digest: str,
                    action: str, observed_at: datetime, **values: Any) -> dict[str, Any]:
        _require_digest(expected_snapshot_digest, "CAS_DIGEST_INVALID")
        observed = _timestamp(observed_at)
        with _safe_errors():
            root_fd = self._validated_root_fd()
            try:
                with self._execution_lease(root_fd) as lease_fd:
                    record = self._read_locked(root_fd)
                    if record["snapshot_digest"] != expected_snapshot_digest:
                        _fail("CAS_VERSION_MISMATCH")
                    indexes = [index for index, item in enumerate(record["operations"]) if item["operation_id"] == operation_id]
                    if len(indexes) != 1:
                        _fail("OPERATION_NOT_FOUND")
                    index = indexes[0]
                    op = record["operations"][index]
                    if action in {"claim", "record_noop"}:
                        if op["status"] != "READY":
                            _fail("OPERATION_NOT_READY")
                        if any(item["status"] not in _READY_PREDECESSORS for item in record["operations"][:index]):
                            _fail("PREDECESSOR_NOT_RESOLVED")
                        op["request_digest"] = values["request_digest"]
                        if action == "claim":
                            op.update(status="IN_FLIGHT", attempt_count=1,
                                      claim={"authorization_digest": values["authorization_digest"], "observed_at": observed})
                        else:
                            op.update(status="EXACT_PRESENT_NO_TOUCH", noop={
                                "authorization_digest": values["authorization_digest"],
                                "receipt_digest": values["receipt_digest"], "observed_at": observed})
                    elif action == "finish":
                        if op["status"] != "IN_FLIGHT":
                            _fail("OPERATION_NOT_IN_FLIGHT")
                        op.update(status=values["outcome"], outcome=values["outcome"])
                        if values["receipt_digest"] is not None:
                            op["receipt_digest"] = values["receipt_digest"]
                    else:
                        if op["status"] not in {"IN_FLIGHT", "AMBIGUOUS"}:
                            _fail("OPERATION_NOT_RECONCILABLE")
                        op.update(status="RECONCILED", reconciliation={
                            "receipt_digest": values["receipt_digest"], "observed_at": observed})
                    _append_event(record, {"action": action, "operation_id": operation_id,
                                           "observed_at": observed, **values})
                    return self._swap_locked(root_fd, lease_fd, record)
            finally:
                os.close(root_fd)

    def claim(self, operation_id: str, *, expected_snapshot_digest: str, request_digest: str,
              authorization_digest: str, observed_at: datetime) -> dict[str, Any]:
        return self._transition(operation_id, expected_snapshot_digest=expected_snapshot_digest,
            action="claim", observed_at=observed_at,
            request_digest=_require_digest(request_digest, "REQUEST_DIGEST_INVALID"),
            authorization_digest=_require_digest(authorization_digest, "AUTHORIZATION_DIGEST_INVALID"))

    def record_noop(self, operation_id: str, *, expected_snapshot_digest: str,
                    request_digest: str, authorization_digest: str, receipt_digest: str,
                    observed_at: datetime) -> dict[str, Any]:
        return self._transition(operation_id, expected_snapshot_digest=expected_snapshot_digest,
            action="record_noop", observed_at=observed_at,
            request_digest=_require_digest(request_digest, "REQUEST_DIGEST_INVALID"),
            authorization_digest=_require_digest(authorization_digest, "AUTHORIZATION_DIGEST_INVALID"),
            receipt_digest=_require_digest(receipt_digest, "RECEIPT_DIGEST_INVALID"))

    def finish(self, operation_id: str, *, expected_snapshot_digest: str, outcome: str,
               receipt_digest: str | None, observed_at: datetime) -> dict[str, Any]:
        if outcome not in {"SUCCEEDED", "FAILED", "AMBIGUOUS"}:
            _fail("OUTCOME_INVALID")
        if outcome == "SUCCEEDED" and receipt_digest is None:
            _fail("RECEIPT_DIGEST_REQUIRED")
        if receipt_digest is not None:
            _require_digest(receipt_digest, "RECEIPT_DIGEST_INVALID")
        return self._transition(operation_id, expected_snapshot_digest=expected_snapshot_digest,
            action="finish", observed_at=observed_at, outcome=outcome, receipt_digest=receipt_digest)

    def reconcile(self, operation_id: str, *, expected_snapshot_digest: str,
                  receipt_digest: str, observed_at: datetime) -> dict[str, Any]:
        return self._transition(operation_id, expected_snapshot_digest=expected_snapshot_digest,
            action="reconcile", observed_at=observed_at,
            receipt_digest=_require_digest(receipt_digest, "RECEIPT_DIGEST_INVALID"))
