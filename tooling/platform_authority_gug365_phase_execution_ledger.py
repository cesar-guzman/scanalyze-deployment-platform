"""Durable, offline GUG-365 phase execution ledger.

The module owns no AWS client and executes no provider operation.  It prepares
and validates create-only JSON records that a separately authorized runner can
use as the durable causal guard around exactly one phase attempt.  Every state
transition is compare-and-swap (CAS), every mutation is one-attempt/no-retry,
and an ambiguous result may only enter the read-only reconciliation path.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Callable, Iterator, Mapping, Sequence


RECORD_TYPE = "scanalyze.platform_authority.gug365_phase_execution_ledger.v1"
RECORD_VERSION = 1
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_PROFILE_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,95}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
_PHASE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_HOST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_RESULT = frozenset({"SUCCEEDED", "FAILED", "AMBIGUOUS"})
_TERMINAL = frozenset({"CONSUMED", "RECONCILED"})
FORWARD_PHASES = (
    "POLICY_FACTORY",
    "FOUNDATION_FACTORY",
    "FUNCTION_FACTORY",
    "LEDGER_FACTORY_FUNCTION_FACTORY",
    "LEDGER_FACTORY_ACTIVATOR",
    "LEDGER_FACTORY_INVOKER",
    "LEDGER_FACTORY_REVOKER",
    "ACTIVATOR",
)
_AUTHORITY_EVIDENCE_FIELDS = frozenset(
    {
        "record_type",
        "phase",
        "caller_account_id",
        "region",
        "caller_arn_digest",
        "session_identifier_digest",
        "session_issued_at",
        "session_expires_at",
        "evidence_collected_at",
        "session_lifetime_seconds",
        "session_remaining_seconds",
        "session_chain_depth",
        "evidence_collected_after_sts",
        "effective_policy_inventory_complete",
        "sole_identity_policy_document_digest",
        "additional_inline_policy_count",
        "additional_attached_policy_count",
        "group_policy_count",
        "maximum_authority_source",
        "maximum_authority_document_digest",
        "raw_caller_arn_persisted",
        "evidence_digest",
    }
)
_TOP_LEVEL_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "ledger_id",
        "ledger_version",
        "initial_ledger_digest",
        "previous_ledger_digest",
        "plan_digest",
        "bundle_digest",
        "account_id",
        "region",
        "profile_class",
        "caller_arn_digest",
        "executor_authority_evidence_digest",
        "authority_session_identifier_digest",
        "authority_session_issued_at",
        "authority_session_expires_at",
        "authority_evidence_collected_at",
        "authority_evaluation_at",
        "phase",
        "ordered_operations_digest",
        "operation_count",
        "ordered_request_digests",
        "not_before",
        "expires_at",
        "host_digest",
        "predecessor_phase",
        "predecessor_terminal_receipt_digest",
        "predecessor_ledger_digest",
        "before_state_digest",
        "required_predecessor_checkpoint_digest",
        "status",
        "attempt_count",
        "claim",
        "operation_outcomes",
        "in_flight_operation",
        "reconciliation",
        "receipt_chain",
        "ledger_digest",
    }
)
_EXECUTION_AUTHORIZATION_FIELDS = frozenset(
    {
        "ledger_id",
        "initial_ledger_digest",
        "claim_nonce_digest",
        "plan_digest",
        "bundle_digest",
        "account_id",
        "region",
        "profile_class",
        "caller_arn_digest",
        "executor_authority_evidence_digest",
        "authority_session_identifier_digest",
        "authority_session_issued_at",
        "authority_session_expires_at",
        "authority_evidence_collected_at",
        "authority_evaluation_at",
        "phase",
        "ordered_operations_digest",
        "operation_count",
        "ordered_request_digests",
        "not_before",
        "expires_at",
        "host_digest",
        "predecessor_phase",
        "predecessor_terminal_receipt_digest",
        "predecessor_ledger_digest",
        "before_state_digest",
        "required_predecessor_checkpoint_digest",
    }
)
_PREDECESSOR_EXECUTION_BINDING_FIELDS = frozenset(
    {
        "phase",
        "ledger_id",
        "initial_ledger_digest",
        "claim_nonce_digest",
        "terminal_receipt_digest",
        "ledger_digest",
        "checkpoint_digest",
    }
)
_CLOUD_PATH_PARTS = frozenset(
    {"cloudstorage", "mobile documents", "onedrive", "dropbox", "google drive"}
)
_CLOUD_XATTR_MARKERS = ("fileprovider", "ubiquit", "onedrive", "dropbox", "googledrive")
_DARWIN_F_FULLFSYNC = 51
_DARWIN_MNT_LOCAL = 0x00001000
_DARWIN_ACL_TYPE_EXTENDED = 0x00000100
_LOCAL_LINUX_FILESYSTEM_TYPES = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs"})


class _DarwinFsid(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFsid),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


class PhaseLedgerError(ValueError):
    """Stable fail-closed ledger failure without caller-controlled text."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN_RE.fullmatch(code) else "PHASE_LEDGER_BLOCKED"
        super().__init__(self.code)


def _durable_sync(descriptor: int) -> None:
    """Flush bytes and metadata, including the Darwin drive-cache barrier."""

    try:
        os.fsync(descriptor)
        if sys.platform == "darwin":
            fcntl.fcntl(descriptor, _DARWIN_F_FULLFSYNC)
    except OSError:
        _fail("DURABLE_SYNC_FAILED")


def _required_nofollow() -> int:
    """Return the platform no-follow flag or fail before opening custody data."""

    value = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(value, int) or isinstance(value, bool) or value == 0:
        _fail("LEDGER_NOFOLLOW_UNAVAILABLE")
    return value


@dataclass(frozen=True, slots=True)
class CasTransition:
    """One storage-adapter CAS transition; the adapter must not retry it."""

    expected_version: int
    expected_digest: str
    proposed_record: dict[str, Any]
    attempt_limit: int = 1
    retry_permitted: bool = False


@dataclass(frozen=True, slots=True)
class DurablePhaseLedgerStore:
    """Owner-only local JSON store with create-only publish and locked CAS."""

    root: Path

    def _validated_root_fd(self) -> int:
        candidate = Path(os.path.abspath(os.path.expanduser(os.fspath(self.root))))
        try:
            initial_metadata = os.lstat(candidate)
        except OSError:
            _fail("LEDGER_ROOT_INVALID")
        if stat.S_ISLNK(initial_metadata.st_mode):
            _fail("LEDGER_ROOT_SYMLINK_FORBIDDEN")
        if any(part.casefold() in _CLOUD_PATH_PARTS for part in candidate.parts):
            _fail("LEDGER_ROOT_CLOUD_MANAGED_FORBIDDEN")
        _reject_cloud_xattrs(candidate)
        _reject_extended_acl(candidate, "LEDGER_ROOT_ACL_FORBIDDEN")
        _require_local_filesystem(candidate)
        nofollow = _required_nofollow()
        directory = getattr(os, "O_DIRECTORY", None)
        if directory is None:
            _fail("LEDGER_ROOT_NOFOLLOW_UNAVAILABLE")
        descriptor: int | None = None
        try:
            descriptor = os.open(candidate.anchor, os.O_RDONLY | nofollow | directory)
            _reject_fd_cloud_xattrs(descriptor)
            for part in candidate.parts[1:]:
                component = os.stat(
                    part, dir_fd=descriptor, follow_symlinks=False
                )
                if stat.S_ISLNK(component.st_mode):
                    _fail("LEDGER_ROOT_SYMLINK_FORBIDDEN")
                child: int | None = None
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | nofollow | directory,
                        dir_fd=descriptor,
                    )
                    _reject_fd_cloud_xattrs(child)
                except BaseException:
                    if child is not None:
                        os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            assert descriptor is not None
            metadata = os.fstat(descriptor)
            path_metadata = os.lstat(candidate)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino)
                != (path_metadata.st_dev, path_metadata.st_ino)
                or (metadata.st_dev, metadata.st_ino)
                != (initial_metadata.st_dev, initial_metadata.st_ino)
            ):
                _fail("LEDGER_ROOT_MODE_INVALID")
            _reject_fd_acl(descriptor, "LEDGER_ROOT_ACL_FORBIDDEN")
            _reject_fd_cloud_xattrs(descriptor)
            _require_local_filesystem_fd(descriptor)
            result = descriptor
            descriptor = None
            return result
        except OSError:
            _fail("LEDGER_ROOT_INVALID")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _name(ledger_id: str) -> str:
        digest = _require_digest(ledger_id, "LEDGER_ID_INVALID").split(":", 1)[1]
        return f"gug365-phase-ledger-{digest}.json"

    @staticmethod
    def _lock_name(ledger_id: str) -> str:
        digest = _require_digest(ledger_id, "LEDGER_ID_INVALID").split(":", 1)[1]
        return f".gug365-phase-ledger-{digest}.lease"

    @staticmethod
    def _pending_name(ledger_id: str) -> str:
        digest = _require_digest(ledger_id, "LEDGER_ID_INVALID").split(":", 1)[1]
        return f".gug365-phase-ledger-{digest}.pending"

    @contextmanager
    def execution_lease(self, ledger_id: str) -> Iterator[int]:
        """Hold the stable per-ledger inode across effect and outcome CAS.

        The data inode is replaced after every CAS and therefore cannot be the
        mutual-exclusion primitive.  The separate lease inode is never
        replaced.  A crashed runner releases its kernel lock automatically;
        recovery must win this same lock before changing IN_FLIGHT state.
        """

        root_fd = self._validated_root_fd()
        descriptor: int | None = None
        try:
            descriptor, _metadata = _open_regular_private(
                root_fd, self._lock_name(ledger_id), writable=True
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("RUNNER_ACTIVE")
            yield descriptor
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(root_fd)

    def create(self, record: Mapping[str, Any]) -> None:
        """Stage and atomically publish PREPARED once; never overwrite."""

        snapshot = _canonical_snapshot(record, "LEDGER_CREATE_SNAPSHOT_INVALID")
        if not isinstance(snapshot, dict):
            _fail("LEDGER_CREATE_SNAPSHOT_INVALID")
        validate_ledger(snapshot)
        if snapshot["status"] != "PREPARED":
            _fail("LEDGER_CREATE_STATE_INVALID")
        root_fd = self._validated_root_fd()
        descriptor: int | None = None
        lease_descriptor: int | None = None
        data_created = False
        pending_created_this_call = False
        pending = ""
        try:
            name = self._name(str(snapshot["ledger_id"]))
            lease_name = self._lock_name(str(snapshot["ledger_id"]))
            pending = self._pending_name(str(snapshot["ledger_id"]))
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | _required_nofollow()
            try:
                lease_descriptor = os.open(lease_name, flags, 0o600, dir_fd=root_fd)
            except FileExistsError:
                lease_descriptor, _lease_metadata = _open_regular_private(
                    root_fd, lease_name, writable=True
                )
            try:
                fcntl.flock(lease_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("RUNNER_ACTIVE")
            os.fchmod(lease_descriptor, 0o600)
            _reject_fd_acl(lease_descriptor, "LEDGER_FILE_ACL_FORBIDDEN")
            _durable_sync(lease_descriptor)
            lease_metadata = os.fstat(lease_descriptor)
            if (
                lease_metadata.st_uid != os.geteuid()
                or lease_metadata.st_nlink != 1
                or stat.S_IMODE(lease_metadata.st_mode) != 0o600
            ):
                _fail("LEDGER_FILE_INVALID")
            _durable_sync(root_fd)
            try:
                existing = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                try:
                    staged_path = os.stat(
                        pending, dir_fd=root_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    _fail("LEDGER_ALREADY_EXISTS")
                if (
                    not stat.S_ISREG(existing.st_mode)
                    or not stat.S_ISREG(staged_path.st_mode)
                    or (existing.st_dev, existing.st_ino)
                    != (staged_path.st_dev, staged_path.st_ino)
                    or existing.st_uid != os.geteuid()
                    or existing.st_nlink != 2
                    or stat.S_IMODE(existing.st_mode) != 0o600
                ):
                    _fail("LEDGER_CREATE_RECOVERY_INVALID")
                recovery_descriptor = os.open(
                    name,
                    os.O_RDONLY | _required_nofollow(),
                    dir_fd=root_fd,
                )
                try:
                    _verify_open_file_binding(
                        root_fd,
                        name,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    _verify_open_file_binding(
                        root_fd,
                        pending,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    _reject_fd_acl(
                        recovery_descriptor, "LEDGER_FILE_ACL_FORBIDDEN"
                    )
                    recovered = _read_record(recovery_descriptor)
                    _verify_open_file_binding(
                        root_fd,
                        name,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    _verify_open_file_binding(
                        root_fd,
                        pending,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    validate_ledger(recovered)
                    if recovered != snapshot:
                        _fail("LEDGER_CREATE_RECOVERY_BINDING_MISMATCH")
                    _verify_open_file_binding(
                        root_fd,
                        name,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    _verify_open_file_binding(
                        root_fd,
                        pending,
                        recovery_descriptor,
                        expected_link_count=2,
                    )
                    os.unlink(pending, dir_fd=root_fd)
                    pending = ""
                    _verify_open_file_binding(
                        root_fd,
                        name,
                        recovery_descriptor,
                        expected_link_count=1,
                    )
                    _durable_sync(root_fd)
                finally:
                    os.close(recovery_descriptor)
                return
            try:
                os.unlink(pending, dir_fd=root_fd)
                _durable_sync(root_fd)
            except FileNotFoundError:
                pass
            descriptor = os.open(pending, flags, 0o600, dir_fd=root_fd)
            pending_created_this_call = True
            os.fchmod(descriptor, 0o600)
            _reject_fd_acl(descriptor, "LEDGER_FILE_ACL_FORBIDDEN")
            _write_all(descriptor, _record_bytes(snapshot))
            _durable_sync(descriptor)
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                _fail("LEDGER_FILE_INVALID")
            os.lseek(descriptor, 0, os.SEEK_SET)
            staged = _read_record(descriptor)
            validate_ledger(staged)
            if staged != snapshot:
                _fail("LEDGER_CREATE_STAGE_READBACK_MISMATCH")
            _durable_sync(root_fd)
            _verify_open_file_binding(
                root_fd, pending, descriptor, expected_link_count=1
            )
            try:
                os.link(
                    pending,
                    name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                _fail("LEDGER_ALREADY_EXISTS")
            data_created = True
            _verify_open_file_binding(
                root_fd, pending, descriptor, expected_link_count=2
            )
            _verify_open_file_binding(
                root_fd, name, descriptor, expected_link_count=2
            )
            _durable_sync(root_fd)
            os.unlink(pending, dir_fd=root_fd)
            pending = ""
            _verify_open_file_binding(
                root_fd, name, descriptor, expected_link_count=1
            )
            _durable_sync(root_fd)
            published_descriptor, _published_metadata = _open_regular_private(
                root_fd, name
            )
            try:
                published = _read_record(published_descriptor)
                _verify_open_file_binding(
                    root_fd, name, published_descriptor, expected_link_count=1
                )
            finally:
                os.close(published_descriptor)
            validate_ledger(published)
            if published != snapshot:
                _fail("LEDGER_CREATE_READBACK_MISMATCH")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if lease_descriptor is not None:
                os.close(lease_descriptor)
            if pending and pending_created_this_call and not data_created:
                try:
                    os.unlink(pending, dir_fd=root_fd)
                    _durable_sync(root_fd)
                except FileNotFoundError:
                    pass
            os.close(root_fd)

    def read(self, ledger_id: str) -> dict[str, Any]:
        return _store_read(self, ledger_id)

    def compare_and_swap(self, transition: CasTransition) -> dict[str, Any]:
        return _store_compare_and_swap(self, transition)

    def _compare_and_swap_under_lease(
        self, transition: CasTransition, lease_descriptor: int
    ) -> dict[str, Any]:
        return _store_compare_and_swap_locked(self, transition, lease_descriptor)


@dataclass(frozen=True, slots=True)
class OperationResult:
    outcome: str
    provider_result_digest: str | None


def execute_claimed_phase(
    *, store: DurablePhaseLedgerStore, plan: Mapping[str, Any], ledger_id: str,
    expected_plan_digest: str,
    execution_authorization: Mapping[str, Any],
    executor_authority_evidence: Mapping[str, Any],
    authority_evaluation_at: datetime,
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
    clock: Callable[[], datetime],
    invoke_once: Callable[[Mapping[str, Any]], OperationResult],
) -> dict[str, Any]:
    """Enforce an already claimed phase, with one callback per exact operation.

    ``invoke_once`` is injected deliberately: this repository ships no AWS
    adapter and cannot create a client or session.  The callback contract is
    exactly one attempt.  The runner persists each result before continuing.
    """

    plan_snapshot = _canonical_snapshot(plan, "RUNNER_PLAN_SNAPSHOT_INVALID")
    if not isinstance(plan_snapshot, Mapping):
        _fail("RUNNER_PLAN_SNAPSHOT_INVALID")
    authorization_snapshot = _canonical_snapshot(
        execution_authorization, "RUNNER_AUTHORIZATION_SNAPSHOT_INVALID"
    )
    evidence_snapshot = _canonical_snapshot(
        executor_authority_evidence, "RUNNER_AUTHORITY_SNAPSHOT_INVALID"
    )
    predecessor_snapshot = _optional_mapping_snapshot(
        predecessor_record, "RUNNER_PREDECESSOR_SNAPSHOT_INVALID"
    )
    predecessor_binding_snapshot = _optional_mapping_snapshot(
        expected_predecessor_binding,
        "RUNNER_PREDECESSOR_BINDING_SNAPSHOT_INVALID",
    )
    if not isinstance(authorization_snapshot, Mapping) or not isinstance(
        evidence_snapshot, Mapping
    ):
        _fail("RUNNER_AUTHORIZATION_SNAPSHOT_INVALID")
    with store.execution_lease(ledger_id) as lease_descriptor:
        return _execute_claimed_phase_under_lease(
            store=store,
            plan_snapshot=plan_snapshot,
            ledger_id=ledger_id,
            expected_plan_digest=expected_plan_digest,
            execution_authorization=authorization_snapshot,
            executor_authority_evidence=evidence_snapshot,
            authority_evaluation_at=authority_evaluation_at,
            expected_initial_bundle_absence_digest=(
                expected_initial_bundle_absence_digest
            ),
            predecessor_record=predecessor_snapshot,
            expected_predecessor_binding=predecessor_binding_snapshot,
            lease_descriptor=lease_descriptor,
            clock=clock,
            invoke_once=invoke_once,
        )


def _execute_claimed_phase_under_lease(
    *,
    store: DurablePhaseLedgerStore,
    plan_snapshot: Mapping[str, Any],
    ledger_id: str,
    expected_plan_digest: str,
    execution_authorization: Mapping[str, Any],
    executor_authority_evidence: Mapping[str, Any],
    authority_evaluation_at: datetime,
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
    lease_descriptor: int,
    clock: Callable[[], datetime],
    invoke_once: Callable[[Mapping[str, Any]], OperationResult],
) -> dict[str, Any]:
    current = store.read(ledger_id)
    _validate_execution_authorization(current, execution_authorization)
    claim = current.get("claim")
    if (
        not isinstance(claim, Mapping)
        or claim.get("claim_nonce_digest")
        != execution_authorization.get("claim_nonce_digest")
    ):
        _fail("RUNNER_CLAIM_NONCE_NOT_AUTHORIZED")
    if current["status"] != "CLAIMED" or current["attempt_count"] != 1:
        _fail("RUNNER_LEDGER_NOT_CLAIMED")
    binding = _phase_binding_from_snapshot(
        plan_snapshot,
        phase=str(current["phase"]),
        expected_plan_digest=expected_plan_digest,
    )
    _validate_record_against_phase_binding(current, binding)
    _validate_phase_authority_evidence(
        plan_snapshot=plan_snapshot,
        record=current,
        evidence=executor_authority_evidence,
        evaluation_at=authority_evaluation_at,
    )
    validate_ledger(
        current,
        expected_plan_digest=binding["plan_digest"],
        expected_bundle_digest=binding["bundle_digest"],
        expected_phase=binding["phase"],
    )
    _validate_pre_effect_predecessor(
        plan_snapshot=plan_snapshot,
        current_record=current,
        expected_initial_bundle_absence_digest=(
            expected_initial_bundle_absence_digest
        ),
        predecessor_record=predecessor_record,
        expected_predecessor_binding=expected_predecessor_binding,
        effect_at=_parse_timestamp(
            current.get("claim", {}).get("claimed_at"), "CLAIMED_AT_INVALID"
        ),
    )
    candidates = [
        item for item in plan_snapshot.get("authorization_phases", [])
        if isinstance(item, Mapping) and item.get("phase") == current["phase"]
    ]
    revocation = plan_snapshot.get("revocation")
    if isinstance(revocation, Mapping) and revocation.get("phase") == current["phase"]:
        candidates.append(revocation)
    if len(candidates) != 1 or candidates[0].get("operations") is None:
        _fail("RUNNER_PHASE_OPERATIONS_INVALID")
    operations = candidates[0]["operations"]
    while current["status"] == "CLAIMED":
        now = _utc(clock(), "RUNNER_TIME_INVALID")
        if now < _parse_timestamp(
            current["authority_evaluation_at"],
            "AUTHORITY_EVALUATION_TIME_INVALID",
        ):
            _fail("RUNNER_AUTHORITY_EVALUATION_NOT_YET_VALID")
        if now >= min(
            _parse_timestamp(current["expires_at"], "EXPIRES_AT_INVALID"),
            _parse_timestamp(
                current["authority_session_expires_at"],
                "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
            ),
        ):
            _fail("RUNNER_LEDGER_EXPIRED")
        sequence = current["claim"]["next_operation_sequence"]
        operation = _canonical_snapshot(
            operations[sequence - 1], "RUNNER_OPERATION_SNAPSHOT_INVALID"
        )
        if operation.get("sequence") != sequence:
            _fail("RUNNER_OPERATION_SEQUENCE_INVALID")
        _operation_request_digest(operation)
        if (
            operation.get("request_digest")
            != current["ordered_request_digests"][sequence - 1]
            or operation.get("attempt_limit", 1) != 1
            or operation.get("retry_permitted", False) is not False
        ):
            _fail("RUNNER_OPERATION_BINDING_INVALID")
        in_flight = prepare_operation_in_flight(
            current,
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=now,
            operation_sequence=sequence,
        )
        current = store._compare_and_swap_under_lease(  # noqa: SLF001
            in_flight, lease_descriptor
        )
        before_invoke = _utc(clock(), "RUNNER_TIME_INVALID")
        effective_deadline = min(
            _parse_timestamp(current["expires_at"], "EXPIRES_AT_INVALID"),
            _parse_timestamp(
                current["authority_session_expires_at"],
                "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
            ),
        )
        if before_invoke < now:
            _fail("RUNNER_TIME_ROLLBACK")
        if before_invoke >= effective_deadline:
            return store._compare_and_swap_under_lease(  # noqa: SLF001
                prepare_operation_record(
                    current,
                    expected_version=current["ledger_version"],
                    expected_digest=current["ledger_digest"],
                    at=before_invoke,
                    operation_sequence=sequence,
                    outcome="AMBIGUOUS",
                    provider_result_digest=None,
                ),
                lease_descriptor,
            )
        try:
            result = invoke_once(
                _canonical_snapshot(
                    operation, "RUNNER_CALLBACK_OPERATION_SNAPSHOT_INVALID"
                )
            )
        except BaseException:
            after = _utc(clock(), "RUNNER_TIME_INVALID")
            if after < before_invoke:
                _fail("RUNNER_TIME_ROLLBACK")
            current = store._compare_and_swap_under_lease(  # noqa: SLF001
                prepare_operation_record(
                    current,
                    expected_version=current["ledger_version"],
                    expected_digest=current["ledger_digest"],
                    at=after,
                    operation_sequence=sequence,
                    outcome="AMBIGUOUS",
                    provider_result_digest=None,
                ),
                lease_descriptor,
            )
            return current
        if not isinstance(result, OperationResult):
            result = OperationResult("AMBIGUOUS", None)
        after = _utc(clock(), "RUNNER_TIME_INVALID")
        if after < before_invoke:
            _fail("RUNNER_TIME_ROLLBACK")
        if after >= min(
            _parse_timestamp(current["expires_at"], "EXPIRES_AT_INVALID"),
            _parse_timestamp(
                current["authority_session_expires_at"],
                "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
            ),
        ):
            # The provider outcome is now ambiguous relative to the durable
            # validity window.  Persist AMBIGUOUS and never invoke again.
            result = OperationResult("AMBIGUOUS", None)
        transition = prepare_operation_record(
            current,
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=after,
            operation_sequence=sequence,
            outcome=result.outcome,
            provider_result_digest=result.provider_result_digest,
        )
        current = store._compare_and_swap_under_lease(  # noqa: SLF001
            transition, lease_descriptor
        )
        if current["status"] in {"AMBIGUOUS", "CONSUMED"}:
            break
    return current


def recover_persisted_in_flight(
    *, store: DurablePhaseLedgerStore, ledger_id: str, at: datetime
) -> dict[str, Any]:
    """Convert a crash-surviving IN_FLIGHT record to durable AMBIGUOUS."""

    with store.execution_lease(ledger_id) as lease_descriptor:
        current = store.read(ledger_id)
        if current["status"] != "IN_FLIGHT":
            _fail("RUNNER_LEDGER_NOT_IN_FLIGHT")
        operation = current["in_flight_operation"]
        transition = prepare_operation_record(
            current,
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=at,
            operation_sequence=operation["operation_sequence"],
            outcome="AMBIGUOUS",
            provider_result_digest=None,
        )
        return store._compare_and_swap_under_lease(  # noqa: SLF001
            transition, lease_descriptor
        )


def _store_read(
    store: DurablePhaseLedgerStore, ledger_id: str
) -> dict[str, Any]:
    root_fd = store._validated_root_fd()  # noqa: SLF001
    try:
        name = store._name(ledger_id)  # noqa: SLF001
        descriptor, metadata = _open_regular_private(root_fd, name)
        try:
            value = _read_record(descriptor)
            _verify_open_file_binding(
                root_fd, name, descriptor, expected_link_count=1
            )
            final = os.fstat(descriptor)
            if (final.st_dev, final.st_ino, final.st_size) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
            ):
                _fail("LEDGER_FILE_CHANGED")
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    if value.get("ledger_id") != ledger_id:
        _fail("LEDGER_FILE_BINDING_MISMATCH")
    validate_ledger(value)
    return value


def _store_compare_and_swap(
    store: DurablePhaseLedgerStore, transition: CasTransition
) -> dict[str, Any]:
    snapshot = _snapshot_transition(transition)
    ledger_id = str(snapshot.proposed_record.get("ledger_id", ""))
    with store.execution_lease(ledger_id) as lease_descriptor:
        return _store_compare_and_swap_locked(
            store, snapshot, lease_descriptor, already_snapshotted=True
        )


def _snapshot_transition(transition: CasTransition) -> CasTransition:
    proposed = _canonical_snapshot(
        transition.proposed_record, "LEDGER_CAS_SNAPSHOT_INVALID"
    )
    if not isinstance(proposed, dict):
        _fail("LEDGER_CAS_SNAPSHOT_INVALID")
    return CasTransition(
        expected_version=transition.expected_version,
        expected_digest=str(transition.expected_digest),
        proposed_record=proposed,
        attempt_limit=transition.attempt_limit,
        retry_permitted=transition.retry_permitted,
    )


def _store_compare_and_swap_locked(
    store: DurablePhaseLedgerStore,
    transition: CasTransition,
    lease_descriptor: int,
    already_snapshotted: bool = False,
) -> dict[str, Any]:
    """Lock, verify current CAS, and atomically replace exactly once."""

    frozen = transition if already_snapshotted else _snapshot_transition(transition)
    if frozen.attempt_limit != 1 or frozen.retry_permitted:
        _fail("LEDGER_CAS_RETRY_INVALID")
    proposed = frozen.proposed_record
    validate_ledger(proposed)
    root_fd = store._validated_root_fd()  # noqa: SLF001
    descriptor: int | None = None
    temporary = ""
    try:
        name = store._name(str(proposed["ledger_id"]))  # noqa: SLF001
        _verify_lease_descriptor(
            root_fd,
            store._lock_name(str(proposed["ledger_id"])),  # noqa: SLF001
            lease_descriptor,
        )
        descriptor, metadata = _open_regular_private(root_fd, name)
        current = _read_record(descriptor)
        _verify_open_file_binding(root_fd, name, descriptor, expected_link_count=1)
        validate_ledger(current)
        if (
            current["ledger_version"] != frozen.expected_version
            or current["ledger_digest"] != frozen.expected_digest
            or proposed["previous_ledger_digest"]
            != current["ledger_digest"]
            or proposed["ledger_version"]
            != current["ledger_version"] + 1
            or proposed["initial_ledger_digest"]
            != current["initial_ledger_digest"]
        ):
            _fail("LEDGER_CAS_CONFLICT")
        current_path = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (current_path.st_dev, current_path.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            _fail("LEDGER_FILE_CHANGED")
        temporary = f".gug365-ledger-{os.getpid()}-{secrets.token_hex(12)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_nofollow()
        target = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        try:
            os.fchmod(target, 0o600)
            _reject_fd_acl(target, "LEDGER_FILE_ACL_FORBIDDEN")
            _write_all(target, _record_bytes(proposed))
            _durable_sync(target)
            target_metadata = os.fstat(target)
            if (
                target_metadata.st_uid != os.geteuid()
                or target_metadata.st_nlink != 1
                or stat.S_IMODE(target_metadata.st_mode) != 0o600
            ):
                _fail("LEDGER_FILE_INVALID")
            _durable_sync(root_fd)
            _verify_open_file_binding(
                root_fd, temporary, target, expected_link_count=1
            )
            _verify_open_file_binding(
                root_fd, name, descriptor, expected_link_count=1
            )
            os.replace(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            temporary = ""
            _verify_open_file_binding(
                root_fd, name, target, expected_link_count=1
            )
            _durable_sync(root_fd)
        finally:
            os.close(target)
        published_descriptor, _published_metadata = _open_regular_private(
            root_fd, name
        )
        try:
            published = _read_record(published_descriptor)
            _verify_open_file_binding(
                root_fd, name, published_descriptor, expected_link_count=1
            )
        finally:
            os.close(published_descriptor)
        validate_ledger(published)
        if published != proposed:
            _fail("LEDGER_CAS_READBACK_MISMATCH")
        return published
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.close(root_fd)

def _reject_cloud_xattrs(path: Path) -> None:
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None and sys.platform == "darwin":
        attributes: list[str] = []
        for candidate in (path, *path.parents):
            try:
                result = subprocess.run(
                    ["/usr/bin/xattr", os.fspath(candidate)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env={"PATH": "/usr/bin:/bin"},
                )
            except (OSError, subprocess.SubprocessError):
                _fail("LEDGER_ROOT_CLOUD_STATUS_UNVERIFIED")
            if result.returncode != 0:
                _fail("LEDGER_ROOT_CLOUD_STATUS_UNVERIFIED")
            attributes.extend(result.stdout.splitlines())
    elif listxattr is None:
        return
    else:
        attributes: list[str] = []
        for candidate in (path, *path.parents):
            try:
                attributes.extend(listxattr(candidate, follow_symlinks=False))
            except OSError as exc:
                if exc.errno in {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
                    continue
                _fail("LEDGER_ROOT_CLOUD_STATUS_UNVERIFIED")
    if any(marker in attribute.casefold() for attribute in attributes for marker in _CLOUD_XATTR_MARKERS):
        _fail("LEDGER_ROOT_CLOUD_MANAGED_FORBIDDEN")


def _reject_extended_acl(path: Path, code: str) -> None:
    """Reject POSIX/macOS ACLs that mode bits do not represent."""

    if sys.platform.startswith("linux"):
        listxattr = getattr(os, "listxattr", None)
        if listxattr is None:
            _fail("LEDGER_ACL_STATUS_UNVERIFIED")
        try:
            attributes = listxattr(path, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in {
                errno.ENOTSUP,
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
            }:
                return
            _fail("LEDGER_ACL_STATUS_UNVERIFIED")
        if any(str(item).startswith("system.posix_acl_") for item in attributes):
            _fail(code)
        return
    if sys.platform != "darwin":
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    try:
        result = subprocess.run(
            ["/bin/ls", "-lde", os.fspath(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    if result.returncode != 0:
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    lines = result.stdout.splitlines()
    if any(re.match(r"^\s*\d+:\s", line) for line in lines[1:]):
        _fail(code)


def _fd_xattrs(descriptor: int) -> list[str]:
    """List attributes from the opened inode, never by a mutable pathname."""

    listxattr = getattr(os, "listxattr", None)
    if listxattr is not None:
        try:
            return [str(item) for item in listxattr(descriptor)]
        except OSError:
            _fail("LEDGER_XATTR_STATUS_UNVERIFIED")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        flistxattr = libc.flistxattr
        if sys.platform == "darwin":
            flistxattr.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_int,
            ]
        elif sys.platform.startswith("linux"):
            flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        else:
            _fail("LEDGER_XATTR_STATUS_UNVERIFIED")
        flistxattr.restype = ctypes.c_ssize_t
        ctypes.set_errno(0)
        size = (
            flistxattr(descriptor, None, 0, 0)
            if sys.platform == "darwin"
            else flistxattr(descriptor, None, 0)
        )
        if size < 0:
            _fail("LEDGER_XATTR_STATUS_UNVERIFIED")
        if size == 0:
            return []
        buffer = ctypes.create_string_buffer(size)
        actual = (
            flistxattr(descriptor, buffer, size, 0)
            if sys.platform == "darwin"
            else flistxattr(descriptor, buffer, size)
        )
        if actual < 0 or actual > size:
            _fail("LEDGER_XATTR_STATUS_UNVERIFIED")
        return [
            item.decode("utf-8", "strict")
            for item in buffer.raw[:actual].split(b"\0")
            if item
        ]
    except (AttributeError, OSError, UnicodeDecodeError):
        _fail("LEDGER_XATTR_STATUS_UNVERIFIED")


def _reject_fd_cloud_xattrs(descriptor: int) -> None:
    attributes = _fd_xattrs(descriptor)
    if any(
        marker in attribute.casefold()
        for attribute in attributes
        for marker in _CLOUD_XATTR_MARKERS
    ):
        _fail("LEDGER_ROOT_CLOUD_MANAGED_FORBIDDEN")


def _reject_fd_acl(descriptor: int, code: str) -> None:
    if sys.platform.startswith("linux"):
        attributes = _fd_xattrs(descriptor)
        if any(str(item).startswith("system.posix_acl_") for item in attributes):
            _fail(code)
        return
    if sys.platform != "darwin":
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        acl_get_fd_np = libc.acl_get_fd_np
        acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        acl_get_fd_np.restype = ctypes.c_void_p
        acl_free = libc.acl_free
        acl_free.argtypes = [ctypes.c_void_p]
        acl_free.restype = ctypes.c_int
        ctypes.set_errno(0)
        acl = acl_get_fd_np(descriptor, _DARWIN_ACL_TYPE_EXTENDED)
        captured_errno = ctypes.get_errno()
    except (AttributeError, OSError):
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    if not acl:
        if captured_errno == errno.ENOENT:
            return
        _fail("LEDGER_ACL_STATUS_UNVERIFIED")
    try:
        _fail(code)
    finally:
        if acl_free(acl) != 0:
            _fail("LEDGER_ACL_STATUS_UNVERIFIED")


def _require_local_filesystem_fd(descriptor: int) -> None:
    """Prove durable-local filesystem type from the held root descriptor."""

    if sys.platform == "darwin":
        if (
            ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(_DarwinStatfs) != 2168
        ):
            _fail("LEDGER_FILESYSTEM_ABI_UNSUPPORTED")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            fstatfs = libc.fstatfs
            fstatfs.restype = ctypes.c_int
            fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatfs)]
            value = _DarwinStatfs()
            if fstatfs(descriptor, ctypes.byref(value)) != 0:
                _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        except (AttributeError, OSError):
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        filesystem_type = bytes(value.f_fstypename).split(b"\0", 1)[0]
        if (
            value.f_flags & _DARWIN_MNT_LOCAL == 0
            or filesystem_type not in {b"apfs", b"hfs"}
        ):
            _fail("LEDGER_FILESYSTEM_NOT_LOCAL")
        return
    if not sys.platform.startswith("linux"):
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    metadata = os.fstat(descriptor)
    expected_device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    try:
        with open(
            "/proc/self/mountinfo", encoding="utf-8", errors="strict"
        ) as mountinfo:
            lines = mountinfo.read(4 * 1024 * 1024 + 1).splitlines()
    except (OSError, UnicodeError):
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    if not lines or sum(len(line) + 1 for line in lines) > 4 * 1024 * 1024:
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    matching_types: set[str] = set()
    for line in lines:
        fields = line.split()
        if "-" not in fields or len(fields) < 7:
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        separator = fields.index("-")
        if separator < 6 or len(fields) <= separator + 1 or ":" not in fields[2]:
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        if fields[2] == expected_device:
            matching_types.add(fields[separator + 1].casefold())
    if len(matching_types) != 1:
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    if next(iter(matching_types)) not in _LOCAL_LINUX_FILESYSTEM_TYPES:
        _fail("LEDGER_FILESYSTEM_NOT_LOCAL")


def _require_local_filesystem(path: Path) -> None:
    """Fail closed unless the custody root is on a local filesystem."""

    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/sbin/mount"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin:/sbin"},
            )
        except (OSError, subprocess.SubprocessError):
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        if result.returncode != 0:
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        candidate = os.fspath(path.resolve(strict=True))
        matches: list[tuple[int, str]] = []
        for line in result.stdout.splitlines():
            match = re.match(r"^.+ on (.+) \(([^)]*)\)$", line)
            if match is None:
                continue
            mount_point, options = match.groups()
            if candidate == mount_point or candidate.startswith(mount_point.rstrip("/") + "/"):
                matches.append((len(mount_point), options))
        if not matches:
            _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
        options = max(matches)[1].casefold()
        tokens = {item.strip() for item in options.split(",")}
        if (
            "local" not in tokens
            or not tokens & {"apfs", "hfs", "hfs+"}
            or tokens & {
            "nfs",
            "smbfs",
            "afpfs",
            "webdav",
            "autofs",
            }
        ):
            _fail("LEDGER_FILESYSTEM_NOT_LOCAL")
        return
    if not sys.platform.startswith("linux"):
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    try:
        result = subprocess.run(
            ["df", "-P", "-T", os.fspath(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    if result.returncode != 0:
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    lines = result.stdout.splitlines()
    if len(lines) < 2:
        _fail("LEDGER_FILESYSTEM_STATUS_UNVERIFIED")
    filesystem_type = lines[-1].split()[1].casefold()
    if filesystem_type not in {
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
    }:
        _fail("LEDGER_FILESYSTEM_NOT_LOCAL")


def _open_regular_private(
    root_fd: int, name: str, *, writable: bool = False
) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(
            name,
            (os.O_RDWR if writable else os.O_RDONLY) | _required_nofollow(),
            dir_fd=root_fd,
        )
    except OSError:
        _fail("LEDGER_FILE_INVALID")
    try:
        metadata = os.fstat(descriptor)
        _reject_fd_acl(descriptor, "LEDGER_FILE_ACL_FORBIDDEN")
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (current.st_dev, current.st_ino, current.st_uid)
            != (metadata.st_dev, metadata.st_ino, metadata.st_uid)
        ):
            _fail("LEDGER_FILE_INVALID")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, metadata


def _verify_open_file_binding(
    root_fd: int,
    name: str,
    descriptor: int,
    *,
    expected_link_count: int,
) -> None:
    """Bind an already validated fd to the exact path immediately before use."""

    try:
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        _fail("LEDGER_FILE_CHANGED")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or metadata.st_uid != os.geteuid()
        or current.st_uid != os.geteuid()
        or metadata.st_nlink != expected_link_count
        or current.st_nlink != expected_link_count
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or stat.S_IMODE(current.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino, metadata.st_uid)
        != (current.st_dev, current.st_ino, current.st_uid)
    ):
        _fail("LEDGER_FILE_CHANGED")


def _verify_lease_descriptor(
    root_fd: int, name: str, descriptor: int
) -> None:
    """Bind a held stable lease fd to the exact non-replaced lock path."""

    metadata = os.fstat(descriptor)
    current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino)
        != (current.st_dev, current.st_ino)
    ):
        _fail("LEDGER_LEASE_INVALID")
    _reject_fd_acl(descriptor, "LEDGER_FILE_ACL_FORBIDDEN")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            _fail("LEDGER_FILE_WRITE_FAILED")
        remaining = remaining[written:]


def _record_bytes(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _read_record(descriptor: int) -> dict[str, Any]:
    payload = bytearray()
    while len(payload) <= 8 * 1024 * 1024:
        chunk = os.read(descriptor, 65_536)
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > 8 * 1024 * 1024:
        _fail("LEDGER_FILE_TOO_LARGE")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("LEDGER_FILE_JSON_INVALID")
    if not isinstance(value, dict):
        _fail("LEDGER_FILE_JSON_INVALID")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_snapshot(value: Any, code: str) -> Any:
    """Take one detached canonical snapshot and reject non-JSON values."""

    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(code)


def _optional_mapping_snapshot(
    value: Mapping[str, Any] | None, code: str
) -> dict[str, Any] | None:
    if value is None:
        return None
    snapshot = _canonical_snapshot(value, code)
    if not isinstance(snapshot, dict):
        _fail(code)
    return snapshot


def _immutable_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact projection from which ``ledger_id`` is derived."""

    return {
        "plan_digest": record.get("plan_digest"),
        "bundle_digest": record.get("bundle_digest"),
        "account_id": record.get("account_id"),
        "region": record.get("region"),
        "phase": record.get("phase"),
        "ordered_operations_digest": record.get("ordered_operations_digest"),
        "operation_count": record.get("operation_count"),
        "ordered_request_digests": record.get("ordered_request_digests"),
        "profile_class": record.get("profile_class"),
        "caller_arn_digest": record.get("caller_arn_digest"),
        "executor_authority_evidence_digest": record.get(
            "executor_authority_evidence_digest"
        ),
        "authority_session_identifier_digest": record.get(
            "authority_session_identifier_digest"
        ),
        "authority_session_issued_at": record.get("authority_session_issued_at"),
        "authority_session_expires_at": record.get("authority_session_expires_at"),
        "authority_evidence_collected_at": record.get(
            "authority_evidence_collected_at"
        ),
        "authority_evaluation_at": record.get("authority_evaluation_at"),
        "not_before": record.get("not_before"),
        "expires_at": record.get("expires_at"),
        "host_digest": record.get("host_digest"),
        "predecessor_phase": record.get("predecessor_phase"),
        "predecessor_terminal_receipt_digest": record.get(
            "predecessor_terminal_receipt_digest"
        ),
        "predecessor_ledger_digest": record.get("predecessor_ledger_digest"),
        "before_state_digest": record.get("before_state_digest"),
        "required_predecessor_checkpoint_digest": record.get(
            "required_predecessor_checkpoint_digest"
        ),
    }


def _prepared_baseline(record: Mapping[str, Any]) -> dict[str, Any]:
    """Reconstruct the v1 PREPARED record used for the immutable root."""

    return {
        "record_type": RECORD_TYPE,
        "schema_version": RECORD_VERSION,
        "ledger_id": record.get("ledger_id"),
        "ledger_version": 1,
        "initial_ledger_digest": "",
        "previous_ledger_digest": None,
        **_immutable_projection(record),
        "status": "PREPARED",
        "attempt_count": 0,
        "claim": None,
        "operation_outcomes": [],
        "in_flight_operation": None,
        "reconciliation": None,
        "receipt_chain": [],
    }


def _fail(code: str) -> None:
    raise PhaseLedgerError(code)


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail(code)
    return value


def _utc(value: datetime, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return _utc(value, "TIME_INVALID").isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)
    if parsed.microsecond != 0:
        _fail(code)
    return parsed


def _operation_request_digest(operation: Mapping[str, Any]) -> str:
    request = operation.get("request")
    supplied = _require_digest(
        operation.get("request_digest"), "OPERATION_REQUEST_DIGEST_INVALID"
    )
    if not isinstance(request, Mapping) or canonical_digest(request) != supplied:
        _fail("OPERATION_REQUEST_DIGEST_MISMATCH")
    if (
        operation.get("attempt_limit", 1) != 1
        or operation.get("retry_permitted", False) is not False
    ):
        _fail("OPERATION_RETRY_CONTRACT_INVALID")
    return supplied


def phase_binding_from_plan(
    plan: Mapping[str, Any], *, phase: str, expected_plan_digest: str
) -> dict[str, Any]:
    """Snapshot a plan once and extract one exact immutable phase binding."""

    snapshot = _canonical_snapshot(plan, "PLAN_SNAPSHOT_INVALID")
    if not isinstance(snapshot, dict):
        _fail("PLAN_SNAPSHOT_INVALID")
    return _phase_binding_from_snapshot(
        snapshot, phase=phase, expected_plan_digest=expected_plan_digest
    )


def _phase_binding_from_snapshot(
    plan: Mapping[str, Any], *, phase: str, expected_plan_digest: str
) -> dict[str, Any]:
    """Extract a binding from an already detached canonical plan snapshot."""

    plan_digest = _require_digest(plan.get("plan_digest"), "PLAN_DIGEST_INVALID")
    independently_expected = _require_digest(
        expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID"
    )
    if plan_digest != independently_expected:
        _fail("PLAN_DIGEST_NOT_AUTHORIZED")
    if canonical_digest({k: v for k, v in plan.items() if k != "plan_digest"}) != plan_digest:
        _fail("PLAN_DIGEST_MISMATCH")
    planned_phases = plan.get("authorization_phases")
    if (
        not isinstance(planned_phases, list)
        or tuple(
            item.get("phase") if isinstance(item, Mapping) else None
            for item in planned_phases
        )
        != FORWARD_PHASES
        or not isinstance(plan.get("revocation"), Mapping)
        or plan.get("revocation", {}).get("phase") != "REVOCATOR"
    ):
        _fail("CANONICAL_AUTHORIZATION_PHASE_SET_INVALID")
    candidates = [
        item
        for item in planned_phases
        if isinstance(item, Mapping) and item.get("phase") == phase
    ]
    revocation = plan.get("revocation")
    if isinstance(revocation, Mapping) and revocation.get("phase") == phase:
        candidates.append(revocation)
    if len(candidates) != 1:
        _fail("PHASE_BINDING_INVALID")
    selected = candidates[0]
    operations = selected.get("operations")
    if not isinstance(operations, list) or not operations:
        _fail("PHASE_OPERATIONS_INVALID")
    if [item.get("sequence") for item in operations if isinstance(item, Mapping)] != list(
        range(1, len(operations) + 1)
    ):
        _fail("PHASE_OPERATION_ORDER_INVALID")
    request_digests = [
        _operation_request_digest(item)
        for item in operations
        if isinstance(item, Mapping)
    ]
    if len(request_digests) != len(operations):
        _fail("PHASE_OPERATIONS_INVALID")
    target = plan.get("target")
    if not isinstance(target, Mapping):
        _fail("PLAN_TARGET_INVALID")
    account_id = target.get("authority_account_id")
    region = target.get("region")
    if not isinstance(account_id, str) or _ACCOUNT_RE.fullmatch(account_id) is None:
        _fail("PLAN_ACCOUNT_INVALID")
    if not isinstance(region, str) or _REGION_RE.fullmatch(region) is None:
        _fail("PLAN_REGION_INVALID")
    return {
        "plan_digest": plan_digest,
        "bundle_digest": canonical_digest(
            {
                "boundary_set_digest": plan.get("boundary_set_digest"),
                "child_role_set_digest": plan.get("child_role_set_digest"),
                "service_role_digest": plan.get("service_role_digest"),
                "ledger_table_digest": plan.get("ledger_table_digest"),
                "broker_function_digest": plan.get("broker_function_digest"),
                "ledger_factory_function_digest": plan.get(
                    "ledger_factory_function_digest"
                ),
                "ledger_factory_log_group_digest": plan.get(
                    "ledger_factory_log_group_digest"
                ),
                "planned_iam_write_digest": plan.get("planned_iam_write_digest"),
                "planned_readback_digest": plan.get("planned_readback_digest"),
            }
        ),
        "account_id": account_id,
        "region": region,
        "phase": phase,
        "ordered_operations_digest": canonical_digest(operations),
        "operation_count": len(operations),
        "ordered_request_digests": request_digests,
    }


def _validate_record_against_phase_binding(
    record: Mapping[str, Any], binding: Mapping[str, Any]
) -> None:
    """Require an exact authorized-plan binding before any effect or proof."""

    fields = (
        "plan_digest",
        "bundle_digest",
        "account_id",
        "region",
        "phase",
        "ordered_operations_digest",
        "operation_count",
        "ordered_request_digests",
    )
    if any(record.get(field) != binding.get(field) for field in fields):
        _fail("LEDGER_AUTHORIZED_PHASE_BINDING_MISMATCH")


def _validate_pre_effect_predecessor(
    *,
    plan_snapshot: Mapping[str, Any],
    current_record: Mapping[str, Any],
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
    effect_at: datetime,
) -> None:
    """Prove the exact predecessor (or owner-bound initial absence) pre-effect."""

    phases = plan_snapshot.get("authorization_phases")
    if not isinstance(phases, list):
        _fail("PHASE_PRECONDITION_PLAN_INVALID")
    phase_names = [
        item.get("phase") if isinstance(item, Mapping) else None for item in phases
    ]
    if tuple(phase_names) != FORWARD_PHASES:
        _fail("CANONICAL_AUTHORIZATION_PHASE_SET_INVALID")
    try:
        phase_index = phase_names.index(current_record.get("phase"))
    except ValueError:
        _fail("PHASE_PRECONDITION_PHASE_INVALID")
    at = _utc(effect_at, "PHASE_PRECONDITION_TIME_INVALID")

    if phase_index == 0:
        if predecessor_record is not None or expected_predecessor_binding is not None:
            _fail("INITIAL_PHASE_PREDECESSOR_FORBIDDEN")
        initial_absence = _require_digest(
            expected_initial_bundle_absence_digest,
            "EXPECTED_INITIAL_BUNDLE_ABSENCE_DIGEST_INVALID",
        )
        if (
            current_record.get("before_state_digest") != initial_absence
            or current_record.get("required_predecessor_checkpoint_digest")
            != initial_absence
            or current_record.get("predecessor_phase") is not None
            or current_record.get("predecessor_terminal_receipt_digest") is not None
            or current_record.get("predecessor_ledger_digest") is not None
        ):
            _fail("INITIAL_PHASE_PRECONDITION_MISMATCH")
        return

    if expected_initial_bundle_absence_digest is not None:
        _fail("LATER_PHASE_INITIAL_ABSENCE_FORBIDDEN")
    if not isinstance(predecessor_record, Mapping) or not isinstance(
        expected_predecessor_binding, Mapping
    ):
        _fail("PREDECESSOR_RECORD_AND_BINDING_REQUIRED")
    if set(expected_predecessor_binding) != _PREDECESSOR_EXECUTION_BINDING_FIELDS:
        _fail("PREDECESSOR_EXECUTION_BINDING_FIELDS_INVALID")

    previous_phase_item = phases[phase_index - 1]
    assert isinstance(previous_phase_item, Mapping)
    previous_phase = str(previous_phase_item.get("phase"))
    checkpoint = _require_digest(
        previous_phase_item.get("checkpoint_digest"),
        "PREDECESSOR_CHECKPOINT_DIGEST_INVALID",
    )
    previous_binding = _phase_binding_from_snapshot(
        plan_snapshot,
        phase=previous_phase,
        expected_plan_digest=str(current_record.get("plan_digest")),
    )
    _validate_record_against_phase_binding(predecessor_record, previous_binding)
    receipts = predecessor_record.get("receipt_chain")
    if not isinstance(receipts, list) or not receipts:
        _fail("PREDECESSOR_TERMINAL_RECEIPT_MISSING")
    terminal_receipt = receipts[-1]
    if not isinstance(terminal_receipt, Mapping):
        _fail("PREDECESSOR_TERMINAL_RECEIPT_MISSING")
    for field in (
        "phase",
        "ledger_id",
        "initial_ledger_digest",
        "ledger_digest",
    ):
        if expected_predecessor_binding.get(field) != predecessor_record.get(field):
            _fail("PREDECESSOR_EXECUTION_BINDING_MISMATCH")
    claim = predecessor_record.get("claim")
    if (
        not isinstance(claim, Mapping)
        or expected_predecessor_binding.get("claim_nonce_digest")
        != claim.get("claim_nonce_digest")
        or expected_predecessor_binding.get("terminal_receipt_digest")
        != terminal_receipt.get("receipt_digest")
        or expected_predecessor_binding.get("checkpoint_digest") != checkpoint
    ):
        _fail("PREDECESSOR_EXECUTION_BINDING_MISMATCH")
    validate_consumed_causal_record(
        predecessor_record,
        expected_plan_digest=str(current_record.get("plan_digest")),
        expected_bundle_digest=str(current_record.get("bundle_digest")),
        expected_phase=previous_phase,
        expected_ledger_id=str(expected_predecessor_binding.get("ledger_id")),
        expected_initial_ledger_digest=str(
            expected_predecessor_binding.get("initial_ledger_digest")
        ),
        expected_claim_nonce_digest=str(
            expected_predecessor_binding.get("claim_nonce_digest")
        ),
        expected_terminal_receipt_digest=str(
            expected_predecessor_binding.get("terminal_receipt_digest")
        ),
        accepted_reconciliation=(),
    )
    terminal_at = _parse_timestamp(
        terminal_receipt.get("at"), "PREDECESSOR_TERMINAL_TIME_INVALID"
    )
    previous_session_expires = _parse_timestamp(
        predecessor_record.get("authority_session_expires_at"),
        "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
    )
    current_session_issued = _parse_timestamp(
        current_record.get("authority_session_issued_at"),
        "AUTHORITY_SESSION_ISSUED_AT_INVALID",
    )
    if (
        current_record.get("predecessor_phase") != previous_phase
        or current_record.get("predecessor_terminal_receipt_digest")
        != terminal_receipt.get("receipt_digest")
        or current_record.get("predecessor_ledger_digest")
        != predecessor_record.get("ledger_digest")
        or current_record.get("before_state_digest") != checkpoint
        or current_record.get("required_predecessor_checkpoint_digest")
        != checkpoint
        or previous_session_expires > current_session_issued
        or terminal_at >= at
    ):
        _fail("PREDECESSOR_PHASE_PRECONDITION_MISMATCH")


def _validate_execution_authorization(
    record: Mapping[str, Any], authorization: Mapping[str, Any]
) -> None:
    """Require an independently delivered exact pre-effect authorization."""

    if (
        not isinstance(authorization, Mapping)
        or set(authorization) != _EXECUTION_AUTHORIZATION_FIELDS
    ):
        _fail("PHASE_EXECUTION_AUTHORIZATION_FIELDS_INVALID")
    for field in _EXECUTION_AUTHORIZATION_FIELDS - {
        "claim_nonce_digest",
    }:
        if authorization.get(field) != record.get(field):
            _fail("PHASE_EXECUTION_AUTHORIZATION_BINDING_MISMATCH")
    for field in (
        "ledger_id",
        "initial_ledger_digest",
        "claim_nonce_digest",
        "plan_digest",
        "bundle_digest",
        "caller_arn_digest",
        "executor_authority_evidence_digest",
        "authority_session_identifier_digest",
        "ordered_operations_digest",
        "host_digest",
        "before_state_digest",
        "required_predecessor_checkpoint_digest",
    ):
        _require_digest(
            authorization.get(field), "PHASE_EXECUTION_AUTHORIZATION_DIGEST_INVALID"
        )
    for field in (
        "predecessor_terminal_receipt_digest",
        "predecessor_ledger_digest",
    ):
        value = authorization.get(field)
        if value is not None:
            _require_digest(
                value, "PHASE_EXECUTION_AUTHORIZATION_DIGEST_INVALID"
            )
    issued = _parse_timestamp(
        authorization.get("authority_session_issued_at"),
        "AUTHORITY_SESSION_ISSUED_AT_INVALID",
    )
    collected = _parse_timestamp(
        authorization.get("authority_evidence_collected_at"),
        "AUTHORITY_EVIDENCE_COLLECTED_AT_INVALID",
    )
    evaluated = _parse_timestamp(
        authorization.get("authority_evaluation_at"),
        "AUTHORITY_EVALUATION_TIME_INVALID",
    )
    session_expires = _parse_timestamp(
        authorization.get("authority_session_expires_at"),
        "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
    )
    not_before = _parse_timestamp(
        authorization.get("not_before"), "NOT_BEFORE_INVALID"
    )
    expires_at = _parse_timestamp(
        authorization.get("expires_at"), "EXPIRES_AT_INVALID"
    )
    if not (
        issued <= collected <= evaluated <= not_before < expires_at <= session_expires
        and (session_expires - issued).total_seconds() <= 900
    ):
        _fail("PHASE_EXECUTION_AUTHORIZATION_SESSION_INVALID")


def _validate_phase_authority_evidence(
    *,
    plan_snapshot: Mapping[str, Any],
    record: Mapping[str, Any],
    evidence: Mapping[str, Any],
    evaluation_at: datetime,
) -> None:
    """Validate the exact fresh sole-and-capped session before any effect."""

    if not isinstance(evidence, Mapping) or set(evidence) != _AUTHORITY_EVIDENCE_FIELDS:
        _fail("EXECUTOR_AUTHORITY_EVIDENCE_FIELDS_INVALID")
    candidates = [
        item
        for item in plan_snapshot.get("authorization_phases", [])
        if isinstance(item, Mapping) and item.get("phase") == record.get("phase")
    ]
    if len(candidates) != 1:
        _fail("EXECUTOR_AUTHORITY_PHASE_INVALID")
    requirement = candidates[0].get("executor_effective_authority_requirement")
    if not isinstance(requirement, Mapping):
        _fail("EXECUTOR_AUTHORITY_REQUIREMENT_MISSING")
    required_policy_digest = _require_digest(
        requirement.get("required_policy_document_digest"),
        "EXECUTOR_AUTHORITY_POLICY_DIGEST_INVALID",
    )
    accepted_caps = requirement.get("accepted_cap_sources")
    maximum_lifetime = requirement.get("maximum_session_lifetime_seconds")
    if (
        not isinstance(accepted_caps, list)
        or not accepted_caps
        or type(maximum_lifetime) is not int
        or not 1 <= maximum_lifetime <= 900
    ):
        _fail("EXECUTOR_AUTHORITY_REQUIREMENT_INVALID")
    supplied_digest = _require_digest(
        evidence.get("evidence_digest"),
        "EXECUTOR_AUTHORITY_EVIDENCE_DIGEST_INVALID",
    )
    calculated_digest = canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    issued = _parse_timestamp(
        evidence.get("session_issued_at"), "AUTHORITY_SESSION_ISSUED_AT_INVALID"
    )
    collected = _parse_timestamp(
        evidence.get("evidence_collected_at"),
        "AUTHORITY_EVIDENCE_COLLECTED_AT_INVALID",
    )
    expires = _parse_timestamp(
        evidence.get("session_expires_at"), "AUTHORITY_SESSION_EXPIRES_AT_INVALID"
    )
    evaluated = _utc(evaluation_at, "AUTHORITY_EVALUATION_TIME_INVALID")
    bound_evaluation = _parse_timestamp(
        record.get("authority_evaluation_at"),
        "AUTHORITY_EVALUATION_TIME_INVALID",
    )
    not_before = _parse_timestamp(record.get("not_before"), "NOT_BEFORE_INVALID")
    ledger_expires = _parse_timestamp(record.get("expires_at"), "EXPIRES_AT_INVALID")
    lifetime = evidence.get("session_lifetime_seconds")
    remaining = evidence.get("session_remaining_seconds")
    if (
        supplied_digest != calculated_digest
        or supplied_digest != record.get("executor_authority_evidence_digest")
        or evidence.get("record_type")
        != "scanalyze.platform_authority.gug365_executor_authority_evidence.v1"
        or evidence.get("phase") != record.get("phase")
        or evidence.get("caller_account_id") != record.get("account_id")
        or evidence.get("region") != record.get("region")
        or evidence.get("caller_arn_digest") != record.get("caller_arn_digest")
        or evidence.get("session_identifier_digest")
        != record.get("authority_session_identifier_digest")
        or evidence.get("session_issued_at")
        != record.get("authority_session_issued_at")
        or evidence.get("session_expires_at")
        != record.get("authority_session_expires_at")
        or evidence.get("evidence_collected_at")
        != record.get("authority_evidence_collected_at")
        or evaluated != bound_evaluation
        or not issued <= collected <= evaluated <= not_before
        or not not_before < ledger_expires <= expires
        or type(lifetime) is not int
        or lifetime != int((expires - issued).total_seconds())
        or not 1 <= lifetime <= maximum_lifetime
        or type(remaining) is not int
        or remaining != int((expires - evaluated).total_seconds())
        or not 1 <= remaining <= lifetime
        or evidence.get("session_chain_depth") != 0
        or evidence.get("evidence_collected_after_sts") is not True
        or evidence.get("effective_policy_inventory_complete") is not True
        or evidence.get("sole_identity_policy_document_digest")
        != required_policy_digest
        or evidence.get("additional_inline_policy_count") != 0
        or evidence.get("additional_attached_policy_count") != 0
        or evidence.get("group_policy_count") != 0
        or evidence.get("maximum_authority_source") not in accepted_caps
        or evidence.get("maximum_authority_document_digest")
        != required_policy_digest
        or evidence.get("raw_caller_arn_persisted") is not False
    ):
        _fail("EXECUTOR_EFFECTIVE_AUTHORITY_NOT_CLOSED")


def build_prepared_ledger(
    *,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    phase: str,
    profile_class: str,
    caller_arn_digest: str,
    executor_authority_evidence_digest: str,
    executor_authority_evidence: Mapping[str, Any],
    authority_evaluation_at: datetime,
    authority_session_identifier_digest: str,
    authority_session_issued_at: datetime,
    authority_session_expires_at: datetime,
    authority_evidence_collected_at: datetime,
    host_digest: str,
    predecessor_phase: str | None,
    predecessor_terminal_receipt_digest: str | None,
    predecessor_ledger_digest: str | None,
    before_state_digest: str,
    required_predecessor_checkpoint_digest: str,
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
    not_before: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Build a create-only PREPARED record; publishing must use O_EXCL."""

    if _PHASE_RE.fullmatch(phase) is None:
        _fail("PHASE_INVALID")
    if _PROFILE_CLASS_RE.fullmatch(profile_class) is None:
        _fail("PROFILE_CLASS_INVALID")
    for value, code in (
        (caller_arn_digest, "CALLER_DIGEST_INVALID"),
        (executor_authority_evidence_digest, "AUTHORITY_EVIDENCE_DIGEST_INVALID"),
        (authority_session_identifier_digest, "AUTHORITY_SESSION_DIGEST_INVALID"),
        (host_digest, "HOST_DIGEST_INVALID"),
        (before_state_digest, "BEFORE_STATE_DIGEST_INVALID"),
        (
            required_predecessor_checkpoint_digest,
            "PREDECESSOR_CHECKPOINT_DIGEST_INVALID",
        ),
    ):
        _require_digest(value, code)
    evidence_snapshot = _canonical_snapshot(
        executor_authority_evidence, "AUTHORITY_EVIDENCE_SNAPSHOT_INVALID"
    )
    if not isinstance(evidence_snapshot, Mapping):
        _fail("AUTHORITY_EVIDENCE_SNAPSHOT_INVALID")
    predecessor_snapshot = _optional_mapping_snapshot(
        predecessor_record, "BUILD_PREDECESSOR_SNAPSHOT_INVALID"
    )
    predecessor_binding_snapshot = _optional_mapping_snapshot(
        expected_predecessor_binding,
        "BUILD_PREDECESSOR_BINDING_SNAPSHOT_INVALID",
    )
    start = _utc(not_before, "NOT_BEFORE_INVALID")
    end = _utc(expires_at, "EXPIRES_AT_INVALID")
    session_issued = _utc(
        authority_session_issued_at, "AUTHORITY_SESSION_ISSUED_AT_INVALID"
    )
    evidence_collected = _utc(
        authority_evidence_collected_at, "AUTHORITY_EVIDENCE_COLLECTED_AT_INVALID"
    )
    session_expires = _utc(
        authority_session_expires_at, "AUTHORITY_SESSION_EXPIRES_AT_INVALID"
    )
    evaluation = _utc(
        authority_evaluation_at, "AUTHORITY_EVALUATION_TIME_INVALID"
    )
    if end <= start or int((end - start).total_seconds()) > 900:
        _fail("VALIDITY_WINDOW_INVALID")
    if not (
        session_issued
        <= evidence_collected
        <= evaluation
        <= start
        < end
        <= session_expires
        and (session_expires - session_issued).total_seconds() <= 900
    ):
        _fail("AUTHORITY_SESSION_WINDOW_INVALID")
    plan_snapshot = _canonical_snapshot(plan, "PLAN_SNAPSHOT_INVALID")
    if not isinstance(plan_snapshot, dict):
        _fail("PLAN_SNAPSHOT_INVALID")
    binding = _phase_binding_from_snapshot(
        plan_snapshot, phase=phase, expected_plan_digest=expected_plan_digest
    )
    forward_phases = [
        item.get("phase")
        for item in plan_snapshot.get("authorization_phases", [])
        if isinstance(item, Mapping)
    ]
    if phase not in forward_phases:
        _fail("FORWARD_PHASE_REQUIRED")
    phase_index = forward_phases.index(phase)
    if phase_index == 0:
        if any(
            value is not None
            for value in (
                predecessor_phase,
                predecessor_terminal_receipt_digest,
                predecessor_ledger_digest,
            )
        ):
            _fail("PREDECESSOR_BINDING_INVALID")
    else:
        if predecessor_phase != forward_phases[phase_index - 1]:
            _fail("PREDECESSOR_BINDING_INVALID")
        _require_digest(
            predecessor_terminal_receipt_digest,
            "PREDECESSOR_TERMINAL_RECEIPT_INVALID",
        )
        _require_digest(
            predecessor_ledger_digest, "PREDECESSOR_LEDGER_DIGEST_INVALID"
        )
    immutable = {
        **binding,
        "profile_class": profile_class,
        "caller_arn_digest": caller_arn_digest,
        "executor_authority_evidence_digest": executor_authority_evidence_digest,
        "authority_session_identifier_digest": authority_session_identifier_digest,
        "authority_session_issued_at": _timestamp(session_issued),
        "authority_session_expires_at": _timestamp(session_expires),
        "authority_evidence_collected_at": _timestamp(evidence_collected),
        "authority_evaluation_at": _timestamp(evaluation),
        "not_before": _timestamp(start),
        "expires_at": _timestamp(end),
        "host_digest": host_digest,
        "predecessor_phase": predecessor_phase,
        "predecessor_terminal_receipt_digest": (
            predecessor_terminal_receipt_digest
        ),
        "predecessor_ledger_digest": predecessor_ledger_digest,
        "before_state_digest": before_state_digest,
        "required_predecessor_checkpoint_digest": (
            required_predecessor_checkpoint_digest
        ),
    }
    record: dict[str, Any] = {
        "record_type": RECORD_TYPE,
        "schema_version": RECORD_VERSION,
        "ledger_id": canonical_digest(immutable),
        "ledger_version": 1,
        "initial_ledger_digest": "",
        "previous_ledger_digest": None,
        **immutable,
        "status": "PREPARED",
        "attempt_count": 0,
        "claim": None,
        "operation_outcomes": [],
        "in_flight_operation": None,
        "reconciliation": None,
        "receipt_chain": [],
        "ledger_digest": "",
    }
    # The immutable root is defined with both self-digest fields blank.  Every
    # later transition carries it unchanged and classifiers require an
    # independently delivered copy.
    record["initial_ledger_digest"] = canonical_digest(
        _prepared_baseline(record)
    )
    record["ledger_digest"] = canonical_digest(
        {key: value for key, value in record.items() if key != "ledger_digest"}
    )
    _validate_phase_authority_evidence(
        plan_snapshot=plan_snapshot,
        record=record,
        evidence=evidence_snapshot,
        evaluation_at=authority_evaluation_at,
    )
    validate_ledger(record)
    _validate_pre_effect_predecessor(
        plan_snapshot=plan_snapshot,
        current_record=record,
        expected_initial_bundle_absence_digest=(
            expected_initial_bundle_absence_digest
        ),
        predecessor_record=predecessor_snapshot,
        expected_predecessor_binding=predecessor_binding_snapshot,
        effect_at=start,
    )
    return record


def _receipt(
    *, source: Mapping[str, Any], event: str, at: datetime, facts: Mapping[str, Any]
) -> dict[str, Any]:
    sanitized_facts = dict(facts)
    for value in sanitized_facts.values():
        if value is not None and not isinstance(value, (bool, int, str, list)):
            _fail("RECEIPT_FACTS_INVALID")
    prior = source.get("receipt_chain")
    if not isinstance(prior, list):
        _fail("RECEIPT_CHAIN_INVALID")
    receipt = {
        "sequence": len(prior) + 1,
        "event": event,
        "at": _timestamp(at),
        "source_ledger_version": source["ledger_version"],
        "source_ledger_digest": source["ledger_digest"],
        "previous_receipt_digest": prior[-1]["receipt_digest"] if prior else None,
        "facts": sanitized_facts,
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    return receipt


def _transition(
    current: Mapping[str, Any], *, expected_version: int, expected_digest: str
) -> dict[str, Any]:
    validate_ledger(current)
    _require_digest(expected_digest, "EXPECTED_LEDGER_DIGEST_INVALID")
    if current["ledger_version"] != expected_version or current["ledger_digest"] != expected_digest:
        _fail("LEDGER_CAS_CONFLICT")
    proposed = json.loads(canonical_json(current))
    proposed["previous_ledger_digest"] = current["ledger_digest"]
    proposed["ledger_version"] += 1
    return proposed


def prepare_claim(
    current: Mapping[str, Any], *, expected_version: int, expected_digest: str,
    at: datetime, claim_nonce_digest: str, profile_class: str,
    caller_arn_digest: str, executor_authority_evidence_digest: str,
    host_digest: str, execution_authorization: Mapping[str, Any],
    plan: Mapping[str, Any], expected_plan_digest: str,
    executor_authority_evidence: Mapping[str, Any],
    authority_evaluation_at: datetime,
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
) -> CasTransition:
    """Claim one phase once; no operation may run before this CAS succeeds."""

    current_snapshot = _canonical_snapshot(current, "CLAIM_LEDGER_SNAPSHOT_INVALID")
    if not isinstance(current_snapshot, Mapping):
        _fail("CLAIM_LEDGER_SNAPSHOT_INVALID")
    current = current_snapshot
    authorization_snapshot = _canonical_snapshot(
        execution_authorization, "CLAIM_AUTHORIZATION_SNAPSHOT_INVALID"
    )
    evidence_snapshot = _canonical_snapshot(
        executor_authority_evidence, "CLAIM_AUTHORITY_SNAPSHOT_INVALID"
    )
    if not isinstance(authorization_snapshot, Mapping) or not isinstance(
        evidence_snapshot, Mapping
    ):
        _fail("CLAIM_AUTHORIZATION_SNAPSHOT_INVALID")
    predecessor_snapshot = _optional_mapping_snapshot(
        predecessor_record, "CLAIM_PREDECESSOR_SNAPSHOT_INVALID"
    )
    predecessor_binding_snapshot = _optional_mapping_snapshot(
        expected_predecessor_binding,
        "CLAIM_PREDECESSOR_BINDING_SNAPSHOT_INVALID",
    )
    _validate_execution_authorization(current, authorization_snapshot)
    if claim_nonce_digest != authorization_snapshot.get("claim_nonce_digest"):
        _fail("CLAIM_NONCE_NOT_AUTHORIZED")
    plan_snapshot = _canonical_snapshot(plan, "CLAIM_PLAN_SNAPSHOT_INVALID")
    if not isinstance(plan_snapshot, Mapping):
        _fail("CLAIM_PLAN_SNAPSHOT_INVALID")
    binding = _phase_binding_from_snapshot(
        plan_snapshot,
        phase=str(current.get("phase")),
        expected_plan_digest=expected_plan_digest,
    )
    _validate_record_against_phase_binding(current, binding)
    _validate_phase_authority_evidence(
        plan_snapshot=plan_snapshot,
        record=current,
        evidence=evidence_snapshot,
        evaluation_at=authority_evaluation_at,
    )
    proposed = _transition(
        current, expected_version=expected_version, expected_digest=expected_digest
    )
    now = _utc(at, "CLAIM_TIME_INVALID")
    if now < _parse_timestamp(
        current["authority_evaluation_at"],
        "AUTHORITY_EVALUATION_TIME_INVALID",
    ):
        _fail("AUTHORITY_EVALUATION_AFTER_CLAIM")
    if current["status"] != "PREPARED" or current["attempt_count"] != 0:
        _fail("LEDGER_REPLAY_BLOCKED")
    if not (_parse_timestamp(current["not_before"], "NOT_BEFORE_INVALID") <= now < _parse_timestamp(current["expires_at"], "EXPIRES_AT_INVALID")):
        _fail("LEDGER_EXPIRED_OR_NOT_YET_VALID")
    if now >= _parse_timestamp(
        current["authority_session_expires_at"],
        "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
    ):
        _fail("AUTHORITY_SESSION_EXPIRED")
    _validate_pre_effect_predecessor(
        plan_snapshot=plan_snapshot,
        current_record=current,
        expected_initial_bundle_absence_digest=(
            expected_initial_bundle_absence_digest
        ),
        predecessor_record=predecessor_snapshot,
        expected_predecessor_binding=predecessor_binding_snapshot,
        effect_at=now,
    )
    exact = {
        "profile_class": profile_class,
        "caller_arn_digest": caller_arn_digest,
        "executor_authority_evidence_digest": executor_authority_evidence_digest,
        "host_digest": host_digest,
    }
    if any(current[key] != value for key, value in exact.items()):
        _fail("CLAIM_BINDING_MISMATCH")
    _require_digest(claim_nonce_digest, "CLAIM_NONCE_DIGEST_INVALID")
    receipt = _receipt(
        source=current,
        event="CLAIMED",
        at=now,
        facts={"claim_nonce_digest": claim_nonce_digest, "attempt": 1},
    )
    proposed.update(
        {
            "status": "CLAIMED",
            "attempt_count": 1,
            "claim": {
                "claim_nonce_digest": claim_nonce_digest,
                "claimed_at": _timestamp(now),
                "first_operation_sequence": 1,
                "next_operation_sequence": 1,
            },
            "receipt_chain": [*current["receipt_chain"], receipt],
        }
    )
    return _finalize_transition(proposed, current)


def prepare_operation_record(
    current: Mapping[str, Any], *, expected_version: int, expected_digest: str,
    at: datetime, operation_sequence: int, outcome: str,
    provider_result_digest: str | None,
) -> CasTransition:
    """Consume the claim after exactly one operation attempt or ambiguity."""

    proposed = _transition(
        current, expected_version=expected_version, expected_digest=expected_digest
    )
    now = _utc(at, "OUTCOME_TIME_INVALID")
    if current["status"] != "IN_FLIGHT" or current["attempt_count"] != 1:
        _fail("LEDGER_OPERATION_NOT_IN_FLIGHT")
    claim = current.get("claim")
    if not isinstance(claim, Mapping) or operation_sequence != claim.get("next_operation_sequence"):
        _fail("OPERATION_SEQUENCE_INVALID")
    if operation_sequence < 1 or operation_sequence > current["operation_count"]:
        _fail("OPERATION_SEQUENCE_INVALID")
    if outcome not in _ALLOWED_RESULT:
        _fail("OPERATION_OUTCOME_INVALID")
    expired = now >= _parse_timestamp(
        current["expires_at"], "EXPIRES_AT_INVALID"
    )
    if expired and not (
        outcome == "AMBIGUOUS" and provider_result_digest is None
    ):
        _fail("LEDGER_EXPIRED")
    if outcome == "AMBIGUOUS":
        if provider_result_digest is not None:
            _fail("AMBIGUOUS_RESULT_MUST_BE_UNKNOWN")
        status = "AMBIGUOUS"
        next_required_action = "RECONCILE_READ_ONLY"
    else:
        _require_digest(provider_result_digest, "PROVIDER_RESULT_DIGEST_INVALID")
        status = "CONSUMED"
        next_required_action = (
            "STOP_PHASE_NO_RETRY"
            if outcome == "FAILED"
            else "ATTEMPT_NEXT_ORDERED_OPERATION_ONCE"
            if operation_sequence < current["operation_count"]
            else "NO_RETRY"
        )
    request_digest = current["ordered_request_digests"][operation_sequence - 1]
    in_flight = current.get("in_flight_operation")
    if (
        not isinstance(in_flight, Mapping)
        or in_flight.get("operation_sequence") != operation_sequence
        or in_flight.get("request_digest") != request_digest
        or in_flight.get("attempt") != 1
    ):
        _fail("LEDGER_IN_FLIGHT_BINDING_INVALID")
    started_at = _parse_timestamp(
        in_flight.get("started_at"), "IN_FLIGHT_STARTED_AT_INVALID"
    )
    claimed_at = _parse_timestamp(
        claim.get("claimed_at"), "CLAIMED_AT_INVALID"
    )
    if now < started_at or now < claimed_at:
        _fail("OPERATION_OUTCOME_TIME_NOT_MONOTONIC")
    receipt = _receipt(
        source=current,
        event=f"OPERATION_{outcome}",
        at=now,
        facts={
            "operation_sequence": operation_sequence,
            "request_digest": request_digest,
            "outcome": outcome,
            "provider_result_digest": provider_result_digest,
            "next_required_action": next_required_action,
        },
    )
    proposed.update(
        {
            "status": status,
            "in_flight_operation": None,
            "operation_outcomes": [
                *current["operation_outcomes"],
                {
                "operation_sequence": operation_sequence,
                "request_digest": request_digest,
                "result": outcome,
                "provider_result_digest": provider_result_digest,
                "recorded_at": _timestamp(now),
                "write_attempt_count": 1,
                "blind_retry_permitted": False,
                "next_required_action": next_required_action,
                },
            ],
            "receipt_chain": [*current["receipt_chain"], receipt],
        }
    )
    if outcome == "SUCCEEDED" and operation_sequence < current["operation_count"]:
        proposed["status"] = "CLAIMED"
        proposed["claim"]["next_operation_sequence"] = operation_sequence + 1
    return _finalize_transition(proposed, current)


def prepare_operation_in_flight(
    current: Mapping[str, Any], *, expected_version: int, expected_digest: str,
    at: datetime, operation_sequence: int,
) -> CasTransition:
    """Persist the one allowed operation attempt before provider invocation."""

    proposed = _transition(
        current, expected_version=expected_version, expected_digest=expected_digest
    )
    now = _utc(at, "IN_FLIGHT_TIME_INVALID")
    if current["status"] != "CLAIMED" or current["attempt_count"] != 1:
        _fail("LEDGER_NOT_CLAIMED")
    claim = current.get("claim")
    if (
        not isinstance(claim, Mapping)
        or operation_sequence != claim.get("next_operation_sequence")
        or operation_sequence < 1
        or operation_sequence > current["operation_count"]
        or current.get("in_flight_operation") is not None
    ):
        _fail("OPERATION_SEQUENCE_INVALID")
    if now >= _parse_timestamp(current["expires_at"], "EXPIRES_AT_INVALID"):
        _fail("LEDGER_EXPIRED")
    claimed_at = _parse_timestamp(
        claim.get("claimed_at"), "CLAIMED_AT_INVALID"
    )
    previous_outcomes = current.get("operation_outcomes")
    if not isinstance(previous_outcomes, list):
        _fail("LEDGER_OUTCOMES_INVALID")
    previous_time = (
        _parse_timestamp(
            previous_outcomes[-1].get("recorded_at"),
            "OUTCOME_RECORDED_AT_INVALID",
        )
        if previous_outcomes
        else claimed_at
    )
    if (
        now < claimed_at
        or now < previous_time
        or now < _parse_timestamp(current["not_before"], "NOT_BEFORE_INVALID")
    ):
        _fail("OPERATION_IN_FLIGHT_TIME_NOT_MONOTONIC")
    request_digest = current["ordered_request_digests"][operation_sequence - 1]
    receipt = _receipt(
        source=current,
        event="OPERATION_IN_FLIGHT",
        at=now,
        facts={
            "operation_sequence": operation_sequence,
            "request_digest": request_digest,
            "attempt": 1,
            "retry_permitted": False,
        },
    )
    proposed.update(
        {
            "status": "IN_FLIGHT",
            "in_flight_operation": {
                "operation_sequence": operation_sequence,
                "request_digest": request_digest,
                "attempt": 1,
                "started_at": _timestamp(now),
                "retry_permitted": False,
            },
            "receipt_chain": [*current["receipt_chain"], receipt],
        }
    )
    return _finalize_transition(proposed, current)


def prepare_read_only_reconciliation(
    current: Mapping[str, Any], *, expected_version: int, expected_digest: str,
    at: datetime, observed_state_digest: str, classification: str,
) -> CasTransition:
    """Close only an AMBIGUOUS record from independently read provider state."""

    proposed = _transition(
        current, expected_version=expected_version, expected_digest=expected_digest
    )
    outcomes = current.get("operation_outcomes")
    if (
        current["status"] != "AMBIGUOUS"
        or not isinstance(outcomes, list)
        or not outcomes
        or outcomes[-1].get("next_required_action") != "RECONCILE_READ_ONLY"
    ):
        _fail("RECONCILIATION_NOT_PERMITTED")
    if classification not in {"EFFECT_PROVEN", "NO_EFFECT_PROVEN", "INCONCLUSIVE"}:
        _fail("RECONCILIATION_CLASSIFICATION_INVALID")
    _require_digest(observed_state_digest, "OBSERVED_STATE_DIGEST_INVALID")
    now = _utc(at, "RECONCILIATION_TIME_INVALID")
    ambiguous_at = _parse_timestamp(
        outcomes[-1].get("recorded_at"), "OUTCOME_RECORDED_AT_INVALID"
    )
    if now < ambiguous_at:
        _fail("RECONCILIATION_TIME_NOT_MONOTONIC")
    receipt = _receipt(
        source=current,
        event="RECONCILED",
        at=now,
        facts={
            "classification": classification,
            "observed_state_digest": observed_state_digest,
            "provider_writes_performed": 0,
        },
    )
    proposed.update(
        {
            "status": "RECONCILED",
            "reconciliation": {
                "classification": classification,
                "observed_state_digest": observed_state_digest,
                "recorded_at": _timestamp(now),
                "read_only": True,
                "provider_writes_performed": 0,
                "retry_of_ambiguous_write_permitted": False,
            },
            "receipt_chain": [*current["receipt_chain"], receipt],
        }
    )
    return _finalize_transition(proposed, current)


def _finalize_transition(
    proposed: dict[str, Any], source: Mapping[str, Any]
) -> CasTransition:
    proposed["ledger_digest"] = canonical_digest(
        {key: value for key, value in proposed.items() if key != "ledger_digest"}
    )
    validate_ledger(proposed)
    return CasTransition(
        expected_version=source["ledger_version"],
        expected_digest=source["ledger_digest"],
        proposed_record=proposed,
    )


def _validate_claim(record: Mapping[str, Any], count: int) -> None:
    claim = record.get("claim")
    if claim is None:
        return
    if not isinstance(claim, Mapping) or set(claim) != {
        "claim_nonce_digest",
        "claimed_at",
        "first_operation_sequence",
        "next_operation_sequence",
    }:
        _fail("LEDGER_CLAIM_INVALID")
    _require_digest(claim.get("claim_nonce_digest"), "CLAIM_NONCE_DIGEST_INVALID")
    _parse_timestamp(claim.get("claimed_at"), "CLAIMED_AT_INVALID")
    next_sequence = claim.get("next_operation_sequence")
    if (
        claim.get("first_operation_sequence") != 1
        or not isinstance(next_sequence, int)
        or isinstance(next_sequence, bool)
        or not 1 <= next_sequence <= count
    ):
        _fail("LEDGER_CLAIM_SEQUENCE_INVALID")


def _validate_operation_outcomes(
    outcomes: Any, requests: Sequence[str], count: int
) -> list[Mapping[str, Any]]:
    if not isinstance(outcomes, list):
        _fail("LEDGER_OUTCOMES_INVALID")
    validated: list[Mapping[str, Any]] = []
    exact_fields = {
        "operation_sequence",
        "request_digest",
        "result",
        "provider_result_digest",
        "recorded_at",
        "write_attempt_count",
        "blind_retry_permitted",
        "next_required_action",
    }
    for index, item in enumerate(outcomes, 1):
        if not isinstance(item, Mapping) or set(item) != exact_fields:
            _fail("LEDGER_OUTCOME_FIELDS_INVALID")
        result = item.get("result")
        provider_digest = item.get("provider_result_digest")
        if result not in _ALLOWED_RESULT:
            _fail("LEDGER_OUTCOME_RESULT_INVALID")
        if result == "AMBIGUOUS":
            if provider_digest is not None:
                _fail("LEDGER_OUTCOME_PROVIDER_RESULT_INVALID")
            expected_next = "RECONCILE_READ_ONLY"
        else:
            _require_digest(
                provider_digest, "LEDGER_OUTCOME_PROVIDER_RESULT_INVALID"
            )
            expected_next = (
                "STOP_PHASE_NO_RETRY"
                if result == "FAILED"
                else "ATTEMPT_NEXT_ORDERED_OPERATION_ONCE"
                if index < count
                else "NO_RETRY"
            )
        _parse_timestamp(item.get("recorded_at"), "OUTCOME_RECORDED_AT_INVALID")
        if (
            item.get("operation_sequence") != index
            or item.get("request_digest") != requests[index - 1]
            or item.get("write_attempt_count") != 1
            or isinstance(item.get("write_attempt_count"), bool)
            or item.get("blind_retry_permitted") is not False
            or item.get("next_required_action") != expected_next
        ):
            _fail("LEDGER_OUTCOME_SEMANTICS_INVALID")
        validated.append(item)
    return validated


def _validate_in_flight(record: Mapping[str, Any], requests: Sequence[str]) -> None:
    in_flight = record.get("in_flight_operation")
    if in_flight is None:
        return
    if not isinstance(in_flight, Mapping) or set(in_flight) != {
        "operation_sequence",
        "request_digest",
        "attempt",
        "started_at",
        "retry_permitted",
    }:
        _fail("LEDGER_IN_FLIGHT_FIELDS_INVALID")
    sequence = in_flight.get("operation_sequence")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 1 <= sequence <= len(requests)
        or in_flight.get("request_digest") != requests[sequence - 1]
        or in_flight.get("attempt") != 1
        or isinstance(in_flight.get("attempt"), bool)
        or in_flight.get("retry_permitted") is not False
    ):
        _fail("LEDGER_IN_FLIGHT_SEMANTICS_INVALID")
    _parse_timestamp(in_flight.get("started_at"), "IN_FLIGHT_STARTED_AT_INVALID")


def _validate_reconciliation(record: Mapping[str, Any]) -> None:
    reconciliation = record.get("reconciliation")
    if reconciliation is None:
        return
    if not isinstance(reconciliation, Mapping) or set(reconciliation) != {
        "classification",
        "observed_state_digest",
        "recorded_at",
        "read_only",
        "provider_writes_performed",
        "retry_of_ambiguous_write_permitted",
    }:
        _fail("LEDGER_RECONCILIATION_FIELDS_INVALID")
    if reconciliation.get("classification") not in {
        "EFFECT_PROVEN",
        "NO_EFFECT_PROVEN",
        "INCONCLUSIVE",
    }:
        _fail("LEDGER_RECONCILIATION_CLASSIFICATION_INVALID")
    _require_digest(
        reconciliation.get("observed_state_digest"),
        "LEDGER_RECONCILIATION_OBSERVED_DIGEST_INVALID",
    )
    _parse_timestamp(
        reconciliation.get("recorded_at"),
        "LEDGER_RECONCILIATION_RECORDED_AT_INVALID",
    )
    writes = reconciliation.get("provider_writes_performed")
    if (
        reconciliation.get("read_only") is not True
        or type(writes) is not int
        or writes != 0
        or reconciliation.get("retry_of_ambiguous_write_permitted") is not False
    ):
        _fail("LEDGER_RECONCILIATION_SEMANTICS_INVALID")


def _replay_receipt_chain(record: Mapping[str, Any]) -> None:
    """Replay the exact state machine and prove every receipt source link."""

    baseline = _prepared_baseline(record)
    baseline["initial_ledger_digest"] = record["initial_ledger_digest"]
    baseline["ledger_digest"] = canonical_digest(baseline)
    state: dict[str, Any] = baseline
    receipts = record["receipt_chain"]
    terminal_outcomes = record["operation_outcomes"]
    start = _parse_timestamp(record["not_before"], "NOT_BEFORE_INVALID")
    end = _parse_timestamp(record["expires_at"], "EXPIRES_AT_INVALID")
    session_end = _parse_timestamp(
        record["authority_session_expires_at"],
        "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
    )
    authority_evaluation = _parse_timestamp(
        record["authority_evaluation_at"],
        "AUTHORITY_EVALUATION_TIME_INVALID",
    )

    for receipt in receipts:
        if (
            receipt["sequence"] != len(state["receipt_chain"]) + 1
            or receipt["source_ledger_version"] != state["ledger_version"]
            or receipt["source_ledger_digest"] != state["ledger_digest"]
            or receipt["previous_receipt_digest"]
            != (
                state["receipt_chain"][-1]["receipt_digest"]
                if state["receipt_chain"]
                else None
            )
        ):
            _fail("RECEIPT_CAUSAL_SOURCE_MISMATCH")
        at = _parse_timestamp(receipt["at"], "RECEIPT_TIME_INVALID")
        event = receipt["event"]
        facts = receipt["facts"]
        next_state = json.loads(canonical_json(state))
        next_state["previous_ledger_digest"] = state["ledger_digest"]
        next_state["ledger_version"] = state["ledger_version"] + 1
        next_state["receipt_chain"] = [*state["receipt_chain"], receipt]

        if state["status"] == "PREPARED":
            if (
                event != "CLAIMED"
                or set(facts) != {"claim_nonce_digest", "attempt"}
                or facts.get("attempt") != 1
                or not authority_evaluation <= start <= at < min(end, session_end)
            ):
                _fail("CLAIM_RECEIPT_INVALID")
            _require_digest(
                facts.get("claim_nonce_digest"), "CLAIM_NONCE_DIGEST_INVALID"
            )
            next_state.update(
                {
                    "status": "CLAIMED",
                    "attempt_count": 1,
                    "claim": {
                        "claim_nonce_digest": facts["claim_nonce_digest"],
                        "claimed_at": receipt["at"],
                        "first_operation_sequence": 1,
                        "next_operation_sequence": 1,
                    },
                }
            )
        elif state["status"] == "CLAIMED":
            sequence = len(state["operation_outcomes"]) + 1
            expected_request = state["ordered_request_digests"][sequence - 1]
            previous_time = (
                _parse_timestamp(
                    state["operation_outcomes"][-1]["recorded_at"],
                    "OUTCOME_RECORDED_AT_INVALID",
                )
                if state["operation_outcomes"]
                else _parse_timestamp(
                    state["claim"]["claimed_at"], "CLAIMED_AT_INVALID"
                )
            )
            if (
                event != "OPERATION_IN_FLIGHT"
                or facts
                != {
                    "operation_sequence": sequence,
                    "request_digest": expected_request,
                    "attempt": 1,
                    "retry_permitted": False,
                }
                or at < previous_time
                or not authority_evaluation <= start <= at < min(end, session_end)
            ):
                _fail("OPERATION_IN_FLIGHT_RECEIPT_INVALID")
            next_state.update(
                {
                    "status": "IN_FLIGHT",
                    "in_flight_operation": {
                        "operation_sequence": sequence,
                        "request_digest": expected_request,
                        "attempt": 1,
                        "started_at": receipt["at"],
                        "retry_permitted": False,
                    },
                }
            )
        elif state["status"] == "IN_FLIGHT":
            index = len(state["operation_outcomes"])
            if index >= len(terminal_outcomes):
                _fail("OPERATION_RECEIPT_INVALID")
            outcome = terminal_outcomes[index]
            started_at = _parse_timestamp(
                state["in_flight_operation"]["started_at"],
                "IN_FLIGHT_STARTED_AT_INVALID",
            )
            if (
                event != f"OPERATION_{outcome['result']}"
                or receipt["at"] != outcome["recorded_at"]
                or facts
                != {
                    "operation_sequence": outcome["operation_sequence"],
                    "request_digest": outcome["request_digest"],
                    "outcome": outcome["result"],
                    "provider_result_digest": outcome[
                        "provider_result_digest"
                    ],
                    "next_required_action": outcome["next_required_action"],
                }
                or at < started_at
                or (outcome["result"] != "AMBIGUOUS" and at >= end)
            ):
                _fail("OPERATION_RECEIPT_INVALID")
            next_state["operation_outcomes"] = [
                *state["operation_outcomes"],
                outcome,
            ]
            next_state["in_flight_operation"] = None
            if outcome["result"] == "AMBIGUOUS":
                next_state["status"] = "AMBIGUOUS"
            elif (
                outcome["result"] == "SUCCEEDED"
                and outcome["operation_sequence"] < state["operation_count"]
            ):
                next_state["status"] = "CLAIMED"
                next_state["claim"]["next_operation_sequence"] = (
                    outcome["operation_sequence"] + 1
                )
            else:
                next_state["status"] = "CONSUMED"
        elif state["status"] == "AMBIGUOUS":
            reconciliation = record.get("reconciliation")
            ambiguous_at = _parse_timestamp(
                state["operation_outcomes"][-1]["recorded_at"],
                "OUTCOME_RECORDED_AT_INVALID",
            )
            if (
                event != "RECONCILED"
                or not isinstance(reconciliation, Mapping)
                or receipt["at"] != reconciliation.get("recorded_at")
                or at < ambiguous_at
                or facts
                != {
                    "classification": reconciliation.get("classification"),
                    "observed_state_digest": reconciliation.get(
                        "observed_state_digest"
                    ),
                    "provider_writes_performed": 0,
                }
            ):
                _fail("RECONCILIATION_RECEIPT_INVALID")
            next_state["status"] = "RECONCILED"
            next_state["reconciliation"] = reconciliation
        else:
            _fail("RECEIPT_AFTER_TERMINAL_STATE")

        next_state["ledger_digest"] = canonical_digest(
            {key: value for key, value in next_state.items() if key != "ledger_digest"}
        )
        state = next_state

    if state != dict(record):
        _fail("LEDGER_RECEIPT_REPLAY_MISMATCH")


def validate_ledger(
    record: Mapping[str, Any], *, expected_plan_digest: str | None = None,
    expected_bundle_digest: str | None = None, expected_phase: str | None = None,
) -> None:
    """Validate shape, digests, receipt chain, bindings, and state semantics."""

    if not isinstance(record, Mapping) or set(record) != _TOP_LEVEL_FIELDS:
        _fail("LEDGER_FIELDS_INVALID")
    if record.get("record_type") != RECORD_TYPE or record.get("schema_version") != 1:
        _fail("LEDGER_TYPE_INVALID")
    ledger_digest = _require_digest(record.get("ledger_digest"), "LEDGER_DIGEST_INVALID")
    if canonical_digest({k: v for k, v in record.items() if k != "ledger_digest"}) != ledger_digest:
        _fail("LEDGER_DIGEST_MISMATCH")
    for field in (
        "ledger_id", "initial_ledger_digest", "plan_digest", "bundle_digest", "caller_arn_digest",
        "executor_authority_evidence_digest", "authority_session_identifier_digest",
        "ordered_operations_digest", "host_digest", "before_state_digest",
        "required_predecessor_checkpoint_digest",
    ):
        _require_digest(record.get(field), "LEDGER_BINDING_INVALID")
    immutable = _immutable_projection(record)
    if record.get("ledger_id") != canonical_digest(immutable):
        _fail("LEDGER_ID_IMMUTABLE_PROJECTION_MISMATCH")
    if record.get("initial_ledger_digest") != canonical_digest(
        _prepared_baseline(record)
    ):
        _fail("INITIAL_LEDGER_DIGEST_MISMATCH")
    if expected_plan_digest is not None and record["plan_digest"] != _require_digest(expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID"):
        _fail("LEDGER_PLAN_BINDING_MISMATCH")
    if expected_bundle_digest is not None and record["bundle_digest"] != _require_digest(expected_bundle_digest, "EXPECTED_BUNDLE_DIGEST_INVALID"):
        _fail("LEDGER_BUNDLE_BINDING_MISMATCH")
    if expected_phase is not None and record["phase"] != expected_phase:
        _fail("LEDGER_PHASE_BINDING_MISMATCH")
    if _ACCOUNT_RE.fullmatch(str(record.get("account_id"))) is None or _REGION_RE.fullmatch(str(record.get("region"))) is None:
        _fail("LEDGER_TARGET_INVALID")
    if _PROFILE_CLASS_RE.fullmatch(str(record.get("profile_class"))) is None or _PHASE_RE.fullmatch(str(record.get("phase"))) is None:
        _fail("LEDGER_EXECUTION_BINDING_INVALID")
    count = record.get("operation_count")
    requests = record.get("ordered_request_digests")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1 or not isinstance(requests, list) or len(requests) != count:
        _fail("LEDGER_OPERATION_BINDING_INVALID")
    for digest in requests:
        _require_digest(digest, "LEDGER_REQUEST_DIGEST_INVALID")
    _validate_claim(record, count)
    outcomes = _validate_operation_outcomes(
        record.get("operation_outcomes"), requests, count
    )
    _validate_in_flight(record, requests)
    _validate_reconciliation(record)
    start = _parse_timestamp(record.get("not_before"), "NOT_BEFORE_INVALID")
    end = _parse_timestamp(record.get("expires_at"), "EXPIRES_AT_INVALID")
    if end <= start or (end - start).total_seconds() > 900:
        _fail("LEDGER_VALIDITY_INVALID")
    session_issued = _parse_timestamp(
        record.get("authority_session_issued_at"),
        "AUTHORITY_SESSION_ISSUED_AT_INVALID",
    )
    evidence_collected = _parse_timestamp(
        record.get("authority_evidence_collected_at"),
        "AUTHORITY_EVIDENCE_COLLECTED_AT_INVALID",
    )
    authority_evaluation = _parse_timestamp(
        record.get("authority_evaluation_at"),
        "AUTHORITY_EVALUATION_TIME_INVALID",
    )
    session_expires = _parse_timestamp(
        record.get("authority_session_expires_at"),
        "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
    )
    if not (
        session_issued
        <= evidence_collected
        <= authority_evaluation
        <= start
        < end
        <= session_expires
        and (session_expires - session_issued).total_seconds() <= 900
    ):
        _fail("LEDGER_AUTHORITY_SESSION_WINDOW_INVALID")
    predecessor_phase = record.get("predecessor_phase")
    predecessor_receipt = record.get("predecessor_terminal_receipt_digest")
    predecessor_ledger = record.get("predecessor_ledger_digest")
    if predecessor_phase is None:
        if predecessor_receipt is not None or predecessor_ledger is not None:
            _fail("LEDGER_PREDECESSOR_BINDING_INVALID")
    else:
        if _PHASE_RE.fullmatch(str(predecessor_phase)) is None:
            _fail("LEDGER_PREDECESSOR_BINDING_INVALID")
        _require_digest(
            predecessor_receipt, "LEDGER_PREDECESSOR_RECEIPT_INVALID"
        )
        _require_digest(
            predecessor_ledger, "LEDGER_PREDECESSOR_DIGEST_INVALID"
        )
    version = record.get("ledger_version")
    attempts = record.get("attempt_count")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1 or attempts not in {0, 1}:
        _fail("LEDGER_STATE_INVALID")
    previous = record.get("previous_ledger_digest")
    if version == 1:
        if previous is not None:
            _fail("LEDGER_CHAIN_INVALID")
    else:
        _require_digest(previous, "LEDGER_CHAIN_INVALID")
    receipts = record.get("receipt_chain")
    if not isinstance(receipts, list):
        _fail("RECEIPT_CHAIN_INVALID")
    if version != 1 + len(receipts):
        _fail("LEDGER_VERSION_RECEIPT_CHAIN_MISMATCH")
    prior: str | None = None
    for index, receipt in enumerate(receipts, 1):
        if (
            not isinstance(receipt, Mapping)
            or set(receipt)
            != {
                "sequence",
                "event",
                "at",
                "source_ledger_version",
                "source_ledger_digest",
                "previous_receipt_digest",
                "facts",
                "receipt_digest",
            }
            or receipt.get("sequence") != index
            or receipt.get("source_ledger_version") != index
            or receipt.get("previous_receipt_digest") != prior
        ):
            _fail("RECEIPT_CHAIN_INVALID")
        _require_digest(receipt.get("source_ledger_digest"), "RECEIPT_SOURCE_INVALID")
        _parse_timestamp(receipt.get("at"), "RECEIPT_TIME_INVALID")
        digest = _require_digest(receipt.get("receipt_digest"), "RECEIPT_DIGEST_INVALID")
        if canonical_digest({k: v for k, v in receipt.items() if k != "receipt_digest"}) != digest:
            _fail("RECEIPT_DIGEST_MISMATCH")
        prior = digest
    if receipts:
        claim = record.get("claim")
        first = receipts[0]
        if (
            first.get("event") != "CLAIMED"
            or not isinstance(claim, Mapping)
            or first.get("facts")
            != {
                "claim_nonce_digest": claim.get("claim_nonce_digest"),
                "attempt": 1,
            }
            or first.get("at") != claim.get("claimed_at")
        ):
            _fail("CLAIM_RECEIPT_INVALID")
        operation_receipts = [
            item for item in receipts if item.get("event") == "OPERATION_IN_FLIGHT"
        ]
        outcome_receipts = [
            item
            for item in receipts
            if str(item.get("event", "")).startswith("OPERATION_")
            and item.get("event") != "OPERATION_IN_FLIGHT"
        ]
        expected_in_flight_count = len(outcomes) + (
            1 if record.get("status") == "IN_FLIGHT" else 0
        )
        if len(operation_receipts) != expected_in_flight_count or len(
            outcome_receipts
        ) != len(outcomes):
            _fail("OPERATION_RECEIPT_INVALID")
        for offset, operation_receipt in enumerate(operation_receipts, 1):
            expected_request = requests[offset - 1]
            if operation_receipt.get("facts") != {
                "operation_sequence": offset,
                "request_digest": expected_request,
                "attempt": 1,
                "retry_permitted": False,
            }:
                _fail("OPERATION_IN_FLIGHT_RECEIPT_INVALID")
        for offset, outcome in enumerate(outcomes):
            receipt = outcome_receipts[offset]
            if (
                receipt.get("event") != f"OPERATION_{outcome.get('result')}"
                or receipt.get("at") != outcome.get("recorded_at")
                or receipt.get("facts")
                != {
                    "operation_sequence": outcome.get("operation_sequence"),
                    "request_digest": outcome.get("request_digest"),
                    "outcome": outcome.get("result"),
                    "provider_result_digest": outcome.get(
                        "provider_result_digest"
                    ),
                    "next_required_action": (
                        outcome.get("next_required_action")
                    ),
                }
            ):
                _fail("OPERATION_RECEIPT_INVALID")
        if record.get("status") == "RECONCILED":
            receipt = receipts[-1]
            reconciliation = record.get("reconciliation", {})
            if (
                receipt.get("event") != "RECONCILED"
                or receipt.get("at") != reconciliation.get("recorded_at")
                or receipt.get("facts")
                != {
                    "classification": reconciliation.get("classification"),
                    "observed_state_digest": reconciliation.get(
                        "observed_state_digest"
                    ),
                    "provider_writes_performed": 0,
                }
            ):
                _fail("RECONCILIATION_RECEIPT_INVALID")
    status = record.get("status")
    if status == "PREPARED":
        valid = version == 1 and attempts == 0 and not receipts and not outcomes and record.get("claim") is None and record.get("in_flight_operation") is None and record.get("reconciliation") is None
    elif status == "CLAIMED":
        valid = attempts == 1 and len(receipts) == 1 + (2 * len(outcomes)) and len(outcomes) < count and all(item.get("result") == "SUCCEEDED" for item in outcomes) and isinstance(record.get("claim"), Mapping) and record.get("claim", {}).get("next_operation_sequence") == len(outcomes) + 1 and record.get("in_flight_operation") is None and record.get("reconciliation") is None
    elif status == "IN_FLIGHT":
        in_flight = record.get("in_flight_operation")
        valid = attempts == 1 and len(receipts) == 2 + (2 * len(outcomes)) and len(outcomes) < count and all(item.get("result") == "SUCCEEDED" for item in outcomes) and isinstance(record.get("claim"), Mapping) and isinstance(in_flight, Mapping) and in_flight.get("operation_sequence") == len(outcomes) + 1 and in_flight.get("request_digest") == requests[len(outcomes)] and in_flight.get("attempt") == 1 and in_flight.get("retry_permitted") is False and record.get("reconciliation") is None
    elif status in {"CONSUMED", "AMBIGUOUS"}:
        last_result = outcomes[-1].get("result") if outcomes else None
        valid = attempts == 1 and len(receipts) == 1 + (2 * len(outcomes)) and isinstance(record.get("claim"), Mapping) and bool(outcomes) and record.get("in_flight_operation") is None and record.get("reconciliation") is None and ((status == "AMBIGUOUS" and last_result == "AMBIGUOUS" and all(item.get("result") == "SUCCEEDED" for item in outcomes[:-1])) or (status == "CONSUMED" and ((last_result == "FAILED" and all(item.get("result") == "SUCCEEDED" for item in outcomes[:-1])) or (len(outcomes) == count and all(item.get("result") == "SUCCEEDED" for item in outcomes)))))
    elif status == "RECONCILED":
        valid = attempts == 1 and len(receipts) == 2 + (2 * len(outcomes)) and isinstance(record.get("claim"), Mapping) and bool(outcomes) and record.get("in_flight_operation") is None and isinstance(record.get("reconciliation"), Mapping) and record.get("reconciliation", {}).get("read_only") is True and outcomes[-1].get("result") == "AMBIGUOUS" and all(item.get("result") == "SUCCEEDED" for item in outcomes[:-1])
    else:
        valid = False
    if not valid:
        _fail("LEDGER_STATE_INVALID")
    _replay_receipt_chain(record)


def validate_consumed_causal_record(
    record: Mapping[str, Any], *, expected_plan_digest: str,
    expected_bundle_digest: str, expected_phase: str,
    expected_ledger_id: str, expected_initial_ledger_digest: str,
    expected_claim_nonce_digest: str,
    expected_terminal_receipt_digest: str,
    accepted_reconciliation: Sequence[str] = (),
) -> str:
    """Return the validated record digest accepted by a classifier."""

    validate_ledger(
        record,
        expected_plan_digest=expected_plan_digest,
        expected_bundle_digest=expected_bundle_digest,
        expected_phase=expected_phase,
    )
    if record["ledger_id"] != _require_digest(expected_ledger_id, "EXPECTED_LEDGER_ID_INVALID") or record["initial_ledger_digest"] != _require_digest(expected_initial_ledger_digest, "EXPECTED_INITIAL_LEDGER_DIGEST_INVALID"):
        _fail("CAUSAL_LEDGER_ROOT_BINDING_MISMATCH")
    claim = record.get("claim")
    if not isinstance(claim, Mapping) or claim.get("claim_nonce_digest") != _require_digest(expected_claim_nonce_digest, "EXPECTED_CLAIM_NONCE_DIGEST_INVALID"):
        _fail("CAUSAL_LEDGER_CLAIM_BINDING_MISMATCH")
    if not record["receipt_chain"] or record["receipt_chain"][-1]["receipt_digest"] != _require_digest(expected_terminal_receipt_digest, "EXPECTED_TERMINAL_RECEIPT_DIGEST_INVALID"):
        _fail("CAUSAL_LEDGER_TERMINAL_RECEIPT_MISMATCH")
    outcomes = record["operation_outcomes"]
    accepted = record["status"] == "CONSUMED" and len(outcomes) == record["operation_count"] and all(item.get("result") == "SUCCEEDED" for item in outcomes)
    accepted = accepted or (
        record["status"] == "RECONCILED"
        and len(outcomes) == record["operation_count"]
        and record.get("reconciliation", {}).get("classification")
        in set(accepted_reconciliation)
    )
    if not accepted or record.get("attempt_count") != 1:
        _fail("CAUSAL_LEDGER_RECORD_NOT_ACCEPTED")
    return str(record["ledger_digest"])


def validate_consumed_causal_bundle(
    plan: Mapping[str, Any], *, expected_plan_digest: str,
    expected_bundle_digest: str,
    phase_records: Sequence[Mapping[str, Any]],
    expected_phase_bindings: Sequence[Mapping[str, Any]],
    expected_initial_bundle_absence_digest: str,
) -> str:
    """Validate the complete ordered set of forward-phase causal ledgers."""

    plan_snapshot = _canonical_snapshot(plan, "CAUSAL_BUNDLE_PLAN_SNAPSHOT_INVALID")
    if not isinstance(plan_snapshot, dict):
        _fail("CAUSAL_BUNDLE_PLAN_SNAPSHOT_INVALID")
    records_snapshot = _canonical_snapshot(
        phase_records, "CAUSAL_BUNDLE_RECORDS_SNAPSHOT_INVALID"
    )
    bindings_snapshot = _canonical_snapshot(
        expected_phase_bindings, "CAUSAL_BUNDLE_BINDINGS_SNAPSHOT_INVALID"
    )
    if not isinstance(records_snapshot, list) or not isinstance(
        bindings_snapshot, list
    ):
        _fail("CAUSAL_BUNDLE_SNAPSHOT_INVALID")
    phase_records = records_snapshot
    expected_phase_bindings = bindings_snapshot
    authorized_plan_digest = _require_digest(
        expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID"
    )
    authorized_bundle_digest = _require_digest(
        expected_bundle_digest, "EXPECTED_BUNDLE_DIGEST_INVALID"
    )
    initial_absence_digest = _require_digest(
        expected_initial_bundle_absence_digest,
        "EXPECTED_INITIAL_BUNDLE_ABSENCE_DIGEST_INVALID",
    )
    phases = plan_snapshot.get("authorization_phases")
    if not isinstance(phases, list) or not phases:
        _fail("CAUSAL_BUNDLE_PLAN_PHASES_INVALID")
    expected_phases = [
        item.get("phase") for item in phases if isinstance(item, Mapping)
    ]
    if (
        tuple(expected_phases) != FORWARD_PHASES
        or
        len(expected_phases) != len(phases)
        or len(set(expected_phases)) != len(expected_phases)
        or len(phase_records) != len(expected_phases)
        or len(expected_phase_bindings) != len(expected_phases)
    ):
        _fail("CAUSAL_BUNDLE_PHASE_SET_INVALID")
    receipts: list[dict[str, Any]] = []
    seen_session_identifiers: set[str] = set()
    seen_caller_identifiers: set[str] = set()
    binding_fields = {
        "phase",
        "ledger_id",
        "initial_ledger_digest",
        "claim_nonce_digest",
        "terminal_receipt_digest",
        "caller_arn_digest",
        "executor_authority_evidence_digest",
        "authority_session_identifier_digest",
        "authority_session_issued_at",
        "authority_session_expires_at",
        "authority_evidence_collected_at",
        "authority_evaluation_at",
        "predecessor_phase",
        "predecessor_terminal_receipt_digest",
        "predecessor_ledger_digest",
        "before_state_digest",
        "required_predecessor_checkpoint_digest",
    }
    for index, phase in enumerate(expected_phases):
        record = phase_records[index]
        binding = expected_phase_bindings[index]
        if (
            not isinstance(record, Mapping)
            or not isinstance(binding, Mapping)
            or set(binding) != binding_fields
            or record.get("phase") != phase
            or binding.get("phase") != phase
        ):
            _fail("CAUSAL_BUNDLE_PHASE_ORDER_INVALID")
        derived = _phase_binding_from_snapshot(
            plan_snapshot,
            phase=str(phase),
            expected_plan_digest=authorized_plan_digest,
        )
        if derived["bundle_digest"] != authorized_bundle_digest:
            _fail("CAUSAL_BUNDLE_DIGEST_MISMATCH")
        _validate_record_against_phase_binding(record, derived)
        for field in binding_fields - {
            "claim_nonce_digest",
            "terminal_receipt_digest",
        }:
            if record.get(field) != binding.get(field):
                _fail("CAUSAL_BUNDLE_INDEPENDENT_BINDING_MISMATCH")
        session_identifier = str(record.get("authority_session_identifier_digest"))
        caller_identifier = str(record.get("caller_arn_digest"))
        if (
            session_identifier in seen_session_identifiers
            or caller_identifier in seen_caller_identifiers
        ):
            _fail("CAUSAL_BUNDLE_AUTHORITY_SESSION_REUSE")
        seen_session_identifiers.add(session_identifier)
        seen_caller_identifiers.add(caller_identifier)
        if index == 0:
            if (
                record.get("predecessor_phase") is not None
                or record.get("predecessor_terminal_receipt_digest") is not None
                or record.get("predecessor_ledger_digest") is not None
                or record.get("before_state_digest") != initial_absence_digest
                or record.get("required_predecessor_checkpoint_digest")
                != initial_absence_digest
            ):
                _fail("CAUSAL_BUNDLE_INITIAL_PRECONDITION_MISMATCH")
        else:
            previous_record = phase_records[index - 1]
            previous_phase = phases[index - 1]
            checkpoint_digest = previous_phase.get("checkpoint_digest")
            _require_digest(
                checkpoint_digest, "CAUSAL_BUNDLE_CHECKPOINT_DIGEST_INVALID"
            )
            previous_terminal = previous_record["receipt_chain"][-1]
            if (
                record.get("predecessor_phase") != expected_phases[index - 1]
                or record.get("predecessor_terminal_receipt_digest")
                != previous_terminal.get("receipt_digest")
                or record.get("predecessor_ledger_digest")
                != previous_record.get("ledger_digest")
                or record.get("before_state_digest") != checkpoint_digest
                or record.get("required_predecessor_checkpoint_digest")
                != checkpoint_digest
                or _parse_timestamp(
                    record.get("not_before"), "NOT_BEFORE_INVALID"
                )
                < _parse_timestamp(previous_terminal.get("at"), "RECEIPT_TIME_INVALID")
                or _parse_timestamp(
                    record.get("claim", {}).get("claimed_at"),
                    "CLAIMED_AT_INVALID",
                )
                <= _parse_timestamp(previous_terminal.get("at"), "RECEIPT_TIME_INVALID")
                or _parse_timestamp(
                previous_record.get("authority_session_expires_at"),
                "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
            )
            > _parse_timestamp(
                    record.get("authority_session_issued_at"),
                    "AUTHORITY_SESSION_ISSUED_AT_INVALID",
                )
            ):
                _fail("CAUSAL_BUNDLE_PREDECESSOR_CHAIN_MISMATCH")
        terminal = validate_consumed_causal_record(
            record,
            expected_plan_digest=authorized_plan_digest,
            expected_bundle_digest=authorized_bundle_digest,
            expected_phase=str(phase),
            expected_ledger_id=str(binding.get("ledger_id")),
            expected_initial_ledger_digest=str(
                binding.get("initial_ledger_digest")
            ),
            expected_claim_nonce_digest=str(binding.get("claim_nonce_digest")),
            expected_terminal_receipt_digest=str(
                binding.get("terminal_receipt_digest")
            ),
            accepted_reconciliation=(),
        )
        receipts.append(
            {
                "phase": phase,
                "ledger_digest": terminal,
                "terminal_receipt_digest": binding["terminal_receipt_digest"],
            }
        )
    return canonical_digest(receipts)
