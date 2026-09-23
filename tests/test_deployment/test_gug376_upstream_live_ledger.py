import hashlib
import json
import multiprocessing
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tooling.platform_authority_gug376_upstream_live_ledger import (
    DurableMutationLedger,
    LedgerError,
    ledger_root_digest,
)
from tooling import platform_authority_gug376_upstream_live_ledger as module

_RUN_DIGEST = "sha256:" + "a" * 64
_PLAN_DIGEST = "sha256:" + "b" * 64
_REQ_DIGEST = "sha256:" + "c" * 64
_AUTH_DIGEST = "sha256:" + "d" * 64
_RCPT_DIGEST = "sha256:" + "e" * 64

def _utc_now():
    return datetime.now(timezone.utc)

def test_ledger_creation_and_snapshots(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path,
        run_digest=_RUN_DIGEST,
        plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST),)
    )
    res = ledger.create()
    assert res["operations"][0]["status"] == "READY"
    assert "snapshot_digest" in res
    snap = ledger.snapshot(res["snapshot_digest"])
    assert snap == res

    with pytest.raises(LedgerError) as exc:
        ledger.create()
    assert exc.value.code == "LEDGER_ALREADY_EXISTS"

def test_claim_finish_cas_and_noop(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path, run_digest=_RUN_DIGEST, plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST), ("op2", _REQ_DIGEST), ("op3", _REQ_DIGEST))
    )
    res = ledger.create()
    snap_digest = res["snapshot_digest"]

    t1 = _utc_now()
    res = ledger.record_noop("op1", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, receipt_digest=_RCPT_DIGEST, observed_at=t1)
    assert res["operations"][0]["status"] == "EXACT_PRESENT_NO_TOUCH"
    snap_digest = res["snapshot_digest"]

    # Predecessor ok because op1 is EXACT_PRESENT_NO_TOUCH
    res = ledger.claim("op2", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)
    snap_digest = res["snapshot_digest"]

    # Stale CAS
    with pytest.raises(LedgerError) as exc:
        ledger.claim("op3", expected_snapshot_digest="sha256:" + "f"*64, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)
    assert exc.value.code == "CAS_VERSION_MISMATCH"

    # Finish requires receipt if SUCCEEDED
    with pytest.raises(LedgerError) as exc:
        ledger.finish("op2", expected_snapshot_digest=snap_digest, outcome="SUCCEEDED", receipt_digest=None, observed_at=t1)
    assert exc.value.code == "RECEIPT_DIGEST_REQUIRED"

    res = ledger.finish("op2", expected_snapshot_digest=snap_digest, outcome="SUCCEEDED", receipt_digest=_RCPT_DIGEST, observed_at=t1)
    snap_digest = res["snapshot_digest"]

    # Now op3 can claim since op2 SUCCEEDED
    res = ledger.claim("op3", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)

def test_reconciled_blocks_subsequent(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path, run_digest=_RUN_DIGEST, plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST), ("op2", _REQ_DIGEST))
    )
    res = ledger.create()
    snap_digest = res["snapshot_digest"]

    t1 = _utc_now()
    res = ledger.claim("op1", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)
    snap_digest = res["snapshot_digest"]

    res = ledger.finish("op1", expected_snapshot_digest=snap_digest, outcome="AMBIGUOUS", receipt_digest=None, observed_at=t1)
    snap_digest = res["snapshot_digest"]

    res = ledger.reconcile("op1", expected_snapshot_digest=snap_digest, receipt_digest=_RCPT_DIGEST, observed_at=t1)
    snap_digest = res["snapshot_digest"]
    assert res["operations"][0]["status"] == "RECONCILED"

    # op2 should NOT be able to claim because RECONCILED is not SUCCEEDED/EXACT_PRESENT_NO_TOUCH
    with pytest.raises(LedgerError) as exc:
        ledger.claim("op2", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)
    assert exc.value.code == "PREDECESSOR_NOT_RESOLVED"

def test_corruption_hashchain(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path, run_digest=_RUN_DIGEST, plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST),)
    )
    res = ledger.create()
    snap_digest = res["snapshot_digest"]

    res = ledger.claim("op1", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=_utc_now())

    # Corrupt the file
    name = ledger._name()
    filepath = tmp_path / name
    data = json.loads(filepath.read_text())
    # Alter the history
    data["history"][0]["authorization_digest"] = "sha256:" + "f"*64
    filepath.write_text(json.dumps(data))

    # Snapshot should fail integrity
    with pytest.raises(LedgerError) as exc:
        ledger.snapshot()
    assert exc.value.code == "LEDGER_INTEGRITY_COMPROMISED"

def _racer_claim(root_path: str, run_digest: str, plan_digest: str, req_digest: str, auth_digest: str, snap_digest: str):
    ledger = DurableMutationLedger(
        Path(root_path), run_digest=run_digest, plan_digest=plan_digest,
        operations=(("op1", req_digest),)
    )
    try:
        ledger.claim("op1", expected_snapshot_digest=snap_digest, request_digest=req_digest, authorization_digest=auth_digest, observed_at=_utc_now())
        return "SUCCESS"
    except LedgerError as e:
        return e.code

def test_concurrency(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path, run_digest=_RUN_DIGEST, plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST),)
    )
    res = ledger.create()
    snap_digest = res["snapshot_digest"]

    root_fd = ledger._validated_root_fd()
    with ledger._execution_lease(root_fd):
        with multiprocessing.Pool(1) as pool:
            ret = pool.apply(_racer_claim, (str(tmp_path), _RUN_DIGEST, _PLAN_DIGEST, _REQ_DIGEST, _AUTH_DIGEST, snap_digest))
        assert ret == "RUNNER_ACTIVE"
    os.close(root_fd)

    with multiprocessing.Pool(1) as pool:
        ret = pool.apply(_racer_claim, (str(tmp_path), _RUN_DIGEST, _PLAN_DIGEST, _REQ_DIGEST, _AUTH_DIGEST, snap_digest))
    assert ret == "SUCCESS"

def test_time_rollback(tmp_path: Path):
    ledger = DurableMutationLedger(
        tmp_path, run_digest=_RUN_DIGEST, plan_digest=_PLAN_DIGEST,
        operations=(("op1", _REQ_DIGEST),)
    )
    res = ledger.create()
    snap_digest = res["snapshot_digest"]

    t1 = datetime(2026, 1, 2, tzinfo=timezone.utc)
    res = ledger.claim("op1", expected_snapshot_digest=snap_digest, request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST, observed_at=t1)
    snap_digest = res["snapshot_digest"]

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(LedgerError) as exc:
        ledger.finish("op1", expected_snapshot_digest=snap_digest, outcome="FAILED", receipt_digest=None, observed_at=t0)
    assert exc.value.code == "TIME_ROLLBACK"


def _ledger(root: Path, *, two_operations: bool = False):
    operations = (("op1", _REQ_DIGEST), ("op2", _REQ_DIGEST)) if two_operations else (("op1", _REQ_DIGEST),)
    return DurableMutationLedger(root, run_digest=_RUN_DIGEST,
                                 plan_digest=_PLAN_DIGEST, operations=operations)


def _claim(ledger, snapshot, *, operation_id="op1", when=None):
    return ledger.claim(operation_id, expected_snapshot_digest=snapshot["snapshot_digest"],
                        request_digest=_REQ_DIGEST, authorization_digest=_AUTH_DIGEST,
                        observed_at=when or _utc_now())


def _rewrite(ledger, record):
    # Only test-owned synthetic records; no real evidence is read or rewritten.
    (ledger.root / ledger._name()).write_text(json.dumps(record))


def _reseal_history(record):
    previous = record["initial_digest"]
    for version, event in enumerate(record["history"], 1):
        event.pop("event_digest", None)
        event["version"] = version
        event["event_digest"] = module._hash({"previous": previous, "event": event})
        previous = event["event_digest"]
    record["version"] = len(record["history"])
    record["snapshot_digest"] = previous


def test_custody_digest_uses_validated_real_metadata_and_creates_nothing(tmp_path):
    metadata = tmp_path.stat()
    binding = {"absolute_path": str(tmp_path), "st_dev": metadata.st_dev,
               "st_ino": metadata.st_ino, "uid": metadata.st_uid, "mode": 0o700}
    expected = "sha256:" + hashlib.sha256(json.dumps(
        binding, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    assert ledger_root_digest(tmp_path) == expected
    assert _ledger(tmp_path).custody_digest() == expected
    assert list(tmp_path.iterdir()) == []


def test_custody_change_rejected_after_directory_replacement(tmp_path):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    ledger = _ledger(root)
    ledger.create()
    old = tmp_path / "old"
    root.rename(old)
    root.mkdir(mode=0o700)
    shutil.copy2(old / ledger._name(), root / ledger._name())
    with pytest.raises(LedgerError, match="LEDGER_CUSTODY_CHANGED"):
        ledger.custody_digest()


def test_copied_snapshot_cannot_resume_under_another_private_root(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    original = _ledger(first)
    original.create()
    for item in first.iterdir():
        shutil.copy2(item, second / item.name)
    moved = _ledger(second)
    with pytest.raises(LedgerError, match="LEDGER_MISMATCH"):
        moved.snapshot()


@pytest.mark.parametrize("kind", ["relative", "symlink", "mode", "writable_parent", "git"])
def test_invalid_custody_rejected(tmp_path, kind):
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    if kind == "relative":
        root = Path("relative-root")
    elif kind == "symlink":
        link = tmp_path / "link"
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif kind == "mode":
        root.chmod(0o750)
    elif kind == "writable_parent":
        tmp_path.chmod(0o777)
    else:
        (tmp_path / ".git").write_text("synthetic git marker")
    try:
        with pytest.raises(LedgerError):
            ledger_root_digest(root)
    finally:
        tmp_path.chmod(0o700)


def test_initial_digest_is_recomputed_even_without_history(tmp_path):
    ledger = _ledger(tmp_path)
    record = ledger.create()
    record["initial_digest"] = record["snapshot_digest"] = _AUTH_DIGEST
    _rewrite(ledger, record)
    with pytest.raises(LedgerError, match="LEDGER_INTEGRITY_COMPROMISED"):
        ledger.snapshot()


@pytest.mark.parametrize("corruption", ["claim_twice", "finish_without_claim", "future_predecessor", "unknown_action", "extra_field", "bad_receipt"])
def test_rehashed_illegal_history_is_rejected(tmp_path, corruption):
    ledger = _ledger(tmp_path, two_operations=True)
    record = _claim(ledger, ledger.create())
    if corruption == "claim_twice":
        record["history"].append(dict(record["history"][0]))
        record["operations"][0]["attempt_count"] = 2
    elif corruption == "finish_without_claim":
        event = record["history"][0]
        record["history"] = [{"action": "finish", "operation_id": "op1",
                              "outcome": "SUCCEEDED", "receipt_digest": _RCPT_DIGEST,
                              "observed_at": event["observed_at"]}]
        record["operations"][0] = {**record["initial_operations"][0], "status": "SUCCEEDED",
                                    "outcome": "SUCCEEDED", "receipt_digest": _RCPT_DIGEST}
    elif corruption == "future_predecessor":
        record["history"][0]["operation_id"] = "op2"
        altered = dict(record["operations"][0], operation_id="op2")
        record["operations"] = [dict(record["initial_operations"][0]), altered]
    elif corruption == "unknown_action":
        record["history"][0]["action"] = "approve_anything"
    elif corruption == "extra_field":
        record["history"][0]["approval_override"] = True
    else:
        event = {"action": "finish", "operation_id": "op1", "outcome": "SUCCEEDED",
                 "receipt_digest": None, "observed_at": record["history"][0]["observed_at"]}
        record["history"].append(event)
        record["operations"][0].update(status="SUCCEEDED", outcome="SUCCEEDED")
    _reseal_history(record)
    _rewrite(ledger, record)
    with pytest.raises(LedgerError):
        ledger.snapshot()


@pytest.mark.parametrize("field,value", [("version", True), ("schema_version", True),
                                         ("record_type", "forged"), ("extra", "disallowed")])
def test_closed_record_schema(tmp_path, field, value):
    ledger = _ledger(tmp_path)
    record = ledger.create()
    record[field] = value
    _rewrite(ledger, record)
    with pytest.raises(LedgerError, match="LEDGER_INTEGRITY_COMPROMISED"):
        ledger.snapshot()


def test_duplicate_json_keys_rejected(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.create()
    path = tmp_path / ledger._name()
    text = path.read_text()
    path.write_text('{"version":0,' + text[1:])
    with pytest.raises(LedgerError, match="LEDGER_FILE_JSON_INVALID"):
        ledger.snapshot()


def test_subsecond_time_order_uses_datetimes(tmp_path):
    ledger = _ledger(tmp_path)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    claim = _claim(ledger, ledger.create(), when=start)
    result = ledger.finish("op1", expected_snapshot_digest=claim["snapshot_digest"],
                           outcome="SUCCEEDED", receipt_digest=_RCPT_DIGEST,
                           observed_at=start + timedelta(microseconds=1))
    assert result["operations"][0]["status"] == "SUCCEEDED"


def test_before_rename_crash_preserves_pending_and_blocks_retry(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    initial = ledger.create()
    def crash(*_args, **_kwargs):
        raise OSError("synthetic crash")
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "rename", crash)
        with pytest.raises(LedgerError, match="LEDGER_IO_FAILED"):
            _claim(ledger, initial)
    pending = tmp_path / ledger._pending_name()
    assert pending.exists()
    pending_bytes = pending.read_bytes()
    with pytest.raises(LedgerError, match="LEDGER_PENDING_EXISTS"):
        _claim(_ledger(tmp_path), initial)
    assert pending.read_bytes() == pending_bytes


def test_after_rename_crash_keeps_attempt_consumed(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    initial = ledger.create()
    original_rename = module.os.rename
    def crash_after(*args, **kwargs):
        original_rename(*args, **kwargs)
        raise OSError("synthetic crash")
    with monkeypatch.context() as patch:
        patch.setattr(module.os, "rename", crash_after)
        with pytest.raises(LedgerError, match="LEDGER_IO_FAILED"):
            _claim(ledger, initial)
    reopened = _ledger(tmp_path)
    snapshot = reopened.snapshot()
    assert snapshot["operations"][0]["status"] == "IN_FLIGHT"
    assert snapshot["operations"][0]["attempt_count"] == 1
    with pytest.raises(LedgerError, match="OPERATION_NOT_READY"):
        _claim(reopened, snapshot)


def test_replay_validation_happens_before_persistence(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    initial = ledger.create()
    contents = (tmp_path / ledger._name()).read_bytes()
    append = module._append_event
    def corrupt(record, event):
        append(record, event)
        record["operations"][0]["attempt_count"] = 7
    monkeypatch.setattr(module, "_append_event", corrupt)
    with pytest.raises(LedgerError, match="LEDGER_INTEGRITY_COMPROMISED"):
        _claim(ledger, initial)
    assert (tmp_path / ledger._name()).read_bytes() == contents
    assert not (tmp_path / ledger._pending_name()).exists()


def test_two_claimants_release_at_most_one_attempt(tmp_path):
    ledger = _ledger(tmp_path)
    initial = ledger.create()
    args = (str(tmp_path), _RUN_DIGEST, _PLAN_DIGEST, _REQ_DIGEST,
            _AUTH_DIGEST, initial["snapshot_digest"])
    with multiprocessing.Pool(2) as pool:
        results = pool.starmap(_racer_claim, [args, args])
    assert results.count("SUCCESS") == 1
    assert set(results) <= {"SUCCESS", "RUNNER_ACTIVE", "CAS_VERSION_MISMATCH"}
    assert ledger.snapshot()["operations"][0]["attempt_count"] == 1


@pytest.mark.parametrize("kind", ["hardlink", "symlink", "permissions"])
def test_ledger_file_custody_rejected(tmp_path, kind):
    ledger = _ledger(tmp_path)
    ledger.create()
    path = tmp_path / ledger._name()
    if kind == "hardlink":
        os.link(path, tmp_path / "unexpected-link")
    elif kind == "symlink":
        moved = tmp_path / "moved"
        path.rename(moved)
        path.symlink_to(moved)
    else:
        path.chmod(0o644)
    with pytest.raises(LedgerError, match="LEDGER_FILE_INVALID"):
        ledger.snapshot()


def test_lease_replacement_cannot_commit_cas(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    initial = ledger.create()
    path = tmp_path / ledger._name()
    original_contents = path.read_bytes()
    original_write = module._write_all
    def replace_lease(descriptor, payload):
        original_write(descriptor, payload)
        lease = tmp_path / ledger._lock_name()
        lease.unlink()
        lease.write_bytes(b"")
        lease.chmod(0o600)
    monkeypatch.setattr(module, "_write_all", replace_lease)
    with pytest.raises(LedgerError, match="LEDGER_LEASE_INVALID"):
        _claim(ledger, initial)
    assert path.read_bytes() == original_contents
    assert (tmp_path / ledger._pending_name()).exists()
