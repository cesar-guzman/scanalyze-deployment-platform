"""Regression tests for the exact GUG-277 authorization write boundary."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "governance" / "execute_authorized_protection_write.py"
SPEC = importlib.util.spec_from_file_location("execute_authorized_protection_write", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
executor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = executor
SPEC.loader.exec_module(executor)

GATE_TIME = datetime(2026, 8, 4, 19, 0, 0, tzinfo=UTC)


def _canonical_bytes(document: dict[str, object]) -> bytes:
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


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _private_file(run_dir: Path, name: str, content: bytes) -> Path:
    path = run_dir / name
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _bundle(
    run_dir: Path,
    ledger_dir: Path,
    *,
    authorization_id: str = "run-20260804T190000Z-test",
    recovery_mode: str = "FORWARD_ONLY_TARGET",
    observed_at: datetime = GATE_TIME,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    _private_directory(run_dir)
    _private_directory(ledger_dir)
    expires_at = expires_at or (GATE_TIME + timedelta(seconds=120))

    target_content = b'{"required_status_checks":{"checks":[],"strict":true}}\n'
    recovery_content = (
        target_content
        if recovery_mode == "FORWARD_ONLY_TARGET"
        else b'{"required_status_checks":{"checks":[],"strict":false}}\n'
    )
    target_sha256 = hashlib.sha256(target_content).hexdigest()
    recovery_sha256 = hashlib.sha256(recovery_content).hexdigest()
    completion = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_projection_bundle",
        "raw_input_sha256": "2" * 64,
        "sanitized_input_sha256": "3" * 64,
        "policy_sha256": "4" * 64,
        "target_payload_sha256": target_sha256,
        "recovery_payload_sha256": recovery_sha256,
        "recovery_mode": recovery_mode,
        "remote_mutation": "NONE",
    }
    completion_content = _canonical_bytes(completion)
    completion_sha256 = hashlib.sha256(completion_content).hexdigest()
    remote_before_sha256 = "5" * 64
    probe_head_sha = "6" * 40
    collector_path = run_dir.parent / "prewrite-collector"
    collector_path.write_bytes(b"#!/bin/sh\nexit 0\n")
    collector_path.chmod(0o700)
    collector_sha256 = hashlib.sha256(collector_path.read_bytes()).hexdigest()
    gh_path = run_dir.parent / "gh"
    gh_path.write_bytes(b"#!/bin/sh\nexit 0\n# synthetic gh\n")
    gh_path.chmod(0o700)
    gh_sha256 = hashlib.sha256(gh_path.read_bytes()).hexdigest()
    evidence_artifacts: dict[str, object] = {}
    for role in executor.REQUIRED_PREWRITE_CHECKS:
        filename = f"evidence-{role}.raw"
        content = f"synthetic {role} readback\n".encode()
        _private_file(run_dir, filename, content)
        evidence_artifacts[role] = {
            "filename": filename,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    evidence_manifest = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_prewrite_evidence_manifest",
        "authorization_id": authorization_id,
        "artifacts": evidence_artifacts,
    }
    evidence_manifest_content = _canonical_bytes(evidence_manifest)
    evidence_manifest_sha256 = hashlib.sha256(evidence_manifest_content).hexdigest()
    prewrite = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_prewrite_result",
        "authorization_id": authorization_id,
        "operator_login": "cesar-guzman",
        "github_hostname": executor.EXPECTED_GITHUB_HOSTNAME,
        "gh_executable_sha256": gh_sha256,
        "repository": executor.EXPECTED_REPOSITORY,
        "endpoint": executor.EXPECTED_ENDPOINT,
        "target_payload_sha256": target_sha256,
        "completion_manifest_sha256": completion_sha256,
        "recovery_payload_sha256": recovery_sha256,
        "recovery_mode": recovery_mode,
        "prewrite_collector_sha256": collector_sha256,
        "prewrite_evidence_manifest_sha256": evidence_manifest_sha256,
        "remote_before_sha256": remote_before_sha256,
        "probe_pr_number": 58,
        "probe_head_sha": probe_head_sha,
        "observed_at": _format_utc(observed_at),
        "classification": "EXACT_AUTHORIZED_REMOTE_BEFORE",
        "network_write_attempted": False,
        "checks": {name: "PASS" for name in executor.REQUIRED_PREWRITE_CHECKS},
    }
    prewrite_content = _canonical_bytes(prewrite)
    authorization = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_write_authorization",
        "authorization_id": authorization_id,
        "authorizer_login": executor.EXPECTED_AUTHORIZER_LOGIN,
        "operator_login": "cesar-guzman",
        "github_hostname": executor.EXPECTED_GITHUB_HOSTNAME,
        "gh_executable_sha256": gh_sha256,
        "repository": executor.EXPECTED_REPOSITORY,
        "endpoint": executor.EXPECTED_ENDPOINT,
        "target_payload_sha256": target_sha256,
        "completion_manifest_sha256": completion_sha256,
        "recovery_payload_sha256": recovery_sha256,
        "recovery_mode": recovery_mode,
        "prewrite_result_sha256": hashlib.sha256(prewrite_content).hexdigest(),
        "prewrite_collector_sha256": collector_sha256,
        "prewrite_evidence_manifest_sha256": evidence_manifest_sha256,
        "remote_before_sha256": remote_before_sha256,
        "probe_pr_number": 58,
        "probe_head_sha": probe_head_sha,
        "expires_at": _format_utc(expires_at),
        "retry_count": 0,
    }
    authorization_content = _canonical_bytes(authorization)

    execute_kwargs = {
        "target_path": _private_file(run_dir, "target.json", target_content),
        "recovery_path": _private_file(run_dir, "recovery.json", recovery_content),
        "completion_manifest_path": _private_file(
            run_dir, "completion.json", completion_content
        ),
        "authorization_envelope_path": _private_file(
            run_dir, "authorization.json", authorization_content
        ),
        "owner_approved_authorization_sha256": hashlib.sha256(
            authorization_content
        ).hexdigest(),
        "prewrite_result_path": _private_file(
            run_dir, "prewrite-result.json", prewrite_content
        ),
        "prewrite_evidence_manifest_path": _private_file(
            run_dir, "prewrite-evidence-manifest.json", evidence_manifest_content
        ),
        "prewrite_collector_path": collector_path,
        "gh_executable_path": gh_path,
        "receipt_output_path": run_dir / "authorization-boundary.json",
        "response_output_path": run_dir / "write-response.raw",
        "transport_error_output_path": run_dir / "transport-error.raw",
        "consumption_directory": ledger_dir,
    }
    return {
        "execute_kwargs": execute_kwargs,
        "authorization": authorization,
        "prewrite": prewrite,
        "evidence_manifest": evidence_manifest,
        "target_content": target_content,
        "recovery_content": recovery_content,
    }


def _rewrite_authorization(bundle: dict[str, object]) -> None:
    authorization = bundle["authorization"]
    assert isinstance(authorization, dict)
    content = _canonical_bytes(authorization)
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    path = kwargs["authorization_envelope_path"]
    assert isinstance(path, Path)
    path.write_bytes(content)
    path.chmod(0o600)
    kwargs["owner_approved_authorization_sha256"] = hashlib.sha256(content).hexdigest()


def _rewrite_prewrite_and_authorization(bundle: dict[str, object]) -> None:
    prewrite = bundle["prewrite"]
    authorization = bundle["authorization"]
    kwargs = bundle["execute_kwargs"]
    assert isinstance(prewrite, dict) and isinstance(authorization, dict)
    assert isinstance(kwargs, dict)
    content = _canonical_bytes(prewrite)
    path = kwargs["prewrite_result_path"]
    assert isinstance(path, Path)
    path.write_bytes(content)
    path.chmod(0o600)
    authorization["prewrite_result_sha256"] = hashlib.sha256(content).hexdigest()
    _rewrite_authorization(bundle)


def _request_result(return_code: int = 0) -> executor.WriteAttemptResult:
    return executor.WriteAttemptResult(
        return_code=return_code,
        artifact_kind="response",
        artifact_content=b"synthetic response\n",
    )


def _execute(
    bundle: dict[str, object],
    *,
    operator_identity_check=None,
    network_write=None,
    clock=None,
) -> tuple[executor.AuthorizationBoundaryResult, Mock]:
    request = network_write or Mock(return_value=_request_result())
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    result = executor.execute_authorized_write(
        **kwargs,
        operator_identity_check=operator_identity_check
        or Mock(return_value="cesar-guzman"),
        network_write=request,
        clock=clock or (lambda: GATE_TIME),
    )
    return result, request


def test_fresh_exact_authorization_attempts_one_request_and_consumes_id(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")

    result, request = _execute(bundle)

    request.assert_called_once_with(bundle["target_content"])
    assert result.classification == "WRITE_ATTEMPTED_RETURNED"
    assert result.receipt["authorization_consumed"] is True
    assert result.receipt["network_write_attempted"] is True
    assert result.receipt["retry_count"] == 0
    assert result.receipt["recovery_attempted"] is False
    marker = executor._consumption_marker_path(
        tmp_path / "ledger", "run-20260804T190000Z-test"
    )
    assert marker.exists()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600


@pytest.mark.parametrize("remaining_seconds", [90, 89.999999, 60, 0])
def test_launch_threshold_or_less_sends_no_request_and_does_not_consume(
    tmp_path: Path,
    remaining_seconds: float,
) -> None:
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        expires_at=GATE_TIME + timedelta(seconds=remaining_seconds),
    )

    result, request = _execute(bundle)

    request.assert_not_called()
    assert result.classification == "STALE_AUTHORIZATION_NO_REQUEST"
    assert result.receipt["authorization_consumed"] is False
    assert result.receipt["minimum_remaining_seconds"] == 60
    assert result.receipt["transport_startup_reserve_seconds"] == 30
    assert result.receipt["transport_timeout_seconds"] == 10
    assert not list((tmp_path / "ledger").iterdir())


def test_expired_authorization_sends_no_request_and_does_not_consume(
    tmp_path: Path,
) -> None:
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        observed_at=GATE_TIME - timedelta(seconds=2),
        expires_at=GATE_TIME - timedelta(seconds=1),
    )

    result, request = _execute(bundle)

    request.assert_not_called()
    assert result.classification == "STALE_AUTHORIZATION_NO_REQUEST"
    assert result.receipt["remaining_seconds"] == -1
    assert result.receipt["authorization_consumed"] is False


def test_more_than_launch_threshold_attempts_request(tmp_path: Path) -> None:
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        expires_at=GATE_TIME
        + timedelta(seconds=executor.MINIMUM_LAUNCH_REMAINING_SECONDS + 0.000001),
    )

    result, request = _execute(bundle)

    request.assert_called_once()
    assert result.classification == "WRITE_ATTEMPTED_RETURNED"


def test_second_gate_crossing_threshold_consumes_but_sends_no_request(
    tmp_path: Path,
) -> None:
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        expires_at=GATE_TIME + timedelta(seconds=120),
    )
    observations = iter(
        [GATE_TIME, GATE_TIME, GATE_TIME + timedelta(seconds=30)]
    )

    result, request = _execute(bundle, clock=lambda: next(observations))

    request.assert_not_called()
    assert result.classification == "AUTHORIZATION_CONSUMED_STALE_NO_REQUEST"
    assert result.receipt["authorization_consumed"] is True
    assert list((tmp_path / "ledger").glob("*.consumed.json"))


@pytest.mark.parametrize("offset", [-61, 1])
def test_stale_or_future_prewrite_result_fails_before_consumption(
    tmp_path: Path,
    offset: int,
) -> None:
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        observed_at=GATE_TIME + timedelta(seconds=offset),
    )
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="prewrite result"):
        _execute(bundle, network_write=request)

    request.assert_not_called()
    assert not list((tmp_path / "ledger").iterdir())


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-04Z",
        "20260804T190000Z",
        "2026-08-04 19:00:00Z",
        "2026-08-04T19:00Z",
        "2026-08-04T19:00:00+00:00Z",
        "2026-08-04T19:00:00.1234567Z",
    ],
)
def test_noncanonical_or_host_dependent_timestamps_fail_closed(timestamp: str) -> None:
    with pytest.raises(executor.AuthorizedWriteError, match="canonical RFC3339 UTC"):
        executor._parse_utc(timestamp, field="synthetic timestamp")


def test_canonical_fractional_rfc3339_utc_timestamp_is_accepted() -> None:
    assert executor._parse_utc(
        "2026-08-04T19:00:00.123456Z", field="synthetic timestamp"
    ) == datetime(2026, 8, 4, 19, 0, 0, 123456, tzinfo=UTC)


def test_owner_approved_authorization_digest_is_an_external_trust_anchor(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    kwargs["owner_approved_authorization_sha256"] = "f" * 64
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="owner-approved"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("target_payload_sha256", "target payload"),
        ("recovery_payload_sha256", "recovery payload"),
        ("completion_manifest_sha256", "completion manifest"),
    ],
)
def test_authorized_bundle_digest_mismatch_fails_closed(
    tmp_path: Path,
    field: str,
    message: str,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    authorization = bundle["authorization"]
    assert isinstance(authorization, dict)
    authorization[field] = "f" * 64
    _rewrite_authorization(bundle)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match=message):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_missing_physical_recovery_artifact_fails_before_request(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    recovery_path = kwargs["recovery_path"]
    assert isinstance(recovery_path, Path)
    recovery_path.unlink()
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="recovery payload"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_unsafe_physical_recovery_artifact_mode_fails_closed(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    recovery_path = kwargs["recovery_path"]
    assert isinstance(recovery_path, Path)
    recovery_path.chmod(0o640)

    with pytest.raises(executor.AuthorizedWriteError, match="mode 0600"):
        _execute(bundle)


def test_exact_before_requires_and_accepts_distinct_recovery_artifact(
    tmp_path: Path,
) -> None:
    bundle = _bundle(
        tmp_path / "run", tmp_path / "ledger", recovery_mode="EXACT_BEFORE"
    )

    result, request = _execute(bundle)

    request.assert_called_once()
    assert result.receipt["recovery_mode"] == "EXACT_BEFORE"
    assert bundle["recovery_content"] != bundle["target_content"]


def test_prewrite_noop_or_failed_check_is_not_accepted(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    prewrite = bundle["prewrite"]
    assert isinstance(prewrite, dict)
    checks = prewrite["checks"]
    assert isinstance(checks, dict)
    checks["branch_protection"] = "SKIPPED"
    _rewrite_prewrite_and_authorization(bundle)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="must be PASS"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_prewrite_result_must_bind_operator_probe_and_bundle(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    prewrite = bundle["prewrite"]
    assert isinstance(prewrite, dict)
    prewrite["probe_pr_number"] = 59
    _rewrite_prewrite_and_authorization(bundle)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="probe_pr_number"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_effective_github_operator_must_match_authorized_operator(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    identity = Mock(return_value="guguce-google")
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="effective GitHub operator"):
        _execute(
            bundle,
            operator_identity_check=identity,
            network_write=request,
        )

    identity.assert_called_once()
    request.assert_not_called()
    assert not list((tmp_path / "ledger").iterdir())


def test_authorization_pins_github_hostname(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    authorization = bundle["authorization"]
    assert isinstance(authorization, dict)
    authorization["github_hostname"] = "github.example.invalid"
    _rewrite_authorization(bundle)

    with pytest.raises(executor.AuthorizedWriteError, match="hostname is not exact"):
        _execute(bundle)


@pytest.mark.parametrize(
    ("path_field", "message"),
    [
        ("gh_executable_path", "gh executable does not match"),
        ("prewrite_collector_path", "prewrite collector does not match"),
    ],
)
def test_authorized_executable_digest_mismatch_fails_closed(
    tmp_path: Path,
    path_field: str,
    message: str,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    executable = kwargs[path_field]
    assert isinstance(executable, Path)
    executable.write_bytes(executable.read_bytes() + b"# changed\n")
    executable.chmod(0o700)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match=message):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_prewrite_evidence_manifest_requires_every_physical_raw_artifact(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    evidence_manifest = bundle["evidence_manifest"]
    assert isinstance(evidence_manifest, dict)
    artifacts = evidence_manifest["artifacts"]
    assert isinstance(artifacts, dict)
    branch_entry = artifacts["branch_protection"]
    assert isinstance(branch_entry, dict)
    artifact_path = tmp_path / "run" / str(branch_entry["filename"])
    artifact_path.unlink()
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="branch_protection"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_tampered_prewrite_raw_evidence_fails_digest_validation(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    evidence_manifest = bundle["evidence_manifest"]
    assert isinstance(evidence_manifest, dict)
    artifacts = evidence_manifest["artifacts"]
    assert isinstance(artifacts, dict)
    ruleset_entry = artifacts["rulesets"]
    assert isinstance(ruleset_entry, dict)
    artifact_path = tmp_path / "run" / str(ruleset_entry["filename"])
    original_size = artifact_path.stat().st_size
    artifact_path.write_bytes(b"x" * original_size)
    artifact_path.chmod(0o600)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="rulesets digest"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_authorization_envelope_rejects_unexpected_fields(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    authorization = bundle["authorization"]
    assert isinstance(authorization, dict)
    authorization["operator_note"] = "not executable authorization"
    _rewrite_authorization(bundle)

    with pytest.raises(executor.AuthorizedWriteError, match="unexpected"):
        _execute(bundle)


def test_authorizer_must_be_the_exact_repository_owner(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    authorization = bundle["authorization"]
    assert isinstance(authorization, dict)
    authorization["authorizer_login"] = "someone-else"
    _rewrite_authorization(bundle)

    with pytest.raises(executor.AuthorizedWriteError, match="repository owner"):
        _execute(bundle)


def test_authorization_id_cannot_be_replayed_from_a_different_run_directory(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger"
    first = _bundle(tmp_path / "run-a", ledger)
    second = _bundle(tmp_path / "run-b", ledger)
    first_request = Mock(return_value=_request_result())
    second_request = Mock(return_value=_request_result())

    _execute(first, network_write=first_request)
    with pytest.raises(executor.AuthorizedWriteError, match="already consumed"):
        _execute(second, network_write=second_request)

    first_request.assert_called_once()
    second_request.assert_not_called()


def test_transport_exception_is_evidenced_and_never_retried(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger"
    first = _bundle(tmp_path / "run-a", ledger)
    second = _bundle(tmp_path / "run-b", ledger)
    request = Mock(side_effect=TimeoutError("synthetic secret-free timeout"))

    result, _ = _execute(first, network_write=request)

    assert result.classification == "WRITE_ATTEMPTED_TRANSPORT_ERROR"
    assert result.receipt["transport_error_class"] == "TimeoutError"
    artifact = result.receipt["transport_artifact"]
    assert isinstance(artifact, dict)
    raw_path = first["execute_kwargs"]["transport_error_output_path"]
    assert isinstance(raw_path, Path)
    assert artifact["sha256"] == hashlib.sha256(raw_path.read_bytes()).hexdigest()
    assert artifact["size_bytes"] == raw_path.stat().st_size
    with pytest.raises(executor.AuthorizedWriteError, match="already consumed"):
        _execute(second)
    request.assert_called_once()


def test_crash_after_request_cannot_be_replayed_with_a_new_receipt(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger"
    first = _bundle(tmp_path / "run-a", ledger)
    second = _bundle(tmp_path / "run-b", ledger)
    kwargs = first["execute_kwargs"]
    assert isinstance(kwargs, dict)
    response_path = kwargs["response_output_path"]
    original_write = executor._write_private_output

    def fail_after_request(path: Path, content: bytes) -> None:
        if path == response_path:
            raise executor.AuthorizedWriteError("synthetic disk failure")
        original_write(path, content)

    request = Mock(return_value=_request_result())
    with patch.object(executor, "_write_private_output", side_effect=fail_after_request):
        with pytest.raises(executor.AuthorizedWriteError, match="disk failure"):
            _execute(first, network_write=request)

    request.assert_called_once()
    assert list(ledger.glob("*.consumed.json"))
    second_request = Mock(return_value=_request_result())
    with pytest.raises(executor.AuthorizedWriteError, match="already consumed"):
        _execute(second, network_write=second_request)
    second_request.assert_not_called()


def test_response_artifact_digest_and_size_are_bound_into_receipt(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    content = b"opaque response bytes\x00with stderr capture"
    request = Mock(
        return_value=executor.WriteAttemptResult(0, "response", content)
    )

    result, _ = _execute(bundle, network_write=request)

    artifact = result.receipt["transport_artifact"]
    assert artifact == {
        "kind": "response",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }
    response_path = bundle["execute_kwargs"]["response_output_path"]
    assert isinstance(response_path, Path)
    assert response_path.read_bytes() == content


def test_existing_output_blocks_before_authorization_consumption(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    receipt_path = kwargs["receipt_output_path"]
    assert isinstance(receipt_path, Path)
    _private_file(receipt_path.parent, receipt_path.name, b"existing\n")
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="refusing to overwrite"):
        _execute(bundle, network_write=request)

    request.assert_not_called()
    assert not list((tmp_path / "ledger").iterdir())
    assert receipt_path.read_bytes() == b"existing\n"


def test_run_and_ledger_directories_require_exact_mode_0700(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    (tmp_path / "ledger").chmod(0o750)
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="ledger must use mode 0700"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def test_consumption_ledger_cannot_be_the_disposable_run_directory(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path / "run", tmp_path / "ledger")
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    kwargs["consumption_directory"] = tmp_path / "run"
    request = Mock(return_value=_request_result())

    with pytest.raises(executor.AuthorizedWriteError, match="stable and separate"):
        _execute(bundle, network_write=request)

    request.assert_not_called()


def _cli_args(bundle: dict[str, object]) -> list[str]:
    kwargs = bundle["execute_kwargs"]
    assert isinstance(kwargs, dict)
    return [
        "--target",
        str(kwargs["target_path"]),
        "--recovery",
        str(kwargs["recovery_path"]),
        "--completion-manifest",
        str(kwargs["completion_manifest_path"]),
        "--authorization-envelope",
        str(kwargs["authorization_envelope_path"]),
        "--owner-approved-authorization-sha256",
        str(kwargs["owner_approved_authorization_sha256"]),
        "--prewrite-result",
        str(kwargs["prewrite_result_path"]),
        "--prewrite-evidence-manifest",
        str(kwargs["prewrite_evidence_manifest_path"]),
        "--prewrite-collector",
        str(kwargs["prewrite_collector_path"]),
        "--receipt-output",
        str(kwargs["receipt_output_path"]),
        "--response-output",
        str(kwargs["response_output_path"]),
        "--transport-error-output",
        str(kwargs["transport_error_output_path"]),
    ]


def test_cli_runs_only_one_exact_gh_put_and_preserves_both_streams(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    ledger = _private_directory(tmp_path / "ledger")
    bundle = _bundle(
        tmp_path / "run",
        ledger,
        observed_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    identity_completed = subprocess.CompletedProcess(
        [],
        0,
        stdout=b"cesar-guzman\n",
        stderr=b"",
    )
    completed = subprocess.CompletedProcess(
        [],
        0,
        stdout=b"HTTP/2 200\n\n{}\n",
        stderr=b"synthetic warning\n",
    )

    with (
        patch.object(executor, "_default_consumption_directory", return_value=ledger),
        patch.object(
            executor.shutil,
            "which",
            return_value=str(bundle["execute_kwargs"]["gh_executable_path"]),
        ),
        patch.object(
            executor.subprocess,
            "run",
            side_effect=[identity_completed, completed],
        ) as run,
    ):
        assert executor.main(_cli_args(bundle)) == 0

    assert run.call_count == 2
    identity_command = run.call_args_list[0].args[0]
    assert identity_command[1:5] == [
        "api",
        "--hostname",
        "github.com",
        "-H",
    ]
    command = run.call_args_list[1].args[0]
    assert command[1:6] == [
        "api",
        "--hostname",
        "github.com",
        "--method",
        "PUT",
    ]
    assert executor.EXPECTED_API_PATH in command
    assert command[-2:] == ["--input", "-"]
    assert run.call_args_list[1].kwargs["input"] == bundle["target_content"]
    assert run.call_args_list[1].kwargs["timeout"] == 10
    response_path = bundle["execute_kwargs"]["response_output_path"]
    capture = json.loads(response_path.read_text(encoding="utf-8"))
    assert base64.b64decode(capture["stdout_base64"]) == completed.stdout
    assert base64.b64decode(capture["stderr_base64"]) == completed.stderr


def test_cli_stale_authorization_never_invokes_gh_or_consumes_id(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    ledger = _private_directory(tmp_path / "ledger")
    bundle = _bundle(
        tmp_path / "run",
        ledger,
        observed_at=now,
        expires_at=now + timedelta(seconds=70),
    )

    with (
        patch.object(executor, "_default_consumption_directory", return_value=ledger),
        patch.object(
            executor.shutil,
            "which",
            return_value=str(bundle["execute_kwargs"]["gh_executable_path"]),
        ),
        patch.object(executor.subprocess, "run") as run,
    ):
        assert executor.main(_cli_args(bundle)) == 1

    run.assert_not_called()
    assert not list(ledger.iterdir())
    receipt_path = bundle["execute_kwargs"]["receipt_output_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["classification"] == "STALE_AUTHORIZATION_NO_REQUEST"


def test_cli_transport_timeout_is_bounded_and_consumed_without_retry(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    ledger = _private_directory(tmp_path / "ledger")
    bundle = _bundle(
        tmp_path / "run",
        ledger,
        observed_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    identity_completed = subprocess.CompletedProcess(
        [], 0, stdout=b"cesar-guzman\n", stderr=b""
    )
    timeout = subprocess.TimeoutExpired(
        cmd="synthetic gh api",
        timeout=executor.TRANSPORT_TIMEOUT_SECONDS,
        output=b"partial response",
        stderr=b"partial transport error",
    )

    with (
        patch.object(executor, "_default_consumption_directory", return_value=ledger),
        patch.object(
            executor.shutil,
            "which",
            return_value=str(bundle["execute_kwargs"]["gh_executable_path"]),
        ),
        patch.object(
            executor.subprocess,
            "run",
            side_effect=[identity_completed, timeout],
        ) as run,
    ):
        assert executor.main(_cli_args(bundle)) == 1

    assert run.call_count == 2
    assert run.call_args_list[1].kwargs["timeout"] == 10
    receipt_path = bundle["execute_kwargs"]["receipt_output_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["authorization_consumed"] is True
    assert receipt["request_return_code"] == 124
    assert receipt["transport_artifact"]["kind"] == "transport_error"
    assert list(ledger.glob("*.consumed.json"))


def test_cli_has_no_arbitrary_prewrite_command_surface(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    bundle = _bundle(
        tmp_path / "run",
        tmp_path / "ledger",
        observed_at=now,
        expires_at=now + timedelta(seconds=300),
    )

    with pytest.raises(SystemExit) as raised:
        executor._parse_args(
            _cli_args(bundle) + ["--prewrite-command", "/usr/bin/true"]
        )

    assert raised.value.code == 2
