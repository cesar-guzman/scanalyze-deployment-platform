"""GUG-215 bounded single-operator non-production exception contracts."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tooling.platform_authority_change_set_retirement_broker import (
    BROKER_VERSION_BINDING_FIELDS,
    broker_version_binding_digest,
)
from tooling.platform_authority_single_operator_retirement_exception import (
    EXCEPTION_MODE,
    SingleOperatorExceptionError,
    build_single_operator_retirement_exception,
    canonical_digest,
    validate_single_operator_retirement_exception,
)


CREATED = datetime(2030, 1, 1, tzinfo=UTC)
NOT_BEFORE = CREATED + timedelta(minutes=20)
EXPIRES = NOT_BEFORE + timedelta(minutes=15)
RETIREMENT_ID = "gug215#sha256:" + "1" * 64
USER_ID = "00000000-0000-4000-8000-000000000011"
RUNTIME_VERSION_ARN = "arn:aws:lambda:us-east-1::runtime:" + "a" * 64
REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_CLI = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-single-operator-retirement-exception.py"
)


def _digest(seed: str) -> str:
    return canonical_digest({"seed": seed})


def _exception(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "authority_account_id": "111122223333",
        "region": "us-east-1",
        "retirement_id": RETIREMENT_ID,
        "change_set_name_digest": _digest("change-set-name"),
        "template_sha256": _digest("template"),
        "resource_inventory_sha256": _digest("inventory"),
        "identity_binding_digest": _digest("identity-binding"),
        "broker_runtime_version_arn": RUNTIME_VERSION_ARN,
        "broker_version_binding_sha256": _digest("broker-version-binding"),
        "operator_identity_store_user_id": USER_ID,
        "owner_authorization_sha256": _digest("owner-authorization"),
        "created_at": CREATED,
        "not_before": NOT_BEFORE,
        "expires_at": EXPIRES,
    }
    values.update(overrides)
    return build_single_operator_retirement_exception(**values)  # type: ignore[arg-type]


def _redigest(value: dict[str, object]) -> dict[str, object]:
    changed = copy.deepcopy(value)
    changed["authorization_digest"] = canonical_digest(
        {key: item for key, item in changed.items() if key != "authorization_digest"}
    )
    return changed


def test_exception_is_exact_honest_digest_only_and_non_production() -> None:
    exception = _exception()

    validate_single_operator_retirement_exception(exception)
    assert exception["authorization_mode"] == EXCEPTION_MODE
    assert exception["two_human_status"] == "NOT_PROVEN"
    assert exception["independent_approval_present"] is False
    assert exception["production"] is False
    assert exception["single_execution"] is True
    assert exception["deployment_authorized"] is False
    assert exception["operator_identity_store_user_id_digest"] == canonical_digest(
        {"identity_store_user_id": USER_ID.lower()}
    )
    assert exception["broker_runtime_version_arn_digest"] == canonical_digest(
        {"broker_runtime_version_arn": RUNTIME_VERSION_ARN}
    )
    assert USER_ID not in repr(exception)
    assert exception["authorization_digest"] == canonical_digest(
        {key: value for key, value in exception.items() if key != "authorization_digest"}
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("authorization_mode", "TWO_HUMAN", "EXCEPTION_MODE_INVALID"),
        ("two_human_status", "PROVEN", "TWO_HUMAN_OVERCLAIM"),
        ("independent_approval_present", True, "INDEPENDENCE_OVERCLAIM"),
        ("production", True, "PRODUCTION_FORBIDDEN"),
        ("single_execution", False, "SINGLE_EXECUTION_REQUIRED"),
        ("deployment_authorized", True, "DEPLOYMENT_AUTHORITY_OVERCLAIM"),
        ("allowed_action", "cloudformation:ExecuteChangeSet", "ACTION_SCOPE_INVALID"),
    ),
)
def test_exception_rejects_authority_overclaims(
    field: str,
    value: object,
    code: str,
) -> None:
    changed = _exception()
    changed[field] = value
    changed = _redigest(changed)
    with pytest.raises(SingleOperatorExceptionError, match=rf"^{code}$"):
        validate_single_operator_retirement_exception(changed)


@pytest.mark.parametrize(
    "field",
    (
        "authority_account_id_digest",
        "region",
        "retirement_id",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "broker_runtime_version_arn_digest",
        "operator_identity_store_user_id_digest",
        "owner_authorization_sha256",
        "created_at",
        "not_before",
        "expires_at",
    ),
)
def test_authorization_digest_covers_every_exact_binding(field: str) -> None:
    changed = _exception()
    changed[field] = (
        "sha256:" + "f" * 64
        if field.endswith("digest") or field.endswith("sha256")
        else "changed"
    )
    with pytest.raises(
        SingleOperatorExceptionError,
        match="AUTHORIZATION_DIGEST_MISMATCH",
    ):
        validate_single_operator_retirement_exception(changed)


@pytest.mark.parametrize(
    ("created", "not_before", "expires", "code"),
    (
        (CREATED, CREATED - timedelta(seconds=1), EXPIRES, "EXCEPTION_WINDOW_INVALID"),
        (
            CREATED,
            CREATED + timedelta(hours=1, seconds=1),
            CREATED + timedelta(hours=1, minutes=10),
            "EXCEPTION_WINDOW_INVALID",
        ),
        (
            CREATED,
            NOT_BEFORE,
            NOT_BEFORE + timedelta(minutes=15, seconds=1),
            "EXCEPTION_WINDOW_INVALID",
        ),
        (CREATED, NOT_BEFORE, NOT_BEFORE, "EXCEPTION_WINDOW_INVALID"),
    ),
)
def test_exception_has_a_closed_short_lived_window(
    created: datetime,
    not_before: datetime,
    expires: datetime,
    code: str,
) -> None:
    with pytest.raises(SingleOperatorExceptionError, match=rf"^{code}$"):
        _exception(created_at=created, not_before=not_before, expires_at=expires)


def test_exception_rejects_unknown_fields_and_digest_tampering() -> None:
    changed = _exception()
    changed["request_selected_action"] = "allow"
    changed = _redigest(changed)
    with pytest.raises(SingleOperatorExceptionError, match="EXCEPTION_FIELDS_INVALID"):
        validate_single_operator_retirement_exception(changed)

    changed = _exception()
    changed["authorization_digest"] = "sha256:" + "f" * 64
    with pytest.raises(
        SingleOperatorExceptionError,
        match="AUTHORIZATION_DIGEST_MISMATCH",
    ):
        validate_single_operator_retirement_exception(changed)


def _private_cli_input(path: Path) -> None:
    value = {
        "authority_account_id": "111122223333",
        "region": "us-east-1",
        "retirement_id": RETIREMENT_ID,
        "change_set_name_digest": _digest("change-set-name"),
        "template_sha256": _digest("template"),
        "resource_inventory_sha256": _digest("inventory"),
        "identity_binding_digest": _digest("identity-binding"),
        "broker_runtime_version_arn": RUNTIME_VERSION_ARN,
        "broker_version_binding_sha256": _digest("broker-version-binding"),
        "operator_identity_store_user_id": USER_ID,
        "owner_authorization_sha256": _digest("owner-authorization"),
        "created_at": CREATED.isoformat().replace("+00:00", "Z"),
        "not_before": NOT_BEFORE.isoformat().replace("+00:00", "Z"),
        "expires_at": EXPIRES.isoformat().replace("+00:00", "Z"),
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _broker_version_binding_input() -> dict[str, str]:
    return {
        field: f"private-binding-value-{index:02d}-{field}"
        for index, field in enumerate(BROKER_VERSION_BINDING_FIELDS)
    }


def _write_private_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _run_broker_version_binding(source: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "broker-version-binding",
            "--input",
            str(source),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_offline_cli_help_lists_every_exact_broker_version_binding_field() -> None:
    shown = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "broker-version-binding",
            "--help",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert shown.returncode == 0, shown.stderr
    assert "private 0600 JSON" in shown.stdout
    for field in BROKER_VERSION_BINDING_FIELDS:
        assert field in shown.stdout


def test_offline_cli_calculates_only_the_sanitized_broker_version_binding(
    tmp_path: Path,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "broker-version-binding.json"
    values = _broker_version_binding_input()
    _write_private_json(source, values)

    calculated = _run_broker_version_binding(source)

    assert calculated.returncode == 0, calculated.stderr
    receipt = json.loads(calculated.stdout)
    assert receipt == {
        "status": "BROKER_VERSION_BINDING_CALCULATED_REVIEW_REQUIRED",
        "BrokerVersionBindingSha256": broker_version_binding_digest(values),
        "deployment_authorized": False,
        "aws_calls_performed": False,
        "aws_mutations": "NONE",
    }
    assert list(private_dir.iterdir()) == [source]
    assert calculated.stderr == ""
    for raw_value in values.values():
        assert raw_value not in calculated.stdout


@pytest.mark.parametrize("field", BROKER_VERSION_BINDING_FIELDS)
def test_offline_cli_broker_version_binding_causally_covers_each_field(
    tmp_path: Path,
    field: str,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "broker-version-binding.json"
    baseline = _broker_version_binding_input()
    changed = dict(baseline)
    changed[field] = f"{changed[field]}-changed"
    _write_private_json(source, changed)

    calculated = _run_broker_version_binding(source)

    assert calculated.returncode == 0, calculated.stderr
    digest = json.loads(calculated.stdout)["BrokerVersionBindingSha256"]
    assert digest == broker_version_binding_digest(changed)
    assert digest != broker_version_binding_digest(baseline), field


@pytest.mark.parametrize("mutation", ("missing", "extra", "non-string"))
def test_offline_cli_broker_version_binding_rejects_non_exact_private_input(
    tmp_path: Path,
    mutation: str,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "broker-version-binding.json"
    values: dict[str, object] = _broker_version_binding_input()
    expected = "BROKER_VERSION_BINDING_INPUT_FIELDS_INVALID"
    if mutation == "missing":
        values.pop(BROKER_VERSION_BINDING_FIELDS[0])
    elif mutation == "extra":
        values["request_selectable_field"] = "forbidden"
    else:
        values[BROKER_VERSION_BINDING_FIELDS[0]] = 42
        expected = "BROKER_VERSION_BINDING_INPUT_VALUES_INVALID"
    _write_private_json(source, values)

    rejected = _run_broker_version_binding(source)

    assert rejected.returncode == 1
    assert rejected.stdout == ""
    assert rejected.stderr.strip() == f"BLOCKED: {expected}"


def test_offline_cli_broker_version_binding_requires_exact_mode_0600(
    tmp_path: Path,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "broker-version-binding.json"
    _write_private_json(source, _broker_version_binding_input())
    source.chmod(0o400)

    rejected = _run_broker_version_binding(source)

    assert rejected.returncode == 1
    assert rejected.stdout == ""
    assert rejected.stderr.strip() == "BLOCKED: PRIVATE_INPUT_MODE_INVALID"


def test_offline_cli_builds_once_and_verifies_an_independently_pinned_digest(
    tmp_path: Path,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "raw-input.json"
    artifact = private_dir / "exception.json"
    _private_cli_input(source)

    built = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "build",
            "--input",
            str(source),
            "--output",
            str(artifact),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    receipt = json.loads(built.stdout)
    assert receipt["status"] == "EXCEPTION_ARTIFACT_BUILT_REVIEW_REQUIRED"
    assert receipt["two_human_status"] == "NOT_PROVEN"
    assert receipt["independent_approval_present"] is False
    assert receipt["deployment_authorized"] is False
    assert artifact.stat().st_mode & 0o777 == 0o600
    serialized_artifact = artifact.read_text(encoding="utf-8")
    assert USER_ID not in serialized_artifact
    assert "111122223333" not in serialized_artifact
    assert RUNTIME_VERSION_ARN not in serialized_artifact
    assert USER_ID not in built.stdout
    assert "111122223333" not in built.stdout

    verified = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "verify",
            "--artifact",
            str(artifact),
            "--expected-authorization-digest",
            receipt["authorization_digest"],
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["status"] == (
        "EXCEPTION_ARTIFACT_VERIFIED_REVIEW_REQUIRED"
    )

    second_build = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "build",
            "--input",
            str(source),
            "--output",
            str(artifact),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second_build.returncode == 1
    assert second_build.stderr.strip() == "BLOCKED: PRIVATE_OUTPUT_ALREADY_EXISTS"


def test_offline_cli_rejects_wrong_reviewed_digest_and_unsafe_input_mode(
    tmp_path: Path,
) -> None:
    private_dir = tmp_path / "owner-only"
    private_dir.mkdir(mode=0o700)
    private_dir.chmod(0o700)
    source = private_dir / "raw-input.json"
    artifact = private_dir / "exception.json"
    _private_cli_input(source)

    built = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "build",
            "--input",
            str(source),
            "--output",
            str(artifact),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0
    mismatch = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "verify",
            "--artifact",
            str(artifact),
            "--expected-authorization-digest",
            "sha256:" + "f" * 64,
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert mismatch.returncode == 1
    assert mismatch.stderr.strip() == (
        "BLOCKED: EXPECTED_AUTHORIZATION_DIGEST_MISMATCH"
    )

    os.chmod(source, 0o644)
    unsafe = subprocess.run(
        [
            sys.executable,
            str(ARTIFACT_CLI),
            "build",
            "--input",
            str(source),
            "--output",
            str(private_dir / "unsafe.json"),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert unsafe.returncode == 1
    assert unsafe.stderr.strip() == "BLOCKED: PRIVATE_INPUT_MODE_INVALID"
