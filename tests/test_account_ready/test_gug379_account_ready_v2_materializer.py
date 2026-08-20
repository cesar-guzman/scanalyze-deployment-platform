"""GUG-379 deterministic ACCOUNT_READY v2 producer tests."""

from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tooling.account_ready_v2_materializer import (
    EXPECTED_CONTROLS,
    MaterializationError,
    bind_account_ready_v2_candidate,
    build_account_ready_v2_candidate,
    canonical_digest,
    materialize_account_ready_v2,
    write_materialization_outputs,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
ACCOUNT_ID = "111222333444"
REGION = "us-east-1"
ENVIRONMENT = "sandbox"
EVALUATED_AT = "2026-08-16T20:05:00Z"


def test_account_ready_gate_account_id_validation_is_re2_safe(tmp_path: Path) -> None:
    variables = (
        REPO_ROOT / "roots" / "account-ready-gate" / "variables.tf"
    ).read_text(encoding="utf-8")
    assert "(?!" not in variables
    assert variables.count('can(regex("^[0-9]{12}$",') == 2
    assert variables.count("try(tonumber(") == 2

    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")

    for account_id, expected in (
        (ACCOUNT_ID, "true"),
        ("000000000000", "false"),
    ):
        expression = (
            f'can(regex("^[0-9]{{12}}$", "{account_id}")) '
            f'&& try(tonumber("{account_id}") != 0, false)\n'
        )
        result = subprocess.run(
            [terraform_binary, f"-chdir={tmp_path}", "console"],
            input=expression,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected


def test_account_ready_gate_real_root_is_backendless_and_provider_free(
    tmp_path: Path,
) -> None:
    source_root = REPO_ROOT / "roots" / "account-ready-gate"
    harness = tmp_path / "account-ready-gate"
    harness.mkdir()
    source_files = sorted(source_root.glob("*.tf"))
    assert source_files
    for source in source_files:
        shutil.copy2(source, harness / source.name)
    assert {path.name for path in harness.glob("*.tf")} == {
        path.name for path in source_files
    }

    lock_file = source_root / ".terraform.lock.hcl"
    if lock_file.exists():
        shutil.copy2(lock_file, harness / lock_file.name)

    terraform_binary = shutil.which("terraform")
    if terraform_binary is None:
        pytest.skip("Terraform executable is unavailable")
    controlled_bin = tmp_path / "bin"
    controlled_bin.mkdir()
    (controlled_bin / "terraform").symlink_to(terraform_binary)

    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    empty_provider_mirror = tmp_path / "empty-provider-mirror"
    empty_provider_mirror.mkdir()
    (isolated_home / ".terraformrc").write_text(
        "provider_installation {\n"
        "  filesystem_mirror {\n"
        f"    path = {json.dumps(str(empty_provider_mirror))}\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    environment = {
        "CHECKPOINT_DISABLE": "1",
        "HOME": str(isolated_home),
        "LC_ALL": "C",
        "PATH": str(controlled_bin),
    }
    assert not any(
        name.startswith(("AWS_", "TF_")) for name in environment
    )

    def terraform(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["terraform", f"-chdir={harness}", *arguments],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    providers = terraform("providers")
    assert providers.returncode == 0, providers.stderr
    provider_output = providers.stdout + providers.stderr
    assert "registry.terraform.io" not in provider_output
    assert "hashicorp/aws" not in provider_output

    initialized = terraform(
        "init",
        "-backend=false",
        "-input=false",
        "-no-color",
    )
    assert initialized.returncode == 0, initialized.stderr
    assert not any(empty_provider_mirror.iterdir())
    assert not (harness / ".terraform.lock.hcl").exists()
    providers_directory = harness / ".terraform" / "providers"
    assert not providers_directory.exists() or not any(
        providers_directory.rglob("*")
    )

    target, anchor, readback = _documents()
    account_ready = _materialize(target, anchor, readback).account_ready
    projection = {
        "customer_id": target["customer_id"],
        "deployment_id": target["deployment_id"],
        "account_id": target["account_id"],
        "region": target["region"],
        "environment": target["environment"],
        "expected_baseline_version": target["account_ready"]["baseline_version"],
        "expected_contract_digest": target["account_ready"]["contract_digest"],
        "account_ready_binding": {
            field: account_ready[field]
            for field in (
                "schema_version",
                "customer_id",
                "deployment_id",
                "account_id",
                "region",
                "environment",
                "baseline_version",
                "contract_digest",
            )
        },
    }
    variables_path = tmp_path / "gate.auto.tfvars.json"
    variables_path.write_text(json.dumps(projection), encoding="utf-8")
    valid = terraform(
        "plan",
        "-input=false",
        "-no-color",
        "-refresh=false",
        "-lock=false",
        f"-var-file={variables_path}",
    )
    assert valid.returncode == 0, valid.stderr
    valid_output = valid.stdout + valid.stderr
    sensitive_values = (
        projection["customer_id"],
        projection["deployment_id"],
        projection["account_id"],
        projection["region"],
        projection["environment"],
        projection["expected_baseline_version"],
        projection["expected_contract_digest"],
    )
    for sensitive in sensitive_values:
        assert sensitive not in valid_output

    mismatches = (
        (
            "customer_id",
            "cust_01J5A1B2C3D4E5F6G7H8J9K0M2",
            "customer binding",
        ),
        (
            "deployment_id",
            "dep_01J5A1B2C3D4E5F6G7H8J9K0M2",
            "deployment binding",
        ),
        ("account_id", "555666777888", "account binding"),
        ("region", "us-west-2", "region binding"),
        ("environment", "staging", "environment binding"),
        ("baseline_version", "v2.0.1", "baseline version"),
        ("contract_digest", "sha256:" + ("b" * 64), "digest"),
    )
    for field, mismatched_value, expected_error in mismatches:
        mismatched = copy.deepcopy(projection)
        mismatched["account_ready_binding"][field] = mismatched_value
        variables_path.write_text(json.dumps(mismatched), encoding="utf-8")
        denied = terraform(
            "plan",
            "-input=false",
            "-no-color",
            "-refresh=false",
            "-lock=false",
            f"-var-file={variables_path}",
        )
        assert denied.returncode != 0
        denied_output = denied.stdout + denied.stderr
        assert expected_error in denied_output
        for sensitive in (*sensitive_values, mismatched_value):
            assert sensitive not in denied_output


def _roles() -> dict:
    names = {
        "plan": "ScanalyzeCustomer-Plan",
        "apply": "ScanalyzeCustomer-Apply",
        "identity_plan": "ScanalyzeCustomer-Identity-Plan",
        "identity_apply": "ScanalyzeCustomer-Identity-Apply",
        "promotion": "ScanalyzeCustomer-Promotion",
        "validation": "ScanalyzeCustomer-Validation",
        "diagnostic": "ScanalyzeCustomer-Diagnostic",
        "state_recovery": "ScanalyzeCustomer-StateRecovery",
    }
    return {
        key: {
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{name}",
            "customer_id_tag": CUSTOMER_ID,
            "deployment_id_tag": DEPLOYMENT_ID,
            "account_id_tag": ACCOUNT_ID,
            "region_tag": REGION,
            "environment_tag": ENVIRONMENT,
        }
        for key, name in names.items()
    }


def _state_infrastructure() -> dict:
    return {
        "state_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-state",
        "evidence_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-tf-evidence",
        "contracts_bucket": f"arn:aws:s3:::scanalyze-{ACCOUNT_ID}-contracts",
        "state_kms_key": (
            f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
            "11111111-1111-4111-8111-111111111111"
        ),
        "evidence_kms_key": (
            f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
            "22222222-2222-4222-8222-222222222222"
        ),
        "contracts_kms_key": (
            f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
            "33333333-3333-4333-8333-333333333333"
        ),
    }


def _candidate_digest(readback: dict) -> str:
    candidate = {
        "schema_version": "2",
        **{
            key: copy.deepcopy(readback[key])
            for key in (
                "customer_id",
                "deployment_id",
                "account_id",
                "region",
                "environment",
                "baseline_version",
                "provisioned_at",
                "roles",
                "state_infrastructure",
                "controls",
            )
        },
    }
    return canonical_digest(candidate, digest_field="contract_digest")


def _documents() -> tuple[dict, dict, dict]:
    readback = {
        "schema_version": "1",
        "record_type": "account_ready_v2_bootstrap_readback",
        "status": "CLOSED",
        "observed_at": "2026-08-16T20:00:00Z",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-08-16T19:59:00Z",
        "roles": _roles(),
        "state_infrastructure": _state_infrastructure(),
        "controls": copy.deepcopy(EXPECTED_CONTROLS),
    }
    target = {
        "schema_version": "2",
        "record_type": "deployment_target",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": ENVIRONMENT,
        "runtime_origin": {
            "schema_version": "1",
            "domain_name": "app.synthetic.invalid",
        },
        "status": "READY",
        "registry_version": 1,
        "account_ready": {
            "schema_version": "2",
            "baseline_version": readback["baseline_version"],
            "contract_digest": _candidate_digest(readback),
        },
        "state_binding": {
            "state_bucket": readback["state_infrastructure"]["state_bucket"],
            "state_kms_key": readback["state_infrastructure"]["state_kms_key"],
        },
    }
    target["record_digest"] = canonical_digest(
        target,
        digest_field="record_digest",
    )
    anchor = {
        "schema_version": "1",
        "deployment_id": DEPLOYMENT_ID,
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }
    readback["readback_digest"] = canonical_digest(
        readback,
        digest_field="readback_digest",
    )
    return target, anchor, readback


def _refresh_bindings(target: dict, anchor: dict, readback: dict) -> None:
    target["record_digest"] = canonical_digest(
        target,
        digest_field="record_digest",
    )
    anchor.update(
        {
            "deployment_id": target["deployment_id"],
            "registry_version": target["registry_version"],
            "record_digest": target["record_digest"],
        }
    )
    readback["readback_digest"] = canonical_digest(
        readback,
        digest_field="readback_digest",
    )


def _materialize(target: dict, anchor: dict, readback: dict):
    return materialize_account_ready_v2(
        target=target,
        anchor=anchor,
        bootstrap_readback=readback,
        evaluated_at=EVALUATED_AT,
    )


def _assert_code(expected: str, target: dict, anchor: dict, readback: dict) -> None:
    with pytest.raises(MaterializationError) as raised:
        _materialize(target, anchor, readback)
    assert raised.value.code == expected
    assert str(raised.value) == expected


def test_materializer_is_deterministic_v2_and_manifest_is_sanitized() -> None:
    target, anchor, readback = _documents()

    first = _materialize(target, anchor, readback)
    second = _materialize(
        copy.deepcopy(target),
        copy.deepcopy(anchor),
        copy.deepcopy(readback),
    )

    assert first.account_ready_bytes == second.account_ready_bytes
    assert first.operator_manifest_bytes == second.operator_manifest_bytes
    assert first.account_ready["schema_version"] == "2"
    assert set(first.account_ready["roles"]) == set(_roles())
    assert first.account_ready["controls"] == EXPECTED_CONTROLS
    assert first.account_ready["contract_digest"] == canonical_digest(
        first.account_ready,
        digest_field="contract_digest",
    )

    manifest = first.operator_manifest
    assert manifest["status"] == "REPOSITORY_CANDIDATE"
    assert manifest["live_evidence"] == "NOT_PROVEN_LIVE"
    assert manifest["production_status"] == "NO_GO"
    assert manifest["deployment_authorized"] is False
    assert manifest["aws_calls"] == 0
    assert manifest["aws_mutations"] == 0
    assert manifest["binding_counts"] == {
        "terminal_roles": 8,
        "storage_bindings": 3,
        "encryption_bindings": 3,
        "state_controls": 6,
    }

    public_text = first.operator_manifest_bytes.decode("utf-8")
    private_values = {
        CUSTOMER_ID,
        DEPLOYMENT_ID,
        ACCOUNT_ID,
        *readback["state_infrastructure"].values(),
        *(role["arn"] for role in readback["roles"].values()),
    }
    assert "arn:" not in public_text
    assert all(value not in public_text for value in private_values)


def test_candidate_is_built_before_and_then_bound_to_final_target() -> None:
    target, anchor, readback = _documents()
    expected_tuple = {
        field: readback[field]
        for field in (
            "customer_id",
            "deployment_id",
            "account_id",
            "region",
            "environment",
        )
    }

    candidate = build_account_ready_v2_candidate(
        bootstrap_readback=readback,
        expected_tuple=expected_tuple,
        evaluated_at=EVALUATED_AT,
    )

    assert candidate["contract_digest"] == target["account_ready"]["contract_digest"]
    assert "target_record_digest" not in readback
    assert "target_registry_version" not in readback
    bind_account_ready_v2_candidate(
        account_ready=candidate,
        target=target,
        anchor=anchor,
    )


@pytest.mark.parametrize("role", sorted(_roles()))
def test_every_terminal_role_is_required(role: str) -> None:
    target, anchor, readback = _documents()
    del readback["roles"][role]
    readback["readback_digest"] = canonical_digest(
        readback,
        digest_field="readback_digest",
    )

    _assert_code("ACCOUNT_READY_SCHEMA_INVALID", target, anchor, readback)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("target-v1", "TARGET_V2_REQUIRED"),
        ("anchor-mismatch", "ANCHOR_TARGET_MISMATCH"),
        ("partial-readback", "READBACK_SHAPE_INVALID"),
        ("readback-not-closed", "READBACK_NOT_CLOSED"),
        ("readback-digest", "READBACK_DIGEST_MISMATCH"),
        ("placeholder", "PLACEHOLDER_INPUT_DENIED"),
        ("foreign-tag", "ROLE_TAG_MISMATCH"),
        ("foreign-role", "ROLE_ARN_MISMATCH"),
        ("swapped-roles", "ROLE_ARN_MISMATCH"),
        ("arbitrary-bucket", "BUCKET_BINDING_MISMATCH"),
        ("foreign-kms", "KMS_BINDING_MISMATCH"),
        ("wrong-control", "ACCOUNT_READY_SCHEMA_INVALID"),
        ("target-binding", "TARGET_ACCOUNT_READY_BINDING_MISMATCH"),
        ("target-not-ready", "TARGET_NOT_READY"),
    ],
)
def test_v1_partial_placeholder_foreign_and_mismatched_inputs_fail_closed(
    mutation: str,
    expected: str,
) -> None:
    target, anchor, readback = _documents()

    if mutation == "target-v1":
        target["schema_version"] = "1"
    elif mutation == "anchor-mismatch":
        anchor["registry_version"] += 1
    elif mutation == "partial-readback":
        del readback["roles"]
    elif mutation == "readback-not-closed":
        readback["status"] = "PARTIAL"
    elif mutation == "readback-digest":
        readback["observed_at"] = "2026-08-16T19:59:59Z"
    elif mutation == "placeholder":
        readback["roles"]["plan"]["arn"] = "${PLAN_ROLE_ARN}"
    elif mutation == "foreign-tag":
        readback["roles"]["plan"]["account_id_tag"] = "555666777888"
    elif mutation == "foreign-role":
        readback["roles"]["plan"]["arn"] = (
            "arn:aws:iam::555666777888:role/ScanalyzeCustomer-Plan"
        )
    elif mutation == "swapped-roles":
        plan_arn = readback["roles"]["plan"]["arn"]
        readback["roles"]["plan"]["arn"] = readback["roles"]["apply"]["arn"]
        readback["roles"]["apply"]["arn"] = plan_arn
    elif mutation == "arbitrary-bucket":
        readback["state_infrastructure"]["evidence_bucket"] = (
            f"arn:aws:s3:::arbitrary-evidence-{ACCOUNT_ID}"
        )
    elif mutation == "foreign-kms":
        readback["state_infrastructure"]["evidence_kms_key"] = (
            "arn:aws:kms:us-west-2:555666777888:key/"
            "44444444-4444-4444-8444-444444444444"
        )
    elif mutation == "wrong-control":
        readback["controls"]["native_lockfile_enabled"] = False
    elif mutation == "target-binding":
        target["account_ready"]["contract_digest"] = "sha256:" + ("a" * 64)
        _refresh_bindings(target, anchor, readback)
    elif mutation == "target-not-ready":
        target["status"] = "BASELINING"
        _refresh_bindings(target, anchor, readback)

    if mutation in {
        "readback-not-closed",
        "partial-readback",
        "placeholder",
        "foreign-tag",
        "foreign-role",
        "swapped-roles",
        "arbitrary-bucket",
        "foreign-kms",
        "wrong-control",
    }:
        readback["readback_digest"] = canonical_digest(
            readback,
            digest_field="readback_digest",
        )

    _assert_code(expected, target, anchor, readback)


def test_stale_and_future_readback_are_denied() -> None:
    target, anchor, readback = _documents()
    readback["observed_at"] = "2026-08-16T19:49:59Z"
    readback["provisioned_at"] = "2026-08-16T19:49:00Z"
    readback["readback_digest"] = canonical_digest(
        readback,
        digest_field="readback_digest",
    )
    _assert_code("READBACK_STALE", target, anchor, readback)

    target, anchor, readback = _documents()
    readback["observed_at"] = "2026-08-16T20:06:00Z"
    readback["readback_digest"] = canonical_digest(
        readback,
        digest_field="readback_digest",
    )
    _assert_code("READBACK_TIME_INCONSISTENT", target, anchor, readback)


def test_outputs_are_exclusive_owner_only_and_outside_repository(
    tmp_path: Path,
) -> None:
    target, anchor, readback = _documents()
    result = _materialize(target, anchor, readback)
    private_path = tmp_path / "account-ready.v2.json"
    public_path = tmp_path / "operator-manifest.json"

    write_materialization_outputs(
        result,
        account_ready_out=private_path,
        operator_manifest_out=public_path,
    )

    assert private_path.read_bytes() == result.account_ready_bytes
    assert public_path.read_bytes() == result.operator_manifest_bytes
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o600

    with pytest.raises(MaterializationError) as raised:
        write_materialization_outputs(
            result,
            account_ready_out=private_path,
            operator_manifest_out=tmp_path / "unused.json",
        )
    assert raised.value.code == "OUTPUT_ALREADY_EXISTS"
    assert not (tmp_path / "unused.json").exists()


def test_symlink_and_repository_output_paths_are_denied(tmp_path: Path) -> None:
    target, anchor, readback = _documents()
    result = _materialize(target, anchor, readback)
    symlink_target = tmp_path / "existing.json"
    symlink_target.write_text("preserve", encoding="utf-8")
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(symlink_target)

    with pytest.raises(MaterializationError) as raised:
        write_materialization_outputs(
            result,
            account_ready_out=symlink,
            operator_manifest_out=tmp_path / "manifest.json",
        )
    assert raised.value.code == "OUTPUT_ALREADY_EXISTS"
    assert symlink_target.read_text(encoding="utf-8") == "preserve"
    assert not (tmp_path / "manifest.json").exists()

    inside_repo = REPO_ROOT / ".gug379-forbidden-output.json"
    assert not inside_repo.exists()
    with pytest.raises(MaterializationError) as raised:
        write_materialization_outputs(
            result,
            account_ready_out=inside_repo,
            operator_manifest_out=tmp_path / "manifest.json",
        )
    assert raised.value.code == "OUTPUT_PATH_INSIDE_REPOSITORY"
    assert not inside_repo.exists()


def test_partial_write_failure_cleans_destinations_and_temporaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, anchor, readback = _documents()
    result = _materialize(target, anchor, readback)
    private_path = tmp_path / "account-ready.json"
    public_path = tmp_path / "manifest.json"
    real_link = os.link
    calls = 0

    def fail_second_link(source, destination, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic failure")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(
        "tooling.account_ready_v2_materializer.os.link",
        fail_second_link,
    )
    with pytest.raises(MaterializationError) as raised:
        write_materialization_outputs(
            result,
            account_ready_out=private_path,
            operator_manifest_out=public_path,
        )

    assert raised.value.code == "OUTPUT_WRITE_FAILED"
    assert not private_path.exists()
    assert not public_path.exists()
    assert not list(tmp_path.glob(".*.tmp-*"))


def test_parent_directory_swap_fails_closed_and_cleans_original_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, anchor, readback = _documents()
    result = _materialize(target, anchor, readback)
    output_directory = tmp_path / "outputs"
    displaced_directory = tmp_path / "displaced"
    output_directory.mkdir()
    real_link = os.link
    swapped = False

    def swap_parent_then_link(source, destination, **kwargs):
        nonlocal swapped
        if not swapped:
            output_directory.rename(displaced_directory)
            output_directory.mkdir()
            swapped = True
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(
        "tooling.account_ready_v2_materializer.os.link",
        swap_parent_then_link,
    )
    with pytest.raises(MaterializationError) as raised:
        write_materialization_outputs(
            result,
            account_ready_out=output_directory / "account-ready.json",
            operator_manifest_out=output_directory / "manifest.json",
        )

    assert raised.value.code == "OUTPUT_PARENT_CHANGED"
    assert not list(output_directory.iterdir())
    assert not list(displaced_directory.iterdir())


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_module_cli_dry_run_is_zero_cloud_and_emits_only_public_manifest(
    tmp_path: Path,
) -> None:
    target, anchor, readback = _documents()
    target_path = tmp_path / "target.json"
    anchor_path = tmp_path / "anchor.json"
    readback_path = tmp_path / "readback.json"
    _write_json(target_path, target)
    _write_json(anchor_path, anchor)
    _write_json(readback_path, readback)

    marker = tmp_path / "cloud-called"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("aws", "terraform"):
        executable = fake_bin / name
        executable.write_text(
            f"#!/bin/sh\nprintf called > '{marker}'\nexit 99\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["AWS_PROFILE"] = "must-not-be-used"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tooling.account_ready_v2_materializer",
            "--target",
            str(target_path),
            "--anchor",
            str(anchor_path),
            "--bootstrap-readback",
            str(readback_path),
            "--evaluated-at",
            EVALUATED_AT,
            "--dry-run",
        ],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(completed.stdout)
    assert manifest["status"] == "REPOSITORY_CANDIDATE"
    assert manifest["live_evidence"] == "NOT_PROVEN_LIVE"
    assert manifest["aws_calls"] == 0
    assert manifest["aws_mutations"] == 0
    assert not marker.exists()
    assert ACCOUNT_ID not in completed.stdout + completed.stderr
    assert "arn:" not in completed.stdout + completed.stderr


def test_source_has_no_cloud_subprocess_or_environment_inference() -> None:
    source = (
        REPO_ROOT / "tooling" / "account_ready_v2_materializer.py"
    ).read_text(encoding="utf-8")
    forbidden = (
        "import boto",
        "from boto",
        "import subprocess",
        "from subprocess",
        "os.environ",
        "os.getenv",
        "AWS_PROFILE",
    )
    assert all(token not in source for token in forbidden)
