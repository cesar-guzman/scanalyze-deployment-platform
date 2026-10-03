"""Causal offline gates: syntactic Batch consistency never creates authority."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tooling.platform_authority_bootstrap_artifact_package import (
    EXPECTED_BOTO3_VERSION,
    EXPECTED_BOTOCORE_VERSION,
    PROVENANCE_PATHS,
)
from tooling.platform_authority_bootstrap_signed_artifact import (
    BATCH_SHA256_SOURCE,
    CHECKSUM_EVIDENCE_CONTRACT_PATH,
    EXPECTED_VERIFIER_PROFILE,
    MAX_CHECKSUM_CONTRACT_BYTES,
    NATIVE_SHA256_SOURCE,
    BootstrapSignedArtifactError,
    build_signed_artifact_receipt_from_aws,
    load_checksum_evidence_contract,
    require_signed_checksum_source,
    validate_checksum_evidence_contract,
    validate_signed_artifact_receipt,
)


ROOT = Path(__file__).resolve().parents[2]


def _contract() -> dict:
    # Only the public, fixed repository policy; no receipt/provider artifacts.
    return json.loads((ROOT / CHECKSUM_EVIDENCE_CONTRACT_PATH).read_text())


def _write_contract(root: Path, raw: bytes | None = None) -> Path:
    path = root / CHECKSUM_EVIDENCE_CONTRACT_PATH
    path.parent.mkdir(parents=True)
    path.write_bytes(raw if raw is not None else json.dumps(_contract()).encode())
    return path


class _NoProvider:
    def __getattr__(self, name: str):
        raise AssertionError(f"provider access before custody decision: {name}")


def test_disabled_public_contract_has_no_enablement_or_producer_claim() -> None:
    contract = load_checksum_evidence_contract(source_root=ROOT)
    assert contract["configuration_status"] == "NOT_CONFIGURED"
    assert contract["report_producer_verifier"] is None
    assert contract["report_schema"] is None
    assert contract["activation_authorized"] is False
    assert contract["production_status"] == "NO-GO"
    assert CHECKSUM_EVIDENCE_CONTRACT_PATH in PROVENANCE_PATHS
    assert Path("tooling/platform_authority_bootstrap_batch_checksum.py") in PROVENANCE_PATHS


def test_native_route_does_not_depend_on_disabled_batch_policy(tmp_path: Path) -> None:
    # A missing or hostile Batch proposal must not weaken or change native v1.
    require_signed_checksum_source(source_root=tmp_path, checksum_source=NATIVE_SHA256_SOURCE)
    _write_contract(tmp_path, b'{"activation_authorized":true}')
    require_signed_checksum_source(source_root=tmp_path, checksum_source=NATIVE_SHA256_SOURCE)


@pytest.mark.parametrize("source", [None, True, 1, [], {}, "crc64nvme", "latest"])
def test_unknown_or_untyped_selector_stops_before_policy_read(tmp_path: Path, source: object) -> None:
    with pytest.raises(BootstrapSignedArtifactError, match="SIGNED_CHECKSUM_SOURCE_INVALID"):
        require_signed_checksum_source(source_root=tmp_path, checksum_source=source)


def test_batch_route_stops_before_any_source_sdk_or_provider_read(tmp_path: Path, monkeypatch) -> None:
    _write_contract(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("source/SDK/provider collection before custody decision")

    monkeypatch.setattr(
        "tooling.platform_authority_bootstrap_signed_artifact.load_signing_trust_root_contract",
        forbidden,
    )
    monkeypatch.setattr(
        "tooling.platform_authority_bootstrap_signed_artifact.build_bootstrap_artifact_package",
        forbidden,
    )
    monkeypatch.setattr(
        "tooling.platform_authority_bootstrap_signed_artifact.verify_reviewed_source_release",
        forbidden,
    )
    with pytest.raises(BootstrapSignedArtifactError, match="HUMAN_DECISION_REQUIRED:REPORT_PRODUCER_PROVENANCE_UNPROVEN"):
        build_signed_artifact_receipt_from_aws(
            source_root=tmp_path,
            source_commit="a" * 40,
            expected_boto3_version=EXPECTED_BOTO3_VERSION,
            expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
            profile_name=EXPECTED_VERIFIER_PROFILE,
            job_id="11111111-2222-4333-8444-555555555555",
            sts_client=_NoProvider(), signer_client=_NoProvider(), s3_client=_NoProvider(),
            checksum_source=BATCH_SHA256_SOURCE,
        )


@pytest.mark.parametrize(("field", "value"), [
    ("configuration_status", "CONFIGURED_REVIEWED"),
    ("activation_authorized", True), ("activation_authorized", 0),
    ("schema_version", True), ("schema_version", 1.0),
    ("intended_receipt_schema_version", True),
    ("authority_account_id", "905418363887"), ("region", "us-west-2"),
    ("checksum_algorithm", "CRC64NVME"), ("checksum_type", "COMPOSITE"),
    ("report_schema", "Bucket, Key, VersionId, TaskStatus, HTTPStatusCode, ErrorCode, ResultMessage"),
    ("report_producer_verifier", {"custody_verified": True}),
    ("blocking_requirements", []), ("production_status", "PRODUCTION_READY"),
])
def test_no_operator_flag_can_enable_the_unimplemented_route(field: str, value: object) -> None:
    contract = _contract()
    contract[field] = value
    with pytest.raises(BootstrapSignedArtifactError, match="CHECKSUM_EVIDENCE_CONTRACT_INVALID"):
        validate_checksum_evidence_contract(contract)


@pytest.mark.parametrize("change", ["extra", "missing", "array", "null"])
def test_contract_is_closed(change: str) -> None:
    contract = _contract()
    if change == "extra":
        contract["receipt_digest"] = "sha256:" + "a" * 64
    elif change == "missing":
        contract.pop("report_producer_verifier")
    elif change == "array":
        contract = []
    else:
        contract = None
    with pytest.raises(BootstrapSignedArtifactError, match="CHECKSUM_EVIDENCE_CONTRACT_INVALID"):
        validate_checksum_evidence_contract(contract)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":NaN}', b'{"schema_version":Infinity}',
    b'\xff', b'', b'{' * (MAX_CHECKSUM_CONTRACT_BYTES + 1),
])
def test_contract_rejects_duplicate_nonfinite_or_unbounded_input(tmp_path: Path, raw: bytes) -> None:
    _write_contract(tmp_path, raw)
    with pytest.raises(BootstrapSignedArtifactError):
        load_checksum_evidence_contract(source_root=tmp_path)


@pytest.mark.parametrize("parent_link", [False, True])
def test_fixed_policy_cannot_follow_leaf_or_parent_symlink(tmp_path: Path, parent_link: bool) -> None:
    actual_root = tmp_path / "actual"
    actual = _write_contract(actual_root)
    source = tmp_path / "source"
    source.mkdir()
    if parent_link:
        (source / "bootstrap").symlink_to(actual.parent, target_is_directory=True)
    else:
        path = source / CHECKSUM_EVIDENCE_CONTRACT_PATH
        path.parent.mkdir()
        path.symlink_to(actual)
    with pytest.raises(BootstrapSignedArtifactError, match="CHECKSUM_EVIDENCE_CONTRACT_UNAVAILABLE"):
        load_checksum_evidence_contract(source_root=source)


def test_v2_plan_cannot_be_interpreted_as_v1_receipt() -> None:
    forged = copy.deepcopy(_contract())
    forged.update(
        artifact_type="scanalyze.platform_authority.bootstrap_signed_artifact_receipt.v2",
        schema_version=2, receipt_digest="sha256:" + "a" * 64,
        custody_verified=True,
    )
    with pytest.raises(BootstrapSignedArtifactError):
        validate_signed_artifact_receipt(forged)


def test_actual_isolated_cli_batch_choice_stops_before_sdk_and_creates_nothing(tmp_path: Path) -> None:
    output = tmp_path / "not-created.json"
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/deployment/platform-authority-bootstrap-signed-artifact.py"),
         "--profile", EXPECTED_VERIFIER_PROFILE, "--region", "us-east-1",
         "--source-commit", "a" * 40, "--expected-boto3-version", EXPECTED_BOTO3_VERSION,
         "--expected-botocore-version", EXPECTED_BOTOCORE_VERSION,
         "--job-id", "11111111-2222-4333-8444-555555555555",
         "--signed-checksum-source", BATCH_SHA256_SOURCE, "--output-receipt", str(output)],
        env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == (
        "GUG274_SIGNED_ARTIFACT_BLOCKED:HUMAN_DECISION_REQUIRED:"
        "REPORT_PRODUCER_PROVENANCE_UNPROVEN:REPORT_DIALECT_NOT_REVIEWED\n"
    )
    assert not output.exists()


def test_source_contract_schema_matches_runtime_and_is_closed() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas/platform-authority-bootstrap-checksum-evidence-contract.v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(_contract())
    for change in ({"activation_authorized": True}, {"configuration_status": "CONFIGURED_REVIEWED"}, {"extra": True}):
        contract = {**_contract(), **change}
        assert list(validator.iter_errors(contract))


def test_schema_routing_and_semantics_reject_integer_lookalikes() -> None:
    from tooling.validate_schema import find_schema_for_fixture, validate_semantics

    schema = ROOT / "schemas/platform-authority-bootstrap-checksum-evidence-contract.v1.schema.json"
    assert find_schema_for_fixture(
        "platform-authority-bootstrap-checksum-evidence-contract-v1-not-configured.json",
        ROOT / "schemas",
    ) == schema
    assert validate_semantics(_contract(), schema) == []
    # JSON Schema defines 1.0 as an integer; the Python/provider boundary uses
    # exact integers and must not grant a permissive alternate interpretation.
    for change in ({"schema_version": 1.0}, {"schema_version": True}, {"intended_receipt_schema_version": 2.0}):
        contract = {**_contract(), **change}
        assert validate_semantics(contract, schema)
