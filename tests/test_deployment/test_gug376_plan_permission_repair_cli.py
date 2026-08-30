from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tooling.platform_authority_plan_permission_repair import (
    RepairBinding,
    build_private_intent,
    digest_value,
    immutable_configuration_digest_from_parameters,
    validate_private_intent,
)

from tests.test_deployment.test_gug376_plan_permission_repair import (
    _binding_record,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = (
    REPO_ROOT
    / "scripts/deployment/platform-authority-plan-permission-repair.py"
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={"PATH": os.environ.get("PATH", "")},
    )


def test_cli_materializes_and_validates_private_intent(tmp_path: Path) -> None:
    binding = tmp_path / "binding.json"
    intent_path = tmp_path / "private" / "intent.json"
    binding.write_text(json.dumps(_binding_record()), encoding="utf-8")

    materialized = _run(
        "materialize-intent",
        "--binding",
        str(binding),
        "--output",
        str(intent_path),
    )
    assert materialized.returncode == 0, materialized.stderr
    receipt = json.loads(materialized.stdout)
    assert receipt["status"] == "PRIVATE_INTENT_MATERIALIZED"
    assert receipt["aws_calls"] == 0
    assert receipt["aws_mutations"] == 0
    assert receipt["production_status"] == "NO-GO"
    assert intent_path.stat().st_mode & 0o777 == 0o600
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    validate_private_intent(intent)

    validated = _run("validate-intent", "--input", str(intent_path))
    assert validated.returncode == 0, validated.stderr
    validation = json.loads(validated.stdout)
    assert validation["status"] == "CONTRACT_VALIDATED"
    assert validation["contract_digest"] == intent["intent_digest"]


def test_cli_materializes_verified_version_replacement_digest(
    tmp_path: Path,
) -> None:
    binding = RepairBinding.from_mapping(_binding_record())
    intent = build_private_intent(binding, repo_root=REPO_ROOT)
    parameters = {
        "SourceCommit": intent["source_commit"],
        "SourceBundleDigest": intent["source_bundle_digest"],
        "RepairId": intent["repair_id"],
        "PrincipalId": intent["principal_id"],
        "IdentityStoreId": intent["identity_store_id"],
        "IdentityCenterInstanceArn": intent["instance_arn"],
        "PlanPermissionSetArn": intent["permission_set_arn"],
        "ExpectedPermissionSetDescription": intent[
            "permission_set_description"
        ],
        "RepairInvokerPermissionSetArn": intent[
            "repair_invoker_permission_set_arn"
        ],
        "CurrentPolicyDigest": intent["predecessor_policy_digest"],
        "DesiredPolicyDigest": intent["target_policy_digest"],
        "ExpectedPlanPermissionSetTagsJson": json.dumps(
            intent["permission_set_tags"],
            sort_keys=True,
            separators=(",", ":"),
        ),
        "BootstrapChangeSetName": intent["change_set_name"],
        "RepairNotBefore": intent["not_before"],
        "RepairNotAfter": intent["not_after"],
        "PlanSamlProviderArn": intent["saml_provider_arn"],
        "IdentityCenterKmsMode": intent["identity_center_kms_mode"],
        "IdentityCenterKmsKeyArn": (
            intent["identity_center_kms_key_arn"] or ""
        ),
        "ExpectedBoto3Version": intent["expected_boto3_version"],
        "ExpectedBotocoreVersion": intent["expected_botocore_version"],
        "ArtifactCodeSha256": intent["expected_artifact_code_sha256"],
        "SigningProfileVersionArn": intent[
            "expected_signing_profile_version_arn"
        ],
    }
    parameter_path = tmp_path / "private-parameters.json"
    parameter_path.write_text(json.dumps(parameters), encoding="utf-8")

    result = _run(
        "materialize-configuration-digest",
        "--parameters",
        str(parameter_path),
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["status"] == (
        "IMMUTABLE_CONFIGURATION_DIGEST_MATERIALIZED"
    )
    assert receipt["cloudformation_parameter"] == {
        "ParameterKey": "ImmutableConfigurationDigest",
        "ParameterValue": immutable_configuration_digest_from_parameters(
            parameters
        ),
    }
    assert receipt["aws_calls"] == receipt["aws_mutations"] == 0


def test_cli_live_modes_never_call_aws_or_accept_human_mutation() -> None:
    for command in ("plan", "repair", "reconcile"):
        result = _run(command)
        assert result.returncode == 2
        assert not result.stdout
        blocked = json.loads(result.stderr)
        assert blocked["blocker_code"] == (
            "EXACT_VERSIONED_LAMBDA_CONTRACT_REQUIRED"
        )
        assert blocked["aws_calls"] == 0
        assert blocked["aws_mutations"] == 0
        assert blocked["direct_human_sso_mutation_authorized"] is False


def test_cli_does_not_overwrite_existing_private_output(tmp_path: Path) -> None:
    binding = tmp_path / "binding.json"
    output = tmp_path / "intent.json"
    binding.write_text(json.dumps(_binding_record()), encoding="utf-8")
    output.write_text("owner-data", encoding="utf-8")
    result = _run(
        "materialize-intent",
        "--binding",
        str(binding),
        "--output",
        str(output),
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["blocker_code"] == "OUTPUT_WRITE_BLOCKED"
    assert output.read_text(encoding="utf-8") == "owner-data"


def test_cli_rejects_resealed_receipt_with_private_extra_field(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt = json.loads(
        (
            REPO_ROOT
            / "fixtures/valid/"
            "platform-authority-plan-permission-repair-receipt-v1-synthetic.json"
        ).read_text(encoding="utf-8")
    )
    private_value = "/private/operator/evidence.json"
    receipt["private_evidence_path"] = private_value
    receipt.pop("receipt_digest")
    receipt["receipt_digest"] = digest_value(receipt)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = _run("validate-receipt", "--input", str(receipt_path))

    assert result.returncode == 2
    assert result.stdout == ""
    blocker = json.loads(result.stderr)
    assert blocker["blocker_code"] == "RECEIPT_FIELDS_INVALID"
    assert private_value not in result.stderr


@pytest.mark.parametrize(
    ("command", "fixture_name", "digest_field", "expected_code"),
    (
        (
            "validate-intent",
            "platform-authority-plan-permission-repair-intent-v1-synthetic.json",
            "intent_digest",
            "INTENT_FIELDS_INVALID",
        ),
        (
            "validate-ledger",
            "platform-authority-plan-permission-repair-ledger-v1-synthetic.json",
            "ledger_digest",
            "LEDGER_FIELDS_INVALID",
        ),
    ),
)
def test_cli_rejects_resealed_private_contract_with_extra_field(
    tmp_path: Path,
    command: str,
    fixture_name: str,
    digest_field: str,
    expected_code: str,
) -> None:
    contract_path = tmp_path / "private-contract.json"
    contract = json.loads(
        (REPO_ROOT / "fixtures/valid" / fixture_name).read_text(
            encoding="utf-8"
        )
    )
    private_value = "/private/operator/evidence.json"
    contract["operator_profile"] = private_value
    contract.pop(digest_field)
    contract[digest_field] = digest_value(contract)
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    result = _run(command, "--input", str(contract_path))

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["blocker_code"] == expected_code
    assert private_value not in result.stderr
