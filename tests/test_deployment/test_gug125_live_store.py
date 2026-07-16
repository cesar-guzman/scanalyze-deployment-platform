"""GUG-125 AWS adapter command-boundary tests with a defensive fake runner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_store import AwsCliExecutionLedgerStore, AwsCliPlanStore


ACCOUNT_ID = "1" * 12
DEPLOYMENT_ID = "dep_" + ("A" * 26)
EXECUTION_ID = "exec_" + ("A" * 26)
ORCHESTRATOR_ROLE = f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
ORCHESTRATOR_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ORCHESTRATOR_ROLE}"
REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeRunner:
    def __init__(self, role: str = "ScanalyzeCustomer-Plan") -> None:
        self.commands: list[tuple[str, ...]] = []
        self.role = role

    def __call__(self, command: tuple[str, ...]) -> str:
        self.commands.append(tuple(command))
        operation = command[2:4]
        if operation == ("get-caller-identity", "--region"):
            return json.dumps(
                {
                    "Account": ACCOUNT_ID,
                    "Arn": (
                        f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/"
                        f"{self.role}/fixture-session"
                    ),
                }
            )
        if operation == ("put-object", "--region"):
            return json.dumps({"VersionId": "fixture-version"})
        if operation == ("get-object", "--region"):
            Path(command[-3]).write_bytes(b"exact saved plan")
            return "{}"
        if operation == ("get-item", "--region"):
            return json.dumps({"Item": {"document": {"S": json.dumps(_ledger())}}})
        return "{}"


def _ledger() -> dict:
    document = {
        "schema_version": "1",
        "record_type": "live_execution_layer",
        "customer_id": "cust_" + ("A" * 26),
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "environment": "sandbox",
        "execution_id": EXECUTION_ID,
        "change_id": "chg_" + ("A" * 26),
        "layer": "network",
        "status": "PLANNED",
        "ledger_version": 1,
        "plan_record_digest": "sha256:" + ("a" * 64),
        "updated_at": "2026-07-15T18:00:00Z",
        "attempt_count": 0,
    }
    document["ledger_digest"] = canonical_digest(document)
    return document


def _plan_store(runner: FakeRunner) -> AwsCliPlanStore:
    return AwsCliPlanStore(
        region="us-east-1",
        account_id=ACCOUNT_ID,
        runner=runner,
    )


def _ledger_store(runner: FakeRunner) -> AwsCliExecutionLedgerStore:
    return AwsCliExecutionLedgerStore(
        region="us-east-1",
        shared_services_account_id=ACCOUNT_ID,
        ledger_table="scanalyze-deployment-executions",
        runner=runner,
    )


def test_terminal_identity_is_exact_and_no_default_profile_is_injected() -> None:
    runner = FakeRunner()
    store = _plan_store(runner)

    assert store.verify_terminal_identity("ScanalyzeCustomer-Plan") == {
        "account_id": ACCOUNT_ID,
        "role": "ScanalyzeCustomer-Plan",
    }
    assert "--profile" not in runner.commands[0]


def test_plan_write_is_create_only_versioned_and_kms_encrypted(tmp_path: Path) -> None:
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"exact saved plan")
    runner = FakeRunner()
    store = _plan_store(runner)

    result = store.put_plan_once(
        path=plan,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-evidence",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/chg_{'A' * 26}/network/plan.tfplan"
        ),
        kms_key_arn=(
            f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/fixture-evidence-key"
        ),
    )
    command = runner.commands[0]

    assert result["object_version_id"] == "fixture-version"
    assert result["sha256"].startswith("sha256:")
    assert command[0:3] == ("aws", "s3api", "put-object")
    assert command[command.index("--server-side-encryption") + 1] == "aws:kms"
    assert command[command.index("--if-none-match") + 1] == "*"
    assert "--checksum-algorithm" in command


def test_plan_read_uses_exact_version_and_exclusive_destination(tmp_path: Path) -> None:
    runner = FakeRunner()
    store = _plan_store(runner)
    destination = tmp_path / "downloaded.tfplan"

    result = store.get_plan_version(
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-evidence",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/chg_{'A' * 26}/network/plan.tfplan"
        ),
        object_version_id="fixture-version",
        destination=destination,
    )

    assert result["size_bytes"] == len(b"exact saved plan")
    assert "--version-id" in runner.commands[0]
    assert runner.commands[0][runner.commands[0].index("--checksum-mode") + 1] == "ENABLED"
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(AuthorizationError, match="must not already exist"):
        store.get_plan_version(
            bucket=result["bucket"],
            object_key=result["object_key"],
            object_version_id=result["object_version_id"],
            destination=destination,
        )


def test_ledger_create_and_replace_are_conditional() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE)
    store = _ledger_store(runner)

    store.verify_orchestrator_identity(
        ORCHESTRATOR_ROLE_ARN,
        deployment_id=DEPLOYMENT_ID,
    )
    ledger = _ledger()

    store.create_ledger(ledger)
    store.replace_ledger(
        ledger=ledger,
        expected_deployment_id=DEPLOYMENT_ID,
        expected_execution_id=EXECUTION_ID,
        expected_layer="network",
        expected_version=1,
        expected_digest=ledger["ledger_digest"],
        expected_status="PLANNED",
    )

    create = runner.commands[1]
    replace = runner.commands[2]
    assert "attribute_not_exists(deployment_id)" in create[
        create.index("--condition-expression") + 1
    ]
    assert "ledger_version = :expected_version" in replace[
        replace.index("--condition-expression") + 1
    ]
    assert "--condition-expression" in create
    assert "--condition-expression" in replace


def test_ledger_replace_rejects_request_to_document_key_confusion() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE)
    store = _ledger_store(runner)
    ledger = _ledger()

    with pytest.raises(AuthorizationError, match="storage key binding"):
        store.replace_ledger(
            ledger=ledger,
            expected_deployment_id=DEPLOYMENT_ID,
            expected_execution_id="exec_" + ("B" * 26),
            expected_layer="network",
            expected_version=1,
            expected_digest=ledger["ledger_digest"],
            expected_status="PLANNED",
        )


def test_ledger_read_rejects_outer_key_to_document_confusion() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE)
    store = _ledger_store(runner)

    with pytest.raises(AuthorizationError, match="storage key binding"):
        store.get_ledger(
            deployment_id=DEPLOYMENT_ID,
            execution_id="exec_" + ("B" * 26),
            layer="network",
        )


def test_ledger_read_is_strongly_consistent_and_projected() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE)
    store = _ledger_store(runner)

    assert store.get_ledger(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
    ) == _ledger()
    command = runner.commands[0]
    assert "--consistent-read" in command
    assert command[command.index("--projection-expression") + 1] == "document"


def test_noncanonical_table_or_role_is_denied() -> None:
    with pytest.raises(AuthorizationError, match="canonical"):
        AwsCliExecutionLedgerStore(
            region="us-east-1",
            shared_services_account_id=ACCOUNT_ID,
            ledger_table="caller-selected-table",
        )
    with pytest.raises(AuthorizationError, match="not approved"):
        _plan_store(FakeRunner()).verify_terminal_identity("Administrator")


def test_shared_authority_must_be_separate_from_destination_account() -> None:
    store = _ledger_store(FakeRunner(role=ORCHESTRATOR_ROLE))

    with pytest.raises(AuthorizationError, match="separate"):
        store.verify_destination_separation(ACCOUNT_ID)

    assert store.verify_destination_separation("2" * 12) == {
        "destination_account_id": "2" * 12,
        "shared_services_account_id": ACCOUNT_ID,
    }


def test_plan_and_ledger_stores_do_not_share_authority() -> None:
    assert not hasattr(_plan_store(FakeRunner()), "create_ledger")
    assert not hasattr(_ledger_store(FakeRunner()), "put_plan_once")

    wrong = FakeRunner(role="ScanalyzeCustomer-Plan")
    with pytest.raises(AuthorizationError, match="orchestrator"):
        _ledger_store(wrong).verify_orchestrator_identity(
            ORCHESTRATOR_ROLE_ARN,
            deployment_id=DEPLOYMENT_ID,
        )


@pytest.mark.parametrize(
    ("role", "deployment_id"),
    [
        ("ScanalyzeReleaseOrchestrator", DEPLOYMENT_ID),
        (ORCHESTRATOR_ROLE, "dep_" + ("B" * 26)),
        ("scanalyze/" + ORCHESTRATOR_ROLE, DEPLOYMENT_ID),
    ],
)
def test_orchestrator_identity_requires_exact_deployment_role(
    role: str,
    deployment_id: str,
) -> None:
    runner = FakeRunner(role=role)

    with pytest.raises(AuthorizationError, match="authority"):
        _ledger_store(runner).verify_orchestrator_identity(
            f"arn:aws:iam::{ACCOUNT_ID}:role/{role}",
            deployment_id=deployment_id,
        )


def _policy(path: str) -> dict:
    return json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))


def _actions(document: dict, sid: str) -> set[str]:
    statement = next(item for item in document["Statement"] if item["Sid"] == sid)
    actions = statement["Action"]
    return {actions} if isinstance(actions, str) else set(actions)


def test_exact_plan_kms_and_version_permissions_are_complete() -> None:
    plan = _policy("policies/iam/plan-role.json")
    apply = _policy("policies/iam/apply-role.json")
    key = _policy("policies/kms/evidence-key.json")
    bucket = _policy("policies/s3/evidence-bucket.json")

    assert {"kms:Encrypt", "kms:GenerateDataKey"} <= _actions(
        plan, "EncryptEvidenceKey"
    )
    assert {"kms:Decrypt"} <= _actions(apply, "DecryptEvidenceKey")
    assert {"kms:Encrypt", "kms:GenerateDataKey"} <= _actions(
        key, "AllowPlanEncrypt"
    )
    assert {"kms:Decrypt"} <= _actions(key, "AllowApplyDecrypt")
    decrypt_statement = next(
        item for item in key["Statement"] if item["Sid"] == "AllowApplyDecrypt"
    )
    assert set(decrypt_statement["Principal"]["AWS"]) == {
        "arn:aws:iam::${account_id}:role/ScanalyzeCustomer-Apply",
        "arn:aws:iam::${account_id}:role/ScanalyzeCustomer-Identity-Apply",
    }
    assert decrypt_statement["Condition"]["StringEquals"] == {
        "kms:ViaService": "s3.${region}.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": (
            "arn:aws:s3:::scanalyze-${account_id}-tf-evidence"
        ),
    }
    encrypt_statement = next(
        item for item in key["Statement"] if item["Sid"] == "AllowPlanEncrypt"
    )
    assert encrypt_statement["Condition"] == decrypt_statement["Condition"]
    assert {"s3:GetObjectVersion"} <= _actions(apply, "ReadPlanExecutionZone")
    assert {"s3:GetObjectVersion"} <= _actions(
        bucket, "AllowApplyReadPlanExecution"
    )


def test_live_plan_store_has_no_delete_surface() -> None:
    assert not hasattr(_plan_store(FakeRunner()), "delete_plan_version")


def test_orchestrator_policy_owns_only_shared_execution_ledger() -> None:
    policy = _policy("policies/iam/orchestrator-role.json")
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ManageExecutionLedger"
    )

    assert set(statement["Action"]) == {
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
    }
    assert statement["Resource"].endswith("table/scanalyze-deployment-executions")
    assert "${shared_services_account_id}" in statement["Resource"]
