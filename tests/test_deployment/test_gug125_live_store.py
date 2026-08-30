"""GUG-125 AWS adapter command-boundary tests with a defensive fake runner."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_engine import (
    build_saved_plan_approval,
    build_saved_plan_record,
    build_saved_plan_reviewer_packet,
    derive_approval_authority_digest,
)
from tooling.nonprod_live_input_materializer import RUNTIME_ENVIRONMENT_FIELDS
from tooling.nonprod_live_store import (
    AwsCliExecutionLedgerStore,
    AwsCliPlanStore,
    AwsCliTerminalSession,
    TERMINAL_CHILD_ENVIRONMENT_NAMES,
)


ACCOUNT_ID = "1" * 12
SHARED_ACCOUNT_ID = "2" * 12
DEPLOYMENT_ID = "dep_" + ("A" * 26)
EXECUTION_ID = "exec_" + ("A" * 26)
ORCHESTRATOR_ROLE = f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
ORCHESTRATOR_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ORCHESTRATOR_ROLE}"
TERMINAL_ORCHESTRATOR_ROLE_ARN = (
    f"arn:aws:iam::{SHARED_ACCOUNT_ID}:role/{ORCHESTRATOR_ROLE}"
)
REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 21, 18, 0, tzinfo=UTC)


def _sha(character: str) -> str:
    return "sha256:" + character * 64


def _plan_summary() -> dict:
    summary = {
        "add_count": 0,
        "change_count": 0,
        "read_count": 0,
        "no_op_count": 0,
        "destroy_count": 0,
        "replace_count": 0,
        "output_create_count": 0,
        "output_update_count": 0,
        "output_delete_count": 0,
        "output_no_op_count": 0,
        "output_change_count": 0,
        "output_actions": [],
        "applyable": False,
        "resource_change_count": 0,
        "resource_actions": [],
        "classification": "NO_CHANGE",
    }
    summary["summary_digest"] = canonical_digest(summary)
    return summary


def _cost_binding() -> dict:
    return {
        "cost_model_digest": _sha("a"),
        "maximum_cost_usd_micros": 10_000_000,
        "modeled_cost_upper_bound_usd_micros": 5_000_000,
    }


def _bindings() -> dict:
    bindings = {
        "customer_id": "cust_" + ("A" * 26),
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": "us-east-1",
        "environment": "dev",
        "execution_id": EXECUTION_ID,
        "change_id": "chg_" + ("A" * 26),
        "layer": "network",
        "release_version": "2026.08.21-gug382",
        "release_digest": _sha("a"),
        "release_policy_digest": _sha("b"),
        "release_projection_digest": _sha("c"),
        "plan_policy_digest": _sha("d"),
        "github_environment": f"scanalyze-{DEPLOYMENT_ID}-dev",
        "github_deployment_identity_digest": _sha("e"),
        "environment_configuration_digest": _sha("f"),
        "expected_approver_user_id": 50,
        "platform_authority_digest": _sha("1"),
        "registry_record_digest": _sha("2"),
        "account_ready_digest": _sha("3"),
        "execution_lock_digest": _sha("4"),
        "backend_binding_digest": _sha("5"),
        "contract_resolution_digest": _sha("6"),
        "toolchain_digest": _sha("7"),
        "root_module_digest": _sha("8"),
        "source_revision_digest": _sha("9"),
        "state_status": "PRESENT",
        "state_lineage": "synthetic-lineage",
        "state_serial": 3,
    }
    bindings["approval_authority_digest"] = derive_approval_authority_digest(
        github_environment=bindings["github_environment"],
        expected_approver_user_id=bindings["expected_approver_user_id"],
        github_deployment_identity_digest=bindings[
            "github_deployment_identity_digest"
        ],
        environment_configuration_digest=bindings[
            "environment_configuration_digest"
        ],
    )
    return bindings


def _plan_record() -> dict:
    bindings = _bindings()
    return build_saved_plan_record(
        bindings=bindings,
        plan_environment_anchor_digest=_sha("0"),
        plan_sha256=_sha("0"),
        plan_size_bytes=128,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{bindings['change_id']}/"
            "network/plan.tfplan"
        ),
        object_version_id="synthetic-version",
        state_readback={"status": "PRESENT", "lineage": "synthetic-lineage", "serial": 3, "object_version_id": "state-version-3", "sha256": _sha("6"), "size_bytes": 128},
        plan_summary=_plan_summary(),
        cost_binding=_cost_binding(),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _approval_record() -> dict:
    plan = _plan_record()
    return build_saved_plan_approval(
        plan_record=plan,
        repository_owner_id=10,
        repository_id=20,
        workflow_ref=(
            "synthetic-owner/scanalyze-deployment-platform/"
            ".github/workflows/nonprod-release.yml@refs/heads/main"
        ),
        workflow_sha="a" * 40,
        workflow_run_id=30,
        workflow_run_attempt=1,
        github_environment=plan["github_environment"],
        environment_configuration_digest=plan["environment_configuration_digest"],
        apply_environment_anchor_digest=_sha("9"),
        initiator_user_id=40,
        expected_approver_user_id=50,
        approver_user_id=50,
        reviewer_packet_digest=build_saved_plan_reviewer_packet(plan)[
            "packet_digest"
        ],
        approval_evidence_digest=_sha("a"),
        approval_window_started_at=NOW + timedelta(minutes=1),
        approval_observed_at=NOW + timedelta(minutes=2),
        freshness_basis="WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
        expires_at=NOW + timedelta(minutes=7),
    )


class FakeRunner:
    def __init__(
        self,
        role: str = "ScanalyzeCustomer-Plan",
        *,
        account_id: str = ACCOUNT_ID,
        read_document: dict | None = None,
        lose_plan_put_after_commit: bool = False,
        missing_control_record: bool = False,
    ) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.role = role
        self.account_id = account_id
        self.read_document = read_document
        self.lose_plan_put_after_commit = lose_plan_put_after_commit
        self.missing_control_record = missing_control_record
        self.plan_head: dict | None = None

    def __call__(self, command: tuple[str, ...]) -> str:
        self.commands.append(tuple(command))
        operation = command[2:4]
        if operation == ("get-caller-identity", "--region"):
            return json.dumps(
                {
                    "Account": self.account_id,
                    "Arn": (
                        f"arn:aws:sts::{self.account_id}:assumed-role/"
                        f"{self.role}/fixture-session"
                    ),
                }
            )
        if operation == ("put-object", "--region"):
            body = Path(command[command.index("--body") + 1])
            self.plan_head = {
                "VersionId": "fixture-version",
                "ContentLength": body.stat().st_size,
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": command[command.index("--ssekms-key-id") + 1],
                "BucketKeyEnabled": True,
                "ChecksumSHA256": command[command.index("--checksum-sha256") + 1],
                "Metadata": json.loads(command[command.index("--metadata") + 1]),
            }
            if self.lose_plan_put_after_commit:
                self.lose_plan_put_after_commit = False
                raise AuthorizationError("simulated lost S3 put response")
            return json.dumps({"VersionId": "fixture-version"})
        if operation == ("head-object", "--region"):
            if self.plan_head is None:
                raise AuthorizationError("saved plan is absent")
            return json.dumps(self.plan_head)
        if operation == ("get-object", "--region"):
            if command[-3:-1] != ("--output", "json"):
                raise AssertionError("get-object destination must be the final argument")
            Path(command[-1]).write_bytes(b"exact saved plan")
            return "{}"
        if operation == ("get-item", "--region"):
            if self.missing_control_record:
                return "{}"
            document = _ledger() if self.read_document is None else self.read_document
            return json.dumps({"Item": {"document": {"S": json.dumps(document)}}})
        if operation == ("assume-role", "--region"):
            return json.dumps(
                {
                    "Credentials": {
                        "AccessKeyId": "synthetic-access-key",
                        "SecretAccessKey": "synthetic-secret-key",
                        "SessionToken": "synthetic-session-token",
                    }
                }
            )
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
        "plan_environment_anchor_digest": _sha("b"),
        "expected_approver_user_id": 50,
        "approval_authority_digest": _bindings()["approval_authority_digest"],
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


class ProcessRecorder:
    def __init__(self, return_code: int = 0) -> None:
        self.return_code = return_code
        self.command: tuple[str, ...] | None = None
        self.environment: dict[str, str] | None = None

    def __call__(self, command: tuple[str, ...], environment: dict[str, str]) -> int:
        self.command = tuple(command)
        self.environment = dict(environment)
        return self.return_code


def test_terminal_identity_is_exact_and_no_default_profile_is_injected() -> None:
    runner = FakeRunner()
    store = _plan_store(runner)

    assert store.verify_terminal_identity("ScanalyzeCustomer-Plan") == {
        "account_id": ACCOUNT_ID,
        "role": "ScanalyzeCustomer-Plan",
    }
    assert "--profile" not in runner.commands[0]


def test_terminal_child_preserves_every_action_time_runtime_binding() -> None:
    assert set(RUNTIME_ENVIRONMENT_FIELDS.values()) <= set(
        TERMINAL_CHILD_ENVIRONMENT_NAMES
    )


@pytest.mark.parametrize("environment", ["dev", "staging"])
def test_terminal_session_uses_exact_tags_source_identity_and_ephemeral_credentials(
    environment: str,
) -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, account_id=SHARED_ACCOUNT_ID)
    process = ProcessRecorder()
    session = AwsCliTerminalSession(
        region="us-east-1",
        account_id=ACCOUNT_ID,
        runner=runner,
        process_runner=process,
    )
    customer_id = "cust_" + ("A" * 26)
    change_id = "chg_" + ("A" * 26)

    session.run_terminal_phase(
        orchestrator_role_arn=TERMINAL_ORCHESTRATOR_ROLE_ARN,
        role_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-Plan",
        customer_id=customer_id,
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        change_id=change_id,
        environment=environment,
        operation="plan",
        layer="network",
        command=("/repository/terraform-saved-plan.sh", "plan"),
        base_environment={
            "PATH": "/usr/bin:/bin",
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_SHA": "a" * 40,
            "AWS_PROFILE": "must-not-propagate",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/must/not/propagate",
            "AWS_ENDPOINT_URL_STS": "https://must-not-propagate.invalid",
            "BASH_ENV": "/must/not/propagate",
            "PYTHONPATH": "/must/not/propagate",
        },
    )

    identity, assume = runner.commands
    assert identity[:3] == ("aws", "sts", "get-caller-identity")
    assert assume[:3] == ("aws", "sts", "assume-role")
    assert assume[assume.index("--role-session-name") + 1] == EXECUTION_ID
    assert assume[assume.index("--source-identity") + 1] == EXECUTION_ID
    assert assume[assume.index("--duration-seconds") + 1] == "3600"
    for key, value in {
        "customer_id": customer_id,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "environment": environment,
        "operation": "plan",
        "layer": "network",
        "change_id": change_id,
    }.items():
        assert f"Key={key},Value={value}" in assume
    assert "--profile" not in assume
    assert process.command == ("/repository/terraform-saved-plan.sh", "plan")
    assert process.environment is not None
    assert process.environment["AWS_ACCESS_KEY_ID"] == "synthetic-access-key"
    assert process.environment["AWS_EC2_METADATA_DISABLED"] == "true"
    assert process.environment["GITHUB_ACTIONS"] == "true"
    assert process.environment["GITHUB_RUN_ATTEMPT"] == "1"
    assert process.environment["GITHUB_WORKFLOW_SHA"] == "a" * 40
    assert process.environment["PATH"] == "/usr/bin:/bin"
    assert "AWS_PROFILE" not in process.environment
    assert "AWS_WEB_IDENTITY_TOKEN_FILE" not in process.environment
    assert "AWS_ENDPOINT_URL_STS" not in process.environment
    assert "BASH_ENV" not in process.environment
    assert "PYTHONPATH" not in process.environment


def test_terminal_session_rejects_production_before_aws_or_process() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, account_id=SHARED_ACCOUNT_ID)
    process = ProcessRecorder()
    session = AwsCliTerminalSession(
        region="us-east-1",
        account_id=ACCOUNT_ID,
        runner=runner,
        process_runner=process,
    )

    with pytest.raises(AuthorizationError, match="terminal session binding"):
        session.run_terminal_phase(
            orchestrator_role_arn=TERMINAL_ORCHESTRATOR_ROLE_ARN,
            role_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/ScanalyzeCustomer-Plan",
            customer_id="cust_" + ("A" * 26),
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            change_id="chg_" + ("A" * 26),
            environment="production",
            operation="plan",
            layer="network",
            command=("/repository/terraform-saved-plan.sh", "plan"),
            base_environment={},
        )
    assert runner.commands == []
    assert process.command is None


def test_terminal_session_rejects_wrong_role_before_aws_or_process() -> None:
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, account_id=SHARED_ACCOUNT_ID)
    process = ProcessRecorder()
    session = AwsCliTerminalSession(
        region="us-east-1",
        account_id=ACCOUNT_ID,
        runner=runner,
        process_runner=process,
    )

    with pytest.raises(AuthorizationError, match="terminal role"):
        session.run_terminal_phase(
            orchestrator_role_arn=TERMINAL_ORCHESTRATOR_ROLE_ARN,
            role_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/Administrator",
            customer_id="cust_" + ("A" * 26),
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            change_id="chg_" + ("A" * 26),
            environment="dev",
            operation="apply",
            layer="network",
            command=("/repository/terraform-saved-plan.sh", "apply"),
            base_environment={},
        )
    assert runner.commands == []
    assert process.command is None


def test_plan_write_is_create_only_versioned_and_kms_encrypted(tmp_path: Path) -> None:
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"exact saved plan")
    runner = FakeRunner()
    store = _plan_store(runner)

    result = store.put_plan_once(
        path=plan,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
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
    assert "--checksum-sha256" in command
    assert "--metadata" in command


def test_plan_write_reconciles_commit_with_lost_response(tmp_path: Path) -> None:
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"exact saved plan")
    runner = FakeRunner(lose_plan_put_after_commit=True)

    result = _plan_store(runner).put_plan_once(
        path=plan,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/chg_{'A' * 26}/network/plan.tfplan"
        ),
        kms_key_arn=(
            f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/fixture-evidence-key"
        ),
    )

    assert result["object_version_id"] == "fixture-version"
    assert [command[2] for command in runner.commands] == ["put-object", "head-object"]


def test_plan_read_uses_exact_version_and_exclusive_destination(tmp_path: Path) -> None:
    runner = FakeRunner()
    store = _plan_store(runner)
    destination = tmp_path / "downloaded.tfplan"

    result = store.get_plan_version(
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/chg_{'A' * 26}/network/plan.tfplan"
        ),
        object_version_id="fixture-version",
        destination=destination,
    )

    assert result["size_bytes"] == len(b"exact saved plan")
    command = runner.commands[0]
    assert "--version-id" in command
    assert command[command.index("--checksum-mode") + 1] == "ENABLED"
    assert command[-3:] == ("--output", "json", str(destination))
    assert destination.stat().st_mode & 0o777 == 0o600
    original = destination.read_bytes()
    with pytest.raises(AuthorizationError, match="must not already exist"):
        store.get_plan_version(
            bucket=result["bucket"],
            object_key=result["object_key"],
            object_version_id=result["object_version_id"],
            destination=destination,
        )
    assert destination.read_bytes() == original


def test_plan_store_rejects_noncanonical_bucket_key_or_kms_before_aws(
    tmp_path: Path,
) -> None:
    plan = tmp_path / "plan.tfplan"
    plan.write_bytes(b"exact saved plan")
    canonical_key = (
        f"plan-execution/{DEPLOYMENT_ID}/chg_{'A' * 26}/network/plan.tfplan"
    )
    canonical_kms = f"arn:aws:kms:us-east-1:{ACCOUNT_ID}:key/synthetic-state-key"

    for bucket, key, kms in (
        (f"scanalyze-{ACCOUNT_ID}-tf-state", canonical_key, canonical_kms),
        (
            f"scanalyze-{ACCOUNT_ID}-tf-plan",
            "plan-execution/foreign/plan.tfplan",
            canonical_kms,
        ),
        (
            f"scanalyze-{ACCOUNT_ID}-tf-plan",
            canonical_key,
            f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:key/foreign",
        ),
    ):
        runner = FakeRunner()
        with pytest.raises(AuthorizationError, match="bucket|object key|KMS"):
            _plan_store(runner).put_plan_once(
                path=plan,
                bucket=bucket,
                object_key=key,
                kms_key_arn=kms,
            )
        assert runner.commands == []


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


def test_plan_control_record_is_create_only_and_read_consistently() -> None:
    plan = _plan_record()
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, read_document=plan)
    store = _ledger_store(runner)

    store.put_plan_record_once(plan)
    assert store.get_plan_record(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
    ) == plan

    create, read = runner.commands
    assert create[:3] == ("aws", "dynamodb", "put-item")
    assert "attribute_not_exists(record_key)" in create[
        create.index("--condition-expression") + 1
    ]
    item = json.loads(create[create.index("--item") + 1])
    assert item["record_key"]["S"] == f"plan#{EXECUTION_ID}#network"
    assert set(item) == {"deployment_id", "record_key", "document"}
    assert "--consistent-read" in read
    assert read[read.index("--projection-expression") + 1] == "document"
    assert "--profile" not in create + read


def test_optional_health_and_reconciliation_reads_distinguish_absence() -> None:
    runner = FakeRunner(
        role=ORCHESTRATOR_ROLE,
        missing_control_record=True,
    )
    store = _ledger_store(runner)

    assert store.find_health_receipt(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
    ) is None
    assert store.find_reconciliation_receipt(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
    ) is None
    assert all("--consistent-read" in command for command in runner.commands)

    with pytest.raises(AuthorizationError, match="missing"):
        store.get_health_receipt(
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            layer="network",
        )


def test_approval_control_record_is_time_bound_and_create_only() -> None:
    approval = _approval_record()
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, read_document=approval)
    store = _ledger_store(runner)

    store.put_approval_record_once(approval, now=NOW + timedelta(minutes=3))
    assert store.get_approval_record(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
        approval_digest=approval["approval_digest"],
        now=NOW + timedelta(minutes=3),
    ) == approval

    item = json.loads(runner.commands[0][runner.commands[0].index("--item") + 1])
    assert item["record_key"]["S"] == (
        f"approval#{EXECUTION_ID}#network#{approval['approval_digest'][7:]}"
    )

    with pytest.raises(AuthorizationError, match="currently valid"):
        _ledger_store(FakeRunner(read_document=approval)).get_approval_record(
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            layer="network",
            approval_digest=approval["approval_digest"],
            now=NOW + timedelta(minutes=46),
        )


def test_approval_control_records_are_append_only_and_digest_addressed() -> None:
    first = _approval_record()
    second = dict(first)
    second["workflow_run_id"] += 1
    second["approval_digest"] = canonical_digest(
        {key: value for key, value in second.items() if key != "approval_digest"}
    )
    runner = FakeRunner(role=ORCHESTRATOR_ROLE, read_document=second)
    store = _ledger_store(runner)

    store.put_approval_record_once(first, now=NOW + timedelta(minutes=3))
    store.put_approval_record_once(second, now=NOW + timedelta(minutes=3))
    assert store.get_approval_record(
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        layer="network",
        approval_digest=second["approval_digest"],
        now=NOW + timedelta(minutes=3),
    ) == second

    first_item = json.loads(
        runner.commands[0][runner.commands[0].index("--item") + 1]
    )
    second_item = json.loads(
        runner.commands[1][runner.commands[1].index("--item") + 1]
    )
    assert first_item["record_key"] != second_item["record_key"]
    with pytest.raises(AuthorizationError, match="digest is invalid"):
        store.get_approval_record(
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            layer="network",
            approval_digest="sha256:invalid",
            now=NOW + timedelta(minutes=3),
        )


def test_control_record_read_rejects_tuple_or_digest_substitution() -> None:
    foreign_tuple = _plan_record()
    foreign_tuple["execution_id"] = "exec_" + ("B" * 26)
    foreign_tuple["record_digest"] = canonical_digest(
        {key: value for key, value in foreign_tuple.items() if key != "record_digest"}
    )
    with pytest.raises(AuthorizationError, match="storage key binding"):
        _ledger_store(FakeRunner(read_document=foreign_tuple)).get_plan_record(
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            layer="network",
        )

    tampered = _plan_record()
    tampered["plan_sha256"] = _sha("f")
    with pytest.raises(AuthorizationError, match="digest mismatch"):
        _ledger_store(FakeRunner(read_document=tampered)).get_plan_record(
            deployment_id=DEPLOYMENT_ID,
            execution_id=EXECUTION_ID,
            layer="network",
        )


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
    identity_plan = _policy("policies/iam/identity-control-plane-plan-role.json")
    identity_apply = _policy("policies/iam/identity-control-plane-apply-role.json")

    for writer, writer_sid, reader, reader_sid in (
        (plan, "WriteOwnSavedPlan", apply, "ReadOwnSavedPlanVersion"),
        (
            identity_plan,
            "WriteIdentityPlanExecutionZone",
            identity_apply,
            "ReadIdentityPlanExecutionZone",
        ),
    ):
        write_statement = next(
            item for item in writer["Statement"] if item["Sid"] == writer_sid
        )
        read_statement = next(
            item for item in reader["Statement"] if item["Sid"] == reader_sid
        )

        assert _actions(writer, writer_sid) == {"s3:GetObject", "s3:PutObject"}
        assert _actions(reader, reader_sid) == {"s3:GetObjectVersion"}
        assert read_statement["Resource"] == write_statement["Resource"]
        assert "-tf-plan/plan-execution/" in write_statement["Resource"]
        assert "-tf-state/plan-execution/" not in write_statement["Resource"]

    assert {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"} <= _actions(
        plan, "EncryptExactSavedPlan"
    )
    assert {"kms:Decrypt"} <= _actions(apply, "UseApplyBaselineKeys")
    assert {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"} <= _actions(
        identity_plan, "EncryptExactIdentitySavedPlan"
    )
    assert _actions(identity_apply, "ReadSavedPlanKey") == {"kms:Decrypt"}

    state_key_arn = (
        "arn:${aws_partition}:kms:${region}:${account_id}:key/${state_kms_key_id}"
    )
    evidence_key_arn = (
        "arn:${aws_partition}:kms:${region}:${account_id}:key/${evidence_kms_key_id}"
    )
    for policy, sid in (
        (plan, "UsePlanBaselineKeys"),
        (identity_plan, "UseStateKeyForIdentityPlan"),
    ):
        statement = next(item for item in policy["Statement"] if item["Sid"] == sid)
        resources = statement["Resource"]
        resource_set = {resources} if isinstance(resources, str) else set(resources)
        assert state_key_arn in resource_set
        assert evidence_key_arn not in resource_set

    apply_baseline_keys = next(
        item for item in apply["Statement"] if item["Sid"] == "UseApplyBaselineKeys"
    )
    assert state_key_arn in set(apply_baseline_keys["Resource"])
    assert evidence_key_arn not in set(apply_baseline_keys["Resource"])
    apply_saved_plan_key = next(
        item for item in apply["Statement"] if item["Sid"] == "ReadSavedPlanKey"
    )
    assert _actions(apply, "ReadSavedPlanKey") == {"kms:Decrypt"}
    assert apply_saved_plan_key["Resource"] == evidence_key_arn

    identity_apply_saved_plan_key = next(
        item
        for item in identity_apply["Statement"]
        if item["Sid"] == "ReadSavedPlanKey"
    )
    assert identity_apply_saved_plan_key["Resource"] == evidence_key_arn

    for policy, sid, operation in (
        (plan, "EncryptExactSavedPlan", "plan"),
        (identity_plan, "EncryptExactIdentitySavedPlan", "plan"),
        (apply, "ReadSavedPlanKey", "apply"),
        (identity_apply, "ReadSavedPlanKey", "apply"),
    ):
        statement = next(item for item in policy["Statement"] if item["Sid"] == sid)
        context = statement["Condition"]["StringEquals"]
        assert statement["Resource"] == evidence_key_arn
        assert context["aws:PrincipalTag/operation"] == operation
        assert context["kms:ViaService"] == "s3.${region}.${aws_url_suffix}"
        assert context["kms:EncryptionContext:aws:s3:arn"] == (
            "arn:${aws_partition}:s3:::scanalyze-${account_id}-tf-plan"
        )

    for policy in (plan, apply, identity_plan, identity_apply):
        serialized = json.dumps(policy, sort_keys=True)
        assert "-tf-plan/plan-execution/" in serialized
        assert "${evidence_kms_key_id}" in serialized


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
