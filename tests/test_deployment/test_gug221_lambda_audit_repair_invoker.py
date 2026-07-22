"""Tests for the human-side GUG-221 Lambda broker invoker."""

from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Sequence

import pytest

from tooling.platform_authority_lambda_audit_repair_invoker import (
    AUTHORITY_ACCOUNT_ID,
    AwsCommandResult,
    BrokerInvokeError,
    MODE_BINDINGS,
    MODE_INVOKE_TIMEOUTS,
    SYNC_CLIENT_CONTEXT_CUSTOM,
    invoke_broker,
    sanitized_failure,
    validate_public_receipt,
)


SOURCE_COMMIT = "a" * 40
FUNCTION_VERSION = "7"
PROFILE = "042360977644_ScanalyzeLambdaAuditRepair"
SESSION_ARN = (
    "arn:aws:sts::042360977644:assumed-role/"
    "AWSReservedSSO_ScanalyzeLambdaAuditRepair_0123456789ABCDEF/"
    "operator@example.invalid"
)


def receipt(mode: str = "plan") -> dict[str, Any]:
    _, alias = MODE_BINDINGS[mode]
    status = {
        "plan": "PLAN_VERIFIED",
        "repair": "REPAIR_VERIFIED",
        "reconcile": "RECONCILE_VERIFIED",
    }[mode]
    is_durable_proof = mode in {"plan", "repair", "reconcile"}
    is_verified_effect = mode in {"repair", "reconcile"}
    return {
        "schema_version": 1,
        "record_type": "scanalyze.platform_authority.lambda_audit_repair_broker_receipt.v1",
        "mode": mode,
        "status": status,
        "repair_id_digest": "1" * 64,
        "source_commit": SOURCE_COMMIT,
        "function_version": FUNCTION_VERSION,
        "function_qualifier": alias,
        "region": "us-east-1",
        "authority_account_suffix": "7644",
        "management_account_suffix": "1433",
        "intent_digest": "2" * 64,
        "ledger_digest": "3" * 64 if is_durable_proof else None,
        "state_digest": "4" * 64,
        "effects_attempted": 3 if is_verified_effect else 0,
        "effects_completed": 3 if is_verified_effect else 0,
        "mutation_attribution": (
            "PROVEN_BY_DURABLE_LEDGER" if is_durable_proof else "UNPROVEN"
        ),
        "required_next_action": (
            "INVOKE_REPAIR_ALIAS" if mode == "plan" else "NONE"
        ),
        "generated_at": "2026-07-21T15:00:00Z",
        "production_status": "NO-GO",
    }


class FakeRunner:
    def __init__(
        self,
        *,
        public_receipt: dict[str, Any] | None = None,
        invoke_returncode: int = 0,
        function_error: bool = False,
        metadata_stdout: str | None = None,
        response_body: str | None = None,
        write_response: bool = True,
        account: str = AUTHORITY_ACCOUNT_ID,
        arn: str = SESSION_ARN,
    ) -> None:
        self.public_receipt = public_receipt or receipt()
        self.invoke_returncode = invoke_returncode
        self.function_error = function_error
        self.metadata_stdout = metadata_stdout
        self.response_body = response_body
        self.write_response = write_response
        self.account = account
        self.arn = arn
        self.calls: list[tuple[str, ...]] = []
        self.timeouts: list[int] = []

    def __call__(self, command: Sequence[str], timeout: int) -> AwsCommandResult:
        normalized = tuple(command)
        self.calls.append(normalized)
        self.timeouts.append(timeout)
        assert timeout in {30, 330, 630}
        if "get-caller-identity" in normalized:
            return AwsCommandResult(
                0,
                json.dumps({"Account": self.account, "Arn": self.arn, "UserId": "redacted"}),
            )
        assert "invoke" in normalized
        if self.write_response:
            Path(normalized[-1]).write_text(
                self.response_body
                if self.response_body is not None
                else json.dumps(self.public_receipt),
                encoding="utf-8",
            )
        metadata: dict[str, Any] = {
            "StatusCode": 200,
            "ExecutedVersion": FUNCTION_VERSION,
        }
        if self.function_error:
            metadata["FunctionError"] = "Unhandled"
        return AwsCommandResult(
            self.invoke_returncode,
            self.metadata_stdout
            if self.metadata_stdout is not None
            else json.dumps(metadata),
        )


def run(
    tmp_path: Path,
    *,
    mode: str = "plan",
    runner: FakeRunner | None = None,
    allow_repair: bool | None = None,
) -> tuple[dict[str, Any], FakeRunner]:
    active = runner or FakeRunner(public_receipt=receipt(mode))
    value = invoke_broker(
        mode=mode,
        profile=PROFILE,
        expected_source_commit=SOURCE_COMMIT,
        expected_function_version=FUNCTION_VERSION,
        allow_server_side_repair=(mode == "repair" if allow_repair is None else allow_repair),
        runner=active,
        private_directory_factory=lambda: tmp_path,
    )
    return value, active


@pytest.mark.parametrize("mode", tuple(MODE_BINDINGS))
def test_invoker_uses_one_exact_private_alias_and_empty_payload(
    tmp_path: Path, mode: str
) -> None:
    value, runner = run(tmp_path, mode=mode)
    function_name, alias = MODE_BINDINGS[mode]
    assert value == receipt(mode)
    assert len(runner.calls) == 2
    invoke = runner.calls[1]
    assert invoke[invoke.index("--function-name") + 1] == function_name
    assert invoke[invoke.index("--qualifier") + 1] == alias
    assert invoke[invoke.index("--payload") + 1] == "{}"
    assert invoke[invoke.index("--invocation-type") + 1] == "RequestResponse"
    assert invoke[invoke.index("--cli-connect-timeout") + 1] == "10"
    read_timeout, process_timeout = MODE_INVOKE_TIMEOUTS[mode]
    assert invoke[invoke.index("--cli-read-timeout") + 1] == str(read_timeout)
    assert runner.timeouts == [30, process_timeout]
    encoded_context = invoke[invoke.index("--client-context") + 1]
    assert json.loads(base64.b64decode(encoded_context).decode("utf-8")) == {
        "custom": SYNC_CLIENT_CONTEXT_CUSTOM
    }
    assert "Event" not in invoke
    assert invoke.count("invoke") == 1
    serialized = " ".join(invoke)
    assert not any(token in serialized for token in ("sso-admin", "identitystore", "dynamodb"))
    assert not list(tmp_path.glob("response-*.json"))


def test_mode_bindings_use_three_dedicated_functions() -> None:
    assert MODE_BINDINGS == {
        "plan": ("scanalyze-authority-lambda-audit-plan", "plan-v1"),
        "repair": ("scanalyze-authority-lambda-audit-repair", "repair-v1"),
        "reconcile": (
            "scanalyze-authority-lambda-audit-reconcile",
            "reconcile-v1",
        ),
    }
    assert MODE_INVOKE_TIMEOUTS == {
        "plan": (315, 330),
        "repair": (615, 630),
        "reconcile": (315, 330),
    }


def test_repair_requires_explicit_local_confirmation_before_sts(tmp_path: Path) -> None:
    runner = FakeRunner(public_receipt=receipt("repair"))
    with pytest.raises(BrokerInvokeError, match="REPAIR_CONFIRMATION_INVALID"):
        run(tmp_path, mode="repair", runner=runner, allow_repair=False)
    assert runner.calls == []


def test_read_modes_reject_repair_confirmation(tmp_path: Path) -> None:
    runner = FakeRunner(public_receipt=receipt("plan"))
    with pytest.raises(BrokerInvokeError, match="REPAIR_CONFIRMATION_INVALID"):
        run(tmp_path, runner=runner, allow_repair=True)
    assert runner.calls == []


@pytest.mark.parametrize(
    ("account", "arn"),
    [
        ("839393571433", SESSION_ARN),
        (AUTHORITY_ACCOUNT_ID, SESSION_ARN.replace("ScanalyzeLambdaAuditRepair", "AWSReadOnlyAccess")),
    ],
)
def test_invoker_rejects_wrong_account_or_permission_set_before_lambda(
    tmp_path: Path, account: str, arn: str
) -> None:
    runner = FakeRunner(account=account, arn=arn)
    with pytest.raises(BrokerInvokeError, match="INVOKER_IDENTITY_INVALID"):
        run(tmp_path, runner=runner)
    assert len(runner.calls) == 1


def test_invocation_failure_is_uncertain_and_never_retried(tmp_path: Path) -> None:
    runner = FakeRunner(invoke_returncode=255)
    with pytest.raises(BrokerInvokeError) as raised:
        run(tmp_path, runner=runner)
    assert raised.value.code == "INVOKE_RESPONSE_UNCERTAIN"
    assert raised.value.may_have_reached_function is True
    assert len(runner.calls) == 2
    assert sanitized_failure(raised.value) == {
        "status": "UNCERTAIN_RECONCILE_ONLY",
        "reason_code": "INVOKE_RESPONSE_UNCERTAIN",
        "required_next_action": "INVOKE_RECONCILE_ALIAS",
        "production_status": "NO-GO",
    }


def test_function_error_is_uncertain_and_never_exposes_payload(tmp_path: Path) -> None:
    runner = FakeRunner(function_error=True)
    with pytest.raises(BrokerInvokeError) as raised:
        run(tmp_path, runner=runner)
    assert raised.value.may_have_reached_function is True
    assert len(runner.calls) == 2
    assert not list(tmp_path.glob("response-*.json"))


@pytest.mark.parametrize(
    "failure",
    ("malformed_metadata", "missing_body", "malformed_body", "binding_drift"),
)
def test_every_post_dispatch_parse_or_binding_failure_is_uncertain(
    tmp_path: Path, failure: str
) -> None:
    kwargs: dict[str, Any] = {}
    if failure == "malformed_metadata":
        kwargs["metadata_stdout"] = "{"
    elif failure == "missing_body":
        kwargs["write_response"] = False
    elif failure == "malformed_body":
        kwargs["response_body"] = "{"
    else:
        drifted = receipt()
        drifted["source_commit"] = "b" * 40
        kwargs["public_receipt"] = drifted

    runner = FakeRunner(**kwargs)
    with pytest.raises(BrokerInvokeError) as raised:
        run(tmp_path, runner=runner)

    assert raised.value.code == "INVOKE_RESPONSE_UNCERTAIN"
    assert raised.value.may_have_reached_function is True
    assert len(runner.calls) == 2
    assert sanitized_failure(raised.value) == {
        "status": "UNCERTAIN_RECONCILE_ONLY",
        "reason_code": "INVOKE_RESPONSE_UNCERTAIN",
        "required_next_action": "INVOKE_RECONCILE_ALIAS",
        "production_status": "NO-GO",
    }
    assert not list(tmp_path.glob("response-*.json"))


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("source_commit", "b" * 40, "PUBLIC_RECEIPT_BINDING_MISMATCH"),
        ("function_qualifier", "repair-v1", "PUBLIC_RECEIPT_BINDING_MISMATCH"),
        ("authority_account_suffix", "1433", "PUBLIC_RECEIPT_BINDING_MISMATCH"),
        ("production_status", "GO", "PUBLIC_RECEIPT_BINDING_MISMATCH"),
        ("required_next_action", "retry repair", "PUBLIC_RECEIPT_INVALID"),
    ],
)
def test_public_receipt_rejects_drift_and_overclaim(
    field: str, value: Any, code: str
) -> None:
    candidate = receipt()
    candidate[field] = value
    with pytest.raises(BrokerInvokeError, match=code):
        validate_public_receipt(
            candidate,
            expected_mode="plan",
            expected_alias="plan-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )


def test_plan_receipt_requires_durable_create_only_proof() -> None:
    candidate = receipt()
    candidate["ledger_digest"] = None
    candidate["mutation_attribution"] = "UNPROVEN"
    candidate["required_next_action"] = "NONE"
    with pytest.raises(BrokerInvokeError, match="PUBLIC_RECEIPT_OVERCLAIM"):
        validate_public_receipt(
            candidate,
            expected_mode="plan",
            expected_alias="plan-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )


def test_uncertain_receipt_requires_reconcile_alias() -> None:
    candidate = receipt("repair")
    candidate["status"] = "UNCERTAIN_RECONCILE_ONLY"
    candidate["required_next_action"] = "NONE"
    with pytest.raises(BrokerInvokeError, match="PUBLIC_RECEIPT_OVERCLAIM"):
        validate_public_receipt(
            candidate,
            expected_mode="repair",
            expected_alias="repair-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )


def test_blocked_receipt_cannot_claim_all_three_effects_completed() -> None:
    candidate = receipt("repair")
    candidate["status"] = "BLOCKED"
    candidate["required_next_action"] = "REVIEW_BLOCKER"
    with pytest.raises(BrokerInvokeError, match="PUBLIC_RECEIPT_OVERCLAIM"):
        validate_public_receipt(
            candidate,
            expected_mode="repair",
            expected_alias="repair-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )


@pytest.mark.parametrize(
    ("changes", "mode"),
    [
        ({"ledger_digest": None}, "reconcile"),
        ({"effects_attempted": 0, "effects_completed": 0}, "reconcile"),
        ({"mutation_attribution": "UNPROVEN"}, "reconcile"),
        ({"required_next_action": "REVIEW_BLOCKER"}, "reconcile"),
    ],
)
def test_reconcile_verified_receipt_rejects_missing_durable_proof(
    changes: dict[str, Any], mode: str
) -> None:
    candidate = receipt(mode)
    candidate.update(changes)
    with pytest.raises(BrokerInvokeError, match="PUBLIC_RECEIPT_OVERCLAIM"):
        validate_public_receipt(
            candidate,
            expected_mode=mode,
            expected_alias="reconcile-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )


@pytest.mark.parametrize(
    ("profile", "source", "version", "code"),
    [
        ("bad profile", SOURCE_COMMIT, FUNCTION_VERSION, "PROFILE_INVALID"),
        (PROFILE, "short", FUNCTION_VERSION, "SOURCE_COMMIT_INVALID"),
        (PROFILE, SOURCE_COMMIT, "$LATEST", "FUNCTION_VERSION_INVALID"),
    ],
)
def test_invalid_local_bindings_fail_before_aws(
    tmp_path: Path, profile: str, source: str, version: str, code: str
) -> None:
    runner = FakeRunner()
    with pytest.raises(BrokerInvokeError, match=code):
        invoke_broker(
            mode="plan",
            profile=profile,
            expected_source_commit=source,
            expected_function_version=version,
            allow_server_side_repair=False,
            runner=runner,
            private_directory_factory=lambda: tmp_path,
        )
    assert runner.calls == []


def test_receipt_with_unknown_field_is_rejected() -> None:
    candidate = deepcopy(receipt())
    candidate["principal_id"] = "sensitive"
    with pytest.raises(BrokerInvokeError, match="PUBLIC_RECEIPT_INVALID"):
        validate_public_receipt(
            candidate,
            expected_mode="plan",
            expected_alias="plan-v1",
            expected_source_commit=SOURCE_COMMIT,
            expected_function_version=FUNCTION_VERSION,
        )
