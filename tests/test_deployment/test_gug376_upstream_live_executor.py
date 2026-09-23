"""Offline integration: actual ledger/transport, synthetic clients/verifiers."""

from datetime import datetime, timedelta, timezone
import traceback

import pytest

from tooling.platform_authority_gug365_upstream_prerequisites import PHASE_NAMES
from tooling.platform_authority_gug376_upstream_live_executor import (
    Checkpoint, ExecutionError, TrustPins, UpstreamExecutor, VerifiedReceipt, Verifiers,
)
from tooling.platform_authority_gug376_upstream_live_ledger import (
    DurableMutationLedger, LedgerError, ledger_root_digest,
)
from tooling.platform_authority_gug376_upstream_live_plan import (
    LiveOperation, PlanError, Readback, RunPlan, digest,
)
from tooling.platform_authority_gug376_upstream_live_provider import (
    UpstreamLiveProvider, UpstreamProviderError,
)


NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
ACCOUNT = "839393571433"
CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_Fixture_0123456789abcdef/operator"
APP = "arn:aws:sso::111111111111:application/ssoins-1111111111111111/apl-1111111111111111"
PINS = TrustPins(digest("anchor"), digest("verifier-code"))


class FixtureVerifier:
    """Never accepted for AWS: fixture receipts are permanently SYNTHETIC."""

    def __init__(self):
        self.stages = []
        self.failure = None
        self.invalid = None
        self.callback = None
        self.anchor = None

    def identity(self):
        return PINS

    def verify(self, *, stage, expected, evidence, now):
        self.stages.append(stage)
        if self.callback:
            self.callback(stage)
        if stage == self.failure:
            raise ValueError("private provider error must never escape")
        if stage == "LEDGER_ANCHOR":
            assert "snapshot" in evidence and "history" in evidence["snapshot"]
            if self.anchor is not None:
                assert expected["previous_snapshot_digest"] == self.anchor
            self.anchor = expected["snapshot_digest"]
        if stage == self.invalid:
            return True
        return VerifiedReceipt(stage, digest(expected), digest({"stage": stage, "binding": expected}),
                               PINS.trust_anchor_digest, PINS.verifier_code_digest, "SYNTHETIC")


class Client:
    def __init__(self, state, service):
        self.state, self.service = state, service

    def close(self):
        self.state.setdefault("closed_clients", []).append(self.service)

    def __getattr__(self, method):
        def call(**kwargs):
            self.state["calls"].append((self.service, method))
            if method == "get_caller_identity":
                return {"Account": ACCOUNT, "Arn": CALLER}
            if method == "create_application":
                if self.state.get("crash"):
                    raise KeyboardInterrupt
                if self.state.get("timeout"):
                    raise TimeoutError("private request should stay private")
                self.state["writes"] += 1
                return {"ApplicationArn": APP}
            if method == "describe_application":
                return dict(self.state["application"])
            return {}
        return call


def setup(tmp_path):
    plan = RunPlan(source_commit="a" * 40, source_tree="b" * 40,
        owner_decisions_digest=digest("decisions"), template_write_set_digest=digest("write-set"),
        phase_accounts={phase: ACCOUNT if phase == "IDENTITY_CENTER_FOUNDATION" else "042360977644" for phase in PHASE_NAMES},
        custody_digest=ledger_root_digest(tmp_path), trust_anchor_digest=PINS.trust_anchor_digest,
        verifier_code_digest=PINS.verifier_code_digest, run_nonce_digest=digest("one-run"),
        evidence_mode="SYNTHETIC")
    ledger = DurableMutationLedger(tmp_path, run_digest=plan.run_digest,
        plan_digest=plan.plan_digest, operations=plan.operations)
    genesis = ledger.create()
    state = {"calls": [], "writes": 0, "application": {
        "ApplicationArn": APP, "ApplicationProviderArn": "arn:aws:sso::aws:applicationProvider/custom",
        "InstanceArn": "arn:aws:sso:::instance/ssoins-1111111111111111", "Name": "fixture",
        "Status": "ENABLED", "PortalOptions": {"Visibility": "DISABLED"}}}
    read_request = {"ApplicationArn": APP}
    projection = "SSO_DESCRIBE_APPLICATION_V1"
    readback = Readback(projection, read_request, state["application"])
    before = digest([{"projection": projection, "request_digest": digest(read_request),
                      "projection_value": state["application"]}])
    request = {"ApplicationProviderArn": state["application"]["ApplicationProviderArn"],
               "ClientToken": "fixture-client-token-0000000000000000", "Description": "Synthetic fixture",
               "InstanceArn": state["application"]["InstanceArn"], "Name": "fixture",
               "PortalOptions": {"Visibility": "DISABLED"}, "Status": "ENABLED", "Tags": []}
    operation = LiveOperation(operation_id=plan.operations[0][0], account_id=ACCOUNT,
        region="us-east-1", request=request, before_state_digest=before,
        target_state_digest=digest([readback.binding()]), predecessor_slots_digest=digest("genesis-slots"),
        before_readbacks=(readback,), readbacks=(readback,))
    clients = {service: Client(state, service) for service in ("sts", "sso-admin", "kms", "s3", "signer", "lambda")}
    provider = UpstreamLiveProvider.from_injected_clients(clients=clients,
        expected_account_id=ACCOUNT, expected_caller_arn=CALLER, region="us-east-1")
    now = [NOW]
    verifier = FixtureVerifier()
    verifiers = Verifiers(verifier, verifier, verifier, verifier)
    executor = UpstreamExecutor(plan=plan, ledger=ledger, verifiers=verifiers,
        trusted_pins=PINS, clock=lambda: now[0])
    checkpoint = Checkpoint(issued_at=NOW, expires_at=NOW + timedelta(minutes=5),
        session_expires_at=NOW + timedelta(minutes=10), session_digest=digest("session"),
        caller_arn_digest=digest(CALLER), source_verification_digest=digest("source-proof"),
        policy_digest=digest("phase-policy"), maximum_permissions_digest=digest("phase-policy"),
        effective_authority_digest=digest("authority"), expected_snapshot_digest=genesis["snapshot_digest"])
    args = dict(operation=operation, checkpoint=checkpoint, provider=provider,
                owner_evidence=None, preflight_evidence=None, anchor_evidence=None)
    return executor, args, ledger, state, verifier, now


def test_success_requires_external_receipts_and_persists_attempt(tmp_path):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    result = executor.execute_one(**args)
    assert result.status == "SUCCEEDED"
    assert result.mode == "SYNTHETIC" and result.production_authorized is False
    assert state["writes"] == 1
    assert state["calls"][0] == ("sts", "get_caller_identity")
    assert "PREFLIGHT" in verifier.stages and "OPERATION" in verifier.stages
    assert ledger.snapshot()["operations"][0]["attempt_count"] == 1
    with pytest.raises(ExecutionError, match="FRESH_EXECUTOR_SESSION_REQUIRED"):
        executor.execute_one(**args)


@pytest.mark.parametrize("stage", ["LEDGER_ANCHOR", "OWNER_AUTHORIZATION", "PREFLIGHT", "BEFORE_STATE"])
def test_preflight_verification_failure_never_writes(tmp_path, stage):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    verifier.failure = stage
    with pytest.raises(ExecutionError, match="EXTERNAL_VERIFICATION_FAILED"):
        executor.execute_one(**args)
    assert state["writes"] == 0
    assert ledger.snapshot()["operations"][0]["status"] == "READY"


def test_approval_boolean_cannot_authenticate(tmp_path):
    executor, args, _, state, verifier, _ = setup(tmp_path)
    verifier.invalid = "OWNER_AUTHORIZATION"
    with pytest.raises(ExecutionError, match="EXTERNAL_RECEIPT_INVALID"):
        executor.execute_one(**args)
    assert state["writes"] == 0


def test_verifier_error_message_is_not_in_public_traceback(tmp_path):
    executor, args, _, _, verifier, _ = setup(tmp_path)
    verifier.failure = "OWNER_AUTHORIZATION"
    with pytest.raises(ExecutionError) as error:
        executor.execute_one(**args)
    rendered = "".join(traceback.format_exception(error.value))
    assert "private provider error must never escape" not in rendered
    assert "EXTERNAL_VERIFICATION_FAILED" in rendered


def test_receipt_failure_after_write_consumes_attempt(tmp_path):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    verifier.failure = "OPERATION"
    result = executor.execute_one(**args)
    assert result.status == "AMBIGUOUS" and state["writes"] == 1
    assert ledger.snapshot()["operations"][0]["status"] == "AMBIGUOUS"


def test_crash_after_durable_claim_never_replays(tmp_path):
    executor, args, ledger, state, _, _ = setup(tmp_path)
    state["crash"] = True
    with pytest.raises(KeyboardInterrupt):
        executor.execute_one(**args)
    snapshot = ledger.snapshot()
    assert snapshot["operations"][0]["status"] == "IN_FLIGHT"
    with pytest.raises(LedgerError):
        ledger.claim(args["operation"].operation_id, request_digest=args["operation"].request_digest,
                     authorization_digest=digest("new-auth"), observed_at=NOW,
                     expected_snapshot_digest=snapshot["snapshot_digest"])


def test_before_state_drift_stops_before_claim(tmp_path):
    executor, args, ledger, state, _, _ = setup(tmp_path)
    state["application"]["Status"] = "DISABLED"
    with pytest.raises(ExecutionError, match="BEFORE_STATE_DRIFT"):
        executor.execute_one(**args)
    assert state["writes"] == 0 and ledger.snapshot()["operations"][0]["status"] == "READY"


def test_impossible_response_binding_is_rejected_before_ledger_claim(tmp_path):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    operation = args["operation"]
    original = operation.readbacks[0]
    expected = original.expected_projection
    # CreateApplication cannot produce an S3 object version. This must fail
    # before consuming the durable attempt, even with a valid target digest.
    expected["ApplicationArn"] = {"response_field": "VersionId"}
    invalid = Readback(original.projection, original.request, expected)
    args["operation"] = LiveOperation(operation_id=operation.operation_id,
        account_id=operation.account_id, region=operation.region, request=operation.request,
        before_state_digest=operation.before_state_digest,
        target_state_digest=digest([invalid.binding()]),
        predecessor_slots_digest=operation.predecessor_slots_digest,
        before_readbacks=operation.before_readbacks, readbacks=(invalid,))
    before = ledger.snapshot()
    calls_before = list(state["calls"])
    with pytest.raises(UpstreamProviderError, match="READBACK_RESPONSE_BINDING_INVALID"):
        executor.execute_one(**args)
    assert ledger.snapshot() == before
    assert state["calls"] == calls_before and state["writes"] == 0
    assert set(state["closed_clients"]) == {"sts", "sso-admin", "kms", "s3", "signer", "lambda"}
    assert verifier.stages == []


def test_expiry_during_owner_verification_prevents_write(tmp_path):
    executor, args, ledger, state, verifier, now = setup(tmp_path)
    verifier.callback = lambda stage: now.__setitem__(0, NOW + timedelta(minutes=6)) if stage == "OWNER_AUTHORIZATION" else None
    with pytest.raises(ExecutionError, match="AUTHORIZATION_NOT_CURRENT"):
        executor.execute_one(**args)
    assert state["writes"] == 0 and ledger.snapshot()["operations"][0]["status"] == "READY"


def test_expiry_immediately_before_mutation_consumes_claim_without_write(tmp_path):
    executor, args, ledger, state, verifier, now = setup(tmp_path)
    def expire(stage):
        if stage == "OWNER_AUTHORIZATION" and verifier.stages.count(stage) == 3:
            now[0] += timedelta(minutes=6)
    verifier.callback = expire
    result = executor.execute_one(**args)
    assert result.status == "AMBIGUOUS" and state["writes"] == 0
    assert ledger.snapshot()["operations"][0]["attempt_count"] == 1


def test_noop_requires_verification_and_preserves_zero_write_count(tmp_path):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    result = executor.execute_one(**args, exact_present=True)
    assert result.status == "EXACT_PRESENT_NO_TOUCH" and state["writes"] == 0
    assert "EXACT_PRESENT_NO_TOUCH" in verifier.stages
    assert ledger.snapshot()["operations"][0]["attempt_count"] == 0


def test_complete_catalog_and_distinct_request_contracts(tmp_path):
    executor, args, _, _, _, _ = setup(tmp_path)
    assert len(executor.plan.operations) == 30
    assert set(executor.plan.binding()["phase_accounts"]) == set(PHASE_NAMES)
    assert args["operation"].contract_digest != args["operation"].request_digest


def test_private_requests_are_detached_and_absent_from_repr(tmp_path):
    _, args, _, _, _, _ = setup(tmp_path)
    operation = args["operation"]
    original = operation.request_digest
    detached = operation.request
    detached["Name"] = "changed"
    assert operation.request_digest == original and operation.request["Name"] == "fixture"
    assert "fixture-client-token" not in repr(operation)


def test_finalize_requires_complete_ledger_and_cannot_promote_synthetic(tmp_path):
    executor, _, ledger, _, _, _ = setup(tmp_path)
    snapshot = ledger.snapshot()
    with pytest.raises(ExecutionError, match="UPSTREAM_RUN_INCOMPLETE"):
        executor.finalize(expected_snapshot_digest=snapshot["snapshot_digest"], final_evidence=None,
                          anchor_evidence=None, mode="SYNTHETIC")
    with pytest.raises(ExecutionError, match="EVIDENCE_MODE_MISMATCH"):
        executor.finalize(expected_snapshot_digest=snapshot["snapshot_digest"], final_evidence=None,
                          anchor_evidence=None, mode="AWS_TRANSPORT")


@pytest.mark.parametrize("minutes", [0, 16, -1])
def test_invalid_authorization_windows(tmp_path, minutes):
    _, args, _, _, _, _ = setup(tmp_path)
    binding = args["checkpoint"].binding()
    for key in ("issued_at", "expires_at", "session_expires_at", "automatic_rollback", "role_chaining", "additive_grants", "batch_size"):
        binding.pop(key)
    with pytest.raises(ExecutionError, match="AUTHORIZATION_WINDOW_INVALID"):
        Checkpoint(issued_at=NOW, expires_at=NOW + timedelta(minutes=minutes),
                   session_expires_at=NOW + timedelta(minutes=20), **binding)


def test_wrong_trust_pins_reject_before_operation(tmp_path):
    executor, _, ledger, state, verifier, _ = setup(tmp_path)
    with pytest.raises(ExecutionError, match="TRUST_PIN_MISMATCH"):
        UpstreamExecutor(plan=executor.plan, ledger=ledger, verifiers=executor.verifiers,
                         trusted_pins=TrustPins(digest("other"), PINS.verifier_code_digest), clock=lambda: NOW)
    assert state["writes"] == 0 and verifier.stages == []


@pytest.mark.parametrize("phase", PHASE_NAMES)
def test_production_account_cannot_enter_authority_plan(tmp_path, phase):
    executor, _, _, state, _, _ = setup(tmp_path)
    values = executor.plan.binding()
    for key in ("plan_digest", "run_digest", "operations", "region", "environment"):
        values.pop(key)
    values["evidence_mode"] = "AWS_TRANSPORT"
    values["phase_accounts"][phase] = "905418363887"
    with pytest.raises(PlanError, match="AUTHORITY_ACCOUNT_SCOPE_INVALID"):
        RunPlan(**values)
    assert state["writes"] == 0


def test_target_and_readback_cannot_diverge(tmp_path):
    _, args, _, _, _, _ = setup(tmp_path)
    operation = args["operation"]
    with pytest.raises(PlanError, match="TARGET_READBACK_CONTRACT_MISMATCH"):
        LiveOperation(operation_id=operation.operation_id, account_id=operation.account_id,
            region=operation.region, request=operation.request,
            before_state_digest=operation.before_state_digest, target_state_digest=digest("wrong-target"),
            predecessor_slots_digest=operation.predecessor_slots_digest,
            before_readbacks=operation.before_readbacks, readbacks=operation.readbacks)


def test_copied_ledger_root_cannot_reuse_approved_custody(tmp_path):
    executor, _, ledger, state, _, _ = setup(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    copied = DurableMutationLedger(other, run_digest=ledger.run_digest,
                                   plan_digest=ledger.plan_digest, operations=ledger.operations)
    copied.create()
    with pytest.raises(ExecutionError, match="LEDGER_CUSTODY_MISMATCH"):
        UpstreamExecutor(plan=executor.plan, ledger=copied, verifiers=executor.verifiers,
                         trusted_pins=PINS, clock=lambda: NOW)
    assert state["writes"] == 0


@pytest.mark.parametrize("anchor_call,no_touch,status", [
    (2, False, "IN_FLIGHT"), (3, False, "SUCCEEDED"),
    (2, True, "EXACT_PRESENT_NO_TOUCH"),
])
def test_recover_crash_gap_advances_only_external_anchor(tmp_path, anchor_call, no_touch, status):
    executor, args, ledger, state, verifier, _ = setup(tmp_path)
    def crash(stage):
        if stage == "LEDGER_ANCHOR" and verifier.stages.count(stage) == anchor_call:
            raise OSError("simulated external store outage")
    verifier.callback = crash
    with pytest.raises(ExecutionError, match="EXTERNAL_VERIFICATION_FAILED"):
        executor.execute_one(**args, exact_present=no_touch)
    before = ledger.snapshot()
    assert before["operations"][0]["status"] == status
    last_external = verifier.anchor
    calls_before = list(state["calls"])
    verifier.callback = None
    result = executor.recover_anchor(expected_snapshot_digest=before["snapshot_digest"],
        previous_anchor_digest=last_external, evidence=None, mode="SYNTHETIC")
    assert result["provider_calls"] == 0 and result["local_transitions"] == 0
    assert ledger.snapshot() == before and state["calls"] == calls_before
    assert verifier.anchor == before["snapshot_digest"]
    with pytest.raises(ExecutionError, match="EXTERNAL_VERIFICATION_FAILED"):
        executor.recover_anchor(expected_snapshot_digest=before["snapshot_digest"],
            previous_anchor_digest=digest("invented-anchor"), evidence=None, mode="SYNTHETIC")


def test_reconciliation_after_timeout_never_mutates_or_releases_successor(tmp_path):
    executor, args, ledger, state, verifier, now = setup(tmp_path)
    state["timeout"] = True
    result = executor.execute_one(**args)
    assert result.status == "AMBIGUOUS"
    state["timeout"] = False
    clients = {service: Client(state, service) for service in ("sts", "sso-admin")}
    fresh = UpstreamLiveProvider.from_injected_clients(clients=clients,
        expected_account_id=ACCOUNT, expected_caller_arn=CALLER, region="us-east-1")
    recovery = executor.reconcile_one(operation=args["operation"], provider=fresh,
        expected_snapshot_digest=result.snapshot_digest, reconciliation_evidence=None, anchor_evidence=None)
    assert recovery.status == "RECONCILED" and state["writes"] == 0
    snapshot = ledger.snapshot()
    with pytest.raises(LedgerError, match="PREDECESSOR_NOT_RESOLVED"):
        ledger.claim(executor.plan.operations[1][0], request_digest=digest("next-resolved-request"),
                     authorization_digest=digest("next-auth"), observed_at=now[0],
                     expected_snapshot_digest=snapshot["snapshot_digest"])
