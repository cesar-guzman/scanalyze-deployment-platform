"""Single-operation upstream executor; no default trust or CLI activation.

All external verifiers are mandatory, independently pinned trusted code. A
digest is never an authentication mechanism. One invocation is one session and
one resolved request batch. This lane does not authorize downstream production.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
import json
from typing import Any, Callable, Mapping, Protocol

from tooling.platform_authority_gug376_upstream_live_ledger import DurableMutationLedger
from tooling.platform_authority_gug376_upstream_live_plan import (
    LiveOperation, RunPlan, canonical_json, digest, require_digest,
)
from tooling.platform_authority_gug376_upstream_live_provider import UpstreamLiveProvider


class ExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _stop(code: str) -> None:
    raise ExecutionError(code) from None


def _time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        _stop("UTC_TIME_REQUIRED")
    return value.astimezone(timezone.utc)


def _close_transport(method):
    @wraps(method)
    def invoke(self, **kwargs):
        provider = kwargs.get("provider")
        try:
            return method(self, **kwargs)
        finally:
            if type(provider) is UpstreamLiveProvider:
                provider.close()
    return invoke


@dataclass(frozen=True)
class TrustPins:
    """Supplied independently of the plan, checkpoint, and receipt channels."""

    trust_anchor_digest: str
    verifier_code_digest: str

    def __post_init__(self) -> None:
        require_digest(self.trust_anchor_digest)
        require_digest(self.verifier_code_digest)


@dataclass(frozen=True)
class VerifiedReceipt:
    stage: str
    binding_digest: str
    receipt_digest: str
    trust_anchor_digest: str
    verifier_code_digest: str
    mode: str


class ExternalVerifier(Protocol):
    """Trusted integration must authenticate evidence, not echo these fields.

    LEDGER_ANCHOR verification additionally persists a monotonic external CAS
    anchor and rejects rollback/reuse across processes, roots and sessions.
    Returning a bool or reading approval flags from the bundle is invalid.
    """

    def identity(self) -> TrustPins: ...
    def verify(self, *, stage: str, expected: Mapping[str, Any],
               evidence: Any, now: datetime) -> VerifiedReceipt: ...


@dataclass(frozen=True)
class Verifiers:
    owner: ExternalVerifier
    provider: ExternalVerifier
    ledger_anchor: ExternalVerifier
    final: ExternalVerifier


@dataclass(frozen=True, init=False)
class Checkpoint:
    """Private session/authority inputs; the owner verifier authenticates them."""

    issued_at: datetime
    expires_at: datetime
    session_expires_at: datetime
    _json: str = field(repr=False)

    def __init__(self, *, issued_at: datetime, expires_at: datetime,
                 session_expires_at: datetime, session_digest: str,
                 caller_arn_digest: str, source_verification_digest: str,
                 policy_digest: str, maximum_permissions_digest: str,
                 effective_authority_digest: str,
                 expected_snapshot_digest: str) -> None:
        issued, expires, session_end = map(_time, (issued_at, expires_at, session_expires_at))
        if not issued < expires <= min(issued + timedelta(minutes=15), session_end):
            _stop("AUTHORIZATION_WINDOW_INVALID")
        if policy_digest != maximum_permissions_digest:
            _stop("PHASE_PERMISSION_CAP_MISMATCH")
        values = dict(session_digest=session_digest, caller_arn_digest=caller_arn_digest,
                      source_verification_digest=source_verification_digest,
                      policy_digest=policy_digest, maximum_permissions_digest=maximum_permissions_digest,
                      effective_authority_digest=effective_authority_digest,
                      expected_snapshot_digest=expected_snapshot_digest)
        for value in values.values():
            require_digest(value)
        values.update(issued_at=issued.isoformat(), expires_at=expires.isoformat(),
                      session_expires_at=session_end.isoformat(), automatic_rollback=False,
                      role_chaining=False, additive_grants=[], batch_size=1)
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "session_expires_at", session_end)
        object.__setattr__(self, "_json", canonical_json(values))

    def binding(self) -> dict[str, Any]:
        return json.loads(self._json)

    def check_time(self, now: datetime) -> None:
        if not self.issued_at <= _time(now) < self.expires_at:
            _stop("AUTHORIZATION_NOT_CURRENT")


@dataclass(frozen=True)
class ExecutionResult:
    operation_id: str
    status: str
    snapshot_digest: str
    mode: str
    provider_receipt_digest: str | None
    next_owner_checkpoint_required: bool = True
    production_authorized: bool = False


class UpstreamExecutor:
    def __init__(self, *, plan: RunPlan, ledger: DurableMutationLedger,
                 verifiers: Verifiers, trusted_pins: TrustPins,
                 clock: Callable[[], datetime]) -> None:
        if type(plan) is not RunPlan or type(ledger) is not DurableMutationLedger:
            _stop("EXECUTOR_INPUT_TYPE_INVALID")
        if type(verifiers) is not Verifiers or type(trusted_pins) is not TrustPins:
            _stop("EXTERNAL_VERIFIERS_REQUIRED")
        binding = plan.binding()
        if any(binding[name] != getattr(trusted_pins, name)
               for name in ("trust_anchor_digest", "verifier_code_digest")):
            _stop("TRUST_PIN_MISMATCH")
        if (ledger.run_digest, ledger.plan_digest, ledger.operations) != (
                plan.run_digest, plan.plan_digest, plan.operations):
            _stop("LEDGER_PLAN_MISMATCH")
        if ledger.custody_digest() != binding["custody_digest"]:
            _stop("LEDGER_CUSTODY_MISMATCH")
        self.plan, self.ledger = plan, ledger
        self.verifiers, self.pins, self.clock = verifiers, trusted_pins, clock
        self._last_time: datetime | None = None
        self._invoked = False
        for adapter in (verifiers.owner, verifiers.provider, verifiers.ledger_anchor, verifiers.final):
            self._identity(adapter)

    def _identity(self, adapter: ExternalVerifier) -> None:
        try:
            identity = adapter.identity()
        except Exception:
            _stop("VERIFIER_IDENTITY_UNAVAILABLE")
        if type(identity) is not TrustPins or identity != self.pins:
            _stop("VERIFIER_IDENTITY_MISMATCH")

    def _now(self) -> datetime:
        now = _time(self.clock())
        if self._last_time is not None and now < self._last_time:
            _stop("TIME_ROLLBACK")
        self._last_time = now
        return now

    def _verify(self, adapter: ExternalVerifier, stage: str,
                expected: dict[str, Any], evidence: Any, mode: str) -> VerifiedReceipt:
        self._identity(adapter)
        # The verifier gets a detached copy; it cannot alter the expected binding.
        wanted = digest(expected)
        try:
            receipt = adapter.verify(stage=stage, expected=json.loads(canonical_json(expected)),
                                     evidence=evidence, now=self._now())
        except Exception:
            _stop("EXTERNAL_VERIFICATION_FAILED")
        if type(receipt) is not VerifiedReceipt or (
                receipt.stage, receipt.binding_digest, receipt.trust_anchor_digest,
                receipt.verifier_code_digest, receipt.mode) != (
                    stage, wanted, self.pins.trust_anchor_digest, self.pins.verifier_code_digest, mode):
            _stop("EXTERNAL_RECEIPT_INVALID")
        require_digest(receipt.receipt_digest)
        return receipt

    def _anchor(self, snapshot: dict[str, Any], *, previous: str,
                evidence: Any, mode: str) -> None:
        if self.ledger.custody_digest() != self.plan.binding()["custody_digest"]:
            _stop("LEDGER_CUSTODY_MISMATCH")
        self._verify(self.verifiers.ledger_anchor, "LEDGER_ANCHOR", {
            "run_digest": self.plan.run_digest, "plan_digest": self.plan.plan_digest,
            "custody_digest": self.plan.binding()["custody_digest"],
            "previous_snapshot_digest": previous,
            "snapshot_digest": snapshot["snapshot_digest"],
            "version": snapshot["version"],
        }, {"snapshot": snapshot, "external": evidence}, mode)

    @_close_transport
    def execute_one(self, *, operation: LiveOperation, checkpoint: Checkpoint,
                    provider: UpstreamLiveProvider, owner_evidence: Any,
                    preflight_evidence: Any, anchor_evidence: Any,
                    operation_evidence: Any = None,
                    exact_present: bool = False, max_polls: int = 6,
                    poll_interval_seconds: float = 1.0,
                    wait: Callable[[float], None] | None = None) -> ExecutionResult:
        if self._invoked:
            _stop("FRESH_EXECUTOR_SESSION_REQUIRED")
        self._invoked = True
        if type(provider) is not UpstreamLiveProvider or type(checkpoint) is not Checkpoint:
            _stop("EXECUTION_COMPONENT_TYPE_INVALID")
        if type(exact_present) is not bool or type(max_polls) is not int or not 0 <= max_polls <= 12:
            _stop("POLL_BOUND_INVALID")
        if not 1 <= poll_interval_seconds <= 30:
            _stop("POLL_BOUND_INVALID")
        self.plan.validate_operation(operation)
        provider.validate_operation(operation)
        checkpoint.check_time(self._now())
        identity = provider.identity()
        mode = identity["mode"]
        if mode != self.plan.binding()["evidence_mode"] or (
                identity["account_id"], identity["region"], identity["caller_arn_digest"]) != (
                    operation.account_id, operation.region, checkpoint.binding()["caller_arn_digest"]):
            _stop("PROVIDER_SCOPE_MISMATCH")
        before = self.ledger.snapshot(expected_snapshot_digest=checkpoint.binding()["expected_snapshot_digest"])
        self._anchor(before, previous=before["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        authorization = {"run": self.plan.binding(), "operation": operation.binding(),
                         "checkpoint": checkpoint.binding(), "identity": identity,
                         "exact_present_no_touch": exact_present}
        auth_digest = digest(authorization)

        def authorize() -> None:
            checkpoint.check_time(self._now())
            self._verify(self.verifiers.owner, "OWNER_AUTHORIZATION", authorization, owner_evidence, mode)
            # Verification itself can consume the remaining authorization window.
            checkpoint.check_time(self._now())

        authorize()
        self._verify(self.verifiers.provider, "PREFLIGHT", {
            "authorization_digest": auth_digest, "identity": identity,
            "source_verification_digest": checkpoint.binding()["source_verification_digest"],
            "effective_authority_digest": checkpoint.binding()["effective_authority_digest"],
            "first_signed_call": "sts:GetCallerIdentity", "direct_sso": True,
            "fresh_phase_session": True, "additive_grants": [],
        }, preflight_evidence, mode)
        observation = provider.observe(operation)
        if observation.status != "OBSERVED" or observation.mode != mode or observation.readback_digest != operation.before_state_digest:
            _stop("BEFORE_STATE_DRIFT")
        self._verify(self.verifiers.provider, "BEFORE_STATE", {
            "authorization_digest": auth_digest, "observation": asdict(observation),
            "predecessor_slots_digest": operation.predecessor_slots_digest,
        }, {"provider": provider.private_evidence(operation.operation_id), "external": preflight_evidence}, mode)
        authorize()
        if exact_present:
            receipt = self._verify(self.verifiers.provider, "EXACT_PRESENT_NO_TOUCH", {
                "authorization_digest": auth_digest, "operation": operation.binding(),
                "observation": asdict(observation), "write_count": 0,
                "required_target_digest": operation.target_state_digest,
            }, {"provider": provider.private_evidence(operation.operation_id), "external": operation_evidence}, mode)
            checkpoint.check_time(self._now())
            after = self.ledger.record_noop(operation.operation_id, request_digest=operation.request_digest,
                authorization_digest=auth_digest, receipt_digest=receipt.receipt_digest,
                observed_at=self._now(), expected_snapshot_digest=before["snapshot_digest"])
            self._anchor(after, previous=before["snapshot_digest"], evidence=anchor_evidence, mode=mode)
            return ExecutionResult(operation.operation_id, "EXACT_PRESENT_NO_TOUCH", after["snapshot_digest"], mode, receipt.receipt_digest)
        claim = self.ledger.claim(operation.operation_id, request_digest=operation.request_digest,
            authorization_digest=auth_digest, observed_at=self._now(),
            expected_snapshot_digest=before["snapshot_digest"])
        # A failure from here consumes the attempt. Never redispatch on recovery.
        self._anchor(claim, previous=before["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        receipt = None
        status = "AMBIGUOUS"
        try:
            result = provider.dispatch_once(operation, before_mutation=authorize)
            polls = 0
            while result.status == "PENDING" and polls < max_polls:
                checkpoint.check_time(self._now())
                if wait is None:
                    break
                wait(poll_interval_seconds)
                checkpoint.check_time(self._now())
                result = provider.poll_readbacks(operation)
                polls += 1
            if (result.operation_id, result.request_digest, result.mode) != (
                    operation.operation_id, operation.request_digest, mode):
                _stop("PROVIDER_RESULT_BINDING_MISMATCH")
            if result.status in {"SUCCEEDED", "FAILED"}:
                receipt = self._verify(self.verifiers.provider, "OPERATION", {
                    "authorization_digest": auth_digest, "claim_snapshot_digest": claim["snapshot_digest"],
                    "operation": operation.binding(), "outcome": asdict(result),
                }, {"provider": provider.private_evidence(operation.operation_id), "external": operation_evidence}, mode)
                status = result.status
        except Exception:
            # Exception text may contain requests, provider payloads or credentials.
            status, receipt = "AMBIGUOUS", None
        finish = self.ledger.finish(operation.operation_id, outcome=status,
            receipt_digest=receipt.receipt_digest if receipt else None,
            observed_at=self._now(), expected_snapshot_digest=claim["snapshot_digest"])
        self._anchor(finish, previous=claim["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        return ExecutionResult(operation.operation_id, status, finish["snapshot_digest"], mode,
                               receipt.receipt_digest if receipt else None)

    @_close_transport
    def reconcile_one(self, *, operation: LiveOperation, provider: UpstreamLiveProvider,
                      expected_snapshot_digest: str, reconciliation_evidence: Any,
                      anchor_evidence: Any) -> ExecutionResult:
        """Read-only recovery; even a verified effect does not release successors."""
        self.plan.validate_operation(operation)
        if type(provider) is not UpstreamLiveProvider:
            _stop("EXECUTION_COMPONENT_TYPE_INVALID")
        snapshot = self.ledger.snapshot(expected_snapshot_digest=expected_snapshot_digest)
        entry = next(item for item in snapshot["operations"] if item["operation_id"] == operation.operation_id)
        if entry["status"] not in {"IN_FLIGHT", "AMBIGUOUS"} or entry["request_digest"] != operation.request_digest:
            _stop("OPERATION_NOT_RECONCILABLE")
        identity = provider.identity()
        if identity["account_id"] != operation.account_id or identity["region"] != operation.region:
            _stop("PROVIDER_SCOPE_MISMATCH")
        mode = identity["mode"]
        if mode != self.plan.binding()["evidence_mode"]:
            _stop("EVIDENCE_MODE_MISMATCH")
        self._anchor(snapshot, previous=snapshot["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        # Freshly supplied, fully resolved before-readbacks are the reconciliation
        # observation; no original SDK response is fabricated after a restart.
        observation = provider.observe(operation)
        receipt = self._verify(self.verifiers.provider, "RECONCILIATION", {
            "plan_digest": self.plan.plan_digest, "snapshot_digest": snapshot["snapshot_digest"],
            "operation": operation.binding(), "observation": asdict(observation),
            "write_count": 0, "successors_released": False,
        }, {"provider": provider.private_evidence(operation.operation_id), "external": reconciliation_evidence}, mode)
        after = self.ledger.reconcile(operation.operation_id, receipt_digest=receipt.receipt_digest,
            observed_at=self._now(), expected_snapshot_digest=snapshot["snapshot_digest"])
        self._anchor(after, previous=snapshot["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        return ExecutionResult(operation.operation_id, "RECONCILED", after["snapshot_digest"], mode, receipt.receipt_digest)

    def recover_anchor(self, *, expected_snapshot_digest: str,
                       previous_anchor_digest: str, evidence: Any, mode: str) -> dict[str, Any]:
        """Repair a crash gap only through externally authenticated history CAS.

        The complete digest-only history is provided to the anchor verifier.
        It must prove an extension of the last externally held head; accepting
        a caller-selected replacement would destroy the no-replay guarantee.
        No local transition, retry, session or provider call occurs here.
        """
        require_digest(previous_anchor_digest)
        if mode != self.plan.binding()["evidence_mode"]:
            _stop("EVIDENCE_MODE_MISMATCH")
        snapshot = self.ledger.snapshot(expected_snapshot_digest=expected_snapshot_digest)
        self._anchor(snapshot, previous=previous_anchor_digest, evidence=evidence, mode=mode)
        return {"run_digest": self.plan.run_digest, "snapshot_digest": snapshot["snapshot_digest"],
                "anchor_recovered": True, "local_transitions": 0,
                "provider_calls": 0, "production_authorized": False}

    def finalize(self, *, expected_snapshot_digest: str, final_evidence: Any,
                 anchor_evidence: Any, mode: str) -> dict[str, Any]:
        if mode not in {"SYNTHETIC", "AWS_TRANSPORT"}:
            _stop("EVIDENCE_MODE_INVALID")
        if mode != self.plan.binding()["evidence_mode"]:
            _stop("EVIDENCE_MODE_MISMATCH")
        snapshot = self.ledger.snapshot(expected_snapshot_digest=expected_snapshot_digest)
        if any(item["status"] not in {"SUCCEEDED", "EXACT_PRESENT_NO_TOUCH"} for item in snapshot["operations"]):
            _stop("UPSTREAM_RUN_INCOMPLETE")
        self._anchor(snapshot, previous=snapshot["snapshot_digest"], evidence=anchor_evidence, mode=mode)
        receipt = self._verify(self.verifiers.final, "FINAL_NEGATIVE_EVIDENCE", {
            "run": self.plan.binding(), "snapshot_digest": snapshot["snapshot_digest"],
            "unexpected_resources": [], "additive_grants": [], "unexpected_publishers": [],
            "all_provider_slots_causally_verified": True, "all_phase_sessions_closed": True,
            "production_authorized": False,
        }, final_evidence, mode)
        return {"run_digest": self.plan.run_digest, "snapshot_digest": snapshot["snapshot_digest"],
                "final_receipt_digest": receipt.receipt_digest, "mode": mode,
                "upstream_run_verified": True, "production_authorized": False}
