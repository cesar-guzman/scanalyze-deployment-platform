"""One-attempt/CAS runner for the GUG-377 scripted repository materializer.

This runner is deliberately not the GUG-376 live runner.  It accepts only the
checked-in scripted adapter, keeps its ledger in memory, and emits digest-only
records.  The state machine nevertheless models the exact causal guard a
future separately reviewed private orchestrator must enforce: claim before
effect, one attempt, bounded polling, and read-only reconciliation after any
uncertain outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping, Sequence

from tooling.platform_authority_gug365_phase_execution_ledger import CasTransition
from tooling.platform_authority_gug365_upstream_prerequisites import canonical_digest
from tooling.platform_authority_gug365_upstream_provider_contracts import (
    InertProviderAdapter,
    ProviderAdapter,
    ProviderContractError,
    ProviderStatus,
    ReconciliationStatus,
    STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED,
    ScriptedProviderAdapter,
    bind_consumed_slot_projections,
    consumed_slot_binding_digest,
    operation_from_record,
    provider_result_projection_digest,
    provider_slot_projections,
)


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fail(code: str) -> None:
    raise ProviderContractError(code)


def _snapshot(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
    except (TypeError, ValueError) as exc:
        raise ProviderContractError("RUNNER_VALUE_NOT_CANONICAL") from exc


def _status(value: Any) -> str:
    if isinstance(value, ProviderStatus):
        return value.value
    if isinstance(value, str):
        return value
    _fail("PROVIDER_STATUS_INVALID")


def _require_scripted_adapter(adapter: ProviderAdapter) -> None:
    if type(adapter) is InertProviderAdapter:
        _fail(STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED)
    if type(adapter) is not ScriptedProviderAdapter:
        _fail("ADAPTER_NOT_ALLOWLISTED")


@dataclass(frozen=True, slots=True)
class RunnerResult:
    status: str
    before_state_projections: dict[str, dict[str, str]]
    provider_slot_projections: dict[str, str]
    operation_results: tuple[dict[str, Any], ...]
    ledger: dict[str, Any]


class AttemptLedger:
    """In-memory CAS ledger using the repository's existing transition type."""

    def __init__(self, record: Mapping[str, Any]) -> None:
        self._record = _snapshot(record)
        self._validate()

    @classmethod
    def from_plan(cls, plan: Mapping[str, Any]) -> "AttemptLedger":
        operations = plan.get("operations")
        if not isinstance(operations, Sequence) or isinstance(operations, (str, bytes)):
            _fail("LEDGER_PLAN_OPERATIONS_INVALID")
        records: list[dict[str, Any]] = []
        for item in operations:
            if not isinstance(item, Mapping):
                _fail("LEDGER_PLAN_OPERATION_INVALID")
            records.append(
                {
                    "operation_id": item.get("operation_id"),
                    "operation_digest": item.get("operation_digest"),
                    "request_digest": item.get("request_contract_digest"),
                    "dependencies": list(item.get("dependencies", [])),
                    "status": "READY",
                    "attempt_count": 0,
                    "retry_permitted": False,
                    "consumed_slot_binding_digest": None,
                    "operation_result_digest": None,
                }
            )
        base: dict[str, Any] = {
            "record_type": "scanalyze.platform_authority.gug365_upstream_repository_attempt_ledger.v1",
            "schema_version": 1,
            "plan_digest": plan.get("plan_digest"),
            "ledger_version": 1,
            "previous_ledger_digest": None,
            "operations": records,
        }
        base["ledger_digest"] = canonical_digest(base)
        return cls(base)

    def snapshot(self) -> dict[str, Any]:
        return _snapshot(self._record)

    def operation(self, operation_id: str) -> dict[str, Any]:
        for item in self._record["operations"]:
            if item["operation_id"] == operation_id:
                return _snapshot(item)
        _fail("LEDGER_OPERATION_UNKNOWN")

    def _index(self, operation_id: str) -> int:
        for index, item in enumerate(self._record["operations"]):
            if item["operation_id"] == operation_id:
                return index
        _fail("LEDGER_OPERATION_UNKNOWN")

    def _validate(self) -> None:
        record = self._record
        if (
            set(record)
            != {
                "record_type",
                "schema_version",
                "plan_digest",
                "ledger_version",
                "previous_ledger_digest",
                "operations",
                "ledger_digest",
            }
            or record.get("record_type")
            != "scanalyze.platform_authority.gug365_upstream_repository_attempt_ledger.v1"
            or record.get("schema_version") != 1
            or not isinstance(record.get("ledger_version"), int)
            or isinstance(record.get("ledger_version"), bool)
            or record["ledger_version"] < 1
            or not isinstance(record.get("operations"), list)
            or not _DIGEST.fullmatch(str(record.get("plan_digest")))
        ):
            _fail("LEDGER_INVALID")
        previous = record.get("previous_ledger_digest")
        if previous is not None and not _DIGEST.fullmatch(str(previous)):
            _fail("LEDGER_PREVIOUS_DIGEST_INVALID")
        seen: set[str] = set()
        allowed = {
            "READY",
            "CLAIMED",
            "PENDING_POLL",
            "SUCCEEDED",
            "FAILED_TERMINAL",
            "UNCERTAIN_RECONCILE_ONLY",
            "RECONCILED_EFFECT_PROVEN",
            "RECONCILED_NO_EFFECT_PROVEN",
            "RECONCILED_INCONCLUSIVE",
        }
        for item in record["operations"]:
            if (
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "operation_id",
                    "operation_digest",
                    "request_digest",
                    "dependencies",
                    "status",
                    "attempt_count",
                    "retry_permitted",
                    "consumed_slot_binding_digest",
                    "operation_result_digest",
                }
                or not isinstance(item.get("operation_id"), str)
                or item["operation_id"] in seen
                or not _DIGEST.fullmatch(str(item.get("operation_digest")))
                or not _DIGEST.fullmatch(str(item.get("request_digest")))
                or not isinstance(item.get("dependencies"), list)
                or item.get("status") not in allowed
                or item.get("attempt_count") not in {0, 1}
                or item.get("retry_permitted") is not False
            ):
                _fail("LEDGER_OPERATION_INVALID")
            if item["attempt_count"] == 0 and item["status"] != "READY":
                _fail("LEDGER_ATTEMPT_STATE_INVALID")
            if item["attempt_count"] == 1 and item["status"] == "READY":
                _fail("LEDGER_ATTEMPT_STATE_INVALID")
            result_digest = item.get("operation_result_digest")
            if result_digest is not None and not _DIGEST.fullmatch(str(result_digest)):
                _fail("LEDGER_RESULT_DIGEST_INVALID")
            slot_binding_digest = item.get("consumed_slot_binding_digest")
            if item["attempt_count"] == 0 and slot_binding_digest is not None:
                _fail("LEDGER_SLOT_BINDING_WITHOUT_CLAIM")
            if item["attempt_count"] == 1 and not _DIGEST.fullmatch(
                str(slot_binding_digest)
            ):
                _fail("LEDGER_SLOT_BINDING_DIGEST_INVALID")
            seen.add(item["operation_id"])
        expected = canonical_digest(
            {key: value for key, value in record.items() if key != "ledger_digest"}
        )
        if record.get("ledger_digest") != expected:
            _fail("LEDGER_DIGEST_MISMATCH")

    def _commit(self, proposed: dict[str, Any], *, expected_digest: str) -> None:
        transition = CasTransition(
            expected_version=self._record["ledger_version"],
            expected_digest=expected_digest,
            proposed_record=proposed,
            attempt_limit=1,
            retry_permitted=False,
        )
        if (
            transition.expected_version != self._record["ledger_version"]
            or transition.expected_digest != self._record["ledger_digest"]
            or transition.attempt_limit != 1
            or transition.retry_permitted is not False
        ):
            _fail("LEDGER_CAS_MISMATCH")
        next_record = _snapshot(transition.proposed_record)
        next_record["previous_ledger_digest"] = transition.expected_digest
        next_record["ledger_version"] = transition.expected_version + 1
        next_record["ledger_digest"] = canonical_digest(
            {key: value for key, value in next_record.items() if key != "ledger_digest"}
        )
        old = self._record
        self._record = next_record
        try:
            self._validate()
        except BaseException:
            self._record = old
            raise

    def claim_once(
        self,
        operation_record: Mapping[str, Any],
        *,
        consumed_slot_projection_digest: str,
    ) -> None:
        operation_id = str(operation_record.get("operation_id"))
        index = self._index(operation_id)
        current = self._record["operations"][index]
        if current["status"] == "UNCERTAIN_RECONCILE_ONLY":
            _fail("UNCERTAIN_RECONCILE_ONLY")
        if current["attempt_count"] != 0 or current["status"] != "READY":
            _fail("OPERATION_ATTEMPT_ALREADY_CONSUMED")
        if (
            current["operation_digest"] != operation_record.get("operation_digest")
            or current["request_digest"] != operation_record.get("request_contract_digest")
        ):
            _fail("LEDGER_OPERATION_BINDING_MISMATCH")
        for dependency in current["dependencies"]:
            predecessor = self.operation(dependency)
            if predecessor["status"] != "SUCCEEDED":
                _fail("LEDGER_DEPENDENCY_NOT_TERMINAL")
        if not _DIGEST.fullmatch(str(consumed_slot_projection_digest)):
            _fail("LEDGER_SLOT_BINDING_DIGEST_INVALID")
        proposed = self.snapshot()
        proposed["operations"][index]["attempt_count"] = 1
        proposed["operations"][index]["status"] = "CLAIMED"
        proposed["operations"][index]["consumed_slot_binding_digest"] = (
            consumed_slot_projection_digest
        )
        self._commit(proposed, expected_digest=self._record["ledger_digest"])

    def transition(
        self,
        operation_id: str,
        *,
        status: str,
        operation_result_digest: str | None,
    ) -> None:
        index = self._index(operation_id)
        current = self._record["operations"][index]
        if current["attempt_count"] != 1:
            _fail("LEDGER_TRANSITION_WITHOUT_CLAIM")
        allowed_from: dict[str, set[str]] = {
            "CLAIMED": {
                "PENDING_POLL",
                "SUCCEEDED",
                "FAILED_TERMINAL",
                "UNCERTAIN_RECONCILE_ONLY",
            },
            "PENDING_POLL": {
                "PENDING_POLL",
                "SUCCEEDED",
                "FAILED_TERMINAL",
                "UNCERTAIN_RECONCILE_ONLY",
            },
            "UNCERTAIN_RECONCILE_ONLY": {
                "RECONCILED_EFFECT_PROVEN",
                "RECONCILED_NO_EFFECT_PROVEN",
                "RECONCILED_INCONCLUSIVE",
            },
        }
        if status not in allowed_from.get(current["status"], set()):
            _fail("LEDGER_STATE_TRANSITION_INVALID")
        if operation_result_digest is not None and not _DIGEST.fullmatch(
            operation_result_digest
        ):
            _fail("LEDGER_RESULT_DIGEST_INVALID")
        proposed = self.snapshot()
        proposed["operations"][index]["status"] = status
        proposed["operations"][index]["operation_result_digest"] = (
            operation_result_digest
        )
        self._commit(proposed, expected_digest=self._record["ledger_digest"])


def _result_record(operation: Any, result: Any, status: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_operation_receipt.v2",
        "schema_version": 2,
        "implementation_issue": "GUG-377",
        "operation_id": operation.operation_id,
        "operation_kind": operation.operation_kind.value,
        "request_digest": operation.request_digest,
        "before_state_digest": operation.before_state_digest,
        "target_state_digest": operation.target_state_digest,
        "provider_result_projection_digest": result.result_projection_digest,
        "readback_projection_digest": result.readback_projection_digest,
        "consumed_slot_binding_digest": result.consumed_slot_binding_digest,
        "produced_slot_projection_digests": [
            {
                "slot": projection.slot,
                "value_projection_digest": projection.value_projection_digest,
                "projection_digest": projection.projection_digest,
            }
            for projection in result.produced_slot_projections
        ],
        "status": status,
        "attempt_count": 1,
        "write_retry_permitted": False,
        "provider_evidence_origin": "SCRIPTED_SYNTHETIC",
        "provider_response_values_persisted": False,
    }
    record["operation_result_digest"] = canonical_digest(record)
    return record


def _validate_result_binding(
    operation: Any,
    result: Any,
    *,
    allowed_statuses: frozenset[ProviderStatus],
) -> None:
    if (
        result.operation_id != operation.operation_id
        or result.operation_kind != operation.operation_kind
        or result.request_digest != operation.request_digest
        or result.before_state_digest != operation.before_state_digest
        or result.target_state_digest != operation.target_state_digest
        or not isinstance(result.status, ProviderStatus)
        or result.status not in allowed_statuses
        or result.result_projection_digest
        != provider_result_projection_digest(operation, result.status)
        or result.readback_projection_digest
        != canonical_digest(
            {
                "operation_id": operation.operation_id,
                "target_state_digest": operation.target_state_digest,
            }
        )
        or result.consumed_slot_binding_digest
        != consumed_slot_binding_digest(operation)
        or result.produced_slot_projections
        != provider_slot_projections(
            operation, result.status, result.result_projection_digest
        )
    ):
        _fail("PROVIDER_RESULT_BINDING_MISMATCH")


def _observe_before_states(
    operations: Sequence[Mapping[str, Any]], adapter: ProviderAdapter
) -> dict[str, dict[str, str]]:
    projections: dict[str, dict[str, str]] = {}
    for record in operations:
        resource = str(record["inventory_resource"])
        if resource in projections:
            continue
        operation = operation_from_record(record)
        projection = adapter.observe_before_state(operation)
        expected_projection_digest = canonical_digest(
            {
                "operation_id": operation.operation_id,
                "operation_kind": operation.operation_kind.value,
                "resource_kind": operation.resource_kind,
                "classification": "SCRIPTED_SYNTHETIC",
                "request_digest": operation.request_digest,
                "before_state_digest": operation.before_state_digest,
                "target_state_digest": operation.target_state_digest,
            }
        )
        if (
            projection.operation_id != operation.operation_id
            or projection.operation_kind != operation.operation_kind
            or projection.resource_kind != resource
            or projection.request_digest != operation.request_digest
            or projection.before_state_digest != operation.before_state_digest
            or projection.target_state_digest != operation.target_state_digest
            or projection.classification != "SCRIPTED_SYNTHETIC"
            or projection.projection_digest != expected_projection_digest
        ):
            _fail("PROVIDER_BEFORE_STATE_BINDING_MISMATCH")
        projections[resource] = {
            "before_state_digest": projection.before_state_digest,
            "target_state_digest": projection.target_state_digest,
            "projection_digest": projection.projection_digest,
        }
    return projections


def _record_slot_projections(
    result: Any, slot_projections: dict[str, str]
) -> None:
    for projection in result.produced_slot_projections:
        if projection.slot in slot_projections:
            _fail("PROVIDER_SLOT_REPLAY_FORBIDDEN")
        slot_projections[projection.slot] = projection.projection_digest


def _poll_bounded(
    *,
    operation: Any,
    policy: Mapping[str, Any],
    adapter: ProviderAdapter,
    ledger: AttemptLedger,
    now: Callable[[], float],
    sleep: Callable[[float], None],
    operation_results: list[dict[str, Any]],
    slot_projections: dict[str, str],
) -> str:
    maximum = policy.get("max_attempts")
    elapsed_limit = policy.get("max_elapsed_seconds")
    backoff = policy.get("backoff_seconds")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum < 1
        or not isinstance(elapsed_limit, int)
        or isinstance(elapsed_limit, bool)
        or elapsed_limit < 1
        or not isinstance(backoff, list)
        or len(backoff) != maximum - 1
        or any(
            not isinstance(delay, int) or isinstance(delay, bool) or delay < 0
            for delay in backoff
        )
    ):
        _fail("POLLING_POLICY_INVALID")
    started = now()
    for attempt in range(maximum):
        try:
            result = adapter.poll(operation)
            _validate_result_binding(
                operation,
                result,
                allowed_statuses=frozenset(ProviderStatus),
            )
        except ProviderContractError:
            ledger.transition(
                operation.operation_id,
                status="UNCERTAIN_RECONCILE_ONLY",
                operation_result_digest=None,
            )
            return "UNCERTAIN_RECONCILE_ONLY"
        elapsed_after_poll = now() - started
        if elapsed_after_poll < 0 or elapsed_after_poll > elapsed_limit:
            ledger.transition(
                operation.operation_id,
                status="UNCERTAIN_RECONCILE_ONLY",
                operation_result_digest=None,
            )
            return "UNCERTAIN_RECONCILE_ONLY"
        state = _status(result.status)
        if state == ProviderStatus.SUCCEEDED.value:
            record = _result_record(operation, result, "SUCCEEDED")
            operation_results.append(record)
            _record_slot_projections(result, slot_projections)
            ledger.transition(
                operation.operation_id,
                status="SUCCEEDED",
                operation_result_digest=record["operation_result_digest"],
            )
            return "SUCCEEDED"
        if state == ProviderStatus.FAILED.value:
            record = _result_record(operation, result, "FAILED")
            operation_results.append(record)
            ledger.transition(
                operation.operation_id,
                status="FAILED_TERMINAL",
                operation_result_digest=record["operation_result_digest"],
            )
            return "FAILED_TERMINAL"
        if state != ProviderStatus.IN_PROGRESS.value:
            ledger.transition(
                operation.operation_id,
                status="UNCERTAIN_RECONCILE_ONLY",
                operation_result_digest=None,
            )
            return "UNCERTAIN_RECONCILE_ONLY"
        if attempt == maximum - 1:
            break
        delay = backoff[attempt]
        elapsed = now() - started
        if elapsed < 0 or elapsed + delay > elapsed_limit:
            break
        sleep(delay)
    ledger.transition(
        operation.operation_id,
        status="UNCERTAIN_RECONCILE_ONLY",
        operation_result_digest=None,
    )
    return "UNCERTAIN_RECONCILE_ONLY"


def run_repository_plan(
    *,
    plan: Mapping[str, Any],
    adapter: ProviderAdapter,
    ledger: AttemptLedger,
    now: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> RunnerResult:
    """Execute the scripted plan with a claim CAS before every fake write."""

    _require_scripted_adapter(adapter)
    from tooling.platform_authority_gug365_upstream_materializer import (
        validate_repository_plan,
    )

    validate_repository_plan(plan)
    clock = now or (lambda: 0.0)
    sleeper = sleep or (lambda _seconds: None)
    operations = plan.get("operations")
    if not isinstance(operations, list):
        _fail("RUNNER_PLAN_OPERATIONS_INVALID")
    if ledger.snapshot().get("plan_digest") != plan.get("plan_digest"):
        _fail("LEDGER_PLAN_DIGEST_MISMATCH")
    existing_states = {item["status"] for item in ledger.snapshot()["operations"]}
    if "UNCERTAIN_RECONCILE_ONLY" in existing_states or any(
        state.startswith("RECONCILED_") for state in existing_states
    ):
        _fail("UNCERTAIN_RECONCILE_ONLY")
    if any(state != "READY" for state in existing_states):
        _fail("OPERATION_ATTEMPT_ALREADY_CONSUMED")

    before_states = _observe_before_states(operations, adapter)
    operation_results: list[dict[str, Any]] = []
    slot_projections: dict[str, str] = {}
    for record in operations:
        operation = bind_consumed_slot_projections(
            operation_from_record(record), slot_projections
        )
        ledger.claim_once(
            record,
            consumed_slot_projection_digest=consumed_slot_binding_digest(operation),
        )
        try:
            result = adapter.mutate_once(operation)
        except ProviderContractError:
            ledger.transition(
                operation.operation_id,
                status="UNCERTAIN_RECONCILE_ONLY",
                operation_result_digest=None,
            )
            return RunnerResult(
                status="UNCERTAIN_RECONCILE_ONLY",
                before_state_projections=before_states,
                provider_slot_projections=dict(slot_projections),
                operation_results=tuple(operation_results),
                ledger=ledger.snapshot(),
            )
        try:
            _validate_result_binding(
                operation,
                result,
                allowed_statuses=frozenset(
                    {
                        ProviderStatus.SUCCEEDED
                        if operation.polling_kind == "NONE"
                        else ProviderStatus.IN_PROGRESS
                    }
                ),
            )
        except ProviderContractError:
            ledger.transition(
                operation.operation_id,
                status="UNCERTAIN_RECONCILE_ONLY",
                operation_result_digest=None,
            )
            raise
        state = _status(result.status)
        if state == ProviderStatus.SUCCEEDED.value:
            receipt = _result_record(operation, result, "SUCCEEDED")
            operation_results.append(receipt)
            _record_slot_projections(result, slot_projections)
            ledger.transition(
                operation.operation_id,
                status="SUCCEEDED",
                operation_result_digest=receipt["operation_result_digest"],
            )
            continue
        if state == ProviderStatus.FAILED.value:
            receipt = _result_record(operation, result, "FAILED")
            operation_results.append(receipt)
            ledger.transition(
                operation.operation_id,
                status="FAILED_TERMINAL",
                operation_result_digest=receipt["operation_result_digest"],
            )
            return RunnerResult(
                status="FAILED_TERMINAL",
                before_state_projections=before_states,
                provider_slot_projections=dict(slot_projections),
                operation_results=tuple(operation_results),
                ledger=ledger.snapshot(),
            )
        if state == ProviderStatus.IN_PROGRESS.value:
            ledger.transition(
                operation.operation_id,
                status="PENDING_POLL",
                operation_result_digest=None,
            )
            terminal = _poll_bounded(
                operation=operation,
                policy=record["polling_policy"],
                adapter=adapter,
                ledger=ledger,
                now=clock,
                sleep=sleeper,
                operation_results=operation_results,
                slot_projections=slot_projections,
            )
            if terminal != "SUCCEEDED":
                return RunnerResult(
                    status=terminal,
                    before_state_projections=before_states,
                    provider_slot_projections=dict(slot_projections),
                    operation_results=tuple(operation_results),
                    ledger=ledger.snapshot(),
                )
            continue
        ledger.transition(
            operation.operation_id,
            status="UNCERTAIN_RECONCILE_ONLY",
            operation_result_digest=None,
        )
        return RunnerResult(
            status="UNCERTAIN_RECONCILE_ONLY",
            before_state_projections=before_states,
            provider_slot_projections=dict(slot_projections),
            operation_results=tuple(operation_results),
            ledger=ledger.snapshot(),
        )
    return RunnerResult(
        status="COMPLETE",
        before_state_projections=before_states,
        provider_slot_projections=dict(slot_projections),
        operation_results=tuple(operation_results),
        ledger=ledger.snapshot(),
    )


def reconcile_uncertain(
    *,
    plan: Mapping[str, Any],
    operation_id: str,
    adapter: ProviderAdapter,
    ledger: AttemptLedger,
) -> dict[str, Any]:
    """Reconcile a consumed attempt through the adapter's read-only method."""

    _require_scripted_adapter(adapter)
    from tooling.platform_authority_gug365_upstream_materializer import (
        validate_repository_plan,
    )

    validate_repository_plan(plan)
    current = ledger.operation(operation_id)
    if current["status"] != "UNCERTAIN_RECONCILE_ONLY" or current["attempt_count"] != 1:
        _fail("RECONCILIATION_STATE_INVALID")
    operation_record = next(
        (
            item
            for item in plan.get("operations", [])
            if isinstance(item, Mapping) and item.get("operation_id") == operation_id
        ),
        None,
    )
    if operation_record is None:
        _fail("RECONCILIATION_OPERATION_UNKNOWN")
    slot_projections: dict[str, str] = {}
    for prior_record in plan.get("operations", []):
        if prior_record is operation_record:
            break
        prior_operation = bind_consumed_slot_projections(
            operation_from_record(prior_record), slot_projections
        )
        if ledger.operation(prior_operation.operation_id)["status"] != "SUCCEEDED":
            _fail("RECONCILIATION_PREDECESSOR_NOT_PROVEN")
        prior_result_digest = provider_result_projection_digest(
            prior_operation, ProviderStatus.SUCCEEDED
        )
        for slot_projection in provider_slot_projections(
            prior_operation, ProviderStatus.SUCCEEDED, prior_result_digest
        ):
            if slot_projection.slot in slot_projections:
                _fail("PROVIDER_SLOT_REPLAY_FORBIDDEN")
            slot_projections[slot_projection.slot] = slot_projection.projection_digest
    operation = bind_consumed_slot_projections(
        operation_from_record(operation_record), slot_projections
    )
    if current.get("consumed_slot_binding_digest") != consumed_slot_binding_digest(
        operation
    ):
        _fail("RECONCILIATION_SLOT_BINDING_MISMATCH")
    projection = adapter.reconcile_read_only(operation)
    if projection.status is ReconciliationStatus.EFFECT_PROVEN:
        expected_readback_digest = operation.target_state_digest
    elif projection.status is ReconciliationStatus.NO_EFFECT_PROVEN:
        expected_readback_digest = operation.before_state_digest
    elif projection.status is ReconciliationStatus.INCONCLUSIVE:
        expected_readback_digest = canonical_digest(
            {
                "domain": "GUG377_RECONCILIATION_INCONCLUSIVE_V1",
                "operation_id": operation.operation_id,
                "request_digest": operation.request_digest,
            }
        )
    else:
        _fail("RECONCILIATION_STATUS_INVALID")
    expected_projection_digest = canonical_digest(
        {
            "operation_id": operation.operation_id,
            "operation_kind": operation.operation_kind.value,
            "request_digest": operation.request_digest,
            "before_state_digest": operation.before_state_digest,
            "target_state_digest": operation.target_state_digest,
            "status": projection.status.value,
            "readback_projection_digest": expected_readback_digest,
            "consumed_slot_binding_digest": consumed_slot_binding_digest(operation),
            "read_only": True,
            "provider_writes": 0,
        }
    )
    if (
        projection.operation_id != operation.operation_id
        or projection.operation_kind != operation.operation_kind
        or projection.request_digest != operation.request_digest
        or projection.before_state_digest != operation.before_state_digest
        or projection.target_state_digest != operation.target_state_digest
        or projection.readback_projection_digest != expected_readback_digest
        or projection.consumed_slot_binding_digest
        != consumed_slot_binding_digest(operation)
        or projection.provider_writes != 0
        or projection.read_only is not True
        or projection.projection_digest != expected_projection_digest
        or projection.reconciliation_digest != expected_projection_digest
    ):
        _fail("RECONCILIATION_BINDING_MISMATCH")
    state_map = {
        ReconciliationStatus.EFFECT_PROVEN: "RECONCILED_EFFECT_PROVEN",
        ReconciliationStatus.NO_EFFECT_PROVEN: "RECONCILED_NO_EFFECT_PROVEN",
        ReconciliationStatus.INCONCLUSIVE: "RECONCILED_INCONCLUSIVE",
    }
    status = state_map.get(projection.status)
    if status is None:
        _fail("RECONCILIATION_STATUS_UNKNOWN")
    record: dict[str, Any] = {
        "record_type": "scanalyze.platform_authority.gug365_upstream_reconciliation_receipt.v1",
        "schema_version": 1,
        "implementation_issue": "GUG-377",
        "operation_id": operation.operation_id,
        "operation_kind": operation.operation_kind.value,
        "request_digest": operation.request_digest,
        "before_state_digest": operation.before_state_digest,
        "target_state_digest": operation.target_state_digest,
        "readback_projection_digest": projection.readback_projection_digest,
        "consumed_slot_binding_digest": projection.consumed_slot_binding_digest,
        "status": status,
        "read_only": True,
        "provider_writes": 0,
        "write_retry_permitted": False,
        "projection_digest": projection.projection_digest,
    }
    record["reconciliation_digest"] = canonical_digest(record)
    ledger.transition(
        operation_id,
        status=status,
        operation_result_digest=record["reconciliation_digest"],
    )
    return record
