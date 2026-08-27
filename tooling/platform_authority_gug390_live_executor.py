"""Guarded GUG-390 orchestration around the GUG-365 live provider.

The module is deliberately provider-agnostic.  Production entry points must
construct the concrete :mod:`platform_authority_gug365_live_provider` only
after local source, plan, custody, and authorization inputs have passed.  Unit
tests inject fakes and therefore perform no AWS calls.

The existing durable GUG-365 phase ledger remains the authority for causal
ordering.  This module adds only the live boundary around it: two stable
read-only captures, one phase per invocation, read-only reconciliation, and a
sanitized terminal manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
import base64
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import unquote

from tooling import platform_authority_gug365_phase_execution_ledger as phase_ledger
from tooling import (
    platform_authority_gug376_authority_inventory_collector as private_custody,
)
from tooling import (
    platform_authority_retirement_entrypoint_service_role_materializer
    as service_role_materializer,
)


ISSUE = "GUG-390"
REGION = "us-east-1"
PUBLIC_RECORD_TYPE = "scanalyze.platform_authority.gug390_live_run.v1"
PRIVATE_SNAPSHOT_TYPE = "scanalyze.platform_authority.gug390_private_snapshot.v1"
PRIVATE_RUN_TYPE = "scanalyze.platform_authority.gug390_private_run.v1"
PRIVATE_PROVIDER_EVIDENCE_TYPE = (
    "scanalyze.platform_authority.gug390_private_provider_evidence.v1"
)
PRIVATE_RECONCILIATION_EVIDENCE_TYPE = (
    "scanalyze.platform_authority.gug390_private_reconciliation_evidence.v1"
)
FORWARD_PHASES = phase_ledger.FORWARD_PHASES
MAX_INVENTORY_OPERATIONS = 256

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_PRIVATE_FILE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,126}\.json$")
# One provider response is closed at 8 MiB.  The largest mutation evidence has
# one response plus four immediate readbacks; reconciliation retains two such
# four-readback captures.  Sixteen response units leave bounded room for the
# enclosing canonical records without rejecting a valid provider receipt.
_PROVIDER_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_PRIVATE_EVIDENCE_BYTES = 16 * _PROVIDER_MAX_RESPONSE_BYTES
_PRIVATE_PROVIDER_RECORD_FIELDS = frozenset(
    {
        "outcome",
        "phase",
        "sequence",
        "operation_digest",
        "request_digest",
        "response_digest",
        "operation_calls",
        "provider_calls",
        "reconciliation_required",
        "error_code",
        "response",
    }
)

_READ_ACTIONS = frozenset(
    {
        ("sts", "GetCallerIdentity"),
        ("iam", "GetPolicy"),
        ("iam", "GetPolicyVersion"),
        ("iam", "ListPolicyVersions"),
        ("iam", "ListEntitiesForPolicy"),
        ("iam", "ListPolicyTags"),
        ("iam", "GetRole"),
        ("iam", "ListRolePolicies"),
        ("iam", "ListAttachedRolePolicies"),
        ("iam", "ListRoleTags"),
        ("lambda", "GetFunction"),
        ("lambda", "GetFunctionConfiguration"),
        ("lambda", "GetFunctionCodeSigningConfig"),
        ("lambda", "GetFunctionConcurrency"),
        ("lambda", "GetRuntimeManagementConfig"),
        ("lambda", "ListTags"),
        ("lambda", "ListVersionsByFunction"),
        ("lambda", "ListAliases"),
        ("lambda", "ListFunctionUrlConfigs"),
        ("lambda", "GetPolicy"),
        ("lambda", "GetCodeSigningConfig"),
        ("logs", "DescribeLogGroups"),
        ("logs", "ListTagsForResource"),
        ("dynamodb", "DescribeTable"),
        ("dynamodb", "DescribeContinuousBackups"),
        ("dynamodb", "DescribeTimeToLive"),
        ("dynamodb", "GetResourcePolicy"),
        ("dynamodb", "ListTagsOfResource"),
        ("dynamodb", "Scan"),
        ("kms", "DescribeKey"),
        ("s3", "GetObjectVersion"),
    }
)

_WRITE_ACTIONS = frozenset(
    {
        ("iam", "CreatePolicy"),
        ("iam", "CreateRole"),
        ("lambda", "CreateFunction"),
        ("lambda", "PutRuntimeManagementConfig"),
        ("lambda", "PutFunctionConcurrency"),
        ("logs", "CreateLogGroup"),
        ("logs", "PutRetentionPolicy"),
        ("iam", "AttachRolePolicy"),
        ("iam", "PutRolePermissionsBoundary"),
        ("lambda", "InvokeFunction"),
        ("iam", "DetachRolePolicy"),
    }
)

_WAITER_ACTIONS = frozenset(
    {
        ("lambda", "WaitUntilFunctionActiveV2"),
        ("dynamodb", "WaitUntilTableExists"),
    }
)

_EXISTENCE_ANCHORS = frozenset(
    {
        ("iam", "GetPolicy"),
        ("iam", "GetRole"),
        ("lambda", "GetFunction"),
        ("dynamodb", "DescribeTable"),
        ("logs", "DescribeLogGroups"),
    }
)


class Gug390Error(ValueError):
    """Stable fail-closed error that never embeds caller/provider text."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "GUG390_LIVE_BLOCKED"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class InventoryOperation:
    """One plan-derived read operation for a stable inventory capture."""

    sequence: int
    service: str
    api_action: str
    target_arn: str
    request: dict[str, Any]
    request_digest: str
    complete_pagination_required: bool
    resource_scope: str
    attempt_limit: int = 1
    retry_permitted: bool = False

    def as_mapping(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "service": self.service,
            "api_action": self.api_action,
            "target_arn": self.target_arn,
            "request": json.loads(canonical_json(self.request)),
            "request_digest": self.request_digest,
            "complete_pagination_required": self.complete_pagination_required,
            "resource_scope": self.resource_scope,
            "attempt_limit": self.attempt_limit,
            "retry_permitted": self.retry_permitted,
        }


@dataclass(frozen=True, slots=True)
class ReadResult:
    """Canonical provider read result; raw facts remain private."""

    outcome: str
    result_digest: str
    private_result: Mapping[str, Any] | None = None
    page_count: int = 1


@dataclass(frozen=True, slots=True)
class _ProviderInvocation:
    """Detached provider outcome plus its owner-only raw response record."""

    result: phase_ledger.OperationResult
    private_record: Mapping[str, Any] | None


class Provider(Protocol):
    """Narrow interface implemented by the concrete provider and test fakes."""

    mode: str

    def identity(self) -> Mapping[str, Any]: ...

    def read_operation(self, operation: Mapping[str, Any]) -> ReadResult: ...

    def invoke_operation(
        self, operation: Mapping[str, Any]
    ) -> phase_ledger.OperationResult: ...

    def transcript_summary(self) -> Mapping[str, Any]: ...

    def revalidate_identity(self) -> Any: ...

    def reconciliation_readback_calls(self, operation: Any) -> Sequence[Any]: ...


_ABSENCE_ERRORS = frozenset(
    {
        "NoSuchEntity",
        "NoSuchEntityException",
        "NoSuchKey",
        "NoSuchKeyException",
        "NoSuchResource",
        "NotFoundException",
        "ResourceNotFound",
        "ResourceNotFoundException",
    }
)


def canonical_json(value: Any) -> str:
    return phase_ledger.canonical_json(value)


def canonical_digest(value: Any) -> str:
    return phase_ledger.canonical_digest(value)


def _provider_evidence_file(ledger_id: str, operation_sequence: int) -> str:
    digest = _require_digest(ledger_id, "LEDGER_ID_INVALID").split(":", 1)[1]
    if (
        type(operation_sequence) is not int
        or not 1 <= operation_sequence <= MAX_INVENTORY_OPERATIONS
    ):
        _fail("PRIVATE_EVIDENCE_SEQUENCE_INVALID")
    return f"gug390-provider-{digest}-{operation_sequence:03d}.json"


def _reconciliation_evidence_file(ledger_id: str) -> str:
    digest = _require_digest(ledger_id, "LEDGER_ID_INVALID").split(":", 1)[1]
    return f"gug390-reconcile-{digest}.json"


def _private_record_bytes(value: Mapping[str, Any]) -> bytes:
    payload = (canonical_json(value) + "\n").encode("utf-8")
    if not 0 < len(payload) <= _MAX_PRIVATE_EVIDENCE_BYTES:
        _fail("PRIVATE_EVIDENCE_SIZE_INVALID")
    return payload


def _read_private_custody_record(
    root: Path,
    name: str,
    *,
    missing_ok: bool = False,
) -> dict[str, Any] | None:
    """Read one exact canonical owner-only record without following links."""

    if not isinstance(root, Path) or not isinstance(name, str) or not _PRIVATE_FILE.fullmatch(name):
        _fail("PRIVATE_EVIDENCE_LOCATION_INVALID")
    directory: int | None = None
    descriptor: int | None = None
    try:
        directory = private_custody._root(root)  # noqa: SLF001
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except FileNotFoundError:
            if missing_ok:
                return None
            _fail("PRIVATE_EVIDENCE_MISSING")
        opened = os.fstat(descriptor)
        path_item = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not 0 < opened.st_size <= _MAX_PRIVATE_EVIDENCE_BYTES
            or (opened.st_dev, opened.st_ino)
            != (path_item.st_dev, path_item.st_ino)
        ):
            _fail("PRIVATE_EVIDENCE_CUSTODY_INVALID")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                _fail("PRIVATE_EVIDENCE_READ_INCOMPLETE")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _fail("PRIVATE_EVIDENCE_CHANGED_DURING_READ")
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (
            (after.st_dev, after.st_ino, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or (rebound.st_dev, rebound.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            _fail("PRIVATE_EVIDENCE_CHANGED_DURING_READ")
        raw = b"".join(chunks)

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    _fail("PRIVATE_EVIDENCE_DUPLICATE_KEY")
                value[key] = item
            return value

        try:
            parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise Gug390Error("PRIVATE_EVIDENCE_JSON_INVALID") from exc
        if not isinstance(parsed, dict) or raw != _private_record_bytes(parsed):
            _fail("PRIVATE_EVIDENCE_NONCANONICAL")
        return parsed
    except Gug390Error:
        raise
    except private_custody.CollectorError as exc:
        raise Gug390Error("PRIVATE_EVIDENCE_CUSTODY_INVALID") from exc
    except OSError as exc:
        raise Gug390Error("PRIVATE_EVIDENCE_READ_FAILED") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _persist_private_custody_record(
    root: Path, name: str, value: Mapping[str, Any]
) -> dict[str, Any]:
    """Create-only publish, or accept only a byte-identical crash remnant."""

    record = _snapshot(value, "PRIVATE_EVIDENCE_INVALID")
    if not isinstance(record, dict):
        _fail("PRIVATE_EVIDENCE_INVALID")
    supplied = _require_digest(
        record.get("evidence_digest"), "PRIVATE_EVIDENCE_DIGEST_INVALID"
    )
    if supplied != canonical_digest(
        {key: item for key, item in record.items() if key != "evidence_digest"}
    ):
        _fail("PRIVATE_EVIDENCE_DIGEST_MISMATCH")
    _private_record_bytes(record)
    existing = _read_private_custody_record(root, name, missing_ok=True)
    if existing is not None:
        if existing != record:
            _fail("PRIVATE_EVIDENCE_CONFLICT")
        return existing
    try:
        private_custody.write_private_json(root, name, record)
    except private_custody.CollectorError:
        # A crash/concurrent continuation may have completed the create-only
        # publication.  Accept only an exact canonical readback.
        existing = _read_private_custody_record(root, name, missing_ok=True)
        if existing != record:
            _fail("PRIVATE_EVIDENCE_PERSIST_FAILED")
    readback = _read_private_custody_record(root, name)
    if readback != record:
        _fail("PRIVATE_EVIDENCE_READBACK_MISMATCH")
    return record


def _fail(code: str) -> None:
    raise Gug390Error(code)


def _snapshot(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, OverflowError) as exc:
        raise Gug390Error(code) from exc


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _utc(value: datetime, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return value.astimezone(UTC).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_stamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Gug390Error(code) from exc
    return _utc(parsed, code)


def validate_source_binding(
    *,
    expected_commit_sha: str,
    expected_tree_sha: str,
    actual_commit_sha: str,
    actual_tree_sha: str,
) -> None:
    """Require the independently supplied source pair to equal the checkout."""

    values = (
        expected_commit_sha,
        expected_tree_sha,
        actual_commit_sha,
        actual_tree_sha,
    )
    if any(not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None for value in values):
        _fail("SOURCE_BINDING_INVALID")
    if (expected_commit_sha, expected_tree_sha) != (
        actual_commit_sha,
        actual_tree_sha,
    ):
        _fail("SOURCE_BINDING_MISMATCH")


def validate_plan(
    plan: Mapping[str, Any],
    *,
    expected_plan_digest: str,
    expected_account_id: str,
    expected_region: str,
) -> dict[str, Any]:
    """Validate the live-relevant closed projection of a GUG-365 plan.

    The offline compiler remains the canonical full validator.  The live
    process receives the compiler's output plus an independently delivered
    digest and revalidates every executable request before any effect.
    """

    value = _snapshot(plan, "PLAN_SNAPSHOT_INVALID")
    if not isinstance(value, dict):
        _fail("PLAN_SNAPSHOT_INVALID")
    value.pop("_test_metadata", None)
    digest = _require_digest(expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID")
    if value.get("plan_digest") != digest:
        _fail("PLAN_DIGEST_MISMATCH")
    calculated = canonical_digest(
        {key: item for key, item in value.items() if key != "plan_digest"}
    )
    if calculated != digest:
        _fail("PLAN_DIGEST_MISMATCH")
    if (
        not isinstance(expected_account_id, str)
        or _ACCOUNT.fullmatch(expected_account_id) is None
        or expected_region != REGION
    ):
        _fail("TARGET_BINDING_INVALID")
    target = value.get("target")
    if (
        not isinstance(target, Mapping)
        or target.get("authority_account_id") != expected_account_id
        or target.get("region") != REGION
        or target.get("partition") != "aws"
        or value.get("production") is not False
        or value.get("deployment_authorized") is not False
        or value.get("mutation_retry_permitted") is not False
        or value.get("update_permitted") is not False
        or value.get("delete_permitted") is not False
        or value.get("repair_permitted") is not False
        or value.get("ambiguous_outcome_mode")
        != "STOP_AND_RECONCILE_READ_ONLY"
    ):
        _fail("TARGET_BINDING_INVALID")

    phases = value.get("authorization_phases")
    if (
        not isinstance(phases, list)
        or tuple(
            item.get("phase") for item in phases if isinstance(item, Mapping)
        )
        != FORWARD_PHASES
        or len(phases) != len(FORWARD_PHASES)
    ):
        _fail("PHASE_SET_INVALID")
    for phase in phases:
        operations = phase.get("operations")
        if not isinstance(operations, list) or not operations:
            _fail("PHASE_OPERATIONS_INVALID")
        for local_index, operation in enumerate(operations, 1):
            _validate_plan_operation(operation)
            if operation.get("sequence") != local_index:
                _fail("PHASE_OPERATION_SEQUENCE_INVALID")
        if operations[0].get("service") != "sts" or operations[0].get(
            "api_action"
        ) != "GetCallerIdentity":
            _fail("PHASE_STS_FIRST_INVALID")
    return value


def _validate_plan_operation(operation: Any) -> None:
    if not isinstance(operation, Mapping):
        _fail("PLAN_OPERATION_INVALID")
    request = operation.get("request")
    pair = (operation.get("service"), operation.get("api_action"))
    if (
        not isinstance(request, Mapping)
        or pair not in _READ_ACTIONS | _WRITE_ACTIONS | _WAITER_ACTIONS
        or operation.get("request_digest") != canonical_digest(request)
        or operation.get("attempt_limit", 1) != 1
        or operation.get("retry_permitted", False) is not False
    ):
        _fail("PLAN_OPERATION_INVALID")


def _target_scope(plan: Mapping[str, Any], target_arn: str, action: str) -> str:
    if action == "GetCodeSigningConfig":
        return "PREREQUISITE"
    target_arns: set[str] = set()
    for boundary in plan.get("boundaries", []):
        if isinstance(boundary, Mapping):
            target_arns.add(str(boundary.get("arn", "")))
    child_roles = plan.get("child_roles")
    if not isinstance(child_roles, list):
        _fail("PLAN_NESTING_INVALID")
    for role in (plan.get("service_role"), *child_roles):
        if isinstance(role, Mapping):
            target_arns.add(str(role.get("arn", "")))
    for key in (
        "ledger_table",
        "broker_function",
        "ledger_factory_function",
        "ledger_factory_log_group",
    ):
        contract = plan.get(key)
        if isinstance(contract, Mapping):
            target_arns.add(str(contract.get("arn", "")))
            target_arns.add(str(contract.get("immutable_version_arn", "")))
    return "TARGET" if target_arn in target_arns else "PREREQUISITE"


def inventory_operations(plan: Mapping[str, Any]) -> tuple[InventoryOperation, ...]:
    """Return the deduplicated closed inventory contract for all six services."""

    raw = plan.get("planned_readbacks")
    if not isinstance(raw, list) or not raw:
        _fail("PLANNED_READBACKS_INVALID")
    expected_digest = _require_digest(
        plan.get("planned_readback_digest"), "PLANNED_READBACK_DIGEST_INVALID"
    )
    if canonical_digest(raw) != expected_digest:
        _fail("PLANNED_READBACK_DIGEST_MISMATCH")

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            _fail("PLANNED_READBACKS_INVALID")
        pair = (item.get("service"), item.get("api_action"))
        # Waiters are phase-specific.  The plan-bound, read-only COUNT scan is
        # part of the final exact-state proof.  KMS placeholders are replaced
        # below with exact plan-owned key identifiers.
        if pair in _WAITER_ACTIONS:
            continue
        if pair == ("kms", "DescribeKey"):
            continue
        if pair not in _READ_ACTIONS:
            _fail("PLANNED_READBACK_ACTION_INVALID")
        request = item.get("request")
        target_arn = item.get("target_arn")
        if (
            not isinstance(request, Mapping)
            or not isinstance(target_arn, str)
            or not target_arn
            or item.get("attempt_limit", 1) != 1
            or item.get("retry_permitted", False) is not False
        ):
            _fail("PLANNED_READBACKS_INVALID")
        key = canonical_digest(
            {
                "service": pair[0],
                "api_action": pair[1],
                "target_arn": target_arn,
                "request": request,
            }
        )
        if key in seen:
            continue
        seen.add(key)
        selected.append(
            {
                "service": pair[0],
                "api_action": pair[1],
                "target_arn": target_arn,
                "request": dict(request),
                "complete_pagination_required": item.get(
                    "complete_pagination_required", False
                ),
            }
        )

    artifact_contracts = (
        plan.get("signed_artifact_binding"),
        plan.get("ledger_factory_function", {}).get("signed_code"),
    )
    for contract in artifact_contracts:
        if not isinstance(contract, Mapping):
            _fail("ARTIFACT_BINDING_INVALID")
        bucket = contract.get("bucket", contract.get("s3_bucket"))
        key = contract.get("key", contract.get("s3_key"))
        version = contract.get("version_id", contract.get("s3_object_version"))
        if not all(isinstance(value, str) and value for value in (bucket, key, version)):
            _fail("ARTIFACT_BINDING_INVALID")
        target_arn = f"arn:aws:s3:::{bucket}/{key}"
        request = {
            "Bucket": bucket,
            "Key": key,
            "VersionId": version,
            "ChecksumMode": "ENABLED",
        }
        selected.append(
            {
                "service": "s3",
                "api_action": "GetObjectVersion",
                "target_arn": target_arn,
                "request": request,
                "complete_pagination_required": False,
            }
        )

    kms_ids = {
        str(plan.get("signed_artifact_binding", {}).get("sse_kms_key_arn", "")),
        str(
            plan.get("ledger_factory_function", {}).get(
                "artifact_sse_kms_key_arn", ""
            )
        ),
        str(plan.get("ledger_table", {}).get("sse_specification", {}).get("KMSMasterKeyId", "")),
    }
    for key_id in sorted(kms_ids):
        if not key_id:
            _fail("KMS_BINDING_INVALID")
        selected.append(
            {
                "service": "kms",
                "api_action": "DescribeKey",
                "target_arn": key_id,
                "request": {"KeyId": key_id},
                "complete_pagination_required": False,
            }
        )

    if len(selected) > MAX_INVENTORY_OPERATIONS:
        _fail("INVENTORY_OPERATION_LIMIT_EXCEEDED")
    operations: list[InventoryOperation] = []
    for sequence, item in enumerate(selected, 1):
        request = _snapshot(item["request"], "INVENTORY_REQUEST_INVALID")
        operations.append(
            InventoryOperation(
                sequence=sequence,
                service=str(item["service"]),
                api_action=str(item["api_action"]),
                target_arn=str(item["target_arn"]),
                request=request,
                request_digest=canonical_digest(request),
                complete_pagination_required=(
                    item["complete_pagination_required"] is True
                ),
                resource_scope=_target_scope(
                    plan, str(item["target_arn"]), str(item["api_action"])
                ),
            )
        )
    services = {operation.service for operation in operations}
    if services != {"iam", "lambda", "logs", "dynamodb", "s3", "kms"}:
        _fail("INVENTORY_SERVICE_SET_INVALID")
    return tuple(operations)


def _validate_provider_identity(
    identity: Mapping[str, Any],
    *,
    expected_account_id: str,
    expected_region: str,
) -> dict[str, Any]:
    value = _snapshot(identity, "PROVIDER_IDENTITY_INVALID")
    required = {
        "account_id",
        "region",
        "caller_arn_digest",
        "session_identifier_digest",
        "source",
        "chain_depth",
        "observed_at",
    }
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or value.get("account_id") != expected_account_id
        or value.get("region") != expected_region
        or value.get("source") not in {"DIRECT_SSO", "INJECTED_NON_LIVE"}
        or value.get("chain_depth") != 0
    ):
        _fail("PROVIDER_IDENTITY_MISMATCH")
    for key in ("caller_arn_digest", "session_identifier_digest"):
        _require_digest(value.get(key), "PROVIDER_IDENTITY_INVALID")
    _parse_stamp(value.get("observed_at"), "PROVIDER_IDENTITY_TIME_INVALID")
    return value


def _provider_mode(provider: Provider) -> str:
    mode = getattr(provider, "mode", None)
    if mode == "SYNTHETIC":
        return "SYNTHETIC"
    receipt = getattr(provider, "identity_receipt", None)
    concrete = getattr(receipt, "concrete_provider", None)
    if type(concrete) is bool:
        try:
            from tooling import platform_authority_gug365_live_provider as live_provider
        except ImportError as exc:  # pragma: no cover - repository packaging failure
            raise Gug390Error("PROVIDER_MODE_INVALID") from exc
        if type(provider) is not live_provider.LiveProvider or type(
            receipt
        ) is not live_provider.IdentityReceipt:
            _fail("PROVIDER_MODE_INVALID")
        return "LIVE" if concrete else "SYNTHETIC"
    _fail("PROVIDER_MODE_INVALID")


def _provider_identity(
    provider: Provider,
    *,
    expected_account_id: str,
    expected_region: str,
    observed_at: datetime,
) -> dict[str, Any]:
    method = getattr(provider, "identity", None)
    if callable(method):
        raw = method()
    else:
        receipt = getattr(provider, "identity_receipt", None)
        if receipt is None:
            _fail("PROVIDER_IDENTITY_INVALID")
        account_digest = getattr(receipt, "account_digest", None)
        principal_digest = getattr(receipt, "principal_digest", None)
        session_digest = getattr(receipt, "session_digest", None)
        region = getattr(receipt, "region", None)
        concrete = getattr(receipt, "concrete_provider", None)
        if (
            account_digest != canonical_digest(expected_account_id)
            or region != expected_region
            or type(concrete) is not bool
        ):
            _fail("PROVIDER_IDENTITY_MISMATCH")
        raw = {
            "account_id": expected_account_id,
            "region": expected_region,
            "caller_arn_digest": principal_digest,
            "session_identifier_digest": session_digest,
            "source": "DIRECT_SSO" if concrete else "INJECTED_NON_LIVE",
            "chain_depth": 0,
            "observed_at": _stamp(_utc(observed_at, "PROVIDER_IDENTITY_TIME_INVALID")),
        }
    return _validate_provider_identity(
        raw,
        expected_account_id=expected_account_id,
        expected_region=expected_region,
    )


def _as_mapping(value: Any, code: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        candidate = dict(value)
    elif is_dataclass(value):
        candidate = asdict(value)
    else:
        _fail(code)
    result = _snapshot(candidate, code)
    if not isinstance(result, dict):
        _fail(code)
    return result


def _transcript_projection(raw: Mapping[str, Any]) -> dict[str, Any]:
    raw = _as_mapping(raw, "PROVIDER_TRANSCRIPT_INVALID")
    transcript_digest = raw.get("transcript_digest")
    calls = raw.get("call_count", raw.get("provider_calls"))
    writes = raw.get("write_call_count", raw.get("provider_mutation_calls"))
    live = raw.get("live_provider_evidence")
    causal_binding = raw.get("accepted_causal_receipt_binding_digest")
    identity_receipt = raw.get("identity_receipt_digest")
    summary_digest = raw.get("summary_digest")
    complete = raw.get("complete")
    if (
        _DIGEST.fullmatch(str(transcript_digest)) is None
        or type(calls) is not int
        or calls < 1
        or type(writes) is not int
        or not 0 <= writes <= calls
        or type(live) is not bool
        or (
            causal_binding is not None
            and _DIGEST.fullmatch(str(causal_binding)) is None
        )
        or (
            identity_receipt is not None
            and _DIGEST.fullmatch(str(identity_receipt)) is None
        )
        or (
            summary_digest is not None
            and _DIGEST.fullmatch(str(summary_digest)) is None
        )
        or (live and (identity_receipt is None or summary_digest is None))
        or (live and complete is not True)
    ):
        _fail("PROVIDER_TRANSCRIPT_INVALID")
    return {
        "transcript_digest": transcript_digest,
        "call_count": calls,
        "write_call_count": writes,
        "live_provider_evidence": live,
        "accepted_causal_receipt_binding_digest": causal_binding,
        "identity_receipt_digest": identity_receipt,
        "summary_digest": summary_digest,
    }


def _provider_transcript(provider: Provider) -> dict[str, Any]:
    return _transcript_projection(
        _as_mapping(provider.transcript_summary(), "PROVIDER_TRANSCRIPT_INVALID")
    )


def _execution_context(
    *,
    owner_checkpoint_digest: str,
    live_request_digest: str,
    activator_checkpoint_digest: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "issue": ISSUE,
        "owner_checkpoint_digest": _require_digest(
            owner_checkpoint_digest, "OWNER_CHECKPOINT_DIGEST_INVALID"
        ),
        "live_request_digest": _require_digest(
            live_request_digest, "LIVE_REQUEST_DIGEST_INVALID"
        ),
        "activator_checkpoint_digest": activator_checkpoint_digest,
    }
    if activator_checkpoint_digest is not None:
        _require_digest(
            activator_checkpoint_digest,
            "ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
        )
    return {**body, "context_digest": canonical_digest(body)}


def _claim_execution_context(
    record: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None = None,
    required: bool = False,
) -> dict[str, Any] | None:
    claim = record.get("claim")
    raw = claim.get("execution_context") if isinstance(claim, Mapping) else None
    if raw is None:
        if required or expected is not None:
            _fail("EXECUTION_CONTEXT_MISSING")
        return None
    try:
        checked = phase_ledger.validate_execution_context(raw)
    except Exception as exc:
        raise Gug390Error("EXECUTION_CONTEXT_INVALID") from exc
    if expected is not None and checked != _snapshot(
        expected, "EXECUTION_CONTEXT_INVALID"
    ):
        _fail("EXECUTION_CONTEXT_MISMATCH")
    return checked


def _self_bound_receipt(
    value: Mapping[str, Any], *, self_digest_field: str, code: str
) -> tuple[dict[str, Any], str]:
    receipt = _as_mapping(value, code)
    supplied = receipt.get(self_digest_field)
    if supplied is None:
        return receipt, canonical_digest(receipt)
    digest = _require_digest(supplied, code)
    if digest != canonical_digest(
        {key: item for key, item in receipt.items() if key != self_digest_field}
    ):
        _fail(code)
    return receipt, digest


def _durable_provider_evidence(
    *,
    provider: Provider,
    identity: Mapping[str, Any],
    operation: Mapping[str, Any],
    phase: str,
    plan: Mapping[str, Any],
    transcript_before: Mapping[str, Any],
    result: phase_ledger.OperationResult,
    execution_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal provider proof before the ledger outcome CAS.

    Provider-returned evidence is deliberately ignored.  All fields are
    derived from the concrete provider, the validated plan operation, and the
    already-durable claim context.
    """

    raw_identity = getattr(provider, "identity_receipt", None)
    if raw_identity is None:
        raw_identity = identity
    identity_receipt, identity_digest = _self_bound_receipt(
        _as_mapping(raw_identity, "DURABLE_PROVIDER_IDENTITY_INVALID"),
        self_digest_field="receipt_digest",
        code="DURABLE_PROVIDER_IDENTITY_INVALID",
    )
    raw_transcript_before = _as_mapping(
        transcript_before, "DURABLE_PROVIDER_TRANSCRIPT_INVALID"
    )
    _transcript_projection(raw_transcript_before)
    transcript_before_receipt, transcript_before_receipt_digest = (
        _self_bound_receipt(
            raw_transcript_before,
            self_digest_field="summary_digest",
            code="DURABLE_PROVIDER_TRANSCRIPT_INVALID",
        )
    )
    raw_transcript = _as_mapping(
        provider.transcript_summary(), "DURABLE_PROVIDER_TRANSCRIPT_INVALID"
    )
    _transcript_projection(raw_transcript)
    transcript, transcript_receipt_digest = _self_bound_receipt(
        raw_transcript,
        self_digest_field="summary_digest",
        code="DURABLE_PROVIDER_TRANSCRIPT_INVALID",
    )
    causal = _private_causal_receipt_evidence(provider)
    operation_digest = _provider_operation_digest(
        phase=phase, operation=operation, plan=plan
    )
    request_digest = _require_digest(
        operation.get("request_digest"), "PROVIDER_OPERATION_BINDING_INVALID"
    )
    context = phase_ledger.validate_execution_context(execution_context)
    body: dict[str, Any] = {
        "record_type": (
            "scanalyze.platform_authority.gug390_durable_provider_evidence.v1"
        ),
        "schema_version": 1,
        "issue": ISSUE,
        "phase": phase,
        "operation_sequence": operation.get("sequence"),
        "operation_digest": operation_digest,
        "provider_request_digest": request_digest,
        "outcome": result.outcome,
        "provider_result_digest": result.provider_result_digest,
        "provider_mode": _provider_mode(provider),
        "identity_receipt": identity_receipt,
        "identity_receipt_digest": identity_digest,
        "caller_arn_digest": identity.get("caller_arn_digest"),
        "session_identifier_digest": identity.get("session_identifier_digest"),
        "transcript_before": transcript_before_receipt,
        "transcript_before_receipt_digest": (
            transcript_before_receipt_digest
        ),
        "transcript": transcript,
        "transcript_receipt_digest": transcript_receipt_digest,
        "owner_checkpoint_digest": context["owner_checkpoint_digest"],
        "live_request_digest": context["live_request_digest"],
        "execution_context_digest": context["context_digest"],
        "activator_checkpoint_digest": context["activator_checkpoint_digest"],
        "causal_receipt_evidence": causal,
        "causal_receipt_evidence_digest": (
            canonical_digest(causal) if causal is not None else None
        ),
    }
    return {**body, "evidence_digest": canonical_digest(body)}


def _seal_linked_provider_evidence(
    base_evidence: Mapping[str, Any],
    *,
    private_evidence_file: str,
    private_evidence_digest: str,
    outcome: str | None = None,
    provider_result_digest: str | None = None,
) -> dict[str, Any]:
    base = _snapshot(base_evidence, "DURABLE_PROVIDER_EVIDENCE_INVALID")
    if not isinstance(base, dict):
        _fail("DURABLE_PROVIDER_EVIDENCE_INVALID")
    base.pop("evidence_digest", None)
    if outcome is not None:
        if outcome not in {"SUCCEEDED", "FAILED", "AMBIGUOUS"}:
            _fail("DURABLE_PROVIDER_EVIDENCE_INVALID")
        base["outcome"] = outcome
        base["provider_result_digest"] = provider_result_digest
    if not isinstance(private_evidence_file, str) or not _PRIVATE_FILE.fullmatch(
        private_evidence_file
    ):
        _fail("PRIVATE_EVIDENCE_LOCATION_INVALID")
    body = {
        **base,
        "private_provider_evidence_file": private_evidence_file,
        "private_provider_evidence_digest": _require_digest(
            private_evidence_digest, "PRIVATE_EVIDENCE_DIGEST_INVALID"
        ),
    }
    return {**body, "evidence_digest": canonical_digest(body)}


def _private_provider_evidence_record(
    *,
    ledger_record: Mapping[str, Any],
    operation: Mapping[str, Any],
    base_evidence: Mapping[str, Any],
    provider_private_record: Mapping[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    sequence = operation.get("sequence")
    name = _provider_evidence_file(str(ledger_record.get("ledger_id")), sequence)
    private = (
        _snapshot(provider_private_record, "PROVIDER_PRIVATE_RESULT_INVALID")
        if provider_private_record is not None
        else None
    )
    base = _snapshot(base_evidence, "DURABLE_PROVIDER_EVIDENCE_INVALID")
    if not isinstance(base, dict):
        _fail("DURABLE_PROVIDER_EVIDENCE_INVALID")
    base.pop("evidence_digest", None)
    body = {
        "record_type": PRIVATE_PROVIDER_EVIDENCE_TYPE,
        "schema_version": 1,
        "issue": ISSUE,
        "ledger_id": ledger_record.get("ledger_id"),
        "initial_ledger_digest": ledger_record.get("initial_ledger_digest"),
        "private_evidence_file": name,
        "durable_provider_evidence_body": base,
        "provider_private_record": private,
        "provider_private_record_digest": canonical_digest(
            {"provider_private_record": private}
        ),
        "repository_persisted": False,
    }
    return name, {**body, "evidence_digest": canonical_digest(body)}


def _validate_private_provider_record(
    value: Any, *, code: str
) -> dict[str, Any]:
    record = _snapshot(value, code)
    if not isinstance(record, dict) or set(record) != _PRIVATE_PROVIDER_RECORD_FIELDS:
        _fail(code)
    outcome = record.get("outcome")
    phase = record.get("phase")
    sequence = record.get("sequence")
    operation_calls = record.get("operation_calls")
    provider_calls = record.get("provider_calls")
    reconciliation_required = record.get("reconciliation_required")
    error_code = record.get("error_code")
    response = record.get("response")
    response_digest = record.get("response_digest")
    if (
        outcome not in {"SUCCEEDED", "FAILED", "AMBIGUOUS"}
        or not isinstance(phase, str)
        or not phase
        or type(sequence) is not int
        or sequence < 1
        or _DIGEST.fullmatch(str(record.get("operation_digest"))) is None
        or _DIGEST.fullmatch(str(record.get("request_digest"))) is None
        or _DIGEST.fullmatch(str(response_digest)) is None
        or type(operation_calls) is not int
        or operation_calls < 1
        or type(provider_calls) is not int
        or provider_calls < operation_calls
        or type(reconciliation_required) is not bool
        or not isinstance(response, Mapping)
        or response_digest != canonical_digest(response)
        or (
            outcome == "SUCCEEDED"
            and (error_code is not None or reconciliation_required is not False)
        )
        or (
            outcome == "FAILED"
            and (
                not isinstance(error_code, str)
                or not error_code
                or reconciliation_required is not False
            )
        )
        or (
            outcome == "AMBIGUOUS"
            and (
                not isinstance(error_code, str)
                or not error_code
                or reconciliation_required is not True
            )
        )
    ):
        _fail(code)
    return record


def _validate_private_provider_evidence_record(
    value: Mapping[str, Any],
    *,
    name: str,
    ledger_record: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    record = _snapshot(value, "PRIVATE_PROVIDER_EVIDENCE_INVALID")
    fields = {
        "record_type",
        "schema_version",
        "issue",
        "ledger_id",
        "initial_ledger_digest",
        "private_evidence_file",
        "durable_provider_evidence_body",
        "provider_private_record",
        "provider_private_record_digest",
        "repository_persisted",
        "evidence_digest",
    }
    if (
        not isinstance(record, dict)
        or set(record) != fields
        or record.get("record_type") != PRIVATE_PROVIDER_EVIDENCE_TYPE
        or record.get("schema_version") != 1
        or record.get("issue") != ISSUE
        or record.get("ledger_id") != ledger_record.get("ledger_id")
        or record.get("initial_ledger_digest")
        != ledger_record.get("initial_ledger_digest")
        or record.get("private_evidence_file") != name
        or record.get("repository_persisted") is not False
        or record.get("evidence_digest")
        != canonical_digest(
            {key: item for key, item in record.items() if key != "evidence_digest"}
        )
    ):
        _fail("PRIVATE_PROVIDER_EVIDENCE_INVALID")
    base = record.get("durable_provider_evidence_body")
    if not isinstance(base, Mapping):
        _fail("PRIVATE_PROVIDER_EVIDENCE_INVALID")
    sequence = base.get("operation_sequence")
    operation = _phase_operation(
        plan, phase=str(ledger_record.get("phase")), sequence=int(sequence)
    ) if type(sequence) is int else None
    if (
        not isinstance(operation, Mapping)
        or name
        != _provider_evidence_file(str(ledger_record.get("ledger_id")), int(sequence))
        or base.get("operation_digest")
        != _provider_operation_digest(
            phase=str(ledger_record.get("phase")), operation=operation, plan=plan
        )
        or base.get("provider_request_digest") != operation.get("request_digest")
    ):
        _fail("PRIVATE_PROVIDER_EVIDENCE_BINDING_INVALID")
    private = record.get("provider_private_record")
    if record.get("provider_private_record_digest") != canonical_digest(
        {"provider_private_record": private}
    ):
        _fail("PRIVATE_PROVIDER_EVIDENCE_DIGEST_MISMATCH")
    mode = base.get("provider_mode")
    if mode == "LIVE" and not isinstance(private, Mapping):
        _fail("PRIVATE_PROVIDER_PAYLOAD_MISSING")
    if private is not None:
        checked_private = _validate_private_provider_record(
            private, code="PRIVATE_PROVIDER_PAYLOAD_INVALID"
        )
        if (
            checked_private.get("phase") != base.get("phase")
            or checked_private.get("sequence") != sequence
            or checked_private.get("operation_digest")
            != base.get("operation_digest")
            or checked_private.get("request_digest")
            != base.get("provider_request_digest")
            or checked_private.get("outcome") != base.get("outcome")
            or (
                base.get("outcome") != "AMBIGUOUS"
                and checked_private.get("response_digest")
                != base.get("provider_result_digest")
            )
        ):
            _fail("PRIVATE_PROVIDER_PAYLOAD_INVALID")
    linked = _seal_linked_provider_evidence(
        base,
        private_evidence_file=name,
        private_evidence_digest=str(record["evidence_digest"]),
    )
    try:
        phase_ledger.validate_durable_provider_evidence(
            linked,
            record=ledger_record,
            operation_sequence=int(sequence),
            outcome=str(base.get("outcome")),
            provider_result_digest=base.get("provider_result_digest"),
        )
    except Exception as exc:
        raise Gug390Error("PRIVATE_PROVIDER_EVIDENCE_BINDING_INVALID") from exc
    return record, linked


def _read_linked_provider_evidence(
    *,
    root: Path,
    ledger_record: Mapping[str, Any],
    plan: Mapping[str, Any],
    durable_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    name = durable_evidence.get("private_provider_evidence_file")
    digest = durable_evidence.get("private_provider_evidence_digest")
    if not isinstance(name, str):
        _fail("PRIVATE_PROVIDER_EVIDENCE_LINK_INVALID")
    raw = _read_private_custody_record(root, name)
    if not isinstance(raw, Mapping):
        _fail("PRIVATE_PROVIDER_EVIDENCE_MISSING")
    record, linked = _validate_private_provider_evidence_record(
        raw, name=name, ledger_record=ledger_record, plan=plan
    )
    if (
        durable_evidence.get("outcome") == "AMBIGUOUS"
        and durable_evidence.get("provider_result_digest") is None
        and linked.get("outcome") != "AMBIGUOUS"
    ):
        linked = _seal_linked_provider_evidence(
            record["durable_provider_evidence_body"],
            private_evidence_file=name,
            private_evidence_digest=str(record["evidence_digest"]),
            outcome="AMBIGUOUS",
            provider_result_digest=None,
        )
    if record.get("evidence_digest") != digest or linked != durable_evidence:
        _fail("PRIVATE_PROVIDER_EVIDENCE_LINK_MISMATCH")
    return record


def _provider_operation_digest(
    *, phase: str, operation: Mapping[str, Any], plan: Mapping[str, Any]
) -> str:
    try:
        from tooling import platform_authority_gug365_live_provider as live_provider

        call = live_provider.planned_call_from_record(
            phase, operation, plan=plan
        )
    except Exception as exc:
        raise Gug390Error("PROVIDER_OPERATION_BINDING_INVALID") from exc
    return _require_digest(
        getattr(call, "operation_digest", None),
        "PROVIDER_OPERATION_BINDING_INVALID",
    )


def _planned_provider_call(
    provider: Provider,
    operation: Mapping[str, Any],
    *,
    phase: str,
    plan: Mapping[str, Any] | None = None,
) -> Any:
    if getattr(provider, "identity_receipt", None) is None:
        return operation
    try:
        from tooling import platform_authority_gug365_live_provider as live_provider

        return live_provider.planned_call_from_record(
            phase, operation, plan=plan
        )
    except Exception as exc:
        raise Gug390Error("PROVIDER_OPERATION_BINDING_INVALID") from exc


def _read_from_provider(
    provider: Provider, operation: Mapping[str, Any], *, phase: str = "READBACK"
) -> ReadResult:
    call = _planned_provider_call(provider, operation, phase=phase)
    raw = provider.read_operation(call)
    if isinstance(raw, ReadResult):
        return _coerce_read_result(raw)
    value = _as_mapping(raw, "PROVIDER_READ_RESULT_INVALID")
    outcome = value.get("outcome")
    if hasattr(outcome, "value"):
        outcome = outcome.value
    response_digest = value.get("response_digest", value.get("result_digest"))
    error_code = value.get("error_code")
    calls = value.get("operation_calls", value.get("page_count", 1))
    private_result = (
        raw.private_record() if callable(getattr(raw, "private_record", None)) else value
    )
    if outcome == "SUCCEEDED":
        selected = _successful_read_presence(operation, value.get("response"))
        digest = response_digest
    elif outcome == "FAILED" and error_code in _ABSENCE_ERRORS:
        selected = "ABSENT"
        digest = canonical_digest(
            {
                "absence": error_code,
                "request_digest": operation.get("request_digest"),
                "target_digest": canonical_digest(operation.get("target_arn")),
            }
        )
    else:
        _fail("INVENTORY_PROVIDER_CALL_UNCERTAIN")
    return _coerce_read_result(
        {
            "outcome": selected,
            "result_digest": digest,
            "private_result": private_result,
            "page_count": calls,
        }
    )


def _successful_read_presence(
    operation: Mapping[str, Any], response: Any
) -> str:
    """Classify success responses whose API encodes absence as an empty list."""

    pair = (operation.get("service"), operation.get("api_action"))
    if pair != ("logs", "DescribeLogGroups"):
        return "PRESENT"
    request = operation.get("request")
    target_arn = operation.get("target_arn")
    if not isinstance(request, Mapping) or not isinstance(target_arn, str):
        _fail("INVENTORY_RESPONSE_INVALID")
    exact_name = request.get("logGroupNamePrefix")
    groups = response.get("logGroups") if isinstance(response, Mapping) else None
    if (
        not isinstance(exact_name, str)
        or not exact_name
        or not target_arn.endswith(f":log-group:{exact_name}")
        or not isinstance(groups, Sequence)
        or isinstance(groups, (str, bytes))
    ):
        _fail("INVENTORY_RESPONSE_INVALID")
    exact = [
        item
        for item in groups
        if isinstance(item, Mapping) and item.get("logGroupName") == exact_name
    ]
    if len(exact) > 1:
        _fail("INVENTORY_RESPONSE_INVALID")
    return "PRESENT" if exact else "ABSENT"


def _invoke_provider_operation(
    provider: Provider,
    operation: Mapping[str, Any],
    *,
    phase: str,
    plan: Mapping[str, Any],
) -> _ProviderInvocation:
    call = _planned_provider_call(
        provider, operation, phase=phase, plan=plan
    )
    if operation.get("api_action") == "InvokeFunction":
        raw = provider.invoke_operation(call, receipt_plan=plan)
    else:
        raw = provider.invoke_operation(call)
    if isinstance(raw, phase_ledger.OperationResult):
        # Provider implementations own only the outcome.  Durable evidence is
        # constructed below from executor-held context and concrete receipts.
        return _ProviderInvocation(
            phase_ledger.OperationResult(
                raw.outcome, raw.provider_result_digest
            ),
            None,
        )
    value = _as_mapping(raw, "PROVIDER_OPERATION_RESULT_INVALID")
    outcome = value.get("outcome")
    if hasattr(outcome, "value"):
        outcome = outcome.value
    if outcome == "AMBIGUOUS":
        result = phase_ledger.OperationResult("AMBIGUOUS", None)
        private_method = getattr(raw, "private_record", None)
        private = private_method() if callable(private_method) else value
        return _ProviderInvocation(result, _as_mapping(
            private, "PROVIDER_PRIVATE_RESULT_INVALID"
        ))
    if outcome not in {"SUCCEEDED", "FAILED"}:
        _fail("PROVIDER_OPERATION_RESULT_INVALID")
    digest = value.get("response_digest", value.get("provider_result_digest"))
    result = phase_ledger.OperationResult(
        str(outcome), _require_digest(digest, "PROVIDER_OPERATION_RESULT_INVALID")
    )
    private_method = getattr(raw, "private_record", None)
    private = private_method() if callable(private_method) else value
    return _ProviderInvocation(
        result,
        _as_mapping(private, "PROVIDER_PRIVATE_RESULT_INVALID"),
    )


def _coerce_read_result(value: Any) -> ReadResult:
    if isinstance(value, ReadResult):
        result = value
    elif isinstance(value, Mapping):
        try:
            result = ReadResult(
                outcome=str(value["outcome"]),
                result_digest=str(value["result_digest"]),
                private_result=value.get("private_result"),
                page_count=int(value.get("page_count", 1)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise Gug390Error("PROVIDER_READ_RESULT_INVALID") from exc
    else:
        _fail("PROVIDER_READ_RESULT_INVALID")
    if (
        result.outcome not in {"PRESENT", "ABSENT"}
        or _DIGEST.fullmatch(result.result_digest) is None
        or type(result.page_count) is not int
        or not 1 <= result.page_count <= 50
    ):
        _fail("PROVIDER_READ_RESULT_INVALID")
    private = _snapshot(result.private_result, "PROVIDER_PRIVATE_RESULT_INVALID")
    if private is not None and not isinstance(private, Mapping):
        _fail("PROVIDER_PRIVATE_RESULT_INVALID")
    return ReadResult(
        result.outcome,
        result.result_digest,
        private,
        result.page_count,
    )


def capture_inventory_once(
    *,
    plan: Mapping[str, Any],
    provider: Provider,
    expected_plan_digest: str,
    expected_account_id: str,
    expected_region: str,
    capture_index: int,
    captured_at: datetime,
    owner_checkpoint_digest: str,
    live_request_digest: str,
) -> dict[str, Any]:
    """Capture one complete private provider snapshot.

    The provider constructor owns the first STS call.  No inventory client may
    be exposed until :meth:`identity` has returned the bound direct session.
    """

    if capture_index not in {1, 2}:
        _fail("CAPTURE_INDEX_INVALID")
    normalized_plan = validate_plan(
        plan,
        expected_plan_digest=expected_plan_digest,
        expected_account_id=expected_account_id,
        expected_region=expected_region,
    )
    mode = _provider_mode(provider)
    identity = _provider_identity(
        provider,
        expected_account_id=expected_account_id,
        expected_region=expected_region,
        observed_at=captured_at,
    )
    operations = inventory_operations(normalized_plan)
    outcomes: list[dict[str, Any]] = []
    target_presence: dict[str, str] = {}
    for operation in operations:
        mapping = operation.as_mapping()
        try:
            result = _read_from_provider(provider, mapping)
        except Gug390Error:
            raise
        except Exception as exc:
            raise Gug390Error("INVENTORY_PROVIDER_CALL_UNCERTAIN") from exc
        if operation.complete_pagination_required and result.page_count < 1:
            _fail("INVENTORY_PAGINATION_INCOMPLETE")
        target_digest = canonical_digest(operation.target_arn)
        outcomes.append(
            {
                "sequence": operation.sequence,
                "service": operation.service,
                "api_action": operation.api_action,
                "target_digest": target_digest,
                "request_digest": operation.request_digest,
                "outcome": result.outcome,
                "result_digest": result.result_digest,
                "page_count": result.page_count,
                "resource_scope": operation.resource_scope,
                "private_result": result.private_result,
            }
        )
        if (
            operation.resource_scope == "TARGET"
            and (operation.service, operation.api_action) in _EXISTENCE_ANCHORS
        ):
            previous = target_presence.get(target_digest)
            if previous is None:
                target_presence[target_digest] = result.outcome
            elif previous != result.outcome:
                _fail("INVENTORY_TARGET_PRESENCE_CONFLICT")

    expected_anchor_targets = {
        canonical_digest(operation.target_arn)
        for operation in operations
        if operation.resource_scope == "TARGET"
        and (operation.service, operation.api_action) in _EXISTENCE_ANCHORS
    }
    if not expected_anchor_targets or set(target_presence) != expected_anchor_targets:
        _fail("INVENTORY_EXISTENCE_ANCHORS_INCOMPLETE")
    prerequisite_facts = [
        {
            "sequence": item["sequence"],
            "service": item["service"],
            "api_action": item["api_action"],
            "target_digest": item["target_digest"],
            "request_digest": item["request_digest"],
            "outcome": item["outcome"],
            "result_digest": item["result_digest"],
        }
        for item in outcomes
        if item["resource_scope"] == "PREREQUISITE"
    ]
    if not prerequisite_facts:
        _fail("INVENTORY_PREREQUISITES_MISSING")

    transcript = _provider_transcript(provider)
    transcript_digest = _require_digest(
        transcript.get("transcript_digest"), "PROVIDER_TRANSCRIPT_INVALID"
    )
    call_count = transcript.get("call_count")
    write_count = transcript.get("write_call_count")
    if (
        type(call_count) is not int
        or call_count < len(outcomes) + 1
        or type(write_count) is not int
        or write_count != 0
    ):
        _fail("PROVIDER_TRANSCRIPT_INVALID")

    facts = [
        {
            key: item[key]
            for key in (
                "sequence",
                "service",
                "api_action",
                "target_digest",
                "request_digest",
                "outcome",
                "result_digest",
                "page_count",
                "resource_scope",
            )
        }
        for item in outcomes
    ]
    now = _utc(captured_at, "CAPTURE_TIME_INVALID")
    snapshot: dict[str, Any] = {
        "record_type": PRIVATE_SNAPSHOT_TYPE,
        "schema_version": 1,
        "issue": ISSUE,
        "capture_index": capture_index,
        "captured_at": _stamp(now),
        "owner_checkpoint_digest": _require_digest(
            owner_checkpoint_digest, "OWNER_CHECKPOINT_DIGEST_INVALID"
        ),
        "live_request_digest": _require_digest(
            live_request_digest, "LIVE_REQUEST_DIGEST_INVALID"
        ),
        "plan_digest": expected_plan_digest,
        "inventory_contract_digest": canonical_digest(
            [operation.as_mapping() for operation in operations]
        ),
        "identity": identity,
        "identity_digest": canonical_digest(identity),
        "operations": outcomes,
        "facts_digest": canonical_digest(facts),
        "target_presence_digest": canonical_digest(target_presence),
        "all_targets_absent": bool(target_presence)
        and set(target_presence.values()) == {"ABSENT"},
        "all_targets_present": bool(target_presence)
        and set(target_presence.values()) == {"PRESENT"},
        "prerequisite_facts_digest": canonical_digest(prerequisite_facts),
        "all_prerequisites_present": all(
            item["outcome"] == "PRESENT" for item in prerequisite_facts
        ),
        "provider_mode": mode,
        "provider_backed": mode == "LIVE",
        "transcript_digest": transcript_digest,
        "provider_call_count": call_count,
        "aws_mutations": 0,
        "read_only": True,
        "complete": True,
        "repository_persisted": False,
        "snapshot_digest": "",
    }
    snapshot["snapshot_digest"] = canonical_digest(
        {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    )
    return snapshot


def validate_private_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    value = _snapshot(snapshot, "PRIVATE_SNAPSHOT_INVALID")
    fields = {
        "record_type",
        "schema_version",
        "issue",
        "capture_index",
        "captured_at",
        "owner_checkpoint_digest",
        "live_request_digest",
        "plan_digest",
        "inventory_contract_digest",
        "identity",
        "identity_digest",
        "operations",
        "facts_digest",
        "target_presence_digest",
        "all_targets_absent",
        "all_targets_present",
        "prerequisite_facts_digest",
        "all_prerequisites_present",
        "provider_mode",
        "provider_backed",
        "transcript_digest",
        "provider_call_count",
        "aws_mutations",
        "read_only",
        "complete",
        "repository_persisted",
        "snapshot_digest",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("record_type") != PRIVATE_SNAPSHOT_TYPE
        or value.get("schema_version") != 1
        or value.get("issue") != ISSUE
        or value.get("capture_index") not in {1, 2}
        or value.get("provider_mode") not in {"LIVE", "SYNTHETIC"}
        or value.get("provider_backed")
        is not (value.get("provider_mode") == "LIVE")
        or value.get("aws_mutations") != 0
        or value.get("read_only") is not True
        or value.get("complete") is not True
        or value.get("repository_persisted") is not False
    ):
        _fail("PRIVATE_SNAPSHOT_INVALID")
    for field in (
        "plan_digest",
        "owner_checkpoint_digest",
        "live_request_digest",
        "inventory_contract_digest",
        "identity_digest",
        "facts_digest",
        "target_presence_digest",
        "prerequisite_facts_digest",
        "transcript_digest",
        "snapshot_digest",
    ):
        _require_digest(value.get(field), "PRIVATE_SNAPSHOT_INVALID")
    _parse_stamp(value.get("captured_at"), "PRIVATE_SNAPSHOT_INVALID")
    identity = value.get("identity")
    if not isinstance(identity, Mapping):
        _fail("PRIVATE_SNAPSHOT_IDENTITY_INVALID")
    account_id = identity.get("account_id")
    region = identity.get("region")
    if (
        not isinstance(account_id, str)
        or _ACCOUNT.fullmatch(account_id) is None
        or region != REGION
    ):
        _fail("PRIVATE_SNAPSHOT_IDENTITY_INVALID")
    checked_identity = _validate_provider_identity(
        identity,
        expected_account_id=account_id,
        expected_region=REGION,
    )
    expected_source = (
        "DIRECT_SSO" if value.get("provider_mode") == "LIVE" else "INJECTED_NON_LIVE"
    )
    if checked_identity.get("source") != expected_source:
        _fail("PRIVATE_SNAPSHOT_IDENTITY_INVALID")
    if value["identity_digest"] != canonical_digest(checked_identity):
        _fail("PRIVATE_SNAPSHOT_IDENTITY_DIGEST_MISMATCH")
    operations = value.get("operations")
    if (
        not isinstance(operations, list)
        or not operations
        or len(operations) > MAX_INVENTORY_OPERATIONS
    ):
        _fail("PRIVATE_SNAPSHOT_OPERATIONS_INVALID")
    facts: list[dict[str, Any]] = []
    target_presence: dict[str, str] = {}
    prerequisite_facts: list[dict[str, Any]] = []
    operation_fields = {
        "sequence",
        "service",
        "api_action",
        "target_digest",
        "request_digest",
        "outcome",
        "result_digest",
        "page_count",
        "resource_scope",
        "private_result",
    }
    for sequence, operation in enumerate(operations, 1):
        if (
            not isinstance(operation, Mapping)
            or set(operation) != operation_fields
            or operation.get("sequence") != sequence
            or (operation.get("service"), operation.get("api_action"))
            not in _READ_ACTIONS
            or operation.get("outcome") not in {"PRESENT", "ABSENT"}
            or operation.get("resource_scope") not in {"TARGET", "PREREQUISITE"}
            or type(operation.get("page_count")) is not int
            or not 1 <= operation["page_count"] <= 50
        ):
            _fail("PRIVATE_SNAPSHOT_OPERATIONS_INVALID")
        for field in ("target_digest", "request_digest", "result_digest"):
            _require_digest(
                operation.get(field), "PRIVATE_SNAPSHOT_OPERATIONS_INVALID"
            )
        facts.append(
            {
                key: operation[key]
                for key in (
                    "sequence",
                    "service",
                    "api_action",
                    "target_digest",
                    "request_digest",
                    "outcome",
                    "result_digest",
                    "page_count",
                    "resource_scope",
                )
            }
        )
        if (
            operation["resource_scope"] == "TARGET"
            and (operation["service"], operation["api_action"])
            in _EXISTENCE_ANCHORS
        ):
            prior = target_presence.get(str(operation["target_digest"]))
            if prior is not None and prior != operation["outcome"]:
                _fail("PRIVATE_SNAPSHOT_TARGET_PRESENCE_CONFLICT")
            target_presence[str(operation["target_digest"])] = str(
                operation["outcome"]
            )
        if operation["resource_scope"] == "PREREQUISITE":
            prerequisite_facts.append(
                {
                    key: operation[key]
                    for key in (
                        "sequence",
                        "service",
                        "api_action",
                        "target_digest",
                        "request_digest",
                        "outcome",
                        "result_digest",
                    )
                }
            )
    if (
        value.get("facts_digest") != canonical_digest(facts)
        or not target_presence
        or value.get("target_presence_digest") != canonical_digest(target_presence)
        or value.get("all_targets_absent")
        is not (set(target_presence.values()) == {"ABSENT"})
        or value.get("all_targets_present")
        is not (set(target_presence.values()) == {"PRESENT"})
        or not prerequisite_facts
        or value.get("prerequisite_facts_digest")
        != canonical_digest(prerequisite_facts)
        or value.get("all_prerequisites_present")
        is not all(item["outcome"] == "PRESENT" for item in prerequisite_facts)
        or type(value.get("provider_call_count")) is not int
        or value["provider_call_count"] < len(operations) + 1
    ):
        _fail("PRIVATE_SNAPSHOT_FACTS_INVALID")
    expected = canonical_digest(
        {key: item for key, item in value.items() if key != "snapshot_digest"}
    )
    if value["snapshot_digest"] != expected:
        _fail("PRIVATE_SNAPSHOT_DIGEST_MISMATCH")
    return value


def _semantic_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    return value


def _semantic_items(value: Any) -> list[Any]:
    if not isinstance(value, list):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    return value


def _semantic_equal(actual: Any, expected: Any) -> None:
    if canonical_json(actual) != canonical_json(expected):
        _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")


def _policy_document(value: Any) -> Mapping[str, Any]:
    """Decode IAM's URL-encoded documents and normalize set-like arrays."""

    if isinstance(value, str):
        try:
            decoded = unquote(value)

            def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for key, item in pairs:
                    if key in result:
                        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
                    result[key] = item
                return result

            value = json.loads(decoded, object_pairs_hook=reject_duplicates)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise Gug390Error("LIVE_INVENTORY_RESPONSE_MALFORMED") from exc
    if not isinstance(value, Mapping):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")

    def normalize(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(key): normalize(child) for key, child in sorted(item.items())}
        if isinstance(item, list):
            children = [normalize(child) for child in item]
            return sorted(children, key=canonical_json)
        return item

    normalized = normalize(value)
    if not isinstance(normalized, Mapping):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    return normalized


def _tag_map(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        items = list(value.items())
    else:
        items = []
        for raw in _semantic_items(value):
            item = _semantic_mapping(raw)
            items.append((item.get("Key"), item.get("Value")))
    result: dict[str, str] = {}
    for key, item in items:
        if not isinstance(key, str) or not isinstance(item, str) or key in result:
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        result[key] = item
    return dict(sorted(result.items()))


def _string_set(value: Any) -> list[str]:
    items = _semantic_items(value)
    if any(not isinstance(item, str) or not item for item in items):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    if len(set(items)) != len(items):
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    return sorted(items)


def _plan_shaped_projection(actual: Any, expected: Any) -> Any:
    """Select the plan-owned stable shape, supplying only explicit defaults."""

    if isinstance(expected, Mapping):
        source = _semantic_mapping(actual)
        result: dict[str, Any] = {}
        for key, expected_item in expected.items():
            if key in source:
                selected = source[key]
            elif expected_item is None:
                selected = None
            elif expected_item == []:
                selected = []
            elif expected_item == {}:
                selected = {}
            else:
                _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
            result[str(key)] = _plan_shaped_projection(selected, expected_item)
        return result
    if isinstance(expected, list):
        selected_items = _semantic_items(actual)
        return [_snapshot(item, "LIVE_INVENTORY_RESPONSE_MALFORMED") for item in selected_items]
    return _snapshot(actual, "LIVE_INVENTORY_RESPONSE_MALFORMED")


def _expected_live_inventory(plan: Mapping[str, Any]) -> dict[str, Any]:
    try:
        expected = service_role_materializer.expected_normalized_inventory(plan)
    except Exception as exc:
        raise Gug390Error("LIVE_INVENTORY_PLAN_INVALID") from exc
    return _snapshot(expected, "LIVE_INVENTORY_PLAN_INVALID")


def _roles_from_plan(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    service_role = plan.get("service_role")
    children = plan.get("child_roles")
    if not isinstance(service_role, Mapping) or not isinstance(children, list):
        _fail("LIVE_INVENTORY_PLAN_INVALID")
    roles: list[Mapping[str, Any]] = [service_role]
    for item in children:
        roles.append(_semantic_mapping(item))
    return roles


def _validate_iam_response(
    plan: Mapping[str, Any],
    expected: Mapping[str, Any],
    operation: InventoryOperation,
    response: Mapping[str, Any],
) -> Mapping[str, Any]:
    action = operation.api_action
    request = operation.request
    policies = _semantic_mapping(expected.get("policies"))
    roles = _semantic_mapping(expected.get("roles"))
    policy_arn = request.get("PolicyArn")
    role_name = request.get("RoleName")
    if isinstance(policy_arn, str):
        policy = _semantic_mapping(policies.get(policy_arn))
        boundary = next(
            (
                item
                for item in plan.get("boundaries", [])
                if isinstance(item, Mapping) and item.get("arn") == policy_arn
            ),
            None,
        )
        if not isinstance(boundary, Mapping):
            _fail("LIVE_INVENTORY_PLAN_INVALID")
    else:
        policy = {}
        boundary = {}
    if isinstance(role_name, str):
        role = next(
            (
                value
                for value in roles.values()
                if isinstance(value, Mapping) and value.get("role_name") == role_name
            ),
            None,
        )
        if not isinstance(role, Mapping):
            _fail("LIVE_INVENTORY_PLAN_INVALID")
    else:
        role = {}

    if action == "GetPolicy":
        actual = _semantic_mapping(response.get("Policy"))
        raw_roles = _roles_from_plan(plan)
        attached_count = sum(
            policy_arn in item.get("attached_policy_arns", []) for item in raw_roles
        )
        boundary_count = sum(
            item.get("permissions_boundary_arn") == policy_arn for item in raw_roles
        )
        projection = {
            "Arn": actual.get("Arn"),
            "PolicyName": actual.get("PolicyName"),
            "Path": actual.get("Path"),
            "DefaultVersionId": actual.get("DefaultVersionId"),
            "AttachmentCount": actual.get("AttachmentCount"),
            "PermissionsBoundaryUsageCount": actual.get(
                "PermissionsBoundaryUsageCount"
            ),
            "IsAttachable": actual.get("IsAttachable"),
            "Description": actual.get("Description"),
        }
        _semantic_equal(
            projection,
            {
                "Arn": policy["arn"],
                "PolicyName": policy["policy_name"],
                "Path": policy["path"],
                "DefaultVersionId": policy["default_version_id"],
                "AttachmentCount": attached_count,
                "PermissionsBoundaryUsageCount": boundary_count,
                "IsAttachable": True,
                "Description": boundary.get("description"),
            },
        )
        return projection
    if action == "GetPolicyVersion":
        actual = _semantic_mapping(response.get("PolicyVersion"))
        projection = {
            "Document": _policy_document(actual.get("Document")),
            "VersionId": actual.get("VersionId"),
            "IsDefaultVersion": actual.get("IsDefaultVersion"),
        }
        _semantic_equal(
            projection,
            {
                "Document": _policy_document(policy["document"]),
                "VersionId": "v1",
                "IsDefaultVersion": True,
            },
        )
        return projection
    if action == "ListPolicyVersions":
        versions = _semantic_items(response.get("Versions"))
        projection = sorted(
            (
                {
                    "VersionId": _semantic_mapping(item).get("VersionId"),
                    "IsDefaultVersion": _semantic_mapping(item).get(
                        "IsDefaultVersion"
                    ),
                }
                for item in versions
            ),
            key=canonical_json,
        )
        if len({item["VersionId"] for item in projection}) != len(projection):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        _semantic_equal(
            projection,
            [
                {
                    "VersionId": version,
                    "IsDefaultVersion": version == "v1",
                }
                for version in policy["versions"]
            ],
        )
        return {"versions": projection}
    if action == "ListEntitiesForPolicy":
        if response.get("PolicyGroups", []) != [] or response.get("PolicyUsers", []) != []:
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
        names: list[str] = []
        for raw in _semantic_items(response.get("PolicyRoles")):
            item = _semantic_mapping(raw)
            name = item.get("RoleName")
            if not isinstance(name, str) or not name or name in names:
                _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
            names.append(name)
        usage = request.get("PolicyUsageFilter")
        if usage == "PermissionsPolicy":
            expected_names = [
                str(item["role_name"])
                for item in _roles_from_plan(plan)
                if policy_arn in item.get("attached_policy_arns", [])
            ]
        elif usage == "PermissionsBoundary":
            expected_names = [
                str(item["role_name"])
                for item in _roles_from_plan(plan)
                if item.get("permissions_boundary_arn") == policy_arn
            ]
        else:
            _fail("LIVE_INVENTORY_PLAN_INVALID")
        _semantic_equal(sorted(names), sorted(expected_names))
        return {"usage": usage, "role_names": sorted(names)}
    if action == "ListPolicyTags":
        tags = _tag_map(response.get("Tags"))
        _semantic_equal(tags, _tag_map(policy["tags"]))
        return {"tags": tags}
    if action == "GetRole":
        actual = _semantic_mapping(response.get("Role"))
        boundary_value = _semantic_mapping(actual.get("PermissionsBoundary"))
        projection = {
            "Arn": actual.get("Arn"),
            "RoleName": actual.get("RoleName"),
            "Path": actual.get("Path"),
            "Description": actual.get("Description"),
            "MaxSessionDuration": actual.get("MaxSessionDuration"),
            "AssumeRolePolicyDocument": _policy_document(
                actual.get("AssumeRolePolicyDocument")
            ),
            "PermissionsBoundary": {
                "PermissionsBoundaryType": boundary_value.get(
                    "PermissionsBoundaryType"
                ),
                "PermissionsBoundaryArn": boundary_value.get(
                    "PermissionsBoundaryArn"
                ),
            },
            "Tags": _tag_map(actual.get("Tags")),
        }
        _semantic_equal(
            projection,
            {
                "Arn": role["arn"],
                "RoleName": role["role_name"],
                "Path": role["path"],
                "Description": role.get("description"),
                "MaxSessionDuration": role["max_session_duration"],
                "AssumeRolePolicyDocument": _policy_document(role["trust_policy"]),
                "PermissionsBoundary": {
                    "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                    "PermissionsBoundaryArn": role["permissions_boundary_arn"],
                },
                "Tags": _tag_map(role["tags"]),
            },
        )
        return projection
    if action == "ListRolePolicies":
        names = _string_set(response.get("PolicyNames"))
        _semantic_equal(names, sorted(role["inline_policy_names"]))
        return {"policy_names": names}
    if action == "ListAttachedRolePolicies":
        attached: list[dict[str, Any]] = []
        for raw in _semantic_items(response.get("AttachedPolicies")):
            item = _semantic_mapping(raw)
            attached.append(
                {"PolicyArn": item.get("PolicyArn"), "PolicyName": item.get("PolicyName")}
            )
        attached.sort(key=canonical_json)
        if len({item["PolicyArn"] for item in attached}) != len(attached):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        expected_attached = sorted(
            (
                {
                    "PolicyArn": arn,
                    "PolicyName": str(arn).rsplit("/", 1)[-1],
                }
                for arn in role["attached_policy_arns"]
            ),
            key=canonical_json,
        )
        _semantic_equal(attached, expected_attached)
        return {"attached_policies": attached}
    if action == "ListRoleTags":
        tags = _tag_map(response.get("Tags"))
        _semantic_equal(tags, _tag_map(role["tags"]))
        return {"tags": tags}
    _fail("LIVE_INVENTORY_ACTION_UNSUPPORTED")


def _lambda_contract(
    plan: Mapping[str, Any], operation: InventoryOperation
) -> Mapping[str, Any]:
    name = operation.request.get("FunctionName")
    resource = operation.request.get("Resource")
    for key in ("broker_function", "ledger_factory_function"):
        contract = plan.get(key)
        if not isinstance(contract, Mapping):
            _fail("LIVE_INVENTORY_PLAN_INVALID")
        if name == contract.get("function_name") or resource == contract.get("arn"):
            return contract
    _fail("LIVE_INVENTORY_PLAN_INVALID")


def _expected_lambda_configuration(
    contract: Mapping[str, Any], *, version: str | None = None
) -> dict[str, Any]:
    expected = _snapshot(
        contract.get("normalized_configuration"), "LIVE_INVENTORY_PLAN_INVALID"
    )
    if not isinstance(expected, dict):
        _fail("LIVE_INVENTORY_PLAN_INVALID")
    if version is not None:
        expected["Version"] = version
        expected["FunctionArn"] = str(contract["arn"])
        if version != "$LATEST":
            expected["FunctionArn"] += f":{version}"
    environment = expected.get("Environment")
    if not isinstance(environment, Mapping):
        _fail("LIVE_INVENTORY_PLAN_INVALID")
    variables = environment.get("Variables")
    if not isinstance(variables, Mapping):
        _fail("LIVE_INVENTORY_PLAN_INVALID")
    expected["Environment"] = {
        "Variables": {
            "redacted": True,
            "value_digest": canonical_digest(variables),
        }
    }
    return expected


def _lambda_configuration_projection(
    value: Any, expected: Mapping[str, Any]
) -> Mapping[str, Any]:
    actual = dict(_semantic_mapping(value))
    if actual.get("DeadLetterConfig") == {}:
        actual["DeadLetterConfig"] = None
    projection = _plan_shaped_projection(actual, expected)
    _semantic_equal(projection, expected)
    return _semantic_mapping(projection)


def _validate_lambda_response(
    plan: Mapping[str, Any],
    operation: InventoryOperation,
    response: Mapping[str, Any],
) -> Mapping[str, Any]:
    action = operation.api_action
    if action == "GetCodeSigningConfig":
        config = _semantic_mapping(response.get("CodeSigningConfig"))
        contracts = [
            _semantic_mapping(plan[key]).get("code_signing_config_contract")
            for key in ("broker_function", "ledger_factory_function")
        ]
        contract = next(
            (
                item
                for item in contracts
                if isinstance(item, Mapping)
                and item.get("arn") == operation.target_arn
            ),
            None,
        )
        if not isinstance(contract, Mapping):
            _fail("LIVE_INVENTORY_PLAN_INVALID")
        allowed = _semantic_mapping(config.get("AllowedPublishers"))
        policies = _semantic_mapping(config.get("CodeSigningPolicies"))
        projection = {
            "CodeSigningConfigArn": config.get("CodeSigningConfigArn"),
            "AllowedPublishers": {
                "SigningProfileVersionArns": sorted(
                    _string_set(allowed.get("SigningProfileVersionArns"))
                )
            },
            "CodeSigningPolicies": {
                "UntrustedArtifactOnDeployment": policies.get(
                    "UntrustedArtifactOnDeployment"
                )
            },
        }
        _semantic_equal(
            projection,
            {
                "CodeSigningConfigArn": contract["arn"],
                "AllowedPublishers": {
                    "SigningProfileVersionArns": sorted(
                        contract["allowed_signing_profile_version_arns"]
                    )
                },
                "CodeSigningPolicies": {
                    "UntrustedArtifactOnDeployment": contract[
                        "untrusted_artifact_on_deployment"
                    ]
                },
            },
        )
        return projection

    contract = _lambda_contract(plan, operation)
    expected_config = _expected_lambda_configuration(contract)
    if action == "GetFunction":
        configuration = _lambda_configuration_projection(
            response.get("Configuration"), expected_config
        )
        code = _semantic_mapping(response.get("Code"))
        if code.get("RepositoryType") != "S3":
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
        resolved = code.get("ResolvedS3Object")
        if resolved is not None:
            signed = _semantic_mapping(contract.get("signed_code"))
            _semantic_equal(
                _semantic_mapping(resolved),
                {
                    "Bucket": signed["s3_bucket"],
                    "Key": signed["s3_key"],
                    "Version": signed["s3_object_version"],
                },
            )
        tags = _tag_map(response.get("Tags"))
        _semantic_equal(tags, _tag_map(contract["tags"]))
        return {"configuration": configuration, "repository_type": "S3", "tags": tags}
    if action == "GetFunctionConfiguration":
        return _lambda_configuration_projection(response, expected_config)
    if action == "GetFunctionCodeSigningConfig":
        projection = {"CodeSigningConfigArn": response.get("CodeSigningConfigArn")}
        _semantic_equal(
            projection, {"CodeSigningConfigArn": contract["code_signing_config_arn"]}
        )
        return projection
    if action == "GetFunctionConcurrency":
        projection = {
            "ReservedConcurrentExecutions": response.get(
                "ReservedConcurrentExecutions"
            )
        }
        _semantic_equal(
            projection,
            {
                "ReservedConcurrentExecutions": contract[
                    "reserved_concurrent_executions"
                ]
            },
        )
        return projection
    if action == "GetRuntimeManagementConfig":
        runtime = _semantic_mapping(contract.get("runtime_management"))
        projection = {
            key: response.get(key)
            for key in ("UpdateRuntimeOn", "RuntimeVersionArn", "FunctionArn")
            if key in response or key != "FunctionArn"
        }
        expected_runtime = {
            "UpdateRuntimeOn": runtime["UpdateRuntimeOn"],
            "RuntimeVersionArn": runtime["RuntimeVersionArn"],
        }
        if "FunctionArn" in projection:
            expected_runtime["FunctionArn"] = operation.target_arn
        _semantic_equal(projection, expected_runtime)
        return projection
    if action == "ListTags":
        tags = _tag_map(response.get("Tags"))
        _semantic_equal(tags, _tag_map(contract["tags"]))
        return {"tags": tags}
    if action == "ListVersionsByFunction":
        versions = _semantic_items(response.get("Versions"))
        by_version: dict[str, Mapping[str, Any]] = {}
        for raw in versions:
            item = _semantic_mapping(raw)
            version = item.get("Version")
            if not isinstance(version, str) or not version or version in by_version:
                _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
            by_version[version] = _lambda_configuration_projection(
                item, _expected_lambda_configuration(contract, version=version)
            )
        _semantic_equal(sorted(by_version), sorted(contract["expected_versions"]))
        return {"versions": {key: by_version[key] for key in sorted(by_version)}}
    if action == "ListAliases":
        aliases = sorted(
            (
                _snapshot(item, "LIVE_INVENTORY_RESPONSE_MALFORMED")
                for item in _semantic_items(response.get("Aliases"))
            ),
            key=canonical_json,
        )
        _semantic_equal(aliases, sorted(contract["expected_aliases"], key=canonical_json))
        return {"aliases": aliases}
    if action == "ListFunctionUrlConfigs":
        configs = sorted(
            (
                _snapshot(item, "LIVE_INVENTORY_RESPONSE_MALFORMED")
                for item in _semantic_items(response.get("FunctionUrlConfigs"))
            ),
            key=canonical_json,
        )
        _semantic_equal(
            configs, sorted(contract["expected_function_urls"], key=canonical_json)
        )
        return {"function_urls": configs}
    if action == "GetPolicy":
        # Both functions have an explicit no-resource-policy contract.
        _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
    _fail("LIVE_INVENTORY_ACTION_UNSUPPORTED")


def _validate_logs_response(
    plan: Mapping[str, Any], operation: InventoryOperation, response: Mapping[str, Any]
) -> Mapping[str, Any]:
    contract = _semantic_mapping(plan.get("ledger_factory_log_group"))
    if operation.api_action == "DescribeLogGroups":
        exact = [
            _semantic_mapping(item)
            for item in _semantic_items(response.get("logGroups"))
            if isinstance(item, Mapping)
            and item.get("logGroupName") == contract.get("log_group_name")
        ]
        if len(exact) != 1:
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
        group = exact[0]
        projection = {
            "logGroupName": group.get("logGroupName"),
            "arn": group.get("arn"),
            "logGroupArn": group.get("logGroupArn"),
            "retentionInDays": group.get("retentionInDays"),
            "deletionProtectionEnabled": group.get("deletionProtectionEnabled"),
            "kmsKeyId": group.get("kmsKeyId"),
            "logGroupClass": group.get("logGroupClass", "STANDARD"),
            "dataProtectionStatus": group.get("dataProtectionStatus"),
            "inheritedProperties": group.get("inheritedProperties", []),
        }
        _semantic_equal(
            projection,
            {
                "logGroupName": contract["log_group_name"],
                "arn": str(contract["arn"]) + ":*",
                "logGroupArn": contract["arn"],
                "retentionInDays": contract["retention_in_days"],
                "deletionProtectionEnabled": contract[
                    "deletion_protection_enabled"
                ],
                "kmsKeyId": contract["kms_key_id"],
                "logGroupClass": contract["log_group_class"],
                "dataProtectionStatus": contract["data_protection_policy"],
                "inheritedProperties": contract["inherited_properties"],
            },
        )
        return projection
    if operation.api_action == "ListTagsForResource":
        tags = _tag_map(response.get("tags"))
        _semantic_equal(tags, _tag_map(contract["tags"]))
        return {"tags": tags}
    _fail("LIVE_INVENTORY_ACTION_UNSUPPORTED")


def _validate_dynamodb_response(
    plan: Mapping[str, Any], operation: InventoryOperation, response: Mapping[str, Any]
) -> Mapping[str, Any]:
    contract = _semantic_mapping(plan.get("ledger_table"))
    action = operation.api_action
    if action == "DescribeTable":
        table = _semantic_mapping(response.get("Table"))
        billing = _semantic_mapping(table.get("BillingModeSummary"))
        sse = _semantic_mapping(table.get("SSEDescription"))
        table_class = table.get("TableClassSummary", {})
        if not isinstance(table_class, Mapping):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        projection = {
            "TableName": table.get("TableName"),
            "TableArn": table.get("TableArn"),
            "TableStatus": table.get("TableStatus"),
            "BillingMode": billing.get("BillingMode"),
            "AttributeDefinitions": table.get("AttributeDefinitions"),
            "KeySchema": table.get("KeySchema"),
            "DeletionProtectionEnabled": table.get("DeletionProtectionEnabled"),
            "SSEStatus": sse.get("Status"),
            "SSEType": sse.get("SSEType"),
            "SSEKMSMasterKeyArn": sse.get("KMSMasterKeyArn"),
            "TableClass": table_class.get("TableClass", "STANDARD"),
            "LatestStreamLabel": table.get("LatestStreamLabel"),
            "GlobalSecondaryIndexes": table.get("GlobalSecondaryIndexes", []),
            "LocalSecondaryIndexes": table.get("LocalSecondaryIndexes", []),
            "Replicas": table.get("Replicas", []),
            "ItemCount": table.get("ItemCount"),
        }
        expected_projection = {
            "TableName": contract["table_name"],
            "TableArn": contract["arn"],
            "TableStatus": "ACTIVE",
            "BillingMode": contract["billing_mode"],
            "AttributeDefinitions": contract["attribute_definitions"],
            "KeySchema": contract["key_schema"],
            "DeletionProtectionEnabled": contract[
                "deletion_protection_enabled"
            ],
            "SSEStatus": "ENABLED",
            "SSEType": contract["sse_specification"]["SSEType"],
            "SSEKMSMasterKeyArn": projection["SSEKMSMasterKeyArn"],
            "TableClass": contract["table_class"],
            "LatestStreamLabel": contract["latest_stream_label"],
            "GlobalSecondaryIndexes": contract["global_secondary_indexes"],
            "LocalSecondaryIndexes": contract["local_secondary_indexes"],
            "Replicas": contract["replicas"],
            "ItemCount": 0,
        }
        if not isinstance(projection["SSEKMSMasterKeyArn"], str):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        _semantic_equal(projection, expected_projection)
        return projection
    if action == "DescribeContinuousBackups":
        description = _semantic_mapping(response.get("ContinuousBackupsDescription"))
        pitr = _semantic_mapping(description.get("PointInTimeRecoveryDescription"))
        projection = {
            "ContinuousBackupsStatus": description.get("ContinuousBackupsStatus"),
            "PointInTimeRecoveryEnabled": pitr.get("PointInTimeRecoveryStatus")
            == "ENABLED",
            "RecoveryPeriodInDays": pitr.get("RecoveryPeriodInDays"),
        }
        _semantic_equal(
            projection,
            {
                "ContinuousBackupsStatus": "ENABLED",
                **contract["point_in_time_recovery"],
            },
        )
        return projection
    if action == "DescribeTimeToLive":
        ttl = _semantic_mapping(response.get("TimeToLiveDescription"))
        projection = {
            "TimeToLiveStatus": ttl.get("TimeToLiveStatus"),
            "AttributeName": ttl.get("AttributeName"),
        }
        _semantic_equal(projection, contract["time_to_live"])
        return projection
    if action == "GetResourcePolicy":
        projection = {"Policy": _policy_document(response.get("Policy"))}
        _semantic_equal(
            projection, {"Policy": _policy_document(contract["resource_policy"])}
        )
        return projection
    if action == "ListTagsOfResource":
        tags = _tag_map(response.get("Tags"))
        _semantic_equal(tags, _tag_map(contract["tags"]))
        return {"tags": tags}
    if action == "Scan":
        projection = {
            "Count": response.get("Count"),
            "ScannedCount": response.get("ScannedCount"),
            "LastEvaluatedKey": response.get("LastEvaluatedKey"),
        }
        _semantic_equal(
            projection,
            {"Count": 0, "ScannedCount": 0, "LastEvaluatedKey": None},
        )
        return projection
    _fail("LIVE_INVENTORY_ACTION_UNSUPPORTED")


def _artifact_contract(
    plan: Mapping[str, Any], operation: InventoryOperation
) -> Mapping[str, Any]:
    for key in ("broker_function", "ledger_factory_function"):
        function = _semantic_mapping(plan.get(key))
        signed = _semantic_mapping(function.get("signed_code"))
        if (
            operation.request.get("Bucket") == signed.get("s3_bucket")
            and operation.request.get("Key") == signed.get("s3_key")
            and operation.request.get("VersionId") == signed.get("s3_object_version")
        ):
            result = dict(signed)
            result["sse_kms_key_arn"] = (
                plan.get("signed_artifact_binding", {}).get("sse_kms_key_arn")
                if key == "broker_function"
                else function.get("artifact_sse_kms_key_arn")
            )
            return result
    _fail("LIVE_INVENTORY_PLAN_INVALID")


def _validate_s3_response(
    plan: Mapping[str, Any], operation: InventoryOperation, response: Mapping[str, Any]
) -> Mapping[str, Any]:
    contract = _artifact_contract(plan, operation)
    body = _semantic_mapping(response.get("Body"))
    projection = {
        "VersionId": response.get("VersionId"),
        "ContentLength": response.get("ContentLength"),
        "ChecksumSHA256": response.get("ChecksumSHA256"),
        "ChecksumType": response.get("ChecksumType"),
        "ServerSideEncryption": response.get("ServerSideEncryption"),
        "SSEKMSKeyId": response.get("SSEKMSKeyId"),
        "DeleteMarker": response.get("DeleteMarker", False),
        "ContentRange": response.get("ContentRange"),
        "Body": {
            "byte_length": body.get("byte_length"),
            "byte_digest": body.get("byte_digest"),
        },
    }
    expected = {
        "VersionId": contract["s3_object_version"],
        "ContentLength": contract["archive_size_bytes"],
        "ChecksumSHA256": response.get("ChecksumSHA256"),
        "ChecksumType": response.get("ChecksumType"),
        "ServerSideEncryption": "aws:kms",
        "SSEKMSKeyId": contract["sse_kms_key_arn"],
        "DeleteMarker": False,
        "ContentRange": None,
        "Body": {
            "byte_length": contract["archive_size_bytes"],
            "byte_digest": "sha256:" + str(contract["archive_sha256"]),
        },
    }
    checksum = projection["ChecksumSHA256"]
    checksum_type = projection["ChecksumType"]
    if checksum is not None and checksum_type != "COMPOSITE":
        if not isinstance(checksum, str):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        try:
            decoded_checksum = base64.b64decode(checksum, validate=True)
        except (ValueError, TypeError) as exc:
            raise Gug390Error("LIVE_INVENTORY_RESPONSE_MALFORMED") from exc
        if len(decoded_checksum) != 32 or checksum_type not in {None, "FULL_OBJECT"}:
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        if checksum != contract["lambda_code_sha256"]:
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
    elif checksum_type == "COMPOSITE":
        if (
            not isinstance(checksum, str)
            or not checksum.strip()
            or len(checksum.encode("utf-8")) > 1024
        ):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    elif checksum_type is not None:
        _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
    _semantic_equal(projection, expected)
    return projection


def _validate_kms_response(
    plan: Mapping[str, Any], operation: InventoryOperation, response: Mapping[str, Any]
) -> Mapping[str, Any]:
    metadata = _semantic_mapping(response.get("KeyMetadata"))
    key_id = operation.request.get("KeyId")
    account_id = plan.get("target", {}).get("authority_account_id")
    projection = {
        "AWSAccountId": metadata.get("AWSAccountId"),
        "KeyId": metadata.get("KeyId"),
        "Arn": metadata.get("Arn"),
        "Enabled": metadata.get("Enabled"),
        "KeyUsage": metadata.get("KeyUsage"),
        "KeyState": metadata.get("KeyState"),
        "Origin": metadata.get("Origin"),
        "KeyManager": metadata.get("KeyManager"),
        "KeySpec": metadata.get("KeySpec"),
        "MultiRegion": metadata.get("MultiRegion"),
        "EncryptionAlgorithms": metadata.get("EncryptionAlgorithms"),
    }
    table = _semantic_mapping(plan.get("ledger_table"))
    table_alias = table.get("sse_specification", {}).get("KMSMasterKeyId")
    if key_id == table_alias:
        contract = _semantic_mapping(table.get("kms_key_contract"))
        expected_metadata = dict(_semantic_mapping(contract.get("metadata_projection")))
        arn_pattern = expected_metadata.pop("arn_pattern", None)
        if not isinstance(arn_pattern, str):
            _fail("LIVE_INVENTORY_PLAN_INVALID")
        arn_regex = re.escape(arn_pattern).replace(
            re.escape("<AWS_MANAGED_UUID>"), r"[0-9a-f-]{36}"
        )
        if not isinstance(projection["Arn"], str) or re.fullmatch(
            arn_regex, projection["Arn"]
        ) is None:
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
        expected_projection = {
            **expected_metadata,
            "KeyId": str(projection["Arn"]).rsplit("/", 1)[-1],
            "Arn": projection["Arn"],
        }
    else:
        if (
            projection["Origin"]
            not in {"AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"}
            or projection["KeyManager"] not in {"AWS", "CUSTOMER"}
            or projection["KeySpec"] != "SYMMETRIC_DEFAULT"
            or type(projection["MultiRegion"]) is not bool
            or projection["EncryptionAlgorithms"] != ["SYMMETRIC_DEFAULT"]
        ):
            _fail("LIVE_INVENTORY_RESPONSE_MALFORMED")
        expected_projection = {
            "AWSAccountId": account_id,
            "KeyId": str(key_id).rsplit("/", 1)[-1],
            "Arn": key_id,
            "Enabled": True,
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": projection["Origin"],
            "KeyManager": projection["KeyManager"],
            "KeySpec": "SYMMETRIC_DEFAULT",
            "MultiRegion": projection["MultiRegion"],
            "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
        }
    _semantic_equal(projection, expected_projection)
    return projection


def _live_private_response(
    snapshot_operation: Mapping[str, Any], expected_operation: InventoryOperation
) -> Mapping[str, Any] | None:
    private = _semantic_mapping(snapshot_operation.get("private_result"))
    outcome = snapshot_operation.get("outcome")
    provider_outcome = private.get("outcome")
    operation_calls = private.get("operation_calls")
    provider_calls = private.get("provider_calls")
    try:
        from tooling import platform_authority_gug365_live_provider as live_provider

        operation_digest = live_provider.planned_call_from_record(
            "READBACK", expected_operation.as_mapping()
        ).operation_digest
    except Exception as exc:
        raise Gug390Error("LIVE_INVENTORY_EVIDENCE_INVALID") from exc
    if (
        private.get("phase") != "READBACK"
        or private.get("sequence") != expected_operation.sequence
        or private.get("operation_digest") != operation_digest
        or private.get("request_digest") != expected_operation.request_digest
        or type(operation_calls) is not int
        or operation_calls != snapshot_operation.get("page_count")
        or type(provider_calls) is not int
        or provider_calls < operation_calls
        or private.get("reconciliation_required") is not False
    ):
        _fail("LIVE_INVENTORY_EVIDENCE_INVALID")
    response = private.get("response")
    response_digest = (
        canonical_digest(response) if isinstance(response, Mapping) else None
    )
    if outcome == "PRESENT":
        response = _semantic_mapping(response)
        if (
            provider_outcome != "SUCCEEDED"
            or private.get("error_code") is not None
            or private.get("response_digest") != response_digest
            or snapshot_operation.get("result_digest") != response_digest
        ):
            _fail("LIVE_INVENTORY_EVIDENCE_INVALID")
        return response
    if (
        (expected_operation.service, expected_operation.api_action)
        == ("logs", "DescribeLogGroups")
        and provider_outcome == "SUCCEEDED"
    ):
        response = _semantic_mapping(response)
        if (
            private.get("error_code") is not None
            or private.get("response_digest") != response_digest
            or snapshot_operation.get("result_digest") != response_digest
            or _successful_read_presence(expected_operation.as_mapping(), response)
            != "ABSENT"
        ):
            _fail("LIVE_INVENTORY_EVIDENCE_INVALID")
        return None
    error = private.get("error_code")
    accepted_errors = {
        "iam": {"NoSuchEntity", "NoSuchEntityException"},
        "lambda": {"ResourceNotFoundException"},
        "logs": {"ResourceNotFound", "ResourceNotFoundException"},
        "dynamodb": {"ResourceNotFoundException"},
        "s3": {"NoSuchKey", "NoSuchKeyException"},
        "kms": {"NotFoundException"},
    }.get(expected_operation.service, set())
    expected_absence_response: Mapping[str, Any] = (
        {"partial_facts": {}}
        if expected_operation.complete_pagination_required
        else {}
    )
    if (
        provider_outcome != "FAILED"
        or error not in accepted_errors
        or private.get("response") != expected_absence_response
        or private.get("response_digest")
        != canonical_digest(expected_absence_response)
        or snapshot_operation.get("result_digest")
        != canonical_digest(
            {
                "absence": error,
                "request_digest": expected_operation.request_digest,
                "target_digest": canonical_digest(expected_operation.target_arn),
            }
        )
    ):
        _fail("LIVE_INVENTORY_EVIDENCE_INVALID")
    return None


def _validate_live_operation_response(
    plan: Mapping[str, Any],
    expected_inventory: Mapping[str, Any],
    operation: InventoryOperation,
    response: Mapping[str, Any],
) -> Mapping[str, Any]:
    if operation.service == "iam":
        return _validate_iam_response(plan, expected_inventory, operation, response)
    if operation.service == "lambda":
        return _validate_lambda_response(plan, operation, response)
    if operation.service == "logs":
        return _validate_logs_response(plan, operation, response)
    if operation.service == "dynamodb":
        return _validate_dynamodb_response(plan, operation, response)
    if operation.service == "s3":
        return _validate_s3_response(plan, operation, response)
    if operation.service == "kms":
        return _validate_kms_response(plan, operation, response)
    _fail("LIVE_INVENTORY_ACTION_UNSUPPORTED")


def _validate_live_inventory_semantics(
    plan: Mapping[str, Any],
    expected_operations: Sequence[InventoryOperation],
    snapshot: Mapping[str, Any],
) -> str:
    """Bind private LIVE responses to the exact repository plan projection."""

    expected_inventory = _expected_live_inventory(plan)
    projections: list[dict[str, Any]] = []
    table_kms_arn: str | None = None
    described_kms: dict[str, str] = {}
    for operation, snapshot_operation in zip(
        expected_operations, snapshot["operations"], strict=True
    ):
        response = _live_private_response(snapshot_operation, operation)
        outcome = str(snapshot_operation["outcome"])
        pair = (operation.service, operation.api_action)
        expected_absence = pair == ("lambda", "GetPolicy")
        if snapshot["all_targets_absent"] is True and operation.resource_scope == "TARGET":
            expected_absence = True
        elif (
            snapshot["all_targets_present"] is True
            and operation.resource_scope == "TARGET"
            and pair != ("lambda", "GetPolicy")
        ):
            expected_absence = False
        if expected_absence is not (outcome == "ABSENT"):
            _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
        if response is None:
            projection: Mapping[str, Any] = {"outcome": "ABSENT"}
        else:
            projection = _validate_live_operation_response(
                plan, expected_inventory, operation, response
            )
        if pair == ("dynamodb", "DescribeTable") and response is not None:
            table_kms_arn = str(projection["SSEKMSMasterKeyArn"])
        if pair == ("kms", "DescribeKey") and response is not None:
            described_kms[str(operation.request["KeyId"])] = str(projection["Arn"])
        projections.append(
            {
                "sequence": operation.sequence,
                "service": operation.service,
                "api_action": operation.api_action,
                "target_digest": canonical_digest(operation.target_arn),
                "outcome": outcome,
                "projection": projection,
            }
        )
    table_alias = str(
        plan.get("ledger_table", {}).get("sse_specification", {}).get(
            "KMSMasterKeyId", ""
        )
    )
    if table_kms_arn is not None and described_kms.get(table_alias) != table_kms_arn:
        _fail("LIVE_INVENTORY_SEMANTIC_DRIFT")
    return canonical_digest(projections)


def classify_stable_inventory(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    expected_facts_digest: str | None,
    authorized_before_state_digest: str,
    expected_snapshot_digests: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Classify two complete captures without authorizing adoption or repair."""

    left = validate_private_snapshot(first)
    right = validate_private_snapshot(second)
    left_time = _parse_stamp(left["captured_at"], "PRIVATE_SNAPSHOT_TIME_INVALID")
    right_time = _parse_stamp(right["captured_at"], "PRIVATE_SNAPSHOT_TIME_INVALID")
    expected = _require_digest(expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID")
    target = plan.get("target") if isinstance(plan, Mapping) else None
    normalized_plan = validate_plan(
        plan,
        expected_plan_digest=expected,
        expected_account_id=(
            str(target.get("authority_account_id"))
            if isinstance(target, Mapping)
            else ""
        ),
        expected_region=(str(target.get("region")) if isinstance(target, Mapping) else ""),
    )
    expected_operations = inventory_operations(normalized_plan)
    expected_contract_digest = canonical_digest(
        [operation.as_mapping() for operation in expected_operations]
    )
    expected_operation_bindings = [
        {
            "sequence": operation.sequence,
            "service": operation.service,
            "api_action": operation.api_action,
            "target_digest": canonical_digest(operation.target_arn),
            "request_digest": operation.request_digest,
            "resource_scope": operation.resource_scope,
        }
        for operation in expected_operations
    ]
    for snapshot in (left, right):
        actual_bindings = [
            {
                key: item[key]
                for key in (
                    "sequence",
                    "service",
                    "api_action",
                    "target_digest",
                    "request_digest",
                    "resource_scope",
                )
            }
            for item in snapshot["operations"]
        ]
        if (
            snapshot["inventory_contract_digest"] != expected_contract_digest
            or actual_bindings != expected_operation_bindings
        ):
            _fail("INVENTORY_CONTRACT_BINDING_MISMATCH")
    semantic_digests: list[str] = []
    if left["provider_mode"] == "LIVE" or right["provider_mode"] == "LIVE":
        if left["provider_mode"] != "LIVE" or right["provider_mode"] != "LIVE":
            _fail("INVENTORY_NOT_STABLE")
        semantic_digests = [
            _validate_live_inventory_semantics(
                normalized_plan, expected_operations, snapshot
            )
            for snapshot in (left, right)
        ]
        if semantic_digests[0] != semantic_digests[1]:
            _fail("INVENTORY_NOT_STABLE")
    if (
        left["capture_index"] != 1
        or right["capture_index"] != 2
        or left["plan_digest"] != expected
        or right["plan_digest"] != expected
        or left["owner_checkpoint_digest"]
        != right["owner_checkpoint_digest"]
        or left["live_request_digest"] != right["live_request_digest"]
        or left["inventory_contract_digest"] != right["inventory_contract_digest"]
        or left["provider_mode"] != right["provider_mode"]
        or (
            not semantic_digests
            and left["facts_digest"] != right["facts_digest"]
        )
        or left["target_presence_digest"] != right["target_presence_digest"]
        or (
            not semantic_digests
            and left["prerequisite_facts_digest"]
            != right["prerequisite_facts_digest"]
        )
        or not left_time < right_time
    ):
        _fail("INVENTORY_NOT_STABLE")
    if left["snapshot_digest"] == right["snapshot_digest"]:
        # Capture index, time and STS evidence make the private records unique.
        _fail("INVENTORY_SNAPSHOT_REPLAY")
    if expected_snapshot_digests is not None:
        expected_snapshots = [
            _require_digest(item, "EXPECTED_SNAPSHOT_DIGEST_INVALID")
            for item in expected_snapshot_digests
        ]
        if expected_snapshots != [
            left["snapshot_digest"],
            right["snapshot_digest"],
        ]:
            _fail("SNAPSHOT_DIGEST_BINDING_MISMATCH")
    before_state = _require_digest(
        authorized_before_state_digest,
        "AUTHORIZED_BEFORE_STATE_DIGEST_INVALID",
    )
    if expected_facts_digest is not None:
        expected_facts = _require_digest(
            expected_facts_digest, "EXPECTED_INVENTORY_FACTS_DIGEST_INVALID"
        )
    else:
        expected_facts = None
    facts = str(right["facts_digest"])
    facts_accepted = expected_facts is not None and facts == expected_facts
    prerequisites_ready = right["all_prerequisites_present"] is True
    if (
        right["all_targets_absent"] is True
        and facts_accepted
        and prerequisites_ready
    ):
        classification = "ABSENT_READY"
        writes_permitted_by_state = True
    elif right["all_targets_absent"] is True:
        classification = "ABSENT_REVIEW_REQUIRED"
        writes_permitted_by_state = False
    elif (
        right["all_targets_present"] is True
        and facts_accepted
        and prerequisites_ready
    ):
        classification = "EXACT_PRESENT_NO_TOUCH"
        writes_permitted_by_state = False
    else:
        classification = "PREEXISTING_NO_TOUCH"
        writes_permitted_by_state = False
    return {
        "classification": classification,
        "stable": True,
        "provider_backed": right["provider_backed"],
        "owner_checkpoint_digest": right["owner_checkpoint_digest"],
        "live_request_digest": right["live_request_digest"],
        "facts_digest": facts,
        "authorized_before_state_digest": before_state,
        "snapshot_digests": [left["snapshot_digest"], right["snapshot_digest"]],
        "captured_at": [left["captured_at"], right["captured_at"]],
        "identity_digests": [left["identity_digest"], right["identity_digest"]],
        "transcript_digests": [
            left["transcript_digest"],
            right["transcript_digest"],
        ],
        "provider_calls": left["provider_call_count"]
        + right["provider_call_count"],
        "writes_permitted_by_state": writes_permitted_by_state,
        "facts_accepted": facts_accepted,
        "prerequisites_ready": prerequisites_ready,
        "writes_authorized": False,
        "adoption_permitted": False,
        "repair_permitted": False,
        "delete_permitted": False,
    }


def execute_one_phase(
    *,
    store: phase_ledger.DurablePhaseLedgerStore,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    ledger_id: str,
    execution_authorization: Mapping[str, Any],
    executor_authority_evidence: Mapping[str, Any],
    authority_evaluation_at: datetime,
    expected_initial_bundle_absence_digest: str | None,
    predecessor_record: Mapping[str, Any] | None,
    expected_predecessor_binding: Mapping[str, Any] | None,
    provider: Provider | None,
    clock: Callable[[], datetime],
    inventory_classification: Mapping[str, Any],
    claim_nonce_digest: str,
    activator_checkpoint: Mapping[str, Any] | None = None,
    expected_activator_checkpoint_digest: str | None = None,
    require_live_provider: bool = True,
    owner_checkpoint_digest: str | None = None,
    live_request_digest: str | None = None,
) -> dict[str, Any]:
    """Claim and execute exactly one already-prepared forward phase."""

    current = store.read(ledger_id)
    phase = current.get("phase")
    if phase not in FORWARD_PHASES:
        _fail("FORWARD_PHASE_REQUIRED")
    status = current.get("status")
    if type(require_live_provider) is not bool:
        _fail("PROVIDER_MODE_GATE_INVALID")
    expected_provider_mode = "LIVE" if require_live_provider else "SYNTHETIC"
    if phase == "ACTIVATOR":
        if status == "PREPARED":
            activator_digest = _validate_activator_checkpoint(
                activator_checkpoint,
                expected_digest=expected_activator_checkpoint_digest,
                at=clock(),
            )
        else:
            activator_digest = _require_digest(
                expected_activator_checkpoint_digest,
                "EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
            )
    elif (
        activator_checkpoint is not None
        or expected_activator_checkpoint_digest is not None
    ):
        _fail("ACTIVATOR_CHECKPOINT_UNEXPECTED")
    else:
        activator_digest = None
    if (owner_checkpoint_digest is None) is not (live_request_digest is None):
        _fail("EXECUTION_CONTEXT_INCOMPLETE")
    context = (
        _execution_context(
            owner_checkpoint_digest=str(owner_checkpoint_digest),
            live_request_digest=str(live_request_digest),
            activator_checkpoint_digest=activator_digest,
        )
        if owner_checkpoint_digest is not None
        else None
    )
    if status == "PREPARED":
        if require_live_provider and context is None:
            _fail("EXECUTION_CONTEXT_REQUIRED")
    else:
        stored_context = _claim_execution_context(current)
        if stored_context is not None:
            if context is None:
                _fail("EXECUTION_CONTEXT_REQUIRED")
            _claim_execution_context(current, expected=context, required=True)
            context = stored_context
        elif context is not None:
            _fail("EXECUTION_CONTEXT_MISSING")
        elif require_live_provider:
            _fail("EXECUTION_CONTEXT_REQUIRED")
    if status in {"CONSUMED", "AMBIGUOUS"}:
        terminal_run = _private_phase_run_from_terminal_evidence(
            current,
            plan=plan,
            expected_plan_digest=expected_plan_digest,
            private_evidence_root=store.root,
            require_private_evidence=True,
        )
        if terminal_run.get("provider_mode") != expected_provider_mode:
            _fail(
                "LIVE_PROVIDER_REQUIRED"
                if require_live_provider
                else "SYNTHETIC_PROVIDER_REQUIRED"
            )
        return terminal_run
    if status == "IN_FLIGHT":
        recovery_at = _utc(clock(), "RUNNER_TIME_INVALID")
        recovery_evidence: Mapping[str, Any] | None = None
        in_flight = current.get("in_flight_operation")
        sequence = (
            in_flight.get("operation_sequence")
            if isinstance(in_flight, Mapping)
            else None
        )
        if type(sequence) is not int:
            _fail("IN_FLIGHT_OPERATION_INVALID")
        evidence_name = _provider_evidence_file(ledger_id, sequence)
        staged = _read_private_custody_record(
            store.root, evidence_name, missing_ok=True
        )
        if staged is not None:
            private_record, _actual_evidence = (
                _validate_private_provider_evidence_record(
                    staged,
                    name=evidence_name,
                    ledger_record=current,
                    plan=plan,
                )
            )
            recovery_evidence = _seal_linked_provider_evidence(
                private_record["durable_provider_evidence_body"],
                private_evidence_file=evidence_name,
                private_evidence_digest=str(private_record["evidence_digest"]),
                outcome="AMBIGUOUS",
                provider_result_digest=None,
            )
            try:
                phase_ledger.validate_durable_provider_evidence(
                    recovery_evidence,
                    record=current,
                    operation_sequence=sequence,
                    outcome="AMBIGUOUS",
                    provider_result_digest=None,
                )
            except Exception as exc:
                raise Gug390Error(
                    "PRIVATE_PROVIDER_RECOVERY_EVIDENCE_INVALID"
                ) from exc
        recovered = phase_ledger.recover_persisted_in_flight(
            store=store,
            ledger_id=ledger_id,
            at=recovery_at,
            durable_provider_evidence=recovery_evidence,
        )
        return _private_phase_run_from_terminal_evidence(
            recovered,
            plan=plan,
            expected_plan_digest=expected_plan_digest,
            private_evidence_root=store.root,
            require_private_evidence=recovery_evidence is not None,
        )
    if status not in {"PREPARED", "CLAIMED"}:
        _fail("LEDGER_NOT_EXECUTABLE")
    if provider is None:
        _fail("PROVIDER_REQUIRED")
    provider_mode = _provider_mode(provider)
    if provider_mode != expected_provider_mode:
        _fail(
            "LIVE_PROVIDER_REQUIRED"
            if require_live_provider
            else "SYNTHETIC_PROVIDER_REQUIRED"
        )
    _validate_inventory_gate(
        current,
        inventory_classification,
        require_live_provider=require_live_provider,
    )
    identity = _provider_identity(
        provider,
        expected_account_id=str(current.get("account_id")),
        expected_region=str(current.get("region")),
        observed_at=clock(),
    )
    if (
        identity["caller_arn_digest"] != current.get("caller_arn_digest")
        or identity["session_identifier_digest"]
        != current.get("authority_session_identifier_digest")
    ):
        _fail("PHASE_PROVIDER_SESSION_MISMATCH")
    if status == "PREPARED":
        claim = phase_ledger.prepare_claim(
            current,
            expected_version=current["ledger_version"],
            expected_digest=current["ledger_digest"],
            at=_utc(clock(), "RUNNER_TIME_INVALID"),
            claim_nonce_digest=_require_digest(
                claim_nonce_digest, "CLAIM_NONCE_DIGEST_INVALID"
            ),
            profile_class=str(current["profile_class"]),
            caller_arn_digest=str(current["caller_arn_digest"]),
            executor_authority_evidence_digest=str(
                current["executor_authority_evidence_digest"]
            ),
            host_digest=str(current["host_digest"]),
            execution_authorization=execution_authorization,
            plan=plan,
            expected_plan_digest=expected_plan_digest,
            executor_authority_evidence=executor_authority_evidence,
            authority_evaluation_at=authority_evaluation_at,
            expected_initial_bundle_absence_digest=(
                expected_initial_bundle_absence_digest
            ),
            predecessor_record=predecessor_record,
            expected_predecessor_binding=expected_predecessor_binding,
            execution_context=context,
        )
        claimed = store.compare_and_swap(claim)
    else:
        claimed = current
        claim_record = claimed.get("claim")
        if (
            not isinstance(claim_record, Mapping)
            or claim_record.get("claim_nonce_digest")
            != _require_digest(
                claim_nonce_digest, "CLAIM_NONCE_DIGEST_INVALID"
            )
        ):
            _fail("CLAIM_RESUME_BINDING_MISMATCH")
        _claim_execution_context(
            claimed, expected=context, required=context is not None
        )

    def invoke_once(operation: Mapping[str, Any]) -> phase_ledger.OperationResult:
        _validate_plan_operation(operation)
        transcript_before = _as_mapping(
            provider.transcript_summary(),
            "DURABLE_PROVIDER_TRANSCRIPT_INVALID",
        )
        _transcript_projection(transcript_before)
        try:
            invocation = _invoke_provider_operation(
                provider,
                operation,
                phase=str(current["phase"]),
                plan=plan,
            )
        except BaseException:
            # The durable ledger converts this exact boundary to AMBIGUOUS.
            raise
        if not isinstance(invocation, _ProviderInvocation):
            _fail("PROVIDER_OPERATION_RESULT_INVALID")
        result = invocation.result
        if result.outcome not in {"SUCCEEDED", "FAILED", "AMBIGUOUS"}:
            _fail("PROVIDER_OPERATION_RESULT_INVALID")
        if result.outcome == "AMBIGUOUS":
            if result.provider_result_digest is not None:
                _fail("PROVIDER_OPERATION_RESULT_INVALID")
        else:
            _require_digest(
                result.provider_result_digest,
                "PROVIDER_OPERATION_RESULT_INVALID",
            )
        if context is None:
            return result
        base_evidence = _durable_provider_evidence(
            provider=provider,
            identity=identity,
            operation=operation,
            phase=str(current["phase"]),
            plan=plan,
            transcript_before=transcript_before,
            result=result,
            execution_context=context,
        )
        evidence_name, private_evidence = _private_provider_evidence_record(
            ledger_record=claimed,
            operation=operation,
            base_evidence=base_evidence,
            provider_private_record=invocation.private_record,
        )
        persisted = _persist_private_custody_record(
            store.root, evidence_name, private_evidence
        )
        _validated_private, evidence = _validate_private_provider_evidence_record(
            persisted,
            name=evidence_name,
            ledger_record=claimed,
            plan=plan,
        )
        return phase_ledger.OperationResult(
            result.outcome,
            result.provider_result_digest,
            evidence,
        )

    terminal = phase_ledger.execute_claimed_phase(
        store=store,
        plan=plan,
        ledger_id=ledger_id,
        expected_plan_digest=expected_plan_digest,
        execution_authorization=execution_authorization,
        executor_authority_evidence=executor_authority_evidence,
        authority_evaluation_at=authority_evaluation_at,
        expected_initial_bundle_absence_digest=(
            expected_initial_bundle_absence_digest
        ),
        predecessor_record=predecessor_record,
        expected_predecessor_binding=expected_predecessor_binding,
        clock=clock,
        invoke_once=invoke_once,
    )
    if claimed["phase"] != terminal["phase"]:
        _fail("PHASE_ISOLATION_VIOLATION")
    if context is None:
        return _private_phase_run(
            terminal,
            provider,
            recovered_in_flight=False,
            command="execute-phase",
            activator_checkpoint_digest=activator_digest,
        )
    return _private_phase_run_from_terminal_evidence(
        terminal,
        plan=plan,
        expected_plan_digest=expected_plan_digest,
        private_evidence_root=store.root,
        require_private_evidence=True,
    )


def _validate_inventory_gate(
    ledger_record: Mapping[str, Any],
    classification: Mapping[str, Any],
    *,
    require_live_provider: bool,
) -> None:
    value = _snapshot(classification, "INVENTORY_CLASSIFICATION_INVALID")
    if (
        not isinstance(value, Mapping)
        or value.get("stable") is not True
        or (
            require_live_provider
            and value.get("provider_backed") is not True
        )
        or (
            not require_live_provider
            and value.get("provider_backed") not in {True, False}
        )
        or value.get("authorized_before_state_digest")
        != ledger_record.get("before_state_digest")
        or value.get("classification")
        not in {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"}
    ):
        _fail("STABLE_PROVIDER_BEFORE_STATE_REQUIRED")
    if (
        ledger_record.get("phase") == "POLICY_FACTORY"
        and value.get("classification") != "ABSENT_READY"
    ):
        _fail("INITIAL_ABSENCE_REQUIRED")


def _validate_activator_checkpoint(
    value: Mapping[str, Any] | None,
    *,
    expected_digest: str | None,
    at: datetime,
) -> str:
    fields = {
        "record_type",
        "function_configurator_checkpoint_digest",
        "broker_function_evidence_digest",
        "authority_ended_at",
        "stable_provider_readback_digest",
        "factory_role_proof_bound_and_detached",
        "checkpoint_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("ACTIVATOR_CHECKPOINT_REQUIRED")
    if (
        value.get("record_type")
        != "scanalyze.platform_authority.gug357_function_configurator_checkpoint.v1"
        or value.get("factory_role_proof_bound_and_detached") is not True
    ):
        _fail("ACTIVATOR_CHECKPOINT_INVALID")
    for field in fields - {
        "record_type",
        "authority_ended_at",
        "factory_role_proof_bound_and_detached",
    }:
        _require_digest(value.get(field), "ACTIVATOR_CHECKPOINT_INVALID")
    expected = canonical_digest(
        {key: item for key, item in value.items() if key != "checkpoint_digest"}
    )
    authorized = _require_digest(
        expected_digest, "EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID"
    )
    if value.get("checkpoint_digest") != expected or expected != authorized:
        _fail("ACTIVATOR_CHECKPOINT_DIGEST_MISMATCH")
    ended = _parse_stamp(value.get("authority_ended_at"), "ACTIVATOR_CHECKPOINT_INVALID")
    if ended >= _utc(at, "RUNNER_TIME_INVALID"):
        _fail("ACTIVATOR_AUTHORITY_NOT_EXPIRED")
    return expected


def _private_phase_run(
    record: Mapping[str, Any],
    provider: Provider,
    *,
    recovered_in_flight: bool,
    command: str,
    activator_checkpoint_digest: str | None,
) -> dict[str, Any]:
    if command not in {"execute-phase", "reconcile"}:
        _fail("PRIVATE_RUN_COMMAND_INVALID")
    context = _claim_execution_context(record)
    return _private_phase_run_from_evidence(
        record,
        transcript=_provider_transcript(provider),
        provider_mode=_provider_mode(provider),
        causal_evidence=_private_causal_receipt_evidence(provider),
        recovered_in_flight=recovered_in_flight,
        command=command,
        activator_checkpoint_digest=activator_checkpoint_digest,
        owner_checkpoint_digest=(
            str(context["owner_checkpoint_digest"]) if context is not None else None
        ),
        live_request_digest=(
            str(context["live_request_digest"]) if context is not None else None
        ),
        execution_context_digest=(
            str(context["context_digest"]) if context is not None else None
        ),
    )


def _private_phase_run_from_evidence(
    record: Mapping[str, Any],
    *,
    transcript: Mapping[str, Any],
    provider_mode: str,
    causal_evidence: Mapping[str, Any] | None,
    recovered_in_flight: bool,
    command: str,
    activator_checkpoint_digest: str | None,
    owner_checkpoint_digest: str | None = None,
    live_request_digest: str | None = None,
    execution_context_digest: str | None = None,
) -> dict[str, Any]:
    if command not in {"execute-phase", "reconcile"}:
        _fail("PRIVATE_RUN_COMMAND_INVALID")
    if provider_mode not in {"LIVE", "SYNTHETIC"}:
        _fail("PROVIDER_MODE_INVALID")
    status = str(record.get("status"))
    if status == "RECONCILED":
        reconciliation = record.get("reconciliation")
        ledger_classification = (
            reconciliation.get("classification")
            if isinstance(reconciliation, Mapping)
            else None
        )
        if ledger_classification in {"EFFECT_PROVEN", "NO_EFFECT_PROVEN"}:
            classification = "RECONCILIATION_CONCLUSIVE"
        elif ledger_classification == "INCONCLUSIVE":
            classification = "UNCERTAIN_RECONCILE_ONLY"
        else:
            _fail("RECONCILIATION_CLASSIFICATION_INVALID")
    elif status == "AMBIGUOUS":
        classification = "UNCERTAIN_RECONCILE_ONLY"
    elif status == "CONSUMED":
        classification = "PHASE_CONSUMED"
    else:
        classification = "STOP_NO_MUTATION"
    result: dict[str, Any] = {
        "record_type": PRIVATE_RUN_TYPE,
        "schema_version": 1,
        "issue": ISSUE,
        "command": command,
        "phase": record.get("phase"),
        "status": status,
        "classification": classification,
        "ledger_id": record.get("ledger_id"),
        "ledger_digest": record.get("ledger_digest"),
        "terminal_receipt_digest": (
            record.get("receipt_chain", [{}])[-1].get("receipt_digest")
            if record.get("receipt_chain")
            else None
        ),
        "provider_mode": provider_mode,
        "transcript": _snapshot(transcript, "PROVIDER_TRANSCRIPT_INVALID"),
        "causal_receipt_evidence": causal_evidence,
        "activator_checkpoint_digest": activator_checkpoint_digest,
        "recovered_in_flight": recovered_in_flight,
        "retry_permitted": False,
        "automatic_rollback_permitted": False,
        "deployment_authorized": False,
        "production_status": "NO-GO",
        "run_digest": "",
    }
    bindings = (
        owner_checkpoint_digest,
        live_request_digest,
        execution_context_digest,
    )
    if any(item is not None for item in bindings):
        if not all(item is not None for item in bindings):
            _fail("PRIVATE_RUN_EXECUTION_CONTEXT_INCOMPLETE")
        result.update(
            {
                "owner_checkpoint_digest": _require_digest(
                    owner_checkpoint_digest, "OWNER_CHECKPOINT_DIGEST_INVALID"
                ),
                "live_request_digest": _require_digest(
                    live_request_digest, "LIVE_REQUEST_DIGEST_INVALID"
                ),
                "execution_context_digest": _require_digest(
                    execution_context_digest, "EXECUTION_CONTEXT_DIGEST_INVALID"
                ),
            }
        )
    result["run_digest"] = canonical_digest(
        {key: item for key, item in result.items() if key != "run_digest"}
    )
    return result


def _phase_operation(
    plan: Mapping[str, Any], *, phase: str, sequence: int
) -> Mapping[str, Any]:
    candidates = [
        item
        for item in plan.get("authorization_phases", [])
        if isinstance(item, Mapping) and item.get("phase") == phase
    ]
    if len(candidates) != 1:
        _fail("PHASE_OPERATIONS_INVALID")
    operations = candidates[0].get("operations")
    if (
        not isinstance(operations, list)
        or not 1 <= sequence <= len(operations)
        or not isinstance(operations[sequence - 1], Mapping)
    ):
        _fail("PHASE_OPERATIONS_INVALID")
    operation = operations[sequence - 1]
    if operation.get("sequence") != sequence:
        _fail("PHASE_OPERATIONS_INVALID")
    return operation


def _private_phase_run_from_terminal_evidence(
    record: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    private_evidence_root: Path | None = None,
    require_private_evidence: bool = False,
) -> dict[str, Any]:
    """Materialize the exact terminal run without another provider call."""

    phase_ledger.validate_ledger(
        record,
        expected_plan_digest=_require_digest(
            expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID"
        ),
        expected_phase=str(record.get("phase")),
    )
    if record.get("status") not in {"CONSUMED", "AMBIGUOUS"}:
        _fail("TERMINAL_PHASE_REQUIRED")
    context = _claim_execution_context(record, required=True)
    outcomes = record.get("operation_outcomes")
    if not isinstance(outcomes, list) or not outcomes:
        _fail("DURABLE_PROVIDER_EVIDENCE_MISSING")
    transcript, causal, provider_mode = _phase_transcript_from_outcomes(
        record=record,
        outcomes=outcomes,
        plan=plan,
        expected_plan_digest=expected_plan_digest,
        private_evidence_root=private_evidence_root,
        require_private_evidence=require_private_evidence,
    )
    if record.get("phase") == "LEDGER_FACTORY_INVOKER":
        if not isinstance(causal, Mapping):
            _fail("DURABLE_PROVIDER_CAUSAL_EVIDENCE_MISSING")
        _validate_private_causal_receipt(
            plan=plan,
            evidence=causal,
            ledger_record=record,
            transcript=transcript,
        )
    elif causal is not None:
        _fail("DURABLE_PROVIDER_CAUSAL_EVIDENCE_UNEXPECTED")
    return _private_phase_run_from_evidence(
        record,
        transcript=transcript,
        provider_mode=provider_mode,
        causal_evidence=(causal if isinstance(causal, Mapping) else None),
        recovered_in_flight=False,
        command="execute-phase",
        activator_checkpoint_digest=context.get("activator_checkpoint_digest"),
        owner_checkpoint_digest=str(context["owner_checkpoint_digest"]),
        live_request_digest=str(context["live_request_digest"]),
        execution_context_digest=str(context["context_digest"]),
    )


def _private_reconciliation_run_from_terminal_evidence(
    record: Mapping[str, Any],
    *,
    expected_plan_digest: str,
    expected_owner_checkpoint_digest: str | None = None,
    expected_live_request_digest: str | None = None,
    private_evidence_root: Path | None = None,
    require_private_evidence: bool = False,
) -> dict[str, Any]:
    """Rebuild a RECONCILED private run solely from its durable ledger."""

    phase_ledger.validate_ledger(
        record,
        expected_plan_digest=_require_digest(
            expected_plan_digest, "EXPECTED_PLAN_DIGEST_INVALID"
        ),
        expected_phase=str(record.get("phase")),
    )
    reconciliation = record.get("reconciliation")
    if record.get("status") != "RECONCILED" or not isinstance(
        reconciliation, Mapping
    ):
        _fail("TERMINAL_RECONCILIATION_REQUIRED")
    required = {
        "owner_checkpoint_digest",
        "live_request_digest",
        "execution_context_digest",
        "provider_transcript_digest",
        "provider_transcript_summary_digest",
        "provider_call_count",
        "identity_receipt_digest",
    }
    if not required.issubset(reconciliation):
        _fail("DURABLE_RECONCILIATION_EVIDENCE_MISSING")
    claim_context = _claim_execution_context(record, required=True)
    context = _execution_context(
        owner_checkpoint_digest=str(
            reconciliation["owner_checkpoint_digest"]
        ),
        live_request_digest=str(reconciliation["live_request_digest"]),
        activator_checkpoint_digest=claim_context.get(
            "activator_checkpoint_digest"
        ),
    )
    if context["context_digest"] != reconciliation.get(
        "execution_context_digest"
    ):
        _fail("DURABLE_RECONCILIATION_CONTEXT_MISMATCH")
    if (
        expected_owner_checkpoint_digest is not None
        and context["owner_checkpoint_digest"]
        != _require_digest(
            expected_owner_checkpoint_digest,
            "OWNER_CHECKPOINT_DIGEST_INVALID",
        )
    ) or (
        expected_live_request_digest is not None
        and context["live_request_digest"]
        != _require_digest(
            expected_live_request_digest,
            "LIVE_REQUEST_DIGEST_INVALID",
        )
    ):
        _fail("RECONCILIATION_ACTION_CONTEXT_MISMATCH")
    private_file = reconciliation.get("private_reconciliation_evidence_file")
    private_digest = reconciliation.get(
        "private_reconciliation_evidence_digest"
    )
    if private_evidence_root is not None:
        if not isinstance(private_file, str):
            _fail("PRIVATE_RECONCILIATION_EVIDENCE_LINK_INVALID")
        raw = _read_private_custody_record(private_evidence_root, private_file)
        if not isinstance(raw, Mapping):
            _fail("PRIVATE_RECONCILIATION_EVIDENCE_MISSING")
        private_record, linked_binding = (
            _validate_private_reconciliation_evidence_record(
                raw,
                name=private_file,
                current=record,
                expected_effect_state_digest=str(
                    reconciliation["expected_effect_state_digest"]
                ),
                expected_no_effect_state_digest=str(
                    reconciliation["expected_no_effect_state_digest"]
                ),
                expected_binding_digest=str(
                    reconciliation["expectation_binding_digest"]
                ),
                expected_owner_checkpoint_digest=str(
                    reconciliation["owner_checkpoint_digest"]
                ),
                expected_live_request_digest=str(
                    reconciliation["live_request_digest"]
                ),
            )
        )
        if (
            private_record.get("evidence_digest") != private_digest
            or any(
                reconciliation.get(key) != item
                for key, item in linked_binding.items()
            )
        ):
            _fail("PRIVATE_RECONCILIATION_EVIDENCE_LINK_MISMATCH")
    elif require_private_evidence:
        _fail("PRIVATE_RECONCILIATION_EVIDENCE_ROOT_REQUIRED")
    transcript = {
        "transcript_digest": reconciliation["provider_transcript_digest"],
        "call_count": reconciliation["provider_call_count"],
        "write_call_count": 0,
        "live_provider_evidence": True,
        "accepted_causal_receipt_binding_digest": None,
        "identity_receipt_digest": reconciliation[
            "identity_receipt_digest"
        ],
        "summary_digest": reconciliation[
            "provider_transcript_summary_digest"
        ],
    }
    _transcript_projection({**transcript, "complete": True})
    return _private_phase_run_from_evidence(
        record,
        transcript=transcript,
        provider_mode="LIVE",
        causal_evidence=None,
        recovered_in_flight=False,
        command="reconcile",
        activator_checkpoint_digest=claim_context.get(
            "activator_checkpoint_digest"
        ),
        owner_checkpoint_digest=str(context["owner_checkpoint_digest"]),
        live_request_digest=str(context["live_request_digest"]),
        execution_context_digest=str(context["context_digest"]),
    )


def _phase_transcript_from_outcomes(
    *,
    record: Mapping[str, Any],
    outcomes: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    private_evidence_root: Path | None = None,
    require_private_evidence: bool = False,
) -> tuple[dict[str, Any], Mapping[str, Any] | None, str]:
    """Aggregate exact per-operation transcript deltas without prefix double-counting."""

    if plan.get("plan_digest") != expected_plan_digest:
        _fail("DURABLE_PROVIDER_OPERATION_BINDING_MISMATCH")
    provider_mode: str | None = None
    identity_digest: str | None = None
    prior_after_digest: str | None = None
    prior_after: Mapping[str, Any] | None = None
    provider_segments = 0
    provider_calls = 0
    provider_writes = 0
    operation_proofs: list[dict[str, Any]] = []
    causal_evidence: Mapping[str, Any] | None = None
    phase = str(record.get("phase"))
    for sequence, outcome in enumerate(outcomes, 1):
        evidence = outcome.get("durable_provider_evidence")
        if not isinstance(evidence, Mapping):
            _fail("DURABLE_PROVIDER_EVIDENCE_MISSING")
        try:
            checked = phase_ledger.validate_durable_provider_evidence(
                evidence,
                record=record,
                operation_sequence=sequence,
                outcome=str(outcome.get("result")),
                provider_result_digest=outcome.get("provider_result_digest"),
            )
        except Exception as exc:
            raise Gug390Error("DURABLE_PROVIDER_EVIDENCE_INVALID") from exc
        if private_evidence_root is not None:
            _read_linked_provider_evidence(
                root=private_evidence_root,
                ledger_record=record,
                plan=plan,
                durable_evidence=checked,
            )
        elif require_private_evidence:
            _fail("PRIVATE_PROVIDER_EVIDENCE_ROOT_REQUIRED")
        operation = _phase_operation(plan, phase=phase, sequence=sequence)
        if (
            checked.get("operation_digest")
            != _provider_operation_digest(
                phase=phase, operation=operation, plan=plan
            )
            or checked.get("provider_request_digest")
            != operation.get("request_digest")
        ):
            _fail("DURABLE_PROVIDER_OPERATION_BINDING_MISMATCH")
        current_mode = str(checked.get("provider_mode"))
        current_identity = str(checked.get("identity_receipt_digest"))
        if provider_mode is None:
            provider_mode = current_mode
            identity_digest = current_identity
        elif (
            current_mode != provider_mode
            or current_identity != identity_digest
        ):
            _fail("DURABLE_PROVIDER_PHASE_IDENTITY_MISMATCH")
        before_raw = _as_mapping(
            checked.get("transcript_before"),
            "DURABLE_PROVIDER_TRANSCRIPT_INVALID",
        )
        after_raw = _as_mapping(
            checked.get("transcript"),
            "DURABLE_PROVIDER_TRANSCRIPT_INVALID",
        )
        before = _transcript_projection(before_raw)
        after = _transcript_projection(after_raw)
        before_calls = int(before["call_count"])
        after_calls = int(after["call_count"])
        before_writes = int(before["write_call_count"])
        after_writes = int(after["write_call_count"])
        call_delta = after_calls - before_calls
        write_delta = after_writes - before_writes
        if call_delta < 1 or write_delta not in {0, 1}:
            _fail("DURABLE_PROVIDER_TRANSCRIPT_DELTA_INVALID")
        before_digest = str(checked["transcript_before_receipt_digest"])
        after_digest = str(checked["transcript_receipt_digest"])
        continuing = prior_after_digest is not None and before_digest == prior_after_digest
        if continuing:
            if before_raw != prior_after:
                _fail("DURABLE_PROVIDER_TRANSCRIPT_CHAIN_MISMATCH")
        else:
            provider_segments += 1
            if before_writes != 0:
                _fail("DURABLE_PROVIDER_TRANSCRIPT_SEGMENT_INVALID")
            provider_calls += before_calls
        provider_calls += call_delta
        provider_writes += write_delta
        expected_write_delta = int(
            (operation.get("service"), operation.get("api_action"))
            in _WRITE_ACTIONS
        )
        if write_delta != expected_write_delta:
            _fail("DURABLE_PROVIDER_WRITE_COUNT_MISMATCH")
        causal = checked.get("causal_receipt_evidence")
        if isinstance(causal, Mapping):
            if causal_evidence is None:
                causal_evidence = causal
            elif causal != causal_evidence:
                _fail("DURABLE_PROVIDER_CAUSAL_EVIDENCE_MISMATCH")
        operation_proofs.append(
            {
                "operation_sequence": sequence,
                "operation_digest": checked["operation_digest"],
                "provider_request_digest": checked["provider_request_digest"],
                "outcome": checked["outcome"],
                "provider_result_digest": checked["provider_result_digest"],
                "transcript_before_receipt_digest": before_digest,
                "transcript_receipt_digest": after_digest,
                "provider_call_delta": call_delta,
                "provider_write_delta": write_delta,
                "evidence_digest": checked["evidence_digest"],
            }
        )
        prior_after_digest = after_digest
        prior_after = after_raw
    if provider_mode is None or identity_digest is None:
        _fail("DURABLE_PROVIDER_EVIDENCE_MISSING")
    causal_binding = (
        causal_evidence.get("binding_digest")
        if isinstance(causal_evidence, Mapping)
        else None
    )
    proof_digest = canonical_digest(operation_proofs)
    transcript_body = {
        "record_type": (
            "scanalyze.platform_authority.gug390_phase_provider_transcript.v1"
        ),
        "ledger_id": record.get("ledger_id"),
        "phase": phase,
        "provider_mode": provider_mode,
        "identity_receipt_digest": identity_digest,
        "operation_evidence_count": len(operation_proofs),
        "operation_evidence_digest": proof_digest,
        "provider_segment_count": provider_segments,
        "call_count": provider_calls,
        "write_call_count": provider_writes,
        "live_provider_evidence": provider_mode == "LIVE",
        "accepted_causal_receipt_binding_digest": causal_binding,
        "complete": True,
    }
    transcript = {
        **transcript_body,
        "transcript_digest": canonical_digest(
            {"operation_evidence": operation_proofs}
        ),
    }
    transcript["summary_digest"] = canonical_digest(transcript)
    return transcript, causal_evidence, provider_mode


def _private_causal_receipt_evidence(provider: Provider) -> dict[str, Any] | None:
    method = getattr(provider, "private_accepted_causal_receipt", None)
    if not callable(method):
        return None
    try:
        return _as_mapping(method(), "CAUSAL_RECEIPT_EVIDENCE_INVALID")
    except Exception as exc:
        if getattr(exc, "code", None) == "CAUSAL_RECEIPT_NOT_ACCEPTED":
            return None
        raise


def _exact_ambiguous_planned_call(
    plan: Mapping[str, Any],
    current: Mapping[str, Any],
    live_provider: Any,
) -> tuple[Mapping[str, Any], Any]:
    """Select only the plan operation named by the ledger's terminal ambiguity."""

    phases = plan.get("authorization_phases")
    candidates = [
        item
        for item in phases
        if isinstance(item, Mapping) and item.get("phase") == current.get("phase")
    ] if isinstance(phases, list) else []
    if len(candidates) != 1:
        _fail("RECONCILIATION_PHASE_BINDING_INVALID")
    operations = candidates[0].get("operations")
    outcomes = current.get("operation_outcomes")
    ordered_requests = current.get("ordered_request_digests")
    if (
        not isinstance(operations, list)
        or not operations
        or canonical_digest(operations) != current.get("ordered_operations_digest")
        or current.get("operation_count") != len(operations)
        or not isinstance(ordered_requests, list)
        or len(ordered_requests) != len(operations)
        or not isinstance(outcomes, list)
        or not outcomes
    ):
        _fail("RECONCILIATION_PHASE_BINDING_INVALID")
    ambiguous = outcomes[-1]
    if not isinstance(ambiguous, Mapping):
        _fail("RECONCILIATION_AMBIGUOUS_OPERATION_INVALID")
    sequence = ambiguous.get("operation_sequence")
    if (
        ambiguous.get("result") != "AMBIGUOUS"
        or ambiguous.get("provider_result_digest") is not None
        or ambiguous.get("next_required_action") != "RECONCILE_READ_ONLY"
        or type(sequence) is not int
        or sequence != len(outcomes)
        or not 1 <= sequence <= len(operations)
    ):
        _fail("RECONCILIATION_AMBIGUOUS_OPERATION_INVALID")
    operation = operations[sequence - 1]
    if not isinstance(operation, Mapping):
        _fail("RECONCILIATION_AMBIGUOUS_OPERATION_INVALID")
    _validate_plan_operation(operation)
    request_digest = operation.get("request_digest")
    if (
        operation.get("sequence") != sequence
        or request_digest != ambiguous.get("request_digest")
        or request_digest != ordered_requests[sequence - 1]
    ):
        _fail("RECONCILIATION_AMBIGUOUS_OPERATION_INVALID")
    try:
        planned = live_provider.planned_call_from_record(
            str(current["phase"]), operation, plan=plan
        )
    except Exception as exc:
        raise Gug390Error("RECONCILIATION_OPERATION_BINDING_INVALID") from exc
    if planned.request_digest != request_digest or planned.sequence != sequence:
        _fail("RECONCILIATION_OPERATION_BINDING_INVALID")
    return ambiguous, planned


def _reconciliation_readback_contract(
    ambiguous_call: Any,
    readback_calls: Sequence[Any],
    live_provider: Any,
) -> dict[str, Any]:
    if (
        not isinstance(readback_calls, Sequence)
        or isinstance(readback_calls, (str, bytes))
        or not readback_calls
    ):
        _fail("RECONCILIATION_READBACK_CONTRACT_INVALID")
    readbacks: list[dict[str, Any]] = []
    for ordinal, call in enumerate(readback_calls, 1):
        if type(call) is not live_provider.PlannedCall:
            _fail("RECONCILIATION_READBACK_CONTRACT_INVALID")
        try:
            live_provider._validate_call(call)  # noqa: SLF001
        except Exception as exc:
            raise Gug390Error(
                "RECONCILIATION_READBACK_CONTRACT_INVALID"
            ) from exc
        if (
            call.kind not in {live_provider.CallKind.READ, live_provider.CallKind.WAITER}
            or call.phase != ambiguous_call.phase
            or call.sequence != ambiguous_call.sequence
        ):
            _fail("RECONCILIATION_READ_ONLY_REQUIRED")
        readbacks.append(
            {
                "readback_ordinal": ordinal,
                "operation_digest": call.operation_digest,
                "phase": call.phase,
                "sequence": call.sequence,
                "service": call.service,
                "api_action": call.api_action,
                "allowed_action": call.allowed_action,
                "target_digest": canonical_digest(call.target_arn),
                "request_digest": call.request_digest,
                "kind": call.kind.value,
                "complete_pagination_required": (
                    call.complete_pagination_required
                ),
                "poll_interval_seconds": call.poll_interval_seconds,
                "max_poll_attempts": call.max_poll_attempts,
                "timeout_seconds": call.timeout_seconds,
                "attempt_limit": 1,
                "retry_permitted": False,
            }
        )
    body = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug390_reconciliation_readback_contract.v1"
        ),
        "phase": ambiguous_call.phase,
        "ambiguous_operation_sequence": ambiguous_call.sequence,
        "ambiguous_operation_digest": ambiguous_call.operation_digest,
        "capture_count": 2,
        "complete_capture_equality_required": True,
        "write_retry_permitted": False,
        "readback_count": len(readbacks),
        "readbacks": readbacks,
    }
    return {**body, "contract_digest": canonical_digest(body)}


def _reconciliation_call_mapping(call: Any) -> dict[str, Any]:
    return {
        "sequence": call.sequence,
        "service": call.service,
        "api_action": call.api_action,
        "allowed_action": call.allowed_action,
        "target_arn": call.target_arn,
        "request": _snapshot(call.request, "RECONCILIATION_CALL_INVALID"),
        "request_digest": call.request_digest,
        "complete_pagination_required": call.complete_pagination_required,
        "attempt_limit": 1,
        "retry_permitted": False,
    }


def _read_reconciliation_call(
    provider: Provider, call: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        raw = provider.read_operation(call)
    except BaseException as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str) and _TOKEN.fullmatch(code):
            raise Gug390Error(code) from exc
        raise Gug390Error("RECONCILIATION_READBACK_ERROR") from exc
    private_method = getattr(raw, "private_record", None)
    if not callable(private_method):
        _fail("RECONCILIATION_READBACK_RESULT_INVALID")
    value = _as_mapping(
        private_method(), "RECONCILIATION_READBACK_RESULT_INVALID"
    )
    value = _validate_private_provider_record(
        value, code="RECONCILIATION_READBACK_RESULT_INVALID"
    )
    if (
        value.get("phase") != call.phase
        or value.get("sequence") != call.sequence
        or value.get("operation_digest") != call.operation_digest
        or value.get("request_digest") != call.request_digest
        or value.get("reconciliation_required") is not False
    ):
        _fail("RECONCILIATION_READBACK_RESULT_INVALID")
    response_digest = _require_digest(
        value.get("response_digest"), "RECONCILIATION_READBACK_RESULT_INVALID"
    )
    outcome = value.get("outcome")
    response = value.get("response")
    error_code = value.get("error_code")
    operation = _reconciliation_call_mapping(call)
    if (
        outcome == "SUCCEEDED"
        and error_code is None
        and isinstance(response, Mapping)
        and response_digest == canonical_digest(response)
    ):
        selected = _successful_read_presence(operation, response)
        result_digest = response_digest
    elif outcome == "FAILED" and error_code in _ABSENCE_ERRORS:
        selected = "ABSENT"
        result_digest = canonical_digest(
            {
                "absence": error_code,
                "request_digest": call.request_digest,
                "target_digest": canonical_digest(call.target_arn),
            }
        )
    else:
        _fail("RECONCILIATION_READBACK_UNCERTAIN")
    return (
        {
            "operation_digest": call.operation_digest,
            "request_digest": call.request_digest,
            "outcome": selected,
            "result_digest": result_digest,
        },
        value,
    )


def _capture_reconciliation_state(
    provider: Provider,
    *,
    ambiguous_operation_digest: str,
    readback_contract_digest: str,
    readback_calls: Sequence[Any],
    capture_index: int,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    if capture_index not in {1, 2}:
        _fail("RECONCILIATION_CAPTURE_INDEX_INVALID")
    results: list[dict[str, Any]] = []
    private_results: list[dict[str, Any]] = []
    for ordinal, call in enumerate(readback_calls, 1):
        result, private = _read_reconciliation_call(provider, call)
        results.append({"readback_ordinal": ordinal, **result})
        private_results.append(
            {
                "readback_ordinal": ordinal,
                "private_provider_record": private,
                "private_provider_record_digest": canonical_digest(private),
            }
        )
    body = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug390_reconciliation_observed_state.v1"
        ),
        "ambiguous_operation_digest": ambiguous_operation_digest,
        "readback_contract_digest": readback_contract_digest,
        "result_count": len(results),
        "results": results,
        "complete": True,
    }
    state_digest = canonical_digest(body)
    private_body = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug390_private_reconciliation_capture.v1"
        ),
        "capture_index": capture_index,
        "observed_state": body,
        "observed_state_digest": state_digest,
        "private_result_count": len(private_results),
        "private_results": private_results,
    }
    return (
        body,
        state_digest,
        {**private_body, "capture_digest": canonical_digest(private_body)},
    )


def _private_reconciliation_evidence_record(
    *,
    current: Mapping[str, Any],
    contract: Mapping[str, Any],
    first_identity_receipt: Mapping[str, Any],
    final_identity_receipt: Mapping[str, Any],
    first_capture: Mapping[str, Any],
    second_capture: Mapping[str, Any],
    transcript: Mapping[str, Any],
    reconciliation_binding_body: Mapping[str, Any],
    expected_effect_state_digest: str,
    expected_no_effect_state_digest: str,
    recorded_at: datetime,
) -> tuple[str, dict[str, Any]]:
    name = _reconciliation_evidence_file(str(current.get("ledger_id")))
    body = {
        "record_type": PRIVATE_RECONCILIATION_EVIDENCE_TYPE,
        "schema_version": 1,
        "issue": ISSUE,
        "ledger_id": current.get("ledger_id"),
        "initial_ledger_digest": current.get("initial_ledger_digest"),
        "ambiguous_ledger_digest": current.get("ledger_digest"),
        "private_evidence_file": name,
        "readback_contract": _snapshot(
            contract, "RECONCILIATION_READBACK_CONTRACT_INVALID"
        ),
        "first_identity_receipt": _snapshot(
            first_identity_receipt, "RECONCILIATION_IDENTITY_RECEIPT_INVALID"
        ),
        "final_identity_receipt": _snapshot(
            final_identity_receipt, "RECONCILIATION_IDENTITY_RECEIPT_INVALID"
        ),
        "first_capture": _snapshot(
            first_capture, "RECONCILIATION_CAPTURE_INVALID"
        ),
        "second_capture": _snapshot(
            second_capture, "RECONCILIATION_CAPTURE_INVALID"
        ),
        "provider_transcript": _snapshot(
            transcript, "RECONCILIATION_TRANSCRIPT_INVALID"
        ),
        "reconciliation_binding_body": _snapshot(
            reconciliation_binding_body,
            "RECONCILIATION_BINDING_INVALID",
        ),
        "expected_effect_state_digest": expected_effect_state_digest,
        "expected_no_effect_state_digest": expected_no_effect_state_digest,
        "recorded_at": _stamp(recorded_at),
        "repository_persisted": False,
    }
    return name, {**body, "evidence_digest": canonical_digest(body)}


def _validate_private_reconciliation_capture(
    capture: Any,
    *,
    capture_index: int,
    contract: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    value = _snapshot(capture, "PRIVATE_RECONCILIATION_CAPTURE_INVALID")
    fields = {
        "record_type",
        "capture_index",
        "observed_state",
        "observed_state_digest",
        "private_result_count",
        "private_results",
        "capture_digest",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("record_type")
        != "scanalyze.platform_authority.gug390_private_reconciliation_capture.v1"
        or value.get("capture_index") != capture_index
        or value.get("capture_digest")
        != canonical_digest(
            {key: item for key, item in value.items() if key != "capture_digest"}
        )
    ):
        _fail("PRIVATE_RECONCILIATION_CAPTURE_INVALID")
    observed = value.get("observed_state")
    readbacks = contract.get("readbacks")
    results = observed.get("results") if isinstance(observed, Mapping) else None
    private_results = value.get("private_results")
    if (
        not isinstance(observed, Mapping)
        or observed.get("readback_contract_digest") != contract.get("contract_digest")
        or observed.get("complete") is not True
        or not isinstance(readbacks, list)
        or not isinstance(results, list)
        or not isinstance(private_results, list)
        or observed.get("result_count") != len(readbacks)
        or value.get("private_result_count") != len(readbacks)
        or len(results) != len(readbacks)
        or len(private_results) != len(readbacks)
    ):
        _fail("PRIVATE_RECONCILIATION_CAPTURE_INVALID")
    for ordinal, (contract_item, result, private_item) in enumerate(
        zip(readbacks, results, private_results, strict=True), 1
    ):
        private = (
            private_item.get("private_provider_record")
            if isinstance(private_item, Mapping)
            else None
        )
        if (
            not isinstance(contract_item, Mapping)
            or not isinstance(result, Mapping)
            or not isinstance(private_item, Mapping)
            or set(private_item)
            != {
                "readback_ordinal",
                "private_provider_record",
                "private_provider_record_digest",
            }
            or result.get("readback_ordinal") != ordinal
            or private_item.get("readback_ordinal") != ordinal
            or result.get("operation_digest")
            != contract_item.get("operation_digest")
            or result.get("request_digest") != contract_item.get("request_digest")
            or not isinstance(private, Mapping)
            or private_item.get("private_provider_record_digest")
            != canonical_digest(private)
        ):
            _fail("PRIVATE_RECONCILIATION_CAPTURE_INVALID")
        checked_private = _validate_private_provider_record(
            private, code="PRIVATE_RECONCILIATION_CAPTURE_INVALID"
        )
        result_outcome = result.get("outcome")
        if (
            checked_private.get("phase") != contract_item.get("phase")
            or checked_private.get("sequence") != contract_item.get("sequence")
            or checked_private.get("operation_digest")
            != result.get("operation_digest")
            or checked_private.get("request_digest") != result.get("request_digest")
            or (
                result_outcome == "ABSENT"
                and (
                    (
                        checked_private.get("outcome") == "FAILED"
                        and (
                            checked_private.get("error_code")
                            not in _ABSENCE_ERRORS
                            or result.get("result_digest")
                            != canonical_digest(
                                {
                                    "absence": checked_private.get("error_code"),
                                    "request_digest": contract_item.get(
                                        "request_digest"
                                    ),
                                    "target_digest": contract_item.get(
                                        "target_digest"
                                    ),
                                }
                            )
                        )
                    )
                    or (
                        checked_private.get("outcome") == "SUCCEEDED"
                        and (
                            contract_item.get("allowed_action")
                            != "logs:DescribeLogGroups"
                            or checked_private.get("response_digest")
                            != result.get("result_digest")
                        )
                    )
                    or checked_private.get("outcome")
                    not in {"FAILED", "SUCCEEDED"}
                )
            )
            or (
                result_outcome == "PRESENT"
                and (
                    checked_private.get("outcome") != "SUCCEEDED"
                    or checked_private.get("response_digest")
                    != result.get("result_digest")
                )
            )
            or result_outcome not in {"ABSENT", "PRESENT"}
        ):
            _fail("PRIVATE_RECONCILIATION_CAPTURE_INVALID")
    digest = _require_digest(
        value.get("observed_state_digest"),
        "PRIVATE_RECONCILIATION_CAPTURE_INVALID",
    )
    if digest != canonical_digest(observed):
        _fail("PRIVATE_RECONCILIATION_CAPTURE_INVALID")
    return value, digest


def _validate_private_reconciliation_evidence_record(
    value: Mapping[str, Any],
    *,
    name: str,
    current: Mapping[str, Any],
    expected_effect_state_digest: str,
    expected_no_effect_state_digest: str,
    expected_binding_digest: str,
    expected_owner_checkpoint_digest: str,
    expected_live_request_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    record = _snapshot(value, "PRIVATE_RECONCILIATION_EVIDENCE_INVALID")
    expected_ambiguous_ledger_digest = (
        current.get("previous_ledger_digest")
        if current.get("status") == "RECONCILED"
        else current.get("ledger_digest")
    )
    fields = {
        "record_type",
        "schema_version",
        "issue",
        "ledger_id",
        "initial_ledger_digest",
        "ambiguous_ledger_digest",
        "private_evidence_file",
        "readback_contract",
        "first_identity_receipt",
        "final_identity_receipt",
        "first_capture",
        "second_capture",
        "provider_transcript",
        "reconciliation_binding_body",
        "expected_effect_state_digest",
        "expected_no_effect_state_digest",
        "recorded_at",
        "repository_persisted",
        "evidence_digest",
    }
    if (
        not isinstance(record, dict)
        or set(record) != fields
        or record.get("record_type") != PRIVATE_RECONCILIATION_EVIDENCE_TYPE
        or record.get("schema_version") != 1
        or record.get("issue") != ISSUE
        or record.get("ledger_id") != current.get("ledger_id")
        or record.get("initial_ledger_digest") != current.get("initial_ledger_digest")
        or record.get("ambiguous_ledger_digest")
        != expected_ambiguous_ledger_digest
        or record.get("private_evidence_file") != name
        or record.get("repository_persisted") is not False
        or record.get("evidence_digest")
        != canonical_digest(
            {key: item for key, item in record.items() if key != "evidence_digest"}
        )
        or record.get("expected_effect_state_digest")
        != expected_effect_state_digest
        or record.get("expected_no_effect_state_digest")
        != expected_no_effect_state_digest
    ):
        _fail("PRIVATE_RECONCILIATION_EVIDENCE_INVALID")
    contract = record.get("readback_contract")
    if (
        not isinstance(contract, Mapping)
        or contract.get("contract_digest")
        != canonical_digest(
            {key: item for key, item in contract.items() if key != "contract_digest"}
        )
    ):
        _fail("PRIVATE_RECONCILIATION_CONTRACT_INVALID")
    first, first_digest = _validate_private_reconciliation_capture(
        record.get("first_capture"), capture_index=1, contract=contract
    )
    second, second_digest = _validate_private_reconciliation_capture(
        record.get("second_capture"), capture_index=2, contract=contract
    )
    if (
        first.get("observed_state") != second.get("observed_state")
        or first_digest != second_digest
    ):
        _fail("PRIVATE_RECONCILIATION_CAPTURES_UNSTABLE")
    first_receipt, first_receipt_digest = _self_bound_receipt(
        record.get("first_identity_receipt"),
        self_digest_field="receipt_digest",
        code="PRIVATE_RECONCILIATION_IDENTITY_INVALID",
    )
    final_receipt, final_receipt_digest = _self_bound_receipt(
        record.get("final_identity_receipt"),
        self_digest_field="receipt_digest",
        code="PRIVATE_RECONCILIATION_IDENTITY_INVALID",
    )
    transcript = record.get("provider_transcript")
    projection = _transcript_projection(
        {
            **_as_mapping(
                transcript, "PRIVATE_RECONCILIATION_TRANSCRIPT_INVALID"
            ),
            "complete": True,
        }
    )
    binding = record.get("reconciliation_binding_body")
    if (
        first_receipt_digest != final_receipt_digest
        or first_receipt != final_receipt
        or not isinstance(binding, Mapping)
        or binding.get("ambiguous_ledger_digest")
        != expected_ambiguous_ledger_digest
        or binding.get("readback_contract_digest") != contract.get("contract_digest")
        or binding.get("identity_receipt_digest") != final_receipt_digest
        or binding.get("provider_transcript_digest")
        != projection.get("transcript_digest")
        or binding.get("provider_transcript_summary_digest")
        != projection.get("summary_digest")
        or binding.get("provider_call_count") != projection.get("call_count")
        or binding.get("owner_checkpoint_digest")
        != expected_owner_checkpoint_digest
        or binding.get("live_request_digest") != expected_live_request_digest
        or binding.get("expectation_binding_digest") != expected_binding_digest
    ):
        _fail("PRIVATE_RECONCILIATION_BINDING_INVALID")
    _parse_stamp(record.get("recorded_at"), "PRIVATE_RECONCILIATION_TIME_INVALID")
    linked_binding = {
        **dict(binding),
        "private_reconciliation_evidence_file": name,
        "private_reconciliation_evidence_digest": record["evidence_digest"],
    }
    return record, linked_binding


def _fresh_reconciliation_identity(
    provider: Provider,
    *,
    live_provider: Any,
    current: Mapping[str, Any],
    expected_session_identifier_digest: str,
) -> Any:
    try:
        receipt = provider.revalidate_identity()
    except BaseException as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str) and _TOKEN.fullmatch(code):
            raise Gug390Error(code) from exc
        raise Gug390Error("RECONCILIATION_STS_CONTINUITY_FAILED") from exc
    if (
        type(receipt) is not live_provider.IdentityReceipt
        or receipt != getattr(provider, "identity_receipt", None)
    ):
        _fail("RECONCILIATION_IDENTITY_RECEIPT_INVALID")
    value = _as_mapping(receipt, "RECONCILIATION_IDENTITY_RECEIPT_INVALID")
    receipt_digest = value.pop("receipt_digest", None)
    if (
        set(value)
        != {
            "record_type",
            "region",
            "account_digest",
            "principal_digest",
            "sso_role_name_digest",
            "session_digest",
            "response_digest",
            "concrete_provider",
        }
        or receipt_digest != canonical_digest(value)
        or receipt.region != current.get("region")
        or receipt.account_digest != canonical_digest(current.get("account_id"))
        or receipt.principal_digest != current.get("caller_arn_digest")
        or receipt.session_digest != current.get(
            "authority_session_identifier_digest"
        )
        or receipt.session_digest != expected_session_identifier_digest
        or receipt.concrete_provider is not True
    ):
        _fail("RECONCILIATION_PROVIDER_SESSION_MISMATCH")
    return receipt


def _reconciliation_expectation_binding_body(
    current: Mapping[str, Any],
    *,
    ambiguous: Mapping[str, Any],
    ambiguous_operation_digest: str,
    readback_contract_digest: str,
    identity_receipt_digest: str,
    expected_effect_state_digest: str,
    expected_no_effect_state_digest: str,
    execution_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "ledger_id": current["ledger_id"],
        "ambiguous_ledger_digest": current["ledger_digest"],
        "plan_digest": current["plan_digest"],
        "phase": current["phase"],
        "ordered_operations_digest": current["ordered_operations_digest"],
        "ambiguous_operation_sequence": ambiguous["operation_sequence"],
        "ambiguous_request_digest": ambiguous["request_digest"],
        "ambiguous_operation_digest": ambiguous_operation_digest,
        "readback_contract_digest": readback_contract_digest,
        "caller_arn_digest": current["caller_arn_digest"],
        "session_identifier_digest": current[
            "authority_session_identifier_digest"
        ],
        "identity_receipt_digest": identity_receipt_digest,
        "expected_effect_state_digest": expected_effect_state_digest,
        "expected_no_effect_state_digest": expected_no_effect_state_digest,
    }
    if execution_context is not None:
        checked = phase_ledger.validate_execution_context(execution_context)
        body.update(
            {
                "owner_checkpoint_digest": checked[
                    "owner_checkpoint_digest"
                ],
                "live_request_digest": checked["live_request_digest"],
                "execution_context_digest": checked["context_digest"],
            }
        )
    return body


def reconcile_ambiguous(
    *,
    store: phase_ledger.DurablePhaseLedgerStore,
    ledger_id: str,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    expected_phase: str,
    provider: Provider | None,
    expected_ambiguous_ledger_digest: str,
    expected_ambiguous_operation_digest: str,
    expected_reconciliation_readback_contract_digest: str,
    expected_session_identifier_digest: str,
    expected_effect_state_digest: str,
    expected_no_effect_state_digest: str,
    expected_reconciliation_binding_digest: str,
    at: datetime,
    clock: Callable[[], datetime] | None = None,
    owner_checkpoint_digest: str | None = None,
    live_request_digest: str | None = None,
) -> dict[str, Any]:
    """Reconcile the ledger's exact ambiguous operation without replaying it."""

    reconcile_started_at = _utc(at, "RECONCILIATION_TIME_INVALID")
    if (owner_checkpoint_digest is None) is not (live_request_digest is None):
        _fail("EXECUTION_CONTEXT_INCOMPLETE")
    current = store.read(ledger_id)
    if expected_phase not in FORWARD_PHASES or current.get("phase") != expected_phase:
        _fail("RECONCILIATION_PHASE_BINDING_MISMATCH")
    stored_context = _claim_execution_context(current)
    if stored_context is None:
        _fail("EXECUTION_CONTEXT_REQUIRED")
    if owner_checkpoint_digest is None or live_request_digest is None:
        _fail("EXECUTION_CONTEXT_REQUIRED")
    context = _execution_context(
        owner_checkpoint_digest=str(owner_checkpoint_digest),
        live_request_digest=str(live_request_digest),
        activator_checkpoint_digest=stored_context.get(
            "activator_checkpoint_digest"
        ),
    )
    if current.get("status") == "RECONCILED":
        return _private_reconciliation_run_from_terminal_evidence(
            current,
            expected_plan_digest=expected_plan_digest,
            expected_owner_checkpoint_digest=str(owner_checkpoint_digest),
            expected_live_request_digest=str(live_request_digest),
            private_evidence_root=store.root,
            require_private_evidence=True,
        )
    if current.get("status") == "IN_FLIGHT":
        phase_ledger.recover_persisted_in_flight(
            store=store,
            ledger_id=ledger_id,
            at=reconcile_started_at,
        )
        _fail("IN_FLIGHT_RECOVERED_NEW_AMBIGUOUS_BINDING_REQUIRED")
    if current.get("status") != "AMBIGUOUS":
        _fail("RECONCILIATION_NOT_PERMITTED")
    ambiguous_ledger_digest = _require_digest(
        expected_ambiguous_ledger_digest,
        "EXPECTED_AMBIGUOUS_LEDGER_DIGEST_INVALID",
    )
    ambiguous_operation_digest = _require_digest(
        expected_ambiguous_operation_digest,
        "EXPECTED_AMBIGUOUS_OPERATION_DIGEST_INVALID",
    )
    expected_contract_digest = _require_digest(
        expected_reconciliation_readback_contract_digest,
        "EXPECTED_RECONCILIATION_READBACK_CONTRACT_DIGEST_INVALID",
    )
    expected_session = _require_digest(
        expected_session_identifier_digest,
        "EXPECTED_SESSION_IDENTIFIER_DIGEST_INVALID",
    )
    effect = _require_digest(
        expected_effect_state_digest, "EXPECTED_EFFECT_STATE_DIGEST_INVALID"
    )
    no_effect = _require_digest(
        expected_no_effect_state_digest,
        "EXPECTED_NO_EFFECT_STATE_DIGEST_INVALID",
    )
    expected_binding_digest = _require_digest(
        expected_reconciliation_binding_digest,
        "EXPECTED_RECONCILIATION_BINDING_DIGEST_INVALID",
    )
    if effect == no_effect:
        _fail("RECONCILIATION_EXPECTATIONS_INVALID")
    if current.get("ledger_digest") != ambiguous_ledger_digest:
        _fail("AMBIGUOUS_LEDGER_DIGEST_MISMATCH")
    if current.get("authority_session_identifier_digest") != expected_session:
        _fail("RECONCILIATION_SESSION_BINDING_MISMATCH")

    normalized_plan = validate_plan(
        plan,
        expected_plan_digest=expected_plan_digest,
        expected_account_id=str(current.get("account_id")),
        expected_region=str(current.get("region")),
    )
    if current.get("plan_digest") != normalized_plan.get("plan_digest"):
        _fail("RECONCILIATION_PLAN_BINDING_MISMATCH")
    reconciliation_deadline = min(
        _parse_stamp(current.get("expires_at"), "EXPIRES_AT_INVALID"),
        _parse_stamp(
            current.get("authority_session_expires_at"),
            "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
        ),
    )

    def require_open_reconciliation_window(
        value: datetime, *, not_before: datetime
    ) -> datetime:
        checked = _utc(value, "RECONCILIATION_TIME_INVALID")
        if checked < not_before:
            _fail("RECONCILIATION_TIME_ROLLBACK")
        if checked >= reconciliation_deadline:
            _fail("RECONCILIATION_WINDOW_EXPIRED")
        return checked

    evidence_name = _reconciliation_evidence_file(ledger_id)
    staged = _read_private_custody_record(
        store.root, evidence_name, missing_ok=True
    )
    if staged is not None:
        private_evidence, recovery_binding = (
            _validate_private_reconciliation_evidence_record(
                staged,
                name=evidence_name,
                current=current,
                expected_effect_state_digest=effect,
                expected_no_effect_state_digest=no_effect,
                expected_binding_digest=expected_binding_digest,
                expected_owner_checkpoint_digest=str(owner_checkpoint_digest),
                expected_live_request_digest=str(live_request_digest),
            )
        )
        if (
            recovery_binding.get("ambiguous_operation_digest")
            != ambiguous_operation_digest
            or recovery_binding.get("readback_contract_digest")
            != expected_contract_digest
            or recovery_binding.get("session_identifier_digest")
            != expected_session
        ):
            _fail("PRIVATE_RECONCILIATION_BINDING_INVALID")
        recovered_at = _parse_stamp(
            private_evidence.get("recorded_at"),
            "PRIVATE_RECONCILIATION_TIME_INVALID",
        )
        if recovered_at >= min(
            _parse_stamp(current.get("expires_at"), "EXPIRES_AT_INVALID"),
            _parse_stamp(
                current.get("authority_session_expires_at"),
                "AUTHORITY_SESSION_EXPIRES_AT_INVALID",
            ),
        ):
            _fail("PRIVATE_RECONCILIATION_TIME_INVALID")
        observed = private_evidence["second_capture"][
            "observed_state_digest"
        ]
        recovery_transition = phase_ledger.prepare_read_only_reconciliation(
            current,
            expected_version=current["ledger_version"],
            expected_digest=ambiguous_ledger_digest,
            at=recovered_at,
            observed_state_digest=observed,
            expected_effect_state_digest=effect,
            expected_no_effect_state_digest=no_effect,
            reconciliation_binding=recovery_binding,
        )
        require_open_reconciliation_window(
            (clock or (lambda: reconcile_started_at))(),
            not_before=reconcile_started_at,
        )
        recovered = store.compare_and_swap(recovery_transition)
        return _private_reconciliation_run_from_terminal_evidence(
            recovered,
            expected_plan_digest=expected_plan_digest,
            expected_owner_checkpoint_digest=str(owner_checkpoint_digest),
            expected_live_request_digest=str(live_request_digest),
            private_evidence_root=store.root,
            require_private_evidence=True,
        )
    if provider is None or _provider_mode(provider) != "LIVE":
        _fail("LIVE_PROVIDER_REQUIRED")
    try:
        from tooling import platform_authority_gug365_live_provider as live_provider
    except ImportError as exc:  # pragma: no cover - repository packaging failure
        raise Gug390Error("LIVE_PROVIDER_UNAVAILABLE") from exc
    ambiguous, planned = _exact_ambiguous_planned_call(
        normalized_plan, current, live_provider
    )
    if planned.operation_digest != ambiguous_operation_digest:
        _fail("AMBIGUOUS_OPERATION_DIGEST_MISMATCH")
    try:
        readback_calls = provider.reconciliation_readback_calls(planned)
    except BaseException as exc:
        code = getattr(exc, "code", None)
        if code == "RECONCILIATION_CONTRACT_UNAVAILABLE":
            raise Gug390Error(code) from exc
        if isinstance(code, str) and _TOKEN.fullmatch(code):
            raise Gug390Error(code) from exc
        raise Gug390Error("RECONCILIATION_READBACK_CONTRACT_INVALID") from exc
    contract = _reconciliation_readback_contract(
        planned, readback_calls, live_provider
    )
    if contract["contract_digest"] != expected_contract_digest:
        _fail("RECONCILIATION_READBACK_CONTRACT_DIGEST_MISMATCH")

    first_receipt = _fresh_reconciliation_identity(
        provider,
        live_provider=live_provider,
        current=current,
        expected_session_identifier_digest=expected_session,
    )
    first_state, first_digest, first_private_capture = _capture_reconciliation_state(
        provider,
        ambiguous_operation_digest=ambiguous_operation_digest,
        readback_contract_digest=expected_contract_digest,
        readback_calls=readback_calls,
        capture_index=1,
    )
    second_state, second_digest, second_private_capture = _capture_reconciliation_state(
        provider,
        ambiguous_operation_digest=ambiguous_operation_digest,
        readback_contract_digest=expected_contract_digest,
        readback_calls=readback_calls,
        capture_index=2,
    )
    if first_state != second_state or first_digest != second_digest:
        _fail("RECONCILIATION_READBACK_UNSTABLE")
    final_receipt = _fresh_reconciliation_identity(
        provider,
        live_provider=live_provider,
        current=current,
        expected_session_identifier_digest=expected_session,
    )
    if final_receipt.receipt_digest != first_receipt.receipt_digest:
        _fail("RECONCILIATION_PROVIDER_SESSION_MISMATCH")

    transcript = _provider_transcript(provider)
    if (
        transcript["live_provider_evidence"] is not True
        or transcript["write_call_count"] != 0
        or transcript["identity_receipt_digest"]
        != final_receipt.receipt_digest
        or transcript["call_count"] < 3 + 2 * len(readback_calls)
    ):
        _fail("RECONCILIATION_TRANSCRIPT_INVALID")
    binding_body = _reconciliation_expectation_binding_body(
        current,
        ambiguous=ambiguous,
        ambiguous_operation_digest=ambiguous_operation_digest,
        readback_contract_digest=expected_contract_digest,
        identity_receipt_digest=final_receipt.receipt_digest,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        execution_context=context,
    )
    if canonical_digest(binding_body) != expected_binding_digest:
        _fail("RECONCILIATION_BINDING_DIGEST_MISMATCH")
    reconciliation_binding_body = {
        "ambiguous_ledger_digest": ambiguous_ledger_digest,
        "ambiguous_operation_sequence": ambiguous["operation_sequence"],
        "ambiguous_request_digest": ambiguous["request_digest"],
        "ambiguous_operation_digest": ambiguous_operation_digest,
        "readback_contract_digest": expected_contract_digest,
        "caller_arn_digest": current["caller_arn_digest"],
        "session_identifier_digest": expected_session,
        "identity_receipt_digest": final_receipt.receipt_digest,
        "provider_transcript_digest": transcript["transcript_digest"],
        "provider_transcript_summary_digest": transcript["summary_digest"],
        "provider_call_count": transcript["call_count"],
        "owner_checkpoint_digest": context["owner_checkpoint_digest"],
        "live_request_digest": context["live_request_digest"],
        "execution_context_digest": context["context_digest"],
        "expectation_binding_digest": expected_binding_digest,
    }
    reconcile_at = require_open_reconciliation_window(
        (clock or (lambda: reconcile_started_at))(),
        not_before=reconcile_started_at,
    )
    evidence_name, private_evidence = _private_reconciliation_evidence_record(
        current=current,
        contract=contract,
        first_identity_receipt=_as_mapping(
            first_receipt, "RECONCILIATION_IDENTITY_RECEIPT_INVALID"
        ),
        final_identity_receipt=_as_mapping(
            final_receipt, "RECONCILIATION_IDENTITY_RECEIPT_INVALID"
        ),
        first_capture=first_private_capture,
        second_capture=second_private_capture,
        transcript=transcript,
        reconciliation_binding_body=reconciliation_binding_body,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        recorded_at=reconcile_at,
    )
    persisted = _persist_private_custody_record(
        store.root, evidence_name, private_evidence
    )
    _checked_private, reconciliation_binding = (
        _validate_private_reconciliation_evidence_record(
            persisted,
            name=evidence_name,
            current=current,
            expected_effect_state_digest=effect,
            expected_no_effect_state_digest=no_effect,
            expected_binding_digest=expected_binding_digest,
            expected_owner_checkpoint_digest=str(owner_checkpoint_digest),
            expected_live_request_digest=str(live_request_digest),
        )
    )
    transition = phase_ledger.prepare_read_only_reconciliation(
        current,
        expected_version=current["ledger_version"],
        expected_digest=ambiguous_ledger_digest,
        at=reconcile_at,
        observed_state_digest=second_digest,
        expected_effect_state_digest=effect,
        expected_no_effect_state_digest=no_effect,
        reconciliation_binding=reconciliation_binding,
    )
    private_run = _private_phase_run_from_evidence(
        transition.proposed_record,
        transcript=transcript,
        provider_mode="LIVE",
        causal_evidence=None,
        recovered_in_flight=False,
        command="reconcile",
        activator_checkpoint_digest=context.get(
            "activator_checkpoint_digest"
        ),
        owner_checkpoint_digest=(
            str(context["owner_checkpoint_digest"]) if context is not None else None
        ),
        live_request_digest=(
            str(context["live_request_digest"]) if context is not None else None
        ),
        execution_context_digest=(
            str(context["context_digest"]) if context is not None else None
        ),
    )
    require_open_reconciliation_window(
        (clock or (lambda: reconcile_at))(),
        not_before=reconcile_at,
    )
    terminal = store.compare_and_swap(transition)
    if (
        terminal.get("ledger_digest") != transition.proposed_record["ledger_digest"]
        or terminal.get("status") != transition.proposed_record["status"]
    ):
        _fail("RECONCILIATION_CAS_RESULT_INVALID")
    recovered_run = _private_reconciliation_run_from_terminal_evidence(
        terminal,
        expected_plan_digest=expected_plan_digest,
        expected_owner_checkpoint_digest=str(owner_checkpoint_digest),
        expected_live_request_digest=str(live_request_digest),
        private_evidence_root=store.root,
        require_private_evidence=True,
    )
    if recovered_run != private_run:
        _fail("RECONCILIATION_RECOVERY_MISMATCH")
    return recovered_run


def _validate_private_phase_runs(
    *,
    plan: Mapping[str, Any],
    phase_records: Sequence[Mapping[str, Any]],
    phase_runs: Sequence[Mapping[str, Any]],
    expected_phase_run_digests: Sequence[str],
    execution_mode: str,
    expected_activator_checkpoint_digest: str,
    private_evidence_root: Path | None = None,
) -> dict[str, Any]:
    if len(phase_records) != len(FORWARD_PHASES) or len(phase_runs) != len(
        FORWARD_PHASES
    ):
        _fail("PHASE_RUN_SET_INVALID")
    if (
        not isinstance(expected_phase_run_digests, Sequence)
        or isinstance(expected_phase_run_digests, (str, bytes))
        or len(expected_phase_run_digests) != len(FORWARD_PHASES)
    ):
        _fail("EXPECTED_PHASE_RUN_DIGESTS_INVALID")
    expected_run_digests = [
        _require_digest(item, "EXPECTED_PHASE_RUN_DIGESTS_INVALID")
        for item in expected_phase_run_digests
    ]
    if len(set(expected_run_digests)) != len(expected_run_digests):
        _fail("EXPECTED_PHASE_RUN_DIGESTS_INVALID")
    expected_mode = "LIVE" if execution_mode == "LIVE" else "SYNTHETIC"
    activator_digest = _require_digest(
        expected_activator_checkpoint_digest,
        "EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
    )
    run_digests: list[str] = []
    transcript_digests: list[str] = []
    invoker_evidence: Mapping[str, Any] | None = None
    invoker_record: Mapping[str, Any] | None = None
    invoker_transcript: Mapping[str, Any] | None = None
    extended_context: bool | None = None
    fields = {
        "record_type",
        "schema_version",
        "issue",
        "command",
        "phase",
        "status",
        "classification",
        "ledger_id",
        "ledger_digest",
        "terminal_receipt_digest",
        "provider_mode",
        "transcript",
        "causal_receipt_evidence",
        "activator_checkpoint_digest",
        "owner_checkpoint_digest",
        "live_request_digest",
        "execution_context_digest",
        "recovered_in_flight",
        "retry_permitted",
        "automatic_rollback_permitted",
        "deployment_authorized",
        "production_status",
        "run_digest",
    }
    legacy_fields = fields - {
        "owner_checkpoint_digest",
        "live_request_digest",
        "execution_context_digest",
    }
    for phase, record, raw_run, expected_run_digest in zip(
        FORWARD_PHASES,
        phase_records,
        phase_runs,
        expected_run_digests,
        strict=True,
    ):
        run = _snapshot(raw_run, "PRIVATE_PHASE_RUN_INVALID")
        if not isinstance(record, Mapping) or not isinstance(run, Mapping):
            _fail("PRIVATE_PHASE_RUN_INVALID")
        transcript = run.get("transcript")
        receipts = record.get("receipt_chain")
        terminal_receipt = (
            receipts[-1].get("receipt_digest")
            if isinstance(receipts, list) and receipts and isinstance(receipts[-1], Mapping)
            else None
        )
        claim_context = _claim_execution_context(record)
        extended = claim_context is not None
        if extended_context is None:
            extended_context = extended
        elif extended is not extended_context:
            _fail("PRIVATE_PHASE_RUN_EXECUTION_CONTEXT_MISMATCH")
        if (
            set(run) != (fields if extended else legacy_fields)
            or run.get("record_type") != PRIVATE_RUN_TYPE
            or run.get("schema_version") != 1
            or run.get("issue") != ISSUE
            or run.get("command") != "execute-phase"
            or run.get("phase") != phase
            or record.get("phase") != phase
            or run.get("status") != "CONSUMED"
            or run.get("classification") != "PHASE_CONSUMED"
            or run.get("ledger_id") != record.get("ledger_id")
            or run.get("ledger_digest") != record.get("ledger_digest")
            or run.get("terminal_receipt_digest") != terminal_receipt
            or (
                extended
                and run.get("owner_checkpoint_digest")
                != claim_context["owner_checkpoint_digest"]
            )
            or (
                extended
                and run.get("live_request_digest")
                != claim_context["live_request_digest"]
            )
            or (
                extended
                and run.get("execution_context_digest")
                != claim_context["context_digest"]
            )
            or run.get("provider_mode") != expected_mode
            or run.get("recovered_in_flight") is not False
            or run.get("retry_permitted") is not False
            or run.get("automatic_rollback_permitted") is not False
            or run.get("deployment_authorized") is not False
            or run.get("production_status") != "NO-GO"
            or not isinstance(transcript, Mapping)
        ):
            _fail("PRIVATE_PHASE_RUN_INVALID")
        if expected_mode == "LIVE" and not extended:
            _fail("PRIVATE_PHASE_RUN_EXECUTION_CONTEXT_REQUIRED")
        if expected_mode == "LIVE":
            reconstructed = _private_phase_run_from_terminal_evidence(
                record,
                plan=plan,
                expected_plan_digest=str(plan.get("plan_digest")),
                private_evidence_root=private_evidence_root,
                require_private_evidence=True,
            )
            if run != reconstructed:
                _fail("PRIVATE_PHASE_RUN_DURABLE_EVIDENCE_MISMATCH")
        run_digest = _require_digest(
            run.get("run_digest"), "PRIVATE_PHASE_RUN_DIGEST_INVALID"
        )
        if run_digest != canonical_digest(
            {key: item for key, item in run.items() if key != "run_digest"}
        ):
            _fail("PRIVATE_PHASE_RUN_DIGEST_MISMATCH")
        if run_digest != expected_run_digest:
            _fail("PHASE_RUN_DIGEST_BINDING_MISMATCH")
        transcript_digest = _require_digest(
            transcript.get("transcript_digest"), "PRIVATE_PHASE_RUN_INVALID"
        )
        live_evidence = transcript.get("live_provider_evidence")
        call_count = transcript.get("call_count")
        write_count = transcript.get("write_call_count")
        identity_receipt = transcript.get("identity_receipt_digest")
        summary_digest = transcript.get("summary_digest")
        if (
            live_evidence is not (expected_mode == "LIVE")
            or type(call_count) is not int
            or call_count < 1
            or type(write_count) is not int
            or not 0 <= write_count <= call_count
            or (
                identity_receipt is not None
                and _DIGEST.fullmatch(str(identity_receipt)) is None
            )
            or (
                summary_digest is not None
                and _DIGEST.fullmatch(str(summary_digest)) is None
            )
            or (
                expected_mode == "LIVE"
                and (identity_receipt is None or summary_digest is None)
            )
        ):
            _fail("PRIVATE_PHASE_RUN_PROVIDER_MODE_MISMATCH")
        if phase == "ACTIVATOR":
            if run.get("activator_checkpoint_digest") != activator_digest:
                _fail("ACTIVATOR_CHECKPOINT_DIGEST_MISMATCH")
        elif run.get("activator_checkpoint_digest") is not None:
            _fail("ACTIVATOR_CHECKPOINT_UNEXPECTED")
        evidence = run.get("causal_receipt_evidence")
        if phase == "LEDGER_FACTORY_INVOKER":
            if not isinstance(evidence, Mapping):
                _fail("CAUSAL_RECEIPT_EVIDENCE_REQUIRED")
            invoker_evidence = evidence
            invoker_record = record
            invoker_transcript = transcript
        elif evidence is not None:
            _fail("CAUSAL_RECEIPT_EVIDENCE_UNEXPECTED")
        run_digests.append(run_digest)
        transcript_digests.append(transcript_digest)
    assert invoker_evidence is not None
    assert invoker_record is not None
    assert invoker_transcript is not None
    receipt_digest = _validate_private_causal_receipt(
        plan=plan,
        evidence=invoker_evidence,
        ledger_record=invoker_record,
        transcript=invoker_transcript,
    )
    return {
        "run_digests": run_digests,
        "transcript_digests": transcript_digests,
        "causal_receipt_digest": receipt_digest,
        "activator_checkpoint_digest": activator_digest,
    }


def _validate_private_causal_receipt(
    *,
    plan: Mapping[str, Any],
    evidence: Mapping[str, Any],
    ledger_record: Mapping[str, Any],
    transcript: Mapping[str, Any],
) -> str:
    fields = {
        "record_type",
        "plan_digest",
        "operation_digest",
        "provider_result_digest",
        "receipt_digest",
        "identity_receipt_digest",
        "certification_required",
        "activation_authorized",
        "binding_digest",
        "receipt",
        "private_evidence_digest",
    }
    value = _snapshot(evidence, "CAUSAL_RECEIPT_EVIDENCE_INVALID")
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("CAUSAL_RECEIPT_EVIDENCE_INVALID")
    if value.get("private_evidence_digest") != canonical_digest(
        {key: item for key, item in value.items() if key != "private_evidence_digest"}
    ):
        _fail("CAUSAL_RECEIPT_EVIDENCE_DIGEST_MISMATCH")
    binding = {
        key: item
        for key, item in value.items()
        if key not in {"receipt", "private_evidence_digest", "binding_digest"}
    }
    if value.get("binding_digest") != canonical_digest(binding):
        _fail("CAUSAL_RECEIPT_BINDING_DIGEST_MISMATCH")
    if (
        value.get("record_type")
        != "scanalyze.platform_authority.gug390_private_causal_receipt_binding.v1"
        or value.get("plan_digest") != plan.get("plan_digest")
        or value.get("certification_required") is not True
        or value.get("activation_authorized") is not False
        or transcript.get("accepted_causal_receipt_binding_digest")
        != value.get("binding_digest")
        or transcript.get("identity_receipt_digest")
        != value.get("identity_receipt_digest")
    ):
        _fail("CAUSAL_RECEIPT_BINDING_INVALID")
    phase = next(
        (
            item
            for item in plan.get("authorization_phases", [])
            if isinstance(item, Mapping)
            and item.get("phase") == "LEDGER_FACTORY_INVOKER"
        ),
        None,
    )
    operations = phase.get("operations") if isinstance(phase, Mapping) else None
    matching = [
        operation
        for operation in operations or []
        if isinstance(operation, Mapping)
        and operation.get("api_action") == "InvokeFunction"
    ]
    if len(matching) != 1:
        _fail("CAUSAL_RECEIPT_OPERATION_INVALID")
    operation = matching[0]
    try:
        from tooling import platform_authority_gug365_live_provider as live_provider

        planned = live_provider.planned_call_from_record(
            "LEDGER_FACTORY_INVOKER", operation, plan=plan
        )
    except Exception as exc:
        raise Gug390Error("CAUSAL_RECEIPT_OPERATION_INVALID") from exc
    sequence = operation.get("sequence")
    outcomes = ledger_record.get("operation_outcomes")
    outcome = (
        outcomes[sequence - 1]
        if isinstance(outcomes, list)
        and type(sequence) is int
        and 1 <= sequence <= len(outcomes)
        and isinstance(outcomes[sequence - 1], Mapping)
        else None
    )
    provider_result = _require_digest(
        value.get("provider_result_digest"), "CAUSAL_RECEIPT_BINDING_INVALID"
    )
    if (
        value.get("operation_digest") != planned.operation_digest
        or not isinstance(outcome, Mapping)
        or outcome.get("result") != "SUCCEEDED"
        or outcome.get("provider_result_digest") != provider_result
    ):
        _fail("CAUSAL_RECEIPT_LEDGER_BINDING_MISMATCH")
    receipt = value.get("receipt")
    receipt_digest = _require_digest(
        value.get("receipt_digest"), "CAUSAL_RECEIPT_EVIDENCE_INVALID"
    )
    if not isinstance(receipt, Mapping) or receipt.get("receipt_sha256") != receipt_digest:
        _fail("CAUSAL_RECEIPT_EVIDENCE_INVALID")
    try:
        from tooling import (
            platform_authority_retirement_entrypoint_service_role_materializer as materializer,
        )

        materializer.validate_ledger_factory_causal_receipt(
            plan,
            receipt=receipt,
            expected_receipt_sha256=receipt_digest,
        )
    except Exception as exc:
        raise Gug390Error("CAUSAL_RECEIPT_NOT_ACCEPTED") from exc
    return receipt_digest


def certify_bundle(
    *,
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    expected_bundle_digest: str,
    phase_records: Sequence[Mapping[str, Any]],
    phase_runs: Sequence[Mapping[str, Any]],
    expected_phase_run_digests: Sequence[str],
    expected_phase_bindings: Sequence[Mapping[str, Any]],
    expected_initial_bundle_absence_digest: str,
    expected_final_facts_digest: str,
    expected_final_snapshot_digests: Sequence[str],
    first_snapshot: Mapping[str, Any],
    second_snapshot: Mapping[str, Any],
    source_commit_sha: str,
    source_tree_sha: str,
    execution_mode: str,
    activator_checkpoint: Mapping[str, Any],
    expected_activator_checkpoint_digest: str,
    created_at: datetime,
    owner_checkpoint_digest: str,
    live_request_digest: str,
    private_evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Certify the complete causal chain plus stable provider readback."""

    inventory = classify_stable_inventory(
        first_snapshot,
        second_snapshot,
        plan=plan,
        expected_plan_digest=expected_plan_digest,
        expected_facts_digest=expected_final_facts_digest,
        authorized_before_state_digest=expected_initial_bundle_absence_digest,
        expected_snapshot_digests=expected_final_snapshot_digests,
    )
    if (
        inventory["classification"] != "EXACT_PRESENT_NO_TOUCH"
        or inventory["stable"] is not True
    ):
        _fail("FINAL_PROVIDER_STATE_NOT_PRESENT")
    owner_digest = _require_digest(
        owner_checkpoint_digest, "OWNER_CHECKPOINT_DIGEST_INVALID"
    )
    request_digest = _require_digest(
        live_request_digest, "LIVE_REQUEST_DIGEST_INVALID"
    )
    if execution_mode not in {"LIVE", "SYNTHETIC"}:
        _fail("EXECUTION_MODE_INVALID")
    if inventory["provider_backed"] is not (execution_mode == "LIVE"):
        _fail("LIVE_PROVIDER_EVIDENCE_REQUIRED")
    if execution_mode == "LIVE" and private_evidence_root is None:
        _fail("PRIVATE_PROVIDER_EVIDENCE_ROOT_REQUIRED")
    activator_digest = _validate_activator_checkpoint(
        activator_checkpoint,
        expected_digest=expected_activator_checkpoint_digest,
        at=created_at,
    )
    causal_digest = phase_ledger.validate_consumed_causal_bundle(
        plan,
        expected_plan_digest=expected_plan_digest,
        expected_bundle_digest=expected_bundle_digest,
        phase_records=phase_records,
        expected_phase_bindings=expected_phase_bindings,
        expected_initial_bundle_absence_digest=(
            expected_initial_bundle_absence_digest
        ),
    )
    activator_record = phase_records[-1] if phase_records else None
    receipt_chain = (
        activator_record.get("receipt_chain")
        if isinstance(activator_record, Mapping)
        else None
    )
    terminal_at = (
        _parse_stamp(receipt_chain[-1].get("at"), "FINAL_RECEIPT_TIME_INVALID")
        if isinstance(receipt_chain, list)
        and receipt_chain
        and isinstance(receipt_chain[-1], Mapping)
        else None
    )
    capture_times = [
        _parse_stamp(item, "FINAL_SNAPSHOT_TIME_INVALID")
        for item in inventory["captured_at"]
    ]
    certified_at = _utc(created_at, "CERTIFICATION_TIME_INVALID")
    if (
        terminal_at is None
        or not terminal_at < capture_times[0] < capture_times[1] <= certified_at
        or (certified_at - capture_times[1]).total_seconds() > 900
    ):
        _fail("FINAL_SNAPSHOT_CAUSAL_ORDER_INVALID")
    phase_evidence = _validate_private_phase_runs(
        plan=plan,
        phase_records=phase_records,
        phase_runs=phase_runs,
        expected_phase_run_digests=expected_phase_run_digests,
        execution_mode=execution_mode,
        expected_activator_checkpoint_digest=activator_digest,
        private_evidence_root=private_evidence_root,
    )
    return _public_manifest(
        command="certify",
        phase="NONE",
        live=execution_mode == "LIVE",
        live_status="LIVE_CERTIFICATION_RECORDED",
        source_commit_sha=source_commit_sha,
        source_tree_sha=source_tree_sha,
        plan_digest=expected_plan_digest,
        owner_checkpoint_digest=owner_digest,
        live_request_digest=request_digest,
        checkpoint_digest=activator_digest,
        receipt_digest=canonical_digest(
            {
                "causal_ledger_bundle_digest": causal_digest,
                "causal_receipt_digest": phase_evidence["causal_receipt_digest"],
                "phase_run_digests": phase_evidence["run_digests"],
                "inventory_facts_digest": inventory["facts_digest"],
                "snapshot_digests": inventory["snapshot_digests"],
            }
        ),
        transcript_digest=canonical_digest(
            {
                "inventory": inventory["transcript_digests"],
                "phases": phase_evidence["transcript_digests"],
            }
        ),
        aws_calls=0,
        aws_mutations=0,
        live_receipt_count=(11 if execution_mode == "LIVE" else 0),
        read_only=True,
        reconciliation_only=False,
        created_at=created_at,
    )


def public_inventory_manifest(
    *,
    classification: Mapping[str, Any],
    plan: Mapping[str, Any],
    first_snapshot: Mapping[str, Any],
    second_snapshot: Mapping[str, Any],
    expected_facts_digest: str | None,
    authorized_before_state_digest: str,
    expected_snapshot_digests: Sequence[str] | None = None,
    source_commit_sha: str,
    source_tree_sha: str,
    plan_digest: str,
    phase: str,
    created_at: datetime,
    owner_checkpoint_digest: str,
    live_request_digest: str,
    live_providers: Sequence[Provider] | None = None,
) -> dict[str, Any]:
    """Project a stable inventory result to a digest-only public manifest."""

    value = _snapshot(classification, "INVENTORY_CLASSIFICATION_INVALID")
    recomputed = classify_stable_inventory(
        first_snapshot,
        second_snapshot,
        plan=plan,
        expected_plan_digest=plan_digest,
        expected_facts_digest=expected_facts_digest,
        authorized_before_state_digest=authorized_before_state_digest,
        expected_snapshot_digests=expected_snapshot_digests,
    )
    if (
        not isinstance(value, Mapping)
        or value != recomputed
        or value.get("stable") is not True
    ):
        _fail("INVENTORY_CLASSIFICATION_INVALID")
    live = value.get("provider_backed") is True
    if live:
        if (
            not isinstance(live_providers, Sequence)
            or isinstance(live_providers, (str, bytes))
            or len(live_providers) != 2
        ):
            _fail("LIVE_PROVIDER_PROVENANCE_REQUIRED")
        transcripts = [_provider_transcript(provider) for provider in live_providers]
        if (
            any(_provider_mode(provider) != "LIVE" for provider in live_providers)
            or [item["transcript_digest"] for item in transcripts]
            != value.get("transcript_digests")
            or sum(int(item["call_count"]) for item in transcripts)
            != value.get("provider_calls")
            or any(item["write_call_count"] != 0 for item in transcripts)
        ):
            _fail("LIVE_PROVIDER_PROVENANCE_MISMATCH")
    elif live_providers:
        _fail("LIVE_PROVIDER_PROVENANCE_UNEXPECTED")
    calls = value.get("provider_calls")
    if type(calls) is not int or calls < 1:
        _fail("INVENTORY_CLASSIFICATION_INVALID")
    owner_digest = _require_digest(
        owner_checkpoint_digest, "OWNER_CHECKPOINT_DIGEST_INVALID"
    )
    request_digest = _require_digest(
        live_request_digest, "LIVE_REQUEST_DIGEST_INVALID"
    )
    if (
        value.get("owner_checkpoint_digest") != owner_digest
        or value.get("live_request_digest") != request_digest
    ):
        _fail("INVENTORY_ACTION_CONTEXT_MISMATCH")
    return _public_manifest(
        command="inventory",
        phase=phase,
        live=live,
        live_status="LIVE_INVENTORY_RECORDED",
        source_commit_sha=source_commit_sha,
        source_tree_sha=source_tree_sha,
        plan_digest=plan_digest,
        owner_checkpoint_digest=owner_digest,
        live_request_digest=request_digest,
        checkpoint_digest=str(value.get("facts_digest")),
        receipt_digest=canonical_digest(value),
        transcript_digest=canonical_digest(value.get("transcript_digests")),
        aws_calls=calls if live else 0,
        aws_mutations=0,
        live_receipt_count=2 if live else 0,
        read_only=True,
        reconciliation_only=False,
        created_at=created_at,
    )


def public_phase_manifest(
    *,
    private_run: Mapping[str, Any],
    ledger_record: Mapping[str, Any],
    plan: Mapping[str, Any],
    expected_plan_digest: str,
    source_commit_sha: str,
    source_tree_sha: str,
    plan_digest: str,
    created_at: datetime,
    private_evidence_root: Path | None = None,
) -> dict[str, Any]:
    """Project a private execute/reconcile result to the public schema."""

    value = _snapshot(private_run, "PRIVATE_RUN_INVALID")
    record = _snapshot(ledger_record, "PRIVATE_RUN_LEDGER_INVALID")
    if not isinstance(value, Mapping) or not isinstance(record, Mapping):
        _fail("PRIVATE_RUN_INVALID")
    normalized_plan = validate_plan(
        plan,
        expected_plan_digest=expected_plan_digest,
        expected_account_id=str(record.get("account_id")),
        expected_region=str(record.get("region")),
    )
    if (
        plan_digest != expected_plan_digest
        or record.get("plan_digest") != normalized_plan.get("plan_digest")
    ):
        _fail("PRIVATE_RUN_PLAN_BINDING_MISMATCH")
    if record.get("status") in {"CONSUMED", "AMBIGUOUS"}:
        record_outcomes = record.get("operation_outcomes")
        live_private_evidence = bool(
            isinstance(record_outcomes, list)
            and record_outcomes
            and all(
                isinstance(item, Mapping)
                and isinstance(item.get("durable_provider_evidence"), Mapping)
                and item["durable_provider_evidence"].get("provider_mode")
                == "LIVE"
                for item in record_outcomes
            )
        )
        expected_run = _private_phase_run_from_terminal_evidence(
            record,
            plan=normalized_plan,
            expected_plan_digest=expected_plan_digest,
            private_evidence_root=private_evidence_root,
            require_private_evidence=live_private_evidence,
        )
    elif record.get("status") == "RECONCILED":
        expected_run = _private_reconciliation_run_from_terminal_evidence(
            record,
            expected_plan_digest=expected_plan_digest,
            private_evidence_root=private_evidence_root,
            require_private_evidence=True,
        )
    else:
        _fail("PRIVATE_RUN_LEDGER_NOT_TERMINAL")
    if value != expected_run:
        _fail("PRIVATE_RUN_DURABLE_ORIGIN_MISMATCH")
    owner_digest = _require_digest(
        value.get("owner_checkpoint_digest"),
        "OWNER_CHECKPOINT_DIGEST_INVALID",
    )
    request_digest = _require_digest(
        value.get("live_request_digest"), "LIVE_REQUEST_DIGEST_INVALID"
    )
    transcript = value.get("transcript")
    if not isinstance(transcript, Mapping):
        _fail("PRIVATE_RUN_INVALID")
    calls = transcript.get("call_count")
    writes = transcript.get("write_call_count")
    if type(calls) is not int or calls < 0 or type(writes) is not int or writes < 0:
        _fail("PRIVATE_RUN_INVALID")
    live = value.get("provider_mode") == "LIVE"
    command = str(value["command"])
    uncertain = value.get("classification") == "UNCERTAIN_RECONCILE_ONLY"
    status = (
        "UNCERTAIN_RECONCILE_ONLY"
        if uncertain
        else "LIVE_PHASE_TERMINAL"
        if command == "execute-phase"
        else "LIVE_RECONCILIATION_RECORDED"
    )
    return _public_manifest(
        command=command,
        phase=str(value["phase"]),
        live=live,
        live_status=status,
        source_commit_sha=source_commit_sha,
        source_tree_sha=source_tree_sha,
        plan_digest=plan_digest,
        owner_checkpoint_digest=owner_digest,
        live_request_digest=request_digest,
        checkpoint_digest=str(value["ledger_digest"]),
        receipt_digest=str(value["terminal_receipt_digest"]),
        transcript_digest=str(transcript["transcript_digest"]),
        aws_calls=calls if live else 0,
        aws_mutations=writes if live and command == "execute-phase" else 0,
        live_receipt_count=1 if live else 0,
        read_only=command == "reconcile",
        reconciliation_only=command == "reconcile",
        created_at=created_at,
    )


def _public_manifest(
    *,
    command: str,
    phase: str,
    live: bool,
    live_status: str,
    source_commit_sha: str,
    source_tree_sha: str,
    plan_digest: str,
    owner_checkpoint_digest: str,
    live_request_digest: str,
    checkpoint_digest: str,
    receipt_digest: str,
    transcript_digest: str,
    aws_calls: int,
    aws_mutations: int,
    live_receipt_count: int,
    read_only: bool,
    reconciliation_only: bool,
    created_at: datetime,
) -> dict[str, Any]:
    if command not in {"inventory", "execute-phase", "reconcile", "certify"}:
        _fail("PUBLIC_COMMAND_INVALID")
    if (command == "certify" and phase != "NONE") or (
        command != "certify" and phase not in FORWARD_PHASES
    ):
        _fail("PUBLIC_PHASE_INVALID")
    if any(
        not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None
        for value in (source_commit_sha, source_tree_sha)
    ):
        _fail("SOURCE_BINDING_INVALID")
    for value in (
        plan_digest,
        owner_checkpoint_digest,
        live_request_digest,
        checkpoint_digest,
        receipt_digest,
        transcript_digest,
    ):
        _require_digest(value, "PUBLIC_DIGEST_INVALID")
    if (
        type(aws_calls) is not int
        or aws_calls < 0
        or type(aws_mutations) is not int
        or aws_mutations < 0
        or type(live_receipt_count) is not int
        or live_receipt_count < 0
        or (not live and any((aws_calls, aws_mutations, live_receipt_count)))
        or (live and live_receipt_count < 1)
        or (read_only and aws_mutations != 0)
    ):
        _fail("PUBLIC_COUNTER_INVALID")
    manifest: dict[str, Any] = {
        "record_type": PUBLIC_RECORD_TYPE,
        "schema_version": 1,
        "issue": ISSUE,
        "command": command,
        "phase": phase,
        "classification": (
            "LIVE_PROVIDER_EVIDENCE" if live else "SYNTHETIC_VALIDATED"
        ),
        "status": live_status if live else "LIVE_PROVIDER_NOT_PROVEN",
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "plan_digest": plan_digest,
        "owner_checkpoint_digest": owner_checkpoint_digest,
        "live_request_digest": live_request_digest,
        "checkpoint_digest": checkpoint_digest,
        "receipt_digest": receipt_digest,
        "transcript_digest": transcript_digest,
        "aws_calls": aws_calls,
        "aws_mutations": aws_mutations,
        "live_receipt_count": live_receipt_count,
        "live_provider_evidence": live,
        "read_only": read_only,
        "reconciliation_only": reconciliation_only,
        "deployment_authorized": False,
        "deployment_status": "NOT_DEPLOYED",
        "production": False,
        "production_status": "NO-GO",
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "sanitized": True,
        "created_at": _stamp(_utc(created_at, "PUBLIC_TIME_INVALID")),
        "run_digest": "",
    }
    manifest["run_digest"] = canonical_digest(
        {key: item for key, item in manifest.items() if key != "run_digest"}
    )
    return manifest
