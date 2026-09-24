"""Immutable input bindings for the separate GUG-432 execution lane.

An operation is one fully resolved batch. Generated provider identifiers must
be supplied to a new operation/checkpoint, never interpolated into a write by
the executor. These bindings are integrity records, not owner authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from tooling.platform_authority_gug365_upstream_prerequisites import (
    PHASE_NAMES, UpstreamPrerequisiteError, _validate_request_payload,
)
from tooling.platform_authority_gug376_upstream_live_provider import (
    OPERATION_ROUTES,
    READBACK_PROJECTIONS,
)


class PlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise PlanError("DIGEST_INVALID")
    return value


def canonical_json(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise PlanError("PLAN_VALUE_INVALID") from None
    if len(encoded.encode()) > 1024 * 1024:
        raise PlanError("PLAN_VALUE_TOO_LARGE")
    return encoded


def digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode()).hexdigest()


def _no_bindings(value: Any) -> None:
    if isinstance(value, dict):
        if "response_field" in value:
            raise PlanError("WRITE_REQUEST_UNRESOLVED")
        for item in value.values():
            _no_bindings(item)
    elif isinstance(value, list):
        for item in value:
            _no_bindings(item)
    elif isinstance(value, str) and ("${" in value or "$response" in value):
        raise PlanError("WRITE_REQUEST_UNRESOLVED")


@dataclass(frozen=True, init=False)
class Readback:
    projection: str
    _request_json: str = field(repr=False)
    _expected_json: str = field(repr=False)

    def __init__(self, projection: str, request: Mapping[str, Any],
                 expected_projection: Mapping[str, Any]) -> None:
        if projection not in READBACK_PROJECTIONS:
            raise PlanError("READBACK_PROJECTION_INVALID")
        spec = READBACK_PROJECTIONS[projection]
        if not set(request).issubset(spec.request_keys):
            raise PlanError("READBACK_REQUEST_INVALID")
        object.__setattr__(self, "projection", projection)
        object.__setattr__(self, "_request_json", canonical_json(dict(request)))
        object.__setattr__(self, "_expected_json", canonical_json(dict(expected_projection)))

    @property
    def request(self) -> dict[str, Any]:
        return json.loads(self._request_json)

    @property
    def expected_projection(self) -> dict[str, Any]:
        return json.loads(self._expected_json)

    @property
    def service(self) -> str:
        return READBACK_PROJECTIONS[self.projection].service

    @property
    def method(self) -> str:
        return READBACK_PROJECTIONS[self.projection].method

    def binding(self) -> dict[str, Any]:
        return {"projection": self.projection, "request": self.request,
                "expected_projection": self.expected_projection}


def operation_contract(operation_id: str) -> dict[str, Any]:
    if operation_id not in OPERATION_ROUTES:
        raise PlanError("OPERATION_NOT_IN_CATALOG")
    route = OPERATION_ROUTES[operation_id]
    return {"operation_id": operation_id, "phase": route.phase,
            "service": route.service, "api_name": route.api_name,
            "request_keys": sorted(route.request_keys),
            "wire_guards": ({"ExpectedBucketOwner": "042360977644"}
                            if route.service == "s3" and route.api_name != "CreateBucket" else {}),
            "attempt_limit": 1, "sdk_retry_count": 0}


@dataclass(frozen=True, init=False)
class LiveOperation:
    operation_id: str
    phase: str
    account_id: str
    region: str
    request_digest: str
    before_state_digest: str
    target_state_digest: str
    predecessor_slots_digest: str
    approved_principal_digests: tuple[str, ...]
    before_readbacks: tuple[Readback, ...]
    readbacks: tuple[Readback, ...]
    _request_json: str = field(repr=False)

    def __init__(self, *, operation_id: str, account_id: str, region: str,
                 request: Mapping[str, Any], before_state_digest: str,
                 target_state_digest: str, predecessor_slots_digest: str,
                 before_readbacks: tuple[Readback, ...], readbacks: tuple[Readback, ...],
                 approved_principal_digests: tuple[str, ...] = ()) -> None:
        contract = operation_contract(operation_id)
        if re.fullmatch(r"[0-9]{12}", account_id) is None or region != "us-east-1":
            raise PlanError("OPERATION_SCOPE_INVALID")
        if set(request) != set(contract["request_keys"]):
            raise PlanError("WRITE_REQUEST_KEYS_INVALID")
        raw = canonical_json(dict(request))
        _no_bindings(json.loads(raw))
        if not isinstance(approved_principal_digests, tuple):
            raise PlanError("APPROVED_PRINCIPALS_INVALID")
        for principal in approved_principal_digests:
            require_digest(principal)
        route = OPERATION_ROUTES[operation_id]
        action = ("sso" if route.service == "sso-admin" else route.service) + ":" + route.api_name
        if action in {"kms:CreateKey", "s3:PutBucketPolicy"} and not approved_principal_digests:
            raise PlanError("APPROVED_PRINCIPALS_REQUIRED")
        try:
            _validate_request_payload(contract["phase"], action, json.loads(raw),
                                      allowed_principal_digests=approved_principal_digests)
        except UpstreamPrerequisiteError as exc:
            raise PlanError(exc.code) from None
        if action == "sso:CreatePermissionSet" and request["Name"] != (
                "ScanalyzeAuthorityRetireClass" if "CLASSIFIER" in operation_id else "ScanalyzeAuthorityRetireApprove"):
            raise PlanError("IDENTITY_PERMISSION_SET_TARGET_SUBSTITUTION")
        for items in (before_readbacks, readbacks):
            if not isinstance(items, tuple) or not 1 <= len(items) <= 32:
                raise PlanError("READBACKS_REQUIRED")
            if any(type(item) is not Readback for item in items):
                raise PlanError("READBACK_TYPE_INVALID")
        for item in before_readbacks:
            _no_bindings(item.request)
        # Bind the target contract including typed generated-ID references.
        # Its resolved projection digest is distinct and is externally attested
        # after dispatch. Accepting two independent target declarations is unsafe.
        if target_state_digest != digest([item.binding() for item in readbacks]):
            raise PlanError("TARGET_READBACK_CONTRACT_MISMATCH")
        values = dict(operation_id=operation_id, phase=contract["phase"],
                      account_id=account_id, region=region, _request_json=raw,
                      request_digest=digest(json.loads(raw)),
                      before_state_digest=require_digest(before_state_digest),
                      target_state_digest=require_digest(target_state_digest),
                      predecessor_slots_digest=require_digest(predecessor_slots_digest),
                      approved_principal_digests=approved_principal_digests,
                      before_readbacks=before_readbacks, readbacks=readbacks)
        for name, value in values.items():
            object.__setattr__(self, name, value)

    @property
    def request(self) -> dict[str, Any]:
        return json.loads(self._request_json)

    @property
    def contract_digest(self) -> str:
        return digest(operation_contract(self.operation_id))

    def binding(self) -> dict[str, Any]:
        return {"operation_id": self.operation_id, "phase": self.phase,
                "account_id": self.account_id, "region": self.region,
                "request_contract_digest": self.contract_digest,
                "request_digest": self.request_digest,
                "before_state_digest": self.before_state_digest,
                "target_state_digest": self.target_state_digest,
                "predecessor_slots_digest": self.predecessor_slots_digest,
                "approved_principal_digests": list(self.approved_principal_digests),
                "readbacks_digest": digest([item.binding() for item in self.readbacks]),
                "before_readbacks_digest": digest([item.binding() for item in self.before_readbacks])}


@dataclass(frozen=True, init=False)
class RunPlan:
    """Full nine-phase catalog, with account decisions fixed before creation."""

    _json: str = field(repr=False)
    plan_digest: str
    run_digest: str
    operations: tuple[tuple[str, str], ...]

    def __init__(self, *, source_commit: str, source_tree: str,
                 owner_decisions_digest: str, template_write_set_digest: str,
                 phase_accounts: Mapping[str, str], custody_digest: str,
                 trust_anchor_digest: str, verifier_code_digest: str,
                 run_nonce_digest: str, evidence_mode: str) -> None:
        if evidence_mode not in {"SYNTHETIC", "AWS_TRANSPORT"}:
            raise PlanError("EVIDENCE_MODE_INVALID")
        if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in (source_commit, source_tree)):
            raise PlanError("SOURCE_BINDING_INVALID")
        if set(phase_accounts) != set(PHASE_NAMES) or any(
                not isinstance(value, str) or re.fullmatch(r"[0-9]{12}", value) is None
                for value in phase_accounts.values()):
            raise PlanError("PHASE_ACCOUNTS_INVALID")
        if evidence_mode == "AWS_TRANSPORT" and any(
                account != ("839393571433" if phase == "IDENTITY_CENTER_FOUNDATION" else "042360977644")
                for phase, account in phase_accounts.items()):
            raise PlanError("AUTHORITY_ACCOUNT_SCOPE_INVALID")
        bindings = {"source_commit": source_commit, "source_tree": source_tree,
                    "phase_accounts": dict(phase_accounts), "region": "us-east-1",
                    "evidence_mode": evidence_mode}
        bindings["environment"] = "authority-non-production"
        for name, value in dict(owner_decisions_digest=owner_decisions_digest,
                                template_write_set_digest=template_write_set_digest,
                                custody_digest=custody_digest,
                                trust_anchor_digest=trust_anchor_digest,
                                verifier_code_digest=verifier_code_digest,
                                run_nonce_digest=run_nonce_digest).items():
            bindings[name] = require_digest(value)
        operations = tuple((op, digest(operation_contract(op))) for op in OPERATION_ROUTES)
        bindings["operations"] = [list(op) for op in operations]
        plan_digest = digest(bindings)
        object.__setattr__(self, "_json", canonical_json(bindings))
        object.__setattr__(self, "plan_digest", plan_digest)
        object.__setattr__(self, "run_digest", digest({"plan_digest": plan_digest, "run_nonce_digest": run_nonce_digest}))
        object.__setattr__(self, "operations", operations)

    def binding(self) -> dict[str, Any]:
        return {**json.loads(self._json), "plan_digest": self.plan_digest, "run_digest": self.run_digest}

    def validate_operation(self, operation: LiveOperation) -> None:
        if type(operation) is not LiveOperation:
            raise PlanError("OPERATION_TYPE_INVALID")
        if self.binding()["phase_accounts"][operation.phase] != operation.account_id:
            raise PlanError("PHASE_ACCOUNT_MISMATCH")
        if self.binding()["evidence_mode"] == "AWS_TRANSPORT" and "TargetId" in operation.request:
            if operation.request["TargetId"] != "042360977644":
                raise PlanError("IDENTITY_TARGET_ACCOUNT_MISMATCH")
