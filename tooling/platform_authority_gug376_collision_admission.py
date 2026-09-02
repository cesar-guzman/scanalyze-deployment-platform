"""Private, operation-bound collision admission for the GUG-376 live route.

This module contains no AWS client construction and performs no work at import
time.  It converts one validated GUG-395 result plus the complete GUG-376
retained-name catalog into a one-shot private request.  A separate connected
executor must capture two independent snapshots and one immediate pre-effect
snapshot before this contract can mint a short-lived admission capability.

The public receipt is intentionally insufficient to authorize a mutation.  A
consumer must reopen the owner-only result bundle, request and claim from the
same private root and obtain the opaque capability returned by
``read_route_collision_admission``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    private_target_absent,
    read_private_json,
    write_private_json,
)
from tooling.platform_authority_gug376_collision_catalog import (
    validate_route_collision_catalog,
)
from tooling import platform_authority_gug376_collision_budget as collision_budget
from tooling.platform_authority_gug376_collision_policy import (
    validate_route_collision_policy_set,
)
from tooling.platform_authority_gug376_collision_transcript_contract import (
    COLLISION_PROVIDER_IMPLEMENTATION_DIGEST,
    CollisionTranscriptContractError,
    validate_route_collision_transcript_bundle,
)
IMPLEMENTATION_ISSUE = "GUG-376"
REGION = "us-east-1"
AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
ABSENT_READY = "ABSENT_READY"

REQUEST_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_request.v1"
)
CLAIM_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_claim.v1"
)
SNAPSHOT_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_snapshot.v1"
)
PRIVATE_EVIDENCE_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_private_evidence.v1"
)
RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_receipt.v1"
)
RESULT_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_result.v1"
)
CONSUMPTION_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_admission_consumption.v1"
)

DEFAULT_REQUEST_FILE = "gug376-route-collision-admission-request.json"
DEFAULT_CLAIM_FILE = "gug376-route-collision-admission-claim.json"
DEFAULT_RESULT_FILE = "gug376-route-collision-admission-result.json"
DEFAULT_CONSUMPTION_FILE = (
    "gug376-route-collision-admission-consumption.json"
)
DEFAULT_TRANSCRIPT_FILE = "gug376-route-collision-admission-transcript.json"
TRANSCRIPT_SIDECAR_TYPE = (
    "scanalyze.platform_authority."
    "gug376_route_collision_transcript_sidecar.v1"
)

MAX_WINDOW = timedelta(minutes=15)
MAX_SNAPSHOT_SPAN = timedelta(seconds=60)
MAX_PRE_EFFECT_SEAL_DELAY = timedelta(seconds=5)
MAX_ADMISSION_AGE = timedelta(seconds=10)
LOCAL_DIRECT_SSO = "LOCAL_DIRECT_SSO"
POST_READER_RUNTIME = "POST_READER_RUNTIME"
SESSION_MODES = frozenset({LOCAL_DIRECT_SSO, POST_READER_RUNTIME})
LOCAL_ATOMIC_CLI = "LOCAL_ATOMIC_CLI"
INLINE_BROKER_LAMBDA = "INLINE_BROKER_LAMBDA"
EXECUTION_LOCI = frozenset({LOCAL_ATOMIC_CLI, INLINE_BROKER_LAMBDA})
PHASE_OPERATION_ALLOWLIST: Mapping[str, frozenset[str]] = {
    "artifact-bridge": frozenset(
        {
            "bridge-create:dispatch",
            "bridge-create:execute",
            "bridge-pin:dispatch",
            "bridge-pin:execute",
        }
    ),
    "artifact-foundation": frozenset(
        {
            "foundation-create:dispatch",
            "foundation-create:execute",
            "publish-object",
            "start-signing-job",
            "foundation-access-update:dispatch",
            "foundation-access-update:execute",
            "route-reentry-preexecute:create-change-set",
            "route-reentry-preexecute:execute-change-set",
            "route-reentry-cleanup:create-change-set",
            "route-reentry-cleanup:execute-change-set",
        }
    ),
    "route": frozenset(
        {
            "route:create-change-set",
            "route:execute-change-set",
            "broker-reentry-preexecute:create-change-set",
            "broker-reentry-preexecute:execute-change-set",
            "broker-reentry-cleanup:create-change-set",
            "broker-reentry-cleanup:execute-change-set",
        }
    ),
    "broker": frozenset(
        {
            "broker:create-change-set",
            "broker:execute-change-set",
            "broker-protection:create-change-set",
            "broker-protection:execute-change-set",
            "broker-protection-reentry-rollback:create-change-set",
            "broker-protection-reentry-rollback:execute-change-set",
            "seed-revoke-create-v1",
            "seed-revoke-execute-v1",
        }
    ),
    "delegation": frozenset(
        {"delegation-create-v1", "delegation-execute-v1"}
    ),
    "pep": frozenset(
        {
            "pep-create-v1",
            "pep-execute-v1",
            "pep-protection-create-v1",
            "pep-protection-execute-v1",
        }
    ),
    "retirement": frozenset(
        {
            "delegation-revoke-create-v1",
            "delegation-revoke-execute-v1",
            "route-revoke-create-v1",
            "route-revoke-execute-v1",
            "closeout-gate-v1",
            "bridge-revoke:dispatch",
            "bridge-revoke:execute",
        }
    ),
}


def route_collision_operation_phase(operation: str) -> str:
    """Return the sole reviewed phase for an allowlisted operation."""

    matches = [
        phase
        for phase, operations in PHASE_OPERATION_ALLOWLIST.items()
        if operation in operations
    ]
    if len(matches) != 1:
        _fail("ROUTE_COLLISION_PHASE_OPERATION_INVALID")
    return matches[0]

# ``target.phases`` records relevance, not when a retained name starts to
# exist.  These immutable cohorts name the exact resources produced by each
# successful route step; they are deliberately independent of ``PHASE_ORDER``
# and of every target's ``phases`` value.
_BRIDGE_CREATED_TARGET_IDS = frozenset(
    {
        "management.cfn.artifact-bridge-stack",
        "management.iam.route-broker-recovery",
        "management.sso.artifact-bootstrap",
        "management.sso.broker-seed-cleanup",
        "management.sso.route-seed-cleanup",
    }
)
_FOUNDATION_CREATED_TARGET_IDS = frozenset(
    {
        "authority.cfn.artifact-foundation-stack",
        "authority.kms.artifact-alias",
        "authority.lambda.artifact-code-signing-config",
        "authority.s3.artifact-bucket",
        "authority.signer.artifact-profile",
    }
)
_ROUTE_CREATED_TARGET_IDS = frozenset(
    {
        "management.cfn.temporary-route-stack",
        "management.iam.collision-reader",
        "management.iam.route-broker-creator",
        "management.iam.route-broker-executor",
        "management.sso.broker-invoker",
        "management.sso.broker-seed-creator",
        "management.sso.broker-seed-executor",
    }
)
_BROKER_CREATED_TARGET_IDS = frozenset(
    {
        "authority.cfn.route-broker-stack",
        "authority.dynamodb.route-broker-ledger",
        "authority.iam.scanalyzegug376collisionreader",
        "authority.iam.scanalyzegug376routebrokercreator",
        "authority.iam.scanalyzegug376routebrokerexecutor",
        "authority.iam.scanalyzegug376routecreatedispatchrecovery",
        "authority.iam.scanalyzegug376routeexecutedispatchrecovery",
        "authority.kms.route-broker-ledger-alias",
        "authority.lambda.alias.gug376-route-create-dispatch-recovery.recover-v1",
        "authority.lambda.alias.gug376-route-creator.closeout-gate-v1",
        "authority.lambda.alias.gug376-route-creator.delegation-create-v1",
        "authority.lambda.alias.gug376-route-creator.delegation-revoke-create-v1",
        "authority.lambda.alias.gug376-route-creator.pep-create-v1",
        "authority.lambda.alias.gug376-route-creator.pep-protection-create-v1",
        "authority.lambda.alias.gug376-route-creator.route-revoke-create-v1",
        "authority.lambda.alias.gug376-route-creator.seed-revoke-create-v1",
        "authority.lambda.alias.gug376-route-execute-dispatch-recovery.recover-v1",
        "authority.lambda.alias.gug376-route-executor.delegation-execute-v1",
        "authority.lambda.alias.gug376-route-executor.delegation-revoke-execute-v1",
        "authority.lambda.alias.gug376-route-executor.pep-execute-v1",
        "authority.lambda.alias.gug376-route-executor.pep-protection-execute-v1",
        "authority.lambda.alias.gug376-route-executor.route-revoke-execute-v1",
        "authority.lambda.alias.gug376-route-executor.seed-revoke-execute-v1",
        "authority.lambda.route-broker-code-signing-config",
        "authority.lambda.function.gug376-route-create-dispatch-recovery",
        "authority.lambda.function.gug376-route-creator",
        "authority.lambda.function.gug376-route-execute-dispatch-recovery",
        "authority.lambda.function.gug376-route-executor",
        "authority.logs.gug376-route-create-dispatch-recovery",
        "authority.logs.gug376-route-creator",
        "authority.logs.gug376-route-execute-dispatch-recovery",
        "authority.logs.gug376-route-executor",
    }
)
_DELEGATION_CREATED_TARGET_IDS = frozenset(
    {
        "management.cfn.plan-repair-delegation-stack",
        "management.iam.plan-repair-mutation",
        "management.iam.plan-repair-readback",
        "management.sso.plan-repair",
    }
)
_PEP_CREATED_TARGET_IDS = frozenset(
    {
        "authority.cfn.plan-repair-pep-stack",
        "authority.dynamodb.plan-repair-ledger",
        "authority.iam.scanalyzebootstrapplanrepairexecution",
        "authority.iam.scanalyzebootstrapplanrepairinspector",
        "authority.iam.scanalyzebootstrapplanrepairplan",
        "authority.iam.scanalyzebootstrapplanrepairreconcile",
        "authority.kms.plan-repair-ledger-alias",
        "authority.lambda.alias.plan-policy-plan.plan-v1",
        "authority.lambda.alias.plan-policy-reconcile.reconcile-v1",
        "authority.lambda.alias.plan-policy-repair.repair-v1",
        "authority.lambda.plan-repair-code-signing-config",
        "authority.lambda.function.plan-policy-plan",
        "authority.lambda.function.plan-policy-reconcile",
        "authority.lambda.function.plan-policy-repair",
        "authority.logs.plan-policy-plan",
        "authority.logs.plan-policy-reconcile",
        "authority.logs.plan-policy-repair",
    }
)

ROUTE_CREATED_TARGET_IDS = frozenset().union(
    _BRIDGE_CREATED_TARGET_IDS,
    _FOUNDATION_CREATED_TARGET_IDS,
    _ROUTE_CREATED_TARGET_IDS,
    _BROKER_CREATED_TARGET_IDS,
    _DELEGATION_CREATED_TARGET_IDS,
    _PEP_CREATED_TARGET_IDS,
)
COLLISION_ONLY_TARGET_IDS = frozenset(
    {
        "management.sso.retirement-application",
        "management.sso.retirement-approver",
        "management.sso.retirement-classifier",
    }
)

_PRESENT_THROUGH_BRIDGE = _BRIDGE_CREATED_TARGET_IDS
_PRESENT_THROUGH_FOUNDATION = (
    _PRESENT_THROUGH_BRIDGE | _FOUNDATION_CREATED_TARGET_IDS
)
_PRESENT_THROUGH_ROUTE = _PRESENT_THROUGH_FOUNDATION | _ROUTE_CREATED_TARGET_IDS
_PRESENT_THROUGH_BROKER = _PRESENT_THROUGH_ROUTE | _BROKER_CREATED_TARGET_IDS
_PRESENT_THROUGH_DELEGATION = (
    _PRESENT_THROUGH_BROKER | _DELEGATION_CREATED_TARGET_IDS
)
_PRESENT_THROUGH_PEP = _PRESENT_THROUGH_DELEGATION | _PEP_CREATED_TARGET_IDS

# Canonical operation lifecycle API shared by admission consumers.  CREATE and
# execute operations explicitly differ only where CloudFormation has created a
# stack placeholder but has not yet completed the stack's retained resources.
OPERATION_PRESENT_OWNED_TARGET_IDS: Mapping[str, frozenset[str]] = (
    MappingProxyType(
        {
            "bridge-create:dispatch": frozenset(),
            "bridge-create:execute": frozenset(
                {"management.cfn.artifact-bridge-stack"}
            ),
            "bridge-pin:dispatch": _PRESENT_THROUGH_BRIDGE,
            "bridge-pin:execute": _PRESENT_THROUGH_BRIDGE,
            "foundation-create:dispatch": _PRESENT_THROUGH_BRIDGE,
            "foundation-create:execute": _PRESENT_THROUGH_BRIDGE
            | frozenset({"authority.cfn.artifact-foundation-stack"}),
            "publish-object": _PRESENT_THROUGH_FOUNDATION,
            "start-signing-job": _PRESENT_THROUGH_FOUNDATION,
            "foundation-access-update:dispatch": _PRESENT_THROUGH_FOUNDATION,
            "foundation-access-update:execute": _PRESENT_THROUGH_FOUNDATION,
            "route-reentry-preexecute:create-change-set": (
                _PRESENT_THROUGH_FOUNDATION
                | frozenset({"management.cfn.temporary-route-stack"})
            ),
            "route-reentry-preexecute:execute-change-set": (
                _PRESENT_THROUGH_FOUNDATION
                | frozenset({"management.cfn.temporary-route-stack"})
            ),
            "route-reentry-cleanup:create-change-set": (
                _PRESENT_THROUGH_FOUNDATION
            ),
            "route-reentry-cleanup:execute-change-set": (
                _PRESENT_THROUGH_FOUNDATION
                | frozenset({"management.cfn.temporary-route-stack"})
            ),
            "route:create-change-set": _PRESENT_THROUGH_FOUNDATION,
            "route:execute-change-set": _PRESENT_THROUGH_FOUNDATION
            | frozenset({"management.cfn.temporary-route-stack"}),
            "broker-reentry-preexecute:create-change-set": (
                _PRESENT_THROUGH_ROUTE
                | frozenset({"authority.cfn.route-broker-stack"})
            ),
            "broker-reentry-preexecute:execute-change-set": (
                _PRESENT_THROUGH_ROUTE
                | frozenset({"authority.cfn.route-broker-stack"})
            ),
            "broker-reentry-cleanup:create-change-set": _PRESENT_THROUGH_ROUTE,
            "broker-reentry-cleanup:execute-change-set": (
                _PRESENT_THROUGH_ROUTE
                | frozenset({"authority.cfn.route-broker-stack"})
            ),
            "broker:create-change-set": _PRESENT_THROUGH_ROUTE,
            "broker:execute-change-set": _PRESENT_THROUGH_ROUTE
            | frozenset({"authority.cfn.route-broker-stack"}),
            "broker-protection:create-change-set": _PRESENT_THROUGH_BROKER,
            "broker-protection:execute-change-set": _PRESENT_THROUGH_BROKER,
            "broker-protection-reentry-rollback:create-change-set": (
                _PRESENT_THROUGH_BROKER
            ),
            "broker-protection-reentry-rollback:execute-change-set": (
                _PRESENT_THROUGH_BROKER
            ),
            "seed-revoke-create-v1": _PRESENT_THROUGH_BROKER,
            "seed-revoke-execute-v1": _PRESENT_THROUGH_BROKER,
            "delegation-create-v1": _PRESENT_THROUGH_BROKER,
            "delegation-execute-v1": _PRESENT_THROUGH_BROKER
            | frozenset({"management.cfn.plan-repair-delegation-stack"}),
            "pep-create-v1": _PRESENT_THROUGH_DELEGATION,
            "pep-execute-v1": _PRESENT_THROUGH_DELEGATION
            | frozenset({"authority.cfn.plan-repair-pep-stack"}),
            "pep-protection-create-v1": _PRESENT_THROUGH_PEP,
            "pep-protection-execute-v1": _PRESENT_THROUGH_PEP,
            "delegation-revoke-create-v1": _PRESENT_THROUGH_PEP,
            "delegation-revoke-execute-v1": _PRESENT_THROUGH_PEP,
            "route-revoke-create-v1": _PRESENT_THROUGH_PEP,
            "route-revoke-execute-v1": _PRESENT_THROUGH_PEP,
            "closeout-gate-v1": _PRESENT_THROUGH_PEP,
            "bridge-revoke:dispatch": _PRESENT_THROUGH_FOUNDATION,
            "bridge-revoke:execute": _PRESENT_THROUGH_FOUNDATION,
        }
    )
)

_COLLISION_READER_TARGET_IDS = frozenset(
    {
        "management.iam.collision-reader",
        "authority.iam.scanalyzegug376collisionreader",
    }
)

INLINE_BROKER_LAMBDA_OPERATIONS = frozenset(
    {
        "seed-revoke-create-v1",
        "seed-revoke-execute-v1",
        "delegation-create-v1",
        "delegation-execute-v1",
        "pep-create-v1",
        "pep-execute-v1",
        "pep-protection-create-v1",
        "pep-protection-execute-v1",
        "delegation-revoke-create-v1",
        "delegation-revoke-execute-v1",
        "route-revoke-create-v1",
        "route-revoke-execute-v1",
        "closeout-gate-v1",
    }
)


def collision_session_mode_for_operation(
    operation: str,
    *,
    execution_locus: str = LOCAL_ATOMIC_CLI,
) -> str:
    """Derive the sole reachable session mode for an operation and locus.

    Local CLIs cannot assume either reader: the readers trust only the two
    authority broker service roles and those roles trust only Lambda.  Local
    bootstrap, recovery, and final cleanup therefore use the honest direct-SSO
    mode even after both readers exist.  POST is reserved for the inline broker
    Lambda path, where both service-role provenance and both pre-effect reader
    roles are guaranteed.  Local evidence says ``LOCAL_DIRECT_SSO`` literally
    and never asserts that the reader roles are absent.
    """

    present = OPERATION_PRESENT_OWNED_TARGET_IDS.get(operation)
    if present is None or execution_locus not in EXECUTION_LOCI:
        _fail("ROUTE_COLLISION_PHASE_OPERATION_INVALID")
    if execution_locus == LOCAL_ATOMIC_CLI:
        if operation in INLINE_BROKER_LAMBDA_OPERATIONS:
            _fail("ROUTE_COLLISION_SESSION_MODE_UNREACHABLE")
        return LOCAL_DIRECT_SSO
    if (
        operation not in INLINE_BROKER_LAMBDA_OPERATIONS
        or not _COLLISION_READER_TARGET_IDS.issubset(present)
    ):
        _fail("ROUTE_COLLISION_SESSION_MODE_UNREACHABLE")
    return POST_READER_RUNTIME
ALLOWED_DISPOSITIONS = frozenset(
    {
        "ABSENT_AT_SNAPSHOT",
        "PRESENT_OWNED",
        "NOT_APPLICABLE_GENERATED_ID",
    }
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9-]{2,95}$")
_TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,159}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")


class RouteCollisionAdmissionError(RuntimeError):
    """Stable, public-safe failure from the private admission boundary."""

    def __init__(self, code: str) -> None:
        if not isinstance(code, str) or re.fullmatch(
            r"[A-Z][A-Z0-9_]{2,95}", code
        ) is None:
            code = "ROUTE_COLLISION_ADMISSION_FAILED"
        self.code = code
        super().__init__(f"GUG376_ROUTE_COLLISION_ADMISSION_BLOCKED:{code}")


def _fail(code: str) -> None:
    raise RouteCollisionAdmissionError(code)


def _copy(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise RouteCollisionAdmissionError(code) from exc


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _require_sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RouteCollisionAdmissionError(code) from exc
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if normalized.isoformat().replace("+00:00", "Z") != value:
        _fail(code)
    return normalized


def _stamp(value: datetime, code: str = "ROUTE_COLLISION_CLOCK_INVALID") -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    if field in value:
        _fail("ROUTE_COLLISION_SEAL_INVALID")
    value[field] = canonical_digest(value)
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    digest = _require_digest(value.get(field), code)
    body = {key: item for key, item in value.items() if key != field}
    if digest != canonical_digest(body):
        _fail(code)
    return digest


def _exact(value: Mapping[str, Any], fields: set[str], code: str) -> None:
    if set(value) != fields:
        _fail(code)


def _validate_phase_operation(phase: object, operation: object) -> tuple[str, str]:
    if (
        not isinstance(phase, str)
        or phase not in PHASE_OPERATION_ALLOWLIST
        or not isinstance(operation, str)
        or operation not in PHASE_OPERATION_ALLOWLIST[phase]
    ):
        _fail("ROUTE_COLLISION_PHASE_OPERATION_INVALID")
    return phase, operation


def _effect_request(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        _fail("ROUTE_COLLISION_EFFECT_REQUEST_INVALID")
    checked = _copy(value, "ROUTE_COLLISION_EFFECT_REQUEST_INVALID")
    if (
        not isinstance(checked, dict)
        or len(canonical_json(checked).encode("utf-8")) > 256 * 1024
    ):
        _fail("ROUTE_COLLISION_EFFECT_REQUEST_INVALID")
    return checked


def _expected_identity_bindings(
    request395: Mapping[str, Any],
    *,
    collision_policy_set_digest: str,
) -> dict[str, dict[str, Any]]:
    profiles = request395.get("profiles")
    if not isinstance(profiles, Mapping):
        _fail("ROUTE_COLLISION_GUG395_IDENTITY_BINDING_INVALID")
    checked_policy_digest = _require_digest(
        collision_policy_set_digest,
        "ROUTE_COLLISION_POLICY_BINDING_INVALID",
    )
    result: dict[str, dict[str, Any]] = {}
    for domain, source_domain, account_id in (
        ("authority", "authority", AUTHORITY_ACCOUNT_ID),
        ("management", "identity_center", MANAGEMENT_ACCOUNT_ID),
    ):
        profile = profiles.get(source_domain)
        if not isinstance(profile, Mapping):
            _fail("ROUTE_COLLISION_GUG395_IDENTITY_BINDING_INVALID")
        if profile.get("expected_account_id") != account_id:
            _fail("ROUTE_COLLISION_GUG395_IDENTITY_BINDING_INVALID")
        binding = {
            "account_id": account_id,
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "principal_digest": profile.get("expected_principal_digest"),
            "sso_role_name_digest": profile.get(
                "expected_sso_role_name_digest"
            ),
            "authority_verification_digest": profile.get(
                "authority_verification_digest"
            ),
            "policy_digest": checked_policy_digest,
        }
        for field in (
            "principal_digest",
            "sso_role_name_digest",
            "authority_verification_digest",
            "policy_digest",
        ):
            _require_digest(
                binding[field],
                "ROUTE_COLLISION_GUG395_IDENTITY_BINDING_INVALID",
            )
        result[domain] = binding
    return result


def expected_route_collision_identity_bindings(
    request395: Mapping[str, Any],
    *,
    collision_policy_set_digest: str,
) -> dict[str, dict[str, Any]]:
    """Project the validated GUG-395 direct-SSO bindings for one policy.

    The projection deliberately contains only digests and the two fixed account
    identifiers.  Connected adapters keep profile names and credential material
    private; callers cannot replace a direct read-only identity with an ambient,
    default, chained, or broker identity through this boundary.
    """

    return _expected_identity_bindings(
        request395,
        collision_policy_set_digest=collision_policy_set_digest,
    )


def expected_route_collision_identity_bindings_from_custody(
    *,
    private_root: Path,
    collision_policy_set_digest: str,
) -> dict[str, dict[str, Any]]:
    """Load one admissible GUG-395 result and return digest-only bindings."""

    _bundle, evidence, _receipt = _gug395_bundle(private_root)
    request395 = evidence.get("request")
    if not isinstance(request395, Mapping):
        _fail("ROUTE_COLLISION_GUG395_RESULT_INVALID")
    return expected_route_collision_identity_bindings(
        request395,
        collision_policy_set_digest=collision_policy_set_digest,
    )


def _private_root_digest(private_root: Path) -> str:
    try:
        root = Path(private_root).resolve(strict=True)
        metadata = root.stat()
    except OSError as exc:
        raise RouteCollisionAdmissionError(
            "ROUTE_COLLISION_PRIVATE_ROOT_INVALID"
        ) from exc
    if not root.is_dir() or metadata.st_mode & 0o777 != 0o700:
        _fail("ROUTE_COLLISION_PRIVATE_ROOT_INVALID")
    return canonical_digest({"private_root": str(root)})


def _catalog_targets(catalog: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    validate_route_collision_catalog(catalog)
    targets = catalog.get("targets")
    if not isinstance(targets, list) or not targets:
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    result: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for target in targets:
        if not isinstance(target, Mapping):
            _fail("ROUTE_COLLISION_CATALOG_INVALID")
        target_id = target.get("target_id")
        if (
            not isinstance(target_id, str)
            or _TARGET_ID.fullmatch(target_id) is None
            or target_id in seen
        ):
            _fail("ROUTE_COLLISION_CATALOG_INVALID")
        seen.add(target_id)
        result.append(target)
    return result


def expected_route_collision_dispositions(
    catalog: Mapping[str, Any], phase: str, operation: str
) -> dict[str, str]:
    """Return exact operation-bound dispositions without consulting phases."""

    _validate_phase_operation(phase, operation)
    targets = _catalog_targets(catalog)
    allowlisted_operations = frozenset().union(
        *PHASE_OPERATION_ALLOWLIST.values()
    )
    if set(OPERATION_PRESENT_OWNED_TARGET_IDS) != allowlisted_operations:
        _fail("ROUTE_COLLISION_LIFECYCLE_INVALID")
    catalog_route_created = frozenset(
        str(target["target_id"])
        for target in targets
        if target.get("lifecycle") == "ROUTE_CREATED"
    )
    catalog_collision_only = frozenset(
        str(target["target_id"])
        for target in targets
        if target.get("lifecycle") == "COLLISION_ONLY"
    )
    if (
        catalog_route_created != ROUTE_CREATED_TARGET_IDS
        or catalog_collision_only != COLLISION_ONLY_TARGET_IDS
        or len(targets)
        != len(ROUTE_CREATED_TARGET_IDS) + len(COLLISION_ONLY_TARGET_IDS)
        or any(
            not present_ids <= ROUTE_CREATED_TARGET_IDS
            or present_ids & COLLISION_ONLY_TARGET_IDS
            for present_ids in OPERATION_PRESENT_OWNED_TARGET_IDS.values()
        )
    ):
        _fail("ROUTE_COLLISION_LIFECYCLE_INVALID")
    present_ids = OPERATION_PRESENT_OWNED_TARGET_IDS.get(operation)
    if present_ids is None:
        _fail("ROUTE_COLLISION_LIFECYCLE_INVALID")
    return {
        str(target["target_id"]): (
            "PRESENT_OWNED"
            if target["target_id"] in present_ids
            else "ABSENT_AT_SNAPSHOT"
        )
        for target in targets
    }


def _expected_dispositions(
    catalog: Mapping[str, Any], phase: str, operation: str
) -> dict[str, str]:
    return expected_route_collision_dispositions(catalog, phase, operation)


def _gug395_bundle(
    private_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    # Only the legacy file-backed adapter consumes GUG-395.  Keeping this
    # import local lets the deployable broker use the canonical lifecycle and
    # effect-grant contracts without pulling the preplan/retirement graph.
    from tooling.platform_authority_gug395_preplan_collision_probe import (
        ABSENT_READY,
        DEFAULT_RESULT_FILE as GUG395_RESULT_FILE,
        read_collision_probe_result,
    )

    try:
        result = read_collision_probe_result(private_root=private_root)
        bundle = read_private_json(private_root, GUG395_RESULT_FILE)
    except Exception as exc:
        code = getattr(exc, "code", "ROUTE_COLLISION_GUG395_RESULT_INVALID")
        raise RouteCollisionAdmissionError(str(code)) from exc
    evidence = result.private_evidence
    receipt = result.public_receipt
    if not isinstance(bundle, Mapping):
        _fail("ROUTE_COLLISION_GUG395_RESULT_INVALID")
    _verify_seal(
        bundle,
        "bundle_digest",
        "ROUTE_COLLISION_GUG395_RESULT_INVALID",
    )
    if (
        bundle.get("private_evidence") != evidence
        or bundle.get("public_receipt") != receipt
        or receipt.get("classification") != ABSENT_READY
        or receipt.get("provider_implementation_gate")
        != "READY_FOR_PROVIDER_IMPLEMENTATION"
        or receipt.get("status") != "LIVE_READ_ONLY_PROBE_RECORDED"
        or receipt.get("evidence_complete") is not True
        or receipt.get("evidence_stable") is not True
        or receipt.get("live_provider_evidence") is not True
        or receipt.get("aws_mutations") != 0
    ):
        _fail("ROUTE_COLLISION_GUG395_RESULT_NOT_ADMISSIBLE")
    return dict(bundle), evidence, receipt


def materialize_route_collision_admission_request(
    *,
    private_root: Path,
    gug395_private_root: Path,
    catalog: Mapping[str, Any],
    collision_policy_set: Mapping[str, Any],
    phase: str,
    operation: str,
    effect_request: Mapping[str, Any],
    source_commit_sha: str,
    source_tree_sha: str,
    bootstrap_intent_digest: str,
    effect_private_root_digest: str,
    atomic_context_digest: str,
    expected_gug395_request_digest: str,
    expected_gug395_receipt_digest: str,
    expected_gug395_bundle_digest: str,
    expected_identities: Mapping[str, Any] | None = None,
    not_before: str,
    expires_at: str,
    created_at: str,
) -> dict[str, Any]:
    """Build one private request without making an AWS call."""

    checked_catalog = _copy(catalog, "ROUTE_COLLISION_CATALOG_INVALID")
    validate_route_collision_catalog(checked_catalog)
    checked_policy_set = _copy(
        collision_policy_set,
        "ROUTE_COLLISION_POLICY_BINDING_INVALID",
    )
    if not isinstance(checked_policy_set, Mapping):
        _fail("ROUTE_COLLISION_POLICY_BINDING_INVALID")
    try:
        validate_route_collision_policy_set(
            checked_policy_set,
            catalog=checked_catalog,
        )
    except Exception as exc:
        raise RouteCollisionAdmissionError(
            "ROUTE_COLLISION_POLICY_BINDING_INVALID"
        ) from exc
    collision_policy_set_digest = _require_digest(
        checked_policy_set.get("policy_set_digest"),
        "ROUTE_COLLISION_POLICY_BINDING_INVALID",
    )
    collision_policy_digests = _copy(
        checked_policy_set.get("policy_digests"),
        "ROUTE_COLLISION_POLICY_BINDING_INVALID",
    )
    collision_policy_stage = checked_policy_set.get("stage")
    collision_discovery_provenance_digest = checked_policy_set.get(
        "discovery_provenance_digest"
    )
    if (
        not isinstance(collision_policy_digests, Mapping)
        or collision_policy_stage
        not in {"inventory", "inventory-and-candidate-detail"}
        or (
            collision_policy_stage == "inventory"
            and collision_discovery_provenance_digest is not None
        )
        or (
            collision_policy_stage == "inventory-and-candidate-detail"
            and _DIGEST.fullmatch(
                str(collision_discovery_provenance_digest)
            )
            is None
        )
    ):
        _fail("ROUTE_COLLISION_POLICY_BINDING_INVALID")
    targets = _catalog_targets(checked_catalog)
    commit = _require_sha(source_commit_sha, "ROUTE_COLLISION_SOURCE_INVALID")
    tree = _require_sha(source_tree_sha, "ROUTE_COLLISION_SOURCE_INVALID")
    bootstrap_digest = _require_digest(
        bootstrap_intent_digest,
        "ROUTE_COLLISION_BOOTSTRAP_BINDING_INVALID",
    )
    effect_root_digest = _require_digest(
        effect_private_root_digest,
        "ROUTE_COLLISION_EFFECT_ROOT_BINDING_INVALID",
    )
    context_digest = _require_digest(
        atomic_context_digest,
        "ROUTE_COLLISION_ATOMIC_CONTEXT_BINDING_INVALID",
    )
    expected_request395_digest = _require_digest(
        expected_gug395_request_digest,
        "ROUTE_COLLISION_GUG395_LINEAGE_BINDING_INVALID",
    )
    expected_receipt395_digest = _require_digest(
        expected_gug395_receipt_digest,
        "ROUTE_COLLISION_GUG395_LINEAGE_BINDING_INVALID",
    )
    expected_bundle395_digest = _require_digest(
        expected_gug395_bundle_digest,
        "ROUTE_COLLISION_GUG395_LINEAGE_BINDING_INVALID",
    )
    checked_phase, checked_operation = _validate_phase_operation(
        phase, operation
    )
    execution_locus = LOCAL_ATOMIC_CLI
    session_mode = collision_session_mode_for_operation(
        checked_operation,
        execution_locus=execution_locus,
    )
    checked_effect = _effect_request(effect_request)
    effect_digest = canonical_digest(checked_effect)
    start = _parse_time(not_before, "ROUTE_COLLISION_WINDOW_INVALID")
    end = _parse_time(expires_at, "ROUTE_COLLISION_WINDOW_INVALID")
    created = _parse_time(created_at, "ROUTE_COLLISION_WINDOW_INVALID")
    if not start <= created < end or end - start > MAX_WINDOW:
        _fail("ROUTE_COLLISION_WINDOW_INVALID")
    if (
        checked_catalog.get("source_commit_sha") != commit
        or checked_catalog.get("source_tree_sha") != tree
        or checked_catalog.get("bootstrap_intent_digest") != bootstrap_digest
        or checked_catalog.get("not_before") != not_before
        or checked_catalog.get("expires_at") != expires_at
        or checked_catalog.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or checked_catalog.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
        or checked_catalog.get("region") != REGION
        or checked_catalog.get("target_count") != len(targets)
    ):
        _fail("ROUTE_COLLISION_CATALOG_BINDING_INVALID")
    custody_digest = _private_root_digest(private_root)
    gug395_custody_digest = _private_root_digest(gug395_private_root)
    if (
        custody_digest == gug395_custody_digest
        or effect_root_digest in {custody_digest, gug395_custody_digest}
    ):
        _fail("ROUTE_COLLISION_PRIVATE_CUSTODY_MISMATCH")
    bundle, evidence, receipt = _gug395_bundle(gug395_private_root)
    if (
        evidence.get("request_digest") != expected_request395_digest
        or receipt.get("receipt_digest") != expected_receipt395_digest
        or bundle.get("bundle_digest") != expected_bundle395_digest
    ):
        _fail("ROUTE_COLLISION_GUG395_LINEAGE_CHANGED")
    request395 = evidence.get("request")
    if not isinstance(request395, Mapping):
        _fail("ROUTE_COLLISION_GUG395_RESULT_INVALID")
    if (
        receipt.get("source_commit_sha") != commit
        or receipt.get("source_tree_sha") != tree
        or _parse_time(
            str(receipt.get("sealed_at")),
            "ROUTE_COLLISION_GUG395_RESULT_INVALID",
        )
        > created
    ):
        _fail("ROUTE_COLLISION_GUG395_RESULT_STALE")
    targets395 = request395.get("targets")
    artifact395 = (
        targets395.get("artifact_bucket")
        if isinstance(targets395, Mapping)
        else None
    )
    if (
        not isinstance(artifact395, Mapping)
        or artifact395.get("selector_kind")
        != "ACCOUNT_REGIONAL_BUCKET_NAME_AND_TAG"
        or artifact395.get("bucket_namespace") != "account-regional"
        or artifact395.get("name")
        != checked_catalog.get("artifact_bucket_name")
    ):
        _fail("ROUTE_COLLISION_GUG395_TARGET_BINDING_INVALID")
    if (
        request395.get("private_custody_digest") != gug395_custody_digest
    ):
        _fail("ROUTE_COLLISION_PRIVATE_CUSTODY_MISMATCH")
    lineage_identities = _expected_identity_bindings(
        request395,
        collision_policy_set_digest=collision_policy_set_digest,
    )
    if expected_identities is None:
        checked_identities = lineage_identities
    else:
        checked_identities = _copy(
            expected_identities,
            "ROUTE_COLLISION_IDENTITY_BINDING_INVALID",
        )
        if checked_identities != lineage_identities:
            _fail("ROUTE_COLLISION_GUG395_LINEAGE_CHANGED")
    expected = _expected_dispositions(
        checked_catalog, checked_phase, checked_operation
    )
    request = {
        "record_type": REQUEST_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "source_commit_sha": commit,
        "source_tree_sha": tree,
        "bootstrap_intent_digest": bootstrap_digest,
        "effect_private_root_digest": effect_root_digest,
        "atomic_context_digest": context_digest,
        "phase": checked_phase,
        "operation": checked_operation,
        "execution_locus": execution_locus,
        "session_mode": session_mode,
        "collision_budget_digest": collision_budget.collision_budget_digest(
            session_mode=session_mode,
            operation=checked_operation,
        ),
        "effect_request": checked_effect,
        "effect_request_digest": effect_digest,
        "catalog": checked_catalog,
        "catalog_digest": checked_catalog["catalog_digest"],
        "collision_policy_set_digest": collision_policy_set_digest,
        "collision_policy_digests": collision_policy_digests,
        "collision_policy_stage": collision_policy_stage,
        "collision_discovery_provenance_digest": (
            collision_discovery_provenance_digest
        ),
        "collision_provider_implementation_digest": (
            COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        ),
        "expected_dispositions": expected,
        "expected_dispositions_digest": canonical_digest(expected),
        "gug395_result_bundle_digest": bundle["bundle_digest"],
        "gug395_request_digest": evidence["request_digest"],
        "gug395_receipt_digest": receipt["receipt_digest"],
        "gug395_provider_evidence_digest": evidence[
            "provider_evidence_digest"
        ],
        "gug395_source_verification_digest": request395[
            "source_verification_digest"
        ],
        "gug395_private_root_digest": gug395_custody_digest,
        "private_custody_digest": custody_digest,
        "expected_identities": checked_identities,
        "expected_identities_digest": canonical_digest(checked_identities),
        "not_before": not_before,
        "expires_at": expires_at,
        "created_at": created_at,
        "window_digest": canonical_digest(
            {"not_before": not_before, "expires_at": expires_at}
        ),
    }
    return _seal(request, "request_digest")


_REQUEST_FIELDS = {
    "record_type",
    "schema_version",
    "implementation_issue",
    "source_commit_sha",
    "source_tree_sha",
    "bootstrap_intent_digest",
    "effect_private_root_digest",
    "atomic_context_digest",
    "phase",
    "operation",
    "execution_locus",
    "session_mode",
    "collision_budget_digest",
    "effect_request",
    "effect_request_digest",
    "catalog",
    "catalog_digest",
    "collision_policy_set_digest",
    "collision_policy_digests",
    "collision_policy_stage",
    "collision_discovery_provenance_digest",
    "collision_provider_implementation_digest",
    "expected_dispositions",
    "expected_dispositions_digest",
    "gug395_result_bundle_digest",
    "gug395_request_digest",
    "gug395_receipt_digest",
    "gug395_provider_evidence_digest",
    "gug395_source_verification_digest",
    "gug395_private_root_digest",
    "private_custody_digest",
    "expected_identities",
    "expected_identities_digest",
    "not_before",
    "expires_at",
    "created_at",
    "window_digest",
    "request_digest",
}


def validate_route_collision_admission_request(
    request: Mapping[str, Any],
) -> None:
    value = _copy(request, "ROUTE_COLLISION_REQUEST_INVALID")
    if not isinstance(value, Mapping):
        _fail("ROUTE_COLLISION_REQUEST_INVALID")
    _exact(value, _REQUEST_FIELDS, "ROUTE_COLLISION_REQUEST_FIELDS_INVALID")
    if (
        value.get("record_type") != REQUEST_TYPE
        or value.get("schema_version") != 1
        or value.get("implementation_issue") != IMPLEMENTATION_ISSUE
    ):
        _fail("ROUTE_COLLISION_REQUEST_INVALID")
    _validate_phase_operation(value.get("phase"), value.get("operation"))
    if (
        value.get("execution_locus") != LOCAL_ATOMIC_CLI
        or value.get("session_mode")
        != collision_session_mode_for_operation(
            str(value.get("operation")),
            execution_locus=LOCAL_ATOMIC_CLI,
        )
    ):
        _fail("ROUTE_COLLISION_SESSION_MODE_INVALID")
    _require_sha(value.get("source_commit_sha"), "ROUTE_COLLISION_SOURCE_INVALID")
    _require_sha(value.get("source_tree_sha"), "ROUTE_COLLISION_SOURCE_INVALID")
    for field in (
        "bootstrap_intent_digest",
        "effect_private_root_digest",
        "atomic_context_digest",
        "collision_budget_digest",
        "catalog_digest",
        "collision_policy_set_digest",
        "collision_provider_implementation_digest",
        "expected_dispositions_digest",
        "gug395_result_bundle_digest",
        "gug395_request_digest",
        "gug395_receipt_digest",
        "gug395_provider_evidence_digest",
        "gug395_source_verification_digest",
        "gug395_private_root_digest",
        "private_custody_digest",
        "effect_request_digest",
        "expected_identities_digest",
        "window_digest",
    ):
        _require_digest(value.get(field), "ROUTE_COLLISION_REQUEST_INVALID")
    checked_effect = _effect_request(value.get("effect_request"))
    if value.get("effect_request_digest") != canonical_digest(checked_effect):
        _fail("ROUTE_COLLISION_EFFECT_BINDING_INVALID")
    if len(
        {
            value.get("effect_private_root_digest"),
            value.get("private_custody_digest"),
            value.get("gug395_private_root_digest"),
        }
    ) != 3:
        _fail("ROUTE_COLLISION_EFFECT_ROOT_BINDING_INVALID")
    try:
        expected_budget_digest = collision_budget.collision_budget_digest(
            session_mode=str(value.get("session_mode")),
            operation=str(value.get("operation")),
        )
    except collision_budget.CollisionBudgetError:
        _fail("ROUTE_COLLISION_BUDGET_BINDING_INVALID")
    if value.get("collision_budget_digest") != expected_budget_digest:
        _fail("ROUTE_COLLISION_BUDGET_BINDING_INVALID")
    catalog = value.get("catalog")
    if not isinstance(catalog, Mapping):
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    validate_route_collision_catalog(catalog)
    if (
        value["catalog_digest"] != catalog["catalog_digest"]
        or catalog.get("source_commit_sha") != value["source_commit_sha"]
        or catalog.get("source_tree_sha") != value["source_tree_sha"]
        or catalog.get("bootstrap_intent_digest")
        != value["bootstrap_intent_digest"]
    ):
        _fail("ROUTE_COLLISION_CATALOG_BINDING_INVALID")
    policy_digests = value.get("collision_policy_digests")
    policy_stage = value.get("collision_policy_stage")
    discovery_provenance_digest = value.get(
        "collision_discovery_provenance_digest"
    )
    if (
        not isinstance(policy_digests, Mapping)
        or set(policy_digests) != {"authority", "management"}
        or policy_stage not in {"inventory", "inventory-and-candidate-detail"}
        or (
            policy_stage == "inventory"
            and discovery_provenance_digest is not None
        )
        or (
            policy_stage == "inventory-and-candidate-detail"
            and _DIGEST.fullmatch(str(discovery_provenance_digest))
            is None
        )
        or value.get("collision_provider_implementation_digest")
        != COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
    ):
        _fail("ROUTE_COLLISION_POLICY_BINDING_INVALID")
    for domain in ("authority", "management"):
        domain_digests = policy_digests.get(domain)
        if not isinstance(domain_digests, Mapping) or not domain_digests:
            _fail("ROUTE_COLLISION_POLICY_BINDING_INVALID")
        for digest in domain_digests.values():
            _require_digest(
                digest,
                "ROUTE_COLLISION_POLICY_BINDING_INVALID",
            )
    expected = _expected_dispositions(
        catalog,
        str(value.get("phase")),
        str(value.get("operation")),
    )
    if (
        value.get("expected_dispositions") != expected
        or value.get("expected_dispositions_digest")
        != canonical_digest(expected)
    ):
        _fail("ROUTE_COLLISION_DISPOSITIONS_INVALID")
    identities = value.get("expected_identities")
    if not isinstance(identities, Mapping) or set(identities) != {
        "authority",
        "management",
    }:
        _fail("ROUTE_COLLISION_IDENTITY_BINDING_INVALID")
    for domain, account_id in (
        ("authority", AUTHORITY_ACCOUNT_ID),
        ("management", MANAGEMENT_ACCOUNT_ID),
    ):
        binding = identities.get(domain)
        direct_fields = {
            "account_id",
            "source",
            "chain_depth",
            "principal_digest",
            "sso_role_name_digest",
            "authority_verification_digest",
            "policy_digest",
        }
        broker_fields = direct_fields | {
            "role_arn_digest",
            "role_policy_digest",
            "session_policy_digest",
        }
        source = binding.get("source") if isinstance(binding, Mapping) else None
        expected_source = (
            "DIRECT_SSO"
            if value.get("session_mode") == LOCAL_DIRECT_SSO
            else "BROKER_SERVICE_ROLE"
        )
        expected_fields = (
            direct_fields if source == "DIRECT_SSO" else broker_fields
        )
        if (
            not isinstance(binding, Mapping)
            or source not in {"DIRECT_SSO", "BROKER_SERVICE_ROLE"}
            or source != expected_source
            or set(binding) != expected_fields
        ):
            _fail("ROUTE_COLLISION_IDENTITY_BINDING_INVALID")
        if (
            binding.get("account_id") != account_id
            or binding.get("chain_depth")
            != (0 if source == "DIRECT_SSO" else 1)
        ):
            _fail("ROUTE_COLLISION_IDENTITY_BINDING_INVALID")
        digest_fields = [
            "principal_digest",
            "sso_role_name_digest",
            "authority_verification_digest",
            "policy_digest",
        ]
        if source == "BROKER_SERVICE_ROLE":
            digest_fields.extend(
                (
                    "role_arn_digest",
                    "role_policy_digest",
                    "session_policy_digest",
                )
            )
        for field in digest_fields:
            _require_digest(
                binding.get(field),
                "ROUTE_COLLISION_IDENTITY_BINDING_INVALID",
            )
        if binding.get("policy_digest") != value.get(
            "collision_policy_set_digest"
        ):
            _fail("ROUTE_COLLISION_POLICY_BINDING_INVALID")
    if value.get("expected_identities_digest") != canonical_digest(identities):
        _fail("ROUTE_COLLISION_IDENTITY_BINDING_INVALID")
    start = _parse_time(value.get("not_before"), "ROUTE_COLLISION_WINDOW_INVALID")
    end = _parse_time(value.get("expires_at"), "ROUTE_COLLISION_WINDOW_INVALID")
    created = _parse_time(value.get("created_at"), "ROUTE_COLLISION_WINDOW_INVALID")
    if (
        not start <= created < end
        or end - start > MAX_WINDOW
        or value.get("window_digest")
        != canonical_digest(
            {"not_before": value["not_before"], "expires_at": value["expires_at"]}
        )
    ):
        _fail("ROUTE_COLLISION_WINDOW_INVALID")
    _verify_seal(value, "request_digest", "ROUTE_COLLISION_REQUEST_DIGEST_MISMATCH")


def persist_route_collision_admission_request(
    *, private_root: Path, request: Mapping[str, Any]
) -> None:
    validate_route_collision_admission_request(request)
    try:
        private_target_absent(private_root, DEFAULT_REQUEST_FILE)
        private_target_absent(private_root, DEFAULT_CLAIM_FILE)
        private_target_absent(private_root, DEFAULT_RESULT_FILE)
        private_target_absent(private_root, DEFAULT_TRANSCRIPT_FILE)
        private_target_absent(private_root, DEFAULT_CONSUMPTION_FILE)
        write_private_json(private_root, DEFAULT_REQUEST_FILE, dict(request))
        if read_private_json(private_root, DEFAULT_REQUEST_FILE) != dict(request):
            _fail("ROUTE_COLLISION_REQUEST_READBACK_MISMATCH")
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc


class RouteCollisionAdmissionExecutionCapability:
    """Opaque one-shot authority for the connected read-only executor."""

    __slots__ = ("_token", "_request", "_private_root", "_claim", "_active")

    def __init__(
        self,
        *,
        token: object,
        request: Mapping[str, Any],
        private_root: Path,
        claim: Mapping[str, Any],
    ) -> None:
        self._token = token
        self._request = _copy(request, "ROUTE_COLLISION_REQUEST_INVALID")
        self._private_root = Path(private_root)
        self._claim = _copy(claim, "ROUTE_COLLISION_CLAIM_INVALID")
        self._active = True


_EXECUTION_TOKEN = object()

_CLAIM_FIELDS = {
    "record_type",
    "schema_version",
    "request_digest",
    "catalog_digest",
    "operation",
    "effect_request_digest",
    "claimed_at",
    "aws_calls",
    "aws_mutations",
    "claim_digest",
}


def _validate_claim(
    claim: Mapping[str, Any], *, request: Mapping[str, Any]
) -> dict[str, Any]:
    value = _copy(claim, "ROUTE_COLLISION_CLAIM_INVALID")
    if not isinstance(value, Mapping):
        _fail("ROUTE_COLLISION_CLAIM_INVALID")
    _exact(value, _CLAIM_FIELDS, "ROUTE_COLLISION_CLAIM_FIELDS_INVALID")
    claimed_at = _parse_time(
        value.get("claimed_at"), "ROUTE_COLLISION_CLAIM_INVALID"
    )
    active_from = max(
        _parse_time(
            request.get("not_before"), "ROUTE_COLLISION_WINDOW_INVALID"
        ),
        _parse_time(
            request.get("created_at"), "ROUTE_COLLISION_WINDOW_INVALID"
        ),
    )
    if (
        value.get("record_type") != CLAIM_TYPE
        or value.get("schema_version") != 1
        or value.get("request_digest") != request.get("request_digest")
        or value.get("catalog_digest") != request.get("catalog_digest")
        or value.get("operation") != request.get("operation")
        or value.get("effect_request_digest")
        != request.get("effect_request_digest")
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or not active_from <= claimed_at
        < _parse_time(
            request.get("expires_at"), "ROUTE_COLLISION_WINDOW_INVALID"
        )
    ):
        _fail("ROUTE_COLLISION_CLAIM_INVALID")
    _verify_seal(value, "claim_digest", "ROUTE_COLLISION_CLAIM_INVALID")
    return dict(value)


def read_and_claim_route_collision_admission_request(
    *,
    private_root: Path,
    expected_request_digest: str,
    now: datetime,
) -> RouteCollisionAdmissionExecutionCapability:
    checked_digest = _require_digest(
        expected_request_digest, "ROUTE_COLLISION_REQUEST_DIGEST_INVALID"
    )
    checked_now = _parse_time(_stamp(now), "ROUTE_COLLISION_CLOCK_INVALID")
    try:
        request = read_private_json(private_root, DEFAULT_REQUEST_FILE)
        private_target_absent(private_root, DEFAULT_CLAIM_FILE)
        private_target_absent(private_root, DEFAULT_RESULT_FILE)
        private_target_absent(private_root, DEFAULT_TRANSCRIPT_FILE)
        private_target_absent(private_root, DEFAULT_CONSUMPTION_FILE)
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    validate_route_collision_admission_request(request)
    active_from = max(
        _parse_time(request["not_before"], "ROUTE_COLLISION_WINDOW_INVALID"),
        _parse_time(request["created_at"], "ROUTE_COLLISION_WINDOW_INVALID"),
    )
    if (
        request["request_digest"] != checked_digest
        or request["private_custody_digest"] != _private_root_digest(private_root)
        or not active_from <= checked_now
        < _parse_time(request["expires_at"], "ROUTE_COLLISION_WINDOW_INVALID")
    ):
        _fail("ROUTE_COLLISION_REQUEST_NOT_ACTIVE")
    claim = {
        "record_type": CLAIM_TYPE,
        "schema_version": 1,
        "request_digest": request["request_digest"],
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "claimed_at": _stamp(now),
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    _seal(claim, "claim_digest")
    _validate_claim(claim, request=request)
    try:
        write_private_json(private_root, DEFAULT_CLAIM_FILE, claim)
        if read_private_json(private_root, DEFAULT_CLAIM_FILE) != claim:
            _fail("ROUTE_COLLISION_CLAIM_READBACK_MISMATCH")
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    return RouteCollisionAdmissionExecutionCapability(
        token=_EXECUTION_TOKEN,
        request=request,
        private_root=private_root,
        claim=claim,
    )


def approved_route_collision_admission_request(
    capability: object,
) -> dict[str, Any]:
    if (
        type(capability) is not RouteCollisionAdmissionExecutionCapability
        or capability._token is not _EXECUTION_TOKEN
        or capability._active is not True
    ):
        _fail("ROUTE_COLLISION_EXECUTION_CAPABILITY_INVALID")
    validate_route_collision_admission_request(capability._request)
    _validate_claim(capability._claim, request=capability._request)
    return _copy(capability._request, "ROUTE_COLLISION_REQUEST_INVALID")


def _validate_identity(
    value: object, domain: str, *, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    direct_fields = {
        "domain",
        "account_id",
        "region",
        "source",
        "chain_depth",
        "session_digest",
        "principal_digest",
        "sso_role_name_digest",
        "observed_at",
        "policy_digest",
        "authority_verification_digest",
    }
    expected = request.get("expected_identities", {}).get(domain)
    if not isinstance(expected, Mapping):
        _fail("ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    broker_fields = direct_fields | {
        "role_arn_digest",
        "role_policy_digest",
        "session_policy_digest",
    }
    source = expected.get("source")
    _exact(
        value,
        direct_fields if source == "DIRECT_SSO" else broker_fields,
        "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
    )
    if (
        value.get("domain") != domain
        or value.get("account_id") != expected.get("account_id")
        or _ACCOUNT.fullmatch(str(value.get("account_id"))) is None
        or value.get("region") != REGION
        or value.get("source") != expected.get("source")
        or value.get("chain_depth") != expected.get("chain_depth")
        or value.get("principal_digest") != expected.get("principal_digest")
        or value.get("sso_role_name_digest")
        != expected.get("sso_role_name_digest")
        or value.get("policy_digest") != expected.get("policy_digest")
        or value.get("authority_verification_digest")
        != expected.get("authority_verification_digest")
        or (
            source == "BROKER_SERVICE_ROLE"
            and any(
                value.get(field) != expected.get(field)
                for field in (
                    "role_arn_digest",
                    "role_policy_digest",
                    "session_policy_digest",
                )
            )
        )
    ):
        _fail("ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    digest_fields = [
        "session_digest",
        "principal_digest",
        "sso_role_name_digest",
        "policy_digest",
        "authority_verification_digest",
    ]
    if source == "BROKER_SERVICE_ROLE":
        digest_fields.extend(
            (
                "role_arn_digest",
                "role_policy_digest",
                "session_policy_digest",
            )
        )
    for field in digest_fields:
        _require_digest(value.get(field), "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    _parse_time(value.get("observed_at"), "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    return value


_SNAPSHOT_FIELDS = {
    "record_type",
    "schema_version",
    "capture_index",
    "request_digest",
    "catalog_digest",
    "operation",
    "effect_request_digest",
    "identities",
    "target_observations",
    "semantic_facts_digest",
    "transcript_digest",
    "complete",
    "observed_at",
    "snapshot_digest",
}


def validate_route_collision_snapshot(
    snapshot: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    capture_index: int,
) -> dict[str, Any]:
    validate_route_collision_admission_request(request)
    value = _copy(snapshot, "ROUTE_COLLISION_SNAPSHOT_INVALID")
    if not isinstance(value, Mapping):
        _fail("ROUTE_COLLISION_SNAPSHOT_INVALID")
    _exact(value, _SNAPSHOT_FIELDS, "ROUTE_COLLISION_SNAPSHOT_FIELDS_INVALID")
    if (
        value.get("record_type") != SNAPSHOT_TYPE
        or value.get("schema_version") != 1
        or value.get("capture_index") != capture_index
        or capture_index not in {1, 2, 3}
        or value.get("request_digest") != request["request_digest"]
        or value.get("catalog_digest") != request["catalog_digest"]
        or value.get("operation") != request["operation"]
        or value.get("effect_request_digest") != request["effect_request_digest"]
        or value.get("complete") is not True
    ):
        _fail("ROUTE_COLLISION_SNAPSHOT_INVALID")
    identities = value.get("identities")
    if not isinstance(identities, Mapping) or set(identities) != {
        "authority",
        "management",
    }:
        _fail("ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID")
    _validate_identity(identities["authority"], "authority", request=request)
    _validate_identity(
        identities["management"], "management", request=request
    )
    observations = value.get("target_observations")
    expected = request["expected_dispositions"]
    if not isinstance(observations, Mapping) or set(observations) != set(expected):
        _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
    for target_id, observation in observations.items():
        if not isinstance(observation, Mapping) or set(observation) != {
            "disposition",
            "facts_digest",
            "ownership_binding_digest",
        }:
            _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
        disposition = observation.get("disposition")
        ownership = observation.get("ownership_binding_digest")
        if (
            disposition not in ALLOWED_DISPOSITIONS
            or disposition != expected[target_id]
            or _DIGEST.fullmatch(str(observation.get("facts_digest"))) is None
            or (
                disposition == "PRESENT_OWNED"
                and _DIGEST.fullmatch(str(ownership)) is None
            )
            or (disposition != "PRESENT_OWNED" and ownership is not None)
        ):
            _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
    semantic = {
        "catalog_digest": value["catalog_digest"],
        "operation": value["operation"],
        "effect_request_digest": value["effect_request_digest"],
        "target_observations": observations,
    }
    if value.get("semantic_facts_digest") != canonical_digest(semantic):
        _fail("ROUTE_COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    _require_digest(value.get("transcript_digest"), "ROUTE_COLLISION_SNAPSHOT_INVALID")
    observed = _parse_time(value.get("observed_at"), "ROUTE_COLLISION_SNAPSHOT_INVALID")
    identity_times = [
        _parse_time(
            identities[domain].get("observed_at"),
            "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
        )
        for domain in ("authority", "management")
    ]
    if not _parse_time(
        request["not_before"], "ROUTE_COLLISION_WINDOW_INVALID"
    ) <= observed < _parse_time(
        request["expires_at"], "ROUTE_COLLISION_WINDOW_INVALID"
    ) or any(
        identity_time > observed
        or observed - identity_time > MAX_PRE_EFFECT_SEAL_DELAY
        for identity_time in identity_times
    ):
        _fail("ROUTE_COLLISION_SNAPSHOT_NOT_ACTIVE")
    _verify_seal(value, "snapshot_digest", "ROUTE_COLLISION_SNAPSHOT_DIGEST_MISMATCH")
    return dict(value)


@dataclass(frozen=True)
class RouteCollisionAdmissionResult:
    private_evidence: dict[str, Any]
    public_receipt: dict[str, Any]


def _validate_snapshot_stability(
    checked: Sequence[Mapping[str, Any]],
    *,
    request: Mapping[str, Any],
    claim: Mapping[str, Any],
    sealed: datetime,
) -> tuple[list[str], str]:
    semantic_digests = [str(item["semantic_facts_digest"]) for item in checked]
    snapshot_digests = [str(item["snapshot_digest"]) for item in checked]
    session_digests = [
        str(identity["session_digest"])
        for item in checked
        for identity in item["identities"].values()
    ]
    observed = [
        _parse_time(item["observed_at"], "ROUTE_COLLISION_SNAPSHOT_INVALID")
        for item in checked
    ]
    identity_observed = [
        _parse_time(
            identity["observed_at"],
            "ROUTE_COLLISION_SNAPSHOT_IDENTITY_INVALID",
        )
        for item in checked
        for identity in item["identities"].values()
    ]
    minimum_observed_at = max(
        _parse_time(
            request["created_at"], "ROUTE_COLLISION_WINDOW_INVALID"
        ),
        _parse_time(claim["claimed_at"], "ROUTE_COLLISION_CLAIM_INVALID"),
    )
    expires = _parse_time(
        request["expires_at"], "ROUTE_COLLISION_WINDOW_INVALID"
    )
    if (
        len(checked) != 3
        or len(set(snapshot_digests)) != 3
        or len(set(session_digests)) != 6
        or len(set(semantic_digests)) != 1
        or any(item < minimum_observed_at for item in observed)
        or any(item < minimum_observed_at for item in identity_observed)
        or not observed[0] < observed[1] < observed[2]
        or observed[2] - observed[0] > MAX_SNAPSHOT_SPAN
        or not observed[2] <= sealed
        or sealed - observed[2] > MAX_PRE_EFFECT_SEAL_DELAY
        or sealed >= expires
    ):
        _fail("ROUTE_COLLISION_SNAPSHOT_STABILITY_INVALID")
    return snapshot_digests, semantic_digests[0]


def build_route_collision_admission_result(
    *,
    capability: RouteCollisionAdmissionExecutionCapability,
    snapshots: Sequence[Mapping[str, Any]],
    sealed_at: datetime,
    collision_budget_summary: Mapping[str, Any] | None = None,
    collision_budget_events: Sequence[Mapping[str, Any]] | None = None,
    collision_budget_transcript_events: Sequence[Mapping[str, Any]] | None = None,
    session_registry_summary: Mapping[str, Any] | None = None,
) -> RouteCollisionAdmissionResult:
    request = approved_route_collision_admission_request(capability)
    if len(snapshots) != 3:
        _fail("ROUTE_COLLISION_THREE_SNAPSHOTS_REQUIRED")
    checked = [
        validate_route_collision_snapshot(
            snapshot, request=request, capture_index=index
        )
        for index, snapshot in enumerate(snapshots, 1)
    ]
    sealed = _parse_time(_stamp(sealed_at), "ROUTE_COLLISION_CLOCK_INVALID")
    snapshot_digests, semantic_facts_digest = _validate_snapshot_stability(
        checked,
        request=request,
        claim=capability._claim,
        sealed=sealed,
    )
    budget_values = (
        collision_budget_summary,
        collision_budget_events,
        collision_budget_transcript_events,
        session_registry_summary,
    )
    budget_enforced = all(value is not None for value in budget_values)
    if any(value is not None for value in budget_values) and not budget_enforced:
        _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
    checked_budget_summary = None
    checked_budget_events = None
    checked_budget_transcript_events = None
    checked_registry_summary = None
    if budget_enforced:
        checked_budget_summary = _copy(
            collision_budget_summary,
            "ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID",
        )
        checked_budget_events = _copy(
            collision_budget_events,
            "ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID",
        )
        checked_budget_transcript_events = _copy(
            collision_budget_transcript_events,
            "ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID",
        )
        checked_registry_summary = _copy(
            session_registry_summary,
            "ROUTE_COLLISION_SESSION_REGISTRY_INVALID",
        )
        try:
            collision_budget.validate_collision_budget_evidence(
                summary=checked_budget_summary,
                events=checked_budget_events,
                transcript_events=checked_budget_transcript_events,
            )
        except collision_budget.CollisionBudgetError:
            _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
        if (
            not isinstance(checked_registry_summary, Mapping)
            or set(checked_registry_summary)
            != {
                "session_count",
                "session_nonce_count",
                "sdk_session_count",
                "session_digests_digest",
                "session_nonce_digests_digest",
            }
            or checked_registry_summary.get("session_count") != 10
            or checked_registry_summary.get("session_nonce_count") != 10
            or checked_registry_summary.get("sdk_session_count") != 10
        ):
            _fail("ROUTE_COLLISION_SESSION_REGISTRY_INVALID")
        for field in (
            "session_digests_digest",
            "session_nonce_digests_digest",
        ):
            _require_digest(
                checked_registry_summary.get(field),
                "ROUTE_COLLISION_SESSION_REGISTRY_INVALID",
            )
        if (
            checked_budget_summary.get("budget_digest")
            != request.get("collision_budget_digest")
            or checked_budget_summary.get("session_mode")
            != request.get("session_mode")
            or checked_budget_summary.get("operation")
            != request.get("operation")
        ):
            _fail("ROUTE_COLLISION_BUDGET_BINDING_INVALID")
    evidence = {
        "record_type": PRIVATE_EVIDENCE_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "request": request,
        "request_digest": request["request_digest"],
        "claim": _copy(capability._claim, "ROUTE_COLLISION_CLAIM_INVALID"),
        "claim_digest": capability._claim["claim_digest"],
        "snapshots": checked,
        "snapshot_digests": snapshot_digests,
        "semantic_facts_digest": semantic_facts_digest,
        "collision_budget_enforced": budget_enforced,
        "collision_budget_summary": checked_budget_summary,
        "collision_budget_events": checked_budget_events,
        "collision_budget_transcript_events": (
            checked_budget_transcript_events
        ),
        "session_registry_summary": checked_registry_summary,
        "sealed_at": _stamp(sealed_at),
        "read_only": True,
        "aws_mutations": 0,
        "admission_status": "ADMITTED_FOR_EXACT_EFFECT",
    }
    _seal(evidence, "private_evidence_digest")
    receipt = {
        "record_type": RECEIPT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "status": "ROUTE_COLLISION_ADMISSION_RECORDED",
        "admission_status": "ADMITTED_FOR_EXACT_EFFECT",
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "bootstrap_intent_digest": request["bootstrap_intent_digest"],
        "effect_private_root_digest": request[
            "effect_private_root_digest"
        ],
        "atomic_context_digest": request["atomic_context_digest"],
        "phase": request["phase"],
        "operation": request["operation"],
        "execution_locus": request["execution_locus"],
        "session_mode": request["session_mode"],
        "collision_budget_enforced": budget_enforced,
        "collision_budget_digest": request["collision_budget_digest"],
        "collision_budget_summary_digest": (
            checked_budget_summary.get("summary_digest")
            if checked_budget_summary is not None
            else None
        ),
        "collision_budget_events_digest": (
            canonical_digest(checked_budget_events)
            if checked_budget_events is not None
            else None
        ),
        "collision_budget_transcript_events_digest": (
            canonical_digest(checked_budget_transcript_events)
            if checked_budget_transcript_events is not None
            else None
        ),
        "session_registry_summary_digest": (
            canonical_digest(checked_registry_summary)
            if checked_registry_summary is not None
            else None
        ),
        "effect_request_digest": request["effect_request_digest"],
        "catalog_digest": request["catalog_digest"],
        "request_digest": request["request_digest"],
        "claim_digest": capability._claim["claim_digest"],
        "gug395_result_bundle_digest": request["gug395_result_bundle_digest"],
        "gug395_private_root_digest": request["gug395_private_root_digest"],
        "private_evidence_digest": evidence["private_evidence_digest"],
        "snapshot_digests": snapshot_digests,
        "semantic_facts_digest": semantic_facts_digest,
        "not_before": request["not_before"],
        "expires_at": request["expires_at"],
        "sealed_at": evidence["sealed_at"],
        "evidence_complete": True,
        "evidence_stable": True,
        "action_time_recheck_present": True,
        "read_only": True,
        "aws_mutations": 0,
        "production_authorized": False,
    }
    _seal(receipt, "admission_digest")
    capability._active = False
    return RouteCollisionAdmissionResult(evidence, receipt)


_PRIVATE_EVIDENCE_FIELDS = {
    "record_type",
    "schema_version",
    "implementation_issue",
    "request",
    "request_digest",
    "claim",
    "claim_digest",
    "snapshots",
    "snapshot_digests",
    "semantic_facts_digest",
    "collision_budget_enforced",
    "collision_budget_summary",
    "collision_budget_events",
    "collision_budget_transcript_events",
    "session_registry_summary",
    "sealed_at",
    "read_only",
    "aws_mutations",
    "admission_status",
    "private_evidence_digest",
}

_RECEIPT_FIELDS = {
    "record_type",
    "schema_version",
    "implementation_issue",
    "status",
    "admission_status",
    "source_commit_sha",
    "source_tree_sha",
    "bootstrap_intent_digest",
    "effect_private_root_digest",
    "atomic_context_digest",
    "phase",
    "operation",
    "execution_locus",
    "session_mode",
    "collision_budget_enforced",
    "collision_budget_digest",
    "collision_budget_summary_digest",
    "collision_budget_events_digest",
    "collision_budget_transcript_events_digest",
    "session_registry_summary_digest",
    "effect_request_digest",
    "catalog_digest",
    "request_digest",
    "claim_digest",
    "gug395_result_bundle_digest",
    "gug395_private_root_digest",
    "private_evidence_digest",
    "snapshot_digests",
    "semantic_facts_digest",
    "not_before",
    "expires_at",
    "sealed_at",
    "evidence_complete",
    "evidence_stable",
    "action_time_recheck_present",
    "read_only",
    "aws_mutations",
    "production_authorized",
    "admission_digest",
}


def _validate_result(result: RouteCollisionAdmissionResult) -> None:
    if type(result) is not RouteCollisionAdmissionResult:
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    evidence = result.private_evidence
    receipt = result.public_receipt
    if not isinstance(evidence, Mapping) or not isinstance(receipt, Mapping):
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    _exact(
        evidence,
        _PRIVATE_EVIDENCE_FIELDS,
        "ROUTE_COLLISION_PRIVATE_EVIDENCE_FIELDS_INVALID",
    )
    _exact(
        receipt,
        _RECEIPT_FIELDS,
        "ROUTE_COLLISION_RECEIPT_FIELDS_INVALID",
    )
    _verify_seal(
        evidence,
        "private_evidence_digest",
        "ROUTE_COLLISION_PRIVATE_EVIDENCE_INVALID",
    )
    _verify_seal(
        receipt,
        "admission_digest",
        "ROUTE_COLLISION_RECEIPT_INVALID",
    )
    request = evidence.get("request")
    claim = evidence.get("claim")
    snapshots = evidence.get("snapshots")
    if (
        not isinstance(request, Mapping)
        or not isinstance(claim, Mapping)
        or not isinstance(snapshots, list)
        or len(snapshots) != 3
    ):
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    validate_route_collision_admission_request(request)
    checked_claim = _validate_claim(claim, request=request)
    checked_snapshots = [
        validate_route_collision_snapshot(
            snapshot,
            request=request,
            capture_index=index,
        )
        for index, snapshot in enumerate(snapshots, 1)
    ]
    sealed = _parse_time(
        evidence.get("sealed_at"), "ROUTE_COLLISION_RESULT_INVALID"
    )
    snapshot_digests, semantic_facts_digest = _validate_snapshot_stability(
        checked_snapshots,
        request=request,
        claim=checked_claim,
        sealed=sealed,
    )
    budget_enforced = evidence.get("collision_budget_enforced")
    budget_summary = evidence.get("collision_budget_summary")
    budget_events = evidence.get("collision_budget_events")
    budget_transcript_events = evidence.get(
        "collision_budget_transcript_events"
    )
    registry_summary = evidence.get("session_registry_summary")
    if type(budget_enforced) is not bool:
        _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
    if budget_enforced:
        if (
            not isinstance(budget_summary, Mapping)
            or not isinstance(budget_events, list)
            or not isinstance(budget_transcript_events, list)
            or not isinstance(registry_summary, Mapping)
            or set(registry_summary)
            != {
                "session_count",
                "session_nonce_count",
                "sdk_session_count",
                "session_digests_digest",
                "session_nonce_digests_digest",
            }
            or registry_summary.get("session_count") != 10
            or registry_summary.get("session_nonce_count") != 10
            or registry_summary.get("sdk_session_count") != 10
        ):
            _fail("ROUTE_COLLISION_SESSION_REGISTRY_INVALID")
        try:
            collision_budget.validate_collision_budget_evidence(
                summary=budget_summary,
                events=budget_events,
                transcript_events=budget_transcript_events,
            )
        except collision_budget.CollisionBudgetError:
            _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
        if (
            budget_summary.get("budget_digest")
            != request.get("collision_budget_digest")
            or budget_summary.get("session_mode")
            != request.get("session_mode")
            or budget_summary.get("operation")
            != request.get("operation")
            or receipt.get("collision_budget_summary_digest")
            != budget_summary.get("summary_digest")
            or receipt.get("collision_budget_events_digest")
            != canonical_digest(budget_events)
            or receipt.get("collision_budget_transcript_events_digest")
            != canonical_digest(budget_transcript_events)
            or receipt.get("session_registry_summary_digest")
            != canonical_digest(registry_summary)
        ):
            _fail("ROUTE_COLLISION_BUDGET_BINDING_INVALID")
        for field in (
            "session_digests_digest",
            "session_nonce_digests_digest",
        ):
            _require_digest(
                registry_summary.get(field),
                "ROUTE_COLLISION_SESSION_REGISTRY_INVALID",
            )
    elif (
        any(
            value is not None
            for value in (
                budget_summary,
                budget_events,
                budget_transcript_events,
                registry_summary,
                receipt.get("collision_budget_summary_digest"),
                receipt.get("collision_budget_events_digest"),
                receipt.get("collision_budget_transcript_events_digest"),
                receipt.get("session_registry_summary_digest"),
            )
        )
    ):
        _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
    if (
        evidence.get("record_type") != PRIVATE_EVIDENCE_TYPE
        or evidence.get("schema_version") != 1
        or evidence.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or evidence.get("request_digest") != request.get("request_digest")
        or evidence.get("claim") != checked_claim
        or evidence.get("claim_digest") != checked_claim.get("claim_digest")
        or evidence.get("snapshots") != checked_snapshots
        or evidence.get("snapshot_digests") != snapshot_digests
        or evidence.get("semantic_facts_digest") != semantic_facts_digest
        or evidence.get("read_only") is not True
        or evidence.get("aws_mutations") != 0
        or evidence.get("admission_status") != "ADMITTED_FOR_EXACT_EFFECT"
        or receipt.get("record_type") != RECEIPT_TYPE
        or receipt.get("schema_version") != 1
        or receipt.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or receipt.get("status") != "ROUTE_COLLISION_ADMISSION_RECORDED"
        or evidence.get("request_digest") != receipt.get("request_digest")
        or evidence.get("claim_digest") != receipt.get("claim_digest")
        or evidence.get("private_evidence_digest")
        != receipt.get("private_evidence_digest")
        or evidence.get("semantic_facts_digest")
        != receipt.get("semantic_facts_digest")
        or evidence.get("snapshot_digests") != receipt.get("snapshot_digests")
        or receipt.get("source_commit_sha") != request.get("source_commit_sha")
        or receipt.get("source_tree_sha") != request.get("source_tree_sha")
        or receipt.get("bootstrap_intent_digest")
        != request.get("bootstrap_intent_digest")
        or receipt.get("effect_private_root_digest")
        != request.get("effect_private_root_digest")
        or receipt.get("atomic_context_digest")
        != request.get("atomic_context_digest")
        or receipt.get("execution_locus") != request.get("execution_locus")
        or receipt.get("session_mode") != request.get("session_mode")
        or receipt.get("collision_budget_enforced") != budget_enforced
        or receipt.get("collision_budget_digest")
        != request.get("collision_budget_digest")
        or receipt.get("phase") != request.get("phase")
        or receipt.get("operation") != request.get("operation")
        or receipt.get("effect_request_digest")
        != request.get("effect_request_digest")
        or receipt.get("catalog_digest") != request.get("catalog_digest")
        or receipt.get("gug395_result_bundle_digest")
        != request.get("gug395_result_bundle_digest")
        or receipt.get("gug395_private_root_digest")
        != request.get("gug395_private_root_digest")
        or receipt.get("not_before") != request.get("not_before")
        or receipt.get("expires_at") != request.get("expires_at")
        or receipt.get("sealed_at") != evidence.get("sealed_at")
        or receipt.get("admission_status") != "ADMITTED_FOR_EXACT_EFFECT"
        or receipt.get("evidence_complete") is not True
        or receipt.get("evidence_stable") is not True
        or receipt.get("action_time_recheck_present") is not True
        or receipt.get("read_only") is not True
        or receipt.get("production_authorized") is not False
        or receipt.get("aws_mutations") != 0
    ):
        _fail("ROUTE_COLLISION_RESULT_BINDING_INVALID")


def persist_route_collision_admission_result(
    *,
    private_root: Path,
    result: RouteCollisionAdmissionResult,
) -> None:
    _validate_result(result)
    request = result.private_evidence["request"]
    claim = result.private_evidence["claim"]
    try:
        if read_private_json(private_root, DEFAULT_REQUEST_FILE) != request:
            _fail("ROUTE_COLLISION_RESULT_CUSTODY_MISMATCH")
        if read_private_json(private_root, DEFAULT_CLAIM_FILE) != claim:
            _fail("ROUTE_COLLISION_RESULT_CUSTODY_MISMATCH")
        private_target_absent(private_root, DEFAULT_RESULT_FILE)
        private_target_absent(private_root, DEFAULT_CONSUMPTION_FILE)
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    if request["private_custody_digest"] != _private_root_digest(private_root):
        _fail("ROUTE_COLLISION_RESULT_CUSTODY_MISMATCH")
    bundle = {
        "record_type": RESULT_TYPE,
        "schema_version": 1,
        "private_root_digest": request["private_custody_digest"],
        "gug395_private_root_digest": request["gug395_private_root_digest"],
        "effect_private_root_digest": request[
            "effect_private_root_digest"
        ],
        "atomic_context_digest": request["atomic_context_digest"],
        "request_digest": request["request_digest"],
        "claim_digest": claim["claim_digest"],
        "private_evidence": result.private_evidence,
        "public_receipt": result.public_receipt,
    }
    _seal(bundle, "bundle_digest")
    try:
        write_private_json(private_root, DEFAULT_RESULT_FILE, bundle)
        if read_private_json(private_root, DEFAULT_RESULT_FILE) != bundle:
            _fail("ROUTE_COLLISION_RESULT_READBACK_MISMATCH")
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc


class RouteCollisionAdmissionCapability:
    """Opaque, short-lived proof consumed by exactly one mutating adapter."""

    __slots__ = (
        "_token",
        "_receipt",
        "_bundle_digest",
        "_transcript_sidecar_digest",
        "_transcript_events_digest",
        "_private_root",
        "_consumption_digest",
        "_active",
    )

    def __init__(
        self,
        *,
        token: object,
        receipt: Mapping[str, Any],
        bundle_digest: str,
        transcript_sidecar_digest: str,
        transcript_events_digest: str,
        private_root: Path,
        consumption_digest: str,
    ) -> None:
        self._token = token
        self._receipt = _copy(receipt, "ROUTE_COLLISION_RECEIPT_INVALID")
        self._bundle_digest = bundle_digest
        self._transcript_sidecar_digest = transcript_sidecar_digest
        self._transcript_events_digest = transcript_events_digest
        self._private_root = Path(private_root)
        self._consumption_digest = consumption_digest
        self._active = True


@dataclass(frozen=True, slots=True)
class RouteCollisionAdmissionEffectGrant:
    """Minimal verified time contract retained by a mutating adapter."""

    admission_digest: str
    effect_private_root_digest: str
    atomic_context_digest: str
    not_before: datetime
    expires_at: datetime
    sealed_at: datetime


_ADMISSION_TOKEN = object()
_CONSUMPTION_FIELDS = {
    "record_type",
    "schema_version",
    "admission_digest",
    "bundle_digest",
    "transcript_sidecar_digest",
    "transcript_events_digest",
    "operation",
    "effect_request_digest",
    "bootstrap_intent_digest",
    "effect_private_root_digest",
    "atomic_context_digest",
    "consumed_at",
    "aws_calls",
    "aws_mutations",
    "consumption_digest",
}
_RESULT_BUNDLE_FIELDS = {
    "record_type",
    "schema_version",
    "private_root_digest",
    "gug395_private_root_digest",
    "effect_private_root_digest",
    "atomic_context_digest",
    "request_digest",
    "claim_digest",
    "private_evidence",
    "public_receipt",
    "bundle_digest",
}
_TRANSCRIPT_SIDECAR_FIELDS = {
    "record_type",
    "schema_version",
    "request_digest",
    "claim_digest",
    "admission_digest",
    "private_evidence_digest",
    "snapshot_transcript_digests",
    "events",
    "events_digest",
    "summary",
    "recorded_at",
    "read_only",
    "aws_mutations",
    "sidecar_digest",
}
_TRANSCRIPT_SUMMARY_FIELDS = {
    "record_type",
    "schema_version",
    "request_digest",
    "snapshot_count",
    "provider_calls",
    "aws_calls",
    "aws_mutations",
    "read_only",
    "transcript_digest",
}
TRANSCRIPT_SUMMARY_TYPE = (
    "scanalyze.platform_authority."
    "gug376_route_collision_transcript_summary.v1"
)


def read_route_collision_admission(
    *,
    private_root: Path,
    expected_admission_digest: str,
    expected_operation: str,
    expected_effect_request_digest: str,
    expected_bootstrap_intent_digest: str,
    now: datetime,
    require_collision_budget_evidence: bool = False,
) -> RouteCollisionAdmissionCapability:
    if type(require_collision_budget_evidence) is not bool:
        _fail("ROUTE_COLLISION_BUDGET_EVIDENCE_INVALID")
    expected_digest = _require_digest(
        expected_admission_digest, "ROUTE_COLLISION_ADMISSION_DIGEST_INVALID"
    )
    effect_digest = _require_digest(
        expected_effect_request_digest,
        "ROUTE_COLLISION_EFFECT_BINDING_INVALID",
    )
    bootstrap_digest = _require_digest(
        expected_bootstrap_intent_digest,
        "ROUTE_COLLISION_BOOTSTRAP_BINDING_INVALID",
    )
    try:
        bundle = read_private_json(private_root, DEFAULT_RESULT_FILE)
        request = read_private_json(private_root, DEFAULT_REQUEST_FILE)
        claim = read_private_json(private_root, DEFAULT_CLAIM_FILE)
        transcript = read_private_json(private_root, DEFAULT_TRANSCRIPT_FILE)
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    if not isinstance(bundle, Mapping):
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    if not isinstance(transcript, Mapping):
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    _exact(
        transcript,
        _TRANSCRIPT_SIDECAR_FIELDS,
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    )
    transcript_sidecar_digest = _verify_seal(
        transcript,
        "sidecar_digest",
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    )
    _exact(
        bundle,
        _RESULT_BUNDLE_FIELDS,
        "ROUTE_COLLISION_RESULT_FIELDS_INVALID",
    )
    if (
        bundle.get("record_type") != RESULT_TYPE
        or bundle.get("schema_version") != 1
    ):
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    bundle_digest = _verify_seal(
        bundle, "bundle_digest", "ROUTE_COLLISION_RESULT_DIGEST_MISMATCH"
    )
    evidence = bundle.get("private_evidence")
    receipt = bundle.get("public_receipt")
    if not isinstance(evidence, Mapping) or not isinstance(receipt, Mapping):
        _fail("ROUTE_COLLISION_RESULT_INVALID")
    _validate_result(RouteCollisionAdmissionResult(dict(evidence), dict(receipt)))
    checked_now = _parse_time(_stamp(now), "ROUTE_COLLISION_CLOCK_INVALID")
    sealed_at = _parse_time(
        receipt.get("sealed_at"), "ROUTE_COLLISION_RESULT_INVALID"
    )
    transcript_events = transcript.get("events")
    transcript_summary = transcript.get("summary")
    snapshot_transcript_digests = [
        snapshot.get("transcript_digest")
        for snapshot in evidence.get("snapshots", [])
        if isinstance(snapshot, Mapping)
    ]
    if not isinstance(transcript_events, list) or not transcript_events:
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    if not isinstance(transcript_summary, Mapping):
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    _exact(
        transcript_summary,
        _TRANSCRIPT_SUMMARY_FIELDS,
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    )
    segments: dict[int, list[Mapping[str, Any]]] = {1: [], 2: [], 3: []}
    last_capture_index = 0
    for event in transcript_events:
        if not isinstance(event, Mapping):
            _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
        capture_index = event.get("capture_index")
        if (
            type(capture_index) is not int
            or capture_index not in segments
            or capture_index < last_capture_index
            or event.get("request_digest") != request.get("request_digest")
            or event.get("read_only") is not True
            or event.get("aws_mutations") != 0
        ):
            _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
        segments[capture_index].append(event)
        last_capture_index = capture_index
    if any(
        not segment
        or canonical_digest(segment) != snapshot_transcript_digests[index - 1]
        for index, segment in segments.items()
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    transcript_events_digest = canonical_digest(transcript_events)
    try:
        validate_route_collision_transcript_bundle(
            events=transcript_events,
            summary=transcript_summary,
            request=request,
            snapshots=evidence.get("snapshots", []),
        )
    except CollisionTranscriptContractError:
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    if (
        bundle.get("private_root_digest") != _private_root_digest(private_root)
        or bundle.get("gug395_private_root_digest")
        != request.get("gug395_private_root_digest")
        or bundle.get("effect_private_root_digest")
        != request.get("effect_private_root_digest")
        or bundle.get("atomic_context_digest")
        != request.get("atomic_context_digest")
        or bundle.get("request_digest") != request.get("request_digest")
        or bundle.get("claim_digest") != claim.get("claim_digest")
        or evidence.get("request") != request
        or evidence.get("claim") != claim
        or receipt.get("admission_digest") != expected_digest
        or receipt.get("operation") != expected_operation
        or receipt.get("effect_request_digest") != effect_digest
        or receipt.get("bootstrap_intent_digest") != bootstrap_digest
        or receipt.get("effect_private_root_digest")
        != request.get("effect_private_root_digest")
        or receipt.get("atomic_context_digest")
        != request.get("atomic_context_digest")
        or (
            require_collision_budget_evidence
            and receipt.get("collision_budget_enforced") is not True
        )
        or not _parse_time(
            receipt.get("not_before"), "ROUTE_COLLISION_WINDOW_INVALID"
        )
        <= checked_now
        < _parse_time(
            receipt.get("expires_at"), "ROUTE_COLLISION_WINDOW_INVALID"
        )
        or not sealed_at <= checked_now <= sealed_at + MAX_ADMISSION_AGE
        or transcript.get("record_type") != TRANSCRIPT_SIDECAR_TYPE
        or transcript.get("schema_version") != 1
        or transcript.get("request_digest") != request.get("request_digest")
        or transcript.get("claim_digest") != claim.get("claim_digest")
        or transcript.get("admission_digest")
        != receipt.get("admission_digest")
        or transcript.get("private_evidence_digest")
        != evidence.get("private_evidence_digest")
        or transcript.get("snapshot_transcript_digests")
        != snapshot_transcript_digests
        or transcript.get("events_digest")
        != transcript_events_digest
        or transcript_summary.get("record_type") != TRANSCRIPT_SUMMARY_TYPE
        or transcript_summary.get("schema_version") != 1
        or transcript_summary.get("request_digest")
        != request.get("request_digest")
        or transcript_summary.get("snapshot_count") != 3
        or transcript_summary.get("provider_calls") != len(transcript_events)
        or transcript_summary.get("aws_calls") != len(transcript_events)
        or transcript_summary.get("aws_mutations") != 0
        or transcript_summary.get("read_only") is not True
        or transcript_summary.get("transcript_digest")
        != transcript_events_digest
        or transcript.get("recorded_at") != receipt.get("sealed_at")
        or transcript.get("read_only") is not True
        or transcript.get("aws_mutations") != 0
    ):
        _fail("ROUTE_COLLISION_ADMISSION_BINDING_INVALID")
    consumption = {
        "record_type": CONSUMPTION_TYPE,
        "schema_version": 1,
        "admission_digest": receipt["admission_digest"],
        "bundle_digest": bundle_digest,
        "transcript_sidecar_digest": transcript_sidecar_digest,
        "transcript_events_digest": transcript_events_digest,
        "operation": receipt["operation"],
        "effect_request_digest": receipt["effect_request_digest"],
        "bootstrap_intent_digest": receipt["bootstrap_intent_digest"],
        "effect_private_root_digest": receipt[
            "effect_private_root_digest"
        ],
        "atomic_context_digest": receipt["atomic_context_digest"],
        "consumed_at": _stamp(now),
        "aws_calls": 0,
        "aws_mutations": 0,
    }
    _seal(consumption, "consumption_digest")
    try:
        private_target_absent(private_root, DEFAULT_CONSUMPTION_FILE)
        write_private_json(
            private_root,
            DEFAULT_CONSUMPTION_FILE,
            consumption,
        )
        if (
            read_private_json(private_root, DEFAULT_CONSUMPTION_FILE)
            != consumption
        ):
            _fail("ROUTE_COLLISION_CONSUMPTION_READBACK_MISMATCH")
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    return RouteCollisionAdmissionCapability(
        token=_ADMISSION_TOKEN,
        receipt=receipt,
        bundle_digest=bundle_digest,
        transcript_sidecar_digest=transcript_sidecar_digest,
        transcript_events_digest=transcript_events_digest,
        private_root=private_root,
        consumption_digest=consumption["consumption_digest"],
    )


def assert_route_collision_admission_active(
    capability: object,
    *,
    operation: str,
    effect_request_digest: str,
    bootstrap_intent_digest: str,
    now: datetime,
) -> str:
    if (
        type(capability) is not RouteCollisionAdmissionCapability
        or capability._token is not _ADMISSION_TOKEN
        or capability._active is not True
    ):
        _fail("ROUTE_COLLISION_ADMISSION_CAPABILITY_INVALID")
    receipt = capability._receipt
    try:
        consumption = read_private_json(
            capability._private_root, DEFAULT_CONSUMPTION_FILE
        )
        transcript = read_private_json(
            capability._private_root, DEFAULT_TRANSCRIPT_FILE
        )
    except CollectorError as exc:
        raise RouteCollisionAdmissionError(exc.code) from exc
    if not isinstance(consumption, Mapping):
        _fail("ROUTE_COLLISION_CONSUMPTION_INVALID")
    if not isinstance(transcript, Mapping):
        _fail("ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID")
    _exact(
        consumption,
        _CONSUMPTION_FIELDS,
        "ROUTE_COLLISION_CONSUMPTION_INVALID",
    )
    _verify_seal(
        consumption,
        "consumption_digest",
        "ROUTE_COLLISION_CONSUMPTION_INVALID",
    )
    _exact(
        transcript,
        _TRANSCRIPT_SIDECAR_FIELDS,
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    )
    current_transcript_sidecar_digest = _verify_seal(
        transcript,
        "sidecar_digest",
        "ROUTE_COLLISION_TRANSCRIPT_SIDECAR_INVALID",
    )
    checked_now = _parse_time(_stamp(now), "ROUTE_COLLISION_CLOCK_INVALID")
    sealed_at = _parse_time(
        receipt.get("sealed_at"), "ROUTE_COLLISION_RESULT_INVALID"
    )
    consumed_at = _parse_time(
        consumption.get("consumed_at"),
        "ROUTE_COLLISION_CONSUMPTION_INVALID",
    )
    if (
        receipt.get("operation") != operation
        or receipt.get("effect_request_digest") != effect_request_digest
        or receipt.get("bootstrap_intent_digest") != bootstrap_intent_digest
        or not _parse_time(
            receipt.get("not_before"), "ROUTE_COLLISION_WINDOW_INVALID"
        )
        <= checked_now
        < _parse_time(
            receipt.get("expires_at"), "ROUTE_COLLISION_WINDOW_INVALID"
        )
        or not sealed_at <= checked_now <= sealed_at + MAX_ADMISSION_AGE
        or consumption.get("record_type") != CONSUMPTION_TYPE
        or consumption.get("schema_version") != 1
        or consumption.get("admission_digest")
        != receipt.get("admission_digest")
        or consumption.get("bundle_digest") != capability._bundle_digest
        or consumption.get("transcript_sidecar_digest")
        != capability._transcript_sidecar_digest
        or consumption.get("transcript_events_digest")
        != capability._transcript_events_digest
        or current_transcript_sidecar_digest
        != capability._transcript_sidecar_digest
        or transcript.get("events_digest")
        != capability._transcript_events_digest
        or consumption.get("operation") != operation
        or consumption.get("effect_request_digest") != effect_request_digest
        or consumption.get("bootstrap_intent_digest")
        != bootstrap_intent_digest
        or consumption.get("effect_private_root_digest")
        != receipt.get("effect_private_root_digest")
        or consumption.get("atomic_context_digest")
        != receipt.get("atomic_context_digest")
        or consumption.get("consumption_digest")
        != capability._consumption_digest
        or consumption.get("aws_calls") != 0
        or consumption.get("aws_mutations") != 0
        or not sealed_at <= consumed_at <= checked_now
    ):
        _fail("ROUTE_COLLISION_ADMISSION_NOT_ACTIVE")
    capability._active = False
    return str(receipt["admission_digest"])


def consume_route_collision_admission(
    capability: object,
    *,
    operation: str,
    effect_request_digest: str,
    bootstrap_intent_digest: str,
    now: datetime,
) -> RouteCollisionAdmissionEffectGrant:
    """Consume one capability and return only its verified effect-time bounds."""

    admission_digest = assert_route_collision_admission_active(
        capability,
        operation=operation,
        effect_request_digest=effect_request_digest,
        bootstrap_intent_digest=bootstrap_intent_digest,
        now=now,
    )
    # The assertion above proves the exact capability type, receipt binding,
    # private consumption record, transcript, and active time window.  Keep
    # private receipt access inside this module and export only normalized
    # timestamps required for a post-claim, immediate pre-effect recheck.
    receipt = capability._receipt
    return RouteCollisionAdmissionEffectGrant(
        admission_digest=admission_digest,
        effect_private_root_digest=_require_digest(
            receipt.get("effect_private_root_digest"),
            "ROUTE_COLLISION_EFFECT_ROOT_BINDING_INVALID",
        ),
        atomic_context_digest=_require_digest(
            receipt.get("atomic_context_digest"),
            "ROUTE_COLLISION_ATOMIC_CONTEXT_BINDING_INVALID",
        ),
        not_before=_parse_time(
            receipt.get("not_before"), "ROUTE_COLLISION_WINDOW_INVALID"
        ),
        expires_at=_parse_time(
            receipt.get("expires_at"), "ROUTE_COLLISION_WINDOW_INVALID"
        ),
        sealed_at=_parse_time(
            receipt.get("sealed_at"), "ROUTE_COLLISION_RESULT_INVALID"
        ),
    )


def revalidate_route_collision_admission_effect_grant(
    grant: object,
    *,
    now: datetime,
) -> str:
    """Fail closed unless a consumed grant still covers the exact effect."""

    if type(grant) is not RouteCollisionAdmissionEffectGrant:
        _fail("ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID")
    admission_digest = _require_digest(
        grant.admission_digest,
        "ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID",
    )
    _require_digest(
        grant.effect_private_root_digest,
        "ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID",
    )
    _require_digest(
        grant.atomic_context_digest,
        "ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID",
    )
    checked_now = _parse_time(_stamp(now), "ROUTE_COLLISION_CLOCK_INVALID")
    for value in (grant.not_before, grant.expires_at, grant.sealed_at):
        if (
            not isinstance(value, datetime)
            or value.tzinfo is not UTC
            or value.microsecond != 0
        ):
            _fail("ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID")
    if grant.not_before >= grant.expires_at:
        _fail("ROUTE_COLLISION_ADMISSION_EFFECT_GRANT_INVALID")
    if not (
        grant.not_before <= checked_now < grant.expires_at
        and grant.sealed_at
        <= checked_now
        <= grant.sealed_at + MAX_ADMISSION_AGE
    ):
        _fail("ROUTE_COLLISION_ADMISSION_NOT_ACTIVE")
    return admission_digest


__all__ = [
    "ABSENT_READY",
    "ALLOWED_DISPOSITIONS",
    "COLLISION_ONLY_TARGET_IDS",
    "DEFAULT_CLAIM_FILE",
    "DEFAULT_CONSUMPTION_FILE",
    "DEFAULT_REQUEST_FILE",
    "DEFAULT_RESULT_FILE",
    "DEFAULT_TRANSCRIPT_FILE",
    "INLINE_BROKER_LAMBDA",
    "INLINE_BROKER_LAMBDA_OPERATIONS",
    "LOCAL_ATOMIC_CLI",
    "LOCAL_DIRECT_SSO",
    "MAX_ADMISSION_AGE",
    "OPERATION_PRESENT_OWNED_TARGET_IDS",
    "PHASE_OPERATION_ALLOWLIST",
    "POST_READER_RUNTIME",
    "ROUTE_CREATED_TARGET_IDS",
    "TRANSCRIPT_SIDECAR_TYPE",
    "RouteCollisionAdmissionCapability",
    "RouteCollisionAdmissionEffectGrant",
    "RouteCollisionAdmissionError",
    "RouteCollisionAdmissionExecutionCapability",
    "RouteCollisionAdmissionResult",
    "approved_route_collision_admission_request",
    "assert_route_collision_admission_active",
    "build_route_collision_admission_result",
    "consume_route_collision_admission",
    "expected_route_collision_identity_bindings",
    "expected_route_collision_identity_bindings_from_custody",
    "expected_route_collision_dispositions",
    "materialize_route_collision_admission_request",
    "persist_route_collision_admission_request",
    "persist_route_collision_admission_result",
    "read_and_claim_route_collision_admission_request",
    "read_route_collision_admission",
    "revalidate_route_collision_admission_effect_grant",
    "route_collision_operation_phase",
    "collision_session_mode_for_operation",
    "validate_route_collision_admission_request",
    "validate_route_collision_snapshot",
]
