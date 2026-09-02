"""In-process collision admission used only by the GUG-376 route broker.

The Lambda event remains the literal empty object.  This module derives every
read from sealed broker configuration plus the exact materialized provider
request, performs two discovery scans and three immediately preceding
snapshots, and returns a non-serializable one-shot capability.  A digest-only
manifest is inspectable before the ledger CAS; the capability itself can be
consumed only once after that CAS and immediately before the provider effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import re
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling import platform_authority_gug376_collision_aws_provider as provider
from tooling import platform_authority_gug376_collision_admission as admission
from tooling import platform_authority_gug376_collision_budget as collision_budget
from tooling import platform_authority_gug376_collision_policy as policy
from tooling import platform_authority_gug376_collision_transcript_contract as transcript
from tooling.platform_authority_gug376_collision_catalog import (
    validate_route_collision_catalog,
)


REQUEST_TYPE = (
    "scanalyze.platform_authority."
    "gug376_broker_collision_admission_request.v1"
)
CLAIM_TYPE = (
    "scanalyze.platform_authority."
    "gug376_broker_collision_admission_claim.v1"
)
SNAPSHOT_TYPE = (
    "scanalyze.platform_authority.gug376_broker_collision_snapshot.v1"
)
MANIFEST_TYPE = (
    "scanalyze.platform_authority.gug376_broker_collision_admission_manifest.v1"
)
MAX_ADMISSION_AGE = timedelta(seconds=10)
MAX_SNAPSHOT_SPAN = timedelta(seconds=60)
MAX_SESSION_POLICY_BYTES = 2_048
MIN_SESSION_POLICY_HEADROOM_BYTES = 150
MAX_MATERIALIZED_SESSION_POLICY_BYTES = (
    MAX_SESSION_POLICY_BYTES - MIN_SESSION_POLICY_HEADROOM_BYTES
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")

# Inventory reads on deterministic resources may use ``*`` in the session
# policy only because the attached reader-role policy contains their exact
# catalog resources; IAM evaluates the intersection. Candidate-detail
# statements are never projected: their exact discovered ARNs remain literal
# because the attached policy intentionally admits their bounded ARN class.
_STATIC_INTERSECTION_RESOURCES: Mapping[str, Mapping[str, str]] = {
    "authority": {
        "cloudformation": (
            "arn:aws:cloudformation:us-east-1:042360977644:stack/*"
        ),
        "dynamodb": "*",
        "iam": "*",
        # lambda:ListTags is shared by deterministic functions and discovered
        # code-signing configs. Keep the function ARN class in the session
        # intersection so the candidate CSC class cannot inherit ``*``.
        "lambda": "arn:aws:lambda:us-east-1:042360977644:function:*",
        "logs": "*",
        "s3": "*",
        "signer": "*",
    },
    "management": {
        "iam": "*",
    },
}


class BrokerCollisionAdmissionError(RuntimeError):
    """Stable, value-free failure at the inline admission boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise BrokerCollisionAdmissionError(code)


def _copy(value: object, code: str = "BROKER_COLLISION_VALUE_INVALID") -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception:
        raise BrokerCollisionAdmissionError(code) from None


def _stamp(value: object) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("BROKER_COLLISION_CLOCK_INVALID")
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("BROKER_COLLISION_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise BrokerCollisionAdmissionError(
            "BROKER_COLLISION_TIME_INVALID"
        ) from None
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if _stamp(normalized) != value:
        _fail("BROKER_COLLISION_TIME_INVALID")
    return normalized


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    if field in value:
        _fail("BROKER_COLLISION_SEAL_INVALID")
    value[field] = canonical_digest(value)
    return value


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    digest = _require_digest(value.get(field), code)
    if digest != canonical_digest(
        {key: item for key, item in value.items() if key != field}
    ):
        _fail(code)
    return digest


def _expected_dispositions(
    catalog: Mapping[str, Any], operation: str
) -> dict[str, str]:
    try:
        phase = admission.route_collision_operation_phase(operation)
        return admission.expected_route_collision_dispositions(
            catalog,
            phase,
            operation,
        )
    except Exception:
        raise BrokerCollisionAdmissionError(
            "BROKER_COLLISION_LIFECYCLE_INVALID"
        ) from None


def _actions(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(item, str) or ":" not in item for item in values):
        _fail("BROKER_COLLISION_POLICY_INVALID")
    return sorted(set(values))


def materialize_assume_role_session_policy(
    *,
    policy_set: Mapping[str, Any],
    catalog: Mapping[str, Any],
    domain: str,
) -> dict[str, Any]:
    """Return the exact compact STS intersection policy for one domain."""

    try:
        policy.validate_route_collision_policy_set(policy_set, catalog=catalog)
    except Exception:
        raise BrokerCollisionAdmissionError(
            "BROKER_COLLISION_POLICY_INVALID"
        ) from None
    if domain not in {"authority", "management"}:
        _fail("BROKER_COLLISION_DOMAIN_INVALID")
    documents = policy_set.get("policies", {}).get(domain)
    if not isinstance(documents, Mapping):
        _fail("BROKER_COLLISION_POLICY_INVALID")
    wildcard_actions: set[str] = set()
    statements: list[dict[str, Any]] = []
    for stage, document in documents.items():
        raw = document.get("Statement") if isinstance(document, Mapping) else None
        if not isinstance(raw, list):
            _fail("BROKER_COLLISION_POLICY_INVALID")
        for statement in raw:
            if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
                continue
            actions = _actions(statement.get("Action"))
            resources = statement.get("Resource")
            if stage == "candidate_detail":
                if resources == "*" and actions == ["sts:GetCallerIdentity"]:
                    wildcard_actions.update(actions)
                    continue
                if resources == "*" or not isinstance(resources, list):
                    _fail("BROKER_COLLISION_CANDIDATE_POLICY_NOT_EXACT")
                statements.append(
                    {"Effect": "Allow", "Action": actions, "Resource": resources}
                )
                continue
            if resources == "*":
                wildcard_actions.update(actions)
                continue
            by_service: dict[str, list[str]] = {}
            for action in actions:
                by_service.setdefault(action.split(":", 1)[0], []).append(action)
            for service, service_actions in sorted(by_service.items()):
                projected = _STATIC_INTERSECTION_RESOURCES.get(domain, {}).get(
                    service
                )
                if projected is None:
                    # CloudFormation exact-name selectors retain their reviewed
                    # stack-name wildcard rather than broadening to account-wide.
                    if service in {"cloudformation", "sso"} and isinstance(
                        resources, (str, list)
                    ):
                        target_resource: object = resources
                    else:
                        _fail("BROKER_COLLISION_STATIC_INTERSECTION_MISSING")
                else:
                    target_resource = projected
                if target_resource == "*":
                    wildcard_actions.update(service_actions)
                    continue
                statements.append(
                    {
                        "Effect": "Allow",
                        "Action": sorted(service_actions),
                        "Resource": target_resource,
                    }
                )
    # Session policies are an intersection with the reviewed reader-role
    # policy. Cross-service actions cannot authorize another service's ARN;
    # compatible same-service pairs remain bounded by the finite candidate set,
    # AWS action resource types, and the attached policy. One finite statement
    # avoids repeating the maximum-length CloudFormation candidate ARNs.
    exact_actions: set[str] = set()
    exact_resources: set[str] = set()
    for item in statements:
        resources = item["Resource"]
        resource_values = resources if isinstance(resources, list) else [resources]
        exact_actions.update(item["Action"])
        exact_resources.update(resource_values)

    def compact(values: set[str]) -> str | list[str]:
        ordered = sorted(values)
        return ordered[0] if len(ordered) == 1 else ordered

    compacted: list[dict[str, Any]] = []
    if wildcard_actions:
        compacted.append(
            {
                "Effect": "Allow",
                "Action": compact(wildcard_actions),
                "Resource": "*",
            }
        )
    if exact_actions:
        compacted.append(
            {
                "Effect": "Allow",
                "Action": compact(exact_actions),
                "Resource": compact(exact_resources),
            }
        )
    # Scalarizing singleton Action/Resource values preserves the intersection
    # while reserving deterministic headroom below STS's 2,048-byte quota.
    result = {"Version": "2012-10-17", "Statement": compacted}
    if (
        len(canonical_json(result).encode("utf-8"))
        > MAX_MATERIALIZED_SESSION_POLICY_BYTES
    ):
        _fail("BROKER_COLLISION_SESSION_POLICY_TOO_LARGE")
    return result


def _bind_expected_identities(
    base: Mapping[str, Any],
    *,
    policy_digest: str,
    session_policy_digests: Mapping[str, str],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    required = {
        "account_id",
        "source",
        "chain_depth",
        "principal_digest",
        "sso_role_name_digest",
        "role_arn_digest",
        "role_policy_digest",
        "authority_verification_digest",
    }
    for domain in ("authority", "management"):
        value = base.get(domain)
        if (
            not isinstance(value, Mapping)
            or set(value) != required
            or value.get("source") != "BROKER_SERVICE_ROLE"
            or value.get("chain_depth") != 1
        ):
            _fail("BROKER_COLLISION_IDENTITY_BINDING_INVALID")
        for field in required - {"account_id", "source", "chain_depth"}:
            _require_digest(
                value.get(field), "BROKER_COLLISION_IDENTITY_BINDING_INVALID"
            )
        session_policy_digest = _require_digest(
            session_policy_digests.get(domain),
            "BROKER_COLLISION_IDENTITY_BINDING_INVALID",
        )
        result[domain] = {
            **_copy(value),
            "policy_digest": policy_digest,
            "session_policy_digest": session_policy_digest,
        }
    return result


def _request(
    *,
    catalog: Mapping[str, Any],
    policy_set: Mapping[str, Any],
    expected_identities: Mapping[str, Any],
    phase: str,
    operation: str,
    effect_request: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    validate_route_collision_catalog(catalog)
    policy.validate_route_collision_policy_set(policy_set, catalog=catalog)
    if admission.route_collision_operation_phase(operation) != phase:
        _fail("BROKER_COLLISION_OPERATION_INVALID")
    try:
        session_mode = admission.collision_session_mode_for_operation(
            operation,
            execution_locus=admission.INLINE_BROKER_LAMBDA,
        )
        budget_digest = collision_budget.collision_budget_digest(
            session_mode=session_mode,
            operation=operation,
        )
    except Exception:
        raise BrokerCollisionAdmissionError(
            "BROKER_COLLISION_OPERATION_INVALID"
        ) from None
    effect = _copy(effect_request, "BROKER_COLLISION_EFFECT_INVALID")
    if not isinstance(effect, dict) or not effect:
        _fail("BROKER_COLLISION_EFFECT_INVALID")
    dispositions = _expected_dispositions(catalog, operation)
    value = {
        "record_type": REQUEST_TYPE,
        "schema_version": 1,
        "source_commit_sha": catalog["source_commit_sha"],
        "source_tree_sha": catalog["source_tree_sha"],
        "bootstrap_intent_digest": catalog["bootstrap_intent_digest"],
        "phase": phase,
        "operation": operation,
        "execution_locus": admission.INLINE_BROKER_LAMBDA,
        "session_mode": session_mode,
        "collision_budget_digest": budget_digest,
        "effect_request": effect,
        "effect_request_digest": canonical_digest(effect),
        "catalog": _copy(catalog),
        "catalog_digest": catalog["catalog_digest"],
        "collision_policy_set_digest": policy_set["policy_set_digest"],
        "collision_policy_digests": _copy(policy_set["policy_digests"]),
        "collision_policy_stage": policy_set["stage"],
        "collision_discovery_provenance_digest": policy_set[
            "discovery_provenance_digest"
        ],
        "collision_provider_implementation_digest": (
            transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        ),
        "expected_dispositions": dispositions,
        "expected_dispositions_digest": canonical_digest(dispositions),
        "expected_identities": _copy(expected_identities),
        "expected_identities_digest": canonical_digest(expected_identities),
        "not_before": catalog["not_before"],
        "expires_at": catalog["expires_at"],
        "created_at": created_at,
    }
    return _seal(value, "request_digest")


def _validate_identity(
    value: object, *, domain: str, request: Mapping[str, Any]
) -> dict[str, Any]:
    checked = _copy(value, "BROKER_COLLISION_IDENTITY_INVALID")
    expected = request["expected_identities"][domain]
    fields = {
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
        "role_arn_digest",
        "role_policy_digest",
        "session_policy_digest",
    }
    if (
        not isinstance(checked, dict)
        or set(checked) != fields
        or checked["domain"] != domain
        or checked["account_id"] != expected["account_id"]
        or checked["region"] != transcript.REGION
        or any(
            checked.get(field) != expected.get(field)
            for field in (
                "source",
                "chain_depth",
                "principal_digest",
                "sso_role_name_digest",
                "policy_digest",
                "authority_verification_digest",
                "role_arn_digest",
                "role_policy_digest",
                "session_policy_digest",
            )
        )
    ):
        _fail("BROKER_COLLISION_IDENTITY_INVALID")
    _require_digest(checked["session_digest"], "BROKER_COLLISION_IDENTITY_INVALID")
    _time(checked["observed_at"])
    return checked


def _capture(
    *,
    factory: object,
    request: Mapping[str, Any],
    capture_index: int,
    purpose: str,
    clock: Callable[[], datetime],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot = factory.open_snapshot(  # type: ignore[attr-defined]
        request=request, capture_index=capture_index, purpose=purpose
    )
    identities: dict[str, Any] = {}
    observations: dict[str, Any] = {}
    targets = request["catalog"]["targets"]
    for domain in ("authority", "management"):
        selected = [item for item in targets if item["domain"] == domain]
        expected = {
            item["target_id"]: request["expected_dispositions"][item["target_id"]]
            for item in selected
        }
        identities[domain] = _validate_identity(
            snapshot.read_identity(domain=domain),
            domain=domain,
            request=request,
        )
        observed = _copy(
            snapshot.read_target_observations(
                domain=domain,
                targets=selected,
                expected_dispositions=expected,
            ),
            "BROKER_COLLISION_OBSERVATION_INVALID",
        )
        if not isinstance(observed, dict) or set(observed) != set(expected):
            _fail("BROKER_COLLISION_OBSERVATION_INVALID")
        observations.update(observed)
    if set(observations) != set(request["expected_dispositions"]):
        _fail("BROKER_COLLISION_OBSERVATION_INVALID")
    events = _copy(
        snapshot.transcript_events(), "BROKER_COLLISION_TRANSCRIPT_INVALID"
    )
    if not isinstance(events, list) or not events:
        _fail("BROKER_COLLISION_TRANSCRIPT_INVALID")
    observed_at = _stamp(clock())
    semantic = {
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "target_observations": observations,
    }
    value = {
        "record_type": SNAPSHOT_TYPE,
        "schema_version": 1,
        "capture_index": capture_index,
        "request_digest": request["request_digest"],
        "catalog_digest": request["catalog_digest"],
        "operation": request["operation"],
        "effect_request_digest": request["effect_request_digest"],
        "identities": identities,
        "target_observations": observations,
        "semantic_facts_digest": canonical_digest(semantic),
        "transcript_digest": canonical_digest(events),
        "complete": True,
        "observed_at": observed_at,
    }
    return _seal(value, "snapshot_digest"), events


@dataclass(frozen=True, slots=True)
class _AdmissionCapability:
    _token: object
    manifest: dict[str, Any]
    _state: list[str]


@dataclass(frozen=True, slots=True)
class BrokerCollisionAdmissionEffectGrant:
    """Inline-broker-only effect grant; it never claims private-root custody."""

    admission_digest: str
    execution_locus: str
    session_mode: str
    collision_budget_digest: str
    collision_budget_summary_digest: str
    collision_budget_events_digest: str
    collision_budget_transcript_events_digest: str
    session_registry_summary_digest: str
    not_before: datetime
    expires_at: datetime
    sealed_at: datetime


_CAPABILITY_TOKEN = object()


SessionOpenerForPolicy = Callable[
    [
        Mapping[str, Any],
        Mapping[str, Mapping[str, Any]],
        Callable[[], None],
        object,
    ],
    provider.SessionOpener,
]


def execute_inline_broker_collision_admission(
    *,
    catalog: Mapping[str, Any],
    phase: str,
    operation: str,
    effect_request: Mapping[str, Any],
    identity_bindings: Mapping[str, Any],
    identity_center_instance_arn: str,
    session_opener_for_policy: SessionOpenerForPolicy,
    expected_identity_center_kms_binding_digest: str,
    clock: Callable[[], datetime],
    before_call: Callable[[], None],
) -> object:
    """Run discovery plus three snapshots and mint one local capability."""

    try:
        validate_route_collision_catalog(catalog)
        claimed_at = _stamp(clock())
        if not callable(before_call):
            _fail("BROKER_COLLISION_BUDGET_GATE_INVALID")
        not_before = _time(catalog["not_before"])
        expires_at = _time(catalog["expires_at"])

        def active_before_call() -> None:
            before_call()
            checked = _time(_stamp(clock()))
            if not not_before <= checked < expires_at:
                _fail("BROKER_COLLISION_ADMISSION_NOT_ACTIVE")

        effect = _copy(effect_request, "BROKER_COLLISION_EFFECT_INVALID")
        try:
            session_mode = admission.collision_session_mode_for_operation(
                operation,
                execution_locus=admission.INLINE_BROKER_LAMBDA,
            )
            if session_mode != admission.POST_READER_RUNTIME:
                _fail("BROKER_COLLISION_SESSION_MODE_INVALID")
            budget = collision_budget.build_collision_budget(
                session_mode=session_mode,
                operation=operation,
            )
        except collision_budget.CollisionBudgetError:
            _fail("BROKER_COLLISION_BUDGET_INVALID")
        inventory = policy.materialize_route_collision_policy_set(
            catalog,
            identity_center_instance_arn=identity_center_instance_arn,
        )
        inventory_session_policies = {
            domain: materialize_assume_role_session_policy(
                policy_set=inventory, catalog=catalog, domain=domain
            )
            for domain in ("authority", "management")
        }
        inventory_session_policy_digests = {
            domain: canonical_digest(value)
            for domain, value in inventory_session_policies.items()
        }
        inventory_identities = _bind_expected_identities(
            identity_bindings,
            policy_digest=inventory["policy_set_digest"],
            session_policy_digests=inventory_session_policy_digests,
        )
        session_registry = provider.build_session_uniqueness_registry()
        inventory_factory = provider.build_attested_provider_factory(
            session_opener=session_opener_for_policy(
                inventory,
                inventory_session_policies,
                active_before_call,
                budget,
            ),
            clock=clock,
            before_call=active_before_call,
            session_registry=session_registry,
            policy_set=inventory,
            collision_budget_capability=budget,
            budget_stage="inventory",
        )
        discovery = inventory_factory.discover_route_collision_candidates(  # type: ignore[attr-defined]
            catalog=catalog,
            expected_identities=inventory_identities,
            expected_identity_center_kms_binding_digest=(
                expected_identity_center_kms_binding_digest
            ),
        )
        candidate = policy.materialize_route_collision_policy_set(
            catalog,
            discovery_capability=discovery,
            identity_center_instance_arn=identity_center_instance_arn,
        )
        candidate_session_policies = {
            domain: materialize_assume_role_session_policy(
                policy_set=candidate, catalog=catalog, domain=domain
            )
            for domain in ("authority", "management")
        }
        candidate_session_policy_digests = {
            domain: canonical_digest(value)
            for domain, value in candidate_session_policies.items()
        }
        candidate_identities = _bind_expected_identities(
            identity_bindings,
            policy_digest=candidate["policy_set_digest"],
            session_policy_digests=candidate_session_policy_digests,
        )
        created_at = _stamp(clock())
        request = _request(
            catalog=catalog,
            policy_set=candidate,
            expected_identities=candidate_identities,
            phase=phase,
            operation=operation,
            effect_request=effect,
            created_at=created_at,
        )
        claim = _seal(
            {
                "record_type": CLAIM_TYPE,
                "schema_version": 1,
                "operation": operation,
                "effect_request_digest": request["effect_request_digest"],
                "source_commit_sha": request["source_commit_sha"],
                "source_tree_sha": request["source_tree_sha"],
                "bootstrap_intent_digest": request["bootstrap_intent_digest"],
                "catalog_digest": request["catalog_digest"],
                "inventory_policy_set_digest": inventory["policy_set_digest"],
                "candidate_policy_set_digest": candidate["policy_set_digest"],
                "provider_implementation_digest": (
                    transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
                ),
                "identity_bindings_digest": canonical_digest(identity_bindings),
                "claimed_at": claimed_at,
                "read_only": True,
                "aws_mutations": 0,
            },
            "claim_digest",
        )
        candidate_factory = provider.build_attested_provider_factory(
            session_opener=session_opener_for_policy(
                candidate,
                candidate_session_policies,
                active_before_call,
                budget,
            ),
            clock=clock,
            before_call=active_before_call,
            session_registry=session_registry,
            policy_set=candidate,
            discovery_capability=discovery,
            collision_budget_capability=budget,
            budget_stage="candidate",
        )
        attestation = _copy(candidate_factory.provider_attestation())  # type: ignore[attr-defined]
        snapshots: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        purposes = (
            "independent-snapshot-1",
            "independent-snapshot-2",
            "pre-effect-snapshot",
        )
        for index, purpose in enumerate(purposes, 1):
            snapshot, segment = _capture(
                factory=candidate_factory,
                request=request,
                capture_index=index,
                purpose=purpose,
                clock=clock,
            )
            snapshots.append(snapshot)
            events.extend(segment)
        aggregate = _copy(candidate_factory.transcript_events())  # type: ignore[attr-defined]
        summary = _copy(candidate_factory.transcript_summary())  # type: ignore[attr-defined]
        if aggregate != events:
            _fail("BROKER_COLLISION_TRANSCRIPT_INVALID")
        transcript.validate_route_collision_transcript_bundle(
            events=events,
            summary=summary,
            request=request,
            snapshots=snapshots,
        )
        inventory_events = _copy(
            inventory_factory.discovery_transcript_events(),  # type: ignore[attr-defined]
            "BROKER_COLLISION_BUDGET_INVALID",
        )
        combined_events = inventory_events + events
        try:
            budget_summary = collision_budget.complete_collision_budget(
                budget,
                transcript_events=combined_events,
            )
            budget_events = collision_budget.collision_budget_events(budget)
            collision_budget.validate_collision_budget_evidence(
                summary=budget_summary,
                events=budget_events,
                transcript_events=combined_events,
            )
        except collision_budget.CollisionBudgetError:
            _fail("BROKER_COLLISION_BUDGET_INVALID")
        sealed_at = _time(_stamp(clock()))
        observed = [_time(item["observed_at"]) for item in snapshots]
        semantic = {item["semantic_facts_digest"] for item in snapshots}
        sessions = {
            identity["session_digest"]
            for item in snapshots
            for identity in item["identities"].values()
        }
        registry_summary = _copy(
            provider.session_uniqueness_registry_summary(session_registry)
        )
        if (
            len(semantic) != 1
            or len(sessions) != 6
            or registry_summary.get("session_count") != 10
            or registry_summary.get("session_nonce_count") != 10
            or registry_summary.get("sdk_session_count") != 10
            or not observed[0] < observed[1] < observed[2] <= sealed_at
            or observed[2] - observed[0] > MAX_SNAPSHOT_SPAN
            or sealed_at - observed[2] > MAX_ADMISSION_AGE
            or not _time(request["not_before"]) <= sealed_at < _time(request["expires_at"])
        ):
            _fail("BROKER_COLLISION_SNAPSHOT_STABILITY_INVALID")
        manifest = _seal(
            {
                "record_type": MANIFEST_TYPE,
                "schema_version": 1,
                "operation": operation,
                "execution_locus": admission.INLINE_BROKER_LAMBDA,
                "session_mode": admission.POST_READER_RUNTIME,
                "collision_budget_digest": request[
                    "collision_budget_digest"
                ],
                "collision_budget_summary": budget_summary,
                "collision_budget_events_digest": canonical_digest(
                    budget_events
                ),
                "collision_budget_transcript_events_digest": (
                    canonical_digest(combined_events)
                ),
                "effect_request_digest": request["effect_request_digest"],
                "source_commit_sha": request["source_commit_sha"],
                "source_tree_sha": request["source_tree_sha"],
                "bootstrap_intent_digest": request["bootstrap_intent_digest"],
                "catalog_digest": request["catalog_digest"],
                "inventory_policy_set_digest": inventory["policy_set_digest"],
                "candidate_policy_set_digest": candidate["policy_set_digest"],
                "candidate_policy_digests": _copy(candidate["policy_digests"]),
                "inventory_session_policy_digests": {
                    **inventory_session_policy_digests
                },
                "candidate_session_policy_digests": {
                    **candidate_session_policy_digests
                },
                "session_uniqueness_registry": registry_summary,
                "provider_implementation_digest": (
                    transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
                ),
                "provider_attestation_digest": canonical_digest(attestation),
                "identity_bindings_digest": canonical_digest(identity_bindings),
                "claim_digest": claim["claim_digest"],
                "request_digest": request["request_digest"],
                "snapshot_digests": [item["snapshot_digest"] for item in snapshots],
                "semantic_facts_digest": next(iter(semantic)),
                "transcript_digest": canonical_digest(events),
                "sealed_at": _stamp(sealed_at),
                "not_before": request["not_before"],
                "expires_at": request["expires_at"],
                "read_only": True,
                "aws_mutations": 0,
            },
            "manifest_digest",
        )
        return _AdmissionCapability(
            _token=_CAPABILITY_TOKEN,
            manifest=manifest,
            _state=["ACTIVE"],
        )
    except BrokerCollisionAdmissionError:
        raise
    except Exception:
        raise BrokerCollisionAdmissionError(
            "BROKER_COLLISION_ADMISSION_FAILED"
        ) from None


def broker_collision_admission_manifest(capability: object) -> dict[str, Any]:
    if (
        type(capability) is not _AdmissionCapability
        or capability._token is not _CAPABILITY_TOKEN
        or capability._state != ["ACTIVE"]
    ):
        _fail("BROKER_COLLISION_CAPABILITY_INVALID")
    _verify_seal(
        capability.manifest,
        "manifest_digest",
        "BROKER_COLLISION_MANIFEST_INVALID",
    )
    return _copy(capability.manifest)


def consume_broker_collision_admission(
    capability: object,
    *,
    operation: str,
    effect_request_digest: str,
    expected_manifest_digest: str,
    now: datetime,
) -> BrokerCollisionAdmissionEffectGrant:
    manifest = broker_collision_admission_manifest(capability)
    checked_now = _time(_stamp(now))
    budget_summary = manifest.get("collision_budget_summary")
    registry_summary = manifest.get("session_uniqueness_registry")
    if not isinstance(budget_summary, Mapping) or not isinstance(
        registry_summary, Mapping
    ):
        _fail("BROKER_COLLISION_BUDGET_INVALID")
    summary_digest = _verify_seal(
        budget_summary,
        "summary_digest",
        "BROKER_COLLISION_BUDGET_INVALID",
    )
    registry_digest = canonical_digest(registry_summary)
    try:
        expected_budget_digest = collision_budget.collision_budget_digest(
            session_mode=admission.POST_READER_RUNTIME,
            operation=operation,
        )
    except collision_budget.CollisionBudgetError:
        _fail("BROKER_COLLISION_BUDGET_INVALID")
    if (
        manifest.get("operation") != operation
        or manifest.get("effect_request_digest") != effect_request_digest
        or manifest.get("manifest_digest") != expected_manifest_digest
        or manifest.get("execution_locus")
        != admission.INLINE_BROKER_LAMBDA
        or manifest.get("session_mode") != admission.POST_READER_RUNTIME
        or manifest.get("collision_budget_digest")
        != expected_budget_digest
        or budget_summary.get("budget_digest") != expected_budget_digest
        or budget_summary.get("operation") != operation
        or budget_summary.get("session_mode")
        != admission.POST_READER_RUNTIME
        or budget_summary.get("session_open_count") != 10
        or budget_summary.get("direct_sso_session_opens") != 0
        or budget_summary.get("assume_role_opens") != 10
        or budget_summary.get("assume_role_duration_seconds") != 900
        or budget_summary.get("source_credential_bindings") != 0
        or budget_summary.get("source_credential_vends") != 0
        or manifest.get("collision_budget_events_digest")
        != budget_summary.get("events_digest")
        or manifest.get("collision_budget_transcript_events_digest")
        != budget_summary.get("transcript_events_digest")
        or registry_summary.get("session_count") != 10
        or registry_summary.get("session_nonce_count") != 10
        or registry_summary.get("sdk_session_count") != 10
        or not _time(manifest["sealed_at"]) <= checked_now
        <= _time(manifest["sealed_at"]) + MAX_ADMISSION_AGE
        or checked_now >= _time(manifest["expires_at"])
    ):
        _fail("BROKER_COLLISION_ADMISSION_NOT_ACTIVE")
    capability._state[0] = "CONSUMED"
    grant = BrokerCollisionAdmissionEffectGrant(
        admission_digest=str(manifest["manifest_digest"]),
        execution_locus=admission.INLINE_BROKER_LAMBDA,
        session_mode=admission.POST_READER_RUNTIME,
        collision_budget_digest=expected_budget_digest,
        collision_budget_summary_digest=summary_digest,
        collision_budget_events_digest=str(
            manifest["collision_budget_events_digest"]
        ),
        collision_budget_transcript_events_digest=str(
            manifest["collision_budget_transcript_events_digest"]
        ),
        session_registry_summary_digest=registry_digest,
        not_before=_time(manifest["not_before"]),
        expires_at=_time(manifest["expires_at"]),
        sealed_at=_time(manifest["sealed_at"]),
    )
    revalidate_broker_collision_admission_effect_grant(grant, now=checked_now)
    return grant


def revalidate_broker_collision_admission_effect_grant(
    grant: object,
    *,
    now: datetime,
) -> str:
    """Recheck a POST reader grant immediately before the typed SDK effect."""

    if type(grant) is not BrokerCollisionAdmissionEffectGrant:
        _fail("BROKER_COLLISION_EFFECT_GRANT_INVALID")
    checked_now = _time(_stamp(now))
    for digest in (
        grant.admission_digest,
        grant.collision_budget_digest,
        grant.collision_budget_summary_digest,
        grant.collision_budget_events_digest,
        grant.collision_budget_transcript_events_digest,
        grant.session_registry_summary_digest,
    ):
        _require_digest(digest, "BROKER_COLLISION_EFFECT_GRANT_INVALID")
    if (
        grant.execution_locus != admission.INLINE_BROKER_LAMBDA
        or grant.session_mode != admission.POST_READER_RUNTIME
        or grant.not_before >= grant.expires_at
        or not grant.not_before <= checked_now < grant.expires_at
        or not grant.sealed_at
        <= checked_now
        <= grant.sealed_at + MAX_ADMISSION_AGE
    ):
        _fail("BROKER_COLLISION_ADMISSION_NOT_ACTIVE")
    return grant.admission_digest


__all__ = [
    "BrokerCollisionAdmissionError",
    "BrokerCollisionAdmissionEffectGrant",
    "MAX_MATERIALIZED_SESSION_POLICY_BYTES",
    "MAX_SESSION_POLICY_BYTES",
    "MIN_SESSION_POLICY_HEADROOM_BYTES",
    "broker_collision_admission_manifest",
    "consume_broker_collision_admission",
    "execute_inline_broker_collision_admission",
    "materialize_assume_role_session_policy",
    "revalidate_broker_collision_admission_effect_grant",
]
