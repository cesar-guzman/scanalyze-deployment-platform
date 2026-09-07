"""Atomic, typed GUG-376 collision admission for known mutating providers.

The returned loader is called by the existing route, artifact-bootstrap, and
recovery providers immediately before their create-only mutation claim.  It
performs the two independent discovery scans, materializes the exact candidate
policy, performs the three admission snapshots, and returns the one-shot
capability in the same process.  It never executes a command or accepts an
effect callback.

Each effect owns a fresh, distinct ``0700`` admission root.  A separately
bound, immutable GUG-395 ``ABSENT_READY`` lineage root is reopened before the
scan and again while the admission request is materialized.  Evidence is never
copied between roots.  The fixed create-only filenames therefore remain
collision-free while preserving both effect custody and baseline provenance.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling import platform_authority_gug376_collision_admission as admission
from tooling import (
    platform_authority_gug376_collision_admission_executor as executor,
)
from tooling import platform_authority_gug376_collision_aws_provider as provider
from tooling import platform_authority_gug376_collision_budget as collision_budget
from tooling import platform_authority_gug376_collision_policy as policy
from tooling.platform_authority_gug376_collision_catalog import (
    validate_route_collision_catalog,
)


class AtomicCollisionAdmissionError(admission.RouteCollisionAdmissionError):
    """Stable, value-free failure at the atomic loader boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)


PolicySessionOpenerFactory = Callable[
    [Mapping[str, Any], object, str], provider.SessionOpener
]
IdentityBindingsFactory = Callable[..., Mapping[str, Any]]
Clock = Callable[[], datetime]
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _fail(code: str) -> None:
    raise AtomicCollisionAdmissionError(code)


def _stamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("ATOMIC_COLLISION_CLOCK_INVALID")
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise AtomicCollisionAdmissionError(
            "ATOMIC_COLLISION_WINDOW_INVALID"
        ) from None
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if _stamp(normalized) != value:
        _fail("ATOMIC_COLLISION_WINDOW_INVALID")
    return normalized


def _root(value: Path, *, code: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute() or candidate.is_symlink():
        _fail(code)
    try:
        resolved = candidate.resolve(strict=True)
        mode = resolved.stat().st_mode & 0o777
    except OSError:
        raise AtomicCollisionAdmissionError(code) from None
    if resolved != candidate or not resolved.is_dir() or mode != 0o700:
        _fail(code)
    return resolved


@dataclass(frozen=True, slots=True)
class AtomicCollisionAdmissionConfig:
    """Private, operation-independent inputs for one effect admission."""

    admission_private_root: Path
    effect_private_root: Path
    gug395_private_root: Path
    effect_private_root_digest: str
    atomic_context_digest: str
    expected_gug395_request_digest: str
    expected_gug395_receipt_digest: str
    expected_gug395_bundle_digest: str
    approval_reference_digest: str
    approved_operation: str
    authorized_at: str
    expires_at: str
    execution_locus: str
    catalog: Mapping[str, Any]
    identity_center_instance_arn: str
    identity_center_kms_binding_digest: str
    session_opener_factory: PolicySessionOpenerFactory
    identity_bindings_factory: IdentityBindingsFactory
    clock: Clock


def _validated_config(
    value: AtomicCollisionAdmissionConfig,
) -> AtomicCollisionAdmissionConfig:
    if type(value) is not AtomicCollisionAdmissionConfig:
        _fail("ATOMIC_COLLISION_CONFIG_INVALID")
    admission_root = _root(
        value.admission_private_root,
        code="ATOMIC_COLLISION_ADMISSION_ROOT_INVALID",
    )
    effect_root = _root(
        value.effect_private_root,
        code="ATOMIC_COLLISION_EFFECT_ROOT_INVALID",
    )
    gug395_root = _root(
        value.gug395_private_root,
        code="ATOMIC_COLLISION_GUG395_ROOT_INVALID",
    )
    if len({admission_root, effect_root, gug395_root}) != 3:
        _fail("ATOMIC_COLLISION_ROOT_REUSE_FORBIDDEN")
    if (
        not callable(value.session_opener_factory)
        or not callable(value.identity_bindings_factory)
        or not callable(value.clock)
    ):
        _fail("ATOMIC_COLLISION_CONFIG_INVALID")
    try:
        validate_route_collision_catalog(value.catalog)
    except Exception:
        raise AtomicCollisionAdmissionError(
            "ATOMIC_COLLISION_CATALOG_INVALID"
        ) from None
    if (
        not isinstance(value.effect_private_root_digest, str)
        or value.effect_private_root_digest
        != admission._private_root_digest(effect_root)  # noqa: SLF001
        or not isinstance(value.atomic_context_digest, str)
        or _DIGEST.fullmatch(value.atomic_context_digest) is None
        or not isinstance(value.expected_gug395_request_digest, str)
        or _DIGEST.fullmatch(value.expected_gug395_request_digest) is None
        or not isinstance(value.expected_gug395_receipt_digest, str)
        or _DIGEST.fullmatch(value.expected_gug395_receipt_digest) is None
        or not isinstance(value.expected_gug395_bundle_digest, str)
        or _DIGEST.fullmatch(value.expected_gug395_bundle_digest) is None
        or value.effect_private_root_digest == admission._private_root_digest(  # noqa: SLF001
            admission_root
        )
        or value.execution_locus != admission.LOCAL_ATOMIC_CLI
        or not isinstance(value.identity_center_instance_arn, str)
        or not value.identity_center_instance_arn.startswith(
            "arn:aws:sso:::instance/ssoins-"
        )
        or not isinstance(value.identity_center_kms_binding_digest, str)
        or _DIGEST.fullmatch(value.identity_center_kms_binding_digest) is None
    ):
        _fail("ATOMIC_COLLISION_PRIVATE_BINDING_INVALID")
    authorized_at = _time(value.authorized_at)
    expires_at = _time(value.expires_at)
    if (
        not isinstance(value.approval_reference_digest, str)
        or _DIGEST.fullmatch(value.approval_reference_digest) is None
        or not isinstance(value.approved_operation, str)
        or not value.approved_operation
        or value.authorized_at != value.catalog.get("not_before")
        or value.expires_at != value.catalog.get("expires_at")
        or not authorized_at < expires_at
        or expires_at - authorized_at > timedelta(minutes=15)
    ):
        _fail("ATOMIC_COLLISION_APPROVAL_BINDING_INVALID")
    try:
        admission.collision_session_mode_for_operation(
            value.approved_operation,
            execution_locus=admission.LOCAL_ATOMIC_CLI,
        )
    except Exception:
        raise AtomicCollisionAdmissionError(
            "ATOMIC_COLLISION_APPROVAL_BINDING_INVALID"
        ) from None
    # Do not retain a caller-owned mutable mapping after validation.
    try:
        checked_catalog = json.loads(canonical_json(value.catalog))
    except (TypeError, ValueError):
        raise AtomicCollisionAdmissionError(
            "ATOMIC_COLLISION_CATALOG_INVALID"
        ) from None
    return AtomicCollisionAdmissionConfig(
        admission_private_root=admission_root,
        effect_private_root=effect_root,
        gug395_private_root=gug395_root,
        effect_private_root_digest=value.effect_private_root_digest,
        atomic_context_digest=value.atomic_context_digest,
        expected_gug395_request_digest=(
            value.expected_gug395_request_digest
        ),
        expected_gug395_receipt_digest=(
            value.expected_gug395_receipt_digest
        ),
        expected_gug395_bundle_digest=value.expected_gug395_bundle_digest,
        approval_reference_digest=value.approval_reference_digest,
        approved_operation=value.approved_operation,
        authorized_at=value.authorized_at,
        expires_at=value.expires_at,
        execution_locus=value.execution_locus,
        catalog=checked_catalog,
        identity_center_instance_arn=value.identity_center_instance_arn,
        identity_center_kms_binding_digest=(
            value.identity_center_kms_binding_digest
        ),
        session_opener_factory=value.session_opener_factory,
        identity_bindings_factory=value.identity_bindings_factory,
        clock=value.clock,
    )


def _assert_gug395_lineage_unchanged(
    config: AtomicCollisionAdmissionConfig,
) -> None:
    """Reopen and bind the exact immutable GUG-395 baseline artifacts."""

    try:
        bundle, evidence, receipt = admission._gug395_bundle(  # noqa: SLF001
            config.gug395_private_root
        )
    except Exception:
        raise AtomicCollisionAdmissionError(
            "ATOMIC_COLLISION_GUG395_LINEAGE_INVALID"
        ) from None
    if (
        evidence.get("request_digest")
        != config.expected_gug395_request_digest
        or receipt.get("receipt_digest")
        != config.expected_gug395_receipt_digest
        or bundle.get("bundle_digest")
        != config.expected_gug395_bundle_digest
    ):
        _fail("ATOMIC_COLLISION_GUG395_LINEAGE_CHANGED")


class _WindowClock:
    """Reject regressions and enforce the catalog window before every call."""

    __slots__ = ("_clock", "_not_before", "_expires_at", "_last")

    def __init__(self, clock: Clock, catalog: Mapping[str, Any]) -> None:
        self._clock = clock
        self._not_before = _time(catalog.get("not_before"))
        self._expires_at = _time(catalog.get("expires_at"))
        self._last: datetime | None = None

    def __call__(self) -> datetime:
        try:
            observed = self._clock()
        except Exception:
            raise AtomicCollisionAdmissionError(
                "ATOMIC_COLLISION_CLOCK_INVALID"
            ) from None
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            _fail("ATOMIC_COLLISION_CLOCK_INVALID")
        checked = observed.astimezone(UTC).replace(microsecond=0)
        if (
            (self._last is not None and checked < self._last)
            or not self._not_before <= checked < self._expires_at
        ):
            _fail("ATOMIC_COLLISION_WINDOW_NOT_ACTIVE")
        self._last = checked
        return checked


class _AtomicLoader:
    __slots__ = ("_config", "_active")

    def __init__(self, config: AtomicCollisionAdmissionConfig) -> None:
        self._config = _validated_config(config)
        self._active = True

    def __call__(
        self,
        *,
        operation: str,
        effect_request_digest: str,
        bootstrap_intent_digest: str,
        now: datetime,
        effect_request: Mapping[str, Any] | None = None,
    ) -> admission.RouteCollisionAdmissionCapability:
        """Mint and return exactly one action-time capability.

        Existing provider loader protocols pass only the effect digest.  The
        typed integration should bind ``effect_request`` when constructing the
        loader; accepting it here supports providers that already retain the
        request object without adding a generic execution callback.
        """

        if not self._active:
            _fail("ATOMIC_COLLISION_LOADER_ALREADY_USED")
        self._active = False
        if not isinstance(effect_request, Mapping) or not effect_request:
            _fail("ATOMIC_COLLISION_EFFECT_REQUEST_REQUIRED")
        if canonical_digest(effect_request) != effect_request_digest:
            _fail("ATOMIC_COLLISION_EFFECT_BINDING_INVALID")
        catalog = self._config.catalog
        if (
            operation != self._config.approved_operation
            or bootstrap_intent_digest != catalog.get("bootstrap_intent_digest")
            or not isinstance(now, datetime)
            or now.tzinfo is None
        ):
            _fail("ATOMIC_COLLISION_EFFECT_BINDING_INVALID")
        try:
            phase = admission.route_collision_operation_phase(operation)
            session_mode = admission.collision_session_mode_for_operation(
                operation,
                execution_locus=self._config.execution_locus,
            )
        except Exception:
            raise AtomicCollisionAdmissionError(
                "ATOMIC_COLLISION_OPERATION_INVALID"
            ) from None

        # Fail before opening any SDK session if the immutable baseline was
        # replaced after the private context was read.
        _assert_gug395_lineage_unchanged(self._config)

        active_clock = _WindowClock(self._config.clock, catalog)
        sampled_now = active_clock()
        supplied_now = now.astimezone(UTC).replace(microsecond=0)
        if supplied_now > sampled_now:
            _fail("ATOMIC_COLLISION_CLOCK_REGRESSED")

        try:
            registry = provider.build_session_uniqueness_registry()
            budget = collision_budget.build_collision_budget(
                session_mode=session_mode,
                operation=operation,
            )
            inventory_policy = policy.materialize_route_collision_policy_set(
                catalog,
                identity_center_instance_arn=(
                    self._config.identity_center_instance_arn
                ),
            )
            inventory_identities = self._config.identity_bindings_factory(
                private_root=self._config.gug395_private_root,
                collision_policy_set=inventory_policy,
                session_mode=session_mode,
            )
            inventory_opener = self._config.session_opener_factory(
                inventory_policy,
                budget,
                session_mode,
            )
            inventory_factory = provider.build_attested_provider_factory(
                session_opener=inventory_opener,
                clock=active_clock,
                policy_set=inventory_policy,
                before_call=active_clock,
                session_registry=registry,
                collision_budget_capability=budget,
                budget_stage="inventory",
            )
            discovery = (
                provider.assert_attested_provider_factory(
                    inventory_factory
                ).discover_route_collision_candidates(
                    catalog=catalog,
                    expected_identities=inventory_identities,
                    expected_identity_center_kms_binding_digest=(
                        self._config.identity_center_kms_binding_digest
                    ),
                )
            )
            candidate_policy = policy.materialize_route_collision_policy_set(
                catalog,
                discovery_capability=discovery,
                identity_center_instance_arn=(
                    self._config.identity_center_instance_arn
                ),
            )
            candidate_identities = self._config.identity_bindings_factory(
                private_root=self._config.gug395_private_root,
                collision_policy_set=candidate_policy,
                session_mode=session_mode,
            )
            candidate_opener = self._config.session_opener_factory(
                candidate_policy,
                budget,
                session_mode,
            )
            candidate_factory = provider.build_attested_provider_factory(
                session_opener=candidate_opener,
                clock=active_clock,
                policy_set=candidate_policy,
                discovery_capability=discovery,
                before_call=active_clock,
                session_registry=registry,
                collision_budget_capability=budget,
                budget_stage="candidate",
            )
            created_at = _stamp(active_clock())
            request = admission.materialize_route_collision_admission_request(
                private_root=self._config.admission_private_root,
                gug395_private_root=self._config.gug395_private_root,
                catalog=catalog,
                collision_policy_set=candidate_policy,
                phase=phase,
                operation=operation,
                effect_request=effect_request,
                source_commit_sha=str(catalog["source_commit_sha"]),
                source_tree_sha=str(catalog["source_tree_sha"]),
                bootstrap_intent_digest=bootstrap_intent_digest,
                effect_private_root_digest=(
                    self._config.effect_private_root_digest
                ),
                atomic_context_digest=self._config.atomic_context_digest,
                expected_gug395_request_digest=(
                    self._config.expected_gug395_request_digest
                ),
                expected_gug395_receipt_digest=(
                    self._config.expected_gug395_receipt_digest
                ),
                expected_gug395_bundle_digest=(
                    self._config.expected_gug395_bundle_digest
                ),
                expected_identities=candidate_identities,
                not_before=str(catalog["not_before"]),
                expires_at=str(catalog["expires_at"]),
                created_at=created_at,
            )
            admission.persist_route_collision_admission_request(
                private_root=self._config.admission_private_root,
                request=request,
            )
            result = executor.execute_route_collision_admission(
                provider_factory=candidate_factory,
                private_root=self._config.admission_private_root,
                expected_request_digest=str(request["request_digest"]),
                clock=active_clock,
                collision_budget_capability=budget,
                prior_transcript_events=(
                    inventory_factory.discovery_transcript_events()
                ),
                session_registry=registry,
            )
            digest = result.public_receipt.get("admission_digest")
            if not isinstance(digest, str):
                _fail("ATOMIC_COLLISION_RESULT_INVALID")
            return admission.read_route_collision_admission(
                private_root=self._config.admission_private_root,
                expected_admission_digest=digest,
                expected_operation=operation,
                expected_effect_request_digest=effect_request_digest,
                expected_bootstrap_intent_digest=bootstrap_intent_digest,
                now=active_clock(),
                require_collision_budget_evidence=True,
            )
        except AtomicCollisionAdmissionError:
            raise
        except Exception:
            # Connected SDK and private-custody failures may contain values.
            # Keep the atomic boundary stable and value-free.
            raise AtomicCollisionAdmissionError(
                "ATOMIC_COLLISION_ADMISSION_FAILED"
            ) from None


def build_atomic_route_collision_admission_loader(
    *,
    config: AtomicCollisionAdmissionConfig,
) -> object:
    """Build the only opaque loader accepted for full typed effect input."""

    return _AtomicLoader(config)


def is_atomic_route_collision_admission_loader(loader: object) -> bool:
    """Return true only for the opaque loader minted by this module."""

    return type(loader) is _AtomicLoader


def invoke_route_collision_admission_loader(
    loader: object,
    *,
    operation: str,
    effect_request: Mapping[str, Any],
    effect_request_digest: str,
    bootstrap_intent_digest: str,
    now: datetime,
) -> admission.RouteCollisionAdmissionCapability:
    """Invoke an atomic loader with the exact request or a legacy loader.

    Only the exact private class built above receives the effect request.  A
    callable cannot self-assert that it is atomic, so existing file-backed
    loaders keep their narrower digest-only protocol and no generic callback
    can obtain mutation inputs through this bridge.
    """

    if type(loader) is _AtomicLoader:
        return loader(
            operation=operation,
            effect_request_digest=effect_request_digest,
            bootstrap_intent_digest=bootstrap_intent_digest,
            now=now,
            effect_request=effect_request,
        )
    if not callable(loader):
        _fail("ATOMIC_COLLISION_LOADER_INVALID")
    return loader(
        operation=operation,
        effect_request_digest=effect_request_digest,
        bootstrap_intent_digest=bootstrap_intent_digest,
        now=now,
    )


__all__ = [
    "AtomicCollisionAdmissionConfig",
    "AtomicCollisionAdmissionError",
    "PolicySessionOpenerFactory",
    "build_atomic_route_collision_admission_loader",
    "is_atomic_route_collision_admission_loader",
    "invoke_route_collision_admission_loader",
]
