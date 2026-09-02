"""Pre-reader direct-SSO adapter for the atomic GUG-376 collision gate.

Profile names and expected identity digests come only from the private,
previously validated GUG-395 request.  The adapter rejects ambient AWS
configuration, default/chained/static/admin/bootstrap/deploy profiles, loads
the reviewed SDK runtime, opens one source binding per domain, and derives one
fresh SDK session object per requested snapshot from those two temporary
bindings.  This mode deliberately makes no claim that the ten scan sessions
have ten distinct credentials or 900-second STS lifetimes.  Once both reader
roles exist, the operation matrix must select the separate broker-role path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling import platform_authority_gug376_collision_admission as admission
from tooling import platform_authority_gug376_collision_aws_provider as provider
from tooling import platform_authority_gug376_collision_policy as collision_policy
from tooling.platform_authority_gug376_collision_catalog import (
    validate_route_collision_catalog,
)
from tooling.platform_authority_gug395_preplan_collision_probe import (
    ABSENT_READY as GUG395_ABSENT_READY,
)
from tooling import platform_authority_gug376_live_provider as live


class DirectSsoCollisionAdapterError(RuntimeError):
    """Stable, value-free connected-adapter failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


Clock = Callable[[], datetime]

_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9.-]{16}$")
_KMS = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/[A-Za-z0-9-]{8,128}$"
)
LOCAL_DIRECT_SSO = admission.LOCAL_DIRECT_SSO

_SESSION_PURPOSES = {
    "inventory": {
        1: "policy-discovery-independent-scan-1",
        2: "policy-discovery-independent-scan-2",
    },
    "inventory-and-candidate-detail": {
        1: "independent-snapshot-1",
        2: "independent-snapshot-2",
        3: "pre-effect-snapshot",
    },
}
_BUDGET_STAGE = {
    "inventory": "inventory",
    "inventory-and-candidate-detail": "candidate-detail",
}


def _fail(code: str) -> None:
    raise DirectSsoCollisionAdapterError(code)


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("COLLISION_DIRECT_SSO_WINDOW_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise DirectSsoCollisionAdapterError(
            "COLLISION_DIRECT_SSO_WINDOW_INVALID"
        ) from None
    normalized = parsed.astimezone(UTC).replace(microsecond=0)
    if normalized.isoformat().replace("+00:00", "Z") != value:
        _fail("COLLISION_DIRECT_SSO_WINDOW_INVALID")
    return normalized


def _permission_set_index(policy_set: Mapping[str, Any]) -> dict[str, str]:
    if policy_set.get("stage") == "inventory":
        return {}
    evidence = policy_set.get("discovery_evidence")
    domains = evidence.get("domains") if isinstance(evidence, Mapping) else None
    management = (
        domains.get("management") if isinstance(domains, Mapping) else None
    )
    group = (
        management.get("sso_permission_set")
        if isinstance(management, Mapping)
        else None
    )
    pages = group.get("pages") if isinstance(group, Mapping) else None
    if not isinstance(pages, list):
        _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
    result: dict[str, str] = {}
    for page in pages:
        items = page.get("items") if isinstance(page, Mapping) else None
        if not isinstance(items, list):
            _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
        for item in items:
            arn = item.get("PermissionSetArn") if isinstance(item, Mapping) else None
            name = item.get("Name") if isinstance(item, Mapping) else None
            if (
                not isinstance(arn, str)
                or not isinstance(name, str)
                or not name
                or arn in result
            ):
                _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
            result[arn] = name
    return dict(sorted(result.items()))


class _GuardedSdkSession:
    """Pin retry, endpoint, region, TLS and SDK provenance for every client."""

    __slots__ = ("_session", "_config_factory", "_sdk_guard")

    def __init__(
        self,
        session: object,
        *,
        config_factory: Callable[..., object],
        sdk_guard: Callable[[], None],
    ) -> None:
        self._session = session
        self._config_factory = config_factory
        self._sdk_guard = sdk_guard

    def client(self, service: str, *, region_name: str) -> object:
        expected_host = live._EXACT_SERVICE_ENDPOINT_HOSTS.get(service)  # noqa: SLF001
        if region_name != provider.REGION or expected_host is None:
            _fail("COLLISION_DIRECT_SSO_CLIENT_FORBIDDEN")
        self._sdk_guard()
        try:
            config = self._config_factory(
                region_name=region_name,
                retries={"mode": "standard", "total_max_attempts": 1},
                connect_timeout=15,
                read_timeout=60,
                parameter_validation=True,
                tcp_keepalive=True,
                ignore_configured_endpoint_urls=True,
                user_agent_extra="scanalyze-gug376-atomic-collision/1",
            )
            client = self._session.client(
                service,
                region_name=region_name,
                config=config,
            )
            endpoint = getattr(getattr(client, "meta", None), "endpoint_url", None)
            host = urlsplit(endpoint).hostname if isinstance(endpoint, str) else None
        except DirectSsoCollisionAdapterError:
            raise
        except Exception:
            raise DirectSsoCollisionAdapterError(
                "COLLISION_DIRECT_SSO_CLIENT_OPEN_FAILED"
            ) from None
        self._sdk_guard()
        if host != expected_host:
            _fail("COLLISION_DIRECT_SSO_ENDPOINT_INVALID")
        return client


class _Adapter:
    __slots__ = (
        "_profiles",
        "_catalog",
        "_loaded_sdk",
        "_clock",
        "_required_end",
        "_instance_arn",
        "_kms_mode",
        "_kms_key_arn",
        "_kms_binding_digest",
        "_ordinal",
        "_source_bindings",
        "_budget",
    )

    def __init__(
        self,
        *,
        private_root: Path,
        catalog: Mapping[str, Any],
        environment: Mapping[str, str],
        clock: Clock,
        required_end: datetime,
        expected_gug395_request_digest: str,
        expected_gug395_receipt_digest: str,
        expected_gug395_bundle_digest: str,
        identity_center_instance_arn: str,
        identity_center_kms_mode: str,
        identity_center_kms_key_arn: str | None,
        identity_center_kms_binding_digest: str,
    ) -> None:
        if not callable(clock):
            _fail("COLLISION_DIRECT_SSO_CONFIG_INVALID")
        if any(
            _DIGEST.fullmatch(value) is None
            for value in (
                expected_gug395_request_digest,
                expected_gug395_receipt_digest,
                expected_gug395_bundle_digest,
            )
        ):
            _fail("COLLISION_DIRECT_SSO_GUG395_LINEAGE_INVALID")
        try:
            # Populate the cache only from the same exact lineage bundle whose
            # three seals were captured in the private atomic context.
            bundle, evidence, receipt = admission._gug395_bundle(  # noqa: SLF001
                private_root
            )
            request = evidence["request"]
        except Exception:
            raise DirectSsoCollisionAdapterError(
                "COLLISION_DIRECT_SSO_GUG395_INVALID"
            ) from None
        if (
            evidence.get("request_digest")
            != expected_gug395_request_digest
            or receipt.get("receipt_digest")
            != expected_gug395_receipt_digest
            or bundle.get("bundle_digest")
            != expected_gug395_bundle_digest
        ):
            _fail("COLLISION_DIRECT_SSO_GUG395_LINEAGE_CHANGED")
        profiles = request.get("profiles") if isinstance(request, Mapping) else None
        sdk_runtime_root = (
            request.get("sdk_runtime_root") if isinstance(request, Mapping) else None
        )
        try:
            validate_route_collision_catalog(catalog)
            checked_catalog = json.loads(canonical_json(catalog))
        except Exception:
            _fail("COLLISION_DIRECT_SSO_CATALOG_INVALID")
        targets = request.get("targets") if isinstance(request, Mapping) else None
        selector_instances = {
            targets[name].get("instance_arn")
            for name in (
                "identity_center_application",
                "classifier_permission_set",
                "approver_permission_set",
            )
            if isinstance(targets, Mapping)
            and isinstance(targets.get(name), Mapping)
        }
        if (
            not isinstance(profiles, Mapping)
            or set(profiles) != {"authority", "identity_center"}
            or not isinstance(sdk_runtime_root, str)
            or not Path(sdk_runtime_root).is_absolute()
            or request.get("source_commit_sha")
            != catalog.get("source_commit_sha")
            or request.get("source_tree_sha") != catalog.get("source_tree_sha")
            or receipt.get("classification") != GUG395_ABSENT_READY
            or receipt.get("read_only") is not True
            or receipt.get("aws_mutations") != 0
            or required_end != _time(catalog.get("expires_at"))
            or _INSTANCE.fullmatch(identity_center_instance_arn) is None
            or selector_instances != {identity_center_instance_arn}
        ):
            _fail("COLLISION_DIRECT_SSO_GUG395_INVALID")
        checked_profiles: dict[str, dict[str, str]] = {}
        for domain in ("authority", "identity_center"):
            value = profiles.get(domain)
            if not isinstance(value, Mapping):
                _fail("COLLISION_DIRECT_SSO_PROFILE_INVALID")
            name = value.get("name")
            if (
                not isinstance(name, str)
                or _PROFILE.fullmatch(name) is None
                or name.casefold() == "default"
                or live._forbidden_authority_name(name)  # noqa: SLF001
            ):
                _fail("COLLISION_DIRECT_SSO_PROFILE_INVALID")
            fields = {
                key: value.get(key)
                for key in (
                    "name",
                    "expected_account_id",
                    "expected_principal_digest",
                    "expected_sso_role_name_digest",
                    "authority_verification_digest",
                )
            }
            if any(
                not isinstance(item, str)
                or (
                    key.endswith("digest")
                    and _DIGEST.fullmatch(item) is None
                )
                for key, item in fields.items()
            ):
                _fail("COLLISION_DIRECT_SSO_PROFILE_INVALID")
            checked_profiles[domain] = dict(fields)  # type: ignore[arg-type]
        if (
            checked_profiles["authority"]["name"].casefold()
            == checked_profiles["identity_center"]["name"].casefold()
        ):
            _fail("COLLISION_DIRECT_SSO_PROFILE_INVALID")
        try:
            live._ambient_gate(environment)  # noqa: SLF001
            loaded = live._load_sdk(Path(sdk_runtime_root))  # noqa: SLF001
        except Exception:
            raise DirectSsoCollisionAdapterError(
                "COLLISION_DIRECT_SSO_SDK_INVALID"
            ) from None
        if (
            identity_center_kms_mode
            not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
            or (
                identity_center_kms_mode == "AWS_OWNED_KMS_KEY"
                and identity_center_kms_key_arn is not None
            )
            or (
                identity_center_kms_mode == "CUSTOMER_MANAGED_KEY"
                and _KMS.fullmatch(str(identity_center_kms_key_arn)) is None
            )
            or _DIGEST.fullmatch(identity_center_kms_binding_digest) is None
            or identity_center_kms_binding_digest
            != canonical_digest(
                {
                    "binding_name": "identity_center_kms_key_arn",
                    "identity_center_instance_arn": (
                        identity_center_instance_arn
                    ),
                    "mode": identity_center_kms_mode,
                    "key_arn": identity_center_kms_key_arn,
                }
            )
        ):
            _fail("COLLISION_DIRECT_SSO_KMS_BINDING_INVALID")
        self._profiles = MappingProxyType(checked_profiles)
        self._catalog = MappingProxyType(checked_catalog)
        self._loaded_sdk = loaded
        self._clock = clock
        self._required_end = required_end
        self._instance_arn = identity_center_instance_arn
        self._kms_mode = identity_center_kms_mode
        self._kms_key_arn = identity_center_kms_key_arn
        self._kms_binding_digest = identity_center_kms_binding_digest
        self._ordinal = 0
        self._source_bindings: dict[str, tuple[Any, str, str]] = {}
        self._budget: object | None = None

    def _source_binding(
        self,
        *,
        source_domain: str,
        budget: object,
    ) -> tuple[Any, str, str]:
        cached = self._source_bindings.get(source_domain)
        if cached is not None:
            return cached
        binding = self._profiles[source_domain]
        vend_observed = False

        def record_vend(_operation: str) -> None:
            nonlocal vend_observed
            if vend_observed:
                _fail("COLLISION_DIRECT_SSO_SOURCE_BINDING_INVALID")
            vend_observed = True

        try:
            self._loaded_sdk.guard()
            session = self._loaded_sdk.session_factory(
                profile_name=binding["name"],
                region_name=provider.REGION,
            )
            now = self._clock()
            if not isinstance(now, datetime) or now.tzinfo is None:
                _fail("COLLISION_DIRECT_SSO_CLOCK_INVALID")
            _expiry, source_binding_digest, frozen = (
                live._validate_direct_sso_profile(  # noqa: SLF001
                    session,
                    profile_name=binding["name"],
                    account_id=binding["expected_account_id"],
                    sso_role_name_digest=binding[
                        "expected_sso_role_name_digest"
                    ],
                    region=provider.REGION,
                    opened_at=now.astimezone(UTC).replace(microsecond=0),
                    required_end=self._required_end,
                    observe_credential_bootstrap=True,
                    credential_vend_recorder=record_vend,
                )
            )
            _full, profile_document = live._profile_document(  # noqa: SLF001
                session,
                binding["name"],
            )
            role_name = profile_document.get("sso_role_name")
            if not isinstance(role_name, str):
                _fail("COLLISION_DIRECT_SSO_PROFILE_INVALID")
            recorder = getattr(budget, "record_source_credential_binding", None)
            if not callable(recorder):
                _fail("COLLISION_DIRECT_SSO_BUDGET_INVALID")
            recorder(
                domain=(
                    "authority"
                    if source_domain == "authority"
                    else "management"
                ),
                binding_digest=source_binding_digest,
                credential_vended=vend_observed,
            )
        except DirectSsoCollisionAdapterError:
            raise
        except Exception:
            raise DirectSsoCollisionAdapterError(
                "COLLISION_DIRECT_SSO_SOURCE_BINDING_INVALID"
            ) from None
        checked = (frozen, source_binding_digest, role_name)
        self._source_bindings[source_domain] = checked
        return checked

    def for_policy(
        self,
        policy_set: Mapping[str, Any],
        budget: object,
        session_mode: str,
    ) -> provider.SessionOpener:
        if session_mode != LOCAL_DIRECT_SSO:
            _fail("COLLISION_DIRECT_SSO_MODE_FORBIDDEN")
        try:
            collision_policy.validate_route_collision_policy_set(
                policy_set,
                catalog=self._catalog,
            )
        except Exception:
            _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
        digest = policy_set.get("policy_set_digest")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
        names = _permission_set_index(policy_set)
        expected_purposes = _SESSION_PURPOSES.get(str(policy_set.get("stage")))
        budget_stage = _BUDGET_STAGE.get(str(policy_set.get("stage")))
        if expected_purposes is None or budget_stage is None:
            _fail("COLLISION_DIRECT_SSO_POLICY_INVALID")
        if self._budget is None:
            self._budget = budget
        elif self._budget is not budget:
            _fail("COLLISION_DIRECT_SSO_BUDGET_REUSE_FORBIDDEN")

        def open_session(
            *,
            domain: str,
            expected_account_id: str,
            region: str,
            capture_index: int,
            purpose: str,
        ) -> provider.OpenedReadOnlySession:
            if domain not in {"authority", "management"}:
                _fail("COLLISION_DIRECT_SSO_DOMAIN_INVALID")
            source_domain = (
                "authority" if domain == "authority" else "identity_center"
            )
            binding = self._profiles[source_domain]
            if (
                expected_account_id != binding["expected_account_id"]
                or region != provider.REGION
                or type(capture_index) is not int
                or expected_purposes.get(capture_index) != purpose
            ):
                _fail("COLLISION_DIRECT_SSO_SESSION_BINDING_INVALID")
            try:
                reserver = getattr(budget, "reserve_direct_sso_session_open", None)
                if not callable(reserver):
                    _fail("COLLISION_DIRECT_SSO_BUDGET_INVALID")
                reserver(
                    domain=domain,
                    policy_stage=budget_stage,
                    capture_index=capture_index,
                    purpose=purpose,
                )
                frozen, source_binding_digest, role_name = self._source_binding(
                    source_domain=source_domain,
                    budget=budget,
                )
                self._loaded_sdk.guard()
                session = self._loaded_sdk.session_factory(
                    aws_access_key_id=frozen.access_key,
                    aws_secret_access_key=frozen.secret_key,
                    aws_session_token=frozen.token,
                    region_name=region,
                )
                now = self._clock()
                if not isinstance(now, datetime) or now.tzinfo is None:
                    _fail("COLLISION_DIRECT_SSO_CLOCK_INVALID")
            except DirectSsoCollisionAdapterError:
                raise
            except Exception:
                raise DirectSsoCollisionAdapterError(
                    "COLLISION_DIRECT_SSO_SESSION_OPEN_FAILED"
                ) from None
            self._ordinal += 1
            guarded = _GuardedSdkSession(
                session,
                config_factory=self._loaded_sdk.config_factory,
                sdk_guard=self._loaded_sdk.guard,
            )
            return provider.OpenedReadOnlySession(
                sdk_session=guarded,
                principal_arn=None,
                sso_role_name=role_name,
                policy_digest=digest,
                authority_verification_digest=binding[
                    "authority_verification_digest"
                ],
                session_nonce_digest=canonical_digest(
                    {
                        "source_binding_digest": source_binding_digest,
                        "session_mode": LOCAL_DIRECT_SSO,
                        "domain": domain,
                        "capture_index": capture_index,
                        "purpose": purpose,
                        "ordinal": self._ordinal,
                    }
                ),
                identity_center_instance_arn=(
                    self._instance_arn if domain == "management" else None
                ),
                permission_set_name_by_arn=(
                    names if domain == "management" else {}
                ),
                identity_center_kms_mode=(
                    self._kms_mode if domain == "management" else None
                ),
                identity_center_kms_key_arn=(
                    self._kms_key_arn if domain == "management" else None
                ),
                identity_center_kms_binding_source=(
                    "GUG393_PRIVATE_MATERIALIZATION"
                    if domain == "management"
                    else None
                ),
                identity_center_kms_private_binding_digest=(
                    self._kms_binding_digest
                    if domain == "management"
                    else None
                ),
            )

        return open_session


def build_direct_sso_policy_session_opener_factory(
    *,
    private_root: Path,
    catalog: Mapping[str, Any],
    environment: Mapping[str, str],
    clock: Clock,
    expires_at: str,
    expected_gug395_request_digest: str,
    expected_gug395_receipt_digest: str,
    expected_gug395_bundle_digest: str,
    identity_center_instance_arn: str,
    identity_center_kms_mode: str,
    identity_center_kms_key_arn: str | None,
    identity_center_kms_binding_digest: str,
) -> Callable[[Mapping[str, Any], object, str], provider.SessionOpener]:
    """Build the concrete, policy-bound opener factory used by atomic loads."""

    adapter = _Adapter(
        private_root=private_root,
        catalog=catalog,
        environment=environment,
        clock=clock,
        required_end=_time(expires_at),
        expected_gug395_request_digest=expected_gug395_request_digest,
        expected_gug395_receipt_digest=expected_gug395_receipt_digest,
        expected_gug395_bundle_digest=expected_gug395_bundle_digest,
        identity_center_instance_arn=identity_center_instance_arn,
        identity_center_kms_mode=identity_center_kms_mode,
        identity_center_kms_key_arn=identity_center_kms_key_arn,
        identity_center_kms_binding_digest=(
            identity_center_kms_binding_digest
        ),
    )
    return adapter.for_policy


__all__ = [
    "DirectSsoCollisionAdapterError",
    "LOCAL_DIRECT_SSO",
    "build_direct_sso_policy_session_opener_factory",
]
