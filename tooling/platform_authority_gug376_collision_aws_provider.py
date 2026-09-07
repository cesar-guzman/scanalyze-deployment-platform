"""Attested, inert AWS provider for the GUG-376 collision admission gate.

The module performs no import-time SDK discovery and opens no ambient AWS
session.  Callers inject an already-governed session opener.  Every operation
is selected from the complete retained-name catalog, is constrained to the pure
transcript contract's read-only allowlist, and is projected to digests before
it leaves this module.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
import json
import re
from types import MappingProxyType
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_collision_catalog import (
    TARGET_COUNT,
    validate_route_collision_catalog,
)
from tooling import platform_authority_gug376_collision_policy as policy_contract
from tooling import platform_authority_gug376_collision_budget as collision_budget
from tooling import platform_authority_gug376_collision_transcript_contract as transcript


REGION = transcript.REGION
MAX_PAGES = transcript.MAX_PAGES
DEFAULT_MAX_ITEMS = 2_048
_CAPTURE_PURPOSES = {
    1: "independent-snapshot-1",
    2: "independent-snapshot-2",
    3: "pre-effect-snapshot",
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_IDENTITY_STORE = re.compile(r"^d-[A-Za-z0-9]{10}$")
_KMS_KEY_ARN = re.compile(
    rf"^arn:aws:kms:{REGION}:(?P<account>[0-9]{{12}}):key/"
    r"(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|mrk-[0-9a-f]{32})$"
)
_ROLE = re.compile(r"^[A-Za-z0-9+=,.@_/-]{1,128}$")
_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[^:]*:[0-9]{0,12}:.+$")
_FACTORY_TOKEN = object()
_SESSION_REGISTRY_TOKEN = object()
_DISCOVERY_CAPABILITY_TOKEN = object()
_DISCOVERY_SCAN_PURPOSES = {
    1: "policy-discovery-independent-scan-1",
    2: "policy-discovery-independent-scan-2",
}
_DISCOVERY_CAPABILITY_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_collision_discovery_capability.v1"
)
_DISCOVERY_PROVENANCE_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_collision_discovery_provenance.v1"
)
_IDENTITY_CENTER_KMS_BINDING_SOURCE = (
    "GUG376_ATTESTED_IDENTITY_CENTER_KMS_BINDING"
)
_DEFAULT_OWNERSHIP_TAGS = {
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-376",
}


class CollisionAwsProviderError(RuntimeError):
    """Stable, value-free failure from the closed provider boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CollisionAwsProviderError(code)


def _copy(value: object, code: str = "COLLISION_PROVIDER_VALUE_INVALID") -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception:
        raise CollisionAwsProviderError(code) from None


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _stamp(value: object) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("COLLISION_PROVIDER_CLOCK_INVALID")
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


@dataclass(frozen=True, slots=True)
class OpenedReadOnlySession:
    """Non-secret provenance envelope returned by the injected opener.

    ``permission_set_name_by_arn`` is the closed selector index produced by
    the private request materializer.  AWS ListPermissionSets returns only
    ARNs, so unknown ARNs fail closed instead of being guessed or omitted.
    """

    sdk_session: object
    # Direct SSO adapters may not know the STS session name before the single
    # transcripted GetCallerIdentity call.  ``None`` is therefore accepted for
    # DIRECT_SSO only; the returned principal is digest-bound immediately
    # afterwards.  Broker role adapters still provide the exact principal.
    principal_arn: str | None
    sso_role_name: str
    policy_digest: str
    authority_verification_digest: str
    session_nonce_digest: str
    source: str = "DIRECT_SSO"
    chain_depth: int = 0
    role_arn: str | None = None
    role_policy_digest: str | None = None
    session_policy_digest: str | None = None
    identity_center_instance_arn: str | None = None
    permission_set_name_by_arn: Mapping[str, str] = field(default_factory=dict)
    identity_center_kms_mode: str | None = None
    identity_center_kms_key_arn: str | None = None
    identity_center_kms_binding_source: str | None = None
    identity_center_kms_private_binding_digest: str | None = None


SessionOpener = Callable[..., OpenedReadOnlySession]
Clock = Callable[[], datetime]
BeforeCall = Callable[[], None]


class _SessionUniquenessRegistry:
    """Process-local registry shared by discovery and snapshot factories."""

    __slots__ = (
        "_token",
        "session_digests",
        "session_nonce_digests",
        "sdk_sessions",
    )

    def __init__(self, token: object) -> None:
        if token is not _SESSION_REGISTRY_TOKEN:
            _fail("COLLISION_PROVIDER_SESSION_REGISTRY_INVALID")
        self._token = token
        self.session_digests: set[str] = set()
        self.session_nonce_digests: set[str] = set()
        self.sdk_sessions: list[object] = []


def build_session_uniqueness_registry() -> object:
    """Build the only registry accepted across one complete admission run."""

    return _SessionUniquenessRegistry(_SESSION_REGISTRY_TOKEN)


def session_uniqueness_registry_summary(registry: object) -> Mapping[str, Any]:
    """Return a digest-only proof of the globally reserved fresh sessions."""

    if (
        type(registry) is not _SessionUniquenessRegistry
        or registry._token is not _SESSION_REGISTRY_TOKEN
    ):
        _fail("COLLISION_PROVIDER_SESSION_REGISTRY_INVALID")
    return {
        "session_count": len(registry.session_digests),
        "session_nonce_count": len(registry.session_nonce_digests),
        "sdk_session_count": len(registry.sdk_sessions),
        "session_digests_digest": canonical_digest(
            sorted(registry.session_digests)
        ),
        "session_nonce_digests_digest": canonical_digest(
            sorted(registry.session_nonce_digests)
        ),
    }


@dataclass(slots=True)
class _PendingCall:
    capture_index: int
    domain: str
    account_id: str
    session_digest: str
    operation: str
    outcome: str
    route_request_digest: str
    page_index: int
    input_cursor_digest: str | None
    output_cursor_digest: str | None
    page_item_digests: list[str]
    target_ids: list[str]
    budget_reservation: object | None
    budget_event_bound: bool = False


@dataclass(frozen=True, slots=True)
class _Plan:
    operation: str
    service: str
    method: str
    request: Mapping[str, Any]
    item_key: str | None = None
    request_cursor: str | None = None
    response_cursor: str | None = None
    truncated_key: str | None = None

    @property
    def paginated(self) -> bool:
        return self.item_key is not None


class _RouteCollisionDiscoveryCapability:
    """Opaque one-shot bridge from connected inventory to candidate IAM."""

    __slots__ = (
        "_token",
        "_catalog_digest",
        "_inventory_policy_set_digest",
        "_evidence",
        "_candidate_resources",
        "_provenance",
        "_provenance_digest",
        "_capability_digest",
        "_state",
        "_candidate_policy_set_digest",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        _fail("COLLISION_DISCOVERY_CAPABILITY_SUBCLASS_FORBIDDEN")

    def __init__(
        self,
        token: object,
        *,
        catalog_digest: str,
        inventory_policy_set_digest: str,
        evidence: Mapping[str, Any],
        candidate_resources: Mapping[str, Any],
        provenance: Mapping[str, Any],
    ) -> None:
        if token is not _DISCOVERY_CAPABILITY_TOKEN:
            _fail("COLLISION_DISCOVERY_CAPABILITY_BUILDER_REQUIRED")
        copied_evidence = _copy(
            evidence,
            "COLLISION_DISCOVERY_CAPABILITY_INVALID",
        )
        copied_candidates = _copy(
            candidate_resources,
            "COLLISION_DISCOVERY_CAPABILITY_INVALID",
        )
        copied_provenance = _copy(
            provenance,
            "COLLISION_DISCOVERY_CAPABILITY_INVALID",
        )
        provenance_digest = canonical_digest(copied_provenance)
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_catalog_digest", catalog_digest)
        object.__setattr__(
            self,
            "_inventory_policy_set_digest",
            inventory_policy_set_digest,
        )
        object.__setattr__(self, "_evidence", copied_evidence)
        object.__setattr__(self, "_candidate_resources", copied_candidates)
        object.__setattr__(self, "_provenance", copied_provenance)
        object.__setattr__(self, "_provenance_digest", provenance_digest)
        object.__setattr__(
            self,
            "_capability_digest",
            canonical_digest(
                {
                    "record_type": _DISCOVERY_CAPABILITY_RECORD_TYPE,
                    "catalog_digest": catalog_digest,
                    "inventory_policy_set_digest": inventory_policy_set_digest,
                    "evidence_digest": canonical_digest(copied_evidence),
                    "candidate_resources_digest": canonical_digest(
                        copied_candidates
                    ),
                    "provenance_digest": provenance_digest,
                }
            ),
        )
        object.__setattr__(self, "_state", "DISCOVERED")
        object.__setattr__(self, "_candidate_policy_set_digest", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        _fail("COLLISION_DISCOVERY_CAPABILITY_IMMUTABLE")


def _assert_discovery_capability(value: object) -> _RouteCollisionDiscoveryCapability:
    if (
        type(value) is not _RouteCollisionDiscoveryCapability
        or value._token is not _DISCOVERY_CAPABILITY_TOKEN
        or value._provenance_digest != canonical_digest(value._provenance)
        or value._capability_digest
        != canonical_digest(
            {
                "record_type": _DISCOVERY_CAPABILITY_RECORD_TYPE,
                "catalog_digest": value._catalog_digest,
                "inventory_policy_set_digest": value._inventory_policy_set_digest,
                "evidence_digest": canonical_digest(value._evidence),
                "candidate_resources_digest": canonical_digest(
                    value._candidate_resources
                ),
                "provenance_digest": value._provenance_digest,
            }
        )
    ):
        _fail("COLLISION_DISCOVERY_CAPABILITY_NOT_ATTESTED")
    return value


def _target_map(request: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    catalog = request.get("catalog")
    if not isinstance(catalog, Mapping):
        _fail("COLLISION_PROVIDER_REQUEST_INVALID")
    try:
        validate_route_collision_catalog(catalog)
    except Exception:
        raise CollisionAwsProviderError("COLLISION_PROVIDER_CATALOG_INVALID") from None
    if request.get("catalog_digest") != catalog.get("catalog_digest"):
        _fail("COLLISION_PROVIDER_CATALOG_INVALID")
    route_digest = request.get("request_digest")
    _require_digest(route_digest, "COLLISION_PROVIDER_REQUEST_INVALID")
    targets = catalog.get("targets")
    if not isinstance(targets, list) or len(targets) != TARGET_COUNT:
        _fail("COLLISION_PROVIDER_CATALOG_INVALID")
    result = {str(value["target_id"]): _copy(value) for value in targets}
    if len(result) != TARGET_COUNT:
        _fail("COLLISION_PROVIDER_CATALOG_INVALID")
    return result


def _expected_identity(request: Mapping[str, Any], domain: str) -> dict[str, Any]:
    identities = request.get("expected_identities")
    value = identities.get(domain) if isinstance(identities, Mapping) else None
    if not isinstance(value, Mapping):
        _fail("COLLISION_PROVIDER_IDENTITY_BINDING_INVALID")
    direct_fields = {
        "account_id",
        "source",
        "chain_depth",
        "principal_digest",
        "sso_role_name_digest",
        "policy_digest",
        "authority_verification_digest",
    }
    broker_fields = direct_fields | {
        "role_arn_digest",
        "role_policy_digest",
        "session_policy_digest",
    }
    source = value.get("source")
    expected_fields = (
        direct_fields if source == "DIRECT_SSO" else broker_fields
    )
    if (
        source not in {"DIRECT_SSO", "BROKER_SERVICE_ROLE"}
        or set(value) != expected_fields
        or _ACCOUNT.fullmatch(str(value.get("account_id"))) is None
    ):
        _fail("COLLISION_PROVIDER_IDENTITY_BINDING_INVALID")
    digest_fields = [
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
    for name in digest_fields:
        _require_digest(value.get(name), "COLLISION_PROVIDER_IDENTITY_BINDING_INVALID")
    expected_depth = 0 if source == "DIRECT_SSO" else 1
    if value.get("chain_depth") != expected_depth:
        _fail("COLLISION_PROVIDER_IDENTITY_BINDING_INVALID")
    return _copy(value)


def _discovery_request(
    *,
    catalog: Mapping[str, Any],
    expected_identities: Mapping[str, Any],
    inventory_policy_set_digest: str,
    expected_identity_center_kms_binding_digest: str,
) -> dict[str, Any]:
    try:
        validate_route_collision_catalog(catalog)
    except Exception:
        raise CollisionAwsProviderError("COLLISION_PROVIDER_CATALOG_INVALID") from None
    _require_digest(
        expected_identity_center_kms_binding_digest,
        "COLLISION_DISCOVERY_KMS_BINDING_INVALID",
    )
    value = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug376_collision_discovery_request.v1"
        ),
        "schema_version": 1,
        "catalog": _copy(catalog),
        "catalog_digest": catalog["catalog_digest"],
        "inventory_policy_set_digest": inventory_policy_set_digest,
        "expected_identities": _copy(expected_identities),
        "expected_identity_center_kms_binding_digest": (
            expected_identity_center_kms_binding_digest
        ),
        "expected_dispositions": {},
    }
    for domain, account in (
        ("authority", "042360977644"),
        ("management", "839393571433"),
    ):
        identity = _expected_identity(value, domain)
        if (
            identity["account_id"] != account
            or identity["policy_digest"] != inventory_policy_set_digest
        ):
            _fail("COLLISION_PROVIDER_IDENTITY_BINDING_INVALID")
    value["request_digest"] = canonical_digest(value)
    return value


def _catalog_selector_attestation(catalog: Mapping[str, Any]) -> dict[str, Any]:
    bucket_name = catalog.get("artifact_bucket_name")
    bucket_target = next(
        (
            target
            for target in catalog.get("targets", [])
            if isinstance(target, Mapping)
            and target.get("target_id") == "authority.s3.artifact-bucket"
        ),
        None,
    )
    if (
        not isinstance(bucket_name, str)
        or not isinstance(bucket_target, Mapping)
        or bucket_target.get("name") != bucket_name
        or bucket_target.get("account_id") != "042360977644"
        or bucket_target.get("region") != REGION
    ):
        _fail("COLLISION_DISCOVERY_S3_SELECTOR_INVALID")
    value = {
        "catalog_digest": catalog["catalog_digest"],
        "artifact_bucket": {
            "target_id": "authority.s3.artifact-bucket",
            "bucket_name": bucket_name,
            "namespace": "account-regional",
            "owner_account_id": "042360977644",
            "region": REGION,
            "absence_operation": "s3:ListAllMyBuckets",
            "absence_request": {
                "BucketRegion": REGION,
                "Prefix": bucket_name,
                "MaxBuckets": 100,
            },
            "head_bucket_used": False,
        },
        "dynamic_discovery_plan": policy_contract.route_collision_discovery_plan(
            catalog
        ),
    }
    value["selector_attestation_digest"] = canonical_digest(value)
    return value


def _client_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return code if isinstance(code, str) else None


_NOT_FOUND_CODES: Mapping[str, frozenset[str]] = {
    "cloudformation:DescribeStacks": frozenset({"ValidationError"}),
    "cloudformation:DescribeStackResource": frozenset({"ValidationError"}),
    "dynamodb:DescribeTable": frozenset({"ResourceNotFoundException"}),
    "iam:GetRole": frozenset({"NoSuchEntity", "NoSuchEntityException"}),
    "lambda:GetAlias": frozenset({"ResourceNotFoundException"}),
    "lambda:GetCodeSigningConfig": frozenset({"ResourceNotFoundException"}),
    "lambda:GetFunction": frozenset({"ResourceNotFoundException"}),
    "signer:GetSigningProfile": frozenset({"ResourceNotFoundException"}),
    "sso:DescribeApplication": frozenset({"ResourceNotFoundException"}),
    "sso:DescribePermissionSet": frozenset({"ResourceNotFoundException"}),
}


def _without_metadata(value: object) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_metadata(item)
            for key, item in value.items()
            if key != "ResponseMetadata"
        }
    if isinstance(value, list):
        return [_without_metadata(item) for item in value]
    if isinstance(value, datetime):
        return _stamp(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return {
            "byte_length": len(value),
            "byte_digest": canonical_digest(value.hex()),
        }
    if value is not None and not isinstance(value, (str, int, float, bool)):
        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
    return value


def _as_items(response: Mapping[str, Any], key: str) -> list[Any]:
    values = response.get(key)
    if not isinstance(values, list):
        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
    return values


def _cursor(response: Mapping[str, Any], key: str | None, truncated: str | None) -> str | None:
    if key is None:
        return None
    value = response.get(key)
    if truncated is not None:
        flag = response.get(truncated, False)
        if flag not in {True, False}:
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        if flag is False:
            return None
    if value is None:
        if truncated is not None and response.get(truncated) is True:
            _fail("COLLISION_PROVIDER_PAGINATION_INVALID")
        return None
    if not isinstance(value, str) or not value or len(value) > 8_192:
        _fail("COLLISION_PROVIDER_PAGINATION_INVALID")
    return value


def _operation_plan(
    target: Mapping[str, Any], envelope: OpenedReadOnlySession
) -> _Plan:
    service = str(target.get("service"))
    scope = str(target.get("scope"))
    name = str(target.get("name"))
    selector = target.get("selector")
    selector = selector if isinstance(selector, Mapping) else {}
    kind = selector.get("kind")
    if (service, scope) == ("cloudformation", "stack"):
        return _Plan(
            "cloudformation:ListStacks", "cloudformation", "list_stacks",
            {
                "StackStatusFilter": [
                    "CREATE_COMPLETE", "CREATE_FAILED", "CREATE_IN_PROGRESS",
                    "DELETE_FAILED", "DELETE_IN_PROGRESS",
                    "IMPORT_COMPLETE", "IMPORT_IN_PROGRESS",
                    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
                    "IMPORT_ROLLBACK_IN_PROGRESS", "REVIEW_IN_PROGRESS",
                    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "ROLLBACK_IN_PROGRESS",
                    "UPDATE_COMPLETE", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
                    "UPDATE_FAILED", "UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
                    "UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS",
                ]
            },
            "StackSummaries", "NextToken", "NextToken",
        )
    if (service, scope) == ("dynamodb", "table"):
        return _Plan("dynamodb:DescribeTable", "dynamodb", "describe_table", {"TableName": name})
    if (service, scope) == ("iam", "role"):
        return _Plan("iam:GetRole", "iam", "get_role", {"RoleName": name.rsplit("/", 1)[-1]})
    if (service, scope) == ("kms", "alias"):
        return _Plan("kms:ListAliases", "kms", "list_aliases", {"Limit": 100}, "Aliases", "Marker", "NextMarker", "Truncated")
    if (service, scope) == ("lambda", "alias") and kind == "lambda_alias":
        return _Plan(
            "lambda:GetAlias", "lambda", "get_alias",
            {"FunctionName": selector.get("function_name"), "Name": selector.get("alias_name")},
        )
    if (service, scope) == ("lambda", "code_signing_config") and kind in {
        "cloudformation_stack_resource", "cloudformation_ownership_tags"
    }:
        return _Plan(
            "cloudformation:DescribeStackResource", "cloudformation", "describe_stack_resource",
            {"StackName": selector.get("stack_name"), "LogicalResourceId": selector.get("logical_resource_id")},
        )
    if (service, scope) == ("lambda", "function"):
        return _Plan("lambda:GetFunction", "lambda", "get_function", {"FunctionName": name})
    if (service, scope) == ("logs", "log_group"):
        return _Plan(
            "logs:DescribeLogGroups", "logs", "describe_log_groups",
            {"logGroupNamePrefix": name, "limit": 50}, "logGroups", "nextToken", "nextToken",
        )
    if (service, scope) == ("s3", "bucket"):
        return _Plan(
            "s3:ListAllMyBuckets", "s3", "list_buckets",
            {"BucketRegion": REGION, "Prefix": name, "MaxBuckets": 100},
            "Buckets", "ContinuationToken", "ContinuationToken",
        )
    if (service, scope) == ("signer", "signing_profile"):
        return _Plan("signer:GetSigningProfile", "signer", "get_signing_profile", {"profileName": name})
    if service == "sso" and scope in {"application", "permission_set"}:
        instance = envelope.identity_center_instance_arn
        if not isinstance(instance, str) or _ARN.fullmatch(instance) is None:
            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        if scope == "application":
            return _Plan(
                "sso:ListApplications", "sso-admin", "list_applications",
                {"InstanceArn": instance, "MaxResults": 100},
                "Applications", "NextToken", "NextToken",
            )
        return _Plan(
            "sso:ListPermissionSets", "sso-admin", "list_permission_sets",
            {"InstanceArn": instance, "MaxResults": 100},
            "PermissionSets", "NextToken", "NextToken",
        )
    _fail("COLLISION_PROVIDER_TARGET_UNSUPPORTED")


def _normalized_item(
    *, target: Mapping[str, Any], operation: str, item: object,
    envelope: OpenedReadOnlySession,
) -> Any:
    if operation == "sso:ListPermissionSets":
        arn = item if isinstance(item, str) else (
            item.get("PermissionSetArn") if isinstance(item, Mapping) else None
        )
        if not isinstance(arn, str) or _ARN.fullmatch(arn) is None:
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        indexed_name = envelope.permission_set_name_by_arn.get(arn)
        supplied_name = item.get("Name") if isinstance(item, Mapping) else None
        if not isinstance(indexed_name, str) or (
            supplied_name is not None and supplied_name != indexed_name
        ):
            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        return {
            "permission_set_arn_digest": canonical_digest(arn),
            "name_digest": canonical_digest(indexed_name),
        }
    return _without_metadata(item)


def _matches(
    *, target: Mapping[str, Any], operation: str, item: object,
    envelope: OpenedReadOnlySession,
) -> bool:
    name = str(target["name"])
    selector = target["selector"]
    if operation in {"cloudformation:DescribeStacks", "cloudformation:ListStacks"}:
        return isinstance(item, Mapping) and item.get("StackName") == name
    if operation == "dynamodb:DescribeTable":
        return isinstance(item, Mapping) and item.get("TableName") == name
    if operation == "iam:GetRole":
        if not isinstance(item, Mapping):
            return False
        path = item.get("Path", "/")
        role = item.get("RoleName")
        observed = f"{str(path).strip('/')}/{role}".strip("/")
        return observed == name
    if operation == "kms:ListAliases":
        return isinstance(item, Mapping) and item.get("AliasName") == name
    if operation == "lambda:GetAlias":
        return isinstance(item, Mapping) and item.get("Name") == selector.get("alias_name")
    if operation == "cloudformation:DescribeStackResource":
        return isinstance(item, Mapping) and item.get("LogicalResourceId") == selector.get("logical_resource_id")
    if operation == "lambda:GetFunction":
        return isinstance(item, Mapping) and item.get("FunctionName") == name
    if operation == "logs:DescribeLogGroups":
        return isinstance(item, Mapping) and item.get("logGroupName") == name
    if operation == "s3:ListAllMyBuckets":
        if not isinstance(item, Mapping):
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        observed_name = item.get("Name")
        if not isinstance(observed_name, str) or item.get("BucketRegion") != REGION:
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        return observed_name == name
    if operation == "signer:GetSigningProfile":
        return isinstance(item, Mapping) and item.get("profileName", name) == name
    if operation == "sso:ListApplications":
        return isinstance(item, Mapping) and item.get("Name") == name
    if operation == "sso:ListPermissionSets":
        arn = item if isinstance(item, str) else (
            item.get("PermissionSetArn") if isinstance(item, Mapping) else None
        )
        return isinstance(arn, str) and envelope.permission_set_name_by_arn.get(arn) == name
    return False


def _direct_items(operation: str, response: Mapping[str, Any]) -> list[Any]:
    if operation == "cloudformation:DescribeStacks":
        return _as_items(response, "Stacks")
    keys = {
        "dynamodb:DescribeTable": "Table",
        "iam:GetRole": "Role",
        "cloudformation:DescribeStackResource": "StackResourceDetail",
        "lambda:GetFunction": "Configuration",
    }
    key = keys.get(operation)
    if key is not None:
        value = response.get(key)
        if not isinstance(value, Mapping):
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        return [value]
    if operation in {"lambda:GetAlias", "signer:GetSigningProfile"}:
        return [_without_metadata(response)]
    _fail("COLLISION_PROVIDER_RESPONSE_INVALID")


def _tags(value: object) -> dict[str, str]:
    if isinstance(value, Mapping):
        if all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
            return dict(value)
        for key in ("Tags", "tags", "TagSet"):
            if key in value:
                return _tags(value[key])
    if isinstance(value, list):
        result: dict[str, str] = {}
        for entry in value:
            if not isinstance(entry, Mapping):
                _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
            key = entry.get("Key", entry.get("key"))
            item = entry.get("Value", entry.get("value"))
            if not isinstance(key, str) or not isinstance(item, str) or key in result:
                _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
            result[key] = item
        return result
    _fail("COLLISION_PROVIDER_RESPONSE_INVALID")


def _required_tags(target: Mapping[str, Any]) -> dict[str, str]:
    selector = target.get("selector")
    explicit = selector.get("required_tags") if isinstance(selector, Mapping) else None
    if explicit is not None:
        if not isinstance(explicit, Mapping):
            _fail("COLLISION_PROVIDER_TARGET_INVALID")
        return {str(key): str(value) for key, value in explicit.items()}
    return dict(_DEFAULT_OWNERSHIP_TAGS)


class _SnapshotProvider:
    __slots__ = (
        "_owner", "_request", "_targets", "_capture_index", "_purpose",
        "_sessions", "_identities", "_observations", "_calls", "_sealed",
        "_identity_center_attested",
    )

    def __init__(self, owner: "_AttestedProviderFactory", request: Mapping[str, Any], capture_index: int, purpose: str) -> None:
        self._owner = owner
        self._request = _copy(request, "COLLISION_PROVIDER_REQUEST_INVALID")
        self._targets = _target_map(self._request)
        self._capture_index = capture_index
        self._purpose = purpose
        self._sessions: dict[str, OpenedReadOnlySession] = {}
        self._identities: dict[str, dict[str, Any]] = {}
        self._observations: dict[str, dict[str, Any]] = {}
        self._calls: list[_PendingCall] = []
        self._sealed = False
        self._identity_center_attested = False

    def _session(self, domain: str) -> OpenedReadOnlySession:
        value = self._sessions.get(domain)
        if value is None:
            _fail("COLLISION_PROVIDER_IDENTITY_REQUIRED")
        return value

    def _sdk_client(self, domain: str, service: str) -> object:
        self._owner._run_before_call()
        session = self._session(domain).sdk_session
        client = getattr(session, "client", None)
        if not callable(client):
            _fail("COLLISION_PROVIDER_SDK_SESSION_INVALID")
        try:
            return client(service, region_name=REGION)
        except Exception:
            raise CollisionAwsProviderError("COLLISION_PROVIDER_CLIENT_OPEN_FAILED") from None

    def _call(
        self,
        *,
        domain: str,
        operation: str,
        service: str,
        method: str,
        request: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any], object | None]:
        if operation not in transcript.READ_ONLY_OPERATION_ALLOWLIST:
            _fail("COLLISION_PROVIDER_OPERATION_FORBIDDEN")
        if operation not in self._owner._allowed_actions[domain]:
            _fail("COLLISION_PROVIDER_POLICY_STAGE_INSUFFICIENT")
        reservation = None
        if self._owner._collision_budget is not None:
            try:
                reservation = collision_budget.reserve_provider_call(
                    self._owner._collision_budget,
                    stage=self._owner._budget_stage,
                    domain=domain,
                    operation=operation,
                )
            except collision_budget.CollisionBudgetError as exc:
                raise CollisionAwsProviderError(exc.code) from None
        client = self._sdk_client(domain, service)
        invoke = getattr(client, method, None)
        if not callable(invoke):
            _fail("COLLISION_PROVIDER_SDK_CLIENT_INVALID")
        self._owner._run_before_call()
        try:
            response = invoke(**_copy(request))
        except Exception as exc:
            if _client_error_code(exc) in _NOT_FOUND_CODES.get(operation, frozenset()):
                normalized: dict[str, Any] = {}
                if reservation is not None:
                    try:
                        collision_budget.account_provider_response(
                            reservation,
                            response=normalized,
                        )
                    except collision_budget.CollisionBudgetError as budget_exc:
                        raise CollisionAwsProviderError(
                            budget_exc.code
                        ) from None
                return "NOT_FOUND", normalized, reservation
            raise CollisionAwsProviderError("COLLISION_PROVIDER_AWS_READ_FAILED") from None
        if not isinstance(response, Mapping):
            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
        normalized = _copy(
            _without_metadata(response),
            "COLLISION_PROVIDER_RESPONSE_INVALID",
        )
        if reservation is not None:
            try:
                collision_budget.account_provider_response(
                    reservation,
                    response=normalized,
                )
            except collision_budget.CollisionBudgetError as exc:
                raise CollisionAwsProviderError(exc.code) from None
        return "SUCCESS", normalized, reservation

    def _append_call(
        self, *, domain: str, operation: str, outcome: str, page_index: int,
        input_cursor_digest: str | None, output_cursor_digest: str | None,
        page_item_digests: Sequence[str], target_ids: Sequence[str],
        budget_reservation: object | None,
    ) -> None:
        identity = self._identities[domain]
        value = _PendingCall(
            capture_index=self._capture_index,
            domain=domain,
            account_id=str(identity["account_id"]),
            session_digest=str(identity["session_digest"]),
            operation=operation,
            outcome=outcome,
            route_request_digest=str(self._request["request_digest"]),
            page_index=page_index,
            input_cursor_digest=input_cursor_digest,
            output_cursor_digest=output_cursor_digest,
            page_item_digests=sorted(set(page_item_digests)),
            target_ids=sorted(set(target_ids)),
            budget_reservation=budget_reservation,
        )
        self._calls.append(value)
        self._owner._calls.append(value)

    def read_identity(self, *, domain: str) -> Mapping[str, Any]:
        if self._sealed or domain not in {"authority", "management"} or domain in self._identities:
            _fail("COLLISION_PROVIDER_IDENTITY_ORDER_INVALID")
        expected = _expected_identity(self._request, domain)
        self._owner._run_before_call()
        try:
            envelope = self._owner._session_opener(
                domain=domain,
                expected_account_id=expected["account_id"],
                region=REGION,
                capture_index=self._capture_index,
                purpose=self._purpose,
            )
        except CollisionAwsProviderError:
            raise
        except Exception:
            raise CollisionAwsProviderError("COLLISION_PROVIDER_SESSION_OPEN_FAILED") from None
        if type(envelope) is not OpenedReadOnlySession:
            _fail("COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        _require_digest(envelope.policy_digest, "COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        _require_digest(envelope.authority_verification_digest, "COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        _require_digest(envelope.session_nonce_digest, "COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        if (
            not isinstance(envelope.sso_role_name, str)
            or _ROLE.fullmatch(envelope.sso_role_name) is None
            or envelope.source != expected["source"]
            or envelope.chain_depth != expected["chain_depth"]
            or canonical_digest(envelope.sso_role_name) != expected["sso_role_name_digest"]
            or envelope.policy_digest != self._owner._policy_set_digest
            or expected["policy_digest"] != self._owner._policy_set_digest
            or envelope.authority_verification_digest != expected["authority_verification_digest"]
        ):
            _fail("COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        if expected["source"] == "BROKER_SERVICE_ROLE":
            if (
                not isinstance(envelope.principal_arn, str)
                or _ARN.fullmatch(envelope.principal_arn) is None
                or canonical_digest(envelope.principal_arn)
                != expected["principal_digest"]
                or not isinstance(envelope.role_arn, str)
                or _ARN.fullmatch(envelope.role_arn) is None
                or canonical_digest(envelope.role_arn)
                != expected["role_arn_digest"]
                or envelope.role_arn.rsplit("/", 1)[-1]
                != envelope.sso_role_name
                or envelope.role_policy_digest
                != expected["role_policy_digest"]
                or envelope.session_policy_digest
                != expected["session_policy_digest"]
            ):
                _fail("COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        elif (
            envelope.role_arn is not None
            or envelope.role_policy_digest is not None
            or envelope.session_policy_digest is not None
        ):
            _fail("COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        if domain == "management" and self._owner._policy_set.get("stage") == "inventory-and-candidate-detail":
            instances = self._owner._candidate_resources("management", "sso_instance")
            permission_sets = self._owner._candidate_resources(
                "management", "sso_permission_set"
            )
            if (
                instances != frozenset({envelope.identity_center_instance_arn})
                or not set(envelope.permission_set_name_by_arn).issubset(permission_sets)
            ):
                _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        exact_instance = self._owner._policy_set.get(
            "identity_center_instance_arn"
        )
        if domain == "management" and exact_instance is not None:
            if (
                envelope.identity_center_instance_arn != exact_instance
                or (
                    self._owner._policy_set.get("stage") == "inventory"
                    and dict(envelope.permission_set_name_by_arn)
                )
                or (
                    self._owner._policy_set.get("stage")
                    == "inventory-and-candidate-detail"
                    and dict(envelope.permission_set_name_by_arn)
                    != self._owner._expected_permission_set_name_index()
                )
            ):
                _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        self._owner._reserve_session_envelope(envelope)
        self._sessions[domain] = envelope
        outcome, response, reservation = self._call(
            domain=domain, operation="sts:GetCallerIdentity", service="sts",
            method="get_caller_identity", request={},
        )
        if outcome != "SUCCESS":
            _fail("COLLISION_PROVIDER_IDENTITY_READ_FAILED")
        account = response.get("Account")
        principal = response.get("Arn")
        user_id = response.get("UserId")
        if (
            account != expected["account_id"]
            or not isinstance(principal, str)
            or _ARN.fullmatch(principal) is None
            or canonical_digest(principal) != expected["principal_digest"]
            or (
                envelope.principal_arn is not None
                and principal != envelope.principal_arn
            )
            or not isinstance(user_id, str)
        ):
            _fail("COLLISION_PROVIDER_IDENTITY_CONTRADICTION")
        assumed_role_marker = ":assumed-role/"
        if assumed_role_marker not in principal or (
            principal.split(assumed_role_marker, 1)[1].split("/", 1)[0]
            != envelope.sso_role_name
        ):
            _fail("COLLISION_PROVIDER_SESSION_ENVELOPE_INVALID")
        session_digest = canonical_digest(
            {
                "capture_index": self._capture_index,
                "purpose": self._purpose,
                "domain": domain,
                "account_id": account,
                "principal_digest": canonical_digest(principal),
                "user_id_digest": canonical_digest(user_id),
                "session_nonce_digest": envelope.session_nonce_digest,
            }
        )
        self._owner._reserve_session_digest(session_digest)
        observed_at = _stamp(self._owner._clock())
        identity = {
            "domain": domain,
            "account_id": account,
            "region": REGION,
            "source": envelope.source,
            "chain_depth": envelope.chain_depth,
            "session_digest": session_digest,
            "principal_digest": canonical_digest(principal),
            "sso_role_name_digest": canonical_digest(envelope.sso_role_name),
            "observed_at": observed_at,
            "policy_digest": envelope.policy_digest,
            "authority_verification_digest": envelope.authority_verification_digest,
        }
        if envelope.source == "BROKER_SERVICE_ROLE":
            identity.update(
                {
                    "role_arn_digest": canonical_digest(envelope.role_arn),
                    "role_policy_digest": envelope.role_policy_digest,
                    "session_policy_digest": envelope.session_policy_digest,
                }
            )
        self._identities[domain] = identity
        self._append_call(
            domain=domain, operation="sts:GetCallerIdentity", outcome="SUCCESS",
            page_index=1, input_cursor_digest=None, output_cursor_digest=None,
            page_item_digests=[], target_ids=[],
            budget_reservation=reservation,
        )
        return _copy(identity)

    def _inventory(self, domain: str, target: Mapping[str, Any]) -> tuple[list[Any], list[str]]:
        envelope = self._session(domain)
        if domain == "management" and (
            not isinstance(envelope.permission_set_name_by_arn, Mapping)
            or any(
                not isinstance(arn, str)
                or _ARN.fullmatch(arn) is None
                or not isinstance(name, str)
                or not name
                for arn, name in envelope.permission_set_name_by_arn.items()
            )
        ):
            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        plan = _operation_plan(target, envelope)
        target_id = str(target["target_id"])
        if not plan.paginated:
            outcome, response, reservation = self._call(
                domain=domain, operation=plan.operation, service=plan.service,
                method=plan.method, request=plan.request,
            )
            items = [] if outcome == "NOT_FOUND" else _direct_items(plan.operation, response)
            normalized = [
                _normalized_item(target=target, operation=plan.operation, item=item, envelope=envelope)
                for item in items
            ]
            self._append_call(
                domain=domain, operation=plan.operation, outcome=outcome,
                page_index=1, input_cursor_digest=None, output_cursor_digest=None,
                page_item_digests=[canonical_digest(item) for item in normalized],
                target_ids=[target_id],
                budget_reservation=reservation,
            )
            return items, [canonical_digest(item) for item in normalized]

        request = dict(plan.request)
        raw_items: list[Any] = []
        item_digests: list[str] = []
        seen_cursors: set[str] = set()
        input_digest: str | None = None
        for page_index in range(1, self._owner._max_pages + 1):
            outcome, response, reservation = self._call(
                domain=domain, operation=plan.operation, service=plan.service,
                method=plan.method, request=request,
            )
            if outcome != "SUCCESS":
                _fail("COLLISION_PROVIDER_LIST_OUTCOME_INVALID")
            page = _as_items(response, str(plan.item_key))
            if len(raw_items) + len(page) > self._owner._max_items:
                _fail("COLLISION_PROVIDER_ITEM_CAP_EXCEEDED")
            normalized = [
                _normalized_item(target=target, operation=plan.operation, item=item, envelope=envelope)
                for item in page
            ]
            page_digests = sorted({canonical_digest(item) for item in normalized})
            raw_items.extend(page)
            item_digests.extend(page_digests)
            next_cursor = _cursor(response, plan.response_cursor, plan.truncated_key)
            output_digest = (
                canonical_digest({"operation": plan.operation, "cursor": next_cursor})
                if next_cursor is not None else None
            )
            if output_digest is not None:
                if output_digest in seen_cursors or output_digest == input_digest:
                    _fail("COLLISION_PROVIDER_CURSOR_LOOP")
                seen_cursors.add(output_digest)
            self._append_call(
                domain=domain, operation=plan.operation, outcome="SUCCESS",
                page_index=page_index, input_cursor_digest=input_digest,
                output_cursor_digest=output_digest, page_item_digests=page_digests,
                target_ids=[target_id],
                budget_reservation=reservation,
            )
            if next_cursor is None:
                return raw_items, sorted(set(item_digests))
            if page_index == self._owner._max_pages:
                _fail("COLLISION_PROVIDER_PAGE_CAP_EXCEEDED")
            request[str(plan.request_cursor)] = next_cursor
            input_digest = output_digest
        _fail("COLLISION_PROVIDER_PAGE_CAP_EXCEEDED")

    def _discovery_pages(
        self,
        *,
        domain: str,
        plan: _Plan,
        target_ids: Sequence[str],
        normalize_match: Callable[[Any], Mapping[str, Any] | None],
    ) -> list[dict[str, Any]]:
        if not plan.paginated:
            _fail("COLLISION_DISCOVERY_PLAN_INVALID")
        request = dict(plan.request)
        pages: list[dict[str, Any]] = []
        seen_cursors: set[str] = set()
        input_digest: str | None = None
        item_count = 0
        for page_index in range(1, self._owner._max_pages + 1):
            outcome, response, reservation = self._call(
                domain=domain,
                operation=plan.operation,
                service=plan.service,
                method=plan.method,
                request=request,
            )
            if outcome != "SUCCESS":
                _fail("COLLISION_PROVIDER_LIST_OUTCOME_INVALID")
            raw_items = _as_items(response, str(plan.item_key))
            item_count += len(raw_items)
            if item_count > self._owner._max_items:
                _fail("COLLISION_PROVIDER_ITEM_CAP_EXCEEDED")
            normalized_all = [_without_metadata(item) for item in raw_items]
            matched = [
                normalized
                for item in raw_items
                if (normalized := normalize_match(item)) is not None
            ]
            next_cursor = _cursor(
                response,
                plan.response_cursor,
                plan.truncated_key,
            )
            output_digest = (
                canonical_digest(
                    {"operation": plan.operation, "cursor": next_cursor}
                )
                if next_cursor is not None
                else None
            )
            if output_digest is not None:
                if output_digest in seen_cursors or output_digest == input_digest:
                    _fail("COLLISION_PROVIDER_CURSOR_LOOP")
                seen_cursors.add(output_digest)
            page_item_digests = sorted(
                {canonical_digest(item) for item in normalized_all}
            )
            self._append_call(
                domain=domain,
                operation=plan.operation,
                outcome="SUCCESS",
                page_index=page_index,
                input_cursor_digest=input_digest,
                output_cursor_digest=output_digest,
                page_item_digests=page_item_digests,
                target_ids=target_ids,
                budget_reservation=reservation,
            )
            pages.append(
                {
                    "page_index": page_index,
                    "input_cursor_digest": input_digest,
                    "output_cursor_digest": output_digest,
                    "items": sorted(matched, key=canonical_json),
                }
            )
            if next_cursor is None:
                return pages
            if page_index == self._owner._max_pages:
                _fail("COLLISION_PROVIDER_PAGE_CAP_EXCEEDED")
            request[str(plan.request_cursor)] = next_cursor
            input_digest = output_digest
        _fail("COLLISION_PROVIDER_PAGE_CAP_EXCEEDED")

    def discover_artifact_bucket_inventory(self) -> dict[str, Any]:
        """Bind one complete account-regional owner sweep to this scan."""

        domain = "authority"
        if self._sealed or domain not in self._identities:
            _fail("COLLISION_PROVIDER_IDENTITY_REQUIRED")
        target = self._targets.get("authority.s3.artifact-bucket")
        if not isinstance(target, Mapping):
            _fail("COLLISION_DISCOVERY_S3_SELECTOR_INVALID")
        plan = _operation_plan(target, self._session(domain))
        selector = _catalog_selector_attestation(self._request["catalog"])[
            "artifact_bucket"
        ]
        if (
            plan.operation != selector["absence_operation"]
            or canonical_json(plan.request)
            != canonical_json(selector["absence_request"])
            or self._identities[domain]["account_id"]
            != selector["owner_account_id"]
        ):
            _fail("COLLISION_DISCOVERY_S3_SELECTOR_INVALID")

        bucket_name = str(target["name"])

        def normalize_bucket(item: Any) -> Mapping[str, Any] | None:
            if not isinstance(item, Mapping):
                _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
            observed_name = item.get("Name")
            if (
                not isinstance(observed_name, str)
                or item.get("BucketRegion") != REGION
            ):
                _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
            if observed_name != bucket_name:
                return None
            return {"Name": bucket_name, "BucketRegion": REGION}

        pages = self._discovery_pages(
            domain=domain,
            plan=plan,
            target_ids=[str(target["target_id"])],
            normalize_match=normalize_bucket,
        )
        matched_names = [
            str(item["Name"])
            for page in pages
            for item in page["items"]
        ]
        if len(matched_names) > 1:
            _fail("COLLISION_DISCOVERY_RESULT_INVALID")
        result = {
            "target_id": target["target_id"],
            "namespace": selector["namespace"],
            "owner_account_id": selector["owner_account_id"],
            "region": selector["region"],
            "operation": plan.operation,
            "request_digest": canonical_digest(plan.request),
            "page_chain_digest": canonical_digest(pages),
            "matched_bucket_count": len(matched_names),
            "matched_bucket_digest": canonical_digest(matched_names),
            "session_digest": self._identities[domain]["session_digest"],
            "head_bucket_used": False,
            "complete": True,
        }
        result["inventory_binding_digest"] = canonical_digest(result)
        return result

    def _attest_identity_center_instance(
        self,
    ) -> tuple[str, str | None, str, str]:
        """Re-read and bind the exact encrypted instance once per snapshot."""

        domain = "management"
        if (
            self._sealed
            or domain not in self._identities
            or self._identity_center_attested
        ):
            _fail("COLLISION_DISCOVERY_KMS_BINDING_INVALID")
        envelope = self._session(domain)
        expected_binding = _require_digest(
            self._request.get(
                "expected_identity_center_kms_binding_digest"
            ),
            "COLLISION_DISCOVERY_KMS_BINDING_INVALID",
        )
        mode = envelope.identity_center_kms_mode
        key_arn = envelope.identity_center_kms_key_arn
        instance_arn = envelope.identity_center_instance_arn
        if (
            envelope.identity_center_kms_binding_source
            != _IDENTITY_CENTER_KMS_BINDING_SOURCE
            or envelope.identity_center_kms_private_binding_digest
            != expected_binding
            or mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
            or (mode == "AWS_OWNED_KMS_KEY" and key_arn is not None)
            or (
                mode == "CUSTOMER_MANAGED_KEY"
                and (
                    not isinstance(key_arn, str)
                    or (key_match := _KMS_KEY_ARN.fullmatch(key_arn)) is None
                    or key_match.group("account")
                    != self._identities[domain]["account_id"]
                )
            )
            or not isinstance(instance_arn, str)
            or re.fullmatch(
                r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}",
                instance_arn,
            )
            is None
        ):
            _fail("COLLISION_DISCOVERY_KMS_BINDING_INVALID")
        derived_binding = canonical_digest(
            {
                "binding_name": "identity_center_kms_key_arn",
                "identity_center_instance_arn": instance_arn,
                "mode": mode,
                "key_arn": key_arn,
            }
        )
        if derived_binding != expected_binding:
            _fail("COLLISION_DISCOVERY_KMS_BINDING_INVALID")
        target_ids = sorted(
            target["target_id"]
            for target in self._targets.values()
            if target["domain"] == domain and target["service"] == "sso"
        )
        if not target_ids:
            _fail("COLLISION_DISCOVERY_KMS_BINDING_INVALID")
        outcome, response, reservation = self._call(
            domain=domain,
            operation="sso:DescribeInstance",
            service="sso-admin",
            method="describe_instance",
            request={"InstanceArn": instance_arn},
        )
        encryption = response.get("EncryptionConfigurationDetails")
        raw_mode = (
            encryption.get("KeyType")
            if isinstance(encryption, Mapping)
            else None
        )
        observed_mode = raw_mode
        observed_key_arn = (
            encryption.get("KmsKeyArn")
            if isinstance(encryption, Mapping)
            else None
        )
        described_projection = {
            "InstanceArn": response.get("InstanceArn"),
            "IdentityStoreId": response.get("IdentityStoreId"),
            "OwnerAccountId": response.get("OwnerAccountId"),
            "Status": response.get("Status"),
            "EncryptionConfigurationDetails": {
                "KeyType": observed_mode,
                "KmsKeyArn": observed_key_arn,
                "EncryptionStatus": (
                    encryption.get("EncryptionStatus")
                    if isinstance(encryption, Mapping)
                    else None
                ),
            },
        }
        if (
            outcome != "SUCCESS"
            or described_projection["InstanceArn"] != instance_arn
            or _IDENTITY_STORE.fullmatch(
                str(described_projection["IdentityStoreId"])
            )
            is None
            or described_projection["OwnerAccountId"]
            != self._identities[domain]["account_id"]
            or described_projection["Status"] != "ACTIVE"
            or described_projection["EncryptionConfigurationDetails"]
            != {
                "KeyType": mode,
                "KmsKeyArn": key_arn,
                "EncryptionStatus": "ENABLED",
            }
        ):
            _fail("COLLISION_DISCOVERY_KMS_BINDING_INVALID")
        described_instance_digest = canonical_digest(described_projection)
        self._append_call(
            domain=domain,
            operation="sso:DescribeInstance",
            outcome="SUCCESS",
            page_index=1,
            input_cursor_digest=None,
            output_cursor_digest=None,
            page_item_digests=[expected_binding, described_instance_digest],
            target_ids=target_ids,
            budget_reservation=reservation,
        )
        self._identity_center_attested = True
        return mode, key_arn, expected_binding, described_instance_digest

    def discover_candidate_groups(
        self,
        *,
        domain: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Execute one complete catalog-derived discovery scan for a domain."""

        if self._sealed or domain not in self._identities:
            _fail("COLLISION_PROVIDER_IDENTITY_REQUIRED")
        catalog = self._request["catalog"]
        discovery_plan = policy_contract.route_collision_discovery_plan(catalog)
        domain_plan = discovery_plan[domain]
        targets = [
            target
            for target in self._targets.values()
            if target["domain"] == domain
        ]
        envelope = self._session(domain)
        if domain == "management" and (
            not isinstance(envelope.permission_set_name_by_arn, Mapping)
            or any(
                not isinstance(arn, str)
                or _ARN.fullmatch(arn) is None
                or not isinstance(name, str)
                or not name
                for arn, name in envelope.permission_set_name_by_arn.items()
            )
        ):
            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        groups: dict[str, Any] = {}
        discovered_instance: str | None = None
        kinds = (
            ("cloudformation_stack", "kms_key", "lambda_code_signing_config")
            if domain == "authority"
            else (
                "cloudformation_stack",
                "identity_center_kms_key",
                "sso_instance",
                "sso_application",
                "sso_permission_set",
            )
        )
        kms_session_binding_digest: str | None = None
        for kind in kinds:
            contract = domain_plan[kind]
            operation = contract["operation"]
            selector = contract["selector"]
            target_ids: list[str] = []
            pages: list[dict[str, Any]]
            if kind == "cloudformation_stack":
                names = set(selector["stack_names"])
                representative = next(
                    target
                    for target in targets
                    if target["service"] == "cloudformation"
                )
                target_ids = sorted(
                    target["target_id"]
                    for target in targets
                    if target["service"] == "cloudformation"
                    and target["name"] in names
                )
                plan = _operation_plan(representative, envelope)

                def normalize_stack(item: Any) -> Mapping[str, Any] | None:
                    if not isinstance(item, Mapping) or item.get("StackName") not in names:
                        return None
                    stack_id = item.get("StackId")
                    if not isinstance(stack_id, str):
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    return {"StackName": item["StackName"], "StackId": stack_id}

                pages = self._discovery_pages(
                    domain=domain,
                    plan=plan,
                    target_ids=target_ids,
                    normalize_match=normalize_stack,
                )
            elif kind == "kms_key":
                names = set(selector["alias_names"])
                representative = next(
                    target for target in targets if target["service"] == "kms"
                )
                target_ids = sorted(
                    target["target_id"]
                    for target in targets
                    if target["service"] == "kms"
                )
                plan = _operation_plan(representative, envelope)

                def normalize_alias(item: Any) -> Mapping[str, Any] | None:
                    if not isinstance(item, Mapping) or item.get("AliasName") not in names:
                        return None
                    key_id = item.get("TargetKeyId")
                    if not isinstance(key_id, str) or not key_id:
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    return {"AliasName": item["AliasName"], "TargetKeyId": key_id}

                pages = self._discovery_pages(
                    domain=domain,
                    plan=plan,
                    target_ids=target_ids,
                    normalize_match=normalize_alias,
                )
            elif kind == "lambda_code_signing_config":
                items: list[dict[str, str]] = []
                target_ids = []
                for descriptor in selector["stack_resources"]:
                    target = next(
                        target
                        for target in targets
                        if target["service"] == "lambda"
                        and target["scope"] == "code_signing_config"
                        and target["selector"].get("stack_name")
                        == descriptor["stack_name"]
                        and target["selector"].get("logical_resource_id")
                        == descriptor["logical_resource_id"]
                    )
                    target_ids.append(str(target["target_id"]))
                    request = {
                        "StackName": descriptor["stack_name"],
                        "LogicalResourceId": descriptor["logical_resource_id"],
                    }
                    outcome, response, reservation = self._call(
                        domain=domain,
                        operation=operation,
                        service="cloudformation",
                        method="describe_stack_resource",
                        request=request,
                    )
                    normalized_response = _without_metadata(response)
                    self._append_call(
                        domain=domain,
                        operation=operation,
                        outcome=outcome,
                        page_index=1,
                        input_cursor_digest=None,
                        output_cursor_digest=None,
                        page_item_digests=(
                            [canonical_digest(normalized_response)]
                            if outcome == "SUCCESS"
                            else []
                        ),
                        target_ids=[str(target["target_id"])],
                        budget_reservation=reservation,
                    )
                    if outcome == "NOT_FOUND":
                        continue
                    detail = response.get("StackResourceDetail")
                    if not isinstance(detail, Mapping):
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    physical = detail.get("PhysicalResourceId")
                    if not isinstance(physical, str) or not physical:
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    items.append(
                        {
                            "StackName": descriptor["stack_name"],
                            "LogicalResourceId": descriptor["logical_resource_id"],
                            "PhysicalResourceId": physical,
                        }
                    )
                pages = [
                    {
                        "page_index": 1,
                        "input_cursor_digest": None,
                        "output_cursor_digest": None,
                        "items": sorted(items, key=canonical_json),
                    }
                ]
            elif kind == "identity_center_kms_key":
                (
                    mode,
                    key_arn,
                    expected_binding,
                    described_instance_digest,
                ) = self._attest_identity_center_instance()
                kms_session_binding_digest = canonical_digest(
                    {
                        "source": _IDENTITY_CENTER_KMS_BINDING_SOURCE,
                        "mode": mode,
                        "key_arn": key_arn,
                        "private_binding_digest": expected_binding,
                        "session_digest": self._identities[domain]["session_digest"],
                        "authority_verification_digest": self._identities[domain][
                            "authority_verification_digest"
                        ],
                        "described_instance_digest": described_instance_digest,
                    }
                )
                pages = [
                    {
                        "page_index": 1,
                        "input_cursor_digest": None,
                        "output_cursor_digest": None,
                        "items": [
                            {
                                "BindingName": "identity_center_kms_key_arn",
                                "Mode": mode,
                                "PrivateBindingDigest": expected_binding,
                                **(
                                    {"KeyArn": key_arn}
                                    if key_arn is not None
                                    else {}
                                ),
                            }
                        ],
                    }
                ]
            elif kind == "sso_instance":
                owners = set(selector["owner_account_ids"])
                target_ids = sorted(
                    target["target_id"]
                    for target in targets
                    if target["service"] == "sso"
                )
                plan = _Plan(
                    operation,
                    "sso-admin",
                    "list_instances",
                    {"MaxResults": 10},
                    "Instances",
                    "NextToken",
                    "NextToken",
                )

                def normalize_instance(item: Any) -> Mapping[str, Any] | None:
                    if not isinstance(item, Mapping) or item.get("OwnerAccountId") not in owners:
                        return None
                    instance = item.get("InstanceArn")
                    if not isinstance(instance, str):
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    return {
                        "InstanceArn": instance,
                        "OwnerAccountId": item["OwnerAccountId"],
                    }

                pages = self._discovery_pages(
                    domain=domain,
                    plan=plan,
                    target_ids=target_ids,
                    normalize_match=normalize_instance,
                )
                instances = [
                    item["InstanceArn"]
                    for page in pages
                    for item in page["items"]
                ]
                if len(set(instances)) != 1:
                    _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                discovered_instance = instances[0]
                if envelope.identity_center_instance_arn != discovered_instance:
                    _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
            elif kind == "sso_application":
                if discovered_instance is None:
                    _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                names = set(selector["application_names"])
                target_ids = sorted(
                    target["target_id"]
                    for target in targets
                    if target["service"] == "sso"
                    and target["scope"] == "application"
                )
                plan = _Plan(
                    operation,
                    "sso-admin",
                    "list_applications",
                    {"InstanceArn": discovered_instance, "MaxResults": 100},
                    "Applications",
                    "NextToken",
                    "NextToken",
                )

                def normalize_application(item: Any) -> Mapping[str, Any] | None:
                    if not isinstance(item, Mapping) or item.get("Name") not in names:
                        return None
                    arn = item.get("ApplicationArn")
                    if not isinstance(arn, str):
                        _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                    return {
                        "Name": item["Name"],
                        "ApplicationArn": arn,
                        "InstanceArn": discovered_instance,
                    }

                pages = self._discovery_pages(
                    domain=domain,
                    plan=plan,
                    target_ids=target_ids,
                    normalize_match=normalize_application,
                )
            elif kind == "sso_permission_set":
                if discovered_instance is None:
                    _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                names = set(selector["permission_set_names"])
                target_ids = sorted(
                    target["target_id"]
                    for target in targets
                    if target["service"] == "sso"
                    and target["scope"] == "permission_set"
                )
                plan = _Plan(
                    operation,
                    "sso-admin",
                    "list_permission_sets",
                    {"InstanceArn": discovered_instance, "MaxResults": 100},
                    "PermissionSets",
                    "NextToken",
                    "NextToken",
                )

                exact_instance = self._owner._policy_set.get(
                    "identity_center_instance_arn"
                )
                if exact_instance is None:
                    def normalize_permission_set(
                        item: Any,
                    ) -> Mapping[str, Any] | None:
                        arn = item if isinstance(item, str) else None
                        name = envelope.permission_set_name_by_arn.get(
                            str(arn)
                        )
                        if name not in names:
                            return None
                        if not isinstance(arn, str):
                            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                        return {
                            "Name": name,
                            "PermissionSetArn": arn,
                            "InstanceArn": discovered_instance,
                        }

                    pages = self._discovery_pages(
                        domain=domain,
                        plan=plan,
                        target_ids=target_ids,
                        normalize_match=normalize_permission_set,
                    )
                else:
                    if exact_instance != discovered_instance:
                        _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")

                    def retain_permission_set_arn(
                        item: Any,
                    ) -> Mapping[str, Any] | None:
                        if not isinstance(item, str) or _ARN.fullmatch(item) is None:
                            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                        return {"PermissionSetArn": item}

                    listed_pages = self._discovery_pages(
                        domain=domain,
                        plan=plan,
                        target_ids=target_ids,
                        normalize_match=retain_permission_set_arn,
                    )
                    listed = [
                        str(item["PermissionSetArn"])
                        for page in listed_pages
                        for item in page["items"]
                    ]
                    if len(listed) != len(set(listed)):
                        _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                    resolved: dict[str, str] = {}
                    names_seen: dict[str, str] = {}
                    for detail_index, arn in enumerate(sorted(listed), 1):
                        outcome, response, reservation = self._call(
                            domain=domain,
                            operation="sso:DescribePermissionSet",
                            service="sso-admin",
                            method="describe_permission_set",
                            request={
                                "InstanceArn": discovered_instance,
                                "PermissionSetArn": arn,
                            },
                        )
                        permission_set = response.get("PermissionSet")
                        if (
                            outcome != "SUCCESS"
                            or not isinstance(permission_set, Mapping)
                            or permission_set.get("PermissionSetArn") != arn
                            or not isinstance(permission_set.get("Name"), str)
                            or not permission_set.get("Name")
                        ):
                            _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                        name = str(permission_set["Name"])
                        if name in names_seen and names_seen[name] != arn:
                            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                        names_seen[name] = arn
                        resolved[arn] = name
                        projected = {
                            "PermissionSetArn": arn,
                            "Name": name,
                        }
                        self._append_call(
                            domain=domain,
                            operation="sso:DescribePermissionSet",
                            outcome="SUCCESS",
                            page_index=detail_index,
                            input_cursor_digest=None,
                            output_cursor_digest=None,
                            page_item_digests=[canonical_digest(projected)],
                            target_ids=target_ids,
                            budget_reservation=reservation,
                        )
                    pages = [
                        {
                            **page,
                            "items": sorted(
                                [
                                    {
                                        "Name": resolved[
                                            str(item["PermissionSetArn"])
                                        ],
                                        "PermissionSetArn": str(
                                            item["PermissionSetArn"]
                                        ),
                                        "InstanceArn": discovered_instance,
                                    }
                                    for item in page["items"]
                                    if resolved[
                                        str(item["PermissionSetArn"])
                                    ] in names
                                ],
                                key=canonical_json,
                            ),
                        }
                        for page in listed_pages
                    ]
            else:
                _fail("COLLISION_DISCOVERY_PLAN_INVALID")
            groups[kind] = {
                "operation": operation,
                "selector": selector,
                "pages": pages,
            }
        return groups, {
            "domain": domain,
            "session_digest": self._identities[domain]["session_digest"],
            "authority_verification_digest": self._identities[domain][
                "authority_verification_digest"
            ],
            "identity_center_kms_session_binding_digest": (
                kms_session_binding_digest
            ),
            "permission_set_name_index_digest": (
                canonical_digest(
                    dict(sorted(envelope.permission_set_name_by_arn.items()))
                )
                if domain == "management"
                else None
            ),
        }

    def _ownership(
        self, domain: str, target: Mapping[str, Any], matched: Mapping[str, Any]
    ) -> tuple[dict[str, str], str]:
        service = str(target["service"])
        selector = target["selector"]
        account = str(target["account_id"])
        name = str(target["name"])
        operation: str
        sdk_service: str
        method: str
        request: dict[str, Any]
        response_tags: object | None = None
        candidate_kind: str | None = None
        candidate_resource: str | None = None
        if service == "lambda" and selector.get("kind") == "cloudformation_stack_resource":
            required = _required_tags(target)
            return required, canonical_digest(
                {
                    "target_id": target["target_id"],
                    "operation": "cloudformation:DescribeStackResource",
                    "resource_binding_digest": canonical_digest(
                        {
                            "StackName": selector.get("stack_name"),
                            "LogicalResourceId": selector.get("logical_resource_id"),
                            "PhysicalResourceId": matched.get("PhysicalResourceId"),
                        }
                    ),
                    "required_tags": required,
                    "observed_tags_digest": canonical_digest(required),
                }
            )
        if service == "cloudformation":
            candidate_kind = "cloudformation_stack"
            candidate_resource = matched.get("StackId")
            operation = "cloudformation:DescribeStacks"
            sdk_service, method = "cloudformation", "describe_stacks"
            request = {"StackName": name}
        elif service == "dynamodb":
            arn = matched.get("TableArn")
            if arn != f"arn:aws:dynamodb:{REGION}:{account}:table/{name}":
                _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
            operation, sdk_service, method = "dynamodb:ListTagsOfResource", "dynamodb", "list_tags_of_resource"
            request = {"ResourceArn": arn}
        elif service == "iam":
            if matched.get("Arn") != f"arn:aws:iam::{account}:role/{name}":
                _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
            operation, sdk_service, method = "iam:ListRoleTags", "iam", "list_role_tags"
            request = {"RoleName": name.rsplit("/", 1)[-1]}
        elif service == "kms":
            key_id = matched.get("TargetKeyId")
            candidate_kind = "kms_key"
            candidate_resource = (
                key_id
                if isinstance(key_id, str) and key_id.startswith("arn:")
                else f"arn:aws:kms:{REGION}:{account}:key/{key_id}"
                if isinstance(key_id, str) else None
            )
            operation, sdk_service, method = "kms:ListResourceTags", "kms", "list_resource_tags"
            request = {"KeyId": key_id, "Limit": 50}
        elif service == "lambda":
            if target["scope"] == "alias":
                arn = matched.get("AliasArn")
                expected_alias_arn = (
                    f"arn:aws:lambda:{REGION}:{account}:function:"
                    f"{selector.get('function_name')}:{selector.get('alias_name')}"
                )
                if arn != expected_alias_arn:
                    _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
                resource = arn.rsplit(":", 1)[0] if isinstance(arn, str) else None
            elif target["scope"] == "function":
                resource = matched.get("FunctionArn")
                if resource != f"arn:aws:lambda:{REGION}:{account}:function:{name}":
                    _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
            else:
                resource = matched.get("PhysicalResourceId")
                candidate_kind = "lambda_code_signing_config"
                candidate_resource = resource
            operation, sdk_service, method = "lambda:ListTags", "lambda", "list_tags"
            request = {"Resource": resource}
        elif service == "logs":
            arn = matched.get("arn", matched.get("logGroupArn"))
            if isinstance(arn, str) and arn.endswith(":*"):
                arn = arn[:-2]
            if arn != f"arn:aws:logs:{REGION}:{account}:log-group:{name}":
                _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
            operation, sdk_service, method = "logs:ListTagsForResource", "logs", "list_tags_for_resource"
            request = {"resourceArn": arn}
        elif service == "s3":
            operation, sdk_service, method = "s3:GetBucketTagging", "s3", "get_bucket_tagging"
            request = {"Bucket": name, "ExpectedBucketOwner": account}
        elif service == "signer":
            arn = (
                f"arn:aws:signer:{REGION}:{account}:"
                f"/signing-profiles/{name}"
            )
            operation, sdk_service, method = "signer:ListTagsForResource", "signer", "list_tags_for_resource"
            request = {"resourceArn": arn}
        elif service == "sso":
            arn = matched.get("ApplicationArn", matched.get("PermissionSetArn"))
            candidate_kind = (
                "sso_application"
                if target["scope"] == "application"
                else "sso_permission_set"
            )
            candidate_resource = arn
            operation, sdk_service, method = "sso:ListTagsForResource", "sso-admin", "list_tags_for_resource"
            request = {"ResourceArn": arn}
        else:
            _fail("COLLISION_PROVIDER_TARGET_UNSUPPORTED")
        if any(value is None or value == "" for value in request.values()):
            _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
        if candidate_kind is not None and candidate_resource not in self._owner._candidate_resources(domain, candidate_kind):
            _fail("COLLISION_PROVIDER_RESOURCE_BINDING_INVALID")
        outcome, response, reservation = self._call(
            domain=domain, operation=operation, service=sdk_service,
            method=method, request=request,
        )
        if outcome != "SUCCESS":
            _fail("COLLISION_PROVIDER_OWNERSHIP_NOT_PROVEN")
        if service == "cloudformation":
            stacks = _as_items(response, "Stacks")
            if len(stacks) != 1 or not isinstance(stacks[0], Mapping) or stacks[0].get("StackName") != name:
                _fail("COLLISION_PROVIDER_RESPONSE_CONTRADICTION")
            response_tags = stacks[0].get("Tags", [])
        else:
            response_tags = response
        observed = _tags(response_tags)
        required = _required_tags(target)
        if any(observed.get(key) != value for key, value in required.items()):
            _fail("COLLISION_PROVIDER_OWNERSHIP_NOT_PROVEN")
        digest = canonical_digest(
            {
                "target_id": target["target_id"],
                "operation": operation,
                "resource_binding_digest": canonical_digest(request),
                "required_tags": required,
                "observed_tags_digest": canonical_digest(observed),
            }
        )
        self._append_call(
            domain=domain, operation=operation, outcome="SUCCESS", page_index=1,
            input_cursor_digest=None, output_cursor_digest=None,
            page_item_digests=[canonical_digest(_without_metadata(response))],
            target_ids=[str(target["target_id"])],
            budget_reservation=reservation,
        )
        return observed, digest

    def read_target_observations(
        self, *, domain: str, targets: Sequence[Mapping[str, Any]],
        expected_dispositions: Mapping[str, str],
    ) -> Mapping[str, Mapping[str, Any]]:
        if self._sealed or domain not in self._identities:
            _fail("COLLISION_PROVIDER_IDENTITY_REQUIRED")
        supplied: dict[str, dict[str, Any]] = {}
        for target in targets:
            if not isinstance(target, Mapping):
                _fail("COLLISION_PROVIDER_TARGET_INVALID")
            target_id = target.get("target_id")
            if not isinstance(target_id, str) or target_id in supplied:
                _fail("COLLISION_PROVIDER_TARGET_INVALID")
            trusted = self._targets.get(target_id)
            if trusted is None or _copy(target) != trusted:
                _fail("COLLISION_PROVIDER_TARGET_INVALID")
            if trusted["domain"] != domain or trusted["region"] != REGION:
                _fail("COLLISION_PROVIDER_TARGET_INVALID")
            if trusted["account_id"] != self._identities[domain]["account_id"]:
                _fail("COLLISION_PROVIDER_TARGET_ACCOUNT_CONTRADICTION")
            supplied[target_id] = trusted
        expected = dict(expected_dispositions)
        if set(expected) != set(supplied) or any(
            value not in {"ABSENT_AT_SNAPSHOT", "PRESENT_OWNED"}
            for value in expected.values()
        ):
            _fail("COLLISION_PROVIDER_DISPOSITIONS_INVALID")
        if (
            domain == "management"
            and self._request.get(
                "expected_identity_center_kms_binding_digest"
            )
            is not None
        ):
            self._attest_identity_center_instance()
        result: dict[str, dict[str, Any]] = {}
        for target_id in sorted(supplied):
            target = supplied[target_id]
            items, inventory_digests = self._inventory(domain, target)
            envelope = self._session(domain)
            matches = [
                item for item in items
                if _matches(target=target, operation=_operation_plan(target, envelope).operation, item=item, envelope=envelope)
            ]
            if len(matches) > 1:
                _fail("COLLISION_PROVIDER_RESPONSE_CONTRADICTION")
            observed_disposition = "PRESENT_OWNED" if matches else "ABSENT_AT_SNAPSHOT"
            if observed_disposition != expected[target_id]:
                _fail("COLLISION_PROVIDER_DISPOSITION_CONTRADICTION")
            ownership_digest: str | None = None
            observed_tags_digest: str | None = None
            if matches:
                matched = matches[0]
                if isinstance(matched, str) and target["service"] == "sso" and target["scope"] == "permission_set":
                    matched = {"PermissionSetArn": matched}
                if not isinstance(matched, Mapping):
                    _fail("COLLISION_PROVIDER_RESPONSE_INVALID")
                observed_tags, ownership_digest = self._ownership(domain, target, matched)
                observed_tags_digest = canonical_digest(observed_tags)
            observation = {
                "disposition": observed_disposition,
                "facts_digest": canonical_digest(
                    {
                        "target_descriptor_digest": canonical_digest(target),
                        "inventory_operation": _operation_plan(target, envelope).operation,
                        "inventory_item_digests": inventory_digests,
                        "matched_item_digests": [
                            canonical_digest(
                                _normalized_item(
                                    target=target,
                                    operation=_operation_plan(target, envelope).operation,
                                    item=item,
                                    envelope=envelope,
                                )
                            )
                            for item in matches
                        ],
                        "observed_tags_digest": observed_tags_digest,
                    }
                ),
                "ownership_binding_digest": ownership_digest,
            }
            self._observations[target_id] = observation
            result[target_id] = observation
        return _copy(result)

    def _render_calls(self) -> list[dict[str, Any]]:
        if set(self._identities) != {"authority", "management"}:
            _fail("COLLISION_PROVIDER_SNAPSHOT_INCOMPLETE")
        expected_target_ids = {
            target_id for target_id in self._targets
            if target_id in self._request.get("expected_dispositions", {})
        }
        if set(self._observations) != expected_target_ids:
            _fail("COLLISION_PROVIDER_SNAPSHOT_INCOMPLETE")
        rendered: list[dict[str, Any]] = []
        owner_calls = self._owner._calls
        for pending in self._calls:
            stream = [
                value for value in self._calls
                if value.domain == pending.domain
                and value.operation == pending.operation
                and value.target_ids == pending.target_ids
            ]
            final = pending is stream[-1]
            evidence = (
                {
                    target_id: canonical_digest(self._observations[target_id])
                    for target_id in pending.target_ids
                    if target_id in self._observations
                }
                if final else {}
            )
            projection = {
                "page_item_digests": pending.page_item_digests,
                "output_cursor_digest": pending.output_cursor_digest,
                "page_complete": pending.output_cursor_digest is None,
                "target_evidence_digests": evidence,
            }
            event = {
                "ordinal": owner_calls.index(pending) + 1,
                "capture_index": pending.capture_index,
                "domain": pending.domain,
                "account_id": pending.account_id,
                "region": REGION,
                "session_digest": pending.session_digest,
                "provider_implementation_digest": transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST,
                "operation": pending.operation,
                "outcome": pending.outcome,
                "request_digest": pending.route_request_digest,
                "operation_request_digest": "",
                "page_index": pending.page_index,
                "input_cursor_digest": pending.input_cursor_digest,
                "response_projection": projection,
                "response_digest": canonical_digest(projection),
                "target_ids": pending.target_ids,
                "read_only": True,
                "aws_mutations": 0,
            }
            event["operation_request_digest"] = canonical_digest(
                transcript.operation_request_descriptor(request=self._request, event=event)
            )
            if (
                pending.budget_reservation is not None
                and not pending.budget_event_bound
            ):
                try:
                    collision_budget.bind_provider_transcript_event(
                        pending.budget_reservation,
                        transcript_event=event,
                    )
                except collision_budget.CollisionBudgetError as exc:
                    raise CollisionAwsProviderError(exc.code) from None
                pending.budget_event_bound = True
            rendered.append(event)
        return rendered

    def transcript_events(self) -> Sequence[Mapping[str, Any]]:
        self._sealed = True
        return _copy(self._render_calls())


class _AttestedProviderFactory:
    __slots__ = (
        "_token", "_session_opener", "_clock", "_before_call",
        "_max_pages", "_max_items",
        "_calls", "_snapshots", "_request_digest", "_session_digests",
        "_session_nonce_digests", "_sdk_sessions",
        "_policy_set", "_policy_set_digest", "_policy_digests",
        "_allowed_actions", "_attestation_digest", "_discovery_created",
        "_discovery_capability_digest", "_discovery_provenance_digest",
        "_collision_budget", "_budget_stage", "_discovery_events",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        _fail("COLLISION_PROVIDER_FACTORY_SUBCLASS_FORBIDDEN")

    def __setattr__(self, name: str, value: object) -> None:
        immutable = {
            "_token", "_session_opener", "_clock", "_before_call",
            "_max_pages", "_max_items",
            "_policy_set", "_policy_set_digest", "_policy_digests",
            "_allowed_actions", "_attestation_digest",
            "_discovery_capability_digest", "_discovery_provenance_digest",
            "_collision_budget", "_budget_stage",
        }
        if name in immutable:
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                pass
            else:
                _fail("COLLISION_PROVIDER_FACTORY_IMMUTABLE")
        object.__setattr__(self, name, value)

    def __init__(
        self, token: object, *, session_opener: SessionOpener, clock: Clock,
        before_call: BeforeCall | None,
        session_registry: object | None,
        policy_set: Mapping[str, Any],
        discovery_capability: object | None,
        collision_budget_capability: object | None,
        budget_stage: str | None,
        max_pages: int, max_items: int,
    ) -> None:
        if token is not _FACTORY_TOKEN:
            _fail("COLLISION_PROVIDER_FACTORY_BUILDER_REQUIRED")
        if (
            not callable(session_opener)
            or not callable(clock)
            or (before_call is not None and not callable(before_call))
            or (
                (collision_budget_capability is None)
                != (budget_stage is None)
            )
            or (
                budget_stage is not None
                and budget_stage not in {"inventory", "candidate"}
            )
        ):
            _fail("COLLISION_PROVIDER_FACTORY_CONFIG_INVALID")
        if session_registry is None:
            session_registry = build_session_uniqueness_registry()
        if (
            type(session_registry) is not _SessionUniquenessRegistry
            or session_registry._token is not _SESSION_REGISTRY_TOKEN
        ):
            _fail("COLLISION_PROVIDER_SESSION_REGISTRY_INVALID")
        if type(max_pages) is not int or not 1 <= max_pages <= MAX_PAGES:
            _fail("COLLISION_PROVIDER_FACTORY_CONFIG_INVALID")
        if type(max_items) is not int or not 1 <= max_items <= DEFAULT_MAX_ITEMS:
            _fail("COLLISION_PROVIDER_FACTORY_CONFIG_INVALID")
        copied_policy_set = _copy(
            policy_set, "COLLISION_PROVIDER_POLICY_SET_INVALID"
        )
        policy_set_digest = copied_policy_set.get("policy_set_digest") if isinstance(copied_policy_set, Mapping) else None
        policy_digests = copied_policy_set.get("policy_digests") if isinstance(copied_policy_set, Mapping) else None
        allowed = copied_policy_set.get("allowed_actions") if isinstance(copied_policy_set, Mapping) else None
        if (
            not isinstance(copied_policy_set, Mapping)
            or _require_digest(policy_set_digest, "COLLISION_PROVIDER_POLICY_SET_INVALID") != canonical_digest(
                {key: value for key, value in copied_policy_set.items() if key != "policy_set_digest"}
            )
            or not isinstance(policy_digests, Mapping)
            or not isinstance(allowed, Mapping)
            or copied_policy_set.get("target_count") != TARGET_COUNT
            or copied_policy_set.get("region") != REGION
            or copied_policy_set.get("read_only") is not True
            or copied_policy_set.get("aws_mutations") != 0
        ):
            _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
        policy_stage = copied_policy_set.get("stage")
        policy_provenance = copied_policy_set.get(
            "discovery_provenance_digest"
        )
        capability_digest: str | None = None
        if policy_stage == "inventory":
            if discovery_capability is not None or policy_provenance is not None:
                _fail("COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID")
        elif policy_stage == "inventory-and-candidate-detail":
            try:
                capability = _assert_discovery_capability(
                    discovery_capability
                )
            except CollisionAwsProviderError:
                _fail("COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID")
            if (
                capability._state != "POLICY_MATERIALIZED"
                or capability._candidate_policy_set_digest != policy_set_digest
                or capability._provenance_digest != policy_provenance
            ):
                _fail("COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID")
            capability_digest = capability._capability_digest
            object.__setattr__(capability, "_state", "FACTORY_BOUND")
        else:
            _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
        normalized_actions: dict[str, frozenset[str]] = {}
        for domain in ("authority", "management"):
            domain_digests = policy_digests.get(domain)
            domain_actions = allowed.get(domain)
            if not isinstance(domain_digests, Mapping) or not isinstance(domain_actions, Mapping):
                _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
            if any(_DIGEST.fullmatch(str(value)) is None for value in domain_digests.values()):
                _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
            flattened = {
                action
                for actions in domain_actions.values()
                if isinstance(actions, list)
                for action in actions
                if isinstance(action, str)
            }
            normalized_actions[domain] = frozenset(
                flattened & set(transcript.READ_ONLY_OPERATION_ALLOWLIST)
            )
        self._token = token
        self._session_opener = session_opener
        self._clock = clock
        self._before_call = before_call
        self._max_pages = max_pages
        self._max_items = max_items
        self._policy_set = copied_policy_set
        self._policy_set_digest = str(policy_set_digest)
        self._policy_digests = _copy(policy_digests)
        self._allowed_actions = MappingProxyType(normalized_actions)
        self._discovery_capability_digest = capability_digest
        self._discovery_provenance_digest = policy_provenance
        self._collision_budget = collision_budget_capability
        self._budget_stage = budget_stage
        self._discovery_created = False
        self._discovery_events: list[dict[str, Any]] = []
        self._calls: list[_PendingCall] = []
        self._snapshots: list[_SnapshotProvider] = []
        self._request_digest: str | None = None
        self._session_digests = session_registry.session_digests
        self._session_nonce_digests = session_registry.session_nonce_digests
        self._sdk_sessions = session_registry.sdk_sessions
        self._attestation_digest = self._expected_attestation()

    def _run_before_call(self) -> None:
        callback = self._before_call
        if callback is None:
            return
        try:
            callback()
        except CollisionAwsProviderError:
            raise
        except Exception:
            raise CollisionAwsProviderError(
                "COLLISION_PROVIDER_BUDGET_EXPIRED"
            ) from None

    def _expected_attestation(self) -> str:
        return canonical_digest(
            {
                "implementation_digest": transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST,
                "mode": "ATTESTED_CONNECTED_READ_ONLY",
                "region": REGION,
                "target_count": TARGET_COUNT,
                "max_pages": self._max_pages,
                "max_items": self._max_items,
                "before_call_enforced": self._before_call is not None,
                "policy_set_digest": self._policy_set_digest,
                "policy_digests": self._policy_digests,
                "policy_stage": self._policy_set["stage"],
                "discovery_provenance_digest": self._discovery_provenance_digest,
                "discovery_capability_digest": self._discovery_capability_digest,
                "operations": sorted(transcript.READ_ONLY_OPERATION_ALLOWLIST),
            }
        )

    def discover_route_collision_candidates(
        self,
        *,
        catalog: Mapping[str, Any],
        expected_identities: Mapping[str, Any],
        expected_identity_center_kms_binding_digest: str,
    ) -> object:
        """Run exactly two complete independent inventory scans and seal them."""

        assert_attested_provider_factory(self)
        if self._policy_set.get("stage") != "inventory" or self._discovery_created:
            _fail("COLLISION_DISCOVERY_LIFECYCLE_INVALID")
        try:
            policy_contract.validate_route_collision_policy_set(
                self._policy_set,
                catalog=catalog,
            )
        except Exception:
            raise CollisionAwsProviderError(
                "COLLISION_PROVIDER_POLICY_SET_INVALID"
            ) from None
        request = _discovery_request(
            catalog=catalog,
            expected_identities=expected_identities,
            inventory_policy_set_digest=self._policy_set_digest,
            expected_identity_center_kms_binding_digest=(
                expected_identity_center_kms_binding_digest
            ),
        )
        selector_attestation = _catalog_selector_attestation(catalog)
        scans: list[dict[str, Any]] = []
        evidence_values: list[dict[str, Any]] = []
        candidate_values: list[dict[str, Any]] = []
        bucket_values: list[dict[str, Any]] = []
        for capture_index, purpose in _DISCOVERY_SCAN_PURPOSES.items():
            snapshot = _SnapshotProvider(
                self,
                request,
                capture_index,
                purpose,
            )
            identities = {
                domain: snapshot.read_identity(domain=domain)
                for domain in ("authority", "management")
            }
            bucket_inventory = snapshot.discover_artifact_bucket_inventory()
            domains: dict[str, Any] = {}
            domain_provenance: dict[str, Any] = {}
            for domain in ("authority", "management"):
                groups, binding = snapshot.discover_candidate_groups(
                    domain=domain
                )
                domains[domain] = groups
                domain_provenance[domain] = binding
            evidence = {
                "schema_version": policy_contract.SCHEMA_VERSION,
                "record_type": policy_contract.DISCOVERY_EVIDENCE_RECORD_TYPE,
                "catalog_digest": catalog["catalog_digest"],
                "domains": domains,
            }
            try:
                normalized_evidence, candidates = (
                    policy_contract._normalize_discovery_evidence(  # noqa: SLF001
                        catalog,
                        evidence,
                    )
                )
            except policy_contract.CollisionPolicyError:
                raise CollisionAwsProviderError(
                    "COLLISION_DISCOVERY_RESULT_INVALID"
                ) from None
            if normalized_evidence is None:
                _fail("COLLISION_DISCOVERY_RESULT_INVALID")
            events = list(snapshot.transcript_events())
            # Preserve the exact, already-rendered events in capture order so
            # the caller can complete one aggregate budget spanning both the
            # inventory discovery factory and the candidate-detail factory.
            # The detached canonical copy prevents later caller mutation from
            # changing the budget evidence.
            self._discovery_events.extend(
                _copy(events, "COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            )
            scan = {
                "scan_index": capture_index,
                "purpose": purpose,
                "identity_bindings_digest": canonical_digest(identities),
                "session_bindings": domain_provenance,
                "artifact_bucket_inventory": bucket_inventory,
                "evidence_digest": canonical_digest(normalized_evidence),
                "candidate_resources_digest": canonical_digest(candidates),
                "transcript_digest": canonical_digest(events),
                "transcript_event_count": len(events),
                "complete": True,
            }
            scan["scan_digest"] = canonical_digest(scan)
            scans.append(scan)
            evidence_values.append(normalized_evidence)
            candidate_values.append(candidates)
            bucket_values.append(
                {
                    "matched_bucket_count": bucket_inventory[
                        "matched_bucket_count"
                    ],
                    "matched_bucket_digest": bucket_inventory[
                        "matched_bucket_digest"
                    ],
                }
            )
        if canonical_json(candidate_values[0]) != canonical_json(
            candidate_values[1]
        ) or canonical_json(bucket_values[0]) != canonical_json(
            bucket_values[1]
        ):
            _fail("COLLISION_DISCOVERY_INDEPENDENT_RESULT_MISMATCH")
        if any(
            scans[0]["session_bindings"][domain]["session_digest"]
            == scans[1]["session_bindings"][domain]["session_digest"]
            for domain in ("authority", "management")
        ):
            _fail("COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT")
        result = {
            "catalog_digest": catalog["catalog_digest"],
            "candidate_resources": candidate_values[1],
            "candidate_resources_digest": canonical_digest(candidate_values[1]),
            "selector_attestation_digest": selector_attestation[
                "selector_attestation_digest"
            ],
        }
        result["result_digest"] = canonical_digest(result)
        provenance = {
            "record_type": _DISCOVERY_PROVENANCE_RECORD_TYPE,
            "schema_version": 1,
            "catalog_digest": catalog["catalog_digest"],
            "inventory_policy_set_digest": self._policy_set_digest,
            "provider_implementation_digest": (
                transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
            ),
            "inventory_factory_attestation_digest": self._attestation_digest,
            "expected_identities_digest": canonical_digest(expected_identities),
            "identity_center_kms_private_binding_digest": (
                expected_identity_center_kms_binding_digest
            ),
            "selector_attestation_digest": selector_attestation[
                "selector_attestation_digest"
            ],
            "scan_count": 2,
            "scans": scans,
            "result_digest": result["result_digest"],
            "read_only": True,
            "aws_mutations": 0,
        }
        object.__setattr__(self, "_discovery_created", True)
        return _RouteCollisionDiscoveryCapability(
            _DISCOVERY_CAPABILITY_TOKEN,
            catalog_digest=str(catalog["catalog_digest"]),
            inventory_policy_set_digest=self._policy_set_digest,
            evidence=evidence_values[1],
            candidate_resources=candidate_values[1],
            provenance=provenance,
        )

    def discovery_transcript_events(self) -> Sequence[Mapping[str, Any]]:
        """Return both completed inventory scans in their exact call order."""

        assert_attested_provider_factory(self)
        if (
            self._policy_set.get("stage") != "inventory"
            or not self._discovery_created
            or not self._discovery_events
        ):
            _fail("COLLISION_DISCOVERY_LIFECYCLE_INVALID")
        return _copy(
            self._discovery_events,
            "COLLISION_PROVIDER_TRANSCRIPT_INVALID",
        )

    def _reserve_session_envelope(
        self, envelope: OpenedReadOnlySession
    ) -> None:
        if (
            envelope.session_nonce_digest in self._session_nonce_digests
            or any(
                envelope.sdk_session is reserved
                for reserved in self._sdk_sessions
            )
        ):
            _fail("COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT")
        self._session_nonce_digests.add(envelope.session_nonce_digest)
        self._sdk_sessions.append(envelope.sdk_session)

    def _reserve_session_digest(self, session_digest: str) -> None:
        if session_digest in self._session_digests:
            _fail("COLLISION_PROVIDER_SESSION_NOT_INDEPENDENT")
        self._session_digests.add(session_digest)

    def _candidate_resources(self, domain: str, kind: str) -> frozenset[str]:
        candidates = self._policy_set.get("candidate_resources")
        domain_candidates = candidates.get(domain) if isinstance(candidates, Mapping) else None
        values = domain_candidates.get(kind) if isinstance(domain_candidates, Mapping) else None
        if values is None:
            return frozenset()
        if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
            _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
        return frozenset(values)

    def _expected_permission_set_name_index(self) -> dict[str, str]:
        evidence = self._policy_set.get("discovery_evidence")
        domains = evidence.get("domains") if isinstance(evidence, Mapping) else None
        management = domains.get("management") if isinstance(domains, Mapping) else None
        group = management.get("sso_permission_set") if isinstance(management, Mapping) else None
        pages = group.get("pages") if isinstance(group, Mapping) else None
        if not isinstance(pages, list):
            _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
        result: dict[str, str] = {}
        for page in pages:
            items = page.get("items") if isinstance(page, Mapping) else None
            if not isinstance(items, list):
                _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
            for item in items:
                arn = item.get("PermissionSetArn") if isinstance(item, Mapping) else None
                name = item.get("Name") if isinstance(item, Mapping) else None
                if (
                    not isinstance(arn, str)
                    or not isinstance(name, str)
                    or arn in result
                ):
                    _fail("COLLISION_PROVIDER_SELECTOR_BINDING_INVALID")
                result[arn] = name
        return dict(sorted(result.items()))

    def open_snapshot(
        self, *, request: Mapping[str, Any], capture_index: int, purpose: str,
    ) -> _SnapshotProvider:
        assert_attested_provider_factory(self)
        targets = _target_map(request)
        del targets
        try:
            policy_contract.validate_route_collision_policy_set(
                self._policy_set, catalog=request["catalog"]
            )
        except Exception:
            raise CollisionAwsProviderError("COLLISION_PROVIDER_POLICY_SET_INVALID") from None
        if self._policy_set.get("catalog_digest") != request.get("catalog_digest"):
            _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
        if (
            request.get("collision_policy_set_digest")
            != self._policy_set_digest
            or request.get("collision_policy_digests")
            != self._policy_digests
            or request.get("collision_policy_stage")
            != self._policy_set.get("stage")
            or request.get("collision_provider_implementation_digest")
            != transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        ):
            _fail("COLLISION_PROVIDER_POLICY_SET_INVALID")
        if capture_index != len(self._snapshots) + 1 or _CAPTURE_PURPOSES.get(capture_index) != purpose:
            _fail("COLLISION_PROVIDER_CAPTURE_ORDER_INVALID")
        request_digest = str(request.get("request_digest"))
        if self._request_digest is None:
            self._request_digest = request_digest
        elif self._request_digest != request_digest:
            _fail("COLLISION_PROVIDER_REQUEST_REBIND_FORBIDDEN")
        value = _SnapshotProvider(self, request, capture_index, purpose)
        self._snapshots.append(value)
        return value

    def transcript_events(self) -> Sequence[Mapping[str, Any]]:
        assert_attested_provider_factory(self)
        if len(self._snapshots) != 3:
            _fail("COLLISION_PROVIDER_SNAPSHOT_INCOMPLETE")
        events: list[dict[str, Any]] = []
        for snapshot in self._snapshots:
            events.extend(_copy(snapshot.transcript_events()))
        if [event["ordinal"] for event in events] != list(range(1, len(events) + 1)):
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        return events

    def transcript_summary(self) -> Mapping[str, Any]:
        events = self.transcript_events()
        return {
            "record_type": transcript.TRANSCRIPT_SUMMARY_TYPE,
            "schema_version": 1,
            "request_digest": self._request_digest,
            "snapshot_count": len(self._snapshots),
            "provider_calls": len(events),
            "aws_calls": len(events),
            "aws_mutations": 0,
            "read_only": True,
            "transcript_digest": canonical_digest(events),
        }

    def provider_attestation(self) -> Mapping[str, Any]:
        """Return the immutable digest-only executor integration binding."""

        assert_attested_provider_factory(self)
        return {
            "record_type": "scanalyze.platform_authority.gug376_collision_aws_provider_attestation.v1",
            "schema_version": 1,
            "provider_implementation_digest": transcript.COLLISION_PROVIDER_IMPLEMENTATION_DIGEST,
            "factory_attestation_digest": self._attestation_digest,
            "policy_set_digest": self._policy_set_digest,
            "policy_digests": _copy(self._policy_digests),
            "policy_stage": self._policy_set["stage"],
            "discovery_provenance_digest": self._discovery_provenance_digest,
            "target_count": TARGET_COUNT,
            "region": REGION,
            "before_call_enforced": self._before_call is not None,
            "read_only": True,
            "aws_mutations": 0,
        }


def build_attested_provider_factory(
    *, session_opener: SessionOpener, clock: Clock,
    policy_set: Mapping[str, Any],
    discovery_capability: object | None = None,
    before_call: BeforeCall | None = None,
    session_registry: object | None = None,
    collision_budget_capability: object | None = None,
    budget_stage: str | None = None,
    max_pages: int = MAX_PAGES, max_items: int = DEFAULT_MAX_ITEMS,
) -> object:
    """Build the only accepted concrete provider factory."""

    return _AttestedProviderFactory(
        _FACTORY_TOKEN,
        session_opener=session_opener,
        clock=clock,
        before_call=before_call,
        session_registry=session_registry,
        policy_set=policy_set,
        discovery_capability=discovery_capability,
        collision_budget_capability=collision_budget_capability,
        budget_stage=budget_stage,
        max_pages=max_pages,
        max_items=max_items,
    )


def consume_discovery_for_policy(
    capability: object,
    *,
    catalog: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    """Consume one discovered capability at most once for policy materialization."""

    value = _assert_discovery_capability(capability)
    try:
        validate_route_collision_catalog(catalog)
    except Exception:
        raise CollisionAwsProviderError("COLLISION_PROVIDER_CATALOG_INVALID") from None
    if (
        value._state != "DISCOVERED"
        or value._catalog_digest != catalog.get("catalog_digest")
    ):
        _fail("COLLISION_DISCOVERY_LIFECYCLE_INVALID")
    object.__setattr__(value, "_state", "POLICY_MATERIALIZING")
    return _copy(value._evidence), value._provenance_digest


def bind_materialized_candidate_policy(
    capability: object,
    *,
    policy_set: Mapping[str, Any],
    catalog: Mapping[str, Any],
) -> None:
    """Finish the one-shot policy transition and pin its exact digest."""

    value = _assert_discovery_capability(capability)
    copied = _copy(policy_set, "COLLISION_PROVIDER_POLICY_SET_INVALID")
    try:
        policy_contract.validate_route_collision_policy_set(
            copied,
            catalog=catalog,
        )
    except Exception:
        raise CollisionAwsProviderError("COLLISION_PROVIDER_POLICY_SET_INVALID") from None
    if (
        value._state != "POLICY_MATERIALIZING"
        or value._catalog_digest != catalog.get("catalog_digest")
        or copied.get("stage") != "inventory-and-candidate-detail"
        or copied.get("discovery_provenance_digest")
        != value._provenance_digest
        or copied.get("discovery_evidence_digest")
        != canonical_digest(value._evidence)
        or copied.get("candidate_resources_digest")
        != canonical_digest(value._candidate_resources)
        or canonical_json(copied.get("candidate_resources"))
        != canonical_json(value._candidate_resources)
    ):
        _fail("COLLISION_PROVIDER_DISCOVERY_BINDING_INVALID")
    object.__setattr__(
        value,
        "_candidate_policy_set_digest",
        str(copied["policy_set_digest"]),
    )
    object.__setattr__(value, "_state", "POLICY_MATERIALIZED")


def discovery_capability_attestation(capability: object) -> Mapping[str, Any]:
    """Return a digest-only view; candidate values and private bindings stay opaque."""

    value = _assert_discovery_capability(capability)
    return {
        "record_type": _DISCOVERY_CAPABILITY_RECORD_TYPE,
        "schema_version": 1,
        "catalog_digest": value._catalog_digest,
        "inventory_policy_set_digest": value._inventory_policy_set_digest,
        "provenance_digest": value._provenance_digest,
        "capability_digest": value._capability_digest,
        "selector_attestation_digest": value._provenance[
            "selector_attestation_digest"
        ],
        "scan_count": value._provenance["scan_count"],
        "read_only": True,
        "aws_mutations": 0,
    }


def assert_attested_provider_factory(value: object) -> object:
    """Reject duck types, subclasses, token forgery, and config tampering."""

    if (
        type(value) is not _AttestedProviderFactory
        or value._token is not _FACTORY_TOKEN
        or value._attestation_digest != value._expected_attestation()
        or value._policy_set_digest
        != canonical_digest(
            {
                key: item
                for key, item in value._policy_set.items()
                if key != "policy_set_digest"
            }
        )
    ):
        _fail("COLLISION_PROVIDER_FACTORY_NOT_ATTESTED")
    return value


__all__ = [
    "CollisionAwsProviderError",
    "DEFAULT_MAX_ITEMS",
    "MAX_PAGES",
    "OpenedReadOnlySession",
    "REGION",
    "assert_attested_provider_factory",
    "build_attested_provider_factory",
    "build_session_uniqueness_registry",
    "bind_materialized_candidate_policy",
    "consume_discovery_for_policy",
    "discovery_capability_attestation",
    "session_uniqueness_registry_summary",
]
