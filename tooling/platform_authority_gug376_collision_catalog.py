"""Deterministic retained-name catalog for the GUG-376 bootstrap route.

The catalog is provider-free.  It names every deterministic resource that the
temporary route may retain and describes generated Lambda code-signing
configurations through CloudFormation ownership selectors.  ``lifecycle``
separates resources created by this route from collision-only names that must
remain absent.  ``phases`` records relevance and never substitutes for live
ownership evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Sequence


AUTHORITY_ACCOUNT_ID = "042360977644"
MANAGEMENT_ACCOUNT_ID = "839393571433"
REGION = "us-east-1"
SCHEMA_VERSION = 1
RECORD_TYPE = "scanalyze.platform_authority.gug376_route_collision_catalog.v1"
TARGET_COUNT = 73

PHASE_ORDER = (
    "artifact-bridge",
    "artifact-foundation",
    "route",
    "broker",
    "delegation",
    "pep",
    "retirement",
)

BRIDGE_STACK_NAME = (
    "scanalyze-platform-authority-gug376-artifact-bootstrap-bridge"
)
FOUNDATION_STACK_NAME = (
    "scanalyze-platform-authority-gug376-artifact-foundation"
)
ROUTE_STACK_NAME = (
    "scanalyze-platform-authority-gug376-temporary-change-set-route"
)
BROKER_STACK_NAME = "scanalyze-platform-authority-gug376-route-broker"
DELEGATION_STACK_NAME = (
    "scanalyze-platform-authority-bootstrap-plan-repair-delegation"
)
PEP_STACK_NAME = "scanalyze-platform-authority-bootstrap-plan-repair-pep"

_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit_sha",
        "source_tree_sha",
        "bootstrap_intent_digest",
        "authority_account_id",
        "management_account_id",
        "region",
        "not_before",
        "expires_at",
        "artifact_bucket_name",
        "targets",
        "target_count",
        "catalog_digest",
    }
)
_TARGET_FIELDS = frozenset(
    {
        "target_id",
        "service",
        "domain",
        "account_id",
        "region",
        "scope",
        "name",
        "selector",
        "phases",
        "lifecycle",
    }
)
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_TIME = re.compile(
    r"^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_BUCKET = re.compile(
    r"^(?!xn--)(?!sthree-)(?!amzn-s3-demo-)"
    r"[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$"
)
_ACCOUNT_REGIONAL_ARTIFACT_BUCKET = re.compile(
    rf"^scanalyze-g376-art-[a-f0-9]{{12}}-"
    rf"{AUTHORITY_ACCOUNT_ID}-{REGION}-an$"
)
_TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{2,159}$")
_AMBIGUOUS_MARKERS = ("*", "?", "${", "@@", "!Ref", "<", ">", "[", "]")
_MAX_WINDOW = timedelta(hours=2)

_COMMON_OWNERSHIP_TAGS = {
    "managed_by": "cloudformation",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-376",
}

_SERVICE_SCOPES = {
    "cloudformation": frozenset({"stack"}),
    "dynamodb": frozenset({"table"}),
    "iam": frozenset({"role"}),
    "kms": frozenset({"alias"}),
    "lambda": frozenset({"alias", "code_signing_config", "function"}),
    "logs": frozenset({"log_group"}),
    "s3": frozenset({"bucket"}),
    "signer": frozenset({"signing_profile"}),
    "sso": frozenset({"application", "permission_set"}),
}


class CollisionCatalogError(ValueError):
    """Stable fail-closed catalog error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CollisionCatalogError(code)


def canonical_json(value: Any) -> str:
    """Return the sole JSON representation used by catalog digests."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CollisionCatalogError("CANONICAL_JSON_INVALID") from error


def canonical_digest(value: Any) -> str:
    """Digest one JSON-compatible value with an explicit algorithm prefix."""

    encoded = canonical_json(value).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _fail(code)
    return parsed


def _validate_bucket_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _BUCKET.fullmatch(value) is None
        or ".." in value
        or ".-" in value
        or "-." in value
        or value.endswith(("-s3alias", "--ol-s3", ".mrap", "--x-s3"))
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", value) is not None
        or any(marker in value for marker in _AMBIGUOUS_MARKERS)
    ):
        _fail("ARTIFACT_BUCKET_NAME_INVALID")
    return value


def _expected_artifact_bucket(source_commit_sha: str) -> str:
    return (
        f"scanalyze-g376-art-{source_commit_sha[:12]}-"
        f"{AUTHORITY_ACCOUNT_ID}-{REGION}-an"
    )


def _validate_artifact_bucket_binding(
    value: Any, *, source_commit_sha: str
) -> str:
    bucket_name = _validate_bucket_name(value)
    if (
        _ACCOUNT_REGIONAL_ARTIFACT_BUCKET.fullmatch(bucket_name) is None
        or bucket_name != _expected_artifact_bucket(source_commit_sha)
    ):
        _fail("ARTIFACT_BUCKET_BINDING_INVALID")
    return bucket_name


def _validate_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or value != value.strip()
        or any(character.isspace() for character in value)
        or any(marker in value for marker in _AMBIGUOUS_MARKERS)
    ):
        _fail("TARGET_NAME_AMBIGUOUS")
    return value


def _exact(
    target_id: str,
    service: str,
    domain: str,
    account_id: str,
    scope: str,
    name: str,
    phases: Sequence[str],
    *,
    lifecycle: str = "ROUTE_CREATED",
) -> dict[str, Any]:
    return {
        "target_id": target_id,
        "service": service,
        "domain": domain,
        "account_id": account_id,
        "region": REGION,
        "scope": scope,
        "name": name,
        "selector": {"kind": "exact_name"},
        "phases": list(phases),
        "lifecycle": lifecycle,
    }


def _lambda_alias(
    target_id: str, function_name: str, alias_name: str, phase: str
) -> dict[str, Any]:
    return {
        "target_id": target_id,
        "service": "lambda",
        "domain": "authority",
        "account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "scope": "alias",
        "name": f"{function_name}:{alias_name}",
        "selector": {
            "kind": "lambda_alias",
            "function_name": function_name,
            "alias_name": alias_name,
        },
        "phases": [phase],
        "lifecycle": "ROUTE_CREATED",
    }


def _code_signing_config(
    target_id: str,
    stack_name: str,
    logical_resource_id: str,
    phase: str,
    *,
    tags_available: bool,
) -> dict[str, Any]:
    selector: dict[str, Any] = {
        "kind": (
            "cloudformation_ownership_tags"
            if tags_available
            else "cloudformation_stack_resource"
        ),
        "stack_name": stack_name,
        "logical_resource_id": logical_resource_id,
    }
    if tags_available:
        selector["required_tags"] = dict(_COMMON_OWNERSHIP_TAGS)
    return {
        "target_id": target_id,
        "service": "lambda",
        "domain": "authority",
        "account_id": AUTHORITY_ACCOUNT_ID,
        "region": REGION,
        "scope": "code_signing_config",
        "name": f"{stack_name}/{logical_resource_id}",
        "selector": selector,
        "phases": [phase],
        "lifecycle": "ROUTE_CREATED",
    }


def _target_sort_key(target: Mapping[str, Any]) -> tuple[Any, ...]:
    phases = target["phases"]
    phase_index = PHASE_ORDER.index(phases[0])
    domain_index = {"management": 0, "authority": 1}[target["domain"]]
    return (
        phase_index,
        domain_index,
        target["service"],
        target["scope"],
        target["name"],
        target["target_id"],
    )


def _expected_targets(
    *, source_commit_sha: str, artifact_bucket_name: str
) -> list[dict[str, Any]]:
    suffix = source_commit_sha[:12]
    targets: list[dict[str, Any]] = [
        _exact(
            "management.cfn.artifact-bridge-stack",
            "cloudformation",
            "management",
            MANAGEMENT_ACCOUNT_ID,
            "stack",
            BRIDGE_STACK_NAME,
            ("artifact-bridge",),
        ),
        _exact(
            "management.iam.route-broker-recovery",
            "iam",
            "management",
            MANAGEMENT_ACCOUNT_ID,
            "role",
            "scanalyze/platform-authority/ScanalyzeGug376RouteBrokerRecovery",
            ("artifact-bridge",),
        ),
    ]

    for name, target_id in (
        ("ScanalyzeGug376ArtifactBootstrap", "artifact-bootstrap"),
        ("ScanalyzeGug376RouteSeedCleanup", "route-seed-cleanup"),
        ("ScanalyzeGug376BrokerSeedCleanup", "broker-seed-cleanup"),
    ):
        targets.append(
            _exact(
                f"management.sso.{target_id}",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "permission_set",
                name,
                ("artifact-bridge",),
            )
        )

    targets.extend(
        [
            _exact(
                "authority.cfn.artifact-foundation-stack",
                "cloudformation",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "stack",
                FOUNDATION_STACK_NAME,
                ("artifact-foundation",),
            ),
            _exact(
                "authority.s3.artifact-bucket",
                "s3",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "bucket",
                artifact_bucket_name,
                ("artifact-foundation",),
            ),
            _exact(
                "authority.kms.artifact-alias",
                "kms",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "alias",
                (
                    "alias/scanalyze-platform-authority-gug376-artifacts-"
                    f"{suffix}"
                ),
                ("artifact-foundation",),
            ),
            _exact(
                "authority.signer.artifact-profile",
                "signer",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "signing_profile",
                f"ScanalyzeGug376ArtifactSigner_{suffix}",
                ("artifact-foundation",),
            ),
            _code_signing_config(
                "authority.lambda.artifact-code-signing-config",
                FOUNDATION_STACK_NAME,
                "CodeSigningConfig",
                "artifact-foundation",
                tags_available=True,
            ),
            _exact(
                "management.cfn.temporary-route-stack",
                "cloudformation",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "stack",
                ROUTE_STACK_NAME,
                ("route",),
            ),
        ]
    )

    for name, target_id in (
        (
            "scanalyze/platform-authority/ScanalyzeGug376RouteBrokerCreator",
            "route-broker-creator",
        ),
        (
            "scanalyze/platform-authority/ScanalyzeGug376RouteBrokerExecutor",
            "route-broker-executor",
        ),
        (
            "scanalyze/platform-authority/ScanalyzeGug376CollisionReader",
            "collision-reader",
        ),
    ):
        targets.append(
            _exact(
                f"management.iam.{target_id}",
                "iam",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "role",
                name,
                ("route",),
            )
        )

    for name, target_id in (
        ("ScanalyzeGug376BrokerSeedCreator", "broker-seed-creator"),
        ("ScanalyzeGug376BrokerSeedExec", "broker-seed-executor"),
        ("ScanalyzeGug376BrokerInvoker", "broker-invoker"),
    ):
        targets.append(
            _exact(
                f"management.sso.{target_id}",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "permission_set",
                name,
                ("route",),
            )
        )

    targets.extend(
        [
            _exact(
                "authority.cfn.route-broker-stack",
                "cloudformation",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "stack",
                BROKER_STACK_NAME,
                ("broker",),
            ),
            _exact(
                "authority.dynamodb.route-broker-ledger",
                "dynamodb",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "table",
                "scanalyze-platform-authority-gug376-route-broker-ledger",
                ("broker",),
            ),
            _exact(
                "authority.kms.route-broker-ledger-alias",
                "kms",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "alias",
                "alias/scanalyze/platform-authority/gug376-route-broker-ledger",
                ("broker",),
            ),
            _code_signing_config(
                "authority.lambda.route-broker-code-signing-config",
                BROKER_STACK_NAME,
                "BrokerCodeSigningConfig",
                "broker",
                tags_available=False,
            ),
        ]
    )

    authority_broker_roles = (
        "ScanalyzeGug376RouteBrokerCreator",
        "ScanalyzeGug376RouteBrokerExecutor",
        "ScanalyzeGug376RouteCreateDispatchRecovery",
        "ScanalyzeGug376RouteExecuteDispatchRecovery",
        "ScanalyzeGug376CollisionReader",
    )
    for name in authority_broker_roles:
        targets.append(
            _exact(
                f"authority.iam.{name.lower()}",
                "iam",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "role",
                name,
                ("broker",),
            )
        )

    broker_functions = (
        "scanalyze-platform-authority-gug376-route-creator",
        "scanalyze-platform-authority-gug376-route-executor",
        "scanalyze-platform-authority-gug376-route-create-dispatch-recovery",
        "scanalyze-platform-authority-gug376-route-execute-dispatch-recovery",
    )
    for name in broker_functions:
        slug = name.removeprefix("scanalyze-platform-authority-")
        targets.extend(
            [
                _exact(
                    f"authority.lambda.function.{slug}",
                    "lambda",
                    "authority",
                    AUTHORITY_ACCOUNT_ID,
                    "function",
                    name,
                    ("broker",),
                ),
                _exact(
                    f"authority.logs.{slug}",
                    "logs",
                    "authority",
                    AUTHORITY_ACCOUNT_ID,
                    "log_group",
                    f"/aws/lambda/{name}",
                    ("broker",),
                ),
            ]
        )

    broker_aliases = {
        broker_functions[0]: (
            "seed-revoke-create-v1",
            "delegation-create-v1",
            "pep-create-v1",
            "pep-protection-create-v1",
            "closeout-gate-v1",
            "delegation-revoke-create-v1",
            "route-revoke-create-v1",
        ),
        broker_functions[1]: (
            "seed-revoke-execute-v1",
            "delegation-execute-v1",
            "pep-execute-v1",
            "pep-protection-execute-v1",
            "delegation-revoke-execute-v1",
            "route-revoke-execute-v1",
        ),
        broker_functions[2]: ("recover-v1",),
        broker_functions[3]: ("recover-v1",),
    }
    for function_name, aliases in broker_aliases.items():
        function_slug = function_name.removeprefix(
            "scanalyze-platform-authority-"
        )
        for alias_name in aliases:
            targets.append(
                _lambda_alias(
                    f"authority.lambda.alias.{function_slug}.{alias_name}",
                    function_name,
                    alias_name,
                    "broker",
                )
            )

    targets.extend(
        [
            _exact(
                "management.cfn.plan-repair-delegation-stack",
                "cloudformation",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "stack",
                DELEGATION_STACK_NAME,
                ("delegation",),
            ),
            _exact(
                "management.iam.plan-repair-mutation",
                "iam",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "role",
                "scanalyze/platform-authority/ScanalyzeBootstrapPlanRepairMutation",
                ("delegation",),
            ),
            _exact(
                "management.iam.plan-repair-readback",
                "iam",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "role",
                "scanalyze/platform-authority/ScanalyzeBootstrapPlanRepairReadback",
                ("delegation",),
            ),
            _exact(
                "management.sso.plan-repair",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "permission_set",
                "ScanalyzeBootstrapPlanRepair",
                ("delegation",),
            ),
            _exact(
                "authority.cfn.plan-repair-pep-stack",
                "cloudformation",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "stack",
                PEP_STACK_NAME,
                ("pep",),
            ),
            _exact(
                "authority.dynamodb.plan-repair-ledger",
                "dynamodb",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "table",
                "scanalyze-platform-authority-plan-policy-repair-ledger",
                ("pep",),
            ),
            _exact(
                "authority.kms.plan-repair-ledger-alias",
                "kms",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "alias",
                "alias/scanalyze/platform-authority/gug376-plan-policy-repair-ledger",
                ("pep",),
            ),
            _code_signing_config(
                "authority.lambda.plan-repair-code-signing-config",
                PEP_STACK_NAME,
                "RepairCodeSigningConfig",
                "pep",
                tags_available=True,
            ),
        ]
    )

    for name in (
        "ScanalyzeBootstrapPlanRepairPlan",
        "ScanalyzeBootstrapPlanRepairExecution",
        "ScanalyzeBootstrapPlanRepairReconcile",
        "scanalyze/platform-authority/ScanalyzeBootstrapPlanRepairInspector",
    ):
        target_id = name.rsplit("/", 1)[-1].lower()
        targets.append(
            _exact(
                f"authority.iam.{target_id}",
                "iam",
                "authority",
                AUTHORITY_ACCOUNT_ID,
                "role",
                name,
                ("pep",),
            )
        )

    pep_functions = (
        ("scanalyze-platform-authority-plan-policy-plan", "plan-v1"),
        ("scanalyze-platform-authority-plan-policy-repair", "repair-v1"),
        ("scanalyze-platform-authority-plan-policy-reconcile", "reconcile-v1"),
    )
    for function_name, alias_name in pep_functions:
        slug = function_name.removeprefix("scanalyze-platform-authority-")
        targets.extend(
            [
                _exact(
                    f"authority.lambda.function.{slug}",
                    "lambda",
                    "authority",
                    AUTHORITY_ACCOUNT_ID,
                    "function",
                    function_name,
                    ("pep",),
                ),
                _lambda_alias(
                    f"authority.lambda.alias.{slug}.{alias_name}",
                    function_name,
                    alias_name,
                    "pep",
                ),
                _exact(
                    f"authority.logs.{slug}",
                    "logs",
                    "authority",
                    AUTHORITY_ACCOUNT_ID,
                    "log_group",
                    f"/aws/lambda/{function_name}",
                    ("pep",),
                ),
            ]
        )

    targets.extend(
        [
            _exact(
                "management.sso.retirement-application",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "application",
                "ScanalyzeAuthorityRetirement",
                ("retirement",),
                lifecycle="COLLISION_ONLY",
            ),
            _exact(
                "management.sso.retirement-classifier",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "permission_set",
                "ScanalyzeAuthorityRetireClass",
                ("retirement",),
                lifecycle="COLLISION_ONLY",
            ),
            _exact(
                "management.sso.retirement-approver",
                "sso",
                "management",
                MANAGEMENT_ACCOUNT_ID,
                "permission_set",
                "ScanalyzeAuthorityRetireApprove",
                ("retirement",),
                lifecycle="COLLISION_ONLY",
            ),
        ]
    )

    return sorted(targets, key=_target_sort_key)


def _validate_target_shape(target: Any) -> None:
    if not isinstance(target, Mapping) or set(target) != _TARGET_FIELDS:
        _fail("TARGET_FIELDS_INVALID")
    target_id = target.get("target_id")
    service = target.get("service")
    domain = target.get("domain")
    account_id = target.get("account_id")
    scope = target.get("scope")
    phases = target.get("phases")
    selector = target.get("selector")
    lifecycle = target.get("lifecycle")
    if not isinstance(target_id, str) or _TARGET_ID.fullmatch(target_id) is None:
        _fail("TARGET_ID_INVALID")
    if service not in _SERVICE_SCOPES or scope not in _SERVICE_SCOPES[service]:
        _fail("TARGET_SERVICE_SCOPE_INVALID")
    if domain not in {"authority", "management"}:
        _fail("TARGET_DOMAIN_INVALID")
    expected_account = (
        AUTHORITY_ACCOUNT_ID if domain == "authority" else MANAGEMENT_ACCOUNT_ID
    )
    if account_id != expected_account:
        _fail("TARGET_ACCOUNT_INVALID")
    if target.get("region") != REGION:
        _fail("TARGET_REGION_INVALID")
    if lifecycle not in {"ROUTE_CREATED", "COLLISION_ONLY"}:
        _fail("TARGET_LIFECYCLE_INVALID")
    if lifecycle == "COLLISION_ONLY" and phases != ["retirement"]:
        _fail("TARGET_LIFECYCLE_INVALID")
    _validate_name(target.get("name"))
    if (
        not isinstance(phases, list)
        or not phases
        or len(phases) != len(set(phases))
        or any(phase not in PHASE_ORDER for phase in phases)
        or phases != sorted(phases, key=PHASE_ORDER.index)
    ):
        _fail("TARGET_PHASES_INVALID")
    if not isinstance(selector, Mapping):
        _fail("TARGET_SELECTOR_INVALID")
    kind = selector.get("kind")
    if kind == "exact_name":
        expected_fields = {"kind"}
    elif kind == "lambda_alias":
        expected_fields = {"kind", "function_name", "alias_name"}
        _validate_name(selector.get("function_name"))
        _validate_name(selector.get("alias_name"))
        if target.get("name") != (
            f"{selector['function_name']}:{selector['alias_name']}"
        ):
            _fail("TARGET_SELECTOR_INVALID")
    elif kind == "cloudformation_stack_resource":
        expected_fields = {"kind", "stack_name", "logical_resource_id"}
        _validate_name(selector.get("stack_name"))
        _validate_name(selector.get("logical_resource_id"))
    elif kind == "cloudformation_ownership_tags":
        expected_fields = {
            "kind",
            "stack_name",
            "logical_resource_id",
            "required_tags",
        }
        _validate_name(selector.get("stack_name"))
        _validate_name(selector.get("logical_resource_id"))
        if selector.get("required_tags") != _COMMON_OWNERSHIP_TAGS:
            _fail("TARGET_SELECTOR_INVALID")
    else:
        _fail("TARGET_SELECTOR_INVALID")
    if set(selector) != expected_fields:
        _fail("TARGET_SELECTOR_INVALID")


def materialize_route_collision_catalog(
    *,
    source_commit_sha: str,
    source_tree_sha: str,
    bootstrap_intent_digest: str,
    not_before: str,
    expires_at: str,
    artifact_bucket_name: str,
) -> dict[str, Any]:
    """Build and seal the sole deterministic GUG-376 route name catalog."""

    if not isinstance(source_commit_sha, str) or _COMMIT.fullmatch(
        source_commit_sha
    ) is None:
        _fail("SOURCE_COMMIT_INVALID")
    if not isinstance(source_tree_sha, str) or _COMMIT.fullmatch(
        source_tree_sha
    ) is None:
        _fail("SOURCE_TREE_INVALID")
    if not isinstance(bootstrap_intent_digest, str) or _DIGEST.fullmatch(
        bootstrap_intent_digest
    ) is None:
        _fail("BOOTSTRAP_INTENT_DIGEST_INVALID")
    before = _parse_time(not_before, "WINDOW_INVALID")
    after = _parse_time(expires_at, "WINDOW_INVALID")
    if not before < after or after - before > _MAX_WINDOW:
        _fail("WINDOW_INVALID")
    bucket_name = _validate_artifact_bucket_binding(
        artifact_bucket_name,
        source_commit_sha=source_commit_sha,
    )
    targets = _expected_targets(
        source_commit_sha=source_commit_sha,
        artifact_bucket_name=bucket_name,
    )
    if len(targets) != TARGET_COUNT:
        _fail("TARGET_CATALOG_COUNT_INVALID")
    catalog: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": RECORD_TYPE,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "bootstrap_intent_digest": bootstrap_intent_digest,
        "authority_account_id": AUTHORITY_ACCOUNT_ID,
        "management_account_id": MANAGEMENT_ACCOUNT_ID,
        "region": REGION,
        "not_before": not_before,
        "expires_at": expires_at,
        "artifact_bucket_name": bucket_name,
        "targets": targets,
        "target_count": len(targets),
    }
    catalog["catalog_digest"] = canonical_digest(catalog)
    validate_route_collision_catalog(catalog)
    return catalog


def validate_route_collision_catalog(catalog: Mapping[str, Any]) -> None:
    """Validate exact shape, membership, ordering and digest bindings."""

    if not isinstance(catalog, Mapping) or set(catalog) != _TOP_FIELDS:
        _fail("CATALOG_FIELDS_INVALID")
    if catalog.get("schema_version") != SCHEMA_VERSION:
        _fail("CATALOG_SCHEMA_VERSION_INVALID")
    if catalog.get("record_type") != RECORD_TYPE:
        _fail("CATALOG_RECORD_TYPE_INVALID")
    source_commit_sha = catalog.get("source_commit_sha")
    source_tree_sha = catalog.get("source_tree_sha")
    bootstrap_digest = catalog.get("bootstrap_intent_digest")
    if not isinstance(source_commit_sha, str) or _COMMIT.fullmatch(
        source_commit_sha
    ) is None:
        _fail("SOURCE_COMMIT_INVALID")
    if not isinstance(source_tree_sha, str) or _COMMIT.fullmatch(
        source_tree_sha
    ) is None:
        _fail("SOURCE_TREE_INVALID")
    if not isinstance(bootstrap_digest, str) or _DIGEST.fullmatch(
        bootstrap_digest
    ) is None:
        _fail("BOOTSTRAP_INTENT_DIGEST_INVALID")
    if (
        catalog.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or catalog.get("management_account_id") != MANAGEMENT_ACCOUNT_ID
    ):
        _fail("CATALOG_ACCOUNT_INVALID")
    if catalog.get("region") != REGION:
        _fail("CATALOG_REGION_INVALID")
    before = _parse_time(catalog.get("not_before"), "WINDOW_INVALID")
    after = _parse_time(catalog.get("expires_at"), "WINDOW_INVALID")
    if not before < after or after - before > _MAX_WINDOW:
        _fail("WINDOW_INVALID")
    bucket_name = _validate_artifact_bucket_binding(
        catalog.get("artifact_bucket_name"),
        source_commit_sha=source_commit_sha,
    )
    targets = catalog.get("targets")
    if not isinstance(targets, list):
        _fail("TARGETS_INVALID")
    for target in targets:
        _validate_target_shape(target)
    target_ids = [target["target_id"] for target in targets]
    if len(target_ids) != len(set(target_ids)):
        _fail("TARGET_DUPLICATE")
    physical_keys = [
        (
            target["service"],
            target["account_id"],
            target["region"],
            target["scope"],
            target["name"],
            canonical_json(target["selector"]),
        )
        for target in targets
    ]
    if len(physical_keys) != len(set(physical_keys)):
        _fail("TARGET_DUPLICATE")
    expected_targets = _expected_targets(
        source_commit_sha=source_commit_sha,
        artifact_bucket_name=bucket_name,
    )
    if len(expected_targets) != TARGET_COUNT:
        _fail("TARGET_CATALOG_COUNT_INVALID")
    expected_ids = {target["target_id"] for target in expected_targets}
    if set(target_ids) != expected_ids:
        _fail("TARGET_SET_INVALID")
    if targets != expected_targets:
        _fail("TARGET_CATALOG_INVALID")
    if catalog.get("target_count") != len(expected_targets):
        _fail("TARGET_COUNT_INVALID")
    sealed = dict(catalog)
    supplied_digest = sealed.pop("catalog_digest")
    if (
        not isinstance(supplied_digest, str)
        or _DIGEST.fullmatch(supplied_digest) is None
        or supplied_digest != canonical_digest(sealed)
    ):
        _fail("CATALOG_DIGEST_INVALID")


__all__ = [
    "AUTHORITY_ACCOUNT_ID",
    "BRIDGE_STACK_NAME",
    "BROKER_STACK_NAME",
    "CollisionCatalogError",
    "DELEGATION_STACK_NAME",
    "FOUNDATION_STACK_NAME",
    "MANAGEMENT_ACCOUNT_ID",
    "PEP_STACK_NAME",
    "PHASE_ORDER",
    "RECORD_TYPE",
    "REGION",
    "ROUTE_STACK_NAME",
    "canonical_digest",
    "canonical_json",
    "materialize_route_collision_catalog",
    "validate_route_collision_catalog",
]
