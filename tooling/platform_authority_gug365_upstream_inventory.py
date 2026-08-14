"""Pure inventory primitives for the GUG-376 upstream prerequisite lane.

The module deliberately has no AWS SDK dependency and owns no credentials or
clients.  Callers inject one-page readers and persist the resulting private
records outside the repository.  Every paginated surface must terminate
cleanly, and two independently collected snapshots must be byte-for-byte
equivalent after removing their collection-time envelope.

An access error, timeout, malformed page, pagination cycle, or page-limit hit
is never classified as absence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
from typing import Any, Callable, Mapping, Protocol, Sequence


RECORD_TYPE = "scanalyze.platform_authority.gug365_upstream_inventory_snapshot.v1"
STABILITY_RECORD_TYPE = (
    "scanalyze.platform_authority.gug365_upstream_inventory_stability.v1"
)
RAW_PROVIDER_RECORD_TYPE = (
    "scanalyze.platform_authority.gug365_upstream_raw_provider_snapshot.v1"
)
RAW_PROVIDER_STABILITY_RECORD_TYPE = (
    "scanalyze.platform_authority.gug365_upstream_raw_provider_stability.v1"
)
IMPLEMENTATION_ISSUE = "GUG-376"
CONSUMER_ISSUE = "GUG-365"
REGION = "us-east-1"
PRODUCTION_STATUS = "NO-GO"
MAX_PAGES = 50

SURFACES = (
    "s3",
    "kms",
    "signer",
    "lambda_code_signing",
    "lambda_runtime",
    "identity_center",
    "identity_store",
    "iam_roles",
    "artifact_objects",
)
CLASSIFICATIONS = frozenset(
    {
        "ABSENT_READY",
        "EXACT_PRESENT_NO_TOUCH",
        "PREEXISTING_NO_TOUCH",
        "DRIFT_BLOCKED_NO_REPAIR",
        "UNCERTAIN_RECONCILE_ONLY",
        "NOT_AUTHORIZED",
    }
)

# This is intentionally an exact allowlist, not a verb heuristic.  Several AWS
# mutating actions do not start with the usual write verbs (for example
# lambda:InvokeFunction, iam:PassRole, and sqs:PurgeQueue), so a blacklist is
# not a security boundary.  Keep this set byte-for-byte aligned with the two
# reviewed GUG-376 inventory policies.
READ_ONLY_ACTION_ALLOWLIST = frozenset(
    {
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListRoleTags",
        "identitystore:DescribeUser",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListGrants",
        "kms:ListKeys",
        "kms:ListResourceTags",
        "lambda:GetCodeSigningConfig",
        "lambda:GetFunctionConfiguration",
        "lambda:GetRuntimeManagementConfig",
        "lambda:ListCodeSigningConfigs",
        "lambda:ListFunctions",
        "lambda:ListFunctionsByCodeSigningConfig",
        "lambda:ListTags",
        "lambda:ListVersionsByFunction",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLifecycleConfiguration",
        "s3:GetBucketLocation",
        "s3:GetBucketOwnershipControls",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "s3:GetObjectAttributes",
        "s3:GetObjectTagging",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionTagging",
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "signer:DescribeSigningJob",
        "signer:GetRevocationStatus",
        "signer:GetSigningProfile",
        "signer:ListProfilePermissions",
        "signer:ListSigningJobs",
        "signer:ListSigningPlatforms",
        "signer:ListSigningProfiles",
        "signer:ListTagsForResource",
        "sso:DescribeAccountAssignmentCreationStatus",
        "sso:DescribeApplication",
        "sso:DescribeInstance",
        "sso:DescribePermissionSet",
        "sso:DescribePermissionSetProvisioningStatus",
        "sso:GetApplicationAccessScope",
        "sso:GetApplicationAssignmentConfiguration",
        "sso:GetApplicationAuthenticationMethod",
        "sso:GetApplicationGrant",
        "sso:GetInlinePolicyForPermissionSet",
        "sso:GetPermissionsBoundaryForPermissionSet",
        "sso:ListAccountAssignmentCreationStatus",
        "sso:ListAccountAssignments",
        "sso:ListAccountsForProvisionedPermissionSet",
        "sso:ListApplicationAccessScopes",
        "sso:ListApplicationAssignments",
        "sso:ListApplicationAuthenticationMethods",
        "sso:ListApplicationGrants",
        "sso:ListApplications",
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        "sso:ListInstances",
        "sso:ListManagedPoliciesInPermissionSet",
        "sso:ListPermissionSetProvisioningStatus",
        "sso:ListPermissionSets",
        "sso:ListTagsForResource",
        "sts:GetCallerIdentity",
    }
)

SURFACE_READ_ACTION_ALLOWLIST = {
    "s3": frozenset(
        {
            "s3:GetAccountPublicAccessBlock",
            "s3:GetBucketAcl",
            "s3:GetBucketEncryption",
            "s3:GetBucketLifecycleConfiguration",
            "s3:GetBucketLocation",
            "s3:GetBucketOwnershipControls",
            "s3:GetBucketPolicy",
            "s3:GetBucketPolicyStatus",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketTagging",
            "s3:GetBucketVersioning",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:ListBucketVersions",
        }
    ),
    "kms": frozenset(
        {
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListGrants",
            "kms:ListKeys",
            "kms:ListResourceTags",
        }
    ),
    "signer": frozenset(
        {
            "signer:DescribeSigningJob",
            "signer:GetRevocationStatus",
            "signer:GetSigningProfile",
            "signer:ListProfilePermissions",
            "signer:ListSigningJobs",
            "signer:ListSigningPlatforms",
            "signer:ListSigningProfiles",
            "signer:ListTagsForResource",
        }
    ),
    "lambda_code_signing": frozenset(
        {
            "lambda:GetCodeSigningConfig",
            "lambda:ListCodeSigningConfigs",
            "lambda:ListFunctionsByCodeSigningConfig",
            "lambda:ListTags",
        }
    ),
    "lambda_runtime": frozenset(
        {
            "lambda:GetFunctionConfiguration",
            "lambda:GetRuntimeManagementConfig",
            "lambda:ListFunctions",
            "lambda:ListTags",
            "lambda:ListVersionsByFunction",
        }
    ),
    "identity_center": frozenset(
        {
            "sso:DescribeAccountAssignmentCreationStatus",
            "sso:DescribeApplication",
            "sso:DescribeInstance",
            "sso:DescribePermissionSet",
            "sso:DescribePermissionSetProvisioningStatus",
            "sso:GetApplicationAccessScope",
            "sso:GetApplicationAssignmentConfiguration",
            "sso:GetApplicationAuthenticationMethod",
            "sso:GetApplicationGrant",
            "sso:GetInlinePolicyForPermissionSet",
            "sso:GetPermissionsBoundaryForPermissionSet",
            "sso:ListAccountAssignmentCreationStatus",
            "sso:ListAccountAssignments",
            "sso:ListAccountsForProvisionedPermissionSet",
            "sso:ListApplicationAccessScopes",
            "sso:ListApplicationAssignments",
            "sso:ListApplicationAuthenticationMethods",
            "sso:ListApplicationGrants",
            "sso:ListApplications",
            "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
            "sso:ListInstances",
            "sso:ListManagedPoliciesInPermissionSet",
            "sso:ListPermissionSetProvisioningStatus",
            "sso:ListPermissionSets",
            "sso:ListTagsForResource",
        }
    ),
    "identity_store": frozenset({"identitystore:DescribeUser"}),
    "iam_roles": frozenset(
        {
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:ListRoles",
            "iam:ListRoleTags",
        }
    ),
    "artifact_objects": frozenset(
        {
            "s3:GetObject",
            "s3:GetObjectAttributes",
            "s3:GetObjectTagging",
            "s3:GetObjectVersion",
            "s3:GetObjectVersionTagging",
            "s3:ListBucket",
            "s3:ListBucketVersions",
        }
    ),
}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RUNTIME_ARN = re.compile(
    r"^arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}$"
)
MAX_DIRECT_SSO_SESSION = timedelta(hours=1)


class UpstreamInventoryError(ValueError):
    """Stable failure code that never includes provider-controlled text."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "UPSTREAM_INVENTORY_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise UpstreamInventoryError(code)


def canonical_json(value: Any) -> str:
    """Return the single JSON representation accepted by digest contracts."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("INVENTORY_VALUE_NOT_CANONICAL")
    raise AssertionError("unreachable")


class ProviderInventoryTranscriptVerifier(Protocol):
    """External verifier for an opaque, read-only provider transcript."""

    def identity_digest(self) -> str: ...

    def verify(
        self,
        *,
        stage: str,
        transcript_receipt: Mapping[str, Any],
        raw_provider_snapshot: Mapping[str, Any],
        evaluated_at: datetime,
    ) -> Mapping[str, Any]: ...


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_snapshot(value: Any, *, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(code)
    raise AssertionError("unreachable")


def _timestamp(value: datetime, *, code: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail(code)
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: Any, *, code: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _fail(code)
    if _timestamp(parsed, code=code) != value:
        _fail(code)
    return parsed


def _digest(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _exact_integer(value: Any, expected: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value == expected
    )


def collect_paginated(
    fetch_page: Callable[[str | None], Mapping[str, Any]],
    *,
    items_key: str,
    response_token_key: str = "NextToken",
    maximum_pages: int = MAX_PAGES,
) -> dict[str, Any]:
    """Collect one complete provider list without treating errors as empty.

    ``fetch_page`` receives the prior response token (or ``None`` initially).
    The returned envelope is suitable for a private provider snapshot and
    records the exact number of successful pages.
    """

    if (
        not callable(fetch_page)
        or not isinstance(items_key, str)
        or not items_key
        or not isinstance(response_token_key, str)
        or not response_token_key
        or not isinstance(maximum_pages, int)
        or isinstance(maximum_pages, bool)
        or not 1 <= maximum_pages <= MAX_PAGES
    ):
        _fail("PAGINATION_CONTRACT_INVALID")

    items: list[Any] = []
    page_digests: list[str] = []
    seen_tokens: set[str] = set()
    request_token: str | None = None

    for _ in range(maximum_pages):
        try:
            response = fetch_page(request_token)
        except Exception as exc:
            raise UpstreamInventoryError("INVENTORY_READ_UNAVAILABLE") from exc
        if not isinstance(response, Mapping):
            _fail("INVENTORY_PAGE_INVALID")
        page = canonical_snapshot(response, code="INVENTORY_PAGE_INVALID")
        page_items = page.get(items_key)
        if not isinstance(page_items, list):
            _fail("INVENTORY_PAGE_ITEMS_INVALID")
        items.extend(page_items)
        page_digests.append(canonical_digest(page))

        next_token = page.get(response_token_key)
        if next_token is None:
            return {
                "complete": True,
                "page_count": len(page_digests),
                "item_count": len(items),
                "items": items,
                "page_digests": page_digests,
                "pagination_digest": canonical_digest(page_digests),
            }
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen_tokens
            or next_token == request_token
        ):
            _fail("INVENTORY_PAGINATION_CYCLE")
        seen_tokens.add(next_token)
        request_token = next_token

    _fail("INVENTORY_PAGE_LIMIT_EXCEEDED")
    raise AssertionError("unreachable")


def surface_record(
    *,
    classification: str,
    resources: Sequence[Mapping[str, Any]],
    page_digests: Sequence[str],
    required_read_actions: Sequence[str],
) -> dict[str, Any]:
    """Normalize one fully authorized inventory surface."""

    if classification not in CLASSIFICATIONS:
        _fail("INVENTORY_CLASSIFICATION_INVALID")
    if classification == "NOT_AUTHORIZED":
        _fail("INVENTORY_SURFACE_NOT_AUTHORIZED")
    if not all(isinstance(item, Mapping) for item in resources):
        _fail("INVENTORY_RESOURCE_INVALID")
    if not page_digests or not all(
        isinstance(value, str) and _DIGEST.fullmatch(value)
        for value in page_digests
    ):
        _fail("INVENTORY_PAGE_DIGEST_INVALID")
    if not required_read_actions or not all(
        isinstance(action, str) and action in READ_ONLY_ACTION_ALLOWLIST
        for action in required_read_actions
    ):
        _fail("INVENTORY_READ_ACTION_INVALID")

    normalized_resources = canonical_snapshot(
        list(resources), code="INVENTORY_RESOURCE_INVALID"
    )
    normalized_resources.sort(key=canonical_json)
    record = {
        "access": "AUTHORIZED",
        "complete": True,
        "classification": classification,
        "resources": normalized_resources,
        "resource_count": len(normalized_resources),
        "page_digests": list(page_digests),
        "required_read_actions": sorted(set(required_read_actions)),
    }
    record["surface_digest"] = canonical_digest(record)
    _validate_surface_record(record)
    return record


def _validate_surface_record(record: Any) -> None:
    expected_keys = {
        "access",
        "complete",
        "classification",
        "resources",
        "resource_count",
        "page_digests",
        "required_read_actions",
        "surface_digest",
    }
    if not isinstance(record, Mapping) or set(record) != expected_keys:
        _fail("INVENTORY_SURFACE_INVALID")
    resources = record.get("resources")
    page_digests = record.get("page_digests")
    actions = record.get("required_read_actions")
    if (
        record.get("access") != "AUTHORIZED"
        or record.get("complete") is not True
        or record.get("classification")
        not in CLASSIFICATIONS - {"NOT_AUTHORIZED"}
        or not isinstance(resources, list)
        or not all(isinstance(item, Mapping) for item in resources)
        or resources != sorted(resources, key=canonical_json)
            or not _exact_integer(record.get("resource_count"), len(resources))
        or not isinstance(page_digests, list)
        or not page_digests
        or not all(
            isinstance(value, str) and _DIGEST.fullmatch(value)
            for value in page_digests
        )
        or not isinstance(actions, list)
        or not actions
        or not all(
            isinstance(action, str) and action in READ_ONLY_ACTION_ALLOWLIST
            for action in actions
        )
        or actions != sorted(set(actions))
    ):
        if isinstance(actions, list) and any(
            not isinstance(action, str) or action not in READ_ONLY_ACTION_ALLOWLIST
            for action in actions
        ):
            _fail("INVENTORY_READ_ACTION_INVALID")
        _fail("INVENTORY_SURFACE_INVALID")
    if record.get("surface_digest") != canonical_digest(
        {
            key: item
            for key, item in record.items()
            if key != "surface_digest"
        }
    ):
        _fail("INVENTORY_SURFACE_INVALID")


def _normalize_provider_pages(
    provider_pages: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(provider_pages, Mapping) or set(provider_pages) != set(SURFACES):
        _fail("RAW_PROVIDER_SURFACE_SET_INVALID")

    normalized: dict[str, dict[str, Any]] = {}
    expected_keys = {
        "complete",
        "page_count",
        "item_count",
        "items",
        "page_digests",
        "pagination_digest",
    }
    for name in SURFACES:
        collection = provider_pages[name]
        if not isinstance(collection, Mapping) or set(collection) != expected_keys:
            _fail("RAW_PROVIDER_PAGINATION_INVALID")
        items = collection.get("items")
        page_digests = collection.get("page_digests")
        if (
            collection.get("complete") is not True
            or not isinstance(items, list)
            or not all(isinstance(item, Mapping) for item in items)
            or not _exact_integer(collection.get("item_count"), len(items))
            or not isinstance(page_digests, list)
            or not page_digests
            or not all(
                isinstance(value, str) and _DIGEST.fullmatch(value)
                for value in page_digests
            )
            or not _exact_integer(
                collection.get("page_count"), len(page_digests)
            )
            or collection.get("pagination_digest")
            != canonical_digest(page_digests)
        ):
            _fail("RAW_PROVIDER_PAGINATION_INVALID")

        resources = canonical_snapshot(
            items, code="RAW_PROVIDER_RESOURCE_INVALID"
        )
        resources.sort(key=canonical_json)
        record = {
            "complete": True,
            "page_count": len(page_digests),
            "resource_count": len(resources),
            "resources": resources,
            "page_digests": list(page_digests),
            "pagination_digest": collection["pagination_digest"],
        }
        record["resource_digest"] = canonical_digest(record)
        normalized[name] = record
    return normalized


def _validate_raw_runtime_evidence(
    evidence: Any,
    *,
    session_started_at: datetime,
    collected_at: datetime,
) -> None:
    expected_keys = {
        "runtime",
        "update_runtime_on",
        "runtime_version_arn",
        "runtime_version_arn_digest",
        "source_function_arn_digest",
        "source_function_version",
        "function_configuration_digest",
        "runtime_management_config_digest",
        "provider_backed",
        "readback_complete",
        "evidence_collected_at",
        "runtime_evidence_digest",
    }
    if not isinstance(evidence, Mapping) or set(evidence) != expected_keys:
        _fail("RAW_PROVIDER_RUNTIME_FIELDS_INVALID")
    runtime_arn = evidence.get("runtime_version_arn")
    if (
        evidence.get("runtime") != "python3.12"
        or evidence.get("update_runtime_on") != "Manual"
        or not isinstance(runtime_arn, str)
        or _RUNTIME_ARN.fullmatch(runtime_arn) is None
        or evidence.get("runtime_version_arn_digest")
        != canonical_digest(runtime_arn)
        or evidence.get("provider_backed") is not True
        or evidence.get("readback_complete") is not True
        or not isinstance(evidence.get("source_function_version"), str)
        or re.fullmatch(r"[1-9][0-9]*", evidence["source_function_version"])
        is None
    ):
        _fail("STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN")
    for field in (
        "runtime_version_arn_digest",
        "source_function_arn_digest",
        "function_configuration_digest",
        "runtime_management_config_digest",
    ):
        _digest(evidence.get(field), code="RAW_PROVIDER_RUNTIME_DIGEST_INVALID")
    runtime_collected_at = _parse_timestamp(
        evidence.get("evidence_collected_at"), code="RAW_PROVIDER_RUNTIME_TIME_INVALID"
    )
    if not session_started_at <= runtime_collected_at <= collected_at:
        _fail("RAW_PROVIDER_RUNTIME_TIME_INVALID")
    if evidence.get("runtime_evidence_digest") != canonical_digest(
        {
            key: value
            for key, value in evidence.items()
            if key != "runtime_evidence_digest"
        }
    ):
        _fail("RAW_PROVIDER_RUNTIME_DIGEST_MISMATCH")


def _validate_raw_resource_evidence(value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != set(SURFACES):
        _fail("RAW_PROVIDER_SURFACE_SET_INVALID")
    expected_keys = {
        "complete",
        "page_count",
        "resource_count",
        "resources",
        "page_digests",
        "pagination_digest",
        "resource_digest",
    }
    for record in value.values():
        if not isinstance(record, Mapping) or set(record) != expected_keys:
            _fail("RAW_PROVIDER_RESOURCE_INVALID")
        resources = record.get("resources")
        page_digests = record.get("page_digests")
        if (
            record.get("complete") is not True
            or not isinstance(resources, list)
            or not all(isinstance(item, Mapping) for item in resources)
        or not _exact_integer(record.get("resource_count"), len(resources))
            or resources != sorted(resources, key=canonical_json)
            or not isinstance(page_digests, list)
            or not page_digests
            or not all(
                isinstance(item, str) and _DIGEST.fullmatch(item)
                for item in page_digests
            )
            or not _exact_integer(record.get("page_count"), len(page_digests))
            or record.get("pagination_digest") != canonical_digest(page_digests)
            or record.get("resource_digest")
            != canonical_digest(
                {
                    key: item
                    for key, item in record.items()
                    if key != "resource_digest"
                }
            )
        ):
            _fail("RAW_PROVIDER_RESOURCE_INVALID")


def build_raw_provider_snapshot(
    *,
    session_source: str,
    session_chain_depth: int,
    credential_source_digest: str,
    account_binding_digest: str,
    caller_identity_digest: str,
    session_identifier_digest: str,
    session_started_at: datetime,
    session_expires_at: datetime,
    collected_at: datetime,
    signed_calls: Sequence[Mapping[str, Any]],
    provider_pages: Mapping[str, Mapping[str, Any]],
    runtime_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a private, closed-world trace for one direct SSO inventory session.

    This pure builder performs no AWS calls.  ``signed_calls`` must be supplied
    in observed order; each item has exactly ``action``, ``surface``,
    ``called_at``, ``response_digest``, and ``pagination_complete``.  The first
    item must be STS and every later action is checked against the reviewed
    surface-specific allowlist.
    """

    if (
        session_source != "DIRECT_SSO"
        or session_chain_depth != 0
        or isinstance(session_chain_depth, bool)
    ):
        _fail("RAW_PROVIDER_SESSION_SOURCE_INVALID")
    for value in (
        credential_source_digest,
        account_binding_digest,
        caller_identity_digest,
        session_identifier_digest,
    ):
        _digest(value, code="RAW_PROVIDER_IDENTITY_BINDING_INVALID")
    started = _timestamp(
        session_started_at, code="RAW_PROVIDER_SESSION_TIME_INVALID"
    )
    expires = _timestamp(
        session_expires_at, code="RAW_PROVIDER_SESSION_TIME_INVALID"
    )
    collected = _timestamp(collected_at, code="RAW_PROVIDER_SESSION_TIME_INVALID")

    normalized_calls: list[dict[str, Any]] = []
    call_input_keys = {
        "action",
        "surface",
        "called_at",
        "response_digest",
        "pagination_complete",
    }
    if not isinstance(signed_calls, Sequence) or isinstance(
        signed_calls, (str, bytes)
    ):
        _fail("RAW_PROVIDER_CALLS_INVALID")
    for sequence, supplied_call in enumerate(signed_calls, start=1):
        if not isinstance(supplied_call, Mapping) or set(supplied_call) != call_input_keys:
            _fail("RAW_PROVIDER_CALL_FIELDS_INVALID")
        called_at = _timestamp(
            supplied_call.get("called_at"), code="RAW_PROVIDER_CALL_TIME_INVALID"
        )
        normalized_calls.append(
            {
                "sequence": sequence,
                "action": supplied_call.get("action"),
                "surface": supplied_call.get("surface"),
                "called_at": called_at,
                "response_digest": supplied_call.get("response_digest"),
                "pagination_complete": supplied_call.get("pagination_complete"),
            }
        )

    normalized_resources = _normalize_provider_pages(provider_pages)
    normalized_runtime = canonical_snapshot(
        runtime_evidence, code="RAW_PROVIDER_RUNTIME_INVALID"
    )
    snapshot = {
        "record_type": RAW_PROVIDER_RECORD_TYPE,
        "schema_version": 1,
        "region": REGION,
        "session_source": session_source,
        "session_chained": session_chain_depth != 0,
        "session_chain_depth": session_chain_depth,
        "credential_source_digest": credential_source_digest,
        "session_started_at": started,
        "session_expires_at": expires,
        "collected_at": collected,
        "account_binding_digest": account_binding_digest,
        "caller_identity_digest": caller_identity_digest,
        "session_identifier_digest": session_identifier_digest,
        "sts_first": True,
        "signed_calls": normalized_calls,
        "resource_evidence": normalized_resources,
        "resources_digest": canonical_digest(normalized_resources),
        "runtime_evidence": normalized_runtime,
        "aws_calls_complete": True,
        "pagination_complete": True,
        "aws_mutations": 0,
        "repository_persisted": False,
    }
    snapshot["raw_provider_digest"] = canonical_digest(snapshot)
    validate_raw_provider_snapshot(snapshot)
    return snapshot


def validate_raw_provider_snapshot(snapshot: Mapping[str, Any]) -> None:
    """Validate one direct-SSO raw provider trace without echoing its facts."""

    expected_keys = {
        "record_type",
        "schema_version",
        "region",
        "session_source",
        "session_chained",
        "session_chain_depth",
        "session_started_at",
        "session_expires_at",
        "collected_at",
        "credential_source_digest",
        "account_binding_digest",
        "caller_identity_digest",
        "session_identifier_digest",
        "sts_first",
        "signed_calls",
        "resource_evidence",
        "resources_digest",
        "runtime_evidence",
        "aws_calls_complete",
        "pagination_complete",
        "aws_mutations",
        "repository_persisted",
        "raw_provider_digest",
    }
    if not isinstance(snapshot, Mapping) or set(snapshot) != expected_keys:
        _fail("RAW_PROVIDER_FIELDS_INVALID")
    if any(
        (
            snapshot.get("record_type") != RAW_PROVIDER_RECORD_TYPE,
            not _exact_integer(snapshot.get("schema_version"), 1),
            snapshot.get("region") != REGION,
            snapshot.get("session_source") != "DIRECT_SSO",
            snapshot.get("session_chained") is not False,
            not _exact_integer(snapshot.get("session_chain_depth"), 0),
            snapshot.get("sts_first") is not True,
            snapshot.get("aws_calls_complete") is not True,
            snapshot.get("pagination_complete") is not True,
            not _exact_integer(snapshot.get("aws_mutations"), 0),
            snapshot.get("repository_persisted") is not False,
        )
    ):
        _fail("RAW_PROVIDER_CONSTANT_INVALID")
    for field in (
        "credential_source_digest",
        "account_binding_digest",
        "caller_identity_digest",
        "session_identifier_digest",
        "resources_digest",
    ):
        _digest(snapshot.get(field), code="RAW_PROVIDER_DIGEST_INVALID")

    started = _parse_timestamp(
        snapshot.get("session_started_at"), code="RAW_PROVIDER_SESSION_TIME_INVALID"
    )
    expires = _parse_timestamp(
        snapshot.get("session_expires_at"), code="RAW_PROVIDER_SESSION_TIME_INVALID"
    )
    collected = _parse_timestamp(
        snapshot.get("collected_at"), code="RAW_PROVIDER_SESSION_TIME_INVALID"
    )
    if (
        not started < collected < expires
        or expires - started > MAX_DIRECT_SSO_SESSION
    ):
        _fail("RAW_PROVIDER_SESSION_TIME_INVALID")

    calls = snapshot.get("signed_calls")
    call_keys = {
        "sequence",
        "action",
        "surface",
        "called_at",
        "response_digest",
        "pagination_complete",
    }
    if not isinstance(calls, list) or not calls:
        _fail("RAW_PROVIDER_CALLS_INVALID")
    observed_surfaces: set[str] = set()
    prior_call_at = started
    for sequence, call in enumerate(calls, start=1):
        if not isinstance(call, Mapping) or set(call) != call_keys:
            _fail("RAW_PROVIDER_CALL_FIELDS_INVALID")
        action = call.get("action")
        surface = call.get("surface")
        called_at = _parse_timestamp(
            call.get("called_at"), code="RAW_PROVIDER_CALL_TIME_INVALID"
        )
        if (
            not _exact_integer(call.get("sequence"), sequence)
            or not isinstance(action, str)
            or action not in READ_ONLY_ACTION_ALLOWLIST
            or call.get("pagination_complete") is not True
            or not prior_call_at <= called_at <= collected
        ):
            _fail("RAW_PROVIDER_CALL_INVALID")
        _digest(call.get("response_digest"), code="RAW_PROVIDER_CALL_DIGEST_INVALID")
        if sequence == 1:
            if action != "sts:GetCallerIdentity" or surface is not None:
                _fail("RAW_PROVIDER_STS_FIRST_REQUIRED")
        else:
            if action == "sts:GetCallerIdentity":
                _fail("RAW_PROVIDER_STS_FIRST_REQUIRED")
            if (
                not isinstance(surface, str)
                or surface not in SURFACE_READ_ACTION_ALLOWLIST
                or action not in SURFACE_READ_ACTION_ALLOWLIST[surface]
            ):
                _fail("RAW_PROVIDER_SURFACE_ACTION_INVALID")
            observed_surfaces.add(surface)
        prior_call_at = called_at
    if observed_surfaces != set(SURFACES):
        _fail("RAW_PROVIDER_CALL_SURFACE_SET_INVALID")

    resources = snapshot.get("resource_evidence")
    _validate_raw_resource_evidence(resources)
    if snapshot.get("resources_digest") != canonical_digest(resources):
        _fail("RAW_PROVIDER_RESOURCE_DIGEST_MISMATCH")
    _validate_raw_runtime_evidence(
        snapshot.get("runtime_evidence"),
        session_started_at=_parse_timestamp(
            calls[0]["called_at"], code="RAW_PROVIDER_CALL_TIME_INVALID"
        ),
        collected_at=collected,
    )
    if snapshot.get("raw_provider_digest") != canonical_digest(
        {
            key: item
            for key, item in snapshot.items()
            if key != "raw_provider_digest"
        }
    ):
        _fail("RAW_PROVIDER_DIGEST_MISMATCH")


def certify_raw_provider_sessions(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> dict[str, Any]:
    """Certify stable provider facts collected through two distinct SSO sessions."""

    validate_raw_provider_snapshot(first)
    validate_raw_provider_snapshot(second)
    if (
        first["session_identifier_digest"] == second["session_identifier_digest"]
        or first["account_binding_digest"] != second["account_binding_digest"]
        or _parse_timestamp(second["collected_at"], code="RAW_PROVIDER_SESSION_TIME_INVALID")
        <= _parse_timestamp(first["collected_at"], code="RAW_PROVIDER_SESSION_TIME_INVALID")
    ):
        _fail("RAW_PROVIDER_SESSIONS_NOT_INDEPENDENT")

    runtime_volatile = {"evidence_collected_at", "runtime_evidence_digest"}
    first_facts = {
        "resources": {
            name: first["resource_evidence"][name]["resources"] for name in SURFACES
        },
        "runtime": {
            key: item
            for key, item in first["runtime_evidence"].items()
            if key not in runtime_volatile
        },
    }
    second_facts = {
        "resources": {
            name: second["resource_evidence"][name]["resources"] for name in SURFACES
        },
        "runtime": {
            key: item
            for key, item in second["runtime_evidence"].items()
            if key not in runtime_volatile
        },
    }
    if canonical_digest(first_facts) != canonical_digest(second_facts):
        _fail("RAW_PROVIDER_FACTS_NOT_STABLE")

    result = {
        "record_type": RAW_PROVIDER_STABILITY_RECORD_TYPE,
        "schema_version": 1,
        "first_raw_provider_digest": first["raw_provider_digest"],
        "second_raw_provider_digest": second["raw_provider_digest"],
        "provider_facts_digest": canonical_digest(first_facts),
        "session_source": "DIRECT_SSO",
        "session_count": 2,
        "sts_first_every_session": True,
        "stable": True,
        "aws_mutations": 0,
    }
    result["raw_provider_stability_digest"] = canonical_digest(result)
    return result


def build_inventory_snapshot(
    *,
    source_merge_sha: str,
    source_tree_sha: str,
    account_binding_digest: str,
    management_binding_digest: str,
    caller_identity_digest: str,
    session_identifier_digest: str,
    session_expires_at: datetime,
    collected_at: datetime,
    surfaces: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one private, complete, zero-write snapshot."""

    if _COMMIT.fullmatch(source_merge_sha) is None or _COMMIT.fullmatch(
        source_tree_sha
    ) is None:
        _fail("INVENTORY_SOURCE_BINDING_INVALID")
    for value in (
        account_binding_digest,
        management_binding_digest,
        caller_identity_digest,
        session_identifier_digest,
    ):
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            _fail("INVENTORY_IDENTITY_BINDING_INVALID")
    if set(surfaces) != set(SURFACES):
        _fail("INVENTORY_SURFACE_SET_INVALID")
    normalized_surfaces = canonical_snapshot(
        dict(surfaces), code="INVENTORY_SURFACE_INVALID"
    )
    for name in SURFACES:
        _validate_surface_record(normalized_surfaces[name])

    collected = _timestamp(collected_at, code="INVENTORY_TIME_INVALID")
    expires = _timestamp(session_expires_at, code="INVENTORY_TIME_INVALID")
    if not collected < expires:
        _fail("INVENTORY_SESSION_EXPIRED")
    snapshot = {
        "record_type": RECORD_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "consumer_issue": CONSUMER_ISSUE,
        "environment": "authority-non-production",
        "production": False,
        "deployment_authorized": False,
        "source_merge_sha": source_merge_sha,
        "source_tree_sha": source_tree_sha,
        "region": REGION,
        "account_binding_digest": account_binding_digest,
        "management_binding_digest": management_binding_digest,
        "caller_identity_digest": caller_identity_digest,
        "session_identifier_digest": session_identifier_digest,
        "sts_first": True,
        "session_chained": False,
        "session_expires_at": expires,
        "collected_at": collected,
        "surfaces": normalized_surfaces,
        "aws_calls_complete": True,
        "aws_mutations": 0,
        "production_status": PRODUCTION_STATUS,
    }
    snapshot["inventory_digest"] = canonical_digest(snapshot)
    return snapshot


def validate_inventory_snapshot(snapshot: Mapping[str, Any]) -> None:
    """Validate a snapshot without echoing private values."""

    if not isinstance(snapshot, Mapping):
        _fail("INVENTORY_INVALID")
    expected_keys = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "consumer_issue",
        "environment",
        "production",
        "deployment_authorized",
        "source_merge_sha",
        "source_tree_sha",
        "region",
        "account_binding_digest",
        "management_binding_digest",
        "caller_identity_digest",
        "session_identifier_digest",
        "sts_first",
        "session_chained",
        "session_expires_at",
        "collected_at",
        "surfaces",
        "aws_calls_complete",
        "aws_mutations",
        "production_status",
        "inventory_digest",
    }
    if set(snapshot) != expected_keys:
        _fail("INVENTORY_FIELDS_INVALID")
    if any(
        (
            snapshot.get("record_type") != RECORD_TYPE,
            snapshot.get("schema_version") != 1,
            snapshot.get("implementation_issue") != IMPLEMENTATION_ISSUE,
            snapshot.get("consumer_issue") != CONSUMER_ISSUE,
            snapshot.get("environment") != "authority-non-production",
            snapshot.get("production") is not False,
            snapshot.get("deployment_authorized") is not False,
            snapshot.get("region") != REGION,
            snapshot.get("sts_first") is not True,
            snapshot.get("session_chained") is not False,
            snapshot.get("aws_calls_complete") is not True,
            snapshot.get("aws_mutations") != 0,
            snapshot.get("production_status") != PRODUCTION_STATUS,
        )
    ):
        _fail("INVENTORY_CONSTANT_INVALID")
    expected_digest = canonical_digest(
        {key: item for key, item in snapshot.items() if key != "inventory_digest"}
    )
    if snapshot.get("inventory_digest") != expected_digest:
        _fail("INVENTORY_DIGEST_MISMATCH")
    surfaces = snapshot.get("surfaces")
    if not isinstance(surfaces, Mapping) or set(surfaces) != set(SURFACES):
        _fail("INVENTORY_SURFACE_SET_INVALID")
    for surface in surfaces.values():
        _validate_surface_record(surface)


def certify_stable_inventory(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> dict[str, Any]:
    """Require two independent snapshots with identical provider facts."""

    validate_inventory_snapshot(first)
    validate_inventory_snapshot(second)
    volatile = {
        "collected_at",
        "session_expires_at",
        "caller_identity_digest",
        "session_identifier_digest",
        "inventory_digest",
    }
    first_facts = {key: item for key, item in first.items() if key not in volatile}
    second_facts = {key: item for key, item in second.items() if key not in volatile}
    if canonical_digest(first_facts) != canonical_digest(second_facts):
        _fail("INVENTORY_NOT_STABLE")
    result = {
        "record_type": STABILITY_RECORD_TYPE,
        "schema_version": 1,
        "first_inventory_digest": first["inventory_digest"],
        "second_inventory_digest": second["inventory_digest"],
        "provider_facts_digest": canonical_digest(first_facts),
        "stable": True,
        "snapshot_count": 2,
        "aws_mutations": 0,
    }
    result["stable_inventory_digest"] = canonical_digest(result)
    return result


def certify_stable_inventory_provider_transcripts(
    *,
    inventory: Mapping[str, Any],
    first_raw_provider_snapshot: Mapping[str, Any],
    second_raw_provider_snapshot: Mapping[str, Any],
    execution_trust_anchor: Mapping[str, Any],
    verifier: ProviderInventoryTranscriptVerifier,
    first_transcript_receipt: Mapping[str, Any],
    second_transcript_receipt: Mapping[str, Any],
    evaluated_at: datetime,
) -> dict[str, Any]:
    """Fail closed until the out-of-repository live verifier is implemented.

    A serialized digest-only inventory cannot authenticate its own provider
    provenance.  The future live orchestrator must consume both raw snapshots,
    both opaque receipts and the out-of-band trust anchor in one private call;
    this repository deliberately exposes no promotion path.
    """

    _fail("STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED")

    try:
        from tooling.platform_authority_gug365_upstream_prerequisites import (
            UpstreamPrerequisiteError,
            validate_execution_trust_anchor,
            validate_provider_transcript_verification,
            validate_stable_inventory,
        )

        validate_stable_inventory(inventory)
        validate_execution_trust_anchor(execution_trust_anchor)
    except (ImportError, UpstreamPrerequisiteError):
        _fail("INVENTORY_PROVIDER_TRUST_CONTRACT_INVALID")
    validate_raw_provider_snapshot(first_raw_provider_snapshot)
    validate_raw_provider_snapshot(second_raw_provider_snapshot)
    if (
        inventory.get("provider_transcript_verified") is not False
        or inventory.get("evidence_origin")
        != "REPOSITORY_OBSERVED_UNATTESTED"
        or inventory.get("provider_transcript_verification_digests") != []
        or inventory.get("provider_verifier_identity_digest") is not None
        or inventory.get("provider_attestation_root_digest") is not None
        or first_raw_provider_snapshot["raw_provider_digest"]
        != inventory.get("first_snapshot_digest")
        or second_raw_provider_snapshot["raw_provider_digest"]
        != inventory.get("second_snapshot_digest")
        or first_raw_provider_snapshot["account_binding_digest"]
        != inventory.get("account_binding_digest")
        or second_raw_provider_snapshot["account_binding_digest"]
        != inventory.get("account_binding_digest")
        or first_raw_provider_snapshot["caller_identity_digest"]
        != inventory.get("caller_identity_digest")
        or second_raw_provider_snapshot["caller_identity_digest"]
        != inventory.get("caller_identity_digest")
        or first_raw_provider_snapshot["session_identifier_digest"]
        == second_raw_provider_snapshot["session_identifier_digest"]
    ):
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_INPUT_BINDING_INVALID")
    identity = getattr(verifier, "identity_digest", None)
    verify = getattr(verifier, "verify", None)
    if not callable(identity) or not callable(verify):
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_VERIFIER_REQUIRED")
    try:
        verifier_identity_digest = identity()
    except Exception:
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_VERIFIER_IDENTITY_INVALID")
    if (
        not isinstance(verifier_identity_digest, str)
        or _DIGEST.fullmatch(verifier_identity_digest) is None
        or verifier_identity_digest
        != execution_trust_anchor.get("executor_session_verifier_identity_digest")
    ):
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_VERIFIER_IDENTITY_INVALID")
    evaluation = _timestamp(
        evaluated_at, code="INVENTORY_PROVIDER_TRANSCRIPT_TIME_INVALID"
    )
    evaluation_time = _parse_timestamp(
        evaluation, code="INVENTORY_PROVIDER_TRANSCRIPT_TIME_INVALID"
    )
    verified_records: list[dict[str, Any]] = []
    for raw_snapshot, opaque_receipt in (
        (first_raw_provider_snapshot, first_transcript_receipt),
        (second_raw_provider_snapshot, second_transcript_receipt),
    ):
        if not isinstance(opaque_receipt, Mapping):
            _fail("INVENTORY_PROVIDER_TRANSCRIPT_RECEIPT_INVALID")
        try:
            record = dict(
                verify(
                    stage="INVENTORY",
                    transcript_receipt=opaque_receipt,
                    raw_provider_snapshot=raw_snapshot,
                    evaluated_at=evaluated_at,
                )
            )
            validate_provider_transcript_verification(record)
        except Exception:
            _fail("INVENTORY_PROVIDER_TRANSCRIPT_VERIFICATION_FAILED")
        verified_at = _parse_timestamp(
            record.get("verified_at"),
            code="INVENTORY_PROVIDER_TRANSCRIPT_TIME_INVALID",
        )
        collected_at = _parse_timestamp(
            raw_snapshot["collected_at"],
            code="INVENTORY_PROVIDER_TRANSCRIPT_TIME_INVALID",
        )
        if (
            record["stage"] != "INVENTORY"
            or record["evidence_origin"] != "EXTERNALLY_ATTESTED_PROVIDER"
            or record["verifier_identity_digest"] != verifier_identity_digest
            or record["attestation_root_digest"]
            != execution_trust_anchor.get(
                "executor_session_attestation_root_digest"
            )
            or record["session_identifier_digest"]
            != raw_snapshot["session_identifier_digest"]
            or record["account_or_management_binding_digest"]
            != inventory["account_binding_digest"]
            or record["caller_identity_digest"]
            != inventory["caller_identity_digest"]
            or record["region"] != REGION
            or record["raw_provider_digest"]
            != raw_snapshot["raw_provider_digest"]
            or not collected_at <= verified_at <= evaluation_time
        ):
            _fail("INVENTORY_PROVIDER_TRANSCRIPT_BINDING_INVALID")
        verified_records.append(record)
    if (
        verified_records[0]["verification_digest"]
        == verified_records[1]["verification_digest"]
        or verified_records[0]["session_identifier_digest"]
        == verified_records[1]["session_identifier_digest"]
        or verified_records[0]["attestation_root_digest"]
        != verified_records[1]["attestation_root_digest"]
    ):
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_INDEPENDENCE_INVALID")
    result = canonical_snapshot(
        inventory, code="INVENTORY_PROVIDER_TRANSCRIPT_INPUT_INVALID"
    )
    result["evidence_origin"] = "EXTERNALLY_ATTESTED_PROVIDER"
    result["provider_transcript_verified"] = True
    result["provider_transcript_verification_digests"] = [
        record["verification_digest"] for record in verified_records
    ]
    result["provider_verifier_identity_digest"] = verifier_identity_digest
    result["provider_attestation_root_digest"] = verified_records[0][
        "attestation_root_digest"
    ]
    result["inventory_digest"] = canonical_digest(
        {key: value for key, value in result.items() if key != "inventory_digest"}
    )
    try:
        validate_stable_inventory(result)
    except UpstreamPrerequisiteError:
        _fail("INVENTORY_PROVIDER_TRANSCRIPT_RESULT_INVALID")
    return result
