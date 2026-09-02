"""Pure transcript contract for the GUG-376 retained-name collision gate."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)


REGION = "us-east-1"
MAX_PAGES = 32
TRANSCRIPT_SUMMARY_TYPE = (
    "scanalyze.platform_authority."
    "gug376_route_collision_transcript_summary.v1"
)
TRANSCRIPT_SIDECAR_TYPE = (
    "scanalyze.platform_authority."
    "gug376_route_collision_transcript_sidecar.v1"
)
COLLISION_PROVIDER_IMPLEMENTATION_DIGEST = canonical_digest(
    {
        "implementation": (
            "tooling.platform_authority_gug376_collision_aws_provider"
        ),
        "contract": "gug376-route-collision-provider-v1",
        "schema_version": 1,
    }
)

READ_ONLY_OPERATION_ALLOWLIST = frozenset(
    {
        "sts:GetCallerIdentity",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackResource",
        "cloudformation:ListStacks",
        "dynamodb:DescribeTable",
        "dynamodb:ListTagsOfResource",
        "iam:GetRole",
        "iam:ListRoleTags",
        "kms:ListAliases",
        "kms:ListResourceTags",
        "lambda:GetAlias",
        "lambda:GetFunction",
        "lambda:ListAliases",
        "lambda:ListFunctions",
        "lambda:ListTags",
        "logs:DescribeLogGroups",
        "logs:ListTagsForResource",
        "s3:GetBucketTagging",
        "s3:ListAllMyBuckets",
        "signer:GetSigningProfile",
        "signer:ListSigningProfiles",
        "signer:ListTagsForResource",
        "sso:DescribeApplication",
        "sso:DescribePermissionSet",
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListPermissionSets",
        "sso:ListTagsForResource",
    }
)
READ_ONLY_OUTCOMES = frozenset({"SUCCESS", "NOT_FOUND"})

TARGET_INVENTORY_OPERATIONS: Mapping[
    tuple[str, str], tuple[frozenset[str], ...]
] = {
    ("cloudformation", "stack"): (
        frozenset(
            {
                "cloudformation:DescribeStacks",
                "cloudformation:ListStacks",
            }
        ),
    ),
    ("dynamodb", "table"): (frozenset({"dynamodb:DescribeTable"}),),
    ("iam", "role"): (frozenset({"iam:GetRole"}),),
    ("kms", "alias"): (frozenset({"kms:ListAliases"}),),
    ("lambda", "alias"): (
        frozenset({"lambda:GetAlias", "lambda:ListAliases"}),
    ),
    ("lambda", "code_signing_config"): (
        frozenset({"cloudformation:DescribeStackResource"}),
    ),
    ("lambda", "function"): (
        frozenset({"lambda:GetFunction", "lambda:ListFunctions"}),
    ),
    ("logs", "log_group"): (frozenset({"logs:DescribeLogGroups"}),),
    ("s3", "bucket"): (frozenset({"s3:ListAllMyBuckets"}),),
    ("signer", "signing_profile"): (
        frozenset(
            {
                "signer:GetSigningProfile",
                "signer:ListSigningProfiles",
            }
        ),
    ),
    ("sso", "application"): (
        frozenset({"sso:DescribeApplication", "sso:ListApplications"}),
    ),
    ("sso", "permission_set"): (
        frozenset(
            {
                "sso:DescribePermissionSet",
                "sso:ListPermissionSets",
            }
        ),
    ),
}
TARGET_OWNERSHIP_OPERATIONS: Mapping[str, frozenset[str]] = {
    "cloudformation": frozenset({"cloudformation:DescribeStacks"}),
    "dynamodb": frozenset({"dynamodb:ListTagsOfResource"}),
    "iam": frozenset({"iam:ListRoleTags"}),
    "kms": frozenset({"kms:ListResourceTags"}),
    "lambda": frozenset({"lambda:ListTags"}),
    "logs": frozenset({"logs:ListTagsForResource"}),
    "s3": frozenset({"s3:GetBucketTagging"}),
    "signer": frozenset({"signer:ListTagsForResource"}),
    "sso": frozenset({"sso:ListTagsForResource"}),
}
LIST_DISCOVERY_OPERATIONS = frozenset(
    {
        "cloudformation:ListStacks",
        "kms:ListAliases",
        "lambda:ListAliases",
        "lambda:ListFunctions",
        "logs:DescribeLogGroups",
        "s3:ListAllMyBuckets",
        "signer:ListSigningProfiles",
        "sso:ListApplications",
        "sso:ListInstances",
        "sso:ListPermissionSets",
    }
)

EVENT_FIELDS = frozenset(
    {
        "ordinal",
        "capture_index",
        "domain",
        "account_id",
        "region",
        "session_digest",
        "provider_implementation_digest",
        "operation",
        "outcome",
        "request_digest",
        "operation_request_digest",
        "page_index",
        "input_cursor_digest",
        "response_projection",
        "response_digest",
        "target_ids",
        "read_only",
        "aws_mutations",
    }
)
RESPONSE_PROJECTION_FIELDS = frozenset(
    {
        "page_item_digests",
        "output_cursor_digest",
        "page_complete",
        "target_evidence_digests",
    }
)
SUMMARY_FIELDS = frozenset(
    {
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
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class CollisionTranscriptContractError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CollisionTranscriptContractError(code)


def _copy(value: object, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception:
        raise CollisionTranscriptContractError(code) from None


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _catalog_targets(request: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    catalog = request.get("catalog")
    targets = catalog.get("targets") if isinstance(catalog, Mapping) else None
    if not isinstance(targets, list):
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    by_id: dict[str, Mapping[str, Any]] = {}
    for target in targets:
        if not isinstance(target, Mapping):
            _fail("ROUTE_COLLISION_CATALOG_INVALID")
        target_id = target.get("target_id")
        if not isinstance(target_id, str) or target_id in by_id:
            _fail("ROUTE_COLLISION_CATALOG_INVALID")
        by_id[target_id] = target
    if not by_id:
        _fail("ROUTE_COLLISION_CATALOG_INVALID")
    return by_id


def operation_request_descriptor(
    *,
    request: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the exact logical call descriptor from trusted request fields."""

    targets = _catalog_targets(request)
    target_ids = event.get("target_ids")
    if not isinstance(target_ids, list) or any(
        not isinstance(target_id, str) or target_id not in targets
        for target_id in target_ids
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    descriptors = [_copy(targets[target_id], "ROUTE_COLLISION_CATALOG_INVALID") for target_id in target_ids]
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug376_route_collision_operation_request.v1"
        ),
        "schema_version": 1,
        "route_request_digest": request.get("request_digest"),
        "catalog_digest": request.get("catalog_digest"),
        "capture_index": event.get("capture_index"),
        "domain": event.get("domain"),
        "account_id": event.get("account_id"),
        "region": event.get("region"),
        "session_digest": event.get("session_digest"),
        "provider_implementation_digest": event.get(
            "provider_implementation_digest"
        ),
        "operation": event.get("operation"),
        "page_index": event.get("page_index"),
        "input_cursor_digest": event.get("input_cursor_digest"),
        "target_descriptors": descriptors,
    }


def _required_groups(target: Mapping[str, Any]) -> tuple[frozenset[str], ...]:
    service = str(target.get("service"))
    scope = str(target.get("scope"))
    selector = target.get("selector")
    selector_kind = selector.get("kind") if isinstance(selector, Mapping) else None
    if (
        scope == "code_signing_config"
        and selector_kind
        in {
            "cloudformation_stack_resource",
            "cloudformation_ownership_tags",
        }
    ):
        # Both generated-id selector variants are discovered through the exact
        # catalog stack/logical-resource pair.  The policy contract grants this
        # call only on those catalog-named stack ARNs.
        return (frozenset({"cloudformation:DescribeStackResource"}),)
    return TARGET_INVENTORY_OPERATIONS.get((service, scope), ())


def _ownership_operations(target: Mapping[str, Any]) -> frozenset[str]:
    selector = target.get("selector")
    if (
        isinstance(selector, Mapping)
        and selector.get("kind") == "cloudformation_stack_resource"
    ):
        # The stack resource itself is the ownership boundary when the
        # generated resource has no independent ownership-tag contract.
        return frozenset({"cloudformation:DescribeStackResource"})
    if (
        isinstance(selector, Mapping)
        and selector.get("kind") == "cloudformation_ownership_tags"
    ):
        # DescribeStackResource binds the generated physical ARN; ListTags on
        # that exact ARN separately proves the catalog's ownership tag set.
        return frozenset({"lambda:ListTags"})
    return TARGET_OWNERSHIP_OPERATIONS.get(
        str(target.get("service")), frozenset()
    )


def _validate_event_shape(
    event: object,
    *,
    ordinal: int,
    capture_index: int,
    request: Mapping[str, Any],
    identities: Mapping[str, Mapping[str, Any]],
    targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(event, Mapping) or set(event) != EVENT_FIELDS:
        _fail("ROUTE_COLLISION_TRANSCRIPT_FIELDS_INVALID")
    value = dict(event)
    domain = value.get("domain")
    operation = value.get("operation")
    identity = identities.get(str(domain))
    target_ids = value.get("target_ids")
    projection = value.get("response_projection")
    if not isinstance(target_ids, list) or any(
        not isinstance(target_id, str) for target_id in target_ids
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if len(set(target_ids)) != len(target_ids) or target_ids != sorted(target_ids):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if not isinstance(projection, Mapping) or set(projection) != RESPONSE_PROJECTION_FIELDS:
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    item_digests = projection.get("page_item_digests")
    evidence_digests = projection.get("target_evidence_digests")
    input_cursor = value.get("input_cursor_digest")
    output_cursor = projection.get("output_cursor_digest")
    if (
        not isinstance(item_digests, list)
        or item_digests != sorted(set(item_digests))
        or any(_DIGEST.fullmatch(str(item)) is None for item in item_digests)
        or not isinstance(evidence_digests, Mapping)
        or any(
            not isinstance(key, str)
            or key not in target_ids
            or _DIGEST.fullmatch(str(digest)) is None
            for key, digest in evidence_digests.items()
        )
        or input_cursor is not None
        and _DIGEST.fullmatch(str(input_cursor)) is None
        or output_cursor is not None
        and _DIGEST.fullmatch(str(output_cursor)) is None
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if (
        type(value.get("ordinal")) is not int
        or value.get("ordinal") != ordinal
        or type(value.get("capture_index")) is not int
        or value.get("capture_index") != capture_index
        or domain not in identities
        or not isinstance(identity, Mapping)
        or value.get("account_id") != identity.get("account_id")
        or value.get("region") != REGION
        or value.get("session_digest") != identity.get("session_digest")
        or value.get("provider_implementation_digest")
        != COLLISION_PROVIDER_IMPLEMENTATION_DIGEST
        or operation not in READ_ONLY_OPERATION_ALLOWLIST
        or value.get("outcome") not in READ_ONLY_OUTCOMES
        or value.get("request_digest") != request.get("request_digest")
        or type(value.get("page_index")) is not int
        or not 1 <= value["page_index"] <= MAX_PAGES
        or projection.get("page_complete") not in {True, False}
        or (projection.get("page_complete") is True) != (output_cursor is None)
        or value.get("read_only") is not True
        or type(value.get("aws_mutations")) is not int
        or value.get("aws_mutations") != 0
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if any(
        target_id not in targets
        or targets[target_id].get("domain") != domain
        or targets[target_id].get("account_id") != value.get("account_id")
        or targets[target_id].get("region") != value.get("region")
        for target_id in target_ids
    ):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if operation == "sts:GetCallerIdentity":
        if (
            target_ids
            or value.get("outcome") != "SUCCESS"
            or value.get("page_index") != 1
            or input_cursor is not None
            or output_cursor is not None
            or projection.get("page_complete") is not True
            or item_digests
            or evidence_digests
        ):
            _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    elif not target_ids:
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if value.get("operation_request_digest") != canonical_digest(
        operation_request_descriptor(request=request, event=value)
    ):
        _fail("ROUTE_COLLISION_OPERATION_REQUEST_BINDING_INVALID")
    if value.get("response_digest") != canonical_digest(projection):
        _fail("ROUTE_COLLISION_RESPONSE_BINDING_INVALID")
    return value


def _validate_streams(
    events: Sequence[Mapping[str, Any]],
    *,
    snapshots: Sequence[Mapping[str, Any]],
    targets: Mapping[str, Mapping[str, Any]],
) -> None:
    for capture_index, snapshot in enumerate(snapshots, 1):
        observations = snapshot.get("target_observations")
        if not isinstance(observations, Mapping):
            _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
        segment = [
            event
            for event in events
            if event.get("capture_index") == capture_index
        ]
        streams: dict[tuple[str, str, tuple[str, ...]], list[Mapping[str, Any]]] = {}
        for event in segment:
            if event["operation"] == "sts:GetCallerIdentity":
                continue
            key = (
                str(event["domain"]),
                str(event["operation"]),
                tuple(event["target_ids"]),
            )
            streams.setdefault(key, []).append(event)
        completed_by_target: dict[str, list[tuple[str, str]]] = {
            target_id: [] for target_id in targets
        }
        for (_domain, operation, target_ids), stream in streams.items():
            if [event["page_index"] for event in stream] != list(
                range(1, len(stream) + 1)
            ):
                _fail("ROUTE_COLLISION_PAGINATION_INVALID")
            previous_output: str | None = None
            for index, event in enumerate(stream):
                projection = event["response_projection"]
                if event["input_cursor_digest"] != previous_output:
                    _fail("ROUTE_COLLISION_PAGINATION_INVALID")
                if index < len(stream) - 1 and projection["page_complete"] is not False:
                    _fail("ROUTE_COLLISION_PAGINATION_INVALID")
                previous_output = projection["output_cursor_digest"]
            final = stream[-1]
            final_projection = final["response_projection"]
            if final_projection["page_complete"] is not True:
                _fail("ROUTE_COLLISION_PAGINATION_INCOMPLETE")
            if operation not in LIST_DISCOVERY_OPERATIONS and len(stream) != 1:
                _fail("ROUTE_COLLISION_PAGINATION_INVALID")
            expected_evidence = {
                target_id: canonical_digest(observations[target_id])
                for target_id in target_ids
            }
            if final_projection["target_evidence_digests"] != expected_evidence:
                _fail("ROUTE_COLLISION_RESPONSE_BINDING_INVALID")
            if any(
                event["response_projection"]["target_evidence_digests"]
                for event in stream[:-1]
            ):
                _fail("ROUTE_COLLISION_RESPONSE_BINDING_INVALID")
            for target_id in target_ids:
                completed_by_target[target_id].append(
                    (operation, str(final["outcome"]))
                )
        for target_id, target in targets.items():
            observation = observations.get(target_id)
            if not isinstance(observation, Mapping):
                _fail("ROUTE_COLLISION_TARGET_EVIDENCE_INVALID")
            disposition = observation.get("disposition")
            expected_outcome = (
                "SUCCESS" if disposition == "PRESENT_OWNED" else "NOT_FOUND"
            )
            completed = completed_by_target[target_id]
            required_groups = _required_groups(target)
            if not required_groups:
                _fail("ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID")
            for alternatives in required_groups:
                matching = [
                    (operation, outcome)
                    for operation, outcome in completed
                    if operation in alternatives
                ]
                if not matching or any(
                    outcome
                    != (
                        "SUCCESS"
                        if operation in LIST_DISCOVERY_OPERATIONS
                        else expected_outcome
                    )
                    for operation, outcome in matching
                ):
                    _fail("ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID")
            ownership = _ownership_operations(target)
            discovery = frozenset().union(*required_groups)
            if disposition == "PRESENT_OWNED":
                if not ownership or not any(
                    operation in ownership and outcome == "SUCCESS"
                    for operation, outcome in completed
                ):
                    _fail("ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID")
            elif any(
                operation in ownership - discovery for operation, _outcome in completed
            ):
                _fail("ROUTE_COLLISION_INVENTORY_COVERAGE_INVALID")


def validate_route_collision_transcript_bundle(
    *,
    events: object,
    summary: object,
    request: Mapping[str, Any],
    snapshots: Sequence[Mapping[str, Any]],
) -> None:
    """Validate provenance, pagination, coverage, and snapshot bindings."""

    checked_events = _copy(events, "ROUTE_COLLISION_TRANSCRIPT_INVALID")
    checked_summary = _copy(summary, "ROUTE_COLLISION_CALL_SUMMARY_INVALID")
    if not isinstance(checked_events, list) or not checked_events:
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    if not isinstance(checked_summary, Mapping) or set(checked_summary) != SUMMARY_FIELDS:
        _fail("ROUTE_COLLISION_CALL_SUMMARY_INVALID")
    if len(snapshots) != 3:
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    targets = _catalog_targets(request)
    checked: list[dict[str, Any]] = []
    first_domain_operation: dict[tuple[int, str], str] = {}
    identity_counts: dict[tuple[int, str], int] = {}
    for ordinal, event in enumerate(checked_events, 1):
        capture_index = event.get("capture_index") if isinstance(event, Mapping) else None
        if type(capture_index) is not int or capture_index not in {1, 2, 3}:
            _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
        snapshot = snapshots[capture_index - 1]
        identities = snapshot.get("identities") if isinstance(snapshot, Mapping) else None
        if not isinstance(identities, Mapping):
            _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
        value = _validate_event_shape(
            event,
            ordinal=ordinal,
            capture_index=capture_index,
            request=request,
            identities=identities,
            targets=targets,
        )
        key = (capture_index, str(value["domain"]))
        first_domain_operation.setdefault(key, str(value["operation"]))
        if value["operation"] == "sts:GetCallerIdentity":
            identity_counts[key] = identity_counts.get(key, 0) + 1
        checked.append(value)
    expected_identity_keys = {
        (capture_index, domain)
        for capture_index in (1, 2, 3)
        for domain in ("authority", "management")
    }
    if (
        set(first_domain_operation) != expected_identity_keys
        or any(
            operation != "sts:GetCallerIdentity"
            for operation in first_domain_operation.values()
        )
        or identity_counts != {key: 1 for key in expected_identity_keys}
    ):
        _fail("ROUTE_COLLISION_IDENTITY_CALL_ORDER_INVALID")
    offset = 0
    for capture_index, snapshot in enumerate(snapshots, 1):
        segment = [
            event for event in checked if event["capture_index"] == capture_index
        ]
        if not segment or checked[offset : offset + len(segment)] != segment:
            _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
        if canonical_digest(segment) != snapshot.get("transcript_digest"):
            _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
        offset += len(segment)
    if offset != len(checked):
        _fail("ROUTE_COLLISION_TRANSCRIPT_INVALID")
    _validate_streams(checked, snapshots=snapshots, targets=targets)
    if (
        checked_summary.get("record_type") != TRANSCRIPT_SUMMARY_TYPE
        or checked_summary.get("schema_version") != 1
        or checked_summary.get("request_digest") != request.get("request_digest")
        or checked_summary.get("snapshot_count") != 3
        or checked_summary.get("provider_calls") != len(checked)
        or checked_summary.get("aws_calls") != len(checked)
        or checked_summary.get("aws_mutations") != 0
        or checked_summary.get("read_only") is not True
        or checked_summary.get("transcript_digest") != canonical_digest(checked)
    ):
        _fail("ROUTE_COLLISION_CALL_SUMMARY_INVALID")


__all__ = [
    "COLLISION_PROVIDER_IMPLEMENTATION_DIGEST",
    "CollisionTranscriptContractError",
    "EVENT_FIELDS",
    "LIST_DISCOVERY_OPERATIONS",
    "MAX_PAGES",
    "READ_ONLY_OPERATION_ALLOWLIST",
    "RESPONSE_PROJECTION_FIELDS",
    "SUMMARY_FIELDS",
    "TARGET_INVENTORY_OPERATIONS",
    "TARGET_OWNERSHIP_OPERATIONS",
    "TRANSCRIPT_SIDECAR_TYPE",
    "TRANSCRIPT_SUMMARY_TYPE",
    "operation_request_descriptor",
    "validate_route_collision_transcript_bundle",
]
