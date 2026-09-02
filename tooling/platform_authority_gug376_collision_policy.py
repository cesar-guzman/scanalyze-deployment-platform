"""Closed IAM policy construction for the GUG-376 collision catalog.

The catalog contains both deterministic resource names and resources whose ARN
contains an identifier assigned by AWS.  This module therefore emits two
strictly separated policy stages:

* ``inventory`` grants only the list-class calls that cannot be resource
  scoped plus exact reads for resources whose ARN is derived from the catalog;
* ``candidate_detail`` is optional and grants detail reads only for finite,
  exact ARNs rederived from a closed, complete discovery-evidence contract.

No allow statement uses a wildcard resource except ``sts:GetCallerIdentity``,
AWS list-class operations that do not have a usable catalog-derived ARN, and
the AWS-assigned suffix of an exact catalog-named CloudFormation stack ARN.
Every such exception is recorded in the sealed policy-set object.  Explicit
deny statements cover every resource by design and a NotAction boundary denies
every mutation and every other unreviewed action.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from hashlib import sha256
import json
import re
from typing import Any

from tooling import platform_authority_gug376_collision_catalog as catalog_contract


SCHEMA_VERSION = 1
RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_route_collision_policy_set.v1"
)
DISCOVERY_EVIDENCE_RECORD_TYPE = (
    "scanalyze.platform_authority."
    "gug376_route_collision_discovery_evidence.v1"
)
IAM_VERSION = "2012-10-17"
DOMAINS = ("authority", "management")
MAX_IAM_POLICY_CHARS = 10_240
MAX_DISCOVERY_PAGES = 32

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARN_SAFE = re.compile(r"^[A-Za-z0-9+=,.@_:/-]+$")
_DYNAMIC_RESOURCE_KINDS = {
    "authority": frozenset(
        {
            "cloudformation_stack",
            "kms_key",
            "lambda_code_signing_config",
        }
    ),
    "management": frozenset(
        {
            "cloudformation_stack",
            "identity_center_kms_key",
            "sso_application",
            "sso_instance",
            "sso_permission_set",
        }
    ),
}
_DISCOVERY_OPERATIONS = {
    "cloudformation_stack": "cloudformation:ListStacks",
    "kms_key": "kms:ListAliases",
    "lambda_code_signing_config": "cloudformation:DescribeStackResource",
    "identity_center_kms_key": (
        "gug393:MaterializePrivateIdentityCenterKmsKey"
    ),
    "sso_application": "sso:ListApplications",
    "sso_instance": "sso:ListInstances",
    "sso_permission_set": "sso:ListPermissionSets",
}
_MAX_CANDIDATES_PER_KIND = 512

_TOP_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "catalog_digest",
        "source_commit_sha",
        "source_tree_sha",
        "authority_account_id",
        "management_account_id",
        "region",
        "not_before",
        "expires_at",
        "target_count",
        "identity_center_instance_arn",
        "target_coverage",
        "stage",
        "discovery_evidence",
        "candidate_resources",
        "candidate_resources_digest",
        "discovery_evidence_digest",
        "discovery_provenance_digest",
        "policies",
        "policy_digests",
        "allowed_actions",
        "wildcard_resource_exceptions",
        "read_only",
        "aws_mutations",
        "policy_set_digest",
    }
)
_DISCOVERY_EVIDENCE_FIELDS = frozenset(
    {"schema_version", "record_type", "catalog_digest", "domains"}
)
_DISCOVERY_GROUP_FIELDS = frozenset({"operation", "selector", "pages"})
_DISCOVERY_PAGE_FIELDS = frozenset(
    {
        "page_index",
        "input_cursor_digest",
        "output_cursor_digest",
        "items",
    }
)
_COVERAGE_FIELDS = frozenset(
    {
        "target_id",
        "domain",
        "account_id",
        "region",
        "service",
        "scope",
        "inventory_actions",
        "detail_actions",
        "exact_resources",
        "deferred_resource_kinds",
    }
)
_EXCEPTION_FIELDS = frozenset(
    {
        "domain",
        "stage",
        "statement_sid",
        "actions",
        "resource",
        "reason_code",
    }
)


class CollisionPolicyError(ValueError):
    """Stable fail-closed policy construction error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise CollisionPolicyError(code)


def canonical_json(value: Any) -> str:
    """Return the sole JSON representation accepted by policy digests."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CollisionPolicyError("COLLISION_POLICY_JSON_INVALID") from error


def canonical_digest(value: Any) -> str:
    """Digest one JSON-compatible value with an algorithm prefix."""

    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _condition(
    *,
    account_id: str,
    not_before: str,
    expires_at: str,
    regional: bool,
    sso: bool = False,
    resource_account: bool = False,
) -> dict[str, Any]:
    equals: dict[str, str] = {"aws:PrincipalAccount": account_id}
    if regional:
        equals["aws:RequestedRegion"] = catalog_contract.REGION
    if sso:
        equals["sso:PrimaryRegion"] = catalog_contract.REGION
    if resource_account:
        equals["aws:ResourceAccount"] = account_id
    return {
        "StringEquals": equals,
        "DateGreaterThanEquals": {"aws:CurrentTime": not_before},
        "DateLessThan": {"aws:CurrentTime": expires_at},
    }


def _role_arn(account_id: str, name: str) -> str:
    return f"arn:aws:iam::{account_id}:role/{name}"


def _resource_arn(target: Mapping[str, Any]) -> str | None:
    """Return a wildcard-free ARN when the catalog fully determines it."""

    account_id = target["account_id"]
    region = target["region"]
    service = target["service"]
    scope = target["scope"]
    name = target["name"]
    if (service, scope) == ("dynamodb", "table"):
        return f"arn:aws:dynamodb:{region}:{account_id}:table/{name}"
    if (service, scope) == ("iam", "role"):
        return _role_arn(account_id, name)
    if (service, scope) == ("lambda", "function"):
        return f"arn:aws:lambda:{region}:{account_id}:function:{name}"
    if (service, scope) == ("lambda", "alias"):
        selector = target["selector"]
        return (
            f"arn:aws:lambda:{region}:{account_id}:function:"
            f"{selector['function_name']}:{selector['alias_name']}"
        )
    if (service, scope) == ("logs", "log_group"):
        return f"arn:aws:logs:{region}:{account_id}:log-group:{name}"
    if (service, scope) == ("s3", "bucket"):
        return f"arn:aws:s3:::{name}"
    if (service, scope) == ("signer", "signing_profile"):
        return f"arn:aws:signer:{region}:{account_id}:/signing-profiles/{name}"
    return None


def _action_contract(target: Mapping[str, Any]) -> tuple[
    tuple[str, ...], tuple[str, ...], tuple[str, ...]
]:
    """Return inventory actions, detail actions and deferred ARN kinds."""

    key = (target["service"], target["scope"])
    contracts: dict[
        tuple[str, str], tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]
    ] = {
        ("cloudformation", "stack"): (
            ("cloudformation:ListStacks",),
            ("cloudformation:DescribeStacks",),
            ("cloudformation_stack",),
        ),
        ("dynamodb", "table"): (
            (),
            ("dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"),
            (),
        ),
        ("iam", "role"): (
            (),
            ("iam:GetRole", "iam:ListRoleTags"),
            (),
        ),
        ("kms", "alias"): (
            ("kms:ListAliases",),
            ("kms:DescribeKey", "kms:ListResourceTags"),
            ("kms_key",),
        ),
        ("lambda", "alias"): (
            (),
            ("lambda:GetAlias",),
            (),
        ),
        ("lambda", "code_signing_config"): (
            ("cloudformation:DescribeStackResource",),
            ("lambda:ListTags",),
            ("lambda_code_signing_config",),
        ),
        ("lambda", "function"): (
            (),
            ("lambda:GetFunction", "lambda:ListTags"),
            (),
        ),
        ("logs", "log_group"): (
            ("logs:DescribeLogGroups",),
            ("logs:ListTagsForResource",),
            (),
        ),
        ("s3", "bucket"): (
            ("s3:ListAllMyBuckets",),
            ("s3:GetBucketTagging",),
            (),
        ),
        ("signer", "signing_profile"): (
            ("signer:ListSigningProfiles",),
            ("signer:GetSigningProfile", "signer:ListTagsForResource"),
            (),
        ),
        ("sso", "application"): (
            ("sso:ListApplications", "sso:ListInstances"),
            ("sso:DescribeApplication", "sso:ListTagsForResource"),
            (
                "identity_center_kms_key",
                "sso_application",
                "sso_instance",
            ),
        ),
        ("sso", "permission_set"): (
            ("sso:ListInstances", "sso:ListPermissionSets"),
            ("sso:DescribePermissionSet", "sso:ListTagsForResource"),
            (
                "identity_center_kms_key",
                "sso_instance",
                "sso_permission_set",
            ),
        ),
    }
    try:
        return contracts[key]
    except KeyError as error:
        raise CollisionPolicyError("COLLISION_POLICY_TARGET_UNSUPPORTED") from error


def _target_coverage(catalog: Mapping[str, Any]) -> list[dict[str, Any]]:
    coverage: list[dict[str, Any]] = []
    for target in catalog["targets"]:
        inventory, detail, deferred = _action_contract(target)
        exact = _resource_arn(target)
        if exact is None and not deferred:
            _fail("COLLISION_POLICY_TARGET_UNBOUND")
        coverage.append(
            {
                "target_id": target["target_id"],
                "domain": target["domain"],
                "account_id": target["account_id"],
                "region": target["region"],
                "service": target["service"],
                "scope": target["scope"],
                "inventory_actions": list(inventory),
                "detail_actions": list(detail),
                "exact_resources": [] if exact is None else [exact],
                "deferred_resource_kinds": list(deferred),
            }
        )
    return coverage


def _sid_token(service: str) -> str:
    return {
        "cloudformation": "CloudFormation",
        "dynamodb": "DynamoDb",
        "iam": "Iam",
        "kms": "Kms",
        "lambda": "Lambda",
        "logs": "LogGroup",
        "s3": "AccountRegionalS3",
        "signer": "Signer",
        "sso": "IdentityCenter",
    }[service]


def _build_inventory_policy(
    *,
    domain: str,
    catalog: Mapping[str, Any],
    coverage: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, Sequence[str]],
    identity_center_instance_arn: str | None,
) -> dict[str, Any]:
    account_id = (
        catalog_contract.AUTHORITY_ACCOUNT_ID
        if domain == "authority"
        else catalog_contract.MANAGEMENT_ACCOUNT_ID
    )
    not_before = catalog["not_before"]
    expires_at = catalog["expires_at"]
    statements: list[dict[str, Any]] = [
        {
            "Sid": "ConfirmOnlyTheCurrentCaller",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*",
            "Condition": _condition(
                account_id=account_id,
                not_before=not_before,
                expires_at=expires_at,
                regional=False,
            ),
        }
    ]

    discovery: dict[str, set[str]] = defaultdict(set)
    exact_actions: dict[str, set[str]] = defaultdict(set)
    exact_resources: dict[str, set[str]] = defaultdict(set)
    for item in coverage:
        if item["domain"] != domain:
            continue
        service = item["service"]
        # Generated code-signing-config physical ids are resolved through the
        # catalog-named CloudFormation stack resource below.  Do not also
        # grant the broader Lambda list API: it is not part of the provider or
        # transcript contract and would make the coverage declaration diverge
        # from the call that actually proves absence/presence.
        discovery[service].update(
            action
            for action in item["inventory_actions"]
            if action != "cloudformation:DescribeStackResource"
        )
        resources = item["exact_resources"]
        if resources:
            exact_actions[service].update(item["detail_actions"])
            exact_resources[service].update(resources)

    for service, actions in sorted(discovery.items()):
        if not actions:
            continue
        if service == "sso":
            bound_instance = candidates.get("sso_instance", [])
            sso_groups = (
                (
                    "DiscoverIdentityCenterInstances",
                    sorted(actions & {"sso:ListInstances"}),
                    False,
                    False,
                ),
                (
                    "DiscoverIdentityCenterApplications",
                    sorted(actions & {"sso:ListApplications"}),
                    False,
                    True,
                ),
                (
                    "DiscoverIdentityCenterPermissionSets",
                    sorted(actions & {"sso:ListPermissionSets"}),
                    True,
                    False,
                ),
            )
            for sid, group_actions, primary_region, application_account in sso_groups:
                if not group_actions:
                    continue
                condition = _condition(
                    account_id=account_id,
                    not_before=not_before,
                    expires_at=expires_at,
                    regional=True,
                    sso=primary_region,
                )
                if application_account:
                    condition["StringEquals"]["sso:ApplicationAccount"] = account_id
                statements.append(
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Action": group_actions,
                        "Resource": (
                            identity_center_instance_arn
                            if sid == "DiscoverIdentityCenterPermissionSets"
                            and identity_center_instance_arn is not None
                            else (
                                bound_instance[0]
                                if sid == "DiscoverIdentityCenterPermissionSets"
                                and len(bound_instance) == 1
                                else "*"
                            )
                        ),
                        "Condition": condition,
                    }
                )
            if identity_center_instance_arn is not None:
                instance_id = identity_center_instance_arn.rsplit("/", 1)[-1]
                statements.append(
                    {
                        "Sid": "ResolveIdentityCenterPermissionSetNames",
                        "Effect": "Allow",
                        "Action": ["sso:DescribePermissionSet"],
                        "Resource": [
                            identity_center_instance_arn,
                            (
                                "arn:aws:sso:::permissionSet/"
                                f"{instance_id}/*"
                            ),
                        ],
                        "Condition": _condition(
                            account_id=account_id,
                            not_before=not_before,
                            expires_at=expires_at,
                            regional=True,
                            sso=True,
                        ),
                    }
                )
            continue
        condition = _condition(
            account_id=account_id,
            not_before=not_before,
            expires_at=expires_at,
            regional=service != "iam",
        )
        statements.append(
            {
                "Sid": f"Discover{_sid_token(service)}CollisionCandidates",
                "Effect": "Allow",
                "Action": sorted(actions),
                "Resource": "*",
                "Condition": condition,
            }
        )

    stack_resource_arns = sorted(
        {
            (
                f"arn:aws:cloudformation:{catalog_contract.REGION}:"
                f"{account_id}:stack/{target['selector']['stack_name']}/*"
            )
            for target in catalog["targets"]
            if target["domain"] == domain
            and target["service"] == "lambda"
            and target["scope"] == "code_signing_config"
            and target["selector"].get("kind")
            in {
                "cloudformation_stack_resource",
                "cloudformation_ownership_tags",
            }
        }
    )
    if stack_resource_arns:
        statements.append(
            {
                "Sid": "ReadCatalogNamedStackResourceSelectors",
                "Effect": "Allow",
                "Action": "cloudformation:DescribeStackResource",
                "Resource": stack_resource_arns,
                "Condition": _condition(
                    account_id=account_id,
                    not_before=not_before,
                    expires_at=expires_at,
                    regional=True,
                ),
            }
        )

    scoped_groups: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"actions": set(), "resources": set()}
    )
    for service, resources in exact_resources.items():
        group = service if service in {"iam", "s3"} else "regional"
        scoped_groups[group]["actions"].update(exact_actions[service])
        scoped_groups[group]["resources"].update(resources)
    for group, contract in sorted(scoped_groups.items()):
        # ``Sid`` is diagnostic-only in IAM.  Keep it stable and descriptive,
        # but compact enough that the exact retained-resource catalog fits the
        # 10,240-byte aggregate inline-role-policy quota without weakening any
        # action, resource, condition, or explicit-deny boundary.
        sid_token = {
            "iam": "Iam",
            "regional": "Regional",
            "s3": "S3",
        }[group]
        statements.append(
            {
                "Sid": f"Read{sid_token}Targets",
                "Effect": "Allow",
                "Action": sorted(contract["actions"]),
                "Resource": sorted(contract["resources"]),
                "Condition": _condition(
                    account_id=account_id,
                    not_before=not_before,
                    expires_at=expires_at,
                    regional=group != "iam",
                    resource_account=group == "s3",
                ),
            }
        )

    allowed = sorted(
        {
            action
            for statement in statements
            if statement["Effect"] == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
    )
    regional_services = sorted(
        {
            action.split(":", 1)[0]
            for action in allowed
            if action.split(":", 1)[0] not in {"iam", "sts"}
        }
    )
    statements.extend(
        [
            {
                "Sid": "DenyReadsOutsideExactRegion",
                "Effect": "Deny",
                "Action": [f"{service}:*" for service in regional_services],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": catalog_contract.REGION
                    }
                },
            },
            {
                "Sid": "DenyMismatchedPrincipalAccount",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:PrincipalAccount": account_id}
                },
            },
            {
                "Sid": "DenyAllActionsBeforeAbsoluteStart",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:CurrentTime": not_before}
                },
            },
            {
                "Sid": "DenyAllActionsAtAbsoluteExpiry",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThanEquals": {"aws:CurrentTime": expires_at}
                },
            },
            {
                "Sid": "DenyEveryMutationAndUnreviewedAction",
                "Effect": "Deny",
                "NotAction": allowed,
                "Resource": "*",
            },
        ]
    )
    return {"Version": IAM_VERSION, "Statement": statements}


def _expected_discovery_selector(
    catalog: Mapping[str, Any], *, domain: str, kind: str
) -> dict[str, Any]:
    account_id = (
        catalog_contract.AUTHORITY_ACCOUNT_ID
        if domain == "authority"
        else catalog_contract.MANAGEMENT_ACCOUNT_ID
    )
    selector: dict[str, Any] = {
        "account_id": account_id,
        "region": catalog_contract.REGION,
    }
    targets = [
        target
        for target in catalog["targets"]
        if target["domain"] == domain
    ]
    if kind == "cloudformation_stack":
        selector["stack_names"] = sorted(
            target["name"]
            for target in targets
            if target["service"] == "cloudformation"
            and target["scope"] == "stack"
        )
    elif kind == "kms_key":
        selector["alias_names"] = sorted(
            target["name"]
            for target in targets
            if target["service"] == "kms" and target["scope"] == "alias"
        )
    elif kind == "lambda_code_signing_config":
        selector["stack_resources"] = sorted(
            (
                {
                    "stack_name": target["selector"]["stack_name"],
                    "logical_resource_id": target["selector"][
                        "logical_resource_id"
                    ],
                }
                for target in targets
                if target["service"] == "lambda"
                and target["scope"] == "code_signing_config"
            ),
            key=canonical_json,
        )
    elif kind == "identity_center_kms_key":
        selector["binding_names"] = ["identity_center_kms_key_arn"]
    elif kind == "sso_application":
        selector["application_names"] = sorted(
            target["name"]
            for target in targets
            if target["service"] == "sso"
            and target["scope"] == "application"
        )
    elif kind == "sso_instance":
        selector["owner_account_ids"] = [account_id]
    elif kind == "sso_permission_set":
        selector["permission_set_names"] = sorted(
            target["name"]
            for target in targets
            if target["service"] == "sso"
            and target["scope"] == "permission_set"
        )
    else:
        _fail("COLLISION_POLICY_CANDIDATE_KIND_INVALID")
    return selector


def route_collision_discovery_plan(
    catalog: Mapping[str, Any],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Return the sole catalog-derived inventory plan accepted by the provider."""

    catalog_contract.validate_route_collision_catalog(catalog)
    return {
        domain: {
            kind: {
                "operation": _DISCOVERY_OPERATIONS[kind],
                "selector": _expected_discovery_selector(
                    catalog,
                    domain=domain,
                    kind=kind,
                ),
            }
            for kind in sorted(_DYNAMIC_RESOURCE_KINDS[domain])
        }
        for domain in DOMAINS
    }


def _require_discovery_item_fields(
    item: Any, *, fields: set[str]
) -> dict[str, str]:
    if (
        not isinstance(item, Mapping)
        or set(item) != fields
        or any(not isinstance(value, str) or not value for value in item.values())
    ):
        _fail("COLLISION_POLICY_DISCOVERY_ITEM_INVALID")
    return {str(key): str(value) for key, value in item.items()}


def _candidate_from_discovery_item(
    *,
    domain: str,
    kind: str,
    item: Any,
    selector: Mapping[str, Any],
) -> tuple[dict[str, str], str, str | None]:
    """Return normalized projection, exact selector identity and candidate ARN."""

    if kind == "cloudformation_stack":
        normalized = _require_discovery_item_fields(
            item, fields={"StackId", "StackName"}
        )
        selector_id = normalized["StackName"]
        if selector_id not in selector["stack_names"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        candidate = normalized["StackId"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        observed_name = candidate.split(":stack/", 1)[1].split("/", 1)[0]
        if observed_name != selector_id:
            _fail("COLLISION_POLICY_CANDIDATE_BINDING_INVALID")
        return normalized, selector_id, candidate

    if kind == "kms_key":
        normalized = _require_discovery_item_fields(
            item, fields={"AliasName", "TargetKeyId"}
        )
        selector_id = normalized["AliasName"]
        if selector_id not in selector["alias_names"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        key_id = normalized["TargetKeyId"]
        candidate = (
            key_id
            if key_id.startswith("arn:")
            else (
                f"arn:aws:kms:{catalog_contract.REGION}:"
                f"{selector['account_id']}:key/{key_id}"
            )
        )
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        return normalized, selector_id, candidate

    if kind == "lambda_code_signing_config":
        normalized = _require_discovery_item_fields(
            item,
            fields={"LogicalResourceId", "PhysicalResourceId", "StackName"},
        )
        selector_value = {
            "stack_name": normalized["StackName"],
            "logical_resource_id": normalized["LogicalResourceId"],
        }
        if selector_value not in selector["stack_resources"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        selector_id = canonical_json(selector_value)
        candidate = normalized["PhysicalResourceId"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        return normalized, selector_id, candidate

    if kind == "identity_center_kms_key":
        if not isinstance(item, Mapping):
            _fail("COLLISION_POLICY_DISCOVERY_ITEM_INVALID")
        mode = item.get("Mode")
        fields = {"BindingName", "Mode", "PrivateBindingDigest"}
        if mode == "CUSTOMER_MANAGED_KEY":
            fields.add("KeyArn")
        normalized = _require_discovery_item_fields(item, fields=fields)
        selector_id = normalized["BindingName"]
        if (
            selector_id not in selector["binding_names"]
            or _DIGEST.fullmatch(normalized["PrivateBindingDigest"]) is None
        ):
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        if mode == "AWS_OWNED_KMS_KEY":
            return normalized, selector_id, None
        if mode != "CUSTOMER_MANAGED_KEY":
            _fail("COLLISION_POLICY_DISCOVERY_ITEM_INVALID")
        candidate = normalized["KeyArn"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        return normalized, selector_id, candidate

    if kind == "sso_instance":
        normalized = _require_discovery_item_fields(
            item, fields={"InstanceArn", "OwnerAccountId"}
        )
        selector_id = normalized["OwnerAccountId"]
        if selector_id not in selector["owner_account_ids"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        candidate = normalized["InstanceArn"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        return normalized, selector_id, candidate

    if kind == "sso_application":
        normalized = _require_discovery_item_fields(
            item, fields={"ApplicationArn", "InstanceArn", "Name"}
        )
        selector_id = normalized["Name"]
        if selector_id not in selector["application_names"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        candidate = normalized["ApplicationArn"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        _validate_candidate_arn(
            domain=domain,
            kind="sso_instance",
            arn=normalized["InstanceArn"],
        )
        return normalized, selector_id, candidate

    if kind == "sso_permission_set":
        normalized = _require_discovery_item_fields(
            item, fields={"InstanceArn", "Name", "PermissionSetArn"}
        )
        selector_id = normalized["Name"]
        if selector_id not in selector["permission_set_names"]:
            _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
        candidate = normalized["PermissionSetArn"]
        _validate_candidate_arn(domain=domain, kind=kind, arn=candidate)
        _validate_candidate_arn(
            domain=domain,
            kind="sso_instance",
            arn=normalized["InstanceArn"],
        )
        return normalized, selector_id, candidate

    _fail("COLLISION_POLICY_CANDIDATE_KIND_INVALID")


def _normalize_discovery_evidence(
    catalog: Mapping[str, Any], value: Mapping[str, Any] | None
) -> tuple[dict[str, Any] | None, dict[str, dict[str, list[str]]]]:
    if value is None:
        return None, {}
    if (
        not isinstance(value, Mapping)
        or set(value) != _DISCOVERY_EVIDENCE_FIELDS
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("record_type") != DISCOVERY_EVIDENCE_RECORD_TYPE
        or value.get("catalog_digest") != catalog.get("catalog_digest")
    ):
        _fail("COLLISION_POLICY_DISCOVERY_EVIDENCE_INVALID")
    domains = value.get("domains")
    if not isinstance(domains, Mapping) or set(domains) != set(DOMAINS):
        _fail("COLLISION_POLICY_DISCOVERY_DOMAINS_INVALID")

    normalized_domains: dict[str, dict[str, Any]] = {}
    candidates: dict[str, dict[str, list[str]]] = {}
    instance_references: list[str] = []
    for domain in DOMAINS:
        groups = domains.get(domain)
        if (
            not isinstance(groups, Mapping)
            or set(groups) != set(_DYNAMIC_RESOURCE_KINDS[domain])
        ):
            _fail("COLLISION_POLICY_CANDIDATE_KIND_INVALID")
        normalized_domains[domain] = {}
        candidates[domain] = {}
        for kind in sorted(_DYNAMIC_RESOURCE_KINDS[domain]):
            group = groups.get(kind)
            if not isinstance(group, Mapping) or set(group) != _DISCOVERY_GROUP_FIELDS:
                _fail("COLLISION_POLICY_DISCOVERY_GROUP_INVALID")
            operation = group.get("operation")
            expected_selector = _expected_discovery_selector(
                catalog, domain=domain, kind=kind
            )
            if operation != _DISCOVERY_OPERATIONS[kind]:
                _fail("COLLISION_POLICY_DISCOVERY_OPERATION_INVALID")
            if canonical_json(group.get("selector")) != canonical_json(
                expected_selector
            ):
                _fail("COLLISION_POLICY_DISCOVERY_SELECTOR_INVALID")
            pages = group.get("pages")
            if (
                not isinstance(pages, list)
                or not pages
                or len(pages) > MAX_DISCOVERY_PAGES
            ):
                _fail("COLLISION_POLICY_DISCOVERY_PAGINATION_INVALID")

            normalized_pages: list[dict[str, Any]] = []
            selector_ids: set[str] = set()
            candidate_arns: set[str] = set()
            seen_cursor_digests: set[str] = set()
            previous_output: str | None = None
            for expected_index, page in enumerate(pages, start=1):
                if (
                    not isinstance(page, Mapping)
                    or set(page) != _DISCOVERY_PAGE_FIELDS
                    or page.get("page_index") != expected_index
                    or page.get("input_cursor_digest") != previous_output
                ):
                    _fail("COLLISION_POLICY_DISCOVERY_PAGINATION_INVALID")
                output = page.get("output_cursor_digest")
                if output is not None and (
                    not isinstance(output, str)
                    or _DIGEST.fullmatch(output) is None
                    or output == previous_output
                    or output in seen_cursor_digests
                ):
                    _fail("COLLISION_POLICY_DISCOVERY_PAGINATION_INVALID")
                if expected_index < len(pages) and output is None:
                    _fail("COLLISION_POLICY_DISCOVERY_PAGINATION_INVALID")
                if expected_index == len(pages) and output is not None:
                    _fail("COLLISION_POLICY_DISCOVERY_INCOMPLETE")
                raw_items = page.get("items")
                if not isinstance(raw_items, list):
                    _fail("COLLISION_POLICY_DISCOVERY_ITEM_INVALID")
                normalized_items: list[dict[str, str]] = []
                for item in raw_items:
                    normalized, selector_id, candidate = (
                        _candidate_from_discovery_item(
                            domain=domain,
                            kind=kind,
                            item=item,
                            selector=expected_selector,
                        )
                    )
                    if selector_id in selector_ids or (
                        candidate is not None and candidate in candidate_arns
                    ):
                        _fail("COLLISION_POLICY_CANDIDATE_DUPLICATE")
                    selector_ids.add(selector_id)
                    if candidate is not None:
                        candidate_arns.add(candidate)
                    normalized_items.append(normalized)
                    if kind in {"sso_application", "sso_permission_set"}:
                        instance_references.append(normalized["InstanceArn"])
                if len(candidate_arns) > _MAX_CANDIDATES_PER_KIND:
                    _fail("COLLISION_POLICY_CANDIDATE_SET_INVALID")
                normalized_pages.append(
                    {
                        "page_index": expected_index,
                        "input_cursor_digest": previous_output,
                        "output_cursor_digest": output,
                        "items": sorted(normalized_items, key=canonical_json),
                    }
                )
                if output is not None:
                    seen_cursor_digests.add(output)
                previous_output = output
            candidates[domain][kind] = sorted(candidate_arns)
            normalized_domains[domain][kind] = {
                "operation": operation,
                "selector": expected_selector,
                "pages": normalized_pages,
            }

    management_instances = candidates["management"]["sso_instance"]
    if len(management_instances) != 1 or any(
        reference != management_instances[0] for reference in instance_references
    ):
        _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "record_type": DISCOVERY_EVIDENCE_RECORD_TYPE,
        "catalog_digest": catalog["catalog_digest"],
        "domains": normalized_domains,
    }
    return evidence, candidates


def _validate_candidate_arn(*, domain: str, kind: str, arn: Any) -> None:
    if (
        not isinstance(arn, str)
        or not arn
        or "*" in arn
        or "?" in arn
        or "${" in arn
        or _ARN_SAFE.fullmatch(arn) is None
    ):
        _fail("COLLISION_POLICY_CANDIDATE_ARN_INVALID")
    account = (
        catalog_contract.AUTHORITY_ACCOUNT_ID
        if domain == "authority"
        else catalog_contract.MANAGEMENT_ACCOUNT_ID
    )
    region = catalog_contract.REGION
    patterns = {
        "cloudformation_stack": re.compile(
            rf"^arn:aws:cloudformation:{region}:{account}:stack/"
            r"[A-Za-z0-9][A-Za-z0-9-]{0,127}/"
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}$"
        ),
        "kms_key": re.compile(
            rf"^arn:aws:kms:{region}:{account}:key/"
            r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}|mrk-[0-9a-f]{32})$"
        ),
        "identity_center_kms_key": re.compile(
            rf"^arn:aws:kms:{region}:{account}:key/"
            r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}|mrk-[0-9a-f]{32})$"
        ),
        "lambda_code_signing_config": re.compile(
            rf"^arn:aws:lambda:{region}:{account}:"
            r"code-signing-config:csc-[a-z0-9]{17}$"
        ),
        "sso_application": re.compile(
            rf"^arn:aws:sso::{account}:application/"
            r"ssoins-[A-Za-z0-9]{16}/apl-[A-Za-z0-9]{16}$"
        ),
        "sso_instance": re.compile(
            r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$"
        ),
        "sso_permission_set": re.compile(
            r"^arn:aws:sso:::permissionSet/"
            r"ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}$"
        ),
    }
    pattern = patterns.get(kind)
    if pattern is None or pattern.fullmatch(arn) is None:
        _fail("COLLISION_POLICY_CANDIDATE_ARN_INVALID")


def _candidate_action_contract(kind: str) -> tuple[str, ...]:
    return {
        "cloudformation_stack": (
            "cloudformation:DescribeStacks",
        ),
        "kms_key": ("kms:DescribeKey", "kms:ListResourceTags"),
        "identity_center_kms_key": (),
        "lambda_code_signing_config": (
            "lambda:ListTags",
        ),
        "sso_application": (
            "sso:DescribeApplication",
            "sso:ListTagsForResource",
        ),
        "sso_instance": (
            "sso:DescribeInstance",
            "sso:ListPermissionSets",
            "sso:ListTagsForResource",
        ),
        "sso_permission_set": (
            "sso:DescribePermissionSet",
            "sso:ListTagsForResource",
        ),
    }[kind]


def _build_candidate_detail_policy(
    *,
    domain: str,
    catalog: Mapping[str, Any],
    candidates: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    account_id = (
        catalog_contract.AUTHORITY_ACCOUNT_ID
        if domain == "authority"
        else catalog_contract.MANAGEMENT_ACCOUNT_ID
    )
    not_before = catalog["not_before"]
    expires_at = catalog["expires_at"]
    statements: list[dict[str, Any]] = [
        {
            "Sid": "ConfirmOnlyTheCurrentCaller",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*",
            "Condition": _condition(
                account_id=account_id,
                not_before=not_before,
                expires_at=expires_at,
                regional=False,
            ),
        }
    ]
    service_groups: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"actions": set(), "resources": set()}
    )
    stack_resource_arns: set[str] = set()
    stack_resource_names = {
        target["selector"]["stack_name"]
        for target in catalog["targets"]
        if target["domain"] == domain
        and target["service"] == "lambda"
        and target["scope"] == "code_signing_config"
        and target["selector"]["kind"]
        in {
            "cloudformation_stack_resource",
            "cloudformation_ownership_tags",
        }
    }
    for kind, resources in sorted(candidates.items()):
        if not resources:
            continue
        if kind == "identity_center_kms_key":
            # The key ARN is a selector binding supplied by the validated
            # private discovery evidence.  Collision inventory never decrypts
            # data, so the runtime policy intentionally grants no KMS data
            # plane action for this candidate kind.
            continue
        if kind == "cloudformation_stack":
            stack_resource_arns.update(
                arn
                for arn in resources
                if arn.split(":stack/", 1)[1].split("/", 1)[0]
                in stack_resource_names
            )
        service = _candidate_action_contract(kind)[0].split(":", 1)[0]
        service_groups[service]["actions"].update(
            _candidate_action_contract(kind)
        )
        service_groups[service]["resources"].update(resources)
    if stack_resource_arns:
        statements.append(
            {
                "Sid": "ReadExactDiscoveredStackResourceSelectors",
                "Effect": "Allow",
                "Action": "cloudformation:DescribeStackResource",
                "Resource": sorted(stack_resource_arns),
                "Condition": _condition(
                    account_id=account_id,
                    not_before=not_before,
                    expires_at=expires_at,
                    regional=True,
                ),
            }
        )
    for service, contract in sorted(service_groups.items()):
        statements.append(
            {
                "Sid": f"ReadExactDiscovered{_sid_token(service)}Candidates",
                "Effect": "Allow",
                "Action": sorted(contract["actions"]),
                "Resource": sorted(contract["resources"]),
                "Condition": _condition(
                    account_id=account_id,
                    not_before=not_before,
                    expires_at=expires_at,
                    regional=True,
                    sso=service == "sso",
                ),
            }
        )
    allowed = sorted(
        {
            action
            for statement in statements
            if statement["Effect"] == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
    )
    services = sorted(
        {action.split(":", 1)[0] for action in allowed if ":" in action}
        - {"sts"}
    )
    if services:
        statements.append(
            {
                "Sid": "DenyReadsOutsideExactRegion",
                "Effect": "Deny",
                "Action": [f"{service}:*" for service in services],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": catalog_contract.REGION
                    }
                },
            }
        )
    statements.extend(
        [
            {
                "Sid": "DenyMismatchedPrincipalAccount",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:PrincipalAccount": account_id}
                },
            },
            {
                "Sid": "DenyAllActionsBeforeAbsoluteStart",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:CurrentTime": not_before}
                },
            },
            {
                "Sid": "DenyAllActionsAtAbsoluteExpiry",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThanEquals": {"aws:CurrentTime": expires_at}
                },
            },
            {
                "Sid": "DenyEveryMutationAndUnreviewedAction",
                "Effect": "Deny",
                "NotAction": allowed,
                "Resource": "*",
            },
        ]
    )
    return {"Version": IAM_VERSION, "Statement": statements}


def _actions(policy: Mapping[str, Any]) -> list[str]:
    return sorted(
        {
            action
            for statement in policy["Statement"]
            if statement.get("Effect") == "Allow"
            for action in (
                statement["Action"]
                if isinstance(statement["Action"], list)
                else [statement["Action"]]
            )
        }
    )


def _wildcard_exceptions(
    *, domain: str, stage: str, policy: Mapping[str, Any]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for statement in policy["Statement"]:
        resources = statement.get("Resource")
        resource_values = resources if isinstance(resources, list) else [resources]
        if not any(
            isinstance(resource, str) and ("*" in resource or "?" in resource)
            for resource in resource_values
        ):
            continue
        actions = statement.get("Action", statement.get("NotAction"))
        normalized = actions if isinstance(actions, list) else [actions]
        sid = statement["Sid"]
        if statement["Effect"] == "Deny":
            reason = "EXPLICIT_DENY_MUST_COVER_ALL_RESOURCES"
        elif sid == "ConfirmOnlyTheCurrentCaller":
            reason = "ACTION_HAS_NO_RESOURCE_LEVEL_AUTHORIZATION"
        elif sid == "ResolveIdentityCenterPermissionSetNames":
            reason = "AWS_LIST_PERMISSIONSETS_OMITS_NAME"
        elif resources != "*":
            reason = "AWS_ASSIGNED_STACK_ID_REQUIRES_EXACT_NAME_WILDCARD"
        else:
            reason = "AWS_LIST_CLASS_API_REQUIRES_WILDCARD_RESOURCE"
        result.append(
            {
                "domain": domain,
                "stage": stage,
                "statement_sid": sid,
                "actions": normalized,
                "resource": resources,
                "reason_code": reason,
            }
        )
    return result


def _build_policy_set(
    catalog: Mapping[str, Any],
    *,
    discovery_evidence: Mapping[str, Any] | None,
    discovery_provenance_digest: str | None = None,
    identity_center_instance_arn: str | None = None,
) -> dict[str, Any]:
    """Build a structurally sealed policy set, never an authority token.

    Candidate evidence supplied to this private helper is useful for pure
    validation fixtures only.  The public materializer obtains candidate
    evidence exclusively by consuming the concrete provider's opaque,
    non-serializable discovery capability; the connected provider factory
    independently requires that same one-shot capability before it can use a
    candidate-detail policy.  A self-consistent JSON document therefore cannot
    become operational authority merely by recomputing its formal digests.
    """
    catalog_contract.validate_route_collision_catalog(catalog)
    if identity_center_instance_arn is not None and re.fullmatch(
        r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}",
        identity_center_instance_arn,
    ) is None:
        _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")
    normalized_evidence, normalized_candidates = _normalize_discovery_evidence(
        catalog, discovery_evidence
    )
    if normalized_evidence is None:
        if discovery_provenance_digest is not None:
            _fail("COLLISION_POLICY_DISCOVERY_PROVENANCE_INVALID")
        stage = "inventory"
        candidate_digest = None
        discovery_evidence_digest = None
    else:
        if (
            not isinstance(discovery_provenance_digest, str)
            or _DIGEST.fullmatch(discovery_provenance_digest) is None
        ):
            _fail("COLLISION_POLICY_DISCOVERY_PROVENANCE_INVALID")
        stage = "inventory-and-candidate-detail"
        candidate_digest = canonical_digest(normalized_candidates)
        discovery_evidence_digest = canonical_digest(normalized_evidence)
        management_candidates = normalized_candidates["management"]
        kms_group = normalized_evidence["domains"]["management"][
            "identity_center_kms_key"
        ]
        kms_items = [
            item
            for page in kms_group["pages"]
            for item in page["items"]
        ]
        kms_candidates = management_candidates.get(
            "identity_center_kms_key", []
        )
        if len(kms_items) != 1:
            _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")
        kms_item = kms_items[0]
        if (
            kms_item.get("Mode") == "AWS_OWNED_KMS_KEY"
            and kms_candidates != []
        ) or (
            kms_item.get("Mode") == "CUSTOMER_MANAGED_KEY"
            and (
                len(kms_candidates) != 1
                or kms_item.get("KeyArn") != kms_candidates[0]
            )
        ) or kms_item.get("Mode") not in {
            "AWS_OWNED_KMS_KEY",
            "CUSTOMER_MANAGED_KEY",
        }:
            _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")
        if len(management_candidates.get("sso_instance", [])) != 1:
            _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")
        if (
            identity_center_instance_arn is not None
            and management_candidates["sso_instance"]
            != [identity_center_instance_arn]
        ):
            _fail("COLLISION_POLICY_IDENTITY_CENTER_BINDING_INVALID")

    coverage = _target_coverage(catalog)
    policies: dict[str, dict[str, dict[str, Any]]] = {}
    policy_digests: dict[str, dict[str, str]] = {}
    allowed_actions: dict[str, dict[str, list[str]]] = {}
    exceptions: list[dict[str, Any]] = []
    for domain in DOMAINS:
        inventory = _build_inventory_policy(
            domain=domain,
            catalog=catalog,
            coverage=coverage,
            candidates=normalized_candidates.get(domain, {}),
            identity_center_instance_arn=(
                identity_center_instance_arn
                if domain == "management"
                else None
            ),
        )
        policies[domain] = {"inventory": inventory}
        if normalized_evidence is not None:
            policies[domain]["candidate_detail"] = _build_candidate_detail_policy(
                domain=domain,
                catalog=catalog,
                candidates=normalized_candidates[domain],
            )
        policy_digests[domain] = {
            name: canonical_digest(policy)
            for name, policy in policies[domain].items()
        }
        if any(
            len(canonical_json(policy).encode("utf-8"))
            > MAX_IAM_POLICY_CHARS
            for policy in policies[domain].values()
        ):
            _fail("COLLISION_POLICY_DOCUMENT_TOO_LARGE")
        allowed_actions[domain] = {
            name: _actions(policy) for name, policy in policies[domain].items()
        }
        for name, policy in policies[domain].items():
            exceptions.extend(
                _wildcard_exceptions(
                    domain=domain, stage=name, policy=policy
                )
            )

    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_type": RECORD_TYPE,
        "catalog_digest": catalog["catalog_digest"],
        "source_commit_sha": catalog["source_commit_sha"],
        "source_tree_sha": catalog["source_tree_sha"],
        "authority_account_id": catalog_contract.AUTHORITY_ACCOUNT_ID,
        "management_account_id": catalog_contract.MANAGEMENT_ACCOUNT_ID,
        "region": catalog_contract.REGION,
        "not_before": catalog["not_before"],
        "expires_at": catalog["expires_at"],
        "target_count": catalog["target_count"],
        "identity_center_instance_arn": identity_center_instance_arn,
        "target_coverage": coverage,
        "stage": stage,
        "discovery_evidence": normalized_evidence,
        "candidate_resources": normalized_candidates,
        "candidate_resources_digest": candidate_digest,
        "discovery_evidence_digest": discovery_evidence_digest,
        "discovery_provenance_digest": discovery_provenance_digest,
        "policies": policies,
        "policy_digests": policy_digests,
        "allowed_actions": allowed_actions,
        "wildcard_resource_exceptions": exceptions,
        "read_only": True,
        "aws_mutations": 0,
    }
    value["policy_set_digest"] = canonical_digest(value)
    return value


def materialize_route_collision_policy_set(
    catalog: Mapping[str, Any],
    *,
    discovery_capability: object | None = None,
    identity_center_instance_arn: str | None = None,
) -> dict[str, Any]:
    """Build inventory policy or consume one exact provider capability once."""

    if discovery_capability is None:
        value = _build_policy_set(
            catalog,
            discovery_evidence=None,
            identity_center_instance_arn=identity_center_instance_arn,
        )
        validate_route_collision_policy_set(value, catalog=catalog)
        return value

    # Imported lazily to avoid a module cycle: the concrete provider validates
    # policy sets before it can mint this exact, non-serializable capability.
    from tooling import platform_authority_gug376_collision_aws_provider as provider

    evidence, provenance_digest = provider.consume_discovery_for_policy(
        discovery_capability,
        catalog=catalog,
    )
    value = _build_policy_set(
        catalog,
        discovery_evidence=evidence,
        discovery_provenance_digest=provenance_digest,
        identity_center_instance_arn=identity_center_instance_arn,
    )
    validate_route_collision_policy_set(value, catalog=catalog)
    provider.bind_materialized_candidate_policy(
        discovery_capability,
        policy_set=value,
        catalog=catalog,
    )
    return value


def validate_route_collision_policy_set(
    value: Mapping[str, Any], *, catalog: Mapping[str, Any]
) -> None:
    """Validate structural closure; this never confers operational authority.

    Candidate-detail policy use additionally requires the provider-owned,
    non-serializable discovery capability bound by
    ``build_attested_provider_factory``.
    """

    if not isinstance(value, Mapping) or set(value) != _TOP_FIELDS:
        _fail("COLLISION_POLICY_SET_FIELDS_INVALID")
    if value.get("schema_version") != SCHEMA_VERSION:
        _fail("COLLISION_POLICY_SET_VERSION_INVALID")
    if value.get("record_type") != RECORD_TYPE:
        _fail("COLLISION_POLICY_SET_TYPE_INVALID")
    coverage = value.get("target_coverage")
    if (
        not isinstance(coverage, list)
        or len(coverage) != catalog_contract.TARGET_COUNT
        or any(
            not isinstance(item, Mapping) or set(item) != _COVERAGE_FIELDS
            for item in coverage
        )
    ):
        _fail("COLLISION_POLICY_COVERAGE_INVALID")
    exceptions = value.get("wildcard_resource_exceptions")
    if not isinstance(exceptions, list) or any(
        not isinstance(item, Mapping) or set(item) != _EXCEPTION_FIELDS
        for item in exceptions
    ):
        _fail("COLLISION_POLICY_WILDCARD_DOCUMENTATION_INVALID")
    supplied_digest = value.get("policy_set_digest")
    unsigned = dict(value)
    unsigned.pop("policy_set_digest", None)
    if (
        not isinstance(supplied_digest, str)
        or _DIGEST.fullmatch(supplied_digest) is None
        or supplied_digest != canonical_digest(unsigned)
    ):
        _fail("COLLISION_POLICY_SET_DIGEST_INVALID")

    candidates_raw = value.get("candidate_resources")
    if value.get("stage") == "inventory":
        if (
            candidates_raw != {}
            or value.get("discovery_evidence") is not None
            or value.get("discovery_provenance_digest") is not None
        ):
            _fail("COLLISION_POLICY_CANDIDATE_SET_INVALID")
    elif value.get("stage") == "inventory-and-candidate-detail":
        if not isinstance(candidates_raw, Mapping) or not isinstance(
            value.get("discovery_evidence"), Mapping
        ) or _DIGEST.fullmatch(
            str(value.get("discovery_provenance_digest"))
        ) is None:
            _fail("COLLISION_POLICY_CANDIDATE_SET_INVALID")
    else:
        _fail("COLLISION_POLICY_STAGE_INVALID")
    expected = _build_policy_set(
        catalog,
        discovery_evidence=(
            value.get("discovery_evidence")
            if value.get("stage") == "inventory-and-candidate-detail"
            else None
        ),
        discovery_provenance_digest=(
            value.get("discovery_provenance_digest")
            if value.get("stage") == "inventory-and-candidate-detail"
            else None
        ),
        identity_center_instance_arn=value.get(
            "identity_center_instance_arn"
        ),
    )
    if canonical_json(value) != canonical_json(expected):
        _fail("COLLISION_POLICY_SET_BINDING_INVALID")


__all__ = [
    "CollisionPolicyError",
    "DISCOVERY_EVIDENCE_RECORD_TYPE",
    "DOMAINS",
    "IAM_VERSION",
    "MAX_DISCOVERY_PAGES",
    "MAX_IAM_POLICY_CHARS",
    "RECORD_TYPE",
    "SCHEMA_VERSION",
    "canonical_digest",
    "canonical_json",
    "materialize_route_collision_policy_set",
    "route_collision_discovery_plan",
    "validate_route_collision_policy_set",
]
