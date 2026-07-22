"""Provider-derived invocation-authority verification for GUG-221.

The GUG-221 repair Lambda is a privileged PEP. Lambda does not expose the
original IAM caller to the function runtime, so the execution-role identity
returned by STS cannot authenticate the invoker. This module instead proves
the narrow, account-wide precondition that exactly one reviewed Identity
Center role can invoke the three private GUG-221 aliases.

AWS discovery is delegated to the GUG-218 read-only collector. IAM policy
parsing and matching also reuse its conservative semantics; this module only
defines the different, three-edge GUG-221 topology. A verifier returns a
typed, digest-only result only when every observed surface is complete and
exact. All ambiguous, stale, foreign, or unsupported states raise a sanitized
``AuthorityInventoryError`` before a caller can perform effects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from tooling.platform_authority_lambda_invocation_authority import (
    ACCOUNT_ID,
    CLOUDFORMATION_MUTATION_ACTIONS,
    COVERAGE_STATUSES,
    COVERAGE_SURFACES,
    DIGEST,
    EVIDENCE_SOURCE_AWS_READ_ONLY,
    IAM_MUTATION_ACTIONS,
    INVOCATION_ACTIONS,
    LAMBDA_MUTATION_ACTIONS,
    RAW_SNAPSHOT_FORMAT,
    REGION,
    AuthorityInventoryError,
    AwsReadOnlyInventoryAdapter,
    TargetBinding,
    _allowed_sensitive_actions,
    _canonical_sts_principal_arn,
    _condition_class,
    _has_unknown_authority_action,
    _is_target_function_pattern,
    _observed_invocation_resources,
    _parse_time,
    _policy_sources,
    _principal_values,
    _resource_applies,
    _seal_raw_snapshot,
    _statement_resource_values,
    _statements,
    _strict_policy_document,
    _strict_string_list,
    canonical_digest,
    digest_text,
)


PLAN_FUNCTION_NAME = "scanalyze-authority-lambda-audit-plan"
REPAIR_FUNCTION_NAME = "scanalyze-authority-lambda-audit-repair"
RECONCILE_FUNCTION_NAME = "scanalyze-authority-lambda-audit-reconcile"
EXPECTED_ALIASES = {
    PLAN_FUNCTION_NAME: frozenset({"plan-v1"}),
    REPAIR_FUNCTION_NAME: frozenset({"repair-v1"}),
    RECONCILE_FUNCTION_NAME: frozenset({"reconcile-v1"}),
}
EXPECTED_AUTHORITY_EDGE_COUNT = 3
VERIFIED_STATUS = "VERIFIED_EXACT_ACCOUNT_WIDE_INVOCATION_AUTHORITY"

_SSO_ROLE_NAME = re.compile(
    r"^AWSReservedSSO_ScanalyzeLambdaAuditRepair_[0-9a-fA-F]{16}$"
)
_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$")
_SAML_AUDIENCE = "https://signin.aws.amazon.com/saml"


@dataclass(frozen=True, slots=True)
class RepairInvocationAuthorityBinding:
    """Trusted server-side binding for one GUG-221 authority decision.

    ``invoker_role_arn`` and both digests must be obtained from reviewed,
    provider-derived control-plane state. Request payloads and Lambda
    ClientContext are not valid sources for these fields.
    """

    authority_account_id: str
    region: str
    invoker_role_arn: str
    invoker_policy_digest: str
    collector_principal_digest: str
    saml_provider_arn: str
    partition: str = "aws"

    def __post_init__(self) -> None:
        if ACCOUNT_ID.fullmatch(self.authority_account_id) is None:
            raise AuthorityInventoryError("AUTHORITY_ACCOUNT_INVALID")
        if REGION.fullmatch(self.region) is None:
            raise AuthorityInventoryError("TARGET_REGION_INVALID")
        if self.partition not in {"aws", "aws-us-gov", "aws-cn"}:
            raise AuthorityInventoryError("AWS_PARTITION_INVALID")
        for value in (self.invoker_policy_digest, self.collector_principal_digest):
            if DIGEST.fullmatch(value) is None:
                raise AuthorityInventoryError("AUTHORITY_DIGEST_INVALID")

        role_prefix = (
            f"arn:{self.partition}:iam::{self.authority_account_id}:role/"
            "aws-reserved/sso.amazonaws.com/"
        )
        if not self.invoker_role_arn.startswith(role_prefix):
            raise AuthorityInventoryError("INVOKER_ROLE_ARN_INVALID")
        role_path = self.invoker_role_arn.removeprefix(role_prefix)
        role_name = role_path.rsplit("/", 1)[-1]
        if _SSO_ROLE_NAME.fullmatch(role_name) is None:
            raise AuthorityInventoryError("INVOKER_ROLE_ARN_INVALID")
        path_prefix = role_path[: -len(role_name)]
        if path_prefix not in {"", f"{self.region}/"}:
            raise AuthorityInventoryError("INVOKER_ROLE_ARN_INVALID")

        saml_pattern = re.compile(
            rf"^arn:{re.escape(self.partition)}:iam::{self.authority_account_id}:"
            r"saml-provider/AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
        )
        if saml_pattern.fullmatch(self.saml_provider_arn) is None:
            raise AuthorityInventoryError("INVOKER_SAML_PROVIDER_INVALID")

    @property
    def plan_binding(self) -> TargetBinding:
        return TargetBinding(
            authority_account_id=self.authority_account_id,
            region=self.region,
            function_name=PLAN_FUNCTION_NAME,
            partition=self.partition,
        )

    @property
    def repair_binding(self) -> TargetBinding:
        return TargetBinding(
            authority_account_id=self.authority_account_id,
            region=self.region,
            function_name=REPAIR_FUNCTION_NAME,
            partition=self.partition,
        )

    @property
    def reconcile_binding(self) -> TargetBinding:
        return TargetBinding(
            authority_account_id=self.authority_account_id,
            region=self.region,
            function_name=RECONCILE_FUNCTION_NAME,
            partition=self.partition,
        )

    @property
    def expected_resources(self) -> frozenset[str]:
        return frozenset(
            {
                f"{self.plan_binding.function_arn}:plan-v1",
                f"{self.repair_binding.function_arn}:repair-v1",
                f"{self.reconcile_binding.function_arn}:reconcile-v1",
            }
        )

    @property
    def binding_digest(self) -> str:
        return canonical_digest(
            {
                "authority_account_id_digest": digest_text(
                    self.authority_account_id
                ),
                "region": self.region,
                "invoker_role_digest": digest_text(self.invoker_role_arn),
                "invoker_policy_digest": self.invoker_policy_digest,
                "collector_principal_digest": self.collector_principal_digest,
                "saml_provider_digest": digest_text(self.saml_provider_arn),
                "expected_resource_digests": sorted(
                    digest_text(item) for item in self.expected_resources
                ),
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderInvocationSnapshots:
    """One provider capture covering all three private GUG-221 functions."""

    scan_id: str
    plan: Mapping[str, Any]
    repair: Mapping[str, Any]
    reconcile: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class VerifiedRepairInvocationAuthority:
    """Sanitized evidence returned only for an exact, complete graph."""

    binding_digest: str
    collector_principal_digest: str
    plan_snapshot_digest: str
    repair_snapshot_digest: str
    reconcile_snapshot_digest: str
    authority_graph_digest: str
    expected_edge_count: int
    verified_at: str
    expires_at: str
    status: str = VERIFIED_STATUS

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1",
            "record_type": (
                "platform_authority_lambda_audit_repair_invocation_authority"
            ),
            "environment": "non-production",
            "production": False,
            "status": self.status,
            "binding_digest": self.binding_digest,
            "collector_principal_digest": self.collector_principal_digest,
            "plan_snapshot_digest": self.plan_snapshot_digest,
            "repair_snapshot_digest": self.repair_snapshot_digest,
            "reconcile_snapshot_digest": self.reconcile_snapshot_digest,
            "authority_graph_digest": self.authority_graph_digest,
            "expected_edge_count": self.expected_edge_count,
            "foreign_edge_count": 0,
            "unknown_edge_count": 0,
            "mutating_authority_count": 0,
            "coverage_complete": True,
            "provider_derived": True,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "aws_mutation_performed": False,
            "lambda_invocation_performed": False,
            "live_effect_authorized": False,
        }
        value["evidence_digest"] = canonical_digest(value)
        return value


@dataclass(frozen=True, slots=True)
class _ValidatedSnapshot:
    digest: str
    started_at: datetime
    completed_at: datetime
    expires_at: datetime
    lambda_inventory: Mapping[str, Any]
    iam_inventory: Mapping[str, Any]
    iam_digest: str
    function_surface_digest: str


def collect_provider_invocation_snapshots(
    *,
    adapter: AwsReadOnlyInventoryAdapter,
    binding: RepairInvocationAuthorityBinding,
    scan_id: str,
    ttl_minutes: int = 5,
) -> ProviderInvocationSnapshots:
    """Collect all three raw snapshots with the reviewed GUG-218 adapter."""

    if _SCAN_ID.fullmatch(scan_id) is None:
        raise AuthorityInventoryError("SCAN_ID_INVALID")
    plan = adapter.collect(
        binding=binding.plan_binding,
        scan_id=f"{scan_id}:plan",
        expected_collector_principal_digest=binding.collector_principal_digest,
        ttl_minutes=ttl_minutes,
    )
    repair = adapter.collect(
        binding=binding.repair_binding,
        scan_id=f"{scan_id}:repair",
        expected_collector_principal_digest=binding.collector_principal_digest,
        ttl_minutes=ttl_minutes,
    )
    reconcile = adapter.collect(
        binding=binding.reconcile_binding,
        scan_id=f"{scan_id}:reconcile",
        expected_collector_principal_digest=binding.collector_principal_digest,
        ttl_minutes=ttl_minutes,
    )
    return ProviderInvocationSnapshots(
        scan_id=scan_id,
        plan=plan,
        repair=repair,
        reconcile=reconcile,
    )


def _surface_items(snapshot: Mapping[str, Any]) -> dict[str, list[Any]]:
    lambda_inventory = snapshot.get("lambda")
    iam_inventory = snapshot.get("iam")
    if not isinstance(lambda_inventory, Mapping) or not isinstance(
        iam_inventory, Mapping
    ):
        raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    for key in (
        "functions",
        "aliases",
        "versions",
        "function_urls",
        "resource_policies",
        "event_source_mappings",
        "event_invoke_configs",
    ):
        if not isinstance(lambda_inventory.get(key), list):
            raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    for key in ("users", "groups", "roles", "policies"):
        if not isinstance(iam_inventory.get(key), list):
            raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    if not isinstance(iam_inventory.get("managed_policy_documents"), Mapping):
        raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    enabled_regions = snapshot.get("enabled_regions")
    if not isinstance(enabled_regions, list):
        raise AuthorityInventoryError("INVENTORY_SNAPSHOT_MALFORMED")
    return {
        "region_discovery": list(enabled_regions),
        "lambda_functions": list(lambda_inventory["functions"]),
        "lambda_aliases": list(lambda_inventory["aliases"]),
        "lambda_versions": list(lambda_inventory["versions"]),
        "lambda_function_urls": list(lambda_inventory["function_urls"]),
        "lambda_resource_policies": list(lambda_inventory["resource_policies"]),
        "lambda_event_source_mappings": [
            *lambda_inventory["event_source_mappings"],
            *lambda_inventory["event_invoke_configs"],
        ],
        "iam_account_authorization": [
            *iam_inventory["users"],
            *iam_inventory["groups"],
            *iam_inventory["roles"],
            *iam_inventory["policies"],
            iam_inventory["managed_policy_documents"],
        ],
    }


def _normalized_collection_digest(items: Sequence[Any]) -> str:
    return canonical_digest(sorted((canonical_digest(item) for item in items)))


def _iam_digest(iam_inventory: Mapping[str, Any]) -> str:
    return canonical_digest(
        {
            "users": _normalized_collection_digest(iam_inventory["users"]),
            "groups": _normalized_collection_digest(iam_inventory["groups"]),
            "roles": _normalized_collection_digest(iam_inventory["roles"]),
            "policies": _normalized_collection_digest(iam_inventory["policies"]),
            "managed_policy_documents": canonical_digest(
                iam_inventory["managed_policy_documents"]
            ),
        }
    )


def _validate_snapshot(
    *,
    snapshot: Mapping[str, Any],
    binding: RepairInvocationAuthorityBinding,
    target: TargetBinding,
    expected_nonce: str,
    decision_at: str,
) -> _ValidatedSnapshot:
    if snapshot.get("snapshot_format") != RAW_SNAPSHOT_FORMAT:
        raise AuthorityInventoryError("SNAPSHOT_FORMAT_INVALID")
    snapshot_digest = snapshot.get("snapshot_digest")
    if (
        not isinstance(snapshot_digest, str)
        or DIGEST.fullmatch(snapshot_digest) is None
        or _seal_raw_snapshot(snapshot)["snapshot_digest"] != snapshot_digest
    ):
        raise AuthorityInventoryError("SNAPSHOT_DIGEST_MISMATCH")
    if snapshot.get("collector_nonce") != expected_nonce:
        raise AuthorityInventoryError("COLLECTOR_NONCE_MISMATCH")

    collector_arn = _canonical_sts_principal_arn(
        snapshot.get("collector_principal_arn"),
        partition=binding.partition,
        account_id=binding.authority_account_id,
    )
    collector_digest = snapshot.get("collector_principal_arn_digest")
    if (
        snapshot.get("collector_principal_arn") != collector_arn
        or collector_digest != digest_text(collector_arn)
        or collector_digest != binding.collector_principal_digest
    ):
        raise AuthorityInventoryError("COLLECTOR_PRINCIPAL_NOT_ALLOWLISTED")

    started_at = _parse_time(
        snapshot.get("capture_started_at"), "SCAN_STARTED_AT_INVALID"
    )
    completed_at = _parse_time(
        snapshot.get("capture_completed_at"), "SCAN_COMPLETED_AT_INVALID"
    )
    expires_at = _parse_time(
        snapshot.get("capture_expires_at"), "EXPIRES_AT_INVALID"
    )
    decision = _parse_time(decision_at, "DECISION_AT_INVALID")
    if (
        not (started_at <= completed_at <= decision < expires_at)
        or completed_at - started_at > timedelta(minutes=5)
        or expires_at - completed_at > timedelta(minutes=5)
        or decision - completed_at > timedelta(minutes=5)
    ):
        raise AuthorityInventoryError("INVENTORY_TIME_WINDOW_INVALID")

    enabled_regions = snapshot.get("enabled_regions")
    scanned_regions = snapshot.get("scanned_regions")
    if (
        not isinstance(enabled_regions, list)
        or not isinstance(scanned_regions, list)
        or enabled_regions != sorted(set(enabled_regions))
        or scanned_regions != sorted(set(scanned_regions))
        or enabled_regions != scanned_regions
        or binding.region not in enabled_regions
    ):
        raise AuthorityInventoryError("REGION_COVERAGE_INCOMPLETE")

    surface_items = _surface_items(snapshot)
    coverage = snapshot.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != set(COVERAGE_SURFACES):
        raise AuthorityInventoryError("COVERAGE_INCOMPLETE")
    for name in COVERAGE_SURFACES:
        entry = coverage[name]
        items = surface_items[name]
        if (
            not isinstance(entry, Mapping)
            or entry.get("status") not in COVERAGE_STATUSES
            or not isinstance(entry.get("page_count"), int)
            or entry["page_count"] < 0
            or not isinstance(entry.get("item_count"), int)
            or entry["item_count"] < 0
            or not isinstance(entry.get("evidence_digest"), str)
            or DIGEST.fullmatch(entry["evidence_digest"]) is None
        ):
            raise AuthorityInventoryError("COVERAGE_MALFORMED")
        if entry["status"] != "COMPLETE":
            raise AuthorityInventoryError("COVERAGE_NOT_COMPLETE")
        if (
            entry["item_count"] != len(items)
            or entry["evidence_digest"] != canonical_digest(items)
        ):
            raise AuthorityInventoryError("COVERAGE_EVIDENCE_MISMATCH")

    lambda_inventory = snapshot["lambda"]
    functions = lambda_inventory["functions"]
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("FunctionName"), str)
        or not isinstance(item.get("FunctionArn"), str)
        for item in functions
    ):
        raise AuthorityInventoryError("LAMBDA_FUNCTION_INVENTORY_MALFORMED")
    matching_functions = [
        item
        for item in functions
        if item.get("FunctionName") == target.function_name
        and item.get("FunctionArn") == target.function_arn
    ]
    if len(matching_functions) != 1:
        raise AuthorityInventoryError("TARGET_FUNCTION_INVENTORY_MISMATCH")
    function_arns = [
        item.get("FunctionArn")
        for item in functions
        if isinstance(item, Mapping)
    ]
    if len(function_arns) != len(set(function_arns)):
        raise AuthorityInventoryError("FUNCTION_INVENTORY_DUPLICATE")

    aliases = lambda_inventory["aliases"]
    expected_aliases = EXPECTED_ALIASES[target.function_name]
    observed_aliases: set[str] = set()
    for alias in aliases:
        if not isinstance(alias, Mapping):
            raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
        name = alias.get("Name")
        version = alias.get("FunctionVersion")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or re.fullmatch(r"[1-9][0-9]*", version) is None
            or alias.get("FunctionArn") != f"{target.function_arn}:{name}"
            or name in observed_aliases
        ):
            raise AuthorityInventoryError("LAMBDA_ALIAS_INVENTORY_MALFORMED")
        observed_aliases.add(name)
    if observed_aliases != set(expected_aliases):
        raise AuthorityInventoryError("LAMBDA_ALIAS_SET_MISMATCH")

    versions = lambda_inventory["versions"]
    observed_versions: set[str] = set()
    for version in versions:
        if not isinstance(version, Mapping):
            raise AuthorityInventoryError("LAMBDA_VERSION_INVENTORY_MALFORMED")
        value = version.get("Version")
        if (
            not isinstance(value, str)
            or (
                value != "$LATEST"
                and re.fullmatch(r"[1-9][0-9]*", value) is None
            )
            or version.get("FunctionArn") != f"{target.function_arn}:{value}"
            or value in observed_versions
        ):
            raise AuthorityInventoryError("LAMBDA_VERSION_INVENTORY_MALFORMED")
        observed_versions.add(value)
    if "$LATEST" not in observed_versions:
        raise AuthorityInventoryError("LAMBDA_VERSION_INVENTORY_MALFORMED")

    for forbidden_surface in (
        "function_urls",
        "resource_policies",
        "event_source_mappings",
        "event_invoke_configs",
    ):
        if lambda_inventory[forbidden_surface]:
            raise AuthorityInventoryError("FOREIGN_INVOCATION_SURFACE_PRESENT")

    iam_inventory = snapshot["iam"]
    return _ValidatedSnapshot(
        digest=snapshot_digest,
        started_at=started_at,
        completed_at=completed_at,
        expires_at=expires_at,
        lambda_inventory=lambda_inventory,
        iam_inventory=iam_inventory,
        iam_digest=_iam_digest(iam_inventory),
        function_surface_digest=canonical_digest(
            {
                "functions": _normalized_collection_digest(functions),
                "aliases": _normalized_collection_digest(aliases),
                "versions": _normalized_collection_digest(
                    versions
                ),
            }
        ),
    )


def _validate_invoker_role(
    binding: RepairInvocationAuthorityBinding, iam: Mapping[str, Any]
) -> None:
    matching_roles: list[Mapping[str, Any]] = []
    expected_prefix = (
        f"arn:{binding.partition}:iam::{binding.authority_account_id}:role/"
        "aws-reserved/sso.amazonaws.com/"
    )
    for role in iam["roles"]:
        if not isinstance(role, Mapping) or not isinstance(role.get("Arn"), str):
            raise AuthorityInventoryError("IAM_AUTHORIZATION_DETAILS_MALFORMED")
        arn = role["Arn"]
        if not arn.startswith(expected_prefix):
            continue
        role_name = arn.rsplit("/", 1)[-1]
        if _SSO_ROLE_NAME.fullmatch(role_name):
            matching_roles.append(role)
    if (
        len(matching_roles) != 1
        or matching_roles[0].get("Arn") != binding.invoker_role_arn
    ):
        raise AuthorityInventoryError("INVOKER_ROLE_SET_MISMATCH")
    role = matching_roles[0]
    if role.get("PermissionsBoundary") is not None:
        raise AuthorityInventoryError("INVOKER_ROLE_BOUNDARY_PRESENT")

    trust = _strict_policy_document(role.get("AssumeRolePolicyDocument"))
    statements = _statements(trust)
    if len(statements) != 1:
        raise AuthorityInventoryError("INVOKER_SAML_TRUST_MISMATCH")
    statement = statements[0]
    try:
        actions = set(
            _strict_string_list(
                statement.get("Action"), "INVOKER_SAML_TRUST_MISMATCH"
            )
        )
        principals = _principal_values(statement.get("Principal"))
    except AuthorityInventoryError as exc:
        raise AuthorityInventoryError("INVOKER_SAML_TRUST_MISMATCH") from exc
    if (
        statement.get("Effect") != "Allow"
        or actions != {"sts:AssumeRoleWithSAML", "sts:TagSession"}
        or principals != (("Federated", binding.saml_provider_arn),)
        or statement.get("Condition")
        != {"StringEquals": {"SAML:aud": _SAML_AUDIENCE}}
    ):
        raise AuthorityInventoryError("INVOKER_SAML_TRUST_MISMATCH")


def _target_candidates(
    target: TargetBinding,
    lambda_inventory: Mapping[str, Any],
    statement_resources: Sequence[str],
) -> tuple[str, ...]:
    candidates = set(_observed_invocation_resources(target, lambda_inventory))
    for resource in statement_resources:
        if (
            not any(character in resource for character in "*?[")
            and resource.startswith(target.function_arn + ":")
        ):
            candidates.add(resource)
    return tuple(sorted(candidates))


def _policy_authority_edges(
    binding: RepairInvocationAuthorityBinding,
    plan: _ValidatedSnapshot,
    repair: _ValidatedSnapshot,
    reconcile: _ValidatedSnapshot,
) -> tuple[tuple[str, str, str, str, str], ...]:
    targets = (
        (binding.plan_binding, plan.lambda_inventory),
        (binding.repair_binding, repair.lambda_inventory),
        (binding.reconcile_binding, reconcile.lambda_inventory),
    )
    expected_resources = binding.expected_resources
    observed: list[tuple[str, str, str, str, str]] = []

    for actor, source_type, _source_name, document in _policy_sources(
        repair.iam_inventory
    ):
        source_digest = canonical_digest(document)
        for statement in _statements(document):
            try:
                if _has_unknown_authority_action(statement):
                    raise AuthorityInventoryError(
                        "POLICY_SEMANTICS_UNSUPPORTED"
                    )
                actions = _allowed_sensitive_actions(statement)
            except AuthorityInventoryError as exc:
                raise AuthorityInventoryError(
                    "POLICY_SEMANTICS_UNSUPPORTED"
                ) from exc
            if not actions:
                continue
            try:
                resources = _statement_resource_values(statement)
            except AuthorityInventoryError as exc:
                raise AuthorityInventoryError(
                    "POLICY_SEMANTICS_UNSUPPORTED"
                ) from exc

            for action in actions:
                if (
                    action in IAM_MUTATION_ACTIONS
                    or action in CLOUDFORMATION_MUTATION_ACTIONS
                ):
                    raise AuthorityInventoryError("AUTHORITY_MUTATION_PRESENT")

                for target, lambda_inventory in targets:
                    if action in LAMBDA_MUTATION_ACTIONS and any(
                        _is_target_function_pattern(target, resource)
                        for resource in resources
                    ):
                        raise AuthorityInventoryError(
                            "AUTHORITY_MUTATION_PRESENT"
                        )
                    for resource in _target_candidates(
                        target, lambda_inventory, resources
                    ):
                        try:
                            applies = _resource_applies(statement, resource)
                        except AuthorityInventoryError as exc:
                            raise AuthorityInventoryError(
                                "POLICY_SEMANTICS_UNSUPPORTED"
                            ) from exc
                        if not applies:
                            continue
                        if action in LAMBDA_MUTATION_ACTIONS:
                            raise AuthorityInventoryError(
                                "AUTHORITY_MUTATION_PRESENT"
                            )
                        if action not in INVOCATION_ACTIONS:
                            raise AuthorityInventoryError(
                                "POLICY_SEMANTICS_UNSUPPORTED"
                            )
                        condition = _condition_class(
                            statement.get("Condition"), action
                        )
                        edge = (
                            actor,
                            source_type,
                            action,
                            resource,
                            source_digest,
                        )
                        if (
                            actor != binding.invoker_role_arn
                            or source_type != "IAM_ROLE_INLINE_POLICY"
                            or action != "lambda:InvokeFunction"
                            or resource not in expected_resources
                            or condition != "MISSING"
                            or source_digest != binding.invoker_policy_digest
                        ):
                            raise AuthorityInventoryError(
                                "FOREIGN_INVOCATION_AUTHORITY"
                            )
                        observed.append(edge)

    unique = set(observed)
    if len(observed) != len(unique):
        raise AuthorityInventoryError("DUPLICATE_INVOCATION_AUTHORITY")
    expected = {
        (
            binding.invoker_role_arn,
            "IAM_ROLE_INLINE_POLICY",
            "lambda:InvokeFunction",
            resource,
            binding.invoker_policy_digest,
        )
        for resource in expected_resources
    }
    if unique != expected:
        raise AuthorityInventoryError("EXPECTED_INVOCATION_AUTHORITY_MISSING")
    return tuple(sorted(unique))


def verify_provider_invocation_authority(
    *,
    binding: RepairInvocationAuthorityBinding,
    snapshots: ProviderInvocationSnapshots,
    decision_at: str,
    evidence_source_mode: str = EVIDENCE_SOURCE_AWS_READ_ONLY,
) -> VerifiedRepairInvocationAuthority:
    """Verify exact account-wide invocation authority or fail closed."""

    if evidence_source_mode != EVIDENCE_SOURCE_AWS_READ_ONLY:
        raise AuthorityInventoryError("UNVERIFIED_EVIDENCE_SOURCE")
    if _SCAN_ID.fullmatch(snapshots.scan_id) is None:
        raise AuthorityInventoryError("SCAN_ID_INVALID")
    plan = _validate_snapshot(
        snapshot=snapshots.plan,
        binding=binding,
        target=binding.plan_binding,
        expected_nonce=f"{snapshots.scan_id}:plan",
        decision_at=decision_at,
    )
    repair = _validate_snapshot(
        snapshot=snapshots.repair,
        binding=binding,
        target=binding.repair_binding,
        expected_nonce=f"{snapshots.scan_id}:repair",
        decision_at=decision_at,
    )
    reconcile = _validate_snapshot(
        snapshot=snapshots.reconcile,
        binding=binding,
        target=binding.reconcile_binding,
        expected_nonce=f"{snapshots.scan_id}:reconcile",
        decision_at=decision_at,
    )
    if (
        plan.completed_at > repair.started_at
        or repair.completed_at > reconcile.started_at
    ):
        raise AuthorityInventoryError("CAPTURE_ORDER_INVALID")
    if len({plan.iam_digest, repair.iam_digest, reconcile.iam_digest}) != 1:
        raise AuthorityInventoryError("IAM_AUTHORITY_CHANGED_DURING_CAPTURE")
    if len(
        {
            plan.function_surface_digest,
            repair.function_surface_digest,
            reconcile.function_surface_digest,
        }
    ) != 3:
        raise AuthorityInventoryError("TARGET_SNAPSHOT_SUBSTITUTION_DETECTED")

    _validate_invoker_role(binding, plan.iam_inventory)
    edges = _policy_authority_edges(binding, plan, repair, reconcile)
    authority_graph_digest = canonical_digest(
        {
            "binding_digest": binding.binding_digest,
            "iam_digest": plan.iam_digest,
            "plan_function_surface_digest": plan.function_surface_digest,
            "repair_function_surface_digest": repair.function_surface_digest,
            "reconcile_function_surface_digest": (
                reconcile.function_surface_digest
            ),
            "edge_digests": sorted(canonical_digest(edge) for edge in edges),
        }
    )
    expires_at = min(plan.expires_at, repair.expires_at, reconcile.expires_at)
    return VerifiedRepairInvocationAuthority(
        binding_digest=binding.binding_digest,
        collector_principal_digest=binding.collector_principal_digest,
        plan_snapshot_digest=plan.digest,
        repair_snapshot_digest=repair.digest,
        reconcile_snapshot_digest=reconcile.digest,
        authority_graph_digest=authority_graph_digest,
        expected_edge_count=EXPECTED_AUTHORITY_EDGE_COUNT,
        verified_at=decision_at,
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
    )


def require_stable_authority(
    before: VerifiedRepairInvocationAuthority,
    after: VerifiedRepairInvocationAuthority,
) -> None:
    """Fail when provider authority changed across a protected boundary."""

    if (
        before.status != VERIFIED_STATUS
        or after.status != VERIFIED_STATUS
        or before.binding_digest != after.binding_digest
        or before.collector_principal_digest != after.collector_principal_digest
        or before.authority_graph_digest != after.authority_graph_digest
    ):
        raise AuthorityInventoryError("AUTHORITY_CHANGED_DURING_EXECUTION")
