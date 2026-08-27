"""Private, owner-approved input discovery for the GUG-392 live lane.

This module closes the gap between reviewed GUG-363/GUG-365 source plans and
the complete GUG-392 Authority/Identity Center inputs.  Historical plans are
accepted only as selectors.  Current AWS facts must come from a fresh,
create-only preflight and must be approved by exact digest before any GUG-392
input or plan is materialized.

The module contains no AWS client construction.  The reviewed GUG-392 CLI and
provider remain the sole connected entrypoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import platform
import re
import threading
from typing import Any, Callable, Mapping, Sequence

from tooling import platform_authority_retirement_entrypoint_materializer as gug363
from tooling import (
    platform_authority_retirement_entrypoint_service_role_materializer as gug365,
)
from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    TARGETS as AUTHORITY_TARGET_FIELDS,
    CollectorError,
    certify_live as certify_authority_live,
    private_target_absent,
    read_private_json,
    render_policy as render_authority_policy,
    validate_live_generated_identity_center_roles,
    write_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    APPLICATION_DESCRIPTION,
    APPLICATION_GRANT,
    APPLICATION_SCOPE,
    EXACT_TAGS,
    LIVE_PRIVATE_FIELDS as IDENTITY_PRIVATE_FIELDS,
    NAMES as PERMISSION_SET_NAMES,
    PERMISSION_DESCRIPTIONS,
    POLICY_SHA256 as IDENTITY_POLICY_SHA256,
    POLICY_TARGET_FIELDS as IDENTITY_TARGET_FIELDS,
    bind_live_discovery_transition,
    certify_live as certify_identity_live,
    plan_binding as identity_plan_binding,
    valid_live_owner_application_contract,
)
from tooling.platform_authority_gug376_live_request_materializer import (
    LiveRequestMaterializationError,
    materialize_live_plans,
    private_root_binding_digest,
    render_application_actor_policy,
    render_permission_set_inline_policies,
    valid_identity_center_exact_facts,
)
import tooling.platform_authority_gug376_live_request_materializer as live_materializer
from tooling.platform_authority_gug393_discovery_budget import (
    DiscoveryBudgetError,
    HARD_MAX_CREDENTIAL_VENDING_CALLS,
    HARD_MAX_NETWORK_CALLS,
    HARD_MAX_PAGE_CALLS,
    HARD_MAX_PROVIDER_CALLS,
    HARD_MAX_TOTAL_RESPONSE_BYTES,
    NANO_USD_PER_USD,
    SUMMARY_RECORD_TYPE,
    ValidatedDiscoveryBudget,
    validate_discovery_budget,
)


IMPLEMENTATION_ISSUE = "GUG-393"
PARENT_ISSUE = "GUG-376"
LIVE_ISSUE = "GUG-392"
REGION = "us-east-1"
REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_BUNDLE_TYPE = (
    "scanalyze.platform_authority.gug393_private_input_source_bundle.v1"
)
SOURCE_CONTRACT_TYPE = (
    "scanalyze.platform_authority.gug393_private_input_source_contract.v1"
)
REQUEST_TYPE = "scanalyze.platform_authority.gug393_discovery_request.v2"
CHECKPOINT_TYPE = "scanalyze.platform_authority.gug393_discovery_checkpoint.v2"
CLAIM_TYPE = "scanalyze.platform_authority.gug393_discovery_claim.v1"
PROPOSAL_TYPE = "scanalyze.platform_authority.gug393_private_input_candidate.v1"
DECISION_TYPE = (
    "scanalyze.platform_authority.gug393_private_input_owner_decision.v1"
)
MANIFEST_TYPE = (
    "scanalyze.platform_authority.gug393_private_input_materialization_manifest.v1"
)
OPT_IN = "DISCOVER_GUG392_PRIVATE_INPUTS_READ_ONLY"
DEFAULT_REQUEST_FILE = "gug393-discovery-request.json"
DEFAULT_CHECKPOINT_FILE = "gug393-discovery-checkpoint.json"
DEFAULT_CLAIM_FILE = "gug393-discovery-claim.json"
DEFAULT_PROPOSAL_FILE = "gug393-private-input-proposal.json"
DEFAULT_DECISION_FILE = "gug393-private-input-owner-decision.json"
DEFAULT_MANIFEST_FILE = "gug393-private-input-materialization-manifest.json"
DEFAULT_AUTHORITY_INPUT_FILE = "gug392-authority-plan-input.json"
DEFAULT_IDENTITY_INPUT_FILE = "gug392-identity-center-plan-input.json"
DEFAULT_AUTHORITY_PLAN_FILE = "gug392-authority-plan.json"
DEFAULT_IDENTITY_PLAN_FILE = "gug392-identity-center-plan.json"
AUTHORITY_SNAPSHOT_FILES = (
    "gug393-authority-snapshot-1.json",
    "gug393-authority-snapshot-2.json",
)
IDENTITY_SNAPSHOT_FILES = (
    "gug393-identity-center-snapshot-1.json",
    "gug393-identity-center-snapshot-2.json",
)
RESERVED_LIFECYCLE_OUTPUT_FILES = frozenset(
    {
        *AUTHORITY_SNAPSHOT_FILES,
        *IDENTITY_SNAPSHOT_FILES,
        DEFAULT_CLAIM_FILE,
        DEFAULT_PROPOSAL_FILE,
        DEFAULT_DECISION_FILE,
        DEFAULT_MANIFEST_FILE,
        DEFAULT_AUTHORITY_INPUT_FILE,
        DEFAULT_IDENTITY_INPUT_FILE,
        DEFAULT_AUTHORITY_PLAN_FILE,
        DEFAULT_IDENTITY_PLAN_FILE,
    }
)
MAX_WINDOW = timedelta(minutes=15)
MAX_DECISION_WINDOW = timedelta(minutes=15)
MAX_PROPOSAL_REVIEW_DELAY = timedelta(minutes=15)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ROLE_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
_STS_ARN = re.compile(
    r"^arn:aws:sts::(?P<account>[0-9]{12}):"
    r"assumed-role/[A-Za-z0-9+=,.@_/-]+/[A-Za-z0-9+=,.@_-]+$"
)
_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:(?P<account>[0-9]{12}):key/[A-Za-z0-9-]{8,128}$"
)
_APPLICATION_ARN = re.compile(
    r"^arn:aws:sso::(?P<account>[0-9]{12}):application/"
    r"(?P<instance>ssoins-[A-Za-z0-9.-]{16})/[A-Za-z0-9-]+$"
)
_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/(?P<instance>ssoins-[A-Za-z0-9.-]{16})$"
)
_STORE_ARN = re.compile(
    r"^arn:aws:identitystore:::identitystore/(?P<store>d-[0-9a-f]{10})$"
)
_PROVIDER_ARN = re.compile(
    r"^arn:aws:sso::aws:applicationProvider/[A-Za-z0-9/-]+$"
)
_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_USD = re.compile(r"^(0|[1-9][0-9]*)\.([0-9]{9})$")
_FORBIDDEN_PROFILE_FRAGMENTS = (
    "administrator",
    "admin",
    "bootstrap",
    "seed",
    "deploy",
    "destroy",
)
_PLACEHOLDER_FRAGMENTS = (
    "replace",
    "placeholder",
    "synthetic",
    "example.invalid",
    "<",
    ">${",
    "${",
)
_ABSENT_ROLE_SUFFIX = "0000000000000000"
_CAPABILITY_SENTINEL = object()
_SOURCE_CONTRACT_SENTINEL = object()
_MATERIALIZATION_SENTINEL = object()
_REQUEST_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "parent_issue",
        "live_issue",
        "opt_in",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract",
        "source_contract_digest",
        "profiles",
        "profile_binding_digest",
        "discovery_budget",
        "budget_digest",
        "sdk_runtime_root",
        "sdk_runtime_root_digest",
        "private_root_digest",
        "host_digest",
        "region",
        "not_before",
        "expires_at",
        "approval_reference_digest",
        "request_file",
        "owner_checkpoint_file",
        "read_only",
        "aws_mutations",
        "deployment_authorized",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "owner_checkpoint_digest",
        "request_digest",
    }
)
_CHECKPOINT_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "parent_issue",
        "live_issue",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "request_digest",
        "profile_binding_digest",
        "budget_digest",
        "sdk_runtime_root_digest",
        "private_root_digest",
        "host_digest",
        "not_before",
        "expires_at",
        "approval_reference_digest",
        "request_file",
        "owner_checkpoint_file",
        "read_only",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "checkpoint_digest",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "source_commit_sha",
        "source_tree_sha",
        "request_digest",
        "checkpoint_digest",
        "approval_reference_digest",
        "request_file",
        "owner_checkpoint_file",
        "private_root_digest",
        "host_digest",
        "provider_binding_digest",
        "policy_binding_digest",
        "claimed_at",
        "read_only",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "claim_digest",
    }
)
_STORED_PROFILE_FIELDS = frozenset(
    {
        "name",
        "source",
        "chain_depth",
        "expected_account_id",
        "expected_principal_arn",
        "expected_sso_role_name",
        "authority_verification_digest",
        "expected_principal_digest",
        "expected_sso_role_name_digest",
    }
)
_DECISION_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "proposal_digest",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "request_digest",
        "budget_digest",
        "private_root_digest",
        "host_digest",
        "approval_reference_digest",
        "approved_at",
        "expires_at",
        "read_only",
        "aws_mutations",
        "deployment_authorized",
        "production_status",
        "decision_digest",
    }
)
_PROPOSAL_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "parent_issue",
        "live_issue",
        "status",
        "classification",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "request_digest",
        "checkpoint_digest",
        "request_file",
        "owner_checkpoint_file",
        "claim_digest",
        "approval_reference_digest",
        "budget_digest",
        "discovery_budget",
        "private_root_digest",
        "host_digest",
        "provider_summary",
        "provider_transcript",
        "authority_snapshot_digests",
        "identity_center_snapshot_digests",
        "authority_input",
        "identity_center_input",
        "authority_plan",
        "identity_center_plan",
        "not_before",
        "expires_at",
        "created_at",
        "read_only",
        "aws_mutations",
        "deployment_authorized",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "proposal_digest",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "implementation_issue",
        "parent_issue",
        "live_issue",
        "proposal_digest",
        "decision_digest",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "request_digest",
        "budget_digest",
        "private_root_digest",
        "host_digest",
        "artifact_digests",
        "authority_input_file",
        "identity_center_input_file",
        "authority_plan_file",
        "identity_center_plan_file",
        "decision_file",
        "manifest_file",
        "materialized_at",
        "read_only",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "manifest_digest",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "classification",
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "proposal_digest",
        "budget_digest",
        "network_calls",
        "provider_calls",
        "credential_vending_calls",
        "page_calls",
        "projected_response_bytes",
        "modeled_cost_usd_upper",
        "cost_status",
        "transcript_digest",
        "missing_input_categories",
        "live_provider_evidence",
        "read_only",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "receipt_digest",
    }
)


class PrivateInputDiscoveryError(RuntimeError):
    """Stable, public-safe GUG-393 failure."""

    def __init__(self, code: str) -> None:
        self.code = (
            code
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code)
            else "GUG393_PRIVATE_INPUT_DISCOVERY_BLOCKED"
        )
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise PrivateInputDiscoveryError(code)


def _copy(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception as exc:
        raise PrivateInputDiscoveryError(code) from exc


def _name(value: Any, code: str) -> str:
    if not isinstance(value, str) or _FILE_NAME.fullmatch(value) is None:
        _fail(code)
    return value


def _request_artifact_names(
    request_file: Any, owner_checkpoint_file: Any
) -> tuple[str, str]:
    request_name = _name(request_file, "DISCOVERY_REQUEST_FILE_INVALID")
    checkpoint_name = _name(
        owner_checkpoint_file, "DISCOVERY_CHECKPOINT_FILE_INVALID"
    )
    if (
        request_name == checkpoint_name
        or {request_name, checkpoint_name} & RESERVED_LIFECYCLE_OUTPUT_FILES
    ):
        _fail("PRIVATE_OUTPUT_COLLISION")
    return request_name, checkpoint_name


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _nano_usd(value: Any, code: str) -> int:
    if not isinstance(value, str) or (match := _USD.fullmatch(value)) is None:
        _fail(code)
    return int(match.group(1)) * NANO_USD_PER_USD + int(match.group(2))


def _format_nano_usd(value: int) -> str:
    if type(value) is not int or value < 0:
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    whole, fractional = divmod(value, NANO_USD_PER_USD)
    return f"{whole}.{fractional:09d}"


def _validate_provider_evidence(
    *,
    provider_summary: Mapping[str, Any],
    provider_transcript: Mapping[str, Any],
    discovery_budget: Mapping[str, Any],
    expected_budget_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    try:
        validated_budget = validate_discovery_budget(discovery_budget)
    except DiscoveryBudgetError as exc:
        raise PrivateInputDiscoveryError(
            "DISCOVERY_BUDGET_BINDING_INVALID"
        ) from exc
    _digest(expected_budget_digest, "DISCOVERY_BUDGET_BINDING_INVALID")
    budget = validated_budget.document
    if validated_budget.digest != expected_budget_digest:
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")

    summary = _copy(provider_summary, "DISCOVERY_BUDGET_BINDING_INVALID")
    summary_fields = {
        "record_type",
        "budget_digest",
        "cost_model_digest",
        "provider_calls",
        "credential_vending_calls",
        "network_calls",
        "page_calls",
        "projected_response_bytes",
        "modeled_cost_nano_usd",
        "summary_digest",
    }
    scalar_fields = (
        "provider_calls",
        "credential_vending_calls",
        "network_calls",
        "page_calls",
        "projected_response_bytes",
        "modeled_cost_nano_usd",
    )
    if (
        not isinstance(summary, dict)
        or set(summary) != summary_fields
        or any(
            type(summary.get(key)) is not int or summary[key] < 0
            for key in scalar_fields
        )
    ):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")

    transcript = _copy(
        provider_transcript, "PROVIDER_TRANSCRIPT_MISMATCH"
    )
    if (
        not isinstance(transcript, dict)
        or set(transcript)
        != {
            "provider_calls",
            "aws_calls",
            "aws_mutations",
            "live_provider_evidence",
            "transcript_digest",
        }
        or type(transcript.get("provider_calls")) is not int
        or transcript.get("provider_calls") != summary["provider_calls"]
        or type(transcript.get("aws_calls")) is not int
        or transcript.get("aws_calls") != summary["provider_calls"]
        or type(transcript.get("aws_mutations")) is not int
        or transcript.get("aws_mutations") != 0
        or transcript.get("live_provider_evidence") is not True
        or _DIGEST.fullmatch(str(transcript.get("transcript_digest"))) is None
    ):
        _fail("PROVIDER_TRANSCRIPT_MISMATCH")

    model = budget["cost_model"]
    modeled_cost = (
        _nano_usd(
            model["fixed_run_cost_usd_upper"],
            "DISCOVERY_BUDGET_BINDING_INVALID",
        )
        + summary["network_calls"]
        * _nano_usd(
            model["per_network_attempt_cost_usd_upper"],
            "DISCOVERY_BUDGET_BINDING_INVALID",
        )
        + summary["projected_response_bytes"]
        * _nano_usd(
            model["per_projected_response_byte_cost_usd_upper"],
            "DISCOVERY_BUDGET_BINDING_INVALID",
        )
    )
    if (
        summary.get("record_type") != SUMMARY_RECORD_TYPE
        or summary.get("budget_digest") != expected_budget_digest
        or summary.get("cost_model_digest") != canonical_digest(model)
        or summary["provider_calls"] < 1
        or summary["network_calls"]
        != summary["provider_calls"] + summary["credential_vending_calls"]
        or summary["provider_calls"] > budget["max_provider_calls"]
        or summary["credential_vending_calls"]
        > budget["max_credential_vending_calls"]
        or summary["network_calls"] > budget["max_network_calls"]
        or summary["page_calls"] > budget["max_page_calls"]
        or summary["page_calls"] > summary["provider_calls"]
        or summary["projected_response_bytes"]
        > budget["max_total_response_bytes"]
        or summary["modeled_cost_nano_usd"] != modeled_cost
        or modeled_cost
        > _nano_usd(
            budget["maximum_cost_usd"],
            "DISCOVERY_BUDGET_BINDING_INVALID",
        )
        or summary.get("summary_digest")
        != canonical_digest(
            {
                key: item
                for key, item in summary.items()
                if key != "summary_digest"
            }
        )
    ):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    return summary, transcript, modeled_cost


def _parse_stamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PrivateInputDiscoveryError(code) from exc
    parsed = parsed.astimezone(UTC).replace(microsecond=0)
    if _stamp(parsed) != value:
        _fail(code)
    return parsed


def _checked_clock(value: Any, code: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _fail(code)
    return value.astimezone(UTC).replace(microsecond=0)


def _private_root_digest(private_root: Path) -> str:
    try:
        return private_root_binding_digest(private_root)
    except LiveRequestMaterializationError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc


def _stamp(value: datetime) -> str:
    checked = _checked_clock(value, "DISCOVERY_WINDOW_INVALID")
    return (
        checked.isoformat().replace("+00:00", "Z")
    )


def _window(start: Any, end: Any, *, now: datetime | None = None) -> tuple[str, str]:
    start_time = _parse_stamp(start, "DISCOVERY_WINDOW_INVALID")
    end_time = _parse_stamp(end, "DISCOVERY_WINDOW_INVALID")
    if not start_time < end_time or end_time - start_time > MAX_WINDOW:
        _fail("DISCOVERY_WINDOW_INVALID")
    if now is not None:
        checked_now = _checked_clock(now, "DISCOVERY_WINDOW_INVALID")
        if not start_time <= checked_now < end_time:
            _fail("PROPOSAL_EXPIRED")
    return _stamp(start_time), _stamp(end_time)


def _assert_no_placeholder(
    value: Any,
    *,
    code: str = "PLACEHOLDER_FORBIDDEN",
    allow_absence_role: bool = False,
) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _assert_no_placeholder(key, code=code)
            _assert_no_placeholder(
                item,
                code=code,
                allow_absence_role=(
                    allow_absence_role
                    or str(key).endswith("generated_role_arn")
                ),
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            _assert_no_placeholder(item, code=code)
        return
    if not isinstance(value, str):
        return
    folded = value.casefold()
    if any(fragment in folded for fragment in _PLACEHOLDER_FRAGMENTS):
        _fail(code)
    if _DIGEST.fullmatch(value) and value == "sha256:" + "0" * 64:
        _fail(code)
    if (
        _ACCOUNT.fullmatch(value)
        and value in {"000000000000", "111122223333", "444455556666"}
    ):
        _fail(code)
    if _ABSENT_ROLE_SUFFIX in value and not allow_absence_role:
        _fail(code)


def _self_digest(value: Mapping[str, Any], field: str, code: str) -> None:
    if value.get(field) != canonical_digest(
        {key: item for key, item in value.items() if key != field}
    ):
        _fail(code)


def _profile(value: Any, *, domain: str) -> dict[str, Any]:
    expected = {
        "name",
        "source",
        "chain_depth",
        "expected_account_id",
        "expected_principal_arn",
        "expected_sso_role_name",
        "authority_verification_digest",
    }
    profile = _copy(value, "PROFILE_BINDING_INVALID")
    if not isinstance(profile, dict) or set(profile) != expected:
        _fail("PROFILE_BINDING_INVALID")
    name = profile["name"]
    role_name = profile["expected_sso_role_name"]
    account = profile["expected_account_id"]
    principal = profile["expected_principal_arn"]
    principal_match = _STS_ARN.fullmatch(str(principal))
    normalized = re.sub(r"[^a-z0-9]", "", str(role_name).casefold())
    if (
        not isinstance(name, str)
        or _PROFILE.fullmatch(name) is None
        or name.casefold() == "default"
        or any(fragment in name.casefold() for fragment in _FORBIDDEN_PROFILE_FRAGMENTS)
        or profile["source"] != "DIRECT_SSO"
        or type(profile["chain_depth"]) is not int
        or profile["chain_depth"] != 0
        or not isinstance(account, str)
        or _ACCOUNT.fullmatch(account) is None
        or principal_match is None
        or principal_match.group("account") != account
        or not isinstance(role_name, str)
        or _ROLE_NAME.fullmatch(role_name) is None
        or any(fragment in normalized for fragment in _FORBIDDEN_PROFILE_FRAGMENTS)
        or _DIGEST.fullmatch(str(profile["authority_verification_digest"]))
        is None
    ):
        _fail("PROFILE_BINDING_INVALID")
    _assert_no_placeholder(profile)
    profile["domain"] = domain
    profile["expected_principal_digest"] = canonical_digest(principal)
    profile["expected_sso_role_name_digest"] = canonical_digest(role_name)
    return profile


def _stored_profiles(value: Any) -> dict[str, dict[str, Any]]:
    supplied = _copy(value, "PROFILE_BINDING_INVALID")
    if not isinstance(supplied, dict) or set(supplied) != {
        "authority",
        "identity_center",
    }:
        _fail("PROFILE_BINDING_INVALID")
    checked: dict[str, dict[str, Any]] = {}
    for domain, profile in supplied.items():
        if not isinstance(profile, dict) or set(profile) != _STORED_PROFILE_FIELDS:
            _fail("PROFILE_BINDING_INVALID")
        original = {
            key: item
            for key, item in profile.items()
            if key
            not in {
                "expected_principal_digest",
                "expected_sso_role_name_digest",
            }
        }
        derived = _profile(original, domain=domain)
        derived.pop("domain")
        if derived != profile:
            _fail("PROFILE_BINDING_INVALID")
        checked[domain] = derived
    if (
        checked["authority"]["name"].casefold()
        == checked["identity_center"]["name"].casefold()
        or checked["authority"]["expected_account_id"]
        == checked["identity_center"]["expected_account_id"]
    ):
        _fail("PROFILE_BINDING_INVALID")
    return checked


def _object_arn(value: Mapping[str, Any]) -> str:
    return f"arn:aws:s3:::{value['bucket']}/{value['key']}"


def _unversioned_signing_profile_arn(version_arn: str) -> str:
    match = re.fullmatch(
        r"(?P<base>arn:aws:signer:us-east-1:[0-9]{12}:"
        r"/signing-profiles/[A-Za-z0-9_.-]+)/[A-Za-z0-9]{10}",
        version_arn,
    )
    if match is None:
        _fail("SOURCE_SELECTOR_MISSING")
    return match.group("base")


def _selector(value: str, *, artifact_digest: str, pointer: str) -> dict[str, str]:
    return {
        "artifact_digest": artifact_digest,
        "json_pointer": pointer,
        "value_digest": canonical_digest(value),
    }


class DerivedSourceContract:
    """Opaque result minted only after both reviewed source plans validate."""

    __slots__ = ("_token", "_document")

    def __init__(self, token: object, document: Mapping[str, Any]) -> None:
        if token is not _SOURCE_CONTRACT_SENTINEL:
            _fail("SOURCE_CONTRACT_DERIVATION_REQUIRED")
        self._token = token
        self._document = _copy(document, "SOURCE_CONTRACT_INVALID")

    @property
    def document(self) -> dict[str, Any]:
        return _copy(self._document, "SOURCE_CONTRACT_INVALID")


def derive_source_contract(
    *,
    source_bundle: Mapping[str, Any],
    source_commit_sha: str,
    source_tree_sha: str,
    repo_root: Path = REPO_ROOT,
) -> DerivedSourceContract:
    """Derive the exact private candidates from current reviewed plans.

    GUG-363/GUG-365 classifications and observations are never consumed here;
    only their deterministic selectors are accepted after complete recompilation.
    """

    bundle = _copy(source_bundle, "SOURCE_BUNDLE_INVALID")
    fields = {
        "record_type",
        "schema_version",
        "gug363_plan",
        "gug365_plan",
        "identity_center_application_name",
        "identity_center_application_provider_arn",
        "identity_center_kms_key_arn",
        "source_bundle_digest",
    }
    if (
        not isinstance(bundle, dict)
        or set(bundle) != fields
        or bundle.get("record_type") != SOURCE_BUNDLE_TYPE
        or bundle.get("schema_version") != 1
    ):
        _fail("SOURCE_BUNDLE_INVALID")
    _self_digest(bundle, "source_bundle_digest", "SOURCE_BUNDLE_INVALID")
    commit = _sha(source_commit_sha, "SOURCE_BINDING_MISMATCH")
    tree = _sha(source_tree_sha, "SOURCE_BINDING_MISMATCH")
    plan363 = bundle["gug363_plan"]
    plan365 = bundle["gug365_plan"]
    if not isinstance(plan363, Mapping) or not isinstance(plan365, Mapping):
        _fail("SOURCE_BUNDLE_INVALID")
    try:
        gug363.validate_materialization_plan(plan363, repo_root=repo_root)
        factory_contract = plan365["ledger_factory_artifact_signing_contract"]
        factory_digest = plan365[
            "ledger_factory_artifact_signing_contract_digest"
        ]
        gug365.validate_service_role_materialization_plan(
            plan365,
            gug363_plan=plan363,
            expected_gug363_plan_digest=str(plan363["plan_digest"]),
            ledger_factory_artifact_signing_contract=factory_contract,
            expected_ledger_factory_artifact_signing_contract_digest=str(
                factory_digest
            ),
            repo_root=repo_root,
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("SOURCE_BINDING_MISMATCH") from exc
    source = plan363.get("source")
    if not isinstance(source, Mapping):
        _fail("SOURCE_BINDING_MISMATCH")
    selector_commit = _sha(
        source.get("commit"), "SOURCE_BINDING_MISMATCH"
    )
    selector_tree = _sha(source.get("tree"), "SOURCE_BINDING_MISMATCH")

    try:
        parameters = plan363["parameters"]
        broker_contract = plan363["artifact_signing_contract"]
        broker_unsigned = broker_contract["unsigned_source"]
        broker_signed = broker_contract["signed_destination"]
        factory_unsigned = factory_contract["unsigned_source"]
        factory_signed = factory_contract["signed_destination"]
        factory_function = plan365["ledger_factory_function"]
        source_roles = {
            "retire_approve": parameters["ApproverPermissionSetRoleArn"],
            "retire_class": parameters["ClassifierPermissionSetRoleArn"],
        }
        authority_account = parameters["AuthorityAccountId"]
        identity_store_arn = parameters["IdentityStoreArn"]
        identity_instance_arn = parameters["IdentityCenterInstanceArn"]
        identity_application_arn = parameters["IdentityCenterApplicationArn"]
        redirect_uri = parameters["IdentityCenterRedirectUri"]
        approved_user_id = parameters["ApproverIdentityStoreUserId"]
        if parameters["ClassifierIdentityStoreUserId"] != approved_user_id:
            _fail("CROSS_DOMAIN_BINDING_INVALID")
    except (KeyError, TypeError) as exc:
        raise PrivateInputDiscoveryError("SOURCE_SELECTOR_MISSING") from exc

    buckets = {
        str(item["bucket"])
        for item in (
            broker_unsigned,
            broker_signed,
            factory_unsigned,
            factory_signed,
        )
    }
    kms_keys = {
        str(item["sse_kms_key_arn"])
        for item in (
            broker_unsigned,
            broker_signed,
            factory_unsigned,
            factory_signed,
        )
    }
    if len(buckets) != 1 or len(kms_keys) != 1:
        _fail("SOURCE_BINDING_MISMATCH")
    bucket = next(iter(buckets))
    artifact_kms = next(iter(kms_keys))
    authority_targets = {
        "artifact_bucket_arn": f"arn:aws:s3:::{bucket}",
        "broker_signed_object_arn": _object_arn(broker_signed),
        "broker_unsigned_object_arn": _object_arn(broker_unsigned),
        "ledger_factory_signed_object_arn": _object_arn(factory_signed),
        "ledger_factory_unsigned_object_arn": _object_arn(factory_unsigned),
        "artifact_kms_key_arn": artifact_kms,
        "signing_profile_arn": _unversioned_signing_profile_arn(
            str(broker_contract["signer"]["profile_version_arn"])
        ),
        "code_signing_config_arn": str(
            broker_contract["code_signing_config"]["arn"]
        ),
        "runtime_source_function_arn": str(factory_function["arn"]),
        "runtime_source_function_version_arn": str(
            factory_function["immutable_version_arn"]
        ),
        "retire_approve_generated_role_arn": str(source_roles["retire_approve"]),
        "retire_class_generated_role_arn": str(source_roles["retire_class"]),
    }
    if set(authority_targets) != set(AUTHORITY_TARGET_FIELDS):
        _fail("SOURCE_SELECTOR_MISSING")
    _assert_no_placeholder(authority_targets, allow_absence_role=True)

    store_match = _STORE_ARN.fullmatch(str(identity_store_arn))
    instance_match = _INSTANCE_ARN.fullmatch(str(identity_instance_arn))
    application_match = _APPLICATION_ARN.fullmatch(str(identity_application_arn))
    kms_match = _KMS_ARN.fullmatch(str(bundle["identity_center_kms_key_arn"]))
    if (
        store_match is None
        or instance_match is None
        or application_match is None
        or kms_match is None
        or application_match.group("instance") != instance_match.group("instance")
        or application_match.group("account") != kms_match.group("account")
        or _PROVIDER_ARN.fullmatch(
            str(bundle["identity_center_application_provider_arn"])
        )
        is None
        or not isinstance(bundle["identity_center_application_name"], str)
        or not 1 <= len(bundle["identity_center_application_name"]) <= 100
    ):
        _fail("SOURCE_SELECTOR_MISSING")
    identity_account = application_match.group("account")
    identity_store_id = store_match.group("store")
    actor_policy, actor_digest = render_application_actor_policy(
        authority_targets, authority_account_id=str(authority_account)
    )
    del actor_policy
    source_actor_digest = parameters["IdentityCenterApplicationActorPolicySha256"]
    if source_actor_digest != actor_digest:
        _fail("SOURCE_BINDING_MISMATCH")
    identity_private = {
        "application_actor_policy_digest": actor_digest,
        "application_name": str(bundle["identity_center_application_name"]),
        "application_provider_arn": str(
            bundle["identity_center_application_provider_arn"]
        ),
        "application_redirect_uri": str(redirect_uri),
        "approved_user_id": str(approved_user_id),
        "approved_single_operator_user_arn": (
            f"arn:aws:identitystore:::user/{identity_store_id}/{approved_user_id}"
        ),
        "authority_account_arn": f"arn:aws:sso:::account/{authority_account}",
        "identity_center_kms_key_arn": str(
            bundle["identity_center_kms_key_arn"]
        ),
        "identity_store_arn": str(identity_store_arn),
        "identity_store_id": identity_store_id,
    }
    if set(identity_private) != set(IDENTITY_PRIVATE_FIELDS):
        _fail("SOURCE_SELECTOR_MISSING")
    _assert_no_placeholder(identity_private)
    digest363 = str(plan363["plan_digest"])
    digest365 = str(plan365["plan_digest"])
    source_selectors = {
        key: _selector(
            value,
            artifact_digest=digest363 if not key.startswith("ledger_factory") else digest365,
            pointer=(
                f"/derived/authority_targets/{key}"
                if key not in {
                    "retire_approve_generated_role_arn",
                    "retire_class_generated_role_arn",
                }
                else (
                    "/gug363_plan/parameters/ApproverPermissionSetRoleArn"
                    if key.startswith("retire_approve")
                    else "/gug363_plan/parameters/ClassifierPermissionSetRoleArn"
                )
            ),
        )
        for key, value in authority_targets.items()
    }
    fixed_source = {
        "permission_set_names": list(PERMISSION_SET_NAMES),
        "permission_descriptions": dict(PERMISSION_DESCRIPTIONS),
        "application_description": APPLICATION_DESCRIPTION,
        "application_grant": APPLICATION_GRANT,
        "application_scope": APPLICATION_SCOPE,
        "exact_tags": [list(item) for item in EXACT_TAGS],
        "identity_policy_source_sha256": IDENTITY_POLICY_SHA256,
    }
    body: dict[str, Any] = {
        "record_type": SOURCE_CONTRACT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "live_issue": LIVE_ISSUE,
        "selector_source_commit_sha": selector_commit,
        "selector_source_tree_sha": selector_tree,
        "executor_source_commit_sha": commit,
        "executor_source_tree_sha": tree,
        "gug363_plan_digest": digest363,
        "gug365_plan_digest": digest365,
        "source_bundle_digest": bundle["source_bundle_digest"],
        "authority_account_id": str(authority_account),
        "identity_center_account_id": identity_account,
        "authority_targets": authority_targets,
        "identity_center_private_targets": identity_private,
        "identity_center_source_expectations": {
            "instance_arn": str(identity_instance_arn),
            "application_arn": str(identity_application_arn),
            "generated_role_arns": source_roles,
        },
        "selector_provenance": source_selectors,
        "fixed_source_digest": canonical_digest(fixed_source),
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    return DerivedSourceContract(
        _SOURCE_CONTRACT_SENTINEL,
        {**body, "source_contract_digest": canonical_digest(body)},
    )


@dataclass(frozen=True, slots=True)
class MaterializedDiscoveryRequest:
    request: dict[str, Any]
    owner_checkpoint: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DiscoveryProposal:
    private_candidate: dict[str, Any]
    public_receipt: dict[str, Any]


class MaterializedApprovedInputs:
    """Opaque, sealed, one-shot result of approved input materialization."""

    __slots__ = ("_consumed", "_digest", "_documents", "_lock", "_token")

    def __init__(
        self,
        token: object,
        *,
        authority_input: Mapping[str, Any],
        identity_center_input: Mapping[str, Any],
        authority_plan: Mapping[str, Any],
        identity_center_plan: Mapping[str, Any],
        owner_decision: Mapping[str, Any],
        manifest: Mapping[str, Any],
    ) -> None:
        if token is not _MATERIALIZATION_SENTINEL:
            _fail("DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED")
        self._token = token
        self._documents = _copy(
            {
                "authority_input": authority_input,
                "identity_center_input": identity_center_input,
                "authority_plan": authority_plan,
                "identity_center_plan": identity_center_plan,
                "owner_decision": owner_decision,
                "manifest": manifest,
            },
            "DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED",
        )
        self._digest = canonical_digest(self._documents)
        self._consumed = False
        self._lock = threading.Lock()

    def _document(self, name: str) -> dict[str, Any]:
        if self._token is not _MATERIALIZATION_SENTINEL:
            _fail("DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED")
        return _copy(
            self._documents[name],
            "DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED",
        )

    @property
    def authority_input(self) -> dict[str, Any]:
        return self._document("authority_input")

    @property
    def identity_center_input(self) -> dict[str, Any]:
        return self._document("identity_center_input")

    @property
    def authority_plan(self) -> dict[str, Any]:
        return self._document("authority_plan")

    @property
    def identity_center_plan(self) -> dict[str, Any]:
        return self._document("identity_center_plan")

    @property
    def owner_decision(self) -> dict[str, Any]:
        return self._document("owner_decision")

    @property
    def manifest(self) -> dict[str, Any]:
        return self._document("manifest")

    def _consume(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            if (
                self._token is not _MATERIALIZATION_SENTINEL
                or self._consumed
                or self._digest != canonical_digest(self._documents)
            ):
                _fail("DISCOVERY_MATERIALIZATION_CAPABILITY_CONSUMED")
            self._consumed = True
            return _copy(
                self._documents,
                "DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED",
            )


def materialize_discovery_request(
    *,
    source_contract: DerivedSourceContract,
    profiles: Mapping[str, Any],
    discovery_budget: Mapping[str, Any],
    sdk_runtime_root: str,
    private_root: Path,
    source_commit_sha: str,
    source_tree_sha: str,
    host_digest: str,
    not_before: str,
    expires_at: str,
    approval_reference_digest: str,
    request_file: str = DEFAULT_REQUEST_FILE,
    owner_checkpoint_file: str = DEFAULT_CHECKPOINT_FILE,
) -> MaterializedDiscoveryRequest:
    if (
        type(source_contract) is not DerivedSourceContract
        or source_contract._token is not _SOURCE_CONTRACT_SENTINEL
    ):
        _fail("SOURCE_CONTRACT_DERIVATION_REQUIRED")
    contract = source_contract.document
    if (
        not isinstance(contract, dict)
        or contract.get("record_type") != SOURCE_CONTRACT_TYPE
        or contract.get("source_contract_digest")
        != canonical_digest(
            {
                key: item
                for key, item in contract.items()
                if key != "source_contract_digest"
            }
        )
        or contract.get("executor_source_commit_sha") != source_commit_sha
        or contract.get("executor_source_tree_sha") != source_tree_sha
    ):
        _fail("SOURCE_CONTRACT_INVALID")
    if not isinstance(profiles, Mapping) or set(profiles) != {
        "authority",
        "identity_center",
    }:
        _fail("PROFILE_BINDING_INVALID")
    expanded_profiles = {
        domain: _profile(profiles[domain], domain=domain)
        for domain in ("authority", "identity_center")
    }
    checked_profiles = {
        domain: {
            key: value for key, value in profile.items() if key != "domain"
        }
        for domain, profile in expanded_profiles.items()
    }
    if (
        checked_profiles["authority"]["name"].casefold()
        == checked_profiles["identity_center"]["name"].casefold()
        or checked_profiles["authority"]["expected_account_id"]
        == checked_profiles["identity_center"]["expected_account_id"]
        or checked_profiles["authority"]["expected_account_id"]
        != contract["authority_account_id"]
        or checked_profiles["identity_center"]["expected_account_id"]
        != contract["identity_center_account_id"]
    ):
        _fail("PROFILE_BINDING_INVALID")
    try:
        checked_budget = validate_discovery_budget(
            discovery_budget,
            now=_parse_stamp(not_before, "DISCOVERY_WINDOW_INVALID"),
            require_active=True,
        )
        sdk_root, sdk_root_digest = live_materializer._sdk_runtime_root_binding(  # noqa: SLF001
            sdk_runtime_root
        )
        root_digest = private_root_binding_digest(private_root)
    except Exception as exc:
        code = getattr(exc, "code", "DISCOVERY_REQUEST_INVALID")
        raise PrivateInputDiscoveryError(str(code)) from exc
    start, end = _window(not_before, expires_at)
    request_name, checkpoint_name = _request_artifact_names(
        request_file, owner_checkpoint_file
    )
    _digest(host_digest, "HOST_BINDING_INVALID")
    _digest(approval_reference_digest, "APPROVAL_REFERENCE_INVALID")
    _assert_no_placeholder(host_digest, code="HOST_BINDING_INVALID")
    _assert_no_placeholder(
        approval_reference_digest, code="APPROVAL_REFERENCE_INVALID"
    )
    request_body: dict[str, Any] = {
        "record_type": REQUEST_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "live_issue": LIVE_ISSUE,
        "opt_in": OPT_IN,
        "source_commit_sha": _sha(
            source_commit_sha, "SOURCE_BINDING_MISMATCH"
        ),
        "source_tree_sha": _sha(source_tree_sha, "SOURCE_BINDING_MISMATCH"),
        "source_contract": contract,
        "source_contract_digest": contract["source_contract_digest"],
        "profiles": checked_profiles,
        "profile_binding_digest": canonical_digest(checked_profiles),
        "discovery_budget": checked_budget.document,
        "budget_digest": checked_budget.digest,
        "sdk_runtime_root": sdk_root,
        "sdk_runtime_root_digest": sdk_root_digest,
        "private_root_digest": root_digest,
        "host_digest": host_digest,
        "region": REGION,
        "not_before": start,
        "expires_at": end,
        "approval_reference_digest": approval_reference_digest,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    preliminary_request_digest = canonical_digest(request_body)
    checkpoint_body: dict[str, Any] = {
        "record_type": CHECKPOINT_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "live_issue": LIVE_ISSUE,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "source_contract_digest": contract["source_contract_digest"],
        "request_digest": preliminary_request_digest,
        "profile_binding_digest": request_body["profile_binding_digest"],
        "budget_digest": checked_budget.digest,
        "sdk_runtime_root_digest": sdk_root_digest,
        "private_root_digest": root_digest,
        "host_digest": host_digest,
        "not_before": start,
        "expires_at": end,
        "approval_reference_digest": approval_reference_digest,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    checkpoint = {
        **checkpoint_body,
        "checkpoint_digest": canonical_digest(checkpoint_body),
    }
    # The checkpoint binds the preliminary request body.  The final request
    # then binds the independently sealed checkpoint, avoiding a digest cycle.
    request_with_checkpoint = {
        **request_body,
        "owner_checkpoint_digest": checkpoint["checkpoint_digest"],
    }
    request = {
        **request_with_checkpoint,
        "request_digest": canonical_digest(request_with_checkpoint),
    }
    return MaterializedDiscoveryRequest(request=request, owner_checkpoint=checkpoint)


def _validate_request_pair(
    request: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    private_root: Path,
    now: datetime | None,
    require_active: bool,
) -> tuple[dict[str, Any], dict[str, Any], ValidatedDiscoveryBudget]:
    checked_request = _copy(request, "DISCOVERY_REQUEST_INVALID")
    checked_checkpoint = _copy(checkpoint, "DISCOVERY_CHECKPOINT_INVALID")
    if (
        not isinstance(checked_request, dict)
        or not isinstance(checked_checkpoint, dict)
        or set(checked_request) != _REQUEST_FIELDS
        or set(checked_checkpoint) != _CHECKPOINT_FIELDS
        or checked_request.get("record_type") != REQUEST_TYPE
        or checked_checkpoint.get("record_type") != CHECKPOINT_TYPE
        or checked_request.get("schema_version") != 2
        or checked_checkpoint.get("schema_version") != 2
        or checked_request.get("opt_in") != OPT_IN
        or checked_request.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or checked_checkpoint.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or checked_request.get("parent_issue") != PARENT_ISSUE
        or checked_checkpoint.get("parent_issue") != PARENT_ISSUE
        or checked_request.get("live_issue") != LIVE_ISSUE
        or checked_checkpoint.get("live_issue") != LIVE_ISSUE
        or checked_request.get("region") != REGION
        or any(
            item.get("read_only") is not True
            or type(item.get("aws_mutations")) is not int
            or item.get("aws_mutations") != 0
            or item.get("deployment_authorized") is not False
            or item.get("production_status") != "NO-GO"
            for item in (checked_request, checked_checkpoint)
        )
        or checked_request.get("two_human_status") != "NOT_PROVEN"
        or checked_request.get("independent_approval_present") is not False
    ):
        _fail("DISCOVERY_REQUEST_INVALID")
    request_digest = checked_request.get("request_digest")
    checkpoint_digest = checked_checkpoint.get("checkpoint_digest")
    _digest(request_digest, "DISCOVERY_REQUEST_INVALID")
    _digest(checkpoint_digest, "DISCOVERY_CHECKPOINT_INVALID")
    _assert_no_placeholder(
        checked_request.get("host_digest"), code="HOST_BINDING_INVALID"
    )
    _assert_no_placeholder(
        checked_request.get("approval_reference_digest"),
        code="APPROVAL_REFERENCE_INVALID",
    )
    if request_digest != canonical_digest(
        {
            key: item
            for key, item in checked_request.items()
            if key != "request_digest"
        }
    ):
        _fail("DISCOVERY_REQUEST_INVALID")
    if checkpoint_digest != canonical_digest(
        {
            key: item
            for key, item in checked_checkpoint.items()
            if key != "checkpoint_digest"
        }
    ):
        _fail("DISCOVERY_CHECKPOINT_INVALID")
    preliminary_request = {
        key: item
        for key, item in checked_request.items()
        if key not in {"owner_checkpoint_digest", "request_digest"}
    }
    if (
        checked_checkpoint.get("request_digest")
        != canonical_digest(preliminary_request)
        or checked_request.get("owner_checkpoint_digest") != checkpoint_digest
    ):
        _fail("DISCOVERY_CHECKPOINT_BINDING_MISMATCH")
    common = {
        "source_commit_sha",
        "source_tree_sha",
        "source_contract_digest",
        "profile_binding_digest",
        "budget_digest",
        "sdk_runtime_root_digest",
        "private_root_digest",
        "host_digest",
        "not_before",
        "expires_at",
        "approval_reference_digest",
        "request_file",
        "owner_checkpoint_file",
    }
    if any(checked_request.get(key) != checked_checkpoint.get(key) for key in common):
        _fail("DISCOVERY_CHECKPOINT_BINDING_MISMATCH")
    request_name, checkpoint_name = _request_artifact_names(
        checked_request.get("request_file"),
        checked_request.get("owner_checkpoint_file"),
    )
    if (
        request_name != checked_checkpoint.get("request_file")
        or checkpoint_name != checked_checkpoint.get("owner_checkpoint_file")
    ):
        _fail("DISCOVERY_CHECKPOINT_BINDING_MISMATCH")
    if checked_request.get("private_root_digest") != private_root_binding_digest(
        private_root
    ):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    start, end = _window(
        checked_request.get("not_before"),
        checked_request.get("expires_at"),
        now=now if require_active else None,
    )
    try:
        budget = validate_discovery_budget(
            checked_request.get("discovery_budget"),
            now=now,
            require_active=require_active,
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError(
            str(getattr(exc, "code", "DISCOVERY_BUDGET_INVALID"))
        ) from exc
    if budget.digest != checked_request.get("budget_digest"):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    model = budget.document["cost_model"]
    if (
        _parse_stamp(model["valid_from"], "DISCOVERY_BUDGET_BINDING_INVALID")
        > _parse_stamp(start, "DISCOVERY_WINDOW_INVALID")
        or _parse_stamp(model["valid_until"], "DISCOVERY_BUDGET_BINDING_INVALID")
        < _parse_stamp(end, "DISCOVERY_WINDOW_INVALID")
    ):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    try:
        sdk_root, sdk_digest = live_materializer._sdk_runtime_root_binding(  # noqa: SLF001
            checked_request.get("sdk_runtime_root")
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("AWS_SDK_RUNTIME_ROOT_INVALID") from exc
    if (
        sdk_root != checked_request.get("sdk_runtime_root")
        or sdk_digest != checked_request.get("sdk_runtime_root_digest")
    ):
        _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
    contract = checked_request.get("source_contract")
    if (
        not isinstance(contract, Mapping)
        or contract.get("record_type") != SOURCE_CONTRACT_TYPE
        or contract.get("executor_source_commit_sha")
        != checked_request.get("source_commit_sha")
        or contract.get("executor_source_tree_sha")
        != checked_request.get("source_tree_sha")
        or contract.get("source_contract_digest")
        != checked_request.get("source_contract_digest")
        or contract.get("source_contract_digest")
        != canonical_digest(
            {
                key: item
                for key, item in contract.items()
                if key != "source_contract_digest"
            }
        )
    ):
        _fail("SOURCE_CONTRACT_INVALID")
    profiles = _stored_profiles(checked_request.get("profiles"))
    if (
        canonical_digest(profiles) != checked_request.get("profile_binding_digest")
        or profiles["authority"]["expected_account_id"]
        != contract.get("authority_account_id")
        or profiles["identity_center"]["expected_account_id"]
        != contract.get("identity_center_account_id")
    ):
        _fail("PROFILE_BINDING_INVALID")
    _assert_no_placeholder(contract, allow_absence_role=True)
    return checked_request, checked_checkpoint, budget


def persist_discovery_request(
    private_root: Path, materialization: MaterializedDiscoveryRequest
) -> None:
    request = materialization.request
    checkpoint = materialization.owner_checkpoint
    _validate_request_pair(
        request,
        checkpoint,
        private_root=private_root,
        now=None,
        require_active=False,
    )
    try:
        for name in (
            request["request_file"],
            request["owner_checkpoint_file"],
            *RESERVED_LIFECYCLE_OUTPUT_FILES,
        ):
            private_target_absent(private_root, str(name))
        write_private_json(private_root, str(request["request_file"]), request)
        write_private_json(
            private_root,
            str(request["owner_checkpoint_file"]),
            checkpoint,
        )
        if read_private_json(private_root, str(request["request_file"])) != request:
            _fail("DISCOVERY_REQUEST_READBACK_MISMATCH")
        if (
            read_private_json(private_root, str(request["owner_checkpoint_file"]))
            != checkpoint
        ):
            _fail("DISCOVERY_CHECKPOINT_READBACK_MISMATCH")
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc


class DiscoveryExecutionCapability:
    """Opaque one-shot authority minted from the reviewed private pair."""

    __slots__ = (
        "_token",
        "_request_digest",
        "_request_document_digest",
        "_approved_request",
        "_checkpoint_digest",
        "_approval_reference_digest",
        "_source_commit_sha",
        "_source_tree_sha",
        "_private_root_digest",
        "_claim_digest",
        "_provider_binding_digest",
        "_policy_binding_digest",
        "_fixed_policy_digests",
        "_identity_plan_binding_digest",
        "_exact_policy_digests",
        "_exact_plan_binding_digests",
        "_exact_target_digests",
        "_authorized_sessions",
        "_validity_gate",
        "_lock",
        "_provider_bound",
        "_execution_started",
        "_proposal_built",
    )

    def __init__(
        self,
        token: object,
        *,
        request: Mapping[str, Any],
        checkpoint: Mapping[str, Any],
        claim: Mapping[str, Any],
        provider_binding_digest: str,
        policy_binding: Mapping[str, Any],
        validity_gate: Callable[[], None],
    ) -> None:
        if token is not _CAPABILITY_SENTINEL:
            _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
        self._token = token
        self._request_digest = request["request_digest"]
        self._request_document_digest = canonical_digest(request)
        self._approved_request = _copy(request, "DISCOVERY_REQUEST_INVALID")
        self._checkpoint_digest = checkpoint["checkpoint_digest"]
        self._approval_reference_digest = request["approval_reference_digest"]
        self._source_commit_sha = request["source_commit_sha"]
        self._source_tree_sha = request["source_tree_sha"]
        self._private_root_digest = request["private_root_digest"]
        self._claim_digest = claim["claim_digest"]
        self._provider_binding_digest = provider_binding_digest
        self._policy_binding_digest = policy_binding["policy_binding_digest"]
        self._fixed_policy_digests = {
            ("authority", "authority"): policy_binding[
                "authority_policy_digest"
            ],
            ("identity_center", "discovery"): policy_binding[
                "identity_discovery_policy_digest"
            ],
        }
        self._identity_plan_binding_digest = policy_binding[
            "identity_plan_binding_digest"
        ]
        self._exact_policy_digests: dict[int, str] = {}
        self._exact_plan_binding_digests: dict[int, str] = {}
        self._exact_target_digests: dict[int, str] = {}
        self._authorized_sessions: set[tuple[str, int, str]] = set()
        self._validity_gate = validity_gate
        self._lock = threading.Lock()
        self._provider_bound = False
        self._execution_started = False
        self._proposal_built = False


class _DiscoveryProviderCapabilityGate:
    """Callable custody gate plus exact one-shot session authorization."""

    __slots__ = ("_capability",)

    def __init__(self, capability: DiscoveryExecutionCapability) -> None:
        self._capability = capability

    def __call__(self) -> None:
        self._capability._validity_gate()

    def authorize_session(
        self,
        *,
        domain: str,
        capture_index: int,
        stage: str,
        policy_digest: str,
    ) -> None:
        _authorize_discovery_provider_session(
            self._capability,
            domain=domain,
            capture_index=capture_index,
            stage=stage,
            policy_digest=policy_digest,
        )


def _provider_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    profiles = request["profiles"]
    return {
        "sdk_runtime_root": request["sdk_runtime_root"],
        "authority_profile": profiles["authority"]["name"],
        "identity_center_profile": profiles["identity_center"]["name"],
        "authority_expected_account_id": profiles["authority"][
            "expected_account_id"
        ],
        "authority_expected_principal_digest": profiles["authority"][
            "expected_principal_digest"
        ],
        "authority_expected_sso_role_name_digest": profiles["authority"][
            "expected_sso_role_name_digest"
        ],
        "identity_expected_account_id": profiles["identity_center"][
            "expected_account_id"
        ],
        "identity_expected_principal_digest": profiles["identity_center"][
            "expected_principal_digest"
        ],
        "identity_expected_sso_role_name_digest": profiles["identity_center"][
            "expected_sso_role_name_digest"
        ],
        "authority_verification_digest": profiles["authority"][
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": profiles["identity_center"][
            "authority_verification_digest"
        ],
        "budget_digest": request["budget_digest"],
    }


def _plan_binding_digest(plan: Mapping[str, Any]) -> str:
    if not isinstance(plan, Mapping):
        _fail("DISCOVERY_POLICY_BINDING_INVALID")
    try:
        body = {
            key: (
                _stamp(value)
                if key in {"not_before", "not_after"}
                else _copy(value, "DISCOVERY_POLICY_BINDING_INVALID")
            )
            for key, value in plan.items()
        }
    except PrivateInputDiscoveryError:
        raise
    except Exception as exc:
        raise PrivateInputDiscoveryError(
            "DISCOVERY_POLICY_BINDING_INVALID"
        ) from exc
    return canonical_digest(body)


def _discovery_policy_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    authority_plan, identity_plan = provisional_discovery_plans(request)
    body = {
        "request_digest": request["request_digest"],
        "authority_plan_binding_digest": _plan_binding_digest(authority_plan),
        "authority_target_digest": canonical_digest(authority_plan["targets"]),
        "authority_policy_digest": authority_plan["expected_policy_digest"],
        "identity_plan_binding_digest": _plan_binding_digest(identity_plan),
        "identity_private_target_digest": canonical_digest(
            identity_plan["private_targets"]
        ),
        "identity_discovery_policy_digest": identity_plan[
            "expected_discovery_policy_digest"
        ],
    }
    return {**body, "policy_binding_digest": canonical_digest(body)}


def _validate_claim_document(
    candidate: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
) -> dict[str, Any]:
    claim = _copy(candidate, "DISCOVERY_CLAIM_BINDING_MISMATCH")
    if (
        not isinstance(claim, dict)
        or set(claim) != _CLAIM_FIELDS
        or claim.get("record_type") != CLAIM_TYPE
        or claim.get("schema_version") != 1
        or claim.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or claim.get("read_only") is not True
        or type(claim.get("aws_mutations")) is not int
        or claim.get("aws_mutations") != 0
        or claim.get("deployment_authorized") is not False
        or claim.get("production_status") != "NO-GO"
        or claim.get("claim_digest")
        != canonical_digest(
            {key: item for key, item in claim.items() if key != "claim_digest"}
        )
    ):
        _fail("DISCOVERY_CLAIM_BINDING_MISMATCH")
    for field in (
        "request_digest",
        "checkpoint_digest",
        "approval_reference_digest",
        "private_root_digest",
        "host_digest",
        "provider_binding_digest",
        "policy_binding_digest",
        "claim_digest",
    ):
        _digest(claim.get(field), "DISCOVERY_CLAIM_BINDING_MISMATCH")
    _sha(claim.get("source_commit_sha"), "DISCOVERY_CLAIM_BINDING_MISMATCH")
    _sha(claim.get("source_tree_sha"), "DISCOVERY_CLAIM_BINDING_MISMATCH")
    claimed_at = _parse_stamp(
        claim.get("claimed_at"), "DISCOVERY_CLAIM_BINDING_MISMATCH"
    )
    start, end = _window(request.get("not_before"), request.get("expires_at"))
    exact = {
        "source_commit_sha": request.get("source_commit_sha"),
        "source_tree_sha": request.get("source_tree_sha"),
        "request_digest": request.get("request_digest"),
        "checkpoint_digest": checkpoint.get("checkpoint_digest"),
        "approval_reference_digest": request.get("approval_reference_digest"),
        "request_file": request.get("request_file"),
        "owner_checkpoint_file": request.get("owner_checkpoint_file"),
        "private_root_digest": request.get("private_root_digest"),
        "host_digest": request.get("host_digest"),
        "provider_binding_digest": canonical_digest(_provider_binding(request)),
        "policy_binding_digest": _discovery_policy_binding(request)[
            "policy_binding_digest"
        ],
    }
    if (
        any(claim.get(key) != value for key, value in exact.items())
        or not _parse_stamp(start, "DISCOVERY_CLAIM_BINDING_MISMATCH")
        <= claimed_at
        < _parse_stamp(end, "DISCOVERY_CLAIM_BINDING_MISMATCH")
    ):
        _fail("DISCOVERY_CLAIM_BINDING_MISMATCH")
    _assert_no_placeholder(
        claim, code="DISCOVERY_CLAIM_BINDING_MISMATCH"
    )
    return claim


def read_and_claim_discovery_request(
    *,
    private_root: Path,
    request_file: str,
    owner_checkpoint_file: str,
    expected_request_digest: str,
    expected_checkpoint_digest: str,
    approval_reference_digest: str,
    source_commit_sha: str,
    source_tree_sha: str,
    host_digest: str,
    now: datetime,
    claim_file: str = DEFAULT_CLAIM_FILE,
) -> tuple[dict[str, Any], DiscoveryExecutionCapability]:
    request_name = _name(request_file, "DISCOVERY_REQUEST_FILE_INVALID")
    checkpoint_name = _name(
        owner_checkpoint_file, "DISCOVERY_CHECKPOINT_FILE_INVALID"
    )
    claim_name = _name(claim_file, "DISCOVERY_CLAIM_FILE_INVALID")
    if (
        claim_name != DEFAULT_CLAIM_FILE
        or len({request_name, checkpoint_name, claim_name}) != 3
    ):
        _fail("PRIVATE_OUTPUT_COLLISION")
    _digest(expected_request_digest, "DISCOVERY_APPROVAL_BINDING_MISMATCH")
    _digest(expected_checkpoint_digest, "DISCOVERY_APPROVAL_BINDING_MISMATCH")
    _digest(approval_reference_digest, "DISCOVERY_APPROVAL_BINDING_MISMATCH")
    _assert_no_placeholder(
        approval_reference_digest,
        code="DISCOVERY_APPROVAL_BINDING_MISMATCH",
    )
    _digest(host_digest, "HOST_BINDING_INVALID")
    _sha(source_commit_sha, "SOURCE_BINDING_MISMATCH")
    _sha(source_tree_sha, "SOURCE_BINDING_MISMATCH")
    if host_digest != operational_host_digest():
        _fail("HOST_BINDING_INVALID")
    try:
        request = read_private_json(private_root, request_name)
        checkpoint = read_private_json(private_root, checkpoint_name)
        request, checkpoint, _ = _validate_request_pair(
            request,
            checkpoint,
            private_root=private_root,
            now=now,
            require_active=True,
        )
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc
    exact = {
        "request_digest": expected_request_digest,
        "checkpoint_digest": expected_checkpoint_digest,
        "approval_reference_digest": approval_reference_digest,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "host_digest": host_digest,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
    }
    if any(request.get(key) != value for key, value in exact.items() if key in request):
        _fail("DISCOVERY_APPROVAL_BINDING_MISMATCH")
    if checkpoint.get("checkpoint_digest") != expected_checkpoint_digest:
        _fail("DISCOVERY_APPROVAL_BINDING_MISMATCH")
    try:
        for name in RESERVED_LIFECYCLE_OUTPUT_FILES - {claim_name}:
            private_target_absent(private_root, name)
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc
    binding = _provider_binding(request)
    binding_digest = canonical_digest(binding)
    policy_binding = _discovery_policy_binding(request)
    claim_body: dict[str, Any] = {
        "record_type": CLAIM_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "request_digest": expected_request_digest,
        "checkpoint_digest": expected_checkpoint_digest,
        "approval_reference_digest": approval_reference_digest,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
        "private_root_digest": request["private_root_digest"],
        "host_digest": host_digest,
        "provider_binding_digest": binding_digest,
        "policy_binding_digest": policy_binding["policy_binding_digest"],
        "claimed_at": _stamp(now),
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    claim = {**claim_body, "claim_digest": canonical_digest(claim_body)}
    try:
        private_target_absent(private_root, claim_name)
        write_private_json(private_root, claim_name, claim)
        if read_private_json(private_root, claim_name) != claim:
            _fail("DISCOVERY_CLAIM_READBACK_MISMATCH")
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc

    def validity_gate() -> None:
        observed_now = datetime.now(UTC).replace(microsecond=0)
        current_request = read_private_json(private_root, request_name)
        current_checkpoint = read_private_json(private_root, checkpoint_name)
        validated_request, validated_checkpoint, _ = _validate_request_pair(
            current_request,
            current_checkpoint,
            private_root=private_root,
            now=observed_now,
            require_active=True,
        )
        if (
            validated_request.get("request_digest")
            != request["request_digest"]
            or validated_checkpoint.get("checkpoint_digest")
            != checkpoint["checkpoint_digest"]
            or validated_request.get("approval_reference_digest")
            != request["approval_reference_digest"]
            or validated_request.get("source_commit_sha")
            != request["source_commit_sha"]
            or validated_request.get("source_tree_sha")
            != request["source_tree_sha"]
            or validated_request.get("host_digest")
            != operational_host_digest()
        ):
            _fail("DISCOVERY_CLAIM_BINDING_MISMATCH")
        current_claim = read_private_json(private_root, claim_name)
        if current_claim != claim:
            _fail("DISCOVERY_CLAIM_BINDING_MISMATCH")

    capability = DiscoveryExecutionCapability(
        _CAPABILITY_SENTINEL,
        request=request,
        checkpoint=checkpoint,
        claim=claim,
        provider_binding_digest=binding_digest,
        policy_binding=policy_binding,
        validity_gate=validity_gate,
    )
    return request, capability


def assert_preflight_provider_capability_bindings(
    capability: object, **bindings: Any
) -> _DiscoveryProviderCapabilityGate:
    if (
        type(capability) is not DiscoveryExecutionCapability
        or capability._token is not _CAPABILITY_SENTINEL  # type: ignore[attr-defined]
        or canonical_digest(bindings)
        != capability._provider_binding_digest  # type: ignore[attr-defined]
    ):
        _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
    with capability._lock:  # type: ignore[attr-defined]
        if capability._provider_bound:  # type: ignore[attr-defined]
            _fail("DISCOVERY_EXECUTION_CAPABILITY_CONSUMED")
        capability._provider_bound = True  # type: ignore[attr-defined]
    gate = _DiscoveryProviderCapabilityGate(capability)
    gate()
    return gate


def _authorize_discovery_provider_session(
    capability: DiscoveryExecutionCapability,
    *,
    domain: str,
    capture_index: int,
    stage: str,
    policy_digest: str,
) -> None:
    if (
        type(capability) is not DiscoveryExecutionCapability
        or capability._token is not _CAPABILITY_SENTINEL
        or type(capture_index) is not int
        or capture_index not in {1, 2}
        or (domain, stage)
        not in {
            ("authority", "authority"),
            ("identity_center", "discovery"),
            ("identity_center", "exact"),
        }
    ):
        _fail("DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED")
    _digest(policy_digest, "DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED")
    capability._validity_gate()
    session_key = (domain, capture_index, stage)
    with capability._lock:
        if (
            capability._provider_bound is not True
            or capability._execution_started is not True
            or capability._proposal_built is True
            or session_key in capability._authorized_sessions
        ):
            _fail("DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED")
        if stage == "exact":
            expected = capability._exact_policy_digests.get(capture_index)
            if (
                ("identity_center", capture_index, "discovery")
                not in capability._authorized_sessions
                or expected is None
                or capture_index
                not in capability._exact_plan_binding_digests
                or capture_index not in capability._exact_target_digests
            ):
                _fail("DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED")
        else:
            expected = capability._fixed_policy_digests.get((domain, stage))
        if policy_digest != expected:
            _fail("DISCOVERY_PROVIDER_POLICY_BINDING_MISMATCH")
        capability._authorized_sessions.add(session_key)
    capability._validity_gate()


def authorize_exact_identity_plan(
    capability: object,
    *,
    capture_index: int,
    provisional_plan: Mapping[str, Any],
    targets: Mapping[str, Any],
    transition_attestation: object,
) -> dict[str, Any]:
    """Bind one exact Identity policy to that capture's discovered targets."""

    if (
        type(capability) is not DiscoveryExecutionCapability
        or capability._token is not _CAPABILITY_SENTINEL  # type: ignore[attr-defined]
        or type(capture_index) is not int
        or capture_index not in {1, 2}
        or _plan_binding_digest(provisional_plan)
        != capability._identity_plan_binding_digest  # type: ignore[attr-defined]
    ):
        _fail("DISCOVERY_EXACT_POLICY_NOT_AUTHORIZED")
    capability._validity_gate()  # type: ignore[attr-defined]
    with capability._lock:  # type: ignore[attr-defined]
        if (
            capability._provider_bound is not True  # type: ignore[attr-defined]
            or capability._execution_started is not True  # type: ignore[attr-defined]
            or capability._proposal_built is True  # type: ignore[attr-defined]
            or (
                "identity_center",
                capture_index,
                "discovery",
            )
            not in capability._authorized_sessions  # type: ignore[attr-defined]
            or capture_index
            in capability._exact_policy_digests  # type: ignore[attr-defined]
        ):
            _fail("DISCOVERY_EXACT_POLICY_NOT_AUTHORIZED")
    try:
        from tooling.platform_authority_gug376_live_provider import (
            consume_identity_discovery_transition_attestation,
        )

        attested_discovery = (
            consume_identity_discovery_transition_attestation(
                transition_attestation,
                execution_capability=capability,
                capture_index=capture_index,
                expected_policy_digest=provisional_plan[
                    "expected_discovery_policy_digest"
                ],
            )
        )
        classification, attested_targets = bind_live_discovery_transition(
            provisional_plan, attested_discovery
        )
    except PrivateInputDiscoveryError:
        raise
    except Exception as exc:
        code = getattr(
            exc, "code", "DISCOVERY_TRANSITION_ATTESTATION_REQUIRED"
        )
        raise PrivateInputDiscoveryError(
            str(code)
        ) from exc
    if (
        classification != "DRIFT_BLOCKED_NO_REPAIR"
        or canonical_digest(attested_targets) != canonical_digest(targets)
    ):
        _fail("DISCOVERY_EXACT_POLICY_NOT_AUTHORIZED")
    exact_plan = exact_probe_identity_plan(
        provisional_plan, attested_targets
    )
    exact_policy_digest = exact_plan["expected_exact_policy_digest"]
    exact_plan_binding_digest = _plan_binding_digest(exact_plan)
    exact_target_digest = canonical_digest(attested_targets)
    with capability._lock:  # type: ignore[attr-defined]
        if (
            capability._provider_bound is not True  # type: ignore[attr-defined]
            or capability._execution_started is not True  # type: ignore[attr-defined]
            or capability._proposal_built is True  # type: ignore[attr-defined]
            or (
                "identity_center",
                capture_index,
                "discovery",
            )
            not in capability._authorized_sessions  # type: ignore[attr-defined]
            or capture_index
            in capability._exact_policy_digests  # type: ignore[attr-defined]
        ):
            _fail("DISCOVERY_EXACT_POLICY_NOT_AUTHORIZED")
        capability._exact_policy_digests[capture_index] = exact_policy_digest  # type: ignore[attr-defined]
        capability._exact_plan_binding_digests[capture_index] = (  # type: ignore[attr-defined]
            exact_plan_binding_digest
        )
        capability._exact_target_digests[capture_index] = (  # type: ignore[attr-defined]
            exact_target_digest
        )
    capability._validity_gate()  # type: ignore[attr-defined]
    return exact_plan


def claim_discovery_execution(capability: object) -> None:
    if type(capability) is not DiscoveryExecutionCapability:
        _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
    with capability._lock:  # type: ignore[attr-defined]
        if (
            not capability._provider_bound  # type: ignore[attr-defined]
            or capability._execution_started  # type: ignore[attr-defined]
        ):
            _fail("DISCOVERY_EXECUTION_CAPABILITY_CONSUMED")
        capability._execution_started = True  # type: ignore[attr-defined]
    capability._validity_gate()  # type: ignore[attr-defined]


def approved_discovery_request(capability: object) -> dict[str, Any]:
    """Return the frozen approved request before any discovery SDK call."""

    if (
        type(capability) is not DiscoveryExecutionCapability
        or capability._token is not _CAPABILITY_SENTINEL  # type: ignore[attr-defined]
    ):
        _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
    with capability._lock:  # type: ignore[attr-defined]
        if (
            capability._provider_bound is not True  # type: ignore[attr-defined]
            or capability._execution_started is True  # type: ignore[attr-defined]
        ):
            _fail("DISCOVERY_EXECUTION_CAPABILITY_CONSUMED")
        frozen = _copy(
            capability._approved_request,  # type: ignore[attr-defined]
            "DISCOVERY_REQUEST_INVALID",
        )
    capability._validity_gate()  # type: ignore[attr-defined]
    if (
        not isinstance(frozen, dict)
        or canonical_digest(frozen)
        != capability._request_document_digest  # type: ignore[attr-defined]
    ):
        _fail("DISCOVERY_REQUEST_INVALID")
    return frozen


def _assert_claimed_discovery_execution(
    capability: object, request: Mapping[str, Any]
) -> None:
    if (
        type(capability) is not DiscoveryExecutionCapability
        or capability._token is not _CAPABILITY_SENTINEL  # type: ignore[attr-defined]
        or capability._execution_started is not True  # type: ignore[attr-defined]
        or capability._request_digest  # type: ignore[attr-defined]
        != request.get("request_digest")
        or capability._checkpoint_digest  # type: ignore[attr-defined]
        != request.get("owner_checkpoint_digest")
        or capability._approval_reference_digest  # type: ignore[attr-defined]
        != request.get("approval_reference_digest")
        or capability._source_commit_sha  # type: ignore[attr-defined]
        != request.get("source_commit_sha")
        or capability._source_tree_sha  # type: ignore[attr-defined]
        != request.get("source_tree_sha")
        or request.get("request_digest")
        != canonical_digest(
            {key: item for key, item in request.items() if key != "request_digest"}
        )
        or capability._request_document_digest  # type: ignore[attr-defined]
        != canonical_digest(request)
    ):
        _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
    with capability._lock:  # type: ignore[attr-defined]
        required_sessions = {
            ("authority", 1, "authority"),
            ("authority", 2, "authority"),
            ("identity_center", 1, "discovery"),
            ("identity_center", 2, "discovery"),
        }
        exact_captures = set(  # type: ignore[attr-defined]
            capability._exact_policy_digests
        )
        exact_sessions = {
            ("identity_center", capture_index, "exact")
            for capture_index in exact_captures
        }
        if (
            capability._proposal_built  # type: ignore[attr-defined]
            or exact_captures not in (set(), {1, 2})
            or set(capability._exact_plan_binding_digests)  # type: ignore[attr-defined]
            != exact_captures
            or set(capability._exact_target_digests)  # type: ignore[attr-defined]
            != exact_captures
            or capability._authorized_sessions  # type: ignore[attr-defined]
            != required_sessions | exact_sessions
        ):
            _fail("DISCOVERY_EXECUTION_CAPABILITY_CONSUMED")
        capability._proposal_built = True  # type: ignore[attr-defined]
    capability._validity_gate()  # type: ignore[attr-defined]


def provisional_discovery_plans(request: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build policy-valid plans whose expected facts cannot be mistaken as truth."""

    contract = request["source_contract"]
    profiles = request["profiles"]
    start = _parse_stamp(request["not_before"], "DISCOVERY_WINDOW_INVALID")
    end = _parse_stamp(request["expires_at"], "DISCOVERY_WINDOW_INVALID")
    pending = canonical_digest(
        {
            "issue": IMPLEMENTATION_ISSUE,
            "state": "FRESH_DISCOVERY_REQUIRED",
            "request_digest": request["request_digest"],
        }
    )
    authority: dict[str, Any] = {
        "targets": _copy(contract["authority_targets"], "SOURCE_CONTRACT_INVALID"),
        "not_before": start,
        "not_after": end,
        "expected_policy_digest": pending,
        "expected_account_id": profiles["authority"]["expected_account_id"],
        "expected_principal_arn": profiles["authority"]["expected_principal_arn"],
        "authority_verification_digest": profiles["authority"][
            "authority_verification_digest"
        ],
        "expected_generated_role_trust_policy_digests": {
            key: canonical_digest(
                {"issue": IMPLEMENTATION_ISSUE, "pending": key}
            )
            for key in ("retire_approve", "retire_class")
        },
    }
    from tooling.platform_authority_gug376_authority_inventory_collector import (
        render_policy_candidate as render_authority_policy_candidate,
    )
    from tooling.platform_authority_gug376_identity_center_inventory_collector import (
        render_live_policy_candidate as render_identity_policy_candidate,
    )

    _, authority["expected_policy_digest"] = render_authority_policy_candidate(
        authority
    )
    identity: dict[str, Any] = {
        "private_targets": _copy(
            contract["identity_center_private_targets"],
            "SOURCE_CONTRACT_INVALID",
        ),
        "not_before": start,
        "not_after": end,
        "expected_account_id": profiles["identity_center"]["expected_account_id"],
        "expected_principal_arn": profiles["identity_center"][
            "expected_principal_arn"
        ],
        "authority_verification_digest": profiles["identity_center"][
            "authority_verification_digest"
        ],
        "expected_discovery_policy_digest": pending,
        "expected_exact_policy_digest": pending,
        "expected_target_digest": pending,
        "expected_facts_digest": pending,
    }
    _, identity["expected_discovery_policy_digest"] = (
        render_identity_policy_candidate(identity)
    )
    return authority, identity


def exact_probe_identity_plan(
    provisional_plan: Mapping[str, Any], targets: Mapping[str, Any]
) -> dict[str, Any]:
    from tooling.platform_authority_gug376_identity_center_inventory_collector import (
        render_live_policy_candidate as render_identity_policy_candidate,
    )

    if not isinstance(targets, Mapping) or set(targets) != set(IDENTITY_TARGET_FIELDS):
        _fail("IDENTITY_TARGET_PARTIAL")
    if not isinstance(provisional_plan, Mapping):
        _fail("IDENTITY_STATE_DRIFT")
    try:
        start = provisional_plan["not_before"]
        end = provisional_plan["not_after"]
        result = _copy(
            {
                key: item
                for key, item in provisional_plan.items()
                if key not in {"not_before", "not_after"}
            },
            "IDENTITY_STATE_DRIFT",
        )
    except KeyError as exc:
        raise PrivateInputDiscoveryError("IDENTITY_STATE_DRIFT") from exc
    result["not_before"] = start
    result["not_after"] = end
    result["expected_target_digest"] = canonical_digest(targets)
    _, result["expected_exact_policy_digest"] = render_identity_policy_candidate(
        result, targets
    )
    return result


def _absent_role_arn(account_id: str, permission_set_name: str) -> str:
    return (
        f"arn:aws:iam::{account_id}:role/aws-reserved/sso.amazonaws.com/"
        f"AWSReservedSSO_{permission_set_name}_{_ABSENT_ROLE_SUFFIX}"
    )


def _absent_trust_digests() -> dict[str, str]:
    return {
        key: canonical_digest(
            {
                "classification": "ABSENT_READY",
                "not_applicable": "generated-role-trust-policy",
                "role": key,
            }
        )
        for key in ("retire_approve", "retire_class")
    }


def _stable_pair(values: Sequence[Mapping[str, Any]], *, kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(values) != 2:
        _fail(f"{kind}_SNAPSHOT_SET_INVALID")
    first, second = (_copy(value, f"{kind}_SNAPSHOT_INVALID") for value in values)
    if (
        not isinstance(first, dict)
        or not isinstance(second, dict)
        or first.get("snapshot_digest") == second.get("snapshot_digest")
        or first.get("facts_digest") != second.get("facts_digest")
    ):
        _fail("DISCOVERY_UNCERTAIN_RECONCILE_ONLY")
    return first, second


def _derive_discovery_proposal(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_snapshots: Sequence[Mapping[str, Any]],
    now: datetime,
    provider_summary: Mapping[str, Any],
    provider_transcript: Mapping[str, Any],
    claim_digest: str,
) -> DiscoveryProposal:
    """Purely derive the proposal from the complete persisted evidence chain."""

    checked_request = _copy(request, "DISCOVERY_REQUEST_INVALID")
    if not isinstance(checked_request, dict):
        _fail("DISCOVERY_REQUEST_INVALID")
    request = checked_request
    _digest(claim_digest, "DISCOVERY_CLAIM_BINDING_MISMATCH")
    _window(request["not_before"], request["expires_at"], now=now)
    authority_plan, provisional_identity_plan = provisional_discovery_plans(request)
    authority_first, authority_second = _stable_pair(
        authority_snapshots, kind="AUTHORITY"
    )
    identity_first, identity_second = _stable_pair(
        identity_snapshots, kind="IDENTITY"
    )
    authority_surfaces = authority_second.get("surfaces")
    identity_facts = identity_second.get("facts")
    identity_targets = identity_second.get("targets")
    try:
        _, authority_policy_digest = render_authority_policy(authority_plan)
        authority_runtime_digest = canonical_digest(
            {
                "policy_digest": authority_policy_digest,
                "runtime_source_function_version_arn": authority_plan["targets"][
                    "runtime_source_function_version_arn"
                ],
            }
        )
        authority_receipt = certify_authority_live(
            authority_first,
            authority_second,
            expected_runtime_target_digest=authority_runtime_digest,
        )
        identity_policies = identity_second.get("policies")
        if not isinstance(identity_policies, Mapping):
            _fail("IDENTITY_STATE_DRIFT")
        if set(identity_policies) == {"discovery"}:
            certified_identity_plan = provisional_identity_plan
        elif set(identity_policies) == {"discovery", "exact"}:
            certified_identity_plan = exact_probe_identity_plan(
                provisional_identity_plan,
                identity_targets,
            )
        else:
            _fail("IDENTITY_STATE_DRIFT")
        _, expected_identity_binding = identity_plan_binding(
            certified_identity_plan
        )
        identity_receipt = certify_identity_live(
            identity_first,
            identity_second,
            expected_plan_binding_digest=expected_identity_binding,
        )
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc
    if (
        authority_receipt.get("stable") is not True
        or identity_receipt.get("stable") is not True
        or any(
            item.get("policy_digest") != authority_policy_digest
            or item.get("identity", {}).get("account_id")
            != authority_plan["expected_account_id"]
            or item.get("identity", {}).get("principal_arn")
            != authority_plan["expected_principal_arn"]
            or item.get("identity", {}).get("authority_verification_digest")
            != authority_plan["authority_verification_digest"]
            for item in (authority_first, authority_second)
        )
    ):
        _fail("DISCOVERY_UNCERTAIN_RECONCILE_ONLY")
    if not isinstance(authority_surfaces, Mapping):
        _fail("AUTHORITY_TARGET_DRIFT")
    if any(
        not isinstance(surface, Mapping) or surface.get("complete") is not True
        for surface in authority_surfaces.values()
    ):
        _fail("DISCOVERY_UNCERTAIN_RECONCILE_ONLY")
    if not isinstance(identity_facts, Mapping) or not isinstance(
        identity_targets, Mapping
    ):
        _fail("IDENTITY_STATE_DRIFT")
    contract = request["source_contract"]
    authority_targets = _copy(
        contract["authority_targets"], "SOURCE_CONTRACT_INVALID"
    )
    identity_discovery = identity_facts.get("discovery")
    if not isinstance(identity_discovery, Mapping):
        _fail("IDENTITY_STATE_DRIFT")
    applications = identity_discovery.get("applications")
    permission_sets = identity_discovery.get("permission_sets")
    instances = identity_discovery.get("instances")
    if not all(isinstance(value, list) for value in (applications, permission_sets, instances)):
        _fail("IDENTITY_STATE_DRIFT")
    if len(instances) != 1:
        _fail("IDENTITY_INSTANCE_MISSING" if not instances else "IDENTITY_INSTANCE_AMBIGUOUS")
    source_expectations = contract["identity_center_source_expectations"]
    if instances[0].get("instance_arn") != source_expectations["instance_arn"]:
        _fail("IDENTITY_STATE_DRIFT")
    absent = not applications and not permission_sets
    exact = len(applications) == 1 and len(permission_sets) == 2
    if not absent and not exact:
        _fail("IDENTITY_TARGET_PARTIAL")

    role_items = authority_surfaces.get("iam_roles", {}).get("items")
    if not isinstance(role_items, list):
        _fail("AUTHORITY_TARGET_DRIFT")
    if absent:
        if role_items:
            _fail("CROSS_DOMAIN_BINDING_INVALID")
        account = contract["authority_account_id"]
        authority_targets["retire_approve_generated_role_arn"] = _absent_role_arn(
            account, PERMISSION_SET_NAMES[0]
        )
        authority_targets["retire_class_generated_role_arn"] = _absent_role_arn(
            account, PERMISSION_SET_NAMES[1]
        )
        trust_digests = _absent_trust_digests()
        expected_state = {
            "classification": "ABSENT_READY",
            "instance": instances[0],
        }
    else:
        if (
            set(identity_targets) != set(IDENTITY_TARGET_FIELDS)
            or identity_targets.get("identity_center_application_arn")
            != source_expectations["application_arn"]
        ):
            _fail("IDENTITY_STATE_DRIFT")
        expected_roles = {
            str(value)
            for value in source_expectations["generated_role_arns"].values()
        }
        detailed = {
            item.get("role_arn"): item
            for item in role_items
            if isinstance(item, Mapping) and not item.get("collision")
        }
        if set(detailed) != expected_roles or any(
            isinstance(item, Mapping) and item.get("collision")
            for item in role_items
        ):
            _fail("CROSS_DOMAIN_BINDING_INVALID")
        try:
            trust_digests = {
                key: detailed[role_arn]["role"]["Role"][
                    "AssumeRolePolicyDocumentDigest"
                ]
                for key, role_arn in source_expectations[
                    "generated_role_arns"
                ].items()
            }
        except (KeyError, TypeError) as exc:
            raise PrivateInputDiscoveryError("AUTHORITY_TARGET_DRIFT") from exc
        if any(_DIGEST.fullmatch(str(value)) is None for value in trust_digests.values()):
            _fail("AUTHORITY_TARGET_DRIFT")
        private_targets = contract["identity_center_private_targets"]
        if not valid_identity_center_exact_facts(
            identity_facts, identity_targets, live=True
        ) or not valid_live_owner_application_contract(
            identity_facts, identity_targets, private_targets
        ):
            _fail("IDENTITY_STATE_DRIFT")
        try:
            rendered_permissions = render_permission_set_inline_policies(
                authority_account_id=str(contract["authority_account_id"]),
                identity_center_targets=identity_targets,
            )
            permissions = identity_facts["permission_sets"]
            if {
                name: permissions[name]["inline_policy"]["policy_digest"]
                for name in rendered_permissions
            } != {
                name: rendered[1]
                for name, rendered in rendered_permissions.items()
            }:
                _fail("CROSS_DOMAIN_BINDING_INVALID")
            role_policy_digests = {
                authority_targets["retire_approve_generated_role_arn"]: (
                    permissions[PERMISSION_SET_NAMES[0]]["inline_policy"][
                        "policy_digest"
                    ]
                ),
                authority_targets["retire_class_generated_role_arn"]: (
                    permissions[PERMISSION_SET_NAMES[1]]["inline_policy"][
                        "policy_digest"
                    ]
                ),
            }
            role_trust_digests = {
                authority_targets["retire_approve_generated_role_arn"]: (
                    trust_digests["retire_approve"]
                ),
                authority_targets["retire_class_generated_role_arn"]: (
                    trust_digests["retire_class"]
                ),
            }
            for snapshot in (authority_first, authority_second):
                validate_live_generated_identity_center_roles(
                    snapshot,
                    expected_role_policy_digests=role_policy_digests,
                    expected_role_trust_policy_digests=role_trust_digests,
                )
        except PrivateInputDiscoveryError:
            raise
        except (CollectorError, LiveRequestMaterializationError, KeyError, TypeError) as exc:
            raise PrivateInputDiscoveryError(
                "CROSS_DOMAIN_BINDING_INVALID"
            ) from exc
        expected_state = {
            "classification": "EXACT_PRESENT_NO_TOUCH",
            "targets": identity_targets,
            "facts": identity_facts,
        }

    private_targets = _copy(
        contract["identity_center_private_targets"], "SOURCE_CONTRACT_INVALID"
    )
    _, private_targets["application_actor_policy_digest"] = (
        render_application_actor_policy(
            authority_targets,
            authority_account_id=contract["authority_account_id"],
        )
    )
    authority_input = {
        "targets": authority_targets,
        "not_before": request["not_before"],
        "not_after": request["expires_at"],
        "expected_account_id": request["profiles"]["authority"][
            "expected_account_id"
        ],
        "expected_principal_arn": request["profiles"]["authority"][
            "expected_principal_arn"
        ],
        "authority_verification_digest": request["profiles"]["authority"][
            "authority_verification_digest"
        ],
        "expected_generated_role_trust_policy_digests": trust_digests,
    }
    identity_input = {
        "private_targets": private_targets,
        "not_before": request["not_before"],
        "not_after": request["expires_at"],
        "expected_account_id": request["profiles"]["identity_center"][
            "expected_account_id"
        ],
        "expected_principal_arn": request["profiles"]["identity_center"][
            "expected_principal_arn"
        ],
        "authority_verification_digest": request["profiles"]["identity_center"][
            "authority_verification_digest"
        ],
        "expected_state": expected_state,
    }
    try:
        plans = materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_input,
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("CROSS_DOMAIN_BINDING_INVALID") from exc
    budget = request["discovery_budget"]
    summary, transcript, modeled_cost = _validate_provider_evidence(
        provider_summary=provider_summary,
        provider_transcript=provider_transcript,
        discovery_budget=budget,
        expected_budget_digest=request["budget_digest"],
    )
    proposal_body: dict[str, Any] = {
        "record_type": PROPOSAL_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "live_issue": LIVE_ISSUE,
        "status": "READY_FOR_OWNER_DECISION",
        "classification": expected_state["classification"],
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "source_contract_digest": request["source_contract_digest"],
        "request_digest": request["request_digest"],
        "checkpoint_digest": request["owner_checkpoint_digest"],
        "request_file": request["request_file"],
        "owner_checkpoint_file": request["owner_checkpoint_file"],
        "claim_digest": claim_digest,
        "approval_reference_digest": request["approval_reference_digest"],
        "budget_digest": request["budget_digest"],
        "discovery_budget": budget,
        "private_root_digest": request["private_root_digest"],
        "host_digest": request["host_digest"],
        "provider_summary": summary,
        "provider_transcript": transcript,
        "authority_snapshot_digests": [
            authority_first["snapshot_digest"],
            authority_second["snapshot_digest"],
        ],
        "identity_center_snapshot_digests": [
            identity_first["snapshot_digest"],
            identity_second["snapshot_digest"],
        ],
        "authority_input": authority_input,
        "identity_center_input": identity_input,
        "authority_plan": plans.authority_plan,
        "identity_center_plan": plans.identity_center_plan,
        "not_before": request["not_before"],
        "expires_at": request["expires_at"],
        "created_at": _stamp(now),
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    proposal = {
        **proposal_body,
        "proposal_digest": canonical_digest(proposal_body),
    }
    receipt_body = {
        "record_type": "scanalyze.platform_authority.gug393_discovery_receipt.v1",
        "status": "READY_FOR_OWNER_DECISION",
        "classification": expected_state["classification"],
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "source_contract_digest": request["source_contract_digest"],
        "proposal_digest": proposal["proposal_digest"],
        "budget_digest": request["budget_digest"],
        "network_calls": summary["network_calls"],
        "provider_calls": summary["provider_calls"],
        "credential_vending_calls": summary["credential_vending_calls"],
        "page_calls": summary["page_calls"],
        "projected_response_bytes": summary["projected_response_bytes"],
        "modeled_cost_usd_upper": _format_nano_usd(modeled_cost),
        "cost_status": "COST_WITHIN_BOUND",
        "transcript_digest": transcript["transcript_digest"],
        "missing_input_categories": [],
        "live_provider_evidence": True,
        "read_only": True,
        "aws_calls": summary["provider_calls"],
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    receipt = {**receipt_body, "receipt_digest": canonical_digest(receipt_body)}
    return DiscoveryProposal(
        private_candidate=proposal,
        public_receipt=validate_public_discovery_receipt(receipt),
    )


def build_discovery_proposal(
    *,
    request: Mapping[str, Any],
    execution_capability: object,
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_snapshots: Sequence[Mapping[str, Any]],
    now: datetime,
    provider_factory: object,
) -> DiscoveryProposal:
    """Build an owner-reviewable exact proposal from attested fresh snapshots."""

    checked_request = _copy(request, "DISCOVERY_REQUEST_INVALID")
    if not isinstance(checked_request, dict):
        _fail("DISCOVERY_REQUEST_INVALID")
    _assert_claimed_discovery_execution(execution_capability, checked_request)
    try:
        from tooling.platform_authority_gug376_live_provider import (
            is_attested_discovery_provider,
        )

        if not is_attested_discovery_provider(
            provider_factory, execution_capability
        ):
            _fail("ATTESTED_DISCOVERY_PROVIDER_REQUIRED")
        provider_summary = provider_factory.discovery_budget_summary()  # type: ignore[attr-defined]
        provider_transcript = provider_factory.transcript_summary()  # type: ignore[attr-defined]
        claim_digest = execution_capability._claim_digest  # type: ignore[attr-defined]
    except PrivateInputDiscoveryError:
        raise
    except Exception as exc:
        raise PrivateInputDiscoveryError(
            "ATTESTED_DISCOVERY_PROVIDER_REQUIRED"
        ) from exc
    return _derive_discovery_proposal(
        request=checked_request,
        authority_snapshots=authority_snapshots,
        identity_snapshots=identity_snapshots,
        now=now,
        provider_summary=provider_summary,
        provider_transcript=provider_transcript,
        claim_digest=claim_digest,
    )


def validate_public_discovery_receipt(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _copy(value, "PUBLIC_DISCOVERY_RECEIPT_INVALID")
    counters = (
        "network_calls",
        "provider_calls",
        "credential_vending_calls",
        "page_calls",
        "projected_response_bytes",
        "aws_calls",
        "aws_mutations",
    )
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _RECEIPT_FIELDS
        or receipt.get("record_type")
        != "scanalyze.platform_authority.gug393_discovery_receipt.v1"
        or receipt.get("status") != "READY_FOR_OWNER_DECISION"
        or receipt.get("classification")
        not in {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"}
        or any(
            type(receipt.get(field)) is not int or receipt[field] < 0
            for field in counters
        )
        or receipt["provider_calls"] < 1
        or receipt["network_calls"]
        != receipt["provider_calls"] + receipt["credential_vending_calls"]
        or receipt["page_calls"] > receipt["provider_calls"]
        or receipt["aws_calls"] != receipt["provider_calls"]
        or receipt["network_calls"] > HARD_MAX_NETWORK_CALLS
        or receipt["provider_calls"] > HARD_MAX_PROVIDER_CALLS
        or receipt["credential_vending_calls"]
        > HARD_MAX_CREDENTIAL_VENDING_CALLS
        or receipt["page_calls"] > HARD_MAX_PAGE_CALLS
        or receipt["projected_response_bytes"]
        > HARD_MAX_TOTAL_RESPONSE_BYTES
        or _USD.fullmatch(str(receipt.get("modeled_cost_usd_upper"))) is None
        or receipt.get("cost_status") != "COST_WITHIN_BOUND"
        or receipt.get("missing_input_categories") != []
        or receipt.get("live_provider_evidence") is not True
        or receipt.get("read_only") is not True
        or receipt.get("aws_mutations") != 0
        or receipt.get("deployment_authorized") is not False
        or receipt.get("two_human_status") != "NOT_PROVEN"
        or receipt.get("independent_approval_present") is not False
        or receipt.get("production_status") != "NO-GO"
        or receipt.get("receipt_digest")
        != canonical_digest(
            {key: item for key, item in receipt.items() if key != "receipt_digest"}
        )
    ):
        _fail("PUBLIC_DISCOVERY_RECEIPT_INVALID")
    _sha(receipt.get("source_commit_sha"), "PUBLIC_DISCOVERY_RECEIPT_INVALID")
    _sha(receipt.get("source_tree_sha"), "PUBLIC_DISCOVERY_RECEIPT_INVALID")
    for field in (
        "source_contract_digest",
        "proposal_digest",
        "budget_digest",
        "transcript_digest",
        "receipt_digest",
    ):
        _digest(receipt.get(field), "PUBLIC_DISCOVERY_RECEIPT_INVALID")
    return receipt


def persist_discovery_proposal(
    private_root: Path,
    proposal: DiscoveryProposal,
    *,
    proposal_file: str = DEFAULT_PROPOSAL_FILE,
) -> None:
    if type(proposal) is not DiscoveryProposal:
        _fail("PROPOSAL_NOT_COMPLETE")
    name = _name(proposal_file, "PROPOSAL_FILE_INVALID")
    if name != DEFAULT_PROPOSAL_FILE:
        _fail("PROPOSAL_FILE_INVALID")
    value = _validate_proposal_evidence_chain(
        private_root, proposal.private_candidate, require_persisted=False
    )
    receipt = validate_public_discovery_receipt(proposal.public_receipt)
    if (
        receipt["proposal_digest"] != value["proposal_digest"]
        or receipt["source_contract_digest"]
        != value["source_contract_digest"]
        or receipt["budget_digest"] != value["budget_digest"]
        or receipt["transcript_digest"]
        != value["provider_transcript"]["transcript_digest"]
        or receipt["classification"] != value["classification"]
        or receipt["source_commit_sha"] != value["source_commit_sha"]
        or receipt["source_tree_sha"] != value["source_tree_sha"]
        or receipt["network_calls"]
        != value["provider_summary"]["network_calls"]
        or receipt["provider_calls"]
        != value["provider_summary"]["provider_calls"]
        or receipt["credential_vending_calls"]
        != value["provider_summary"]["credential_vending_calls"]
        or receipt["page_calls"]
        != value["provider_summary"]["page_calls"]
        or receipt["projected_response_bytes"]
        != value["provider_summary"]["projected_response_bytes"]
        or receipt["modeled_cost_usd_upper"]
        != _format_nano_usd(
            value["provider_summary"]["modeled_cost_nano_usd"]
        )
    ):
        _fail("PROPOSAL_DIGEST_MISMATCH")
    try:
        private_target_absent(private_root, name)
        write_private_json(private_root, name, value)
        if read_private_json(private_root, name) != value:
            _fail("PROPOSAL_READBACK_MISMATCH")
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc


def _validate_proposal_document(candidate: Mapping[str, Any]) -> dict[str, Any]:
    proposal = _copy(candidate, "PROPOSAL_NOT_COMPLETE")
    if (
        not isinstance(proposal, dict)
        or set(proposal) != _PROPOSAL_FIELDS
        or proposal.get("record_type") != PROPOSAL_TYPE
        or proposal.get("schema_version") != 1
        or proposal.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or proposal.get("parent_issue") != PARENT_ISSUE
        or proposal.get("live_issue") != LIVE_ISSUE
        or proposal.get("status") != "READY_FOR_OWNER_DECISION"
        or proposal.get("classification")
        not in {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"}
        or proposal.get("read_only") is not True
        or type(proposal.get("aws_mutations")) is not int
        or proposal.get("aws_mutations") != 0
        or proposal.get("deployment_authorized") is not False
        or proposal.get("two_human_status") != "NOT_PROVEN"
        or proposal.get("independent_approval_present") is not False
        or proposal.get("production_status") != "NO-GO"
        or proposal.get("proposal_digest")
        != canonical_digest(
            {key: item for key, item in proposal.items() if key != "proposal_digest"}
        )
    ):
        _fail("PROPOSAL_NOT_COMPLETE")
    for field in (
        "source_contract_digest",
        "request_digest",
        "checkpoint_digest",
        "claim_digest",
        "approval_reference_digest",
        "budget_digest",
        "private_root_digest",
        "host_digest",
        "proposal_digest",
    ):
        _digest(proposal.get(field), "PROPOSAL_NOT_COMPLETE")
    _sha(proposal.get("source_commit_sha"), "PROPOSAL_NOT_COMPLETE")
    _sha(proposal.get("source_tree_sha"), "PROPOSAL_NOT_COMPLETE")
    request_name, checkpoint_name = _request_artifact_names(
        proposal.get("request_file"), proposal.get("owner_checkpoint_file")
    )
    if (
        request_name != proposal.get("request_file")
        or checkpoint_name != proposal.get("owner_checkpoint_file")
    ):
        _fail("PROPOSAL_NOT_COMPLETE")
    proposal_start, proposal_end = _window(
        proposal.get("not_before"), proposal.get("expires_at")
    )
    proposal_created = _parse_stamp(
        proposal.get("created_at"), "PROPOSAL_NOT_COMPLETE"
    )
    if not (
        _parse_stamp(proposal_start, "PROPOSAL_NOT_COMPLETE")
        <= proposal_created
        < _parse_stamp(proposal_end, "PROPOSAL_NOT_COMPLETE")
    ):
        _fail("PROPOSAL_NOT_COMPLETE")
    summary, transcript, _ = _validate_provider_evidence(
        provider_summary=proposal["provider_summary"],
        provider_transcript=proposal["provider_transcript"],
        discovery_budget=proposal["discovery_budget"],
        expected_budget_digest=proposal["budget_digest"],
    )
    if (
        summary != proposal["provider_summary"]
        or transcript != proposal["provider_transcript"]
    ):
        _fail("PROPOSAL_NOT_COMPLETE")
    try:
        plans = materialize_live_plans(
            authority_input=proposal["authority_input"],
            identity_center_input=proposal["identity_center_input"],
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("PROPOSAL_NOT_COMPLETE") from exc
    expected_state = proposal["identity_center_input"].get("expected_state")
    if (
        not isinstance(expected_state, Mapping)
        or expected_state.get("classification") != proposal["classification"]
        or plans.authority_plan != proposal["authority_plan"]
        or plans.identity_center_plan != proposal["identity_center_plan"]
    ):
        _fail("PROPOSAL_NOT_COMPLETE")
    for field in (
        "authority_snapshot_digests",
        "identity_center_snapshot_digests",
    ):
        values = proposal.get(field)
        if (
            not isinstance(values, list)
            or len(values) != 2
            or len(set(values)) != 2
            or any(_DIGEST.fullmatch(str(value)) is None for value in values)
        ):
            _fail("PROPOSAL_NOT_COMPLETE")
    _assert_no_placeholder(proposal, allow_absence_role=True)
    return proposal


def _validate_proposal_evidence_chain(
    private_root: Path,
    candidate: Mapping[str, Any],
    *,
    require_persisted: bool,
) -> dict[str, Any]:
    """Reconstruct a proposal from the immutable canonical private chain."""

    proposal = _validate_proposal_document(candidate)
    if proposal["private_root_digest"] != _private_root_digest(private_root):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    if proposal["host_digest"] != operational_host_digest():
        _fail("HOST_BINDING_INVALID")
    if require_persisted:
        try:
            persisted = read_private_json(private_root, DEFAULT_PROPOSAL_FILE)
        except CollectorError as exc:
            raise PrivateInputDiscoveryError(
                "PROPOSAL_READBACK_MISMATCH"
            ) from exc
        if persisted != proposal:
            _fail("PROPOSAL_READBACK_MISMATCH")

    try:
        request = read_private_json(private_root, proposal["request_file"])
        checkpoint = read_private_json(
            private_root, proposal["owner_checkpoint_file"]
        )
        request, checkpoint, _ = _validate_request_pair(
            request,
            checkpoint,
            private_root=private_root,
            now=None,
            require_active=False,
        )
        claim = _validate_claim_document(
            read_private_json(private_root, DEFAULT_CLAIM_FILE),
            request=request,
            checkpoint=checkpoint,
        )
        authority_snapshots = [
            read_private_json(private_root, name)
            for name in AUTHORITY_SNAPSHOT_FILES
        ]
        identity_snapshots = [
            read_private_json(private_root, name)
            for name in IDENTITY_SNAPSHOT_FILES
        ]
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(
            "DISCOVERY_PROVENANCE_MISMATCH"
        ) from exc
    if (
        proposal["claim_digest"] != claim["claim_digest"]
        or proposal["request_digest"] != request["request_digest"]
        or proposal["checkpoint_digest"] != checkpoint["checkpoint_digest"]
    ):
        _fail("DISCOVERY_PROVENANCE_MISMATCH")
    try:
        reconstructed = _derive_discovery_proposal(
            request=request,
            authority_snapshots=authority_snapshots,
            identity_snapshots=identity_snapshots,
            now=_parse_stamp(
                proposal["created_at"], "DISCOVERY_PROVENANCE_MISMATCH"
            ),
            provider_summary=proposal["provider_summary"],
            provider_transcript=proposal["provider_transcript"],
            claim_digest=claim["claim_digest"],
        ).private_candidate
    except PrivateInputDiscoveryError as exc:
        if exc.code in {
            "PRIVATE_ROOT_BINDING_MISMATCH",
            "HOST_BINDING_INVALID",
            "DISCOVERY_CLAIM_BINDING_MISMATCH",
        }:
            raise
        raise PrivateInputDiscoveryError(
            "DISCOVERY_PROVENANCE_MISMATCH"
        ) from exc
    if reconstructed != proposal:
        _fail("DISCOVERY_PROVENANCE_MISMATCH")
    try:
        observed_times = [
            _parse_stamp(
                snapshot["identity"]["observed_at"],
                "DISCOVERY_PROVENANCE_MISMATCH",
            )
            for snapshot in authority_snapshots
        ]
        observed_times.extend(
            _parse_stamp(
                identity["observed_at"],
                "DISCOVERY_PROVENANCE_MISMATCH",
            )
            for snapshot in identity_snapshots
            for identity in snapshot["identities"]
        )
        claimed_at = _parse_stamp(
            claim["claimed_at"], "DISCOVERY_PROVENANCE_MISMATCH"
        )
        proposal_created_at = _parse_stamp(
            proposal["created_at"], "DISCOVERY_PROVENANCE_MISMATCH"
        )
    except PrivateInputDiscoveryError:
        raise
    except (KeyError, TypeError) as exc:
        raise PrivateInputDiscoveryError(
            "DISCOVERY_PROVENANCE_MISMATCH"
        ) from exc
    if (
        not observed_times
        or claimed_at > min(observed_times)
        or max(observed_times) > proposal_created_at
    ):
        _fail("DISCOVERY_PROVENANCE_MISMATCH")
    return proposal


def materialize_owner_decision(
    *,
    private_root: Path,
    source_commit_sha: str,
    source_tree_sha: str,
    candidate: Mapping[str, Any],
    expected_proposal_digest: str,
    approval_reference_digest: str,
    now: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    proposal = _validate_proposal_evidence_chain(
        private_root, candidate, require_persisted=True
    )
    if (
        proposal["source_commit_sha"]
        != _sha(source_commit_sha, "SOURCE_BINDING_MISMATCH")
        or proposal["source_tree_sha"]
        != _sha(source_tree_sha, "SOURCE_BINDING_MISMATCH")
    ):
        _fail("SOURCE_BINDING_MISMATCH")
    _digest(expected_proposal_digest, "PROPOSAL_DIGEST_MISMATCH")
    _digest(approval_reference_digest, "APPROVAL_REFERENCE_INVALID")
    _assert_no_placeholder(
        approval_reference_digest, code="APPROVAL_REFERENCE_INVALID"
    )
    if (
        proposal.get("proposal_digest") != expected_proposal_digest
    ):
        _fail("PROPOSAL_DIGEST_MISMATCH")
    checked_now = _checked_clock(now, "OWNER_DECISION_EXPIRED")
    checked_end = _checked_clock(expires_at, "OWNER_DECISION_EXPIRED")
    proposal_created = _parse_stamp(
        proposal.get("created_at"), "PROPOSAL_NOT_COMPLETE"
    )
    if approval_reference_digest == proposal.get("approval_reference_digest"):
        _fail("OWNER_DECISION_APPROVAL_NOT_DISTINCT")
    if (
        checked_now
        < proposal_created
        or checked_now - proposal_created > MAX_PROPOSAL_REVIEW_DELAY
        or not checked_now < checked_end
        or checked_end - checked_now > MAX_DECISION_WINDOW
    ):
        _fail("OWNER_DECISION_EXPIRED")
    body = {
        "record_type": DECISION_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "proposal_digest": expected_proposal_digest,
        "source_commit_sha": proposal["source_commit_sha"],
        "source_tree_sha": proposal["source_tree_sha"],
        "source_contract_digest": proposal["source_contract_digest"],
        "request_digest": proposal["request_digest"],
        "budget_digest": proposal["budget_digest"],
        "private_root_digest": proposal["private_root_digest"],
        "host_digest": proposal["host_digest"],
        "approval_reference_digest": approval_reference_digest,
        "approved_at": _stamp(checked_now),
        "expires_at": _stamp(checked_end),
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    return {**body, "decision_digest": canonical_digest(body)}


def _validate_owner_decision_document(
    decision: Mapping[str, Any],
    *,
    proposal: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked = _copy(decision, "OWNER_DECISION_REQUIRED")
    if (
        not isinstance(checked, dict)
        or set(checked) != _DECISION_FIELDS
        or checked.get("record_type") != DECISION_TYPE
        or checked.get("schema_version") != 1
        or checked.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or checked.get("read_only") is not True
        or type(checked.get("aws_mutations")) is not int
        or checked.get("aws_mutations") != 0
        or checked.get("deployment_authorized") is not False
        or checked.get("production_status") != "NO-GO"
        or checked.get("decision_digest")
        != canonical_digest(
            {key: item for key, item in checked.items() if key != "decision_digest"}
        )
    ):
        _fail("OWNER_DECISION_DIGEST_MISMATCH")
    for field in (
        "proposal_digest",
        "source_contract_digest",
        "request_digest",
        "budget_digest",
        "private_root_digest",
        "host_digest",
        "decision_digest",
    ):
        _digest(checked.get(field), "OWNER_DECISION_DIGEST_MISMATCH")
    _digest(
        checked.get("approval_reference_digest"),
        "APPROVAL_REFERENCE_INVALID",
    )
    _assert_no_placeholder(
        checked.get("approval_reference_digest"),
        code="APPROVAL_REFERENCE_INVALID",
    )
    _sha(checked.get("source_commit_sha"), "SOURCE_BINDING_MISMATCH")
    _sha(checked.get("source_tree_sha"), "SOURCE_BINDING_MISMATCH")
    approved_at = _parse_stamp(
        checked.get("approved_at"), "OWNER_DECISION_EXPIRED"
    )
    expires_at = _parse_stamp(
        checked.get("expires_at"), "OWNER_DECISION_EXPIRED"
    )
    if (
        not approved_at < expires_at
        or expires_at - approved_at > MAX_DECISION_WINDOW
    ):
        _fail("OWNER_DECISION_EXPIRED")
    if proposal is not None:
        proposal_created_at = _parse_stamp(
            proposal.get("created_at"), "PROPOSAL_NOT_COMPLETE"
        )
        proposal_bindings = {
            "proposal_digest": "proposal_digest",
            "source_commit_sha": "source_commit_sha",
            "source_tree_sha": "source_tree_sha",
            "source_contract_digest": "source_contract_digest",
            "request_digest": "request_digest",
            "budget_digest": "budget_digest",
            "private_root_digest": "private_root_digest",
            "host_digest": "host_digest",
        }
        if any(
            checked.get(decision_field) != proposal.get(proposal_field)
            for decision_field, proposal_field in proposal_bindings.items()
        ):
            _fail("OWNER_DECISION_DIGEST_MISMATCH")
        if (
            checked.get("approval_reference_digest")
            == proposal.get("approval_reference_digest")
            or approved_at < proposal_created_at
            or approved_at - proposal_created_at
            > MAX_PROPOSAL_REVIEW_DELAY
        ):
            _fail("OWNER_DECISION_EXPIRED")
    if now is not None:
        checked_now = _checked_clock(now, "OWNER_DECISION_EXPIRED")
        if approved_at > checked_now or checked_now >= expires_at:
            _fail("OWNER_DECISION_EXPIRED")
    return checked


def persist_owner_decision(
    private_root: Path,
    decision: Mapping[str, Any],
    *,
    decision_file: str = DEFAULT_DECISION_FILE,
) -> None:
    name = _name(decision_file, "PRIVATE_OUTPUT_INVALID")
    if name != DEFAULT_DECISION_FILE:
        _fail("PRIVATE_OUTPUT_INVALID")
    try:
        persisted_proposal = read_private_json(
            private_root, DEFAULT_PROPOSAL_FILE
        )
    except CollectorError as exc:
        raise PrivateInputDiscoveryError("PROPOSAL_READBACK_MISMATCH") from exc
    proposal = _validate_proposal_evidence_chain(
        private_root, persisted_proposal, require_persisted=True
    )
    checked = _validate_owner_decision_document(decision, proposal=proposal)
    if checked["private_root_digest"] != _private_root_digest(private_root):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    if checked["host_digest"] != operational_host_digest():
        _fail("HOST_BINDING_INVALID")
    try:
        private_target_absent(private_root, name)
        write_private_json(private_root, name, checked)
        if read_private_json(private_root, name) != checked:
            _fail("OWNER_DECISION_READBACK_MISMATCH")
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc


def materialize_approved_gug392_inputs(
    *,
    private_root: Path,
    source_commit_sha: str,
    source_tree_sha: str,
    candidate: Mapping[str, Any],
    decision: Mapping[str, Any],
    expected_proposal_digest: str,
    expected_decision_digest: str,
    now: datetime,
    authority_input_file: str = DEFAULT_AUTHORITY_INPUT_FILE,
    identity_center_input_file: str = DEFAULT_IDENTITY_INPUT_FILE,
    authority_plan_file: str = DEFAULT_AUTHORITY_PLAN_FILE,
    identity_center_plan_file: str = DEFAULT_IDENTITY_PLAN_FILE,
    decision_file: str = DEFAULT_DECISION_FILE,
    manifest_file: str = DEFAULT_MANIFEST_FILE,
) -> MaterializedApprovedInputs:
    proposal = _validate_proposal_evidence_chain(
        private_root, candidate, require_persisted=True
    )
    current_private_root_digest = _private_root_digest(private_root)
    current_host_digest = operational_host_digest()
    checked_source_commit = _sha(
        source_commit_sha, "SOURCE_BINDING_MISMATCH"
    )
    checked_source_tree = _sha(source_tree_sha, "SOURCE_BINDING_MISMATCH")
    if (
        proposal["source_commit_sha"] != checked_source_commit
        or proposal["source_tree_sha"] != checked_source_tree
    ):
        _fail("SOURCE_BINDING_MISMATCH")
    checked_now = _checked_clock(now, "OWNER_DECISION_EXPIRED")
    owner_decision = _validate_owner_decision_document(
        decision,
        proposal=proposal,
        now=checked_now,
    )
    if (
        not isinstance(proposal, dict)
        or proposal.get("record_type") != PROPOSAL_TYPE
        or proposal.get("status") != "READY_FOR_OWNER_DECISION"
        or proposal.get("proposal_digest") != expected_proposal_digest
        or proposal.get("proposal_digest")
        != canonical_digest(
            {key: item for key, item in proposal.items() if key != "proposal_digest"}
        )
        or owner_decision.get("decision_digest") != expected_decision_digest
        or owner_decision.get("decision_digest")
        != canonical_digest(
            {
                key: item
                for key, item in owner_decision.items()
                if key != "decision_digest"
            }
        )
        or owner_decision.get("proposal_digest") != expected_proposal_digest
        or owner_decision.get("source_contract_digest")
        != proposal.get("source_contract_digest")
        or owner_decision.get("request_digest")
        != proposal.get("request_digest")
        or owner_decision.get("budget_digest") != proposal.get("budget_digest")
        or owner_decision.get("private_root_digest")
        != current_private_root_digest
        or owner_decision.get("host_digest") != current_host_digest
        or owner_decision.get("source_commit_sha") != checked_source_commit
        or owner_decision.get("source_tree_sha") != checked_source_tree
    ):
        _fail("OWNER_DECISION_DIGEST_MISMATCH")
    try:
        discovery_plans = materialize_live_plans(
            authority_input=proposal["authority_input"],
            identity_center_input=proposal["identity_center_input"],
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("DISCOVERY_PROVENANCE_MISMATCH") from exc
    if (
        discovery_plans.authority_plan != proposal["authority_plan"]
        or discovery_plans.identity_center_plan != proposal["identity_center_plan"]
    ):
        _fail("DISCOVERY_PROVENANCE_MISMATCH")
    authority_input = _copy(
        proposal["authority_input"], "PROPOSAL_NOT_COMPLETE"
    )
    identity_center_input = _copy(
        proposal["identity_center_input"], "PROPOSAL_NOT_COMPLETE"
    )
    for value in (authority_input, identity_center_input):
        value["not_before"] = owner_decision["approved_at"]
        value["not_after"] = owner_decision["expires_at"]
    try:
        plans = materialize_live_plans(
            authority_input=authority_input,
            identity_center_input=identity_center_input,
        )
    except Exception as exc:
        raise PrivateInputDiscoveryError("DISCOVERY_PROVENANCE_MISMATCH") from exc
    names = {
        "authority_input_file": _name(authority_input_file, "PRIVATE_OUTPUT_INVALID"),
        "identity_center_input_file": _name(
            identity_center_input_file, "PRIVATE_OUTPUT_INVALID"
        ),
        "authority_plan_file": _name(authority_plan_file, "PRIVATE_OUTPUT_INVALID"),
        "identity_center_plan_file": _name(
            identity_center_plan_file, "PRIVATE_OUTPUT_INVALID"
        ),
        "decision_file": _name(decision_file, "PRIVATE_OUTPUT_INVALID"),
        "manifest_file": _name(manifest_file, "PRIVATE_OUTPUT_INVALID"),
    }
    if names != {
        "authority_input_file": DEFAULT_AUTHORITY_INPUT_FILE,
        "identity_center_input_file": DEFAULT_IDENTITY_INPUT_FILE,
        "authority_plan_file": DEFAULT_AUTHORITY_PLAN_FILE,
        "identity_center_plan_file": DEFAULT_IDENTITY_PLAN_FILE,
        "decision_file": DEFAULT_DECISION_FILE,
        "manifest_file": DEFAULT_MANIFEST_FILE,
    }:
        _fail("PRIVATE_OUTPUT_INVALID")
    if len(set(names.values())) != len(names):
        _fail("PRIVATE_OUTPUT_COLLISION")
    artifacts = {
        names["authority_input_file"]: authority_input,
        names["identity_center_input_file"]: identity_center_input,
        names["authority_plan_file"]: plans.authority_plan,
        names["identity_center_plan_file"]: plans.identity_center_plan,
        names["decision_file"]: owner_decision,
    }
    manifest_body: dict[str, Any] = {
        "record_type": MANIFEST_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "live_issue": LIVE_ISSUE,
        "proposal_digest": expected_proposal_digest,
        "decision_digest": expected_decision_digest,
        "source_commit_sha": checked_source_commit,
        "source_tree_sha": checked_source_tree,
        "source_contract_digest": proposal["source_contract_digest"],
        "request_digest": proposal["request_digest"],
        "budget_digest": proposal["budget_digest"],
        "private_root_digest": current_private_root_digest,
        "host_digest": current_host_digest,
        "artifact_digests": {
            name: canonical_digest(value) for name, value in artifacts.items()
        },
        **names,
        "materialized_at": _stamp(checked_now),
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }
    manifest = {
        **manifest_body,
        "manifest_digest": canonical_digest(manifest_body),
    }
    return MaterializedApprovedInputs(
        _MATERIALIZATION_SENTINEL,
        authority_input=authority_input,
        identity_center_input=identity_center_input,
        authority_plan=plans.authority_plan,
        identity_center_plan=plans.identity_center_plan,
        owner_decision=owner_decision,
        manifest=manifest,
    )


def persist_approved_gug392_inputs(
    private_root: Path, materialization: MaterializedApprovedInputs
) -> None:
    if type(materialization) is not MaterializedApprovedInputs:
        _fail("DISCOVERY_MATERIALIZATION_CAPABILITY_REQUIRED")
    documents = materialization._consume()
    manifest = documents["manifest"]
    names = {
        "authority_input_file": documents["authority_input"],
        "identity_center_input_file": documents["identity_center_input"],
        "authority_plan_file": documents["authority_plan"],
        "identity_center_plan_file": documents["identity_center_plan"],
    }
    decision_name = str(manifest["decision_file"])
    manifest_name = str(manifest["manifest_file"])
    artifact_names = [str(manifest[key]) for key in names]
    all_names = [*artifact_names, decision_name, manifest_name]
    if len(set(all_names)) != len(all_names):
        _fail("PRIVATE_OUTPUT_COLLISION")
    checked_manifest = _validate_manifest_document(manifest)
    if checked_manifest["private_root_digest"] != _private_root_digest(
        private_root
    ):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    expected_artifacts = {
        str(manifest[field]): value for field, value in names.items()
    }
    expected_artifacts[decision_name] = documents["owner_decision"]
    if checked_manifest["artifact_digests"] != {
        name: canonical_digest(value) for name, value in expected_artifacts.items()
    }:
        _fail("DISCOVERY_PROVENANCE_MISMATCH")
    try:
        if read_private_json(private_root, decision_name) != documents[
            "owner_decision"
        ]:
            _fail("OWNER_DECISION_DIGEST_MISMATCH")
        for name in [*artifact_names, manifest_name]:
            private_target_absent(private_root, name)
        for field, value in names.items():
            write_private_json(private_root, str(manifest[field]), value)
        # Manifest is the commit marker and is always published last.
        write_private_json(private_root, manifest_name, manifest)
        validate_input_materialization_manifest(private_root, manifest)
    except PrivateInputDiscoveryError:
        raise
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc


def _validate_manifest_document(manifest: Mapping[str, Any]) -> dict[str, Any]:
    checked = _copy(manifest, "DISCOVERY_MANIFEST_REQUIRED")
    if (
        not isinstance(checked, dict)
        or set(checked) != _MANIFEST_FIELDS
        or checked.get("record_type") != MANIFEST_TYPE
        or checked.get("schema_version") != 1
        or checked.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or checked.get("parent_issue") != PARENT_ISSUE
        or checked.get("live_issue") != LIVE_ISSUE
        or checked.get("read_only") is not True
        or type(checked.get("aws_calls")) is not int
        or checked.get("aws_calls") != 0
        or type(checked.get("aws_mutations")) is not int
        or checked.get("aws_mutations") != 0
        or checked.get("deployment_authorized") is not False
        or checked.get("two_human_status") != "NOT_PROVEN"
        or checked.get("independent_approval_present") is not False
        or checked.get("production_status") != "NO-GO"
        or checked.get("manifest_digest")
        != canonical_digest(
            {key: item for key, item in checked.items() if key != "manifest_digest"}
        )
    ):
        _fail("DISCOVERY_MANIFEST_REQUIRED")
    file_fields = (
        "authority_input_file",
        "identity_center_input_file",
        "authority_plan_file",
        "identity_center_plan_file",
        "decision_file",
        "manifest_file",
    )
    names = [_name(checked.get(field), "DISCOVERY_MANIFEST_REQUIRED") for field in file_fields]
    if names != [
        DEFAULT_AUTHORITY_INPUT_FILE,
        DEFAULT_IDENTITY_INPUT_FILE,
        DEFAULT_AUTHORITY_PLAN_FILE,
        DEFAULT_IDENTITY_PLAN_FILE,
        DEFAULT_DECISION_FILE,
        DEFAULT_MANIFEST_FILE,
    ]:
        _fail("DISCOVERY_MANIFEST_REQUIRED")
    if len(set(names)) != len(names):
        _fail("PRIVATE_OUTPUT_COLLISION")
    digests = checked.get("artifact_digests")
    expected_artifact_names = set(names[:-1])
    if (
        not isinstance(digests, dict)
        or set(digests) != expected_artifact_names
        or any(_DIGEST.fullmatch(str(value)) is None for value in digests.values())
    ):
        _fail("DISCOVERY_MANIFEST_REQUIRED")
    _digest(checked.get("proposal_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _digest(checked.get("decision_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _digest(checked.get("source_contract_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _digest(checked.get("request_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _digest(checked.get("budget_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _digest(
        checked.get("private_root_digest"), "DISCOVERY_MANIFEST_REQUIRED"
    )
    _digest(checked.get("host_digest"), "DISCOVERY_MANIFEST_REQUIRED")
    _sha(checked.get("source_commit_sha"), "DISCOVERY_MANIFEST_REQUIRED")
    _sha(checked.get("source_tree_sha"), "DISCOVERY_MANIFEST_REQUIRED")
    _parse_stamp(checked.get("materialized_at"), "DISCOVERY_MANIFEST_REQUIRED")
    return checked


def validate_input_materialization_manifest(
    private_root: Path, manifest: Mapping[str, Any]
) -> dict[str, Any]:
    checked = _validate_manifest_document(manifest)
    if checked["private_root_digest"] != _private_root_digest(private_root):
        _fail("PRIVATE_ROOT_BINDING_MISMATCH")
    if checked["host_digest"] != operational_host_digest():
        _fail("HOST_BINDING_INVALID")
    try:
        stored_manifest = read_private_json(
            private_root, str(checked["manifest_file"])
        )
    except CollectorError as exc:
        raise PrivateInputDiscoveryError(exc.code) from exc
    if stored_manifest != checked:
        _fail("DISCOVERY_MANIFEST_READBACK_MISMATCH")
    digests = checked["artifact_digests"]
    for name, expected in digests.items():
        artifact = read_private_json(private_root, str(name))
        if canonical_digest(artifact) != expected:
            _fail("DISCOVERY_PROVENANCE_MISMATCH")
        if str(name) == checked["decision_file"] and (
            not isinstance(artifact, Mapping)
            or artifact.get("decision_digest") != checked["decision_digest"]
            or artifact.get("decision_digest")
            != canonical_digest(
                {
                    key: item
                    for key, item in artifact.items()
                    if key != "decision_digest"
                }
            )
        ):
            _fail("DISCOVERY_PROVENANCE_MISMATCH")
    return checked


def operational_host_digest() -> str:
    """Return a non-identifying binding to the current operator host."""

    hostname = platform.node()
    if not isinstance(hostname, str) or not hostname:
        _fail("HOST_BINDING_UNAVAILABLE")
    return canonical_digest(
        {
            "hostname": hostname,
            "machine": platform.machine(),
            "system": platform.system(),
            "python": platform.python_version(),
            "uid": os.geteuid(),
        }
    )


__all__ = [
    "AUTHORITY_SNAPSHOT_FILES",
    "DEFAULT_AUTHORITY_INPUT_FILE",
    "DEFAULT_AUTHORITY_PLAN_FILE",
    "DEFAULT_CHECKPOINT_FILE",
    "DEFAULT_CLAIM_FILE",
    "DEFAULT_DECISION_FILE",
    "DEFAULT_IDENTITY_INPUT_FILE",
    "DEFAULT_IDENTITY_PLAN_FILE",
    "DEFAULT_MANIFEST_FILE",
    "DEFAULT_PROPOSAL_FILE",
    "DEFAULT_REQUEST_FILE",
    "DerivedSourceContract",
    "DiscoveryExecutionCapability",
    "DiscoveryProposal",
    "IDENTITY_SNAPSHOT_FILES",
    "MaterializedApprovedInputs",
    "MaterializedDiscoveryRequest",
    "PrivateInputDiscoveryError",
    "RESERVED_LIFECYCLE_OUTPUT_FILES",
    "assert_preflight_provider_capability_bindings",
    "approved_discovery_request",
    "authorize_exact_identity_plan",
    "build_discovery_proposal",
    "claim_discovery_execution",
    "derive_source_contract",
    "exact_probe_identity_plan",
    "materialize_approved_gug392_inputs",
    "materialize_discovery_request",
    "materialize_owner_decision",
    "operational_host_digest",
    "persist_approved_gug392_inputs",
    "persist_discovery_proposal",
    "persist_discovery_request",
    "persist_owner_decision",
    "provisional_discovery_plans",
    "read_and_claim_discovery_request",
    "validate_input_materialization_manifest",
    "validate_public_discovery_receipt",
]
