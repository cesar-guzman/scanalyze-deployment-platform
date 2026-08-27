"""Deterministic private request materialization for the GUG-376 live reader.

This module is deliberately offline.  It builds and validates the two private
records needed by a future live entry point, and delegates owner-only file
custody to the already reviewed GUG-384 private JSON helpers.  It imports no
AWS SDK and never constructs a provider.

The digest graph is acyclic and intentional::

    request core -> request binding digest -> owner checkpoint digest
                 -> final request digest

The checkpoint is persisted before the request.  Therefore an interrupted
two-file publication can leave only an inert checkpoint; the request is the
activation-side artifact and is always published last.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import threading
from typing import Any, Callable, Mapping

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
    canonical_policy_digest,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    private_target_absent,
    read_private_json,
    render_policy as render_authority_policy,
    render_policy_candidate as render_authority_policy_candidate,
    write_private_json,
)
from tooling.platform_authority_gug376_identity_center_inventory_collector import (
    LIVE_PRIVATE_FIELDS as IDENTITY_LIVE_PRIVATE_FIELDS,
    POLICY_TARGET_FIELDS as IDENTITY_POLICY_TARGET_FIELDS,
    _valid_exact as valid_identity_center_exact_facts,
    plan_binding as identity_center_plan_binding,
    render_live_policy as render_identity_center_policy,
    render_live_policy_candidate as render_identity_center_policy_candidate,
    valid_live_owner_application_contract,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    ARTIFACT_NAMES,
    EVIDENCE_MANIFEST_NAME,
    OPT_IN,
    live_policy_digest,
)


IMPLEMENTATION_ISSUE = "GUG-392"
PARENT_ISSUE = "GUG-376"
REGION = "us-east-1"
ACTION = "DUAL_DOMAIN_LIVE_READ_ONLY_INVENTORY"
REQUEST_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_live_readonly_request.v1"
)
CHECKPOINT_RECORD_TYPE = (
    "scanalyze.platform_authority.gug376_live_readonly_owner_checkpoint.v1"
)
MAX_CHECKPOINT_WINDOW = timedelta(minutes=15)
CONSUMPTION_CLAIM = "gug376-live-consumption-claim.json"
REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_POLICY_DIGEST = live_policy_digest()
APPLICATION_ACTOR_POLICY_SOURCE = (
    REPO_ROOT
    / "policies/iam/platform-authority-identity-enhanced-application-actor-policy.json"
)
APPLICATION_ACTOR_POLICY_SOURCE_SHA256 = (
    "18363c04aedc3000560de7b3a8fe2fe3fb256f57419f789425718011fb467ca3"
)
PERMISSION_SET_POLICY_SOURCES = {
    "ScanalyzeAuthorityRetireApprove": (
        REPO_ROOT
        / "policies/iam/platform-authority-change-set-retirement-role.json",
        "6c2e2b4dd396525bc676495be4cefb48388d0dadaf4a8854666af27e9a2204bd",
    ),
    "ScanalyzeAuthorityRetireClass": (
        REPO_ROOT
        / "policies/iam/platform-authority-change-set-retirement-classifier-role.json",
        "530241af4d43f3308896c32fa53f9d088bb6dab6826e4250cbb973443b51b2cb",
    ),
}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_READ_CAPABILITY_SENTINEL = object()
_EXECUTION_CAPABILITY_SENTINEL = object()
_FORBIDDEN_AUTHORITY_NAME_FRAGMENTS = (
    "administrator",
    "admin",
    "bootstrap",
    "seed",
    "deploy",
    "destroy",
)
_GENERATED_ROLE_PATTERNS = {
    "retire_approve_generated_role_arn": (
        "ScanalyzeAuthorityRetireApprove"
    ),
    "retire_class_generated_role_arn": "ScanalyzeAuthorityRetireClass",
}
_ABSENT_GENERATED_ROLE_SUFFIX = "0000000000000000"

_AUTHORITY_PLAN_INPUT_FIELDS = {
    "targets",
    "not_before",
    "not_after",
    "expected_account_id",
    "expected_principal_arn",
    "authority_verification_digest",
    "expected_generated_role_trust_policy_digests",
}
_IDENTITY_PLAN_INPUT_FIELDS = {
    "private_targets",
    "not_before",
    "not_after",
    "expected_account_id",
    "expected_principal_arn",
    "authority_verification_digest",
    "expected_state",
}

_PROFILE_FIELDS = {"name", "source", "chain_depth"}
_FIXED_REQUEST_FIELDS = {
    "record_type",
    "schema_version",
    "implementation_issue",
    "parent_issue",
    "action",
    "opt_in",
    "source_commit_sha",
    "source_tree_sha",
    "run_id",
    "profiles",
    "profile_expectations",
    "authority_plan",
    "identity_center_plan",
    "authorization",
    "authorization_digest",
    "attestation",
    "attestation_digest",
    "trust_anchor",
    "trust_anchor_digest",
    "not_before",
    "expires_at",
    "request_window_digest",
    "host_digest",
    "private_root_digest",
    "sdk_runtime_root",
    "approval_reference_digest",
    "request_file",
    "owner_checkpoint_file",
    "live_read_only_authorized",
    "read_only",
    "aws_mutations",
    "deployment_authorized",
    "two_human_status",
    "independent_approval_present",
    "production_status",
}
REQUEST_FIELDS = _FIXED_REQUEST_FIELDS | {
    "owner_checkpoint_digest",
    "request_digest",
}
CHECKPOINT_FIELDS = {
    "record_type",
    "schema_version",
    "implementation_issue",
    "parent_issue",
    "action",
    "opt_in",
    "source_commit_sha",
    "source_tree_sha",
    "request_file",
    "owner_checkpoint_file",
    "host_digest",
    "private_root_digest",
    "sdk_runtime_root",
    "sdk_runtime_root_digest",
    "approval_reference_digest",
    "not_before",
    "expires_at",
    "request_window_digest",
    "plan_window_digest",
    "policy_digest",
    "profile_binding_digest",
    "profile_expectations_digest",
    "authority_plan_digest",
    "identity_center_plan_digest",
    "authorization_digest",
    "attestation_digest",
    "trust_anchor_digest",
    "run_id_digest",
    "request_binding_digest",
    "live_read_only_authorized",
    "read_only",
    "aws_mutations",
    "deployment_authorized",
    "two_human_status",
    "independent_approval_present",
    "production_status",
    "checkpoint_digest",
}


class LiveRequestMaterializationError(ValueError):
    """Stable, public-safe failure from the offline materializer."""

    def __init__(self, code: str) -> None:
        self.code = (
            code if _TOKEN.fullmatch(code) else "LIVE_REQUEST_MATERIALIZATION_BLOCKED"
        )
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise LiveRequestMaterializationError(code)


def _current_time() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _current_host_digest() -> str:
    hostname = platform.node()
    if not isinstance(hostname, str) or not hostname:
        _fail("HOST_BINDING_UNAVAILABLE")
    return canonical_digest({"hostname": hostname, "uid": os.geteuid()})


def _current_source_identity() -> tuple[str, str]:
    git_binary = shutil.which("git", path=os.defpath)
    if git_binary is None or not Path(git_binary).is_absolute():
        _fail("SOURCE_CHECKOUT_INVALID")
    environment = {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
    }

    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(
                [git_binary, "-C", str(REPO_ROOT), *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                env=environment,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LiveRequestMaterializationError(
                "SOURCE_CHECKOUT_INVALID"
            ) from exc
        if result.returncode != 0:
            _fail("SOURCE_CHECKOUT_INVALID")
        return result.stdout.strip()

    try:
        reported_root = Path(git("rev-parse", "--show-toplevel")).resolve(
            strict=True
        )
        expected_root = REPO_ROOT.resolve(strict=True)
    except OSError as exc:
        raise LiveRequestMaterializationError("SOURCE_CHECKOUT_INVALID") from exc
    if reported_root != expected_root:
        _fail("SOURCE_CHECKOUT_INVALID")

    def snapshot() -> tuple[str, str]:
        values = git("show", "-s", "--format=%H%n%T", "HEAD").splitlines()
        if len(values) != 2 or any(_GIT_SHA.fullmatch(value) is None for value in values):
            _fail("SOURCE_CHECKOUT_INVALID")
        return values[0], values[1]

    before = snapshot()
    first_status = git("status", "--porcelain=v1", "--untracked-files=normal")
    after = snapshot()
    second_status = git("status", "--porcelain=v1", "--untracked-files=normal")
    if before != after:
        _fail("SOURCE_CHECKOUT_CHANGED")
    if first_status or second_status:
        _fail("SOURCE_CHECKOUT_NOT_CLEAN")
    return after


@dataclass(frozen=True, slots=True)
class MaterializedLiveRequest:
    request: dict[str, Any]
    owner_checkpoint: dict[str, Any]
    request_bytes: bytes
    owner_checkpoint_bytes: bytes


@dataclass(frozen=True, slots=True)
class MaterializedLivePlans:
    authority_plan: dict[str, Any]
    identity_center_plan: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ValidatedLiveRequest:
    request: dict[str, Any]
    owner_checkpoint: dict[str, Any]
    runtime_config: dict[str, Any]
    _read_capability: object | None = field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True, slots=True)
class _ReadCapability:
    token: object
    private_root_digest: str
    source_commit_sha: str
    source_tree_sha: str
    host_digest: str
    approval_reference_digest: str
    request_digest: str
    checkpoint_digest: str
    runtime_config_digest: str
    provider_binding_digest: str


class LiveRequestExecutionCapability:
    """Opaque, one-shot binding minted only after reviewed private I/O."""

    __slots__ = (
        "_token",
        "_private_root_digest",
        "_source_commit_sha",
        "_source_tree_sha",
        "_approval_reference_digest",
        "_request_digest",
        "_checkpoint_digest",
        "_runtime_config_digest",
        "_provider_binding_digest",
        "_claim",
        "_validity_gate",
        "_state_lock",
        "_provider_bound",
        "_execution_started",
    )

    def __init__(
        self,
        *,
        token: object,
        read_capability: _ReadCapability,
        claim: dict[str, Any],
        validity_gate: Callable[[], None],
    ) -> None:
        if token is not _EXECUTION_CAPABILITY_SENTINEL:
            _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED")
        self._token = token
        self._private_root_digest = read_capability.private_root_digest
        self._source_commit_sha = read_capability.source_commit_sha
        self._source_tree_sha = read_capability.source_tree_sha
        self._approval_reference_digest = (
            read_capability.approval_reference_digest
        )
        self._request_digest = read_capability.request_digest
        self._checkpoint_digest = read_capability.checkpoint_digest
        self._runtime_config_digest = read_capability.runtime_config_digest
        self._provider_binding_digest = read_capability.provider_binding_digest
        self._claim = claim
        self._validity_gate = validity_gate
        self._state_lock = threading.Lock()
        self._provider_bound = False
        self._execution_started = False


@dataclass(frozen=True, slots=True)
class _PlanBindings:
    authority_json: dict[str, Any]
    identity_json: dict[str, Any]
    authority_runtime: dict[str, Any]
    identity_runtime: dict[str, Any]
    plan_window_digest: str
    authority_policy_digest: str
    authority_plan_digest: str
    identity_plan_digest: str


def _canonical_copy(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception as exc:
        raise LiveRequestMaterializationError(code) from exc


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _name(value: Any, code: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        _fail(code)
    return value


def _stamp(value: Any, code: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveRequestMaterializationError(code) from exc
    canonical = (
        parsed.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if parsed.tzinfo is None or canonical != value:
        _fail(code)
    return parsed.astimezone(UTC).replace(microsecond=0), canonical


def private_root_binding_digest(private_root: Path) -> str:
    """Return the canonical path binding; custody is checked during I/O."""

    if not private_root.is_absolute():
        _fail("PRIVATE_ROOT_NOT_ABSOLUTE")
    try:
        resolved = private_root.resolve(strict=True)
    except OSError as exc:
        raise LiveRequestMaterializationError("PRIVATE_ROOT_INVALID") from exc
    return canonical_digest(str(resolved))


def _sdk_runtime_root_binding(sdk_runtime_root: Any) -> tuple[str, str]:
    """Return one canonical, existing SDK root outside this repository."""

    if not isinstance(sdk_runtime_root, str) or not sdk_runtime_root:
        _fail("SDK_RUNTIME_ROOT_INVALID")
    candidate = Path(sdk_runtime_root)
    if not candidate.is_absolute():
        _fail("SDK_RUNTIME_ROOT_INVALID")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise LiveRequestMaterializationError(
            "SDK_RUNTIME_ROOT_INVALID"
        ) from exc
    if (
        str(resolved) != sdk_runtime_root
        or candidate != resolved
        or not resolved.is_dir()
    ):
        _fail("SDK_RUNTIME_ROOT_INVALID")
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        pass
    else:
        _fail("SDK_RUNTIME_INSIDE_SOURCE_ROOT")
    canonical = str(resolved)
    return canonical, canonical_digest(canonical)


def _profiles(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = _canonical_copy(value, "PROFILE_BINDING_INVALID")
    if not isinstance(profiles, dict) or set(profiles) != {
        "authority",
        "identity_center",
    }:
        _fail("PROFILE_BINDING_INVALID")
    for profile in profiles.values():
        if (
            not isinstance(profile, dict)
            or set(profile) != _PROFILE_FIELDS
            or not isinstance(profile.get("name"), str)
            or _PROFILE.fullmatch(profile["name"]) is None
            or profile["name"].casefold() == "default"
            or any(
                fragment in re.sub(r"[^a-z0-9]", "", profile["name"].casefold())
                for fragment in _FORBIDDEN_AUTHORITY_NAME_FRAGMENTS
            )
            or profile.get("source") != "DIRECT_SSO"
            or type(profile.get("chain_depth")) is not int
            or profile["chain_depth"] != 0
        ):
            _fail("PROFILE_BINDING_INVALID")
    if (
        profiles["authority"]["name"].casefold()
        == profiles["identity_center"]["name"].casefold()
    ):
        _fail("PROFILE_BINDING_INVALID")
    return profiles


def _sso_role_digests(value: Mapping[str, Any]) -> dict[str, str]:
    result = _canonical_copy(value, "SSO_ROLE_BINDING_INVALID")
    if not isinstance(result, dict) or set(result) != {
        "authority",
        "identity_center",
    }:
        _fail("SSO_ROLE_BINDING_INVALID")
    for digest in result.values():
        _digest(digest, "SSO_ROLE_BINDING_INVALID")
    return result


def _runtime_plan(value: Mapping[str, Any], code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized = _canonical_copy(value, code)
    if not isinstance(normalized, dict):
        _fail(code)
    start, start_text = _stamp(normalized.get("not_before"), code)
    end, end_text = _stamp(normalized.get("not_after"), code)
    if not start < end or end - start > timedelta(hours=1):
        _fail(code)
    normalized["not_before"], normalized["not_after"] = start_text, end_text
    runtime = _canonical_copy(normalized, code)
    runtime["not_before"], runtime["not_after"] = start, end
    return normalized, runtime


def render_application_actor_policy(
    authority_targets: Mapping[str, Any], *, authority_account_id: str
) -> tuple[dict[str, Any], str]:
    """Render the repository-pinned actor policy for the two generated roles."""

    if not isinstance(authority_targets, Mapping):
        _fail("GENERATED_ROLE_SOURCE_CONTRACT_INVALID")
    for field_name, permission_set_name in _GENERATED_ROLE_PATTERNS.items():
        role_arn = authority_targets.get(field_name)
        if (
            not isinstance(role_arn, str)
            or re.fullmatch(
                rf"arn:aws:iam::{re.escape(authority_account_id)}:role/"
                r"aws-reserved/sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
                rf"AWSReservedSSO_{permission_set_name}_[0-9a-fA-F]{{16}}",
                role_arn,
            )
            is None
        ):
            _fail("GENERATED_ROLE_SOURCE_CONTRACT_INVALID")

    try:
        raw = APPLICATION_ACTOR_POLICY_SOURCE.read_bytes()
    except OSError as exc:
        raise LiveRequestMaterializationError(
            "APPLICATION_ACTOR_POLICY_SOURCE_INVALID"
        ) from exc
    if sha256(raw).hexdigest() != APPLICATION_ACTOR_POLICY_SOURCE_SHA256:
        _fail("APPLICATION_ACTOR_POLICY_SOURCE_DRIFT")
    try:
        rendered = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LiveRequestMaterializationError(
            "APPLICATION_ACTOR_POLICY_SOURCE_INVALID"
        ) from exc
    replacements = {
        "classifier_permission_set_role_arn": authority_targets[
            "retire_class_generated_role_arn"
        ],
        "approver_permission_set_role_arn": authority_targets[
            "retire_approve_generated_role_arn"
        ],
    }
    for key, value in replacements.items():
        if rendered.count("${" + key + "}") != 1:
            _fail("APPLICATION_ACTOR_POLICY_SOURCE_INVALID")
        rendered = rendered.replace(
            "${" + key + "}", json.dumps(value)[1:-1]
        )
    if "${" in rendered:
        _fail("APPLICATION_ACTOR_POLICY_SOURCE_INVALID")
    try:
        policy_digest = canonical_policy_digest(rendered)
        policy = json.loads(rendered)
    except (TypeError, ValueError) as exc:
        raise LiveRequestMaterializationError(
            "APPLICATION_ACTOR_POLICY_SOURCE_INVALID"
        ) from exc
    return policy, policy_digest


def render_permission_set_inline_policies(
    *,
    authority_account_id: str,
    identity_center_targets: Mapping[str, Any],
) -> dict[str, tuple[dict[str, Any], str]]:
    """Render both repository-pinned permission-set inline policies."""

    if not isinstance(identity_center_targets, Mapping):
        _fail("PERMISSION_SET_POLICY_BINDING_INVALID")
    management_account_id = identity_center_targets.get("management_account_id")
    instance_arn = identity_center_targets.get("identity_center_instance_arn")
    application_arn = identity_center_targets.get(
        "identity_center_application_arn"
    )
    if (
        not isinstance(management_account_id, str)
        or not isinstance(instance_arn, str)
        or not isinstance(application_arn, str)
    ):
        _fail("PERMISSION_SET_POLICY_BINDING_INVALID")
    instance_id = instance_arn.rsplit("/", 1)[-1]
    application_parts = application_arn.rsplit("/", 2)
    if (
        len(application_parts) != 3
        or application_parts[-2] != instance_id
        or re.fullmatch(r"ssoins-[A-Za-z0-9]{16}", instance_id) is None
        or re.fullmatch(r"apl-[A-Za-z0-9]{16}", application_parts[-1]) is None
    ):
        _fail("PERMISSION_SET_POLICY_BINDING_INVALID")
    replacements = {
        "aws_partition": "aws",
        "identity_center_management_account_id": management_account_id,
        "identity_center_instance_id": instance_id,
        "identity_center_application_id": application_parts[-1],
        "authority_account_id": authority_account_id,
    }
    result: dict[str, tuple[dict[str, Any], str]] = {}
    for name, (source, expected_source_sha256) in (
        PERMISSION_SET_POLICY_SOURCES.items()
    ):
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise LiveRequestMaterializationError(
                "PERMISSION_SET_POLICY_SOURCE_INVALID"
            ) from exc
        if sha256(raw).hexdigest() != expected_source_sha256:
            _fail("PERMISSION_SET_POLICY_SOURCE_DRIFT")
        try:
            rendered = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LiveRequestMaterializationError(
                "PERMISSION_SET_POLICY_SOURCE_INVALID"
            ) from exc
        placeholders = set(re.findall(r"\$\{([A-Za-z0-9_]+)\}", rendered))
        if placeholders != set(replacements):
            _fail("PERMISSION_SET_POLICY_SOURCE_INVALID")
        for key, value in replacements.items():
            rendered = rendered.replace(
                "${" + key + "}", json.dumps(value)[1:-1]
            )
        if "${" in rendered:
            _fail("PERMISSION_SET_POLICY_SOURCE_INVALID")
        try:
            policy_digest = canonical_policy_digest(rendered)
            policy = json.loads(rendered)
        except (TypeError, ValueError) as exc:
            raise LiveRequestMaterializationError(
                "PERMISSION_SET_POLICY_SOURCE_INVALID"
            ) from exc
        result[name] = (policy, policy_digest)
    return result


def _validate_cross_domain_source_contract(
    authority_plan: Mapping[str, Any],
    identity_center_plan: Mapping[str, Any],
) -> str:
    targets = authority_plan.get("targets")
    account_id = authority_plan.get("expected_account_id")
    private_targets = identity_center_plan.get("private_targets")
    if (
        not isinstance(targets, Mapping)
        or not isinstance(account_id, str)
        or not isinstance(private_targets, Mapping)
    ):
        _fail("CROSS_DOMAIN_SOURCE_CONTRACT_INVALID")
    _, expected_digest = render_application_actor_policy(
        targets, authority_account_id=account_id
    )
    expected_state = identity_center_plan.get("expected_state")
    if isinstance(expected_state, Mapping):
        classification = expected_state.get("classification")
    elif identity_center_plan.get("expected_target_digest") == canonical_digest({}):
        classification = "ABSENT_READY"
    else:
        classification = "EXACT_PRESENT_NO_TOUCH"
    if classification not in {"ABSENT_READY", "EXACT_PRESENT_NO_TOUCH"}:
        _fail("CROSS_DOMAIN_SOURCE_CONTRACT_INVALID")
    trust_policy_digests = authority_plan.get(
        "expected_generated_role_trust_policy_digests"
    )
    if (
        not isinstance(trust_policy_digests, Mapping)
        or set(trust_policy_digests) != {"retire_approve", "retire_class"}
        or any(
            _DIGEST.fullmatch(str(value)) is None
            for value in trust_policy_digests.values()
        )
    ):
        _fail("GENERATED_ROLE_TRUST_EXPECTATION_INVALID")
    if classification == "ABSENT_READY":
        expected_absent_roles = {
            field_name: (
                f"arn:aws:iam::{account_id}:role/aws-reserved/"
                "sso.amazonaws.com/AWSReservedSSO_"
                f"{permission_set_name}_{_ABSENT_GENERATED_ROLE_SUFFIX}"
            )
            for field_name, permission_set_name in (
                _GENERATED_ROLE_PATTERNS.items()
            )
        }
        if any(
            targets.get(field_name) != role_arn
            for field_name, role_arn in expected_absent_roles.items()
        ):
            _fail("ABSENT_GENERATED_ROLE_SENTINEL_INVALID")
        expected_absent_trust = {
            key: canonical_digest(
                {
                    "classification": "ABSENT_READY",
                    "not_applicable": "generated-role-trust-policy",
                    "role": key,
                }
            )
            for key in ("retire_approve", "retire_class")
        }
        if dict(trust_policy_digests) != expected_absent_trust:
            _fail("ABSENT_GENERATED_ROLE_TRUST_SENTINEL_INVALID")
    if private_targets.get("application_actor_policy_digest") != expected_digest:
        _fail("APPLICATION_ACTOR_POLICY_BINDING_INVALID")
    return expected_digest


def materialize_live_plans(
    *,
    authority_input: Mapping[str, Any],
    identity_center_input: Mapping[str, Any],
) -> MaterializedLivePlans:
    """Derive both closed live plans and all policy/fact digests offline."""

    authority_seed = _canonical_copy(
        authority_input, "AUTHORITY_PLAN_INPUT_INVALID"
    )
    identity_seed = _canonical_copy(
        identity_center_input, "IDENTITY_CENTER_PLAN_INPUT_INVALID"
    )
    if (
        not isinstance(authority_seed, dict)
        or set(authority_seed) != _AUTHORITY_PLAN_INPUT_FIELDS
    ):
        _fail("AUTHORITY_PLAN_INPUT_INVALID")
    if (
        not isinstance(identity_seed, dict)
        or set(identity_seed) != _IDENTITY_PLAN_INPUT_FIELDS
        or not isinstance(identity_seed.get("private_targets"), dict)
        or set(identity_seed["private_targets"]) != IDENTITY_LIVE_PRIVATE_FIELDS
    ):
        _fail("IDENTITY_CENTER_PLAN_INPUT_INVALID")
    _validate_cross_domain_source_contract(authority_seed, identity_seed)

    authority_candidate = {
        **authority_seed,
        "expected_policy_digest": canonical_digest(
            {"pending": "authority-policy"}
        ),
    }
    authority_json, authority_runtime = _runtime_plan(
        authority_candidate, "AUTHORITY_PLAN_INPUT_INVALID"
    )
    try:
        _, authority_policy_digest = render_authority_policy_candidate(
            authority_runtime
        )
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc
    authority_json["expected_policy_digest"] = authority_policy_digest
    authority_runtime["expected_policy_digest"] = authority_policy_digest

    expected_state = identity_seed.pop("expected_state")
    if not isinstance(expected_state, dict):
        _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
    classification = expected_state.get("classification")
    if classification == "ABSENT_READY":
        if set(expected_state) != {"classification", "instance"}:
            _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
        expected_instance = _canonical_copy(
            expected_state["instance"], "IDENTITY_CENTER_EXPECTED_STATE_INVALID"
        )
        private_targets = identity_seed["private_targets"]
        if (
            not isinstance(expected_instance, dict)
            or set(expected_instance)
            != {
                "identity_store_id",
                "instance_arn",
                "owner_account_id",
                "status",
            }
            or expected_instance.get("identity_store_id")
            != private_targets.get("identity_store_id")
            or expected_instance.get("owner_account_id")
            != identity_seed["expected_account_id"]
            or expected_instance.get("status") != "ACTIVE"
            or re.fullmatch(
                r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9-]+",
                str(expected_instance.get("instance_arn")),
            )
            is None
        ):
            _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
        expected_targets: dict[str, Any] = {}
        expected_facts: dict[str, Any] = {
            "discovery": {
                "instances": [expected_instance],
                "applications": [],
                "permission_sets": [],
            }
        }
        expected_exact_policy_digest = canonical_digest(
            {
                "not_applicable": "identity-center-exact-policy",
                "classification": classification,
            }
        )
    elif classification == "EXACT_PRESENT_NO_TOUCH":
        if set(expected_state) != {"classification", "targets", "facts"}:
            _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
        expected_targets = _canonical_copy(
            expected_state["targets"], "IDENTITY_CENTER_EXPECTED_STATE_INVALID"
        )
        expected_facts = _canonical_copy(
            expected_state["facts"], "IDENTITY_CENTER_EXPECTED_STATE_INVALID"
        )
        if (
            not isinstance(expected_targets, dict)
            or set(expected_targets) != IDENTITY_POLICY_TARGET_FIELDS
            or not isinstance(expected_facts, dict)
        ):
            _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
        try:
            facts_valid = valid_identity_center_exact_facts(
                expected_facts, expected_targets, live=True
            )
        except Exception as exc:
            raise LiveRequestMaterializationError(
                "IDENTITY_CENTER_EXPECTED_STATE_INVALID"
            ) from exc
        if not facts_valid or not valid_live_owner_application_contract(
            expected_facts,
            expected_targets,
            identity_seed["private_targets"],
        ):
            _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")
        rendered_permission_policies = render_permission_set_inline_policies(
            authority_account_id=str(authority_seed["expected_account_id"]),
            identity_center_targets=expected_targets,
        )
        try:
            observed_permission_policy_digests = {
                name: expected_facts["permission_sets"][name][
                    "inline_policy"
                ]["policy_digest"]
                for name in PERMISSION_SET_POLICY_SOURCES
            }
        except (KeyError, TypeError) as exc:
            raise LiveRequestMaterializationError(
                "PERMISSION_SET_POLICY_BINDING_INVALID"
            ) from exc
        if observed_permission_policy_digests != {
            name: value[1]
            for name, value in rendered_permission_policies.items()
        }:
            _fail("PERMISSION_SET_POLICY_BINDING_INVALID")
        expected_exact_policy_digest = canonical_digest(
            {"pending": "identity-center-exact-policy"}
        )
    else:
        _fail("IDENTITY_CENTER_EXPECTED_STATE_INVALID")

    identity_candidate = {
        **identity_seed,
        "expected_discovery_policy_digest": canonical_digest(
            {"pending": "identity-center-discovery-policy"}
        ),
        "expected_exact_policy_digest": expected_exact_policy_digest,
        "expected_target_digest": canonical_digest(expected_targets),
        "expected_facts_digest": canonical_digest(expected_facts),
    }
    identity_json, identity_runtime = _runtime_plan(
        identity_candidate, "IDENTITY_CENTER_PLAN_INPUT_INVALID"
    )
    try:
        _, discovery_policy_digest = render_identity_center_policy_candidate(
            identity_runtime
        )
        if classification == "EXACT_PRESENT_NO_TOUCH":
            _, expected_exact_policy_digest = (
                render_identity_center_policy_candidate(
                    identity_runtime, expected_targets
                )
            )
        identity_json["expected_discovery_policy_digest"] = (
            discovery_policy_digest
        )
        identity_runtime["expected_discovery_policy_digest"] = (
            discovery_policy_digest
        )
        identity_json["expected_exact_policy_digest"] = (
            expected_exact_policy_digest
        )
        identity_runtime["expected_exact_policy_digest"] = (
            expected_exact_policy_digest
        )
        render_authority_policy(authority_runtime)
        render_identity_center_policy(identity_runtime)
        if classification == "EXACT_PRESENT_NO_TOUCH":
            render_identity_center_policy(identity_runtime, expected_targets)
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc

    # Reuse the request-time verifier so cross-account, window, policy and
    # target bindings cannot diverge between plan and request materialization.
    _plan_bindings(authority_json, identity_json)
    return MaterializedLivePlans(
        authority_plan=_canonical_copy(
            authority_json, "AUTHORITY_PLAN_INVALID"
        ),
        identity_center_plan=_canonical_copy(
            identity_json, "IDENTITY_CENTER_PLAN_INVALID"
        ),
    )


def persist_materialized_live_plans(
    private_root: Path,
    materialization: MaterializedLivePlans,
    *,
    authority_plan_file: str,
    identity_center_plan_file: str,
) -> None:
    """Create both owner-only plan files without overwriting any target."""

    authority_name = _name(
        authority_plan_file, "AUTHORITY_PLAN_FILE_INVALID"
    )
    identity_name = _name(
        identity_center_plan_file, "IDENTITY_CENTER_PLAN_FILE_INVALID"
    )
    if (
        authority_name == identity_name
        or {authority_name, identity_name}
        & (
            set(ARTIFACT_NAMES)
            | {CONSUMPTION_CLAIM, EVIDENCE_MANIFEST_NAME}
        )
    ):
        _fail("PRIVATE_OUTPUT_COLLISION")
    _plan_bindings(
        materialization.authority_plan,
        materialization.identity_center_plan,
    )
    try:
        private_target_absent(private_root, authority_name)
        private_target_absent(private_root, identity_name)
        write_private_json(
            private_root, authority_name, materialization.authority_plan
        )
        write_private_json(
            private_root, identity_name, materialization.identity_center_plan
        )
        if canonical_json(read_private_json(private_root, authority_name)) != canonical_json(
            materialization.authority_plan
        ):
            _fail("AUTHORITY_PLAN_READBACK_MISMATCH")
        if canonical_json(read_private_json(private_root, identity_name)) != canonical_json(
            materialization.identity_center_plan
        ):
            _fail("IDENTITY_CENTER_PLAN_READBACK_MISMATCH")
    except LiveRequestMaterializationError:
        raise
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc


def _plan_bindings(
    authority_plan: Mapping[str, Any], identity_center_plan: Mapping[str, Any]
) -> _PlanBindings:
    authority_json, authority_runtime = _runtime_plan(
        authority_plan, "AUTHORITY_PLAN_INVALID"
    )
    identity_json, identity_runtime = _runtime_plan(
        identity_center_plan, "IDENTITY_CENTER_PLAN_INVALID"
    )
    if (
        authority_json["not_before"],
        authority_json["not_after"],
    ) != (
        identity_json["not_before"],
        identity_json["not_after"],
    ):
        _fail("PLAN_WINDOW_MISMATCH")
    authority_account = authority_json.get("expected_account_id")
    identity_account = identity_json.get("expected_account_id")
    private_targets = identity_json.get("private_targets")
    expected_authority_account_arn = f"arn:aws:sso:::account/{authority_account}"
    if (
        not isinstance(authority_account, str)
        or not isinstance(identity_account, str)
        or authority_account == identity_account
        or not isinstance(private_targets, Mapping)
        or private_targets.get("authority_account_arn")
        != expected_authority_account_arn
    ):
        _fail("CROSS_DOMAIN_PLAN_BINDING_INVALID")
    _validate_cross_domain_source_contract(authority_json, identity_json)
    try:
        _, authority_policy_digest = render_authority_policy(authority_runtime)
        identity_binding, identity_plan_digest = identity_center_plan_binding(
            identity_runtime
        )
        render_identity_center_policy(identity_runtime)
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc
    plan_window_digest = canonical_digest(
        {
            "not_before": authority_json["not_before"],
            "not_after": authority_json["not_after"],
            "region": REGION,
        }
    )
    runtime_target_digest = canonical_digest(
        {
            "policy_digest": authority_policy_digest,
            "runtime_source_function_version_arn": authority_json["targets"][
                "runtime_source_function_version_arn"
            ],
        }
    )
    authority_binding = {
        "account_id": authority_json["expected_account_id"],
        "principal_arn": authority_json["expected_principal_arn"],
        "not_before": authority_json["not_before"],
        "not_after": authority_json["not_after"],
        "policy_digest": authority_policy_digest,
        "authority_verification_digest": authority_json[
            "authority_verification_digest"
        ],
        "runtime_target_digest": runtime_target_digest,
        "target_digest": canonical_digest(authority_json["targets"]),
        "region": REGION,
    }
    if identity_binding.get("region") != REGION:
        _fail("IDENTITY_CENTER_PLAN_INVALID")
    return _PlanBindings(
        authority_json=authority_json,
        identity_json=identity_json,
        authority_runtime=authority_runtime,
        identity_runtime=identity_runtime,
        plan_window_digest=plan_window_digest,
        authority_policy_digest=authority_policy_digest,
        authority_plan_digest=canonical_digest(authority_binding),
        identity_plan_digest=identity_plan_digest,
    )


def _request_window(
    *, not_before: str, expires_at: str, plans: _PlanBindings
) -> tuple[str, str, str]:
    start, start_text = _stamp(not_before, "REQUEST_WINDOW_INVALID")
    end, end_text = _stamp(expires_at, "REQUEST_WINDOW_INVALID")
    plan_start, _ = _stamp(
        plans.authority_json["not_before"], "AUTHORITY_PLAN_INVALID"
    )
    plan_end, _ = _stamp(
        plans.authority_json["not_after"], "AUTHORITY_PLAN_INVALID"
    )
    if (
        not start < end
        or end - start > MAX_CHECKPOINT_WINDOW
        or not plan_start <= start < end <= plan_end
    ):
        _fail("REQUEST_WINDOW_INVALID")
    digest = canonical_digest(
        {"not_before": start_text, "expires_at": end_text, "region": REGION}
    )
    return start_text, end_text, digest


def _fixed_truth() -> dict[str, Any]:
    return {
        "live_read_only_authorized": True,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": "NO-GO",
    }


def materialize_live_request(
    *,
    authority_plan: Mapping[str, Any],
    identity_center_plan: Mapping[str, Any],
    profiles: Mapping[str, Any],
    expected_sso_role_name_digests: Mapping[str, Any],
    source_commit_sha: str,
    source_tree_sha: str,
    run_id: str,
    not_before: str,
    expires_at: str,
    host_digest: str,
    private_root_digest: str,
    sdk_runtime_root: str,
    approval_reference_digest: str,
    request_file: str,
    owner_checkpoint_file: str,
) -> MaterializedLiveRequest:
    """Build the exact request/checkpoint pair without consulting a clock or AWS."""

    if (
        not isinstance(source_commit_sha, str)
        or _GIT_SHA.fullmatch(source_commit_sha) is None
        or not isinstance(source_tree_sha, str)
        or _GIT_SHA.fullmatch(source_tree_sha) is None
    ):
        _fail("SOURCE_BINDING_INVALID")
    if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
        _fail("RUN_ID_INVALID")
    _digest(host_digest, "HOST_BINDING_INVALID")
    _digest(private_root_digest, "PRIVATE_ROOT_BINDING_INVALID")
    checked_sdk_runtime_root, sdk_runtime_root_digest = (
        _sdk_runtime_root_binding(sdk_runtime_root)
    )
    _digest(approval_reference_digest, "APPROVAL_REFERENCE_DIGEST_INVALID")
    request_name = _name(request_file, "REQUEST_FILE_INVALID")
    checkpoint_name = _name(
        owner_checkpoint_file, "OWNER_CHECKPOINT_FILE_INVALID"
    )
    if (
        request_name == checkpoint_name
        or request_name
        in set(ARTIFACT_NAMES) | {CONSUMPTION_CLAIM, EVIDENCE_MANIFEST_NAME}
        or checkpoint_name
        in set(ARTIFACT_NAMES) | {CONSUMPTION_CLAIM, EVIDENCE_MANIFEST_NAME}
    ):
        _fail("PRIVATE_OUTPUT_COLLISION")

    checked_profiles = _profiles(profiles)
    sso_role_digests = _sso_role_digests(expected_sso_role_name_digests)
    plans = _plan_bindings(authority_plan, identity_center_plan)
    start, end, request_window_digest = _request_window(
        not_before=not_before, expires_at=expires_at, plans=plans
    )

    profile_binding_digest = canonical_digest(checked_profiles)
    profile_expectations = {
        domain: {
            "expected_principal_digest": canonical_digest(
                plans.authority_json["expected_principal_arn"]
                if domain == "authority"
                else plans.identity_json["expected_principal_arn"]
            ),
            "expected_sso_role_name_digest": sso_role_digests[domain],
        }
        for domain in ("authority", "identity_center")
    }
    profile_expectations_digest = canonical_digest(profile_expectations)
    run_id_digest = canonical_digest(run_id)

    authorization = {
        "record_type": (
            "scanalyze.platform_authority.gug376_live_readonly_authorization.v1"
        ),
        "opt_in": OPT_IN,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "window_digest": plans.plan_window_digest,
        "policy_digest": LIVE_POLICY_DIGEST,
        "profile_binding_digest": profile_binding_digest,
        "authority_plan_digest": plans.authority_plan_digest,
        "identity_center_plan_digest": plans.identity_plan_digest,
        "run_id_digest": run_id_digest,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
    }
    authorization_digest = canonical_digest(authorization)
    attestation = {
        "record_type": (
            "scanalyze.platform_authority.gug376_live_readonly_attestation.v1"
        ),
        "authorization_digest": authorization_digest,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "window_digest": plans.plan_window_digest,
        "policy_digest": LIVE_POLICY_DIGEST,
        "profile_binding_digest": profile_binding_digest,
        "authority_account_digest": canonical_digest(
            plans.authority_json["expected_account_id"]
        ),
        "authority_principal_digest": profile_expectations["authority"][
            "expected_principal_digest"
        ],
        "identity_center_account_digest": canonical_digest(
            plans.identity_json["expected_account_id"]
        ),
        "identity_center_principal_digest": profile_expectations[
            "identity_center"
        ]["expected_principal_digest"],
        "read_only": True,
        "aws_mutations": 0,
    }
    attestation_digest = canonical_digest(attestation)
    trust_anchor = {
        "record_type": (
            "scanalyze.platform_authority.gug376_live_readonly_trust_anchor.v1"
        ),
        "authorization_digest": authorization_digest,
        "attestation_digest": attestation_digest,
        "policy_digest": LIVE_POLICY_DIGEST,
        "authority_verification_digest": plans.authority_json[
            "authority_verification_digest"
        ],
        "identity_center_authority_verification_digest": plans.identity_json[
            "authority_verification_digest"
        ],
        "read_only": True,
    }
    trust_anchor_digest = canonical_digest(trust_anchor)

    request_core: dict[str, Any] = {
        "record_type": REQUEST_RECORD_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "action": ACTION,
        "opt_in": OPT_IN,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "run_id": run_id,
        "profiles": checked_profiles,
        "profile_expectations": profile_expectations,
        "authority_plan": plans.authority_json,
        "identity_center_plan": plans.identity_json,
        "authorization": authorization,
        "authorization_digest": authorization_digest,
        "attestation": attestation,
        "attestation_digest": attestation_digest,
        "trust_anchor": trust_anchor,
        "trust_anchor_digest": trust_anchor_digest,
        "not_before": start,
        "expires_at": end,
        "request_window_digest": request_window_digest,
        "host_digest": host_digest,
        "private_root_digest": private_root_digest,
        "sdk_runtime_root": checked_sdk_runtime_root,
        "approval_reference_digest": approval_reference_digest,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
        **_fixed_truth(),
    }
    if set(request_core) != _FIXED_REQUEST_FIELDS:
        _fail("PRIVATE_REQUEST_FIELDS_INVALID")
    request_binding_digest = canonical_digest(request_core)
    checkpoint_body: dict[str, Any] = {
        "record_type": CHECKPOINT_RECORD_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "action": ACTION,
        "opt_in": OPT_IN,
        "source_commit_sha": source_commit_sha,
        "source_tree_sha": source_tree_sha,
        "request_file": request_name,
        "owner_checkpoint_file": checkpoint_name,
        "host_digest": host_digest,
        "private_root_digest": private_root_digest,
        "sdk_runtime_root": checked_sdk_runtime_root,
        "sdk_runtime_root_digest": sdk_runtime_root_digest,
        "approval_reference_digest": approval_reference_digest,
        "not_before": start,
        "expires_at": end,
        "request_window_digest": request_window_digest,
        "plan_window_digest": plans.plan_window_digest,
        "policy_digest": LIVE_POLICY_DIGEST,
        "profile_binding_digest": profile_binding_digest,
        "profile_expectations_digest": profile_expectations_digest,
        "authority_plan_digest": plans.authority_plan_digest,
        "identity_center_plan_digest": plans.identity_plan_digest,
        "authorization_digest": authorization_digest,
        "attestation_digest": attestation_digest,
        "trust_anchor_digest": trust_anchor_digest,
        "run_id_digest": run_id_digest,
        "request_binding_digest": request_binding_digest,
        **_fixed_truth(),
    }
    owner_checkpoint = {
        **checkpoint_body,
        "checkpoint_digest": canonical_digest(checkpoint_body),
    }
    request_without_digest = {
        **request_core,
        "owner_checkpoint_digest": owner_checkpoint["checkpoint_digest"],
    }
    request = {
        **request_without_digest,
        "request_digest": canonical_digest(request_without_digest),
    }
    if set(owner_checkpoint) != CHECKPOINT_FIELDS or set(request) != REQUEST_FIELDS:
        _fail("PRIVATE_REQUEST_FIELDS_INVALID")
    request = _canonical_copy(request, "PRIVATE_REQUEST_INVALID")
    owner_checkpoint = _canonical_copy(
        owner_checkpoint, "OWNER_CHECKPOINT_INVALID"
    )
    return MaterializedLiveRequest(
        request=request,
        owner_checkpoint=owner_checkpoint,
        request_bytes=(canonical_json(request) + "\n").encode("utf-8"),
        owner_checkpoint_bytes=(canonical_json(owner_checkpoint) + "\n").encode(
            "utf-8"
        ),
    )


def _runtime_config(request: Mapping[str, Any]) -> dict[str, Any]:
    authority_json, authority_runtime = _runtime_plan(
        request["authority_plan"], "AUTHORITY_PLAN_INVALID"
    )
    identity_json, identity_runtime = _runtime_plan(
        request["identity_center_plan"], "IDENTITY_CENTER_PLAN_INVALID"
    )
    if authority_json != request["authority_plan"] or identity_json != request[
        "identity_center_plan"
    ]:
        _fail("PRIVATE_REQUEST_NOT_CANONICAL")
    return {
        "opt_in": request["opt_in"],
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "sdk_runtime_root": request["sdk_runtime_root"],
        "run_id": request["run_id"],
        "profiles": request["profiles"],
        "authority_plan": authority_runtime,
        "identity_center_plan": identity_runtime,
        "authorization": request["authorization"],
        "authorization_digest": request["authorization_digest"],
        "attestation": request["attestation"],
        "attestation_digest": request["attestation_digest"],
        "trust_anchor": request["trust_anchor"],
        "trust_anchor_digest": request["trust_anchor_digest"],
    }


def _runtime_config_digest(config: Mapping[str, Any]) -> str:
    def normalized(value: Any) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                _fail("RUNTIME_CONFIG_BINDING_INVALID")
            return (
                value.astimezone(UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        if isinstance(value, Mapping):
            return {str(key): normalized(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalized(item) for item in value]
        return value

    try:
        return canonical_digest(normalized(config))
    except Exception as exc:
        raise LiveRequestMaterializationError(
            "RUNTIME_CONFIG_BINDING_INVALID"
        ) from exc


def _provider_binding_digest(request: Mapping[str, Any]) -> str:
    profiles = request["profiles"]
    expectations = request["profile_expectations"]
    authority = request["authority_plan"]
    identity = request["identity_center_plan"]
    return canonical_digest(
        {
            "authority_profile": profiles["authority"]["name"],
            "identity_center_profile": profiles["identity_center"]["name"],
            "authority_expected_account_id": authority["expected_account_id"],
            "authority_expected_principal_digest": expectations["authority"][
                "expected_principal_digest"
            ],
            "authority_expected_sso_role_name_digest": expectations[
                "authority"
            ]["expected_sso_role_name_digest"],
            "identity_expected_account_id": identity["expected_account_id"],
            "identity_expected_principal_digest": expectations[
                "identity_center"
            ]["expected_principal_digest"],
            "identity_expected_sso_role_name_digest": expectations[
                "identity_center"
            ]["expected_sso_role_name_digest"],
            "authority_verification_digest": authority[
                "authority_verification_digest"
            ],
            "identity_authority_verification_digest": identity[
                "authority_verification_digest"
            ],
            "sdk_runtime_root": request["sdk_runtime_root"],
            "sdk_runtime_root_digest": canonical_digest(
                request["sdk_runtime_root"]
            ),
        }
    )


def validate_materialized_live_request(
    request: Mapping[str, Any],
    owner_checkpoint: Mapping[str, Any],
    *,
    now: datetime,
    expected_source_commit_sha: str,
    expected_source_tree_sha: str,
    expected_host_digest: str,
    expected_private_root_digest: str,
    expected_approval_reference_digest: str,
) -> ValidatedLiveRequest:
    """Rebuild both records and require an active, exact local binding."""

    normalized_request = _canonical_copy(request, "PRIVATE_REQUEST_INVALID")
    normalized_checkpoint = _canonical_copy(
        owner_checkpoint, "OWNER_CHECKPOINT_INVALID"
    )
    if (
        not isinstance(normalized_request, dict)
        or set(normalized_request) != REQUEST_FIELDS
        or not isinstance(normalized_checkpoint, dict)
        or set(normalized_checkpoint) != CHECKPOINT_FIELDS
    ):
        _fail("PRIVATE_REQUEST_FIELDS_INVALID")
    request_digest = _digest(
        normalized_request.get("request_digest"),
        "PRIVATE_REQUEST_DIGEST_INVALID",
    )
    checkpoint_digest = _digest(
        normalized_checkpoint.get("checkpoint_digest"),
        "OWNER_CHECKPOINT_DIGEST_INVALID",
    )
    if request_digest != canonical_digest(
        {
            key: value
            for key, value in normalized_request.items()
            if key != "request_digest"
        }
    ):
        _fail("PRIVATE_REQUEST_DIGEST_MISMATCH")
    if checkpoint_digest != canonical_digest(
        {
            key: value
            for key, value in normalized_checkpoint.items()
            if key != "checkpoint_digest"
        }
    ):
        _fail("OWNER_CHECKPOINT_DIGEST_MISMATCH")
    if normalized_request.get("owner_checkpoint_digest") != checkpoint_digest:
        _fail("OWNER_CHECKPOINT_BINDING_MISMATCH")
    checked_sdk_runtime_root, sdk_runtime_root_digest = (
        _sdk_runtime_root_binding(normalized_request.get("sdk_runtime_root"))
    )
    if (
        normalized_checkpoint.get("sdk_runtime_root")
        != checked_sdk_runtime_root
        or normalized_checkpoint.get("sdk_runtime_root_digest")
        != sdk_runtime_root_digest
    ):
        _fail("SDK_RUNTIME_ROOT_BINDING_MISMATCH")
    _digest(
        expected_approval_reference_digest,
        "APPROVAL_REFERENCE_DIGEST_INVALID",
    )
    if (
        normalized_request.get("approval_reference_digest")
        != expected_approval_reference_digest
        or normalized_checkpoint.get("approval_reference_digest")
        != expected_approval_reference_digest
    ):
        _fail("APPROVAL_REFERENCE_MISMATCH")
    if (
        normalized_request.get("source_commit_sha") != expected_source_commit_sha
        or normalized_request.get("source_tree_sha") != expected_source_tree_sha
        or normalized_request.get("host_digest") != expected_host_digest
        or normalized_request.get("private_root_digest")
        != expected_private_root_digest
    ):
        _fail("PRIVATE_REQUEST_LOCAL_BINDING_MISMATCH")
    if not isinstance(now, datetime) or now.tzinfo is None:
        _fail("REQUEST_CLOCK_INVALID")
    start, _ = _stamp(
        normalized_request.get("not_before"), "REQUEST_WINDOW_INVALID"
    )
    end, _ = _stamp(
        normalized_request.get("expires_at"), "REQUEST_WINDOW_INVALID"
    )
    current = now.astimezone(UTC).replace(microsecond=0)
    if not start <= current < end:
        _fail("REQUEST_WINDOW_INACTIVE")

    expectations = normalized_request.get("profile_expectations")
    if not isinstance(expectations, Mapping) or set(expectations) != {
        "authority",
        "identity_center",
    }:
        _fail("PROFILE_EXPECTATIONS_INVALID")
    role_digests: dict[str, str] = {}
    for domain in ("authority", "identity_center"):
        item = expectations.get(domain)
        if (
            not isinstance(item, Mapping)
            or set(item)
            != {"expected_principal_digest", "expected_sso_role_name_digest"}
        ):
            _fail("PROFILE_EXPECTATIONS_INVALID")
        _digest(item.get("expected_principal_digest"), "PROFILE_EXPECTATIONS_INVALID")
        role_digests[domain] = _digest(
            item.get("expected_sso_role_name_digest"),
            "PROFILE_EXPECTATIONS_INVALID",
        )
    expected = materialize_live_request(
        authority_plan=normalized_request["authority_plan"],
        identity_center_plan=normalized_request["identity_center_plan"],
        profiles=normalized_request["profiles"],
        expected_sso_role_name_digests=role_digests,
        source_commit_sha=expected_source_commit_sha,
        source_tree_sha=expected_source_tree_sha,
        run_id=normalized_request["run_id"],
        not_before=normalized_request["not_before"],
        expires_at=normalized_request["expires_at"],
        host_digest=expected_host_digest,
        private_root_digest=expected_private_root_digest,
        sdk_runtime_root=checked_sdk_runtime_root,
        approval_reference_digest=normalized_request[
            "approval_reference_digest"
        ],
        request_file=normalized_request["request_file"],
        owner_checkpoint_file=normalized_request["owner_checkpoint_file"],
    )
    if canonical_json(expected.request) != canonical_json(normalized_request):
        _fail("PRIVATE_REQUEST_BINDING_MISMATCH")
    if canonical_json(expected.owner_checkpoint) != canonical_json(
        normalized_checkpoint
    ):
        _fail("OWNER_CHECKPOINT_BINDING_MISMATCH")
    return ValidatedLiveRequest(
        request=normalized_request,
        owner_checkpoint=normalized_checkpoint,
        runtime_config=_runtime_config(normalized_request),
    )


def persist_materialized_live_request(
    private_root: Path, materialization: MaterializedLiveRequest
) -> None:
    """Publish checkpoint then request as canonical create-only private files."""

    request = materialization.request
    checkpoint = materialization.owner_checkpoint
    request_name = _name(request.get("request_file"), "REQUEST_FILE_INVALID")
    checkpoint_name = _name(
        request.get("owner_checkpoint_file"), "OWNER_CHECKPOINT_FILE_INVALID"
    )
    root_digest = private_root_binding_digest(private_root)
    if (
        request_name == checkpoint_name
        or request.get("private_root_digest") != root_digest
        or checkpoint.get("private_root_digest") != root_digest
        or materialization.request_bytes
        != (canonical_json(request) + "\n").encode("utf-8")
        or materialization.owner_checkpoint_bytes
        != (canonical_json(checkpoint) + "\n").encode("utf-8")
    ):
        _fail("PRIVATE_MATERIALIZATION_BINDING_INVALID")
    start, _ = _stamp(request.get("not_before"), "REQUEST_WINDOW_INVALID")
    validate_materialized_live_request(
        request,
        checkpoint,
        now=start,
        expected_source_commit_sha=str(request.get("source_commit_sha")),
        expected_source_tree_sha=str(request.get("source_tree_sha")),
        expected_host_digest=str(request.get("host_digest")),
        expected_private_root_digest=root_digest,
        expected_approval_reference_digest=str(
            request.get("approval_reference_digest")
        ),
    )
    try:
        private_target_absent(private_root, checkpoint_name)
        private_target_absent(private_root, request_name)
        write_private_json(private_root, checkpoint_name, checkpoint)
        write_private_json(private_root, request_name, request)
        if canonical_json(read_private_json(private_root, checkpoint_name)) != canonical_json(
            checkpoint
        ):
            _fail("OWNER_CHECKPOINT_READBACK_MISMATCH")
        if canonical_json(read_private_json(private_root, request_name)) != canonical_json(
            request
        ):
            _fail("PRIVATE_REQUEST_READBACK_MISMATCH")
    except LiveRequestMaterializationError:
        raise
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc


def read_materialized_live_request(
    private_root: Path,
    request_file: str,
    *,
    now: datetime,
    expected_source_commit_sha: str,
    expected_source_tree_sha: str,
    expected_host_digest: str,
    expected_approval_reference_digest: str,
    expected_request_digest: str,
    expected_checkpoint_digest: str,
) -> ValidatedLiveRequest:
    """Read two owner-only files and return the hydrated executor config."""

    request_name = _name(request_file, "REQUEST_FILE_INVALID")
    root_digest = private_root_binding_digest(private_root)
    try:
        request = read_private_json(private_root, request_name)
        if request.get("request_file") != request_name:
            _fail("PRIVATE_REQUEST_FILE_BINDING_MISMATCH")
        checkpoint_name = _name(
            request.get("owner_checkpoint_file"),
            "OWNER_CHECKPOINT_FILE_INVALID",
        )
        checkpoint = read_private_json(private_root, checkpoint_name)
    except LiveRequestMaterializationError:
        raise
    except CollectorError as exc:
        raise LiveRequestMaterializationError(exc.code) from exc
    reviewed_request_digest = _digest(
        expected_request_digest, "REVIEWED_PRIVATE_DIGEST_INVALID"
    )
    reviewed_checkpoint_digest = _digest(
        expected_checkpoint_digest, "REVIEWED_PRIVATE_DIGEST_INVALID"
    )
    if (
        request.get("request_digest") != reviewed_request_digest
        or checkpoint.get("checkpoint_digest") != reviewed_checkpoint_digest
    ):
        _fail("REVIEWED_PRIVATE_DIGEST_MISMATCH")
    validated = validate_materialized_live_request(
        request,
        checkpoint,
        now=now,
        expected_source_commit_sha=expected_source_commit_sha,
        expected_source_tree_sha=expected_source_tree_sha,
        expected_host_digest=expected_host_digest,
        expected_private_root_digest=root_digest,
        expected_approval_reference_digest=expected_approval_reference_digest,
    )
    read_capability = _ReadCapability(
        token=_READ_CAPABILITY_SENTINEL,
        private_root_digest=root_digest,
        source_commit_sha=expected_source_commit_sha,
        source_tree_sha=expected_source_tree_sha,
        host_digest=expected_host_digest,
        approval_reference_digest=expected_approval_reference_digest,
        request_digest=reviewed_request_digest,
        checkpoint_digest=reviewed_checkpoint_digest,
        runtime_config_digest=_runtime_config_digest(validated.runtime_config),
        provider_binding_digest=_provider_binding_digest(validated.request),
    )
    return ValidatedLiveRequest(
        request=validated.request,
        owner_checkpoint=validated.owner_checkpoint,
        runtime_config=validated.runtime_config,
        _read_capability=read_capability,
    )


def claim_materialized_live_request(
    validated: ValidatedLiveRequest,
    *,
    private_root: Path,
) -> LiveRequestExecutionCapability:
    """Consume one reviewed request before any provider can be constructed."""

    read_capability = getattr(validated, "_read_capability", None)
    if (
        type(validated) is not ValidatedLiveRequest
        or type(read_capability) is not _ReadCapability
        or read_capability.token is not _READ_CAPABILITY_SENTINEL
        or private_root_binding_digest(private_root)
        != read_capability.private_root_digest
        or validated.request.get("request_digest")
        != read_capability.request_digest
        or validated.owner_checkpoint.get("checkpoint_digest")
        != read_capability.checkpoint_digest
    ):
        _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED")

    def assert_local_bindings() -> datetime:
        if _current_source_identity() != (
            read_capability.source_commit_sha,
            read_capability.source_tree_sha,
        ):
            _fail("SOURCE_CHECKOUT_CHANGED")
        if _current_host_digest() != read_capability.host_digest:
            _fail("HOST_BINDING_CHANGED")
        current = _current_time()
        read_materialized_live_request(
            private_root,
            validated.request["request_file"],
            now=current,
            expected_source_commit_sha=read_capability.source_commit_sha,
            expected_source_tree_sha=read_capability.source_tree_sha,
            expected_host_digest=read_capability.host_digest,
            expected_approval_reference_digest=(
                read_capability.approval_reference_digest
            ),
            expected_request_digest=read_capability.request_digest,
            expected_checkpoint_digest=read_capability.checkpoint_digest,
        )
        return current

    claimed_at = assert_local_bindings()
    claimed_at_text = (
        claimed_at.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    body = {
        "record_type": (
            "scanalyze.platform_authority.gug376_live_consumption_claim.v1"
        ),
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "source_commit_sha": read_capability.source_commit_sha,
        "source_tree_sha": read_capability.source_tree_sha,
        "request_digest": read_capability.request_digest,
        "checkpoint_digest": read_capability.checkpoint_digest,
        "approval_reference_digest": read_capability.approval_reference_digest,
        "host_digest": read_capability.host_digest,
        "private_root_digest": read_capability.private_root_digest,
        "claimed_at": claimed_at_text,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    claim = {**body, "claim_digest": canonical_digest(body)}
    try:
        private_target_absent(private_root, CONSUMPTION_CLAIM)
        write_private_json(private_root, CONSUMPTION_CLAIM, claim)
        if canonical_json(
            read_private_json(private_root, CONSUMPTION_CLAIM)
        ) != canonical_json(claim):
            _fail("PRIVATE_CONSUMPTION_CLAIM_MISMATCH")
    except LiveRequestMaterializationError:
        raise
    except CollectorError as exc:
        code = (
            "PRIVATE_CONSUMPTION_ALREADY_CLAIMED"
            if exc.code == "PRIVATE_ARTIFACT_EXISTS"
            else exc.code
        )
        raise LiveRequestMaterializationError(code) from exc

    def validity_gate() -> None:
        assert_local_bindings()
        try:
            current_claim = read_private_json(private_root, CONSUMPTION_CLAIM)
        except CollectorError as exc:
            raise LiveRequestMaterializationError(
                "PRIVATE_CONSUMPTION_CLAIM_CHANGED"
            ) from exc
        if canonical_json(current_claim) != canonical_json(claim):
            _fail("PRIVATE_CONSUMPTION_CLAIM_CHANGED")

    return LiveRequestExecutionCapability(
        token=_EXECUTION_CAPABILITY_SENTINEL,
        read_capability=read_capability,
        claim=claim,
        validity_gate=validity_gate,
    )


def execution_capability_validity_gate(
    value: object,
) -> Callable[[], None]:
    """Return the bound gate only for a module-minted capability."""

    if (
        type(value) is not LiveRequestExecutionCapability
        or getattr(value, "_token", None) is not _EXECUTION_CAPABILITY_SENTINEL
        or not callable(getattr(value, "_validity_gate", None))
    ):
        _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED")
    return value._validity_gate


def assert_live_provider_capability_bindings(
    value: object,
    *,
    authority_profile: str,
    identity_center_profile: str,
    authority_expected_account_id: str,
    authority_expected_principal_digest: str,
    authority_expected_sso_role_name_digest: str,
    identity_expected_account_id: str,
    identity_expected_principal_digest: str,
    identity_expected_sso_role_name_digest: str,
    authority_verification_digest: str,
    identity_authority_verification_digest: str,
    sdk_runtime_root: str,
) -> Callable[[], None]:
    """Bind the concrete provider configuration to the reviewed request."""

    gate = execution_capability_validity_gate(value)
    checked_sdk_runtime_root, sdk_runtime_root_digest = (
        _sdk_runtime_root_binding(sdk_runtime_root)
    )
    supplied = canonical_digest(
        {
            "authority_profile": authority_profile,
            "identity_center_profile": identity_center_profile,
            "authority_expected_account_id": authority_expected_account_id,
            "authority_expected_principal_digest": (
                authority_expected_principal_digest
            ),
            "authority_expected_sso_role_name_digest": (
                authority_expected_sso_role_name_digest
            ),
            "identity_expected_account_id": identity_expected_account_id,
            "identity_expected_principal_digest": identity_expected_principal_digest,
            "identity_expected_sso_role_name_digest": (
                identity_expected_sso_role_name_digest
            ),
            "authority_verification_digest": authority_verification_digest,
            "identity_authority_verification_digest": (
                identity_authority_verification_digest
            ),
            "sdk_runtime_root": checked_sdk_runtime_root,
            "sdk_runtime_root_digest": sdk_runtime_root_digest,
        }
    )
    if supplied != value._provider_binding_digest:
        _fail("LIVE_PROVIDER_CAPABILITY_BINDING_MISMATCH")
    gate()
    with value._state_lock:
        if value._provider_bound or value._execution_started:
            _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_ALREADY_USED")
        value._provider_bound = True
    return gate


def assert_live_request_execution_capability(
    value: object,
    *,
    private_root: Path,
    source_commit_sha: str,
    source_tree_sha: str,
    request_digest: str,
    checkpoint_digest: str,
    approval_reference_digest: str,
    runtime_config: Mapping[str, Any],
) -> None:
    """Action-time verification of the one-shot provider capability."""

    gate = execution_capability_validity_gate(value)
    if (
        value._private_root_digest != private_root_binding_digest(private_root)
        or value._source_commit_sha != source_commit_sha
        or value._source_tree_sha != source_tree_sha
        or value._request_digest != request_digest
        or value._checkpoint_digest != checkpoint_digest
        or value._approval_reference_digest != approval_reference_digest
        or value._runtime_config_digest != _runtime_config_digest(runtime_config)
    ):
        _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_MISMATCH")
    gate()
    with value._state_lock:
        if not value._provider_bound or value._execution_started:
            _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_ALREADY_USED")
        value._execution_started = True


__all__ = [
    "ACTION",
    "CHECKPOINT_RECORD_TYPE",
    "CONSUMPTION_CLAIM",
    "IMPLEMENTATION_ISSUE",
    "LiveRequestMaterializationError",
    "LiveRequestExecutionCapability",
    "MaterializedLiveRequest",
    "PARENT_ISSUE",
    "REQUEST_RECORD_TYPE",
    "ValidatedLiveRequest",
    "assert_live_request_execution_capability",
    "assert_live_provider_capability_bindings",
    "claim_materialized_live_request",
    "execution_capability_validity_gate",
    "materialize_live_request",
    "persist_materialized_live_request",
    "private_root_binding_digest",
    "read_materialized_live_request",
    "validate_materialized_live_request",
]
