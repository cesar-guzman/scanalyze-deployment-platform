"""Attested GUG-376/GUG-395 dual-domain pre-plan collision contract.

This module is inert at import time.  It materializes one private, digest-bound
request, mints a one-shot execution capability from create-only custody, keeps
the connected read-only budget global across both AWS domains, and projects a
private provider result into one digest-only public receipt.

It does not create, adopt, repair, delete, deploy, or authorize any AWS
resource.  A matching resource is always a collision, even when its tags look
compatible with the planned target.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import threading
from typing import Any

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError,
    private_target_absent,
    read_private_json,
    write_private_json,
)
from tooling.platform_authority_gug395_preplan_seed import (
    ARTIFACT_BUCKET_NAMESPACE,
    AUTHORITY_ACCOUNT_ID,
    validate_mutation_plan,
    validate_preplan_seed,
)
from tooling import platform_authority_repository_source_verifier as source_verifier


IMPLEMENTATION_ISSUE = "GUG-376"
SEED_ISSUE = "GUG-395"
DOWNSTREAM_CONSUMER_ISSUE = "GUG-365"
REGION = "us-east-1"
EXPECTED_REMOTE_REF = "refs/remotes/origin/main"
PRODUCTION_STATUS = "NO-GO"
EXECUTION_COMPLETED = "COMPLETED"
EXECUTION_BLOCKED = "BLOCKED"

REQUEST_TYPE_V1 = (
    "scanalyze.platform_authority.gug395_preplan_collision_request.v1"
)
REQUEST_TYPE_V2 = (
    "scanalyze.platform_authority.gug395_preplan_collision_request.v2"
)
# New materializations are KMS-bound v2 records.  The explicit v1 constant and
# validator below remain available for persisted pre-migration requests.
REQUEST_TYPE = REQUEST_TYPE_V2
CLAIM_TYPE = "scanalyze.platform_authority.gug395_preplan_collision_claim.v1"
PRIVATE_EVIDENCE_TYPE = (
    "scanalyze.platform_authority.gug395_preplan_collision_private_evidence.v1"
)
RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug395_preplan_collision_probe_receipt.v1"
)
RESULT_TYPE = (
    "scanalyze.platform_authority.gug395_preplan_collision_result_bundle.v1"
)

DEFAULT_REQUEST_FILE = "gug395-preplan-collision-request.json"
DEFAULT_CLAIM_FILE = "gug395-preplan-collision-claim.json"
DEFAULT_EVIDENCE_FILE = "gug395-preplan-collision-private-evidence.json"
DEFAULT_RECEIPT_FILE = "gug395-preplan-collision-receipt.json"
DEFAULT_RESULT_FILE = "gug395-preplan-collision-result.json"

MAX_WINDOW = timedelta(minutes=15)
MAX_PAGES = 50
MAX_PROVIDER_CALLS = 2_048
MAX_SESSION_BOOTSTRAP_ATTEMPTS = 4
MAX_CREDENTIAL_VENDING_CALLS = 4
MAX_NETWORK_CALLS = MAX_PROVIDER_CALLS + MAX_CREDENTIAL_VENDING_CALLS
MAX_PAGE_CALLS = 1_024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_OWNED_BUCKETS = 256
MAX_KMS_KEYS = 256
MAX_SIGNING_PROFILES = 256
MAX_CODE_SIGNING_CONFIGS = 256
MAX_APPLICATIONS = 256
MAX_PERMISSION_SETS = 512
MAX_MODELED_COST_NANO_USD = 50_000_000
PER_NETWORK_CALL_COST_NANO_USD = 5_000
PER_PROJECTED_BYTE_COST_NANO_USD = 1

ABSENT_READY = "ABSENT_READY_FOR_PROVIDER_IMPLEMENTATION"
COLLISION_BLOCKED = "COLLISION_BLOCKED_NO_MUTATION"
UNCERTAIN = "UNCERTAIN_RECONCILE_ONLY"
CLASSIFICATIONS = frozenset({ABSENT_READY, COLLISION_BLOCKED, UNCERTAIN})

AUTHORITY_ACTIONS = frozenset(
    {
        "sts:GetCallerIdentity",
        "s3:ListAllMyBuckets",
        "s3:GetBucketTagging",
        "kms:ListAliases",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:ListResourceTags",
        "signer:ListSigningProfiles",
        "signer:GetSigningProfile",
        "signer:ListTagsForResource",
        "lambda:ListCodeSigningConfigs",
        "lambda:GetCodeSigningConfig",
        "lambda:ListTags",
    }
)
IDENTITY_ACTIONS_V1 = frozenset(
    {
        "sts:GetCallerIdentity",
        "sso:ListInstances",
        "sso:ListApplications",
        "sso:DescribeApplication",
        "sso:ListPermissionSets",
        "sso:DescribePermissionSet",
        "sso:ListTagsForResource",
    }
)
IDENTITY_ACTIONS_V2 = IDENTITY_ACTIONS_V1 | {"sso:DescribeInstance"}
IDENTITY_ACTIONS = IDENTITY_ACTIONS_V2
COLLISION_OPERATION_ALLOWLIST_V1: Mapping[str, frozenset[str]] = {
    "authority": AUTHORITY_ACTIONS,
    "identity_center": IDENTITY_ACTIONS_V1,
}
COLLISION_OPERATION_ALLOWLIST: Mapping[str, frozenset[str]] = {
    "authority": AUTHORITY_ACTIONS,
    "identity_center": IDENTITY_ACTIONS_V2,
}
PAGINATED_ACTIONS = frozenset(
    {
        "s3:ListAllMyBuckets",
        "kms:ListAliases",
        "kms:ListKeys",
        "kms:ListResourceTags",
        "signer:ListSigningProfiles",
        "lambda:ListCodeSigningConfigs",
        "sso:ListInstances",
        "sso:ListApplications",
        "sso:ListPermissionSets",
        "sso:ListTagsForResource",
    }
)

AUTHORITY_TAG_CONTRACT = {"ScanalyzeIssue": "GUG-376"}
IDENTITY_TAG_CONTRACT = {
    "managed_by": "identity-center",
    "service": "scanalyze-platform-authority",
    "work_package": "GUG-376",
    "environment": "non-production",
    "production": "false",
}

TARGET_ORDER = (
    "artifact_bucket",
    "kms_key",
    "signing_profile",
    "code_signing_config",
    "identity_center_application",
    "classifier_permission_set",
    "approver_permission_set",
)

_SOURCE_PATHS = (
    "tooling/platform_authority_gug395_preplan_collision_probe.py",
    "tooling/platform_authority_gug395_preplan_collision_executor.py",
    "tooling/platform_authority_gug376_live_provider.py",
    "scripts/deployment/platform-authority-gug395-preplan-collision-probe.py",
    "policies/iam/platform-authority-gug395-preplan-collision-authority-read-only.json",
    "policies/iam/platform-authority-gug395-preplan-collision-identity-read-only.json",
    "schemas/platform-authority-gug395-preplan-collision-probe-receipt.v1.schema.json",
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_IDENTITY_STORE = re.compile(r"^d-[A-Za-z0-9]{10}$")
_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9.-]{16}$"
)
_KMS_KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:([0-9]{12}):key/"
    r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|"
    r"mrk-[0-9a-f]{32})$"
)
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACCOUNT_REGIONAL_ARTIFACT_BUCKET = re.compile(
    r"^scanalyze-g376-art-[a-f0-9]{12}-"
    rf"{AUTHORITY_ACCOUNT_ID}-{REGION}-an$"
)
_PRINCIPAL = re.compile(
    r"^arn:aws:sts::([0-9]{12}):assumed-role/"
    r"([A-Za-z0-9+=,.@_/-]+)/([A-Za-z0-9+=,.@_-]+)$"
)
_STAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}Z$"
)
_FORBIDDEN_PUBLIC = re.compile(
    r"(?:arn:aws:|/Users/|/home/|AWSReservedSSO_|ssoins-|"
    r"d-[A-Za-z0-9]{10}|\.aws/)"
)
_FORBIDDEN_PROFILE_FRAGMENTS = (
    "administrator",
    "admin",
    "bootstrap",
    "seed",
    "deploy",
    "destroy",
)

_VERIFIED_SOURCE_SENTINEL = object()
_EXECUTION_CAPABILITY_SENTINEL = object()


class CollisionProbeError(RuntimeError):
    """Stable, public-safe fail-closed error."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "COLLISION_PROBE_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise CollisionProbeError(code)


def _copy(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except Exception as exc:
        raise CollisionProbeError(code) from exc


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _parse_stamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or _STAMP.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollisionProbeError(code) from exc
    if parsed.tzinfo is None:
        _fail(code)
    return parsed.astimezone(UTC).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("COLLISION_CLOCK_INVALID")
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    if field in value:
        _fail("COLLISION_SELF_DIGEST_INVALID")
    value[field] = canonical_digest(value)
    return value


def _verify_self_digest(
    value: Mapping[str, Any], field: str, code: str
) -> None:
    if set(value).issuperset({field}) is False:
        _fail(code)
    body = {key: item for key, item in value.items() if key != field}
    if value.get(field) != canonical_digest(body):
        _fail(code)


def _require_exact_keys(
    value: Mapping[str, Any], keys: set[str], code: str
) -> None:
    if set(value) != keys:
        _fail(code)


def _forbidden_profile(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return any(fragment in normalized for fragment in _FORBIDDEN_PROFILE_FRAGMENTS)


def _required_source_digests(repo_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for relative in _SOURCE_PATHS:
            path = repo_root / relative
            if path.is_symlink() or not path.is_file():
                _fail("COLLISION_SOURCE_PATH_INVALID")
            result[relative] = "sha256:" + sha256(path.read_bytes()).hexdigest()
    except CollisionProbeError:
        raise
    except OSError as exc:
        raise CollisionProbeError("COLLISION_SOURCE_PATH_INVALID") from exc
    return result


@dataclass(frozen=True)
class VerifiedCollisionProbeSource:
    """Opaque proof of an exact clean fetched ``origin/main`` checkout."""

    _token: object
    _record: dict[str, Any]
    _repo_root: Path

    def __post_init__(self) -> None:
        if self._token is not _VERIFIED_SOURCE_SENTINEL:
            _fail("COLLISION_SOURCE_VERIFICATION_REQUIRED")
        _validate_source_record(self._record)
        if not self._repo_root.is_absolute():
            _fail("COLLISION_SOURCE_ROOT_INVALID")

    @property
    def record(self) -> dict[str, Any]:
        return _copy(self._record, "COLLISION_SOURCE_RECORD_INVALID")

    def reverify(self) -> None:
        record = self._record
        try:
            observed = source_verifier.verify_clean_repository_source(
                repo_root=self._repo_root,
                expected_commit_sha=str(record["source_commit_sha"]),
                expected_tree_sha=str(record["source_tree_sha"]),
                expected_remote_ref=EXPECTED_REMOTE_REF,
                required_source_digests=_required_source_digests(self._repo_root),
            ).document
        except source_verifier.RepositorySourceVerificationError as exc:
            raise CollisionProbeError(exc.code) from exc
        if observed != record:
            _fail("COLLISION_SOURCE_REVERIFICATION_MISMATCH")


def _validate_source_record(record: Mapping[str, Any]) -> None:
    required = {
        "record_type",
        "schema_version",
        "verifier_id",
        "expected_remote_ref",
        "source_commit_sha",
        "source_tree_sha",
        "remote_ref_commit_sha",
        "checkout_clean",
        "required_source_count",
        "required_source_set_digest",
        "repository_tree_entries_digest",
        "aws_calls",
        "aws_mutations",
        "verification_digest",
    }
    _require_exact_keys(record, required, "COLLISION_SOURCE_RECORD_INVALID")
    if (
        record.get("record_type") != source_verifier.RECORD_TYPE
        or record.get("schema_version") != 1
        or record.get("verifier_id") != source_verifier.VERIFIER_ID
        or record.get("expected_remote_ref") != EXPECTED_REMOTE_REF
        or record.get("remote_ref_commit_sha") != record.get("source_commit_sha")
        or record.get("checkout_clean") is not True
        or record.get("required_source_count") != len(_SOURCE_PATHS)
        or record.get("aws_calls") != 0
        or record.get("aws_mutations") != 0
    ):
        _fail("COLLISION_SOURCE_RECORD_INVALID")
    _sha(record.get("source_commit_sha"), "COLLISION_SOURCE_RECORD_INVALID")
    _sha(record.get("source_tree_sha"), "COLLISION_SOURCE_RECORD_INVALID")
    for field in (
        "required_source_set_digest",
        "repository_tree_entries_digest",
        "verification_digest",
    ):
        _digest(record.get(field), "COLLISION_SOURCE_RECORD_INVALID")
    _verify_self_digest(
        record,
        "verification_digest",
        "COLLISION_SOURCE_VERIFICATION_DIGEST_MISMATCH",
    )


def verify_collision_probe_source(
    *, repo_root: Path, expected_commit_sha: str, expected_tree_sha: str
) -> VerifiedCollisionProbeSource:
    """Verify the future merged probe bytes against clean ``origin/main``."""

    root = Path(repo_root)
    if not root.is_absolute():
        _fail("COLLISION_SOURCE_ROOT_INVALID")
    try:
        record = source_verifier.verify_clean_repository_source(
            repo_root=root,
            expected_commit_sha=_sha(
                expected_commit_sha, "COLLISION_SOURCE_BINDING_INVALID"
            ),
            expected_tree_sha=_sha(
                expected_tree_sha, "COLLISION_SOURCE_BINDING_INVALID"
            ),
            expected_remote_ref=EXPECTED_REMOTE_REF,
            required_source_digests=_required_source_digests(root),
        ).document
    except source_verifier.RepositorySourceVerificationError as exc:
        raise CollisionProbeError(exc.code) from exc
    _validate_source_record(record)
    return VerifiedCollisionProbeSource(
        _VERIFIED_SOURCE_SENTINEL,
        _copy(record, "COLLISION_SOURCE_RECORD_INVALID"),
        root,
    )


def operational_host_digest() -> str:
    """Return a non-identifying binding to the current execution host."""

    hostname = platform.node()
    if not hostname:
        _fail("COLLISION_HOST_BINDING_UNAVAILABLE")
    return canonical_digest(
        {
            "hostname": hostname,
            "machine": platform.machine(),
            "system": platform.system(),
            "python": platform.python_version(),
            "uid": os.geteuid(),
        }
    )


def _assert_operational_host_binding(request: Mapping[str, Any]) -> None:
    """Require a persisted request to remain on its materialization host."""

    if request["operational_host_digest"] != operational_host_digest():
        _fail("COLLISION_HOST_BINDING_MISMATCH")


def private_root_digest(private_root: Path) -> str:
    try:
        root = Path(private_root).resolve(strict=True)
    except OSError as exc:
        raise CollisionProbeError("COLLISION_PRIVATE_ROOT_INVALID") from exc
    if not root.is_absolute() or not root.is_dir():
        _fail("COLLISION_PRIVATE_ROOT_INVALID")
    # This intentionally matches the exact GUG-395 custody binding while the
    # collector independently enforces owner-only 0700/0600 inode custody.
    return canonical_digest({"private_root": str(root)})


def _profile_bindings_v1(
    value: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    """Read the historical v1 profile shape without changing its digest."""

    if not isinstance(value, Mapping) or set(value) != {
        "authority",
        "identity_center",
    }:
        _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    result: dict[str, dict[str, str]] = {}
    fields = {
        "name",
        "expected_account_id",
        "expected_principal_digest",
        "expected_sso_role_name_digest",
        "authority_verification_digest",
    }
    for domain in ("authority", "identity_center"):
        raw = value.get(domain)
        if not isinstance(raw, Mapping):
            _fail("COLLISION_PROFILE_BINDINGS_INVALID")
        _require_exact_keys(raw, fields, "COLLISION_PROFILE_BINDINGS_INVALID")
        name = raw.get("name")
        account = raw.get("expected_account_id")
        if (
            not isinstance(name, str)
            or _PROFILE.fullmatch(name) is None
            or name.casefold() == "default"
            or _forbidden_profile(name)
            or not isinstance(account, str)
            or _ACCOUNT.fullmatch(account) is None
        ):
            _fail("COLLISION_PROFILE_BINDINGS_INVALID")
        for field in fields - {"name", "expected_account_id"}:
            _digest(raw.get(field), "COLLISION_PROFILE_BINDINGS_INVALID")
        result[domain] = {key: str(raw[key]) for key in fields}
    if (
        result["authority"]["name"].casefold()
        == result["identity_center"]["name"].casefold()
        or result["authority"]["expected_account_id"]
        == result["identity_center"]["expected_account_id"]
    ):
        _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    return result


def _profile_bindings_v2(
    value: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {
        "authority",
        "identity_center",
    }:
        _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    result: dict[str, dict[str, Any]] = {}
    common_fields = {
        "name",
        "expected_account_id",
        "expected_principal_digest",
        "expected_sso_role_name_digest",
        "authority_verification_digest",
    }
    for domain in ("authority", "identity_center"):
        raw = value.get(domain)
        if not isinstance(raw, Mapping):
            _fail("COLLISION_PROFILE_BINDINGS_INVALID")
        fields = common_fields | (
            {
                "identity_center_kms_mode",
                "identity_center_kms_key_arn",
            }
            if domain == "identity_center"
            else set()
        )
        _require_exact_keys(raw, fields, "COLLISION_PROFILE_BINDINGS_INVALID")
        name = raw.get("name")
        account = raw.get("expected_account_id")
        if (
            not isinstance(name, str)
            or _PROFILE.fullmatch(name) is None
            or name.casefold() == "default"
            or _forbidden_profile(name)
            or not isinstance(account, str)
            or _ACCOUNT.fullmatch(account) is None
        ):
            _fail("COLLISION_PROFILE_BINDINGS_INVALID")
        for field in common_fields - {"name", "expected_account_id"}:
            _digest(raw.get(field), "COLLISION_PROFILE_BINDINGS_INVALID")
        result[domain] = {key: raw[key] for key in fields}
        if domain == "identity_center":
            mode = raw.get("identity_center_kms_mode")
            key_arn = raw.get("identity_center_kms_key_arn")
            key_match = (
                _KMS_KEY_ARN.fullmatch(key_arn)
                if isinstance(key_arn, str)
                else None
            )
            if (
                mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
                or (mode == "AWS_OWNED_KMS_KEY" and key_arn is not None)
                or (
                    mode == "CUSTOMER_MANAGED_KEY"
                    and (
                        key_match is None
                        or key_match.group(1) != account
                    )
                )
            ):
                _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    if (
        result["authority"]["name"].casefold()
        == result["identity_center"]["name"].casefold()
        or result["authority"]["expected_account_id"]
        == result["identity_center"]["expected_account_id"]
    ):
        _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    return result


def _profile_bindings(
    value: Mapping[str, Any], *, schema_version: int
) -> dict[str, dict[str, Any]]:
    if schema_version == 1:
        return _profile_bindings_v1(value)
    if schema_version == 2:
        return _profile_bindings_v2(value)
    _fail("COLLISION_REQUEST_VERSION_UNSUPPORTED")


def _decision_values(seed: Mapping[str, Any]) -> dict[str, str]:
    decisions = seed.get("decisions")
    if not isinstance(decisions, list):
        _fail("COLLISION_SEED_DECISIONS_INVALID")
    result: dict[str, str] = {}
    for decision in decisions:
        if not isinstance(decision, Mapping):
            _fail("COLLISION_SEED_DECISIONS_INVALID")
        key, value = decision.get("key"), decision.get("value")
        if not isinstance(key, str) or not isinstance(value, str) or not value:
            _fail("COLLISION_SEED_DECISIONS_INVALID")
        if canonical_digest(value) != decision.get("value_digest"):
            _fail("COLLISION_SEED_DECISIONS_INVALID")
        result[key] = value
    required = {
        "artifact_bucket_name",
        "authority_account_id",
        "kms_alias_name",
        "identity_center_application_name",
        "identity_center_instance_arn",
        "classifier_permission_set_name",
        "approver_permission_set_name",
        "signing_profile_name",
    }
    if not required <= set(result):
        _fail("COLLISION_SEED_DECISIONS_INVALID")
    return result


def collision_target_catalog(seed: Mapping[str, Any]) -> dict[str, Any]:
    """Derive the seven private collision selectors from the exact seed."""

    validate_preplan_seed(seed)
    values = _decision_values(seed)
    authority_tags_digest = canonical_digest(AUTHORITY_TAG_CONTRACT)
    identity_tags_digest = canonical_digest(IDENTITY_TAG_CONTRACT)
    targets = {
        "artifact_bucket": {
            "domain": "authority",
            "selector_kind": "ACCOUNT_REGIONAL_BUCKET_NAME_AND_TAG",
            "name": values["artifact_bucket_name"],
            "bucket_namespace": ARTIFACT_BUCKET_NAMESPACE,
            "expected_tag_contract_digest": authority_tags_digest,
        },
        "kms_key": {
            "domain": "authority",
            "selector_kind": "KMS_ALIAS_OR_TAG",
            "alias_name": values["kms_alias_name"],
            "expected_tag_contract_digest": authority_tags_digest,
        },
        "signing_profile": {
            "domain": "authority",
            "selector_kind": "SIGNING_PROFILE_NAME_OR_TAG",
            "name": values["signing_profile_name"],
            "expected_tag_contract_digest": authority_tags_digest,
        },
        "code_signing_config": {
            "domain": "authority",
            "selector_kind": "TAG_ONLY",
            "expected_tag_contract_digest": authority_tags_digest,
        },
        "identity_center_application": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": values["identity_center_instance_arn"],
            "name": values["identity_center_application_name"],
            "expected_tag_contract_digest": identity_tags_digest,
        },
        "classifier_permission_set": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": values["identity_center_instance_arn"],
            "name": values["classifier_permission_set_name"],
            "expected_tag_contract_digest": identity_tags_digest,
        },
        "approver_permission_set": {
            "domain": "identity_center",
            "selector_kind": "INSTANCE_NAME_OR_TAG",
            "instance_arn": values["identity_center_instance_arn"],
            "name": values["approver_permission_set_name"],
            "expected_tag_contract_digest": identity_tags_digest,
        },
    }
    if tuple(targets) != TARGET_ORDER:
        _fail("COLLISION_TARGET_CATALOG_INVALID")
    return targets


def _validate_target_catalog(targets: object) -> Mapping[str, Any]:
    """Validate target semantics without relying on JSON object key order."""

    if not isinstance(targets, Mapping) or set(targets) != set(TARGET_ORDER):
        _fail("COLLISION_TARGET_CATALOG_INVALID")
    authority_digest = canonical_digest(AUTHORITY_TAG_CONTRACT)
    identity_digest = canonical_digest(IDENTITY_TAG_CONTRACT)
    specs: Mapping[str, tuple[str, str, frozenset[str], str]] = {
        "artifact_bucket": (
            "authority",
            "ACCOUNT_REGIONAL_BUCKET_NAME_AND_TAG",
            frozenset({"name", "bucket_namespace"}),
            authority_digest,
        ),
        "kms_key": (
            "authority",
            "KMS_ALIAS_OR_TAG",
            frozenset({"alias_name"}),
            authority_digest,
        ),
        "signing_profile": (
            "authority",
            "SIGNING_PROFILE_NAME_OR_TAG",
            frozenset({"name"}),
            authority_digest,
        ),
        "code_signing_config": (
            "authority",
            "TAG_ONLY",
            frozenset(),
            authority_digest,
        ),
        "identity_center_application": (
            "identity_center",
            "INSTANCE_NAME_OR_TAG",
            frozenset({"instance_arn", "name"}),
            identity_digest,
        ),
        "classifier_permission_set": (
            "identity_center",
            "INSTANCE_NAME_OR_TAG",
            frozenset({"instance_arn", "name"}),
            identity_digest,
        ),
        "approver_permission_set": (
            "identity_center",
            "INSTANCE_NAME_OR_TAG",
            frozenset({"instance_arn", "name"}),
            identity_digest,
        ),
    }
    common = {"domain", "selector_kind", "expected_tag_contract_digest"}
    instance_arns: set[str] = set()
    for target_name in TARGET_ORDER:
        raw = targets.get(target_name)
        if not isinstance(raw, Mapping):
            _fail("COLLISION_TARGET_CATALOG_INVALID")
        domain, selector_kind, selector_fields, tag_digest = specs[target_name]
        _require_exact_keys(
            raw,
            common | set(selector_fields),
            "COLLISION_TARGET_CATALOG_INVALID",
        )
        if (
            raw.get("domain") != domain
            or raw.get("selector_kind") != selector_kind
            or raw.get("expected_tag_contract_digest") != tag_digest
        ):
            _fail("COLLISION_TARGET_CATALOG_INVALID")
        for field in selector_fields:
            value = raw.get(field)
            if not isinstance(value, str) or not value or value != value.strip():
                _fail("COLLISION_TARGET_CATALOG_INVALID")
            if field == "instance_arn":
                if _INSTANCE_ARN.fullmatch(value) is None:
                    _fail("COLLISION_TARGET_CATALOG_INVALID")
                instance_arns.add(value)
        if target_name == "artifact_bucket" and (
            raw.get("bucket_namespace") != ARTIFACT_BUCKET_NAMESPACE
            or _ACCOUNT_REGIONAL_ARTIFACT_BUCKET.fullmatch(
                str(raw.get("name"))
            )
            is None
        ):
            _fail("COLLISION_TARGET_CATALOG_INVALID")
    if len(instance_arns) != 1:
        _fail("COLLISION_TARGET_CATALOG_INVALID")
    return targets


def _closed_policy(
    *,
    domain: str,
    not_before: str,
    expires_at: str,
    schema_version: int = 2,
) -> dict[str, Any]:
    allowlist = {
        1: COLLISION_OPERATION_ALLOWLIST_V1,
        2: COLLISION_OPERATION_ALLOWLIST,
    }.get(schema_version)
    if allowlist is None:
        _fail("COLLISION_REQUEST_VERSION_UNSUPPORTED")
    actions = allowlist.get(domain)
    if actions is None:
        _fail("COLLISION_POLICY_DOMAIN_INVALID")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ConfirmOnlyTheCurrentCaller",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
                "Condition": {
                    "DateGreaterThanEquals": {"aws:CurrentTime": not_before},
                    "DateLessThan": {"aws:CurrentTime": expires_at},
                },
            },
            {
                "Sid": "ReadOnlyPreplanCollisionInventory",
                "Effect": "Allow",
                "Action": sorted(actions - {"sts:GetCallerIdentity"}),
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": REGION}
                },
            },
        ],
    }


def _validate_sdk_runtime_root(value: object) -> str:
    if not isinstance(value, str):
        _fail("COLLISION_SDK_RUNTIME_ROOT_INVALID")
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CollisionProbeError("COLLISION_SDK_RUNTIME_ROOT_INVALID") from exc
    if not path.is_absolute() or resolved != path or not resolved.is_dir():
        _fail("COLLISION_SDK_RUNTIME_ROOT_INVALID")
    return str(resolved)


def materialize_collision_probe_request(
    *,
    seed: Mapping[str, Any],
    plan: Mapping[str, Any],
    verified_source: VerifiedCollisionProbeSource,
    profiles: Mapping[str, Any],
    sdk_runtime_root: str,
    private_custody_digest: str,
    operational_host_binding_digest: str,
    approval_reference_digest: str,
    not_before: str,
    expires_at: str,
    created_at: str,
) -> dict[str, Any]:
    """Materialize one private request without making an AWS call."""

    validate_preplan_seed(
        seed, expected_private_custody_digest=private_custody_digest
    )
    validate_mutation_plan(plan, seed=seed)
    if not isinstance(verified_source, VerifiedCollisionProbeSource):
        _fail("COLLISION_SOURCE_VERIFICATION_REQUIRED")
    verified_source.reverify()
    source_record = verified_source.record
    start = _parse_stamp(not_before, "COLLISION_WINDOW_INVALID")
    end = _parse_stamp(expires_at, "COLLISION_WINDOW_INVALID")
    created = _parse_stamp(created_at, "COLLISION_CREATED_AT_INVALID")
    if not timedelta(seconds=1) <= end - start <= MAX_WINDOW or created > end:
        _fail("COLLISION_WINDOW_INVALID")
    checked_profiles = _profile_bindings(profiles, schema_version=2)
    if checked_profiles["authority"]["expected_account_id"] != _decision_values(
        seed
    )["authority_account_id"]:
        _fail("COLLISION_AUTHORITY_ACCOUNT_MISMATCH")
    _digest(private_custody_digest, "COLLISION_PRIVATE_CUSTODY_INVALID")
    _digest(
        operational_host_binding_digest,
        "COLLISION_HOST_BINDING_INVALID",
    )
    _digest(approval_reference_digest, "COLLISION_APPROVAL_BINDING_INVALID")
    targets = collision_target_catalog(seed)
    policies = {
        domain: _closed_policy(
            domain=domain,
            not_before=not_before,
            expires_at=expires_at,
            schema_version=2,
        )
        for domain in ("authority", "identity_center")
    }
    policy_digests = {
        domain: canonical_digest(policy) for domain, policy in policies.items()
    }
    budget = {
        "max_pages": MAX_PAGES,
        "max_provider_calls": MAX_PROVIDER_CALLS,
        "max_session_bootstrap_attempts": MAX_SESSION_BOOTSTRAP_ATTEMPTS,
        "max_credential_vending_calls": MAX_CREDENTIAL_VENDING_CALLS,
        "max_network_calls": MAX_NETWORK_CALLS,
        "max_page_calls": MAX_PAGE_CALLS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "max_owned_buckets": MAX_OWNED_BUCKETS,
        "max_kms_keys": MAX_KMS_KEYS,
        "max_signing_profiles": MAX_SIGNING_PROFILES,
        "max_code_signing_configs": MAX_CODE_SIGNING_CONFIGS,
        "max_applications": MAX_APPLICATIONS,
        "max_permission_sets": MAX_PERMISSION_SETS,
        "max_modeled_cost_nano_usd": MAX_MODELED_COST_NANO_USD,
        "per_network_call_cost_nano_usd": PER_NETWORK_CALL_COST_NANO_USD,
        "per_projected_byte_cost_nano_usd": PER_PROJECTED_BYTE_COST_NANO_USD,
    }
    _seal(budget, "budget_digest")
    request = {
        "record_type": REQUEST_TYPE_V2,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "seed_issue": SEED_ISSUE,
        "downstream_consumer_issue": DOWNSTREAM_CONSUMER_ISSUE,
        "environment": "authority-non-production",
        "region": REGION,
        "source_commit_sha": source_record["source_commit_sha"],
        "source_tree_sha": source_record["source_tree_sha"],
        "source_verification_digest": source_record["verification_digest"],
        "repository_tree_entries_digest": source_record[
            "repository_tree_entries_digest"
        ],
        "preplan_source_commit_sha": seed["source_commit_sha"],
        "preplan_source_tree_sha": seed["source_tree_sha"],
        "preplan_seed_digest": seed["seed_digest"],
        "mutation_plan_digest": plan["plan_digest"],
        "private_custody_digest": private_custody_digest,
        "operational_host_digest": operational_host_binding_digest,
        "approval_reference_digest": approval_reference_digest,
        "bound_values_digest": seed["bound_values_digest"],
        "operation_catalog_digest": seed["operation_catalog_digest"],
        "phase_catalog_digest": seed["phase_catalog_digest"],
        "provider_slot_catalog_digest": seed["provider_slot_catalog_digest"],
        "targets": targets,
        "target_catalog_digest": canonical_digest(targets),
        "expected_tag_contract_digest": canonical_digest(
            {
                "authority": AUTHORITY_TAG_CONTRACT,
                "identity_center": IDENTITY_TAG_CONTRACT,
            }
        ),
        "profiles": checked_profiles,
        "profile_binding_digest": canonical_digest(checked_profiles),
        "sdk_runtime_root": _validate_sdk_runtime_root(sdk_runtime_root),
        "sdk_runtime_root_digest": canonical_digest(sdk_runtime_root),
        "not_before": not_before,
        "expires_at": expires_at,
        "created_at": created_at,
        "window_digest": canonical_digest(
            {"not_before": not_before, "expires_at": expires_at}
        ),
        "policies": policies,
        "policy_digests": policy_digests,
        "policy_set_digest": canonical_digest(policy_digests),
        "budget": budget,
        "budget_digest": budget["budget_digest"],
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
    }
    _seal(request, "request_digest")
    validate_collision_probe_request(request)
    verified_source.reverify()
    return request


def _collision_probe_request_version(value: Mapping[str, Any]) -> int:
    selector = (value.get("record_type"), value.get("schema_version"))
    if selector == (REQUEST_TYPE_V1, 1):
        return 1
    if selector == (REQUEST_TYPE_V2, 2):
        return 2
    _fail("COLLISION_REQUEST_VERSION_UNSUPPORTED")


def _validate_collision_probe_request(
    request: Mapping[str, Any], *, schema_version: int
) -> None:
    value = _copy(request, "COLLISION_REQUEST_INVALID")
    if not isinstance(value, Mapping):
        _fail("COLLISION_REQUEST_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "seed_issue",
        "downstream_consumer_issue", "environment", "region",
        "source_commit_sha", "source_tree_sha", "source_verification_digest",
        "repository_tree_entries_digest", "preplan_source_commit_sha",
        "preplan_source_tree_sha", "preplan_seed_digest",
        "mutation_plan_digest", "private_custody_digest",
        "operational_host_digest", "approval_reference_digest",
        "bound_values_digest", "operation_catalog_digest",
        "phase_catalog_digest", "provider_slot_catalog_digest", "targets",
        "target_catalog_digest", "expected_tag_contract_digest", "profiles",
        "profile_binding_digest", "sdk_runtime_root", "sdk_runtime_root_digest",
        "not_before", "expires_at", "created_at", "window_digest", "policies",
        "policy_digests", "policy_set_digest", "budget", "budget_digest",
        "read_only", "aws_calls", "aws_mutations", "deployment_authorized",
        "production", "production_status", "request_digest",
    }
    _require_exact_keys(value, required, "COLLISION_REQUEST_FIELDS_INVALID")
    constants = {
        "record_type": {
            1: REQUEST_TYPE_V1,
            2: REQUEST_TYPE_V2,
        }[schema_version],
        "schema_version": schema_version,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "seed_issue": SEED_ISSUE,
        "downstream_consumer_issue": DOWNSTREAM_CONSUMER_ISSUE,
        "environment": "authority-non-production",
        "region": REGION,
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("COLLISION_REQUEST_SCOPE_INVALID")
    for field in (
        "source_commit_sha",
        "source_tree_sha",
        "preplan_source_commit_sha",
        "preplan_source_tree_sha",
    ):
        _sha(value.get(field), "COLLISION_REQUEST_SOURCE_INVALID")
    for field in (
        "source_verification_digest", "repository_tree_entries_digest",
        "preplan_seed_digest", "mutation_plan_digest", "private_custody_digest",
        "operational_host_digest", "approval_reference_digest",
        "bound_values_digest", "operation_catalog_digest", "phase_catalog_digest",
        "provider_slot_catalog_digest", "target_catalog_digest",
        "expected_tag_contract_digest", "profile_binding_digest",
        "sdk_runtime_root_digest", "window_digest", "policy_set_digest",
        "budget_digest",
    ):
        _digest(value.get(field), "COLLISION_REQUEST_DIGEST_INVALID")
    start = _parse_stamp(value.get("not_before"), "COLLISION_WINDOW_INVALID")
    end = _parse_stamp(value.get("expires_at"), "COLLISION_WINDOW_INVALID")
    created = _parse_stamp(value.get("created_at"), "COLLISION_CREATED_AT_INVALID")
    if not timedelta(seconds=1) <= end - start <= MAX_WINDOW or created > end:
        _fail("COLLISION_WINDOW_INVALID")
    if value["window_digest"] != canonical_digest(
        {"not_before": value["not_before"], "expires_at": value["expires_at"]}
    ):
        _fail("COLLISION_WINDOW_DIGEST_MISMATCH")
    checked_profiles = _profile_bindings(
        value["profiles"], schema_version=schema_version
    )
    if (
        checked_profiles["authority"]["expected_account_id"]
        != AUTHORITY_ACCOUNT_ID
    ):
        _fail("COLLISION_PROFILE_BINDINGS_INVALID")
    if value["profile_binding_digest"] != canonical_digest(checked_profiles):
        _fail("COLLISION_PROFILE_BINDING_DIGEST_MISMATCH")
    if value["sdk_runtime_root_digest"] != canonical_digest(
        value["sdk_runtime_root"]
    ):
        _fail("COLLISION_SDK_RUNTIME_BINDING_MISMATCH")
    targets = _validate_target_catalog(value.get("targets"))
    if value["target_catalog_digest"] != canonical_digest(targets):
        _fail("COLLISION_TARGET_CATALOG_INVALID")
    if value["expected_tag_contract_digest"] != canonical_digest(
        {
            "authority": AUTHORITY_TAG_CONTRACT,
            "identity_center": IDENTITY_TAG_CONTRACT,
        }
    ):
        _fail("COLLISION_TAG_CONTRACT_MISMATCH")
    expected_policies = {
        domain: _closed_policy(
            domain=domain,
            not_before=str(value["not_before"]),
            expires_at=str(value["expires_at"]),
            schema_version=schema_version,
        )
        for domain in ("authority", "identity_center")
    }
    expected_policy_digests = {
        domain: canonical_digest(policy)
        for domain, policy in expected_policies.items()
    }
    if (
        value.get("policies") != expected_policies
        or value.get("policy_digests") != expected_policy_digests
        or value["policy_set_digest"] != canonical_digest(expected_policy_digests)
    ):
        _fail("COLLISION_POLICY_BINDING_MISMATCH")
    budget = value.get("budget")
    expected_budget = {
        "max_pages": MAX_PAGES,
        "max_provider_calls": MAX_PROVIDER_CALLS,
        "max_session_bootstrap_attempts": MAX_SESSION_BOOTSTRAP_ATTEMPTS,
        "max_credential_vending_calls": MAX_CREDENTIAL_VENDING_CALLS,
        "max_network_calls": MAX_NETWORK_CALLS,
        "max_page_calls": MAX_PAGE_CALLS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_total_response_bytes": MAX_TOTAL_RESPONSE_BYTES,
        "max_owned_buckets": MAX_OWNED_BUCKETS,
        "max_kms_keys": MAX_KMS_KEYS,
        "max_signing_profiles": MAX_SIGNING_PROFILES,
        "max_code_signing_configs": MAX_CODE_SIGNING_CONFIGS,
        "max_applications": MAX_APPLICATIONS,
        "max_permission_sets": MAX_PERMISSION_SETS,
        "max_modeled_cost_nano_usd": MAX_MODELED_COST_NANO_USD,
        "per_network_call_cost_nano_usd": PER_NETWORK_CALL_COST_NANO_USD,
        "per_projected_byte_cost_nano_usd": PER_PROJECTED_BYTE_COST_NANO_USD,
    }
    _seal(expected_budget, "budget_digest")
    if budget != expected_budget or value["budget_digest"] != expected_budget[
        "budget_digest"
    ]:
        _fail("COLLISION_BUDGET_BINDING_MISMATCH")
    _verify_self_digest(
        value, "request_digest", "COLLISION_REQUEST_DIGEST_MISMATCH"
    )


def validate_collision_probe_request_v1(
    request: Mapping[str, Any],
) -> None:
    value = _copy(request, "COLLISION_REQUEST_INVALID")
    if not isinstance(value, Mapping) or _collision_probe_request_version(value) != 1:
        _fail("COLLISION_REQUEST_VERSION_UNSUPPORTED")
    _validate_collision_probe_request(value, schema_version=1)


def validate_collision_probe_request_v2(
    request: Mapping[str, Any],
) -> None:
    value = _copy(request, "COLLISION_REQUEST_INVALID")
    if not isinstance(value, Mapping) or _collision_probe_request_version(value) != 2:
        _fail("COLLISION_REQUEST_VERSION_UNSUPPORTED")
    _validate_collision_probe_request(value, schema_version=2)


def validate_collision_probe_request(request: Mapping[str, Any]) -> None:
    """Dispatch a persisted request through its exact versioned reader."""

    value = _copy(request, "COLLISION_REQUEST_INVALID")
    if not isinstance(value, Mapping):
        _fail("COLLISION_REQUEST_INVALID")
    version = _collision_probe_request_version(value)
    _validate_collision_probe_request(value, schema_version=version)


def persist_collision_probe_request(
    *, private_root: Path, request: Mapping[str, Any], filename: str = DEFAULT_REQUEST_FILE
) -> str:
    if filename != DEFAULT_REQUEST_FILE:
        _fail("COLLISION_PRIVATE_ARTIFACT_NAME_INVALID")
    validate_collision_probe_request(request)
    try:
        private_target_absent(private_root, filename)
        write_private_json(private_root, filename, request)
        observed = read_private_json(private_root, filename)
    except CollectorError as exc:
        raise CollisionProbeError(exc.code) from exc
    if observed != _copy(request, "COLLISION_REQUEST_INVALID"):
        _fail("COLLISION_REQUEST_READBACK_MISMATCH")
    return str(request["request_digest"])


class CollisionProbeExecutionCapability:
    """Opaque one-shot capability bound to request, claim and source bytes."""

    __slots__ = (
        "_token", "_request", "_claim", "_private_root", "_source", "_clock",
        "_executing", "_consumed", "_lock",
    )

    def __init__(
        self,
        token: object,
        *,
        request: Mapping[str, Any],
        claim: Mapping[str, Any],
        private_root: Path,
        source: VerifiedCollisionProbeSource,
        clock: Callable[[], datetime],
    ) -> None:
        if token is not _EXECUTION_CAPABILITY_SENTINEL:
            _fail("COLLISION_EXECUTION_CAPABILITY_REQUIRED")
        self._token = token
        self._request = _copy(request, "COLLISION_REQUEST_INVALID")
        self._claim = _copy(claim, "COLLISION_CLAIM_INVALID")
        self._private_root = Path(private_root)
        self._source = source
        self._clock = clock
        self._executing = False
        self._consumed = False
        self._lock = threading.Lock()


def _validate_capability(value: object) -> CollisionProbeExecutionCapability:
    if (
        type(value) is not CollisionProbeExecutionCapability
        or value._token is not _EXECUTION_CAPABILITY_SENTINEL  # type: ignore[attr-defined]
    ):
        _fail("COLLISION_EXECUTION_CAPABILITY_REQUIRED")
    capability = value
    validate_collision_probe_request(capability._request)
    _validate_collision_probe_claim(capability._claim, capability._request)
    return capability


def _validate_collision_probe_claim(
    claim: Mapping[str, Any], request: Mapping[str, Any]
) -> dict[str, Any]:
    value = _copy(claim, "COLLISION_CLAIM_INVALID")
    if not isinstance(value, Mapping):
        _fail("COLLISION_CLAIM_INVALID")
    _require_exact_keys(
        value,
        {
            "record_type", "schema_version", "request_digest",
            "source_verification_digest", "claimed_at", "aws_calls",
            "aws_mutations", "deployment_authorized", "production_status",
            "claim_digest",
        },
        "COLLISION_CLAIM_INVALID",
    )
    _verify_self_digest(
        value, "claim_digest", "COLLISION_CLAIM_DIGEST_MISMATCH"
    )
    claimed_at = _parse_stamp(
        value.get("claimed_at"), "COLLISION_CLAIM_INVALID"
    )
    if (
        value.get("record_type") != CLAIM_TYPE
        or value.get("schema_version") != 1
        or value.get("request_digest") != request["request_digest"]
        or value.get("source_verification_digest")
        != request["source_verification_digest"]
        or value.get("aws_calls") != 0
        or value.get("aws_mutations") != 0
        or value.get("deployment_authorized") is not False
        or value.get("production_status") != PRODUCTION_STATUS
        or not _parse_stamp(
            request["not_before"], "COLLISION_CLAIM_INVALID"
        )
        <= claimed_at
        < _parse_stamp(request["expires_at"], "COLLISION_CLAIM_INVALID")
    ):
        _fail("COLLISION_CLAIM_INVALID")
    return dict(value)


def read_and_claim_collision_probe_request(
    *,
    private_root: Path,
    verified_source: VerifiedCollisionProbeSource,
    expected_request_digest: str,
    now: datetime,
    clock: Callable[[], datetime] | None = None,
    request_file: str = DEFAULT_REQUEST_FILE,
    claim_file: str = DEFAULT_CLAIM_FILE,
) -> CollisionProbeExecutionCapability:
    """Consume the create-only request boundary before any SDK construction."""

    if request_file != DEFAULT_REQUEST_FILE or claim_file != DEFAULT_CLAIM_FILE:
        _fail("COLLISION_PRIVATE_ARTIFACT_NAME_INVALID")
    _digest(expected_request_digest, "COLLISION_REQUEST_DIGEST_INVALID")
    checked_now = _parse_stamp(_stamp(now), "COLLISION_CLOCK_INVALID")
    if not isinstance(verified_source, VerifiedCollisionProbeSource):
        _fail("COLLISION_SOURCE_VERIFICATION_REQUIRED")
    verified_source.reverify()
    try:
        request = read_private_json(private_root, request_file)
        private_target_absent(private_root, claim_file)
        private_target_absent(private_root, DEFAULT_EVIDENCE_FILE)
        private_target_absent(private_root, DEFAULT_RECEIPT_FILE)
        private_target_absent(private_root, DEFAULT_RESULT_FILE)
    except CollectorError as exc:
        raise CollisionProbeError(exc.code) from exc
    validate_collision_probe_request(request)
    _assert_operational_host_binding(request)
    if private_root_digest(private_root) != request["private_custody_digest"]:
        _fail("COLLISION_PRIVATE_ROOT_BINDING_MISMATCH")
    source_record = verified_source.record
    if (
        request["request_digest"] != expected_request_digest
        or request["source_commit_sha"] != source_record["source_commit_sha"]
        or request["source_tree_sha"] != source_record["source_tree_sha"]
        or request["source_verification_digest"]
        != source_record["verification_digest"]
        or request["repository_tree_entries_digest"]
        != source_record["repository_tree_entries_digest"]
        or _parse_stamp(request["created_at"], "COLLISION_CREATED_AT_INVALID")
        > checked_now
        or not _parse_stamp(request["not_before"], "COLLISION_WINDOW_INVALID")
        <= checked_now
        < _parse_stamp(request["expires_at"], "COLLISION_WINDOW_INVALID")
    ):
        _fail("COLLISION_REQUEST_CAPABILITY_MISMATCH")
    claim = {
        "record_type": CLAIM_TYPE,
        "schema_version": 1,
        "request_digest": request["request_digest"],
        "source_verification_digest": request["source_verification_digest"],
        "claimed_at": _stamp(checked_now),
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    _seal(claim, "claim_digest")
    _validate_collision_probe_claim(claim, request)
    # All source and request checks occur before the create-only claim is
    # published.  A failed re-verification therefore cannot orphan a claim.
    verified_source.reverify()
    try:
        if (
            read_private_json(private_root, request_file) != request
            or private_root_digest(private_root)
            != request["private_custody_digest"]
        ):
            _fail("COLLISION_PRIVATE_CUSTODY_CHANGED")
        write_private_json(private_root, claim_file, claim)
        if read_private_json(private_root, claim_file) != claim:
            _fail("COLLISION_CLAIM_READBACK_MISMATCH")
    except CollectorError as exc:
        raise CollisionProbeError(exc.code) from exc
    return CollisionProbeExecutionCapability(
        _EXECUTION_CAPABILITY_SENTINEL,
        request=request,
        claim=claim,
        private_root=private_root,
        source=verified_source,
        clock=(lambda: datetime.now(UTC)) if clock is None else clock,
    )


def approved_collision_probe_request(
    capability: object,
) -> dict[str, Any]:
    checked = _validate_capability(capability)
    return _copy(checked._request, "COLLISION_REQUEST_INVALID")


def approved_collision_probe_claim_digest(capability: object) -> str:
    checked = _validate_capability(capability)
    return str(checked._claim["claim_digest"])


def assert_collision_probe_private_root_binding(
    capability: object, private_root: Path
) -> None:
    """Require the executor output root to be the claimed custody root."""

    checked = _validate_capability(capability)
    try:
        supplied = Path(private_root).resolve(strict=True)
        expected = checked._private_root.resolve(strict=True)
    except OSError as exc:
        raise CollisionProbeError("COLLISION_PRIVATE_ROOT_INVALID") from exc
    if (
        supplied != expected
        or private_root_digest(supplied)
        != checked._request["private_custody_digest"]
    ):
        _fail("COLLISION_PRIVATE_ROOT_BINDING_MISMATCH")


def claim_collision_probe_execution(capability: object) -> None:
    checked = _validate_capability(capability)
    with checked._lock:
        if checked._executing or checked._consumed:
            _fail("COLLISION_EXECUTION_CAPABILITY_CONSUMED")
        checked._executing = True
    # Transition first: if source custody changes at execution start, the
    # executor still owns an active capability with which to seal BLOCKED.
    checked._source.reverify()


def assert_collision_probe_execution_active(capability: object) -> None:
    checked = _validate_capability(capability)
    with checked._lock:
        if not checked._executing or checked._consumed:
            _fail("COLLISION_EXECUTION_CAPABILITY_STATE_INVALID")


def complete_collision_probe_execution(capability: object) -> None:
    checked = _validate_capability(capability)
    with checked._lock:
        if not checked._executing or checked._consumed:
            _fail("COLLISION_EXECUTION_CAPABILITY_STATE_INVALID")
        checked._consumed = True


class _CollisionCapabilityGate:
    __slots__ = ("_capability",)

    def __init__(self, capability: CollisionProbeExecutionCapability) -> None:
        self._capability = capability

    def __call__(self) -> None:
        capability = _validate_capability(self._capability)
        with capability._lock:
            if not capability._executing or capability._consumed:
                _fail("COLLISION_EXECUTION_CAPABILITY_STATE_INVALID")
        now = capability._clock()
        checked_now = _parse_stamp(_stamp(now), "COLLISION_CLOCK_INVALID")
        if not _parse_stamp(
            capability._request["not_before"], "COLLISION_WINDOW_INVALID"
        ) <= checked_now < _parse_stamp(
            capability._request["expires_at"], "COLLISION_WINDOW_INVALID"
        ):
            _fail("COLLISION_EXECUTION_WINDOW_INACTIVE")
        _assert_operational_host_binding(capability._request)
        try:
            request = read_private_json(capability._private_root, DEFAULT_REQUEST_FILE)
            claim = read_private_json(capability._private_root, DEFAULT_CLAIM_FILE)
        except CollectorError as exc:
            raise CollisionProbeError(exc.code) from exc
        if request != capability._request or claim != capability._claim:
            _fail("COLLISION_PRIVATE_CUSTODY_CHANGED")

    def authorize_session(
        self,
        *,
        domain: str,
        capture_index: int,
        stage: str,
        policy_digest: str,
    ) -> None:
        self()
        request = self._capability._request
        expected_stage = "collision_probe"
        if (
            domain not in {"authority", "identity_center"}
            or capture_index not in {1, 2}
            or stage != expected_stage
            or policy_digest != request["policy_digests"][domain]
        ):
            _fail("COLLISION_PROVIDER_SESSION_NOT_AUTHORIZED")


def assert_collision_probe_provider_capability_bindings(
    execution_capability: object,
    *,
    sdk_runtime_root: str,
    authority_profile: str,
    identity_center_profile: str,
    authority_expected_account_id: str,
    authority_expected_principal_digest: str,
    authority_expected_sso_role_name_digest: str,
    identity_expected_account_id: str,
    identity_expected_principal_digest: str,
    identity_expected_sso_role_name_digest: str,
    identity_expected_kms_mode: str,
    identity_expected_kms_key_arn: str | None,
    authority_verification_digest: str,
    identity_authority_verification_digest: str,
    budget_digest: str,
) -> _CollisionCapabilityGate:
    """Bind the concrete provider builder to one exact claimed request."""

    capability = _validate_capability(execution_capability)
    request = capability._request
    _assert_operational_host_binding(request)
    authority = request["profiles"]["authority"]
    identity = request["profiles"]["identity_center"]
    supplied = {
        "sdk_runtime_root": sdk_runtime_root,
        "authority_profile": authority_profile,
        "identity_center_profile": identity_center_profile,
        "authority_expected_account_id": authority_expected_account_id,
        "authority_expected_principal_digest": authority_expected_principal_digest,
        "authority_expected_sso_role_name_digest": (
            authority_expected_sso_role_name_digest
        ),
        "identity_expected_account_id": identity_expected_account_id,
        "identity_expected_principal_digest": identity_expected_principal_digest,
        "identity_expected_sso_role_name_digest": (
            identity_expected_sso_role_name_digest
        ),
        "identity_expected_kms_mode": identity_expected_kms_mode,
        "identity_expected_kms_key_arn": identity_expected_kms_key_arn,
        "authority_verification_digest": authority_verification_digest,
        "identity_authority_verification_digest": (
            identity_authority_verification_digest
        ),
        "budget_digest": budget_digest,
    }
    expected = {
        "sdk_runtime_root": request["sdk_runtime_root"],
        "authority_profile": authority["name"],
        "identity_center_profile": identity["name"],
        "authority_expected_account_id": authority["expected_account_id"],
        "authority_expected_principal_digest": authority[
            "expected_principal_digest"
        ],
        "authority_expected_sso_role_name_digest": authority[
            "expected_sso_role_name_digest"
        ],
        "identity_expected_account_id": identity["expected_account_id"],
        "identity_expected_principal_digest": identity[
            "expected_principal_digest"
        ],
        "identity_expected_sso_role_name_digest": identity[
            "expected_sso_role_name_digest"
        ],
        "identity_expected_kms_mode": identity[
            "identity_center_kms_mode"
        ],
        "identity_expected_kms_key_arn": identity[
            "identity_center_kms_key_arn"
        ],
        "authority_verification_digest": authority[
            "authority_verification_digest"
        ],
        "identity_authority_verification_digest": identity[
            "authority_verification_digest"
        ],
        "budget_digest": request["budget_digest"],
    }
    if supplied != expected:
        _fail("COLLISION_PROVIDER_CAPABILITY_BINDING_MISMATCH")
    return _CollisionCapabilityGate(capability)


class CollisionProbeBudget:
    """Atomic four-session budget shared by both collision domains."""

    def __init__(self, request: Mapping[str, Any]) -> None:
        validate_collision_probe_request(request)
        self._budget = _copy(request["budget"], "COLLISION_BUDGET_INVALID")
        self._provider_calls = 0
        self._session_bootstrap_attempts = 0
        self._credential_vending_calls = 0
        self._network_calls = 0
        self._page_calls = 0
        self._response_bytes = 0
        self._modeled_cost = 0
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _require_cost(self, value: int) -> None:
        if value > self._budget["max_modeled_cost_nano_usd"]:
            _fail("COLLISION_COST_BUDGET_EXCEEDED")

    def reserve_provider_call(self, operation: str, *, is_page: bool) -> None:
        if (
            not isinstance(operation, str)
            or operation not in AUTHORITY_ACTIONS | IDENTITY_ACTIONS
            or type(is_page) is not bool
        ):
            _fail("COLLISION_PROVIDER_OPERATION_INVALID")
        page_call = operation in PAGINATED_ACTIONS
        if is_page is not page_call:
            _fail("COLLISION_PROVIDER_PAGE_INVALID")
        with self._lock:
            provider_calls = self._provider_calls + 1
            network_calls = self._network_calls + 1
            page_calls = self._page_calls + int(page_call)
            cost = self._modeled_cost + self._budget[
                "per_network_call_cost_nano_usd"
            ]
            if provider_calls > self._budget["max_provider_calls"]:
                _fail("COLLISION_PROVIDER_CALL_BUDGET_EXCEEDED")
            if network_calls > self._budget["max_network_calls"]:
                _fail("COLLISION_NETWORK_CALL_BUDGET_EXCEEDED")
            if page_calls > self._budget["max_page_calls"]:
                _fail("COLLISION_PAGE_CALL_BUDGET_EXCEEDED")
            self._require_cost(cost)
            self._provider_calls = provider_calls
            self._network_calls = network_calls
            self._page_calls = page_calls
            self._modeled_cost = cost
            self._events.append(
                {
                    "ordinal": len(self._events) + 1,
                    "kind": "PROVIDER_CALL",
                    "operation": operation,
                    "page_call": page_call,
                }
            )

    def record_session_bootstrap(self, operation: str) -> None:
        """Count a direct-SSO session bootstrap, cached or network-backed."""

        if operation != "sso:GetRoleCredentials":
            _fail("COLLISION_SESSION_BOOTSTRAP_OPERATION_INVALID")
        with self._lock:
            attempts = self._session_bootstrap_attempts + 1
            if attempts > self._budget["max_session_bootstrap_attempts"]:
                _fail("COLLISION_SESSION_BOOTSTRAP_BUDGET_EXCEEDED")
            self._session_bootstrap_attempts = attempts
            self._events.append(
                {
                    "ordinal": len(self._events) + 1,
                    "kind": "SESSION_BOOTSTRAP",
                    "operation": operation,
                }
            )

    def record_credential_vend(self, operation: str) -> None:
        if operation != "sso:GetRoleCredentials":
            _fail("COLLISION_CREDENTIAL_VENDING_OPERATION_INVALID")
        with self._lock:
            vends = self._credential_vending_calls + 1
            network_calls = self._network_calls + 1
            cost = self._modeled_cost + self._budget[
                "per_network_call_cost_nano_usd"
            ]
            if vends > self._budget["max_credential_vending_calls"]:
                _fail("COLLISION_CREDENTIAL_VENDING_BUDGET_EXCEEDED")
            if network_calls > self._budget["max_network_calls"]:
                _fail("COLLISION_NETWORK_CALL_BUDGET_EXCEEDED")
            self._require_cost(cost)
            self._credential_vending_calls = vends
            self._network_calls = network_calls
            self._modeled_cost = cost
            self._events.append(
                {
                    "ordinal": len(self._events) + 1,
                    "kind": "CREDENTIAL_VEND",
                    "operation": operation,
                }
            )

    def record_response(self, byte_count: int) -> None:
        if type(byte_count) is not int or byte_count < 0:
            _fail("COLLISION_RESPONSE_BYTE_COUNT_INVALID")
        with self._lock:
            total = self._response_bytes + byte_count
            cost = self._modeled_cost + byte_count * self._budget[
                "per_projected_byte_cost_nano_usd"
            ]
            if byte_count > self._budget["max_response_bytes"]:
                _fail("COLLISION_RESPONSE_BYTE_BUDGET_EXCEEDED")
            if total > self._budget["max_total_response_bytes"]:
                _fail("COLLISION_TOTAL_RESPONSE_BYTE_BUDGET_EXCEEDED")
            self._require_cost(cost)
            self._response_bytes = total
            self._modeled_cost = cost
            self._events.append(
                {
                    "ordinal": len(self._events) + 1,
                    "kind": "PROJECTED_RESPONSE",
                    "byte_count": byte_count,
                }
            )

    def summary(self) -> dict[str, Any]:
        with self._lock:
            body = {
                "record_type": (
                    "scanalyze.platform_authority."
                    "gug395_preplan_collision_budget_summary.v1"
                ),
                "budget_digest": self._budget["budget_digest"],
                "provider_calls": self._provider_calls,
                "session_bootstrap_attempts": self._session_bootstrap_attempts,
                "credential_vending_calls": self._credential_vending_calls,
                "network_calls": self._network_calls,
                "page_calls": self._page_calls,
                "projected_response_bytes": self._response_bytes,
                "modeled_cost_nano_usd": self._modeled_cost,
            }
            return {**body, "summary_digest": canonical_digest(body)}

    def evidence_events(self) -> list[dict[str, Any]]:
        with self._lock:
            provider = sum(
                event["kind"] == "PROVIDER_CALL" for event in self._events
            )
            responses = sum(
                event["kind"] == "PROJECTED_RESPONSE" for event in self._events
            )
            vends = sum(
                event["kind"] == "CREDENTIAL_VEND" for event in self._events
            )
            bootstraps = sum(
                event["kind"] == "SESSION_BOOTSTRAP" for event in self._events
            )
            if (
                provider != self._provider_calls
                or responses != provider
                or bootstraps != self._session_bootstrap_attempts
                or vends != self._credential_vending_calls
            ):
                _fail("COLLISION_BUDGET_EVIDENCE_INCOMPLETE")
            return _copy(self._events, "COLLISION_BUDGET_EVIDENCE_INVALID")

    def partial_evidence_events(self) -> list[dict[str, Any]]:
        """Return the truthful journal accumulated before a blocked result."""

        with self._lock:
            return _copy(self._events, "COLLISION_BUDGET_EVIDENCE_INVALID")


class CollisionCallLedger:
    """Exact-action, STS-first, pagination-complete digest-only call ledger."""

    def __init__(self) -> None:
        self.mode = "ATTESTED_LIVE"
        self._ordinal = 0
        self._pending: dict[str, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._sessions: dict[str, str] = {}
        self._sts_complete: set[str] = set()
        self._streams: dict[str, dict[str, Any]] = {}
        self._failure: str | None = None
        self._last_completed_at: datetime | None = None

    def _reject(self, code: str) -> None:
        self._failure = code
        _fail(code)

    def authorize(
        self,
        *,
        domain: str,
        session_digest: str,
        operation: str,
        retries: int,
        request: Any = None,
        page_token: Any = None,
        pagination_key: str | None = None,
        started_at: str | None = None,
    ) -> str:
        if (
            domain not in COLLISION_OPERATION_ALLOWLIST
            or _DIGEST.fullmatch(str(session_digest)) is None
            or operation not in COLLISION_OPERATION_ALLOWLIST[domain]
            or retries != 0
        ):
            self._reject("COLLISION_PROVIDER_CALL_NOT_ALLOWED")
        owner = self._sessions.get(session_digest)
        if operation == "sts:GetCallerIdentity":
            if owner is not None or page_token is not None or pagination_key is not None:
                self._reject("COLLISION_STS_FIRST_REQUIRED")
            self._sessions[session_digest] = domain
        elif owner != domain or session_digest not in self._sts_complete:
            self._reject("COLLISION_STS_FIRST_REQUIRED")
        start = _parse_stamp(started_at, "COLLISION_PROVIDER_CALL_TIME_INVALID")
        if self._last_completed_at is not None and start < self._last_completed_at:
            self._reject("COLLISION_PROVIDER_CALL_TIME_INVALID")
        request_digest = (
            request
            if _DIGEST.fullmatch(str(request)) is not None
            else canonical_digest({} if request is None else request)
        )
        token_digest = canonical_digest(page_token) if page_token is not None else None
        stream_key: str | None = None
        if operation in PAGINATED_ACTIONS:
            stream_key = pagination_key or canonical_digest(
                {
                    "domain": domain,
                    "session": session_digest,
                    "operation": operation,
                    "ordinal": self._ordinal + 1,
                }
            )
            stream = self._streams.setdefault(
                stream_key,
                {
                    "domain": domain,
                    "session": session_digest,
                    "operation": operation,
                    "expected": None,
                    "seen": set(),
                    "pages": 0,
                    "closed": False,
                },
            )
            if (
                stream["closed"]
                or stream["expected"] != token_digest
                or stream["pages"] >= MAX_PAGES
            ):
                self._reject("COLLISION_PROVIDER_PAGE_SEQUENCE_INVALID")
            stream["pages"] += 1
        elif page_token is not None or pagination_key is not None:
            self._reject("COLLISION_PROVIDER_PAGE_INVALID")
        self._ordinal += 1
        ticket = canonical_digest(
            {
                "ordinal": self._ordinal,
                "domain": domain,
                "session": session_digest,
                "operation": operation,
                "request": request_digest,
            }
        )
        self._pending[ticket] = {
            "ordinal": self._ordinal,
            "domain": domain,
            "session_digest": session_digest,
            "operation": operation,
            "request_digest": request_digest,
            "page_token_digest": token_digest,
            "pagination_stream_digest": stream_key,
            "started_at": _stamp(start),
        }
        return ticket

    def complete(
        self,
        ticket: str,
        response: Any = None,
        *,
        complete: bool = True,
        truncated: bool = False,
        next_token: Any = None,
        outcome: str = "SUCCESS",
        completed_at: str | None = None,
    ) -> None:
        # Keep the authorized call pending until every response-side invariant
        # has been checked.  A malformed page, repeated token, regressing clock
        # or invalid response digest must still be representable as one durable
        # INCOMPLETE event by ``partial_evidence_events``.
        call = self._pending.get(ticket)
        if call is None:
            self._reject("COLLISION_PROVIDER_CALL_TICKET_INVALID")
        assert call is not None
        if outcome not in {"SUCCESS", "ERROR"}:
            self._reject("COLLISION_PROVIDER_CALL_RESULT_INVALID")
        if outcome == "SUCCESS" and (
            truncated != (next_token is not None)
            or complete != (next_token is None)
        ):
            self._reject("COLLISION_PROVIDER_PAGE_INCOMPLETE")
        completed = _parse_stamp(
            completed_at, "COLLISION_PROVIDER_CALL_TIME_INVALID"
        )
        started = _parse_stamp(
            call["started_at"], "COLLISION_PROVIDER_CALL_TIME_INVALID"
        )
        if completed < started:
            self._reject("COLLISION_PROVIDER_CALL_TIME_INVALID")
        next_digest = canonical_digest(next_token) if next_token is not None else None
        stream_key = call["pagination_stream_digest"]
        if stream_key is not None and outcome == "SUCCESS":
            stream = self._streams[stream_key]
            if next_digest is not None:
                if next_digest in stream["seen"] or next_digest == call[
                    "page_token_digest"
                ]:
                    self._reject("COLLISION_PROVIDER_PAGE_TOKEN_REPEATED")
        response_digest = (
            response
            if _DIGEST.fullmatch(str(response)) is not None
            else canonical_digest({} if response is None else response)
        )
        # No validation below this point may fail: commit the completed call and
        # its derived stream/session state together.
        self._pending.pop(ticket)
        self._last_completed_at = completed
        if stream_key is not None and outcome == "SUCCESS":
            stream = self._streams[stream_key]
            if next_digest is not None:
                stream["seen"].add(next_digest)
                stream["expected"] = next_digest
            else:
                stream["expected"] = None
                stream["closed"] = True
        if call["operation"] == "sts:GetCallerIdentity" and outcome == "SUCCESS":
            self._sts_complete.add(call["session_digest"])
        if outcome == "ERROR":
            self._failure = "COLLISION_UNCERTAIN_RECONCILE_ONLY"
        self._events.append(
            {
                **call,
                "completed_at": _stamp(completed),
                "response_digest": response_digest,
                "outcome": outcome,
                "complete": complete,
                "truncated": truncated,
                "next_token_digest": next_digest,
            }
        )

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            _fail(self._failure)

    def finalize(self) -> tuple[int, str]:
        self.raise_if_failed()
        if (
            self._pending
            or not self._events
            or set(self._sessions) != self._sts_complete
            or any(not stream["closed"] for stream in self._streams.values())
        ):
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INCOMPLETE")
        return self._ordinal, canonical_digest(self._events)

    def evidence_events(self) -> list[dict[str, Any]]:
        self.finalize()
        return _copy(self._events, "COLLISION_PROVIDER_TRANSCRIPT_INVALID")

    def partial_evidence_events(self) -> list[dict[str, Any]]:
        """Return complete calls plus digest-only pending calls after failure."""

        pending = [
            {
                **call,
                "pending_ticket_digest": ticket,
                "completed_at": None,
                "response_digest": canonical_digest(
                    {"outcome": "INCOMPLETE", "ticket_digest": ticket}
                ),
                "outcome": "INCOMPLETE",
                "complete": False,
                "truncated": False,
                "next_token_digest": None,
            }
            for ticket, call in sorted(
                self._pending.items(), key=lambda item: item[1]["ordinal"]
            )
        ]
        events = sorted(
            [*self._events, *pending], key=lambda item: item["ordinal"]
        )
        if len(events) != self._ordinal:
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INCOMPLETE")
        return _copy(events, "COLLISION_PROVIDER_TRANSCRIPT_INVALID")

    def partial_summary(self) -> tuple[int, str]:
        events = self.partial_evidence_events()
        return len(events), canonical_digest(events)


def _snapshot_facts(snapshot: Mapping[str, Any], domain: str) -> dict[str, Any]:
    if not isinstance(snapshot, Mapping):
        _fail("COLLISION_SNAPSHOT_INVALID")
    required = {
        "domain", "capture_index", "identity", "complete", "prerequisites_ready",
        "collisions", "collision_count", "resource_counts", "facts",
        "facts_digest", "transcript_segment_digest", "snapshot_digest",
    }
    _require_exact_keys(snapshot, required, "COLLISION_SNAPSHOT_INVALID")
    if (
        snapshot.get("domain") != domain
        or snapshot.get("capture_index") not in {1, 2}
        or type(snapshot.get("complete")) is not bool
        or type(snapshot.get("prerequisites_ready")) is not bool
        or not isinstance(snapshot.get("collisions"), list)
        or snapshot.get("collision_count") != len(snapshot["collisions"])
        or not isinstance(snapshot.get("resource_counts"), Mapping)
        or not isinstance(snapshot.get("facts"), Mapping)
        or _DIGEST.fullmatch(
            str(snapshot.get("transcript_segment_digest"))
        ) is None
    ):
        _fail("COLLISION_SNAPSHOT_INVALID")
    allowed_collisions = set(
        TARGET_ORDER[:4] if domain == "authority" else TARGET_ORDER[4:]
    )
    collisions = snapshot["collisions"]
    resource_counts = snapshot["resource_counts"]
    if (
        collisions != sorted(set(collisions))
        or any(
            not isinstance(item, str) or item not in allowed_collisions
            for item in collisions
        )
        or any(
            not isinstance(key, str)
            or not key
            or type(item) is not int
            or item < 0
            for key, item in resource_counts.items()
        )
    ):
        _fail("COLLISION_SNAPSHOT_INVALID")
    facts = snapshot["facts"]
    if domain == "authority":
        if set(facts) != set(TARGET_ORDER[:4]) or any(
            not isinstance(facts.get(name), Mapping)
            or type(facts[name].get("collision")) is not bool
            for name in TARGET_ORDER[:4]
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        expected_collisions = sorted(
            name for name in TARGET_ORDER[:4] if facts[name]["collision"]
        )
        try:
            expected_counts = {
                "owned_buckets_examined": facts["artifact_bucket"][
                    "owned_bucket_count"
                ],
                "kms_keys_examined": facts["kms_key"]["keys_examined"],
                "signing_profiles_examined": facts["signing_profile"][
                    "signing_profiles_examined"
                ],
                "code_signing_configs_examined": facts[
                    "code_signing_config"
                ]["code_signing_configs_examined"],
            }
        except (KeyError, TypeError) as exc:
            raise CollisionProbeError(
                "COLLISION_SNAPSHOT_SEMANTICS_INVALID"
            ) from exc
        expected_complete = True
        expected_prerequisites = True
    else:
        flags = {
            "identity_center_application": "application_collision",
            "classifier_permission_set": (
                "classifier_permission_set_collision"
            ),
            "approver_permission_set": "approver_permission_set_collision",
        }
        if any(type(facts.get(field)) is not bool for field in flags.values()):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        expected_collisions = sorted(
            name for name, field in flags.items() if facts[field]
        )
        try:
            expected_counts = {
                "applications_examined": facts["applications_examined"],
                "permission_sets_examined": facts[
                    "permission_sets_examined"
                ],
            }
        except (KeyError, TypeError) as exc:
            raise CollisionProbeError(
                "COLLISION_SNAPSHOT_SEMANTICS_INVALID"
            ) from exc
        instances = facts.get("instances")
        instance_matches = facts.get("instance_matches")
        described_instance = _identity_described_instance(facts)
        matched = (
            instance_matches[0]
            if isinstance(instance_matches, list) and len(instance_matches) == 1
            else None
        )
        expected_complete = facts.get("complete") is True
        expected_prerequisites = (
            isinstance(instances, list)
            and len(instances) == 1
            and isinstance(matched, Mapping)
            and {
                key: described_instance[key]
                for key in (
                    "InstanceArn",
                    "IdentityStoreId",
                    "OwnerAccountId",
                    "Status",
                )
            }
            == matched
        )
    if (
        any(
            type(value) is not int or value < 0
            for value in expected_counts.values()
        )
        or collisions != expected_collisions
        or snapshot["collision_count"] != len(expected_collisions)
        or resource_counts != expected_counts
        or snapshot["complete"] is not expected_complete
        or snapshot["prerequisites_ready"] is not expected_prerequisites
    ):
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    semantic_facts = {
        "complete": snapshot["complete"],
        "prerequisites_ready": snapshot["prerequisites_ready"],
        "collisions": snapshot["collisions"],
        "collision_count": snapshot["collision_count"],
        "resource_counts": snapshot["resource_counts"],
        "facts": snapshot["facts"],
    }
    if snapshot.get("facts_digest") != canonical_digest(semantic_facts):
        _fail("COLLISION_SNAPSHOT_INVALID")
    identity = snapshot.get("identity")
    identity_fields = {
        "source", "chain_depth", "account_id", "region", "principal_arn",
        "session_id_digest", "started_at", "expires_at", "observed_at",
        "policy_digest", "authority_verification_digest",
    }
    if not isinstance(identity, Mapping) or set(identity) != identity_fields:
        _fail("COLLISION_SNAPSHOT_INVALID")
    principal = identity.get("principal_arn")
    principal_match = _PRINCIPAL.fullmatch(str(principal))
    if (
        identity.get("source") != "DIRECT_SSO"
        or type(identity.get("chain_depth")) is not int
        or identity.get("chain_depth") != 0
        or _ACCOUNT.fullmatch(str(identity.get("account_id"))) is None
        or identity.get("region") != REGION
        or principal_match is None
        or principal_match.group(1) != identity.get("account_id")
    ):
        _fail("COLLISION_SNAPSHOT_INVALID")
    for field in (
        "session_id_digest", "policy_digest", "authority_verification_digest"
    ):
        _digest(identity.get(field), "COLLISION_SNAPSHOT_INVALID")
    started = _parse_stamp(identity.get("started_at"), "COLLISION_SNAPSHOT_INVALID")
    expires = _parse_stamp(identity.get("expires_at"), "COLLISION_SNAPSHOT_INVALID")
    observed = _parse_stamp(identity.get("observed_at"), "COLLISION_SNAPSHOT_INVALID")
    if (
        not started <= observed < expires
        or expires - started > timedelta(hours=1)
    ):
        _fail("COLLISION_SNAPSHOT_INVALID")
    _verify_self_digest(
        snapshot, "snapshot_digest", "COLLISION_SNAPSHOT_DIGEST_MISMATCH"
    )
    return dict(snapshot)


def _same_json_items(left: Sequence[Any], right: Sequence[Any]) -> bool:
    return sorted(canonical_json(item) for item in left) == sorted(
        canonical_json(item) for item in right
    )


def _snapshot_list(
    value: Mapping[str, Any], field: str
) -> list[Any]:
    result = value.get(field)
    if not isinstance(result, list):
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    return result


def _identity_described_instance(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the normalized, private Identity Center instance projection."""

    value = facts.get("described_instance")
    fields = {
        "InstanceArn",
        "IdentityStoreId",
        "OwnerAccountId",
        "Status",
        "EncryptionConfigurationDetails",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    encryption = value.get("EncryptionConfigurationDetails")
    if not isinstance(encryption, Mapping) or set(encryption) != {
        "KeyType",
        "KmsKeyArn",
        "EncryptionStatus",
    }:
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    owner = value.get("OwnerAccountId")
    mode = encryption.get("KeyType")
    key_arn = encryption.get("KmsKeyArn")
    key_match = (
        _KMS_KEY_ARN.fullmatch(key_arn)
        if isinstance(key_arn, str)
        else None
    )
    if (
        _INSTANCE_ARN.fullmatch(str(value.get("InstanceArn"))) is None
        or _IDENTITY_STORE.fullmatch(str(value.get("IdentityStoreId"))) is None
        or _ACCOUNT.fullmatch(str(owner)) is None
        or value.get("Status") != "ACTIVE"
        or encryption.get("EncryptionStatus") != "ENABLED"
        or mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
        or (mode == "AWS_OWNED_KMS_KEY" and key_arn is not None)
        or (
            mode == "CUSTOMER_MANAGED_KEY"
            and (
                key_match is None
                or key_match.group(1) != owner
            )
        )
    ):
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    return dict(value)


def _tagged_records(records: Sequence[Any]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping) or type(
            record.get("tag_contract_matches")
        ) is not bool:
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        if record["tag_contract_matches"]:
            result.append(record)
    return result


def _validate_snapshot_target_bindings(
    request: Mapping[str, Any], snapshot: Mapping[str, Any], domain: str
) -> None:
    """Re-derive selector, match, collision and cap semantics from private facts."""

    facts = snapshot["facts"]
    targets = request["targets"]
    budget = request["budget"]
    if domain == "authority":
        artifact = facts.get("artifact_bucket")
        kms = facts.get("kms_key")
        signer = facts.get("signing_profile")
        signing_config = facts.get("code_signing_config")
        if any(
            not isinstance(item, Mapping)
            for item in (artifact, kms, signer, signing_config)
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        assert isinstance(artifact, Mapping)
        assert isinstance(kms, Mapping)
        assert isinstance(signer, Mapping)
        assert isinstance(signing_config, Mapping)

        discovered_buckets = _snapshot_list(artifact, "discovered_buckets")
        owned_matches = _snapshot_list(artifact, "owned_matches")
        bucket_details = _snapshot_list(artifact, "bucket_details")
        bucket_tag_matches = _snapshot_list(artifact, "tag_matches")
        bucket_count = artifact.get("owned_bucket_count")
        target_bucket = targets["artifact_bucket"]
        derived_owned_matches = [
            item
            for item in discovered_buckets
            if isinstance(item, Mapping)
            and item.get("Name") == target_bucket["name"]
        ]
        if (
            artifact.get("target_name") != target_bucket["name"]
            or artifact.get("bucket_namespace")
            != target_bucket["bucket_namespace"]
            or artifact.get("bucket_region") != REGION
            or type(bucket_count) is not int
            or bucket_count != len(discovered_buckets)
            or bucket_count > budget["max_owned_buckets"]
            or any(
                not isinstance(item, Mapping)
                or not isinstance(item.get("Name"), str)
                or not str(item["Name"]).startswith(target_bucket["name"])
                or item.get("BucketRegion") != REGION
                for item in discovered_buckets
            )
            or not _same_json_items(owned_matches, derived_owned_matches)
            or len(derived_owned_matches) > 1
            or len(bucket_details) != len(derived_owned_matches)
            or any(
                not isinstance(item, Mapping)
                or item.get("name") != target_bucket["name"]
                or item.get("bucket_region") != REGION
                for item in bucket_details
            )
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        derived_bucket_tags = _tagged_records(bucket_details)
        if (
            not _same_json_items(bucket_tag_matches, derived_bucket_tags)
            or artifact.get("absent") is not (not derived_owned_matches)
            or artifact.get("collision")
            is not bool(derived_owned_matches)
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")

        keys = _snapshot_list(kms, "discovered_keys")
        aliases = _snapshot_list(kms, "discovered_aliases")
        alias_matches = _snapshot_list(kms, "alias_matches")
        key_details = _snapshot_list(kms, "key_details")
        key_tag_matches = _snapshot_list(kms, "tag_matches")
        derived_alias_matches = [
            item
            for item in aliases
            if isinstance(item, Mapping)
            and item.get("AliasName") == targets["kms_key"]["alias_name"]
        ]
        derived_key_tags = _tagged_records(key_details)
        if (
            kms.get("target_alias_name") != targets["kms_key"]["alias_name"]
            or type(kms.get("keys_examined")) is not int
            or kms["keys_examined"] != len(keys)
            or len(key_details) != len(keys)
            or kms["keys_examined"] > budget["max_kms_keys"]
            or not _same_json_items(alias_matches, derived_alias_matches)
            or not _same_json_items(key_tag_matches, derived_key_tags)
            or kms.get("collision")
            is not (bool(derived_alias_matches) or bool(derived_key_tags))
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")

        profiles = _snapshot_list(signer, "discovered_profiles")
        profile_matches = _snapshot_list(signer, "name_matches")
        profile_details = _snapshot_list(signer, "details")
        profile_tag_matches = _snapshot_list(signer, "tag_matches")
        derived_profile_matches = [
            item
            for item in profiles
            if isinstance(item, Mapping)
            and item.get("profileName") == targets["signing_profile"]["name"]
        ]
        derived_profile_tags = _tagged_records(profile_details)
        if (
            signer.get("target_profile_name")
            != targets["signing_profile"]["name"]
            or type(signer.get("signing_profiles_examined")) is not int
            or signer["signing_profiles_examined"] != len(profiles)
            or len(profile_details) != len(profiles)
            or signer["signing_profiles_examined"]
            > budget["max_signing_profiles"]
            or not _same_json_items(profile_matches, derived_profile_matches)
            or not _same_json_items(profile_tag_matches, derived_profile_tags)
            or signer.get("collision")
            is not (bool(derived_profile_matches) or bool(derived_profile_tags))
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")

        configurations = _snapshot_list(
            signing_config, "discovered_configurations"
        )
        configuration_details = _snapshot_list(signing_config, "details")
        configuration_matches = _snapshot_list(signing_config, "matches")
        derived_configuration_matches = _tagged_records(configuration_details)
        if (
            signing_config.get("tag_contract_digest")
            != targets["code_signing_config"][
                "expected_tag_contract_digest"
            ]
            or type(signing_config.get("code_signing_configs_examined"))
            is not int
            or signing_config["code_signing_configs_examined"]
            != len(configurations)
            or len(configuration_details) != len(configurations)
            or signing_config["code_signing_configs_examined"]
            > budget["max_code_signing_configs"]
            or not _same_json_items(
                configuration_matches, derived_configuration_matches
            )
            or signing_config.get("collision")
            is not bool(derived_configuration_matches)
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        return

    application_target = targets["identity_center_application"]
    classifier_target = targets["classifier_permission_set"]
    approver_target = targets["approver_permission_set"]
    expected_permission_names = sorted(
        [classifier_target["name"], approver_target["name"]]
    )
    identity_profile = request["profiles"]["identity_center"]
    instances = _snapshot_list(facts, "instances")
    instance_matches = _snapshot_list(facts, "instance_matches")
    described_instance = _identity_described_instance(facts)
    applications = _snapshot_list(facts, "applications")
    described_applications = _snapshot_list(facts, "described_applications")
    application_matches = _snapshot_list(facts, "application_matches")
    permission_set_arns = _snapshot_list(facts, "permission_set_arns")
    described_permission_sets = _snapshot_list(
        facts, "described_permission_sets"
    )
    permission_set_matches = _snapshot_list(facts, "permission_set_matches")
    derived_instance_matches = [
        item
        for item in instances
        if isinstance(item, Mapping)
        and item.get("InstanceArn") == application_target["instance_arn"]
    ]
    expected_instance_summary = {
        key: described_instance[key]
        for key in (
            "InstanceArn",
            "IdentityStoreId",
            "OwnerAccountId",
            "Status",
        )
    }
    expected_encryption = {
        "KeyType": identity_profile["identity_center_kms_mode"],
        "KmsKeyArn": identity_profile["identity_center_kms_key_arn"],
        "EncryptionStatus": "ENABLED",
    }
    if (
        len(instances) != 1
        or len(derived_instance_matches) != 1
        or not _same_json_items(instance_matches, derived_instance_matches)
        or derived_instance_matches[0] != expected_instance_summary
        or described_instance["InstanceArn"]
        != application_target["instance_arn"]
        or described_instance["OwnerAccountId"]
        != identity_profile["expected_account_id"]
        or described_instance["EncryptionConfigurationDetails"]
        != expected_encryption
    ):
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
    derived_application_matches: list[Mapping[str, Any]] = []
    for item in described_applications:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("summary"), Mapping)
            or type(item.get("name_matches")) is not bool
            or type(item.get("tag_contract_matches")) is not bool
            or item["name_matches"]
            is not (
                item["summary"].get("Name") == application_target["name"]
            )
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        if item["name_matches"] or item["tag_contract_matches"]:
            derived_application_matches.append(item)
    derived_permission_matches: list[Mapping[str, Any]] = []
    for item in described_permission_sets:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("name"), str)
            or type(item.get("tag_contract_matches")) is not bool
        ):
            _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")
        if item["name"] in expected_permission_names or item[
            "tag_contract_matches"
        ]:
            derived_permission_matches.append(item)
    classifier_collision = any(
        item.get("name") == classifier_target["name"]
        or item.get("tag_contract_matches") is True
        for item in derived_permission_matches
    )
    approver_collision = any(
        item.get("name") == approver_target["name"]
        or item.get("tag_contract_matches") is True
        for item in derived_permission_matches
    )
    applications_examined = facts.get("applications_examined")
    permission_sets_examined = facts.get("permission_sets_examined")
    if (
        facts.get("target_instance_arn") != application_target["instance_arn"]
        or classifier_target["instance_arn"] != application_target["instance_arn"]
        or approver_target["instance_arn"] != application_target["instance_arn"]
        or facts.get("target_application_name") != application_target["name"]
        or facts.get("target_permission_set_names") != expected_permission_names
        or type(applications_examined) is not int
        or applications_examined != len(applications)
        or len(described_applications) != len(applications)
        or applications_examined > budget["max_applications"]
        or not _same_json_items(
            application_matches, derived_application_matches
        )
        or type(permission_sets_examined) is not int
        or permission_sets_examined != len(permission_set_arns)
        or len(described_permission_sets) != len(permission_set_arns)
        or permission_sets_examined > budget["max_permission_sets"]
        or not _same_json_items(
            permission_set_matches, derived_permission_matches
        )
        or facts.get("application_collision")
        is not bool(derived_application_matches)
        or facts.get("classifier_permission_set_collision")
        is not classifier_collision
        or facts.get("approver_permission_set_collision")
        is not approver_collision
    ):
        _fail("COLLISION_SNAPSHOT_SEMANTICS_INVALID")


def _validate_snapshot_request_bindings(
    request: Mapping[str, Any],
    *,
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    sealed_at: str,
    complete: bool,
) -> None:
    request_start = _parse_stamp(
        request.get("not_before"), "COLLISION_SNAPSHOT_BINDING_INVALID"
    )
    request_end = _parse_stamp(
        request.get("expires_at"), "COLLISION_SNAPSHOT_BINDING_INVALID"
    )
    sealed = _parse_stamp(sealed_at, "COLLISION_SEALED_AT_INVALID")
    if not request_start <= sealed < request_end:
        _fail("COLLISION_SNAPSHOT_BINDING_INVALID")
    domains = {
        "authority": authority_snapshots,
        "identity_center": identity_center_snapshots,
    }
    all_sessions: list[str] = []
    for domain, snapshots in domains.items():
        profile = request["profiles"][domain]
        previous_observed: datetime | None = None
        for snapshot in snapshots:
            checked = _snapshot_facts(snapshot, domain)
            _validate_snapshot_target_bindings(request, checked, domain)
            identity = checked["identity"]
            started = _parse_stamp(
                identity["started_at"], "COLLISION_SNAPSHOT_BINDING_INVALID"
            )
            observed = _parse_stamp(
                identity["observed_at"], "COLLISION_SNAPSHOT_BINDING_INVALID"
            )
            expires = _parse_stamp(
                identity["expires_at"], "COLLISION_SNAPSHOT_BINDING_INVALID"
            )
            if (
                identity["account_id"] != profile["expected_account_id"]
                or canonical_digest(identity["principal_arn"])
                != profile["expected_principal_digest"]
                or identity["policy_digest"] != request["policy_digests"][domain]
                or identity["authority_verification_digest"]
                != profile["authority_verification_digest"]
                or not request_start <= started <= observed <= sealed
                or expires < request_end
                or (
                    previous_observed is not None
                    and observed < previous_observed
                )
            ):
                _fail("COLLISION_SNAPSHOT_BINDING_INVALID")
            previous_observed = observed
            all_sessions.append(identity["session_id_digest"])
    if len(all_sessions) != len(set(all_sessions)):
        _fail("COLLISION_SNAPSHOT_BINDING_INVALID")


def _classify_collision_domain_snapshots(
    domain: str,
    snapshots: Sequence[Mapping[str, Any]],
    *,
    require_pair: bool,
) -> dict[str, Any]:
    if domain not in {"authority", "identity_center"}:
        _fail("COLLISION_SNAPSHOT_INVALID")
    if len(snapshots) > 2 or (require_pair and len(snapshots) != 2):
        _fail("COLLISION_SNAPSHOT_PAIR_REQUIRED")
    pair = [_snapshot_facts(item, domain) for item in snapshots]
    capture_indexes = [item["capture_index"] for item in pair]
    if capture_indexes != list(range(1, len(pair) + 1)):
        _fail("COLLISION_SNAPSHOT_PAIR_INVALID")
    sessions = [item["identity"]["session_id_digest"] for item in pair]
    snapshot_digests = [item["snapshot_digest"] for item in pair]
    if len(set(sessions)) != len(sessions) or len(set(snapshot_digests)) != len(
        snapshot_digests
    ):
        _fail("COLLISION_SNAPSHOT_PAIR_INVALID")
    stable = (
        len(pair) == 2
        and pair[0]["facts_digest"] == pair[1]["facts_digest"]
        and all(item["complete"] for item in pair)
        and all(item["prerequisites_ready"] for item in pair)
    )
    if not stable:
        classification = UNCERTAIN
    elif pair[0]["collision_count"] > 0:
        classification = COLLISION_BLOCKED
    else:
        classification = ABSENT_READY
    facts_digest = (
        pair[0]["facts_digest"]
        if stable
        else canonical_digest(
            {
                "domain": domain,
                "partial_facts_digests": sorted(
                    item["facts_digest"] for item in pair
                ),
            }
        )
    )
    return {
        "classification": classification,
        "stable": stable,
        "collision_count": pair[0]["collision_count"] if stable else 0,
        "facts_digest": facts_digest,
        "snapshot_digests": snapshot_digests,
        "session_digests": sessions,
        "resource_counts": pair[0]["resource_counts"] if stable else {},
    }


def classify_collision_probe_snapshots(
    *,
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Apply the closed ``uncertain > collision > absent`` lattice."""

    result: dict[str, Any] = {
        "authority": _classify_collision_domain_snapshots(
            "authority", authority_snapshots, require_pair=True
        ),
        "identity_center": _classify_collision_domain_snapshots(
            "identity_center", identity_center_snapshots, require_pair=True
        ),
    }
    domain_classes = {
        result["authority"]["classification"],
        result["identity_center"]["classification"],
    }
    if UNCERTAIN in domain_classes:
        classification = UNCERTAIN
    elif COLLISION_BLOCKED in domain_classes:
        classification = COLLISION_BLOCKED
    else:
        classification = ABSENT_READY
    collision_count = sum(
        result[domain]["collision_count"]
        for domain in ("authority", "identity_center")
    )
    result["classification"] = classification
    result["collision_count"] = collision_count
    result["evidence_stable"] = classification != UNCERTAIN
    result["evidence_complete"] = classification != UNCERTAIN
    result["reconciliation_only"] = classification == UNCERTAIN
    return result


def classify_partial_collision_probe_snapshots(
    *,
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Classify durable post-claim partial evidence without overclaiming it."""

    result: dict[str, Any] = {
        "authority": _classify_collision_domain_snapshots(
            "authority", authority_snapshots, require_pair=False
        ),
        "identity_center": _classify_collision_domain_snapshots(
            "identity_center", identity_center_snapshots, require_pair=False
        ),
    }
    result["classification"] = UNCERTAIN
    result["collision_count"] = sum(
        result[domain]["collision_count"]
        for domain in ("authority", "identity_center")
    )
    result["evidence_stable"] = False
    result["evidence_complete"] = False
    result["reconciliation_only"] = True
    return result


@dataclass(frozen=True)
class CollisionProbeResult:
    private_evidence: dict[str, Any]
    public_receipt: dict[str, Any]


def _modeled_cost(value: int) -> str:
    if type(value) is not int or value < 0:
        _fail("COLLISION_MODELED_COST_INVALID")
    whole, fractional = divmod(value, 1_000_000_000)
    return f"{whole}.{fractional:09d}"


def _validate_provider_evidence(
    request: Mapping[str, Any],
    provider_summary: Mapping[str, Any],
    transcript_events: Sequence[Mapping[str, Any]],
    *,
    sealed_at: str,
    complete: bool,
) -> dict[str, Any]:
    window_start = _parse_stamp(
        request.get("not_before"), "COLLISION_PROVIDER_TRANSCRIPT_INVALID"
    )
    window_end = _parse_stamp(
        request.get("expires_at"), "COLLISION_PROVIDER_TRANSCRIPT_INVALID"
    )
    sealed = _parse_stamp(
        sealed_at, "COLLISION_PROVIDER_TRANSCRIPT_INVALID"
    )
    if not window_start <= sealed < window_end:
        _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
    required = {
        "provider_calls", "aws_calls", "aws_mutations",
        "live_provider_evidence", "transcript_digest",
    }
    if not isinstance(provider_summary, Mapping):
        _fail("COLLISION_PROVIDER_SUMMARY_INVALID")
    _require_exact_keys(
        provider_summary, required, "COLLISION_PROVIDER_SUMMARY_INVALID"
    )
    if not isinstance(transcript_events, Sequence) or isinstance(
        transcript_events, (str, bytes)
    ) or any(not isinstance(event, Mapping) for event in transcript_events):
        _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
    provider_calls = provider_summary.get("provider_calls")
    aws_calls = provider_summary.get("aws_calls")
    if (
        type(provider_calls) is not int
        or not 0 <= provider_calls <= MAX_PROVIDER_CALLS
        or provider_summary.get("aws_mutations") != 0
        or provider_summary.get("transcript_digest")
        != canonical_digest(transcript_events)
        or len(transcript_events) != provider_calls
    ):
        _fail("COLLISION_PROVIDER_SUMMARY_INVALID")
    if complete:
        if (
            provider_calls < 1
            or aws_calls != provider_calls
            or provider_summary.get("live_provider_evidence") is not True
        ):
            _fail("COLLISION_PROVIDER_SUMMARY_INVALID")
    elif (
        aws_calls is not None
        or provider_summary.get("live_provider_evidence") is not False
    ):
        _fail("COLLISION_PROVIDER_SUMMARY_INVALID")

    base_fields = {
        "ordinal", "domain", "session_digest", "operation",
        "request_digest", "page_token_digest", "pagination_stream_digest",
        "started_at", "completed_at", "response_digest", "outcome",
        "complete", "truncated", "next_token_digest",
    }
    sessions: dict[str, dict[str, Any]] = {}
    stream_state: dict[str, dict[str, Any]] = {}
    previous_completed: datetime | None = None
    terminal_failure_seen = False
    operations: list[str] = []
    for ordinal, event in enumerate(transcript_events, start=1):
        pending = event.get("outcome") == "INCOMPLETE"
        expected_fields = base_fields | ({"pending_ticket_digest"} if pending else set())
        if set(event) != expected_fields or event.get("ordinal") != ordinal:
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        domain = event.get("domain")
        operation = event.get("operation")
        session_digest = event.get("session_digest")
        if (
            domain not in COLLISION_OPERATION_ALLOWLIST
            or operation not in COLLISION_OPERATION_ALLOWLIST[domain]
            or _DIGEST.fullmatch(str(session_digest)) is None
        ):
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        for field in ("request_digest", "response_digest"):
            _digest(event.get(field), "COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        for field in (
            "page_token_digest", "pagination_stream_digest",
            "next_token_digest", "pending_ticket_digest",
        ):
            item = event.get(field)
            if item is not None:
                _digest(item, "COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        started = _parse_stamp(
            event.get("started_at"), "COLLISION_PROVIDER_TRANSCRIPT_INVALID"
        )
        if (
            not window_start <= started <= sealed
            or (
                previous_completed is not None
                and started < previous_completed
            )
        ):
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        outcome = event.get("outcome")
        if pending:
            if (
                complete
                or event.get("completed_at") is not None
                or event.get("complete") is not False
                or event.get("truncated") is not False
                or event.get("next_token_digest") is not None
            ):
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        else:
            if outcome not in {"SUCCESS", "ERROR"}:
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            completed = _parse_stamp(
                event.get("completed_at"),
                "COLLISION_PROVIDER_TRANSCRIPT_INVALID",
            )
            if not started <= completed <= sealed:
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            previous_completed = completed
            if outcome == "SUCCESS":
                if (
                    event.get("truncated")
                    is not (event.get("next_token_digest") is not None)
                    or event.get("complete")
                    is not (event.get("next_token_digest") is None)
                ):
                    _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            elif (
                event.get("truncated") is not False
                or event.get("next_token_digest") is not None
            ):
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        if terminal_failure_seen:
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        if outcome in {"ERROR", "INCOMPLETE"}:
            terminal_failure_seen = True
        session = sessions.setdefault(
            str(session_digest),
            {
                "domain": domain,
                "operations": [],
                "events": [],
                "sts_success": False,
            },
        )
        if session["domain"] != domain:
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        if not session["operations"]:
            if operation != "sts:GetCallerIdentity":
                _fail("COLLISION_STS_FIRST_REQUIRED")
        elif operation == "sts:GetCallerIdentity":
            _fail("COLLISION_STS_FIRST_REQUIRED")
        session["operations"].append(operation)
        session["events"].append(dict(event))
        if operation == "sts:GetCallerIdentity" and outcome == "SUCCESS":
            session["sts_success"] = True
        is_list = operation in PAGINATED_ACTIONS
        stream_digest = event.get("pagination_stream_digest")
        if is_list:
            if stream_digest is None:
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            stream = stream_state.setdefault(
                str(stream_digest),
                {
                    "session": session_digest,
                    "operation": operation,
                    "expected": None,
                    "seen": set(),
                    "pages": 0,
                    "closed": False,
                },
            )
            if (
                stream["session"] != session_digest
                or stream["operation"] != operation
                or stream["closed"]
                or event.get("page_token_digest") != stream["expected"]
            ):
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            stream["pages"] += 1
            if stream["pages"] > MAX_PAGES:
                _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
            if outcome == "SUCCESS":
                next_token_digest = event.get("next_token_digest")
                if next_token_digest is not None:
                    if (
                        next_token_digest in stream["seen"]
                        or next_token_digest
                        == event.get("page_token_digest")
                    ):
                        _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
                    stream["seen"].add(next_token_digest)
                stream["expected"] = next_token_digest
                stream["closed"] = next_token_digest is None
        elif (
            event.get("page_token_digest") is not None
            or stream_digest is not None
        ):
            _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
        operations.append(str(operation))
    if complete and (
        terminal_failure_seen
        or len(sessions) != MAX_SESSION_BOOTSTRAP_ATTEMPTS
        or any(not session["sts_success"] for session in sessions.values())
        or any(not stream["closed"] for stream in stream_state.values())
    ):
        _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
    return {
        "provider_calls": provider_calls,
        "sessions": sessions,
        "operations": operations,
    }


def _validate_budget_evidence(
    request: Mapping[str, Any],
    budget_summary: Mapping[str, Any],
    budget_events: Sequence[Mapping[str, Any]],
    *,
    complete: bool,
) -> dict[str, int]:
    required = {
        "record_type", "budget_digest", "provider_calls",
        "session_bootstrap_attempts", "credential_vending_calls",
        "network_calls", "page_calls",
        "projected_response_bytes", "modeled_cost_nano_usd",
        "summary_digest",
    }
    if not isinstance(budget_summary, Mapping):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    _require_exact_keys(
        budget_summary, required, "COLLISION_BUDGET_SUMMARY_INVALID"
    )
    if (
        budget_summary.get("record_type")
        != "scanalyze.platform_authority.gug395_preplan_collision_budget_summary.v1"
        or budget_summary.get("budget_digest") != request.get("budget_digest")
    ):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    _verify_self_digest(
        budget_summary,
        "summary_digest",
        "COLLISION_BUDGET_SUMMARY_INVALID",
    )
    fields = (
        "provider_calls", "session_bootstrap_attempts",
        "credential_vending_calls", "network_calls", "page_calls",
        "projected_response_bytes", "modeled_cost_nano_usd",
    )
    counters = {field: budget_summary.get(field) for field in fields}
    if any(type(value) is not int or value < 0 for value in counters.values()):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    if (
        counters["provider_calls"] > MAX_PROVIDER_CALLS
        or counters["session_bootstrap_attempts"]
        > MAX_SESSION_BOOTSTRAP_ATTEMPTS
        or counters["credential_vending_calls"] > MAX_CREDENTIAL_VENDING_CALLS
        or counters["network_calls"] > MAX_NETWORK_CALLS
        or counters["page_calls"] > MAX_PAGE_CALLS
        or counters["page_calls"] > counters["provider_calls"]
        or counters["projected_response_bytes"] > MAX_TOTAL_RESPONSE_BYTES
        or counters["modeled_cost_nano_usd"] > MAX_MODELED_COST_NANO_USD
        or counters["network_calls"]
        != counters["provider_calls"] + counters["credential_vending_calls"]
        or counters["modeled_cost_nano_usd"]
        != counters["network_calls"] * PER_NETWORK_CALL_COST_NANO_USD
        + counters["projected_response_bytes"]
        * PER_PROJECTED_BYTE_COST_NANO_USD
    ):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    if complete and (
        counters["session_bootstrap_attempts"]
        != MAX_SESSION_BOOTSTRAP_ATTEMPTS
    ):
        _fail("COLLISION_BUDGET_SUMMARY_INVALID")
    if (
        not isinstance(budget_events, Sequence)
        or isinstance(budget_events, (str, bytes))
        or any(not isinstance(event, Mapping) for event in budget_events)
        or [event.get("ordinal") for event in budget_events] != list(
        range(1, len(budget_events) + 1)
        )
    ):
        _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
    provider_events = 0
    response_events = 0
    bootstrap_events = 0
    vending_events = 0
    response_bytes = 0
    page_calls = 0
    provider_operations: list[str] = []
    awaiting_response = False
    for event in budget_events:
        kind = event.get("kind")
        if awaiting_response and kind != "PROJECTED_RESPONSE":
            _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
        if kind == "PROVIDER_CALL":
            operation = event.get("operation")
            expected_page_call = operation in PAGINATED_ACTIONS
            if (
                set(event) != {"ordinal", "kind", "operation", "page_call"}
                or operation not in AUTHORITY_ACTIONS | IDENTITY_ACTIONS
                or type(event.get("page_call")) is not bool
                or event["page_call"] is not expected_page_call
            ):
                _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
            provider_events += 1
            provider_operations.append(str(operation))
            page_calls += int(event["page_call"])
            awaiting_response = True
        elif kind == "PROJECTED_RESPONSE":
            if (
                not awaiting_response
                or
                set(event) != {"ordinal", "kind", "byte_count"}
                or type(event.get("byte_count")) is not int
                or not 0 <= event["byte_count"] <= MAX_RESPONSE_BYTES
            ):
                _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
            response_events += 1
            response_bytes += event["byte_count"]
            awaiting_response = False
        elif kind == "SESSION_BOOTSTRAP":
            if (
                set(event) != {"ordinal", "kind", "operation"}
                or event.get("operation") != "sso:GetRoleCredentials"
            ):
                _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
            bootstrap_events += 1
        elif kind == "CREDENTIAL_VEND":
            if (
                set(event) != {"ordinal", "kind", "operation"}
                or event.get("operation") != "sso:GetRoleCredentials"
            ):
                _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
            vending_events += 1
        else:
            _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
    if (
        provider_events != counters["provider_calls"]
        or bootstrap_events != counters["session_bootstrap_attempts"]
        or vending_events != counters["credential_vending_calls"]
        or response_events > provider_events
        or (complete and response_events != provider_events)
        or (complete and awaiting_response)
        or response_bytes != counters["projected_response_bytes"]
        or page_calls != counters["page_calls"]
    ):
        _fail("COLLISION_BUDGET_EVIDENCE_INVALID")
    return {
        **{field: int(counters[field]) for field in fields},
        "provider_operations": provider_operations,
    }


def _validate_transcript_snapshot_bindings(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    transcript: Mapping[str, Any],
    sealed_at: str,
    complete: bool,
) -> None:
    sessions = transcript.get("sessions")
    if not isinstance(sessions, Mapping):
        _fail("COLLISION_PROVIDER_TRANSCRIPT_INVALID")
    observed: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for domain, snapshots in (
        ("authority", authority_snapshots),
        ("identity_center", identity_center_snapshots),
    ):
        for snapshot in snapshots:
            checked = _snapshot_facts(snapshot, domain)
            session_digest = checked["identity"]["session_id_digest"]
            if session_digest in observed:
                _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
            observed[session_digest] = (domain, checked)
    if (complete and set(observed) != set(sessions)) or (
        not complete and not set(observed) <= set(sessions)
    ):
        _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
    sealed = _parse_stamp(
        sealed_at, "COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH"
    )
    for session_digest, (domain, snapshot) in observed.items():
        session = sessions.get(session_digest)
        if (
            not isinstance(session, Mapping)
            or session.get("domain") != domain
            or session.get("sts_success") is not True
        ):
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        operations = session.get("operations")
        events = session.get("events")
        if not isinstance(operations, list) or any(
            not isinstance(operation, str) for operation in operations
        ) or not isinstance(events, list) or any(
            not isinstance(event, Mapping) for event in events
        ):
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        if snapshot["transcript_segment_digest"] != canonical_digest(events):
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        identity = snapshot["identity"]
        identity_started = _parse_stamp(
            identity["started_at"],
            "COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH",
        )
        identity_expires = _parse_stamp(
            identity["expires_at"],
            "COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH",
        )
        for event in events:
            started = _parse_stamp(
                event.get("started_at"),
                "COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH",
            )
            completed = _parse_stamp(
                event.get("completed_at"),
                "COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH",
            )
            if (
                event.get("outcome") != "SUCCESS"
                or not identity_started
                <= started
                <= completed
                <= sealed
                < identity_expires
            ):
                _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        required_operations = (
            {
                "sts:GetCallerIdentity",
                "s3:ListAllMyBuckets",
                "kms:ListKeys",
                "kms:ListAliases",
                "signer:ListSigningProfiles",
                "lambda:ListCodeSigningConfigs",
            }
            if domain == "authority"
            else {
                "sts:GetCallerIdentity",
                "sso:ListInstances",
                "sso:DescribeInstance",
            }
        )
        if domain == "identity_center" and snapshot["facts"][
            "instance_matches"
        ]:
            required_operations |= {
                "sso:ListApplications",
                "sso:ListPermissionSets",
            }
        if not required_operations <= set(operations):
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")

        events_by_operation: dict[str, list[Mapping[str, Any]]] = {}
        for event in events:
            events_by_operation.setdefault(
                str(event["operation"]), []
            ).append(event)
        sts_events = events_by_operation.get("sts:GetCallerIdentity", [])
        if len(sts_events) != 1:
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        expected_sts_response = {
            "Account": identity["account_id"],
            "Arn": identity["principal_arn"],
            "UserIdPresent": True,
        }
        if (
            sts_events[0].get("request_digest") != canonical_digest({})
            or sts_events[0].get("response_digest")
            != canonical_digest(expected_sts_response)
        ):
            _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")

        fixed_requests: dict[str, Mapping[str, Any]] = {
            "s3:ListAllMyBuckets": {
                "BucketRegion": REGION,
                "Prefix": request["targets"]["artifact_bucket"]["name"],
                "MaxBuckets": request["budget"]["max_owned_buckets"],
            },
            "kms:ListKeys": {},
            "kms:ListAliases": {},
            "signer:ListSigningProfiles": {
                "includeCanceled": True,
                "statuses": ["Active", "Canceled", "Revoked"],
            },
            "lambda:ListCodeSigningConfigs": {},
            "sso:ListInstances": {},
            "sso:DescribeInstance": {
                "InstanceArn": request["targets"][
                    "identity_center_application"
                ]["instance_arn"]
            },
            "sso:ListApplications": {
                "InstanceArn": request["targets"][
                    "identity_center_application"
                ]["instance_arn"]
            },
            "sso:ListPermissionSets": {
                "InstanceArn": request["targets"][
                    "identity_center_application"
                ]["instance_arn"]
            },
        }
        for operation in required_operations & PAGINATED_ACTIONS:
            operation_events = events_by_operation.get(operation, [])
            if not operation_events:
                _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
            base_request = fixed_requests[operation]
            expected_stream = canonical_digest(
                {
                    "session": session_digest,
                    "operation": operation,
                    "request": base_request,
                }
            )
            if (
                operation_events[0].get("page_token_digest") is not None
                or operation_events[0].get("request_digest")
                != canonical_digest(base_request)
                or any(
                    event.get("pagination_stream_digest")
                    != expected_stream
                    for event in operation_events
                )
            ):
                _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")
        if domain == "identity_center":
            describe_events = events_by_operation.get(
                "sso:DescribeInstance", []
            )
            if (
                len(describe_events) != 1
                or describe_events[0].get("request_digest")
                != canonical_digest(fixed_requests["sso:DescribeInstance"])
                or describe_events[0].get("response_digest")
                != canonical_digest(snapshot["facts"]["described_instance"])
                or operations.index("sso:ListInstances")
                >= operations.index("sso:DescribeInstance")
                or (
                    "sso:ListApplications" in operations
                    and operations.index("sso:DescribeInstance")
                    >= operations.index("sso:ListApplications")
                )
                or (
                    "sso:ListPermissionSets" in operations
                    and operations.index("sso:DescribeInstance")
                    >= operations.index("sso:ListPermissionSets")
                )
            ):
                _fail("COLLISION_SNAPSHOT_TRANSCRIPT_MISMATCH")


def _validated_result_components(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    provider_summary: Mapping[str, Any],
    transcript_events: Sequence[Mapping[str, Any]],
    budget_summary: Mapping[str, Any],
    budget_events: Sequence[Mapping[str, Any]],
    sealed_at: str,
    complete: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    validate_collision_probe_request(request)
    classification = (
        classify_collision_probe_snapshots(
            authority_snapshots=authority_snapshots,
            identity_center_snapshots=identity_center_snapshots,
        )
        if complete
        else classify_partial_collision_probe_snapshots(
            authority_snapshots=authority_snapshots,
            identity_center_snapshots=identity_center_snapshots,
        )
    )
    _validate_snapshot_request_bindings(
        request,
        authority_snapshots=authority_snapshots,
        identity_center_snapshots=identity_center_snapshots,
        sealed_at=sealed_at,
        complete=complete,
    )
    transcript = _validate_provider_evidence(
        request,
        provider_summary,
        transcript_events,
        sealed_at=sealed_at,
        complete=complete,
    )
    counters = _validate_budget_evidence(
        request, budget_summary, budget_events, complete=complete
    )
    if complete:
        if (
            counters["provider_calls"] != transcript["provider_calls"]
            or counters["provider_operations"] != transcript["operations"]
        ):
            _fail("COLLISION_BUDGET_PROVIDER_TRANSCRIPT_MISMATCH")
    elif (
        counters["provider_operations"][: len(transcript["operations"])]
        != transcript["operations"]
        or len(counters["provider_operations"])
        - len(transcript["operations"])
        not in {0, 1}
    ):
        _fail("COLLISION_BUDGET_PROVIDER_TRANSCRIPT_MISMATCH")
    _validate_transcript_snapshot_bindings(
        request=request,
        authority_snapshots=authority_snapshots,
        identity_center_snapshots=identity_center_snapshots,
        transcript=transcript,
        sealed_at=sealed_at,
        complete=complete,
    )
    return classification, transcript, counters


def _private_evidence(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    provider_summary: Mapping[str, Any],
    transcript_events: Sequence[Mapping[str, Any]],
    budget_summary: Mapping[str, Any],
    budget_events: Sequence[Mapping[str, Any]],
    sealed_at: str,
    execution_status: str,
    blocker_code: str,
) -> dict[str, Any]:
    complete = execution_status == EXECUTION_COMPLETED
    if (
        execution_status not in {EXECUTION_COMPLETED, EXECUTION_BLOCKED}
        or (complete and blocker_code != "NONE")
        or (
            not complete
            and (blocker_code == "NONE" or _TOKEN.fullmatch(blocker_code) is None)
        )
    ):
        _fail("COLLISION_EXECUTION_STATUS_INVALID")
    classification, _, _ = _validated_result_components(
        request=request,
        authority_snapshots=authority_snapshots,
        identity_center_snapshots=identity_center_snapshots,
        provider_summary=provider_summary,
        transcript_events=transcript_events,
        budget_summary=budget_summary,
        budget_events=budget_events,
        sealed_at=sealed_at,
        complete=complete,
    )
    evidence = {
        "record_type": PRIVATE_EVIDENCE_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "seed_issue": SEED_ISSUE,
        "execution_status": execution_status,
        "blocker_code": blocker_code,
        "request": _copy(request, "COLLISION_REQUEST_INVALID"),
        "request_digest": request["request_digest"],
        "authority_snapshots": _copy(
            authority_snapshots, "COLLISION_SNAPSHOT_INVALID"
        ),
        "identity_center_snapshots": _copy(
            identity_center_snapshots, "COLLISION_SNAPSHOT_INVALID"
        ),
        "classification": classification,
        "provider_summary": _copy(
            provider_summary, "COLLISION_PROVIDER_SUMMARY_INVALID"
        ),
        "transcript_events": _copy(
            transcript_events, "COLLISION_PROVIDER_TRANSCRIPT_INVALID"
        ),
        "budget_summary": _copy(
            budget_summary, "COLLISION_BUDGET_SUMMARY_INVALID"
        ),
        "budget_events": _copy(
            budget_events, "COLLISION_BUDGET_EVIDENCE_INVALID"
        ),
        "sealed_at": sealed_at,
        "read_only": True,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
    }
    return _seal(evidence, "provider_evidence_digest")


def _public_receipt_from_private_evidence(
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    request = evidence["request"]
    classification = evidence["classification"]
    provider_summary = evidence["provider_summary"]
    budget_summary = evidence["budget_summary"]
    authority = classification["authority"]
    identity = classification["identity_center"]
    completed = evidence["execution_status"] == EXECUTION_COMPLETED
    resource_counts = {
        **{
            f"authority_{key}": value
            for key, value in authority["resource_counts"].items()
        },
        **{
            f"identity_{key}": value
            for key, value in identity["resource_counts"].items()
        },
    }
    if completed:
        gate = {
            ABSENT_READY: "READY_FOR_PROVIDER_IMPLEMENTATION",
            COLLISION_BLOCKED: "BLOCKED_COLLISION",
            UNCERTAIN: "BLOCKED_RECONCILIATION_REQUIRED",
        }[classification["classification"]]
        status = "LIVE_READ_ONLY_PROBE_RECORDED"
        evidence_scope = "LIVE_PROVIDER_DIGEST_ONLY"
        aws_calls: int | None = provider_summary["aws_calls"]
        network_calls: int | None = budget_summary["network_calls"]
        modeled_cost: str | None = _modeled_cost(
            budget_summary["modeled_cost_nano_usd"]
        )
        cost_status = "WITHIN_REVIEWED_BOUND"
    else:
        gate = "BLOCKED_RECONCILIATION_REQUIRED"
        status = "LIVE_READ_ONLY_PROBE_BLOCKED"
        evidence_scope = "LIVE_ATTEMPT_DIGEST_ONLY"
        aws_calls = None
        network_calls = None
        modeled_cost = None
        cost_status = "INCOMPLETE_UNBOUNDED"
    receipt = {
        "record_type": RECEIPT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "seed_issue": SEED_ISSUE,
        "downstream_consumer_issue": DOWNSTREAM_CONSUMER_ISSUE,
        "status": status,
        "evidence_scope": evidence_scope,
        "classification": classification["classification"],
        "provider_implementation_gate": gate,
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "preplan_seed_digest": request["preplan_seed_digest"],
        "mutation_plan_digest": request["mutation_plan_digest"],
        "target_catalog_digest": request["target_catalog_digest"],
        "expected_tag_contract_digest": request[
            "expected_tag_contract_digest"
        ],
        "request_digest": request["request_digest"],
        "profile_binding_digest": request["profile_binding_digest"],
        "policy_set_digest": request["policy_set_digest"],
        "budget_digest": request["budget_digest"],
        "window_digest": request["window_digest"],
        "authority_session_digests": authority["session_digests"],
        "identity_center_session_digests": identity["session_digests"],
        "authority_snapshot_digests": authority["snapshot_digests"],
        "identity_center_snapshot_digests": identity["snapshot_digests"],
        "authority_facts_digest": authority["facts_digest"],
        "identity_center_facts_digest": identity["facts_digest"],
        "authority_classification": authority["classification"],
        "identity_center_classification": identity["classification"],
        "authority_collision_count": authority["collision_count"],
        "identity_center_collision_count": identity["collision_count"],
        "collision_count": classification["collision_count"],
        "resource_counts_digest": canonical_digest(resource_counts),
        "provider_evidence_digest": evidence["provider_evidence_digest"],
        "transcript_digest": provider_summary["transcript_digest"],
        "evidence_manifest_digest": canonical_digest(
            {
                "execution_status": evidence["execution_status"],
                "provider_evidence_digest": evidence[
                    "provider_evidence_digest"
                ],
                "transcript_digest": provider_summary["transcript_digest"],
                "budget_summary_digest": budget_summary["summary_digest"],
            }
        ),
        "provider_calls": (
            provider_summary["provider_calls"]
            if completed
            else budget_summary["provider_calls"]
        ),
        "aws_calls": aws_calls,
        "session_bootstrap_attempts": budget_summary[
            "session_bootstrap_attempts"
        ],
        "credential_vending_calls": budget_summary[
            "credential_vending_calls"
        ],
        "network_calls": network_calls,
        "page_calls": budget_summary["page_calls"],
        "projected_response_bytes": budget_summary[
            "projected_response_bytes"
        ],
        "modeled_cost_usd_upper": modeled_cost,
        "cost_status": cost_status,
        "evidence_complete": classification["evidence_complete"],
        "evidence_stable": classification["evidence_stable"],
        "live_provider_evidence": provider_summary[
            "live_provider_evidence"
        ],
        "read_only": True,
        "reconciliation_only": classification["reconciliation_only"],
        "live_execution_ready": False,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
        "sealed_at": evidence["sealed_at"],
    }
    return _seal(receipt, "receipt_digest")


def build_collision_probe_result(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    provider_summary: Mapping[str, Any],
    transcript_events: Sequence[Mapping[str, Any]],
    budget_summary: Mapping[str, Any],
    budget_events: Sequence[Mapping[str, Any]],
    sealed_at: str,
) -> CollisionProbeResult:
    """Seal private evidence and its public digest-only projection."""

    evidence = _private_evidence(
        request=request,
        authority_snapshots=authority_snapshots,
        identity_center_snapshots=identity_center_snapshots,
        provider_summary=provider_summary,
        transcript_events=transcript_events,
        budget_summary=budget_summary,
        budget_events=budget_events,
        sealed_at=sealed_at,
        execution_status=EXECUTION_COMPLETED,
        blocker_code="NONE",
    )
    receipt = _public_receipt_from_private_evidence(evidence)
    validate_private_collision_probe_evidence(evidence)
    validate_public_collision_probe_receipt(receipt)
    return CollisionProbeResult(evidence, receipt)


def build_collision_probe_failure_result(
    *,
    request: Mapping[str, Any],
    authority_snapshots: Sequence[Mapping[str, Any]],
    identity_center_snapshots: Sequence[Mapping[str, Any]],
    provider_summary: Mapping[str, Any],
    transcript_events: Sequence[Mapping[str, Any]],
    budget_summary: Mapping[str, Any],
    budget_events: Sequence[Mapping[str, Any]],
    blocker_code: str,
    sealed_at: str,
) -> CollisionProbeResult:
    """Seal one conservative durable artifact after a claimed probe blocks."""

    evidence = _private_evidence(
        request=request,
        authority_snapshots=authority_snapshots,
        identity_center_snapshots=identity_center_snapshots,
        provider_summary=provider_summary,
        transcript_events=transcript_events,
        budget_summary=budget_summary,
        budget_events=budget_events,
        sealed_at=sealed_at,
        execution_status=EXECUTION_BLOCKED,
        blocker_code=blocker_code,
    )
    receipt = _public_receipt_from_private_evidence(evidence)
    validate_private_collision_probe_evidence(evidence)
    validate_public_collision_probe_receipt(receipt)
    return CollisionProbeResult(evidence, receipt)


def _assert_public(value: Any) -> None:
    encoded = canonical_json(value)
    if _FORBIDDEN_PUBLIC.search(encoded):
        _fail("COLLISION_PUBLIC_RECEIPT_SENSITIVE")


def validate_public_collision_probe_receipt(receipt: Mapping[str, Any]) -> None:
    value = _copy(receipt, "COLLISION_PUBLIC_RECEIPT_INVALID")
    if not isinstance(value, Mapping):
        _fail("COLLISION_PUBLIC_RECEIPT_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "seed_issue",
        "downstream_consumer_issue", "status", "evidence_scope", "classification",
        "provider_implementation_gate", "source_commit_sha", "source_tree_sha",
        "preplan_seed_digest", "mutation_plan_digest", "target_catalog_digest",
        "expected_tag_contract_digest", "request_digest", "profile_binding_digest",
        "policy_set_digest", "budget_digest", "window_digest",
        "authority_session_digests", "identity_center_session_digests",
        "authority_snapshot_digests", "identity_center_snapshot_digests",
        "authority_facts_digest", "identity_center_facts_digest",
        "authority_classification", "identity_center_classification",
        "authority_collision_count", "identity_center_collision_count",
        "collision_count", "resource_counts_digest", "provider_evidence_digest",
        "transcript_digest", "evidence_manifest_digest", "provider_calls",
        "aws_calls", "session_bootstrap_attempts", "credential_vending_calls",
        "network_calls", "page_calls",
        "projected_response_bytes", "modeled_cost_usd_upper", "cost_status",
        "evidence_complete", "evidence_stable", "live_provider_evidence",
        "read_only", "reconciliation_only", "live_execution_ready",
        "aws_mutations", "deployment_authorized", "production",
        "two_human_status", "independent_approval_present", "production_status",
        "sealed_at", "receipt_digest",
    }
    _require_exact_keys(value, required, "COLLISION_PUBLIC_RECEIPT_FIELDS_INVALID")
    constants = {
        "record_type": RECEIPT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "seed_issue": SEED_ISSUE,
        "downstream_consumer_issue": DOWNSTREAM_CONSUMER_ISSUE,
        "read_only": True,
        "live_execution_ready": False,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("COLLISION_PUBLIC_RECEIPT_SCOPE_INVALID")
    classification = value.get("classification")
    if (
        classification not in CLASSIFICATIONS
        or value.get("authority_classification") not in CLASSIFICATIONS
        or value.get("identity_center_classification") not in CLASSIFICATIONS
    ):
        _fail("COLLISION_PUBLIC_CLASSIFICATION_INVALID")
    for field in ("source_commit_sha", "source_tree_sha"):
        _sha(value.get(field), "COLLISION_PUBLIC_SOURCE_INVALID")
    for field in (
        "preplan_seed_digest", "mutation_plan_digest", "target_catalog_digest",
        "expected_tag_contract_digest", "request_digest", "profile_binding_digest",
        "policy_set_digest", "budget_digest", "window_digest",
        "authority_facts_digest", "identity_center_facts_digest",
        "resource_counts_digest", "provider_evidence_digest", "transcript_digest",
        "evidence_manifest_digest",
    ):
        _digest(value.get(field), "COLLISION_PUBLIC_DIGEST_INVALID")
    for field in (
        "authority_session_digests", "identity_center_session_digests",
        "authority_snapshot_digests", "identity_center_snapshot_digests",
    ):
        items = value.get(field)
        expected_length = (
            None
            if value.get("status") == "LIVE_READ_ONLY_PROBE_BLOCKED"
            else 2
        )
        if (
            not isinstance(items, list)
            or (expected_length is not None and len(items) != expected_length)
            or (expected_length is None and not 0 <= len(items) <= 2)
            or len(set(items)) != len(items)
            or any(_DIGEST.fullmatch(str(item)) is None for item in items)
        ):
            _fail("COLLISION_PUBLIC_SESSION_BINDING_INVALID")
    if value.get("status") == "LIVE_READ_ONLY_PROBE_BLOCKED" and (
        len(value["authority_session_digests"])
        != len(value["authority_snapshot_digests"])
        or len(value["identity_center_session_digests"])
        != len(value["identity_center_snapshot_digests"])
    ):
        _fail("COLLISION_PUBLIC_SESSION_BINDING_INVALID")
    counts = (
        value.get("authority_collision_count"),
        value.get("identity_center_collision_count"),
        value.get("collision_count"),
    )
    if (
        any(type(item) is not int or item < 0 for item in counts)
        or counts[2] != counts[0] + counts[1]
    ):
        _fail("COLLISION_PUBLIC_COUNT_INVALID")
    provider_calls = value.get("provider_calls")
    bootstraps = value.get("session_bootstrap_attempts")
    credentials = value.get("credential_vending_calls")
    network = value.get("network_calls")
    pages = value.get("page_calls")
    response_bytes = value.get("projected_response_bytes")
    if value.get("status") == "SYNTHETIC_CONTRACT_ONLY_BLOCKED":
        zero_counter_fields = (
            "provider_calls",
            "aws_calls",
            "session_bootstrap_attempts",
            "credential_vending_calls",
            "network_calls",
            "page_calls",
            "projected_response_bytes",
        )
        if any(
            type(value.get(field)) is not int or value[field] != 0
            for field in zero_counter_fields
        ):
            _fail("COLLISION_PUBLIC_SYNTHETIC_OVERCLAIM")
        synthetic_constants = {
            "evidence_scope": "SYNTHETIC_SCHEMA_EXAMPLE",
            "classification": UNCERTAIN,
            "authority_classification": UNCERTAIN,
            "identity_center_classification": UNCERTAIN,
            "provider_implementation_gate": "BLOCKED_SYNTHETIC_EVIDENCE",
            "authority_collision_count": 0,
            "identity_center_collision_count": 0,
            "collision_count": 0,
            "modeled_cost_usd_upper": "0.000000000",
            "cost_status": "SYNTHETIC_ZERO_COST",
            "evidence_complete": False,
            "evidence_stable": False,
            "live_provider_evidence": False,
            "reconciliation_only": True,
        }
        if any(
            value.get(key) != expected
            for key, expected in synthetic_constants.items()
        ):
            _fail("COLLISION_PUBLIC_SYNTHETIC_OVERCLAIM")
        _parse_stamp(value.get("sealed_at"), "COLLISION_SEALED_AT_INVALID")
        _verify_self_digest(
            value,
            "receipt_digest",
            "COLLISION_PUBLIC_RECEIPT_DIGEST_MISMATCH",
        )
        _assert_public(value)
        return
    if value.get("status") == "LIVE_READ_ONLY_PROBE_BLOCKED":
        if (
            classification != UNCERTAIN
            or type(provider_calls) is not int
            or not 0 <= provider_calls <= MAX_PROVIDER_CALLS
            or value.get("aws_calls") is not None
            or type(bootstraps) is not int
            or not 0 <= bootstraps <= MAX_SESSION_BOOTSTRAP_ATTEMPTS
            or type(credentials) is not int
            or not 0 <= credentials <= MAX_CREDENTIAL_VENDING_CALLS
            or network is not None
            or type(pages) is not int
            or not 0 <= pages <= min(provider_calls, MAX_PAGE_CALLS)
            or type(response_bytes) is not int
            or not 0 <= response_bytes <= MAX_TOTAL_RESPONSE_BYTES
            or value.get("modeled_cost_usd_upper") is not None
            or value.get("cost_status") != "INCOMPLETE_UNBOUNDED"
            or value.get("evidence_scope") != "LIVE_ATTEMPT_DIGEST_ONLY"
            or value.get("provider_implementation_gate")
            != "BLOCKED_RECONCILIATION_REQUIRED"
            or value.get("evidence_complete") is not False
            or value.get("evidence_stable") is not False
            or value.get("live_provider_evidence") is not False
            or value.get("reconciliation_only") is not True
        ):
            _fail("COLLISION_PUBLIC_BLOCKED_OVERCLAIM")
        domain_classes = {
            "authority": value["authority_classification"],
            "identity_center": value["identity_center_classification"],
        }
        domain_counts = {
            "authority": counts[0],
            "identity_center": counts[1],
        }
        if any(
            (
                domain_classes[domain] == COLLISION_BLOCKED
                and domain_counts[domain] == 0
            )
            or (
                domain_classes[domain] != COLLISION_BLOCKED
                and domain_counts[domain] != 0
            )
            for domain in domain_classes
        ):
            _fail("COLLISION_PUBLIC_BLOCKED_OVERCLAIM")
        _parse_stamp(value.get("sealed_at"), "COLLISION_SEALED_AT_INVALID")
        _verify_self_digest(
            value,
            "receipt_digest",
            "COLLISION_PUBLIC_RECEIPT_DIGEST_MISMATCH",
        )
        _assert_public(value)
        return
    if (
        type(provider_calls) is not int
        or not 1 <= provider_calls <= MAX_PROVIDER_CALLS
        or value.get("aws_calls") != provider_calls
        or bootstraps != MAX_SESSION_BOOTSTRAP_ATTEMPTS
        or type(credentials) is not int
        or not 0 <= credentials <= MAX_CREDENTIAL_VENDING_CALLS
        or network != provider_calls + credentials
        or network > MAX_NETWORK_CALLS
        or type(pages) is not int
        or not 0 <= pages <= min(provider_calls, MAX_PAGE_CALLS)
        or type(response_bytes) is not int
        or not 0 <= response_bytes <= MAX_TOTAL_RESPONSE_BYTES
    ):
        _fail("COLLISION_PUBLIC_COUNTER_INVALID")
    expected_cost = (
        network * PER_NETWORK_CALL_COST_NANO_USD
        + response_bytes * PER_PROJECTED_BYTE_COST_NANO_USD
    )
    if (
        expected_cost > MAX_MODELED_COST_NANO_USD
        or value.get("modeled_cost_usd_upper") != _modeled_cost(expected_cost)
    ):
        _fail("COLLISION_PUBLIC_COUNTER_INVALID")
    expected = {
        ABSENT_READY: {
            "gate": "READY_FOR_PROVIDER_IMPLEMENTATION",
            "complete": True,
            "stable": True,
            "reconciliation": False,
        },
        COLLISION_BLOCKED: {
            "gate": "BLOCKED_COLLISION",
            "complete": True,
            "stable": True,
            "reconciliation": False,
        },
        UNCERTAIN: {
            "gate": "BLOCKED_RECONCILIATION_REQUIRED",
            "complete": False,
            "stable": False,
            "reconciliation": True,
        },
    }[str(classification)]
    if (
        value.get("status") != "LIVE_READ_ONLY_PROBE_RECORDED"
        or value.get("evidence_scope") != "LIVE_PROVIDER_DIGEST_ONLY"
        or value.get("provider_implementation_gate") != expected["gate"]
        or value.get("evidence_complete") is not expected["complete"]
        or value.get("evidence_stable") is not expected["stable"]
        or value.get("reconciliation_only") is not expected["reconciliation"]
        or value.get("live_provider_evidence") is not True
        or value.get("cost_status") != "WITHIN_REVIEWED_BOUND"
    ):
        _fail("COLLISION_PUBLIC_CLASSIFICATION_OVERCLAIM")
    domain_classes = {
        "authority": value["authority_classification"],
        "identity_center": value["identity_center_classification"],
    }
    domain_counts = {
        "authority": counts[0],
        "identity_center": counts[1],
    }
    if any(
        (domain_classes[domain] == COLLISION_BLOCKED)
        != (domain_counts[domain] > 0)
        for domain in domain_classes
    ):
        _fail("COLLISION_PUBLIC_CLASSIFICATION_OVERCLAIM")
    observed_domain_classes = set(domain_classes.values())
    expected_global = (
        UNCERTAIN
        if UNCERTAIN in observed_domain_classes
        else (
            COLLISION_BLOCKED
            if COLLISION_BLOCKED in observed_domain_classes
            else ABSENT_READY
        )
    )
    if classification != expected_global:
        _fail("COLLISION_PUBLIC_CLASSIFICATION_OVERCLAIM")
    _parse_stamp(value.get("sealed_at"), "COLLISION_SEALED_AT_INVALID")
    _verify_self_digest(
        value, "receipt_digest", "COLLISION_PUBLIC_RECEIPT_DIGEST_MISMATCH"
    )
    _assert_public(value)


def validate_private_collision_probe_evidence(evidence: Mapping[str, Any]) -> None:
    value = _copy(evidence, "COLLISION_PRIVATE_EVIDENCE_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "seed_issue",
        "execution_status", "blocker_code",
        "request", "request_digest", "authority_snapshots",
        "identity_center_snapshots", "classification", "provider_summary",
        "transcript_events", "budget_summary", "budget_events", "sealed_at",
        "read_only", "aws_mutations", "deployment_authorized", "production",
        "production_status", "provider_evidence_digest",
    }
    _require_exact_keys(value, required, "COLLISION_PRIVATE_EVIDENCE_FIELDS_INVALID")
    if (
        value.get("record_type") != PRIVATE_EVIDENCE_TYPE
        or value.get("schema_version") != 1
        or value.get("implementation_issue") != IMPLEMENTATION_ISSUE
        or value.get("seed_issue") != SEED_ISSUE
        or value.get("read_only") is not True
        or value.get("aws_mutations") != 0
        or value.get("deployment_authorized") is not False
        or value.get("production") is not False
        or value.get("production_status") != PRODUCTION_STATUS
    ):
        _fail("COLLISION_PRIVATE_EVIDENCE_SCOPE_INVALID")
    execution_status = value.get("execution_status")
    blocker_code = value.get("blocker_code")
    if (
        execution_status not in {EXECUTION_COMPLETED, EXECUTION_BLOCKED}
        or (
            execution_status == EXECUTION_COMPLETED
            and blocker_code != "NONE"
        )
        or (
            execution_status == EXECUTION_BLOCKED
            and (
                blocker_code == "NONE"
                or _TOKEN.fullmatch(str(blocker_code)) is None
            )
        )
    ):
        _fail("COLLISION_EXECUTION_STATUS_INVALID")
    validate_collision_probe_request(value["request"])
    if value["request_digest"] != value["request"]["request_digest"]:
        _fail("COLLISION_PRIVATE_EVIDENCE_REQUEST_MISMATCH")
    expected, _, _ = _validated_result_components(
        request=value["request"],
        authority_snapshots=value["authority_snapshots"],
        identity_center_snapshots=value["identity_center_snapshots"],
        provider_summary=value["provider_summary"],
        transcript_events=value["transcript_events"],
        budget_summary=value["budget_summary"],
        budget_events=value["budget_events"],
        sealed_at=value["sealed_at"],
        complete=execution_status == EXECUTION_COMPLETED,
    )
    if value["classification"] != expected:
        _fail("COLLISION_PRIVATE_EVIDENCE_CLASSIFICATION_MISMATCH")
    _verify_self_digest(
        value,
        "provider_evidence_digest",
        "COLLISION_PRIVATE_EVIDENCE_DIGEST_MISMATCH",
    )


def _read_collision_result_custody(
    *,
    private_root: Path,
    evidence: Mapping[str, Any],
    expected_claim_digest: str | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Read the exact request/claim pair that owns a result bundle."""

    request = evidence.get("request")
    if not isinstance(request, Mapping):
        _fail("COLLISION_RESULT_CUSTODY_MISMATCH")
    try:
        root_digest = private_root_digest(private_root)
        persisted_request = read_private_json(private_root, DEFAULT_REQUEST_FILE)
        persisted_claim = read_private_json(private_root, DEFAULT_CLAIM_FILE)
        validate_collision_probe_request(persisted_request)
        checked_claim = _validate_collision_probe_claim(
            persisted_claim, persisted_request
        )
    except (CollectorError, CollisionProbeError) as exc:
        raise CollisionProbeError(
            "COLLISION_RESULT_CUSTODY_MISMATCH"
        ) from exc
    if (
        root_digest != request.get("private_custody_digest")
        or persisted_request != dict(request)
        or persisted_request.get("request_digest")
        != evidence.get("request_digest")
        or (
            expected_claim_digest is not None
            and checked_claim["claim_digest"] != expected_claim_digest
        )
    ):
        _fail("COLLISION_RESULT_CUSTODY_MISMATCH")
    return root_digest, persisted_request, checked_claim


def persist_collision_probe_result(
    *,
    private_root: Path,
    result: CollisionProbeResult,
    expected_claim_digest: str,
    result_file: str = DEFAULT_RESULT_FILE,
) -> None:
    if (
        type(result) is not CollisionProbeResult
        or result_file != DEFAULT_RESULT_FILE
    ):
        _fail("COLLISION_RESULT_INVALID")
    _digest(expected_claim_digest, "COLLISION_RESULT_CUSTODY_MISMATCH")
    validate_private_collision_probe_evidence(result.private_evidence)
    validate_public_collision_probe_receipt(result.public_receipt)
    expected_receipt = _public_receipt_from_private_evidence(
        result.private_evidence
    )
    if result.public_receipt != expected_receipt:
        _fail("COLLISION_RESULT_BINDING_MISMATCH")
    root_digest, persisted_request, persisted_claim = (
        _read_collision_result_custody(
            private_root=private_root,
            evidence=result.private_evidence,
            expected_claim_digest=expected_claim_digest,
        )
    )
    bundle = {
        "record_type": RESULT_TYPE,
        "schema_version": 1,
        "private_root_digest": root_digest,
        "request_digest": persisted_request["request_digest"],
        "claim_digest": persisted_claim["claim_digest"],
        "private_evidence": result.private_evidence,
        "public_receipt": result.public_receipt,
    }
    _seal(bundle, "bundle_digest")
    try:
        private_target_absent(private_root, result_file)
        write_private_json(private_root, result_file, bundle)
        if read_private_json(private_root, result_file) != bundle:
            _fail("COLLISION_RESULT_READBACK_MISMATCH")
    except CollectorError as exc:
        raise CollisionProbeError(exc.code) from exc
    observed_root, observed_request, observed_claim = (
        _read_collision_result_custody(
            private_root=private_root,
            evidence=result.private_evidence,
            expected_claim_digest=expected_claim_digest,
        )
    )
    if (
        observed_root != root_digest
        or observed_request != persisted_request
        or observed_claim != persisted_claim
    ):
        _fail("COLLISION_RESULT_CUSTODY_MISMATCH")


def read_collision_probe_result(
    *, private_root: Path, result_file: str = DEFAULT_RESULT_FILE
) -> CollisionProbeResult:
    """Read and validate the single authoritative create-only result bundle."""

    if result_file != DEFAULT_RESULT_FILE:
        _fail("COLLISION_RESULT_INVALID")
    try:
        bundle = read_private_json(private_root, result_file)
    except CollectorError as exc:
        raise CollisionProbeError(exc.code) from exc
    if set(bundle) != {
        "record_type", "schema_version", "private_root_digest",
        "request_digest", "claim_digest", "private_evidence",
        "public_receipt", "bundle_digest",
    } or bundle.get("record_type") != RESULT_TYPE or bundle.get(
        "schema_version"
    ) != 1:
        _fail("COLLISION_RESULT_INVALID")
    _verify_self_digest(
        bundle, "bundle_digest", "COLLISION_RESULT_DIGEST_MISMATCH"
    )
    evidence = bundle.get("private_evidence")
    receipt = bundle.get("public_receipt")
    if not isinstance(evidence, Mapping) or not isinstance(receipt, Mapping):
        _fail("COLLISION_RESULT_INVALID")
    validate_private_collision_probe_evidence(evidence)
    validate_public_collision_probe_receipt(receipt)
    if receipt != _public_receipt_from_private_evidence(evidence):
        _fail("COLLISION_RESULT_BINDING_MISMATCH")
    root_digest, request, claim = _read_collision_result_custody(
        private_root=private_root,
        evidence=evidence,
    )
    if (
        bundle.get("private_root_digest") != root_digest
        or bundle.get("request_digest") != request["request_digest"]
        or bundle.get("claim_digest") != claim["claim_digest"]
    ):
        _fail("COLLISION_RESULT_CUSTODY_MISMATCH")
    return CollisionProbeResult(dict(evidence), dict(receipt))


__all__ = [
    "ABSENT_READY",
    "AUTHORITY_ACTIONS",
    "AUTHORITY_TAG_CONTRACT",
    "CLASSIFICATIONS",
    "COLLISION_BLOCKED",
    "COLLISION_OPERATION_ALLOWLIST",
    "PAGINATED_ACTIONS",
    "CollisionCallLedger",
    "CollisionProbeBudget",
    "CollisionProbeError",
    "CollisionProbeExecutionCapability",
    "CollisionProbeResult",
    "DEFAULT_CLAIM_FILE",
    "DEFAULT_EVIDENCE_FILE",
    "DEFAULT_RECEIPT_FILE",
    "DEFAULT_REQUEST_FILE",
    "DEFAULT_RESULT_FILE",
    "IDENTITY_ACTIONS",
    "IDENTITY_TAG_CONTRACT",
    "MAX_APPLICATIONS",
    "MAX_CODE_SIGNING_CONFIGS",
    "MAX_KMS_KEYS",
    "MAX_OWNED_BUCKETS",
    "MAX_PERMISSION_SETS",
    "MAX_SESSION_BOOTSTRAP_ATTEMPTS",
    "MAX_SIGNING_PROFILES",
    "REQUEST_TYPE",
    "REQUEST_TYPE_V1",
    "REQUEST_TYPE_V2",
    "RECEIPT_TYPE",
    "TARGET_ORDER",
    "UNCERTAIN",
    "VerifiedCollisionProbeSource",
    "approved_collision_probe_request",
    "approved_collision_probe_claim_digest",
    "assert_collision_probe_execution_active",
    "assert_collision_probe_private_root_binding",
    "assert_collision_probe_provider_capability_bindings",
    "build_collision_probe_result",
    "build_collision_probe_failure_result",
    "claim_collision_probe_execution",
    "classify_collision_probe_snapshots",
    "collision_target_catalog",
    "complete_collision_probe_execution",
    "materialize_collision_probe_request",
    "operational_host_digest",
    "persist_collision_probe_request",
    "persist_collision_probe_result",
    "private_root_digest",
    "read_and_claim_collision_probe_request",
    "read_collision_probe_result",
    "validate_collision_probe_request",
    "validate_collision_probe_request_v1",
    "validate_collision_probe_request_v2",
    "validate_private_collision_probe_evidence",
    "validate_public_collision_probe_receipt",
    "verify_collision_probe_source",
]
