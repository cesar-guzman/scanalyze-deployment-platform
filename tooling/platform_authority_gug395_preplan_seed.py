"""Offline GUG-395 pre-plan seed and certified downstream materializer.

This module breaks the GUG-376/GUG-393 post-plan dependency cycle without
constructing an AWS client or granting mutation authority.  It projects the
reviewed GUG-377 repository catalog into a new private pre-plan contract,
binds explicit owner decisions, and validates the terminal handoff required
to materialize the existing GUG-393 source bundle after the nine live phases.

The live mutation provider, durable executor, external verifier and every AWS
call remain deliberately outside this module.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from tooling import platform_authority_gug393_private_input_discovery as discovery
from tooling import platform_authority_change_set_retirement_package as broker_package
from tooling import platform_authority_retirement_ledger_factory_package as factory_package
from tooling import platform_authority_repository_source_verifier as source_verifier
from tooling import platform_authority_retirement_entrypoint_materializer as gug363
from tooling import (
    platform_authority_retirement_entrypoint_service_role_materializer as gug365,
)
from tooling.platform_authority_gug365_upstream_materializer import (
    build_repository_plan,
    validate_repository_plan,
)
from tooling.platform_authority_gug365_upstream_prerequisites import (
    PROVIDER_SLOT_ROUTES,
    SOURCE_CONTRACT_GAPS,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    CollectorError as CustodyError,
    private_target_absent as _custody_target_absent,
    read_private_json as _custody_read_private_json,
    write_private_json as _custody_write_private_json,
)


IMPLEMENTATION_ISSUE = "GUG-395"
PARENT_ISSUE = "GUG-376"
REGION = "us-east-1"
AUTHORITY_ACCOUNT_ID = "042360977644"
IDENTITY_CENTER_ACCOUNT_ID = "839393571433"
ARTIFACT_BUCKET_NAMESPACE = "account-regional"
EXPECTED_REMOTE_REF = "refs/remotes/origin/main"
SCHEMA_VERSION = 1

OWNER_INPUT_TYPE = (
    "scanalyze.platform_authority.gug395_preplan_owner_input.v1"
)
SEED_TYPE = "scanalyze.platform_authority.gug395_preplan_seed.v1"
PLAN_TYPE = "scanalyze.platform_authority.gug395_mutation_plan.v1"
TERMINAL_HANDOFF_TYPE = (
    "scanalyze.platform_authority.gug376_mutation_terminal_handoff.v2"
)
DOWNSTREAM_MANIFEST_TYPE = (
    "scanalyze.platform_authority.gug395_downstream_materialization.v2"
)
SEED_RECEIPT_TYPE = (
    "scanalyze.platform_authority.gug395_preplan_seed_receipt.v1"
)
DOWNSTREAM_RECEIPT_TYPE_V1 = (
    "scanalyze.platform_authority.gug395_downstream_materialization_receipt.v1"
)
DOWNSTREAM_RECEIPT_TYPE_V2 = (
    "scanalyze.platform_authority.gug395_downstream_materialization_receipt.v2"
)
DOWNSTREAM_RECEIPT_TYPE = DOWNSTREAM_RECEIPT_TYPE_V2

EVIDENCE_SCOPE = "REPOSITORY_OFFLINE_PREPLAN_ONLY"
TERMINAL_EVIDENCE_SCOPE = "LIVE_PROVIDER_ATTESTED_PRIVATE"
PRODUCTION_STATUS = "NO-GO"
REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_PRIVATE_JSON_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_INSTANCE_ARN = re.compile(
    r"^arn:aws:sso:::instance/(ssoins-[A-Za-z0-9.-]{16})$"
)
_STORE_ARN = re.compile(
    r"^arn:aws:identitystore:::identitystore/(d-[A-Za-z0-9]{10})$"
)
_USER_ID = re.compile(
    r"^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
    r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"
)
_PROVIDER_ARN = re.compile(
    r"^arn:aws:sso::aws:applicationProvider/[A-Za-z0-9/-]{1,256}$"
)
_KMS_ARN = re.compile(
    r"^arn:aws:kms:us-east-1:([0-9]{12}):key/"
    r"(?:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}|mrk-[0-9a-f]{32})$"
)
_KMS_MODES = {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}
_ARTIFACT_BUCKET = re.compile(
    r"^scanalyze-g376-art-[a-f0-9]{12}-"
    rf"{AUTHORITY_ACCOUNT_ID}-{REGION}-an$"
)
_AWS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+=,.@_-]{0,127}$")
_SIGNING_PROFILE_NAME = re.compile(r"^[A-Za-z0-9_]{2,64}$")
_ALIAS = re.compile(r"^alias/[A-Za-z0-9/_-]{2,250}$")
_OBJECT_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.=-]{2,511}/$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_FORBIDDEN_PUBLIC = re.compile(
    r"(?:arn:aws:|/Users/|/home/|AWSReservedSSO_|ssoins-|d-[A-Za-z0-9]{10})"
)
_STAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_IAM_PRINCIPAL_ARN = re.compile(
    r"^arn:aws:iam::([0-9]{12}):(root|role/[A-Za-z0-9+=,.@_/-]{1,512})$"
)
_OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.=-]{2,1023}$")

REQUIRED_DECISION_KEYS = (
    "artifact_bucket_name",
    "authority_account_id",
    "kms_alias_name",
    "kms_admin_principal_arn",
    "artifact_bucket_policy_principal_arn",
    "identity_center_application_name",
    "identity_center_redirect_uri",
    "identity_center_application_provider_arn",
    "identity_center_instance_arn",
    "identity_store_user_id",
    "authority_target_id",
    "classifier_permission_set_name",
    "approver_permission_set_name",
    "signing_profile_name",
    "broker_unsigned_object_key",
    "ledger_factory_unsigned_object_key",
)

OWNER_DECISION_KEYS = REQUIRED_DECISION_KEYS[:14]
DERIVED_BINDING_KEYS = REQUIRED_DECISION_KEYS[14:]

ARTIFACT_PACKAGES = ("broker", "ledger_factory")
SOURCE_BINDING_IMPLEMENTATION_PATHS = (
    "tooling/platform_authority_gug395_preplan_seed.py",
    "scripts/deployment/platform-authority-gug395-preplan-seed.py",
    "tooling/platform_authority_repository_source_verifier.py",
    "tooling/platform_authority_change_set_retirement_package.py",
    "tooling/platform_authority_retirement_ledger_factory_package.py",
    "tooling/platform_authority_gug376_authority_inventory_collector.py",
    "tooling/platform_authority_gug393_private_input_discovery.py",
    "tooling/platform_authority_retirement_entrypoint_materializer.py",
    "tooling/platform_authority_retirement_entrypoint_service_role_materializer.py",
)
BLOCKING_CODES = (
    "MISSING_PROVIDER_SLOT_ROUTES",
    "UPSTREAM_SOURCE_CONTRACT_GAPS",
    "CONNECTED_PREFLIGHT_REQUIRED",
    "LIVE_PROVIDER_NOT_IMPLEMENTED",
    "DURABLE_EXECUTOR_NOT_IMPLEMENTED",
)

# These bindings are source-owned.  Adding a key or attaching a decision to a
# different operation requires a reviewed code change; callers cannot invent
# opaque decision bindings at runtime.
OPERATION_OWNER_KEYS: dict[str, tuple[str, ...]] = {
    "CREATE_APPLICATION": (
        "identity_center_instance_arn",
        "identity_center_application_name",
        "identity_center_application_provider_arn",
        "identity_center_redirect_uri",
    ),
    "PUT_APPLICATION_GRANT": ("identity_center_redirect_uri",),
    "PUT_APPLICATION_ACCESS_SCOPE": ("identity_center_instance_arn",),
    "PUT_APPLICATION_ASSIGNMENT_CONFIG": (),
    "CREATE_APPLICATION_ASSIGNMENT": ("identity_store_user_id",),
    "CLASSIFIER_CREATE_PERMISSION_SET": (
        "identity_center_instance_arn",
        "classifier_permission_set_name",
    ),
    "APPROVER_CREATE_PERMISSION_SET": (
        "identity_center_instance_arn",
        "approver_permission_set_name",
    ),
    "CLASSIFIER_PUT_INLINE_POLICY": (
        "authority_account_id",
        "identity_center_instance_arn",
    ),
    "APPROVER_PUT_INLINE_POLICY": (
        "authority_account_id",
        "identity_center_instance_arn",
    ),
    "CLASSIFIER_CREATE_ACCOUNT_ASSIGNMENT": (
        "authority_target_id",
        "identity_center_instance_arn",
        "identity_store_user_id",
    ),
    "APPROVER_CREATE_ACCOUNT_ASSIGNMENT": (
        "authority_target_id",
        "identity_center_instance_arn",
        "identity_store_user_id",
    ),
    "CLASSIFIER_PROVISION_PERMISSION_SET": (
        "authority_target_id",
        "identity_center_instance_arn",
    ),
    "APPROVER_PROVISION_PERMISSION_SET": (
        "authority_target_id",
        "identity_center_instance_arn",
    ),
    "PUT_APPLICATION_AUTH_METHOD": (),
    "CREATE_KMS_KEY": ("authority_account_id", "kms_admin_principal_arn"),
    "ENABLE_KMS_KEY_ROTATION": (),
    "CREATE_KMS_ALIAS": ("kms_alias_name",),
    "CREATE_ARTIFACT_BUCKET": ("artifact_bucket_name",),
    "PUT_BUCKET_OWNERSHIP_CONTROLS": ("artifact_bucket_name",),
    "PUT_BUCKET_PUBLIC_ACCESS_BLOCK": ("artifact_bucket_name",),
    "PUT_BUCKET_VERSIONING": ("artifact_bucket_name",),
    "PUT_BUCKET_ENCRYPTION": ("artifact_bucket_name",),
    "PUT_BUCKET_POLICY": (
        "authority_account_id",
        "artifact_bucket_name",
        "artifact_bucket_policy_principal_arn",
    ),
    "PUT_BUCKET_TAGGING": ("artifact_bucket_name",),
    "PUT_SIGNING_PROFILE": ("signing_profile_name",),
    "CREATE_CODE_SIGNING_CONFIG": (),
    "BROKER_PUT_UNSIGNED_OBJECT": (
        "artifact_bucket_name",
        "broker_unsigned_object_key",
    ),
    "BROKER_START_SIGNING_JOB": (
        "authority_account_id",
        "artifact_bucket_name",
        "broker_unsigned_object_key",
        "signing_profile_name",
    ),
    "LEDGER_FACTORY_PUT_UNSIGNED_OBJECT": (
        "artifact_bucket_name",
        "ledger_factory_unsigned_object_key",
    ),
    "LEDGER_FACTORY_START_SIGNING_JOB": (
        "authority_account_id",
        "artifact_bucket_name",
        "ledger_factory_unsigned_object_key",
        "signing_profile_name",
    ),
}

OPERATION_ARTIFACT_BINDINGS = {
    "BROKER_PUT_UNSIGNED_OBJECT": ("broker",),
    "BROKER_START_SIGNING_JOB": ("broker",),
    "LEDGER_FACTORY_PUT_UNSIGNED_OBJECT": ("ledger_factory",),
    "LEDGER_FACTORY_START_SIGNING_JOB": ("ledger_factory",),
}

_VERIFIED_HANDOFF_SENTINEL = object()
_FRESH_CHECKPOINT_SENTINEL = object()
_VERIFIED_SOURCE_SENTINEL = object()


class PreplanSeedError(RuntimeError):
    """Stable fail-closed GUG-395 error without caller values."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "GUG395_INVALID"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise PreplanSeedError(code)


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PreplanSeedError("CANONICAL_JSON_INVALID") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _copy(value: Any, code: str) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (json.JSONDecodeError, PreplanSeedError) as exc:
        raise PreplanSeedError(code) from exc


def _json_ready(value: Any) -> Any:
    """Project closed Python catalog containers into canonical JSON values."""

    if isinstance(value, Mapping):
        return {
            str(key): _json_ready(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (set, frozenset)):
        return sorted((_json_ready(item) for item in value), key=canonical_json)
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _fail(code)
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _fail(code)
    return value


def _timestamp(value: object, code: str) -> str:
    if not isinstance(value, str) or _STAMP.fullmatch(value) is None:
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PreplanSeedError(code) from exc
    canonical = (
        parsed.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    if parsed.tzinfo is None or canonical != value:
        _fail(code)
    return canonical


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    if field in value:
        _fail("SELF_DIGEST_FIELD_PRESENT")
    value[field] = canonical_digest(value)
    return value


def _verify_self_digest(value: Mapping[str, Any], field: str, code: str) -> None:
    digest = _digest(value.get(field), code)
    if digest != canonical_digest({key: item for key, item in value.items() if key != field}):
        _fail(code)


def _require_keys(value: Mapping[str, Any], keys: set[str], code: str) -> None:
    if not isinstance(value, Mapping) or set(value) != keys:
        _fail(code)


def _validate_decision_value(key: str, value: object, decisions: Mapping[str, str]) -> None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        _fail("DECISION_VALUE_INVALID")
    if key in {"authority_account_id", "authority_target_id"}:
        if _ACCOUNT.fullmatch(value) is None:
            _fail("DECISION_ACCOUNT_INVALID")
    elif key == "identity_center_instance_arn":
        if _INSTANCE_ARN.fullmatch(value) is None:
            _fail("DECISION_INSTANCE_INVALID")
    elif key == "identity_store_user_id":
        if _USER_ID.fullmatch(value) is None:
            _fail("DECISION_USER_INVALID")
    elif key == "identity_center_application_provider_arn":
        if _PROVIDER_ARN.fullmatch(value) is None:
            _fail("DECISION_PROVIDER_INVALID")
    elif key == "identity_center_redirect_uri":
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            _fail("DECISION_REDIRECT_INVALID")
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or port is None
            or not 1024 <= port <= 65535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/callback"
        ):
            _fail("DECISION_REDIRECT_INVALID")
    elif key == "artifact_bucket_name":
        if _ARTIFACT_BUCKET.fullmatch(value) is None:
            _fail("DECISION_BUCKET_INVALID")
    elif key == "kms_alias_name":
        if (
            _ALIAS.fullmatch(value) is None
            or not value.startswith("alias/scanalyze-")
        ):
            _fail("DECISION_ALIAS_INVALID")
    elif key in {"kms_admin_principal_arn", "artifact_bucket_policy_principal_arn"}:
        match = _IAM_PRINCIPAL_ARN.fullmatch(value)
        if (
            match is None
            or match.group(1) != decisions.get("authority_account_id")
            or match.group(2) != "root"
        ):
            _fail("DECISION_PRINCIPAL_INVALID")
    elif key in {"broker_unsigned_object_key", "ledger_factory_unsigned_object_key"}:
        if (
            _OBJECT_KEY.fullmatch(value) is None
            or ".." in value
            or value.startswith("/")
            or not value.endswith(".zip")
        ):
            _fail("DECISION_OBJECT_KEY_INVALID")
    elif key == "identity_center_application_name":
        if _AWS_NAME.fullmatch(value) is None or len(value) > 100:
            _fail("DECISION_NAME_INVALID")
    elif key == "signing_profile_name":
        if _SIGNING_PROFILE_NAME.fullmatch(value) is None:
            _fail("DECISION_NAME_INVALID")
    elif key in {
        "classifier_permission_set_name",
        "approver_permission_set_name",
    }:
        if (
            _AWS_NAME.fullmatch(value) is None
            or (
                key == "classifier_permission_set_name"
                and value != "ScanalyzeAuthorityRetireClass"
            )
            or (
                key == "approver_permission_set_name"
                and value != "ScanalyzeAuthorityRetireApprove"
            )
        ):
            _fail("DECISION_NAME_INVALID")
    else:  # pragma: no cover - guarded by exact key set
        _fail("DECISION_KEY_INVALID")


def _expected_unsigned_object_keys(source_commit_sha: str) -> dict[str, str]:
    _sha(source_commit_sha, "SOURCE_BINDING_INVALID")
    return {
        "broker_unsigned_object_key": (
            "scanalyze/platform-authority/gug-215/unsigned/"
            f"{source_commit_sha}/{broker_package.ARCHIVE_NAME}"
        ),
        "ledger_factory_unsigned_object_key": (
            "scanalyze/platform-authority/gug-365/ledger-factory/unsigned/"
            f"{source_commit_sha}/{factory_package.ARCHIVE_NAME}"
        ),
    }


def _repository_catalog() -> dict[str, Any]:
    """Project the existing public repository catalog without promoting it."""

    source = build_repository_plan()
    validate_repository_plan(source)
    operations = [
        {
            key: operation[key]
            for key in (
                "global_sequence",
                "phase_sequence",
                "phase",
                "operation_id",
                "operation_kind",
                "action",
                "inventory_resource",
                "dependencies",
                "produced_slots",
                "consumed_slots",
                "polling_policy",
                "attempt_limit",
                "sdk_retry_count",
                "retry_permitted",
                "ambiguous_outcome",
                "result_projection_kind",
            )
        }
        for operation in source["operations"]
    ]
    phases = [
        {
            key: phase[key]
            for key in (
                "sequence",
                "phase",
                "inventory_target",
                "causal_predecessor",
                "operation_ids",
                "automatic_rollback",
            )
        }
        for phase in source["phases"]
    ]
    slots = [
        {
            key: slot[key]
            for key in (
                "slot",
                "producer_operation_kind",
                "consumer_operation_kinds",
                "derivation_kind",
                "value_storage",
            )
        }
        for slot in source["target_manifest"]["provider_slots"]
    ]
    slot_names = {item["slot"] for item in slots}
    routed_slots = sorted(slot_names & set(PROVIDER_SLOT_ROUTES))
    missing_route_slots = sorted(slot_names - set(PROVIDER_SLOT_ROUTES))
    if (
        len(operations) != 30
        or len(phases) != 9
        or len(slots) != 22
        or [item["global_sequence"] for item in operations] != list(range(1, 31))
        or [item["sequence"] for item in phases] != list(range(1, 10))
        or len(routed_slots) != 8
        or len(missing_route_slots) != 14
        or set(PROVIDER_SLOT_ROUTES) - slot_names
    ):
        _fail("REPOSITORY_CATALOG_INVALID")
    if set(OPERATION_OWNER_KEYS) != {item["operation_kind"] for item in operations}:
        _fail("OWNER_BINDING_CATALOG_INVALID")
    source_manifest = source["source_manifest"]
    source_digests = {
        str(item["repository_path"]): str(item["content_digest"])
        for section in ("contracts", "implementation_sources")
        for item in source_manifest[section]
    }
    return {
        "operations": operations,
        "phases": phases,
        "provider_slots": slots,
        "routed_provider_slots": routed_slots,
        "missing_provider_route_slots": missing_route_slots,
        "source_manifest_digest": source_manifest["source_manifest_digest"],
        "source_digests": source_digests,
        "operation_catalog_digest": canonical_digest(operations),
        "phase_catalog_digest": canonical_digest(phases),
        "provider_slot_catalog_digest": canonical_digest(slots),
        "provider_route_catalog_digest": canonical_digest(
            _json_ready(PROVIDER_SLOT_ROUTES)
        ),
        "source_contract_gap_catalog_digest": canonical_digest(
            list(SOURCE_CONTRACT_GAPS)
        ),
    }


def public_catalog_summary() -> dict[str, Any]:
    catalog = _repository_catalog()
    return {
        "record_type": "scanalyze.platform_authority.gug395_catalog_summary.v1",
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "phase_count": 9,
        "operation_count": 30,
        "provider_slot_count": 22,
        "routed_provider_slot_count": 8,
        "missing_provider_route_count": 14,
        "source_contract_gap_count": len(SOURCE_CONTRACT_GAPS),
        "live_execution_ready": False,
        "operation_catalog_digest": catalog["operation_catalog_digest"],
        "phase_catalog_digest": catalog["phase_catalog_digest"],
        "provider_slot_catalog_digest": catalog["provider_slot_catalog_digest"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }


def _raw_file_digest(relative_path: str) -> str:
    target = REPO_ROOT / relative_path
    try:
        if target.is_symlink() or not target.is_file():
            raise OSError
        payload = target.read_bytes()
    except OSError as exc:
        raise PreplanSeedError("SOURCE_FILE_UNAVAILABLE") from exc
    return "sha256:" + sha256(payload).hexdigest()


def _current_required_source_digests() -> dict[str, str]:
    catalog = _repository_catalog()
    result = dict(catalog["source_digests"])
    package_paths = {
        path.as_posix()
        for path in (*broker_package.SOURCE_PATHS, *factory_package.SOURCE_PATHS)
    }
    for relative in (*SOURCE_BINDING_IMPLEMENTATION_PATHS, *sorted(package_paths)):
        result[relative] = _raw_file_digest(relative)
    return dict(sorted(result.items()))


def _required_source_digests(owner_input: Mapping[str, Any]) -> dict[str, str]:
    result = _current_required_source_digests()
    artifact_inputs = owner_input.get("artifact_inputs")
    if not isinstance(artifact_inputs, list) or len(artifact_inputs) != 2:
        _fail("ARTIFACT_INPUTS_INVALID")
    for index, item in enumerate(artifact_inputs):
        if not isinstance(item, Mapping) or item.get("package") != ARTIFACT_PACKAGES[index]:
            _fail("ARTIFACT_INPUT_INVALID")
        manifest = item.get("package_manifest")
        if not isinstance(manifest, Mapping):
            _fail("ARTIFACT_PACKAGE_MANIFEST_INVALID")
        try:
            if item["package"] == "broker":
                broker_package.validate_retirement_package_manifest(manifest)
            else:
                factory_package.validate_ledger_factory_package_manifest(manifest)
        except (
            broker_package.RetirementPackageError,
            factory_package.LedgerFactoryPackageError,
        ) as exc:
            raise PreplanSeedError("ARTIFACT_PACKAGE_MANIFEST_INVALID") from exc
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            _fail("ARTIFACT_PACKAGE_MANIFEST_INVALID")
        for entry in entries:
            if not isinstance(entry, Mapping):
                _fail("ARTIFACT_PACKAGE_MANIFEST_INVALID")
            relative = entry.get("path")
            raw_digest = entry.get("sha256")
            if not isinstance(relative, str) or not isinstance(raw_digest, str):
                _fail("ARTIFACT_PACKAGE_MANIFEST_INVALID")
            digest = "sha256:" + raw_digest
            previous = result.get(relative)
            if previous is not None and previous != digest:
                _fail("SOURCE_DIGEST_CONFLICT")
            result[relative] = digest
    return dict(sorted(result.items()))


@dataclass(frozen=True, slots=True)
class VerifiedRepositorySource:
    """Opaque capability minted only by the clean remote-ref verifier."""

    _token: object
    _record: dict[str, Any]
    _repo_root: Path

    def __post_init__(self) -> None:
        if self._token is not _VERIFIED_SOURCE_SENTINEL:
            _fail("SOURCE_VERIFICATION_REQUIRED")
        _validate_source_verification_record(self._record)
        if not isinstance(self._repo_root, Path) or not self._repo_root.is_absolute():
            _fail("SOURCE_ROOT_INVALID")

    @property
    def record(self) -> dict[str, Any]:
        return _copy(self._record, "SOURCE_VERIFICATION_INVALID")

    def reverify(self) -> None:
        """Fail if HEAD/tree/ref/working bytes changed after capability minting."""

        try:
            observed = source_verifier.verify_clean_repository_source(
                repo_root=self._repo_root,
                expected_commit_sha=str(self._record["source_commit_sha"]),
                expected_tree_sha=str(self._record["source_tree_sha"]),
                expected_remote_ref=EXPECTED_REMOTE_REF,
                required_source_digests=_current_required_source_digests(),
            ).document
        except source_verifier.RepositorySourceVerificationError as exc:
            raise PreplanSeedError(exc.code) from exc
        if observed != self._record:
            _fail("SOURCE_REVERIFICATION_MISMATCH")


def _validate_source_verification_record(record: Mapping[str, Any]) -> None:
    required = {
        "record_type", "schema_version", "verifier_id", "expected_remote_ref",
        "source_commit_sha", "source_tree_sha", "remote_ref_commit_sha",
        "checkout_clean", "required_source_count", "required_source_set_digest",
        "repository_tree_entries_digest", "aws_calls", "aws_mutations",
        "verification_digest",
    }
    _require_keys(record, required, "SOURCE_VERIFICATION_FIELDS_INVALID")
    if (
        record.get("record_type") != source_verifier.RECORD_TYPE
        or record.get("schema_version") != 1
        or record.get("verifier_id") != source_verifier.VERIFIER_ID
        or record.get("expected_remote_ref") != EXPECTED_REMOTE_REF
        or record.get("remote_ref_commit_sha") != record.get("source_commit_sha")
        or record.get("checkout_clean") is not True
        or not isinstance(record.get("required_source_count"), int)
        or isinstance(record.get("required_source_count"), bool)
        or record["required_source_count"] < 1
        or record.get("aws_calls") != 0
        or record.get("aws_mutations") != 0
    ):
        _fail("SOURCE_VERIFICATION_INVALID")
    _sha(record.get("source_commit_sha"), "SOURCE_VERIFICATION_INVALID")
    _sha(record.get("source_tree_sha"), "SOURCE_VERIFICATION_INVALID")
    _digest(record.get("required_source_set_digest"), "SOURCE_VERIFICATION_INVALID")
    _digest(record.get("repository_tree_entries_digest"), "SOURCE_VERIFICATION_INVALID")
    _verify_self_digest(
        record, "verification_digest", "SOURCE_VERIFICATION_DIGEST_MISMATCH"
    )


def verify_repository_source_binding(
    *, owner_input: Mapping[str, Any], repo_root: Path
) -> VerifiedRepositorySource:
    """Mint a source capability only for clean exact fetched origin/main."""

    value = _copy(owner_input, "OWNER_INPUT_INVALID")
    if not isinstance(value, Mapping):
        _fail("OWNER_INPUT_INVALID")
    commit = _sha(value.get("source_commit_sha"), "SOURCE_BINDING_INVALID")
    tree = _sha(value.get("source_tree_sha"), "SOURCE_BINDING_INVALID")
    required = _required_source_digests(value)
    try:
        verified = source_verifier.verify_clean_repository_source(
            repo_root=Path(repo_root),
            expected_commit_sha=commit,
            expected_tree_sha=tree,
            expected_remote_ref=EXPECTED_REMOTE_REF,
            required_source_digests=required,
        ).document
    except source_verifier.RepositorySourceVerificationError as exc:
        raise PreplanSeedError(exc.code) from exc
    record = _copy(verified, "SOURCE_VERIFICATION_INVALID")
    _validate_source_verification_record(record)
    if (
        record["source_commit_sha"] != commit
        or record["source_tree_sha"] != tree
        or record["required_source_count"] != len(required)
        or record["required_source_set_digest"]
        != canonical_digest(
            [
                {"repository_path": path, "content_digest": digest}
                for path, digest in required.items()
            ]
        )
    ):
        _fail("SOURCE_VERIFICATION_MISMATCH")
    return VerifiedRepositorySource(
        _VERIFIED_SOURCE_SENTINEL, record, Path(repo_root)
    )


def reverify_seed_source_binding(
    *, seed: Mapping[str, Any], repo_root: Path
) -> VerifiedRepositorySource:
    """Re-prove one stored seed against the same clean origin/main bytes."""

    validate_preplan_seed(seed)
    try:
        verified = source_verifier.verify_clean_repository_source(
            repo_root=Path(repo_root),
            expected_commit_sha=str(seed["source_commit_sha"]),
            expected_tree_sha=str(seed["source_tree_sha"]),
            expected_remote_ref=EXPECTED_REMOTE_REF,
            required_source_digests=_current_required_source_digests(),
        ).document
    except source_verifier.RepositorySourceVerificationError as exc:
        raise PreplanSeedError(exc.code) from exc
    record = _copy(verified, "SOURCE_VERIFICATION_INVALID")
    _validate_source_verification_record(record)
    if (
        record["verification_digest"] != seed["source_verification_digest"]
        or record["repository_tree_entries_digest"]
        != seed["repository_tree_entries_digest"]
    ):
        _fail("SOURCE_REVERIFICATION_MISMATCH")
    return VerifiedRepositorySource(
        _VERIFIED_SOURCE_SENTINEL, record, Path(repo_root)
    )


def _normalize_artifact_inputs(
    value: object,
    *,
    decisions: Mapping[str, str],
    source_commit_sha: str,
    manifests_required: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        _fail("ARTIFACT_INPUTS_INVALID")
    raw_items = _copy(list(value), "ARTIFACT_INPUTS_INVALID")
    if len(raw_items) != 2:
        _fail("ARTIFACT_INPUTS_INVALID")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, Mapping):
            _fail("ARTIFACT_INPUT_INVALID")
        package = raw.get("package")
        if package != ARTIFACT_PACKAGES[index]:
            _fail("ARTIFACT_INPUT_INVALID")
        if manifests_required:
            _require_keys(
                raw,
                {"package", "package_manifest"},
                "ARTIFACT_INPUT_FIELDS_INVALID",
            )
            manifest = raw.get("package_manifest")
            if not isinstance(manifest, Mapping):
                _fail("ARTIFACT_INPUT_INVALID")
            try:
                if package == "broker":
                    broker_package.validate_retirement_package_manifest(manifest)
                else:
                    factory_package.validate_ledger_factory_package_manifest(
                        manifest
                    )
            except (
                broker_package.RetirementPackageError,
                factory_package.LedgerFactoryPackageError,
            ) as exc:
                raise PreplanSeedError("ARTIFACT_PACKAGE_MANIFEST_INVALID") from exc
            if manifest.get("source_commit") != source_commit_sha:
                _fail("ARTIFACT_PACKAGE_SOURCE_MISMATCH")
            summary = {
                "package": package,
                "archive_sha256": manifest.get("archive_sha256"),
                "lambda_code_sha256": manifest.get("lambda_code_sha256"),
                "manifest_digest": manifest.get("manifest_digest"),
                "archive_size_bytes": manifest.get("archive_size_bytes"),
            }
        else:
            _require_keys(
                raw,
                {
                    "package",
                    "archive_sha256",
                    "lambda_code_sha256",
                    "manifest_digest",
                    "archive_size_bytes",
                },
                "ARTIFACT_INPUT_FIELDS_INVALID",
            )
            summary = dict(raw)
        size = summary.get("archive_size_bytes")
        key = decisions.get(f"{package}_unsigned_object_key")
        archive_sha256 = summary.get("archive_sha256")
        lambda_code_sha256 = summary.get("lambda_code_sha256")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= MAX_PACKAGE_BYTES
            or not isinstance(key, str)
            or f"/{source_commit_sha}/" not in f"/{key}"
            or not isinstance(archive_sha256, str)
            or _HEX64.fullmatch(archive_sha256) is None
            or not isinstance(lambda_code_sha256, str)
        ):
            _fail("ARTIFACT_INPUT_INVALID")
        try:
            decoded = base64.b64decode(lambda_code_sha256, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PreplanSeedError("ARTIFACT_INPUT_DIGEST_INVALID") from exc
        if decoded.hex() != archive_sha256:
            _fail("ARTIFACT_INPUT_DIGEST_INVALID")
        _digest(summary.get("manifest_digest"), "ARTIFACT_INPUT_DIGEST_INVALID")
        item = dict(summary)
        item["artifact_input_digest"] = canonical_digest(item)
        result.append(item)
    if (
        result[0]["archive_sha256"] == result[1]["archive_sha256"]
        or result[0]["manifest_digest"] == result[1]["manifest_digest"]
    ):
        _fail("ARTIFACT_PACKAGE_SET_NOT_DISTINCT")
    return result


def build_preplan_seed(
    *,
    owner_input: Mapping[str, Any],
    private_custody_digest: str,
    verified_source: VerifiedRepositorySource,
) -> dict[str, Any]:
    """Build one private, zero-authority pre-plan seed."""

    value = _copy(owner_input, "OWNER_INPUT_INVALID")
    if not isinstance(value, Mapping):
        _fail("OWNER_INPUT_INVALID")
    _require_keys(
        value,
        {
            "record_type",
            "schema_version",
            "source_commit_sha",
            "source_tree_sha",
            "decisions",
            "artifact_inputs",
            "owner_input_digest",
        },
        "OWNER_INPUT_FIELDS_INVALID",
    )
    if value.get("record_type") != OWNER_INPUT_TYPE or value.get("schema_version") != 1:
        _fail("OWNER_INPUT_INVALID")
    _verify_self_digest(value, "owner_input_digest", "OWNER_INPUT_DIGEST_MISMATCH")
    source_commit = _sha(value.get("source_commit_sha"), "SOURCE_BINDING_INVALID")
    source_tree = _sha(value.get("source_tree_sha"), "SOURCE_BINDING_INVALID")
    if not isinstance(verified_source, VerifiedRepositorySource):
        _fail("SOURCE_VERIFICATION_REQUIRED")
    verified_source.reverify()
    source_verification = verified_source.record
    if (
        source_verification["source_commit_sha"] != source_commit
        or source_verification["source_tree_sha"] != source_tree
    ):
        _fail("SOURCE_VERIFICATION_MISMATCH")
    _digest(private_custody_digest, "PRIVATE_CUSTODY_DIGEST_INVALID")
    decisions = value.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != len(REQUIRED_DECISION_KEYS):
        _fail("DECISIONS_INVALID")
    compiled: list[dict[str, Any]] = []
    raw_values: dict[str, str] = {}
    for index, raw in enumerate(decisions):
        if not isinstance(raw, Mapping):
            _fail("DECISION_INVALID")
        _require_keys(
            raw,
            {"key", "value", "provenance", "impact", "rollback_boundary"},
            "DECISION_FIELDS_INVALID",
        )
        key = raw.get("key")
        if key != REQUIRED_DECISION_KEYS[index]:
            _fail("DECISION_ORDER_INVALID")
        provenance = raw.get("provenance")
        if not isinstance(provenance, Mapping):
            _fail("DECISION_PROVENANCE_INVALID")
        _require_keys(
            provenance,
            {"kind", "source_digest", "source_pointer"},
            "DECISION_PROVENANCE_FIELDS_INVALID",
        )
        expected_provenance_kind = (
            "REPOSITORY_SOURCE"
            if key in _expected_unsigned_object_keys(source_commit)
            else "OWNER_DECISION"
        )
        if (
            provenance.get("kind") != expected_provenance_kind
            or not isinstance(provenance.get("source_pointer"), str)
            or not provenance["source_pointer"].startswith("/")
            or not isinstance(raw.get("impact"), str)
            or not raw["impact"]
            or not isinstance(raw.get("rollback_boundary"), str)
            or not raw["rollback_boundary"]
        ):
            _fail("DECISION_INVALID")
        _digest(provenance.get("source_digest"), "DECISION_PROVENANCE_INVALID")
        raw_values[str(key)] = str(raw.get("value"))
        _validate_decision_value(str(key), raw.get("value"), raw_values)
        decision = {
            "key": key,
            "value": raw["value"],
            "value_digest": canonical_digest(raw["value"]),
            "provenance": dict(provenance),
            "impact": raw["impact"],
            "rollback_boundary": raw["rollback_boundary"],
        }
        decision["decision_digest"] = canonical_digest(decision)
        compiled.append(decision)
    if (
        raw_values["authority_target_id"] != raw_values["authority_account_id"]
        or raw_values["authority_account_id"] != AUTHORITY_ACCOUNT_ID
        or any(
            raw_values[key] != expected
            for key, expected in _expected_unsigned_object_keys(source_commit).items()
        )
    ):
        _fail("OWNER_VALUE_CROSS_BINDING_INVALID")
    artifact_inputs = _normalize_artifact_inputs(
        value["artifact_inputs"],
        decisions=raw_values,
        source_commit_sha=source_commit,
        manifests_required=True,
    )
    catalog = _repository_catalog()
    seed = {
        "record_type": SEED_TYPE,
        "schema_version": SCHEMA_VERSION,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "environment": "authority-non-production",
        "region": REGION,
        "evidence_scope": EVIDENCE_SCOPE,
        "source_commit_sha": source_commit,
        "source_tree_sha": source_tree,
        "source_verification_digest": source_verification[
            "verification_digest"
        ],
        "repository_tree_entries_digest": source_verification[
            "repository_tree_entries_digest"
        ],
        "source_manifest_digest": catalog["source_manifest_digest"],
        "operation_catalog_digest": catalog["operation_catalog_digest"],
        "phase_catalog_digest": catalog["phase_catalog_digest"],
        "provider_slot_catalog_digest": catalog["provider_slot_catalog_digest"],
        "provider_route_catalog_digest": catalog["provider_route_catalog_digest"],
        "source_contract_gap_catalog_digest": catalog[
            "source_contract_gap_catalog_digest"
        ],
        "source_contract_gap_count": len(SOURCE_CONTRACT_GAPS),
        "routed_provider_slot_count": len(catalog["routed_provider_slots"]),
        "missing_provider_route_count": len(catalog["missing_provider_route_slots"]),
        "private_custody_digest": private_custody_digest,
        "owner_input_digest": value["owner_input_digest"],
        "decisions": compiled,
        "owner_decision_count": len(OWNER_DECISION_KEYS),
        "derived_binding_count": len(DERIVED_BINDING_KEYS),
        "bound_value_count": len(compiled),
        "bound_values_digest": canonical_digest(compiled),
        "artifact_inputs": artifact_inputs,
        "artifact_input_digest": canonical_digest(artifact_inputs),
        "unsigned_package_set_digest": canonical_digest(artifact_inputs),
        "gug363_plan_required": False,
        "gug365_plan_required": False,
        "connected_preflight_required": True,
        "exact_live_plan_materialized": False,
        "live_execution_ready": False,
        "blocking_codes": list(BLOCKING_CODES),
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    _seal(seed, "seed_digest")
    validate_preplan_seed(seed)
    verified_source.reverify()
    return seed


def validate_preplan_seed(
    seed: Mapping[str, Any], *, expected_private_custody_digest: str | None = None
) -> None:
    value = _copy(seed, "SEED_INVALID")
    if not isinstance(value, Mapping):
        _fail("SEED_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "parent_issue",
        "environment", "region", "evidence_scope", "source_commit_sha",
        "source_tree_sha", "source_verification_digest",
        "repository_tree_entries_digest", "source_manifest_digest",
        "operation_catalog_digest",
        "phase_catalog_digest", "provider_slot_catalog_digest",
        "provider_route_catalog_digest", "source_contract_gap_catalog_digest",
        "source_contract_gap_count", "routed_provider_slot_count",
        "missing_provider_route_count", "private_custody_digest",
        "owner_input_digest", "decisions", "owner_decision_count",
        "derived_binding_count", "bound_value_count", "bound_values_digest",
        "artifact_inputs", "artifact_input_digest",
        "unsigned_package_set_digest", "gug363_plan_required",
        "gug365_plan_required", "connected_preflight_required",
        "exact_live_plan_materialized", "live_execution_ready", "blocking_codes", "aws_calls",
        "aws_mutations", "deployment_authorized", "production",
        "production_status", "two_human_status", "independent_approval_present",
        "seed_digest",
    }
    _require_keys(value, required, "SEED_FIELDS_INVALID")
    constants = {
        "record_type": SEED_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "environment": "authority-non-production",
        "region": REGION,
        "evidence_scope": EVIDENCE_SCOPE,
        "gug363_plan_required": False,
        "gug365_plan_required": False,
        "connected_preflight_required": True,
        "exact_live_plan_materialized": False,
        "live_execution_ready": False,
        "routed_provider_slot_count": 8,
        "missing_provider_route_count": 14,
        "source_contract_gap_count": len(SOURCE_CONTRACT_GAPS),
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("SEED_SCOPE_INVALID")
    _sha(value.get("source_commit_sha"), "SOURCE_BINDING_INVALID")
    _sha(value.get("source_tree_sha"), "SOURCE_BINDING_INVALID")
    for field in (
        "source_manifest_digest", "operation_catalog_digest", "phase_catalog_digest",
        "provider_slot_catalog_digest", "provider_route_catalog_digest",
        "source_contract_gap_catalog_digest",
        "source_verification_digest", "repository_tree_entries_digest",
        "private_custody_digest", "owner_input_digest", "bound_values_digest",
        "artifact_input_digest", "unsigned_package_set_digest",
    ):
        _digest(value.get(field), "SEED_DIGEST_INVALID")
    catalog = _repository_catalog()
    for field in (
        "source_manifest_digest", "operation_catalog_digest", "phase_catalog_digest",
        "provider_slot_catalog_digest", "provider_route_catalog_digest",
        "source_contract_gap_catalog_digest",
    ):
        if value[field] != catalog[field]:
            _fail("SEED_CATALOG_DRIFT")
    decisions = value.get("decisions")
    if (
        not isinstance(decisions, list)
        or value.get("owner_decision_count") != len(OWNER_DECISION_KEYS)
        or value.get("derived_binding_count") != len(DERIVED_BINDING_KEYS)
        or value.get("bound_value_count") != len(REQUIRED_DECISION_KEYS)
        or len(decisions) != len(REQUIRED_DECISION_KEYS)
        or [item.get("key") for item in decisions if isinstance(item, Mapping)]
        != list(REQUIRED_DECISION_KEYS)
    ):
        _fail("DECISIONS_INVALID")
    raw_values: dict[str, str] = {}
    for item in decisions:
        _require_keys(
            item,
            {"key", "value", "value_digest", "provenance", "impact", "rollback_boundary", "decision_digest"},
            "DECISION_FIELDS_INVALID",
        )
        key = str(item["key"])
        raw_values[key] = str(item["value"])
        _validate_decision_value(key, item["value"], raw_values)
        provenance = item.get("provenance")
        if not isinstance(provenance, Mapping):
            _fail("DECISION_PROVENANCE_INVALID")
        _require_keys(
            provenance,
            {"kind", "source_digest", "source_pointer"},
            "DECISION_PROVENANCE_FIELDS_INVALID",
        )
        expected_provenance_kind = (
            "REPOSITORY_SOURCE"
            if key
            in _expected_unsigned_object_keys(str(value["source_commit_sha"]))
            else "OWNER_DECISION"
        )
        if (
            provenance.get("kind") != expected_provenance_kind
            or not isinstance(provenance.get("source_pointer"), str)
            or not provenance["source_pointer"].startswith("/")
            or not isinstance(item.get("impact"), str)
            or not item["impact"]
            or not isinstance(item.get("rollback_boundary"), str)
            or not item["rollback_boundary"]
        ):
            _fail("DECISION_INVALID")
        _digest(provenance.get("source_digest"), "DECISION_PROVENANCE_INVALID")
        if item["value_digest"] != canonical_digest(item["value"]):
            _fail("DECISION_VALUE_DIGEST_MISMATCH")
        _verify_self_digest(item, "decision_digest", "DECISION_DIGEST_MISMATCH")
    if (
        raw_values["authority_target_id"] != raw_values["authority_account_id"]
        or raw_values["authority_account_id"] != AUTHORITY_ACCOUNT_ID
        or any(
            raw_values[key] != expected
            for key, expected in _expected_unsigned_object_keys(
                str(value["source_commit_sha"])
            ).items()
        )
    ):
        _fail("OWNER_VALUE_CROSS_BINDING_INVALID")
    if value["bound_values_digest"] != canonical_digest(decisions):
        _fail("OWNER_DECISIONS_DIGEST_MISMATCH")
    if value.get("blocking_codes") != list(BLOCKING_CODES):
        _fail("SEED_GAP_STATUS_INVALID")
    artifacts = value.get("artifact_inputs")
    expected_artifacts = _normalize_artifact_inputs(
        [
            {key: item[key] for key in item if key != "artifact_input_digest"}
            for item in artifacts
        ] if isinstance(artifacts, list) else artifacts,
        decisions=raw_values,
        source_commit_sha=str(value["source_commit_sha"]),
        manifests_required=False,
    )
    if (
        artifacts != expected_artifacts
        or value["artifact_input_digest"] != canonical_digest(artifacts)
        or value["unsigned_package_set_digest"] != canonical_digest(artifacts)
    ):
        _fail("ARTIFACT_INPUT_DIGEST_MISMATCH")
    if expected_private_custody_digest is not None:
        _digest(
            expected_private_custody_digest,
            "PRIVATE_CUSTODY_DIGEST_INVALID",
        )
        if value["private_custody_digest"] != expected_private_custody_digest:
            _fail("PRIVATE_CUSTODY_DIGEST_MISMATCH")
    _verify_self_digest(value, "seed_digest", "SEED_DIGEST_MISMATCH")


def _verify_seed_source_capability(
    *, seed: Mapping[str, Any], verified_source: VerifiedRepositorySource
) -> dict[str, Any]:
    """Reverify and bind one private seed to its exact source capability."""

    validate_preplan_seed(seed)
    if not isinstance(verified_source, VerifiedRepositorySource):
        _fail("SOURCE_VERIFICATION_REQUIRED")
    verified_source.reverify()
    source_verification = verified_source.record
    if (
        source_verification["source_commit_sha"] != seed["source_commit_sha"]
        or source_verification["source_tree_sha"] != seed["source_tree_sha"]
        or source_verification["verification_digest"]
        != seed["source_verification_digest"]
        or source_verification["repository_tree_entries_digest"]
        != seed["repository_tree_entries_digest"]
    ):
        _fail("SOURCE_VERIFICATION_MISMATCH")
    return source_verification


def build_preplan_seed_receipt(
    *,
    seed: Mapping[str, Any],
    verified_source: VerifiedRepositorySource,
    created_at: str,
) -> dict[str, Any]:
    """Project one private seed into its exact digest-only public receipt."""

    _verify_seed_source_capability(seed=seed, verified_source=verified_source)
    value = _copy(seed, "SEED_INVALID")
    receipt = {
        "record_type": SEED_RECEIPT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "discovery_issue": "GUG-393",
        "live_readonly_issue": "GUG-392",
        "downstream_consumer_issue": "GUG-365",
        "status": "PRIVATE_PREPLAN_SEED_MATERIALIZED",
        "evidence_scope": "OFFLINE_DIGEST_ONLY",
        "verified_source_capability_present": True,
        "source_commit_sha": value["source_commit_sha"],
        "source_tree_sha": value["source_tree_sha"],
        "source_verification_digest": value["source_verification_digest"],
        "repository_tree_entries_digest": value[
            "repository_tree_entries_digest"
        ],
        "source_manifest_digest": value["source_manifest_digest"],
        "bound_values_digest": value["bound_values_digest"],
        "operation_catalog_digest": value["operation_catalog_digest"],
        "phase_catalog_digest": value["phase_catalog_digest"],
        "provider_slot_catalog_digest": value["provider_slot_catalog_digest"],
        "unsigned_package_set_digest": value["unsigned_package_set_digest"],
        "private_seed_digest": value["seed_digest"],
        "owner_decision_count": len(OWNER_DECISION_KEYS),
        "derived_binding_count": len(DERIVED_BINDING_KEYS),
        "bound_value_count": len(REQUIRED_DECISION_KEYS),
        "phase_count": 9,
        "operation_count": 30,
        "provider_slot_count": 22,
        "missing_provider_route_count": 14,
        "routed_provider_slot_count": 8,
        "connected_preflight_required": True,
        "exact_live_plan_materialized": False,
        "live_execution_ready": False,
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
        "created_at": _timestamp(created_at, "SEED_RECEIPT_TIME_INVALID"),
    }
    _seal(receipt, "receipt_digest")
    validate_preplan_seed_receipt(
        receipt, seed=seed, verified_source=verified_source
    )
    return receipt


def validate_preplan_seed_receipt_shape(receipt: Mapping[str, Any]) -> None:
    """Validate public shape only; never attest private seed materialization."""

    value = _copy(receipt, "SEED_RECEIPT_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "parent_issue",
        "discovery_issue", "live_readonly_issue", "downstream_consumer_issue",
        "status", "evidence_scope", "verified_source_capability_present",
        "source_commit_sha", "source_tree_sha",
        "source_verification_digest", "repository_tree_entries_digest",
        "source_manifest_digest", "bound_values_digest",
        "operation_catalog_digest", "phase_catalog_digest",
        "provider_slot_catalog_digest", "unsigned_package_set_digest",
        "private_seed_digest", "owner_decision_count",
        "derived_binding_count", "bound_value_count", "phase_count",
        "operation_count", "provider_slot_count", "missing_provider_route_count",
        "routed_provider_slot_count", "connected_preflight_required",
        "exact_live_plan_materialized", "live_execution_ready", "read_only",
        "aws_calls", "aws_mutations", "deployment_authorized", "production",
        "two_human_status", "independent_approval_present", "production_status",
        "created_at", "receipt_digest",
    }
    _require_keys(value, required, "SEED_RECEIPT_FIELDS_INVALID")
    constants = {
        "record_type": SEED_RECEIPT_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "discovery_issue": "GUG-393",
        "live_readonly_issue": "GUG-392",
        "downstream_consumer_issue": "GUG-365",
        "owner_decision_count": len(OWNER_DECISION_KEYS),
        "derived_binding_count": len(DERIVED_BINDING_KEYS),
        "bound_value_count": len(REQUIRED_DECISION_KEYS),
        "phase_count": 9,
        "operation_count": 30,
        "provider_slot_count": 22,
        "missing_provider_route_count": 14,
        "routed_provider_slot_count": 8,
        "connected_preflight_required": True,
        "exact_live_plan_materialized": False,
        "live_execution_ready": False,
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("SEED_RECEIPT_SCOPE_INVALID")
    modes = {
        "SYNTHETIC_CONTRACT_ONLY_BLOCKED": (
            "SYNTHETIC_SCHEMA_EXAMPLE",
            False,
        ),
        "PRIVATE_PREPLAN_SEED_MATERIALIZED": (
            "OFFLINE_DIGEST_ONLY",
            True,
        ),
    }
    expected_mode = modes.get(value.get("status"))
    if expected_mode != (
        value.get("evidence_scope"),
        value.get("verified_source_capability_present"),
    ):
        _fail("SEED_RECEIPT_SCOPE_INVALID")
    _sha(value.get("source_commit_sha"), "SEED_RECEIPT_SOURCE_INVALID")
    _sha(value.get("source_tree_sha"), "SEED_RECEIPT_SOURCE_INVALID")
    for field in (
        "source_verification_digest", "repository_tree_entries_digest",
        "source_manifest_digest", "bound_values_digest",
        "operation_catalog_digest", "phase_catalog_digest",
        "provider_slot_catalog_digest", "unsigned_package_set_digest",
        "private_seed_digest",
    ):
        _digest(value.get(field), "SEED_RECEIPT_DIGEST_INVALID")
    _timestamp(value.get("created_at"), "SEED_RECEIPT_TIME_INVALID")
    _verify_self_digest(value, "receipt_digest", "SEED_RECEIPT_DIGEST_MISMATCH")
    _assert_public(value)


def validate_preplan_seed_receipt(
    receipt: Mapping[str, Any],
    *,
    seed: Mapping[str, Any] | None = None,
    verified_source: VerifiedRepositorySource | None = None,
) -> None:
    """Validate a materialized receipt only with its seed and source capability."""

    validate_preplan_seed_receipt_shape(receipt)
    value = _copy(receipt, "SEED_RECEIPT_INVALID")
    if not isinstance(verified_source, VerifiedRepositorySource):
        _fail("SOURCE_VERIFICATION_REQUIRED")
    if not isinstance(seed, Mapping):
        _fail("SEED_RECEIPT_SEED_REQUIRED")
    if value["status"] != "PRIVATE_PREPLAN_SEED_MATERIALIZED":
        _fail("SEED_RECEIPT_NOT_MATERIALIZED")
    _verify_seed_source_capability(seed=seed, verified_source=verified_source)
    bindings = {
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "source_verification_digest": seed["source_verification_digest"],
        "repository_tree_entries_digest": seed["repository_tree_entries_digest"],
        "source_manifest_digest": seed["source_manifest_digest"],
        "bound_values_digest": seed["bound_values_digest"],
        "operation_catalog_digest": seed["operation_catalog_digest"],
        "phase_catalog_digest": seed["phase_catalog_digest"],
        "provider_slot_catalog_digest": seed["provider_slot_catalog_digest"],
        "unsigned_package_set_digest": seed["unsigned_package_set_digest"],
        "private_seed_digest": seed["seed_digest"],
    }
    if any(value[key] != expected for key, expected in bindings.items()):
        _fail("SEED_RECEIPT_CAPABILITY_MISMATCH")


def _downstream_receipt_private_projection_v1(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct the immutable private-manifest binding used by receipt v1."""

    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_downstream_private_manifest_binding.v1"
        ),
        "source_commit_sha": value["source_commit_sha"],
        "source_tree_sha": value["source_tree_sha"],
        "preplan_seed_digest": value["preplan_seed_digest"],
        "terminal_verification_digest": value["terminal_verification_digest"],
        "mutation_plan_digest": value["mutation_plan_digest"],
        "terminal_handoff_digest": value["terminal_handoff_digest"],
        "execution_ledger_digest": value["execution_ledger_digest"],
        "phase_certification_digests": value["phase_certification_digests"],
        "operation_receipt_digests": value["operation_receipt_digests"],
        "provider_slot_binding_set_digest": value[
            "provider_slot_binding_set_digest"
        ],
        "broker_package_manifest_digest": value[
            "broker_package_manifest_digest"
        ],
        "broker_signing_contract_digest": value[
            "broker_signing_contract_digest"
        ],
        "ledger_factory_package_manifest_digest": value[
            "ledger_factory_package_manifest_digest"
        ],
        "ledger_factory_signing_contract_digest": value[
            "ledger_factory_signing_contract_digest"
        ],
        "gug363_intent_digest": value["gug363_intent_digest"],
        "gug363_plan_digest": value["gug363_plan_digest"],
    }


def validate_downstream_materialization_receipt_v1_shape(
    receipt: Mapping[str, Any],
) -> None:
    """Validate frozen v1 evidence without granting current execution authority."""

    value = _copy(receipt, "DOWNSTREAM_RECEIPT_INVALID")
    required = {
        "record_type",
        "schema_version",
        "implementation_issue",
        "parent_issue",
        "discovery_issue",
        "upstream_plan_issue",
        "downstream_consumer_issue",
        "status",
        "evidence_scope",
        "checkpoint_builder_status",
        "certified_terminal_capability_present",
        "source_commit_sha",
        "source_tree_sha",
        "preplan_seed_digest",
        "terminal_verification_digest",
        "mutation_plan_digest",
        "terminal_handoff_digest",
        "execution_ledger_digest",
        "phase_count",
        "operation_count",
        "phase_certification_digests",
        "operation_receipt_digests",
        "provider_slot_binding_set_digest",
        "broker_package_manifest_digest",
        "broker_signing_contract_digest",
        "ledger_factory_package_manifest_digest",
        "ledger_factory_signing_contract_digest",
        "gug363_intent_digest",
        "gug363_plan_digest",
        "gug365_plan_status",
        "gug365_plan_materialized",
        "consumer_fresh_checkpoint_required",
        "private_manifest_digest",
        "aws_calls",
        "aws_mutations",
        "deployment_authorized",
        "production",
        "two_human_status",
        "independent_approval_present",
        "production_status",
        "created_at",
        "receipt_digest",
    }
    _require_keys(value, required, "DOWNSTREAM_RECEIPT_FIELDS_INVALID")
    constants = {
        "record_type": DOWNSTREAM_RECEIPT_TYPE_V1,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "discovery_issue": "GUG-393",
        "upstream_plan_issue": "GUG-363",
        "downstream_consumer_issue": "GUG-365",
        "phase_count": 9,
        "operation_count": 30,
        "gug365_plan_status": "PENDING_FRESH_PROVIDER_CHECKPOINT",
        "gug365_plan_materialized": False,
        "consumer_fresh_checkpoint_required": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("DOWNSTREAM_RECEIPT_SCOPE_INVALID")
    modes = {
        "SYNTHETIC_CONTRACT_ONLY_BLOCKED": (
            "SYNTHETIC_SCHEMA_EXAMPLE",
            "BLOCKED_LIVE_EXECUTION_NOT_IMPLEMENTED",
            False,
        ),
        "READY_FOR_GUG365_FRESH_CHECKPOINT": (
            "CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
            "MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF",
            True,
        ),
    }
    expected_mode = modes.get(value.get("status"))
    if expected_mode != (
        value.get("evidence_scope"),
        value.get("checkpoint_builder_status"),
        value.get("certified_terminal_capability_present"),
    ):
        _fail("DOWNSTREAM_RECEIPT_SCOPE_INVALID")
    _sha(value.get("source_commit_sha"), "DOWNSTREAM_RECEIPT_SOURCE_INVALID")
    _sha(value.get("source_tree_sha"), "DOWNSTREAM_RECEIPT_SOURCE_INVALID")
    for field in required - set(constants) - {
        "source_commit_sha",
        "source_tree_sha",
        "created_at",
        "phase_certification_digests",
        "operation_receipt_digests",
        "receipt_digest",
    }:
        if field.endswith("_digest"):
            _digest(value.get(field), "DOWNSTREAM_RECEIPT_DIGEST_INVALID")
    for field, count in (
        ("phase_certification_digests", 9),
        ("operation_receipt_digests", 30),
    ):
        items = value.get(field)
        if (
            not isinstance(items, list)
            or len(items) != count
            or len(set(items)) != count
        ):
            _fail("DOWNSTREAM_RECEIPT_CHAIN_INVALID")
        for item in items:
            _digest(item, "DOWNSTREAM_RECEIPT_CHAIN_INVALID")
    if value["private_manifest_digest"] != canonical_digest(
        _downstream_receipt_private_projection_v1(value)
    ):
        _fail("DOWNSTREAM_RECEIPT_PRIVATE_MANIFEST_MISMATCH")
    _timestamp(value.get("created_at"), "DOWNSTREAM_RECEIPT_TIME_INVALID")
    _verify_self_digest(
        value, "receipt_digest", "DOWNSTREAM_RECEIPT_DIGEST_MISMATCH"
    )
    _assert_public(value)


def _downstream_receipt_private_projection(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_downstream_private_manifest_binding.v2"
        ),
        "source_commit_sha": value["source_commit_sha"],
        "source_tree_sha": value["source_tree_sha"],
        "preplan_seed_digest": value["preplan_seed_digest"],
        "terminal_verification_digest": value["terminal_verification_digest"],
        "mutation_plan_digest": value["mutation_plan_digest"],
        "terminal_handoff_digest": value["terminal_handoff_digest"],
        "execution_ledger_digest": value["execution_ledger_digest"],
        "phase_certification_digests": value["phase_certification_digests"],
        "operation_receipt_digests": value["operation_receipt_digests"],
        "provider_slot_binding_set_digest": value[
            "provider_slot_binding_set_digest"
        ],
        "identity_center_kms_binding_digest": value[
            "identity_center_kms_binding_digest"
        ],
        "broker_package_manifest_digest": value[
            "broker_package_manifest_digest"
        ],
        "broker_signing_contract_digest": value[
            "broker_signing_contract_digest"
        ],
        "ledger_factory_package_manifest_digest": value[
            "ledger_factory_package_manifest_digest"
        ],
        "ledger_factory_signing_contract_digest": value[
            "ledger_factory_signing_contract_digest"
        ],
        "gug363_intent_digest": value["gug363_intent_digest"],
        "gug363_plan_digest": value["gug363_plan_digest"],
    }


def validate_downstream_materialization_receipt_shape(
    receipt: Mapping[str, Any],
) -> None:
    """Validate schema/example shape only; never certify live readiness."""

    value = _copy(receipt, "DOWNSTREAM_RECEIPT_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "parent_issue",
        "discovery_issue", "upstream_plan_issue", "downstream_consumer_issue",
        "status", "evidence_scope", "checkpoint_builder_status",
        "certified_terminal_capability_present", "source_commit_sha",
        "source_tree_sha", "preplan_seed_digest", "terminal_verification_digest",
        "mutation_plan_digest", "terminal_handoff_digest",
        "execution_ledger_digest", "phase_count", "operation_count",
        "phase_certification_digests", "operation_receipt_digests",
        "provider_slot_binding_set_digest", "identity_center_kms_binding_digest",
        "broker_package_manifest_digest",
        "broker_signing_contract_digest",
        "ledger_factory_package_manifest_digest",
        "ledger_factory_signing_contract_digest", "gug363_intent_digest",
        "gug363_plan_digest", "gug365_plan_status",
        "gug365_plan_materialized", "consumer_fresh_checkpoint_required",
        "private_manifest_digest", "aws_calls", "aws_mutations",
        "deployment_authorized", "production", "two_human_status",
        "independent_approval_present", "production_status", "created_at",
        "receipt_digest",
    }
    _require_keys(value, required, "DOWNSTREAM_RECEIPT_FIELDS_INVALID")
    constants = {
        "record_type": DOWNSTREAM_RECEIPT_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "discovery_issue": "GUG-393",
        "upstream_plan_issue": "GUG-363",
        "downstream_consumer_issue": "GUG-365",
        "phase_count": 9,
        "operation_count": 30,
        "gug365_plan_status": "PENDING_FRESH_PROVIDER_CHECKPOINT",
        "gug365_plan_materialized": False,
        "consumer_fresh_checkpoint_required": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("DOWNSTREAM_RECEIPT_SCOPE_INVALID")
    modes = {
        "SYNTHETIC_CONTRACT_ONLY_BLOCKED": (
            "SYNTHETIC_SCHEMA_EXAMPLE",
            "BLOCKED_LIVE_EXECUTION_NOT_IMPLEMENTED",
            False,
        ),
        "READY_FOR_GUG365_FRESH_CHECKPOINT": (
            "CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
            "MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF",
            True,
        ),
    }
    expected_mode = modes.get(value.get("status"))
    if expected_mode != (
        value.get("evidence_scope"),
        value.get("checkpoint_builder_status"),
        value.get("certified_terminal_capability_present"),
    ):
        _fail("DOWNSTREAM_RECEIPT_SCOPE_INVALID")
    _sha(value.get("source_commit_sha"), "DOWNSTREAM_RECEIPT_SOURCE_INVALID")
    _sha(value.get("source_tree_sha"), "DOWNSTREAM_RECEIPT_SOURCE_INVALID")
    for field in required - set(constants) - {
        "source_commit_sha", "source_tree_sha", "created_at",
        "phase_certification_digests", "operation_receipt_digests",
        "receipt_digest",
    }:
        if field.endswith("_digest"):
            _digest(value.get(field), "DOWNSTREAM_RECEIPT_DIGEST_INVALID")
    for field, count in (
        ("phase_certification_digests", 9),
        ("operation_receipt_digests", 30),
    ):
        items = value.get(field)
        if (
            not isinstance(items, list)
            or len(items) != count
            or len(set(items)) != count
        ):
            _fail("DOWNSTREAM_RECEIPT_CHAIN_INVALID")
        for item in items:
            _digest(item, "DOWNSTREAM_RECEIPT_CHAIN_INVALID")
    if value["private_manifest_digest"] != canonical_digest(
        _downstream_receipt_private_projection(value)
    ):
        _fail("DOWNSTREAM_RECEIPT_PRIVATE_MANIFEST_MISMATCH")
    _timestamp(value.get("created_at"), "DOWNSTREAM_RECEIPT_TIME_INVALID")
    _verify_self_digest(
        value, "receipt_digest", "DOWNSTREAM_RECEIPT_DIGEST_MISMATCH"
    )
    _assert_public(value)


def validate_downstream_materialization_receipt(
    receipt: Mapping[str, Any],
    *,
    verified_handoff: VerifiedTerminalHandoff | None = None,
) -> None:
    """Validate READY authority only with the opaque terminal capability."""

    validate_downstream_materialization_receipt_shape(receipt)
    value = _copy(receipt, "DOWNSTREAM_RECEIPT_INVALID")
    if not isinstance(verified_handoff, VerifiedTerminalHandoff):
        _fail("TERMINAL_HANDOFF_VERIFICATION_REQUIRED")
    if value["status"] != "READY_FOR_GUG365_FRESH_CHECKPOINT":
        _fail("DOWNSTREAM_RECEIPT_NOT_CERTIFIED")
    handoff = verified_handoff.record
    phase_digests = [
        item["phase_certification_digest"]
        for item in handoff["phase_certifications"]
    ]
    operation_digests = [
        item["operation_receipt_digest"]
        for item in handoff["operation_receipts"]
    ]
    bindings = {
        "source_commit_sha": handoff["source_commit_sha"],
        "source_tree_sha": handoff["source_tree_sha"],
        "preplan_seed_digest": handoff["seed_digest"],
        "terminal_verification_digest": verified_handoff.verification_digest,
        "mutation_plan_digest": handoff["plan_digest"],
        "terminal_handoff_digest": handoff["handoff_digest"],
        "execution_ledger_digest": handoff["execution_ledger_digest"],
        "phase_certification_digests": phase_digests,
        "operation_receipt_digests": operation_digests,
        "provider_slot_binding_set_digest": handoff[
            "provider_slot_binding_set_digest"
        ],
        "identity_center_kms_binding_digest": handoff[
            "identity_center_kms_binding_digest"
        ],
        "broker_package_manifest_digest": handoff[
            "broker_package_manifest_digest"
        ],
        "broker_signing_contract_digest": handoff[
            "broker_signing_contract_digest"
        ],
        "ledger_factory_package_manifest_digest": handoff[
            "ledger_factory_package_manifest_digest"
        ],
        "ledger_factory_signing_contract_digest": handoff[
            "ledger_factory_signing_contract_digest"
        ],
        "gug363_intent_digest": handoff["gug363_intent_digest"],
        "gug363_plan_digest": handoff["gug363_plan_digest"],
    }
    if any(value[key] != expected for key, expected in bindings.items()):
        _fail("DOWNSTREAM_RECEIPT_CAPABILITY_MISMATCH")


def _decision_digest_map(seed: Mapping[str, Any]) -> dict[str, str]:
    return {item["key"]: item["decision_digest"] for item in seed["decisions"]}


def _compile_mutation_plan(seed: Mapping[str, Any]) -> dict[str, Any]:
    catalog = _repository_catalog()
    decision_digests = _decision_digest_map(seed)
    artifact_digests = {
        item["package"]: item["artifact_input_digest"]
        for item in seed["artifact_inputs"]
    }
    operations: list[dict[str, Any]] = []
    for source in catalog["operations"]:
        kind = source["operation_kind"]
        owner_keys = list(OPERATION_OWNER_KEYS[kind])
        packages = list(OPERATION_ARTIFACT_BINDINGS.get(kind, ()))
        referenced_slots = set(source["produced_slots"]) | set(
            source["consumed_slots"]
        )
        missing_routes = sorted(
            referenced_slots & set(catalog["missing_provider_route_slots"])
        )
        binding = {
            "global_sequence": source["global_sequence"],
            "phase_sequence": source["phase_sequence"],
            "phase": source["phase"],
            "operation_id": source["operation_id"],
            "operation_kind": kind,
            "action": source["action"],
            "inventory_resource": source["inventory_resource"],
            "dependencies": source["dependencies"],
            "produced_slots": source["produced_slots"],
            "consumed_slots": source["consumed_slots"],
            "polling_policy": source["polling_policy"],
            "attempt_limit": source["attempt_limit"],
            "sdk_retry_count": source["sdk_retry_count"],
            "retry_permitted": source["retry_permitted"],
            "ambiguous_outcome": source["ambiguous_outcome"],
            "result_projection_kind": source["result_projection_kind"],
            "owner_decision_keys": owner_keys,
            "owner_decision_digests": [decision_digests[key] for key in owner_keys],
            "artifact_packages": packages,
            "artifact_input_digests": [artifact_digests[key] for key in packages],
            "missing_provider_routes": missing_routes,
            "provider_route_status": (
                "BLOCKED_MISSING_ROUTE" if missing_routes else "ROUTED"
            ),
            "source_contract_status": (
                "BLOCKED_AUTH_METHOD_SOURCE_GAP"
                if kind == "PUT_APPLICATION_AUTH_METHOD"
                else "CATALOG_BOUND"
            ),
            "request_materialization_status": "BLOCKED_SOURCE_CONTRACT_GAPS",
        }
        binding["request_template_binding_digest"] = canonical_digest(binding)
        operations.append(binding)
    operation_by_id = {item["operation_id"]: item for item in operations}
    phases: list[dict[str, Any]] = []
    for source in catalog["phases"]:
        phase_operations = [operation_by_id[item] for item in source["operation_ids"]]
        phase = {
            **source,
            "operation_count": len(phase_operations),
            "operation_binding_digests": [
                item["request_template_binding_digest"] for item in phase_operations
            ],
            "request_materialization_status": "BLOCKED_SOURCE_CONTRACT_GAPS",
        }
        phase["phase_binding_digest"] = canonical_digest(phase)
        phases.append(phase)
    slots = [
        {
            **slot,
            "route_status": (
                "ROUTED"
                if slot["slot"] in catalog["routed_provider_slots"]
                else "MISSING_ROUTE"
            ),
        }
        for slot in catalog["provider_slots"]
    ]
    plan = {
        "record_type": PLAN_TYPE,
        "schema_version": 1,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "environment": "authority-non-production",
        "region": REGION,
        "evidence_scope": EVIDENCE_SCOPE,
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "seed_digest": seed["seed_digest"],
        "operation_catalog_digest": catalog["operation_catalog_digest"],
        "phase_catalog_digest": catalog["phase_catalog_digest"],
        "provider_slot_catalog_digest": catalog["provider_slot_catalog_digest"],
        "phase_count": len(phases),
        "operation_count": len(operations),
        "provider_slot_count": len(slots),
        "routed_provider_slot_count": len(catalog["routed_provider_slots"]),
        "missing_provider_route_count": len(
            catalog["missing_provider_route_slots"]
        ),
        "missing_provider_route_slots_digest": canonical_digest(
            catalog["missing_provider_route_slots"]
        ),
        "provider_route_catalog_digest": catalog["provider_route_catalog_digest"],
        "source_contract_gap_catalog_digest": catalog[
            "source_contract_gap_catalog_digest"
        ],
        "source_contract_gap_count": len(SOURCE_CONTRACT_GAPS),
        "phases": phases,
        "operations": operations,
        "provider_slots": slots,
        "blocking_codes": list(BLOCKING_CODES),
        "request_materialization_status": "BLOCKED_SOURCE_CONTRACT_GAPS",
        "exact_live_plan_materialized": False,
        "live_execution_ready": False,
        "live_provider_implemented": False,
        "durable_executor_implemented": False,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    _seal(plan, "plan_digest")
    return plan


def build_mutation_plan(*, seed: Mapping[str, Any]) -> dict[str, Any]:
    """Compile the exact pending 9-phase/30-operation private plan."""

    validate_preplan_seed(seed)
    plan = _compile_mutation_plan(_copy(seed, "SEED_INVALID"))
    validate_mutation_plan(plan, seed=seed)
    return plan


def validate_mutation_plan(plan: Mapping[str, Any], *, seed: Mapping[str, Any]) -> None:
    validate_preplan_seed(seed)
    value = _copy(plan, "PLAN_INVALID")
    expected = _compile_mutation_plan(_copy(seed, "SEED_INVALID"))
    if value != expected:
        _fail("PLAN_RECOMPILATION_MISMATCH")
    if (
        value.get("phase_count") != 9
        or value.get("operation_count") != 30
        or value.get("provider_slot_count") != 22
        or value.get("routed_provider_slot_count") != 8
        or value.get("missing_provider_route_count") != 14
        or value.get("live_execution_ready") is not False
        or value.get("exact_live_plan_materialized") is not False
        or value.get("request_materialization_status")
        != "BLOCKED_SOURCE_CONTRACT_GAPS"
        or [item["global_sequence"] for item in value["operations"]] != list(range(1, 31))
        or [item["sequence"] for item in value["phases"]] != list(range(1, 10))
        or any(item["attempt_limit"] != 1 for item in value["operations"])
        or any(item["sdk_retry_count"] != 0 for item in value["operations"])
        or any(item["retry_permitted"] is not False for item in value["operations"])
        or any(item["ambiguous_outcome"] != "UNCERTAIN_RECONCILE_ONLY" for item in value["operations"])
    ):
        _fail("PLAN_INVARIANT_INVALID")


def validate_terminal_handoff(
    handoff: Mapping[str, Any], *, seed: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    """Validate structure only; this does not mint provider attestation."""

    validate_preplan_seed(seed)
    validate_mutation_plan(plan, seed=seed)
    if plan.get("live_execution_ready") is not True:
        # GUG-395 deliberately freezes the causal contract before authority.
        # A successor must close all 14 routes, the authentication-method
        # source gap, the connected collision preflight and the durable
        # executor before this module can accept a terminal live handoff.
        _fail("STOP_LIVE_EXECUTION_PLAN_NOT_IMPLEMENTED")
    value = _copy(handoff, "TERMINAL_HANDOFF_INVALID")
    if not isinstance(value, Mapping):
        _fail("TERMINAL_HANDOFF_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "parent_issue",
        "environment", "region", "evidence_scope", "source_commit_sha",
        "source_tree_sha", "seed_digest", "plan_digest", "state",
        "provider_certification_complete", "phase_certifications",
        "operation_receipts", "phase_count", "operation_count",
        "provider_transcript_digest", "execution_ledger_digest",
        "artifact_readback_digest", "authority_targets_digest",
        "identity_center_private_targets_digest",
        "identity_center_application_name_digest",
        "identity_center_application_provider_arn_digest",
        "identity_center_kms_mode", "identity_center_kms_key_arn",
        "identity_center_kms_mode_digest", "identity_center_kms_key_arn_digest",
        "identity_center_kms_binding_digest", "external_verification_digest",
        "provider_slot_binding_set_digest", "broker_package_manifest_digest",
        "broker_signing_contract_digest",
        "ledger_factory_package_manifest_digest",
        "ledger_factory_signing_contract_digest", "gug363_intent_digest",
        "gug363_plan_digest", "downstream_checkpoint_binding_digest",
        "aws_calls", "aws_mutations", "consumer_fresh_checkpoint_required",
        "deployment_authorized", "production", "production_status",
        "two_human_status", "independent_approval_present", "handoff_digest",
    }
    _require_keys(value, required, "TERMINAL_HANDOFF_FIELDS_INVALID")
    constants = {
        "record_type": TERMINAL_HANDOFF_TYPE,
        "schema_version": 2,
        "implementation_issue": PARENT_ISSUE,
        "parent_issue": "GUG-365",
        "environment": "authority-non-production",
        "region": REGION,
        "evidence_scope": TERMINAL_EVIDENCE_SCOPE,
        "state": "TERMINAL_NINE_PHASES_CERTIFIED",
        "provider_certification_complete": True,
        "phase_count": 9,
        "operation_count": 30,
        "consumer_fresh_checkpoint_required": True,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("TERMINAL_HANDOFF_SCOPE_INVALID")
    if (
        value.get("source_commit_sha") != seed["source_commit_sha"]
        or value.get("source_tree_sha") != seed["source_tree_sha"]
        or value.get("seed_digest") != seed["seed_digest"]
        or value.get("plan_digest") != plan["plan_digest"]
    ):
        _fail("TERMINAL_HANDOFF_SOURCE_MISMATCH")
    decision_values = {
        item["key"]: item["value"] for item in seed["decisions"]
    }
    kms_binding = _validate_identity_selectors(
        decision_values["identity_center_application_name"],
        decision_values["identity_center_application_provider_arn"],
        decision_values["identity_center_instance_arn"],
        value.get("identity_center_kms_mode"),
        value.get("identity_center_kms_key_arn"),
    )
    if (
        value.get("identity_center_application_name_digest")
        != canonical_digest(decision_values["identity_center_application_name"])
        or value.get("identity_center_application_provider_arn_digest")
        != canonical_digest(
                decision_values["identity_center_application_provider_arn"]
            )
        or value.get("identity_center_kms_mode_digest")
        != canonical_digest(value.get("identity_center_kms_mode"))
        or value.get("identity_center_kms_key_arn_digest")
        != canonical_digest(value.get("identity_center_kms_key_arn"))
        or value.get("identity_center_kms_binding_digest")
        != canonical_digest(kms_binding)
    ):
        _fail("TERMINAL_HANDOFF_OWNER_BINDING_MISMATCH")
    for field in (
        "provider_transcript_digest", "execution_ledger_digest",
        "artifact_readback_digest", "authority_targets_digest",
        "identity_center_private_targets_digest",
        "identity_center_application_name_digest",
        "identity_center_application_provider_arn_digest",
        "identity_center_kms_mode_digest", "identity_center_kms_key_arn_digest",
        "identity_center_kms_binding_digest", "external_verification_digest",
        "provider_slot_binding_set_digest", "broker_package_manifest_digest",
        "broker_signing_contract_digest",
        "ledger_factory_package_manifest_digest",
        "ledger_factory_signing_contract_digest", "gug363_intent_digest",
        "gug363_plan_digest", "downstream_checkpoint_binding_digest",
    ):
        _digest(value.get(field), "TERMINAL_HANDOFF_DIGEST_INVALID")
    phase_records = value.get("phase_certifications")
    operation_records = value.get("operation_receipts")
    if not isinstance(phase_records, list) or not isinstance(operation_records, list):
        _fail("TERMINAL_HANDOFF_RECEIPTS_INVALID")
    expected_phases = plan["phases"]
    expected_operations = plan["operations"]
    if len(phase_records) != 9 or len(operation_records) != 30:
        _fail("TERMINAL_HANDOFF_RECEIPTS_INVALID")
    for expected, observed in zip(expected_phases, phase_records, strict=True):
        _require_keys(
            observed,
            {"sequence", "phase", "status", "phase_certification_digest"},
            "TERMINAL_PHASE_CERTIFICATION_INVALID",
        )
        if (
            observed.get("sequence") != expected["sequence"]
            or observed.get("phase") != expected["phase"]
            or observed.get("status") != "CERTIFIED"
        ):
            _fail("TERMINAL_PHASE_CERTIFICATION_INVALID")
        _digest(observed.get("phase_certification_digest"), "TERMINAL_PHASE_CERTIFICATION_INVALID")
    succeeded = 0
    for expected, observed in zip(expected_operations, operation_records, strict=True):
        _require_keys(
            observed,
            {"global_sequence", "operation_id", "status", "operation_receipt_digest"},
            "TERMINAL_OPERATION_RECEIPT_INVALID",
        )
        if (
            observed.get("global_sequence") != expected["global_sequence"]
            or observed.get("operation_id") != expected["operation_id"]
            or observed.get("status") not in {"SUCCEEDED", "EXACT_PRESENT_NO_TOUCH"}
        ):
            _fail("TERMINAL_OPERATION_RECEIPT_INVALID")
        _digest(observed.get("operation_receipt_digest"), "TERMINAL_OPERATION_RECEIPT_INVALID")
        succeeded += observed["status"] == "SUCCEEDED"
    phase_digests = [
        item["phase_certification_digest"] for item in phase_records
    ]
    operation_digests = [
        item["operation_receipt_digest"] for item in operation_records
    ]
    if len(set(phase_digests)) != 9 or len(set(operation_digests)) != 30:
        _fail("TERMINAL_HANDOFF_RECEIPT_CHAIN_INVALID")
    if (
        value["broker_package_manifest_digest"]
        != seed["artifact_inputs"][0]["manifest_digest"]
        or value["ledger_factory_package_manifest_digest"]
        != seed["artifact_inputs"][1]["manifest_digest"]
    ):
        _fail("TERMINAL_HANDOFF_PACKAGE_BINDING_MISMATCH")
    downstream_binding = {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_terminal_downstream_checkpoint_binding.v2"
        ),
        "source_commit_sha": value["source_commit_sha"],
        "source_tree_sha": value["source_tree_sha"],
        "seed_digest": value["seed_digest"],
        "plan_digest": value["plan_digest"],
        "provider_slot_binding_set_digest": value[
            "provider_slot_binding_set_digest"
        ],
        "identity_center_kms_binding_digest": value[
            "identity_center_kms_binding_digest"
        ],
        "phase_certification_digests": phase_digests,
        "operation_receipt_digests": operation_digests,
        "broker_package_manifest_digest": value[
            "broker_package_manifest_digest"
        ],
        "broker_signing_contract_digest": value[
            "broker_signing_contract_digest"
        ],
        "ledger_factory_package_manifest_digest": value[
            "ledger_factory_package_manifest_digest"
        ],
        "ledger_factory_signing_contract_digest": value[
            "ledger_factory_signing_contract_digest"
        ],
        "gug363_intent_digest": value["gug363_intent_digest"],
        "gug363_plan_digest": value["gug363_plan_digest"],
    }
    if value["downstream_checkpoint_binding_digest"] != canonical_digest(
        downstream_binding
    ):
        _fail("TERMINAL_HANDOFF_DOWNSTREAM_BINDING_MISMATCH")
    calls = value.get("aws_calls")
    mutations = value.get("aws_mutations")
    if (
        not isinstance(calls, int) or isinstance(calls, bool) or calls < 1
        or not isinstance(mutations, int) or isinstance(mutations, bool)
        or mutations != succeeded
        or not 0 <= mutations <= 30
        or calls < mutations
    ):
        _fail("TERMINAL_HANDOFF_CALL_COUNT_INVALID")
    _verify_self_digest(value, "handoff_digest", "TERMINAL_HANDOFF_DIGEST_MISMATCH")


@dataclass(frozen=True, slots=True)
class VerifiedTerminalHandoff:
    """Opaque future capability; GUG-395 deliberately exposes no minter."""

    _token: object
    _record: dict[str, Any]
    verification_digest: str

    def __post_init__(self) -> None:
        if self._token is not _VERIFIED_HANDOFF_SENTINEL:
            _fail("TERMINAL_HANDOFF_VERIFICATION_REQUIRED")
        record = _copy(self._record, "TERMINAL_HANDOFF_INVALID")
        if not isinstance(record, Mapping):
            _fail("TERMINAL_HANDOFF_INVALID")
        object.__setattr__(self, "_record", record)
        verification_digest = _digest(
            self.verification_digest,
            "TERMINAL_HANDOFF_VERIFICATION_INVALID",
        )
        if (
            _digest(
                record.get("external_verification_digest"),
                "TERMINAL_HANDOFF_VERIFICATION_INVALID",
            )
            != verification_digest
        ):
            _fail("TERMINAL_HANDOFF_VERIFICATION_MISMATCH")

    @property
    def record(self) -> dict[str, Any]:
        return _copy(self._record, "TERMINAL_HANDOFF_INVALID")


def build_downstream_checkpoint_receipt(
    *,
    seed: Mapping[str, Any],
    plan: Mapping[str, Any],
    verified_handoff: VerifiedTerminalHandoff,
    gug363_intent: Mapping[str, Any],
    gug363_plan: Mapping[str, Any],
    broker_package_manifest: Mapping[str, Any],
    broker_package_archive: bytes,
    ledger_factory_signing_contract: Mapping[str, Any],
    ledger_factory_package_archive: bytes,
    created_at: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Emit READY only from the future certified terminal capability."""

    validate_preplan_seed(seed)
    validate_mutation_plan(plan, seed=seed)
    if not isinstance(verified_handoff, VerifiedTerminalHandoff):
        _fail("TERMINAL_HANDOFF_VERIFICATION_REQUIRED")
    handoff = verified_handoff.record
    # This is the intentional v1 stop. A successor must first implement the
    # connected provider, routes, auth-method source, durable executor and
    # trusted terminal-capability minter. No code below grants that authority.
    validate_terminal_handoff(handoff, seed=seed, plan=plan)

    root = Path(repo_root)
    intent = _copy(gug363_intent, "GUG363_INTENT_INVALID")
    plan363 = _copy(gug363_plan, "GUG363_PLAN_INVALID")
    broker_manifest = _copy(
        broker_package_manifest, "BROKER_PACKAGE_MANIFEST_INVALID"
    )
    factory_contract = _copy(
        ledger_factory_signing_contract,
        "LEDGER_FACTORY_SIGNING_CONTRACT_INVALID",
    )
    if not isinstance(broker_package_archive, bytes) or not isinstance(
        ledger_factory_package_archive, bytes
    ):
        _fail("DOWNSTREAM_PACKAGE_ARCHIVE_INVALID")
    try:
        gug363.validate_materialization_intent(intent)
        broker_package.validate_retirement_package_manifest(
            broker_manifest, archive=broker_package_archive
        )
        rebuilt = gug363.build_materialization_plan(
            intent=intent,
            package_manifest=broker_manifest,
            package_archive=broker_package_archive,
            repo_root=root,
        )
        if plan363.get("function_configuration_state") == "CONFIGURED":
            rebuilt = gug363.finalize_materialization_plan(
                pre_function_plan=rebuilt,
                broker_function_evidence_digest=str(
                    plan363.get("broker_function_evidence_digest")
                ),
                function_configurator_checkpoint_digest=str(
                    plan363.get("function_configurator_checkpoint_digest")
                ),
                repo_root=root,
            )
        gug363.validate_materialization_plan(plan363, repo_root=root)
        if rebuilt != plan363:
            _fail("GUG363_PLAN_RECOMPILATION_MISMATCH")
        factory_manifest = factory_contract["package_manifest"]
        factory_package.validate_ledger_factory_package_manifest(
            factory_manifest, archive=ledger_factory_package_archive
        )
        factory_contract_digest = (
            gug365.ledger_factory_artifact_signing_contract_digest(
                factory_contract
            )
        )
        gug365.validate_ledger_factory_artifact_signing_contract(
            contract=factory_contract,
            expected_contract_digest=factory_contract_digest,
            gug363_plan=plan363,
            repo_root=root,
        )
    except PreplanSeedError:
        raise
    except (
        gug363.RetirementEntrypointMaterializationError,
        broker_package.RetirementPackageError,
        factory_package.LedgerFactoryPackageError,
        gug365.ServiceRoleMaterializationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise PreplanSeedError("DOWNSTREAM_CHECKPOINT_INPUT_INVALID") from exc

    source = plan363.get("source")
    broker_contract = plan363.get("artifact_signing_contract")
    if (
        not isinstance(source, Mapping)
        or source.get("commit") != seed["source_commit_sha"]
        or source.get("tree") != seed["source_tree_sha"]
        or not isinstance(broker_contract, Mapping)
        or broker_contract.get("unsigned_source", {}).get("manifest_digest")
        != broker_manifest.get("manifest_digest")
    ):
        _fail("DOWNSTREAM_CHECKPOINT_SOURCE_MISMATCH")
    summaries = []
    for package, manifest in (
        ("broker", broker_manifest),
        ("ledger_factory", factory_contract["package_manifest"]),
    ):
        summary = {
            "package": package,
            "archive_sha256": manifest["archive_sha256"],
            "lambda_code_sha256": manifest["lambda_code_sha256"],
            "manifest_digest": manifest["manifest_digest"],
            "archive_size_bytes": manifest["archive_size_bytes"],
        }
        summary["artifact_input_digest"] = canonical_digest(summary)
        summaries.append(summary)
    if summaries != seed["artifact_inputs"]:
        _fail("DOWNSTREAM_CHECKPOINT_PACKAGE_SEED_MISMATCH")

    broker_contract_digest = str(plan363["artifact_signing_contract_digest"])
    expected_terminal = {
        "identity_center_kms_binding_digest": handoff[
            "identity_center_kms_binding_digest"
        ],
        "broker_package_manifest_digest": broker_manifest["manifest_digest"],
        "broker_signing_contract_digest": broker_contract_digest,
        "ledger_factory_package_manifest_digest": factory_contract[
            "package_manifest"
        ]["manifest_digest"],
        "ledger_factory_signing_contract_digest": factory_contract_digest,
        "gug363_intent_digest": intent["intent_digest"],
        "gug363_plan_digest": plan363["plan_digest"],
    }
    if any(handoff[key] != expected for key, expected in expected_terminal.items()):
        _fail("DOWNSTREAM_CHECKPOINT_TERMINAL_BINDING_MISMATCH")

    phase_digests = [
        item["phase_certification_digest"]
        for item in handoff["phase_certifications"]
    ]
    operation_digests = [
        item["operation_receipt_digest"]
        for item in handoff["operation_receipts"]
    ]
    receipt: dict[str, Any] = {
        "record_type": DOWNSTREAM_RECEIPT_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "discovery_issue": "GUG-393",
        "upstream_plan_issue": "GUG-363",
        "downstream_consumer_issue": "GUG-365",
        "status": "READY_FOR_GUG365_FRESH_CHECKPOINT",
        "evidence_scope": "CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
        "checkpoint_builder_status": (
            "MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF"
        ),
        "certified_terminal_capability_present": True,
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "preplan_seed_digest": seed["seed_digest"],
        "terminal_verification_digest": verified_handoff.verification_digest,
        "mutation_plan_digest": plan["plan_digest"],
        "terminal_handoff_digest": handoff["handoff_digest"],
        "execution_ledger_digest": handoff["execution_ledger_digest"],
        "phase_count": 9,
        "operation_count": 30,
        "phase_certification_digests": phase_digests,
        "operation_receipt_digests": operation_digests,
        "provider_slot_binding_set_digest": handoff[
            "provider_slot_binding_set_digest"
        ],
        **expected_terminal,
        "gug365_plan_status": "PENDING_FRESH_PROVIDER_CHECKPOINT",
        "gug365_plan_materialized": False,
        "consumer_fresh_checkpoint_required": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production_status": PRODUCTION_STATUS,
        "created_at": _timestamp(
            created_at, "DOWNSTREAM_RECEIPT_TIME_INVALID"
        ),
    }
    receipt["private_manifest_digest"] = canonical_digest(
        _downstream_receipt_private_projection(receipt)
    )
    _seal(receipt, "receipt_digest")
    validate_downstream_materialization_receipt(
        receipt, verified_handoff=verified_handoff
    )
    return receipt


@dataclass(frozen=True, slots=True)
class VerifiedFreshGug365Checkpoint:
    """Opaque future capability; GUG-395 deliberately exposes no minter."""

    _token: object
    checkpoint_digest: str
    terminal_handoff_digest: str
    gug365_plan_digest: str
    downstream_checkpoint_receipt_digest: str
    downstream_checkpoint_private_manifest_digest: str
    source_commit_sha: str
    source_tree_sha: str
    authority_account_id_digest: str
    caller_identity_digest: str
    provider_evidence_digest: str
    inventory_digest: str
    verified_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if self._token is not _FRESH_CHECKPOINT_SENTINEL:
            _fail("GUG365_FRESH_CHECKPOINT_REQUIRED")
        for value in (
            self.checkpoint_digest,
            self.terminal_handoff_digest,
            self.gug365_plan_digest,
            self.downstream_checkpoint_receipt_digest,
            self.downstream_checkpoint_private_manifest_digest,
            self.authority_account_id_digest,
            self.caller_identity_digest,
            self.provider_evidence_digest,
            self.inventory_digest,
        ):
            _digest(value, "GUG365_FRESH_CHECKPOINT_INVALID")
        _sha(self.source_commit_sha, "GUG365_FRESH_CHECKPOINT_INVALID")
        _sha(self.source_tree_sha, "GUG365_FRESH_CHECKPOINT_INVALID")
        verified = datetime.fromisoformat(
            _timestamp(
                self.verified_at, "GUG365_FRESH_CHECKPOINT_INVALID"
            )[:-1]
            + "+00:00"
        )
        expires = datetime.fromisoformat(
            _timestamp(
                self.expires_at, "GUG365_FRESH_CHECKPOINT_INVALID"
            )[:-1]
            + "+00:00"
        )
        if not verified < expires or expires - verified > timedelta(minutes=15):
            _fail("GUG365_FRESH_CHECKPOINT_INVALID")


@dataclass(frozen=True, slots=True)
class DownstreamMaterialization:
    """Private source bundle plus its sanitized public manifest."""

    source_bundle: dict[str, Any]
    source_contract: dict[str, Any]
    public_manifest: dict[str, Any]


def _identity_center_kms_binding(
    *, instance_arn: object, mode: object, key_arn: object
) -> dict[str, Any]:
    if not isinstance(instance_arn, str) or _INSTANCE_ARN.fullmatch(instance_arn) is None:
        _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    if mode not in _KMS_MODES:
        _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    if mode == "AWS_OWNED_KMS_KEY":
        if key_arn is not None:
            _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    else:
        match = _KMS_ARN.fullmatch(str(key_arn))
        if match is None or match.group(1) != IDENTITY_CENTER_ACCOUNT_ID:
            _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    return {
        "binding_name": "identity_center_kms_key_arn",
        "identity_center_instance_arn": instance_arn,
        "mode": mode,
        "key_arn": key_arn,
    }


def _validate_identity_selectors(
    name: object,
    provider_arn: object,
    instance_arn: object,
    kms_mode: object,
    kms_arn: object,
) -> dict[str, Any]:
    if not isinstance(name, str) or _AWS_NAME.fullmatch(name) is None:
        _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    if not isinstance(provider_arn, str) or _PROVIDER_ARN.fullmatch(provider_arn) is None:
        _fail("DOWNSTREAM_IDENTITY_SELECTOR_INVALID")
    return _identity_center_kms_binding(
        instance_arn=instance_arn,
        mode=kms_mode,
        key_arn=kms_arn,
    )


def materialize_post_checkpoint_source_bundle(
    *,
    seed: Mapping[str, Any],
    plan: Mapping[str, Any],
    verified_handoff: VerifiedTerminalHandoff,
    downstream_checkpoint_receipt: Mapping[str, Any],
    fresh_gug365_checkpoint: VerifiedFreshGug365Checkpoint,
    gug363_plan: Mapping[str, Any],
    gug365_plan: Mapping[str, Any],
    identity_center_application_name: str,
    identity_center_application_provider_arn: str,
    identity_center_kms_mode: str,
    identity_center_kms_key_arn: str | None,
    materialized_at: str,
    repo_root: Path,
) -> DownstreamMaterialization:
    """Build the GUG-393 bundle only after the future fresh checkpoint."""

    validate_preplan_seed(seed)
    validate_mutation_plan(plan, seed=seed)
    if not isinstance(verified_handoff, VerifiedTerminalHandoff):
        _fail("TERMINAL_HANDOFF_VERIFICATION_REQUIRED")
    if not isinstance(fresh_gug365_checkpoint, VerifiedFreshGug365Checkpoint):
        _fail("GUG365_FRESH_CHECKPOINT_REQUIRED")
    checkpoint_receipt = _copy(
        downstream_checkpoint_receipt,
        "DOWNSTREAM_RECEIPT_INVALID",
    )
    validate_downstream_materialization_receipt(
        checkpoint_receipt,
        verified_handoff=verified_handoff,
    )
    observed_at = datetime.fromisoformat(
        _timestamp(materialized_at, "DOWNSTREAM_TIME_INVALID")[:-1] + "+00:00"
    )
    verified_at = datetime.fromisoformat(
        fresh_gug365_checkpoint.verified_at[:-1] + "+00:00"
    )
    expires_at = datetime.fromisoformat(
        fresh_gug365_checkpoint.expires_at[:-1] + "+00:00"
    )
    if not verified_at <= observed_at < expires_at:
        _fail("GUG365_FRESH_CHECKPOINT_EXPIRED")
    handoff = verified_handoff.record
    validate_terminal_handoff(handoff, seed=seed, plan=plan)
    checkpoint_bindings = {
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "preplan_seed_digest": seed["seed_digest"],
        "terminal_verification_digest": verified_handoff.verification_digest,
        "mutation_plan_digest": plan["plan_digest"],
        "terminal_handoff_digest": handoff["handoff_digest"],
    }
    if any(
        checkpoint_receipt[key] != expected
        for key, expected in checkpoint_bindings.items()
    ):
        _fail("DOWNSTREAM_CHECKPOINT_CAUSAL_BINDING_MISMATCH")
    identity_center_instance_arn = next(
        item["value"]
        for item in seed["decisions"]
        if item["key"] == "identity_center_instance_arn"
    )
    kms_binding = _validate_identity_selectors(
        identity_center_application_name,
        identity_center_application_provider_arn,
        identity_center_instance_arn,
        identity_center_kms_mode,
        identity_center_kms_key_arn,
    )
    if (
        canonical_digest(identity_center_application_name)
        != handoff["identity_center_application_name_digest"]
        or canonical_digest(identity_center_application_provider_arn)
        != handoff["identity_center_application_provider_arn_digest"]
        or identity_center_kms_mode != handoff["identity_center_kms_mode"]
        or identity_center_kms_key_arn != handoff["identity_center_kms_key_arn"]
        or canonical_digest(identity_center_kms_mode)
        != handoff["identity_center_kms_mode_digest"]
        or canonical_digest(identity_center_kms_key_arn)
        != handoff["identity_center_kms_key_arn_digest"]
        or canonical_digest(kms_binding)
        != handoff["identity_center_kms_binding_digest"]
    ):
        _fail("DOWNSTREAM_IDENTITY_SELECTOR_MISMATCH")
    root = Path(repo_root)
    plan363 = _copy(gug363_plan, "GUG363_PLAN_INVALID")
    plan365 = _copy(gug365_plan, "GUG365_PLAN_INVALID")
    if (
        fresh_gug365_checkpoint.terminal_handoff_digest
        != handoff["handoff_digest"]
        or fresh_gug365_checkpoint.gug365_plan_digest
        != plan365.get("plan_digest")
        or fresh_gug365_checkpoint.downstream_checkpoint_receipt_digest
        != checkpoint_receipt["receipt_digest"]
        or fresh_gug365_checkpoint.downstream_checkpoint_private_manifest_digest
        != checkpoint_receipt["private_manifest_digest"]
        or fresh_gug365_checkpoint.source_commit_sha
        != seed["source_commit_sha"]
        or fresh_gug365_checkpoint.source_tree_sha != seed["source_tree_sha"]
        or fresh_gug365_checkpoint.authority_account_id_digest
        != canonical_digest(
            next(
                item["value"]
                for item in seed["decisions"]
                if item["key"] == "authority_account_id"
            )
        )
    ):
        _fail("GUG365_FRESH_CHECKPOINT_MISMATCH")
    try:
        gug363.validate_materialization_plan(plan363, repo_root=root)
        factory_contract = plan365["ledger_factory_artifact_signing_contract"]
        factory_digest = plan365[
            "ledger_factory_artifact_signing_contract_digest"
        ]
        gug365.validate_service_role_materialization_plan(
            plan365,
            gug363_plan=plan363,
            expected_gug363_plan_digest=str(plan363["plan_digest"]),
            ledger_factory_artifact_signing_contract=factory_contract,
            expected_ledger_factory_artifact_signing_contract_digest=str(factory_digest),
            repo_root=root,
        )
    except Exception as exc:
        raise PreplanSeedError("DOWNSTREAM_PLAN_INVALID") from exc
    source = plan363.get("source")
    broker_contract = plan363.get("artifact_signing_contract")
    factory_contract = plan365.get(
        "ledger_factory_artifact_signing_contract"
    )
    if (
        not isinstance(source, Mapping)
        or source.get("commit") != seed["source_commit_sha"]
        or source.get("tree") != seed["source_tree_sha"]
        or not isinstance(broker_contract, Mapping)
        or not isinstance(factory_contract, Mapping)
    ):
        _fail("DOWNSTREAM_SOURCE_MISMATCH")
    broker_unsigned_source = broker_contract.get("unsigned_source")
    factory_package_manifest = factory_contract.get("package_manifest")
    exact_terminal_bindings = {
        "gug363_intent_digest": plan363.get("intent_digest"),
        "gug363_plan_digest": plan363.get("plan_digest"),
        "broker_package_manifest_digest": (
            broker_unsigned_source.get("manifest_digest")
            if isinstance(broker_unsigned_source, Mapping)
            else None
        ),
        "broker_signing_contract_digest": plan363.get(
            "artifact_signing_contract_digest"
        ),
        "ledger_factory_package_manifest_digest": (
            factory_package_manifest.get("manifest_digest")
            if isinstance(factory_package_manifest, Mapping)
            else None
        ),
        "ledger_factory_signing_contract_digest": plan365.get(
            "ledger_factory_artifact_signing_contract_digest"
        ),
    }
    if any(
        not isinstance(expected, str)
        or checkpoint_receipt[key] != expected
        or handoff[key] != expected
        for key, expected in exact_terminal_bindings.items()
    ):
        _fail("DOWNSTREAM_PLAN_TERMINAL_BINDING_MISMATCH")
    body = {
        "record_type": discovery.SOURCE_BUNDLE_TYPE,
        "schema_version": 2,
        "gug363_plan": plan363,
        "gug365_plan": plan365,
        "identity_center_application_name": identity_center_application_name,
        "identity_center_application_provider_arn": identity_center_application_provider_arn,
        "identity_center_kms_mode": identity_center_kms_mode,
        "identity_center_kms_key_arn": identity_center_kms_key_arn,
        "identity_center_kms_binding_digest": canonical_digest(kms_binding),
    }
    source_bundle = {**body, "source_bundle_digest": canonical_digest(body)}
    try:
        derived = discovery.derive_source_contract(
            source_bundle=source_bundle,
            source_commit_sha=str(seed["source_commit_sha"]),
            source_tree_sha=str(seed["source_tree_sha"]),
            repo_root=root,
        ).document
    except Exception as exc:
        raise PreplanSeedError("DOWNSTREAM_SOURCE_CONTRACT_INVALID") from exc
    if (
        canonical_digest(derived.get("authority_targets"))
        != handoff["authority_targets_digest"]
        or canonical_digest(derived.get("identity_center_private_targets"))
        != handoff["identity_center_private_targets_digest"]
    ):
        _fail("DOWNSTREAM_PROVIDER_BINDING_MISMATCH")
    manifest = {
        "record_type": DOWNSTREAM_MANIFEST_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "source_commit_sha": seed["source_commit_sha"],
        "source_tree_sha": seed["source_tree_sha"],
        "seed_digest": seed["seed_digest"],
        "plan_digest": plan["plan_digest"],
        "terminal_handoff_digest": handoff["handoff_digest"],
        "external_verification_digest": verified_handoff.verification_digest,
        "downstream_checkpoint_receipt_digest": checkpoint_receipt[
            "receipt_digest"
        ],
        "gug363_plan_digest": plan363["plan_digest"],
        "gug365_plan_digest": plan365["plan_digest"],
        "gug365_fresh_checkpoint_digest": (
            fresh_gug365_checkpoint.checkpoint_digest
        ),
        "gug365_provider_evidence_digest": (
            fresh_gug365_checkpoint.provider_evidence_digest
        ),
        "gug365_inventory_digest": fresh_gug365_checkpoint.inventory_digest,
        "gug365_caller_identity_digest": (
            fresh_gug365_checkpoint.caller_identity_digest
        ),
        "gug365_checkpoint_verified_at": fresh_gug365_checkpoint.verified_at,
        "gug365_checkpoint_expires_at": fresh_gug365_checkpoint.expires_at,
        "source_bundle_digest": source_bundle["source_bundle_digest"],
        "source_contract_digest": derived["source_contract_digest"],
        "identity_center_kms_binding_digest": handoff[
            "identity_center_kms_binding_digest"
        ],
        "private_payload_emitted": False,
        "gug365_fresh_checkpoint_satisfied": True,
        "gug393_fresh_discovery_required": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    _seal(manifest, "manifest_digest")
    validate_downstream_manifest(manifest)
    return DownstreamMaterialization(
        source_bundle=source_bundle,
        source_contract=derived,
        public_manifest=manifest,
    )


def _assert_public(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _FORBIDDEN_PUBLIC.search(key):
                _fail("PUBLIC_MANIFEST_SENSITIVE")
            _assert_public(item)
    elif isinstance(value, list):
        for item in value:
            _assert_public(item)
    elif isinstance(value, str) and (
        _FORBIDDEN_PUBLIC.search(value) or _ACCOUNT.fullmatch(value)
    ):
        _fail("PUBLIC_MANIFEST_SENSITIVE")


def validate_downstream_manifest(manifest: Mapping[str, Any]) -> None:
    value = _copy(manifest, "DOWNSTREAM_MANIFEST_INVALID")
    required = {
        "record_type", "schema_version", "implementation_issue", "parent_issue",
        "source_commit_sha", "source_tree_sha", "seed_digest", "plan_digest",
        "terminal_handoff_digest", "external_verification_digest",
        "downstream_checkpoint_receipt_digest",
        "gug363_plan_digest", "gug365_plan_digest",
        "gug365_fresh_checkpoint_digest", "gug365_provider_evidence_digest",
        "gug365_inventory_digest", "gug365_caller_identity_digest",
        "gug365_checkpoint_verified_at", "gug365_checkpoint_expires_at",
        "source_bundle_digest", "identity_center_kms_binding_digest",
        "source_contract_digest", "private_payload_emitted",
        "gug365_fresh_checkpoint_satisfied", "gug393_fresh_discovery_required",
        "aws_calls", "aws_mutations",
        "deployment_authorized", "production", "production_status",
        "two_human_status", "independent_approval_present", "manifest_digest",
    }
    _require_keys(value, required, "DOWNSTREAM_MANIFEST_FIELDS_INVALID")
    constants = {
        "record_type": DOWNSTREAM_MANIFEST_TYPE,
        "schema_version": 2,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "parent_issue": PARENT_ISSUE,
        "private_payload_emitted": False,
        "gug365_fresh_checkpoint_satisfied": True,
        "gug393_fresh_discovery_required": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production": False,
        "production_status": PRODUCTION_STATUS,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
    }
    if any(value.get(key) != expected for key, expected in constants.items()):
        _fail("DOWNSTREAM_MANIFEST_SCOPE_INVALID")
    _sha(value.get("source_commit_sha"), "DOWNSTREAM_SOURCE_INVALID")
    _sha(value.get("source_tree_sha"), "DOWNSTREAM_SOURCE_INVALID")
    verified_at = datetime.fromisoformat(
        _timestamp(
            value.get("gug365_checkpoint_verified_at"),
            "DOWNSTREAM_TIME_INVALID",
        )[:-1]
        + "+00:00"
    )
    expires_at = datetime.fromisoformat(
        _timestamp(
            value.get("gug365_checkpoint_expires_at"),
            "DOWNSTREAM_TIME_INVALID",
        )[:-1]
        + "+00:00"
    )
    if not verified_at < expires_at or expires_at - verified_at > timedelta(minutes=15):
        _fail("DOWNSTREAM_TIME_INVALID")
    for field in required - set(constants) - {"source_commit_sha", "source_tree_sha"}:
        if field.endswith("_digest"):
            _digest(value.get(field), "DOWNSTREAM_MANIFEST_DIGEST_INVALID")
    _verify_self_digest(value, "manifest_digest", "DOWNSTREAM_MANIFEST_DIGEST_MISMATCH")
    _assert_public(value)


def _private_root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _fail("PRIVATE_ROOT_INVALID")
    try:
        root = path.resolve(strict=True)
    except OSError as exc:
        raise PreplanSeedError("PRIVATE_ROOT_INVALID") from exc
    if root != path:
        _fail("PRIVATE_ROOT_INVALID")
    return root


def _private_name(value: object) -> str:
    if not isinstance(value, str) or _FILENAME.fullmatch(value) is None:
        _fail("PRIVATE_FILENAME_INVALID")
    return value


def read_private_json(*, private_root: Path, filename: str) -> dict[str, Any]:
    try:
        return _custody_read_private_json(
            Path(private_root), _private_name(filename)
        )
    except CustodyError as exc:
        raise PreplanSeedError(exc.code) from exc


def write_private_json_create_only(
    *, private_root: Path, filename: str, value: Mapping[str, Any]
) -> str:
    name = _private_name(filename)
    try:
        _custody_target_absent(Path(private_root), name)
        _custody_write_private_json(Path(private_root), name, value)
        if _custody_read_private_json(Path(private_root), name) != _copy(
            value, "PRIVATE_JSON_INVALID"
        ):
            _fail("PRIVATE_OUTPUT_READBACK_MISMATCH")
    except CustodyError as exc:
        raise PreplanSeedError(exc.code) from exc
    return canonical_digest(value)


def _public_result(*, status: str, record_digest: str) -> dict[str, Any]:
    _digest(record_digest, "PUBLIC_RESULT_DIGEST_INVALID")
    return {
        "status": status,
        "implementation_issue": IMPLEMENTATION_ISSUE,
        "record_digest": record_digest,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("catalog", help="Print the sanitized closed catalog summary")
    seed = subparsers.add_parser("seed", help="Create one private pre-plan seed")
    seed.add_argument("--repo-root", type=Path, required=True)
    seed.add_argument("--private-root", type=Path, required=True)
    seed.add_argument("--owner-input", required=True)
    seed.add_argument("--output", required=True)
    seed.add_argument("--created-at", required=True)
    plan = subparsers.add_parser("plan", help="Create one private pending mutation plan")
    plan.add_argument("--repo-root", type=Path, required=True)
    plan.add_argument("--private-root", type=Path, required=True)
    plan.add_argument("--seed", required=True)
    plan.add_argument("--output", required=True)
    check = subparsers.add_parser(
        "validate-terminal",
        help="Validate terminal structure without minting external attestation",
    )
    check.add_argument("--private-root", type=Path, required=True)
    check.add_argument("--repo-root", type=Path, required=True)
    check.add_argument("--seed", required=True)
    check.add_argument("--plan", required=True)
    check.add_argument("--handoff", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "catalog":
            result = public_catalog_summary()
        elif args.command == "seed":
            created_at = _timestamp(
                args.created_at, "SEED_RECEIPT_TIME_INVALID"
            )
            owner = read_private_json(
                private_root=args.private_root, filename=args.owner_input
            )
            verified_source = verify_repository_source_binding(
                owner_input=owner, repo_root=args.repo_root
            )
            custody_digest = canonical_digest(
                {"private_root": str(_private_root(args.private_root))}
            )
            record = build_preplan_seed(
                owner_input=owner,
                private_custody_digest=custody_digest,
                verified_source=verified_source,
            )
            result = build_preplan_seed_receipt(
                seed=record,
                verified_source=verified_source,
                created_at=created_at,
            )
            write_private_json_create_only(
                private_root=args.private_root, filename=args.output, value=record
            )
            persisted = read_private_json(
                private_root=args.private_root,
                filename=args.output,
            )
            if persisted != record:
                _fail("PRIVATE_OUTPUT_READBACK_MISMATCH")
            verified_source.reverify()
            validate_preplan_seed_receipt(
                result,
                seed=persisted,
                verified_source=verified_source,
            )
        elif args.command == "plan":
            seed = read_private_json(private_root=args.private_root, filename=args.seed)
            reverify_seed_source_binding(seed=seed, repo_root=args.repo_root)
            custody_digest = canonical_digest(
                {"private_root": str(_private_root(args.private_root))}
            )
            validate_preplan_seed(
                seed, expected_private_custody_digest=custody_digest
            )
            record = build_mutation_plan(seed=seed)
            write_private_json_create_only(
                private_root=args.private_root, filename=args.output, value=record
            )
            result = _public_result(status="OFFLINE_MUTATION_PLAN_CREATED", record_digest=record["plan_digest"])
        else:
            seed = read_private_json(private_root=args.private_root, filename=args.seed)
            reverify_seed_source_binding(seed=seed, repo_root=args.repo_root)
            custody_digest = canonical_digest(
                {"private_root": str(_private_root(args.private_root))}
            )
            validate_preplan_seed(
                seed, expected_private_custody_digest=custody_digest
            )
            plan = read_private_json(private_root=args.private_root, filename=args.plan)
            handoff = read_private_json(private_root=args.private_root, filename=args.handoff)
            validate_terminal_handoff(handoff, seed=seed, plan=plan)
            result = _public_result(status="EXTERNAL_ATTESTATION_REQUIRED", record_digest=handoff["handoff_digest"])
        _assert_public(result)
        print(canonical_json(result))
        return 0
    except PreplanSeedError as exc:
        print(canonical_json({"error": exc.code}), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
