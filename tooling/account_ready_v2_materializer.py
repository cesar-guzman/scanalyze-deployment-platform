"""Deterministic repository-only ACCOUNT_READY v2 materializer for GUG-379.

The materializer consumes three caller-supplied, closed documents:

* an approved deployment target v2;
* its independently retrieved registry anchor; and
* an exact bootstrap readback bound to that target.

It does not discover infrastructure, inspect environment variables, construct
an AWS client, or run a subprocess.  Successful output is therefore a
repository candidate only.  It is not evidence that any AWS resource exists
and it does not authorize deployment or production activity.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Mapping, Sequence

import jsonschema


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "schemas"
MAX_READBACK_AGE_SECONDS = 15 * 60

READBACK_RECORD_TYPE = "account_ready_v2_bootstrap_readback"
OPERATOR_MANIFEST_RECORD_TYPE = "account_ready_v2_operator_manifest"

ROLE_NAMES = {
    "plan": "ScanalyzeCustomer-Plan",
    "apply": "ScanalyzeCustomer-Apply",
    "identity_plan": "ScanalyzeCustomer-Identity-Plan",
    "identity_apply": "ScanalyzeCustomer-Identity-Apply",
    "promotion": "ScanalyzeCustomer-Promotion",
    "validation": "ScanalyzeCustomer-Validation",
    "diagnostic": "ScanalyzeCustomer-Diagnostic",
    "state_recovery": "ScanalyzeCustomer-StateRecovery",
}
ROLE_TAG_FIELDS = {
    "customer_id_tag": "customer_id",
    "deployment_id_tag": "deployment_id",
    "account_id_tag": "account_id",
    "region_tag": "region",
    "environment_tag": "environment",
}
STATE_INFRASTRUCTURE_FIELDS = frozenset(
    {
        "state_bucket",
        "evidence_bucket",
        "contracts_bucket",
        "state_kms_key",
        "evidence_kms_key",
        "contracts_kms_key",
    }
)
BUCKET_SUFFIXES = {
    "state_bucket": "tf-state",
    "evidence_bucket": "tf-evidence",
    "contracts_bucket": "contracts",
}
EXPECTED_CONTROLS = {
    "state_versioning_enabled": True,
    "state_default_encryption": "aws:kms",
    "state_bucket_key_enabled": True,
    "state_public_access_blocked": True,
    "state_object_lock_enabled": False,
    "native_lockfile_enabled": True,
}
READBACK_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "status",
        "observed_at",
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "baseline_version",
        "provisioned_at",
        "roles",
        "state_infrastructure",
        "controls",
        "readback_digest",
    }
)
DEPLOYMENT_TUPLE_FIELDS = (
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "environment",
)
ACCOUNT_READY_FIELDS = (
    "customer_id",
    "deployment_id",
    "account_id",
    "region",
    "environment",
    "baseline_version",
    "provisioned_at",
    "roles",
    "state_infrastructure",
    "controls",
)

_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ROLE_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):iam::"
    r"(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_-]+)$"
)
_S3_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):s3:::"
    r"(?P<name>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$"
)
_KMS_ARN = re.compile(
    r"^arn:(?P<partition>aws(?:-[a-z]+)*):kms:"
    r"(?P<region>[a-z0-9-]+):(?P<account>[0-9]{12}):"
    r"key/(?P<key>[A-Za-z0-9-]+)$"
)
_PLACEHOLDER_MARKERS = (
    "${",
    "{{",
    "}}",
    "<ACCOUNT",
    "<REGION",
    "PLACEHOLDER",
    "CHANGEME",
    "REPLACE_ME",
    "TODO",
    "TBD",
    "UNKNOWN",
)


class MaterializationError(ValueError):
    """Stable materialization failure that never includes caller data."""

    def __init__(self, code: str) -> None:
        self.code = code if _ERROR_CODE.fullmatch(code) else "MATERIALIZATION_DENIED"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class MaterializationResult:
    """Deterministic private contract and sanitized public manifest."""

    account_ready: dict[str, Any]
    operator_manifest: dict[str, Any]
    account_ready_bytes: bytes
    operator_manifest_bytes: bytes


@dataclass(frozen=True, slots=True)
class _Destination:
    parent: Path
    name: str
    parent_fd: int
    device: int
    inode: int


def _fail(code: str) -> None:
    raise MaterializationError(code)


def canonical_json_bytes(document: Mapping[str, Any]) -> bytes:
    """Return canonical UTF-8 JSON with one trailing newline."""

    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def canonical_digest(
    document: Mapping[str, Any],
    *,
    digest_field: str,
) -> str:
    """Return the SHA-256 digest of a document without its digest field."""

    body = {key: value for key, value in document.items() if key != digest_field}
    canonical = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def load_json_strict(path: Path, *, error_code: str) -> dict[str, Any]:
    """Load one non-symlink JSON object without exposing parse details."""

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            _fail(error_code)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            value = json.load(
                stream,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
            )
    except MaterializationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        _fail(error_code)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        _fail(error_code)
    return value


def _load_schema(name: str) -> dict[str, Any]:
    try:
        value = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail("SCHEMA_LOAD_FAILED")
    if not isinstance(value, dict):
        _fail("SCHEMA_LOAD_FAILED")
    return value


def _validate_schema(
    document: Mapping[str, Any],
    *,
    schema_name: str,
    error_code: str,
) -> None:
    schema = _load_schema(schema_name)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    if next(validator.iter_errors(document), None) is not None:
        _fail(error_code)


def _parse_timestamp(value: Any, *, error_code: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        _fail(error_code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        _fail(error_code)


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_placeholder(key) or _contains_placeholder(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_placeholder(item) for item in value)
    if not isinstance(value, str):
        return False
    upper = value.upper()
    if any(marker in upper for marker in _PLACEHOLDER_MARKERS):
        return True
    candidate = value.removeprefix("sha256:").replace("-", "")
    return len(candidate) >= 12 and set(candidate) == {"0"}


def _validate_target_and_anchor(
    target: dict[str, Any],
    anchor: dict[str, Any],
) -> None:
    if target.get("schema_version") != "2":
        _fail("TARGET_V2_REQUIRED")
    _validate_schema(
        target,
        schema_name="deployment-target.v2.schema.json",
        error_code="TARGET_SCHEMA_INVALID",
    )
    if target.get("record_digest") != canonical_digest(
        target,
        digest_field="record_digest",
    ):
        _fail("TARGET_DIGEST_MISMATCH")
    if target.get("status") != "READY":
        _fail("TARGET_NOT_READY")
    if target.get("environment") == "production":
        _fail("PRODUCTION_TARGET_DENIED")

    _validate_schema(
        anchor,
        schema_name="deployment-target-anchor.v1.schema.json",
        error_code="ANCHOR_SCHEMA_INVALID",
    )
    if anchor != {
        "schema_version": "1",
        "deployment_id": target["deployment_id"],
        "registry_version": target["registry_version"],
        "record_digest": target["record_digest"],
    }:
        _fail("ANCHOR_TARGET_MISMATCH")


def _validate_readback(
    readback: dict[str, Any],
    *,
    expected_tuple: Mapping[str, Any],
    evaluated_at: str,
) -> None:
    if set(readback) != READBACK_FIELDS:
        _fail("READBACK_SHAPE_INVALID")
    if (
        readback.get("schema_version") != "1"
        or readback.get("record_type") != READBACK_RECORD_TYPE
    ):
        _fail("READBACK_SCHEMA_INVALID")
    if readback.get("status") != "CLOSED":
        _fail("READBACK_NOT_CLOSED")
    claimed_digest = readback.get("readback_digest")
    if not isinstance(claimed_digest, str) or not _DIGEST.fullmatch(claimed_digest):
        _fail("READBACK_DIGEST_INVALID")
    if claimed_digest != canonical_digest(readback, digest_field="readback_digest"):
        _fail("READBACK_DIGEST_MISMATCH")

    observed = _parse_timestamp(
        readback.get("observed_at"),
        error_code="READBACK_TIME_INVALID",
    )
    evaluated = _parse_timestamp(
        evaluated_at,
        error_code="EVALUATION_TIME_INVALID",
    )
    provisioned = _parse_timestamp(
        readback.get("provisioned_at"),
        error_code="PROVISIONING_TIME_INVALID",
    )
    if observed > evaluated or provisioned > observed:
        _fail("READBACK_TIME_INCONSISTENT")
    if (evaluated - observed).total_seconds() > MAX_READBACK_AGE_SECONDS:
        _fail("READBACK_STALE")

    if set(expected_tuple) != set(DEPLOYMENT_TUPLE_FIELDS):
        _fail("EXPECTED_TUPLE_INVALID")
    for field in DEPLOYMENT_TUPLE_FIELDS:
        if readback.get(field) != expected_tuple.get(field):
            _fail("READBACK_BINDING_MISMATCH")


def _candidate_account_ready(readback: Mapping[str, Any]) -> dict[str, Any]:
    document = {
        "schema_version": "2",
        **{
            field: copy.deepcopy(readback[field])
            for field in ACCOUNT_READY_FIELDS
        },
    }
    document["contract_digest"] = canonical_digest(
        document,
        digest_field="contract_digest",
    )
    return document


def _validate_role_bindings(account_ready: Mapping[str, Any]) -> str:
    roles = account_ready.get("roles")
    if not isinstance(roles, Mapping) or set(roles) != set(ROLE_NAMES):
        _fail("ROLE_SET_INVALID")

    partitions: set[str] = set()
    arns: set[str] = set()
    for role_key, expected_name in ROLE_NAMES.items():
        role = roles.get(role_key)
        if not isinstance(role, Mapping):
            _fail("ROLE_BINDING_INVALID")
        arn = role.get("arn")
        if not isinstance(arn, str):
            _fail("ROLE_ARN_INVALID")
        match = _ROLE_ARN.fullmatch(arn)
        if (
            match is None
            or match.group("account") != account_ready["account_id"]
            or match.group("name") != expected_name
        ):
            _fail("ROLE_ARN_MISMATCH")
        for tag_field, binding_field in ROLE_TAG_FIELDS.items():
            if role.get(tag_field) != account_ready[binding_field]:
                _fail("ROLE_TAG_MISMATCH")
        partitions.add(match.group("partition"))
        arns.add(arn)

    if len(partitions) != 1 or len(arns) != len(ROLE_NAMES):
        _fail("ROLE_OWNERSHIP_AMBIGUOUS")
    return next(iter(partitions))


def _validate_state_ownership(
    account_ready: Mapping[str, Any],
    *,
    expected_partition: str,
) -> None:
    state = account_ready.get("state_infrastructure")
    if not isinstance(state, Mapping) or set(state) != STATE_INFRASTRUCTURE_FIELDS:
        _fail("STATE_BINDING_INVALID")

    bucket_values: set[str] = set()
    for field, suffix in BUCKET_SUFFIXES.items():
        value = state.get(field)
        match = _S3_ARN.fullmatch(value) if isinstance(value, str) else None
        expected_name = f"scanalyze-{account_ready['account_id']}-{suffix}"
        if (
            match is None
            or match.group("partition") != expected_partition
            or match.group("name") != expected_name
        ):
            _fail("BUCKET_BINDING_MISMATCH")
        bucket_values.add(value)
    if len(bucket_values) != 3:
        _fail("BUCKET_BINDING_AMBIGUOUS")

    kms_values: set[str] = set()
    for field in ("state_kms_key", "evidence_kms_key", "contracts_kms_key"):
        value = state.get(field)
        match = _KMS_ARN.fullmatch(value) if isinstance(value, str) else None
        if (
            match is None
            or match.group("partition") != expected_partition
            or match.group("account") != account_ready["account_id"]
            or match.group("region") != account_ready["region"]
        ):
            _fail("KMS_BINDING_MISMATCH")
        kms_values.add(value)
    if len(kms_values) != 3:
        _fail("KMS_BINDING_AMBIGUOUS")


def _validate_candidate(account_ready: dict[str, Any]) -> None:
    _validate_schema(
        account_ready,
        schema_name="account-ready.v2.schema.json",
        error_code="ACCOUNT_READY_SCHEMA_INVALID",
    )
    if account_ready.get("contract_digest") != canonical_digest(
        account_ready,
        digest_field="contract_digest",
    ):
        _fail("ACCOUNT_READY_DIGEST_MISMATCH")
    partition = _validate_role_bindings(account_ready)
    _validate_state_ownership(
        account_ready,
        expected_partition=partition,
    )
    if account_ready.get("controls") != EXPECTED_CONTROLS:
        _fail("CONTROL_BINDING_INVALID")


def _validate_target_bindings(
    account_ready: Mapping[str, Any],
    *,
    target: Mapping[str, Any],
) -> None:
    for field in DEPLOYMENT_TUPLE_FIELDS:
        if target.get(field) != account_ready.get(field):
            _fail("TARGET_ACCOUNT_READY_TUPLE_MISMATCH")

    state = account_ready["state_infrastructure"]
    if target.get("state_binding") != {
        "state_bucket": state["state_bucket"],
        "state_kms_key": state["state_kms_key"],
    }:
        _fail("TARGET_STATE_BINDING_MISMATCH")

    target_contract = target.get("account_ready")
    if not isinstance(target_contract, Mapping):
        _fail("TARGET_ACCOUNT_READY_BINDING_INVALID")
    if (
        target_contract.get("schema_version") != "2"
        or target_contract.get("baseline_version")
        != account_ready["baseline_version"]
        or target_contract.get("contract_digest")
        != account_ready["contract_digest"]
    ):
        _fail("TARGET_ACCOUNT_READY_BINDING_MISMATCH")


def build_account_ready_v2_candidate(
    *,
    bootstrap_readback: Mapping[str, Any],
    expected_tuple: Mapping[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    """Build and validate a candidate without requiring a finalized target.

    The bootstrap readback is bound only to the immutable deployment tuple.
    It deliberately contains no target digest, so the candidate digest can be
    computed before the finalized target and its independent anchor exist.
    """

    if not isinstance(bootstrap_readback, Mapping) or not isinstance(
        expected_tuple,
        Mapping,
    ):
        _fail("INPUT_DOCUMENT_INVALID")
    readback_copy = copy.deepcopy(dict(bootstrap_readback))
    tuple_copy = copy.deepcopy(dict(expected_tuple))
    if _contains_placeholder((readback_copy, tuple_copy)):
        _fail("PLACEHOLDER_INPUT_DENIED")
    _validate_readback(
        readback_copy,
        expected_tuple=tuple_copy,
        evaluated_at=evaluated_at,
    )
    candidate = _candidate_account_ready(readback_copy)
    _validate_candidate(candidate)
    return candidate


def bind_account_ready_v2_candidate(
    *,
    account_ready: Mapping[str, Any],
    target: Mapping[str, Any],
    anchor: Mapping[str, Any],
) -> None:
    """Bind a candidate to one finalized target and exact registry anchor."""

    if not all(
        isinstance(document, Mapping)
        for document in (account_ready, target, anchor)
    ):
        _fail("INPUT_DOCUMENT_INVALID")
    candidate_copy = copy.deepcopy(dict(account_ready))
    target_copy = copy.deepcopy(dict(target))
    anchor_copy = copy.deepcopy(dict(anchor))
    if _contains_placeholder((candidate_copy, target_copy, anchor_copy)):
        _fail("PLACEHOLDER_INPUT_DENIED")
    _validate_candidate(candidate_copy)
    _validate_target_and_anchor(target_copy, anchor_copy)
    _validate_target_bindings(candidate_copy, target=target_copy)


def _operator_manifest(
    *,
    account_ready: Mapping[str, Any],
    target: Mapping[str, Any],
    readback: Mapping[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": "1",
        "record_type": OPERATOR_MANIFEST_RECORD_TYPE,
        "status": "REPOSITORY_CANDIDATE",
        "live_evidence": "NOT_PROVEN_LIVE",
        "production_status": "NO_GO",
        "deployment_authorized": False,
        "aws_calls": 0,
        "aws_mutations": 0,
        "evaluated_at": evaluated_at,
        "contract_schema_version": "2",
        "contract_digest": account_ready["contract_digest"],
        "target_record_digest": target["record_digest"],
        "bootstrap_readback_digest": readback["readback_digest"],
        "binding_counts": {
            "terminal_roles": 8,
            "storage_bindings": 3,
            "encryption_bindings": 3,
            "state_controls": 6,
        },
        "deterministic": True,
        "independent_review_required": True,
    }
    manifest["manifest_digest"] = canonical_digest(
        manifest,
        digest_field="manifest_digest",
    )
    return manifest


def materialize_account_ready_v2(
    *,
    target: Mapping[str, Any],
    anchor: Mapping[str, Any],
    bootstrap_readback: Mapping[str, Any],
    evaluated_at: str,
) -> MaterializationResult:
    """Materialize one deterministic ACCOUNT_READY v2 repository candidate."""

    if not all(
        isinstance(document, Mapping)
        for document in (target, anchor, bootstrap_readback)
    ):
        _fail("INPUT_DOCUMENT_INVALID")

    target_copy = copy.deepcopy(dict(target))
    anchor_copy = copy.deepcopy(dict(anchor))
    readback_copy = copy.deepcopy(dict(bootstrap_readback))

    if _contains_placeholder((target_copy, anchor_copy, readback_copy)):
        _fail("PLACEHOLDER_INPUT_DENIED")

    expected_tuple = {
        field: copy.deepcopy(target_copy.get(field))
        for field in DEPLOYMENT_TUPLE_FIELDS
    }
    account_ready = build_account_ready_v2_candidate(
        bootstrap_readback=readback_copy,
        expected_tuple=expected_tuple,
        evaluated_at=evaluated_at,
    )
    bind_account_ready_v2_candidate(
        account_ready=account_ready,
        target=target_copy,
        anchor=anchor_copy,
    )
    operator_manifest = _operator_manifest(
        account_ready=account_ready,
        target=target_copy,
        readback=readback_copy,
        evaluated_at=evaluated_at,
    )
    return MaterializationResult(
        account_ready=account_ready,
        operator_manifest=operator_manifest,
        account_ready_bytes=canonical_json_bytes(account_ready),
        operator_manifest_bytes=canonical_json_bytes(operator_manifest),
    )


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _resolve_destination(path: Path) -> _Destination:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        _fail("OUTPUT_PATH_INVALID")
    try:
        parent = path.parent.resolve(strict=True)
        before_open = parent.stat(follow_symlinks=False)
    except OSError:
        _fail("OUTPUT_PARENT_INVALID")
    if not stat.S_ISDIR(before_open.st_mode):
        _fail("OUTPUT_PARENT_INVALID")
    destination = parent / path.name
    if _is_within(destination, REPO_ROOT.resolve()):
        _fail("OUTPUT_PATH_INSIDE_REPOSITORY")
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(parent, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (
            before_open.st_dev,
            before_open.st_ino,
        ):
            _fail("OUTPUT_PARENT_CHANGED")
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("OUTPUT_ALREADY_EXISTS")
        return _Destination(
            parent=parent,
            name=path.name,
            parent_fd=descriptor,
            device=opened.st_dev,
            inode=opened.st_ino,
        )
    except MaterializationError:
        if descriptor >= 0:
            _safe_close(descriptor)
        raise
    except OSError:
        if descriptor >= 0:
            _safe_close(descriptor)
        _fail("OUTPUT_PARENT_INVALID")


def _parent_unchanged(destination: _Destination) -> bool:
    try:
        current = destination.parent.stat(follow_symlinks=False)
        opened = os.fstat(destination.parent_fd)
    except OSError:
        return False
    identity = (destination.device, destination.inode)
    return (current.st_dev, current.st_ino) == identity and (
        opened.st_dev,
        opened.st_ino,
    ) == identity


def _safe_unlink_at(destination: _Destination, name: str) -> None:
    try:
        os.unlink(name, dir_fd=destination.parent_fd)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _create_temporary(destination: _Destination) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(32):
        name = f".{destination.name}.tmp-{secrets.token_hex(12)}"
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=destination.parent_fd,
            )
        except FileExistsError:
            continue
        return descriptor, name
    _fail("OUTPUT_WRITE_FAILED")


def write_materialization_outputs(
    result: MaterializationResult,
    *,
    account_ready_out: Path,
    operator_manifest_out: Path,
) -> None:
    """Create both outputs exclusively with mode 0600 or leave neither."""

    destinations: list[_Destination] = []
    staged: list[tuple[_Destination, str]] = []
    created: list[_Destination] = []
    try:
        private_destination = _resolve_destination(account_ready_out)
        destinations.append(private_destination)
        public_destination = _resolve_destination(operator_manifest_out)
        destinations.append(public_destination)
        if (
            private_destination.device,
            private_destination.inode,
            private_destination.name,
        ) == (
            public_destination.device,
            public_destination.inode,
            public_destination.name,
        ):
            _fail("OUTPUT_PATH_COLLISION")

        for destination, payload in (
            (private_destination, result.account_ready_bytes),
            (public_destination, result.operator_manifest_bytes),
        ):
            if not _parent_unchanged(destination):
                _fail("OUTPUT_PARENT_CHANGED")
            descriptor, temporary_name = _create_temporary(destination)
            staged.append((destination, temporary_name))
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = -1
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)

        for (temporary_destination, temporary_name), destination in zip(
            staged,
            (private_destination, public_destination),
            strict=True,
        ):
            if not _parent_unchanged(destination):
                _fail("OUTPUT_PARENT_CHANGED")
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=temporary_destination.parent_fd,
                dst_dir_fd=destination.parent_fd,
                follow_symlinks=False,
            )
            created.append(destination)
            if not _parent_unchanged(destination):
                _fail("OUTPUT_PARENT_CHANGED")

        for temporary_destination, temporary_name in staged:
            _safe_unlink_at(temporary_destination, temporary_name)
        staged.clear()
        if not all(_parent_unchanged(destination) for destination in destinations):
            _fail("OUTPUT_PARENT_CHANGED")
    except MaterializationError:
        for destination in created:
            _safe_unlink_at(destination, destination.name)
        for temporary_destination, temporary_name in staged:
            _safe_unlink_at(temporary_destination, temporary_name)
        raise
    except (OSError, ValueError):
        for destination in created:
            _safe_unlink_at(destination, destination.name)
        for temporary_destination, temporary_name in staged:
            _safe_unlink_at(temporary_destination, temporary_name)
        _fail("OUTPUT_WRITE_FAILED")
    finally:
        for destination in destinations:
            _safe_close(destination.parent_fd)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        _fail("CLI_ARGUMENT_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = _SanitizedArgumentParser(
        description="Materialize one repository-only ACCOUNT_READY v2 candidate."
    )
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--bootstrap-readback", type=Path, required=True)
    parser.add_argument("--evaluated-at", required=True)
    parser.add_argument("--account-ready-out", type=Path)
    parser.add_argument("--operator-manifest-out", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.dry_run:
            if (
                args.account_ready_out is not None
                or args.operator_manifest_out is not None
            ):
                _fail("DRY_RUN_OUTPUT_PATH_DENIED")
        elif args.account_ready_out is None or args.operator_manifest_out is None:
            _fail("OUTPUT_PATH_REQUIRED")

        result = materialize_account_ready_v2(
            target=load_json_strict(
                args.target,
                error_code="TARGET_INPUT_INVALID",
            ),
            anchor=load_json_strict(
                args.anchor,
                error_code="ANCHOR_INPUT_INVALID",
            ),
            bootstrap_readback=load_json_strict(
                args.bootstrap_readback,
                error_code="READBACK_INPUT_INVALID",
            ),
            evaluated_at=args.evaluated_at,
        )
        if args.dry_run:
            sys.stdout.buffer.write(result.operator_manifest_bytes)
        else:
            write_materialization_outputs(
                result,
                account_ready_out=args.account_ready_out,
                operator_manifest_out=args.operator_manifest_out,
            )
            print("PASS: ACCOUNT_READY_V2_REPOSITORY_CANDIDATE_WRITTEN")
    except MaterializationError as exc:
        print(f"DENY: {exc.code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
