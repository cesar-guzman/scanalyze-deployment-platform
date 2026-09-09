"""Offline review drafts for the shared reader and bootstrap Plan migration.

This module has no cloud provider, executor, credential discovery or approval
mechanism. Supplied baseline documents are unverified inputs, never attestations.
The existing connected snapshot and additive repair contracts remain unchanged.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from string import Template
from typing import Any, NoReturn
import unicodedata

from tooling import platform_authority_plan_permission_repair as repair


ROOT = Path(__file__).resolve().parents[1]
SUPPLEMENT_PATH = "policies/iam/platform-authority-plan-seed-management-read-supplement.json"
PLAN_PATH = "policies/iam/platform-authority-bootstrap-plan-role.json"
MAX_BYTES = 1_048_576
MAX_READ_WINDOW = timedelta(hours=1)
_ID = r"(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_FIELDS = {
    "schema_version", "management_account_id", "authority_account_id", "region",
    "identity_center_instance_arn", "identity_store_id", "reader_permission_set_arn",
    "plan_permission_set_arn", "target_user_id", "change_set_name", "not_before",
    "not_after", "target_plan_tags", "baseline",
}
_BASELINE_FIELDS = {
    "reader_inline_policy", "reader_provisioned_accounts", "reader_assignments_coverage",
    "reader_boundary_observation", "plan_inline_policy", "plan_role_inline_policy",
    "plan_tags", "plan_assignment", "plan_provisioned_accounts",
    "plan_boundary_observation",
}


class MigrationDraftError(ValueError):
    """Errors contain only stable codes, not private input or path values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise MigrationDraftError(code)


def _json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        _fail("JSON_INVALID")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode()).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _parse(payload: str) -> Any:
    try:
        return json.loads(payload, object_pairs_hook=_pairs,
                          parse_constant=lambda _: _fail("JSON_INVALID"))
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, MigrationDraftError):
            raise
        _fail("JSON_INVALID")


def _match(value: Any, pattern: str, code: str) -> str:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        _fail(code)
    return value


def _valid_tag_text(value: Any, minimum: int, maximum: int) -> bool:
    # Identity Center Tag pattern: Unicode letters, separators, numbers and
    # exactly _.:/=+-@. Do not trim or normalize supplied ownership evidence.
    return (isinstance(value, str) and minimum <= len(value) <= maximum
            and all(char in "_.:/=+-@" or unicodedata.category(char)[0] in "LZN"
                    for char in value))


def _tags(value: Any, *, required: bool) -> None:
    if not isinstance(value, dict) or len(value) > 50 or (required and not value):
        _fail("TAGS_INVALID")
    for key, item in value.items():
        if (not _valid_tag_text(key, 1, 128) or key.lower().startswith("aws:")
                or not _valid_tag_text(item, 0, 256)):
            _fail("TAGS_INVALID")


def _policy(value: Any, *, nullable: bool = False) -> dict[str, Any] | None:
    if nullable and value is None:
        return None
    if (not isinstance(value, dict) or value.get("Version") != "2012-10-17"
            or not set(value).issubset({"Version", "Id", "Statement"})):
        _fail("BASELINE_POLICY_INVALID")
    statements = value.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        _fail("BASELINE_POLICY_INVALID")
    sids = set()
    for statement in statements:
        if (not isinstance(statement, dict) or not isinstance(statement.get("Effect"), str)
                or statement["Effect"] not in {"Allow", "Deny"}
                or not set(statement).issubset({"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"})
                or ("Action" in statement) == ("NotAction" in statement)
                or ("Resource" in statement) == ("NotResource" in statement)
                or ("Condition" in statement and not isinstance(statement["Condition"], dict))):
            _fail("BASELINE_POLICY_INVALID")
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in statement:
                values = statement[key] if isinstance(statement[key], list) else [statement[key]]
                if not values or any(not isinstance(v, str) or not v for v in values):
                    _fail("BASELINE_POLICY_INVALID")
        if "Sid" in statement:
            sid = _match(statement["Sid"], r"[A-Za-z0-9]+", "BASELINE_POLICY_INVALID")
            if sid in sids:
                _fail("BASELINE_POLICY_INVALID")
            sids.add(sid)
    normalized = deepcopy(value)
    normalized["Statement"] = deepcopy(statements)
    return normalized


def _accounts(value: Any) -> None:
    if (not isinstance(value, list) or not value or len(value) > 10_000
            or any(not isinstance(v, str) or re.fullmatch(r"[0-9]{12}", v) is None for v in value)
            or len(set(value)) != len(value)):
        _fail("PROVISIONED_ACCOUNTS_INVALID")


def _validate(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != _FIELDS:
        _fail("INPUT_FIELDS_INVALID")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        _fail("INPUT_VERSION_INVALID")
    for field, expected in (("management_account_id", repair.MANAGEMENT_ACCOUNT_ID),
                            ("authority_account_id", repair.AUTHORITY_ACCOUNT_ID),
                            ("region", repair.REGION)):
        if request[field] != expected:
            _fail("ACCOUNT_OR_REGION_DRIFT")
    instance = _match(request["identity_center_instance_arn"],
                      r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}", "INSTANCE_INVALID")
    instance_id = instance.rsplit("/", 1)[1]
    for field in ("reader_permission_set_arn", "plan_permission_set_arn"):
        _match(request[field], rf"arn:aws:sso:::permissionSet/{instance_id}/ps-[A-Za-z0-9]{{16}}",
               "PERMISSION_SET_BINDING_INVALID")
    if request["reader_permission_set_arn"] == request["plan_permission_set_arn"]:
        _fail("PERMISSION_SET_BINDING_INVALID")
    _match(request["identity_store_id"], r"d-[a-z0-9]{10,32}", "IDENTITY_STORE_INVALID")
    _match(request["target_user_id"], _ID, "USER_INVALID")
    _match(request["change_set_name"], r"scanalyze-platform-authority-bootstrap-[0-9]{14}",
           "CHANGE_SET_NAME_INVALID")
    times = []
    for field in ("not_before", "not_after"):
        _match(request[field], r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
               "READ_WINDOW_INVALID")
        try:
            times.append(datetime.fromisoformat(request[field].replace("Z", "+00:00")))
        except ValueError:
            _fail("READ_WINDOW_INVALID")
    if not timedelta(0) < times[1] - times[0] <= MAX_READ_WINDOW:
        _fail("READ_WINDOW_INVALID")
    _tags(request["target_plan_tags"], required=True)
    baseline = request["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != _BASELINE_FIELDS:
        _fail("BASELINE_FIELDS_INVALID")
    _policy(baseline["reader_inline_policy"], nullable=True)
    _policy(baseline["plan_inline_policy"])
    _policy(baseline["plan_role_inline_policy"], nullable=True)
    _tags(baseline["plan_tags"], required=False)
    for field in ("reader_provisioned_accounts", "plan_provisioned_accounts"):
        _accounts(baseline[field])
    if (repair.MANAGEMENT_ACCOUNT_ID not in baseline["reader_provisioned_accounts"]
            or baseline["plan_provisioned_accounts"] != [repair.AUTHORITY_ACCOUNT_ID]):
        _fail("PROVISIONED_ACCOUNT_SCOPE_DRIFT")
    if baseline["reader_assignments_coverage"] not in ("COMPLETE", "NOT_COMPLETE"):
        _fail("COVERAGE_INVALID")
    for field in ("reader_boundary_observation", "plan_boundary_observation"):
        if baseline[field] not in ("ABSENT", "PRESENT", "NOT_OBSERVED"):
            _fail("BOUNDARY_OBSERVATION_INVALID")
    assignment = baseline["plan_assignment"]
    if (not isinstance(assignment, dict)
            or set(assignment) != {"account_id", "principal_type", "principal_id"}
            or assignment["account_id"] != repair.AUTHORITY_ACCOUNT_ID
            or assignment["principal_type"] != "GROUP"):
        _fail("GROUP_BASELINE_REQUIRED")
    _match(assignment["principal_id"], _ID, "GROUP_BASELINE_REQUIRED")
    if assignment["principal_id"] == request["target_user_id"]:
        _fail("PRINCIPAL_COLLISION")
    return deepcopy(request)


def _supplement(request: dict[str, Any], root: Path) -> dict[str, Any]:
    instance = request["identity_center_instance_arn"]
    values = {key: str(value) for key, value in request.items()}
    values.update({
        "identity_center_instance_id": instance.rsplit("/", 1)[1],
        "identity_store_arn": (f"arn:aws:identitystore::{repair.MANAGEMENT_ACCOUNT_ID}:"
                               f"identitystore/{request['identity_store_id']}"),
        "principal_user_arn": f"arn:aws:identitystore:::user/{request['target_user_id']}",
    })
    try:
        rendered = Template((root / SUPPLEMENT_PATH).read_text()).substitute(values)
        result = _parse(rendered)
    except (OSError, UnicodeError, KeyError, ValueError):
        _fail("SUPPLEMENT_SOURCE_INVALID")
    if "${" in rendered:
        _fail("SUPPLEMENT_SOURCE_INVALID")
    _policy(result)
    return result


def _merge(baseline: Any, supplement: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(baseline) if baseline is not None else {"Version": "2012-10-17", "Statement": []}
    before_sids = {s.get("Sid") for s in merged["Statement"]}
    if any(s.get("Sid") in before_sids for s in supplement["Statement"]):
        _fail("READER_STATEMENT_SID_COLLISION")
    merged["Statement"].extend(deepcopy(supplement["Statement"]))
    if len(_json(merged).encode()) > 32_768:
        _fail("READER_INLINE_POLICY_TOO_LARGE")
    return merged


def _statement_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    # Structural differences only, never a proof of effective privilege reduction.
    old = Counter(_digest(s) for s in before["Statement"])
    new = Counter(_digest(s) for s in after["Statement"])
    return {"removed_statement_digests": sorted((old - new).elements()),
            "added_statement_digests": sorted((new - old).elements()),
            "effective_authorization_evaluated": False}


def build_review_draft(request: Any, *, repo_root: Path = ROOT) -> dict[str, Any]:
    """Return private proposed documents; never create an executable intent."""
    supplied = _validate(request)
    # Normalize only the working view: input digest and rollback before-image
    # retain the exact supplied singleton/list representation.
    baseline = deepcopy(supplied["baseline"])
    for field in ("reader_inline_policy", "plan_inline_policy", "plan_role_inline_policy"):
        baseline[field] = _policy(baseline[field], nullable=field != "plan_inline_policy")
    supplement = _supplement(supplied, repo_root)
    try:
        target = repair.render_target_policy(supplied["change_set_name"], repo_root=repo_root)
        predecessor = repair.render_predecessor_policy(target)
        source_digests = {path: "sha256:" + hashlib.sha256((repo_root / path).read_bytes()).hexdigest()
                          for path in (SUPPLEMENT_PATH, PLAN_PATH)}
    except (OSError, repair.PlanPermissionRepairError):
        _fail("PLAN_SOURCE_INVALID")
    issues = ["FRESH_ATTESTED_BASELINE_REQUIRED", "EXPLICIT_MUTATION_APPROVAL_REQUIRED",
              "TARGET_USER_AND_OWNERSHIP_REVIEW_REQUIRED", "OLD_GROUP_SESSIONS_CLOSED_REQUIRED",
              "EFFECTIVE_AUTHORITY_AND_POLICY_SIZE_REVIEW_REQUIRED", "ROLLBACK_REVIEW_REQUIRED"]
    if baseline["reader_assignments_coverage"] != "COMPLETE":
        issues.append("READER_ASSIGNMENT_IMPACT_UNKNOWN")
    for name in ("reader", "plan"):
        if baseline[f"{name}_boundary_observation"] != "ABSENT":
            issues.append(f"{name.upper()}_BOUNDARY_REQUIRES_REVIEW")
    role_policy = baseline["plan_role_inline_policy"]
    if role_policy is None or _digest(role_policy) != _digest(baseline["plan_inline_policy"]):
        issues.append("PLAN_SSO_IAM_EQUALITY_NOT_ESTABLISHED")
    if any(s.get("Effect") == "Deny" for s in (baseline["reader_inline_policy"] or {}).get("Statement", [])):
        issues.append("EXISTING_READER_DENIES_PRESERVED_REQUIRE_EVALUATION")
    if supplied["target_plan_tags"] != baseline["plan_tags"]:
        issues.append("TAG_BASED_ADMIN_AUTHORITY_DELTA_REQUIRES_REVIEW")
    result = {
        "schema_version": 1,
        "record_type": "scanalyze.platform_authority.permission_plan_migration_draft.v1",
        "status": "DRAFT_REVIEW_ONLY",
        "source_status": "LOCAL_WORKING_COPY_NOT_ATTESTED",
        "source_material_digests": source_digests,
        "input_digest": _digest(supplied),
        "supplied_input": supplied,
        "baseline_verified": False,
        "admission_snapshot": False,
        "reader_provisioned_account_count": len(baseline["reader_provisioned_accounts"]),
        "reader_supplement_policy": supplement,
        "reader_proposed_inline_policy": _merge(baseline["reader_inline_policy"], supplement),
        "plan_proposed_predecessor_policy": predecessor,
        "plan_predecessor_digest": _digest(predecessor),
        "plan_later_repair_target_digest": _digest(target),
        "plan_policy_delta": _statement_delta(baseline["plan_inline_policy"], predecessor),
        "plan_proposed_assignment": {"account_id": repair.AUTHORITY_ACCOUNT_ID,
                                     "principal_type": "USER", "principal_id": supplied["target_user_id"]},
        "plan_proposed_tags": supplied["target_plan_tags"],
        "required_reviews": issues,
        "migration_outline": [
            {"stage": "VERIFY_BASELINE_AND_AUTHORIZE", "gate": "Fresh full dual-domain policies, role/trust/attachments/boundaries, metadata, accounts, assignments, no pending operations, approved targets, transition/session impact and rollback; stop on unknown or drift."},
            {"stage": "READER_SUPPLEMENT", "gate": "Review merged inline policy and all shared-account impacts; if separately authorized, update only the exact reader set and provision management only. Preserve attachments and assignments; retain baseline for bounded cleanup."},
            {"stage": "ADD_TARGET_USER", "gate": "Only after SSO/IAM equality and transition approval: create exact USER assignment while preserving GROUP; creation also provisions policy. Verify asynchronous success, both assignments, unchanged role ARN/trust and policy."},
            {"stage": "REMOVE_OLD_GROUP_ASSIGNMENT", "gate": "Only with verified USER remaining and explicit removal approval: remove the scoped GROUP assignment, not the group or its members; verify success and sole USER. Never pass through zero assignments."},
            {"stage": "CLOSE_OLD_GROUP_SESSIONS", "gate": "Separately reviewed session containment/expiry proof required before new permissions. Assignment removal, PT1H and the reader window do not revoke existing sessions."},
            {"stage": "MIGRATE_PLAN", "gate": "After all prior gates: separately approve tag-based administrator impact and complete policy replacement; preserve other metadata and attachments, provision authority only, verify success and complete dual-domain readback. No ALL_PROVISIONED_ACCOUNTS."},
            {"stage": "ORIGINAL_ADMISSION", "gate": "Run the unchanged connected snapshot with its exact read-only profiles; then use the existing protected additive repair. This draft is not accepted evidence and grants no execution or production authority."},
        ],
        "rollback": {"automatic": False, "before_image": "supplied_input.baseline",
                     "gate": "Refresh and compare against the approved after-image; stop on drift. Review restoration and provisioning targets, remaining assignments and active sessions. Expiry of the additive Allow does not remove policy JSON or prove global denial. Never directly edit an AWSReservedSSO role."},
        "aws_calls": 0, "aws_mutations": 0, "execution_authorized": False,
        "deployment_authorized": False, "production_status": "NO-GO",
    }
    result["draft_digest"] = _digest(result)
    return result


def public_summary(draft: dict[str, Any]) -> dict[str, Any]:
    """Only non-private status and digests may be printed by the CLI."""
    return {key: draft[key] for key in (
        "status", "draft_digest", "reader_provisioned_account_count", "required_reviews",
        "aws_calls", "aws_mutations", "execution_authorized", "deployment_authorized", "production_status")}


def _directory(path: Path) -> int:
    try:
        if (not path.is_absolute() or path.suffix != ".json" or ".." in path.parts
                or any(p.is_symlink() for p in (path, *path.parents))
                or any(p.name.casefold() in {"cloudstorage", "mobile documents"}
                       or p.name.casefold().startswith(("onedrive", "dropbox", "googledrive"))
                       for p in path.parents)
                or any((p / ".git").exists() for p in path.parents)):
            _fail("PRIVATE_PATH_INVALID")
    except (OSError, ValueError):
        _fail("PRIVATE_PATH_INVALID")
    try:
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            _fail("PRIVATE_DIRECTORY_INVALID")
        return fd
    except (OSError, ValueError):
        _fail("PRIVATE_DIRECTORY_INVALID")


def read_private_input(path: Path) -> dict[str, Any]:
    root_fd = _directory(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > MAX_BYTES):
                _fail("PRIVATE_INPUT_INVALID")
            payload = stream.read(MAX_BYTES + 1)
        if len(payload) > MAX_BYTES:
            _fail("PRIVATE_INPUT_INVALID")
        return _parse(payload.decode("utf-8"))
    except (OSError, UnicodeError):
        _fail("PRIVATE_INPUT_INVALID")
    finally:
        os.close(root_fd)


def write_private_draft(path: Path, draft: dict[str, Any]) -> None:
    payload = (_json(draft) + "\n").encode()
    if len(payload) > MAX_BYTES:
        _fail("PRIVATE_OUTPUT_TOO_LARGE")
    root_fd = _directory(path)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=root_fd)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(root_fd)
    except OSError:
        # A partial create-only file is retained privately for diagnosis, never retried.
        _fail("PRIVATE_OUTPUT_CREATE_FAILED")
    finally:
        os.close(root_fd)
