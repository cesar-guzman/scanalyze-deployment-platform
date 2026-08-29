"""Materialize one sanitized GitHub Environment approval for live DEV apply.

The GitHub token is transport authority only for two read-only requests: exact
workflow-run metadata and Environment review history. Raw API responses,
reviewer logins, comments, URLs, and the token are
never persisted or printed.  The resulting private evidence is short-lived and
bound to the exact repository, workflow run, Environment, initiator, and one
independent reviewer.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import jsonschema

from tooling.authorize_deployment_backend import (
    AuthorizationError,
    canonical_digest,
    load_json_strict,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas/nonprod-live-github-approval-evidence.v1.schema.json"
APPROVAL_RELATIVE_PATH = Path("materialized/controller/github-approval.json")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_SHA = re.compile(r"^[a-f0-9]{40}$")
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GITHUB_ENVIRONMENT = re.compile(
    r"^scanalyze-dep_[0-9A-HJKMNP-TV-Z]{26}-dev$"
)
MAX_RESPONSE_BYTES = 262_144
EVIDENCE_LIFETIME = timedelta(minutes=5)
MAX_WORKFLOW_RUN_AGE = timedelta(minutes=15)
GITHUB_API_VERSION = "2026-03-10"
ReviewFetcher = Callable[[str, int, str], Sequence[Mapping[str, Any]]]


class GitHubApprovalError(ValueError):
    """Public-safe approval materialization failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise GitHubApprovalError(code)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        _fail("APPROVAL_TIME_INVALID")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        _fail("APPROVAL_EVIDENCE_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("APPROVAL_EVIDENCE_INVALID")
    if parsed.tzinfo is None:
        _fail("APPROVAL_EVIDENCE_INVALID")
    return parsed.astimezone(UTC)


def _strict_json_object(content: bytes) -> dict[str, Any]:
    """Parse one private JSON object without duplicate or non-finite values."""

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("APPROVAL_EVIDENCE_INVALID")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        _fail("APPROVAL_EVIDENCE_INVALID")

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError):
        _fail("APPROVAL_EVIDENCE_INVALID")
    if not isinstance(document, dict):
        _fail("APPROVAL_EVIDENCE_INVALID")
    return document


def _read_private_json(path: Path, *, max_bytes: int) -> dict[str, Any]:
    """Read one private file through one no-follow, identity-stable descriptor."""
    descriptor: int | None = None
    content = bytearray()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 2
            or before.st_size > max_bytes
        ):
            _fail("APPROVAL_EVIDENCE_INVALID")
        while len(content) <= max_bytes:
            block = os.read(descriptor, min(65_536, max_bytes + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(content) > max_bytes or identity(before) != identity(after):
            _fail("APPROVAL_EVIDENCE_INVALID")
        return _strict_json_object(bytes(content))
    except OSError:
        _fail("APPROVAL_EVIDENCE_INVALID")
    finally:
        content[:] = b"\x00" * len(content)
        if descriptor is not None:
            os.close(descriptor)


def _validate_selectors(
    *,
    repository: str,
    repository_id: int,
    workflow_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    github_environment: str,
    initiator_user_id: int,
    expected_approver_user_id: int,
) -> None:
    if not REPOSITORY.fullmatch(repository):
        _fail("APPROVAL_SELECTOR_INVALID")
    if not COMMIT_SHA.fullmatch(workflow_sha):
        _fail("APPROVAL_SELECTOR_INVALID")
    if not GITHUB_ENVIRONMENT.fullmatch(github_environment):
        _fail("APPROVAL_SELECTOR_INVALID")
    for value in (
        repository_id,
        workflow_run_id,
        workflow_run_attempt,
        initiator_user_id,
        expected_approver_user_id,
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            _fail("APPROVAL_SELECTOR_INVALID")
    if workflow_run_attempt != 1:
        _fail("APPROVAL_SELECTOR_INVALID")


def _fetch_github_json(repository: str, path: str, token: str) -> Any:
    """Read one bounded JSON response from the fixed GitHub API host."""
    if not REPOSITORY.fullmatch(repository):
        _fail("APPROVAL_SELECTOR_INVALID")
    if not token or any(character in token for character in "\r\n"):
        _fail("GITHUB_TOKEN_UNAVAILABLE")
    connection = http.client.HTTPSConnection("api.github.com", timeout=10)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "scanalyze-nonprod-live-approval",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            _fail("GITHUB_APPROVAL_READ_FAILED")
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
    except (OSError, http.client.HTTPException):
        _fail("GITHUB_APPROVAL_READ_FAILED")
    finally:
        connection.close()
    try:
        document = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
    return document


def fetch_review_history(
    repository: str, workflow_run_id: int, token: str
) -> Sequence[Mapping[str, Any]]:
    """Read one workflow review history from the fixed GitHub API host."""
    owner, name = repository.split("/", 1)
    document = _fetch_github_json(
        repository,
        f"/repos/{owner}/{name}/actions/runs/{workflow_run_id}/approvals",
        token,
    )
    if not isinstance(document, list) or not all(
        isinstance(item, Mapping) for item in document
    ):
        _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
    return document


def fetch_workflow_run(
    repository: str, workflow_run_id: int, token: str
) -> Mapping[str, Any]:
    """Read exact workflow-run metadata used as a conservative time bound."""
    owner, name = repository.split("/", 1)
    document = _fetch_github_json(
        repository,
        f"/repos/{owner}/{name}/actions/runs/{workflow_run_id}",
        token,
    )
    if not isinstance(document, Mapping):
        _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
    return document


def build_approval_evidence(
    *,
    repository: str,
    repository_id: int,
    workflow_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    github_environment: str,
    reviewer_packet_digest: str,
    apply_environment_anchor_digest: str,
    approval_authority_digest: str,
    initiator_user_id: int,
    expected_approver_user_id: int,
    workflow_run: Mapping[str, Any],
    reviews: Sequence[Mapping[str, Any]],
    observed_at: datetime,
) -> dict[str, Any]:
    """Project untrusted review history into one short-lived exact decision."""
    _validate_selectors(
        repository=repository,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        github_environment=github_environment,
        initiator_user_id=initiator_user_id,
        expected_approver_user_id=expected_approver_user_id,
    )
    if any(
        not DIGEST.fullmatch(value)
        for value in (
            reviewer_packet_digest,
            apply_environment_anchor_digest,
            approval_authority_digest,
        )
    ):
        _fail("APPROVAL_SELECTOR_INVALID")
    if observed_at.tzinfo is None:
        _fail("APPROVAL_TIME_INVALID")
    run_repository = workflow_run.get("repository")
    run_actor = workflow_run.get("actor")
    if (
        workflow_run.get("id") != workflow_run_id
        or workflow_run.get("run_attempt") != workflow_run_attempt
        or workflow_run.get("event") != "workflow_dispatch"
        or workflow_run.get("status") != "in_progress"
        or workflow_run.get("head_branch") != "main"
        or workflow_run.get("head_sha") != workflow_sha
        or not isinstance(run_repository, Mapping)
        or run_repository.get("id") != repository_id
        or not isinstance(run_actor, Mapping)
        or run_actor.get("id") != initiator_user_id
    ):
        _fail("GITHUB_WORKFLOW_RUN_BINDING_INVALID")
    run_created = _parse_timestamp(workflow_run.get("created_at"))
    observed = observed_at.astimezone(UTC).replace(microsecond=0)
    if observed < run_created or observed - run_created > MAX_WORKFLOW_RUN_AGE:
        _fail("GITHUB_WORKFLOW_RUN_NOT_FRESH")
    normalized: list[dict[str, int | str]] = []
    for review in reviews:
        if review.get("state") != "approved":
            continue
        environments = review.get("environments")
        user = review.get("user")
        if not isinstance(environments, list) or not isinstance(user, Mapping):
            _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
        matching_ids = sorted(
            {
                environment.get("id")
                for environment in environments
                if isinstance(environment, Mapping)
                and environment.get("name") == github_environment
                and isinstance(environment.get("id"), int)
                and not isinstance(environment.get("id"), bool)
                and environment["id"] > 0
            }
        )
        if not matching_ids:
            continue
        user_id = user.get("id")
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            _fail("GITHUB_APPROVAL_RESPONSE_INVALID")
        for environment_id in matching_ids:
            normalized.append(
                {
                    "state": "approved",
                    "environment_id": environment_id,
                    "approver_user_id": user_id,
                }
            )
    if not normalized or len(normalized) > 16:
        _fail("INDEPENDENT_ENVIRONMENT_APPROVAL_NOT_PROVEN")
    unique_approvers = {item["approver_user_id"] for item in normalized}
    if (
        initiator_user_id in unique_approvers
        or unique_approvers != {expected_approver_user_id}
    ):
        _fail("INDEPENDENT_ENVIRONMENT_APPROVAL_NOT_PROVEN")
    normalized.sort(
        key=lambda item: (int(item["approver_user_id"]), int(item["environment_id"]))
    )
    approver_user_id = int(next(iter(unique_approvers)))
    evidence: dict[str, Any] = {
        "schema_version": "1",
        "record_type": "nonprod_live_github_approval_evidence",
        "repository": repository,
        "repository_id": repository_id,
        "workflow_sha": workflow_sha,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "workflow_run_created_at": _timestamp(run_created),
        "workflow_event": "workflow_dispatch",
        "github_environment": github_environment,
        "reviewer_packet_digest": reviewer_packet_digest,
        "apply_environment_anchor_digest": apply_environment_anchor_digest,
        "approval_authority_digest": approval_authority_digest,
        "initiator_user_id": initiator_user_id,
        "expected_approver_user_id": expected_approver_user_id,
        "approver_user_id": approver_user_id,
        "matching_review_count": len(normalized),
        "review_set_digest": canonical_digest({"reviews": normalized}),
        "approval_observed_at": _timestamp(observed),
        "freshness_basis": "WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
        "expires_at": _timestamp(
            min(
                observed + EVIDENCE_LIFETIME,
                run_created + MAX_WORKFLOW_RUN_AGE,
            )
        ),
    }
    evidence["evidence_digest"] = canonical_digest(evidence)
    validate_approval_evidence(
        evidence,
        repository=repository,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        github_environment=github_environment,
        reviewer_packet_digest=reviewer_packet_digest,
        apply_environment_anchor_digest=apply_environment_anchor_digest,
        approval_authority_digest=approval_authority_digest,
        initiator_user_id=initiator_user_id,
        expected_approver_user_id=expected_approver_user_id,
        now=observed,
    )
    return evidence


def validate_approval_evidence(
    evidence: Mapping[str, Any],
    *,
    repository: str,
    repository_id: int,
    workflow_sha: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
    github_environment: str,
    reviewer_packet_digest: str,
    apply_environment_anchor_digest: str,
    approval_authority_digest: str,
    initiator_user_id: int,
    expected_approver_user_id: int,
    now: datetime,
) -> None:
    """Revalidate schema, digest, exact run tuple, independence, and freshness."""
    _validate_selectors(
        repository=repository,
        repository_id=repository_id,
        workflow_sha=workflow_sha,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        github_environment=github_environment,
        initiator_user_id=initiator_user_id,
        expected_approver_user_id=expected_approver_user_id,
    )
    if any(
        not DIGEST.fullmatch(value)
        for value in (
            reviewer_packet_digest,
            apply_environment_anchor_digest,
            approval_authority_digest,
        )
    ):
        _fail("APPROVAL_SELECTOR_INVALID")
    try:
        schema = load_json_strict(SCHEMA_PATH)
    except AuthorizationError:
        _fail("APPROVAL_SCHEMA_INVALID")
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    if next(iter(validator.iter_errors(evidence)), None) is not None:
        _fail("APPROVAL_EVIDENCE_INVALID")
    expected_digest = canonical_digest(
        {key: value for key, value in evidence.items() if key != "evidence_digest"}
    )
    if evidence.get("evidence_digest") != expected_digest:
        _fail("APPROVAL_EVIDENCE_DIGEST_MISMATCH")
    expected = {
        "repository": repository,
        "repository_id": repository_id,
        "workflow_sha": workflow_sha,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "github_environment": github_environment,
        "reviewer_packet_digest": reviewer_packet_digest,
        "apply_environment_anchor_digest": apply_environment_anchor_digest,
        "approval_authority_digest": approval_authority_digest,
        "initiator_user_id": initiator_user_id,
        "expected_approver_user_id": expected_approver_user_id,
    }
    if any(evidence.get(field) != value for field, value in expected.items()):
        _fail("APPROVAL_EVIDENCE_BINDING_MISMATCH")
    approver = evidence.get("approver_user_id")
    if approver == initiator_user_id or approver != expected_approver_user_id:
        _fail("INDEPENDENT_ENVIRONMENT_APPROVAL_NOT_PROVEN")
    current = now.astimezone(UTC) if now.tzinfo else None
    if current is None:
        _fail("APPROVAL_TIME_INVALID")
    run_created = _parse_timestamp(evidence.get("workflow_run_created_at"))
    observed = _parse_timestamp(evidence.get("approval_observed_at"))
    expires = _parse_timestamp(evidence.get("expires_at"))
    if (
        evidence.get("workflow_event") != "workflow_dispatch"
        or evidence.get("freshness_basis")
        != "WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND"
        or observed < run_created
        or observed - run_created > MAX_WORKFLOW_RUN_AGE
        or expires
        != min(
            observed + EVIDENCE_LIFETIME,
            run_created + MAX_WORKFLOW_RUN_AGE,
        )
        or current < observed
        or current >= expires
    ):
        _fail("APPROVAL_EVIDENCE_NOT_CURRENT")


def approval_evidence_path(private_root: Path) -> Path:
    return private_root / APPROVAL_RELATIVE_PATH


def _validate_private_root(private_root: Path) -> None:
    if not private_root.is_absolute() or private_root.is_symlink():
        _fail("PRIVATE_ROOT_INVALID")
    try:
        metadata = private_root.stat()
    except OSError:
        _fail("PRIVATE_ROOT_INVALID")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("PRIVATE_ROOT_INVALID")
    controller = private_root / "materialized/controller"
    try:
        controller_metadata = controller.stat()
    except OSError:
        _fail("PRIVATE_ROOT_INVALID")
    if (
        controller.is_symlink()
        or not stat.S_ISDIR(controller_metadata.st_mode)
        or controller_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(controller_metadata.st_mode) != 0o700
    ):
        _fail("PRIVATE_ROOT_INVALID")


def persist_approval_evidence(private_root: Path, evidence: Mapping[str, Any]) -> Path:
    """Persist evidence once at the sole controller-owned private path."""
    _validate_private_root(private_root)
    destination = approval_evidence_path(private_root)
    content = (
        json.dumps(evidence, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o600)
        created = True
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(destination, 0o600)
    except OSError:
        if created:
            destination.unlink(missing_ok=True)
        _fail("APPROVAL_EVIDENCE_WRITE_FAILED")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return destination


def load_private_approval_evidence(private_root: Path) -> dict[str, Any]:
    _validate_private_root(private_root)
    return _read_private_json(approval_evidence_path(private_root), max_bytes=32_768)


__all__ = [
    "GitHubApprovalError",
    "approval_evidence_path",
    "build_approval_evidence",
    "fetch_review_history",
    "fetch_workflow_run",
    "load_private_approval_evidence",
    "persist_approval_evidence",
    "validate_approval_evidence",
]
