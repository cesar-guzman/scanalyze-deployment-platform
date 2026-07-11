#!/usr/bin/env python3
"""Safely reconcile classic GitHub required status checks.

The default operation is a read-only plan.  Remote writes are restricted to the
dedicated classic branch-protection required-status-checks endpoint and require
an explicit repository confirmation.  The policy manifest is intentionally
declarative so the same reconciler can be reused across platform repositories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence
from urllib.parse import quote, urlsplit


API_VERSION = "2022-11-28"
DEFAULT_MANIFEST = Path("governance/github-policy.json")
SNAPSHOT_SCHEMA_VERSION = 1
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
WORKFLOW_PATH_RE = re.compile(
    r"^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$"
)
JOB_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,99}$")
MAX_WORKFLOW_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024


class GovernanceError(RuntimeError):
    """A fail-closed governance error safe to present to an operator."""


class PolicyState(str, Enum):
    LEGACY = "LEGACY"
    TARGET = "TARGET"
    TRANSITION = "TRANSITION"
    MIXED = "MIXED"
    DIVERGED = "DIVERGED"


@dataclass(frozen=True, order=True)
class CheckBinding:
    context: str
    app_id: int | None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"context": self.context}
        if self.app_id is not None:
            result["app_id"] = self.app_id
        return result


@dataclass(frozen=True)
class RequiredStatusPolicy:
    strict: bool
    checks: tuple[CheckBinding, ...]

    @property
    def contexts(self) -> frozenset[str]:
        return frozenset(check.context for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict": self.strict,
            "checks": [check.to_dict() for check in self.checks],
        }

    def to_patch_payload(self) -> dict[str, Any]:
        # Explicitly clear legacy, provider-agnostic contexts.  The `checks`
        # collection preserves provider binding through app_id.
        return {
            "strict": self.strict,
            "contexts": [],
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass(frozen=True)
class ManifestCheck:
    context: str
    workflow: str
    job: str


@dataclass(frozen=True)
class EvidencePullRequest:
    number: int
    head_sha: str
    base_ref: str


@dataclass(frozen=True)
class PolicyManifest:
    schema_version: str
    default_branch: str
    strict: bool
    expected_app_slug: str
    checks: tuple[ManifestCheck, ...]
    added_contexts: frozenset[str]
    retired_contexts: frozenset[str]

    @property
    def target_contexts(self) -> frozenset[str]:
        return frozenset(check.context for check in self.checks)

    @property
    def stable_contexts(self) -> frozenset[str]:
        return self.target_contexts - self.added_contexts

    @property
    def legacy_contexts(self) -> frozenset[str]:
        return self.stable_contexts | self.retired_contexts

    @property
    def transition_contexts(self) -> frozenset[str]:
        return self.target_contexts | self.retired_contexts

    @property
    def managed_contexts(self) -> frozenset[str]:
        return self.target_contexts | self.retired_contexts


@dataclass(frozen=True)
class StateAssessment:
    state: PolicyState
    current_contexts: frozenset[str]
    target_contexts: frozenset[str]
    unknown_contexts: frozenset[str]
    missing_stable_contexts: frozenset[str]
    missing_added_contexts: frozenset[str]
    present_retired_contexts: frozenset[str]
    strict_matches: bool


@dataclass(frozen=True)
class Inspection:
    repository: str
    branch: str
    policy: RequiredStatusPolicy
    effective_rules: tuple[dict[str, Any], ...]
    assessment: StateAssessment


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def run_gh(args: Sequence[str], *, input_data: str | None = None) -> Any:
    """Run GitHub CLI and decode one JSON response.

    Callers pass the complete arguments after ``gh``.  Tests replace this
    function, which keeps all network and mutation behavior auditable.
    """

    try:
        completed = subprocess.run(
            ["gh", *args],
            check=False,
            capture_output=True,
            input=input_data,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GovernanceError(f"unable to execute gh safely: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\n", " ")[:1000]
        raise GovernanceError(
            f"gh command failed with exit code {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise GovernanceError("gh returned a non-JSON response") from exc


def _validate_repository(repository: str) -> None:
    if not REPOSITORY_RE.fullmatch(repository):
        raise GovernanceError("--repo must use the exact owner/repository form")


def _api_args(method: str, endpoint: str) -> list[str]:
    return [
        "api",
        "--method",
        method,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {API_VERSION}",
        endpoint,
    ]


def _required_checks_endpoint(repository: str, branch: str) -> str:
    return (
        f"repos/{repository}/branches/{quote(branch, safe='')}/protection/"
        "required_status_checks"
    )


def _effective_rules_endpoint(repository: str, branch: str) -> str:
    return f"repos/{repository}/rules/branches/{quote(branch, safe='')}"


def _check_runs_endpoint(repository: str, sha: str) -> str:
    return f"repos/{repository}/commits/{quote(sha, safe='')}/check-runs"


def _commit_pulls_endpoint(repository: str, sha: str) -> str:
    return f"repos/{repository}/commits/{quote(sha, safe='')}/pulls"


def _workflow_run_endpoint(repository: str, run_id: int) -> str:
    return f"repos/{repository}/actions/runs/{run_id}"


def _workflow_job_endpoint(repository: str, job_id: int) -> str:
    return f"repos/{repository}/actions/jobs/{job_id}"


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"manifest field {field} must be a non-empty string")
    return value.strip()


def _require_static_context(value: Any, field: str) -> str:
    context = _require_string(value, field)
    if "${{" in context:
        raise GovernanceError(f"manifest field {field} must be a static check context")
    return context


def _require_workflow_path(value: Any, field: str) -> str:
    workflow = _require_string(value, field)
    if not WORKFLOW_PATH_RE.fullmatch(workflow):
        raise GovernanceError(
            f"manifest field {field} must be a repository workflow YAML path"
        )
    return workflow


def _require_job_id(value: Any, field: str) -> str:
    job = _require_string(value, field)
    if not JOB_ID_RE.fullmatch(job):
        raise GovernanceError(f"manifest field {field} must be a static YAML job ID")
    return job


def _reject_unknown_keys(
    value: dict[str, Any], allowed: set[str], field: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise GovernanceError(
            f"manifest field {field} contains unknown keys: {', '.join(unknown)}"
        )


def _string_set(value: Any, field: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise GovernanceError(f"manifest field {field} must be an array")
    items = [_require_static_context(item, field) for item in value]
    if len(items) != len(set(items)):
        raise GovernanceError(f"manifest field {field} contains duplicates")
    return frozenset(items)


def load_manifest(path: Path) -> PolicyManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GovernanceError(f"unable to read policy manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"policy manifest {path} is not valid JSON") from exc

    return _policy_manifest_from_document(raw)


def _policy_manifest_from_document(raw: Any) -> PolicyManifest:
    """Validate one decoded policy manifest without trusting its source."""

    if not isinstance(raw, dict):
        raise GovernanceError("policy manifest must be a JSON object")
    _reject_unknown_keys(
        raw,
        {
            "$schema",
            "schema_version",
            "scope",
            "default_branch",
            "required_status_checks",
            "migration",
        },
        "root",
    )
    if raw.get("schema_version") != "1":
        raise GovernanceError(
            'unsupported policy manifest schema_version (expected string "1")'
        )
    if raw.get("scope") != "repository":
        raise GovernanceError('policy manifest scope must be exactly "repository"')

    branch = _require_string(raw.get("default_branch"), "default_branch")
    required = raw.get("required_status_checks")
    migration = raw.get("migration")
    if not isinstance(required, dict) or not isinstance(migration, dict):
        raise GovernanceError(
            "manifest requires required_status_checks and migration objects"
        )
    _reject_unknown_keys(
        required,
        {"strict", "expected_app_slug", "checks"},
        "required_status_checks",
    )
    _reject_unknown_keys(
        migration,
        {"added_contexts", "retired_contexts"},
        "migration",
    )
    strict = required.get("strict")
    if not isinstance(strict, bool):
        raise GovernanceError("required_status_checks.strict must be boolean")
    expected_app_slug = _require_string(
        required.get("expected_app_slug"),
        "required_status_checks.expected_app_slug",
    )

    raw_checks = required.get("checks")
    if not isinstance(raw_checks, list) or not raw_checks:
        raise GovernanceError("required_status_checks.checks must be a non-empty array")
    if len(raw_checks) > 100:
        raise GovernanceError("required_status_checks.checks exceeds the evidence page limit")
    checks: list[ManifestCheck] = []
    for index, raw_check in enumerate(raw_checks):
        if not isinstance(raw_check, dict):
            raise GovernanceError(f"required_status_checks.checks[{index}] must be an object")
        _reject_unknown_keys(
            raw_check,
            {"context", "workflow", "job"},
            f"required_status_checks.checks[{index}]",
        )
        checks.append(
            ManifestCheck(
                context=_require_static_context(
                    raw_check.get("context"), f"checks[{index}].context"
                ),
                workflow=_require_workflow_path(
                    raw_check.get("workflow"), f"checks[{index}].workflow"
                ),
                job=_require_job_id(raw_check.get("job"), f"checks[{index}].job"),
            )
        )
    contexts = [check.context for check in checks]
    if len(contexts) != len(set(contexts)):
        raise GovernanceError("required_status_checks.checks contains duplicate contexts")

    added = _string_set(migration.get("added_contexts"), "migration.added_contexts")
    retired = _string_set(
        migration.get("retired_contexts"), "migration.retired_contexts"
    )
    target = frozenset(contexts)
    if not added <= target:
        raise GovernanceError("migration.added_contexts must be a subset of target checks")
    if retired & target:
        raise GovernanceError("retired contexts cannot remain in target checks")
    if added & retired:
        raise GovernanceError("added and retired contexts must be disjoint")

    return PolicyManifest(
        schema_version="1",
        default_branch=branch,
        strict=strict,
        expected_app_slug=expected_app_slug,
        checks=tuple(checks),
        added_contexts=added,
        retired_contexts=retired,
    )


def required_policy_from_api(raw: Any) -> RequiredStatusPolicy:
    if not isinstance(raw, dict):
        raise GovernanceError("required-status-checks API response must be an object")
    strict = raw.get("strict")
    checks_raw = raw.get("checks")
    if not isinstance(strict, bool) or not isinstance(checks_raw, list):
        raise GovernanceError("required-status-checks response is missing strict/checks")

    checks: list[CheckBinding] = []
    for index, check in enumerate(checks_raw):
        if not isinstance(check, dict):
            raise GovernanceError(f"required check {index} is not an object")
        context = check.get("context")
        app_id = check.get("app_id")
        if not isinstance(context, str) or not context.strip():
            raise GovernanceError(f"required check {index} has an invalid context")
        if app_id is not None and (isinstance(app_id, bool) or not isinstance(app_id, int)):
            raise GovernanceError(f"required check {context!r} has an invalid app_id")
        checks.append(CheckBinding(context=context.strip(), app_id=app_id))

    check_contexts = [check.context for check in checks]
    if len(check_contexts) != len(set(check_contexts)):
        raise GovernanceError("required-status-checks response contains duplicate contexts")

    flattened = raw.get("contexts")
    if flattened is not None:
        if not isinstance(flattened, list) or any(
            not isinstance(item, str) for item in flattened
        ):
            raise GovernanceError("required-status-checks contexts is malformed")
        if set(flattened) != set(check_contexts):
            raise GovernanceError(
                "required-status-checks contexts/checks disagree; refusing unsafe reconciliation"
            )

    return RequiredStatusPolicy(strict=strict, checks=tuple(sorted(checks)))


def read_required_policy(repository: str, branch: str) -> RequiredStatusPolicy:
    raw = run_gh(_api_args("GET", _required_checks_endpoint(repository, branch)))
    return required_policy_from_api(raw)


def read_effective_rules(repository: str, branch: str) -> tuple[dict[str, Any], ...]:
    raw = run_gh(_api_args("GET", _effective_rules_endpoint(repository, branch)))
    if isinstance(raw, dict) and isinstance(raw.get("rules"), list):
        raw = raw["rules"]
    if not isinstance(raw, list) or any(not isinstance(rule, dict) for rule in raw):
        raise GovernanceError("effective-rules API response must be an array")
    return tuple(raw)


def assess_state(
    current: RequiredStatusPolicy, manifest: PolicyManifest
) -> StateAssessment:
    current_contexts = current.contexts
    target = manifest.target_contexts
    unknown = current_contexts - manifest.managed_contexts
    missing_stable = manifest.stable_contexts - current_contexts
    strict_matches = current.strict == manifest.strict

    if not strict_matches or unknown or missing_stable:
        state = PolicyState.DIVERGED
    elif current_contexts == target:
        state = PolicyState.TARGET
    elif current_contexts == manifest.legacy_contexts:
        state = PolicyState.LEGACY
    elif (
        manifest.retired_contexts
        and current_contexts == manifest.transition_contexts
    ):
        state = PolicyState.TRANSITION
    else:
        state = PolicyState.MIXED

    return StateAssessment(
        state=state,
        current_contexts=current_contexts,
        target_contexts=target,
        unknown_contexts=unknown,
        missing_stable_contexts=missing_stable,
        missing_added_contexts=manifest.added_contexts - current_contexts,
        present_retired_contexts=manifest.retired_contexts & current_contexts,
        strict_matches=strict_matches,
    )


def inspect_repository(repository: str, manifest: PolicyManifest) -> Inspection:
    _validate_repository(repository)
    policy = read_required_policy(repository, manifest.default_branch)
    rules = read_effective_rules(repository, manifest.default_branch)
    return Inspection(
        repository=repository,
        branch=manifest.default_branch,
        policy=policy,
        effective_rules=rules,
        assessment=assess_state(policy, manifest),
    )


def plan_document(inspection: Inspection, manifest: PolicyManifest) -> dict[str, Any]:
    assessment = inspection.assessment
    return {
        "repository": inspection.repository,
        "branch": inspection.branch,
        "state": assessment.state.value,
        "strict": {
            "current": inspection.policy.strict,
            "target": manifest.strict,
            "matches": assessment.strict_matches,
        },
        "current_contexts": sorted(assessment.current_contexts),
        "target_contexts": sorted(assessment.target_contexts),
        "added_contexts": sorted(manifest.added_contexts),
        "retired_contexts": sorted(manifest.retired_contexts),
        "unknown_contexts": sorted(assessment.unknown_contexts),
        "missing_stable_contexts": sorted(assessment.missing_stable_contexts),
        "missing_added_contexts": sorted(assessment.missing_added_contexts),
        "present_retired_contexts": sorted(assessment.present_retired_contexts),
        "effective_rules_count": len(inspection.effective_rules),
        "ruleset_conflict": bool(inspection.effective_rules),
        "remote_mutation_required": assessment.state
        in {PolicyState.LEGACY, PolicyState.TRANSITION},
    }


def read_git_blob(revision: str, repository_path: str) -> str:
    """Read one workflow exactly as committed, without contacting GitHub."""

    if not FULL_SHA_RE.fullmatch(revision):
        raise GovernanceError("offline workflow revision must be a full commit SHA")
    if not WORKFLOW_PATH_RE.fullmatch(repository_path):
        raise GovernanceError("offline workflow path is outside .github/workflows")
    try:
        completed = subprocess.run(
            ["git", "cat-file", "blob", f"{revision}:{repository_path}"],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GovernanceError("unable to read the committed workflow safely") from exc
    if completed.returncode != 0:
        raise GovernanceError(
            f"offline workflow mapping cannot read {repository_path!r} at the evidence SHA"
        )
    if len(completed.stdout) > MAX_WORKFLOW_BYTES:
        raise GovernanceError("offline workflow mapping exceeds the safe size limit")
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GovernanceError("offline workflow mapping is not valid UTF-8") from exc


def _canonical_manifest_repository_path(path: Path) -> str:
    repository_path = path.as_posix()
    if path.is_absolute() or repository_path != DEFAULT_MANIFEST.as_posix():
        raise GovernanceError(
            "apply manifest must use the canonical repository-relative path "
            f"{DEFAULT_MANIFEST.as_posix()!r}"
        )
    return repository_path


def read_manifest_blob(revision: str, repository_path: str) -> bytes:
    """Read the canonical policy manifest exactly as committed at a full SHA."""

    if not FULL_SHA_RE.fullmatch(revision):
        raise GovernanceError("manifest evidence revision must be a full commit SHA")
    if repository_path != DEFAULT_MANIFEST.as_posix():
        raise GovernanceError("committed manifest path is not canonical")
    try:
        completed = subprocess.run(
            ["git", "cat-file", "blob", f"{revision}:{repository_path}"],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GovernanceError("unable to read the committed policy manifest safely") from exc
    if completed.returncode != 0:
        raise GovernanceError(
            "canonical policy manifest does not exist at the evidence SHA"
        )
    if len(completed.stdout) > MAX_MANIFEST_BYTES:
        raise GovernanceError("committed policy manifest exceeds the safe size limit")
    return completed.stdout


def read_working_manifest(repository_path: str) -> bytes:
    """Read a regular canonical manifest file from the repository working tree."""

    if repository_path != DEFAULT_MANIFEST.as_posix():
        raise GovernanceError("working-tree manifest path is not canonical")
    path = Path(repository_path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GovernanceError("unable to inspect the working-tree policy manifest") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GovernanceError("working-tree policy manifest must be a regular file")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise GovernanceError("working-tree policy manifest exceeds the safe size limit")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise GovernanceError("unable to read the working-tree policy manifest") from exc
    if len(content) > MAX_MANIFEST_BYTES:
        raise GovernanceError("working-tree policy manifest exceeds the safe size limit")
    return content


def _validate_apply_manifest_binding(
    manifest: PolicyManifest,
    manifest_path: Path,
    evidence_sha: str,
) -> None:
    repository_path = _canonical_manifest_repository_path(manifest_path)
    committed = read_manifest_blob(evidence_sha, repository_path)
    working = read_working_manifest(repository_path)
    if working != committed:
        raise GovernanceError(
            "working tree differs from the policy manifest committed at the evidence SHA"
        )
    try:
        raw = json.loads(working.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError("bound policy manifest is not valid UTF-8 JSON") from exc
    bound_manifest = _policy_manifest_from_document(raw)
    if bound_manifest != manifest:
        raise GovernanceError(
            "loaded manifest does not match the policy manifest bound to the evidence SHA"
        )


def _decode_static_yaml_scalar(value: str, workflow: str, job: str) -> str:
    scalar = value.strip()
    if not scalar:
        raise GovernanceError(
            f"offline workflow mapping has an empty name for {workflow}:{job}"
        )
    if scalar.startswith("'"):
        if len(scalar) < 2 or not scalar.endswith("'"):
            raise GovernanceError("offline workflow mapping has an unsupported YAML name")
        return scalar[1:-1].replace("''", "'")
    if scalar.startswith('"'):
        try:
            decoded = json.loads(scalar)
        except json.JSONDecodeError as exc:
            raise GovernanceError(
                "offline workflow mapping has an unsupported YAML name"
            ) from exc
        if not isinstance(decoded, str):
            raise GovernanceError("offline workflow mapping job name must be a string")
        return decoded
    if scalar in {"|", ">"} or scalar.startswith(("&", "*", "!", "{", "[")):
        raise GovernanceError("offline workflow mapping requires a static scalar job name")
    if " #" in scalar:
        scalar = scalar.split(" #", 1)[0].rstrip()
    if not scalar or "${{" in scalar:
        raise GovernanceError("offline workflow mapping requires a static scalar job name")
    return scalar


def _static_workflow_job_names(source: str, workflow: str) -> dict[str, str | None]:
    lines = source.splitlines()
    jobs_markers = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(r"jobs:\s*(?:#.*)?", line)
    ]
    if len(jobs_markers) != 1:
        raise GovernanceError(
            f"offline workflow mapping requires one top-level jobs block in {workflow!r}"
        )

    names: dict[str, str | None] = {}
    current_job: str | None = None
    for line in lines[jobs_markers[0] + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            break
        job_match = re.fullmatch(
            r"  ([A-Za-z_][A-Za-z0-9_-]{0,99}):\s*(?:#.*)?", line
        )
        if job_match:
            current_job = job_match.group(1)
            if current_job in names:
                raise GovernanceError(
                    f"offline workflow mapping contains duplicate job {current_job!r}"
                )
            names[current_job] = None
            continue
        name_match = re.fullmatch(r"    name:\s*(.+?)\s*", line)
        if name_match and current_job is not None:
            if names[current_job] is not None:
                raise GovernanceError(
                    f"offline workflow mapping contains duplicate names for {current_job!r}"
                )
            names[current_job] = _decode_static_yaml_scalar(
                name_match.group(1), workflow, current_job
            )
    return names


def _validate_offline_manifest_job_mapping(
    manifest: PolicyManifest, evidence_sha: str
) -> None:
    mappings: dict[str, dict[str, str | None]] = {}
    for check in manifest.checks:
        if check.workflow not in mappings:
            mappings[check.workflow] = _static_workflow_job_names(
                read_git_blob(evidence_sha, check.workflow), check.workflow
            )
        actual_context = mappings[check.workflow].get(check.job)
        if actual_context != check.context:
            raise GovernanceError(
                "offline workflow mapping does not bind "
                f"{check.workflow}:{check.job} to context {check.context!r}"
            )


def _resolve_evidence_pull_request(
    repository: str, evidence_sha: str, target_branch: str
) -> EvidencePullRequest:
    args = _api_args("GET", _commit_pulls_endpoint(repository, evidence_sha))
    args.extend(["-F", "per_page=100", "--paginate", "--slurp"])
    raw = run_gh(args)
    if not isinstance(raw, list):
        raise GovernanceError("commit pull-request API response is malformed")
    pages = raw if all(isinstance(page, list) for page in raw) else [raw]
    pull_requests = [item for page in pages for item in page]
    if any(not isinstance(item, dict) for item in pull_requests):
        raise GovernanceError("commit pull-request API response contains an invalid item")

    candidates: list[EvidencePullRequest] = []
    for item in pull_requests:
        number = item.get("number")
        state = item.get("state")
        head = item.get("head")
        base = item.get("base")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or not isinstance(state, str)
            or not isinstance(head, dict)
            or not isinstance(head.get("sha"), str)
            or not isinstance(base, dict)
            or not isinstance(base.get("ref"), str)
            or not isinstance(base.get("repo"), dict)
            or not isinstance(base["repo"].get("full_name"), str)
        ):
            raise GovernanceError("commit pull-request API response is malformed")
        if (
            state == "open"
            and head["sha"] == evidence_sha
            and base["ref"] == target_branch
            and base["repo"]["full_name"] == repository
        ):
            candidates.append(
                EvidencePullRequest(
                    number=number,
                    head_sha=head["sha"],
                    base_ref=base["ref"],
                )
            )
    if len(candidates) != 1:
        raise GovernanceError(
            "evidence SHA must be the current head of exactly one open pull request "
            f"targeting {repository}:{target_branch}"
        )
    return candidates[0]


def _revalidate_evidence_pull_request(
    repository: str,
    evidence_sha: str,
    target_branch: str,
    expected: EvidencePullRequest,
) -> None:
    try:
        current = _resolve_evidence_pull_request(
            repository, evidence_sha, target_branch
        )
    except GovernanceError as exc:
        raise GovernanceError(
            "evidence pull request changed before PATCH; apply aborted"
        ) from exc
    if current != expected:
        raise GovernanceError(
            "evidence pull request changed identity before PATCH; apply aborted"
        )


def _require_pull_request_association(
    raw: Any, expected: EvidencePullRequest, source: str
) -> None:
    if not isinstance(raw, list):
        raise GovernanceError(f"{source} pull request provenance is malformed")
    matches = 0
    for item in raw:
        if not isinstance(item, dict):
            raise GovernanceError(f"{source} pull request provenance is malformed")
        number = item.get("number")
        head = item.get("head")
        base = item.get("base")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or not isinstance(head, dict)
            or not isinstance(head.get("sha"), str)
            or not isinstance(base, dict)
            or not isinstance(base.get("ref"), str)
        ):
            raise GovernanceError(f"{source} pull request provenance is malformed")
        if (
            number == expected.number
            and head["sha"] == expected.head_sha
            and base["ref"] == expected.base_ref
        ):
            matches += 1
    if matches != 1:
        raise GovernanceError(
            f"{source} is not associated with the exact evidence pull request"
        )


def _actions_details_ids(details_url: Any, repository: str) -> tuple[int, int]:
    if not isinstance(details_url, str):
        raise GovernanceError("CheckRun details_url is missing or malformed")
    parsed = urlsplit(details_url)
    owner, repo = repository.split("/", 1)
    parts = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.query
        or parsed.fragment
        or parts[:5] != ["", owner, repo, "actions", "runs"]
        or len(parts) != 8
        or parts[6] != "job"
        or not parts[5].isdigit()
        or not parts[7].isdigit()
    ):
        raise GovernanceError("CheckRun details_url is not a canonical GitHub Actions job URL")
    run_id = int(parts[5])
    job_id = int(parts[7])
    if run_id <= 0 or job_id <= 0 or str(run_id) != parts[5] or str(job_id) != parts[7]:
        raise GovernanceError("CheckRun details_url contains invalid Actions IDs")
    return run_id, job_id


def _workflow_path_without_ref(raw_path: Any) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise GovernanceError("workflow run path is missing or malformed")
    if raw_path.count("@") > 1:
        raise GovernanceError("workflow run path is missing or malformed")
    path, separator, ref = raw_path.partition("@")
    if separator and (not ref or any(character.isspace() for character in ref)):
        raise GovernanceError("workflow run path is missing or malformed")
    return path


def _validate_workflow_run(
    raw: Any,
    *,
    repository: str,
    run_id: int,
    evidence_sha: str,
    expected_workflow: str,
    pull_request: EvidencePullRequest,
) -> None:
    if not isinstance(raw, dict):
        raise GovernanceError("workflow run API response is malformed")
    repository_value = raw.get("repository")
    if raw.get("id") != run_id:
        raise GovernanceError("workflow run API returned an unexpected run ID")
    if (
        not isinstance(repository_value, dict)
        or repository_value.get("full_name") != repository
    ):
        raise GovernanceError("workflow run belongs to an unexpected repository")
    if raw.get("event") != "pull_request":
        raise GovernanceError("workflow run was not created by the pull_request event")
    if raw.get("head_sha") != evidence_sha:
        raise GovernanceError("workflow run has an unexpected head SHA")
    if _workflow_path_without_ref(raw.get("path")) != expected_workflow:
        raise GovernanceError("workflow run has an unexpected workflow path")
    if raw.get("status") != "completed" or raw.get("conclusion") != "success":
        raise GovernanceError("workflow run is not complete and successful")
    _require_pull_request_association(raw.get("pull_requests"), pull_request, "workflow run")


def _validate_workflow_job(
    raw: Any,
    *,
    repository: str,
    job_id: int,
    run_id: int,
    check_run_id: int,
    evidence_sha: str,
    context: str,
    details_url: str,
) -> None:
    if not isinstance(raw, dict):
        raise GovernanceError("Actions job API response is malformed")
    if raw.get("id") != job_id:
        raise GovernanceError("Actions job API returned an unexpected job ID")
    if raw.get("run_id") != run_id:
        raise GovernanceError("Actions job does not belong to the declared workflow run")
    if raw.get("head_sha") != evidence_sha:
        raise GovernanceError("Actions job has an unexpected head SHA")
    if raw.get("name") != context:
        raise GovernanceError("Actions job name does not match the required context")
    if raw.get("status") != "completed" or raw.get("conclusion") != "success":
        raise GovernanceError("Actions job is not complete and successful")
    if raw.get("html_url") != details_url:
        raise GovernanceError("Actions job URL does not match the CheckRun details_url")
    expected_check_url = (
        f"https://api.github.com/repos/{repository}/check-runs/{check_run_id}"
    )
    if raw.get("check_run_url") != expected_check_url:
        raise GovernanceError("Actions job is not bound to the expected CheckRun")


def _collect_evidence(
    repository: str, evidence_sha: str, manifest: PolicyManifest
) -> tuple[dict[str, int], EvidencePullRequest]:
    if not FULL_SHA_RE.fullmatch(evidence_sha):
        raise GovernanceError("--evidence-sha must be a full 40-character commit SHA")

    pull_request = _resolve_evidence_pull_request(
        repository, evidence_sha, manifest.default_branch
    )
    _validate_offline_manifest_job_mapping(manifest, evidence_sha)

    args = _api_args("GET", _check_runs_endpoint(repository, evidence_sha))
    args.extend(
        ["-F", "per_page=100", "-f", "filter=latest", "--paginate", "--slurp"]
    )
    raw = run_gh(args)
    pages = [raw] if isinstance(raw, dict) else raw
    if not isinstance(pages, list) or any(not isinstance(page, dict) for page in pages):
        raise GovernanceError("check-runs API response is malformed")
    if any(not isinstance(page.get("check_runs"), list) for page in pages):
        raise GovernanceError("check-runs API response is malformed")
    runs = [run for page in pages for run in page["check_runs"]]
    if any(not isinstance(run, dict) for run in runs):
        raise GovernanceError("check-runs API response contains an invalid run")

    app_ids: dict[str, int] = {}
    workflow_run_cache: dict[int, Any] = {}
    job_cache: dict[int, Any] = {}
    seen_check_run_ids: set[int] = set()
    seen_job_ids: set[int] = set()
    for check in manifest.checks:
        named = [run for run in runs if run.get("name") == check.context]
        from_expected_app = [
            run
            for run in named
            if isinstance(run.get("app"), dict)
            and run["app"].get("slug") == manifest.expected_app_slug
        ]
        if not from_expected_app:
            if named:
                raise GovernanceError(
                    f"evidence for {check.context!r} came from the wrong GitHub App"
                )
            raise GovernanceError(f"missing CheckRun evidence for {check.context!r}")
        if len(from_expected_app) != 1:
            raise GovernanceError(
                f"CheckRun evidence for {check.context!r} is ambiguous"
            )

        check_run = from_expected_app[0]
        if check_run.get("status") != "completed" or check_run.get("conclusion") != "success":
            raise GovernanceError(f"latest CheckRun for {check.context!r} is not SUCCESS")
        if check_run.get("head_sha") != evidence_sha:
            raise GovernanceError(f"CheckRun for {check.context!r} has an unexpected head SHA")
        check_run_id = check_run.get("id")
        if (
            isinstance(check_run_id, bool)
            or not isinstance(check_run_id, int)
            or check_run_id <= 0
            or check_run_id in seen_check_run_ids
        ):
            raise GovernanceError(f"CheckRun for {check.context!r} has an invalid ID")
        seen_check_run_ids.add(check_run_id)
        _require_pull_request_association(
            check_run.get("pull_requests"), pull_request, f"CheckRun {check.context!r}"
        )

        details_url = check_run.get("details_url")
        run_id, job_id = _actions_details_ids(details_url, repository)
        if job_id in seen_job_ids:
            raise GovernanceError("multiple required contexts resolved to the same Actions job")
        seen_job_ids.add(job_id)

        if run_id not in workflow_run_cache:
            workflow_run_cache[run_id] = run_gh(
                _api_args("GET", _workflow_run_endpoint(repository, run_id))
            )
        _validate_workflow_run(
            workflow_run_cache[run_id],
            repository=repository,
            run_id=run_id,
            evidence_sha=evidence_sha,
            expected_workflow=check.workflow,
            pull_request=pull_request,
        )

        if job_id not in job_cache:
            job_cache[job_id] = run_gh(
                _api_args("GET", _workflow_job_endpoint(repository, job_id))
            )
        assert isinstance(details_url, str)
        _validate_workflow_job(
            job_cache[job_id],
            repository=repository,
            job_id=job_id,
            run_id=run_id,
            check_run_id=check_run_id,
            evidence_sha=evidence_sha,
            context=check.context,
            details_url=details_url,
        )

        app = check_run["app"]
        app_id = app.get("id")
        if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
            raise GovernanceError(f"CheckRun for {check.context!r} has no valid app ID")
        app_ids[check.context] = app_id

    if len(set(app_ids.values())) != 1:
        raise GovernanceError(
            "the expected GitHub App slug resolved to inconsistent app IDs"
        )
    return app_ids, pull_request


def collect_evidence_app_ids(
    repository: str, evidence_sha: str, manifest: PolicyManifest
) -> dict[str, int]:
    """Collect application bindings while preserving the public helper API."""

    app_ids, _ = _collect_evidence(repository, evidence_sha, manifest)
    return app_ids


def target_policy(
    manifest: PolicyManifest, app_ids: dict[str, int]
) -> RequiredStatusPolicy:
    if set(app_ids) != set(manifest.target_contexts):
        raise GovernanceError("evidence app IDs do not cover the exact target context set")
    return RequiredStatusPolicy(
        strict=manifest.strict,
        checks=tuple(
            sorted(
                CheckBinding(context=check.context, app_id=app_ids[check.context])
                for check in manifest.checks
            )
        ),
    )


def patch_required_policy(
    repository: str, branch: str, policy: RequiredStatusPolicy
) -> None:
    payload = canonical_json(policy.to_patch_payload())
    run_gh(
        [*_api_args("PATCH", _required_checks_endpoint(repository, branch)), "--input", "-"],
        input_data=payload,
    )


def _snapshot_unsigned(
    repository: str,
    branch: str,
    before: RequiredStatusPolicy,
    expected_after: RequiredStatusPolicy,
) -> dict[str, Any]:
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "repository": repository,
        "branch": branch,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "before": before.to_dict(),
        "expected_after": expected_after.to_dict(),
    }


def write_snapshot(
    path: Path,
    repository: str,
    branch: str,
    before: RequiredStatusPolicy,
    expected_after: RequiredStatusPolicy,
) -> str:
    unsigned = _snapshot_unsigned(repository, branch, before, expected_after)
    digest = canonical_sha256(unsigned)
    document = {**unsigned, "canonical_sha256": digest}

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    except OSError as exc:
        raise GovernanceError(f"unable to create snapshot {path}: {exc}") from exc
    return digest


def _policy_from_snapshot(value: Any, field: str) -> RequiredStatusPolicy:
    if not isinstance(value, dict):
        raise GovernanceError(f"snapshot field {field} must be an object")
    synthetic = {
        "strict": value.get("strict"),
        "checks": value.get("checks"),
        "contexts": [
            check.get("context")
            for check in value.get("checks", [])
            if isinstance(check, dict)
        ],
    }
    return required_policy_from_api(synthetic)


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GovernanceError(f"unable to inspect snapshot {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GovernanceError("snapshot must be a regular, non-symlink file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GovernanceError("snapshot permissions must be exactly 0600")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"unable to load snapshot {path}") from exc
    if not isinstance(document, dict):
        raise GovernanceError("snapshot must be a JSON object")
    digest = document.get("canonical_sha256")
    unsigned = {key: value for key, value in document.items() if key != "canonical_sha256"}
    if not isinstance(digest, str) or digest != canonical_sha256(unsigned):
        raise GovernanceError("snapshot canonical SHA-256 verification failed")
    if unsigned.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise GovernanceError("unsupported snapshot schema_version")
    # Validate policy payloads while loading so rollback never trusts malformed data.
    _policy_from_snapshot(unsigned.get("before"), "before")
    _policy_from_snapshot(unsigned.get("expected_after"), "expected_after")
    return document


def _assert_no_rulesets(rules: tuple[dict[str, Any], ...]) -> None:
    if rules:
        raise GovernanceError(
            "active effective rulesets were detected; classic protection apply is blocked"
        )


def _read_policy_for_recovery(
    repository: str,
    branch: str,
    operation: str,
    transition_error: Exception,
) -> RequiredStatusPolicy:
    try:
        return read_required_policy(repository, branch)
    except Exception as read_error:
        raise GovernanceError(
            f"{operation} failed and the PATCH outcome is unknown because safe readback "
            "failed; compensation was not attempted: "
            f"operation={transition_error}; readback={read_error}"
        ) from read_error


def _recover_failed_policy_transition(
    repository: str,
    branch: str,
    original: RequiredStatusPolicy,
    written: RequiredStatusPolicy,
    transition_error: Exception,
    *,
    operation: str,
    compensation: str,
) -> None:
    observed = _read_policy_for_recovery(
        repository, branch, operation, transition_error
    )
    if observed == original:
        raise GovernanceError(
            f"{operation} failed; safe readback confirms the original policy remains "
            f"and no compensation was required: {transition_error}"
        ) from transition_error
    if observed != written:
        raise GovernanceError(
            f"{operation} failed; remote drift was detected and not compensated: "
            f"operation={transition_error}; observed={observed.to_dict()}"
        ) from transition_error

    # A second exact read narrows the compensation race. Never issue a write when
    # another actor has moved the remote away from our exact written state.
    observed_again = _read_policy_for_recovery(
        repository, branch, operation, transition_error
    )
    if observed_again == original:
        raise GovernanceError(
            f"{operation} failed; the original policy was restored concurrently and "
            f"no compensation was required: {transition_error}"
        ) from transition_error
    if observed_again != written:
        raise GovernanceError(
            f"{operation} failed; remote drift was detected before compensation and "
            "was not compensated: "
            f"operation={transition_error}; observed={observed_again.to_dict()}"
        ) from transition_error

    try:
        patch_required_policy(repository, branch, original)
    except Exception as compensation_error:
        restored = _read_policy_for_recovery(
            repository,
            branch,
            operation,
            compensation_error,
        )
        if restored == original:
            raise GovernanceError(
                f"{operation} failed; {compensation} restored the original policy "
                f"despite a lost compensation response: {transition_error}"
            ) from compensation_error
        if restored == written:
            raise GovernanceError(
                f"{operation} failed and {compensation} did not take effect; the exact "
                "written policy remains: "
                f"operation={transition_error}; compensation={compensation_error}"
            ) from compensation_error
        raise GovernanceError(
            f"{operation} failed; remote drift appeared during compensation and was "
            "not overwritten: "
            f"operation={transition_error}; observed={restored.to_dict()}"
        ) from compensation_error

    restored = _read_policy_for_recovery(
        repository, branch, operation, transition_error
    )
    if restored != original:
        if restored == written:
            raise GovernanceError(
                f"{operation} failed and {compensation} verification found the exact "
                f"written policy still present: {transition_error}"
            ) from transition_error
        raise GovernanceError(
            f"{operation} failed; remote drift appeared after compensation and was "
            "not overwritten: "
            f"operation={transition_error}; observed={restored.to_dict()}"
        ) from transition_error
    raise GovernanceError(
        f"{operation} verification failed; {compensation} restored the original "
        f"policy: {transition_error}"
    ) from transition_error


def _recover_failed_apply(
    repository: str,
    branch: str,
    before: RequiredStatusPolicy,
    desired: RequiredStatusPolicy,
    apply_error: Exception,
) -> None:
    _recover_failed_policy_transition(
        repository,
        branch,
        before,
        desired,
        apply_error,
        operation="apply",
        compensation="automatic rollback",
    )


def _recover_failed_rollback(
    repository: str,
    branch: str,
    expected_after: RequiredStatusPolicy,
    before: RequiredStatusPolicy,
    rollback_error: Exception,
) -> None:
    _recover_failed_policy_transition(
        repository,
        branch,
        expected_after,
        before,
        rollback_error,
        operation="rollback",
        compensation="compensating roll-forward",
    )


def apply_policy(
    repository: str,
    manifest: PolicyManifest,
    *,
    evidence_sha: str,
    snapshot_out: Path,
    confirm_repository: str,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    _validate_repository(repository)
    if confirm_repository != repository:
        raise GovernanceError("--confirm-repository must exactly match --repo")
    _validate_apply_manifest_binding(manifest, manifest_path, evidence_sha)

    initial = inspect_repository(repository, manifest)
    _assert_no_rulesets(initial.effective_rules)
    state = initial.assessment.state
    if state in {PolicyState.MIXED, PolicyState.DIVERGED}:
        raise GovernanceError(f"refusing apply from fail-closed state {state.value}")

    app_ids, evidence_pull_request = _collect_evidence(
        repository, evidence_sha, manifest
    )
    desired = target_policy(manifest, app_ids)

    if state is PolicyState.TARGET:
        if initial.policy != desired:
            raise GovernanceError(
                "target contexts have unexpected GitHub App bindings; refusing mutation"
            )
        return {
            "repository": repository,
            "branch": manifest.default_branch,
            "state_before": state.value,
            "state_after": PolicyState.TARGET.value,
            "changed": False,
            "snapshot": None,
        }

    # Optimistic concurrency: re-read both control planes immediately before
    # creating the rollback snapshot and issuing the single PATCH.
    current_again = read_required_policy(repository, manifest.default_branch)
    rules_again = read_effective_rules(repository, manifest.default_branch)
    _assert_no_rulesets(rules_again)
    if current_again != initial.policy:
        raise GovernanceError("required status checks changed concurrently; apply aborted")
    _revalidate_evidence_pull_request(
        repository,
        evidence_sha,
        manifest.default_branch,
        evidence_pull_request,
    )

    snapshot_digest = write_snapshot(
        snapshot_out,
        repository,
        manifest.default_branch,
        initial.policy,
        desired,
    )
    _revalidate_evidence_pull_request(
        repository,
        evidence_sha,
        manifest.default_branch,
        evidence_pull_request,
    )
    _validate_apply_manifest_binding(manifest, manifest_path, evidence_sha)
    # Snapshot creation and evidence revalidation take time. Narrow the
    # unavoidable read/PATCH race again after those operations so a concurrent
    # administrator change is never knowingly overwritten.
    current_final = read_required_policy(repository, manifest.default_branch)
    rules_final = read_effective_rules(repository, manifest.default_branch)
    _assert_no_rulesets(rules_final)
    if current_final != initial.policy:
        raise GovernanceError(
            "required status checks changed concurrently after snapshot; apply aborted"
        )
    try:
        patch_required_policy(repository, manifest.default_branch, desired)
        readback = read_required_policy(repository, manifest.default_branch)
        if readback != desired:
            raise GovernanceError("post-apply readback does not match the target policy")
    except Exception as apply_error:
        _recover_failed_apply(
            repository,
            manifest.default_branch,
            initial.policy,
            desired,
            apply_error,
        )

    return {
        "repository": repository,
        "branch": manifest.default_branch,
        "state_before": state.value,
        "state_after": PolicyState.TARGET.value,
        "changed": True,
        "snapshot": str(snapshot_out),
        "snapshot_sha256": snapshot_digest,
        "app_ids": dict(sorted(app_ids.items())),
    }


def rollback_policy(
    repository: str,
    manifest: PolicyManifest,
    *,
    snapshot_in: Path,
    confirm_repository: str,
) -> dict[str, Any]:
    _validate_repository(repository)
    if confirm_repository != repository:
        raise GovernanceError("--confirm-repository must exactly match --repo")
    snapshot = load_snapshot(snapshot_in)
    if snapshot.get("repository") != repository:
        raise GovernanceError("snapshot repository does not match --repo")
    if snapshot.get("branch") != manifest.default_branch:
        raise GovernanceError("snapshot branch does not match the manifest default branch")

    before = _policy_from_snapshot(snapshot.get("before"), "before")
    expected_after = _policy_from_snapshot(
        snapshot.get("expected_after"), "expected_after"
    )
    current = read_required_policy(repository, manifest.default_branch)
    rules = read_effective_rules(repository, manifest.default_branch)
    _assert_no_rulesets(rules)
    if current == before:
        return {
            "repository": repository,
            "branch": manifest.default_branch,
            "changed": False,
            "restored": True,
        }
    if current != expected_after:
        raise GovernanceError(
            "current policy matches neither snapshot state; rollback aborted for drift"
        )

    current_again = read_required_policy(repository, manifest.default_branch)
    rules_again = read_effective_rules(repository, manifest.default_branch)
    _assert_no_rulesets(rules_again)
    if current_again != current:
        raise GovernanceError("required status checks changed concurrently; rollback aborted")

    try:
        patch_required_policy(repository, manifest.default_branch, before)
        readback = read_required_policy(repository, manifest.default_branch)
        if readback != before:
            raise GovernanceError("rollback readback does not match the snapshot")
    except Exception as rollback_error:
        _recover_failed_rollback(
            repository,
            manifest.default_branch,
            expected_after,
            before,
            rollback_error,
        )

    return {
        "repository": repository,
        "branch": manifest.default_branch,
        "changed": True,
        "restored": True,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reconcile classic required GitHub checks. Supplying options without "
            "a subcommand defaults to the read-only plan operation."
        )
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", required=True, help="Exact owner/repository target")
    common.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help=f"Policy manifest (default: {DEFAULT_MANIFEST})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", parents=[common], help="Read-only reconciliation plan")
    subparsers.add_parser("check", parents=[common], help="Read-only target-state check")

    apply_parser = subparsers.add_parser(
        "apply", parents=[common], help="Apply a verified classic-protection migration"
    )
    apply_parser.add_argument(
        "--evidence-sha",
        required=True,
        help="Full commit SHA whose successful CheckRuns prove every target context",
    )
    apply_parser.add_argument(
        "--snapshot-out",
        required=True,
        type=Path,
        help="New 0600 JSON snapshot path used for rollback",
    )
    apply_parser.add_argument(
        "--confirm-repository",
        required=True,
        help="Safety confirmation; must exactly equal --repo",
    )

    rollback_parser = subparsers.add_parser(
        "rollback", parents=[common], help="Restore a verified apply snapshot"
    )
    rollback_parser.add_argument(
        "--snapshot-in",
        required=True,
        type=Path,
        help="Verified 0600 snapshot produced by apply",
    )
    rollback_parser.add_argument(
        "--confirm-repository",
        required=True,
        help="Safety confirmation; must exactly equal --repo",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    commands = {"plan", "check", "apply", "rollback"}
    if not arguments:
        arguments = ["--help"]
    elif arguments[0] not in commands and arguments[0] not in {"-h", "--help"}:
        # Read-only plan is the default when the caller supplies only options.
        arguments.insert(0, "plan")

    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        manifest = load_manifest(args.manifest)
        if args.command in {"plan", "check"}:
            inspection = inspect_repository(args.repo, manifest)
            document = plan_document(inspection, manifest)
            document["command"] = args.command
            print(json.dumps(document, indent=2, sort_keys=True))
            if args.command == "check":
                healthy = (
                    inspection.assessment.state is PolicyState.TARGET
                    and not inspection.effective_rules
                )
                return 0 if healthy else 1
            return 0
        if args.command == "apply":
            result = apply_policy(
                args.repo,
                manifest,
                evidence_sha=args.evidence_sha,
                snapshot_out=args.snapshot_out,
                confirm_repository=args.confirm_repository,
                manifest_path=args.manifest,
            )
        else:
            result = rollback_policy(
                args.repo,
                manifest,
                snapshot_in=args.snapshot_in,
                confirm_repository=args.confirm_repository,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except GovernanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
