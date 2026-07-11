#!/usr/bin/env python3
"""Validate the repository's GitHub required-check contract offline.

The validator deliberately treats a required check name as a compatibility API.
It rejects dynamic name collisions across workflows, matrix contexts,
workflow-level PR path filters, privileged required dependency closures, and
required jobs that can disappear or tolerate failures dynamically.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import jsonschema
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO_ROOT / "governance" / "github-policy.json"
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "github-policy.schema.json"
DEFAULT_WORKFLOWS = REPO_ROOT / ".github" / "workflows"
REQUIRED_PR_ACTIVITY_TYPES = frozenset({"opened", "synchronize", "reopened"})


class GitHubPolicyError(ValueError):
    """Raised when the declared policy and workflow implementation diverge."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubPolicyError(f"unable to load JSON document {path}: {exc}") from None
    if not isinstance(document, dict):
        raise GitHubPolicyError(f"JSON document must be an object: {path}")
    return document


def _load_workflow(path: Path) -> dict[str, Any]:
    try:
        # BaseLoader preserves the key `on` instead of applying YAML 1.1 boolean
        # coercion. GitHub Actions owns the final workflow syntax validation.
        document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise GitHubPolicyError(f"unable to load workflow {path}: {exc}") from None
    if not isinstance(document, dict):
        raise GitHubPolicyError(f"workflow must be a mapping: {path}")
    return document


def _normalize_condition(value: object) -> str:
    condition = str(value or "").strip()
    if condition.startswith("${{") and condition.endswith("}}"):
        condition = condition[3:-2].strip()
    return "".join(condition.split())


def _read_only_permissions_error(permissions: object, owner: str) -> str | None:
    """Return an error unless GitHub permissions are explicitly read-only or empty."""

    if isinstance(permissions, str):
        if permissions.strip().lower() == "read-all":
            return None
        return f"{owner} permissions must be read-only or empty"
    if not isinstance(permissions, dict):
        return f"{owner} permissions must be read-only or empty"

    for scope, raw_access in permissions.items():
        access = str(raw_access).strip().lower()
        if str(scope).strip().lower() == "id-token":
            if access == "write":
                return (
                    f"{owner} cannot grant id-token: write; "
                    "permissions must be read-only or empty"
                )
            if access != "none":
                return f"{owner} permissions must be read-only or empty"
        elif access not in {"read", "none"}:
            return f"{owner} permissions must be read-only or empty"
    return None


def _job_authority_errors(
    job: dict[str, Any], workflow_permissions: object, owner: str
) -> list[str]:
    """Reject authority and failure-tolerance on a required PR execution path."""

    errors: list[str] = []
    if "environment" in job:
        errors.append(f"{owner} cannot target a deployment Environment")
    if "continue-on-error" in job:
        continue_on_error = str(job["continue-on-error"]).strip().lower()
        if continue_on_error != "false":
            errors.append(
                f"{owner} cannot continue on error; only literal false is permitted"
            )

    effective_permissions = (
        job["permissions"] if "permissions" in job else workflow_permissions
    )
    permission_error = _read_only_permissions_error(effective_permissions, owner)
    if permission_error:
        errors.append(permission_error)
    return errors


def _required_job_closure(
    jobs: dict[str, Any], root_job_id: str, context: str
) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """Return the required job plus every transitive ``needs`` dependency."""

    closure: list[tuple[str, dict[str, Any]]] = []
    errors: list[str] = []
    pending = [root_job_id]
    seen: set[str] = set()
    while pending:
        job_id = pending.pop()
        if job_id in seen:
            continue
        seen.add(job_id)
        job = jobs.get(job_id)
        if not isinstance(job, dict):
            errors.append(f"{context}: dependency job {job_id!r} does not exist")
            continue
        closure.append((job_id, job))

        needs = job.get("needs")
        if needs is None:
            continue
        raw_dependencies = needs if isinstance(needs, list) else [needs]
        for raw_dependency in raw_dependencies:
            dependency = str(raw_dependency).strip()
            if not dependency:
                errors.append(f"{context}: job {job_id!r} has an invalid needs entry")
                continue
            pending.append(dependency)
    return closure, errors


def _dynamic_name_matches_context(name: str, context: str) -> bool:
    """Conservatively model every GitHub expression as an arbitrary string."""

    if "${{" not in name:
        return False

    parts: list[str] = []
    cursor = 0
    while True:
        start = name.find("${{", cursor)
        if start < 0:
            parts.append(re.escape(name[cursor:]))
            break
        parts.append(re.escape(name[cursor:start]))
        parts.append(".*")
        end = name.find("}}", start + 3)
        if end < 0:
            cursor = len(name)
            break
        cursor = end + 2
    return re.fullmatch("".join(parts), context) is not None


def _as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _validate_pr_trigger(
    workflow: dict[str, Any], workflow_path: Path, default_branch: str
) -> list[str]:
    errors: list[str] = []
    triggers = workflow.get("on")
    if not isinstance(triggers, dict) or "pull_request" not in triggers:
        return [f"{workflow_path}: required-check workflow must run on pull_request"]

    pull_request = triggers.get("pull_request")
    if pull_request is None or pull_request == "":
        return errors
    if not isinstance(pull_request, dict):
        return [f"{workflow_path}: pull_request configuration must be a mapping"]

    for filter_name in ("paths", "paths-ignore"):
        if filter_name in pull_request:
            errors.append(
                f"{workflow_path}: required-check workflow cannot use pull_request.{filter_name}"
            )

    branches = _as_string_list(pull_request.get("branches"))
    branches_ignore = _as_string_list(pull_request.get("branches-ignore"))
    if branches and default_branch not in branches:
        errors.append(
            f"{workflow_path}: pull_request.branches does not include {default_branch!r}"
        )
    if default_branch in branches_ignore:
        errors.append(
            f"{workflow_path}: pull_request.branches-ignore excludes {default_branch!r}"
        )
    if "types" in pull_request:
        activity_types = set(_as_string_list(pull_request.get("types")))
        if not REQUIRED_PR_ACTIVITY_TYPES <= activity_types:
            errors.append(
                f"{workflow_path}: pull_request.types must include "
                "opened, synchronize, and reopened"
            )
    return errors


def validate_policy(
    *,
    repo_root: Path = REPO_ROOT,
    policy_path: Path = DEFAULT_POLICY,
    schema_path: Path = DEFAULT_SCHEMA,
    workflows_dir: Path = DEFAULT_WORKFLOWS,
) -> dict[str, Any]:
    """Validate policy/schema/workflow consistency and return the policy."""

    repo_root = repo_root.resolve()
    policy = _load_json(policy_path.resolve())
    schema = _load_json(schema_path.resolve())
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(policy)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "root"
        raise GitHubPolicyError(
            f"GitHub policy schema validation failed at {location}: {exc.message}"
        ) from None
    except jsonschema.SchemaError as exc:
        raise GitHubPolicyError(f"invalid GitHub policy schema: {exc.message}") from None

    required = policy["required_status_checks"]
    checks = required["checks"]
    contexts = [str(check["context"]) for check in checks]
    if len(contexts) != len(set(contexts)):
        raise GitHubPolicyError("required status-check contexts must be unique")

    migration = policy["migration"]
    added = set(str(item) for item in migration["added_contexts"])
    retired = set(str(item) for item in migration["retired_contexts"])
    target = set(contexts)
    if not added <= target:
        raise GitHubPolicyError("migration.added_contexts must be target required checks")
    if target & retired:
        raise GitHubPolicyError("target and retired status-check contexts must be disjoint")
    legacy = (target - added) | retired
    if not legacy:
        raise GitHubPolicyError("derived legacy status-check set cannot be empty")

    workflow_documents: dict[Path, dict[str, Any]] = {}
    static_producers: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    dynamic_producers: list[tuple[Path, str, str]] = []
    for workflow_path in sorted(workflows_dir.glob("*.y*ml")):
        document = _load_workflow(workflow_path)
        workflow_documents[workflow_path.resolve()] = document
        jobs = document.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            name = str(job.get("name", "")).strip()
            if name and "${{" not in name:
                static_producers[name].append((workflow_path.resolve(), str(job_id)))
            elif name:
                dynamic_producers.append(
                    (workflow_path.resolve(), str(job_id), name)
                )

    errors: list[str] = []
    default_branch = str(policy["default_branch"])
    checked_workflows: set[Path] = set()
    for check in checks:
        context = str(check["context"])
        relative_workflow = Path(str(check["workflow"]))
        workflow_path = (repo_root / relative_workflow).resolve()
        try:
            workflow_path.relative_to(repo_root)
        except ValueError:
            errors.append(f"{context}: workflow path escapes repository")
            continue

        workflow = workflow_documents.get(workflow_path)
        if workflow is None:
            errors.append(f"{context}: workflow does not exist: {relative_workflow}")
            continue
        if workflow_path not in checked_workflows:
            errors.extend(_validate_pr_trigger(workflow, relative_workflow, default_branch))
            if "permissions" in workflow:
                permission_error = _read_only_permissions_error(
                    workflow["permissions"],
                    f"{relative_workflow}: required-check workflow",
                )
                if permission_error:
                    errors.append(permission_error)
            checked_workflows.add(workflow_path)

        jobs = workflow.get("jobs")
        job_id = str(check["job"])
        job = jobs.get(job_id) if isinstance(jobs, dict) else None
        if not isinstance(job, dict):
            errors.append(f"{context}: producer job {job_id!r} does not exist")
            continue
        if str(job.get("name", "")) != context:
            errors.append(
                f"{context}: producer name is {job.get('name')!r}, expected exact context"
            )
        strategy = job.get("strategy")
        if isinstance(strategy, dict) and "matrix" in strategy:
            errors.append(f"{context}: a required check cannot be a matrix job")
        condition = _normalize_condition(job.get("if"))
        if condition and condition != "always()":
            errors.append(f"{context}: required job condition must be exactly always()")
        if job.get("needs") is not None and condition != "always()":
            errors.append(f"{context}: dependent required job must use if: always()")
        closure, closure_errors = _required_job_closure(jobs, job_id, context)
        errors.extend(closure_errors)
        for closure_job_id, closure_job in closure:
            owner = (
                f"{context}: required PR check"
                if closure_job_id == job_id
                else f"{context}: required dependency {closure_job_id!r}"
            )
            errors.extend(
                _job_authority_errors(
                    closure_job,
                    workflow.get("permissions"),
                    owner,
                )
            )

        producers = static_producers.get(context, [])
        if producers != [(workflow_path, job_id)]:
            rendered = ", ".join(f"{path.name}:{producer}" for path, producer in producers)
            errors.append(
                f"{context}: context must have exactly one static producer; found {rendered or 'none'}"
            )
        for dynamic_path, dynamic_job_id, dynamic_name in dynamic_producers:
            if _dynamic_name_matches_context(dynamic_name, context):
                rendered_path = dynamic_path.relative_to(repo_root)
                errors.append(
                    f"{rendered_path}:{dynamic_job_id}: dynamic job name could "
                    f"resolve to required context {context!r}"
                )

    if errors:
        raise GitHubPolicyError("\n".join(f"- {error}" for error in errors))

    policy["_derived"] = {
        "target_contexts": sorted(target),
        "legacy_contexts": sorted(legacy),
    }
    return policy


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate repository-global GitHub required-check governance offline"
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--workflows-dir", type=Path, default=DEFAULT_WORKFLOWS)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        policy = validate_policy(
            repo_root=args.repo_root,
            policy_path=args.policy,
            schema_path=args.schema,
            workflows_dir=args.workflows_dir,
        )
    except GitHubPolicyError as exc:
        print(f"FAIL: GitHub governance policy is invalid\n{exc}", file=sys.stderr)
        return 1

    derived = policy["_derived"]
    print("PASS: GitHub governance policy is schema-valid and workflow-bound")
    print(f"Target required checks: {len(derived['target_contexts'])}")
    print(f"Legacy required checks: {len(derived['legacy_contexts'])}")
    print("Client-specific check contexts: prohibited")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
