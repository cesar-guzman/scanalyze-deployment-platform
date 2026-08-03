#!/usr/bin/env python3
"""Project a fresh, sanitized GitHub protection readback into an exact PUT body.

This tool is deliberately offline. It neither calls GitHub nor authorizes a
future mutation. Operational inputs and outputs must be private files outside
the repository; only synthetic fixtures belong in Git.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

import jsonschema


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = REPO_ROOT / "governance" / "github-policy.json"
POLICY_SCHEMA = REPO_ROOT / "schemas" / "github-policy.schema.json"
EXPECTED_REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
DEFAULT_MAX_AGE_SECONDS = 300
EXPECTED_STATUS_CONTEXTS = (
    "Lint, security, and schema checks",
    "Python tests",
    "Validate deployment manifest schema",
    "Terraform validate (no AWS)",
    "Verify clean clone reproducibility",
    "Microservices validation gate",
)

ENVELOPE_FIELDS = {
    "schema_version",
    "repository",
    "branch",
    "captured_at",
    "rulesets",
    "check_app_bindings",
    "protection",
}
PROTECTION_FIELDS = {
    "url",
    "required_status_checks",
    "enforce_admins",
    "required_pull_request_reviews",
    "required_signatures",
    "required_linear_history",
    "allow_force_pushes",
    "allow_deletions",
    "block_creations",
    "required_conversation_resolution",
    "lock_branch",
    "allow_fork_syncing",
    "restrictions",
}
REQUIRED_PROTECTION_FIELDS = PROTECTION_FIELDS - {"url"}
STATUS_CHECK_FIELDS = {
    "url",
    "strict",
    "contexts",
    "contexts_url",
    "checks",
    "enforcement_level",
}
REVIEW_FIELDS = {
    "url",
    "dismissal_restrictions",
    "bypass_pull_request_allowances",
    "dismiss_stale_reviews",
    "require_code_owner_reviews",
    "require_last_push_approval",
    "required_approving_review_count",
}
REQUIRED_REVIEW_FIELDS = REVIEW_FIELDS - {"url"}
BOOLEAN_FIELDS_TO_PRESERVE = (
    "required_linear_history",
    "block_creations",
    "lock_branch",
    "allow_fork_syncing",
)


class GitHubProtectionError(ValueError):
    """Raised when an offline projection cannot be proven lossless and current."""


@dataclass(frozen=True)
class GenerationResult:
    """Deterministic result metadata safe to print without the payload."""

    payload: dict[str, Any]
    digest: str
    classifications: dict[str, dict[str, Any]]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubProtectionError(f"duplicate JSON key: {key!r}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise GitHubProtectionError(f"non-finite JSON value is prohibited: {value}")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except GitHubProtectionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GitHubProtectionError(f"unable to load JSON document {path}: {exc}") from None
    if not isinstance(document, dict):
        raise GitHubProtectionError(f"JSON document must be an object: {path}")
    return document


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise GitHubProtectionError(f"symlinked operational path is prohibited: {path}")


def _ensure_outside_repository(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    repository = REPO_ROOT.resolve()
    # APFS is commonly case-insensitive. Textual Path.relative_to checks alone
    # can therefore miss an in-repository path reached with different casing.
    # Compare every existing ancestor by filesystem identity first; this also
    # covers a not-yet-created output whose parent already exists.
    for candidate in (absolute, *absolute.parents):
        try:
            if candidate.samefile(repository):
                raise GitHubProtectionError(
                    f"operational evidence must stay outside the repository: {path}"
                )
        except OSError:
            continue

    resolved = absolute.resolve(strict=False)
    try:
        resolved.relative_to(repository)
    except ValueError:
        return
    raise GitHubProtectionError(f"operational evidence must stay outside the repository: {path}")


def _validate_private_parent(path: Path) -> None:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise GitHubProtectionError(f"unable to inspect operational directory {path}: {exc}") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise GitHubProtectionError(f"operational parent is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise GitHubProtectionError(f"operational directory must be owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise GitHubProtectionError(f"operational directory must not grant group/world access: {path}")


def _validate_private_input(path: Path) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_parent(path.parent)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GitHubProtectionError(f"unable to inspect operational input {path}: {exc}") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise GitHubProtectionError(f"operational input must be a regular file: {path}")
    if metadata.st_uid != os.getuid():
        raise GitHubProtectionError(f"operational input must be owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GitHubProtectionError(f"operational input must use mode 0600: {path}")


def _validate_new_private_output(path: Path) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_parent(path.parent)
    if path.exists() or path.is_symlink():
        raise GitHubProtectionError(f"refusing to overwrite operational output: {path}")


def _write_private_output(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise GitHubProtectionError(f"unable to create private output {path}: {exc}") from None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise GitHubProtectionError(f"generated output is not mode 0600: {path}")


def _validate_exact_fields(
    document: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    owner: str,
) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise GitHubProtectionError(f"unknown or unmapped {owner} field: {unknown[0]!r}")
    missing = sorted(required - set(document))
    if missing:
        raise GitHubProtectionError(f"missing required {owner} field: {missing[0]!r}")


def _validate_policy(policy: dict[str, Any]) -> None:
    schema = _load_json(POLICY_SCHEMA)
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(policy)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "root"
        raise GitHubProtectionError(
            f"policy schema validation failed at {location}: {exc.message}"
        ) from None
    except jsonschema.SchemaError as exc:
        raise GitHubProtectionError(f"invalid policy schema: {exc.message}") from None
    observed_contexts = tuple(
        check["context"] for check in policy["required_status_checks"]["checks"]
    )
    if observed_contexts != EXPECTED_STATUS_CONTEXTS:
        raise GitHubProtectionError(
            "policy must preserve the canonical six required status checks in order"
        )


def _parse_capture_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GitHubProtectionError("captured_at must be an RFC3339 UTC timestamp ending in Z")
    try:
        captured = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise GitHubProtectionError("captured_at must be a valid RFC3339 timestamp") from None
    if captured.tzinfo is None:
        raise GitHubProtectionError("captured_at must include a UTC offset")
    return captured.astimezone(UTC)


def _validate_envelope(
    envelope: dict[str, Any],
    policy: dict[str, Any],
    *,
    now: datetime,
    max_age_seconds: int,
) -> dict[str, Any]:
    _validate_exact_fields(
        envelope,
        allowed=ENVELOPE_FIELDS,
        required=ENVELOPE_FIELDS,
        owner="evidence envelope",
    )
    if envelope["schema_version"] != "1":
        raise GitHubProtectionError("evidence envelope schema_version must be '1'")
    if envelope["repository"] != EXPECTED_REPOSITORY:
        raise GitHubProtectionError(f"evidence repository must be {EXPECTED_REPOSITORY}")
    if envelope["branch"] != policy["default_branch"]:
        raise GitHubProtectionError("evidence branch differs from the policy default branch")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise GitHubProtectionError("current time must be timezone-aware")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
        raise GitHubProtectionError("max_age_seconds must be a positive integer")
    captured = _parse_capture_time(envelope["captured_at"])
    age = (now.astimezone(UTC) - captured).total_seconds()
    if age < -60:
        raise GitHubProtectionError("captured_at is unreasonably in the future")
    if age > max_age_seconds:
        raise GitHubProtectionError(
            f"branch-protection readback is stale ({int(age)}s > {max_age_seconds}s)"
        )
    rulesets = envelope["rulesets"]
    if not isinstance(rulesets, list):
        raise GitHubProtectionError("rulesets evidence must be an array")
    if rulesets:
        raise GitHubProtectionError(
            "ruleset/classic-protection overlap cannot be excluded; refusing projection"
        )
    protection = envelope["protection"]
    if not isinstance(protection, dict):
        raise GitHubProtectionError("protection evidence must be an object")
    _validate_exact_fields(
        protection,
        allowed=PROTECTION_FIELDS,
        required=REQUIRED_PROTECTION_FIELDS,
        owner="branch protection",
    )
    return protection


def _validate_check_app_bindings(
    value: object,
    *,
    expected_slug: str,
) -> int:
    if not isinstance(value, list) or len(value) != 1:
        raise GitHubProtectionError(
            "check_app_bindings must contain exactly the required-check producer"
        )
    binding = value[0]
    if not isinstance(binding, dict) or set(binding) != {"app_id", "slug"}:
        raise GitHubProtectionError(
            "check_app_bindings entries must contain exactly app_id and slug"
        )
    app_id = binding["app_id"]
    slug = binding["slug"]
    if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
        raise GitHubProtectionError("check_app_bindings.app_id must be positive")
    if slug != expected_slug:
        raise GitHubProtectionError(
            f"check app slug must be the policy target {expected_slug!r}"
        )
    return app_id


def _enabled_wrapper(value: object, owner: str) -> bool:
    if not isinstance(value, dict):
        raise GitHubProtectionError(f"{owner} must be a GET object with enabled")
    _validate_exact_fields(
        value,
        allowed={"url", "enabled"},
        required={"enabled"},
        owner=owner,
    )
    enabled = value["enabled"]
    if not isinstance(enabled, bool):
        raise GitHubProtectionError(f"{owner}.enabled must be boolean")
    return enabled


def _project_actor_list(
    value: object,
    *,
    field: str,
    identity_key: str,
    owner: str,
) -> list[str]:
    if not isinstance(value, list):
        raise GitHubProtectionError(f"{owner}.{field} must be an array")
    identities: list[str] = []
    seen: set[str] = set()
    for actor in value:
        if not isinstance(actor, dict) or set(actor) != {identity_key}:
            raise GitHubProtectionError(
                f"{owner}.{field} actors must be sanitized objects containing only {identity_key}"
            )
        identity = actor[identity_key]
        if not isinstance(identity, str) or not identity.strip():
            raise GitHubProtectionError(f"{owner}.{field} has an invalid {identity_key}")
        normalized = identity.casefold()
        if normalized in seen:
            raise GitHubProtectionError(f"{owner}.{field} contains a duplicate actor")
        seen.add(normalized)
        identities.append(identity)
    return identities


def _project_actor_group(
    value: object,
    *,
    owner: str,
    apps_optional: bool,
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise GitHubProtectionError(f"{owner} must be an object")
    required = {"users", "teams"} if apps_optional else {"users", "teams", "apps"}
    _validate_exact_fields(
        value,
        allowed={"users", "teams", "apps"},
        required=required,
        owner=owner,
    )
    projected = {
        "users": _project_actor_list(
            value["users"], field="users", identity_key="login", owner=owner
        ),
        "teams": _project_actor_list(
            value["teams"], field="teams", identity_key="slug", owner=owner
        ),
    }
    if "apps" in value:
        projected["apps"] = _project_actor_list(
            value["apps"], field="apps", identity_key="slug", owner=owner
        )
    if sum(len(actors) for actors in projected.values()) > 100:
        raise GitHubProtectionError(f"{owner} exceeds GitHub's 100-actor limit")
    return projected


def _project_status_checks(
    current: object,
    policy: dict[str, Any],
    *,
    expected_app_id: int,
) -> dict[str, Any]:
    if not isinstance(current, dict):
        raise GitHubProtectionError("required_status_checks must be a GET object")
    _validate_exact_fields(
        current,
        allowed=STATUS_CHECK_FIELDS,
        required={"strict", "contexts", "checks"},
        owner="required_status_checks",
    )
    if not isinstance(current["strict"], bool):
        raise GitHubProtectionError("required_status_checks.strict must be boolean")
    contexts = current["contexts"]
    checks = current["checks"]
    if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
        raise GitHubProtectionError("required_status_checks.contexts must be strings")
    if len(contexts) != len(set(contexts)):
        raise GitHubProtectionError("duplicate status check context in contexts")
    if not isinstance(checks, list):
        raise GitHubProtectionError("required_status_checks.checks must be an array")
    bindings: dict[str, int] = {}
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"context", "app_id"}:
            raise GitHubProtectionError(
                "each status check must contain exactly context and a positive app_id"
            )
        context = check["context"]
        app_id = check["app_id"]
        if not isinstance(context, str) or not context:
            raise GitHubProtectionError("status check context must be a non-empty string")
        if context in bindings:
            raise GitHubProtectionError(f"duplicate status check: {context!r}")
        if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
            raise GitHubProtectionError(
                f"status check {context!r} must retain a positive app_id"
            )
        bindings[context] = app_id
    if set(contexts) != set(bindings):
        raise GitHubProtectionError("bare contexts and app-bound checks differ")

    policy_checks = policy["required_status_checks"]["checks"]
    target_contexts = [item["context"] for item in policy_checks]
    target = set(target_contexts)
    observed = set(bindings)
    missing = sorted(target - observed)
    unexpected = sorted(observed - target)
    if missing:
        raise GitHubProtectionError(f"missing required status check: {missing[0]!r}")
    if unexpected:
        raise GitHubProtectionError(f"unexpected status check: {unexpected[0]!r}")
    if len(set(bindings.values())) != 1:
        raise GitHubProtectionError("required checks are not bound to a single GitHub App")
    if set(bindings.values()) != {expected_app_id}:
        raise GitHubProtectionError(
            "required check app_id does not match the observed expected app slug binding"
        )

    return {
        "strict": policy["required_status_checks"]["strict"],
        "contexts": [],
        "checks": [
            {"context": context, "app_id": bindings[context]}
            for context in target_contexts
        ],
    }


def _project_reviews(current: object, policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(current, dict):
        raise GitHubProtectionError("required_pull_request_reviews must be a GET object")
    _validate_exact_fields(
        current,
        allowed=REVIEW_FIELDS,
        required=REQUIRED_REVIEW_FIELDS,
        owner="required_pull_request_reviews",
    )
    for field in (
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
    ):
        if not isinstance(current[field], bool):
            raise GitHubProtectionError(f"required_pull_request_reviews.{field} must be boolean")
    count = current["required_approving_review_count"]
    if isinstance(count, bool) or not isinstance(count, int):
        raise GitHubProtectionError(
            "required_pull_request_reviews.required_approving_review_count must be integer"
        )

    dismissal = current["dismissal_restrictions"]
    if dismissal is None:
        projected_dismissal = None
    else:
        projected_dismissal = _project_actor_group(
            dismissal,
            owner="dismissal_restrictions",
            apps_optional=True,
        )
    # Parse the full current bypass surface before intentionally applying the
    # reviewed empty target. This rejects hidden or lossy actor shapes.
    _project_actor_group(
        current["bypass_pull_request_allowances"],
        owner="bypass_pull_request_allowances",
        apps_optional=False,
    )

    target = policy["required_pull_request_reviews"]
    projected: dict[str, Any] = {
        "dismiss_stale_reviews": target["dismiss_stale_reviews"],
        "require_code_owner_reviews": target["require_code_owner_reviews"],
        "required_approving_review_count": target["required_approving_review_count"],
        "require_last_push_approval": target["require_last_push_approval"],
        "bypass_pull_request_allowances": target["bypass_pull_request_allowances"],
    }
    if projected_dismissal is not None:
        projected["dismissal_restrictions"] = projected_dismissal
    return projected


def _project_restrictions(value: object) -> dict[str, list[str]] | None:
    if value is None:
        return None
    return _project_actor_group(
        value,
        owner="restrictions",
        apps_optional=True,
    )


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def generate_payload(
    input_path: Path,
    policy_path: Path,
    output_path: Path,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> GenerationResult:
    """Validate evidence and write one deterministic, private PUT payload."""

    input_path = _absolute_without_resolving(input_path)
    policy_path = _absolute_without_resolving(policy_path)
    output_path = _absolute_without_resolving(output_path)
    _validate_private_input(input_path)
    _validate_new_private_output(output_path)
    _reject_symlink_components(policy_path)
    if policy_path.resolve(strict=False) != DEFAULT_POLICY.resolve():
        raise GitHubProtectionError(
            "--policy must reference the canonical governance/github-policy.json"
        )
    envelope = _load_json(input_path)
    policy = _load_json(policy_path)
    _validate_policy(policy)
    protection = _validate_envelope(
        envelope,
        policy,
        now=now or datetime.now(UTC),
        max_age_seconds=max_age_seconds,
    )
    expected_app_id = _validate_check_app_bindings(
        envelope["check_app_bindings"],
        expected_slug=policy["required_status_checks"]["expected_app_slug"],
    )

    # These current-state values are intentionally replaced by the reviewed
    # policy target. Still parse their complete GET wrapper first so an API
    # shape change or hidden field cannot be silently discarded by the PUT.
    for field in (
        "enforce_admins",
        "required_conversation_resolution",
        "allow_force_pushes",
        "allow_deletions",
    ):
        _enabled_wrapper(protection[field], field)

    payload: dict[str, Any] = {
        "required_status_checks": _project_status_checks(
            protection["required_status_checks"],
            policy,
            expected_app_id=expected_app_id,
        ),
        "enforce_admins": policy["enforce_admins"],
        "required_pull_request_reviews": _project_reviews(
            protection["required_pull_request_reviews"], policy
        ),
        "restrictions": _project_restrictions(protection["restrictions"]),
    }
    for field in BOOLEAN_FIELDS_TO_PRESERVE:
        payload[field] = _enabled_wrapper(protection[field], field)
    payload["required_conversation_resolution"] = policy[
        "required_conversation_resolution"
    ]
    payload["allow_force_pushes"] = policy["allow_force_pushes"]
    payload["allow_deletions"] = policy["allow_deletions"]

    required_signatures = _enabled_wrapper(
        protection["required_signatures"], "required_signatures"
    )
    classifications: dict[str, dict[str, Any]] = {
        "required_signatures": {
            "action": "separate_endpoint_unchanged",
            "observed_enabled": required_signatures,
        },
        "environments": {
            "action": "separate_endpoint_not_mutated",
            "existing_environments_only": policy["environment_protection"][
                "existing_environments_only"
            ],
            "create_missing_environments": policy["environment_protection"][
                "create_missing_environments"
            ],
            "required_reviewer": policy["environment_protection"][
                "required_reviewer"
            ],
            "prevent_self_review": policy["environment_protection"][
                "prevent_self_review"
            ],
        },
        "private_vulnerability_reporting": {
            "action": "separate_endpoint_not_mutated",
            "target_enabled": policy["private_vulnerability_reporting"]["enabled"],
        },
        "auto_merge": {
            "action": "separate_endpoint_not_mutated",
            "target_enabled": policy["auto_merge"]["enabled"],
        },
    }
    content = _canonical_bytes(payload)
    digest = hashlib.sha256(content).hexdigest()
    _write_private_output(output_path, content)
    return GenerationResult(
        payload=payload,
        digest=digest,
        classifications=classifications,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline, exact branch-protection PUT payload"
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=DEFAULT_MAX_AGE_SECONDS,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = generate_payload(
            input_path=args.input,
            policy_path=args.policy,
            output_path=args.output,
            max_age_seconds=args.max_age_seconds,
        )
    except GitHubProtectionError as exc:
        print(f"FAIL: branch-protection payload was not generated\n{exc}", file=sys.stderr)
        return 1
    print("PASS: deterministic branch-protection PUT payload generated offline")
    print(f"payload_sha256={result.digest}")
    print(
        "separate_controls="
        + json.dumps(
            result.classifications,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    print("remote_mutation=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
