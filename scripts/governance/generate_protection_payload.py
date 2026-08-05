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
import tempfile
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
REQUIRED_PROTECTION_FIELDS = PROTECTION_FIELDS - {"url", "restrictions"}
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
REQUIRED_REVIEW_FIELDS = REVIEW_FIELDS - {
    "url",
    "dismissal_restrictions",
    "bypass_pull_request_allowances",
}
RAW_ACTOR_GROUP_FIELDS = {
    "users",
    "teams",
    "apps",
    "url",
    "users_url",
    "teams_url",
    "apps_url",
}


class GitHubProtectionError(ValueError):
    """Raised when an offline projection cannot be proven lossless and current."""


@dataclass(frozen=True)
class GenerationResult:
    """Deterministic result metadata safe to print without either payload."""

    payload: dict[str, Any]
    digest: str
    recovery_payload: dict[str, Any]
    recovery_digest: str
    recovery_mode: str
    raw_input_digest: str
    input_digest: str
    policy_digest: str
    completion_manifest: dict[str, Any]
    completion_digest: str
    classifications: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class ParsedProtection:
    """One canonical semantic parse shared by target and recovery builders."""

    required_status_checks: dict[str, Any]
    enforce_admins: bool
    required_pull_request_reviews: dict[str, Any]
    restrictions: dict[str, list[str]] | None
    required_signatures: bool
    required_linear_history: bool
    allow_force_pushes: bool
    allow_deletions: bool
    block_creations: bool
    required_conversation_resolution: bool
    lock_branch: bool
    allow_fork_syncing: bool


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubProtectionError(f"duplicate JSON key: {key!r}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise GitHubProtectionError(f"non-finite JSON value is prohibited: {value}")


def _load_json_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        content = path.read_bytes()
        document = json.loads(
            content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except GitHubProtectionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GitHubProtectionError(f"unable to load JSON document {path}: {exc}") from None
    if not isinstance(document, dict):
        raise GitHubProtectionError(f"JSON document must be an object: {path}")
    return document, content


def _load_json(path: Path) -> dict[str, Any]:
    document, _ = _load_json_bytes(path)
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
    """Fully sync a private temporary file, then publish it without overwrite."""

    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            if stat.S_IMODE(os.fstat(output.fileno()).st_mode) != 0o600:
                raise GitHubProtectionError(
                    f"generated temporary output is not mode 0600: {path}"
                )
        # All fallible content operations happen before this atomic,
        # no-overwrite publication step. Never unlink the published path: a
        # later failure may race with a replacement. The completion manifest,
        # written last, is the only bundle commit marker.
        os.link(temporary_path, path, follow_symlinks=False)
    except GitHubProtectionError:
        raise
    except OSError as exc:
        raise GitHubProtectionError(
            f"unable to atomically create private output {path}: {exc}"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


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
        if identity != identity.strip():
            raise GitHubProtectionError(
                f"{owner}.{field} {identity_key} must not contain surrounding whitespace"
            )
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


def _project_raw_actor_list(
    value: object,
    *,
    field: str,
    identity_key: str,
    owner: str,
) -> list[str]:
    """Project authenticated raw GitHub actors to the sanitized identity surface."""

    if not isinstance(value, list):
        raise GitHubProtectionError(f"raw {owner}.{field} must be an array")
    identities: list[str] = []
    seen: set[str] = set()
    for actor in value:
        if not isinstance(actor, dict) or identity_key not in actor:
            raise GitHubProtectionError(
                f"raw {owner}.{field} actors must contain {identity_key}"
            )
        identity = actor[identity_key]
        if not isinstance(identity, str) or not identity.strip():
            raise GitHubProtectionError(
                f"raw {owner}.{field} has an invalid {identity_key}"
            )
        if identity != identity.strip():
            raise GitHubProtectionError(
                f"raw {owner}.{field} {identity_key} has surrounding whitespace"
            )
        normalized = identity.casefold()
        if normalized in seen:
            raise GitHubProtectionError(f"raw {owner}.{field} contains a duplicate actor")
        seen.add(normalized)
        identities.append(identity)
    return identities


def _project_raw_actor_group(
    value: object,
    *,
    owner: str,
    apps_optional: bool,
) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise GitHubProtectionError(f"raw {owner} must be an object")
    required = {"users", "teams"} if apps_optional else {"users", "teams", "apps"}
    _validate_exact_fields(
        value,
        allowed=RAW_ACTOR_GROUP_FIELDS,
        required=required,
        owner=f"raw {owner}",
    )
    for metadata_field in RAW_ACTOR_GROUP_FIELDS - {"users", "teams", "apps"}:
        if metadata_field in value and not isinstance(value[metadata_field], str):
            raise GitHubProtectionError(
                f"raw {owner}.{metadata_field} must be a string"
            )
    projected = {
        "users": _project_raw_actor_list(
            value["users"], field="users", identity_key="login", owner=owner
        ),
        "teams": _project_raw_actor_list(
            value["teams"], field="teams", identity_key="slug", owner=owner
        ),
    }
    if "apps" in value:
        projected["apps"] = _project_raw_actor_list(
            value["apps"], field="apps", identity_key="slug", owner=owner
        )
    if sum(len(actors) for actors in projected.values()) > 100:
        raise GitHubProtectionError(f"raw {owner} exceeds GitHub's 100-actor limit")
    return projected


def _actor_group_semantics(
    container: dict[str, Any],
    field: str,
    *,
    owner: str,
    apps_optional: bool,
    raw: bool,
) -> dict[str, list[str]] | None:
    value = container.get(field)
    if value is None:
        return None
    projector = _project_raw_actor_group if raw else _project_actor_group
    return projector(value, owner=owner, apps_optional=apps_optional)


def _validate_raw_actor_provenance(
    raw_protection: dict[str, Any],
    protection: dict[str, Any],
    *,
    branch: str,
) -> dict[str, Any]:
    """Bind nullable/omitted sanitized groups to the authenticated raw GET shape."""

    _validate_exact_fields(
        raw_protection,
        allowed=PROTECTION_FIELDS,
        required=REQUIRED_PROTECTION_FIELDS | {"url"},
        owner="raw branch protection",
    )
    expected_url = (
        f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/branches/{branch}/protection"
    )
    if raw_protection["url"] != expected_url:
        raise GitHubProtectionError("raw branch-protection URL differs from repository/branch")

    raw_reviews = raw_protection["required_pull_request_reviews"]
    sanitized_reviews = protection["required_pull_request_reviews"]
    if not isinstance(raw_reviews, dict):
        raise GitHubProtectionError("raw required_pull_request_reviews must be an object")
    if not isinstance(sanitized_reviews, dict):
        raise GitHubProtectionError("required_pull_request_reviews must be an object")
    _validate_exact_fields(
        raw_reviews,
        allowed=REVIEW_FIELDS,
        required=REQUIRED_REVIEW_FIELDS,
        owner="raw required_pull_request_reviews",
    )

    groups = (
        (
            raw_reviews,
            sanitized_reviews,
            "dismissal_restrictions",
            "dismissal_restrictions",
            True,
        ),
        (
            raw_reviews,
            sanitized_reviews,
            "bypass_pull_request_allowances",
            "bypass_pull_request_allowances",
            False,
        ),
        (raw_protection, protection, "restrictions", "restrictions", True),
    )
    provenance: dict[str, Any] = {}
    for raw_container, sanitized_container, field, owner, apps_optional in groups:
        raw_semantics = _actor_group_semantics(
            raw_container,
            field,
            owner=owner,
            apps_optional=apps_optional,
            raw=True,
        )
        sanitized_semantics = _actor_group_semantics(
            sanitized_container,
            field,
            owner=owner,
            apps_optional=apps_optional,
            raw=False,
        )
        if raw_semantics != sanitized_semantics:
            raise GitHubProtectionError(
                f"sanitized {owner} does not match authenticated raw evidence"
            )
        provenance[owner] = {
            "raw_presence": (
                "omitted"
                if field not in raw_container
                else "null"
                if raw_container[field] is None
                else "object"
            ),
            "semantic_actor_count": (
                0
                if raw_semantics is None
                else sum(len(actors) for actors in raw_semantics.values())
            ),
        }
    return provenance


def _parse_status_checks(
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
        "strict": current["strict"],
        "checks": [
            {"context": context, "app_id": bindings[context]}
            for context in target_contexts
        ],
    }


def _parse_reviews(
    current: object,
    *,
    raw_actor_groups: bool = False,
) -> dict[str, Any]:
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
    if not 0 <= count <= 6:
        raise GitHubProtectionError(
            "required_pull_request_reviews.required_approving_review_count must be 0..6"
        )

    actor_projector = (
        _project_raw_actor_group if raw_actor_groups else _project_actor_group
    )
    dismissal = current.get("dismissal_restrictions")
    if dismissal is None:
        projected_dismissal = None
    else:
        projected_dismissal = actor_projector(
            dismissal,
            owner="dismissal_restrictions",
            apps_optional=True,
        )
    bypass = current.get("bypass_pull_request_allowances")
    projected_bypass = (
        {"users": [], "teams": [], "apps": []}
        if bypass is None
        else actor_projector(
            bypass,
            owner="bypass_pull_request_allowances",
            apps_optional=False,
        )
    )
    projected: dict[str, Any] = {
        "dismiss_stale_reviews": current["dismiss_stale_reviews"],
        "require_code_owner_reviews": current["require_code_owner_reviews"],
        "required_approving_review_count": count,
        "require_last_push_approval": current["require_last_push_approval"],
        "bypass_pull_request_allowances": projected_bypass,
    }
    if projected_dismissal is not None:
        projected["dismissal_restrictions"] = projected_dismissal
    return projected


def _project_restrictions(
    value: object,
    *,
    raw_actor_group: bool = False,
) -> dict[str, list[str]] | None:
    if value is None:
        return None
    actor_projector = (
        _project_raw_actor_group if raw_actor_group else _project_actor_group
    )
    return actor_projector(
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


def _put_reviews(reviews: dict[str, Any]) -> dict[str, Any]:
    """Return the GitHub PUT representation for review protections.

    GitHub rejects user/team restriction shapes on personal repositories, even
    when their arrays are empty. Omitting an empty bypass allowance encodes the
    same zero-actor policy without sending an organization-only shape.
    """

    projected = dict(reviews)
    bypass = projected.get("bypass_pull_request_allowances")
    if bypass is not None and not any(
        bypass[actor_type] for actor_type in ("users", "teams", "apps")
    ):
        projected.pop("bypass_pull_request_allowances")
    return projected


def _parse_protection(
    protection: dict[str, Any],
    policy: dict[str, Any],
    *,
    expected_app_id: int,
    raw_actor_groups: bool = False,
) -> ParsedProtection:
    """Parse every mapped GET field once before building either PUT body."""

    return ParsedProtection(
        required_status_checks=_parse_status_checks(
            protection["required_status_checks"],
            policy,
            expected_app_id=expected_app_id,
        ),
        enforce_admins=_enabled_wrapper(protection["enforce_admins"], "enforce_admins"),
        required_pull_request_reviews=_parse_reviews(
            protection["required_pull_request_reviews"],
            raw_actor_groups=raw_actor_groups,
        ),
        restrictions=_project_restrictions(
            protection.get("restrictions"),
            raw_actor_group=raw_actor_groups,
        ),
        required_signatures=_enabled_wrapper(
            protection["required_signatures"], "required_signatures"
        ),
        required_linear_history=_enabled_wrapper(
            protection["required_linear_history"], "required_linear_history"
        ),
        allow_force_pushes=_enabled_wrapper(
            protection["allow_force_pushes"], "allow_force_pushes"
        ),
        allow_deletions=_enabled_wrapper(
            protection["allow_deletions"], "allow_deletions"
        ),
        block_creations=_enabled_wrapper(protection["block_creations"], "block_creations"),
        required_conversation_resolution=_enabled_wrapper(
            protection["required_conversation_resolution"],
            "required_conversation_resolution",
        ),
        lock_branch=_enabled_wrapper(protection["lock_branch"], "lock_branch"),
        allow_fork_syncing=_enabled_wrapper(
            protection["allow_fork_syncing"], "allow_fork_syncing"
        ),
    )


def _validate_full_raw_projection(
    raw: ParsedProtection,
    sanitized: ParsedProtection,
) -> None:
    """Require every mapped sanitized control to equal authenticated raw GET."""

    for field_name in ParsedProtection.__dataclass_fields__:
        if getattr(raw, field_name) != getattr(sanitized, field_name):
            raise GitHubProtectionError(
                "sanitized branch protection does not match authenticated raw "
                f"evidence for {field_name}"
            )


def _target_payload(parsed: ParsedProtection, policy: dict[str, Any]) -> dict[str, Any]:
    target_reviews = policy["required_pull_request_reviews"]
    projected_reviews: dict[str, Any] = {
        "dismiss_stale_reviews": target_reviews["dismiss_stale_reviews"],
        "require_code_owner_reviews": target_reviews["require_code_owner_reviews"],
        "required_approving_review_count": target_reviews[
            "required_approving_review_count"
        ],
        "require_last_push_approval": target_reviews["require_last_push_approval"],
        "bypass_pull_request_allowances": target_reviews[
            "bypass_pull_request_allowances"
        ],
    }
    if "dismissal_restrictions" in parsed.required_pull_request_reviews:
        projected_reviews["dismissal_restrictions"] = parsed.required_pull_request_reviews[
            "dismissal_restrictions"
        ]
    projected_reviews = _put_reviews(projected_reviews)
    return {
        "required_status_checks": {
            **parsed.required_status_checks,
            "strict": policy["required_status_checks"]["strict"],
        },
        "enforce_admins": policy["enforce_admins"],
        "required_pull_request_reviews": projected_reviews,
        "restrictions": parsed.restrictions,
        "required_linear_history": parsed.required_linear_history,
        "block_creations": parsed.block_creations,
        "lock_branch": parsed.lock_branch,
        "allow_fork_syncing": parsed.allow_fork_syncing,
        "required_conversation_resolution": policy[
            "required_conversation_resolution"
        ],
        "allow_force_pushes": policy["allow_force_pushes"],
        "allow_deletions": policy["allow_deletions"],
    }


def _exact_before_payload(parsed: ParsedProtection) -> dict[str, Any]:
    return {
        "required_status_checks": parsed.required_status_checks,
        "enforce_admins": parsed.enforce_admins,
        "required_pull_request_reviews": _put_reviews(
            parsed.required_pull_request_reviews
        ),
        "restrictions": parsed.restrictions,
        "required_linear_history": parsed.required_linear_history,
        "block_creations": parsed.block_creations,
        "lock_branch": parsed.lock_branch,
        "allow_fork_syncing": parsed.allow_fork_syncing,
        "required_conversation_resolution": parsed.required_conversation_resolution,
        "allow_force_pushes": parsed.allow_force_pushes,
        "allow_deletions": parsed.allow_deletions,
    }


def _recovery_floor_violations(payload: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    status_checks = payload["required_status_checks"]
    checks = status_checks["checks"]
    observed_contexts = tuple(check["context"] for check in checks)
    observed_app_ids = {check["app_id"] for check in checks}
    if status_checks["strict"] is not True:
        violations.append("strict_required_checks_disabled")
    if "contexts" in status_checks:
        violations.append("bare_required_check_contexts_present")
    if observed_contexts != EXPECTED_STATUS_CONTEXTS:
        violations.append("required_check_contract_changed")
    invalid_app_id = any(
        isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0
        for app_id in observed_app_ids
    )
    if len(observed_app_ids) != 1 or invalid_app_id:
        violations.append("required_check_app_binding_invalid")

    reviews = payload["required_pull_request_reviews"]
    if reviews["required_approving_review_count"] < 1:
        violations.append("required_approving_review_count_below_one")
    if reviews["require_code_owner_reviews"] is not True:
        violations.append("code_owner_review_disabled")
    if reviews["dismiss_stale_reviews"] is not True:
        violations.append("stale_review_dismissal_disabled")
    if reviews["require_last_push_approval"] is not True:
        violations.append("last_push_approval_disabled")
    bypass = reviews.get("bypass_pull_request_allowances")
    if bypass is not None and any(
        bypass[actor_type] for actor_type in ("users", "teams", "apps")
    ):
        violations.append("bypass_actors_present")
    if payload["required_conversation_resolution"] is not True:
        violations.append("conversation_resolution_disabled")
    if payload["enforce_admins"] is not True:
        violations.append("admin_enforcement_disabled")
    if payload["allow_force_pushes"] is not False:
        violations.append("force_push_allowed")
    if payload["allow_deletions"] is not False:
        violations.append("branch_deletion_allowed")
    return violations


def generate_payload(
    input_path: Path,
    raw_input_path: Path,
    policy_path: Path,
    output_path: Path,
    recovery_output_path: Path,
    completion_output_path: Path,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> GenerationResult:
    """Write a deterministic target/recovery bundle with a commit manifest."""

    input_path = _absolute_without_resolving(input_path)
    raw_input_path = _absolute_without_resolving(raw_input_path)
    policy_path = _absolute_without_resolving(policy_path)
    output_path = _absolute_without_resolving(output_path)
    recovery_output_path = _absolute_without_resolving(recovery_output_path)
    completion_output_path = _absolute_without_resolving(completion_output_path)
    _validate_private_input(input_path)
    _validate_private_input(raw_input_path)
    if input_path == raw_input_path:
        raise GitHubProtectionError("sanitized and raw operational inputs must differ")
    output_paths = {output_path, recovery_output_path, completion_output_path}
    if len(output_paths) != 3:
        raise GitHubProtectionError(
            "target, recovery, and completion output paths must differ"
        )
    _validate_new_private_output(output_path)
    _validate_new_private_output(recovery_output_path)
    _validate_new_private_output(completion_output_path)
    _reject_symlink_components(policy_path)
    if policy_path.resolve(strict=False) != DEFAULT_POLICY.resolve():
        raise GitHubProtectionError(
            "--policy must reference the canonical governance/github-policy.json"
        )
    envelope, input_bytes = _load_json_bytes(input_path)
    input_digest = hashlib.sha256(input_bytes).hexdigest()
    raw_protection, raw_input_bytes = _load_json_bytes(raw_input_path)
    raw_input_digest = hashlib.sha256(raw_input_bytes).hexdigest()
    policy, policy_bytes = _load_json_bytes(policy_path)
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
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
    actor_provenance = _validate_raw_actor_provenance(
        raw_protection,
        protection,
        branch=envelope["branch"],
    )
    parsed = _parse_protection(
        protection,
        policy,
        expected_app_id=expected_app_id,
    )
    raw_parsed = _parse_protection(
        raw_protection,
        policy,
        expected_app_id=expected_app_id,
        raw_actor_groups=True,
    )
    _validate_full_raw_projection(raw_parsed, parsed)
    payload = _target_payload(parsed, policy)
    target_violations = _recovery_floor_violations(payload)
    if target_violations:
        raise GitHubProtectionError(
            "RECOVERY_NOT_PROVABLE: target violates non-weaker floor: "
            + target_violations[0]
        )

    exact_before = _exact_before_payload(parsed)
    before_violations = _recovery_floor_violations(exact_before)
    if before_violations:
        recovery_mode = "FORWARD_ONLY_TARGET"
        recovery_payload = payload
        rollback_disposition = "ROLLBACK_NOT_PROVABLE"
    else:
        recovery_mode = "EXACT_BEFORE"
        recovery_payload = exact_before
        rollback_disposition = "EXACT_BEFORE"

    content = _canonical_bytes(payload)
    digest = hashlib.sha256(content).hexdigest()
    recovery_content = _canonical_bytes(recovery_payload)
    recovery_digest = hashlib.sha256(recovery_content).hexdigest()
    completion_manifest: dict[str, Any] = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_projection_bundle",
        "raw_input_sha256": raw_input_digest,
        "sanitized_input_sha256": input_digest,
        "policy_sha256": policy_digest,
        "target_payload_sha256": digest,
        "recovery_payload_sha256": recovery_digest,
        "recovery_mode": recovery_mode,
        "remote_mutation": "NONE",
    }
    completion_content = _canonical_bytes(completion_manifest)
    completion_digest = hashlib.sha256(completion_content).hexdigest()
    classifications: dict[str, dict[str, Any]] = {
        "raw_actor_provenance": actor_provenance,
        "recovery": {
            "strategy": recovery_mode,
            "rollback_disposition": rollback_disposition,
            "before_floor_violations": before_violations,
            "requires_fresh_readback": True,
            "requires_independent_review": True,
            "requires_owner_authorization": True,
            "target_payload_sha256": digest,
            "recovery_payload_sha256": recovery_digest,
            "completion_manifest_sha256": completion_digest,
        },
        "required_signatures": {
            "action": "separate_endpoint_unchanged",
            "observed_enabled": parsed.required_signatures,
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
    # The completion manifest is the commit marker. A bundle without it and a
    # successful PASS is incomplete and must never be used. Earlier payloads
    # may remain after a failure, but this function never deletes a published
    # path and therefore cannot unlink a concurrent replacement.
    _write_private_output(recovery_output_path, recovery_content)
    _write_private_output(output_path, content)
    _write_private_output(completion_output_path, completion_content)
    return GenerationResult(
        payload=payload,
        digest=digest,
        recovery_payload=recovery_payload,
        recovery_digest=recovery_digest,
        recovery_mode=recovery_mode,
        raw_input_digest=raw_input_digest,
        input_digest=input_digest,
        policy_digest=policy_digest,
        completion_manifest=completion_manifest,
        completion_digest=completion_digest,
        classifications=classifications,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline target/recovery bundle with commit manifest"
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--raw-input", required=True, type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--recovery-output", required=True, type=Path)
    parser.add_argument("--completion-output", required=True, type=Path)
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
            raw_input_path=args.raw_input,
            policy_path=args.policy,
            output_path=args.output,
            recovery_output_path=args.recovery_output,
            completion_output_path=args.completion_output,
            max_age_seconds=args.max_age_seconds,
        )
    except GitHubProtectionError as exc:
        print(f"FAIL: branch-protection payload was not generated\n{exc}", file=sys.stderr)
        return 1
    print("PASS: deterministic target/recovery bundle generated offline")
    print(f"raw_input_sha256={result.raw_input_digest}")
    print(f"sanitized_input_sha256={result.input_digest}")
    print(f"policy_sha256={result.policy_digest}")
    print(f"target_payload_sha256={result.digest}")
    print(f"recovery_payload_sha256={result.recovery_digest}")
    print(f"recovery_mode={result.recovery_mode}")
    print(f"completion_manifest_sha256={result.completion_digest}")
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
