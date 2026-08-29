"""Collect a stable, read-only GitHub deployment identity and evidence anchor.

The collector runs in the protected job immediately before OIDC.  It combines
one private, reviewed identity template with two identical snapshots obtained
using a repository-scoped GitHub App installation token.  A short-lived App JWT
independently verifies the installation identity and exact read-only permissions.
Environment, repository, and effective organization variable values; secret
name inventories; and OIDC settings are all bound.  Tokens, secret values, and
raw responses are never persisted or printed.
"""
from __future__ import annotations

import base64
import copy
import http.client
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote

import jsonschema
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tooling.validate_github_deployment_identity import (
    DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA,
    DEFAULT_SCHEMA,
    _validate_environment,
    _validate_workflow_and_oidc,
    canonical_digest,
    derive_oidc_subject,
    environment_configuration_digest,
)


GITHUB_API_VERSION = "2026-03-10"
GITHUB_API_HOST = "api.github.com"
MAX_RESPONSE_BYTES = 1_048_576
MAX_TEMPLATE_BYTES = 1_048_576
MAX_APP_PRIVATE_KEY_BYTES = 32_768
MAX_COLLECTION_ITEMS = 1_000
MAX_COLLECTION_PAGES = 100
ANCHOR_LIFETIME = timedelta(minutes=10)
IDENTITY_FILENAME = "github-deployment-identity.json"
ANCHOR_FILENAME = "github-environment-anchor.json"

REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
OWNER_COMPONENT = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$"
)
ENVIRONMENT_NAME = re.compile(
    r"^scanalyze-dep_[0-9A-HJKMNP-TV-Z]{26}-(?:sandbox|dev|staging|production)$"
)
TOKEN_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
CONFIGURATION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")
EXPECTED_CLAIM_KEYS = (
    "repository_owner_id",
    "repository_id",
    "context",
    "workflow_ref",
    "event_name",
)
EXPECTED_ENVIRONMENT_VARIABLES = frozenset(
    {
        "CUSTOMER_ID",
        "DEPLOYMENT_ID",
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "LOGICAL_ENVIRONMENT",
        "OIDC_ORCHESTRATOR_ROLE_ARN",
        "ORCHESTRATOR_ROLE_ARN",
        "GENERIC_PLAN_ROLE_ARN",
        "GENERIC_APPLY_ROLE_ARN",
        "IDENTITY_PLAN_ROLE_ARN",
        "IDENTITY_APPLY_ROLE_ARN",
        "PLATFORM_AUTHORITY_ACCOUNT_ID",
        "REPOSITORY_ID",
        "REPOSITORY_OWNER_ID",
        "SECOND_P0_REVIEWER_ID",
        "GITHUB_ENVIRONMENT_COLLECTOR_APP_ID",
    }
)
EXPECTED_ENVIRONMENT_SECRET_NAMES = frozenset(
    {
        "SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY",
        "SCANALYZE_LIVE_INPUT_BUNDLE_B64",
    }
)
DECODED_SECRET_TRANSPORT_PATH_ENV = "SCANALYZE_DECODED_SECRET_TRANSPORT_PATH"
GITHUB_APP_ID_ENV = "SCANALYZE_GITHUB_APP_ID"
GITHUB_APP_INSTALLATION_ID_ENV = "SCANALYZE_GITHUB_APP_INSTALLATION_ID"
GITHUB_APP_PRIVATE_KEY_ENV = "SCANALYZE_GITHUB_APP_PRIVATE_KEY"
GITHUB_APP_SLUG_ENV = "SCANALYZE_GITHUB_APP_SLUG"
EXPECTED_GITHUB_APP_PERMISSIONS = {
    "actions": "read",
    "environments": "read",
    "metadata": "read",
    "secrets": "read",
    "variables": "read",
}

JsonObject = dict[str, Any]
JsonFetcher = Callable[[str], Mapping[str, Any]]
Clock = Callable[[], datetime]


class GitHubEnvironmentCollectorError(ValueError):
    """Public-safe, non-sensitive collector failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise GitHubEnvironmentCollectorError(code)


def _strict_json_object(content: bytes) -> JsonObject:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in pairs:
            if key in result:
                _fail("GITHUB_RESPONSE_INVALID")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        _fail("GITHUB_RESPONSE_INVALID")

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError):
        _fail("GITHUB_RESPONSE_INVALID")
    if not isinstance(document, dict):
        _fail("GITHUB_RESPONSE_INVALID")
    return document


class GitHubRestReader:
    """Bounded GET-only reader for one GitHub credential type and API host."""

    def __init__(
        self,
        token: str,
        *,
        app_installation_id: str | None = None,
        timeout_seconds: int = 10,
    ) -> None:
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 4_096
            or any(not 0x21 <= ord(character) <= 0x7E for character in token)
        ):
            _fail("GITHUB_TOKEN_UNAVAILABLE")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 30:
            _fail("COLLECTOR_CONFIGURATION_INVALID")
        if app_installation_id is not None and not re.fullmatch(
            r"[1-9][0-9]{0,19}", app_installation_id
        ):
            _fail("COLLECTOR_CONFIGURATION_INVALID")
        self._token = token
        self._app_installation_id = app_installation_id
        self._timeout_seconds = timeout_seconds

    def get(self, path: str) -> JsonObject:
        if self._app_installation_id is None:
            allowed_path = (
                isinstance(path, str)
                and (
                    path.startswith("/installation/repositories?")
                    or path.startswith("/repos/")
                )
            )
        else:
            allowed_path = path == (
                f"/app/installations/{self._app_installation_id}"
            )
        if (
            not isinstance(path, str)
            or not allowed_path
            or "//" in path
            or any(character in path for character in "\r\n#")
        ):
            _fail("GITHUB_SELECTOR_INVALID")
        connection = http.client.HTTPSConnection(
            GITHUB_API_HOST,
            timeout=self._timeout_seconds,
        )
        body = b""
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "User-Agent": "scanalyze-github-environment-identity-collector",
                    "X-GitHub-Api-Version": GITHUB_API_VERSION,
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                _fail("GITHUB_READ_FAILED")
            content_type = response.getheader("Content-Type")
            if not isinstance(content_type, str) or not content_type.lower().startswith(
                "application/json"
            ):
                _fail("GITHUB_RESPONSE_INVALID")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                _fail("GITHUB_RESPONSE_INVALID")
        except GitHubEnvironmentCollectorError:
            raise
        except (OSError, http.client.HTTPException):
            _fail("GITHUB_READ_FAILED")
        finally:
            connection.close()
        return _strict_json_object(body)


def _read_private_json(path: Path) -> JsonObject:
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
            or before.st_size > MAX_TEMPLATE_BYTES
        ):
            _fail("IDENTITY_TEMPLATE_INVALID")
        while len(content) <= MAX_TEMPLATE_BYTES:
            block = os.read(
                descriptor,
                min(65_536, MAX_TEMPLATE_BYTES + 1 - len(content)),
            )
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        stable_identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if len(content) > MAX_TEMPLATE_BYTES or stable_identity(before) != stable_identity(
            after
        ):
            _fail("IDENTITY_TEMPLATE_INVALID")
        try:
            return _strict_json_object(bytes(content))
        except GitHubEnvironmentCollectorError:
            _fail("IDENTITY_TEMPLATE_INVALID")
    except GitHubEnvironmentCollectorError:
        raise
    except OSError:
        _fail("IDENTITY_TEMPLATE_INVALID")
    finally:
        content[:] = b"\x00" * len(content)
        if descriptor is not None:
            os.close(descriptor)


def _require_object(document: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = document.get(field)
    if not isinstance(value, Mapping):
        _fail("GITHUB_RESPONSE_INVALID")
    return value


def _require_string(document: Mapping[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        _fail("GITHUB_RESPONSE_INVALID")
    return value


def _require_positive_id(document: Mapping[str, Any], field: str) -> str:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail("GITHUB_RESPONSE_INVALID")
    return str(value)


def _list_paginated(
    fetch_json: JsonFetcher,
    base_path: str,
    *,
    collection_field: str,
    page_size: int,
) -> list[Mapping[str, Any]]:
    expected_total: int | None = None
    collected: list[Mapping[str, Any]] = []
    for page in range(1, MAX_COLLECTION_PAGES + 1):
        response = fetch_json(f"{base_path}?per_page={page_size}&page={page}")
        if not isinstance(response, Mapping):
            _fail("GITHUB_PAGINATION_INVALID")
        total = response.get("total_count")
        items = response.get(collection_field)
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or total > MAX_COLLECTION_ITEMS
            or not isinstance(items, list)
            or len(items) > page_size
            or not all(isinstance(item, Mapping) for item in items)
        ):
            _fail("GITHUB_PAGINATION_INVALID")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            _fail("GITHUB_PAGINATION_INVALID")
        if len(collected) + len(items) > total:
            _fail("GITHUB_PAGINATION_INVALID")
        collected.extend(items)
        if len(collected) == total:
            return collected
        if not items:
            _fail("GITHUB_PAGINATION_INVALID")
    _fail("GITHUB_PAGINATION_INVALID")


def _name_map(
    items: Sequence[Mapping[str, Any]],
    *,
    include_values: bool,
) -> dict[str, str]:
    result: dict[str, str] = {}
    normalized_names: set[str] = set()
    for item in items:
        name = item.get("name")
        if (
            not isinstance(name, str)
            or not CONFIGURATION_NAME.fullmatch(name)
            or name.casefold() in normalized_names
        ):
            _fail("GITHUB_RESPONSE_INVALID")
        normalized_names.add(name.casefold())
        if include_values:
            value = item.get("value")
            if not isinstance(value, str):
                _fail("GITHUB_RESPONSE_INVALID")
            result[name] = value
        else:
            result[name] = ""
    return dict(sorted(result.items()))


def _positive_id_string(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value):
        _fail(code)
    return value


def _base64url(content: bytes) -> str:
    return base64.urlsafe_b64encode(content).rstrip(b"=").decode("ascii")


def _mint_github_app_jwt(
    private_key: str,
    *,
    app_id: str,
    clock: Clock | None = None,
) -> str:
    """Mint one short-lived App JWT without exposing key or JWT material."""
    _positive_id_string(app_id, code="GITHUB_APP_IDENTITY_INVALID")
    if not isinstance(private_key, str) or "\x00" in private_key:
        _fail("GITHUB_APP_PRIVATE_KEY_INVALID")
    try:
        key_bytes = bytearray(private_key.encode("utf-8"))
    except UnicodeError:
        _fail("GITHUB_APP_PRIVATE_KEY_INVALID")
    if not 1 <= len(key_bytes) <= MAX_APP_PRIVATE_KEY_BYTES:
        key_bytes[:] = b"\x00" * len(key_bytes)
        _fail("GITHUB_APP_PRIVATE_KEY_INVALID")

    raw_now = datetime.now(UTC) if clock is None else clock()
    if not isinstance(raw_now, datetime) or raw_now.tzinfo is None:
        key_bytes[:] = b"\x00" * len(key_bytes)
        _fail("COLLECTION_TIME_INVALID")
    now = int(raw_now.astimezone(UTC).timestamp())
    header = _base64url(
        json.dumps(
            {"alg": "RS256", "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    payload = _base64url(
        json.dumps(
            {"exp": now + 8 * 60, "iat": now - 60, "iss": app_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    try:
        signing_key = serialization.load_pem_private_key(
            key_bytes,
            password=None,
        )
        if not isinstance(signing_key, rsa.RSAPrivateKey):
            _fail("GITHUB_APP_PRIVATE_KEY_INVALID")
        signature = signing_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except GitHubEnvironmentCollectorError:
        raise
    except (TypeError, ValueError, UnsupportedAlgorithm):
        _fail("GITHUB_APP_PRIVATE_KEY_INVALID")
    finally:
        key_bytes[:] = b"\x00" * len(key_bytes)
    return f"{header}.{payload}.{_base64url(signature)}"


def _app_identity_from_process(
    environment: Mapping[str, str],
) -> tuple[str, str, str]:
    app_id = _positive_id_string(
        environment.get(GITHUB_APP_ID_ENV),
        code="GITHUB_APP_IDENTITY_INVALID",
    )
    installation_id = _positive_id_string(
        environment.get(GITHUB_APP_INSTALLATION_ID_ENV),
        code="GITHUB_APP_IDENTITY_INVALID",
    )
    app_slug = environment.get(GITHUB_APP_SLUG_ENV)
    if (
        not isinstance(app_slug, str)
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?", app_slug)
    ):
        _fail("GITHUB_APP_IDENTITY_INVALID")
    return app_id, installation_id, app_slug


def _prove_decoded_secret_transport(
    path: Path,
    *,
    identity_template: Mapping[str, Any],
) -> None:
    try:
        decoded_request = _read_private_json(path)
        sources = decoded_request.get("sources")
        if (
            path.name != "sealed-request.json"
            or not isinstance(sources, Mapping)
            or sources.get("github_deployment_identity") != identity_template
        ):
            _fail("SECRET_TRANSPORT_UNPROVEN")
    except GitHubEnvironmentCollectorError:
        _fail("SECRET_TRANSPORT_UNPROVEN")


def _selectors(identity_template: Mapping[str, Any]) -> tuple[str, str, str, str]:
    try:
        repository = identity_template["repository"]
        workflow = identity_template["workflow"]
        protection = identity_template["environment_protection"]
        owner = repository["owner"]
        name = repository["name"]
        environment_name = workflow["github_environment"]
        initiator_login = protection["initiator_login"]
    except (KeyError, TypeError):
        _fail("IDENTITY_TEMPLATE_INVALID")
    if (
        not isinstance(owner, str)
        or not OWNER_COMPONENT.fullmatch(owner)
        or not isinstance(name, str)
        or not REPOSITORY_COMPONENT.fullmatch(name)
        or not isinstance(environment_name, str)
        or not ENVIRONMENT_NAME.fullmatch(environment_name)
        or not isinstance(initiator_login, str)
        or not REPOSITORY_COMPONENT.fullmatch(initiator_login)
    ):
        _fail("IDENTITY_TEMPLATE_INVALID")
    return owner, name, environment_name, initiator_login


def _required_reviewer(
    environment: Mapping[str, Any],
    *,
    initiator_login: str,
) -> dict[str, str]:
    rules = environment.get("protection_rules")
    if not isinstance(rules, list) or not all(isinstance(rule, Mapping) for rule in rules):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    rule_types = [rule.get("type") for rule in rules]
    if (
        not all(isinstance(rule_type, str) for rule_type in rule_types)
        or sorted(rule_types) != ["branch_policy", "required_reviewers"]
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    reviewer_rule = next(rule for rule in rules if rule.get("type") == "required_reviewers")
    if reviewer_rule.get("prevent_self_review") is not True:
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    reviewers = reviewer_rule.get("reviewers")
    if not isinstance(reviewers, list) or len(reviewers) != 1:
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    entry = reviewers[0]
    if not isinstance(entry, Mapping) or entry.get("type") != "User":
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    reviewer = entry.get("reviewer")
    if not isinstance(reviewer, Mapping):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    login = reviewer.get("login")
    reviewer_type = reviewer.get("type")
    if (
        reviewer_type != "User"
        or not isinstance(login, str)
        or not REPOSITORY_COMPONENT.fullmatch(login)
        or login.casefold() == initiator_login.casefold()
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    return {
        "type": "User",
        "id": _require_positive_id(reviewer, "id"),
        "login": login,
    }


def _branch_projection(
    environment: Mapping[str, Any],
    policies: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[str]]:
    branch_policy = _require_object(environment, "deployment_branch_policy")
    if (
        branch_policy.get("protected_branches") is not False
        or branch_policy.get("custom_branch_policies") is not True
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    branches: list[str] = []
    tags: list[str] = []
    seen_ids: set[str] = set()
    for policy in policies:
        policy_id = _require_positive_id(policy, "id")
        name = _require_string(policy, "name")
        policy_type = policy.get("type")
        if policy_id in seen_ids or policy_type not in {"branch", "tag"}:
            _fail("GITHUB_ENVIRONMENT_UNSAFE")
        seen_ids.add(policy_id)
        (branches if policy_type == "branch" else tags).append(name)
    if sorted(branches) != ["main"] or tags:
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    return ["main"], []


def _installation_projection(
    fetch_json: JsonFetcher,
    fetch_app_json: JsonFetcher,
    *,
    repository: Mapping[str, str],
    owner_type: str,
    expected_app_id: str,
    expected_installation_id: str,
    expected_app_slug: str,
) -> JsonObject:
    installation = fetch_app_json(
        f"/app/installations/{expected_installation_id}"
    )
    if not isinstance(installation, Mapping):
        _fail("GITHUB_APP_INSTALLATION_INVALID")
    account = installation.get("account")
    permissions = installation.get("permissions")
    if not isinstance(account, Mapping) or not isinstance(permissions, Mapping):
        _fail("GITHUB_APP_INSTALLATION_INVALID")
    normalized_permissions = {
        key: value
        for key, value in permissions.items()
        if isinstance(key, str) and isinstance(value, str)
    }
    if (
        _require_positive_id(installation, "id") != expected_installation_id
        or _require_positive_id(installation, "app_id") != expected_app_id
        or installation.get("app_slug") != expected_app_slug
        or installation.get("repository_selection") != "selected"
        or installation.get("target_type") != owner_type
        or installation.get("suspended_at") is not None
        or _require_positive_id(account, "id") != repository["owner_id"]
        or _require_string(account, "login").casefold()
        != repository["owner"].casefold()
        or account.get("type") != owner_type
        or normalized_permissions != EXPECTED_GITHUB_APP_PERMISSIONS
        or len(normalized_permissions) != len(permissions)
    ):
        _fail("GITHUB_APP_INSTALLATION_INVALID")

    installation_repositories = _list_paginated(
        fetch_json,
        "/installation/repositories",
        collection_field="repositories",
        page_size=100,
    )
    if len(installation_repositories) != 1:
        _fail("GITHUB_APP_INSTALLATION_INVALID")
    installed_repository = installation_repositories[0]
    installed_owner = installed_repository.get("owner")
    if (
        not isinstance(installed_owner, Mapping)
        or _require_positive_id(installed_repository, "id")
        != repository["repository_id"]
        or _require_string(installed_repository, "name").casefold()
        != repository["name"].casefold()
        or _require_positive_id(installed_owner, "id") != repository["owner_id"]
        or _require_string(installed_owner, "login").casefold()
        != repository["owner"].casefold()
    ):
        _fail("GITHUB_APP_INSTALLATION_INVALID")
    return {
        "authentication": "github_app_installation_token",
        "installation_verification": "github_app_jwt",
        "app_id": expected_app_id,
        "app_slug": expected_app_slug,
        "installation_id": expected_installation_id,
        "installation_account_id": repository["owner_id"],
        "installation_account_login": repository["owner"],
        "installation_target_type": owner_type,
        "repository_selection": "selected",
        "repository_ids": [repository["repository_id"]],
        "permissions": dict(sorted(normalized_permissions.items())),
    }


def _collect_projection(
    identity_template: Mapping[str, Any],
    fetch_json: JsonFetcher,
    fetch_app_json: JsonFetcher,
    *,
    expected_app_id: str,
    expected_installation_id: str,
    expected_app_slug: str,
    secret_transport_proven: bool,
) -> JsonObject:
    if secret_transport_proven is not True:
        _fail("SECRET_TRANSPORT_UNPROVEN")
    owner, name, environment_name, initiator_login = _selectors(identity_template)
    encoded_owner = quote(owner, safe="")
    encoded_name = quote(name, safe="")
    encoded_environment = quote(environment_name, safe="")
    repository_base = f"/repos/{encoded_owner}/{encoded_name}"

    repository = fetch_json(repository_base)
    if not isinstance(repository, Mapping):
        _fail("GITHUB_RESPONSE_INVALID")
    actual_owner = _require_object(repository, "owner")
    actual_owner_login = _require_string(actual_owner, "login")
    actual_owner_type = _require_string(actual_owner, "type")
    actual_name = _require_string(repository, "name")
    visibility = _require_string(repository, "visibility")
    if (
        actual_owner_login.casefold() != owner.casefold()
        or actual_name.casefold() != name.casefold()
        or actual_owner_type not in {"Organization", "User"}
        or visibility not in {"private", "internal"}
    ):
        _fail("GITHUB_REPOSITORY_MISMATCH")
    repository_projection = {
        "owner": actual_owner_login,
        "name": actual_name,
        "owner_id": _require_positive_id(actual_owner, "id"),
        "repository_id": _require_positive_id(repository, "id"),
        "visibility": visibility,
    }
    collector_authority = _installation_projection(
        fetch_json,
        fetch_app_json,
        repository=repository_projection,
        owner_type=actual_owner_type,
        expected_app_id=expected_app_id,
        expected_installation_id=expected_installation_id,
        expected_app_slug=expected_app_slug,
    )

    environment_path = f"{repository_base}/environments/{encoded_environment}"
    environment = fetch_json(environment_path)
    if not isinstance(environment, Mapping):
        _fail("GITHUB_RESPONSE_INVALID")
    if (
        environment.get("name") != environment_name
        or environment.get("can_admins_bypass") is not False
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")
    reviewer = _required_reviewer(environment, initiator_login=initiator_login)

    policies = _list_paginated(
        fetch_json,
        f"{environment_path}/deployment-branch-policies",
        collection_field="branch_policies",
        page_size=100,
    )
    protected_branches, protected_tags = _branch_projection(environment, policies)

    custom_protection_rules = _list_paginated(
        fetch_json,
        f"{environment_path}/deployment_protection_rules",
        collection_field="custom_deployment_protection_rules",
        page_size=30,
    )
    if custom_protection_rules:
        _fail("GITHUB_ENVIRONMENT_UNSAFE")

    environment_variables = _name_map(
        _list_paginated(
            fetch_json,
            f"{environment_path}/variables",
            collection_field="variables",
            page_size=30,
        ),
        include_values=True,
    )
    if (
        frozenset(environment_variables) != EXPECTED_ENVIRONMENT_VARIABLES
        or environment_variables.get("GITHUB_ENVIRONMENT_COLLECTOR_APP_ID")
        != expected_app_id
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")

    environment_secret_names = _name_map(
        _list_paginated(
            fetch_json,
            f"{environment_path}/secrets",
            collection_field="secrets",
            page_size=100,
        ),
        include_values=False,
    )
    if frozenset(environment_secret_names) != EXPECTED_ENVIRONMENT_SECRET_NAMES:
        _fail("GITHUB_ENVIRONMENT_UNSAFE")

    repository_variables = _name_map(
        _list_paginated(
            fetch_json,
            f"{repository_base}/actions/variables",
            collection_field="variables",
            page_size=30,
        ),
        include_values=True,
    )
    expected_variable_names = {
        name.casefold() for name in EXPECTED_ENVIRONMENT_VARIABLES
    }
    if expected_variable_names.intersection(
        name.casefold() for name in repository_variables
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")

    effective_organization_variables: dict[str, str] = {}
    if actual_owner_type == "Organization":
        effective_organization_variables = _name_map(
            _list_paginated(
                fetch_json,
                f"{repository_base}/actions/organization-variables",
                collection_field="variables",
                page_size=30,
            ),
            include_values=True,
        )
        if expected_variable_names.intersection(
            name.casefold() for name in effective_organization_variables
        ):
            _fail("GITHUB_ENVIRONMENT_UNSAFE")

    repository_secret_names = _name_map(
        _list_paginated(
            fetch_json,
            f"{repository_base}/actions/secrets",
            collection_field="secrets",
            page_size=100,
        ),
        include_values=False,
    )
    expected_secret_names = {
        name.casefold() for name in EXPECTED_ENVIRONMENT_SECRET_NAMES
    }
    if expected_secret_names.intersection(
        name.casefold() for name in repository_secret_names
    ):
        _fail("GITHUB_ENVIRONMENT_UNSAFE")

    effective_organization_secret_names: dict[str, str] = {}
    if actual_owner_type == "Organization":
        effective_organization_secret_names = _name_map(
            _list_paginated(
                fetch_json,
                f"{repository_base}/actions/organization-secrets",
                collection_field="secrets",
                page_size=100,
            ),
            include_values=False,
        )
        if expected_secret_names.intersection(
            name.casefold() for name in effective_organization_secret_names
        ):
            _fail("GITHUB_ENVIRONMENT_UNSAFE")

    oidc = fetch_json(f"{repository_base}/actions/oidc/customization/sub")
    if not isinstance(oidc, Mapping):
        _fail("GITHUB_RESPONSE_INVALID")
    use_default = oidc.get("use_default")
    include_claim_keys = oidc.get("include_claim_keys")
    if (
        use_default is not False
        or not isinstance(include_claim_keys, list)
        or tuple(include_claim_keys) != EXPECTED_CLAIM_KEYS
        or oidc.get("use_immutable_subject", False) is not False
    ):
        _fail("GITHUB_OIDC_UNSAFE")

    return {
        "repository": repository_projection,
        "owner_type": actual_owner_type,
        "collector_authority": collector_authority,
        "environment_protection": {
            "name": environment_name,
            "custom_branch_policies": True,
            "protected_branches": protected_branches,
            "protected_tags": protected_tags,
            "required_reviewers": [reviewer],
            "prevent_self_review": True,
            "prevent_admin_bypass": True,
            "reserved_variables_absent_at_repository": True,
            "reserved_variables_absent_at_effective_organization": True,
            "reserved_secrets_absent_at_repository": True,
            "reserved_secrets_absent_at_effective_organization": True,
            "repository_variables": repository_variables,
            "effective_organization_variables": (
                effective_organization_variables
            ),
            "repository_secret_names": sorted(repository_secret_names),
            "effective_organization_secret_names": sorted(
                effective_organization_secret_names
            ),
            "variables": environment_variables,
            "secret_names": sorted(environment_secret_names),
        },
        "oidc_subject_customization": {
            "use_default_subject": False,
            "include_claim_keys": list(EXPECTED_CLAIM_KEYS),
        },
    }


def _validate_schema(document: Mapping[str, Any], schema_path: Path) -> None:
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        if next(iter(validator.iter_errors(document)), None) is not None:
            _fail("COLLECTED_ARTIFACT_INVALID")
    except GitHubEnvironmentCollectorError:
        raise
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError):
        _fail("COLLECTED_ARTIFACT_INVALID")


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("COLLECTION_TIME_INVALID")
    normalized = value.astimezone(UTC).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def collect_github_environment_identity(
    *,
    identity_template: Mapping[str, Any],
    fetch_json: JsonFetcher,
    fetch_app_json: JsonFetcher,
    expected_app_id: str,
    expected_installation_id: str,
    expected_app_slug: str,
    secret_transport_proven: bool,
    clock: Clock | None = None,
    identity_schema_path: Path = DEFAULT_SCHEMA,
    anchor_schema_path: Path = DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA,
) -> tuple[JsonObject, JsonObject]:
    """Return one schema-valid identity and a ten-minute stable evidence anchor."""
    if not isinstance(identity_template, Mapping):
        _fail("IDENTITY_TEMPLATE_INVALID")
    _positive_id_string(expected_app_id, code="GITHUB_APP_IDENTITY_INVALID")
    _positive_id_string(
        expected_installation_id,
        code="GITHUB_APP_IDENTITY_INVALID",
    )
    if (
        not isinstance(expected_app_slug, str)
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?",
            expected_app_slug,
        )
    ):
        _fail("GITHUB_APP_IDENTITY_INVALID")
    first = _collect_projection(
        identity_template,
        fetch_json,
        fetch_app_json,
        expected_app_id=expected_app_id,
        expected_installation_id=expected_installation_id,
        expected_app_slug=expected_app_slug,
        secret_transport_proven=secret_transport_proven,
    )
    second = _collect_projection(
        identity_template,
        fetch_json,
        fetch_app_json,
        expected_app_id=expected_app_id,
        expected_installation_id=expected_installation_id,
        expected_app_slug=expected_app_slug,
        secret_transport_proven=secret_transport_proven,
    )
    if first != second:
        _fail("GITHUB_CONFIGURATION_UNSTABLE")

    identity = copy.deepcopy(dict(identity_template))
    identity.pop("contract_digest", None)
    try:
        workflow = identity["workflow"]
        oidc = identity["oidc"]
        protection_template = identity["environment_protection"]
        initiator_login = protection_template["initiator_login"]
        workflow.pop("source_sha", None)
        identity["repository"] = copy.deepcopy(second["repository"])
        workflow["workflow_ref"] = (
            f"{identity['repository']['owner']}/{identity['repository']['name']}/"
            f"{workflow['path']}@{workflow['ref']}"
        )
        protection = copy.deepcopy(second["environment_protection"])
        protection["initiator_login"] = initiator_login
        identity["environment_protection"] = protection
        identity["collector_authority"] = copy.deepcopy(
            second["collector_authority"]
        )
        oidc["use_default_subject"] = second["oidc_subject_customization"][
            "use_default_subject"
        ]
        oidc["include_claim_keys"] = copy.deepcopy(
            second["oidc_subject_customization"]["include_claim_keys"]
        )
        oidc["subject"] = derive_oidc_subject(identity)
    except (AttributeError, KeyError, TypeError):
        _fail("IDENTITY_TEMPLATE_INVALID")
    identity["contract_digest"] = canonical_digest(identity)
    _validate_schema(identity, identity_schema_path)
    try:
        _validate_workflow_and_oidc(identity)
        _validate_environment(identity)
    except (KeyError, TypeError, ValueError):
        _fail("COLLECTED_ARTIFACT_INVALID")

    raw_observed_at = datetime.now(UTC) if clock is None else clock()
    if not isinstance(raw_observed_at, datetime) or raw_observed_at.tzinfo is None:
        _fail("COLLECTION_TIME_INVALID")
    observed_at = raw_observed_at.astimezone(UTC)
    captured_at = _timestamp(observed_at)
    expires_at = _timestamp(observed_at + ANCHOR_LIFETIME)
    anchor: JsonObject = {
        "schema_version": "1",
        "record_type": "github_environment_anchor",
        "source": "github-api",
        "repository_owner_id": identity["repository"]["owner_id"],
        "repository_id": identity["repository"]["repository_id"],
        "environment_name": identity["workflow"]["github_environment"],
        "configuration_digest": environment_configuration_digest(identity),
        "captured_at": captured_at,
        "expires_at": expires_at,
    }
    anchor["evidence_digest"] = canonical_digest(anchor)
    _validate_schema(anchor, anchor_schema_path)
    return identity, anchor


def _write_create_only(path: Path, document: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                _fail("OUTPUT_WRITE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            _fail("OUTPUT_WRITE_FAILED")
    except GitHubEnvironmentCollectorError:
        raise
    except OSError:
        _fail("OUTPUT_WRITE_FAILED")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_collected_artifacts(
    *,
    output_dir: Path,
    identity: Mapping[str, Any],
    anchor: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Create one new private directory and two immutable JSON artifacts."""
    _validate_schema(identity, DEFAULT_SCHEMA)
    _validate_schema(anchor, DEFAULT_ENVIRONMENT_ANCHOR_SCHEMA)
    try:
        _validate_workflow_and_oidc(dict(identity))
        _validate_environment(dict(identity))
        artifacts_match = (
            identity.get("contract_digest") == canonical_digest(dict(identity))
            and anchor.get("evidence_digest") == canonical_digest(dict(anchor))
            and anchor.get("repository_owner_id")
            == identity["repository"]["owner_id"]
            and anchor.get("repository_id")
            == identity["repository"]["repository_id"]
            and anchor.get("environment_name")
            == identity["workflow"]["github_environment"]
            and anchor.get("configuration_digest")
            == environment_configuration_digest(dict(identity))
        )
    except (KeyError, TypeError, ValueError):
        artifacts_match = False
    if not artifacts_match:
        _fail("COLLECTED_ARTIFACT_INVALID")
    directory_descriptor: int | None = None
    try:
        os.mkdir(output_dir, 0o700)
        directory_descriptor = os.open(
            output_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fchmod(directory_descriptor, 0o700)
        metadata = os.fstat(directory_descriptor)
    except OSError:
        _fail("OUTPUT_DIRECTORY_INVALID")
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail("OUTPUT_DIRECTORY_INVALID")
    identity_path = output_dir / IDENTITY_FILENAME
    anchor_path = output_dir / ANCHOR_FILENAME
    _write_create_only(identity_path, identity)
    _write_create_only(anchor_path, anchor)
    return identity_path, anchor_path


def collect_to_private_directory(
    *,
    identity_template_path: Path,
    output_dir: Path,
    token: str,
    clock: Clock | None = None,
) -> tuple[Path, Path]:
    template = _read_private_json(identity_template_path)
    decoded_transport_path = os.environ.get(DECODED_SECRET_TRANSPORT_PATH_ENV, "")
    if not decoded_transport_path:
        _fail("SECRET_TRANSPORT_UNPROVEN")
    transport_path = Path(decoded_transport_path)
    if transport_path.parent != identity_template_path.parent:
        _fail("SECRET_TRANSPORT_UNPROVEN")
    _prove_decoded_secret_transport(
        transport_path,
        identity_template=template,
    )
    expected_app_id, expected_installation_id, expected_app_slug = (
        _app_identity_from_process(os.environ)
    )
    app_jwt = _mint_github_app_jwt(
        os.environ.get(GITHUB_APP_PRIVATE_KEY_ENV, ""),
        app_id=expected_app_id,
        clock=clock,
    )
    reader = GitHubRestReader(token)
    app_reader = GitHubRestReader(
        app_jwt,
        app_installation_id=expected_installation_id,
    )
    identity, anchor = collect_github_environment_identity(
        identity_template=template,
        fetch_json=reader.get,
        fetch_app_json=app_reader.get,
        expected_app_id=expected_app_id,
        expected_installation_id=expected_installation_id,
        expected_app_slug=expected_app_slug,
        secret_transport_proven=True,
        clock=clock,
    )
    return write_collected_artifacts(
        output_dir=output_dir,
        identity=identity,
        anchor=anchor,
    )


__all__ = [
    "ANCHOR_FILENAME",
    "ANCHOR_LIFETIME",
    "DECODED_SECRET_TRANSPORT_PATH_ENV",
    "EXPECTED_ENVIRONMENT_SECRET_NAMES",
    "EXPECTED_ENVIRONMENT_VARIABLES",
    "EXPECTED_GITHUB_APP_PERMISSIONS",
    "GITHUB_APP_ID_ENV",
    "GITHUB_APP_INSTALLATION_ID_ENV",
    "GITHUB_APP_PRIVATE_KEY_ENV",
    "GITHUB_APP_SLUG_ENV",
    "GITHUB_API_VERSION",
    "GitHubEnvironmentCollectorError",
    "GitHubRestReader",
    "IDENTITY_FILENAME",
    "collect_github_environment_identity",
    "collect_to_private_directory",
    "write_collected_artifacts",
]
