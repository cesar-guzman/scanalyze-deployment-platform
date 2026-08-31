"""Connected, read-only attestor for exact GUG-376 template objects.

The product entrypoint derives the one permitted artifact bucket and KMS key
from the exact artifact-bootstrap intent plus foundation publish binding and
uses the direct ``ScanalyzeGug376ArtifactBootstrap`` profile.  Operators cannot
pass either storage coordinate on the command line.  The historical
GUG-363/GUG-365 plan-derived constructor remains only for hermetic compatibility
tests; it is not a product fallback.  The attestor proves one exact, versioned
S3 object is byte-for-byte equal to the reviewed Git object (or to the private
rendered broker template) using only STS and S3 read calls.

This module never uploads an object, creates a stack, or authorizes a
deployment.  Its output remains private because the broker materialization
receipt and immutable S3 coordinates are operational evidence.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling import platform_authority_plan_permission_repair_deployment_route as route


RECORD_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_template_readback.v1"
)
STORAGE_BINDING_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_gug365_template_storage_binding.v1"
)
EXPECTED_PROFILE = (
    "042360977644_ScanalyzeGug376ArtifactBootstrap"
)
LEGACY_EXPECTED_PROFILE = "042360977644_AWSReadOnlyAccess"
FOUNDATION_EXPECTED_PROFILE = EXPECTED_PROFILE
EXPECTED_ACCOUNT_ID = route.AUTHORITY_ACCOUNT_ID
EXPECTED_REGION = route.REGION
EXPECTED_SSO_ROLE = "ScanalyzeGug376ArtifactBootstrap"
LEGACY_EXPECTED_SSO_ROLE = "AWSReadOnlyAccess"
FOUNDATION_EXPECTED_SSO_ROLE = EXPECTED_SSO_ROLE
SOURCE_MARKER = "AWS_STS_S3_VERSIONED_OBJECT_READBACK"
MAX_TEMPLATE_BYTES = 4 * 1024 * 1024
DEFAULT_OUTPUT_NAMES = {
    "route_template": "route-template-readback.json",
    "delegation_template": "delegation-template-readback.json",
    "pep_template": "pep-template-readback.json",
    "pep_protection_template": "pep-protection-template-readback.json",
    "broker_template": "broker-template-readback.json",
    "broker_protection_template": "broker-protection-template-readback.json",
}

_ARTIFACTS = {
    "route_template": {
        "source_path": route.ROUTE_TEMPLATE_PATH,
        "scope": "templates",
        "filename": (
            "cfn-platform-authority-gug376-temporary-change-set-route.yaml"
        ),
    },
    "delegation_template": {
        "source_path": route.DELEGATION_TEMPLATE_PATH,
        "scope": "templates",
        "filename": (
            "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
        ),
    },
    "pep_template": {
        "source_path": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "scope": "templates",
        "filename": "cfn-platform-authority-bootstrap-plan-repair-pep.yaml",
    },
    "pep_protection_template": {
        "source_path": (
            "bootstrap/cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
        ),
        "scope": "templates",
        "filename": (
            "cfn-platform-authority-bootstrap-plan-repair-pep-protection.yaml"
        ),
    },
    "broker_template": {
        "source_path": route.BROKER_TEMPLATE_PATH,
        "scope": "private",
        "filename": "cfn-platform-authority-gug376-route-broker.yaml",
    },
    "broker_protection_template": {
        "source_path": route.BROKER_TEMPLATE_PATH,
        "scope": "private",
        "filename": (
            "cfn-platform-authority-gug376-route-broker-protection.yaml"
        ),
    },
}
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_KMS_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:kms:us-east-1:042360977644:key/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_CALLER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_FOUNDATION_CALLER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_OUTPUT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_ERROR_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_PROFILE_ALLOWED = frozenset(
    {
        "cli_pager",
        "output",
        "region",
        "sso_account_id",
        "sso_region",
        "sso_role_name",
        "sso_session",
        "sso_start_url",
    }
)
_AMBIENT_FORBIDDEN = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_CA_BUNDLE",
        "BOTO_CONFIG",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "source_path",
        "source_sha256",
        "bucket",
        "key",
        "version",
        "template_url",
        "artifact_sha256",
        "content_length",
        "sse_algorithm",
        "sse_kms_key_arn",
        "upstream_storage_binding",
        "materialization_receipt",
        "verifier",
        "observed_at",
        "source_marker",
        "aws_calls",
        "aws_mutations",
        "receipt_digest",
    }
)
_STORAGE_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "gug363_plan_digest",
        "gug363_artifact_signing_contract_digest",
        "gug365_plan_digest",
        "gug365_ledger_factory_artifact_signing_contract_digest",
        "gug365_signed_artifact_binding_digest",
        "bucket",
        "sse_algorithm",
        "sse_kms_key_arn",
        "source_marker",
        "binding_digest",
    }
)
_FOUNDATION_STORAGE_BINDING_FIELDS = frozenset(
    {
        "schema_version", "record_type", "source_commit",
        "bootstrap_intent_digest", "foundation_readback_digest",
        "reviewed_sources_digest", "access_update_intent_digest",
        "access_readback_digest", "route_template_receipt_digest",
        "delegation_template_receipt_digest", "route_template_sha256",
        "delegation_template_sha256", "route_template_version_digest",
        "delegation_template_version_digest", "access_not_after", "bucket",
        "sse_algorithm", "sse_kms_key_arn", "signing_profile_version_arn",
        "code_signing_config_arn", "source_marker", "aws_calls",
        "aws_mutations", "production_authorized", "production_status",
        "foundation_readback", "reviewed_sources", "access_update",
        "access_readback", "route_template_receipt",
        "delegation_template_receipt",
        "binding_digest",
    }
)


class TemplateReadbackError(RuntimeError):
    """Stable, public-safe error from the template readback boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if _ERROR_RE.fullmatch(code) else "TEMPLATE_READBACK_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise TemplateReadbackError(code)


class GitPort(Protocol):
    def root(self) -> Path: ...

    def branch(self) -> str: ...

    def head(self) -> str: ...

    def origin_main(self) -> str: ...

    def status(self) -> str: ...

    def read_at(self, commit: str, path: str) -> bytes: ...


class SubprocessGit:
    """Shell-free Git object reader used by the connected CLI."""

    def __init__(self, source_root: Path) -> None:
        try:
            self._root = source_root.resolve(strict=True)
        except OSError as exc:
            raise TemplateReadbackError("SOURCE_ROOT_INVALID") from exc

    def _run(self, *arguments: str) -> bytes:
        try:
            completed = subprocess.run(
                ["git", "-C", str(self._root), *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TemplateReadbackError("GIT_READ_FAILED") from exc
        if completed.returncode != 0:
            _fail("GIT_READ_FAILED")
        return completed.stdout

    def root(self) -> Path:
        return Path(
            self._run("rev-parse", "--show-toplevel").decode("utf-8").strip()
        ).resolve()

    def branch(self) -> str:
        return self._run("symbolic-ref", "--short", "HEAD").decode().strip()

    def head(self) -> str:
        return self._run("rev-parse", "HEAD").decode("ascii").strip()

    def origin_main(self) -> str:
        return self._run("rev-parse", "origin/main").decode("ascii").strip()

    def status(self) -> str:
        return self._run(
            "status", "--porcelain=v1", "--untracked-files=all"
        ).decode("utf-8")

    def read_at(self, commit: str, path: str) -> bytes:
        return self._run("show", f"{commit}:{path}")


def _call(method: Any, /, *, code: str, **request: Any) -> Mapping[str, Any]:
    try:
        response = method(**request)
    except Exception as exc:  # optional botocore dependency is isolated here
        raise TemplateReadbackError(code) from exc
    if not isinstance(response, Mapping):
        _fail(code)
    return response


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _validate_environment(
    environment: Mapping[str, str], *, expected_profile: str
) -> None:
    if any(environment.get(name) for name in _AMBIENT_FORBIDDEN) or any(
        name.startswith("AWS_ENDPOINT_URL") and value
        for name, value in environment.items()
    ):
        _fail("AWS_ENVIRONMENT_UNSAFE")
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if environment.get(name) not in (None, "", expected_profile):
            _fail("AWS_PROFILE_DRIFT")
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if environment.get(name) not in (None, "", EXPECTED_REGION):
            _fail("AWS_REGION_DRIFT")


def _new_session(
    profile: str,
    region: str,
    factory: Callable[[str, str], Any] | None,
) -> Any:
    if factory is not None:
        return factory(profile, region)
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TemplateReadbackError("AWS_SDK_UNAVAILABLE") from exc
    return boto3.Session(profile_name=profile, region_name=region)


def _validate_session(
    session: Any, profile: str, region: str, *, expected_sso_role: str
) -> None:
    if (
        getattr(session, "profile_name", None) != profile
        or getattr(session, "region_name", None) != region
    ):
        _fail("AWS_SESSION_DRIFT")
    sdk_session = getattr(session, "_session", None)
    full_config = getattr(sdk_session, "full_config", None)
    profiles = full_config.get("profiles") if isinstance(full_config, Mapping) else None
    document = profiles.get(profile) if isinstance(profiles, Mapping) else None
    modern = isinstance(document, Mapping) and isinstance(
        document.get("sso_session"), str
    ) and bool(document.get("sso_session"))
    legacy = isinstance(document, Mapping) and all(
        isinstance(document.get(key), str) and bool(document.get(key))
        for key in ("sso_start_url", "sso_region")
    )
    sessions = (
        full_config.get("sso_sessions")
        if isinstance(full_config, Mapping)
        else None
    )
    selected_session = (
        sessions.get(document["sso_session"])
        if modern and isinstance(sessions, Mapping)
        else None
    )
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(_PROFILE_ALLOWED)
        or document.get("sso_account_id") != EXPECTED_ACCOUNT_ID
        or document.get("sso_role_name") != expected_sso_role
        or document.get("region", region) != region
        or not (modern or legacy)
        or (
            modern
            and (
                not isinstance(selected_session, Mapping)
                or not all(
                    isinstance(selected_session.get(key), str)
                    and bool(selected_session.get(key))
                    for key in ("sso_start_url", "sso_region")
                )
            )
        )
    ):
        _fail("AWS_PROFILE_CONFIGURATION_INVALID")
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise TemplateReadbackError("AWS_SSO_CREDENTIALS_UNAVAILABLE") from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        _fail("AWS_CREDENTIAL_SOURCE_INVALID")


def _client_config(factory: Callable[[], Any] | None) -> Any:
    if factory is not None:
        return factory()
    try:
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TemplateReadbackError("AWS_SDK_UNAVAILABLE") from exc
    return Config(
        connect_timeout=3,
        read_timeout=8,
        retries={"mode": "standard", "total_max_attempts": 1},
        s3={"us_east_1_regional_endpoint": "regional"},
        ignore_configured_endpoint_urls=True,
    )


def _exact_client(session: Any, service: str, region: str, config: Any) -> Any:
    try:
        client = session.client(service, region_name=region, config=config)
        endpoint = client.meta.endpoint_url
    except Exception as exc:
        raise TemplateReadbackError("AWS_CLIENT_INVALID") from exc
    expected = {
        "sts": f"sts.{region}.amazonaws.com",
        "s3": f"s3.{region}.amazonaws.com",
    }
    parsed = urlsplit(str(endpoint))
    if (
        service not in expected
        or parsed.scheme != "https"
        or parsed.hostname != expected[service]
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        _fail("AWS_ENDPOINT_INVALID")
    return client


def _validate_git_source(
    git: GitPort, source_commit: str, *, expected_root: Path
) -> None:
    try:
        root = git.root()
        exact = (
            root == expected_root
            and root == root.resolve()
            and git.branch() == "main"
            and git.head() == source_commit
            and git.origin_main() == source_commit
            and git.status() == ""
        )
    except (OSError, UnicodeError, route.RouteSeedError) as exc:
        raise TemplateReadbackError("SOURCE_GIT_INVALID") from exc
    if not exact:
        _fail("SOURCE_NOT_EXACT_CLEAN_MAIN")


def _validate_upstream_plans(
    gug363_plan: Mapping[str, Any] | None,
    gug365_plan: Mapping[str, Any] | None,
    *,
    source_root: Path,
    gug363_validator: Callable[..., Any] | None,
    gug365_validator: Callable[..., Any] | None,
) -> None:
    try:
        if gug363_validator is None:
            from tooling import (
                platform_authority_retirement_entrypoint_materializer as gug363,
            )

            gug363.validate_materialization_plan(
                gug363_plan, repo_root=source_root
            )
        else:
            gug363_validator(gug363_plan, repo_root=source_root)
        if gug365_validator is None:
            from tooling import (
                platform_authority_retirement_entrypoint_service_role_materializer
                as gug365,
            )

            gug365.validate_service_role_materialization_plan(
                gug365_plan,
                gug363_plan=gug363_plan,
                expected_gug363_plan_digest=gug363_plan["plan_digest"],
                ledger_factory_artifact_signing_contract=gug365_plan[
                    "ledger_factory_artifact_signing_contract"
                ],
                expected_ledger_factory_artifact_signing_contract_digest=(
                    gug365_plan[
                        "ledger_factory_artifact_signing_contract_digest"
                    ]
                ),
                repo_root=source_root,
            )
        else:
            gug365_validator(
                gug365_plan,
                gug363_plan=gug363_plan,
                expected_gug363_plan_digest=gug363_plan.get("plan_digest"),
                ledger_factory_artifact_signing_contract=gug365_plan.get(
                    "ledger_factory_artifact_signing_contract"
                ),
                expected_ledger_factory_artifact_signing_contract_digest=(
                    gug365_plan.get(
                        "ledger_factory_artifact_signing_contract_digest"
                    )
                ),
                repo_root=source_root,
            )
    except Exception as exc:
        raise TemplateReadbackError("UPSTREAM_PLAN_INVALID") from exc


def derive_upstream_storage_binding(
    *,
    gug363_plan: Mapping[str, Any],
    gug365_plan: Mapping[str, Any],
    source_root: Path,
    gug363_validator: Callable[..., Any] | None = None,
    gug365_validator: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Validate both causal plans and derive their single shared S3/KMS pair."""

    if not isinstance(gug363_plan, Mapping) or not isinstance(gug365_plan, Mapping):
        _fail("UPSTREAM_PLAN_INVALID")
    _validate_upstream_plans(
        gug363_plan,
        gug365_plan,
        source_root=source_root,
        gug363_validator=gug363_validator,
        gug365_validator=gug365_validator,
    )
    gug363_contract = gug363_plan.get("artifact_signing_contract")
    gug365_contract = gug365_plan.get(
        "ledger_factory_artifact_signing_contract"
    )
    gug365_signed = gug365_plan.get("signed_artifact_binding")
    if (
        gug363_plan.get("record_type")
        != "scanalyze.platform_authority.retirement_entrypoint_plan.v1"
        or gug363_plan.get("target", {}).get("authority_account_id")
        != EXPECTED_ACCOUNT_ID
        or gug363_plan.get("target", {}).get("region") != EXPECTED_REGION
        or gug363_plan.get("production") is not False
        or gug363_plan.get("deployment_authorized") is not False
        or gug365_plan.get("record_type")
        != (
            "scanalyze.platform_authority."
            "retirement_entrypoint_service_role_plan.v1"
        )
        or gug365_plan.get("implementation_issue") != "GUG-365"
        or gug365_plan.get("source_issue") != "GUG-363"
        or gug365_plan.get("production") is not False
        or gug365_plan.get("deployment_authorized") is not False
        or gug365_plan.get("aws_calls_performed") is not False
        or not isinstance(gug363_contract, Mapping)
        or not isinstance(gug365_contract, Mapping)
        or not isinstance(gug365_signed, Mapping)
    ):
        _fail("UPSTREAM_PLAN_SCOPE_INVALID")
    try:
        gug363_unsigned = gug363_contract["unsigned_source"]
        gug363_signed = gug363_contract["signed_destination"]
        gug365_unsigned = gug365_contract["unsigned_source"]
        gug365_destination = gug365_contract["signed_destination"]
        bucket = gug363_unsigned["bucket"]
        key_arn = gug363_unsigned["sse_kms_key_arn"]
        locations = (
            gug363_unsigned,
            gug363_signed,
            gug365_unsigned,
            gug365_destination,
            gug365_signed,
        )
    except (KeyError, TypeError) as exc:
        raise TemplateReadbackError("UPSTREAM_STORAGE_BINDING_INVALID") from exc
    if (
        not isinstance(bucket, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
        or _KMS_ARN_RE.fullmatch(str(key_arn)) is None
        or any(item.get("bucket") != bucket for item in locations)
        or any(item.get("sse_kms_key_arn") != key_arn for item in locations)
        or any(
            item.get("sse_algorithm") != "aws:kms"
            for item in locations[:4]
        )
        or gug365_plan.get("gug363_pre_function_binding_sha256")
        != gug363_plan.get("gug363_pre_function_binding_sha256")
        or gug365_plan.get("gug363_artifact_signing_contract_digest")
        != gug363_plan.get("artifact_signing_contract_digest")
        or gug365_signed.get("binding_digest") is None
    ):
        _fail("UPSTREAM_STORAGE_BINDING_MISMATCH")
    digest_fields = {
        "gug363_plan_digest": gug363_plan.get("plan_digest"),
        "gug363_artifact_signing_contract_digest": gug363_plan.get(
            "artifact_signing_contract_digest"
        ),
        "gug365_plan_digest": gug365_plan.get("plan_digest"),
        "gug365_ledger_factory_artifact_signing_contract_digest": (
            gug365_plan.get("ledger_factory_artifact_signing_contract_digest")
        ),
        "gug365_signed_artifact_binding_digest": gug365_signed.get(
            "binding_digest"
        ),
    }
    if any(
        _DIGEST_RE.fullmatch(str(value)) is None
        for value in digest_fields.values()
    ):
        _fail("UPSTREAM_STORAGE_BINDING_INVALID")
    binding: dict[str, Any] = {
        "schema_version": 1,
        "record_type": STORAGE_BINDING_TYPE,
        **digest_fields,
        "bucket": bucket,
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": key_arn,
        "source_marker": "VALIDATED_GUG363_AND_GUG365_CAUSAL_PLANS",
    }
    return route.seal(binding, "binding_digest")


def derive_foundation_storage_binding(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_publish_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive storage from the sealed pre-revoke foundation authority."""

    try:
        from tooling import (
            platform_authority_plan_permission_repair_artifact_bootstrap as foundation,
        )

        binding = foundation.validate_foundation_publish_binding(
            foundation_publish_binding,
            bootstrap_intent=bootstrap_intent,
        )
    except Exception as exc:
        raise TemplateReadbackError("FOUNDATION_ROUTE_RELEASE_INVALID") from exc
    if set(binding) != _FOUNDATION_STORAGE_BINDING_FIELDS:
        _fail("FOUNDATION_STORAGE_BINDING_INVALID")
    return dict(binding)


def _expected_object_coordinates(
    artifact_kind: str, source_commit: str, bucket: str, version: str
) -> tuple[str, str]:
    metadata = _ARTIFACTS[artifact_kind]
    key = (
        "scanalyze/platform-authority/gug-376/plan-policy-repair/"
        f"{metadata['scope']}/{source_commit}/{metadata['filename']}"
    )
    url = (
        f"https://{bucket}.s3.{EXPECTED_REGION}.amazonaws.com/"
        f"{quote(key, safe='/-_.~')}?versionId={quote(version, safe='-_.~')}"
    )
    return key, url


def _parse_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TemplateReadbackError(code) from exc
    if parsed.microsecond:
        _fail(code)
    return parsed


def validate_template_readback_receipt(
    value: Mapping[str, Any],
    *,
    artifact_kind: str,
    source_commit: str,
    now: datetime | None = None,
    materialization_validator: Callable[[Mapping[str, Any]], Any] | None = None,
    expected_storage_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one closed receipt before any downstream descriptor is used."""

    if (
        not isinstance(value, Mapping)
        or set(value) != _RECEIPT_FIELDS
        or artifact_kind not in _ARTIFACTS
        or _COMMIT_RE.fullmatch(str(source_commit)) is None
    ):
        _fail("TEMPLATE_RECEIPT_INVALID")
    receipt = dict(value)
    storage = receipt.get("upstream_storage_binding")
    verifier = receipt.get("verifier")
    legacy_storage = (
        isinstance(storage, Mapping)
        and set(storage) == _STORAGE_BINDING_FIELDS
        and storage.get("schema_version") == 1
        and storage.get("record_type") == STORAGE_BINDING_TYPE
        and storage.get("source_marker")
        == "VALIDATED_GUG363_AND_GUG365_CAUSAL_PLANS"
        and all(
            _DIGEST_RE.fullmatch(str(storage.get(field, ""))) is not None
            for field in (
                "gug363_plan_digest",
                "gug363_artifact_signing_contract_digest",
                "gug365_plan_digest",
                "gug365_ledger_factory_artifact_signing_contract_digest",
                "gug365_signed_artifact_binding_digest",
            )
        )
    )
    foundation_storage = (
        isinstance(storage, Mapping)
        and set(storage) == _FOUNDATION_STORAGE_BINDING_FIELDS
        and storage.get("schema_version") == 1
        and storage.get("record_type")
        == (
            "scanalyze.platform_authority."
            "gug376_artifact_foundation_publish_binding.v1"
        )
        and storage.get("source_commit") == source_commit
        and storage.get("source_marker")
        == "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY"
        and all(
            _DIGEST_RE.fullmatch(str(storage.get(field, ""))) is not None
            for field in (
                "bootstrap_intent_digest",
                "foundation_readback_digest",
                "access_update_intent_digest",
                "access_readback_digest",
                "reviewed_sources_digest",
                "route_template_receipt_digest",
                "delegation_template_receipt_digest",
            )
        )
    )
    foundation_mode = (
        foundation_storage
        and expected_storage_binding is not None
        and storage == expected_storage_binding
    )
    if (
        not (legacy_storage or foundation_storage)
        or route.digest_value(
            {key: item for key, item in storage.items() if key != "binding_digest"}
        )
        != storage.get("binding_digest")
        or (
            expected_storage_binding is not None
            and storage != expected_storage_binding
        )
    ):
        _fail("TEMPLATE_STORAGE_BINDING_INVALID")
    if foundation_storage and not foundation_mode:
        _fail("FOUNDATION_STORAGE_BINDING_REQUIRED")
    expected_profile = (
        EXPECTED_PROFILE if foundation_mode else LEGACY_EXPECTED_PROFILE
    )
    caller_pattern = _FOUNDATION_CALLER_RE if foundation_mode else _CALLER_RE
    bucket = receipt.get("bucket")
    version = receipt.get("version")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("record_type") != RECORD_TYPE
        or receipt.get("source_commit") != source_commit
        or receipt.get("source_path") != _ARTIFACTS[artifact_kind]["source_path"]
        or _DIGEST_RE.fullmatch(str(receipt.get("source_sha256", ""))) is None
        or _DIGEST_RE.fullmatch(str(receipt.get("artifact_sha256", ""))) is None
        or not isinstance(bucket, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
        or not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
        or version.casefold() == "null"
        or type(receipt.get("content_length")) is not int
        or not 0 < receipt["content_length"] <= MAX_TEMPLATE_BYTES
        or receipt.get("sse_algorithm") != "aws:kms"
        or _KMS_ARN_RE.fullmatch(str(receipt.get("sse_kms_key_arn", "")))
        is None
        or storage.get("bucket") != bucket
        or storage.get("sse_algorithm") != receipt.get("sse_algorithm")
        or storage.get("sse_kms_key_arn") != receipt.get("sse_kms_key_arn")
        or not isinstance(verifier, Mapping)
        or set(verifier) != {"account_id", "caller_arn", "profile", "region"}
        or verifier.get("account_id") != EXPECTED_ACCOUNT_ID
        or verifier.get("profile") != expected_profile
        or verifier.get("region") != EXPECTED_REGION
        or caller_pattern.fullmatch(str(verifier.get("caller_arn", ""))) is None
        or receipt.get("source_marker") != SOURCE_MARKER
        or receipt.get("aws_calls") != 4
        or receipt.get("aws_mutations") != 0
    ):
        _fail("TEMPLATE_RECEIPT_INVALID")
    expected_key, expected_url = _expected_object_coordinates(
        artifact_kind, source_commit, bucket, version
    )
    if (
        receipt.get("key") != expected_key
        or receipt.get("template_url") != expected_url
    ):
        _fail("TEMPLATE_OBJECT_COORDINATES_INVALID")
    materialization = receipt.get("materialization_receipt")
    if artifact_kind in {
        "pep_template",
        "pep_protection_template",
        "broker_template",
        "broker_protection_template",
    }:
        try:
            if materialization_validator is not None:
                materialization = materialization_validator(materialization)
            elif artifact_kind in {"pep_template", "pep_protection_template"}:
                materialization = seed.validate_pep_template_materialization_receipt(
                    materialization,
                    expected_protection_enabled=(
                        artifact_kind == "pep_protection_template"
                    ),
                )
            else:
                materialization = seed.validate_broker_seed_receipt(
                    materialization,
                    expected_protection_enabled=(
                        artifact_kind == "broker_protection_template"
                    ),
                )
        except Exception as exc:
            raise TemplateReadbackError(
                "TEMPLATE_MATERIALIZATION_RECEIPT_INVALID"
            ) from exc
        if (
            materialization.get("source_commit") != source_commit
            or materialization.get("template_sha256")
            != receipt.get("artifact_sha256")
            or materialization.get("template_bytes")
            != receipt.get("content_length")
        ):
            _fail("TEMPLATE_MATERIALIZATION_BINDING_MISMATCH")
        receipt["materialization_receipt"] = materialization
    elif (
        materialization is not None
        or receipt.get("source_sha256") != receipt.get("artifact_sha256")
    ):
        _fail("PUBLIC_TEMPLATE_RECEIPT_INVALID")
    evaluated = now or datetime.now(timezone.utc)
    if evaluated.tzinfo is None or evaluated.utcoffset() is None:
        _fail("CLOCK_INVALID")
    observed = _parse_timestamp(
        receipt.get("observed_at"), "TEMPLATE_RECEIPT_TIME_INVALID"
    )
    evaluated = evaluated.astimezone(timezone.utc).replace(microsecond=0)
    if observed > evaluated or (evaluated - observed).total_seconds() > 3600:
        _fail("TEMPLATE_RECEIPT_STALE")
    if foundation_mode:
        access_not_after = _parse_timestamp(
            storage.get("access_not_after"),
            "FOUNDATION_ACCESS_WINDOW_INVALID",
        )
        if not observed < access_not_after:
            _fail("FOUNDATION_ACCESS_WINDOW_CLOSED")
    expected_seal = route.digest_value(
        {key: item for key, item in receipt.items() if key != "receipt_digest"}
    )
    if receipt.get("receipt_digest") != expected_seal:
        _fail("TEMPLATE_RECEIPT_DIGEST_INVALID")
    receipt["upstream_storage_binding"] = dict(storage)
    receipt["verifier"] = dict(verifier)
    return receipt


def pep_template_descriptor(
    value: Mapping[str, Any],
    *,
    source_commit: str,
    gug363_plan: Mapping[str, Any],
    gug365_plan: Mapping[str, Any],
    upstream_source_root: Path,
    now: datetime | None = None,
    gug363_validator: Callable[..., Any] | None = None,
    gug365_validator: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Return the exact broker-seed PEP descriptor from an attested receipt."""

    expected_storage = derive_upstream_storage_binding(
        gug363_plan=gug363_plan,
        gug365_plan=gug365_plan,
        source_root=upstream_source_root,
        gug363_validator=gug363_validator,
        gug365_validator=gug365_validator,
    )
    receipt = validate_template_readback_receipt(
        value,
        artifact_kind="pep_template",
        source_commit=source_commit,
        now=now,
        expected_storage_binding=expected_storage,
    )
    return {
        "bucket": str(receipt["bucket"]),
        "key": str(receipt["key"]),
        "version": str(receipt["version"]),
        "url": str(receipt["template_url"]),
    }


def pep_protection_template_descriptor(
    value: Mapping[str, Any],
    *,
    source_commit: str,
    gug363_plan: Mapping[str, Any],
    gug365_plan: Mapping[str, Any],
    upstream_source_root: Path,
    now: datetime | None = None,
    gug363_validator: Callable[..., Any] | None = None,
    gug365_validator: Callable[..., Any] | None = None,
) -> dict[str, str]:
    """Return the exact broker-seed PEP protection descriptor."""

    expected_storage = derive_upstream_storage_binding(
        gug363_plan=gug363_plan,
        gug365_plan=gug365_plan,
        source_root=upstream_source_root,
        gug363_validator=gug363_validator,
        gug365_validator=gug365_validator,
    )
    receipt = validate_template_readback_receipt(
        value,
        artifact_kind="pep_protection_template",
        source_commit=source_commit,
        now=now,
        expected_storage_binding=expected_storage,
    )
    return {
        "bucket": str(receipt["bucket"]),
        "key": str(receipt["key"]),
        "version": str(receipt["version"]),
        "url": str(receipt["template_url"]),
    }


def _object_metadata(
    response: Mapping[str, Any],
    *,
    version: str,
    expected_size: int,
    kms_key_arn: str,
    expected_checksum: str,
    code: str,
) -> None:
    checksum = response.get("ChecksumSHA256")
    checksum_type = response.get("ChecksumType")
    if (
        response.get("VersionId") != version
        or type(response.get("ContentLength")) is not int
        or response.get("ContentLength") != expected_size
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("SSEKMSKeyId") != kms_key_arn
        or response.get("DeleteMarker") is True
        or response.get("ContentRange") is not None
        or (checksum is None and checksum_type is not None)
        or (
            checksum is not None
            and (
                checksum != expected_checksum
                or checksum_type not in (None, "FULL_OBJECT")
            )
        )
    ):
        _fail(code)


def _read_body(body: Any, *, expected_size: int) -> bytes:
    if body is None or not callable(getattr(body, "read", None)):
        _fail("S3_OBJECT_BODY_INVALID")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            remaining = MAX_TEMPLATE_BYTES + 1 - total
            if remaining <= 0:
                _fail("S3_OBJECT_BODY_TOO_LARGE")
            requested = min(65_536, remaining)
            chunk = body.read(requested)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                _fail("S3_OBJECT_BODY_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except TemplateReadbackError:
        raise
    except Exception as exc:
        raise TemplateReadbackError("S3_OBJECT_BODY_INVALID") from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    payload = b"".join(chunks)
    if len(payload) != expected_size:
        _fail("S3_OBJECT_BODY_INVALID")
    return payload


def _get_object(
    s3: Any,
    *,
    request: Mapping[str, str],
    expected_size: int,
    kms_key_arn: str,
    expected_checksum: str,
) -> bytes:
    try:
        response = s3.get_object(**dict(request))
    except Exception as exc:
        code = _aws_error_code(exc)
        if code in (
            "AccessDenied",
            "AccessDeniedException",
            "KMSAccessDeniedException",
        ):
            raise TemplateReadbackError(
                "S3_GET_OR_KMS_DECRYPT_AUTHORITY_REQUIRED"
            ) from exc
        raise TemplateReadbackError("S3_OBJECT_GET_FAILED") from exc
    if not isinstance(response, Mapping):
        _fail("S3_OBJECT_GET_INVALID")
    _object_metadata(
        response,
        version=request["VersionId"],
        expected_size=expected_size,
        kms_key_arn=kms_key_arn,
        expected_checksum=expected_checksum,
        code="S3_OBJECT_GET_INVALID",
    )
    return _read_body(response.get("Body"), expected_size=expected_size)


def _aws_error_code(error: Exception) -> str | None:
    response = getattr(error, "response", None)
    error_body = response.get("Error") if isinstance(response, Mapping) else None
    code = error_body.get("Code") if isinstance(error_body, Mapping) else None
    return code if isinstance(code, str) else None


def _head_object(s3: Any, *, request: Mapping[str, str]) -> Mapping[str, Any]:
    try:
        response = s3.head_object(**dict(request))
    except Exception as exc:
        if _aws_error_code(exc) in (
            "AccessDenied",
            "AccessDeniedException",
            "KMSAccessDeniedException",
        ):
            raise TemplateReadbackError(
                "S3_GET_OR_KMS_DECRYPT_AUTHORITY_REQUIRED"
            ) from exc
        raise TemplateReadbackError("S3_OBJECT_HEAD_FAILED") from exc
    if not isinstance(response, Mapping):
        _fail("S3_OBJECT_HEAD_INVALID")
    return response


def attest_template_readback(
    *,
    source_root: Path,
    upstream_source_root: Path | None = None,
    source_commit: str,
    artifact_kind: str,
    version: str,
    gug363_plan: Mapping[str, Any],
    gug365_plan: Mapping[str, Any],
    aws_profile: str,
    expected_account_id: str,
    region: str,
    private_artifact: bytes | None = None,
    materialization_receipt: Mapping[str, Any] | None = None,
    git: GitPort | None = None,
    session_factory: Callable[[str, str], Any] | None = None,
    config_factory: Callable[[], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
    environment: Mapping[str, str] | None = None,
    gug363_validator: Callable[..., Any] | None = None,
    gug365_validator: Callable[..., Any] | None = None,
    materialization_validator: Callable[[Mapping[str, Any]], Any] | None = None,
    bootstrap_intent: Mapping[str, Any] | None = None,
    foundation_publish_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Attest one exact template version using four read-only AWS calls."""

    foundation_mode = (
        bootstrap_intent is not None or foundation_publish_binding is not None
    )
    if foundation_mode and (
        bootstrap_intent is None or foundation_publish_binding is None
    ):
        _fail("FOUNDATION_PUBLISH_BINDING_REQUIRED")
    expected_profile = (
        EXPECTED_PROFILE if foundation_mode else LEGACY_EXPECTED_PROFILE
    )
    expected_sso_role = (
        EXPECTED_SSO_ROLE if foundation_mode else LEGACY_EXPECTED_SSO_ROLE
    )
    caller_pattern = _FOUNDATION_CALLER_RE if foundation_mode else _CALLER_RE
    if (
        not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit) is None
        or artifact_kind not in _ARTIFACTS
        or not isinstance(version, str)
        or _VERSION_RE.fullmatch(version) is None
        or version.casefold() == "null"
        or aws_profile != expected_profile
        or expected_account_id != EXPECTED_ACCOUNT_ID
        or region != EXPECTED_REGION
    ):
        _fail("ATTESTATION_INPUT_INVALID")
    _validate_environment(
        environment if environment is not None else os.environ,
        expected_profile=expected_profile,
    )
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise TemplateReadbackError("SOURCE_ROOT_INVALID") from exc
    if not source_root.is_absolute() or source_root.is_symlink() or root != source_root:
        _fail("SOURCE_ROOT_INVALID")
    upstream_candidate = upstream_source_root or source_root
    try:
        upstream_root = upstream_candidate.resolve(strict=True)
    except OSError as exc:
        raise TemplateReadbackError("UPSTREAM_SOURCE_ROOT_INVALID") from exc
    if (
        not upstream_candidate.is_absolute()
        or upstream_candidate.is_symlink()
        or upstream_root != upstream_candidate
    ):
        _fail("UPSTREAM_SOURCE_ROOT_INVALID")
    adapter = git or SubprocessGit(root)
    _validate_git_source(adapter, source_commit, expected_root=root)
    metadata = _ARTIFACTS[artifact_kind]
    try:
        source_payload = adapter.read_at(source_commit, metadata["source_path"])
    except (OSError, route.RouteSeedError) as exc:
        raise TemplateReadbackError("SOURCE_OBJECT_READ_FAILED") from exc
    if not isinstance(source_payload, bytes) or not source_payload:
        _fail("SOURCE_OBJECT_INVALID")
    if artifact_kind in {
        "pep_template",
        "pep_protection_template",
        "broker_template",
        "broker_protection_template",
    }:
        if (
            not isinstance(private_artifact, bytes)
            or not 0 < len(private_artifact) <= MAX_TEMPLATE_BYTES
            or not isinstance(materialization_receipt, Mapping)
        ):
            _fail("TEMPLATE_MATERIALIZED_ARTIFACT_REQUIRED")
        try:
            if materialization_validator is not None:
                validated_materialization = materialization_validator(
                    materialization_receipt
                )
            elif artifact_kind in {"pep_template", "pep_protection_template"}:
                validated_materialization = (
                    seed.validate_pep_template_materialization_receipt(
                        materialization_receipt,
                        expected_protection_enabled=(
                            artifact_kind == "pep_protection_template"
                        ),
                    )
                )
            else:
                validated_materialization = seed.validate_broker_seed_receipt(
                    materialization_receipt,
                    expected_protection_enabled=(
                        artifact_kind == "broker_protection_template"
                    ),
                )
        except Exception as exc:
            raise TemplateReadbackError(
                "TEMPLATE_MATERIALIZATION_RECEIPT_INVALID"
            ) from exc
        if (
            not isinstance(validated_materialization, Mapping)
            or validated_materialization.get("source_commit") != source_commit
            or validated_materialization.get("template_sha256")
            != route.bytes_digest(private_artifact)
        ):
            _fail("TEMPLATE_MATERIALIZATION_BINDING_MISMATCH")
        artifact_payload = private_artifact
        materialization: Mapping[str, Any] | None = dict(validated_materialization)
    else:
        if private_artifact is not None or materialization_receipt is not None:
            _fail("PUBLIC_TEMPLATE_PRIVATE_INPUT_FORBIDDEN")
        artifact_payload = source_payload
        materialization = None
    if not 0 < len(artifact_payload) <= MAX_TEMPLATE_BYTES:
        _fail("TEMPLATE_SIZE_INVALID")

    clock_reader = clock or (lambda: datetime.now(timezone.utc))
    observed = clock_reader()
    observed_at = _timestamp(observed)
    if foundation_mode:
        assert bootstrap_intent is not None
        assert foundation_publish_binding is not None
        storage = derive_foundation_storage_binding(
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
        )
        observed_utc = _parse_timestamp(observed_at, "CLOCK_INVALID")
        access_not_before = _parse_timestamp(
            bootstrap_intent.get("access_not_before"),
            "FOUNDATION_ACCESS_WINDOW_INVALID",
        )
        access_not_after = _parse_timestamp(
            storage.get("access_not_after"),
            "FOUNDATION_ACCESS_WINDOW_INVALID",
        )
        if not access_not_before <= observed_utc < access_not_after:
            _fail("FOUNDATION_ACCESS_WINDOW_CLOSED")
    else:
        if not isinstance(gug363_plan, Mapping) or not isinstance(
            gug365_plan, Mapping
        ):
            _fail("UPSTREAM_STORAGE_BINDING_REQUIRED")
        storage = derive_upstream_storage_binding(
            gug363_plan=gug363_plan,
            gug365_plan=gug365_plan,
            source_root=upstream_root,
            gug363_validator=gug363_validator,
            gug365_validator=gug365_validator,
        )
    bucket = str(storage["bucket"])
    key, template_url = _expected_object_coordinates(
        artifact_kind, source_commit, bucket, version
    )
    kms_key_arn = str(storage["sse_kms_key_arn"])
    request = {
        "Bucket": bucket,
        "Key": key,
        "VersionId": version,
        "ExpectedBucketOwner": expected_account_id,
        "ChecksumMode": "ENABLED",
    }
    session = _new_session(aws_profile, region, session_factory)
    _validate_session(
        session,
        aws_profile,
        region,
        expected_sso_role=expected_sso_role,
    )
    config = _client_config(config_factory)

    # Identity is both the first client and first AWS call.  S3 is not even
    # constructed until the exact SSO account/role/session has been proven.
    sts = _exact_client(session, "sts", region, config)
    identity = _call(
        sts.get_caller_identity,
        code="STS_IDENTITY_READ_FAILED",
    )
    caller_arn = identity.get("Arn")
    if (
        identity.get("Account") != expected_account_id
        or not isinstance(caller_arn, str)
        or caller_pattern.fullmatch(caller_arn) is None
    ):
        _fail("STS_IDENTITY_INVALID")
    aws_calls = 1

    s3 = _exact_client(session, "s3", region, config)
    versioning = _call(
        s3.get_bucket_versioning,
        code="S3_BUCKET_VERSIONING_READ_FAILED",
        Bucket=bucket,
        ExpectedBucketOwner=expected_account_id,
    )
    aws_calls += 1
    if versioning.get("Status") != "Enabled" or versioning.get(
        "MFADelete", "Disabled"
    ) not in ("Disabled", "Enabled"):
        _fail("S3_BUCKET_VERSIONING_INVALID")

    digest = sha256(artifact_payload).digest()
    expected_checksum = base64.b64encode(digest).decode("ascii")
    head = _head_object(s3, request=request)
    aws_calls += 1
    _object_metadata(
        head,
        version=version,
        expected_size=len(artifact_payload),
        kms_key_arn=kms_key_arn,
        expected_checksum=expected_checksum,
        code="S3_OBJECT_HEAD_INVALID",
    )
    remote_payload = _get_object(
        s3,
        request=request,
        expected_size=len(artifact_payload),
        kms_key_arn=kms_key_arn,
        expected_checksum=expected_checksum,
    )
    aws_calls += 1
    if remote_payload != artifact_payload:
        _fail("S3_OBJECT_BYTES_MISMATCH")

    observed_at = _timestamp(clock_reader())
    if foundation_mode:
        completed = _parse_timestamp(observed_at, "CLOCK_INVALID")
        access_not_before = _parse_timestamp(
            bootstrap_intent.get("access_not_before"),
            "FOUNDATION_ACCESS_WINDOW_INVALID",
        )
        access_not_after = _parse_timestamp(
            storage.get("access_not_after"),
            "FOUNDATION_ACCESS_WINDOW_INVALID",
        )
        if not access_not_before <= completed < access_not_after:
            _fail("FOUNDATION_ACCESS_WINDOW_CLOSED")

    receipt: dict[str, Any] = {
        "schema_version": 1,
        "record_type": RECORD_TYPE,
        "source_commit": source_commit,
        "source_path": metadata["source_path"],
        "source_sha256": route.bytes_digest(source_payload),
        "bucket": bucket,
        "key": key,
        "version": version,
        "template_url": template_url,
        "artifact_sha256": route.bytes_digest(artifact_payload),
        "content_length": len(artifact_payload),
        "sse_algorithm": "aws:kms",
        "sse_kms_key_arn": kms_key_arn,
        "upstream_storage_binding": storage,
        "materialization_receipt": materialization,
        "verifier": {
            "account_id": expected_account_id,
            "caller_arn": caller_arn,
            "profile": aws_profile,
            "region": region,
        },
        "observed_at": observed_at,
        "source_marker": SOURCE_MARKER,
        "aws_calls": aws_calls,
        "aws_mutations": 0,
    }
    sealed = route.seal(receipt, "receipt_digest")
    return validate_template_readback_receipt(
        sealed,
        artifact_kind=artifact_kind,
        source_commit=source_commit,
        now=observed,
        materialization_validator=materialization_validator,
        expected_storage_binding=storage,
    )


def write_private_receipt(
    *, private_root: Path, output_name: str, receipt: Mapping[str, Any]
) -> Path:
    """Create one owner-only receipt and durably sync its directory entry."""

    if _OUTPUT_RE.fullmatch(output_name) is None:
        _fail("OUTPUT_NAME_INVALID")
    try:
        return seed._write_private_payload(  # noqa: SLF001
            private_root=private_root,
            name=output_name,
            payload=(route.canonical_json(dict(receipt)) + "\n").encode("utf-8"),
        )
    except seed.BrokerSeedError as exc:
        raise TemplateReadbackError(exc.code) from exc


__all__ = [
    "DEFAULT_OUTPUT_NAMES",
    "EXPECTED_ACCOUNT_ID",
    "EXPECTED_PROFILE",
    "EXPECTED_REGION",
    "EXPECTED_SSO_ROLE",
    "FOUNDATION_EXPECTED_PROFILE",
    "FOUNDATION_EXPECTED_SSO_ROLE",
    "GitPort",
    "MAX_TEMPLATE_BYTES",
    "RECORD_TYPE",
    "STORAGE_BINDING_TYPE",
    "SubprocessGit",
    "TemplateReadbackError",
    "attest_template_readback",
    "derive_foundation_storage_binding",
    "derive_upstream_storage_binding",
    "pep_template_descriptor",
    "pep_protection_template_descriptor",
    "validate_template_readback_receipt",
    "write_private_receipt",
]
