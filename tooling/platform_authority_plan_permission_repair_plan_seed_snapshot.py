"""Connected read-only producer for the private GUG-376 Plan seed snapshot.

The producer has one narrow purpose: prove that the live
``ScanalyzeAuthorityBootstrapPlan`` permission set and its generated IAM role
both contain the exact reviewed predecessor policy.  It uses two explicit SSO
profiles, limits itself to read-only calls, verifies each identity with STS
before constructing any inventory client, and persists one owner-only private
snapshot.

No method in this module performs an AWS mutation.  The snapshot remains
``production_status=NO-GO`` because it is an input to the protected broker
route, not evidence that the route executed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from tooling import platform_authority_bootstrap as bootstrap
from tooling import platform_authority_plan_permission_repair as repair
from tooling import platform_authority_plan_permission_repair_broker_config as broker_config
from tooling import platform_authority_plan_permission_repair_deployment_route as route


AUTHORITY_PROFILE = "042360977644_AWSReadOnlyAccess"
MANAGEMENT_PROFILE = "839393571433_ReadOnlyAccess"
AUTHORITY_SSO_ROLE = "AWSReadOnlyAccess"
MANAGEMENT_SSO_ROLE = "AWSReadOnlyAccess"
EXPECTED_REGION = route.REGION
DEFAULT_OUTPUT_NAME = "plan-seed-snapshot.json"
POLICY_SOURCE_PATH = "policies/iam/platform-authority-bootstrap-plan-role.json"
MAX_PROVIDER_PAGES = 64
MAX_PROVIDER_ITEMS = 10_000

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_INSTANCE_RE = re.compile(r"^arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}$")
_STORE_RE = re.compile(r"^d-[a-z0-9]{10,}$")
_PERMISSION_SET_RE = re.compile(
    r"^arn:aws:sso:::permissionSet/ssoins-[A-Za-z0-9]{16}/ps-[A-Za-z0-9]{16}$"
)
_PRINCIPAL_RE = re.compile(
    r"^(?:[0-9a-f]{10}-)?[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_ROLE_NAME_RE = re.compile(
    r"^AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"
)
_SAML_PROVIDER_RE = re.compile(
    r"^arn:aws:iam::042360977644:saml-provider/"
    r"AWSSSO_[A-Za-z0-9+=,.@_-]+_DO_NOT_DELETE$"
)
_KMS_RE = re.compile(
    r"^arn:aws:kms:us-east-1:839393571433:key/"
    r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
)
_OUTPUT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_CALLER_PATTERNS = {
    route.AUTHORITY_ACCOUNT_ID: re.compile(
        r"^arn:aws:sts::042360977644:assumed-role/"
        r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
        r"[A-Za-z0-9+=,.@_-]{1,64}$"
    ),
    route.MANAGEMENT_ACCOUNT_ID: re.compile(
        r"^arn:aws:sts::839393571433:assumed-role/"
        r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
        r"[A-Za-z0-9+=,.@_-]{1,64}$"
    ),
}
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
_ENDPOINT_HOSTS = {
    "sts": f"sts.{EXPECTED_REGION}.amazonaws.com",
    "sso-admin": f"sso.{EXPECTED_REGION}.amazonaws.com",
    "identitystore": f"identitystore.{EXPECTED_REGION}.amazonaws.com",
    "iam": "iam.amazonaws.com",
}


class PlanSeedSnapshotError(RuntimeError):
    """Stable public-safe failure from the connected snapshot boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PlanSeedSnapshotError(code)


class _ProviderReadError(RuntimeError):
    def __init__(self, operation: str, cause: Exception) -> None:
        self.operation = operation
        self.cause = cause
        super().__init__(operation)


class GitPort(Protocol):
    def root(self) -> Path: ...

    def branch(self) -> str: ...

    def head(self) -> str: ...

    def origin_main(self) -> str: ...

    def status(self) -> str: ...

    def read_at(self, commit: str, path: str) -> bytes: ...


class SubprocessGit:
    """Shell-free reader for the exact reviewed Git object."""

    def __init__(self, source_root: Path) -> None:
        try:
            self._root = source_root.resolve(strict=True)
        except OSError as exc:
            raise PlanSeedSnapshotError("SOURCE_ROOT_INVALID") from exc

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
            raise PlanSeedSnapshotError("GIT_READ_FAILED") from exc
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


class _CallLedger:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def call(
        self,
        operation: str,
        method: Callable[..., Any],
        /,
        **request: Any,
    ) -> Mapping[str, Any]:
        self.calls.append(operation)
        try:
            response = method(**request)
        except PlanSeedSnapshotError:
            raise
        except Exception as exc:
            raise _ProviderReadError(operation, exc) from exc
        if not isinstance(response, Mapping):
            _fail("AWS_RESPONSE_INVALID")
        return response


def _aws_error_code(error: Exception) -> str | None:
    if isinstance(error, _ProviderReadError):
        error = error.cause
    response = getattr(error, "response", None)
    body = response.get("Error") if isinstance(response, Mapping) else None
    code = body.get("Code") if isinstance(body, Mapping) else None
    return code if isinstance(code, str) else None


def _validate_environment(environment: Mapping[str, str]) -> None:
    if any(environment.get(name) for name in _AMBIENT_FORBIDDEN) or any(
        name.startswith("AWS_ENDPOINT_URL") and value
        for name, value in environment.items()
    ):
        _fail("AWS_ENVIRONMENT_UNSAFE")
    if any(
        environment.get(name)
        for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE")
    ):
        _fail("AMBIENT_AWS_PROFILE_FORBIDDEN")
    if any(
        environment.get(name) not in (None, "", EXPECTED_REGION)
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
    ):
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
        raise PlanSeedSnapshotError("AWS_SDK_UNAVAILABLE") from exc
    return boto3.Session(profile_name=profile, region_name=region)


def _validate_session(
    session: Any,
    *,
    profile: str,
    account_id: str,
    sso_role: str,
    region: str,
) -> None:
    if (
        profile == "default"
        or getattr(session, "profile_name", None) != profile
        or getattr(session, "region_name", None) != region
    ):
        _fail("AWS_SESSION_DRIFT")
    sdk_session = getattr(session, "_session", None)
    full_config = getattr(sdk_session, "full_config", None)
    profiles = full_config.get("profiles") if isinstance(full_config, Mapping) else None
    document = profiles.get(profile) if isinstance(profiles, Mapping) else None
    modern = (
        isinstance(document, Mapping)
        and isinstance(document.get("sso_session"), str)
        and bool(document.get("sso_session"))
    )
    legacy = isinstance(document, Mapping) and all(
        isinstance(document.get(key), str) and bool(document.get(key))
        for key in ("sso_start_url", "sso_region")
    )
    sessions = (
        full_config.get("sso_sessions")
        if isinstance(full_config, Mapping)
        else None
    )
    selected = (
        sessions.get(document["sso_session"])
        if modern and isinstance(sessions, Mapping)
        else None
    )
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(_PROFILE_ALLOWED)
        or document.get("sso_account_id") != account_id
        or document.get("sso_role_name") != sso_role
        or document.get("region", region) != region
        or not (modern or legacy)
        or (
            modern
            and (
                not isinstance(selected, Mapping)
                or not isinstance(selected.get("sso_start_url"), str)
                or not selected.get("sso_start_url")
                or selected.get("sso_region") != region
            )
        )
        or (legacy and document.get("sso_region") != region)
    ):
        _fail("AWS_PROFILE_CONFIGURATION_INVALID")
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise PlanSeedSnapshotError("AWS_SSO_CREDENTIALS_UNAVAILABLE") from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        _fail("AWS_CREDENTIAL_SOURCE_INVALID")


def _client_config(factory: Callable[[], Any] | None) -> Any:
    if factory is not None:
        return factory()
    try:
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        raise PlanSeedSnapshotError("AWS_SDK_UNAVAILABLE") from exc
    return Config(
        connect_timeout=3,
        read_timeout=8,
        retries={"mode": "standard", "total_max_attempts": 1},
        ignore_configured_endpoint_urls=True,
    )


def _exact_client(session: Any, service: str, region: str, config: Any) -> Any:
    try:
        client = session.client(service, region_name=region, config=config)
        endpoint = urlsplit(str(client.meta.endpoint_url))
    except Exception as exc:
        raise PlanSeedSnapshotError("AWS_CLIENT_INVALID") from exc
    if (
        service not in _ENDPOINT_HOSTS
        or endpoint.scheme != "https"
        or endpoint.hostname != _ENDPOINT_HOSTS[service]
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.port is not None
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        _fail("AWS_ENDPOINT_INVALID")
    return client


def _validate_git_source(
    git: GitPort, *, source_root: Path, source_commit: str
) -> None:
    try:
        exact = (
            git.root() == source_root
            and git.branch() == "main"
            and git.head() == source_commit
            and git.origin_main() == source_commit
            and git.status() == ""
        )
    except Exception as exc:
        raise PlanSeedSnapshotError("SOURCE_GIT_INVALID") from exc
    if not exact:
        _fail("SOURCE_NOT_EXACT_CLEAN_MAIN")


def _source_policies(
    *,
    git: GitPort,
    source_commit: str,
    bootstrap_change_set_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        canonical_name = repair.validate_bootstrap_change_set_name(
            bootstrap_change_set_name
        )
        payload = git.read_at(source_commit, POLICY_SOURCE_PATH)
        template = json.loads(payload.decode("utf-8"))
        if type(template) is not dict:
            raise ValueError("policy template is not an object")
        target = bootstrap.render_bootstrap_iam_policy(
            policy_template=template,
            binding=bootstrap.BootstrapBinding(
                authority_account_id=route.AUTHORITY_ACCOUNT_ID,
                region=route.REGION,
                stack_name="scanalyze-platform-authority-state-backend",
                state_bucket_name=(
                    "scanalyze-platform-authority-042360977644-us-east-1-state"
                ),
                state_key="platform-authority/terraform.tfstate",
                destination_account_ids=(route.MANAGEMENT_ACCOUNT_ID,),
            ),
            change_set_name=canonical_name,
        )
        predecessor = repair.render_predecessor_policy(target)
        repair.policy_delta_digest(predecessor, target)
    except Exception as exc:
        raise PlanSeedSnapshotError("SOURCE_POLICY_INVALID") from exc
    return predecessor, target


def _normal_policy(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        parsed: Any = dict(value)
    elif isinstance(value, str):
        parsed = None
        for candidate in (value, unquote(value)):
            try:
                parsed = json.loads(
                    candidate,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            break
    else:
        parsed = None
    try:
        normalized = json.loads(route.canonical_json(parsed))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PlanSeedSnapshotError("POLICY_READBACK_MALFORMED") from exc
    statements = normalized.get("Statement") if isinstance(normalized, Mapping) else None
    if isinstance(statements, Mapping):
        normalized["Statement"] = [dict(statements)]
    if (
        type(normalized) is not dict
        or normalized.get("Version") != "2012-10-17"
        or not isinstance(normalized.get("Statement"), list)
        or not all(
            isinstance(item, Mapping) for item in normalized["Statement"]
        )
    ):
        _fail("POLICY_READBACK_MALFORMED")
    return normalized


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _paginate_token(
    ledger: _CallLedger,
    client: Any,
    method_name: str,
    result_key: str,
    **request: Any,
) -> list[Any]:
    values: list[Any] = []
    token: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        page_request = dict(request)
        if token is not None:
            page_request["NextToken"] = token
        response = ledger.call(
            f"{method_name}", getattr(client, method_name), **page_request
        )
        page = response.get(result_key)
        if not isinstance(page, list):
            _fail("AWS_PAGINATION_INVALID")
        values.extend(page)
        if len(values) > MAX_PROVIDER_ITEMS:
            _fail("AWS_PAGINATION_LIMIT")
        next_token = response.get("NextToken")
        if next_token is None:
            return values
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
        ):
            _fail("AWS_PAGINATION_INVALID")
        seen.add(next_token)
        token = next_token
    _fail("AWS_PAGINATION_LIMIT")


def _paginate_marker(
    ledger: _CallLedger,
    client: Any,
    method_name: str,
    result_key: str,
    **request: Any,
) -> list[Any]:
    values: list[Any] = []
    marker: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_PROVIDER_PAGES):
        page_request = dict(request)
        if marker is not None:
            page_request["Marker"] = marker
        response = ledger.call(
            f"{method_name}", getattr(client, method_name), **page_request
        )
        page = response.get(result_key)
        if not isinstance(page, list):
            _fail("AWS_PAGINATION_INVALID")
        values.extend(page)
        if len(values) > MAX_PROVIDER_ITEMS:
            _fail("AWS_PAGINATION_LIMIT")
        truncated = response.get("IsTruncated", False)
        if truncated is False:
            return values
        next_marker = response.get("Marker")
        if (
            truncated is not True
            or not isinstance(next_marker, str)
            or not next_marker
            or next_marker in seen
        ):
            _fail("AWS_PAGINATION_INVALID")
        seen.add(next_marker)
        marker = next_marker
    _fail("AWS_PAGINATION_LIMIT")


def _identity(
    ledger: _CallLedger,
    sts: Any,
    *,
    account_id: str,
    profile: str,
) -> dict[str, str]:
    try:
        response = ledger.call("sts:GetCallerIdentity", sts.get_caller_identity)
    except PlanSeedSnapshotError:
        raise
    except Exception as exc:
        raise PlanSeedSnapshotError("STS_IDENTITY_READ_FAILED") from exc
    caller = response.get("Arn")
    if (
        response.get("Account") != account_id
        or not isinstance(caller, str)
        or _CALLER_PATTERNS[account_id].fullmatch(caller) is None
    ):
        _fail("STS_IDENTITY_INVALID")
    return {
        "profile": profile,
        "account_id": account_id,
        "caller_arn": caller,
        "region": EXPECTED_REGION,
    }


def _describe_instance(
    ledger: _CallLedger, sso: Any
) -> tuple[str, str, str, str | None]:
    instances = _paginate_token(
        ledger, sso, "list_instances", "Instances"
    )
    if len(instances) != 1 or not isinstance(instances[0], Mapping):
        _fail("IDENTITY_CENTER_INSTANCE_SET_INVALID")
    listed = instances[0]
    instance_arn = listed.get("InstanceArn")
    store_id = listed.get("IdentityStoreId")
    if (
        not isinstance(instance_arn, str)
        or _INSTANCE_RE.fullmatch(instance_arn) is None
        or not isinstance(store_id, str)
        or _STORE_RE.fullmatch(store_id) is None
    ):
        _fail("IDENTITY_CENTER_INSTANCE_INVALID")
    response = ledger.call(
        "describe_instance", sso.describe_instance, InstanceArn=instance_arn
    )
    details = response.get("EncryptionConfigurationDetails")
    if (
        response.get("InstanceArn") != instance_arn
        or response.get("IdentityStoreId") != store_id
        or response.get("OwnerAccountId") != route.MANAGEMENT_ACCOUNT_ID
        or response.get("Status") != "ACTIVE"
        or not isinstance(details, Mapping)
        or details.get("EncryptionStatus") != "ENABLED"
    ):
        _fail("IDENTITY_CENTER_INSTANCE_INVALID")
    kms_mode = details.get("KeyType")
    kms_key = details.get("KmsKeyArn")
    if (
        kms_mode == "AWS_OWNED_KMS_KEY"
        and kms_key is not None
    ) or (
        kms_mode == "CUSTOMER_MANAGED_KEY"
        and (
            not isinstance(kms_key, str)
            or _KMS_RE.fullmatch(kms_key) is None
        )
    ):
        _fail("IDENTITY_CENTER_KMS_INVALID")
    if kms_mode not in {"AWS_OWNED_KMS_KEY", "CUSTOMER_MANAGED_KEY"}:
        _fail("IDENTITY_CENTER_KMS_INVALID")
    return instance_arn, store_id, str(kms_mode), kms_key


def _permission_set(
    ledger: _CallLedger,
    sso: Any,
    identitystore: Any,
    *,
    instance_arn: str,
    identity_store_id: str,
    predecessor: Mapping[str, Any],
) -> dict[str, Any]:
    arns = _paginate_token(
        ledger,
        sso,
        "list_permission_sets",
        "PermissionSets",
        InstanceArn=instance_arn,
    )
    if (
        not arns
        or any(
            not isinstance(item, str)
            or _PERMISSION_SET_RE.fullmatch(item) is None
            for item in arns
        )
        or len(arns) != len(set(arns))
    ):
        _fail("PERMISSION_SET_INVENTORY_INVALID")
    matches: list[dict[str, Any]] = []
    for permission_set_arn in sorted(arns):
        response = ledger.call(
            "describe_permission_set",
            sso.describe_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        )
        described = response.get("PermissionSet")
        if (
            not isinstance(described, Mapping)
            or described.get("PermissionSetArn") != permission_set_arn
            or not isinstance(described.get("Name"), str)
        ):
            _fail("PERMISSION_SET_INVENTORY_INVALID")
        if described.get("Name") == repair.PLAN_PERMISSION_SET_NAME:
            matches.append(dict(described))
    if len(matches) != 1:
        _fail("PLAN_PERMISSION_SET_SET_INVALID")
    described = matches[0]
    permission_set_arn = str(described["PermissionSetArn"])
    description = described.get("Description")
    if (
        not isinstance(description, str)
        or not 1 <= len(description.encode("utf-8")) <= 700
        or described.get("SessionDuration") != repair.PLAN_SESSION_DURATION
        or described.get("RelayState") not in (None, "")
    ):
        _fail("PLAN_PERMISSION_SET_METADATA_INVALID")
    raw_tags = _paginate_token(
        ledger,
        sso,
        "list_tags_for_resource",
        "Tags",
        InstanceArn=instance_arn,
        ResourceArn=permission_set_arn,
    )
    if (
        not raw_tags
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"Key", "Value"}
            or not isinstance(item.get("Key"), str)
            or not item.get("Key")
            or not isinstance(item.get("Value"), str)
            or not item.get("Value")
            for item in raw_tags
        )
    ):
        _fail("PLAN_PERMISSION_SET_TAGS_INVALID")
    tags = {str(item["Key"]): str(item["Value"]) for item in raw_tags}
    if len(tags) != len(raw_tags):
        _fail("PLAN_PERMISSION_SET_TAGS_INVALID")
    inline = _normal_policy(
        ledger.call(
            "get_inline_policy_for_permission_set",
            sso.get_inline_policy_for_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        ).get("InlinePolicy")
    )
    managed = _paginate_token(
        ledger,
        sso,
        "list_managed_policies_in_permission_set",
        "AttachedManagedPolicies",
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn,
    )
    customer = _paginate_token(
        ledger,
        sso,
        "list_customer_managed_policy_references_in_permission_set",
        "CustomerManagedPolicyReferences",
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn,
    )
    try:
        boundary = ledger.call(
            "get_permissions_boundary_for_permission_set",
            sso.get_permissions_boundary_for_permission_set,
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set_arn,
        ).get("PermissionsBoundary")
    except Exception as exc:
        if _aws_error_code(exc) in {
            "ResourceNotFoundException",
            "ResourceNotFound",
        }:
            boundary = None
        else:
            raise PlanSeedSnapshotError(
                "PERMISSION_SET_BOUNDARY_READ_FAILED"
            ) from exc
    if managed or customer or boundary is not None:
        _fail("FOREIGN_PERMISSION_SET_AUTHORITY")
    accounts = _paginate_token(
        ledger,
        sso,
        "list_accounts_for_provisioned_permission_set",
        "AccountIds",
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn,
    )
    if accounts != [route.AUTHORITY_ACCOUNT_ID]:
        _fail("PROVISIONED_ACCOUNT_SET_INVALID")
    assignments = _paginate_token(
        ledger,
        sso,
        "list_account_assignments",
        "AccountAssignments",
        InstanceArn=instance_arn,
        AccountId=route.AUTHORITY_ACCOUNT_ID,
        PermissionSetArn=permission_set_arn,
    )
    if len(assignments) != 1 or not isinstance(assignments[0], Mapping):
        _fail("PLAN_ASSIGNMENT_SET_INVALID")
    assignment = assignments[0]
    principal_id = assignment.get("PrincipalId")
    if (
        assignment.get("AccountId") != route.AUTHORITY_ACCOUNT_ID
        or assignment.get("PermissionSetArn") != permission_set_arn
        or assignment.get("PrincipalType") != "USER"
        or not isinstance(principal_id, str)
        or _PRINCIPAL_RE.fullmatch(principal_id) is None
    ):
        _fail("PLAN_ASSIGNMENT_SET_INVALID")
    user = ledger.call(
        "describe_user",
        identitystore.describe_user,
        IdentityStoreId=identity_store_id,
        UserId=principal_id,
    )
    if user.get("UserId") != principal_id:
        _fail("PLAN_PRINCIPAL_INVALID")
    pending = _pending_operations(
        ledger,
        sso,
        instance_arn=instance_arn,
        permission_set_arn=permission_set_arn,
    )
    if pending != 0:
        _fail("PLAN_PENDING_OPERATION")
    if inline != dict(predecessor):
        _fail("LIVE_PERMISSION_SET_POLICY_NOT_PREDECESSOR")
    return {
        "permission_set_arn": permission_set_arn,
        "permission_set_description": description,
        "permission_set_tags": dict(sorted(tags.items())),
        "principal_id": principal_id,
    }


def _pending_operations(
    ledger: _CallLedger,
    sso: Any,
    *,
    instance_arn: str,
    permission_set_arn: str,
) -> int:
    specifications = (
        (
            "list_account_assignment_creation_status",
            "AccountAssignmentsCreationStatus",
            "describe_account_assignment_creation_status",
            "AccountAssignmentCreationRequestId",
            "AccountAssignmentCreationStatus",
        ),
        (
            "list_account_assignment_deletion_status",
            "AccountAssignmentsDeletionStatus",
            "describe_account_assignment_deletion_status",
            "AccountAssignmentDeletionRequestId",
            "AccountAssignmentDeletionStatus",
        ),
        (
            "list_permission_set_provisioning_status",
            "PermissionSetsProvisioningStatus",
            "describe_permission_set_provisioning_status",
            "ProvisionPermissionSetRequestId",
            "PermissionSetProvisioningStatus",
        ),
    )
    pending = 0
    for list_name, result_key, describe_name, request_key, detail_key in specifications:
        summaries = _paginate_token(
            ledger,
            sso,
            list_name,
            result_key,
            InstanceArn=instance_arn,
            Filter={"Status": "IN_PROGRESS"},
        )
        for summary in summaries:
            if (
                not isinstance(summary, Mapping)
                or summary.get("Status") != "IN_PROGRESS"
                or not isinstance(summary.get("RequestId"), str)
                or not summary.get("RequestId")
            ):
                _fail("OPERATION_READBACK_MALFORMED")
            request_id = str(summary["RequestId"])
            detail = ledger.call(
                describe_name,
                getattr(sso, describe_name),
                InstanceArn=instance_arn,
                **{request_key: request_id},
            ).get(detail_key)
            if (
                not isinstance(detail, Mapping)
                or detail.get("RequestId") != request_id
                or detail.get("Status") != "IN_PROGRESS"
                or not isinstance(detail.get("PermissionSetArn"), str)
            ):
                _fail("OPERATION_READBACK_MALFORMED")
            if detail.get("PermissionSetArn") == permission_set_arn:
                pending += 1
    return pending


def _saml_provider(value: Any) -> str:
    policy = _normal_policy(value)
    statements = policy.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        _fail("SAML_TRUST_MISMATCH")
    statement = statements[0]
    if not isinstance(statement, Mapping):
        _fail("SAML_TRUST_MISMATCH")
    actions = statement.get("Action")
    if isinstance(actions, str):
        action_values = [actions]
    elif isinstance(actions, list) and all(
        isinstance(item, str) for item in actions
    ):
        action_values = actions
    else:
        _fail("SAML_TRUST_MISMATCH")
    action_set = set(action_values)
    principal = statement.get("Principal")
    provider = principal.get("Federated") if isinstance(principal, Mapping) else None
    if (
        statement.get("Effect") != "Allow"
        or action_set != {"sts:AssumeRoleWithSAML", "sts:TagSession"}
        or len(action_values) != 2
        or not isinstance(provider, str)
        or _SAML_PROVIDER_RE.fullmatch(provider) is None
        or principal != {"Federated": provider}
        or statement.get("Condition")
        != {"StringEquals": {"SAML:aud": repair.SAML_AUDIENCE}}
        or set(statement)
        != {"Effect", "Principal", "Action", "Condition"}
    ):
        _fail("SAML_TRUST_MISMATCH")
    return provider


def _generated_role(
    ledger: _CallLedger,
    iam: Any,
    *,
    predecessor: Mapping[str, Any],
) -> dict[str, str]:
    roles = _paginate_marker(
        ledger,
        iam,
        "list_roles",
        "Roles",
        PathPrefix="/aws-reserved/sso.amazonaws.com/",
    )
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("RoleName"), str)
        or not item.get("RoleName")
        or not isinstance(item.get("Arn"), str)
        or not item.get("Arn")
        or not isinstance(item.get("Path"), str)
        or not item.get("Path")
        for item in roles
    ):
        _fail("GENERATED_ROLE_INVENTORY_INVALID")
    role_names = [str(item["RoleName"]) for item in roles]
    if len(role_names) != len(set(role_names)):
        _fail("GENERATED_ROLE_INVENTORY_INVALID")
    candidates = [
        item
        for item in roles
        if isinstance(item, Mapping)
        and isinstance(item.get("RoleName"), str)
        and str(item["RoleName"]).startswith(repair.PLAN_ROLE_PREFIX)
    ]
    if len(candidates) != 1:
        _fail("GENERATED_ROLE_SET_INVALID")
    listed = candidates[0]
    role_name = str(listed["RoleName"])
    role_arn = (
        f"arn:aws:iam::{route.AUTHORITY_ACCOUNT_ID}:role/"
        f"aws-reserved/sso.amazonaws.com/{role_name}"
    )
    if (
        _ROLE_NAME_RE.fullmatch(role_name) is None
        or listed.get("Path") != "/aws-reserved/sso.amazonaws.com/"
        or listed.get("Arn") != role_arn
    ):
        _fail("GENERATED_ROLE_BINDING_INVALID")
    role = ledger.call("get_role", iam.get_role, RoleName=role_name).get("Role")
    if (
        not isinstance(role, Mapping)
        or role.get("RoleName") != role_name
        or role.get("Arn") != role_arn
        or role.get("Path") != "/aws-reserved/sso.amazonaws.com/"
    ):
        _fail("GENERATED_ROLE_BINDING_INVALID")
    provider = _saml_provider(role.get("AssumeRolePolicyDocument"))
    attached = _paginate_marker(
        ledger,
        iam,
        "list_attached_role_policies",
        "AttachedPolicies",
        RoleName=role_name,
    )
    names = _paginate_marker(
        ledger,
        iam,
        "list_role_policies",
        "PolicyNames",
        RoleName=role_name,
    )
    boundary = role.get("PermissionsBoundary")
    if attached or names != [repair.PLAN_ROLE_INLINE_POLICY_NAME] or boundary is not None:
        _fail("FOREIGN_GENERATED_ROLE_AUTHORITY")
    policy_response = ledger.call(
        "get_role_policy",
        iam.get_role_policy,
        RoleName=role_name,
        PolicyName=repair.PLAN_ROLE_INLINE_POLICY_NAME,
    )
    if (
        policy_response.get("RoleName") != role_name
        or policy_response.get("PolicyName") != repair.PLAN_ROLE_INLINE_POLICY_NAME
        or _normal_policy(policy_response.get("PolicyDocument")) != dict(predecessor)
    ):
        _fail("LIVE_GENERATED_ROLE_POLICY_NOT_PREDECESSOR")
    return {
        "generated_role_arn": role_arn,
        "generated_role_name": role_name,
        "saml_provider_arn": provider,
    }


def _stamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail("CLOCK_INVALID")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def capture_plan_seed_snapshot(
    *,
    source_root: Path,
    source_commit: str,
    bootstrap_change_set_name: str,
    authority_profile: str,
    management_profile: str,
    region: str,
    git: GitPort | None = None,
    session_factory: Callable[[str, str], Any] | None = None,
    config_factory: Callable[[], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Capture and seal the sole live predecessor state accepted by GUG-376."""

    if (
        authority_profile != AUTHORITY_PROFILE
        or management_profile != MANAGEMENT_PROFILE
        or authority_profile == management_profile
        or region != EXPECTED_REGION
        or _COMMIT_RE.fullmatch(str(source_commit)) is None
    ):
        _fail("SNAPSHOT_INPUT_INVALID")
    _validate_environment(environment if environment is not None else os.environ)
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise PlanSeedSnapshotError("SOURCE_ROOT_INVALID") from exc
    if not source_root.is_absolute() or source_root.is_symlink() or root != source_root:
        _fail("SOURCE_ROOT_INVALID")
    source = git or SubprocessGit(root)
    _validate_git_source(source, source_root=root, source_commit=source_commit)
    predecessor, target = _source_policies(
        git=source,
        source_commit=source_commit,
        bootstrap_change_set_name=bootstrap_change_set_name,
    )
    try:
        canonical_change_set_name = repair.validate_bootstrap_change_set_name(
            bootstrap_change_set_name
        )
    except Exception as exc:
        raise PlanSeedSnapshotError("SOURCE_POLICY_INVALID") from exc

    management = _new_session(management_profile, region, session_factory)
    authority = _new_session(authority_profile, region, session_factory)
    _validate_session(
        management,
        profile=management_profile,
        account_id=route.MANAGEMENT_ACCOUNT_ID,
        sso_role=MANAGEMENT_SSO_ROLE,
        region=region,
    )
    _validate_session(
        authority,
        profile=authority_profile,
        account_id=route.AUTHORITY_ACCOUNT_ID,
        sso_role=AUTHORITY_SSO_ROLE,
        region=region,
    )
    config = _client_config(config_factory)
    ledger = _CallLedger()

    # Both caller gates complete before SSO Admin, Identity Store, or IAM is
    # even constructed.  This makes STS the first two and only identity calls.
    try:
        management_sts = _exact_client(management, "sts", region, config)
        management_verifier = _identity(
            ledger,
            management_sts,
            account_id=route.MANAGEMENT_ACCOUNT_ID,
            profile=management_profile,
        )
        authority_sts = _exact_client(authority, "sts", region, config)
        authority_verifier = _identity(
            ledger,
            authority_sts,
            account_id=route.AUTHORITY_ACCOUNT_ID,
            profile=authority_profile,
        )

        sso = _exact_client(management, "sso-admin", region, config)
        identitystore = _exact_client(
            management, "identitystore", region, config
        )
        iam = _exact_client(authority, "iam", region, config)
        instance_arn, store_id, kms_mode, kms_key = _describe_instance(
            ledger, sso
        )
        plan = _permission_set(
            ledger,
            sso,
            identitystore,
            instance_arn=instance_arn,
            identity_store_id=store_id,
            predecessor=predecessor,
        )
        role = _generated_role(ledger, iam, predecessor=predecessor)
    except PlanSeedSnapshotError:
        raise
    except _ProviderReadError as exc:
        raise PlanSeedSnapshotError("AWS_READ_FAILED") from exc
    observed = (clock or (lambda: datetime.now(timezone.utc)))()
    observed_at = _stamp(observed)
    principal_id = str(plan["principal_id"])
    snapshot: dict[str, Any] = {
        "schema_version": 1,
        "record_type": broker_config.PLAN_SNAPSHOT_RECORD_TYPE,
        "source_commit": source_commit,
        "bootstrap_change_set_name": canonical_change_set_name,
        "management_account_id": route.MANAGEMENT_ACCOUNT_ID,
        "authority_account_id": route.AUTHORITY_ACCOUNT_ID,
        "region": region,
        "identity_center_instance_arn": instance_arn,
        "identity_store_id": store_id,
        "identity_store_arn": (
            f"arn:aws:identitystore::{route.MANAGEMENT_ACCOUNT_ID}:"
            f"identitystore/{store_id}"
        ),
        "principal_id": principal_id,
        "principal_user_arn": f"arn:aws:identitystore:::user/{principal_id}",
        "permission_set_arn": plan["permission_set_arn"],
        "permission_set_description": plan["permission_set_description"],
        "permission_set_tags": plan["permission_set_tags"],
        "current_policy_digest": repair.canonical_digest(predecessor),
        "desired_policy_digest": repair.canonical_digest(target),
        **role,
        "identity_center_kms_mode": kms_mode,
        "identity_center_kms_key_arn": kms_key,
        "authority_verifier": authority_verifier,
        "identity_center_verifier": management_verifier,
        "observed_at": observed_at,
        "aws_calls": len(ledger.calls),
        "aws_mutations": 0,
        "production_status": "NO-GO",
    }
    sealed = route.seal(snapshot, "snapshot_digest")
    try:
        return broker_config.validate_plan_snapshot(
            sealed,
            source_commit=source_commit,
            now=observed,
        )
    except Exception as exc:
        raise PlanSeedSnapshotError("PLAN_SNAPSHOT_INVALID") from exc


def _private_root(path: Path) -> int:
    if not path.is_absolute() or path.is_symlink():
        _fail("PRIVATE_ROOT_INVALID")
    try:
        if not path.exists():
            path.mkdir(mode=0o700)
        current = path.lstat()
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o700
        ):
            _fail("PRIVATE_ROOT_INVALID")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            os.close(descriptor)
            _fail("PRIVATE_ROOT_INVALID")
        return descriptor
    except PlanSeedSnapshotError:
        raise
    except OSError as exc:
        raise PlanSeedSnapshotError("PRIVATE_ROOT_INVALID") from exc


def write_private_snapshot(
    *,
    private_root: Path,
    output_name: str,
    snapshot: Mapping[str, Any],
    source_commit: str,
    now: datetime,
) -> Path:
    """Create one owner-only snapshot with O_EXCL and durable fsyncs."""

    if _OUTPUT_RE.fullmatch(output_name) is None:
        _fail("OUTPUT_NAME_INVALID")
    try:
        validated = broker_config.validate_plan_snapshot(
            snapshot, source_commit=source_commit, now=now
        )
    except Exception as exc:
        raise PlanSeedSnapshotError("PLAN_SNAPSHOT_INVALID") from exc
    payload = (route.canonical_json(validated) + "\n").encode("utf-8")
    root_fd = _private_root(private_root)
    descriptor: int | None = None
    created = False
    try:
        try:
            descriptor = os.open(
                output_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=root_fd,
            )
            created = True
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    _fail("PRIVATE_SNAPSHOT_WRITE_FAILED")
                remaining = remaining[written:]
            os.fsync(descriptor)
            item = os.fstat(descriptor)
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != os.geteuid()
                or item.st_nlink != 1
                or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_size != len(payload)
            ):
                _fail("PRIVATE_SNAPSHOT_WRITE_FAILED")
            os.close(descriptor)
            descriptor = None
            os.fsync(root_fd)
        except PlanSeedSnapshotError:
            raise
        except FileExistsError as exc:
            raise PlanSeedSnapshotError("PRIVATE_SNAPSHOT_EXISTS") from exc
        except OSError as exc:
            raise PlanSeedSnapshotError("PRIVATE_SNAPSHOT_WRITE_FAILED") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                os.unlink(output_name, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(root_fd)
    return private_root / output_name


__all__ = [
    "AUTHORITY_PROFILE",
    "AUTHORITY_SSO_ROLE",
    "DEFAULT_OUTPUT_NAME",
    "EXPECTED_REGION",
    "GitPort",
    "MANAGEMENT_PROFILE",
    "MANAGEMENT_SSO_ROLE",
    "PlanSeedSnapshotError",
    "SubprocessGit",
    "capture_plan_seed_snapshot",
    "write_private_snapshot",
]
