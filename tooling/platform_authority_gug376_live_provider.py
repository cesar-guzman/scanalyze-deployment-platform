"""Concrete, read-only boto3 adapters for the GUG-376 inventory collectors.

The module is inert at import time.  The production builder is the only path
that can report ``ATTESTED_LIVE``; the injected builder exists for deterministic
tests and can never report AWS or live-provider evidence.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import gzip
from hashlib import sha256
import importlib.abc
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
from types import MappingProxyType
from typing import Any, Protocol
from urllib.parse import urlsplit

from tooling.platform_authority_gug365_upstream_inventory import (
    canonical_digest,
    canonical_json,
    canonical_policy_digest,
)
from tooling.platform_authority_gug376_authority_inventory_collector import (
    AuthorityAccessDenied,
)
from tooling.platform_authority_gug376_live_readonly_orchestrator import (
    ALLOWED_OPERATIONS as _CLOSED_OPERATIONS,
)
from tooling.platform_authority_gug376_live_request_materializer import (
    assert_live_provider_capability_bindings,
)


REGION = "us-east-1"
MAX_PAGES = 50
MAX_RESPONSE_BYTES = 256 * 1024
OPERATION_ALLOWLIST: Mapping[str, frozenset[str]] = MappingProxyType(
    {domain: frozenset(actions) for domain, actions in _CLOSED_OPERATIONS.items()}
)

_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SSO_ROLE_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINCIPAL = re.compile(
    r"^arn:aws:sts::([0-9]{12}):assumed-role/([A-Za-z0-9+=,.@_/-]+)/"
    r"([A-Za-z0-9+=,.@_-]+)$"
)
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_FORBIDDEN_AUTHORITY_NAME_FRAGMENTS = (
    "administrator",
    "admin",
    "bootstrap",
    "seed",
    "deploy",
    "destroy",
)
_AMBIENT = frozenset(
    {"BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
)
_PROFILE_FORBIDDEN = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "credential_process",
        "credential_source",
        "external_id",
        "mfa_serial",
        "role_arn",
        "source_profile",
        "web_identity_token_file",
        "endpoint_url",
        "ca_bundle",
        "services",
    }
)
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
_ACCESS_DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "ForbiddenException",
        "UnauthorizedException",
    }
)
_ABSENT = frozenset(
    {
        "NoSuchBucket",
        "NoSuchBucketPolicy",
        "NoSuchConfiguration",
        "NoSuchEntity",
        "NoSuchEntityException",
        "NoSuchLifecycleConfiguration",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchTagSet",
        "OwnershipControlsNotFoundError",
        "ResourceNotFoundException",
        "ServerSideEncryptionConfigurationNotFoundError",
    }
)
_CONCRETE_PROVIDER_ATTESTATION = object()
_DISCOVERY_PROVIDER_ATTESTATION = object()
_IDENTITY_DISCOVERY_TRANSITION_ATTESTATION = object()
_SDK_RUNTIME_SITE_PATH = Path("site-packages")
_SDK_VIRTUAL_DATA_ROOT = "/__scanalyze_gug392_authenticated_botocore_data__"
_REVIEWED_BOTO3_VERSION = "1.42.57"
_REVIEWED_BOTOCORE_VERSION = "1.42.97"
_REVIEWED_SDK_DISTRIBUTIONS: Mapping[str, str] = MappingProxyType(
    {
        "boto3": _REVIEWED_BOTO3_VERSION,
        "botocore": _REVIEWED_BOTOCORE_VERSION,
        "jmespath": "1.1.0",
        "python-dateutil": "2.9.0.post0",
        "s3transfer": "0.16.1",
        "six": "1.17.0",
        "urllib3": "2.7.0",
    }
)
_REVIEWED_SDK_WHEEL_HASHES: Mapping[str, str] = MappingProxyType(
    {
        "boto3": "74f47051e3b741a0c1e64d57b891076c2c68f8d7b98aee36b044fab1849b4823",
        "botocore": "77d2c8ce1bc592d3fbd7c01c35836f4a5b0cac2ca03ccdf6ffc60faa16b5fadc",
        "jmespath": "a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64",
        "python-dateutil": "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427",
        "s3transfer": "61bcd00ccb83b21a0fe7e91a553fff9729d46c83b4e0106e7c314a733891f7c2",
        "six": "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
        "urllib3": "9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897",
    }
)
_SDK_LOCK_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts/deployment/"
    "platform-authority-gug392-live-provider.requirements.lock"
)
_SDK_LOCK_SHA256 = (
    "a4fa58c14b45e7e74a4310adb8fd35edaa451a41d9deed24adffc54268beb30b"
)
_REVIEWED_SDK_RUNTIME_CONTENT: Mapping[
    str, tuple[str, int, int, str]
] = MappingProxyType(
    {
        "boto3": (
            "boto3",
            56,
            971_054,
            "sha256:225fad2b3365b35603bd0d64758af4d18913041afc3e00675517d6fac616a90a",
        ),
        "botocore": (
            "botocore",
            1_964,
            19_159_088,
            "sha256:238232e9707fdda89f511eb51a6bc9fd6b0cbb520439c3d40268eb2f3ae1e6e6",
        ),
        "jmespath": (
            "jmespath",
            8,
            58_628,
            "sha256:f18986805c6b2cba41b8e2ab35735c07557235b22ec7aba9e3fc0a40ae5c3c73",
        ),
        "python-dateutil": (
            "dateutil",
            19,
            428_136,
            "sha256:bacc05694882d872817410f1afb260dd946f4e2056c44f54ae757441dd21fa58",
        ),
        "s3transfer": (
            "s3transfer",
            16,
            307_726,
            "sha256:f265830479d5c65ffe3f28342f2438eabf5f86c0305725d3000c8910949da49f",
        ),
        "six": (
            "six.py",
            1,
            34_703,
            "sha256:4a16060ca731d07137b8aed95391bc06ba7842e24d9986ed7750eea7ba27715a",
        ),
        "urllib3": (
            "urllib3",
            38,
            420_902,
            "sha256:b898d3f4ba5c262629955a2ce6395cef833c9faf7b7f2b471986a6e3a0f896ac",
        ),
    }
)
_REVIEWED_SDK_TOP_LEVEL = frozenset(
    {
        "boto3",
        "botocore",
        "dateutil",
        "jmespath",
        "s3transfer",
        "six.py",
        "urllib3",
    }
)
_SDK_MODULE_ROOTS: Mapping[str, str] = MappingProxyType(
    {
        "boto3": "boto3",
        "botocore": "botocore",
        "dateutil": "python-dateutil",
        "jmespath": "jmespath",
        "s3transfer": "s3transfer",
        "six": "six",
        "urllib3": "urllib3",
    }
)
_SDK_PRELOAD_ROOTS = frozenset(
    {*_SDK_MODULE_ROOTS, "awscrt", "boto", "certifi"}
)


class LiveProviderError(RuntimeError):
    """Stable, public-safe provider boundary error."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "GUG392_LIVE_PROVIDER_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise LiveProviderError(code)


def _safe_discovery_error(
    exc: Exception, fallback: str
) -> LiveProviderError:
    """Translate only stable GUG-393 boundary codes across lazy imports."""

    code = getattr(exc, "code", None)
    if (
        isinstance(code, str)
        and code.startswith("DISCOVERY_")
        and _TOKEN.fullmatch(code) is not None
    ):
        return LiveProviderError(code)
    return LiveProviderError(fallback)


class CallLedger(Protocol):
    def authorize(
        self,
        *,
        domain: str,
        session_digest: str,
        operation: str,
        retries: int,
        request: Any = None,
        page_token: Any = None,
        pagination_key: str | None = None,
        started_at: str | None = None,
    ) -> str: ...

    def complete(
        self,
        ticket: str,
        response: Any = None,
        *,
        complete: bool = True,
        truncated: bool = False,
        next_token: Any = None,
        outcome: str = "SUCCESS",
        completed_at: str | None = None,
    ) -> None: ...

    def finalize(self) -> tuple[int, str]: ...

    def evidence_events(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class ProviderConfig:
    """Exact dual-profile and caller binding supplied by the private request."""

    authority_profile: str
    identity_center_profile: str
    authority_expected_account_id: str
    authority_expected_principal_digest: str
    authority_expected_sso_role_name_digest: str
    authority_verification_digest: str
    identity_expected_account_id: str
    identity_expected_principal_digest: str
    identity_expected_sso_role_name_digest: str
    identity_authority_verification_digest: str
    validity_gate: Callable[[], None]
    sdk_runtime_root: Path | None = None
    region: str = REGION
    max_pages: int = MAX_PAGES


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_stamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LiveProviderError("POLICY_WINDOW_INVALID") from exc
    if parsed.tzinfo is None or _stamp(parsed) != value:
        _fail("POLICY_WINDOW_INVALID")
    return parsed.astimezone(UTC).replace(microsecond=0)


def _detach(value: Any) -> Any:
    """Produce bounded JSON facts and discard transport metadata."""

    if isinstance(value, Mapping):
        return {
            str(key): _detach(item)
            for key, item in value.items()
            if key != "ResponseMetadata"
        }
    if isinstance(value, (list, tuple)):
        return sorted((_detach(item) for item in value), key=canonical_json)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            _fail("PROVIDER_RESPONSE_INVALID")
        return _stamp(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        return {"byte_length": len(value), "sha256": sha256(value).hexdigest()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    _fail("PROVIDER_RESPONSE_INVALID")


def _bounded(value: Any) -> Any:
    detached = _detach(value)
    try:
        size = len(canonical_json(detached).encode("utf-8"))
    except Exception as exc:
        raise LiveProviderError("PROVIDER_RESPONSE_INVALID") from exc
    if size > MAX_RESPONSE_BYTES:
        _fail("PROVIDER_RESPONSE_TOO_LARGE")
    return detached


_ResponseProjector = Callable[
    [Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]
]


def _selected(value: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return {field: value[field] for field in fields if field in value}


def _fact_digest(value: Any) -> str:
    """Bind an exact fact without retaining its provider-supplied plaintext."""

    return canonical_digest(_detach(value))


def _policy_digest(value: Any) -> str:
    """Bind a policy through the shared source/live canonicalization path."""

    try:
        return canonical_policy_digest(value)
    except ValueError as exc:
        raise LiveProviderError("PROVIDER_RESPONSE_INVALID") from exc


def _fields(*fields: str) -> _ResponseProjector:
    def project(
        value: Mapping[str, Any], request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        del request
        return _selected(value, fields)

    return project


def _item_fields(*fields: str) -> Callable[[Any, Mapping[str, Any]], Any]:
    def project(item: Any, request: Mapping[str, Any]) -> Any:
        del request
        if not isinstance(item, Mapping):
            _fail("PROVIDER_RESPONSE_INVALID")
        return _selected(item, fields)

    return project


def _identity_item(item: Any, request: Mapping[str, Any]) -> Any:
    del request
    if isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return item


def _page(
    item_key: str,
    item_projector: Callable[[Any, Mapping[str, Any]], Any],
    *controls: str,
) -> _ResponseProjector:
    def project(
        value: Mapping[str, Any], request: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        result = _selected(value, controls)
        if item_key not in value:
            return result
        items = value[item_key]
        if not isinstance(items, list):
            _fail("PROVIDER_RESPONSE_INVALID")
        result[item_key] = [item_projector(item, request) for item in items]
        return result

    return project


def _digest_member(
    value: Mapping[str, Any], source: str, target: str
) -> dict[str, Any]:
    return {target: _fact_digest(value[source])} if source in value else {}


def _digest_item(name: str) -> Callable[[Any, Mapping[str, Any]], Any]:
    def project(item: Any, request: Mapping[str, Any]) -> Any:
        del request
        return {name: _fact_digest(item)}

    return project


def _project_tag_item(item: Any, request: Mapping[str, Any]) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result: dict[str, Any] = {}
    for source, target in (
        ("Key", "key_digest"),
        ("Value", "value_digest"),
        ("TagKey", "key_digest"),
        ("TagValue", "value_digest"),
    ):
        if source in item:
            result[target] = _fact_digest(item[source])
    if not result:
        _fail("PROVIDER_RESPONSE_INVALID")
    return result


def _project_kms_grant_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(item, ("KeyId", "Operations", "CreationDate"))
    for source, target in (
        ("GrantId", "grant_id_digest"),
        ("Name", "name_digest"),
        ("GranteePrincipal", "grantee_principal_digest"),
        ("RetiringPrincipal", "retiring_principal_digest"),
        ("IssuingAccount", "issuing_account_digest"),
        ("Constraints", "constraints_digest"),
    ):
        result.update(_digest_member(item, source, target))
    return result


def _project_signer_permission_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(item, ("action", "profileVersion"))
    for source, target in (
        ("principal", "principal_digest"),
        ("statementId", "statement_id_digest"),
    ):
        result.update(_digest_member(item, source, target))
    return result


def _project_sts_identity(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(value, ("Account", "Arn"))
    user_id = value.get("UserId")
    result["UserIdPresent"] = isinstance(user_id, str) and bool(user_id)
    return result


_LAMBDA_RUNTIME_CONFIGURATION_FIELDS = (
    "FunctionArn",
    "Version",
    "Runtime",
    "Architectures",
    "LastModified",
    "CodeSha256",
    "PackageType",
    "State",
    "LastUpdateStatus",
)


def _project_lambda_runtime_item(
    value: Any, request: Mapping[str, Any]
) -> dict[str, Any]:
    del request
    if not isinstance(value, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(value, _LAMBDA_RUNTIME_CONFIGURATION_FIELDS)
    runtime_version = value.get("RuntimeVersionConfig")
    if isinstance(runtime_version, Mapping):
        projected = _selected(runtime_version, ("RuntimeVersionArn",))
        error = runtime_version.get("Error")
        if isinstance(error, Mapping) and "ErrorCode" in error:
            projected["Error"] = {"ErrorCode": error["ErrorCode"]}
        result["RuntimeVersionConfig"] = projected
    return result


def _project_lambda_runtime_configuration(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    return _project_lambda_runtime_item(value, request)


_project_lambda_runtime_versions = _page(
    "Versions", _project_lambda_runtime_item, "NextMarker"
)
_project_lambda_functions = _page(
    "Functions", _project_lambda_runtime_item, "NextMarker"
)


def _project_identity_user(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(value.get("UserId"), str) or not value["UserId"]:
        _fail("PROVIDER_RESPONSE_INVALID")
    return {"UserId": value["UserId"]}


def _project_public_access_block(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result: dict[str, Any] = {}
    configuration = value.get("PublicAccessBlockConfiguration")
    if isinstance(configuration, Mapping):
        result["PublicAccessBlockConfiguration"] = _selected(
            configuration,
            (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ),
        )
    return result


def _project_s3_acl(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result: dict[str, Any] = {}
    owner = value.get("Owner")
    if isinstance(owner, Mapping) and "ID" in owner:
        result["OwnerIdDigest"] = _fact_digest(owner["ID"])
    grants = value.get("Grants")
    if grants is not None:
        if not isinstance(grants, list):
            _fail("PROVIDER_RESPONSE_INVALID")
        projected_grants: list[dict[str, Any]] = []
        for grant in grants:
            if not isinstance(grant, Mapping):
                _fail("PROVIDER_RESPONSE_INVALID")
            projected = _selected(grant, ("Permission",))
            grantee = grant.get("Grantee")
            if isinstance(grantee, Mapping):
                projected_grantee = _selected(grantee, ("Type",))
                for source, target in (
                    ("ID", "id_digest"),
                    ("URI", "uri_digest"),
                    ("EmailAddress", "email_address_digest"),
                ):
                    projected_grantee.update(
                        _digest_member(grantee, source, target)
                    )
                projected["Grantee"] = projected_grantee
            projected_grants.append(projected)
        result["Grants"] = projected_grants
    return result


def _project_s3_encryption(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    configuration = value.get("ServerSideEncryptionConfiguration")
    if not isinstance(configuration, Mapping):
        return {}
    rules = configuration.get("Rules")
    if not isinstance(rules, list):
        _fail("PROVIDER_RESPONSE_INVALID")
    projected_rules: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            _fail("PROVIDER_RESPONSE_INVALID")
        projected = _selected(rule, ("BucketKeyEnabled",))
        blocked = rule.get("BlockedEncryptionTypes")
        if isinstance(blocked, list):
            projected["BlockedEncryptionTypes"] = [
                _selected(item, ("EncryptionType",))
                if isinstance(item, Mapping)
                else item
                for item in blocked
            ]
        default = rule.get("ApplyServerSideEncryptionByDefault")
        if isinstance(default, Mapping):
            projected["ApplyServerSideEncryptionByDefault"] = _selected(
                default, ("SSEAlgorithm", "KMSMasterKeyID")
            )
        projected_rules.append(projected)
    return {"ServerSideEncryptionConfiguration": {"Rules": projected_rules}}


def _project_s3_lifecycle(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    return _digest_member(value, "Rules", "RulesDigest")


def _project_s3_policy(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    return _digest_member(value, "Policy", "PolicyDigest")


def _project_s3_tags(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    tags = value.get("TagSet")
    if tags is None:
        return {}
    if not isinstance(tags, list):
        _fail("PROVIDER_RESPONSE_INVALID")
    return {"TagSet": [_project_tag_item(tag, {}) for tag in tags]}


def _project_s3_version_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        item,
        (
            "VersionId",
            "IsLatest",
            "LastModified",
            "ETag",
            "ChecksumAlgorithm",
            "ChecksumType",
            "Size",
            "StorageClass",
        ),
    )
    key = item.get("Key")
    prefix = request.get("Prefix")
    if isinstance(key, str):
        if isinstance(prefix, str) and key.startswith(prefix):
            result["Key"] = key
        else:
            result["KeyDigest"] = _fact_digest(key)
    return result


def _project_s3_versions(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    result = _selected(
        value,
        ("IsTruncated", "NextKeyMarker", "NextVersionIdMarker"),
    )
    for key in ("Versions", "DeleteMarkers"):
        if key not in value:
            continue
        items = value[key]
        if not isinstance(items, list):
            _fail("PROVIDER_RESPONSE_INVALID")
        result[key] = [_project_s3_version_item(item, request) for item in items]
    return result


def _project_s3_objects(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    result = _selected(value, ("IsTruncated", "NextContinuationToken"))
    contents = value.get("Contents")
    if contents is not None:
        if not isinstance(contents, list):
            _fail("PROVIDER_RESPONSE_INVALID")
        result["Contents"] = [
            _project_s3_version_item(item, request) for item in contents
        ]
    return result


def _project_object_attributes(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if "ObjectParts" in value:
        parts = value.get("ObjectParts")
        if isinstance(parts, Mapping) and parts.get("IsTruncated") is True:
            _fail("PROVIDER_PAGE_INCOMPLETE")
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        value,
        (
            "DeleteMarker",
            "LastModified",
            "VersionId",
            "ETag",
            "StorageClass",
            "ObjectSize",
        ),
    )
    checksum = value.get("Checksum")
    if isinstance(checksum, Mapping):
        result["Checksum"] = _selected(
            checksum,
            (
                "ChecksumCRC32",
                "ChecksumCRC32C",
                "ChecksumCRC64NVME",
                "ChecksumSHA1",
                "ChecksumSHA256",
                "ChecksumSHA512",
                "ChecksumMD5",
                "ChecksumXXHASH64",
                "ChecksumXXHASH3",
                "ChecksumXXHASH128",
                "ChecksumType",
            ),
        )
    return result


def _project_s3_ownership(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    controls = value.get("OwnershipControls")
    if not isinstance(controls, Mapping):
        return {}
    rules = controls.get("Rules")
    if not isinstance(rules, list):
        _fail("PROVIDER_RESPONSE_INVALID")
    projected_rules: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            _fail("PROVIDER_RESPONSE_INVALID")
        projected_rules.append(_selected(rule, ("ObjectOwnership",)))
    return {"OwnershipControls": {"Rules": projected_rules}}


def _project_s3_policy_status(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    status = value.get("PolicyStatus")
    return (
        {"PolicyStatus": _selected(status, ("IsPublic",))}
        if isinstance(status, Mapping)
        else {}
    )


def _project_object_metadata(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(
        value,
        (
            "DeleteMarker",
            "LastModified",
            "ContentLength",
            "ETag",
            "ChecksumCRC32",
            "ChecksumCRC32C",
            "ChecksumCRC64NVME",
            "ChecksumSHA1",
            "ChecksumSHA256",
            "ChecksumSHA512",
            "ChecksumMD5",
            "ChecksumXXHASH64",
            "ChecksumXXHASH3",
            "ChecksumXXHASH128",
            "ChecksumType",
            "VersionId",
            "ServerSideEncryption",
            "SSEKMSKeyId",
            "BucketKeyEnabled",
            "StorageClass",
            "ReplicationStatus",
            "ObjectLockMode",
            "ObjectLockRetainUntilDate",
            "ObjectLockLegalHoldStatus",
        ),
    )
    result.update(_digest_member(value, "Metadata", "MetadataDigest"))
    return result


def _project_kms_description(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    metadata = value.get("KeyMetadata")
    if not isinstance(metadata, Mapping):
        return {}
    projected = _selected(
        metadata,
        (
            "AWSAccountId",
            "KeyId",
            "Arn",
            "CreationDate",
            "Enabled",
            "KeyUsage",
            "KeyState",
            "DeletionDate",
            "ValidTo",
            "Origin",
            "ExpirationModel",
            "KeyManager",
            "CustomerMasterKeySpec",
            "KeySpec",
            "EncryptionAlgorithms",
            "SigningAlgorithms",
            "MultiRegion",
            "PendingDeletionWindowInDays",
            "MacAlgorithms",
        ),
    )
    projected.update(_digest_member(metadata, "Description", "DescriptionDigest"))
    return {"KeyMetadata": projected}


def _project_kms_policy(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(value, ("PolicyName",))
    result.update(_digest_member(value, "Policy", "PolicyDigest"))
    return result


def _project_signing_profile_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        item,
        (
            "profileName",
            "profileVersion",
            "profileVersionArn",
            "arn",
            "platformId",
            "status",
        ),
    )
    for source, target in (
        ("validityPeriod", "validity_period_digest"),
        ("signatureValidityPeriod", "signature_validity_period_digest"),
    ):
        result.update(_digest_member(item, source, target))
    return result


def _project_signing_job_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return _selected(
        item,
        (
            "jobId",
            "profileName",
            "profileVersion",
            "profileVersionArn",
            "status",
            "createdAt",
            "completedAt",
            "revokedAt",
        ),
    )


def _project_signing_job(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    result = dict(_project_signing_job_item(value, request))
    for source, target in (
        ("source", "source_digest"),
        ("signedObject", "signed_object_digest"),
        ("signingParameters", "signing_parameters_digest"),
        ("statusReason", "status_reason_digest"),
        ("revocationRecord", "revocation_record_digest"),
    ):
        result.update(_digest_member(value, source, target))
    return result


def _project_signing_profile(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    result = dict(_project_signing_profile_item(value, request))
    for source, target in (
        ("overrides", "overrides_digest"),
        ("signingMaterial", "signing_material_digest"),
        ("signingParameters", "signing_parameters_digest"),
        ("statusReason", "status_reason_digest"),
        ("tags", "tags_digest"),
    ):
        result.update(_digest_member(value, source, target))
    return result


def _project_lambda_code_signing_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        item,
        (
            "CodeSigningConfigId",
            "CodeSigningConfigArn",
            "LastModified",
        ),
    )
    publishers = item.get("AllowedPublishers")
    if isinstance(publishers, Mapping):
        result["AllowedPublishers"] = _selected(
            publishers, ("SigningProfileVersionArns",)
        )
    policies = item.get("CodeSigningPolicies")
    if isinstance(policies, Mapping):
        result["CodeSigningPolicies"] = _selected(
            policies, ("UntrustedArtifactOnDeployment",)
        )
    result.update(_digest_member(item, "Description", "DescriptionDigest"))
    return result


def _project_lambda_code_signing(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    result: dict[str, Any] = {}
    configuration = value.get("CodeSigningConfig")
    if isinstance(configuration, Mapping):
        result["CodeSigningConfig"] = _project_lambda_code_signing_item(
            configuration, request
        )
    return result


def _project_lambda_tags(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    return (
        {"Tags": {"tags_digest": _fact_digest(value["Tags"])}}
        if "Tags" in value
        else {}
    )


def _project_iam_role_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        item,
        (
            "Path",
            "RoleName",
            "Arn",
            "CreateDate",
            "MaxSessionDuration",
        ),
    )
    boundary = item.get("PermissionsBoundary")
    if isinstance(boundary, Mapping):
        result["PermissionsBoundary"] = _selected(
            boundary, ("PermissionsBoundaryType", "PermissionsBoundaryArn")
        )
    for source, target in (
        ("RoleId", "RoleIdDigest"),
        ("Description", "DescriptionDigest"),
        ("Tags", "TagsDigest"),
    ):
        result.update(_digest_member(item, source, target))
    if "AssumeRolePolicyDocument" in item:
        result["AssumeRolePolicyDocumentDigest"] = _policy_digest(
            item["AssumeRolePolicyDocument"]
        )
    return result


def _project_iam_role(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    role = value.get("Role")
    return (
        {"Role": _project_iam_role_item(role, request)}
        if isinstance(role, Mapping)
        else {}
    )


def _project_iam_role_policy(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(value, ("RoleName", "PolicyName"))
    if "PolicyDocument" in value:
        result["PolicyDocumentDigest"] = _policy_digest(
            value["PolicyDocument"]
        )
    return result


def _project_sso_instance_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return _selected(
        item, ("InstanceArn", "IdentityStoreId", "OwnerAccountId", "Status")
    )


def _project_sso_application_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return _selected(item, ("ApplicationArn", "Name"))


def _project_sso_application_description(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(
        value,
        (
            "ApplicationArn",
            "ApplicationProviderArn",
            "ApplicationAccount",
            "InstanceArn",
            "Status",
            "CreatedDate",
            "CreatedFrom",
        ),
    )
    for source, target in (
        ("Name", "NameDigest"),
        ("PortalOptions", "PortalOptionsDigest"),
        ("Description", "DescriptionDigest"),
    ):
        result.update(_digest_member(value, source, target))
    return result


def _project_sso_permission_set(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    permission_set = value.get("PermissionSet")
    if not isinstance(permission_set, Mapping):
        return {}
    result = _selected(
        permission_set,
        (
            "Name",
            "PermissionSetArn",
            "CreatedDate",
            "SessionDuration",
        ),
    )
    result.update(_digest_member(permission_set, "Description", "DescriptionDigest"))
    result.update(_digest_member(permission_set, "RelayState", "RelayStateDigest"))
    return {"PermissionSet": result}


def _project_sso_describe_instance(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(
        value, ("InstanceArn", "IdentityStoreId", "OwnerAccountId", "Status")
    )
    encryption = value.get("EncryptionConfigurationDetails")
    if isinstance(encryption, Mapping):
        result["EncryptionConfigurationDetails"] = _selected(
            encryption, ("KeyType", "KmsKeyArn", "EncryptionStatus")
        )
    return result


def _project_sso_access_scope(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    result = _selected(value, ("Scope",))
    result.update(
        _digest_member(value, "AuthorizedTargets", "AuthorizedTargetsDigest")
    )
    return result


def _project_sso_permission_boundary(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    boundary = value.get("PermissionsBoundary")
    if not isinstance(boundary, Mapping):
        return {}
    projected = _selected(boundary, ("ManagedPolicyArn",))
    customer = boundary.get("CustomerManagedPolicyReference")
    if isinstance(customer, Mapping):
        projected["CustomerManagedPolicyReference"] = _selected(
            customer, ("Name", "Path")
        )
    return {"PermissionsBoundary": projected}


def _project_sso_inline_policy(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if "InlinePolicy" not in value:
        return {}
    return {
        "InlinePolicy": {
            "policy_digest": _policy_digest(value["InlinePolicy"])
        }
    }


def _project_sso_auth_method(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    method = value.get("AuthenticationMethod")
    if not isinstance(method, Mapping):
        return {}
    iam = method.get("Iam")
    if not isinstance(iam, Mapping) or "ActorPolicy" not in iam:
        return {"AuthenticationMethod": {}}
    return {
        "AuthenticationMethod": {
            "Iam": {
                "ActorPolicy": {
                    "policy_digest": _policy_digest(iam["ActorPolicy"])
                }
            }
        }
    }


def _project_sso_auth_index_item(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    return _selected(item, ("AuthenticationMethodType",))


def _is_loopback_pkce_redirect(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and parsed.path == "/callback"
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None
        and parsed.password is None
        and port is not None
        and 1024 <= port <= 65535
    )


def _project_sso_grant(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    grant = value.get("Grant")
    if not isinstance(grant, Mapping):
        return {}
    authorization = grant.get("AuthorizationCode")
    projected_grant: dict[str, Any] = {}
    if isinstance(authorization, Mapping):
        uris = authorization.get("RedirectUris")
        if isinstance(uris, list):
            projected_grant["AuthorizationCode"] = {
                "RedirectUris": [
                    {
                        "loopback_pkce": _is_loopback_pkce_redirect(uri),
                        "uri_digest": _fact_digest(uri),
                    }
                    for uri in uris
                ]
            }
    return {"Grant": projected_grant}


def _project_sso_assignment(
    item: Any, request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    if not isinstance(item, Mapping):
        _fail("PROVIDER_RESPONSE_INVALID")
    result = _selected(
        item,
        ("AccountId", "ApplicationArn", "PermissionSetArn", "PrincipalType"),
    )
    if "PrincipalId" in item:
        result["PrincipalId"] = _fact_digest(item["PrincipalId"])
    return result


def _project_sso_provisioning_status(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    status = value.get("PermissionSetProvisioningStatus")
    if not isinstance(status, Mapping):
        return {}
    return {
        "PermissionSetProvisioningStatus": _selected(
            status,
            ("Status", "RequestId", "AccountId", "PermissionSetArn", "CreatedDate"),
        )
    }


def _project_sso_assignment_creation_status(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    del request
    status = value.get("AccountAssignmentCreationStatus")
    if not isinstance(status, Mapping):
        return {}
    projected = _selected(
        status,
        (
            "Status",
            "RequestId",
            "TargetId",
            "TargetType",
            "PermissionSetArn",
            "PrincipalType",
            "CreatedDate",
        ),
    )
    if "PrincipalId" in status:
        projected["PrincipalId"] = _fact_digest(status["PrincipalId"])
    projected.update(_digest_member(status, "FailureReason", "FailureReasonDigest"))
    return {"AccountAssignmentCreationStatus": projected}


_RESPONSE_PROJECTORS: Mapping[str, _ResponseProjector] = MappingProxyType(
    {
        "sts:GetCallerIdentity": _project_sts_identity,
        "s3:ListAllMyBuckets": _page(
            "Buckets", _item_fields("Name"), "ContinuationToken"
        ),
        "s3:GetAccountPublicAccessBlock": _project_public_access_block,
        "s3:GetBucketPublicAccessBlock": _project_public_access_block,
        "s3:GetBucketAcl": _project_s3_acl,
        "s3:GetBucketEncryption": _project_s3_encryption,
        "s3:GetBucketLifecycleConfiguration": _project_s3_lifecycle,
        "s3:GetBucketLocation": _fields("LocationConstraint"),
        "s3:GetBucketOwnershipControls": _project_s3_ownership,
        "s3:GetBucketPolicy": _project_s3_policy,
        "s3:GetBucketPolicyStatus": _project_s3_policy_status,
        "s3:GetBucketTagging": _project_s3_tags,
        "s3:GetBucketVersioning": _fields("Status", "MFADelete"),
        "s3:ListBucketVersions": _project_s3_versions,
        "s3:ListBucket": _project_s3_objects,
        "s3:GetObject": _project_object_metadata,
        "s3:GetObjectVersion": _project_object_metadata,
        "s3:GetObjectAttributes": _project_object_attributes,
        "s3:GetObjectTagging": _project_s3_tags,
        "s3:GetObjectVersionTagging": _project_s3_tags,
        "kms:ListKeys": _page(
            "Keys", _item_fields("KeyId", "KeyArn"), "NextMarker", "Truncated"
        ),
        "kms:ListAliases": _page(
            "Aliases",
            _item_fields(
                "AliasName",
                "AliasArn",
                "TargetKeyId",
                "CreationDate",
                "LastUpdatedDate",
            ),
            "NextMarker",
            "Truncated",
        ),
        "kms:DescribeKey": _project_kms_description,
        "kms:GetKeyPolicy": _project_kms_policy,
        "kms:GetKeyRotationStatus": _fields(
            "KeyRotationEnabled",
            "RotationPeriodInDays",
            "NextRotationDate",
            "OnDemandRotationStartDate",
        ),
        "kms:ListGrants": _page(
            "Grants", _project_kms_grant_item, "NextMarker", "Truncated"
        ),
        "kms:ListResourceTags": _page(
            "Tags", _project_tag_item, "NextMarker", "Truncated"
        ),
        "signer:ListSigningProfiles": _page(
            "profiles", _project_signing_profile_item, "nextToken"
        ),
        "signer:ListSigningJobs": _page(
            "jobs", _project_signing_job_item, "nextToken"
        ),
        "signer:DescribeSigningJob": _project_signing_job,
        "signer:GetSigningProfile": _project_signing_profile,
        "signer:ListProfilePermissions": _page(
            "permissions", _project_signer_permission_item, "nextToken"
        ),
        "signer:ListTagsForResource": lambda value, request: _digest_member(
            value, "tags", "tags_digest"
        ),
        "signer:GetRevocationStatus": _page(
            "revokedEntities", _digest_item("entity_digest")
        ),
        "signer:ListSigningPlatforms": _page(
            "platforms",
            _item_fields(
                "platformId", "target", "category", "maxSizeInMB", "revocationSupported"
            ),
            "nextToken",
        ),
        "lambda:ListCodeSigningConfigs": _page(
            "CodeSigningConfigs", _project_lambda_code_signing_item, "NextMarker"
        ),
        "lambda:GetCodeSigningConfig": _project_lambda_code_signing,
        "lambda:ListFunctionsByCodeSigningConfig": _page(
            "FunctionArns", _identity_item, "NextMarker"
        ),
        "lambda:ListTags": _project_lambda_tags,
        "lambda:GetFunctionConfiguration": _project_lambda_runtime_configuration,
        "lambda:GetRuntimeManagementConfig": _fields(
            "UpdateRuntimeOn", "RuntimeVersionArn", "FunctionArn"
        ),
        "lambda:ListVersionsByFunction": _project_lambda_runtime_versions,
        "lambda:ListFunctions": _project_lambda_functions,
        "iam:ListRoles": _page(
            "Roles", _project_iam_role_item, "Marker", "IsTruncated"
        ),
        "iam:GetRole": _project_iam_role,
        "iam:ListRolePolicies": _page(
            "PolicyNames", _identity_item, "Marker", "IsTruncated"
        ),
        "iam:GetRolePolicy": _project_iam_role_policy,
        "iam:ListAttachedRolePolicies": _page(
            "AttachedPolicies",
            _item_fields("PolicyName", "PolicyArn"),
            "Marker",
            "IsTruncated",
        ),
        "iam:ListRoleTags": _page(
            "Tags", _project_tag_item, "Marker", "IsTruncated"
        ),
        "sso:ListInstances": _page(
            "Instances", _project_sso_instance_item, "NextToken"
        ),
        "sso:ListApplications": _page(
            "Applications", _project_sso_application_item, "NextToken"
        ),
        "sso:ListPermissionSets": _page(
            "PermissionSets", _identity_item, "NextToken"
        ),
        "sso:DescribePermissionSet": _project_sso_permission_set,
        "sso:DescribeInstance": _project_sso_describe_instance,
        "sso:DescribeApplication": _project_sso_application_description,
        "sso:ListApplicationAuthenticationMethods": _page(
            "AuthenticationMethods", _project_sso_auth_index_item, "NextToken"
        ),
        "sso:GetApplicationAuthenticationMethod": _project_sso_auth_method,
        "sso:ListApplicationGrants": _page(
            "Grants", _item_fields("GrantType"), "NextToken"
        ),
        "sso:GetApplicationGrant": _project_sso_grant,
        "sso:ListApplicationAccessScopes": _page(
            "Scopes", _item_fields("Scope"), "NextToken"
        ),
        "sso:GetApplicationAccessScope": _project_sso_access_scope,
        "sso:GetApplicationAssignmentConfiguration": _fields(
            "AssignmentRequired"
        ),
        "sso:ListTagsForResource": _page(
            "Tags", _project_tag_item, "NextToken"
        ),
        "sso:GetPermissionsBoundaryForPermissionSet": _project_sso_permission_boundary,
        "sso:ListManagedPoliciesInPermissionSet": _page(
            "AttachedManagedPolicies",
            _item_fields("Name", "Arn"),
            "NextToken",
        ),
        "sso:ListCustomerManagedPolicyReferencesInPermissionSet": _page(
            "CustomerManagedPolicyReferences",
            _item_fields("Name", "Path"),
            "NextToken",
        ),
        "sso:GetInlinePolicyForPermissionSet": _project_sso_inline_policy,
        "sso:ListAccountAssignments": _page(
            "AccountAssignments", _project_sso_assignment, "NextToken"
        ),
        "sso:ListPermissionSetProvisioningStatus": _page(
            "PermissionSetsProvisioningStatus",
            _item_fields("Status", "RequestId", "CreatedDate"),
            "NextToken",
        ),
        "sso:DescribePermissionSetProvisioningStatus": _project_sso_provisioning_status,
        "sso:ListAccountsForProvisionedPermissionSet": _page(
            "AccountIds", _identity_item, "NextToken"
        ),
        "sso:DescribeAccountAssignmentCreationStatus": _project_sso_assignment_creation_status,
        "sso:ListAccountAssignmentCreationStatus": _page(
            "AccountAssignmentsCreationStatus",
            _item_fields("Status", "RequestId", "CreatedDate"),
            "NextToken",
        ),
        "sso:ListApplicationAssignments": _page(
            "ApplicationAssignments", _project_sso_assignment, "NextToken"
        ),
        "identitystore:DescribeUser": _project_identity_user,
    }
)

if set(_RESPONSE_PROJECTORS) != set().union(*OPERATION_ALLOWLIST.values()):
    raise RuntimeError("GUG392_RESPONSE_PROJECTOR_COVERAGE_INVALID")


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and isinstance(error.get("Code"), str):
            return str(error["Code"])
    return type(exc).__name__


def _next_page_token(
    page: Mapping[str, Any],
    primary_key: str | None,
    secondary_key: str | None,
) -> str | dict[str, str] | None:
    if primary_key is None:
        return None
    primary = page.get(primary_key)
    secondary = page.get(secondary_key) if secondary_key is not None else None
    if primary is None and secondary is None:
        return None
    if not isinstance(primary, str) or not primary:
        _fail("PROVIDER_PAGE_INVALID")
    if secondary_key is None:
        return primary
    if secondary is not None and (not isinstance(secondary, str) or not secondary):
        _fail("PROVIDER_PAGE_INVALID")
    result = {"primary": primary}
    if secondary is not None:
        result["secondary"] = secondary
    return result


def _ambient_gate(environment: Mapping[str, str]) -> None:
    if any(key.startswith("AWS_") or key in _AMBIENT for key in environment):
        _fail("AMBIENT_AWS_OVERRIDE_FORBIDDEN")


def _forbidden_authority_name(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return any(
        fragment in normalized for fragment in _FORBIDDEN_AUTHORITY_NAME_FRAGMENTS
    )


def _validate_config(config: ProviderConfig) -> None:
    if type(config) is not ProviderConfig or config.region != REGION:
        _fail("PROVIDER_CONFIG_INVALID")
    profiles = (config.authority_profile, config.identity_center_profile)
    if (
        any(not isinstance(item, str) or _PROFILE.fullmatch(item) is None for item in profiles)
        or any(item.casefold() == "default" for item in profiles)
        or any(_forbidden_authority_name(item) for item in profiles)
        or profiles[0].casefold() == profiles[1].casefold()
    ):
        _fail("PROFILE_BINDING_INVALID")
    accounts = (
        config.authority_expected_account_id,
        config.identity_expected_account_id,
    )
    if accounts[0] == accounts[1]:
        _fail("PROFILE_BINDING_INVALID")
    digests = (
        config.authority_expected_principal_digest,
        config.authority_expected_sso_role_name_digest,
        config.authority_verification_digest,
        config.identity_expected_principal_digest,
        config.identity_expected_sso_role_name_digest,
        config.identity_authority_verification_digest,
    )
    if (
        any(_ACCOUNT.fullmatch(str(item)) is None for item in accounts)
        or any(_DIGEST.fullmatch(str(item)) is None for item in digests)
        or type(config.max_pages) is not int
        or not 1 <= config.max_pages <= MAX_PAGES
        or not callable(config.validity_gate)
        or (
            config.sdk_runtime_root is not None
            and not isinstance(config.sdk_runtime_root, Path)
        )
    ):
        _fail("PROVIDER_CONFIG_INVALID")


def _verify_sdk_lock() -> None:
    try:
        if _SDK_LOCK_PATH.is_symlink():
            _fail("AWS_SDK_PROVENANCE_INVALID")
        raw = _SDK_LOCK_PATH.read_bytes()
        if sha256(raw).hexdigest() != _SDK_LOCK_SHA256:
            _fail("AWS_SDK_PROVENANCE_INVALID")
        lines = [
            line
            for line in raw.decode("ascii").splitlines()
            if line and not line.startswith("#")
        ]
    except (OSError, UnicodeDecodeError) as exc:
        raise LiveProviderError("AWS_SDK_PROVENANCE_INVALID") from exc
    if len(lines) != 2 * len(_REVIEWED_SDK_DISTRIBUTIONS):
        _fail("AWS_SDK_PROVENANCE_INVALID")
    versions: dict[str, str] = {}
    wheel_hashes: dict[str, str] = {}
    for index in range(0, len(lines), 2):
        requirement_line, hash_line = lines[index : index + 2]
        if not requirement_line.endswith(" \\") or "==" not in requirement_line:
            _fail("AWS_SDK_PROVENANCE_INVALID")
        name, version = requirement_line[:-2].split("==", 1)
        hash_prefix = "    --hash=sha256:"
        wheel_hash = hash_line.removeprefix(hash_prefix)
        if (
            re.fullmatch(r"[a-z0-9-]+", name) is None
            or re.fullmatch(r"[A-Za-z0-9.]+", version) is None
            or not hash_line.startswith(hash_prefix)
            or re.fullmatch(r"[0-9a-f]{64}", wheel_hash) is None
            or name in versions
        ):
            _fail("AWS_SDK_PROVENANCE_INVALID")
        versions[name] = version
        wheel_hashes[name] = wheel_hash
    if (
        versions != dict(_REVIEWED_SDK_DISTRIBUTIONS)
        or wheel_hashes != dict(_REVIEWED_SDK_WHEEL_HASHES)
    ):
        _fail("AWS_SDK_PROVENANCE_INVALID")


def _runtime_path_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LiveProviderError("AWS_SDK_PROVENANCE_INVALID") from exc
    if stat.S_ISLNK(metadata.st_mode):
        _fail("AWS_SDK_PROVENANCE_INVALID")
    return metadata


def _read_runtime_file(path: Path, *, site_root: Path) -> bytes:
    """Read one owner-controlled regular file without following a link."""

    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        _fail("AWS_SDK_PLATFORM_UNREVIEWED")
    before = _runtime_path_metadata(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid not in {0, os.geteuid()}
        or before.st_mode & 0o022
    ):
        _fail("AWS_SDK_PROVENANCE_INVALID")
    try:
        exact_path = path.resolve(strict=True)
        exact_path.relative_to(site_root)
        if exact_path != path:
            _fail("AWS_SDK_PROVENANCE_INVALID")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read()
            after_open = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except LiveProviderError:
        raise
    except (OSError, ValueError) as exc:
        raise LiveProviderError("AWS_SDK_PROVENANCE_INVALID") from exc
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_uid,
        item.st_size,
        item.st_mtime_ns,
    )
    if identity(before) != identity(opened) or identity(opened) != identity(
        after_open
    ) or identity(after_open) != identity(after):
        _fail("AWS_SDK_PROVENANCE_INVALID")
    return payload


def _trusted_sdk_site_root(runtime_root: Path) -> Path:
    """Resolve one dedicated, closed SDK target installed outside the repo."""

    if (
        os.name != "posix"
        or not hasattr(os, "geteuid")
        or not isinstance(runtime_root, Path)
        or not runtime_root.is_absolute()
        or runtime_root.is_symlink()
    ):
        _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
    try:
        exact_root = runtime_root.resolve(strict=True)
        repository_root = Path(__file__).resolve(strict=True).parents[1]
        if exact_root != runtime_root or not exact_root.is_dir():
            _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
        try:
            exact_root.relative_to(repository_root)
        except ValueError:
            pass
        else:
            _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
        site_root = (exact_root / _SDK_RUNTIME_SITE_PATH).resolve(strict=True)
        if site_root != exact_root / _SDK_RUNTIME_SITE_PATH or not site_root.is_dir():
            _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
    except LiveProviderError:
        raise
    except OSError as exc:
        raise LiveProviderError("AWS_SDK_RUNTIME_ROOT_INVALID") from exc

    trusted_owners = {0, os.geteuid()}
    for ancestor in (exact_root, *exact_root.parents):
        metadata = _runtime_path_metadata(ancestor)
        sticky_root_directory = (
            metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in trusted_owners
            or (metadata.st_mode & 0o022 and not sticky_root_directory)
        ):
            _fail("AWS_SDK_RUNTIME_CUSTODY_INVALID")

    entries = tuple(site_root.iterdir())
    if {entry.name for entry in entries} != _REVIEWED_SDK_TOP_LEVEL:
        _fail("AWS_SDK_RUNTIME_CLOSURE_INVALID")
    for candidate in (site_root, *site_root.rglob("*")):
        metadata = _runtime_path_metadata(candidate)
        if (
            metadata.st_uid not in trusted_owners
            or metadata.st_mode & 0o022
            or not (
                stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISREG(metadata.st_mode)
            )
            or (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink != 1
            )
            or "__pycache__" in candidate.parts
            or candidate.suffix in {".pyc", ".pyo", ".pth"}
        ):
            _fail("AWS_SDK_RUNTIME_CUSTODY_INVALID")
    return site_root


@dataclass(frozen=True, slots=True)
class _RuntimeTreeSnapshot:
    file_count: int
    total_bytes: int
    digest: str
    files: Mapping[Path, bytes]


def _runtime_tree_snapshot(
    *, site_root: Path, runtime_root: Path
) -> _RuntimeTreeSnapshot:
    """Capture every reviewed package byte once, before any SDK import."""

    try:
        if runtime_root.is_symlink():
            _fail("AWS_SDK_PROVENANCE_INVALID")
        exact_runtime_root = runtime_root.resolve(strict=True)
        exact_runtime_root.relative_to(site_root)
        runtime_is_file = exact_runtime_root.is_file()
        if runtime_is_file:
            paths = (exact_runtime_root,)
        elif exact_runtime_root.is_dir():
            paths = tuple(
                sorted(exact_runtime_root.rglob("*"), key=lambda item: str(item))
            )
        else:
            _fail("AWS_SDK_PROVENANCE_INVALID")

        records: list[dict[str, Any]] = []
        files: dict[Path, bytes] = {}
        total_bytes = 0
        for path in paths:
            metadata = _runtime_path_metadata(path)
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                _fail("AWS_SDK_PROVENANCE_INVALID")
            content = _read_runtime_file(path, site_root=site_root)
            total_bytes += len(content)
            if len(records) >= 4_096 or total_bytes > 32 * 1024 * 1024:
                _fail("AWS_SDK_PROVENANCE_INVALID")
            files[path] = content
            records.append(
                {
                    "path": path.relative_to(site_root).as_posix(),
                    "sha256": sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
    except LiveProviderError:
        raise
    except (OSError, ValueError) as exc:
        raise LiveProviderError("AWS_SDK_PROVENANCE_INVALID") from exc
    return _RuntimeTreeSnapshot(
        file_count=len(records),
        total_bytes=total_bytes,
        digest=canonical_digest(records),
        files=MappingProxyType(files),
    )


def _runtime_tree_fingerprint(
    *, site_root: Path, runtime_root: Path
) -> tuple[int, int, str]:
    """Hash every immutable runtime byte before importing the AWS SDK."""

    snapshot = _runtime_tree_snapshot(
        site_root=site_root, runtime_root=runtime_root
    )
    return snapshot.file_count, snapshot.total_bytes, snapshot.digest


@dataclass(frozen=True, slots=True)
class _VerifiedSdkRuntime:
    runtime_root: Path
    site_root: Path
    package_roots: Mapping[str, Path]
    files: Mapping[Path, bytes]
    tree_digest: str
    botocore_data: Mapping[str, bytes]
    ca_bundle_path: Path
    ca_bundle_digest: str

    def guard(self) -> None:
        observed = _capture_verified_sdk_runtime(self.runtime_root)
        if (
            observed.site_root != self.site_root
            or observed.tree_digest != self.tree_digest
            or observed.ca_bundle_digest != self.ca_bundle_digest
        ):
            _fail("AWS_SDK_RUNTIME_CHANGED")

    def authenticated_ca_bundle(self) -> str:
        """Return the pre-import CA snapshot without reopening its path."""

        payload = self.files.get(self.ca_bundle_path)
        if payload is None or sha256(payload).hexdigest() != self.ca_bundle_digest:
            _fail("AWS_SDK_PROVENANCE_INVALID")
        try:
            return payload.decode("ascii")
        except UnicodeDecodeError as exc:
            raise LiveProviderError("AWS_SDK_CA_BUNDLE_INVALID") from exc


def _capture_verified_sdk_runtime(runtime_root: Path) -> _VerifiedSdkRuntime:
    site_root = _trusted_sdk_site_root(runtime_root)
    verified: dict[str, Path] = {}
    all_files: dict[Path, bytes] = {}
    tree_records: list[dict[str, Any]] = []
    for distribution_name, expected in _REVIEWED_SDK_RUNTIME_CONTENT.items():
        relative_root, expected_files, expected_bytes, expected_digest = expected
        candidate = site_root / relative_root
        snapshot = _runtime_tree_snapshot(
            site_root=site_root,
            runtime_root=candidate,
        )
        if (
            snapshot.file_count,
            snapshot.total_bytes,
            snapshot.digest,
        ) != (expected_files, expected_bytes, expected_digest):
            _fail("AWS_SDK_PROVENANCE_INVALID")
        verified[distribution_name] = candidate.resolve(strict=True)
        for path, payload in snapshot.files.items():
            if path in all_files:
                _fail("AWS_SDK_PROVENANCE_INVALID")
            all_files[path] = payload
        tree_records.append(
            {
                "distribution": distribution_name,
                "digest": snapshot.digest,
                "files": snapshot.file_count,
                "bytes": snapshot.total_bytes,
            }
        )
    botocore_data_root = verified["botocore"] / "data"
    botocore_data = {
        path.relative_to(botocore_data_root).as_posix(): payload
        for path, payload in all_files.items()
        if path.is_relative_to(botocore_data_root)
        and path.suffix in {".json", ".gz"}
    }
    ca_bundle_path = verified["botocore"] / "cacert.pem"
    ca_bundle = all_files.get(ca_bundle_path)
    if not botocore_data or ca_bundle is None:
        _fail("AWS_SDK_PROVENANCE_INVALID")
    return _VerifiedSdkRuntime(
        runtime_root=runtime_root,
        site_root=site_root,
        package_roots=MappingProxyType(verified),
        files=MappingProxyType(all_files),
        tree_digest=canonical_digest(tree_records),
        botocore_data=MappingProxyType(botocore_data),
        ca_bundle_path=ca_bundle_path,
        ca_bundle_digest=sha256(ca_bundle).hexdigest(),
    )


class _AuthenticatedSdkSourceLoader(SourceFileLoader):
    """Compile the authenticated in-memory source and never consult bytecode."""

    def __init__(
        self,
        fullname: str,
        path: str,
        *,
        runtime: _VerifiedSdkRuntime,
    ) -> None:
        super().__init__(fullname, path)
        self._runtime = runtime

    def get_code(self, fullname: str) -> Any:
        path = Path(self.get_filename(fullname))
        source = self._runtime.files.get(path)
        if source is None or path.suffix != ".py":
            raise ImportError("authenticated SDK source unavailable")
        return self.source_to_code(source, str(path))

    def get_data(self, path: str) -> bytes:
        candidate = Path(os.path.normpath(path))
        payload = self._runtime.files.get(candidate)
        if payload is None:
            raise OSError("authenticated SDK data unavailable")
        return payload

    def set_data(
        self,
        _path: str,
        _data: bytes,
        *_args: Any,
        **_kwargs: Any,
    ) -> None:
        return None


class _AuthenticatedSdkFinder(importlib.abc.MetaPathFinder):
    """Resolve only the seven reviewed import roots from the memory snapshot."""

    def __init__(self, runtime: _VerifiedSdkRuntime) -> None:
        self.runtime = runtime

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> Any:
        del path, target
        parts = fullname.split(".")
        distribution_name = _SDK_MODULE_ROOTS.get(parts[0])
        if distribution_name is None:
            return None
        if parts[0] == "six" and len(parts) > 1:
            return None
        root = self.runtime.package_roots[distribution_name]
        if root.suffix == ".py":
            if len(parts) != 1 or root not in self.runtime.files:
                raise ModuleNotFoundError(fullname)
            source_path = root
            locations = None
        else:
            relative = parts[1:]
            package_source = root.joinpath(*relative, "__init__.py")
            module_source = root.joinpath(*relative).with_suffix(".py")
            if package_source in self.runtime.files:
                source_path = package_source
                locations = [str(package_source.parent)]
            elif module_source in self.runtime.files:
                source_path = module_source
                locations = None
            else:
                raise ModuleNotFoundError(fullname)
        loader = _AuthenticatedSdkSourceLoader(
            fullname, str(source_path), runtime=self.runtime
        )
        return importlib.util.spec_from_file_location(
            fullname,
            source_path,
            loader=loader,
            submodule_search_locations=locations,
        )


class _ClosedSearchPaths(list[str]):
    def __init__(self, allowed_boto3_data_path: Path) -> None:
        super().__init__([_SDK_VIRTUAL_DATA_ROOT])
        self._allowed_boto3_data_path = allowed_boto3_data_path

    def append(self, value: str) -> None:
        try:
            supplied = Path(value).resolve(strict=True)
        except (OSError, TypeError) as exc:
            raise LiveProviderError("AWS_SDK_DATA_PATH_INVALID") from exc
        if supplied != self._allowed_boto3_data_path:
            _fail("AWS_SDK_DATA_PATH_INVALID")
        # GUG-392 uses low-level clients only. Boto3 resource models are not
        # admitted into the botocore model search path.

    def _reject_mutation(self, *_args: Any, **_kwargs: Any) -> None:
        _fail("AWS_SDK_DATA_PATH_INVALID")

    clear = _reject_mutation
    extend = _reject_mutation
    insert = _reject_mutation
    pop = _reject_mutation
    remove = _reject_mutation
    reverse = _reject_mutation
    sort = _reject_mutation
    __delitem__ = _reject_mutation
    __iadd__ = _reject_mutation
    __imul__ = _reject_mutation
    __setitem__ = _reject_mutation


class _MemoryJsonFileLoader:
    def __init__(self, files: Mapping[str, bytes]) -> None:
        self._files = files

    def _relative(self, path: str) -> str | None:
        prefix = _SDK_VIRTUAL_DATA_ROOT + "/"
        return path[len(prefix) :] if path.startswith(prefix) else None

    def exists(self, file_path: str) -> bool:
        relative = self._relative(file_path)
        return relative is not None and any(
            relative + suffix in self._files for suffix in (".json", ".json.gz")
        )

    def load_file(self, file_path: str) -> Any:
        relative = self._relative(file_path)
        if relative is None:
            return None
        for suffix in (".json", ".json.gz"):
            payload = self._files.get(relative + suffix)
            if payload is None:
                continue
            try:
                raw = gzip.decompress(payload) if suffix == ".json.gz" else payload
                return json.loads(
                    raw.decode("utf-8"), object_pairs_hook=OrderedDict
                )
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                raise LiveProviderError("AWS_SDK_DATA_INVALID") from exc
        return None


def _frozen_botocore_loader(
    loader_class: type[Any], runtime: _VerifiedSdkRuntime
) -> Any:
    files = runtime.botocore_data
    boto3_data = runtime.package_roots["boto3"] / "data"

    class FrozenLoader(loader_class):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__(
                extra_search_paths=[],
                file_loader=_MemoryJsonFileLoader(files),
                include_default_search_paths=False,
            )
            self._search_paths = _ClosedSearchPaths(boto3_data)

        def _matching_files(self, type_name: str) -> tuple[str, ...]:
            endings = (f"/{type_name}.json", f"/{type_name}.json.gz")
            return tuple(
                name for name in files if name.endswith(endings)
            )

        def list_available_services(self, type_name: str) -> list[str]:
            return sorted(
                {
                    name.split("/", 1)[0]
                    for name in self._matching_files(type_name)
                    if name.count("/") >= 2
                }
            )

        def list_api_versions(
            self, service_name: str, type_name: str
        ) -> list[str]:
            versions = {
                parts[1]
                for name in self._matching_files(type_name)
                if (parts := name.split("/"))[:1] == [service_name]
                and len(parts) >= 3
            }
            if not versions:
                from botocore.exceptions import DataNotFoundError

                raise DataNotFoundError(data_path=service_name)
            return sorted(versions)

        def load_data_with_path(self, name: str) -> tuple[Any, str]:
            virtual_path = f"{_SDK_VIRTUAL_DATA_ROOT}/{name}"
            value = self.file_loader.load_file(virtual_path)
            if value is None:
                from botocore.exceptions import DataNotFoundError

                raise DataNotFoundError(data_path=name)
            return value, virtual_path

        def _potential_locations(
            self,
            name: str | None = None,
            must_exist: bool = False,
            is_dir: bool = False,
        ) -> Any:
            del must_exist, is_dir
            yield (
                _SDK_VIRTUAL_DATA_ROOT
                if name is None
                else f"{_SDK_VIRTUAL_DATA_ROOT}/{name}"
            )

        def is_builtin_path(self, path: str) -> bool:
            return path.startswith(_SDK_VIRTUAL_DATA_ROOT + "/")

    return FrozenLoader()


def _reject_preloaded_sdk_modules() -> None:
    if any(
        name == root or name.startswith(root + ".")
        for name in sys.modules
        for root in _SDK_PRELOAD_ROOTS
    ):
        _fail("AWS_SDK_MODULE_PRELOADED")


def _validate_imported_sdk_modules(
    runtime: _VerifiedSdkRuntime, six_module: Any
) -> None:
    six_importer = getattr(six_module, "_importer", None)
    six_known = getattr(six_importer, "known_modules", None)
    if not isinstance(six_known, dict) or six_importer not in sys.meta_path:
        _fail("AWS_SDK_PROVENANCE_INVALID")
    for name, module in tuple(sys.modules.items()):
        root = name.split(".", 1)[0]
        if root not in _SDK_MODULE_ROOTS:
            continue
        if name.startswith("six."):
            registered = six_known.get(name)
            resolver = getattr(registered, "_resolve", None)
            expected_module = resolver() if callable(resolver) else registered
            if registered is None or module is not expected_module:
                _fail("AWS_SDK_PROVENANCE_INVALID")
            continue
        module_file = getattr(module, "__file__", None)
        spec = getattr(module, "__spec__", None)
        loader = getattr(module, "__loader__", None)
        if not isinstance(module_file, str) or spec is None:
            _fail("AWS_SDK_PROVENANCE_INVALID")
        candidate = Path(module_file)
        if (
            candidate not in runtime.files
            or Path(str(getattr(spec, "origin", ""))) != candidate
            or not isinstance(loader, _AuthenticatedSdkSourceLoader)
            or loader._runtime.tree_digest != runtime.tree_digest  # noqa: SLF001
        ):
            _fail("AWS_SDK_PROVENANCE_INVALID")


@dataclass(frozen=True, slots=True)
class _LoadedSdk:
    session_factory: Callable[..., Any]
    config_factory: Callable[..., Any]
    guard: Callable[[], None]


def _load_sdk(runtime_root: Path) -> _LoadedSdk:
    _verify_sdk_lock()
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.pycache_prefix is not None
    ):
        _fail("AWS_SDK_ISOLATION_REQUIRED")
    sys.dont_write_bytecode = True
    _reject_preloaded_sdk_modules()
    runtime = _capture_verified_sdk_runtime(runtime_root)
    finder = _AuthenticatedSdkFinder(runtime)
    sys.meta_path.insert(0, finder)
    try:
        import boto3  # type: ignore[import-not-found]
        import botocore  # type: ignore[import-not-found]
        import botocore.httpsession  # type: ignore[import-not-found]
        import botocore.loaders  # type: ignore[import-not-found]
        import botocore.session  # type: ignore[import-not-found]
        import dateutil  # type: ignore[import-not-found]
        import jmespath  # type: ignore[import-not-found]
        import s3transfer  # type: ignore[import-not-found]
        import six  # type: ignore[import-not-found]
        import urllib3  # type: ignore[import-not-found]
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        raise LiveProviderError("AWS_SDK_UNAVAILABLE") from exc
    try:
        sdk_modules = {
            "boto3": boto3,
            "botocore": botocore,
            "jmespath": jmespath,
            "python-dateutil": dateutil,
            "s3transfer": s3transfer,
            "six": six,
            "urllib3": urllib3,
        }
        sdk_paths = {
            name: Path(module.__file__).resolve(strict=True)
            for name, module in sdk_modules.items()
        }
    except (AttributeError, OSError, TypeError) as exc:
        raise LiveProviderError("AWS_SDK_PROVENANCE_INVALID") from exc
    if (
        any(
            getattr(sdk_modules[name], "__version__", None) != version
            for name, version in _REVIEWED_SDK_DISTRIBUTIONS.items()
        )
        or any(
            path
            != (
                runtime.package_roots[name] / "__init__.py"
                if runtime.package_roots[name].is_dir()
                else runtime.package_roots[name]
            )
            for name, path in sdk_paths.items()
        )
        or not callable(getattr(boto3, "Session", None))
        or getattr(Config, "__module__", None) != "botocore.config"
    ):
        _fail("AWS_SDK_PROVENANCE_INVALID")
    _validate_imported_sdk_modules(runtime, six)
    if any(
        name == root or name.startswith(root + ".")
        for name in sys.modules
        for root in ("awscrt", "certifi", "boto")
    ):
        _fail("AWS_SDK_RUNTIME_CLOSURE_INVALID")
    if (
        botocore.httpsession.DEFAULT_CA_BUNDLE != str(runtime.ca_bundle_path)
        or Path(botocore.httpsession.where()) != runtime.ca_bundle_path
    ):
        _fail("AWS_SDK_CA_BUNDLE_INVALID")

    def guard_loaded_sdk() -> None:
        runtime.guard()
        _validate_imported_sdk_modules(runtime, six)
        if any(
            name == root or name.startswith(root + ".")
            for name in sys.modules
            for root in ("awscrt", "certifi", "boto")
        ):
            _fail("AWS_SDK_RUNTIME_CLOSURE_INVALID")

    guard_loaded_sdk()

    ca_bundle_cadata = runtime.authenticated_ca_bundle()
    minted_tls_contexts: dict[int, Any] = {}

    def authenticated_ssl_context(_session: Any) -> Any:
        context = botocore.httpsession.create_urllib3_context()
        try:
            context.load_verify_locations(cadata=ca_bundle_cadata)
        except (OSError, ValueError) as exc:
            raise LiveProviderError("AWS_SDK_CA_BUNDLE_INVALID") from exc
        context.check_hostname = True
        if (
            context.verify_mode != botocore.httpsession.ssl.CERT_REQUIRED
            or not context.check_hostname
            or context.cert_store_stats().get("x509_ca", 0) < 1
        ):
            _fail("AWS_SDK_CA_BUNDLE_INVALID")
        minted_tls_contexts[id(context)] = context
        return context

    def authenticated_ssl_setup(
        _session: Any, connection: Any, url: Any, verify: Any
    ) -> None:
        context = getattr(connection, "ssl_context", None)
        try:
            scheme = urlsplit(url).scheme.lower() if isinstance(url, str) else ""
        except ValueError:
            scheme = ""
        if (
            scheme != "https"
            or verify is not True
            or minted_tls_contexts.get(id(context)) is not context
            or context.verify_mode != botocore.httpsession.ssl.CERT_REQUIRED
            or not context.check_hostname
        ):
            _fail("AWS_TLS_VERIFICATION_REQUIRED")
        connection.cert_reqs = "CERT_REQUIRED"
        connection.ca_certs = None
        connection.ca_cert_dir = None
        connection.ca_cert_data = None

    def authenticated_proxy_ssl_context(_session: Any, proxy_url: Any) -> Any:
        settings = getattr(getattr(_session, "_proxy_config", None), "settings", None)
        if not isinstance(settings, Mapping) or any(
            key in settings
            for key in (
                "proxy_ca_bundle",
                "proxy_client_cert",
                "proxy_use_forwarding_for_https",
            )
        ):
            _fail("AWS_PROXY_TLS_CONFIGURATION_FORBIDDEN")
        try:
            scheme = (
                urlsplit(proxy_url).scheme.lower()
                if isinstance(proxy_url, str)
                else ""
            )
        except ValueError:
            scheme = ""
        if scheme == "https":
            return authenticated_ssl_context(_session)
        if scheme == "http":
            return None
        _fail("AWS_PROXY_TLS_CONFIGURATION_FORBIDDEN")

    def reject_ca_path_reopen(*_args: Any, **_kwargs: Any) -> str:
        _fail("AWS_SDK_CA_PATH_REOPEN_FORBIDDEN")

    # EndpointCreator captures this class object when botocore.endpoint is
    # imported.  Replace methods on that authenticated object so every normal,
    # SSO and proxy session builds trust from the captured PEM bytes.  Keeping
    # the legacy path helpers fail-closed prevents a later code path from
    # silently reintroducing a mutable cafile lookup.
    botocore.httpsession.URLLib3Session._get_ssl_context = authenticated_ssl_context
    botocore.httpsession.URLLib3Session._setup_ssl_cert = authenticated_ssl_setup
    botocore.httpsession.URLLib3Session._setup_proxy_ssl_context = (
        authenticated_proxy_ssl_context
    )
    botocore.httpsession.where = reject_ca_path_reopen
    botocore.httpsession.get_cert_path = reject_ca_path_reopen

    def session_factory(**kwargs: Any) -> Any:
        guard_loaded_sdk()
        loader = _frozen_botocore_loader(botocore.loaders.Loader, runtime)
        core_session = botocore.session.Session()
        core_session.register_component("data_loader", loader)
        session = boto3.Session(botocore_session=core_session, **kwargs)
        if (
            getattr(session, "_loader", None) is not loader
            or list(loader.search_paths) != [_SDK_VIRTUAL_DATA_ROOT]
        ):
            _fail("AWS_SDK_DATA_PATH_INVALID")
        guard_loaded_sdk()
        return session

    return _LoadedSdk(
        session_factory=session_factory,
        config_factory=Config,
        guard=guard_loaded_sdk,
    )


def _profile_document(session: Any, profile_name: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    try:
        full = session._session.full_config  # noqa: SLF001 - no public profile document API
        profile = full["profiles"][profile_name]
    except (AttributeError, KeyError, TypeError) as exc:
        raise LiveProviderError("SSO_PROFILE_METADATA_UNAVAILABLE") from exc
    if not isinstance(full, Mapping) or not isinstance(profile, Mapping):
        _fail("SSO_PROFILE_METADATA_UNAVAILABLE")
    return full, profile


def _validate_direct_sso_profile(
    session: Any,
    *,
    profile_name: str,
    account_id: str,
    sso_role_name_digest: str,
    region: str,
    opened_at: datetime,
    required_end: datetime,
    observe_credential_bootstrap: bool,
    credential_vend_recorder: Callable[[str], None] | None = None,
) -> tuple[datetime, str, Any]:
    if credential_vend_recorder is not None and not callable(
        credential_vend_recorder
    ):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    full, profile = _profile_document(session, profile_name)
    if set(profile) & _PROFILE_FORBIDDEN or not set(profile) <= _PROFILE_ALLOWED:
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    role_name = profile.get("sso_role_name")
    if (
        profile.get("sso_account_id") != account_id
        or not isinstance(role_name, str)
        or _SSO_ROLE_NAME.fullmatch(role_name) is None
        or _forbidden_authority_name(role_name)
        or canonical_digest(role_name) != sso_role_name_digest
        or profile.get("region", region) != region
    ):
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    modern = isinstance(profile.get("sso_session"), str) and bool(profile["sso_session"])
    legacy = all(
        isinstance(profile.get(key), str) and bool(profile[key])
        for key in ("sso_start_url", "sso_region")
    )
    if not modern and not legacy:
        _fail("DIRECT_SSO_PROFILE_REQUIRED")
    if modern:
        sessions = full.get("sso_sessions")
        selected = sessions.get(profile["sso_session"]) if isinstance(sessions, Mapping) else None
        if not isinstance(selected, Mapping) or not all(
            isinstance(selected.get(key), str) and bool(selected[key])
            for key in ("sso_start_url", "sso_region")
        ):
            _fail("DIRECT_SSO_PROFILE_REQUIRED")
    try:
        sdk_core_session = session._session  # noqa: SLF001
        sdk_core_session.set_config_variable("retry_mode", "standard")
        sdk_core_session.set_config_variable("max_attempts", 1)
        if (
            sdk_core_session.get_config_variable("retry_mode") != "standard"
            or sdk_core_session.get_config_variable("max_attempts") != 1
        ):
            _fail("DIRECT_SSO_CREDENTIAL_RETRIES_FORBIDDEN")
    except LiveProviderError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise LiveProviderError(
            "DIRECT_SSO_CREDENTIAL_RETRIES_FORBIDDEN"
        ) from exc
    bootstrap_calls = 0
    emitter: Any | None = None
    event_name = "before-call.*.*"
    observer_id = f"gug392-sso-bootstrap-{id(session)}"

    def observe_before_call(*_: Any, **event: Any) -> None:
        nonlocal bootstrap_calls
        if event.get("event_name") != "before-call.sso.GetRoleCredentials":
            _fail("DIRECT_SSO_CREDENTIAL_BOOTSTRAP_FORBIDDEN")
        context = event.get("context")
        client_config = context.get("client_config") if isinstance(context, Mapping) else None
        effective_retries = getattr(client_config, "retries", None)
        if not isinstance(effective_retries, Mapping) or dict(effective_retries) != {
            "mode": "standard",
            "total_max_attempts": 1,
        }:
            _fail("DIRECT_SSO_CREDENTIAL_RETRIES_FORBIDDEN")
        if credential_vend_recorder is not None:
            credential_vend_recorder("sso:GetRoleCredentials")
        bootstrap_calls += 1
        if bootstrap_calls > 1:
            _fail("DIRECT_SSO_CREDENTIAL_BOOTSTRAP_FORBIDDEN")

    if observe_credential_bootstrap:
        try:
            emitter = session._session.get_component(  # noqa: SLF001
                "event_emitter"
            )
            emitter.register(
                event_name,
                observe_before_call,
                unique_id=observer_id,
            )
        except (AttributeError, TypeError) as exc:
            raise LiveProviderError(
                "DIRECT_SSO_CREDENTIAL_OBSERVER_REQUIRED"
            ) from exc
    try:
        credentials = session.get_credentials()
        method = credentials.method
        frozen = credentials.get_frozen_credentials()
        access_key = frozen.access_key
        secret_key = frozen.secret_key
        session_token = frozen.token
        expires_at = credentials._expiry_time  # noqa: SLF001 - no public expiry API
    except LiveProviderError:
        raise
    except Exception as exc:
        raise LiveProviderError("DIRECT_SSO_CREDENTIALS_REQUIRED") from exc
    finally:
        if emitter is not None:
            try:
                emitter.unregister(event_name, unique_id=observer_id)
            except (AttributeError, TypeError) as exc:
                raise LiveProviderError(
                    "DIRECT_SSO_CREDENTIAL_OBSERVER_REQUIRED"
                ) from exc
    if method not in {"sso", "sso-session"}:
        _fail("DIRECT_SSO_CREDENTIALS_REQUIRED")
    if (
        not isinstance(access_key, str)
        or not access_key
        or not isinstance(secret_key, str)
        or not secret_key
        or not isinstance(session_token, str)
        or not session_token
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
    ):
        _fail("DIRECT_SSO_SESSION_EXPIRY_REQUIRED")
    expires_at = expires_at.astimezone(UTC).replace(microsecond=0)
    if (
        not opened_at < expires_at
        or required_end > expires_at
        or expires_at - opened_at > timedelta(hours=1)
    ):
        _fail("DIRECT_SSO_SESSION_EXPIRY_INVALID")
    if getattr(session, "region_name", region) != region:
        _fail("REGION_BINDING_INVALID")
    session_digest = canonical_digest(
        {
            "access_key_digest": canonical_digest(access_key),
            "credential_bootstrap_calls": bootstrap_calls,
            "expires_at": _stamp(expires_at),
        }
    )
    return expires_at, session_digest, frozen


def _policy_window(
    policy: Mapping[str, Any],
    *,
    domain: str,
    policy_digest: str,
    now: datetime,
) -> tuple[datetime, datetime, frozenset[str]]:
    if canonical_digest(policy) != policy_digest or "${" in canonical_json(policy):
        _fail("POLICY_DIGEST_INVALID")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        _fail("CLOSED_POLICY_INVALID")
    allowed = set(OPERATION_ALLOWLIST[domain]) | {"kms:Decrypt"}
    granted: set[str] = set()
    caller: Mapping[str, Any] | None = None
    for statement in statements:
        if not isinstance(statement, Mapping):
            _fail("CLOSED_POLICY_INVALID")
        if statement.get("Sid") == "ConfirmOnlyTheCurrentCaller":
            caller = statement
        if statement.get("Effect") != "Allow":
            continue
        supplied = statement.get("Action")
        actions = supplied if isinstance(supplied, list) else [supplied]
        if any(not isinstance(action, str) or action not in allowed for action in actions):
            _fail("PROVIDER_OPERATION_NOT_ALLOWED")
        granted.update(actions)
    try:
        condition = caller["Condition"]  # type: ignore[index]
        start = _parse_stamp(condition["DateGreaterThanEquals"]["aws:CurrentTime"])
        end = _parse_stamp(condition["DateLessThan"]["aws:CurrentTime"])
    except (KeyError, TypeError) as exc:
        raise LiveProviderError("POLICY_WINDOW_INVALID") from exc
    observed = now.astimezone(UTC).replace(microsecond=0)
    if not start <= observed < end or not start < end or (end - start).total_seconds() > 3600:
        _fail("POLICY_WINDOW_INVALID")
    if "sts:GetCallerIdentity" not in granted:
        _fail("STS_FIRST_REQUIRED")
    return start, end, frozenset(granted - {"kms:Decrypt"})


def _frozen_client_session(
    session_factory: Callable[..., Any],
    frozen_credentials: Any,
    *,
    region: str,
) -> Any:
    """Build a profile-independent client session from reviewed SSO material."""

    try:
        session_parameters = {
            "aws_access_key_id": frozen_credentials.access_key,
            "aws_secret_access_key": frozen_credentials.secret_key,
            "aws_session_token": frozen_credentials.token,
            "region_name": region,
        }
        session = session_factory(**session_parameters)
        credentials = session.get_credentials()
        observed = credentials.get_frozen_credentials()
    except Exception as exc:
        raise LiveProviderError("FROZEN_CLIENT_SESSION_FAILED") from exc
    if (
        getattr(credentials, "method", None) != "explicit"
        or getattr(session, "region_name", None) != region
        or getattr(observed, "access_key", None) != frozen_credentials.access_key
        or getattr(observed, "secret_key", None) != frozen_credentials.secret_key
        or getattr(observed, "token", None) != frozen_credentials.token
    ):
        _fail("FROZEN_CLIENT_CREDENTIALS_REQUIRED")
    return session


class _PolicyScope:
    def __init__(self, policy: Mapping[str, Any]) -> None:
        statements = policy.get("Statement")
        if not isinstance(statements, list):
            _fail("CLOSED_POLICY_INVALID")
        self._by_sid = {
            item["Sid"]: item
            for item in statements
            if isinstance(item, Mapping) and isinstance(item.get("Sid"), str)
        }

    def resources(self, sid: str) -> list[str]:
        statement = self._by_sid.get(sid)
        if not isinstance(statement, Mapping):
            _fail("POLICY_SCOPE_INVALID")
        supplied = statement.get("Resource")
        values = supplied if isinstance(supplied, list) else [supplied]
        if not values or any(
            not isinstance(item, str) or not item or "*" in item or "${" in item
            for item in values
        ):
            _fail("POLICY_SCOPE_INVALID")
        return list(values)


class LiveProviderFactory:
    """Build collector-compatible domain session factories."""

    def __init__(self) -> None:  # pragma: no cover - builders are mandatory
        _fail("LIVE_PROVIDER_BUILDER_REQUIRED")

    @classmethod
    def _open(
        cls,
        config: ProviderConfig,
        *,
        concrete: bool,
        session_factory: Callable[..., Any] | None,
        config_factory: Callable[..., Any] | None,
        clock: Callable[[], datetime],
        environment: Mapping[str, str],
        execution_capability: object | None,
        discovery_budget: object | None = None,
    ) -> "LiveProviderFactory":
        _validate_config(config)
        _ambient_gate(environment)
        if concrete and (session_factory is not None or config_factory is not None):
            _fail("CONCRETE_SDK_INJECTION_FORBIDDEN")
        if concrete and execution_capability is None:
            _fail("LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED")
        if not concrete and execution_capability is not None:
            _fail("INJECTED_CAPABILITY_FORBIDDEN")
        if not concrete and discovery_budget is not None:
            _fail("DISCOVERY_PROVIDER_INJECTION_FORBIDDEN")
        if not concrete and (not callable(session_factory) or not callable(config_factory)):
            _fail("INJECTED_SDK_REQUIRED")
        if not callable(clock):
            _fail("PROVIDER_CLOCK_INVALID")
        loaded_sdk: _LoadedSdk | None = None
        if concrete:
            if config.sdk_runtime_root is None:
                _fail("AWS_SDK_RUNTIME_ROOT_REQUIRED")
            loaded_sdk = _load_sdk(config.sdk_runtime_root)
        self = object.__new__(cls)
        self._config = config
        self._concrete = concrete
        self._session_factory = (
            loaded_sdk.session_factory if loaded_sdk is not None else session_factory
        )
        self._config_factory = (
            loaded_sdk.config_factory if loaded_sdk is not None else config_factory
        )
        self._sdk_guard = loaded_sdk.guard if loaded_sdk is not None else None
        self._clock = clock
        self._environment = environment
        self._execution_capability = execution_capability
        self._discovery_budget = discovery_budget
        self._events: list[dict[str, Any]] = []
        self._session_ordinal = 0
        self._ledger: CallLedger | None = None
        self._provider_attestation = None
        if concrete:
            self._provider_attestation = (
                _DISCOVERY_PROVIDER_ATTESTATION
                if discovery_budget is not None
                else _CONCRETE_PROVIDER_ATTESTATION
            )
        self.concrete_provider = concrete
        self.discovery_provider = discovery_budget is not None
        self.mode = (
            "ATTESTED_DISCOVERY"
            if discovery_budget is not None
            else ("ATTESTED_LIVE" if concrete else "INJECTED_NON_LIVE")
        )
        return self

    def _reserve_discovery_provider_call(
        self, operation: str, *, is_page: bool
    ) -> None:
        if self._discovery_budget is None:
            return
        reserve = getattr(self._discovery_budget, "reserve_provider_call", None)
        if not callable(reserve):
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")
        try:
            reserve(operation, is_page=is_page)
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_BUDGET_BLOCKED"
            ) from exc

    def _record_discovery_credential_vend(self, operation: str) -> None:
        if self._discovery_budget is None:
            return
        record = getattr(self._discovery_budget, "record_credential_vend", None)
        if not callable(record):
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")
        try:
            record(operation)
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_BUDGET_BLOCKED"
            ) from exc

    def _record_discovery_response(self, response: Mapping[str, Any]) -> None:
        if self._discovery_budget is None:
            return
        record = getattr(self._discovery_budget, "record_response", None)
        if not callable(record):
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")
        byte_count = len(canonical_json(response).encode("utf-8"))
        try:
            record(byte_count)
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_BUDGET_BLOCKED"
            ) from exc

    def _authorize_discovery_session(
        self,
        *,
        domain: str,
        capture_index: int,
        stage: str,
        policy_digest: str,
    ) -> None:
        if self._discovery_budget is None:
            return
        authorize = getattr(
            self._config.validity_gate, "authorize_session", None
        )
        if not callable(authorize):
            _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
        try:
            authorize(
                domain=domain,
                capture_index=capture_index,
                stage=stage,
                policy_digest=policy_digest,
            )
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_PROVIDER_SESSION_NOT_AUTHORIZED"
            ) from exc

    def _sdk(self) -> tuple[Callable[..., Any], Callable[..., Any]]:
        if self._concrete:
            _ambient_gate(self._environment)
            if not callable(self._sdk_guard):
                _fail("AWS_SDK_PROVENANCE_INVALID")
            self._sdk_guard()
            assert callable(self._session_factory)
            assert callable(self._config_factory)
            return self._session_factory, self._config_factory
        assert self._session_factory is not None and self._config_factory is not None
        return self._session_factory, self._config_factory

    def _binding(self, domain: str) -> tuple[str, str, str, str, str]:
        if domain == "authority":
            return (
                self._config.authority_profile,
                self._config.authority_expected_account_id,
                self._config.authority_expected_principal_digest,
                self._config.authority_expected_sso_role_name_digest,
                self._config.authority_verification_digest,
            )
        if domain == "identity_center":
            return (
                self._config.identity_center_profile,
                self._config.identity_expected_account_id,
                self._config.identity_expected_principal_digest,
                self._config.identity_expected_sso_role_name_digest,
                self._config.identity_authority_verification_digest,
            )
        _fail("PROVIDER_DOMAIN_INVALID")

    def build_authority(
        self,
        *,
        profile: str,
        ledger: CallLedger,
        capture_index: int,
        retries: int,
    ) -> "_DomainFactory":
        return self._build("authority", profile, ledger, capture_index, retries)

    def build_identity(
        self,
        *,
        profile: str,
        ledger: CallLedger,
        capture_index: int,
        retries: int,
    ) -> "_DomainFactory":
        return self._build("identity_center", profile, ledger, capture_index, retries)

    def _build(
        self,
        domain: str,
        profile: str,
        ledger: CallLedger,
        capture_index: int,
        retries: int,
    ) -> "_DomainFactory":
        expected_profile, account, principal_digest, sso_role_digest, verification = self._binding(domain)
        if profile != expected_profile:
            _fail("PROFILE_BINDING_INVALID")
        if type(capture_index) is not int or capture_index not in {1, 2}:
            _fail("CAPTURE_INDEX_INVALID")
        if type(retries) is not int or retries != 0:
            _fail("PROVIDER_RETRIES_FORBIDDEN")
        if not callable(getattr(ledger, "authorize", None)) or not callable(
            getattr(ledger, "complete", None)
        ):
            _fail("CALL_LEDGER_REQUIRED")
        if self._ledger is None:
            self._ledger = ledger
        elif self._ledger is not ledger:
            _fail("CALL_LEDGER_BINDING_INVALID")
        return _DomainFactory(
            owner=self,
            domain=domain,
            profile=profile,
            account_id=account,
            principal_digest=principal_digest,
            sso_role_name_digest=sso_role_digest,
            authority_verification_digest=verification,
            ledger=ledger,
            capture_index=capture_index,
        )

    def _next_session_digest(
        self,
        *,
        domain: str,
        profile: str,
        capture_index: int,
        stage: str,
        policy_digest: str,
        credential_binding_digest: str,
        opened_at: datetime,
    ) -> str:
        self._session_ordinal += 1
        return canonical_digest(
            {
                "domain": domain,
                "profile_binding_digest": canonical_digest(profile),
                "capture_index": capture_index,
                "stage": stage,
                "policy_digest": policy_digest,
                "credential_binding_digest": credential_binding_digest,
                "opened_at": opened_at.astimezone(UTC).isoformat(),
                "session_ordinal": self._session_ordinal,
            }
        )

    def _record(
        self,
        *,
        domain: str,
        session_digest: str,
        operation: str,
        request_digest: str,
        response_digest: str,
        outcome: str,
    ) -> None:
        self._events.append(
            {
                "ordinal": len(self._events) + 1,
                "domain": domain,
                "session_digest": session_digest,
                "operation": operation,
                "request_digest": request_digest,
                "response_digest": response_digest,
                "outcome": outcome,
            }
        )

    def transcript_summary(self) -> dict[str, Any]:
        if self._ledger is None or not callable(getattr(self._ledger, "finalize", None)):
            _fail("CALL_LEDGER_FINALIZE_REQUIRED")
        calls, transcript_digest = self._ledger.finalize()  # type: ignore[attr-defined]
        if type(calls) is not int or calls != len(self._events) or _DIGEST.fullmatch(str(transcript_digest)) is None:
            _fail("PROVIDER_TRANSCRIPT_MISMATCH")
        return {
            # Both counters cover only the closed, ledgered inventory API
            # surface. Direct-SSO credential vending happens beforehand and
            # is committed through each session digest instead.
            "provider_calls": calls,
            "aws_calls": calls if self._concrete else 0,
            "aws_mutations": 0,
            "live_provider_evidence": self._concrete and calls > 0,
            "transcript_digest": transcript_digest,
        }

    def transcript_events(self) -> list[dict[str, Any]]:
        """Return the finalized digest-only provider journal."""

        if self._ledger is None:
            _fail("CALL_LEDGER_FINALIZE_REQUIRED")
        evidence = getattr(self._ledger, "evidence_events", None)
        if not callable(evidence):
            _fail("PROVIDER_TRANSCRIPT_MISMATCH")
        try:
            events = evidence()
        except LiveProviderError:
            raise
        except Exception as exc:
            raise LiveProviderError("PROVIDER_TRANSCRIPT_MISMATCH") from exc
        if not isinstance(events, list) or not events:
            _fail("PROVIDER_TRANSCRIPT_MISMATCH")
        return events

    def discovery_budget_summary(self) -> dict[str, Any]:
        """Return the shared discovery budget's digest-only counters."""

        if (
            self._provider_attestation is not _DISCOVERY_PROVIDER_ATTESTATION
            or self._discovery_budget is None
        ):
            _fail("DISCOVERY_PROVIDER_REQUIRED")
        summary = getattr(self._discovery_budget, "summary", None)
        if not callable(summary):
            _fail("DISCOVERY_BUDGET_BINDING_INVALID")
        try:
            value = summary()
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_BUDGET_SUMMARY_INVALID"
            ) from exc
        if not isinstance(value, Mapping):
            _fail("DISCOVERY_BUDGET_SUMMARY_INVALID")
        return dict(value)

    def discovery_budget_evidence_events(self) -> list[dict[str, Any]]:
        """Return the replayable sanitized journal behind the budget summary."""

        if (
            self._provider_attestation is not _DISCOVERY_PROVIDER_ATTESTATION
            or self._discovery_budget is None
        ):
            _fail("DISCOVERY_PROVIDER_REQUIRED")
        evidence = getattr(self._discovery_budget, "evidence_events", None)
        if not callable(evidence):
            _fail("DISCOVERY_BUDGET_EVIDENCE_INVALID")
        try:
            events = evidence()
        except LiveProviderError:
            raise
        except Exception as exc:
            raise _safe_discovery_error(
                exc, "DISCOVERY_BUDGET_EVIDENCE_INVALID"
            ) from exc
        if not isinstance(events, list) or not events:
            _fail("DISCOVERY_BUDGET_EVIDENCE_INVALID")
        return events

    def evaluation_time(self) -> datetime:
        """Return the post-call trusted time after revalidating local custody."""

        self._config.validity_gate()
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _fail("PROVIDER_CLOCK_INVALID")
        return value.astimezone(UTC).replace(microsecond=0)


class _DomainFactory:
    def __init__(
        self,
        *,
        owner: LiveProviderFactory,
        domain: str,
        profile: str,
        account_id: str,
        principal_digest: str,
        sso_role_name_digest: str,
        authority_verification_digest: str,
        ledger: CallLedger,
        capture_index: int,
    ) -> None:
        self._owner = owner
        self._domain = domain
        self._profile = profile
        self._account_id = account_id
        self._principal_digest = principal_digest
        self._sso_role_name_digest = sso_role_name_digest
        self._authority_verification_digest = authority_verification_digest
        self._ledger = ledger
        self._capture_index = capture_index

    def open_sts(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        region: str,
        stage: str | None = None,
    ) -> "_StsSession":
        expected_stage = "authority" if self._domain == "authority" else stage
        if self._domain == "authority" and stage is not None:
            _fail("PROVIDER_STAGE_INVALID")
        if self._domain == "identity_center" and stage not in {"discovery", "exact"}:
            _fail("PROVIDER_STAGE_INVALID")
        if region != self._owner._config.region:
            _fail("REGION_BINDING_INVALID")
        assert expected_stage is not None
        self._owner._authorize_discovery_session(
            domain=self._domain,
            capture_index=self._capture_index,
            stage=expected_stage,
            policy_digest=policy_digest,
        )
        now = self._owner._clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            _fail("PROVIDER_CLOCK_INVALID")
        start, end, policy_actions = _policy_window(
            policy,
            domain=self._domain,
            policy_digest=policy_digest,
            now=now,
        )
        self._owner._config.validity_gate()
        session_factory, config_factory = self._owner._sdk()
        try:
            sdk_config = config_factory(
                region_name=region,
                retries={"mode": "standard", "total_max_attempts": 1},
                connect_timeout=15,
                read_timeout=60,
                parameter_validation=True,
                tcp_keepalive=True,
                ignore_configured_endpoint_urls=True,
                user_agent_extra=(
                    "scanalyze-gug393-discovery-provider/1"
                    if self._owner._discovery_budget is not None
                    else "scanalyze-gug392-live-provider/1"
                ),
            )
            sdk_session = session_factory(profile_name=self._profile, region_name=region)
        except Exception as exc:
            raise LiveProviderError("AWS_SESSION_OPEN_FAILED") from exc
        credential_expires_at, credential_binding_digest, frozen_credentials = (
            _validate_direct_sso_profile(
            sdk_session,
            profile_name=self._profile,
            account_id=self._account_id,
            sso_role_name_digest=self._sso_role_name_digest,
            region=region,
            opened_at=now,
            required_end=end,
            observe_credential_bootstrap=self._owner._concrete,
            credential_vend_recorder=(
                self._owner._record_discovery_credential_vend
                if self._owner._discovery_budget is not None
                else None
            ),
        )
        )
        session_digest = self._owner._next_session_digest(
            domain=self._domain,
            profile=self._profile,
            capture_index=self._capture_index,
            stage=expected_stage,
            policy_digest=policy_digest,
            credential_binding_digest=credential_binding_digest,
            opened_at=now,
        )
        client_session = sdk_session
        if self._owner._concrete:
            # Detach inventory clients from botocore's refreshable SSO
            # provider. These temporary values stay in memory only; the
            # provider independently enforces their original expiry.
            client_session = _frozen_client_session(
                session_factory,
                frozen_credentials,
                region=region,
            )
        try:
            sts = client_session.client("sts", config=sdk_config, verify=True)
        except Exception as exc:
            raise LiveProviderError("STS_CLIENT_OPEN_FAILED") from exc
        return _StsSession(
            owner=self._owner,
            domain=self._domain,
            sdk_session=client_session,
            sdk_config=sdk_config,
            sts_client=sts,
            ledger=self._ledger,
            session_digest=session_digest,
            account_id=self._account_id,
            principal_digest=self._principal_digest,
            authority_verification_digest=self._authority_verification_digest,
            policy=policy,
            policy_digest=policy_digest,
            start=start,
            end=end,
            opened_at=now,
            credential_expires_at=credential_expires_at,
            policy_actions=policy_actions,
            region=region,
            capture_index=self._capture_index,
            stage=expected_stage,
        )


class _StsSession:
    def __init__(
        self,
        *,
        owner: LiveProviderFactory,
        domain: str,
        sdk_session: Any,
        sdk_config: Any,
        sts_client: Any,
        ledger: CallLedger,
        session_digest: str,
        account_id: str,
        principal_digest: str,
        authority_verification_digest: str,
        policy: Mapping[str, Any],
        policy_digest: str,
        start: datetime,
        end: datetime,
        opened_at: datetime,
        credential_expires_at: datetime,
        policy_actions: frozenset[str],
        region: str,
        capture_index: int = 1,
        stage: str | None = None,
    ) -> None:
        self._owner = owner
        self._domain = domain
        self._sdk_session = sdk_session
        self._sdk_config = sdk_config
        self._clients = {"sts": sts_client}
        self._ledger = ledger
        self._session_digest = session_digest
        self._account_id = account_id
        self._principal_digest = principal_digest
        self._authority_verification_digest = authority_verification_digest
        self._policy = policy
        self._policy_digest = policy_digest
        self._start = start
        self._end = end
        self._opened_at = opened_at
        self._credential_expires_at = credential_expires_at
        self._policy_actions = policy_actions
        self._region = region
        self._capture_index = capture_index
        self._stage = stage
        self._identity_validated = False

    def _client(self, service: str) -> Any:
        if service != "sts" and not self._identity_validated:
            _fail("STS_FIRST_REQUIRED")
        if service not in self._clients:
            try:
                self._clients[service] = self._sdk_session.client(
                    service, config=self._sdk_config, verify=True
                )
            except Exception as exc:
                raise LiveProviderError("AWS_CLIENT_OPEN_FAILED") from exc
        return self._clients[service]

    def _assert_active_window(self) -> datetime:
        if self._owner._concrete:
            self._owner._sdk()
        self._owner._config.validity_gate()
        current = self._owner._clock()
        if not isinstance(current, datetime) or current.tzinfo is None:
            _fail("PROVIDER_CLOCK_INVALID")
        current = current.astimezone(UTC).replace(microsecond=0)
        if not self._start <= current < self._end <= self._credential_expires_at:
            error = LiveProviderError("DIRECT_SSO_SESSION_WINDOW_INACTIVE")
            error._observed_at = current  # type: ignore[attr-defined]
            raise error
        return current

    def _fail_pending_post_response(
        self,
        *,
        ticket: str,
        operation: str,
        request_digest: str,
        completed_at: datetime,
    ) -> None:
        blocked_digest = canonical_digest({"blocked": "post_response_gate"})
        self._ledger.complete(
            ticket,
            blocked_digest,
            outcome="ERROR",
            completed_at=_stamp(completed_at),
        )
        self._owner._record(
            domain=self._domain,
            session_digest=self._session_digest,
            operation=operation,
            request_digest=request_digest,
            response_digest=blocked_digest,
            outcome="ERROR",
        )

    def _invoke(
        self,
        *,
        operation: str,
        service: str,
        method: str,
        request: Mapping[str, Any],
        page_token: Any = None,
        pagination_key: str | None = None,
        response_token_key: str | None = None,
        secondary_response_token_key: str | None = None,
        truncated_key: str | None = None,
        absent_ok: bool = False,
    ) -> Mapping[str, Any]:
        if (
            operation not in OPERATION_ALLOWLIST[self._domain]
            or operation not in self._policy_actions
            or operation == "kms:Decrypt"
        ):
            _fail("PROVIDER_OPERATION_NOT_ALLOWED")
        started_at = self._assert_active_window()
        request_digest = canonical_digest(request)
        ledger_token = canonical_digest(page_token) if page_token is not None else None
        self._owner._reserve_discovery_provider_call(
            operation, is_page=pagination_key is not None
        )
        ticket = self._ledger.authorize(
            domain=self._domain,
            session_digest=self._session_digest,
            operation=operation,
            retries=0,
            request=request_digest,
            page_token=ledger_token,
            pagination_key=pagination_key,
            started_at=_stamp(started_at),
        )
        try:
            response = getattr(self._client(service), method)(**dict(request))
        except Exception as exc:
            code = _error_code(exc)
            try:
                completed_at = self._assert_active_window()
            except Exception as gate_error:
                self._fail_pending_post_response(
                    ticket=ticket,
                    operation=operation,
                    request_digest=request_digest,
                    completed_at=getattr(gate_error, "_observed_at", started_at),
                )
                raise
            if absent_ok and code in _ABSENT:
                detached = {"Absent": code}
                try:
                    self._owner._record_discovery_response(detached)
                except LiveProviderError:
                    self._fail_pending_post_response(
                        ticket=ticket,
                        operation=operation,
                        request_digest=request_digest,
                        completed_at=completed_at,
                    )
                    raise
                response_digest = canonical_digest(detached)
                self._ledger.complete(
                    ticket,
                    response_digest,
                    completed_at=_stamp(completed_at),
                )
                self._owner._record(
                    domain=self._domain,
                    session_digest=self._session_digest,
                    operation=operation,
                    request_digest=request_digest,
                    response_digest=response_digest,
                    outcome="SUCCESS",
                )
                return detached
            detached_error = {"error_code": code}
            try:
                self._owner._record_discovery_response(detached_error)
            except LiveProviderError:
                self._fail_pending_post_response(
                    ticket=ticket,
                    operation=operation,
                    request_digest=request_digest,
                    completed_at=completed_at,
                )
                raise
            response_digest = canonical_digest(detached_error)
            self._ledger.complete(
                ticket,
                response_digest,
                outcome="ERROR",
                completed_at=_stamp(completed_at),
            )
            self._owner._record(
                domain=self._domain,
                session_digest=self._session_digest,
                operation=operation,
                request_digest=request_digest,
                response_digest=response_digest,
                outcome="ERROR",
            )
            if code in _ACCESS_DENIED:
                raise AuthorityAccessDenied(code) from exc
            raise LiveProviderError("PROVIDER_READ_FAILED") from exc
        try:
            completed_at = self._assert_active_window()
        except Exception as gate_error:
            self._fail_pending_post_response(
                ticket=ticket,
                operation=operation,
                request_digest=request_digest,
                completed_at=getattr(gate_error, "_observed_at", started_at),
            )
            raise
        try:
            if not isinstance(response, Mapping):
                _fail("PROVIDER_RESPONSE_INVALID")
            projector = _RESPONSE_PROJECTORS.get(operation)
            if projector is None:
                _fail("PROVIDER_RESPONSE_PROJECTOR_MISSING")
            response = projector(response, request)
            if not isinstance(response, Mapping):
                _fail("PROVIDER_RESPONSE_INVALID")
            detached = _bounded(response)
            assert isinstance(detached, Mapping)
            self._owner._record_discovery_response(detached)
            next_token = _next_page_token(
                detached, response_token_key, secondary_response_token_key
            )
            truncated = next_token is not None
            if truncated_key is not None and detached.get(truncated_key) is not truncated:
                _fail("PROVIDER_PAGE_INCOMPLETE")
            next_digest = canonical_digest(next_token) if next_token is not None else None
            response_digest = canonical_digest(detached)
        except Exception as exc:
            blocked_digest = canonical_digest({"blocked": True})
            self._ledger.complete(
                ticket,
                blocked_digest,
                outcome="ERROR",
                completed_at=_stamp(completed_at),
            )
            self._owner._record(
                domain=self._domain,
                session_digest=self._session_digest,
                operation=operation,
                request_digest=request_digest,
                response_digest=blocked_digest,
                outcome="ERROR",
            )
            if isinstance(exc, LiveProviderError):
                raise
            raise LiveProviderError("PROVIDER_RESPONSE_INVALID") from exc
        self._ledger.complete(
            ticket,
            response_digest,
            complete=not truncated,
            truncated=truncated,
            next_token=next_digest,
            completed_at=_stamp(completed_at),
        )
        self._owner._record(
            domain=self._domain,
            session_digest=self._session_digest,
            operation=operation,
            request_digest=request_digest,
            response_digest=response_digest,
            outcome="SUCCESS",
        )
        return detached

    def _paginate(
        self,
        *,
        operation: str,
        service: str,
        method: str,
        request: Mapping[str, Any],
        item_key: str,
        request_token_key: str,
        response_token_key: str,
        secondary_request_token_key: str | None = None,
        secondary_response_token_key: str | None = None,
        truncated_key: str | None = None,
    ) -> list[Any]:
        pagination_key = canonical_digest(
            {
                "session": self._session_digest,
                "operation": operation,
                "request": request,
            }
        )
        token: str | dict[str, str] | None = None
        seen: set[str] = set()
        items: list[Any] = []
        aggregate_bytes = 0
        for _ in range(self._owner._config.max_pages):
            current = dict(request)
            if isinstance(token, str):
                current[request_token_key] = token
            elif isinstance(token, Mapping):
                current[request_token_key] = token["primary"]
                if "secondary" in token:
                    if secondary_request_token_key is None:
                        _fail("PROVIDER_PAGE_INVALID")
                    current[secondary_request_token_key] = token["secondary"]
            page = self._invoke(
                operation=operation,
                service=service,
                method=method,
                request=current,
                page_token=token,
                pagination_key=pagination_key,
                response_token_key=response_token_key,
                secondary_response_token_key=secondary_response_token_key,
                truncated_key=truncated_key,
            )
            supplied = page.get(item_key)
            if not isinstance(supplied, list):
                _fail("PROVIDER_PAGE_INVALID")
            aggregate_bytes += len(canonical_json(supplied).encode("utf-8"))
            if aggregate_bytes > MAX_RESPONSE_BYTES:
                _fail("PROVIDER_RESPONSE_TOO_LARGE")
            items.extend(supplied)
            next_token = _next_page_token(
                page, response_token_key, secondary_response_token_key
            )
            if next_token is None:
                return sorted(items, key=canonical_json)
            token_key = canonical_json(next_token)
            if token_key in seen:
                _fail("PROVIDER_PAGE_TOKEN_REPEATED")
            seen.add(token_key)
            token = next_token
        _fail("PROVIDER_PAGE_LIMIT_EXCEEDED")

    def _paginate_object_versions(self, request: Mapping[str, Any]) -> list[dict[str, Any]]:
        pagination_key = canonical_digest(
            {
                "session": self._session_digest,
                "operation": "s3:ListBucketVersions",
                "request": request,
            }
        )
        token: dict[str, str] | None = None
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        aggregate_bytes = 0
        for _ in range(self._owner._config.max_pages):
            current = dict(request)
            if token is not None:
                current["KeyMarker"] = token["primary"]
                if "secondary" in token:
                    current["VersionIdMarker"] = token["secondary"]
            page = self._invoke(
                operation="s3:ListBucketVersions",
                service="s3",
                method="list_object_versions",
                request=current,
                page_token=token,
                pagination_key=pagination_key,
                response_token_key="NextKeyMarker",
                secondary_response_token_key="NextVersionIdMarker",
                truncated_key="IsTruncated",
                absent_ok=True,
            )
            if set(page) == {"Absent"}:
                return []
            for response_key, record_type in (
                ("Versions", "OBJECT_VERSION"),
                ("DeleteMarkers", "DELETE_MARKER"),
            ):
                supplied = page.get(response_key, [])
                if not isinstance(supplied, list) or not all(
                    isinstance(item, Mapping) for item in supplied
                ):
                    _fail("PROVIDER_PAGE_INVALID")
                aggregate_bytes += len(canonical_json(supplied).encode("utf-8"))
                if aggregate_bytes > MAX_RESPONSE_BYTES:
                    _fail("PROVIDER_RESPONSE_TOO_LARGE")
                records.extend(
                    {**dict(item), "record_type": record_type} for item in supplied
                )
            next_token = _next_page_token(
                page, "NextKeyMarker", "NextVersionIdMarker"
            )
            if next_token is None:
                return sorted(records, key=canonical_json)
            if not isinstance(next_token, dict):
                _fail("PROVIDER_PAGE_INVALID")
            token_key = canonical_json(next_token)
            if token_key in seen:
                _fail("PROVIDER_PAGE_TOKEN_REPEATED")
            seen.add(token_key)
            token = next_token
        _fail("PROVIDER_PAGE_LIMIT_EXCEEDED")

    def get_caller_identity(self) -> Mapping[str, Any]:
        response = self._invoke(
            operation="sts:GetCallerIdentity",
            service="sts",
            method="get_caller_identity",
            request={},
        )
        observed = self._owner._clock()
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            _fail("PROVIDER_CLOCK_INVALID")
        observed = observed.astimezone(UTC).replace(microsecond=0)
        if (
            response.get("Account") != self._account_id
            or canonical_digest(response.get("Arn")) != self._principal_digest
            or _PRINCIPAL.fullmatch(str(response.get("Arn"))) is None
            or response.get("UserIdPresent") is not True
            or not self._start <= observed < self._end
            or not observed < self._credential_expires_at
            or self._end > self._credential_expires_at
        ):
            _fail("CALLER_IDENTITY_MISMATCH")
        self._identity_validated = True
        return {
            "source": "DIRECT_SSO",
            "chain_depth": 0,
            "account_id": self._account_id,
            "region": self._region,
            "principal_arn": response["Arn"],
            "session_id_digest": self._session_digest,
            "started_at": self._opened_at,
            "expires_at": self._credential_expires_at,
            "observed_at": observed,
            "policy_digest": self._policy_digest,
            "authority_verification_digest": self._authority_verification_digest,
        }

    def open_reader(self) -> "_AuthorityReader":
        if self._domain != "authority":
            _fail("PROVIDER_DOMAIN_INVALID")
        if not self._identity_validated:
            _fail("STS_FIRST_REQUIRED")
        return _AuthorityReader(self, _PolicyScope(self._policy))

    def open_discovery(self) -> "_IdentityDiscoveryReader":
        if self._domain != "identity_center" or self._stage != "discovery":
            _fail("PROVIDER_DOMAIN_INVALID")
        if not self._identity_validated:
            _fail("STS_FIRST_REQUIRED")
        return _IdentityDiscoveryReader(self)

    def open_exact(self) -> "_IdentityExactReader":
        if self._domain != "identity_center" or self._stage != "exact":
            _fail("PROVIDER_DOMAIN_INVALID")
        if not self._identity_validated:
            _fail("STS_FIRST_REQUIRED")
        return _IdentityExactReader(self)


def _single_page(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"items": list(items), "next_cursor": None, "truncated": False}


def _identity_page(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {"items": list(items), "next_token": None, "truncated": False, "complete": True}


def _require_first_cursor(cursor: object | None) -> None:
    if cursor is not None:
        _fail("COLLECTOR_CURSOR_UNEXPECTED")


def _arn_suffix(arn: str, marker: str) -> str:
    if marker not in arn:
        _fail("POLICY_SCOPE_INVALID")
    value = arn.split(marker, 1)[1]
    if not value:
        _fail("POLICY_SCOPE_INVALID")
    return value


class _AuthorityReader:
    def __init__(self, session: _StsSession, scope: _PolicyScope) -> None:
        self._session = session
        self._scope = scope

    def s3(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        bucket_arn = self._scope.resources("ReadExactArtifactBucketAndVersions")[0]
        bucket = _arn_suffix(bucket_arn, "arn:aws:s3:::")
        discovered = self._session._paginate(
            operation="s3:ListAllMyBuckets",
            service="s3",
            method="list_buckets",
            request={},
            item_key="Buckets",
            request_token_key="ContinuationToken",
            response_token_key="ContinuationToken",
        )
        present = any(
            item.get("Name") == bucket
            for item in discovered
            if isinstance(item, Mapping)
        )
        if not present:
            return _single_page([])
        account_public = self._session._invoke(
            operation="s3:GetAccountPublicAccessBlock",
            service="s3control",
            method="get_public_access_block",
            request={"AccountId": self._session._account_id},
            absent_ok=True,
        )
        calls = (
            ("s3:GetBucketAcl", "get_bucket_acl"),
            ("s3:GetBucketEncryption", "get_bucket_encryption"),
            ("s3:GetBucketLifecycleConfiguration", "get_bucket_lifecycle_configuration"),
            ("s3:GetBucketLocation", "get_bucket_location"),
            ("s3:GetBucketOwnershipControls", "get_bucket_ownership_controls"),
            ("s3:GetBucketPolicy", "get_bucket_policy"),
            ("s3:GetBucketPolicyStatus", "get_bucket_policy_status"),
            ("s3:GetBucketPublicAccessBlock", "get_public_access_block"),
            ("s3:GetBucketTagging", "get_bucket_tagging"),
            ("s3:GetBucketVersioning", "get_bucket_versioning"),
        )
        settings = {
            operation: self._session._invoke(
                operation=operation,
                service="s3",
                method=method,
                request={"Bucket": bucket},
                absent_ok=True,
            )
            for operation, method in calls
        }
        versions = self._session._paginate_object_versions({"Bucket": bucket})
        return _single_page(
            [
                {
                    "bucket_arn": bucket_arn,
                    "present": True,
                    "account_public_access": account_public,
                    "settings": settings,
                    "versions": versions,
                }
            ]
        )

    def kms(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        key_arn = self._scope.resources("ReadExactKmsKey")[0]
        keys = self._session._paginate(
            operation="kms:ListKeys",
            service="kms",
            method="list_keys",
            request={},
            item_key="Keys",
            request_token_key="Marker",
            response_token_key="NextMarker",
            truncated_key="Truncated",
        )
        exact_keys = [
            item
            for item in keys
            if isinstance(item, Mapping) and item.get("KeyArn") == key_arn
        ]
        if not exact_keys:
            return _single_page([])
        aliases = self._session._paginate(
            operation="kms:ListAliases",
            service="kms",
            method="list_aliases",
            request={"KeyId": key_arn},
            item_key="Aliases",
            request_token_key="Marker",
            response_token_key="NextMarker",
            truncated_key="Truncated",
        )
        facts = {
            "key_arn": key_arn,
            "discovered_keys": exact_keys,
            "aliases": aliases,
            "description": self._session._invoke(
                operation="kms:DescribeKey", service="kms", method="describe_key", request={"KeyId": key_arn}, absent_ok=True
            ),
            "policy": self._session._invoke(
                operation="kms:GetKeyPolicy", service="kms", method="get_key_policy", request={"KeyId": key_arn, "PolicyName": "default"}, absent_ok=True
            ),
            "rotation": self._session._invoke(
                operation="kms:GetKeyRotationStatus", service="kms", method="get_key_rotation_status", request={"KeyId": key_arn}, absent_ok=True
            ),
            "grants": self._session._paginate(
                operation="kms:ListGrants", service="kms", method="list_grants", request={"KeyId": key_arn}, item_key="Grants", request_token_key="Marker", response_token_key="NextMarker", truncated_key="Truncated"
            ),
            "tags": self._session._paginate(
                operation="kms:ListResourceTags", service="kms", method="list_resource_tags", request={"KeyId": key_arn}, item_key="Tags", request_token_key="Marker", response_token_key="NextMarker", truncated_key="Truncated"
            ),
        }
        return _single_page([facts])

    def signer(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        profile_arn = self._scope.resources("ReadExactSigningProfile")[0]
        profile_name = _arn_suffix(profile_arn, "/signing-profiles/")
        profiles = self._session._paginate(
            operation="signer:ListSigningProfiles", service="signer", method="list_signing_profiles", request={}, item_key="profiles", request_token_key="nextToken", response_token_key="nextToken"
        )
        exact_profiles = [
            item
            for item in profiles
            if isinstance(item, Mapping)
            and (
                item.get("profileName") == profile_name
                or item.get("arn") == profile_arn
                or item.get("profileVersionArn") == profile_arn
            )
        ]
        if not exact_profiles:
            return _single_page([])
        jobs = self._session._paginate(
            operation="signer:ListSigningJobs", service="signer", method="list_signing_jobs", request={}, item_key="jobs", request_token_key="nextToken", response_token_key="nextToken"
        )
        job_facts = []
        for job in jobs:
            if isinstance(job, Mapping) and job.get("profileName") == profile_name and isinstance(job.get("jobId"), str):
                job_facts.append(self._session._invoke(
                    operation="signer:DescribeSigningJob", service="signer", method="describe_signing_job", request={"jobId": job["jobId"]}, absent_ok=True
                ))
        return _single_page([{
            "profile_arn": profile_arn,
            "profiles": exact_profiles,
            "profile": self._session._invoke(operation="signer:GetSigningProfile", service="signer", method="get_signing_profile", request={"profileName": profile_name}, absent_ok=True),
            "permissions": self._session._paginate(operation="signer:ListProfilePermissions", service="signer", method="list_profile_permissions", request={"profileName": profile_name}, item_key="permissions", request_token_key="nextToken", response_token_key="nextToken"),
            "tags": self._session._invoke(operation="signer:ListTagsForResource", service="signer", method="list_tags_for_resource", request={"resourceArn": profile_arn}, absent_ok=True),
            "jobs": job_facts,
        }])

    def lambda_code_signing(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        arn = self._scope.resources("ReadExactLambdaCodeSigningConfig")[0]
        discovery = self._session._paginate(operation="lambda:ListCodeSigningConfigs", service="lambda", method="list_code_signing_configs", request={}, item_key="CodeSigningConfigs", request_token_key="Marker", response_token_key="NextMarker")
        exact_discovery = [
            item
            for item in discovery
            if isinstance(item, Mapping) and item.get("CodeSigningConfigArn") == arn
        ]
        if not exact_discovery:
            return _single_page([])
        return _single_page([{
            "code_signing_config_arn": arn,
            "discovery": exact_discovery,
            "configuration": self._session._invoke(operation="lambda:GetCodeSigningConfig", service="lambda", method="get_code_signing_config", request={"CodeSigningConfigArn": arn}, absent_ok=True),
            "functions": self._session._paginate(operation="lambda:ListFunctionsByCodeSigningConfig", service="lambda", method="list_functions_by_code_signing_config", request={"CodeSigningConfigArn": arn}, item_key="FunctionArns", request_token_key="Marker", response_token_key="NextMarker"),
            "tags": self._session._invoke(operation="lambda:ListTags", service="lambda", method="list_tags", request={"Resource": arn}, absent_ok=True),
        }])

    def lambda_runtime(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        resources = self._scope.resources("ReadExactLambdaRuntimeEvidence")
        version_arn = next((item for item in resources if re.search(r":[1-9][0-9]*$", item)), None)
        base_arn = next((item for item in resources if item != version_arn), None)
        if version_arn is None or base_arn is None:
            _fail("POLICY_SCOPE_INVALID")
        version = version_arn.rsplit(":", 1)[-1]
        configuration = self._session._invoke(
            operation="lambda:GetFunctionConfiguration", service="lambda", method="get_function_configuration", request={"FunctionName": base_arn, "Qualifier": version}, absent_ok=True
        )
        management = self._session._invoke(
            operation="lambda:GetRuntimeManagementConfig", service="lambda", method="get_runtime_management_config", request={"FunctionName": base_arn, "Qualifier": version}, absent_ok=True
        )
        tags = self._session._invoke(
            operation="lambda:ListTags", service="lambda", method="list_tags", request={"Resource": version_arn}, absent_ok=True
        )
        versions = self._session._paginate(
            operation="lambda:ListVersionsByFunction", service="lambda", method="list_versions_by_function", request={"FunctionName": base_arn}, item_key="Versions", request_token_key="Marker", response_token_key="NextMarker"
        )
        return _single_page([{
            "function_arn": version_arn,
            "version": version,
            "runtime": configuration.get("Runtime"),
            "architectures": configuration.get("Architectures"),
            "update_runtime_on": management.get("UpdateRuntimeOn"),
            "runtime_version_arn": management.get("RuntimeVersionArn"),
            "configuration": configuration,
            "tags": tags.get("Tags", {}),
            "versions": versions,
        }])

    def iam_roles(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        role_arns = self._scope.resources("ReadExactGeneratedIdentityCenterRoles")
        role_matches = [
            re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/.+", arn)
            for arn in role_arns
        ]
        if (
            len(role_arns) != 2
            or any(match is None for match in role_matches)
            or len(
                {
                    match.group(1)
                    for match in role_matches
                    if match is not None
                }
            )
            != 1
        ):
            _fail("POLICY_SCOPE_INVALID")
        account_id = next(
            match.group(1) for match in role_matches if match is not None
        )
        collision_pattern = re.compile(
            rf"arn:aws:iam::{account_id}:role/aws-reserved/"
            r"sso\.amazonaws\.com/(?:[a-z0-9-]+/)?"
            r"AWSReservedSSO_ScanalyzeAuthorityRetire"
            r"(?:Approve|Class)_[0-9a-fA-F]{16}"
        )
        discovered = self._session._paginate(
            operation="iam:ListRoles", service="iam", method="list_roles", request={}, item_key="Roles", request_token_key="Marker", response_token_key="Marker", truncated_key="IsTruncated"
        )
        items = []
        for arn in role_arns:
            exact_discovered = [
                item
                for item in discovered
                if isinstance(item, Mapping) and item.get("Arn") == arn
            ]
            if not exact_discovered:
                continue
            role_name = _arn_suffix(arn, ":role/").rsplit("/", 1)[-1]
            inline_names = self._session._paginate(operation="iam:ListRolePolicies", service="iam", method="list_role_policies", request={"RoleName": role_name}, item_key="PolicyNames", request_token_key="Marker", response_token_key="Marker", truncated_key="IsTruncated")
            inline = [
                self._session._invoke(operation="iam:GetRolePolicy", service="iam", method="get_role_policy", request={"RoleName": role_name, "PolicyName": name}, absent_ok=True)
                for name in inline_names if isinstance(name, str)
            ]
            items.append({
                "role_arn": arn,
                "discovered": exact_discovered,
                "role": self._session._invoke(operation="iam:GetRole", service="iam", method="get_role", request={"RoleName": role_name}, absent_ok=True),
                "attached_policies": self._session._paginate(operation="iam:ListAttachedRolePolicies", service="iam", method="list_attached_role_policies", request={"RoleName": role_name}, item_key="AttachedPolicies", request_token_key="Marker", response_token_key="Marker", truncated_key="IsTruncated"),
                "inline_policies": inline,
                "tags": self._session._paginate(operation="iam:ListRoleTags", service="iam", method="list_role_tags", request={"RoleName": role_name}, item_key="Tags", request_token_key="Marker", response_token_key="Marker", truncated_key="IsTruncated"),
            })
        exact_role_arns = set(role_arns)
        items.extend(
            {
                "role_arn": item["Arn"],
                "collision": True,
                "discovered": [item],
            }
            for item in discovered
            if isinstance(item, Mapping)
            and isinstance(item.get("Arn"), str)
            and collision_pattern.fullmatch(item["Arn"]) is not None
            and item["Arn"] not in exact_role_arns
        )
        return _single_page(items)

    def artifact_objects(self, cursor: object | None) -> Mapping[str, Any]:
        _require_first_cursor(cursor)
        object_arns = self._scope.resources("ReadExactArtifactObjectVersions")
        items = []
        for arn in object_arns:
            remainder = _arn_suffix(arn, "arn:aws:s3:::")
            if "/" not in remainder:
                _fail("POLICY_SCOPE_INVALID")
            bucket, key = remainder.split("/", 1)
            versions = self._session._paginate_object_versions({"Bucket": bucket, "Prefix": key})
            exact_versions = [item for item in versions if isinstance(item, Mapping) and item.get("Key") == key]
            if not exact_versions:
                continue
            observations = []
            for version in exact_versions:
                if version.get("record_type") == "DELETE_MARKER":
                    observations.append({"version": version, "deleted": True})
                    continue
                request = {"Bucket": bucket, "Key": key}
                operation = "s3:GetObjectAttributes"
                tag_operation = "s3:GetObjectTagging"
                if isinstance(version.get("VersionId"), str):
                    request["VersionId"] = version["VersionId"]
                    tag_operation = "s3:GetObjectVersionTagging"
                attributes = self._session._invoke(
                    operation=operation,
                    service="s3",
                    method="get_object_attributes",
                    request={
                        **request,
                        "ObjectAttributes": [
                            "ETag",
                            "Checksum",
                            "StorageClass",
                            "ObjectSize",
                        ],
                    },
                    absent_ok=True,
                )
                if "ObjectParts" in attributes:
                    parts = attributes.get("ObjectParts")
                    if isinstance(parts, Mapping) and parts.get("IsTruncated") is True:
                        _fail("PROVIDER_PAGE_INCOMPLETE")
                    _fail("PROVIDER_RESPONSE_INVALID")
                observations.append({
                    "version": version,
                    "attributes": attributes,
                    "tags": self._session._invoke(operation=tag_operation, service="s3", method="get_object_tagging", request=request, absent_ok=True),
                })
            items.append({"object_arn": arn, "observations": observations})
        return _single_page(items)


class _IdentityDiscoveryTransitionAttestation:
    """Opaque one-shot proof of the concrete discovery session's outputs."""

    __slots__ = (
        "_token",
        "_owner",
        "_execution_capability",
        "_capture_index",
        "_session_digest",
        "_policy_digest",
        "_discovery",
        "_discovery_digest",
        "_session_events_digest",
        "_consumed",
        "_lock",
    )

    def __init__(
        self,
        token: object,
        *,
        owner: LiveProviderFactory,
        execution_capability: object,
        capture_index: int,
        session_digest: str,
        policy_digest: str,
        discovery: Mapping[str, Any],
        discovery_digest: str,
        session_events_digest: str,
    ) -> None:
        if token is not _IDENTITY_DISCOVERY_TRANSITION_ATTESTATION:
            _fail("DISCOVERY_TRANSITION_ATTESTATION_REQUIRED")
        self._token = token
        self._owner = owner
        self._execution_capability = execution_capability
        self._capture_index = capture_index
        self._session_digest = session_digest
        self._policy_digest = policy_digest
        self._discovery = json.loads(canonical_json(discovery))
        self._discovery_digest = discovery_digest
        self._session_events_digest = session_events_digest
        self._consumed = False
        self._lock = threading.Lock()


def consume_identity_discovery_transition_attestation(
    value: object,
    *,
    execution_capability: object,
    capture_index: int,
    expected_policy_digest: str,
) -> dict[str, Any]:
    """Consume concrete discovery proof without exposing provider internals."""

    if (
        type(value) is not _IdentityDiscoveryTransitionAttestation
        or value._token  # type: ignore[attr-defined]
        is not _IDENTITY_DISCOVERY_TRANSITION_ATTESTATION
        or value._execution_capability  # type: ignore[attr-defined]
        is not execution_capability
        or value._capture_index != capture_index  # type: ignore[attr-defined]
        or value._policy_digest  # type: ignore[attr-defined]
        != expected_policy_digest
        or not is_attested_discovery_provider(
            value._owner, execution_capability  # type: ignore[attr-defined]
        )
    ):
        _fail("DISCOVERY_TRANSITION_ATTESTATION_REQUIRED")
    owner = value._owner  # type: ignore[attr-defined]
    session_events = [
        item
        for item in owner._events
        if item.get("session_digest")
        == value._session_digest  # type: ignore[attr-defined]
    ]
    if (
        canonical_digest(session_events)
        != value._session_events_digest  # type: ignore[attr-defined]
        or canonical_digest(value._discovery)  # type: ignore[attr-defined]
        != value._discovery_digest  # type: ignore[attr-defined]
    ):
        _fail("DISCOVERY_TRANSITION_ATTESTATION_INVALID")
    with value._lock:  # type: ignore[attr-defined]
        if value._consumed:  # type: ignore[attr-defined]
            _fail("DISCOVERY_TRANSITION_ATTESTATION_CONSUMED")
        value._consumed = True  # type: ignore[attr-defined]
    return json.loads(canonical_json(value._discovery))  # type: ignore[attr-defined]


class _IdentityDiscoveryReader:
    def __init__(self, session: _StsSession) -> None:
        self._session = session
        self._observed: dict[str, list[dict[str, Any]]] = {}
        self._attested = False

    def _record_surface(
        self, name: str, items: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        if name in self._observed:
            _fail("DISCOVERY_TRANSITION_ATTESTATION_INVALID")
        try:
            detached = json.loads(canonical_json(list(items)))
        except Exception as exc:
            raise LiveProviderError(
                "DISCOVERY_TRANSITION_ATTESTATION_INVALID"
            ) from exc
        if not isinstance(detached, list) or any(
            not isinstance(item, dict) for item in detached
        ):
            _fail("DISCOVERY_TRANSITION_ATTESTATION_INVALID")
        result = sorted(detached, key=canonical_json)
        self._observed[name] = result
        return result

    def list_instances(self, token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        values = self._session._paginate(operation="sso:ListInstances", service="sso-admin", method="list_instances", request={}, item_key="Instances", request_token_key="NextToken", response_token_key="NextToken")
        items = [{
            "identity_store_id": item.get("IdentityStoreId"),
            "instance_arn": item.get("InstanceArn"),
            "owner_account_id": item.get("OwnerAccountId"),
            "status": item.get("Status"),
        } for item in values if isinstance(item, Mapping)]
        return _identity_page(self._record_surface("instances", items))

    def list_applications(self, instance_arn: str, application_name: str, token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        values = self._session._paginate(operation="sso:ListApplications", service="sso-admin", method="list_applications", request={"InstanceArn": instance_arn}, item_key="Applications", request_token_key="NextToken", response_token_key="NextToken")
        items = [{
            "application_arn": item.get("ApplicationArn"), "name": item.get("Name")
        } for item in values if isinstance(item, Mapping) and item.get("Name") == application_name]
        return _identity_page(self._record_surface("applications", items))

    def list_permission_sets(self, instance_arn: str, names: tuple[str, str], token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        values = self._session._paginate(operation="sso:ListPermissionSets", service="sso-admin", method="list_permission_sets", request={"InstanceArn": instance_arn}, item_key="PermissionSets", request_token_key="NextToken", response_token_key="NextToken")
        expected_names = set(names)
        if len(names) != 2 or len(expected_names) != 2 or any(
            not isinstance(name, str) or not name for name in names
        ):
            _fail("PERMISSION_SET_NAMES_INVALID")
        items = []
        for arn in values:
            if not isinstance(arn, str) or not arn:
                _fail("PROVIDER_RESPONSE_INVALID")
            described = self._session._invoke(
                operation="sso:DescribePermissionSet",
                service="sso-admin",
                method="describe_permission_set",
                request={"InstanceArn": instance_arn, "PermissionSetArn": arn},
            )
            permission_set = described.get("PermissionSet")
            if not isinstance(permission_set, Mapping):
                _fail("PROVIDER_RESPONSE_INVALID")
            name = permission_set.get("Name")
            observed_arn = permission_set.get("PermissionSetArn")
            if observed_arn != arn or not isinstance(name, str) or not name:
                _fail("PROVIDER_RESPONSE_INVALID")
            if name in expected_names:
                items.append({"name": name, "permission_set_arn": arn})
        return _identity_page(self._record_surface("permission_sets", items))

    def attest_transition(
        self, discovery_digest: str
    ) -> _IdentityDiscoveryTransitionAttestation:
        owner = self._session._owner
        execution_capability = owner._execution_capability
        discovery = {
            key: self._observed[key]
            for key in ("instances", "applications", "permission_sets")
            if key in self._observed
        }
        session_events = [
            item
            for item in owner._events
            if item.get("session_digest") == self._session._session_digest
        ]
        required_operations = {
            "sts:GetCallerIdentity",
            "sso:ListInstances",
            "sso:ListApplications",
            "sso:ListPermissionSets",
        }
        if (
            self._attested
            or owner._provider_attestation is not _DISCOVERY_PROVIDER_ATTESTATION
            or execution_capability is None
            or self._session._stage != "discovery"
            or self._session._identity_validated is not True
            or set(discovery)
            != {"instances", "applications", "permission_sets"}
            or _DIGEST.fullmatch(str(discovery_digest)) is None
            or canonical_digest(discovery) != discovery_digest
            or not session_events
            or session_events[0].get("operation") != "sts:GetCallerIdentity"
            or required_operations
            - {item.get("operation") for item in session_events}
            or any(item.get("outcome") != "SUCCESS" for item in session_events)
        ):
            _fail("DISCOVERY_TRANSITION_ATTESTATION_INVALID")
        self._attested = True
        return _IdentityDiscoveryTransitionAttestation(
            _IDENTITY_DISCOVERY_TRANSITION_ATTESTATION,
            owner=owner,
            execution_capability=execution_capability,
            capture_index=self._session._capture_index,
            session_digest=self._session._session_digest,
            policy_digest=self._session._policy_digest,
            discovery=discovery,
            discovery_digest=discovery_digest,
            session_events_digest=canonical_digest(session_events),
        )


def _one(value: Mapping[str, Any]) -> dict[str, Any]:
    return {"complete": True, "value": dict(value)}


def _strings(value: Any, key: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for name, item in value.items():
            if name == key:
                if isinstance(item, str):
                    found.append(item)
                elif isinstance(item, list):
                    found.extend(raw for raw in item if isinstance(raw, str))
            else:
                found.extend(_strings(item, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_strings(item, key))
    return sorted(set(found))


def _first_mapping(value: Any, key: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        selected = value.get(key)
        if isinstance(selected, Mapping):
            return dict(selected)
        for item in value.values():
            found = _first_mapping(item, key)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _first_mapping(item, key)
            if found:
                return found
    return {}


class _IdentityExactReader:
    def __init__(self, session: _StsSession) -> None:
        self._session = session

    def describe_instance(self, instance_arn: str) -> Mapping[str, Any]:
        value = self._session._invoke(
            operation="sso:DescribeInstance",
            service="sso-admin",
            method="describe_instance",
            request={"InstanceArn": instance_arn},
        )
        encryption = value.get("EncryptionConfigurationDetails")
        if not isinstance(encryption, Mapping):
            _fail("PROVIDER_RESPONSE_INVALID")
        return _one(
            {
                "instance_arn": value.get("InstanceArn"),
                "identity_store_id": value.get("IdentityStoreId"),
                "owner_account_id": value.get("OwnerAccountId"),
                "status": value.get("Status"),
                "encryption": {
                    "key_type": encryption.get("KeyType"),
                    "kms_key_arn": encryption.get("KmsKeyArn"),
                    "status": encryption.get("EncryptionStatus"),
                },
            }
        )

    def read_application(self, application_arn: str) -> Mapping[str, Any]:
        description = self._session._invoke(operation="sso:DescribeApplication", service="sso-admin", method="describe_application", request={"ApplicationArn": application_arn})
        auth_index = self._session._paginate(operation="sso:ListApplicationAuthenticationMethods", service="sso-admin", method="list_application_authentication_methods", request={"ApplicationArn": application_arn}, item_key="AuthenticationMethods", request_token_key="NextToken", response_token_key="NextToken")
        authentication = []
        for item in auth_index:
            kind = item.get("AuthenticationMethodType") if isinstance(item, Mapping) else None
            if isinstance(kind, str):
                authentication.append(self._session._invoke(operation="sso:GetApplicationAuthenticationMethod", service="sso-admin", method="get_application_authentication_method", request={"ApplicationArn": application_arn, "AuthenticationMethodType": kind}))
        grant_index = self._session._paginate(operation="sso:ListApplicationGrants", service="sso-admin", method="list_application_grants", request={"ApplicationArn": application_arn}, item_key="Grants", request_token_key="NextToken", response_token_key="NextToken")
        grant_facts = []
        for item in grant_index:
            kind = item.get("GrantType") if isinstance(item, Mapping) else None
            if isinstance(kind, str):
                grant_facts.append(self._session._invoke(operation="sso:GetApplicationGrant", service="sso-admin", method="get_application_grant", request={"ApplicationArn": application_arn, "GrantType": kind}))
        scope_index = self._session._paginate(operation="sso:ListApplicationAccessScopes", service="sso-admin", method="list_application_access_scopes", request={"ApplicationArn": application_arn}, item_key="Scopes", request_token_key="NextToken", response_token_key="NextToken")
        scopes = []
        for item in scope_index:
            name = item.get("Scope") if isinstance(item, Mapping) else item
            if isinstance(name, str):
                scopes.append(self._session._invoke(operation="sso:GetApplicationAccessScope", service="sso-admin", method="get_application_access_scope", request={"ApplicationArn": application_arn, "Scope": name}))
        assignment = self._session._invoke(operation="sso:GetApplicationAssignmentConfiguration", service="sso-admin", method="get_application_assignment_configuration", request={"ApplicationArn": application_arn})
        application_assignments = self._session._paginate(
            operation="sso:ListApplicationAssignments",
            service="sso-admin",
            method="list_application_assignments",
            request={"ApplicationArn": application_arn},
            item_key="ApplicationAssignments",
            request_token_key="NextToken",
            response_token_key="NextToken",
        )
        tags = self._session._paginate(
            operation="sso:ListTagsForResource",
            service="sso-admin",
            method="list_tags_for_resource",
            request={"ResourceArn": application_arn},
            item_key="Tags",
            request_token_key="NextToken",
            response_token_key="NextToken",
        )
        redirect_uris = []
        for item in grant_facts:
            grant = item.get("Grant") if isinstance(item, Mapping) else None
            authorization = (
                grant.get("AuthorizationCode")
                if isinstance(grant, Mapping)
                else None
            )
            values = (
                authorization.get("RedirectUris")
                if isinstance(authorization, Mapping)
                else None
            )
            if isinstance(values, list):
                redirect_uris.extend(
                    dict(value) for value in values if isinstance(value, Mapping)
                )
        scope_facts = [
            {
                "authorized_targets_digest": item.get(
                    "AuthorizedTargetsDigest"
                ),
                "scope": item.get("Scope"),
            }
            for item in scopes
            if isinstance(item, Mapping)
        ]
        return _one({
            "application_arn": description.get("ApplicationArn"),
            "description": description,
            "grants": sorted(item.get("GrantType") for item in grant_index if isinstance(item, Mapping) and isinstance(item.get("GrantType"), str)),
            "scopes": sorted(scope_facts, key=canonical_json),
            "redirect_uris": sorted(redirect_uris, key=canonical_json),
            "authentication_methods": authentication,
            "assignment_configuration": assignment,
            "actor_policy": _first_mapping(authentication, "ActorPolicy"),
            "assignments": [
                {
                    "application_arn": item.get("ApplicationArn"),
                    "principal_id": item.get("PrincipalId"),
                    "principal_type": item.get("PrincipalType"),
                }
                for item in application_assignments
                if isinstance(item, Mapping)
            ],
            "tags": tags,
        })

    def read_permission_set(self, instance_arn: str, permission_set_arn: str) -> Mapping[str, Any]:
        boundary_response = self._session._invoke(
            operation="sso:GetPermissionsBoundaryForPermissionSet",
            service="sso-admin",
            method="get_permissions_boundary_for_permission_set",
            request={
                "InstanceArn": instance_arn,
                "PermissionSetArn": permission_set_arn,
            },
            absent_ok=True,
        )
        boundary = (
            None
            if set(boundary_response) == {"Absent"}
            else boundary_response.get("PermissionsBoundary")
        )
        value = {
            "instance_arn": instance_arn,
            "permission_set_arn": permission_set_arn,
            "description": self._session._invoke(operation="sso:DescribePermissionSet", service="sso-admin", method="describe_permission_set", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}),
            "managed_policies": self._session._paginate(operation="sso:ListManagedPoliciesInPermissionSet", service="sso-admin", method="list_managed_policies_in_permission_set", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}, item_key="AttachedManagedPolicies", request_token_key="NextToken", response_token_key="NextToken"),
            "customer_managed_policies": self._session._paginate(operation="sso:ListCustomerManagedPolicyReferencesInPermissionSet", service="sso-admin", method="list_customer_managed_policy_references_in_permission_set", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}, item_key="CustomerManagedPolicyReferences", request_token_key="NextToken", response_token_key="NextToken"),
            "inline_policy": self._session._invoke(operation="sso:GetInlinePolicyForPermissionSet", service="sso-admin", method="get_inline_policy_for_permission_set", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}).get("InlinePolicy"),
            "boundary": boundary,
            "tags": self._session._paginate(
                operation="sso:ListTagsForResource",
                service="sso-admin",
                method="list_tags_for_resource",
                request={"ResourceArn": permission_set_arn},
                item_key="Tags",
                request_token_key="NextToken",
                response_token_key="NextToken",
            ),
        }
        return _one(value)

    def list_assignments(self, instance_arn: str, permission_set_arn: str, account_arn: str, token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        account_id = account_arn.rsplit("/", 1)[-1]
        values = self._session._paginate(operation="sso:ListAccountAssignments", service="sso-admin", method="list_account_assignments", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn, "AccountId": account_id}, item_key="AccountAssignments", request_token_key="NextToken", response_token_key="NextToken")
        return _identity_page([{"account_arn": account_arn, "permission_set_arn": permission_set_arn, "principal_id": item.get("PrincipalId"), "principal_type": item.get("PrincipalType")} for item in values if isinstance(item, Mapping)])

    def list_provisioning(self, instance_arn: str, permission_set_arn: str, token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        values = self._session._paginate(operation="sso:ListPermissionSetProvisioningStatus", service="sso-admin", method="list_permission_set_provisioning_status", request={"InstanceArn": instance_arn}, item_key="PermissionSetsProvisioningStatus", request_token_key="NextToken", response_token_key="NextToken")
        facts = []
        for item in values:
            request_id = item.get("RequestId") if isinstance(item, Mapping) else None
            if not isinstance(request_id, str):
                continue
            described = self._session._invoke(operation="sso:DescribePermissionSetProvisioningStatus", service="sso-admin", method="describe_permission_set_provisioning_status", request={"InstanceArn": instance_arn, "ProvisionPermissionSetRequestId": request_id})
            status = described.get("PermissionSetProvisioningStatus")
            if isinstance(status, Mapping) and status.get("PermissionSetArn") == permission_set_arn:
                facts.append({"permission_set_arn": permission_set_arn, "status": status.get("Status")})
        return _identity_page(facts)

    def list_target_accounts(self, instance_arn: str, permission_set_arn: str, token: object | None) -> Mapping[str, Any]:
        _require_first_cursor(token)
        values = self._session._paginate(operation="sso:ListAccountsForProvisionedPermissionSet", service="sso-admin", method="list_accounts_for_provisioned_permission_set", request={"InstanceArn": instance_arn, "PermissionSetArn": permission_set_arn}, item_key="AccountIds", request_token_key="NextToken", response_token_key="NextToken")
        return _identity_page([{"account_arn": f"arn:aws:sso:::account/{item}", "permission_set_arn": permission_set_arn} for item in values if isinstance(item, str)])

    def describe_approved_user(self, identity_store_id: str, user_id: str) -> Mapping[str, Any]:
        value = self._session._invoke(operation="identitystore:DescribeUser", service="identitystore", method="describe_user", request={"IdentityStoreId": identity_store_id, "UserId": user_id})
        return _one({"UserId": value.get("UserId")})


def build_discovery_provider_factory(
    *,
    sdk_runtime_root: str,
    authority_profile: str,
    identity_center_profile: str,
    authority_expected_account_id: str,
    authority_expected_principal_digest: str,
    authority_expected_sso_role_name_digest: str,
    identity_expected_account_id: str,
    identity_expected_principal_digest: str,
    identity_expected_sso_role_name_digest: str,
    authority_verification_digest: str,
    identity_authority_verification_digest: str,
    discovery_budget: object,
    execution_capability: object,
) -> LiveProviderFactory:
    """Build the concrete, budgeted GUG-393 discovery provider."""

    try:
        from tooling.platform_authority_gug393_discovery_budget import (
            GlobalDiscoveryBudget,
        )
        from tooling.platform_authority_gug393_private_input_discovery import (
            assert_preflight_provider_capability_bindings,
        )
    except Exception as exc:
        raise LiveProviderError(
            "DISCOVERY_PROVIDER_DEPENDENCY_REQUIRED"
        ) from exc

    if type(discovery_budget) is not GlobalDiscoveryBudget:
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")
    try:
        budget_summary = discovery_budget.summary()
    except Exception as exc:
        raise _safe_discovery_error(
            exc, "DISCOVERY_BUDGET_BINDING_INVALID"
        ) from exc
    budget_digest = (
        budget_summary.get("budget_digest")
        if isinstance(budget_summary, Mapping)
        else None
    )
    zero_counters = (
        "provider_calls",
        "credential_vending_calls",
        "network_calls",
        "page_calls",
        "projected_response_bytes",
    )
    if (
        not isinstance(budget_digest, str)
        or _DIGEST.fullmatch(budget_digest) is None
        or any(
            type(budget_summary.get(field)) is not int
            or budget_summary.get(field) != 0
            for field in zero_counters
        )
    ):
        _fail("DISCOVERY_BUDGET_BINDING_INVALID")

    try:
        validity_gate = assert_preflight_provider_capability_bindings(
            execution_capability,
            sdk_runtime_root=sdk_runtime_root,
            authority_profile=authority_profile,
            identity_center_profile=identity_center_profile,
            authority_expected_account_id=authority_expected_account_id,
            authority_expected_principal_digest=(
                authority_expected_principal_digest
            ),
            authority_expected_sso_role_name_digest=(
                authority_expected_sso_role_name_digest
            ),
            identity_expected_account_id=identity_expected_account_id,
            identity_expected_principal_digest=(
                identity_expected_principal_digest
            ),
            identity_expected_sso_role_name_digest=(
                identity_expected_sso_role_name_digest
            ),
            authority_verification_digest=authority_verification_digest,
            identity_authority_verification_digest=(
                identity_authority_verification_digest
            ),
            budget_digest=budget_digest,
        )
        if not callable(getattr(validity_gate, "authorize_session", None)):
            _fail("DISCOVERY_EXECUTION_CAPABILITY_REQUIRED")
    except Exception as exc:
        raise _safe_discovery_error(
            exc, "DISCOVERY_EXECUTION_CAPABILITY_REQUIRED"
        ) from exc

    try:
        checked_sdk_runtime_root = Path(sdk_runtime_root)
        if (
            not checked_sdk_runtime_root.is_absolute()
            or checked_sdk_runtime_root.resolve(strict=True)
            != checked_sdk_runtime_root
        ):
            _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
    except LiveProviderError:
        raise
    except (OSError, TypeError) as exc:
        raise LiveProviderError("AWS_SDK_RUNTIME_ROOT_INVALID") from exc

    return LiveProviderFactory._open(
        ProviderConfig(
            authority_profile=authority_profile,
            identity_center_profile=identity_center_profile,
            authority_expected_account_id=authority_expected_account_id,
            authority_expected_principal_digest=authority_expected_principal_digest,
            authority_expected_sso_role_name_digest=(
                authority_expected_sso_role_name_digest
            ),
            authority_verification_digest=authority_verification_digest,
            identity_expected_account_id=identity_expected_account_id,
            identity_expected_principal_digest=identity_expected_principal_digest,
            identity_expected_sso_role_name_digest=(
                identity_expected_sso_role_name_digest
            ),
            identity_authority_verification_digest=(
                identity_authority_verification_digest
            ),
            validity_gate=validity_gate,
            sdk_runtime_root=checked_sdk_runtime_root,
        ),
        concrete=True,
        session_factory=None,
        config_factory=None,
        clock=lambda: datetime.now(UTC),
        environment=os.environ,
        execution_capability=execution_capability,
        discovery_budget=discovery_budget,
    )


def build_live_provider_factory(
    *,
    sdk_runtime_root: str,
    authority_profile: str,
    identity_center_profile: str,
    authority_expected_account_id: str,
    authority_expected_principal_digest: str,
    authority_expected_sso_role_name_digest: str,
    identity_expected_account_id: str,
    identity_expected_principal_digest: str,
    identity_expected_sso_role_name_digest: str,
    authority_verification_digest: str,
    identity_authority_verification_digest: str,
    execution_capability: object,
) -> LiveProviderFactory:
    """Production-only builder; accepts no SDK/session injection."""

    try:
        validity_gate = assert_live_provider_capability_bindings(
            execution_capability,
            sdk_runtime_root=sdk_runtime_root,
            authority_profile=authority_profile,
            identity_center_profile=identity_center_profile,
            authority_expected_account_id=authority_expected_account_id,
            authority_expected_principal_digest=authority_expected_principal_digest,
            authority_expected_sso_role_name_digest=(
                authority_expected_sso_role_name_digest
            ),
            identity_expected_account_id=identity_expected_account_id,
            identity_expected_principal_digest=identity_expected_principal_digest,
            identity_expected_sso_role_name_digest=(
                identity_expected_sso_role_name_digest
            ),
            authority_verification_digest=authority_verification_digest,
            identity_authority_verification_digest=(
                identity_authority_verification_digest
            ),
        )
    except Exception as exc:
        raise LiveProviderError(
            "LIVE_REQUEST_EXECUTION_CAPABILITY_REQUIRED"
        ) from exc

    try:
        checked_sdk_runtime_root = Path(sdk_runtime_root)
        if (
            not checked_sdk_runtime_root.is_absolute()
            or checked_sdk_runtime_root.resolve(strict=True)
            != checked_sdk_runtime_root
        ):
            _fail("AWS_SDK_RUNTIME_ROOT_INVALID")
    except LiveProviderError:
        raise
    except (OSError, TypeError) as exc:
        raise LiveProviderError("AWS_SDK_RUNTIME_ROOT_INVALID") from exc

    return LiveProviderFactory._open(
        ProviderConfig(
            authority_profile=authority_profile,
            identity_center_profile=identity_center_profile,
            authority_expected_account_id=authority_expected_account_id,
            authority_expected_principal_digest=authority_expected_principal_digest,
            authority_expected_sso_role_name_digest=authority_expected_sso_role_name_digest,
            authority_verification_digest=authority_verification_digest,
            identity_expected_account_id=identity_expected_account_id,
            identity_expected_principal_digest=identity_expected_principal_digest,
            identity_expected_sso_role_name_digest=identity_expected_sso_role_name_digest,
            identity_authority_verification_digest=identity_authority_verification_digest,
            validity_gate=validity_gate,
            sdk_runtime_root=checked_sdk_runtime_root,
        ),
        concrete=True,
        session_factory=None,
        config_factory=None,
        clock=lambda: datetime.now(UTC),
        environment=os.environ,
        execution_capability=execution_capability,
    )


def build_injected_provider_factory(
    *,
    authority_profile: str,
    identity_center_profile: str,
    authority_expected_account_id: str,
    authority_expected_principal_digest: str,
    authority_expected_sso_role_name_digest: str,
    identity_expected_account_id: str,
    identity_expected_principal_digest: str,
    identity_expected_sso_role_name_digest: str,
    authority_verification_digest: str,
    identity_authority_verification_digest: str,
    validity_gate: Callable[[], None],
    session_factory: Callable[..., Any],
    config_factory: Callable[..., Any],
    clock: Callable[[], datetime],
    environment: Mapping[str, str] | None = None,
) -> LiveProviderFactory:
    """Deterministic test builder that is permanently non-live."""

    return LiveProviderFactory._open(
        ProviderConfig(
            authority_profile=authority_profile,
            identity_center_profile=identity_center_profile,
            authority_expected_account_id=authority_expected_account_id,
            authority_expected_principal_digest=authority_expected_principal_digest,
            authority_expected_sso_role_name_digest=authority_expected_sso_role_name_digest,
            authority_verification_digest=authority_verification_digest,
            identity_expected_account_id=identity_expected_account_id,
            identity_expected_principal_digest=identity_expected_principal_digest,
            identity_expected_sso_role_name_digest=identity_expected_sso_role_name_digest,
            identity_authority_verification_digest=identity_authority_verification_digest,
            validity_gate=validity_gate,
        ),
        concrete=False,
        session_factory=session_factory,
        config_factory=config_factory,
        clock=clock,
        environment={} if environment is None else environment,
        execution_capability=None,
    )


def is_attested_live_provider(
    value: object, execution_capability: object | None = None
) -> bool:
    """Return true only for the concrete builder's exact factory instance."""

    return (
        type(value) is LiveProviderFactory
        and getattr(value, "_concrete", None) is True
        and getattr(value, "_provider_attestation", None)
        is _CONCRETE_PROVIDER_ATTESTATION
        and getattr(value, "concrete_provider", None) is True
        and getattr(value, "mode", None) == "ATTESTED_LIVE"
        and execution_capability is not None
        and getattr(value, "_execution_capability", None)
        is execution_capability
    )


def is_attested_discovery_provider(
    value: object, execution_capability: object | None = None
) -> bool:
    """Return true only for the concrete GUG-393 discovery builder."""

    return (
        type(value) is LiveProviderFactory
        and getattr(value, "_concrete", None) is True
        and getattr(value, "_provider_attestation", None)
        is _DISCOVERY_PROVIDER_ATTESTATION
        and getattr(value, "concrete_provider", None) is True
        and getattr(value, "discovery_provider", None) is True
        and getattr(value, "mode", None) == "ATTESTED_DISCOVERY"
        and getattr(value, "_discovery_budget", None) is not None
        and execution_capability is not None
        and getattr(value, "_execution_capability", None)
        is execution_capability
    )


__all__ = [
    "LiveProviderError",
    "LiveProviderFactory",
    "MAX_PAGES",
    "OPERATION_ALLOWLIST",
    "ProviderConfig",
    "REGION",
    "build_discovery_provider_factory",
    "build_injected_provider_factory",
    "build_live_provider_factory",
    "consume_identity_discovery_transition_attestation",
    "is_attested_discovery_provider",
    "is_attested_live_provider",
]
