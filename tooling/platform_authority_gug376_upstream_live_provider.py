"""Closed AWS transport for the separately authorized GUG-432 upstream lane.

This module is inert on import. It does not approve an operation, certify a
provider transcript, or replace GUG-377's inert construction boundary. The
executor owns durable claims and external authorization/attestation. Responses
stay in memory for that verifier; public results contain only bounded digests.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from tooling.platform_authority_gug365_upstream_prerequisites import REQUEST_KEYS
from tooling.platform_authority_gug365_upstream_provider_contracts import (
    OPERATION_DEFINITIONS,
)

REGION = "us-east-1"
AUTHORITY_ACCOUNT_ID = "042360977644"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CALLER = re.compile(r"^arn:aws:sts::([0-9]{12}):assumed-role/[^/]+/[^/]+$")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_READBACKS = 32
_MAX_POLLS = 12


class UpstreamProviderError(ValueError):
    """Stable error without request, provider message, ARN, or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code if re.fullmatch(r"[A-Z][A-Z0-9_]{2,95}", code) else "PROVIDER_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise UpstreamProviderError(code) from None


def _json(value: Any) -> str:
    def encode(item: Any) -> str:
        if isinstance(item, (datetime, date)):
            return item.isoformat()
        raise TypeError
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False, default=encode)
    except (ValueError, TypeError, OverflowError, RecursionError):
        _fail("PROVIDER_VALUE_INVALID")


def digest(value: Any) -> str:
    return "sha256:" + sha256(_json(value).encode()).hexdigest()


def _snapshot(value: Any) -> Any:
    payload = _json(value)
    if len(payload.encode()) > _MAX_RESPONSE_BYTES:
        _fail("PROVIDER_RESPONSE_TOO_LARGE")
    return json.loads(payload)


def _get(value: Any, field: str) -> Any:
    return value.get(field) if isinstance(value, Mapping) else getattr(value, field, None)


# Explicit routes: no caller-supplied service, action, method, or execute hook.
_METHODS = (
    "create_application", "put_application_grant", "put_application_access_scope",
    "put_application_assignment_configuration", "create_application_assignment",
    "create_permission_set", "create_permission_set", "put_inline_policy_to_permission_set",
    "put_inline_policy_to_permission_set", "create_account_assignment", "create_account_assignment",
    "provision_permission_set", "provision_permission_set", "put_application_authentication_method",
    "create_key", "enable_key_rotation", "create_alias", "create_bucket",
    "put_bucket_ownership_controls", "put_public_access_block", "put_bucket_versioning",
    "put_bucket_encryption", "put_bucket_policy", "put_bucket_tagging", "put_signing_profile",
    "create_code_signing_config", "put_object", "start_signing_job", "put_object", "start_signing_job",
)
_PHASES = (
    *("IDENTITY_CENTER_FOUNDATION",) * 14,
    *("KMS_FOUNDATION",) * 3,
    *("S3_ARTIFACT_FOUNDATION",) * 7,
    "SIGNER_PROFILE_FOUNDATION", "LAMBDA_CSC_FOUNDATION", "BROKER_UNSIGNED_PUBLISH",
    "BROKER_SIGNING_JOB", "LEDGER_FACTORY_UNSIGNED_PUBLISH", "LEDGER_FACTORY_SIGNING_JOB",
)


@dataclass(frozen=True)
class OperationRoute:
    service: str
    method: str
    api_name: str
    phase: str
    request_keys: frozenset[str]


OPERATION_ROUTES = MappingProxyType({
    definition.operation_id: OperationRoute(
        "sso-admin" if definition.action.startswith("sso:") else definition.action.split(":")[0],
        method, definition.action.split(":")[1], phase, REQUEST_KEYS[definition.action],
    )
    for definition, method, phase in zip(OPERATION_DEFINITIONS, _METHODS, _PHASES, strict=True)
})


@dataclass(frozen=True)
class ReadbackProjection:
    service: str
    method: str
    api_name: str
    request_keys: frozenset[str]
    fields: tuple[str, ...]
    terminal_field: str | None = None


def _projection(service: str, method: str, api: str, keys: str, fields: str,
                terminal: str | None = None) -> ReadbackProjection:
    return ReadbackProjection(service, method, api, frozenset(keys.split()), tuple(fields.split()), terminal)


# Projection names are a closed vocabulary, not JSON paths chosen by a caller.
READBACK_PROJECTIONS = MappingProxyType({
    "SSO_DESCRIBE_APPLICATION_V1": _projection("sso-admin", "describe_application", "DescribeApplication", "ApplicationArn", "ApplicationArn ApplicationProviderArn InstanceArn Name Status PortalOptions"),
    "SSO_APPLICATION_GRANT_V1": _projection("sso-admin", "get_application_grant", "GetApplicationGrant", "ApplicationArn GrantType", "Grant GrantType"),
    "SSO_APPLICATION_SCOPE_V1": _projection("sso-admin", "get_application_access_scope", "GetApplicationAccessScope", "ApplicationArn Scope", "Scope AuthorizedTargets"),
    "SSO_APPLICATION_AUTHENTICATION_V1": _projection("sso-admin", "get_application_authentication_method", "GetApplicationAuthenticationMethod", "ApplicationArn AuthenticationMethodType", "AuthenticationMethod"),
    "SSO_ASSIGNMENT_CONFIGURATION_V1": _projection("sso-admin", "get_application_assignment_configuration", "GetApplicationAssignmentConfiguration", "ApplicationArn", "AssignmentRequired"),
    "SSO_APPLICATION_ASSIGNMENTS_V1": _projection("sso-admin", "list_application_assignments", "ListApplicationAssignments", "ApplicationArn MaxResults", "ApplicationAssignments"),
    "SSO_PERMISSION_SET_V1": _projection("sso-admin", "describe_permission_set", "DescribePermissionSet", "InstanceArn PermissionSetArn", "PermissionSet.PermissionSetArn PermissionSet.Name PermissionSet.Description PermissionSet.SessionDuration PermissionSet.RelayState"),
    "SSO_INLINE_POLICY_V1": _projection("sso-admin", "get_inline_policy_for_permission_set", "GetInlinePolicyForPermissionSet", "InstanceArn PermissionSetArn", "InlinePolicy"),
    "SSO_ACCOUNT_ASSIGNMENTS_V1": _projection("sso-admin", "list_account_assignments", "ListAccountAssignments", "AccountId InstanceArn PermissionSetArn MaxResults", "AccountAssignments"),
    "SSO_ACCOUNT_ASSIGNMENT_STATUS_V1": _projection("sso-admin", "describe_account_assignment_creation_status", "DescribeAccountAssignmentCreationStatus", "InstanceArn AccountAssignmentCreationRequestId", "AccountAssignmentCreationStatus.Status AccountAssignmentCreationStatus.RequestId AccountAssignmentCreationStatus.TargetId AccountAssignmentCreationStatus.TargetType AccountAssignmentCreationStatus.PermissionSetArn AccountAssignmentCreationStatus.PrincipalId AccountAssignmentCreationStatus.PrincipalType", "AccountAssignmentCreationStatus.Status"),
    "SSO_PROVISION_STATUS_V1": _projection("sso-admin", "describe_permission_set_provisioning_status", "DescribePermissionSetProvisioningStatus", "InstanceArn ProvisionPermissionSetRequestId", "PermissionSetProvisioningStatus.Status PermissionSetProvisioningStatus.RequestId PermissionSetProvisioningStatus.AccountId PermissionSetProvisioningStatus.PermissionSetArn", "PermissionSetProvisioningStatus.Status"),
    "KMS_DESCRIBE_KEY_V1": _projection("kms", "describe_key", "DescribeKey", "KeyId", "KeyMetadata.Arn KeyMetadata.KeyId KeyMetadata.KeyState KeyMetadata.KeyUsage KeyMetadata.KeySpec KeyMetadata.Origin KeyMetadata.MultiRegion KeyMetadata.Enabled"),
    "KMS_KEY_POLICY_V1": _projection("kms", "get_key_policy", "GetKeyPolicy", "KeyId PolicyName", "Policy"),
    "KMS_KEY_ROTATION_V1": _projection("kms", "get_key_rotation_status", "GetKeyRotationStatus", "KeyId", "KeyId KeyRotationEnabled RotationPeriodInDays"),
    "KMS_ALIASES_V1": _projection("kms", "list_aliases", "ListAliases", "KeyId Limit", "Aliases"),
    "KMS_TAGS_V1": _projection("kms", "list_resource_tags", "ListResourceTags", "KeyId Limit", "Tags"),
    "S3_HEAD_BUCKET_V1": _projection("s3", "head_bucket", "HeadBucket", "Bucket ExpectedBucketOwner", "BucketRegion"),
    "S3_OWNERSHIP_V1": _projection("s3", "get_bucket_ownership_controls", "GetBucketOwnershipControls", "Bucket ExpectedBucketOwner", "OwnershipControls"),
    "S3_PUBLIC_ACCESS_V1": _projection("s3", "get_public_access_block", "GetPublicAccessBlock", "Bucket ExpectedBucketOwner", "PublicAccessBlockConfiguration"),
    "S3_VERSIONING_V1": _projection("s3", "get_bucket_versioning", "GetBucketVersioning", "Bucket ExpectedBucketOwner", "Status MFADelete"),
    "S3_ENCRYPTION_V1": _projection("s3", "get_bucket_encryption", "GetBucketEncryption", "Bucket ExpectedBucketOwner", "ServerSideEncryptionConfiguration"),
    "S3_POLICY_V1": _projection("s3", "get_bucket_policy", "GetBucketPolicy", "Bucket ExpectedBucketOwner", "Policy"),
    "S3_TAGS_V1": _projection("s3", "get_bucket_tagging", "GetBucketTagging", "Bucket ExpectedBucketOwner", "TagSet"),
    "S3_HEAD_OBJECT_V1": _projection("s3", "head_object", "HeadObject", "Bucket Key VersionId ChecksumMode ExpectedBucketOwner", "VersionId ContentLength ChecksumSHA256 ServerSideEncryption SSEKMSKeyId"),
    "S3_OBJECT_ATTRIBUTES_V1": _projection("s3", "get_object_attributes", "GetObjectAttributes", "Bucket Key VersionId ObjectAttributes ExpectedBucketOwner", "VersionId Checksum ObjectSize"),
    "S3_OBJECT_TAGS_V1": _projection("s3", "get_object_tagging", "GetObjectTagging", "Bucket Key VersionId ExpectedBucketOwner", "VersionId TagSet"),
    "SIGNER_PROFILE_V1": _projection("signer", "get_signing_profile", "GetSigningProfile", "profileName profileOwner", "profileName profileVersion profileVersionArn status platformId signatureValidityPeriod signingMaterial signingParameters"),
    "SIGNER_PERMISSIONS_V1": _projection("signer", "list_profile_permissions", "ListProfilePermissions", "profileName", "permissions revisionId"),
    "SIGNER_TAGS_V1": _projection("signer", "list_tags_for_resource", "ListTagsForResource", "resourceArn", "tags"),
    "SIGNER_JOB_V1": _projection("signer", "describe_signing_job", "DescribeSigningJob", "jobId", "jobId source destination signedObject profileName profileVersion platformId status", "status"),
    "LAMBDA_CSC_V1": _projection("lambda", "get_code_signing_config", "GetCodeSigningConfig", "CodeSigningConfigArn", "CodeSigningConfig.CodeSigningConfigId CodeSigningConfig.CodeSigningConfigArn CodeSigningConfig.Description CodeSigningConfig.AllowedPublishers CodeSigningConfig.CodeSigningPolicies"),
    "LAMBDA_TAGS_V1": _projection("lambda", "list_tags", "ListTags", "Resource", "Tags"),
})
_ENDPOINTS = MappingProxyType({
    "sts": "sts.us-east-1.amazonaws.com", "sso-admin": "sso.us-east-1.amazonaws.com",
    "kms": "kms.us-east-1.amazonaws.com", "s3": "s3.us-east-1.amazonaws.com",
    "signer": "signer.us-east-1.amazonaws.com", "lambda": "lambda.us-east-1.amazonaws.com",
})
_RESPONSE_FIELDS = frozenset({
    "ApplicationArn", "PermissionSet.PermissionSetArn", "KeyMetadata.KeyId", "KeyMetadata.Arn",
    "VersionId", "jobId", "profileVersionArn", "CodeSigningConfig.CodeSigningConfigArn",
    "CodeSigningConfig.CodeSigningConfigId", "profileVersion", "arn",
    "AccountAssignmentCreationStatus.RequestId", "PermissionSetProvisioningStatus.RequestId",
})
_BEFORE_ONLY = {
    "SSO_APPLICATIONS_V1": _projection("sso-admin", "list_applications", "ListApplications", "InstanceArn MaxResults", "Applications"),
    "SSO_PERMISSION_SETS_V1": _projection("sso-admin", "list_permission_sets", "ListPermissionSets", "InstanceArn MaxResults", "PermissionSets"),
    "LAMBDA_CSCS_V1": _projection("lambda", "list_code_signing_configs", "ListCodeSigningConfigs", "MaxItems", "CodeSigningConfigs"),
    "KMS_KEYS_V1": _projection("kms", "list_keys", "ListKeys", "Limit", "Keys"),
}
READBACK_PROJECTIONS = MappingProxyType({**READBACK_PROJECTIONS, **_BEFORE_ONLY})
_REQUIRED_AFTER = MappingProxyType(dict(zip(_METHODS, (
    "SSO_DESCRIBE_APPLICATION_V1", "SSO_APPLICATION_GRANT_V1", "SSO_APPLICATION_SCOPE_V1",
    "SSO_ASSIGNMENT_CONFIGURATION_V1", "SSO_APPLICATION_ASSIGNMENTS_V1",
    "SSO_PERMISSION_SET_V1", "SSO_PERMISSION_SET_V1", "SSO_INLINE_POLICY_V1", "SSO_INLINE_POLICY_V1",
    "SSO_ACCOUNT_ASSIGNMENT_STATUS_V1", "SSO_ACCOUNT_ASSIGNMENT_STATUS_V1", "SSO_PROVISION_STATUS_V1", "SSO_PROVISION_STATUS_V1",
    "SSO_APPLICATION_AUTHENTICATION_V1", "KMS_DESCRIBE_KEY_V1", "KMS_KEY_ROTATION_V1", "KMS_ALIASES_V1",
    "S3_HEAD_BUCKET_V1", "S3_OWNERSHIP_V1", "S3_PUBLIC_ACCESS_V1", "S3_VERSIONING_V1", "S3_ENCRYPTION_V1", "S3_POLICY_V1", "S3_TAGS_V1",
    "SIGNER_PROFILE_V1", "LAMBDA_CSC_V1", "S3_HEAD_OBJECT_V1", "SIGNER_JOB_V1", "S3_HEAD_OBJECT_V1", "SIGNER_JOB_V1",
), strict=True)))
_ABSENCE = frozenset({"NoSuchEntity", "NoSuchKey", "NoSuchBucket", "NotFound", "NotFoundException", "ResourceNotFoundException"})
_NO_EFFECT = frozenset({"AccessDenied", "AccessDeniedException", "ValidationException", "ValidationError", "InvalidParameterException", "InvalidParameterValueException", "MalformedPolicyDocument", "ParamValidationError"})


@dataclass(frozen=True)
class Observation:
    status: str
    readback_digest: str
    provider_calls: int
    mode: str


@dataclass(frozen=True)
class ProviderOutcome:
    status: str
    operation_id: str
    request_digest: str
    response_digest: str
    readback_digest: str
    provider_calls: int
    mode: str
    error_code: str | None = None


def describe_readback_projections() -> dict[str, dict[str, Any]]:
    return {name: {"service": item.service, "method": item.method, "fields": list(item.fields), "request_keys": sorted(item.request_keys)} for name, item in READBACK_PROJECTIONS.items()}


def _field(response: Mapping[str, Any], path: str) -> Any:
    value: Any = response
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _project(response: Mapping[str, Any], projection: ReadbackProjection) -> dict[str, Any]:
    if any(response.get(key) not in (None, "", False) for key in ("NextToken", "nextToken", "NextMarker", "IsTruncated", "Truncated")):
        _fail("READBACK_PAGINATION_INCOMPLETE")
    if _field(response, projection.fields[0]) is None:
        _fail("READBACK_ANCHOR_MISSING")
    # Missing optional fields are explicit None, never silently dropped.
    return {field: _field(response, field) for field in projection.fields}


def _safe_error(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    code = response.get("Error", {}).get("Code") if isinstance(response, Mapping) else type(exc).__name__
    return code if isinstance(code, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,95}", code) else "ProviderError"


def _packaged_model_loader() -> Any:
    """Load only installed SDK data, excluding user models and AWS_DATA_PATH."""
    import botocore
    from botocore.loaders import Loader
    return Loader(extra_search_paths=[str(Path(botocore.__file__).parent / "data")],
                  include_default_search_paths=False)


def _sdk_operation_model(service: str, api: str) -> Any:
    from botocore.model import ServiceModel
    return ServiceModel(_packaged_model_loader().load_service_model(service, "service-2")).operation_model(api)


def _validate_response_field(operation_id: str, field: Any) -> None:
    route = OPERATION_ROUTES.get(operation_id)
    if route is None or not isinstance(field, str) or field not in _RESPONSE_FIELDS:
        _fail("READBACK_RESPONSE_BINDING_INVALID")
    try:
        shape = _sdk_operation_model(route.service, route.api_name).output_shape
        for part in field.split("."):
            if shape is None or shape.type_name != "structure" or part not in shape.members:
                _fail("READBACK_RESPONSE_BINDING_INVALID")
            shape = shape.members[part]
        if shape is None or shape.type_name != "string":
            _fail("READBACK_RESPONSE_BINDING_INVALID")
    except Exception:
        _fail("READBACK_RESPONSE_BINDING_INVALID")


def _validate_sdk_request(service: str, api: str, request: Mapping[str, Any]) -> None:
    # Botocore's model loader is offline; no Session credentials/provider calls.
    try:
        from botocore.validate import validate_parameters
        validate_parameters(dict(request), _sdk_operation_model(service, api).input_shape)
    except Exception:
        _fail("SDK_REQUEST_INVALID")


class UpstreamLiveProvider:
    """One-attempt transport. AWS_TRANSPORT means transport provenance only."""

    def __init__(self, *, clients: Mapping[str, Any], expected_account_id: str,
                 expected_caller_arn: str, region: str,
                 artifact_bytes: Mapping[str, bytes] | None = None) -> None:
        self._initialize(clients, expected_account_id, expected_caller_arn, region, artifact_bytes)
        self.mode = "SYNTHETIC"
        self._factory = None
        self._live = False
        self._identity()

    def _initialize(self, clients: Mapping[str, Any], account: str, caller: str,
                    region: str, artifact_bytes: Mapping[str, bytes] | None) -> None:
        match = _CALLER.fullmatch(caller) if isinstance(caller, str) else None
        if region != REGION or account not in {"042360977644", "839393571433"} or not match or match[1] != account:
            _fail("PROVIDER_SCOPE_INVALID")
        if not isinstance(clients, Mapping) or "sts" not in clients or set(clients) - set(_ENDPOINTS):
            _fail("PROVIDER_CLIENTS_INVALID")
        self._clients = dict(clients)
        self._account = account
        self._caller = caller
        self._region = region
        self._artifacts = dict(artifact_bytes or {})
        if any(not _DIGEST.fullmatch(key) or not isinstance(value, bytes) for key, value in self._artifacts.items()):
            _fail("ARTIFACT_BINDING_INVALID")
        self._attempts: dict[str, str] = {}
        self._evidence: dict[str, dict[str, Any]] = {}
        self._polls: dict[str, int] = {}
        self._calls = 0
        self._closed = False
        self._wire_calls = 0
        self._current_wire_service: str | None = None

    @classmethod
    def from_injected_clients(cls, **kwargs: Any) -> UpstreamLiveProvider:
        return cls(**kwargs)

    @classmethod
    def open(cls, *, profile: str, expected_account_id: str, expected_caller_arn: str,
             region: str = REGION, artifact_bytes: Mapping[str, bytes] | None = None) -> UpstreamLiveProvider:
        if not isinstance(profile, str) or not _PROFILE.fullmatch(profile):
            _fail("PROVIDER_PROFILE_INVALID")
        match = _CALLER.fullmatch(expected_caller_arn) if isinstance(expected_caller_arn, str) else None
        if region != REGION or expected_account_id not in {"042360977644", "839393571433"} or not match or match[1] != expected_account_id:
            _fail("PROVIDER_SCOPE_INVALID")
        forbidden = {name for name in os.environ if name.startswith("AWS_") and name not in {"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_SDK_LOAD_CONFIG"}}
        if forbidden or any(os.environ.get(name) for name in ("BOTO_CONFIG", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")):
            _fail("PROVIDER_AMBIENT_CONFIGURATION_FORBIDDEN")
        if any(os.environ.get(name) not in (None, value) for name, value in (("AWS_PROFILE", profile), ("AWS_REGION", region), ("AWS_DEFAULT_REGION", region))):
            _fail("PROVIDER_AMBIENT_SCOPE_MISMATCH")
        try:
            import boto3
            import botocore.session
            from botocore.config import Config
            core = botocore.session.Session()
            core.register_component("data_loader", _packaged_model_loader())
            session = boto3.Session(botocore_session=core, profile_name=profile, region_name=region)
            # Inspect routing metadata before credential resolution; reject a
            # credential_process or role chain before it can execute anything.
            scoped = session._session.get_scoped_config()
            if not isinstance(scoped, Mapping) or any(key in scoped for key in (
                    "credential_process", "credential_source", "role_arn", "source_profile",
                    "web_identity_token_file", "aws_access_key_id", "aws_secret_access_key",
                    "aws_session_token", "endpoint_url", "ca_bundle", "services")):
                _fail("DIRECT_SSO_REQUIRED")
            if scoped.get("sso_account_id") != expected_account_id or not isinstance(scoped.get("sso_role_name"), str) or not (scoped.get("sso_session") or scoped.get("sso_start_url")):
                _fail("DIRECT_SSO_REQUIRED")
            credentials = session.get_credentials()
            if credentials is None or credentials.method != "sso":
                _fail("DIRECT_SSO_REQUIRED")
            # Freeze one authenticated session; no automatic credential refresh
            # may switch callers after STS validated the exact expected ARN.
            frozen = credentials.get_frozen_credentials()
            config = Config(region_name=region, retries={"mode": "standard", "total_max_attempts": 1},
                            connect_timeout=5, read_timeout=20, ignore_configured_endpoint_urls=True,
                            use_dualstack_endpoint=False, use_fips_endpoint=False,
                            proxies={}, s3={"addressing_style": "path", "us_east_1_regional_endpoint": "regional"})
            def factory(service: str) -> Any:
                return session.client(service, region_name=region, config=config, verify=True,
                                      endpoint_url="https://" + _ENDPOINTS[service],
                                      aws_access_key_id=frozen.access_key, aws_secret_access_key=frozen.secret_key,
                                      aws_session_token=frozen.token)
            provider = object.__new__(cls)
            provider._initialize({"sts": factory("sts")}, expected_account_id, expected_caller_arn, region, artifact_bytes)
            provider.mode = "AWS_TRANSPORT"
            provider._factory = factory
            provider._live = True
            provider._validate_client("sts", provider._clients["sts"])
            provider._identity()
            return provider
        except UpstreamProviderError:
            raise
        except Exception:
            _fail("PROVIDER_OPEN_FAILED")

    def _validate_client(self, service: str, client: Any) -> None:
        meta = getattr(client, "meta", None)
        config = getattr(meta, "config", None)
        retries = getattr(config, "retries", {})
        if getattr(meta, "endpoint_url", None) != "https://" + _ENDPOINTS[service] or getattr(meta, "region_name", None) != REGION:
            _fail("PROVIDER_ENDPOINT_INVALID")
        if retries.get("total_max_attempts") != 1 or retries.get("max_attempts", 0) != 0:
            _fail("PROVIDER_RETRIES_INVALID")
        if getattr(getattr(client, "_endpoint", None), "http_session", None) is None or client._endpoint.http_session._verify is not True:
            _fail("PROVIDER_TLS_INVALID")
        meta.events.register_first("before-send.*.*", self._before_send)

    def _before_send(self, request: Any, **_kwargs: Any) -> None:
        service = self._current_wire_service
        parsed = urlparse(request.url)
        if service is None or parsed.scheme != "https" or parsed.hostname != _ENDPOINTS[service] or parsed.port not in (None, 443):
            _fail("PROVIDER_REQUEST_ENDPOINT_INVALID")
        self._wire_calls += 1
        if self._wire_calls != 1:
            _fail("PROVIDER_RETRY_FORBIDDEN")

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            if not self._live or service not in _ENDPOINTS:
                _fail("PROVIDER_CLIENT_MISSING")
            client = self._factory(service)
            self._validate_client(service, client)
            self._clients[service] = client
        return self._clients[service]

    def _call(self, service: str, method: str, request: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._closed:
            _fail("PROVIDER_CLOSED")
        client = self._client(service)
        self._calls += 1
        self._wire_calls = 0
        self._current_wire_service = service
        try:
            result = getattr(client, method)(**request)
            if not isinstance(result, Mapping):
                _fail("PROVIDER_RESPONSE_INVALID")
            return _snapshot(result)
        finally:
            self._current_wire_service = None

    def _identity(self) -> None:
        try:
            value = self._call("sts", "get_caller_identity", {})
        except Exception:
            _fail("PROVIDER_IDENTITY_FAILED")
        if value.get("Account") != self._account or value.get("Arn") != self._caller:
            _fail("PROVIDER_IDENTITY_MISMATCH")
        self._identity_digest = digest({"Account": self._account, "Arn": self._caller})

    def identity(self) -> dict[str, Any]:
        return {"account_id": self._account, "region": self._region, "caller_arn_digest": digest(self._caller),
                "identity_digest": self._identity_digest, "mode": self.mode, "live_provider_evidence": False}

    def _operation(self, operation: Any) -> tuple[str, OperationRoute, dict[str, Any]]:
        identifier = _get(operation, "operation_id")
        route = OPERATION_ROUTES.get(identifier) if isinstance(identifier, str) else None
        request = _get(operation, "request")
        if not route or _get(operation, "phase") != route.phase or _get(operation, "account_id") != self._account or _get(operation, "region") != REGION:
            _fail("OPERATION_BINDING_INVALID")
        if route.service == "sso-admin" and self._account != "839393571433" or route.service != "sso-admin" and self._account != "042360977644":
            _fail("OPERATION_ACCOUNT_INVALID")
        if not isinstance(request, Mapping) or set(request) != route.request_keys:
            _fail("OPERATION_REQUEST_FIELDS_INVALID")
        private = _snapshot(request)
        if route.method in {"create_account_assignment", "provision_permission_set"} and (private.get("TargetId") != "042360977644" or private.get("TargetType") != "AWS_ACCOUNT"):
            _fail("OPERATION_TARGET_ACCOUNT_INVALID")
        if route.method == "start_signing_job" and private.get("profileOwner") != "042360977644":
            _fail("OPERATION_TARGET_ACCOUNT_INVALID")
        if _get(operation, "request_digest") != digest(private) or any(not isinstance(_get(operation, field), str) or not _DIGEST.fullmatch(_get(operation, field)) for field in ("before_state_digest", "target_state_digest")):
            _fail("OPERATION_DIGEST_INVALID")
        sdk_request = deepcopy(private)
        # Source contracts bind canonical policy objects. AWS's wire shapes
        # require JSON strings for these fields; this conversion preserves the
        # original request digest and never widens the policy.
        for policy_field in ("Policy", "InlinePolicy"):
            if isinstance(sdk_request.get(policy_field), Mapping):
                sdk_request[policy_field] = _json(sdk_request[policy_field])
        if route.method == "put_object":
            content_sha = sdk_request.pop("BodySha256")
            if not isinstance(content_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", content_sha):
                _fail("ARTIFACT_CONTENT_MISMATCH")
            content_digest = "sha256:" + content_sha
            body = self._artifacts.get(content_digest)
            if body is None or "sha256:" + sha256(body).hexdigest() != content_digest or len(body) != sdk_request.get("ContentLength") or base64.b64encode(sha256(body).digest()).decode() != sdk_request.get("ChecksumSHA256"):
                _fail("ARTIFACT_CONTENT_MISMATCH")
            sdk_request["Body"] = body
        if route.service == "s3" and route.method != "create_bucket":
            # Bind bucket ownership at AWS's wire boundary as well as the
            # externally approved source contract. Cross-account bucket policy
            # grants must never redirect this authority lane into production.
            try:
                supported = "ExpectedBucketOwner" in _sdk_operation_model(route.service, route.api_name).input_shape.members
            except Exception:
                _fail("S3_OWNER_GUARD_UNAVAILABLE")
            if not supported:
                _fail("S3_OWNER_GUARD_UNAVAILABLE")
            sdk_request["ExpectedBucketOwner"] = AUTHORITY_ACCOUNT_ID
        _validate_sdk_request(route.service, route.api_name, sdk_request)
        return identifier, route, sdk_request

    def validate_operation(self, operation: Any) -> None:
        """Offline validation before the executor acquires a durable claim."""
        operation = self._freeze_operation(operation)
        self._operation(operation)
        self._validate_readbacks(operation, after=False)
        self._validate_readbacks(operation, after=True)

    def _validate_readbacks(self, operation: Any, *, after: bool) -> tuple[Any, ...]:
        requested = _get(operation, "readbacks" if after else "before_readbacks")
        if not isinstance(requested, (list, tuple)) or not 1 <= len(requested) <= _MAX_READBACKS:
            _fail("READBACKS_REQUIRED")
        if after and _REQUIRED_AFTER[OPERATION_ROUTES[_get(operation, "operation_id")].method] not in {_get(item, "projection") for item in requested}:
            _fail("READBACK_OPERATION_PROOF_MISSING")
        for item in requested:
            name = _get(item, "projection")
            projection = READBACK_PROJECTIONS.get(name) if isinstance(name, str) else None
            request = _get(item, "request")
            expected = _get(item, "expected_projection")
            absence = isinstance(expected, Mapping) and set(expected) == {"absence"} and expected["absence"] in _ABSENCE
            if not projection or _get(item, "service") != projection.service or _get(item, "method") != projection.method or not isinstance(request, Mapping) or set(request) - projection.request_keys or not isinstance(expected, Mapping) or not (not after and absence or set(expected) == set(projection.fields)):
                _fail("READBACK_CONTRACT_INVALID")
            if after and name in _BEFORE_ONLY:
                _fail("READBACK_AFTER_SCOPE_INVALID")
            if projection.service == "sso-admin" and self._account != "839393571433" or projection.service != "sso-admin" and self._account != "042360977644":
                _fail("READBACK_ACCOUNT_INVALID")
            native_request = dict(request)
            if any(key in request and request[key] != "042360977644" for key in ("AccountId", "ExpectedBucketOwner", "profileOwner")):
                _fail("READBACK_TARGET_ACCOUNT_INVALID")
            if projection.service == "s3" and request.get("ExpectedBucketOwner") != AUTHORITY_ACCOUNT_ID:
                _fail("READBACK_TARGET_ACCOUNT_INVALID")
            for key, value in request.items():
                if isinstance(value, Mapping) and set(value) == {"response_field"}:
                    if not after:
                        _fail("READBACK_RESPONSE_BINDING_INVALID")
                    _validate_response_field(_get(operation, "operation_id"), value["response_field"])
                    # Type/required-field checks remain offline before a write.
                    # Actual generated values are validated again after binding.
                    native_request[key] = "r" * 36
            _validate_sdk_request(projection.service, projection.api_name, native_request)
            self._resolve_bindings(expected, operation_id=_get(operation, "operation_id"), after=after, validate_only=True)
        return tuple(requested)

    def _resolve_bindings(self, value: Any, *, operation_id: str, after: bool,
                          validate_only: bool = False) -> Any:
        if isinstance(value, Mapping):
            if "response_field" in value:
                field = value.get("response_field")
                if set(value) != {"response_field"} or not after:
                    _fail("READBACK_RESPONSE_BINDING_INVALID")
                _validate_response_field(operation_id, field)
                if validate_only:
                    return value
                resolved = _field(self._evidence.get(operation_id, {}).get("response", {}), field)
                if not isinstance(resolved, str) or not resolved:
                    _fail("READBACK_RESPONSE_BINDING_INVALID")
                return resolved
            return {key: self._resolve_bindings(item, operation_id=operation_id, after=after, validate_only=validate_only) for key, item in value.items()}
        if isinstance(value, list):
            return [self._resolve_bindings(item, operation_id=operation_id, after=after, validate_only=validate_only) for item in value]
        return value

    @staticmethod
    def _binding(operation: Any) -> str:
        values = {key: _get(operation, key) for key in ("operation_id", "phase", "account_id", "region", "request_digest", "before_state_digest", "target_state_digest")}
        for field in ("before_readbacks", "readbacks"):
            values[field] = [{key: _get(item, key) for key in ("service", "method", "request", "expected_projection", "projection")} for item in _get(operation, field) or ()]
        return digest(values)

    @staticmethod
    def _freeze_operation(operation: Any) -> dict[str, Any]:
        values = {key: _get(operation, key) for key in ("operation_id", "phase", "account_id", "region", "request", "request_digest", "before_state_digest", "target_state_digest")}
        for field in ("before_readbacks", "readbacks"):
            items = _get(operation, field)
            if not isinstance(items, (tuple, list)):
                _fail("READBACKS_REQUIRED")
            values[field] = [{key: _get(item, key) for key in ("service", "method", "request", "expected_projection", "projection")} for item in items]
        return _snapshot(values)

    def _readbacks(self, operation: Any, *, after: bool) -> tuple[list[dict[str, Any]], bool, str | None]:
        requested = self._validate_readbacks(operation, after=after)
        records: list[dict[str, Any]] = []
        matched = True
        terminal: str | None = None
        for item in requested:
            name = _get(item, "projection")
            projection = READBACK_PROJECTIONS.get(name) if isinstance(name, str) else None
            request = _get(item, "request")
            expected = _get(item, "expected_projection")
            assert projection is not None
            resolved: dict[str, Any] = {}
            for key, value in request.items():
                if isinstance(value, Mapping) and set(value) == {"response_field"}:
                    field = value["response_field"]
                    if not after:
                        _fail("READBACK_RESPONSE_BINDING_INVALID")
                    _validate_response_field(_get(operation, "operation_id"), field)
                    response = self._evidence.get(_get(operation, "operation_id"), {}).get("response", {})
                    value = _field(response, field)
                    if not isinstance(value, str) or not value:
                        _fail("READBACK_RESPONSE_BINDING_INVALID")
                resolved[key] = value
            _validate_sdk_request(projection.service, projection.api_name, resolved)
            try:
                response = self._call(projection.service, projection.method, resolved)
                projected = _project(response, projection)
                observed_status = _field(response, projection.terminal_field) if projection.terminal_field else None
                if observed_status is not None:
                    status = str(observed_status).upper().replace("_", "")
                    if status == "SUCCEEDED":
                        terminal = terminal or "SUCCEEDED"
                    elif status == "FAILED":
                        terminal = "FAILED"
                    elif status == "INPROGRESS":
                        if terminal != "FAILED":
                            terminal = "PENDING"
                    else:
                        terminal = "UNKNOWN"
            except UpstreamProviderError:
                raise
            except Exception as exc:
                error = _safe_error(exc)
                if error not in _ABSENCE:
                    _fail("READBACK_FAILED")
                projected = {"absence": error}
            expected = self._resolve_bindings(expected, operation_id=_get(operation, "operation_id"), after=after)
            matched = matched and projected == _snapshot(expected)
            records.append({"projection": name, "request_digest": digest(resolved), "projection_value": projected})
        return records, matched, terminal

    def observe(self, operation: Any) -> Observation:
        operation = self._freeze_operation(operation)
        identifier, _route, _request = self._operation(operation)
        calls = self._calls
        records, _matched, _terminal = self._readbacks(operation, after=False)
        self._evidence[identifier] = {"before": records}
        return Observation("OBSERVED", digest(records), self._calls - calls, self.mode)

    def dispatch_once(self, operation: Any, *, before_mutation: Callable[[], None] | None = None) -> ProviderOutcome:
        operation = self._freeze_operation(operation)
        identifier, route, request = self._operation(operation)
        binding = self._binding(operation)
        if identifier in self._attempts:
            _fail("OPERATION_ATTEMPT_CONSUMED")
        self._validate_readbacks(operation, after=False)
        self._validate_readbacks(operation, after=True)
        calls = self._calls
        self._identity()
        # Open/validate the transport before the executor's final time-sensitive
        # gate, so no SDK setup or identity operation separates it from dispatch.
        self._client(route.service)
        self._attempts[identifier] = binding
        if before_mutation is not None:
            if not callable(before_mutation):
                _fail("PRE_MUTATION_GATE_INVALID")
            try:
                before_mutation()
            except Exception:
                _fail("PRE_MUTATION_GATE_REJECTED")
        try:
            response = self._call(route.service, route.method, request)
            self._evidence.setdefault(identifier, {})["response"] = response
        except Exception as exc:
            error = _safe_error(exc)
            status = "FAILED" if error in _NO_EFFECT else "AMBIGUOUS"
            return ProviderOutcome(status, identifier, _get(operation, "request_digest"), digest({"error_code": error}), digest([]), self._calls - calls, self.mode, "PROVIDER_MUTATION_FAILED" if status == "FAILED" else "PROVIDER_MUTATION_AMBIGUOUS")
        return self._outcome(operation, response, calls)

    def _outcome(self, operation: Any, response: Mapping[str, Any], calls: int) -> ProviderOutcome:
        identifier = _get(operation, "operation_id")
        try:
            records, matched, terminal = self._readbacks(operation, after=True)
            self._evidence[identifier]["after"] = records
            async_method = OPERATION_ROUTES[identifier].method in {"create_account_assignment", "provision_permission_set", "start_signing_job"}
            if terminal == "FAILED":
                status = "FAILED"
            elif terminal == "PENDING":
                status = "PENDING"
            elif terminal == "UNKNOWN" or async_method and terminal != "SUCCEEDED":
                status = "AMBIGUOUS"
            else:
                status = "SUCCEEDED" if matched else "AMBIGUOUS"
            return ProviderOutcome(status, identifier, _get(operation, "request_digest"), digest(response), digest(records), self._calls - calls, self.mode, None if status in {"SUCCEEDED", "PENDING"} else "READBACK_NOT_PROVEN")
        except Exception:
            return ProviderOutcome("AMBIGUOUS", identifier, _get(operation, "request_digest"), digest(response), digest([]), self._calls - calls, self.mode, "READBACK_NOT_PROVEN")

    def poll_readbacks(self, operation: Any) -> ProviderOutcome:
        operation = self._freeze_operation(operation)
        identifier, _route, _request = self._operation(operation)
        if identifier not in self._attempts or "response" not in self._evidence.get(identifier, {}):
            _fail("READBACK_ATTEMPT_MISSING")
        if self._binding(operation) != self._attempts[identifier]:
            _fail("READBACK_ATTEMPT_BINDING_MISMATCH")
        count = self._polls.get(identifier, 0)
        if count >= _MAX_POLLS:
            _fail("READBACK_POLL_LIMIT")
        self._polls[identifier] = count + 1
        return self._outcome(operation, self._evidence[identifier]["response"], self._calls)

    def private_evidence(self, operation_id: str) -> dict[str, Any]:
        """Detached private facts for an independent verifier; never a receipt."""
        if operation_id not in self._evidence:
            _fail("PRIVATE_EVIDENCE_MISSING")
        return _snapshot(self._evidence[operation_id])

    def close(self) -> None:
        """Close SDK HTTP clients; this neither revokes nor logs out of SSO."""
        failed = False
        for client in self._clients.values():
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    failed = True
        self._closed = True
        self._factory = None
        self._clients.clear()
        self._artifacts.clear()
        if failed:
            _fail("PROVIDER_CLOSE_FAILED")
