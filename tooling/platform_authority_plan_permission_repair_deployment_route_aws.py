"""Connected one-shot provider for the two initial GUG-376 seed stacks.

The provider never polls and never retries a mutation.  A durable O_EXCL claim
is created before each CreateChangeSet or ExecuteChangeSet call.  Read-only
attestation and terminal-readback operations are separate commands.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from tooling import platform_authority_plan_permission_repair_deployment_route as route


DISPATCH_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_create_dispatch.v1"
)
EXECUTION_RECEIPT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_execute_dispatch.v1"
)
TERMINAL_RECEIPT_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_terminal_readback.v1"
)
CLAIM_RECORD_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_seed_provider_claim.v1"
)

_DISPATCH_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "intent_digest",
        "create_request_digest",
        "creation_authorization",
        "creation_authorization_digest",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "dispatched_at",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "dispatch_digest",
    }
)
_EXECUTION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_intent_digest",
        "stack_arn",
        "change_set_arn",
        "execute_request_id",
        "dispatched_at",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "receipt_digest",
    }
)
_TERMINAL_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "account_id",
        "execution_receipt_digest",
        "execute_cloudtrail_event_digest",
        "stack_arn",
        "stack_status",
        "template_digest",
        "resource_count",
        "resources_digest",
        "outputs_digest",
        "assignment_count",
        "assignments_digest",
        "live_property_read_count",
        "live_properties_digest",
        "read_at",
        "aws_calls",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
        "readback_digest",
    }
)
_CREATE_ATTESTATION_IMMUTABLE_FIELDS = frozenset(
    {
        "schema_version",
        "record_type",
        "source_commit",
        "target",
        "intent_digest",
        "create_request_digest",
        "account_id",
        "stack_arn",
        "change_set_arn",
        "create_request_id",
        "cloudtrail_event_digest",
        "describe_change_set_digest",
        "template_digest",
        "changes_digest",
        "status",
        "execution_status",
        "aws_mutations",
        "retry_permitted",
        "production_authorized",
        "production_status",
    }
)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LAMBDA_RUNTIME_VERSION_ARN_RE = re.compile(
    r"^arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}$"
)
_EXPECTED_SSO_PROFILES = {
    "839393571433_AWSAdministratorAccess": (
        route.MANAGEMENT_ACCOUNT_ID,
        "AWSAdministratorAccess",
    ),
    "042360977644_ScanalyzeGug376BrokerSeedCreator": (
        route.AUTHORITY_ACCOUNT_ID,
        "ScanalyzeGug376BrokerSeedCreator",
    ),
    "042360977644_ScanalyzeGug376BrokerSeedExec": (
        route.AUTHORITY_ACCOUNT_ID,
        "ScanalyzeGug376BrokerSeedExec",
    ),
}
_PROFILE_CONFIGURATION_KEYS = frozenset(
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
_SSO_SESSION_CONFIGURATION_KEYS = frozenset(
    {"sso_region", "sso_registration_scopes", "sso_start_url"}
)
_AMBIENT_AWS_FORBIDDEN = frozenset(
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


class ConnectedRouteError(RuntimeError):
    def __init__(self, code: str, *, uncertain: bool = False) -> None:
        self.code = code
        self.uncertain = uncertain
        super().__init__(f"GUG376_CONNECTED_SEED_BLOCKED:{code}")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConnectedRouteError("CLOCK_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_time(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ConnectedRouteError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ConnectedRouteError(code) from exc
    if parsed.microsecond:
        raise ConnectedRouteError(code)
    return parsed


def _change_set_parameters_match(
    observed: object,
    requested: object,
    *,
    target: str,
) -> bool:
    """Require exact authoritative values for every route parameter."""

    if observed is None:
        observed = []
    if requested is None:
        requested = []
    if (
        target not in route.TARGETS
        or not isinstance(observed, list)
        or not isinstance(requested, list)
    ):
        return False
    if len(observed) != len(requested):
        return False
    observed_by_key: dict[str, Mapping[str, Any]] = {}
    for item in observed:
        if (
            not isinstance(item, Mapping)
            or set(item).difference(
                {
                    "ParameterKey",
                    "ParameterValue",
                    "UsePreviousValue",
                    "ResolvedValue",
                }
            )
            or not isinstance(item.get("ParameterKey"), str)
            or item["ParameterKey"] in observed_by_key
            or item.get("UsePreviousValue") not in (None, False)
            or item.get("ResolvedValue") is not None
        ):
            return False
        observed_by_key[item["ParameterKey"]] = item
    if len(observed_by_key) != len(requested):
        return False
    for item in requested:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"ParameterKey", "ParameterValue"}
            or not isinstance(item.get("ParameterKey"), str)
            or not isinstance(item.get("ParameterValue"), str)
        ):
            return False
        current = observed_by_key.get(item["ParameterKey"])
        if current is None:
            return False
        if current.get("ParameterValue") != item["ParameterValue"]:
            return False
    return True


def _require_lambda_resource_policy_absent(
    lambda_client: Any, *, function_name: str, qualifier: str | None = None
) -> None:
    request = {"FunctionName": function_name}
    if qualifier is not None:
        request["Qualifier"] = qualifier
    try:
        lambda_client.get_policy(**request)
    except Exception as exc:
        response = getattr(exc, "response", None)
        error = response.get("Error") if isinstance(response, Mapping) else None
        metadata = (
            response.get("ResponseMetadata")
            if isinstance(response, Mapping)
            else None
        )
        if (
            isinstance(error, Mapping)
            and error.get("Code") == "ResourceNotFoundException"
            and isinstance(metadata, Mapping)
            and metadata.get("HTTPStatusCode") == 404
        ):
            return
        raise ConnectedRouteError(
            "BROKER_FUNCTION_INVOCATION_AUTHORITY_INVALID"
        ) from exc
    raise ConnectedRouteError("BROKER_FUNCTION_INVOCATION_AUTHORITY_INVALID")


def _lookup_cloudtrail_events(
    client: Any,
    *,
    request: Mapping[str, Any],
    error_code: str,
) -> tuple[list[Mapping[str, Any]], int]:
    """Read a bounded CloudTrail result set without treating page one as complete."""

    events: list[Mapping[str, Any]] = []
    seen_tokens: set[str] = set()
    next_token: str | None = None
    for page_number in range(1, 101):
        page_request = dict(request)
        if next_token is not None:
            page_request["NextToken"] = next_token
        try:
            response = client.lookup_events(**page_request)
        except Exception as exc:
            raise ConnectedRouteError(error_code) from exc
        raw_events = response.get("Events") if isinstance(response, Mapping) else None
        if not isinstance(raw_events, list) or any(
            not isinstance(item, Mapping) for item in raw_events
        ):
            raise ConnectedRouteError(error_code)
        events.extend(raw_events)
        token = response.get("NextToken")
        if token is None:
            return events, page_number
        if (
            not isinstance(token, str)
            or not token
            or token in seen_tokens
            or page_number == 100
        ):
            raise ConnectedRouteError(error_code)
        seen_tokens.add(token)
        next_token = token
    raise ConnectedRouteError(error_code)


def _resolve_cloudformation_value(
    value: object, *, parameters: Mapping[str, str]
) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"Ref"}:
            name = value["Ref"]
            if not isinstance(name, str) or name not in parameters:
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            return parameters[name]
        if set(value) == {"Fn::Sub"}:
            raw = value["Fn::Sub"]
            substitutions: dict[str, str] = {}
            if isinstance(raw, str):
                template = raw
            elif (
                isinstance(raw, list)
                and len(raw) == 2
                and isinstance(raw[0], str)
                and isinstance(raw[1], Mapping)
            ):
                template = raw[0]
                variables = raw[1]
                for name, child in variables.items():
                    if (
                        not isinstance(name, str)
                        or re.fullmatch(r"[A-Za-z0-9_.:-]+", name) is None
                        or name in parameters
                    ):
                        raise ConnectedRouteError(
                            "ROUTE_PERMISSION_SET_CONTRACT_INVALID"
                        )
                    resolved = _resolve_cloudformation_value(
                        child, parameters=parameters
                    )
                    if not isinstance(resolved, str):
                        raise ConnectedRouteError(
                            "ROUTE_PERMISSION_SET_CONTRACT_INVALID"
                        )
                    substitutions[name] = resolved
            else:
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")

            names = re.findall(r"\$\{([^}]+)\}", template)
            if (
                any(re.fullmatch(r"[A-Za-z0-9_.:-]+", name) is None for name in names)
                or any(name not in names for name in substitutions)
            ):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")

            def replace(match: re.Match[str]) -> str:
                name = match.group(1)
                if name in substitutions:
                    return substitutions[name]
                if name not in parameters:
                    raise ConnectedRouteError(
                        "ROUTE_PERMISSION_SET_CONTRACT_INVALID"
                    )
                return parameters[name]

            rendered = re.sub(r"\$\{([^}]+)\}", replace, template)
            if "${" in rendered:
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            return rendered
        if set(value) == {"Fn::Join"}:
            raw = value["Fn::Join"]
            if not isinstance(raw, list) or len(raw) != 2 or not isinstance(
                raw[0], str
            ):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            items = _resolve_cloudformation_value(raw[1], parameters=parameters)
            if not isinstance(items, list) or any(
                not isinstance(item, str) for item in items
            ):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            return raw[0].join(items)
        if set(value) == {"Fn::Split"}:
            raw = value["Fn::Split"]
            if not isinstance(raw, list) or len(raw) != 2 or not isinstance(
                raw[0], str
            ):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            source = _resolve_cloudformation_value(raw[1], parameters=parameters)
            if not isinstance(source, str):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            return source.split(raw[0])
        if set(value) == {"Fn::Select"}:
            raw = value["Fn::Select"]
            if (
                not isinstance(raw, list)
                or len(raw) != 2
                or type(raw[0]) is not int
            ):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            items = _resolve_cloudformation_value(raw[1], parameters=parameters)
            if not isinstance(items, list) or not 0 <= raw[0] < len(items):
                raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
            return items[raw[0]]
        if any(key == "Ref" or str(key).startswith("Fn::") for key in value):
            raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
        return {
            str(key): _resolve_cloudformation_value(child, parameters=parameters)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            _resolve_cloudformation_value(child, parameters=parameters)
            for child in value
        ]
    if value is None or isinstance(value, (bool, int, str)):
        return value
    raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")


def _route_permission_set_contracts(
    *,
    template_body: str,
    create_parameters: list[Mapping[str, Any]],
    outputs: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    try:
        from tooling.platform_authority_plan_permission_repair_broker_seed import (
            BrokerSeedError,
            _load_rendered_yaml,
            canonicalize_policy_document,
        )

        template = _load_rendered_yaml(template_body.encode("utf-8"))
    except (ImportError, BrokerSeedError) as exc:
        raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID") from exc
    parameter_values = {
        str(item.get("ParameterKey")): str(item.get("ParameterValue"))
        for item in create_parameters
        if isinstance(item, Mapping)
    }
    parameter_values.update(
        {
            "AWS::Partition": "aws",
            "AWS::Region": route.REGION,
            "AWS::AccountId": route.MANAGEMENT_ACCOUNT_ID,
        }
    )
    resources = template.get("Resources")
    if not isinstance(resources, Mapping):
        raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
    logical_by_output = {
        "BrokerSeedCreatorPermissionSetArn": "BrokerSeedCreatorPermissionSet",
        "BrokerSeedExecutorPermissionSetArn": "BrokerSeedExecutorPermissionSet",
        "BrokerInvokerPermissionSetArn": "BrokerInvokerPermissionSet",
    }
    contracts: dict[str, dict[str, Any]] = {}
    for output_key, logical_id in logical_by_output.items():
        resource = resources.get(logical_id)
        properties = resource.get("Properties") if isinstance(resource, Mapping) else None
        if (
            not isinstance(resource, Mapping)
            or resource.get("Type") != "AWS::SSO::PermissionSet"
            or not isinstance(properties, Mapping)
            or output_key not in outputs
        ):
            raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
        resolved = _resolve_cloudformation_value(
            properties, parameters=parameter_values
        )
        try:
            inline_policy = canonicalize_policy_document(resolved["InlinePolicy"])
        except (KeyError, BrokerSeedError) as exc:
            raise ConnectedRouteError(
                "ROUTE_PERMISSION_SET_CONTRACT_INVALID"
            ) from exc
        if set(resolved) != {
            "InstanceArn",
            "Name",
            "SessionDuration",
            "InlinePolicy",
            "Tags",
        }:
            raise ConnectedRouteError("ROUTE_PERMISSION_SET_CONTRACT_INVALID")
        contracts[output_key] = {
            "permission_set_arn": outputs[output_key],
            "instance_arn": resolved["InstanceArn"],
            "name": resolved["Name"],
            "session_duration": resolved["SessionDuration"],
            "inline_policy": inline_policy,
            "tags": sorted(resolved["Tags"], key=lambda item: item["Key"]),
        }
    return contracts


def _paginate_items(
    method: Any,
    *,
    request: Mapping[str, Any],
    item_key: str,
    error_code: str,
) -> tuple[list[Any], int]:
    items: list[Any] = []
    seen: set[str] = set()
    token: str | None = None
    for page_number in range(1, 101):
        page_request = dict(request)
        if token is not None:
            page_request["NextToken"] = token
        try:
            response = method(**page_request)
        except Exception as exc:
            raise ConnectedRouteError(error_code) from exc
        page = response.get(item_key) if isinstance(response, Mapping) else None
        if not isinstance(page, list):
            raise ConnectedRouteError(error_code)
        items.extend(page)
        next_token = response.get("NextToken")
        if next_token is None:
            return items, page_number
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
            or page_number == 100
        ):
            raise ConnectedRouteError(error_code)
        seen.add(next_token)
        token = next_token
    raise ConnectedRouteError(error_code)


def _paginate_tokenized_items(
    method: Any,
    *,
    request: Mapping[str, Any],
    item_key: str,
    request_token_key: str,
    response_token_key: str,
    error_code: str,
    truncated_key: str | None = None,
) -> tuple[list[Any], int]:
    items: list[Any] = []
    seen: set[str] = set()
    token: str | None = None
    for page_number in range(1, 101):
        page_request = dict(request)
        if token is not None:
            page_request[request_token_key] = token
        try:
            response = method(**page_request)
        except Exception as exc:
            raise ConnectedRouteError(error_code) from exc
        if not isinstance(response, Mapping):
            raise ConnectedRouteError(error_code)
        page = response.get(item_key)
        if not isinstance(page, list):
            raise ConnectedRouteError(error_code)
        items.extend(page)
        next_token = response.get(response_token_key)
        if truncated_key is not None:
            truncated = response.get(truncated_key)
            if type(truncated) is not bool or truncated is not (next_token is not None):
                raise ConnectedRouteError(error_code)
        if next_token is None:
            return items, page_number
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen
            or page_number == 100
        ):
            raise ConnectedRouteError(error_code)
        seen.add(next_token)
        token = next_token
    raise ConnectedRouteError(error_code)


def validate_aws_environment(
    *,
    expected_profile: str,
    environment: Mapping[str, str] | None = None,
) -> None:
    """Reject credential, endpoint, proxy, CA, profile, and region drift."""

    values = os.environ if environment is None else environment
    if expected_profile not in _EXPECTED_SSO_PROFILES:
        raise ConnectedRouteError("AWS_PROFILE_INVALID")
    if any(values.get(key) for key in _AMBIENT_AWS_FORBIDDEN) or any(
        value
        and (key == "AWS_ENDPOINT_URL" or key.startswith("AWS_ENDPOINT_URL_"))
        for key, value in values.items()
    ):
        raise ConnectedRouteError("AMBIENT_AWS_CONFIGURATION_FORBIDDEN")
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if values.get(key) not in {None, "", expected_profile}:
            raise ConnectedRouteError("AMBIENT_PROFILE_INVALID")
    for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if values.get(key) not in {None, "", route.REGION}:
            raise ConnectedRouteError("AMBIENT_REGION_INVALID")


def _validate_sso_start_url(value: object) -> None:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or re.fullmatch(
            r"[a-z0-9-]+\.awsapps\.com(?:\.cn)?",
            str(parsed.hostname or ""),
        )
        is None
    ):
        raise ConnectedRouteError("AWS_SSO_CONFIGURATION_INVALID")


def validate_aws_session(
    session: Any, *, expected_profile: str
) -> None:
    """Require one exact direct SSO profile and its selected session."""

    expected = _EXPECTED_SSO_PROFILES.get(expected_profile)
    if (
        expected is None
        or getattr(session, "profile_name", None) != expected_profile
        or getattr(session, "region_name", None) != route.REGION
    ):
        raise ConnectedRouteError("AWS_SESSION_INVALID")
    internal = getattr(session, "_session", None)
    full_config = getattr(internal, "full_config", None)
    profiles = (
        full_config.get("profiles")
        if isinstance(full_config, Mapping)
        else None
    )
    document = (
        profiles.get(expected_profile)
        if isinstance(profiles, Mapping)
        else None
    )
    expected_account, expected_role = expected
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(_PROFILE_CONFIGURATION_KEYS)
        or document.get("region") != route.REGION
        or document.get("sso_account_id") != expected_account
        or document.get("sso_role_name") != expected_role
    ):
        raise ConnectedRouteError("AWS_SSO_CONFIGURATION_INVALID")
    sso_session_name = document.get("sso_session")
    if sso_session_name is None:
        if document.get("sso_region") != route.REGION:
            raise ConnectedRouteError("AWS_SSO_CONFIGURATION_INVALID")
        _validate_sso_start_url(document.get("sso_start_url"))
    else:
        sso_sessions = (
            full_config.get("sso_sessions")
            if isinstance(full_config, Mapping)
            else None
        )
        sso_document = (
            sso_sessions.get(sso_session_name)
            if isinstance(sso_session_name, str)
            and isinstance(sso_sessions, Mapping)
            else None
        )
        if (
            not isinstance(sso_document, Mapping)
            or not set(sso_document).issubset(
                _SSO_SESSION_CONFIGURATION_KEYS
            )
            or sso_document.get("sso_region") != route.REGION
            or document.get("sso_region") is not None
            or document.get("sso_start_url") is not None
        ):
            raise ConnectedRouteError("AWS_SSO_CONFIGURATION_INVALID")
        _validate_sso_start_url(sso_document.get("sso_start_url"))
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise ConnectedRouteError("AWS_SSO_CREDENTIALS_UNAVAILABLE") from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        raise ConnectedRouteError("AWS_CREDENTIAL_SOURCE_INVALID")


def sdk_client_config(config_type: Any) -> Any:
    return config_type(
        connect_timeout=3,
        read_timeout=8,
        retries={"total_max_attempts": 1, "mode": "standard"},
        ignore_configured_endpoint_urls=True,
    )


def _client(session: Any, service: str, config: Any) -> Any:
    client = session.client(service, region_name=route.REGION, config=config)
    metadata = getattr(client, "meta", None)
    endpoint = getattr(metadata, "endpoint_url", None)
    parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
    expected_host = {
        "sts": f"sts.{route.REGION}.amazonaws.com",
        "cloudformation": f"cloudformation.{route.REGION}.amazonaws.com",
        "cloudtrail": f"cloudtrail.{route.REGION}.amazonaws.com",
        "sso-admin": f"sso.{route.REGION}.amazonaws.com",
        "lambda": f"lambda.{route.REGION}.amazonaws.com",
        "iam": "iam.amazonaws.com",
        "dynamodb": f"dynamodb.{route.REGION}.amazonaws.com",
        "kms": f"kms.{route.REGION}.amazonaws.com",
        "logs": f"logs.{route.REGION}.amazonaws.com",
    }.get(service)
    expected_region = "aws-global" if service == "iam" else route.REGION
    if (
        metadata is None
        or getattr(metadata, "region_name", None) != expected_region
        or parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConnectedRouteError("AWS_CLIENT_BOUNDARY_INVALID")
    return client


def clients_from_session(
    session: Any,
    config_type: Any,
    *,
    expected_profile: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    validate_aws_environment(
        expected_profile=expected_profile,
        environment=environment,
    )
    validate_aws_session(session, expected_profile=expected_profile)
    config = sdk_client_config(config_type)
    return {
        "sts": _client(session, "sts", config),
        "cloudformation": _client(session, "cloudformation", config),
        "cloudtrail": _client(session, "cloudtrail", config),
        "sso-admin": _client(session, "sso-admin", config),
        "lambda": _client(session, "lambda", config),
        "iam": _client(session, "iam", config),
        "dynamodb": _client(session, "dynamodb", config),
        "kms": _client(session, "kms", config),
        "logs": _client(session, "logs", config),
    }


class OExclClaimStore:
    def __init__(
        self,
        root: Path,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        candidate = Path(os.path.abspath(os.path.expanduser(os.fspath(root))))
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise ConnectedRouteError("CLAIM_ROOT_INVALID") from exc
        if (
            resolved != candidate
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ConnectedRouteError("CLAIM_ROOT_INVALID")
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if nofollow is None or directory is None:
            raise ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
        try:
            descriptor = os.open(
                candidate,
                os.O_RDONLY | nofollow | directory,
            )
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise ConnectedRouteError("CLAIM_ROOT_INVALID") from exc
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise ConnectedRouteError("CLAIM_ROOT_INVALID")
        if expected_root_identity is not None and (
            opened.st_dev,
            opened.st_ino,
        ) != expected_root_identity:
            os.close(descriptor)
            raise ConnectedRouteError("CLAIM_ROOT_CHANGED")
        self._root = candidate
        self._root_device = opened.st_dev
        self._root_inode = opened.st_ino
        self._directory = descriptor

    def _assert_root_unchanged(self) -> None:
        try:
            current = self._root.lstat()
            opened = os.fstat(self._directory)
        except OSError as exc:
            raise ConnectedRouteError("CLAIM_ROOT_CHANGED") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or current.st_dev != self._root_device
            or current.st_ino != self._root_inode
            or current.st_uid != os.geteuid()
            or stat.S_IMODE(current.st_mode) != 0o700
            or opened.st_dev != self._root_device
            or opened.st_ino != self._root_inode
            or not stat.S_ISDIR(opened.st_mode)
        ):
            raise ConnectedRouteError("CLAIM_ROOT_CHANGED")

    def close(self) -> None:
        descriptor = getattr(self, "_directory", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._directory = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @staticmethod
    def _name(key: str, suffix: str) -> str:
        digest = route.bytes_digest(key.encode("utf-8")).removeprefix("sha256:")
        return f"{digest}.{suffix}.json"

    @staticmethod
    def _payload(record: Mapping[str, Any]) -> bytes:
        return (route.canonical_json(record) + "\n").encode("utf-8")

    @staticmethod
    def _write_exclusive(
        root_descriptor: int,
        *,
        name: str,
        payload: bytes,
        exists_code: str,
        write_code: str,
    ) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
                dir_fd=root_descriptor,
            )
        except FileExistsError as exc:
            raise ConnectedRouteError(exists_code) from exc
        except OSError as exc:
            raise ConnectedRouteError(write_code) from exc
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise ConnectedRouteError(write_code)
                remaining = remaining[written:]
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != len(payload)
            ):
                raise ConnectedRouteError(write_code)
        finally:
            os.close(descriptor)
        # Durability includes the directory entry, not only the file payload.
        os.fsync(root_descriptor)

    @staticmethod
    def _read_exact(root_descriptor: int, *, name: str, code: str) -> bytes:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | nofollow,
                dir_fd=root_descriptor,
            )
        except OSError as exc:
            raise ConnectedRouteError(code) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or not 0 < metadata.st_size <= 16 * 1024 * 1024
            ):
                raise ConnectedRouteError(code)
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    raise ConnectedRouteError(code)
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(payload) != metadata.st_size
                or (after.st_dev, after.st_ino, after.st_size)
                != (metadata.st_dev, metadata.st_ino, metadata.st_size)
            ):
                raise ConnectedRouteError(code)
            return payload
        finally:
            os.close(descriptor)

    def claim(self, key: str, record: Mapping[str, Any]) -> None:
        self._assert_root_unchanged()
        self._write_exclusive(
            self._directory,
            name=self._name(key, "claim"),
            payload=self._payload(record),
            exists_code="MUTATION_REPLAY_REJECTED",
            write_code="CLAIM_WRITE_FAILED",
        )
        self._assert_root_unchanged()

    def complete(self, key: str, record: Mapping[str, Any]) -> None:
        """Durably bind one provider result to its already persisted claim."""

        self._assert_root_unchanged()
        payload = self._payload(record)
        self._read_exact(
            self._directory,
            name=self._name(key, "claim"),
            code="MUTATION_CLAIM_MISSING",
        )
        try:
            self._write_exclusive(
                self._directory,
                name=self._name(key, "result"),
                payload=payload,
                exists_code="MUTATION_RESULT_EXISTS",
                write_code="MUTATION_RESULT_WRITE_FAILED",
            )
        except ConnectedRouteError as exc:
            if exc.code != "MUTATION_RESULT_EXISTS":
                raise
            existing = self._read_exact(
                self._directory,
                name=self._name(key, "result"),
                code="MUTATION_RESULT_INVALID",
            )
            if existing != payload:
                raise ConnectedRouteError("MUTATION_RESULT_MISMATCH") from exc
        self._assert_root_unchanged()

    def read_claim(self, key: str) -> dict[str, Any]:
        self._assert_root_unchanged()
        payload = self._read_exact(
            self._directory,
            name=self._name(key, "claim"),
            code="MUTATION_CLAIM_MISSING",
        )
        self._assert_root_unchanged()
        try:
            value = _strict_json_mapping(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConnectedRouteError("MUTATION_CLAIM_INVALID") from exc
        if payload != self._payload(value):
            raise ConnectedRouteError("MUTATION_CLAIM_INVALID")
        return dict(value)

    def read_result(self, key: str) -> dict[str, Any]:
        """Read the immutable result paired with an existing mutation claim."""

        self._assert_root_unchanged()
        self._read_exact(
            self._directory,
            name=self._name(key, "claim"),
            code="MUTATION_CLAIM_MISSING",
        )
        payload = self._read_exact(
            self._directory,
            name=self._name(key, "result"),
            code="MUTATION_RESULT_MISSING",
        )
        self._assert_root_unchanged()
        try:
            value = _strict_json_mapping(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConnectedRouteError("MUTATION_RESULT_INVALID") from exc
        if payload != self._payload(value):
            raise ConnectedRouteError("MUTATION_RESULT_INVALID")
        return dict(value)


def _role_pattern(*, target: str, phase: str) -> tuple[str, re.Pattern[str]]:
    if target == "route":
        account = route.MANAGEMENT_ACCOUNT_ID
        role = r"AWSReservedSSO_AWSAdministratorAccess_[0-9A-Fa-f]{16}"
    elif target in {"broker", route.BROKER_PROTECTION_TARGET} and phase == "creator":
        account = route.AUTHORITY_ACCOUNT_ID
        role = r"AWSReservedSSO_ScanalyzeGug376BrokerSeedCreator_[0-9A-Fa-f]{16}"
    elif target in {"broker", route.BROKER_PROTECTION_TARGET} and phase == "executor":
        account = route.AUTHORITY_ACCOUNT_ID
        role = r"AWSReservedSSO_ScanalyzeGug376BrokerSeedExec_[0-9A-Fa-f]{16}"
    else:
        raise ConnectedRouteError("TARGET_PHASE_INVALID")
    return account, re.compile(
        rf"^arn:aws:sts::{account}:assumed-role/{role}/[^/]+$"
    )


def _verify_identity(
    sts: Any, *, target: str, phase: str
) -> tuple[str, str]:
    # This must be the first provider API call in every public operation.
    response = sts.get_caller_identity()
    account, pattern = _role_pattern(target=target, phase=phase)
    arn = response.get("Arn") if isinstance(response, Mapping) else None
    if (
        not isinstance(response, Mapping)
        or response.get("Account") != account
        or not isinstance(response.get("UserId"), str)
        or not response.get("UserId")
        or not isinstance(arn, str)
        or pattern.fullmatch(arn) is None
    ):
        raise ConnectedRouteError("STS_IDENTITY_INVALID")
    return account, arn


def _window(intent: Mapping[str, Any], clock: Callable[[], datetime]) -> datetime:
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ConnectedRouteError("CLOCK_INVALID")
    normalized = now.astimezone(timezone.utc).replace(microsecond=0)
    admission_not_after = _parse_time(
        intent["route_not_after"], "WINDOW_INVALID"
    ) - timedelta(seconds=route.MUTATION_COMPLETION_RESERVE_SECONDS)
    if not _parse_time(
        intent["route_not_before"], "WINDOW_INVALID"
    ) <= normalized < admission_not_after:
        raise ConnectedRouteError("ROUTE_WINDOW_CLOSED")
    return normalized


def _recovery_window(
    intent: Mapping[str, Any], clock: Callable[[], datetime]
) -> datetime:
    """Allow a bounded read-only recovery after the mutation window closes."""

    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ConnectedRouteError("CLOCK_INVALID")
    normalized = now.astimezone(timezone.utc).replace(microsecond=0)
    not_before = _parse_time(intent["route_not_before"], "WINDOW_INVALID")
    recovery_not_after = _parse_time(
        intent["recovery_not_after"], "WINDOW_INVALID"
    )
    if not not_before <= normalized < recovery_not_after:
        raise ConnectedRouteError("RECOVERY_WINDOW_CLOSED")
    return normalized


def _active_creation_time(
    *,
    intent: Mapping[str, Any],
    target: str,
    authorization: Mapping[str, Any],
    clock: Callable[[], datetime],
) -> datetime:
    now = _window(intent, clock)
    try:
        route.validate_creation_authorization(
            authorization,
            seed_intent=intent,
            target=target,
            now=now,
        )
    except route.RouteSeedError as exc:
        raise ConnectedRouteError(exc.code) from exc
    return now


def _active_execution_time(
    *,
    intent: Mapping[str, Any],
    create_attestation: Mapping[str, Any],
    authorization: Mapping[str, Any],
    clock: Callable[[], datetime],
) -> datetime:
    now = _window(intent, clock)
    try:
        route.validate_execution_authorization(
            authorization,
            seed_intent=intent,
            create_attestation=create_attestation,
            now=now,
        )
    except route.RouteSeedError as exc:
        raise ConnectedRouteError(exc.code) from exc
    return now


def _provider_ids(
    response: Mapping[str, Any], *, target_spec: Mapping[str, Any]
) -> tuple[str, str, str]:
    change_set_arn = response.get("Id")
    stack_arn = response.get("StackId")
    request_id = (response.get("ResponseMetadata") or {}).get("RequestId")
    try:
        route._full_arn(
            change_set_arn,
            account_id=target_spec["account_id"],
            kind="changeSet",
            name=target_spec["change_set_name"],
        )
        route._full_arn(
            stack_arn,
            account_id=target_spec["account_id"],
            kind="stack",
            name=target_spec["stack_name"],
        )
    except route.RouteSeedError as exc:
        raise ConnectedRouteError("CREATE_RESPONSE_UNCERTAIN", uncertain=True) from exc
    if not isinstance(request_id, str) or _UUID_RE.fullmatch(request_id) is None:
        raise ConnectedRouteError("CREATE_RESPONSE_UNCERTAIN", uncertain=True)
    return str(change_set_arn), str(stack_arn), request_id


def _create_cloudtrail_params(request: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "stackName": request["StackName"],
        "changeSetName": request["ChangeSetName"],
        "changeSetType": request["ChangeSetType"],
        "description": request["Description"],
        "templateURL": request["TemplateURL"],
        "capabilities": request["Capabilities"],
        "tags": [
            {"key": item["Key"], "value": item["Value"]}
            for item in request["Tags"]
        ],
        "includeNestedStacks": False,
        "notificationARNs": [],
        "rollbackConfiguration": {
            "rollbackTriggers": [],
            "monitoringTimeInMinutes": 0,
        },
        "clientToken": request["ClientToken"],
    }
    if "Parameters" in request:
        result["parameters"] = [
            {"parameterKey": item["ParameterKey"]}
            for item in request["Parameters"]
        ]
    if "OnStackFailure" in request:
        result["onStackFailure"] = request["OnStackFailure"]
    return result


def validate_dispatch(
    value: Mapping[str, Any], *, seed_intent: Mapping[str, Any]
) -> dict[str, Any]:
    intent = route.validate_seed_intent(seed_intent)
    if not isinstance(value, Mapping) or set(value) != _DISPATCH_FIELDS:
        raise ConnectedRouteError("DISPATCH_FIELDS_INVALID")
    try:
        route._verify_seal(value, "dispatch_digest", "DISPATCH_DIGEST_INVALID")
    except route.RouteSeedError as exc:
        raise ConnectedRouteError(exc.code) from exc
    target = value.get("target")
    if target not in route.TARGETS:
        raise ConnectedRouteError("DISPATCH_INVALID")
    spec = intent["targets"][target]
    try:
        dispatched_at = _parse_time(
            value.get("dispatched_at"), "DISPATCH_INVALID"
        )
        validated_authorization = route.validate_creation_authorization(
            value.get("creation_authorization"),
            seed_intent=intent,
            target=target,
            now=dispatched_at,
        )
    except route.RouteSeedError as exc:
        raise ConnectedRouteError("DISPATCH_INVALID") from exc
    if (
        value.get("record_type") != DISPATCH_RECORD_TYPE
        or value.get("source_commit") != intent["source_commit"]
        or value.get("intent_digest") != intent["intent_digest"]
        or value.get("account_id") != spec["account_id"]
        or value.get("create_request_digest") != spec["create_request_digest"]
        or value.get("creation_authorization_digest")
        != validated_authorization["authorization_digest"]
        or value.get("aws_mutations") != 1
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
        or value.get("production_status") != route.PRODUCTION_STATUS
    ):
        raise ConnectedRouteError("DISPATCH_INVALID")
    try:
        route._full_arn(value.get("stack_arn"), account_id=spec["account_id"], kind="stack", name=spec["stack_name"])
        route._full_arn(value.get("change_set_arn"), account_id=spec["account_id"], kind="changeSet", name=spec["change_set_name"])
    except route.RouteSeedError as exc:
        raise ConnectedRouteError("DISPATCH_INVALID") from exc
    if _UUID_RE.fullmatch(str(value.get("create_request_id", ""))) is None:
        raise ConnectedRouteError("DISPATCH_INVALID")
    return json.loads(route.canonical_json(value))


def _validate_create_claim(
    value: Mapping[str, Any],
    *,
    seed_intent: Mapping[str, Any],
    target: str,
) -> dict[str, Any]:
    """Validate the durable local input that authorizes one create readback."""

    intent = route.validate_seed_intent(seed_intent)
    if target not in route.TARGETS:
        raise ConnectedRouteError("TARGET_INVALID")
    spec = intent["targets"][target]
    request = spec["create_request"]
    expected_fields = {
        "schema_version",
        "record_type",
        "operation",
        "target",
        "intent_digest",
        "request_digest",
        "creation_authorization",
        "creation_authorization_digest",
        "client_token",
        "stack_name",
        "change_set_name",
        "caller_arn_digest",
        "claimed_at",
        "retry_permitted",
        "production_authorized",
    }
    claimed_at = _parse_time(
        value.get("claimed_at"), "MUTATION_CLAIM_INVALID"
    )
    try:
        original_authorization = route.validate_creation_authorization(
            value.get("creation_authorization"),
            seed_intent=intent,
            target=target,
            now=claimed_at,
        )
    except route.RouteSeedError as exc:
        raise ConnectedRouteError("MUTATION_CLAIM_INVALID") from exc
    if (
        set(value) != expected_fields
        or value.get("schema_version") != 1
        or value.get("record_type") != CLAIM_RECORD_TYPE
        or value.get("operation") != "CreateChangeSet"
        or value.get("target") != target
        or value.get("intent_digest") != intent["intent_digest"]
        or value.get("request_digest") != spec["create_request_digest"]
        or value.get("creation_authorization_digest")
        != original_authorization["authorization_digest"]
        or value.get("client_token") != request["ClientToken"]
        or value.get("stack_name") != request["StackName"]
        or value.get("change_set_name") != request["ChangeSetName"]
        or _DIGEST_RE.fullmatch(str(value.get("caller_arn_digest", "")))
        is None
        or not _parse_time(
            intent["route_not_before"], "MUTATION_CLAIM_INVALID"
        )
        <= claimed_at
        < _parse_time(intent["route_not_after"], "MUTATION_CLAIM_INVALID")
        or value.get("retry_permitted") is not False
        or value.get("production_authorized") is not False
    ):
        raise ConnectedRouteError("MUTATION_CLAIM_INVALID")
    return json.loads(route.canonical_json(value))


def _strict_json_mapping(raw: Any) -> Mapping[str, Any]:
    if not isinstance(raw, str):
        raise ValueError("JSON text required")

    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise ValueError("duplicate or non-string JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError("non-finite JSON number")

    value = json.loads(
        raw,
        object_pairs_hook=closed_object,
        parse_constant=reject_constant,
    )
    if not isinstance(value, Mapping):
        raise ValueError("JSON object required")
    return value


def _log_policy_references_any(
    policy: Mapping[str, Any], *, resource_arns: tuple[str, ...]
) -> bool:
    """Return whether an IAM-style log resource policy can select a target ARN."""

    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
    candidates = tuple(
        candidate
        for arn in resource_arns
        for candidate in (arn, f"{arn}:*")
    )
    for statement in statements:
        if not isinstance(statement, Mapping):
            raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
        resources = statement.get("Resource")
        not_resources = statement.get("NotResource")
        if resources is not None and not_resources is not None:
            raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
        if resources is None and not_resources is None:
            return True
        selected = resources if resources is not None else not_resources
        if isinstance(selected, str):
            selected = [selected]
        if (
            not isinstance(selected, list)
            or not selected
            or any(not isinstance(item, str) or not item for item in selected)
        ):
            raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
        if resources is not None and any(
            fnmatchcase(candidate, pattern)
            for pattern in selected
            for candidate in candidates
        ):
            return True
        if not_resources is not None and any(
            not any(fnmatchcase(candidate, pattern) for pattern in selected)
            for candidate in candidates
        ):
            return True
    return False


def _change_projection(
    response: Mapping[str, Any],
    *,
    change_set_type: str,
    expected_changes: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    changes = response.get("Changes")
    if not isinstance(changes, list):
        raise ConnectedRouteError("CHANGE_SET_READBACK_INVALID")
    result: list[dict[str, str]] = []
    expected_by_logical_id = {
        item.get("logical_resource_id"): item.get("resource_type")
        for item in expected_changes
        if isinstance(item, Mapping)
    }
    if (
        len(expected_by_logical_id) != len(expected_changes)
        or any(
            not isinstance(logical_id, str)
            or not logical_id
            or not isinstance(resource_type, str)
            or not resource_type
            for logical_id, resource_type in expected_by_logical_id.items()
        )
    ):
        raise ConnectedRouteError("CHANGE_SET_CHANGES_INVALID")
    for change in changes:
        resource = change.get("ResourceChange") if isinstance(change, Mapping) else None
        expected_action = "Add" if change_set_type == "CREATE" else "Modify"
        logical_id = (
            resource.get("LogicalResourceId")
            if isinstance(resource, Mapping)
            else None
        )
        resource_type = (
            resource.get("ResourceType")
            if isinstance(resource, Mapping)
            else None
        )
        expected_scope = (
            []
            if change_set_type == "CREATE"
            else sorted(
                [
                    "DeletionPolicy",
                    "UpdateReplacePolicy",
                    *(["Properties"] if logical_id == "BrokerLedger" else []),
                ]
            )
        )
        if (
            change_set_type not in {"CREATE", "UPDATE"}
            or not isinstance(change, Mapping)
            or change.get("Type") != "Resource"
            or not isinstance(resource, Mapping)
            or resource.get("Action") != expected_action
            or logical_id not in expected_by_logical_id
            or resource_type != expected_by_logical_id[logical_id]
            or (
                resource.get("Replacement") not in {None, "False"}
                if change_set_type == "CREATE"
                else resource.get("Replacement") != "False"
            )
            or sorted(resource.get("Scope", [])) != expected_scope
        ):
            raise ConnectedRouteError("CHANGE_SET_CHANGES_INVALID")
        if change_set_type == "CREATE" and resource.get("Details", []) != []:
            raise ConnectedRouteError("CHANGE_SET_CHANGES_INVALID")
        expected_details = [
            {
                "Target": {
                    "Attribute": "DeletionPolicy",
                },
                "Evaluation": "Static",
                "ChangeSource": "DirectModification",
            },
            {
                "Target": {
                    "Attribute": "UpdateReplacePolicy",
                },
                "Evaluation": "Static",
                "ChangeSource": "DirectModification",
            },
        ]
        if logical_id == "BrokerLedger":
            expected_details.append(
                {
                    "Target": {
                        "Attribute": "Properties",
                        "Name": "DeletionProtectionEnabled",
                        "RequiresRecreation": "Never",
                    },
                    "Evaluation": "Static",
                    "ChangeSource": "DirectModification",
                }
            )
        if change_set_type == "UPDATE":
            details = resource.get("Details")
            if (
                not isinstance(details, list)
                or sorted(
                    details,
                    key=lambda detail: (
                        str((detail.get("Target") or {}).get("Attribute")),
                        str((detail.get("Target") or {}).get("Name", "")),
                    ),
                )
                != sorted(
                    expected_details,
                    key=lambda detail: (
                        str(detail["Target"]["Attribute"]),
                        str(detail["Target"].get("Name", "")),
                    ),
                )
            ):
                raise ConnectedRouteError("CHANGE_SET_CHANGES_INVALID")
        result.append(
            {
                "logical_resource_id": str(logical_id),
                "resource_type": str(resource_type),
            }
        )
    return sorted(result, key=lambda item: item["logical_resource_id"])


class ConnectedSeedProvider:
    def __init__(
        self,
        *,
        clients: Mapping[str, Any],
        claims: OExclClaimStore,
        clock: Callable[[], datetime],
    ) -> None:
        if set(clients) != {
            "sts",
            "cloudformation",
            "cloudtrail",
            "sso-admin",
            "lambda",
            "iam",
            "dynamodb",
            "kms",
            "logs",
        }:
            raise ConnectedRouteError("CLIENT_SET_INVALID")
        self._sts = clients["sts"]
        self._cfn = clients["cloudformation"]
        self._trail = clients["cloudtrail"]
        self._sso = clients["sso-admin"]
        self._lambda = clients["lambda"]
        self._iam = clients["iam"]
        self._dynamodb = clients["dynamodb"]
        self._kms = clients["kms"]
        self._logs = clients["logs"]
        self._claims = claims
        self._clock = clock

    def create_change_set(
        self,
        *,
        seed_input: Mapping[str, Any],
        seed_intent: Mapping[str, Any],
        git: route.GitPort,
        target: str,
        creation_authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        observed_at = self._clock()
        try:
            intent = route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=observed_at,
            )
        except route.RouteSeedError as exc:
            raise ConnectedRouteError(exc.code) from exc
        if target not in route.TARGETS:
            raise ConnectedRouteError("TARGET_INVALID")
        now = _window(intent, lambda: observed_at)
        try:
            authorization = route.validate_creation_authorization(
                creation_authorization,
                seed_intent=intent,
                target=target,
                now=now,
            )
        except route.RouteSeedError as exc:
            raise ConnectedRouteError(exc.code) from exc
        account_id, caller_arn = _verify_identity(
            self._sts, target=target, phase="creator"
        )
        now = _active_creation_time(
            intent=intent,
            target=target,
            authorization=authorization,
            clock=self._clock,
        )
        spec = intent["targets"][target]
        if spec["account_id"] != account_id:
            raise ConnectedRouteError("TARGET_ACCOUNT_INVALID")
        request = spec["create_request"]
        claim_key = (
            f"create:{target}:{intent['intent_digest']}:"
            f"{spec['create_request_digest']}"
        )
        claim = {
            "schema_version": 1,
            "record_type": CLAIM_RECORD_TYPE,
            "operation": "CreateChangeSet",
            "target": target,
            "intent_digest": intent["intent_digest"],
            "request_digest": spec["create_request_digest"],
            "creation_authorization": authorization,
            "creation_authorization_digest": authorization[
                "authorization_digest"
            ],
            "client_token": request["ClientToken"],
            "stack_name": request["StackName"],
            "change_set_name": request["ChangeSetName"],
            "caller_arn_digest": route.digest_value(caller_arn),
            "claimed_at": _timestamp(now),
            "retry_permitted": False,
            "production_authorized": False,
        }
        self._claims.claim(claim_key, claim)
        _active_creation_time(
            intent=intent,
            target=target,
            authorization=authorization,
            clock=self._clock,
        )
        try:
            response = self._cfn.create_change_set(**dict(request))
        except Exception as exc:
            raise ConnectedRouteError("CREATE_CHANGE_SET_UNCERTAIN", uncertain=True) from exc
        change_set_arn, stack_arn, request_id = _provider_ids(
            response, target_spec=spec
        )
        receipt = {
            "schema_version": 1,
            "record_type": DISPATCH_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": account_id,
            "intent_digest": intent["intent_digest"],
            "create_request_digest": spec["create_request_digest"],
            "creation_authorization": authorization,
            "creation_authorization_digest": authorization[
                "authorization_digest"
            ],
            "stack_arn": stack_arn,
            "change_set_arn": change_set_arn,
            "create_request_id": request_id,
            # This is the pre-call dispatch boundary.  CloudTrail records the
            # request before the SDK response returns, so a post-response
            # timestamp would make a valid event permanently unverifiable.
            "dispatched_at": _timestamp(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        }
        sealed = route.seal(receipt, "dispatch_digest")
        try:
            self._claims.complete(claim_key, sealed)
        except Exception as exc:
            raise ConnectedRouteError(
                "CREATE_RESULT_DURABILITY_UNCERTAIN", uncertain=True
            ) from exc
        return sealed

    def recover_create_change_set(
        self,
        *,
        seed_intent: Mapping[str, Any],
        target: str,
    ) -> dict[str, Any]:
        """Reconstruct a lost CreateChangeSet result without a second mutation."""

        intent = route.validate_seed_intent(seed_intent)
        if target not in route.TARGETS:
            raise ConnectedRouteError("TARGET_INVALID")
        now = _recovery_window(intent, self._clock)
        spec = intent["targets"][target]
        request = spec["create_request"]
        claim_key = (
            f"create:{target}:{intent['intent_digest']}:"
            f"{spec['create_request_digest']}"
        )
        claim = _validate_create_claim(
            self._claims.read_claim(claim_key),
            seed_intent=intent,
            target=target,
        )
        claimed_at = _parse_time(
            claim.get("claimed_at"), "MUTATION_CLAIM_INVALID"
        )
        original_authorization = claim["creation_authorization"]
        account_id, _recovery_caller = _verify_identity(
            self._sts, target=target, phase="creator"
        )
        if spec["account_id"] != account_id:
            raise ConnectedRouteError("TARGET_ACCOUNT_INVALID")
        events, _pages = _lookup_cloudtrail_events(
            self._trail,
            request={
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "CreateChangeSet",
                    }
                ],
                "StartTime": claimed_at,
                "EndTime": now,
                "MaxResults": 50,
            },
            error_code="CREATE_RECOVERY_AMBIGUOUS",
        )
        expected_params = _create_cloudtrail_params(request)
        matches: list[dict[str, Any]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise ConnectedRouteError("CREATE_RECOVERY_EVENT_INVALID")
            try:
                event = _strict_json_mapping(raw)
            except ValueError as exc:
                raise ConnectedRouteError("CREATE_RECOVERY_EVENT_INVALID") from exc
            params = event.get("requestParameters") or {}
            result = event.get("responseElements") or {}
            identity = event.get("userIdentity") or {}
            caller_arn = identity.get("arn")
            if params.get("clientToken") != request["ClientToken"]:
                continue
            event_time = _parse_time(
                event.get("eventTime"), "CREATE_RECOVERY_EVENT_INVALID"
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "CreateChangeSet"
                or event.get("awsRegion") != route.REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or not isinstance(caller_arn, str)
                or route.digest_value(caller_arn) != claim["caller_arn_digest"]
                or params != expected_params
                or "roleARN" in params
                or not claimed_at <= event_time <= now
                or _UUID_RE.fullmatch(str(event.get("requestID", ""))) is None
                or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
            ):
                raise ConnectedRouteError("CREATE_RECOVERY_EVENT_INVALID")
            change_set_arn = result.get("id")
            stack_arn = result.get("stackId")
            try:
                route._full_arn(
                    change_set_arn,
                    account_id=account_id,
                    kind="changeSet",
                    name=spec["change_set_name"],
                )
                route._full_arn(
                    stack_arn,
                    account_id=account_id,
                    kind="stack",
                    name=spec["stack_name"],
                )
            except route.RouteSeedError as exc:
                raise ConnectedRouteError("CREATE_RECOVERY_EVENT_INVALID") from exc
            matches.append(
                {
                    "change_set_arn": change_set_arn,
                    "stack_arn": stack_arn,
                    "request_id": event["requestID"],
                }
            )
        if len(matches) != 1:
            raise ConnectedRouteError("CREATE_RECOVERY_MISSING")
        match = matches[0]
        readback = self._cfn.describe_change_set(
            StackName=match["stack_arn"],
            ChangeSetName=match["change_set_arn"],
        )
        if (
            readback.get("NextToken") is not None
            or readback.get("ChangeSetId") != match["change_set_arn"]
            or readback.get("StackId") != match["stack_arn"]
            or readback.get("StackName") != spec["stack_name"]
            or readback.get("ChangeSetName") != spec["change_set_name"]
            or readback.get("Description") != request["Description"]
            or readback.get("ChangeSetType") != request["ChangeSetType"]
            or not _change_set_parameters_match(
                readback.get("Parameters"),
                request.get("Parameters", []),
                target=target,
            )
            or readback.get("Capabilities") != request["Capabilities"]
            or readback.get("Tags") != request["Tags"]
            or readback.get("IncludeNestedStacks") is not False
            or readback.get("NotificationARNs", []) != []
            or readback.get("RollbackConfiguration")
            != request["RollbackConfiguration"]
            or (
                readback.get("OnStackFailure")
                != request["OnStackFailure"]
                if request["ChangeSetType"] == "CREATE"
                else readback.get("OnStackFailure") is not None
            )
        ):
            raise ConnectedRouteError("CREATE_RECOVERY_READBACK_INVALID")
        receipt = route.seal(
            {
                "schema_version": 1,
                "record_type": DISPATCH_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account_id,
                "intent_digest": intent["intent_digest"],
                "create_request_digest": spec["create_request_digest"],
                "creation_authorization": original_authorization,
                "creation_authorization_digest": claim[
                    "creation_authorization_digest"
                ],
                "stack_arn": match["stack_arn"],
                "change_set_arn": match["change_set_arn"],
                "create_request_id": match["request_id"],
                "dispatched_at": claim["claimed_at"],
                "aws_mutations": 1,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "dispatch_digest",
        )
        try:
            self._claims.complete(claim_key, receipt)
        except Exception as exc:
            raise ConnectedRouteError("CREATE_RECOVERY_DURABILITY_FAILED") from exc
        return receipt

    def _cloudtrail_create_digest(
        self,
        *,
        intent: Mapping[str, Any],
        target: str,
        dispatch: Mapping[str, Any],
        creator_arn_digest: str,
        now: datetime,
    ) -> str:
        events, _pages = _lookup_cloudtrail_events(
            self._trail,
            request={
                "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "CreateChangeSet"}
                ],
                "StartTime": _parse_time(
                    intent["route_not_before"], "WINDOW_INVALID"
                ),
                "EndTime": now,
                "MaxResults": 50,
            },
            error_code="CREATE_CLOUDTRAIL_AMBIGUOUS",
        )
        request = intent["targets"][target]["create_request"]
        expected_params = _create_cloudtrail_params(request)
        matches: list[dict[str, Any]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise ConnectedRouteError("CREATE_CLOUDTRAIL_INVALID")
            event = _strict_json_mapping(raw)
            if event.get("requestID") != dispatch["create_request_id"]:
                continue
            params = event.get("requestParameters") or {}
            result = event.get("responseElements") or {}
            identity = event.get("userIdentity") or {}
            caller_arn = identity.get("arn")
            _account, creator_pattern = _role_pattern(
                target=target,
                phase="creator",
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "CreateChangeSet"
                or event.get("awsRegion") != route.REGION
                or event.get("recipientAccountId") != dispatch["account_id"]
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or not isinstance(caller_arn, str)
                or creator_pattern.fullmatch(caller_arn) is None
                or route.digest_value(caller_arn) != creator_arn_digest
                or params != expected_params
                or "roleARN" in params
                or result.get("id") != dispatch["change_set_arn"]
                or result.get("stackId") != dispatch["stack_arn"]
            ):
                raise ConnectedRouteError("CREATE_CLOUDTRAIL_INVALID")
            matches.append(
                {
                    "event_id": event.get("eventID"),
                    "event_time": event.get("eventTime"),
                    "request_id": event.get("requestID"),
                    "caller_arn": caller_arn,
                    "cloudtrail_request_digest": route.digest_value(params),
                    "request_digest": intent["targets"][target][
                        "create_request_digest"
                    ],
                    "stack_arn": dispatch["stack_arn"],
                    "change_set_arn": dispatch["change_set_arn"],
                }
            )
        if len(matches) != 1 or _UUID_RE.fullmatch(str(matches[0]["event_id"])) is None:
            raise ConnectedRouteError("CREATE_CLOUDTRAIL_MISSING")
        _parse_time(matches[0]["event_time"], "CREATE_CLOUDTRAIL_INVALID")
        return route.digest_value(matches[0])

    def _cloudtrail_execute_digest(
        self,
        *,
        execution: Mapping[str, Any],
        receipt: Mapping[str, Any],
        caller_arn: str,
        now: datetime,
    ) -> tuple[str, int]:
        events, page_count = _lookup_cloudtrail_events(
            self._trail,
            request={
                "LookupAttributes": [
                {
                    "AttributeKey": "EventName",
                    "AttributeValue": "ExecuteChangeSet",
                }
                ],
                "StartTime": _parse_time(
                    receipt["dispatched_at"], "EXECUTION_RECEIPT_INVALID"
                ),
                "EndTime": now,
                "MaxResults": 50,
            },
            error_code="EXECUTE_CLOUDTRAIL_AMBIGUOUS",
        )
        request = execution["execute_request"]
        expected_params = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        }
        if "DisableRollback" in request:
            expected_params["disableRollback"] = request["DisableRollback"]
        matches: list[dict[str, Any]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise ConnectedRouteError("EXECUTE_CLOUDTRAIL_INVALID")
            try:
                event = _strict_json_mapping(raw)
            except ValueError as exc:
                raise ConnectedRouteError("EXECUTE_CLOUDTRAIL_INVALID") from exc
            if event.get("requestID") != receipt["execute_request_id"]:
                continue
            identity = event.get("userIdentity") or {}
            params = event.get("requestParameters") or {}
            event_time = _parse_time(
                event.get("eventTime"), "EXECUTE_CLOUDTRAIL_INVALID"
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "ExecuteChangeSet"
                or event.get("awsRegion") != route.REGION
                or event.get("recipientAccountId") != receipt["account_id"]
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or identity.get("arn") != caller_arn
                or params != expected_params
                or event_time
                < _parse_time(receipt["dispatched_at"], "EXECUTION_RECEIPT_INVALID")
                or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
            ):
                raise ConnectedRouteError("EXECUTE_CLOUDTRAIL_INVALID")
            matches.append(
                {
                    "event_id": event["eventID"],
                    "event_time": _timestamp(event_time),
                    "request_id": event["requestID"],
                    "caller_arn": caller_arn,
                    "request_digest": execution["execute_request_digest"],
                    "cloudtrail_request_digest": route.digest_value(params),
                }
            )
        if len(matches) != 1:
            raise ConnectedRouteError("EXECUTE_CLOUDTRAIL_MISSING")
        return route.digest_value(matches[0]), page_count

    def _read_create_attestation_immutables(
        self,
        *,
        intent: Mapping[str, Any],
        target: str,
        dispatch: Mapping[str, Any],
        creator_arn_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Repeat the authoritative create-set readback used at execution."""

        if _DIGEST_RE.fullmatch(creator_arn_digest) is None:
            raise ConnectedRouteError("MUTATION_CLAIM_INVALID")
        spec = intent["targets"][target]
        request = spec["create_request"]
        response = self._cfn.describe_change_set(
            StackName=dispatch["stack_arn"],
            ChangeSetName=dispatch["change_set_arn"],
        )
        if response.get("NextToken") is not None:
            raise ConnectedRouteError("CHANGE_SET_READBACK_INCOMPLETE")
        if response.get("Status") in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
            raise ConnectedRouteError("CHANGE_SET_NOT_READY")
        resources = _change_projection(
            response,
            change_set_type=str(request["ChangeSetType"]),
            expected_changes=spec["expected_changes"],
        )
        if (
            response.get("ChangeSetId") != dispatch["change_set_arn"]
            or response.get("StackId") != dispatch["stack_arn"]
            or response.get("StackName") != spec["stack_name"]
            or response.get("ChangeSetName") != spec["change_set_name"]
            or response.get("Status") != "CREATE_COMPLETE"
            or response.get("ExecutionStatus") != "AVAILABLE"
            or response.get("Description") != request["Description"]
            or response.get("ChangeSetType") != request["ChangeSetType"]
            or not _change_set_parameters_match(
                response.get("Parameters"),
                request.get("Parameters", []),
                target=target,
            )
            or response.get("Capabilities", []) != request["Capabilities"]
            or response.get("Tags", []) != request["Tags"]
            or response.get("IncludeNestedStacks", False) is not False
            or response.get("NotificationARNs", []) != []
            or response.get("RollbackConfiguration", {})
            != request["RollbackConfiguration"]
            or (
                response.get("OnStackFailure") != request["OnStackFailure"]
                if request["ChangeSetType"] == "CREATE"
                else response.get("OnStackFailure") is not None
            )
            or "RoleARN" in response
            or "ResourcesToImport" in response
            or resources != spec["expected_changes"]
        ):
            raise ConnectedRouteError("CHANGE_SET_READBACK_INVALID")
        template_response = self._cfn.get_template(
            ChangeSetName=dispatch["change_set_arn"],
            TemplateStage="Original",
        )
        body = template_response.get("TemplateBody")
        if not isinstance(body, str):
            raise ConnectedRouteError("TEMPLATE_READBACK_INVALID")
        template_digest = route.bytes_digest(body.encode("utf-8"))
        if template_digest != spec["template_digest"]:
            raise ConnectedRouteError("TEMPLATE_DIGEST_MISMATCH")
        cloudtrail_digest = self._cloudtrail_create_digest(
            intent=intent,
            target=target,
            dispatch=dispatch,
            creator_arn_digest=creator_arn_digest,
            now=now,
        )
        return {
            "schema_version": 1,
            "record_type": route.RECORD_TYPE_CREATE_ATTESTATION,
            "source_commit": intent["source_commit"],
            "target": target,
            "intent_digest": intent["intent_digest"],
            "create_request_digest": spec["create_request_digest"],
            "account_id": dispatch["account_id"],
            "stack_arn": dispatch["stack_arn"],
            "change_set_arn": dispatch["change_set_arn"],
            "create_request_id": dispatch["create_request_id"],
            "cloudtrail_event_digest": cloudtrail_digest,
            "describe_change_set_digest": route.digest_value(
                {
                    "id": response["ChangeSetId"],
                    "stack_id": response["StackId"],
                    "creation_time": _timestamp(response["CreationTime"]),
                    "status": response["Status"],
                    "execution_status": response["ExecutionStatus"],
                    "request_digest": spec["create_request_digest"],
                }
            ),
            "template_digest": template_digest,
            "changes_digest": route.digest_value(resources),
            "status": "CREATE_COMPLETE",
            "execution_status": "AVAILABLE",
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        }

    def attest_change_set(
        self,
        *,
        seed_intent: Mapping[str, Any],
        dispatch_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        intent = route.validate_seed_intent(seed_intent)
        dispatch = validate_dispatch(dispatch_receipt, seed_intent=intent)
        target = dispatch["target"]
        now = _recovery_window(intent, self._clock)
        account_id, caller_arn = _verify_identity(
            self._sts, target=target, phase="creator"
        )
        if account_id != dispatch["account_id"]:
            raise ConnectedRouteError("TARGET_ACCOUNT_INVALID")
        attestation = self._read_create_attestation_immutables(
            intent=intent,
            target=target,
            dispatch=dispatch,
            creator_arn_digest=route.digest_value(caller_arn),
            now=now,
        )
        attestation["attested_at"] = _timestamp(now)
        return route.seal(attestation, "attestation_digest")

    def execute_change_set(
        self,
        *,
        seed_input: Mapping[str, Any],
        seed_intent: Mapping[str, Any],
        git: route.GitPort,
        create_attestation: Mapping[str, Any],
        execution_authorization: Mapping[str, Any],
        execution_intent: Mapping[str, Any],
    ) -> dict[str, Any]:
        observed_at = self._clock()
        try:
            seed = route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=observed_at,
            )
            intent = route.validate_execution_intent_against_causal_records(
                execution_intent,
                seed_intent=seed,
                create_attestation=create_attestation,
                authorization=execution_authorization,
            )
        except route.RouteSeedError as exc:
            raise ConnectedRouteError(exc.code) from exc
        _active_execution_time(
            intent=seed,
            create_attestation=create_attestation,
            authorization=execution_authorization,
            clock=lambda: observed_at,
        )
        target = intent["target"]
        spec = seed["targets"][target]
        create_claim_key = (
            f"create:{target}:{seed['intent_digest']}:"
            f"{spec['create_request_digest']}"
        )
        create_claim = _validate_create_claim(
            self._claims.read_claim(create_claim_key),
            seed_intent=seed,
            target=target,
        )
        persisted_dispatch = validate_dispatch(
            self._claims.read_result(create_claim_key),
            seed_intent=seed,
        )
        try:
            attestation = route.validate_create_attestation(
                create_attestation,
                intent=seed,
                target=target,
            )
        except route.RouteSeedError as exc:
            raise ConnectedRouteError(exc.code) from exc
        if (
            attestation["stack_arn"] != persisted_dispatch["stack_arn"]
            or attestation["change_set_arn"]
            != persisted_dispatch["change_set_arn"]
            or attestation["create_request_id"]
            != persisted_dispatch["create_request_id"]
            or _parse_time(
                attestation["attested_at"],
                "CREATE_ATTESTATION_DISPATCH_BINDING_INVALID",
            )
            < _parse_time(
                persisted_dispatch["dispatched_at"],
                "CREATE_ATTESTATION_DISPATCH_BINDING_INVALID",
            )
        ):
            raise ConnectedRouteError(
                "CREATE_ATTESTATION_DISPATCH_BINDING_INVALID"
            )
        account_id, caller_arn = _verify_identity(
            self._sts, target=target, phase="executor"
        )
        readback_now = _active_execution_time(
            intent=seed,
            create_attestation=attestation,
            authorization=execution_authorization,
            clock=self._clock,
        )
        if account_id != intent["account_id"]:
            raise ConnectedRouteError("TARGET_ACCOUNT_INVALID")
        observed_attestation = self._read_create_attestation_immutables(
            intent=seed,
            target=target,
            dispatch=persisted_dispatch,
            creator_arn_digest=create_claim["caller_arn_digest"],
            now=readback_now,
        )
        if any(
            attestation.get(field) != observed_attestation[field]
            for field in _CREATE_ATTESTATION_IMMUTABLE_FIELDS
        ):
            raise ConnectedRouteError(
                "CREATE_ATTESTATION_LIVE_BINDING_INVALID"
            )
        now = _active_execution_time(
            intent=seed,
            create_attestation=attestation,
            authorization=execution_authorization,
            clock=self._clock,
        )
        request = intent["execute_request"]
        claim_key = f"execute:{target}:{intent['execute_operation_digest']}"
        claim = {
            "schema_version": 1,
            "record_type": CLAIM_RECORD_TYPE,
            "operation": "ExecuteChangeSet",
            "target": target,
            "execution_intent_digest": intent["execution_intent_digest"],
            "request_digest": intent["execute_request_digest"],
            "client_request_token": request["ClientRequestToken"],
            "stack_arn": request["StackName"],
            "change_set_arn": request["ChangeSetName"],
            "caller_arn_digest": route.digest_value(caller_arn),
            "claimed_at": _timestamp(now),
            "retry_permitted": False,
            "production_authorized": False,
        }
        self._claims.claim(claim_key, claim)
        _active_execution_time(
            intent=seed,
            create_attestation=attestation,
            authorization=execution_authorization,
            clock=self._clock,
        )
        try:
            response = self._cfn.execute_change_set(**dict(request))
        except Exception as exc:
            raise ConnectedRouteError("EXECUTE_CHANGE_SET_UNCERTAIN", uncertain=True) from exc
        request_id = (response.get("ResponseMetadata") or {}).get("RequestId")
        if not isinstance(request_id, str) or _UUID_RE.fullmatch(request_id) is None:
            raise ConnectedRouteError("EXECUTE_RESPONSE_UNCERTAIN", uncertain=True)
        receipt = {
            "schema_version": 1,
            "record_type": EXECUTION_RECEIPT_RECORD_TYPE,
            "source_commit": intent["source_commit"],
            "target": target,
            "account_id": account_id,
            "execution_intent_digest": intent["execution_intent_digest"],
            "stack_arn": request["StackName"],
            "change_set_arn": request["ChangeSetName"],
            "execute_request_id": request_id,
            # Preserve the pre-call boundary used by the CloudTrail lookup.
            # The service event may precede the SDK response timestamp.
            "dispatched_at": _timestamp(now),
            "aws_mutations": 1,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        }
        sealed = route.seal(receipt, "receipt_digest")
        try:
            self._claims.complete(claim_key, sealed)
        except Exception as exc:
            raise ConnectedRouteError(
                "EXECUTE_RESULT_DURABILITY_UNCERTAIN", uncertain=True
            ) from exc
        return sealed

    def recover_execute_change_set(
        self, *, execution_intent: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Reconstruct a lost ExecuteChangeSet result without executing again."""

        intent = route.validate_execution_intent(execution_intent)
        target = intent["target"]
        now = _recovery_window(intent, self._clock)
        request = intent["execute_request"]
        claim_key = f"execute:{target}:{intent['execute_operation_digest']}"
        claim = self._claims.read_claim(claim_key)
        expected_claim_fields = {
            "schema_version",
            "record_type",
            "operation",
            "target",
            "execution_intent_digest",
            "request_digest",
            "client_request_token",
            "stack_arn",
            "change_set_arn",
            "caller_arn_digest",
            "claimed_at",
            "retry_permitted",
            "production_authorized",
        }
        claimed_at = _parse_time(
            claim.get("claimed_at"), "MUTATION_CLAIM_INVALID"
        )
        if (
            set(claim) != expected_claim_fields
            or claim.get("schema_version") != 1
            or claim.get("record_type") != CLAIM_RECORD_TYPE
            or claim.get("operation") != "ExecuteChangeSet"
            or claim.get("target") != target
            or claim.get("execution_intent_digest")
            != intent["execution_intent_digest"]
            or claim.get("request_digest") != intent["execute_request_digest"]
            or claim.get("client_request_token")
            != request["ClientRequestToken"]
            or claim.get("stack_arn") != request["StackName"]
            or claim.get("change_set_arn") != request["ChangeSetName"]
            or _DIGEST_RE.fullmatch(str(claim.get("caller_arn_digest", "")))
            is None
            or not _parse_time(
                intent["authorization_not_before"], "MUTATION_CLAIM_INVALID"
            )
            <= claimed_at
            < _parse_time(
                intent["authorization_expires_at"], "MUTATION_CLAIM_INVALID"
            )
            or claim.get("retry_permitted") is not False
            or claim.get("production_authorized") is not False
        ):
            raise ConnectedRouteError("MUTATION_CLAIM_INVALID")
        account_id, _recovery_caller = _verify_identity(
            self._sts, target=target, phase="executor"
        )
        if account_id != intent["account_id"]:
            raise ConnectedRouteError("TARGET_ACCOUNT_INVALID")
        events, _pages = _lookup_cloudtrail_events(
            self._trail,
            request={
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "ExecuteChangeSet",
                    }
                ],
                "StartTime": claimed_at,
                "EndTime": now,
                "MaxResults": 50,
            },
            error_code="EXECUTE_RECOVERY_AMBIGUOUS",
        )
        expected_params = {
            "stackName": request["StackName"],
            "changeSetName": request["ChangeSetName"],
            "clientRequestToken": request["ClientRequestToken"],
        }
        if "DisableRollback" in request:
            expected_params["disableRollback"] = request["DisableRollback"]
        matches: list[dict[str, str]] = []
        for envelope in events:
            raw = envelope.get("CloudTrailEvent")
            if not isinstance(raw, str):
                raise ConnectedRouteError("EXECUTE_RECOVERY_EVENT_INVALID")
            try:
                event = _strict_json_mapping(raw)
            except ValueError as exc:
                raise ConnectedRouteError("EXECUTE_RECOVERY_EVENT_INVALID") from exc
            params = event.get("requestParameters") or {}
            identity = event.get("userIdentity") or {}
            caller_arn = identity.get("arn")
            if params.get("clientRequestToken") != request["ClientRequestToken"]:
                continue
            event_time = _parse_time(
                event.get("eventTime"), "EXECUTE_RECOVERY_EVENT_INVALID"
            )
            if (
                event.get("eventSource") != "cloudformation.amazonaws.com"
                or event.get("eventName") != "ExecuteChangeSet"
                or event.get("awsRegion") != route.REGION
                or event.get("recipientAccountId") != account_id
                or event.get("readOnly") is not False
                or event.get("errorCode") is not None
                or event.get("errorMessage") is not None
                or event.get("responseElements") is not None
                or not isinstance(caller_arn, str)
                or route.digest_value(caller_arn) != claim["caller_arn_digest"]
                or params != expected_params
                or not claimed_at <= event_time <= now
                or _UUID_RE.fullmatch(str(event.get("requestID", ""))) is None
                or _UUID_RE.fullmatch(str(event.get("eventID", ""))) is None
            ):
                raise ConnectedRouteError("EXECUTE_RECOVERY_EVENT_INVALID")
            matches.append({"request_id": str(event["requestID"])})
        if len(matches) != 1:
            raise ConnectedRouteError("EXECUTE_RECOVERY_MISSING")
        stacks = self._cfn.describe_stacks(StackName=request["StackName"])
        stack_items = stacks.get("Stacks")
        if (
            stacks.get("NextToken") is not None
            or not isinstance(stack_items, list)
            or len(stack_items) != 1
            or not isinstance(stack_items[0], Mapping)
            or stack_items[0].get("StackId") != request["StackName"]
        ):
            raise ConnectedRouteError("EXECUTE_RECOVERY_READBACK_INVALID")
        receipt = route.seal(
            {
                "schema_version": 1,
                "record_type": EXECUTION_RECEIPT_RECORD_TYPE,
                "source_commit": intent["source_commit"],
                "target": target,
                "account_id": account_id,
                "execution_intent_digest": intent["execution_intent_digest"],
                "stack_arn": request["StackName"],
                "change_set_arn": request["ChangeSetName"],
                "execute_request_id": matches[0]["request_id"],
                "dispatched_at": claim["claimed_at"],
                "aws_mutations": 1,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            },
            "receipt_digest",
        )
        try:
            self._claims.complete(claim_key, receipt)
        except Exception as exc:
            raise ConnectedRouteError("EXECUTE_RECOVERY_DURABILITY_FAILED") from exc
        return receipt

    def _broker_live_readback(
        self,
        *,
        seed: Mapping[str, Any],
        spec: Mapping[str, Any],
        resources: Mapping[str, Mapping[str, Any]],
        stack_arn: str,
        expected_deletion_protection: bool = True,
    ) -> tuple[str, int]:
        source_commit = seed["source_commit"]
        try:
            from tooling.platform_authority_plan_permission_repair_broker_seed import (
                BrokerSeedError,
                canonicalize_policy_document,
                validate_effective_policy_projection,
            )

            expected_policy_projection = validate_effective_policy_projection(
                spec["broker_effective_policy_projection"],
                source_commit=source_commit,
            )
        except (ImportError, KeyError) as exc:
            raise ConnectedRouteError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
        except BrokerSeedError as exc:
            raise ConnectedRouteError("BROKER_EFFECTIVE_POLICY_INVALID") from exc
        broker_tags = sorted(
            route.EXACT_TAGS
            + [
                {"Key": "component", "Value": "gug376-route-broker"},
                {"Key": "environment", "Value": "non-production"},
                {"Key": "production", "Value": "false"},
                {"Key": "source_commit", "Value": source_commit},
            ],
            key=lambda item: item["Key"],
        )
        if (
            not isinstance(stack_arn, str)
            or not stack_arn.startswith(
                f"arn:aws:cloudformation:{route.REGION}:"
                f"{route.AUTHORITY_ACCOUNT_ID}:stack/{spec['stack_name']}/"
            )
            or _UUID_RE.fullmatch(stack_arn.rsplit("/", 1)[-1]) is None
        ):
            raise ConnectedRouteError("BROKER_STACK_ARN_INVALID")

        def expected_tags(logical_id: str) -> list[dict[str, str]]:
            return sorted(
                broker_tags
                + [
                    {
                        "Key": "aws:cloudformation:logical-id",
                        "Value": logical_id,
                    },
                    {
                        "Key": "aws:cloudformation:stack-id",
                        "Value": stack_arn,
                    },
                    {
                        "Key": "aws:cloudformation:stack-name",
                        "Value": spec["stack_name"],
                    },
                ],
                key=lambda item: item["Key"],
            )

        def expected_tag_map(logical_id: str) -> dict[str, str]:
            return {
                item["Key"]: item["Value"]
                for item in expected_tags(logical_id)
            }
        function_contracts = {
            "CreatorFunction": (
                "scanalyze-platform-authority-gug376-route-creator",
                "tooling.platform_authority_plan_permission_repair_route_broker.creator_handler",
                "ScanalyzeGug376RouteBrokerCreator",
                (
                    "seed-revoke-create-v1",
                    "delegation-create-v1",
                    "pep-create-v1",
                    "pep-protection-create-v1",
                    "closeout-gate-v1",
                    "delegation-revoke-create-v1",
                    "route-revoke-create-v1",
                ),
                "creator",
            ),
            "ExecutorFunction": (
                "scanalyze-platform-authority-gug376-route-executor",
                "tooling.platform_authority_plan_permission_repair_route_broker.executor_handler",
                "ScanalyzeGug376RouteBrokerExecutor",
                (
                    "seed-revoke-execute-v1",
                    "delegation-execute-v1",
                    "pep-execute-v1",
                    "pep-protection-execute-v1",
                    "delegation-revoke-execute-v1",
                    "route-revoke-execute-v1",
                ),
                "executor",
            ),
            "CreateDispatchRecoveryFunction": (
                "scanalyze-platform-authority-gug376-route-create-dispatch-recovery",
                "tooling.platform_authority_plan_permission_repair_route_broker.create_dispatch_recovery_handler",
                "ScanalyzeGug376RouteCreateDispatchRecovery",
                ("recover-v1",),
                "create dispatch recovery",
            ),
            "ExecuteDispatchRecoveryFunction": (
                "scanalyze-platform-authority-gug376-route-execute-dispatch-recovery",
                "tooling.platform_authority_plan_permission_repair_route_broker.execute_dispatch_recovery_handler",
                "ScanalyzeGug376RouteExecuteDispatchRecovery",
                ("recover-v1",),
                "execute dispatch recovery",
            ),
        }
        live: dict[str, Any] = {"functions": {}, "roles": {}}
        calls = 0
        code_signing_arn = resources["BrokerCodeSigningConfig"].get(
            "PhysicalResourceId"
        )
        if not isinstance(code_signing_arn, str) or not code_signing_arn.startswith(
            f"arn:aws:lambda:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:code-signing-config:"
        ):
            raise ConnectedRouteError("BROKER_CODE_SIGNING_RESOURCE_INVALID")
        signing = self._lambda.get_code_signing_config(
            CodeSigningConfigArn=code_signing_arn
        )
        calls += 1
        signing_config = signing.get("CodeSigningConfig")
        signing_config_id = (
            signing_config.get("CodeSigningConfigId")
            if isinstance(signing_config, Mapping)
            else None
        )
        if (
            not isinstance(signing_config, Mapping)
            or re.fullmatch(r"csc-[a-z0-9]{17}", str(signing_config_id)) is None
            or signing_config.get("CodeSigningConfigArn") != code_signing_arn
            or code_signing_arn
            != (
                f"arn:aws:lambda:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
                f"code-signing-config:{signing_config_id}"
            )
            or signing_config.get("Description")
            != "GUG-376 route broker signed code only"
            or signing_config.get("AllowedPublishers")
            != {
                "SigningProfileVersionArns": [
                    spec["broker_signing_profile_version_arn"]
                ]
            }
            or signing_config.get("CodeSigningPolicies")
            != {"UntrustedArtifactOnDeployment": "Enforce"}
        ):
            raise ConnectedRouteError("BROKER_CODE_SIGNING_INVALID")
        live["code_signing"] = {
            "arn": code_signing_arn,
            "config_id": signing_config_id,
            "policy_digest": route.digest_value(
                {
                    "allowed_publishers": signing_config["AllowedPublishers"],
                    "policies": signing_config["CodeSigningPolicies"],
                }
            ),
        }
        expected_key_id = resources["BrokerLedgerKey"].get("PhysicalResourceId")
        if not isinstance(expected_key_id, str) or _UUID_RE.fullmatch(expected_key_id) is None:
            raise ConnectedRouteError("BROKER_LEDGER_RESOURCE_INVALID")
        expected_key_arn = (
            f"arn:aws:kms:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
            f"key/{expected_key_id}"
        )
        for logical_id, (
            name,
            handler,
            role_name,
            aliases,
            version_label,
        ) in function_contracts.items():
            if resources[logical_id].get("PhysicalResourceId") != name:
                raise ConnectedRouteError("BROKER_FUNCTION_RESOURCE_INVALID")
            function_arn = (
                f"arn:aws:lambda:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
                f"function:{name}"
            )
            function = self._lambda.get_function(FunctionName=name)
            concurrency = self._lambda.get_function_concurrency(FunctionName=name)
            runtime = self._lambda.get_runtime_management_config(FunctionName=name)
            function_signing = self._lambda.get_function_code_signing_config(
                FunctionName=name
            )
            function_tags = self._lambda.list_tags(Resource=function_arn)
            provisioned_configs, provisioned_pages = _paginate_tokenized_items(
                self._lambda.list_provisioned_concurrency_configs,
                request={"FunctionName": name, "MaxItems": 50},
                item_key="ProvisionedConcurrencyConfigs",
                request_token_key="Marker",
                response_token_key="NextMarker",
                error_code="BROKER_FUNCTION_PROVISIONED_CONCURRENCY_INVALID",
            )
            versions = self._lambda.list_versions_by_function(
                FunctionName=name, MaxItems=50
            )
            alias_page = self._lambda.list_aliases(FunctionName=name, MaxItems=50)
            calls += 7 + provisioned_pages
            if provisioned_configs != []:
                raise ConnectedRouteError(
                    "BROKER_FUNCTION_PROVISIONED_CONCURRENCY_INVALID"
                )
            configuration = function.get("Configuration")
            code = function.get("Code")
            runtime_version = (
                configuration.get("RuntimeVersionConfig")
                if isinstance(configuration, Mapping)
                else None
            )
            logging_config = (
                configuration.get("LoggingConfig")
                if isinstance(configuration, Mapping)
                else None
            )
            vpc_config = (
                configuration.get("VpcConfig")
                if isinstance(configuration, Mapping)
                else None
            )
            if (
                not isinstance(configuration, Mapping)
                or configuration.get("FunctionName") != name
                or configuration.get("FunctionArn") != function_arn
                or configuration.get("Runtime") != "python3.12"
                or configuration.get("Handler") != handler
                or configuration.get("Role")
                != f"arn:aws:iam::{route.AUTHORITY_ACCOUNT_ID}:role/{role_name}"
                or configuration.get("CodeSha256") != spec["broker_code_sha256"]
                or configuration.get("Timeout") != 900
                or configuration.get("MemorySize") != 256
                or configuration.get("TracingConfig") != {"Mode": "Active"}
                or configuration.get("State") != "Active"
                or configuration.get("LastUpdateStatus") != "Successful"
                or configuration.get("Architectures") != ["x86_64"]
                or configuration.get("Version") != "$LATEST"
                or configuration.get("PackageType") != "Zip"
                or configuration.get("EphemeralStorage") != {"Size": 512}
                or configuration.get("SnapStart", {}).get("ApplyOn") != "None"
                or configuration.get("SnapStart", {}).get("OptimizationStatus")
                != "Off"
                or configuration.get("Description", "") != ""
                or configuration.get("Layers", []) != []
                or configuration.get("FileSystemConfigs", []) != []
                or configuration.get("DeadLetterConfig", {}) not in ({}, {"TargetArn": ""})
                or configuration.get("KMSKeyArn") not in {None, ""}
                or configuration.get("MasterArn") not in {None, ""}
                or configuration.get("DurableConfig") not in {None}
                or configuration.get("CapacityProviderConfig") not in {None}
                or configuration.get("TenancyConfig") not in {None}
                or not isinstance(vpc_config, Mapping)
                or vpc_config.get("SubnetIds", []) != []
                or vpc_config.get("SecurityGroupIds", []) != []
                or vpc_config.get("VpcId", "") != ""
                or vpc_config.get("Ipv6AllowedForDualStack", False) is not False
                or not isinstance(logging_config, Mapping)
                or logging_config.get("LogFormat") != "Text"
                or logging_config.get("LogGroup") != f"/aws/lambda/{name}"
                or logging_config.get("ApplicationLogLevel") is not None
                or logging_config.get("SystemLogLevel") is not None
                or not isinstance(code, Mapping)
                or code.get("RepositoryType") != "S3"
                or not isinstance(code.get("Location"), str)
                or not code["Location"]
                or not isinstance(runtime_version, Mapping)
                or set(runtime_version) != {"RuntimeVersionArn"}
                or _LAMBDA_RUNTIME_VERSION_ARN_RE.fullmatch(
                    str(runtime_version.get("RuntimeVersionArn", ""))
                )
                is None
                or concurrency.get("ReservedConcurrentExecutions") != 1
                or runtime.get("UpdateRuntimeOn") != "FunctionUpdate"
                or runtime.get("FunctionArn") != function_arn
                or runtime.get("RuntimeVersionArn") is not None
                or function_signing.get("CodeSigningConfigArn") != code_signing_arn
                or function_tags.get("Tags") != expected_tag_map(logical_id)
                or versions.get("NextMarker") is not None
                or alias_page.get("NextMarker") is not None
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_LIVE_INVALID")
            environment = configuration.get("Environment", {}).get("Variables")
            if (
                not isinstance(environment, Mapping)
                or set(environment)
                != {
                    "LEDGER_TABLE_NAME",
                    "BROKER_LEDGER_KEY_ARN",
                    "BROKER_CONFIG_JSON",
                }
                or environment.get("LEDGER_TABLE_NAME")
                != "scanalyze-platform-authority-gug376-route-broker-ledger"
                or environment.get("BROKER_LEDGER_KEY_ARN") != expected_key_arn
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_ENVIRONMENT_INVALID")
            try:
                from tooling.platform_authority_plan_permission_repair_route_broker import (
                    BrokerConfig,
                    ROUTE_LEDGER_ID,
                    decode_runtime_config,
                )

                envelope = _strict_json_mapping(environment["BROKER_CONFIG_JSON"])
                runtime_config = BrokerConfig.from_mapping(
                    decode_runtime_config(envelope)
                )
            except Exception as exc:
                raise ConnectedRouteError("BROKER_FUNCTION_ENVIRONMENT_INVALID") from exc
            if (
                runtime_config.source_commit != source_commit
                or runtime_config.ledger_id != ROUTE_LEDGER_ID
                or runtime_config.config_digest != spec["broker_config_digest"]
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_ENVIRONMENT_INVALID")
            raw_versions = versions.get("Versions")
            if not isinstance(raw_versions, list):
                raise ConnectedRouteError("BROKER_FUNCTION_VERSIONS_INVALID")
            published = [
                item
                for item in raw_versions
                if isinstance(item, Mapping) and item.get("Version") != "$LATEST"
            ]
            if (
                len(raw_versions) != 2
                or len(published) != 1
                or not any(
                    isinstance(item, Mapping)
                    and item.get("FunctionName") == name
                    and item.get("Version") == "$LATEST"
                    and item.get("CodeSha256") == spec["broker_code_sha256"]
                    for item in raw_versions
                )
                or not str(published[0].get("Version", "")).isdigit()
                or published[0].get("CodeSha256") != spec["broker_code_sha256"]
                or published[0].get("FunctionName") != name
                or published[0].get("Description")
                != (
                    f"GUG-376 {version_label} "
                    f"{source_commit} {spec['broker_config_digest']}"
                )
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_VERSIONS_INVALID")
            version = str(published[0]["Version"])
            published_function = self._lambda.get_function(
                FunctionName=name, Qualifier=version
            )
            published_runtime = self._lambda.get_runtime_management_config(
                FunctionName=name, Qualifier=version
            )
            calls += 2
            published_configuration = published_function.get("Configuration")
            if (
                not isinstance(published_configuration, Mapping)
                or published_configuration.get("FunctionArn")
                != (
                    f"arn:aws:lambda:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
                    f"function:{name}:{version}"
                )
                or published_configuration.get("Version") != version
                or published_configuration.get("CodeSha256")
                != spec["broker_code_sha256"]
                or published_configuration.get("RuntimeVersionConfig")
                != runtime_version
                or published_configuration.get("Runtime")
                != configuration["Runtime"]
                or published_configuration.get("Handler")
                != configuration["Handler"]
                or published_configuration.get("Role") != configuration["Role"]
                or published_configuration.get("Timeout")
                != configuration["Timeout"]
                or published_configuration.get("MemorySize")
                != configuration["MemorySize"]
                or published_configuration.get("Architectures")
                != configuration["Architectures"]
                or published_configuration.get("PackageType")
                != configuration["PackageType"]
                or published_configuration.get("Environment")
                != configuration["Environment"]
                or published_configuration.get("TracingConfig")
                != configuration["TracingConfig"]
                or published_configuration.get("EphemeralStorage")
                != configuration["EphemeralStorage"]
                or published_configuration.get("SnapStart")
                != configuration["SnapStart"]
                or published_configuration.get("VpcConfig")
                != configuration["VpcConfig"]
                or published_configuration.get("LoggingConfig")
                != configuration["LoggingConfig"]
                or published_configuration.get("Description")
                != published[0]["Description"]
                or published_runtime.get("FunctionArn")
                != f"{function_arn}:{version}"
                or published_runtime.get("UpdateRuntimeOn") != "FunctionUpdate"
                or published_runtime.get("RuntimeVersionArn") is not None
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_VERSIONS_INVALID")
            raw_aliases = alias_page.get("Aliases")
            if not isinstance(raw_aliases, list):
                raise ConnectedRouteError("BROKER_FUNCTION_ALIASES_INVALID")
            listed_alias_projection = sorted(
                [
                    {
                        "alias_arn": item.get("AliasArn"),
                        "description": item.get("Description", ""),
                        "name": item.get("Name"),
                        "function_version": item.get("FunctionVersion"),
                        "revision_id": item.get("RevisionId"),
                        "routing_config": item.get("RoutingConfig", {}),
                    }
                    for item in raw_aliases
                    if isinstance(item, Mapping)
                ],
                key=lambda item: str(item["name"]),
            )
            if [item["name"] for item in listed_alias_projection] != sorted(
                aliases
            ) or any(
                item["alias_arn"] != f"{function_arn}:{item['name']}"
                or item["description"] != ""
                or item["function_version"] != version
                or not isinstance(item["revision_id"], str)
                or not item["revision_id"]
                or item["routing_config"] != {}
                for item in listed_alias_projection
            ):
                raise ConnectedRouteError("BROKER_FUNCTION_ALIASES_INVALID")
            alias_projection: list[dict[str, Any]] = []
            event_configs: list[dict[str, Any]] = []
            for alias in aliases:
                alias_value = self._lambda.get_alias(
                    FunctionName=name, Name=alias
                )
                invoke = self._lambda.get_function_event_invoke_config(
                    FunctionName=name, Qualifier=alias
                )
                calls += 2
                listed_alias = next(
                    item
                    for item in listed_alias_projection
                    if item["name"] == alias
                )
                if (
                    alias_value.get("AliasArn") != f"{function_arn}:{alias}"
                    or alias_value.get("Name") != alias
                    or alias_value.get("Description", "") != ""
                    or alias_value.get("FunctionVersion") != version
                    or alias_value.get("RevisionId")
                    != listed_alias["revision_id"]
                    or alias_value.get("RoutingConfig", {}) != {}
                    or invoke.get("FunctionArn")
                    != f"{function_arn}:{alias}"
                    or invoke.get("MaximumRetryAttempts") != 0
                    or invoke.get("MaximumEventAgeInSeconds") != 60
                    or invoke.get("DestinationConfig", {}) != {}
                ):
                    raise ConnectedRouteError("BROKER_EVENT_INVOKE_INVALID")
                alias_projection.append(listed_alias)
                event_configs.append(
                    {
                        "alias": alias,
                        "maximum_retries": 0,
                        "maximum_event_age": 60,
                    }
                )
            _require_lambda_resource_policy_absent(
                self._lambda, function_name=name
            )
            calls += 1
            _require_lambda_resource_policy_absent(
                self._lambda, function_name=name, qualifier=version
            )
            calls += 1
            for alias in aliases:
                _require_lambda_resource_policy_absent(
                    self._lambda,
                    function_name=name,
                    qualifier=alias,
                )
                calls += 1
            function_urls = self._lambda.list_function_url_configs(
                FunctionName=name, MaxItems=50
            )
            event_sources = self._lambda.list_event_source_mappings(
                FunctionName=name, MaxItems=100
            )
            calls += 2
            if (
                function_urls.get("FunctionUrlConfigs") != []
                or function_urls.get("NextMarker") is not None
                or event_sources.get("EventSourceMappings") != []
                or event_sources.get("NextMarker") is not None
            ):
                raise ConnectedRouteError(
                    "BROKER_FUNCTION_INVOCATION_AUTHORITY_INVALID"
                )
            live["functions"][logical_id] = {
                "function_arn": configuration["FunctionArn"],
                "code_sha256": configuration["CodeSha256"],
                "environment_digest": route.digest_value(dict(environment)),
                "runtime_config_digest": runtime_config.config_digest,
                "runtime_version_arn_digest": route.digest_value(
                    runtime_version["RuntimeVersionArn"]
                ),
                "tags_digest": route.digest_value(
                    expected_tag_map(logical_id)
                ),
                "published_version": version,
                "aliases": alias_projection,
                "event_configs_digest": route.digest_value(event_configs),
            }
        for logical_id, role_name, policy_name, projection_name in (
            (
                "CreatorRole",
                "ScanalyzeGug376RouteBrokerCreator",
                "ExactBrokerCreation",
                "creator_role_inline_policy",
            ),
            (
                "ExecutorRole",
                "ScanalyzeGug376RouteBrokerExecutor",
                "ExactBrokerExecution",
                "executor_role_inline_policy",
            ),
            (
                "CreateDispatchRecoveryRole",
                "ScanalyzeGug376RouteCreateDispatchRecovery",
                "ExactCreateDispatchRecoveryReadback",
                "create_dispatch_recovery_role_inline_policy",
            ),
            (
                "ExecuteDispatchRecoveryRole",
                "ScanalyzeGug376RouteExecuteDispatchRecovery",
                "ExactExecuteDispatchRecoveryReadback",
                "execute_dispatch_recovery_role_inline_policy",
            ),
        ):
            if resources[logical_id].get("PhysicalResourceId") != role_name:
                raise ConnectedRouteError("BROKER_ROLE_RESOURCE_INVALID")
            role_response = self._iam.get_role(RoleName=role_name)
            policy_names = self._iam.list_role_policies(RoleName=role_name)
            attached_policies = self._iam.list_attached_role_policies(
                RoleName=role_name, MaxItems=1000
            )
            policy_response = self._iam.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
            calls += 4
            role_value = role_response.get("Role")
            policy = policy_response.get("PolicyDocument")
            expected_policy = expected_policy_projection["policies"][
                projection_name
            ]
            try:
                canonical_policy = canonicalize_policy_document(policy)
            except BrokerSeedError as exc:
                raise ConnectedRouteError("BROKER_ROLE_LIVE_INVALID") from exc
            if (
                not isinstance(role_value, Mapping)
                or role_value.get("RoleName") != role_name
                or role_value.get("Path") != "/"
                or role_value.get("Arn")
                != f"arn:aws:iam::{route.AUTHORITY_ACCOUNT_ID}:role/{role_name}"
                or role_value.get("MaxSessionDuration") != 3600
                or "PermissionsBoundary" in role_value
                or role_value.get("AssumeRolePolicyDocument")
                != {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
                or sorted(role_value.get("Tags", []), key=lambda item: item["Key"])
                != expected_tags(logical_id)
                or policy_names.get("IsTruncated") is not False
                or policy_names.get("PolicyNames") != [policy_name]
                or attached_policies.get("IsTruncated") is not False
                or attached_policies.get("AttachedPolicies") != []
                or policy_response.get("RoleName") != role_name
                or policy_response.get("PolicyName") != policy_name
                or expected_policy["selector"]
                != {
                    "role_arn": role_value["Arn"],
                    "role_name": role_name,
                    "policy_name": policy_name,
                }
                or canonical_policy != expected_policy["document"]
                or route.digest_value(canonical_policy)
                != expected_policy["document_digest"]
            ):
                raise ConnectedRouteError("BROKER_ROLE_LIVE_INVALID")
            live["roles"][logical_id] = {
                "arn": role_value["Arn"],
                "trust_digest": route.digest_value(
                    role_value["AssumeRolePolicyDocument"]
                ),
                "policy_name": policy_name,
                "policy_digest": route.digest_value(canonical_policy),
                "tags_digest": route.digest_value(expected_tags(logical_id)),
            }
        table_name = "scanalyze-platform-authority-gug376-route-broker-ledger"
        table_arn = (
            f"arn:aws:dynamodb:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
            f"table/{table_name}"
        )
        expected_key_alias_name = (
            "alias/scanalyze/platform-authority/gug376-route-broker-ledger"
        )
        expected_key_alias_arn = (
            f"arn:aws:kms:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
            f"{expected_key_alias_name}"
        )
        if (
            resources["BrokerLedger"].get("PhysicalResourceId") != table_name
            or resources["BrokerLedgerKeyAlias"].get("PhysicalResourceId")
            not in {expected_key_alias_name, expected_key_alias_arn}
        ):
            raise ConnectedRouteError("BROKER_LEDGER_RESOURCE_INVALID")
        table = self._dynamodb.describe_table(TableName=table_name).get("Table")
        ttl = self._dynamodb.describe_time_to_live(TableName=table_name).get(
            "TimeToLiveDescription"
        )
        backups = self._dynamodb.describe_continuous_backups(
            TableName=table_name
        ).get("ContinuousBackupsDescription")
        resource_policy = self._dynamodb.get_resource_policy(
            ResourceArn=table_arn
        ).get("Policy")
        table_tags = self._dynamodb.list_tags_of_resource(
            ResourceArn=table_arn
        )
        calls += 5
        if not isinstance(resource_policy, str):
            raise ConnectedRouteError("BROKER_LEDGER_POLICY_INVALID")
        try:
            policy_value = canonicalize_policy_document(
                _strict_json_mapping(resource_policy)
            )
        except (ConnectedRouteError, BrokerSeedError) as exc:
            raise ConnectedRouteError("BROKER_LEDGER_POLICY_INVALID") from exc
        expected_ledger_policy = expected_policy_projection["policies"][
            "broker_ledger_resource_policy"
        ]
        if (
            not isinstance(table, Mapping)
            or table.get("TableName") != table_name
            or table.get("TableArn") != table_arn
            or table.get("TableStatus") != "ACTIVE"
            or table.get("BillingModeSummary", {}).get("BillingMode")
            != "PAY_PER_REQUEST"
            or table.get("AttributeDefinitions")
            != [{"AttributeName": "ledger_id", "AttributeType": "S"}]
            or table.get("KeySchema")
            != [{"AttributeName": "ledger_id", "KeyType": "HASH"}]
            or table.get("DeletionProtectionEnabled")
            is not expected_deletion_protection
            or table.get("SSEDescription", {}).get("Status") != "ENABLED"
            or table.get("SSEDescription", {}).get("SSEType") != "KMS"
            or table.get("SSEDescription", {}).get("KMSMasterKeyArn")
            != expected_key_arn
            or "LatestStreamArn" in table
            or "LatestStreamLabel" in table
            or "StreamSpecification" in table
            or table.get("GlobalSecondaryIndexes", []) != []
            or table.get("LocalSecondaryIndexes", []) != []
            or ttl != {"TimeToLiveStatus": "DISABLED"}
            or backups.get("ContinuousBackupsStatus") != "ENABLED"
            or backups.get("PointInTimeRecoveryDescription", {}).get(
                "PointInTimeRecoveryStatus"
            )
            != "ENABLED"
            or backups.get("PointInTimeRecoveryDescription", {}).get(
                "RecoveryPeriodInDays"
            )
            != 35
            or sorted(table_tags.get("Tags", []), key=lambda item: item["Key"])
            != expected_tags("BrokerLedger")
            or table_tags.get("NextToken") is not None
            or expected_ledger_policy["selector"]
            != {"resource_arn": table_arn, "table_name": table_name}
            or policy_value != expected_ledger_policy["document"]
            or route.digest_value(policy_value)
            != expected_ledger_policy["document_digest"]
        ):
            raise ConnectedRouteError("BROKER_LEDGER_LIVE_INVALID")
        key_id = expected_key_id
        key = self._kms.describe_key(KeyId=key_id).get("KeyMetadata")
        rotation = self._kms.get_key_rotation_status(KeyId=key_id)
        key_policy = self._kms.get_key_policy(KeyId=key_id, PolicyName="default").get(
            "Policy"
        )
        key_tags = self._kms.list_resource_tags(KeyId=key_id)
        aliases = self._kms.list_aliases(KeyId=key_id, Limit=100)
        grants, grant_pages = _paginate_tokenized_items(
            self._kms.list_grants,
            request={"KeyId": expected_key_arn, "Limit": 100},
            item_key="Grants",
            request_token_key="Marker",
            response_token_key="NextMarker",
            truncated_key="Truncated",
            error_code="BROKER_KMS_GRANTS_INVALID",
        )
        calls += 5 + grant_pages
        if not isinstance(key_policy, str):
            raise ConnectedRouteError("BROKER_KMS_LIVE_INVALID")
        try:
            key_policy_value = canonicalize_policy_document(
                _strict_json_mapping(key_policy)
            )
        except (ConnectedRouteError, BrokerSeedError) as exc:
            raise ConnectedRouteError("BROKER_KMS_LIVE_INVALID") from exc
        expected_key_policy = expected_policy_projection["policies"][
            "broker_ledger_key_policy"
        ]
        expected_key_alias = expected_key_policy["selector"]["key_id"]
        raw_aliases = aliases.get("Aliases")
        alias_projection = (
            [
                {
                    "AliasName": item.get("AliasName"),
                    "AliasArn": item.get("AliasArn"),
                    "TargetKeyId": item.get("TargetKeyId"),
                }
                for item in raw_aliases
                if isinstance(item, Mapping)
            ]
            if isinstance(raw_aliases, list)
            else None
        )
        expected_grant_context = {
            "aws:dynamodb:subscriberId": route.AUTHORITY_ACCOUNT_ID,
            "aws:dynamodb:tableName": table_name,
        }
        expected_grant_operations = sorted(
            [
                "Decrypt",
                "DescribeKey",
                "Encrypt",
                "GenerateDataKey",
                "ReEncryptFrom",
                "ReEncryptTo",
                "RetireGrant",
            ]
        )
        dynamodb_principal = f"dynamodb.{route.REGION}.amazonaws.com"
        authority_root = f"arn:aws:iam::{route.AUTHORITY_ACCOUNT_ID}:root"
        grant_ids: set[str] = set()
        grant_projection: list[dict[str, Any]] = []
        if not 1 <= len(grants) <= 4:
            raise ConnectedRouteError("BROKER_KMS_GRANTS_INVALID")
        for grant in grants:
            if not isinstance(grant, Mapping):
                raise ConnectedRouteError("BROKER_KMS_GRANTS_INVALID")
            grant_id = grant.get("GrantId")
            grant_name = grant.get("Name")
            operations = grant.get("Operations")
            grantee_principal = grant.get("GranteePrincipal")
            grantee_service_principal = grant.get("GranteeServicePrincipal")
            retiring_principal = grant.get("RetiringPrincipal")
            retiring_service_principal = grant.get("RetiringServicePrincipal")
            constraints = grant.get("Constraints")
            valid_grantee = (
                grantee_principal == dynamodb_principal
                and grantee_service_principal is None
            ) or (
                grantee_principal is None
                and grantee_service_principal == dynamodb_principal
            )
            valid_retiring_principal = (
                retiring_principal == dynamodb_principal
                and retiring_service_principal is None
            ) or (
                retiring_principal is None
                and retiring_service_principal == dynamodb_principal
            )
            valid_constraints = constraints in (
                {"EncryptionContextSubset": expected_grant_context},
                {
                    "EncryptionContextSubset": expected_grant_context,
                    "SourceArn": table_arn,
                },
            )
            if (
                not isinstance(grant_id, str)
                or not 1 <= len(grant_id) <= 128
                or grant_id in grant_ids
                or not isinstance(grant_name, str)
                or len(grant_name) > 256
                or (
                    grant_name
                    and re.fullmatch(r"[A-Za-z0-9:/_-]+", grant_name) is None
                )
                or grant.get("KeyId") != expected_key_arn
                or not valid_grantee
                or not valid_retiring_principal
                or grant.get("IssuingAccount") != authority_root
                or not isinstance(operations, list)
                or any(not isinstance(operation, str) for operation in operations)
                or len(operations) != len(expected_grant_operations)
                or sorted(operations) != expected_grant_operations
                or not valid_constraints
            ):
                raise ConnectedRouteError("BROKER_KMS_GRANTS_INVALID")
            grant_ids.add(grant_id)
            grant_projection.append(
                {
                    "constraints": constraints,
                    "grantee_service": dynamodb_principal,
                    "issuing_account": grant["IssuingAccount"],
                    "key_arn": grant["KeyId"],
                    "operations": sorted(operations),
                    "retiring_service": dynamodb_principal,
                }
            )
        grant_projection.sort(key=route.canonical_json)
        if (
            not isinstance(key, Mapping)
            or key.get("AWSAccountId") != route.AUTHORITY_ACCOUNT_ID
            or key.get("KeyId") != key_id
            or key.get("Arn")
            != f"arn:aws:kms:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:key/{key_id}"
            or key.get("Enabled") is not True
            or key.get("KeyState") != "Enabled"
            or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or key.get("Origin") != "AWS_KMS"
            or key.get("KeyManager") != "CUSTOMER"
            or key.get("MultiRegion") is not False
            or key.get("Description") != "GUG-376 route broker CAS ledger"
            or key.get("KeySpec") != "SYMMETRIC_DEFAULT"
            or key.get("EncryptionAlgorithms") != ["SYMMETRIC_DEFAULT"]
            or key.get("SigningAlgorithms") not in {None}
            or key.get("MacAlgorithms") not in {None}
            or key.get("MultiRegionConfiguration") not in {None}
            or rotation.get("KeyRotationEnabled") is not True
            or rotation.get("RotationPeriodInDays") != 365
            or sorted(
                [
                    {"Key": item.get("TagKey"), "Value": item.get("TagValue")}
                    for item in key_tags.get("Tags", [])
                ],
                key=lambda item: str(item["Key"]),
            )
            != expected_tags("BrokerLedgerKey")
            or key_tags.get("NextMarker") is not None
            or aliases.get("Truncated") is not False
            or aliases.get("NextMarker") is not None
            or alias_projection
            != [
                {
                    "AliasName": expected_key_alias,
                    "AliasArn": expected_key_alias_arn,
                    "TargetKeyId": key_id,
                }
            ]
            or expected_key_policy["selector"]
            != {"key_id": expected_key_alias, "policy_name": "default"}
            or key_policy_value != expected_key_policy["document"]
            or route.digest_value(key_policy_value)
            != expected_key_policy["document_digest"]
        ):
            raise ConnectedRouteError("BROKER_KMS_LIVE_INVALID")
        log_groups = self._logs.describe_log_groups(
            logGroupNamePrefix="/aws/lambda/scanalyze-platform-authority-gug376-route-",
            limit=50,
        )
        calls += 1
        raw_log_groups = log_groups.get("logGroups")
        if (
            log_groups.get("nextToken") is not None
            or not isinstance(raw_log_groups, list)
            or len(raw_log_groups) != 4
        ):
            raise ConnectedRouteError("BROKER_LOG_GROUPS_INVALID")
        log_contracts = {
            "CreatorLogGroup": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-creator"
            ),
            "ExecutorLogGroup": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-executor"
            ),
            "CreateDispatchRecoveryLogGroup": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-create-dispatch-recovery"
            ),
            "ExecuteDispatchRecoveryLogGroup": (
                "/aws/lambda/scanalyze-platform-authority-gug376-route-execute-dispatch-recovery"
            ),
        }
        log_group_arns = tuple(
            f"arn:aws:logs:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
            f"log-group:{log_group_name}"
            for log_group_name in log_contracts.values()
        )
        observed_log_groups = {
            item.get("logGroupName"): item
            for item in raw_log_groups
            if isinstance(item, Mapping)
        }
        log_projection: list[dict[str, Any]] = []
        for logical_id, log_group_name in log_contracts.items():
            log_group_arn = (
                f"arn:aws:logs:{route.REGION}:{route.AUTHORITY_ACCOUNT_ID}:"
                f"log-group:{log_group_name}"
            )
            item = observed_log_groups.get(log_group_name)
            tags = self._logs.list_tags_for_resource(resourceArn=log_group_arn)
            subscriptions, subscription_pages = _paginate_tokenized_items(
                self._logs.describe_subscription_filters,
                request={"logGroupName": log_group_name, "limit": 50},
                item_key="subscriptionFilters",
                request_token_key="nextToken",
                response_token_key="nextToken",
                error_code="BROKER_LOG_SUBSCRIPTIONS_INVALID",
            )
            resource_policies, resource_policy_pages = _paginate_tokenized_items(
                self._logs.describe_resource_policies,
                request={
                    "policyScope": "RESOURCE",
                    "resourceArn": log_group_arn,
                    "limit": 50,
                },
                item_key="resourcePolicies",
                request_token_key="nextToken",
                response_token_key="nextToken",
                error_code="BROKER_LOG_RESOURCE_POLICIES_INVALID",
            )
            calls += 1 + subscription_pages + resource_policy_pages
            if subscriptions != []:
                raise ConnectedRouteError("BROKER_LOG_SUBSCRIPTIONS_INVALID")
            if resource_policies != []:
                raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
            if (
                resources[logical_id].get("PhysicalResourceId")
                != log_group_name
                or not isinstance(item, Mapping)
                or item.get("arn") != f"{log_group_arn}:*"
                or item.get("logGroupArn") != log_group_arn
                or item.get("retentionInDays") != 30
                or item.get("kmsKeyId") not in {None, ""}
                or item.get("logGroupClass", "STANDARD") != "STANDARD"
                or item.get("dataProtectionStatus") is not None
                or item.get("deletionProtectionEnabled", False) is not False
                or item.get("bearerTokenAuthenticationEnabled", False)
                is not False
                or item.get("inheritedProperties", []) != []
                or tags.get("tags") != expected_tag_map(logical_id)
            ):
                raise ConnectedRouteError("BROKER_LOG_GROUPS_INVALID")
            log_projection.append(
                {
                    "arn": log_group_arn,
                    "name": log_group_name,
                    "retention": 30,
                    "resource_policy_count": 0,
                    "subscription_filter_count": 0,
                    "tags_digest": route.digest_value(
                        expected_tag_map(logical_id)
                    ),
                }
            )
        account_policies, account_policy_pages = _paginate_tokenized_items(
            self._logs.describe_resource_policies,
            request={"policyScope": "ACCOUNT", "limit": 50},
            item_key="resourcePolicies",
            request_token_key="nextToken",
            response_token_key="nextToken",
            error_code="BROKER_LOG_RESOURCE_POLICIES_INVALID",
        )
        calls += account_policy_pages
        account_policy_names: set[str] = set()
        account_policy_projection: list[dict[str, Any]] = []
        for policy in account_policies:
            if not isinstance(policy, Mapping):
                raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
            policy_name = policy.get("policyName")
            revision_id = policy.get("revisionId")
            last_updated = policy.get("lastUpdatedTime")
            policy_resource_arn = policy.get("resourceArn")
            if (
                not isinstance(policy_name, str)
                or not policy_name
                or policy_name in account_policy_names
                or policy.get("policyScope", "ACCOUNT") != "ACCOUNT"
                or (
                    policy_resource_arn is not None
                    and policy_resource_arn != ""
                )
                or (
                    revision_id is not None
                    and (not isinstance(revision_id, str) or not revision_id)
                )
                or (
                    last_updated is not None
                    and (type(last_updated) is not int or last_updated < 0)
                )
            ):
                raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
            try:
                policy_document = _strict_json_mapping(policy.get("policyDocument"))
            except ValueError as exc:
                raise ConnectedRouteError(
                    "BROKER_LOG_RESOURCE_POLICIES_INVALID"
                ) from exc
            if _log_policy_references_any(
                policy_document, resource_arns=log_group_arns
            ):
                raise ConnectedRouteError("BROKER_LOG_RESOURCE_POLICIES_INVALID")
            account_policy_names.add(policy_name)
            account_policy_projection.append(
                {
                    "document_digest": route.digest_value(policy_document),
                    "policy_name": policy_name,
                    "policy_scope": "ACCOUNT",
                }
            )
        account_policy_projection.sort(key=lambda item: item["policy_name"])
        log_projection.sort(key=lambda item: item["name"])
        live["ledger"] = {
            "table_arn": table["TableArn"],
            "kms_key_arn": key["Arn"],
            "resource_policy_digest": route.digest_value(policy_value),
            "key_policy_digest": route.digest_value(key_policy_value),
            "table_tags_digest": route.digest_value(
                expected_tags("BrokerLedger")
            ),
            "key_tags_digest": route.digest_value(
                expected_tags("BrokerLedgerKey")
            ),
            "grant_count": len(grant_projection),
            "grant_semantics_digest": route.digest_value(grant_projection),
        }
        live["log_groups"] = log_projection
        live["log_resource_policy_inventory_digest"] = route.digest_value(
            account_policy_projection
        )
        live["effective_policy_projection_digest"] = (
            expected_policy_projection["projection_digest"]
        )
        return route.digest_value(live), calls

    def terminal_readback(
        self,
        *,
        seed_intent: Mapping[str, Any],
        execution_intent: Mapping[str, Any],
        execution_receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        seed = route.validate_seed_intent(seed_intent)
        recovery: Any | None = None
        if execution_intent.get("record_type") == route.RECORD_TYPE_EXECUTION_INTENT:
            execution = route.validate_execution_intent(execution_intent)
            expected_receipt_record_type = EXECUTION_RECEIPT_RECORD_TYPE
            expected_receipt_fields = _EXECUTION_RECEIPT_FIELDS
        else:
            # Import lazily because the recovery provider builds on this
            # connected provider.  Re-entry is accepted only through its
            # sealed, exact-field validator; arbitrary alternate intent types
            # never fall through to the terminal readback.
            from tooling import (
                platform_authority_plan_permission_repair_deployment_recovery
                as recovery,
            )

            try:
                execution = recovery.validate_reentry_execution_intent_structure(
                    execution_intent
                )
            except recovery.DeploymentRecoveryError as exc:
                raise ConnectedRouteError(exc.code) from exc
            expected_receipt_record_type = (
                recovery.REENTRY_EXECUTION_RECEIPT_RECORD_TYPE
            )
            expected_receipt_fields = _EXECUTION_RECEIPT_FIELDS | {"attempt"}
        normalized_now = _recovery_window(execution, self._clock)
        if (
            not isinstance(execution_receipt, Mapping)
            or set(execution_receipt) != expected_receipt_fields
        ):
            raise ConnectedRouteError("EXECUTION_RECEIPT_FIELDS_INVALID")
        try:
            route._verify_seal(execution_receipt, "receipt_digest", "EXECUTION_RECEIPT_DIGEST_INVALID")
        except route.RouteSeedError as exc:
            raise ConnectedRouteError(exc.code) from exc
        target = execution["target"]
        spec = seed["targets"][target]
        expected_stack_status = (
            "UPDATE_COMPLETE"
            if target == route.BROKER_PROTECTION_TARGET
            else "CREATE_COMPLETE"
        )
        if (
            execution.get("parent_intent_digest") != seed["intent_digest"]
            or execution.get("source_commit") != seed["source_commit"]
            or execution_receipt.get("schema_version") != 1
            or execution_receipt.get("record_type")
            != expected_receipt_record_type
            or (recovery is not None and execution_receipt.get("attempt") != 1)
            or execution_receipt.get("source_commit") != seed["source_commit"]
            or execution_receipt.get("execution_intent_digest") != execution["execution_intent_digest"]
            or execution_receipt.get("target") != target
            or execution_receipt.get("account_id") != execution["account_id"]
            or execution_receipt.get("stack_arn") != execution["execute_request"]["StackName"]
            or execution_receipt.get("change_set_arn") != execution["execute_request"]["ChangeSetName"]
            or execution_receipt.get("aws_mutations") != 1
            or execution_receipt.get("retry_permitted") is not False
            or execution_receipt.get("production_authorized") is not False
            or execution_receipt.get("production_status") != route.PRODUCTION_STATUS
            or _UUID_RE.fullmatch(
                str(execution_receipt.get("execute_request_id", ""))
            )
            is None
        ):
            raise ConnectedRouteError("EXECUTION_RECEIPT_INVALID")
        dispatched_at = _parse_time(
            execution_receipt.get("dispatched_at"), "EXECUTION_RECEIPT_INVALID"
        )
        if not _parse_time(
            execution["authorization_not_before"], "EXECUTION_RECEIPT_INVALID"
        ) <= dispatched_at < _parse_time(
            execution["authorization_expires_at"], "EXECUTION_RECEIPT_INVALID"
        ):
            raise ConnectedRouteError("EXECUTION_RECEIPT_INVALID")
        account_id, caller = _verify_identity(
            self._sts, target=target, phase="executor"
        )
        stack_response = self._cfn.describe_stacks(
            StackName=execution_receipt["stack_arn"]
        )
        stacks = stack_response.get("Stacks")
        if (
            not isinstance(stacks, list)
            or len(stacks) != 1
            or stack_response.get("NextToken") is not None
        ):
            raise ConnectedRouteError("TERMINAL_READBACK_INCOMPLETE")
        stack = stacks[0]
        if stack.get("StackStatus") != expected_stack_status:
            raise ConnectedRouteError("STACK_NOT_TERMINAL")
        updated = (
            stack.get("LastUpdatedTime")
            if target == route.BROKER_PROTECTION_TARGET
            else stack.get("CreationTime")
        )
        stack_parameters = [
            {
                "ParameterKey": item.get("ParameterKey"),
                "ParameterValue": item.get("ParameterValue"),
            }
            for item in stack.get("Parameters", [])
            if isinstance(item, Mapping)
        ]
        expected_parameters = spec["create_request"].get("Parameters", [])
        if (
            len(stack_parameters) != len(expected_parameters)
            or len({item["ParameterKey"] for item in stack_parameters})
            != len(stack_parameters)
        ):
            raise ConnectedRouteError("TERMINAL_STACK_INVALID")
        observed_parameter_map = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in stack_parameters
        }
        expected_parameter_map = {
            item["ParameterKey"]: item["ParameterValue"]
            for item in expected_parameters
        }
        if set(observed_parameter_map) != set(expected_parameter_map) or any(
            observed_parameter_map[key] != expected_parameter_map[key]
            for key in expected_parameter_map
        ):
            raise ConnectedRouteError("TERMINAL_STACK_INVALID")
        if (
            stack.get("StackId") != execution_receipt["stack_arn"]
            or stack.get("StackName") != spec["stack_name"]
            or "RoleARN" in stack
            or "ParentId" in stack
            or "RootId" in stack
            or stack.get("NotificationARNs", []) != []
            or stack.get("Capabilities", [])
            != spec["create_request"]["Capabilities"]
            or stack.get("Tags", []) != spec["create_request"]["Tags"]
            or stack.get("EnableTerminationProtection", False) is not False
            or not isinstance(updated, datetime)
            or updated.astimezone(timezone.utc)
            < _parse_time(execution_receipt["dispatched_at"], "EXECUTION_RECEIPT_INVALID")
        ):
            raise ConnectedRouteError("TERMINAL_STACK_INVALID")
        resources_response = self._cfn.list_stack_resources(
            StackName=execution_receipt["stack_arn"]
        )
        raw_resources = resources_response.get("StackResourceSummaries")
        if (
            not isinstance(raw_resources, list)
            or resources_response.get("NextToken") is not None
        ):
            raise ConnectedRouteError("TERMINAL_RESOURCES_INCOMPLETE")
        resource_map: dict[str, Mapping[str, Any]] = {}
        protection_change_ids = {
            item["logical_resource_id"] for item in spec["expected_changes"]
        }
        for item in raw_resources:
            logical_id = item.get("LogicalResourceId") if isinstance(item, Mapping) else None
            if target == route.BROKER_PROTECTION_TARGET:
                expected_resource_statuses = (
                    {"UPDATE_COMPLETE"}
                    if logical_id == "BrokerLedger"
                    else (
                        {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                        if logical_id in protection_change_ids
                        else {"CREATE_COMPLETE"}
                    )
                )
            else:
                expected_resource_statuses = {"CREATE_COMPLETE"}
            if (
                not isinstance(logical_id, str)
                or not logical_id
                or logical_id in resource_map
                or not isinstance(item.get("PhysicalResourceId"), str)
                or not item.get("PhysicalResourceId")
                or item.get("ResourceStatus") not in expected_resource_statuses
            ):
                raise ConnectedRouteError("TERMINAL_RESOURCES_INVALID")
            resource_map[logical_id] = item
        resources = sorted(
            [
                {
                    "logical_resource_id": item.get("LogicalResourceId"),
                    "resource_type": item.get("ResourceType"),
                }
                for item in raw_resources
                if isinstance(item, Mapping)
            ],
            key=lambda item: str(item["logical_resource_id"]),
        )
        if resources != spec["expected_resources"]:
            raise ConnectedRouteError("TERMINAL_RESOURCE_INVENTORY_INVALID")
        template_response = self._cfn.get_template(
            StackName=execution_receipt["stack_arn"], TemplateStage="Original"
        )
        template_body = template_response.get("TemplateBody")
        if not isinstance(template_body, str):
            raise ConnectedRouteError("TERMINAL_TEMPLATE_INVALID")
        template_digest = route.bytes_digest(template_body.encode("utf-8"))
        if template_digest != spec["template_digest"]:
            raise ConnectedRouteError("TERMINAL_TEMPLATE_INVALID")
        raw_outputs = stack.get("Outputs")
        if not isinstance(raw_outputs, list):
            raise ConnectedRouteError("TERMINAL_OUTPUTS_INVALID")
        outputs: dict[str, str] = {}
        for item in raw_outputs:
            if (
                not isinstance(item, Mapping)
                or not isinstance(item.get("OutputKey"), str)
                or not isinstance(item.get("OutputValue"), str)
                or item["OutputKey"] in outputs
            ):
                raise ConnectedRouteError("TERMINAL_OUTPUTS_INVALID")
            outputs[item["OutputKey"]] = item["OutputValue"]
        if sorted(outputs) != spec["expected_outputs"]:
            raise ConnectedRouteError("TERMINAL_OUTPUTS_INVALID")
        assignments: list[dict[str, str]] = []
        live_properties_digest = route.digest_value([])
        live_property_read_count = 0
        if target == "route":
            if (
                outputs.get("SeedAssignmentMode") != "true"
                or outputs.get("BrokerInvokerAssignmentMode") != "true"
                or outputs.get("CleanupOrder") != "SEED_FALSE_KEEP_INVOKER_THEN_CLOSEOUT_FALSE_FALSE"
                or outputs.get("BrokerStackName") != route.BROKER_STACK_NAME
                or outputs.get("ProductionAuthorized") != "false"
            ):
                raise ConnectedRouteError("TERMINAL_OUTPUTS_INVALID")
            permission_keys = (
                "BrokerSeedCreatorPermissionSetArn",
                "BrokerSeedExecutorPermissionSetArn",
                "BrokerInvokerPermissionSetArn",
            )
            permission_contracts = _route_permission_set_contracts(
                template_body=template_body,
                create_parameters=spec["create_request"]["Parameters"],
                outputs=outputs,
            )
            permission_projection: list[dict[str, Any]] = []
            try:
                from tooling.platform_authority_plan_permission_repair_broker_seed import (
                    BrokerSeedError,
                    canonicalize_policy_document,
                )
            except ImportError as exc:
                raise ConnectedRouteError(
                    "ROUTE_PERMISSION_SET_READBACK_INVALID"
                ) from exc
            for key in permission_keys:
                permission_set_arn = outputs[key]
                contract = permission_contracts[key]
                permission_response = self._sso.describe_permission_set(
                    InstanceArn=seed["identity_center_instance_arn"],
                    PermissionSetArn=permission_set_arn,
                )
                inline_response = self._sso.get_inline_policy_for_permission_set(
                    InstanceArn=seed["identity_center_instance_arn"],
                    PermissionSetArn=permission_set_arn,
                )
                boundary_response = self._sso.get_permissions_boundary_for_permission_set(
                    InstanceArn=seed["identity_center_instance_arn"],
                    PermissionSetArn=permission_set_arn,
                )
                live_property_read_count += 3
                managed, pages = _paginate_items(
                    self._sso.list_managed_policies_in_permission_set,
                    request={
                        "InstanceArn": seed["identity_center_instance_arn"],
                        "PermissionSetArn": permission_set_arn,
                        "MaxResults": 100,
                    },
                    item_key="AttachedManagedPolicies",
                    error_code="ROUTE_PERMISSION_SET_READBACK_INVALID",
                )
                live_property_read_count += pages
                customer, pages = _paginate_items(
                    self._sso.list_customer_managed_policy_references_in_permission_set,
                    request={
                        "InstanceArn": seed["identity_center_instance_arn"],
                        "PermissionSetArn": permission_set_arn,
                        "MaxResults": 100,
                    },
                    item_key="CustomerManagedPolicyReferences",
                    error_code="ROUTE_PERMISSION_SET_READBACK_INVALID",
                )
                live_property_read_count += pages
                tags, pages = _paginate_items(
                    self._sso.list_tags_for_resource,
                    request={
                        "InstanceArn": seed["identity_center_instance_arn"],
                        "ResourceArn": permission_set_arn,
                    },
                    item_key="Tags",
                    error_code="ROUTE_PERMISSION_SET_READBACK_INVALID",
                )
                live_property_read_count += pages
                permission = permission_response.get("PermissionSet")
                raw_inline = inline_response.get("InlinePolicy")
                if not isinstance(raw_inline, str):
                    raise ConnectedRouteError(
                        "ROUTE_PERMISSION_SET_READBACK_INVALID"
                    )
                try:
                    live_inline = canonicalize_policy_document(
                        _strict_json_mapping(raw_inline)
                    )
                except (ConnectedRouteError, BrokerSeedError) as exc:
                    raise ConnectedRouteError(
                        "ROUTE_PERMISSION_SET_READBACK_INVALID"
                    ) from exc
                if (
                    not isinstance(permission, Mapping)
                    or permission.get("PermissionSetArn") != permission_set_arn
                    or permission.get("Name") != contract["name"]
                    or permission.get("SessionDuration")
                    != contract["session_duration"]
                    or permission.get("Description") not in {None, ""}
                    or permission.get("RelayState") not in {None, ""}
                    or live_inline != contract["inline_policy"]
                    or managed != []
                    or customer != []
                    or boundary_response.get("PermissionsBoundary") is not None
                    or sorted(tags, key=lambda item: item.get("Key", ""))
                    != contract["tags"]
                ):
                    raise ConnectedRouteError(
                        "ROUTE_PERMISSION_SET_READBACK_INVALID"
                    )
                permission_projection.append(
                    {
                        "output_key": key,
                        "permission_set_arn": permission_set_arn,
                        "name": contract["name"],
                        "session_duration": contract["session_duration"],
                        "inline_policy_digest": route.digest_value(live_inline),
                        "attachments_absent": True,
                        "permissions_boundary_absent": True,
                        "tags_digest": route.digest_value(contract["tags"]),
                    }
                )
                next_token: str | None = None
                seen: set[str] = set()
                found: list[Mapping[str, Any]] = []
                while True:
                    request = {
                        "InstanceArn": seed["identity_center_instance_arn"],
                        "AccountId": route.AUTHORITY_ACCOUNT_ID,
                        "PermissionSetArn": permission_set_arn,
                        "MaxResults": 100,
                    }
                    if next_token is not None:
                        request["NextToken"] = next_token
                    response = self._sso.list_account_assignments(**request)
                    page = response.get("AccountAssignments")
                    if not isinstance(page, list):
                        raise ConnectedRouteError("ASSIGNMENT_READBACK_INVALID")
                    found.extend(page)
                    token = response.get("NextToken")
                    if token is None:
                        break
                    if not isinstance(token, str) or not token or token in seen or len(seen) >= 99:
                        raise ConnectedRouteError("ASSIGNMENT_READBACK_INVALID")
                    seen.add(token)
                    next_token = token
                expected = {
                    "AccountId": route.AUTHORITY_ACCOUNT_ID,
                    "PermissionSetArn": permission_set_arn,
                    "PrincipalId": seed["bootstrap_principal_id"],
                    "PrincipalType": "USER",
                }
                if found != [expected]:
                    raise ConnectedRouteError("ASSIGNMENT_READBACK_INVALID")
                assignments.append(
                    {"output_key": key, "permission_set_arn": permission_set_arn}
                )
            live_properties_digest = route.digest_value(permission_projection)
        else:
            if (
                outputs.get("ParametersAccepted") != "false"
                or outputs.get("ProductionAuthorized") != "false"
                or outputs.get("BrokerLedgerDeletionProtectionMode")
                != (
                    "true"
                    if target == route.BROKER_PROTECTION_TARGET
                    else "false"
                )
                or outputs.get("BrokerLedgerName")
                != "scanalyze-platform-authority-gug376-route-broker-ledger"
                or outputs.get("ManagementCreatorRoleArn")
                != "arn:aws:iam::839393571433:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerCreator"
                or outputs.get("ManagementExecutorRoleArn")
                != "arn:aws:iam::839393571433:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerExecutor"
                or outputs.get("ManagementRecoveryRoleArn")
                != "arn:aws:iam::839393571433:role/scanalyze/platform-authority/ScanalyzeGug376RouteBrokerRecovery"
                or outputs.get("CreatorFunctionArn")
                != "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug376-route-creator"
                or outputs.get("ExecutorFunctionArn")
                != "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug376-route-executor"
                or outputs.get("CreateDispatchRecoveryAliasArn")
                != "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug376-route-create-dispatch-recovery:recover-v1"
                or outputs.get("ExecuteDispatchRecoveryAliasArn")
                != "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug376-route-execute-dispatch-recovery:recover-v1"
            ):
                raise ConnectedRouteError("TERMINAL_OUTPUTS_INVALID")
            live_properties_digest, live_property_read_count = (
                self._broker_live_readback(
                    seed=seed,
                    spec=spec,
                    resources=resource_map,
                    stack_arn=execution_receipt["stack_arn"],
                    expected_deletion_protection=(
                        target == route.BROKER_PROTECTION_TARGET
                    ),
                )
            )
        if recovery is None:
            execute_cloudtrail_digest, cloudtrail_read_count = (
                self._cloudtrail_execute_digest(
                    execution=execution,
                    receipt=execution_receipt,
                    caller_arn=caller,
                    now=normalized_now,
                )
            )
        else:
            try:
                execute_cloudtrail_digest, cloudtrail_read_count = (
                    recovery.reentry_execute_event_digest(
                        cloudtrail=self._trail,
                        claims=self._claims,
                        execution_intent=execution,
                        execution_receipt=execution_receipt,
                        observed_at=normalized_now,
                    )
                )
            except recovery.DeploymentRecoveryError as exc:
                raise ConnectedRouteError(exc.code) from exc
        receipt = {
            "schema_version": 1,
            "record_type": TERMINAL_RECEIPT_RECORD_TYPE,
            "source_commit": seed["source_commit"],
            "target": target,
            "account_id": account_id,
            "execution_receipt_digest": execution_receipt["receipt_digest"],
            "execute_cloudtrail_event_digest": execute_cloudtrail_digest,
            "stack_arn": execution_receipt["stack_arn"],
            "stack_status": expected_stack_status,
            "template_digest": template_digest,
            "resource_count": len(resources),
            "resources_digest": route.digest_value(resources),
            "outputs_digest": route.digest_value(outputs),
            "assignment_count": len(assignments),
            "assignments_digest": route.digest_value(assignments),
            "live_property_read_count": live_property_read_count,
            "live_properties_digest": live_properties_digest,
            "read_at": _timestamp(normalized_now),
            "aws_calls": (
                4
                + cloudtrail_read_count
                + len(assignments)
                + live_property_read_count
            ),
            "aws_mutations": 0,
            "retry_permitted": False,
            "production_authorized": False,
            "production_status": route.PRODUCTION_STATUS,
        }
        return route.seal(receipt, "readback_digest")


__all__ = [
    "CLAIM_RECORD_TYPE",
    "ConnectedRouteError",
    "ConnectedSeedProvider",
    "DISPATCH_RECORD_TYPE",
    "EXECUTION_RECEIPT_RECORD_TYPE",
    "OExclClaimStore",
    "TERMINAL_RECEIPT_RECORD_TYPE",
    "clients_from_session",
    "sdk_client_config",
    "validate_dispatch",
]
