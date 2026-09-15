"""Structural verification of GUG215 HTTP API readbacks; no I/O or authority.

The collector must call every API against the exact expected ApiId, using the
execution-role client and one shared deadline, and bracket ExportApi with two
GetStages calls. These supplied objects do NOT authenticate their own origin.
An independently approved post-publication binding remains mandatory in the
installer/materializer. No digest or local result here grants permission.

AWS distinguishes an exported stage from the latest, possibly undeployed API:
https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-export.html
IAM and integration encodings (inline or one local component reference):
https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions-authtype.html
https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-extensions-integrations.html

Only these documented representations are accepted. No live export has been
collected for this implementation; an unrecognized representation fails closed.
The stage reads detect observed drift, not atomicity with a subsequent effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import math
import re
from typing import Any, Mapping


MAX_EXPORT_BYTES = 262_144
_ACCOUNT = "042360977644"
_REGION = "us-east-1"
_STAGE = "retirement"
_OPERATIONS = ("classify", "retire", "reconcile")
_VERSION_ARN = re.compile(
    r"arn:aws:lambda:us-east-1:042360977644:function:"
    r"scanalyze-platform-authority-gug215-retirement:[1-9][0-9]{0,7}"
)
_ID = re.compile(r"[a-zA-Z0-9_-]{1,64}")


class WorkforceStageBindingError(ValueError):
    """A static code only; supplied values and provider details never escape."""


@dataclass(frozen=True, slots=True)
class VerifiedWorkforceStage:
    """Matching metadata only, not authentication or deployment authorization."""

    api_id: str
    deployment_id: str
    function_version_arn: str


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise WorkforceStageBindingError(code)


def _snapshot(value: Any, budget: list[int], depth: int = 0) -> Any:
    budget[0] -= 1
    _require(budget[0] >= 0 and depth <= 24, "STAGE_READBACK_LIMIT")
    if type(value) is dict:
        _require(all(type(key) is str for key in value), "STAGE_READBACK_INVALID")
        return {_snapshot(key, budget, depth + 1): _snapshot(item, budget, depth + 1)
                for key, item in value.items()}
    if type(value) is list:
        return [_snapshot(item, budget, depth + 1) for item in value]
    if type(value) is str:
        _require(len(value.encode("utf-8", "strict")) <= MAX_EXPORT_BYTES, "STAGE_READBACK_LIMIT")
        return value
    if value is None or type(value) in (bool, int, datetime):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise WorkforceStageBindingError("STAGE_READBACK_INVALID")


def _object(value: Any, code: str) -> dict:
    _require(type(value) is dict, code)
    return value


def _keys(value: dict, allowed: set[str], code: str) -> None:
    _require(set(value) <= allowed, code)


def _empty(value: dict, names: tuple[str, ...], code: str) -> None:
    for name in names:
        _require(name not in value or value[name] in (None, "", [], {}), code)


def _false(value: dict, name: str, code: str) -> None:
    _require(name not in value or value[name] is False, code)


def _response(value: Any) -> dict:
    value = _object(value, "STAGE_READBACK_INVALID")
    if "ResponseMetadata" in value:
        metadata = _object(value["ResponseMetadata"], "STAGE_RESPONSE_INVALID")
        _require(type(metadata.get("HTTPStatusCode")) is int
                 and metadata["HTTPStatusCode"] == 200
                 and ("RetryAttempts" not in metadata or
                      type(metadata["RetryAttempts"]) is int and metadata["RetryAttempts"] == 0),
                 "STAGE_RESPONSE_INVALID")
    return value


def _items(value: Any, count: int) -> list[dict]:
    value = _response(value)
    _keys(value, {"Items", "ResponseMetadata"}, "STAGE_PAGINATION_OR_FIELDS_INVALID")
    items = value.get("Items")
    _require(type(items) is list and len(items) == count, "STAGE_RESOURCE_SET_INVALID")
    return [_object(item, "STAGE_RESOURCE_INVALID") for item in items]


def _stage(value: Any) -> str:
    stage = _items(value, 1)[0]
    _keys(stage, {"StageName", "DeploymentId", "AutoDeploy", "StageVariables", "ApiGatewayManaged",
                  "AccessLogSettings", "ClientCertificateId", "CreatedDate", "DefaultRouteSettings",
                  "Description", "LastDeploymentStatusMessage", "LastUpdatedDate", "RouteSettings", "Tags"},
          "STAGE_CONFIGURATION_INVALID")
    deployment = stage.get("DeploymentId")
    _require(stage.get("StageName") == _STAGE and stage.get("AutoDeploy") is False
             and type(deployment) is str and _ID.fullmatch(deployment) is not None,
             "STAGE_CONFIGURATION_INVALID")
    _empty(stage, ("StageVariables", "ClientCertificateId", "LastDeploymentStatusMessage"),
           "STAGE_CONFIGURATION_INVALID")
    _false(stage, "ApiGatewayManaged", "STAGE_CONFIGURATION_INVALID")
    return deployment


def _numeric_uri(uri: Any, expected: str) -> bool:
    return type(uri) is str and uri in (
        expected,
        "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/" + expected + "/invocations",
    )


def _integration(value: dict, expected: str, *, exported: bool) -> None:
    if exported:
        _keys(value, {"type", "httpMethod", "uri", "payloadFormatVersion", "connectionType",
                      "timeoutInMillis", "passthroughBehavior", "credentials", "connectionId",
                      "requestParameters", "requestTemplates", "responses", "responseParameters",
                      "integrationSubtype", "tlsConfig"}, "STAGE_INTEGRATION_INVALID")
        kind, method, uri, payload = (value.get(name) for name in
                                     ("type", "httpMethod", "uri", "payloadFormatVersion"))
        connection, timeout = "connectionType", "timeoutInMillis"
        absent = ("credentials", "connectionId", "requestParameters", "requestTemplates", "responses",
                  "responseParameters", "integrationSubtype", "tlsConfig")
        passthrough = "passthroughBehavior"
    else:
        _keys(value, {"IntegrationId", "IntegrationType", "IntegrationMethod", "IntegrationUri",
                      "PayloadFormatVersion", "ConnectionType", "TimeoutInMillis", "PassthroughBehavior",
                      "CredentialsArn", "ConnectionId", "RequestParameters", "ResponseParameters",
                      "IntegrationSubtype", "TlsConfig", "ApiGatewayManaged", "ContentHandlingStrategy",
                      "Description", "TemplateSelectionExpression"}, "STAGE_INTEGRATION_INVALID")
        kind, method, uri, payload = (value.get(name) for name in
                                     ("IntegrationType", "IntegrationMethod", "IntegrationUri", "PayloadFormatVersion"))
        connection, timeout = "ConnectionType", "TimeoutInMillis"
        absent = ("CredentialsArn", "ConnectionId", "RequestParameters", "ResponseParameters",
                  "IntegrationSubtype", "TlsConfig", "ContentHandlingStrategy", "TemplateSelectionExpression")
        passthrough = "PassthroughBehavior"
        _false(value, "ApiGatewayManaged", "STAGE_INTEGRATION_INVALID")
    _require(kind in ({"aws_proxy", "AWS_PROXY"} if exported else {"AWS_PROXY"})
             and method == "POST" and payload == "2.0" and _numeric_uri(uri, expected),
             "STAGE_INTEGRATION_TARGET_INVALID")
    _require(connection not in value or value[connection] == "INTERNET", "STAGE_INTEGRATION_INVALID")
    _require(timeout not in value or type(value[timeout]) is int and 1 <= value[timeout] <= 30000,
             "STAGE_INTEGRATION_INVALID")
    _require(passthrough not in value or value[passthrough] in
             ("when_no_match", "when_no_templates", "never"), "STAGE_INTEGRATION_INVALID")
    _empty(value, absent, "STAGE_INTEGRATION_INVALID")


def _strict_json(raw: bytes) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_EXPORT_BYTES, "STAGE_EXPORT_SIZE_INVALID")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            _require(key not in result, "STAGE_EXPORT_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise WorkforceStageBindingError("STAGE_EXPORT_JSON_INVALID")

    document = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)
    return _object(_snapshot(document, [12000]), "STAGE_EXPORT_JSON_INVALID")


def _iam_security(value: Any, schemes: dict) -> None:
    _require(type(value) is list and len(value) == 1 and type(value[0]) is dict
             and len(value[0]) == 1, "STAGE_EXPORT_AUTH_INVALID")
    name, scopes = next(iter(value[0].items()))
    _require(scopes == [] and type(scopes) is list and name in schemes, "STAGE_EXPORT_AUTH_INVALID")
    scheme = _object(schemes[name], "STAGE_EXPORT_AUTH_INVALID")
    _keys(scheme, {"type", "name", "in", "x-amazon-apigateway-authtype", "description"}, "STAGE_EXPORT_AUTH_INVALID")
    _require(scheme.get("type") == "apiKey" and scheme.get("name") == "Authorization"
             and scheme.get("in") == "header" and scheme.get("x-amazon-apigateway-authtype") == "awsSigv4",
             "STAGE_EXPORT_AUTH_INVALID")


def _export(document: dict, api_id: str, version_arn: str) -> None:
    _keys(document, {"openapi", "info", "servers", "paths", "components", "security", "tags", "externalDocs",
                     "x-amazon-apigateway-importexport-version"}, "STAGE_EXPORT_FIELDS_INVALID")
    _require(document.get("openapi") in ("3.0.0", "3.0.1", "3.0.2", "3.0.3"), "STAGE_EXPORT_FORMAT_INVALID")
    _require("x-amazon-apigateway-importexport-version" not in document
             or document["x-amazon-apigateway-importexport-version"] == "1.0", "STAGE_EXPORT_FORMAT_INVALID")
    if "servers" in document:
        servers = document["servers"]
        _require(type(servers) is list and len(servers) == 1, "STAGE_EXPORT_SERVER_INVALID")
        server = _object(servers[0], "STAGE_EXPORT_SERVER_INVALID")
        _keys(server, {"url", "variables", "description"}, "STAGE_EXPORT_SERVER_INVALID")
        host = f"https://{api_id}.execute-api.{_REGION}.amazonaws.com"
        if server.get("url") == host + "/{basePath}":
            _require(server.get("variables") == {"basePath": {"default": _STAGE}}, "STAGE_EXPORT_SERVER_INVALID")
        else:
            _require(server.get("url") == host + "/" + _STAGE and "variables" not in server,
                     "STAGE_EXPORT_SERVER_INVALID")
    components = _object(document.get("components"), "STAGE_EXPORT_COMPONENTS_INVALID")
    _keys(components, {"securitySchemes", "x-amazon-apigateway-integrations", "schemas"},
          "STAGE_EXPORT_COMPONENTS_INVALID")
    schemes = _object(components.get("securitySchemes"), "STAGE_EXPORT_AUTH_INVALID")
    _require(len(schemes) == 1, "STAGE_EXPORT_AUTH_INVALID")
    if "security" in document:
        _iam_security(document["security"], schemes)
    paths = _object(document.get("paths"), "STAGE_EXPORT_ROUTES_INVALID")
    _require(set(paths) == {"/" + operation for operation in _OPERATIONS}, "STAGE_EXPORT_ROUTES_INVALID")
    shared = components.get("x-amazon-apigateway-integrations", {})
    _require(type(shared) is dict and len(shared) <= 1, "STAGE_EXPORT_COMPONENTS_INVALID")
    referenced: set[str] = set()
    for path in paths.values():
        path = _object(path, "STAGE_EXPORT_ROUTES_INVALID")
        _keys(path, {"post", "summary", "description"}, "STAGE_EXPORT_ROUTES_INVALID")
        operation = _object(path.get("post"), "STAGE_EXPORT_ROUTES_INVALID")
        _keys(operation, {"summary", "description", "operationId", "tags", "deprecated", "responses",
                          "requestBody", "parameters", "security", "x-amazon-apigateway-integration"},
              "STAGE_EXPORT_ROUTES_INVALID")
        _iam_security(operation.get("security", document.get("security")), schemes)
        integration = _object(operation.get("x-amazon-apigateway-integration"), "STAGE_EXPORT_INTEGRATION_INVALID")
        if "$ref" in integration:
            _require(set(integration) == {"$ref"}, "STAGE_EXPORT_REFERENCE_INVALID")
            reference = integration["$ref"]
            prefix = "#/components/x-amazon-apigateway-integrations/"
            _require(type(reference) is str and reference.startswith(prefix), "STAGE_EXPORT_REFERENCE_INVALID")
            name = reference[len(prefix):]
            _require(_ID.fullmatch(name) is not None and name in shared, "STAGE_EXPORT_REFERENCE_INVALID")
            referenced.add(name)
            integration = _object(shared[name], "STAGE_EXPORT_REFERENCE_INVALID")
        _integration(integration, version_arn, exported=True)
    _require(set(shared) == referenced, "STAGE_EXPORT_UNUSED_INTEGRATION")


def verify_workforce_deployed_stage(
    *, expected_api_id: str, expected_version_arn: str,
    api: Mapping[str, Any], routes: Mapping[str, Any], integrations: Mapping[str, Any],
    stages_before: Mapping[str, Any], stages_after: Mapping[str, Any],
    export_request: Mapping[str, Any], export_body: bytes,
) -> VerifiedWorkforceStage:
    """Reject incomplete/editable-only evidence; return structural metadata only.

    Expected version comes from trusted numeric Lambda context at runtime, or an
    independently approved post-publication binding in an installer. Collection
    origin, freshness, ordering, request credentials and custody are the caller's
    responsibility; none can be proven by passing a dict to this pure function.
    """
    try:
        _require(type(expected_api_id) is str and re.fullmatch(r"[a-z0-9]{10}", expected_api_id) is not None
                 and type(expected_version_arn) is str and _VERSION_ARN.fullmatch(expected_version_arn) is not None,
                 "STAGE_EXPECTED_BINDING_INVALID")
        values = _snapshot([api, routes, integrations, stages_before, stages_after, export_request], [12000])
        api, routes, integrations, stages_before, stages_after, export_request = values
        api = _response(api)
        _keys(api, {"ApiId", "ApiEndpoint", "ProtocolType", "RouteSelectionExpression", "DisableExecuteApiEndpoint",
                    "ApiGatewayManaged", "CorsConfiguration", "ImportInfo", "ApiKeySelectionExpression",
                    "CreatedDate", "Description", "DisableSchemaValidation", "Name", "Tags", "Version", "Warnings",
                    "ResponseMetadata"}, "STAGE_API_INVALID")
        _require(api.get("ApiId") == expected_api_id and api.get("ProtocolType") == "HTTP"
                 and api.get("ApiEndpoint") == f"https://{expected_api_id}.execute-api.{_REGION}.amazonaws.com"
                 and api.get("RouteSelectionExpression") == "$request.method $request.path"
                 and api.get("DisableExecuteApiEndpoint") is False, "STAGE_API_INVALID")
        _false(api, "ApiGatewayManaged", "STAGE_API_INVALID")
        _empty(api, ("CorsConfiguration", "ImportInfo", "Warnings"), "STAGE_API_INVALID")
        _require(type(export_request) is dict and export_request == {
            "ApiId": expected_api_id, "StageName": _STAGE, "Specification": "OAS30",
            "OutputType": "JSON", "IncludeExtensions": True,
        } and export_request.get("IncludeExtensions") is True, "STAGE_EXPORT_REQUEST_INVALID")
        deployment_id = _stage(stages_before)
        _require(_stage(stages_after) == deployment_id, "STAGE_DEPLOYMENT_CHANGED")
        integration = _items(integrations, 1)[0]
        integration_id = integration.get("IntegrationId")
        _require(type(integration_id) is str and _ID.fullmatch(integration_id) is not None, "STAGE_INTEGRATION_INVALID")
        _integration(integration, expected_version_arn, exported=False)
        seen: set[str] = set()
        route_ids: set[str] = set()
        for route in _items(routes, 3):
            _keys(route, {"RouteId", "RouteKey", "AuthorizationType", "Target", "ApiKeyRequired", "AuthorizerId",
                          "AuthorizationScopes", "RequestParameters", "RequestModels", "ModelSelectionExpression",
                          "OperationName", "RouteResponseSelectionExpression", "ApiGatewayManaged"}, "STAGE_ROUTE_INVALID")
            key, route_id = route.get("RouteKey"), route.get("RouteId")
            _require(type(key) is str and key in {"POST /" + operation for operation in _OPERATIONS}
                     and key not in seen and type(route_id) is str and _ID.fullmatch(route_id) is not None
                     and route_id not in route_ids and route.get("AuthorizationType") == "AWS_IAM"
                     and route.get("Target") == "integrations/" + integration_id, "STAGE_ROUTE_INVALID")
            _false(route, "ApiKeyRequired", "STAGE_ROUTE_INVALID")
            _false(route, "ApiGatewayManaged", "STAGE_ROUTE_INVALID")
            _empty(route, ("AuthorizerId", "AuthorizationScopes", "RequestParameters", "RequestModels",
                           "ModelSelectionExpression", "RouteResponseSelectionExpression"), "STAGE_ROUTE_INVALID")
            seen.add(key)
            route_ids.add(route_id)
        _export(_strict_json(export_body), expected_api_id, expected_version_arn)
        return VerifiedWorkforceStage(expected_api_id, deployment_id, expected_version_arn)
    except WorkforceStageBindingError:
        raise
    except Exception:
        raise WorkforceStageBindingError("STAGE_READBACK_INVALID") from None
