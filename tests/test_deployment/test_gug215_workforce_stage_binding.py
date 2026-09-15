"""Offline API-boundary tests, with documented public AWS shapes only.

No captured deployment, SDK, credentials, cloud, or application runtime imports.
The function under test is the real verifier; the fixture is not authorization.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json

import pytest

from tooling.platform_authority_workforce_stage_binding import (
    MAX_EXPORT_BYTES,
    VerifiedWorkforceStage,
    WorkforceStageBindingError,
    verify_workforce_deployed_stage,
)


API = "a1b2c3d4e5"
ARN = "arn:aws:lambda:us-east-1:042360977644:function:scanalyze-platform-authority-gug215-retirement:12"
OLD = ARN.rsplit(":", 1)[0] + ":11"
OPS = ("classify", "retire", "reconcile")


def export_document():
    return {
        "openapi": "3.0.1",
        "info": {"title": "Synthetic offline contract", "version": "1"},
        "servers": [{"url": f"https://{API}.execute-api.us-east-1.amazonaws.com/retirement"}],
        "paths": {"/" + operation: {"post": {
            "responses": {"default": {"description": "default response"}},
            "security": [{"sigv4": []}],
            "x-amazon-apigateway-integration": {
                "type": "aws_proxy", "httpMethod": "POST", "uri": ARN,
                "payloadFormatVersion": "2.0", "timeoutInMillis": 30000,
            },
        }} for operation in OPS},
        "components": {"securitySchemes": {"sigv4": {
            "type": "apiKey", "name": "Authorization", "in": "header",
            "x-amazon-apigateway-authtype": "awsSigv4",
        }}},
    }


def encode(document):
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.fixture
def readbacks():
    stage = {"Items": [{"StageName": "retirement", "DeploymentId": "deploy12", "AutoDeploy": False,
                         "StageVariables": {}, "LastUpdatedDate": datetime(2026, 9, 14, tzinfo=timezone.utc)}]}
    return {
        "expected_api_id": API,
        "expected_version_arn": ARN,
        "api": {"ApiId": API, "ProtocolType": "HTTP", "Name": "Synthetic",
                "ApiEndpoint": f"https://{API}.execute-api.us-east-1.amazonaws.com",
                "RouteSelectionExpression": "$request.method $request.path", "DisableExecuteApiEndpoint": False},
        "routes": {"Items": [{"RouteId": "route" + operation, "RouteKey": "POST /" + operation,
                               "AuthorizationType": "AWS_IAM", "Target": "integrations/integration12"}
                              for operation in OPS]},
        "integrations": {"Items": [{"IntegrationId": "integration12", "IntegrationType": "AWS_PROXY",
                                     "IntegrationMethod": "POST", "IntegrationUri": ARN,
                                     "PayloadFormatVersion": "2.0", "ConnectionType": "INTERNET"}]},
        "stages_before": deepcopy(stage), "stages_after": deepcopy(stage),
        "export_request": {"ApiId": API, "StageName": "retirement", "Specification": "OAS30",
                           "OutputType": "JSON", "IncludeExtensions": True},
        "export_body": encode(export_document()),
    }


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def assert_rejected(readbacks):
    with pytest.raises(WorkforceStageBindingError) as error:
        verify_workforce_deployed_stage(**readbacks)
    assert str(error.value).startswith("STAGE_")
    assert "private-provider-detail" not in str(error.value)
    assert API not in str(error.value)


def test_matching_deployed_stage_returns_only_immutable_metadata(readbacks):
    before = deepcopy(readbacks)
    result = verify_workforce_deployed_stage(**readbacks)
    assert result == VerifiedWorkforceStage(API, "deploy12", ARN)
    assert readbacks == before
    assert not hasattr(result, "allowed") and not hasattr(result, "deployment_authorized")
    with pytest.raises(FrozenInstanceError):
        result.deployment_id = "replacement"
    readbacks["stages_after"]["Items"][0]["DeploymentId"] = "replacement"
    assert result.deployment_id == "deploy12"


@pytest.mark.parametrize("variant", ["shared", "global-auth", "base-path-server", "no-server", "wrapped-uri", "metadata"])
def test_documented_equivalent_representations(readbacks, variant):
    document = export_document()
    if variant == "shared":
        integration = deepcopy(document["paths"]["/classify"]["post"]["x-amazon-apigateway-integration"])
        document["components"]["x-amazon-apigateway-integrations"] = {"shared": integration}
        for path in document["paths"].values():
            path["post"]["x-amazon-apigateway-integration"] = {"$ref": "#/components/x-amazon-apigateway-integrations/shared"}
    elif variant == "global-auth":
        document["security"] = [{"sigv4": []}]
        for path in document["paths"].values():
            del path["post"]["security"]
    elif variant == "base-path-server":
        document["servers"] = [{"url": f"https://{API}.execute-api.us-east-1.amazonaws.com/{{basePath}}",
                                "variables": {"basePath": {"default": "retirement"}}}]
    elif variant == "no-server":
        del document["servers"]
    elif variant == "wrapped-uri":
        wrapped = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/" + ARN + "/invocations"
        readbacks["integrations"]["Items"][0]["IntegrationUri"] = wrapped
        for path in document["paths"].values():
            path["post"]["x-amazon-apigateway-integration"]["uri"] = wrapped
    else:
        for name in ("api", "routes", "integrations", "stages_before", "stages_after"):
            readbacks[name]["ResponseMetadata"] = {"HTTPStatusCode": 200, "RetryAttempts": 0, "RequestId": "synthetic"}
    readbacks["export_body"] = encode(document)
    assert verify_workforce_deployed_stage(**readbacks).function_version_arn == ARN


@pytest.mark.parametrize("path,value", [
    (("expected_api_id",), "wrong"),
    (("expected_version_arn",), ARN.rsplit(":", 1)[0] + ":$LATEST"),
    (("expected_version_arn",), ARN.rsplit(":", 1)[0] + ":retire"),
    (("expected_version_arn",), ARN.rsplit(":", 1)[0] + ":012"),
    (("expected_version_arn",), ARN.replace("042360977644", "905418363887")),
    (("expected_version_arn",), ARN.replace("us-east-1", "us-west-2")),
    (("expected_version_arn",), ARN.replace("gug215-retirement", "other")),
    (("api", "ApiId"), "b1b2c3d4e5"),
    (("api", "ProtocolType"), "WEBSOCKET"),
    (("api", "ApiEndpoint"), f"https://{API}.execute-api.us-west-2.amazonaws.com"),
    (("api", "ApiEndpoint"), f"https://{API}.execute-api.us-east-1.amazonaws.com.attacker.invalid"),
    (("api", "RouteSelectionExpression"), "$request.body.action"),
    (("api", "DisableExecuteApiEndpoint"), 0),
    (("api", "CorsConfiguration"), {"AllowOrigins": ["*"]}),
    (("routes", "NextToken"), "private-provider-detail"),
    (("integrations", "NextToken"), "next"),
    (("stages_before", "NextToken"), "next"),
    (("stages_after", "NextToken"), ""),
    (("stages_after", "Items", 0, "DeploymentId"), "other12"),
    (("stages_before", "Items", 0, "DeploymentId"), ""),
    (("stages_after", "Items", 0, "StageName"), "$default"),
    (("stages_before", "Items", 0, "AutoDeploy"), True),
    (("stages_before", "Items", 0, "StageVariables"), {"version": "12"}),
    (("routes", "Items", 0, "AuthorizationType"), "NONE"),
    (("routes", "Items", 0, "AuthorizationType"), "JWT"),
    (("routes", "Items", 0, "AuthorizationType"), "CUSTOM"),
    (("routes", "Items", 0, "AuthorizerId"), "other"),
    (("routes", "Items", 0, "RouteKey"), "$default"),
    (("routes", "Items", 0, "RouteKey"), "ANY /classify"),
    (("routes", "Items", 0, "Target"), "integrations/other"),
    (("routes", "Items", 0, "RequestParameters"), {"rewrite": True}),
    (("integrations", "Items", 0, "IntegrationUri"), OLD),
    (("integrations", "Items", 0, "IntegrationUri"), ARN.rsplit(":", 1)[0]),
    (("integrations", "Items", 0, "PayloadFormatVersion"), "1.0"),
    (("integrations", "Items", 0, "IntegrationMethod"), "GET"),
    (("integrations", "Items", 0, "IntegrationType"), "HTTP_PROXY"),
    (("integrations", "Items", 0, "CredentialsArn"), "arn:aws:iam::042360977644:role/other"),
    (("integrations", "Items", 0, "RequestParameters"), {"overwrite:path": "/retire"}),
    (("integrations", "Items", 0, "TimeoutInMillis"), True),
    (("export_request", "ApiId"), "b1b2c3d4e5"),
    (("export_request", "StageName"), "current"),
    (("export_request", "OutputType"), "YAML"),
    (("export_request", "Specification"), "swagger"),
    (("export_request", "IncludeExtensions"), False),
    (("export_request", "IncludeExtensions"), 1),
    (("routes", "ResponseMetadata"), {"HTTPStatusCode": 403}),
    (("stages_after", "ResponseMetadata"), {"HTTPStatusCode": 200, "RetryAttempts": 1}),
])
def test_editable_scope_and_export_request_are_closed(readbacks, path, value):
    set_path(readbacks, path, value)
    assert_rejected(readbacks)


@pytest.mark.parametrize("collection", ["routes", "integrations", "stages_before", "stages_after"])
@pytest.mark.parametrize("change", ["extra", "missing"])
def test_exact_resource_closure(readbacks, collection, change):
    items = readbacks[collection]["Items"]
    if change == "extra":
        items.append(deepcopy(items[0]))
    else:
        items.pop()
    assert_rejected(readbacks)


@pytest.mark.parametrize("field", ["RouteId", "RouteKey"])
def test_silent_dedup_cannot_hide_a_missing_route(readbacks, field):
    readbacks["routes"]["Items"][1][field] = readbacks["routes"]["Items"][0][field]
    assert_rejected(readbacks)


def test_export_without_stage_cannot_attest_deployment(readbacks):
    del readbacks["export_request"]["StageName"]
    assert_rejected(readbacks)


@pytest.mark.parametrize("scenario", ["latest-current-deployed-old", "old-context-current-deployment", "old-context-latest-old-deployed-current"])
def test_historical_version_cannot_pass_by_using_editable_or_context_metadata(readbacks, scenario):
    document = export_document()
    if scenario == "latest-current-deployed-old":
        for path in document["paths"].values():
            path["post"]["x-amazon-apigateway-integration"]["uri"] = OLD
    elif scenario == "old-context-current-deployment":
        readbacks["expected_version_arn"] = OLD
    else:
        readbacks["expected_version_arn"] = OLD
        readbacks["integrations"]["Items"][0]["IntegrationUri"] = OLD
    readbacks["export_body"] = encode(document)
    assert_rejected(readbacks)


@pytest.mark.parametrize("path,value", [
    (("paths", "/retire", "post", "security"), []),
    (("paths", "/retire", "post", "security"), [{}]),
    (("paths", "/retire", "post", "security"), [{"sigv4": []}, {}]),
    (("paths", "/retire", "post", "security"), [{"sigv4": ["scope"]}]),
    (("paths", "/retire", "post", "security"), [{"jwt": []}]),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "uri"), OLD),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "uri"), ARN + "/invocations"),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "uri"), ARN.rsplit(":", 1)[0] + ":live"),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "payloadFormatVersion"), 2.0),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "credentials"), "role"),
    (("paths", "/retire", "post", "x-amazon-apigateway-integration", "requestParameters"), {"overwrite:path": "/classify"}),
    (("paths", "/retire", "post", "x-amazon-apigateway-auth"), {"type": "NONE"}),
    (("components", "securitySchemes", "sigv4", "x-amazon-apigateway-authtype"), "jwt"),
    (("components", "securitySchemes", "sigv4", "type"), "http"),
    (("components", "securitySchemes", "sigv4", "in"), "query"),
    (("components", "securitySchemes", "sigv4", "name"), "X-Authorization"),
    (("components", "securitySchemes", "sigv4", "x-amazon-apigateway-authorizer"), {"type": "jwt"}),
    (("servers", 0, "url"), f"https://{API}.execute-api.us-east-1.amazonaws.com/other"),
    (("servers", 0, "url"), "https://b1b2c3d4e5.execute-api.us-east-1.amazonaws.com/retirement"),
    (("openapi",), "3.1.0"),
    (("x-amazon-apigateway-cors",), {"allowOrigins": ["*"]}),
])
def test_deployed_auth_integration_and_scope_are_verified(readbacks, path, value):
    document = export_document()
    set_path(document, path, value)
    readbacks["export_body"] = encode(document)
    assert_rejected(readbacks)


@pytest.mark.parametrize("mutation", ["extra-path", "extra-method", "missing-path", "missing-security", "global-empty", "unused-integration"])
def test_deployed_closure_and_effective_security(readbacks, mutation):
    document = export_document()
    if mutation == "extra-path":
        document["paths"]["/unapproved"] = deepcopy(document["paths"]["/retire"])
    elif mutation == "extra-method":
        document["paths"]["/retire"]["get"] = deepcopy(document["paths"]["/retire"]["post"])
    elif mutation == "missing-path":
        del document["paths"]["/retire"]
    elif mutation == "missing-security":
        del document["paths"]["/retire"]["post"]["security"]
    elif mutation == "global-empty":
        document["security"] = []
    else:
        document["components"]["x-amazon-apigateway-integrations"] = {"unused": {}}
    readbacks["export_body"] = encode(document)
    assert_rejected(readbacks)


@pytest.mark.parametrize("reference", ["https://example.invalid/private-provider-detail", "#/components/schemas/other",
                                        "#/components/x-amazon-apigateway-integrations/missing",
                                        "#/components/x-amazon-apigateway-integrations/../other"])
def test_external_and_unresolved_integration_references_are_rejected(readbacks, reference):
    document = export_document()
    document["paths"]["/retire"]["post"]["x-amazon-apigateway-integration"] = {"$ref": reference}
    readbacks["export_body"] = encode(document)
    assert_rejected(readbacks)


@pytest.mark.parametrize("body", [b"", b"[]", b"{}", b"\xff", b"\xef\xbb\xbf{}", b'{"a":1,"a":2}',
                                   b'{"a":{"nested":1,"nested":2}}', b'{"a":NaN}', b'{"a":Infinity}',
                                   b'{"a":"\\ud800"}', b"{} trailing-private-provider-detail",
                                   b" " * (MAX_EXPORT_BYTES + 1), b"[" * 2000 + b"]" * 2000])
def test_export_json_limits_and_sanitized_errors(readbacks, body):
    readbacks["export_body"] = body
    assert_rejected(readbacks)


def test_duplicate_operation_in_otherwise_valid_export_is_rejected(readbacks):
    body = readbacks["export_body"].replace(b'"security":[{"sigv4":[]}]', b'"security":[],"security":[{"sigv4":[]}]', 1)
    # Ordinary json.loads silently keeps the valid second value.
    assert json.loads(body)["paths"]["/classify"]["post"]["security"] == [{"sigv4": []}]
    readbacks["export_body"] = body
    with pytest.raises(WorkforceStageBindingError, match="^STAGE_EXPORT_DUPLICATE_KEY$"):
        verify_workforce_deployed_stage(**readbacks)


def test_self_asserted_authority_field_cannot_change_result(readbacks):
    readbacks["api"]["deployment_authorized"] = True
    assert_rejected(readbacks)


def test_arbitrary_objects_cannot_execute_callbacks(readbacks):
    class ForeignMapping(dict):
        def items(self):
            raise AssertionError("private-provider-detail")
    readbacks["api"] = ForeignMapping(readbacks["api"])
    assert_rejected(readbacks)
