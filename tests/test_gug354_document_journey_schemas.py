from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "schemas" / "scanalyze-document-journey.openapi.v1.json"
RESULT_SCHEMA_PATH = ROOT / "schemas" / "scanalyze-document-journey-result.v1.schema.json"
FRONTEND_TYPES_PATH = (
    ROOT
    / "frontend"
    / "scanalyze-frontend-ui"
    / "src"
    / "contracts"
    / "documentJourney.v1.ts"
)
FRONTEND_FIXTURES_PATH = FRONTEND_TYPES_PATH.with_name(
    "documentJourney.v1.fixtures.ts"
)
EDGE_CLOUDFRONT_PATH = ROOT / "modules" / "edge" / "cloudfront.tf"
EDGE_REWRITE_PATH = ROOT / "modules" / "edge" / "api_path_rewrite.js"
EDGE_IDENTITY_API_PATH = ROOT / "modules" / "edge-identity" / "api_gateway.tf"
INGEST_API_ROOT = ROOT / "backend" / "workers" / "scanalyze-ingest-api"
SERVICES_TFVARS_PATH = ROOT / "environments" / "bcm-corp-services.tfvars"
CONTRACT_DOCUMENTATION_PATHS = (
    ROOT / "ADR" / "ADR-049-versioned-idempotent-document-journey.md",
    ROOT / "docs" / "deployment" / "document-journey-api.md",
    ROOT / "docs" / "security" / "gug-354-document-journey-threat-model.md",
)

CONTRACT_VERSION = "scanalyze.document-journey.v1"
EXPECTED_PATHS = {
    "/api/v2/batches": "post",
    "/api/v2/documents": "post",
    "/api/v2/documents/{documentId}/submit": "post",
    "/api/v2/documents/{documentId}": "get",
    "/api/v2/documents/{documentId}/upload-capabilities": "post",
    "/api/v2/operations/{operation}/reconciliation": "post",
    "/api/v2/documents/{documentId}/result": "get",
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def openapi() -> dict[str, Any]:
    return _load(OPENAPI_PATH)


@pytest.fixture(scope="module")
def result_schema() -> dict[str, Any]:
    return _load(RESULT_SCHEMA_PATH)


def _parameter_names(path_item: dict[str, Any], operation: dict[str, Any]) -> set[str]:
    parameters = [*path_item.get("parameters", []), *operation.get("parameters", [])]
    names: set[str] = set()
    for parameter in parameters:
        reference = parameter.get("$ref")
        if reference:
            names.add(reference.rsplit("/", 1)[-1])
        elif isinstance(parameter.get("name"), str):
            names.add(parameter["name"])
    return names


def _validator(openapi: dict[str, Any], schema_name: str) -> Draft202012Validator:
    resource_contents = {"$schema": openapi["jsonSchemaDialect"], **openapi}
    registry = Registry().with_resource(
        "urn:scanalyze:document-journey-openapi",
        Resource.from_contents(resource_contents),
    )
    return Draft202012Validator(
        {
            "$schema": openapi["jsonSchemaDialect"],
            "$ref": (
                "urn:scanalyze:document-journey-openapi"
                f"#/components/schemas/{schema_name}"
            ),
        },
        registry=registry,
        format_checker=FormatChecker(),
    )


def _fixture(name: str) -> dict[str, Any]:
    source = FRONTEND_FIXTURES_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"export const {re.escape(name)} = (?P<value>\{{.*?\}}) as const satisfies ",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, f"missing JSON-compatible frontend fixture {name}"
    value = json.loads(match.group("value"))
    assert isinstance(value, dict)
    return value


def _typescript_array(name: str) -> list[str]:
    source = FRONTEND_TYPES_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"export const {re.escape(name)} = (?P<value>\[[^\n]+\]) as const;",
        source,
    )
    assert match is not None, f"missing contract-derived frontend constant {name}"
    value = json.loads(match.group("value"))
    assert isinstance(value, list) and all(isinstance(item, str) for item in value)
    return value


def _typescript_object(name: str) -> dict[str, Any]:
    source = FRONTEND_TYPES_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"export const {re.escape(name)} = (?P<value>\{{.*?\}}) as const satisfies ",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, f"missing JSON-compatible frontend constant {name}"
    value = json.loads(match.group("value"))
    assert isinstance(value, dict)
    return value


def _hcl_string_lists(source: str, assignment: str) -> list[list[str]]:
    matches = re.findall(
        rf"\b{re.escape(assignment)}\s*=\s*\[(?P<value>.*?)\]",
        source,
        flags=re.DOTALL,
    )
    return [re.findall(r'"([^"]+)"', match) for match in matches]


def _assert_closed_objects(node: Any, location: str = "$") -> None:
    if isinstance(node, dict):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, (
                f"object schema at {location} is not closed"
            )
        for key, value in node.items():
            _assert_closed_objects(value, f"{location}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _assert_closed_objects(value, f"{location}/{index}")


def _runtime_contract() -> Any:
    ingest_root = str(INGEST_API_ROOT)
    if ingest_root not in sys.path:
        sys.path.insert(0, ingest_root)
    from app import journey_contract

    return journey_contract


def test_openapi_is_the_explicit_additive_contract(openapi: dict[str, Any]) -> None:
    assert openapi["openapi"] == "3.1.0"
    assert openapi["jsonSchemaDialect"] == Draft202012Validator.META_SCHEMA["$id"]
    assert openapi["x-contract-version"] == CONTRACT_VERSION
    assert openapi["x-canonical-namespace"] == "/api/v2"
    assert openapi["x-historical-routes"] == {
        "namespace": "/api/v1",
        "status": "historical_noncanonical",
        "equivalentToCurrentContract": False,
    }
    assert set(openapi["paths"]) == set(EXPECTED_PATHS)
    assert all(path.startswith("/api/v2/") for path in openapi["paths"])
    assert openapi["x-json-parsing"] == {
        "duplicateKeys": "reject",
        "nonFiniteNumbers": "reject",
        "unknownRequestFields": "reject",
    }


def test_every_route_requires_the_exact_contract_header(
    openapi: dict[str, Any],
) -> None:
    parameter = openapi["components"]["parameters"]["ContractVersionHeader"]
    assert parameter["name"] == "X-Scanalyze-Contract-Version"
    assert parameter["in"] == "header"
    assert parameter["required"] is True
    assert parameter["schema"] == {"const": CONTRACT_VERSION}

    for path, method in EXPECTED_PATHS.items():
        path_item = openapi["paths"][path]
        operation = path_item[method]
        assert "ContractVersionHeader" in _parameter_names(path_item, operation)
        success = next(
            response
            for status, response in operation["responses"].items()
            if status.startswith("2")
        )
        assert "X-Scanalyze-Contract-Version" not in success["headers"]


def test_idempotency_key_is_uuid_bound_only_to_create_and_reconciliation(
    openapi: dict[str, Any],
) -> None:
    parameter = openapi["components"]["parameters"]["IdempotencyKeyHeader"]
    assert parameter["name"] == "Idempotency-Key"
    assert parameter["required"] is True
    assert parameter["schema"]["format"] == "uuid"
    assert parameter["schema"]["minLength"] == parameter["schema"]["maxLength"] == 36

    required_paths = {
        "/api/v2/batches",
        "/api/v2/documents",
        "/api/v2/operations/{operation}/reconciliation",
    }
    for path, method in EXPECTED_PATHS.items():
        names = _parameter_names(openapi["paths"][path], openapi["paths"][path][method])
        assert ("IdempotencyKeyHeader" in names) is (path in required_paths)


def test_openapi_declares_all_reviewed_error_statuses_and_headers(
    openapi: dict[str, Any],
) -> None:
    required_errors = {"400", "401", "403", "404", "409", "422", "429", "500", "502", "503"}
    for path, method in EXPECTED_PATHS.items():
        responses = openapi["paths"][path][method]["responses"]
        applicable = required_errors - ({"404"} if path == "/api/v2/batches" else set())
        assert applicable <= set(responses), f"missing error status on {method.upper()} {path}"

    responses = openapi["components"]["responses"]
    for response in responses.values():
        assert "X-Correlation-ID" in response["headers"]
        assert "X-Scanalyze-Contract-Version" not in response["headers"]
    for name in ("RateLimited", "ServiceUnavailable"):
        assert "Retry-After" in responses[name]["headers"]
    for name in set(responses) - {"RateLimited", "ServiceUnavailable"}:
        assert "Retry-After" not in responses[name]["headers"]
    retry_after = openapi["components"]["headers"]["RetryAfterHeader"]
    assert retry_after["required"] is False
    assert "retry-only-after-reconciliation" in retry_after["x-emission-policy"]


def test_every_committed_contract_object_schema_is_closed(
    openapi: dict[str, Any], result_schema: dict[str, Any]
) -> None:
    for name, schema in openapi["components"]["schemas"].items():
        Draft202012Validator.check_schema(schema)
        _assert_closed_objects(schema, f"#/components/schemas/{name}")
    Draft202012Validator.check_schema(result_schema)
    _assert_closed_objects(result_schema)


def test_contract_fixtures_validate_against_authoritative_schemas(
    openapi: dict[str, Any], result_schema: dict[str, Any]
) -> None:
    fixture_to_schema = {
        "BATCH_CREATE_RESPONSE_FIXTURE": "BatchCreateResponse",
        "DOCUMENT_CREATE_RESPONSE_FIXTURE": "DocumentCreateResponse",
        "DOCUMENT_REPLAY_RESPONSE_WITHOUT_CAPABILITY_FIXTURE": (
            "DocumentCreateResponse"
        ),
        "RECONCILIATION_RESPONSE_FIXTURE": "ReconciliationResponse",
        "EXPIRED_RECONCILIATION_RESPONSE_FIXTURE": "ReconciliationResponse",
        "DOCUMENT_STATUS_RESPONSE_FIXTURE": "DocumentStatusResponse",
        "DOCUMENT_PROCESSING_STATUS_RESPONSE_FIXTURE": "DocumentStatusResponse",
        "ERROR_ENVELOPE_FIXTURE": "ErrorEnvelope",
    }
    for fixture_name, schema_name in fixture_to_schema.items():
        _validator(openapi, schema_name).validate(_fixture(fixture_name))

    Draft202012Validator(
        result_schema,
        format_checker=FormatChecker(),
    ).validate(_fixture("BANK_STATEMENT_RESULT_FIXTURE"))


@pytest.mark.parametrize(
    ("typescript_name", "schema_name"),
    [
        ("DOCUMENT_JOURNEY_OPERATIONS", "Operation"),
        ("DOCUMENT_JOURNEY_LEDGER_STATES", "LedgerState"),
        ("DOCUMENT_LIFECYCLES", "DocumentLifecycle"),
        ("DOCUMENT_PIPELINE_STAGES", "PipelineStage"),
        ("DOCUMENT_STAGE_STATES", "StageState"),
        ("DOCUMENT_PROCESSING_CONDITIONS", "ProcessingCondition"),
        ("DOCUMENT_FAILURE_DISPOSITIONS", "FailureDisposition"),
        ("DOCUMENT_SAFE_FAILURE_CODES", "SafeFailureCode"),
        ("DOCUMENT_JOURNEY_RETRY_CLASSES", "RetryClass"),
    ],
)
def test_frontend_enums_are_derived_from_openapi(
    openapi: dict[str, Any], typescript_name: str, schema_name: str
) -> None:
    assert _typescript_array(typescript_name) == openapi["components"]["schemas"][schema_name]["enum"]


def test_frontend_content_and_error_enums_are_derived_from_openapi(
    openapi: dict[str, Any],
) -> None:
    assert _typescript_array("DOCUMENT_JOURNEY_CONTENT_TYPES") == (
        openapi["components"]["schemas"]["DocumentCreateRequest"]["properties"][
            "contentType"
        ]["enum"]
    )
    assert _typescript_array("DOCUMENT_JOURNEY_ERROR_CODES") == (
        openapi["components"]["schemas"]["ErrorEnvelope"]["properties"]["code"][
            "enum"
        ]
    )
    assert _typescript_object("DOCUMENT_JOURNEY_ERROR_POLICY") == (
        openapi["components"]["schemas"]["ErrorEnvelope"]["properties"]["code"][
            "x-code-contract"
        ]
    )


def test_error_policy_is_exactly_discriminated_and_matches_runtime(
    openapi: dict[str, Any],
) -> None:
    runtime = _runtime_contract()
    validator = _validator(openapi, "ErrorEnvelope")
    static_policy = openapi["components"]["schemas"]["ErrorEnvelope"][
        "properties"
    ]["code"]["x-code-contract"]
    retry_after_codes = {"RATE_LIMITED", "SERVICE_UNAVAILABLE"}

    runtime_policy: dict[str, dict[str, Any]] = {}
    envelopes: dict[str, dict[str, Any]] = {}
    for code in runtime.ErrorCode:
        status, envelope = runtime.public_error(code, "corr.synthetic.policy")
        serialized = envelope.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        validator.validate(serialized)
        envelopes[code.value] = serialized
        runtime_policy[code.value] = {
            "httpStatus": status,
            "message": envelope.message,
            "retryClass": envelope.retry_class.value,
            "retryAfterAllowed": code.value in retry_after_codes,
        }

    assert static_policy == runtime_policy
    assert list(static_policy) == [member.value for member in runtime.ErrorCode]

    codes = list(envelopes)
    for index, code in enumerate(codes):
        exact = envelopes[code]
        other = envelopes[codes[(index + 1) % len(codes)]]

        wrong_message = copy.deepcopy(exact)
        wrong_message["message"] = other["message"]
        with pytest.raises(ValidationError):
            validator.validate(wrong_message)

        wrong_retry_class = copy.deepcopy(exact)
        wrong_retry_class["retryClass"] = other["retryClass"]
        if wrong_retry_class["retryClass"] == exact["retryClass"]:
            wrong_retry_class["retryClass"] = "NOT_RETRYABLE" if exact[
                "retryClass"
            ] != "NOT_RETRYABLE" else "TERMINAL"
        with pytest.raises(ValidationError):
            validator.validate(wrong_retry_class)

        stale_cross_product = copy.deepcopy(exact)
        stale_cross_product["code"] = other["code"]
        with pytest.raises(ValidationError):
            validator.validate(stale_cross_product)


def test_error_response_components_enforce_runtime_http_status(
    openapi: dict[str, Any],
) -> None:
    runtime = _runtime_contract()
    component_statuses = {
        "BadRequest": 400,
        "Unauthorized": 401,
        "Forbidden": 403,
        "NotFound": 404,
        "Conflict": 409,
        "UnprocessableEntity": 422,
        "RateLimited": 429,
        "InternalError": 500,
        "UpstreamError": 502,
        "ServiceUnavailable": 503,
    }
    resource_contents = {"$schema": openapi["jsonSchemaDialect"], **openapi}
    registry = Registry().with_resource(
        "urn:scanalyze:document-journey-openapi",
        Resource.from_contents(resource_contents),
    )

    for response_name, response_status in component_statuses.items():
        response_validator = Draft202012Validator(
            {
                "$schema": openapi["jsonSchemaDialect"],
                "$ref": (
                    "urn:scanalyze:document-journey-openapi"
                    f"#/components/responses/{response_name}/content/"
                    "application~1json/schema"
                ),
            },
            registry=registry,
            format_checker=FormatChecker(),
        )
        for code in runtime.ErrorCode:
            status, envelope = runtime.public_error(code, "corr.synthetic.policy")
            serialized = envelope.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            if status == response_status:
                response_validator.validate(serialized)
            else:
                with pytest.raises(ValidationError):
                    response_validator.validate(serialized)

    assert "timeout" not in openapi["components"]["responses"]["BadRequest"][
        "description"
    ].lower()
    assert "unknown write outcome" not in openapi["components"]["responses"][
        "Conflict"
    ]["description"].lower()
    assert "unknown-write-outcome" in openapi["components"]["responses"][
        "InternalError"
    ]["description"].lower()
    assert "requires reconciliation" in openapi["components"]["responses"][
        "ServiceUnavailable"
    ]["description"].lower()


def test_frontend_bank_statement_enums_are_derived_from_result_schema(
    result_schema: dict[str, Any],
) -> None:
    transaction_categories = result_schema["$defs"]["transaction"]["properties"][
        "category"
    ]["enum"]
    assert _typescript_array("BANK_STATEMENT_TRANSACTION_CATEGORIES") == [
        value for value in transaction_categories if value is not None
    ]
    assert _typescript_array("BANK_STATEMENT_WARNING_CODES") == result_schema[
        "$defs"
    ]["warning"]["properties"]["code"]["enum"]


def test_frontend_contract_constants_point_to_the_authority() -> None:
    source = FRONTEND_TYPES_PATH.read_text(encoding="utf-8")
    assert f'DOCUMENT_JOURNEY_API_NAMESPACE = "/api/v2"' in source
    assert f'DOCUMENT_JOURNEY_CONTRACT_VERSION = "{CONTRACT_VERSION}"' in source
    assert 'DOCUMENT_JOURNEY_CONTRACT_HEADER = "X-Scanalyze-Contract-Version"' in source
    assert 'DOCUMENT_JOURNEY_IDEMPOTENCY_HEADER = "Idempotency-Key"' in source
    assert "scanalyze-document-journey.openapi.v1.json" in source
    assert "scanalyze-document-journey-result.v1.schema.json" in source


def test_committed_schema_is_the_only_v2_openapi_authority(
    openapi: dict[str, Any],
) -> None:
    assert openapi["x-schema-authority"] == {
        "status": "sole_v2_authority",
        "fastApiOpenApiPath": "/openapi.json",
        "fastApiOpenApiStatus": "legacy_noncanonical",
        "fastApiOpenApiIncludesV2": False,
    }
    sys.path.insert(0, str(INGEST_API_ROOT))
    try:
        from app.api.v2.router import router as v2_router
    finally:
        sys.path.remove(str(INGEST_API_ROOT))
    v2_routes = [
        route
        for route in v2_router.routes
        if getattr(route, "path", "").startswith("/api/v2")
    ]
    assert v2_routes
    assert all(route.include_in_schema is False for route in v2_routes)


def test_public_status_enums_are_exactly_the_reachable_outputs(
    openapi: dict[str, Any],
) -> None:
    schemas = openapi["components"]["schemas"]
    assert schemas["DocumentLifecycle"]["enum"] == [
        "UPLOAD_PENDING",
        "SUBMITTED",
        "PROCESSING",
        "COMPLETED",
        "FAILED",
    ]
    assert schemas["PipelineStage"]["enum"] == [
        "INGEST",
        "OCR",
        "CLASSIFY",
        "BANK_EXTRACT",
        "PERSONAL_EXTRACT",
        "VALIDATE",
        "TERMINAL",
    ]
    assert schemas["StageState"]["enum"] == [
        "PENDING",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
    ]
    assert schemas["ProcessingCondition"]["enum"] == [
        "ACTIVE",
        "NOT_APPLICABLE",
    ]
    assert schemas["FailureDisposition"]["enum"] == ["RETRYABLE", "TERMINAL"]
    assert schemas["SafeFailureCode"]["enum"] == [
        "DOCUMENT_PROCESSING_FAILED",
        "OCR_FAILED",
        "ENQUEUE_FAILED",
    ]


def test_runtime_constants_and_enums_match_the_authoritative_sources(
    openapi: dict[str, Any], result_schema: dict[str, Any]
) -> None:
    runtime = _runtime_contract()
    assert runtime.API_NAMESPACE == openapi["x-canonical-namespace"]
    assert runtime.CONTRACT_VERSION == openapi["x-contract-version"]
    assert runtime.CONTRACT_HEADER == "X-Scanalyze-Contract-Version"
    assert runtime.IDEMPOTENCY_HEADER == "Idempotency-Key"

    parity = {
        runtime.OperationKind: openapi["components"]["schemas"]["Operation"]["enum"],
        runtime.LedgerState: openapi["components"]["schemas"]["LedgerState"]["enum"],
        runtime.DocumentContentType: openapi["components"]["schemas"][
            "DocumentCreateRequest"
        ]["properties"]["contentType"]["enum"],
        runtime.DocumentLifecycle: openapi["components"]["schemas"][
            "DocumentLifecycle"
        ]["enum"],
        runtime.PipelineStage: openapi["components"]["schemas"]["PipelineStage"][
            "enum"
        ],
        runtime.StageState: openapi["components"]["schemas"]["StageState"]["enum"],
        runtime.ProcessingCondition: openapi["components"]["schemas"][
            "ProcessingCondition"
        ]["enum"],
        runtime.FailureDisposition: openapi["components"]["schemas"][
            "FailureDisposition"
        ]["enum"],
        runtime.SafeFailureCode: openapi["components"]["schemas"][
            "SafeFailureCode"
        ]["enum"],
        runtime.RetryClass: openapi["components"]["schemas"]["RetryClass"]["enum"],
        runtime.ErrorCode: openapi["components"]["schemas"]["ErrorEnvelope"][
            "properties"
        ]["code"]["enum"],
        runtime.TransactionCategory: [
            value
            for value in result_schema["$defs"]["transaction"]["properties"][
                "category"
            ]["enum"]
            if value is not None
        ],
        runtime.BankStatementWarningCode: result_schema["$defs"]["warning"][
            "properties"
        ]["code"]["enum"],
    }
    for runtime_enum, authority_values in parity.items():
        assert [member.value for member in runtime_enum] == authority_values


def test_runtime_models_round_trip_the_exact_frontend_fixtures() -> None:
    runtime = _runtime_contract()
    fixture_models = {
        "BATCH_CREATE_RESPONSE_FIXTURE": runtime.BatchCreateResponse,
        "DOCUMENT_CREATE_RESPONSE_FIXTURE": runtime.DocumentCreateResponse,
        "DOCUMENT_REPLAY_RESPONSE_WITHOUT_CAPABILITY_FIXTURE": (
            runtime.DocumentCreateResponse
        ),
        "RECONCILIATION_RESPONSE_FIXTURE": runtime.ReconciliationResponse,
        "EXPIRED_RECONCILIATION_RESPONSE_FIXTURE": (
            runtime.ReconciliationResponse
        ),
        "DOCUMENT_STATUS_RESPONSE_FIXTURE": runtime.DocumentStatusResponse,
        "DOCUMENT_PROCESSING_STATUS_RESPONSE_FIXTURE": (
            runtime.DocumentStatusResponse
        ),
        "ERROR_ENVELOPE_FIXTURE": runtime.ErrorEnvelope,
        "BANK_STATEMENT_RESULT_FIXTURE": runtime.BankStatementResult,
    }
    for fixture_name, model in fixture_models.items():
        fixture = _fixture(fixture_name)
        serialized = model.model_validate(fixture).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=model is not runtime.BankStatementResult,
        )
        assert serialized == fixture


def test_unknown_request_fields_and_unknown_public_values_reject(
    openapi: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        _validator(openapi, "BatchCreateRequest").validate({"metadata": {}})
    with pytest.raises(ValidationError):
        _validator(openapi, "DocumentCreateRequest").validate(
            {"contentType": "application/pdf", "customerId": "spoofed"}
        )

    status = _fixture("DOCUMENT_STATUS_RESPONSE_FIXTURE")
    status["lifecycle"] = "STILL_PROCESSING_MAYBE"
    with pytest.raises(ValidationError):
        _validator(openapi, "DocumentStatusResponse").validate(status)


def test_document_create_and_submit_wire_types_are_strict(
    openapi: dict[str, Any],
) -> None:
    create = _validator(openapi, "DocumentCreateRequest")
    for filename in ("report.pdf", " reporte 01.pdf "):
        create.validate({"contentType": "application/pdf", "filename": filename})
    for filename in (
        "   ",
        ".",
        "..",
        " .. ",
        "a/b.pdf",
        "a\\b.pdf",
        "a\nb.pdf",
        "a\x7fb.pdf",
    ):
        with pytest.raises(ValidationError):
            create.validate({"contentType": "application/pdf", "filename": filename})
    for coerced_length in (True, "1"):
        with pytest.raises(ValidationError):
            create.validate(
                {"contentType": "application/pdf", "contentLength": coerced_length}
            )
    content_length = openapi["components"]["schemas"]["DocumentCreateRequest"][
        "properties"
    ]["contentLength"]
    assert "floating-point tokens such as 1.0" in content_length["x-strict-json-type"]

    submit_schema = openapi["components"]["schemas"]["SubmitDocumentRequest"]
    assert submit_schema["properties"]["stage"]["default"] == "ingest"
    submit = _validator(openapi, "SubmitDocumentRequest")
    submit.validate({})
    submit.validate({"stage": "ingest"})
    for invalid_stage in (None, "ocr", 1):
        with pytest.raises(ValidationError):
            submit.validate({"stage": invalid_stage})


def test_reconciliation_operation_and_durable_response_must_agree(
    openapi: dict[str, Any],
) -> None:
    response = _fixture("RECONCILIATION_RESPONSE_FIXTURE")
    response["operation"] = "batches.create"
    with pytest.raises(ValidationError):
        _validator(openapi, "ReconciliationResponse").validate(response)


def test_document_create_capability_is_required_only_for_first_create(
    openapi: dict[str, Any],
) -> None:
    validator = _validator(openapi, "DocumentCreateResponse")
    first = _fixture("DOCUMENT_CREATE_RESPONSE_FIXTURE")
    replay = _fixture("DOCUMENT_REPLAY_RESPONSE_WITHOUT_CAPABILITY_FIXTURE")

    validator.validate(first)
    validator.validate(replay)

    first_without_capability = copy.deepcopy(first)
    first_without_capability.pop("uploadCapability")
    with pytest.raises(ValidationError):
        validator.validate(first_without_capability)

    replay_with_fresh_capability = copy.deepcopy(replay)
    replay_with_fresh_capability["uploadCapability"] = first["uploadCapability"]
    validator.validate(replay_with_fresh_capability)


def test_reconciliation_states_have_closed_payload_rules(
    openapi: dict[str, Any],
) -> None:
    validator = _validator(openapi, "ReconciliationResponse")
    pending = _fixture("RECONCILIATION_RESPONSE_FIXTURE")
    pending["ledgerState"] = "PENDING"
    pending.pop("durableResponse")
    pending.pop("completedAt")
    validator.validate(pending)

    pending["durableResponse"] = _fixture("RECONCILIATION_RESPONSE_FIXTURE")[
        "durableResponse"
    ]
    with pytest.raises(ValidationError):
        validator.validate(pending)
    pending.pop("durableResponse")
    pending["completedAt"] = pending["updatedAt"]
    with pytest.raises(ValidationError):
        validator.validate(pending)

    failed = copy.deepcopy(pending)
    failed["ledgerState"] = "FAILED_TERMINAL"
    failed["failureCode"] = "CREATE_FAILED_RETRYABLE"
    with pytest.raises(ValidationError):
        validator.validate(failed)
    failed["failureCode"] = "CREATE_FAILED_TERMINAL"
    validator.validate(failed)

    retryable = copy.deepcopy(pending)
    retryable["ledgerState"] = "FAILED_RETRYABLE"
    retryable["failureCode"] = "CREATE_FAILED_RETRYABLE"
    retryable.pop("completedAt", None)
    validator.validate(retryable)
    retryable["completedAt"] = retryable["updatedAt"]
    with pytest.raises(ValidationError):
        validator.validate(retryable)

    expired = _fixture("EXPIRED_RECONCILIATION_RESPONSE_FIXTURE")
    assert expired["completedAt"] < expired["expiresAt"] <= expired["updatedAt"]
    validator.validate(expired)

    timestamp_invariant = openapi["components"]["schemas"][
        "ReconciliationResponse"
    ]["x-timestamp-invariant"]
    assert "For EXPIRED" in timestamp_invariant
    assert "createdAt <= completedAt <= updatedAt" in timestamp_invariant
    assert "completedAt may preserve an original terminal completion" in (
        timestamp_invariant
    )
    assert "expiresAt <= updatedAt" in timestamp_invariant
    assert "updatedAt < expiresAt" in timestamp_invariant


def test_status_terminal_and_failure_invariants_are_in_the_schema(
    openapi: dict[str, Any],
) -> None:
    validator = _validator(openapi, "DocumentStatusResponse")
    status = _fixture("DOCUMENT_STATUS_RESPONSE_FIXTURE")

    missing_terminal_time = copy.deepcopy(status)
    missing_terminal_time.pop("terminalAt")
    with pytest.raises(ValidationError):
        validator.validate(missing_terminal_time)

    failed_without_safe_failure = copy.deepcopy(status)
    failed_without_safe_failure["lifecycle"] = "FAILED"
    failed_without_safe_failure["stageState"] = "FAILED"
    with pytest.raises(ValidationError):
        validator.validate(failed_without_safe_failure)

    active_terminal_stage = copy.deepcopy(status)
    active_terminal_stage["lifecycle"] = "PROCESSING"
    active_terminal_stage.pop("terminalAt")
    with pytest.raises(ValidationError):
        validator.validate(active_terminal_stage)

    enqueue_failed = copy.deepcopy(status)
    enqueue_failed.update(
        {
            "lifecycle": "SUBMITTED",
            "currentStage": "INGEST",
            "stageState": "FAILED",
            "processingCondition": "NOT_APPLICABLE",
            "failureDisposition": "RETRYABLE",
            "safeFailureCode": "ENQUEUE_FAILED",
        }
    )
    enqueue_failed.pop("terminalAt")
    validator.validate(enqueue_failed)

    unknown_safe_code = copy.deepcopy(enqueue_failed)
    unknown_safe_code["safeFailureCode"] = "ARBITRARY_PROVIDER_FAILURE"
    with pytest.raises(ValidationError):
        validator.validate(unknown_safe_code)

    wrong_retryable_shape = copy.deepcopy(enqueue_failed)
    wrong_retryable_shape["currentStage"] = "OCR"
    with pytest.raises(ValidationError):
        validator.validate(wrong_retryable_shape)

    unexplained_nonterminal_failure = copy.deepcopy(enqueue_failed)
    unexplained_nonterminal_failure.pop("failureDisposition")
    unexplained_nonterminal_failure.pop("safeFailureCode")
    unexplained_nonterminal_failure["processingCondition"] = "ACTIVE"
    with pytest.raises(ValidationError):
        validator.validate(unexplained_nonterminal_failure)

    impossible_received = copy.deepcopy(status)
    impossible_received.update(
        {
            "lifecycle": "RECEIVED",
            "currentStage": "PERSIST",
            "stageState": "SUCCEEDED",
            "processingCondition": "ACTIVE",
        }
    )
    impossible_received.pop("terminalAt")
    with pytest.raises(ValidationError):
        validator.validate(impossible_received)

    impossible_submitted = copy.deepcopy(impossible_received)
    impossible_submitted.update(
        {
            "lifecycle": "SUBMITTED",
            "currentStage": "OCR",
            "stageState": "SUCCEEDED",
        }
    )
    with pytest.raises(ValidationError):
        validator.validate(impossible_submitted)

    terminal_failed = copy.deepcopy(status)
    terminal_failed.update(
        {
            "lifecycle": "FAILED",
            "stageState": "FAILED",
            "failureDisposition": "TERMINAL",
            "safeFailureCode": "OCR_FAILED",
        }
    )
    validator.validate(terminal_failed)
    terminal_failed["safeFailureCode"] = "ENQUEUE_FAILED"
    with pytest.raises(ValidationError):
        validator.validate(terminal_failed)

    removed_quarantined_projection = copy.deepcopy(status)
    removed_quarantined_projection.update(
        {
            "lifecycle": "UNKNOWN_OR_QUARANTINED",
            "stageState": "FAILED",
            "failureDisposition": "UNKNOWN_OR_QUARANTINED",
            "safeFailureCode": "UNSUPPORTED_INTERNAL_STATE",
        }
    )
    with pytest.raises(ValidationError):
        validator.validate(removed_quarantined_projection)


def test_lifecycle_transitions_and_progress_cross_field_rules_are_authoritative(
    openapi: dict[str, Any],
) -> None:
    runtime = _runtime_contract()
    lifecycle = openapi["components"]["schemas"]["DocumentLifecycle"]
    assert set(lifecycle["x-valid-transitions"]) == set(lifecycle["enum"])
    assert all(
        current in next_values
        for current, next_values in lifecycle["x-valid-transitions"].items()
    )
    assert lifecycle["x-valid-transitions"]["COMPLETED"] == ["COMPLETED"]
    assert lifecycle["x-valid-transitions"]["FAILED"] == ["FAILED"]
    assert lifecycle["x-valid-transitions"] == {
        "UPLOAD_PENDING": ["UPLOAD_PENDING", "SUBMITTED"],
        "SUBMITTED": ["SUBMITTED", "PROCESSING"],
        "PROCESSING": ["PROCESSING", "COMPLETED", "FAILED"],
        "COMPLETED": ["COMPLETED"],
        "FAILED": ["FAILED"],
    }
    assert openapi["components"]["schemas"]["Progress"]["x-progress-invariant"] == (
        "completedStages must not exceed totalStages when both are present"
    )
    runtime_transitions = {
        previous.value: {current.value for current in next_values}
        for previous, next_values in runtime._VALID_TRANSITIONS.items()
    }
    assert runtime_transitions == {
        previous: set(next_values)
        for previous, next_values in lifecycle["x-valid-transitions"].items()
    }
    with pytest.raises(ValueError):
        runtime.DocumentProgress(completedStages=2, totalStages=1)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Account 12345678", "Account ****5678"),
        ("Account 1234-5678-9012", "Account ****9012"),
        ("Account 1234 5678 9012 345", "Account ****2345"),
        ("CLABE 123 456 789 012 345 678", "CLABE ****5678"),
    ],
)
def test_public_text_masks_separator_tolerant_8_to_18_digit_identifiers(
    value: str,
    expected: str,
) -> None:
    runtime = _runtime_contract()
    assert runtime._safe_public_text(value) == expected


def test_contract_docs_state_every_explicit_no_live_boundary() -> None:
    required = {
        "no live dynamodb",
        "no live api gateway",
        "no live cognito",
        "no live upload",
        "no live ocr, textract, or bedrock",
        "no aws access or mutation",
        "no deployment",
    }
    for path in CONTRACT_DOCUMENTATION_PATHS:
        source = path.read_text(encoding="utf-8").lower()
        assert required <= {
            boundary for boundary in required if boundary in source
        }, f"{path} is missing an explicit no-live boundary"


def test_retry_after_details_are_limited_to_public_runtime_emitters(
    openapi: dict[str, Any],
) -> None:
    runtime = _runtime_contract()
    validator = _validator(openapi, "ErrorEnvelope")
    for code in runtime.ErrorCode:
        _, envelope = runtime.public_error(code, "corr.synthetic.retry")
        error = envelope.model_dump(mode="json", by_alias=True, exclude_none=True)
        error["details"] = {"retryAfterSeconds": 30}
        if code.value in {"RATE_LIMITED", "SERVICE_UNAVAILABLE"}:
            validator.validate(error)
        else:
            with pytest.raises(ValidationError):
                validator.validate(error)


def test_bank_statement_result_is_closed_typed_and_identity_bound(
    result_schema: dict[str, Any],
) -> None:
    validator = Draft202012Validator(result_schema, format_checker=FormatChecker())
    fixture = _fixture("BANK_STATEMENT_RESULT_FIXTURE")

    assert fixture["resultId"] == f"result_{fixture['documentId']}_v1"
    assert fixture["documentType"] == fixture["resultType"] == "bank_statement"
    assert "url" not in json.dumps(fixture).lower()

    mutations = []
    arbitrary = copy.deepcopy(fixture)
    arbitrary["data"]["arbitrary"] = {"unreviewed": True}
    mutations.append(arbitrary)

    wrong_discriminator = copy.deepcopy(fixture)
    wrong_discriminator["resultType"] = "personal_document"
    mutations.append(wrong_discriminator)

    malformed_transaction = copy.deepcopy(fixture)
    malformed_transaction["data"]["transactions"][0]["amount"] = "500.00"
    mutations.append(malformed_transaction)

    for exposed_mask in ("1234567890123456", "XXXX0001", "***0001", "****12345"):
        malformed_mask = copy.deepcopy(fixture)
        malformed_mask["data"]["account"]["numberMasked"] = exposed_mask
        mutations.append(malformed_mask)

    for mutation in mutations:
        with pytest.raises(ValidationError):
            validator.validate(mutation)

    assert result_schema["x-identity-binding"] == (
        "resultId must equal result_<documentId>_v1 and is enforced by the runtime "
        "adapter before serialization"
    )
    assert result_schema["$defs"]["statement"]["x-period-invariant"] == (
        "When both values are present, periodStart must be less than or equal to "
        "periodEnd."
    )


def test_result_contract_never_embeds_a_signed_locator(
    result_schema: dict[str, Any]
) -> None:
    serialized = json.dumps(result_schema).lower()
    forbidden = (
        "downloadurl",
        "presigned",
        "signedurl",
        "x-amz-signature",
        "authorization",
        "bucket",
        "objectkey",
    )
    assert all(value not in serialized for value in forbidden)
    assert set(result_schema["$defs"]["account"]["properties"]) == {
        "holder",
        "numberMasked",
        "clabeMasked",
        "currency",
    }


def test_repository_edge_forwards_only_reviewed_request_headers() -> None:
    source = EDGE_CLOUDFRONT_PATH.read_text(encoding="utf-8")
    forwarded = _hcl_string_lists(source, "headers")
    assert [
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "Origin",
        "X-Correlation-ID",
        "X-Scanalyze-Contract-Version",
    ] in forwarded
    assert "x-tenant-id" not in source.lower()


def test_repository_cors_matches_the_reviewed_browser_contract() -> None:
    source = EDGE_IDENTITY_API_PATH.read_text(encoding="utf-8")
    allow_headers = _hcl_string_lists(source, "allow_headers")
    expose_headers = _hcl_string_lists(source, "expose_headers")

    expected_allow = {
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "X-Correlation-ID",
        "X-Scanalyze-Contract-Version",
    }
    expected_expose = {
        "Retry-After",
        "X-Correlation-ID",
        "X-Request-ID",
        "X-Trace-ID",
    }
    assert allow_headers and all(set(headers) == expected_allow for headers in allow_headers)
    assert expose_headers and all(
        set(headers) == expected_expose for headers in expose_headers
    )
    assert "x-tenant-id" not in source.lower()
    assert re.search(r"\ballow_origins\s*=\s*var\.cors_allowed_origins\b", source)


def test_edge_preserves_explicit_v2_before_rewriting_the_historical_facade() -> None:
    source = EDGE_REWRITE_PATH.read_text(encoding="utf-8")
    explicit_v2 = "request.uri === '/api/v2'"
    historical = "request.uri === '/api'"
    assert explicit_v2 in source
    assert "request.uri.indexOf('/api/v2/') === 0" in source
    assert source.index(explicit_v2) < source.index(historical)
    assert "return request;" in source[source.index(explicit_v2) : source.index(historical)]
    assert "request.uri = '/api/v1'" in source
    assert "request.uri = '/';" not in source


def test_ingest_service_configures_the_structured_result_bucket() -> None:
    source = SERVICES_TFVARS_PATH.read_text(encoding="utf-8")
    start = source.index('name              = "ingest-api"')
    end = source.index('name              = "ocr-worker"', start)
    ingest = source[start:end]
    environment = dict(
        re.findall(
            r'\{\s*name\s*=\s*"([A-Z0-9_]+)"\s*,\s*value\s*=\s*"([^"]+)"\s*\}',
            ingest,
        )
    )
    assert environment["STRUCTURED_BUCKET"] == environment["DOCUMENTS_BUCKET"]
    assert environment["OPERATION_LEDGER_TABLE_NAME"] == environment[
        "DOCUMENTS_TABLE_NAME"
    ]
